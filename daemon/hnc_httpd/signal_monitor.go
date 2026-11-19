// signal_monitor.go — HNC v6.0.0 · Vector: 热点手机自身 5G SA/NSA · 4G LTE · Wi-Fi STA 异步零阻塞信号质量感知
//
// 技术原理:
//   1. 彻底消灭 HTTP 请求线程同步跑 dumpsys:
//      - Get() / Snapshot() 永不在调用线程内执行外部命令! 缓存未命中或过期时立即返回上一份
//        内存快照(首次尚未采样时返回轻量初始态), 同时通过无阻塞容量为 1 的信号槽唤醒单实例
//        后台协程异步刷新;
//   2. 自适应刷新节拍省掉 70% system_server Binder 唤醒:
//      - 活跃态刷新周期从 3s 调优至 8s, 空闲态(熄屏无面板/无在线设备/热点关闭)放宽至 45s;
//      - 外部命令统一启用进程组隔离(Setpgid + 超时向 -pgid 发 SIGKILL), 杜绝僵尸进程堆积;
//   3. 攻克 AOSP 12–16 五大解析陷阱与 5G Autorate 联动(完整保留既有字段语义)。
package main

import (
	"bufio"
	"context"
	"math"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	sigUnavailable    = 2147483647
	sigActiveInterval = 8 * time.Second
	sigIdleInterval   = 45 * time.Second
	sigCacheTTL       = 8 * time.Second
)

type hostSignalStatus struct {
	Available       bool    `json:"available"`
	Mode            string  `json:"mode"`             // "cellular" | "wifi_sta" | "unknown"
	RAT             string  `json:"rat"`              // "5G SA" | "5G NSA" | "4G LTE" | "Wi-Fi" | "Unknown"
	Slot            int     `json:"slot,omitempty"`   // 1 | 2
	SubID           int     `json:"sub_id,omitempty"` // active data subId
	Carrier         string  `json:"carrier,omitempty"`
	UpstreamIface   string  `json:"upstream_iface,omitempty"`
	Band            string  `json:"band,omitempty"` // e.g. "n78", "n41", "B3", "5GHz"
	BandwidthMHz    int     `json:"bandwidth_mhz,omitempty"`
	RSRPdBm         int     `json:"rsrp_dbm,omitempty"` // NR ssRsrp or LTE rsrp (-140..-44)
	RSRQdB          int     `json:"rsrq_db,omitempty"`  // NR ssRsrq or LTE rsrq (-20..-3)
	SINRdB          int     `json:"sinr_db,omitempty"`  // NR ssSinr or LTE rssnr (-20..40)
	LTERSRPdBm      int     `json:"lte_rsrp_dbm,omitempty"`
	WifiRSSIdBm     int     `json:"wifi_rssi_dbm,omitempty"`
	WifiLinkMbps    int     `json:"wifi_link_mbps,omitempty"`
	Bars            int     `json:"bars"`              // 0..4
	Quality         string  `json:"quality"`           // "excellent" | "good" | "fair" | "weak" | "critical" | "unknown"
	QualityCN       string  `json:"quality_cn"`        // 中文健康标签
	RFCeilingFactor float64 `json:"rf_ceiling_factor"` // α_rf in [0.35, 1.0] for Autorate
	Diagnosis       string  `json:"diagnosis"`         // "ok" | "rf_weak" | "congestion" | "lan_bottleneck" | "idle"
	DiagnosisCN     string  `json:"diagnosis_cn"`
	UpdatedAt       int64   `json:"updated_at"`
}

// signalMonitor 零阻塞异步信号监测器。
// 铁律: 64 位原子字段置于结构体最开头(offset 0), 满足 32 位 ARMv7 原子对齐要求。
type signalMonitor struct {
	asyncRuns      atomic.Uint64 // offset 0: 后台异步采样完成次数
	asyncCoalesced atomic.Uint64 // offset 8: 合并丢弃的并发触发信号数
	lastRefreshNs  atomic.Int64  // offset 16: 最近一次采样耗时(ns)

	inFlight  atomic.Bool
	forceNext atomic.Bool
	closed    atomic.Bool

	hncDir   string
	sampleFn func(s *server) hostSignalStatus // 单测注入点(默认 sampleHostSignal)

	mu     sync.RWMutex
	last   hostSignalStatus
	lastAt time.Time
}

func newSignalMonitor(hncDir string) *signalMonitor {
	m := &signalMonitor{
		hncDir: hncDir,
		last: hostSignalStatus{
			Available:       false,
			Mode:            "unknown",
			RAT:             "Unknown",
			Quality:         "unknown",
			QualityCN:       "待采样",
			RFCeilingFactor: 1.0,
			Diagnosis:       "idle",
			DiagnosisCN:     "等待后台异步信号采样",
		},
	}
	m.sampleFn = m.sampleHostSignal
	return m
}

// currentTTL 按系统活跃档位动态返回缓存有效期: 活跃态 8s, 空闲/熄屏态 45s。
func (m *signalMonitor) currentTTL() time.Duration {
	act := activityNow()
	if act.Known {
		switch act.Level {
		case lvlHotspotOff, lvlNoClients, lvlBackground:
			return sigIdleInterval
		}
		if act.screenOff() {
			return sigIdleInterval
		}
	}
	return sigActiveInterval
}

// Get 供 HTTP 线程(/api/signal, /api/live, /api/vector_sync)无阻塞读取信号状态:
// 绝不在当前请求线程内同步执行 dumpsys! 缓存过期时立即返回上一份快照并触发单飞后台协程刷新。
func (m *signalMonitor) Get(s *server) hostSignalStatus {
	if s != nil && s.simActive() {
		return simSignalSnapshot(s)
	}
	if m == nil {
		return hostSignalStatus{
			Mode:            "unknown",
			RAT:             "Unknown",
			Quality:         "unknown",
			QualityCN:       "待采样",
			RFCeilingFactor: 1.0,
			Diagnosis:       "idle",
		}
	}
	ttl := m.currentTTL()
	m.mu.RLock()
	stale := m.lastAt.IsZero() || time.Since(m.lastAt) >= ttl
	cp := m.last
	m.mu.RUnlock()

	if s != nil {
		enrichSignalDiagnosis(&cp, s)
	}
	if stale {
		m.TriggerRefresh(s, false)
	}
	return cp
}

// Snapshot 兼容全仓既有调用点(s.signalCtl.Snapshot(s)), 同样走 100% 非阻塞快路径。
func (m *signalMonitor) Snapshot(s *server) hostSignalStatus {
	return m.Get(s)
}

// TriggerRefresh 非阻塞触发单实例后台异步刷新(已在途时自动合并, 零排队、零常驻泄漏)。
func (m *signalMonitor) TriggerRefresh(s *server, force bool) {
	if m == nil || m.closed.Load() {
		return
	}
	if force {
		m.forceNext.Store(true)
	}
	if !m.inFlight.CompareAndSwap(false, true) {
		m.asyncCoalesced.Add(1)
		return
	}
	go func(srv *server) {
		defer m.inFlight.Store(false)
		forced := m.forceNext.Swap(false)
		if !forced {
			ttl := m.currentTTL()
			m.mu.RLock()
			fresh := !m.lastAt.IsZero() && time.Since(m.lastAt) < ttl
			m.mu.RUnlock()
			if fresh {
				return
			}
		}
		start := time.Now()
		_ = m.Refresh(srv)
		m.lastRefreshNs.Store(int64(time.Since(start)))
		m.asyncRuns.Add(1)
	}(s)
}

// Refresh 执行单次真实采样并更新缓存(仅供后台异步协程或显式单测内部调用)。
func (m *signalMonitor) Refresh(s *server) hostSignalStatus {
	if s != nil && s.simActive() {
		return simSignalSnapshot(s)
	}
	fn := m.sampleHostSignal
	if m.sampleFn != nil {
		fn = m.sampleFn
	}
	st := fn(s)
	now := time.Now()
	if st.UpdatedAt == 0 {
		st.UpdatedAt = now.Unix()
	}
	if s != nil {
		enrichSignalDiagnosis(&st, s)
	}
	m.mu.Lock()
	m.last = st
	m.lastAt = now
	m.mu.Unlock()
	return st
}

func (m *signalMonitor) sampleHostSignal(s *server) hostSignalStatus {
	now := time.Now()
	det := readIfaceDetect(m.hncDir)
	upIf := det.TetherUpstream
	if upIf == "" {
		upIf = det.Upstream
	}

	// 若服务器已挂载 AndroidBridgeBulkhead, 先检查熔断器状态, 熔断期间直接跳过系统调用保护 system_server。
	var bridge *Bulkhead
	if s != nil {
		bridge = s.CoreHub().AndroidBridgeBulkhead
		if bridge != nil && bridge.CircuitState() == "open" {
			return hostSignalStatus{
				Available:       false,
				Mode:            "unknown",
				RAT:             "Unknown",
				UpstreamIface:   upIf,
				Bars:            0,
				Quality:         "unknown",
				QualityCN:       "桥接熔断保护中",
				RFCeilingFactor: 1.0,
				Diagnosis:       "idle",
				DiagnosisCN:     "Android 服务响应超时，熔断退避中",
				UpdatedAt:       now.Unix(),
			}
		}
	}

	var st hostSignalStatus
	if strings.HasPrefix(upIf, "wlan") && upIf == "wlan0" {
		if out, err := runFastSystemCmd(1500*time.Millisecond, "cmd", "wifi", "status"); err == nil && out != "" {
			st = parseWifiStatusOutput(out, upIf, now.Unix())
		}
	}
	if !st.Available {
		if bridge != nil {
			var raw string
			_ = bridge.Execute(context.Background(), 1800*time.Millisecond, func(ctx context.Context) error {
				var derr error
				raw, derr = dumpTelephonyRegistryHeadCtx(ctx, 1800*time.Millisecond)
				return derr
			})
			if raw != "" {
				st = parseTelephonyRegistryDump(raw, upIf, now.Unix())
			}
		} else if raw, err := dumpTelephonyRegistryHead(1800 * time.Millisecond); err == nil && raw != "" {
			st = parseTelephonyRegistryDump(raw, upIf, now.Unix())
		}
	}
	if !st.Available {
		st = hostSignalStatus{
			Available:       false,
			Mode:            "unknown",
			RAT:             "Unknown",
			UpstreamIface:   upIf,
			Bars:            0,
			Quality:         "unknown",
			QualityCN:       "未读取到基带缓存",
			RFCeilingFactor: 1.0,
			Diagnosis:       "idle",
			DiagnosisCN:     "未读取到蜂窝/Wi-Fi 信号指标",
			UpdatedAt:       now.Unix(),
		}
	}
	return st
}

func simSignalSnapshot(s *server) hostSignalStatus {
	st := hostSignalStatus{
		Available:       true,
		Mode:            "cellular",
		RAT:             "5G SA",
		Slot:            1,
		SubID:           1,
		Carrier:         "中国移动",
		UpstreamIface:   "rmnet_data2",
		Band:            "n78",
		BandwidthMHz:    100,
		RSRPdBm:         -88,
		RSRQdB:          -9,
		SINRdB:          19,
		Bars:            4,
		Quality:         "excellent",
		QualityCN:       "5G 极佳",
		RFCeilingFactor: 1.0,
		Diagnosis:       "ok",
		DiagnosisCN:     "上游 5G n78 满格低延迟，空口无拥塞",
		UpdatedAt:       time.Now().Unix(),
	}
	enrichSignalDiagnosis(&st, s)
	return st
}

func enrichSignalDiagnosis(st *hostSignalStatus, s *server) {
	if st == nil || s == nil || s.autorate == nil {
		return
	}
	ar := s.autorate.Snapshot()
	if !st.Available {
		return
	}
	weakRF := st.Quality == "weak" || st.Quality == "critical"
	bloated := ar.Enabled && ar.DeltaRTTMs > math.Max(20, ar.RTTDeltaMs)
	switch {
	case weakRF && bloated:
		st.Diagnosis = "rf_weak"
		st.DiagnosisCN = "热点机处于弱信号边缘区且空口排队膨胀，Autorate 已联动预压顶稳帧"
	case weakRF:
		st.Diagnosis = "rf_weak"
		st.DiagnosisCN = "热点机当前信号偏弱（建议移至窗边），已启用弱网防抖保护上限"
	case bloated:
		st.Diagnosis = "congestion"
		st.DiagnosisCN = "热点机信号良好但基站空口繁忙（ΔRTT 升高），Autorate 正在退避消肿"
	default:
		st.Diagnosis = "ok"
		if st.Mode == "wifi_sta" {
			st.DiagnosisCN = "上游 Wi-Fi 中继链路通畅"
		} else {
			st.DiagnosisCN = "上游蜂窝射频与排队延迟均健康"
		}
	}
}

func dumpTelephonyRegistryHead(timeout time.Duration) (string, error) {
	return dumpTelephonyRegistryHeadCtx(context.Background(), timeout)
}

func dumpTelephonyRegistryHeadCtx(parentCtx context.Context, timeout time.Duration) (string, error) {
	bins := []string{"/system/bin/dumpsys", "dumpsys"}
	var binPath string
	for _, b := range bins {
		if p, err := exec.LookPath(b); err == nil {
			binPath = p
			break
		}
	}
	if binPath == "" {
		return "", exec.ErrNotFound
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, binPath, "telephony.registry"))
	cmd.Env = []string{"PATH=/system/bin:/system/xbin:/vendor/bin"}
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error {
			if cmd.Process != nil && cmd.Process.Pid > 0 {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				return cmd.Process.Kill()
			}
			return nil
		}
	}
	cmd.WaitDelay = 400 * time.Millisecond

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	var sb strings.Builder
	sc := bufio.NewScanner(stdout)
	lines := 0
	truncated := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "local logs:") || lines >= 650 {
			truncated = true
			cancel()
			break
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
		lines++
	}
	waitErr := cmd.Wait()
	if !truncated && ctx.Err() == context.DeadlineExceeded {
		return sb.String(), context.DeadlineExceeded
	}
	_ = waitErr
	return sb.String(), nil
}

func runFastSystemCmd(timeout time.Duration, name string, args ...string) (string, error) {
	out, err := ExecIsolatedAndroidCmd(context.Background(), timeout, name, args...)
	return string(out), err
}

var (
	rePhoneBlock   = regexp.MustCompile(`^\s*Phone Id=(\d+)`)
	reActiveSub    = regexp.MustCompile(`mActiveDataSubId=(-?\d+)`)
	reSubIDField   = regexp.MustCompile(`\bmSubId=(\d+)`)
	reNrSignal     = regexp.MustCompile(`CellSignalStrengthNr:\{[^}]*?ssRsrp\s*=\s*(-?\d+)[^}]*?ssRsrq\s*=\s*(-?\d+)[^}]*?ssSinr\s*=\s*(-?\d+)`)
	reLteSignal    = regexp.MustCompile(`CellSignalStrengthLte:\s*rssi=(-?\d+)\s+rsrp=(-?\d+)\s+rsrq=(-?\d+)\s+rssnr=(-?\d+)`)
	reAccessTech   = regexp.MustCompile(`accessNetworkTechnology=([A-Za-z0-9_ -]+)`)
	reEndcAvail    = regexp.MustCompile(`isEnDcAvailable\s*=\s*true`)
	reDispOverride = regexp.MustCompile(`override(?:Network)?=(NR_NSA|NR_ADVANCED|NR_MMWAVE|LTE_CA)`)
	reOperatorLong = regexp.MustCompile(`mOperatorAlphaLong=([^,\n}]+)`)
	reOperatorShrt = regexp.MustCompile(`mOperatorAlphaShort=([^,\n}]+)`)
	reDataIface    = regexp.MustCompile(`InterfaceName:\s*([A-Za-z0-9_.-]+)`)
	rePhysChan     = regexp.MustCompile(`mConnectionStatus=PrimaryServing[^}]*?mNetworkType=(NR|LTE)[^}]*?mBand=(\d+)`)
	rePhysBW       = regexp.MustCompile(`mCellBandwidthDownlinkKhz=(\d+)`)
	reWifiRSSI     = regexp.MustCompile(`RSSI:\s*(-?\d+)`)
	reWifiSpeed    = regexp.MustCompile(`Tx Link speed:\s*(\d+)Mbps`)
	reWifiFreq     = regexp.MustCompile(`Frequency:\s*(\d+)MHz`)
)

type parsedPhoneSlot struct {
	PhoneID     int
	SubID       int
	Carrier     string
	Ifaces      map[string]bool
	HasNRValid  bool
	NRRsrp      int
	NRRsrq      int
	NRSinr      int
	HasLTEValid bool
	LTERsrp     int
	LTERsrq     int
	LTESinr     int
	IsSA        bool
	IsNSA       bool
	IsLTE       bool
	Band        string
	BWMHz       int
}

func validRSRP(v int) bool { return v != sigUnavailable && v >= -145 && v <= -40 }
func validRSRQ(v int) bool { return v != sigUnavailable && v >= -30 && v <= 0 }
func validSINR(v int) bool { return v != sigUnavailable && v >= -25 && v <= 50 }

func parseTelephonyRegistryDump(raw, wantIface string, nowUnix int64) hostSignalStatus {
	activeSubID := -1
	if m := reActiveSub.FindStringSubmatch(raw); m != nil {
		activeSubID, _ = strconv.Atoi(m[1])
	}

	var slots []*parsedPhoneSlot
	var cur *parsedPhoneSlot
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "local logs:") {
			break
		}
		if m := rePhoneBlock.FindStringSubmatch(line); m != nil {
			pid, _ := strconv.Atoi(m[1])
			cur = &parsedPhoneSlot{PhoneID: pid, Ifaces: map[string]bool{}}
			slots = append(slots, cur)
			continue
		}
		if cur == nil {
			continue
		}
		if m := reSubIDField.FindStringSubmatch(line); m != nil && cur.SubID == 0 {
			cur.SubID, _ = strconv.Atoi(m[1])
		}
		if m := reOperatorShrt.FindStringSubmatch(line); m != nil && cur.Carrier == "" {
			v := strings.TrimSpace(m[1])
			if v != "" && v != "null" {
				cur.Carrier = v
			}
		}
		if m := reOperatorLong.FindStringSubmatch(line); m != nil && cur.Carrier == "" {
			v := strings.TrimSpace(m[1])
			if v != "" && v != "null" {
				cur.Carrier = v
			}
		}
		for _, im := range reDataIface.FindAllStringSubmatch(line, -1) {
			if im[1] != "" {
				cur.Ifaces[im[1]] = true
			}
		}
		if m := reNrSignal.FindStringSubmatch(line); m != nil {
			rsrp, _ := strconv.Atoi(m[1])
			rsrq, _ := strconv.Atoi(m[2])
			sinr, _ := strconv.Atoi(m[3])
			if validRSRP(rsrp) {
				cur.HasNRValid = true
				cur.NRRsrp = rsrp
				if validRSRQ(rsrq) {
					cur.NRRsrq = rsrq
				}
				if validSINR(sinr) {
					cur.NRSinr = sinr
				}
			}
		}
		if m := reLteSignal.FindStringSubmatch(line); m != nil {
			rsrp, _ := strconv.Atoi(m[2])
			rsrq, _ := strconv.Atoi(m[3])
			sinr, _ := strconv.Atoi(m[4])
			if validRSRP(rsrp) {
				cur.HasLTEValid = true
				cur.LTERsrp = rsrp
				if validRSRQ(rsrq) {
					cur.LTERsrq = rsrq
				}
				if validSINR(sinr) {
					cur.LTESinr = sinr
				}
			}
		}
		for _, am := range reAccessTech.FindAllStringSubmatch(line, -1) {
			tech := strings.ToUpper(strings.TrimSpace(am[1]))
			switch {
			case tech == "NR":
				cur.IsSA = true
			case strings.Contains(tech, "LTE"):
				cur.IsLTE = true
			}
		}
		if reEndcAvail.MatchString(line) {
			cur.IsNSA = true
		}
		if m := reDispOverride.FindStringSubmatch(line); m != nil {
			if strings.HasPrefix(m[1], "NR_") {
				cur.IsNSA = true
			}
		}
		if m := rePhysChan.FindStringSubmatch(line); m != nil {
			bNum, _ := strconv.Atoi(m[2])
			if bNum > 0 {
				if m[1] == "NR" {
					cur.Band = "n" + strconv.Itoa(bNum)
				} else if cur.Band == "" {
					cur.Band = "B" + strconv.Itoa(bNum)
				}
			}
			if bm := rePhysBW.FindStringSubmatch(line); bm != nil {
				khz, _ := strconv.Atoi(bm[1])
				if khz >= 1000 && khz/1000 > cur.BWMHz {
					cur.BWMHz = khz / 1000
				}
			}
		}
	}

	var chosen *parsedPhoneSlot
	if wantIface != "" {
		for _, sl := range slots {
			if sl.Ifaces[wantIface] {
				chosen = sl
				break
			}
		}
	}
	if chosen == nil && activeSubID > 0 {
		for _, sl := range slots {
			if sl.SubID == activeSubID {
				chosen = sl
				break
			}
		}
	}
	if chosen == nil {
		for _, sl := range slots {
			if sl.HasNRValid || sl.HasLTEValid {
				chosen = sl
				break
			}
		}
	}
	if chosen == nil || (!chosen.HasNRValid && !chosen.HasLTEValid) {
		return hostSignalStatus{Available: false, UpdatedAt: nowUnix}
	}

	if wantIface == "" {
		for ifc := range chosen.Ifaces {
			wantIface = ifc
			break
		}
	}

	out := hostSignalStatus{
		Available:     true,
		Mode:          "cellular",
		Slot:          chosen.PhoneID + 1,
		SubID:         chosen.SubID,
		Carrier:       chosen.Carrier,
		UpstreamIface: wantIface,
		Band:          chosen.Band,
		BandwidthMHz:  chosen.BWMHz,
		UpdatedAt:     nowUnix,
	}

	// 强制优先采信有效 NR 载波指标 (规避 mLteAsPrimaryInNrNsa=true 导致的 LTE 锚点假满格)
	if chosen.HasNRValid {
		out.RSRPdBm = chosen.NRRsrp
		out.RSRQdB = chosen.NRRsrq
		out.SINRdB = chosen.NRSinr
		if chosen.HasLTEValid {
			out.LTERSRPdBm = chosen.LTERsrp
		}
		if chosen.IsSA {
			out.RAT = "5G SA"
		} else {
			out.RAT = "5G NSA"
		}
	} else {
		out.RSRPdBm = chosen.LTERsrp
		out.RSRQdB = chosen.LTERsrq
		out.SINRdB = chosen.LTESinr
		out.RAT = "4G LTE"
	}

	out.Bars, out.Quality, out.QualityCN, out.RFCeilingFactor = scoreCellularSignal(out.RSRPdBm, out.SINRdB, strings.HasPrefix(out.RAT, "5G"))
	out.Diagnosis = "ok"
	out.DiagnosisCN = "蜂窝射频状态已同步"
	return out
}

func scoreCellularSignal(rsrp, sinr int, is5G bool) (bars int, quality, qualityCN string, alpha float64) {
	switch {
	case rsrp >= -88 && sinr >= 13:
		return 4, "excellent", map[bool]string{true: "5G 极佳", false: "4G 极佳"}[is5G], 1.0
	case rsrp >= -98 && sinr >= 6:
		return 3, "good", map[bool]string{true: "5G 良好", false: "4G 良好"}[is5G], 0.95
	case rsrp >= -108 && sinr >= 0:
		return 2, "fair", "信号一般", 0.80
	case rsrp >= -116:
		return 1, "weak", "弱信号边缘", 0.55
	default:
		return 0, "critical", "极弱易断流", 0.35
	}
}

func parseWifiStatusOutput(raw, upIf string, nowUnix int64) hostSignalStatus {
	m := reWifiRSSI.FindStringSubmatch(raw)
	if m == nil {
		return hostSignalStatus{Available: false, UpdatedAt: nowUnix}
	}
	rssi, _ := strconv.Atoi(m[1])
	if rssi < -100 || rssi > -15 {
		return hostSignalStatus{Available: false, UpdatedAt: nowUnix}
	}
	var linkMbps, freq int
	if sm := reWifiSpeed.FindStringSubmatch(raw); sm != nil {
		linkMbps, _ = strconv.Atoi(sm[1])
	}
	if fm := reWifiFreq.FindStringSubmatch(raw); fm != nil {
		freq, _ = strconv.Atoi(fm[1])
	}
	band := "2.4GHz"
	if freq >= 5900 {
		band = "6GHz"
	} else if freq >= 5000 {
		band = "5GHz"
	}
	var bars int
	var q, qCN string
	var alpha float64
	switch {
	case rssi >= -58:
		bars, q, qCN, alpha = 4, "excellent", "Wi-Fi 极佳", 1.0
	case rssi >= -68:
		bars, q, qCN, alpha = 3, "good", "Wi-Fi 良好", 0.95
	case rssi >= -77:
		bars, q, qCN, alpha = 2, "fair", "Wi-Fi 一般", 0.78
	case rssi >= -85:
		bars, q, qCN, alpha = 1, "weak", "Wi-Fi 偏弱", 0.52
	default:
		bars, q, qCN, alpha = 0, "critical", "Wi-Fi 极弱", 0.35
	}
	return hostSignalStatus{
		Available:       true,
		Mode:            "wifi_sta",
		RAT:             "Wi-Fi 中继",
		UpstreamIface:   upIf,
		Band:            band,
		WifiRSSIdBm:     rssi,
		WifiLinkMbps:    linkMbps,
		Bars:            bars,
		Quality:         q,
		QualityCN:       qCN,
		RFCeilingFactor: alpha,
		Diagnosis:       "ok",
		DiagnosisCN:     "上游 Wi-Fi 中继状态已同步",
		UpdatedAt:       nowUnix,
	}
}

func (s *server) apiSignal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("refresh") == "1" {
		s.signalCtl.TriggerRefresh(s, true)
	}
	snap := s.signalCtl.Get(s)
	WriteJSONv2(w, http.StatusOK, &snap)
}
