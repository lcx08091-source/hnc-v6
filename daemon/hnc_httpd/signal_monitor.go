// signal_monitor.go — HNC v6.0.0 · Vector: 热点手机自身 5G-A / 5G SA/NSA · 4G LTE · Wi-Fi STA 异步零阻塞全频段信号感知
//
// 技术原理:
//   1. 彻底消灭 HTTP 请求线程同步跑 dumpsys:
//      - Get() / Snapshot() 永不在调用线程内执行外部命令! 缓存未命中或过期时立即返回上一份
//        内存快照(首次尚未采样时返回轻量初始态), 同时通过无阻塞容量为 1 的信号槽唤醒单实例
//        后台协程异步刷新;
//   2. 自适应刷新节拍省掉 70% system_server Binder 唤醒:
//      - 活跃态刷新周期从 3s 调优至 8s, 空闲态(熄屏无面板/无在线设备/热点关闭)放宽至 45s;
//      - 外部命令统一启用进程组隔离(Setpgid + 超时向 -pgid 发 SIGKILL), 杜绝僵尸进程堆积;
//   3. AOSP 12–16 / ColorOS 16 全频段 5G-A 精准解析与 5G Autorate 联动:
//      - 扩大 Scanner 缓冲至 512KB、头部扫描上限放宽至 2500 行(遇 "local logs:" 立即截断, 零 Modem 唤醒);
//      - 精准识别 NR_ADVANCED (5G-A) 图标态与 PrimaryServing + SecondaryServing 多载波聚合 (2CC/3CC) 组合及总带宽;
//      - 当高通/联发科基带隐藏 mBand=0 时, 自动通过 mDownlinkChannelNumber / mNrArfcn / mEarfcn 查 3GPP 频段表反推;
//      - 完整保留既有 JSON 字段语义(RAT 保持 "5G SA"/"5G NSA"/"4G LTE" 零破坏既有单测, 新增 DisplayRAT="5G-A" 等增强字段)。
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
	Available          bool    `json:"available"`
	Mode               string  `json:"mode"`                         // "cellular" | "wifi_sta" | "unknown"
	RAT                string  `json:"rat"`                          // 兼容契约: "5G SA" | "5G NSA" | "4G LTE" | "Wi-Fi 中继" | "Unknown"
	DisplayRAT         string  `json:"display_rat,omitempty"`        // 界面展示制式: "5G-A" | "5G SA" | "5G NSA" | "4G+" | "4G LTE" | "Wi-Fi 中继"
	Is5GA              bool    `json:"is_5ga,omitempty"`             // 是否处于 5G-A (NR_ADVANCED / 多载波聚合 / >=140MHz)
	Slot               int     `json:"slot,omitempty"`               // 1 | 2
	SubID              int     `json:"sub_id,omitempty"`             // active data subId
	Carrier            string  `json:"carrier,omitempty"`            // 归一化运营商全称 (如 "中国移动", "中国广电")
	CarrierShort       string  `json:"carrier_short,omitempty"`      // 顶栏紧凑短名 (如 "移动", "广电", "电信", "联通")
	MCCMNC             string  `json:"mcc_mnc,omitempty"`            // 5~6 位 PLMN (如 "46000", "46015")
	SharingMode        string  `json:"sharing_mode,omitempty"`       // 共建共享提示 (如 "700MHz 移广共建共享", "3.5GHz 电联共建共享")
	UpstreamIface      string  `json:"upstream_iface,omitempty"`     // 如 "rmnet_data2", "ccmni0"
	Band               string  `json:"band,omitempty"`               // 主载波频段: 如 "n41", "n78", "n28", "B3", "5GHz"
	BandwidthMHz       int     `json:"bandwidth_mhz,omitempty"`      // 主载波带宽 (MHz)
	BandCombo          string  `json:"band_combo,omitempty"`         // 多载波组合: 如 "n41+n28", "n78+n78"
	TotalBWMHz         int     `json:"total_bw_mhz,omitempty"`       // 多载波聚合总带宽 (MHz), 如 130, 200
	CACount            int     `json:"ca_count,omitempty"`           // 活跃聚合载波数 (1..4)
	ARFCN              int     `json:"arfcn,omitempty"`              // 主载波 NR-ARFCN / EARFCN 频点号
	FreqMHz            int     `json:"freq_mhz,omitempty"`           // 主频段近似中心频率 (MHz), 如 2600, 700, 3500
	BandTrait          string  `json:"band_trait,omitempty"`         // 频段物理特性人话解读
	RSRPdBm            int     `json:"rsrp_dbm,omitempty"`           // NR ssRsrp or LTE rsrp (-140..-44)
	RSRQdB             int     `json:"rsrq_db,omitempty"`            // NR ssRsrq or LTE rsrq (-20..-3)
	SINRdB             int     `json:"sinr_db,omitempty"`            // NR ssSinr or LTE rssnr (-20..40)
	LTERSRPdBm         int     `json:"lte_rsrp_dbm,omitempty"`       // NSA 场景下的 LTE 锚点 RSRP
	WifiRSSIdBm        int     `json:"wifi_rssi_dbm,omitempty"`      // Wi-Fi STA RSSI
	WifiLinkMbps       int     `json:"wifi_link_mbps,omitempty"`     // Wi-Fi STA 协商速率
	RSRPLabel          string  `json:"rsrp_label,omitempty"`         // 信号强度人话评级 ("极强"/"良好"/"一般"/"偏弱"/"极弱")
	SINRLabel          string  `json:"sinr_label,omitempty"`         // 信号纯净度人话评级 ("极纯净"/"纯净"/"轻度干扰"/"嘈杂易跳Ping")
	RSRQLabel          string  `json:"rsrq_label,omitempty"`         // 基站空闲度人话评级 ("基站空闲"/"负载正常"/"晚高峰偏忙"/"基站拥塞")
	SpeedPotentialPct  int     `json:"speed_potential_pct,omitempty"` // 网速潜力百分比 (35..100)
	SpeedPotentialText string  `json:"speed_potential_text,omitempty"`
	Bars               int     `json:"bars"`              // 0..4
	Quality            string  `json:"quality"`           // "excellent" | "good" | "fair" | "weak" | "critical" | "unknown"
	QualityCN          string  `json:"quality_cn"`        // 中文健康标签
	RFCeilingFactor    float64 `json:"rf_ceiling_factor"` // α_rf in [0.35, 1.0] for Autorate
	Diagnosis          string  `json:"diagnosis"`         // "ok" | "rf_weak" | "congestion" | "lan_bottleneck" | "idle"
	DiagnosisCN        string  `json:"diagnosis_cn"`
	UpdatedAt          int64   `json:"updated_at"`
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

func (m *signalMonitor) shouldSuppressBackgroundRefresh() bool {
	act := activityNow()
	if !act.Known || act.WebUIActive {
		return false
	}
	return act.Level == lvlHotspotOff || act.Level == lvlNoClients
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
	if stale && !m.shouldSuppressBackgroundRefresh() {
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
	if !force && m.shouldSuppressBackgroundRefresh() {
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
			if m.shouldSuppressBackgroundRefresh() {
				return
			}
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

// simSignalSnapshot 提供符合真实国内运营商频谱分配的 5G-A 双载波模拟快照(中国移动 n41 100MHz + n28 30MHz = 130MHz)。
func simSignalSnapshot(s *server) hostSignalStatus {
	rsrpLbl, sinrLbl, rsrqLbl, spPct, spTxt := build4DSignalLabels(-84, 21, -8, true, 1.0, false, 0)
	st := hostSignalStatus{
		Available:          true,
		Mode:               "cellular",
		RAT:                "5G SA",
		DisplayRAT:         "5G-A",
		Is5GA:              true,
		Slot:               1,
		SubID:              1,
		Carrier:            "中国移动",
		CarrierShort:       "移动",
		MCCMNC:             "46000",
		SharingMode:        "2.6GHz+700MHz 移广双载波共享",
		UpstreamIface:      "rmnet_data2",
		Band:               "n41",
		BandwidthMHz:       100,
		BandCombo:          "n41+n28",
		TotalBWMHz:         130,
		CACount:            2,
		ARFCN:              504990,
		FreqMHz:            2600,
		BandTrait:          describeBandTrait("n41", "n41+n28", 130, 2, false),
		RSRPdBm:            -84,
		RSRQdB:             -8,
		SINRdB:             21,
		RSRPLabel:          rsrpLbl,
		SINRLabel:          sinrLbl,
		RSRQLabel:          rsrqLbl,
		SpeedPotentialPct:  spPct,
		SpeedPotentialText: spTxt,
		Bars:               4,
		Quality:            "excellent",
		QualityCN:          "5G-A 极佳",
		RFCeilingFactor:    1.0,
		Diagnosis:          "ok",
		DiagnosisCN:        "上游 5G-A 双载波 (n41+n28 · 130MHz) 满格低延迟，空口无拥塞",
		UpdatedAt:          time.Now().Unix(),
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
	cellBusy := st.Mode == "cellular" && validRSRQ(st.RSRQdB) && st.RSRQdB <= -17
	bloated := ar.Enabled && ar.DeltaRTTMs > math.Max(20, ar.RTTDeltaMs)
	switch {
	case weakRF && bloated:
		st.Diagnosis = "rf_weak"
		st.DiagnosisCN = "热点机处于弱信号边缘区且空口排队膨胀，智能带宽已联动收紧上限稳住延迟"
	case weakRF:
		st.Diagnosis = "rf_weak"
		st.DiagnosisCN = "热点机当前基站信号偏弱（建议移至窗边），已启用弱网防断流保护"
	case bloated || cellBusy:
		st.Diagnosis = "congestion"
		if bloated {
			st.DiagnosisCN = "手机信号强度充足，但基站当前上网人数多（排队延迟升高），智能带宽正在自动稳帧"
		} else {
			st.DiagnosisCN = "手机信号格数充足，但当前基站信道负载偏忙，高峰期网速可能略有波动"
		}
	default:
		st.Diagnosis = "ok"
		if st.Mode == "wifi_sta" {
			st.DiagnosisCN = "上游 Wi-Fi 中继链路通畅"
		} else if st.Is5GA && st.BandCombo != "" {
			st.DiagnosisCN = "5G-A 多载波通道（" + st.BandCombo + "）信号纯净、基站空闲，热点可跑满高速带宽"
		} else {
			st.DiagnosisCN = "手机基站信号纯净、空口延迟平稳，热点可顺畅跑满物理网速"
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
	// ColorOS 16 / HyperOS 2 / OneUI 7 单行 mServiceState 常超 64KB, 扩容至 512KB 防止 ErrTooLong 中断读取!
	sc.Buffer(make([]byte, 64*1024), 512*1024)
	lines := 0
	truncated := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "local logs:") || lines >= 2500 {
			truncated = true
			break
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
		lines++
	}
	timedOut := ctx.Err() == context.DeadlineExceeded
	cancel()
	waitErr := cmd.Wait()
	if !truncated && timedOut {
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
	rePhoneBlock     = regexp.MustCompile(`^\s*Phone Id\s*=\s*(\d+)`)
	reActiveSub      = regexp.MustCompile(`mActiveDataSubId\s*=\s*(-?\d+)`)
	reSubIDField     = regexp.MustCompile(`\bmSubId\s*=\s*(\d+)`)
	reNrSignal       = regexp.MustCompile(`CellSignalStrengthNr:\s*\{[^}]*?ssRsrp\s*=\s*(-?\d+)[^}]*?ssRsrq\s*=\s*(-?\d+)[^}]*?ssSinr\s*=\s*(-?\d+)`)
	reLteSignal      = regexp.MustCompile(`CellSignalStrengthLte:[^,}\n]*?\brssi\s*=\s*(-?\d+)\s+rsrp\s*=\s*(-?\d+)\s+rsrq\s*=\s*(-?\d+)\s+rssnr\s*=\s*(-?\d+)`)
	reAccessTech     = regexp.MustCompile(`accessNetworkTechnology\s*=\s*([A-Za-z0-9_ -]+)`)
	reEndcAvail      = regexp.MustCompile(`isEnDcAvailable\s*=\s*true`)
	reNrConnected    = regexp.MustCompile(`nrState\s*=\s*CONNECTED`)
	reDispOverride   = regexp.MustCompile(`override(?:Network|NetworkType)?\s*=\s*(NR_NSA|NR_ADVANCED|NR_MMWAVE|LTE_CA|LTE_ADVANCED_PRO)`)
	reOperatorLong   = regexp.MustCompile(`mOperatorAlphaLong\s*=\s*([^,\n}]+)`)
	reOperatorShrt   = regexp.MustCompile(`mOperatorAlphaShort\s*=\s*([^,\n}]+)`)
	reOperatorNum    = regexp.MustCompile(`mOperatorNumeric\s*=\s*(\d{5,6})`)
	reMccMncPair     = regexp.MustCompile(`mMcc\s*=\s*(\d{3})\s*,?\s*mMnc\s*=\s*(\d{2,3})`)
	reDataIface      = regexp.MustCompile(`InterfaceName:\s*([A-Za-z0-9_.-]+)`)
	rePhysChanEntry  = regexp.MustCompile(`\{[^{}]*mConnectionStatus\s*=\s*(PrimaryServing|SecondaryServing|1|2)[^{}]*\}`)
	reChanConnStatus = regexp.MustCompile(`mConnectionStatus\s*=\s*(PrimaryServing|SecondaryServing|1|2)`)
	reChanNetType    = regexp.MustCompile(`mNetworkType\s*=\s*(NR|LTE|13|20)`)
	reChanBand       = regexp.MustCompile(`mBand\s*=\s*(\d+)`)
	reChanDLKhz      = regexp.MustCompile(`mCellBandwidthDownlinkKhz\s*=\s*(\d+)`)
	reChanDLArfcn    = regexp.MustCompile(`(?:mDownlinkChannelNumber|mChannelNumber)\s*=\s*(\d+)`)
	reCellIdNr       = regexp.MustCompile(`CellIdentityNr:\s*\{[^}]*\}`)
	reCellIdLte      = regexp.MustCompile(`CellIdentityLte:\s*\{[^}]*\}`)
	reNrArfcnField   = regexp.MustCompile(`mNrArfcn\s*=\s*(\d+)`)
	reEarfcnField    = regexp.MustCompile(`mEarfcn\s*=\s*(\d+)`)
	reBandsArray     = regexp.MustCompile(`mBands\s*=\s*\[([0-9,\s]+)\]`)
	reLteBwField     = regexp.MustCompile(`mBandwidth\s*=\s*(\d+)`)
	reWifiRSSI       = regexp.MustCompile(`RSSI:\s*(-?\d+)`)
	reWifiSpeed      = regexp.MustCompile(`Tx Link speed:\s*(\d+)Mbps`)
	reWifiFreq       = regexp.MustCompile(`Frequency:\s*(\d+)MHz`)
)

type parsedServingCarrier struct {
	IsPrimary bool
	IsNR      bool
	Band      string
	BWMHz     int
	ARFCN     int
}

type parsedPhoneSlot struct {
	PhoneID          int
	SubID            int
	AlphaLong        string
	AlphaShort       string
	MCCMNC           string
	Ifaces           map[string]bool
	HasNRValid       bool
	NRRsrp           int
	NRRsrq           int
	NRSinr           int
	HasNRRsrq        bool
	HasLTEValid      bool
	LTERsrp          int
	LTERsrq          int
	LTESinr          int
	HasLTERsrq       bool
	IsSA             bool
	IsNSA            bool
	IsLTE            bool
	Is5GA            bool
	IsLTECA          bool
	Carriers         []parsedServingCarrier
	FallbackNRBand   string
	FallbackNRArfcn  int
	FallbackLTEBand  string
	FallbackLTEArfcn int
	FallbackLTEBWMHz int
}

func validRSRP(v int) bool { return v != sigUnavailable && v >= -145 && v <= -40 }
func validRSRQ(v int) bool { return v != sigUnavailable && v >= -30 && v <= 0 }
func validSINR(v int) bool { return v != sigUnavailable && v >= -25 && v <= 50 }

func parseBandsBracket(s string, prefix string) string {
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil && n > 0 && n < 1000 {
			return prefix + strconv.Itoa(n)
		}
	}
	return ""
}

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
		if m := reOperatorLong.FindStringSubmatch(line); m != nil && cur.AlphaLong == "" {
			if v := cleanOperatorToken(m[1]); v != "" {
				cur.AlphaLong = v
			}
		}
		if m := reOperatorShrt.FindStringSubmatch(line); m != nil && cur.AlphaShort == "" {
			if v := cleanOperatorToken(m[1]); v != "" {
				cur.AlphaShort = v
			}
		}
		if m := reOperatorNum.FindStringSubmatch(line); m != nil && cur.MCCMNC == "" {
			cur.MCCMNC = m[1]
		}
		if cur.MCCMNC == "" {
			if m := reMccMncPair.FindStringSubmatch(line); m != nil {
				cur.MCCMNC = m[1] + m[2]
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
					cur.HasNRRsrq = true
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
					cur.HasLTERsrq = true
				}
				if validSINR(sinr) {
					cur.LTESinr = sinr
				}
			}
		}
		for _, am := range reAccessTech.FindAllStringSubmatch(line, -1) {
			tech := strings.ToUpper(strings.TrimSpace(am[1]))
			switch {
			case tech == "NR" || tech == "NR_SA":
				cur.IsSA = true
			case strings.Contains(tech, "LTE"):
				cur.IsLTE = true
				if strings.Contains(tech, "CA") {
					cur.IsLTECA = true
				}
			}
		}
		if reEndcAvail.MatchString(line) || reNrConnected.MatchString(line) {
			cur.IsNSA = true
		}
		for _, dm := range reDispOverride.FindAllStringSubmatch(line, -1) {
			switch dm[1] {
			case "NR_NSA":
				cur.IsNSA = true
			case "NR_ADVANCED", "NR_MMWAVE":
				// 严禁把 SA 下的 NR_ADVANCED (5G-A) 误标为 NSA!
				cur.Is5GA = true
			case "LTE_CA", "LTE_ADVANCED_PRO":
				cur.IsLTECA = true
			}
		}

		// 提取 CellIdentityNr / CellIdentityLte 兜底频段与频点 (防止部分 ROM 清空 PhysicalChannelConfig)
		for _, nrBlk := range reCellIdNr.FindAllString(line, -1) {
			if am := reNrArfcnField.FindStringSubmatch(nrBlk); am != nil {
				if arfcn, err := strconv.Atoi(am[1]); err == nil && arfcn > 0 && arfcn != sigUnavailable {
					cur.FallbackNRArfcn = arfcn
					if b, _ := nrBandFromARFCN(arfcn, cur.MCCMNC); b != "" && cur.FallbackNRBand == "" {
						cur.FallbackNRBand = b
					}
				}
			}
			if bm := reBandsArray.FindStringSubmatch(nrBlk); bm != nil && cur.FallbackNRBand == "" {
				cur.FallbackNRBand = parseBandsBracket(bm[1], "n")
			}
		}
		for _, lteBlk := range reCellIdLte.FindAllString(line, -1) {
			if am := reEarfcnField.FindStringSubmatch(lteBlk); am != nil {
				if earfcn, err := strconv.Atoi(am[1]); err == nil && earfcn >= 0 && earfcn != sigUnavailable {
					cur.FallbackLTEArfcn = earfcn
					if b, _ := lteBandFromEARFCN(earfcn); b != "" && cur.FallbackLTEBand == "" {
						cur.FallbackLTEBand = b
					}
				}
			}
			if bm := reBandsArray.FindStringSubmatch(lteBlk); bm != nil && cur.FallbackLTEBand == "" {
				cur.FallbackLTEBand = parseBandsBracket(bm[1], "B")
			}
			if bwm := reLteBwField.FindStringSubmatch(lteBlk); bwm != nil && cur.FallbackLTEBWMHz == 0 {
				if khz, err := strconv.Atoi(bwm[1]); err == nil && khz >= 1000 && khz <= 100000 {
					cur.FallbackLTEBWMHz = khz / 1000
				}
			}
		}

		// 提取 PhysicalChannelConfigList 中全部主/辅载波 (PrimaryServing + SecondaryServing), 支持 5G-A 2CC/3CC 聚合计算
		if strings.Contains(line, "mConnectionStatus") {
			entries := rePhysChanEntry.FindAllString(line, -1)
			if len(entries) == 0 {
				entries = []string{line}
			}
			// 仅采信最新一行非空的 PhysicalChannelConfigList 快照, 避免历史同槽行重复累加
			var lineCarriers []parsedServingCarrier
			for _, ent := range entries {
				sm := reChanConnStatus.FindStringSubmatch(ent)
				if sm == nil {
					continue
				}
				isPri := sm[1] == "PrimaryServing" || sm[1] == "1"
				isNR := false
				if nm := reChanNetType.FindStringSubmatch(ent); nm != nil {
					isNR = nm[1] == "NR" || nm[1] == "20"
				} else if cur.HasNRValid && !cur.IsLTE {
					isNR = true
				}
				var arfcn, bwMHz int
				if cm := reChanDLArfcn.FindStringSubmatch(ent); cm != nil {
					if v, err := strconv.Atoi(cm[1]); err == nil && v > 0 && v != sigUnavailable {
						arfcn = v
					}
				}
				if bm := reChanDLKhz.FindStringSubmatch(ent); bm != nil {
					if khz, err := strconv.Atoi(bm[1]); err == nil && khz >= 1000 && khz <= 400000 {
						bwMHz = khz / 1000
					}
				}
				bandStr := ""
				if mdm := reChanBand.FindStringSubmatch(ent); mdm != nil {
					if bNum, err := strconv.Atoi(mdm[1]); err == nil && bNum > 0 && bNum < 1000 {
						if isNR {
							bandStr = "n" + strconv.Itoa(bNum)
						} else {
							bandStr = "B" + strconv.Itoa(bNum)
						}
					}
				}
				if bandStr == "" && arfcn > 0 {
					if isNR {
						bandStr, _ = nrBandFromARFCN(arfcn, cur.MCCMNC)
					} else {
						bandStr, _ = lteBandFromEARFCN(arfcn)
					}
				}
				if bandStr != "" || bwMHz > 0 || arfcn > 0 {
					lineCarriers = append(lineCarriers, parsedServingCarrier{
						IsPrimary: isPri,
						IsNR:      isNR,
						Band:      bandStr,
						BWMHz:     bwMHz,
						ARFCN:     arfcn,
					})
				}
			}
			if len(lineCarriers) > 0 {
				cur.Carriers = lineCarriers
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

	// 汇总主载波与多载波聚合信息
	var priBand string
	var priBW, priArfcn, totalBW, nrCount, activeCount int
	var comboParts []string
	wantNR := chosen.HasNRValid

	for _, c := range chosen.Carriers {
		if wantNR && !c.IsNR && !chosen.IsNSA {
			continue
		}
		activeCount++
		if c.IsNR {
			nrCount++
		}
		if c.BWMHz > 0 {
			totalBW += c.BWMHz
		}
		if c.Band != "" {
			comboParts = append(comboParts, c.Band)
		}
		if c.IsPrimary && priBand == "" {
			priBand = c.Band
			priBW = c.BWMHz
			priArfcn = c.ARFCN
		} else if priBand == "" && (!wantNR || c.IsNR) {
			priBand = c.Band
			priBW = c.BWMHz
			priArfcn = c.ARFCN
		}
	}

	// 若 PhysicalChannelConfigList 未给出频段, 启用 CellIdentity NR-ARFCN / EARFCN 兜底反推
	if wantNR {
		if priBand == "" {
			priBand = chosen.FallbackNRBand
		}
		if priArfcn == 0 {
			priArfcn = chosen.FallbackNRArfcn
		}
		if priBand == "" && priArfcn > 0 {
			priBand, _ = nrBandFromARFCN(priArfcn, chosen.MCCMNC)
		}
	} else {
		if priBand == "" {
			priBand = chosen.FallbackLTEBand
		}
		if priArfcn == 0 {
			priArfcn = chosen.FallbackLTEArfcn
		}
		if priBW == 0 {
			priBW = chosen.FallbackLTEBWMHz
		}
		if priBand == "" && priArfcn > 0 {
			priBand, _ = lteBandFromEARFCN(priArfcn)
		}
	}
	if totalBW == 0 && priBW > 0 {
		totalBW = priBW
	}
	if activeCount == 0 && priBand != "" {
		activeCount = 1
	}
	bandCombo := strings.Join(comboParts, "+")
	if bandCombo == "" && priBand != "" {
		bandCombo = priBand
	}

	is5GA := false
	if wantNR && (chosen.Is5GA || nrCount >= 2 || totalBW >= 140) {
		is5GA = true
	}

	carrierFull, carrierShort, sharingMode := normalizeCarrierAndMOCN(
		chosen.AlphaLong, chosen.AlphaShort, chosen.MCCMNC, priBand, bandCombo,
	)

	freqMHz := lookupBandFreqMHz(priBand)
	if freqMHz == 0 && priArfcn > 0 {
		if wantNR {
			_, freqMHz = nrBandFromARFCN(priArfcn, chosen.MCCMNC)
		} else {
			_, freqMHz = lteBandFromEARFCN(priArfcn)
		}
	}

	out := hostSignalStatus{
		Available:     true,
		Mode:          "cellular",
		Is5GA:         is5GA,
		Slot:          chosen.PhoneID + 1,
		SubID:         chosen.SubID,
		Carrier:       carrierFull,
		CarrierShort:  carrierShort,
		MCCMNC:        chosen.MCCMNC,
		SharingMode:   sharingMode,
		UpstreamIface: wantIface,
		Band:          priBand,
		BandwidthMHz:  priBW,
		BandCombo:     bandCombo,
		TotalBWMHz:    totalBW,
		CACount:       activeCount,
		ARFCN:         priArfcn,
		FreqMHz:       freqMHz,
		BandTrait:     describeBandTrait(priBand, bandCombo, totalBW, activeCount, false),
		UpdatedAt:     nowUnix,
	}

	// 强制优先采信有效 NR 载波指标 (规避 mLteAsPrimaryInNrNsa=true 导致的 LTE 锚点假满格)
	hasValidRSRQ := false
	if chosen.HasNRValid {
		out.RSRPdBm = chosen.NRRsrp
		out.RSRQdB = chosen.NRRsrq
		out.SINRdB = chosen.NRSinr
		hasValidRSRQ = chosen.HasNRRsrq
		if chosen.HasLTEValid {
			out.LTERSRPdBm = chosen.LTERsrp
		}
		// 若明确为 SA 且未启用 EN-DC 锚点, RAT 记为 "5G SA", 否则记为 "5G NSA" (100% 保持既有单测兼容);
		// 5G-A 图标展示统一走 DisplayRAT = "5G-A"。
		if chosen.IsSA && !chosen.IsNSA {
			out.RAT = "5G SA"
		} else if chosen.IsSA && !chosen.HasLTEValid {
			out.RAT = "5G SA"
		} else {
			out.RAT = "5G NSA"
		}
		if is5GA {
			out.DisplayRAT = "5G-A"
		} else {
			out.DisplayRAT = out.RAT
		}
	} else {
		out.RSRPdBm = chosen.LTERsrp
		out.RSRQdB = chosen.LTERsrq
		out.SINRdB = chosen.LTESinr
		hasValidRSRQ = chosen.HasLTERsrq
		out.RAT = "4G LTE"
		if chosen.IsLTECA || activeCount >= 2 {
			out.DisplayRAT = "4G+"
		} else {
			out.DisplayRAT = "4G LTE"
		}
	}

	out.Bars, out.Quality, out.QualityCN, out.RFCeilingFactor = scoreCellularSignal4D(
		out.RSRPdBm, out.SINRdB, out.RSRQdB, hasValidRSRQ, strings.HasPrefix(out.RAT, "5G"), is5GA,
	)
	out.RSRPLabel, out.SINRLabel, out.RSRQLabel, out.SpeedPotentialPct, out.SpeedPotentialText = build4DSignalLabels(
		out.RSRPdBm, out.SINRdB, out.RSRQdB, hasValidRSRQ, out.RFCeilingFactor, false, 0,
	)
	out.Diagnosis = "ok"
	out.DiagnosisCN = "蜂窝射频状态已同步"
	return out
}

func scoreCellularSignal(rsrp, sinr int, is5G bool) (bars int, quality, qualityCN string, alpha float64) {
	return scoreCellularSignal4D(rsrp, sinr, -9, false, is5G, false)
}

func scoreCellularSignal4D(rsrp, sinr, rsrq int, hasRSRQ, is5G, is5GA bool) (bars int, quality, qualityCN string, alpha float64) {
	prefix := "4G"
	if is5GA {
		prefix = "5G-A"
	} else if is5G {
		prefix = "5G"
	}
	severeLoad := hasRSRQ && rsrq <= -17

	switch {
	case rsrp >= -88 && sinr >= 13:
		if severeLoad {
			return 3, "good", prefix + " 良好（基站繁忙）", 0.90
		}
		return 4, "excellent", prefix + " 极佳", 1.0
	case rsrp >= -98 && sinr >= 6:
		if severeLoad {
			return 2, "fair", "信号尚可（基站拥塞）", 0.78
		}
		return 3, "good", prefix + " 良好", 0.95
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
	rsrpLbl, sinrLbl, rsrqLbl, spPct, spTxt := build4DSignalLabels(0, 0, 0, false, alpha, true, rssi)
	return hostSignalStatus{
		Available:          true,
		Mode:               "wifi_sta",
		RAT:                "Wi-Fi 中继",
		DisplayRAT:         "Wi-Fi 中继",
		UpstreamIface:      upIf,
		Band:               band,
		BandCombo:          band,
		FreqMHz:            freq,
		BandTrait:          describeBandTrait(band, band, 0, 1, true),
		WifiRSSIdBm:        rssi,
		WifiLinkMbps:       linkMbps,
		RSRPLabel:          rsrpLbl,
		SINRLabel:          sinrLbl,
		RSRQLabel:          rsrqLbl,
		SpeedPotentialPct:  spPct,
		SpeedPotentialText: spTxt,
		Bars:               bars,
		Quality:            q,
		QualityCN:          qCN,
		RFCeilingFactor:    alpha,
		Diagnosis:          "ok",
		DiagnosisCN:        "上游 Wi-Fi 中继状态已同步",
		UpdatedAt:          nowUnix,
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
