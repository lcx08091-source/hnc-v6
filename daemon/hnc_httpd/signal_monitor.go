// signal_monitor.go — HNC v5.38.0: 热点手机自身 5G SA/NSA · 4G LTE · Wi-Fi STA 实时零唤醒信号质量感知与四象限卡顿归因
//
// 技术原理:
//   1. 蜂窝侧零 Modem 唤醒读取: 流式解析 `/system/bin/dumpsys telephony.registry` 内存缓存至 `local logs:` 即提前截断(~2ms),
//      不调用 RIL / 不唤醒基带;
//   2. 攻克 AOSP 12–16 五大解析陷阱:
//      - CellSignalStrengthNr 等号两侧带空格 (`ssRsrp = -95 ssRsrq = -11 ssSinr = 16`), CellSignalStrengthLte 无空格 (`rsrp=-94 rssnr=12`);
//      - 过滤 `2147483647` (CellInfo.UNAVAILABLE);
//      - 双卡通过 PreciseDataConnectionState (`InterfaceName: rmnet_data*` / `ccmni*`) 对齐真实承载热点的物理卡槽, 回退 `mActiveDataSubId`;
//      - 零售 user 版屏蔽 `nrState=****` 时, 结合 `accessNetworkTechnology=NR` (5G SA) 与 `isEnDcAvailable = true` / `overrideNetwork=NR_NSA` + 有效 `ssRsrp` 准确区分 5G SA / 5G NSA / 4G LTE;
//      - 忽略 `mLteAsPrimaryInNrNsa=true` 的虚高 LTE 信号格, 强制优先按真实 NR 载波 RSRP/SINR 计算信号格与空口天花板系数 α_rf;
//   3. Wi-Fi 中继上游支持: 当热点上游为 `wlan0` (STA+AP 并发中继) 时自动读取 `cmd wifi status` RSSI 与协商速率;
//   4. 联动 5G Autorate 与四象限网络健康诊断:
//      - 弱信号边缘基站 (`RSRP <= -110 dBm` 或 `SINR <= 2 dB`) 自动计算 `rf_ceiling_factor` (0.35~1.0) 提前压低 Autorate 探测天花板防队列雪崩;
//      - 发生 5G <-> 4G 制式切换时通知 Autorate 重锚定 `BaseRTTMs`, 避免基线失真导致误锁保底带宽。
package main

import (
	"bufio"
	"context"
	"math"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sigUnavailable    = 2147483647
	sigActiveInterval = 4 * time.Second
	sigCacheTTL       = 3 * time.Second
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
	RSRPdBm         int     `json:"rsrp_dbm,omitempty"`  // NR ssRsrp or LTE rsrp (-140..-44)
	RSRQdB          int     `json:"rsrq_db,omitempty"`   // NR ssRsrq or LTE rsrq (-20..-3)
	SINRdB          int     `json:"sinr_db,omitempty"`   // NR ssSinr or LTE rssnr (-20..40)
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

type signalMonitor struct {
	hncDir string
	mu     sync.RWMutex
	last   hostSignalStatus
	lastAt time.Time
}

func newSignalMonitor(hncDir string) *signalMonitor {
	return &signalMonitor{
		hncDir: hncDir,
		last: hostSignalStatus{
			Mode:            "unknown",
			RAT:             "Unknown",
			Quality:         "unknown",
			QualityCN:       "待采样",
			RFCeilingFactor: 1.0,
			Diagnosis:       "idle",
			DiagnosisCN:     "等待热点流量",
		},
	}
}

func (m *signalMonitor) Snapshot(s *server) hostSignalStatus {
	if s != nil && s.simActive() {
		return simSignalSnapshot(s)
	}
	m.mu.RLock()
	fresh := !m.lastAt.IsZero() && time.Since(m.lastAt) < sigCacheTTL
	cp := m.last
	m.mu.RUnlock()
	if fresh {
		if s != nil {
			enrichSignalDiagnosis(&cp, s)
		}
		return cp
	}
	return m.Refresh(s)
}

func (m *signalMonitor) Refresh(s *server) hostSignalStatus {
	if s != nil && s.simActive() {
		return simSignalSnapshot(s)
	}
	now := time.Now()
	det := readIfaceDetect(m.hncDir)
	upIf := det.TetherUpstream
	if upIf == "" {
		upIf = det.Upstream
	}

	var st hostSignalStatus
	if strings.HasPrefix(upIf, "wlan") && upIf == "wlan0" {
		if out, err := runFastSystemCmd(1500*time.Millisecond, "cmd", "wifi", "status"); err == nil && out != "" {
			st = parseWifiStatusOutput(out, upIf, now.Unix())
		}
	}
	if !st.Available {
		if raw, err := dumpTelephonyRegistryHead(1800 * time.Millisecond); err == nil && raw != "" {
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
	if s != nil {
		enrichSignalDiagnosis(&st, s)
	}

	m.mu.Lock()
	m.last = st
	m.lastAt = now
	m.mu.Unlock()
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
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, binPath, "telephony.registry"))
	cmd.Env = []string{"PATH=/system/bin:/system/xbin:/vendor/bin"}
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
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "local logs:") || lines >= 650 {
			cancel()
			break
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
		lines++
	}
	_ = cmd.Wait()
	return sb.String(), nil
}

func runFastSystemCmd(timeout time.Duration, name string, args ...string) (string, error) {
	return calRunCmd(timeout, name, args...)
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
	force := r.URL.Query().Get("refresh") == "1"
	var snap hostSignalStatus
	if force {
		snap = s.signalCtl.Refresh(s)
	} else {
		snap = s.signalCtl.Snapshot(s)
	}
	writeJSON(w, http.StatusOK, snap)
}
