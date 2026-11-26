// signal_monitor.go — HNC v6.0.0 · Vector: 热点手机自身 5G-A / 5G SA/NSA · 4G LTE · Wi-Fi STA 异步零阻塞全频段信号感知
//
// 技术原理:
//  1. 彻底消灭 HTTP 请求线程同步跑 dumpsys:
//     - Get() / Snapshot() 永不在调用线程内执行外部命令! 缓存未命中或过期时立即返回上一份
//     内存快照(首次尚未采样时返回轻量初始态), 同时通过无阻塞容量为 1 的信号槽唤醒单实例
//     后台协程异步刷新;
//  2. 自适应刷新节拍省掉 70% system_server Binder 唤醒:
//     - 活跃态刷新周期从 3s 调优至 8s, 空闲态(熄屏无面板/无在线设备/热点关闭)放宽至 45s;
//     - 外部命令统一启用进程组隔离(Setpgid + 超时向 -pgid 发 SIGKILL), 杜绝僵尸进程堆积;
//  3. AOSP 12–16 / ColorOS 16 全频段 5G-A 精准解析与 5G Autorate 联动:
//     - 扩大 Scanner 缓冲至 512KB、头部扫描上限放宽至 2500 行(遇 "local logs:" 立即截断, 零 Modem 唤醒);
//     - 精准识别 NR_ADVANCED (5G-A) 图标态与 PrimaryServing + SecondaryServing 多载波聚合 (2CC/3CC) 组合及总带宽;
//     - 当高通/联发科基带隐藏 mBand=0 时, 自动通过 mDownlinkChannelNumber / mNrArfcn / mEarfcn 查 3GPP 频段表反推;
//     - 完整保留既有 JSON 字段语义(RAT 保持 "5G SA"/"5G NSA"/"4G LTE" 零破坏既有单测, 新增 DisplayRAT="5G-A" 等增强字段)。
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	sigUnavailable         = 2147483647
	sigActiveInterval      = 8 * time.Second
	sigIdleInterval        = 45 * time.Second
	sigScreenOffBgInterval = 90 * time.Second
	sigForceMinInterval    = 1500 * time.Millisecond
	sigHistoryCap          = 60
	sigHandoverWindowS     = 300
)

// SignalCarrierInfo 描述主/辅服务载波或 Wi-Fi MLO 活跃链路的频段、带宽、频点/信道与物理小区标识。
type SignalCarrierInfo struct {
	IsPrimary bool   `json:"is_primary"`
	NetType   string `json:"net_type,omitempty"`
	Band      string `json:"band,omitempty"`
	BWMHz     int    `json:"bw_mhz,omitempty"`
	ARFCN     int    `json:"arfcn,omitempty"`
	FreqMHz   int    `json:"freq_mhz,omitempty"`
	Channel   int    `json:"channel,omitempty"`
	LinkMbps  int    `json:"link_mbps,omitempty"`
	RSSIdBm   int    `json:"rssi_dbm,omitempty"`
	PCI       int    `json:"pci,omitempty"`
	HasPCI    bool   `json:"has_pci,omitempty"`
}

// SignalHistoryPoint 描述单次采样的双轨信号历史点(电平 RSRP/RSSI + 信噪比 SINR/RTT)。
type SignalHistoryPoint struct {
	Ts          int64   `json:"ts"`
	RSRPdBm     int     `json:"rsrp_dbm,omitempty"`
	WifiRSSIdBm int     `json:"wifi_rssi_dbm,omitempty"`
	SINRdB      int     `json:"sinr_db"`
	HasSINR     bool    `json:"has_sinr"`
	RSRQdB      int     `json:"rsrq_db,omitempty"`
	PCI         int     `json:"pci,omitempty"`
	HasPCI      bool    `json:"has_pci,omitempty"`
	Band        string  `json:"band,omitempty"`
	RTTMs       float64 `json:"rtt_ms,omitempty"`
}

// SignalInterferenceSource 描述四维射频/空口干扰源中的单个维度量化评估。
type SignalInterferenceSource struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Available  bool   `json:"available"`
	ReasonCode string `json:"reason_code,omitempty"`
	Pct        int    `json:"pct"`
	Level      string `json:"level"`
	Value      string `json:"value"`
	Summary    string `json:"summary"`
}

// SignalSnapshot 为 hostSignalStatus 的导出别名, 保持内外契约一致。
type SignalSnapshot = hostSignalStatus

type hostSignalStatus struct {
	Available          bool    `json:"available"`
	Mode               string  `json:"mode"`                          // "cellular" | "wifi_sta" | "unknown"
	RAT                string  `json:"rat"`                           // 兼容契约: "5G SA" | "5G NSA" | "4G LTE" | "Wi-Fi 中继" | "Unknown"
	DisplayRAT         string  `json:"display_rat,omitempty"`         // 界面展示制式: "5G-A" | "5G SA" | "5G NSA" | "4G+" | "4G LTE" | "Wi-Fi 7 MLO" | "Wi-Fi 中继"
	Is5GA              bool    `json:"is_5ga,omitempty"`              // 是否处于 5G-A (NR_ADVANCED / 多载波聚合 / >=140MHz)
	WifiGen            string  `json:"wifi_gen,omitempty"`            // Wi-Fi 物理代际: "Wi-Fi 4" | "Wi-Fi 5" | "Wi-Fi 6" | "Wi-Fi 6E" | "Wi-Fi 7"
	Slot               int     `json:"slot,omitempty"`                // 1 | 2
	SubID              int     `json:"sub_id,omitempty"`              // active data subId
	Carrier            string  `json:"carrier,omitempty"`             // 归一化运营商全称 (如 "中国移动", "中国广电")
	CarrierShort       string  `json:"carrier_short,omitempty"`       // 顶栏紧凑短名 (如 "移动", "广电", "电信", "联通")
	MCCMNC             string  `json:"mcc_mnc,omitempty"`             // 5~6 位 PLMN (如 "46000", "46015")
	SharingMode        string  `json:"sharing_mode,omitempty"`        // 共建共享提示 (如 "700MHz 移广共建共享", "3.5GHz 电联共建共享")
	UpstreamIface      string  `json:"upstream_iface,omitempty"`      // 如 "rmnet_data2", "ccmni0"
	Band               string  `json:"band,omitempty"`                // 主载波频段: 如 "n41", "n78", "n28", "B3", "5GHz"
	BandwidthMHz       int     `json:"bandwidth_mhz,omitempty"`       // 主载波带宽 (MHz)
	BWMHz              int     `json:"bw_mhz,omitempty"`              // 主载波/主信道频宽别名 (MHz), 与 BandwidthMHz 保持一致
	Channel            int     `json:"channel,omitempty"`             // Wi-Fi 主链路信道号 (如 36, 44, 149, 6, 37)
	BSSIDTag           string  `json:"bssid_tag,omitempty"`           // 上游 Wi-Fi AP/MLD 脱敏短哈希 (绝不暴露明文 MAC)
	BandCombo          string  `json:"band_combo,omitempty"`          // 多载波/多链路组合: 如 "n41+n28", "n78+n78", "5GHz+2.4GHz"
	TotalBWMHz         int     `json:"total_bw_mhz,omitempty"`        // 多载波聚合总带宽 (MHz), 如 130, 200
	CACount            int     `json:"ca_count,omitempty"`            // 活跃聚合载波/链路数 (1..4)
	ARFCN              int     `json:"arfcn,omitempty"`               // 主载波 NR-ARFCN / EARFCN 频点号
	FreqMHz            int     `json:"freq_mhz,omitempty"`            // 主频段近似中心频率 (MHz), 如 2600, 700, 3500
	BandTrait          string  `json:"band_trait,omitempty"`          // 频段物理特性人话解读
	RSRPdBm            int     `json:"rsrp_dbm,omitempty"`            // NR ssRsrp or LTE rsrp (-140..-44)
	RSRQdB             int     `json:"rsrq_db,omitempty"`             // NR ssRsrq or LTE rsrq (-20..-3)
	SINRdB             int     `json:"sinr_db"`                       // NR ssSinr / LTE rssnr / Wi-Fi SNR (-25..50, 显式保留 0 dB)
	LTERSRPdBm         int     `json:"lte_rsrp_dbm,omitempty"`        // NSA 场景下的 LTE 锚点 RSRP
	WifiRSSIdBm        int     `json:"wifi_rssi_dbm,omitempty"`       // Wi-Fi STA RSSI
	WifiLinkMbps       int     `json:"wifi_link_mbps,omitempty"`      // Wi-Fi STA 协商速率
	RSRPLabel          string  `json:"rsrp_label,omitempty"`          // 信号强度人话评级 ("极强"/"良好"/"一般"/"偏弱"/"极弱")
	SINRLabel          string  `json:"sinr_label,omitempty"`          // 信号纯净度人话评级 ("极纯净"/"纯净"/"轻度干扰"/"嘈杂易跳Ping")
	RSRQLabel          string  `json:"rsrq_label,omitempty"`          // 基站空闲度人话评级 ("基站空闲"/"负载正常"/"晚高峰偏忙"/"基站拥塞")
	SpeedPotentialPct  int     `json:"speed_potential_pct,omitempty"` // 网速潜力百分比 (35..100)
	SpeedPotentialText string  `json:"speed_potential_text,omitempty"`
	Bars               int     `json:"bars"`              // 0..4
	Quality            string  `json:"quality"`           // "excellent" | "good" | "fair" | "weak" | "critical" | "unknown"
	QualityCN          string  `json:"quality_cn"`        // 中文健康标签
	RFCeilingFactor    float64 `json:"rf_ceiling_factor"` // α_rf in [0.35, 1.0] for Autorate
	Diagnosis          string  `json:"diagnosis"`         // "ok" | "rf_weak" | "rf_interference" | "congestion" | "lan_bottleneck" | "idle"
	DiagnosisCN        string  `json:"diagnosis_cn"`
	UpdatedAt          int64   `json:"updated_at"`

	// RC2/RC4/RC10 双轨曲线、物理小区标识、载波详情、乒乓切换与四维干扰诊断
	HasSINR             bool                       `json:"has_sinr"`
	HasRSRQ             bool                       `json:"has_rsrq"`
	RSSIdBm             int                        `json:"rssi_dbm,omitempty"`
	PCI                 int                        `json:"pci,omitempty"`
	HasPCI              bool                       `json:"has_pci,omitempty"`
	LTEPCI              int                        `json:"lte_pci,omitempty"`
	HasLTEPCI           bool                       `json:"has_lte_pci,omitempty"`
	LTERSRQdB           int                        `json:"lte_rsrq_db,omitempty"`
	LTESINRdB           int                        `json:"lte_sinr_db"`
	HasLTESINR          bool                       `json:"has_lte_sinr,omitempty"`
	WifiNoiseDbm        int                        `json:"wifi_noise_dbm,omitempty"`
	Carriers            []SignalCarrierInfo        `json:"carriers,omitempty"`
	HandoverCount       int                        `json:"handover_count"`
	JitterdB            int                        `json:"jitter_db"`
	MinDbm              int                        `json:"min_dbm,omitempty"`
	MaxDbm              int                        `json:"max_dbm,omitempty"`
	AvgDbm              int                        `json:"avg_dbm,omitempty"`
	InterferencePct     int                        `json:"interference_pct"`
	InterferenceLevel   string                     `json:"interference_level,omitempty"`
	InterferenceLabel   string                     `json:"interference_label,omitempty"`
	InterferenceSources []SignalInterferenceSource `json:"interference_sources,omitempty"`
	History             []SignalHistoryPoint       `json:"history,omitempty"`
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

	mu          sync.RWMutex
	last        hostSignalStatus
	lastAt      time.Time
	lastForceAt time.Time
	history     [sigHistoryCap]SignalHistoryPoint
	histHead    int
	histLen     int
	handoverTs  []int64
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

// signalTTLForActivity 按系统活跃档位计算信号缓存 TTL:
//   - 明确熄屏(!act.ScreenOn && act.ScreenKnown)或后台带载(lvlBackground)统一放宽至 90s 省电节流档, 严禁落入 8s 高频档;
//   - 热点未开 / 无客户端空闲态为 45s;
//   - 亮屏活跃态为 8s。
func signalTTLForActivity(act Activity) time.Duration {
	if !act.ScreenOn && act.ScreenKnown {
		return sigScreenOffBgInterval
	}
	if act.Known {
		switch act.Level {
		case lvlHotspotOff, lvlNoClients:
			return sigIdleInterval
		case lvlBackground:
			return sigScreenOffBgInterval
		}
	}
	return sigActiveInterval
}

// currentTTL 按系统活跃档位动态返回缓存有效期。
func (m *signalMonitor) currentTTL() time.Duration {
	return signalTTLForActivity(activityNow())
}

func cloneHostSignalStatus(src hostSignalStatus) hostSignalStatus {
	cp := src
	if len(src.Carriers) > 0 {
		cp.Carriers = make([]SignalCarrierInfo, len(src.Carriers))
		copy(cp.Carriers, src.Carriers)
	}
	if len(src.InterferenceSources) > 0 {
		cp.InterferenceSources = make([]SignalInterferenceSource, len(src.InterferenceSources))
		copy(cp.InterferenceSources, src.InterferenceSources)
	}
	if len(src.History) > 0 {
		cp.History = make([]SignalHistoryPoint, len(src.History))
		copy(cp.History, src.History)
	}
	return cp
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
	cp := cloneHostSignalStatus(m.last)
	m.mu.RUnlock()

	if now := time.Now().Unix(); cp.UpdatedAt > 0 && now-cp.UpdatedAt > 600 {
		cp.HandoverCount = 0
		cp.JitterdB = 0
	}
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

// PeekCached 纯内存零唤醒读取最近一次缓存的信号快照, 绝不触发后台 dumpsys 采样协程(供 200ms 黑匣子归因高频读取)。
func (m *signalMonitor) PeekCached(s *server) hostSignalStatus {
	if s != nil && s.hncDir != "" && s.simActive() {
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
	m.mu.RLock()
	cp := cloneHostSignalStatus(m.last)
	m.mu.RUnlock()
	if s != nil && cp.Available {
		enrichSignalDiagnosis(&cp, s)
	}
	return cp
}

// TriggerRefresh 非阻塞触发单实例后台异步刷新(已在途时自动合并, 零排队、零常驻泄漏)。
// 当 force==true 时启用 1500ms lastForceAt 最小防抖间隔保护 system_server。
func (m *signalMonitor) TriggerRefresh(s *server, force bool) {
	if m == nil || m.closed.Load() {
		return
	}
	if !force && m.shouldSuppressBackgroundRefresh() {
		return
	}
	if force {
		now := time.Now()
		m.mu.Lock()
		if !m.lastForceAt.IsZero() && now.Sub(m.lastForceAt) < sigForceMinInterval {
			m.mu.Unlock()
			m.asyncCoalesced.Add(1)
			return
		}
		m.lastForceAt = now
		m.mu.Unlock()
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

// Refresh 执行单次真实采样并更新缓存与 60 点环形历史缓冲(仅供后台异步协程或显式单测内部调用)。
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

	var curRTT float64
	if s != nil && s.autorate != nil {
		ar := s.autorate.Snapshot()
		if ar.Enabled && ar.RTTMs > 0 && !invalidFiniteFloat(ar.RTTMs) {
			curRTT = math.Round(ar.RTTMs*10) / 10
		}
	}

	m.mu.Lock()
	m.recordHistoryLocked(&st, curRTT)
	m.mu.Unlock()

	if s != nil {
		enrichSignalDiagnosis(&st, s)
	} else if st.Available {
		computeInterference4D(&st, autorateStatus{})
	}

	m.mu.Lock()
	m.last = cloneHostSignalStatus(st)
	m.lastAt = now
	m.mu.Unlock()
	return st
}

// recordHistoryLocked 在 m.mu 写锁保护下维护 60 点环形缓冲、跨制式/切卡/切路由清空重置、近 5 分钟乒乓切换统计及极值抖动。
// Copy-on-Write 铁律: 每次导出的 st.History 均为全新 make 切片, 绝不暴露内部数组引用。
func (m *signalMonitor) recordHistoryLocked(st *hostSignalStatus, curRTT float64) {
	if st == nil {
		return
	}
	syncSignalPresenceFlags(st)

	// 检测制式切换、双卡物理槽/订阅切换(Slot/SubID)或上游路由器切换(BSSIDTag): 一旦切换立即清空环形缓冲与切换记录, 根除假乒乓告警
	if st.Mode == "cellular" || st.Mode == "wifi_sta" {
		ctxSwitched := (m.last.Mode == "cellular" || m.last.Mode == "wifi_sta") && m.last.Mode != st.Mode
		if !ctxSwitched && st.Mode == "cellular" && m.last.Mode == "cellular" {
			if (st.Slot > 0 && m.last.Slot > 0 && st.Slot != m.last.Slot) ||
				(st.SubID > 0 && m.last.SubID > 0 && st.SubID != m.last.SubID) {
				ctxSwitched = true
			}
		}
		if !ctxSwitched && st.Mode == "wifi_sta" && m.last.Mode == "wifi_sta" {
			if st.BSSIDTag != "" && m.last.BSSIDTag != "" && st.BSSIDTag != m.last.BSSIDTag {
				ctxSwitched = true
			}
		}
		if !ctxSwitched && m.histLen > 0 {
			lastIdx := (m.histHead - 1 + sigHistoryCap) % sigHistoryCap
			prev := m.history[lastIdx]
			if (st.Mode == "wifi_sta" && prev.RSRPdBm != 0) || (st.Mode == "cellular" && prev.WifiRSSIdBm != 0) {
				ctxSwitched = true
			}
		}
		if ctxSwitched {
			m.history = [sigHistoryCap]SignalHistoryPoint{}
			m.histHead = 0
			m.histLen = 0
			m.handoverTs = nil
		}
	}

	if !st.Available {
		return
	}

	hasValidLevel := (st.Mode == "wifi_sta" && st.WifiRSSIdBm < 0) ||
		(st.Mode != "wifi_sta" && validRSRP(st.RSRPdBm))
	if !hasValidLevel {
		return
	}

	// 蜂窝 PCI 或主频段跳变统计(近 300 秒滑窗, 且与上一采样点相邻间隔 <= 300s 才计切换, 排除长时间休眠后唤醒跨站)
	if st.Mode == "cellular" {
		if m.histLen > 0 {
			prevIdx := (m.histHead - 1 + sigHistoryCap) % sigHistoryCap
			prev := m.history[prevIdx]
			if prev.Ts > 0 && st.UpdatedAt >= prev.Ts && st.UpdatedAt-prev.Ts <= sigHandoverWindowS {
				pciChanged := st.HasPCI && prev.HasPCI && st.PCI != prev.PCI
				bandChanged := st.Band != "" && prev.Band != "" && st.Band != prev.Band
				if pciChanged || bandChanged {
					m.handoverTs = append(m.handoverTs, st.UpdatedAt)
				}
			}
		}
		cutoff := st.UpdatedAt - sigHandoverWindowS
		keep := m.handoverTs[:0]
		for _, ts := range m.handoverTs {
			if ts >= cutoff {
				keep = append(keep, ts)
			}
		}
		m.handoverTs = keep
		st.HandoverCount = len(m.handoverTs)
	} else {
		st.HandoverCount = 0
	}

	sinrVal, hasSINR := effectiveSINR(st)
	rsrqVal, _ := effectiveRSRQ(st)
	pt := SignalHistoryPoint{
		Ts:    st.UpdatedAt,
		Band:  st.Band,
		RTTMs: curRTT,
	}
	if st.Mode == "wifi_sta" {
		pt.WifiRSSIdBm = st.WifiRSSIdBm
		if hasSINR {
			pt.SINRdB = sinrVal
			pt.HasSINR = true
		}
	} else {
		pt.RSRPdBm = st.RSRPdBm
		if hasSINR {
			pt.SINRdB = sinrVal
			pt.HasSINR = true
		}
		pt.RSRQdB = rsrqVal
		if st.HasPCI {
			pt.PCI = st.PCI
			pt.HasPCI = true
		}
	}

	// 剔除 Ts < UpdatedAt-600 的跨天/长休眠过期旧样本(兼容 500s 滑窗单测), 消除 27h 前旧点造成假抖动强干扰
	if m.histLen > 0 && st.UpdatedAt > 600 {
		minTs := st.UpdatedAt - 600
		oldStart := (m.histHead - m.histLen + sigHistoryCap) % sigHistoryCap
		var compacted [sigHistoryCap]SignalHistoryPoint
		kept := 0
		for i := 0; i < m.histLen; i++ {
			item := m.history[(oldStart+i)%sigHistoryCap]
			if item.Ts > 0 && item.Ts < minTs {
				continue
			}
			compacted[kept] = item
			kept++
		}
		if kept < m.histLen {
			m.history = compacted
			m.histLen = kept
			m.histHead = kept % sigHistoryCap
		}
	}

	m.history[m.histHead] = pt
	m.histHead = (m.histHead + 1) % sigHistoryCap
	if m.histLen < sigHistoryCap {
		m.histLen++
	}

	outHist := make([]SignalHistoryPoint, m.histLen)
	startIdx := (m.histHead - m.histLen + sigHistoryCap) % sigHistoryCap
	minDbm, maxDbm, sumDbm, cnt := 0, 0, 0, 0
	for i := 0; i < m.histLen; i++ {
		item := m.history[(startIdx+i)%sigHistoryCap]
		outHist[i] = item
		v := item.RSRPdBm
		if st.Mode == "wifi_sta" {
			v = item.WifiRSSIdBm
		}
		if v < 0 {
			if cnt == 0 || v < minDbm {
				minDbm = v
			}
			if cnt == 0 || v > maxDbm {
				maxDbm = v
			}
			sumDbm += v
			cnt++
		}
	}
	st.History = outHist
	if cnt > 0 {
		st.MinDbm = minDbm
		st.MaxDbm = maxDbm
		st.AvgDbm = int(math.Round(float64(sumDbm) / float64(cnt)))
		st.JitterdB = maxDbm - minDbm
	}
}

// isWifiSTAUpstream 判断热点当前上游是否为 Wi-Fi STA 中继链路(排除本地下行热点 AP 自身接口)。
func isWifiSTAUpstream(det ifaceDetect, upIf string) bool {
	up := strings.TrimPrefix(strings.TrimSpace(upIf), "v4-")
	ap := strings.TrimSpace(det.Iface)
	if up != "" && ap != "" && up == ap {
		return false
	}
	isCellIface := strings.HasPrefix(up, "rmnet") ||
		strings.HasPrefix(up, "ccmni") ||
		strings.HasPrefix(up, "seth") ||
		strings.HasPrefix(up, "pdp") ||
		strings.HasPrefix(up, "clat")
	if strings.EqualFold(strings.TrimSpace(det.UpstreamClass), "wifi") && !isCellIface {
		return true
	}
	if up != "" && (strings.HasPrefix(up, "wlan") || strings.HasPrefix(up, "sta")) {
		return true
	}
	return false
}

func sampleWifiSTASignal(upIf, apIface string, nowUnix int64, runWifiCmd func() (string, error), readWireless func() (string, error)) hostSignalStatus {
	var st hostSignalStatus
	if runWifiCmd != nil {
		if out, err := runWifiCmd(); err == nil && out != "" {
			st = parseWifiStatusOutput(out, upIf, nowUnix)
		}
	}
	// 若 cmd wifi status 已成功但缺少底噪, 顺手尝试从 /proc/net/wireless 补齐 WifiNoiseDbm 与 SNR;
	// 若 cmd wifi status 失败, 则完整用 /proc/net/wireless 兜底提取 RSSI 与 Noise。
	if readWireless != nil {
		if raw, err := readWireless(); err == nil && raw != "" {
			fb := parseProcNetWireless(raw, upIf, apIface, nowUnix)
			if !st.Available && fb.Available {
				st = fb
			} else if st.Available && fb.Available {
				if st.WifiNoiseDbm == 0 && fb.WifiNoiseDbm < 0 {
					st.WifiNoiseDbm = fb.WifiNoiseDbm
				}
				if !st.HasSINR && validWifiNoise(st.WifiNoiseDbm) {
					snr := st.WifiRSSIdBm - st.WifiNoiseDbm
					if validSINR(snr) {
						st.SINRdB = snr
						st.HasSINR = true
						st.RSRPLabel, st.SINRLabel, st.RSRQLabel, st.SpeedPotentialPct, st.SpeedPotentialText = build4DSignalLabels(
							0, st.SINRdB, 0, true, false, st.RFCeilingFactor, true, st.WifiRSSIdBm,
						)
					}
				}
				if st.UpstreamIface == "" {
					st.UpstreamIface = fb.UpstreamIface
				}
				computeInterference4D(&st, autorateStatus{})
			}
		}
	}
	if st.Available {
		return st
	}
	// 严禁回退蜂窝基带 dumpTelephonyRegistryHead, 避免 Wi-Fi STA 串台显示 SIM 卡信号!
	return hostSignalStatus{
		Available:       false,
		Mode:            "wifi_sta",
		RAT:             "Wi-Fi 中继",
		DisplayRAT:      "Wi-Fi 中继",
		UpstreamIface:   upIf,
		Bars:            0,
		Quality:         "unknown",
		QualityCN:       "Wi-Fi 状态待读取",
		RFCeilingFactor: 1.0,
		Diagnosis:       "idle",
		DiagnosisCN:     "上游为 Wi-Fi 中继模式，暂未读取到无线网卡信号指标",
		UpdatedAt:       nowUnix,
	}
}

func sigCachedSlotSubIDs(s *server) map[int]int {
	if s == nil {
		return nil
	}
	pu := s.phoneUsage()
	if pu == nil {
		return nil
	}
	_, present, _ := pu.simTopologySnapshot()
	if len(present) == 0 {
		return nil
	}
	out := make(map[int]int, len(present))
	for slot, info := range present {
		if slot >= 1 && sigValidSubID(info.SubID) {
			out[slot] = info.SubID
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (m *signalMonitor) sampleHostSignal(s *server) hostSignalStatus {
	now := time.Now()
	det := readIfaceDetect(m.hncDir)
	upIf := strings.TrimPrefix(strings.TrimSpace(det.TetherUpstream), "v4-")
	if upIf == "" {
		upIf = strings.TrimPrefix(strings.TrimSpace(det.Upstream), "v4-")
	}

	// Wi-Fi STA 上游独立通道: 即使桥接熔断也可走 /proc/net/wireless 零 Binder 纯文件兜底, 且绝不回退蜂窝!
	var bridge *Bulkhead
	if s != nil {
		bridge = s.CoreHub().AndroidBridgeBulkhead
	}
	if isWifiSTAUpstream(det, upIf) {
		var wifiCmdFn func() (string, error)
		if bridge == nil || bridge.CircuitState() != "open" {
			wifiCmdFn = func() (string, error) {
				return runFastSystemCmd(1500*time.Millisecond, "cmd", "wifi", "status")
			}
		}
		return sampleWifiSTASignal(
			upIf,
			det.Iface,
			now.Unix(),
			wifiCmdFn,
			func() (string, error) {
				b, err := os.ReadFile("/proc/net/wireless")
				return string(b), err
			},
		)
	}

	// 蜂窝路径: 若服务器已挂载 AndroidBridgeBulkhead, 先检查熔断器状态保护 system_server。
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

	slotSubIDs := sigCachedSlotSubIDs(s)
	var st hostSignalStatus
	if bridge != nil {
		var raw string
		_ = bridge.Execute(context.Background(), 1800*time.Millisecond, func(ctx context.Context) error {
			var derr error
			raw, derr = dumpTelephonyRegistryHeadCtx(ctx, 1800*time.Millisecond)
			return derr
		})
		if raw != "" {
			st = parseTelephonyRegistryDumpWithSubMap(raw, upIf, now.Unix(), slotSubIDs)
		}
	} else if raw, err := dumpTelephonyRegistryHead(1800 * time.Millisecond); err == nil && raw != "" {
		st = parseTelephonyRegistryDumpWithSubMap(raw, upIf, now.Unix(), slotSubIDs)
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
	nowUnix := time.Now().Unix()
	rsrpLbl, sinrLbl, rsrqLbl, spPct, spTxt := build4DSignalLabels(-84, 21, -8, true, true, 1.0, false, 0)
	carriers := []SignalCarrierInfo{
		{IsPrimary: true, NetType: "NR", Band: "n41", BWMHz: 100, ARFCN: 504990, FreqMHz: 2600, PCI: 312, HasPCI: true},
		{IsPrimary: false, NetType: "NR", Band: "n28", BWMHz: 30, ARFCN: 154570, FreqMHz: 700, PCI: 108, HasPCI: true},
	}
	rsrpWave := [8]int{-85, -84, -83, -82, -84, -85, -86, -84}
	sinrWave := [8]int{20, 21, 22, 23, 21, 20, 19, 21}
	rttWave := [8]float64{19.4, 18.8, 18.5, 19.1, 20.2, 21.0, 19.8, 18.9}
	const simPts = 24
	hist := make([]SignalHistoryPoint, simPts)
	minDbm, maxDbm, sumDbm := 0, 0, 0
	for i := 0; i < simPts; i++ {
		idx := i % len(rsrpWave)
		if i == simPts-1 {
			idx = 7
		}
		rv := rsrpWave[idx]
		hist[i] = SignalHistoryPoint{
			Ts:      nowUnix - int64((simPts-1-i)*8),
			RSRPdBm: rv,
			SINRdB:  sinrWave[idx],
			HasSINR: true,
			RSRQdB:  -8,
			PCI:     312,
			HasPCI:  true,
			Band:    "n41",
			RTTMs:   rttWave[idx],
		}
		if i == 0 || rv < minDbm {
			minDbm = rv
		}
		if i == 0 || rv > maxDbm {
			maxDbm = rv
		}
		sumDbm += rv
	}
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
		BWMHz:              100,
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
		UpdatedAt:          nowUnix,
		HasSINR:            true,
		HasRSRQ:            true,
		PCI:                312,
		HasPCI:             true,
		Carriers:           carriers,
		HandoverCount:      0,
		JitterdB:           maxDbm - minDbm,
		MinDbm:             minDbm,
		MaxDbm:             maxDbm,
		AvgDbm:             int(math.Round(float64(sumDbm) / float64(simPts))),
		History:            hist,
	}
	computeInterference4D(&st, autorateStatus{})
	if s != nil {
		enrichSignalDiagnosis(&st, s)
	}
	return st
}

// syncSignalPresenceFlags 同步信号存在性布尔位与别名字段:
//   - 当 Wi-Fi STA 有真实底噪(WifiNoiseDbm < 0)时自动计算 SNR = RSSI - Noise(含 0 dB)并置 HasSINR=true;
//   - 当 SINRdB / LTESINRdB 有效(含 0 dB)时同步置 HasSINR=true, 同时兼容旧单测未填字面量(全零且无 Has* 标记时保 false);
//   - 保持 BandwidthMHz 与 BWMHz 双向一致。
func syncSignalPresenceFlags(st *hostSignalStatus) {
	if st == nil {
		return
	}
	if st.BWMHz == 0 && st.BandwidthMHz > 0 {
		st.BWMHz = st.BandwidthMHz
	} else if st.BandwidthMHz == 0 && st.BWMHz > 0 {
		st.BandwidthMHz = st.BWMHz
	}
	if st.Mode == "wifi_sta" && !st.HasSINR && st.SINRdB == 0 && st.WifiRSSIdBm < 0 && validWifiNoise(st.WifiNoiseDbm) {
		cand := st.WifiRSSIdBm - st.WifiNoiseDbm
		if validSINR(cand) {
			st.SINRdB = cand
			st.HasSINR = true
		}
	}
	if !st.HasLTESINR && st.LTESINRdB != 0 && validSINR(st.LTESINRdB) {
		st.HasLTESINR = true
	}
	if !st.HasSINR && st.SINRdB != 0 && validSINR(st.SINRdB) {
		st.HasSINR = true
	}
	if !st.HasSINR && st.HasLTESINR && validSINR(st.LTESINRdB) {
		st.SINRdB = st.LTESINRdB
		st.HasSINR = true
	}
	if !st.HasRSRQ && st.RSRQdB != 0 && validRSRQ(st.RSRQdB) {
		st.HasRSRQ = true
	}
}

// effectiveSINR 读取有效 SINR/SNR(含真实 0 dB), 同时兼容未设 HasSINR 的旧测试字面量。
func effectiveSINR(st *hostSignalStatus) (int, bool) {
	if st == nil {
		return 0, false
	}
	syncSignalPresenceFlags(st)
	if st.HasSINR && validSINR(st.SINRdB) {
		return st.SINRdB, true
	}
	return 0, false
}

// effectiveRSRQ 读取有效 RSRQ(含 0 dB), 同时兼容未设 HasRSRQ 的旧测试字面量。
func effectiveRSRQ(st *hostSignalStatus) (int, bool) {
	if st == nil {
		return 0, false
	}
	syncSignalPresenceFlags(st)
	if st.HasRSRQ && validRSRQ(st.RSRQdB) {
		return st.RSRQdB, true
	}
	return 0, false
}

func sigClampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func interferenceLevelFromPct(pct int) (level, label string) {
	p := sigClampInt(pct, 0, 100)
	switch {
	case p >= 75:
		return "severe", "强干扰易跳Ping"
	case p >= 50:
		return "moderate", "中度射频干扰"
	case p >= 25:
		return "mild", "轻度环境干扰"
	default:
		return "clean", "信道纯净低噪"
	}
}

// buildSignalInterferenceSources 构建四维真实射频/空口干扰源评估切片。
// 铁律: 当底层指标(蜂窝 SINR/RSRQ、Wi-Fi Noise/LinkMbps、多点电平差分、Autorate 真实 RTT)不可读或未开启探测时,
// 如实返回 Available: false, Pct: 0, ReasonCode: "metric_unavailable" / "probe_disabled", 严禁伪造任何固定基础百分比!
func buildSignalInterferenceSources(st *hostSignalStatus, ar autorateStatus) []SignalInterferenceSource {
	sinrVal, hasSINR := effectiveSINR(st)
	rsrqVal, hasRSRQ := effectiveRSRQ(st)

	sources := make([]SignalInterferenceSource, 4)

	// 1. co_channel: 同频与邻区底噪干扰 (仅依赖真实蜂窝 SINR 或真实 Wi-Fi RSSI-Noise 信噪比, 含 0 dB!)
	if st.Mode == "wifi_sta" {
		var snr int
		var hasWifiSNR bool
		if st.WifiNoiseDbm < 0 && st.WifiRSSIdBm < 0 {
			cand := st.WifiRSSIdBm - st.WifiNoiseDbm
			if validSINR(cand) {
				snr, hasWifiSNR = cand, true
			}
		} else if hasSINR {
			snr, hasWifiSNR = sinrVal, true
		}
		if hasWifiSNR {
			var coPct int
			switch {
			case snr >= 40:
				coPct = 0
			case snr >= 30:
				coPct = 40 - snr
			case snr >= 20:
				coPct = sigClampInt(25+(29-snr)*2, 25, 48)
			case snr >= 12:
				coPct = sigClampInt(52+(19-snr)*3, 50, 74)
			default:
				coPct = sigClampInt(78+(11-snr)*3, 75, 98)
			}
			coLvl, _ := interferenceLevelFromPct(coPct)
			var coSum string
			switch {
			case coPct >= 75:
				coSum = "Wi-Fi 信道底噪极高或同频路由严重拥挤，建议切换至 5GHz 低干扰信道"
			case coPct >= 50:
				coSum = "周边存在明显邻道 Wi-Fi 争抢，吞吐波动偏大"
			case coPct >= 25:
				coSum = "存在轻度同频 Wi-Fi 共享环境底噪，整体连接可用"
			default:
				coSum = "无线回传信道底噪干净，信噪比充裕"
			}
			sources[0] = SignalInterferenceSource{
				ID:        "co_channel",
				Name:      "同频与底噪干扰",
				Available: true,
				Pct:       coPct,
				Level:     coLvl,
				Value:     "SNR " + strconv.Itoa(snr) + " dB",
				Summary:   coSum,
			}
		} else {
			sources[0] = SignalInterferenceSource{
				ID:         "co_channel",
				Name:       "同频与底噪干扰",
				Available:  false,
				ReasonCode: "metric_unavailable",
				Pct:        0,
				Level:      "unavailable",
				Value:      "底噪未上报",
				Summary:    "当前无线网卡驱动未上报信道底噪（Noise），不作同频干扰估算",
			}
		}
	} else if hasSINR {
		var coPct int
		switch {
		case sinrVal >= 30:
			coPct = 0
		case sinrVal >= 20:
			coPct = 30 - sinrVal
		case sinrVal >= 13:
			coPct = sigClampInt(12+(20-sinrVal)*10/7, 12, 23)
		case sinrVal >= 6:
			coPct = sigClampInt(30+(13-sinrVal)*15/7, 28, 48)
		case sinrVal >= 3:
			coPct = sigClampInt(52+(6-sinrVal)*6, 52, 70)
		case sinrVal >= 0:
			coPct = sigClampInt(76+(3-sinrVal)*4, 76, 88)
		default:
			coPct = sigClampInt(88+(-sinrVal)*2, 88, 100)
		}
		coLvl, _ := interferenceLevelFromPct(coPct)
		var coSum string
		switch {
		case coPct >= 75:
			coSum = "邻区同频强串扰导致信噪比极低，易丢包跳Ping，建议移至靠窗开阔处"
		case coPct >= 50:
			coSum = "周边基站同频与隔墙干扰明显，高阶调制受限，建议避开墙体遮挡"
		case coPct >= 25:
			coSum = "存在轻度同频或隔墙环境底噪干扰，移至窗边可提升空口纯净度"
		default:
			coSum = "主载波信噪比优良，同频串扰极低"
		}
		sources[0] = SignalInterferenceSource{
			ID:        "co_channel",
			Name:      "同频与底噪干扰",
			Available: true,
			Pct:       coPct,
			Level:     coLvl,
			Value:     "SINR " + strconv.Itoa(sinrVal) + " dB",
			Summary:   coSum,
		}
	} else {
		sources[0] = SignalInterferenceSource{
			ID:         "co_channel",
			Name:       "同频与底噪干扰",
			Available:  false,
			ReasonCode: "metric_unavailable",
			Pct:        0,
			Level:      "unavailable",
			Value:      "基带未上报",
			Summary:    "当前基带未上报实时 SINR 信噪比，不作估算",
		}
	}

	// 2. cell_load: 基站扇区或无线信道负载 (仅依赖真实蜂窝 RSRQ 或真实 Wi-Fi 物理协商速率)
	if st.Mode == "wifi_sta" {
		if st.WifiLinkMbps > 0 {
			var loadPct int
			switch {
			case st.WifiLinkMbps >= 600:
				loadPct = 0
			case st.WifiLinkMbps >= 300:
				loadPct = (600 - st.WifiLinkMbps) * 15 / 300
			case st.WifiLinkMbps >= 144:
				loadPct = 15 + (300-st.WifiLinkMbps)*15/156
			case st.WifiLinkMbps > 72:
				loadPct = 30 + (144-st.WifiLinkMbps)*22/72
			default:
				loadPct = sigClampInt(55+(72-st.WifiLinkMbps)*25/72, 55, 85)
			}
			loadLvl, _ := interferenceLevelFromPct(loadPct)
			loadSum := "上游路由器物理握手速率正常"
			if loadPct >= 50 {
				loadSum = "本地 Wi-Fi 物理协商速率偏低，空口占空比受限"
			}
			sources[1] = SignalInterferenceSource{
				ID:        "cell_load",
				Name:      "基站信道负载",
				Available: true,
				Pct:       loadPct,
				Level:     loadLvl,
				Value:     strconv.Itoa(st.WifiLinkMbps) + " Mbps",
				Summary:   loadSum,
			}
		} else {
			sources[1] = SignalInterferenceSource{
				ID:         "cell_load",
				Name:       "基站信道负载",
				Available:  false,
				ReasonCode: "metric_unavailable",
				Pct:        0,
				Level:      "unavailable",
				Value:      "速率未上报",
				Summary:    "当前系统未上报无线物理握手速率，不作负载估算",
			}
		}
	} else if hasRSRQ {
		var loadPct int
		switch {
		case rsrqVal >= -6:
			loadPct = 0
		case rsrqVal >= -12:
			loadPct = (-6 - rsrqVal) * 22 / 6
		case rsrqVal >= -15:
			loadPct = sigClampInt(30+(-13-rsrqVal)*8, 30, 46)
		case rsrqVal >= -17:
			loadPct = sigClampInt(56+(-16-rsrqVal)*12, 56, 70)
		default:
			loadPct = sigClampInt(80+(-18-rsrqVal)*4, 78, 96)
		}
		loadLvl, _ := interferenceLevelFromPct(loadPct)
		var loadSum string
		switch {
		case loadPct >= 75:
			loadSum = "当前基站扇区资源块重度拥塞，多用户密集争抢空口时隙"
		case loadPct >= 50:
			loadSum = "基站扇区晚高峰负载偏忙，网速上限可能随并发波动"
		case loadPct >= 25:
			loadSum = "基站存在日常共享负载，空口调度基本顺畅"
		default:
			loadSum = "基站扇区资源充裕，空口时隙空闲"
		}
		sources[1] = SignalInterferenceSource{
			ID:        "cell_load",
			Name:      "基站信道负载",
			Available: true,
			Pct:       loadPct,
			Level:     loadLvl,
			Value:     "RSRQ " + strconv.Itoa(rsrqVal) + " dB",
			Summary:   loadSum,
		}
	} else {
		sources[1] = SignalInterferenceSource{
			ID:         "cell_load",
			Name:       "基站信道负载",
			Available:  false,
			ReasonCode: "metric_unavailable",
			Pct:        0,
			Level:      "unavailable",
			Value:      "基带未上报",
			Summary:    "当前基带未上报实时 RSRQ 接收质量，不作负载估算",
		}
	}

	// 3. multipath_fading: 多径衰落与乒乓切换 (零基础常数: 0 dB 抖动且无切换无边缘衰落即为 0%)
	var jitterScore, hoScore, fadeScore int
	hasMultiSample := len(st.History) >= 2 || st.JitterdB > 0 || st.HandoverCount > 0
	if hasMultiSample {
		switch {
		case st.JitterdB <= 0:
			jitterScore = 0
		case st.JitterdB <= 3:
			jitterScore = st.JitterdB * 5
		case st.JitterdB <= 6:
			jitterScore = 20 + (st.JitterdB-4)*3
		case st.JitterdB <= 10:
			jitterScore = 32 + (st.JitterdB-7)*5
		case st.JitterdB <= 15:
			jitterScore = 52 + (st.JitterdB-11)*5
		default:
			jitterScore = sigClampInt(76+(st.JitterdB-16)*3, 76, 98)
		}
	}
	if st.Mode == "cellular" {
		switch {
		case st.HandoverCount >= 3:
			hoScore = sigClampInt(78+(st.HandoverCount-3)*6, 78, 98)
		case st.HandoverCount == 2:
			hoScore = 52
		case st.HandoverCount == 1:
			hoScore = 28
		}
		if validRSRP(st.RSRPdBm) {
			switch {
			case st.RSRPdBm <= -115:
				fadeScore = 72
			case st.RSRPdBm <= -108:
				fadeScore = 46
			case st.RSRPdBm <= -100:
				fadeScore = 26
			}
			if hasSINR && sinrVal < 10 && st.RSRPdBm < -88 && fadeScore < 26 {
				fadeScore = 26
			}
		}
	} else if st.WifiRSSIdBm < 0 {
		switch {
		case st.WifiRSSIdBm <= -82:
			fadeScore = 64
		case st.WifiRSSIdBm <= -74:
			fadeScore = 34
		}
	}
	if !hasMultiSample && fadeScore == 0 {
		sources[2] = SignalInterferenceSource{
			ID:         "multipath_fading",
			Name:       "多径衰落与切换",
			Available:  false,
			ReasonCode: "metric_unavailable",
			Pct:        0,
			Level:      "unavailable",
			Value:      "采样积累中",
			Summary:    "需至少 2 次连续信号采样方可计算真实电平波动与乒乓切换",
		}
	} else {
		mpPct := jitterScore
		if hoScore > mpPct {
			mpPct = hoScore
		}
		if fadeScore > mpPct {
			mpPct = fadeScore
		}
		mpPct = sigClampInt(mpPct, 0, 100)
		mpLvl, _ := interferenceLevelFromPct(mpPct)
		var mpVal, mpSum string
		if st.Mode == "cellular" {
			mpVal = "波动 " + strconv.Itoa(st.JitterdB) + " dB · 切换 " + strconv.Itoa(st.HandoverCount) + " 次/5m"
		} else {
			mpVal = "波动 " + strconv.Itoa(st.JitterdB) + " dB"
		}
		switch {
		case st.Mode == "cellular" && st.HandoverCount >= 3:
			mpSum = "近 5 分钟发生 " + strconv.Itoa(st.HandoverCount) + " 次基站/频段乒乓切换，建议固定手机位置避免跨区摇摆"
		case st.JitterdB >= 10:
			mpSum = "信号电平起伏达 " + strconv.Itoa(st.JitterdB) + " dB，存在遮挡反射或移动多径衰落"
		case mpPct >= 25:
			mpSum = "存在墙体遮挡衰减或轻微多径波动，靠近窗边摆放更稳"
		default:
			mpSum = "驻留小区稳定，电平曲线平滑无乒乓切换"
		}
		sources[2] = SignalInterferenceSource{
			ID:        "multipath_fading",
			Name:      "多径衰落与切换",
			Available: true,
			Pct:       mpPct,
			Level:     mpLvl,
			Value:     mpVal,
			Summary:   mpSum,
		}
	}

	// 4. bufferbloat: 空口排队与延迟膨胀 (探测关闭返 probe_disabled, 无有效 RTT 返 metric_unavailable)
	if !ar.Enabled {
		sources[3] = SignalInterferenceSource{
			ID:         "bufferbloat",
			Name:       "空口排队膨胀",
			Available:  false,
			ReasonCode: "probe_disabled",
			Pct:        0,
			Level:      "unavailable",
			Value:      "探测未开启",
			Summary:    "自适应带宽 RTT 探测未开启，暂不评估空口排队抖动",
		}
	} else if (ar.RTTMs <= 0 && ar.DeltaRTTMs <= 0) || invalidFiniteFloat(ar.DeltaRTTMs) {
		sources[3] = SignalInterferenceSource{
			ID:         "bufferbloat",
			Name:       "空口排队膨胀",
			Available:  false,
			ReasonCode: "metric_unavailable",
			Pct:        0,
			Level:      "unavailable",
			Value:      "待采样",
			Summary:    "RTT 探测尚未采集到有效时延增量样本，不作估算",
		}
	} else {
		thr := math.Max(20, ar.RTTDeltaMs)
		ratio := 0.0
		if ar.DeltaRTTMs > 0 {
			ratio = ar.DeltaRTTMs / thr
		}
		var bloatPct int
		switch {
		case ratio <= 0:
			bloatPct = 0
		case ratio <= 0.35:
			bloatPct = sigClampInt(int(math.Round(ratio*55)), 0, 20)
		case ratio < 1.0:
			bloatPct = sigClampInt(int(math.Round(25+(ratio-0.35)/0.65*23)), 25, 48)
		case ratio < 1.8:
			bloatPct = sigClampInt(int(math.Round(52+(ratio-1.0)/0.8*22)), 52, 74)
		default:
			bloatPct = sigClampInt(int(math.Round(76+(ratio-1.8)*15)), 76, 98)
		}
		bloatLvl, _ := interferenceLevelFromPct(bloatPct)
		bloatVal := "+" + strconv.FormatFloat(math.Max(0, ar.DeltaRTTMs), 'f', 1, 64) + " ms"
		var bloatSum string
		switch {
		case bloatPct >= 50:
			bloatSum = "空口队列积压导致 RTT 明显抬升，智能带宽正在主动削峰稳延迟"
		case bloatPct >= 25:
			bloatSum = "大流量突发引起轻微空口排队波动，整体延迟受控"
		default:
			bloatSum = "空口转发时延紧贴基线，无队列膨胀积压"
		}
		sources[3] = SignalInterferenceSource{
			ID:        "bufferbloat",
			Name:      "空口排队膨胀",
			Available: true,
			Pct:       bloatPct,
			Level:     bloatLvl,
			Value:     bloatVal,
			Summary:   bloatSum,
		}
	}

	return sources
}

// computeInterference4D 计算四维干扰源(同频底噪 / 基站负载 / 多径切换 / 空口排队)及峰值加权总干扰指数。
// Copy-on-Write 铁律: 每次调用总是 make 全新 []SignalInterferenceSource 切片, 绝不原地修改已发布切片!
func computeInterference4D(st *hostSignalStatus, ar autorateStatus) {
	if st == nil || !st.Available {
		return
	}
	sources := buildSignalInterferenceSources(st, ar)

	// 仅对真实可读(Available == true)的维度执行峰值加权合成
	var availPcts []int
	for _, src := range sources {
		if src.Available {
			availPcts = append(availPcts, src.Pct)
		}
	}
	if len(availPcts) == 0 {
		st.InterferencePct = 0
		st.InterferenceLevel = "unavailable"
		st.InterferenceLabel = "指标未上报"
		st.InterferenceSources = sources
		return
	}
	for i := 0; i < len(availPcts)-1; i++ {
		for j := i + 1; j < len(availPcts); j++ {
			if availPcts[j] > availPcts[i] {
				availPcts[i], availPcts[j] = availPcts[j], availPcts[i]
			}
		}
	}
	var boost float64
	if len(availPcts) >= 2 {
		boost += 0.18 * math.Max(0, float64(availPcts[1]-12))
	}
	if len(availPcts) >= 3 {
		boost += 0.10 * math.Max(0, float64(availPcts[2]-12))
	}
	if len(availPcts) >= 4 {
		boost += 0.06 * math.Max(0, float64(availPcts[3]-12))
	}
	totalPct := sigClampInt(int(math.Round(float64(availPcts[0])+boost)), 0, 100)
	totLvl, totLbl := interferenceLevelFromPct(totalPct)

	st.InterferencePct = totalPct
	st.InterferenceLevel = totLvl
	st.InterferenceLabel = totLbl
	st.InterferenceSources = sources
}

func enrichSignalDiagnosis(st *hostSignalStatus, s *server) {
	if st == nil || !st.Available {
		return
	}
	var ar autorateStatus
	if s != nil && s.autorate != nil {
		ar = s.autorate.Snapshot()
	}
	computeInterference4D(st, ar)
	if s == nil {
		return
	}

	sinrVal, hasSINR := effectiveSINR(st)
	rsrqVal, hasRSRQ := effectiveRSRQ(st)
	weakRF := st.Quality == "weak" || st.Quality == "critical"
	cellBusy := st.Mode == "cellular" && hasRSRQ && rsrqVal <= -17
	bloated := ar.Enabled && ar.DeltaRTTMs > math.Max(20, ar.RTTDeltaMs)
	severeCellInterf := st.Mode == "cellular" && ((hasSINR && sinrVal < 3) || st.HandoverCount >= 3)
	mildModCellInterf := st.Mode == "cellular" && hasSINR && sinrVal < 13
	thermo := s.peekThermoQuickState()
	lanSat := ar.Enabled && (ar.State == "active" || ar.State == "backoff") && (ar.LoadDown >= 0.88 || ar.LoadUp >= 0.88)
	if !lanSat {
		var rxSum, txSum int64
		s.rateMu.Lock()
		for _, v := range s.rates {
			if v.rxBps > 0 {
				rxSum += v.rxBps
			}
			if v.txBps > 0 {
				txSum += v.txBps
			}
		}
		s.rateMu.Unlock()
		if rxSum > 0 || txSum > 0 {
			downCap, upCap := s.peekCachedStaticGlobalShaperBps()
			if (downCap > 0 && float64(rxSum)/float64(downCap) >= 0.88) ||
				(upCap > 0 && float64(txSum)/float64(upCap) >= 0.88) {
				lanSat = true
			}
		}
	}
	wifiLinkLow := st.Mode == "wifi_sta" && st.WifiLinkMbps > 0 && st.WifiLinkMbps <= 72

	switch {
	case weakRF && bloated:
		st.Diagnosis = "rf_weak"
		st.DiagnosisCN = "热点机处于弱信号边缘区且空口排队膨胀，智能带宽已联动收紧上限稳住延迟"
	case weakRF:
		st.Diagnosis = "rf_weak"
		st.DiagnosisCN = "热点机当前基站信号偏弱（建议移至窗边），已启用弱网防断流保护"
	case severeCellInterf:
		st.Diagnosis = "rf_interference"
		switch {
		case st.HandoverCount >= 3 && hasSINR && sinrVal < 3:
			st.DiagnosisCN = "手机信号格数尚可，但存在强同频干扰（SINR " + strconv.Itoa(sinrVal) + " dB）且近 5 分钟频繁切换基站 " + strconv.Itoa(st.HandoverCount) + " 次，建议移至靠窗固定位置"
		case st.HandoverCount >= 3:
			st.DiagnosisCN = "手机近 5 分钟发生 " + strconv.Itoa(st.HandoverCount) + " 次基站/频段乒乓切换，跨区摇摆易引起瞬时跳Ping，建议移至窗边固定摆放"
		default:
			st.DiagnosisCN = "手机信号强度尚可，但同频与邻区强射频干扰严重（SINR " + strconv.Itoa(sinrVal) + " dB），空口重传率高易跳Ping，建议将热点机移至窗边开阔处"
		}
	case bloated || cellBusy:
		st.Diagnosis = "congestion"
		if bloated {
			st.DiagnosisCN = "手机信号强度充足，但基站当前上网人数多（排队延迟升高），智能带宽正在自动稳帧"
		} else {
			st.DiagnosisCN = "手机信号格数充足，但当前基站信道负载偏忙，高峰期网速可能略有波动"
		}
	case thermo.Stage2ShaperActive || lanSat || wifiLinkLow:
		st.Diagnosis = "lan_bottleneck"
		switch {
		case thermo.Stage2ShaperActive:
			st.DiagnosisCN = "上游基站信号正常，当前受手机高温二阶温控保护限制热点总带宽"
		case wifiLinkLow:
			st.DiagnosisCN = "上游信号强度尚可，但本地 Wi-Fi 物理握手速率偏低，建议切换至 5GHz 频段"
		default:
			st.DiagnosisCN = "上游基站空口通畅，当前热点局域网带宽池已被连接设备跑满"
		}
	case mildModCellInterf:
		st.Diagnosis = "rf_interference"
		if sinrVal < 6 {
			st.DiagnosisCN = "手机信号格数充足，但存在中度同频与隔墙多径干扰（SINR " + strconv.Itoa(sinrVal) + " dB），建议将热点机移至窗边开阔处以减少空口抖动"
		} else {
			st.DiagnosisCN = "手机信号强度良好，但存在轻度同频或隔墙多径干扰（SINR " + strconv.Itoa(sinrVal) + " dB），移至窗边开阔位置可提升信道纯净度与峰值网速"
		}
	case st.Mode == "wifi_sta" && st.InterferencePct >= 50:
		st.Diagnosis = "rf_interference"
		st.DiagnosisCN = "上游 Wi-Fi 中继信道存在同频干扰或底噪偏高，建议切换至 5GHz 低拥挤信道并靠近主路由"
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
	cmd.Env = hubAppendAndroidEnv("PATH=/system/bin:/system/xbin:/vendor/bin")
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
		if puIsLocalLogsHeader(line) || lines >= 2500 {
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
	rePhoneBlock        = regexp.MustCompile(`^\s*Phone Id\s*=\s*(-?\d+)`)
	reActiveSub         = regexp.MustCompile(`(?i)\b(?:mActiveDataSubId|active\s*data\s*sub(?:scription)?\s*id)\s*[=:]\s*(-?\d+)`)
	reDefaultSub        = regexp.MustCompile(`(?i)\b(?:mDefault(?:Data)?SubId|default\s*(?:data\s*)?sub(?:scription)?\s*id)\s*[=:]\s*(-?\d+)`)
	reDefaultPhone      = regexp.MustCompile(`(?i)\b(?:mDefault(?:Data)?PhoneId|default\s*(?:data\s*)?phone\s*id)\s*[=:]\s*(-?\d+)`)
	reSubIDField        = regexp.MustCompile(`\bmSubId\s*=\s*(-?\d+)`)
	reDataConnState     = regexp.MustCompile(`\bmDataConnectionState\s*=\s*(-?\d+)`)
	reNrSignal          = regexp.MustCompile(`CellSignalStrengthNr:\s*\{[^}]*?ssRsrp\s*=\s*(-?\d+)[^}]*?ssRsrq\s*=\s*(-?\d+)[^}]*?ssSinr\s*=\s*(-?\d+)`)
	reLteSignal         = regexp.MustCompile(`CellSignalStrengthLte:[^,}\n]*?\brssi\s*=\s*(-?\d+)\s+rsrp\s*=\s*(-?\d+)\s+rsrq\s*=\s*(-?\d+)\s+rssnr\s*=\s*(-?\d+)`)
	reAccessTech        = regexp.MustCompile(`(?i)\b(?:m?access(?:Network)?Technology)\s*=\s*(LTE[\s_-]+CA\b|NR[\s_-]+(?:SA|NSA|ADVANCED|MMWAVE)\b|[A-Za-z0-9_+-]+)`)
	reRilDataRadioSA    = regexp.MustCompile(`(?i)\b(?:get|m)?RilDataRadioTechnology\s*=\s*(?:[^\n,}]*\(NR_SA\)|NR_SA\b)`)
	reRilDataRadioNSA   = regexp.MustCompile(`(?i)\b(?:get|m)?RilDataRadioTechnology\s*=\s*(?:[^\n,}]*\(NR_NSA\)|NR_NSA\b)`)
	reEndcAvail         = regexp.MustCompile(`isEnDcAvailable\s*=\s*true`)
	reNrConnected       = regexp.MustCompile(`nrState\s*=\s*CONNECTED`)
	reDispOverride      = regexp.MustCompile(`override(?:Network|NetworkType)?\s*=\s*(NR_NSA|NR_ADVANCED|NR_MMWAVE|LTE_CA|LTE_ADVANCED_PRO)`)
	reOperatorLong      = regexp.MustCompile(`mOperatorAlphaLong\s*=\s*([^,\n}]+)`)
	reOperatorShrt      = regexp.MustCompile(`mOperatorAlphaShort\s*=\s*([^,\n}]+)`)
	reOperatorNum       = regexp.MustCompile(`mOperatorNumeric\s*=\s*(\d{5,6})`)
	reMccMncPair        = regexp.MustCompile(`mMcc\s*=\s*(\d{3})\s*,?\s*mMnc\s*=\s*(\d{2,3})`)
	reCellBandwidths    = regexp.MustCompile(`mCellBandwidths\s*=\s*\[([0-9,\s]*)\]`)
	reDataIface         = regexp.MustCompile(`InterfaceName:\s*([A-Za-z0-9_.-]+)`)
	reNonEmptyPcscf     = regexp.MustCompile(`(?i)PcscfAddresses:\s*\[\s*[^\s\]]`)
	reVoiceApnToken     = regexp.MustCompile(`(?i)(?:\[\s*(?:ims|emergency)(?:\s*,\s*(?:ims|emergency))*\s*\]|\b(?:apn|apnTypes?|mApnTypes?)\s*[=:]\s*\[?\s*(?:ims|emergency)\b|,\s*(?:ims|emergency)\s*,)`)
	reDataBearingApn    = regexp.MustCompile(`(?i)\b(?:default|dun|hipri|internet)\b`)
	rePhysChanEntry     = regexp.MustCompile(`\{[^{}]*mConnectionStatus\s*=\s*(PrimaryServing|SecondaryServing|1|2)[^{}]*\}`)
	reChanConnStatus    = regexp.MustCompile(`mConnectionStatus\s*=\s*(PrimaryServing|SecondaryServing|1|2)`)
	reChanNetType       = regexp.MustCompile(`mNetworkType\s*=\s*(NR|LTE|13|20)`)
	reChanBand          = regexp.MustCompile(`mBand\s*=\s*(\d+)`)
	reChanDLKhz         = regexp.MustCompile(`mCellBandwidthDownlinkKhz\s*=\s*(\d+)`)
	reChanDLArfcn       = regexp.MustCompile(`(?:mDownlinkChannelNumber|mChannelNumber)\s*=\s*(\d+)`)
	rePhysCellId        = regexp.MustCompile(`\b(?:mPhysicalCellId|mPci)\s*=\s*(-?\d+)`)
	rePciField          = regexp.MustCompile(`\bmPci\s*=\s*(-?\d+)`)
	reCellInfoLineStart = regexp.MustCompile(`^CellInfo(?:Nr|Lte|Wcdma|Gsm|Tdscdma|Cdma)\b`)
	reCellInfoBlkStart  = regexp.MustCompile(`CellInfo(?:Nr|Lte|Wcdma|Gsm|Tdscdma|Cdma):\s*\{`)
	reCellRegisteredNo  = regexp.MustCompile(`\bmRegistered\s*=\s*(?:NO|false|0)\b`)
	reCellRegisteredYes = regexp.MustCompile(`\bmRegistered\s*=\s*(?:YES|true|1)\b`)
	reNrArfcnField      = regexp.MustCompile(`mNrArfcn\s*=\s*(\d+)`)
	reEarfcnField       = regexp.MustCompile(`mEarfcn\s*=\s*(\d+)`)
	reBandsArray        = regexp.MustCompile(`mBands\s*=\s*\[([0-9,\s]+)\]`)
	reLteBwField        = regexp.MustCompile(`mBandwidth\s*=\s*(\d+)`)
)

type parsedServingCarrier struct {
	IsPrimary     bool
	IsNR          bool
	Band          string
	BandFromARFCN bool
	BWMHz         int
	ARFCN         int
	PCI           int
	HasPCI        bool
}

type parsedPhoneSlot struct {
	PhoneID              int
	SubID                int
	DataConnState        int
	AlphaLong            string
	AlphaShort           string
	MCCMNC               string
	Ifaces               map[string]bool
	HasNRValid           bool
	NRRsrp               int
	NRRsrq               int
	NRSinr               int
	HasNRRsrq            bool
	HasNRSinr            bool
	HasFallbackNRSignal  bool
	FallbackNRRsrp       int
	FallbackNRRsrq       int
	FallbackNRSinr       int
	HasFallbackNRRsrq    bool
	HasFallbackNRSinr    bool
	HasLTEValid          bool
	LTERssi              int
	HasLTERssi           bool
	LTERsrp              int
	LTERsrq              int
	LTESinr              int
	HasLTERsrq           bool
	HasLTESinr           bool
	HasFallbackLTESignal bool
	FallbackLTERssi      int
	HasFallbackLTERssi   bool
	FallbackLTERsrp      int
	FallbackLTERsrq      int
	FallbackLTESinr      int
	HasFallbackLTERsrq   bool
	HasFallbackLTESinr   bool
	IsSA                 bool
	IsNSA                bool
	ExplicitNSA          bool
	IsLTE                bool
	Is5GA                bool
	IsLTECA              bool
	Carriers             []parsedServingCarrier
	ServiceCellBWMHzs    []int
	ExplicitNRBand       string
	CellIDNRBands        map[int]string
	FallbackNRBand       string
	FallbackNRArfcn      int
	FallbackNRPCI        int
	HasFallbackNRPCI     bool
	ExplicitLTEBand      string
	CellIDLTEBands       map[int]string
	FallbackLTEBand      string
	FallbackLTEArfcn     int
	FallbackLTEBWMHz     int
	FallbackLTEPCI       int
	HasFallbackLTEPCI    bool
	SawSubID             bool
}

func sigValidSubID(v int) bool  { return v > 0 && v != sigUnavailable }
func validRSRP(v int) bool      { return v != sigUnavailable && v >= -145 && v <= -40 }
func validRSRQ(v int) bool      { return v != sigUnavailable && v >= -30 && v <= 0 }
func validSINR(v int) bool      { return v != sigUnavailable && v >= -25 && v <= 50 }
func validRSSI(v int) bool      { return v != sigUnavailable && v >= -120 && v <= -25 }
func validNRPCI(v int) bool     { return v >= 0 && v <= 1007 }
func validLTEPCI(v int) bool    { return v >= 0 && v <= 503 }
func validWifiNoise(v int) bool { return v >= -120 && v <= -40 }

// sigStripUnregisteredCellInfo 使用花括号深度配对扫描剥离 mCellInfo 中所有 mRegistered=NO/false 的邻区块,
// 彻底防止内嵌 `mAdditionalPlmns = {}` 提前闭合正则导致邻区电平或邻区 PCI 泄漏。
func sigStripUnregisteredCellInfo(s string) string {
	if !strings.Contains(s, "CellInfo") {
		return s
	}
	var sb strings.Builder
	pos := 0
	for pos < len(s) {
		loc := reCellInfoBlkStart.FindStringIndex(s[pos:])
		if loc == nil {
			sb.WriteString(s[pos:])
			break
		}
		blkStart := pos + loc[0]
		openBrace := pos + loc[1] - 1
		sb.WriteString(s[pos:blkStart])

		depth := 0
		blkEnd := len(s)
		for k := openBrace; k < len(s); k++ {
			switch s[k] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					blkEnd = k + 1
					k = len(s)
				}
			}
		}
		blk := s[blkStart:blkEnd]
		if !reCellRegisteredNo.MatchString(blk) {
			sb.WriteString(blk)
		}
		pos = blkEnd
	}
	return sb.String()
}

// sigExtractBracedBlocks 提取形如 `<tag>:{ ... }` 的完整配对花括号块(免疫内部嵌套 `{}` 截断)。
func sigExtractBracedBlocks(s, tag string) []string {
	if !strings.Contains(s, tag) {
		return nil
	}
	var out []string
	pos := 0
	for pos < len(s) {
		rel := strings.Index(s[pos:], tag)
		if rel < 0 {
			break
		}
		tagIdx := pos + rel
		k := tagIdx + len(tag)
		for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
			k++
		}
		if k >= len(s) || s[k] != ':' {
			pos = tagIdx + len(tag)
			continue
		}
		k++
		for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
			k++
		}
		if k >= len(s) || s[k] != '{' {
			pos = k
			continue
		}
		depth := 0
		blkEnd := len(s)
		for j := k; j < len(s); j++ {
			switch s[j] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					blkEnd = j + 1
					j = len(s)
				}
			}
		}
		out = append(out, s[tagIdx:blkEnd])
		pos = blkEnd
	}
	return out
}

// sigExtractNonVoiceDataIfaces 从单行提取数据承载网卡名:
// 严禁按名字硬滤 rmnet_data1; 仅剔除明确标为纯 ims/emergency(不含 default/dun/hipri/internet)或含非空 PcscfAddresses 的语音专用承载。
func sigExtractNonVoiceDataIfaces(line string) []string {
	matches := reDataIface.FindAllStringSubmatchIndex(line, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	prevEnd := 0
	for i, loc := range matches {
		ifName := line[loc[2]:loc[3]]
		if ifName == "" {
			continue
		}
		nextStart := len(line)
		if i+1 < len(matches) {
			nextStart = matches[i+1][0]
		}
		linkStart := loc[0]
		for k := loc[0] - 1; k >= prevEnd; k-- {
			if line[k] == '{' {
				linkStart = k
				break
			}
		}
		linkEnd := nextStart
		depth := 0
		for k := linkStart; k < nextStart; k++ {
			if line[k] == '{' {
				depth++
			} else if line[k] == '}' {
				depth--
				if depth <= 0 {
					linkEnd = k + 1
					break
				}
			}
		}
		apnCtx := line[prevEnd:loc[0]]
		linkBlk := line[linkStart:linkEnd]
		prevEnd = linkEnd

		hasDataApn := reDataBearingApn.MatchString(apnCtx)
		if !hasDataApn {
			if reNonEmptyPcscf.MatchString(linkBlk) || reVoiceApnToken.MatchString(apnCtx) {
				continue
			}
		}
		out = append(out, ifName)
	}
	return out
}

func sigLineIndent(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ':
			n++
		case '\t':
			n += 2
		default:
			return n
		}
	}
	return n
}

func sigIsRegistryTopSection(trimmed string) bool {
	low := strings.ToLower(trimmed)
	return strings.HasPrefix(low, "registrations:") ||
		strings.HasPrefix(low, "local log") ||
		strings.HasPrefix(low, "mdefaultsubid") ||
		strings.HasPrefix(low, "defaultsubid") ||
		strings.HasPrefix(low, "mdefaultphoneid") ||
		strings.HasPrefix(low, "defaultphoneid") ||
		strings.HasPrefix(low, "carrier privilege") ||
		strings.HasPrefix(low, "subscription")
}

func sigResolveMaxSlots(raw string) int {
	tripleHW := puIsubTripleSimRE.MatchString(raw)
	modemCount := 0
	for _, line := range strings.Split(raw, "\n") {
		if puIsLocalLogsHeader(line) {
			break
		}
		if m := puIsubModemCountRE.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
				modemCount = n
				break
			}
		}
	}
	switch {
	case modemCount == 1:
		return 1
	case tripleHW && modemCount >= 3:
		return 3
	default:
		return 2
	}
}

func parseBandsBracket(s string, prefix string) string {
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil && n > 0 && n < 1000 {
			return prefix + strconv.Itoa(n)
		}
	}
	return ""
}

func parseCellBandwidthsMHz(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		tok := strings.TrimSpace(part)
		if tok == "" {
			continue
		}
		khz, err := strconv.Atoi(tok)
		if err == nil && khz >= 1000 && khz <= 400000 {
			out = append(out, khz/1000)
		}
	}
	return out
}

func parseTelephonyRegistryDump(raw, wantIface string, nowUnix int64) hostSignalStatus {
	return parseTelephonyRegistryDumpWithSubMap(raw, wantIface, nowUnix, nil)
}

func parseTelephonyRegistryDumpWithSubMap(raw, wantIface string, nowUnix int64, slotSubIDs map[int]int) hostSignalStatus {
	wantIface = strings.TrimPrefix(strings.TrimSpace(wantIface), "v4-")
	maxSlots := sigResolveMaxSlots(raw)
	activeSubID := 0
	defaultSubID := 0
	defaultPhoneID := -1

	var slots []*parsedPhoneSlot
	var cur *parsedPhoneSlot
	curIndent := -1
	for _, line := range strings.Split(raw, "\n") {
		if puIsLocalLogsHeader(line) {
			cur = nil
			break
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if activeSubID == 0 {
			if m := reActiveSub.FindStringSubmatch(line); m != nil {
				if id, err := strconv.Atoi(m[1]); err == nil && sigValidSubID(id) {
					activeSubID = id
				}
			}
		}
		if defaultSubID == 0 {
			if m := reDefaultSub.FindStringSubmatch(line); m != nil {
				if id, err := strconv.Atoi(m[1]); err == nil && sigValidSubID(id) {
					defaultSubID = id
				}
			}
		}
		if defaultPhoneID < 0 {
			if m := reDefaultPhone.FindStringSubmatch(line); m != nil {
				if pid, err := strconv.Atoi(m[1]); err == nil && pid >= 0 && pid < maxSlots {
					defaultPhoneID = pid
				}
			}
		}
		if m := rePhoneBlock.FindStringSubmatch(line); m != nil {
			pid, err := strconv.Atoi(m[1])
			if err != nil || pid < 0 || pid >= maxSlots {
				cur = nil
				curIndent = -1
				continue
			}
			curIndent = sigLineIndent(line)
			cur = &parsedPhoneSlot{
				PhoneID:        pid,
				DataConnState:  -1,
				Ifaces:         map[string]bool{},
				CellIDNRBands:  map[int]string{},
				CellIDLTEBands: map[int]string{},
			}
			slots = append(slots, cur)
			continue
		}
		if cur == nil {
			continue
		}
		lineIndent := sigLineIndent(line)
		if sigIsRegistryTopSection(trimmed) || lineIndent == 0 || (curIndent > 0 && lineIndent <= curIndent) {
			cur = nil
			curIndent = -1
			continue
		}
		if m := reSubIDField.FindStringSubmatch(line); m != nil {
			cur.SawSubID = true
			if cur.SubID == 0 {
				if id, err := strconv.Atoi(m[1]); err == nil && sigValidSubID(id) {
					cur.SubID = id
				}
			}
		}
		if m := reDataConnState.FindStringSubmatch(line); m != nil {
			if stCode, err := strconv.Atoi(m[1]); err == nil {
				cur.DataConnState = stCode
			}
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
		if bm := reCellBandwidths.FindStringSubmatch(line); bm != nil {
			if bws := parseCellBandwidthsMHz(bm[1]); len(bws) > 0 {
				cur.ServiceCellBWMHzs = bws
			}
		}
		for _, ifName := range sigExtractNonVoiceDataIfaces(line) {
			cur.Ifaces[ifName] = true
			if phys := strings.TrimPrefix(ifName, "v4-"); phys != "" {
				cur.Ifaces[phys] = true
			}
		}

		isCellInfoLine := strings.Contains(line, "mCellInfo") || reCellInfoLineStart.MatchString(trimmed)
		cellScanLine := line
		if isCellInfoLine {
			cellScanLine = sigStripUnregisteredCellInfo(line)
			// mCellInfo 行仅将已注册小区的信号存为 fallback, 绝不覆盖主 mSignalStrength 实时电平(根除 RMX5010 9dB 偏差)!
			hasRegMarker := !strings.Contains(cellScanLine, "mRegistered") || reCellRegisteredYes.MatchString(cellScanLine)
			if hasRegMarker {
				if m := reNrSignal.FindStringSubmatch(cellScanLine); m != nil && !cur.HasFallbackNRSignal {
					rsrp, _ := strconv.Atoi(m[1])
					rsrq, _ := strconv.Atoi(m[2])
					sinr, _ := strconv.Atoi(m[3])
					if validRSRP(rsrp) {
						cur.HasFallbackNRSignal = true
						cur.FallbackNRRsrp = rsrp
						if validRSRQ(rsrq) {
							cur.FallbackNRRsrq = rsrq
							cur.HasFallbackNRRsrq = true
						}
						if validSINR(sinr) {
							cur.FallbackNRSinr = sinr
							cur.HasFallbackNRSinr = true
						}
					}
				}
				if m := reLteSignal.FindStringSubmatch(cellScanLine); m != nil && !cur.HasFallbackLTESignal {
					rssi, _ := strconv.Atoi(m[1])
					rsrp, _ := strconv.Atoi(m[2])
					rsrq, _ := strconv.Atoi(m[3])
					sinr, _ := strconv.Atoi(m[4])
					if validRSRP(rsrp) {
						cur.HasFallbackLTESignal = true
						cur.FallbackLTERsrp = rsrp
						if validRSSI(rssi) {
							cur.FallbackLTERssi = rssi
							cur.HasFallbackLTERssi = true
						}
						if validRSRQ(rsrq) {
							cur.FallbackLTERsrq = rsrq
							cur.HasFallbackLTERsrq = true
						}
						if validSINR(sinr) {
							cur.FallbackLTESinr = sinr
							cur.HasFallbackLTESinr = true
						}
					}
				}
			}
		} else {
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
						cur.HasNRSinr = true
					}
				}
			}
			if m := reLteSignal.FindStringSubmatch(line); m != nil {
				rssi, _ := strconv.Atoi(m[1])
				rsrp, _ := strconv.Atoi(m[2])
				rsrq, _ := strconv.Atoi(m[3])
				sinr, _ := strconv.Atoi(m[4])
				if validRSRP(rsrp) {
					cur.HasLTEValid = true
					cur.LTERsrp = rsrp
					if validRSSI(rssi) {
						cur.LTERssi = rssi
						cur.HasLTERssi = true
					}
					if validRSRQ(rsrq) {
						cur.LTERsrq = rsrq
						cur.HasLTERsrq = true
					}
					if validSINR(sinr) {
						cur.LTESinr = sinr
						cur.HasLTESinr = true
					}
				}
			}
		}

		for _, am := range reAccessTech.FindAllStringSubmatch(line, -1) {
			tech := strings.ToUpper(strings.TrimSpace(am[1]))
			techNorm := strings.NewReplacer(" ", "_", "-", "_").Replace(tech)
			switch {
			case techNorm == "NR" || techNorm == "NR_SA":
				cur.IsSA = true
			case techNorm == "NR_NSA":
				cur.IsNSA = true
				cur.ExplicitNSA = true
			case techNorm == "NR_ADVANCED" || techNorm == "NR_MMWAVE":
				cur.IsSA = true
				cur.Is5GA = true
			case strings.Contains(techNorm, "LTE"):
				cur.IsLTE = true
				if strings.Contains(techNorm, "CA") {
					cur.IsLTECA = true
				}
			}
		}
		if reRilDataRadioSA.MatchString(line) {
			cur.IsSA = true
		}
		if reRilDataRadioNSA.MatchString(line) {
			cur.IsNSA = true
			cur.ExplicitNSA = true
		}
		if reEndcAvail.MatchString(line) || reNrConnected.MatchString(line) {
			cur.IsNSA = true
		}
		for _, dm := range reDispOverride.FindAllStringSubmatch(line, -1) {
			switch dm[1] {
			case "NR_NSA":
				cur.IsNSA = true
				cur.ExplicitNSA = true
			case "NR_ADVANCED", "NR_MMWAVE":
				// 严禁把 SA 下的 NR_ADVANCED (5G-A) 误标为 NSA!
				cur.Is5GA = true
			case "LTE_CA", "LTE_ADVANCED_PRO":
				cur.IsLTECA = true
			}
		}

		// 提取 CellIdentityNr / CellIdentityLte 频段、频点与 PCI (使用平衡花括号提取并屏蔽未注册邻区污染)
		for _, nrBlk := range sigExtractBracedBlocks(cellScanLine, "CellIdentityNr") {
			var arfcn, pci, bw int
			var hasPCI bool
			var explicitBand, band string
			if am := reNrArfcnField.FindStringSubmatch(nrBlk); am != nil {
				if v, err := strconv.Atoi(am[1]); err == nil && v > 0 && v != sigUnavailable {
					arfcn = v
				}
			}
			if pm := rePciField.FindStringSubmatch(nrBlk); pm != nil {
				if v, err := strconv.Atoi(pm[1]); err == nil && validNRPCI(v) {
					pci = v
					hasPCI = true
				}
			}
			if bm := reBandsArray.FindStringSubmatch(nrBlk); bm != nil {
				explicitBand = parseBandsBracket(bm[1], "n")
				band = explicitBand
			}
			if bwm := reLteBwField.FindStringSubmatch(nrBlk); bwm != nil {
				if khz, err := strconv.Atoi(bwm[1]); err == nil && khz >= 1000 && khz <= 400000 {
					bw = khz / 1000
				}
			}
			if pci == 0 && arfcn == 0 && band == "" && bw == 0 {
				continue
			}
			if explicitBand != "" {
				if arfcn > 0 && (!isCellInfoLine || cur.CellIDNRBands[arfcn] == "") {
					cur.CellIDNRBands[arfcn] = explicitBand
				}
				if !isCellInfoLine || cur.ExplicitNRBand == "" {
					cur.ExplicitNRBand = explicitBand
				}
			}
			if arfcn > 0 {
				if !isCellInfoLine || cur.FallbackNRArfcn == 0 {
					cur.FallbackNRArfcn = arfcn
				}
				if band == "" {
					band, _ = nrBandFromARFCN(arfcn, cur.MCCMNC)
				}
			}
			if hasPCI && (!isCellInfoLine || !cur.HasFallbackNRPCI) {
				cur.FallbackNRPCI = pci
				cur.HasFallbackNRPCI = true
			}
			if band != "" && (cur.FallbackNRBand == "" || (!isCellInfoLine && explicitBand != "")) {
				cur.FallbackNRBand = band
			}
		}
		for _, lteBlk := range sigExtractBracedBlocks(cellScanLine, "CellIdentityLte") {
			var earfcn, pci, bw int
			var hasEarfcn, hasPCI bool
			var explicitBand, band string
			if am := reEarfcnField.FindStringSubmatch(lteBlk); am != nil {
				if v, err := strconv.Atoi(am[1]); err == nil && v >= 0 && v != sigUnavailable {
					earfcn = v
					hasEarfcn = true
				}
			}
			if pm := rePciField.FindStringSubmatch(lteBlk); pm != nil {
				if v, err := strconv.Atoi(pm[1]); err == nil && validLTEPCI(v) {
					pci = v
					hasPCI = true
				}
			}
			if bm := reBandsArray.FindStringSubmatch(lteBlk); bm != nil {
				explicitBand = parseBandsBracket(bm[1], "B")
				band = explicitBand
			}
			if bwm := reLteBwField.FindStringSubmatch(lteBlk); bwm != nil {
				if khz, err := strconv.Atoi(bwm[1]); err == nil && khz >= 1000 && khz <= 100000 {
					bw = khz / 1000
				}
			}
			if pci == 0 && earfcn == 0 && band == "" && bw == 0 {
				continue
			}
			if explicitBand != "" {
				if hasEarfcn && (!isCellInfoLine || cur.CellIDLTEBands[earfcn] == "") {
					cur.CellIDLTEBands[earfcn] = explicitBand
				}
				if !isCellInfoLine || cur.ExplicitLTEBand == "" {
					cur.ExplicitLTEBand = explicitBand
				}
			}
			if hasEarfcn {
				if !isCellInfoLine || cur.FallbackLTEArfcn == 0 {
					cur.FallbackLTEArfcn = earfcn
				}
				if band == "" {
					band, _ = lteBandFromEARFCN(earfcn)
				}
			}
			if hasPCI && (!isCellInfoLine || !cur.HasFallbackLTEPCI) {
				cur.FallbackLTEPCI = pci
				cur.HasFallbackLTEPCI = true
			}
			if band != "" && (cur.FallbackLTEBand == "" || (!isCellInfoLine && explicitBand != "")) {
				cur.FallbackLTEBand = band
			}
			if bw > 0 && (cur.FallbackLTEBWMHz == 0 || !isCellInfoLine) {
				cur.FallbackLTEBWMHz = bw
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
				} else if (cur.HasNRValid || cur.HasFallbackNRSignal) && !cur.IsLTE {
					isNR = true
				}
				var arfcn, bwMHz, pci int
				var hasPCI bool
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
				if pm := rePhysCellId.FindStringSubmatch(ent); pm != nil {
					if v, err := strconv.Atoi(pm[1]); err == nil {
						if (isNR && validNRPCI(v)) || (!isNR && validLTEPCI(v)) {
							pci = v
							hasPCI = true
						}
					}
				}
				bandStr := ""
				bandFromARFCN := false
				if mdm := reChanBand.FindStringSubmatch(ent); mdm != nil {
					if bNum, err := strconv.Atoi(mdm[1]); err == nil && bNum > 0 && bNum < 1000 {
						if isNR {
							bandStr = "n" + strconv.Itoa(bNum)
						} else {
							bandStr = "B" + strconv.Itoa(bNum)
						}
					}
				}
				// 仅当通道自身 pci==0 且无频段/带宽/频点 全空占位时立即跳过(严禁先回填 CellIdentity.mBands 导致全零假 PCI=0 留存!),
				// 同时严禁盲删带有频段/带宽/频点的合法 3GPP PCI=0!
				if hasPCI && pci == 0 && bandStr == "" && bwMHz == 0 && arfcn == 0 {
					continue
				}
				// 当 mBand=0 时优先采用 CellIdentity 已给出的 mBands, 再回退 ARFCN 查表
				if bandStr == "" {
					if isNR {
						if arfcn > 0 && cur.CellIDNRBands[arfcn] != "" {
							bandStr = cur.CellIDNRBands[arfcn]
						} else if isPri && cur.ExplicitNRBand != "" && (arfcn == 0 || cur.FallbackNRArfcn == 0 || arfcn == cur.FallbackNRArfcn) {
							bandStr = cur.ExplicitNRBand
						} else if arfcn > 0 {
							bandStr, _ = nrBandFromARFCN(arfcn, cur.MCCMNC)
							bandFromARFCN = bandStr != ""
						}
					} else {
						if arfcn > 0 && cur.CellIDLTEBands[arfcn] != "" {
							bandStr = cur.CellIDLTEBands[arfcn]
						} else if isPri && cur.ExplicitLTEBand != "" && (arfcn == 0 || cur.FallbackLTEArfcn == 0 || arfcn == cur.FallbackLTEArfcn) {
							bandStr = cur.ExplicitLTEBand
						} else if arfcn > 0 {
							bandStr, _ = lteBandFromEARFCN(arfcn)
							bandFromARFCN = bandStr != ""
						}
					}
				}
				if bandStr != "" || bwMHz > 0 || arfcn > 0 || hasPCI {
					lineCarriers = append(lineCarriers, parsedServingCarrier{
						IsPrimary:     isPri,
						IsNR:          isNR,
						Band:          bandStr,
						BandFromARFCN: bandFromARFCN,
						BWMHz:         bwMHz,
						ARFCN:         arfcn,
						PCI:           pci,
						HasPCI:        hasPCI,
					})
				}
			}
			if len(lineCarriers) > 0 {
				cur.Carriers = lineCarriers
			}
		}
	}

	if activeSubID == 0 && sigValidSubID(defaultSubID) {
		activeSubID = defaultSubID
	}

	filteredSlots := make([]*parsedPhoneSlot, 0, len(slots))
	for _, sl := range slots {
		// 仅当该槽主 mSignalStrength 未提取到有效值时, 兜底启用已注册 CellInfo 的电平
		if !sl.HasNRValid && sl.HasFallbackNRSignal {
			sl.HasNRValid = true
			sl.NRRsrp = sl.FallbackNRRsrp
			sl.NRRsrq = sl.FallbackNRRsrq
			sl.HasNRRsrq = sl.HasFallbackNRRsrq
			sl.NRSinr = sl.FallbackNRSinr
			sl.HasNRSinr = sl.HasFallbackNRSinr
		}
		if !sl.HasLTEValid && sl.HasFallbackLTESignal {
			sl.HasLTEValid = true
			sl.LTERsrp = sl.FallbackLTERsrp
			sl.LTERssi = sl.FallbackLTERssi
			sl.HasLTERssi = sl.HasFallbackLTERssi
			sl.LTERsrq = sl.FallbackLTERsrq
			sl.HasLTERsrq = sl.HasFallbackLTERsrq
			sl.LTESinr = sl.FallbackLTESinr
			sl.HasLTESinr = sl.HasFallbackLTESinr
		}
		// Phone Id 块缺 mSubId= (SubID==0) 时联动 phoneUsage 的 isub 槽位映射或底部 mDefaultPhoneId/mDefaultSubId 回填
		if sl.SubID == 0 && !sl.SawSubID {
			if slotSubIDs != nil {
				if id := slotSubIDs[sl.PhoneID+1]; sigValidSubID(id) {
					sl.SubID = id
				}
			}
			if sl.SubID == 0 && defaultPhoneID == sl.PhoneID && sigValidSubID(defaultSubID) {
				sl.SubID = defaultSubID
			}
		}
		mcc := ""
		if len(sl.MCCMNC) >= 3 {
			mcc = sl.MCCMNC[:3]
		}
		if puIsCloudVirtualSim(mcc, "", sl.AlphaLong, sl.AlphaShort) {
			continue
		}
		filteredSlots = append(filteredSlots, sl)
	}
	slots = filteredSlots

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
			if sl.SubID == activeSubID && (sl.HasNRValid || sl.HasLTEValid) {
				chosen = sl
				break
			}
		}
		if chosen == nil {
			for _, sl := range slots {
				if sl.SubID == activeSubID {
					chosen = sl
					break
				}
			}
		}
	}
	if chosen == nil {
		// 缺 mSubId 时优先选取 mDataConnectionState=2 (CONNECTED) 的上网槽位
		for _, sl := range slots {
			if sl.SawSubID && sl.SubID <= 0 {
				continue
			}
			if sl.DataConnState == 2 && (sl.HasNRValid || sl.HasLTEValid) {
				chosen = sl
				break
			}
		}
	}
	if chosen == nil && defaultPhoneID >= 0 && (activeSubID == 0 || activeSubID == defaultSubID) {
		for _, sl := range slots {
			if sl.SawSubID && sl.SubID <= 0 {
				continue
			}
			if sl.PhoneID == defaultPhoneID && (sl.HasNRValid || sl.HasLTEValid) {
				chosen = sl
				break
			}
		}
	}
	if chosen == nil {
		for _, sl := range slots {
			if sl.SawSubID && sl.SubID <= 0 {
				continue
			}
			if sl.HasNRValid || sl.HasLTEValid {
				chosen = sl
				break
			}
		}
	}
	if chosen == nil || (!chosen.HasNRValid && !chosen.HasLTEValid) {
		return hostSignalStatus{Available: false, UpdatedAt: nowUnix}
	}
	if chosen.SubID == 0 && !chosen.SawSubID && activeSubID > 0 {
		taken := false
		for _, sl := range slots {
			if sl != chosen && sl.SubID == activeSubID {
				taken = true
				break
			}
		}
		if !taken && (chosen.DataConnState == 2 || len(slots) == 1 || chosen.PhoneID == defaultPhoneID) {
			chosen.SubID = activeSubID
		}
	}

	if wantIface == "" {
		for ifc := range chosen.Ifaces {
			if !strings.HasPrefix(ifc, "v4-") && (wantIface == "" || ifc < wantIface) {
				wantIface = ifc
			}
		}
	}

	// 汇总主载波、多载波聚合信息与物理小区标识
	var priBand string
	var priBW, priArfcn, totalBW, nrCount, activeCount int
	var nrPCI, ltePCI int
	var hasNRPCI, hasLTEPCI bool
	var comboParts []string
	var outCarriers []SignalCarrierInfo
	wantNR := chosen.HasNRValid
	isEffectiveNSA := chosen.IsNSA && (!chosen.IsSA || chosen.ExplicitNSA)

	for _, c := range chosen.Carriers {
		if wantNR && !c.IsNR && !isEffectiveNSA {
			continue
		}
		// 若 CellIdentity 行出现在 PhysicalChannelConfigList 之后, 再次优先校准 mBands
		if c.BandFromARFCN || c.Band == "" {
			if c.IsNR {
				if c.ARFCN > 0 && chosen.CellIDNRBands[c.ARFCN] != "" {
					c.Band = chosen.CellIDNRBands[c.ARFCN]
				} else if c.IsPrimary && chosen.ExplicitNRBand != "" && (c.ARFCN == 0 || chosen.FallbackNRArfcn == 0 || c.ARFCN == chosen.FallbackNRArfcn) {
					c.Band = chosen.ExplicitNRBand
				}
			} else {
				if c.ARFCN > 0 && chosen.CellIDLTEBands[c.ARFCN] != "" {
					c.Band = chosen.CellIDLTEBands[c.ARFCN]
				} else if c.IsPrimary && chosen.ExplicitLTEBand != "" && (c.ARFCN == 0 || chosen.FallbackLTEArfcn == 0 || c.ARFCN == chosen.FallbackLTEArfcn) {
					c.Band = chosen.ExplicitLTEBand
				}
			}
		}
		activeCount++
		if c.IsNR {
			nrCount++
			if c.HasPCI && (!hasNRPCI || c.IsPrimary) {
				nrPCI = c.PCI
				hasNRPCI = true
			}
		} else if c.HasPCI && (!hasLTEPCI || c.IsPrimary) {
			ltePCI = c.PCI
			hasLTEPCI = true
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

		netType := "LTE"
		if c.IsNR {
			netType = "NR"
		}
		cFreq := lookupBandFreqMHz(c.Band)
		if cFreq == 0 && c.ARFCN > 0 {
			if c.IsNR {
				_, cFreq = nrBandFromARFCN(c.ARFCN, chosen.MCCMNC)
			} else {
				_, cFreq = lteBandFromEARFCN(c.ARFCN)
			}
		}
		cPCI, cHasPCI := c.PCI, c.HasPCI
		if !cHasPCI && c.IsPrimary {
			if c.IsNR && chosen.HasFallbackNRPCI {
				cPCI, cHasPCI = chosen.FallbackNRPCI, true
			} else if !c.IsNR && chosen.HasFallbackLTEPCI {
				cPCI, cHasPCI = chosen.FallbackLTEPCI, true
			}
		}
		outCarriers = append(outCarriers, SignalCarrierInfo{
			IsPrimary: c.IsPrimary,
			NetType:   netType,
			Band:      c.Band,
			BWMHz:     c.BWMHz,
			ARFCN:     c.ARFCN,
			FreqMHz:   cFreq,
			PCI:       cPCI,
			HasPCI:    cHasPCI,
		})
	}

	if !hasNRPCI && chosen.HasFallbackNRPCI {
		nrPCI = chosen.FallbackNRPCI
		hasNRPCI = true
	}
	if !hasLTEPCI && chosen.HasFallbackLTEPCI {
		ltePCI = chosen.FallbackLTEPCI
		hasLTEPCI = true
	}

	// 若 PhysicalChannelConfigList 未给出频段, 启用 CellIdentity mBands / NR-ARFCN / EARFCN 兜底反推
	if wantNR {
		if priBand == "" {
			if chosen.ExplicitNRBand != "" {
				priBand = chosen.ExplicitNRBand
			} else {
				priBand = chosen.FallbackNRBand
			}
		}
		if priArfcn == 0 {
			priArfcn = chosen.FallbackNRArfcn
		}
		if priBand == "" && priArfcn > 0 {
			priBand, _ = nrBandFromARFCN(priArfcn, chosen.MCCMNC)
		}
	} else {
		if priBand == "" {
			if chosen.ExplicitLTEBand != "" {
				priBand = chosen.ExplicitLTEBand
			} else {
				priBand = chosen.FallbackLTEBand
			}
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

	// ServiceState mCellBandwidths=[...] 兜底主载波带宽与多载波总带宽(全 0 时如实保 0, 绝不捏造假带宽)
	if len(chosen.ServiceCellBWMHzs) > 0 {
		if len(outCarriers) > 0 && len(chosen.ServiceCellBWMHzs) == len(outCarriers) {
			recalcTotal := 0
			for i := range outCarriers {
				if outCarriers[i].BWMHz == 0 {
					outCarriers[i].BWMHz = chosen.ServiceCellBWMHzs[i]
				}
				recalcTotal += outCarriers[i].BWMHz
				if priBW == 0 && (outCarriers[i].IsPrimary || i == 0) {
					priBW = outCarriers[i].BWMHz
				}
			}
			if totalBW == 0 {
				totalBW = recalcTotal
			}
		} else {
			if priBW == 0 {
				priBW = chosen.ServiceCellBWMHzs[0]
				for i := range outCarriers {
					if outCarriers[i].IsPrimary || i == 0 {
						if outCarriers[i].BWMHz == 0 {
							outCarriers[i].BWMHz = priBW
						}
						break
					}
				}
			}
			if totalBW == 0 {
				for _, bw := range chosen.ServiceCellBWMHzs {
					totalBW += bw
				}
			}
		}
		if len(chosen.ServiceCellBWMHzs) > activeCount {
			activeCount = len(chosen.ServiceCellBWMHzs)
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
		BWMHz:         priBW,
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
		out.HasRSRQ = chosen.HasNRRsrq
		out.SINRdB = chosen.NRSinr
		out.HasSINR = chosen.HasNRSinr
		hasValidRSRQ = chosen.HasNRRsrq
		if hasNRPCI {
			out.PCI = nrPCI
			out.HasPCI = true
		}
		if chosen.HasLTEValid {
			out.LTERSRPdBm = chosen.LTERsrp
			if chosen.HasLTERsrq {
				out.LTERSRQdB = chosen.LTERsrq
			}
			if chosen.HasLTESinr {
				out.LTESINRdB = chosen.LTESinr
				out.HasLTESINR = true
				if !out.HasSINR {
					out.SINRdB = chosen.LTESinr
					out.HasSINR = true
				}
			}
			if chosen.HasLTERssi {
				out.RSSIdBm = chosen.LTERssi
			}
			if hasLTEPCI {
				out.LTEPCI = ltePCI
				out.HasLTEPCI = true
			}
		}
		// 若明确为 SA 且未启用 EN-DC 锚点, RAT 记为 "5G SA", 否则记为 "5G NSA" (100% 保持既有单测兼容);
		// 5G-A 图标展示统一走 DisplayRAT = "5G-A"。
		if chosen.IsSA && !isEffectiveNSA {
			out.RAT = "5G SA"
		} else if chosen.IsSA && !chosen.HasLTEValid && !chosen.ExplicitNSA {
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
		out.HasRSRQ = chosen.HasLTERsrq
		out.SINRdB = chosen.LTESinr
		out.HasSINR = chosen.HasLTESinr
		out.LTESINRdB = chosen.LTESinr
		out.HasLTESINR = chosen.HasLTESinr
		hasValidRSRQ = chosen.HasLTERsrq
		if chosen.HasLTERssi {
			out.RSSIdBm = chosen.LTERssi
		}
		if hasLTEPCI {
			out.PCI = ltePCI
			out.HasPCI = true
		}
		out.RAT = "4G LTE"
		if chosen.IsLTECA || activeCount >= 2 {
			out.DisplayRAT = "4G+"
		} else {
			out.DisplayRAT = "4G LTE"
		}
	}

	if len(outCarriers) == 0 && (priBand != "" || priArfcn > 0 || out.HasPCI) {
		netType := "LTE"
		if wantNR {
			netType = "NR"
		}
		outCarriers = []SignalCarrierInfo{
			{
				IsPrimary: true,
				NetType:   netType,
				Band:      priBand,
				BWMHz:     priBW,
				ARFCN:     priArfcn,
				FreqMHz:   freqMHz,
				PCI:       out.PCI,
				HasPCI:    out.HasPCI,
			},
		}
	}
	out.Carriers = outCarriers

	out.Bars, out.Quality, out.QualityCN, out.RFCeilingFactor = scoreCellularSignal4D(
		out.RSRPdBm, out.SINRdB, out.RSRQdB, out.HasSINR, hasValidRSRQ, strings.HasPrefix(out.RAT, "5G"), is5GA,
	)
	out.RSRPLabel, out.SINRLabel, out.RSRQLabel, out.SpeedPotentialPct, out.SpeedPotentialText = build4DSignalLabels(
		out.RSRPdBm, out.SINRdB, out.RSRQdB, out.HasSINR, hasValidRSRQ, out.RFCeilingFactor, false, 0,
	)
	out.Diagnosis = "ok"
	out.DiagnosisCN = "蜂窝射频状态已同步"
	computeInterference4D(&out, autorateStatus{})
	return out
}

func scoreCellularSignal4D(rsrp, sinr, rsrq int, hasSINR, hasRSRQ, is5G, is5GA bool) (bars int, quality, qualityCN string, alpha float64) {
	prefix := "4G"
	if is5GA {
		prefix = "5G-A"
	} else if is5G {
		prefix = "5G"
	}
	severeLoad := hasRSRQ && rsrq <= -17

	if !hasSINR {
		switch {
		case rsrp >= -88:
			if severeLoad {
				return 3, "good", prefix + " 良好（基站繁忙）", 0.90
			}
			return 4, "excellent", prefix + " 极佳", 1.0
		case rsrp >= -98:
			if severeLoad {
				return 2, "fair", "信号尚可（基站拥塞）", 0.78
			}
			return 3, "good", prefix + " 良好", 0.95
		case rsrp >= -108:
			return 2, "fair", "信号一般", 0.80
		case rsrp >= -116:
			return 1, "weak", "弱信号边缘", 0.55
		default:
			return 0, "critical", "极弱易断流", 0.35
		}
	}

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
	case rsrp >= -105 && sinr < 0:
		return 2, "fair", "强干扰受限", 0.60
	case rsrp >= -116:
		return 1, "weak", "弱信号边缘", 0.55
	default:
		return 0, "critical", "极弱易断流", 0.35
	}
}

func scoreWifiSignal(rssi int) (bars int, q, qCN string, alpha float64) {
	switch {
	case rssi >= -58:
		return 4, "excellent", "Wi-Fi 极佳", 1.0
	case rssi >= -68:
		return 3, "good", "Wi-Fi 良好", 0.95
	case rssi >= -77:
		return 2, "fair", "Wi-Fi 一般", 0.78
	case rssi >= -85:
		return 1, "weak", "Wi-Fi 偏弱", 0.52
	default:
		return 0, "critical", "Wi-Fi 极弱", 0.35
	}
}

var (
	reWifiRSSI          = regexp.MustCompile(`(?i)\brssi\s*[=:]\s*(-?\d+)`)
	reWifiTxSpeed       = regexp.MustCompile(`(?i)(?:txLinkSpeedMbps|Tx\s+Link\s+speed|(?:\b|^)Link\s+speed)\s*[=:]\s*(-?\d+)(?:\s*Mbps)?`)
	reWifiRxSpeed       = regexp.MustCompile(`(?i)(?:rxLinkSpeedMbps|Rx\s+Link\s+speed)\s*[=:]\s*(-?\d+)(?:\s*Mbps)?`)
	reWifiFreq          = regexp.MustCompile(`(?i)\bfrequency\s*[=:]\s*(\d+)(?:\s*MHz)?`)
	reWifiChannel       = regexp.MustCompile(`(?i)\bchannel\s*[=:]\s*(\d+)\b`)
	reWifiBandField     = regexp.MustCompile(`(?i)\bband\s*[=:]\s*(2\.4\s*GHz|5\s*GHz|6\s*GHz|\d+\b)`)
	reWifiBWExplicit    = regexp.MustCompile(`(?i)(?:channel\s*(?:width|bandwidth)|bandwidth|bw)\s*[=:]\s*(80\s*\+\s*80|\d+)\s*(MHz)?`)
	reWifiChanWidthKey  = regexp.MustCompile(`(?i)\bchannelWidth\s*[=:]\s*(\d+)\b`)
	reWifiNoise         = regexp.MustCompile(`(?i)\bnoise\s*[=:]\s*(-?\d+)`)
	reWifiStandard      = regexp.MustCompile(`(?i)(?:Wi-?Fi\s+standard|wifiStandard|standard)\s*[=:]\s*([A-Za-z0-9_.-]+(?:\s*\d+)?)`)
	reWifiAPMLD         = regexp.MustCompile(`(?i)AP\s+MLD\s+Address\s*[=:]\s*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})`)
	reWifiBSSID         = regexp.MustCompile(`(?i)\bBSSID\s*[=:]\s*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})`)
	reWifiMloMac        = regexp.MustCompile(`(?i)\b(?:mloMacAddress|MLO\s+MAC)\s*[=:]\s*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})`)
	reWifiAffiliatedHdr = regexp.MustCompile(`(?i)(?:ap\s+mlo\s+)?affiliated(?:\s+mlo)?\s+links\s*:`)
	reWifiMLOLinkHdr    = regexp.MustCompile(`(?i)^\s*(?:-\s*)?(?:mlo\s+)?link(?:\s+id)?\s*[#:=]?\s*\d+\b`)
	reWifiMLOState      = regexp.MustCompile(`(?i)\bstate\s*[=:]\s*([A-Za-z0-9_]+)`)
)

type parsedWifiMLOLink struct {
	Band     string
	Channel  int
	FreqMHz  int
	BWMHz    int
	RSSI     int
	HasRSSI  bool
	LinkMbps int
	MAC      string
}

func validWifiRSSI(v int) bool {
	return v >= -100 && v <= -15
}

func validWifiBSSID(mac string) bool {
	m := strings.ToLower(strings.TrimSpace(mac))
	if len(m) != 17 {
		return false
	}
	return m != "00:00:00:00:00:00" && m != "02:00:00:00:00:00" && m != "ff:ff:ff:ff:ff:ff"
}

func hashWifiBSSIDTag(mac string) string {
	if !validWifiBSSID(mac) {
		return ""
	}
	sum := sha256.Sum256([]byte("hnc-bssid-tag-v6:" + strings.ToLower(strings.TrimSpace(mac))))
	return hex.EncodeToString(sum[:4])
}

func wifiFreqToChannel(freq int) (band string, ch int) {
	switch {
	case freq == 2484:
		return "2.4GHz", 14
	case freq >= 2412 && freq <= 2472:
		return "2.4GHz", (freq - 2407) / 5
	case freq >= 2400 && freq < 2500:
		return "2.4GHz", 0
	case freq == 5935:
		return "6GHz", 2
	case freq >= 5955 && freq <= 7115:
		return "6GHz", (freq - 5950) / 5
	case freq >= 5900:
		return "6GHz", 0
	case freq >= 5000 && freq <= 5895:
		return "5GHz", (freq - 5000) / 5
	default:
		return "", 0
	}
}

func wifiChannelToFreq(band string, ch int) (normBand string, freq int) {
	normBand = band
	switch normBand {
	case "6GHz":
		if ch == 2 {
			return "6GHz", 5935
		}
		if ch >= 1 && ch <= 233 {
			return "6GHz", 5950 + ch*5
		}
	case "5GHz":
		if ch >= 32 && ch <= 177 {
			return "5GHz", 5000 + ch*5
		}
	case "2.4GHz":
		if ch == 14 {
			return "2.4GHz", 2484
		}
		if ch >= 1 && ch <= 13 {
			return "2.4GHz", 2407 + ch*5
		}
	default:
		if ch >= 1 && ch <= 14 {
			if ch == 14 {
				return "2.4GHz", 2484
			}
			return "2.4GHz", 2407 + ch*5
		}
		if ch >= 32 && ch <= 177 {
			return "5GHz", 5000 + ch*5
		}
	}
	return normBand, 0
}

func normalizeWifiBandToken(raw string) string {
	s := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), " ", ""))
	switch s {
	case "6ghz", "8":
		return "6GHz"
	case "5ghz", "2", "4", "6":
		return "5GHz"
	case "2.4ghz", "1":
		return "2.4GHz"
	default:
		return ""
	}
}

func wifiBandRank(band string) int {
	switch band {
	case "6GHz":
		return 3
	case "5GHz":
		return 2
	case "2.4GHz":
		return 1
	default:
		return 0
	}
}

func parseWifiBandwidthMHz(text string) int {
	if m := reWifiBWExplicit.FindStringSubmatch(text); m != nil {
		tok := strings.ReplaceAll(m[1], " ", "")
		if tok == "80+80" {
			return 160
		}
		if v, err := strconv.Atoi(tok); err == nil {
			switch v {
			case 20, 40, 80, 160, 320:
				return v
			}
		}
	}
	if m := reWifiChanWidthKey.FindStringSubmatch(text); m != nil {
		if v, err := strconv.Atoi(m[1]); err == nil {
			switch v {
			case 20, 40, 80, 160, 320:
				return v
			case 1:
				return 40
			case 2:
				return 80
			case 3, 4:
				return 160
			case 5:
				return 320
			}
		}
	}
	return 0
}

func parseWifiSpeedMbps(text string) int {
	best := 0
	for _, m := range reWifiTxSpeed.FindAllStringSubmatch(text, -1) {
		if v, err := strconv.Atoi(m[1]); err == nil && v > best {
			best = v
		}
	}
	if best > 0 {
		return best
	}
	for _, m := range reWifiRxSpeed.FindAllStringSubmatch(text, -1) {
		if v, err := strconv.Atoi(m[1]); err == nil && v > best {
			best = v
		}
	}
	return best
}

func extractWifiMLOLinkBlocks(mloRaw string) []string {
	var braced []string
	for i := 0; i < len(mloRaw); i++ {
		if mloRaw[i] == ']' && len(braced) > 0 {
			break
		}
		if mloRaw[i] != '{' {
			continue
		}
		depth := 0
		end := len(mloRaw)
		for j := i; j < len(mloRaw); j++ {
			switch mloRaw[j] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = j + 1
					j = len(mloRaw)
				}
			}
		}
		braced = append(braced, mloRaw[i:end])
		i = end - 1
	}
	if len(braced) > 0 {
		return braced
	}

	var blocks []string
	var cur strings.Builder
	inLink := false
	baseIndent := -1
	for _, line := range strings.Split(mloRaw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		indent := sigLineIndent(line)
		if reWifiMLOLinkHdr.MatchString(line) {
			if inLink && cur.Len() > 0 {
				blocks = append(blocks, cur.String())
				cur.Reset()
			}
			inLink = true
			if baseIndent < 0 || indent < baseIndent {
				baseIndent = indent
			}
			cur.WriteString(line)
			cur.WriteByte('\n')
			continue
		}
		if inLink {
			if indent == 0 || (baseIndent > 0 && indent < baseIndent) {
				break
			}
			cur.WriteString(line)
			cur.WriteByte('\n')
		}
	}
	if inLink && cur.Len() > 0 {
		blocks = append(blocks, cur.String())
	}
	return blocks
}

func parseSingleWifiMLOLink(blk string) (parsedWifiMLOLink, bool) {
	var out parsedWifiMLOLink
	explicitActive := false
	if sm := reWifiMLOState.FindStringSubmatch(blk); sm != nil {
		st := strings.ToUpper(strings.TrimSpace(sm[1]))
		if strings.Contains(st, "IDLE") ||
			strings.Contains(st, "INACTIVE") ||
			strings.Contains(st, "UNASSOCIATED") ||
			strings.Contains(st, "INVALID") ||
			strings.Contains(st, "DISCONNECTED") ||
			strings.Contains(st, "DISABLED") ||
			st == "OFF" || st == "0" || st == "1" || st == "2" {
			return out, false
		}
		if strings.Contains(st, "ACTIVE") || strings.Contains(st, "CONNECTED") || strings.Contains(st, "ASSOCIATED") || st == "3" {
			explicitActive = true
		}
	}
	if rm := reWifiRSSI.FindStringSubmatch(blk); rm != nil {
		if v, err := strconv.Atoi(rm[1]); err == nil {
			if validWifiRSSI(v) {
				out.RSSI = v
				out.HasRSSI = true
			} else if v < -100 {
				// 如 -127 dBm 未关联/休眠哨兵
				if !explicitActive {
					return out, false
				}
			}
		}
	}
	out.LinkMbps = parseWifiSpeedMbps(blk)
	if fm := reWifiFreq.FindStringSubmatch(blk); fm != nil {
		out.FreqMHz, _ = strconv.Atoi(fm[1])
	}
	if cm := reWifiChannel.FindStringSubmatch(blk); cm != nil {
		out.Channel, _ = strconv.Atoi(cm[1])
	}
	if bm := reWifiBandField.FindStringSubmatch(blk); bm != nil {
		out.Band = normalizeWifiBandToken(bm[1])
	}
	if out.FreqMHz > 0 {
		fbBand, fbCh := wifiFreqToChannel(out.FreqMHz)
		if out.Band == "" {
			out.Band = fbBand
		}
		if out.Channel == 0 {
			out.Channel = fbCh
		}
	} else if out.Channel > 0 {
		out.Band, out.FreqMHz = wifiChannelToFreq(out.Band, out.Channel)
	}
	out.BWMHz = parseWifiBandwidthMHz(blk)
	if mm := reWifiMloMac.FindStringSubmatch(blk); mm != nil && validWifiBSSID(mm[1]) {
		out.MAC = mm[1]
	} else if bm := reWifiBSSID.FindStringSubmatch(blk); bm != nil && validWifiBSSID(bm[1]) {
		out.MAC = bm[1]
	}

	if out.Band == "" {
		return out, false
	}
	if !explicitActive && !out.HasRSSI && out.LinkMbps <= 0 {
		return out, false
	}
	return out, true
}

func resolveWifiGeneration(raw string, hasMLO, has6GHz bool, bwMHz int) string {
	if m := reWifiStandard.FindStringSubmatch(raw); m != nil {
		tok := strings.ToUpper(strings.TrimSpace(m[1]))
		switch {
		case tok == "8" || strings.Contains(tok, "11BE") || strings.Contains(tok, "WIFI 7") || strings.Contains(tok, "WI-FI 7") || strings.Contains(tok, "EHT"):
			return "Wi-Fi 7"
		case strings.Contains(tok, "6E"):
			return "Wi-Fi 6E"
		case tok == "6" || strings.Contains(tok, "11AX") || strings.Contains(tok, "WIFI 6") || strings.Contains(tok, "WI-FI 6") || strings.HasPrefix(tok, "HE"):
			if has6GHz {
				return "Wi-Fi 6E"
			}
			return "Wi-Fi 6"
		case tok == "5" || strings.Contains(tok, "11AC") || strings.Contains(tok, "WIFI 5") || strings.Contains(tok, "WI-FI 5") || strings.HasPrefix(tok, "VHT"):
			return "Wi-Fi 5"
		case tok == "4" || strings.Contains(tok, "11N") || strings.Contains(tok, "WIFI 4") || strings.Contains(tok, "WI-FI 4") || strings.HasPrefix(tok, "HT"):
			return "Wi-Fi 4"
		}
	}
	upper := strings.ToUpper(raw)
	switch {
	case hasMLO || bwMHz >= 320 || strings.Contains(upper, "802.11BE") || strings.Contains(upper, "WIFI_STANDARD_11BE"):
		return "Wi-Fi 7"
	case strings.Contains(upper, "802.11AX") || strings.Contains(upper, "WIFI_STANDARD_11AX"):
		if has6GHz {
			return "Wi-Fi 6E"
		}
		return "Wi-Fi 6"
	case has6GHz:
		return "Wi-Fi 6E"
	case strings.Contains(upper, "802.11AC") || strings.Contains(upper, "WIFI_STANDARD_11AC"):
		return "Wi-Fi 5"
	case strings.Contains(upper, "802.11N") || strings.Contains(upper, "WIFI_STANDARD_11N"):
		return "Wi-Fi 4"
	}
	return ""
}

func parseWifiStatusOutput(raw, upIf string, nowUnix int64) hostSignalStatus {
	headRaw := raw
	mloRaw := ""
	hasAffiliatedSection := false
	if loc := reWifiAffiliatedHdr.FindStringIndex(raw); loc != nil {
		headRaw = raw[:loc[0]]
		mloRaw = raw[loc[1]:]
		hasAffiliatedSection = true
	}

	var topRSSI, topSpeed, topFreq, topChannel, topBW, noise int
	hasTopRSSI := false
	if rm := reWifiRSSI.FindStringSubmatch(headRaw); rm != nil {
		if v, err := strconv.Atoi(rm[1]); err == nil && validWifiRSSI(v) {
			topRSSI = v
			hasTopRSSI = true
		}
	}
	topSpeed = parseWifiSpeedMbps(headRaw)
	if fm := reWifiFreq.FindStringSubmatch(headRaw); fm != nil {
		topFreq, _ = strconv.Atoi(fm[1])
	}
	if cm := reWifiChannel.FindStringSubmatch(headRaw); cm != nil {
		topChannel, _ = strconv.Atoi(cm[1])
	}
	topBW = parseWifiBandwidthMHz(headRaw)
	if nm := reWifiNoise.FindStringSubmatch(raw); nm != nil {
		if nv, err := strconv.Atoi(nm[1]); err == nil && validWifiNoise(nv) {
			noise = nv
		}
	}

	var apMLD, topBSSID string
	if mm := reWifiAPMLD.FindStringSubmatch(raw); mm != nil && validWifiBSSID(mm[1]) {
		apMLD = mm[1]
	}
	if bm := reWifiBSSID.FindStringSubmatch(headRaw); bm != nil && validWifiBSSID(bm[1]) {
		topBSSID = bm[1]
	} else if bm := reWifiBSSID.FindStringSubmatch(raw); bm != nil && validWifiBSSID(bm[1]) {
		topBSSID = bm[1]
	}

	var activeLinks []parsedWifiMLOLink
	if hasAffiliatedSection {
		for _, blk := range extractWifiMLOLinkBlocks(mloRaw) {
			if lnk, ok := parseSingleWifiMLOLink(blk); ok {
				if !lnk.HasRSSI && hasTopRSSI {
					lnk.RSSI = topRSSI
					lnk.HasRSSI = true
				}
				activeLinks = append(activeLinks, lnk)
			}
		}
	}

	// 按活跃链路 6GHz > 5GHz > 2.4GHz 及最高速率优选主链路(杜绝被首条 2.4GHz 保底链误导)
	if len(activeLinks) > 1 {
		sort.SliceStable(activeLinks, func(i, j int) bool {
			a, b := activeLinks[i], activeLinks[j]
			if ra, rb := wifiBandRank(a.Band), wifiBandRank(b.Band); ra != rb {
				return ra > rb
			}
			if a.LinkMbps != b.LinkMbps {
				return a.LinkMbps > b.LinkMbps
			}
			if a.BWMHz != b.BWMHz {
				return a.BWMHz > b.BWMHz
			}
			if a.HasRSSI != b.HasRSSI {
				return a.HasRSSI
			}
			return a.RSSI > b.RSSI
		})
	}

	var rssi, linkMbps, freq, channel, priBW, totalBW, caCount int
	var band, bandCombo, primaryMAC string
	var outCarriers []SignalCarrierInfo
	has6GHz := false

	if len(activeLinks) > 0 {
		pri := activeLinks[0]
		if pri.HasRSSI {
			rssi = pri.RSSI
		} else if hasTopRSSI {
			rssi = topRSSI
		} else {
			return hostSignalStatus{Available: false, UpdatedAt: nowUnix}
		}
		band = pri.Band
		freq = pri.FreqMHz
		channel = pri.Channel
		priBW = pri.BWMHz
		if priBW == 0 && len(activeLinks) == 1 && topBW > 0 {
			priBW = topBW
		}
		linkMbps = pri.LinkMbps
		if linkMbps == 0 {
			linkMbps = topSpeed
		}
		primaryMAC = pri.MAC
		caCount = len(activeLinks)

		comboParts := make([]string, 0, len(activeLinks))
		outCarriers = make([]SignalCarrierInfo, 0, len(activeLinks))
		for i, lnk := range activeLinks {
			if lnk.Band == "6GHz" {
				has6GHz = true
			}
			comboParts = append(comboParts, lnk.Band)
			totalBW += lnk.BWMHz
			netType := "WLAN"
			if len(activeLinks) >= 2 || apMLD != "" {
				netType = "MLO"
			}
			cRSSI := 0
			if lnk.HasRSSI {
				cRSSI = lnk.RSSI
			}
			outCarriers = append(outCarriers, SignalCarrierInfo{
				IsPrimary: i == 0,
				NetType:   netType,
				Band:      lnk.Band,
				BWMHz:     lnk.BWMHz,
				FreqMHz:   lnk.FreqMHz,
				Channel:   lnk.Channel,
				LinkMbps:  lnk.LinkMbps,
				RSSIdBm:   cRSSI,
			})
		}
		if totalBW == 0 && priBW > 0 {
			totalBW = priBW
		}
		bandCombo = strings.Join(comboParts, "+")
	} else {
		if !hasTopRSSI {
			if rm := reWifiRSSI.FindStringSubmatch(raw); rm != nil {
				if v, err := strconv.Atoi(rm[1]); err == nil && validWifiRSSI(v) {
					topRSSI = v
					hasTopRSSI = true
				}
			}
		}
		if !hasTopRSSI {
			return hostSignalStatus{Available: false, UpdatedAt: nowUnix}
		}
		rssi = topRSSI
		linkMbps = topSpeed
		freq = topFreq
		channel = topChannel
		priBW = topBW
		totalBW = priBW
		caCount = 1

		if bm := reWifiBandField.FindStringSubmatch(headRaw); bm != nil {
			band = normalizeWifiBandToken(bm[1])
		}
		if freq > 0 {
			fbBand, fbCh := wifiFreqToChannel(freq)
			if band == "" {
				band = fbBand
			}
			if channel == 0 {
				channel = fbCh
			}
		} else if channel > 0 {
			band, freq = wifiChannelToFreq(band, channel)
		}
		if band == "" {
			band = "2.4GHz"
		}
		if band == "6GHz" {
			has6GHz = true
		}
		bandCombo = band
		outCarriers = []SignalCarrierInfo{
			{
				IsPrimary: true,
				NetType:   "WLAN",
				Band:      band,
				BWMHz:     priBW,
				FreqMHz:   freq,
				Channel:   channel,
				LinkMbps:  linkMbps,
				RSSIdBm:   rssi,
			},
		}
	}

	hasMLO := len(activeLinks) >= 2 || apMLD != ""
	wifiGen := resolveWifiGeneration(raw, hasMLO, has6GHz, priBW)
	displayRAT := "Wi-Fi 中继"
	if wifiGen != "" {
		if len(activeLinks) >= 2 {
			displayRAT = wifiGen + " MLO"
		} else {
			displayRAT = wifiGen
		}
	}

	bssidForHash := apMLD
	if bssidForHash == "" {
		bssidForHash = topBSSID
	}
	if bssidForHash == "" {
		bssidForHash = primaryMAC
	}
	bssidTag := hashWifiBSSIDTag(bssidForHash)

	var snr int
	var hasSNR bool
	if validWifiNoise(noise) {
		cand := rssi - noise
		if validSINR(cand) {
			snr = cand
			hasSNR = true
		}
	}

	bars, q, qCN, alpha := scoreWifiSignal(rssi)
	rsrpLbl, sinrLbl, rsrqLbl, spPct, spTxt := build4DSignalLabels(0, snr, 0, hasSNR, false, alpha, true, rssi)
	out := hostSignalStatus{
		Available:          true,
		Mode:               "wifi_sta",
		RAT:                "Wi-Fi 中继",
		DisplayRAT:         displayRAT,
		WifiGen:            wifiGen,
		UpstreamIface:      upIf,
		Band:               band,
		BandwidthMHz:       priBW,
		BWMHz:              priBW,
		Channel:            channel,
		BSSIDTag:           bssidTag,
		BandCombo:          bandCombo,
		TotalBWMHz:         totalBW,
		CACount:            caCount,
		FreqMHz:            freq,
		BandTrait:          describeBandTrait(band, bandCombo, totalBW, caCount, true),
		WifiRSSIdBm:        rssi,
		WifiLinkMbps:       linkMbps,
		WifiNoiseDbm:       noise,
		SINRdB:             snr,
		HasSINR:            hasSNR,
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
		Carriers:           outCarriers,
	}
	computeInterference4D(&out, autorateStatus{})
	return out
}

func parseWirelessDotInt(tok string) (int, bool) {
	clean := strings.TrimSuffix(strings.TrimSpace(tok), ".")
	if clean == "" {
		return 0, false
	}
	v, err := strconv.Atoi(clean)
	if err != nil {
		return 0, false
	}
	// 兼容部分 WEXT 驱动以无符号 u8 补码(136..241 -> -120..-15 dBm)输出负电平
	if v > 127 && v < 256 {
		v -= 256
	}
	return v, true
}

// parseProcNetWireless 解析 /proc/net/wireless 作为 Wi-Fi STA 信号与底噪的零 Binder 兜底源。
func parseProcNetWireless(raw, upIf, apIface string, nowUnix int64) hostSignalStatus {
	want := strings.TrimSpace(upIf)
	ap := strings.TrimSpace(apIface)

	for _, line := range strings.Split(raw, "\n") {
		colonIdx := strings.IndexByte(line, ':')
		if colonIdx <= 0 {
			continue
		}
		ifc := strings.TrimSpace(line[:colonIdx])
		if ifc == "" || strings.Contains(ifc, "|") {
			continue
		}
		if want != "" {
			if ifc != want {
				continue
			}
		} else if ap != "" && ifc == ap {
			continue
		}

		fields := strings.Fields(line[colonIdx+1:])
		// /proc/net/wireless 列布局: status(0) link(1) level(2) noise(3) ...
		if len(fields) < 3 {
			continue
		}
		rssi, ok := parseWirelessDotInt(fields[2])
		if !ok || rssi < -100 || rssi > -15 {
			continue
		}
		var noise int
		if len(fields) >= 4 {
			if nv, nok := parseWirelessDotInt(fields[3]); nok && validWifiNoise(nv) {
				noise = nv
			}
		}
		var snr int
		var hasSNR bool
		if noise < 0 {
			cand := rssi - noise
			if validSINR(cand) {
				snr = cand
				hasSNR = true
			}
		}

		bars, q, qCN, alpha := scoreWifiSignal(rssi)
		rsrpLbl, sinrLbl, rsrqLbl, spPct, spTxt := build4DSignalLabels(0, snr, 0, hasSNR, false, alpha, true, rssi)
		out := hostSignalStatus{
			Available:          true,
			Mode:               "wifi_sta",
			RAT:                "Wi-Fi 中继",
			DisplayRAT:         "Wi-Fi 中继",
			UpstreamIface:      ifc,
			Band:               "Wi-Fi",
			BandCombo:          "Wi-Fi",
			BandTrait:          "无线中继回传链路 · 自动跟踪主路由信号与信道底噪",
			WifiRSSIdBm:        rssi,
			WifiNoiseDbm:       noise,
			SINRdB:             snr,
			HasSINR:            hasSNR,
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
		computeInterference4D(&out, autorateStatus{})
		return out
	}
	return hostSignalStatus{Available: false, UpdatedAt: nowUnix}
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
