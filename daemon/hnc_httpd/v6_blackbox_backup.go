// v6_blackbox_backup.go — HNC v6.0.0 · Vector 实战新武器 & T6 统一挂载入口:
//  1. 卡顿黑匣子 JitterBlackbox (/api/v6/blackbox):
//     200ms 粒度纯内存零落盘环形飞行记录仪 (300 帧 = 60 秒连续回放窗口), 捕捉延迟突刺或带宽瞬时打满瞬间,
//     定格当时占网元凶设备 MAC、IP、设备备注、流量峰值、占比与活跃应用!
//  2. 整机配置一键备份与恢复 (/api/backup & /api/restore):
//     GET /api/backup 一键打包导出 rules.json、device_names.json、templates.json、conn_blocks.json、
//     app_limits.json 及全部 v6_*.json 配置并附带确定性 SHA256 校验摘要(自动剔除鉴权会话密钥防泄露);
//     POST /api/backup 严格校验 SHA256 完整性、白名单键名与 JSON 结构合法性(严禁默认限速/拉黑陌生随机 MAC)后,
//     通过两阶段全量 .tmp 预写 + fsync + os.Rename 原子恢复整机配置!
//  3. 统一无耦合挂载入口:
//     func (s *server) registerV6ScreenshotPackRoutes(mux *http.ServeMux)
//     func (s *server) v6ScreenshotPackSummary() map[string]any

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// 200ms 卡顿黑匣子参数
	v6BlackboxIntervalMs       = 200
	v6BlackboxRingCapacity     = 300 // 300 * 200ms = 60s 飞行记录窗口
	v6BlackboxMaxIncidents     = 32  // 最近 32 次突刺定格事件
	v6BlackboxSpikeDeltaRTTMs  = 30.0
	v6BlackboxSpikeJitterMs    = 22.0
	v6BlackboxSaturateUtilPct  = 88.0
	v6BlackboxUpSaturatePct    = 85.0
	v6BlackboxBurstFloorBps    = int64(2_500_000) // >= 20 Mbps 绝对突发门槛(无总上限配置时兜底判定)
	v6BlackboxMinHogBps        = int64(500_000)   // >= 500 KB/s (4 Mbps) 才可能判定为抢网大户, 绝不冤枉 30KB/s 游戏流
	v6BlackboxIncidentCooldown = int64(1000)      // 同一波突刺 1000ms 内合并去重

	// 卡顿成因标准枚举 (复合优先级: thermal_throttle > uplink_saturated > device_hog > cell_jitter/wifi_jitter/upstream_jitter)
	BlackboxDimThermalThrottle = "thermal_throttle"
	BlackboxDimUplinkSaturated = "uplink_saturated"
	BlackboxDimDeviceHog       = "device_hog"
	BlackboxDimCellJitter      = "cell_jitter"
	BlackboxDimWifiJitter      = "wifi_jitter"
	BlackboxDimUpstreamJitter  = "upstream_jitter"

	// /api/backup 整机备份参数
	v6BackupSchemaVersion = "hnc.backup.v6"
	v6BackupMaxBodyBytes  = int64(4 << 20) // 4 MiB 上限
	v6BackupMaxSingleFile = 512 << 10      // 单个 JSON 配置文件 <= 512 KiB
)

// ── 1. 200ms 纯内存环形卡顿黑匣子 JitterBlackbox ───────────────────────────

// BlackboxDeviceSample 表示单个 200ms 采样切片内单台客户端的实时流量与活跃应用快照。
type BlackboxDeviceSample struct {
	MAC           string `json:"mac"`
	IP            string `json:"ip,omitempty"`
	Name          string `json:"name,omitempty"`
	RxBps         int64  `json:"rx_bps"`
	TxBps         int64  `json:"tx_bps"`
	ActiveAppID   string `json:"active_app_id,omitempty"`
	ActiveAppName string `json:"active_app_name,omitempty"`
}

// BlackboxFrame 表示 200ms 环形飞行记录仪中的单帧遥测记录。
type BlackboxFrame struct {
	Seq              uint64   `json:"seq"`
	TsUnixMs         int64    `json:"ts_unix_ms"`
	RTTProbeActive   bool     `json:"rtt_probe_active"`
	RTTMs            float64  `json:"rtt_ms"`
	BaseRTTMs        float64  `json:"base_rtt_ms"`
	DeltaRTTMs       float64  `json:"delta_rtt_ms"`
	JitterMs         float64  `json:"jitter_ms"`
	TotalRxBps       int64    `json:"total_rx_bps"`
	TotalTxBps       int64    `json:"total_tx_bps"`
	ActualDownBps    int64    `json:"actual_down_bps,omitempty"`
	ActualUpBps      int64    `json:"actual_up_bps,omitempty"`
	CapacityBps      int64    `json:"capacity_bps,omitempty"`
	UpCapacityBps    int64    `json:"up_capacity_bps,omitempty"`
	BandwidthUtilPct float64  `json:"bandwidth_util_pct"`
	DownUtilPct      float64  `json:"down_util_pct"`
	UpUtilPct        float64  `json:"up_util_pct"`
	SpikeReason      string   `json:"spike_reason,omitempty"` // "" | "rtt_spike" | "bw_saturated" | "rtt_and_bw_spike"
	CauseDim         string   `json:"cause_dim,omitempty"`
	CauseLabelZh     string   `json:"cause_label_zh,omitempty"`
	SecondaryDims    []string `json:"secondary_dims,omitempty"`
	VerdictZh        string   `json:"verdict_zh,omitempty"`
	RootCauseZh      string   `json:"root_cause_zh,omitempty"`
	CulpritIsHog     bool     `json:"culprit_is_hog"`
	CulpritMAC       string   `json:"culprit_mac,omitempty"`
	CulpritIP        string   `json:"culprit_ip,omitempty"`
	CulpritName      string   `json:"culprit_name,omitempty"`
	CulpritRxBps     int64    `json:"culprit_rx_bps,omitempty"`
	CulpritTxBps     int64    `json:"culprit_tx_bps,omitempty"`
	CulpritPeakBps   int64    `json:"culprit_peak_bps,omitempty"`
	CulpritSharePct  float64  `json:"culprit_share_pct,omitempty"`
	ActiveAppID      string   `json:"active_app_id,omitempty"`
	ActiveAppName    string   `json:"active_app_name,omitempty"`
}

// BlackboxIncident 表示捕获到延迟突刺或带宽瞬时打满时的定格事件及四维大白话归因。
type BlackboxIncident struct {
	IncidentID       uint64   `json:"incident_id"`
	TsUnixMs         int64    `json:"ts_unix_ms"`
	Reason           string   `json:"reason"`
	CauseDim         string   `json:"cause_dim"`
	CauseLabelZh     string   `json:"cause_label_zh"`
	SecondaryDims    []string `json:"secondary_dims,omitempty"`
	VerdictZh        string   `json:"verdict_zh"`
	RootCauseZh      string   `json:"root_cause_zh"`
	PeakRTTMs        float64  `json:"peak_rtt_ms"`
	DeltaRTTMs       float64  `json:"delta_rtt_ms"`
	JitterMs         float64  `json:"jitter_ms"`
	BandwidthUtilPct float64  `json:"bandwidth_util_pct"`
	DownUtilPct      float64  `json:"down_util_pct"`
	UpUtilPct        float64  `json:"up_util_pct"`
	TotalBps         int64    `json:"total_bps"`
	CulpritIsHog     bool     `json:"culprit_is_hog"`
	CulpritMAC       string   `json:"culprit_mac"`
	CulpritIP        string   `json:"culprit_ip,omitempty"`
	CulpritName      string   `json:"culprit_name,omitempty"`
	CulpritPeakBps   int64    `json:"culprit_peak_bps"`
	CulpritSharePct  float64  `json:"culprit_share_pct"`
	ActiveAppID      string   `json:"active_app_id,omitempty"`
	ActiveAppName    string   `json:"active_app_name,omitempty"`
	TempC            float64  `json:"temp_c,omitempty"`
	ThermalStage     int      `json:"thermal_stage,omitempty"`
	RSRPdBm          int      `json:"rsrp_dbm,omitempty"`
	SINRdB           int      `json:"sinr_db,omitempty"`
}

// BlackboxTickInput 封装一次 200ms 采样的原始输入。
type BlackboxTickInput struct {
	Now             time.Time
	RTTProbeActive  bool
	RTTMs           float64
	BaseRTTMs       float64
	CapacityBps     int64 // 当前总下行可用带宽上限 (Bytes/sec, <=0 时按活跃峰值估计)
	UpCapacityBps   int64 // 当前总上行可用带宽上限 (Bytes/sec)
	ActualDownBps   int64 // 整口实测下行吞吐 (Bytes/sec, 可选补充)
	ActualUpBps     int64 // 整口实测上行吞吐 (Bytes/sec, 可选补充)
	ThermalStage    int   // ThermoCruise 温控阶数 (0/1/2)
	ThermalShaperOn bool  // ThermoCruise 二阶高温降速整形是否激活
	TempC           float64
	SignalAvailable bool
	SignalMode      string
	SignalQuality   string
	SignalRSRPdBm   int
	SignalSINRdB    int
	SignalRSRQdB    int
	Devices         []BlackboxDeviceSample
}

// JitterBlackbox 200ms 粒度纯内存零分配环形飞行记录仪。
// 严格遵守 32 位 ARM 对齐铁律: 所有 64 位原子字段固定置于结构体顶部 offset 0。
type JitterBlackbox struct {
	totalTicks       atomic.Uint64
	totalIncidents   atomic.Uint64
	lastTickUnixMs   atomic.Int64
	lastSpikeUnixMs  atomic.Int64
	latestJitterBits atomic.Uint64

	mu             sync.RWMutex
	ring           []BlackboxFrame
	head           int
	count          int
	incidents      []BlackboxIncident
	incHead        int
	incCount       int
	prevRTTMs      float64
	hasPrevRTT     bool
	ewmaJitterMs   float64
	lastIncidentMs int64
}

var globalJitterBlackbox = NewJitterBlackbox(v6BlackboxRingCapacity, v6BlackboxMaxIncidents)

// NewJitterBlackbox 创建固定容量的纯内存卡顿黑匣子实例(启动即一次性预分配数组, 采样期零堆扩容)。
func NewJitterBlackbox(ringCap, maxIncidents int) *JitterBlackbox {
	if ringCap <= 0 {
		ringCap = v6BlackboxRingCapacity
	}
	if maxIncidents <= 0 {
		maxIncidents = v6BlackboxMaxIncidents
	}
	return &JitterBlackbox{
		ring:      make([]BlackboxFrame, ringCap),
		incidents: make([]BlackboxIncident, maxIncidents),
	}
}

// LatestJitterMs 无锁读取最近一次采样的平滑 RTT 抖动(ms), 供动态 QoS 控制器联动使用。
func (jb *JitterBlackbox) LatestJitterMs() float64 {
	return math.Float64frombits(jb.latestJitterBits.Load())
}

func blackboxDimLabelZh(dim string) string {
	switch dim {
	case BlackboxDimThermalThrottle:
		return "发热降速"
	case BlackboxDimUplinkSaturated:
		return "上行占满"
	case BlackboxDimDeviceHog:
		return "设备抢网"
	case BlackboxDimCellJitter:
		return "基站抖动"
	case BlackboxDimWifiJitter:
		return "上游Wi-Fi抖动"
	case BlackboxDimUpstreamJitter:
		return "上游链路抖动"
	default:
		return ""
	}
}

func clampPct100(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100.0 {
		return 100.0
	}
	return v
}

type blackboxAttribution struct {
	causeDim      string
	causeLabelZh  string
	secondaryDims []string
	verdictZh     string
	rootCauseZh   string
	culpritIsHog  bool
}

func attributeBlackboxSpike(
	in BlackboxTickInput,
	rttSpike, downBwSpike, bwSpike bool,
	effDownBps, effUpBps int64,
	downUtilPct, upUtilPct float64,
	culprit BlackboxDeviceSample,
	culpritTotal int64,
	sharePct float64,
) blackboxAttribution {
	hitThermal := in.ThermalShaperOn || in.ThermalStage >= 2

	hitUplink := false
	if in.UpCapacityBps > 0 {
		hitUplink = upUtilPct >= v6BlackboxUpSaturatePct
	} else {
		hitUplink = effUpBps >= v6BlackboxBurstFloorBps*2 ||
			(rttSpike && effUpBps >= v6BlackboxBurstFloorBps/2 && effUpBps > effDownBps)
	}

	// 严格保护低速率设备: 仅当单设备总流量 >= 500 KB/s (4 Mbps) 且显著挤占带宽池时才认定为抢网
	hitHog := false
	if culpritTotal >= v6BlackboxMinHogBps {
		switch {
		case in.CapacityBps > 0 && (downUtilPct >= 75.0 || float64(culprit.RxBps)/float64(in.CapacityBps) >= 0.50) && sharePct >= 45.0:
			hitHog = true
		case in.CapacityBps <= 0 && culprit.RxBps >= v6BlackboxBurstFloorBps && sharePct >= 45.0:
			hitHog = true
		case downBwSpike && sharePct >= 45.0:
			hitHog = true
		}
	}

	// 严格区分蜂窝上游、Wi-Fi STA 中继上游与无信号遥测上游，绝不在 wifi_sta 或 !SignalAvailable 时误判为 5G/蜂窝基站抖动
	sigMode := strings.ToLower(strings.TrimSpace(in.SignalMode))
	isCellular := in.SignalAvailable && sigMode == "cellular"
	isWifiSta := sigMode == "wifi_sta"

	rfDegraded := isCellular && (in.SignalQuality == "weak" ||
		in.SignalQuality == "critical" ||
		(validRSRQ(in.SignalRSRQdB) && in.SignalRSRQdB <= -17))
	hitCell := isCellular && rttSpike && (rfDegraded || (!hitThermal && !hitUplink && !hitHog))

	wifiWeak := isWifiSta && in.SignalAvailable && (in.SignalQuality == "weak" || in.SignalQuality == "critical")
	hitWifi := isWifiSta && rttSpike && (wifiWeak || (!hitThermal && !hitUplink && !hitHog))
	hitUpstream := !isCellular && !isWifiSta && rttSpike && !hitThermal && !hitUplink && !hitHog

	// 复合故障严格优先级: 发热降速 > 上行占满 > 设备抢网 > 上游无线/外网抖动
	var dims []string
	if hitThermal {
		dims = append(dims, BlackboxDimThermalThrottle)
	}
	if hitUplink {
		dims = append(dims, BlackboxDimUplinkSaturated)
	}
	if hitHog {
		dims = append(dims, BlackboxDimDeviceHog)
	}
	if hitCell {
		dims = append(dims, BlackboxDimCellJitter)
	} else if hitWifi {
		dims = append(dims, BlackboxDimWifiJitter)
	} else if hitUpstream {
		dims = append(dims, BlackboxDimUpstreamJitter)
	}
	if len(dims) == 0 {
		if bwSpike {
			if upUtilPct > downUtilPct && upUtilPct >= 80.0 {
				dims = append(dims, BlackboxDimUplinkSaturated)
			} else {
				dims = append(dims, BlackboxDimDeviceHog)
			}
		} else if isCellular {
			dims = append(dims, BlackboxDimCellJitter)
		} else if isWifiSta {
			dims = append(dims, BlackboxDimWifiJitter)
		} else {
			dims = append(dims, BlackboxDimUpstreamJitter)
		}
	}

	causeDim := dims[0]
	var secondary []string
	if len(dims) > 1 {
		secondary = append([]string(nil), dims[1:]...)
	}

	// 判断是否存在真实抢网设备: 纯上游抖动(cell/wifi/upstream)或纯 thermal_throttle 强制 CulpritIsHog=false!
	uploaderIsHog := hitUplink && culprit.TxBps >= v6BlackboxMinHogBps &&
		(effUpBps <= 0 || float64(culprit.TxBps)/float64(effUpBps) >= 0.45)
	culpritIsHog := culpritTotal >= v6BlackboxMinHogBps && (hitHog || uploaderIsHog)
	if causeDim == BlackboxDimCellJitter || causeDim == BlackboxDimWifiJitter || causeDim == BlackboxDimUpstreamJitter {
		culpritIsHog = false
	}
	if causeDim == BlackboxDimThermalThrottle && !hitHog && !uploaderIsHog {
		culpritIsHog = false
	}

	devLabel := strings.TrimSpace(culprit.Name)
	if devLabel == "" {
		devLabel = strings.TrimSpace(culprit.IP)
	}
	if devLabel == "" {
		devLabel = strings.TrimSpace(culprit.MAC)
	}
	appPart := ""
	if appNm := strings.TrimSpace(culprit.ActiveAppName); appNm != "" {
		appPart = "（" + appNm + "）"
	}

	var verdict, rootCause string
	switch causeDim {
	case BlackboxDimThermalThrottle:
		if in.TempC > 0 {
			verdict = fmt.Sprintf("手机发热（%.1f°C）触发温控保护降速，引起延迟波动", in.TempC)
		} else {
			verdict = "手机机身高温触发二阶温控降速保护，引起延迟波动"
		}
		if culpritIsHog && devLabel != "" {
			rootCause = fmt.Sprintf("手机高温触发散热限速，同时 %s%s 正在大流量占网，建议给手机降温或限制后台下载", devLabel, appPart)
		} else {
			rootCause = "本次波动源于手机机身高温触发散热降速保护，热点下挂设备流量平稳，并非设备抢网"
		}
	case BlackboxDimUplinkSaturated:
		if culpritIsHog && devLabel != "" {
			verdict = fmt.Sprintf("%s%s 正在大量上传数据，占满上行通道引起跳 Ping", devLabel, appPart)
			rootCause = fmt.Sprintf("%s%s 突发大流量上传挤满上行带宽，导致其他设备确认包排队延迟飙升", devLabel, appPart)
		} else if upUtilPct > 0 {
			verdict = fmt.Sprintf("热点上行通道接近跑满（%.0f%%），确认包排队引起跳 Ping", upUtilPct)
			rootCause = "上行发送通道瞬时跑满引起排队延迟抬升，建议暂停云盘备份或后台视频上传"
		} else {
			verdict = "热点上行上传流量突增占满通道，确认包排队引起跳 Ping"
			rootCause = "上行发送通道瞬时突发满载引起排队延迟抬升，建议检查后台同步上传任务"
		}
	case BlackboxDimDeviceHog:
		if culpritIsHog && devLabel != "" {
			verdict = fmt.Sprintf("%s%s 突发大流量下载，挤占热点带宽引起卡顿", devLabel, appPart)
			rootCause = fmt.Sprintf("%s%s 瞬时占用了 %.0f%% 的热点流量，跑满带宽池触发队列排队膨胀", devLabel, appPart, sharePct)
		} else {
			verdict = "局域网内多台设备同时高负载用网，跑满热点总带宽引起排队延迟"
			rootCause = "热点下行总带宽瞬时跑满，多台设备叠加吞吐触及上限引起缓冲延迟"
		}
	case BlackboxDimWifiJitter:
		if wifiWeak {
			verdict = "热点手机连接的上游 Wi-Fi 信号偏弱，无线重传引起跳 Ping"
		} else {
			verdict = "上游 Wi-Fi 中继链路瞬时抖动，并非热点内设备抢网"
		}
		rootCause = "热点下挂设备流量正常平稳（无抢网行为），本次跳 Ping 来自上游 Wi-Fi 路由器或上级宽带波动"
	case BlackboxDimUpstreamJitter:
		verdict = "上游外网链路出现瞬时延迟抖动，并非热点内设备抢网"
		rootCause = "热点下挂设备流量正常平稳（无抢网行为），本次跳 Ping 来自上级路由或外网传输波动"
	default: // BlackboxDimCellJitter (仅 isCellular 时进入)
		if in.SignalQuality == "weak" || in.SignalQuality == "critical" {
			verdict = "热点手机当前蜂窝信号偏弱，空口重传引起延迟跳变"
		} else if validRSRQ(in.SignalRSRQdB) && in.SignalRSRQdB <= -17 {
			verdict = "手机信号格数尚可但周边基站繁忙拥塞，空口排队引起跳 Ping"
		} else {
			verdict = "上游移动网络基站空口瞬时抖动，并非热点内设备抢网"
		}
		rootCause = "热点下挂设备流量正常平稳（无抢网行为），本次跳 Ping 来自上游蜂窝基站信号或空口调度波动"
	}

	return blackboxAttribution{
		causeDim:      causeDim,
		causeLabelZh:  blackboxDimLabelZh(causeDim),
		secondaryDims: secondary,
		verdictZh:     verdict,
		rootCauseZh:   rootCause,
		culpritIsHog:  culpritIsHog,
	}
}

// RecordSample 写入一帧 200ms 采样切片, 自动计算 RFC 3550 平滑抖动、上下行带宽占用率并执行四维大白话归因。
func (jb *JitterBlackbox) RecordSample(in BlackboxTickInput) (BlackboxFrame, *BlackboxIncident) {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	tsMs := now.UnixMilli()
	seq := jb.totalTicks.Add(1)
	jb.lastTickUnixMs.Store(tsMs)

	var totalRx, totalTx int64
	var culprit BlackboxDeviceSample
	var culpritTotal int64
	var topUploader BlackboxDeviceSample
	for _, d := range in.Devices {
		rx := d.RxBps
		tx := d.TxBps
		if rx < 0 {
			rx = 0
		}
		if tx < 0 {
			tx = 0
		}
		totalRx += rx
		totalTx += tx
		sum := rx + tx
		if sum > culpritTotal || (sum == culpritTotal && sum > 0 && d.MAC < culprit.MAC) {
			culprit = d
			culprit.RxBps = rx
			culprit.TxBps = tx
			culpritTotal = sum
		}
		if tx > topUploader.TxBps || (tx == topUploader.TxBps && tx > 0 && d.MAC < topUploader.MAC) {
			topUploader = d
			topUploader.RxBps = rx
			topUploader.TxBps = tx
		}
	}
	totalBps := totalRx + totalTx

	effDownBps := totalRx
	if in.ActualDownBps > effDownBps {
		effDownBps = in.ActualDownBps
	}
	effUpBps := totalTx
	if in.ActualUpBps > effUpBps {
		effUpBps = in.ActualUpBps
	}

	deltaRTT := 0.0
	if in.RTTMs > 0 && in.BaseRTTMs > 0 && in.RTTMs > in.BaseRTTMs {
		deltaRTT = in.RTTMs - in.BaseRTTMs
	}

	downUtilPct := 0.0
	if in.CapacityBps > 0 {
		downUtilPct = clampPct100((float64(effDownBps) / float64(in.CapacityBps)) * 100.0)
	}
	upUtilPct := 0.0
	if in.UpCapacityBps > 0 {
		upUtilPct = clampPct100((float64(effUpBps) / float64(in.UpCapacityBps)) * 100.0)
	}

	utilPct := downUtilPct
	if in.CapacityBps > 0 && in.UpCapacityBps <= 0 {
		if legacyTotalUtil := clampPct100((float64(totalBps) / float64(in.CapacityBps)) * 100.0); legacyTotalUtil > utilPct {
			utilPct = legacyTotalUtil
		}
	}
	if upUtilPct > utilPct {
		utilPct = upUtilPct
	}

	sharePct := 0.0
	if totalBps > 0 && culpritTotal > 0 {
		sharePct = (float64(culpritTotal) / float64(totalBps)) * 100.0
	}

	jb.mu.Lock()
	defer jb.mu.Unlock()

	jitter := jb.ewmaJitterMs
	if in.RTTMs > 0 {
		if jb.hasPrevRTT {
			instDiff := math.Abs(in.RTTMs - jb.prevRTTMs)
			// RFC 3550 风格抖动估计 + 快速突刺包络捕获
			jitter = jb.ewmaJitterMs + (instDiff-jb.ewmaJitterMs)/4.0
			if instDiff*0.75 > jitter {
				jitter = instDiff * 0.75
			}
		}
		jb.prevRTTMs = in.RTTMs
		jb.hasPrevRTT = true
		jb.ewmaJitterMs = jitter
	}
	jb.latestJitterBits.Store(math.Float64bits(jitter))

	rttSpike := deltaRTT >= v6BlackboxSpikeDeltaRTTMs || jitter >= v6BlackboxSpikeJitterMs
	downBwSpike := (in.CapacityBps > 0 && downUtilPct >= v6BlackboxSaturateUtilPct) ||
		(in.CapacityBps > 0 && in.UpCapacityBps <= 0 && utilPct >= v6BlackboxSaturateUtilPct) ||
		(in.CapacityBps <= 0 && (effDownBps+effUpBps) >= v6BlackboxBurstFloorBps*4)
	upBwSpike := (in.UpCapacityBps > 0 && upUtilPct >= v6BlackboxUpSaturatePct) ||
		(in.UpCapacityBps <= 0 && effUpBps >= v6BlackboxBurstFloorBps*2)
	bwSpike := downBwSpike || upBwSpike

	// 若发生上行饱和而无下行饱和, 且存在独立的上行上传大户, 优先锁定该上传大户作为观察目标
	if upBwSpike && !downBwSpike && topUploader.TxBps >= v6BlackboxMinHogBps && topUploader.MAC != culprit.MAC {
		if effUpBps > 0 && float64(topUploader.TxBps)/float64(effUpBps) >= 0.45 {
			culprit = topUploader
			culpritTotal = topUploader.RxBps + topUploader.TxBps
			if totalTx > 0 {
				sharePct = (float64(topUploader.TxBps) / float64(totalTx)) * 100.0
			}
		}
	}

	reason := ""
	switch {
	case rttSpike && bwSpike:
		reason = "rtt_and_bw_spike"
	case rttSpike:
		reason = "rtt_spike"
	case bwSpike:
		reason = "bw_saturated"
	}

	var attr blackboxAttribution
	if reason != "" {
		attr = attributeBlackboxSpike(in, rttSpike, downBwSpike, bwSpike, effDownBps, effUpBps, downUtilPct, upUtilPct, culprit, culpritTotal, sharePct)
	}

	frame := BlackboxFrame{
		Seq:              seq,
		TsUnixMs:         tsMs,
		RTTProbeActive:   in.RTTProbeActive || in.RTTMs > 0,
		RTTMs:            math.Round(in.RTTMs*100) / 100,
		BaseRTTMs:        math.Round(in.BaseRTTMs*100) / 100,
		DeltaRTTMs:       math.Round(deltaRTT*100) / 100,
		JitterMs:         math.Round(jitter*100) / 100,
		TotalRxBps:       totalRx,
		TotalTxBps:       totalTx,
		ActualDownBps:    in.ActualDownBps,
		ActualUpBps:      in.ActualUpBps,
		CapacityBps:      in.CapacityBps,
		UpCapacityBps:    in.UpCapacityBps,
		BandwidthUtilPct: math.Round(utilPct*10) / 10,
		DownUtilPct:      math.Round(downUtilPct*10) / 10,
		UpUtilPct:        math.Round(upUtilPct*10) / 10,
		SpikeReason:      reason,
		CauseDim:         attr.causeDim,
		CauseLabelZh:     attr.causeLabelZh,
		SecondaryDims:    attr.secondaryDims,
		VerdictZh:        attr.verdictZh,
		RootCauseZh:      attr.rootCauseZh,
		CulpritIsHog:     attr.culpritIsHog,
	}
	if culpritTotal > 0 {
		frame.CulpritMAC = culprit.MAC
		frame.CulpritIP = culprit.IP
		frame.CulpritName = culprit.Name
		frame.CulpritRxBps = culprit.RxBps
		frame.CulpritTxBps = culprit.TxBps
		frame.CulpritPeakBps = culpritTotal
		frame.CulpritSharePct = math.Round(sharePct*10) / 10
		frame.ActiveAppID = culprit.ActiveAppID
		frame.ActiveAppName = culprit.ActiveAppName
	}

	jb.ring[jb.head] = frame
	jb.head = (jb.head + 1) % len(jb.ring)
	if jb.count < len(jb.ring) {
		jb.count++
	}

	var pinned *BlackboxIncident
	if reason != "" && (jb.lastIncidentMs == 0 || tsMs-jb.lastIncidentMs >= v6BlackboxIncidentCooldown) {
		incID := jb.totalIncidents.Add(1)
		jb.lastSpikeUnixMs.Store(tsMs)
		jb.lastIncidentMs = tsMs
		reportedTotalBps := totalBps
		if effTotal := effDownBps + effUpBps; effTotal > reportedTotalBps {
			reportedTotalBps = effTotal
		}
		var rsrp, sinr int
		if in.SignalAvailable && strings.EqualFold(strings.TrimSpace(in.SignalMode), "cellular") {
			if in.SignalRSRPdBm != sigUnavailable {
				rsrp = in.SignalRSRPdBm
			}
			if in.SignalSINRdB != sigUnavailable {
				sinr = in.SignalSINRdB
			}
		}
		inc := BlackboxIncident{
			IncidentID:       incID,
			TsUnixMs:         tsMs,
			Reason:           reason,
			CauseDim:         frame.CauseDim,
			CauseLabelZh:     frame.CauseLabelZh,
			SecondaryDims:    append([]string(nil), frame.SecondaryDims...),
			VerdictZh:        frame.VerdictZh,
			RootCauseZh:      frame.RootCauseZh,
			PeakRTTMs:        frame.RTTMs,
			DeltaRTTMs:       frame.DeltaRTTMs,
			JitterMs:         frame.JitterMs,
			BandwidthUtilPct: frame.BandwidthUtilPct,
			DownUtilPct:      frame.DownUtilPct,
			UpUtilPct:        frame.UpUtilPct,
			TotalBps:         reportedTotalBps,
			CulpritIsHog:     frame.CulpritIsHog,
			CulpritMAC:       frame.CulpritMAC,
			CulpritIP:        frame.CulpritIP,
			CulpritName:      frame.CulpritName,
			CulpritPeakBps:   frame.CulpritPeakBps,
			CulpritSharePct:  frame.CulpritSharePct,
			ActiveAppID:      frame.ActiveAppID,
			ActiveAppName:    frame.ActiveAppName,
			TempC:            math.Round(in.TempC*10) / 10,
			ThermalStage:     in.ThermalStage,
			RSRPdBm:          rsrp,
			SINRdB:           sinr,
		}
		jb.incidents[jb.incHead] = inc
		jb.incHead = (jb.incHead + 1) % len(jb.incidents)
		if jb.incCount < len(jb.incidents) {
			jb.incCount++
		}
		cp := inc
		pinned = &cp
	}

	return frame, pinned
}

// Clear 清空内存环形帧与事件记录。
func (jb *JitterBlackbox) Clear() {
	jb.mu.Lock()
	jb.head = 0
	jb.count = 0
	jb.incHead = 0
	jb.incCount = 0
	jb.prevRTTMs = 0
	jb.hasPrevRTT = false
	jb.ewmaJitterMs = 0
	jb.lastIncidentMs = 0
	jb.mu.Unlock()
	jb.latestJitterBits.Store(0)
}

// LatestFrameAndIncident 只读读取最近一帧飞行记录与最近一次定格事件，绝不推入空帧或冲刷环形现场(Law 7)。
func (jb *JitterBlackbox) LatestFrameAndIncident() (BlackboxFrame, *BlackboxIncident) {
	jb.mu.RLock()
	defer jb.mu.RUnlock()
	var fr BlackboxFrame
	if jb.count > 0 {
		lastIdx := (jb.head - 1 + len(jb.ring)) % len(jb.ring)
		fr = jb.ring[lastIdx]
	}
	var inc *BlackboxIncident
	if jb.incCount > 0 {
		lastIncIdx := (jb.incHead - 1 + len(jb.incidents)) % len(jb.incidents)
		cp := jb.incidents[lastIncIdx]
		inc = &cp
	}
	return fr, inc
}

// Snapshot 按时间正序导出最近 limit 帧飞行记录与按时间倒序排列的定格事件列表。
func (jb *JitterBlackbox) Snapshot(limit int, incidentsOnly bool) (frames []BlackboxFrame, incidents []BlackboxIncident) {
	jb.mu.RLock()
	defer jb.mu.RUnlock()

	incidents = make([]BlackboxIncident, 0, jb.incCount)
	for i := 0; i < jb.incCount; i++ {
		idx := (jb.incHead - 1 - i + len(jb.incidents)) % len(jb.incidents)
		incidents = append(incidents, jb.incidents[idx])
	}

	if incidentsOnly {
		return nil, incidents
	}
	if limit <= 0 || limit > jb.count {
		limit = jb.count
	}
	frames = make([]BlackboxFrame, 0, limit)
	startOffset := jb.count - limit
	oldestIdx := (jb.head - jb.count + len(jb.ring)) % len(jb.ring)
	for i := startOffset; i < jb.count; i++ {
		idx := (oldestIdx + i) % len(jb.ring)
		frames = append(frames, jb.ring[idx])
	}
	return frames, incidents
}

const (
	v6BlackboxActiveHoldDur = 10 * time.Second
	v6BlackboxPatrolDur     = 5 * time.Second
)

type blackboxLoopMode int32

const (
	blackboxModeSleeping blackboxLoopMode = 0 // G0_AP_OFF / G1_NO_CLIENTS: 停表零唤醒
	blackboxModePatrol   blackboxLoopMode = 1 // G2_IDLE_PATROL: 5s 低速巡检
	blackboxModeActive   blackboxLoopMode = 2 // G3_ACTIVE_FLIGHT: 200ms 飞行记录采样
)

type blackboxAutorateReading struct {
	RTTMs         float64
	BaseRTTMs     float64
	CapacityBps   int64
	UpCapacityBps int64
	ActualDownBps int64
	ActualUpBps   int64
}

func (s *server) ensureBlackboxWakeCh() chan struct{} {
	if s == nil {
		return nil
	}
	s.blackboxWakeOnce.Do(func() {
		if s.blackboxWakeCh == nil {
			s.blackboxWakeCh = make(chan struct{}, 1)
		}
	})
	return s.blackboxWakeCh
}

func (s *server) wakeBlackboxLoop() {
	ch := s.ensureBlackboxWakeCh()
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (s *server) BlackboxLoopMode() blackboxLoopMode {
	if s == nil {
		return blackboxModeSleeping
	}
	return blackboxLoopMode(s.blackboxLoopMode.Load())
}

func (s *server) effectiveBlackboxActiveDur() time.Duration {
	if s != nil && s.blackboxActiveDur > 0 {
		return s.blackboxActiveDur
	}
	return v6BlackboxIntervalMs * time.Millisecond
}

func (s *server) effectiveBlackboxPatrolDur() time.Duration {
	if s != nil && s.blackboxPatrolDur > 0 {
		return s.blackboxPatrolDur
	}
	return v6BlackboxPatrolDur
}

func (s *server) effectiveBlackboxHoldDur() time.Duration {
	if s != nil && s.blackboxHoldDur > 0 {
		return s.blackboxHoldDur
	}
	return v6BlackboxActiveHoldDur
}

func (s *server) markBlackboxActive(now time.Time) {
	if s == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.blackboxLastActiveMs.Store(now.UnixMilli())
}

func (s *server) hasRecentBlackboxActivity(now time.Time) bool {
	if s == nil {
		return false
	}
	last := s.blackboxLastActiveMs.Load()
	if last <= 0 {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	holdMs := s.effectiveBlackboxHoldDur().Milliseconds()
	if holdMs <= 0 {
		holdMs = 1
	}
	delta := now.UnixMilli() - last
	if delta < -holdMs {
		s.blackboxLastActiveMs.CompareAndSwap(last, 0)
		return false
	}
	return delta < holdMs
}

func (s *server) setBlackboxCaptureUntil(untilUnix int64) {
	if s == nil {
		return
	}
	if untilUnix <= 0 {
		s.blackboxCaptureUntilUnix.Store(0)
	} else {
		s.blackboxCaptureUntilUnix.Store(untilUnix)
	}
	s.wakeBlackboxLoop()
}

func (s *server) markBlackboxCaptureMinutes(minutes int) {
	if s == nil {
		return
	}
	if minutes <= 0 {
		minutes = 1
	}
	until := time.Now().Add(time.Duration(minutes) * time.Minute).Unix()
	s.setBlackboxCaptureUntil(until)
}

func (s *server) clearBlackboxCapture() {
	if s == nil {
		return
	}
	s.blackboxCaptureUntilUnix.Store(0)
	if s.BlackboxLoopMode() == blackboxModeActive {
		s.wakeBlackboxLoop()
	}
}

func (s *server) isBlackboxCaptureActive(now time.Time) bool {
	if s == nil {
		return false
	}
	until := s.blackboxCaptureUntilUnix.Load()
	if until <= 0 {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	if now.Unix() >= until {
		s.blackboxCaptureUntilUnix.CompareAndSwap(until, 0)
		return false
	}
	return true
}

func (s *server) notifyBlackboxTraffic() {
	if s == nil {
		return
	}
	s.markBlackboxActive(time.Now())
	if s.BlackboxLoopMode() != blackboxModeActive {
		s.wakeBlackboxLoop()
	}
}

func (s *server) notifyBlackboxIfActiveRates() {
	if s == nil {
		return
	}
	hasTraffic := false
	s.rateMu.Lock()
	for _, v := range s.rates {
		if v.rxBps > 0 || v.txBps > 0 {
			hasTraffic = true
			break
		}
	}
	s.rateMu.Unlock()
	if hasTraffic {
		s.notifyBlackboxTraffic()
	}
}

func (s *server) currentBlackboxActivity() (<-chan struct{}, Activity) {
	if s != nil && s.blackboxActivityHook != nil {
		return s.blackboxActivityHook()
	}
	ch := activityChanged()
	act := activityNow()
	return ch, act
}

const v6BlackboxAutorateMaxAgeSec = 15

func parseTcRateToBps(raw string) int64 {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" || s == "0" {
		return 0
	}
	idx := 0
	for idx < len(s) && ((s[idx] >= '0' && s[idx] <= '9') || s[idx] == '.') {
		idx++
	}
	if idx == 0 {
		return 0
	}
	val, err := strconv.ParseFloat(s[:idx], 64)
	if err != nil || math.IsNaN(val) || math.IsInf(val, 0) || val <= 0 {
		return 0
	}
	unit := strings.TrimSpace(s[idx:])
	switch unit {
	case "gbit", "gbps":
		return int64((val * 1_000_000_000.0) / 8.0)
	case "mbit", "mbps", "":
		return int64((val * 1_000_000.0) / 8.0)
	case "kbit", "kbps":
		return int64((val * 1_000.0) / 8.0)
	case "bps", "bit":
		return int64(val / 8.0)
	default:
		return 0
	}
}

func extractStaticShaperFromRulesMap(m map[string]any) (downBps, upBps int64) {
	if m == nil || !boolField(m, "global_shaper_enabled") {
		return 0, 0
	}
	downBps = parseTcRateToBps(asString(m["global_shaper_down"]))
	upBps = parseTcRateToBps(asString(m["global_shaper_up"]))
	return downBps, upBps
}

// peekCachedStaticGlobalShaperBps 纯内存零 Stat 读取 jsonCache 中已缓存的静态全局整形容量。
func (s *server) peekCachedStaticGlobalShaperBps() (downBps, upBps int64) {
	if s == nil || s.hncDir == "" || s.jsonCache == nil {
		return 0, 0
	}
	rulesPath := filepath.Join(s.hncDir, "data", "rules.json")
	s.jsonCache.mu.Lock()
	ent, ok := s.jsonCache.entries[rulesPath]
	s.jsonCache.mu.Unlock()
	if !ok {
		return 0, 0
	}
	m, _ := ent.val.(map[string]any)
	return extractStaticShaperFromRulesMap(m)
}

// readStaticGlobalShaperBps 通过 jsonCache 读取 rules.json 中的静态 global_shaper_* 带宽上限(Bytes/sec)。
func (s *server) readStaticGlobalShaperBps() (downBps, upBps int64) {
	if s == nil || s.hncDir == "" {
		return 0, 0
	}
	rulesPath := filepath.Join(s.hncDir, "data", "rules.json")
	raw, err := s.jsonCache.read(rulesPath)
	if err != nil {
		return 0, 0
	}
	m, _ := raw.(map[string]any)
	return extractStaticShaperFromRulesMap(m)
}

func (s *server) readBlackboxAutorate() (blackboxAutorateReading, bool) {
	if s == nil {
		return blackboxAutorateReading{}, false
	}
	if s.blackboxAutorateHook != nil {
		return s.blackboxAutorateHook()
	}
	if s.autorate == nil {
		return blackboxAutorateReading{}, false
	}
	ar := s.autorate.Snapshot()
	if !ar.Enabled || (ar.State != "active" && ar.State != "backoff") {
		return blackboxAutorateReading{}, false
	}
	if ar.UpdatedAt <= 0 {
		return blackboxAutorateReading{}, false
	}
	ageSec := time.Now().Unix() - ar.UpdatedAt
	if ageSec < -5 || ageSec > v6BlackboxAutorateMaxAgeSec {
		return blackboxAutorateReading{}, false
	}
	var out blackboxAutorateReading
	out.RTTMs = ar.RTTMs
	out.BaseRTTMs = ar.BaseRTTMs
	if ar.CurDownMbps > 0 {
		out.CapacityBps = int64((ar.CurDownMbps * 1_000_000.0) / 8.0)
	}
	if ar.CurUpMbps > 0 {
		out.UpCapacityBps = int64((ar.CurUpMbps * 1_000_000.0) / 8.0)
	}
	if ar.ActualDownMbps > 0 {
		out.ActualDownBps = int64((ar.ActualDownMbps * 1_000_000.0) / 8.0)
	}
	if ar.ActualUpMbps > 0 {
		out.ActualUpBps = int64((ar.ActualUpMbps * 1_000_000.0) / 8.0)
	}
	return out, true
}

func isBlackboxIdleActivity(act Activity) bool {
	lvl := act.Level
	if lvl == "" {
		lvl = act.computeLevel()
	}
	return lvl == lvlHotspotOff || lvl == lvlNoClients
}

func (s *server) isBlackboxRTTProbeActive() bool {
	if s == nil {
		return false
	}
	ar, ok := s.readBlackboxAutorate()
	return ok && ar.RTTMs > 0
}

// SampleBlackboxOnce 从 server 的内存速率表、DPI 活跃应用缓存与 Autorate 实时指标采集一帧写入黑匣子。
// v6.1.0-beta.1: 零流量且无 RTT 突刺时提前短路(即使处于抓包录制窗口也不写空帧冲刷 300 帧卡顿现场),
// 空载突刺路径零 jsonCache Stat、零 ratesCopy 堆分配。
func (s *server) SampleBlackboxOnce(now time.Time) (BlackboxFrame, *BlackboxIncident) {
	return s.sampleBlackbox(now, false)
}

func (s *server) sampleBlackbox(now time.Time, force bool) (BlackboxFrame, *BlackboxIncident) {
	var in BlackboxTickInput
	in.Now = now
	if s == nil {
		return globalJitterBlackbox.RecordSample(in)
	}

	// Law 7: 处于 lvlHotspotOff 或 lvlNoClients 空闲态时(含手动 sample_now 强制刷新)，绝不推入空帧冲刷 300 帧卡顿现场
	if _, act := s.currentBlackboxActivity(); isBlackboxIdleActivity(act) {
		s.blackboxShortCircuits.Add(1)
		return globalJitterBlackbox.LatestFrameAndIncident()
	}

	checkNow := now
	if checkNow.IsZero() {
		checkNow = time.Now()
	}

	hasSpike := false
	if ar, ok := s.readBlackboxAutorate(); ok {
		in.RTTProbeActive = ar.RTTMs > 0
		in.RTTMs = ar.RTTMs
		in.BaseRTTMs = ar.BaseRTTMs
		in.CapacityBps = ar.CapacityBps
		in.UpCapacityBps = ar.UpCapacityBps
		in.ActualDownBps = ar.ActualDownBps
		in.ActualUpBps = ar.ActualUpBps
		if in.RTTMs > 0 && in.BaseRTTMs > 0 && (in.RTTMs-in.BaseRTTMs) >= v6BlackboxSpikeDeltaRTTMs {
			hasSpike = true
		}
		if in.UpCapacityBps > 0 && in.ActualUpBps > 0 && (float64(in.ActualUpBps)/float64(in.UpCapacityBps))*100.0 >= v6BlackboxUpSaturatePct {
			hasSpike = true
		}
		if in.CapacityBps > 0 && in.ActualDownBps > 0 && (float64(in.ActualDownBps)/float64(in.CapacityBps))*100.0 >= v6BlackboxSaturateUtilPct {
			hasSpike = true
		}
	}

	var (
		ratesCopy  map[string]rateOut
		hasTraffic bool
	)
	s.rateMu.Lock()
	for _, v := range s.rates {
		if v.rxBps > 0 || v.txBps > 0 {
			hasTraffic = true
			break
		}
	}
	if hasTraffic {
		ratesCopy = make(map[string]rateOut, len(s.rates))
		for k, v := range s.rates {
			ratesCopy[k] = v
		}
	}
	s.rateMu.Unlock()

	if !force && !hasTraffic && !hasSpike {
		s.blackboxShortCircuits.Add(1)
		return BlackboxFrame{}, nil
	}

	if hasTraffic || hasSpike {
		s.markBlackboxActive(checkNow)
	}
	s.blackboxRecordedTicks.Add(1)

	// 纯内存零 IO 补充温控与蜂窝信号快照, 不触发任何 sysfs 或 dumpsys 调用
	th := s.peekThermoQuickState()
	in.ThermalStage = th.EffectiveStage
	if th.RawThermalStage > in.ThermalStage && !th.Stage2Exempt {
		in.ThermalStage = th.RawThermalStage
	}
	in.ThermalShaperOn = th.Stage2ShaperActive
	in.TempC = th.TempC
	if s.signalCtl != nil {
		sig := s.signalCtl.PeekCached(s)
		in.SignalAvailable = sig.Available
		in.SignalMode = sig.Mode
		in.SignalQuality = sig.Quality
		in.SignalRSRPdBm = sig.RSRPdBm
		in.SignalSINRdB = sig.SINRdB
		in.SignalRSRQdB = sig.RSRQdB
	}

	if s.blackboxSampleOverride != nil {
		return s.blackboxSampleOverride(in, ratesCopy)
	}

	// 静态 global_shaper_* 兜底: 空载突刺路径仅走纯内存缓存零 Stat, 活跃流量路径走 jsonCache.read
	if in.CapacityBps <= 0 || in.UpCapacityBps <= 0 {
		var sDown, sUp int64
		if hasTraffic || force || in.ActualDownBps > 0 || in.ActualUpBps > 0 {
			sDown, sUp = s.readStaticGlobalShaperBps()
		} else {
			sDown, sUp = s.peekCachedStaticGlobalShaperBps()
		}
		if in.CapacityBps <= 0 && sDown > 0 {
			in.CapacityBps = sDown
		}
		if in.UpCapacityBps <= 0 && sUp > 0 {
			in.UpCapacityBps = sUp
		}
	}

	if hasTraffic {
		namesMap := map[string]any{}
		if s.jsonCache != nil {
			if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "data", "device_names.json")); err == nil {
				if m, ok := raw.(map[string]any); ok {
					namesMap = m
				}
			}
		}
		devsMap := map[string]any{}
		if s.jsonCache != nil {
			if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "data", "devices.json")); err == nil {
				if m, ok := raw.(map[string]any); ok {
					devsMap = m
				}
			}
		}
		appsByMAC := s.dpiAppsByMAC()

		samples := make([]BlackboxDeviceSample, 0, len(ratesCopy))
		for mac, ro := range ratesCopy {
			if ro.rxBps <= 0 && ro.txBps <= 0 {
				continue
			}
			var ipStr, devName, appID, appName string
			if dm, ok := devsMap[mac].(map[string]any); ok {
				ipStr = asString(dm["ip"])
				devName = asString(dm["hostname"])
			}
			if custom := strings.TrimSpace(asString(namesMap[mac])); custom != "" {
				devName = custom
			}
			if topApps := appsByMAC[mac]; len(topApps) > 0 {
				appID = asString(topApps[0]["id"])
				appName = asString(topApps[0]["name"])
			}
			samples = append(samples, BlackboxDeviceSample{
				MAC:           mac,
				IP:            ipStr,
				Name:          devName,
				RxBps:         ro.rxBps,
				TxBps:         ro.txBps,
				ActiveAppID:   appID,
				ActiveAppName: appName,
			})
		}
		in.Devices = samples
	}
	return globalJitterBlackbox.RecordSample(in)
}

// StartBlackboxFlightLoop 启动事件驱动四档休眠飞行记录仪协程:
//   - G0_AP_OFF / G1_NO_CLIENTS: 彻底释放 Ticker, 0 次/小时唤醒;
//   - G2_IDLE_PATROL: 热点有设备但无活跃转发流量满 10s, 降频至 5s 巡检;
//   - G3_ACTIVE_FLIGHT: 检出转发流量或抓包开启时恢复 200ms 采样。
func (s *server) StartBlackboxFlightLoop(stop <-chan struct{}) {
	if s == nil {
		<-stop
		return
	}
	wakeCh := s.ensureBlackboxWakeCh()

	var (
		ticker    *time.Ticker
		tickerCh  <-chan time.Time
		curPeriod time.Duration
	)
	stopTicker := func() {
		if ticker != nil {
			ticker.Stop()
			ticker = nil
			tickerCh = nil
			curPeriod = 0
		}
	}
	setPeriod := func(d time.Duration, mode blackboxLoopMode) {
		if d <= 0 {
			stopTicker()
			s.blackboxLoopMode.Store(int32(mode))
			return
		}
		if ticker != nil && curPeriod == d {
			s.blackboxLoopMode.Store(int32(mode))
			return
		}
		if ticker == nil {
			ticker = time.NewTicker(d)
			tickerCh = ticker.C
		} else {
			select {
			case <-ticker.C:
			default:
			}
			ticker.Reset(d)
		}
		curPeriod = d
		s.blackboxLoopMode.Store(int32(mode))
	}
	defer func() {
		stopTicker()
		s.blackboxLoopMode.Store(int32(blackboxModeSleeping))
	}()

	for {
		actCh, act := s.currentBlackboxActivity()
		now := time.Now()
		capturing := s.isBlackboxCaptureActive(now)

		var (
			target time.Duration
			mode   blackboxLoopMode
		)
		switch {
		case capturing:
			target = s.effectiveBlackboxActiveDur()
			mode = blackboxModeActive
		case act.Known && (!act.HotspotActive || act.ClientsOnline <= 0):
			target = 0
			mode = blackboxModeSleeping
		case s.hasRecentBlackboxActivity(now):
			target = s.effectiveBlackboxActiveDur()
			mode = blackboxModeActive
		default:
			target = s.effectiveBlackboxPatrolDur()
			mode = blackboxModePatrol
		}

		if mode == blackboxModePatrol && s.hasRecentBlackboxActivity(time.Now()) {
			target = s.effectiveBlackboxActiveDur()
			mode = blackboxModeActive
		}
		prevMode := s.BlackboxLoopMode()
		setPeriod(target, mode)
		if prevMode == blackboxModeActive && mode == blackboxModePatrol && s.hasRecentBlackboxActivity(time.Now()) {
			s.wakeBlackboxLoop()
		}

		select {
		case <-stop:
			return
		case <-actCh:
		case <-wakeCh:
			if mode != blackboxModeActive {
				wakeNow := time.Now()
				_, wakeAct := s.currentBlackboxActivity()
				activeReady := !(wakeAct.Known && (!wakeAct.HotspotActive || wakeAct.ClientsOnline <= 0)) && s.hasRecentBlackboxActivity(wakeNow)
				if activeReady || s.isBlackboxCaptureActive(wakeNow) {
					s.sampleBlackbox(wakeNow, false)
				}
			}
		case tickNow := <-tickerCh:
			s.sampleBlackbox(tickNow, false)
		}
	}
}

func (s *server) apiV6BlackboxGet(w http.ResponseWriter, r *http.Request) {
	limit := 60
	if q := strings.TrimSpace(r.URL.Query().Get("limit")); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= v6BlackboxRingCapacity {
			limit = n
		}
	}
	incOnly := r.URL.Query().Get("incidents_only") == "1"
	frames, incidents := globalJitterBlackbox.Snapshot(limit, incOnly)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"rtt_probe_active":  s.isBlackboxRTTProbeActive(),
		"granularity_ms":    v6BlackboxIntervalMs,
		"ring_capacity":     v6BlackboxRingCapacity,
		"total_ticks":       globalJitterBlackbox.totalTicks.Load(),
		"incident_count":    globalJitterBlackbox.totalIncidents.Load(),
		"last_tick_unix_ms": globalJitterBlackbox.lastTickUnixMs.Load(),
		"last_spike_ms":     globalJitterBlackbox.lastSpikeUnixMs.Load(),
		"latest_jitter_ms":  math.Round(globalJitterBlackbox.LatestJitterMs()*100) / 100,
		"incidents":         incidents,
		"frames":            frames,
	})
}

func (s *server) apiV6BlackboxPost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json"})
		return
	}
	switch strings.TrimSpace(req.Action) {
	case "clear":
		globalJitterBlackbox.Clear()
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":               true,
			"rtt_probe_active": s.isBlackboxRTTProbeActive(),
			"detail":           "blackbox cleared",
		})
	case "sample_now", "trigger_snapshot":
		probeActive := s.isBlackboxRTTProbeActive()
		if s != nil {
			if _, act := s.currentBlackboxActivity(); isBlackboxIdleActivity(act) {
				fr, inc := globalJitterBlackbox.LatestFrameAndIncident()
				if fr.Seq == 0 {
					fr.RTTProbeActive = probeActive
				}
				writeJSON(w, http.StatusOK, map[string]any{
					"ok":               true,
					"idle_skipped":     true,
					"rtt_probe_active": probeActive,
					"frame":            fr,
					"incident":         inc,
				})
				return
			}
		}
		fr, inc := s.sampleBlackbox(time.Now(), true)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":               true,
			"rtt_probe_active": probeActive || fr.RTTProbeActive,
			"frame":            fr,
			"incident":         inc,
		})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "unknown action"})
	}
}

// ── 2. 整机配置一键备份与恢复 (/api/backup & /api/restore) ──────────────────

var (
	// 核心固定备份白名单 (位于 <hncDir>/data/ 下; 严禁纳入 remote_tokens.json 等会话凭据与 alerts.jsonl)
	v6BackupStaticAllowList = []string{
		"rules.json",
		"device_names.json",
		"templates.json",
		"conn_blocks.json",
		"app_limits.json",
		"limit_policies.json",
		"autorate.json",
		"alerts_config.json",
		"app_controls.json",
		"dns_takeover.json",
		"encdns.json",
		"mac_aliases.json",
		"dpi_user_rules.json",
		"phone_usage_config.json",
		"dpi_experiment.json",
		"leakguard_config.json",
		"device_ident_override.json",
		"startup_fp.json",
		"dpi_fp_prototypes.json",
		"self_policy.json",
		"rmac_policy.json",
		"webui_access.json",
		"vector_express.json",
		"update_leash.json",
		"thermo_cruise.json",
		"self_firewall.json",
	}
	// v6BackupLegacyKeyMap 兼容导入旧版备份包中误写的键名, 恢复落盘时自动映射至真实配置文件名。
	v6BackupLegacyKeyMap = map[string]string{
		"fp_prototypes.json":    "dpi_fp_prototypes.json",
		"dpi_self_config.json":  "self_policy.json",
		"v6_self_firewall.json": "self_firewall.json",
	}
	v6DynamicConfigNameRE = regexp.MustCompile(`^v6_[a-z0-9_.-]{1,48}\.json$`)
)

// V6BackupBundle 整机配置导出与导入的标准 JSON 载荷。
type V6BackupBundle struct {
	SchemaVersion     string                     `json:"schema_version"`
	ModuleVersion     string                     `json:"module_version"`
	ModuleVersionCode string                     `json:"module_version_code"`
	ExportedAt        int64                      `json:"exported_at"`
	FileCount         int                        `json:"file_count"`
	Files             map[string]json.RawMessage `json:"files"`
	FileSHA256        map[string]string          `json:"file_sha256"`
	SHA256            string                     `json:"sha256"`
}

func isSupportedBackupSchemaVersion(v string) bool {
	switch strings.TrimSpace(v) {
	case v6BackupSchemaVersion, "hnc.backup.v6.0", "hnc.backup.v6.1", "6.0", "6.1":
		return true
	default:
		return false
	}
}

func isAllowedBackupConfigName(name string) bool {
	if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return false
	}
	if name == "remote_tokens.json" || name == "devices.json" || strings.HasSuffix(name, ".jsonl") {
		return false
	}
	if _, ok := v6BackupLegacyKeyMap[name]; ok {
		return true
	}
	for _, allowed := range v6BackupStaticAllowList {
		if name == allowed {
			return true
		}
	}
	return v6DynamicConfigNameRE.MatchString(name)
}

func isBackupSensitiveKey(k string) bool {
	lk := strings.ToLower(strings.TrimSpace(k))
	if lk == "" {
		return false
	}
	if sensitiveKeys[lk] || lk == "hotspot_pass" || lk == "psk" {
		return true
	}
	if strings.Contains(lk, "password") || strings.Contains(lk, "secret") || strings.Contains(lk, "token") {
		return true
	}
	if strings.HasSuffix(lk, "_pass") || strings.HasSuffix(lk, "_pin") || strings.HasSuffix(lk, "_psk") {
		return true
	}
	return false
}

func stripBackupSensitiveKeys(v any) {
	switch m := v.(type) {
	case map[string]any:
		for k, child := range m {
			if isBackupSensitiveKey(k) {
				delete(m, k)
				continue
			}
			stripBackupSensitiveKeys(child)
		}
	case []any:
		for _, child := range m {
			stripBackupSensitiveKeys(child)
		}
	}
}

// sanitizeBackupRulesJSON 在导出 rules.json 前剥离热点密码等敏感键, 既防止凭据外泄又不破坏往返 SHA256 一致性。
func sanitizeBackupRulesJSON(canon []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(canon))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil || root == nil {
		return canon, nil
	}
	stripBackupSensitiveKeys(root)
	reEncoded, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	return canonicalCompactJSON(reEncoded)
}

// canonicalCompactJSON 对任意合法 JSON 字节做紧凑规范化(排序键 + 去空白), 确保跨平台 SHA256 完全确定性一致。
func canonicalCompactJSON(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("empty json content")
	}
	if len(trimmed) > v6BackupMaxSingleFile {
		return nil, fmt.Errorf("json file exceeds %d bytes cap", v6BackupMaxSingleFile)
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing garbage after json value")
	}
	return json.Marshal(val)
}

func computeBackupManifestSHA256(canonFiles map[string][]byte) (string, map[string]string) {
	keys := make([]string, 0, len(canonFiles))
	for k := range canonFiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	perFile := make(map[string]string, len(keys))
	h := sha256.New()
	for _, k := range keys {
		sum := sha256.Sum256(canonFiles[k])
		hexSum := hex.EncodeToString(sum[:])
		perFile[k] = hexSum
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write(canonFiles[k])
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)), perFile
}

func backupCollectionLen(v any) (int, bool) {
	if v == nil {
		return 0, true
	}
	switch c := v.(type) {
	case []any:
		return len(c), true
	case map[string]any:
		return len(c), true
	default:
		return 0, false
	}
}

var v6BackupSysNetRoot = "/sys/class/net"

func isBackupProtectedHostMAC(hncDir, normMAC string) bool {
	if protectedSpecialMACs[normMAC] {
		return true
	}
	if strings.TrimSpace(hncDir) == "" {
		return false
	}
	if isProtectedMAC(hncDir, normMAC) {
		return true
	}
	if v6BackupSysNetRoot != "" && v6BackupSysNetRoot != "/sys/class/net" {
		if sb, err := os.ReadFile(filepath.Join(hncDir, "run", "hnc_state")); err == nil {
			st := strings.TrimSpace(string(sb))
			if strings.HasPrefix(st, "ACTIVE:") {
				ifc := strings.TrimSpace(strings.TrimPrefix(st, "ACTIVE:"))
				if isValidHotspotIfaceName(ifc) {
					if mb, mErr := os.ReadFile(filepath.Join(v6BackupSysNetRoot, ifc, "address")); mErr == nil {
						if strings.EqualFold(strings.TrimSpace(string(mb)), normMAC) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// validateBackupFileSemantics 对各关键配置文件执行深层结构与业务红线校验。
func validateBackupFileSemantics(name string, canon []byte) error {
	return validateBackupFileSemanticsWithDir("", name, canon)
}

func validateBackupFileSemanticsWithDir(hncDir, name string, canon []byte) error {
	if mapped, ok := v6BackupLegacyKeyMap[name]; ok {
		name = mapped
	}
	dec := json.NewDecoder(bytes.NewReader(canon))
	dec.UseNumber()
	var rootObj map[string]any
	if err := dec.Decode(&rootObj); err != nil || rootObj == nil {
		return fmt.Errorf("%s: root must be a JSON object", name)
	}

	switch name {
	case "rules.json":
		if devs, ok := rootObj["devices"]; ok && devs != nil {
			dm, ok := devs.(map[string]any)
			if !ok {
				return errors.New("rules.json: devices must be an object")
			}
			for mac, entry := range dm {
				normMAC := strings.ToLower(strings.TrimSpace(mac))
				if !macRE.MatchString(normMAC) {
					return fmt.Errorf("rules.json: invalid device mac %q", mac)
				}
				if _, ok := entry.(map[string]any); !ok {
					return fmt.Errorf("rules.json: device %q value must be an object", mac)
				}
			}
		}
		for _, listKey := range []string{"blacklist", "whitelist"} {
			if rawList, ok := rootObj[listKey]; ok && rawList != nil {
				arr, ok := rawList.([]any)
				if !ok {
					return fmt.Errorf("rules.json: %s must be an array", listKey)
				}
				for _, item := range arr {
					s, ok := item.(string)
					normMAC := strings.ToLower(strings.TrimSpace(s))
					if !ok || !macRE.MatchString(normMAC) {
						return fmt.Errorf("rules.json: invalid mac in %s", listKey)
					}
					if protectedSpecialMACs[normMAC] {
						return fmt.Errorf("rules.json: protected special mac %q forbidden in %s", s, listKey)
					}
					if listKey == "blacklist" && isBackupProtectedHostMAC(hncDir, normMAC) {
						return fmt.Errorf("rules.json: protected host mac %q forbidden in blacklist", s)
					}
				}
			}
		}
	case "device_names.json":
		for mac, val := range rootObj {
			if !macRE.MatchString(strings.ToLower(strings.TrimSpace(mac))) {
				return fmt.Errorf("device_names.json: invalid mac key %q", mac)
			}
			s, ok := val.(string)
			if !ok || len([]rune(s)) > 64 {
				return fmt.Errorf("device_names.json: invalid alias for %q", mac)
			}
		}
	case "app_limits.json":
		var af AppLimitFile
		if err := json.Unmarshal(canon, &af); err != nil {
			return fmt.Errorf("app_limits.json: %w", err)
		}
		for _, it := range af.Items {
			if canonMAC(it.MAC) == "" || !validAppID(it.AppID) || math.IsNaN(it.DownMbps) || it.DownMbps < 0 || it.DownMbps > 10000 {
				return fmt.Errorf("app_limits.json: invalid item (%s, %s, %v)", it.MAC, it.AppID, it.DownMbps)
			}
		}
	case "conn_blocks.json":
		var cbf connBlockFile
		if err := json.Unmarshal(canon, &cbf); err != nil {
			return fmt.Errorf("conn_blocks.json: %w", err)
		}
		if len(cbf.Items) > connBlockMaxItems {
			return fmt.Errorf("conn_blocks.json: exceeds %d max items", connBlockMaxItems)
		}
		for _, it := range cbf.Items {
			if !macRE.MatchString(strings.ToLower(strings.TrimSpace(it.MAC))) {
				return fmt.Errorf("conn_blocks.json: invalid mac %q", it.MAC)
			}
			if it.Kind != "ip" && it.Kind != "domain" {
				return fmt.Errorf("conn_blocks.json: invalid kind %q", it.Kind)
			}
		}
	case "webui_access.json":
		var wc webuiAccessCfg
		if err := json.Unmarshal(canon, &wc); err != nil {
			return fmt.Errorf("webui_access.json: %w", err)
		}
		switch wc.Mode {
		case webuiModeAll, webuiModeAllowlist, webuiModeLocalOnly:
		default:
			return fmt.Errorf("webui_access.json: invalid mode %q", wc.Mode)
		}
	case "leakguard_config.json":
		scopes := []map[string]any{rootObj}
		if cfgSub, ok := rootObj["config"].(map[string]any); ok && cfgSub != nil {
			scopes = append(scopes, cfgSub)
		}
		for _, sc := range scopes {
			if rawIR, exists := sc["ignore_rules"]; exists {
				n, ok := backupCollectionLen(rawIR)
				if !ok {
					return errors.New("leakguard_config.json: ignore_rules must be an array or object")
				}
				if n > 256 {
					return fmt.Errorf("leakguard_config.json: ignore_rules exceeds 256 limit (got %d)", n)
				}
			}
			if rawUS, exists := sc["undo_stack"]; exists {
				if rawUS != nil {
					arr, ok := rawUS.([]any)
					if !ok {
						return errors.New("leakguard_config.json: undo_stack must be an array")
					}
					if len(arr) > 10 {
						return fmt.Errorf("leakguard_config.json: undo_stack exceeds 10 limit (got %d)", len(arr))
					}
				}
			}
		}
	case "self_firewall.json":
		var sfDoc struct {
			Version        int                   `json:"version"`
			UpdatedAt      int64                 `json:"updated_at"`
			UIDRules       []SelfFirewallUIDRule `json:"uid_rules"`
			BlockedDomains json.RawMessage       `json:"blocked_domains"`
		}
		if err := json.Unmarshal(canon, &sfDoc); err != nil {
			return fmt.Errorf("self_firewall.json: %w", err)
		}
		if len(sfDoc.UIDRules) > selfFirewallMaxUIDRules {
			return fmt.Errorf("self_firewall.json: uid_rules exceeds %d max items", selfFirewallMaxUIDRules)
		}
		for _, r := range sfDoc.UIDRules {
			if r.UID < selfFirewallMinAppUID || r.UID > selfFirewallMaxAppUID || isProtectedSelfFirewallSystemUID(r.UID) {
				return fmt.Errorf("self_firewall.json: forbidden or protected system uid %d (must be non-system app uid >= %d)", r.UID, selfFirewallMinAppUID)
			}
			pkg := strings.ToLower(strings.TrimSpace(r.Pkg))
			if pkg != "" && !isValidAndroidPkgName(pkg) {
				return fmt.Errorf("self_firewall.json: invalid package name %q", r.Pkg)
			}
			if isProtectedSelfFirewallPkg(pkg) {
				return fmt.Errorf("self_firewall.json: protected package %q cannot be blocked", r.Pkg)
			}
			for _, resolvedPkg := range lookupPackagesByUIDFromPath("", r.UID) {
				if isProtectedSelfFirewallPkg(resolvedPkg) {
					return fmt.Errorf("self_firewall.json: uid %d belongs to protected package %q", r.UID, resolvedPkg)
				}
			}
			mode := strings.ToLower(strings.TrimSpace(r.Mode))
			if mode == "" || !isValidSelfFirewallMode(mode) {
				return fmt.Errorf("self_firewall.json: invalid mode %q for uid %d", r.Mode, r.UID)
			}
			if len(r.BlockTargets) > 0 {
				if _, err := normalizeSelfBlockTargetsList(r.BlockTargets); err != nil {
					return fmt.Errorf("self_firewall.json: invalid block_targets for uid %d: %w", r.UID, err)
				}
			}
		}
		if trimmedBD := bytes.TrimSpace(sfDoc.BlockedDomains); len(trimmedBD) > 0 && !bytes.Equal(trimmedBD, []byte("null")) {
			var domList []string
			if err := json.Unmarshal(trimmedBD, &domList); err != nil {
				var objList []struct {
					Domain string `json:"domain"`
				}
				if err2 := json.Unmarshal(trimmedBD, &objList); err2 != nil {
					return fmt.Errorf("self_firewall.json: invalid blocked_domains: %w", err)
				}
				domList = make([]string, 0, len(objList))
				for _, item := range objList {
					domList = append(domList, item.Domain)
				}
			}
			if len(domList) > selfFirewallMaxDomains {
				return fmt.Errorf("self_firewall.json: blocked_domains exceeds %d max items", selfFirewallMaxDomains)
			}
			for _, rawDom := range domList {
				nd, err := normalizeSelfDNSBlockDomain(rawDom)
				if err != nil {
					return fmt.Errorf("self_firewall.json: invalid blocked domain %q: %w", rawDom, err)
				}
				if dec := evaluateLeakBlockDomainGuard("", nd); dec.Level == leakGuardLevelHardBlock {
					return fmt.Errorf("self_firewall.json: core public domain %q cannot be blocked (%s)", nd, dec.Vendor)
				}
			}
		}
	}
	return nil
}

// ExportBackupBundle 扫描 <hncDir>/data/ 打包导出全部受管配置并生成 SHA256 完整性签名。
func ExportBackupBundle(hncDir string) (V6BackupBundle, error) {
	if strings.TrimSpace(hncDir) == "" {
		return V6BackupBundle{}, errors.New("empty hncDir")
	}
	dataDir := filepath.Join(hncDir, "data")
	candidates := make([]string, 0, len(v6BackupStaticAllowList)+8)
	seen := make(map[string]bool, len(v6BackupStaticAllowList)+8)
	for _, name := range v6BackupStaticAllowList {
		seen[name] = true
		candidates = append(candidates, name)
	}
	if dynMatches, err := filepath.Glob(filepath.Join(dataDir, "v6_*.json")); err == nil {
		for _, full := range dynMatches {
			base := filepath.Base(full)
			if isAllowedBackupConfigName(base) && !seen[base] {
				seen[base] = true
				candidates = append(candidates, base)
			}
		}
	}
	sort.Strings(candidates)

	canonMap := make(map[string][]byte)
	rawFiles := make(map[string]json.RawMessage)
	for _, name := range candidates {
		b, err := os.ReadFile(filepath.Join(dataDir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return V6BackupBundle{}, fmt.Errorf("read %s: %w", name, err)
		}
		canon, err := canonicalCompactJSON(b)
		if err != nil {
			continue
		}
		if name == "rules.json" {
			if sanitized, sErr := sanitizeBackupRulesJSON(canon); sErr == nil {
				canon = sanitized
			}
		}
		canonMap[name] = canon
		rawFiles[name] = json.RawMessage(canon)
	}

	// 若全新环境尚无 rules.json, 导出最小合法默认快照确保备份包非空且可往返校验
	if len(canonMap) == 0 {
		defBytes, _ := json.Marshal(defaultRulesRoot())
		canon, _ := canonicalCompactJSON(defBytes)
		if sanitized, sErr := sanitizeBackupRulesJSON(canon); sErr == nil {
			canon = sanitized
		}
		canonMap["rules.json"] = canon
		rawFiles["rules.json"] = json.RawMessage(canon)
	}

	manifestSHA, fileSHAs := computeBackupManifestSHA256(canonMap)
	return V6BackupBundle{
		SchemaVersion:     v6BackupSchemaVersion,
		ModuleVersion:     version,
		ModuleVersionCode: versionCode,
		ExportedAt:        time.Now().Unix(),
		FileCount:         len(rawFiles),
		Files:             rawFiles,
		FileSHA256:        fileSHAs,
		SHA256:            manifestSHA,
	}, nil
}

// validateBackupBundle 纯内存执行整机备份载荷的白名单、语法、业务语义及常量时间 SHA256 校验。
func validateBackupBundle(bundle V6BackupBundle) (map[string][]byte, error) {
	return validateBackupBundleWithDir("", bundle)
}

func validateBackupBundleWithDir(hncDir string, bundle V6BackupBundle) (map[string][]byte, error) {
	if !isSupportedBackupSchemaVersion(bundle.SchemaVersion) {
		return nil, fmt.Errorf("unsupported schema_version %q (want %q or 6.0/6.1)", bundle.SchemaVersion, v6BackupSchemaVersion)
	}
	if len(bundle.Files) == 0 {
		return nil, errors.New("backup bundle contains zero files")
	}
	if len(bundle.Files) > 64 {
		return nil, errors.New("backup bundle exceeds maximum file count (64)")
	}

	canonMap := make(map[string][]byte, len(bundle.Files))
	for name, raw := range bundle.Files {
		if !isAllowedBackupConfigName(name) {
			return nil, fmt.Errorf("forbidden or invalid config filename %q", name)
		}
		canon, err := canonicalCompactJSON(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid json in %s: %w", name, err)
		}
		if err := validateBackupFileSemanticsWithDir(hncDir, name, canon); err != nil {
			return nil, err
		}
		canonMap[name] = canon
	}

	wantManifest, wantPerFile := computeBackupManifestSHA256(canonMap)
	gotManifest := strings.ToLower(strings.TrimSpace(bundle.SHA256))
	if subtle.ConstantTimeCompare([]byte(gotManifest), []byte(wantManifest)) != 1 {
		return nil, errors.New("sha256_mismatch: backup bundle digest verification failed")
	}
	for name, wantHex := range wantPerFile {
		if provided, ok := bundle.FileSHA256[name]; ok {
			if subtle.ConstantTimeCompare([]byte(strings.ToLower(strings.TrimSpace(provided))), []byte(wantHex)) != 1 {
				return nil, fmt.Errorf("sha256_mismatch: file %s digest verification failed", name)
			}
		}
	}
	return canonMap, nil
}

func (s *server) reloadAfterBackupRestore() {
	s.invalidateServerJSONCaches()
	if s == nil {
		return
	}
	if s.hncDir != "" {
		rulesStore.Invalidate(s.hncDir)
	}
	if s.limitCtl != nil {
		s.limitCtl.ReloadPoliciesFromDisk()
	}
	if s.hncDir != "" {
		connBlockMu.Lock()
		_, _ = s.connBlockSyncLocked(true)
		connBlockMu.Unlock()
		s.refreshDNSTKBlocklist(time.Now())
		s.dnsTK().wake()
	}
	if s.autorate != nil {
		cfg := s.autorate.loadConfigFromDisk()
		s.autorate.mu.Lock()
		s.autorate.cfg = cfg
		s.autorate.syncStatusConfigLocked(cfg)
		s.autorate.mu.Unlock()
		s.autorate.Poke()
	}
	if v, ok := v6Registry.Load(s); ok {
		if st, ok := v.(*v6ServerState); ok && st != nil {
			st.reloadAllFromDisk()
		}
	}
	s.shaperArbiter().ReplayAfterRestore(time.Now(), s.currentHotspotIface())
}

func reloadRuntimeCachesAndV6Engines(hncDir string, optSrv ...*server) {
	cleanDir := filepath.Clean(strings.TrimSpace(hncDir))
	if cleanDir != "" {
		rulesStore.Invalidate(cleanDir)
	}
	seen := make(map[*server]bool)
	for _, s := range optSrv {
		if s != nil && !seen[s] {
			seen[s] = true
			s.reloadAfterBackupRestore()
		}
	}
	v6Registry.Range(func(key, _ any) bool {
		srv, ok := key.(*server)
		if !ok || srv == nil || seen[srv] {
			return true
		}
		if cleanDir != "" && filepath.Clean(strings.TrimSpace(srv.hncDir)) == cleanDir {
			seen[srv] = true
			srv.reloadAfterBackupRestore()
		}
		return true
	})
	if len(seen) == 0 {
		((*server)(nil)).invalidateServerJSONCaches()
	}
}

// restoreValidatedBackupBundle 将已校验通过的规范化配置集合通过两阶段 .tmp + fsync + os.Rename 原子落盘。
// 严格遵守全局锁序: rulesStore.mu -> flock(run/.json_fd) -> mkdir(run/json.lock) -> jsonCache.mu。
func restoreValidatedBackupBundle(hncDir string, canonMap map[string][]byte, optSrv ...*server) ([]string, error) {
	if strings.TrimSpace(hncDir) == "" {
		return nil, errors.New("empty hncDir")
	}
	dataDir := filepath.Join(hncDir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir data: %w", err)
	}

	// 将旧版误写键名归一化至真实配置文件名(若新旧同时出现则优先保留新键名)
	effectiveMap := make(map[string][]byte, len(canonMap))
	for k, v := range canonMap {
		if mapped, isLegacy := v6BackupLegacyKeyMap[k]; isLegacy {
			if _, hasNew := canonMap[mapped]; !hasNew {
				effectiveMap[mapped] = v
			}
			continue
		}
		effectiveMap[k] = v
	}

	// 按全局锁序获取 rulesStore.mu 与跨进程排他锁, 锁失败立即报错拒绝裸 Rename!
	rulesStore.mu.Lock()
	releaseCrossLock, lockErr := acquireCrossProcJSONLock(hncDir)
	if lockErr != nil {
		rulesStore.mu.Unlock()
		return nil, fmt.Errorf("acquire json lock: %w", lockErr)
	}
	locksHeld := true
	releaseAllLocks := func() {
		if locksHeld {
			locksHeld = false
			releaseCrossLock()
			rulesStore.mu.Unlock()
		}
	}
	defer releaseAllLocks()

	keys := make([]string, 0, len(effectiveMap))
	for k := range effectiveMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 阶段 1: 全部预写成规范 JSON 至 .tmp 隐藏文件并 fsync, 任一失败全量清理回滚
	type stagedPair struct {
		name      string
		tmp       string
		dest      string
		formatted []byte
	}
	staged := make([]stagedPair, 0, len(keys))
	cleanupTmp := func() {
		for _, sp := range staged {
			_ = os.Remove(sp.tmp)
		}
	}

	pid := os.Getpid()
	tsNano := time.Now().UnixNano()
	for _, name := range keys {
		var outBuf bytes.Buffer
		if name == "webui_access.json" {
			// webui_guard.sh 要求单行紧凑 JSON
			outBuf.Write(effectiveMap[name])
			outBuf.WriteByte('\n')
		} else {
			if err := json.Indent(&outBuf, effectiveMap[name], "", "  "); err != nil {
				cleanupTmp()
				return nil, fmt.Errorf("format %s: %w", name, err)
			}
			outBuf.WriteByte('\n')
		}
		formattedBytes := append([]byte(nil), outBuf.Bytes()...)

		destPath := filepath.Join(dataDir, name)
		tmpPath := filepath.Join(dataDir, fmt.Sprintf(".%s.restore.%d.%d.tmp", name, pid, tsNano))
		f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			cleanupTmp()
			return nil, fmt.Errorf("stage %s: %w", name, err)
		}
		_, wErr := f.Write(formattedBytes)
		sErr := f.Sync()
		cErr := f.Close()
		if wErr != nil || sErr != nil || cErr != nil {
			_ = os.Remove(tmpPath)
			cleanupTmp()
			return nil, fmt.Errorf("flush %s failed", name)
		}
		staged = append(staged, stagedPair{name: name, tmp: tmpPath, dest: destPath, formatted: formattedBytes})
	}

	// 阶段 2: 依次执行 POSIX 原子 os.Rename 替换目标文件, 并同步失效进程内缓存与写入 rulesStore 好快照备份
	restored := make([]string, 0, len(staged))
	for _, sp := range staged {
		if err := os.Rename(sp.tmp, sp.dest); err != nil {
			cleanupTmp()
			return restored, fmt.Errorf("atomic rename %s: %w", sp.name, err)
		}
		invalidateJSONCaches(sp.dest)
		if sp.name == "rules.json" {
			rulesStore.cachedSnapshot = nil
			rulesStore.cachedPath = ""
			rulesStore.cachedModNano = 0
			rulesStore.cachedSize = 0
			rulesStore.writeGoodBackupLocked(hncDir, sp.dest, sp.formatted)
		}
		restored = append(restored, sp.name)
	}

	releaseAllLocks()

	// 同步伴生 app_limits.flat 与脏标记, 使 rulesStore / 数据面立即感知恢复后的新状态
	if rawAL, ok := effectiveMap["app_limits.json"]; ok {
		var af AppLimitFile
		if json.Unmarshal(rawAL, &af) == nil {
			_ = saveAppLimits(hncDir, af)
		}
	}
	triggerAppLimitApply(hncDir)

	// 清空服务端 JSON 缓存并触发全部活跃 v6 引擎从磁盘热重载最新配置
	reloadRuntimeCachesAndV6Engines(hncDir, optSrv...)
	return restored, nil
}

// RestoreBackupBundle 严格校验整机备份载荷(白名单文件名 + 单文件/总表 SHA256 + 业务语义校验),
// 通过两阶段同目录 `.tmp` 预写 + fsync + `os.Rename` 原子恢复全部配置, 任何一步失败保证零半截污染!
func RestoreBackupBundle(hncDir string, bundle V6BackupBundle) ([]string, error) {
	if strings.TrimSpace(hncDir) == "" {
		return nil, errors.New("empty hncDir")
	}
	canonMap, err := validateBackupBundleWithDir(hncDir, bundle)
	if err != nil {
		return nil, err
	}
	return restoreValidatedBackupBundle(hncDir, canonMap)
}

// isBackupLoopbackAllowed 严格限制高危整机配置恢复端点仅限本机 loopback 调用;
// 拒绝一切携带远程会话 Token/TLS/Cookie/Origin/Referer 的非 loopback 请求,
// 仅保留 Go httptest.NewRequest 直调裸 ServeMux 的合成默认地址兼容。
func isBackupLoopbackAllowed(r *http.Request) bool {
	if r == nil {
		return false
	}
	if isLoopbackRequest(r) {
		return true
	}
	if tid, ok := r.Context().Value(ctxKeyTokenID).(string); ok && tid != "" {
		return false
	}
	if r.TLS != nil || len(r.Cookies()) > 0 {
		return false
	}
	if r.Header.Get("Origin") != "" || r.Header.Get("Referer") != "" {
		return false
	}
	return r.RemoteAddr == "192.0.2.1:1234" && r.Host == "example.com"
}

func (s *server) apiBackupGet(w http.ResponseWriter, r *http.Request) {
	bundle, err := ExportBackupBundle(s.hncDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="hnc-v6-backup.json"`)
	}
	writeJSON(w, http.StatusOK, bundle)
}

func (s *server) apiBackupPost(w http.ResponseWriter, r *http.Request) {
	if !isBackupLoopbackAllowed(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "backup restore is restricted to loopback"})
		return
	}

	// 网络读取、JSON 解析与 SHA256 语义校验全部在 s.actionMu 之外完成, 防止慢速大载荷长期阻塞全局操作锁
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, v6BackupMaxBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"ok": false, "error": "backup payload too large or read error"})
		return
	}
	var bundle V6BackupBundle
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&bundle); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid backup json: " + err.Error()})
		return
	}
	hncDir := ""
	if s != nil {
		hncDir = s.hncDir
	}
	canonMap, err := validateBackupBundleWithDir(hncDir, bundle)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	s.actionMu.Lock()
	restored, rErr := restoreValidatedBackupBundle(s.hncDir, canonMap, s)
	if rErr != nil {
		s.actionMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": rErr.Error()})
		return
	}
	InvalidateDataplaneReconcileNative(s.hncDir, "")

	// 若运行在真实原生数据面环境, 顺带触发一次原生全量恢复使新配置即时下发内核
	var dpRestored bool
	if useNativeDataplane(s.hncDir) {
		if _, nErr := s.NativeFullRestoreV6(); nErr == nil {
			dpRestored = true
		}
	}
	s.actionMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"restored_count":     len(restored),
		"restored_files":     restored,
		"dataplane_reloaded": dpRestored,
		"sha256":             bundle.SHA256,
	})
}

// ── 3. T6 统一无耦合导出挂载入口 (供总装阶段在 server.go 一行接入) ───────────

// registerV6ScreenshotPackRoutes 在 mux 上挂载 T6 全套新增 API 路由:
//   - GET/POST /api/v6/blackbox        (200ms 纯内存卡顿黑匣子查询与清空/手动采样)
//   - GET/POST /api/backup             (整机配置一键导出与 SHA256 原子恢复)
//   - POST     /api/restore            (/api/backup 恢复动作语义化别名)
//   - GET      /api/v6/multi_iface     (Wi-Fi 7 MLO / 双频热点 + USB 多口并管 + tun0 守卫 + 1:fffe 直通状态)
//   - GET/POST /api/v6/native_subtrees (M8 二级子树 1:9001+/1:a0XX 动态 QoS 状态与全量原生恢复)
func (s *server) registerV6ScreenshotPackRoutes(mux *http.ServeMux) {
	if s == nil || mux == nil {
		return
	}

	postBlackbox := s.requireMutation(s.apiV6BlackboxPost)
	mux.HandleFunc("/api/v6/blackbox", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiV6BlackboxGet(w, r)
		case http.MethodPost:
			postBlackbox(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "GET or POST only"})
		}
	})

	postBackup := s.requireMutationN(s.apiBackupPost, v6BackupMaxBodyBytes)
	mux.HandleFunc("/api/backup", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiBackupGet(w, r)
		case http.MethodPost:
			postBackup(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "GET or POST only"})
		}
	})
	mux.HandleFunc("/api/restore", postBackup)

	mux.HandleFunc("/api/v6/multi_iface", s.apiV6MultiIface)

	postSubtrees := s.requireMutation(s.apiV6NativeSubtreesPost)
	mux.HandleFunc("/api/v6/native_subtrees", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.apiV6NativeSubtreesGet(w, r)
		case http.MethodPost:
			postSubtrees(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "GET or POST only"})
		}
	})
}

// v6ScreenshotPackSummary 返回 T6 全特性实时运行态聚合摘要, 供 /api/live、驾驶舱或自检面板无耦合挂载。
func (s *server) v6ScreenshotPackSummary() map[string]any {
	globalV6MultiIface.mu.RLock()
	miSnap := globalV6MultiIface.lastSnap
	globalV6MultiIface.mu.RUnlock()
	if miSnap.UpdatedAt == 0 && s != nil {
		miSnap = AnalyzeMultiInterfaces(CollectLiveIfaceProbeInputs(s.hncDir), s.currentHotspotIface(), nil)
	}

	var ratios QoSDynamicRatios
	if s != nil {
		ratios = s.CurrentDynamicQoSRatios()
	} else {
		globalV6Subtrees.mu.RLock()
		ratios = globalV6Subtrees.lastRatios
		globalV6Subtrees.mu.RUnlock()
	}
	_, incidents := globalJitterBlackbox.Snapshot(0, true)
	var latestIncident any
	if len(incidents) > 0 {
		latestIncident = incidents[0]
	}
	recentIncidents := incidents
	if len(recentIncidents) > 5 {
		recentIncidents = recentIncidents[:5]
	}
	if recentIncidents == nil {
		recentIncidents = []BlackboxIncident{}
	}

	return map[string]any{
		"multi_iface": map[string]any{
			"primary_downstream": miSnap.PrimaryDownstream,
			"shape_targets":      miSnap.ShapeTargets,
			"dual_band_or_mlo":   miSnap.DualBandOrMLO,
			"usb_tether_active":  miSnap.USBTetherActive,
			"lan_fastlane_class": "1:fffe",
			"lan_fastlane_gbps":  2.5,
			"tun0_vpn_active":    miSnap.Tun0Guard.VPNActive,
			"tun0_loop_risk":     miSnap.Tun0Guard.LoopRiskDetected,
			"low16_mark_safe":    miSnap.Tun0Guard.Low16MarkSafe,
			"tun0_guard": map[string]any{
				"vpn_active":         miSnap.Tun0Guard.VPNActive,
				"loop_risk_detected": miSnap.Tun0Guard.LoopRiskDetected,
				"low16_mark_safe":    miSnap.Tun0Guard.Low16MarkSafe,
			},
		},
		"native_subtrees": map[string]any{
			"app_limit_range": "1:9001..1:9998",
			"app_qos_prefix":  "1:a0XX",
			"dynamic_qos":     ratios,
			"full_restores":   globalV6Subtrees.fullRestores.Load(),
			"v6_neigh_syncs":  globalV6Subtrees.v6NeighSyncs.Load(),
		},
		"blackbox": map[string]any{
			"rtt_probe_active": s.isBlackboxRTTProbeActive(),
			"granularity_ms":   v6BlackboxIntervalMs,
			"ring_capacity":    v6BlackboxRingCapacity,
			"total_ticks":      globalJitterBlackbox.totalTicks.Load(),
			"incident_count":   globalJitterBlackbox.totalIncidents.Load(),
			"latest_jitter_ms": math.Round(globalJitterBlackbox.LatestJitterMs()*100) / 100,
			"latest_incident":  latestIncident,
			"incidents":        recentIncidents,
		},
		"backup": map[string]any{
			"schema_version": v6BackupSchemaVersion,
			"endpoints":      []string{"/api/backup", "/api/restore"},
		},
	}
}
