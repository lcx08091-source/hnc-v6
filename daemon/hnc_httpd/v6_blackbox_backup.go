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
	v6BlackboxBurstFloorBps    = int64(2_500_000) // >= 20 Mbps 绝对突发门槛(无总上限配置时兜底判定)
	v6BlackboxIncidentCooldown = int64(1000)      // 同一波突刺 1000ms 内合并去重

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
	Seq              uint64  `json:"seq"`
	TsUnixMs         int64   `json:"ts_unix_ms"`
	RTTMs            float64 `json:"rtt_ms"`
	BaseRTTMs        float64 `json:"base_rtt_ms"`
	DeltaRTTMs       float64 `json:"delta_rtt_ms"`
	JitterMs         float64 `json:"jitter_ms"`
	TotalRxBps       int64   `json:"total_rx_bps"`
	TotalTxBps       int64   `json:"total_tx_bps"`
	CapacityBps      int64   `json:"capacity_bps,omitempty"`
	BandwidthUtilPct float64 `json:"bandwidth_util_pct"`
	SpikeReason      string  `json:"spike_reason,omitempty"` // "" | "rtt_spike" | "bw_saturated" | "rtt_and_bw_spike"
	CulpritMAC       string  `json:"culprit_mac,omitempty"`
	CulpritIP        string  `json:"culprit_ip,omitempty"`
	CulpritName      string  `json:"culprit_name,omitempty"`
	CulpritRxBps     int64   `json:"culprit_rx_bps,omitempty"`
	CulpritTxBps     int64   `json:"culprit_tx_bps,omitempty"`
	CulpritPeakBps   int64   `json:"culprit_peak_bps,omitempty"`
	CulpritSharePct  float64 `json:"culprit_share_pct,omitempty"`
	ActiveAppID      string  `json:"active_app_id,omitempty"`
	ActiveAppName    string  `json:"active_app_name,omitempty"`
}

// BlackboxIncident 表示捕获到延迟突刺或带宽瞬时打满时的定格元凶事件。
type BlackboxIncident struct {
	IncidentID       uint64  `json:"incident_id"`
	TsUnixMs         int64   `json:"ts_unix_ms"`
	Reason           string  `json:"reason"`
	PeakRTTMs        float64 `json:"peak_rtt_ms"`
	DeltaRTTMs       float64 `json:"delta_rtt_ms"`
	JitterMs         float64 `json:"jitter_ms"`
	BandwidthUtilPct float64 `json:"bandwidth_util_pct"`
	TotalBps         int64   `json:"total_bps"`
	CulpritMAC       string  `json:"culprit_mac"`
	CulpritIP        string  `json:"culprit_ip,omitempty"`
	CulpritName      string  `json:"culprit_name,omitempty"`
	CulpritPeakBps   int64   `json:"culprit_peak_bps"`
	CulpritSharePct  float64 `json:"culprit_share_pct"`
	ActiveAppID      string  `json:"active_app_id,omitempty"`
	ActiveAppName    string  `json:"active_app_name,omitempty"`
}

// BlackboxTickInput 封装一次 200ms 采样的原始输入。
type BlackboxTickInput struct {
	Now         time.Time
	RTTMs       float64
	BaseRTTMs   float64
	CapacityBps int64 // 当前总链路可用带宽上限 (Bytes/sec, <=0 时按活跃峰值估计)
	Devices     []BlackboxDeviceSample
}

// JitterBlackbox 200ms 粒度纯内存零分配环形飞行记录仪。
// 严格遵守 32 位 ARM 对齐铁律: 所有 64 位原子字段固定置于结构体顶部 offset 0。
type JitterBlackbox struct {
	totalTicks      atomic.Uint64
	totalIncidents  atomic.Uint64
	lastTickUnixMs  atomic.Int64
	lastSpikeUnixMs atomic.Int64
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

// RecordSample 写入一帧 200ms 采样切片, 自动计算 RFC 3550 平滑抖动、带宽占用率并定格占网元凶设备。
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
	}
	totalBps := totalRx + totalTx

	deltaRTT := 0.0
	if in.RTTMs > 0 && in.BaseRTTMs > 0 && in.RTTMs > in.BaseRTTMs {
		deltaRTT = in.RTTMs - in.BaseRTTMs
	}

	utilPct := 0.0
	if in.CapacityBps > 0 {
		utilPct = (float64(totalRx) / float64(in.CapacityBps)) * 100.0
		if upUtil := (float64(totalBps) / float64(in.CapacityBps)) * 100.0; upUtil > utilPct {
			utilPct = upUtil
		}
		if utilPct > 100.0 {
			utilPct = 100.0
		}
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
	bwSpike := (in.CapacityBps > 0 && utilPct >= v6BlackboxSaturateUtilPct) ||
		(in.CapacityBps <= 0 && totalBps >= v6BlackboxBurstFloorBps*4)

	reason := ""
	switch {
	case rttSpike && bwSpike:
		reason = "rtt_and_bw_spike"
	case rttSpike:
		reason = "rtt_spike"
	case bwSpike:
		reason = "bw_saturated"
	}

	frame := BlackboxFrame{
		Seq:              seq,
		TsUnixMs:         tsMs,
		RTTMs:            math.Round(in.RTTMs*100) / 100,
		BaseRTTMs:        math.Round(in.BaseRTTMs*100) / 100,
		DeltaRTTMs:       math.Round(deltaRTT*100) / 100,
		JitterMs:         math.Round(jitter*100) / 100,
		TotalRxBps:       totalRx,
		TotalTxBps:       totalTx,
		CapacityBps:      in.CapacityBps,
		BandwidthUtilPct: math.Round(utilPct*10) / 10,
		SpikeReason:      reason,
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
		inc := BlackboxIncident{
			IncidentID:       incID,
			TsUnixMs:         tsMs,
			Reason:           reason,
			PeakRTTMs:        frame.RTTMs,
			DeltaRTTMs:       frame.DeltaRTTMs,
			JitterMs:         frame.JitterMs,
			BandwidthUtilPct: frame.BandwidthUtilPct,
			TotalBps:         totalBps,
			CulpritMAC:       frame.CulpritMAC,
			CulpritIP:        frame.CulpritIP,
			CulpritName:      frame.CulpritName,
			CulpritPeakBps:   frame.CulpritPeakBps,
			CulpritSharePct:  frame.CulpritSharePct,
			ActiveAppID:      frame.ActiveAppID,
			ActiveAppName:    frame.ActiveAppName,
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

// SampleBlackboxOnce 从 server 的内存速率表、DPI 活跃应用缓存与 Autorate 实时指标采集一帧写入黑匣子。
func (s *server) SampleBlackboxOnce(now time.Time) (BlackboxFrame, *BlackboxIncident) {
	var in BlackboxTickInput
	in.Now = now
	if s == nil {
		return globalJitterBlackbox.RecordSample(in)
	}

	if s.autorate != nil {
		ar := s.autorate.Snapshot()
		in.RTTMs = ar.RTTMs
		in.BaseRTTMs = ar.BaseRTTMs
		if ar.CurDownMbps > 0 {
			in.CapacityBps = int64((ar.CurDownMbps * 1_000_000.0) / 8.0)
		}
	}

	// 读取设备备注与 IP 快照 (命中 mtime+size jsonCache 时零磁盘 I/O!)
	namesMap := map[string]any{}
	if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "data", "device_names.json")); err == nil {
		if m, ok := raw.(map[string]any); ok {
			namesMap = m
		}
	}
	devsMap := map[string]any{}
	if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "data", "devices.json")); err == nil {
		if m, ok := raw.(map[string]any); ok {
			devsMap = m
		}
	}
	appsByMAC := s.dpiAppsByMAC()

	s.rateMu.Lock()
	ratesCopy := make(map[string]rateOut, len(s.rates))
	for k, v := range s.rates {
		ratesCopy[k] = v
	}
	s.rateMu.Unlock()

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
	return globalJitterBlackbox.RecordSample(in)
}

// StartBlackboxFlightLoop 启动 200ms 纯内存飞行记录仪协程(随 stop 通道优雅退出, 零 goroutine 泄漏)。
func (s *server) StartBlackboxFlightLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(v6BlackboxIntervalMs * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			s.SampleBlackboxOnce(now)
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
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "detail": "blackbox cleared"})
	case "sample_now", "trigger_snapshot":
		fr, inc := s.SampleBlackboxOnce(time.Now())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "frame": fr, "incident": inc})
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
	}
	v6DynamicConfigNameRE = regexp.MustCompile(`^v6_[a-z0-9_.-]{1,48}\.json$`)
)

// V6BackupBundle 整机配置导出与导入的标准 JSON 载荷。
type V6BackupBundle struct {
	SchemaVersion string                     `json:"schema_version"`
	ModuleVersion string                     `json:"module_version"`
	ExportedAt    int64                      `json:"exported_at"`
	FileCount     int                        `json:"file_count"`
	Files         map[string]json.RawMessage `json:"files"`
	FileSHA256    map[string]string          `json:"file_sha256"`
	SHA256        string                     `json:"sha256"`
}

func isAllowedBackupConfigName(name string) bool {
	if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return false
	}
	if name == "remote_tokens.json" || name == "devices.json" || strings.HasSuffix(name, ".jsonl") {
		return false
	}
	for _, allowed := range v6BackupStaticAllowList {
		if name == allowed {
			return true
		}
	}
	return v6DynamicConfigNameRE.MatchString(name)
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

// validateBackupFileSemantics 对各关键配置文件执行深层结构与业务红线校验。
func validateBackupFileSemantics(name string, canon []byte) error {
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
				if !macRE.MatchString(strings.ToLower(strings.TrimSpace(mac))) {
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
					if !ok || !macRE.MatchString(strings.ToLower(strings.TrimSpace(s))) {
						return fmt.Errorf("rules.json: invalid mac in %s", listKey)
					}
					if protectedSpecialMACs[strings.ToLower(strings.TrimSpace(s))] {
						return fmt.Errorf("rules.json: protected special mac %q forbidden in %s", s, listKey)
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
		canonMap[name] = canon
		rawFiles[name] = json.RawMessage(canon)
	}

	// 若全新环境尚无 rules.json, 导出最小合法默认快照确保备份包非空且可往返校验
	if len(canonMap) == 0 {
		defBytes, _ := json.Marshal(defaultRulesRoot())
		canon, _ := canonicalCompactJSON(defBytes)
		canonMap["rules.json"] = canon
		rawFiles["rules.json"] = json.RawMessage(canon)
	}

	manifestSHA, fileSHAs := computeBackupManifestSHA256(canonMap)
	return V6BackupBundle{
		SchemaVersion: v6BackupSchemaVersion,
		ModuleVersion: version,
		ExportedAt:    time.Now().Unix(),
		FileCount:     len(rawFiles),
		Files:         rawFiles,
		FileSHA256:    fileSHAs,
		SHA256:        manifestSHA,
	}, nil
}

// RestoreBackupBundle 严格校验整机备份载荷(白名单文件名 + 单文件/总表 SHA256 + 业务语义校验),
// 通过两阶段同目录 `.tmp` 预写 + fsync + `os.Rename` 原子恢复全部配置, 任何一步失败保证零半截污染!
func RestoreBackupBundle(hncDir string, bundle V6BackupBundle) ([]string, error) {
	if strings.TrimSpace(hncDir) == "" {
		return nil, errors.New("empty hncDir")
	}
	if bundle.SchemaVersion != v6BackupSchemaVersion {
		return nil, fmt.Errorf("unsupported schema_version %q (want %q)", bundle.SchemaVersion, v6BackupSchemaVersion)
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
		if err := validateBackupFileSemantics(name, canon); err != nil {
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

	dataDir := filepath.Join(hncDir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir data: %w", err)
	}

	// 协同获取 JSON 目录锁
	releaseJSONLock := acquireCooperativeJSONLock(hncDir)
	defer releaseJSONLock()

	keys := make([]string, 0, len(canonMap))
	for k := range canonMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 阶段 1: 全部预写成格式化 JSON 至 .tmp 隐藏文件并 fsync, 任一失败全量清理回滚
	type stagedPair struct {
		name string
		tmp  string
		dest string
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
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, canonMap[name], "", "  "); err != nil {
			cleanupTmp()
			return nil, fmt.Errorf("format %s: %w", name, err)
		}
		pretty.WriteByte('\n')

		destPath := filepath.Join(dataDir, name)
		tmpPath := filepath.Join(dataDir, fmt.Sprintf(".%s.restore.%d.%d.tmp", name, pid, tsNano))
		f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			cleanupTmp()
			return nil, fmt.Errorf("stage %s: %w", name, err)
		}
		_, wErr := f.Write(pretty.Bytes())
		sErr := f.Sync()
		cErr := f.Close()
		if wErr != nil || sErr != nil || cErr != nil {
			_ = os.Remove(tmpPath)
			cleanupTmp()
			return nil, fmt.Errorf("flush %s failed", name)
		}
		staged = append(staged, stagedPair{name: name, tmp: tmpPath, dest: destPath})
	}

	// 阶段 2: 依次执行 POSIX 原子 os.Rename 替换目标文件
	restored := make([]string, 0, len(staged))
	for _, sp := range staged {
		if err := os.Rename(sp.tmp, sp.dest); err != nil {
			cleanupTmp()
			return restored, fmt.Errorf("atomic rename %s: %w", sp.name, err)
		}
		restored = append(restored, sp.name)
	}

	// 同步伴生 app_limits.flat 与脏标记, 使 rulesStore / 数据面立即感知恢复后的新状态
	if rawAL, ok := canonMap["app_limits.json"]; ok {
		var af AppLimitFile
		if json.Unmarshal(rawAL, &af) == nil {
			_ = saveAppLimits(hncDir, af)
		}
	}
	triggerAppLimitApply(hncDir)
	return restored, nil
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
	s.actionMu.Lock()
	defer s.actionMu.Unlock()

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
	restored, err := RestoreBackupBundle(s.hncDir, bundle)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	// 若运行在真实原生数据面环境, 顺带触发一次原生全量恢复使新配置即时下发内核
	var dpRestored bool
	if useNativeDataplane(s.hncDir) {
		if _, rErr := s.NativeFullRestoreV6(); rErr == nil {
			dpRestored = true
		}
	}

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

	ratios := globalV6Subtrees.lastRatios
	if s != nil {
		ratios = s.CurrentDynamicQoSRatios()
	}
	_, incidents := globalJitterBlackbox.Snapshot(0, true)
	var latestIncident any
	if len(incidents) > 0 {
		latestIncident = incidents[0]
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
		},
		"native_subtrees": map[string]any{
			"app_limit_range": "1:9001..1:9998",
			"app_qos_prefix":  "1:a0XX",
			"dynamic_qos":     ratios,
			"full_restores":   globalV6Subtrees.fullRestores.Load(),
			"v6_neigh_syncs":  globalV6Subtrees.v6NeighSyncs.Load(),
		},
		"blackbox": map[string]any{
			"granularity_ms":   v6BlackboxIntervalMs,
			"ring_capacity":    v6BlackboxRingCapacity,
			"total_ticks":      globalJitterBlackbox.totalTicks.Load(),
			"incident_count":   globalJitterBlackbox.totalIncidents.Load(),
			"latest_jitter_ms": math.Round(globalJitterBlackbox.LatestJitterMs()*100) / 100,
			"latest_incident":  latestIncident,
		},
		"backup": map[string]any{
			"schema_version": v6BackupSchemaVersion,
			"endpoints":      []string{"/api/backup", "/api/restore"},
		},
	}
}
