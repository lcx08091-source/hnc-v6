// v6_vector_express.go — HNC v6.0.0 · Vector (T4 模块 2):
// Vector Express 跨设备微秒级零排队护航状态机。
//
// 核心机制:
//   1. 常态零干预: 所有设备（含未知设备与随机 MAC 设备）100% 满速无干预, 保持硬件加速/快路径。
//   2. 自动识别 + 防 P2P 误判: 复用 flow_shape.go / fg_model.go / liveCallsByMAC 识别游戏或实时音视频会议,
//      同时校验该设备当前外网并发目的 IP 数 <= max_concurrent_dst_ips (默认 48), 精准排除 BT/P2P 种子下载!
//   3. 救护车通道: 激活跨设备 prio 0 浅驻留 fq_codel (target 2ms / interval 40ms), 背景总池上限温和收至 85%;
//      对局或会议结束后保持 60s 防重开抖动, 随后自动恢复 100% 常规满速与硬件加速。

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	expressStateIdle     = "idle_fullspeed"
	expressStateActive   = "active_escort"
	expressStateCooldown = "cooldown_hold"

	expressDefaultBgCeilPct       = 85
	expressDefaultHoldAfterEndSec = 60
	expressDefaultMaxDstIPs       = 48
	expressTargetLatencyUs        = 2000  // 2ms 浅驻留 fq_codel target
	expressIntervalLatencyUs      = 40000 // 40ms fq_codel interval
	expressPrioBand               = 0     // 跨设备最高优先 prio 0
)

// VectorExpressConfig 护航配置。
type VectorExpressConfig struct {
	Enabled             bool     `json:"enabled"`
	AutoDetect          bool     `json:"auto_detect"`
	ForcedMACs          []string `json:"forced_macs"`
	BgCeilPct           int      `json:"bg_ceil_pct"`
	HoldAfterEndSec     int      `json:"hold_after_end_sec"`
	MaxConcurrentDstIPs int      `json:"max_concurrent_dst_ips"`
}

func defaultVectorExpressConfig() VectorExpressConfig {
	return VectorExpressConfig{
		Enabled:             true,
		AutoDetect:          true,
		ForcedMACs:          []string{},
		BgCeilPct:           expressDefaultBgCeilPct,
		HoldAfterEndSec:     expressDefaultHoldAfterEndSec,
		MaxConcurrentDstIPs: expressDefaultMaxDstIPs,
	}
}

// VectorExpressDeviceSignal 单设备实时信号（支持线上自动采集与单测注入）。
type VectorExpressDeviceSignal struct {
	MAC          string
	TrafficType  string  // gaming | video_call | voice_call | ...
	Confidence   float64 // 0..1
	FgCategory   string  // game | voip | office | ...
	FgAppName    string
	HasLiveCall  bool
	ActiveDstIPs int
}

// VectorExpressDataplaneSpec 下发给底层 tc / offload 的目标姿态。
type VectorExpressDataplaneSpec struct {
	Active          bool     `json:"active"`
	Prio            int      `json:"prio"`
	Qdisc           string   `json:"qdisc"`
	TargetUs        int      `json:"target_us"`
	IntervalUs      int      `json:"interval_us"`
	BgPoolCeilPct   int      `json:"bg_pool_ceil_pct"`
	HwOffloadBypass bool     `json:"hw_offload_bypass"` // true=暂停硬件快路径让 prio 0 接管; false=恢复满速硬件加速
	EscortedMACs    []string `json:"escorted_macs"`
	UpdatedAt       int64    `json:"updated_at"`
}

type vectorExpressEngine struct {
	// 64 位原子字段严格置于 offset 0 (兼容 32-bit ARM)
	transitions atomic.Uint64
	activeFlag  atomic.Int64 // 1 = active_escort 或 cooldown_hold, 0 = idle_fullspeed

	srv            *server
	mu             sync.Mutex
	cfg            VectorExpressConfig
	state          string
	escortedMACs   []string
	escortReasons  map[string]string
	p2pExcluded    []string
	sinceAt        time.Time
	lastRealtimeAt time.Time
	lastApplied    VectorExpressDataplaneSpec
	applyHook      func(spec VectorExpressDataplaneSpec) error
}

func newVectorExpressEngine(s *server) *vectorExpressEngine {
	eng := &vectorExpressEngine{
		srv:           s,
		cfg:           defaultVectorExpressConfig(),
		state:         expressStateIdle,
		escortedMACs:  []string{},
		escortReasons: make(map[string]string),
		p2pExcluded:   []string{},
		lastApplied: VectorExpressDataplaneSpec{
			Active:          false,
			Prio:            expressPrioBand,
			Qdisc:           "fq_codel",
			TargetUs:        expressTargetLatencyUs,
			IntervalUs:      expressIntervalLatencyUs,
			BgPoolCeilPct:   100,
			HwOffloadBypass: false,
			EscortedMACs:    []string{},
		},
	}
	eng.loadConfigLocked()
	return eng
}

func (e *vectorExpressEngine) configPath() string {
	return filepath.Join(e.srv.hncDir, "data", "vector_express.json")
}

func (e *vectorExpressEngine) stateRunPath() string {
	return filepath.Join(e.srv.hncDir, "run", "vector_express_state.json")
}

func (e *vectorExpressEngine) loadConfigLocked() {
	if e.srv == nil || e.srv.hncDir == "" {
		return
	}
	b, err := os.ReadFile(e.configPath())
	if err != nil {
		return
	}
	var loaded VectorExpressConfig
	if json.Unmarshal(b, &loaded) != nil {
		return
	}
	e.cfg = normalizeExpressConfig(loaded)
}

func normalizeExpressConfig(c VectorExpressConfig) VectorExpressConfig {
	if c.BgCeilPct < 50 || c.BgCeilPct > 98 {
		c.BgCeilPct = expressDefaultBgCeilPct
	}
	if c.HoldAfterEndSec < 5 || c.HoldAfterEndSec > 600 {
		c.HoldAfterEndSec = expressDefaultHoldAfterEndSec
	}
	if c.MaxConcurrentDstIPs < 8 || c.MaxConcurrentDstIPs > 2000 {
		c.MaxConcurrentDstIPs = expressDefaultMaxDstIPs
	}
	seen := make(map[string]bool)
	clean := make([]string, 0, len(c.ForcedMACs))
	for _, m := range c.ForcedMACs {
		cm := canonMAC(m)
		if cm != "" && !seen[cm] {
			seen[cm] = true
			clean = append(clean, cm)
		}
	}
	sort.Strings(clean)
	c.ForcedMACs = clean
	return c
}

func (e *vectorExpressEngine) saveConfigLocked() error {
	if e.srv == nil || e.srv.hncDir == "" {
		return nil
	}
	b, err := json.MarshalIndent(e.cfg, "", "  ")
	if err != nil {
		return err
	}
	return discoverWriteAtomic(e.configPath(), b)
}

// collectLiveSignals 从现有 flow_shape / fg_model / liveCalls / conntrack 零侵入聚合各设备信号。
func (e *vectorExpressEngine) collectLiveSignals(now time.Time) []VectorExpressDeviceSignal {
	if e.srv == nil {
		return nil
	}
	ipsBy := e.srv.deviceIPsByMAC()
	owner := make(map[string]string)
	for mac, ips := range ipsBy {
		for _, ip := range ips {
			owner[ip] = mac
		}
	}

	// 统计每台设备当前外网并发目的 IP 数（排除局域网通讯, 精准识别 P2P/BT 洪流）
	dstSets := make(map[string]map[string]bool)
	sn := conntrackSnapshot()
	if sn != nil && sn.readable {
		for _, ent := range sn.entries {
			mac := owner[ent.Src]
			if mac == "" || isPrivateIP(ent.Dst) {
				continue
			}
			if ent.Dport == 53 || ent.Dport == 123 {
				continue
			}
			s := dstSets[mac]
			if s == nil {
				s = make(map[string]bool)
				dstSets[mac] = s
			}
			s[ent.Dst] = true
		}
	}

	tts := trafficTypesByMAC()
	fgs := fgViewsByMAC(now)
	calls := liveCallsByMAC()

	macSet := make(map[string]bool)
	for m := range ipsBy {
		macSet[m] = true
	}
	for m := range tts {
		macSet[m] = true
	}
	for m := range fgs {
		macSet[m] = true
	}
	for m := range calls {
		macSet[m] = true
	}

	out := make([]VectorExpressDeviceSignal, 0, len(macSet))
	for mac := range macSet {
		sig := VectorExpressDeviceSignal{
			MAC:          mac,
			ActiveDstIPs: len(dstSets[mac]),
		}
		if tt, ok := tts[mac]; ok {
			sig.TrafficType = tt.Type
			sig.Confidence = tt.Confidence
		}
		if fv, ok := fgs[mac]; ok && (fv.State == "active" || fv.State == "paused") && !fv.Stale {
			sig.FgCategory = fv.Category
			sig.FgAppName = fv.Name
		}
		if lc := calls[mac]; lc != nil {
			sig.HasLiveCall = true
		}
		out = append(out, sig)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

func isRealtimeAppCategory(cat string) bool {
	c := strings.ToLower(strings.TrimSpace(cat))
	return c == "game" || strings.HasPrefix(c, "game-") || strings.HasPrefix(c, "game_") ||
		c == "voip" || c == "meeting" || c == "rtc"
}

// Step 状态机单步推演（纯确定性输入 now + signals, 便于单元测试覆盖护航触发、P2P 排除与 60s 恢复）。
func (e *vectorExpressEngine) Step(now time.Time, signals []VectorExpressDeviceSignal) map[string]any {
	e.mu.Lock()
	cfg := e.cfg
	prevState := e.state

	if !cfg.Enabled {
		e.state = expressStateIdle
		e.escortedMACs = []string{}
		e.escortReasons = make(map[string]string)
		e.p2pExcluded = []string{}
		e.sinceAt = time.Time{}
		e.lastRealtimeAt = time.Time{}
		e.activeFlag.Store(0)
		if prevState != expressStateIdle {
			e.transitions.Add(1)
			e.applyDataplaneLocked(now, false, nil)
		}
		snap := e.buildSnapshotLocked(now)
		e.mu.Unlock()
		return snap
	}

	forcedSet := make(map[string]bool, len(cfg.ForcedMACs))
	for _, m := range cfg.ForcedMACs {
		forcedSet[m] = true
	}

	escortMap := make(map[string]string)
	for _, m := range cfg.ForcedMACs {
		escortMap[m] = "manual_forced"
	}

	var p2pExcl []string
	if cfg.AutoDetect {
		for _, sig := range signals {
			mac := canonMAC(sig.MAC)
			if mac == "" {
				continue
			}
			if forcedSet[mac] {
				continue
			}
			isRT := (isRealtimeType(sig.TrafficType) && sig.Confidence >= 0.5) ||
				isRealtimeAppCategory(sig.FgCategory) ||
				sig.HasLiveCall
			if !isRT {
				continue
			}
			// P2P / BT 种子洪流排除门禁: 并发外网目的 IP 过载绝不触发救护车抢占
			if sig.ActiveDstIPs > cfg.MaxConcurrentDstIPs {
				p2pExcl = append(p2pExcl, mac)
				continue
			}
			reason := sig.TrafficType
			if reason == "" {
				if sig.HasLiveCall {
					reason = "live_call"
				} else {
					reason = "fg:" + sig.FgCategory
				}
			}
			if sig.FgAppName != "" {
				reason += "(" + sig.FgAppName + ")"
			}
			escortMap[mac] = reason
		}
	}
	sort.Strings(p2pExcl)
	e.p2pExcluded = p2pExcl

	escorted := make([]string, 0, len(escortMap))
	for m := range escortMap {
		escorted = append(escorted, m)
	}
	sort.Strings(escorted)

	holdDur := time.Duration(cfg.HoldAfterEndSec) * time.Second
	if len(escorted) > 0 {
		if e.state == expressStateIdle {
			e.sinceAt = now
		}
		e.state = expressStateActive
		e.lastRealtimeAt = now
		e.escortedMACs = escorted
		e.escortReasons = escortMap
		e.activeFlag.Store(1)
	} else if (e.state == expressStateActive || e.state == expressStateCooldown) &&
		!e.lastRealtimeAt.IsZero() && now.Sub(e.lastRealtimeAt) < holdDur {
		// 对局/会议刚结束: 保持 60s 缓冲期防止选英雄/换局间隙频繁切队列
		e.state = expressStateCooldown
		e.activeFlag.Store(1)
	} else {
		// 常态满速: 所有设备（含未知与随机 MAC 设备）100% 满速无干预 + 恢复硬件加速
		e.state = expressStateIdle
		e.escortedMACs = []string{}
		e.escortReasons = make(map[string]string)
		e.sinceAt = time.Time{}
		e.lastRealtimeAt = time.Time{}
		e.activeFlag.Store(0)
	}

	needActiveDP := e.state == expressStateActive || e.state == expressStateCooldown
	if prevState != e.state || needActiveDP != e.lastApplied.Active {
		e.transitions.Add(1)
		e.applyDataplaneLocked(now, needActiveDP, e.escortedMACs)
	}

	snap := e.buildSnapshotLocked(now)
	e.mu.Unlock()
	return snap
}

func (e *vectorExpressEngine) applyDataplaneLocked(now time.Time, active bool, macs []string) {
	ceilPct := 100
	if active {
		ceilPct = e.cfg.BgCeilPct
	}
	cpMACs := append([]string(nil), macs...)
	if cpMACs == nil {
		cpMACs = []string{}
	}
	spec := VectorExpressDataplaneSpec{
		Active:          active,
		Prio:            expressPrioBand,
		Qdisc:           "fq_codel",
		TargetUs:        expressTargetLatencyUs,
		IntervalUs:      expressIntervalLatencyUs,
		BgPoolCeilPct:   ceilPct,
		HwOffloadBypass: active,
		EscortedMACs:    cpMACs,
		UpdatedAt:       now.Unix(),
	}
	e.lastApplied = spec

	if e.srv != nil && e.srv.hncDir != "" {
		if b, err := json.MarshalIndent(spec, "", "  "); err == nil {
			_ = discoverWriteAtomic(e.stateRunPath(), b)
		}
		// 若真机存在 bin/tc_manager.sh 且处于热点活跃态, 异步通知底层同步队列姿态
		if useNativeDataplane(e.srv.hncDir) {
			mode := "off"
			if active {
				mode = "on"
			}
			if b, err := os.ReadFile(filepath.Join(e.srv.hncDir, "run", "hnc_state")); err == nil {
				st := strings.TrimSpace(string(b))
				if strings.HasPrefix(st, "ACTIVE:") {
					iface := strings.TrimPrefix(st, "ACTIVE:")
					if ifaceNameRE.MatchString(iface) {
						go runBin(e.srv.hncDir, "tc_manager.sh", "vector_express", iface, mode)
					}
				}
			}
		}
	}
	if e.applyHook != nil {
		_ = e.applyHook(spec)
	}
}

func (e *vectorExpressEngine) buildSnapshotLocked(now time.Time) map[string]any {
	cooldownRem := 0
	if e.state == expressStateCooldown && !e.lastRealtimeAt.IsZero() {
		rem := time.Duration(e.cfg.HoldAfterEndSec)*time.Second - now.Sub(e.lastRealtimeAt)
		if rem > 0 {
			cooldownRem = int((rem + time.Second - 1) / time.Second)
		}
	}
	sinceUnix := int64(0)
	if !e.sinceAt.IsZero() {
		sinceUnix = e.sinceAt.Unix()
	}
	reasons := make(map[string]string, len(e.escortReasons))
	for k, v := range e.escortReasons {
		reasons[k] = v
	}
	return map[string]any{
		"ok":                        true,
		"state":                     e.state,
		"active":                    e.state == expressStateActive || e.state == expressStateCooldown,
		"enabled":                   e.cfg.Enabled,
		"auto_detect":               e.cfg.AutoDetect,
		"forced_macs":               append([]string(nil), e.cfg.ForcedMACs...),
		"escorted_macs":             append([]string(nil), e.escortedMACs...),
		"escort_reasons":            reasons,
		"p2p_excluded_macs":         append([]string(nil), e.p2pExcluded...),
		"bg_ceil_pct":               e.lastApplied.BgPoolCeilPct,
		"configured_bg_ceil_pct":    e.cfg.BgCeilPct,
		"hold_after_end_sec":        e.cfg.HoldAfterEndSec,
		"cooldown_remaining_sec":    cooldownRem,
		"since":                     sinceUnix,
		"unknown_devices_fullspeed": true, // 硬门禁保证: 未知与随机 MAC 设备默认 100% 满速无干预
		"dataplane":                 e.lastApplied,
		"transitions":               e.transitions.Load(),
		"config":                    e.cfg,
	}
}

func (e *vectorExpressEngine) isActive() bool {
	return e.activeFlag.Load() == 1
}

func (e *vectorExpressEngine) summary() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return map[string]any{
		"enabled":       e.cfg.Enabled,
		"auto_detect":   e.cfg.AutoDetect,
		"state":         e.state,
		"active":        e.state == expressStateActive || e.state == expressStateCooldown,
		"escorted_macs": append([]string(nil), e.escortedMACs...),
		"bg_ceil_pct":   e.lastApplied.BgPoolCeilPct,
	}
}

func (e *vectorExpressEngine) runLoop(stop <-chan struct{}) {
	tk := time.NewTicker(2 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-tk.C:
			sigs := e.collectLiveSignals(now)
			e.Step(now, sigs)
		}
	}
}

// isVectorExpressActive 供 ThermoCruise O(1) 查询当前是否处于游戏/实时护航期。
func (s *server) isVectorExpressActive() bool {
	if s == nil {
		return false
	}
	return s.v6State().express.isActive()
}

// ── HTTP: GET & POST /api/v6/express ─────────────────────────────────────────

func (s *server) apiVectorExpress(w http.ResponseWriter, r *http.Request) {
	eng := s.v6State().express
	if r.Method == http.MethodGet {
		now := time.Now()
		snap := eng.Step(now, eng.collectLiveSignals(now))
		writeJSON(w, http.StatusOK, snap)
		return
	}
	s.requireMutation(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled             *bool    `json:"enabled"`
			AutoDetect          *bool    `json:"auto_detect"`
			ForcedMACs          []string `json:"forced_macs"`
			ManualMACs          []string `json:"manual_macs"`
			BgCeilPct           *int     `json:"bg_ceil_pct"`
			HoldAfterEndSec     *int     `json:"hold_after_end_sec"`
			MaxConcurrentDstIPs *int     `json:"max_concurrent_dst_ips"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json", "detail": err.Error()})
			return
		}

		eng.mu.Lock()
		next := eng.cfg
		if req.Enabled != nil {
			next.Enabled = *req.Enabled
		}
		if req.AutoDetect != nil {
			next.AutoDetect = *req.AutoDetect
		}
		macInput := req.ForcedMACs
		if macInput == nil && req.ManualMACs != nil {
			macInput = req.ManualMACs
		}
		if macInput != nil {
			cleaned := make([]string, 0, len(macInput))
			seen := make(map[string]bool)
			for _, raw := range macInput {
				cm := canonMAC(raw)
				if cm == "" {
					eng.mu.Unlock()
					writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "invalid mac in forced_macs: " + raw})
					return
				}
				if !seen[cm] {
					seen[cm] = true
					cleaned = append(cleaned, cm)
				}
			}
			sort.Strings(cleaned)
			next.ForcedMACs = cleaned
		}
		if req.BgCeilPct != nil {
			if *req.BgCeilPct < 50 || *req.BgCeilPct > 98 {
				eng.mu.Unlock()
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "bg_ceil_pct must be 50..98"})
				return
			}
			next.BgCeilPct = *req.BgCeilPct
		}
		if req.HoldAfterEndSec != nil {
			if *req.HoldAfterEndSec < 5 || *req.HoldAfterEndSec > 600 {
				eng.mu.Unlock()
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "hold_after_end_sec must be 5..600"})
				return
			}
			next.HoldAfterEndSec = *req.HoldAfterEndSec
		}
		if req.MaxConcurrentDstIPs != nil {
			if *req.MaxConcurrentDstIPs < 8 || *req.MaxConcurrentDstIPs > 2000 {
				eng.mu.Unlock()
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "max_concurrent_dst_ips must be 8..2000"})
				return
			}
			next.MaxConcurrentDstIPs = *req.MaxConcurrentDstIPs
		}
		eng.cfg = normalizeExpressConfig(next)
		err := eng.saveConfigLocked()
		eng.mu.Unlock()

		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write failed", "detail": err.Error()})
			return
		}
		now := time.Now()
		snap := eng.Step(now, eng.collectLiveSignals(now))
		writeJSON(w, http.StatusOK, snap)
	})(w, r)
}
