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
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type v6EngineLoopMode int32

const (
	v6EngineModeSleeping     v6EngineLoopMode = 0 // HotspotOff 或 NoClients 无待释放限速: 0 唤醒停表
	v6EngineModeReleaseTimer v6EngineLoopMode = 1 // NoClients 挂一次性到期 Timer 等待解限后转休眠
	v6EngineModeActive       v6EngineLoopMode = 2 // 活跃周期巡检 (含手机熄屏有客户端 lvlBackground)
)

// isV6EngineActive 判定三大 v6 引擎是否应保持原周期巡检（手机熄屏揣兜开热点有客户端 lvlBackground 严禁停表）。
func isV6EngineActive(act Activity, simOn bool) bool {
	return !act.Known || simOn || (act.HotspotActive && (act.ClientsOnline > 0 || act.WebUIActive))
}

const (
	expressStateIdle     = "idle_fullspeed"
	expressStateActive   = "active_escort"
	expressStateCooldown = "cooldown_hold"

	expressDefaultBgCeilPct       = 85
	expressDefaultHoldAfterEndSec = 60
	expressDefaultMaxDstIPs       = 48
	expressTargetLatencyUs        = 2000     // 2ms 浅驻留 fq_codel target
	expressIntervalLatencyUs      = 40000    // 40ms fq_codel interval
	expressPrioBand               = 0        // 跨设备最高优先 prio 0
	expressClassID                = "1:8010" // 独立高优特快类 (避开 mid=16 的 1:10)
	expressFilterPrioV4           = 4
	expressFilterPrioV6           = 5
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
	ClassID         string   `json:"class_id"`
	Prio            int      `json:"prio"`
	FilterPrioV4    int      `json:"filter_prio_v4"`
	FilterPrioV6    int      `json:"filter_prio_v6"`
	Qdisc           string   `json:"qdisc"`
	TargetUs        int      `json:"target_us"`
	IntervalUs      int      `json:"interval_us"`
	BgPoolCeilPct   int      `json:"bg_pool_ceil_pct"`
	HwOffloadBypass bool     `json:"hw_offload_bypass"` // true=暂停硬件快路径让 prio 0 接管; false=恢复满速硬件加速
	EscortedMACs    []string `json:"escorted_macs"`
	UpdatedAt       int64    `json:"updated_at"`
}

type expressDataplaneJob struct {
	active          bool
	bgCeilPct       int
	bgCeilKbps      int
	upBgCeilKbps    int
	iface           string
	lastActiveIface string
	hotspotOff      bool
}

type vectorExpressEngine struct {
	// 64 位原子字段严格置于 offset 0 (兼容 32-bit ARM)
	transitions atomic.Uint64
	activeFlag  atomic.Int64 // 1 = active_escort 或 cooldown_hold, 0 = idle_fullspeed

	// 非 64 位原子字段、通道、锁与钩子严格放在全部 64 位原子字段之后
	loopMode atomic.Int32
	wakeOnce sync.Once
	wakeCh   chan struct{}

	srv             *server
	mu              sync.Mutex
	cfg             VectorExpressConfig
	state           string
	escortedMACs    []string
	escortReasons   map[string]string
	p2pExcluded     []string
	sinceAt         time.Time
	lastRealtimeAt  time.Time
	lastApplied     VectorExpressDataplaneSpec
	lastActiveIface string
	applyHook       func(spec VectorExpressDataplaneSpec) error

	// 单槽串行数据面下发协调器(杜绝并发 go runBin 乱序竞态)
	dpMu            sync.Mutex
	pendingDPJob    *expressDataplaneJob
	dpRunning       bool
	dpIdleCh        chan struct{}
	dpEnabledFn     func(hncDir string) bool
	nativeApplyFn   func(hncDir string, enable bool, gameMark uint32, bgCeilKbps int) error
	invalidateFn    func(hncDir, iface string)
	fallbackCmdFn   func(hncDir, script string, args ...string) (int, string)
	pollInterval    time.Duration
	holdDurOverride time.Duration
	activityHook    func() (<-chan struct{}, Activity)
	simActiveHook   func() bool
	signalHook      func(now time.Time) []VectorExpressDeviceSignal
}

func newVectorExpressEngine(s *server) *vectorExpressEngine {
	eng := &vectorExpressEngine{
		wakeCh:        make(chan struct{}, 1),
		srv:           s,
		cfg:           defaultVectorExpressConfig(),
		state:         expressStateIdle,
		escortedMACs:  []string{},
		escortReasons: make(map[string]string),
		p2pExcluded:   []string{},
		lastApplied: VectorExpressDataplaneSpec{
			Active:          false,
			ClassID:         expressClassID,
			Prio:            expressPrioBand,
			FilterPrioV4:    expressFilterPrioV4,
			FilterPrioV6:    expressFilterPrioV6,
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

// ReloadFromDisk 在整机配置恢复后从磁盘重新加载 Vector Express 配置。
func (e *vectorExpressEngine) ReloadFromDisk() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.cfg = defaultVectorExpressConfig()
	e.loadConfigLocked()
	e.mu.Unlock()
	if !e.isHotspotOffReadOnly() {
		e.Wake()
	}
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

	holdDur := e.effectiveHoldDuration(cfg)
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

func (e *vectorExpressEngine) effectivePollInterval() time.Duration {
	if e != nil && e.pollInterval > 0 {
		return e.pollInterval
	}
	return 2 * time.Second
}

func (e *vectorExpressEngine) effectiveHoldDuration(cfg VectorExpressConfig) time.Duration {
	if e != nil && e.holdDurOverride > 0 {
		return e.holdDurOverride
	}
	return time.Duration(cfg.HoldAfterEndSec) * time.Second
}

func (e *vectorExpressEngine) ensureWakeCh() chan struct{} {
	if e == nil {
		return nil
	}
	e.wakeOnce.Do(func() {
		if e.wakeCh == nil {
			e.wakeCh = make(chan struct{}, 1)
		}
	})
	return e.wakeCh
}

// Wake 非阻塞唤醒护航协程（配置修改或外部事件触发时即时重算）。
func (e *vectorExpressEngine) Wake() {
	ch := e.ensureWakeCh()
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

// LoopMode 返回当前护航协程的休眠/一次性释放定时器/活跃周期档位。
func (e *vectorExpressEngine) LoopMode() v6EngineLoopMode {
	if e == nil {
		return v6EngineModeSleeping
	}
	return v6EngineLoopMode(e.loopMode.Load())
}

func (e *vectorExpressEngine) sampleSignals(now time.Time) []VectorExpressDeviceSignal {
	if e != nil && e.signalHook != nil {
		return e.signalHook(now)
	}
	return e.collectLiveSignals(now)
}

func (e *vectorExpressEngine) isDataplaneEnabled(hncDir string) bool {
	if e.dpEnabledFn != nil {
		return e.dpEnabledFn(hncDir)
	}
	if e.nativeApplyFn != nil || e.fallbackCmdFn != nil {
		return true
	}
	return useNativeDataplane(hncDir)
}

func readAutorateDiskCurMbps(hncDir string) (downMbps, upMbps float64) {
	hncDir = strings.TrimSpace(hncDir)
	if hncDir == "" {
		return 0, 0
	}
	for _, rel := range []string{filepath.Join("run", "autorate.json"), filepath.Join("data", "autorate.json")} {
		b, err := os.ReadFile(filepath.Join(hncDir, rel))
		if err != nil || len(b) == 0 {
			continue
		}
		var raw struct {
			Enabled     *bool   `json:"enabled"`
			CurDownMbps float64 `json:"cur_down_mbps"`
			CurUpMbps   float64 `json:"cur_up_mbps"`
		}
		if json.Unmarshal(b, &raw) != nil {
			continue
		}
		if raw.Enabled != nil && !*raw.Enabled {
			return 0, 0
		}
		var d, u float64
		if !invalidFiniteFloat(raw.CurDownMbps) && raw.CurDownMbps > 0 {
			d = raw.CurDownMbps
		}
		if !invalidFiniteFloat(raw.CurUpMbps) && raw.CurUpMbps > 0 {
			u = raw.CurUpMbps
		}
		if d > 0 || u > 0 {
			return d, u
		}
	}
	return 0, 0
}

func readStaticShaperDiskBps(hncDir string) (downBps, upBps int64) {
	hncDir = strings.TrimSpace(hncDir)
	if hncDir == "" {
		return 0, 0
	}
	b, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json"))
	if err != nil || len(b) == 0 {
		return 0, 0
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return 0, 0
	}
	return extractStaticShaperFromRulesMap(m)
}

func resolveConfiguredUpShaperKbpsWithServer(srv *server, hncDir string, actorUpKbps int) int {
	if actorUpKbps > 0 {
		return actorUpKbps
	}
	if hncDir == "" && srv != nil {
		hncDir = srv.hncDir
	}
	_, diskUpMbps := readAutorateDiskCurMbps(hncDir)
	if srv != nil && srv.autorate != nil {
		ar := srv.autorate.Snapshot()
		if ar.Enabled && ar.CurUpMbps > 0 && (diskUpMbps <= 0 || (ar.State != "sleeping" && ar.State != "disabled")) {
			return int(math.Round(ar.CurUpMbps * 1000.0))
		}
	}
	if diskUpMbps > 0 {
		return int(math.Round(diskUpMbps * 1000.0))
	}
	var upBps int64
	if srv != nil {
		_, upBps = srv.readStaticGlobalShaperBps()
	}
	if upBps <= 0 && hncDir != "" {
		_, upBps = readStaticShaperDiskBps(hncDir)
	}
	if upBps > 0 {
		return int((upBps * 8) / 1000)
	}
	return 0
}

func computeUpBgCeilKbpsForServer(srv *server, hncDir string, pct int) int {
	if pct <= 0 || pct >= 100 {
		return 0
	}
	upRootKbps := resolveConfiguredUpShaperKbpsWithServer(srv, hncDir, 0)
	if upRootKbps <= 0 {
		return 0
	}
	upBgKbps := (upRootKbps * pct) / 100
	if upBgKbps <= 0 {
		upBgKbps = 1
	}
	return upBgKbps
}

func (e *vectorExpressEngine) computeBgCeilKbps(ceilPct int) int {
	if ceilPct <= 0 || ceilPct >= 100 {
		return 0
	}
	hncDir := ""
	if e.srv != nil {
		hncDir = e.srv.hncDir
	}
	diskDownMbps, _ := readAutorateDiskCurMbps(hncDir)
	rootKbps := 0
	if e.srv != nil && e.srv.autorate != nil {
		if ar := e.srv.autorate.Snapshot(); ar.Enabled && ar.CurDownMbps > 0 && (diskDownMbps <= 0 || (ar.State != "sleeping" && ar.State != "disabled")) {
			rootKbps = int(math.Round(ar.CurDownMbps * 1000.0))
		}
	}
	if rootKbps <= 0 && diskDownMbps > 0 {
		rootKbps = int(math.Round(diskDownMbps * 1000.0))
	}
	if rootKbps <= 0 {
		var downBps int64
		if e.srv != nil {
			downBps, _ = e.srv.readStaticGlobalShaperBps()
		}
		if downBps <= 0 && hncDir != "" {
			downBps, _ = readStaticShaperDiskBps(hncDir)
		}
		if downBps > 0 {
			rootKbps = int((downBps * 8) / 1000)
		}
	}
	if rootKbps <= 0 {
		rootKbps = dpDefaultRootRateKbp
	}
	bgKbps := (rootKbps * ceilPct) / 100
	if bgKbps <= 0 {
		bgKbps = 1
	}
	return bgKbps
}

// computeUpBgCeilKbps 独立折算 5G 非对称上行背景上限:
// 优先读取 autorate.json / Autorate 的 cur_up_mbps, 次选 rules.json 的 global_shaper_up 乘以 pct%;
// 若两者均未开启或为 0 则严格返回 0, 绝不误拿 1000mbit 默认根速率乱锁上行。
func (e *vectorExpressEngine) computeUpBgCeilKbps(pct int) int {
	if e == nil {
		return 0
	}
	hncDir := ""
	if e.srv != nil {
		hncDir = e.srv.hncDir
	}
	return computeUpBgCeilKbpsForServer(e.srv, hncDir, pct)
}

func (e *vectorExpressEngine) resolveCurrentIfaceLocked() string {
	var iface string
	if e.srv != nil && e.srv.hncDir != "" {
		iface = readHotspotIfaceName(e.srv.hncDir)
	}
	if iface == "" {
		if act := activityNow(); act.HotspotActive && isValidHotspotIfaceName(act.HotspotIface) {
			iface = act.HotspotIface
		}
	}
	if iface != "" {
		e.lastActiveIface = iface
	}
	return iface
}

// WaitDataplaneIdle 等待单槽串行数据面消费协程处理完当前队列中的任务。
func (e *vectorExpressEngine) WaitDataplaneIdle() {
	if e == nil {
		return
	}
	e.dpMu.Lock()
	idleCh := e.dpIdleCh
	e.dpMu.Unlock()
	if idleCh != nil {
		<-idleCh
	}
}

func (e *vectorExpressEngine) enqueueDataplaneJob(job expressDataplaneJob, syncWait bool) {
	cp := job
	e.dpMu.Lock()
	e.pendingDPJob = &cp
	if !e.dpRunning {
		e.dpRunning = true
		e.dpIdleCh = make(chan struct{})
		go e.drainDataplaneJobs()
	}
	idleCh := e.dpIdleCh
	e.dpMu.Unlock()
	if syncWait && idleCh != nil {
		<-idleCh
	}
}

func (e *vectorExpressEngine) drainDataplaneJobs() {
	for {
		e.dpMu.Lock()
		job := e.pendingDPJob
		if job == nil {
			e.dpRunning = false
			if e.dpIdleCh != nil {
				close(e.dpIdleCh)
				e.dpIdleCh = nil
			}
			e.dpMu.Unlock()
			return
		}
		e.pendingDPJob = nil
		e.dpMu.Unlock()

		e.executeDataplaneJob(*job)
	}
}

func (e *vectorExpressEngine) executeDataplaneJob(job expressDataplaneJob) {
	hncDir := ""
	if e.srv != nil {
		hncDir = e.srv.hncDir
	}
	if hncDir == "" && e.nativeApplyFn == nil && e.fallbackCmdFn == nil {
		return
	}
	if !e.isDataplaneEnabled(hncDir) {
		return
	}
	callNative := func(enable bool, mark uint32, downBgKbps, upBgKbps int) error {
		if e.nativeApplyFn != nil {
			return e.nativeApplyFn(hncDir, enable, mark, downBgKbps)
		}
		return ApplyVectorExpressNative(hncDir, enable, mark, downBgKbps, upBgKbps)
	}
	invalidate := InvalidateDataplaneReconcileNative
	if e.invalidateFn != nil {
		invalidate = e.invalidateFn
	}
	fallbackCmd := runBin
	if e.fallbackCmdFn != nil {
		fallbackCmd = e.fallbackCmdFn
	}

	if job.hotspotOff {
		err := callNative(false, v6ExpressDefaultMark, 0, 0)
		invalidate(hncDir, "")
		if err != nil {
			targetIface := job.iface
			if targetIface == "" {
				targetIface = job.lastActiveIface
			}
			if isValidHotspotIfaceName(targetIface) {
				_, _ = fallbackCmd(hncDir, "tc_manager.sh", "vector_express", targetIface, "off", "100")
			}
		}
		return
	}

	mode := "off"
	bgPct := 100
	bgKbps := 0
	upBgKbps := 0
	if job.active {
		mode = "on"
		bgPct = job.bgCeilPct
		bgKbps = job.bgCeilKbps
		upBgKbps = job.upBgCeilKbps
	}
	if err := callNative(job.active, v6ExpressDefaultMark, bgKbps, upBgKbps); err != nil {
		targetIface := job.iface
		if !job.active && targetIface == "" {
			targetIface = job.lastActiveIface
		}
		if isValidHotspotIfaceName(targetIface) {
			_, _ = fallbackCmd(hncDir, "tc_manager.sh", "vector_express", targetIface, mode, strconv.Itoa(bgPct))
		}
	}
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
		ClassID:         expressClassID,
		Prio:            expressPrioBand,
		FilterPrioV4:    expressFilterPrioV4,
		FilterPrioV6:    expressFilterPrioV6,
		Qdisc:           "fq_codel",
		TargetUs:        expressTargetLatencyUs,
		IntervalUs:      expressIntervalLatencyUs,
		BgPoolCeilPct:   ceilPct,
		HwOffloadBypass: active,
		EscortedMACs:    cpMACs,
		UpdatedAt:       now.Unix(),
	}
	e.lastApplied = spec
	iface := e.resolveCurrentIfaceLocked()
	lastIface := e.lastActiveIface
	bgKbps := 0
	upBgKbps := 0
	if active {
		bgKbps = e.computeBgCeilKbps(ceilPct)
		upBgKbps = e.computeUpBgCeilKbps(ceilPct)
	}

	if e.srv != nil && e.srv.hncDir != "" {
		if b, err := json.MarshalIndent(spec, "", "  "); err == nil {
			_ = discoverWriteAtomic(e.stateRunPath(), b)
		}
	}
	e.enqueueDataplaneJob(expressDataplaneJob{
		active:          active,
		bgCeilPct:       ceilPct,
		bgCeilKbps:      bgKbps,
		upBgCeilKbps:    upBgKbps,
		iface:           iface,
		lastActiveIface: lastIface,
		hotspotOff:      false,
	}, false)

	if e.applyHook != nil {
		_ = e.applyHook(spec)
	}
}

// resetForHotspotOff 在热点关闭时即刻清空动态护航态、复位满速并通过单槽串行通道解限清缓存。
func (e *vectorExpressEngine) resetForHotspotOff(now time.Time) {
	if now.IsZero() {
		now = time.Now()
	}
	e.mu.Lock()
	prevState := e.state
	prevActive := e.lastApplied.Active || e.activeFlag.Load() != 0 || e.lastApplied.BgPoolCeilPct != 100

	e.state = expressStateIdle
	e.escortedMACs = []string{}
	e.escortReasons = make(map[string]string)
	e.p2pExcluded = []string{}
	e.sinceAt = time.Time{}
	e.lastRealtimeAt = time.Time{}
	e.activeFlag.Store(0)

	spec := VectorExpressDataplaneSpec{
		Active:          false,
		ClassID:         expressClassID,
		Prio:            expressPrioBand,
		FilterPrioV4:    expressFilterPrioV4,
		FilterPrioV6:    expressFilterPrioV6,
		Qdisc:           "fq_codel",
		TargetUs:        expressTargetLatencyUs,
		IntervalUs:      expressIntervalLatencyUs,
		BgPoolCeilPct:   100,
		HwOffloadBypass: false,
		EscortedMACs:    []string{},
		UpdatedAt:       now.Unix(),
	}
	e.lastApplied = spec
	if prevState != expressStateIdle || prevActive {
		e.transitions.Add(1)
	}
	var iface string
	if e.srv != nil && e.srv.hncDir != "" {
		iface = readHotspotIfaceName(e.srv.hncDir)
	}
	lastIface := e.lastActiveIface
	hook := e.applyHook
	e.mu.Unlock()

	if (prevState != expressStateIdle || prevActive) && e.srv != nil && e.srv.hncDir != "" {
		if b, err := json.MarshalIndent(spec, "", "  "); err == nil {
			_ = discoverWriteAtomic(e.stateRunPath(), b)
		}
	}

	e.enqueueDataplaneJob(expressDataplaneJob{
		active:          false,
		bgCeilPct:       100,
		bgCeilKbps:      0,
		upBgCeilKbps:    0,
		iface:           iface,
		lastActiveIface: lastIface,
		hotspotOff:      true,
	}, true)

	if (prevState != expressStateIdle || prevActive) && hook != nil {
		_ = hook(spec)
	}
}

func (e *vectorExpressEngine) needsHotspotOffCleanup() bool {
	if e.activeFlag.Load() != 0 {
		return true
	}
	e.mu.Lock()
	dirty := e.state != expressStateIdle || e.lastApplied.Active || e.lastApplied.BgPoolCeilPct != 100 || len(e.escortedMACs) > 0
	e.mu.Unlock()
	return dirty
}

func (e *vectorExpressEngine) isHotspotOffReadOnly() bool {
	if e == nil {
		return false
	}
	_, act, sim := e.readActivity()
	return act.Known && !act.HotspotActive && !sim
}

// ReadOnlySnapshot 在 HotspotOff 期间返回零副作用的纯配置只读视图,
// 严禁推进 activeFlag / state, 严禁覆写 run/vector_express_state.json 或投递数据面启用任务。
func (e *vectorExpressEngine) ReadOnlySnapshot(now time.Time) map[string]any {
	if now.IsZero() {
		now = time.Now()
	}
	e.mu.Lock()
	cfg := e.cfg
	e.mu.Unlock()

	spec := VectorExpressDataplaneSpec{
		Active:          false,
		ClassID:         expressClassID,
		Prio:            expressPrioBand,
		FilterPrioV4:    expressFilterPrioV4,
		FilterPrioV6:    expressFilterPrioV6,
		Qdisc:           "fq_codel",
		TargetUs:        expressTargetLatencyUs,
		IntervalUs:      expressIntervalLatencyUs,
		BgPoolCeilPct:   100,
		HwOffloadBypass: false,
		EscortedMACs:    []string{},
		UpdatedAt:       now.Unix(),
	}
	return map[string]any{
		"ok":                        true,
		"state":                     expressStateIdle,
		"active":                    false,
		"enabled":                   cfg.Enabled,
		"auto_detect":               cfg.AutoDetect,
		"forced_macs":               append([]string(nil), cfg.ForcedMACs...),
		"escorted_macs":             []string{},
		"escort_reasons":            map[string]string{},
		"p2p_excluded_macs":         []string{},
		"bg_ceil_pct":               100,
		"configured_bg_ceil_pct":    cfg.BgCeilPct,
		"hold_after_end_sec":        cfg.HoldAfterEndSec,
		"cooldown_remaining_sec":    0,
		"since":                     int64(0),
		"unknown_devices_fullspeed": true,
		"dataplane":                 spec,
		"transitions":               e.transitions.Load(),
		"config":                    cfg,
	}
}

func (e *vectorExpressEngine) buildSnapshotLocked(now time.Time) map[string]any {
	cooldownRem := 0
	if e.state == expressStateCooldown && !e.lastRealtimeAt.IsZero() {
		rem := e.effectiveHoldDuration(e.cfg) - now.Sub(e.lastRealtimeAt)
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

func (e *vectorExpressEngine) readActivity() (<-chan struct{}, Activity, bool) {
	if e.activityHook != nil {
		ch, act := e.activityHook()
		sim := false
		if e.simActiveHook != nil {
			sim = e.simActiveHook()
		} else if e.srv != nil && e.srv.hncDir != "" {
			sim = e.srv.simActive()
		}
		return ch, act, sim
	}
	ch := activityChanged()
	act := activityNow()
	sim := false
	if e.simActiveHook != nil {
		sim = e.simActiveHook()
	} else if e.srv != nil && e.srv.hncDir != "" {
		sim = e.srv.simActive()
	}
	return ch, act, sim
}

func (e *vectorExpressEngine) evalNoClientsRelease(now time.Time, syncedOnce *bool) (time.Duration, bool) {
	if syncedOnce != nil && !*syncedOnce {
		*syncedOnce = true
		// 静态同步一次(处理 ForcedMACs 或将先前活跃态推进为 cooldown_hold / idle_fullspeed), 随后若无冷却直接停表不死循环!
		e.Step(now, nil)
	}
	e.mu.Lock()
	st := e.state
	lastRT := e.lastRealtimeAt
	holdDur := e.effectiveHoldDuration(e.cfg)
	e.mu.Unlock()

	if st != expressStateCooldown || lastRT.IsZero() {
		return 0, false
	}
	rem := holdDur - now.Sub(lastRT)
	if rem <= 0 {
		e.Step(now.Add(time.Millisecond), nil)
		return 0, false
	}
	return rem + 15*time.Millisecond, true
}

func (e *vectorExpressEngine) runLoop(stop <-chan struct{}) {
	if e == nil {
		<-stop
		return
	}
	wakeCh := e.ensureWakeCh()

	var (
		tk              *time.Ticker
		tkCh            <-chan time.Time
		relTimer        *time.Timer
		relTimerCh      <-chan time.Time
		wasActive       bool
		resetDone       bool
		noClientsSynced bool
	)
	stopTicker := func() {
		if tk != nil {
			tk.Stop()
			tk = nil
			tkCh = nil
		}
	}
	ensureTicker := func(d time.Duration) {
		if tk == nil {
			tk = time.NewTicker(d)
			tkCh = tk.C
		}
	}
	stopRelTimer := func() {
		if relTimer != nil {
			if !relTimer.Stop() {
				select {
				case <-relTimer.C:
				default:
				}
			}
			relTimer = nil
			relTimerCh = nil
		}
	}
	armRelTimer := func(d time.Duration) {
		stopRelTimer()
		if d <= 0 {
			d = time.Millisecond
		}
		relTimer = time.NewTimer(d)
		relTimerCh = relTimer.C
	}
	defer func() {
		stopTicker()
		stopRelTimer()
		e.loopMode.Store(int32(v6EngineModeSleeping))
	}()

	patrolOnce := func(now time.Time) {
		e.Step(now, e.sampleSignals(now))
	}

	for {
		actCh, act, simOn := e.readActivity()
		now := time.Now()

		if isV6EngineActive(act, simOn) {
			resetDone = false
			noClientsSynced = false
			stopRelTimer()
			if !wasActive {
				patrolOnce(now)
				wasActive = true
			}
			ensureTicker(e.effectivePollInterval())
			e.loopMode.Store(int32(v6EngineModeActive))
		} else if !act.HotspotActive {
			wasActive = false
			noClientsSynced = false
			stopTicker()
			stopRelTimer()
			if !resetDone || e.activeFlag.Load() != 0 || e.needsHotspotOffCleanup() {
				e.resetForHotspotOff(now)
				resetDone = true
			}
			e.loopMode.Store(int32(v6EngineModeSleeping))
		} else {
			wasActive = false
			resetDone = false
			stopTicker()
			if rem, pending := e.evalNoClientsRelease(now, &noClientsSynced); pending {
				armRelTimer(rem)
				e.loopMode.Store(int32(v6EngineModeReleaseTimer))
			} else {
				stopRelTimer()
				e.loopMode.Store(int32(v6EngineModeSleeping))
			}
		}

		select {
		case <-stop:
			return
		case <-actCh:
		case <-wakeCh:
			noClientsSynced = false
			if wasActive {
				patrolOnce(time.Now())
			}
		case tickNow := <-tkCh:
			patrolOnce(tickNow)
		case timerNow := <-relTimerCh:
			relTimer = nil
			relTimerCh = nil
			e.Step(timerNow, nil)
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
	isOffReadOnly := func() bool {
		if eng.isHotspotOffReadOnly() {
			return true
		}
		if act := activityNow(); act.Known && !act.HotspotActive && (s == nil || !s.simActive()) {
			return true
		}
		return false
	}
	if r.Method == http.MethodGet {
		now := time.Now()
		if isOffReadOnly() {
			writeJSON(w, http.StatusOK, eng.ReadOnlySnapshot(now))
			return
		}
		snap := eng.Step(now, eng.sampleSignals(now))
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
		if isOffReadOnly() {
			writeJSON(w, http.StatusOK, eng.ReadOnlySnapshot(now))
			return
		}
		snap := eng.Step(now, eng.sampleSignals(now))
		eng.Wake()
		writeJSON(w, http.StatusOK, snap)
	})(w, r)
}
