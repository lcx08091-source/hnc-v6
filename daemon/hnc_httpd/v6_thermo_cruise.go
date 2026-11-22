// v6_thermo_cruise.go — HNC v6.0.0 · Vector (T4 模块 5):
// ThermoCruise sysfs 零开销温控与电量自适应巡航引擎。
//
// 核心机制:
//   1. 零子进程微秒级读取 (<50µs): 直接使用 os.ReadFile 读取 /sys/class/power_supply/* 下的
//      type / temp / capacity / status, 自动探测并缓存真实 Battery 节点, 零 fork、零 dumpsys。
//   2. 3.0°C 施密特回差防抖 + 60s 持续冷却确认:
//      - 升温立即响应: >= stage1_temp_c (默认 42.0°C) 进一阶; >= stage2_temp_c (默认 45.0°C) 进二阶;
//      - 降温严格回差: 二阶须持续 <= stage2_temp_c - 3.0°C (42.0°C) 满 60s 才退回一阶;
//        一阶须持续 <= stage1_temp_c - 3.0°C (39.0°C) 满 60s 才恢复常态 Stage 0, 彻底根治临界乒乓抖动!
//   3. 快充与游戏护航智能豁免:
//      当电池处于 Charging 状态或 Vector Express 游戏/会议护航激活时, 自动豁免二阶热点限速降频,
//      仅执行一阶 HNC 内部轮询闭息省电!

package main

import (
	"encoding/json"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	thermoDefaultSysfsRoot   = "/sys/class/power_supply"
	thermoDefaultStage1TempC = 42.0
	thermoDefaultStage2TempC = 45.0
	thermoDefaultLowBatPct   = 20
	thermoHysteresisC        = 3.0
	thermoCoolHoldDuration   = 60 * time.Second
)

// ThermoCruiseConfig 温控与低电巡航直接数字阈值配置。
type ThermoCruiseConfig struct {
	Enabled             bool    `json:"enabled"`
	Stage2ShaperEnabled bool    `json:"stage2_shaper_enabled"`
	Stage1TempC         float64 `json:"stage1_temp_c"`
	Stage2TempC         float64 `json:"stage2_temp_c"`
	LowBatPct           int     `json:"low_bat_pct"`
}

func defaultThermoCruiseConfig() ThermoCruiseConfig {
	return ThermoCruiseConfig{
		Enabled:             true,
		Stage2ShaperEnabled: true,
		Stage1TempC:         thermoDefaultStage1TempC,
		Stage2TempC:         thermoDefaultStage2TempC,
		LowBatPct:           thermoDefaultLowBatPct,
	}
}

// ThermoBatteryReading 单次 sysfs 传感器零开销读数。
type ThermoBatteryReading struct {
	Available   bool    `json:"available"`
	SupplyNode  string  `json:"supply_node,omitempty"`
	TempC       float64 `json:"temp_c"`
	CapacityPct int     `json:"capacity_pct"`
	Status      string  `json:"status"`
	IsCharging  bool    `json:"is_charging"`
	ReadLatency int64   `json:"read_latency_ns"`
}

// ThermoQuickState 纯内存零 sysfs IO 温控快速快照（供黑匣子 200ms 归因与信号诊断无阻塞读取）。
type ThermoQuickState struct {
	Enabled            bool    `json:"enabled"`
	Available          bool    `json:"available"`
	RawThermalStage    int     `json:"raw_thermal_stage"`
	EffectiveStage     int     `json:"effective_stage"`
	Stage2ShaperActive bool    `json:"stage2_shaper_active"`
	Stage2Exempt       bool    `json:"stage2_exempt"`
	TempC              float64 `json:"temp_c"`
	CapacityPct        int     `json:"capacity_pct"`
	IsCharging         bool    `json:"is_charging"`
}

type thermoCruiseEngine struct {
	// 64 位原子字段严格置于 offset 0 (兼容 32-bit ARM)
	evalCount      atomic.Uint64
	effectiveStage atomic.Int64

	// 非 64 位原子字段与通道/钩子严格排在全部 64 位原子字段之后
	loopMode atomic.Int32
	wakeOnce sync.Once
	wakeCh   chan struct{}

	srv                  *server
	mu                   sync.Mutex
	cfg                  ThermoCruiseConfig
	sysfsRoot            string
	cachedBatDir         string
	rawThermalStage      int       // 0 | 1 | 2（纯温度施密特状态机输出）
	coolBelowStage2Since time.Time // 持续 <= stage2_temp_c - 3.0°C 的起始时刻
	coolBelowStage1Since time.Time // 持续 <= stage1_temp_c - 3.0°C 的起始时刻
	lastStage2Shaper     bool
	lastStage2Exempt     bool
	lastReading          ThermoBatteryReading
	lastSnap             map[string]any
	lastPersistedKey     string

	pollInterval    time.Duration
	coolHoldDur     time.Duration
	activityHook    func() (<-chan struct{}, Activity)
	simActiveHook   func() bool
	batteryReadHook func() ThermoBatteryReading
}

func newThermoCruiseEngine(s *server) *thermoCruiseEngine {
	eng := &thermoCruiseEngine{
		wakeCh:    make(chan struct{}, 1),
		srv:       s,
		cfg:       defaultThermoCruiseConfig(),
		sysfsRoot: thermoDefaultSysfsRoot,
	}
	eng.loadConfigLocked()
	return eng
}

func (e *thermoCruiseEngine) configPath() string {
	return filepath.Join(e.srv.hncDir, "data", "thermo_cruise.json")
}

func (e *thermoCruiseEngine) stateRunPath() string {
	return filepath.Join(e.srv.hncDir, "run", "thermo_state.json")
}

func (e *thermoCruiseEngine) effectivePollInterval() time.Duration {
	if e != nil && e.pollInterval > 0 {
		return e.pollInterval
	}
	return 10 * time.Second
}

func (e *thermoCruiseEngine) effectiveCoolHoldDuration() time.Duration {
	if e != nil && e.coolHoldDur > 0 {
		return e.coolHoldDur
	}
	return thermoCoolHoldDuration
}

func (e *thermoCruiseEngine) ensureWakeCh() chan struct{} {
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

// Wake 非阻塞唤醒温控巡航协程（配置修改或外部事件触发时即时重算）。
func (e *thermoCruiseEngine) Wake() {
	ch := e.ensureWakeCh()
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

// LoopMode 返回当前温控巡航协程的休眠/定时器/活跃档位。
func (e *thermoCruiseEngine) LoopMode() v6EngineLoopMode {
	if e == nil {
		return v6EngineModeSleeping
	}
	return v6EngineLoopMode(e.loopMode.Load())
}

func (e *thermoCruiseEngine) loadConfigLocked() {
	if e.srv == nil || e.srv.hncDir == "" {
		return
	}
	b, err := os.ReadFile(e.configPath())
	if err != nil {
		return
	}
	var c ThermoCruiseConfig
	if json.Unmarshal(b, &c) != nil {
		return
	}
	if validThermoConfig(c) == "" {
		e.cfg = c
	}
}

// ReloadFromDisk 在整机备份恢复后从磁盘重新加载 ThermoCruise 配置。
func (e *thermoCruiseEngine) ReloadFromDisk() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.cfg = defaultThermoCruiseConfig()
	e.loadConfigLocked()
	e.mu.Unlock()
	if !e.isHotspotOffReadOnly() {
		e.Wake()
	}
}

func validThermoConfig(c ThermoCruiseConfig) string {
	if math.IsNaN(c.Stage1TempC) || math.IsInf(c.Stage1TempC, 0) || c.Stage1TempC < 30.0 || c.Stage1TempC > 70.0 {
		return "stage1_temp_c must be 30.0..70.0"
	}
	if math.IsNaN(c.Stage2TempC) || math.IsInf(c.Stage2TempC, 0) || c.Stage2TempC < 32.0 || c.Stage2TempC > 75.0 {
		return "stage2_temp_c must be 32.0..75.0"
	}
	if c.Stage2TempC < c.Stage1TempC {
		return "stage2_temp_c must be >= stage1_temp_c"
	}
	if c.LowBatPct < 1 || c.LowBatPct > 80 {
		return "low_bat_pct must be 1..80"
	}
	return ""
}

func (e *thermoCruiseEngine) saveConfigLocked() error {
	if e.srv == nil || e.srv.hncDir == "" {
		return nil
	}
	b, err := json.MarshalIndent(e.cfg, "", "  ")
	if err != nil {
		return err
	}
	return discoverWriteAtomic(e.configPath(), b)
}

// ── 零子进程 sysfs 电池温度/电量/充电态读取 (<50µs) ──────────────────────────

// parseSysfsTempCelsius 按 sysfs 路径语义固定缩放温度:
//   - thermal_zone*/temp: 恒按毫摄氏度 /1000.0;
//   - power_supply/*/temp (默认电池节点): 恒按 0.1°C /10.0, 彻底避免冬季 8.5°C(85) 被误判为 85°C!
func parseSysfsTempCelsius(path, raw string) (float64, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	slash := strings.ToLower(filepath.ToSlash(path))
	scale := 10.0
	if strings.Contains(slash, "thermal_zone") {
		scale = 1000.0
	}
	return math.Round((v/scale)*10) / 10, true
}

func readSmallSysfsFile(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func discoverBatteryNodeDir(root string) string {
	if root == "" {
		return ""
	}
	// 优先探测标准聚合节点 <root>/battery (避免 OPLUS 等机型 bms 次级节点屏蔽真实充电状态)
	primary := filepath.Join(root, "battery")
	if _, hasTemp := readSmallSysfsFile(filepath.Join(primary, "temp")); hasTemp {
		typ, hasType := readSmallSysfsFile(filepath.Join(primary, "type"))
		if !hasType || strings.EqualFold(typ, "Battery") {
			return primary
		}
	}
	// 再遍历全部 power_supply 子目录核验 type == Battery
	ents, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	var fallbackTempDir string
	for _, ent := range ents {
		if ent.Name() == "battery" {
			continue
		}
		cand := filepath.Join(root, ent.Name())
		typ, ok := readSmallSysfsFile(filepath.Join(cand, "type"))
		if ok && strings.EqualFold(typ, "Battery") {
			if _, hasTemp := readSmallSysfsFile(filepath.Join(cand, "temp")); hasTemp {
				return cand
			}
			if fallbackTempDir == "" {
				fallbackTempDir = cand
			}
		}
	}
	if fallbackTempDir != "" {
		return fallbackTempDir
	}
	for _, name := range []string{"battery", "Battery", "BAT0", "bms"} {
		cand := filepath.Join(root, name)
		if _, ok := readSmallSysfsFile(filepath.Join(cand, "temp")); ok {
			return cand
		}
	}
	return ""
}

// ReadBatteryFromSysfs 直接通过 os.ReadFile 读取缓存的 Battery 节点（典型耗时 10~35µs）。
func (e *thermoCruiseEngine) ReadBatteryFromSysfs() ThermoBatteryReading {
	t0 := time.Now()

	e.mu.Lock()
	root := e.sysfsRoot
	batDir := e.cachedBatDir
	e.mu.Unlock()

	if batDir == "" {
		batDir = discoverBatteryNodeDir(root)
		if batDir != "" {
			e.mu.Lock()
			if e.sysfsRoot == root {
				e.cachedBatDir = batDir
			}
			e.mu.Unlock()
		}
	}
	if batDir == "" {
		return ThermoBatteryReading{Available: false, ReadLatency: time.Since(t0).Nanoseconds()}
	}

	tempPath := filepath.Join(batDir, "temp")
	tempStr, okTemp := readSmallSysfsFile(tempPath)
	if !okTemp {
		// 节点变化时清缓存重探一次
		batDir = discoverBatteryNodeDir(root)
		e.mu.Lock()
		e.cachedBatDir = batDir
		e.mu.Unlock()
		if batDir == "" {
			return ThermoBatteryReading{Available: false, ReadLatency: time.Since(t0).Nanoseconds()}
		}
		tempPath = filepath.Join(batDir, "temp")
		tempStr, okTemp = readSmallSysfsFile(tempPath)
	}
	tempC, validTemp := parseSysfsTempCelsius(tempPath, tempStr)
	if !okTemp || !validTemp {
		return ThermoBatteryReading{Available: false, SupplyNode: filepath.Base(batDir), ReadLatency: time.Since(t0).Nanoseconds()}
	}

	capPct := -1
	if capStr, ok := readSmallSysfsFile(filepath.Join(batDir, "capacity")); ok {
		if n, err := strconv.Atoi(capStr); err == nil && n >= 0 && n <= 100 {
			capPct = n
		}
	}
	statusStr, _ := readSmallSysfsFile(filepath.Join(batDir, "status"))
	if statusStr == "" {
		statusStr = "Unknown"
	}
	charging := strings.EqualFold(statusStr, "Charging") || strings.EqualFold(statusStr, "Full")

	return ThermoBatteryReading{
		Available:   true,
		SupplyNode:  filepath.Base(batDir),
		TempC:       tempC,
		CapacityPct: capPct,
		Status:      statusStr,
		IsCharging:  charging,
		ReadLatency: time.Since(t0).Nanoseconds(),
	}
}

func (e *thermoCruiseEngine) sampleBattery() ThermoBatteryReading {
	if e != nil && e.batteryReadHook != nil {
		return e.batteryReadHook()
	}
	return e.ReadBatteryFromSysfs()
}

// PeekQuickState 纯内存零 sysfs IO 读取最新缓存的温控状态（供 200ms 黑匣子归因与信号诊断高频调用）。
func (e *thermoCruiseEngine) PeekQuickState() ThermoQuickState {
	if e == nil {
		return ThermoQuickState{}
	}
	eff := int(e.effectiveStage.Load())
	e.mu.Lock()
	cfg := e.cfg
	raw := e.rawThermalStage
	rd := e.lastReading
	s2Active := e.lastStage2Shaper
	s2Exempt := e.lastStage2Exempt
	e.mu.Unlock()

	return ThermoQuickState{
		Enabled:            cfg.Enabled,
		Available:          rd.Available,
		RawThermalStage:    raw,
		EffectiveStage:     eff,
		Stage2ShaperActive: s2Active,
		Stage2Exempt:       s2Exempt,
		TempC:              rd.TempC,
		CapacityPct:        rd.CapacityPct,
		IsCharging:         rd.IsCharging || strings.EqualFold(rd.Status, "Charging") || strings.EqualFold(rd.Status, "Full"),
	}
}

func (s *server) peekThermoQuickState() ThermoQuickState {
	if s == nil {
		return ThermoQuickState{}
	}
	if v, ok := v6Registry.Load(s); ok {
		return v.(*v6ServerState).thermo.PeekQuickState()
	}
	if s.hncDir == "" {
		return ThermoQuickState{}
	}
	return s.v6State().thermo.PeekQuickState()
}

// ── 3.0°C 施密特回差 + 60s 持续冷却 + 快充/游戏护航豁免推演核心 ───────────────

// Evaluate 给定当前时刻、电池读数与 Vector Express 激活标志, 推进温控巡航状态机。
func (e *thermoCruiseEngine) Evaluate(now time.Time, rd ThermoBatteryReading, expressActive bool) map[string]any {
	e.evalCount.Add(1)
	holdDur := e.effectiveCoolHoldDuration()

	e.mu.Lock()
	cfg := e.cfg
	e.lastReading = rd

	exitStage2Temp := cfg.Stage2TempC - thermoHysteresisC // 默认 45.0 - 3.0 = 42.0°C
	exitStage1Temp := cfg.Stage1TempC - thermoHysteresisC // 默认 42.0 - 3.0 = 39.0°C

	if !cfg.Enabled || !rd.Available {
		e.rawThermalStage = 0
		e.coolBelowStage1Since = time.Time{}
		e.coolBelowStage2Since = time.Time{}
	} else {
		t := rd.TempC
		// 1) 升温方向: 越过阈值立即升档并重置对应冷却计时器
		if t >= cfg.Stage2TempC {
			e.rawThermalStage = 2
			e.coolBelowStage2Since = time.Time{}
			e.coolBelowStage1Since = time.Time{}
		} else if t >= cfg.Stage1TempC && e.rawThermalStage < 1 {
			e.rawThermalStage = 1
			e.coolBelowStage1Since = time.Time{}
		}

		// 2) 降温方向: 必须低于 (阈值 - 3.0°C) 且连续保持满 60 秒才退档!
		if e.rawThermalStage == 2 {
			if t <= exitStage2Temp {
				if e.coolBelowStage2Since.IsZero() {
					e.coolBelowStage2Since = now
				}
				// 若同时已低于一阶退出线 (<= 39.0°C), 同步累计一阶冷却计时
				if t <= exitStage1Temp {
					if e.coolBelowStage1Since.IsZero() {
						e.coolBelowStage1Since = now
					}
				} else {
					e.coolBelowStage1Since = time.Time{}
				}
				if now.Sub(e.coolBelowStage2Since) >= holdDur {
					if !e.coolBelowStage1Since.IsZero() && now.Sub(e.coolBelowStage1Since) >= holdDur {
						e.rawThermalStage = 0
						e.coolBelowStage1Since = time.Time{}
					} else {
						e.rawThermalStage = 1
					}
					e.coolBelowStage2Since = time.Time{}
				}
			} else {
				// 温度回弹至回差死区 (42.0°C, 45.0°C), 清零冷却计时防抖
				e.coolBelowStage2Since = time.Time{}
				e.coolBelowStage1Since = time.Time{}
			}
		} else if e.rawThermalStage == 1 {
			if t <= exitStage1Temp {
				if e.coolBelowStage1Since.IsZero() {
					e.coolBelowStage1Since = now
				}
				if now.Sub(e.coolBelowStage1Since) >= holdDur {
					e.rawThermalStage = 0
					e.coolBelowStage1Since = time.Time{}
				}
			} else {
				// 温度处于回差死区 (39.0°C, 42.0°C), 保持一阶不退出
				e.coolBelowStage1Since = time.Time{}
			}
		}
	}

	pluggedIn := rd.IsCharging || strings.EqualFold(rd.Status, "Charging") || strings.EqualFold(rd.Status, "Full")
	lowBatActive := cfg.Enabled && rd.Available && rd.CapacityPct >= 0 &&
		rd.CapacityPct <= cfg.LowBatPct && !pluggedIn

	rawStage := e.rawThermalStage
	effStage := 0
	stage1PollingRelax := false
	stage2ShaperActive := false
	stage2Exempt := false
	var exemptReasons []string

	if cfg.Enabled && rd.Available {
		if rawStage >= 1 || lowBatActive {
			stage1PollingRelax = true
			effStage = 1
		}
		if rawStage == 2 {
			if pluggedIn {
				exemptReasons = append(exemptReasons, "charging")
			}
			if expressActive {
				exemptReasons = append(exemptReasons, "vector_express")
			}
			if len(exemptReasons) > 0 {
				// 快充/满电插电或 Vector Express 游戏护航激活: 自动豁免二阶限速, 仅保留一阶内部轮询省电!
				stage2Exempt = true
				stage2ShaperActive = false
				effStage = 1
			} else if cfg.Stage2ShaperEnabled {
				stage2ShaperActive = true
				effStage = 2
			} else {
				effStage = 1
			}
		}
	}
	e.lastStage2Shaper = stage2ShaperActive
	e.lastStage2Exempt = stage2Exempt
	e.effectiveStage.Store(int64(effStage))

	coolHoldRemSec := 0
	if rawStage == 2 && !e.coolBelowStage2Since.IsZero() {
		rem := holdDur - now.Sub(e.coolBelowStage2Since)
		if rem > 0 {
			coolHoldRemSec = int((rem + time.Second - 1) / time.Second)
		}
	} else if rawStage == 1 && !e.coolBelowStage1Since.IsZero() {
		rem := holdDur - now.Sub(e.coolBelowStage1Since)
		if rem > 0 {
			coolHoldRemSec = int((rem + time.Second - 1) / time.Second)
		}
	}

	exemptReasonStr := strings.Join(exemptReasons, "+")
	snap := map[string]any{
		"ok":                      true,
		"enabled":                 cfg.Enabled,
		"stage2_shaper_enabled":   cfg.Stage2ShaperEnabled,
		"stage1_temp_c":           cfg.Stage1TempC,
		"stage2_temp_c":           cfg.Stage2TempC,
		"stage1_exit_temp_c":      math.Round(exitStage1Temp*10) / 10,
		"stage2_exit_temp_c":      math.Round(exitStage2Temp*10) / 10,
		"hysteresis_c":            thermoHysteresisC,
		"low_bat_pct":             cfg.LowBatPct,
		"raw_thermal_stage":       rawStage,
		"effective_stage":         effStage,
		"stage1_polling_relaxed":  stage1PollingRelax,
		"stage2_shaper_active":    stage2ShaperActive,
		"stage2_exempt":           stage2Exempt,
		"exempt_reason":           exemptReasonStr,
		"low_battery_cruise":      lowBatActive,
		"vector_express_active":   expressActive,
		"cool_hold_remaining_sec": coolHoldRemSec,
		"battery":                 rd,
		"config":                  cfg,
		"updated_at":              now.Unix(),
	}
	e.lastSnap = snap

	// 状态脏检查(忽略 updated_at 与 read_latency_ns): 状态无实质变化时不重复刷盘 run/thermo_state.json
	stateKey := buildThermoPersistKey(cfg, rawStage, effStage, stage1PollingRelax, stage2ShaperActive, stage2Exempt, exemptReasonStr, lowBatActive, expressActive, coolHoldRemSec, rd, pluggedIn)
	needPersist := stateKey == "" || stateKey != e.lastPersistedKey
	e.mu.Unlock()

	if needPersist && e.srv != nil && e.srv.hncDir != "" {
		if b, err := json.MarshalIndent(snap, "", "  "); err == nil {
			if discoverWriteAtomic(e.stateRunPath(), b) == nil && stateKey != "" {
				e.mu.Lock()
				e.lastPersistedKey = stateKey
				e.mu.Unlock()
			}
		}
	}
	return snap
}

func buildThermoPersistKey(
	cfg ThermoCruiseConfig,
	rawStage, effStage int,
	s1Relax, s2Active, s2Exempt bool,
	exemptReason string,
	lowBat, express bool,
	coolRem int,
	rd ThermoBatteryReading,
	plugged bool,
) string {
	db, err := json.Marshal(struct {
		Cfg          ThermoCruiseConfig `json:"cfg"`
		RawStage     int                `json:"raw"`
		EffStage     int                `json:"eff"`
		S1Relax      bool               `json:"s1"`
		S2Active     bool               `json:"s2"`
		S2Exempt     bool               `json:"ex"`
		ExemptReason string             `json:"exr"`
		LowBat       bool               `json:"lb"`
		Express      bool               `json:"exp"`
		CoolRem      int                `json:"cr"`
		Avail        bool               `json:"av"`
		Node         string             `json:"nd"`
		TempC        float64            `json:"tc"`
		CapPct       int                `json:"cp"`
		Status       string             `json:"st"`
		Plugged      bool               `json:"pl"`
	}{
		Cfg: cfg, RawStage: rawStage, EffStage: effStage, S1Relax: s1Relax,
		S2Active: s2Active, S2Exempt: s2Exempt, ExemptReason: exemptReason,
		LowBat: lowBat, Express: express, CoolRem: coolRem,
		Avail: rd.Available, Node: rd.SupplyNode, TempC: rd.TempC, CapPct: rd.CapacityPct,
		Status: rd.Status, Plugged: plugged,
	})
	if err != nil {
		return ""
	}
	return string(db)
}

// resetForHotspotOff 在热点关闭时即刻复位温控阶数与冷却计时, 并归零落盘 thermo_state.json。
func (e *thermoCruiseEngine) resetForHotspotOff(now time.Time) {
	if now.IsZero() {
		now = time.Now()
	}
	e.mu.Lock()
	cfg := e.cfg
	rd := e.lastReading
	e.rawThermalStage = 0
	e.coolBelowStage1Since = time.Time{}
	e.coolBelowStage2Since = time.Time{}
	e.lastStage2Shaper = false
	e.lastStage2Exempt = false
	e.effectiveStage.Store(0)

	exitStage2Temp := cfg.Stage2TempC - thermoHysteresisC
	exitStage1Temp := cfg.Stage1TempC - thermoHysteresisC
	pluggedIn := rd.IsCharging || strings.EqualFold(rd.Status, "Charging") || strings.EqualFold(rd.Status, "Full")

	snap := map[string]any{
		"ok":                      true,
		"enabled":                 cfg.Enabled,
		"stage2_shaper_enabled":   cfg.Stage2ShaperEnabled,
		"stage1_temp_c":           cfg.Stage1TempC,
		"stage2_temp_c":           cfg.Stage2TempC,
		"stage1_exit_temp_c":      math.Round(exitStage1Temp*10) / 10,
		"stage2_exit_temp_c":      math.Round(exitStage2Temp*10) / 10,
		"hysteresis_c":            thermoHysteresisC,
		"low_bat_pct":             cfg.LowBatPct,
		"raw_thermal_stage":       0,
		"effective_stage":         0,
		"stage1_polling_relaxed":  false,
		"stage2_shaper_active":    false,
		"stage2_exempt":           false,
		"exempt_reason":           "",
		"low_battery_cruise":      false,
		"vector_express_active":   false,
		"cool_hold_remaining_sec": 0,
		"battery":                 rd,
		"config":                  cfg,
		"updated_at":              now.Unix(),
	}
	e.lastSnap = snap
	stateKey := buildThermoPersistKey(cfg, 0, 0, false, false, false, "", false, false, 0, rd, pluggedIn)
	needPersist := stateKey == "" || stateKey != e.lastPersistedKey
	e.mu.Unlock()

	if needPersist && e.srv != nil && e.srv.hncDir != "" {
		if b, err := json.MarshalIndent(snap, "", "  "); err == nil {
			if discoverWriteAtomic(e.stateRunPath(), b) == nil && stateKey != "" {
				e.mu.Lock()
				e.lastPersistedKey = stateKey
				e.mu.Unlock()
			}
		}
	}
}

func (e *thermoCruiseEngine) needsHotspotOffCleanup() bool {
	if e.effectiveStage.Load() != 0 {
		return true
	}
	e.mu.Lock()
	dirty := e.rawThermalStage != 0 || !e.coolBelowStage1Since.IsZero() || !e.coolBelowStage2Since.IsZero() || e.lastStage2Shaper
	e.mu.Unlock()
	return dirty
}

func (e *thermoCruiseEngine) isHotspotOffReadOnly() bool {
	if e == nil {
		return false
	}
	_, act, sim := e.readActivity()
	return act.Known && !act.HotspotActive && !sim
}

// ReadOnlySnapshot 在 HotspotOff 期间返回配置与实时传感器读数的纯只读快照,
// 严禁推进 effectiveStage / rawThermalStage, 严禁覆写 run/thermo_state.json。
func (e *thermoCruiseEngine) ReadOnlySnapshot(now time.Time, rd ThermoBatteryReading) map[string]any {
	if now.IsZero() {
		now = time.Now()
	}
	e.mu.Lock()
	cfg := e.cfg
	e.mu.Unlock()

	exitStage2Temp := cfg.Stage2TempC - thermoHysteresisC
	exitStage1Temp := cfg.Stage1TempC - thermoHysteresisC
	return map[string]any{
		"ok":                      true,
		"enabled":                 cfg.Enabled,
		"stage2_shaper_enabled":   cfg.Stage2ShaperEnabled,
		"stage1_temp_c":           cfg.Stage1TempC,
		"stage2_temp_c":           cfg.Stage2TempC,
		"stage1_exit_temp_c":      math.Round(exitStage1Temp*10) / 10,
		"stage2_exit_temp_c":      math.Round(exitStage2Temp*10) / 10,
		"hysteresis_c":            thermoHysteresisC,
		"low_bat_pct":             cfg.LowBatPct,
		"raw_thermal_stage":       0,
		"effective_stage":         0,
		"stage1_polling_relaxed":  false,
		"stage2_shaper_active":    false,
		"stage2_exempt":           false,
		"exempt_reason":           "",
		"low_battery_cruise":      false,
		"vector_express_active":   false,
		"cool_hold_remaining_sec": 0,
		"battery":                 rd,
		"config":                  cfg,
		"updated_at":              now.Unix(),
	}
}

func (e *thermoCruiseEngine) summary() map[string]any {
	e.mu.Lock()
	cfg := e.cfg
	rd := e.lastReading
	rawStage := e.rawThermalStage
	e.mu.Unlock()
	return map[string]any{
		"enabled":           cfg.Enabled,
		"effective_stage":   int(e.effectiveStage.Load()),
		"raw_thermal_stage": rawStage,
		"temp_c":            rd.TempC,
		"capacity_pct":      rd.CapacityPct,
		"status":            rd.Status,
	}
}

func (e *thermoCruiseEngine) readActivity() (<-chan struct{}, Activity, bool) {
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

func (e *thermoCruiseEngine) evalNoClientsRelease(now time.Time, probedOnce *bool) (time.Duration, bool) {
	e.mu.Lock()
	rawStage := e.rawThermalStage
	e.mu.Unlock()

	// rawThermalStage == 0 (含纯低电态 low_battery_cruise) 直接停表 0 唤醒!
	if rawStage <= 0 {
		return 0, false
	}

	if probedOnce != nil && !*probedOnce {
		*probedOnce = true
		rd := e.sampleBattery()
		e.Evaluate(now, rd, e.srv.isVectorExpressActive())
	}

	holdDur := e.effectiveCoolHoldDuration()
	e.mu.Lock()
	rawStage = e.rawThermalStage
	c2 := e.coolBelowStage2Since
	c1 := e.coolBelowStage1Since
	e.mu.Unlock()

	if rawStage <= 0 {
		return 0, false
	}
	var rem time.Duration
	if rawStage == 2 && !c2.IsZero() {
		rem = holdDur - now.Sub(c2)
	} else if rawStage == 1 && !c1.IsZero() {
		rem = holdDur - now.Sub(c1)
	} else {
		rem = holdDur
	}
	if rem < 0 {
		rem = 0
	}
	return rem + 15*time.Millisecond, true
}

func (e *thermoCruiseEngine) runLoop(stop <-chan struct{}) {
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
		noClientsProbed bool
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
		rd := e.sampleBattery()
		e.Evaluate(now, rd, e.srv.isVectorExpressActive())
	}

	for {
		actCh, act, simOn := e.readActivity()
		now := time.Now()

		if isV6EngineActive(act, simOn) {
			resetDone = false
			noClientsProbed = false
			stopRelTimer()
			if !wasActive {
				patrolOnce(now)
				wasActive = true
			}
			ensureTicker(e.effectivePollInterval())
			e.loopMode.Store(int32(v6EngineModeActive))
		} else if !act.HotspotActive {
			wasActive = false
			noClientsProbed = false
			stopTicker()
			stopRelTimer()
			if !resetDone || e.effectiveStage.Load() != 0 || e.needsHotspotOffCleanup() {
				e.resetForHotspotOff(now)
				resetDone = true
			}
			e.loopMode.Store(int32(v6EngineModeSleeping))
		} else {
			wasActive = false
			resetDone = false
			stopTicker()
			if rem, pending := e.evalNoClientsRelease(now, &noClientsProbed); pending {
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
			noClientsProbed = false
			if wasActive {
				patrolOnce(time.Now())
			}
		case tickNow := <-tkCh:
			patrolOnce(tickNow)
		case timerNow := <-relTimerCh:
			relTimer = nil
			relTimerCh = nil
			patrolOnce(timerNow)
		}
	}
}

// ── HTTP: GET & POST /api/v6/thermo ──────────────────────────────────────────

func (s *server) apiThermoCruise(w http.ResponseWriter, r *http.Request) {
	eng := s.v6State().thermo
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
		rd := eng.sampleBattery()
		if isOffReadOnly() {
			writeJSON(w, http.StatusOK, eng.ReadOnlySnapshot(time.Now(), rd))
			return
		}
		snap := eng.Evaluate(time.Now(), rd, s.isVectorExpressActive())
		writeJSON(w, http.StatusOK, snap)
		return
	}
	s.requireMutation(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled             *bool    `json:"enabled"`
			Stage2ShaperEnabled *bool    `json:"stage2_shaper_enabled"`
			Stage1TempC         *float64 `json:"stage1_temp_c"`
			Stage2TempC         *float64 `json:"stage2_temp_c"`
			LowBatPct           *int     `json:"low_bat_pct"`
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
		if req.Stage2ShaperEnabled != nil {
			next.Stage2ShaperEnabled = *req.Stage2ShaperEnabled
		}
		if req.Stage1TempC != nil {
			next.Stage1TempC = *req.Stage1TempC
		}
		if req.Stage2TempC != nil {
			next.Stage2TempC = *req.Stage2TempC
		}
		if req.LowBatPct != nil {
			next.LowBatPct = *req.LowBatPct
		}
		if msg := validThermoConfig(next); msg != "" {
			eng.mu.Unlock()
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": msg})
			return
		}
		eng.cfg = next
		err := eng.saveConfigLocked()
		eng.mu.Unlock()

		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write failed", "detail": err.Error()})
			return
		}
		rd := eng.sampleBattery()
		if isOffReadOnly() {
			writeJSON(w, http.StatusOK, eng.ReadOnlySnapshot(time.Now(), rd))
			return
		}
		snap := eng.Evaluate(time.Now(), rd, s.isVectorExpressActive())
		eng.Wake()
		writeJSON(w, http.StatusOK, snap)
	})(w, r)
}
