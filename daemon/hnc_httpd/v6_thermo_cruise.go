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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	thermoDefaultSysfsRoot   = "/sys/class/power_supply"
	thermoDefaultThermalRoot = "/sys/class/thermal"
	thermoDefaultStage1TempC = 42.0
	thermoDefaultStage2TempC = 45.0
	thermoDefaultLowBatPct   = 20
	thermoHysteresisC        = 3.0
	thermoCoolHoldDuration   = 60 * time.Second

	ThermoReasonSensorUnreadable = "sensor_unreadable"
	ThermoReasonSensorSentinel   = "sensor_sentinel"
	ThermoReasonSensorOutOfRange = "sensor_out_of_range"

	thermoMinValidTempC        = -20.0
	thermoMaxValidBatteryTempC = 85.0
	thermoMaxValidZoneTempC    = 100.0

	thermoMinValidShellTempC     = 0.0
	thermoMaxValidShellTempC     = 75.0
	thermoSpoofSuspectDeltaC     = 6.5
	thermoIdleSummaryThrottleDur = 3 * time.Second
)

var thermoAllowedZoneTypes = map[string]bool{
	"battery":   true,
	"bms":       true,
	"chg_therm": true,
}

type cachedShellZoneNode struct {
	tier     int
	zoneType string
	tempPath string
}

var activeLiveThermoEngine atomic.Pointer[thermoCruiseEngine]

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

// ThermoBatteryReading 单次 sysfs 传感器零开销读数（含电芯+机身壳温双源校准）。
type ThermoBatteryReading struct {
	Available             bool    `json:"available"`
	ReasonCode            string  `json:"reason_code,omitempty"`
	SupplyNode            string  `json:"supply_node,omitempty"`
	TempC                 float64 `json:"temp_c"`
	BatteryTempC          float64 `json:"battery_temp_c"`
	ShellTempC            float64 `json:"shell_temp_c"`
	ShellTempAvailable    bool    `json:"shell_temp_available"`
	ShellZone             string  `json:"shell_zone,omitempty"`
	BatterySpoofSuspected bool    `json:"battery_spoof_suspected,omitempty"`
	CapacityPct           int     `json:"capacity_pct"`
	Status                string  `json:"status"`
	IsCharging            bool    `json:"is_charging"`
	ChargerOnline         bool    `json:"charger_online,omitempty"`
	IsBypassSupply        bool    `json:"is_bypass_supply,omitempty"`
	ReadLatency           int64   `json:"read_latency_ns"`
}

// ThermoQuickState 纯内存零 sysfs IO 温控快速快照（供黑匣子 200ms 归因与信号诊断无阻塞读取）。
type ThermoQuickState struct {
	Enabled               bool    `json:"enabled"`
	Available             bool    `json:"available"`
	ReasonCode            string  `json:"reason_code,omitempty"`
	SensorFaultCount      uint64  `json:"sensor_fault_count,omitempty"`
	RawThermalStage       int     `json:"raw_thermal_stage"`
	EffectiveStage        int     `json:"effective_stage"`
	Stage2ShaperActive    bool    `json:"stage2_shaper_active"`
	Stage2Exempt          bool    `json:"stage2_exempt"`
	TempC                 float64 `json:"temp_c"`
	BatteryTempC          float64 `json:"battery_temp_c"`
	ShellTempC            float64 `json:"shell_temp_c"`
	ShellTempAvailable    bool    `json:"shell_temp_available"`
	ShellZone             string  `json:"shell_zone,omitempty"`
	BatterySpoofSuspected bool    `json:"battery_spoof_suspected,omitempty"`
	CapacityPct           int     `json:"capacity_pct"`
	IsCharging            bool    `json:"is_charging"`
	IsBypassSupply        bool    `json:"is_bypass_supply,omitempty"`
}

type thermoCruiseEngine struct {
	// 64 位原子字段严格置于 offset 0 (兼容 32-bit ARM)
	evalCount        atomic.Uint64
	effectiveStage   atomic.Int64
	sensorFaultCount atomic.Uint64

	// 非 64 位原子字段与通道/钩子严格排在全部 64 位原子字段之后
	loopMode        atomic.Int32
	stage1RelaxFlag atomic.Bool
	wakeOnce        sync.Once
	wakeCh          chan struct{}

	srv                  *server
	mu                   sync.Mutex
	cfg                  ThermoCruiseConfig
	sysfsRoot            string
	thermalRoot          string
	cachedBatDir         string
	cachedTempPath       string
	cachedShellThRoot    string
	shellZonesScanned    bool
	cachedShellZones     []cachedShellZoneNode
	rawThermalStage      int       // 0 | 1 | 2（纯温度施密特状态机输出）
	coolBelowStage2Since time.Time // 持续 <= stage2_temp_c - 3.0°C 的起始时刻
	coolBelowStage1Since time.Time // 持续 <= stage1_temp_c - 3.0°C 的起始时刻
	lastStage2Shaper     bool
	lastStage2Exempt     bool
	lastReading          ThermoBatteryReading
	summaryReadAt        time.Time
	summaryReading       ThermoBatteryReading
	lastSnap             map[string]any
	lastPersistedKey     string
	cfgSaveMu            sync.Mutex
	cfgSaveSeq           uint64
	lastSavedCfgSeq      uint64

	pollInterval      time.Duration
	coolHoldDur       time.Duration
	idleSummaryMinGap time.Duration
	activityHook      func() (<-chan struct{}, Activity)
	simActiveHook     func() bool
	batteryReadHook   func() ThermoBatteryReading
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

// IsStage1PollingRelaxed 返回当前温控引擎是否处于一阶及以上省电轮询节流态。
func (e *thermoCruiseEngine) IsStage1PollingRelaxed() bool {
	if e == nil {
		return false
	}
	return e.stage1RelaxFlag.Load()
}

func (s *server) isThermoStage1Relaxed() bool {
	if s == nil {
		return false
	}
	if v, ok := v6Registry.Load(s); ok {
		if vs, ok := v.(*v6ServerState); ok && vs != nil && vs.thermo != nil {
			return vs.thermo.IsStage1PollingRelaxed()
		}
	}
	return false
}

func isGlobalLiveThermoStage1Relaxed() bool {
	eng := activeLiveThermoEngine.Load()
	return eng != nil && eng.IsStage1PollingRelaxed()
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

func (e *thermoCruiseEngine) persistConfigBytesUnlocked(seq uint64, b []byte) error {
	if e.srv == nil || e.srv.hncDir == "" || len(b) == 0 {
		return nil
	}
	e.cfgSaveMu.Lock()
	defer e.cfgSaveMu.Unlock()
	if seq < e.lastSavedCfgSeq {
		return nil
	}
	if err := discoverWriteAtomic(e.configPath(), b); err != nil {
		return err
	}
	e.lastSavedCfgSeq = seq
	return nil
}

// ── 零子进程 sysfs 多量纲自适应温度解析与坏传感器熔断 (<50µs) ─────────────────

func isBrokenTempSentinel(v float64, isThermalZone bool) bool {
	if isThermalZone && math.Abs(v) < 1e-9 {
		return true
	}
	iv := int64(math.Round(v))
	if math.Abs(v-float64(iv)) > 1e-6 {
		return false
	}
	switch iv {
	case 2147483647, -2147483648, 125000, 127000, 255000, -273000, -40000, -400:
		return true
	default:
		return false
	}
}

// parseSysfsTempAdaptive 按是否热区节点执行量纲换算、哨兵拦截与物理合理区间校验。
func parseSysfsTempAdaptive(raw string, isThermalZone, powerSupplyTenthsABI bool) (celsius float64, reasonCode string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, ThermoReasonSensorUnreadable, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, ThermoReasonSensorUnreadable, false
	}
	if isBrokenTempSentinel(v, isThermalZone) {
		return 0, ThermoReasonSensorSentinel, false
	}

	absV := math.Abs(v)
	var c float64
	if !isThermalZone && powerSupplyTenthsABI {
		switch {
		case absV >= 1000.0:
			c = v / 1000.0
		case strings.Contains(s, "."):
			c = v
		default:
			c = v / 10.0
		}
	} else if isThermalZone {
		if strings.Contains(s, ".") {
			c = v
		} else {
			// Linux thermal_zone ABI 固定采用整数毫摄氏度 (millidegrees, 如 500 -> 0.5℃, 42000 -> 42.0℃)
			c = v / 1000.0
		}
	} else {
		switch {
		case absV >= 1000.0:
			c = v / 1000.0
		case absV >= 100.0:
			c = v / 10.0
		default:
			c = v
		}
	}
	c = math.Round(c*10) / 10

	maxValid := thermoMaxValidBatteryTempC
	if isThermalZone {
		maxValid = thermoMaxValidZoneTempC
	}
	if c < thermoMinValidTempC || c > maxValid {
		return 0, ThermoReasonSensorOutOfRange, false
	}
	return c, "", true
}

// parseSysfsTempCelsiusDetail 结合 sysfs 路径语义做多量纲自适应换算与坏传感器熔断判定:
//   - power_supply 电芯节点: 过滤哨兵值; |v|>=1000 按毫摄氏度 /1000.0, 显式小数按原值, 其余按 Linux ABI 0.1℃ /10.0, 合法区间 [-20.0, 85.0]℃;
//   - thermal_zone 热区节点: 过滤哨兵值及未初始化 0; 显式小数按原值, 整数统一按标准毫摄氏度 /1000.0 (如 500 -> 0.5℃), 合法区间 [-20.0, 100.0]℃。
func parseSysfsTempCelsiusDetail(path, raw string) (celsius float64, reasonCode string, ok bool) {
	slash := strings.ToLower(filepath.ToSlash(strings.TrimSpace(path)))
	isThermalZone := strings.Contains(slash, "thermal_zone") || strings.Contains(slash, "/thermal/")
	isPowerSupply := !isThermalZone && slash != ""
	return parseSysfsTempAdaptive(raw, isThermalZone, isPowerSupply)
}

// parseSysfsTempCelsius 保持原有 (path, raw) -> (float64, bool) 签名兼容旧调用方。
func parseSysfsTempCelsius(path, raw string) (float64, bool) {
	c, _, ok := parseSysfsTempCelsiusDetail(path, raw)
	return c, ok
}

func readSmallSysfsFile(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func resolveEffectiveThermalRoot(sysfsRoot, explicitThermalRoot string) string {
	if strings.TrimSpace(explicitThermalRoot) != "" {
		return strings.TrimSpace(explicitThermalRoot)
	}
	if sysfsRoot == "" || filepath.Clean(sysfsRoot) == filepath.Clean(thermoDefaultSysfsRoot) {
		return thermoDefaultThermalRoot
	}
	// 单测自定义 sysfsRoot 时仅探测同父目录下的测试热区目录, 严防逃逸读取宿主机真实 /sys/class/thermal
	parent := filepath.Dir(filepath.Clean(sysfsRoot))
	for _, sub := range []string{"thermal", "sysfs_thermal"} {
		cand := filepath.Join(parent, sub)
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
	}
	return ""
}

func collectTempCandidatePaths(psRoot, thRoot string) (tempPaths []string, primaryBatDir string) {
	seen := make(map[string]bool)
	addPath := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			tempPaths = append(tempPaths, p)
		}
	}

	if psRoot != "" {
		primary := filepath.Join(psRoot, "battery")
		if typ, hasType := readSmallSysfsFile(filepath.Join(primary, "type")); !hasType || strings.EqualFold(typ, "Battery") {
			if st, err := os.Stat(primary); err == nil && st.IsDir() {
				primaryBatDir = primary
			}
			addPath(filepath.Join(primary, "temp"))
		}
		if ents, err := os.ReadDir(psRoot); err == nil {
			for _, ent := range ents {
				name := ent.Name()
				if name == "battery" {
					continue
				}
				cand := filepath.Join(psRoot, name)
				if typ, ok := readSmallSysfsFile(filepath.Join(cand, "type")); ok && strings.EqualFold(typ, "Battery") {
					if primaryBatDir == "" {
						primaryBatDir = cand
					}
					addPath(filepath.Join(cand, "temp"))
				}
			}
		}
		for _, name := range []string{"bms", "BAT0", "Battery"} {
			cand := filepath.Join(psRoot, name)
			if st, err := os.Stat(cand); err == nil && st.IsDir() && primaryBatDir == "" {
				primaryBatDir = cand
			}
			addPath(filepath.Join(cand, "temp"))
		}
	}

	if thRoot != "" {
		if ents, err := os.ReadDir(thRoot); err == nil {
			for _, ent := range ents {
				name := ent.Name()
				if !strings.HasPrefix(name, "thermal_zone") {
					continue
				}
				zDir := filepath.Join(thRoot, name)
				typ, ok := readSmallSysfsFile(filepath.Join(zDir, "type"))
				if !ok {
					continue
				}
				normType := strings.ToLower(strings.TrimSpace(typ))
				if thermoAllowedZoneTypes[normType] {
					addPath(filepath.Join(zDir, "temp"))
				}
			}
		}
	}
	return tempPaths, primaryBatDir
}

func probeChargerAndBypassState(psRoot, batDir string, statusStr string) (isCharging, chargerOnline, isBypass bool) {
	rawCharging := strings.EqualFold(statusStr, "Charging") || strings.EqualFold(statusStr, "Full")
	if psRoot == "" {
		return rawCharging, rawCharging, false
	}

	hasOnlineNode := false
	for _, supplyName := range []string{"usb", "ac", "wireless", "Mains", "USB"} {
		if val, ok := readSmallSysfsFile(filepath.Join(psRoot, supplyName, "online")); ok {
			hasOnlineNode = true
			if val == "1" {
				chargerOnline = true
			}
		}
	}

	explicitBypass := false
	for _, dir := range []string{batDir, filepath.Join(psRoot, "battery")} {
		if dir == "" {
			continue
		}
		if v, ok := readSmallSysfsFile(filepath.Join(dir, "bypass_charging")); ok && (v == "1" || strings.EqualFold(v, "enabled") || strings.EqualFold(v, "true")) {
			explicitBypass = true
			break
		}
		if v, ok := readSmallSysfsFile(filepath.Join(dir, "charging_enabled")); ok && v == "0" && chargerOnline {
			explicitBypass = true
			break
		}
		if v, ok := readSmallSysfsFile(filepath.Join(dir, "input_suspend")); ok && v == "1" {
			explicitBypass = true
			break
		}
	}

	if explicitBypass {
		return false, chargerOnline, true
	}
	if !hasOnlineNode {
		// 未提供 usb/online 或 ac/online 节点时保持原有 Charging / Full 判定兼容
		return rawCharging, rawCharging, false
	}
	if !chargerOnline {
		// usb/online 与 ac/online 均存在且均为 0: 即使 status 滞后报 Charging 也拒绝叠加快充偏置/豁免
		if rawCharging {
			return false, false, true
		}
		return false, false, false
	}
	// usb/online 或 ac/online == 1, 但电芯处于 Not charging / Discharging / Idle -> 典型旁路供电
	if strings.EqualFold(statusStr, "Not charging") || strings.EqualFold(statusStr, "Discharging") || strings.EqualFold(statusStr, "Idle") {
		return false, true, true
	}
	return rawCharging, true, false
}

func matchShellThermalZoneTier(rawType string) (tier int, normType string, ok bool) {
	t := strings.ToLower(strings.TrimSpace(rawType))
	if t == "" {
		return 0, "", false
	}
	switch {
	case t == "shell_front" || t == "shell_frame" || t == "shell_back":
		return 1, t, true
	case strings.HasPrefix(t, "shell"):
		return 2, t, true
	case strings.HasPrefix(t, "skin"):
		return 3, t, true
	case strings.HasPrefix(t, "quiet_therm"):
		return 4, t, true
	case strings.HasPrefix(t, "xo_therm") || strings.HasPrefix(t, "xo-therm"):
		return 5, t, true
	default:
		return 0, "", false
	}
}

func discoverShellThermalZones(thRoot string) []cachedShellZoneNode {
	if thRoot == "" {
		return nil
	}
	ents, err := os.ReadDir(thRoot)
	if err != nil {
		return nil
	}
	var out []cachedShellZoneNode
	for _, ent := range ents {
		name := ent.Name()
		if !strings.HasPrefix(name, "thermal_zone") {
			continue
		}
		zDir := filepath.Join(thRoot, name)
		typ, ok := readSmallSysfsFile(filepath.Join(zDir, "type"))
		if !ok {
			continue
		}
		tier, normType, matched := matchShellThermalZoneTier(typ)
		if !matched {
			continue
		}
		out = append(out, cachedShellZoneNode{
			tier:     tier,
			zoneType: normType,
			tempPath: filepath.Join(zDir, "temp"),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].tier != out[j].tier {
			return out[i].tier < out[j].tier
		}
		if out[i].zoneType != out[j].zoneType {
			return out[i].zoneType < out[j].zoneType
		}
		return out[i].tempPath < out[j].tempPath
	})
	return out
}

func evalCachedShellZones(zones []cachedShellZoneNode) (shellTempC float64, shellZone string, ok bool) {
	bestTier := 0
	for _, z := range zones {
		if bestTier > 0 && z.tier > bestTier {
			break
		}
		raw, okRead := readSmallSysfsFile(z.tempPath)
		if !okRead {
			continue
		}
		c, _, okValid := parseSysfsTempCelsiusDetail(z.tempPath, raw)
		if !okValid || c < thermoMinValidShellTempC || c > thermoMaxValidShellTempC {
			continue
		}
		if !ok || c > shellTempC {
			shellTempC = c
			shellZone = z.zoneType
			bestTier = z.tier
			ok = true
		}
	}
	return shellTempC, shellZone, ok
}

// readShellTempFromSysfs 读取机身壳温传感器（首次扫描缓存节点路径避免每次 ReadDir）。
func (e *thermoCruiseEngine) readShellTempFromSysfs(thRoot string) (shellTempC float64, shellZone string, ok bool) {
	if thRoot == "" {
		return 0, "", false
	}
	e.mu.Lock()
	scanned := e.shellZonesScanned && e.cachedShellThRoot == thRoot
	var zones []cachedShellZoneNode
	if scanned && len(e.cachedShellZones) > 0 {
		zones = append([]cachedShellZoneNode(nil), e.cachedShellZones...)
	}
	e.mu.Unlock()

	if !scanned {
		discovered := discoverShellThermalZones(thRoot)
		if len(discovered) > 0 {
			e.mu.Lock()
			e.cachedShellThRoot = thRoot
			e.shellZonesScanned = true
			e.cachedShellZones = append([]cachedShellZoneNode(nil), discovered...)
			e.mu.Unlock()
		} else {
			e.mu.Lock()
			if e.cachedShellThRoot != thRoot {
				e.cachedShellThRoot = thRoot
				e.shellZonesScanned = false
				e.cachedShellZones = nil
			}
			e.mu.Unlock()
		}
		zones = discovered
	}
	if len(zones) == 0 {
		return 0, "", false
	}
	if c, zn, valid := evalCachedShellZones(zones); valid {
		return c, zn, true
	}
	return 0, "", false
}

// calibrateThermoDualReading 统一执行电芯与机身壳温双源校准（兼容 fopbatt 等电池负偏置伪装模块并防高温过热致盲）。
func calibrateThermoDualReading(rd ThermoBatteryReading) ThermoBatteryReading {
	if !rd.Available {
		return rd
	}
	if rd.BatteryTempC == 0 && rd.TempC != 0 && !rd.BatterySpoofSuspected {
		rd.BatteryTempC = math.Round(rd.TempC*10) / 10
	} else {
		rd.BatteryTempC = math.Round(rd.BatteryTempC*10) / 10
	}
	if rd.ShellTempAvailable {
		rd.ShellTempC = math.Round(rd.ShellTempC*10) / 10
		if rd.ShellTempC-rd.BatteryTempC >= thermoSpoofSuspectDeltaC-1e-6 {
			rd.BatterySpoofSuspected = true
			rd.TempC = math.Round(math.Max(rd.BatteryTempC, rd.ShellTempC)*10) / 10
		} else {
			rd.BatterySpoofSuspected = false
			rd.TempC = rd.BatteryTempC
		}
	} else {
		rd.ShellTempC = 0
		rd.ShellZone = ""
		rd.BatterySpoofSuspected = false
		if rd.TempC == 0 && rd.BatteryTempC != 0 {
			rd.TempC = rd.BatteryTempC
		} else {
			rd.TempC = math.Round(rd.TempC*10) / 10
		}
	}
	return rd
}

// ReadBatteryFromSysfs 直接通过 os.ReadFile 读取电芯/壳温热区节点并执行量纲自适应与双温校准（典型耗时 15~45µs）。
func (e *thermoCruiseEngine) ReadBatteryFromSysfs() ThermoBatteryReading {
	t0 := time.Now()

	e.mu.Lock()
	root := e.sysfsRoot
	thRootCfg := e.thermalRoot
	batDir := e.cachedBatDir
	tempPath := e.cachedTempPath
	e.mu.Unlock()

	thRoot := resolveEffectiveThermalRoot(root, thRootCfg)

	var (
		batTempC       float64
		supplyNode     string
		firstFaultCode string
		firstFaultNode string
		gotValid       bool
	)

	tryTempPath := func(p string) bool {
		if p == "" {
			return false
		}
		raw, okRead := readSmallSysfsFile(p)
		if !okRead {
			return false
		}
		c, reason, okValid := parseSysfsTempCelsiusDetail(p, raw)
		nodeName := filepath.Base(filepath.Dir(p))
		if okValid {
			batTempC = c
			supplyNode = nodeName
			tempPath = p
			gotValid = true
			return true
		}
		if firstFaultCode == "" && reason != "" {
			firstFaultCode = reason
			firstFaultNode = nodeName
		}
		return false
	}

	if tempPath != "" {
		_ = tryTempPath(tempPath)
	}
	if !gotValid {
		cands, discoveredBatDir := collectTempCandidatePaths(root, thRoot)
		if discoveredBatDir != "" {
			batDir = discoveredBatDir
		}
		for _, candPath := range cands {
			if tryTempPath(candPath) {
				if !strings.Contains(strings.ToLower(filepath.ToSlash(candPath)), "thermal_zone") && batDir == "" {
					batDir = filepath.Dir(candPath)
				}
				break
			}
		}
		e.mu.Lock()
		if e.sysfsRoot == root && e.thermalRoot == thRootCfg {
			if gotValid {
				e.cachedBatDir = batDir
				e.cachedTempPath = tempPath
			} else {
				e.cachedBatDir = ""
				e.cachedTempPath = ""
			}
		}
		e.mu.Unlock()
	}

	if !gotValid {
		e.sensorFaultCount.Add(1)
		reason := firstFaultCode
		if reason == "" {
			reason = ThermoReasonSensorUnreadable
		}
		node := firstFaultNode
		if node == "" && batDir != "" {
			node = filepath.Base(batDir)
		}
		return ThermoBatteryReading{
			Available:   false,
			ReasonCode:  reason,
			SupplyNode:  node,
			ReadLatency: time.Since(t0).Nanoseconds(),
		}
	}

	shellTempC, shellZone, shellOK := e.readShellTempFromSysfs(thRoot)

	statusDir := batDir
	if statusDir == "" && root != "" {
		primary := filepath.Join(root, "battery")
		if st, err := os.Stat(primary); err == nil && st.IsDir() {
			statusDir = primary
		} else if !strings.Contains(strings.ToLower(filepath.ToSlash(tempPath)), "thermal_zone") {
			statusDir = filepath.Dir(tempPath)
		}
	}

	capPct := -1
	statusStr := ""
	if statusDir != "" {
		if capStr, ok := readSmallSysfsFile(filepath.Join(statusDir, "capacity")); ok {
			if n, err := strconv.Atoi(capStr); err == nil && n >= 0 && n <= 100 {
				capPct = n
			}
		}
		statusStr, _ = readSmallSysfsFile(filepath.Join(statusDir, "status"))
	}
	if statusStr == "" {
		statusStr = "Unknown"
	}
	charging, chargerOnline, isBypass := probeChargerAndBypassState(root, statusDir, statusStr)

	return calibrateThermoDualReading(ThermoBatteryReading{
		Available:          true,
		SupplyNode:         supplyNode,
		TempC:              batTempC,
		BatteryTempC:       batTempC,
		ShellTempC:         shellTempC,
		ShellTempAvailable: shellOK,
		ShellZone:          shellZone,
		CapacityPct:        capPct,
		Status:             statusStr,
		IsCharging:         charging,
		ChargerOnline:      chargerOnline,
		IsBypassSupply:     isBypass,
		ReadLatency:        time.Since(t0).Nanoseconds(),
	})
}

func (e *thermoCruiseEngine) sampleBattery() ThermoBatteryReading {
	if e != nil && e.batteryReadHook != nil {
		rd := e.batteryReadHook()
		if !rd.Available {
			e.sensorFaultCount.Add(1)
			if rd.ReasonCode == "" {
				rd.ReasonCode = ThermoReasonSensorUnreadable
			}
			return rd
		}
		return calibrateThermoDualReading(rd)
	}
	return e.ReadBatteryFromSysfs()
}

// PeekQuickState 纯内存零 sysfs IO 读取最新缓存的温控状态（供 200ms 黑匣子归因与信号诊断高频调用）。
func (e *thermoCruiseEngine) PeekQuickState() ThermoQuickState {
	if e == nil {
		return ThermoQuickState{}
	}
	eff := int(e.effectiveStage.Load())
	faults := e.sensorFaultCount.Load()
	e.mu.Lock()
	cfg := e.cfg
	raw := e.rawThermalStage
	rd := calibrateThermoDualReading(e.lastReading)
	s2Active := e.lastStage2Shaper
	s2Exempt := e.lastStage2Exempt
	e.mu.Unlock()

	charging := rd.IsCharging
	if !charging && !rd.IsBypassSupply && (strings.EqualFold(rd.Status, "Charging") || strings.EqualFold(rd.Status, "Full")) {
		charging = true
	}

	return ThermoQuickState{
		Enabled:               cfg.Enabled,
		Available:             rd.Available,
		ReasonCode:            rd.ReasonCode,
		SensorFaultCount:      faults,
		RawThermalStage:       raw,
		EffectiveStage:        eff,
		Stage2ShaperActive:    s2Active,
		Stage2Exempt:          s2Exempt,
		TempC:                 rd.TempC,
		BatteryTempC:          rd.BatteryTempC,
		ShellTempC:            rd.ShellTempC,
		ShellTempAvailable:    rd.ShellTempAvailable,
		ShellZone:             rd.ShellZone,
		BatterySpoofSuspected: rd.BatterySpoofSuspected,
		CapacityPct:           rd.CapacityPct,
		IsCharging:            charging,
		IsBypassSupply:        rd.IsBypassSupply,
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
	faultCnt := e.sensorFaultCount.Load()
	rd = calibrateThermoDualReading(rd)

	e.mu.Lock()
	cfg := e.cfg
	if !rd.Available && rd.ReasonCode == "" {
		rd.ReasonCode = ThermoReasonSensorUnreadable
	}
	e.lastReading = rd
	e.summaryReading = rd
	e.summaryReadAt = time.Now()

	exitStage2Temp := cfg.Stage2TempC - thermoHysteresisC // 默认 45.0 - 3.0 = 42.0°C
	exitStage1Temp := cfg.Stage1TempC - thermoHysteresisC // 默认 42.0 - 3.0 = 39.0°C

	if !cfg.Enabled || !rd.Available {
		// 传感器不可读/哨兵值/越界异常或温控禁用: 立即熔断归零温控档位, 绝不因坏节点误触发限速!
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

	// 旁路供电保护: 仅真实快充/满电插电豁免二阶温控; 旁路供电不误判为大电流快充自发热, 但有外部供电时不触发低电量巡航
	chargingExempt := !rd.IsBypassSupply && (rd.IsCharging || strings.EqualFold(rd.Status, "Charging") || strings.EqualFold(rd.Status, "Full"))
	externalPower := chargingExempt || (rd.IsBypassSupply && rd.ChargerOnline)
	lowBatActive := cfg.Enabled && rd.Available && rd.CapacityPct >= 0 &&
		rd.CapacityPct <= cfg.LowBatPct && !externalPower

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
			if chargingExempt {
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
	e.stage1RelaxFlag.Store(stage1PollingRelax)

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
		"available":               rd.Available,
		"reason_code":             rd.ReasonCode,
		"sensor_fault_count":      faultCnt,
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
		"bypass_supply_active":    rd.IsBypassSupply,
		"vector_express_active":   expressActive,
		"cool_hold_remaining_sec": coolHoldRemSec,
		"temp_c":                  rd.TempC,
		"battery_temp_c":          rd.BatteryTempC,
		"shell_temp_c":            rd.ShellTempC,
		"shell_temp_available":    rd.ShellTempAvailable,
		"battery_spoof_suspected": rd.BatterySpoofSuspected,
		"battery":                 rd,
		"config":                  cfg,
		"updated_at":              now.Unix(),
	}
	if rd.ShellZone != "" {
		snap["shell_zone"] = rd.ShellZone
	}
	e.lastSnap = snap

	// 状态脏检查(忽略 updated_at 与 read_latency_ns): 状态无实质变化时不重复刷盘 run/thermo_state.json
	stateKey := buildThermoPersistKey(cfg, rawStage, effStage, stage1PollingRelax, stage2ShaperActive, stage2Exempt, exemptReasonStr, lowBatActive, expressActive, coolHoldRemSec, rd, externalPower)
	needPersist := stateKey == "" || stateKey != e.lastPersistedKey
	srv := e.srv
	e.mu.Unlock()

	if srv != nil {
		_, act, sim := e.readActivity()
		noClients := act.Known && act.HotspotActive && act.ClientsOnline <= 0 && !act.WebUIActive && !sim
		immediateRelease := !cfg.Enabled || !rd.Available || !cfg.Stage2ShaperEnabled || stage2Exempt || (!stage2ShaperActive && noClients)
		arbSnap := srv.shaperArbiter().UpdateThermoStage2(now, stage2ShaperActive, rd.TempC, immediateRelease)
		snap["thermo_cap_down_mbps"] = arbSnap.ThermoCapDownMbps
		snap["thermo_cap_up_mbps"] = arbSnap.ThermoCapUpMbps
		snap["thermo_recovering"] = arbSnap.ThermoRecovering
	}

	if needPersist && srv != nil && srv.hncDir != "" {
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
		Reason       string             `json:"rc"`
		Node         string             `json:"nd"`
		TempC        float64            `json:"tc"`
		BatTempC     float64            `json:"btc"`
		ShellTempC   float64            `json:"stc"`
		ShellAvail   bool               `json:"sav"`
		ShellZone    string             `json:"szn"`
		Spoof        bool               `json:"spf"`
		CapPct       int                `json:"cp"`
		Status       string             `json:"st"`
		Plugged      bool               `json:"pl"`
		Bypass       bool               `json:"bp"`
	}{
		Cfg: cfg, RawStage: rawStage, EffStage: effStage, S1Relax: s1Relax,
		S2Active: s2Active, S2Exempt: s2Exempt, ExemptReason: exemptReason,
		LowBat: lowBat, Express: express, CoolRem: coolRem,
		Avail: rd.Available, Reason: rd.ReasonCode, Node: rd.SupplyNode, TempC: rd.TempC,
		BatTempC: rd.BatteryTempC, ShellTempC: rd.ShellTempC, ShellAvail: rd.ShellTempAvailable,
		ShellZone: rd.ShellZone, Spoof: rd.BatterySpoofSuspected,
		CapPct: rd.CapacityPct, Status: rd.Status, Plugged: plugged, Bypass: rd.IsBypassSupply,
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
	faultCnt := e.sensorFaultCount.Load()
	e.mu.Lock()
	cfg := e.cfg
	rd := calibrateThermoDualReading(e.lastReading)
	e.rawThermalStage = 0
	e.coolBelowStage1Since = time.Time{}
	e.coolBelowStage2Since = time.Time{}
	e.lastStage2Shaper = false
	e.lastStage2Exempt = false
	e.summaryReadAt = time.Time{}
	e.effectiveStage.Store(0)
	e.stage1RelaxFlag.Store(false)

	exitStage2Temp := cfg.Stage2TempC - thermoHysteresisC
	exitStage1Temp := cfg.Stage1TempC - thermoHysteresisC
	pluggedIn := rd.IsCharging || strings.EqualFold(rd.Status, "Charging") || strings.EqualFold(rd.Status, "Full")

	snap := map[string]any{
		"ok":                      true,
		"enabled":                 cfg.Enabled,
		"available":               rd.Available,
		"reason_code":             rd.ReasonCode,
		"sensor_fault_count":      faultCnt,
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
		"bypass_supply_active":    rd.IsBypassSupply,
		"vector_express_active":   false,
		"cool_hold_remaining_sec": 0,
		"temp_c":                  rd.TempC,
		"battery_temp_c":          rd.BatteryTempC,
		"shell_temp_c":            rd.ShellTempC,
		"shell_temp_available":    rd.ShellTempAvailable,
		"battery_spoof_suspected": rd.BatterySpoofSuspected,
		"battery":                 rd,
		"config":                  cfg,
		"updated_at":              now.Unix(),
	}
	if rd.ShellZone != "" {
		snap["shell_zone"] = rd.ShellZone
	}
	e.lastSnap = snap
	stateKey := buildThermoPersistKey(cfg, 0, 0, false, false, false, "", false, false, 0, rd, pluggedIn)
	needPersist := stateKey == "" || stateKey != e.lastPersistedKey
	srv := e.srv
	e.mu.Unlock()

	if srv != nil {
		srv.shaperArbiter().UpdateThermoStage2(now, false, 0, true)
	}

	if needPersist && srv != nil && srv.hncDir != "" {
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
	if e.effectiveStage.Load() != 0 || e.stage1RelaxFlag.Load() {
		return true
	}
	if e.srv != nil && e.srv.shaperArbiter().IsThermoRecovering() {
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
	rd = calibrateThermoDualReading(rd)
	faultCnt := e.sensorFaultCount.Load()
	e.mu.Lock()
	cfg := e.cfg
	e.mu.Unlock()

	exitStage2Temp := cfg.Stage2TempC - thermoHysteresisC
	exitStage1Temp := cfg.Stage1TempC - thermoHysteresisC
	snap := map[string]any{
		"ok":                      true,
		"enabled":                 cfg.Enabled,
		"available":               rd.Available,
		"reason_code":             rd.ReasonCode,
		"sensor_fault_count":      faultCnt,
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
		"bypass_supply_active":    rd.IsBypassSupply,
		"vector_express_active":   false,
		"cool_hold_remaining_sec": 0,
		"temp_c":                  rd.TempC,
		"battery_temp_c":          rd.BatteryTempC,
		"shell_temp_c":            rd.ShellTempC,
		"shell_temp_available":    rd.ShellTempAvailable,
		"battery_spoof_suspected": rd.BatterySpoofSuspected,
		"battery":                 rd,
		"config":                  cfg,
		"updated_at":              now.Unix(),
	}
	if rd.ShellZone != "" {
		snap["shell_zone"] = rd.ShellZone
	}
	return snap
}

func (e *thermoCruiseEngine) effectiveIdleSummaryGap() time.Duration {
	if e != nil && e.idleSummaryMinGap > 0 {
		return e.idleSummaryMinGap
	}
	return thermoIdleSummaryThrottleDur
}

func (e *thermoCruiseEngine) summary() map[string]any {
	if e == nil {
		return map[string]any{}
	}
	loopActive := e.LoopMode() == v6EngineModeActive
	now := time.Now()
	minGap := e.effectiveIdleSummaryGap()
	holdDur := e.effectiveCoolHoldDuration()

	e.mu.Lock()
	cfg := e.cfg
	rawStage := e.rawThermalStage
	lastS2Shaper := e.lastStage2Shaper
	lastS2Exempt := e.lastStage2Exempt
	c2 := e.coolBelowStage2Since
	c1 := e.coolBelowStage1Since
	rd := e.lastReading
	needReadOnlySample := false
	if !loopActive {
		if !e.summaryReadAt.IsZero() && now.Sub(e.summaryReadAt) < minGap {
			rd = e.summaryReading
		} else {
			needReadOnlySample = true
		}
	} else if !rd.Available && rd.ReasonCode == "" {
		if !e.summaryReadAt.IsZero() && now.Sub(e.summaryReadAt) < minGap {
			rd = e.summaryReading
		} else {
			needReadOnlySample = true
		}
	}
	e.mu.Unlock()

	if needReadOnlySample {
		// 热点未开启或后台未轮询时: 3s 内存节流的无副作用只读传感器采样,
		// 严禁修改 effectiveStage / rawThermalStage / lastReading, 严禁写入 run/thermo_state.json!
		sampled := calibrateThermoDualReading(e.sampleBattery())
		sampleTs := time.Now()
		e.mu.Lock()
		e.summaryReadAt = sampleTs
		e.summaryReading = sampled
		cfg = e.cfg
		rawStage = e.rawThermalStage
		lastS2Shaper = e.lastStage2Shaper
		lastS2Exempt = e.lastStage2Exempt
		c2 = e.coolBelowStage2Since
		c1 = e.coolBelowStage1Since
		e.mu.Unlock()
		rd = sampled
	} else {
		rd = calibrateThermoDualReading(rd)
	}

	coolHoldRemSec := 0
	if rawStage == 2 && !c2.IsZero() {
		rem := holdDur - now.Sub(c2)
		if rem > 0 {
			coolHoldRemSec = int((rem + time.Second - 1) / time.Second)
		}
	} else if rawStage == 1 && !c1.IsZero() {
		rem := holdDur - now.Sub(c1)
		if rem > 0 {
			coolHoldRemSec = int((rem + time.Second - 1) / time.Second)
		}
	}
	externalPower := rd.IsCharging || rd.ChargerOnline || rd.IsBypassSupply ||
		strings.EqualFold(rd.Status, "Charging") || strings.EqualFold(rd.Status, "Full")
	lowBatCruise := loopActive && cfg.Enabled && rd.Available && !externalPower &&
		rd.CapacityPct > 0 && rd.CapacityPct <= cfg.LowBatPct

	faultCnt := e.sensorFaultCount.Load()
	out := map[string]any{
		"enabled":                 cfg.Enabled,
		"available":               rd.Available,
		"bat_available":           rd.Available,
		"reason_code":             rd.ReasonCode,
		"sensor_fault_count":      faultCnt,
		"stage2_shaper_enabled":   cfg.Stage2ShaperEnabled,
		"stage1_temp_c":           cfg.Stage1TempC,
		"stage2_temp_c":           cfg.Stage2TempC,
		"low_bat_pct":             cfg.LowBatPct,
		"effective_stage":         int(e.effectiveStage.Load()),
		"raw_thermal_stage":       rawStage,
		"stage2_shaper_active":    lastS2Shaper,
		"stage2_exempt":           lastS2Exempt,
		"low_battery_cruise":      lowBatCruise,
		"vector_express_active":   e.srv != nil && e.srv.isVectorExpressActive(),
		"cool_hold_remaining_sec": coolHoldRemSec,
		"temp_c":                  rd.TempC,
		"battery_temp_c":          rd.BatteryTempC,
		"shell_temp_c":            rd.ShellTempC,
		"shell_temp_available":    rd.ShellTempAvailable,
		"battery_spoof_suspected": rd.BatterySpoofSuspected,
		"capacity_pct":            rd.CapacityPct,
		"status":                  rd.Status,
		"is_charging":             rd.IsCharging,
		"charger_online":          rd.ChargerOnline,
		"bypass_supply":           rd.IsBypassSupply,
		"bypass_supply_active":    rd.IsBypassSupply,
	}
	if rd.ShellZone != "" {
		out["shell_zone"] = rd.ShellZone
	}
	return out
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

	arbRecovering := e.srv != nil && e.srv.shaperArbiter().IsThermoRecovering()
	// rawThermalStage == 0 且仲裁器无残余渐进爬坡限速时直接停表 0 唤醒!
	if rawStage <= 0 && !arbRecovering {
		return 0, false
	}

	if (probedOnce != nil && !*probedOnce) || (rawStage <= 0 && arbRecovering) {
		if probedOnce != nil {
			*probedOnce = true
		}
		rd := e.sampleBattery()
		e.Evaluate(now, rd, e.srv != nil && e.srv.isVectorExpressActive())
	}

	holdDur := e.effectiveCoolHoldDuration()
	e.mu.Lock()
	rawStage = e.rawThermalStage
	lastS2 := e.lastStage2Shaper
	c2 := e.coolBelowStage2Since
	c1 := e.coolBelowStage1Since
	e.mu.Unlock()

	// 若二阶温控已解除但仲裁器仍处于渐进爬坡恢复期, 0 客户端下立即一步解限恢复 100% 满速后再进入休眠!
	if !lastS2 && e.srv != nil && e.srv.shaperArbiter().IsThermoRecovering() {
		e.srv.shaperArbiter().UpdateThermoStage2(now, false, 0, true)
	}

	if rawStage <= 0 {
		if e.srv != nil && e.srv.shaperArbiter().IsThermoRecovering() {
			return e.effectivePollInterval(), true
		}
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
	activeLiveThermoEngine.Store(e)

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
		activeLiveThermoEngine.CompareAndSwap(e, nil)
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
		prevCfg := eng.cfg
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
		eng.cfgSaveSeq++
		saveSeq := eng.cfgSaveSeq
		cfgBytes, mErr := json.MarshalIndent(eng.cfg, "", "  ")
		eng.mu.Unlock()

		if mErr != nil {
			eng.mu.Lock()
			if eng.cfgSaveSeq == saveSeq {
				eng.cfg = prevCfg
			}
			eng.mu.Unlock()
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write failed", "detail": mErr.Error()})
			return
		}
		if err := eng.persistConfigBytesUnlocked(saveSeq, cfgBytes); err != nil {
			eng.mu.Lock()
			if eng.cfgSaveSeq == saveSeq {
				eng.cfg = prevCfg
			}
			eng.mu.Unlock()
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
