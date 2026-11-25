// root_shaper_arbiter.go — HNC v6.1.0-rc.4:
// 统一根带宽仲裁器 RootShaperArbiter（消除 static_shaper、5G Autorate、ThermoCruise Stage 2 覆写 1:1 与 rules.json 互搏）。
//
// 核心铁律:
//  1. 单一静态基准写盘权: data/rules.json 的 global_shaper_* 仅允许由用户手动静态总限速写入,
//     5G Autorate 与 ThermoCruise 严禁覆写 rules.json 静态基准。
//  2. 全局最低可用带宽地板 (Floor): 自动战术模块 (autorate / thermo_stage2) 触发的压速保底不低于
//     下行 5.0 Mbps / 上行 2.0 Mbps; 仅当用户手动将静态总限速设得低于 5/2 Mbps 时才尊重用户手动值。
//  3. 温控平滑退坡: Stage 2 激活时若静态未开按 40/15 Mbps 软顶压速, 静态已开按静态基准 60% 压速;
//     降温退出 Stage 2 时按每轮 +20% 平滑回升直至完全解除, 坏传感器熔断或热点关闭时立即解除。
//  4. 32 位 ARM 对齐: 所有 64 位原子字段严格排在结构体起始 offset 0; 持锁期间零子进程调用。

package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ArbiterAutoFloorDownMbps = 5.0
	ArbiterAutoFloorUpMbps   = 2.0

	ThermoStage2SoftCapDownMbps = 40.0
	ThermoStage2SoftCapUpMbps   = 15.0
	ThermoStage2StaticRatio     = 0.60
	ThermoRecoveryStepFactor    = 1.20

	// 静态总限速未开启时, 温控平滑恢复完全解除的目标阈值 (40 -> 48 -> 57.6 -> 69.12 -> 82.94 -> 99.53 -> 解除)
	thermoUnboundReleaseDownMbps = 100.0
	thermoUnboundReleaseUpMbps   = 37.5
	thermoMaxRecoverySteps       = 6

	arbiterTuneDeadbandRatio = 0.02
)

// ArbiterSnapshot 暴露给 /api/live 与 /api/vector_sync extensions.arbiter 的实时仲裁快照。
type ArbiterSnapshot struct {
	HotspotActive       bool     `json:"hotspot_active"`
	HotspotIface        string   `json:"hotspot_iface,omitempty"`
	StaticEnabled       bool     `json:"static_enabled"`
	StaticDownMbps      float64  `json:"static_down_mbps"`
	StaticUpMbps        float64  `json:"static_up_mbps"`
	AutorateActive      bool     `json:"autorate_active"`
	AutorateRawDownMbps float64  `json:"autorate_raw_down_mbps"`
	AutorateRawUpMbps   float64  `json:"autorate_raw_up_mbps"`
	ThermoStage2Active  bool     `json:"thermo_stage2_active"`
	ThermoRecovering    bool     `json:"thermo_recovering"`
	ThermoTempC         float64  `json:"thermo_temp_c"`
	ThermoCapDownMbps   float64  `json:"thermo_cap_down_mbps"`
	ThermoCapUpMbps     float64  `json:"thermo_cap_up_mbps"`
	FloorClamped        bool     `json:"floor_clamped"`
	FloorDownMbps       float64  `json:"floor_down_mbps"`
	FloorUpMbps         float64  `json:"floor_up_mbps"`
	EffectiveDownMbps   float64  `json:"effective_down_mbps"`
	EffectiveUpMbps     float64  `json:"effective_up_mbps"`
	EffectiveDownKbps   int      `json:"effective_down_kbps"`
	EffectiveUpKbps     int      `json:"effective_up_kbps"`
	WinningSource       string   `json:"winning_source,omitempty"`
	ThrottleSources     []string `json:"throttle_sources"`
	ActiveLimiterReason string   `json:"active_limiter_reason"`
	EvalTotal           uint64   `json:"eval_total"`
	ApplyTotal          uint64   `json:"apply_total"`
	FloorClamps         uint64   `json:"floor_clamps"`
	RecoverySteps       uint64   `json:"recovery_steps"`
	UpdatedAt           int64    `json:"updated_at"`
}

// RootShaperArbiter 统一根类 1:1 速率仲裁器。
// 严格遵守 32 位 ARM 对齐铁律: 所有 64 位原子字段位于 offset 0..39。
type RootShaperArbiter struct {
	evalTotal     atomic.Uint64
	applyTotal    atomic.Uint64
	floorClamps   atomic.Uint64
	recoverySteps atomic.Uint64
	lastApplyUnix atomic.Int64

	srv *server
	mu  sync.Mutex

	// 输入 1: 用户静态基准 (唯一允许落盘 rules.json 的值)
	staticLoaded  bool
	staticEnabled bool
	staticDown    float64
	staticUp      float64

	// 输入 2: 5G Autorate 动态上限
	autorateExplicit bool
	autorateActive   bool
	autorateDown     float64
	autorateUp       float64

	// 输入 3: ThermoCruise Stage 2 温控软顶与平滑回升状态
	thermoStage2Active  bool
	thermoRecovering    bool
	thermoRecoveryRound int
	thermoTempC         float64
	thermoCurDown       float64
	thermoCurUp         float64

	// 最近一次计算与实际下发缓存
	lastSnap         ArbiterSnapshot
	appliedActive    bool
	appliedIface     string
	appliedDownKbps  int
	appliedUpKbps    int
	applyHook        func(iface string, active bool, downKbps, upKbps int, prevActive bool) error
	expressNotifyFn  func(downKbps, upKbps int)
}

var rootShaperArbiterRegistry sync.Map // map[*server]*RootShaperArbiter

func init() {
	RegisterServerVectorSyncProvider("arbiter", func(s *server) any {
		if s == nil {
			return ArbiterSnapshot{
				FloorDownMbps:   ArbiterAutoFloorDownMbps,
				FloorUpMbps:     ArbiterAutoFloorUpMbps,
				ThrottleSources: []string{},
			}
		}
		return s.shaperArbiter().Snapshot()
	})
}

func newRootShaperArbiter(s *server) *RootShaperArbiter {
	arb := &RootShaperArbiter{
		srv: s,
		lastSnap: ArbiterSnapshot{
			FloorDownMbps:   ArbiterAutoFloorDownMbps,
			FloorUpMbps:     ArbiterAutoFloorUpMbps,
			ThrottleSources: []string{},
		},
	}
	arb.mu.Lock()
	arb.reloadStaticFromDiskLocked()
	arb.recomputeLocked(time.Now(), "")
	arb.mu.Unlock()
	return arb
}

func (s *server) shaperArbiter() *RootShaperArbiter {
	if s == nil {
		return nil
	}
	if v, ok := rootShaperArbiterRegistry.Load(s); ok {
		return v.(*RootShaperArbiter)
	}
	created := newRootShaperArbiter(s)
	actual, _ := rootShaperArbiterRegistry.LoadOrStore(s, created)
	return actual.(*RootShaperArbiter)
}

func bpsToMbpsFloat(bps int64) float64 {
	if bps <= 0 {
		return 0
	}
	return round2((float64(bps) * 8.0) / 1_000_000.0)
}

func tcRateStrToMbps(rate string) float64 {
	bps := parseTcRateToBps(strings.TrimSpace(rate))
	return bpsToMbpsFloat(bps)
}

func fmtArbiterMbps(v float64) string {
	if v <= 0 {
		return "0"
	}
	rounded := math.Round(v)
	if math.Abs(v-rounded) < 0.05 {
		return fmt.Sprintf("%.0f", rounded)
	}
	return fmt.Sprintf("%.1f", v)
}

func (a *RootShaperArbiter) reloadStaticFromDiskLocked() {
	if a == nil || a.srv == nil || a.srv.hncDir == "" {
		return
	}
	var downBps, upBps int64
	if a.srv.jsonCache != nil {
		downBps, upBps = a.srv.readStaticGlobalShaperBps()
	} else {
		downBps, upBps = readStaticShaperDiskBps(a.srv.hncDir)
	}
	if downBps > 0 || upBps > 0 {
		a.staticEnabled = true
		a.staticDown = bpsToMbpsFloat(downBps)
		a.staticUp = bpsToMbpsFloat(upBps)
	} else {
		a.staticEnabled = false
		a.staticDown = 0
		a.staticUp = 0
	}
	a.staticLoaded = true
}

func (a *RootShaperArbiter) syncPassiveInputsLocked() {
	if a == nil || a.srv == nil {
		return
	}
	// 同步 rules.json 最新静态基准 (支持测试直接写 rules.json 文件的场景)
	a.reloadStaticFromDiskLocked()

	if a.autorateExplicit {
		if a.srv.autorate != nil {
			ar := a.srv.autorate.Snapshot()
			if ar.Enabled && ar.State != "disabled" && ar.SleepReason != "hotspot_off" && (ar.CurDownMbps > 0 || ar.CurUpMbps > 0) {
				a.autorateActive = true
				a.autorateDown = ar.CurDownMbps
				a.autorateUp = ar.CurUpMbps
			}
		}
		return
	}

	// 若未通过 UpdateAutorate 显式推送, 被动同步 server.autorate 或 run/autorate.json
	if a.srv.autorate != nil {
		ar := a.srv.autorate.Snapshot()
		if ar.Enabled && ar.State != "disabled" && ar.SleepReason != "hotspot_off" {
			if ar.CurDownMbps > 0 || ar.CurUpMbps > 0 {
				a.autorateActive = true
				a.autorateDown = ar.CurDownMbps
				a.autorateUp = ar.CurUpMbps
			}
			return
		}
	}
	if a.srv.hncDir != "" {
		if dMbps, uMbps := readAutorateDiskCurMbps(a.srv.hncDir); dMbps > 0 || uMbps > 0 {
			a.autorateActive = true
			a.autorateDown = dMbps
			a.autorateUp = uMbps
			return
		}
	}
	if a.srv.autorate != nil && !a.srv.autorate.Snapshot().Enabled {
		a.autorateActive = false
		a.autorateDown = 0
		a.autorateUp = 0
	}
}

func (a *RootShaperArbiter) computeThermoStage2TargetLocked() (downMbps, upMbps float64) {
	if a.staticEnabled && a.staticDown > 0 {
		downMbps = round2(a.staticDown * ThermoStage2StaticRatio)
	} else {
		downMbps = ThermoStage2SoftCapDownMbps
	}
	if a.staticEnabled && a.staticUp > 0 {
		upMbps = round2(a.staticUp * ThermoStage2StaticRatio)
	} else {
		upMbps = ThermoStage2SoftCapUpMbps
	}
	if downMbps < ArbiterAutoFloorDownMbps {
		downMbps = ArbiterAutoFloorDownMbps
	}
	if upMbps < ArbiterAutoFloorUpMbps {
		upMbps = ArbiterAutoFloorUpMbps
	}
	return downMbps, upMbps
}

func (a *RootShaperArbiter) thermoReleaseTargetsLocked() (relDown, relUp float64) {
	relDown = thermoUnboundReleaseDownMbps
	if a.staticEnabled && a.staticDown > 0 {
		relDown = a.staticDown
	} else if a.autorateActive && a.autorateDown > ThermoStage2SoftCapDownMbps {
		relDown = a.autorateDown
	}
	relUp = thermoUnboundReleaseUpMbps
	if a.staticEnabled && a.staticUp > 0 {
		relUp = a.staticUp
	} else if a.autorateActive && a.autorateUp > ThermoStage2SoftCapUpMbps {
		relUp = a.autorateUp
	}
	return relDown, relUp
}

// recomputeLocked 纯内存仲裁计算 (绝不执行外部命令)。
func (a *RootShaperArbiter) recomputeLocked(now time.Time, ifaceHint string) ArbiterSnapshot {
	if now.IsZero() {
		now = time.Now()
	}
	a.evalTotal.Add(1)

	iface := strings.TrimSpace(ifaceHint)
	if iface == "" && a.srv != nil && a.srv.hncDir != "" {
		iface = a.srv.currentHotspotIface()
	}
	hotspotActive := iface != ""
	if a.srv != nil && a.srv.simActive() {
		hotspotActive = true
	}

	var (
		candDown      float64
		candUp        float64
		winningSource string
		floorClamped  bool
	)

	mergeDown := func(val float64, src string) {
		if val <= 0 {
			return
		}
		if candDown <= 0 || val < candDown {
			candDown = val
			winningSource = src
		}
	}
	mergeUp := func(val float64, src string) {
		if val <= 0 {
			return
		}
		if candUp <= 0 || val < candUp {
			candUp = val
			if winningSource == "" {
				winningSource = src
			}
		}
	}

	hasThermo := a.thermoStage2Active || a.thermoRecovering
	hasAutorate := a.autorateActive && (a.autorateDown > 0 || a.autorateUp > 0)
	hasStatic := a.staticEnabled && (a.staticDown > 0 || a.staticUp > 0)

	var arEffDown, arEffUp float64
	if hasAutorate {
		if a.autorateDown > 0 {
			arEffDown = a.autorateDown
			if arEffDown < ArbiterAutoFloorDownMbps {
				arEffDown = ArbiterAutoFloorDownMbps
				floorClamped = true
			}
		}
		if a.autorateUp > 0 {
			arEffUp = a.autorateUp
			if arEffUp < ArbiterAutoFloorUpMbps {
				arEffUp = ArbiterAutoFloorUpMbps
				floorClamped = true
			}
		}
	}

	var thEffDown, thEffUp float64
	if hasThermo {
		thEffDown = a.thermoCurDown
		thEffUp = a.thermoCurUp
		if thEffDown > 0 && thEffDown < ArbiterAutoFloorDownMbps {
			thEffDown = ArbiterAutoFloorDownMbps
			floorClamped = true
		}
		if thEffUp > 0 && thEffUp < ArbiterAutoFloorUpMbps {
			thEffUp = ArbiterAutoFloorUpMbps
			floorClamped = true
		}
	}

	// 若静态基准开启且用户手动设在 5/2 Mbps 以上, 但 60% 温控折算触发了 5/2 地板, 同样标记 floorClamped
	if a.thermoStage2Active {
		if a.staticEnabled && a.staticDown >= ArbiterAutoFloorDownMbps && a.staticDown*ThermoStage2StaticRatio < ArbiterAutoFloorDownMbps {
			floorClamped = true
		}
		if a.staticEnabled && a.staticUp >= ArbiterAutoFloorUpMbps && a.staticUp*ThermoStage2StaticRatio < ArbiterAutoFloorUpMbps {
			floorClamped = true
		}
	}
	if floorClamped {
		a.floorClamps.Add(1)
	}

	// 按优先级合并上限: 相等时优先归因自动控速源 (thermo_stage2 -> autorate -> static_shaper)
	if hasThermo {
		mergeDown(thEffDown, "thermo_stage2")
		mergeUp(thEffUp, "thermo_stage2")
	}
	if hasAutorate {
		mergeDown(arEffDown, "autorate")
		mergeUp(arEffUp, "autorate")
	}
	if hasStatic {
		// 仅当用户手动设得更低 (含低于 5/2 Mbps 地板的用户显式意图) 时由静态基准胜出
		mergeDown(a.staticDown, "static_shaper")
		mergeUp(a.staticUp, "static_shaper")
	}

	sources := make([]string, 0, 3)
	addSource := func(s string) {
		if s == "" {
			return
		}
		for _, ex := range sources {
			if ex == s {
				return
			}
		}
		sources = append(sources, s)
	}
	if winningSource != "" {
		addSource(winningSource)
	}
	if hasThermo {
		addSource("thermo_stage2")
	}
	if hasAutorate {
		addSource("autorate")
	}
	if hasStatic {
		addSource("static_shaper")
	}

	var effDownKbps, effUpKbps int
	if candDown > 0 {
		effDownKbps = int(math.Round(candDown * 1000.0))
		if effDownKbps < minRateKbit {
			effDownKbps = minRateKbit
		}
	}
	if candUp > 0 {
		effUpKbps = int(math.Round(candUp * 1000.0))
		if effUpKbps < minRateKbit {
			effUpKbps = minRateKbit
		}
	}

	reason := buildArbiterLimiterReason(
		winningSource,
		hasThermo, a.thermoStage2Active, a.thermoRecovering, a.thermoTempC,
		hasAutorate, hasStatic,
		candDown, candUp,
	)

	snap := ArbiterSnapshot{
		HotspotActive:       hotspotActive,
		HotspotIface:        iface,
		StaticEnabled:       a.staticEnabled,
		StaticDownMbps:      round2(a.staticDown),
		StaticUpMbps:        round2(a.staticUp),
		AutorateActive:      hasAutorate,
		AutorateRawDownMbps: round2(a.autorateDown),
		AutorateRawUpMbps:   round2(a.autorateUp),
		ThermoStage2Active:  a.thermoStage2Active,
		ThermoRecovering:    a.thermoRecovering,
		ThermoTempC:         math.Round(a.thermoTempC*10) / 10,
		ThermoCapDownMbps:   round2(thEffDown),
		ThermoCapUpMbps:     round2(thEffUp),
		FloorClamped:        floorClamped,
		FloorDownMbps:       ArbiterAutoFloorDownMbps,
		FloorUpMbps:         ArbiterAutoFloorUpMbps,
		EffectiveDownMbps:   round2(candDown),
		EffectiveUpMbps:     round2(candUp),
		EffectiveDownKbps:   effDownKbps,
		EffectiveUpKbps:     effUpKbps,
		WinningSource:       winningSource,
		ThrottleSources:     sources,
		ActiveLimiterReason: reason,
		EvalTotal:           a.evalTotal.Load(),
		ApplyTotal:          a.applyTotal.Load(),
		FloorClamps:         a.floorClamps.Load(),
		RecoverySteps:       a.recoverySteps.Load(),
		UpdatedAt:           now.Unix(),
	}
	a.lastSnap = snap
	return snap
}

func buildArbiterLimiterReason(
	winner string,
	hasThermo, thermoStage2, thermoRecovering bool, tempC float64,
	hasAutorate, hasStatic bool,
	effDown, effUp float64,
) string {
	if winner == "" || (effDown <= 0 && effUp <= 0) {
		return ""
	}
	capText := fmt.Sprintf("当前总上限 %s Mbps", fmtArbiterMbps(effDown))
	if effDown <= 0 && effUp > 0 {
		capText = fmt.Sprintf("当前上行上限 %s Mbps", fmtArbiterMbps(effUp))
	}

	switch winner {
	case "thermo_stage2":
		if thermoRecovering && !thermoStage2 {
			return fmt.Sprintf("电芯 %.1f°C 降温平滑恢复中（%s）", tempC, capText)
		}
		if hasAutorate {
			return fmt.Sprintf("电芯 %.1f°C 温控巡航保护中（叠加 5G 自适应，%s）", tempC, capText)
		}
		return fmt.Sprintf("电芯 %.1f°C 温控巡航保护中（%s）", tempC, capText)
	case "autorate":
		if hasThermo {
			return fmt.Sprintf("5G 信号抖动自适应控速中（叠加温控保护，%s）", capText)
		}
		return fmt.Sprintf("5G 信号抖动自适应控速中（%s）", capText)
	case "static_shaper":
		_ = hasStatic
		return fmt.Sprintf("手动全局总限速生效中（%s）", capText)
	default:
		return ""
	}
}

// SetStaticBaseline 更新用户手动静态总限速基准并立即仲裁下发 (不修改 autorate/thermo 状态)。
func (a *RootShaperArbiter) SetStaticBaseline(now time.Time, iface string, enabled bool, downMbps, upMbps float64, strictApply bool) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	a.staticLoaded = true
	a.staticEnabled = enabled && (downMbps > 0 || upMbps > 0)
	if a.staticEnabled {
		a.staticDown = round2(downMbps)
		a.staticUp = round2(upMbps)
	} else {
		a.staticDown = 0
		a.staticUp = 0
	}
	// 若当前处于温控二阶激活态, 立即按新静态基准重算 60% 温控目标
	if a.thermoStage2Active {
		a.thermoCurDown, a.thermoCurUp = a.computeThermoStage2TargetLocked()
	}
	snap := a.recomputeLocked(now, iface)
	a.mu.Unlock()

	return a.applyArbitratedState(snap, false, strictApply)
}

// UpdateAutorate 更新 5G Autorate 动态速率输入并仲裁下发。
func (a *RootShaperArbiter) UpdateAutorate(now time.Time, iface string, active bool, downMbps, upMbps float64, strictApply bool) (ArbiterSnapshot, error) {
	if a == nil {
		return ArbiterSnapshot{ThrottleSources: []string{}}, nil
	}
	a.mu.Lock()
	a.reloadStaticFromDiskLocked()
	a.autorateExplicit = active && (downMbps > 0 || upMbps > 0)
	a.autorateActive = a.autorateExplicit
	if a.autorateActive {
		a.autorateDown = downMbps
		a.autorateUp = upMbps
	} else {
		a.autorateDown = 0
		a.autorateUp = 0
	}
	snap := a.recomputeLocked(now, iface)
	a.mu.Unlock()

	err := a.applyArbitratedState(snap, false, strictApply)
	return snap, err
}

// UpdateThermoStage2 接收 ThermoCruise 温度状态推进:
//   - immediateRelease=true (坏传感器熔断 / 热点关闭 / 温控关闭 / 无在线设备退出): 立即清除温控压速, 零残留;
//   - stage2Active=true: 进入或保持二阶温控软顶 (静态未开 40/15 Mbps, 静态已开 60% 基准, 保底 5/2 Mbps);
//   - stage2Active=false 且此前处于二阶或恢复中: 按每轮 +20% 平滑回升直至达到基准后彻底解除。
func (a *RootShaperArbiter) UpdateThermoStage2(now time.Time, stage2Active bool, tempC float64, immediateRelease bool) ArbiterSnapshot {
	if a == nil {
		return ArbiterSnapshot{ThrottleSources: []string{}}
	}
	a.mu.Lock()
	a.syncPassiveInputsLocked()
	prevHadThermo := a.thermoStage2Active || a.thermoRecovering
	a.thermoTempC = tempC

	switch {
	case immediateRelease:
		a.thermoStage2Active = false
		a.thermoRecovering = false
		a.thermoRecoveryRound = 0
		a.thermoCurDown = 0
		a.thermoCurUp = 0

	case stage2Active:
		targetDown, targetUp := a.computeThermoStage2TargetLocked()
		a.thermoStage2Active = true
		a.thermoRecovering = false
		a.thermoRecoveryRound = 0
		a.thermoCurDown = targetDown
		a.thermoCurUp = targetUp

	case a.thermoStage2Active || a.thermoRecovering:
		// 降温退出 Stage 2: 每轮 +20% 平滑回升直至追平目标上限后彻底解除!
		a.thermoStage2Active = false
		a.thermoRecoveryRound++
		a.recoverySteps.Add(1)
		nextDown := round2(a.thermoCurDown * ThermoRecoveryStepFactor)
		nextUp := round2(a.thermoCurUp * ThermoRecoveryStepFactor)
		relDown, relUp := a.thermoReleaseTargetsLocked()

		if a.thermoRecoveryRound >= thermoMaxRecoverySteps || (nextDown >= relDown && nextUp >= relUp) {
			a.thermoRecovering = false
			a.thermoRecoveryRound = 0
			a.thermoCurDown = 0
			a.thermoCurUp = 0
		} else {
			a.thermoRecovering = true
			if nextDown > relDown {
				nextDown = relDown
			}
			if nextUp > relUp {
				nextUp = relUp
			}
			a.thermoCurDown = nextDown
			a.thermoCurUp = nextUp
		}
	}

	nowHasThermo := a.thermoStage2Active || a.thermoRecovering
	snap := a.recomputeLocked(now, "")
	shouldApply := prevHadThermo || nowHasThermo
	a.mu.Unlock()

	if shouldApply {
		_ = a.applyArbitratedState(snap, false, false)
	}
	return snap
}

// ResetForHotspotOff 在热点关闭时复位动态控速状态并保留 rules.json 静态基准。
func (a *RootShaperArbiter) ResetForHotspotOff(now time.Time) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.thermoStage2Active = false
	a.thermoRecovering = false
	a.thermoRecoveryRound = 0
	a.thermoCurDown = 0
	a.thermoCurUp = 0
	a.autorateExplicit = false
	a.autorateActive = false
	a.autorateDown = 0
	a.autorateUp = 0
	a.appliedActive = false
	a.appliedIface = ""
	a.appliedDownKbps = 0
	a.appliedUpKbps = 0
	a.reloadStaticFromDiskLocked()
	a.recomputeLocked(now, "")
	a.mu.Unlock()
}

// Snapshot 返回最新仲裁状态快照 (同步被动配置变更, 零子进程阻塞)。
func (a *RootShaperArbiter) Snapshot() ArbiterSnapshot {
	if a == nil {
		return ArbiterSnapshot{
			FloorDownMbps:   ArbiterAutoFloorDownMbps,
			FloorUpMbps:     ArbiterAutoFloorUpMbps,
			ThrottleSources: []string{},
		}
	}
	a.mu.Lock()
	a.syncPassiveInputsLocked()
	snap := a.recomputeLocked(time.Now(), "")
	cp := snap
	cp.ThrottleSources = append([]string(nil), snap.ThrottleSources...)
	if cp.ThrottleSources == nil {
		cp.ThrottleSources = []string{}
	}
	a.mu.Unlock()
	return cp
}

// EffectiveRateKbps 返回当前仲裁生效的根类 1:1 上限 (kbps, 0 表示该方向未限速)。
func (a *RootShaperArbiter) EffectiveRateKbps() (downKbps, upKbps int) {
	if a == nil {
		return 0, 0
	}
	snap := a.Snapshot()
	return snap.EffectiveDownKbps, snap.EffectiveUpKbps
}

// IsThermoRecovering 纯内存零 IO 查询当前仲裁器是否处于温控降温爬坡恢复期。
func (a *RootShaperArbiter) IsThermoRecovering() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	recovering := a.thermoRecovering
	a.mu.Unlock()
	return recovering
}

// ReplayAfterRestore 在 NativeFullRestoreV6 重建 tc 树后强制重放当前仲裁器生效上限(含 0 总带宽复位旧 1:1)。
func (a *RootShaperArbiter) ReplayAfterRestore(now time.Time, iface string) ArbiterSnapshot {
	if a == nil {
		return ArbiterSnapshot{ThrottleSources: []string{}}
	}
	a.mu.Lock()
	a.syncPassiveInputsLocked()
	prevActive := a.appliedActive
	snap := a.recomputeLocked(now, iface)
	a.mu.Unlock()

	if snap.EffectiveDownKbps > 0 || snap.EffectiveUpKbps > 0 || prevActive {
		_ = a.applyArbitratedState(snap, true, false)
	}
	return snap
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (a *RootShaperArbiter) applyArbitratedState(snap ArbiterSnapshot, force bool, strictInitial bool) error {
	if a == nil {
		return nil
	}
	iface := strings.TrimSpace(snap.HotspotIface)
	wantActive := snap.EffectiveDownKbps > 0 || snap.EffectiveUpKbps > 0

	a.mu.Lock()
	prevActive := a.appliedActive
	prevIface := a.appliedIface
	prevDown := a.appliedDownKbps
	prevUp := a.appliedUpKbps
	hook := a.applyHook
	notifyFn := a.expressNotifyFn
	a.mu.Unlock()

	if iface == "" && prevIface != "" && !wantActive {
		iface = prevIface
	}
	if iface == "" {
		return nil
	}

	deadbandDown := int(math.Max(200, float64(prevDown)*arbiterTuneDeadbandRatio))
	deadbandUp := int(math.Max(150, float64(prevUp)*arbiterTuneDeadbandRatio))
	changed := force ||
		strictInitial ||
		wantActive != prevActive ||
		(wantActive && prevIface != iface) ||
		absInt(snap.EffectiveDownKbps-prevDown) >= deadbandDown ||
		absInt(snap.EffectiveUpKbps-prevUp) >= deadbandUp

	if !changed {
		return nil
	}

	hncDir := ""
	if a.srv != nil {
		hncDir = a.srv.hncDir
	}

	var applyErr error
	if hook != nil {
		applyErr = hook(iface, wantActive, snap.EffectiveDownKbps, snap.EffectiveUpKbps, prevActive)
	} else if hncDir != "" {
		applyErr = executeRootShaperDataplane(hncDir, iface, wantActive, snap.EffectiveDownKbps, snap.EffectiveUpKbps, prevActive, strictInitial)
	}

	if applyErr != nil {
		return applyErr
	}

	nowUnix := time.Now().Unix()
	a.applyTotal.Add(1)
	a.lastApplyUnix.Store(nowUnix)

	a.mu.Lock()
	a.appliedActive = wantActive
	if wantActive {
		a.appliedIface = iface
		a.appliedDownKbps = snap.EffectiveDownKbps
		a.appliedUpKbps = snap.EffectiveUpKbps
	} else {
		a.appliedIface = ""
		a.appliedDownKbps = 0
		a.appliedUpKbps = 0
	}
	a.lastSnap.ApplyTotal = a.applyTotal.Load()
	a.mu.Unlock()

	// 根速率发生变更时通知 VectorExpress 动态重算同步 1:8010 与默认类 1:9999 保障带宽
	if notifyFn != nil {
		notifyFn(snap.EffectiveDownKbps, snap.EffectiveUpKbps)
	} else if a.srv != nil {
		a.srv.notifyVectorExpressRootRateChanged(snap.EffectiveDownKbps, snap.EffectiveUpKbps)
	}
	return nil
}

func executeRootShaperDataplane(hncDir, iface string, active bool, downKbps, upKbps int, prevActive, preferFullSetup bool) error {
	if !active {
		InvalidateDataplaneReconcileNative(hncDir, "")
		if useNativeDataplane(hncDir) {
			// 原生模式将已建树口 1:1 复位回默认 1000Mbit 根速率并清零 shaperSpec, 严防 1000000 污染 Express 上行重放
			if err := ResetGlobalShaperNative(hncDir); err == nil {
				return nil
			}
		}
		if _, err := os.Stat(filepath.Join(hncDir, "bin", "tc_manager.sh")); err == nil {
			if rc, out := runBin(hncDir, "tc_manager.sh", "global_shaper", iface, "off", "0", "0"); rc != 0 {
				return fmt.Errorf("%s", strings.TrimSpace(out))
			}
		}
		return nil
	}

	downStr := "0"
	if downKbps > 0 {
		downStr = mbpsToTcRate(float64(downKbps) / 1000.0)
	}
	upStr := "0"
	if upKbps > 0 {
		upStr = mbpsToTcRate(float64(upKbps) / 1000.0)
	}

	// 若可走 Go 原生 Netlink 且 ifb0 已就绪(或无需初始化 IFB), 优先零子进程原地热更新 1:1
	needIFBInit := false
	if useNativeDataplane(hncDir) {
		nErr := TuneGlobalShaperNative(hncDir, downKbps, upKbps)
		if nErr == nil {
			return nil
		}
		if errors.Is(nErr, errGlobalShaperNeedIFBInit) {
			needIFBInit = true
		}
	}

	scriptPath := filepath.Join(hncDir, "bin", "tc_manager.sh")
	if _, err := os.Stat(scriptPath); err != nil {
		return nil
	}
	subCmd := "global_shaper_tune"
	if !prevActive || preferFullSetup || needIFBInit {
		subCmd = "global_shaper"
	}
	var rc int
	var out string
	if subCmd == "global_shaper" {
		rc, out = runBin(hncDir, "tc_manager.sh", "global_shaper", iface, "on", downStr, upStr)
		InvalidateDataplaneReconcileNative(hncDir, "")
	} else {
		rc, out = runBin(hncDir, "tc_manager.sh", "global_shaper_tune", iface, downStr, upStr)
	}
	if rc != 0 {
		log.Printf("arbiter: %s failed on %s: %s", subCmd, iface, strings.TrimSpace(out))
		return fmt.Errorf("%s", strings.TrimSpace(out))
	}
	return nil
}

func (s *server) replayRootShaperArbiterAfterRestore(iface string) {
	if s == nil {
		return
	}
	InvalidateDataplaneReconcileNative(s.hncDir, "")
	s.shaperArbiter().ReplayAfterRestore(time.Now(), iface)
}

func (s *server) notifyVectorExpressRootRateChanged(downKbps, upKbps int) {
	if s == nil {
		return
	}
	if v, ok := v6Registry.Load(s); ok {
		if vs, ok := v.(*v6ServerState); ok && vs != nil && vs.express != nil {
			vs.express.OnRootRateChanged(downKbps, upKbps)
		}
	}
}
