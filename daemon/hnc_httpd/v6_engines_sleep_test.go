package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func waitEngineCond(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(3 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for %s", desc)
	}
}

type mockActivityFeed struct {
	mu  sync.Mutex
	cur Activity
	ch  chan struct{}
}

func newMockActivityFeed(initAct Activity) *mockActivityFeed {
	initAct.Level = initAct.computeLevel()
	return &mockActivityFeed{
		cur: initAct,
		ch:  make(chan struct{}),
	}
}

func (f *mockActivityFeed) Read() (<-chan struct{}, Activity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ch, f.cur
}

func (f *mockActivityFeed) Set(next Activity) {
	next.Level = next.computeLevel()
	f.mu.Lock()
	f.cur = next
	old := f.ch
	f.ch = make(chan struct{})
	f.mu.Unlock()
	close(old)
}

// 1. 32 位 ARM 原子对齐硬门禁: 验证五大结构体顶部全部 64 位原子字段严格 8 字节对齐
func TestV6EnginesAndSignalAtomic64Alignment(t *testing.T) {
	var (
		zExp vectorExpressEngine
		zLsh updateLeashEngine
		zThm thermoCruiseEngine
		zJB  JitterBlackbox
		zSig signalMonitor
	)
	checks := []struct {
		name   string
		offset uintptr
	}{
		{"vectorExpressEngine.transitions", unsafe.Offsetof(zExp.transitions)},
		{"vectorExpressEngine.activeFlag", unsafe.Offsetof(zExp.activeFlag)},
		{"updateLeashEngine.leashedCount", unsafe.Offsetof(zLsh.leashedCount)},
		{"updateLeashEngine.totalSavedB", unsafe.Offsetof(zLsh.totalSavedB)},
		{"thermoCruiseEngine.evalCount", unsafe.Offsetof(zThm.evalCount)},
		{"thermoCruiseEngine.effectiveStage", unsafe.Offsetof(zThm.effectiveStage)},
		{"JitterBlackbox.totalTicks", unsafe.Offsetof(zJB.totalTicks)},
		{"JitterBlackbox.totalIncidents", unsafe.Offsetof(zJB.totalIncidents)},
		{"JitterBlackbox.lastTickUnixMs", unsafe.Offsetof(zJB.lastTickUnixMs)},
		{"JitterBlackbox.lastSpikeUnixMs", unsafe.Offsetof(zJB.lastSpikeUnixMs)},
		{"JitterBlackbox.latestJitterBits", unsafe.Offsetof(zJB.latestJitterBits)},
		{"signalMonitor.asyncRuns", unsafe.Offsetof(zSig.asyncRuns)},
		{"signalMonitor.asyncCoalesced", unsafe.Offsetof(zSig.asyncCoalesced)},
		{"signalMonitor.lastRefreshNs", unsafe.Offsetof(zSig.lastRefreshNs)},
	}
	if checks[0].offset != 0 || checks[2].offset != 0 || checks[4].offset != 0 || checks[6].offset != 0 || checks[11].offset != 0 {
		t.Fatalf("first 64-bit atomic field in every engine must sit at offset 0: %+v", checks)
	}
	for _, c := range checks {
		if c.offset%8 != 0 {
			t.Fatalf("32-bit GOARCH=arm hazard: %s offset=%d is not 8-byte aligned", c.name, c.offset)
		}
	}
}

// 2. VectorExpress 深度停表、熄屏有客户端防误停、原生优先双轨回退、HotspotOff 解限与 NoClients 一次性冷却释放
func TestV6VectorExpressSleepUnlimitAndDualTrackFallback(t *testing.T) {
	s, _, dir := newV6TestMux(t)
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)

	exp := s.v6State().express
	exp.pollInterval = 25 * time.Millisecond
	exp.holdDurOverride = 70 * time.Millisecond

	// 初始设为手机熄屏揣兜但开热点且有 1 台在线客户端 (lvlBackground): 严禁误停表!
	feed := newMockActivityFeed(Activity{
		Known:         true,
		ScreenKnown:   true,
		ScreenOn:      false,
		HotspotActive: true,
		HotspotIface:  "wlan2",
		ClientsOnline: 1,
		WebUIActive:   false,
	})
	exp.activityHook = feed.Read

	var sigMu sync.Mutex
	curSigs := []VectorExpressDeviceSignal{
		{MAC: "aa:bb:cc:dd:ee:01", TrafficType: ttGaming, Confidence: 0.92, FgAppName: "王者荣耀", ActiveDstIPs: 4},
	}
	var sampleCount atomic.Int64
	exp.signalHook = func(_ time.Time) []VectorExpressDeviceSignal {
		sampleCount.Add(1)
		sigMu.Lock()
		defer sigMu.Unlock()
		return append([]VectorExpressDeviceSignal(nil), curSigs...)
	}

	var dpMu sync.Mutex
	var nativeCalls []bool
	var fallbackCalls []string
	var invalidations int
	failNative := true

	exp.nativeApplyFn = func(_ string, enable bool, gameMark uint32, _ int) error {
		if gameMark != v6ExpressDefaultMark {
			t.Errorf("unexpected gameMark: 0x%x", gameMark)
		}
		dpMu.Lock()
		nativeCalls = append(nativeCalls, enable)
		shouldFail := failNative
		dpMu.Unlock()
		if shouldFail {
			return errors.New("simulated netlink failure")
		}
		return nil
	}
	exp.invalidateFn = func(_, _ string) {
		dpMu.Lock()
		invalidations++
		dpMu.Unlock()
	}
	exp.fallbackCmdFn = func(_, script string, args ...string) (int, string) {
		dpMu.Lock()
		fallbackCalls = append(fallbackCalls, script+" "+strings.Join(args, " "))
		dpMu.Unlock()
		return 0, ""
	}

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		exp.runLoop(stopCh)
	}()
	defer func() {
		select {
		case <-doneCh:
		default:
			close(stopCh)
			<-doneCh
		}
	}()

	// (a) 验证熄屏有客户端 lvlBackground 保持活跃巡检, 且原生失败时回退 tc_manager.sh vector_express wlan2 on 85
	waitEngineCond(t, 2*time.Second, "lvlBackground active escort & fallback on", func() bool {
		exp.WaitDataplaneIdle()
		dpMu.Lock()
		defer dpMu.Unlock()
		return exp.LoopMode() == v6EngineModeActive &&
			exp.isActive() &&
			sampleCount.Load() >= 2 &&
			len(fallbackCalls) >= 1 &&
			fallbackCalls[len(fallbackCalls)-1] == "tc_manager.sh vector_express wlan2 on 85"
	})

	// (b) 模拟热点已关闭(hnc_state 不再为 ACTIVE), 切入 HotspotOff:
	//     必须清空动态护航、复位 idle_fullspeed/activeFlag=0/BgPoolCeilPct=100,
	//     调 ApplyVectorExpressNative(false) + InvalidateDataplaneReconcileNative,
	//     并在原生失败时使用记住的 lastActiveIface="wlan2" 回退调 tc_manager.sh vector_express wlan2 off 100, 然后 0 唤醒停表!
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("INACTIVE\n"), 0o644)
	feed.Set(Activity{Known: true, HotspotActive: false, ClientsOnline: 0})

	waitEngineCond(t, 2*time.Second, "HotspotOff immediate unlimit and sleeping", func() bool {
		return exp.LoopMode() == v6EngineModeSleeping && !exp.isActive()
	})
	dpMu.Lock()
	gotInv := invalidations
	lastFB := ""
	if len(fallbackCalls) > 0 {
		lastFB = fallbackCalls[len(fallbackCalls)-1]
	}
	dpMu.Unlock()
	if gotInv < 1 || lastFB != "tc_manager.sh vector_express wlan2 off 100" {
		t.Fatalf("HotspotOff unlimit mismatch: invalidations=%d lastFallback=%q", gotInv, lastFB)
	}
	sumOff := exp.summary()
	if sumOff["state"] != expressStateIdle || sumOff["bg_ceil_pct"] != 100 {
		t.Fatalf("expected idle_fullspeed & bg_ceil_pct=100 on HotspotOff, got %+v", sumOff)
	}
	samplesAtSleep := sampleCount.Load()
	time.Sleep(70 * time.Millisecond)
	if got := sampleCount.Load(); got != samplesAtSleep {
		t.Fatalf("expected 0 wakeups during HotspotOff sleep, sampleCount grew %d -> %d", samplesAtSleep, got)
	}

	// (c) 恢复原生成功路径, 从休眠唤醒进入活跃态: 首拍立即同步巡检激活护航, 不再调回退脚本
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)
	dpMu.Lock()
	failNative = false
	fbBeforeResume := len(fallbackCalls)
	dpMu.Unlock()

	feed.Set(Activity{Known: true, HotspotActive: true, HotspotIface: "wlan2", ClientsOnline: 1})
	waitEngineCond(t, 2*time.Second, "immediate patrol upon wakeup", func() bool {
		exp.WaitDataplaneIdle()
		return exp.LoopMode() == v6EngineModeActive && exp.isActive() && sampleCount.Load() > samplesAtSleep
	})
	dpMu.Lock()
	if len(fallbackCalls) != fbBeforeResume {
		t.Fatalf("native apply succeeded, fallback script must not be called: %v", fallbackCalls)
	}
	dpMu.Unlock()

	// (d) 客户端断开切入 NoClients: 先挂一次性到期 Timer 保持 cooldown_hold, 到期自动解限后转入 0 唤醒休眠!
	sigMu.Lock()
	curSigs = nil
	sigMu.Unlock()
	feed.Set(Activity{Known: true, HotspotActive: true, HotspotIface: "wlan2", ClientsOnline: 0, WebUIActive: false})

	waitEngineCond(t, 2*time.Second, "NoClients cooldown release completes into 0-wake sleep", func() bool {
		return exp.LoopMode() == v6EngineModeSleeping && !exp.isActive() && exp.summary()["state"] == expressStateIdle
	})
	samplesNoClients := sampleCount.Load()
	time.Sleep(70 * time.Millisecond)
	if got := sampleCount.Load(); got != samplesNoClients {
		t.Fatalf("expected 0 wakeups in NoClients after cooldown release, got %d -> %d", samplesNoClients, got)
	}

	// (e) NoClients 下配置静态 ForcedMACs + Wake(): 静态同步一次后直接停表 0 唤醒, 绝不死循环!
	exp.mu.Lock()
	exp.cfg.ForcedMACs = []string{"aa:bb:cc:dd:ee:77"}
	exp.mu.Unlock()
	exp.Wake()

	waitEngineCond(t, 2*time.Second, "ForcedMACs static sync in NoClients then sleep", func() bool {
		return exp.isActive() && exp.LoopMode() == v6EngineModeSleeping
	})
	transAfterForced := exp.transitions.Load()
	time.Sleep(70 * time.Millisecond)
	if got := exp.transitions.Load(); got != transAfterForced {
		t.Fatalf("ForcedMACs in NoClients caused busy loop transitions: %d -> %d", transAfterForced, got)
	}
}

// 3. UpdateLeash 深度停表: HotspotOff 严格保留 pausedSet/conn_blocks 并移除动态会话, NoClients 一次性释放
func TestV6UpdateLeashSleepPreservesPausedAndOneShotRelease(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	leash := s.v6State().leash
	leash.pollInterval = 25 * time.Millisecond
	leash.idleExpire = 80 * time.Millisecond

	feed := newMockActivityFeed(Activity{
		Known:         true,
		ScreenKnown:   true,
		ScreenOn:      false, // lvlBackground: 熄屏有客户端必须继续巡检!
		HotspotActive: true,
		ClientsOnline: 1,
	})
	leash.activityHook = feed.Read

	const mb = 1024 * 1024
	var flowMu sync.Mutex
	curFlows := []UpdateFlowInput{{
		FlowKey:   "tcp|192.168.43.10|52000|13.107.4.50|443",
		MAC:       "aa:bb:cc:dd:ee:11",
		SrcIP:     "192.168.43.10",
		DstIP:     "13.107.4.50",
		DstHost:   "dl.delivery.mp.microsoft.com",
		Proto:     "tcp",
		UpBytes:   1 * mb,
		DownBytes: 240 * mb,
		DownBps:   30_000_000,
	}}
	var flowPolls atomic.Int64
	leash.flowsHook = func() []UpdateFlowInput {
		flowPolls.Add(1)
		flowMu.Lock()
		defer flowMu.Unlock()
		return append([]UpdateFlowInput(nil), curFlows...)
	}

	var removeCalls atomic.Int64
	var invCalls atomic.Int64
	leash.removeNativeFn = func(_ string, _ uint32) error {
		removeCalls.Add(1)
		return nil
	}
	leash.invalidateFn = func(_, _ string) {
		invCalls.Add(1)
	}

	// 先通过 HTTP API 添加一条 pause_update 静态暂停规则 (落盘 conn_blocks.json + pausedSet)
	pauseRec := doV6JSONReq(t, mux, "POST", "/api/v6/update_leash",
		`{"action":"pause_update","mac":"aa:bb:cc:dd:ee:22","dst_host":"swcdn.apple.com"}`)
	if pauseRec.Code != 200 {
		t.Fatalf("pause_update failed: %d %s", pauseRec.Code, pauseRec.Body.String())
	}

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		leash.runLoop(stopCh)
	}()
	defer func() {
		select {
		case <-doneCh:
		default:
			close(stopCh)
			<-doneCh
		}
	}()

	// (a) 验证 lvlBackground 下正常巡检并将 240MB 更新流压制为 leashedCount=1
	waitEngineCond(t, 2*time.Second, "lvlBackground leashed session active", func() bool {
		return leash.LoopMode() == v6EngineModeActive && leash.leashedCount.Load() == 1
	})

	// (b) 切入 HotspotOff: 动态会话必须被删除, leashedCount 归 0, RemoveUpdateLeashNative + Invalidate 被调用,
	//     同时 pausedSet 与 conn_blocks.json 必须完好无损!
	feed.Set(Activity{Known: true, HotspotActive: false, ClientsOnline: 0})
	waitEngineCond(t, 2*time.Second, "HotspotOff unlimit & sleep", func() bool {
		return leash.LoopMode() == v6EngineModeSleeping && leash.leashedCount.Load() == 0
	})
	if removeCalls.Load() < 1 || invCalls.Load() < 1 {
		t.Fatalf("expected RemoveUpdateLeashNative and InvalidateDataplaneReconcileNative on HotspotOff, got rm=%d inv=%d",
			removeCalls.Load(), invCalls.Load())
	}
	leash.mu.Lock()
	pausedPreserved := leash.pausedSet["aa:bb:cc:dd:ee:22|swcdn.apple.com"]
	_, dynStillHere := leash.sessions["aa:bb:cc:dd:ee:11|dl.delivery.mp.microsoft.com"]
	leash.mu.Unlock()
	if !pausedPreserved || dynStillHere {
		t.Fatalf("HotspotOff session cleanup violated contract: pausedPreserved=%v dynStillHere=%v", pausedPreserved, dynStillHere)
	}
	cbBytes, err := os.ReadFile(filepath.Join(dir, "data", "conn_blocks.json"))
	if err != nil || !strings.Contains(string(cbBytes), "swcdn.apple.com") {
		t.Fatalf("HotspotOff must NEVER clear conn_blocks.json: err=%v body=%s", err, string(cbBytes))
	}
	activeBytes, _ := os.ReadFile(filepath.Join(dir, "run", "update_leash_active.json"))
	if !strings.Contains(string(activeBytes), `"leashed": []`) {
		t.Fatalf("expected empty leashed array persisted on HotspotOff, got %s", string(activeBytes))
	}
	pollsSleep := flowPolls.Load()
	time.Sleep(70 * time.Millisecond)
	if got := flowPolls.Load(); got != pollsSleep {
		t.Fatalf("expected 0 wakeups during HotspotOff, flowPolls %d -> %d", pollsSleep, got)
	}

	// (c) 恢复活跃重新产生 leashed 会话, 再切入 NoClients: 挂一次性到期 Timer 释放后进入 0 唤醒休眠!
	feed.Set(Activity{Known: true, HotspotActive: true, ClientsOnline: 1})
	waitEngineCond(t, 2*time.Second, "resume active leashed", func() bool {
		return leash.LoopMode() == v6EngineModeActive && leash.leashedCount.Load() == 1
	})

	flowMu.Lock()
	curFlows = nil
	flowMu.Unlock()
	rmBeforeNoClients := removeCalls.Load()
	feed.Set(Activity{Known: true, HotspotActive: true, ClientsOnline: 0, WebUIActive: false})

	waitEngineCond(t, 2*time.Second, "NoClients one-shot timer expires leashed session and sleeps", func() bool {
		return leash.LoopMode() == v6EngineModeSleeping &&
			leash.leashedCount.Load() == 0 &&
			removeCalls.Load() > rmBeforeNoClients
	})
	pollsAfterRelease := flowPolls.Load()
	time.Sleep(70 * time.Millisecond)
	if got := flowPolls.Load(); got != pollsAfterRelease {
		t.Fatalf("expected 0 wakeups in NoClients after release, got %d -> %d", pollsAfterRelease, got)
	}
}

// 4. ThermoCruise 深度停表: HotspotOff 归零落盘、NoClients 纯低电态直接 0 唤醒、高温冷却一次性 Timer 退档休眠
func TestV6ThermoCruiseSleepLowBatZeroWakeAndCooldownTimer(t *testing.T) {
	s, _, dir := newV6TestMux(t)
	th := s.v6State().thermo
	th.pollInterval = 25 * time.Millisecond
	th.coolHoldDur = 75 * time.Millisecond

	feed := newMockActivityFeed(Activity{Known: true, HotspotActive: true, ClientsOnline: 1})
	th.activityHook = feed.Read

	var batMu sync.Mutex
	curBat := ThermoBatteryReading{
		Available:   true,
		SupplyNode:  "battery",
		TempC:       46.2, // Stage 2 高温
		CapacityPct: 65,
		Status:      "Discharging",
	}
	var batReads atomic.Int64
	th.batteryReadHook = func() ThermoBatteryReading {
		batReads.Add(1)
		batMu.Lock()
		defer batMu.Unlock()
		return curBat
	}

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		th.runLoop(stopCh)
	}()
	defer func() {
		select {
		case <-doneCh:
		default:
			close(stopCh)
			<-doneCh
		}
	}()

	// (a) 活跃态立即进入 Stage 2
	waitEngineCond(t, 2*time.Second, "Thermo active stage 2", func() bool {
		return th.LoopMode() == v6EngineModeActive && th.effectiveStage.Load() == 2
	})

	// (b) HotspotOff: 立即复位 rawThermalStage=0 / effectiveStage=0 并落盘归零 thermo_state.json, 随后 0 唤醒休眠
	feed.Set(Activity{Known: true, HotspotActive: false, ClientsOnline: 0})
	waitEngineCond(t, 2*time.Second, "Thermo HotspotOff reset & sleep", func() bool {
		return th.LoopMode() == v6EngineModeSleeping && th.effectiveStage.Load() == 0
	})
	stateBytes, err := os.ReadFile(filepath.Join(dir, "run", "thermo_state.json"))
	if err != nil || !strings.Contains(string(stateBytes), `"effective_stage": 0`) || !strings.Contains(string(stateBytes), `"raw_thermal_stage": 0`) {
		t.Fatalf("thermo_state.json not zeroed on HotspotOff: err=%v body=%s", err, string(stateBytes))
	}
	readsOff := batReads.Load()
	time.Sleep(70 * time.Millisecond)
	if got := batReads.Load(); got != readsOff {
		t.Fatalf("expected 0 sysfs reads during HotspotOff, got %d -> %d", readsOff, got)
	}

	// (c) 常温纯低电态 (37.5C, 12% 电量 => rawThermalStage=0, effectiveStage=1) 切入 NoClients: 直接停表 0 唤醒!
	batMu.Lock()
	curBat = ThermoBatteryReading{Available: true, SupplyNode: "battery", TempC: 37.5, CapacityPct: 12, Status: "Discharging"}
	batMu.Unlock()
	feed.Set(Activity{Known: true, HotspotActive: true, ClientsOnline: 1})
	waitEngineCond(t, 2*time.Second, "low battery cruise active", func() bool {
		qs := th.PeekQuickState()
		return th.LoopMode() == v6EngineModeActive && qs.RawThermalStage == 0 && qs.EffectiveStage == 1
	})

	feed.Set(Activity{Known: true, HotspotActive: true, ClientsOnline: 0, WebUIActive: false})
	waitEngineCond(t, 2*time.Second, "pure low-battery immediately sleeps on NoClients", func() bool {
		return th.LoopMode() == v6EngineModeSleeping
	})
	readsLowBat := batReads.Load()
	time.Sleep(75 * time.Millisecond)
	if got := batReads.Load(); got != readsLowBat {
		t.Fatalf("pure low-battery state (rawThermalStage==0) must have 0 wakeups in NoClients, got %d -> %d", readsLowBat, got)
	}

	// (d) 高温 Stage 2 后降温进入 NoClients: 挂一次性冷却 Timer 完成施密特退档回 Stage 0, 再进入 0 唤醒休眠!
	batMu.Lock()
	curBat = ThermoBatteryReading{Available: true, SupplyNode: "battery", TempC: 46.5, CapacityPct: 70, Status: "Discharging"}
	batMu.Unlock()
	feed.Set(Activity{Known: true, HotspotActive: true, ClientsOnline: 1})
	waitEngineCond(t, 2*time.Second, "re-enter stage 2", func() bool {
		return th.LoopMode() == v6EngineModeActive && th.PeekQuickState().RawThermalStage == 2
	})

	// 散热至 37.0C (同时低于 Stage2 退出线 42.0C 与 Stage1 退出线 39.0C) 并断开所有客户端
	batMu.Lock()
	curBat = ThermoBatteryReading{Available: true, SupplyNode: "battery", TempC: 37.0, CapacityPct: 70, Status: "Discharging"}
	batMu.Unlock()
	feed.Set(Activity{Known: true, HotspotActive: true, ClientsOnline: 0, WebUIActive: false})

	waitEngineCond(t, 2*time.Second, "NoClients cooldown timer exits to stage 0 and sleeps", func() bool {
		return th.LoopMode() == v6EngineModeSleeping && th.PeekQuickState().RawThermalStage == 0 && th.effectiveStage.Load() == 0
	})
	readsCool := batReads.Load()
	time.Sleep(75 * time.Millisecond)
	if got := batReads.Load(); got != readsCool {
		t.Fatalf("expected 0 wakeups after Thermo NoClients cooldown completed, got %d -> %d", readsCool, got)
	}
}

// 5. 黑匣子四维大白话归因、30KB/s 游戏免冤枉铁律、复合故障优先级、静态整形兜底与最近 5 条摘要
func TestV6BlackboxFourDimAttributionPriorityAndGameProtection(t *testing.T) {
	globalJitterBlackbox.Clear()
	t.Cleanup(globalJitterBlackbox.Clear)

	jb := NewJitterBlackbox(32, 16)
	t0 := time.Unix(1800100000, 0)

	gameDev := BlackboxDeviceSample{
		MAC:           "aa:bb:cc:00:00:01",
		IP:            "192.168.43.10",
		Name:          "小王的手机",
		RxBps:         20_000, // 20 KB/s
		TxBps:         10_000, // 10 KB/s (合计仅 30 KB/s, 唯一在线设备 sharePct=100%)
		ActiveAppID:   "honor_of_kings",
		ActiveAppName: "王者荣耀",
	}

	// (1) 纯基站抖动 (cell_jitter): 只有 30KB/s 游戏设备在线, 严禁冤枉成抢网元凶 (CulpritIsHog=false)!
	_, incCell := jb.RecordSample(BlackboxTickInput{
		Now:             t0,
		RTTMs:           138.0,
		BaseRTTMs:       24.0,
		CapacityBps:     12_500_000,
		UpCapacityBps:   3_750_000,
		SignalAvailable: true,
		SignalMode:      "cellular",
		SignalQuality:   "weak",
		SignalRSRPdBm:   -113,
		Devices:         []BlackboxDeviceSample{gameDev},
	})
	if incCell == nil || incCell.CauseDim != BlackboxDimCellJitter || incCell.CauseLabelZh != "基站抖动" {
		t.Fatalf("expected cell_jitter attribution, got %+v", incCell)
	}
	if incCell.CulpritIsHog {
		t.Fatalf("30KB/s gaming device MUST NOT be flagged as CulpritIsHog on cell_jitter: %+v", incCell)
	}
	if incCell.VerdictZh == "" || incCell.RootCauseZh == "" {
		t.Fatalf("missing plain Chinese verdict/root_cause: %+v", incCell)
	}

	// (2) 纯发热降速 (thermal_throttle): 46.5C 二阶温控激活 + 30KB/s 游戏设备, 同样强制 CulpritIsHog=false!
	_, incTherm := jb.RecordSample(BlackboxTickInput{
		Now:             t0.Add(2 * time.Second),
		RTTMs:           96.0,
		BaseRTTMs:       24.0,
		CapacityBps:     12_500_000,
		UpCapacityBps:   3_750_000,
		ThermalStage:    2,
		ThermalShaperOn: true,
		TempC:           46.5,
		Devices:         []BlackboxDeviceSample{gameDev},
	})
	if incTherm == nil || incTherm.CauseDim != BlackboxDimThermalThrottle || incTherm.CauseLabelZh != "发热降速" {
		t.Fatalf("expected thermal_throttle attribution, got %+v", incTherm)
	}
	if incTherm.CulpritIsHog {
		t.Fatalf("30KB/s gaming device MUST NOT be flagged as CulpritIsHog on thermal_throttle: %+v", incTherm)
	}

	// (3) 上行占满 (uplink_saturated): 设备 A 看视频下行 3MB/s 未满(100Mbps 下行池), 设备 B 云盘上传 2.3MB/s 打满 20Mbps(2.5MB/s) 上行池!
	_, incUp := jb.RecordSample(BlackboxTickInput{
		Now:           t0.Add(4 * time.Second),
		RTTMs:         112.0,
		BaseRTTMs:     22.0,
		CapacityBps:   12_500_000, // 100 Mbps 下行
		UpCapacityBps: 2_500_000,  // 20 Mbps 上行
		Devices: []BlackboxDeviceSample{
			{MAC: "aa:bb:cc:00:00:02", Name: "客厅电视", RxBps: 3_000_000, TxBps: 40_000, ActiveAppName: "哔哩哔哩"},
			{MAC: "aa:bb:cc:00:00:03", Name: "办公笔记本", RxBps: 60_000, TxBps: 2_300_000, ActiveAppName: "百度网盘"},
		},
	})
	if incUp == nil || incUp.CauseDim != BlackboxDimUplinkSaturated || incUp.CauseLabelZh != "上行占满" {
		t.Fatalf("expected uplink_saturated attribution, got %+v", incUp)
	}
	if !incUp.CulpritIsHog || incUp.CulpritMAC != "aa:bb:cc:00:00:03" || incUp.UpUtilPct < 90.0 {
		t.Fatalf("expected top uploader pinned with CulpritIsHog=true & UpUtilPct>=90, got %+v", incUp)
	}

	// (4) 设备抢网 (device_hog): 平板狂下 11.5MB/s 跑满 100Mbps 下行池
	_, incHog := jb.RecordSample(BlackboxTickInput{
		Now:           t0.Add(6 * time.Second),
		RTTMs:         105.0,
		BaseRTTMs:     22.0,
		CapacityBps:   12_500_000,
		UpCapacityBps: 3_750_000,
		Devices: []BlackboxDeviceSample{
			gameDev,
			{MAC: "aa:bb:cc:00:00:09", Name: "室友平板", RxBps: 11_500_000, TxBps: 180_000, ActiveAppName: "Steam"},
		},
	})
	if incHog == nil || incHog.CauseDim != BlackboxDimDeviceHog || incHog.CauseLabelZh != "设备抢网" || !incHog.CulpritIsHog {
		t.Fatalf("expected device_hog with CulpritIsHog=true, got %+v", incHog)
	}

	// (5) 四维全开复合优先级验证: 发热降速 > 上行占满 > 设备抢网 > 基站抖动
	_, incCombo := jb.RecordSample(BlackboxTickInput{
		Now:             t0.Add(8 * time.Second),
		RTTMs:           160.0,
		BaseRTTMs:       22.0,
		CapacityBps:     12_500_000,
		UpCapacityBps:   2_500_000,
		ThermalStage:    2,
		ThermalShaperOn: true,
		TempC:           47.0,
		SignalAvailable: true,
		SignalMode:      "cellular",
		SignalQuality:   "weak",
		SignalRSRPdBm:   -114,
		Devices: []BlackboxDeviceSample{
			{MAC: "aa:bb:cc:00:00:09", Name: "全满载主机", RxBps: 11_600_000, TxBps: 2_350_000, ActiveAppName: "迅雷"},
		},
	})
	if incCombo == nil || incCombo.CauseDim != BlackboxDimThermalThrottle {
		t.Fatalf("expected thermal_throttle as primary cause, got %+v", incCombo)
	}
	wantSec := []string{BlackboxDimUplinkSaturated, BlackboxDimDeviceHog, BlackboxDimCellJitter}
	if !reflect.DeepEqual(incCombo.SecondaryDims, wantSec) {
		t.Fatalf("secondary_dims=%v want %v", incCombo.SecondaryDims, wantSec)
	}

	// (6) 验证 server.SampleBlackboxOnce 的静态 global_shaper_* 兜底采集及 v6ScreenshotPackSummary 最近 5 条 incidents
	s, _, dir := newV6TestMux(t)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{
		"version": 1,
		"global_shaper_enabled": true,
		"global_shaper_down": "80mbit",
		"global_shaper_up": "16mbit",
		"devices": {}
	}`), 0o600)
	s.rateMu.Lock()
	s.rates["aa:bb:cc:00:00:55"] = rateOut{rxBps: 200_000, txBps: 1_900_000} // 15.2 Mbps 上行 -> 占 16mbit 的 95%!
	s.rateMu.Unlock()

	baseSampleTs := time.Now().Add(-10 * time.Second)
	for i := 0; i < 6; i++ {
		s.SampleBlackboxOnce(baseSampleTs.Add(time.Duration(i*1500) * time.Millisecond))
	}
	pack := s.v6ScreenshotPackSummary()
	bbMap, _ := pack["blackbox"].(map[string]any)
	recent, ok := bbMap["incidents"].([]BlackboxIncident)
	if !ok || len(recent) != 5 {
		t.Fatalf("expected blackbox summary to carry 5 most recent incidents, got ok=%v len=%d map=%+v", ok, len(recent), bbMap)
	}
	if recent[0].CauseDim != BlackboxDimUplinkSaturated || recent[0].UpUtilPct < 90.0 {
		t.Fatalf("static global_shaper_up fallback failed to detect uplink_saturated: %+v", recent[0])
	}
}

// 6. SignalMonitor.PeekCached 纯内存零唤醒与 enrichSignalDiagnosis "lan_bottleneck" 分支测试
func TestSignalMonitorPeekCachedZeroWakeAndLanBottleneck(t *testing.T) {
	s, _, dir := newV6TestMux(t)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{
		"version": 1,
		"global_shaper_enabled": true,
		"global_shaper_down": "40mbit",
		"global_shaper_up": "10mbit",
		"devices": {}
	}`), 0o600)
	// 预热一次 jsonCache 供纯内存零 Stat 读取
	_, _ = s.readStaticGlobalShaperBps()

	mon := newSignalMonitor(dir)
	var sampleCalls atomic.Int64
	mon.sampleFn = func(_ *server) hostSignalStatus {
		sampleCalls.Add(1)
		return hostSignalStatus{
			Available:       true,
			Mode:            "cellular",
			RAT:             "5G SA",
			DisplayRAT:      "5G-A",
			Is5GA:           true,
			BandCombo:       "n41+n28",
			RSRPdBm:         -82,
			RSRQdB:          -8,
			SINRdB:          22,
			Bars:            4,
			Quality:         "excellent",
			QualityCN:       "5G-A 极佳",
			RFCeilingFactor: 1.0,
		}
	}

	// 写入一份早已过期的缓存快照 (10 分钟前), 验证 PeekCached 绝不触发后台 sampleFn 刷新!
	mon.mu.Lock()
	mon.last = mon.sampleFn(nil)
	mon.lastAt = time.Now().Add(-10 * time.Minute)
	mon.mu.Unlock()
	sampleCalls.Store(0)

	stOk := mon.PeekCached(s)
	time.Sleep(30 * time.Millisecond)
	if sampleCalls.Load() != 0 || mon.asyncRuns.Load() != 0 {
		t.Fatalf("PeekCached must NEVER trigger background refresh: sampleCalls=%d asyncRuns=%d",
			sampleCalls.Load(), mon.asyncRuns.Load())
	}
	if stOk.Diagnosis != "ok" {
		t.Fatalf("expected Diagnosis='ok' when idle, got %q (%s)", stOk.Diagnosis, stOk.DiagnosisCN)
	}

	// 场景 A: 上游 5G-A 极佳且无空口膨胀, 但局域网设备跑满 40mbit(5,000,000 B/s) 的 92% -> lan_bottleneck!
	s.rateMu.Lock()
	s.rates["aa:bb:cc:dd:ee:01"] = rateOut{rxBps: 4_600_000, txBps: 100_000}
	s.rateMu.Unlock()
	stLan := mon.PeekCached(s)
	if stLan.Diagnosis != "lan_bottleneck" {
		t.Fatalf("expected Diagnosis='lan_bottleneck' on saturated LAN shaper, got %q (%s)", stLan.Diagnosis, stLan.DiagnosisCN)
	}

	// 场景 B: 清空流量, 但触发手机二阶高温温控限速 -> 同样归为 lan_bottleneck!
	s.rateMu.Lock()
	s.rates["aa:bb:cc:dd:ee:01"] = rateOut{}
	s.rateMu.Unlock()
	s.v6State().thermo.Evaluate(time.Now(), ThermoBatteryReading{
		Available:   true,
		SupplyNode:  "battery",
		TempC:       46.8,
		CapacityPct: 60,
		Status:      "Discharging",
	}, false)
	stTherm := mon.PeekCached(s)
	if stTherm.Diagnosis != "lan_bottleneck" {
		t.Fatalf("expected Diagnosis='lan_bottleneck' under active Stage2 thermal shaper, got %q (%s)", stTherm.Diagnosis, stTherm.DiagnosisCN)
	}

	// 校验 JSON 序列化无错误
	if _, err := json.Marshal(stTherm); err != nil {
		t.Fatalf("marshal hostSignalStatus: %v", err)
	}
}

// 7. UpdateLeash 精确 `>=` 过期边界、evalNoClientsRelease 残留兜底与正向 ApplyUpdateLeashNative(1:9990) 幂等闭环
func TestV6UpdateLeashBoundaryExpiryAndForwardApplyClosedLoop(t *testing.T) {
	s, mux, _ := newV6TestMux(t)
	leash := s.v6State().leash
	leash.idleExpire = 100 * time.Millisecond

	var applyMu sync.Mutex
	var appliedKbps []int
	var removeCalls int
	leash.applyDataplaneFn = func(_ string, _ uint32, rateKbps int) error {
		applyMu.Lock()
		appliedKbps = append(appliedKbps, rateKbps)
		applyMu.Unlock()
		return nil
	}
	leash.removeNativeFn = func(_ string, _ uint32) error {
		applyMu.Lock()
		removeCalls++
		applyMu.Unlock()
		return nil
	}
	leash.invalidateFn = func(_, _ string) {}

	t0 := time.Unix(1850000000, 0)
	const mb = 1024 * 1024
	flow := UpdateFlowInput{
		FlowKey:   "tcp|192.168.43.11|55000|13.107.4.50|443",
		MAC:       "aa:bb:cc:dd:ee:31",
		SrcIP:     "192.168.43.11",
		DstIP:     "13.107.4.50",
		DstHost:   "dl.delivery.mp.microsoft.com",
		Proto:     "tcp",
		DownBytes: 250 * mb,
		DownBps:   20_000_000,
	}

	// (a) 首次进入 leashed: 必须调用正向 applyDataplaneFn 下发默认 1500 Kbps 1:9990
	leash.ObserveFlows(t0, []UpdateFlowInput{flow})
	if leash.leashedCount.Load() != 1 {
		t.Fatalf("expected leashedCount=1, got %d", leash.leashedCount.Load())
	}
	applyMu.Lock()
	if len(appliedKbps) != 1 || appliedKbps[0] != 1500 {
		t.Fatalf("expected initial forward ApplyUpdateLeashNative(1500), got %v", appliedKbps)
	}
	applyMu.Unlock()

	// (b) 同一 leash_kbps 下重复采样必须幂等零重复下发
	leash.ObserveFlows(t0.Add(20*time.Millisecond), []UpdateFlowInput{flow})
	applyMu.Lock()
	if len(appliedKbps) != 1 {
		t.Fatalf("expected idempotent 0 duplicate apply on unchanged leash_kbps, got %v", appliedKbps)
	}
	applyMu.Unlock()

	// (c) 在线修改 leash_kbps=2400 -> 下一轮或 API 即时重算立即正向更新 1:9990 至 2400 Kbps
	leash.flowsHook = func() []UpdateFlowInput { return []UpdateFlowInput{flow} }
	rec := doV6JSONReq(t, mux, "POST", "/api/v6/update_leash", `{"leash_kbps":2400}`)
	if rec.Code != 200 {
		t.Fatalf("update leash_kbps failed: %d %s", rec.Code, rec.Body.String())
	}
	applyMu.Lock()
	if len(appliedKbps) != 2 || appliedKbps[1] != 2400 {
		t.Fatalf("expected forward ApplyUpdateLeashNative(2400) on config change, got %v", appliedKbps)
	}
	applyMu.Unlock()

	// (d) 精确 `>=` 空闲过期边界: 在 updatedTime + idleExpire 恰相等时刻必须立即判定过期并移除 1:9990!
	leash.mu.Lock()
	var exactUpdated time.Time
	for _, sess := range leash.sessions {
		exactUpdated = sess.updatedTime
	}
	leash.mu.Unlock()
	if exactUpdated.IsZero() {
		t.Fatal("expected non-zero sess.updatedTime")
	}
	leash.ObserveFlows(exactUpdated.Add(leash.idleExpire), nil)
	if leash.leashedCount.Load() != 0 {
		t.Fatalf("expected exact `>=` boundary (updatedTime + idleExpire) to expire session, leashedCount=%d", leash.leashedCount.Load())
	}
	applyMu.Lock()
	if removeCalls < 1 {
		t.Fatalf("expected RemoveUpdateLeashNative called when last leashed session expires, got %d", removeCalls)
	}
	applyMu.Unlock()

	// (e) evalNoClientsRelease 兜底分支: 当会话刚好到点 (!found) 但 leashedCount 仍 >0 时返回 (50ms, true) 触发收尾清理
	leash.leashedCount.Store(1)
	waitDur, needTimer := leash.evalNoClientsRelease(exactUpdated.Add(leash.idleExpire))
	if !needTimer || waitDur != 50*time.Millisecond {
		t.Fatalf("expected (50ms, true) fallback when !found && leashedCount>0, got (%v, %v)", waitDur, needTimer)
	}
	leash.leashedCount.Store(0)
}

// 8. HotspotOff 期间 GET/POST /api/v6/thermo 与 /api/v6/express 纯只读防污染与 runLoop resetDone 状态感知幂等门禁
func TestV6HotspotOffReadOnlyGETPOSTThermoAndExpressNoPollution(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("INACTIVE\n"), 0o644)

	feed := newMockActivityFeed(Activity{
		Known:         true,
		HotspotActive: false,
		ClientsOnline: 0,
	})

	th := s.v6State().thermo
	th.activityHook = feed.Read
	th.simActiveHook = func() bool { return false }
	th.batteryReadHook = func() ThermoBatteryReading {
		return ThermoBatteryReading{
			Available:   true,
			SupplyNode:  "battery",
			TempC:       47.5, // 高温读数: HotspotOff 下严禁推进 effectiveStage!
			CapacityPct: 10,
			Status:      "Discharging",
		}
	}

	exp := s.v6State().express
	exp.activityHook = feed.Read
	exp.simActiveHook = func() bool { return false }
	exp.signalHook = func(_ time.Time) []VectorExpressDeviceSignal {
		return []VectorExpressDeviceSignal{
			{MAC: "aa:bb:cc:dd:ee:01", TrafficType: ttGaming, Confidence: 0.99, FgAppName: "原神", ActiveDstIPs: 3},
		}
	}
	var dpApplyCalls atomic.Int64
	exp.nativeApplyFn = func(_ string, _ bool, _ uint32, _ int) error {
		dpApplyCalls.Add(1)
		return nil
	}
	exp.fallbackCmdFn = func(_, _ string, _ ...string) (int, string) {
		dpApplyCalls.Add(1)
		return 0, ""
	}
	exp.invalidateFn = func(_, _ string) {}

	// 先预置干净归零的 run 状态文件并记录内容, 验证 HotspotOff 下 GET/POST 绝不污染覆写
	thermoRunPath := filepath.Join(dir, "run", "thermo_state.json")
	expressRunPath := filepath.Join(dir, "run", "vector_express_state.json")
	sentinelThermo := `{"effective_stage":0,"sentinel":"clean_off"}`
	sentinelExpress := `{"active":false,"sentinel":"clean_off"}`
	_ = os.WriteFile(thermoRunPath, []byte(sentinelThermo), 0o644)
	_ = os.WriteFile(expressRunPath, []byte(sentinelExpress), 0o644)

	// (a) HotspotOff 下连续发起 GET / POST /api/v6/thermo
	getTh := doV6JSONReq(t, mux, "GET", "/api/v6/thermo", "")
	if getTh.Code != 200 || th.effectiveStage.Load() != 0 {
		t.Fatalf("GET /api/v6/thermo polluted effectiveStage=%d code=%d body=%s", th.effectiveStage.Load(), getTh.Code, getTh.Body.String())
	}
	postTh := doV6JSONReq(t, mux, "POST", "/api/v6/thermo", `{"stage1_temp_c":42.5,"stage2_temp_c":46.0}`)
	if postTh.Code != 200 || th.effectiveStage.Load() != 0 {
		t.Fatalf("POST /api/v6/thermo polluted effectiveStage=%d code=%d body=%s", th.effectiveStage.Load(), postTh.Code, postTh.Body.String())
	}
	if gotThDisk, _ := os.ReadFile(thermoRunPath); string(gotThDisk) != sentinelThermo {
		t.Fatalf("HotspotOff GET/POST /api/v6/thermo overwrote run/thermo_state.json: %s", string(gotThDisk))
	}

	// (b) HotspotOff 下连续发起 GET / POST /api/v6/express (含配置 forced_macs)
	getExp := doV6JSONReq(t, mux, "GET", "/api/v6/express", "")
	if getExp.Code != 200 || exp.isActive() || dpApplyCalls.Load() != 0 {
		t.Fatalf("GET /api/v6/express polluted active=%v dpCalls=%d body=%s", exp.isActive(), dpApplyCalls.Load(), getExp.Body.String())
	}
	postExp := doV6JSONReq(t, mux, "POST", "/api/v6/express", `{"bg_ceil_pct":80,"forced_macs":["aa:bb:cc:dd:ee:88"]}`)
	if postExp.Code != 200 || exp.isActive() || dpApplyCalls.Load() != 0 {
		t.Fatalf("POST /api/v6/express polluted active=%v dpCalls=%d body=%s", exp.isActive(), dpApplyCalls.Load(), postExp.Body.String())
	}
	var expResp map[string]any
	_ = json.Unmarshal(postExp.Body.Bytes(), &expResp)
	if expResp["active"] != false || expResp["state"] != expressStateIdle || expResp["configured_bg_ceil_pct"] != float64(80) {
		t.Fatalf("expected HotspotOff POST /api/v6/express snapshot idle/inactive, got %+v", expResp)
	}
	if gotExpDisk, _ := os.ReadFile(expressRunPath); string(gotExpDisk) != sentinelExpress {
		t.Fatalf("HotspotOff GET/POST /api/v6/express overwrote run/vector_express_state.json: %s", string(gotExpDisk))
	}

	// (c) 验证 runLoop 在 HotspotOff 首次完成 resetDone 后, 即使收到外部 Wake() 也不会重复空转下发数据面解限任务
	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); th.runLoop(stopCh) }()
	go func() { defer wg.Done(); exp.runLoop(stopCh) }()
	defer func() {
		close(stopCh)
		wg.Wait()
	}()

	waitEngineCond(t, time.Second, "initial HotspotOff resetDone completed in both engines", func() bool {
		exp.WaitDataplaneIdle()
		b, _ := os.ReadFile(thermoRunPath)
		return dpApplyCalls.Load() >= 1 && string(b) != sentinelThermo
	})
	callsAfterInit := dpApplyCalls.Load()
	_ = os.WriteFile(thermoRunPath, []byte(sentinelThermo), 0o644)

	th.Wake()
	exp.Wake()
	time.Sleep(40 * time.Millisecond)
	exp.WaitDataplaneIdle()

	if dpApplyCalls.Load() != callsAfterInit {
		t.Fatalf("Wake() during HotspotOff with activeFlag==0 must NOT re-enqueue dataplane reset: %d -> %d", callsAfterInit, dpApplyCalls.Load())
	}
	if gotThDisk, _ := os.ReadFile(thermoRunPath); string(gotThDisk) != sentinelThermo {
		t.Fatalf("Wake() during HotspotOff with effectiveStage==0 must NOT rewrite run/thermo_state.json: %s", string(gotThDisk))
	}
}

// 9. Blackbox 四项现场证据字段、整机恢复缓存清空与热重载、以及 LeakGuard 配置/白名单 SSE 唤醒闭环
func TestV6BlackboxEvidenceFieldsBackupHotReloadAndLeakGuardSSE(t *testing.T) {
	// (1) BlackboxIncident 必须完整携带 TempC / ThermalStage / RSRPdBm / SINRdB 证据字段
	jb := NewJitterBlackbox(16, 8)
	_, inc := jb.RecordSample(BlackboxTickInput{
		Now:             time.Unix(1860000000, 0),
		RTTMs:           145.0,
		BaseRTTMs:       25.0,
		CapacityBps:     12_500_000,
		UpCapacityBps:   2_500_000,
		TempC:           45.6,
		ThermalStage:    2,
		ThermalShaperOn: true,
		SignalAvailable: true,
		SignalMode:      "cellular",
		SignalQuality:   "weak",
		SignalRSRPdBm:   -112,
		SignalSINRdB:    -3,
	})
	if inc == nil {
		t.Fatal("expected BlackboxIncident to be recorded")
	}
	if inc.TempC != 45.6 || inc.ThermalStage != 2 || inc.RSRPdBm != -112 || inc.SINRdB != -3 {
		t.Fatalf("BlackboxIncident evidence fields mismatch: %+v", inc)
	}
	rawInc, err := json.Marshal(inc)
	if err != nil {
		t.Fatalf("marshal BlackboxIncident: %v", err)
	}
	for _, field := range []string{`"temp_c":45.6`, `"thermal_stage":2`, `"rsrp_dbm":-112`, `"sinr_db":-3`} {
		if !strings.Contains(string(rawInc), field) {
			t.Fatalf("missing JSON field %s in %s", field, string(rawInc))
		}
	}

	// (2) 整机备份恢复必须立即失效 server JSON 缓存并热重载四大 v6 引擎内存配置, 且不破坏导出文件哈希
	s, mux, dir := newV6TestMux(t)
	s.registerV6ScreenshotPackRoutes(mux)

	// 先构造一份备份源目录并导出 V6BackupBundle
	srcDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(srcDir, "data"), 0o755)
	_ = os.WriteFile(filepath.Join(srcDir, "data", "rules.json"), []byte(`{
		"version": 1,
		"global_shaper_enabled": true,
		"global_shaper_down": "180mbit",
		"global_shaper_up": "36mbit",
		"devices": {}
	}`), 0o600)
	_ = os.WriteFile(filepath.Join(srcDir, "data", "vector_express.json"), []byte(`{
		"enabled": true,
		"auto_detect": true,
		"bg_ceil_pct": 72,
		"hold_after_end_sec": 45,
		"max_concurrent_dst_ips": 64,
		"forced_macs": ["aa:bb:cc:00:00:99"]
	}`), 0o600)
	_ = os.WriteFile(filepath.Join(srcDir, "data", "update_leash.json"), []byte(`{
		"enabled": true,
		"grace_mb": 350,
		"leash_kbps": 2800
	}`), 0o600)
	_ = os.WriteFile(filepath.Join(srcDir, "data", "thermo_cruise.json"), []byte(`{
		"enabled": true,
		"stage2_shaper_enabled": false,
		"stage1_temp_c": 41.5,
		"stage2_temp_c": 45.5,
		"low_bat_pct": 18
	}`), 0o600)
	_ = os.WriteFile(filepath.Join(srcDir, "data", "leakguard_config.json"), []byte(`{
		"config": {
			"capacity": 320,
			"cooldown_sec": 90,
			"notify_enabled": false,
			"lockscreen_mask": true
		},
		"ignore_rules": [
			{"id":"ig_demo","scope":"host","dst_host":"telemetry.example.com","created_at":1800000000}
		]
	}`), 0o600)

	bundle, err := ExportBackupBundle(srcDir)
	if err != nil {
		t.Fatalf("ExportBackupBundle failed: %v", err)
	}

	// 在目标 server 上先写入旧配置并预热 jsonCache
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{
		"version": 1,
		"global_shaper_enabled": true,
		"global_shaper_down": "50mbit",
		"global_shaper_up": "10mbit",
		"devices": {}
	}`), 0o600)
	if d0, u0 := s.readStaticGlobalShaperBps(); d0 != 6_250_000 || u0 != 1_250_000 {
		t.Fatalf("unexpected pre-warmed shaper bps: %d / %d", d0, u0)
	}

	bundleJSON, _ := json.Marshal(bundle)
	resRec := doV6JSONReq(t, mux, "POST", "/api/restore", string(bundleJSON))
	if resRec.Code != 200 {
		t.Fatalf("POST /api/restore failed: %d %s", resRec.Code, resRec.Body.String())
	}

	// 验证 jsonCache 已被即时清空: 无需等待文件 mtime 跳秒即可读到 180mbit / 36mbit
	if d1, u1 := s.readStaticGlobalShaperBps(); d1 != 22_500_000 || u1 != 4_500_000 {
		t.Fatalf("expected invalidated jsonCache to return 22500000/4500000 immediately after restore, got %d/%d", d1, u1)
	}
	// 验证四大 v6 引擎内存态已全部热重载生效
	s.v6State().express.mu.Lock()
	gotPct := s.v6State().express.cfg.BgCeilPct
	s.v6State().express.mu.Unlock()
	if gotPct != 72 {
		t.Fatalf("express memory config not hot-reloaded after restore: BgCeilPct=%v", gotPct)
	}
	if gotKbps := s.v6State().leash.summary()["leash_kbps"]; gotKbps != 2800 {
		t.Fatalf("leash memory config not hot-reloaded after restore: leash_kbps=%v", gotKbps)
	}
	s.v6State().thermo.mu.Lock()
	gotS1 := s.v6State().thermo.cfg.Stage1TempC
	s.v6State().thermo.mu.Unlock()
	if gotS1 != 41.5 {
		t.Fatalf("thermo memory config not hot-reloaded after restore: Stage1TempC=%v", gotS1)
	}
	lgSnap := s.v6State().leakGuard.snapshotPayload()
	lgCfg, _ := lgSnap["config"].(LeakGuardConfig)
	if lgCfg.Capacity != 320 || lgCfg.CooldownSec != 90 {
		t.Fatalf("leakGuard memory config not hot-reloaded after restore: %+v", lgCfg)
	}
	// 验证恢复后的 data/leakguard_config.json 未被 ReloadFromDisk 改写破坏备份 SHA256 一致性
	lgDiskBytes, err := os.ReadFile(filepath.Join(dir, "data", "leakguard_config.json"))
	if err != nil {
		t.Fatalf("read restored leakguard_config.json: %v", err)
	}
	reExport, err := ExportBackupBundle(dir)
	if err != nil {
		t.Fatalf("re-export after restore failed: %v", err)
	}
	if reExport.FileSHA256["leakguard_config.json"] != bundle.FileSHA256["leakguard_config.json"] || len(sha256.Sum256(lgDiskBytes)) != 32 {
		t.Fatalf("leakguard_config.json canonical SHA256 drifted after ReloadFromDisk")
	}

	// (3) 验证 apiLeakGuardConfig 与 apiLeakGuardWhitelist(remove/clear) 均调用 notifySSEChanged() 立即唤醒引擎
	lg := s.v6State().leakGuard
	wakeCh := lg.ensureWakeCh()
	drainWake := func() {
		for {
			select {
			case <-wakeCh:
			default:
				return
			}
		}
	}

	drainWake()
	cfgRec := doV6JSONReq(t, mux, "POST", "/api/leakguard/config", `{"cooldown_sec":120}`)
	if cfgRec.Code != 200 {
		t.Fatalf("POST /api/leakguard/config failed: %d %s", cfgRec.Code, cfgRec.Body.String())
	}
	select {
	case <-wakeCh:
	default:
		t.Fatal("expected apiLeakGuardConfig to trigger notifySSEChanged()")
	}

	addRec := doV6JSONReq(t, mux, "POST", "/api/leakguard/whitelist", `{"action":"add","scope":"host","dst_host":"ads1.example.com"}`)
	if addRec.Code != 200 {
		t.Fatalf("whitelist add failed: %d %s", addRec.Code, addRec.Body.String())
	}
	_ = doV6JSONReq(t, mux, "POST", "/api/leakguard/whitelist", `{"action":"add","scope":"host","dst_host":"ads2.example.com"}`)

	drainWake()
	rmRec := doV6JSONReq(t, mux, "POST", "/api/leakguard/whitelist", `{"action":"remove","scope":"host","dst_host":"ads1.example.com"}`)
	if rmRec.Code != 200 {
		t.Fatalf("whitelist remove failed: %d %s", rmRec.Code, rmRec.Body.String())
	}
	select {
	case <-wakeCh:
	default:
		t.Fatal("expected apiLeakGuardWhitelist(remove) to trigger notifySSEChanged()")
	}

	drainWake()
	clrRec := doV6JSONReq(t, mux, "POST", "/api/leakguard/whitelist", `{"action":"clear"}`)
	if clrRec.Code != 200 {
		t.Fatalf("whitelist clear failed: %d %s", clrRec.Code, clrRec.Body.String())
	}
	select {
	case <-wakeCh:
	default:
		t.Fatal("expected apiLeakGuardWhitelist(clear) to trigger notifySSEChanged()")
	}
}
