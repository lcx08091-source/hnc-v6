// offload_sched_test.go — offload/clsact 的 Go 调度状态机与看门狗真脉搏单测(v6.0)。
package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hnc.io/dpid/nlroute"
)

// ── parseOffloadPlan(plan 子命令末行 "<秒> <早醒条件>") ─────────────

func TestParseOffloadPlanNormal(t *testing.T) {
	d, w := parseOffloadPlan("300 none")
	if d != 300*time.Second || w != "none" {
		t.Fatalf("got (%v,%q)", d, w)
	}
	d, w = parseOffloadPlan("60 hotspot")
	if d != 60*time.Second || w != "hotspot" {
		t.Fatalf("got (%v,%q)", d, w)
	}
	d, w = parseOffloadPlan("120 clients")
	if d != 120*time.Second || w != "clients" {
		t.Fatalf("got (%v,%q)", d, w)
	}
	// 只有秒数没有条件 → wake 缺省 none(末行由 runOffloadPlan 提取)
	d, w = parseOffloadPlan("300")
	if d != 300*time.Second || w != "none" {
		t.Fatalf("seconds-only: got (%v,%q)", d, w)
	}
}

func TestParseOffloadPlanBad(t *testing.T) {
	// 坏行 / 空 / 负数 / 超界 → 60 秒兜底(wake=none)
	for _, c := range []string{"", "garbage", "abc none", "-5 none", "99999999 none", "0 none"} {
		d, w := parseOffloadPlan(c)
		if d != offloadFallback || w != "none" {
			t.Errorf("parse(%q) = (%v,%q), want (60s,\"none\")", c, d, w)
		}
	}
}

// ── 早醒条件(v6.0 修复: clients 仅在 0 → >0 上线跃迁时早醒) ──────────

func TestOffloadEarlyWake(t *testing.T) {
	if !offloadEarlyWake("hotspot", "screen_on", 0, 0) {
		t.Error("wake=hotspot + 热点开 → 应早醒")
	}
	if !offloadEarlyWake("clients", "hotspot_off", 0, 3) {
		t.Error("wake=clients + 从 0 台变为 3 台设备 → 应早醒")
	}
	if offloadEarlyWake("clients", "screen_on", 1, 1) {
		t.Error("wake=clients + 睡眠前已有 1 台设备在线 → 绝不能每 30s 死循环早醒!")
	}
	if offloadEarlyWake("clients", "screen_on", 2, 3) {
		t.Error("wake=clients + 睡眠前已有 2 台设备在线 → 不早醒")
	}
	if offloadEarlyWake("hotspot", "hotspot_off", 0, 0) {
		t.Error("wake=hotspot + 热点没开 → 不早醒")
	}
	if offloadEarlyWake("clients", "screen_on", 0, 0) {
		t.Error("wake=clients + 0 设备 → 不早醒")
	}
	if offloadEarlyWake("none", "screen_on", 0, 5) {
		t.Error("wake=none → 永不早醒")
	}
}

// ── 预算: 无设备(plan=300 none)时 1 小时 plan 次数 ≤ 15 ────────────

func TestOffloadPlanBudget(t *testing.T) {
	p := &offloadPlanner{}
	start := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	now := start
	for elapsed := time.Duration(0); elapsed < time.Hour; elapsed += offloadWakeEvery {
		now = start.Add(elapsed)
		if p.advance(now, false) {
			p.observe(300*time.Second, "none", now)
		}
	}
	if p.planCalls > 15 {
		t.Fatalf("plan 次数 = %d, 超 15(300 秒节拍应 ~12)", p.planCalls)
	}
}

func TestOffloadEarlyWakeTriggersPlan(t *testing.T) {
	p := &offloadPlanner{}
	p.observeWithClients(300*time.Second, "clients", 0, time.Now())
	next := time.Now().Add(200 * time.Second) // 还没到 300 秒
	if !p.advance(next, offloadEarlyWake(p.wakeMode, "active", p.prevClients, 1)) {
		t.Fatal("0 → 1 客户端上线满足早醒条件时应该提前跑 plan")
	}
	if p.advance(next, false) {
		t.Fatal("没到 nextAt 且无早醒 → 不该跑")
	}
}

// v6.0 关键回归测试: 1 台客户端持续在线且 plan 返回 "300 clients" 时,
// 绝不能陷入每 30 秒早醒一次的死循环(旧代码 calls=121, 修复后应为 ~13 次/小时 ≤ 15)!
func TestOffloadSteadyClientOnlineNo30sDeadLoop(t *testing.T) {
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	p := &offloadPlanner{}
	curClients := 1 // 始终有 1 台设备在线
	for off := 0; off <= 3600; off += 30 {
		now := base.Add(time.Duration(off) * time.Second)
		early := offloadEarlyWake(p.wakeMode, "hotspot_off", p.prevClients, curClients)
		if p.advance(now, early) {
			p.observeWithClients(300*time.Second, "clients", curClients, now)
		}
	}
	if p.planCalls > 15 {
		t.Fatalf("steady 1 client online triggered %d plan calls in 1h (want <=15, old bug was ~121)", p.planCalls)
	}
}

// v6.0 边界测试: 0 台起步 → 第 60s 上线 1 台(早醒 1 次)→ 后续保持 1 台不再重复早醒。
func TestOffloadZeroToOneClientWakesOnceThenSleepsFull(t *testing.T) {
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	p := &offloadPlanner{}
	for off := 0; off <= 300; off += 30 {
		now := base.Add(time.Duration(off) * time.Second)
		curClients := 0
		if off >= 60 {
			curClients = 1
		}
		early := offloadEarlyWake(p.wakeMode, "active", p.prevClients, curClients)
		if p.advance(now, early) {
			p.observeWithClients(300*time.Second, "clients", curClients, now)
		}
	}
	// t=0 首轮(1) + t=60s 客户端上线早醒(2); t=90..300 因 nextAt=t+360s 且 prevClients=1 不再早醒!
	if p.planCalls != 2 {
		t.Fatalf("0->1 transition over 300s want exactly 2 plan calls, got %d", p.planCalls)
	}
}

// ── clsact 判定: check 输出含 "ok":true 才算好 ──────────────────────

func TestClsactCheckOutputJudged(t *testing.T) {
	okOut := `{"ok":true,"qdisc":"clsact","bpf_filter":true}`
	badOut := `{"ok":false,"qdisc":"clsact"}`
	if !strings.Contains(okOut, `"ok":true`) {
		t.Fatal("ok 判定自检失败")
	}
	if strings.Contains(badOut, `"ok":true`) {
		t.Fatal("bad 不该含 ok:true")
	}
}

func TestOffloadPlanBudgetNoClients(t *testing.T) {
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	p := &offloadPlanner{}
	calls := 0
	for off := 0; off <= 3600; off += 30 {
		now := base.Add(time.Duration(off) * time.Second)
		if p.advance(now, false) {
			calls++
			p.observe(300*time.Second, "none", now)
		}
	}
	if calls == 0 || calls > 15 {
		t.Fatalf("plan calls = %d, want 1..15(300 秒节拍应为 12)", calls)
	}
}

func TestOffloadPlanBudgetHotspotEarlyWake(t *testing.T) {
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	p := &offloadPlanner{}
	calls := 0
	for off := 0; off <= 3600; off += 30 {
		now := base.Add(time.Duration(off) * time.Second)
		early := offloadEarlyWake(p.wakeMode, "active", 0, 0)
		if p.advance(now, early) {
			calls++
			p.observe(300*time.Second, "hotspot", now)
		}
	}
	if calls < 60 || calls > 130 {
		t.Fatalf("plan calls = %d, want ~120(wake=hotspot 持续开启时每 30 秒早醒)", calls)
	}
}

// ── clsactTick: 只在 offload guard 说「on 模式装着 clsact」时 check, 不 ok 才修 ──

type clsactFake struct {
	checkOK func(n int) bool
	scripts [][]string
}

func withClsactFake(t *testing.T, target string, f *clsactFake) {
	t.Helper()
	oldT, oldC, oldS := clsactTargetFn, clsactCheckFn, runScriptFn
	n := 0
	clsactTargetFn = func() string { return target }
	clsactCheckFn = func(string) string {
		n++
		if f.checkOK != nil && f.checkOK(n) {
			return `{"ok":true,"qdisc":"clsact","bpf_filter":true}`
		}
		return `{"ok":false,"qdisc":"clsact"}`
	}
	runScriptFn = func(path string, args ...string) { f.scripts = append(f.scripts, append([]string{path}, args...)) }
	t.Cleanup(func() { clsactTargetFn, clsactCheckFn, runScriptFn = oldT, oldC, oldS })
}

func TestClsactTickRepairArgs(t *testing.T) {
	f := &clsactFake{checkOK: func(n int) bool { return n%3 != 0 }}
	withClsactFake(t, "wlan2", f)
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	c := &clsactSched{}
	for off := 0; off <= 600; off += 10 {
		clsactTick(c, base.Add(time.Duration(off)*time.Second))
	}
	if c.checks != 61 || len(f.scripts) != 20 {
		t.Fatalf("checks = %d repairs = %d, want 61 / 20", c.checks, len(f.scripts))
	}
	got := f.scripts[0]
	if len(got) != 3 || !strings.HasSuffix(got[0], "/hnc_offload_guard.sh") || got[1] != "clsact_repair" || got[2] != "wlan2" {
		t.Fatalf("repair 调用参数 = %q, want [.../hnc_offload_guard.sh clsact_repair wlan2]", got)
	}
}

func TestClsactTickNoTargetNoExec(t *testing.T) {
	f := &clsactFake{}
	withClsactFake(t, "", f)
	c := &clsactSched{}
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	for off := 0; off < 3600; off += 10 {
		clsactTick(c, base.Add(time.Duration(off)*time.Second))
	}
	if c.checks != 0 || len(f.scripts) != 0 {
		t.Fatalf("guard 没说要盯时不该 check / repair: checks=%d repairs=%d", c.checks, len(f.scripts))
	}
}

func TestClsactTargetFromGuardStatus(t *testing.T) {
	old := offloadGuardStatusPath
	offloadGuardStatusPath = t.TempDir() + "/offload_guard.json"
	t.Cleanup(func() { offloadGuardStatusPath = old })
	for _, c := range []struct{ json, want string }{
		{`{"mode":"on","clsact":"installed","iface":"wlan2"}`, "wlan2"},
		{`{"mode":"on","clsact":"skipped_pref1_mirred","iface":"wlan2"}`, ""},
		{`{"mode":"auto","clsact":"installed","iface":"wlan2"}`, ""},
		{`{"mode":"off","clsact":"off","iface":"wlan2"}`, ""},
		{`garbage`, ""},
	} {
		if err := os.WriteFile(offloadGuardStatusPath, []byte(c.json), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := clsactTarget(); got != c.want {
			t.Errorf("%s → %q, want %q", c.json, got, c.want)
		}
	}
	_ = os.Remove(offloadGuardStatusPath)
	if got := clsactTarget(); got != "" {
		t.Errorf("没有状态文件 → %q, want \"\"", got)
	}
}

// ── v6.0 看门狗「脑死亡脉搏正常」根治单测(90s 停刷心跳, 120s 告警退出, Doze 睡眠豁免) ──

func TestWatchdogHeartbeatBoundToMainLoopProgress(t *testing.T) {
	tmp := t.TempDir()
	hbTmp := filepath.Join(tmp, "watchdog.heartbeat")
	alertTmp := filepath.Join(tmp, "alerts.jsonl")

	var fakeMono atomic.Int64
	fakeMono.Store(int64(10 * time.Second))

	oldMono := wdMonoNowFn
	oldHB := wdHeartbeatPath
	oldAlertDir := wdAlertBaseDir
	oldExit := wdStallExitFn
	var exitCode atomic.Int32
	exitCode.Store(-1)

	wdMonoNowFn = fakeMono.Load
	wdHeartbeatPath = hbTmp
	wdAlertBaseDir = tmp
	wdStallExitFn = func(code int) { exitCode.Store(int32(code)) }
	t.Cleanup(func() {
		wdMonoNowFn = oldMono
		wdHeartbeatPath = oldHB
		wdAlertBaseDir = oldAlertDir
		wdStallExitFn = oldExit
		endMainLoopSleep()
	})

	_ = os.MkdirAll(filepath.Join(tmp, "run"), 0o755)
	_ = os.MkdirAll(filepath.Join(tmp, "data"), 0o755)
	_ = alertTmp

	// 1. mainLoop 正常推进(刚推进 10s < 90s) → 允许写 watchdog.heartbeat
	endMainLoopSleep()
	touchMainLoopStep()
	fakeMono.Add(int64(30 * time.Second))
	if !heartbeatTickOnce() {
		t.Fatal("fresh mainLoop (<90s) should refresh heartbeat")
	}
	if _, err := os.Stat(hbTmp); err != nil {
		t.Fatalf("expected heartbeat file written: %v", err)
	}

	// 2. mainLoop 卡死 95s (>= 90s, < 120s) → 停刷 heartbeat, 尚不退出
	_ = os.Remove(hbTmp)
	fakeMono.Add(int64(65 * time.Second)) // 累计停滞 95s
	if heartbeatTickOnce() {
		t.Fatal("stalled mainLoop (95s >= 90s) MUST NOT refresh heartbeat")
	}
	if _, err := os.Stat(hbTmp); err == nil {
		t.Fatal("heartbeat file should not have been recreated when stalled >=90s")
	}
	if exitCode.Load() != -1 {
		t.Fatalf("should not exit before 120s, got exitCode=%d", exitCode.Load())
	}

	// 3. mainLoop 卡死 125s (>= 120s) → 记录告警并调用退出钩子交由哨兵干净重拉!
	fakeMono.Add(int64(30 * time.Second)) // 累计停滞 125s
	if heartbeatTickOnce() {
		t.Fatal("stalled mainLoop (125s) must return false")
	}
	if exitCode.Load() != 1 {
		t.Fatalf("expected clean self-exit code 1 on >=120s stall, got %d", exitCode.Load())
	}

	// 4. Doze 180s 计划内睡眠期间: 即使过去 150s 也不算卡死, 照常刷新心跳且不误退出!
	exitCode.Store(-1)
	beginMainLoopSleep(180 * time.Second)
	fakeMono.Add(int64(150 * time.Second))
	if !heartbeatTickOnce() || exitCode.Load() != -1 {
		t.Fatalf("planned 180s Doze sleep must remain healthy at 150s (exitCode=%d)", exitCode.Load())
	}
}

func TestClsactPureGoZeroForkCheck(t *testing.T) {
	oldByN, oldNL, oldPin := netInterfaceByNameFn, nlClsactBPFCheckFn, clsactMapPinPath
	t.Cleanup(func() {
		netInterfaceByNameFn, nlClsactBPFCheckFn, clsactMapPinPath = oldByN, oldNL, oldPin
	})

	netInterfaceByNameFn = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 7}, nil
	}
	clsactMapPinPath = filepath.Join(t.TempDir(), "ip_mark_map")

	nlClsactBPFCheckFn = func(ifindex int, pin string) (nlroute.ClsactStatus, error) {
		if ifindex != 7 {
			t.Fatalf("unexpected ifindex=%d", ifindex)
		}
		return nlroute.ClsactStatus{Qdisc: true, IngressBPF: true, MapOK: true}, nil
	}
	if out := checkClsact("wlan2"); !strings.Contains(out, `"ok":true`) {
		t.Fatalf("pure Go healthy check want ok:true, got %q", out)
	}

	nlClsactBPFCheckFn = func(ifindex int, pin string) (nlroute.ClsactStatus, error) {
		return nlroute.ClsactStatus{Qdisc: true, IngressBPF: false, MapOK: true}, nil
	}
	if out := checkClsact("wlan2"); strings.Contains(out, `"ok":true`) {
		t.Fatalf("pure Go missing BPF want ok:false, got %q", out)
	}

	// netlink 不可用时回退 execClsactCheck(测试环境二进制不存在返回空串, 不 panic)
	nlClsactBPFCheckFn = func(ifindex int, pin string) (nlroute.ClsactStatus, error) {
		return nlroute.ClsactStatus{}, errors.New("netlink EACCES")
	}
	_ = checkClsact("wlan2")
}

func TestOffloadIdleCleanupAndZeroWakePause(t *testing.T) {
	tmp := t.TempDir()
	oldRun, oldStatus, oldState := offloadRunDir, offloadGuardStatusPath, offloadStateFn
	oldPlan, oldFirst, oldEvery, oldStop := runOffloadPlanFn, offloadFirstDelayDur, clsactEveryDur, stopCh
	oldTarget := clsactTargetFn

	offloadRunDir = tmp
	offloadGuardStatusPath = filepath.Join(tmp, "offload_guard.json")
	curState := wdState{kind: StateIdle}
	offloadStateFn = func() wdState { return curState }
	offloadFirstDelayDur = 0
	clsactEveryDur = 20 * time.Millisecond
	clsactTargetFn = func() string { return "" }
	localStop := make(chan struct{})
	stopCh = localStop

	var planCount atomic.Int32
	runOffloadPlanFn = func() string {
		planCount.Add(1)
		return "300 none"
	}

	t.Cleanup(func() {
		offloadRunDir, offloadGuardStatusPath, offloadStateFn = oldRun, oldStatus, oldState
		runOffloadPlanFn, offloadFirstDelayDur, clsactEveryDur, stopCh = oldPlan, oldFirst, oldEvery, oldStop
		clsactTargetFn = oldTarget
	})

	// 1. 存在残留 orig_tether_offload_disabled 时必须判为需要清理, 不可挂起!
	origFile := filepath.Join(tmp, "orig_tether_offload_disabled")
	_ = os.WriteFile(origFile, []byte("0\n"), 0o644)
	if offloadIdleShouldPause() {
		t.Fatal("残留 orig_tether_offload_disabled 未清理前绝不能提前挂起")
	}

	// 2. 清理完毕且归位 NOHOTSPOT + StateIdle → 允许挂起, 待机零唤醒!
	_ = os.Remove(origFile)
	_ = os.WriteFile(offloadGuardStatusPath, []byte(`{"mode":"auto","offload_state":"NOHOTSPOT","fallback_active":false,"clsact":"off","iface":""}`), 0o644)
	if !offloadIdleShouldPause() {
		t.Fatal("StateIdle 且无残留清理项时应允许挂起定时器")
	}

	// 清空可能残留的信号后启动两个调度循环, 验证 StateIdle 下 0 次 plan 调用
	select {
	case <-offloadWakeCh:
	default:
	}
	select {
	case <-clsactWakeCh:
	default:
	}

	doneOffload := make(chan struct{})
	doneClsact := make(chan struct{})
	go func() {
		defer close(doneOffload)
		offloadLoop()
	}()
	go func() {
		defer close(doneClsact)
		clsactLoop()
	}()

	time.Sleep(60 * time.Millisecond)
	if got := planCount.Load(); got != 0 {
		t.Fatalf("StateIdle 挂起期间不应触发任何 offload plan, got %d", got)
	}

	// 3. 模拟热点开启切换至 ACTIVE 并调用 wakeOffloadSched() → 立即唤醒跑首轮 plan!
	curState = wdState{kind: stateActive, iface: "wlan2"}
	wakeOffloadSched()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && planCount.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := planCount.Load(); got == 0 {
		t.Fatal("wakeOffloadSched 后应立即唤醒 offloadLoop 执行 plan")
	}

	close(localStop)
	<-doneOffload
	<-doneClsact
}

func TestOffloadFirstDelayImmediateWakeOnHotspotStart(t *testing.T) {
	tmp := t.TempDir()
	oldRun, oldStatus, oldState := offloadRunDir, offloadGuardStatusPath, offloadStateFn
	oldPlan, oldFirst, oldStop := runOffloadPlanFn, offloadFirstDelayDur, stopCh

	offloadRunDir = tmp
	offloadGuardStatusPath = filepath.Join(tmp, "offload_guard.json")
	var stateAtomic atomic.Int32
	stateAtomic.Store(int32(StateIdle))
	offloadStateFn = func() wdState {
		if stateKind(stateAtomic.Load()) == stateActive {
			return wdState{kind: stateActive, iface: "wlan2"}
		}
		return wdState{kind: StateIdle}
	}
	offloadFirstDelayDur = 20 * time.Second
	localStop := make(chan struct{})
	stopCh = localStop

	var planCount atomic.Int32
	runOffloadPlanFn = func() string {
		planCount.Add(1)
		return "300 none"
	}

	t.Cleanup(func() {
		offloadRunDir, offloadGuardStatusPath, offloadStateFn = oldRun, oldStatus, oldState
		runOffloadPlanFn, offloadFirstDelayDur, stopCh = oldPlan, oldFirst, oldStop
	})

	select {
	case <-offloadWakeCh:
	default:
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		offloadLoop()
	}()

	time.Sleep(40 * time.Millisecond)
	if got := planCount.Load(); got != 0 {
		t.Fatalf("StateIdle during first delay must not call plan, got %d", got)
	}

	// Hotspot turns ACTIVE during the 20s first delay -> wakeOffloadSched must wake immediately!
	wakeStart := time.Now()
	stateAtomic.Store(int32(stateActive))
	wakeOffloadSched()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && planCount.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if planCount.Load() == 0 {
		t.Fatal("expected immediate wake from 20s first delay upon wakeOffloadSched")
	}
	if took := time.Since(wakeStart); took > 500*time.Millisecond {
		t.Fatalf("expected sub-second wake from 20s first delay, took %v", took)
	}

	close(localStop)
	<-done
}
