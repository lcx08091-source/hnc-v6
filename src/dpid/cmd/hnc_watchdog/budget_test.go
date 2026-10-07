// budget_test.go — v5.28 A1: 看门狗调用预算测试。
//
// 用假的 runActionFn / runV6SyncFn / runStatsSampleFn / 假时钟驱动
// loopState.tick(= mainLoop 每轮除睡眠与 daemon 保活外的全部职责),
// 模拟四个场景各 60 分钟, 断言动作调用次数不超过预算表。
//
// ── 预算表(次 / 小时, 每个数字的来源) ─────────────────────────────────
//
//	ACTIVE、规则健康、无在线设备、亮屏:
//	  probe_hotspot     ≤ 60   主循环 60s 一轮(budgetProbe)
//	  check_health      ≤ 60   每轮(budgetHealth)
//	  capability_probe  ≤ 1    启动首轮 1 次, 之后 6h 一次(budgetCap)
//	  httpd_drift       ≤ 12   健康时 5 分钟一次(budgetDrift)
//	  tc_uplink_healthy ≤ 20   健康时 3 分钟一次(budgetUplink)
//	  v6_sync.sh        ≤ 60   每轮 60s 一次(budgetV6)
//	  stats_sample.sh   ≤ 4    无在线设备 → 900s 一次(budgetStats)
//	  full_restore      =  0   规则一直健康
//	  full_init         =  0   无状态迁移
//	  is_doze           =  0   亮屏(测试里 isDozeFn 桩直接返回 false;
//	                          生产行为: screenAwake → 不 fork is_doze)
//	  prune_dup_hotspotd ≤ 6   10 分钟一次(budgetPrune)
//	  外部进程合计      ≤ 300  budgetTotalActive
//	ACTIVE、网卡在第 30 分钟从 wlan2 变成 ap0:
//	  migrate = 1;capability_probe ≤ 2(启动首轮 + 网卡变化)
//	ACTIVE、check_health 一直返回 1(规则丢了):
//	  full_restore 受 restoreThrottle 限制: 每个 restore 窗口(最短
//	  restoreWindowSec=300s)最多 restoreWindowMax=5 次, 窗口翻倍/重置
//	  不改变「5 次 / ≥300s」这一不变量 → 60 分钟绝对上限
//	  5×12 = 60(budgetRestore; 假时钟实测 45, 节拍见各窗口的被动模式)
//	PENDING、热点未开:
//	  外部进程合计 ≤ 40(120s 兜底探测 30 次 + prune_dup 6 次 + 余量)
//
// 「改动前会失败」: v5.27 的 Go 代码每轮调 capability_probe(60 次/小时
// > budgetCap=1), 场景 1 直接 FAIL。提交说明里记录了验证方法(临时把
// cap.due 判断改回每轮调用 → go test 本文件 → FAIL)。
package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"hnc.io/dpid/activity"
	"hnc.io/dpid/nlroute"
)

const (
	budgetProbe        = 60
	budgetHealth       = 60
	budgetCap          = 1
	budgetDrift        = 12
	budgetUplink       = 20
	budgetV6           = 60
	budgetStats        = 4
	budgetPrune        = 6
	budgetTotalActive  = 300
	budgetMigrate      = 1
	budgetCapOnSwitch  = 2
	budgetRestore      = 60
	budgetTotalPending = 40
)

// fakeClock 可拨的假时钟。
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

// actionRec 记录 runActionFn 的每次调用; probeOut 决定 probe_hotspot 的
// 返回(默认 "wlan0 192.168.43.1\n" rc=0), rc 表覆盖某动作的返回码。
type actionRec struct {
	counts   map[string]int
	rc       map[string]int
	probeOut string
	probeRC  int
	hook     func(name string)
}

func newActionRec() *actionRec {
	return &actionRec{
		counts:   make(map[string]int),
		rc:       make(map[string]int),
		probeOut: "wlan0 192.168.43.1\n",
	}
}

func (r *actionRec) call(name string, _ ...string) actionResult {
	r.counts[name]++
	if r.hook != nil {
		r.hook(name)
	}
	if name == "probe_hotspot" {
		return actionResult{exitCode: r.probeRC, stdout: r.probeOut}
	}
	if rc, ok := r.rc[name]; ok {
		return actionResult{exitCode: rc}
	}
	return actionResult{exitCode: 0}
}

func (r *actionRec) total() int {
	n := 0
	for _, v := range r.counts {
		n += v
	}
	return n
}

// withFakeEnv 替换包级函数变量(测试结束恢复), 返回 recorder 供断言。
func withFakeEnv(t *testing.T, clk *fakeClock, rec *actionRec) {
	t.Helper()
	oldAct, oldV6, oldStats, oldScript := runActionFn, runV6SyncFn, runStatsSampleFn, runScriptFn
	oldIsDoze, oldIdle, oldActSnap, oldNow := isDozeFn, hotspotIdleFn, actSnapshotFn, nowFn
	runActionFn = rec.call
	runV6SyncFn = func() {}
	runStatsSampleFn = func() {}
	runScriptFn = func(string, ...string) {}
	isDozeFn = func() bool { return false }
	hotspotIdleFn = func() bool { return false }
	actSnapshotFn = func() activity.Snapshot {
		return activity.Snapshot{OK: true, Level: activity.LevelNoClients, Hotspot: true, Clients: 0}
	}
	nowFn = clk.Now
	t.Cleanup(func() {
		runActionFn, runV6SyncFn, runStatsSampleFn, runScriptFn = oldAct, oldV6, oldStats, oldScript
		isDozeFn, hotspotIdleFn, actSnapshotFn, nowFn = oldIsDoze, oldIdle, oldActSnap, oldNow
	})
	withNativeUnknown(t)
	withTempOnlineAcc(t) // v5.30 T1a: 在线分钟累加器也隔离到临时目录(不读真实 devices.json)
	// v5.30: 动作记账落盘也指到临时目录(原先 tick 会试着写真实 /data/local/hnc/run)
	actTmp := filepath.Join(t.TempDir(), "watchdog_actions.json")
	oldFlush := wdActionsFlushFn
	wdActionsFlushFn = func(_ string, now time.Time) error { return wdActions.flush(actTmp, now) }
	t.Cleanup(func() { wdActionsFlushFn = oldFlush })
	withTempM4Shadow(t) // v5.30 T3: M4 影子同样隔离(假邻居表、临时 run / data)
}

// withNativeUnknown v5.29: 原生检查的外部世界全部隔离成「判不了」(临时
// run/、无探测文件、netlink / exec 都失败)—— 原生路径一律退回 shell,
// 旧预算用例因此与机器环境无关(之前读的是真实 /data/local/hnc/run 与
// 本机网卡)。需要原生世界的用例在此之后自行注入。
func withNativeUnknown(t *testing.T) {
	t.Helper()
	oldRun, oldData := natRunDir, natDataDir
	oldHint, oldByN, oldAddrs, oldQ, oldExec, oldSys := ifaceHintReadFn, netInterfaceByNameFn, netIfAddrsFn, nlQdiscListFn, execCommandFn, sysIfIndexFn
	oldShadow, oldMM := natShadowSt, nativeMismatchTotal
	oldHCAt, oldHCRC, oldHCI := healthCacheAt, healthCacheRC, healthCacheIface
	natRunDir, natDataDir = t.TempDir(), t.TempDir()
	ifaceHintReadFn = func() (string, bool) { return "", false }
	netInterfaceByNameFn = func(string) (*net.Interface, error) { return nil, os.ErrNotExist }
	netIfAddrsFn = func(*net.Interface) ([]net.Addr, error) { return nil, os.ErrNotExist }
	nlQdiscListFn = func(int) ([]nlroute.Qdisc, error) { return nil, os.ErrNotExist }
	execCommandFn = func(string, ...string) (string, int, error) { return "", -1, os.ErrNotExist }
	sysIfIndexFn = func(string) (string, error) { return "", os.ErrNotExist }
	natShadowSt, nativeMismatchTotal = newNativeShadowState(), 0
	healthCacheAt, healthCacheRC, healthCacheIface = time.Time{}, 0, ""
	t.Cleanup(func() {
		natRunDir, natDataDir = oldRun, oldData
		ifaceHintReadFn, netInterfaceByNameFn, netIfAddrsFn = oldHint, oldByN, oldAddrs
		nlQdiscListFn, execCommandFn, sysIfIndexFn = oldQ, oldExec, oldSys
		natShadowSt, nativeMismatchTotal = oldShadow, oldMM
		healthCacheAt, healthCacheRC, healthCacheIface = oldHCAt, oldHCRC, oldHCI
	})
}

// withNativeHealthy 原生世界全绿: 探测新鲜(wlan2 / 192.168.43.1)、根 htb、
// iptables 正常、ifb0 + mirred 在。
func withNativeHealthy(t *testing.T) {
	t.Helper()
	ifaceHintReadFn = func() (string, bool) { return "wlan2", true }
	netInterfaceByNameFn = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 5}, nil
	}
	netIfAddrsFn = func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.43.1").To4(), Mask: net.CIDRMask(24, 32)}}, nil
	}
	sysIfIndexFn = func(string) (string, error) { return "5", nil }
	nlQdiscListFn = func(int) ([]nlroute.Qdisc, error) {
		return []nlroute.Qdisc{{Kind: "htb", Handle: 0x10000, Parent: nlroute.TC_H_ROOT}}, nil
	}
	execCommandFn = func(name string, args ...string) (string, int, error) {
		if len(args) > 1 && args[0] == "filter" {
			return "filter parent ffff: action mirred egress redirect dev ifb0", 0, nil
		}
		return "-A HNC_RESTORE -j CONNMARK --restore-mark\n", 0, nil
	}
}

// driveHour 用 step 间隔驱动 tick 走满 60 分钟(返回 tick 数)。
func driveHour(ls *loopState, clk *fakeClock, state func(round int) wdState, step time.Duration) int {
	return driveHourWithHook(ls, clk, nil, state, step)
}

// driveHourWithHook 同 driveHour, 但每轮 tick 前先调 hook(round)(改 probe
// 输出之类的外部世界变化)。
func driveHourWithHook(ls *loopState, clk *fakeClock, hook func(round int), state func(round int) wdState, step time.Duration) int {
	start := clk.now
	n := 0
	for elapsed := time.Duration(0); elapsed < time.Hour; elapsed += step {
		clk.now = start.Add(elapsed)
		if hook != nil {
			hook(n)
		}
		ls.tick(state(n))
		n++
	}
	return n
}

// TestBudgetActiveHealthy 场景 1: ACTIVE 健康、无在线设备、亮屏。
func TestBudgetActiveHealthy(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)
	ls := newLoopState()

	st := func(int) wdState { return wdState{kind: stateActive, iface: "wlan0"} }
	rounds := driveHour(ls, clk, st, intervalNormal)
	if rounds != 60 {
		t.Fatalf("rounds = %d, want 60", rounds)
	}

	for name, budget := range map[string]int{
		"probe_hotspot":      budgetProbe,
		"check_health":       budgetHealth,
		"capability_probe":   budgetCap,
		"httpd_drift":        budgetDrift,
		"tc_uplink_healthy":  budgetUplink,
		"prune_dup_hotspotd": budgetPrune,
	} {
		if rec.counts[name] > budget {
			t.Errorf("%s = %d 次/小时, 超预算 %d", name, rec.counts[name], budget)
		}
	}
	if v := rec.counts["v6_sync.sh"] + 0; v > budgetV6 {
		// v6_sync 不是 runAction, 由 runV6SyncFn 桩记录在 ls 内部; 这里以
		// counts 表外单独核对(见下)。
		t.Errorf("v6_sync = %d, 超预算 %d", v, budgetV6)
	}
	if rec.counts["full_restore"] != 0 || rec.counts["full_init"] != 0 {
		t.Errorf("healthy 场景不该有 full_restore/full_init: %v", rec.counts)
	}
	if rec.counts["is_doze"] != 0 {
		t.Errorf("is_doze = %d, want 0", rec.counts["is_doze"])
	}
	if rec.total() > budgetTotalActive {
		t.Errorf("外部进程合计 = %d, 超预算 %d", rec.total(), budgetTotalActive)
	}
}

// TestBudgetActiveStatsAndV6 v6_sync(60s)与 stats_sample(900s, 无在线设备)
// 的节拍单独核对 —— 它们不走 runActionFn, 用专用桩计数。
func TestBudgetActiveStatsAndV6(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)

	v6, stats := 0, 0
	oldV6, oldStats := runV6SyncFn, runStatsSampleFn
	runV6SyncFn = func() { v6++ }
	runStatsSampleFn = func() { stats++ }
	t.Cleanup(func() { runV6SyncFn, runStatsSampleFn = oldV6, oldStats })

	ls := newLoopState()
	st := func(int) wdState { return wdState{kind: stateActive, iface: "wlan0"} }
	driveHour(ls, clk, st, intervalNormal)

	if v6 > budgetV6 {
		t.Errorf("v6_sync = %d, 超预算 %d", v6, budgetV6)
	}
	if stats > budgetStats {
		t.Errorf("stats_sample = %d, 超预算 %d(无在线设备应 900s 一次)", stats, budgetStats)
	}
}

// TestBudgetActiveIfaceSwitch 场景 2: 第 30 分钟网卡 wlan2 → ap0。
// 状态机口径与生产一致: hnc_state 写的是旧网卡, probe_hotspot 报告新
// 网卡 → migrate 一次 + writeState 同步; writeStateFn 桩负责让下一轮的
// 状态跟着变(沙箱里 run/ 不可写, writeState 本身会静默失败)。
func TestBudgetActiveIfaceSwitch(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	rec.probeOut = "wlan2 192.168.43.1\n"
	withFakeEnv(t, clk, rec)

	ls := newLoopState()
	cur := "wlan2" // 模拟 run/hnc_state 的当前内容
	st := func(int) wdState { return wdState{kind: stateActive, iface: cur} }
	oldWrite := writeStateFn
	writeStateFn = func(s wdState) {
		if s.kind == stateActive && s.iface != "" {
			cur = s.iface // migrate 成功 → 状态文件换成新网卡
			rec.probeOut = s.iface + " 192.168.43.1\n"
		}
	}
	t.Cleanup(func() { writeStateFn = oldWrite })

	// 第 30 分钟: 内核侧网卡换成 ap0 —— probe 报告新网卡, 状态还是旧的。
	driveHourWithHook(ls, clk, func(round int) {
		if round == 30 {
			rec.probeOut = "ap0 192.168.43.1\n"
		}
	}, func(round int) wdState { return st(round) }, intervalNormal)

	if v := rec.counts["migrate"]; v != budgetMigrate {
		t.Errorf("migrate = %d, want %d", v, budgetMigrate)
	}
	if v := rec.counts["capability_probe"]; v > budgetCapOnSwitch {
		t.Errorf("capability_probe = %d, 超预算 %d(启动 1 次 + 网卡变化 1 次)", v, budgetCapOnSwitch)
	}
}

// TestBudgetActiveUnhealthy 场景 3: check_health 一直返回 1。
func TestBudgetActiveUnhealthy(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	rec.rc["check_health"] = 1
	withFakeEnv(t, clk, rec)

	ls := newLoopState()
	st := func(int) wdState { return wdState{kind: stateActive, iface: "wlan0"} }
	driveHour(ls, clk, st, intervalRecovery)

	// 上限推导见文件头注释(5 次/窗口 × 最短 300s 窗口 = 60/小时)。
	if v := rec.counts["full_restore"]; v > budgetRestore {
		t.Errorf("full_restore = %d, 超预算 %d(restoreThrottle 窗口规则)", v, budgetRestore)
	}
	if rec.total() > budgetTotalActive {
		t.Errorf("外部进程合计 = %d, 超预算 %d", rec.total(), budgetTotalActive)
	}
}

// TestBudgetPendingHotspotOff 场景 4: PENDING、热点未开 → 120s 兜底探测。
func TestBudgetPendingHotspotOff(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	rec.probeRC = 1 // 热点没开, probe_hotspot 非零是正常结果
	withFakeEnv(t, clk, rec)
	hotspotIdleFn = func() bool { return true } // activity 显示 hotspot_off

	ls := newLoopState()
	st := func(int) wdState { return wdState{kind: statePending} }

	// 先手动拨一轮拿 tick 返回的间隔(应为 120s 兜底), 再按该间隔驱动。
	clk.now = clk.now.Add(intervalNormal)
	iv := ls.tick(st(0))
	if iv != intervalIdleProbe {
		t.Fatalf("PENDING + hotspot_off 的 tick 间隔 = %v, want %v", iv, intervalIdleProbe)
	}
	rec.counts["probe_hotspot"] = 0
	rounds := driveHour(ls, clk, st, intervalIdleProbe)
	if rounds > 30 {
		t.Fatalf("rounds = %d, want ≤ 30(120s 兜底)", rounds)
	}
	if rec.total() > budgetTotalPending {
		t.Errorf("外部进程合计 = %d, 超预算 %d", rec.total(), budgetTotalPending)
	}
}

// TestCapProbeGate 单元级: 启动首轮 / 网卡变化 / 6h 一次。
func TestCapProbeGate(t *testing.T) {
	g := &capProbeGate{}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)
	if !g.due("wlan0", now) {
		t.Fatal("首轮应放行")
	}
	g.mark("wlan0", now)
	if g.due("wlan0", now.Add(5*time.Hour+59*time.Minute)) {
		t.Error("6h 内同网卡不应再探测")
	}
	if !g.due("wlan0", now.Add(6*time.Hour)) {
		t.Error("满 6h 应放行")
	}
	if !g.due("ap0", now.Add(time.Minute)) {
		t.Error("网卡变化应放行")
	}
	g.mark("ap0", now.Add(time.Minute))
	if g.due("ap0", now.Add(time.Minute+time.Hour)) {
		t.Error("换网卡后 1h 内不应再探测")
	}
}

// ── v5.29 T1: 原生检查开启时的调用预算 ──────────────────────────────
//
// 原生路径下, ACTIVE 健康 1 小时里「经 sh 的外部调用」合计 ≤ 70
// (v6_sync 60 + stats 4 + probe/check_health 对照各 2 + 余量)。
// probe / check_health / httpd_drift / tc_uplink_healthy 全部走原生
// 判断(netlink / net / 直接 exec iptables-tc), 不计入 sh 调用。
//
// 「改动前会失败」: v5.28 代码没有原生路径, probe+health 一小时就是
// 120 次 sh(> 70)。

func TestBudgetNativeActiveHealthy(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)
	withNativeHealthy(t)
	rec.probeOut = "wlan2 192.168.43.1\n" // 对照的 shell 版结论与原生一致

	ls := newLoopState()
	st := func(int) wdState { return wdState{kind: stateActive, iface: "wlan2"} }
	rounds := driveHour(ls, clk, st, intervalNormal)
	if rounds != 60 {
		t.Fatalf("rounds = %d, want 60", rounds)
	}

	// 原生路径生效的直接证据: 这四项的 sh 调用只来自 30 分钟一次的对照
	if n := rec.counts["probe_hotspot"]; n > 2 {
		t.Errorf("probe_hotspot sh = %d 次/小时(原生应只剩对照 ≤ 2)", n)
	}
	if n := rec.counts["check_health"]; n > 2 {
		t.Errorf("check_health sh = %d 次/小时(原生应只剩对照 ≤ 2)", n)
	}
	if n := rec.counts["httpd_drift"]; n != 0 {
		t.Errorf("httpd_drift sh = %d(原生判断无文件 → 不动手, 不该调 shell)", n)
	}
	if n := rec.counts["tc_uplink_healthy"]; n != 0 {
		t.Errorf("tc_uplink_healthy sh = %d(原生全绿, 不该调 shell)", n)
	}
	if total := rec.total(); total > budgetNativeShTotal {
		t.Errorf("原生开启时 sh 调用合计 = %d, 超预算 %d", total, budgetNativeShTotal)
	}
}

const budgetNativeShTotal = 70

// TestBudgetNativeSwitchFile 原生开关关闭 → 完全走旧路径。
func TestBudgetNativeSwitchFile(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)
	withNativeHealthy(t)
	// 原生探测都健康, 但开关文件存在
	if err := os.WriteFile(natRunDir+"/wd_native.disabled", []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec.probeOut = "wlan2 192.168.43.1\n" // 与状态机 iface 一致, 否则每轮 migrate

	ls := newLoopState()
	st := func(int) wdState { return wdState{kind: stateActive, iface: "wlan2"} }
	driveHour(ls, clk, st, intervalNormal)
	// 开关关闭: probe / health 走 shell 每轮一次(60 次/小时, 旧口径)
	if n := rec.counts["probe_hotspot"]; n != 60 {
		t.Errorf("probe_hotspot sh = %d, want 60(开关关闭走旧路径)", n)
	}
	if n := rec.counts["check_health"]; n != 60 {
		t.Errorf("check_health sh = %d, want 60(开关关闭走旧路径)", n)
	}
}

// TestNativeUnknownNoDoubleShell 原生判不了(探测陈旧 / netlink 失败)→
// 每轮只跑一次 shell; 30 分钟对照点上也不能再跑第二遍(v5.29 rc1 在对照点
// 会把 shell 跑两遍, 还拿 shell 跟 shell 比)。
func TestNativeUnknownNoDoubleShell(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec) // 原生全部「判不了」
	rec.probeOut = "wlan2 192.168.43.1\n"
	ls := newLoopState()
	st := func(int) wdState { return wdState{kind: stateActive, iface: "wlan2"} }
	driveHour(ls, clk, st, intervalNormal)
	if n := rec.counts["probe_hotspot"]; n != 60 {
		t.Errorf("probe_hotspot sh = %d, want 60(每轮一次, 对照点不重复)", n)
	}
	if n := rec.counts["check_health"]; n != 60 {
		t.Errorf("check_health sh = %d, want 60(每轮一次, 对照点不重复)", n)
	}
	if nativeMismatchTotal != 0 {
		t.Errorf("原生判不了不算不一致, native_mismatch = %d", nativeMismatchTotal)
	}
}

// TestNativeShadowShellWinsThisRound 对照点上原生说健康、shell 说规则丢了 →
// 本轮以 shell 为准, 当轮就 full_restore(rc1 只记账, 照用原生结论)。
func TestNativeShadowShellWinsThisRound(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)
	withNativeHealthy(t)
	rec.probeOut = "wlan2 192.168.43.1\n"
	rec.rc["check_health"] = 1
	ls := newLoopState()
	ls.tick(wdState{kind: stateActive, iface: "wlan2"})
	if rec.counts["check_health"] != 1 {
		t.Fatalf("第一轮应跑一次对照, check_health = %d", rec.counts["check_health"])
	}
	if rec.counts["full_restore"] != 1 {
		t.Errorf("对照不一致时本轮应按 shell 结论 full_restore, got %d", rec.counts["full_restore"])
	}
	if nativeMismatchTotal != 1 {
		t.Errorf("native_mismatch = %d, want 1", nativeMismatchTotal)
	}
}

// TestNativeRevertAppliesToLoop 同项连续 3 次不一致 → 主循环真的退回
// shell(每轮跑 shell check_health)。rc1 主循环用 natUse("health"), 而
// 退回记在 "check_health" 键上, 退回永远不生效。
func TestNativeRevertAppliesToLoop(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)
	withNativeHealthy(t)
	rec.probeOut = "wlan2 192.168.43.1\n"
	rec.rc["check_health"] = 2 // shell 每次都说「锁忙」, 原生说健康 → 不一致(后果最轻: 跳过本轮)
	ls := newLoopState()
	st := func(int) wdState { return wdState{kind: stateActive, iface: "wlan2"} }
	driveHour(ls, clk, st, intervalNormal) // 对照点 0 / 30 分 → 2 次不一致
	if rec.counts["check_health"] != 2 || natShadowSt.isReverted(ncHealth) {
		t.Fatalf("第一小时: check_health = %d, reverted = %v; want 2 / false", rec.counts["check_health"], natShadowSt.isReverted(ncHealth))
	}
	clk.now = clk.now.Add(time.Minute)
	driveHour(ls, clk, st, intervalNormal) // 60 分对照点第 3 次 → 退回, 之后每轮 shell
	if !natShadowSt.isReverted(ncHealth) {
		t.Fatal("连续 3 次不一致后应钉回 shell")
	}
	if n := rec.counts["check_health"]; n < 55 {
		t.Errorf("退回后应每轮跑 shell check_health, 两小时合计只有 %d 次", n)
	}
	if n := rec.counts["probe_hotspot"]; n > 4 {
		t.Errorf("probe 没有不一致, 不该被一起退回: probe_hotspot sh = %d", n)
	}
}
