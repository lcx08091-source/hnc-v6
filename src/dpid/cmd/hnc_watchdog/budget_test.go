// budget_test.go — v5.28 A1: 看门狗调用预算测试。
//
// 用假的 runActionFn / runV6SyncFn / runStatsSampleFn / 假时钟驱动
// loopState.tick(= mainLoop 每轮除睡眠与 daemon 保活外的全部职责),
// 模拟四个场景各 60 分钟, 断言动作调用次数不超过预算表。
//
// 热点探测 / 规则健康(native.go)不起 sh, 场景用例里换成「世界状态」桩
// (actionRec.probeOut / rc["check_health"]); 真实实现的 sh 开销(探测陈旧时
// 跑 hnc_iface.sh get, 动作名 iface_detect)由 TestBudgetNative* 单独核对。
//
// ── 预算表(次 / 小时, 每个数字的来源) ─────────────────────────────────
//
//	ACTIVE、规则健康、无在线设备、亮屏:
//	  capability_probe  ≤ 1    启动首轮 1 次, 之后 6h 一次(budgetCap)
//	  tc_uplink_healthy ≤ 20   健康时 3 分钟一次(budgetUplink; 原生判全绿时 0)
//	  iface_detect      ≤ 12   热点探测结果 5 分钟过期才刷新(budgetIfaceDetect)
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
//	ACTIVE、规则健康检查一直返回 1(规则丢了):
//	  full_restore 受 restoreThrottle 限制: 每个 restore 窗口(最短
//	  restoreWindowSec=300s)最多 restoreWindowMax=5 次, 窗口翻倍/重置
//	  不改变「5 次 / ≥300s」这一不变量 → 60 分钟绝对上限
//	  5×12 = 60(budgetRestore; 假时钟实测 45, 节拍见各窗口的被动模式)
//	PENDING、热点未开:
//	  外部进程合计 ≤ 40(120s 兜底探测 30 次 iface_detect + prune_dup 6 次 + 余量)
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
	budgetCap          = 1
	budgetUplink       = 20
	budgetIfaceDetect  = 12
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

// actionRec 记录 runActionFn 的每次调用(以及 iface_detect); probeOut / probeRC
// 决定热点探测桩的结论(默认 "wlan0 192.168.43.1" rc=0), rc 表覆盖某动作的
// 返回码(rc["check_health"] 是规则健康桩的结论, 不计入调用次数)。
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
	if rc, ok := r.rc[name]; ok {
		return actionResult{exitCode: rc}
	}
	return actionResult{exitCode: 0}
}

// probe 热点探测的世界状态桩(不起 sh, 不计数)。
func (r *actionRec) probe() actionResult {
	return actionResult{exitCode: r.probeRC, stdout: r.probeOut}
}

// health 规则健康的世界状态桩(不起 sh, 不计数)。
func (r *actionRec) health(string) int { return r.rc["check_health"] }

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
	oldProbe, oldHealth, oldDetect := probeHotspotFn, checkHealthFn, ifaceDetectFn
	runActionFn = rec.call
	probeHotspotFn = rec.probe
	checkHealthFn = rec.health
	ifaceDetectFn = func() { rec.counts["iface_detect"]++ }
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
		probeHotspotFn, checkHealthFn, ifaceDetectFn = oldProbe, oldHealth, oldDetect
	})
	withNativeUnknown(t)
	withTempOnlineAcc(t) // v5.30 T1a: 在线分钟累加器也隔离到临时目录(不读真实 devices.json)
	// v5.30: 动作记账落盘也指到临时目录(原先 tick 会试着写真实 /data/local/hnc/run)
	actTmp := filepath.Join(t.TempDir(), "watchdog_actions.json")
	oldFlush := wdActionsFlushFn
	wdActionsFlushFn = func(_ string, now time.Time) error { return wdActions.flush(actTmp, now) }
	t.Cleanup(func() { wdActionsFlushFn = oldFlush })
	withTempM4Writer(t) // v5.31 审查修复: 设备发现写者同样隔离(临时路径)
}

// withNativeUnknown 检查的外部世界全部隔离成「判不了」(临时 run/、无探测
// 文件、netlink / exec 都失败), 用例因此与机器环境无关(不读真实
// /data/local/hnc/run 与本机网卡)。需要原生世界的用例在此之后自行注入。
func withNativeUnknown(t *testing.T) {
	t.Helper()
	oldRun, oldData := natRunDir, natDataDir
	oldHint, oldByN, oldAddrs, oldQ, oldExec, oldSys := ifaceHintReadFn, netInterfaceByNameFn, netIfAddrsFn, nlQdiscListFn, execCommandFn, sysIfIndexFn
	oldUnknown := nativeUnknownTotal
	natRunDir, natDataDir = t.TempDir(), t.TempDir()
	ifaceHintReadFn = func() (string, bool) { return "", false }
	netInterfaceByNameFn = func(string) (*net.Interface, error) { return nil, os.ErrNotExist }
	netIfAddrsFn = func(*net.Interface) ([]net.Addr, error) { return nil, os.ErrNotExist }
	nlQdiscListFn = func(int) ([]nlroute.Qdisc, error) { return nil, os.ErrNotExist }
	execCommandFn = func(string, ...string) (string, int, error) { return "", -1, os.ErrNotExist }
	sysIfIndexFn = func(string) (string, error) { return "", os.ErrNotExist }
	nativeUnknownTotal = 0
	t.Cleanup(func() {
		natRunDir, natDataDir = oldRun, oldData
		ifaceHintReadFn, netInterfaceByNameFn, netIfAddrsFn = oldHint, oldByN, oldAddrs
		nlQdiscListFn, execCommandFn, sysIfIndexFn = oldQ, oldExec, oldSys
		nativeUnknownTotal = oldUnknown
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
		"capability_probe":   budgetCap,
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
// 状态机口径与生产一致: hnc_state 写的是旧网卡, 热点探测报告新
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

// TestBudgetActiveUnhealthy 场景 3: 规则健康检查一直返回 1。
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
// 用真实 probeHotspot(世界: 没有新鲜的探测结果)—— 每轮跑一次 iface_detect。
func TestBudgetPendingHotspotOff(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)
	probeHotspotFn = probeHotspot               // 真实探测; withNativeUnknown 的世界里看不到热点
	hotspotIdleFn = func() bool { return true } // activity 显示 hotspot_off

	ls := newLoopState()
	st := func(int) wdState { return wdState{kind: statePending} }

	// 先手动拨一轮拿 tick 返回的间隔(应为 120s 兜底), 再按该间隔驱动。
	clk.now = clk.now.Add(intervalNormal)
	iv := ls.tick(st(0))
	if iv != intervalIdleProbe {
		t.Fatalf("PENDING + hotspot_off 的 tick 间隔 = %v, want %v", iv, intervalIdleProbe)
	}
	rec.counts["iface_detect"] = 0
	rounds := driveHour(ls, clk, st, intervalIdleProbe)
	if rounds > 30 {
		t.Fatalf("rounds = %d, want ≤ 30(120s 兜底)", rounds)
	}
	if n := rec.counts["iface_detect"]; n != rounds {
		t.Errorf("iface_detect = %d, want %d(每轮一次, 不重复)", n, rounds)
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

// ── 检查的真实实现(native.go)的 sh 预算 ─────────────────────────────
//
// ACTIVE 健康 1 小时: 热点探测只在 run/iface_detect.json 过期(5 分钟)时跑一次
// hnc_iface.sh get(iface_detect ≤ 12), 规则健康 / 上行链路全在 Go 里判(0 次 sh);
// 经 runActionFn / iface_detect 的外部进程合计 ≤ budgetNativeShTotal。
// v5.33 前同一场景还有每 30 分钟一次的 shell 对照(probe_hotspot / check_health
// 各 2 次), 原生判不了时每轮退回 shell。

const budgetNativeShTotal = 25 // capability_probe 1 + prune_dup 6 + iface_detect 12 + 余量

// withDetectFreshness 模拟 iface_detect.json 的新鲜度: iface_detect 跑过后
// natHintFresh 内读得到 iface, 之后过期。
func withDetectFreshness(rec *actionRec, iface string) {
	var last time.Time
	ifaceHintReadFn = func() (string, bool) {
		if !last.IsZero() && nowFn().Sub(last) < natHintFresh {
			return iface, true
		}
		return "", false
	}
	ifaceDetectFn = func() {
		rec.counts["iface_detect"]++
		last = nowFn()
	}
}

func TestBudgetNativeActiveHealthy(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)
	withNativeHealthy(t)
	withDetectFreshness(rec, "wlan2")
	probeHotspotFn, checkHealthFn = probeHotspot, checkHealth // 真实实现

	ls := newLoopState()
	st := func(int) wdState { return wdState{kind: stateActive, iface: "wlan2"} }
	rounds := driveHour(ls, clk, st, intervalNormal)
	if rounds != 60 {
		t.Fatalf("rounds = %d, want 60", rounds)
	}
	if n := rec.counts["iface_detect"]; n == 0 || n > budgetIfaceDetect {
		t.Errorf("iface_detect = %d 次/小时, want 1..%d(5 分钟过期才刷新)", n, budgetIfaceDetect)
	}
	if n := rec.counts["tc_uplink_healthy"]; n != 0 {
		t.Errorf("tc_uplink_healthy sh = %d(上行全绿, 不该调 shell)", n)
	}
	if rec.counts["full_restore"] != 0 || rec.counts["migrate"] != 0 {
		t.Errorf("健康世界不该有 full_restore / migrate: %v", rec.counts)
	}
	if total := rec.total(); total > budgetNativeShTotal {
		t.Errorf("sh 调用合计 = %d, 超预算 %d: %v", total, budgetNativeShTotal, rec.counts)
	}
}

// TestBudgetNativeHealthUnknownNoShell 规则健康一直判不了(netlink 失败)→
// 每轮跳过(不 full_restore), 计 native_unknown, 不调任何 shell 检查。
// 「改动前会失败」: v5.32 判不了每轮退回 shell check_health(60 次 sh)。
func TestBudgetNativeHealthUnknownNoShell(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)
	withNativeHealthy(t)
	withDetectFreshness(rec, "wlan2")
	nlQdiscListFn = func(int) ([]nlroute.Qdisc, error) { return nil, os.ErrPermission }
	probeHotspotFn, checkHealthFn = probeHotspot, checkHealth

	ls := newLoopState()
	st := func(int) wdState { return wdState{kind: stateActive, iface: "wlan2"} }
	driveHour(ls, clk, st, intervalNormal)
	for _, name := range []string{"check_health", "probe_hotspot", "full_restore"} {
		if n := rec.counts[name]; n != 0 {
			t.Errorf("%s = %d, want 0", name, n)
		}
	}
	if nativeUnknownTotal != 60 {
		t.Errorf("native_unknown = %d, want 60(每轮一次)", nativeUnknownTotal)
	}
}
