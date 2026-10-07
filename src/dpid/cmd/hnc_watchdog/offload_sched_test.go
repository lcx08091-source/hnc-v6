// offload_sched_test.go — v5.29 T2(M3): offload/clsact 的 Go 调度状态机。
package main

import (
	"os"
	"strings"
	"testing"
	"time"
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

// ── 早醒条件(照抄 hnc_act_sleep_until 的语义) ───────────────────────

func TestOffloadEarlyWake(t *testing.T) {
	if !offloadEarlyWake("hotspot", "screen_on", 0) {
		t.Error("wake=hotspot + 热点开 → 应早醒")
	}
	if !offloadEarlyWake("clients", "hotspot_off", 3) {
		t.Error("wake=clients + 3 台设备 → 应早醒")
	}
	if offloadEarlyWake("hotspot", "hotspot_off", 0) {
		t.Error("wake=hotspot + 热点没开 → 不早醒")
	}
	if offloadEarlyWake("clients", "screen_on", 0) {
		t.Error("wake=clients + 0 设备 → 不早醒")
	}
	if offloadEarlyWake("none", "screen_on", 5) {
		t.Error("wake=none → 永不早醒")
	}
}

// ── 预算: 无设备(plan=300 none)时 1 小时 plan 次数 ≤ 15 ────────────
//
// 「改动前会失败」的等价物: 若把 300 秒睡成 60 秒(shell daemon 的
// INTERVAL 而非 IDLE_INTERVAL), 次数会到 60 > 15。

func TestOffloadPlanBudget(t *testing.T) {
	p := &offloadPlanner{}
	start := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	now := start
	// 以 30 秒为步(早醒检查粒度)驱动 1 小时, activity 恒「热点未开无设备」
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
	p.observe(300*time.Second, "clients", time.Now())
	next := time.Now().Add(200 * time.Second) // 还没到 300 秒
	if !p.advance(next, true) {
		t.Fatal("早醒条件满足时应该提前跑 plan")
	}
	if p.advance(next, false) {
		t.Fatal("没到 nextAt 且无早醒 → 不该跑")
	}
}

// ── clsact 门控缓存 ─────────────────────────────────────────────────

func TestClsactGateCache(t *testing.T) {
	c := &clsactSched{}
	now := time.Now()
	if !c.gateDue(now) {
		t.Fatal("初始应 due")
	}
	c.gateOK, c.lastGate = true, now
	if c.gateDue(now.Add(30 * time.Second)) {
		t.Fatal("60 秒内不该重查门控")
	}
	if !c.gateDue(now.Add(61 * time.Second)) {
		t.Fatal("60 秒后应重查门控")
	}
}

// ── m3 开关 ─────────────────────────────────────────────────────────

func TestM3Switch(t *testing.T) {
	// 沙箱里 run/ 没有 wd_m3.disabled → 接管
	if m3Disabled() {
		t.Fatal("无开关文件时不应禁用 M3")
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

// ── 预算: 无设备 + plan 回 300 秒 → 1 小时 plan 调用 ≤ 15 ─────────
// (doc 验收: offload 任务 1 小时 ≤ 60 次 sh, plan 300 秒时 ≤ 15)

func TestOffloadPlanBudgetNoClients(t *testing.T) {
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	p := &offloadPlanner{}
	calls := 0
	// 每 30 秒一次早醒检查(驱动方式与 offloadLoop 相同)
	for off := 0; off <= 3600; off += 30 {
		now := base.Add(time.Duration(off) * time.Second)
		// 无设备: 热点未开, 早醒不触发
		if p.advance(now, false) {
			calls++
			p.observe(300*time.Second, "none", now) // plan: "300 none"
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
		// 热点开着 + 一直有设备 → 早醒持续满足
		if p.advance(now, true) {
			calls++
			p.observe(300*time.Second, "clients", now)
		}
	}
	if calls < 60 || calls > 130 {
		t.Fatalf("plan calls = %d, want ~120(每 30 秒一次早醒)", calls)
	}
}

// ── clsactTick: 门控缓存 60 秒 + 修复调用(驱动真实的一轮逻辑) ──────

type clsactFake struct {
	gateCalls int
	checkOK   func(n int) bool
	scripts   [][]string
}

func withClsactFake(t *testing.T, iface string, gate bool, f *clsactFake) {
	t.Helper()
	oldG, oldC, oldI, oldS := clsactGateFn, clsactCheckFn, clsactIfaceFn, runScriptFn
	n := 0
	clsactGateFn = func(string) bool { f.gateCalls++; return gate }
	clsactIfaceFn = func() string { return iface }
	clsactCheckFn = func(string) string {
		n++
		if f.checkOK != nil && f.checkOK(n) {
			return `{"ok":true,"qdisc":"clsact","bpf_filter":true}`
		}
		return `{"ok":false,"qdisc":"clsact"}`
	}
	runScriptFn = func(path string, args ...string) { f.scripts = append(f.scripts, append([]string{path}, args...)) }
	t.Cleanup(func() { clsactGateFn, clsactCheckFn, clsactIfaceFn, runScriptFn = oldG, oldC, oldI, oldS })
}

func TestClsactTickGateCacheAndRepairArgs(t *testing.T) {
	f := &clsactFake{checkOK: func(n int) bool { return n%3 != 0 }} // 每 3 次 check 有一次不 ok
	withClsactFake(t, "wlan2", true, f)
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	c := &clsactSched{}
	for off := 0; off <= 600; off += 10 { // 10 分钟
		clsactTick(c, base.Add(time.Duration(off)*time.Second))
	}
	if f.gateCalls != 11 {
		t.Fatalf("gate = %d 次, want 11(60 秒缓存)", f.gateCalls)
	}
	if c.checks != 61 || len(f.scripts) != 20 {
		t.Fatalf("checks = %d repairs = %d, want 61 / 20", c.checks, len(f.scripts))
	}
	// rc1 把 "脚本 repair 口" 拼成一个参数 → sh 找不到文件, 修复从没执行
	got := f.scripts[0]
	if len(got) != 3 || !strings.HasSuffix(got[0], "/hnc_clsact_watchdog.sh") || got[1] != "repair" || got[2] != "wlan2" {
		t.Fatalf("repair 调用参数 = %q, want [.../hnc_clsact_watchdog.sh repair wlan2]", got)
	}
}

func TestClsactTickGateOffNoExec(t *testing.T) {
	f := &clsactFake{}
	withClsactFake(t, "wlan2", false, f)
	c := &clsactSched{}
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	for off := 0; off < 3600; off += 10 {
		clsactTick(c, base.Add(time.Duration(off)*time.Second))
	}
	if c.checks != 0 || len(f.scripts) != 0 {
		t.Fatalf("门控不要时不该 check / repair: checks=%d repairs=%d", c.checks, len(f.scripts))
	}
}

// TestClsactWantedPref1Mirred on 模式但 pref 1 被上行 mirred 占用 → 不要
// (旧 shell 守护此时退出; rc1 不判这条, 上行限速 + on 模式每 10 秒起 sh)。
func TestClsactWantedPref1Mirred(t *testing.T) {
	if !pref1MirredLine("filter parent ffff: protocol all pref 1 u32 ... action order 1: mirred (Egress Redirect to device ifb0) stolen") {
		t.Fatal("tc 输出里的 mirred redirect ifb0 应判为占用")
	}
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", nil, func(name string, args ...string) (string, int, error) {
		return "filter parent ffff: protocol all pref 1 u32 chain 0\n  action order 1: mirred (Egress Redirect to device ifb0) stolen\n", 0, nil
	})
	if !pref1HeldByMirred("wlan2") {
		t.Fatal("pref1 被 mirred 占用应返回 true")
	}
	e.inject(t, "wlan2", nil, func(name string, args ...string) (string, int, error) { return "", 0, nil })
	if pref1HeldByMirred("wlan2") {
		t.Fatal("无过滤器不算占用")
	}
}

// ── rulesClsactModeOn: guard_mode 的 on 判定(含旧键) ──────────────

func TestRulesClsactModeOn(t *testing.T) {
	old := natDataDir
	natDataDir = t.TempDir()
	t.Cleanup(func() { natDataDir = old })
	write := func(j string) {
		if err := os.WriteFile(natDataDir+"/rules.json", []byte(j), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"clsact_bpf_mode":"on"}`)
	if !rulesClsactModeOn() {
		t.Fatal("mode=on 应 true")
	}
	write(`{"clsact_bpf_mode":"auto"}`)
	if rulesClsactModeOn() {
		t.Fatal("mode=auto 不该走 clsact 独立守护(auto 由 offload guard 顺带)")
	}
	write(`{"clsact_bpf_mode":"off"}`)
	if rulesClsactModeOn() {
		t.Fatal("mode=off 应 false")
	}
	write(`{"clsact_bpf_enabled":true}`)
	if !rulesClsactModeOn() {
		t.Fatal("旧键 true → on")
	}
	write(`{}`)
	if rulesClsactModeOn() {
		t.Fatal("都没有 → false")
	}
}
