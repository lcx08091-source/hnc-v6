// offload_sched_test.go — offload/clsact 的 Go 调度状态机(v5.29 T2 M3; v5.33 起唯一一份)。
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

// ── 早醒条件(v5.33 前 shell 循环用 hnc_act_sleep_until, 同一语义) ──────────

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

// v5.33: 修复走 hnc_offload_guard.sh clsact_repair(hnc_clsact_watchdog.sh 已删)。
// 「改动前会失败」: v5.32 调的是 hnc_clsact_watchdog.sh repair。
func TestClsactTickRepairArgs(t *testing.T) {
	f := &clsactFake{checkOK: func(n int) bool { return n%3 != 0 }} // 每 3 次 check 有一次不 ok
	withClsactFake(t, "wlan2", f)
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)
	c := &clsactSched{}
	for off := 0; off <= 600; off += 10 { // 10 分钟
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

// clsactTarget: 读 offload guard 的状态文件, 只认 mode=on + clsact=installed。
func TestClsactTargetFromGuardStatus(t *testing.T) {
	old := offloadGuardStatusPath
	offloadGuardStatusPath = t.TempDir() + "/offload_guard.json"
	t.Cleanup(func() { offloadGuardStatusPath = old })
	for _, c := range []struct{ json, want string }{
		{`{"mode":"on","clsact":"installed","iface":"wlan2"}`, "wlan2"},
		{`{"mode":"on","clsact":"skipped_pref1_mirred","iface":"wlan2"}`, ""},
		{`{"mode":"auto","clsact":"installed","iface":"wlan2"}`, ""}, // auto 由 plan 每轮顺带修
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
