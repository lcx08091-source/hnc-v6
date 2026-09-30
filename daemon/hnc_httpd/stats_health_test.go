package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shIDs(is []shIssue) string {
	var ids []string
	for _, i := range is {
		ids = append(ids, i.Level+":"+i.ID)
	}
	return strings.Join(ids, ",")
}

func TestShIssues(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	healthy := shInput{CtActive: true, CtAcct: 1, IptChecked: true, IptJump: true, HotspotUp: true,
		SampleAge: 60, ClockSane: true, GuardKnown: true, GuardActive: true, NetstatsMode: "auto",
		NetstatsOK: true, CalStatus: "ok", DriftPct: f(1), OffloadGap: f(2), OffloadKind: "none"}
	if got := shIssues(healthy); len(got) != 0 {
		t.Fatalf("healthy → %v", got)
	}
	cases := []struct {
		mod  func(*shInput)
		want string
	}{
		{func(i *shInput) { i.ClockSane = false }, "error:clock_insane"},
		{func(i *shInput) { i.IptJump = false }, "error:iptables_chain_missing"},
		{func(i *shInput) { i.IptChecked, i.IptJump = false, false }, ""}, // iptables 跑不了: 不下结论
		{func(i *shInput) { i.IptStalled = true }, "warn:iptables_stalled"},
		{func(i *shInput) { i.CtActive = false }, "warn:ct_events_off"},
		{func(i *shInput) { i.CtLostRecent = true }, "info:ct_events_lost"},
		{func(i *shInput) { i.CtAcct = 0 }, "warn:ct_acct_off"},
		{func(i *shInput) { i.CtAcct = -1 }, ""},
		{func(i *shInput) { i.SampleAge, i.HsActive = 3600, true }, "warn:stats_sample_stale"},
		{func(i *shInput) { i.SampleAge = 3600 }, ""}, // 热点没流量, 采样器不写是正常的
		{func(i *shInput) { i.OffloadGap, i.OffloadKind = f(42), "hw" }, "warn:offload_undercount"},
		{func(i *shInput) { i.OffloadGap, i.OffloadKind, i.GuardActive = f(42), "hw", false }, "warn:offload_undercount,info:offload_guard_inactive"},
		{func(i *shInput) { i.CalStatus, i.DriftPct = "drift", f(-12) }, "warn:netstats_drift"},
		{func(i *shInput) {
			i.NetstatsOK, i.CalStatus, i.CalReason = false, "unavailable", "netstats_parse_failed"
		}, "info:netstats_unavailable"},
		{func(i *shInput) { i.NetstatsOK, i.CalStatus, i.CalReason = false, "unavailable", "pending" }, ""},
		{func(i *shInput) { i.NetstatsMode, i.CalStatus, i.DriftPct = "off", "drift", f(-50) }, ""},
		// 排序: error 在前
		{func(i *shInput) { i.CtActive, i.ClockSane = false, false }, "error:clock_insane,warn:ct_events_off"},
	}
	for n, c := range cases {
		in := healthy
		c.mod(&in)
		if got := shIDs(shIssues(in)); got != c.want {
			t.Errorf("case %d: got %q want %q", n, got, c.want)
		}
	}
	in := healthy
	in.OffloadGap, in.OffloadKind = f(37.6), "hw"
	if txt := shIssues(in)[0].TextCN; txt != "硬件分流导致漏计 ≈ 38%" {
		t.Errorf("text %q", txt)
	}
	in.OffloadKind = "bpf"
	if txt := shIssues(in)[0].TextCN; !strings.Contains(txt, "BPF") {
		t.Errorf("text %q", txt)
	}
}

func TestStatsHealthGather(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	defer clockForget(dir)
	now := time.Now()

	// 全局 ct 状态: 保存/恢复
	ctEvents.mu.Lock()
	saveActive, saveRecv, saveLost := ctEvents.active, ctEvents.received, ctEvents.lostN
	ctEvents.active, ctEvents.received, ctEvents.lostN = true, 1000, 0
	ctEvents.mu.Unlock()
	defer func() {
		ctEvents.mu.Lock()
		ctEvents.active, ctEvents.received, ctEvents.lostN = saveActive, saveRecv, saveLost
		ctEvents.mu.Unlock()
	}()

	hsBytes := uint64(1 << 30)
	ipt := uint64(5000)
	jump := true
	env := shEnv{
		hotspotIface: func() string { return "wlan2" },
		readNetDev: func() ([]byte, error) {
			return []byte(fmt.Sprintf(" wlan2: %d 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", hsBytes)), nil
		},
		iptForward: func() (string, error) {
			out := "Chain FORWARD (policy ACCEPT 1 packets, 2 bytes)\n"
			if jump {
				out += fmt.Sprintf(" 10 %d HNC_STATS all -- * * 0.0.0.0/0 0.0.0.0/0\n", ipt)
			}
			return out, nil
		},
		ctAcct: func() int { return 1 },
	}
	os.WriteFile(filepath.Join(dir, "run", "offload_guard.json"),
		[]byte(`{"mode":"auto","offload_state":"ACTIVE","fallback_active":true,"last_check":1}`), 0o644)
	st := &shState{}

	h := statsHealth(dir, env, st, now)
	if h["precise_mode"] != true || h["ct_poll_fallback"] != false || h["ct_destroy_events_per_min"] != nil ||
		h["iptables_stats_ok"] != true || h["offload_guard_active"] != true || h["clock_sane"] != true ||
		h["last_stats_sample_age"] != nil || h["netstats_available"] != false {
		t.Fatalf("first: %v", h)
	}
	if len(h["issues"].([]shIssue)) != 0 {
		t.Errorf("issues %v", h["issues"])
	}

	// 2 分钟后: 300 个事件 → 150/分钟; 热点口 +16MB, HNC_STATS 不动 → 停滞
	ctEvents.mu.Lock()
	ctEvents.received += 300
	ctEvents.mu.Unlock()
	hsBytes += 16 << 20
	h = statsHealth(dir, env, st, now.Add(2*time.Minute))
	if h["ct_destroy_events_per_min"] != 150.0 {
		t.Errorf("rate %v", h["ct_destroy_events_per_min"])
	}
	if h["iptables_stats_ok"] != false || h["iptables_stalled"] != true {
		t.Errorf("stall not detected %v", h)
	}
	if got := shIDs(h["issues"].([]shIssue)); got != "warn:iptables_stalled" {
		t.Errorf("issues %s", got)
	}

	// 计数恢复增长 + 事件丢失 + 链没了 + 对账结果带分流漏计
	ipt += 16 << 20
	hsBytes += 16 << 20
	ctEvents.mu.Lock()
	ctEvents.lostN++
	ctEvents.mu.Unlock()
	jump = false
	gap := 45.0
	c := calInstall(dir, calEnv{})
	defer func() { calReg.mu.Lock(); delete(calReg.m, dir); calReg.mu.Unlock() }()
	c.last = &calResult{Status: "ok", NetstatsOK: true, OffloadGapPct: &gap, OffloadKind: "hw"}
	os.WriteFile(filepath.Join(dir, "data", "stats_raw.jsonl"), []byte("{}\n"), 0o644)
	h = statsHealth(dir, env, st, now.Add(4*time.Minute))
	if h["ct_poll_fallback"] != true || h["iptables_stats_ok"] != false || h["offload_gap_pct"] != 45.0 ||
		h["netstats_available"] != true || h["last_stats_sample_age"] == nil {
		t.Errorf("third %v", h)
	}
	if got := shIDs(h["issues"].([]shIssue)); got != "error:iptables_chain_missing,warn:offload_undercount,info:ct_events_lost" {
		t.Errorf("issues %s", got)
	}
}
