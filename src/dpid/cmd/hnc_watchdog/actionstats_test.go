// actionstats_test.go — v5.28 A2: 动作记账 / 失败分类 / 小时桶 / 文件格式。
package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestActionFailedClassification 失败分类表: 每个动作的正常码 / 失败码。
func TestActionFailedClassification(t *testing.T) {
	cases := []struct {
		name string
		rc   int
		err  error
		fail bool
		why  string
	}{
		{"probe_hotspot", 0, nil, false, "热点开着"},
		{"probe_hotspot", 1, nil, false, "热点没开是正常结果"},
		{"check_health", 1, nil, false, "规则丢(触发 restore 的正常信号)"},
		{"check_health", 2, nil, false, "xtables 锁忙"},
		{"check_health", 3, nil, true, "未知码"},
		{"is_doze", 1, nil, false, "不在 Doze"},
		{"tc_uplink_healthy", 0, nil, false, "成功"},
		{"tc_uplink_healthy", 127, nil, true, "v5.26 真机事故: 脚本内命令不存在"},
		{"tc_uplink_healthy", 126, nil, true, "命令不可执行"},
		{"migrate", 64, nil, true, "未知动作"},
		{"full_init", -1, errors.New("action full_init timed out"), true, "超时"},
		{"rotate_logs", -1, nil, true, "rc=-1(超时)即使 err 被清也按失败"},
		{"rotate_logs", 1, nil, true, "不在正常码表的动作非零即失败"},
	}
	for _, c := range cases {
		if got := actionFailed(c.name, c.rc, c.err); got != c.fail {
			t.Errorf("actionFailed(%s, rc=%d, err=%v) = %v, want %v(%s)",
				c.name, c.rc, c.err, got, c.fail, c.why)
		}
	}
}

// TestActionStatsHourBuckets 小时桶滚动: 前一小时的数据滚出 1h 窗口,
// 24 小时前的桶被淘汰。
func TestActionStatsHourBuckets(t *testing.T) {
	s := &actionStats{m: make(map[string]*actionCounter)}
	base := time.Date(2026, 10, 4, 12, 30, 0, 0, time.Local)

	s.record("probe_hotspot", 0, nil, 10, base)                     // 12:30 桶
	s.record("probe_hotspot", 0, nil, 20, base.Add(20*time.Minute)) // 12:50 桶(同小时)

	snap := s.snapshot(base.Add(30 * time.Minute))
	if got := snap.Actions["probe_hotspot"].Calls1H; got != 2 {
		t.Fatalf("同一小时两次调用 calls_1h = %d, want 2", got)
	}
	if got := snap.Actions["probe_hotspot"].AvgMS; got != 15 {
		t.Errorf("avg_ms = %v, want 15", got)
	}
	if got := snap.Actions["probe_hotspot"].MaxMS; got != 20 {
		t.Errorf("max_ms = %v, want 20", got)
	}

	// 13:31 快照: 12 点的桶(起点 12:00)已早于 12:31 → 滚出 1h 窗口
	s.record("probe_hotspot", 0, nil, 5, base.Add(61*time.Minute)) // 13:31 桶
	snap = s.snapshot(base.Add(61 * time.Minute))
	if got := snap.Actions["probe_hotspot"].Calls1H; got != 1 {
		t.Errorf("跨小时后 calls_1h = %d, want 1(旧桶滚出)", got)
	}

	// 25 小时前再记一桶(桶键极老), 再快照应只剩近 24h 的桶(内部淘汰)。
	old := base.Add(-25 * time.Hour)
	s.record("probe_hotspot", 0, nil, 1, old)
	if n := len(s.m["probe_hotspot"].buckets); n > 24 {
		t.Errorf("桶数 = %d, 应 ≤ 24(懒淘汰)", n)
	}
}

// TestActionStatsFlushFileFormat 落盘文件格式 + 失败字段 + 排序。
func TestActionStatsFlushFileFormat(t *testing.T) {
	s := &actionStats{m: make(map[string]*actionCounter)}
	base := time.Date(2026, 10, 4, 12, 0, 5, 0, time.Local)

	s.record("check_health", 0, nil, 100, base)
	s.record("check_health", 0, nil, 300, base)
	s.record("tc_uplink_healthy", 127, nil, 50, base) // 失败(v5.26 场景)
	s.record("probe_hotspot", 1, nil, 30, base)       // 正常非零

	dir := t.TempDir()
	path := filepath.Join(dir, "watchdog_actions.json")
	if err := s.flush(path, base.Add(time.Minute)); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("原子写应不留 .tmp 残留")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var out wdActionOut
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("json: %v", err)
	}
	if out.Schema != 1 {
		t.Errorf("schema = %d, want 1", out.Schema)
	}
	ch := out.Actions["check_health"]
	if ch.Calls1H != 2 || ch.Fails1H != 0 || ch.LastRC != 0 {
		t.Errorf("check_health = %+v", ch)
	}
	if ch.AvgMS != 200 || ch.MaxMS != 300 {
		t.Errorf("check_health avg/max = %v/%v, want 200/300", ch.AvgMS, ch.MaxMS)
	}
	up := out.Actions["tc_uplink_healthy"]
	if up.Fails1H != 1 || up.LastRC != 127 || up.LastFailAt == 0 {
		t.Errorf("tc_uplink_healthy = %+v, want fails=1 last_rc=127 last_fail_at>0", up)
	}
	ph := out.Actions["probe_hotspot"]
	if ph.Fails1H != 0 || ph.LastRC != 1 {
		t.Errorf("probe_hotspot rc=1 不算失败: %+v", ph)
	}
	// order: calls_1h 降序(check_health 2 → probe/tc 1, 按名字 probe < tc)
	if len(out.Order) != 3 || out.Order[0] != "check_health" {
		t.Errorf("order = %v, want check_health 在首位(次数降序)", out.Order)
	}
	if got := out.actionsTotal1H(); got != 4 {
		t.Errorf("actionsTotal1H = %d, want 4", got)
	}
}

// TestActionStatsRecordFailedAt last_fail_at 滚动更新。
func TestActionStatsRecordFailedAt(t *testing.T) {
	s := &actionStats{m: make(map[string]*actionCounter)}
	base := time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)
	s.record("full_init", 0, nil, 1, base)
	if s.m["full_init"].hasFail {
		t.Fatal("成功调用不应置 hasFail")
	}
	failAt := base.Add(3 * time.Minute)
	s.record("full_init", 127, nil, 1, failAt)
	snap := s.snapshot(base.Add(4 * time.Minute))
	if got := snap.Actions["full_init"].LastFailAt; got != failAt.Unix() {
		t.Errorf("last_fail_at = %d, want %d", got, failAt.Unix())
	}
}

// TestBudgetFlushInTick 记账随 tick 每分钟落盘(不新开循环)。
func TestBudgetFlushInTick(t *testing.T) {
	if _, err := os.Stat(runDir); err == nil {
		t.Skip("沙箱里 run/ 存在时跳过(会写真 /data/local/hnc)")
	}
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)
	flushed := 0
	oldFlush := wdActionsFlushFn
	wdActionsFlushFn = func(string, time.Time) error { flushed++; return nil }
	t.Cleanup(func() { wdActionsFlushFn = oldFlush })

	ls := newLoopState()
	st := func(int) wdState { return wdState{kind: stateActive, iface: "wlan0"} }
	driveHour(ls, clk, st, intervalNormal)
	// 60 分钟 / 60s 节奏 → 每轮都到 60s 间隔, 60 次落盘
	if flushed != 60 {
		t.Errorf("flush 次数 = %d, want 60(每分钟一次)", flushed)
	}
}
