package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeMono 替换 clockMono, 测试结束恢复
func fakeMono(t *testing.T) *time.Duration {
	t.Helper()
	var m time.Duration = time.Hour
	old := clockMono
	clockMono = func() time.Duration { return m }
	t.Cleanup(func() { clockMono = old })
	return &m
}

func clockTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"data", "run"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	t.Cleanup(func() { clockForget(dir) })
	return dir
}

func TestClockSaneAt(t *testing.T) {
	loc := time.Local
	cases := []struct {
		now  time.Time
		hwm  int64
		want bool
	}{
		{time.Unix(0, 0), 0, false},                                                                        // 1970
		{time.Date(2000, 1, 1, 0, 0, 0, 0, loc), 0, false},                                                 // 常见 RTC 默认
		{time.Date(2024, 12, 31, 23, 0, 0, 0, loc), 0, false},                                              // < 2025
		{time.Date(2025, 1, 2, 0, 0, 0, 0, loc), 0, true},                                                  // 无高水位
		{time.Date(2026, 9, 30, 12, 0, 0, 0, loc), 0, true},                                                //
		{time.Date(2026, 9, 30, 12, 0, 0, 0, loc), time.Date(2026, 9, 30, 12, 5, 0, 0, loc).Unix(), true},  // 落后 5 分钟: 容忍
		{time.Date(2026, 9, 30, 12, 0, 0, 0, loc), time.Date(2026, 9, 30, 13, 0, 0, 0, loc).Unix(), false}, // 落后 1 小时: 过期 RTC
		{time.Date(2026, 9, 30, 12, 0, 0, 0, loc), time.Date(2026, 9, 29, 0, 0, 0, 0, loc).Unix(), true},   // 高水位之后
	}
	for i, c := range cases {
		if got := clockSaneAt(c.now, c.hwm); got != c.want {
			t.Errorf("case %d: clockSaneAt(%s, %d) = %v, want %v", i, c.now, c.hwm, got, c.want)
		}
	}
}

func TestClockGuardJumps(t *testing.T) {
	dir := clockTestDir(t)
	t0 := time.Date(2026, 9, 30, 10, 0, 0, 0, time.Local)
	mono := time.Hour
	g := clockGuard{name: "t"}
	step := func(wall time.Time, dm time.Duration) clockVerdict {
		mono += dm
		return g.check(dir, wall, mono)
	}
	if v := step(t0, 0); v != clockOK {
		t.Fatalf("first = %v", v)
	}
	if v := step(t0.Add(10*time.Second), 10*time.Second); v != clockOK {
		t.Fatalf("steady = %v", v)
	}
	// 小幅校时(墙钟比单调多 3 分钟)不算跳变
	if v := step(t0.Add(3*time.Minute+20*time.Second), 10*time.Second); v != clockOK {
		t.Fatalf("small correction = %v", v)
	}
	// 前跳 2 小时(单调只过了 10 秒)
	if v := step(t0.Add(2*time.Hour+3*time.Minute+30*time.Second), 10*time.Second); v != clockJump {
		t.Fatalf("forward jump = %v", v)
	}
	// 跳变后下一轮恢复正常
	if v := step(t0.Add(2*time.Hour+3*time.Minute+40*time.Second), 10*time.Second); v != clockOK {
		t.Fatalf("after jump = %v", v)
	}
	// 回跳 1 小时: 落后高水位 → 不可信
	if v := step(t0.Add(1*time.Hour+4*time.Minute), 10*time.Second); v != clockInsane {
		t.Fatalf("backward jump beyond tolerance = %v", v)
	}
	// 时钟追回来(短暂不可信) → 与上次可信采样比: 墙钟 +20s vs 单调 +20s → OK
	if v := step(t0.Add(2*time.Hour+4*time.Minute), 10*time.Second); v != clockOK {
		t.Fatalf("recovered after short insane = %v", v)
	}
	// 回跳 5 分钟以内(容忍)但 > 阈值? 5 分钟 < 10 分钟阈值 → OK
	if v := step(t0.Add(2*time.Hour-1*time.Minute+10*time.Second), 10*time.Second); v != clockOK {
		t.Fatalf("small backward = %v", v)
	}
	st := readClockState(t, dir)
	if !strings.Contains(st, `"jumps":1`) {
		t.Fatalf("clock_state.json = %s", st)
	}
}

func TestClockGuardLongInsaneThenSane(t *testing.T) {
	dir := clockTestDir(t)
	g := clockGuard{name: "t"}
	mono := time.Minute
	// 开机 1970, 30 分钟后才对时
	for i := 0; i < 3; i++ {
		if v := g.check(dir, time.Unix(int64(i*600), 0), mono); v != clockInsane {
			t.Fatalf("1970 tick %d = %v", i, v)
		}
		mono += 10 * time.Minute
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "clock_state.json")); err != nil {
		t.Fatal("clock_state.json should be written on insane")
	}
	if v := g.check(dir, time.Date(2026, 9, 30, 8, 0, 0, 0, time.Local), mono); v != clockJump {
		t.Fatalf("recover after 30min insane = %v, want jump (re-baseline)", v)
	}
	// 短暂不可信(1 分钟)后恢复 → OK(积压的差分正常记)
	g2 := clockGuard{name: "t2"}
	dir2 := clockTestDir(t)
	if v := g2.check(dir2, time.Unix(100, 0), time.Minute); v != clockInsane {
		t.Fatalf("insane = %v", v)
	}
	if v := g2.check(dir2, time.Date(2026, 9, 30, 8, 0, 0, 0, time.Local), 2*time.Minute); v != clockOK {
		t.Fatalf("recover after short insane = %v", v)
	}
}

func TestClockHighWaterPersistAndHeal(t *testing.T) {
	dir := clockTestDir(t)
	t0 := time.Date(2026, 9, 30, 10, 0, 0, 0, time.Local)
	clockNote(dir, t0)
	b, err := os.ReadFile(filepath.Join(dir, "data", "clock_hwm"))
	if err != nil || strings.TrimSpace(string(b)) != strconv.FormatInt(t0.Unix(), 10) {
		t.Fatalf("clock_hwm = %q, %v", b, err)
	}
	// 1 分钟后的推进不立即落盘(节流), 内存已推进
	clockNote(dir, t0.Add(time.Minute))
	if clockHighWater(dir) != t0.Add(time.Minute).Unix() {
		t.Fatal("in-memory high-water not advanced")
	}
	b, _ = os.ReadFile(filepath.Join(dir, "data", "clock_hwm"))
	if strings.TrimSpace(string(b)) != strconv.FormatInt(t0.Unix(), 10) {
		t.Fatalf("high-water persisted too often: %s", b)
	}
	clockNote(dir, t0.Add(6*time.Minute))
	b, _ = os.ReadFile(filepath.Join(dir, "data", "clock_hwm"))
	if strings.TrimSpace(string(b)) != strconv.FormatInt(t0.Add(6*time.Minute).Unix(), 10) {
		t.Fatalf("high-water not persisted after 5min: %s", b)
	}
	// 重启(内存丢弃)后读回: 过期 RTC(落后 1 天)不可信
	clockForget(dir)
	stale := t0.Add(-24 * time.Hour)
	if clockSaneMono(dir, stale, time.Minute) {
		t.Fatal("stale RTC behind persisted high-water must be insane")
	}
	// 高水位本身错(曾跑到未来): 年份合法且持续落后 6 小时 → 自愈
	if clockSaneMono(dir, stale.Add(5*time.Hour), time.Minute+5*time.Hour) {
		t.Fatal("should not heal before 6h")
	}
	if !clockSaneMono(dir, stale.Add(6*time.Hour), time.Minute+6*time.Hour) {
		t.Fatal("should heal after 6h behind")
	}
	if clockHighWater(dir) != stale.Add(6*time.Hour).Unix() {
		t.Fatal("high-water should be reset to now after heal")
	}
}

func readClockState(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "run", "clock_state.json"))
	if err != nil {
		t.Fatalf("clock_state.json: %v", err)
	}
	return string(b)
}

// ─── 写入器: app_usage ───────────────────────────────────────────

func TestAppUsageClockGuard(t *testing.T) {
	dir := clockTestDir(t)
	mono := fakeMono(t)
	w := func(p, s string) {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("data/devices.json", `{"aa:bb:cc:00:00:01":{"ip":"192.168.43.12"}}`)
	t.Setenv("HNC_CONNTRACK_PATH", filepath.Join(dir, "ct"))
	t.Setenv("HNC_CONNTRACK_ACCT_PATH", filepath.Join(dir, "acct"))
	line := func(up, dn int) string {
		return "ipv4 2 tcp 6 300 ESTABLISHED src=192.168.43.12 dst=9.9.9.9 sport=1000 dport=443 packets=1 bytes=" + itoa(up) +
			" src=9.9.9.9 dst=10.0.0.1 sport=443 dport=1000 packets=1 bytes=" + itoa(dn) + " mark=0 use=1\n"
	}
	feed := func(up, dn int) {
		w("ct", line(up, dn))
		ctState.mu.Lock()
		ctState.snap, ctState.prev, ctState.acctTried = nil, nil, true
		ctState.mu.Unlock()
	}
	resetAU := func() {
		appUsage.mu.Lock()
		appUsage.day, appUsage.prev, appUsage.init, appUsage.dirty = nil, nil, false, false
		appUsage.guard = clockGuard{}
		appTimeLastTick = time.Time{}
		appUsage.mu.Unlock()
	}
	resetAU()
	t.Cleanup(resetAU)
	s := newServer(dir)
	t0 := time.Date(2026, 9, 30, 10, 0, 0, 0, time.Local)
	adv := func(d time.Duration) { *mono += d }

	feed(100, 1000)
	if got := s.appUsageTick(t0); got != 0 {
		t.Fatalf("baseline = %d", got)
	}
	// 时钟回到 1970: 不记账, 不写 19700101 文件
	feed(200, 2000)
	adv(10 * time.Second)
	if got := s.appUsageTick(time.Unix(50, 0)); got != 0 {
		t.Fatalf("insane tick counted %d", got)
	}
	s.appUsageFlush(time.Unix(60, 0))
	if _, err := os.Stat(appUsagePath(dir, "19700101")); err == nil {
		t.Fatal("wrote 1970 day file")
	}
	// 短暂不可信后恢复: 积压的差分(未被不可信轮消费)记到正确的天
	feed(300, 3000)
	adv(10 * time.Second)
	if got := s.appUsageTick(t0.Add(20 * time.Second)); got != 200+2000 {
		t.Fatalf("after short insane = %d, want 2200", got)
	}
	// 墙钟前跳 3 小时(单调只过 10 秒): 重建基线, 不记这一段
	feed(10_300, 100_000)
	adv(10 * time.Second)
	if got := s.appUsageTick(t0.Add(3*time.Hour + 30*time.Second)); got != 0 {
		t.Fatalf("jump tick counted %d", got)
	}
	// 跳变后正常差分
	feed(10_400, 100_500)
	adv(10 * time.Second)
	if got := s.appUsageTick(t0.Add(3*time.Hour + 40*time.Second)); got != 600 {
		t.Fatalf("post-jump delta = %d, want 600", got)
	}
	s.appUsageFlush(t0.Add(3*time.Hour + time.Minute))
	d := loadAppUsageDay(dir, "20260930")
	var tot uint64
	for h, cells := range d.Hours {
		for _, v := range cells {
			tot += v[0] + v[1]
		}
		if h != "10" && h != "13" {
			t.Fatalf("unexpected hour bucket %s", h)
		}
	}
	if tot != 2200+600 {
		t.Fatalf("day total = %d, want 2800", tot)
	}
}

// ─── 写入器: phone_usage ─────────────────────────────────────────

func TestPhoneUsageClockGuard(t *testing.T) {
	dir := clockTestDir(t)
	mono := fakeMono(t)
	t0 := time.Date(2026, 9, 30, 10, 0, 0, 0, time.Local)
	f := &puFake{boot: "boot-A", route: "rmnet_data0",
		sim: puSIM{Slot: 1, Carrier: "中国移动", SubID: 1, Source: "settings"},
		ctr: map[string][2]uint64{"rmnet_data0": {1000, 1000}}}
	e := newPuEngine(dir, f.env())
	e.tick(t0) // 基线
	// 不可信: 不消费计数器
	f.ctr["rmnet_data0"] = [2]uint64{2000, 1500}
	*mono += time.Minute
	if out := e.tick(time.Date(2000, 1, 1, 0, 0, 0, 0, time.Local)); out != nil {
		t.Fatalf("insane tick = %v", out)
	}
	e.flush(time.Date(2000, 1, 1, 0, 0, 0, 0, time.Local))
	if _, ok := puLoadDay(dir, "20000101"); ok {
		t.Fatal("wrote 2000 day file")
	}
	if _, err := os.Stat(puStatePath(dir)); err == nil {
		t.Fatal("state saved while clock insane")
	}
	// 恢复(短): 增量记到今天
	*mono += time.Minute
	if out := e.tick(t0.Add(2 * time.Minute)); out["cell"] != [2]uint64{1000, 500} {
		t.Fatalf("recovered = %v", out)
	}
	// 回跳到昨天 23:50(落后高水位 > 10 分钟)→ 不可信, 不记到昨天
	f.ctr["rmnet_data0"] = [2]uint64{3000, 1600}
	*mono += time.Minute
	if out := e.tick(t0.Add(-10*time.Hour - 10*time.Minute)); out != nil {
		t.Fatalf("backward jump tick = %v", out)
	}
	// 前跳 5 小时 → 重建基线
	f.ctr["rmnet_data0"] = [2]uint64{9000, 9000}
	*mono += time.Minute
	if out := e.tick(t0.Add(5 * time.Hour)); out != nil {
		t.Fatalf("jump tick = %v", out)
	}
	f.ctr["rmnet_data0"] = [2]uint64{9100, 9050}
	*mono += time.Minute
	if out := e.tick(t0.Add(5*time.Hour + time.Minute)); out["cell"] != [2]uint64{100, 50} {
		t.Fatalf("post-jump = %v", out)
	}
	e.flush(t0.Add(5*time.Hour + time.Minute))
	d, ok := puLoadDay(dir, "20260930")
	if !ok {
		t.Fatal("day file missing")
	}
	if d.Cell["1|中国移动"] != [2]uint64{1100, 550} {
		t.Fatalf("day cell = %v", d.Cell)
	}
	if _, ok := puLoadDay(dir, "20260929"); ok {
		t.Fatal("bytes attributed to the wrong (previous) day")
	}
}

// ─── 写入器: limit_policy 用量 ───────────────────────────────────

func TestLimitCtlClockGuard(t *testing.T) {
	mono := fakeMono(t)
	f := newFixture(t)
	t.Cleanup(func() { clockForget(f.dir) })
	f.rules[tMAC] = limitRule{DownKbit: 10000}
	f.writeRules()
	if r := f.c.actionQuotaSet(map[string]string{"mac": tMAC, "daily_gb": "1", "action": "block"}); !r.OK {
		t.Fatalf("quota set: %+v", r)
	}
	t0 := time.Date(2026, 9, 30, 10, 0, 0, 0, time.Local)
	f.writeDevices(map[string][2]int64{tMAC: {1000, 1000}})
	f.c.tick(t0)
	f.writeDevices(map[string][2]int64{tMAC: {6000, 1000}})
	*mono += time.Minute
	f.c.tick(t0.Add(time.Minute))
	used := func() (string, uint64) {
		f.c.mu.Lock()
		defer f.c.mu.Unlock()
		u := f.c.st.Devices[tMAC].Usage
		return u.DayKey, u.DayBytes
	}
	if k, b := used(); k != "2026-09-30" || b != 5000 {
		t.Fatalf("usage = %s %d", k, b)
	}
	// 时钟回到 1970: 不 rollover(不清零用量), 不落盘
	f.writeDevices(map[string][2]int64{tMAC: {7000, 1000}})
	*mono += time.Minute
	f.c.tick(time.Unix(120, 0))
	if k, b := used(); k != "2026-09-30" || b != 5000 {
		t.Fatalf("insane tick touched usage: %s %d", k, b)
	}
	// 短暂后恢复: 积压的 1000 记入今天
	*mono += time.Minute
	f.c.tick(t0.Add(3 * time.Minute))
	if _, b := used(); b != 6000 {
		t.Fatalf("after recovery = %d, want 6000", b)
	}
	// 前跳 4 小时 + 期间计数器涨了 100MB: 重建基线, 不记这一坨
	f.writeDevices(map[string][2]int64{tMAC: {100_007_000, 1000}})
	*mono += time.Minute
	f.c.tick(t0.Add(4 * time.Hour))
	if _, b := used(); b != 6000 {
		t.Fatalf("jump attributed delta: %d", b)
	}
	f.writeDevices(map[string][2]int64{tMAC: {100_008_000, 1000}})
	*mono += time.Minute
	f.c.tick(t0.Add(4*time.Hour + time.Minute))
	if _, b := used(); b != 7000 {
		t.Fatalf("post-jump = %d, want 7000", b)
	}
}

// ─── 写入器: app_time 告警去重状态 ──────────────────────────────

func TestAppTimeEnforceClockGuard(t *testing.T) {
	resetAppTimeGlobals(t)
	dir, s := setupAppCtlDir(t)
	t.Cleanup(func() { clockForget(dir) })
	mac := "aa:bb:cc:00:00:01"
	now := time.Now()
	setTodayActive(now, mac+"|douyin", 55*60)
	if r := actionAppTimeLimitSet(s, map[string]string{"mac": mac, "app_id": "douyin", "minutes": "60"}); !r.OK {
		t.Fatalf("set: %+v", r)
	}
	// 1970: 不判定、不写 app_time_alerts.json / alerts.jsonl
	s.appTimeEnforce(time.Unix(1000, 0))
	if _, err := os.Stat(appTimeAlertStatePath(dir)); err == nil {
		t.Fatal("alert state written while clock insane")
	}
	if strings.Contains(readFileStr(filepath.Join(dir, "run", "alerts.jsonl")), "app_time") {
		t.Fatal("alert emitted while clock insane")
	}
	s.appTimeEnforce(now)
	if strings.Count(readFileStr(filepath.Join(dir, "run", "alerts.jsonl")), `"app_time_warn"`) != 1 {
		t.Fatal("warn alert missing once clock is sane")
	}
}
