// online_minutes_test.go — v5.30 T1a: 在线时长按分钟累计。
//
// 「改动前会失败」: v5.29 的 sampleOnlineHours 每 ~55 分钟采样一次, 写的行
// 没有 m 字段(httpd 一行算 1 小时)。TestHandleActiveOnlineOnceIs5Min 驱动
// 真实调用方 loopState.tick → handleActive, 断言只在一次采样时在线的设备
// 落盘为 "m":5 —— 旧代码下该行不存在 m(且旧代码没有 onlineAcc, 编译即失败)。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var cst = time.FixedZone("CST", 8*3600)

// withTempOnlineAcc 把包级 onlineAcc 换成临时目录里的实例(时钟一律可信),
// 返回它; 测试结束恢复。
func withTempOnlineAcc(t *testing.T) *onlineAccum {
	t.Helper()
	dir := t.TempDir()
	old := onlineAcc
	a := newOnlineAccum(filepath.Join(dir, "online_hours.jsonl"), filepath.Join(dir, "devices.json"))
	a.clockOK = func(time.Time) bool { return true }
	a.failLog = func(string, ...any) {}
	onlineAcc = a
	t.Cleanup(func() { onlineAcc = old })
	return a
}

// setDevices 写 devices.json: online 里的 MAC 的 last_seen = now(在线), 其余离线。
func setDevices(t *testing.T, a *onlineAccum, now time.Time, online ...string) {
	t.Helper()
	var parts []string
	for _, m := range online {
		parts = append(parts, fmt.Sprintf(`"%s":{"status":"allowed","last_seen":%d}`, m, now.Unix()))
	}
	parts = append(parts, fmt.Sprintf(`"aa:bb:cc:00:00:99":{"status":"allowed","last_seen":%d}`, now.Unix()-3600))
	if err := os.WriteFile(a.devices, []byte("{"+strings.Join(parts, ",")+"}"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

const macA, macB = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"

func TestOnlineAccumSingleSampleIs5Min(t *testing.T) {
	a := withTempOnlineAcc(t)
	t0 := time.Date(2026, 10, 7, 10, 0, 0, 0, cst)
	setDevices(t, a, t0, macA)
	a.sample(t0)
	if got := a.pending[onlineKey{"20261007", macA}]; got != 5 {
		t.Fatalf("单次采样记 %d 分钟, want 5", got)
	}
	if lines := readLines(t, a.file); lines != nil {
		t.Fatalf("不到 55 分钟不应落盘: %v", lines)
	}
	oldNow := nowFn
	nowFn = func() time.Time { return t0 }
	defer func() { nowFn = oldNow }()
	onExit()
	lines := readLines(t, a.file)
	want := fmt.Sprintf(`{"t":%d,"day":"20261007","mac":"%s","m":5}`, t0.Unix(), macA)
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("退出落盘 = %v, want [%s]", lines, want)
	}
}

func TestOnlineAccumCadenceCreditAndCap(t *testing.T) {
	a := withTempOnlineAcc(t)
	t0 := time.Date(2026, 10, 7, 10, 0, 0, 0, cst)
	setDevices(t, a, t0, macA)
	a.sample(t0)                      // 首次 5
	a.sample(t0.Add(2 * time.Minute)) // 不到 5 分钟: 不采样
	setDevices(t, a, t0.Add(6*time.Minute), macA)
	a.sample(t0.Add(6 * time.Minute)) // 间隔 6 分钟(Doze 3 分钟一轮)→ 记 6
	setDevices(t, a, t0.Add(46*time.Minute), macA)
	a.sample(t0.Add(46 * time.Minute)) // 空档 40 分钟 → 封顶 onlineCreditMaxMin
	want := 5 + 6 + onlineCreditMaxMin
	if got := a.pending[onlineKey{"20261007", macA}]; got != want {
		t.Fatalf("累计 %d 分钟, want %d", got, want)
	}
}

func TestOnlineAccumOfflineAndClockInsane(t *testing.T) {
	a := withTempOnlineAcc(t)
	t0 := time.Date(2026, 10, 7, 10, 0, 0, 0, cst)
	setDevices(t, a, t0) // 只有一台 1 小时前离线的
	a.sample(t0)
	if len(a.pending) != 0 {
		t.Fatalf("离线设备不应记分钟: %v", a.pending)
	}
	b := withTempOnlineAcc(t)
	b.clockOK = func(time.Time) bool { return false }
	setDevices(t, b, t0, macA)
	b.sample(t0)
	if len(b.pending) != 0 || !b.last.IsZero() {
		t.Fatalf("时钟不可信时不应采样: pending=%v last=%v", b.pending, b.last)
	}
}

// 跨日: 23:58 → 00:03 的 5 分钟拆成前一天 2 分钟 + 当天 3 分钟, 并立即落盘(不等 55 分钟)。
func TestOnlineAccumCrossDaySplitsAndFlushes(t *testing.T) {
	a := withTempOnlineAcc(t)
	t0 := time.Date(2026, 10, 7, 23, 58, 0, 0, cst)
	setDevices(t, a, t0, macA)
	a.sample(t0) // 首次 5 分钟: [23:53, 23:58] 全在 10-07
	t1 := time.Date(2026, 10, 8, 0, 3, 0, 0, cst)
	setDevices(t, a, t1, macA)
	a.sample(t1)
	lines := readLines(t, a.file)
	want := []string{
		fmt.Sprintf(`{"t":%d,"day":"20261007","mac":"%s","m":7}`, t1.Unix(), macA),
		fmt.Sprintf(`{"t":%d,"day":"20261008","mac":"%s","m":3}`, t1.Unix(), macA),
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("跨日落盘 =\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if len(a.pending) != 0 {
		t.Fatalf("落盘后应清空: %v", a.pending)
	}
}

func TestCreditSplitBoundaries(t *testing.T) {
	mid := time.Date(2026, 10, 8, 0, 0, 0, 0, cst)
	cases := []struct {
		now    time.Time
		credit time.Duration
		want   map[string]int
	}{
		{mid, 5 * time.Minute, map[string]int{"20261007": 5}},                                      // 正好零点: 全算前一天
		{mid.Add(5 * time.Minute), 5 * time.Minute, map[string]int{"20261008": 5}},                 // 区间从零点开始: 全算当天
		{mid.Add(time.Minute), 6 * time.Minute, map[string]int{"20261007": 5, "20261008": 1}},      // 跨零点
		{mid.Add(-time.Hour), 5 * time.Minute, map[string]int{"20261007": 5}},                      // 不跨日
		{mid.Add(10 * time.Second), 20 * time.Second, map[string]int{}},                            // 不足半分钟: 不记
		{mid.Add(90 * time.Second), 3 * time.Minute, map[string]int{"20261007": 2, "20261008": 1}}, // 四舍五入
	}
	for i, c := range cases {
		got := creditSplit(c.now, c.credit)
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("#%d creditSplit(%s, %v) = %v, want %v", i, c.now.Format("01-02 15:04:05"), c.credit, got, c.want)
		}
	}
}

// 55 分钟落盘节拍: 两台设备一直在线, 5 分钟一采; 55 分钟那次落盘, 一台一行。
func TestOnlineAccumFlushEvery55Min(t *testing.T) {
	a := withTempOnlineAcc(t)
	t0 := time.Date(2026, 10, 7, 10, 0, 0, 0, cst)
	for i := 0; i <= 11; i++ { // 0, 5, ..., 55 分钟
		now := t0.Add(time.Duration(i) * 5 * time.Minute)
		setDevices(t, a, now, macA, macB)
		a.sample(now)
		if i < 11 && readLines(t, a.file) != nil {
			t.Fatalf("第 %d 次采样(%d 分钟)就落盘了", i, i*5)
		}
	}
	lines := readLines(t, a.file)
	if len(lines) != 2 {
		t.Fatalf("55 分钟应落盘两行(一台一行): %v", lines)
	}
	for _, l := range lines {
		if !strings.HasSuffix(l, `"m":60}`) {
			t.Errorf("12 次采样 × 5 分钟 = 60: %s", l)
		}
	}
}

func TestOnlineAccumWriteFailureKeepsPending(t *testing.T) {
	a := withTempOnlineAcc(t)
	a.file = filepath.Join(t.TempDir(), "no-such-dir", "online_hours.jsonl")
	t0 := time.Date(2026, 10, 7, 10, 0, 0, 0, cst)
	setDevices(t, a, t0, macA)
	a.sample(t0)
	a.flush(t0)
	if a.pending[onlineKey{"20261007", macA}] != 5 {
		t.Fatalf("写失败应保留累加: %v", a.pending)
	}
}

// 接线: 驱动真实调用方 loopState.tick(ACTIVE)→ handleActive → onlineAcc.sample。
// 设备只在第一次采样时在线, 之后离线; 跑满 1 小时 → 第 55 分钟落盘一行 "m":5,
// 退出时没有未落盘的分钟, 不再多写。
func TestHandleActiveOnlineOnceIs5Min(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 7, 10, 0, 0, 0, cst)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)
	a := onlineAcc
	setDevices(t, a, clk.now, macA)
	ls := newLoopState()
	start := clk.now
	driveHourWithHook(ls, clk, func(round int) {
		if round == 1 { // 第一轮之后离线
			setDevices(t, a, start)
		}
	}, func(int) wdState { return wdState{kind: stateActive, iface: "wlan0"} }, 60*time.Second)
	onExit()
	lines := readLines(t, a.file)
	want := fmt.Sprintf(`{"t":%d,"day":"20261007","mac":"%s","m":5}`, start.Add(55*time.Minute).Unix(), macA)
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("online_hours.jsonl = %v, want [%s]", lines, want)
	}
}

// 热点未开(PENDING)不采样。
func TestPendingDoesNotSampleOnline(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 7, 10, 0, 0, 0, cst)}
	rec := newActionRec()
	rec.probeRC = 1
	withFakeEnv(t, clk, rec)
	setDevices(t, onlineAcc, clk.now, macA)
	ls := newLoopState()
	ls.tick(wdState{kind: statePending})
	if len(onlineAcc.pending) != 0 {
		t.Fatalf("PENDING 不应采样: %v", onlineAcc.pending)
	}
}
