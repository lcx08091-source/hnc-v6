package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─── dumpsys 解析(§T2 要求: Android 12 / 14 / 16 风格都要能解析) ───

// Android 12/13 原生 `dumpsys activity activities`: mResumedActivity 行。
const fgActivitiesA12 = `
  Display #0 (products from display 0):
    rootTaskId=12
      mResumedActivity: ActivityRecord{a1b2c3 u0 com.ss.android.ugc.aweme/.main.MainActivity t34}
    Hist #0: ActivityRecord{deadbeef u0 com.android.settings/.Settings t40}
`

// Android 14 原生: topResumedActivity 行。
const fgActivitiesA14 = `
  Display #0:
    topResumedActivity=ActivityRecord{f00baa u0 com.tencent.mm/.ui.LauncherUI t77}
    mFocusedApp=AppWindowToken{1234 token=Token{5678}}
`

// Android 16 / ColorOS: 字段名和排版可能不同, 但仍含 topResumedActivity。
const fgActivitiesA16ColorOS = `
  * Task{abcd type=standard A=10123:tv.danmaku.bili}
    topResumedActivity = ActivityRecord{99aa u0 tv.danmaku.bili/.ui.splash.SplashActivity t5}
`

// `dumpsys window` 兜底: mCurrentFocus 行。
const fgWindowFocus = `
  mCurrentFocus=Window{11223344 u0 com.tencent.mm/com.tencent.mm.ui.LauncherUI}
  mFocusedApp=ActivityRecord{55667788 u0 com.tencent.mm/.ui.LauncherUI t90}
`

// `dumpsys window` 只有 mFocusedApp 的形态(有些 ROM)。
const fgWindowFocusedApp = `
  Window #0:
    mFocusedApp=AppWindowToken{aabbcc token=Token{ddeeff ActivityRecord{112233 u0 com.android.chrome/com.google.android.apps.chrome.Main t12}}}
`

// 完全不认识的格式(极端 ColorOS / 未来 ROM): 应降级为空, 不 panic。
const fgGarbage = `
  Some totally different vendor output
  focus: <none>
  resumed: null
`

func TestParseFGActivities_Variants(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"android12_mResumedActivity", fgActivitiesA12, "com.ss.android.ugc.aweme"},
		{"android14_topResumedActivity", fgActivitiesA14, "com.tencent.mm"},
		{"android16_coloros", fgActivitiesA16ColorOS, "tv.danmaku.bili"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseFGActivities(c.in); got != c.want {
				t.Errorf("parseFGActivities = %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseFGWindow_Variants(t *testing.T) {
	if got := parseFGWindow(fgWindowFocus); got != "com.tencent.mm" {
		t.Errorf("mCurrentFocus 解析 = %q, want com.tencent.mm", got)
	}
	if got := parseFGWindow(fgWindowFocusedApp); got != "com.android.chrome" {
		t.Errorf("mFocusedApp 解析 = %q, want com.android.chrome", got)
	}
}

func TestParseFG_GarbageNoPanic(t *testing.T) {
	if got := parseFGActivities(fgGarbage); got != "" {
		t.Errorf("垃圾输出应返回空, got %q", got)
	}
	if got := parseFGWindow(fgGarbage); got != "" {
		t.Errorf("垃圾输出应返回空, got %q", got)
	}
	// 空字符串 / 只有关键字没有包名的行也不能崩。
	if got := parseFGActivities("mResumedActivity: null"); got != "" {
		t.Errorf("无包名应返回空, got %q", got)
	}
	if got := parseFGWindow(""); got != "" {
		t.Errorf("空输出应返回空, got %q", got)
	}
}

// readForegroundPkg: activities 成功就不该再调 window; 都失败降级 none。
func TestReadForegroundPkg_Priority(t *testing.T) {
	var calls []string
	run := func(args ...string) (string, bool) {
		calls = append(calls, strings.Join(args, " "))
		switch args[0] {
		case "activity":
			return fgActivitiesA14, true
		case "window":
			return fgWindowFocus, true
		}
		return "", false
	}
	pkg, src := readForegroundPkg(run)
	if pkg != "com.tencent.mm" || src != "activities" {
		t.Errorf("应优先用 activities: pkg=%q src=%q", pkg, src)
	}
	if len(calls) != 1 {
		t.Errorf("activities 成功就不该再调 window, 实际调了 %v", calls)
	}
}

func TestReadForegroundPkg_FallbackWindow(t *testing.T) {
	run := func(args ...string) (string, bool) {
		if args[0] == "activity" {
			return fgGarbage, true // 命令成功但解析不出
		}
		return fgWindowFocus, true
	}
	pkg, src := readForegroundPkg(run)
	if pkg != "com.tencent.mm" || src != "window" {
		t.Errorf("应回退 window: pkg=%q src=%q", pkg, src)
	}
}

func TestReadForegroundPkg_AllFail(t *testing.T) {
	run := func(args ...string) (string, bool) { return "", false } // dumpsys 命令都失败
	pkg, src := readForegroundPkg(run)
	if pkg != "" || src != "none" {
		t.Errorf("全失败应降级 none: pkg=%q src=%q", pkg, src)
	}
}

// firstPkg 正则: 只抓形如 com.x.y/ 的包名, 不误抓普通词。
func TestFirstPkg(t *testing.T) {
	cases := map[string]string{
		"foo com.tencent.mm/.Launcher t1":      "com.tencent.mm",
		"mCurrentFocus=Window{1 u0 a.b.c/d.e}": "a.b.c",
		"no package here":                      "",
		"single/word":                          "", // 没有 "." 分隔, 不算包名
		"":                                     "",
	}
	for in, want := range cases {
		if got := firstPkg(in); got != want {
			t.Errorf("firstPkg(%q) = %q, want %q", in, got, want)
		}
	}
}

// ─── 文件写入 / 摘要 / 过期清理 ───

func mkHncDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestAppendAndSummarizeSelfFG(t *testing.T) {
	dir := mkHncDir(t)
	now := time.Now()
	recs := []selfFGRecord{
		{Ts: now.Add(-3 * time.Hour).Unix(), Pkg: "com.tencent.mm", Source: "activities"},
		{Ts: now.Add(-2 * time.Hour).Unix(), Pkg: "tv.danmaku.bili", Source: "window"},
		{Ts: now.Add(-1 * time.Hour).Unix(), Pkg: "com.ss.android.ugc.aweme", Source: "activities"},
	}
	for _, r := range recs {
		if err := appendSelfFG(dir, now, r); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	// 文件按本地日期命名。
	path := selfFGPath(dir, now)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("应有当天文件 %s: %v", path, err)
	}
	b, _ := os.ReadFile(path)
	if n := len(strings.Split(strings.TrimSpace(string(b)), "\n")); n != 3 {
		t.Errorf("应写 3 行, got %d", n)
	}
	// 每行都是合法 JSON, 且字段名固定。
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("行非法 JSON: %v (%s)", err, line)
		}
		for _, k := range []string{"ts", "pkg", "source"} {
			if _, ok := m[k]; !ok {
				t.Errorf("缺字段 %q: %s", k, line)
			}
		}
	}

	sum := summarizeSelfFG(dir, now)
	if sum.Switches24h != 3 {
		t.Errorf("switches_24h = %d, want 3", sum.Switches24h)
	}
	if sum.LastPkg != "com.ss.android.ugc.aweme" || sum.Source != "activities" {
		t.Errorf("最近一次 = %q/%q, want 抖音/activities", sum.LastPkg, sum.Source)
	}
	if sum.LastTs != recs[2].Ts {
		t.Errorf("last_ts = %d, want %d", sum.LastTs, recs[2].Ts)
	}
}

// 24 小时窗口外的记录不计入 switches_24h, 但更早的仍可能成为 last(这里验证裁剪)。
func TestSummarizeSelfFG_24hWindow(t *testing.T) {
	dir := mkHncDir(t)
	now := time.Now()
	// 一条在窗口内(昨天此刻 + 1 分钟 → 落在昨天的日期文件, 但 <24h 内)。
	inWin := now.Add(-1 * time.Hour)
	// 一条在窗口外(2 天前)。
	outWin := now.Add(-50 * time.Hour)
	_ = appendSelfFG(dir, inWin, selfFGRecord{Ts: inWin.Unix(), Pkg: "com.in.win", Source: "activities"})
	_ = appendSelfFG(dir, outWin, selfFGRecord{Ts: outWin.Unix(), Pkg: "com.out.win", Source: "activities"})
	sum := summarizeSelfFG(dir, now)
	if sum.Switches24h != 1 {
		t.Errorf("只应计窗口内 1 条, got %d", sum.Switches24h)
	}
	if sum.LastPkg != "com.in.win" {
		t.Errorf("最近一次应是窗口内那条, got %q", sum.LastPkg)
	}
}

// 没有任何前台文件时, 摘要为 source:"none" 且不报错(评估页据此提示)。
func TestSummarizeSelfFG_Empty(t *testing.T) {
	dir := mkHncDir(t)
	sum := summarizeSelfFG(dir, time.Now())
	if sum.Switches24h != 0 || sum.Source != "none" || sum.LastPkg != "" {
		t.Errorf("空摘要不对: %+v", sum)
	}
}

// 过期清理: 只删 7 天前的 self_fg.*.jsonl, 不碰别的文件。
func TestSweepSelfFG(t *testing.T) {
	dir := mkHncDir(t)
	run := filepath.Join(dir, "run")
	now := time.Now()
	mk := func(name string) string {
		p := filepath.Join(run, name)
		if err := os.WriteFile(p, []byte("x\n"), selfFGFileMode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oldDay := now.AddDate(0, 0, -9).Format("20060102")
	keepDay := now.AddDate(0, 0, -2).Format("20060102")
	old := mk("self_fg." + oldDay + ".jsonl")
	keep := mk("self_fg." + keepDay + ".jsonl")
	other := mk("label_samples." + oldDay + ".jsonl") // 别的采集文件, 不能碰
	junk := mk("dpi_state.json")

	sweepSelfFG(dir, now)

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("7 天前的 self_fg 应被删")
	}
	for _, p := range []string{keep, other, junk} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s 不该被动: %v", filepath.Base(p), err)
		}
	}
}

// selfFGEnabled: 标志文件在/不在。
func TestSelfFGEnabled(t *testing.T) {
	dir := mkHncDir(t)
	if selfFGEnabled(dir) {
		t.Error("没有标志文件时应为 false")
	}
	flag := filepath.Join(dir, "run", "self_capture.enabled")
	if err := os.WriteFile(flag, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if !selfFGEnabled(dir) {
		t.Error("有标志文件时应为 true")
	}
}
