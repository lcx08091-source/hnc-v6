package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestStartupToken(t *testing.T) {
	for in, want := range map[string]string{
		"v26-dy.ixigua.com":      "v#-dy.ixigua.com",
		"API5-Normal.amemv.com.": "api#-normal.amemv.com",
		"p3.douyinpic.com":       "p#.douyinpic.com",
		"a123b45.cdn.com":        "a#b#.cdn.com",
		"1.2.3.4":                "",
		"2001:db8::1":            "",
		"cloudflare-ech.com":     "", // ECH 外层 public_name
		"":                       "",
	} {
		if got := startupToken(in); got != want {
			t.Errorf("%q → %q want %q", in, got, want)
		}
	}
}

func ss(ts int64, pkg, sni string) startupSample {
	return startupSample{Ts: ts, Pkg: pkg, UID: 10100, SNI: sni}
}

// 启动切分: 600 秒间隔才算新启动, 只取 8 秒窗口, < 2 个 token 丢弃
func TestStartupSegment(t *testing.T) {
	sg := newStartupSegmenter()
	var done []*startupOpen
	feed := func(s startupSample) {
		if o := sg.feed(s, "app_a"); o != nil {
			done = append(done, o)
		}
	}
	feed(ss(1000, "com.a", "xa.a.com"))
	feed(ss(1003, "com.a", "xb.a.com"))
	feed(ss(1003, "com.a", "xa.a.com")) // 重复 token
	feed(ss(1008, "com.a", "xc.a.com")) // 窗口边界(含)
	feed(ss(1009, "com.a", "late.a.com"))
	if len(done) != 1 || len(done[0].Tokens) != 3 || done[0].Start != 1000 {
		t.Fatalf("first start: %+v", done)
	}
	// 与上一条只隔 599 秒: 不是新启动
	feed(ss(1009+599, "com.a", "ya.a.com"))
	feed(ss(1009+600, "com.a", "yb.a.com"))
	if l := sg.flush(-1); len(l) != 0 {
		t.Fatalf("599s gap must not start: %+v", l)
	}
	// 隔 600 秒: 新启动, 但窗口里只有 1 个 token → 丢弃
	feed(ss(1609+600, "com.a", "za.a.com"))
	feed(ss(1609+600+20, "com.a", "zb.a.com"))
	if len(done) != 1 {
		t.Fatalf("single-token start must be dropped: %+v", done)
	}
	// flush 只收尾窗口已过的
	feed(ss(5000, "com.a", "wa.a.com"))
	feed(ss(5001, "com.a", "wb.a.com"))
	if l := sg.flush(5005); len(l) != 0 {
		t.Fatal("window still open")
	}
	if l := sg.flush(5009); len(l) != 1 {
		t.Fatalf("flush: %+v", l)
	}
}

func TestStartupHalfLife(t *testing.T) {
	tb := newStartupTable()
	tb.addStart("app_a", "A", []string{"a1", "a2"}, 1000, true)
	tb.addStart("app_a", "A", []string{"a1"}, 1000+startupHalfLifeSec, true)
	a := tb.apps["app_a"]
	if a.Starts < 1.49 || a.Starts > 1.51 || a.Tokens["a1"] < 1.49 || a.Tokens["a2"] < 0.49 || a.Tokens["a2"] > 0.51 {
		t.Fatalf("decay: %+v", a)
	}
}

// 合成学习表: A 特征 {a1,a2,a3}, B {b1,b2}; s 被 A、B、C 三个应用共用(不算特征);
// D 只启动 2 次(不可用)
func synthStartupTable() *startupTable { return synthStartupTableAt(1000) }

func synthStartupTableAt(ts int64) *startupTable {
	tb := newStartupTable()
	for i := 0; i < 4; i++ {
		tb.addStart("app_a", "A", []string{"a#.a.com", "a-api.a.com", "a-cdn.a.com", "shared.sdk.com"}, ts, false)
		tb.addStart("app_b", "B", []string{"b.b.com", "b-api.b.com", "shared.sdk.com"}, ts, false)
		tb.addStart("app_c", "C", []string{"c.c.com", "c-api.c.com", "shared.sdk.com"}, ts, false)
	}
	tb.addStart("app_d", "D", []string{"d.d.com", "d#.d.com"}, ts, false)
	tb.addStart("app_d", "D", []string{"d.d.com", "d#.d.com"}, ts, false)
	// 噪声 token(频率 < 0.5)不进特征
	tb.addStart("app_a", "A", []string{"a#.a.com", "a-api.a.com", "rare.a.com"}, ts, false)
	return tb
}

func TestStartupFeaturesUsable(t *testing.T) {
	m := buildStartupModel(synthStartupTable(), nil, 0, false)
	fs := startupFeatSet(m)
	if len(fs) != 3 || fs["app_d"] != nil {
		t.Fatalf("usable apps: %v", fs)
	}
	if fs["app_a"]["shared.sdk.com"] || fs["app_a"]["rare.a.com"] || !fs["app_a"]["a-cdn.a.com"] || len(fs["app_a"]) != 3 {
		t.Fatalf("A features: %v", fs["app_a"])
	}
	if len(fs["app_b"]) != 2 {
		t.Fatalf("B features: %v", fs["app_b"])
	}
	// 导入的启动指纹并入; 同一应用本机学到的优先
	imp := map[string]startupImported{
		"app_e": {Name: "E", Starts: 5, Tokens: map[string]float64{"e1.e.com": 0.9, "e2.e.com": 0.8}},
		"app_a": {Name: "A导入", Starts: 9, Tokens: map[string]float64{"x.x.com": 1, "y.y.com": 1}},
	}
	fs = startupFeatSet(buildStartupModel(synthStartupTable(), imp, 0, false))
	if len(fs["app_e"]) != 2 || fs["app_a"]["x.x.com"] {
		t.Fatalf("imported merge: %v", fs)
	}
}

func TestStartupRecognize(t *testing.T) {
	m := buildStartupModel(synthStartupTable(), nil, 0, false)
	r := newStartupRecognizer()
	mac := "aa:bb:cc:00:00:01"
	// 只有 a1 → 无
	if ev := r.feed(m, mac, 100, "a#.a.com"); ev != nil {
		t.Fatalf("single token: %+v", ev)
	}
	// 共享 token 不算
	if ev := r.feed(m, mac, 101, "shared.sdk.com"); ev != nil {
		t.Fatalf("shared token: %+v", ev)
	}
	// a1 + a2 → A
	ev := r.feed(m, mac, 103, "a-api.a.com")
	if ev == nil || ev.AppID != "app_a" || ev.Score < 60 || len(ev.Matched) != 2 {
		t.Fatalf("A: %+v", ev)
	}
	// 600 秒内不重复
	if ev := r.feed(m, mac, 105, "a-cdn.a.com"); ev != nil {
		t.Fatalf("dedup: %+v", ev)
	}
	// 窗口外的 token 不算: b1 在 200, b2 在 209(相隔 9 秒)
	r.feed(m, mac, 200, "b.b.com")
	if ev := r.feed(m, mac, 209, "b-api.b.com"); ev != nil {
		t.Fatalf("outside window: %+v", ev)
	}
	// 另一台设备独立
	if ev := r.feed(m, "aa:bb:cc:00:00:02", 210, "b.b.com"); ev != nil {
		t.Fatal("other dev single")
	}
	if ev := r.feed(m, "aa:bb:cc:00:00:02", 212, "b-api.b.com"); ev == nil || ev.AppID != "app_b" || ev.Score != 100 {
		t.Fatalf("B: %+v", ev)
	}
	// 600 秒后同一应用可再出
	r.feed(m, mac, 800, "a#.a.com")
	if ev := r.feed(m, mac, 801, "a-api.a.com"); ev == nil {
		t.Fatal("after dedup window")
	}
	// 两个应用都够格但差距 < 0.2 → 不出
	tb := newStartupTable()
	for i := 0; i < 3; i++ {
		tb.addStart("x", "X", []string{"x1", "x2", "x3"}, 1, false)
		tb.addStart("y", "Y", []string{"y1", "y2", "y3"}, 1, false)
	}
	m2 := buildStartupModel(tb, nil, 0, false)
	r2 := newStartupRecognizer()
	for i, tok := range []string{"x1", "y1", "x2"} {
		r2.feed(m2, mac, int64(10+i), tok)
	}
	if ev := r2.feed(m2, mac, 13, "y2"); ev != nil {
		t.Fatalf("tie must not emit: %+v", ev)
	}
}

// ── 交叉验证 + 增量学习: 合成多天样本 ──

func stDir(t *testing.T) string {
	t.Helper()
	d := evalDir(t)
	writePkgMap(t, d, map[string]string{"com.a": "app_a", "com.b": "app_b"})
	writeRules(t, d, map[string]string{"app_a": "应用A", "app_b": "应用B"})
	return d
}

func writeLines(t *testing.T, path string, lines []string, appendMode bool) {
	t.Helper()
	fl := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if appendMode {
		fl = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	f, err := os.OpenFile(path, fl, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l); err != nil {
			t.Fatal(err)
		}
	}
}

func sampleLine(ts int64, pkg, sni string) string {
	b, _ := json.Marshal(map[string]interface{}{"ts": ts, "pkg": pkg, "uid": 10100, "sni": sni, "ja4": "t13d_x_y", "dport": 443, "quic": false, "ech": false, "partial": false, "rip": "1.1.1.1"})
	return string(b) + "\n"
}

// 一天的合成样本: A、B 交替启动 4 次(每次 3 个 token, 相隔 1 秒), 真值在启动后 5 秒记录
func synthDay(t *testing.T, dir string, day time.Time) {
	t.Helper()
	date := day.Format("20060102")
	base := day.Unix()
	var lines, fg []string
	for i := 0; i < 4; i++ {
		st := base + int64(i)*1000
		pkg, pre := "com.a", "a"
		if i%2 == 1 {
			pkg, pre = "com.b", "b"
		}
		lines = append(lines,
			sampleLine(st, pkg, pre+"-conf.example.com"),
			sampleLine(st+1, pkg, pre+"-api"+strconv.Itoa(i+10)+".example.com"), // 数字归一后同一 token
			sampleLine(st+2, pkg, pre+"-cdn.example.com"))
		b, _ := json.Marshal(selfFGRecord{Ts: st + 5, Pkg: pkg, Source: "activities"})
		fg = append(fg, string(b)+"\n")
	}
	writeLines(t, filepath.Join(dir, "run", "label_samples."+date+".jsonl"), lines, false)
	writeLines(t, filepath.Join(dir, "run", "self_fg."+date+".jsonl"), fg, false)
}

func TestStartupCrossValidation(t *testing.T) {
	dir := stDir(t)
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)
	synthDay(t, dir, time.Date(2026, 10, 2, 10, 0, 0, 0, time.Local))
	if r := evalStartup(dir, now); r.Note != "样本不足 2 天，无法交叉验证" || r.Days != 1 {
		t.Fatalf("one day: %+v", r)
	}
	synthDay(t, dir, time.Date(2026, 10, 3, 10, 0, 0, 0, time.Local))
	synthDay(t, dir, time.Date(2026, 10, 4, 10, 0, 0, 0, time.Local))
	r := evalStartup(dir, now)
	// 每天 4 次切换, 训练集(另外两天)每个应用 4 次启动 → 都可用
	if r.Days != 3 || r.Switches != 12 || r.SwitchHit != 12 || r.SwitchRate != 1 {
		t.Fatalf("switches: %+v", r)
	}
	if r.Events != 12 || r.EventsCorrect != 12 || r.EventAccuracy != 1 || r.MedianLagSec != -4 {
		t.Fatalf("events: %+v", r)
	}
	// 接到识别自评里
	res := evalDPI(dir, 1, now)
	if res.Startup == nil || res.Startup.Switches != 12 {
		t.Fatalf("eval startup: %+v", res.Startup)
	}
}

func TestStartupIncrementalLearn(t *testing.T) {
	dir := stDir(t)
	st := startupFor(dir)
	d1 := time.Date(2026, 10, 2, 10, 0, 0, 0, time.Local)
	p1 := filepath.Join(dir, "run", "label_samples."+d1.Format("20060102")+".jsonl")
	var lines []string
	for i := 0; i < 4; i++ {
		s := d1.Unix() + int64(i)*1000
		lines = append(lines, sampleLine(s, "com.a", "aa.a.com"), sampleLine(s+1, "com.a", "ab.a.com"), sampleLine(s+2, "com.a", "ac.a.com"))
	}
	writeLines(t, p1, lines, false)
	// 最后一行没写完(无换行)不消费
	writeLines(t, p1, []string{`{"ts":1,"pkg":"com.a"`}, true)
	// 最后一次启动在 d1+3000 秒: 学习时刻要过了它的窗口 + 600 秒才收尾
	st.learnOnce(d1.Add(2 * time.Hour))
	if st.stats.SamplesRead != 12 || st.stats.StartsLearned != 4 {
		t.Fatalf("first pass: %+v", st.stats)
	}
	learned, usable := st.learnedView(d1.Add(2 * time.Hour))
	if usable != 1 || len(learned) != 1 || !learned[0].Usable || learned[0].Starts != 4 || learned[0].Feat != 3 {
		t.Fatalf("learned: %+v", learned)
	}
	// 再跑一次: 没有新行就什么都不读
	st.learnOnce(d1.Add(3 * time.Hour))
	if st.stats.SamplesRead != 12 {
		t.Fatalf("re-read: %+v", st.stats)
	}
	// 把没写完的行补完 + 追加一行: 只读这两行
	writeLines(t, p1, []string{`,"uid":10100,"sni":"z.a.com"}` + "\n", sampleLine(d1.Unix()+5000, "com.b", "b1.b.com")}, true)
	st.learnOnce(d1.Add(4 * time.Hour))
	if st.stats.SamplesRead != 14 {
		t.Fatalf("append: %+v", st.stats)
	}
	// 换天: 旧文件被删(过期), 新一天的文件从头读
	_ = os.Remove(p1)
	d2 := d1.AddDate(0, 0, 1)
	p2 := filepath.Join(dir, "run", "label_samples."+d2.Format("20060102")+".jsonl")
	writeLines(t, p2, []string{sampleLine(d2.Unix(), "com.b", "b1.b.com"), sampleLine(d2.Unix()+1, "com.b", "b2.b.com")}, false)
	st.learnOnce(d2.Add(time.Hour))
	if st.stats.SamplesRead != 16 || st.cursor.Date != d2.Format("20060102") {
		t.Fatalf("next day: %+v %+v", st.stats, st.cursor)
	}
	// 落盘 → 新进程加载: 游标与学习表都在
	st2 := &startupStore{hncDir: dir, table: newStartupTable(), seg: newStartupSegmenter(), rec: newStartupRecognizer()}
	st2.mu.Lock()
	st2.loadLocked()
	st2.mu.Unlock()
	if st2.cursor != st.cursor || st2.table.apps["app_a"] == nil || st2.table.apps["app_a"].Name != "应用A" {
		t.Fatalf("reload: %+v %+v", st2.cursor, st2.table.apps)
	}
	// 文件被截短重建(偏移超过文件大小): 从头读
	writeLines(t, p2, []string{sampleLine(d2.Unix()+9000, "com.b", "b9.b.com")}, false)
	st.learnOnce(d2.Add(2 * time.Hour))
	if st.stats.SamplesRead != 17 {
		t.Fatalf("truncated: %+v", st.stats)
	}
}

// 节流: 30 分钟一次; 本机抓包没开时不学
func TestStartupLearnThrottleAndGate(t *testing.T) {
	dir := stDir(t)
	st := startupFor(dir)
	d1 := time.Date(2026, 10, 2, 10, 0, 0, 0, time.Local)
	p1 := filepath.Join(dir, "run", "label_samples."+d1.Format("20060102")+".jsonl")
	writeLines(t, p1, []string{sampleLine(d1.Unix(), "com.a", "a1.a.com")}, false)
	st.maybeLearn(d1)
	if st.stats.SamplesRead != 1 {
		t.Fatalf("first: %+v", st.stats)
	}
	writeLines(t, p1, []string{sampleLine(d1.Unix()+1, "com.a", "a2.a.com")}, true)
	st.maybeLearn(d1.Add(29 * time.Minute))
	if st.stats.SamplesRead != 1 {
		t.Fatal("throttle broken")
	}
	st.maybeLearn(d1.Add(31 * time.Minute))
	if st.stats.SamplesRead != 2 {
		t.Fatalf("after 30min: %+v", st.stats)
	}
	_ = os.Remove(filepath.Join(dir, "run", "self_capture.enabled"))
	writeLines(t, p1, []string{sampleLine(d1.Unix()+2, "com.a", "a3.a.com")}, true)
	st.maybeLearn(d1.Add(90 * time.Minute))
	if st.stats.SamplesRead != 2 {
		t.Fatal("must not learn when self capture is off")
	}
}

// 客户端: fpSt.tick 新摄入的 dpi_flows 记录交给 observe 产出事件; 接口可读
func TestStartupObserveFromFlows(t *testing.T) {
	dir := stDir(t)
	st := startupFor(dir)
	st.mu.Lock()
	st.loaded = true
	now := time.Unix(1_800_000_000, 0)
	st.table = synthStartupTableAt(now.Unix())
	st.mu.Unlock()
	f := &fptFlows{boot: 1}
	f.add(fptMAC1, "192.168.43.10", 30000, "203.0.113.1", 443, fptJA4A, "a1.a.com", "", "", now.Unix())
	f.add(fptMAC1, "192.168.43.10", 30001, "203.0.113.1", 443, fptJA4A, "a-api.a.com", "", "", now.Unix()+1)
	f.add(fptMAC1, "192.168.43.10", 30002, "203.0.113.1", 443, fptJA4A, "a-cdn.a.com", "", "", now.Unix()+2)
	f.write(t, dir)
	fresh := fpFor(dir).tick(now, nil)
	if len(fresh) != 3 {
		t.Fatalf("fresh: %d", len(fresh))
	}
	st.observe(fresh, now)
	if len(st.events) != 1 || st.events[0].AppID != "app_a" || st.events[0].MAC != fptMAC1 {
		t.Fatalf("events: %+v", st.events)
	}
	if got := st.eventsSince(fptMAC1, now.Unix()-1, now.Unix()+10); !got["app_a"] {
		t.Fatalf("eventsSince: %v", got)
	}
	if got := st.eventsSince(fptMAC1, now.Unix()+5, now.Unix()+10); got != nil {
		t.Fatalf("eventsSince after: %v", got)
	}
	// 同一文件再 tick: 没有新记录
	fpFor(dir).flowsKey = ""
	if fresh := fpFor(dir).tick(now, nil); len(fresh) != 0 {
		t.Fatalf("re-tick fresh: %d", len(fresh))
	}
}

func TestStartupAPI(t *testing.T) {
	dir := stDir(t)
	st := startupFor(dir)
	now := time.Now()
	st.mu.Lock()
	st.loaded = true
	st.table = synthStartupTableAt(now.Unix())
	st.events = []startupEvent{{MAC: fptMAC1, AppID: "app_a", Name: "A", Ts: now.Unix(), Score: 80, Matched: []string{"a#.a.com", "a-api.a.com"}}}
	st.mu.Unlock()
	s := newServer(dir)
	rec := httptest.NewRecorder()
	s.apiDPIStartup(rec, httptest.NewRequest("GET", "/api/dpi_startup", nil))
	var out struct {
		Learned []startupAppOut `json:"learned"`
		Events  []startupEvent  `json:"events"`
		Stats   map[string]any  `json:"stats"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Learned) != 4 || !out.Learned[0].Usable || out.Stats["apps_usable"].(float64) != 3 || len(out.Events) != 1 {
		t.Fatalf("api: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.apiDPIStartup(rec, httptest.NewRequest("POST", "/api/dpi_startup", nil))
	if rec.Code != 405 {
		t.Fatalf("POST: %d", rec.Code)
	}
}
