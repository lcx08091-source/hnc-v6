package main

// v5.27 T4 前台 HMM: 合成观测序列(10 秒一轮)。测试锁「行为」, 不锁具体数值。

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// run 喂 n 轮同样的分数, 返回最后的决定
func hmmRun(h *hmmDev, n int, inst map[string]float64, started map[string]bool) string {
	for i := 0; i < n; i++ {
		hmmStep(h, inst, started, 10)
	}
	return h.cur
}

func TestHMMStableUseIgnoresOneSpike(t *testing.T) {
	h := newHMMDev()
	if got := hmmRun(h, 20, map[string]float64{"a": 60, "b": 5}, nil); got != "a" {
		t.Fatalf("stable A: %q", got)
	}
	// 中间一轮 B 的分数冲高(A 还在用): HMM 不切。
	// 对比: 经典模型同样靠「连续领先 2 轮」挡住一轮插曲(TestFgSwitchAppsHysteresis),
	// 但只要尖峰够大(平滑分 ≥ 60 且领先当前前台 ≥ 40)就会当轮切走 —— HMM 没有这条捷径,
	// 单轮观测最多 ×e^κ, 压不过长期累积的后验。
	hmmStep(h, map[string]float64{"a": 40, "b": 110}, nil, 10)
	if h.cur != "a" {
		t.Fatalf("one spike switched to %q", h.cur)
	}
	if got := hmmRun(h, 1, map[string]float64{"a": 60, "b": 5}, nil); got != "a" {
		t.Fatalf("after spike: %q", got)
	}
}

func TestHMMSustainedSwitchWithinTwoRounds(t *testing.T) {
	h := newHMMDev()
	hmmRun(h, 20, map[string]float64{"a": 60, "b": 0}, nil)
	switched := -1
	for i := 0; i < 5; i++ {
		hmmStep(h, map[string]float64{"a": 0, "b": 70}, nil, 10)
		if h.cur == "b" && switched < 0 {
			switched = i
		}
	}
	if switched < 0 || switched > 1 {
		t.Fatalf("switched at round %d (want ≤ 2 rounds)", switched+1)
	}
}

func TestHMMStartupEventSwitchesSameRound(t *testing.T) {
	h := newHMMDev()
	hmmRun(h, 20, map[string]float64{"a": 60}, nil)
	// 没有启动事件时, 同样的一轮不够
	h2 := newHMMDev()
	hmmRun(h2, 20, map[string]float64{"a": 60}, nil)
	hmmStep(h2, map[string]float64{"a": 0, "b": 55}, nil, 10)
	if h2.cur == "b" {
		t.Fatal("without startup event should not switch in one round")
	}
	hmmStep(h, map[string]float64{"a": 0, "b": 55}, map[string]bool{"b": true}, 10)
	if h.cur != "b" || h.post < hmmPick {
		t.Fatalf("startup event: cur=%q post=%.2f", h.cur, h.post)
	}
}

func TestHMMAllQuietGoesNone(t *testing.T) {
	h := newHMMDev()
	hmmRun(h, 20, map[string]float64{"a": 60, "b": 10}, nil)
	n := -1
	for i := 0; i < 30; i++ {
		hmmStep(h, map[string]float64{"a": 0, "b": 0}, nil, 10)
		if h.cur == "" {
			n = i
			break
		}
	}
	if n < 0 {
		t.Fatal("never went to _none")
	}
	if n == 0 {
		t.Fatal("一轮安静不该立刻没有前台")
	}
}

func TestHMMStateCap(t *testing.T) {
	h := newHMMDev()
	inst := map[string]float64{}
	for i := 0; i < 20; i++ {
		inst[string(rune('a'+i))] = float64(i)
	}
	hmmRun(h, 3, inst, nil)
	if len(h.logp) > hmmMaxStates {
		t.Fatalf("states=%d", len(h.logp))
	}
	if _, ok := h.logp[hmmNone]; !ok {
		t.Fatal("_none dropped")
	}
	// 消失的应用移除
	hmmStep(h, map[string]float64{"t": 50}, nil, 10)
	if len(h.logp) != 2 {
		t.Fatalf("states after shrink: %v", h.logp)
	}
}

// ── 接到 fg_model 上 ──

func newFgTBHMM(t *testing.T, start time.Time, engine string) *fgTB {
	b := newFgTB(t, start)
	b.m.engine = func() string { return engine }
	return b
}

func TestFgHMMEngineDrivesViewAndTimeline(t *testing.T) {
	b := newFgTBHMM(t, fgStart(), fgEngineHMM)
	b.tick(tk)
	var v fgView
	for i := 0; i < 6; i++ {
		v = b.tick(tk, b.video(tk), b.wechatHB())
	}
	if v.AppID != "bilibili" || !strings.Contains(strings.Join(v.Reasons, "|"), "HMM 后验") || v.Confidence <= 0 || v.Confidence > 95 {
		t.Fatalf("hmm view: %+v", v)
	}
	if s := b.sessions(); len(s) != 1 || s[0].App != "bilibili" {
		t.Fatalf("timeline: %+v", s)
	}
	// 一轮插曲不切, 持续切换后跟随 HMM
	if v := b.tick(tk, b.video(tk), b.browse(tk)); v.AppID != "bilibili" {
		t.Fatalf("spike: %+v", v)
	}
	for i := 0; i < 6; i++ {
		v = b.tick(tk, b.game(tk))
	}
	if v.AppID != "wzry" {
		t.Fatalf("switch: %+v", v)
	}
	s := b.sessions()
	if len(s) != 2 || s[1].App != "wzry" {
		t.Fatalf("timeline after switch: %+v", s)
	}
	// 隧道置信度仍按来源封顶
	d := b.m.devs[fgMAC]
	if d.hmm == nil || d.shown != d.hmm.cur {
		t.Fatalf("shown should follow hmm: %+v", d)
	}
}

func TestFgHMMStartupEventHook(t *testing.T) {
	b := newFgTBHMM(t, fgStart(), fgEngineHMM)
	var calls int
	b.m.started = func(mac string, after, upTo int64) map[string]bool {
		calls++
		if upTo-after > 30 || after >= upTo {
			t.Errorf("window (%d,%d]", after, upTo)
		}
		return map[string]bool{"wzry": true}
	}
	b.tick(tk)
	for i := 0; i < 6; i++ {
		b.tick(tk, b.video(tk))
	}
	// 启动事件 + 一轮活跃 → 当轮切过去(视频这一轮已经停了)
	v := b.tick(tk, b.game(tk))
	if v.AppID != "wzry" || calls == 0 {
		t.Fatalf("startup hook: %+v calls=%d", v, calls)
	}
}

func TestFgHMMResetOnGap(t *testing.T) {
	b := newFgTBHMM(t, fgStart(), fgEngineHMM)
	b.tick(tk)
	for i := 0; i < 6; i++ {
		b.tick(tk, b.video(tk))
	}
	old := b.m.devs[fgMAC].hmm
	if old == nil || old.cur != "bilibili" {
		t.Fatalf("before gap: %+v", old)
	}
	b.tick(120*time.Second, b.game(tk))
	d := b.m.devs[fgMAC]
	if d.hmm == old || d.hmm.cur == "bilibili" {
		t.Fatalf("hmm not reset after gap: %+v", d.hmm)
	}
}

// classic(默认)时: shown 恒等于 cur, HMM 只在后台算; 对比统计照记
func TestFgClassicEngineShadowAndCompare(t *testing.T) {
	b := newFgTB(t, fgStart())
	b.tick(tk)
	var v fgView
	for i := 0; i < 8; i++ {
		v = b.tick(tk, b.video(tk))
		if d := b.m.devs[fgMAC]; d != nil && d.shown != d.cur {
			t.Fatalf("classic: shown %q != cur %q", d.shown, d.cur)
		}
	}
	if strings.Contains(strings.Join(v.Reasons, "|"), "HMM") {
		t.Fatalf("classic view must not mention HMM: %v", v.Reasons)
	}
	if b.m.devs[fgMAC].hmm == nil || b.m.devs[fgMAC].hmm.cur != "bilibili" {
		t.Fatal("hmm shadow not computed")
	}
	sum := b.m.cmp.summary(b.now, 1)
	if sum["rounds"].(int) != 8 || sum["agree_rounds"].(int) < 5 {
		t.Fatalf("compare: %+v", sum)
	}
}

func TestFgCompareBuckets(t *testing.T) {
	c := newFgCompare()
	t0 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	// classic: A → B(20 秒后)→ A: 两次切换后的 B 段短于 30 秒 → 1 个短段
	// hmm:     一直 A
	seq := []struct{ c, h string }{{"a", "a"}, {"a", "a"}, {"b", "a"}, {"b", "a"}, {"a", "a"}, {"a", "a"}}
	for i, x := range seq {
		c.record("m1", t0.Add(time.Duration(i)*10*time.Second), 10, x.c, x.h)
	}
	s := c.summary(t0.Add(time.Minute), 1)
	cl, hm := s["classic"].(map[string]interface{}), s["hmm"].(map[string]interface{})
	if s["rounds"].(int) != 6 || s["agree_rounds"].(int) != 4 || cl["switches"].(int) != 2 || cl["short_segments"].(int) != 1 ||
		hm["switches"].(int) != 0 || hm["short_segments"].(int) != 0 {
		t.Fatalf("summary: %+v", s)
	}
	// 每小时: 6 轮 × 10 秒 = 60 设备秒 → 2 次切换 = 120 次/小时
	if cl["switches_per_hour"].(float64) != 120 || s["agree_pct"].(float64) != 66.7 {
		t.Fatalf("per hour: %+v", s)
	}
	// 小时桶滚动: 下一小时新桶; 8 天前的桶被清掉
	c.record("m1", t0.Add(time.Hour), 10, "a", "a")
	if len(c.buckets) != 2 {
		t.Fatalf("buckets: %d", len(c.buckets))
	}
	c.record("m1", t0.Add(8*24*time.Hour), 10, "a", "a")
	if len(c.buckets) != 1 {
		t.Fatalf("old buckets not pruned: %d", len(c.buckets))
	}
	// 落盘 → 载入
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	if err := os.WriteFile(fgCmpPath(dir), c.snapshot(t0.Add(8*24*time.Hour)), 0o644); err != nil {
		t.Fatal(err)
	}
	c2 := newFgCompare()
	c2.load(dir)
	if len(c2.buckets) != 1 {
		t.Fatalf("reload: %+v", c2.buckets)
	}
}

func TestFgEngineActionAndAPI(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "run"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	if fgEngineFor(dir) != fgEngineClass {
		t.Fatal("default must be classic")
	}
	if r := actionDPIFgEngine(dir, map[string]string{"engine": "magic"}); r.OK {
		t.Fatal("invalid engine accepted")
	}
	_ = os.WriteFile(fgExperimentPath(dir), []byte(`{"other":1}`), 0o644)
	if r := actionDPIFgEngine(dir, map[string]string{"engine": "hmm"}); !r.OK {
		t.Fatalf("set hmm: %+v", r)
	}
	if fgEngineFor(dir) != fgEngineHMM {
		t.Fatal("engine not hmm")
	}
	b, _ := os.ReadFile(fgExperimentPath(dir))
	if !strings.Contains(string(b), `"other"`) {
		t.Fatalf("other keys lost: %s", b)
	}
	// 同一秒内改回 classic(mtime 可能不变, size 变)
	if r := dispatchAction(newServer(dir), "dpi_fg_engine", map[string]string{"engine": "classic"}, true); !r.OK {
		t.Fatalf("dispatch: %+v", r)
	}
	if fgEngineFor(dir) != fgEngineClass {
		t.Fatal("engine not back to classic")
	}
	s := newServer(dir)
	rec := httptest.NewRecorder()
	s.apiFgCompare(rec, httptest.NewRequest("GET", "/api/fg_compare?days=7", nil))
	var out map[string]interface{}
	if json.Unmarshal(rec.Body.Bytes(), &out) != nil || out["ok"] != true || out["engine"] != "classic" || out["classic"] == nil {
		t.Fatalf("api: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.apiFgCompare(rec, httptest.NewRequest("GET", "/api/fg_compare?days=3", nil))
	if rec.Code != 400 {
		t.Fatalf("days=3: %d", rec.Code)
	}
}

// load / flush 时从文件刷新引擎; 每轮 step 不读文件
func TestFgEngineLoadedFromFile(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "run"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	_ = os.WriteFile(fgExperimentPath(dir), []byte(`{"fg_engine":"hmm"}`), 0o644)
	m := newFgModel()
	now := fgStart()
	m.load(dir, now)
	if m.engineLocked() != fgEngineHMM {
		t.Fatal("load should pick up hmm")
	}
	_ = os.WriteFile(fgExperimentPath(dir), []byte(`{"fg_engine":"classic","x":1}`), 0o644)
	m.flush(now)
	if m.engineLocked() != fgEngineClass {
		t.Fatal("flush should refresh engine")
	}
}
