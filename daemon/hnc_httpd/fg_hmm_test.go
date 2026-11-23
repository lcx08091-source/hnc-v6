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

// 显式切到 classic 时: shown 恒等于 cur, HMM 只在后台算; 对比统计照记
func TestFgClassicEngineShadowAndCompare(t *testing.T) {
	b := newFgTBHMM(t, fgStart(), fgEngineClass)
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
	if fgEngineFor("") != fgEngineHMM || fgEngineFor(dir) != fgEngineHMM {
		t.Fatalf("empty/missing dir default must be hmm, got empty=%q dir=%q", fgEngineFor(""), fgEngineFor(dir))
	}
	if r := actionDPIFgEngine(dir, map[string]string{"engine": "magic"}); r.OK {
		t.Fatal("invalid engine accepted")
	}
	_ = os.WriteFile(fgExperimentPath(dir), []byte(`{"other":1}`), 0o644)
	if fgEngineFor(dir) != fgEngineHMM {
		t.Fatal("missing fg_engine key must default to hmm")
	}
	// 显式切换到 classic -> 落盘读取为 classic 且保留其它键
	if r := actionDPIFgEngine(dir, map[string]string{"engine": "classic"}); !r.OK {
		t.Fatalf("set classic: %+v", r)
	}
	if fgEngineFor(dir) != fgEngineClass {
		t.Fatal("engine not classic")
	}
	b, _ := os.ReadFile(fgExperimentPath(dir))
	if !strings.Contains(string(b), `"other"`) {
		t.Fatalf("other keys lost after classic: %s", b)
	}
	s := newServer(dir)
	rec := httptest.NewRecorder()
	s.apiFgCompare(rec, httptest.NewRequest("GET", "/api/fg_compare?days=7", nil))
	var out map[string]interface{}
	if json.Unmarshal(rec.Body.Bytes(), &out) != nil || out["ok"] != true || out["engine"] != "classic" || out["classic"] == nil {
		t.Fatalf("api (classic): %s", rec.Body.String())
	}
	// 同一秒内再切回 hmm -> 落盘读取为 hmm 且保留其它键
	if r := dispatchAction(s, "dpi_fg_engine", map[string]string{"engine": "hmm"}, true); !r.OK {
		t.Fatalf("dispatch hmm: %+v", r)
	}
	if fgEngineFor(dir) != fgEngineHMM {
		t.Fatal("engine not back to hmm")
	}
	b, _ = os.ReadFile(fgExperimentPath(dir))
	if !strings.Contains(string(b), `"other"`) {
		t.Fatalf("other keys lost after hmm: %s", b)
	}
	rec = httptest.NewRecorder()
	s.apiFgCompare(rec, httptest.NewRequest("GET", "/api/fg_compare?days=7", nil))
	out = nil
	if json.Unmarshal(rec.Body.Bytes(), &out) != nil || out["ok"] != true || out["engine"] != "hmm" || out["hmm"] == nil {
		t.Fatalf("api (hmm): %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.apiFgCompare(rec, httptest.NewRequest("GET", "/api/fg_compare?days=3", nil))
	if rec.Code != 400 {
		t.Fatalf("days=3: %d", rec.Code)
	}
}

// load / flush 时从文件刷新引擎; 空目录默认 hmm, 显式 classic 才切 classic, 再切回 hmm 正常生效
func TestFgEngineLoadedFromFile(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "run"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	m := newFgModel()
	now := fgStart()
	m.load(dir, now)
	if m.engineLocked() != fgEngineHMM {
		t.Fatalf("empty dir load should default to hmm, got %q", m.engineLocked())
	}
	_ = os.WriteFile(fgExperimentPath(dir), []byte(`{"fg_engine":"classic","x":1}`), 0o644)
	m.flush(now)
	if m.engineLocked() != fgEngineClass {
		t.Fatalf("flush should refresh engine to classic, got %q", m.engineLocked())
	}
	_ = os.WriteFile(fgExperimentPath(dir), []byte(`{"fg_engine":"hmm","x":1}`), 0o644)
	m.flush(now)
	if m.engineLocked() != fgEngineHMM {
		t.Fatalf("flush should refresh engine back to hmm, got %q", m.engineLocked())
	}
}

// (1) 默认新建并带空目录加载的模型默认走 hmm 引擎
func TestFgDefaultModelUsesHMM(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"data", "run"} {
		_ = os.MkdirAll(filepath.Join(dir, sub), 0o755)
	}
	m := newFgModel()
	if m.engineLocked() != fgEngineHMM {
		t.Fatalf("newFgModel default engine=%q, want %q", m.engineLocked(), fgEngineHMM)
	}
	start := fgStart()
	m.load(dir, start)
	if m.engineLocked() != fgEngineHMM {
		t.Fatalf("after load(emptyDir) engine=%q, want %q", m.engineLocked(), fgEngineHMM)
	}
	b := &fgTB{t: t, m: m, now: start, keys: map[string]string{}}
	b.tick(tk)
	var v fgView
	for i := 0; i < 4; i++ {
		v = b.tick(tk, b.video(tk))
	}
	if v.AppID != "bilibili" || !strings.Contains(strings.Join(v.Reasons, "|"), "HMM 后验") {
		t.Fatalf("default model should use HMM foreground & reasons, got %+v", v)
	}
}

// (2) 长视频 playBufSec > 0 在连续 2 轮 0 字节缓冲间隙下 HMM 不掉前台, 缓冲耗尽后正常释放
func TestFgHMMPlayBufferHoldsAcrossZeroByteTicks(t *testing.T) {
	b := newFgTBHMM(t, fgStart(), fgEngineHMM)
	b.tick(tk)
	var v fgView
	for i := 0; i < 6; i++ {
		v = b.tick(tk, b.video(tk))
	}
	if v.AppID != "bilibili" {
		t.Fatalf("setup video fg failed: %+v", v)
	}
	a := b.m.devs[fgMAC].apps["bilibili"]
	if a == nil || a.playBufSec < 25 {
		t.Fatalf("expected charged playBufSec >= 25s, got %+v", a)
	}
	// 连续 2 轮 0 字节(20 秒本地缓冲区续播): playBufSec > 0, HMM 不得因 allSilent 把视频清出前台
	for round := 1; round <= 2; round++ {
		v = b.tick(tk)
		if a.playBufSec <= 0 {
			t.Fatalf("round %d: expected playBufSec > 0, got %.1f", round, a.playBufSec)
		}
		if v.AppID != "bilibili" || b.m.devs[fgMAC].hmm.cur != "bilibili" {
			t.Fatalf("round %d: HMM dropped buffered video foreground: view=%+v hmmCur=%q playBuf=%.1f",
				round, v, b.m.devs[fgMAC].hmm.cur, a.playBufSec)
		}
		if v.State != "paused" || !strings.Contains(strings.Join(v.EvidenceTags, "|"), "缓冲续播") {
			t.Fatalf("round %d: unexpected view state/tags during buffer hold: %+v", round, v)
		}
	}
	// 缓冲耗尽并继续静默后正常释放前台(无锁屏僵尸前台)
	released := false
	for i := 0; i < 8; i++ {
		if v = b.tick(tk); v.AppID == "" {
			released = true
			break
		}
	}
	if !released {
		t.Fatalf("expected foreground release after playBufSec drained, got %+v (playBuf=%.1f)", v, a.playBufSec)
	}
}

// (3) 微信语音持续通话(伴随轨)期间打开淘宝交互, HMM 主前台顺利切给淘宝且微信留在 Companion
func TestFgHMMCompanionCallYieldsToShopping(t *testing.T) {
	b := newFgTBHMM(t, fgStart(), fgEngineHMM)
	b.tick(tk)
	wxCall := func() []fgObs {
		return []fgObs{{
			MAC: fgMAC, ID: "wechat", Name: "微信", Category: "voip",
			Key: b.key("wxcall", "2.2.2.8"), Up: 40 << 10, Dn: 60 << 10, DSCPClass: 3,
		}}
	}
	taobaoShop := func() []fgObs {
		var out []fgObs
		for i := 0; i < 5; i++ {
			out = append(out, fob("taobao", "手机淘宝", "shopping", b.newKey("4.4.8.8"), 2<<10, 30<<10))
		}
		return out
	}

	var v fgView
	// 独自打微信语音: 正常显示在前台
	for i := 0; i < 6; i++ {
		v = b.tick(tk, wxCall())
	}
	if v.AppID != "wechat" {
		t.Fatalf("solo voice call should be HMM foreground, got %+v", v)
	}

	// 保持微信语音不断, 打开手机淘宝浏览商品: HMM 主前台切给淘宝, 微信退居 Companion 伴随轨
	for i := 0; i < 4; i++ {
		v = b.tick(tk, wxCall(), taobaoShop())
	}
	if v.AppID != "taobao" || b.m.devs[fgMAC].hmm.cur != "taobao" {
		t.Fatalf("expected HMM main foreground to switch to taobao, got view=%+v hmmCur=%q", v, b.m.devs[fgMAC].hmm.cur)
	}
	if v.Companion == nil || v.Companion.AppID != "wechat" || v.Companion.Mode != "call" {
		t.Fatalf("expected wechat in Companion call slot, got %+v", v.Companion)
	}

	// 关掉淘宝继续独自语音: 微信恢复主前台
	for i := 0; i < 5; i++ {
		v = b.tick(tk, wxCall())
	}
	if v.AppID != "wechat" {
		t.Fatalf("expected wechat to reclaim foreground after shopping stopped, got %+v", v)
	}
}

// (4) doze 锁屏静默态下弱消息推送(< 52 分且无启动指纹)不抢占 HMM 前台
func TestFgHMMDozeSuppressesWeakPush(t *testing.T) {
	b := newFgTBHMM(t, fgStart(), fgEngineHMM)
	b.tick(tk, b.wechatHB())
	// 连续 70 秒静默进入 doze 锁屏态
	var v fgView
	for i := 0; i < 7; i++ {
		v = b.tick(tk, b.wechatHB())
	}
	d := b.m.devs[fgMAC]
	if d == nil || d.screenState != "doze" || v.AppID != "" {
		t.Fatalf("expected device in doze with empty fg, got screen=%q view=%+v", d.screenState, v)
	}

	// 模拟锁屏推送唤醒(LastPushWakeAt 生效保持 doze), 连续 4 轮收到普通社交消息弱突发(20 < inst < 52)
	for i := 0; i < 4; i++ {
		b.m.setSidechan(nil, map[string]fgDevSideHint{
			fgMAC: {LastPushWakeAt: b.now.Add(tk).Unix()},
		})
		pushObs := []fgObs{
			fob("wechat", "微信", "social", b.newKey("2.2.2.9"), 1<<10, 12<<10),
			fob("wechat", "微信", "social", b.newKey("2.2.2.10"), 1<<10, 12<<10),
		}
		v = b.tick(tk, pushObs)
		wx := d.apps["wechat"]
		if d.screenState != "doze" {
			t.Fatalf("round %d: expected screenState=doze, got %q", i+1, d.screenState)
		}
		if wx == nil || wx.inst <= hmmTheta || wx.inst >= 52.0 {
			t.Fatalf("round %d: expected weak push inst in (%.0f, 52), got %+v", i+1, hmmTheta, wx)
		}
		if v.AppID != "" || d.hmm.cur != "" {
			t.Fatalf("round %d: weak push in doze hijacked HMM foreground: view=%+v hmmCur=%q", i+1, v, d.hmm.cur)
		}
	}
}

// (5) dt = 30s 省电粗采样档下 HMM 置信度扣减 10 分(上限 ≤ 85, < 95)
func TestFgHMMCoarseTickCapsConfidence(t *testing.T) {
	b := newFgTBHMM(t, fgStart(), fgEngineHMM)
	b.tick(30 * time.Second)
	var v fgView
	for i := 0; i < 6; i++ {
		v = b.tick(30*time.Second, b.video(30*time.Second))
	}
	if v.AppID != "bilibili" || !v.Coarse || v.TickSec != 30 {
		t.Fatalf("expected 30s coarse HMM foreground bilibili, got %+v", v)
	}
	if v.Confidence <= 0 || v.Confidence > 85 || v.Confidence >= 95 {
		t.Fatalf("expected coarse HMM confidence <= 85 (< 95), got %d (post=%.3f)", v.Confidence, b.m.devs[fgMAC].hmm.post)
	}
}

func TestFgHmmRC2CompareForgetAndDevCap(t *testing.T) {
	c := newFgCompare()
	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	// 1. 320 unique MACs in same minute -> hard-capped at fgCmpMaxDevs (256)
	const hx = "0123456789abcdef"
	mkMAC := func(i int) string {
		return "02:11:22:33:" + string([]byte{hx[(i>>12)&0xf], hx[(i>>8)&0xf]}) + ":" + string([]byte{hx[(i>>4)&0xf], hx[i&0xf]})
	}
	for i := 0; i < 320; i++ {
		c.record(mkMAC(i), t0.Add(time.Duration(i)*time.Millisecond), 10, "a", "a")
	}
	if len(c.devs) != fgCmpMaxDevs {
		t.Fatalf("fgCompare devs=%d, want cap %d", len(c.devs), fgCmpMaxDevs)
	}

	// 2. forget(mac) removes target device immediately
	latestMAC := mkMAC(319)
	c.forget(strings.ToUpper(latestMAC))
	if _, exists := c.devs[latestMAC]; exists {
		t.Fatalf("forget(%s) did not remove entry", latestMAC)
	}

	// 3. > 30m idle devices are evicted automatically on record/snapshot/summary
	tLater := t0.Add(35 * time.Minute)
	c.record("aa:bb:cc:00:00:99", tLater, 10, "b", "b")
	if len(c.devs) != 1 || c.devs["aa:bb:cc:00:00:99"] == nil {
		t.Fatalf("expected >30m idle devs pruned leaving 1 active dev, got %d", len(c.devs))
	}
	_ = c.summary(tLater.Add(31*time.Minute), 1)
	if len(c.devs) != 0 {
		t.Fatalf("expected summary after 31m idle to prune remaining dev, got %d", len(c.devs))
	}
}

