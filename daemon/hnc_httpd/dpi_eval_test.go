package main

// dpi_eval_test.go — v5.24 T4 识别自评单测。
// 覆盖: 各方法指标计算、真值映射(含未对照的 pkg:)、空数据、全部未命中、
// 系统 UID 跳过、capped 标记、按应用汇总、top_wrong / top_unknown、
// owner 降级(只算覆盖率)、GET 接口 days 参数校验、dpi_eval_clear 动作。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── 测试脚手架 ───────────────────────────────────────────────────────

func evalDir(t *testing.T) string {
	t.Helper()
	d := mkHncDir(t)
	if err := os.MkdirAll(filepath.Join(d, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	// 打开本机抓包标志(评估的 enabled 前提)。
	if err := os.WriteFile(filepath.Join(d, "run", "self_capture.enabled"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

func writePkgMap(t *testing.T, dir string, m map[string]string) {
	t.Helper()
	b, _ := json.Marshal(map[string]interface{}{"schema": 1, "map": m})
	if err := os.WriteFile(filepath.Join(dir, "data", "pkg_app_map.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeRules(t *testing.T, dir string, idToApp map[string]string) {
	t.Helper()
	type rule struct {
		ID  string `json:"id"`
		App string `json:"app"`
	}
	rules := make([]rule, 0, len(idToApp))
	for id, app := range idToApp {
		rules = append(rules, rule{ID: id, App: app})
	}
	b, _ := json.Marshal(map[string]interface{}{"rules": rules})
	if err := os.MkdirAll(filepath.Join(dir, "data", "dpi_rules.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "dpi_rules.d", "90-test.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// appendSample 往 run/label_samples.<day>.jsonl 写一行。
func appendSample(t *testing.T, dir string, ts time.Time, s evalSample) {
	t.Helper()
	path := filepath.Join(dir, "run", "label_samples."+ts.Local().Format("20060102")+".jsonl")
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
}

// seedFP 往指纹学习表塞一个可用条目(top 应用占比高、support 足够)。
func seedFP(t *testing.T, dir, ja4, alpn string, dport int, appID, appName string, w float64, now time.Time) {
	t.Helper()
	st := fpFor(dir)
	key := fpKeyOf(ja4, alpn, fpPortClass(dport))
	e := &fpEntry{
		JA4: ja4, ALPN: alpn, Port: fpPortClass(dport),
		Apps:  map[string]*fpAppCount{appID: {N: w, Name: appName, Category: "test"}},
		Total: w, First: now.Unix(), Last: now.Unix(), Upd: now.Unix(),
	}
	st.mu.Lock()
	st.loaded = true // 阻止 loadLocked 覆盖我们塞的条目
	st.m[key] = e
	st.mu.Unlock()
}

// ─── 真值映射 ─────────────────────────────────────────────────────────

func TestEvalTruthMappingAndPkgFallback(t *testing.T) {
	dir := evalDir(t)
	now := time.Unix(1_800_000_000, 0)
	writePkgMap(t, dir, map[string]string{"com.ss.android.ugc.aweme": "douyin"})
	writeRules(t, dir, map[string]string{"douyin": "抖音"})

	// 两条抖音(对照表命中)+ 一条未对照的包。
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.ss.android.ugc.aweme", UID: 10100, RuleID: "douyin"})
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.ss.android.ugc.aweme", UID: 10100, RuleID: "douyin"})
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.unknown.app", UID: 10200})

	res := evalDPI(dir, 1, now)
	if !res.Enabled {
		t.Fatal("enabled should be true")
	}
	if res.Samples != 3 {
		t.Fatalf("samples = %d, want 3", res.Samples)
	}
	if res.Apps != 2 {
		t.Fatalf("apps = %d, want 2 (douyin + pkg:com.unknown.app)", res.Apps)
	}
	// rule 方法: 2 条有 rule_id 且都 == 真值 douyin。
	rm := res.Methods["rule"]
	if rm.Predicted != 2 || rm.Correct != 2 || rm.Samples != 3 {
		t.Fatalf("rule method = %+v, want predicted=2 correct=2 samples=3", rm)
	}
	if rm.Coverage != round2(2.0/3.0) || rm.Accuracy != 1 {
		t.Fatalf("rule coverage/accuracy = %v/%v", rm.Coverage, rm.Accuracy)
	}
	// 未对照的包应出现在 top_unknown, name 去掉 pkg: 前缀。
	found := false
	for _, u := range res.TopUnknown {
		if u.Truth == "pkg:com.unknown.app" {
			found = true
			if u.Name != "com.unknown.app" {
				t.Fatalf("unknown name = %q, want com.unknown.app", u.Name)
			}
			if u.N != 1 {
				t.Fatalf("unknown n = %d, want 1", u.N)
			}
		}
	}
	if !found {
		t.Fatalf("pkg:com.unknown.app missing from top_unknown: %+v", res.TopUnknown)
	}
}

// ─── 空数据 / 全部未命中 ──────────────────────────────────────────────

func TestEvalEmpty(t *testing.T) {
	dir := evalDir(t)
	now := time.Unix(1_800_000_000, 0)
	res := evalDPI(dir, 1, now)
	if res.Samples != 0 || res.Apps != 0 {
		t.Fatalf("empty: samples=%d apps=%d", res.Samples, res.Apps)
	}
	for _, m := range []string{"rule", "fp", "owner", "combined"} {
		if res.Methods[m].Samples != 0 || res.Methods[m].Coverage != 0 {
			t.Fatalf("empty method %s = %+v", m, res.Methods[m])
		}
	}
}

func TestEvalAllMiss(t *testing.T) {
	dir := evalDir(t)
	now := time.Unix(1_800_000_000, 0)
	writePkgMap(t, dir, map[string]string{"com.x": "appx"})
	// 有样本但没有任何 rule_id / 指纹 / IP 归属 → 全部方法 predicted=0。
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.x", UID: 10100, SNI: "a.example.com"})
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.x", UID: 10100, SNI: "b.example.com"})
	res := evalDPI(dir, 1, now)
	if res.Samples != 2 {
		t.Fatalf("samples = %d", res.Samples)
	}
	for _, m := range []string{"rule", "fp", "combined"} {
		if res.Methods[m].Predicted != 0 || res.Methods[m].Coverage != 0 {
			t.Fatalf("all-miss method %s = %+v", m, res.Methods[m])
		}
	}
	// 全都认不出 → top_unknown 有 appx, snis 收集到。
	if len(res.TopUnknown) != 1 || res.TopUnknown[0].Truth != "appx" || res.TopUnknown[0].N != 2 {
		t.Fatalf("top_unknown = %+v", res.TopUnknown)
	}
	if len(res.TopUnknown[0].SNIs) != 2 {
		t.Fatalf("unknown snis = %+v", res.TopUnknown[0].SNIs)
	}
}

// ─── 指纹方法 ─────────────────────────────────────────────────────────

func TestEvalFPMethod(t *testing.T) {
	dir := evalDir(t)
	now := time.Unix(1_800_000_000, 0)
	writePkgMap(t, dir, map[string]string{"com.w": "wechat"})
	writeRules(t, dir, map[string]string{"wechat": "微信"})
	const ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"
	// 指纹表里这个 ja4 → wechat, support 足够高。
	seedFP(t, dir, ja4, "h2", 443, "wechat", "微信", 100, now)

	// 样本无 rule_id, 但 ja4 命中指纹 → fp 预测 wechat, combined 也用 fp。
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.w", UID: 10100, JA4: ja4, ALPN: "h2", DPort: 443})
	res := evalDPI(dir, 1, now)
	if res.Methods["fp"].Predicted != 1 || res.Methods["fp"].Correct != 1 {
		t.Fatalf("fp = %+v", res.Methods["fp"])
	}
	if res.Methods["combined"].Predicted != 1 || res.Methods["combined"].Correct != 1 {
		t.Fatalf("combined = %+v", res.Methods["combined"])
	}
	if res.Methods["rule"].Predicted != 0 {
		t.Fatalf("rule should be 0 (no rule_id): %+v", res.Methods["rule"])
	}
}

// ─── 系统 UID 跳过 / capped ───────────────────────────────────────────

func TestEvalSkipsSystemUID(t *testing.T) {
	dir := evalDir(t)
	now := time.Unix(1_800_000_000, 0)
	writePkgMap(t, dir, map[string]string{"com.x": "appx"})
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.x", UID: 1000})  // 系统
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.x", UID: 0})     // root
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.x", UID: 10100}) // 正常
	res := evalDPI(dir, 1, now)
	if res.SkippedSystem != 2 {
		t.Fatalf("skipped_system = %d, want 2", res.SkippedSystem)
	}
	if res.Samples != 1 {
		t.Fatalf("samples = %d, want 1", res.Samples)
	}
}

func TestEvalCapped(t *testing.T) {
	dir := evalDir(t)
	now := time.Unix(1_800_000_000, 0)
	writePkgMap(t, dir, map[string]string{"com.x": "appx"})
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.x", UID: 10100})
	// 留下当天 .capped 标记。
	capPath := filepath.Join(dir, "run", "label_samples."+now.Local().Format("20060102")+".capped")
	if err := os.WriteFile(capPath, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	res := evalDPI(dir, 1, now)
	if !res.Capped {
		t.Fatal("capped should be true")
	}
}

// ─── owner 降级 ───────────────────────────────────────────────────────

func TestEvalOwnerAccuracyNA(t *testing.T) {
	dir := evalDir(t)
	now := time.Unix(1_800_000_000, 0)
	writePkgMap(t, dir, map[string]string{"com.x": "appx"})
	// owner 库不可用(测试环境没 ip_owner.bin), owner predicted=0 → accuracy_na 不触发。
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.x", UID: 10100})
	res := evalDPI(dir, 1, now)
	// 没 IP 归属数据时 owner 覆盖率为 0, 不应崩溃。
	if res.Methods["owner"].Coverage != 0 {
		t.Fatalf("owner coverage = %v, want 0 (no ip_owner db)", res.Methods["owner"].Coverage)
	}
}

// ─── 关闭时 ───────────────────────────────────────────────────────────

func TestEvalDisabled(t *testing.T) {
	d := mkHncDir(t) // 没有 self_capture.enabled
	now := time.Unix(1_800_000_000, 0)
	res := evalDPI(d, 1, now)
	if res.Enabled {
		t.Fatal("enabled should be false when flag absent")
	}
	if res.Samples != 0 || len(res.Methods) != 0 {
		t.Fatalf("disabled result should be empty: %+v", res)
	}
	if res.Note == "" {
		t.Fatal("disabled note should explain how to enable")
	}
}

// ─── top_wrong 排序 ───────────────────────────────────────────────────

func TestEvalTopWrong(t *testing.T) {
	dir := evalDir(t)
	now := time.Unix(1_800_000_000, 0)
	writePkgMap(t, dir, map[string]string{"com.d": "douyin"})
	writeRules(t, dir, map[string]string{"douyin": "抖音", "toutiao": "今日头条"})
	// 5 条真值 douyin, rule_id 都是 toutiao(认错)。
	for i := 0; i < 5; i++ {
		appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.d", UID: 10100, RuleID: "toutiao"})
	}
	res := evalDPI(dir, 1, now)
	if len(res.TopWrong) != 1 {
		t.Fatalf("top_wrong len = %d, want 1: %+v", len(res.TopWrong), res.TopWrong)
	}
	w := res.TopWrong[0]
	if w.Truth != "douyin" || w.Pred != "toutiao" || w.N != 5 {
		t.Fatalf("top_wrong[0] = %+v", w)
	}
	if w.PredName != "今日头条" {
		t.Fatalf("pred_name = %q, want 今日头条", w.PredName)
	}
	// combined 用 rule(无用户纠正)→ 也全错, accuracy=0。
	if res.Methods["combined"].Correct != 0 || res.Methods["combined"].Accuracy != 0 {
		t.Fatalf("combined = %+v", res.Methods["combined"])
	}
}

// ─── GET 接口 days 校验 ───────────────────────────────────────────────

func TestEvalHTTPDaysValidation(t *testing.T) {
	dir := evalDir(t)
	s := &server{hncDir: dir}
	cases := []struct {
		q    string
		code int
	}{
		{"", http.StatusOK},
		{"?days=1", http.StatusOK},
		{"?days=7", http.StatusOK},
		{"?days=3", http.StatusBadRequest},
		{"?days=abc", http.StatusBadRequest},
		{"?days=0", http.StatusBadRequest},
		{"?days=-1", http.StatusBadRequest},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		s.apiDPIEval(rec, httptest.NewRequest("GET", "/api/dpi_eval"+c.q, nil))
		if rec.Code != c.code {
			t.Fatalf("days q=%q → code %d, want %d", c.q, rec.Code, c.code)
		}
	}
	// refresh=1 也应正常。
	rec := httptest.NewRecorder()
	s.apiDPIEval(rec, httptest.NewRequest("GET", "/api/dpi_eval?days=1&refresh=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh → code %d", rec.Code)
	}
	var body dpiEvalResult
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OK || body.Days != 1 {
		t.Fatalf("body = %+v", body)
	}
}

// ─── dpi_eval_clear 动作 ──────────────────────────────────────────────

func TestEvalClearAction(t *testing.T) {
	dir := evalDir(t)
	now := time.Unix(1_800_000_000, 0)
	runDir := filepath.Join(dir, "run")
	// 造出所有应删除的文件 + 一个不该动的文件。
	files := []string{
		"label_samples." + now.Local().Format("20060102") + ".jsonl",
		"label_samples." + now.Local().Format("20060102") + ".capped",
		"self_fg." + now.Local().Format("20060102") + ".jsonl",
		"dpi_eval.json",
	}
	for _, n := range files {
		if err := os.WriteFile(filepath.Join(runDir, n), []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	keep := "devices.json"
	if err := os.WriteFile(filepath.Join(runDir, keep), []byte("y"), 0o640); err != nil {
		t.Fatal(err)
	}

	resp := actionDPIEvalClear(dir)
	if !resp.OK {
		t.Fatalf("clear not ok: %+v", resp)
	}
	for _, n := range files {
		if _, err := os.Stat(filepath.Join(runDir, n)); !os.IsNotExist(err) {
			t.Fatalf("%s should be deleted", n)
		}
	}
	if _, err := os.Stat(filepath.Join(runDir, keep)); err != nil {
		t.Fatalf("unrelated file %s must survive", keep)
	}
	// self_capture.enabled 不该被删(它是开关, 不是样本)。
	if _, err := os.Stat(filepath.Join(runDir, "self_capture.enabled")); err != nil {
		t.Fatal("self_capture.enabled must survive clear")
	}
}

// ─── 缓存落盘 ─────────────────────────────────────────────────────────

func TestEvalComputeWritesFile(t *testing.T) {
	dir := evalDir(t)
	now := time.Unix(1_800_000_000, 0)
	writePkgMap(t, dir, map[string]string{"com.x": "appx"})
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.x", UID: 10100})
	evalCompute(dir, 1, now)
	b, err := os.ReadFile(dpiEvalPath(dir))
	if err != nil {
		t.Fatalf("dpi_eval.json not written: %v", err)
	}
	var r dpiEvalResult
	if json.Unmarshal(b, &r) != nil {
		t.Fatal("dpi_eval.json corrupt")
	}
	if r.Samples != 1 || r.Days != 1 {
		t.Fatalf("persisted = %+v", r)
	}
}

// 规则库认成广告 / SDK / CDN 类的样本不算规则预测(第三方服务, 不代表 App 本身),
// 单独计 sdk_samples; top_wrong 带真值名字。
func TestEvalHiddenTierRulesExcluded(t *testing.T) {
	dir := evalDir(t)
	now := time.Unix(1_800_000_000, 0)
	writePkgMap(t, dir, map[string]string{"com.d": "douyin"})
	b, _ := json.Marshal(map[string]interface{}{"rules": []map[string]string{
		{"id": "douyin", "app": "抖音", "category": "video"},
		{"id": "pangle", "app": "穿山甲广告", "category": "ads"},
		{"id": "toutiao", "app": "今日头条", "category": "news"},
	}})
	if err := os.MkdirAll(filepath.Join(dir, "data", "dpi_rules.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "dpi_rules.d", "90-test.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.d", UID: 10100, RuleID: "pangle"})
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.d", UID: 10100, RuleID: "douyin"})
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.d", UID: 10100, RuleID: "toutiao"})
	res := evalDPI(dir, 1, now)
	if res.SDKSamples != 1 {
		t.Fatalf("sdk_samples = %d, want 1", res.SDKSamples)
	}
	if m := res.Methods["rule"]; m.Predicted != 2 || m.Correct != 1 {
		t.Fatalf("rule = %+v, want predicted=2 correct=1", m)
	}
	if len(res.TopWrong) != 1 || res.TopWrong[0].Pred != "toutiao" || res.TopWrong[0].Name != "抖音" {
		t.Fatalf("top_wrong = %+v", res.TopWrong)
	}
}

// 系统 UID 在 dpid 采集端就被跳过, 数量从 run/label_samples.stats.json 读。
func TestEvalSkippedSystemFromDpidStats(t *testing.T) {
	dir := evalDir(t)
	now := time.Unix(1_800_000_000, 0)
	if err := os.WriteFile(filepath.Join(dir, "run", "label_samples.stats.json"), []byte(`{"skipped_system":7}`), 0o640); err != nil {
		t.Fatal(err)
	}
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.d", UID: 10100})
	if res := evalDPI(dir, 1, now); res.SkippedSystem != 7 {
		t.Fatalf("skipped_system = %d, want 7", res.SkippedSystem)
	}
}
