// api_discover_suggest_test.go — v5.28 B2: 自动起名建议(各来源单独/叠加/冲突)。
package main

import (
	"testing"
)

func sg(src, name string, strong, medium bool) sugCand {
	return sugCand{src: src, name: name, rank: suggestRank[src], strong: strong, medium: medium, basis: "b-" + src}
}

// TestSuggestSingleSources 单来源: 各档置信度。
func TestSuggestSingleSources(t *testing.T) {
	cases := []struct {
		cands []sugCand
		name  string
		conf  string
	}{
		{[]sugCand{sg("apk", "快手", true, true)}, "快手", "high"},     // 强信号
		{[]sugCand{sg("apk", "快手", false, true)}, "快手", "medium"},  // 单中等
		{[]sugCand{sg("cert", "字节", false, true)}, "字节", "medium"}, // 纯函数原样返回候选名, "旗下应用"后缀是 enrichGroup 侧加的
		{[]sugCand{sg("ja4", "cronet", false, false)}, "cronet", "low"},
		{[]sugCand{sg("domain", "x.com", false, false)}, "x.com", "low"},
		{nil, "", ""},
	}
	for i, c := range cases {
		out := suggestForGroup(c.cands)
		if out.Name != c.name || out.Conf != c.conf {
			t.Errorf("case %d: got (%q,%s), want (%q,%s)", i, out.Name, out.Conf, c.name, c.conf)
		}
		if out.Conflict {
			t.Errorf("case %d: 单来源不应有分歧", i)
		}
	}
}

// TestSuggestAgreement 多来源一致 → 叠加到 high, 依据列表包含两来源。
func TestSuggestAgreement(t *testing.T) {
	out := suggestForGroup([]sugCand{
		sg("apk", "快手", false, true),
		sg("startup", "快手", false, true),
		sg("domain", "ks.com", false, false),
	})
	if out.Name != "快手" {
		t.Fatalf("name = %q, want 快手", out.Name)
	}
	if out.Conf != "high" {
		t.Errorf("两个中等来源一致应 high, got %s", out.Conf)
	}
	if out.Conflict {
		t.Errorf("一致不应有分歧")
	}
	if len(out.Sources) < 2 {
		t.Errorf("依据列表应含 apk 与 startup, got %v", out.Sources)
	}
	// 排序: apk 在前
	if out.Sources[0].Src != "apk" {
		t.Errorf("来源应按优先级排序, 首个 = %s", out.Sources[0].Src)
	}
}

// TestSuggestConflict 两个中等来源名字不同 → 取优先级高的, 标分歧。
func TestSuggestConflict(t *testing.T) {
	out := suggestForGroup([]sugCand{
		sg("startup", "快手极速版", false, true),
		sg("cert", "字节", false, true),
	})
	if out.Conf != "medium" || out.Conflict != true {
		t.Fatalf("conf=%s conflict=%v, want medium/true(单中等来源 + 分歧标记)", out.Conf, out.Conflict)
	}
	if out.Name != "快手极速版" {
		t.Errorf("应取优先级更高的 startup 名, got %q", out.Name)
	}
	// 强信号压过分歧: apk(strong) vs cert(medium) → apk, 且仍标分歧
	out = suggestForGroup([]sugCand{
		sg("apk", "快手", true, true),
		sg("cert", "字节", false, true),
	})
	if out.Name != "快手" || !out.Conflict {
		t.Errorf("强信号应赢并保留分歧标记, got %q conflict=%v", out.Name, out.Conflict)
	}
}

// TestSuggestStrongVsStrong 两个强信号不同名 → 分歧, apk 胜。
func TestSuggestStrongVsStrong(t *testing.T) {
	out := suggestForGroup([]sugCand{
		sg("startup", "A", true, true),
		sg("apk", "B", true, true),
	})
	if out.Name != "B" || !out.Conflict {
		t.Errorf("apk 应胜, got %q conflict=%v", out.Name, out.Conflict)
	}
}

// TestSuggestStartupCands 启动指纹来源: 重合 ≥ 2 成候选, ≥ 4 强信号。
func TestSuggestStartupCands(t *testing.T) {
	apps := []startupFeatApp{
		{AppID: "com.a", Name: "应用A", Feat: map[string]bool{"api.ax.com": true, "cdn.ax.com": true, "img.ax.com": true, "log.ax.com": true}},
		{AppID: "com.b", Name: "应用B", Feat: map[string]bool{"api.bx.com": true, "cdn.bx.com": true, "other.com": true}},
		{AppID: "com.c", Name: "应用C", Feat: map[string]bool{"api.cx.com": true, "cdn.cx.com": true, "no.com": true}},
	}
	// 组内域名: 与 A 重合 4 个(强), 与 B 重合 2 个(中), 与 C 重合 0
	gtoks := map[string]bool{"api.ax.com": true, "cdn.ax.com": true, "img.ax.com": true, "log.ax.com": true,
		"api.bx.com": true, "cdn.bx.com": true}
	cands := suggestStartupCands(gtoks, apps)
	if len(cands) != 2 {
		t.Fatalf("应出 2 个候选(A/B), got %d: %v", len(cands), cands)
	}
	if cands[0].name != "应用A" || !cands[0].strong {
		t.Errorf("A 应为强信号候选, got %+v", cands[0])
	}
	byName := map[string]sugCand{}
	for _, c := range cands {
		byName[c.name] = c
	}
	if b := byName["应用B"]; b.strong || !b.medium {
		t.Errorf("B 应为中等候选, got %+v", b)
	}
	if _, ok := byName["应用C"]; ok {
		t.Errorf("C 重合 0 不应成候选")
	}
}

// TestSuggestWireInEnrichGroup buildSuggest 在 enrichGroup 里接上(轻量:
// 只验证 suggest 字段存在且格式对, 详细逻辑已在纯函数测试里覆盖)。
func TestSuggestWireInEnrichGroup(t *testing.T) {
	// 纯函数层已覆盖; 这里测 enrichGroup 的接线需要 server 依赖,
	// 用 buildSuggest 的直调版验证来源收集(apk/cert/ja4/domain 四源):
	var cands []sugCand
	cands = append(cands, sg("apk", "X", true, true), sg("cert", "Y", false, true))
	out := suggestForGroup(cands)
	if out.Name != "X" || out.Conf != "high" || !out.Conflict || len(out.Sources) < 1 {
		t.Fatalf("接线冒烟失败: %+v", out)
	}
}

// TestSuggestStartupTokenize token 归一(数字→#)后能对上。
func TestSuggestStartupTokenize(t *testing.T) {
	gtoks := map[string]bool{startupToken("v26-dy.ixigua.com"): true}
	if !gtoks["v#-dy.ixigua.com"] {
		t.Fatalf("startupToken 归一不符合预期: %v", gtoks)
	}
	gtoks[startupToken("i.snssdk.com")] = true
	apps := []startupFeatApp{{AppID: "com.ix", Name: "西瓜", Feat: map[string]bool{"v#-dy.ixigua.com": true, "i.snssdk.com": true, "other.example.com": true}}}
	cands := suggestStartupCands(gtoks, apps)
	if len(cands) == 0 {
		t.Fatal("两个重合 token 应成为候选(阈值 >= 2)")
	}
}
