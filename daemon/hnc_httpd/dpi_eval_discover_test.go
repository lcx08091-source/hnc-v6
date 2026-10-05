// dpi_eval_discover_test.go — v5.28 B1: 新应用发现自评(纯度 / 完整度)。
package main

import (
	"fmt"
	"testing"
)

// discSamples 合成样本: 两个包各两个专属可注册域(4 轮突发, 共现边权 ≈4
// 过阈值), 共享 SDK 域名偶发(边权 1~2 不过阈值 → 单域组)。
func discSamples() []evalSample {
	const base = int64(1791000000)
	mk := func(t int64, sni, pkg string) evalSample {
		return evalSample{Ts: base + t, Pkg: pkg, SNI: sni, UID: 10086}
	}
	var ss []evalSample
	for r := int64(0); r < 4; r++ {
		t := r * 600
		ss = append(ss,
			mk(t, "api.appa-1.com", "com.a.app"), mk(t+1, "cdn.appa-1.com", "com.a.app"),
			mk(t+2, "img.appa-2.net", "com.a.app"), mk(t+3, "cdn.appa-2.net", "com.a.app"),
			mk(t+300, "ws.appb-1.org", "com.b.app"), mk(t+301, "img.appb-1.org", "com.b.app"),
			mk(t+302, "api.appb-2.io", "com.b.app"), mk(t+303, "img.appb-2.io", "com.b.app"))
	}
	ss = append(ss, mk(5, "sdk.shared-cdn.com", "com.a.app"), mk(605, "sdk.shared-cdn.com", "com.a.app"))
	return ss
}

func TestEvalDiscoverPureAndComplete(t *testing.T) {
	d := evalDiscover(discSamples())
	if d == nil {
		t.Fatal("evalDiscover 不应返回 nil")
	}
	if d.Samples != 34 {
		t.Errorf("samples = %d, want 34", d.Samples)
	}
	// 两个包各 4 轮突发 → 2 个多域组 + sdk 单域组 = 3 组
	if d.Groups != 3 {
		t.Errorf("groups = %d, want 3(两包各一组 + SDK 单域组)", d.Groups)
	}
	if d.Purity < 0.999 {
		t.Errorf("纯度 = %v, want ≈1.0(每组成员同包)", d.Purity)
	}
	// 完整度: com.a.app 的 3 个未知域里 sdk(共享域)单独成组、专属 2 域同组
	// → 2/3; com.b.app 2/2 → 总 (2+2)/(3+2) = 0.8(共享 SDK 域不并组是预期)。
	if d.Completeness < 0.79 || d.Completeness > 0.81 {
		t.Errorf("完整度 = %v, want 0.8", d.Completeness)
	}
	if d.Hubs != 0 {
		t.Errorf("hubs = %d, want 0", d.Hubs)
	}
	if len(d.Variants) != 3 {
		t.Fatalf("variants = %d, want 3(当前/更松/更紧)", len(d.Variants))
	}
	if d.Variants[0].Label != "当前" || d.Variants[1].Label != "更松" || d.Variants[2].Label != "更紧" {
		t.Errorf("variants 顺序 = %v", []string{d.Variants[0].Label, d.Variants[1].Label, d.Variants[2].Label})
	}
	// 顶层指标 = 当前参数
	if d.Purity != d.Variants[0].Purity || d.Completeness != d.Variants[0].Completeness || d.Groups != d.Variants[0].Groups {
		t.Errorf("顶层指标应等于当前参数变体")
	}
}

func TestEvalDiscoverHubCounted(t *testing.T) {
	// 25 个互不相邻的 leaf 域 + hub 域: hub 度数 25 > 24 → 被判枢纽,
	// 不参与合并 → 每包(leaf 域)各自单域组, 完整度骤降。
	const base = int64(1791000000)
	var ss []evalSample
	for i := int64(1); i <= 25; i++ {
		for r := int64(0); r < 4; r++ {
			t0 := (i-1)*40 + r*10
			ss = append(ss,
				evalSample{Ts: base + t0, Pkg: "com.hub.app", SNI: "hub.example.net", UID: 10086},
				evalSample{Ts: base + t0 + 1, Pkg: "com.hub.app", SNI: mkLeaf(i), UID: 10086})
		}
	}
	d := evalDiscover(ss)
	if d.Hubs < 1 {
		t.Errorf("hubs = %d, want ≥1(example.net 度数 25 > 24)", d.Hubs)
	}
	if d.Completeness > 0.5 {
		t.Errorf("枢纽被排除后 25 个 leaf 域应各自单域组, 完整度 = %v(应很低)", d.Completeness)
	}
}

func mkLeaf(i int64) string {
	return fmt.Sprintf("api.lf%02de.com", i) // 25 个互不相同的可注册域
}

func TestEvalDiscoverEmpty(t *testing.T) {
	d := evalDiscover(nil)
	if d == nil {
		t.Fatal("nil 样本应返回带说明的结果")
	}
	if d.Samples != 0 || d.Groups != 0 {
		t.Errorf("空样本: samples=%d groups=%d, want 0/0", d.Samples, d.Groups)
	}
	if d.Note == "" {
		t.Errorf("空样本应有说明")
	}
}

func TestEvalDiscoverOnlyKnownSamples(t *testing.T) {
	// 规则库认出的样本(rule_id 非空)不参与 —— 与线上一致
	ss := []evalSample{{Ts: 100, Pkg: "com.a.app", SNI: "api.appa-1.com", RuleID: "r1", UID: 10086}}
	d := evalDiscover(ss)
	if d.Samples != 0 {
		t.Errorf("已知样本不应参与 discover 评估, samples = %d", d.Samples)
	}
}
