package output

import (
	"encoding/json"
	"testing"
)

// v5.27 T1: 带 _parent_rule_id 的规则(自动扩展 / 规则库扩充 / 导入的规则包)
// 要把后缀并进父规则, 分类结果是父 id —— 规则 id 就是应用 id, 子 id 独立存在
// 会把同一个应用拆成两份统计, 识别自评里也被判成「认错」。
func compileFilesForTest(t *testing.T, files ...string) []l3Rule {
	t.Helper()
	var all []externalRule
	for _, s := range files {
		var f externalRuleFile
		if err := json.Unmarshal([]byte(s), &f); err != nil {
			t.Fatalf("parse: %v", err)
		}
		all = append(all, f.Rules...)
	}
	return compileExternalRules(all)
}

func classifyForTest(rules []l3Rule, host string) string {
	r, ok := classifyHostIndexed(buildHostIndex(rules), rules, host)
	if !ok {
		return ""
	}
	return r.ID
}

const attachParentFile = `{"rules":[
 {"id":"douyin","app":"抖音","category":"video","suffixes":["douyin.com","amemv.com"]},
 {"id":"wechat","app":"微信","category":"social","suffixes":["weixin.qq.com"]}
]}`

func TestAttachChildToParent(t *testing.T) {
	child := `{"rules":[
	 {"id":"douyin_autoexp_api5","app":"抖音 (自动扩展: api5)","category":"video",
	  "suffixes":["api5-normal.amemv.com","x.douyinpic.com"],"_parent_rule_id":"douyin"}
	]}`
	rules := compileFilesForTest(t, attachParentFile, child)
	for host, want := range map[string]string{
		"api5-normal.amemv.com": "douyin",
		"p3.x.douyinpic.com":    "douyin",
		"x.douyinpic.com":       "douyin",
		"www.douyin.com":        "douyin",
		"long.weixin.qq.com":    "wechat",
		"unrelated.example.com": "",
	} {
		if got := classifyForTest(rules, host); got != want {
			t.Errorf("%s → %q, want %q", host, got, want)
		}
	}
	for _, r := range rules {
		if r.ID == "douyin_autoexp_api5" {
			t.Fatalf("子规则挂靠后不应独立存在")
		}
		if r.ID == "douyin" {
			n := 0
			for _, s := range r.Suffixes {
				if s == "x.douyinpic.com" {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("父规则后缀应合并且去重, got %v", r.Suffixes)
			}
		}
	}
}

func TestAttachMissingParentStaysIndependent(t *testing.T) {
	child := `{"rules":[
	 {"id":"gone_autoexp_x","app":"某应用 (自动扩展: x)","category":"video",
	  "suffixes":["x.gone.example"],"_parent_rule_id":"gone"}
	]}`
	rules := compileFilesForTest(t, attachParentFile, child)
	if got := classifyForTest(rules, "x.gone.example"); got != "gone_autoexp_x" {
		t.Fatalf("父规则不存在时应保持独立规则, got %q", got)
	}
}

func TestAttachAfterDedupAndChains(t *testing.T) {
	// 父规则在后面的文件里被同 id 覆盖(后写覆盖)→ 挂到覆盖后的那条;
	// 父的父链式挂靠到根; 互相挂靠成环 → 保持独立, 不死循环。
	override := `{"rules":[{"id":"douyin","app":"抖音","category":"video","suffixes":["douyin.com"]}]}`
	child := `{"rules":[
	 {"id":"douyin_v2fly","app":"抖音","category":"video","suffixes":["iesdouyin.com"],"_parent_rule_id":"douyin"},
	 {"id":"imp_douyin_v2fly","app":"抖音","category":"video","suffixes":["snssdk.example"],"_parent_rule_id":"douyin_v2fly"},
	 {"id":"loop_a","app":"A","category":"game","suffixes":["a.loop.example"],"_parent_rule_id":"loop_b"},
	 {"id":"loop_b","app":"B","category":"game","suffixes":["b.loop.example"],"_parent_rule_id":"loop_a"},
	 {"id":"self","app":"S","category":"game","suffixes":["self.example"],"_parent_rule_id":"self"}
	]}`
	rules := compileFilesForTest(t, attachParentFile, override, child)
	for host, want := range map[string]string{
		"www.douyin.com":     "douyin",
		"amemv.com":          "", // 被 override 覆盖后父规则只剩 douyin.com
		"m.iesdouyin.com":    "douyin",
		"api.snssdk.example": "douyin",
		"a.loop.example":     "loop_a",
		"b.loop.example":     "loop_b",
		"self.example":       "self",
	} {
		if got := classifyForTest(rules, host); got != want {
			t.Errorf("%s → %q, want %q", host, got, want)
		}
	}
}

// 子规则多了也不能把真正的应用规则挤出上限(上限只算挂靠后的独立规则)。
func TestAttachChildrenDoNotConsumeRuleCap(t *testing.T) {
	var rs []externalRule
	for i := 0; i < 1500; i++ {
		rs = append(rs, externalRule{ID: "douyin_autoexp_" + itoaForTest(i), Category: "video",
			Suffixes: []string{"h" + itoaForTest(i) + ".amemv.com"}, ParentRuleID: "douyin"})
	}
	rs = append(rs, externalRule{ID: "douyin", App: "抖音", Category: "video", Suffixes: []string{"douyin.com"}})
	rs = append(rs, externalRule{ID: "late_app", App: "晚到的应用", Category: "game", Suffixes: []string{"late.example"}})
	rules := compileExternalRules(rs)
	if got := classifyForTest(rules, "late.example"); got != "late_app" {
		t.Fatalf("late_app 被子规则挤掉了: %q (rules=%d)", got, len(rules))
	}
	if got := classifyForTest(rules, "h1499.amemv.com"); got != "douyin" {
		t.Fatalf("h1499 → %q", got)
	}
}

func itoaForTest(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
