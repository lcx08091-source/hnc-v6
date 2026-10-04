package main

import (
	"os"
	"path/filepath"
	"testing"
)

// v5.27 T1: 应用目录与 dpid 的规则挂靠一致 —— _auto_expanded 等子规则并进父应用,
// 不再作为「名字相同、id 不同」的另一个应用出现在应用列表 / 限时选择里。
func TestAppCatalogAttachChildren(t *testing.T) {
	dir := t.TempDir()
	rd := filepath.Join(dir, "etc", "dpi_rules.d")
	_ = os.MkdirAll(rd, 0o755)
	_ = os.WriteFile(filepath.Join(rd, "30-video.json"), []byte(`{"rules":[
	 {"id":"douyin","app":"抖音","category":"video","suffixes":["douyin.com"]},
	 {"id":"loop_a","app":"A","category":"game","suffixes":["a.example"],"_parent_rule_id":"loop_b"},
	 {"id":"loop_b","app":"B","category":"game","suffixes":["b.example"],"_parent_rule_id":"loop_a"}]}`), 0o644)
	_ = os.WriteFile(filepath.Join(rd, "_auto_expanded.json"), []byte(`{"rules":[
	 {"id":"douyin_autoexp_api5","app":"抖音 (自动扩展: api5)","category":"video","suffixes":["api5.amemv.com"],"_parent_rule_id":"douyin"},
	 {"id":"gone_autoexp_x","app":"X","category":"video","suffixes":["x.gone.example"],"_parent_rule_id":"gone"}]}`), 0o644)
	_ = os.WriteFile(filepath.Join(rd, "_imported.json"), []byte(`{"rules":[
	 {"id":"imp_douyin_autoexp_api5","app":"抖音","category":"video","suffixes":["api6.amemv.com"],"_parent_rule_id":"douyin_autoexp_api5"}]}`), 0o644)
	c := loadAppCatalog(dir)
	if _, ok := c.apps["douyin_autoexp_api5"]; ok {
		t.Fatal("子规则不应作为独立应用出现")
	}
	if _, ok := c.apps["imp_douyin_autoexp_api5"]; ok {
		t.Fatal("链式子规则不应作为独立应用出现")
	}
	got := map[string]bool{}
	for _, s := range c.apps["douyin"].Suffixes {
		got[s] = true
	}
	if !got["douyin.com"] || !got["api5.amemv.com"] || !got["api6.amemv.com"] {
		t.Fatalf("父应用后缀未合并: %v", c.apps["douyin"].Suffixes)
	}
	for _, id := range []string{"gone_autoexp_x", "loop_a", "loop_b"} {
		if _, ok := c.apps[id]; !ok {
			t.Errorf("%s 应保持独立(父不存在 / 成环)", id)
		}
	}
	for _, id := range c.byCat["video"] {
		if id == "douyin_autoexp_api5" {
			t.Fatal("byCat 里不应有子规则")
		}
	}
}
