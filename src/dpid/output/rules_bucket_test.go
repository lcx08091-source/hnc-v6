package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// v5.27 T5: 出厂规则目录 data/dpi_rules.d/ 的每个 bucket: ≤ 1 MiB、合法 JSON、
// 规则 id(规范化后)全目录不重复、类别非空; 挂靠的子规则(_parent_rule_id)父规则必须存在。
func TestShippedRuleBuckets(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(testDataDir, "dpi_rules.d", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v (%d)", err, len(files))
	}
	sort.Strings(files)
	idFile := map[string]string{}
	var all []externalRule
	for _, f := range files {
		base := filepath.Base(f)
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() > externalRulesSubsetMaxBytes {
			t.Errorf("%s: %d bytes > 1 MiB", base, fi.Size())
		}
		b, _ := os.ReadFile(f)
		if !json.Valid(b) {
			t.Errorf("%s: invalid JSON", base)
			continue
		}
		var sub externalRuleFile
		if err := json.Unmarshal(b, &sub); err != nil {
			t.Errorf("%s: %v", base, err)
			continue
		}
		for _, r := range sub.Rules {
			id := normalizeRuleID(r.ID)
			if id == "" {
				t.Errorf("%s: empty id", base)
				continue
			}
			if prev, dup := idFile[id]; dup {
				t.Errorf("id %q in both %s and %s", id, prev, base)
			}
			idFile[id] = base
			if strings.TrimSpace(r.Category) == "" {
				t.Errorf("%s: rule %s has empty category", base, id)
			}
		}
		all = append(all, sub.Rules...)
	}
	for _, r := range all {
		if p := normalizeRuleID(r.ParentRuleID); p != "" {
			if _, ok := idFile[p]; !ok {
				t.Errorf("rule %s: parent %q not shipped", r.ID, p)
			}
		}
	}
	// 挂靠后的独立规则不超过加载上限, 且子规则一条都不剩
	compiled := compileExternalRules(all)
	if len(compiled) >= maxCompiledRules {
		t.Errorf("compiled %d rules, cap %d", len(compiled), maxCompiledRules)
	}
	for _, r := range compiled {
		if r.parentID != "" && r.parentID != r.ID {
			t.Errorf("child %s not attached (parent %s)", r.ID, r.parentID)
		}
	}
}

// v2fly 并入的子域名按父应用分类; 新应用可分类; 冲突的后缀不被抢走
func TestV2flyBucketClassify(t *testing.T) {
	rules, perFile := loadRuleDirForTest(t)
	if _, ok := perFile["46-v2fly-a.json"]; !ok {
		t.Skip("46-v2fly-a.json not generated")
	}
	idx := buildHostIndex(rules)
	for host, want := range map[string]string{
		"www.bilibili.com":   "bilibili",
		"i0.hdslb.com":       "bilibili",
		"www.acfun.cn":       "acfun",
		"api.amemv.com":      "douyin",
		"www.reddit.com":     "reddit",
		"music.163.com":      "netease_music",
		"api.qishui.com":     "qishui_music", // douyin 清单里的汽水音乐域名不抢
		"www.netflix.com":    "netflix",
		"cdn.discordapp.com": "discord",
		"a.akamaized.net":    "akamai_cdn",
	} {
		r, ok := classifyHostIndexed(idx, rules, host)
		if !ok || r.ID != want {
			t.Errorf("%s → %q ok=%v, want %q", host, r.ID, ok, want)
		}
	}
}
