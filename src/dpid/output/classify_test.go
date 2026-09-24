package output

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const testDataDir = "../../../data"

// classifyHostLinear 是 v5.13 之前的 classifyHost 原样实现(只把规则来源改成
// 参数), 仅用于等价性测试与基准对比。
func classifyHostLinear(rules []l3Rule, host string) (l3Rule, bool) {
	host = normalizeName(host)
	if host == "" {
		return l3Rule{}, false
	}
	for _, want := range []PriorityClass{PrioritySpecific, PriorityFallback} {
		bestLen := -1
		var best l3Rule
		for _, r := range rules {
			if r.Priority != want {
				continue
			}
			for _, suf := range r.Suffixes {
				suf = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(suf), "."))
				if suf == "" {
					continue
				}
				if host == suf || strings.HasSuffix(host, "."+suf) {
					if len(suf) > bestLen {
						bestLen = len(suf)
						best = r
					}
				}
			}
		}
		if bestLen >= 0 {
			return best, true
		}
	}
	return l3Rule{}, false
}

// classifyHostIndexed 是新实现的纯函数形式(绕过 loadL3Rules 的固定路径)。
func classifyHostIndexed(idx *hostIndex, rules []l3Rule, host string) (l3Rule, bool) {
	host = normalizeName(host)
	if host == "" {
		return l3Rule{}, false
	}
	if i, ok := idx.lookup(host); ok {
		return rules[i], true
	}
	return l3Rule{}, false
}

// loadRuleDirForTest 复刻 loadL3RulesFromDir 的读取/合并流程(glob *.json、
// 文件名排序、compileExternalRules 去重、再拼 builtinRules), 但解析失败直接
// 让测试失败 —— 线上 loader 只会 WARN 跳过, 测试必须把坏文件拦在提交前。
func loadRuleDirForTest(t testing.TB) ([]l3Rule, map[string][]externalRule) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(testDataDir, "dpi_rules.d", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("glob dpi_rules.d: %v (%d files)", err, len(files))
	}
	sort.Strings(files)
	perFile := make(map[string][]externalRule)
	var all []externalRule
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if len(b) > externalRulesSubsetMaxBytes {
			t.Fatalf("%s exceeds subset cap", f)
		}
		var sub externalRuleFile
		if err := json.Unmarshal(b, &sub); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		perFile[filepath.Base(f)] = sub.Rules
		all = append(all, sub.Rules...)
	}
	compiled := compileExternalRules(all)
	merged := append(append([]l3Rule{}, compiled...), builtinRules...)
	return merged, perFile
}

func loadLegacyRulesForTest(t testing.TB) []l3Rule {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testDataDir, "dpi_rules.json"))
	if err != nil {
		t.Fatalf("read dpi_rules.json: %v", err)
	}
	var f externalRuleFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse dpi_rules.json: %v", err)
	}
	return append(compileExternalRules(f.Rules), builtinRules...)
}

func TestRulesDirLoadsCNAppsExtra(t *testing.T) {
	rules, perFile := loadRuleDirForTest(t)
	extra, ok := perFile["45-cn-apps-extra.json"]
	if !ok || len(extra) == 0 {
		t.Fatalf("45-cn-apps-extra.json 未被 glob 加载")
	}
	// 新文件的每条规则都必须能编译(id/category 合法、有后缀)。
	if got := len(compileExternalRules(extra)); got != len(extra) {
		t.Fatalf("45-cn-apps-extra: %d/%d 条规则编译成功", got, len(extra))
	}
	// id 不得与其他子集冲突(冲突会触发 last-write-wins 静默覆盖别人的规则)。
	idFile := map[string]string{}
	for fname, rs := range perFile {
		for _, r := range rs {
			id := normalizeRuleID(r.ID)
			if prev, dup := idFile[id]; dup && (fname == "45-cn-apps-extra.json" || prev == "45-cn-apps-extra.json") {
				t.Errorf("id %q 同时出现在 %s 与 %s", id, prev, fname)
			}
			idFile[id] = fname
		}
	}
	// 新文件的后缀不得与其他子集重复。
	other := map[string]string{}
	for fname, rs := range perFile {
		if fname == "45-cn-apps-extra.json" {
			continue
		}
		for _, r := range rs {
			for _, s := range normalizeSuffixList(append(append([]string{}, r.Suffixes...), r.Domains...)) {
				other[s] = r.ID
			}
		}
	}
	for _, r := range extra {
		for _, s := range normalizeSuffixList(r.Suffixes) {
			if id, dup := other[s]; dup {
				t.Errorf("后缀 %q (%s) 与已有规则 %s 重复", s, r.ID, id)
			}
		}
	}
	// 抽查语义: 新规则命中, 且更长后缀压过集团兜底规则。
	idx := buildHostIndex(rules)
	for host, want := range map[string]string{
		"m.ctrip.com":             "ctrip",
		"kyfw.12306.cn":           "rail_12306",
		"meeting.tencent.com":     "tencent_meeting",
		"api.meeting.tencent.com": "tencent_meeting",
		"cloud.tencent.com":       "tencent_group",
		"mail.163.com":            "netease_mail",
		"music.163.com":           "netease_music",
		"www.163.com":             "netease_group",
		"imgs.xmcdn.com":          "ximalaya",
	} {
		r, ok := classifyHostIndexed(idx, rules, host)
		if !ok || r.ID != want {
			t.Errorf("%s → %q ok=%v, want %q", host, r.ID, ok, want)
		}
	}
}

// equivalenceInputs 用规则里全部后缀派生测试主机名: 原样、加子域、多级子域、
// 去掉首字符(制造"非标签边界"的假后缀)、首标签截断、大写、带尾点等。
func equivalenceInputs(rules []l3Rule, rng *rand.Rand) []string {
	var out []string
	for _, r := range rules {
		for _, s := range r.Suffixes {
			out = append(out,
				s,
				"www."+s,
				"a.b.c."+s,
				"x"+s,
				strings.ToUpper("cdn."+s),
				s+".",
				" "+s+" ",
			)
			if len(s) > 1 {
				out = append(out, s[1:])
			}
			if i := strings.IndexByte(s, '.'); i >= 0 {
				out = append(out, s[i+1:], "zz"+s[i:])
			}
		}
	}
	out = append(out, "", ".", "..", "com", "a..b.com", "localhost", "1.2.3.4", "中文.com", "unknown-host.example")
	// 随机拼接两个后缀的片段。
	for i := 0; i < 2000 && len(out) > 1; i++ {
		a, b := out[rng.Intn(len(out))], out[rng.Intn(len(out))]
		out = append(out, a+"."+b)
	}
	return out
}

func assertEquivalent(t *testing.T, name string, rules []l3Rule) {
	t.Helper()
	idx := buildHostIndex(rules)
	inputs := equivalenceInputs(rules, rand.New(rand.NewSource(7)))
	mismatch := 0
	for _, h := range inputs {
		want, wok := classifyHostLinear(rules, h)
		got, gok := classifyHostIndexed(idx, rules, h)
		if wok != gok || want.ID != got.ID || want.Name != got.Name || want.Category != got.Category {
			mismatch++
			if mismatch <= 10 {
				t.Errorf("%s: host=%q linear=(%q,%v) index=(%q,%v)", name, h, want.ID, wok, got.ID, gok)
			}
		}
	}
	if mismatch > 0 {
		t.Fatalf("%s: %d/%d 不一致", name, mismatch, len(inputs))
	}
	t.Logf("%s: %d 条规则, %d 个输入逐条一致", name, len(rules), len(inputs))
}

func TestClassifyHostIndexEquivalence(t *testing.T) {
	dirRules, _ := loadRuleDirForTest(t)
	assertEquivalent(t, "dpi_rules.d", dirRules)
	assertEquivalent(t, "dpi_rules.json", loadLegacyRulesForTest(t))
	assertEquivalent(t, "builtin", builtinRules)

	// 人造边界: 同后缀多规则(先到先得)、Fallback 更长 vs Specific 更短、
	// 带前导点/大写/空白的原始后缀。
	synthetic := []l3Rule{
		{ID: "fb_long", Priority: PriorityFallback, Suffixes: []string{"a.example.com"}},
		{ID: "sp_short", Priority: PrioritySpecific, Suffixes: []string{"example.com"}},
		{ID: "dup1", Priority: PrioritySpecific, Suffixes: []string{"dup.net"}},
		{ID: "dup2", Priority: PrioritySpecific, Suffixes: []string{"dup.net", "x.dup.net"}},
		{ID: "raw", Priority: PrioritySpecific, Suffixes: []string{" .Raw.ORG ", ""}},
		{ID: "fb_only", Priority: PriorityFallback, Suffixes: []string{"fb.io"}},
		{ID: "weird_pri", Priority: PriorityClass(7), Suffixes: []string{"weird.io"}},
	}
	assertEquivalent(t, "synthetic", synthetic)
	idx := buildHostIndex(synthetic)
	for host, want := range map[string]string{
		"z.a.example.com": "sp_short", // Specific 桶优先, 即使 Fallback 后缀更长
		"q.dup.net":       "dup1",     // 同后缀先到先得
		"q.x.dup.net":     "dup2",     // 更长后缀胜出
		"www.raw.org":     "raw",
		"a.fb.io":         "fb_only",
		"weird.io":        "",
	} {
		r, _ := classifyHostIndexed(idx, synthetic, host)
		if r.ID != want {
			t.Errorf("%s → %q want %q", host, r.ID, want)
		}
	}
}

// 规则切片换了(重载)索引必须重建; 同一切片复用缓存。
func TestHostIndexRebuildOnReload(t *testing.T) {
	a := []l3Rule{{ID: "a", Suffixes: []string{"a.com"}}}
	b := []l3Rule{{ID: "b", Suffixes: []string{"b.com"}}}
	ia := hostIndexFor(a)
	if hostIndexFor(a) != ia {
		t.Fatal("same rules should reuse index")
	}
	ib := hostIndexFor(b)
	if ib == ia {
		t.Fatal("new rules should rebuild index")
	}
	if _, ok := ib.lookup("x.a.com"); ok {
		t.Fatal("stale index")
	}
	if i, ok := ib.lookup("x.b.com"); !ok || b[i].ID != "b" {
		t.Fatal("rebuilt index miss")
	}
}

func benchHosts(rules []l3Rule) []string {
	rng := rand.New(rand.NewSource(1))
	var hosts []string
	for _, r := range rules {
		for _, s := range r.Suffixes {
			hosts = append(hosts, "api."+s)
		}
	}
	for i := 0; i < len(hosts)/3; i++ {
		hosts = append(hosts, "miss"+string(rune('a'+rng.Intn(26)))+".unknown-cdn.example.net")
	}
	return hosts
}

func BenchmarkClassifyHostLinear(b *testing.B) {
	rules, _ := loadRuleDirForTest(b)
	hosts := benchHosts(rules)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		classifyHostLinear(rules, hosts[i%len(hosts)])
	}
}

func BenchmarkClassifyHostIndexed(b *testing.B) {
	rules, _ := loadRuleDirForTest(b)
	hosts := benchHosts(rules)
	idx := hostIndexFor(rules)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		classifyHostIndexed(idx, rules, hosts[i%len(hosts)])
	}
}
