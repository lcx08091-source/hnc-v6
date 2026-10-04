package main

// v5.27 T6「我的规则包」: 导出来源汇总与过滤、隐私断言、导入校验的每条拒绝路径、冲突跳过、
// imp_ 前缀与 _parent_rule_id、重复导入幂等、清除、导出 → 导入往返。

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	rpMAC     = "aa:bb:cc:00:77:01"
	rpIP      = "203.0.113.77"
	rpUID     = "10123"
	rpPkg     = "com.ss.android.ugc.aweme"
	rpJA4Good = "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"
	rpJA4Gen  = "t13d1517h2_cccccccccccc_dddddddddddd"
	rpJA4Low  = "t13d1518h2_eeeeeeeeeeee_ffffffffffff"
	rpJA4User = "t13d1519h2_111111111111_222222222222"
)

func rpWrite(t *testing.T, path, body string) {
	t.Helper()
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// rpFactory 两台手机共用的出厂规则 + blocklist
func rpFactory(t *testing.T, dir string) {
	t.Helper()
	for _, d := range []string{"data", "run", "etc/dpi_rules.d", "exports"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	rpWrite(t, filepath.Join(dir, "etc", "dpi_rules.d", "10-factory.json"), `{"rules":[
	 {"id":"douyin","app":"抖音","category":"video","suffixes":["douyin.com","amemv.com"]},
	 {"id":"wechat","app":"微信","category":"social","suffixes":["weixin.qq.com"]},
	 {"id":"tencent_group","app":"腾讯系","category":"system","suffixes":["qq.com"]},
	 {"id":"game_x","app":"游戏X","category":"game","suffixes":["a.b.gamex.example"]},
	 {"id":"ads_x","app":"广告","category":"ads","suffixes":["adx.example"]}]}`)
	rpWrite(t, filepath.Join(dir, "etc", "auto_expand_blocklist.json"), `{"blocked_apex":["sharedcdn.example"]}`)
}

// rpPhoneA 一台「学了东西」的手机
func rpPhoneA(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	rpFactory(t, dir)
	rd := filepath.Join(dir, "etc", "dpi_rules.d")
	rpWrite(t, filepath.Join(rd, "_auto_expanded.json"), `{"schema_version":"2.0","rules":[
	 {"id":"douyin_autoexp_v3","name":"抖音 (自动扩展: v3)","app":"抖音 (自动扩展: v3)","category":"video","suffixes":["v3.douyinvod.com"],
	  "_source":"auto_expanded","_apex":"douyinvod.com","_parent_rule_id":"douyin","_added_at":1790000123,
	  "_evidence":{"uid":`+rpUID+`,"uid_pkg":"`+rpPkg+`","parent_hits_at_time_of_expand":42,"observed_hostname":"v3.douyinvod.com"}}]}`)
	rpWrite(t, filepath.Join(rd, "_auto_promoted.json"), `{"rules":[
	 {"id":"promo_newapp","app":"新应用","category":"game","suffixes":["newapp.example"],"_source":"auto_promoted",
	  "_added_at":1790000456,"_evidence":{"uid":`+rpUID+`,"uid_pkg":"`+rpPkg+`"}}]}`)
	// 99: 与出厂同 id 的 douyin 只导出出厂没有的后缀; myapp 全部导出(裸数组格式)
	rpWrite(t, filepath.Join(rd, "99-user-custom.json"), `[
	 {"id":"douyin","app":"抖音","category":"video","suffixes":["douyin.com","extra-dy.example"]},
	 {"id":"myapp","app":"我的应用","category":"social","suffixes":["myapp.example"]}]`)
	rpWrite(t, filepath.Join(rd, "_imported.json"), `{"rules":[{"id":"imp_frompeer","app":"别人给的","category":"video","suffixes":["peer.example"],"_source":"rulepack:x@2026-10-01"}]}`)
	now := time.Now().Unix()
	rpWrite(t, filepath.Join(dir, "data", "dpi_user_rules.json"), `{"schema":1,"rules":[
	 {"id":"c1","kind":"domain","value":"corrected.example","app_id":"myapp","app_name":"我的应用","category":"social","mac":"`+rpMAC+`","created":`+strconv.FormatInt(now, 10)+`},
	 {"id":"c2","kind":"ip","value":"`+rpIP+`","port":443,"app_id":"myapp","app_name":"我的应用","category":"social","mac":"`+rpMAC+`","created":`+strconv.FormatInt(now, 10)+`,"expires":`+strconv.FormatInt(now+86400, 10)+`},
	 {"id":"c3","kind":"ja4","value":"`+rpJA4User+`","app_id":"myapp","app_name":"我的应用","category":"social","mac":"`+rpMAC+`","created":`+strconv.FormatInt(now, 10)+`}]}`)
	dev := fpDevKey(rpMAC)
	learned := map[string]interface{}{"schema": 1, "saved_at": now, "entries": []map[string]interface{}{
		{"ja4": rpJA4Good, "alpn": "h2", "port": "443", "qtp": "qtp1_0123456789ab", "apps": map[string]interface{}{"douyin": map[string]interface{}{"n": 120, "name": "抖音", "category": "video"}},
			"total": 120, "devs": map[string]int64{dev: now}, "first": now, "last": now, "upd": now},
		{"ja4": rpJA4Gen, "alpn": "h2", "port": "443", "apps": map[string]interface{}{"douyin": map[string]interface{}{"n": 60, "category": "video"}, "_other": map[string]interface{}{"n": 60}},
			"total": 120, "devs": map[string]int64{dev: now}, "first": now, "last": now, "upd": now},
		{"ja4": rpJA4Low, "alpn": "h2", "port": "443", "apps": map[string]interface{}{"douyin": map[string]interface{}{"n": 30, "category": "video"}},
			"total": 30, "devs": map[string]int64{dev: now, "x": now}, "first": now, "last": now, "upd": now},
	}}
	b, _ := json.Marshal(learned)
	rpWrite(t, filepath.Join(dir, "data", "fp_learned.json"), string(b))
	st := startupFor(dir)
	st.mu.Lock()
	st.loaded = true
	st.table = newStartupTable()
	for i := 0; i < 4; i++ {
		st.table.addStart("douyin", "抖音", []string{"api#.amemv.com", "p#.douyinpic.com", "log.snssdk.com"}, now, false)
		st.table.addStart("myapp", "我的应用", []string{"a.myapp.example", "b.myapp.example"}, now, false)
	}
	st.mu.Unlock()
	return dir
}

func TestRulepackExportSourcesAndFilters(t *testing.T) {
	dir := rpPhoneA(t)
	p := buildRulepack(dir, "  家里的手机\x07 ", false, "v5.27.0-rc1", time.Now())
	if p.Format != "hnc-rulepack" || p.Schema != 1 || p.Note != "家里的手机" || !rulepackDateRE.MatchString(p.Created) {
		t.Fatalf("header: %+v", p)
	}
	byKey := map[string]rulepackDomain{}
	for _, d := range p.DomainRules {
		byKey[d.Source+"/"+d.ID] = d
	}
	ae := byKey["auto_expanded/douyin_autoexp_v3"]
	if ae.AttachTo != "douyin" || ae.App != "抖音" || len(ae.Suffixes) != 1 || ae.Suffixes[0] != "v3.douyinvod.com" {
		t.Fatalf("auto_expanded: %+v", ae)
	}
	if d := byKey["auto_promoted/promo_newapp"]; d.AttachTo != "" || d.Category != "game" {
		t.Fatalf("auto_promoted: %+v", d)
	}
	if d := byKey["user_custom/douyin"]; d.AttachTo != "douyin" || strings.Join(d.Suffixes, ",") != "extra-dy.example" {
		t.Fatalf("99 同 id 只导出出厂没有的后缀: %+v", d)
	}
	if d := byKey["user_custom/myapp"]; strings.Join(d.Suffixes, ",") != "myapp.example" {
		t.Fatalf("99 myapp: %+v", d)
	}
	if d := byKey["user_correction/myapp"]; strings.Join(d.Suffixes, ",") != "corrected.example" || d.AttachTo != "myapp" {
		t.Fatalf("user correction domain: %+v", d)
	}
	if _, ok := byKey["imported/frompeer"]; ok {
		t.Fatal("已导入的默认不导出")
	}
	// 指纹: 学到的只留 可用+非通用+置信度≥0.8+支持度≥50; 用户 ja4 纠正导出; ip 纠正不导出
	var fps []string
	for _, f := range p.Fingerprints {
		fps = append(fps, f.Source+":"+f.JA4)
	}
	if len(p.Fingerprints) != 2 || !strings.Contains(strings.Join(fps, ","), "learned:"+rpJA4Good) || !strings.Contains(strings.Join(fps, ","), "user_correction:"+rpJA4User) {
		t.Fatalf("fingerprints: %v", fps)
	}
	for _, f := range p.Fingerprints {
		if f.Source == "learned" && (f.QTP != "qtp1_0123456789ab" || f.Support != 120 || f.Purity != 1) {
			t.Fatalf("learned fp: %+v", f)
		}
	}
	// 启动指纹: 可用的应用, 只导出特征 token
	if len(p.Startup) != 2 {
		t.Fatalf("startup: %+v", p.Startup)
	}
	for _, s := range p.Startup {
		if s.AppID == "douyin" && (s.Category != "video" || len(s.Tokens) != 3 || s.Starts != 4) {
			t.Fatalf("startup douyin: %+v", s)
		}
	}
	if p.Counts.DomainRules != len(p.DomainRules) || p.Counts.Fingerprints != 2 || p.Counts.Startup != 2 || p.Counts.Suffixes != 5 {
		t.Fatalf("counts: %+v", p.Counts)
	}
	// 包含已导入
	p2 := buildRulepack(dir, "", true, "", time.Now())
	found := false
	for _, d := range p2.DomainRules {
		if d.Source == "imported" && d.ID == "frompeer" {
			found = true
		}
	}
	if !found {
		t.Fatal("include_imported 应带上已导入的")
	}
	// 摘要
	sum := rulepackSummary(dir, time.Now())
	ex := sum["exportable"].(rulepackCounts)
	im := sum["imported"].(rulepackCounts)
	if ex.DomainRules != p.Counts.DomainRules || ex.Fingerprints != 2 || im.DomainRules != 1 || im.Suffixes != 1 {
		t.Fatalf("summary: %+v", sum)
	}
}

// 隐私: 序列化结果里搜不到夹具中的 MAC / IP / UID / 包名 / 设备散列 / _evidence / 秒级时间
func TestRulepackPrivacy(t *testing.T) {
	dir := rpPhoneA(t)
	for _, inc := range []bool{false, true} {
		b, _ := json.Marshal(buildRulepack(dir, "", inc, "", time.Now()))
		s := string(b)
		for _, bad := range []string{rpMAC, strings.ToUpper(rpMAC), rpIP, rpUID, rpPkg, fpDevKey(rpMAC), "_evidence", "uid_pkg",
			"observed_hostname", "devs", "1790000123", "1790000456", "mac", "\"uid\"", "_added_at"} {
			if strings.Contains(s, bad) {
				t.Errorf("rulepack(include_imported=%v) contains %q", inc, bad)
			}
		}
	}
}

func rpPackJSON(t *testing.T, p rulepack) []byte {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rpBase() rulepack {
	return rulepack{Format: "hnc-rulepack", Schema: 1, Created: "2026-10-04", Note: "测试"}
}

func TestRulepackImportRejectsWholePack(t *testing.T) {
	dir := t.TempDir()
	rpFactory(t, dir)
	now := time.Now()
	bad := func(name string, body []byte) {
		t.Helper()
		if _, err := importRulepack(dir, body, now); err == nil {
			t.Errorf("%s: should reject", name)
		}
	}
	bad("not json", []byte("{"))
	p := rpBase()
	p.Format = "other"
	bad("format", rpPackJSON(t, p))
	p = rpBase()
	p.Schema = 2
	bad("schema", rpPackJSON(t, p))
	p = rpBase()
	var many []string
	for i := 0; i < 5001; i++ {
		many = append(many, "h"+strconv.Itoa(i)+".many.example")
	}
	p.DomainRules = []rulepackDomain{{ID: "x", App: "X", Category: "video", Suffixes: many}}
	bad("too many suffixes", rpPackJSON(t, p))
	p = rpBase()
	for i := 0; i < 2001; i++ {
		p.Fingerprints = append(p.Fingerprints, rulepackFP{JA4: rpJA4Good, Port: "443", AppID: "x", Category: "video"})
	}
	bad("too many fps", rpPackJSON(t, p))
	p = rpBase()
	for i := 0; i < 501; i++ {
		p.Startup = append(p.Startup, startupPackEntry{AppID: "x" + strconv.Itoa(i)})
	}
	bad("too many startup", rpPackJSON(t, p))
	for _, f := range []string{"_imported.json"} {
		if _, err := os.Stat(filepath.Join(dir, "etc", "dpi_rules.d", f)); err == nil {
			t.Fatal("rejected pack must not write anything")
		}
	}
	// 未知顶层字段忽略
	if _, err := importRulepack(dir, []byte(`{"format":"hnc-rulepack","schema":1,"whatever":{"x":1}}`), now); err != nil {
		t.Fatalf("unknown top-level field: %v", err)
	}
}

func TestRulepackImportValidationAndConflicts(t *testing.T) {
	dir := t.TempDir()
	rpFactory(t, dir)
	p := rpBase()
	p.DomainRules = []rulepackDomain{
		{ID: "Bad-ID", App: "x", Category: "video", Suffixes: []string{"ok1.example"}},
		{ID: "badcat", App: "x", Category: "nope", Suffixes: []string{"ok2.example"}},
		{ID: "badattach", App: "x", Category: "video", AttachTo: "Bad!", Suffixes: []string{"ok3.example"}},
		{ID: "evil", App: "限时的应用", Category: "game", Suffixes: []string{
			"weixin.qq.com",     // 微信: 归别的应用 → 冲突
			"pay.weixin.qq.com", // 最长后缀匹配也是微信 → 冲突
			"b.gamex.example",   // 会盖住 game_x 的 a.b.gamex.example → 冲突
			"com.cn",            // 公共后缀
			"github.io",         // 多租户托管后缀
			"sharedcdn.example", // blocklist apex 本身
			"x.sharedcdn.example",
			"bad_host!.example",
			"single", // 不到 2 段 → bad_suffix
			"evil.example",
			"EVIL.example.", // 规范化后重复
		}},
		{ID: "douyin_more", App: "抖音", Category: "video", AttachTo: "douyin", Suffixes: []string{"amemv.com", "dy-new.example"}},
	}
	p.Fingerprints = []rulepackFP{
		{JA4: "zzz", Port: "443", AppID: "a", Category: "video"},
		{JA4: rpJA4Good, Port: "443", QTP: "qtp1_XYZ", AppID: "a", Category: "video"},
		{JA4: rpJA4Good, Port: "8443", AppID: "a", Category: "video"},
		{JA4: rpJA4Good, Port: "443", AppID: "A B", Category: "video"},
		{JA4: rpJA4Good, Port: "443", AppID: "a", Category: "ads"}, // 隐藏类不收
		{JA4: rpJA4Good, Port: "443", AppID: "a", Category: "video", Purity: 2},
		{JA4: rpJA4Good, ALPN: "h2", Port: "443", QTP: "qtp1_0123456789ab", AppID: "douyin", App: "抖音", Category: "video", Purity: 0.97, Support: 120},
	}
	p.Startup = []startupPackEntry{
		{AppID: "Bad", Tokens: []startupPackTok{{T: "a.b.com", F: 1}, {T: "c.d.com", F: 1}}},
		{AppID: "few", Tokens: []startupPackTok{{T: "a.b.com", F: 1}}},
		{AppID: "badtok", Tokens: []startupPackTok{{T: "UPPER CASE", F: 1}, {T: "x.y.com", F: 3}}},
		{AppID: "douyin", App: "抖音", Category: "video", Starts: 12, Tokens: []startupPackTok{{T: "api#.amemv.com", F: 0.92}, {T: "p#.douyinpic.com", F: 0.8}}},
	}
	rep, err := importRulepack(dir, rpPackJSON(t, p), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sk := rep.Skipped
	for reason, want := range map[string]int{
		"bad_id": 3, "bad_category": 2, "bad_attach": 1, "conflict": 3, "public_suffix": 2, "shared_apex": 1,
		"bad_suffix": 2, "already_local": 1, "bad_ja4": 1, "bad_qtp": 1, "bad_port": 1, "bad_value": 1,
		"too_few_tokens": 2, "bad_token": 2,
	} {
		if sk[reason] != want {
			t.Errorf("skipped[%s] = %d, want %d (all: %v)", reason, sk[reason], want, sk)
		}
	}
	if rep.Added.DomainRules != 2 || rep.Added.Suffixes != 3 || rep.Added.Fingerprints != 1 || rep.Added.Startup != 1 {
		t.Fatalf("added: %+v", rep.Added)
	}
	if len(rep.Conflicts) != 3 || !strings.Contains(strings.Join(rep.Conflicts, "|"), "wechat") {
		t.Fatalf("conflicts: %v", rep.Conflicts)
	}
	// 落地: imp_ 前缀、_parent_rule_id、_source
	rules, _ := rpReadRuleFile(filepath.Join(dir, "etc", "dpi_rules.d", "_imported.json"))
	got := map[string]rpRawRule{}
	for _, r := range rules {
		got[r.ID] = r
	}
	if r := got["imp_evil"]; strings.Join(r.Suffixes, ",") != "evil.example,x.sharedcdn.example" || r.Parent != "" {
		t.Fatalf("imp_evil: %+v", r)
	}
	if r := got["imp_douyin_more"]; strings.Join(r.Suffixes, ",") != "dy-new.example" || r.Parent != "douyin" {
		t.Fatalf("imp_douyin_more: %+v", r)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "etc", "dpi_rules.d", "_imported.json"))
	if !strings.Contains(string(b), `"_source": "rulepack:测试@2026-10-04"`) {
		t.Fatalf("_source: %s", b)
	}
	// 挂靠: 应用目录里 dy-new.example 归抖音
	c := loadAppCatalog(dir)
	if _, ok := c.apps["imp_douyin_more"]; ok {
		t.Fatal("attached import must not be a separate app")
	}
	if !strings.Contains(strings.Join(c.apps["douyin"].Suffixes, ","), "dy-new.example") {
		t.Fatalf("douyin suffixes: %v", c.apps["douyin"].Suffixes)
	}
}

func TestRulepackIdempotentAndClear(t *testing.T) {
	dir := t.TempDir()
	rpFactory(t, dir)
	p := rpBase()
	p.DomainRules = []rulepackDomain{{ID: "newapp", App: "新应用", Category: "game", Suffixes: []string{"n1.example", "n2.example"}}}
	p.Fingerprints = []rulepackFP{{JA4: rpJA4Good, ALPN: "h2", Port: "443", AppID: "newapp", App: "新应用", Category: "game", Purity: 1, Support: 60}}
	p.Startup = []startupPackEntry{{AppID: "newapp", App: "新应用", Category: "game", Starts: 5, Tokens: []startupPackTok{{T: "a.n1.example", F: 1}, {T: "b.n2.example", F: 0.9}}}}
	body := rpPackJSON(t, p)
	if _, err := importRulepack(dir, body, time.Now()); err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(dir, "etc", "dpi_rules.d", "_imported.json"), fpImportedPath(dir), startupImportedPath(dir)}
	var before [][]byte
	for _, pth := range paths {
		b, err := os.ReadFile(pth)
		if err != nil {
			t.Fatal(err)
		}
		before = append(before, b)
	}
	rep, err := importRulepack(dir, body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Added != (rulepackCounts{}) || rep.Merged != (rulepackCounts{}) || rep.Unchanged.DomainRules != 1 || rep.Unchanged.Suffixes != 2 ||
		rep.Unchanged.Fingerprints != 1 || rep.Unchanged.Startup != 1 {
		t.Fatalf("re-import: %+v", rep)
	}
	for i, pth := range paths {
		b, _ := os.ReadFile(pth)
		if !bytes.Equal(b, before[i]) {
			t.Fatalf("%s changed on re-import", pth)
		}
	}
	// 同 id 追加后缀 → 合并
	p.DomainRules[0].Suffixes = append(p.DomainRules[0].Suffixes, "n3.example")
	rep, _ = importRulepack(dir, rpPackJSON(t, p), time.Now())
	if rep.Merged.DomainRules != 1 || rep.Merged.Suffixes != 1 {
		t.Fatalf("merge: %+v", rep)
	}
	r := actionDPIRulepackClear(dir)
	if !r.OK || r.Detail != "removed 3 file(s)" {
		t.Fatalf("clear: %+v", r)
	}
	for _, pth := range paths {
		if _, err := os.Stat(pth); err == nil {
			t.Fatalf("%s not removed", pth)
		}
	}
	if r := actionDPIRulepackClear(dir); !r.OK {
		t.Fatalf("clear twice: %+v", r)
	}
}

// 导出(手机 A)→ 导入(另一个目录 B)后: 域名分类结果一致(按应用名 + 类别比较; 挂靠的 id 也一致),
// 指纹能给无域名连接归属, 启动指纹进了识别模型。
func TestRulepackRoundTrip(t *testing.T) {
	a := rpPhoneA(t)
	pack := buildRulepack(a, "往返", false, "", time.Now())
	b := t.TempDir()
	rpFactory(t, b)
	rep, err := importRulepack(b, rpPackJSON(t, pack), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// myapp 同时来自 99-user-custom 与用户纠正 → 同一个 imp_myapp, 第二条合并进去
	if len(rep.Skipped) != 0 || rep.Added.Suffixes+rep.Merged.Suffixes != pack.Counts.Suffixes {
		t.Fatalf("round trip report: %+v (pack %+v)", rep, pack.Counts)
	}
	ca, cb := loadAppCatalog(a), loadAppCatalog(b)
	ownerOf := func(c *appCatalog, host string) (string, string) {
		for _, app := range c.apps {
			for _, s := range app.Suffixes {
				if s == host {
					return app.Name, app.Category
				}
			}
		}
		return "", ""
	}
	for _, d := range pack.DomainRules {
		for _, s := range d.Suffixes {
			an, ac := ownerOf(ca, s)
			if d.Source == "user_correction" {
				// A 上用户纠正不在规则文件里(data/dpi_user_rules.json, 优先级最高), 归属就是纠正的应用
				an, ac = d.App, d.Category
			}
			bn, bc := ownerOf(cb, s)
			if an == "" || an != bn || ac != bc {
				t.Errorf("%s: A=(%s,%s) B=(%s,%s)", s, an, ac, bn, bc)
			}
		}
	}
	if _, ok := cb.apps["douyin"]; !ok || !strings.Contains(strings.Join(cb.apps["douyin"].Suffixes, ","), "v3.douyinvod.com") {
		t.Fatal("auto_expanded 子域名在 B 上应并进 douyin")
	}
	// 指纹: B 上一条无域名、带同一指纹的连接 → imported 归属
	now := time.Now()
	stB := fpFor(b)
	f := &fptFlows{boot: 1}
	f.seq++
	f.recs = append(f.recs, fpFlowRec{Seq: f.seq, Ts: now.Unix(), MAC: fptMAC1, CIP: "192.168.43.10", Sport: 40000, DIP: "203.0.113.50",
		Dport: 443, Proto: "udp", JA4: rpJA4Good, ALPN: "h2", QTP: "qtp1_0123456789ab"})
	f.write(t, b)
	stB.tick(now, nil)
	fa, ok := stB.attribute("udp|192.168.43.10|40000|203.0.113.50|443", nil, nil, now)
	if !ok || fa.Src != "imported" || fa.App.ID != "douyin" {
		t.Fatalf("imported fp attribution: %+v %v", fa, ok)
	}
	// 启动指纹进了 B 的识别模型(本机还没学到)
	sb := startupFor(b)
	sb.mu.Lock()
	sb.loaded = true
	m := sb.modelLocked(now.Unix())
	sb.mu.Unlock()
	ids := map[string]bool{}
	for _, x := range m.apps {
		ids[x.id] = true
	}
	if !ids["douyin"] || !ids["myapp"] {
		t.Fatalf("imported startup not in model: %v", ids)
	}
}

func TestRulepackAPIAndExportAction(t *testing.T) {
	dir := rpPhoneA(t)
	s := newServer(dir)
	r := dispatchAction(s, "dpi_rulepack_export", map[string]string{"note": "备份", "include_imported": "1"}, true)
	if !r.OK {
		t.Fatalf("export: %+v", r)
	}
	var d struct {
		Name   string         `json:"name"`
		Counts rulepackCounts `json:"counts"`
	}
	_ = json.Unmarshal([]byte(r.Detail), &d)
	if !isRulepackExport(d.Name) || !isExportArchive(d.Name) || d.Counts.DomainRules == 0 {
		t.Fatalf("export detail: %s", r.Detail)
	}
	// /api/exports/<name> 可下载
	rec := httptest.NewRecorder()
	s.apiExportFile(rec, httptest.NewRequest("GET", "/api/exports/"+d.Name, nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"hnc-rulepack"`) {
		t.Fatalf("download: %d %s", rec.Code, rec.Body.String())
	}
	// GET 摘要
	rec = httptest.NewRecorder()
	s.apiDPIRulepack(rec, httptest.NewRequest("GET", "/api/dpi_rulepack?summary=1", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"exportable"`) {
		t.Fatalf("summary: %d %s", rec.Code, rec.Body.String())
	}
	// POST 导入(pack 为 JSON 文本)
	b := t.TempDir()
	rpFactory(t, b)
	sb := newServer(b)
	pk, _ := os.ReadFile(filepath.Join(dir, "exports", d.Name))
	body, _ := json.Marshal(map[string]string{"pack": string(pk)})
	req := httptest.NewRequest("POST", "/api/dpi_rulepack", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HNC-CSRF", "1")
	rec = httptest.NewRecorder()
	sb.apiDPIRulepack(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"added"`) {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	// 没有 CSRF 头 → 拒绝
	req = httptest.NewRequest("POST", "/api/dpi_rulepack", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	sb.apiDPIRulepack(rec, req)
	if rec.Code == 200 {
		t.Fatal("missing csrf must be rejected")
	}
	// 坏包 → 400 + 原因
	body, _ = json.Marshal(map[string]string{"pack": `{"format":"x","schema":1}`})
	req = httptest.NewRequest("POST", "/api/dpi_rulepack", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HNC-CSRF", "1")
	rec = httptest.NewRecorder()
	sb.apiDPIRulepack(rec, req)
	if rec.Code != 400 {
		t.Fatalf("bad pack: %d", rec.Code)
	}
	if r := dispatchAction(sb, "dpi_rulepack_clear", nil, true); !r.OK {
		t.Fatalf("clear: %+v", r)
	}
}

// 接近 1.2 MB、含大量需要转义字符的规则包, 以 JSON 字符串形式 POST 也能通过请求体上限
func TestRulepackPostEscapedNearLimit(t *testing.T) {
	dir := t.TempDir()
	rpFactory(t, dir)
	p := rpBase()
	// 应用名全是引号: 规则包里每个 " 转成 \", 再作为 JSON 字符串 POST 时又各翻一倍
	name := strings.Repeat(`"`, 60)
	for i := 0; i < 4000; i++ {
		p.DomainRules = append(p.DomainRules, rulepackDomain{ID: "app" + strconv.Itoa(i), App: name,
			Category: "video", Suffixes: []string{"h" + strconv.Itoa(i) + ".escaped.example"}})
	}
	pk := rpPackJSON(t, p)
	if len(pk) > rulepackMaxBody {
		t.Fatalf("fixture too big: %d", len(pk))
	}
	body, _ := json.Marshal(map[string]string{"pack": string(pk)})
	if len(body) <= rulepackMaxBody+64*1024 {
		t.Fatalf("fixture should exceed the old limit: %d", len(body))
	}
	req := httptest.NewRequest("POST", "/api/dpi_rulepack", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HNC-CSRF", "1")
	rec := httptest.NewRecorder()
	newServer(dir).apiDPIRulepack(rec, req)
	if rec.Code != 200 {
		t.Fatalf("near-limit escaped pack: %d %.200s", rec.Code, rec.Body.String())
	}
}
