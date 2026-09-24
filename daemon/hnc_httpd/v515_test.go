package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistrableAndCompany(t *testing.T) {
	for in, want := range map[string]string{"img.xhscdn.com": "xhscdn.com", "a.b.sina.com.cn": "sina.com.cn", "x.com": "x.com", "*.kuaishou.com": "kuaishou.com"} {
		if got := registrable(in); got != want {
			t.Errorf("registrable(%q)=%q want %q", in, got, want)
		}
	}
	if c := companyFromOrg("Beijing Kuaishou Technology Co., Ltd."); c != "快手" {
		t.Fatalf("company = %q", c)
	}
	if c := companyFromOrg("Some Random Org"); c != "" {
		t.Fatalf("unknown org should map to empty, got %q", c)
	}
}

func TestDiscoverFlow(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "run"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	w := func(p, s string) {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("run/dpi_discover.json", `{"schema":1,"groups":[
	 {"id":"g_a","suffixes":["kwaicdn.com","gifshow.com"],"domains":[{"name":"p1.kwaicdn.com","count":40}],"devices":["aa:bb:cc:00:00:01"],"hits":40},
	 {"id":"g_b","suffixes":["weirdapp.io"],"domains":[{"name":"api.weirdapp.io","count":9}],"hits":9,"family_name":"字节跳动"},
	 {"id":"g_c","suffixes":["mystery.net"],"domains":[{"name":"x.mystery.net","count":6}],"hits":6}]}`)
	w("run/apk_domains.json", `{"schema":1,"generated_at":100,"apps":{"com.kuaishou.nebula":{"label":"快手极速版"},"com.x":{"label":"X"}},
	 "suffix_index":{"kwaicdn.com":["com.kuaishou.nebula"],"gifshow.com":["com.kuaishou.nebula"],"umeng.com":["com.x"]},"sdk_suffixes":["umeng.com"]}`)
	certState.mu.Lock()
	certState.loaded, certState.m = false, nil
	certState.mu.Unlock()
	certProbeFunc = func(host string, ips []string) certInfo {
		if host == "x.mystery.net" {
			return certInfo{Host: host, Org: "Beijing Kuaishou Technology Co., Ltd.", SANs: []string{"*.mystery.net"}, Ts: 1}
		}
		return certInfo{Host: host, Err: "连接超时", Ts: 1}
	}
	defer func() { certProbeFunc = probeCert }()
	s := newServer(dir)
	if r := actionDiscoverProbe(s, map[string]string{"id": "g_c"}); !r.OK {
		t.Fatalf("probe: %+v", r)
	}
	get := func() map[string]map[string]interface{} {
		rr := httptest.NewRecorder()
		s.apiDiscover(rr, httptest.NewRequest("GET", "/api/discover", nil))
		var out struct {
			Groups []map[string]interface{} `json:"groups"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		m := map[string]map[string]interface{}{}
		for _, g := range out.Groups {
			m[asString(g["id"])] = g
		}
		return m
	}
	gs := get()
	guess := func(id string) map[string]interface{} { g, _ := gs[id]["guess"].(map[string]interface{}); return g }
	if g := guess("g_a"); g["src"] != "apk" || g["name"] != "快手极速版" {
		t.Fatalf("g_a guess = %v", g)
	}
	if g := guess("g_b"); g["src"] != "ja4" || g["name"] != "疑似字节跳动应用" {
		t.Fatalf("g_b guess = %v", g)
	}
	if g := guess("g_c"); g["src"] != "cert" || g["company"] != "快手" {
		t.Fatalf("g_c guess = %v", g)
	}

	// 确认: 写入用户规则, 组从列表消失
	r := actionDiscoverConfirm(s, map[string]string{"id": "g_a", "name": "快手极速版", "category": "video", "suffixes": "kwaicdn.com, gifshow.com"})
	if !r.OK {
		t.Fatalf("confirm: %+v", r)
	}
	b, err := os.ReadFile(userRulesPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []map[string]interface{} `json:"rules"`
	}
	if json.Unmarshal(b, &doc) != nil || len(doc.Rules) != 1 || doc.Rules[0]["app"] != "快手极速版" || doc.Rules[0]["category"] != "video" {
		t.Fatalf("user rules = %s", b)
	}
	// 再确认同一主后缀 → 合并, 不重复加规则
	_ = addIDList(filepath.Join(dir, "run", "discover_confirmed.json"), "none")
	if r := actionDiscoverConfirm(s, map[string]string{"id": "g_x", "name": "快手", "category": "video", "suffixes": "kwaicdn.com,kuaishou.com"}); !r.OK {
		t.Fatal(r)
	}
	b, _ = os.ReadFile(userRulesPath(dir))
	_ = json.Unmarshal(b, &doc)
	if len(doc.Rules) != 1 || len(strList(doc.Rules[0]["suffixes"])) != 3 {
		t.Fatalf("merge failed: %s", b)
	}
	// 非法输入
	if r := actionDiscoverConfirm(s, map[string]string{"id": "g_b", "name": "x", "category": "evil", "suffixes": "a.com"}); r.OK {
		t.Fatal("bad category accepted")
	}
	if r := actionDiscoverConfirm(s, map[string]string{"id": "g_b", "name": "x", "category": "video", "suffixes": "../../etc"}); r.OK {
		t.Fatal("bad suffix accepted")
	}
	// 忽略
	if r := actionDiscoverIgnore(s, map[string]string{"id": "g_b"}); !r.OK {
		t.Fatal(r)
	}
	gs = get()
	if _, ok := gs["g_a"]; ok {
		t.Fatal("confirmed group still listed")
	}
	if _, ok := gs["g_b"]; ok {
		t.Fatal("ignored group still listed")
	}
	if _, ok := gs["g_c"]; !ok {
		t.Fatal("g_c should remain")
	}
	if r := actionAPKScan(dir); !r.OK || !fileExists(filepath.Join(dir, "run", "apk_scan.request")) {
		t.Fatal("apk scan request not written")
	}
}
