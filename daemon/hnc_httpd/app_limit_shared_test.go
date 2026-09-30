package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAppLimitSplitShared(t *testing.T) {
	nameApp := map[string]string{
		"1.1.1.1": "douyin",     // 同一应用 → 保留
		"2.2.2.2": "weixin",     // 另一应用 → 共享
		"3.3.3.3": "akamai_cdn", // 规则库 cdn 类 → 共享
	}
	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} // 4.4.4.4 反查表没有 → 保留
	cases := []struct {
		name       string
		include    bool
		wantKept   []string
		wantShared []string
	}{
		{"skip shared", false, []string{"1.1.1.1", "4.4.4.4"}, []string{"2.2.2.2", "3.3.3.3"}},
		{"escape hatch", true, ips, nil},
	}
	for _, c := range cases {
		kept, shared := appLimitSplitShared("douyin", ips, nameApp, c.include)
		if !reflect.DeepEqual(kept, c.wantKept) || !reflect.DeepEqual(shared, c.wantShared) {
			t.Errorf("%s: kept=%v shared=%v, want kept=%v shared=%v", c.name, kept, shared, c.wantKept, c.wantShared)
		}
	}
	// 反查表为空: 不能误判
	kept, shared := appLimitSplitShared("douyin", ips, map[string]string{}, false)
	if len(kept) != 4 || len(shared) != 0 {
		t.Errorf("empty name table: kept=%v shared=%v", kept, shared)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAppLimitIncludeSharedFlag(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "data", "rules.json")
	if appLimitIncludeShared(dir) {
		t.Fatal("missing rules.json must default to false")
	}
	for body, want := range map[string]bool{
		`{"app_limit_include_shared_ips":true}`:   true,
		`{"app_limit_include_shared_ips":"true"}`: true,
		`{"app_limit_include_shared_ips":false}`:  false,
		`{"devices":{}}`:                          false,
	} {
		writeFile(t, rules, body)
		if got := appLimitIncludeShared(dir); got != want {
			t.Errorf("%s: got %v want %v", body, got, want)
		}
	}
}

// 与 test/unit/test_v520_qdisc_precision.sh 的 apply_app_limits 用例使用同一组数据,
// 保证 Go 统计与 shell 实际下发一致。
func TestAPIAppLimitsSharedIPStats(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "data", "app_limits.json"),
		`{"version":1,"items":[{"mac":"aa:bb:cc:dd:ee:01","app_id":"douyin","down_mbps":2},{"mac":"aa:bb:cc:dd:ee:01","app_id":"bilibili","down_mbps":1}]}`)
	writeFile(t, filepath.Join(dir, "run", "ip_app_map.flat"),
		"1.1.1.1 douyin\n2.2.2.2 douyin\n3.3.3.3 douyin\n1.1.1.1 douyin\n5.5.5.5 bilibili\n")
	writeFile(t, filepath.Join(dir, "run", "dpi_ipname.json"),
		`{"schema":1,"generated_at":1,"entries":{"1.1.1.1":{"name":"v1.douyinvod.com","src":"sni","ts":1,"app":"douyin","app_name":"抖音","category":"video"},"2.2.2.2":{"name":"x.akamaized.net","src":"dns","ts":1,"app":"akamai_cdn","app_name":"Akamai CDN","category":"cdn"},"5.5.5.5":{"name":"a.weixin.qq.com","src":"dns","ts":1,"app":"weixin","category":"social"}}}`)
	writeFile(t, filepath.Join(dir, "data", "rules.json"), `{"devices":{}}`)

	get := func() map[string]interface{} {
		s := newServer(dir)
		rec := httptest.NewRecorder()
		s.apiAppLimits(rec, httptest.NewRequest("GET", "/api/app_limits", nil))
		var out map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("bad json: %v %s", err, rec.Body.String())
		}
		return out
	}
	out := get()
	items, _ := out["items"].([]interface{})
	if len(items) != 2 {
		t.Fatalf("items=%v", out["items"])
	}
	want := []struct {
		app                    string
		total, shared, limited float64
	}{
		{"douyin", 3, 1, 2},   // 2.2.2.2 反查为 akamai_cdn → 跳过; 1.1.1.1 重复只算一次
		{"bilibili", 1, 1, 0}, // 5.5.5.5 反查为 weixin → 跳过, 该限速无可用 IP
	}
	for i, w := range want {
		m := items[i].(map[string]interface{})
		if m["app_id"] != w.app || m["ips_total"] != w.total || m["ips_shared_skipped"] != w.shared || m["ips_limited"] != w.limited {
			t.Errorf("item %d = %v, want %+v", i, m, w)
		}
		if m["mac"] != "aa:bb:cc:dd:ee:01" || m["ip_stats_source"] != "computed" {
			t.Errorf("item %d missing base fields: %v", i, m)
		}
	}
	if out["include_shared_ips"] != false {
		t.Errorf("include_shared_ips = %v", out["include_shared_ips"])
	}

	// 逃生口打开 → 不跳过
	writeFile(t, filepath.Join(dir, "data", "rules.json"), `{"devices":{},"app_limit_include_shared_ips":true}`)
	out = get()
	items, _ = out["items"].([]interface{})
	m := items[0].(map[string]interface{})
	if m["ips_shared_skipped"] != float64(0) || m["ips_limited"] != float64(3) || out["include_shared_ips"] != true {
		t.Errorf("escape hatch: %v / include=%v", m, out["include_shared_ips"])
	}
}

func TestSQMQdiscFromOutput(t *testing.T) {
	if got := sqmQdiscFromOutput("SQM_APPLY_MODE=on\nSQM_QDISC=fq_codel\n"); got != "fq_codel" {
		t.Errorf("got %q", got)
	}
	if got := sqmQdiscFromOutput("SQM_APPLY_MODE=off\n"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestAPICapabilitiesIncludesQdiscCaps(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "run", "capabilities.json"), `{"tc_htb":true}`)
	writeFile(t, filepath.Join(dir, "run", "qdisc_caps.json"),
		`{"schema":1,"chosen":"fq_codel","available":["fq_codel","sfq","pfifo"],"probed_at":5,"tried":[{"name":"cake","method":"tc_probe","ok":false,"err":"Unknown qdisc"}]}`)
	s := newServer(dir)
	rec := httptest.NewRecorder()
	s.apiCapabilities(rec, httptest.NewRequest("GET", "/api/capabilities", nil))
	var out struct {
		Available bool `json:"available"`
		QdiscCaps struct {
			Chosen    string   `json:"chosen"`
			Available []string `json:"available"`
		} `json:"qdisc_caps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Available || out.QdiscCaps.Chosen != "fq_codel" || len(out.QdiscCaps.Available) != 3 {
		t.Errorf("unexpected: %s", rec.Body.String())
	}
}

func TestTCLeafAQMSetValidates(t *testing.T) {
	if r := actionTCLeafAQMSet(t.TempDir(), map[string]string{"mode": "bogus"}); r.OK {
		t.Error("bogus mode must be rejected")
	}
}
