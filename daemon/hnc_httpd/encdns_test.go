package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v5.21 encdns.go: encdns_set 动作校验 / 落盘 / 调脚本; GET /api/encdns 形状

func setupEncdnsDir(t *testing.T) (string, *server) {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"data", "run", "bin"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	// 桩: 同步时把配置拷一份出来; --counters 输出固定 JSON
	writeStub(t, dir, "encdns_sync.sh", `if [ "$1" = "--counters" ]; then
echo '{"chain":true,"v6":true,"dot":{"pkts":20,"bytes":1300},"doh_ip":{"pkts":11,"bytes":700},"doh_sni":{"pkts":1,"bytes":517},"doh_dns":{"pkts":4,"bytes":300},"total_pkts":36,"total_bytes":2817,"v4_pkts":29,"v6_pkts":7}'
exit 0
fi
cp "$HNC_DIR/data/encdns.json" "$HNC_DIR/run/synced.json"
echo "ENCDNS=on global=x devices=0 rules=4 string_layer=1"
`)
	encdnsCountersInvalidate()
	return dir, newServer(dir)
}

func TestEncdnsSetAction(t *testing.T) {
	dir, s := setupEncdnsDir(t)
	bad := []map[string]string{
		{"policy": "on"},
		{"policy": "strict", "scope": "planet"},
		{"scope": "device", "mac": "zz", "policy": "dot"},
		{"mac": "aa:bb:cc:00:00:01", "policy": "loud"},
		{"mac": "02:5e:00:00:00:01", "policy": "dot"}, // 模拟设备
	}
	for _, p := range bad {
		if r := actionEncdnsSet(s, p); r.OK {
			t.Fatalf("accepted %v", p)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "encdns.json")); err == nil {
		t.Fatal("bad params must not write")
	}
	r := actionEncdnsSet(s, map[string]string{"policy": "strict"})
	if !r.OK || !strings.HasPrefix(r.Detail, "ENCDNS=on") {
		t.Fatalf("global: %+v", r)
	}
	if r := actionEncdnsSet(s, map[string]string{"policy": "strict", "scope": "global"}); !r.OK || r.Detail != "no change" {
		t.Fatalf("idempotent: %+v", r)
	}
	// 带 mac 默认 scope=device; MAC 大写归一
	if r := actionEncdnsSet(s, map[string]string{"policy": "off", "mac": "AA:BB:CC:00:00:01"}); !r.OK {
		t.Fatalf("device: %+v", r)
	}
	if r := actionEncdnsSet(s, map[string]string{"policy": "dot", "scope": "device", "mac": "aa:bb:cc:00:00:02"}); !r.OK {
		t.Fatalf("device2: %+v", r)
	}
	c := loadEncdns(dir)
	if c.Policy != "strict" || c.Devices["aa:bb:cc:00:00:01"] != "off" || c.Devices["aa:bb:cc:00:00:02"] != "dot" || c.Ts == 0 {
		t.Fatalf("conf: %+v", c)
	}
	// 脚本读的是紧凑 JSON, 形状固定
	b, _ := os.ReadFile(filepath.Join(dir, "run", "synced.json"))
	if !strings.Contains(string(b), `"policy":"strict"`) || !strings.Contains(string(b), `"aa:bb:cc:00:00:02":"dot"`) {
		t.Fatalf("synced: %s", b)
	}
	if r := actionEncdnsSet(s, map[string]string{"policy": "inherit", "mac": "aa:bb:cc:00:00:01"}); !r.OK {
		t.Fatalf("inherit: %+v", r)
	}
	if r := actionEncdnsSet(s, map[string]string{"policy": "inherit", "mac": "aa:bb:cc:00:00:01"}); !r.OK || r.Detail != "no change" {
		t.Fatalf("inherit again: %+v", r)
	}
	if c := loadEncdns(dir); len(c.Devices) != 1 {
		t.Fatalf("after inherit: %+v", c)
	}
	// 脚本失败 → 动作失败
	writeStub(t, dir, "encdns_sync.sh", "echo boom; exit 3\n")
	if r := actionEncdnsSet(s, map[string]string{"policy": "dot"}); r.OK || r.Detail != "boom" {
		t.Fatalf("script failure: %+v", r)
	}
	// 坏文件 → 默认 off
	_ = os.WriteFile(filepath.Join(dir, "data", "encdns.json"), []byte(`{"policy":"weird","devices":{"x":"dot","aa:bb:cc:00:00:09":"nope"}}`), 0o644)
	if c := loadEncdns(dir); c.Policy != "off" || len(c.Devices) != 0 {
		t.Fatalf("sanitise: %+v", c)
	}
}

func TestEncdnsAPI(t *testing.T) {
	dir, s := setupEncdnsDir(t)
	_ = os.WriteFile(filepath.Join(dir, "data", "encdns.json"), []byte(`{"policy":"dot","devices":{"aa:bb:cc:00:00:02":"strict","aa:bb:cc:00:00:01":"off"},"ts":5}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "encdns_caps.json"), []byte(`{"string_layer":true,"string_layer_v6":false,"checked":1}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "dpi_state.json"), []byte(`{"encdns":{"dns_seen":120,"dot_attempts":3,"doh_suspect":2}}`), 0o644)
	rec := httptest.NewRecorder()
	s.apiEncdns(rec, httptest.NewRequest("GET", "/api/encdns", nil))
	var r map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r["ok"] != true || r["policy"] != "dot" || r["string_layer"] != "available" || r["updated_at"].(float64) != 5 {
		t.Fatalf("api: %s", rec.Body.String())
	}
	if dv := r["devices"].(map[string]interface{}); dv["aa:bb:cc:00:00:02"] != "strict" || len(dv) != 2 {
		t.Fatalf("devices: %v", dv)
	}
	if dl := r["device_list"].([]interface{}); len(dl) != 2 || dl[0].(map[string]interface{})["mac"] != "aa:bb:cc:00:00:01" {
		t.Fatalf("device_list: %v", dl)
	}
	cnt := r["counters"].(map[string]interface{})
	if cnt["total_pkts"].(float64) != 36 || cnt["dot"].(map[string]interface{})["pkts"].(float64) != 20 {
		t.Fatalf("counters: %v", cnt)
	}
	if d := r["dpid"].(map[string]interface{}); d["doh_suspect"].(float64) != 2 {
		t.Fatalf("dpid: %v", d)
	}
	if !strings.Contains(r["tradeoff"].(string), "指定主机名") || len(r["policies"].([]interface{})) != 3 {
		t.Fatalf("tradeoff/policies: %v", r)
	}
	// 计数脚本失败 → counters=null + counters_error
	writeStub(t, dir, "encdns_sync.sh", "echo 'iptables: nope'; exit 1\n")
	encdnsCountersInvalidate()
	rec = httptest.NewRecorder()
	s.apiEncdns(rec, httptest.NewRequest("GET", "/api/encdns", nil))
	r = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if r["counters"] != nil || r["counters_error"] != "iptables: nope" {
		t.Fatalf("counters error: %s", rec.Body.String())
	}
	// 非 GET
	rec = httptest.NewRecorder()
	s.apiEncdns(rec, httptest.NewRequest("POST", "/api/encdns", nil))
	if rec.Code != 405 {
		t.Fatal(rec.Code)
	}
	if !isSensitiveReadPath("/api/encdns") {
		t.Fatal("/api/encdns must be a sensitive read path")
	}
}
