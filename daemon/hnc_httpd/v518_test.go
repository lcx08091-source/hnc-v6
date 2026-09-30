package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v5.18: clsact_bpf_mode 解析(旧键兼容)
func TestClsactModeFromRules(t *testing.T) {
	cases := []struct {
		m    map[string]interface{}
		want string
	}{
		{map[string]interface{}{}, "auto"},
		{map[string]interface{}{"clsact_bpf_enabled": true}, "on"},
		{map[string]interface{}{"clsact_bpf_enabled": false}, "auto"},
		{map[string]interface{}{"clsact_bpf_enabled": true, "clsact_bpf_mode": "off"}, "off"},
		{map[string]interface{}{"clsact_bpf_mode": "ON"}, "on"},
		{map[string]interface{}{"clsact_bpf_mode": "bogus", "clsact_bpf_enabled": true}, "on"},
	}
	for _, c := range cases {
		if got := clsactModeFromRules(c.m); got != c.want {
			t.Fatalf("%v → %q, want %q", c.m, got, c.want)
		}
	}
}

func writeStub(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "bin", name), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// v5.18: clsact_mode_set 校验 + 写 rules + 立即 apply; clsact_bpf_enabled_set 为别名
func TestClsactModeSetAction(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "run", "bin"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	writeStub(t, dir, "json_set.sh", `echo "$*" >> "$HNC_DIR/run/json_set.log"`+"\n")
	writeStub(t, dir, "hnc_offload_guard.sh", `echo "guard $*" >> "$HNC_DIR/run/json_set.log"; echo '{"mode":"on","offload_state":"IDLE","fallback_active":true,"since":1,"detail":"x","last_check":2,"slowpath":"ok","clsact":"unavailable","iface":"wlan2"}'`+"\n")
	if r := actionClsactModeSet(dir, map[string]string{"mode": "turbo"}); r.OK {
		t.Fatal("bad mode accepted")
	}
	r := actionClsactModeSet(dir, map[string]string{"mode": "on"})
	if !r.OK || !strings.HasPrefix(r.Detail, `{"mode":"on"`) {
		t.Fatalf("mode_set on = %+v", r)
	}
	log, _ := os.ReadFile(filepath.Join(dir, "run", "json_set.log"))
	for _, want := range []string{"top clsact_bpf_mode on", "top clsact_bpf_enabled true", "guard apply"} {
		if !strings.Contains(string(log), want) {
			t.Fatalf("missing %q in %q", want, log)
		}
	}
	_ = os.Remove(filepath.Join(dir, "run", "json_set.log"))
	if r := actionClsactEnabledSet(dir, map[string]string{"enabled": "false"}); !r.OK {
		t.Fatalf("legacy alias: %+v", r)
	}
	log, _ = os.ReadFile(filepath.Join(dir, "run", "json_set.log"))
	if !strings.Contains(string(log), "top clsact_bpf_mode off") || !strings.Contains(string(log), "top clsact_bpf_enabled false") {
		t.Fatalf("legacy false should map to off: %q", log)
	}
	if r := actionClsactEnabledSet(dir, map[string]string{"enabled": "maybe"}); r.OK {
		t.Fatal("legacy bad param accepted")
	}
}

// v5.18: /api/config 透出 clsact_bpf_mode / offload_guard / conn_block_dns_layer
func TestConfigOffloadGuardFields(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "run"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"clsact_bpf_enabled":true}`), 0o644)
	s := newServer(dir)
	get := func() map[string]interface{} {
		w := httptest.NewRecorder()
		s.apiConfig(w, httptest.NewRequest("GET", "/api/config", nil))
		var m map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := get()
	if m["clsact_bpf_mode"] != "on" || m["clsact_bpf_enabled"] != true {
		t.Fatalf("legacy → on: %v", m)
	}
	if v, ok := m["offload_guard"]; !ok || v != nil {
		t.Fatalf("offload_guard must be null when absent: %v", v)
	}
	if m["conn_block_dns_layer"] != "unknown" {
		t.Fatalf("dns layer default: %v", m["conn_block_dns_layer"])
	}
	if _, ok := m["stats_shadow_enabled"]; ok {
		t.Fatal("stats_shadow_enabled should be gone")
	}
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"clsact_bpf_mode":"auto"}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "offload_guard.json"), []byte(`{"mode":"auto","offload_state":"ACTIVE","fallback_active":true,"since":1700000000,"detail":"d","last_check":1700000060,"slowpath":"ok","clsact":"skipped_pref1_mirred","iface":"wlan2"}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "connblock_caps.json"), []byte(`{"dns_layer":false,"dns_layer_v6":false,"checked":1}`), 0o644)
	m = get()
	g, _ := m["offload_guard"].(map[string]interface{})
	if m["clsact_bpf_mode"] != "auto" || m["clsact_bpf_enabled"] != false || g == nil || g["fallback_active"] != true || g["offload_state"] != "ACTIVE" {
		t.Fatalf("guard fields: %v", m)
	}
	if m["conn_block_dns_layer"] != "unavailable" {
		t.Fatalf("dns layer: %v", m["conn_block_dns_layer"])
	}
	// 陈旧的 guard 采样不被 OffloadLoop 复用
	if _, ok := offloadGuardFreshState(dir, 90e9); ok {
		t.Fatal("stale guard state reused")
	}
}

// v5.18: 域名封锁同时写 DNS 层列表
func TestConnBlocksDNSList(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "run", "bin"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	writeStub(t, dir, "connblock_sync.sh", "echo CONN_BLOCK=on rules=0 dns=$(wc -l < \"$HNC_DIR/run/conn_blocks.dns\") dns_layer=1\n")
	s := newServer(dir)
	mac := "aa:bb:cc:00:00:01"
	if r := actionConnBlockAdd(s, map[string]string{"mac": mac, "kind": "domain", "value": "*.Douyin.com"}); !r.OK || !strings.Contains(r.Detail, "dns=1") {
		t.Fatalf("add: %+v", r)
	}
	if r := actionConnBlockAdd(s, map[string]string{"mac": mac, "kind": "ip", "value": "1.2.3.4"}); !r.OK {
		t.Fatalf("add ip: %+v", r)
	}
	b, _ := os.ReadFile(connBlocksDNS(dir))
	if string(b) != mac+" douyin.com\n" {
		t.Fatalf("dns list = %q", b)
	}
	if r := actionConnBlockDel(s, map[string]string{"mac": mac, "kind": "domain", "value": "douyin.com"}); !r.OK {
		t.Fatal(r)
	}
	if b, _ := os.ReadFile(connBlocksDNS(dir)); len(b) != 0 {
		t.Fatalf("dns list should be empty: %q", b)
	}
}
