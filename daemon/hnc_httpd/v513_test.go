package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseConntrackLine(t *testing.T) {
	e, ok := parseConntrackLine("ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.43.12 dst=1.2.3.4 sport=40000 dport=443 packets=10 bytes=1500 src=1.2.3.4 dst=10.1.1.1 sport=443 dport=40000 packets=8 bytes=9000 [ASSURED] mark=0 zone=0 use=2")
	if !ok || e.Proto != "tcp" || e.State != "ESTABLISHED" || e.Src != "192.168.43.12" || e.Dst != "1.2.3.4" ||
		e.Sport != 40000 || e.Dport != 443 || e.UpB != 1500 || e.DnB != 9000 || !e.Assured || !e.Acct || e.TTL != 431999 {
		t.Fatalf("tcp parse wrong: %+v", e)
	}
	u, ok := parseConntrackLine("ipv4     2 udp      17 25 src=192.168.43.12 dst=8.8.8.8 sport=5353 dport=53 [UNREPLIED] src=8.8.8.8 dst=10.1.1.1 sport=53 dport=5353 mark=0 use=1")
	if !ok || u.State != "" || !u.Unrepl || u.Acct || u.Dport != 53 {
		t.Fatalf("udp parse wrong: %+v", u)
	}
	v6, ok := parseConntrackLine("ipv6     10 tcp      6 100 ESTABLISHED src=2409:8a00:0000:0000:0000:0000:0000:0001 dst=2400:3200::1 sport=1 dport=443 packets=1 bytes=60 src=2400:3200::1 dst=2409:8a00::1 sport=443 dport=1 packets=1 bytes=60 mark=0 use=1")
	if !ok || v6.Src != "2409:8a00::1" {
		t.Fatalf("v6 not canonicalized: %+v", v6)
	}
	if _, ok := parseConntrackLine("garbage"); ok {
		t.Fatal("garbage must fail")
	}
}

func TestAPIConnections(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "run"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	w := func(p, s string) {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("data/devices.json", `{"AA:BB:CC:00:00:01":{"ip":"192.168.43.12","last_seen":1}}`)
	w("run/dpi_state.json", `{"clients":{"k":{"client_mac":"aa:bb:cc:00:00:01","client_ip":"192.168.43.12","client_ips":["2409:8a00::5"]}}}`)
	w("run/dpi_ipname.json", `{"schema":1,"entries":{"1.2.3.4":{"name":"v.douyin.com","src":"sni","ts":1}}}`)
	w("run/ip_app_map.json", `{"entries":[{"ip":"1.2.3.4","app_id":"douyin","name":"抖音","last_seen":1}]}`)
	w("run/dpi_devid.json", `{"schema":1,"devices":{"aa:bb:cc:00:00:01":{"hostname":"Redmi-K70","hostname_src":"dhcp","os":"Android","os_ver":"14","brand":"小米","type":"phone","confidence":85,"evidence":[{"src":"dhcp","detail":"opt60=android-dhcp-14","ts":1}]}}}`)
	ct := filepath.Join(dir, "nf_conntrack")
	acct := filepath.Join(dir, "acct")
	w("acct", "0\n")
	t.Setenv("HNC_CONNTRACK_PATH", ct)
	t.Setenv("HNC_CONNTRACK_ACCT_PATH", acct)
	line := func(up, dn int) string {
		return "ipv4 2 tcp 6 300 ESTABLISHED src=192.168.43.12 dst=1.2.3.4 sport=40000 dport=443 packets=1 bytes=" + itoa(up) +
			" src=1.2.3.4 dst=10.1.1.1 sport=443 dport=40000 packets=1 bytes=" + itoa(dn) + " [ASSURED] mark=0 use=1\n" +
			"ipv4 2 udp 17 20 src=192.168.43.12 dst=192.168.43.1 sport=5000 dport=53 packets=1 bytes=70 src=192.168.43.1 dst=192.168.43.12 sport=53 dport=5000 packets=1 bytes=120 mark=0 use=1\n" +
			"ipv4 2 tcp 6 300 ESTABLISHED src=192.168.43.99 dst=5.6.7.8 sport=1 dport=443 packets=1 bytes=10 src=5.6.7.8 dst=10.1.1.1 sport=443 dport=1 packets=1 bytes=10 mark=0 use=1\n"
	}
	w("nf_conntrack", line(1000, 5000))
	ctState.mu.Lock()
	ctState.snap, ctState.prev, ctState.acctTried = nil, nil, false
	ctState.mu.Unlock()

	s := newServer(dir)
	get := func(q string) map[string]interface{} {
		rr := httptest.NewRecorder()
		s.apiConnections(rr, httptest.NewRequest("GET", "/api/connections"+q, nil))
		var out map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("bad json: %v %s", err, rr.Body.String())
		}
		return out
	}
	r1 := get("?mac=AA:BB:CC:00:00:01")
	if b, _ := os.ReadFile(acct); string(b) != "1\n" {
		t.Fatalf("acct should be switched on, got %q", b)
	}
	if r1["total"].(float64) != 2 {
		t.Fatalf("want 2 conns of this device, got %v", r1["total"])
	}
	// 让快照过期后字节增长 → 速率
	ctState.mu.Lock()
	ctState.snap.at = ctState.snap.at.Add(-2 * time.Second)
	for k, p := range ctState.prev {
		p.at = p.at.Add(-2 * time.Second)
		ctState.prev[k] = p
	}
	ctState.mu.Unlock()
	w("nf_conntrack", line(3000, 105000))
	r2 := get("?mac=aa:bb:cc:00:00:01")
	conns := r2["conns"].([]interface{})
	top := conns[0].(map[string]interface{})
	if top["name"] != "v.douyin.com" || top["app"] != "抖音" || top["svc"] != "HTTPS" {
		t.Fatalf("enrichment wrong: %v", top)
	}
	if dn := top["down_bps"].(float64); dn < 300000 || dn > 500000 { // 100000B*8/2s = 400kbps
		t.Fatalf("down_bps = %v", dn)
	}
	dns := conns[1].(map[string]interface{})
	if dns["local"] != true || dns["svc"] != "DNS" {
		t.Fatalf("dns row wrong: %v", dns)
	}
	sum := get("")
	counts := sum["counts"].(map[string]interface{})
	if c, ok := counts["aa:bb:cc:00:00:01"].(map[string]interface{}); !ok || c["n"].(float64) != 2 {
		t.Fatalf("counts wrong: %v", counts)
	}

	// 设备识别合并进 /api/devices
	_, payload := s.buildDevicesPayload()
	devs := payload["devices"].([]map[string]interface{})
	if len(devs) != 1 || devs[0]["hostname"] != "Redmi-K70" || devs[0]["hostname_src"] != "dhcp" {
		t.Fatalf("ident hostname not merged: %v", devs)
	}
	if id, ok := devs[0]["ident"].(map[string]interface{}); !ok || id["os"] != "Android" {
		t.Fatalf("ident missing: %v", devs[0])
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }
