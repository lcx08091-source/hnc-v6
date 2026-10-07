// hostname_junk_v530_test.go — v5.30 T1b: 存量 devices.json / dpi_devid.json 里的
// "null" 之类垃圾名, /api/devices 输出前挡掉。
//
// 「改动前会失败」: v5.29 原样复制 devices.json 的 hostname → 设备名 "null"
// (TestAPIDevicesDropsJunkHostname 的 mac1 / mac2 断言失败)。
package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestIsJunkHostnameHTTPD(t *testing.T) {
	for _, s := range []string{"null", "NULL", " Null ", "(null)", "nil", "none", "(none)",
		"undefined", "unknown", "UNKNOWN", "localhost", "localhost.localdomain",
		"*", "-", "", "   ", "\t", "0", "12345"} {
		if !isJunkHostname(s) {
			t.Errorf("isJunkHostname(%q) = false", s)
		}
	}
	for _, s := range []string{"Mi-10", "nullify", "iPhone", "localhost2", "123abc", "a",
		"Johns-MacBook", "客厅电视", "-x", "none-pc"} {
		if isJunkHostname(s) {
			t.Errorf("isJunkHostname(%q) = true", s)
		}
	}
}

func writeFileT(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// 接线: 走真实 handler /api/devices。
func TestAPIDevicesDropsJunkHostname(t *testing.T) {
	dir := t.TempDir()
	ls := func() string { return "1790000000" } // 固定值: 本用例不看在线状态, 不读真实时钟
	writeFileT(t, filepath.Join(dir, "data", "devices.json"), `{
 "aa:00:00:00:00:01":{"ip":"192.168.43.11","hostname":"null","hostname_src":"dhcp","last_seen":`+ls()+`},
 "aa:00:00:00:00:02":{"ip":"192.168.43.12","hostname":"NULL","hostname_src":"mdns","last_seen":`+ls()+`},
 "aa:00:00:00:00:03":{"ip":"192.168.43.13","hostname":"null","hostname_src":"manual","last_seen":`+ls()+`},
 "aa:00:00:00:00:05":{"ip":"192.168.43.15","hostname":"Mi-10","hostname_src":"dhcp","last_seen":`+ls()+`},
 "aa:00:00:00:00:06":{"ip":"192.168.43.16","last_seen":`+ls()+`}
}`)
	writeFileT(t, filepath.Join(dir, "data", "device_names.json"), `{"aa:00:00:00:00:04":"unknown"}`)
	writeFileT(t, filepath.Join(dir, "data", "rules.json"), `{"devices":{"aa:00:00:00:00:04":{"down_mbps":1}}}`)
	writeFileT(t, filepath.Join(dir, "run", "dpi_devid.json"), `{"devices":{
 "aa:00:00:00:00:02":{"hostname":"Pixel-7","hostname_src":"mdns","os":"android"},
 "aa:00:00:00:00:06":{"hostname":"null","hostname_src":"dhcp","os":"ios"}}}`)
	s := newServer(dir)
	rec := httptest.NewRecorder()
	s.apiDevices(rec, httptest.NewRequest("GET", "/api/devices", nil))
	var r struct {
		Devices []map[string]interface{} `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	by := map[string]map[string]interface{}{}
	for _, d := range r.Devices {
		by[asString(d["mac"])] = d
	}
	type want struct{ hn, src string }
	for mac, w := range map[string]want{
		"aa:00:00:00:00:01": {"", ""},            // dhcp 报 "null" → 没有名字
		"aa:00:00:00:00:02": {"Pixel-7", "mdns"}, // 退到 dpid 抓到的真名
		"aa:00:00:00:00:03": {"null", "manual"},  // 手动命名不过滤
		"aa:00:00:00:00:04": {"unknown", "manual"},
		"aa:00:00:00:00:05": {"Mi-10", "dhcp"},
		"aa:00:00:00:00:06": {"", ""}, // dpid 旧落盘的 "null" 也不用
	} {
		d := by[mac]
		if d == nil {
			t.Errorf("%s 不在输出里: %s", mac, rec.Body.String())
			continue
		}
		if asString(d["hostname"]) != w.hn || asString(d["hostname_src"]) != w.src {
			t.Errorf("%s hostname=%q src=%q, want %q / %q", mac, d["hostname"], d["hostname_src"], w.hn, w.src)
		}
	}
	if id, _ := by["aa:00:00:00:00:06"]["ident"].(map[string]interface{}); id == nil || id["hostname"] != nil || id["os"] != "ios" {
		t.Errorf("ident 应保留其它字段、去掉垃圾名: %v", by["aa:00:00:00:00:06"]["ident"])
	}
}

func TestMACMergeIgnoresJunkHostname(t *testing.T) {
	var o macObs
	o.setHostname("null", "dhcp")
	o.setHostname("localhost", "mdns")
	if o.dhcpName != "" || o.mdnsName != "" {
		t.Fatalf("垃圾名不应参与「同名 = 同一台」: %+v", o)
	}
	o.setHostname("Mi-10", "dhcp")
	if o.dhcpName != "Mi-10" {
		t.Fatalf("真名丢了: %+v", o)
	}
}
