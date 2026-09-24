package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

var t0 = time.Unix(1_760_000_000, 0)

func newTestDevID(t *testing.T) (*DeviceIdentifier, string) {
	t.Helper()
	d := NewDeviceIdentifier()
	p := filepath.Join(t.TempDir(), "dpi_devid.json")
	d.SetPath(p)
	return d, p
}

func mustDev(t *testing.T, d *DeviceIdentifier, mac string) DeviceInfo {
	t.Helper()
	info, ok := d.Get(mac)
	if !ok {
		t.Fatalf("device %s not tracked", mac)
	}
	return info
}

func TestDevIDAndroidDHCP(t *testing.T) {
	d, _ := newTestDevID(t)
	d.ObserveHint(DeviceHint{
		MAC: "3C:22:FB:11:22:33", Source: "dhcp", Hostname: "Redmi-Note-12",
		VendorClass: "android-dhcp-14", ParamList: "1,3,6,15,26,28,51,58,59,43,114,108",
	}, t0)
	info := mustDev(t, d, "3c:22:fb:11:22:33")
	if info.OS != "Android" || info.OSVer != "14" || info.Brand != "小米" || info.Type != "phone" {
		t.Fatalf("%+v", info)
	}
	if info.Hostname != "Redmi-Note-12" || info.HostnameSrc != "dhcp" {
		t.Fatalf("hostname %+v", info)
	}
	if info.VendorClass != "android-dhcp-14" || info.DHCPFP != "1,3,6,15,26,28,51,58,59,43,114,108" {
		t.Fatalf("raw fields %+v", info)
	}
	if info.Confidence < 80 {
		t.Fatalf("confidence=%d, want >=80 (opt60+opt55+hostname 一致)", info.Confidence)
	}
	if len(info.Evidence) == 0 || info.Evidence[0].Ts != t0.Unix() {
		t.Fatalf("evidence %+v", info.Evidence)
	}
}

func TestDevIDMacMDNS(t *testing.T) {
	d, _ := newTestDevID(t)
	d.ObserveHint(DeviceHint{
		MAC: "a4:83:e7:00:00:01", Source: "mdns", Hostname: "Johns-MacBook-Pro",
		Model: "MacBookPro18,1", OSHint: "macOS",
		Services: []string{"_airplay._tcp", "_companion-link._tcp", "_airplay._tcp"},
	}, t0)
	info := mustDev(t, d, "a4:83:e7:00:00:01")
	if info.OS != "macOS" || info.Brand != "Apple" || info.Type != "pc" || info.Model != "MacBookPro18,1" {
		t.Fatalf("%+v", info)
	}
	if !reflect.DeepEqual(info.Services, []string{"_airplay._tcp", "_companion-link._tcp"}) {
		t.Fatalf("services %v", info.Services)
	}
	if info.HostnameSrc != "mdns" {
		t.Fatalf("hostname_src %q", info.HostnameSrc)
	}
}

func TestDevIDWindowsMultiSource(t *testing.T) {
	d, _ := newTestDevID(t)
	mac := "00:11:22:33:44:55"
	d.ObserveHint(DeviceHint{MAC: mac, Source: "nbns", Hostname: "DESKTOP-AB12CD"}, t0)
	d.ObserveDomain(mac, "www.msftconnecttest.com", "dns", t0)
	one := mustDev(t, d, mac)
	d.ObserveHint(DeviceHint{MAC: mac, Source: "dhcp", VendorClass: "MSFT 5.0",
		ParamList: "1,3,6,15,31,33,43,44,46,47,119,121,249,252"}, t0.Add(time.Second))
	info := mustDev(t, d, mac)
	if info.OS != "Windows" || info.Type != "pc" {
		t.Fatalf("%+v", info)
	}
	if info.Confidence <= one.Confidence {
		t.Fatalf("多来源一致应加分: %d -> %d", one.Confidence, info.Confidence)
	}
}

func TestDevIDDomainOnlyWeak(t *testing.T) {
	d, _ := newTestDevID(t)
	mac := "aa:bb:cc:00:00:01"
	d.ObserveDomain(mac, "unrelated.example.com", "dns", t0)
	if _, ok := d.Get(mac); ok {
		t.Fatal("不命中域名表不应创建设备")
	}
	d.ObserveDomain(mac, "api.miui.com", "sni", t0)
	info := mustDev(t, d, mac)
	if info.Brand != "小米" {
		t.Fatalf("%+v", info)
	}
	if info.Confidence >= 50 {
		t.Fatalf("单一弱信号置信度应偏低: %d", info.Confidence)
	}
	// 同一后缀反复出现不累加(证据键去重)。
	for i := 0; i < 50; i++ {
		d.ObserveDomain(mac, fmt.Sprintf("x%d.miui.com", i), "dns", t0)
	}
	if again := mustDev(t, d, mac); again.Confidence >= 50 {
		t.Fatalf("重复弱信号不应刷高置信度: %d", again.Confidence)
	}
}

func TestDevIDStrongBeatsWeak(t *testing.T) {
	d, _ := newTestDevID(t)
	mac := "aa:bb:cc:00:00:02"
	d.ObserveDomain(mac, "login.live.com", "sni", t0)
	d.ObserveDomain(mac, "x.windowsupdate.com", "dns", t0)
	d.ObserveHint(DeviceHint{MAC: mac, Source: "dhcp", VendorClass: "android-dhcp-13"}, t0)
	if info := mustDev(t, d, mac); info.OS != "Android" || info.OSVer != "13" {
		t.Fatalf("%+v", info)
	}
}

func TestDevIDHostnamePriority(t *testing.T) {
	d, _ := newTestDevID(t)
	mac := "aa:bb:cc:00:00:03"
	d.ObserveHint(DeviceHint{MAC: mac, Source: "nbns", Hostname: "NB-NAME"}, t0)
	d.ObserveHint(DeviceHint{MAC: mac, Source: "dhcp", Hostname: "dhcp-name"}, t0)
	d.ObserveHint(DeviceHint{MAC: mac, Source: "mdns", Hostname: "mdns-name"}, t0)
	if info := mustDev(t, d, mac); info.Hostname != "dhcp-name" || info.HostnameSrc != "dhcp" {
		t.Fatalf("%+v", info)
	}
}

func TestDevIDEvidenceAndServiceCaps(t *testing.T) {
	d, _ := newTestDevID(t)
	mac := "aa:bb:cc:00:00:04"
	var svcs []string
	for i := 0; i < 20; i++ {
		svcs = append(svcs, fmt.Sprintf("_s%d._tcp", i))
		d.ObserveHint(DeviceHint{MAC: mac, Source: "ssdp", UserAgent: fmt.Sprintf("Linux/%d UPnP/1.0", i)}, t0.Add(time.Duration(i)*time.Second))
	}
	d.ObserveHint(DeviceHint{MAC: mac, Source: "mdns", Services: svcs}, t0)
	info := mustDev(t, d, mac)
	if len(info.Evidence) > devIDMaxEvidence {
		t.Fatalf("evidence=%d", len(info.Evidence))
	}
	if len(info.Services) != devIDMaxServices {
		t.Fatalf("services=%d", len(info.Services))
	}
}

func TestDevIDLRU(t *testing.T) {
	d, _ := newTestDevID(t)
	mac := func(i int) string { return fmt.Sprintf("02:00:00:00:%02x:%02x", i>>8, i&0xff) }
	for i := 0; i < 300; i++ {
		d.ObserveHint(DeviceHint{MAC: mac(i), Source: "dhcp", Hostname: "h"}, t0.Add(time.Duration(i)*time.Second))
		if i == 10 {
			continue
		}
		// 反复触碰 0 号, 它应一直留在 LRU 前部
		d.ObserveHint(DeviceHint{MAC: mac(0), Source: "dhcp", Hostname: "h0"}, t0.Add(time.Duration(i)*time.Second))
	}
	snap := d.Snapshot()
	if len(snap) != devIDMaxDevices {
		t.Fatalf("tracked=%d", len(snap))
	}
	if _, ok := snap[mac(0)]; !ok {
		t.Fatal("recently-touched device evicted")
	}
	if _, ok := snap[mac(1)]; ok {
		t.Fatal("oldest device should be evicted")
	}
	if _, ok := snap[mac(299)]; !ok {
		t.Fatal("newest device missing")
	}
}

func TestDevIDPersistRoundTrip(t *testing.T) {
	d, p := newTestDevID(t)
	d.ObserveHint(DeviceHint{MAC: "3c:22:fb:11:22:33", Source: "dhcp", Hostname: "Redmi-Note-12",
		VendorClass: "android-dhcp-14", ParamList: "1,3,6,15,26,28,51,58,59,43,114,108"}, t0)
	d.ObserveHint(DeviceHint{MAC: "a4:83:e7:00:00:01", Source: "mdns", Model: "iPhone15,2",
		Services: []string{"_companion-link._tcp"}}, t0)
	if err := d.Flush(t0); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f["schema"].(float64) != 1 || f["generated_at"].(float64) != float64(t0.Unix()) {
		t.Fatalf("header %v", f)
	}
	dev := f["devices"].(map[string]any)["3c:22:fb:11:22:33"].(map[string]any)
	for _, k := range []string{"hostname", "hostname_src", "os", "os_ver", "brand", "model", "type", "confidence", "vendor_class", "dhcp_fp", "services", "last_seen", "evidence"} {
		if _, ok := dev[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}

	// 无变化不重写。
	_ = os.Remove(p)
	if err := d.Flush(t0.Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("unchanged identifier should not rewrite file")
	}
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	// 新实例读回。
	d2 := NewDeviceIdentifier()
	d2.SetPath(p)
	if err := d2.Load(); err != nil {
		t.Fatal(err)
	}
	for _, mac := range []string{"3c:22:fb:11:22:33", "a4:83:e7:00:00:01"} {
		a, b := mustDev(t, d, mac), mustDev(t, d2, mac)
		if a.Hostname != b.Hostname || a.HostnameSrc != b.HostnameSrc || a.OS != b.OS || a.OSVer != b.OSVer ||
			a.Brand != b.Brand || a.Model != b.Model || a.Type != b.Type || a.VendorClass != b.VendorClass ||
			a.DHCPFP != b.DHCPFP || !reflect.DeepEqual(a.Services, b.Services) || a.LastSeen != b.LastSeen ||
			len(a.Evidence) != len(b.Evidence) {
			t.Fatalf("round trip mismatch:\n%+v\n%+v", a, b)
		}
	}
	// 读回后不是 dirty; 新的强信号仍可推翻恢复值。
	d2.ObserveHint(DeviceHint{MAC: "3c:22:fb:11:22:33", Source: "dhcp", VendorClass: "MSFT 5.0",
		ParamList: "1,3,6,15,31,33,43,44,46,47,119,121,249,252", Hostname: "DESKTOP-ZZZZ1"}, t0.Add(time.Hour))
	if info := mustDev(t, d2, "3c:22:fb:11:22:33"); info.OS != "Windows" {
		t.Fatalf("strong new signals should override restored: %+v", info)
	}
}

func TestDevIDLoadBadFile(t *testing.T) {
	for name, content := range map[string]string{
		"garbage":     "{not json",
		"wrongschema": `{"schema":9,"devices":{"aa:bb:cc:dd:ee:ff":{"os":"X"}}}`,
		"badmac":      `{"schema":1,"devices":{"nonsense":{"os":"X"}}}`,
		"empty":       "",
	} {
		d, p := newTestDevID(t)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := d.Load(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if n := len(d.Snapshot()); n != 0 {
			t.Fatalf("%s: loaded %d devices from bad file", name, n)
		}
	}
	d := NewDeviceIdentifier()
	d.SetPath(filepath.Join(t.TempDir(), "missing.json"))
	if err := d.Load(); err != nil {
		t.Fatal(err)
	}
}

func TestDevIDRuleTables(t *testing.T) {
	cases := []struct {
		hint           DeviceHint
		os, brand, typ string
	}{
		{DeviceHint{Source: "dhcp", Hostname: "Johns-iPhone"}, "iOS", "Apple", "phone"},
		{DeviceHint{Source: "dhcp", Hostname: "iPad-Air"}, "iPadOS", "Apple", "tablet"},
		{DeviceHint{Source: "dhcp", Hostname: "Galaxy-S23"}, "Android", "三星", "phone"},
		{DeviceHint{Source: "dhcp", Hostname: "HUAWEI_Mate_60"}, "", "华为", "phone"},
		{DeviceHint{Source: "dhcp", Hostname: "realme-GT"}, "Android", "realme", "phone"},
		{DeviceHint{Source: "dhcp", Hostname: "android-5f3a2b9c1d"}, "Android", "", "phone"},
		{DeviceHint{Source: "dhcp", Hostname: "ESP_3A2B1C"}, "", "", "iot"},
		{DeviceHint{Source: "dhcp", Hostname: "raspberrypi"}, "Linux", "Raspberry Pi", "iot"},
		{DeviceHint{Source: "dhcp", Hostname: "Nintendo-Switch"}, "", "任天堂", "console"},
		{DeviceHint{Source: "dhcp", Hostname: "MiTV-AXSO0"}, "", "小米", "tv"},
		{DeviceHint{Source: "dhcp", VendorClass: "HUAWEI:android:NOH-AN00"}, "Android", "华为", "phone"},
		{DeviceHint{Source: "dhcp", VendorClass: "dhcpcd-9.4.1:Linux-5.10.43-android12-9:aarch64:qcom"}, "Android", "", "unknown"},
		{DeviceHint{Source: "dhcp", VendorClass: "udhcp 1.30.1"}, "Linux", "", "iot"},
		{DeviceHint{Source: "dhcp", ParamList: "1,121,3,6,15,108,114,119,252,95,44,46"}, "", "Apple", "unknown"},
		{DeviceHint{Source: "dhcp", ParamList: "1,28,2,3,15,6,119,12,44,47,26,121,42,249,33,252"}, "Linux", "", "unknown"},
		{DeviceHint{Source: "mdns", Model: "AppleTV14,1"}, "tvOS", "Apple", "tv"},
		{DeviceHint{Source: "mdns", Services: []string{"_googlecast._tcp"}}, "", "", "tv"},
		{DeviceHint{Source: "ssdp", UserAgent: "Linux/4.9 UPnP/1.0 MiTV/2.0"}, "Linux", "小米", "tv"},
		{DeviceHint{Source: "ssdp", UserAgent: "Android/14 UPnP/1.1"}, "Android", "", "unknown"},
		{DeviceHint{Source: "dhcpv6", VendorClass: "MSFT 5.0"}, "Windows", "", "pc"},
	}
	for i, c := range cases {
		d := NewDeviceIdentifier()
		c.hint.MAC = "aa:bb:cc:dd:ee:01"
		d.ObserveHint(c.hint, t0)
		info := mustDev(t, d, c.hint.MAC)
		if info.OS != c.os || info.Brand != c.brand || info.Type != c.typ {
			t.Errorf("case %d %+v: got os=%q brand=%q type=%q", i, c.hint, info.OS, info.Brand, info.Type)
		}
	}
	for host, brand := range map[string]string{
		"captive.apple.com":                      "Apple",
		"p12-caldav.icloud.com":                  "Apple",
		"connectivitycheck.platform.hicloud.com": "华为",
		"dl.heytapdl.com":                        "OPPO/realme/一加",
		"api.vivo.com.cn":                        "vivo",
		"x.samsungapps.com":                      "三星",
		"a.b.nintendo.net":                       "任天堂",
	} {
		_, sig, ok := matchDomain(host)
		if !ok || sig.Brand != brand {
			t.Errorf("%s → %+v ok=%v, want brand %q", host, sig, ok, brand)
		}
	}
	if suf, _, _ := matchDomain("connectivitycheck.platform.hicloud.com"); suf != "connectivitycheck.platform.hicloud.com" {
		t.Errorf("最长后缀应命中 %q", suf)
	}
	for client, want := range map[string]bool{"iOS Safari": true, "Chrome": false, "Android WebView": true, "": false} {
		_, ok := matchJA4Client(client)
		if ok != want {
			t.Errorf("ja4 %q ok=%v", client, ok)
		}
	}
}

// Writer.RecordDNS / RecordTLS 在释放 w.mu 后把域名喂给识别器。
func TestWriterFeedsDeviceIdentifier(t *testing.T) {
	w := NewWriter(filepath.Join(t.TempDir(), "dpi_state.json"), "test")
	d, _ := newTestDevID(t)
	w.SetDeviceIdentifier(d)
	w.RecordDNS("3C:22:FB:11:22:33", "192.168.43.10", "192.168.43.1", "connectivitycheck.gstatic.com", t0)
	w.RecordTLS("3c:22:fb:11:22:33", "192.168.43.10", "1.2.3.4", "play.googleapis.com", "t13d1516h2_8daaf6152771_e5627efa2ab1", t0)
	info := mustDev(t, d, "3c:22:fb:11:22:33")
	if info.OS != "Android" {
		t.Fatalf("%+v", info)
	}
	srcs := map[string]bool{}
	for _, e := range info.Evidence {
		srcs[e.Src] = true
	}
	if !srcs["dns"] || !srcs["sni"] {
		t.Fatalf("evidence srcs %v", srcs)
	}
	// 无 MAC 不喂。
	w.RecordDNS("", "192.168.43.11", "192.168.43.1", "captive.apple.com", t0)
	if len(d.Snapshot()) != 1 {
		t.Fatal("empty MAC should not create device")
	}
}

func TestDevIDConcurrent(t *testing.T) {
	d, _ := newTestDevID(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				mac := fmt.Sprintf("02:00:00:00:%02x:%02x", g, i%50)
				d.ObserveHint(DeviceHint{MAC: mac, Source: "dhcp", Hostname: "Redmi-" + mac, VendorClass: "android-dhcp-14"}, t0)
				d.ObserveDomain(mac, "api.miui.com", "dns", t0)
				d.ObserveJA4Client(mac, "Android Chrome", t0)
				if i%100 == 0 {
					_ = d.Flush(t0)
					_ = d.Snapshot()
				}
			}
		}(g)
	}
	wg.Wait()
	if n := len(d.Snapshot()); n != 256 {
		t.Fatalf("tracked=%d, want 256 (8×50=400 capped)", n)
	}
}
