package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// v5.18: nDPI 删除后 IP→域名表是唯一来源, 下面覆盖新增行为。

func TestIPNameCNAMEChainPerRecordTTL(t *testing.T) {
	tb := NewIPNameTable()
	recs := []DNSAnswer{
		{Name: "www.shop.com", Type: 5, TTL: 300, Value: "shop.edgekey.net"},
		{Name: "shop.edgekey.net", Type: 5, TTL: 300, Value: "e123.a.akamaiedge.net"},
		{Name: "e123.a.akamaiedge.net", Type: 1, TTL: 20, Value: "23.1.1.1"},
		{Name: "e123.a.akamaiedge.net", Type: 28, TTL: 7200, Value: "2600:1406:0:0::17"},
		// 不在 CNAME 链上的地址(附加数据 / 投毒)不入表。
		{Name: "evil.example", Type: 1, TTL: 300, Value: "6.6.6.6"},
		// HTTPS 记录的地址提示, owner 是 qname。
		{Name: "www.shop.com", Type: 65, TTL: 300, Value: "23.1.1.2"},
	}
	tb.RecordDNSAnswers("WWW.Shop.com.", recs, t0)
	for _, ip := range []string{"23.1.1.1", "2600:1406::17", "23.1.1.2"} {
		e, ok := tb.Lookup(ip, t0)
		if !ok || e.Name != "www.shop.com" || e.CNAME != "e123.a.akamaiedge.net" || e.Src != IPNameSrcDNS {
			t.Errorf("%s → %+v ok=%v", ip, e, ok)
		}
	}
	if _, ok := tb.Lookup("6.6.6.6", t0); ok {
		t.Error("off-chain address recorded")
	}
	// 每条地址按自己的 TTL: 20s → 下限 10 分钟; 7200s → 2 小时。
	if _, ok := tb.Lookup("23.1.1.1", t0.Add(11*time.Minute)); ok {
		t.Error("short-TTL record should expire after the 10 min floor")
	}
	if _, ok := tb.Lookup("2600:1406::17", t0.Add(100*time.Minute)); !ok {
		t.Error("long-TTL record should outlive the floor")
	}
	// CNAME 环不死循环; qname 自身直接拥有地址时 cname 为空。
	tb.RecordDNSAnswers("loop.a", []DNSAnswer{
		{Name: "loop.a", Type: 5, Value: "loop.b"}, {Name: "loop.b", Type: 5, Value: "loop.a"},
		{Name: "loop.b", Type: 1, TTL: 60, Value: "7.7.7.7"},
	}, t0)
	if e, ok := tb.Lookup("7.7.7.7", t0); !ok || e.Name != "loop.a" || e.CNAME != "loop.b" {
		t.Errorf("loop: %+v ok=%v", e, ok)
	}
	tb.RecordDNSAnswers("direct.example", []DNSAnswer{{Name: "direct.example", Type: 1, TTL: 60, Value: "7.7.7.8"}}, t0)
	if e, _ := tb.Lookup("7.7.7.8", t0); e.CNAME != "" {
		t.Errorf("direct: %+v", e)
	}
}

func TestIPNameCanonicalIPv6AndIgnoredAddrs(t *testing.T) {
	tb := NewIPNameTable()
	tb.RecordConnName("2001:DB8:0:0:0:0:0:1", "v6.example.com", IPNameSrcSNI, t0)
	tb.RecordConnName("::ffff:1.2.3.4", "mapped.example.com", IPNameSrcSNI, t0)
	tb.RecordDNS("mc.example.com", []string{"224.0.0.251", "ff02::fb", "::1", "127.0.0.1"}, 60, t0)
	if e, ok := tb.Lookup("2001:db8::1", t0); !ok || e.Name != "v6.example.com" {
		t.Errorf("v6 canonical: %+v ok=%v", e, ok)
	}
	if e, ok := tb.Lookup("1.2.3.4", t0); !ok || e.Name != "mapped.example.com" {
		t.Errorf("v4-mapped: %+v ok=%v", e, ok)
	}
	if tb.Len() != 2 {
		t.Errorf("multicast/loopback recorded: len=%d", tb.Len())
	}
}

func TestIPNameECHPublicNameAndHTTPPriority(t *testing.T) {
	tb := NewIPNameTable()
	tb.RecordDNS("blog.example.com", []string{"104.16.1.1"}, 300, t0)
	// ECH 外层 public_name 不能覆盖 DNS 查到的真实站点名。
	tb.RecordConnName("104.16.1.1", "cloudflare-ech.com", IPNameSrcSNI, t0.Add(time.Second))
	if e, _ := tb.Lookup("104.16.1.1", t0.Add(time.Second)); e.Name != "blog.example.com" || e.Src != IPNameSrcDNS {
		t.Errorf("ECH public name overrode DNS: %+v", e)
	}
	if !IsECHPublicName("Cloudflare-ECH.com.") || IsECHPublicName("example.com") {
		t.Error("IsECHPublicName")
	}
	// HTTP Host 与 SNI 同为连接名: 覆盖 DNS, 且不被之后的 DNS 覆盖。
	tb.RecordConnName("104.16.1.1", "static.example.com", IPNameSrcHTTP, t0.Add(2*time.Second))
	tb.RecordDNS("other.example.com", []string{"104.16.1.1"}, 300, t0.Add(3*time.Second))
	if e, _ := tb.Lookup("104.16.1.1", t0.Add(3*time.Second)); e.Name != "static.example.com" || e.Src != IPNameSrcHTTP {
		t.Errorf("http priority: %+v", e)
	}
	// 未知来源拒收。
	tb.RecordConnName("9.9.9.9", "x.com", "bogus", t0)
	if _, ok := tb.Lookup("9.9.9.9", t0); ok {
		t.Error("unknown src accepted")
	}
}

func TestIPNameKeepAliveBounded(t *testing.T) {
	tb := NewIPNameTable()
	tb.RecordDNS("push.example.com", []string{"5.5.5.5"}, 60, t0)
	tb.RecordDNS("idle.example.com", []string{"5.5.5.6"}, 60, t0)
	active := map[string]struct{}{"5.5.5.5": {}, "8.8.8.8": {}}
	// 每 5 分钟有活跃连接 → 一直顺延, 远超 DNS TTL/10 分钟下限。
	now := t0
	for i := 0; i < 12; i++ {
		now = now.Add(5 * time.Minute)
		tb.KeepAlive(active, now)
	}
	if _, ok := tb.Lookup("5.5.5.5", now); !ok {
		t.Error("active entry expired despite keep-alive")
	}
	if _, ok := tb.Lookup("5.5.5.6", now); ok {
		t.Error("idle entry should have expired")
	}
	// 连接结束后 10 分钟内过期。
	if _, ok := tb.Lookup("5.5.5.5", now.Add(11*time.Minute)); ok {
		t.Error("entry should expire after flows stop")
	}
	// 距最后一次 DNS 证据超过 24h 不再顺延(不会永久保留)。
	tb2 := NewIPNameTable()
	tb2.RecordDNS("forever.example.com", []string{"5.5.5.7"}, 60, t0)
	a2 := map[string]struct{}{"5.5.5.7": {}}
	now = t0
	for now.Sub(t0) < 25*time.Hour {
		now = now.Add(5 * time.Minute)
		tb2.KeepAlive(a2, now)
	}
	if _, ok := tb2.Lookup("5.5.5.7", now.Add(time.Minute)); ok {
		t.Error("keep-alive must stop after 24h without fresh evidence")
	}
	// 过期条目不会被 KeepAlive 复活。
	if n := tb.KeepAlive(map[string]struct{}{"5.5.5.6": {}}, now); n != 0 {
		t.Errorf("revived %d expired entries", n)
	}
}

func TestIPNameFlushExpAndCNAMEClassify(t *testing.T) {
	tb := NewIPNameTable()
	p := filepath.Join(t.TempDir(), "dpi_ipname.json")
	tb.SetPath(p)
	now := time.Unix(1_800_000_000, 0)
	// qname 规则认不出, CNAME 目标是 B 站 CDN → 用 cname 归类。
	tb.RecordDNSAnswers("video.unknown-brand.org", []DNSAnswer{
		{Name: "video.unknown-brand.org", Type: 5, TTL: 300, Value: "upos-sz-mirrorcos.bilivideo.com"},
		{Name: "upos-sz-mirrorcos.bilivideo.com", Type: 1, TTL: 300, Value: "9.9.9.9"},
	}, now)
	if err := tb.Flush(now); err != nil {
		t.Fatal(err)
	}
	read := func() ipNameFile {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var f ipNameFile
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	e := read().Entries["9.9.9.9"]
	if e.Name != "video.unknown-brand.org" || e.CNAME != "upos-sz-mirrorcos.bilivideo.com" || e.App != "bilibili" || e.Exp != now.Unix()+ipNameMinTTL {
		t.Fatalf("entry=%+v", e)
	}
	// KeepAlive 把过期时间推后很多 → 标脏, 下次 Flush 更新 exp。
	_ = os.Remove(p)
	later := now.Add(8 * time.Minute)
	tb.KeepAlive(map[string]struct{}{"9.9.9.9": {}}, later)
	if err := tb.Flush(later); err != nil {
		t.Fatal(err)
	}
	if e := read().Entries["9.9.9.9"]; e.Exp != later.Unix()+ipNameKeepAliveSec {
		t.Fatalf("exp not refreshed: %+v", e)
	}
	// 小幅顺延(< ipNameExpDirtySec)不重写文件。
	_ = os.Remove(p)
	tb.KeepAlive(map[string]struct{}{"9.9.9.9": {}}, later.Add(time.Minute))
	if err := tb.Flush(later.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("small keep-alive extension should not rewrite the file")
	}
}

func TestConntrackOrigDst(t *testing.T) {
	cases := map[string]string{
		"ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.43.20 dst=93.184.216.34 sport=5 dport=443 src=93.184.216.34 dst=10.0.0.2 sport=443 dport=5 [ASSURED] mark=0 use=1": "93.184.216.34",
		"ipv6     10 udp     17 29 src=2409:8a00::20 dst=2606:4700:0000::1111 sport=1 dport=443 src=2606:4700::1111 dst=2409::1 sport=443 dport=1":                               "2606:4700::1111",
		"ipv4 2 tcp 6 10 CLOSE src=1.1.1.1 dst=bogus": "",
		"garbage": "",
	}
	for line, want := range cases {
		if got := conntrackOrigDst(line); got != want {
			t.Errorf("%q → %q want %q", line, got, want)
		}
	}
}

// RecordFlow 在 IP 规则未命中时用 IP→域名表兜底(取代 nDPI ip_to_host.json)。
func TestWriterRecordFlowIPNameFallback(t *testing.T) {
	w := NewWriter(filepath.Join(t.TempDir(), "s.json"), "test")
	tb := NewIPNameTable()
	w.SetIPNameTable(tb)
	now := time.Unix(1_800_000_000, 0)
	tb.RecordDNS("upos-sz-mirrorcos.bilivideo.com", []string{"203.0.113.9"}, 300, now)
	w.RecordDNS("aa:bb:cc:dd:ee:01", "192.168.43.20", "192.168.43.1", "example.org", now)
	w.RecordFlow("aa:bb:cc:dd:ee:01", "192.168.43.20", "203.0.113.9", false, 443, 1500, false, now)
	if e, ok := w.IPAppMap.entries["203.0.113.9"]; !ok || e.AppID != "bilibili" {
		t.Fatalf("ipname fallback not applied: %+v ok=%v", e, ok)
	}
	w.mu.Lock()
	n := len(w.globalApps)
	w.mu.Unlock()
	if n == 0 {
		t.Error("global apps not bumped")
	}
}
