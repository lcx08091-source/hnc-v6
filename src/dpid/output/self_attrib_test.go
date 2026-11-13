package output

import (
	"testing"
)

// v6 review fix 回归测试: sampleOnly 的变更检测依赖 connsSignature —— 同一
// 连接集不同顺序必须得到同一签名 (parseProcNet 的遍历顺序不稳定), 否则会
// 误判"变了"导致写放大修复失效。
func TestConnsSignatureOrderIndependent(t *testing.T) {
	a := []SelfAttribConnRow{
		{Proto: "tcp", Local: "10.0.0.1:44444", Remote: "93.0.0.1:443", UID: 10100},
		{Proto: "udp", Local: "10.0.0.1:5353", Remote: "8.8.8.8:53", UID: 10200},
	}
	b := []SelfAttribConnRow{
		{Proto: "udp", Local: "10.0.0.1:5353", Remote: "8.8.8.8:53", UID: 10200},
		{Proto: "tcp", Local: "10.0.0.1:44444", Remote: "93.0.0.1:443", UID: 10100},
	}
	if connsSignature(a) != connsSignature(b) {
		t.Fatal("same conn set in different order must produce the same signature")
	}

	c := append(b[:1:1], SelfAttribConnRow{Proto: "tcp", Local: "10.0.0.2:55555", Remote: "1.1.1.1:443", UID: 10100})
	if connsSignature(a) == connsSignature(c) {
		t.Fatal("different conn sets must produce different signatures")
	}

	// Pkg/State 等非 key 字段不参与签名 (连接集相同即跳过 append 的依据)。
	a[0].Pkg = "com.example.changed"
	if connsSignature(a) != connsSignature(b) {
		t.Fatal("non-key fields must not affect the signature")
	}
}

// v5.12: /proc/net/tcp6 里的 IPv4 映射地址与纯 IPv6 地址, 必须能被抓包侧
// LookupUID(net.IP.String(), port) 命中。
func TestLookupUID_CanonicalKeys(t *testing.T) {
	a := NewSelfAttribAggregator("")
	cases := []struct {
		procHex string // /proc/net/tcp6 remote 字段
		ip      string // 抓包侧 ev.DstIP.String()
	}{
		{"0000000000000000FFFF00000100007F:01BB", "127.0.0.1"},
		{"B80D0120000000000000000001000000:01BB", "2001:db8::1"},
	}
	for i, c := range cases {
		k := canonRemoteKey(parseHexAddr(c.procHex, true))
		if k == "" {
			t.Fatalf("case %d: 规范化失败 %q", i, parseHexAddr(c.procHex, true))
		}
		a.remoteToUID[k] = 10100 + i
	}
	for i, c := range cases {
		uid, _, ok := a.LookupUID(c.ip, 443)
		if !ok || uid != 10100+i {
			t.Errorf("case %d: LookupUID(%s,443) = %d,%v; keys=%v", i, c.ip, uid, ok, a.remoteToUID)
		}
	}
	// IPv4 socket(/proc/net/tcp)也照常命中。
	a.remoteToUID[canonRemoteKey(parseHexAddr("0101A8C0:0050", false))] = 10200
	if uid, _, ok := a.LookupUID("192.168.1.1", 80); !ok || uid != 10200 {
		t.Errorf("IPv4 查找失败: %d %v", uid, ok)
	}
}

func TestLookupFlowUIDSeparatesSharedEndpoints(t *testing.T) {
	a := NewSelfAttribAggregator("")
	rows := []SelfAttribConnRow{
		{Proto: "tcp", Local: "10.0.0.1:41000", Remote: "203.0.113.1:443", UID: 10100},
		{Proto: "tcp", Local: "10.0.0.1:41001", Remote: "203.0.113.1:443", UID: 10200},
		{Proto: "udp", Local: "10.0.0.1:41000", Remote: "203.0.113.1:443", UID: 10300},
		{Proto: "tcp", Local: "10.0.0.2:41000", Remote: "203.0.113.1:443", UID: 10400},
	}
	a.remoteToUID, a.flowToUID = buildSelfUIDIndexes(rows)
	a.pkgCache[10100] = "com.example.first"
	if _, _, ok := a.LookupUID("203.0.113.1", 443); ok {
		t.Fatal("shared endpoint must be unknown to endpoint-only callers")
	}
	for _, tc := range []struct {
		proto, localIP string
		port           uint16
		uid            int
	}{
		{"tcp", "10.0.0.1", 41000, 10100},
		{"tcp", "10.0.0.1", 41001, 10200},
		{"udp", "10.0.0.1", 41000, 10300},
		{"tcp", "10.0.0.2", 41000, 10400},
	} {
		if uid, _, ok := a.LookupFlowUID(tc.proto, tc.localIP, tc.port, "203.0.113.1", 443); !ok || uid != tc.uid {
			t.Errorf("%+v: got uid=%d ok=%v", tc, uid, ok)
		}
	}
	if _, _, ok := a.LookupFlowUID("tcp", "10.0.0.1", 41002, "203.0.113.1", 443); ok {
		t.Fatal("unobserved flow must not fall back to a shared endpoint")
	}
	if _, pkg, _ := a.LookupFlowUID("tcp", "10.0.0.1", 41000, "203.0.113.1", 443); pkg != "com.example.first" {
		t.Fatalf("package=%q", pkg)
	}
	a.SetEnabled(false, "test")
	if _, _, ok := a.LookupFlowUID("tcp", "10.0.0.1", 41000, "203.0.113.1", 443); ok {
		t.Fatal("disabled capture retained a live flow mapping")
	}
}

func TestLookupFlowUIDCanonicalAndConflictingTuples(t *testing.T) {
	a := NewSelfAttribAggregator("")
	rows := []SelfAttribConnRow{
		{Proto: "tcp", Local: "[::ffff:10.0.0.1]:41000", Remote: "[::ffff:203.0.113.1]:443", UID: 10100},
		{Proto: "tcp", Local: "[2001:0db8::1]:41001", Remote: "[2001:db8::2]:443", UID: 10200},
		{Proto: "tcp", Local: "10.0.0.1:41002", Remote: "203.0.113.1:443", UID: 10100},
	}
	a.remoteToUID, a.flowToUID = buildSelfUIDIndexes(rows)
	if uid, _, ok := a.LookupFlowUID("tcp", "10.0.0.1", 41000, "203.0.113.1", 443); !ok || uid != 10100 {
		t.Fatalf("mapped IPv4: uid=%d ok=%v", uid, ok)
	}
	if uid, _, ok := a.LookupFlowUID("tcp", "2001:db8::1", 41001, "2001:0db8::2", 443); !ok || uid != 10200 {
		t.Fatalf("IPv6: uid=%d ok=%v", uid, ok)
	}
	if uid, _, ok := a.LookupUID("203.0.113.1", 443); !ok || uid != 10100 {
		t.Fatalf("same UID across multiple flows is unambiguous: uid=%d ok=%v", uid, ok)
	}
	rows = append(rows, SelfAttribConnRow{Proto: "tcp", Local: "10.0.0.1:41000", Remote: "203.0.113.1:443", UID: 10300})
	a.remoteToUID, a.flowToUID = buildSelfUIDIndexes(rows)
	if _, _, ok := a.LookupFlowUID("tcp", "10.0.0.1", 41000, "203.0.113.1", 443); ok {
		t.Fatal("conflicting exact tuple must remain unknown")
	}
}
