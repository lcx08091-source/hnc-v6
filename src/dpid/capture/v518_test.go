package capture

// v5.18: nDPI 删除后 dpid 需独立覆盖的解析能力 —— DNS(CNAME 链 / 压缩 /
// 截断 / HTTPS 提示 / TCP)、TLS ClientHello(截断容错 / 跨段重组 / ECH /
// IPv6)、明文 HTTP Host、以及畸形包不 panic。

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"
)

var (
	v518Client4 = net.ParseIP("192.168.43.20").To4()
	v518Server4 = net.ParseIP("93.184.216.34").To4()
	v518Client6 = net.ParseIP("2409:8a00:1:2::20")
	v518Server6 = net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")
	v518TS      = time.Unix(1760000000, 0)
)

// ── 构造工具 ─────────────────────────────────────────────────────────────

type tcpOpts struct {
	v6           bool
	src, dst     net.IP
	sport, dport uint16
	seq          uint32
	payload      []byte
	// declared > 0: IP 头声明的载荷长度比实际带的字节多(模拟 snaplen 截断)。
	extraDeclared int
}

// tcpPkt 返回 IP 包(无以太网头)。
func tcpPkt(o tcpOpts) []byte {
	tcp := make([]byte, 20+len(o.payload))
	binary.BigEndian.PutUint16(tcp[0:], o.sport)
	binary.BigEndian.PutUint16(tcp[2:], o.dport)
	binary.BigEndian.PutUint32(tcp[4:], o.seq)
	tcp[12] = 5 << 4
	tcp[13] = 0x18 // PSH|ACK
	copy(tcp[20:], o.payload)
	if o.v6 {
		ip := make([]byte, 40, 40+len(tcp))
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp)+o.extraDeclared))
		ip[6] = 6
		ip[7] = 64
		copy(ip[8:24], o.src.To16())
		copy(ip[24:40], o.dst.To16())
		return append(ip, tcp...)
	}
	ip := make([]byte, 20, 20+len(tcp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)+o.extraDeclared))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], o.src.To4())
	copy(ip[16:20], o.dst.To4())
	return append(ip, tcp...)
}

func v518Ether(ip []byte) []byte {
	return withEther(ip, len(ip) > 0 && ip[0]>>4 == 6)
}

// buildClientHelloRecord 构造完整 TLS record(0x16 0301 len + handshake)。
// exts 按给定顺序排列。
func buildClientHelloRecord(exts ...[]byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, bytes.Repeat([]byte{0x11}, 32)...)
	body = append(body, 32)
	body = append(body, bytes.Repeat([]byte{0x22}, 32)...)                          // session id
	body = append(body, 0x00, 0x08, 0x3a, 0x3a, 0x13, 0x01, 0x13, 0x02, 0xc0, 0x2b) // ciphers(含 GREASE)
	body = append(body, 0x01, 0x00)
	var ext []byte
	for _, e := range exts {
		ext = append(ext, e...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func extSNI(name string) []byte {
	sn := []byte{0}
	sn = binary.BigEndian.AppendUint16(sn, uint16(len(name)))
	sn = append(sn, name...)
	return tlsExt(0x0000, append(binary.BigEndian.AppendUint16(nil, uint16(len(sn))), sn...))
}

func extALPN(protos ...string) []byte {
	var l []byte
	for _, p := range protos {
		l = append(l, byte(len(p)))
		l = append(l, p...)
	}
	return tlsExt(0x0010, append(binary.BigEndian.AppendUint16(nil, uint16(len(l))), l...))
}

var (
	extVersions = tlsExt(0x002b, []byte{0x04, 0x03, 0x04, 0x03, 0x03})
	extSigAlgs  = tlsExt(0x000d, []byte{0x00, 0x04, 0x04, 0x03, 0x08, 0x04})
	// Chrome 带 X25519MLKEM768 的 key_share 约 1.2KB。
	extBigKeyShare = tlsExt(0x0033, append([]byte{0x04, 0xc6, 0x11, 0xec, 0x04, 0xc0}, bytes.Repeat([]byte{0x5a}, 1216)...))
	// BoringSSL 固定的结尾 GREASE 扩展: 类型 xAxA, 长度 1, 内容 0。
	extGreaseTail = tlsExt(0x3a3a, []byte{0x00})
)

// dnsMsg 构造 DNS 响应。answers 为已编码的 RR(可含压缩指针)。
func dnsMsg(qname string, qtype uint16, answers ...[]byte) []byte {
	h := cat(u16(0x1234), u16(0x8180), u16(1), u16(uint16(len(answers))), u16(0), u16(0))
	q := cat(wireName(qname), u16(qtype), u16(1))
	m := cat(h, q)
	for _, a := range answers {
		m = append(m, a...)
	}
	return m
}

func rr(owner []byte, typ uint16, ttl uint32, rdata []byte) []byte {
	return cat(owner, u16(typ), u16(1), u32(ttl), u16(uint16(len(rdata))), rdata)
}

func ptr(off int) []byte { return []byte{0xc0 | byte(off>>8), byte(off)} }

// ── DNS ─────────────────────────────────────────────────────────────────

func TestDNSCNAMEChainCompressedMultiAnswer(t *testing.T) {
	// www.example.com (qname 在偏移 12) → CNAME cdn.provider.net → 两个 A +
	// 一个 AAAA, owner 都用压缩指针指向 CNAME rdata 里的名字。
	qname := "WWW.Example.com"
	base := dnsMsg(qname, 1)
	cnameRROff := len(base)
	cnameRR := rr(ptr(12), 5, 300, wireName("cdn.provider.net"))
	cdnNameOff := cnameRROff + 2 + 10 // owner 指针(2) + type/class/ttl/rdlen(10)
	a1 := rr(ptr(cdnNameOff), 1, 60, []byte{1, 2, 3, 4})
	a2 := rr(ptr(cdnNameOff), 1, 0, []byte{1, 2, 3, 5}) // TTL 0 也要计入最小值
	aaaa := rr(ptr(cdnNameOff), 28, 120, net.ParseIP("2001:db8::1").To16())
	msg := dnsMsg(qname, 1, cnameRR, a1, a2, aaaa)

	d, ok := parseDNS(msg)
	if !ok || !d.IsResponse || d.QName != "www.example.com" {
		t.Fatalf("parse: ok=%v %+v", ok, d)
	}
	if len(d.Records) != 4 {
		t.Fatalf("records=%+v", d.Records)
	}
	if r := d.Records[0]; r.Type != 5 || r.Name != "www.example.com" || r.Value != "cdn.provider.net" {
		t.Errorf("cname rr=%+v", r)
	}
	for _, r := range d.Records[1:] {
		if r.Name != "cdn.provider.net" {
			t.Errorf("addr owner=%q want cdn.provider.net", r.Name)
		}
	}
	if d.Records[3].Value != "2001:db8::1" || d.Records[1].TTL != 60 {
		t.Errorf("records=%+v", d.Records)
	}
	if d.TTL != 0 {
		t.Errorf("min TTL=%d want 0", d.TTL)
	}
	want := []string{"CNAME:cdn.provider.net", "1.2.3.4", "1.2.3.5", "2001:db8::1"}
	if strings.Join(d.Answers, ",") != strings.Join(want, ",") {
		t.Errorf("answers=%v", d.Answers)
	}
}

func TestDNSTruncatedResponseKeepsParsedAnswers(t *testing.T) {
	a1 := rr(ptr(12), 1, 300, []byte{10, 0, 0, 1})
	a2 := rr(ptr(12), 1, 300, []byte{10, 0, 0, 2})
	msg := dnsMsg("a.example.com", 1, a1, a2)
	d, ok := parseDNS(msg[:len(msg)-3]) // 第二条 rdata 被截断
	if !ok || len(d.Records) != 1 || d.Records[0].Value != "10.0.0.1" {
		t.Fatalf("ok=%v records=%+v", ok, d.Records)
	}
}

func TestDNSHTTPSRecordAddrHints(t *testing.T) {
	// HTTPS 1 . alpn=h2,h3 ipv4hint=1.1.1.1,1.0.0.1 ipv6hint=2606:4700::1111
	params := cat(u16(1), u16(6), []byte{2, 'h', '2', 2, 'h', '3'},
		u16(4), u16(8), []byte{1, 1, 1, 1, 1, 0, 0, 1},
		u16(6), u16(16), net.ParseIP("2606:4700::1111").To16())
	rdata := cat(u16(1), []byte{0}, params)
	msg := dnsMsg("cloudflare.com", 65, rr(ptr(12), 65, 200, rdata))
	d, ok := parseDNS(msg)
	if !ok {
		t.Fatal("parse failed")
	}
	var got []string
	for _, r := range d.Records {
		if r.Type != 65 || r.Name != "cloudflare.com" || r.TTL != 200 {
			t.Errorf("rr=%+v", r)
		}
		got = append(got, r.Value)
	}
	if strings.Join(got, ",") != "1.1.1.1,1.0.0.1,2606:4700::1111" {
		t.Errorf("hints=%v", got)
	}
	// AliasMode(priority 0)没有地址; 截断的参数不 panic。
	if h := svcbAddrHints(cat(u16(0), wireName("x.com"))); len(h) != 0 {
		t.Errorf("alias mode hints=%v", h)
	}
	for i := 0; i < len(rdata); i++ {
		_ = svcbAddrHints(rdata[:i])
	}
}

func TestDNSNamePointerLoopsRejected(t *testing.T) {
	m := dnsMsg("a.com", 1)
	// 自指指针与互指指针都必须失败返回, 不能死循环。
	self := append(append([]byte{}, m[:12]...), 0xc0, 12, 0, 1, 0, 1)
	if _, ok := parseDNS(self); ok {
		t.Error("self pointer accepted")
	}
	loop := append(append([]byte{}, m[:12]...), 0xc0, 14, 0xc0, 12, 0, 1, 0, 1)
	if _, ok := parseDNS(loop); ok {
		t.Error("pointer loop accepted")
	}
}

func TestDNSOverTCP(t *testing.T) {
	withHotspot(t)
	msg := dnsMsg("tcp.example.com", 1, rr(ptr(12), 1, 30, []byte{8, 8, 4, 4}))
	pl := append(u16(uint16(len(msg))), msg...)
	pkt := v518Ether(tcpPkt(tcpOpts{src: net.IPv4(1, 1, 1, 1).To4(), dst: v518Client4, sport: 53, dport: 40000, payload: pl}))
	ev, res := parsePacket(pkt, v518TS)
	if res != ParseOK || ev.Kind != EventDNS || ev.DNS.QName != "tcp.example.com" ||
		len(ev.DNS.Records) != 1 || ev.DNS.Records[0].Value != "8.8.4.4" {
		t.Fatalf("res=%v kind=%v dns=%+v", res, ev.Kind, ev.DNS)
	}
	if !ev.ClientIP.Equal(v518Client4) {
		t.Errorf("client=%v", ev.ClientIP)
	}
	// BPF 放行 TCP/53。
	eth, _ := BuildFilter(1024)
	if runCBPF(t, eth, pkt) == 0 {
		t.Error("bpf dropped DNS/TCP")
	}
	// 空段(握手 ACK)与续段: 忽略, 不算解析错误。
	for _, p := range [][]byte{nil, bytes.Repeat([]byte{0xee}, 40)} {
		pkt := v518Ether(tcpPkt(tcpOpts{src: net.IPv4(1, 1, 1, 1).To4(), dst: v518Client4, sport: 53, dport: 40000, payload: p}))
		if _, res := parsePacket(pkt, v518TS); res != ParseIgnore {
			t.Errorf("payload %d bytes: res=%v want ParseIgnore", len(p), res)
		}
	}
	// 长度前缀 < 12: 拒绝。
	if _, ok := parseDNSTCP(append(u16(5), msg...)); ok {
		t.Error("bogus length prefix accepted")
	}
}

// ── TLS ─────────────────────────────────────────────────────────────────

func TestTLSClientHelloIPv6Full(t *testing.T) {
	withHotspot6(t)
	rec := buildClientHelloRecord(tlsExt(0x0a0a, nil), extSNI("Api.Example.COM."), extALPN("h2", "http/1.1"), extVersions, extSigAlgs, extGreaseTail)
	pkt := v518Ether(tcpPkt(tcpOpts{v6: true, src: v518Client6, dst: v518Server6, sport: 50000, dport: 443, payload: rec}))
	ev, res := parsePacket(pkt, v518TS)
	if res != ParseOK || ev.Kind != EventTLSClientHello {
		t.Fatalf("res=%v kind=%v", res, ev.Kind)
	}
	if ev.TLS.SNI != "api.example.com" || len(ev.TLS.ALPN) != 2 || !strings.HasPrefix(ev.TLS.JA4, "t13d") || ev.TLS.Partial {
		t.Errorf("tls=%+v", ev.TLS)
	}
	if ev.RemoteIP.String() != "2606:2800:220:1:248:1893:25c8:1946" || !ev.ClientIP.Equal(v518Client6) {
		t.Errorf("remote=%s client=%s", ev.RemoteIP, ev.ClientIP)
	}
	eth, _ := BuildFilter(1024)
	if got := runCBPF(t, eth, pkt); got != tlsSnaplen {
		t.Errorf("bpf v6 ClientHello snaplen=%d want %d", got, tlsSnaplen)
	}
}

func withHotspot6(t *testing.T) {
	t.Helper()
	_, n4, _ := net.ParseCIDR("192.168.43.0/24")
	_, n6, _ := net.ParseCIDR("2409:8a00:1:2::/64")
	old := hotspotNets
	SetHotspotNets([]*net.IPNet{n4, n6})
	t.Cleanup(func() { hotspotNets = old })
}

func resetTLSAsm(t *testing.T) {
	t.Helper()
	old := tlsAsm
	tlsAsm = newTLSReassembler(tlsAsmMaxEntries, tlsAsmMaxBytes, tlsAsmTTL)
	t.Cleanup(func() { tlsAsm = old })
}

// chromePQHello: key_share(1.2KB)在 SNI 前面, SNI 落在第二个 TCP 段。
func chromePQHello(sni string) []byte {
	return buildClientHelloRecord(tlsExt(0x0a0a, nil), extVersions, extBigKeyShare, extSigAlgs,
		tlsExt(0xfe0d, bytes.Repeat([]byte{0x77}, 200)), // GREASE ECH
		extSNI(sni), extALPN("h2"), extGreaseTail)
}

func TestTLSClientHelloSplitAcrossSegments(t *testing.T) {
	withHotspot(t)
	resetTLSAsm(t)
	rec := chromePQHello("www.youtube.com")
	full, ok := parseTLSClientHelloFull(rec)
	if !ok || full.SNI != "www.youtube.com" || !full.ECH {
		t.Fatalf("reference parse: %+v ok=%v", full, ok)
	}
	const mss = 1400
	seq := uint32(0xfffffe00) // 跨 2^32 回绕
	o1 := tcpOpts{src: v518Client4, dst: v518Server4, sport: 51000, dport: 443, seq: seq, payload: rec[:mss]}
	o2 := o1
	o2.seq, o2.payload = seq+mss, rec[mss:]
	p1, p2 := v518Ether(tcpPkt(o1)), v518Ether(tcpPkt(o2))

	// BPF: 首段按 tlsSnaplen 放行; 末段靠 GREASE 结尾特征放行; 普通上行数据丢弃。
	eth, _ := BuildFilter(1024)
	raw, _ := BuildFilterRawIP(1024)
	if runCBPF(t, eth, p1) != tlsSnaplen || runCBPF(t, raw, tcpPkt(o1)) != tlsSnaplen {
		t.Error("first segment not accepted with tlsSnaplen")
	}
	if runCBPF(t, eth, p2) != tlsSnaplen || runCBPF(t, raw, tcpPkt(o2)) != tlsSnaplen {
		t.Error("tail segment not accepted")
	}
	o3 := o2
	o3.payload = bytes.Repeat([]byte{0x17, 0x03, 0x03, 0x01}, 100)
	if runCBPF(t, eth, v518Ether(tcpPkt(o3))) != 0 || runCBPF(t, raw, tcpPkt(o3)) != 0 {
		t.Error("ordinary uplink segment accepted")
	}
	// 以太网最小帧填充不影响末尾判断(用 IP 长度字段)。
	padded := append(append([]byte{}, p2...), 0, 0, 0, 0)
	if runCBPF(t, eth, padded) != tlsSnaplen {
		t.Error("tail segment with ether padding not accepted")
	}

	// 用户态: 首段 SNI 不在其中 → 挂起(按旧口径记 Flow), 末段接上 → 完整事件。
	ev, res := parsePacket(p1, v518TS)
	if res != ParseOK || ev.Kind != EventFlow {
		t.Fatalf("first seg: res=%v kind=%v", res, ev.Kind)
	}
	if tlsAsm.len() != 1 {
		t.Fatalf("pending=%d", tlsAsm.len())
	}
	ev, res = parsePacket(p2, v518TS.Add(time.Millisecond))
	if res != ParseOK || ev.Kind != EventTLSClientHello {
		t.Fatalf("tail seg: res=%v kind=%v", res, ev.Kind)
	}
	if ev.TLS.SNI != "www.youtube.com" || ev.TLS.JA4 != full.JA4 || !ev.TLS.Reassembled || !ev.TLS.ECH {
		t.Errorf("tls=%+v want JA4 %s", ev.TLS, full.JA4)
	}
	if tlsAsm.len() != 0 {
		t.Errorf("entry not released: %d", tlsAsm.len())
	}
	// 同一末段重放: 没有挂起条目, 忽略。
	if _, res := parsePacket(p2, v518TS.Add(2*time.Millisecond)); res != ParseIgnore {
		t.Errorf("replayed tail res=%v", res)
	}
}

func TestTLSClientHelloThreeSegmentsWithRetransmit(t *testing.T) {
	withHotspot(t)
	resetTLSAsm(t)
	rec := chromePQHello("three.example.org")
	o := tcpOpts{src: v518Client4, dst: v518Server4, sport: 51001, dport: 443, seq: 1000}
	segs := [][2]int{{0, 600}, {600, 1200}, {1200, len(rec)}}
	var last Event
	for i, s := range segs {
		oo := o
		oo.seq, oo.payload = 1000+uint32(s[0]), rec[s[0]:s[1]]
		ev, _ := parsePacket(v518Ether(tcpPkt(oo)), v518TS)
		if i == 1 {
			// 重传第二段(完全落在已收范围内)不应打断重组。
			_, _ = parsePacket(v518Ether(tcpPkt(oo)), v518TS)
		}
		last = ev
	}
	if last.Kind != EventTLSClientHello || last.TLS.SNI != "three.example.org" {
		t.Fatalf("kind=%v tls=%+v", last.Kind, last.TLS)
	}
}

func TestTLSReassemblyGapGivesUp(t *testing.T) {
	withHotspot(t)
	resetTLSAsm(t)
	rec := chromePQHello("gap.example.org")
	o1 := tcpOpts{src: v518Client4, dst: v518Server4, sport: 51002, dport: 443, seq: 5000, payload: rec[:700]}
	o3 := o1
	o3.seq, o3.payload = 5000+1400, rec[1400:] // 中间段丢失
	parsePacket(v518Ether(tcpPkt(o1)), v518TS)
	ev, res := parsePacket(v518Ether(tcpPkt(o3)), v518TS)
	if res != ParseIgnore || ev.Kind == EventTLSClientHello {
		t.Fatalf("gap: res=%v kind=%v", res, ev.Kind)
	}
	if tlsAsm.len() != 0 {
		t.Error("entry should be dropped after gap")
	}
	// 过期: 末段 TTL 之后才到, 放弃。
	parsePacket(v518Ether(tcpPkt(o1)), v518TS)
	o2 := o1
	o2.seq, o2.payload = 5700, rec[700:]
	if ev, _ := parsePacket(v518Ether(tcpPkt(o2)), v518TS.Add(tlsAsmTTL+time.Second)); ev.Kind == EventTLSClientHello {
		t.Error("expired entry completed")
	}
}

func TestTLSPartialSNIFromTruncatedFirstSegment(t *testing.T) {
	withHotspot(t)
	resetTLSAsm(t)
	// Firefox/Safari 风格: SNI 在最前, key_share 大 —— 首段(甚至被 snaplen
	// 截断的首段)里就能拿到 SNI。
	rec := buildClientHelloRecord(extSNI("mail.example.net"), extALPN("h2"), extVersions, extBigKeyShare, extSigAlgs)
	o := tcpOpts{src: v518Client4, dst: v518Server4, sport: 51003, dport: 443, seq: 1, payload: rec[:900], extraDeclared: 500}
	ev, res := parsePacket(v518Ether(tcpPkt(o)), v518TS)
	if res != ParseOK || ev.Kind != EventTLSClientHello || ev.TLS.SNI != "mail.example.net" || !ev.TLS.Partial || ev.TLS.JA4 != "" {
		t.Fatalf("res=%v kind=%v tls=%+v", res, ev.Kind, ev.TLS)
	}
	if tlsAsm.len() != 0 {
		t.Error("partial-SNI hello must not be queued")
	}
	// snaplen 截断且 SNI 不在已抓部分: 不挂起(后面缺字节, 永远接不上)。
	rec2 := chromePQHello("x.example.net")
	o.payload, o.sport = rec2[:900], 51004
	if ev, _ := parsePacket(v518Ether(tcpPkt(o)), v518TS); ev.Kind == EventTLSClientHello || tlsAsm.len() != 0 {
		t.Errorf("kind=%v pending=%d", ev.Kind, tlsAsm.len())
	}
}

func TestTLSReassemblerBounded(t *testing.T) {
	r := newTLSReassembler(8, tlsAsmMaxBytes, tlsAsmTTL)
	rec := chromePQHello("bound.example.com")
	for i := 0; i < 100; i++ {
		ev := Event{SrcIP: v518Client4, DstIP: v518Server4, SrcPort: uint16(20000 + i), DstPort: 443}
		r.handleSegment(&ev, 1, rec[:600], v518TS)
		if r.len() > 8 {
			t.Fatalf("len=%d > cap", r.len())
		}
	}
	// 声明长度超过上限的 ClientHello 不挂起。
	huge := append([]byte{}, rec[:600]...)
	binary.BigEndian.PutUint16(huge[3:5], 0xffff)
	huge[6], huge[7], huge[8] = 0x00, 0xff, 0xfb
	r2 := newTLSReassembler(8, 4096, tlsAsmTTL)
	ev := Event{SrcIP: v518Client4, DstIP: v518Server4, SrcPort: 1, DstPort: 443}
	r2.handleSegment(&ev, 1, huge, v518TS)
	if r2.len() != 0 {
		t.Error("oversize hello queued")
	}
}

func TestTLSECHAndSNISanitize(t *testing.T) {
	rec := buildClientHelloRecord(extSNI("cloudflare-ech.com"), tlsExt(0xfe0d, []byte{0, 1, 2, 3}), extVersions)
	info, ok := parseTLSClientHelloFull(rec)
	if !ok || !info.ECH || info.SNI != "cloudflare-ech.com" {
		t.Errorf("ech: %+v ok=%v", info, ok)
	}
	// 旧 ESNI 草案: 没有 SNI, 仍产出事件(标记 ECH)以便统计 JA4。
	rec = buildClientHelloRecord(tlsExt(0xffce, []byte{1, 2, 3}), extVersions)
	if info, ok := parseTLSClientHelloFull(rec); !ok || !info.ECH || info.SNI != "" {
		t.Errorf("esni: %+v ok=%v", info, ok)
	}
	// 非法 SNI 字符被丢弃。
	for _, bad := range []string{"evil\"host.com", "a b.com", "x\x00y.com", strings.Repeat("a", 300)} {
		rec = buildClientHelloRecord(extSNI(bad), extALPN("h2"))
		if info, _ := parseTLSClientHelloFull(rec); info.SNI != "" {
			t.Errorf("bad SNI %q kept as %q", bad, info.SNI)
		}
	}
}

// ── HTTP ────────────────────────────────────────────────────────────────

func TestHTTPHostParse(t *testing.T) {
	cases := []struct {
		in, host, ua string
		ok           bool
	}{
		{"GET /x HTTP/1.1\r\nHost: WWW.Example.com:8080\r\nUser-Agent: curl/8\r\n\r\n", "www.example.com", "curl/8", true},
		{"POST /api HTTP/1.1\r\nhost:api.qq.com.\r\n\r\nbody", "api.qq.com", "", true},
		{"HEAD / HTTP/1.0\nHost: a.b.c\n\n", "a.b.c", "", true},
		{"GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n", "", "", false},          // IP 字面量
		{"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n", "", "", false}, // IPv6 字面量
		{"GET / HTTP/1.1\r\nHost: bad host\r\n\r\n", "", "", false},
		{"GET / HTTP/1.1\r\nAccept: */*\r\n\r\nHost: late.com\r\n", "", "", false}, // 头部结束后的不算
		{"GET / HTTP/1.1\r\nHost: trunc", "", "", false},                           // 截断
		{"HTTP/1.1 200 OK\r\nHost: x.com\r\n\r\n", "", "", false},                  // 响应
		{"GETX / HTTP/1.1\r\nHost: x.com\r\n\r\n", "", "", false},
		{"GET / SPDY/3\r\nHost: x.com\r\n\r\n", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		h, ua, ok := parseHTTPRequestHost([]byte(c.in))
		if h != c.host || ua != c.ua || ok != c.ok {
			t.Errorf("%q → (%q,%q,%v) want (%q,%q,%v)", c.in, h, ua, ok, c.host, c.ua, c.ok)
		}
	}
}

func TestHTTPHostPacketAndBPF(t *testing.T) {
	withHotspot(t)
	req := []byte("GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\nUser-Agent: Dalvik/2.1.0\r\n\r\n")
	o := tcpOpts{src: v518Client4, dst: v518Server4, sport: 40100, dport: 80, payload: req}
	pkt := v518Ether(tcpPkt(o))
	ev, res := parsePacket(pkt, v518TS)
	if res != ParseOK || ev.Kind != EventHTTP || ev.TLS.SNI != "connectivitycheck.gstatic.com" || ev.TLS.UserAgent != "Dalvik/2.1.0" {
		t.Fatalf("res=%v kind=%v tls=%+v", res, ev.Kind, ev.TLS)
	}
	if !ev.RemoteIP.Equal(v518Server4) {
		t.Errorf("remote=%v", ev.RemoteIP)
	}
	eth, _ := BuildFilter(1024)
	raw, _ := BuildFilterRawIP(1024)
	for _, m := range []string{"GET ", "POST", "HEAD", "PUT ", "OPTIONS", "DELETE", "PATCH"} {
		o.payload = []byte(m + " / HTTP/1.1\r\n")
		if runCBPF(t, eth, v518Ether(tcpPkt(o))) != tlsSnaplen || runCBPF(t, raw, tcpPkt(o)) != tlsSnaplen {
			t.Errorf("bpf dropped HTTP %s", m)
		}
		o6 := o
		o6.v6, o6.src, o6.dst = true, v518Client6, v518Server6
		if runCBPF(t, eth, v518Ether(tcpPkt(o6))) != tlsSnaplen || runCBPF(t, raw, tcpPkt(o6)) != tlsSnaplen {
			t.Errorf("bpf v6 dropped HTTP %s", m)
		}
	}
	// 非请求的 80 端口数据 / 服务器响应 / 其他端口: 丢弃。
	for _, d := range []tcpOpts{
		{src: v518Client4, dst: v518Server4, sport: 40100, dport: 80, payload: []byte("\x00\x01binary")},
		{src: v518Server4, dst: v518Client4, sport: 80, dport: 40100, payload: []byte("HTTP/1.1 200 OK\r\n")},
		{src: v518Client4, dst: v518Server4, sport: 40100, dport: 8081, payload: []byte("GET / HTTP/1.1\r\n")},
	} {
		if runCBPF(t, eth, v518Ether(tcpPkt(d))) != 0 {
			t.Errorf("bpf accepted %q sport=%d dport=%d", d.payload, d.sport, d.dport)
		}
	}
	// 解析不出 Host 的请求: 忽略, 不产生 Flow。
	o.payload = []byte("GET / HTTP/1.1\r\n\r\n")
	if _, res := parsePacket(v518Ether(tcpPkt(o)), v518TS); res != ParseIgnore {
		t.Errorf("hostless request res=%v", res)
	}
}

// ── 健壮性 ───────────────────────────────────────────────────────────────

// TestParseGarbageNoPanic: 合法包的每个前缀 + 随机字节翻转 + 纯随机数据,
// 两种链路层解析器都不能 panic(Run 里虽有 recover, 但 panic 会丢掉该包并
// 计入 Panics)。
func TestParseGarbageNoPanic(t *testing.T) {
	resetTLSAsm(t)
	withHotspot6(t)
	rec := chromePQHello("fuzz.example.com")
	dns := dnsMsg("f.example.com", 1, rr(ptr(12), 5, 1, wireName("g.example.net")), rr(ptr(12), 1, 1, []byte{1, 2, 3, 4}))
	seeds := [][]byte{
		tcpPkt(tcpOpts{src: v518Client4, dst: v518Server4, sport: 1, dport: 443, payload: rec[:1400]}),
		tcpPkt(tcpOpts{src: v518Client4, dst: v518Server4, sport: 1, dport: 443, seq: 1400, payload: rec[1400:]}),
		tcpPkt(tcpOpts{v6: true, src: v518Client6, dst: v518Server6, sport: 2, dport: 443, payload: rec}),
		tcpPkt(tcpOpts{src: v518Client4, dst: v518Server4, sport: 3, dport: 80, payload: []byte("GET / HTTP/1.1\r\nHost: a.com\r\n\r\n")}),
		tcpPkt(tcpOpts{src: v518Server4, dst: v518Client4, sport: 53, dport: 4, payload: append(u16(uint16(len(dns))), dns...)}),
		udp4(53, 40000, dns),
	}
	rng := rand.New(rand.NewSource(518))
	check := func(b []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on %x: %v", b, r)
			}
		}()
		parseRawIPPacket(b, v518TS)
		parsePacket(v518Ether(b), v518TS)
		parseDNS(b)
		parseDNSTCP(b)
		parseClientHello(b, true)
		parseClientHello(b, false)
		parseHTTPRequestHost(b)
		svcbAddrHints(b)
	}
	for _, s := range seeds {
		for i := 0; i <= len(s); i++ {
			check(s[:i])
		}
		for n := 0; n < 300; n++ {
			m := append([]byte{}, s...)
			for k := 0; k < 1+rng.Intn(6); k++ {
				m[rng.Intn(len(m))] = byte(rng.Intn(256))
			}
			check(m)
		}
	}
	for n := 0; n < 2000; n++ {
		b := make([]byte, rng.Intn(1600))
		rng.Read(b)
		if len(b) > 0 {
			b[0] = []byte{0x45, 0x60}[n%2]
		}
		check(b)
	}
	// ClientHello 内部长度字段全部篡改。
	for i := 0; i < len(rec) && i < 200; i++ {
		for _, v := range []byte{0x00, 0x7f, 0xff} {
			m := append([]byte{}, rec...)
			m[i] = v
			check(m)
		}
	}
}

func FuzzParsePacketV518(f *testing.F) {
	rec := chromePQHello("f.example.com")
	f.Add(tcpPkt(tcpOpts{src: v518Client4, dst: v518Server4, sport: 1, dport: 443, payload: rec[:1400]}))
	f.Add(tcpPkt(tcpOpts{src: v518Client4, dst: v518Server4, sport: 3, dport: 80, payload: []byte("GET / HTTP/1.1\r\nHost: a.com\r\n\r\n")}))
	f.Add(udp4(53, 1, dnsMsg("a.com", 1, rr(ptr(12), 1, 1, []byte{1, 2, 3, 4}))))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseRawIPPacket(b, v518TS)
		parseClientHello(b, true)
		parseHTTPRequestHost(b)
	})
}
