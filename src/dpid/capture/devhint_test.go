package capture

import (
	"encoding/binary"
	"math/rand"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ─── 报文构造工具 ──────────────────────────────────────────────────────

func wireName(name string) []byte {
	var out []byte
	for _, l := range strings.Split(name, ".") {
		if l == "" {
			continue
		}
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return append(out, 0)
}

func u16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func u32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ipv4UDP 构造 以太网 + IPv4 + UDP 帧。
func ipv4UDP(srcMAC []byte, src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	ip := make([]byte, 20+8+len(payload))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	binary.BigEndian.PutUint16(ip[20:], sport)
	binary.BigEndian.PutUint16(ip[22:], dport)
	binary.BigEndian.PutUint16(ip[24:], uint16(8+len(payload)))
	copy(ip[28:], payload)
	eth := cat([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, srcMAC, u16(0x0800))
	return cat(eth, ip)
}

func ipv6UDP(srcMAC []byte, src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	ip := make([]byte, 40+8+len(payload))
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(8+len(payload)))
	ip[6] = 17
	ip[7] = 1
	copy(ip[8:24], src.To16())
	copy(ip[24:40], dst.To16())
	binary.BigEndian.PutUint16(ip[40:], sport)
	binary.BigEndian.PutUint16(ip[42:], dport)
	binary.BigEndian.PutUint16(ip[44:], uint16(8+len(payload)))
	copy(ip[48:], payload)
	eth := cat([]byte{0x33, 0x33, 0x00, 0x01, 0x00, 0x02}, srcMAC, u16(0x86dd))
	return cat(eth, ip)
}

var clientMAC = []byte{0x3c, 0x22, 0xfb, 0x11, 0x22, 0x33}

// DHCP DISCOVER: chaddr=3c:22:fb:11:22:33, opt53=1, opt61, opt55(Android 典型),
// opt57, opt60=android-dhcp-14, opt12=Redmi-Note-12, end。
func dhcpDiscover() []byte {
	bootp := make([]byte, 236)
	bootp[0] = 1 // BOOTREQUEST
	bootp[1] = 1 // htype ethernet
	bootp[2] = 6 // hlen
	copy(bootp[4:8], []byte{0xde, 0xad, 0xbe, 0xef})
	copy(bootp[28:34], clientMAC)
	opts := cat(
		u32(dhcpMagic),
		[]byte{53, 1, 1},
		[]byte{61, 7, 1}, clientMAC,
		[]byte{55, 12, 1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114, 108},
		[]byte{57, 2, 0x05, 0xdc},
		[]byte{60, 15}, []byte("android-dhcp-14"),
		[]byte{12, 13}, []byte("Redmi-Note-12"),
		[]byte{255},
	)
	payload := cat(bootp, opts)
	return ipv4UDP(clientMAC, net.IPv4zero, net.IPv4bcast, 68, 67, payload)
}

// mDNS 响应: AirPlay PTR + _device-info TXT(model=MacBookPro18,1, osxvers=21)
// + A 记录 MacBook-Pro.local, 含压缩指针。
func mdnsResponse() []byte {
	hdr := cat(u16(0), u16(0x8400), u16(0), u16(4), u16(0), u16(0))
	// RR1: _airplay._tcp.local PTR MacBook Pro._airplay._tcp.local
	rr1Name := wireName("_airplay._tcp.local")
	off1 := 12         // rr1 owner 在报文中的偏移
	inst := []byte{11} // "MacBook Pro" 标签
	inst = append(inst, "MacBook Pro"...)
	inst = append(inst, 0xc0|byte(off1>>8), byte(off1)) // 指针 → _airplay._tcp.local
	rr1 := cat(rr1Name, u16(12), u16(1), u32(4500), u16(uint16(len(inst))), inst)
	// RR2: MacBook Pro._device-info._tcp.local TXT
	txt := cat([]byte{20}, []byte("model=MacBookPro18,1"), []byte{10}, []byte("osxvers=21"))
	rr2 := cat(wireName("MacBook Pro._device-info._tcp.local"), u16(16), u16(1), u32(4500), u16(uint16(len(txt))), txt)
	// RR3: _services._dns-sd._udp.local PTR _companion-link._tcp.local
	target := wireName("_companion-link._tcp.local")
	rr3 := cat(wireName("_services._dns-sd._udp.local"), u16(12), u16(1), u32(4500), u16(uint16(len(target))), target)
	// RR4: MacBook-Pro.local A 192.168.43.10 (cache-flush 位置位)
	rr4 := cat(wireName("MacBook-Pro.local"), u16(1), u16(0x8001), u32(120), u16(4), []byte{192, 168, 43, 10})
	payload := cat(hdr, rr1, rr2, rr3, rr4)
	return ipv4UDP(clientMAC, net.IPv4(192, 168, 43, 10), net.IPv4(224, 0, 0, 251), 5353, 5353, payload)
}

func ssdpNotify() []byte {
	msg := "NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"LOCATION: http://192.168.43.20:49152/description.xml\r\n" +
		"NT: upnp:rootdevice\r\n" +
		"NTS: ssdp:alive\r\n" +
		"Server: Linux/4.9 UPnP/1.0 MiTV/2.0\r\n" +
		"USN: uuid:abcd::upnp:rootdevice\r\n\r\n"
	return ipv4UDP(clientMAC, net.IPv4(192, 168, 43, 20), net.IPv4(239, 255, 255, 250), 40000, 1900, []byte(msg))
}

// DHCPv6 SOLICIT: opt1 client-id(DUID-LL), opt39 FQDN(android-5f3a2b), opt16
// vendor class(enterprise 311, "MSFT 5.0"), opt6 ORO。
func dhcpv6Solicit() []byte {
	duid := cat(u16(3), u16(1), clientMAC)
	fqdn := cat([]byte{0x01}, wireName("android-5f3a2b.lan"))
	vc := cat(u32(311), u16(8), []byte("MSFT 5.0"))
	oro := cat(u16(23), u16(24))
	msg := cat(
		[]byte{1, 0x12, 0x34, 0x56},
		u16(1), u16(uint16(len(duid))), duid,
		u16(39), u16(uint16(len(fqdn))), fqdn,
		u16(16), u16(uint16(len(vc))), vc,
		u16(6), u16(uint16(len(oro))), oro,
	)
	src := net.ParseIP("fe80::3e22:fbff:fe11:2233")
	dst := net.ParseIP("ff02::1:2")
	return ipv6UDP(clientMAC, src, dst, 546, 547, msg)
}

func nbEncode(name string, suffix byte) []byte {
	var raw [16]byte
	for i := range raw {
		raw[i] = ' '
	}
	copy(raw[:15], strings.ToUpper(name))
	raw[15] = suffix
	enc := make([]byte, 0, 34)
	enc = append(enc, 32)
	for _, c := range raw {
		enc = append(enc, 'A'+(c>>4), 'A'+(c&0x0f))
	}
	return append(enc, 0)
}

// NBNS 名字注册请求(广播): DESKTOP-AB12CD<00>, 附加记录用指针指回问题名。
func nbnsRegistration(name string, group bool) []byte {
	flags := uint16(5<<11) | 0x0110 // opcode=5, RD, B
	hdr := cat(u16(0x1234), u16(flags), u16(1), u16(0), u16(0), u16(1))
	q := cat(nbEncode(name, 0x00), u16(0x20), u16(1))
	nbf := uint16(0)
	if group {
		nbf = 0x8000
	}
	rr := cat([]byte{0xc0, 0x0c}, u16(0x20), u16(1), u32(300000), u16(6), u16(nbf), []byte{192, 168, 43, 30})
	return ipv4UDP(clientMAC, net.IPv4(192, 168, 43, 30), net.IPv4(192, 168, 43, 255), 137, 137, cat(hdr, q, rr))
}

func withHotspot(t *testing.T) {
	t.Helper()
	_, n, _ := net.ParseCIDR("192.168.43.0/24")
	old := hotspotNets
	SetHotspotNets([]*net.IPNet{n})
	t.Cleanup(func() { hotspotNets = old })
}

// ─── 用例 ──────────────────────────────────────────────────────────────

func mustHint(t *testing.T, pkt []byte) *DevHint {
	t.Helper()
	ev, res := parsePacket(pkt, time.Unix(1700000000, 0))
	if res != ParseOK {
		t.Fatalf("parse result=%v, want OK", res)
	}
	if ev.Kind != EventDevHint || ev.Dev == nil {
		t.Fatalf("kind=%v dev=%v, want EventDevHint", ev.Kind, ev.Dev)
	}
	if ev.ClientIP != nil || ev.RemoteIP != nil {
		t.Fatalf("DevHint 不应做 assignClient: client=%v remote=%v", ev.ClientIP, ev.RemoteIP)
	}
	return ev.Dev
}

func TestParseDHCPDiscover(t *testing.T) {
	h := mustHint(t, dhcpDiscover())
	want := &DevHint{
		MAC: "3c:22:fb:11:22:33", Source: "dhcp", Hostname: "Redmi-Note-12",
		VendorClass: "android-dhcp-14", ParamList: "1,3,6,15,26,28,51,58,59,43,114,108",
	}
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("got %+v\nwant %+v", h, want)
	}
}

func TestParseDHCPIgnoresServerReplyAndRelease(t *testing.T) {
	pkt := dhcpDiscover()
	// 改成 RELEASE(7): opt53 值在 以太网14 + IP20 + UDP8 + BOOTP236 + magic4 + 2
	pkt[14+20+8+236+4+2] = 7
	if _, res := parsePacket(pkt, time.Now()); res != ParseIgnore {
		t.Fatalf("release: res=%v want Ignore", res)
	}
	// 服务器应答方向 67→68
	reply := dhcpDiscover()
	binary.BigEndian.PutUint16(reply[14+20:], 67)
	binary.BigEndian.PutUint16(reply[14+22:], 68)
	if ev, res := parsePacket(reply, time.Now()); res != ParseIgnore || ev.Kind == EventFlow {
		t.Fatalf("reply: res=%v kind=%v", res, ev.Kind)
	}
}

func TestParseDHCPOpt81FQDN(t *testing.T) {
	bootp := make([]byte, 236)
	bootp[0], bootp[1], bootp[2] = 1, 1, 6
	copy(bootp[28:34], clientMAC)
	fq := cat([]byte{0x04, 0, 0}, wireName("Johns-MBP.lan"))
	opts := cat(u32(dhcpMagic), []byte{53, 1, 3}, []byte{81, byte(len(fq))}, fq, []byte{255})
	pkt := ipv4UDP(clientMAC, net.IPv4zero, net.IPv4bcast, 68, 67, cat(bootp, opts))
	h := mustHint(t, pkt)
	if h.Hostname != "Johns-MBP" {
		t.Fatalf("hostname=%q", h.Hostname)
	}
}

func TestParseMDNSResponse(t *testing.T) {
	withHotspot(t)
	h := mustHint(t, mdnsResponse())
	if h.Source != "mdns" || h.MAC != "3c:22:fb:11:22:33" {
		t.Fatalf("src/mac: %+v", h)
	}
	if h.Hostname != "MacBook-Pro" {
		t.Errorf("hostname=%q", h.Hostname)
	}
	if h.Model != "MacBookPro18,1" {
		t.Errorf("model=%q", h.Model)
	}
	if h.OSHint != "macOS" {
		t.Errorf("oshint=%q", h.OSHint)
	}
	wantSvc := []string{"_airplay._tcp", "_device-info._tcp", "_companion-link._tcp"}
	if !reflect.DeepEqual(h.Services, wantSvc) {
		t.Errorf("services=%v want %v", h.Services, wantSvc)
	}
}

func TestParseMDNSQueryIgnoredAndForeignIP(t *testing.T) {
	withHotspot(t)
	q := mdnsResponse()
	// flags 改成查询
	binary.BigEndian.PutUint16(q[14+28+2:], 0)
	if _, res := parsePacket(q, time.Now()); res != ParseIgnore {
		t.Fatalf("query res=%v", res)
	}
	// 源 IP 不在热点网段 → 忽略
	payload := mdnsResponse()[14+28:]
	pkt := ipv4UDP(clientMAC, net.IPv4(10, 0, 0, 5), net.IPv4(224, 0, 0, 251), 5353, 5353, payload)
	if _, res := parsePacket(pkt, time.Now()); res != ParseIgnore {
		t.Fatalf("foreign res=%v", res)
	}
	// 本机 MAC → 忽略
	SetLocalMACs([]net.HardwareAddr{net.HardwareAddr(clientMAC)})
	defer SetLocalMACs(nil)
	if _, res := parsePacket(mdnsResponse(), time.Now()); res != ParseIgnore {
		t.Fatalf("local mac res=%v", res)
	}
}

func TestParseMDNSGooglecastMD(t *testing.T) {
	withHotspot(t)
	txt := cat([]byte{16}, []byte("md=Chromecast HD"), []byte{6}, []byte("fn=Den"))
	rr := cat(wireName("Chromecast-HD-abc._googlecast._tcp.local"), u16(16), u16(0x8001), u32(4500), u16(uint16(len(txt))), txt)
	payload := cat(u16(0), u16(0x8400), u16(0), u16(1), u16(0), u16(0), rr)
	pkt := ipv4UDP(clientMAC, net.IPv4(192, 168, 43, 40), net.IPv4(224, 0, 0, 251), 5353, 5353, payload)
	h := mustHint(t, pkt)
	if h.Model != "Chromecast HD" || !reflect.DeepEqual(h.Services, []string{"_googlecast._tcp"}) {
		t.Fatalf("%+v", h)
	}
}

func TestParseSSDPNotify(t *testing.T) {
	withHotspot(t)
	h := mustHint(t, ssdpNotify())
	if h.Source != "ssdp" || h.UserAgent != "Linux/4.9 UPnP/1.0 MiTV/2.0" {
		t.Fatalf("%+v", h)
	}
}

func TestParseSSDPMSearchUserAgent(t *testing.T) {
	withHotspot(t)
	msg := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\nUSER-AGENT: Android/14 UPnP/1.1 Test/1.0\r\n\r\n"
	pkt := ipv4UDP(clientMAC, net.IPv4(192, 168, 43, 10), net.IPv4(239, 255, 255, 250), 50000, 1900, []byte(msg))
	h := mustHint(t, pkt)
	if h.UserAgent != "Android/14 UPnP/1.1 Test/1.0" {
		t.Fatalf("%+v", h)
	}
	junk := ipv4UDP(clientMAC, net.IPv4(192, 168, 43, 10), net.IPv4(239, 255, 255, 250), 50000, 1900, []byte("GARBAGE\r\n\r\n"))
	if ev, res := parsePacket(junk, time.Now()); res != ParseMalformed || ev.Kind == EventFlow {
		t.Fatalf("junk res=%v kind=%v", res, ev.Kind)
	}
}

func TestParseDHCPv6Solicit(t *testing.T) {
	h := mustHint(t, dhcpv6Solicit())
	want := &DevHint{MAC: "3c:22:fb:11:22:33", Source: "dhcpv6", Hostname: "android-5f3a2b", VendorClass: "MSFT 5.0"}
	if !reflect.DeepEqual(h, want) {
		t.Fatalf("got %+v want %+v", h, want)
	}
	// 服务器→客户端(ADVERTISE, 547→546)忽略
	adv := dhcpv6Solicit()
	binary.BigEndian.PutUint16(adv[14+40:], 547)
	binary.BigEndian.PutUint16(adv[14+42:], 546)
	if _, res := parsePacket(adv, time.Now()); res != ParseIgnore {
		t.Fatalf("advertise res=%v", res)
	}
}

func TestParseNBNSRegistration(t *testing.T) {
	withHotspot(t)
	h := mustHint(t, nbnsRegistration("DESKTOP-AB12CD", false))
	if h.Source != "nbns" || h.Hostname != "DESKTOP-AB12CD" {
		t.Fatalf("%+v", h)
	}
	// 组名(WORKGROUP, G 位)忽略
	if _, res := parsePacket(nbnsRegistration("WORKGROUP", true), time.Now()); res != ParseIgnore {
		t.Fatalf("group res=%v", res)
	}
}

func TestParseNBNSQueryIgnored(t *testing.T) {
	withHotspot(t)
	hdr := cat(u16(1), u16(0x0110), u16(1), u16(0), u16(0), u16(0))
	q := cat(nbEncode("WPAD", 0x00), u16(0x20), u16(1))
	pkt := ipv4UDP(clientMAC, net.IPv4(192, 168, 43, 30), net.IPv4(192, 168, 43, 255), 137, 137, cat(hdr, q))
	if _, res := parsePacket(pkt, time.Now()); res != ParseIgnore {
		t.Fatalf("query res=%v", res)
	}
}

// 非设备识别端口的 UDP 行为不变: 仍是 EventFlow。
func TestNonHintUDPStillFlow(t *testing.T) {
	pkt := ipv4UDP(clientMAC, net.IPv4(192, 168, 43, 10), net.IPv4(1, 1, 1, 1), 40000, 443, []byte{1, 2, 3})
	ev, res := parsePacket(pkt, time.Now())
	if res != ParseOK || ev.Kind != EventFlow || ev.Dev != nil {
		t.Fatalf("res=%v kind=%v", res, ev.Kind)
	}
}

// fuzz 风格: 每个样例报文逐字节截断 + 随机翻转若干字节, 解析绝不能 panic,
// 设备识别端口的包也绝不能变成 EventFlow。
func TestDevHintTruncationNoPanic(t *testing.T) {
	withHotspot(t)
	samples := map[string][]byte{
		"dhcp":   dhcpDiscover(),
		"mdns":   mdnsResponse(),
		"ssdp":   ssdpNotify(),
		"dhcpv6": dhcpv6Solicit(),
		"nbns":   nbnsRegistration("DESKTOP-AB12CD", false),
	}
	check := func(name string, pkt []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("%s: panic on %x: %v", name, pkt, r)
			}
		}()
		ev, res := parsePacket(pkt, time.Now())
		if res == ParseOK && ev.Kind == EventFlow {
			t.Fatalf("%s: device-hint packet became EventFlow", name)
		}
		if res == ParseOK && ev.Kind == EventDevHint && ev.Dev == nil {
			t.Fatalf("%s: DevHint nil", name)
		}
	}
	rng := rand.New(rand.NewSource(42))
	for name, full := range samples {
		// 截断整帧: 覆盖 L2/L3/L4/应用层每个边界。
		for n := 0; n <= len(full); n++ {
			check(name, append([]byte(nil), full[:n]...))
		}
		// 只截断应用层载荷但保留 IP/UDP 长度字段为原值(模拟 snaplen 截断)。
		for i := 0; i < 3000; i++ {
			pkt := append([]byte(nil), full...)
			flips := 1 + rng.Intn(6)
			for j := 0; j < flips; j++ {
				// 只翻转 L4 载荷区, 保证能走到设备识别解析器
				hdr := 14 + 28
				if name == "dhcpv6" {
					hdr = 14 + 48
				}
				pos := hdr + rng.Intn(len(pkt)-hdr)
				pkt[pos] = byte(rng.Intn(256))
			}
			if rng.Intn(2) == 0 {
				pkt = pkt[:14+28+rng.Intn(len(pkt)-14-28+1)]
			}
			check(name, pkt)
		}
	}
	// 直接对各解析器喂随机字节。
	for i := 0; i < 5000; i++ {
		b := make([]byte, rng.Intn(300))
		rng.Read(b)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on random %x: %v", b, r)
				}
			}()
			parseDHCPv4(b)
			parseDHCPv6(b)
			parseMDNS(b)
			parseSSDP(b)
			parseNBNS(b)
		}()
	}
}
