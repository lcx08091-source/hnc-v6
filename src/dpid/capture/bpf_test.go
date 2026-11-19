package capture

import (
	"encoding/binary"
	"syscall"
	"testing"
)

// runCBPF 是测试用的最小 cBPF 解释器, 只实现 bpf.go 用到的指令子集。
// 越界读按内核语义返回 0(丢弃)。
func runCBPF(t *testing.T, prog []syscall.SockFilter, pkt []byte) uint32 {
	t.Helper()
	var a, x uint32
	for pc := 0; pc < len(prog); pc++ {
		ins := prog[pc]
		cls := ins.Code & 0x07
		switch cls {
		case 0x00, 0x01: // ld / ldx
			size := ins.Code & 0x18
			mode := ins.Code & 0xe0
			var off int
			switch mode {
			case 0x20: // abs
				off = int(ins.K)
			case 0x40: // ind
				off = int(x) + int(ins.K)
			case 0xa0: // msh (ldx only)
				off = int(ins.K)
			default:
				t.Fatalf("unsupported ld mode %#x at %d", mode, pc)
			}
			var v uint32
			switch size {
			case 0x00: // w
				if off < 0 || off+4 > len(pkt) {
					return 0
				}
				v = binary.BigEndian.Uint32(pkt[off:])
			case 0x08: // h
				if off < 0 || off+2 > len(pkt) {
					return 0
				}
				v = uint32(binary.BigEndian.Uint16(pkt[off:]))
			case 0x10: // b
				if off < 0 || off+1 > len(pkt) {
					return 0
				}
				v = uint32(pkt[off])
			default:
				t.Fatalf("unsupported ld size %#x at %d", size, pc)
			}
			if cls == 0x01 {
				if mode == 0xa0 {
					v = 4 * (v & 0x0f)
				}
				x = v
			} else {
				a = v
			}
		case 0x04: // alu
			src := ins.K
			if ins.Code&0x08 != 0 {
				src = x
			}
			switch ins.Code & 0xf0 {
			case 0x00:
				a += src
			case 0x10:
				a -= src
			case 0x50:
				a &= src
			case 0x70:
				a >>= src
			default:
				t.Fatalf("unsupported alu %#x", ins.Code)
			}
		case 0x05: // jmp
			var cond bool
			switch ins.Code & 0xf0 {
			case 0x10:
				cond = a == ins.K
			case 0x40:
				cond = a&ins.K != 0
			default:
				t.Fatalf("unsupported jmp %#x", ins.Code)
			}
			if cond {
				pc += int(ins.Jt)
			} else {
				pc += int(ins.Jf)
			}
		case 0x06: // ret
			return ins.K
		case 0x07: // misc tax
			x = a
		default:
			t.Fatalf("unsupported class %#x", cls)
		}
	}
	t.Fatalf("program fell off the end")
	return 0
}

func udp4(sport, dport uint16, payload []byte) []byte {
	ip := make([]byte, 20+8+len(payload))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], []byte{192, 168, 43, 10})
	copy(ip[16:20], []byte{224, 0, 0, 251})
	binary.BigEndian.PutUint16(ip[20:], sport)
	binary.BigEndian.PutUint16(ip[22:], dport)
	binary.BigEndian.PutUint16(ip[24:], uint16(8+len(payload)))
	copy(ip[28:], payload)
	return ip
}

func udp6(sport, dport uint16, payload []byte) []byte {
	ip := make([]byte, 40+8+len(payload))
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(8+len(payload)))
	ip[6] = 17
	ip[7] = 255
	ip[8] = 0xfe
	ip[9] = 0x80
	ip[23] = 1
	ip[24] = 0xff
	ip[25] = 0x02
	ip[39] = 0xfb
	binary.BigEndian.PutUint16(ip[40:], sport)
	binary.BigEndian.PutUint16(ip[42:], dport)
	binary.BigEndian.PutUint16(ip[44:], uint16(8+len(payload)))
	copy(ip[48:], payload)
	return ip
}

func tcp4(sport, dport uint16, first byte) []byte {
	ip := make([]byte, 20+20+4)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[9] = 6
	binary.BigEndian.PutUint16(ip[20:], sport)
	binary.BigEndian.PutUint16(ip[22:], dport)
	ip[32] = 5 << 4
	ip[40] = first
	return ip
}

func tcp4Payload(sport, dport uint16, payload []byte) []byte {
	ip := make([]byte, 20+20+len(payload))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], []byte{192, 168, 43, 20})
	copy(ip[16:20], []byte{203, 0, 113, 10})
	binary.BigEndian.PutUint16(ip[20:], sport)
	binary.BigEndian.PutUint16(ip[22:], dport)
	ip[32] = 5 << 4
	copy(ip[40:], payload)
	return ip
}

func tcp6Payload(sport, dport uint16, payload []byte) []byte {
	ip := make([]byte, 40+20+len(payload))
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(20+len(payload)))
	ip[6] = 6
	ip[7] = 64
	ip[8] = 0x24
	ip[9] = 0x09
	ip[23] = 0x20
	ip[24] = 0x20
	ip[25] = 0x01
	ip[39] = 0x99
	binary.BigEndian.PutUint16(ip[40:], sport)
	binary.BigEndian.PutUint16(ip[42:], dport)
	ip[52] = 5 << 4
	copy(ip[60:], payload)
	return ip
}

var testSrcMAC = []byte{0x3c, 0x22, 0xfb, 0x11, 0x22, 0x33}

func withEther(ip []byte, v6 bool) []byte {
	pkt := make([]byte, 14+len(ip))
	copy(pkt[0:6], []byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb})
	copy(pkt[6:12], testSrcMAC)
	if v6 {
		binary.BigEndian.PutUint16(pkt[12:], 0x86dd)
	} else {
		binary.BigEndian.PutUint16(pkt[12:], 0x0800)
	}
	copy(pkt[14:], ip)
	return pkt
}

func TestBPFFilterPorts(t *testing.T) {
	eth, err := BuildFilter(1024)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BuildFilterRawIP(1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("BuildFilter=%d insns, BuildFilterRawIP=%d insns", len(eth), len(raw))
	if len(eth) > 255 || len(raw) > 255 {
		t.Fatalf("filter unexpectedly large")
	}

	type tc struct {
		name   string
		ip     []byte
		v6     bool
		accept bool
	}
	pl := []byte{1, 2, 3, 4}
	// v5.14: QUIC 载荷首字节。0xc3 = long header Initial(v1), 0xd3 = v2 Initial
	// 类型位, 0x40 = short header(1-RTT)。
	qLong := []byte{0xc3, 0, 0, 0, 1, 8}
	qLongV2 := []byte{0xd3, 0x6b, 0x33, 0x43, 0xcf, 8}
	qShort := []byte{0x40, 1, 2, 3, 4, 5}
	cases := []tc{
		{"v4 dns dst", udp4(40000, 53, pl), false, true},
		{"v4 dns src", udp4(53, 40000, pl), false, true},
		{"v4 dhcp 68->67", udp4(68, 67, pl), false, true},
		{"v4 dhcp 67->68", udp4(67, 68, pl), false, true},
		{"v4 mdns", udp4(5353, 5353, pl), false, true},
		{"v4 ssdp notify", udp4(40000, 1900, pl), false, true},
		{"v4 ssdp reply", udp4(1900, 40000, pl), false, true},
		{"v4 nbns", udp4(137, 137, pl), false, true},
		{"v4 quic drop", udp4(40000, 443, pl), false, false},
		{"v4 random udp drop", udp4(40000, 40001, pl), false, false},
		{"v4 dhcpv6 port drop", udp4(546, 547, pl), false, false},
		{"v4 tls accept", tcp4(40000, 443, 0x16), false, true},
		{"v4 tls non-hs drop", tcp4(40000, 443, 0x17), false, false},
		{"v6 dns", udp6(40000, 53, pl), true, true},
		{"v6 mdns", udp6(5353, 5353, pl), true, true},
		{"v6 dhcpv6 546->547", udp6(546, 547, pl), true, true},
		{"v6 dhcpv6 547->546", udp6(547, 546, pl), true, true},
		{"v6 ssdp drop", udp6(40000, 1900, pl), true, false},
		{"v6 nbns drop", udp6(137, 137, pl), true, false},
		{"v6 random drop", udp6(40000, 40001, pl), true, false},
		// v5.14: QUIC
		{"v4 quic long accept", udp4(40000, 443, qLong), false, true},
		{"v4 quic v2 long accept", udp4(40000, 443, qLongV2), false, true},
		{"v4 quic short drop", udp4(40000, 443, qShort), false, false},
		{"v4 quic server->client drop", udp4(443, 40000, qLong), false, false},
		{"v4 quic other port drop", udp4(40000, 8443, qLong), false, false},
		{"v4 quic empty payload drop", udp4(40000, 443, nil), false, false},
		{"v6 quic long accept", udp6(40000, 443, qLong), true, true},
		{"v6 quic short drop", udp6(40000, 443, qShort), true, false},
		{"v6 quic server->client drop", udp6(443, 40000, qLong), true, false},
	}
	for _, c := range cases {
		gotEth := runCBPF(t, eth, withEther(c.ip, c.v6)) != 0
		if gotEth != c.accept {
			t.Errorf("ether %s: accept=%v want %v", c.name, gotEth, c.accept)
		}
		gotRaw := runCBPF(t, raw, c.ip) != 0
		if gotRaw != c.accept {
			t.Errorf("rawip %s: accept=%v want %v", c.name, gotRaw, c.accept)
		}
	}

	// v5.14: QUIC 分支返回放大的 snaplen(Initial ≥1200 字节不能截断),
	// 其余放行仍按原 snaplen。
	if got := runCBPF(t, eth, withEther(udp4(40000, 443, qLong), false)); got != quicSnaplen {
		t.Errorf("ether quic snaplen=%d want %d", got, quicSnaplen)
	}
	if got := runCBPF(t, raw, udp6(40000, 443, qLong)); got != quicSnaplen {
		t.Errorf("rawip v6 quic snaplen=%d want %d", got, quicSnaplen)
	}
	if got := runCBPF(t, eth, withEther(udp4(40000, 53, pl), false)); got != 1024 {
		t.Errorf("ether dns snaplen=%d want 1024", got)
	}
	// IPv4 带选项(IHL=6)时 QUIC 首字节偏移随 IPHL 走。
	opt := udp4(40000, 443, qLong)
	opt = append(opt[:20:20], append([]byte{1, 1, 1, 1}, opt[20:]...)...)
	opt[0] = 0x46
	if runCBPF(t, eth, withEther(opt, false)) == 0 || runCBPF(t, raw, opt) == 0 {
		t.Errorf("v4 with options: quic long header should accept")
	}

	// IPv4 分片(非首片)必须丢弃, 即使端口看起来命中。
	frag := udp4(5353, 5353, pl)
	binary.BigEndian.PutUint16(frag[6:], 0x0010)
	if runCBPF(t, eth, withEther(frag, false)) != 0 {
		t.Errorf("fragment should drop")
	}
	// 非 IP 以太类型丢弃。
	arp := withEther(udp4(5353, 5353, pl), false)
	binary.BigEndian.PutUint16(arp[12:], 0x0806)
	if runCBPF(t, eth, arp) != 0 {
		t.Errorf("arp should drop")
	}
}

func TestBPFWildPortHTTPAndParserMetadata(t *testing.T) {
	eth, err := BuildFilter(1024)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BuildFilterRawIP(1024)
	if err != nil {
		t.Fatal(err)
	}

	// Non-443 wild ports matching HTTP methods must return tlsSnaplen (4096).
	for _, dport := range []uint16{80, 8000, 8080, 9090, 18080} {
		for _, method := range []string{"GET ", "POST", "PUT ", "HEAD"} {
			pay := []byte(method + " /v1/collect?phone=13800138000 HTTP/1.1\r\nHost: sdk.example.com:8080\r\nUser-Agent: CamSDK/2.0\r\n\r\n")
			p4 := tcp4Payload(50123, dport, pay)
			p6 := tcp6Payload(50123, dport, pay)
			if got := runCBPF(t, eth, withEther(p4, false)); got != tlsSnaplen {
				t.Errorf("v4 eth port %d %s: got %d want %d", dport, method, got, tlsSnaplen)
			}
			if got := runCBPF(t, raw, p4); got != tlsSnaplen {
				t.Errorf("v4 raw port %d %s: got %d want %d", dport, method, got, tlsSnaplen)
			}
			if got := runCBPF(t, eth, withEther(p6, true)); got != tlsSnaplen {
				t.Errorf("v6 eth port %d %s: got %d want %d", dport, method, got, tlsSnaplen)
			}
			if got := runCBPF(t, raw, p6); got != tlsSnaplen {
				t.Errorf("v6 raw port %d %s: got %d want %d", dport, method, got, tlsSnaplen)
			}
		}
	}

	// Port 443 (src or dst) must NEVER enter HTTP method check; HTTP responses & empty ACKs drop.
	for _, dropCase := range []struct {
		name string
		ip   []byte
		v6   bool
	}{
		{"dst 443 GET", tcp4Payload(50123, 443, []byte("GET / HTTP/1.1\r\n")), false},
		{"src 443 POST", tcp4Payload(443, 50123, []byte("POST / HTTP/1.1\r\n")), false},
		{"v6 dst 443 PUT", tcp6Payload(50123, 443, []byte("PUT / HTTP/1.1\r\n")), true},
		{"wild 8080 HTTP response", tcp4Payload(8080, 50123, []byte("HTTP/1.1 200 OK\r\n\r\n")), false},
		{"wild 8080 binary", tcp4Payload(50123, 8080, []byte{0x01, 0x02, 0x03, 0x04}), false},
		{"wild 8080 empty ACK", tcp4Payload(50123, 8080, nil), false},
	} {
		if got := runCBPF(t, eth, withEther(dropCase.ip, dropCase.v6)); got != 0 {
			t.Errorf("%s: expected drop (0), got %d", dropCase.name, got)
		}
	}

	// Verify parsePacket populates EventHTTP + full HTTPInfo (Method, Path, Host, UserAgent, RawPayload) on wild port 8080.
	postReq := []byte("POST /v2/report?src=iot HTTP/1.1\r\nHost: leak.camera.example:8080\r\nUser-Agent: IoTCam/3.1\r\nContent-Type: application/json\r\n\r\n{\"mobile\":\"13800138000\"}")
	ev, res := parsePacket(withEther(tcp4Payload(52000, 8080, postReq), false), v518TS)
	if res != ParseOK || ev.Kind != EventHTTP || ev.HTTP == nil {
		t.Fatalf("wild-port HTTP parse failed: res=%v kind=%v http=%v", res, ev.Kind, ev.HTTP)
	}
	if ev.HTTP.Method != "POST" || ev.HTTP.Path != "/v2/report?src=iot" || ev.HTTP.Host != "leak.camera.example" || ev.HTTP.UserAgent != "IoTCam/3.1" {
		t.Fatalf("HTTPInfo metadata mismatch: %+v", ev.HTTP)
	}
	if string(ev.HTTP.RawPayload) != string(postReq) {
		t.Fatalf("HTTPInfo RawPayload mismatch: got %d bytes", len(ev.HTTP.RawPayload))
	}
}
