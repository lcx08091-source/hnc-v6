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
