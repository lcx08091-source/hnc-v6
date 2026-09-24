// Package capture: classic BPF filter for hnc_dpid rc29.
//
// rc20.1 was IPv4-only and accepted three patterns:
//   - UDP/TCP src or dst port 53                      (DNS)
//   - TCP dst port 443 AND first payload byte == 0x16 (TLS handshake)
//
// rc29 expands this to cover IPv6 with the same accept conditions.
// IPv6 extension headers are NOT skipped — packets with HBH/routing/dest-opts
// before the L4 header fall through to DROP. This matches ~99% of real-world
// Android tethered traffic in 2026; user-mode parse.go also handles ext
// headers, so behaviour stays consistent if BPF ever gets more permissive.
//
// The filter is built with symbolic labels and resolved in a second pass,
// because hand-counting JT/JF for ~50 instructions is error-prone.
//
// v5.13: UDP 端口白名单扩展为被动设备识别协议 —— IPv4 额外放行
// 67/68 (DHCP)、137 (NBNS)、1900 (SSDP)、5353 (mDNS); IPv6 额外放行
// 546/547 (DHCPv6)、5353 (mDNS)。这些协议包量极小(接入瞬间几个 DHCP、
// 每分钟若干组播公告), 对 AF_PACKET 队列压力可忽略。src/dst 任一端口
// 命中即放行; 用户态 parse.go 再按方向细分, 且绝不把它们记成 EventFlow。
//
// v5.14: 额外放行 QUIC —— UDP 目的端口 443 且 UDP 载荷首字节 & 0x80 != 0
// (long header)。只放行客户端→服务器方向; long header 之外不再细分类型
// (v1 Initial=0b00 / v2 Initial=0b01 / gQUIC Q046 都是 long header), 由
// quic.go 在用户态判定。QUIC 分支单独返回 max(snaplen, quicSnaplen), 因为
// Initial 至少 1200 字节, 截断后 AEAD 无法解密。握手期 long header 包每连接
// 只有寥寥几个, 1-RTT 数据走 short header, 仍在内核里丢弃。

package capture

import (
	"fmt"
	"syscall"
)

const ETH_P_ALL = 0x0003

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// v5.13: cBPF 放行的 UDP 端口表(src 或 dst 任一命中)。53 = DNS, 其余为
// 设备识别协议。改这里两个 BuildFilter 变体同步生效; bpf_test.go 用 cBPF
// 解释器逐端口校验放行/丢弃。
var (
	bpfUDPPortsV4 = []uint32{53, 67, 68, 137, 1900, 5353}
	bpfUDPPortsV6 = []uint32{53, 546, 547, 5353}
)

// BuildFilter compiles the cBPF program. Returns ~50 instructions.
func BuildFilter(snaplen uint32) ([]syscall.SockFilter, error) {
	if snaplen == 0 {
		snaplen = 1024
	}

	const (
		// Classic BPF opcodes from linux/filter.h.
		ld   = 0x00
		ldx  = 0x01
		alu  = 0x04
		jmp  = 0x05
		ret  = 0x06
		misc = 0x07

		h   = 0x08
		b   = 0x10
		abs = 0x20
		ind = 0x40
		msh = 0xa0

		jeq  = 0x10
		jset = 0x40

		add = 0x00
		and = 0x50
		rsh = 0x70

		k = 0x00
		x = 0x08

		tax = 0x00
	)

	type insn struct {
		op     uint16
		jt, jf string // label names; empty if jump field unused
		k      uint32
	}

	const (
		LBL_DROP   = "DROP"
		LBL_ACCEPT = "ACCEPT"
		// v5.14: QUIC 放行单独返回更大的 snaplen。
		LBL_ACCEPT_QUIC = "ACCEPT_QUIC"
	)

	labels := make(map[string]int)
	plan := []insn{}

	addInsn := func(label string, op uint16, jt, jf string, kk uint32) {
		if label != "" {
			labels[label] = len(plan)
		}
		plan = append(plan, insn{op: op, jt: jt, jf: jf, k: kk})
	}

	// v5.13: A 寄存器已装入端口号时, 逐个 jeq 端口表; 命中跳 ACCEPT。
	// lastJF 非空时最后一条的 JF 指向它(dst 端口检查末尾 → DROP),
	// 为空时落空继续执行下一条(src 端口检查后接着检查 dst)。
	acceptPorts := func(ports []uint32, lastJF string) {
		for i, p := range ports {
			jf := ""
			if i == len(ports)-1 {
				jf = lastJF
			}
			addInsn("", jmp|jeq|k, LBL_ACCEPT, jf, p)
		}
	}

	// ── etherType dispatch ─────────────────────────────────────────────
	addInsn("", ld|h|abs, "", "", 12) // A = etherType
	addInsn("", jmp|jeq|k, "IPV6", "", 0x86dd)
	addInsn("", jmp|jeq|k, "IPV4", LBL_DROP, 0x0800)

	// ── IPv4 path ──────────────────────────────────────────────────────
	addInsn("IPV4", ld|b|abs, "", "", 23) // A = IP proto
	addInsn("", jmp|jeq|k, "IPV4_UDP", "", 17)
	addInsn("", jmp|jeq|k, "IPV4_TCP", LBL_DROP, 6)

	addInsn("IPV4_UDP", ld|h|abs, "", "", 20) // frag
	addInsn("", jmp|jset|k, LBL_DROP, "", 0x1fff)
	addInsn("", ldx|b|msh, "", "", 14) // X = IPHL
	addInsn("", ld|h|ind, "", "", 14)  // UDP src
	acceptPorts(bpfUDPPortsV4, "")
	addInsn("", ld|h|ind, "", "", 16) // UDP dst
	acceptPorts(bpfUDPPortsV4, "")
	addInsn("", jmp|jeq|k, "", LBL_DROP, 443) // v5.14: QUIC
	addInsn("", ld|b|ind, "", "", 22)         // UDP 载荷首字节 (14+IPHL+8)
	addInsn("", jmp|jset|k, LBL_ACCEPT_QUIC, LBL_DROP, 0x80)

	addInsn("IPV4_TCP", ld|h|abs, "", "", 20) // frag
	addInsn("", jmp|jset|k, LBL_DROP, "", 0x1fff)
	addInsn("", ldx|b|msh, "", "", 14) // X = IPHL
	addInsn("", ld|h|ind, "", "", 14)  // TCP src
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", jmp|jeq|k, "IPV4_TLS", "", 443)
	addInsn("", ld|h|ind, "", "", 16) // TCP dst
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", jmp|jeq|k, "IPV4_TLS", LBL_DROP, 443)

	addInsn("IPV4_TLS", ld|b|ind, "", "", 26) // TCP byte 12 (X+26)
	addInsn("", alu|and|k, "", "", 0xf0)
	addInsn("", alu|rsh|k, "", "", 2) // TCPHL bytes
	addInsn("", alu|add|x, "", "", 0) // A = IPHL + TCPHL
	addInsn("", misc|tax, "", "", 0)  // X = A
	addInsn("", ld|b|ind, "", "", 14) // first TCP payload byte (14+IPHL+TCPHL)
	addInsn("", jmp|jeq|k, LBL_ACCEPT, LBL_DROP, 0x16)

	// ── IPv6 path (assumes no ext headers; ext-header packets DROP) ────
	addInsn("IPV6", ld|b|abs, "", "", 20) // A = next header (offset 14+6)
	addInsn("", jmp|jeq|k, "IPV6_UDP", "", 17)
	addInsn("", jmp|jeq|k, "IPV6_TCP", LBL_DROP, 6)

	addInsn("IPV6_UDP", ld|h|abs, "", "", 54) // UDP src
	acceptPorts(bpfUDPPortsV6, "")
	addInsn("", ld|h|abs, "", "", 56) // UDP dst
	acceptPorts(bpfUDPPortsV6, "")
	addInsn("", jmp|jeq|k, "", LBL_DROP, 443) // v5.14: QUIC
	addInsn("", ld|b|abs, "", "", 62)         // UDP 载荷首字节 (14+40+8)
	addInsn("", jmp|jset|k, LBL_ACCEPT_QUIC, LBL_DROP, 0x80)

	addInsn("IPV6_TCP", ld|h|abs, "", "", 54) // TCP src
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", jmp|jeq|k, "IPV6_TLS", "", 443)
	addInsn("", ld|h|abs, "", "", 56) // TCP dst
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", jmp|jeq|k, "IPV6_TLS", LBL_DROP, 443)

	addInsn("IPV6_TLS", ld|b|abs, "", "", 66) // TCP byte 12 at offset 54+12
	addInsn("", alu|and|k, "", "", 0xf0)
	addInsn("", alu|rsh|k, "", "", 2)  // TCPHL bytes
	addInsn("", alu|add|k, "", "", 54) // A = 54 + TCPHL (absolute offset)
	addInsn("", misc|tax, "", "", 0)   // X = A
	addInsn("", ld|b|ind, "", "", 0)   // first payload byte
	addInsn("", jmp|jeq|k, LBL_ACCEPT, LBL_DROP, 0x16)

	// ── Returns ────────────────────────────────────────────────────────
	addInsn(LBL_ACCEPT, ret|k, "", "", snaplen)
	addInsn(LBL_ACCEPT_QUIC, ret|k, "", "", max(snaplen, quicSnaplen))
	addInsn(LBL_DROP, ret|k, "", "", 0)

	// Pass 2: resolve labels to JT/JF byte offsets.
	out := make([]syscall.SockFilter, len(plan))
	for i, ins := range plan {
		out[i].Code = ins.op
		out[i].K = ins.k
		if ins.jt != "" {
			t, ok := labels[ins.jt]
			if !ok {
				return nil, fmt.Errorf("unresolved label %q at insn %d", ins.jt, i)
			}
			d := t - i - 1
			if d < 0 || d > 255 {
				return nil, fmt.Errorf("jt jump out of range: %d -> %d (%s, d=%d)", i, t, ins.jt, d)
			}
			out[i].Jt = uint8(d)
		}
		if ins.jf != "" {
			t, ok := labels[ins.jf]
			if !ok {
				return nil, fmt.Errorf("unresolved label %q at insn %d", ins.jf, i)
			}
			d := t - i - 1
			if d < 0 || d > 255 {
				return nil, fmt.Errorf("jf jump out of range: %d -> %d (%s, d=%d)", i, t, ins.jf, d)
			}
			out[i].Jf = uint8(d)
		}
	}
	return out, nil
}

// BuildFilterRawIP is the BuildFilter sibling for link types that DON'T
// have an Ethernet header — Qualcomm rmnet (ARPHRD_RAWIP=519) and tun
// VPN devices (ARPHRD_NONE=65534). The packet bytes start directly with
// the IP header, so:
//   - Dispatch by IP version (first nibble of byte 0) instead of etherType
//     at offset [12:14] (which on RawIP would land in the middle of the IP
//     header's source-address field — never matches 0x0800/0x86dd).
//   - All "ind" addressing that previously used (IPHL + 14) now uses
//     (IPHL + 0). All "abs" addressing for the IP header drops the +14
//     Ethernet prefix.
//   - For IPv6 fields: offsets 20→6 (next header), 54→40 (UDP/TCP src),
//     56→42 (UDP/TCP dst), 66→52 (TCP byte 12 for header-length calc).
//
// This is bug-for-bug compatible with BuildFilter modulo the 14-byte
// shift and the dispatch front-end. Same accept criteria: TCP/443 (with
// TLS ClientHello first-byte check) + UDP 端口表 + v5.14 QUIC long header。
//
// v5.6.0-rc4 fix: without this, cellular-only or VPN-active devices got
// zero packets through the AF_PACKET capture because the kernel BPF
// program rejected everything. Symptom: dpi_state.json showed
// interfaces[*].packets=0 across all rmnet ifaces even after capture
// handle open succeeded.
func BuildFilterRawIP(snaplen uint32) ([]syscall.SockFilter, error) {
	if snaplen == 0 {
		snaplen = 1024
	}

	const (
		ld   = 0x00
		ldx  = 0x01
		alu  = 0x04
		jmp  = 0x05
		ret  = 0x06
		misc = 0x07

		h   = 0x08
		b   = 0x10
		abs = 0x20
		ind = 0x40
		msh = 0xa0

		jeq  = 0x10
		jset = 0x40

		add = 0x00
		and = 0x50
		rsh = 0x70

		k = 0x00
		x = 0x08

		tax = 0x00
	)

	type insn struct {
		op     uint16
		jt, jf string
		k      uint32
	}

	const (
		LBL_DROP   = "DROP"
		LBL_ACCEPT = "ACCEPT"
		// v5.14: QUIC 放行单独返回更大的 snaplen。
		LBL_ACCEPT_QUIC = "ACCEPT_QUIC"
	)

	labels := make(map[string]int)
	plan := []insn{}

	addInsn := func(label string, op uint16, jt, jf string, kk uint32) {
		if label != "" {
			labels[label] = len(plan)
		}
		plan = append(plan, insn{op: op, jt: jt, jf: jf, k: kk})
	}

	// v5.13: A 寄存器已装入端口号时, 逐个 jeq 端口表; 命中跳 ACCEPT。
	// lastJF 非空时最后一条的 JF 指向它(dst 端口检查末尾 → DROP),
	// 为空时落空继续执行下一条(src 端口检查后接着检查 dst)。
	acceptPorts := func(ports []uint32, lastJF string) {
		for i, p := range ports {
			jf := ""
			if i == len(ports)-1 {
				jf = lastJF
			}
			addInsn("", jmp|jeq|k, LBL_ACCEPT, jf, p)
		}
	}

	// ── IP version dispatch (replaces etherType check) ─────────────────
	// First byte of packet = (version << 4) | IHL. Extract version by
	// AND'ing with 0xf0; compare to 0x40 (IPv4) or 0x60 (IPv6).
	addInsn("", ld|b|abs, "", "", 0)     // A = packet[0]
	addInsn("", alu|and|k, "", "", 0xf0) // A &= 0xf0
	addInsn("", jmp|jeq|k, "IPV6", "", 0x60)
	addInsn("", jmp|jeq|k, "IPV4", LBL_DROP, 0x40)

	// ── IPv4 path ──────────────────────────────────────────────────────
	addInsn("IPV4", ld|b|abs, "", "", 9) // A = IP proto (offset 14→0+9)
	addInsn("", jmp|jeq|k, "IPV4_UDP", "", 17)
	addInsn("", jmp|jeq|k, "IPV4_TCP", LBL_DROP, 6)

	addInsn("IPV4_UDP", ld|h|abs, "", "", 6) // frag (20→6)
	addInsn("", jmp|jset|k, LBL_DROP, "", 0x1fff)
	addInsn("", ldx|b|msh, "", "", 0) // X = IPHL (offset 14→0)
	addInsn("", ld|h|ind, "", "", 0)  // UDP src (X + 14 → X + 0)
	acceptPorts(bpfUDPPortsV4, "")
	addInsn("", ld|h|ind, "", "", 2) // UDP dst (16→2)
	acceptPorts(bpfUDPPortsV4, "")
	addInsn("", jmp|jeq|k, "", LBL_DROP, 443) // v5.14: QUIC
	addInsn("", ld|b|ind, "", "", 8)          // UDP 载荷首字节 (IPHL+8)
	addInsn("", jmp|jset|k, LBL_ACCEPT_QUIC, LBL_DROP, 0x80)

	addInsn("IPV4_TCP", ld|h|abs, "", "", 6) // frag
	addInsn("", jmp|jset|k, LBL_DROP, "", 0x1fff)
	addInsn("", ldx|b|msh, "", "", 0) // X = IPHL
	addInsn("", ld|h|ind, "", "", 0)  // TCP src
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", jmp|jeq|k, "IPV4_TLS", "", 443)
	addInsn("", ld|h|ind, "", "", 2) // TCP dst
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", jmp|jeq|k, "IPV4_TLS", LBL_DROP, 443)

	// First payload byte = IPHL + TCPHL. With Ethernet, the existing
	// filter computes IPHL+TCPHL+14 then adds X (=IPHL) implicitly via
	// ind addressing trick; the cleanest RawIP equivalent is to compute
	// IPHL+TCPHL into X and read at X+0.
	addInsn("IPV4_TLS", ld|b|ind, "", "", 12) // TCP byte 12 (X + 26 → X + 12)
	addInsn("", alu|and|k, "", "", 0xf0)
	addInsn("", alu|rsh|k, "", "", 2) // TCPHL bytes
	addInsn("", alu|add|x, "", "", 0) // A = IPHL + TCPHL
	addInsn("", misc|tax, "", "", 0)  // X = A
	addInsn("", ld|b|ind, "", "", 0)  // first TCP payload byte (offset 14→0)
	addInsn("", jmp|jeq|k, LBL_ACCEPT, LBL_DROP, 0x16)

	// ── IPv6 path (assumes no ext headers) ─────────────────────────────
	addInsn("IPV6", ld|b|abs, "", "", 6) // next header (20→6)
	addInsn("", jmp|jeq|k, "IPV6_UDP", "", 17)
	addInsn("", jmp|jeq|k, "IPV6_TCP", LBL_DROP, 6)

	addInsn("IPV6_UDP", ld|h|abs, "", "", 40) // UDP src (54→40)
	acceptPorts(bpfUDPPortsV6, "")
	addInsn("", ld|h|abs, "", "", 42) // UDP dst (56→42)
	acceptPorts(bpfUDPPortsV6, "")
	addInsn("", jmp|jeq|k, "", LBL_DROP, 443) // v5.14: QUIC
	addInsn("", ld|b|abs, "", "", 48)         // UDP 载荷首字节 (40+8)
	addInsn("", jmp|jset|k, LBL_ACCEPT_QUIC, LBL_DROP, 0x80)

	addInsn("IPV6_TCP", ld|h|abs, "", "", 40) // TCP src
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", jmp|jeq|k, "IPV6_TLS", "", 443)
	addInsn("", ld|h|abs, "", "", 42) // TCP dst
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", jmp|jeq|k, "IPV6_TLS", LBL_DROP, 443)

	addInsn("IPV6_TLS", ld|b|abs, "", "", 52) // TCP byte 12 at offset 40+12 (66→52)
	addInsn("", alu|and|k, "", "", 0xf0)
	addInsn("", alu|rsh|k, "", "", 2)  // TCPHL bytes
	addInsn("", alu|add|k, "", "", 40) // A = 40 + TCPHL (54→40)
	addInsn("", misc|tax, "", "", 0)   // X = A
	addInsn("", ld|b|ind, "", "", 0)   // first payload byte
	addInsn("", jmp|jeq|k, LBL_ACCEPT, LBL_DROP, 0x16)

	// ── Returns ────────────────────────────────────────────────────────
	addInsn(LBL_ACCEPT, ret|k, "", "", snaplen)
	addInsn(LBL_ACCEPT_QUIC, ret|k, "", "", max(snaplen, quicSnaplen))
	addInsn(LBL_DROP, ret|k, "", "", 0)

	// Resolve labels.
	out := make([]syscall.SockFilter, len(plan))
	for i, ins := range plan {
		out[i].Code = ins.op
		out[i].K = ins.k
		if ins.jt != "" {
			t, ok := labels[ins.jt]
			if !ok {
				return nil, fmt.Errorf("unresolved label %q at insn %d", ins.jt, i)
			}
			d := t - i - 1
			if d < 0 || d > 255 {
				return nil, fmt.Errorf("jt jump out of range: %d -> %d (%s, d=%d)", i, t, ins.jt, d)
			}
			out[i].Jt = uint8(d)
		}
		if ins.jf != "" {
			t, ok := labels[ins.jf]
			if !ok {
				return nil, fmt.Errorf("unresolved label %q at insn %d", ins.jf, i)
			}
			d := t - i - 1
			if d < 0 || d > 255 {
				return nil, fmt.Errorf("jf jump out of range: %d -> %d (%s, d=%d)", i, t, ins.jf, d)
			}
			out[i].Jf = uint8(d)
		}
	}
	return out, nil
}

// AttachFilter installs the compiled program on a raw socket.
func AttachFilter(fd int, filters []syscall.SockFilter) error {
	if len(filters) == 0 {
		return fmt.Errorf("empty filter")
	}
	if len(filters) > 4096 {
		return fmt.Errorf("filter too long: %d", len(filters))
	}
	return syscall.AttachLsf(fd, filters)
}
