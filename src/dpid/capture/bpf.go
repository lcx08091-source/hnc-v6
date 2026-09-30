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
//
// v5.18: TCP 部分扩展(用户态见 tls_reasm.go / http.go):
//   - 客户端 → 443 且首字节 0x16(ClientHello 首段)返回 tlsSnaplen(4096),
//     默认 snaplen 1024 会截断带后量子密钥交换的 ~1.8KB ClientHello;
//     服务器 → 443 源端口的 0x16 仍按 snaplen(只用于字节统计);
//   - 客户端 → 443、首字节非 0x16 的段: 只有末 5 字节是 BoringSSL ClientHello
//     的固定结尾(GREASE 扩展 ?A ?A 00 01 00)才放行 —— 这是被拆成多段的
//     ClientHello 的末段, 每连接最多一个; 其他上行数据仍在内核丢弃。末尾偏移
//     用 IP 头里的长度字段算(不受以太网最小帧填充影响);
//   - 客户端 → 80 且载荷前 4 字节是 GET / POST / HEAD / PUT / OPTI / DELE /
//     PATC(HTTP 请求首包, 每请求一个)返回 tlsSnaplen, 用户态取 Host 头。

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

// BuildFilter compiles the cBPF program for Ethernet link types (~100 insns).
func BuildFilter(snaplen uint32) ([]syscall.SockFilter, error) {
	return buildFilter(14, snaplen)
}

// BuildFilterRawIP is the BuildFilter sibling for link types that DON'T
// have an Ethernet header — Qualcomm rmnet (ARPHRD_RAWIP=519) and tun
// VPN devices (ARPHRD_NONE=65534). The packet bytes start directly with
// the IP header, so dispatch is by IP version (first nibble of byte 0)
// instead of etherType, and every offset drops the 14-byte Ethernet prefix.
//
// v5.6.0-rc4 fix: without this, cellular-only or VPN-active devices got
// zero packets through the AF_PACKET capture because the kernel BPF
// program rejected everything.
//
// v5.18: 两个变体合并成同一个按 L2 头长度参数化的生成器, 放行条件完全一致。
func BuildFilterRawIP(snaplen uint32) ([]syscall.SockFilter, error) {
	return buildFilter(0, snaplen)
}

// httpMethodWords: TCP 载荷前 4 字节(大端)等于其中之一才放行 TCP/80。
var httpMethodWords = []uint32{
	0x47455420, // "GET "
	0x504f5354, // "POST"
	0x48454144, // "HEAD"
	0x50555420, // "PUT "
	0x4f505449, // "OPTI"
	0x44454c45, // "DELE"
	0x50415443, // "PATC"
}

// buildFilter 生成 cBPF。l2 = 链路层头长度(以太网 14, RawIP/tun 0)。
func buildFilter(l2 uint32, snaplen uint32) ([]syscall.SockFilter, error) {
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

		w   = 0x00
		h   = 0x08
		b   = 0x10
		abs = 0x20
		ind = 0x40
		msh = 0xa0

		jeq  = 0x10
		jset = 0x40

		add = 0x00
		sub = 0x10
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
		// v5.18: ClientHello 首段/末段、HTTP 请求返回 tlsSnaplen。
		LBL_ACCEPT_BIG = "ACCEPT_BIG"
	)

	labels := make(map[string]int)
	plan := []insn{}

	addInsn := func(label string, op uint16, jt, jf string, kk uint32) {
		if label != "" {
			labels[label] = len(plan)
		}
		plan = append(plan, insn{op: op, jt: jt, jf: jf, k: kk})
	}
	// 无条件跳转(jeq 两路同目标, 解释器/内核都支持)。
	gotoL := func(label string) { addInsn("", jmp|jeq|k, label, label, 0) }

	// v5.13: A 寄存器已装入端口号时, 逐个 jeq 端口表; 命中跳 ACCEPT。
	acceptPorts := func(ports []uint32) {
		for _, p := range ports {
			addInsn("", jmp|jeq|k, LBL_ACCEPT, "", p)
		}
	}
	// X = 末 5 字节起点。A 已装入"IP 头声明的长度"(v4 total length /
	// v6 payload length), base = 该长度对应的包内起点偏移。
	tailX := func(base uint32) {
		if base >= 5 {
			addInsn("", alu|add|k, "", "", base-5)
		} else {
			addInsn("", alu|sub|k, "", "", 5-base)
		}
		addInsn("", misc|tax, "", "", 0)
		gotoL("TAIL_CHECK")
	}

	// ── L3 dispatch ────────────────────────────────────────────────────
	if l2 == 14 {
		addInsn("", ld|h|abs, "", "", 12) // A = etherType
		addInsn("", jmp|jeq|k, "IPV6", "", 0x86dd)
		addInsn("", jmp|jeq|k, "IPV4", LBL_DROP, 0x0800)
	} else {
		// First byte = (version << 4) | IHL.
		addInsn("", ld|b|abs, "", "", 0)
		addInsn("", alu|and|k, "", "", 0xf0)
		addInsn("", jmp|jeq|k, "IPV6", "", 0x60)
		addInsn("", jmp|jeq|k, "IPV4", LBL_DROP, 0x40)
	}

	// ── IPv4 path ──────────────────────────────────────────────────────
	addInsn("IPV4", ld|b|abs, "", "", l2+9) // A = IP proto
	addInsn("", jmp|jeq|k, "IPV4_UDP", "", 17)
	addInsn("", jmp|jeq|k, "IPV4_TCP", LBL_DROP, 6)

	addInsn("IPV4_UDP", ld|h|abs, "", "", l2+6) // frag
	addInsn("", jmp|jset|k, LBL_DROP, "", 0x1fff)
	addInsn("", ldx|b|msh, "", "", l2) // X = IPHL
	addInsn("", ld|h|ind, "", "", l2)  // UDP src
	acceptPorts(bpfUDPPortsV4)
	addInsn("", ld|h|ind, "", "", l2+2) // UDP dst
	acceptPorts(bpfUDPPortsV4)
	addInsn("", jmp|jeq|k, "", LBL_DROP, 443) // v5.14: QUIC
	addInsn("", ld|b|ind, "", "", l2+8)       // UDP 载荷首字节
	addInsn("", jmp|jset|k, LBL_ACCEPT_QUIC, LBL_DROP, 0x80)

	addInsn("IPV4_TCP", ld|h|abs, "", "", l2+6) // frag
	addInsn("", jmp|jset|k, LBL_DROP, "", 0x1fff)
	addInsn("", ldx|b|msh, "", "", l2) // X = IPHL
	addInsn("", ld|h|ind, "", "", l2)  // TCP src
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", jmp|jeq|k, "IPV4_TLS_SRV", "", 443)
	addInsn("", ld|h|ind, "", "", l2+2) // TCP dst
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", jmp|jeq|k, "IPV4_TLS_CLI", "", 443)
	addInsn("", jmp|jeq|k, "IPV4_HTTP", LBL_DROP, 80)

	// X = IPHL + TCPHL, 之后 ld ind l2 即 TCP 载荷首字节。
	v4PayloadX := func(label string) {
		addInsn(label, ld|b|ind, "", "", l2+12) // TCP byte 12
		addInsn("", alu|and|k, "", "", 0xf0)
		addInsn("", alu|rsh|k, "", "", 2) // TCPHL bytes
		addInsn("", alu|add|x, "", "", 0) // A = IPHL + TCPHL
		addInsn("", misc|tax, "", "", 0)
	}
	v4PayloadX("IPV4_TLS_SRV")
	addInsn("", ld|b|ind, "", "", l2)
	addInsn("", jmp|jeq|k, LBL_ACCEPT, LBL_DROP, 0x16)

	v4PayloadX("IPV4_TLS_CLI")
	addInsn("", ld|b|ind, "", "", l2)
	addInsn("", jmp|jeq|k, LBL_ACCEPT_BIG, "", 0x16)
	addInsn("", ld|h|abs, "", "", l2+2) // IPv4 total length
	tailX(l2)

	v4PayloadX("IPV4_HTTP")
	addInsn("", ld|w|ind, "", "", l2)
	gotoL("HTTP_CHECK")

	// ── IPv6 path (assumes no ext headers; ext-header packets DROP) ────
	addInsn("IPV6", ld|b|abs, "", "", l2+6) // A = next header
	addInsn("", jmp|jeq|k, "IPV6_UDP", "", 17)
	addInsn("", jmp|jeq|k, "IPV6_TCP", LBL_DROP, 6)

	addInsn("IPV6_UDP", ld|h|abs, "", "", l2+40) // UDP src
	acceptPorts(bpfUDPPortsV6)
	addInsn("", ld|h|abs, "", "", l2+42) // UDP dst
	acceptPorts(bpfUDPPortsV6)
	addInsn("", jmp|jeq|k, "", LBL_DROP, 443) // v5.14: QUIC
	addInsn("", ld|b|abs, "", "", l2+48)      // UDP 载荷首字节
	addInsn("", jmp|jset|k, LBL_ACCEPT_QUIC, LBL_DROP, 0x80)

	addInsn("IPV6_TCP", ld|h|abs, "", "", l2+40) // TCP src
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", jmp|jeq|k, "IPV6_TLS_SRV", "", 443)
	addInsn("", ld|h|abs, "", "", l2+42) // TCP dst
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", jmp|jeq|k, "IPV6_TLS_CLI", "", 443)
	addInsn("", jmp|jeq|k, "IPV6_HTTP", LBL_DROP, 80)

	// X = l2 + 40 + TCPHL(TCP 载荷首字节的绝对偏移)。
	v6PayloadX := func(label string) {
		addInsn(label, ld|b|abs, "", "", l2+52) // TCP byte 12
		addInsn("", alu|and|k, "", "", 0xf0)
		addInsn("", alu|rsh|k, "", "", 2)
		addInsn("", alu|add|k, "", "", l2+40)
		addInsn("", misc|tax, "", "", 0)
	}
	v6PayloadX("IPV6_TLS_SRV")
	addInsn("", ld|b|ind, "", "", 0)
	addInsn("", jmp|jeq|k, LBL_ACCEPT, LBL_DROP, 0x16)

	v6PayloadX("IPV6_TLS_CLI")
	addInsn("", ld|b|ind, "", "", 0)
	addInsn("", jmp|jeq|k, LBL_ACCEPT_BIG, "", 0x16)
	addInsn("", ld|h|abs, "", "", l2+4) // IPv6 payload length
	tailX(l2 + 40)

	v6PayloadX("IPV6_HTTP")
	addInsn("", ld|w|ind, "", "", 0)
	gotoL("HTTP_CHECK")

	// ── 共用检查块 ─────────────────────────────────────────────────────
	// ClientHello 末段特征: 末 5 字节 = GREASE 扩展类型(两字节低半字节都是
	// 0xA) + 长度 0x0001 + 内容 0x00。越界读(包比声明短)内核直接返回 0 丢弃。
	addInsn("TAIL_CHECK", ld|b|ind, "", "", 0)
	addInsn("", alu|and|k, "", "", 0x0f)
	addInsn("", jmp|jeq|k, "", LBL_DROP, 0x0a)
	addInsn("", ld|b|ind, "", "", 1)
	addInsn("", alu|and|k, "", "", 0x0f)
	addInsn("", jmp|jeq|k, "", LBL_DROP, 0x0a)
	addInsn("", ld|h|ind, "", "", 2)
	addInsn("", jmp|jeq|k, "", LBL_DROP, 0x0001)
	addInsn("", ld|b|ind, "", "", 4)
	addInsn("", jmp|jeq|k, LBL_ACCEPT_BIG, LBL_DROP, 0)

	// A = TCP 载荷前 4 字节。
	for i, m := range httpMethodWords {
		lbl := ""
		if i == 0 {
			lbl = "HTTP_CHECK"
		}
		jf := ""
		if i == len(httpMethodWords)-1 {
			jf = LBL_DROP
		}
		addInsn(lbl, jmp|jeq|k, LBL_ACCEPT_BIG, jf, m)
	}

	// ── Returns ────────────────────────────────────────────────────────
	addInsn(LBL_ACCEPT, ret|k, "", "", snaplen)
	addInsn(LBL_ACCEPT_QUIC, ret|k, "", "", max(snaplen, quicSnaplen))
	addInsn(LBL_ACCEPT_BIG, ret|k, "", "", max(snaplen, tlsSnaplen))
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
