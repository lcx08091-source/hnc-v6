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

package capture

import (
	"fmt"
	"syscall"
)

const ETH_P_ALL = 0x0003

func htons(v uint16) uint16 { return v<<8 | v>>8 }

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
	)

	labels := make(map[string]int)
	plan := []insn{}

	addInsn := func(label string, op uint16, jt, jf string, kk uint32) {
		if label != "" {
			labels[label] = len(plan)
		}
		plan = append(plan, insn{op: op, jt: jt, jf: jf, k: kk})
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
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", ld|h|ind, "", "", 16) // UDP dst
	addInsn("", jmp|jeq|k, LBL_ACCEPT, LBL_DROP, 53)

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
	addInsn("", jmp|jeq|k, LBL_ACCEPT, "", 53)
	addInsn("", ld|h|abs, "", "", 56) // UDP dst
	addInsn("", jmp|jeq|k, LBL_ACCEPT, LBL_DROP, 53)

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
