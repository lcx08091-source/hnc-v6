package output

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func buildNLA(rawType uint16, payload []byte) []byte {
	nlaLen := ctNlaHdrLen + len(payload)
	padded := ctAlign4(nlaLen)
	out := make([]byte, padded)
	binary.LittleEndian.PutUint16(out[0:2], uint16(nlaLen))
	binary.LittleEndian.PutUint16(out[2:4], rawType)
	copy(out[4:], payload)
	return out
}

func be16(v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return b[:]
}

func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func be64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func buildCTMsg(family uint8, attrs ...[]byte) []byte {
	const nlaNested = 0x8000
	_ = nlaNested
	var body []byte
	for _, a := range attrs {
		body = append(body, a...)
	}
	msgLen := ctNlHdrLen + ctNfGenMsgLen + len(body)
	padded := ctAlign4(msgLen)
	msg := make([]byte, padded)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint16(msg[4:6], (nfnlSubsysCTNetlink<<8)|ipctnlMsgCTNew)
	binary.LittleEndian.PutUint16(msg[6:8], 0x0002) // NLM_F_MULTI
	binary.LittleEndian.PutUint32(msg[8:12], 1)
	msg[ctNlHdrLen] = family
	copy(msg[ctNlHdrLen+ctNfGenMsgLen:], body)
	return msg
}

func buildNLDone() []byte {
	msg := make([]byte, ctNlHdrLen)
	binary.LittleEndian.PutUint32(msg[0:4], ctNlHdrLen)
	binary.LittleEndian.PutUint16(msg[4:6], syscall.NLMSG_DONE)
	return msg
}

func TestParseCTNetlinkMsgs_IPv4AndIPv6CompatLines(t *testing.T) {
	const (
		nlaNested = 0x8000
		nlaNetBE  = 0x4000
	)

	// Flow 1: IPv4 TCP ESTABLISHED 192.168.43.20:51234 -> 93.184.216.34:443 with 64-bit counters
	v4OrigIP := append(
		buildNLA(ctaIPV4Src, net.IPv4(192, 168, 43, 20).To4()),
		buildNLA(ctaIPV4Dst, net.IPv4(93, 184, 216, 34).To4())...,
	)
	v4OrigProto := append(
		buildNLA(ctaProtoNum, []byte{6}),
		append(
			buildNLA(ctaProtoSrcPort|nlaNetBE, be16(51234)),
			buildNLA(ctaProtoDstPort|nlaNetBE, be16(443))...,
		)...,
	)
	v4OrigTuple := buildNLA(ctaTupleOrig|nlaNested, append(
		buildNLA(ctaTupleIP|nlaNested, v4OrigIP),
		buildNLA(ctaTupleProto|nlaNested, v4OrigProto)...,
	))

	v4RepIP := append(
		buildNLA(ctaIPV4Src, net.IPv4(93, 184, 216, 34).To4()),
		buildNLA(ctaIPV4Dst, net.IPv4(10, 0, 0, 2).To4())...,
	)
	v4RepProto := append(
		buildNLA(ctaProtoNum, []byte{6}),
		append(
			buildNLA(ctaProtoSrcPort|nlaNetBE, be16(443)),
			buildNLA(ctaProtoDstPort|nlaNetBE, be16(51234))...,
		)...,
	)
	v4RepTuple := buildNLA(ctaTupleReply|nlaNested, append(
		buildNLA(ctaTupleIP|nlaNested, v4RepIP),
		buildNLA(ctaTupleProto|nlaNested, v4RepProto)...,
	))

	v4ProtoInfo := buildNLA(ctaProtoInfo|nlaNested,
		buildNLA(ctaProtoInfoTCP|nlaNested,
			buildNLA(ctaProtoInfoTCPState, []byte{3}), // ESTABLISHED
		),
	)
	v4OrigCnt := buildNLA(ctaCountersOrig|nlaNested, append(
		buildNLA(ctaCountersPackets|nlaNetBE, be64(15)),
		buildNLA(ctaCountersBytes|nlaNetBE, be64(2048))...,
	))
	v4RepCnt := buildNLA(ctaCountersReply|nlaNested, append(
		buildNLA(ctaCountersPackets|nlaNetBE, be64(22)),
		buildNLA(ctaCountersBytes|nlaNetBE, be64(16384))...,
	))

	msg1 := buildCTMsg(syscall.AF_INET,
		v4OrigTuple,
		v4RepTuple,
		buildNLA(ctaStatus|nlaNetBE, be32(ipsSeenReply|ipsAssured)),
		buildNLA(ctaTimeout|nlaNetBE, be32(431999)),
		v4ProtoInfo,
		v4OrigCnt,
		v4RepCnt,
	)

	// Flow 2: IPv6 UDP DoT (port 853) 2409:8a00::20:50000 -> 2400:3200::1:853 UNREPLIED
	v6OrigIP := append(
		buildNLA(ctaIPV6Src, net.ParseIP("2409:8a00::20").To16()),
		buildNLA(ctaIPV6Dst, net.ParseIP("2400:3200::1").To16())...,
	)
	v6OrigProto := append(
		buildNLA(ctaProtoNum, []byte{17}),
		append(
			buildNLA(ctaProtoSrcPort|nlaNetBE, be16(50000)),
			buildNLA(ctaProtoDstPort|nlaNetBE, be16(853))...,
		)...,
	)
	msg2 := buildCTMsg(syscall.AF_INET6,
		buildNLA(ctaTupleOrig|nlaNested, append(
			buildNLA(ctaTupleIP|nlaNested, v6OrigIP),
			buildNLA(ctaTupleProto|nlaNested, v6OrigProto)...,
		)),
		buildNLA(ctaTimeout|nlaNetBE, be32(29)),
		buildNLA(ctaCountersOrig|nlaNested, append(
			buildNLA(ctaCountersPackets|nlaNetBE, be64(1)),
			buildNLA(ctaCountersBytes|nlaNetBE, be64(96))...,
		)),
	)

	stream := append(append(msg1, msg2...), buildNLDone()...)
	var lines []string
	done, err := parseCTNetlinkMsgs(stream, func(line string) bool {
		lines = append(lines, line)
		return true
	})
	if err != nil || !done || len(lines) != 2 {
		t.Fatalf("parseCTNetlinkMsgs: done=%v err=%v lines=%v", done, err, lines)
	}

	if got := ConntrackOrigDst(lines[0]); got != "93.184.216.34" {
		t.Fatalf("flow1 orig dst: got %q, want 93.184.216.34 (line=%q)", got, lines[0])
	}
	proto, state, ok := parseConntrackLine(lines[0])
	if !ok || proto != "tcp" || state != "ESTABLISHED" {
		t.Fatalf("flow1 parseConntrackLine: proto=%q state=%q ok=%v (line=%q)", proto, state, ok, lines[0])
	}
	if !strings.Contains(lines[0], "bytes=2048") || !strings.Contains(lines[0], "bytes=16384") || !strings.Contains(lines[0], "[ASSURED]") {
		t.Fatalf("flow1 missing byte counters or ASSURED flag: %q", lines[0])
	}

	if got := ConntrackOrigDst(lines[1]); got != "2400:3200::1" {
		t.Fatalf("flow2 orig dst: got %q, want 2400:3200::1 (line=%q)", got, lines[1])
	}
	if dotKey := ConntrackDoTKey(lines[1]); dotKey != "udp|2409:8a00::20|50000|2400:3200::1" {
		t.Fatalf("flow2 DoT key: got %q (line=%q)", dotKey, lines[1])
	}
	if !strings.Contains(lines[1], "[UNREPLIED]") || !strings.Contains(lines[1], "bytes=96") {
		t.Fatalf("flow2 missing UNREPLIED or bytes=96: %q", lines[1])
	}
}

func TestParseCTNetlinkMsgs_ErrorAndTruncatedFrames(t *testing.T) {
	// NLMSG_ERROR with -EPERM
	errMsg := make([]byte, ctNlHdrLen+4)
	binary.LittleEndian.PutUint32(errMsg[0:4], uint32(len(errMsg)))
	binary.LittleEndian.PutUint16(errMsg[4:6], syscall.NLMSG_ERROR)
	errnoNeg := int32(-int(syscall.EPERM))
	binary.LittleEndian.PutUint32(errMsg[ctNlHdrLen:], uint32(errnoNeg))
	if _, err := parseCTNetlinkMsgs(errMsg, nil); err != syscall.EPERM {
		t.Fatalf("expected EPERM from NLMSG_ERROR, got %v", err)
	}

	// Truncated header must return error without panic.
	if _, err := parseCTNetlinkMsgs([]byte{1, 2, 3}, nil); err == nil {
		t.Fatal("expected error on truncated nlmsghdr")
	}
}

func TestReadConntrackLines_CustomFakePathNeverTouchesNetlink(t *testing.T) {
	oldPaths := ConntrackPaths
	oldDump := ctnetlinkDumpFn
	t.Cleanup(func() {
		ConntrackPaths = oldPaths
		ctnetlinkDumpFn = oldDump
	})

	netlinkCalled := false
	ctnetlinkDumpFn = func(maxLines int, onLine func(string)) (int, error) {
		netlinkCalled = true
		return 1, nil
	}

	ConntrackPaths = []string{filepath.Join(t.TempDir(), "non_proc_conntrack")}
	r := ReadConntrackLines(nil)
	if netlinkCalled {
		t.Fatal("custom non-/proc path must NOT invoke host CTNETLINK fallback")
	}
	if r.Available || r.Readable || r.Flows != 0 {
		t.Fatalf("unexpected report for missing custom path: %+v", r)
	}
}

func TestReadConntrackLines_ProcDeniedOrMissingFallsBackToCTNetlink(t *testing.T) {
	oldPaths := ConntrackPaths
	oldOpen := openConntrackFileFn
	oldDump := ctnetlinkDumpFn
	t.Cleanup(func() {
		ConntrackPaths = oldPaths
		openConntrackFileFn = oldOpen
		ctnetlinkDumpFn = oldDump
	})

	// Case 1: /proc path missing -> fallback to CTNETLINK
	ConntrackPaths = []string{"/proc/net/hnc_nonexistent_conntrack_rc2_test"}
	ctnetlinkDumpFn = func(maxLines int, onLine func(string)) (int, error) {
		if onLine != nil {
			onLine("ipv4 2 tcp 6 120 ESTABLISHED src=192.168.43.2 dst=1.1.1.1 sport=40000 dport=853 packets=2 bytes=120 [ASSURED] mark=0 use=1")
		}
		return 1, nil
	}

	var gotDst, gotDoT string
	r := ReadConntrackLines(func(line string) {
		gotDst = ConntrackOrigDst(line)
		gotDoT = ConntrackDoTKey(line)
	})
	if !r.Available || !r.Readable || r.Path != ConntrackNetlinkPath || r.Flows != 1 {
		t.Fatalf("missing /proc fallback failed: %+v", r)
	}
	if gotDst != "1.1.1.1" || gotDoT != "tcp|192.168.43.2|40000|1.1.1.1" {
		t.Fatalf("onLine consumer mismatch: dst=%q dot=%q", gotDst, gotDoT)
	}

	// Case 2: existing /proc file returning EACCES -> fallback to CTNETLINK
	ConntrackPaths = []string{"/proc/version"}
	openConntrackFileFn = func(name string) (*os.File, error) {
		return nil, syscall.EACCES
	}
	r2 := ReadConntrackLines(nil)
	if !r2.Available || !r2.Readable || r2.Path != ConntrackNetlinkPath || r2.Flows != 1 {
		t.Fatalf("EACCES /proc fallback failed: %+v", r2)
	}
}

func TestIPNameIgnoresFakeIPRanges(t *testing.T) {
	tb := NewIPNameTable()
	now := time.Unix(1_800_000_000, 0)

	// Fake-IP ranges: 198.18.0.0/15 and fc00::/18 must be ignored.
	fakeIPs := []string{
		"198.18.0.1",
		"198.19.255.254",
		"::ffff:198.18.1.9",
		"fc00::1",
		"fc00:3fff:ffff:ffff:ffff:ffff:ffff:ffff",
	}
	tb.RecordDNS("fake.example.com", fakeIPs, 300, now)
	for _, ip := range fakeIPs {
		tb.RecordConnName(ip, "sni.fake.example.com", IPNameSrcSNI, now)
		if _, ok := tb.Lookup(ip, now); ok {
			t.Errorf("Fake-IP %s must NOT be recorded in IPNameTable", ip)
		}
	}
	if tb.Len() != 0 {
		t.Fatalf("IPNameTable should be empty after Fake-IP inputs, got len=%d", tb.Len())
	}

	// Neighboring legitimate IPs outside 198.18.0.0/15 and fc00::/18 must still work.
	realIPs := []string{
		"198.17.255.255",
		"198.20.0.1",
		"fc00:4000::1",
		"fd00::1",
	}
	tb.RecordDNS("real.example.com", realIPs, 300, now)
	for _, ip := range realIPs {
		if e, ok := tb.Lookup(ip, now); !ok || e.Name != "real.example.com" {
			t.Errorf("legitimate IP %s should be recorded, got %+v ok=%v", ip, e, ok)
		}
	}
}
