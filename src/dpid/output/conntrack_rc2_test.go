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

func TestReadConntrackNetlink_IPv4DeniedWithZeroV6ComplementsFromProcfs(t *testing.T) {
	oldPaths := ConntrackPaths
	oldOpen := openConntrackFileFn
	oldFamDump := dumpCTNetlinkFamilyFn
	t.Cleanup(func() {
		ConntrackPaths = oldPaths
		openConntrackFileFn = oldOpen
		dumpCTNetlinkFamilyFn = oldFamDump
	})

	fakeProc := filepath.Join(t.TempDir(), "nf_conntrack")
	procBody := strings.Join([]string{
		"ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.43.10 dst=93.184.216.34 sport=50001 dport=443 packets=10 bytes=1200 src=93.184.216.34 dst=10.0.0.2 sport=443 dport=50001 packets=12 bytes=8400 [ASSURED] mark=0 use=1",
		"ipv4     2 udp     17 29 src=192.168.43.11 dst=223.5.5.5 sport=53000 dport=53 packets=1 bytes=64 [UNREPLIED] mark=0 use=1",
		"ipv6    10 udp     17 29 src=2409:8a00::20 dst=2400:3200::1 sport=50000 dport=853 packets=1 bytes=96 [UNREPLIED] mark=0 use=1",
	}, "\n") + "\n"
	if err := os.WriteFile(fakeProc, []byte(procBody), 0o644); err != nil {
		t.Fatal(err)
	}
	ConntrackPaths = []string{"/proc/net/nf_conntrack"}
	openConntrackFileFn = func( string) (*os.File, error) {
		return os.Open(fakeProc)
	}

	// 场景 1: AF_UNSPEC 与 AF_INET 均返回 EPERM, AF_INET6 成功但返回 0 条连接(v6OK=true, c6=0)。
	// 此时绝不能因 v6OK 为真而跳过 IPv4 procfs 兜底, 且 procfs 必须补齐全部 2 条 IPv4 连接(不重复解析已被 v6 覆盖的 IPv6)。
	dumpCTNetlinkFamilyFn = func(family uint8, seq uint32, maxLines int, onLine func(string)) (int, error) {
		switch family {
		case syscall.AF_UNSPEC:
			return 0, syscall.EPERM
		case syscall.AF_INET:
			return 0, syscall.EPERM
		case syscall.AF_INET6:
			return 0, nil // v6OK == true 且 0 条
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}

	var gotLines []string
	count, err := readConntrackNetlink(1024, func(line string) {
		gotLines = append(gotLines, line)
	})
	if err != nil {
		t.Fatalf("readConntrackNetlink failed: %v", err)
	}
	if count != 2 || len(gotLines) != 2 {
		t.Fatalf("expected 2 complemented IPv4 lines from procfs, got count=%d lines=%v", count, gotLines)
	}
	if ConntrackOrigDst(gotLines[0]) != "93.184.216.34" || ConntrackOrigDst(gotLines[1]) != "223.5.5.5" {
		t.Fatalf("unexpected complemented IPv4 destinations: %v", gotLines)
	}

	// 场景 2: AF_INET 成功返回 1 条 IPv4 连接, AF_INET6 返回 EPROTONOSUPPORT 失败 -> procfs 仅补齐 1 条 IPv6 连接。
	dumpCTNetlinkFamilyFn = func(family uint8, seq uint32, maxLines int, onLine func(string)) (int, error) {
		switch family {
		case syscall.AF_UNSPEC:
			return 0, syscall.EOPNOTSUPP
		case syscall.AF_INET:
			if onLine != nil {
				onLine("ipv4 2 tcp 6 120 ESTABLISHED src=192.168.43.99 dst=1.1.1.1 sport=41111 dport=443 packets=3 bytes=300 [ASSURED] mark=0 use=1")
			}
			return 1, nil
		case syscall.AF_INET6:
			return 0, syscall.EPROTONOSUPPORT
		default:
			return 0, syscall.EINVAL
		}
	}
	gotLines = nil
	count2, err2 := readConntrackNetlink(1024, func(line string) {
		gotLines = append(gotLines, line)
	})
	if err2 != nil || count2 != 2 || len(gotLines) != 2 {
		t.Fatalf("expected 1 v4 netlink + 1 v6 procfs = 2 flows, got count=%d err=%v lines=%v", count2, err2, gotLines)
	}
	if ConntrackOrigDst(gotLines[0]) != "1.1.1.1" || ConntrackOrigDst(gotLines[1]) != "2400:3200::1" {
		t.Fatalf("unexpected hybrid v4+v6 lines: %v", gotLines)
	}
}

func TestReadConntrackLines_NonPermOpenErrorStillFallsBackToCTNetlink(t *testing.T) {
	oldPaths := ConntrackPaths
	oldOpen := openConntrackFileFn
	oldDump := ctnetlinkDumpFn
	t.Cleanup(func() {
		ConntrackPaths = oldPaths
		openConntrackFileFn = oldOpen
		ctnetlinkDumpFn = oldDump
	})

	ConntrackPaths = []string{"/proc/version"}
	openConntrackFileFn = func(name string) (*os.File, error) {
		return nil, syscall.EINVAL
	}
	ctnetlinkDumpFn = func(maxLines int, onLine func(string)) (int, error) {
		if onLine != nil {
			onLine("ipv4 2 udp 17 30 src=192.168.43.5 dst=8.8.8.8 sport=50000 dport=53 packets=1 bytes=60 [UNREPLIED] mark=0 use=1")
		}
		return 1, nil
	}

	r := ReadConntrackLines(nil)
	if !r.Available || !r.Readable || r.Path != ConntrackNetlinkPath || r.Flows != 1 {
		t.Fatalf("expected EINVAL open error on /proc to fall back to CTNETLINK, got %+v", r)
	}
}

func TestClassifyConntrackLines_ZeroClients230HostFlows(t *testing.T) {
	lines := make([]string, 0, 240)
	// Generate 230 active phone-local TCP/UDP IPv4+IPv6 flows (cellular/Wi-Fi).
	for i := 0; i < 180; i++ {
		port := 40000 + i
		dstOctet := (i % 250) + 1
		lines = append(lines,
			"ipv4 2 tcp 6 431999 ESTABLISHED src=10.45.12.8 dst=203.0.113."+itoaTest(dstOctet)+
				" sport="+itoaTest(port)+" dport=443 packets=8 bytes=1024 src=203.0.113."+itoaTest(dstOctet)+
				" dst=10.45.12.8 sport=443 dport="+itoaTest(port)+" packets=9 bytes=4096 [ASSURED] mark=0 use=1",
		)
	}
	for i := 0; i < 50; i++ {
		port := 50000 + i
		lines = append(lines,
			"ipv6 10 udp 17 120 src=2409:8900:10::abcd dst=2400:3200::1 sport="+itoaTest(port)+
				" dport=443 packets=4 bytes=512 src=2400:3200::1 dst=2409:8900:10::abcd sport=443 dport="+itoaTest(port)+
				" packets=4 bytes=1200 [ASSURED] mark=0 use=1",
		)
	}
	// Add loopback and non-TCP/UDP noise that must NOT be counted in either HotspotFlows or HostFlows.
	lines = append(lines,
		"ipv4 2 tcp 6 120 ESTABLISHED src=127.0.0.1 dst=127.0.0.1 sport=49100 dport=8444 packets=2 bytes=128 src=127.0.0.1 dst=127.0.0.1 sport=8444 dport=49100 packets=2 bytes=256 [ASSURED] mark=0 use=1",
		"ipv4 2 udp 17 29 src=127.0.53.53 dst=127.0.0.1 sport=53100 dport=53 packets=1 bytes=60 [UNREPLIED] mark=0 use=1",
		"ipv6 10 tcp 6 120 ESTABLISHED src=::1 dst=::1 sport=55100 dport=8080 packets=2 bytes=128 src=::1 dst=::1 sport=8080 dport=55100 packets=2 bytes=128 [ASSURED] mark=0 use=1",
		"ipv4 2 icmp 1 29 src=10.45.12.8 dst=8.8.8.8 type=8 code=0 id=123 packets=1 bytes=84 [UNREPLIED] mark=0 use=1",
	)

	// Case A: Hotspot enabled, 0 downstream clients online -> HotspotFlows == 0, HostFlows == 230.
	gotZeroOnline := ClassifyConntrackLines(lines, ConntrackFlowOptions{
		HotspotActive: true,
		Clients:       nil,
	})
	if gotZeroOnline.HotspotFlows != 0 || gotZeroOnline.HostFlows != 230 || gotZeroOnline.LoopbackFlows != 3 {
		t.Fatalf("0 online clients mismatch: got %+v, want HotspotFlows=0 HostFlows=230 LoopbackFlows=3", gotZeroOnline)
	}

	// Case B: Hotspot disabled (even if stale client list is passed) -> HotspotFlows == 0, HostFlows == 230.
	gotHotspotOff := ClassifyConntrackLines(lines, ConntrackFlowOptions{
		HotspotActive: false,
		Clients: []ConntrackClient{
			{MAC: "3c:22:fb:11:22:33", IPs: []string{"192.168.43.20"}},
		},
	})
	if gotHotspotOff.HotspotFlows != 0 || gotHotspotOff.HostFlows != 230 {
		t.Fatalf("hotspot off mismatch: got %+v, want HotspotFlows=0 HostFlows=230", gotHotspotOff)
	}
}

func TestClassifyConntrackLines_OrthogonalHotspotAndHostFlows(t *testing.T) {
	_, hsNet, _ := net.ParseCIDR("192.168.43.0/24")
	lines := []string{
		// 3 downstream forwarding flows (client 1 IPv4 TCP 443, client 1 IPv4 TCP public :8080, client 2 IPv6 UDP 443):
		"ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.43.20 dst=93.184.216.34 sport=51001 dport=443 packets=10 bytes=1200 src=93.184.216.34 dst=10.45.12.8 sport=443 dport=51001 packets=12 bytes=8400 [ASSURED] mark=0 use=1",
		"ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.43.20 dst=198.51.100.77 sport=51002 dport=8080 packets=5 bytes=600 src=198.51.100.77 dst=10.45.12.8 sport=8080 dport=51002 packets=5 bytes=2400 [ASSURED] mark=0 use=1",
		"ipv6 10 udp 17 120 src=2409:8a00:1::88 dst=2400:3200::1 sport=52001 dport=443 packets=6 bytes=900 src=2400:3200::1 dst=2409:8a00:1::88 sport=443 dport=52001 packets=8 bytes=3200 [ASSURED] mark=0 use=1",

		// 6 pure gateway management flows (:53, :67, :68, :8443, :8444, :8080 to local gateway) -> excluded from both!
		"ipv4 2 udp 17 29 src=192.168.43.20 dst=192.168.43.1 sport=53001 dport=53 packets=1 bytes=64 src=192.168.43.1 dst=192.168.43.20 sport=53 dport=53001 packets=1 bytes=128 mark=0 use=1",
		"ipv4 2 udp 17 29 src=192.168.43.20 dst=192.168.43.1 sport=68 dport=67 packets=1 bytes=300 [UNREPLIED] mark=0 use=1",
		"ipv4 2 udp 17 29 src=192.168.43.1 dst=192.168.43.20 sport=67 dport=68 packets=1 bytes=300 [UNREPLIED] mark=0 use=1",
		"ipv4 2 tcp 6 120 ESTABLISHED src=192.168.43.20 dst=192.168.43.1 sport=54001 dport=8443 packets=8 bytes=1200 src=192.168.43.1 dst=192.168.43.20 sport=8443 dport=54001 packets=9 bytes=4200 [ASSURED] mark=0 use=1",
		"ipv4 2 tcp 6 120 ESTABLISHED src=192.168.43.20 dst=192.168.43.1 sport=54002 dport=8444 packets=4 bytes=500 src=192.168.43.1 dst=192.168.43.20 sport=8444 dport=54002 packets=4 bytes=900 [ASSURED] mark=0 use=1",
		"ipv4 2 tcp 6 120 ESTABLISHED src=192.168.43.20 dst=192.168.43.1 sport=54003 dport=8080 packets=4 bytes=500 src=192.168.43.1 dst=192.168.43.20 sport=8080 dport=54003 packets=4 bytes=900 [ASSURED] mark=0 use=1",

		// 1 lingering flow from an offline hotspot client (192.168.43.99) -> neither HotspotFlows nor HostFlows:
		"ipv4 2 tcp 6 300 ESTABLISHED src=192.168.43.99 dst=93.184.216.34 sport=59999 dport=443 packets=2 bytes=120 [ASSURED] mark=0 use=1",

		// 4 phone-local active non-loopback flows (including phone's own upstream DNS :53):
		"ipv4 2 tcp 6 431999 ESTABLISHED src=10.45.12.8 dst=1.1.1.1 sport=41001 dport=443 packets=12 bytes=1800 [ASSURED] mark=0 use=1",
		"ipv4 2 udp 17 29 src=10.45.12.8 dst=223.5.5.5 sport=41002 dport=53 packets=1 bytes=64 [ASSURED] mark=0 use=1",
		"ipv6 10 tcp 6 431999 ESTABLISHED src=2409:8900:10::abcd dst=2606:4700:4700::1111 sport=41003 dport=443 packets=5 bytes=800 [ASSURED] mark=0 use=1",
		"tcp 6 120 ESTABLISHED src=192.168.1.55 dst=198.51.100.12 sport=41004 dport=443 packets=3 bytes=450 [ASSURED] use=1",

		// 2 loopback flows -> excluded:
		"ipv4 2 tcp 6 120 ESTABLISHED src=127.0.0.1 dst=127.0.0.1 sport=39001 dport=9090 packets=2 bytes=100 [ASSURED] mark=0 use=1",
		"ipv6 10 tcp 6 120 ESTABLISHED src=::1 dst=::1 sport=39002 dport=9090 packets=2 bytes=100 [ASSURED] mark=0 use=1",
	}

	got := ClassifyConntrackLines(lines, ConntrackFlowOptions{
		HotspotActive: true,
		Clients: []ConntrackClient{
			{MAC: "3c:22:fb:11:22:33", IPs: []string{"192.168.43.20"}},
			{MAC: "AA:BB:CC:DD:EE:02", IPs: []string{"2409:8a00:1::88"}},
		},
		InactiveClientIPs: []string{"192.168.43.99"},
		GatewayIPs:        []string{"192.168.43.1", "fe80::1"},
		HotspotNets:       []*net.IPNet{hsNet},
	})

	if got.HotspotFlows != 3 {
		t.Fatalf("HotspotFlows=%d, want 3 (got=%+v)", got.HotspotFlows, got)
	}
	if got.MgmtExcluded != 6 {
		t.Fatalf("MgmtExcluded=%d, want 6 (got=%+v)", got.MgmtExcluded, got)
	}
	if got.HostFlows != 4 {
		t.Fatalf("HostFlows=%d, want 4 (got=%+v)", got.HostFlows, got)
	}
	if got.LoopbackFlows != 2 {
		t.Fatalf("LoopbackFlows=%d, want 2 (got=%+v)", got.LoopbackFlows, got)
	}
	if got.PerClientFlows["3c:22:fb:11:22:33"] != 2 || got.PerClientFlows["aa:bb:cc:dd:ee:02"] != 1 {
		t.Fatalf("unexpected PerClientFlows: %+v", got.PerClientFlows)
	}
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

