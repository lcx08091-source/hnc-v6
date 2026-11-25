package capture

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestIfacePatternsAndCGNAT_RC2(t *testing.T) {
	// AP name matches
	for _, ap := range []string{"ap_br_wlan2", "ap_br_ap0", "wigig0", "ap0", "softap0", "swlan0", "wlan2"} {
		if rankAPName(ap) < 0 {
			t.Errorf("expected AP name match for %q", ap)
		}
	}
	if rankAPName("ap_br_wlan2") >= rankAPName("wlan2") {
		t.Errorf("ap_br_wlan2 should rank ahead of generic wlan2")
	}

	// Excluded cellular / CLAT / 464XLAT / OEM & VPN virtual interfaces
	for _, ex := range []string{
		"sipa_eth0", "sipa_eth", "seth_lte0", "seth_nr",
		"gti0", "gti", "v4-rmnet_data0", "r_rmnet_data0", "clat4", "clat",
		"vgate0", "vgate", "veth0", "veth_abc123", "Meta", "meta0", "sing_tun0", "tailscale0",
	} {
		if !isExcluded(ex) {
			t.Errorf("expected %q to be excluded from AP candidates", ex)
		}
	}

	// Without HNC hint or ARP clients, an unrecognized interface name with RFC1918 IP must not become an AP candidate.
	candsNoHint := filterAndSortAPCandidates([]apIfaceInput{
		{Name: "vgate0", Index: 31, Flags: net.FlagUp, IPv4: "10.88.0.1"},
		{Name: "oem_vir0", Index: 32, Flags: net.FlagUp, IPv4: "192.168.200.1"},
	}, "", map[string]bool{}, map[string]bool{})
	if len(candsNoHint) != 0 {
		t.Fatalf("expected virtual/unknown RFC1918 interfaces without hint/ARP to be rejected, got %+v", candsNoHint)
	}

	// CGNAT 100.64.0.0/10 private IPv4 support
	trueIPs := []string{"100.64.0.1", "100.100.43.1", "100.127.255.254", "10.0.0.1", "172.16.0.1", "192.168.188.1"}
	for _, s := range trueIPs {
		if !isRFC1918(net.ParseIP(s)) {
			t.Errorf("expected %s to be accepted as private/CGNAT IPv4", s)
		}
	}
	falseIPs := []string{"100.63.255.255", "100.128.0.1", "8.8.8.8", "172.32.0.1"}
	for _, s := range falseIPs {
		if isRFC1918(net.ParseIP(s)) {
			t.Errorf("expected %s to be rejected as public IPv4", s)
		}
	}
}

func TestSelfIfacePatterns_RC2(t *testing.T) {
	for _, cell := range []string{"rmnet_data0", "ccmni0", "wwan0", "sipa_eth0", "seth_lte0", "gti0"} {
		if !matchAny(selfPositivePatterns, cell) || !isCellularSelfIface(cell) {
			t.Errorf("expected cellular self-iface match & IsCell=true for %q", cell)
		}
		if matchAny(selfNegativePatterns, cell) {
			t.Errorf("cellular self-iface %q must not match selfNegativePatterns", cell)
		}
	}

	for _, neg := range []string{"ap_br_wlan2", "wigig0", "wigig", "rndis0", "ncm0", "bt-pan", "bt-pan0", "p2p-wlan0-0", "p2p0"} {
		if !matchAny(selfNegativePatterns, neg) {
			t.Errorf("expected %q to match selfNegativePatterns", neg)
		}
	}
}

func buildRtNetlinkMsg(dstLen, rtmType uint8, oif int32) []byte {
	var attr []byte
	if oif > 0 {
		attr = make([]byte, 8)
		binary.LittleEndian.PutUint16(attr[0:2], 8)
		binary.LittleEndian.PutUint16(attr[2:4], rtaOif)
		binary.LittleEndian.PutUint32(attr[4:8], uint32(oif))
	}
	msgLen := rtNlHdrLen + rtMsgHdrLen + len(attr)
	msg := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint16(msg[4:6], syscall.RTM_NEWROUTE)
	binary.LittleEndian.PutUint16(msg[6:8], 0x0002)
	msg[rtNlHdrLen] = syscall.AF_INET
	msg[rtNlHdrLen+1] = dstLen
	msg[rtNlHdrLen+4] = 252 // custom Android per-network table ID
	msg[rtNlHdrLen+7] = rtmType
	copy(msg[rtNlHdrLen+rtMsgHdrLen:], attr)
	return msg
}

func TestDualSTADefaultRouteExclusion_RC2(t *testing.T) {
	// 1. Verify RTM_GETROUTE parser catches Dual-STA wlan1 (ifindex=7) default route,
	// while ignoring /24 hotspot subnet route on wlan2 (ifindex=9) and RTN_UNREACHABLE.
	doneMsg := make([]byte, rtNlHdrLen)
	binary.LittleEndian.PutUint32(doneMsg[0:4], rtNlHdrLen)
	binary.LittleEndian.PutUint16(doneMsg[4:6], syscall.NLMSG_DONE)

	var stream []byte
	stream = append(stream, buildRtNetlinkMsg(0, syscall.RTN_UNICAST, 7)...)     // Dual-STA wlan1 default route
	stream = append(stream, buildRtNetlinkMsg(24, syscall.RTN_UNICAST, 9)...)    // Hotspot /24 subnet route on wlan2
	stream = append(stream, buildRtNetlinkMsg(0, syscall.RTN_UNREACHABLE, 11)...) // Unreachable policy rule
	stream = append(stream, doneMsg...)

	defIdx := map[int]bool{}
	done, err := parseRouteMsgsDefaultIfindices(stream, defIdx)
	if err != nil || !done {
		t.Fatalf("parseRouteMsgsDefaultIfindices: done=%v err=%v", done, err)
	}
	if !defIdx[7] || defIdx[9] || defIdx[11] {
		t.Fatalf("unexpected default-route ifindices: %v", defIdx)
	}

	// 2. Verify /proc/net/route parser.
	procRoute := "" +
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"wlan1\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"wlan2\t002BA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
	procMap := parseProcNetRouteDefaultIfaces(strings.NewReader(procRoute))
	if !procMap["wlan1"] || procMap["wlan2"] {
		t.Fatalf("unexpected /proc/net/route default ifaces: %v", procMap)
	}

	// 3. Verify Dual-STA secondary Wi-Fi wlan1 (even with RFC1918 + ARP gateway entry)
	// is excluded when holding a default route, whereas real AP wlan2 is selected.
	inputs := []apIfaceInput{
		{Name: "wlan0", Index: 6, Flags: net.FlagUp, IPv4: "192.168.1.10", IsWireless: true},
		{Name: "wlan1", Index: 7, Flags: net.FlagUp, IPv4: "192.168.2.15", IsWireless: true}, // Dual-STA secondary STA
		{Name: "wlan2", Index: 9, Flags: net.FlagUp, IPv4: "100.64.43.1", IsWireless: true},  // Real hotspot AP on CGNAT
	}
	arp := map[string]bool{"wlan1": true, "wlan2": true}
	cands := filterAndSortAPCandidates(inputs, "", arp, map[string]bool{"wlan0": true, "wlan1": true})
	if len(cands) != 1 || cands[0].Name != "wlan2" {
		t.Fatalf("expected only real AP wlan2 (Dual-STA wlan1 excluded), got %+v", cands)
	}
}

func TestAtomicHotspotNetsConcurrentSwap_RC2(t *testing.T) {
	old := getHotspotNets()
	t.Cleanup(func() { SetHotspotNets(old) })

	_, netA, _ := net.ParseCIDR("192.168.43.0/24")
	_, netB, _ := net.ParseCIDR("192.168.189.0/24")
	SetHotspotNets([]*net.IPNet{netA})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			if i%2 == 0 {
				SetHotspotNets([]*net.IPNet{netA})
			} else {
				SetHotspotNets([]*net.IPNet{netB})
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			ev := Event{
				SrcIP:  net.IPv4(93, 184, 216, 34),
				DstIP:  net.IPv4(192, 168, 189, 22),
				SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5},
				DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11},
			}
			assignClient(&ev, false)
			_ = hintSrcIPOK(ev)
		}
	}()
	wg.Wait()

	SetHotspotNets([]*net.IPNet{netB})
	ev := Event{
		SrcIP:  net.IPv4(93, 184, 216, 34),
		DstIP:  net.IPv4(192, 168, 189, 22),
		SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11},
	}
	assignClient(&ev, false)
	if !ev.ClientIP.Equal(net.IPv4(192, 168, 189, 22)) {
		t.Fatalf("expected randomized subnet client 192.168.189.22 after hot swap, got %v", ev.ClientIP)
	}
}
