package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"hnc.io/dpid/ifacehint" // v5.26 T5: 网卡名唯一权威出口
)

const hncHotspotIfaceFile = "/data/local/hnc/run/hotspot_iface"

// Interfaces in this list are never selected unless explicitly provided by HNC hint/config.
var excludedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^lo$`),
	regexp.MustCompile(`^dummy\d*$`),
	regexp.MustCompile(`^ifb\d*$`),
	regexp.MustCompile(`^tun\d*$`),
	regexp.MustCompile(`^vpn\d*$`),
	regexp.MustCompile(`^vgate\d*$`),
	regexp.MustCompile(`^veth.*$`),
	regexp.MustCompile(`^(?i)meta\d*$`),
	regexp.MustCompile(`^sing_tun\d*$`),
	regexp.MustCompile(`^tailscale\d*$`),
	regexp.MustCompile(`^rmnet.*$`),
	regexp.MustCompile(`^r_rmnet.*$`),
	regexp.MustCompile(`^ccmni\d*$`),
	regexp.MustCompile(`^wwan\d*$`),
	regexp.MustCompile(`^sipa_eth\d*$`),
	regexp.MustCompile(`^seth_[a-z]+\d*$`),
	regexp.MustCompile(`^gti\d*$`),
	regexp.MustCompile(`^v4-.*$`),
	regexp.MustCompile(`^clat.*$`),
	regexp.MustCompile(`^wlan0$`), // usually STA/upstream Wi-Fi, not hotspot AP
}

var apNamePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^ap_br_[a-z0-9_]+$`),
	regexp.MustCompile(`^ap\d*$`),
	regexp.MustCompile(`^softap\d*$`),
	regexp.MustCompile(`^swlan\d+$`),
	regexp.MustCompile(`^wigig\d+$`),
	regexp.MustCompile(`^wlan[1-9]\d*$`),
}

type IfaceCandidate struct {
	Name       string `json:"name"`
	Index      int    `json:"index"`
	IPv4       string `json:"ipv4,omitempty"`
	HasClients bool   `json:"has_clients"`
	IsWireless bool   `json:"is_wireless"`
	NameRank   int    `json:"name_rank"`
	Reason     string `json:"reason"`
}

type apIfaceInput struct {
	Name       string
	Index      int
	Flags      net.Flags
	IPv4       string
	IsWireless bool
}

func DiscoverAPCandidates() ([]IfaceCandidate, error) {
	hintName := readHNCHint()
	arp := readARPClients()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	defaultRouteIfaces := collectDefaultRouteIfaces(ifaces)
	inputs := make([]apIfaceInput, 0, len(ifaces))
	for _, ifc := range ifaces {
		inputs = append(inputs, apIfaceInput{
			Name:       ifc.Name,
			Index:      ifc.Index,
			Flags:      ifc.Flags,
			IPv4:       firstRFC1918(ifc),
			IsWireless: isWireless(ifc.Name),
		})
	}

	return filterAndSortAPCandidates(inputs, hintName, arp, defaultRouteIfaces), nil
}

func filterAndSortAPCandidates(
	ifaces []apIfaceInput,
	hintName string,
	arp map[string]bool,
	defaultRouteIfaces map[string]bool,
) []IfaceCandidate {
	var out []IfaceCandidate

	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}

		isHint := hintName != "" && hintName == ifc.Name
		// Exclude non-AP upstream interfaces as well as Dual-STA secondary Wi-Fi
		// interfaces (e.g. wlan1 holding a default route in a per-network table).
		if !isHint && (isExcluded(ifc.Name) || defaultRouteIfaces[ifc.Name]) {
			continue
		}

		ipv4 := ifc.IPv4
		nameRank := rankAPName(ifc.Name)
		isWifi := ifc.IsWireless
		hasClients := arp[ifc.Name]

		if !isHint && !hasClients && nameRank < 0 {
			continue
		}

		var reasons []string
		if isHint {
			reasons = append(reasons, "hnc_hint")
		}
		if nameRank >= 0 {
			reasons = append(reasons, "name_match")
		}
		if hasClients {
			reasons = append(reasons, "arp_clients")
		}
		if ipv4 != "" {
			reasons = append(reasons, "rfc1918")
		}
		if isWifi {
			reasons = append(reasons, "wireless")
		}

		out = append(out, IfaceCandidate{
			Name:       ifc.Name,
			Index:      ifc.Index,
			IPv4:       ipv4,
			HasClients: hasClients,
			IsWireless: isWifi,
			NameRank:   nameRank,
			Reason:     strings.Join(reasons, ","),
		})
	}

	// Sorting: HNC hint > AP name rank > ARP clients > RFC1918/CGNAT > wireless > name.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		ahint := strings.Contains(a.Reason, "hnc_hint")
		bhint := strings.Contains(b.Reason, "hnc_hint")
		if ahint != bhint {
			return ahint
		}

		ar, br := a.NameRank, b.NameRank
		if ar < 0 {
			ar = 999
		}
		if br < 0 {
			br = 999
		}
		if ar != br {
			return ar < br
		}
		if a.HasClients != b.HasClients {
			return a.HasClients
		}
		if (a.IPv4 != "") != (b.IPv4 != "") {
			return a.IPv4 != ""
		}
		if a.IsWireless != b.IsWireless {
			return a.IsWireless
		}
		return a.Name < b.Name
	})

	return out
}

func isExcluded(name string) bool {
	for _, re := range excludedPatterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// readHNCHint v5.26 T5: 改走 ifacehint.Read —— 优先 hnc_iface.sh 的
// iface_detect.json(10 分钟内新鲜), 回退 hotspot_iface(校验逻辑已挪进
// ifacehint.validIface, 与原实现一致)。DiscoverAPCandidates 自有的
// 排序扫描仍是 ok=false 时的兜底。
func readHNCHint() string {
	s, _ := ifacehint.Read(filepath.Dir(hncHotspotIfaceFile), time.Now())
	return s
}

func firstRFC1918(ifc net.Interface) string {
	addrs, err := ifc.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		if isRFC1918(v4) {
			return v4.String()
		}
	}
	return ""
}

// isRFC1918 reports whether ip is a private IPv4 address suitable for a local
// hotspot subnet: RFC 1918 (10/8, 172.16/12, 192.168/16) or RFC 6598 CGNAT
// (100.64.0.0/10).
func isRFC1918(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 10 ||
		(v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31) ||
		(v4[0] == 192 && v4[1] == 168) ||
		(v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127)
}

func readARPClients() map[string]bool {
	out := make(map[string]bool)
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return out
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 || fields[2] == "0x0" || fields[3] == "00:00:00:00:00:00" {
			continue
		}
		out[fields[5]] = true
	}
	return out
}

func isWireless(name string) bool {
	if _, err := os.Stat(filepath.Join("/sys/class/net", name, "wireless")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", name, "phy80211")); err == nil {
		return true
	}
	return false
}

func rankAPName(name string) int {
	n := strings.ToLower(name)
	for i, re := range apNamePatterns {
		if re.MatchString(n) {
			return i
		}
	}
	return -1
}

// ─── Default-route upstream detector (Dual-STA wlan1 exclusion) ──────────────

const (
	rtNlHdrLen    = 16
	rtMsgHdrLen   = 12 // struct rtmsg
	rtNlaHdrLen   = 4
	rtNlaTypeMask = 0x3fff

	rtaDst       = 1
	rtaOif       = 4
	rtaMultipath = 9
	rtnhHdrLen   = 8 // struct rtnexthop: len(2)+flags(1)+hops(1)+ifindex(4)
)

// collectDefaultRouteIfaces gathers interfaces carrying an IPv4/IPv6 unicast
// default route across all routing tables via pure-Go AF_NETLINK RTM_GETROUTE
// (NLM_F_DUMP) plus /proc/net/route fallback. On Android Dual-STA devices,
// secondary STA wlan1 holds a default route in its per-network routing table
// (invisible in /proc/net/route main table) and must not be mistaken for an AP.
func collectDefaultRouteIfaces(ifaces []net.Interface) map[string]bool {
	out := make(map[string]bool, 4)
	if f, err := os.Open("/proc/net/route"); err == nil {
		for k := range parseProcNetRouteDefaultIfaces(f) {
			out[k] = true
		}
		_ = f.Close()
	}

	ifIdxMap := dumpDefaultRouteIfindicesNetlink()
	if len(ifIdxMap) > 0 {
		for _, ifc := range ifaces {
			if ifIdxMap[ifc.Index] {
				out[ifc.Name] = true
			}
		}
	}
	return out
}

func parseProcNetRouteDefaultIfaces(r io.Reader) map[string]bool {
	out := make(map[string]bool, 4)
	sc := bufio.NewScanner(r)
	if !sc.Scan() { // skip header
		return out
	}
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue
		}
		// Destination == 00000000 and Mask == 00000000 -> 0.0.0.0/0
		if fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil {
			continue
		}
		// RTF_UP (0x1) set and RTF_REJECT (0x200) not set.
		if (flags&0x1) != 0 && (flags&0x200) == 0 && fields[0] != "" {
			out[fields[0]] = true
		}
	}
	return out
}

func recvNetlinkRoutePacket(fd int, buf []byte) ([]byte, int, error) {
	const maxNetlinkPkt = 1 << 20
	for {
		peekLen, _, perr := syscall.Recvfrom(fd, buf[:1], syscall.MSG_PEEK|syscall.MSG_TRUNC)
		if errors.Is(perr, syscall.EINTR) {
			continue
		}
		if perr == nil && peekLen > len(buf) {
			alloc := peekLen
			if alloc > maxNetlinkPkt {
				alloc = maxNetlinkPkt
			}
			buf = make([]byte, alloc)
		}
		break
	}
	for {
		n, _, rerr := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(rerr, syscall.EINTR) {
			continue
		}
		return buf, n, rerr
	}
}

func dumpDefaultRouteIfindicesForFamily(fam uint8, seq uint32, buf []byte, out map[int]bool) []byte {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return buf
	}
	defer syscall.Close(fd)

	tv := syscall.Timeval{Sec: 1}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 256<<10)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return buf
	}

	req := make([]byte, rtNlHdrLen+rtMsgHdrLen)
	native := binary.LittleEndian
	native.PutUint32(req[0:4], uint32(len(req)))
	native.PutUint16(req[4:6], syscall.RTM_GETROUTE)
	native.PutUint16(req[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	native.PutUint32(req[8:12], seq)
	req[rtNlHdrLen] = fam

	if err := sendNetlinkRouteReq(fd, req); err != nil {
		return buf
	}
	for {
		var n int
		var rerr error
		buf, n, rerr = recvNetlinkRoutePacket(fd, buf)
		if rerr != nil {
			if errors.Is(rerr, syscall.ENOBUFS) {
				continue
			}
			break
		}
		if n <= 0 {
			break
		}
		done, perr := parseRouteMsgsDefaultIfindicesSeq(buf[:n], seq, out)
		if perr != nil || done {
			break
		}
	}
	return buf
}

func dumpDefaultRouteIfindicesNetlink() map[int]bool {
	out := make(map[int]bool, 4)
	buf := make([]byte, 1<<16)
	for i, fam := range []uint8{syscall.AF_INET, syscall.AF_INET6} {
		buf = dumpDefaultRouteIfindicesForFamily(fam, uint32(i+1), buf, out)
	}
	return out
}

func sendNetlinkRouteReq(fd int, req []byte) error {
	for {
		err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return err
	}
}

func rtAlign4(n int) int {
	return (n + 3) &^ 3
}

func parseRouteMsgsDefaultIfindices(b []byte, out map[int]bool) (done bool, err error) {
	return parseRouteMsgsDefaultIfindicesSeq(b, 0, out)
}

func parseRouteMsgsDefaultIfindicesSeq(b []byte, wantSeq uint32, out map[int]bool) (done bool, err error) {
	native := binary.LittleEndian
	sawNonMulti := false
	for off := 0; off < len(b); {
		rest := len(b) - off
		if rest < rtNlHdrLen {
			return false, errors.New("rtnetlink: truncated nlmsghdr")
		}
		msgLen := int(native.Uint32(b[off : off+4]))
		msgType := native.Uint16(b[off+4 : off+6])
		msgFlags := native.Uint16(b[off+6 : off+8])
		msgSeq := native.Uint32(b[off+8 : off+12])
		if msgLen < rtNlHdrLen || msgLen > rest {
			return false, errors.New("rtnetlink: bad nlmsg_len")
		}
		msg := b[off : off+msgLen]
		step := rtAlign4(msgLen)
		if step <= 0 || off+step > len(b) {
			off = len(b)
		} else {
			off += step
		}

		if wantSeq != 0 && msgSeq != 0 && msgSeq != wantSeq {
			continue
		}

		switch msgType {
		case syscall.NLMSG_NOOP:
			continue
		case syscall.NLMSG_DONE:
			return true, nil
		case syscall.NLMSG_ERROR:
			if len(msg) < rtNlHdrLen+4 {
				return false, errors.New("rtnetlink: truncated nlmsgerr")
			}
			code := int32(native.Uint32(msg[rtNlHdrLen : rtNlHdrLen+4]))
			if code == 0 {
				if msgFlags&syscall.NLM_F_MULTI == 0 {
					sawNonMulti = true
				}
				continue
			}
			if code < 0 {
				return false, syscall.Errno(-code)
			}
			return false, syscall.Errno(code)
		}

		if msgFlags&syscall.NLM_F_MULTI == 0 {
			sawNonMulti = true
		}

		if msgType != syscall.RTM_NEWROUTE || len(msg) < rtNlHdrLen+rtMsgHdrLen {
			continue
		}
		rtm := msg[rtNlHdrLen : rtNlHdrLen+rtMsgHdrLen]
		dstLen := rtm[1]
		rtmType := rtm[7]
		// Only unicast default routes (dst_len == 0 && rtm_type == RTN_UNICAST).
		if dstLen != 0 || rtmType != syscall.RTN_UNICAST {
			continue
		}

		attrs := msg[rtNlHdrLen+rtMsgHdrLen:]
		nonZeroDst := false
		var oifs []int
		for aoff := 0; aoff+rtNlaHdrLen <= len(attrs); {
			alen := int(native.Uint16(attrs[aoff : aoff+2]))
			atype := native.Uint16(attrs[aoff+2:aoff+4]) & rtNlaTypeMask
			if alen < rtNlaHdrLen || aoff+alen > len(attrs) {
				break
			}
			aval := attrs[aoff+rtNlaHdrLen : aoff+alen]
			switch atype {
			case rtaDst:
				for _, db := range aval {
					if db != 0 {
						nonZeroDst = true
						break
					}
				}
			case rtaOif:
				if len(aval) >= 4 {
					idx := int(int32(native.Uint32(aval[:4])))
					if idx > 0 {
						oifs = append(oifs, idx)
					}
				}
			case rtaMultipath:
				for moff := 0; moff+rtnhHdrLen <= len(aval); {
					nhLen := int(native.Uint16(aval[moff : moff+2]))
					if nhLen < rtnhHdrLen || moff+nhLen > len(aval) {
						break
					}
					idx := int(int32(native.Uint32(aval[moff+4 : moff+8])))
					if idx > 0 {
						oifs = append(oifs, idx)
					}
					moff += rtAlign4(nhLen)
				}
			}
			aoff += rtAlign4(alen)
		}
		if !nonZeroDst && out != nil {
			for _, idx := range oifs {
				out[idx] = true
			}
		}
	}
	return sawNonMulti, nil
}

// InterfaceNets returns every IP+mask configured on the named interface.
// Used by rc29 to tell which end of a flow is the hotspot client (the end
// whose IP falls inside one of these nets) vs the outside world.
//
// For IPv4 we exclude /32 (host route). For IPv6 we exclude /128 (host route)
// and global anycast /127 nonsense, AND we exclude link-local (fe80::/10)
// because every IPv6-capable peer has a link-local, so it'd mis-classify.
// We keep ULA (fc00::/7) and global unicast (2000::/3) — these are what
// real hotspot clients get via SLAAC/DHCPv6-PD.
func InterfaceNets(name string) []*net.IPNet {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil
	}
	var out []*net.IPNet
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ones, bits := ipnet.Mask.Size()
		if ones == bits {
			continue // host route
		}
		// Skip IPv6 link-local.
		if ipnet.IP.To4() == nil && ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		// Normalize: ensure IPNet.IP is the network base (no host bits).
		base := ipnet.IP.Mask(ipnet.Mask)
		out = append(out, &net.IPNet{IP: base, Mask: ipnet.Mask})
	}
	return out
}
