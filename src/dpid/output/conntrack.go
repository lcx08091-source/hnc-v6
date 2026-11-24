// Package output - conntrack.go: read /proc/net/nf_conntrack and count flows.
//
// Android caveat: many Android kernels disable the conntrack export (or
// gate it behind a SELinux denial); we treat any open/read error as
// "not readable" and simply report ConntrackFlows=0 with ConntrackReadable=false.
// This is the rc28.1.1 contract that WebUI already understands.

package output

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// ConntrackNetlinkPath identifies the pure-Go CTNETLINK fallback source.
const ConntrackNetlinkPath = "netlink:ctnetlink"

// ConntrackPaths is the canonical lookup order. On modern kernels only the
// first exists.
var ConntrackPaths = []string{
	"/proc/net/nf_conntrack",
	"/proc/net/ip_conntrack",
}

// Hooks for unit testing /proc permission errors and netlink fallback without
// touching the host kernel when custom non-/proc paths are configured.
var (
	openConntrackFileFn   = os.Open
	ctnetlinkDumpFn       = readConntrackNetlink
	dumpCTNetlinkFamilyFn = dumpCTNetlinkFamily
)

type ConntrackReport struct {
	Available bool   // file or netlink source exists
	Readable  bool   // we could open/dump + scan it
	Path      string // which path/source we used
	Flows     int    // number of conntrack entries
}

func usesDefaultProcPaths(paths []string) bool {
	if len(paths) == 0 {
		return false
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/proc/") {
			return false
		}
	}
	return true
}

func isConntrackPermErr(err error) bool {
	return errors.Is(err, os.ErrPermission) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPERM)
}

// parseProcConntrackFamily 识别一行 /proc/net/{nf,ip}_conntrack 所属协议族("ipv4" 或 "ipv6")。
// 兼容现代 nf_conntrack("ipv4 2 tcp ..." / "ipv6 10 udp ...")与旧版 ip_conntrack("tcp 6 ...")。
func parseProcConntrackFamily(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return "", false
	}
	end := 0
	for end < len(line) && line[end] != ' ' && line[end] != '\t' {
		end++
	}
	tok := strings.ToLower(line[:end])
	switch tok {
	case "ipv4":
		return "ipv4", true
	case "ipv6":
		return "ipv6", true
	case "tcp", "udp", "icmp", "gre", "sctp", "udplite", "unknown":
		// 旧式 /proc/net/ip_conntrack 仅含 IPv4 记录且省略首列协议族。
		return "ipv4", true
	default:
		if strings.Contains(line, " src=") && strings.Contains(line, " dst=") {
			if dst := conntrackOrigDst(line); dst != "" {
				if ip := net.ParseIP(dst); ip != nil {
					if ip.To4() != nil {
						return "ipv4", true
					}
					return "ipv6", true
				}
			}
		}
		return "", false
	}
}

// parseProcConntrack 扫描 procfs 连接表并按 wantV4 / wantV6 过滤协议族(两者皆真时全量解析)。
func parseProcConntrack(r io.Reader, wantV4, wantV6 bool, maxLines int, onLine func(string)) (int, error) {
	if !wantV4 && !wantV6 {
		return 0, nil
	}
	if maxLines <= 0 {
		maxLines = 1 << 16
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	count := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if !wantV4 || !wantV6 {
			fam, ok := parseProcConntrackFamily(line)
			if !ok {
				continue
			}
			if fam == "ipv4" && !wantV4 {
				continue
			}
			if fam == "ipv6" && !wantV6 {
				continue
			}
		}
		count++
		if onLine != nil {
			onLine(line)
		}
		if count >= maxLines {
			break
		}
	}
	return count, sc.Err()
}

// readProcConntrackFamilies 在部分协议族 CTNETLINK 受限时回退读取 procfs 补齐缺失协议族。
func readProcConntrackFamilies(paths []string, wantV4, wantV6 bool, maxLines int, onLine func(string)) (int, bool) {
	if (!wantV4 && !wantV6) || maxLines <= 0 {
		return 0, false
	}
	for _, p := range paths {
		f, err := openConntrackFileFn(p)
		if err != nil {
			continue
		}
		n, scanErr := parseProcConntrack(f, wantV4, wantV6, maxLines, onLine)
		_ = f.Close()
		if scanErr == nil || n > 0 {
			return n, true
		}
	}
	return 0, false
}

// ReadConntrackLines scans the first available conntrack export and returns
// the entry count (capped at maxConntrackLines); when onLine != nil, invokes
// it on each non-empty non-comment conntrack line.
//
// When default /proc/net/*_conntrack paths are missing or fail on open/read,
// automatically falls back to pure-Go AF_NETLINK (NETLINK_NETFILTER,
// IPCTNL_MSG_CT_GET | NLM_F_DUMP). Custom non-/proc paths passed by tests
// never touch the host kernel.
func ReadConntrackLines(onLine func(line string)) ConntrackReport {
	const maxConntrackLines = 1 << 16 // 65536 flows ought to be enough

	allowNetlink := usesDefaultProcPaths(ConntrackPaths)
	var r ConntrackReport
	var partialCount int

	for _, p := range ConntrackPaths {
		if _, err := os.Stat(p); err != nil {
			if isConntrackPermErr(err) {
				r.Available = true
				r.Path = p
			}
			continue
		}
		// File exists; available=true regardless of whether we can read it.
		r.Available = true
		r.Path = p

		f, err := openConntrackFileFn(p)
		if err != nil {
			// 无论返回 EACCES/EPERM 还是 ENOENT/EINVAL/ENOSYS, 继续尝试备选路径并在循环后回退 CTNETLINK。
			continue
		}

		count, scanErr := parseProcConntrack(f, true, true, maxConntrackLines, onLine)
		_ = f.Close()

		if scanErr != nil {
			if count > partialCount {
				partialCount = count
			}
			if !allowNetlink {
				r.Readable = count > 0
				r.Flows = count
				return r
			}
			// 读取中途或首口即遇 SELinux/权限报错(如 open 成功但 read EACCES): 继续尝试兜底。
			if count == 0 {
				continue
			}
			r.Readable = true
			r.Flows = count
			return r
		}
		r.Readable = true
		r.Flows = count
		return r
	}

	if allowNetlink && ctnetlinkDumpFn != nil {
		if count, err := ctnetlinkDumpFn(maxConntrackLines, onLine); err == nil {
			return ConntrackReport{
				Available: true,
				Readable:  true,
				Path:      ConntrackNetlinkPath,
				Flows:     count,
			}
		}
	}
	if partialCount > 0 {
		r.Readable = true
		r.Flows = partialCount
	}
	return r
}

// ProbeConntrackNetlink checks whether CTNETLINK conntrack dump is permitted
// and supported on the running kernel.
func ProbeConntrackNetlink() bool {
	_, err := readConntrackNetlink(1, nil)
	return err == nil
}

// ─── Pure-Go CTNETLINK (NETLINK_NETFILTER) reader ────────────────────────────

const (
	nfnlSubsysCTNetlink = 1
	ipctnlMsgCTNew      = 0
	ipctnlMsgCTGet      = 1

	ctnlMsgGet = (nfnlSubsysCTNetlink << 8) | ipctnlMsgCTGet // 0x0101

	ctNlHdrLen    = 16
	ctNfGenMsgLen = 4
	ctNlAlignTo   = 4
	ctNlaHdrLen   = 4
	ctNlaTypeMask = 0x3fff

	// enum ctattr_type
	ctaTupleOrig     = 1
	ctaTupleReply    = 2
	ctaStatus        = 3
	ctaProtoInfo     = 4
	ctaTimeout       = 7
	ctaMark          = 8
	ctaCountersOrig  = 9
	ctaCountersReply = 10
	ctaUse           = 11

	// enum ctattr_tuple
	ctaTupleIP    = 1
	ctaTupleProto = 2

	// enum ctattr_ip
	ctaIPV4Src = 1
	ctaIPV4Dst = 2
	ctaIPV6Src = 3
	ctaIPV6Dst = 4

	// enum ctattr_l4proto
	ctaProtoNum     = 1
	ctaProtoSrcPort = 2
	ctaProtoDstPort = 3

	// enum ctattr_protoinfo / ctattr_protoinfo_tcp
	ctaProtoInfoTCP      = 1
	ctaProtoInfoTCPState = 1

	// enum ctattr_counters
	ctaCountersPackets   = 1
	ctaCountersBytes     = 2
	ctaCounters32Packets = 3
	ctaCounters32Bytes   = 4

	// enum ip_conntrack_status
	ipsSeenReply = 1 << 1
	ipsAssured   = 1 << 2
)

type ctTuple struct {
	srcIP   net.IP
	dstIP   net.IP
	proto   uint8
	srcPort uint16
	dstPort uint16
	hasPort bool
}

type ctCounters struct {
	packets uint64
	bytes   uint64
}

type ctEntryData struct {
	family    uint8
	orig      ctTuple
	reply     ctTuple
	hasReply  bool
	origCnt   ctCounters
	replyCnt  ctCounters
	status    uint32
	timeout   uint32
	mark      uint32
	use       uint32
	tcpState  uint8
	hasTCPSt  bool
}

func readConntrackNetlink(maxLines int, onLine func(string)) (int, error) {
	if maxLines <= 0 {
		maxLines = 1 << 16
	}
	count, err := dumpCTNetlinkFamilyFn(syscall.AF_UNSPEC, 1, maxLines, onLine)
	if err == nil {
		return count, nil
	}

	// AF_UNSPEC 失败(如旧内核不支持 AF_UNSPEC 或部分协议族模块/SELinux 受限)时,
	// 分别独立尝试 AF_INET 与 AF_INET6; 若任一协议族失败(即使另一族成功但仅返回 0 条),
	// 必须回退读取 procfs 解析补齐缺失的协议族, 严禁静默丢弃全部 IPv4 或 IPv6 连接。
	c4, err4 := dumpCTNetlinkFamilyFn(syscall.AF_INET, 2, maxLines, onLine)
	v4OK := err4 == nil
	if !v4OK {
		c4 = 0
	}

	var c6 int
	v6OK := false
	rem := maxLines - c4
	if rem > 0 {
		var err6 error
		c6, err6 = dumpCTNetlinkFamilyFn(syscall.AF_INET6, 3, rem, onLine)
		v6OK = err6 == nil
		if !v6OK {
			c6 = 0
		}
	} else {
		v6OK = true
	}

	total := c4 + c6
	if (!v4OK || !v6OK) && total < maxLines {
		procCount, procOK := readProcConntrackFamilies(ConntrackPaths, !v4OK, !v6OK, maxLines-total, onLine)
		if procOK {
			total += procCount
			if !v4OK {
				v4OK = true
			}
			if !v6OK {
				v6OK = true
			}
		}
	}

	if v4OK || v6OK {
		return total, nil
	}
	if err4 != nil {
		return 0, err4
	}
	return 0, err
}

func dumpCTNetlinkFamily(family uint8, seq uint32, maxLines int, onLine func(string)) (int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_NETFILTER)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	tv := syscall.Timeval{Sec: 2}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 512<<10)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, err
	}

	req := buildCTNetlinkDumpReq(family, seq)
	for {
		err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		break
	}

	count := 0
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			if errors.Is(err, syscall.ENOBUFS) && count > 0 {
				return count, nil
			}
			return count, err
		}
		if n <= 0 {
			return count, errors.New("ctnetlink: empty recv")
		}
		done, perr := parseCTNetlinkMsgs(buf[:n], func(line string) bool {
			count++
			if onLine != nil {
				onLine(line)
			}
			return count < maxLines
		})
		if perr != nil {
			return count, perr
		}
		if done {
			return count, nil
		}
	}
}

func buildCTNetlinkDumpReq(family uint8, seq uint32) []byte {
	req := make([]byte, ctNlHdrLen+ctNfGenMsgLen)
	native := binary.LittleEndian
	native.PutUint32(req[0:4], uint32(len(req)))
	native.PutUint16(req[4:6], ctnlMsgGet)
	native.PutUint16(req[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	native.PutUint32(req[8:12], seq)
	req[ctNlHdrLen] = family // nfgen_family
	req[ctNlHdrLen+1] = 0    // NFNETLINK_V0
	return req
}

func ctAlign4(n int) int {
	return (n + ctNlAlignTo - 1) &^ (ctNlAlignTo - 1)
}

// parseCTNetlinkMsgs parses a batch of CTNETLINK messages and invokes emit for
// each decoded IPv4/IPv6 conntrack flow. If emit returns false, stops early with
// done=true. Malformed/truncated frames never panic.
func parseCTNetlinkMsgs(b []byte, emit func(line string) bool) (done bool, err error) {
	native := binary.LittleEndian
	for off := 0; off < len(b); {
		rest := len(b) - off
		if rest < ctNlHdrLen {
			return false, errors.New("ctnetlink: truncated nlmsghdr")
		}
		msgLen := int(native.Uint32(b[off : off+4]))
		msgType := native.Uint16(b[off+4 : off+6])
		if msgLen < ctNlHdrLen || msgLen > rest {
			return false, fmt.Errorf("ctnetlink: invalid nlmsg_len %d (rest %d)", msgLen, rest)
		}
		msg := b[off : off+msgLen]
		step := ctAlign4(msgLen)
		if step <= 0 || off+step > len(b) {
			off = len(b)
		} else {
			off += step
		}

		switch msgType {
		case syscall.NLMSG_DONE:
			return true, nil
		case syscall.NLMSG_ERROR:
			if len(msg) < ctNlHdrLen+4 {
				return false, errors.New("ctnetlink: truncated nlmsgerr")
			}
			code := int32(native.Uint32(msg[ctNlHdrLen : ctNlHdrLen+4]))
			if code == 0 {
				continue
			}
			if code < 0 {
				return false, syscall.Errno(-code)
			}
			return false, syscall.Errno(code)
		}

		if (msgType >> 8) != nfnlSubsysCTNetlink {
			continue
		}
		subType := msgType & 0xff
		if subType != ipctnlMsgCTNew && subType != ipctnlMsgCTGet {
			continue
		}
		if len(msg) < ctNlHdrLen+ctNfGenMsgLen {
			return false, errors.New("ctnetlink: truncated nfgenmsg")
		}
		family := msg[ctNlHdrLen]
		entry, ok := parseCTEntryAttrs(family, msg[ctNlHdrLen+ctNfGenMsgLen:])
		if !ok {
			continue
		}
		line := formatCTCompatLine(entry)
		if line != "" && emit != nil {
			if !emit(line) {
				return true, nil
			}
		}
	}
	return false, nil
}

func walkNetlinkAttrs(b []byte, fn func(attrType uint16, val []byte) bool) bool {
	native := binary.LittleEndian
	for off := 0; off+ctNlaHdrLen <= len(b); {
		nlaLen := int(native.Uint16(b[off : off+2]))
		rawType := native.Uint16(b[off+2 : off+4])
		if nlaLen < ctNlaHdrLen || off+nlaLen > len(b) {
			return false
		}
		val := b[off+ctNlaHdrLen : off+nlaLen]
		if !fn(rawType&ctNlaTypeMask, val) {
			return false
		}
		step := ctAlign4(nlaLen)
		if step <= 0 {
			break
		}
		off += step
	}
	return true
}

func parseCTEntryAttrs(family uint8, attrs []byte) (ctEntryData, bool) {
	var e ctEntryData
	e.family = family
	var hasOrig bool

	walkNetlinkAttrs(attrs, func(t uint16, val []byte) bool {
		switch t {
		case ctaTupleOrig:
			if tup, ok := parseCTTuple(val); ok {
				e.orig = tup
				hasOrig = true
				if e.family == 0 {
					if len(tup.srcIP) == 4 {
						e.family = syscall.AF_INET
					} else if len(tup.srcIP) == 16 {
						e.family = syscall.AF_INET6
					}
				}
			}
		case ctaTupleReply:
			if tup, ok := parseCTTuple(val); ok {
				e.reply = tup
				e.hasReply = true
			}
		case ctaStatus:
			if len(val) >= 4 {
				e.status = binary.BigEndian.Uint32(val[:4])
			}
		case ctaTimeout:
			if len(val) >= 4 {
				e.timeout = binary.BigEndian.Uint32(val[:4])
			}
		case ctaMark:
			if len(val) >= 4 {
				e.mark = binary.BigEndian.Uint32(val[:4])
			}
		case ctaUse:
			if len(val) >= 4 {
				e.use = binary.BigEndian.Uint32(val[:4])
			}
		case ctaProtoInfo:
			walkNetlinkAttrs(val, func(pt uint16, pval []byte) bool {
				if pt == ctaProtoInfoTCP {
					walkNetlinkAttrs(pval, func(tt uint16, tval []byte) bool {
						if tt == ctaProtoInfoTCPState && len(tval) >= 1 {
							e.tcpState = tval[0]
							e.hasTCPSt = true
						}
						return true
					})
				}
				return true
			})
		case ctaCountersOrig:
			e.origCnt = parseCTCounters(val)
		case ctaCountersReply:
			e.replyCnt = parseCTCounters(val)
		}
		return true
	})

	if !hasOrig || len(e.orig.srcIP) == 0 || len(e.orig.dstIP) == 0 || e.orig.proto == 0 {
		return e, false
	}
	if e.family != syscall.AF_INET && e.family != syscall.AF_INET6 {
		if e.orig.srcIP.To4() != nil {
			e.family = syscall.AF_INET
		} else {
			e.family = syscall.AF_INET6
		}
	}
	return e, true
}

func parseCTTuple(b []byte) (ctTuple, bool) {
	var t ctTuple
	walkNetlinkAttrs(b, func(at uint16, val []byte) bool {
		switch at {
		case ctaTupleIP:
			walkNetlinkAttrs(val, func(ipt uint16, ipval []byte) bool {
				switch ipt {
				case ctaIPV4Src:
					if len(ipval) >= 4 {
						t.srcIP = net.IPv4(ipval[0], ipval[1], ipval[2], ipval[3])
					}
				case ctaIPV4Dst:
					if len(ipval) >= 4 {
						t.dstIP = net.IPv4(ipval[0], ipval[1], ipval[2], ipval[3])
					}
				case ctaIPV6Src:
					if len(ipval) >= 16 {
						ip := make(net.IP, 16)
						copy(ip, ipval[:16])
						t.srcIP = ip
					}
				case ctaIPV6Dst:
					if len(ipval) >= 16 {
						ip := make(net.IP, 16)
						copy(ip, ipval[:16])
						t.dstIP = ip
					}
				}
				return true
			})
		case ctaTupleProto:
			walkNetlinkAttrs(val, func(pt uint16, pval []byte) bool {
				switch pt {
				case ctaProtoNum:
					if len(pval) >= 1 {
						t.proto = pval[0]
					}
				case ctaProtoSrcPort:
					if len(pval) >= 2 {
						t.srcPort = binary.BigEndian.Uint16(pval[:2])
						t.hasPort = true
					}
				case ctaProtoDstPort:
					if len(pval) >= 2 {
						t.dstPort = binary.BigEndian.Uint16(pval[:2])
						t.hasPort = true
					}
				}
				return true
			})
		}
		return true
	})
	return t, len(t.srcIP) > 0 && len(t.dstIP) > 0 && t.proto > 0
}

func parseCTCounters(b []byte) ctCounters {
	var c ctCounters
	walkNetlinkAttrs(b, func(ct uint16, val []byte) bool {
		switch ct {
		case ctaCountersPackets:
			if len(val) >= 8 {
				c.packets = binary.BigEndian.Uint64(val[:8])
			}
		case ctaCountersBytes:
			if len(val) >= 8 {
				c.bytes = binary.BigEndian.Uint64(val[:8])
			}
		case ctaCounters32Packets:
			if c.packets == 0 && len(val) >= 4 {
				c.packets = uint64(binary.BigEndian.Uint32(val[:4]))
			}
		case ctaCounters32Bytes:
			if c.bytes == 0 && len(val) >= 4 {
				c.bytes = uint64(binary.BigEndian.Uint32(val[:4]))
			}
		}
		return true
	})
	return c
}

func ctTCPStateName(st uint8) string {
	switch st {
	case 1:
		return "SYN_SENT"
	case 2:
		return "SYN_RECV"
	case 3:
		return "ESTABLISHED"
	case 4:
		return "FIN_WAIT"
	case 5:
		return "CLOSE_WAIT"
	case 6:
		return "LAST_ACK"
	case 7:
		return "TIME_WAIT"
	case 8:
		return "CLOSE"
	case 9:
		return "SYN_SENT2"
	default:
		return ""
	}
}

func ctProtoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	default:
		return strconv.Itoa(int(p))
	}
}

// formatCTCompatLine synthesizes a /proc/net/nf_conntrack-compatible text line
// carrying L3/L4 protocol, TCP state, original & reply tuples, and packet/byte counters.
func formatCTCompatLine(e ctEntryData) string {
	var sb strings.Builder
	sb.Grow(192)
	if e.family == syscall.AF_INET6 {
		sb.WriteString("ipv6 10 ")
	} else {
		sb.WriteString("ipv4 2 ")
	}
	sb.WriteString(ctProtoName(e.orig.proto))
	sb.WriteByte(' ')
	sb.WriteString(strconv.Itoa(int(e.orig.proto)))
	sb.WriteByte(' ')
	sb.WriteString(strconv.FormatUint(uint64(e.timeout), 10))

	if e.orig.proto == 6 && e.hasTCPSt {
		if st := ctTCPStateName(e.tcpState); st != "" {
			sb.WriteByte(' ')
			sb.WriteString(st)
		}
	}

	sb.WriteString(" src=")
	sb.WriteString(e.orig.srcIP.String())
	sb.WriteString(" dst=")
	sb.WriteString(e.orig.dstIP.String())
	if e.orig.hasPort {
		sb.WriteString(" sport=")
		sb.WriteString(strconv.Itoa(int(e.orig.srcPort)))
		sb.WriteString(" dport=")
		sb.WriteString(strconv.Itoa(int(e.orig.dstPort)))
	}
	sb.WriteString(" packets=")
	sb.WriteString(strconv.FormatUint(e.origCnt.packets, 10))
	sb.WriteString(" bytes=")
	sb.WriteString(strconv.FormatUint(e.origCnt.bytes, 10))

	if e.status&ipsSeenReply == 0 {
		sb.WriteString(" [UNREPLIED]")
	}

	if e.hasReply && len(e.reply.srcIP) > 0 && len(e.reply.dstIP) > 0 {
		sb.WriteString(" src=")
		sb.WriteString(e.reply.srcIP.String())
		sb.WriteString(" dst=")
		sb.WriteString(e.reply.dstIP.String())
		if e.reply.hasPort {
			sb.WriteString(" sport=")
			sb.WriteString(strconv.Itoa(int(e.reply.srcPort)))
			sb.WriteString(" dport=")
			sb.WriteString(strconv.Itoa(int(e.reply.dstPort)))
		}
		sb.WriteString(" packets=")
		sb.WriteString(strconv.FormatUint(e.replyCnt.packets, 10))
		sb.WriteString(" bytes=")
		sb.WriteString(strconv.FormatUint(e.replyCnt.bytes, 10))
	}

	if e.status&ipsAssured != 0 {
		sb.WriteString(" [ASSURED]")
	}

	use := e.use
	if use == 0 {
		use = 1
	}
	sb.WriteString(" mark=")
	sb.WriteString(strconv.FormatUint(uint64(e.mark), 10))
	sb.WriteString(" use=")
	sb.WriteString(strconv.FormatUint(uint64(use), 10))
	return sb.String()
}

// conntrackOrigDst 取一行 conntrack 记录里第一个 dst= 的值(原方向目的地址),
// 规范化成 net.IP.String()。解析不出返回 ""。
func conntrackOrigDst(line string) string {
	i := strings.Index(line, " dst=")
	if i < 0 {
		return ""
	}
	v := line[i+len(" dst="):]
	if j := strings.IndexByte(v, ' '); j >= 0 {
		v = v[:j]
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// parseConntrackLine is kept for future expansion: rc30 may want to bin
// flows by proto/state to refine background detection. Today we only
// count lines.
//
// Format examples (kernel 5.x):
//
//	ipv4     2 tcp      6 431999 ESTABLISHED src=... dst=... ...
//	ipv6     10 udp     17 29 src=... dst=... ...
func parseConntrackLine(line string) (proto, state string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return "", "", false
	}
	proto = fields[2]
	for _, f := range fields[3:] {
		if strings.Contains(f, "=") {
			break
		}
		if isDigits(f) || strings.HasPrefix(f, "[") {
			continue
		}
		if f == "ASSURED" || f == "UNREPLIED" || f == "SEEN_REPLY" {
			continue
		}
		state = f
		break
	}
	return proto, state, true
}

// ConntrackClient describes a confirmed downstream hotspot client for flow attribution.
type ConntrackClient struct {
	MAC string
	IPs []string
}

// ConntrackFlowOptions configures orthogonal classification of conntrack entries
// into downstream hotspot forwarding flows vs. phone-local host flows.
type ConntrackFlowOptions struct {
	// HotspotActive reports whether hotspot sharing is active. When false (or when
	// zero confirmed downstream clients are online), HotspotFlows is strictly 0.
	HotspotActive bool
	// Clients lists confirmed online downstream hotspot clients (MAC != "" or confirmed client IPs).
	Clients []ConntrackClient
	// InactiveClientIPs optionally lists recently offline downstream client IPs so
	// lingering conntrack entries from disconnected hotspot clients do not pollute HostFlows.
	InactiveClientIPs []string
	// GatewayIPs optionally lists local gateway/interface IPs on the phone.
	GatewayIPs []string
	// HotspotNets optionally lists active hotspot subnets (e.g. 192.168.43.0/24).
	HotspotNets []*net.IPNet
}

// ConntrackFlowSplit holds the orthogonal TCP/UDP flow counts from a conntrack scan.
type ConntrackFlowSplit struct {
	HotspotFlows   uint32            // Confirmed downstream client forwarding TCP/UDP flows
	HostFlows      uint32            // Phone-local non-loopback active TCP/UDP flows
	MgmtExcluded   uint32            // Downstream gateway management flows (:53/:67/:68/:8443/:8444/:8080)
	LoopbackFlows  uint32            // Loopback (127.0.0.0/8, ::1) TCP/UDP flows
	PerClientFlows map[string]uint32 // Per-client forwarding flows keyed by lowercase MAC
}

// ConntrackClassifier classifies conntrack lines in a single streaming pass.
type ConntrackClassifier struct {
	hotspotEnabled bool
	onlineByIP     map[string]string
	inactiveByIP   map[string]struct{}
	gatewayIPs     map[string]struct{}
	hotspotNets    []*net.IPNet
	perClient      map[string]uint32
	hotspotFlows   uint32
	hostFlows      uint32
	mgmtExcluded   uint32
	loopbackFlows  uint32
}

const anonClientMarker = "*"

// NewConntrackClassifier builds a streaming orthogonal flow classifier for ReadConntrackLines.
func NewConntrackClassifier(opts ConntrackFlowOptions) *ConntrackClassifier {
	c := &ConntrackClassifier{
		onlineByIP:   make(map[string]string, len(opts.Clients)*2),
		inactiveByIP: make(map[string]struct{}, len(opts.InactiveClientIPs)),
		gatewayIPs:   make(map[string]struct{}, len(opts.GatewayIPs)),
		hotspotNets:  opts.HotspotNets,
		perClient:    make(map[string]uint32, len(opts.Clients)),
	}
	for _, g := range opts.GatewayIPs {
		if _, key := parseNormCTIP(g); key != "" {
			c.gatewayIPs[key] = struct{}{}
		}
	}
	for _, rawIP := range opts.InactiveClientIPs {
		if _, key := parseNormCTIP(rawIP); key != "" {
			c.inactiveByIP[key] = struct{}{}
		}
	}

	onlineClients := 0
	for _, cl := range opts.Clients {
		mac := strings.ToLower(strings.TrimSpace(cl.MAC))
		tag := mac
		if tag == "" {
			tag = anonClientMarker
		}
		addedAnyIP := false
		for _, rawIP := range cl.IPs {
			_, key := parseNormCTIP(rawIP)
			if key == "" {
				continue
			}
			if _, isGw := c.gatewayIPs[key]; isGw {
				continue
			}
			if opts.HotspotActive {
				c.onlineByIP[key] = tag
				delete(c.inactiveByIP, key)
				addedAnyIP = true
			} else {
				c.inactiveByIP[key] = struct{}{}
			}
		}
		if opts.HotspotActive && (mac != "" || addedAnyIP) && addedAnyIP {
			onlineClients++
		}
	}
	c.hotspotEnabled = opts.HotspotActive && onlineClients > 0
	return c
}

// ClassifyConntrackLines classifies a slice of conntrack text lines into orthogonal
// HotspotFlows and HostFlows counts.
func ClassifyConntrackLines(lines []string, opts ConntrackFlowOptions) ConntrackFlowSplit {
	clf := NewConntrackClassifier(opts)
	for _, line := range lines {
		clf.ObserveLine(line)
	}
	return clf.Result()
}

// ObserveLine inspects one conntrack entry line and updates HotspotFlows or HostFlows.
func (c *ConntrackClassifier) ObserveLine(line string) {
	if c == nil {
		return
	}
	p, ok := parseConntrackTupleLine(line)
	if !ok {
		return
	}
	oSrc, oSrcKey := parseNormCTIP(p.origSrc)
	oDst, oDstKey := parseNormCTIP(p.origDst)
	if oSrc == nil || oDst == nil {
		return
	}
	rSrc, rSrcKey := parseNormCTIP(p.replySrc)
	rDst, rDstKey := parseNormCTIP(p.replyDst)

	// 1. Check whether either endpoint belongs to a confirmed online downstream client.
	if c.hotspotEnabled && len(c.onlineByIP) > 0 {
		if macTag, srvPort, peerIP, hit := c.matchOnlineClient(
			oSrc, oSrcKey, oDst, oDstKey, p.origSPort, p.origDPort,
			rSrc, rSrcKey, rDst, rDstKey, p.replySPort, p.replyDPort,
		); hit {
			if c.isGatewayMgmtFlow(srvPort, p.origSPort, p.origDPort, peerIP, oDst, rSrc) {
				c.mgmtExcluded++
				return
			}
			c.hotspotFlows++
			if macTag != "" && macTag != anonClientMarker {
				c.perClient[macTag]++
			}
			return
		}
	}

	// 2. Lingering flows belonging to offline/inactive hotspot clients (or hotspot subnet
	// peers distinct from the phone's own gateway IPs) must NOT inflate HostFlows, and
	// when 0 clients are online HotspotFlows remains strictly 0.
	if c.isInactiveDownstreamEndpoint(oSrc, oSrcKey) ||
		c.isInactiveDownstreamEndpoint(oDst, oDstKey) ||
		c.isInactiveDownstreamEndpoint(rSrc, rSrcKey) ||
		c.isInactiveDownstreamEndpoint(rDst, rDstKey) {
		return
	}

	// 3. Exclude loopback (127.0.0.0/8, ::1) and unspecified (0.0.0.0, ::) pseudo-flows.
	if isLoopbackCTIP(oSrc) || isLoopbackCTIP(oDst) || isLoopbackCTIP(rSrc) || isLoopbackCTIP(rDst) {
		c.loopbackFlows++
		return
	}
	if oSrc.IsUnspecified() || oDst.IsUnspecified() {
		return
	}

	// 4. Orthogonal phone-local active TCP/UDP flow.
	c.hostFlows++
}

// Result returns the accumulated orthogonal flow counts.
func (c *ConntrackClassifier) Result() ConntrackFlowSplit {
	if c == nil {
		return ConntrackFlowSplit{}
	}
	out := ConntrackFlowSplit{
		HotspotFlows:  c.hotspotFlows,
		HostFlows:     c.hostFlows,
		MgmtExcluded:  c.mgmtExcluded,
		LoopbackFlows: c.loopbackFlows,
	}
	if !c.hotspotEnabled {
		out.HotspotFlows = 0
	}
	if len(c.perClient) > 0 && c.hotspotEnabled {
		out.PerClientFlows = make(map[string]uint32, len(c.perClient))
		for k, v := range c.perClient {
			out.PerClientFlows[k] = v
		}
	}
	return out
}

func (c *ConntrackClassifier) matchOnlineClient(
	oSrc net.IP, oSrcKey string,
	oDst net.IP, oDstKey string,
	oSPort, oDPort uint16,
	rSrc net.IP, rSrcKey string,
	rDst net.IP, rDstKey string,
	rSPort, rDPort uint16,
) (macTag string, srvPort uint16, peerIP net.IP, hit bool) {
	if tag, ok := c.onlineByIP[oSrcKey]; ok {
		return tag, oDPort, oDst, true
	}
	if tag, ok := c.onlineByIP[oDstKey]; ok {
		return tag, oSPort, oSrc, true
	}
	if rDstKey != "" {
		if tag, ok := c.onlineByIP[rDstKey]; ok {
			port := oDPort
			if port == 0 {
				port = rSPort
			}
			return tag, port, oDst, true
		}
	}
	if rSrcKey != "" {
		if tag, ok := c.onlineByIP[rSrcKey]; ok {
			port := oSPort
			if port == 0 {
				port = rDPort
			}
			return tag, port, oSrc, true
		}
	}
	return "", 0, nil, false
}

func (c *ConntrackClassifier) isInactiveDownstreamEndpoint(ip net.IP, key string) bool {
	if ip == nil || key == "" {
		return false
	}
	if _, isGw := c.gatewayIPs[key]; isGw {
		return false
	}
	if _, ok := c.inactiveByIP[key]; ok {
		return true
	}
	if len(c.hotspotNets) > 0 && len(c.gatewayIPs) > 0 {
		for _, n := range c.hotspotNets {
			if n != nil && n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func isGatewayMgmtPort(port uint16) bool {
	switch port {
	case 53, 67, 68, 8443, 8444, 8080:
		return true
	default:
		return false
	}
}

func (c *ConntrackClassifier) isGatewayMgmtFlow(srvPort, origSPort, origDPort uint16, peerIP, origDst, replySrc net.IP) bool {
	if origSPort == 67 || origSPort == 68 || origDPort == 67 || origDPort == 68 {
		return true
	}
	if !isGatewayMgmtPort(srvPort) {
		return false
	}
	if c.isLocalGatewayIP(peerIP) {
		return true
	}
	// Detect iptables PREROUTING REDIRECT hijacking to the phone's local daemon/DNS port:
	// original destination was public (e.g. 8.8.8.8:53), but reply source is a local/gateway IP.
	if replySrc != nil && origDst != nil && !replySrc.Equal(origDst) && c.isLocalGatewayIP(replySrc) {
		return true
	}
	return false
}

func (c *ConntrackClassifier) isLocalGatewayIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if len(c.gatewayIPs) > 0 {
		if _, ok := c.gatewayIPs[ip.String()]; ok {
			return true
		}
	}
	for _, n := range c.hotspotNets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsLoopback() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.Equal(net.IPv4bcast)
}

func parseNormCTIP(s string) (net.IP, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ""
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4, v4.String()
	}
	return ip, ip.String()
}

func isLoopbackCTIP(ip net.IP) bool {
	return ip != nil && ip.IsLoopback()
}

type parsedCTTupleLine struct {
	proto      string
	origSrc    string
	origDst    string
	origSPort  uint16
	origDPort  uint16
	replySrc   string
	replyDst   string
	replySPort uint16
	replyDPort uint16
}

func parseConntrackTupleLine(line string) (parsedCTTupleLine, bool) {
	var out parsedCTTupleLine
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return out, false
	}

	tokIdx := 0
	protoTokIdx := -1
	inReply := false

	for i := 0; i < len(line); {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			break
		}
		start := i
		for i < len(line) && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		tok := line[start:i]

		if tokIdx == 0 {
			switch {
			case strings.EqualFold(tok, "ipv4") || strings.EqualFold(tok, "ipv6"):
				protoTokIdx = 2
			case strings.EqualFold(tok, "tcp") || tok == "6":
				out.proto = "tcp"
			case strings.EqualFold(tok, "udp") || tok == "17":
				out.proto = "udp"
			default:
				return out, false
			}
			tokIdx++
			continue
		}
		if tokIdx == protoTokIdx {
			switch {
			case strings.EqualFold(tok, "tcp") || tok == "6":
				out.proto = "tcp"
			case strings.EqualFold(tok, "udp") || tok == "17":
				out.proto = "udp"
			default:
				return out, false
			}
			tokIdx++
			continue
		}
		tokIdx++

		eq := strings.IndexByte(tok, '=')
		if eq <= 0 {
			continue
		}
		k, v := tok[:eq], tok[eq+1:]
		switch k {
		case "src":
			if out.origSrc == "" {
				out.origSrc = v
			} else if out.replySrc == "" {
				inReply = true
				out.replySrc = v
			}
		case "dst":
			if !inReply {
				if out.origDst == "" {
					out.origDst = v
				}
			} else if out.replyDst == "" {
				out.replyDst = v
			}
		case "sport":
			if p, ok := parsePortU16(v); ok {
				if !inReply {
					if out.origSPort == 0 {
						out.origSPort = p
					}
				} else if out.replySPort == 0 {
					out.replySPort = p
				}
			}
		case "dport":
			if p, ok := parsePortU16(v); ok {
				if !inReply {
					if out.origDPort == 0 {
						out.origDPort = p
					}
				} else if out.replyDPort == 0 {
					out.replyDPort = p
				}
			}
		}
	}

	if out.proto == "" || out.origSrc == "" || out.origDst == "" {
		return out, false
	}
	return out, true
}

func parsePortU16(s string) (uint16, bool) {
	if len(s) == 0 || len(s) > 5 {
		return 0, false
	}
	var n uint32
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint32(c-'0')
	}
	if n > 65535 {
		return 0, false
	}
	return uint16(n), true
}
