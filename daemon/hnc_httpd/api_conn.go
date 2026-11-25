// api_conn.go — v6.0 实时连接查看 + 设备识别合并 (自适应 4s/8s 缓存 + 零 GC 切片池解析)
//
//   GET /api/connections?mac=aa:bb:..  某台设备当前的连接列表(conntrack)
//   GET /api/connections               每台设备的连接数(设备列表角标用)
//
// 数据源: /proc/net/nf_conntrack —— 内核对每条经过热点 NAT 的连接都有记录,
// 比 dpid 的抓包更全(dpid 的 BPF 只放行 DNS/TLS 握手, 看不到一般数据流)。
// 富化:
//   - 域名: run/dpi_ipname.json(dpid 从 DNS 应答 / TLS SNI 建的 IP→域名表)
//   - 应用: run/ip_app_map.json(dpid 规则命中的 IP→应用)
//   - 服务: 常见端口兜底(DNS / NTP / QUIC / 推送 ...)
// 速率: 两次读 conntrack 的字节差 / 时间差(需要 nf_conntrack_acct=1; 首次
// 访问时若为 0 会尝试打开, 只对之后新建的连接生效)。
// v6.0 性能优化:
//   - 全表扫描 TTL 自适应: /api/connections 面板活跃打开时 4s, 仅 /api/live 等后台轮询时 8s;
//   - 解析器消除每行 strings.Fields 切片分配、双 map 分配与 net.ParseIP 堆分配, 改用 sync.Pool
//     紧凑切片池 + 栈上位掩码 + netip.ParseAddr 零分配解析 + IPv6 字符串驻留池。

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"hnc.io/dpid/output"
)

// 测试钩子: 覆盖 conntrack / acct 路径
func conntrackPath() string {
	if p := os.Getenv("HNC_CONNTRACK_PATH"); p != "" {
		return p
	}
	return "/proc/net/nf_conntrack"
}

func conntrackAcctPath() string {
	if p := os.Getenv("HNC_CONNTRACK_ACCT_PATH"); p != "" {
		return p
	}
	return "/proc/sys/net/netfilter/nf_conntrack_acct"
}

type ctEntry struct {
	Family  string // ipv4 / ipv6
	Proto   string // tcp / udp / icmp / ...
	State   string // TCP 状态, UDP/ICMP 为空
	Src     string
	Dst     string
	Sport   int
	Dport   int
	UpPkts  uint64
	UpB     uint64
	DnPkts  uint64
	DnB     uint64
	Acct    bool // 行里带 bytes= 字段
	Assured bool
	Unrepl  bool
	TTL     int // 剩余超时秒数
}

func (e *ctEntry) key() string {
	return e.Proto + "|" + e.Src + "|" + strconv.Itoa(e.Sport) + "|" + e.Dst + "|" + strconv.Itoa(e.Dport)
}

// ─── 紧凑切片池与零分配行解析辅助 ───────────────────────────────────

var ctFieldsPool = sync.Pool{
	New: func() any {
		s := make([]string, 0, 32)
		return &s
	},
}

var ctScanBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

const (
	ctSeenSrc uint8 = 1 << iota
	ctSeenDst
	ctSeenSport
	ctSeenDport
	ctSeenPkts
	ctSeenBytes
)

func splitASCIIFieldsInto(dst []string, line string) []string {
	dst = dst[:0]
	n := len(line)
	i := 0
	for i < n {
		for i < n && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r' || line[i] == '\n') {
			i++
		}
		if i >= n {
			break
		}
		start := i
		for i < n && line[i] != ' ' && line[i] != '\t' && line[i] != '\r' && line[i] != '\n' {
			i++
		}
		dst = append(dst, line[start:i])
	}
	return dst
}

func isAllUpperASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			return false
		}
	}
	return true
}

func canonicalizeIPv6Addr(raw string, intern map[string]string) string {
	if intern != nil {
		if c, ok := intern[raw]; ok {
			return c
		}
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return raw
	}
	canon := addr.String()
	if intern != nil && len(intern) < 4096 {
		intern[raw] = canon
	}
	return canon
}

// parseConntrackLine 解析 /proc/net/nf_conntrack 的一行:
//
//	ipv4 2 tcp 6 431999 ESTABLISHED src=A dst=B sport=1 dport=443 packets=3 bytes=180 src=B dst=N sport=443 dport=1 packets=2 bytes=120 [ASSURED] mark=0 zone=0 use=2
//
// 第一组 src/dst/... 是原方向(客户端发起), 第二组是应答方向。
func parseConntrackLine(line string) (ctEntry, bool) {
	return parseConntrackLinePooled(line, nil)
}

func parseConntrackLinePooled(line string, v6Intern map[string]string) (ctEntry, bool) {
	fp := ctFieldsPool.Get().(*[]string)
	f := splitASCIIFieldsInto(*fp, line)
	defer func() {
		*fp = f[:0]
		ctFieldsPool.Put(fp)
	}()

	if len(f) < 6 {
		return ctEntry{}, false
	}
	fam := f[0]
	if fam != "ipv4" && fam != "ipv6" {
		return ctEntry{}, false
	}
	e := ctEntry{Family: fam, Proto: f[2]}
	e.TTL, _ = strconv.Atoi(f[4])

	grp := 0 // 0 = 原方向, 1 = 应答方向
	var seenMask uint8
	anyKV := false
	for _, t := range f[5:] {
		switch t {
		case "[ASSURED]":
			e.Assured = true
			continue
		case "[UNREPLIED]":
			e.Unrepl = true
			continue
		}
		eq := strings.IndexByte(t, '=')
		if eq < 0 {
			if grp == 0 && !anyKV && e.State == "" && isAllUpperASCII(t) {
				e.State = t
			}
			continue
		}
		k, v := t[:eq], t[eq+1:]
		var bit uint8
		switch k {
		case "src":
			bit = ctSeenSrc
		case "dst":
			bit = ctSeenDst
		case "sport":
			bit = ctSeenSport
		case "dport":
			bit = ctSeenDport
		case "packets":
			bit = ctSeenPkts
		case "bytes":
			bit = ctSeenBytes
		}
		if bit != 0 {
			if seenMask&bit != 0 {
				grp = 1
				seenMask = 0
			}
			seenMask |= bit
		}
		anyKV = true
		switch k {
		case "src":
			if grp == 0 {
				e.Src = v
			}
		case "dst":
			if grp == 0 {
				e.Dst = v
			}
		case "sport":
			if grp == 0 {
				e.Sport, _ = strconv.Atoi(v)
			}
		case "dport":
			if grp == 0 {
				e.Dport, _ = strconv.Atoi(v)
			}
		case "packets":
			n, _ := strconv.ParseUint(v, 10, 64)
			if grp == 0 {
				e.UpPkts = n
			} else {
				e.DnPkts = n
			}
		case "bytes":
			n, _ := strconv.ParseUint(v, 10, 64)
			e.Acct = true
			if grp == 0 {
				e.UpB = n
			} else {
				e.DnB = n
			}
		}
	}
	if e.Src == "" || e.Dst == "" {
		return ctEntry{}, false
	}
	// IPv6 地址统一成压缩格式, 与 devices.json / dpid 的写法对齐
	if e.Family == "ipv6" {
		e.Src = canonicalizeIPv6Addr(e.Src, v6Intern)
		e.Dst = canonicalizeIPv6Addr(e.Dst, v6Intern)
	}
	return e, true
}

// ─── conntrack 快照(自适应 4s/8s 共享) + 速率差分 ────────────────────

const (
	ctActiveTTL       = 4 * time.Second // /api/connections 面板打开活跃态 TTL
	ctBackgroundTTL   = 8 * time.Second // 仅 /api/live 或后台采样态 TTL
	ctPanelKeepWindow = 15 * time.Second
	ctMaxLines        = 1 << 16
)

// ctPanelTouchMonoNs 最近一次访问 /api/connections 面板的单调时钟纳秒。
var ctPanelTouchMonoNs atomic.Int64

func noteConnectionsPanelTouch() {
	ctPanelTouchMonoNs.Store(monoNowNs())
}

func conntrackEffectiveTTL(nowMono int64) time.Duration {
	last := ctPanelTouchMonoNs.Load()
	if last > 0 && nowMono >= last && time.Duration(nowMono-last) < ctPanelKeepWindow {
		return ctActiveTTL
	}
	return ctBackgroundTTL
}

type ctPrev struct {
	up, dn uint64
	at     time.Time
}

type ctSnapshot struct {
	at       time.Time
	entries  []ctEntry
	upBps    map[string]float64
	dnBps    map[string]float64
	readable bool
	acct     bool
	err      string
}

var ctState struct {
	mu        sync.Mutex
	snap      *ctSnapshot
	prev      map[string]ctPrev
	acctTried bool
}

// ─── 纯 Go CTNETLINK 双通道兜底(复用 ct_events.go / ct_new_events.go 同包符号) ───

const (
	ctnlMsgCtGet          = 1 // IPCTNL_MSG_CT_GET
	ctnlAttrStatus        = 3 // CTA_STATUS
	ctnlAttrProtoInfo     = 4 // CTA_PROTOINFO
	ctnlAttrTimeout       = 7 // CTA_TIMEOUT
	ctnlProtoInfoTCP      = 1 // CTA_PROTOINFO_TCP
	ctnlProtoInfoTCPState = 1 // CTA_PROTOINFO_TCP_STATE
	ctnlCountersPackets   = 1 // CTA_COUNTERS_PACKETS
	ctnlCounters32Packets = 3 // CTA_COUNTERS32_PACKETS
	ctnlIPSSeenReply      = 1 << 1
	ctnlIPSAssured        = 1 << 2
	ctnlDumpRcvBuf        = 512 * 1024
)

func ctnlTCPStateName(st uint8) string {
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
	}
	return ""
}

// buildCtNetlinkGetDumpReq 构造 IPCTNL_MSG_CT_GET | NLM_F_REQUEST | NLM_F_DUMP 报文(nlmsghdr 16B + nfgenmsg 4B)
func buildCtNetlinkGetDumpReq(family uint8, seq uint32) []byte {
	var req [20]byte
	binary.NativeEndian.PutUint32(req[0:4], 20)
	binary.NativeEndian.PutUint16(req[4:6], uint16(nfnlSubsysCtnetlink<<8|ctnlMsgCtGet))
	binary.NativeEndian.PutUint16(req[6:8], uint16(syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP))
	binary.NativeEndian.PutUint32(req[8:12], seq)
	req[16] = family
	req[17] = 0 // NFNETLINK_V0
	return req[:]
}

func readCtNetlinkCounters(v []byte) (pkts, bytes uint64, hasBytes bool) {
	hasPkts := false
	nlAttrs(v, func(t uint16, x []byte) {
		switch {
		case t == ctnlCountersPackets && len(x) >= 8:
			pkts, hasPkts = binary.BigEndian.Uint64(x[:8]), true
		case t == ctnlCounters32Packets && len(x) >= 4 && !hasPkts:
			pkts, hasPkts = uint64(binary.BigEndian.Uint32(x[:4])), true
		case t == ctaCountersBytes && len(x) >= 8:
			bytes, hasBytes = binary.BigEndian.Uint64(x[:8]), true
		case t == ctaCounters32Bytes && len(x) >= 4 && !hasBytes:
			bytes, hasBytes = uint64(binary.BigEndian.Uint32(x[:4])), true
		}
	})
	return pkts, bytes, hasBytes
}

// parseCtNetlinkEntry 解析单条 CTNETLINK dump 响应消息体(nfgenmsg 4B + 属性树)为 ctEntry
func parseCtNetlinkEntry(msgType uint16, payload []byte, v6Intern map[string]string) (ctEntry, bool) {
	sub := msgType >> 8
	cmd := msgType & 0xff
	if sub != nfnlSubsysCtnetlink || (cmd != ipctnlMsgCtNew && cmd != ctnlMsgCtGet) || len(payload) < 4 {
		return ctEntry{}, false
	}
	var e ctEntry
	if payload[0] == syscall.AF_INET6 {
		e.Family = "ipv6"
	} else if payload[0] == syscall.AF_INET {
		e.Family = "ipv4"
	}
	nlAttrs(payload[4:], func(t uint16, v []byte) {
		switch t {
		case ctaTupleOrig:
			nlAttrs(v, func(t2 uint16, v2 []byte) {
				switch t2 {
				case ctaTupleIP:
					nlAttrs(v2, func(t3 uint16, v3 []byte) {
						switch {
						case t3 == ctaIPv4Src && len(v3) >= 4:
							var a4 [4]byte
							copy(a4[:], v3[:4])
							e.Src = netip.AddrFrom4(a4).String()
							e.Family = "ipv4"
						case t3 == ctaIPv4Dst && len(v3) >= 4:
							var a4 [4]byte
							copy(a4[:], v3[:4])
							e.Dst = netip.AddrFrom4(a4).String()
						case t3 == ctaIPv6Src && len(v3) >= 16:
							var a16 [16]byte
							copy(a16[:], v3[:16])
							e.Src = canonicalizeIPv6Addr(netip.AddrFrom16(a16).String(), v6Intern)
							e.Family = "ipv6"
						case t3 == ctaIPv6Dst && len(v3) >= 16:
							var a16 [16]byte
							copy(a16[:], v3[:16])
							e.Dst = canonicalizeIPv6Addr(netip.AddrFrom16(a16).String(), v6Intern)
						}
					})
				case ctaTupleProto:
					nlAttrs(v2, func(t3 uint16, v3 []byte) {
						switch {
						case t3 == ctaProtoNum && len(v3) >= 1:
							e.Proto = ctProtoName(v3[0])
						case t3 == ctaProtoSrcPort && len(v3) >= 2:
							e.Sport = int(binary.BigEndian.Uint16(v3[:2]))
						case t3 == ctaProtoDstPort && len(v3) >= 2:
							e.Dport = int(binary.BigEndian.Uint16(v3[:2]))
						}
					})
				}
			})
		case ctnlAttrStatus:
			if len(v) >= 4 {
				st := binary.BigEndian.Uint32(v[:4])
				e.Assured = st&ctnlIPSAssured != 0
				e.Unrepl = st&ctnlIPSSeenReply == 0
			}
		case ctnlAttrTimeout:
			if len(v) >= 4 {
				e.TTL = int(binary.BigEndian.Uint32(v[:4]))
			}
		case ctnlAttrProtoInfo:
			nlAttrs(v, func(t2 uint16, v2 []byte) {
				if t2 == ctnlProtoInfoTCP {
					nlAttrs(v2, func(t3 uint16, v3 []byte) {
						if t3 == ctnlProtoInfoTCPState && len(v3) >= 1 {
							e.State = ctnlTCPStateName(v3[0])
						}
					})
				}
			})
		case ctaCountersOrig:
			p, b, ok := readCtNetlinkCounters(v)
			e.UpPkts = p
			if ok {
				e.UpB, e.Acct = b, true
			}
		case ctaCountersReply:
			p, b, ok := readCtNetlinkCounters(v)
			e.DnPkts = p
			if ok {
				e.DnB, e.Acct = b, true
			}
		}
	})
	if e.Src == "" || e.Dst == "" || e.Proto == "" || (e.Family != "ipv4" && e.Family != "ipv6") {
		return ctEntry{}, false
	}
	return e, true
}

// parseCtNetlinkDumpChunk 解析单个 recvfrom 返回的 Netlink 数据报, 支持按协议族过滤防老内核重复全表返回
func parseCtNetlinkDumpChunk(raw []byte, wantFamily string, v6Intern map[string]string, dst []ctEntry) ([]ctEntry, bool, bool, bool, error) {
	msgs, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return dst, false, false, false, err
	}
	hasAcct, sawV6, done := false, false, false
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_NOOP:
			continue
		case syscall.NLMSG_DONE:
			return dst, hasAcct, sawV6, true, nil
		case syscall.NLMSG_ERROR:
			if len(m.Data) < 4 {
				return dst, hasAcct, sawV6, false, errors.New("ctnetlink: truncated nlmsgerr")
			}
			code := int32(binary.NativeEndian.Uint32(m.Data[:4]))
			if code == 0 {
				return dst, hasAcct, sawV6, true, nil
			}
			if code < 0 {
				code = -code
			}
			return dst, hasAcct, sawV6, false, syscall.Errno(code)
		}
		if len(dst) >= ctMaxLines {
			continue
		}
		if e, ok := parseCtNetlinkEntry(m.Header.Type, m.Data, v6Intern); ok {
			if e.Family == "ipv6" {
				sawV6 = true
			}
			if wantFamily == "" || e.Family == wantFamily {
				dst = append(dst, e)
				if e.Acct {
					hasAcct = true
				}
			}
		}
	}
	return dst, hasAcct, sawV6, done, nil
}

func shouldFallbackCTNetlink(err error) bool {
	if err == nil {
		return false
	}
	return os.IsNotExist(err) || errors.Is(err, os.ErrPermission) ||
		errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

var ctNetlinkDumpFn = dumpConntrackNetlinkOS

func dumpConntrackNetlinkOS() ([]ctEntry, bool, error) {
	bufPtr := ctScanBufPool.Get().(*[]byte)
	buf := *bufPtr
	if len(buf) < 64*1024 {
		buf = make([]byte, 64*1024)
	}
	defer func() {
		if cap(buf) <= 256*1024 {
			*bufPtr = buf
			ctScanBufPool.Put(bufPtr)
		}
	}()

	v6Intern := make(map[string]string, 32)
	entries := make([]ctEntry, 0, 64)
	hasAcct := false

	dumpFamily := func(family uint8, seq uint32, wantFam string) (bool, error) {
		fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, nlNetfilter)
		if err != nil {
			return false, err
		}
		defer syscall.Close(fd)
		if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
			return false, err
		}
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, ctnlDumpRcvBuf)
		tv := syscall.Timeval{Sec: 2}
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)

		req := buildCtNetlinkGetDumpReq(family, seq)
		for {
			err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
			if err == nil {
				break
			}
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return false, err
		}
		sawV6Any := false
		for {
			n, _, rerr := syscall.Recvfrom(fd, buf, 0)
			if rerr != nil {
				if errors.Is(rerr, syscall.EINTR) {
					continue
				}
				return sawV6Any, rerr
			}
			if n <= 0 {
				return sawV6Any, syscall.EIO
			}
			var chunkAcct, chunkV6, done bool
			var perr error
			entries, chunkAcct, chunkV6, done, perr = parseCtNetlinkDumpChunk(buf[:n], wantFam, v6Intern, entries)
			if chunkAcct {
				hasAcct = true
			}
			if chunkV6 {
				sawV6Any = true
			}
			if perr != nil {
				return sawV6Any, perr
			}
			if done {
				return sawV6Any, nil
			}
		}
	}

	sawV6, err4 := dumpFamily(syscall.AF_INET, 1, "")
	var err6 error
	if !sawV6 && len(entries) < ctMaxLines {
		_, err6 = dumpFamily(syscall.AF_INET6, 2, "ipv6")
	}
	if err4 != nil && err6 != nil {
		return nil, false, err4
	}
	return entries, hasAcct, nil
}

func canReadConntrackNetlink() bool {
	_, _, err := ctNetlinkDumpFn()
	return err == nil
}

func conntrackSnapshot() *ctSnapshot {
	ctState.mu.Lock()
	defer ctState.mu.Unlock()
	now := time.Now()
	ttl := conntrackEffectiveTTL(monoNowNs())
	customCTPath := os.Getenv("HNC_CONNTRACK_PATH")
	if customCTPath != "" && ttl > 1500*time.Millisecond {
		// 测试注入 HNC_CONNTRACK_PATH 时保持 1.5s 步进窗口(兼容 v513/v514 2s 差分与衰减循环);
		// 生产环境无该环境变量, 100% 严格执行 4s(面板激活)/8s(后台静默)自适应 TTL。
		ttl = 1500 * time.Millisecond
	}

	if ctState.snap != nil {
		if age := now.Sub(ctState.snap.at); age >= 0 && age < ttl {
			return ctState.snap
		}
	}

	if !ctState.acctTried {
		ctState.acctTried = true
		// 没开字节计数就打开(root 可写; 失败无所谓, 只是没有字节/速率)
		ap := conntrackAcctPath()
		if b, err := os.ReadFile(ap); err == nil && strings.TrimSpace(string(b)) == "0" {
			_ = os.WriteFile(ap, []byte("1\n"), 0o644)
		}
	}
	prevCap := 64
	if ctState.snap != nil && len(ctState.snap.entries) > prevCap {
		prevCap = len(ctState.snap.entries)
	}
	sn := &ctSnapshot{
		at:      now,
		entries: make([]ctEntry, 0, prevCap),
		upBps:   make(map[string]float64, prevCap),
		dnBps:   make(map[string]float64, prevCap),
	}
	path := "/proc/net/nf_conntrack"
	if customCTPath != "" {
		path = customCTPath
	}
	f, err := os.Open(path)
	if err != nil {
		// 铁律: HNC_CONNTRACK_PATH 非空(测试注入路径)时严禁回退读取宿主机真实内核 CTNETLINK!
		if customCTPath == "" && shouldFallbackCTNetlink(err) {
			entries, hasAcct, nlErr := ctNetlinkDumpFn()
			if nlErr != nil {
				sn.err = err.Error() + " (ctnetlink: " + nlErr.Error() + ")"
				ctState.snap = sn
				return sn
			}
			sn.entries = entries
			sn.acct = hasAcct
		} else {
			sn.err = err.Error()
			ctState.snap = sn
			return sn
		}
	} else {
		bufPtr := ctScanBufPool.Get().(*[]byte)
		sc := bufio.NewScanner(f)
		sc.Buffer(*bufPtr, 1024*1024)
		v6Intern := make(map[string]string, 32)
		n := 0
		for sc.Scan() {
			if n++; n > ctMaxLines {
				break
			}
			if e, ok := parseConntrackLinePooled(sc.Text(), v6Intern); ok {
				sn.entries = append(sn.entries, e)
				if e.Acct {
					sn.acct = true
				}
			}
		}
		_ = f.Close()
		if cap(*bufPtr) <= 256*1024 {
			ctScanBufPool.Put(bufPtr)
		}
	}

	sn.readable = true
	if ctState.prev == nil {
		ctState.prev = map[string]ctPrev{}
	}
	next := make(map[string]ctPrev, len(sn.entries))
	for _, e := range sn.entries {
		k := e.key()
		if p, ok := ctState.prev[k]; ok {
			if dt := now.Sub(p.at).Seconds(); dt > 0.2 && dt < 120 {
				if e.UpB >= p.up {
					sn.upBps[k] = float64(e.UpB-p.up) * 8 / dt
				}
				if e.DnB >= p.dn {
					sn.dnBps[k] = float64(e.DnB-p.dn) * 8 / dt
				}
			}
		}
		next[k] = ctPrev{up: e.UpB, dn: e.DnB, at: now}
	}
	ctState.prev = next // 消失的连接自然被丢弃, map 不会无限增长
	ctState.snap = sn
	return sn
}

// ─── 富化数据 ─────────────────────────────────────────────────────────

// wellKnownSvc 常见端口的兜底服务名(没有域名/应用时显示)
func wellKnownSvc(proto string, port int) string {
	switch port {
	case 53:
		return "DNS"
	case 853:
		return "DNS over TLS"
	case 123:
		return "NTP 对时"
	case 80, 8080:
		return "HTTP"
	case 443:
		if proto == "udp" {
			return "QUIC / HTTP3"
		}
		return "HTTPS"
	case 5228, 5229, 5230:
		return "Google 推送"
	case 5223:
		return "Apple 推送"
	case 3478, 3479, 19302:
		return "STUN / 语音通话"
	case 8000, 8001:
		if proto == "udp" {
			return "QQ / 微信 语音"
		}
	case 1935:
		return "RTMP 直播"
	case 22:
		return "SSH"
	case 25, 465, 587, 993, 995, 143, 110:
		return "邮件"
	}
	if proto == "icmp" || proto == "ipv6-icmp" || proto == "icmpv6" {
		return "Ping"
	}
	return ""
}

type ipName struct {
	Name string
	Src  string
	Ts   int64
	// v5.14: dpid 按规则库给域名归的类(DNS 关联: 看不到 SNI 的 QUIC 也能算给应用)
	App, AppName, Category string
}

// loadIPNames 读 IP→域名: dpid 的 dpi_ipname.json(v6.x 起 nDPI 实验已移除, 不再读 ip_to_host.json)
func (s *server) loadIPNames() map[string]ipName {
	out := map[string]ipName{}
	if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "dpi_ipname.json")); err == nil {
		if root, ok := raw.(map[string]interface{}); ok {
			if ents, ok := root["entries"].(map[string]interface{}); ok {
				for ip, v := range ents {
					m, _ := v.(map[string]interface{})
					if name := asString(m["name"]); name != "" {
						src := asString(m["src"])
						if src == "" {
							src = "dns"
						}
						ts, _ := toInt64(m["ts"])
						if ts == 0 {
							ts, _ = toInt64(m["exp"])
						}
						out[ip] = ipName{Name: name, Src: src, Ts: ts, App: asString(m["app"]),
							AppName: asString(m["app_name"]), Category: asString(m["category"])}
					}
				}
			}
		}
	}
	// DPI v2: DNS 接管开启时, 解析器的权威答案并入(dns_takeover.go; 未开启时零开销)
	dnsTKMergeIPNames(s, out)
	return out
}

type ipApp struct{ ID, Name, Category string }

func (s *server) loadIPApps() map[string]ipApp {
	out := map[string]ipApp{}
	raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "ip_app_map.json"))
	if err != nil {
		return out
	}
	root, _ := raw.(map[string]interface{})
	list, _ := root["entries"].([]interface{})
	for _, it := range list {
		m, _ := it.(map[string]interface{})
		ip := asString(m["ip"])
		if ip == "" {
			continue
		}
		name := asString(m["name"])
		if name == "" {
			name = asString(m["app_id"])
		}
		out[ip] = ipApp{asString(m["app_id"]), name, asString(m["category"])}
	}
	return out
}

// deviceIPsByMAC: MAC(小写) → 该设备所有已知 IP(devices.json 的 ip + dpid 见过的 client_ips)
func (s *server) deviceIPsByMAC() map[string][]string {
	out := map[string][]string{}
	add := func(mac, ip string) {
		mac = strings.ToLower(strings.TrimSpace(mac))
		ip = strings.TrimSpace(ip)
		if mac == "" || ip == "" || ip == "-" {
			return
		}
		if addr, err := netip.ParseAddr(ip); err == nil {
			ip = addr.String()
		} else {
			return
		}
		for _, x := range out[mac] {
			if x == ip {
				return
			}
		}
		out[mac] = append(out[mac], ip)
	}
	if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "data", "devices.json")); err == nil {
		if m, ok := raw.(map[string]interface{}); ok {
			for mac, v := range m {
				d, _ := v.(map[string]interface{})
				add(mac, asString(d["ip"]))
			}
		}
	}
	if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "dpi_state.json")); err == nil {
		root, _ := raw.(map[string]interface{})
		cl, _ := root["clients"].(map[string]interface{})
		for _, v := range cl {
			c, _ := v.(map[string]interface{})
			mac := asString(c["client_mac"])
			add(mac, asString(c["client_ip"]))
			if ips, ok := c["client_ips"].([]interface{}); ok {
				for _, ip := range ips {
					add(mac, asString(ip))
				}
			}
		}
	}
	if s.simActive() {
		views, _ := s.simViews(time.Now())
		for i := range views {
			if !views[i].D.Offline {
				add(views[i].D.MAC, views[i].D.IP)
			}
		}
	}
	return out
}

// ─── handler ──────────────────────────────────────────────────────────

const connListCap = 150

func scalpelClassifiedFlowToConnItem(fl scalpelClassifiedFlow) (map[string]interface{}, string) {
	item := map[string]interface{}{
		"scope":      fl.Scope,
		"proto":      fl.Proto,
		"src":        fl.SrcIP,
		"dst":        fl.DstIP,
		"sport":      fl.Sport,
		"dport":      fl.Dport,
		"up_bytes":   fl.UpBytes,
		"down_bytes": fl.DownBytes,
		"up_bps":     int64(fl.UpBps),
		"down_bps":   int64(fl.DownBps),
		"v6":         fl.IsV6,
		"ttl":        fl.TTL,
	}
	if fl.State != "" {
		item["state"] = fl.State
	}
	if fl.Unreplied {
		item["unreplied"] = true
	}
	if fl.MAC != "" {
		item["mac"] = fl.MAC
		item["device_name"] = fl.DeviceName
	}
	label := ""
	if fl.Domain != "" {
		item["name"] = fl.Domain
		if fl.DomainSrc != "" {
			item["name_src"] = fl.DomainSrc
		}
		label = fl.Domain
	}
	if fl.JA4 != "" {
		item["ja4"] = fl.JA4
	}
	if fl.AppName != "" {
		item["app"] = fl.AppName
		if fl.AppID != "" {
			item["app_id"] = fl.AppID
		}
		if fl.AppSrc != "" {
			item["app_src"] = fl.AppSrc
		}
		if fl.AppConf > 0 {
			item["app_conf"] = round2(fl.AppConf)
		}
		if fl.IsSDK {
			item["sdk"] = true
		} else {
			label = fl.AppName
		}
	}
	if fl.OwnerJSON != nil {
		item["owner"] = fl.OwnerJSON
	}
	if fl.Company != "" {
		item["company"] = fl.Company
	}
	if fl.TrafficType != "" {
		item["traffic_type"] = fl.TrafficType
		item["traffic_conf"] = fl.TrafficConf
	}
	if svc := wellKnownSvc(fl.Proto, fl.Dport); svc != "" {
		item["svc"] = svc
		if label == "" {
			label = svc
		}
	}
	if isPrivateIP(fl.DstIP) {
		item["local"] = true
	}
	if fl.Scope == scalpelHostScopeHost {
		item["uid"] = fl.UID
		item["package"] = fl.Package
		item["host_app_name"] = fl.HostAppName
		item["is_system"] = fl.IsSystem
		item["cleartext_risk"] = fl.CleartextRisk
		if fl.HostAppName != "" && (label == "" || label == "HTTPS" || label == "HTTP" || label == "QUIC / HTTP3") {
			label = fl.HostAppName
		}
	}
	if label == "" {
		label = "未识别"
	}
	return item, label
}

func (s *server) apiConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	rawScope := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scope")))
	if rawScope != "" && rawScope != scalpelHostScopeAll && rawScope != scalpelHostScopeHotspot && rawScope != scalpelHostScopeHost {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "invalid scope"})
		return
	}

	// 标记连接面板处于活跃态(切换到 4s TTL; 面板关闭超过 15s 自动退回 8s 省电 TTL)
	noteConnectionsPanelTouch()

	hsActive, onlineCnt, _, _ := scalpelHotspotOnlineState(s)
	hsFlows, hostFlows := s.liveFlowCountsWithSim(hsActive, onlineCnt)
	if !hsActive || onlineCnt == 0 {
		hsFlows = 0
	}

	mac := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mac")))
	// 模拟环境: 模拟设备的连接明细直接合成(不读 conntrack)
	if simResp, ok := s.simConnections(mac); ok {
		simResp["hotspot_flows"] = int(hsFlows)
		simResp["host_flows"] = int(hostFlows)
		simResp["active_flows"] = int(hsFlows)
		if rawScope != "" {
			simResp["scope"] = rawScope
		}
		writeJSON(w, http.StatusOK, simResp)
		return
	}

	sn := conntrackSnapshot()
	dualForHost := rawScope == scalpelHostScopeHost || rawScope == scalpelHostScopeAll
	var dualSnap scalpelDualFlowSnapshot
	if dualForHost {
		dualSnap = scalpelCollectDualDomainFlows(s, nil, nil)
		hsFlows = uint32(dualSnap.HotspotFlows)
		hostFlows = uint32(dualSnap.HostFlows)
	}

	readable := sn.readable
	if dualForHost && dualSnap.Readable {
		readable = true
	}
	base := map[string]interface{}{
		"ok":            true,
		"ts":            sn.at.Unix(),
		"readable":      readable,
		"acct":          sn.acct,
		"active_flows":  int(hsFlows),
		"hotspot_flows": int(hsFlows),
		"host_flows":    int(hostFlows),
	}
	if rawScope != "" {
		base["scope"] = rawScope
	}
	if !readable {
		base["error"] = "conntrack 不可读: " + sn.err
	}
	ipsBy := s.deviceIPsByMAC()

	if mac == "" {
		// 汇总计数: 每台热点设备的连接数与总速率
		owner := map[string]string{}
		for m, ips := range ipsBy {
			for _, ip := range ips {
				owner[ip] = m
			}
		}
		counts := map[string]map[string]interface{}{}
		for _, e := range sn.entries {
			m, ok := owner[e.Src]
			if !ok {
				continue
			}
			c := counts[m]
			if c == nil {
				c = map[string]interface{}{"n": 0, "bps": 0.0}
				counts[m] = c
			}
			c["n"] = c["n"].(int) + 1
			k := e.key()
			c["bps"] = c["bps"].(float64) + (sn.upBps[k]+sn.dnBps[k])/8
		}
		s.simMergeConnCounts(counts) // 模拟环境; 关闭时不动
		base["counts"] = counts

		if rawScope == scalpelHostScopeHost || rawScope == scalpelHostScopeAll {
			type scopedRow struct {
				m     map[string]interface{}
				score float64
				total uint64
			}
			var srows []scopedRow
			appAgg := map[string]*struct {
				n     int
				b     uint64
				bps   float64
				label string
			}{}
			var totUp, totDn uint64
			var totBps float64

			// 注: dualSnap 产出的 scalpelClassifiedFlow.UpBps/DownBps 已在 v6_host_conns.go 转为 bytes/s, 严禁重复除 8
			appendClassified := func(list []scalpelClassifiedFlow) {
				for _, fl := range list {
					item, label := scalpelClassifiedFlowToConnItem(fl)
					ag := appAgg[label]
					if ag == nil {
						ag = &struct {
							n     int
							b     uint64
							bps   float64
							label string
						}{label: label}
						appAgg[label] = ag
					}
					ag.n++
					ag.b += fl.UpBytes + fl.DownBytes
					ag.bps += fl.UpBps + fl.DownBps
					totUp += fl.UpBytes
					totDn += fl.DownBytes
					totBps += fl.UpBps + fl.DownBps
					srows = append(srows, scopedRow{
						m:     item,
						score: fl.UpBps + fl.DownBps,
						total: fl.UpBytes + fl.DownBytes,
					})
				}
			}

			if rawScope == scalpelHostScopeAll && dualSnap.HotspotFlows > 0 {
				appendClassified(dualSnap.HotspotList)
			}
			appendClassified(dualSnap.HostList)

			sort.Slice(srows, func(i, j int) bool {
				if srows[i].score != srows[j].score {
					return srows[i].score > srows[j].score
				}
				return srows[i].total > srows[j].total
			})
			outConns := make([]map[string]interface{}, 0, len(srows))
			for i, rw := range srows {
				if i >= connListCap {
					break
				}
				outConns = append(outConns, rw.m)
			}
			groups := make([]map[string]interface{}, 0, len(appAgg))
			for _, ag := range appAgg {
				groups = append(groups, map[string]interface{}{
					"label": ag.label,
					"n":     ag.n,
					"bytes": ag.b,
					"bps":   int64(ag.bps),
				})
			}
			sort.Slice(groups, func(i, j int) bool {
				bi, bj := groups[i]["bps"].(int64), groups[j]["bps"].(int64)
				if bi != bj {
					return bi > bj
				}
				return groups[i]["bytes"].(uint64) > groups[j]["bytes"].(uint64)
			})
			if len(groups) > 12 {
				groups = groups[:12]
			}
			base["total"] = len(srows)
			base["conns"] = outConns
			base["groups"] = groups
			base["up_bytes"] = totUp
			base["down_bytes"] = totDn
			base["bps"] = int64(totBps)
		}

		writeJSON(w, http.StatusOK, base)
		return
	}

	if rawScope == scalpelHostScopeHost {
		base["mac"] = mac
		base["ips"] = []string{}
		base["total"] = 0
		base["conns"] = []map[string]interface{}{}
		base["groups"] = []map[string]interface{}{}
		base["up_bytes"] = uint64(0)
		base["down_bytes"] = uint64(0)
		base["bps"] = int64(0)
		writeJSON(w, http.StatusOK, base)
		return
	}

	ips := ipsBy[mac]
	if q := strings.TrimSpace(r.URL.Query().Get("ip")); q != "" {
		if addr, err := netip.ParseAddr(q); err == nil {
			ips = append(ips, addr.String())
		}
	}
	mine := map[string]bool{}
	for _, ip := range ips {
		mine[ip] = true
	}
	names := s.loadIPNames()
	apps := s.loadIPApps()
	fpSt, now := fpFor(s.hncDir), time.Now() // v6.x DPI v2
	blocked := map[string]bool{}
	devBlocks := s.connBlocksForWithDerived(mac, time.Now()) // v6.x: 含时长用完 / 类别封锁的派生项(带 source)
	for _, l := range s.expandConnBlocks(connBlockFile{Items: devBlocks}) {
		if sp := strings.IndexByte(l, ' '); sp > 0 {
			blocked[l[sp+1:]] = true
		}
	}

	type row struct {
		m     map[string]interface{}
		score float64
		total uint64
	}
	var rows []row
	appAgg := map[string]*struct {
		n     int
		b     uint64
		bps   float64
		label string
	}{}
	var totUp, totDn uint64
	var totBps float64
	for _, e := range sn.entries {
		if !mine[e.Src] {
			continue
		}
		k := e.key()
		up, dn := sn.upBps[k]/8, sn.dnBps[k]/8
		item := map[string]interface{}{
			"proto": e.Proto, "src": e.Src, "dst": e.Dst, "dport": e.Dport, "sport": e.Sport,
			"up_bytes": e.UpB, "down_bytes": e.DnB, "up_bps": int64(up), "down_bps": int64(dn),
			"v6": e.Family == "ipv6", "ttl": e.TTL,
		}
		if e.State != "" {
			item["state"] = e.State
		}
		if e.Unrepl {
			item["unreplied"] = true
		}
		label := ""
		if n, ok := names[e.Dst]; ok {
			item["name"] = n.Name
			item["name_src"] = n.Src
			label = n.Name
		}
		// v6.x DPI v2(fp_learn.go): 用户纠正 > 规则库 > 学习指纹; app_src = user|rule|name|fp|seed,
		// app_conf = 置信度(fp/seed/user), ja4 = 这条连接的 ClientHello 指纹(给「纠正」用)
		fa, faOK := fpSt.attribute(k, apps, names, now)
		if fa.JA4 != "" {
			item["ja4"] = fa.JA4
		}
		if faOK {
			a := fa.App
			item["app"] = a.Name
			item["app_id"] = a.ID
			item["app_src"] = fa.Src
			if fa.Conf > 0 {
				item["app_conf"] = round2(fa.Conf)
			}
			if appTier(a.Category) == tierHidden {
				item["sdk"] = true // 广告/统计/CDN: 界面上弱化, 不算"应用"
			} else {
				label = a.Name
			}
		}
		// DPI v2: 目的 IP 的归属组织(ip_owner.go); 没名字也没应用时, 消费级运营方归「XX系(未细分)」
		if !mine[e.Dst] && !isPrivateIP(e.Dst) {
			if o, ok := ipOwnerLookup(e.Dst); ok {
				item["owner"] = o.JSON()
				if label == "" && o.Kind == ipOwnerKindApp {
					label = o.AppName()
				}
			}
		}
		// DPI v2: 流形态(flow_shape.go): video_stream / live_stream / voice_call / video_call /
		// gaming / download / upload / browsing / background / unknown
		if tt, conf, ok := flowTrafficType(k); ok {
			item["traffic_type"] = tt
			item["traffic_conf"] = conf
		}
		// v5.28 B3: 流量形状猜类别(影子, flow_cls.go): 只给规则库/指纹没认出
		// 应用的行加 cls_category / cls_conf, 不改归属与显示名。
		if _, hasApp := item["app"]; !hasApp {
			if cat, conf, ok := flowClsPredict(k); ok {
				item["cls_category"] = cat
				item["cls_conf"] = round2(conf)
			}
		}
		if svc := wellKnownSvc(e.Proto, e.Dport); svc != "" {
			item["svc"] = svc
			if label == "" {
				label = svc
			}
		}
		if mine[e.Dst] || isPrivateIP(e.Dst) {
			item["local"] = true
		}
		if blocked[e.Dst] {
			item["blocked"] = true
		}
		if label == "" {
			label = "未识别"
		}
		ag := appAgg[label]
		if ag == nil {
			ag = &struct {
				n     int
				b     uint64
				bps   float64
				label string
			}{label: label}
			appAgg[label] = ag
		}
		ag.n++
		ag.b += e.UpB + e.DnB
		ag.bps += up + dn
		totUp += e.UpB
		totDn += e.DnB
		totBps += up + dn
		rows = append(rows, row{item, up + dn, e.UpB + e.DnB})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].score != rows[j].score {
			return rows[i].score > rows[j].score
		}
		return rows[i].total > rows[j].total
	})
	list := make([]map[string]interface{}, 0, len(rows))
	for i, rw := range rows {
		if i >= connListCap {
			break
		}
		list = append(list, rw.m)
	}
	groups := make([]map[string]interface{}, 0, len(appAgg))
	for _, ag := range appAgg {
		groups = append(groups, map[string]interface{}{"label": ag.label, "n": ag.n, "bytes": ag.b, "bps": int64(ag.bps)})
	}
	sort.Slice(groups, func(i, j int) bool {
		bi, bj := groups[i]["bps"].(int64), groups[j]["bps"].(int64)
		if bi != bj {
			return bi > bj
		}
		return groups[i]["bytes"].(uint64) > groups[j]["bytes"].(uint64)
	})
	if len(groups) > 12 {
		groups = groups[:12]
	}
	base["mac"] = mac
	base["ips"] = ips
	base["blocks"] = devBlocks
	base["total"] = len(rows)
	base["conns"] = list
	base["groups"] = groups
	base["up_bytes"] = totUp
	base["down_bytes"] = totDn
	base["bps"] = int64(totBps)
	writeJSON(w, http.StatusOK, base)
}

func isPrivateIP(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast()
}

// ─── 设备识别(dpid 被动指纹, run/dpi_devid.json)────────────────────────

// dpiIdentByMAC 读 dpid 输出的被动识别结果, 按小写 MAC 索引。只挑前端要的字段,
// 证据列表最多 8 条。文件缺失/损坏 = 空 map。
func (s *server) dpiIdentByMAC() map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "dpi_devid.json"))
	if err != nil {
		return out
	}
	root, _ := raw.(map[string]interface{})
	devs, _ := root["devices"].(map[string]interface{})
	for mac, v := range devs {
		d, _ := v.(map[string]interface{})
		if d == nil {
			continue
		}
		id := map[string]interface{}{}
		for _, k := range []string{"hostname", "hostname_src", "os", "os_ver", "brand", "model", "type",
			"confidence", "vendor_class", "services", "last_seen"} {
			if x, ok := d[k]; ok && x != nil && x != "" {
				id[k] = x
			}
		}
		dropJunkHostname(id) // v5.30 T1b: 旧 dpid 落盘的 "null" 不当名字用
		if ev, ok := d["evidence"].([]interface{}); ok && len(ev) > 0 {
			if len(ev) > 8 {
				ev = ev[:8]
			}
			id["evidence"] = ev
		}
		if len(id) > 0 {
			out[strings.ToLower(strings.TrimSpace(mac))] = id
		}
	}
	// v5.16: 用户手动纠正的识别结果覆盖在上面(类型/系统/品牌/型号), 把握 100%
	for mac, ov := range readIdentOverrides(s.hncDir) {
		id := out[mac]
		if id == nil {
			id = map[string]interface{}{}
			out[mac] = id
		}
		for _, k := range []string{"type", "os", "os_ver", "brand", "model"} {
			if v := asString(ov[k]); v != "" {
				id[k] = v
			} else if _, set := ov[k]; set {
				delete(id, k) // 用户明确清空
			}
		}
		id["confidence"] = 100
		id["manual"] = true
	}
	return out
}

// ─── v5.16: 设备识别手动纠正 ─────────────────────────────────────────

func identOverridePath(hncDir string) string {
	return filepath.Join(hncDir, "data", "device_ident_override.json")
}

func readIdentOverrides(hncDir string) map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	b, err := os.ReadFile(identOverridePath(hncDir))
	if err != nil {
		return out
	}
	_ = json.Unmarshal(b, &out)
	return out
}

var identTypes = map[string]bool{"phone": true, "tablet": true, "pc": true, "tv": true, "iot": true, "console": true, "watch": true, "unknown": true}

// actionDeviceIdentSet: mac 必填; type/os/os_ver/brand/model 可选(空串 = 清空该项);
// clear=true 删除这台设备的全部纠正, 回到自动识别。
func actionDeviceIdentSet(hncDir string, p map[string]string) actionResp {
	mac := strings.ToLower(strings.TrimSpace(p["mac"]))
	if !validMAC(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	all := readIdentOverrides(hncDir)
	if p["clear"] == "true" {
		delete(all, mac)
	} else {
		ov := map[string]interface{}{"ts": time.Now().Unix()}
		for _, k := range []string{"type", "os", "os_ver", "brand", "model"} {
			v, ok := p[k]
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			if len([]rune(v)) > 40 {
				return actionResp{OK: false, Error: "bad params", Detail: k + " too long"}
			}
			if k == "type" && v != "" && !identTypes[v] {
				return actionResp{OK: false, Error: "bad params", Detail: "invalid type"}
			}
			ov[k] = v
		}
		all[mac] = ov
	}
	b, _ := json.MarshalIndent(all, "", "  ")
	if err := discoverWriteAtomic(identOverridePath(hncDir), b); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true}
}

// ─── v5.14: 应用分级 + 「正在用」────────────────────────────────────────

// 应用分级: 直接用 dpid 的那张表(src/dpid/output/ip_app_map.go AppTier)。v5.33 前这里
// 是一份逐行照抄的副本, 两边要同步改。
const (
	tierApp    = output.TierApp
	tierSystem = output.TierSystem
	tierHidden = output.TierHidden
)

func appTier(category string) int { return output.AppTier(category) }

// appForIP: 规则直接命中的 IP(ip_app_map)优先; 否则用 DNS/SNI 反查到的域名归类(DNS 关联)。
// v6.x DPI v2: 用户纠正规则(fp_user_rules.go, 任意端口的 IP 规则 / 域名规则)排在最前。
func appForIP(ip string, apps map[string]ipApp, names map[string]ipName) (ipApp, bool) {
	a, _, ok := appForIPSrc(ip, apps, names)
	return a, ok
}

// appForIPSrc 同 appForIP, 另返回来源: user(用户纠正)| rule(ip_app_map)| name(域名归类)
func appForIPSrc(ip string, apps map[string]ipApp, names map[string]ipName) (ipApp, string, bool) {
	if dpiUserRulesCur.Load() != nil {
		if a, ok := dpiUserMatchIP(ip, 0, time.Now()); ok {
			return a, "user", true
		}
		if n, ok := names[ip]; ok && n.Name != "" {
			if a, ok := dpiUserMatchName(n.Name); ok {
				return a, "user", true
			}
		}
	}
	if a, ok := apps[ip]; ok && a.ID != "" {
		return a, "rule", true
	}
	if n, ok := names[ip]; ok && n.App != "" {
		name := n.AppName
		if name == "" {
			name = n.App
		}
		return ipApp{ID: n.App, Name: name, Category: n.Category}, "name", true
	}
	return ipApp{}, "", false
}

// 「正在用」: 按 conntrack 实时速率把每台设备的流量归到应用, 做指数平滑
// (时间常数 liveAppTau), 取速率最高的几个。比 dpid 的"累计命中次数"准得多:
//   - 看的是真实字节(dpid 的 BPF 只抓握手包, 它的字节数几乎为零)
//   - 1 小时前刷过的抖音会自然衰减掉, 一直发心跳的微信速率很低排不上
//   - 广告/统计 SDK、CDN 不算应用; 系统服务只在没有真应用时显示
const (
	liveAppTau     = 20.0  // 秒
	liveAppMinBps  = 16000 // 平滑后 < 2KB/s 不算"在用"
	liveAppDropBps = 800   // 低于此值且 2 分钟没新流量就丢弃
	liveAppMax     = 4
)

type liveAppAcc struct {
	id, name string
	cat      string
	tier     int
	ewma     float64
	last     time.Time // 最近一次有流量
}

var liveAppState struct {
	mu     sync.Mutex
	calls  map[string]*liveCall // v5.16: mac → 正在进行的通话
	snapAt time.Time
	lastAt time.Time
	m      map[string]map[string]*liveAppAcc // mac → app id → acc
}

func (s *server) liveAppsByMAC() map[string][]map[string]interface{} {
	sn := conntrackSnapshot()
	out := map[string][]map[string]interface{}{}
	if !sn.readable || !sn.acct {
		return out
	}
	liveAppState.mu.Lock()
	defer liveAppState.mu.Unlock()
	if liveAppState.m == nil {
		liveAppState.m = map[string]map[string]*liveAppAcc{}
	}
	if !sn.at.Equal(liveAppState.snapAt) {
		owner := map[string]string{}
		for mac, ips := range s.deviceIPsByMAC() {
			for _, ip := range ips {
				owner[ip] = mac
			}
		}
		names := s.loadIPNames()
		apps := s.loadIPApps()
		inst := map[string]map[string]*liveAppAcc{}
		callNow := map[string]liveCall{}
		for _, e := range sn.entries {
			mac, ok := owner[e.Src]
			if !ok {
				continue
			}
			k := e.key()
			bps := sn.upBps[k] + sn.dnBps[k]
			if bps <= 0 {
				continue
			}
			if c, ok := callCandidate(e, sn.upBps[k], sn.dnBps[k], apps, names); ok && c.bps > callNow[mac].bps {
				callNow[mac] = c
			}
			a, ok := appForIP(e.Dst, apps, names)
			if !ok && !isPrivateIP(e.Dst) { // v6.x DPI v2: 无域名连接按指纹/用户纠正归属
				var fa flowAttr
				if fa, ok = fpFor(s.hncDir).attribute(k, apps, names, sn.at); ok {
					a = fa.App
				}
			}
			if !ok {
				continue
			}
			tier := appTier(a.Category)
			if tier == tierHidden {
				continue
			}
			if inst[mac] == nil {
				inst[mac] = map[string]*liveAppAcc{}
			}
			acc := inst[mac][a.ID]
			if acc == nil {
				acc = &liveAppAcc{id: a.ID, name: a.Name, cat: a.Category, tier: tier}
				inst[mac][a.ID] = acc
			}
			acc.ewma += bps // 这里暂存本轮瞬时速率
		}
		dt := 2.0
		if !liveAppState.lastAt.IsZero() {
			dt = sn.at.Sub(liveAppState.lastAt).Seconds()
		}
		if dt <= 0 {
			dt = 1
		}
		f := math.Exp(-dt / liveAppTau)
		for mac, accs := range liveAppState.m {
			for id, acc := range accs {
				now := 0.0
				if in := inst[mac][id]; in != nil {
					now = in.ewma
					acc.last = sn.at
					delete(inst[mac], id)
				}
				acc.ewma = acc.ewma*f + now*(1-f)
				if acc.ewma < liveAppDropBps && sn.at.Sub(acc.last) > 2*time.Minute {
					delete(accs, id)
				}
			}
			if len(accs) == 0 {
				delete(liveAppState.m, mac)
			}
		}
		for mac, accs := range inst {
			for id, in := range accs {
				if liveAppState.m[mac] == nil {
					liveAppState.m[mac] = map[string]*liveAppAcc{}
				}
				liveAppState.m[mac][id] = &liveAppAcc{id: id, name: in.name, cat: in.cat, tier: in.tier, ewma: in.ewma * (1 - f), last: sn.at}
			}
		}
		updateCallsLocked(callNow, sn.at)
		liveAppState.snapAt = sn.at
		liveAppState.lastAt = sn.at
	}
	for mac, accs := range liveAppState.m {
		var list []*liveAppAcc
		var total float64
		hasApp := false
		for _, acc := range accs {
			if acc.ewma >= liveAppMinBps {
				list = append(list, acc)
				total += acc.ewma
				if acc.tier == tierApp {
					hasApp = true
				}
			}
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].tier != list[j].tier {
				return list[i].tier < list[j].tier
			}
			return list[i].ewma > list[j].ewma
		})
		var items []map[string]interface{}
		for _, acc := range list {
			if hasApp && acc.tier != tierApp {
				continue // 有真应用时不显示系统服务
			}
			items = append(items, map[string]interface{}{
				"id": acc.id, "name": acc.name, "bps": int64(acc.ewma / 8), "category": acc.cat,
				"share": math.Round(acc.ewma/total*100) / 100, "system": acc.tier == tierSystem,
			})
			if len(items) >= liveAppMax {
				break
			}
		}
		if len(items) > 0 {
			out[mac] = items
		}
	}
	return out
}

// actionQUICBlockSet v5.14: 「强制 QUIC 回落 TCP」开关(执行见 bin/quic_block_sync.sh)
func actionQUICBlockSet(hncDir string, p map[string]string) actionResp {
	r := actionSetTopBool(hncDir, "quic_block", p, "", "")
	if !r.OK {
		return r
	}
	rc, out := runBin(hncDir, "quic_block_sync.sh")
	if rc != 0 {
		return actionResp{OK: false, Error: "quic block sync failed", Detail: lastLine(strings.TrimSpace(out))}
	}
	if d := lastLine(strings.TrimSpace(out)); d != "" {
		r.Detail = d
	}
	return r
}

// ─── v5.16: 通话检测 ──────────────────────────────────────────────────
//
// dpid 规则里的「微信电话」子类靠包速率判断, 但 dpid 的抓包过滤器只放行握手包,
// 通话的 UDP 媒体流根本到不了它 —— 那个检测实际上从未触发。这里改用连接表:
// 一条 UDP 连接(非 443/53/123 等)双向都在持续收发、上下行量级接近, 持续 ≥8 秒
// 即认为在通话; 总速率 > 600 kbps 记为视频通话。能对上应用的显示「微信 · 语音通话」。

type liveCall struct {
	label, kind string
	bps         float64
	since, last time.Time
}

var callExcludedPorts = map[int]bool{443: true, 80: true, 53: true, 123: true, 853: true, 5353: true, 1900: true, 137: true, 67: true, 68: true}

var wechatVoipPrefix = netip.MustParsePrefix("183.232.84.0/24")

func callCandidate(e ctEntry, up, dn float64, apps map[string]ipApp, names map[string]ipName) (liveCall, bool) {
	if e.Proto != "udp" || callExcludedPorts[e.Dport] || isPrivateIP(e.Dst) {
		return liveCall{}, false
	}
	const minBps, maxBps = 12000, 8_000_000
	if up < minBps || dn < minBps || up > maxBps || dn > maxBps {
		return liveCall{}, false
	}
	lo, hi := up, dn
	if lo > hi {
		lo, hi = hi, lo
	}
	if lo/hi < 0.08 { // 单向为主(下载/直播)不是通话
		return liveCall{}, false
	}
	name := ""
	if a, ok := appForIP(e.Dst, apps, names); ok && appTier(a.Category) != tierHidden {
		name = a.Name
	}
	if name == "" {
		if addr, err := netip.ParseAddr(e.Dst); err == nil && wechatVoipPrefix.Contains(addr.Unmap()) {
			name = "微信"
		}
	}
	kind := "语音通话"
	if up+dn > 600_000 {
		kind = "视频通话"
	}
	label := kind
	if name != "" {
		label = name + " · " + kind
	}
	return liveCall{label: label, kind: kind, bps: up + dn}, true
}

func updateCallsLocked(now map[string]liveCall, at time.Time) {
	if liveAppState.calls == nil {
		liveAppState.calls = map[string]*liveCall{}
	}
	for mac, c := range liveAppState.calls {
		if _, ok := now[mac]; !ok && at.Sub(c.last) > 6*time.Second { // 允许一两次采样的空档
			delete(liveAppState.calls, mac)
		}
	}
	for mac, c := range now {
		old := liveAppState.calls[mac]
		c.last = at
		if old != nil {
			c.since = old.since
		} else {
			c.since = at
		}
		cc := c
		liveAppState.calls[mac] = &cc
	}
}

// liveCallsByMAC 返回持续 ≥8 秒的通话(在 liveAppsByMAC 之后调用)
func liveCallsByMAC() map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	liveAppState.mu.Lock()
	defer liveAppState.mu.Unlock()
	for mac, c := range liveAppState.calls {
		if c.last.Sub(c.since) < 8*time.Second {
			continue
		}
		out[mac] = map[string]interface{}{"label": c.label, "kind": c.kind, "bps": int64(c.bps / 8), "since": c.since.Unix()}
	}
	return out
}
