// v6_flow_scalpel.go — HNC v6.0.0 · Vector (T4 模块 4):
// FlowScalpel 五元组实时透视 + 免断网单流秒斩手术刀。
//
// 两阶段精准外科手术斩流机制:
//   Step 1: 纯 Go AF_NETLINK (NETLINK_NETFILTER, NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_DELETE),
//           100% 使用 encoding/binary.LittleEndian 编码消息头与属性头,
//           微秒级抹除内核 nf_conntrack 对应五元组状态。
//   Step 2: 通过内存管道向 iptables-restore -w 2 --noflush / ip6tables-restore -w 2 --noflush
//           原子写入独立子链 HNC_SCALPEL 的精确五元组 REJECT 规则:
//             - TCP: -j REJECT --reject-with tcp-reset（借内核真实序列号干净复位双端连接）
//             - UDP: -j REJECT --reject-with icmp-port-unreachable（IPv6 用 icmp6-port-unreachable）
//           规则在 5 秒后自动清理（mode="cut_once"）, 或同步叠加 15 分钟目标端点冻结（mode="cut_freeze_15m"）,
//           同一 CDN IP 上的其他正常应用与连接 100% 毫发无损!

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	scalpelChainName      = "HNC_SCALPEL"
	scalpelModeCutOnce    = "cut_once"
	scalpelModeFreeze15m  = "cut_freeze_15m"
	scalpelResetTTL       = 5 * time.Second
	scalpelUDPResetTTL    = 1 * time.Second
	scalpelFreezeTTL      = 15 * time.Minute
	scalpelMaxActiveRules = 128
	scalpelRestoreTimeout = 2500 * time.Millisecond

	// Netlink / ctnetlink 协议常量（严格对应 linux/netlink.h 与 linux/netfilter/nfnetlink_conntrack.h）
	scalpelNlHdrLen       = 16
	scalpelNfGenMsgLen    = 4
	scalpelNlmFRequest    = 0x0001
	scalpelNlmFAck        = 0x0004
	scalpelNlMsgError     = 0x0002
	scalpelAfInet         = 2
	scalpelAfInet6        = 10
	scalpelNfNetlinkV0    = 0
	scalpelCtDeleteMsgTyp = (nfnlSubsysCtnetlink << 8) | ipctnlMsgCtDelete // 0x0102
)

var errScalpelCtENOENT = errors.New("ctnetlink entry not found (ENOENT)")

type scalpelFreezeGuardError struct {
	ReasonCode string
	Vendor     string
	Detail     string
}

func (e *scalpelFreezeGuardError) Error() string {
	if e == nil {
		return "scalpel freeze guard blocked"
	}
	return e.Detail
}

// ScalpelTuple 五元组输入。
type ScalpelTuple struct {
	Proto string `json:"proto"` // tcp | udp
	SrcIP string `json:"src_ip"`
	Sport int    `json:"sport"`
	DstIP string `json:"dst_ip"`
	Dport int    `json:"dport"`
}

// ScalpelActiveRule 挂入 HNC_SCALPEL / HNC_SCALPEL_HOST 链的精准规则项（到期自动摘除）。
type ScalpelActiveRule struct {
	ID          string       `json:"id"`
	Scope       string       `json:"scope,omitempty"` // hotspot | host
	UID         int          `json:"uid,omitempty"`
	PeerUID     int          `json:"peer_uid,omitempty"`
	HasUID      bool         `json:"-"`
	Package     string       `json:"package,omitempty"`
	Mode        string       `json:"mode"` // reset_5s | freeze_15m
	IsIPv6      bool         `json:"v6"`
	Tuple       ScalpelTuple `json:"tuple"`
	ClientMAC   string       `json:"client_mac,omitempty"`
	MatchSport  bool         `json:"match_sport"` // reset_5s=true(精确五元组); freeze_15m=false(冻结目标端点新建连接)
	CreatedAt   int64        `json:"created_at"`
	ExpiresAt   time.Time    `json:"-"`
	ExpiresUnix int64        `json:"expires_at"`
}

type scalpelRestoreRunner func(family int, payload string) error
type scalpelCtDeleteRunner func(tuple ScalpelTuple, seq uint32) error

type flowScalpelEngine struct {
	// 64 位原子字段严格置于 offset 0 (兼容 32-bit ARM)
	seqGen       atomic.Uint64
	cutTotal     atomic.Uint64
	guardBlocked atomic.Uint64
	hostCutTotal atomic.Uint64

	tickerActive  atomic.Bool
	loopRunning   atomic.Bool
	wakeOnce      sync.Once
	wakeCh        chan struct{}
	sweepInterval time.Duration
	ruleCountHook func() int
	sweepHook     func(time.Time)
	activityHook  func() (<-chan struct{}, Activity)
	simActiveHook func() bool

	srv               *server
	applyMu           sync.Mutex
	mu                sync.Mutex
	timerMu           sync.Mutex
	standaloneTimer   *time.Timer
	rules             []ScalpelActiveRule
	hostRules         []ScalpelActiveRule
	simRules          []ScalpelActiveRule
	hookEnsuredV4     bool
	hookEnsuredV6     bool
	hostHookEnsuredV4 bool
	hostHookEnsuredV6 bool
	forceHookCheck    bool
	ctDelRunner       scalpelCtDeleteRunner
	sockDestroyRunner scalpelSockDestroyRunner
	iptRunner         scalpelRestoreRunner
	hostIptRunner     scalpelRestoreRunner
	resetDuration     time.Duration
	freezeDur         time.Duration
}

func newFlowScalpelEngine(s *server) *flowScalpelEngine {
	eng := &flowScalpelEngine{
		wakeCh:        make(chan struct{}, 1),
		srv:           s,
		resetDuration: scalpelResetTTL,
		freezeDur:     scalpelFreezeTTL,
	}
	eng.ctDelRunner = eng.defaultDeleteConntrackNetlink
	eng.sockDestroyRunner = defaultScalpelHostSockDestroy
	eng.iptRunner = eng.defaultPipeRestore
	return eng
}

// ── Step 1: 纯 Go binary.LittleEndian 构造 CTNETLINK IPCTNL_MSG_CT_DELETE 报文 ──

func protoNumberFromName(proto string) (uint8, string, error) {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "tcp", "6":
		return 6, "tcp", nil
	case "udp", "17":
		return 17, "udp", nil
	default:
		return 0, "", errors.New("proto must be tcp or udp")
	}
}

func validateScalpelTuple(in ScalpelTuple) (ScalpelTuple, uint8, bool, error) {
	pnum, pname, err := protoNumberFromName(in.Proto)
	if err != nil {
		return ScalpelTuple{}, 0, false, err
	}
	src := net.ParseIP(strings.TrimSpace(in.SrcIP))
	dst := net.ParseIP(strings.TrimSpace(in.DstIP))
	if src == nil || dst == nil {
		return ScalpelTuple{}, 0, false, errors.New("invalid src_ip or dst_ip")
	}
	srcV4 := src.To4()
	dstV4 := dst.To4()
	if (srcV4 == nil) != (dstV4 == nil) {
		return ScalpelTuple{}, 0, false, errors.New("src_ip and dst_ip address family mismatch")
	}
	if in.Sport <= 0 || in.Sport > 65535 || in.Dport <= 0 || in.Dport > 65535 {
		return ScalpelTuple{}, 0, false, errors.New("sport and dport must be 1..65535")
	}
	isV6 := srcV4 == nil
	norm := ScalpelTuple{
		Proto: pname,
		SrcIP: src.String(),
		Sport: in.Sport,
		DstIP: dst.String(),
		Dport: in.Dport,
	}
	return norm, pnum, isV6, nil
}

func appendNlAttr(dst []byte, attrType uint16, payload []byte) []byte {
	rawLen := 4 + len(payload)
	alignedLen := (rawLen + 3) &^ 3
	off := len(dst)
	dst = append(dst, make([]byte, alignedLen)...)
	binary.LittleEndian.PutUint16(dst[off:off+2], uint16(rawLen))
	binary.LittleEndian.PutUint16(dst[off+2:off+4], attrType)
	copy(dst[off+4:off+rawLen], payload)
	return dst
}

// buildConntrackDeleteNetlinkMsg 纯字节级编码 NETLINK_NETFILTER IPCTNL_MSG_CT_DELETE 请求帧。
// 100% 使用 encoding/binary.LittleEndian 写入 nlmsghdr / nfgenmsg / nlattr 头部。
func buildConntrackDeleteNetlinkMsg(in ScalpelTuple, seq uint32) ([]byte, error) {
	norm, protoNum, isV6, err := validateScalpelTuple(in)
	if err != nil {
		return nil, err
	}
	srcIP := net.ParseIP(norm.SrcIP)
	dstIP := net.ParseIP(norm.DstIP)

	// 1. 构造 CTA_TUPLE_IP 子属性
	var ipAttrs []byte
	family := uint8(scalpelAfInet)
	if !isV6 {
		ipAttrs = appendNlAttr(ipAttrs, ctaIPv4Src, srcIP.To4())
		ipAttrs = appendNlAttr(ipAttrs, ctaIPv4Dst, dstIP.To4())
	} else {
		family = scalpelAfInet6
		ipAttrs = appendNlAttr(ipAttrs, ctaIPv6Src, srcIP.To16())
		ipAttrs = appendNlAttr(ipAttrs, ctaIPv6Dst, dstIP.To16())
	}

	// 2. 构造 CTA_TUPLE_PROTO 子属性（端口按网络字节序高位在前编码并打 NLA_F_NET_BYTEORDER 标志）
	var protoAttrs []byte
	protoAttrs = appendNlAttr(protoAttrs, ctaProtoNum, []byte{protoNum})
	sportNet := []byte{byte(norm.Sport >> 8), byte(norm.Sport)}
	dportNet := []byte{byte(norm.Dport >> 8), byte(norm.Dport)}
	protoAttrs = appendNlAttr(protoAttrs, nlaFNetByteorder|ctaProtoSrcPort, sportNet)
	protoAttrs = appendNlAttr(protoAttrs, nlaFNetByteorder|ctaProtoDstPort, dportNet)

	// 3. 封装嵌套 CTA_TUPLE_ORIG
	var tupleOrig []byte
	tupleOrig = appendNlAttr(tupleOrig, nlaFNested|ctaTupleIP, ipAttrs)
	tupleOrig = appendNlAttr(tupleOrig, nlaFNested|ctaTupleProto, protoAttrs)

	var attrs []byte
	attrs = appendNlAttr(attrs, nlaFNested|ctaTupleOrig, tupleOrig)

	// 4. 组装 nlmsghdr (16B) + nfgenmsg (4B) + attrs
	totalLen := scalpelNlHdrLen + scalpelNfGenMsgLen + len(attrs)
	msg := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint16(msg[4:6], scalpelCtDeleteMsgTyp)
	binary.LittleEndian.PutUint16(msg[6:8], scalpelNlmFRequest|scalpelNlmFAck)
	binary.LittleEndian.PutUint32(msg[8:12], seq)
	binary.LittleEndian.PutUint32(msg[12:16], 0)

	// nfgenmsg: family(1B), version(1B), res_id(2B)
	msg[16] = family
	msg[17] = scalpelNfNetlinkV0
	binary.LittleEndian.PutUint16(msg[18:20], 0)

	copy(msg[20:], attrs)
	return msg, nil
}

func parseNetlinkAck(resp []byte) error {
	if len(resp) < scalpelNlHdrLen {
		return errors.New("short netlink response")
	}
	nlLen := int(binary.LittleEndian.Uint32(resp[0:4]))
	nlType := binary.LittleEndian.Uint16(resp[4:6])
	if nlLen < scalpelNlHdrLen || nlLen > len(resp) {
		return errors.New("malformed netlink length")
	}
	if nlType == scalpelNlMsgError {
		if nlLen < scalpelNlHdrLen+4 {
			return errors.New("truncated NLMSG_ERROR")
		}
		errnoNeg := int32(binary.LittleEndian.Uint32(resp[16:20]))
		if errnoNeg == 0 {
			return nil
		}
		if -errnoNeg == 2 { // ENOENT(2): 正向元组未命中，交由上层触发反向元组二次补刀或视为已自然销毁
			return errScalpelCtENOENT
		}
		return fmt.Errorf("ctnetlink delete errno %d", -errnoNeg)
	}
	return nil
}

func isScalpelCtENOENT(err error) bool {
	return errors.Is(err, errScalpelCtENOENT) || errors.Is(err, syscall.ENOENT)
}

func reverseScalpelTuple(t ScalpelTuple) ScalpelTuple {
	return ScalpelTuple{
		Proto: t.Proto,
		SrcIP: t.DstIP,
		Sport: t.Dport,
		DstIP: t.SrcIP,
		Dport: t.Sport,
	}
}

func (e *flowScalpelEngine) defaultDeleteConntrackNetlink(tuple ScalpelTuple, seq uint32) error {
	return sendConntrackDeleteNetlink(tuple, seq)
}

func (e *flowScalpelEngine) deleteConntrackWithReverseFallback(norm ScalpelTuple) (seq uint32, reverseRetried bool, err error) {
	seq = uint32(e.seqGen.Add(1))
	if e.ctDelRunner == nil {
		return seq, false, nil
	}
	err1 := e.ctDelRunner(norm, seq)
	if err1 == nil {
		return seq, false, nil
	}
	if !isScalpelCtENOENT(err1) {
		return seq, false, err1
	}
	// 正向五元组返回 ENOENT 时（服务端主动发起或 NAT 反向记录为 ORIG），立即交换源目地址与端口二次补刀
	revSeq := uint32(e.seqGen.Add(1))
	err2 := e.ctDelRunner(reverseScalpelTuple(norm), revSeq)
	if err2 == nil || isScalpelCtENOENT(err2) {
		return seq, true, nil
	}
	return seq, true, err2
}

// ── 共享 CDN 与核心基础设施 15m 端点冻结防误伤守卫 ──────────────────────────

func isScalpelProtectedCorePort(port int) bool {
	switch port {
	case 53, 853, 123:
		return true
	default:
		return false
	}
}

var scalpelFakeIPPrefix = netip.MustParsePrefix("198.18.0.0/15")

func isScalpelFakeIP(ipStr string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return false
	}
	return scalpelFakeIPPrefix.Contains(addr.Unmap())
}

func evaluateScalpelFreezeGuard(s *server, norm ScalpelTuple) *scalpelFreezeGuardError {
	if isScalpelProtectedCorePort(norm.Dport) || isScalpelProtectedCorePort(norm.Sport) {
		corePort := norm.Dport
		if !isScalpelProtectedCorePort(corePort) {
			corePort = norm.Sport
		}
		return &scalpelFreezeGuardError{
			ReasonCode: "core_port_freeze_blocked",
			Vendor:     "Core Network Port",
			Detail:     fmt.Sprintf("目标端口 %d 属于核心网络基础设施（DNS/DoT/NTP），已拒绝 15 分钟端点冻结以防设备断网；仅允许使用 cut_once 执行一次性单流秒斩", corePort),
		}
	}
	if isScalpelFakeIP(norm.DstIP) || isScalpelFakeIP(norm.SrcIP) {
		hitIP := norm.DstIP
		if !isScalpelFakeIP(hitIP) {
			hitIP = norm.SrcIP
		}
		return &scalpelFreezeGuardError{
			ReasonCode: "fake_ip_freeze_blocked",
			Vendor:     "TUN Fake-IP Pool",
			Detail:     fmt.Sprintf("目标地址 %s 属于代理 TUN 虚拟 Fake-IP 地址池（198.18.0.0/15），池内地址会被多个域名动态复用，已拒绝 15 分钟端点冻结以防误伤其他应用；仅允许使用 cut_once 执行一次性单流秒斩", hitIP),
		}
	}
	if shared, vendor := detectSharedInfraIP(s, norm.DstIP); shared {
		if strings.TrimSpace(vendor) == "" {
			vendor = "共享基础设施"
		}
		return &scalpelFreezeGuardError{
			ReasonCode: "shared_cdn_freeze_blocked",
			Vendor:     vendor,
			Detail:     fmt.Sprintf("目标地址 %s 属于 %s 共享 CDN/云网关或公共基础设施节点，已拒绝 15 分钟端点冻结以免误伤共用该节点的其他正常应用新建连接；仅允许使用 cut_once 执行一次性五元组秒斩", norm.DstIP, vendor),
		}
	}
	return nil
}

// ── Step 2: 双栈 iptables-restore / ip6tables-restore -w 2 --noflush 构造与提交 ──

// buildScalpelRestorePayload 纯函数生成 *filter 表 HNC_SCALPEL 子链的 --noflush 内存载荷。
func buildScalpelRestorePayload(isIPv6 bool, rules []ScalpelActiveRule) string {
	var b strings.Builder
	b.WriteString("*filter\n")
	b.WriteString(":" + scalpelChainName + " - [0:0]\n")
	for _, r := range rules {
		if r.IsIPv6 != isIPv6 {
			continue
		}
		t := r.Tuple
		rejectWith := "tcp-reset"
		if t.Proto == "udp" {
			if isIPv6 {
				rejectWith = "icmp6-port-unreachable"
			} else {
				rejectWith = "icmp-port-unreachable"
			}
		}
		if r.MatchSport {
			if t.Proto == "tcp" {
				// TCP 精确五元组双向复位: 严格加 ! --syn 仅对存量报文回发真实 RST, 绝不误杀同端口新建握手
				fmt.Fprintf(&b, "-A %s -p tcp ! --syn -s %s -d %s --sport %d --dport %d -j REJECT --reject-with %s\n",
					scalpelChainName, t.SrcIP, t.DstIP, t.Sport, t.Dport, rejectWith)
				fmt.Fprintf(&b, "-A %s -p tcp ! --syn -s %s -d %s --sport %d --dport %d -j REJECT --reject-with %s\n",
					scalpelChainName, t.DstIP, t.SrcIP, t.Dport, t.Sport, rejectWith)
			} else {
				// UDP 短暂 1s 精确五元组拦截: 快速通知双端端口不可达而避免持续 ICMP 轰炸客户端
				fmt.Fprintf(&b, "-A %s -p %s -s %s -d %s --sport %d --dport %d -j REJECT --reject-with %s\n",
					scalpelChainName, t.Proto, t.SrcIP, t.DstIP, t.Sport, t.Dport, rejectWith)
				fmt.Fprintf(&b, "-A %s -p %s -s %s -d %s --sport %d --dport %d -j REJECT --reject-with %s\n",
					scalpelChainName, t.Proto, t.DstIP, t.SrcIP, t.Dport, t.Sport, rejectWith)
			}
		} else {
			// 15 分钟冻结目标端点: 优先绑定客户端 MAC 并限定 NEW,INVALID 状态, 绝不连坐同一目标 IP 上其他已建立正常连接
			if mac := canonMAC(r.ClientMAC); mac != "" {
				fmt.Fprintf(&b, "-A %s -m mac --mac-source %s -d %s -p %s --dport %d -m conntrack --ctstate NEW,INVALID -j REJECT --reject-with %s\n",
					scalpelChainName, mac, t.DstIP, t.Proto, t.Dport, rejectWith)
			} else {
				fmt.Fprintf(&b, "-A %s -s %s -d %s -p %s --dport %d -m conntrack --ctstate NEW,INVALID -j REJECT --reject-with %s\n",
					scalpelChainName, t.SrcIP, t.DstIP, t.Proto, t.Dport, rejectWith)
			}
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

var (
	scalpelResolveBinFn = resolveScalpelBin
	scalpelIptExecFn    = defaultScalpelIptExec
)

func resolveScalpelBin(name string) string {
	for _, dir := range []string{"/system/bin", "/system/xbin", "/vendor/bin", "/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		cand := dir + "/" + name
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func defaultScalpelIptExec(binPath string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, binPath, args...))
	cmd.Env = subprocEnvWithFallbackPath()
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func runScalpelIptWithWaitFallback(binPath string, args ...string) error {
	out1, err1 := scalpelIptExecFn(binPath, append([]string{"-w", "2"}, args...)...)
	if err1 == nil {
		return nil
	}
	if !isXtablesWaitFlagError(out1 + " " + err1.Error()) {
		return err1
	}
	out2, err2 := scalpelIptExecFn(binPath, append([]string{"-w"}, args...)...)
	if err2 == nil {
		return nil
	}
	if isXtablesWaitFlagError(out2 + " " + err2.Error()) {
		_, err3 := scalpelIptExecFn(binPath, args...)
		return err3
	}
	return err2
}

// ensureForwardJump 每次提交或对账前通过 -t filter -C FORWARD -j HNC_SCALPEL 实时核验挂载点,
// 彻底杜绝粘滞布尔跳过导致 netd 冲刷后规则链悬空。
func (e *flowScalpelEngine) ensureForwardJump(isIPv6 bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	forceCheck := e.forceHookCheck
	e.mu.Unlock()
	if !forceCheck && (e.srv == nil || !useNativeDataplane(e.srv.hncDir)) {
		return
	}
	iptName := "iptables"
	if isIPv6 {
		iptName = "ip6tables"
	}
	binPath := scalpelResolveBinFn(iptName)
	if binPath == "" {
		e.mu.Lock()
		if isIPv6 {
			e.hookEnsuredV6 = false
		} else {
			e.hookEnsuredV4 = false
		}
		e.mu.Unlock()
		return
	}
	ensured := true
	if runScalpelIptWithWaitFallback(binPath, "-t", "filter", "-C", "FORWARD", "-j", scalpelChainName) != nil {
		_ = runScalpelIptWithWaitFallback(binPath, "-t", "filter", "-N", scalpelChainName)
		if insErr := runScalpelIptWithWaitFallback(binPath, "-t", "filter", "-I", "FORWARD", "1", "-j", scalpelChainName); insErr != nil {
			ensured = false
		}
	}
	e.mu.Lock()
	if isIPv6 {
		e.hookEnsuredV6 = ensured
	} else {
		e.hookEnsuredV4 = ensured
	}
	e.mu.Unlock()
}

// ensureHostOutputJump 每次提交或对账前通过 -t filter -C OUTPUT -j HNC_SCALPEL_HOST 实时核验挂载点,
// 缺失时立即建链并挂入 OUTPUT 顶部第 1 条（全程在 e.mu 锁外执行子进程）。
func (e *flowScalpelEngine) ensureHostOutputJump(isIPv6 bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	forceCheck := e.forceHookCheck
	e.mu.Unlock()
	if !forceCheck && (e.srv == nil || !useNativeDataplane(e.srv.hncDir)) {
		return
	}
	iptName := "iptables"
	if isIPv6 {
		iptName = "ip6tables"
	}
	binPath := scalpelResolveBinFn(iptName)
	if binPath == "" {
		e.mu.Lock()
		if isIPv6 {
			e.hostHookEnsuredV6 = false
		} else {
			e.hostHookEnsuredV4 = false
		}
		e.mu.Unlock()
		return
	}
	ensured := true
	if runScalpelIptWithWaitFallback(binPath, "-t", "filter", "-C", "OUTPUT", "-j", scalpelHostChainName) != nil {
		_ = runScalpelIptWithWaitFallback(binPath, "-t", "filter", "-N", scalpelHostChainName)
		if insErr := runScalpelIptWithWaitFallback(binPath, "-t", "filter", "-I", "OUTPUT", "1", "-j", scalpelHostChainName); insErr != nil {
			ensured = false
		}
	}
	e.mu.Lock()
	if isIPv6 {
		e.hostHookEnsuredV6 = ensured
	} else {
		e.hostHookEnsuredV4 = ensured
	}
	e.mu.Unlock()
}

func (e *flowScalpelEngine) defaultPipeRestore(family int, payload string) error {
	if e.srv == nil || !useNativeDataplane(e.srv.hncDir) {
		return nil
	}
	isV6 := family == scalpelAfInet6
	binName := "iptables-restore"
	if isV6 {
		binName = "ip6tables-restore"
	}
	binPath := scalpelResolveBinFn(binName)
	if binPath == "" {
		return fmt.Errorf("%s not found", binName)
	}
	return pipeIptablesRestoreWithTimeout(binPath, []byte(payload), scalpelRestoreTimeout)
}

func (e *flowScalpelEngine) resolveClientMAC(srcIP string) string {
	if e == nil || e.srv == nil || e.srv.hncDir == "" || srcIP == "" {
		return ""
	}
	_, macByIP := scalpelBuildDeviceDirectory(e.srv)
	if mac := canonMAC(macByIP[srcIP]); mac != "" {
		return mac
	}
	return scalpelInferUniqueV6PrefixMAC(srcIP, macByIP)
}

func scalpelSameBidirectionalTuple(a, b ScalpelTuple) bool {
	if a.Proto != b.Proto {
		return false
	}
	if a.SrcIP == b.SrcIP && a.Sport == b.Sport && a.DstIP == b.DstIP && a.Dport == b.Dport {
		return true
	}
	return a.SrcIP == b.DstIP && a.Sport == b.Dport && a.DstIP == b.SrcIP && a.Dport == b.Sport
}

func scalpelSameFreezeTarget(a, b ScalpelActiveRule) bool {
	if a.Mode != "freeze_15m" || b.Mode != "freeze_15m" || a.IsIPv6 != b.IsIPv6 {
		return false
	}
	if a.Tuple.Proto != b.Tuple.Proto || a.Tuple.DstIP != b.Tuple.DstIP || a.Tuple.Dport != b.Tuple.Dport {
		return false
	}
	macA := canonMAC(a.ClientMAC)
	macB := canonMAC(b.ClientMAC)
	if macA != "" && macB != "" {
		return macA == macB
	}
	if macA == "" && macB == "" {
		return a.Tuple.SrcIP == b.Tuple.SrcIP
	}
	return false
}

// upsertRuleLocked 对相同活跃规则原地刷新过期时间去重，并在满 128 条上限时淘汰最早过期项防内存膨胀。
func (e *flowScalpelEngine) upsertRuleLocked(cand ScalpelActiveRule) (changedV4, changedV6 bool) {
	for i := range e.rules {
		ex := &e.rules[i]
		if ex.Mode != cand.Mode || ex.IsIPv6 != cand.IsIPv6 || ex.MatchSport != cand.MatchSport {
			continue
		}
		matched := false
		if cand.MatchSport {
			matched = scalpelSameBidirectionalTuple(ex.Tuple, cand.Tuple)
		} else {
			matched = scalpelSameFreezeTarget(*ex, cand)
		}
		if matched {
			ex.Tuple = cand.Tuple
			if cand.ClientMAC != "" {
				ex.ClientMAC = cand.ClientMAC
			}
			ex.CreatedAt = cand.CreatedAt
			if cand.ExpiresAt.After(ex.ExpiresAt) {
				ex.ExpiresAt = cand.ExpiresAt
				ex.ExpiresUnix = cand.ExpiresUnix
			}
			if cand.IsIPv6 {
				return false, true
			}
			return true, false
		}
	}

	for len(e.rules) >= scalpelMaxActiveRules {
		oldestIdx := 0
		for i := 1; i < len(e.rules); i++ {
			if e.rules[i].ExpiresAt.Before(e.rules[oldestIdx].ExpiresAt) {
				oldestIdx = i
			}
		}
		evicted := e.rules[oldestIdx]
		if evicted.IsIPv6 {
			changedV6 = true
		} else {
			changedV4 = true
		}
		e.rules = append(e.rules[:oldestIdx], e.rules[oldestIdx+1:]...)
	}

	e.rules = append(e.rules, cand)
	if cand.IsIPv6 {
		changedV6 = true
	} else {
		changedV4 = true
	}
	return changedV4, changedV6
}

// Cut 执行两步秒斩手术并驱动单一定时器按最早过期时间回收。
func (e *flowScalpelEngine) Cut(now time.Time, tuple ScalpelTuple, mode string) (map[string]any, error) {
	return e.CutWithMAC(now, tuple, mode, "")
}

// CutWithMAC 支持传入或自动解析客户端 MAC 并执行两步秒斩手术与 15m 共享基础设施防误伤守卫。
func (e *flowScalpelEngine) CutWithMAC(now time.Time, tuple ScalpelTuple, mode, rawMAC string) (map[string]any, error) {
	norm, _, isV6, err := validateScalpelTuple(tuple)
	if err != nil {
		return nil, err
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = scalpelModeCutOnce
	}
	if mode != scalpelModeCutOnce && mode != scalpelModeFreeze15m {
		return nil, errors.New("mode must be cut_once or cut_freeze_15m")
	}

	if mode == scalpelModeFreeze15m {
		if guardErr := evaluateScalpelFreezeGuard(e.srv, norm); guardErr != nil {
			e.guardBlocked.Add(1)
			resp := map[string]any{
				"ok":            false,
				"guard_blocked": true,
				"reason_code":   guardErr.ReasonCode,
				"allowed_mode":  scalpelModeCutOnce,
				"vendor":        guardErr.Vendor,
				"tuple":         norm,
				"error":         "freeze_guard_blocked",
				"detail":        guardErr.Detail,
			}
			return resp, guardErr
		}
	}

	clientMAC := canonMAC(rawMAC)
	if clientMAC == "" {
		clientMAC = e.resolveClientMAC(norm.SrcIP)
	}

	seq, revRetried, ctErr := e.deleteConntrackWithReverseFallback(norm)
	ctErrStr := ""
	if ctErr != nil {
		ctErrStr = ctErr.Error()
	}

	var resetDur time.Duration
	var expFreeze time.Time
	var activeCnt int
	var iptErr error
	func() {
		e.applyMu.Lock()
		defer e.applyMu.Unlock()
		e.mu.Lock()
		ch4, ch6 := e.pruneExpiredLocked(now)
		resetDur = e.resetDuration
		if resetDur <= 0 {
			resetDur = scalpelResetTTL
		}
		if norm.Proto == "udp" && resetDur > scalpelUDPResetTTL {
			// UDP 短暂 1s 拦截避免 ICMP 轰炸客户端，同时兼容单测注入的毫秒级快速超时
			resetDur = scalpelUDPResetTTL
		}
		freezeDur := e.freezeDur
		if freezeDur <= 0 {
			freezeDur = scalpelFreezeTTL
		}

		expReset := now.Add(resetDur)
		r5s := ScalpelActiveRule{
			ID:          fmt.Sprintf("sc_%d_rst", seq),
			Mode:        "reset_5s",
			IsIPv6:      isV6,
			Tuple:       norm,
			ClientMAC:   clientMAC,
			MatchSport:  true,
			CreatedAt:   now.Unix(),
			ExpiresAt:   expReset,
			ExpiresUnix: expReset.Unix(),
		}
		u4, u6 := e.upsertRuleLocked(r5s)
		ch4 = ch4 || u4
		ch6 = ch6 || u6

		if mode == scalpelModeFreeze15m {
			expFreeze = now.Add(freezeDur)
			r15m := ScalpelActiveRule{
				ID:          fmt.Sprintf("sc_%d_frz", seq),
				Mode:        "freeze_15m",
				IsIPv6:      isV6,
				Tuple:       norm,
				ClientMAC:   clientMAC,
				MatchSport:  false,
				CreatedAt:   now.Unix(),
				ExpiresAt:   expFreeze,
				ExpiresUnix: expFreeze.Unix(),
			}
			f4, f6 := e.upsertRuleLocked(r15m)
			ch4 = ch4 || f4
			ch6 = ch6 || f6
		}

		if isV6 {
			ch6 = true
		} else {
			ch4 = true
		}
		var p4, p6 string
		if ch4 {
			p4 = buildScalpelRestorePayload(false, e.rules)
		}
		if ch6 {
			p6 = buildScalpelRestorePayload(true, e.rules)
		}
		runner := e.iptRunner
		activeCnt = len(e.rules)
		e.mu.Unlock()

		e.ensureForwardJump(isV6)
		if isV6 && ch4 {
			e.ensureForwardJump(false)
		} else if !isV6 && ch6 {
			e.ensureForwardJump(true)
		}

		if runner != nil {
			if isV6 {
				iptErr = runner(scalpelAfInet6, p6)
				if ch4 {
					_ = runner(scalpelAfInet, p4)
				}
			} else {
				iptErr = runner(scalpelAfInet, p4)
				if ch6 {
					_ = runner(scalpelAfInet6, p6)
				}
			}
		}
	}()
	e.cutTotal.Add(1)
	e.notifyRuleAdded()
	if !e.loopRunning.Load() {
		e.syncStandaloneTimer()
	}

	cleanupSec := int(resetDur / time.Second)
	if cleanupSec <= 0 && resetDur > 0 {
		cleanupSec = 0
	}
	resp := map[string]any{
		"ok":                   iptErr == nil,
		"mode":                 mode,
		"tuple":                norm,
		"v6":                   isV6,
		"conntrack_deleted":    ctErrStr == "",
		"reverse_tuple_tried":  revRetried,
		"reset_cleanup_in_sec": cleanupSec,
		"active_scalpel_rules": activeCnt,
	}
	if clientMAC != "" {
		resp["client_mac"] = clientMAC
	}
	if mode == scalpelModeFreeze15m {
		resp["frozen_until"] = expFreeze.Unix()
	}
	if ctErrStr != "" {
		resp["conntrack_note"] = ctErrStr
	}
	if iptErr != nil {
		resp["error"] = iptErr.Error()
		return resp, iptErr
	}
	return resp, nil
}

func scalpelSameHostFreezeTarget(a, b ScalpelActiveRule) bool {
	if a.Mode != "freeze_15m" || b.Mode != "freeze_15m" || a.IsIPv6 != b.IsIPv6 {
		return false
	}
	if a.Tuple.Proto != b.Tuple.Proto || a.Tuple.DstIP != b.Tuple.DstIP || a.Tuple.Dport != b.Tuple.Dport {
		return false
	}
	return a.HasUID && b.HasUID && (a.UID == b.UID || scalpelSameOrPairedHostUID(a.UID, b.UID))
}

func (e *flowScalpelEngine) upsertHostRuleLocked(cand ScalpelActiveRule) (changedV4, changedV6 bool) {
	for i := range e.hostRules {
		ex := &e.hostRules[i]
		if ex.Mode != cand.Mode || ex.IsIPv6 != cand.IsIPv6 || ex.MatchSport != cand.MatchSport {
			continue
		}
		matched := false
		if cand.MatchSport {
			matched = scalpelSameBidirectionalTuple(ex.Tuple, cand.Tuple)
		} else {
			matched = scalpelSameHostFreezeTarget(*ex, cand)
		}
		if matched {
			ex.Tuple = cand.Tuple
			ex.UID = cand.UID
			ex.PeerUID = cand.PeerUID
			ex.HasUID = cand.HasUID
			if cand.Package != "" {
				ex.Package = cand.Package
			}
			ex.CreatedAt = cand.CreatedAt
			if cand.ExpiresAt.After(ex.ExpiresAt) {
				ex.ExpiresAt = cand.ExpiresAt
				ex.ExpiresUnix = cand.ExpiresUnix
			}
			if cand.IsIPv6 {
				return false, true
			}
			return true, false
		}
	}

	for len(e.hostRules) >= scalpelMaxActiveRules {
		oldestIdx := 0
		for i := 1; i < len(e.hostRules); i++ {
			if e.hostRules[i].ExpiresAt.Before(e.hostRules[oldestIdx].ExpiresAt) {
				oldestIdx = i
			}
		}
		evicted := e.hostRules[oldestIdx]
		if evicted.IsIPv6 {
			changedV6 = true
		} else {
			changedV4 = true
		}
		e.hostRules = append(e.hostRules[:oldestIdx], e.hostRules[oldestIdx+1:]...)
	}

	e.hostRules = append(e.hostRules, cand)
	if cand.IsIPv6 {
		changedV6 = true
	} else {
		changedV4 = true
	}
	return changedV4, changedV6
}

func (e *flowScalpelEngine) effectiveHostIptRunner() scalpelRestoreRunner {
	if e.hostIptRunner != nil {
		return e.hostIptRunner
	}
	return e.iptRunner
}

// CutHost 执行手机本机双阶段真实斩流:
//   Step 1: 五道防自锁门禁（含按 uid % 100000 双向配对主应用 10000..19999 与 SDK 沙盒 20000..29999）通过后，
//           先发 NETLINK_SOCK_DIAG SOCK_DESTROY 销毁本机 socket + CTNETLINK 清 conntrack；
//   Step 2: 原子提交 *filter 表 HNC_SCALPEL_HOST 独立子链 (挂载于 OUTPUT 链第 1 位)，同步冻结配对主应用与 SDK 沙盒 UID，到期自动回空链零开销。
func (e *flowScalpelEngine) CutHost(now time.Time, tuple ScalpelTuple, mode string, reqUID int, hasReqUID bool) (map[string]any, error) {
	norm, _, isV6, err := validateScalpelTuple(tuple)
	if err != nil {
		return nil, err
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = scalpelModeCutOnce
	}
	if mode != scalpelModeCutOnce && mode != scalpelModeFreeze15m {
		return nil, errors.New("mode must be cut_once or cut_freeze_15m")
	}

	effUID, id, guardErr := evaluateScalpelHostGuard(e.srv, norm, mode, reqUID, hasReqUID)
	if guardErr != nil {
		e.guardBlocked.Add(1)
		allowedMode := ""
		if guardErr.ReasonCode == "core_port_freeze_blocked" ||
			guardErr.ReasonCode == "shared_cdn_freeze_blocked" ||
			guardErr.ReasonCode == "fake_ip_freeze_blocked" ||
			guardErr.ReasonCode == "host_uid_required_for_freeze" {
			allowedMode = scalpelModeCutOnce
		}
		resp := map[string]any{
			"ok":            false,
			"scope":         scalpelHostScopeHost,
			"guard_blocked": true,
			"reason_code":   guardErr.ReasonCode,
			"allowed_mode":  allowedMode,
			"vendor":        guardErr.Vendor,
			"tuple":         norm,
			"uid":           effUID,
			"error":         "freeze_guard_blocked",
			"detail":        guardErr.Detail,
		}
		if id.Package != "" {
			resp["package"] = id.Package
		}
		if id.AppName != "" {
			resp["host_app_name"] = id.AppName
		}
		return resp, guardErr
	}

	peerUID, hasPeer := scalpelPairHostSandboxUID(effUID)
	freezeUIDs := scalpelOrderedHostFreezeUIDs(effUID)

	// Step 1a: 纯 Go NETLINK_SOCK_DIAG (SOCK_DESTROY=21) 强制销毁本机 socket
	sockSeq := uint32(e.seqGen.Add(1))
	sockDestroyed := false
	sockNote := ""
	if e.sockDestroyRunner != nil {
		sdErr := e.sockDestroyRunner(norm, sockSeq)
		if sdErr == nil {
			sockDestroyed = true
		} else if isScalpelSockENOENT(sdErr) {
			sockNote = "socket_already_closed"
		} else {
			sockNote = sdErr.Error()
		}
	}

	// Step 1b: CTNETLINK IPCTNL_MSG_CT_DELETE 清理对应 conntrack 状态
	seq, revRetried, ctErr := e.deleteConntrackWithReverseFallback(norm)
	ctErrStr := ""
	if ctErr != nil {
		ctErrStr = ctErr.Error()
	}

	// Step 2: 原子提交 *filter HNC_SCALPEL_HOST (OUTPUT 链独立子链)
	var (
		resetDur      time.Duration
		expFreeze     time.Time
		hostActiveCnt int
		iptErr        error
	)
	func() {
		e.applyMu.Lock()
		defer e.applyMu.Unlock()

		e.mu.Lock()
		hch4, hch6 := e.pruneHostExpiredLocked(now)
		resetDur = e.resetDuration
		if resetDur <= 0 {
			resetDur = scalpelResetTTL
		}
		if norm.Proto == "udp" && resetDur > scalpelUDPResetTTL {
			resetDur = scalpelUDPResetTTL
		}
		freezeDur := e.freezeDur
		if freezeDur <= 0 {
			freezeDur = scalpelFreezeTTL
		}

		expReset := now.Add(resetDur)
		r5s := ScalpelActiveRule{
			ID:          fmt.Sprintf("sch_%d_rst", seq),
			Scope:       scalpelHostScopeHost,
			UID:         effUID,
			PeerUID:     peerUID,
			HasUID:      effUID >= 0,
			Package:     id.Package,
			Mode:        "reset_5s",
			IsIPv6:      isV6,
			Tuple:       norm,
			MatchSport:  true,
			CreatedAt:   now.Unix(),
			ExpiresAt:   expReset,
			ExpiresUnix: expReset.Unix(),
		}
		u4, u6 := e.upsertHostRuleLocked(r5s)
		hch4 = hch4 || u4
		hch6 = hch6 || u6

		if mode == scalpelModeFreeze15m {
			expFreeze = now.Add(freezeDur)
			r15m := ScalpelActiveRule{
				ID:          fmt.Sprintf("sch_%d_frz", seq),
				Scope:       scalpelHostScopeHost,
				UID:         effUID,
				PeerUID:     peerUID,
				HasUID:      true,
				Package:     id.Package,
				Mode:        "freeze_15m",
				IsIPv6:      isV6,
				Tuple:       norm,
				MatchSport:  false,
				CreatedAt:   now.Unix(),
				ExpiresAt:   expFreeze,
				ExpiresUnix: expFreeze.Unix(),
			}
			f4, f6 := e.upsertHostRuleLocked(r15m)
			hch4 = hch4 || f4
			hch6 = hch6 || f6
		}

		if isV6 {
			hch6 = true
		} else {
			hch4 = true
		}
		var hp4, hp6 string
		if hch4 {
			hp4 = buildScalpelHostRestorePayload(false, e.hostRules)
		}
		if hch6 {
			hp6 = buildScalpelHostRestorePayload(true, e.hostRules)
		}
		runner := e.effectiveHostIptRunner()
		hostActiveCnt = len(e.hostRules)
		e.mu.Unlock()

		e.ensureHostOutputJump(isV6)
		if isV6 && hch4 {
			e.ensureHostOutputJump(false)
		} else if !isV6 && hch6 {
			e.ensureHostOutputJump(true)
		}

		if runner != nil {
			if isV6 {
				iptErr = runner(scalpelAfInet6, hp6)
				if hch4 {
					_ = runner(scalpelAfInet, hp4)
				}
			} else {
				iptErr = runner(scalpelAfInet, hp4)
				if hch6 {
					_ = runner(scalpelAfInet6, hp6)
				}
			}
		}
	}()

	if iptErr == nil {
		hostConnInvalidateProcCache()
	}
	e.cutTotal.Add(1)
	e.hostCutTotal.Add(1)
	e.notifyRuleAdded()
	if !e.loopRunning.Load() {
		e.syncStandaloneTimer()
	}

	cleanupSec := int(resetDur / time.Second)
	if cleanupSec <= 0 && resetDur > 0 {
		cleanupSec = 0
	}
	resp := map[string]any{
		"ok":                   iptErr == nil,
		"scope":                scalpelHostScopeHost,
		"mode":                 mode,
		"tuple":                norm,
		"v6":                   isV6,
		"uid":                  effUID,
		"package":              id.Package,
		"host_app_name":        id.AppName,
		"sock_destroyed":       sockDestroyed,
		"conntrack_deleted":    ctErrStr == "",
		"reverse_tuple_tried":  revRetried,
		"reset_cleanup_in_sec": cleanupSec,
		"host_active_rules":    hostActiveCnt,
		"active_scalpel_rules": hostActiveCnt,
	}
	if hasPeer {
		resp["peer_uid"] = peerUID
	}
	if sockNote != "" {
		resp["sock_destroy_note"] = sockNote
	}
	if mode == scalpelModeFreeze15m {
		resp["frozen_until"] = expFreeze.Unix()
		if len(freezeUIDs) > 0 {
			resp["freeze_uids"] = freezeUIDs
		}
	}
	if ctErrStr != "" {
		resp["conntrack_note"] = ctErrStr
	}
	if iptErr != nil {
		resp["error"] = iptErr.Error()
		return resp, iptErr
	}
	return resp, nil
}

func (e *flowScalpelEngine) pruneExpiredLocked(now time.Time) (changedV4, changedV6 bool) {
	kept := e.rules[:0]
	for _, r := range e.rules {
		if !now.Before(r.ExpiresAt) {
			if r.IsIPv6 {
				changedV6 = true
			} else {
				changedV4 = true
			}
			continue
		}
		kept = append(kept, r)
	}
	e.rules = kept
	return changedV4, changedV6
}

func (e *flowScalpelEngine) pruneHostExpiredLocked(now time.Time) (changedV4, changedV6 bool) {
	kept := e.hostRules[:0]
	for _, r := range e.hostRules {
		if !now.Before(r.ExpiresAt) {
			if r.IsIPv6 {
				changedV6 = true
			} else {
				changedV4 = true
			}
			continue
		}
		kept = append(kept, r)
	}
	e.hostRules = kept
	return changedV4, changedV6
}

// SweepExpired 清理已到期的 1s/5s/15m 规则并同步刷新对应协议栈的 HNC_SCALPEL 与 HNC_SCALPEL_HOST 子链。
func (e *flowScalpelEngine) SweepExpired(now time.Time) {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	e.mu.Lock()
	ch4, ch6 := e.pruneExpiredLocked(now)
	hasV4, hasV6 := false, false
	for _, r := range e.rules {
		if r.IsIPv6 {
			hasV6 = true
		} else {
			hasV4 = true
		}
	}
	var p4, p6 string
	if ch4 {
		p4 = buildScalpelRestorePayload(false, e.rules)
	}
	if ch6 {
		p6 = buildScalpelRestorePayload(true, e.rules)
	}

	hch4, hch6 := e.pruneHostExpiredLocked(now)
	hostHasV4, hostHasV6 := false, false
	for _, r := range e.hostRules {
		if r.IsIPv6 {
			hostHasV6 = true
		} else {
			hostHasV4 = true
		}
	}
	var hp4, hp6 string
	if hch4 {
		hp4 = buildScalpelHostRestorePayload(false, e.hostRules)
	}
	if hch6 {
		hp6 = buildScalpelHostRestorePayload(true, e.hostRules)
	}
	runner := e.iptRunner
	hostRunner := e.effectiveHostIptRunner()
	e.mu.Unlock()

	if ch4 && hasV4 {
		e.ensureForwardJump(false)
	}
	if ch6 && hasV6 {
		e.ensureForwardJump(true)
	}
	if hch4 && hostHasV4 {
		e.ensureHostOutputJump(false)
	}
	if hch6 && hostHasV6 {
		e.ensureHostOutputJump(true)
	}
	if runner != nil {
		if ch4 {
			_ = runner(scalpelAfInet, p4)
		}
		if ch6 {
			_ = runner(scalpelAfInet6, p6)
		}
	}
	if hostRunner != nil {
		if hch4 {
			_ = hostRunner(scalpelAfInet, hp4)
		}
		if hch6 {
			_ = hostRunner(scalpelAfInet6, hp6)
		}
	}
	if !e.loopRunning.Load() {
		e.syncStandaloneTimer()
	}
}

func (e *flowScalpelEngine) clearAllRulesOnHotspotOff() {
	if e == nil {
		return
	}
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	e.mu.Lock()
	if len(e.rules) == 0 {
		e.mu.Unlock()
		return
	}
	ch4, ch6 := false, false
	for _, r := range e.rules {
		if r.IsIPv6 {
			ch6 = true
		} else {
			ch4 = true
		}
	}
	e.rules = nil
	var p4, p6 string
	if ch4 {
		p4 = buildScalpelRestorePayload(false, nil)
	}
	if ch6 {
		p6 = buildScalpelRestorePayload(true, nil)
	}
	runner := e.iptRunner
	e.mu.Unlock()

	if runner != nil {
		if ch4 {
			_ = runner(scalpelAfInet, p4)
		}
		if ch6 {
			_ = runner(scalpelAfInet6, p6)
		}
	}
}

func (e *flowScalpelEngine) earliestExpiry() (time.Time, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var (
		earliest time.Time
		found    bool
	)
	for i := range e.rules {
		if !found || e.rules[i].ExpiresAt.Before(earliest) {
			earliest = e.rules[i].ExpiresAt
			found = true
		}
	}
	for i := range e.hostRules {
		if !found || e.hostRules[i].ExpiresAt.Before(earliest) {
			earliest = e.hostRules[i].ExpiresAt
			found = true
		}
	}
	return earliest, found
}

func (e *flowScalpelEngine) stopStandaloneTimer() {
	if e == nil {
		return
	}
	e.timerMu.Lock()
	if e.standaloneTimer != nil {
		e.standaloneTimer.Stop()
		e.standaloneTimer = nil
	}
	e.timerMu.Unlock()
}

// syncStandaloneTimer 仅在 runLoop 未启动（如 HTTP 路由单测）时以单一 Timer 兜底最早过期时间，列表空则停表 0 唤醒。
func (e *flowScalpelEngine) syncStandaloneTimer() {
	if e == nil || e.loopRunning.Load() {
		return
	}
	earliest, ok := e.earliestExpiry()
	e.timerMu.Lock()
	defer e.timerMu.Unlock()
	if e.standaloneTimer != nil {
		e.standaloneTimer.Stop()
		e.standaloneTimer = nil
	}
	if !ok {
		return
	}
	wait := time.Until(earliest) + 20*time.Millisecond
	if wait < 5*time.Millisecond {
		wait = 5 * time.Millisecond
	}
	e.standaloneTimer = time.AfterFunc(wait, func() {
		e.SweepExpired(time.Now())
	})
}

func (e *flowScalpelEngine) summary() map[string]any {
	now := time.Now()
	e.mu.Lock()
	cnt := 0
	for _, r := range e.rules {
		if now.Before(r.ExpiresAt) {
			cnt++
		}
	}
	hostCnt := 0
	for _, r := range e.hostRules {
		if now.Before(r.ExpiresAt) {
			hostCnt++
		}
	}
	e.mu.Unlock()

	var hsFlows, hostFlows uint32
	if e.srv != nil && e.srv.hncDir != "" {
		hsActive, online, _, _ := scalpelHotspotOnlineState(e.srv)
		hsFlows, hostFlows = scalpelLiveFlowCounts(e.srv, hsActive, online)
	}
	return map[string]any{
		"active_flows":      int(hsFlows),
		"hotspot_flows":     int(hsFlows),
		"host_flows":        int(hostFlows),
		"total_flows":       int(hsFlows + hostFlows),
		"active_rules":      cnt,
		"host_active_rules": hostCnt,
		"cut_total":         e.cutTotal.Load(),
		"host_cut_total":    e.hostCutTotal.Load(),
		"guard_blocked":     e.guardBlocked.Load(),
	}
}

const v6FlowScalpelSweepInterval = 5 * time.Second

func (e *flowScalpelEngine) ensureWakeCh() chan struct{} {
	if e == nil {
		return nil
	}
	e.wakeOnce.Do(func() {
		if e.wakeCh == nil {
			e.wakeCh = make(chan struct{}, 1)
		}
	})
	return e.wakeCh
}

func (e *flowScalpelEngine) notifyRuleAdded() {
	ch := e.ensureWakeCh()
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (e *flowScalpelEngine) IsTickerActive() bool {
	if e == nil {
		return false
	}
	return e.tickerActive.Load()
}

func (e *flowScalpelEngine) HotspotActiveRuleCount() int {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	n := len(e.rules)
	e.mu.Unlock()
	return n
}

func (e *flowScalpelEngine) HostActiveRuleCount() int {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	n := len(e.hostRules)
	e.mu.Unlock()
	return n
}

func (e *flowScalpelEngine) ActiveRuleCount() int {
	if e == nil {
		return 0
	}
	if e.ruleCountHook != nil {
		return e.ruleCountHook()
	}
	e.mu.Lock()
	n := len(e.rules) + len(e.hostRules)
	e.mu.Unlock()
	return n
}

func (e *flowScalpelEngine) effectiveSweepInterval() time.Duration {
	if e != nil && e.sweepInterval > 0 {
		return e.sweepInterval
	}
	return v6FlowScalpelSweepInterval
}

func (e *flowScalpelEngine) sweepOnce(now time.Time) {
	if e == nil {
		return
	}
	if e.sweepHook != nil {
		e.sweepHook(now)
		return
	}
	e.SweepExpired(now)
}

func (e *flowScalpelEngine) readActivity() (<-chan struct{}, Activity, bool) {
	if e.activityHook != nil {
		ch, act := e.activityHook()
		sim := false
		if e.simActiveHook != nil {
			sim = e.simActiveHook()
		} else if e.srv != nil && e.srv.hncDir != "" {
			sim = e.srv.simActive()
		}
		return ch, act, sim
	}
	ch := activityChanged()
	act := activityNow()
	sim := false
	if e.simActiveHook != nil {
		sim = e.simActiveHook()
	} else if e.srv != nil && e.srv.hncDir != "" {
		sim = e.srv.simActive()
	}
	return ch, act, sim
}

func (e *flowScalpelEngine) nextExpiryWait(now time.Time) (time.Duration, bool) {
	if earliest, ok := e.earliestExpiry(); ok {
		if !now.Before(earliest) {
			return 0, true
		}
		wait := earliest.Sub(now) + 15*time.Millisecond
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		return wait, false
	}
	// 当测试仅注入 ruleCountHook 而未写 e.rules 时，回退按 effectiveSweepInterval 单次定时
	return e.effectiveSweepInterval(), false
}

// runLoop 采用单一 time.Timer 按最早 ExpiresAt 事件驱动回收；
// 规则列表为空或 HotspotOff（且无本机活跃规则）时彻底停止定时器，保持 0 次后台唤醒。
func (e *flowScalpelEngine) runLoop(stop <-chan struct{}) {
	if e == nil {
		<-stop
		return
	}
	wakeCh := e.ensureWakeCh()
	e.loopRunning.Store(true)
	e.stopStandaloneTimer()

	var (
		expTimer       *time.Timer
		timerCh        <-chan time.Time
		hotspotCleared bool
	)
	stopTimer := func() {
		if expTimer != nil {
			if !expTimer.Stop() {
				select {
				case <-expTimer.C:
				default:
				}
			}
			expTimer = nil
			timerCh = nil
		}
		e.tickerActive.Store(false)
	}
	armTimer := func(d time.Duration) {
		stopTimer()
		if d <= 0 {
			d = time.Millisecond
		}
		expTimer = time.NewTimer(d)
		timerCh = expTimer.C
		e.tickerActive.Store(true)
	}
	defer func() {
		stopTimer()
		e.loopRunning.Store(false)
	}()

	for {
		actCh, act, simOn := e.readActivity()
		if !simOn && (act.Level == lvlHotspotOff || (act.Known && !act.HotspotActive)) {
			if !hotspotCleared || e.HotspotActiveRuleCount() > 0 {
				if e.sweepHook == nil {
					e.clearAllRulesOnHotspotOff()
				}
				hotspotCleared = true
			}
			if e.HostActiveRuleCount() <= 0 {
				stopTimer()
			} else {
				waitDur, expiredNow := e.nextExpiryWait(time.Now())
				if expiredNow {
					e.sweepOnce(time.Now())
					continue
				}
				armTimer(waitDur)
			}
		} else {
			hotspotCleared = false
			if e.ActiveRuleCount() <= 0 {
				stopTimer()
			} else {
				waitDur, expiredNow := e.nextExpiryWait(time.Now())
				if expiredNow {
					e.sweepOnce(time.Now())
					continue
				}
				armTimer(waitDur)
			}
		}

		select {
		case <-stop:
			return
		case <-actCh:
		case <-wakeCh:
		case timerNow := <-timerCh:
			expTimer = nil
			timerCh = nil
			e.tickerActive.Store(false)
			e.sweepOnce(timerNow)
		}
	}
}

// ── HTTP: GET /api/v6/scalpel/flows & POST /api/v6/scalpel/cut ───────────────

func scalpelFlowToRowMap(fl scalpelClassifiedFlow) map[string]any {
	// 注: fl.UpBps/fl.DownBps 已在 v6_host_conns.go 输出侧统一 / 8 转为 bytes/s, 此处严禁重复除两次
	row := map[string]any{
		"scope":       fl.Scope,
		"flow_key":    fl.FlowKey,
		"proto":       fl.Proto,
		"src_ip":      fl.SrcIP,
		"sport":       fl.Sport,
		"dst_ip":      fl.DstIP,
		"dport":       fl.Dport,
		"v6":          fl.IsV6,
		"state":       fl.State,
		"ttl":         fl.TTL,
		"mac":         fl.MAC,
		"device_name": fl.DeviceName,
		"domain":      fl.Domain,
		"app_id":      fl.AppID,
		"app_name":    fl.AppName,
		"company":     fl.Company,
		"up_bytes":    fl.UpBytes,
		"down_bytes":  fl.DownBytes,
		"up_bps":      int64(fl.UpBps),
		"down_bps":    int64(fl.DownBps),
	}
	if fl.Scope == scalpelHostScopeHost {
		row["uid"] = fl.UID
		row["package"] = fl.Package
		row["host_app_name"] = fl.HostAppName
		row["is_system"] = fl.IsSystem
		row["cleartext_risk"] = fl.CleartextRisk
		if fl.Inode > 0 {
			row["inode"] = fl.Inode
		}
		if fl.TxQueue > 0 || fl.RxQueue > 0 {
			row["tx_queue"] = fl.TxQueue
			row["rx_queue"] = fl.RxQueue
		}
	}
	if fl.TrafficType != "" {
		row["traffic_type"] = fl.TrafficType
		row["traffic_conf"] = fl.TrafficConf
	}
	if fl.FrozenUntil > 0 {
		row["frozen_until"] = fl.FrozenUntil
	}
	return row
}

func (e *flowScalpelEngine) cutSimHotspot(now time.Time, tuple ScalpelTuple, mode, simMAC string) (map[string]any, error) {
	norm, _, isV6, err := validateScalpelTuple(tuple)
	if err != nil {
		return nil, err
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = scalpelModeCutOnce
	}
	if mode != scalpelModeCutOnce && mode != scalpelModeFreeze15m {
		return nil, errors.New("mode must be cut_once or cut_freeze_15m")
	}
	if mode == scalpelModeFreeze15m {
		if guardErr := evaluateScalpelFreezeGuard(e.srv, norm); guardErr != nil {
			e.guardBlocked.Add(1)
			resp := map[string]any{
				"ok":            false,
				"sim":           true,
				"scope":         scalpelHostScopeHotspot,
				"guard_blocked": true,
				"reason_code":   guardErr.ReasonCode,
				"allowed_mode":  scalpelModeCutOnce,
				"vendor":        guardErr.Vendor,
				"tuple":         norm,
				"error":         "freeze_guard_blocked",
				"detail":        guardErr.Detail,
			}
			return resp, guardErr
		}
	}

	seq := uint32(e.seqGen.Add(1))
	e.mu.Lock()
	kept := e.simRules[:0]
	for _, r := range e.simRules {
		if now.Before(r.ExpiresAt) {
			kept = append(kept, r)
		}
	}
	e.simRules = kept

	resetDur := e.resetDuration
	if resetDur <= 0 {
		resetDur = scalpelResetTTL
	}
	if norm.Proto == "udp" && resetDur > scalpelUDPResetTTL {
		resetDur = scalpelUDPResetTTL
	}
	freezeDur := e.freezeDur
	if freezeDur <= 0 {
		freezeDur = scalpelFreezeTTL
	}

	expReset := now.Add(resetDur)
	e.simRules = append(e.simRules, ScalpelActiveRule{
		ID:          fmt.Sprintf("sc_sim_%d_rst", seq),
		Scope:       scalpelHostScopeHotspot,
		Mode:        "reset_5s",
		IsIPv6:      isV6,
		Tuple:       norm,
		ClientMAC:   simMAC,
		MatchSport:  true,
		CreatedAt:   now.Unix(),
		ExpiresAt:   expReset,
		ExpiresUnix: expReset.Unix(),
	})

	var expFreeze time.Time
	if mode == scalpelModeFreeze15m {
		expFreeze = now.Add(freezeDur)
		e.simRules = append(e.simRules, ScalpelActiveRule{
			ID:          fmt.Sprintf("sc_sim_%d_frz", seq),
			Scope:       scalpelHostScopeHotspot,
			Mode:        "freeze_15m",
			IsIPv6:      isV6,
			Tuple:       norm,
			ClientMAC:   simMAC,
			MatchSport:  false,
			CreatedAt:   now.Unix(),
			ExpiresAt:   expFreeze,
			ExpiresUnix: expFreeze.Unix(),
		})
	}
	if len(e.simRules) > scalpelMaxActiveRules {
		e.simRules = e.simRules[len(e.simRules)-scalpelMaxActiveRules:]
	}
	activeCnt := len(e.simRules)
	e.mu.Unlock()

	cleanupSec := int(resetDur / time.Second)
	if cleanupSec <= 0 && resetDur > 0 {
		cleanupSec = 0
	}
	resp := map[string]any{
		"ok":                   true,
		"sim":                  true,
		"scope":                scalpelHostScopeHotspot,
		"mode":                 mode,
		"tuple":                norm,
		"v6":                   isV6,
		"client_mac":           simMAC,
		"conntrack_deleted":    true,
		"reverse_tuple_tried":  false,
		"reset_cleanup_in_sec": cleanupSec,
		"active_scalpel_rules": activeCnt,
	}
	if mode == scalpelModeFreeze15m {
		resp["frozen_until"] = expFreeze.Unix()
	}
	return resp, nil
}

func (s *server) resolveSimScalpelMAC(rawMAC string, norm ScalpelTuple) (string, bool) {
	if s == nil {
		return "", false
	}
	mac := simNormMAC(rawMAC)
	if isSimMAC(mac) {
		return mac, true
	}
	if rawMAC == "" && s.simActive() {
		views, _ := s.simViews(time.Now())
		for i := range views {
			ip := strings.TrimSpace(views[i].D.IP)
			if ip != "" && (ip == norm.SrcIP || ip == norm.DstIP) {
				return views[i].D.MAC, true
			}
		}
	}
	return "", false
}

func (s *server) apiScalpelFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "GET only"})
		return
	}

	qScope := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scope")))
	if qScope == "" {
		qScope = scalpelHostScopeAll
	}
	if qScope != scalpelHostScopeAll && qScope != scalpelHostScopeHotspot && qScope != scalpelHostScopeHost {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid scope"})
		return
	}

	hasUIDFilter := false
	qUID := -1
	if rawUID := strings.TrimSpace(r.URL.Query().Get("uid")); rawUID != "" {
		u, err := strconv.Atoi(rawUID)
		if err != nil || u < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid uid"})
			return
		}
		hasUIDFilter = true
		qUID = u
	}

	qMAC := canonMAC(r.URL.Query().Get("mac"))
	if rawMAC := strings.TrimSpace(r.URL.Query().Get("mac")); rawMAC != "" && qMAC == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid mac"})
		return
	}
	qIP := strings.TrimSpace(r.URL.Query().Get("ip"))
	if qIP != "" && net.ParseIP(qIP) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid ip"})
		return
	}
	if qIP != "" {
		qIP = net.ParseIP(qIP).String()
	}

	now := time.Now()
	simOn := s.simActive()
	eng := s.v6State().scalpel
	eng.mu.Lock()
	activeHotspotRules := make([]ScalpelActiveRule, 0, len(eng.rules)+len(eng.simRules))
	for _, rr := range eng.rules {
		if now.Before(rr.ExpiresAt) {
			cp := rr
			if cp.Scope == "" {
				cp.Scope = scalpelHostScopeHotspot
			}
			activeHotspotRules = append(activeHotspotRules, cp)
		}
	}
	var activeSimCutOnce []ScalpelActiveRule
	if simOn && len(eng.simRules) > 0 {
		keptSim := eng.simRules[:0]
		for _, rr := range eng.simRules {
			if now.Before(rr.ExpiresAt) {
				keptSim = append(keptSim, rr)
				cp := rr
				if cp.Scope == "" {
					cp.Scope = scalpelHostScopeHotspot
				}
				activeHotspotRules = append(activeHotspotRules, cp)
				if cp.MatchSport {
					activeSimCutOnce = append(activeSimCutOnce, cp)
				}
			}
		}
		eng.simRules = keptSim
	} else if !simOn && len(eng.simRules) > 0 {
		eng.simRules = nil
	}
	activeHostRules := make([]ScalpelActiveRule, 0, len(eng.hostRules))
	for _, rr := range eng.hostRules {
		if now.Before(rr.ExpiresAt) {
			cp := rr
			if cp.Scope == "" {
				cp.Scope = scalpelHostScopeHost
			}
			activeHostRules = append(activeHostRules, cp)
		}
	}
	eng.mu.Unlock()

	allActiveRules := make([]ScalpelActiveRule, 0, len(activeHotspotRules)+len(activeHostRules))
	switch qScope {
	case scalpelHostScopeHotspot:
		allActiveRules = append(allActiveRules, activeHotspotRules...)
	case scalpelHostScopeHost:
		allActiveRules = append(allActiveRules, activeHostRules...)
	default:
		allActiveRules = append(allActiveRules, activeHotspotRules...)
		allActiveRules = append(allActiveRules, activeHostRules...)
	}

	dual := scalpelCollectDualDomainFlows(s, activeHotspotRules, activeHostRules)

	ipsBy := s.deviceIPsByMAC()
	macFilterIPs := make(map[string]bool)
	if qMAC != "" {
		for _, ip := range ipsBy[qMAC] {
			macFilterIPs[ip] = true
		}
	}

	type flowItem struct {
		m     map[string]any
		score float64
		bytes uint64
	}
	var items []flowItem

	// 热点流筛选: 若未显式传 mac/ip 单查且热点已关闭/0 在线客户端，不混入离线残留热点流
	if (qScope == scalpelHostScopeAll || qScope == scalpelHostScopeHotspot) && !hasUIDFilter {
		allowHotspotRows := dual.HotspotFlows > 0 || qMAC != "" || qIP != ""
		if allowHotspotRows {
			for _, fl := range dual.HotspotList {
				if len(activeSimCutOnce) > 0 && isSimMAC(fl.MAC) {
					cand := ScalpelTuple{Proto: fl.Proto, SrcIP: fl.SrcIP, Sport: fl.Sport, DstIP: fl.DstIP, Dport: fl.Dport}
					cutHit := false
					for _, sr := range activeSimCutOnce {
						if scalpelSameBidirectionalTuple(sr.Tuple, cand) {
							cutHit = true
							break
						}
					}
					if cutHit {
						continue
					}
				}
				if qMAC != "" && fl.MAC != qMAC && !macFilterIPs[fl.SrcIP] {
					continue
				}
				if qIP != "" && fl.SrcIP != qIP && fl.DstIP != qIP {
					continue
				}
				items = append(items, flowItem{
					m:     scalpelFlowToRowMap(fl),
					score: fl.UpBps + fl.DownBps,
					bytes: fl.UpBytes + fl.DownBytes,
				})
			}
		}
	}

	// 本机流筛选: 当未指定热点设备 MAC 时纳入 scope=all|host (按 uid 筛选时双向覆盖配对 SDK 沙盒)
	if (qScope == scalpelHostScopeAll || qScope == scalpelHostScopeHost) && qMAC == "" {
		for _, fl := range dual.HostList {
			if hasUIDFilter && fl.UID != qUID && !scalpelSameOrPairedHostUID(fl.UID, qUID) {
				continue
			}
			if qIP != "" && fl.SrcIP != qIP && fl.DstIP != qIP {
				continue
			}
			items = append(items, flowItem{
				m:     scalpelFlowToRowMap(fl),
				score: fl.UpBps + fl.DownBps,
				bytes: fl.UpBytes + fl.DownBytes,
			})
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		return items[i].bytes > items[j].bytes
	})
	limit := 200
	if qLim := strings.TrimSpace(r.URL.Query().Get("limit")); qLim != "" {
		if n, err := strconv.Atoi(qLim); err == nil && n >= 1 && n <= 500 {
			limit = n
		}
	}
	flowsOut := make([]map[string]any, 0, len(items))
	for i, it := range items {
		if i >= limit {
			break
		}
		flowsOut = append(flowsOut, it.m)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"readable":      dual.Readable,
		"scope":         qScope,
		"hotspot_flows": dual.HotspotFlows,
		"host_flows":    dual.HostFlows,
		"total":         len(items),
		"flows":         flowsOut,
		"active_rules":  allActiveRules,
	})
}

func (s *server) apiScalpelCut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode  string `json:"mode"`  // cut_once | cut_freeze_15m
		Scope string `json:"scope"` // optional: hotspot | host
		UID   *int   `json:"uid"`   // optional: host socket UID
		Proto string `json:"proto"`
		SrcIP string `json:"src_ip"`
		Sport int    `json:"sport"`
		DstIP string `json:"dst_ip"`
		Dport int    `json:"dport"`
		MAC   string `json:"mac"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json", "detail": err.Error()})
		return
	}

	tuple := ScalpelTuple{
		Proto: req.Proto,
		SrcIP: req.SrcIP,
		Sport: req.Sport,
		DstIP: req.DstIP,
		Dport: req.Dport,
	}
	norm, _, _, valErr := validateScalpelTuple(tuple)
	if valErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": valErr.Error()})
		return
	}

	// 模拟设备物理隔离闸: 遇到 02:5e:00:* 模拟 MAC 纯内存处理, 严禁触碰 netlink/iptables!
	if simMAC, ok := s.resolveSimScalpelMAC(req.MAC, norm); ok {
		st := simFor(s.hncDir)
		st.mu.Lock()
		found := st.findLocked(simMAC) != nil
		enabled := st.f.Enabled
		st.mu.Unlock()
		if !found && enabled {
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "not found", "detail": "sim device not found: " + simMAC})
			return
		}
		if found {
			resp, err := s.v6State().scalpel.cutSimHotspot(time.Now(), norm, req.Mode, simMAC)
			if err != nil {
				if resp == nil {
					writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": err.Error()})
					return
				}
				var guardErr *scalpelFreezeGuardError
				if errors.As(err, &guardErr) {
					writeJSON(w, http.StatusConflict, resp)
					return
				}
				writeJSON(w, http.StatusInternalServerError, resp)
				return
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}

	hasUID := req.UID != nil
	uidVal := -1
	if hasUID {
		uidVal = *req.UID
	}
	targetScope, scopeErr := scalpelInferTargetScope(s, norm, req.Scope, req.MAC, hasUID)
	if scopeErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": scopeErr.Error()})
		return
	}

	var (
		resp map[string]any
		err  error
	)
	if targetScope == scalpelHostScopeHost {
		resp, err = s.v6State().scalpel.CutHost(time.Now(), norm, req.Mode, uidVal, hasUID)
	} else {
		resp, err = s.v6State().scalpel.CutWithMAC(time.Now(), norm, req.Mode, req.MAC)
		if resp != nil {
			resp["scope"] = scalpelHostScopeHotspot
		}
	}
	if err != nil {
		if resp == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": err.Error()})
			return
		}
		var guardErr *scalpelFreezeGuardError
		if errors.As(err, &guardErr) {
			writeJSON(w, http.StatusConflict, resp)
			return
		}
		writeJSON(w, http.StatusInternalServerError, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
