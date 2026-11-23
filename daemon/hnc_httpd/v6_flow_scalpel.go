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

// ScalpelActiveRule 挂入 HNC_SCALPEL 链的精准规则项（到期自动摘除）。
type ScalpelActiveRule struct {
	ID          string       `json:"id"`
	Mode        string       `json:"mode"` // reset_5s | freeze_15m
	IsIPv6      bool         `json:"v6"`
	Tuple       ScalpelTuple `json:"tuple"`
	ClientMAC   string       `json:"client_mac,omitempty"`
	MatchSport  bool         `json:"match_sport"` // reset_5s=true(精确五元组); freeze_15m=false(冻结该客户端到目标 ip:dport 的新建连接)
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

	tickerActive  atomic.Bool
	loopRunning   atomic.Bool
	wakeOnce      sync.Once
	wakeCh        chan struct{}
	sweepInterval time.Duration
	ruleCountHook func() int
	sweepHook     func(time.Time)
	activityHook  func() (<-chan struct{}, Activity)
	simActiveHook func() bool

	srv             *server
	applyMu         sync.Mutex
	mu              sync.Mutex
	timerMu         sync.Mutex
	standaloneTimer *time.Timer
	rules           []ScalpelActiveRule
	hookEnsuredV4   bool
	hookEnsuredV6   bool
	forceHookCheck  bool
	ctDelRunner     scalpelCtDeleteRunner
	iptRunner       scalpelRestoreRunner
	resetDuration   time.Duration
	freezeDur       time.Duration
}

func newFlowScalpelEngine(s *server) *flowScalpelEngine {
	eng := &flowScalpelEngine{
		wakeCh:        make(chan struct{}, 1),
		srv:           s,
		resetDuration: scalpelResetTTL,
		freezeDur:     scalpelFreezeTTL,
	}
	eng.ctDelRunner = eng.defaultDeleteConntrackNetlink
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
	_, macByIP := e.srv.buildDeviceDirectory()
	return canonMAC(macByIP[srcIP])
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

// SweepExpired 清理已到期的 1s/5s/15m 规则并同步刷新对应协议栈的 HNC_SCALPEL 子链。
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
	runner := e.iptRunner
	e.mu.Unlock()

	if ch4 && hasV4 {
		e.ensureForwardJump(false)
	}
	if ch6 && hasV6 {
		e.ensureForwardJump(true)
	}
	if runner != nil {
		if ch4 {
			_ = runner(scalpelAfInet, p4)
		}
		if ch6 {
			_ = runner(scalpelAfInet6, p6)
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
	if len(e.rules) == 0 {
		return time.Time{}, false
	}
	earliest := e.rules[0].ExpiresAt
	for i := 1; i < len(e.rules); i++ {
		if e.rules[i].ExpiresAt.Before(earliest) {
			earliest = e.rules[i].ExpiresAt
		}
	}
	return earliest, true
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
	e.mu.Unlock()
	return map[string]any{
		"active_rules":  cnt,
		"cut_total":     e.cutTotal.Load(),
		"guard_blocked": e.guardBlocked.Load(),
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

func (e *flowScalpelEngine) ActiveRuleCount() int {
	if e == nil {
		return 0
	}
	if e.ruleCountHook != nil {
		return e.ruleCountHook()
	}
	e.mu.Lock()
	n := len(e.rules)
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
// 规则列表为空或 HotspotOff 时彻底停止定时器，保持 0 次后台唤醒。
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
			stopTimer()
			if !hotspotCleared || e.ActiveRuleCount() > 0 {
				if e.sweepHook == nil {
					e.clearAllRulesOnHotspotOff()
				}
				hotspotCleared = true
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

func (s *server) apiScalpelFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "GET only"})
		return
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

	sn := conntrackSnapshot()
	ipsBy := s.deviceIPsByMAC()
	nameByMAC, macByIP := s.buildDeviceDirectory()
	names := s.loadIPNames()
	apps := s.loadIPApps()
	fpSt, now := fpFor(s.hncDir), time.Now()

	filterIPs := make(map[string]bool)
	if qMAC != "" {
		for _, ip := range ipsBy[qMAC] {
			filterIPs[ip] = true
		}
	}
	if qIP != "" {
		filterIPs[qIP] = true
	}
	hasFilter := qMAC != "" || qIP != ""

	eng := s.v6State().scalpel
	eng.mu.Lock()
	activeRules := make([]ScalpelActiveRule, 0, len(eng.rules))
	for _, r := range eng.rules {
		if now.Before(r.ExpiresAt) {
			activeRules = append(activeRules, r)
		}
	}
	eng.mu.Unlock()

	frozenEndpoint := func(mac, src, dst string, dport int, proto string) int64 {
		cMac := canonMAC(mac)
		for _, r := range activeRules {
			if r.Mode != "freeze_15m" || r.Tuple.DstIP != dst || r.Tuple.Dport != dport || r.Tuple.Proto != proto {
				continue
			}
			rMac := canonMAC(r.ClientMAC)
			if (rMac != "" && cMac != "" && rMac == cMac) || r.Tuple.SrcIP == src {
				return r.ExpiresUnix
			}
		}
		return 0
	}

	type flowItem struct {
		m     map[string]any
		score float64
		bytes uint64
	}
	var items []flowItem

	if sn != nil && sn.readable {
		for _, ent := range sn.entries {
			if ent.Proto != "tcp" && ent.Proto != "udp" {
				continue
			}
			if hasFilter && !filterIPs[ent.Src] {
				continue
			}
			mac := macByIP[ent.Src]
			if !hasFilter && mac == "" && isPrivateIP(ent.Dst) {
				continue
			}
			k := ent.key()
			upBps, dnBps := sn.upBps[k], sn.dnBps[k]
			domain := ""
			appName := ""
			appID := ""
			if nm, ok := names[ent.Dst]; ok {
				domain = nm.Name
				appID = nm.App
				appName = nm.AppName
			}
			if fa, ok := fpSt.attribute(k, apps, names, now); ok {
				appID = fa.App.ID
				appName = fa.App.Name
			} else if ap, ok := apps[ent.Dst]; ok {
				appID = ap.ID
				appName = ap.Name
			}
			if appName == "" {
				appName = wellKnownSvc(ent.Proto, ent.Dport)
			}
			devName := nameByMAC[mac]
			if devName == "" {
				devName = mac
			}

			row := map[string]any{
				"flow_key":    k,
				"proto":       ent.Proto,
				"src_ip":      ent.Src,
				"sport":       ent.Sport,
				"dst_ip":      ent.Dst,
				"dport":       ent.Dport,
				"v6":          ent.Family == "ipv6",
				"state":       ent.State,
				"ttl":         ent.TTL,
				"mac":         mac,
				"device_name": devName,
				"domain":      domain,
				"app_id":      appID,
				"app_name":    appName,
				"up_bytes":    ent.UpB,
				"down_bytes":  ent.DnB,
				"up_bps":      int64(upBps),
				"down_bps":    int64(dnBps),
			}
			if tt, conf, ok := flowTrafficType(k); ok {
				row["traffic_type"] = tt
				row["traffic_conf"] = conf
			}
			if frz := frozenEndpoint(mac, ent.Src, ent.Dst, ent.Dport, ent.Proto); frz > 0 {
				row["frozen_until"] = frz
			}
			items = append(items, flowItem{
				m:     row,
				score: upBps + dnBps,
				bytes: ent.UpB + ent.DnB,
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
		"ok":           true,
		"readable":     sn != nil && sn.readable,
		"total":        len(items),
		"flows":        flowsOut,
		"active_rules": activeRules,
	})
}

func (s *server) apiScalpelCut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode  string `json:"mode"` // cut_once | cut_freeze_15m
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
	resp, err := s.v6State().scalpel.CutWithMAC(time.Now(), ScalpelTuple{
		Proto: req.Proto,
		SrcIP: req.SrcIP,
		Sport: req.Sport,
		DstIP: req.DstIP,
		Dport: req.Dport,
	}, req.Mode, req.MAC)
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
