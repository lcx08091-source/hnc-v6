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
	"time"
)

const (
	scalpelChainName      = "HNC_SCALPEL"
	scalpelModeCutOnce    = "cut_once"
	scalpelModeFreeze15m  = "cut_freeze_15m"
	scalpelResetTTL       = 5 * time.Second
	scalpelFreezeTTL      = 15 * time.Minute
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
	MatchSport  bool         `json:"match_sport"` // reset_5s=true(精确五元组); freeze_15m=false(冻结该客户端到目标 ip:dport)
	CreatedAt   int64        `json:"created_at"`
	ExpiresAt   time.Time    `json:"-"`
	ExpiresUnix int64        `json:"expires_at"`
}

type scalpelRestoreRunner func(family int, payload string) error
type scalpelCtDeleteRunner func(tuple ScalpelTuple, seq uint32) error

type flowScalpelEngine struct {
	// 64 位原子字段严格置于 offset 0 (兼容 32-bit ARM)
	seqGen   atomic.Uint64
	cutTotal atomic.Uint64

	tickerActive  atomic.Bool
	wakeOnce      sync.Once
	wakeCh        chan struct{}
	sweepInterval time.Duration
	ruleCountHook func() int
	sweepHook     func(time.Time)

	srv           *server
	mu            sync.Mutex
	rules         []ScalpelActiveRule
	hookEnsuredV4 bool
	hookEnsuredV6 bool
	ctDelRunner   scalpelCtDeleteRunner
	iptRunner     scalpelRestoreRunner
	resetDuration time.Duration
	freezeDur     time.Duration
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
		if errnoNeg == 0 || -errnoNeg == 2 { // 0 = ACK, ENOENT(2) = 连接已自然销毁
			return nil
		}
		return fmt.Errorf("ctnetlink delete errno %d", -errnoNeg)
	}
	return nil
}

func (e *flowScalpelEngine) defaultDeleteConntrackNetlink(tuple ScalpelTuple, seq uint32) error {
	return sendConntrackDeleteNetlink(tuple, seq)
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
			// 精确五元组双向干净复位: 客户端与服务端均在 5s 窗口内收到真实序列号 RST / ICMP 不可达
			fmt.Fprintf(&b, "-A %s -p %s -s %s -d %s --sport %d --dport %d -j REJECT --reject-with %s\n",
				scalpelChainName, t.Proto, t.SrcIP, t.DstIP, t.Sport, t.Dport, rejectWith)
			fmt.Fprintf(&b, "-A %s -p %s -s %s -d %s --sport %d --dport %d -j REJECT --reject-with %s\n",
				scalpelChainName, t.Proto, t.DstIP, t.SrcIP, t.Dport, t.Sport, rejectWith)
		} else {
			// 15 分钟冻结目标端点: 仅拦截该源 IP 发往该 (dst_ip, dport, proto) 的重连尝试
			fmt.Fprintf(&b, "-A %s -p %s -s %s -d %s --dport %d -j REJECT --reject-with %s\n",
				scalpelChainName, t.Proto, t.SrcIP, t.DstIP, t.Dport, rejectWith)
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

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

func (e *flowScalpelEngine) ensureForwardJump(isIPv6 bool) {
	if e.srv == nil || !useNativeDataplane(e.srv.hncDir) {
		return
	}
	e.mu.Lock()
	already := (!isIPv6 && e.hookEnsuredV4) || (isIPv6 && e.hookEnsuredV6)
	e.mu.Unlock()
	if already {
		return
	}
	iptName := "iptables"
	if isIPv6 {
		iptName = "ip6tables"
	}
	binPath := resolveScalpelBin(iptName)
	if binPath == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = hardenCmd(exec.CommandContext(ctx, binPath, "-w", "2", "-t", "filter", "-N", scalpelChainName)).Run()
	if hardenCmd(exec.CommandContext(ctx, binPath, "-w", "2", "-t", "filter", "-C", "FORWARD", "-j", scalpelChainName)).Run() != nil {
		_ = hardenCmd(exec.CommandContext(ctx, binPath, "-w", "2", "-t", "filter", "-I", "FORWARD", "1", "-j", scalpelChainName)).Run()
	}
	e.mu.Lock()
	if isIPv6 {
		e.hookEnsuredV6 = true
	} else {
		e.hookEnsuredV4 = true
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
	binPath := resolveScalpelBin(binName)
	if binPath == "" {
		return fmt.Errorf("%s not found", binName)
	}
	ctx, cancel := context.WithTimeout(context.Background(), scalpelRestoreTimeout)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, binPath, "-w", "2", "--noflush"))
	cmd.Stdin = strings.NewReader(payload)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %v (%s)", binName, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Cut 执行两步秒斩手术并启动 5s 自动清理定时器（若 mode=cut_freeze_15m 同步挂入 15m 冻结）。
func (e *flowScalpelEngine) Cut(now time.Time, tuple ScalpelTuple, mode string) (map[string]any, error) {
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

	seq := uint32(e.seqGen.Add(1))
	ctErrStr := ""
	if e.ctDelRunner != nil {
		if cerr := e.ctDelRunner(norm, seq); cerr != nil {
			ctErrStr = cerr.Error()
		}
	}

	family := scalpelAfInet
	if isV6 {
		family = scalpelAfInet6
	}

	e.mu.Lock()
	e.pruneExpiredLocked(now)
	resetDur := e.resetDuration
	if resetDur <= 0 {
		resetDur = scalpelResetTTL
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
		MatchSport:  true,
		CreatedAt:   now.Unix(),
		ExpiresAt:   expReset,
		ExpiresUnix: expReset.Unix(),
	}
	e.rules = append(e.rules, r5s)

	var expFreeze time.Time
	if mode == scalpelModeFreeze15m {
		expFreeze = now.Add(freezeDur)
		r15m := ScalpelActiveRule{
			ID:          fmt.Sprintf("sc_%d_frz", seq),
			Mode:        "freeze_15m",
			IsIPv6:      isV6,
			Tuple:       norm,
			MatchSport:  false,
			CreatedAt:   now.Unix(),
			ExpiresAt:   expFreeze,
			ExpiresUnix: expFreeze.Unix(),
		}
		e.rules = append(e.rules, r15m)
	}

	payload := buildScalpelRestorePayload(isV6, e.rules)
	runner := e.iptRunner
	activeCnt := len(e.rules)
	e.mu.Unlock()
	e.notifyRuleAdded()

	e.ensureForwardJump(isV6)
	var iptErr error
	if runner != nil {
		iptErr = runner(family, payload)
	}
	e.cutTotal.Add(1)

	time.AfterFunc(resetDur+50*time.Millisecond, func() {
		e.SweepExpired(time.Now())
	})

	resp := map[string]any{
		"ok":                   iptErr == nil,
		"mode":                 mode,
		"tuple":                norm,
		"v6":                   isV6,
		"conntrack_deleted":    ctErrStr == "",
		"reset_cleanup_in_sec": int(resetDur / time.Second),
		"active_scalpel_rules": activeCnt,
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

// SweepExpired 清理已到期的 5s/15m 规则并同步刷新对应协议栈的 HNC_SCALPEL 子链。
func (e *flowScalpelEngine) SweepExpired(now time.Time) {
	e.mu.Lock()
	ch4, ch6 := e.pruneExpiredLocked(now)
	var p4, p6 string
	if ch4 {
		p4 = buildScalpelRestorePayload(false, e.rules)
	}
	if ch6 {
		p6 = buildScalpelRestorePayload(true, e.rules)
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

func (e *flowScalpelEngine) summary() map[string]any {
	e.mu.Lock()
	e.pruneExpiredLocked(time.Now())
	cnt := len(e.rules)
	e.mu.Unlock()
	return map[string]any{
		"active_rules": cnt,
		"cut_total":    e.cutTotal.Load(),
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

func (e *flowScalpelEngine) runLoop(stop <-chan struct{}) {
	if e == nil {
		<-stop
		return
	}
	wakeCh := e.ensureWakeCh()
	var (
		tk   *time.Ticker
		tkCh <-chan time.Time
	)
	stopTicker := func() {
		if tk != nil {
			tk.Stop()
			tk = nil
			tkCh = nil
		}
		e.tickerActive.Store(false)
	}
	ensureTicker := func() {
		if tk == nil {
			tk = time.NewTicker(e.effectiveSweepInterval())
			tkCh = tk.C
		}
		e.tickerActive.Store(true)
	}
	defer stopTicker()

	for {
		if e.ActiveRuleCount() > 0 {
			ensureTicker()
		} else {
			stopTicker()
		}
		select {
		case <-stop:
			return
		case <-wakeCh:
		case now := <-tkCh:
			e.sweepOnce(now)
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
	eng.pruneExpiredLocked(now)
	activeRules := append([]ScalpelActiveRule(nil), eng.rules...)
	eng.mu.Unlock()

	frozenEndpoint := func(src, dst string, dport int, proto string) int64 {
		for _, r := range activeRules {
			if r.Mode == "freeze_15m" && r.Tuple.SrcIP == src && r.Tuple.DstIP == dst &&
				r.Tuple.Dport == dport && r.Tuple.Proto == proto {
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
			if frz := frozenEndpoint(ent.Src, ent.Dst, ent.Dport, ent.Proto); frz > 0 {
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
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json", "detail": err.Error()})
		return
	}
	resp, err := s.v6State().scalpel.Cut(time.Now(), ScalpelTuple{
		Proto: req.Proto,
		SrcIP: req.SrcIP,
		Sport: req.Sport,
		DstIP: req.DstIP,
		Dport: req.Dport,
	}, req.Mode)
	if err != nil {
		if resp == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
