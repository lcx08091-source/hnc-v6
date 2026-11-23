// Package nlroute —— v5.29 T1(M2) / v6.1 RC2: 只读 NETLINK_ROUTE 查询, 纯 syscall 无依赖。
//
// 用途:
//   1. 看门狗原生健康检查(native.go): RTM_GETQDISC + NLM_F_DUMP 查根/子队列 htb;
//   2. 上行链路健康检查(native.go): RTM_GETTFILTER + NLM_F_DUMP 查 ingress/clsact
//      (0xfffffff2 / 0xfffffff1 / 0xffff0000)是否存在指向目标 ifb0 ifindex 的 mirred 动作;
//   3. clsact 周期探活(offload_sched.go): RTM_GETTFILTER 查 0xfffffff2 / 0xfffffff3
//      是否存在 bpf 过滤器并核验 /sys/fs/bpf/hnc/ip_mark_map 可访问, 省去每 10s fork 子进程。
//
// 约束:
//   - 只读。不做任何写操作(加 / 删 qdisc 与 filter 仍走 tc / hnc_clsact_ctl / shell 修复路径);
//   - 报文解析拆成 parseQdiscMsgs / parseFilterMsgs(测试喂手工构造与截断字节, 截断必须返回错误不能 panic);
//   - 所有句柄/parent 常量与切片显式使用 uint32, 严格兼容 32 位 GOARCH=arm GOARM=7。
package nlroute

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ─── netlink 常量(不引 golang.org/x/net) ─────────────────────────────

const (
	nlMsgAligned = 4 // NLMSG_ALIGNTO

	nlMsgHdrLen = 16 // len(4) type(2) flags(2) seq(4) pid(4)

	nlMsgError = 2
	nlMsgDone  = 3

	rtmNewQdisc   = 36 // RTM_NEWQDISC (0x24)
	rtmGetQdisc   = 38 // RTM_GETQDISC (0x26)
	rtmNewTFilter = 44 // RTM_NEWTFILTER (0x2c)
	rtmGetTFilter = 46 // RTM_GETTFILTER (0x2e)

	nlmFRequest = 0x001
	nlmFDump    = 0x300 // NLM_F_ROOT | NLM_F_MATCH

	nlaTypeMask = 0x3FFF // ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

	tcaKind    = 1 // TCA_KIND
	tcaOptions = 2 // TCA_OPTIONS

	tcaActKind    = 1 // TCA_ACT_KIND
	tcaActOptions = 2 // TCA_ACT_OPTIONS

	tcaBPFAct      = 1 // TCA_BPF_ACT
	tcaBPFName     = 7 // TCA_BPF_NAME
	tcaMatchallAct = 2 // TCA_MATCHALL_ACT
	tcaBasicAct    = 3 // TCA_BASIC_ACT
	tcaFlowerAct   = 3 // TCA_FLOWER_ACT
	tcaFwAct       = 4 // TCA_FW_ACT
	tcaU32Act      = 7 // TCA_U32_ACT

	tcaMirredParms = 2  // TCA_MIRRED_PARMS
	sizeofTcMirred = 28 // struct tc_mirred: tc_gen(20) + eaction(4) + ifindex(4)

	sizeofTcMsg = 20 // family(1)+pad1(1)+pad2(2)+ifindex(4)+handle(4)+parent(4)+info(4)
)

// TC 特殊 parent 句柄常量(linux/pkt_cls.h, 无符号 32 位安全)。
const (
	TC_H_ROOT           = 0xFFFFFFFF
	TC_H_INGRESS        = 0xFFFFFFF1 // TC_H_INGRESS / TC_H_CLSACT
	TC_H_INGRESS_MAJ    = 0xFFFF0000 // parent ffff:
	TC_H_CLSACT_INGRESS = 0xFFFFFFF2 // TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)
	TC_H_CLSACT_EGRESS  = 0xFFFFFFF3 // TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)

	// DefaultBPFMapPinPath clsact eBPF pinned IPv4 mark map 默认路径。
	DefaultBPFMapPinPath = "/sys/fs/bpf/hnc/ip_mark_map"
)

// TC_HMaj(handle "1:")的数值 —— handle = major<<16。
func TC_HMaj(major uint32) uint32 { return major << 16 }

// Qdisc 一条排队规则。
type Qdisc struct {
	IfIndex int    // tcmsg.tcm_ifindex(所属网卡)
	Kind    string // TCA_KIND, 如 "htb" / "fq_codel" / "mq" / "clsact"
	Handle  uint32 // 句柄, 如 0x00010000 = "1:"
	Parent  uint32 // parent, 0xFFFFFFFF = root; 0xFFFFFFF1 = ingress/clsact
}

// TFilter 一条 tc 过滤器的只读摘要。
type TFilter struct {
	IfIndex       int    // tcmsg.tcm_ifindex
	Parent        uint32 // tcmsg.tcm_parent
	Handle        uint32 // tcmsg.tcm_handle
	Prio          uint16 // tcm_info >> 16
	Proto         uint16 // ntohs(tcm_info & 0xFFFF)
	Kind          string // TCA_KIND, 如 "matchall" / "u32" / "flower" / "bpf"
	BPFName       string // TCA_BPF_NAME(当 Kind=="bpf" 时可选)
	MirredIfIndex int    // 若挂有 mirred 动作则为目标网卡 ifindex(>0), 否则 0
	MirredEAction int    // struct tc_mirred.eaction(如 TCA_EGRESS_REDIR=1)
}

// ClsactStatus clsact eBPF 过滤器与 pinned map 的只读探活结果。
type ClsactStatus struct {
	Qdisc      bool // 存在 clsact qdisc(或 0xfffffff2/0xfffffff3 挂有过滤器)
	IngressBPF bool // 0xfffffff2 存在 kind=="bpf" 过滤器
	EgressBPF  bool // 0xfffffff3 存在 kind=="bpf" 过滤器
	MapOK      bool // /sys/fs/bpf/hnc/ip_mark_map 可访问
}

// OK 与 `hnc_clsact_ctl check` 的 `"ok":true` 口径一致: qdisc && ingress bpf && map 就绪。
func (s ClsactStatus) OK() bool {
	return s.Qdisc && s.IngressBPF && s.MapOK
}

type netlinkErrno struct {
	code  int32
	errno syscall.Errno
}

func (e *netlinkErrno) Error() string {
	return fmt.Sprintf("nlroute: netlink error %d (%v)", e.code, e.errno)
}

func (e *netlinkErrno) Unwrap() error { return e.errno }

func isAbsentNetlinkErr(err error) bool {
	return errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.EOPNOTSUPP)
}

func openRouteSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return -1, fmt.Errorf("nlroute: socket: %w", err)
	}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 3})
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		_ = syscall.Close(fd)
		return -1, fmt.Errorf("nlroute: bind: %w", err)
	}
	return fd, nil
}

func sendTcDumpReq(fd int, msgType uint16, seq uint32, ifindex int, parent uint32) error {
	req := make([]byte, nlMsgHdrLen+sizeofTcMsg)
	native := binary.LittleEndian
	native.PutUint32(req[0:4], uint32(len(req)))
	native.PutUint16(req[4:6], msgType)
	native.PutUint16(req[6:8], nlmFRequest|nlmFDump)
	native.PutUint32(req[8:12], seq)
	native.PutUint32(req[nlMsgHdrLen+4:nlMsgHdrLen+8], uint32(int32(ifindex)))
	native.PutUint32(req[nlMsgHdrLen+12:nlMsgHdrLen+16], parent)
	for {
		err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("nlroute: send: %w", err)
		}
		return nil
	}
}

func dumpQdiscsOnFD(fd int, seq uint32, ifindex int, buf []byte) ([]Qdisc, error) {
	if err := sendTcDumpReq(fd, rtmGetQdisc, seq, ifindex, 0); err != nil {
		return nil, err
	}
	var out []Qdisc
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("nlroute: recv: %w", err)
		}
		if n <= 0 {
			return nil, errors.New("nlroute: empty recv")
		}
		qs, done, err := parseQdiscMsgs(buf[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, keepIfIndex(qs, ifindex)...)
		if done {
			return out, nil
		}
	}
}

func dumpTFiltersOnFD(fd int, seq uint32, ifindex int, parent uint32, buf []byte) ([]TFilter, error) {
	if err := sendTcDumpReq(fd, rtmGetTFilter, seq, ifindex, parent); err != nil {
		return nil, err
	}
	var out []TFilter
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("nlroute: recv: %w", err)
		}
		if n <= 0 {
			return nil, errors.New("nlroute: empty recv")
		}
		fs, done, err := parseFilterMsgs(buf[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, keepFilterIfIndex(fs, ifindex)...)
		if done {
			return out, nil
		}
	}
}

// QdiscList 查询 ifindex 的全部 qdisc。错误时返回 (nil, err)。
// 一次 socket 生命周期内完成 dump, 读到 NLMSG_DONE 为止。
//
// 注意: 内核的 RTM_GETQDISC dump 不按请求里的 tcm_ifindex 过滤, 会回
// 全部网卡的 qdisc(iproute2 的 `tc qdisc show dev X` 是在用户态按
// ifindex 筛的)。这里同样在用户态筛 —— 不筛的话别的网卡上的 htb
// 会让热点口「看起来有 htb」, 真丢了也查不出来。
func QdiscList(ifindex int) ([]Qdisc, error) {
	if ifindex <= 0 {
		return nil, errors.New("nlroute: bad ifindex")
	}
	fd, err := openRouteSocket()
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	buf := make([]byte, 1<<16)
	return dumpQdiscsOnFD(fd, 1, ifindex, buf)
}

// FilterList 查询指定网卡 ifindex 与挂载点 parent(如 TC_H_CLSACT_INGRESS)上的全部 tc 过滤器。
func FilterList(ifindex int, parent uint32) ([]TFilter, error) {
	if ifindex <= 0 {
		return nil, errors.New("nlroute: bad ifindex")
	}
	fd, err := openRouteSocket()
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	buf := make([]byte, 1<<16)
	return dumpTFiltersOnFD(fd, 1, ifindex, parent, buf)
}

// HasIngressMirred 检查接口 ifindex 的 ingress/clsact 挂载点(0xfffffff2 / 0xfffffff1 / 0xffff0000)
// 是否存在指向 targetIfbIndex(如 ifb0)的 mirred 动作过滤器。
// 返回 (true, nil) 表示存在; (false, nil) 表示明确缺失; (false, err) 表示 netlink 无法查询(调用方回退 tc)。
func HasIngressMirred(ifindex, targetIfbIndex int) (bool, error) {
	if ifindex <= 0 || targetIfbIndex <= 0 {
		return false, errors.New("nlroute: bad ifindex")
	}
	fd, err := openRouteSocket()
	if err != nil {
		return false, err
	}
	defer syscall.Close(fd)

	buf := make([]byte, 1<<16)
	parents := []uint32{TC_H_CLSACT_INGRESS, TC_H_INGRESS, TC_H_INGRESS_MAJ}
	anyProbed := false
	var firstHardErr error

	for i, parent := range parents {
		fs, derr := dumpTFiltersOnFD(fd, uint32(i+1), ifindex, parent, buf)
		if derr == nil {
			anyProbed = true
			for _, f := range fs {
				if f.MirredIfIndex == targetIfbIndex {
					return true, nil
				}
			}
			continue
		}
		if isAbsentNetlinkErr(derr) {
			anyProbed = true
			continue
		}
		if firstHardErr == nil {
			firstHardErr = derr
		}
	}
	if anyProbed {
		return false, nil
	}
	if firstHardErr != nil {
		return false, firstHardErr
	}
	return false, nil
}

// CheckClsactBPF 检查接口 ifindex 的 clsact(0xfffffff2 / 0xfffffff3)是否存在 bpf 过滤器,
// 以及 pinned map(默认 /sys/fs/bpf/hnc/ip_mark_map)是否可访问。
func CheckClsactBPF(ifindex int, mapPinPath string) (ClsactStatus, error) {
	if ifindex <= 0 {
		return ClsactStatus{}, errors.New("nlroute: bad ifindex")
	}
	if mapPinPath == "" {
		mapPinPath = DefaultBPFMapPinPath
	}
	fd, err := openRouteSocket()
	if err != nil {
		return ClsactStatus{}, err
	}
	defer syscall.Close(fd)

	buf := make([]byte, 1<<16)
	var st ClsactStatus

	qs, qerr := dumpQdiscsOnFD(fd, 1, ifindex, buf)
	if qerr != nil {
		return ClsactStatus{}, qerr
	}
	for _, q := range qs {
		if q.Kind == "clsact" {
			st.Qdisc = true
			break
		}
	}

	ingFs, ierr := dumpTFiltersOnFD(fd, 2, ifindex, TC_H_CLSACT_INGRESS, buf)
	if ierr == nil {
		for _, f := range ingFs {
			if f.Kind == "bpf" {
				st.IngressBPF = true
				st.Qdisc = true
				break
			}
		}
	} else if !isAbsentNetlinkErr(ierr) {
		return ClsactStatus{}, ierr
	}

	egFs, eerr := dumpTFiltersOnFD(fd, 3, ifindex, TC_H_CLSACT_EGRESS, buf)
	if eerr == nil {
		for _, f := range egFs {
			if f.Kind == "bpf" {
				st.EgressBPF = true
				st.Qdisc = true
				break
			}
		}
	} else if !isAbsentNetlinkErr(eerr) {
		return ClsactStatus{}, eerr
	}

	if _, serr := os.Stat(mapPinPath); serr == nil {
		st.MapOK = true
	} else if errors.Is(serr, os.ErrPermission) {
		return st, serr
	}
	return st, nil
}

func decodeNlMsgError(msg []byte) error {
	if len(msg) < nlMsgHdrLen+4 {
		return errors.New("nlroute: truncated nlmsgerr")
	}
	code := int32(binary.LittleEndian.Uint32(msg[nlMsgHdrLen : nlMsgHdrLen+4]))
	if code == 0 {
		return errors.New("nlroute: unexpected ACK")
	}
	if code < 0 {
		return &netlinkErrno{code: code, errno: syscall.Errno(-code)}
	}
	return &netlinkErrno{code: code, errno: syscall.Errno(code)}
}

// parseQdiscMsgs 解析一段 netlink 报文(可能含多条消息)。
// 返回 (qdisc 列表, 是否见到 NLMSG_DONE, error)。
func parseQdiscMsgs(b []byte) ([]Qdisc, bool, error) {
	var out []Qdisc
	native := binary.LittleEndian
	for off := 0; off < len(b); {
		rest := len(b) - off
		if rest < nlMsgHdrLen {
			return nil, false, errors.New("nlroute: truncated nlmsg header")
		}
		msgLen := int(native.Uint32(b[off : off+4]))
		msgType := native.Uint16(b[off+4 : off+6])
		if msgLen < nlMsgHdrLen || msgLen > rest {
			return nil, false, fmt.Errorf("nlroute: bad nlmsg len %d (rest %d)", msgLen, rest)
		}
		msg := b[off : off+msgLen]
		off += alignUp(msgLen, nlMsgAligned)

		switch msgType {
		case nlMsgDone:
			return out, true, nil
		case nlMsgError:
			return nil, false, decodeNlMsgError(msg)
		}
		if msgType != rtmNewQdisc {
			continue // 其他类型(如 RTM_NEWTCLASS 混进来)跳过
		}
		if len(msg) < nlMsgHdrLen+sizeofTcMsg {
			return nil, false, errors.New("nlroute: truncated tcmsg")
		}
		q := Qdisc{
			IfIndex: int(int32(native.Uint32(msg[nlMsgHdrLen+4 : nlMsgHdrLen+8]))),
			Handle:  native.Uint32(msg[nlMsgHdrLen+8 : nlMsgHdrLen+12]),
			Parent:  native.Uint32(msg[nlMsgHdrLen+12 : nlMsgHdrLen+16]),
		}
		aoff := nlMsgHdrLen + sizeofTcMsg
		for aoff < len(msg) {
			aremain := len(msg) - aoff
			if aremain < 4 {
				return nil, false, errors.New("nlroute: truncated tca header")
			}
			attrLen := int(native.Uint16(msg[aoff : aoff+2]))
			attrType := native.Uint16(msg[aoff+2:aoff+4]) & nlaTypeMask
			if attrLen < 4 || attrLen > aremain {
				return nil, false, fmt.Errorf("nlroute: bad tca len %d (rest %d)", attrLen, aremain)
			}
			if attrType == tcaKind {
				q.Kind = cString(msg[aoff+4 : aoff+attrLen])
			}
			aoff += alignUp(attrLen, nlMsgAligned)
		}
		out = append(out, q)
	}
	return out, false, nil
}

// parseFilterMsgs 解析 RTM_NEWTFILTER 响应报文(支持 matchall/u32/flower/basic/fw/bpf 及嵌套 mirred 动作)。
// 任何头部或嵌套 TLV 截断均返回 error, 严禁越界 panic。
func parseFilterMsgs(b []byte) ([]TFilter, bool, error) {
	var out []TFilter
	native := binary.LittleEndian
	for off := 0; off < len(b); {
		rest := len(b) - off
		if rest < nlMsgHdrLen {
			return nil, false, errors.New("nlroute: truncated nlmsg header")
		}
		msgLen := int(native.Uint32(b[off : off+4]))
		msgType := native.Uint16(b[off+4 : off+6])
		if msgLen < nlMsgHdrLen || msgLen > rest {
			return nil, false, fmt.Errorf("nlroute: bad nlmsg len %d (rest %d)", msgLen, rest)
		}
		msg := b[off : off+msgLen]
		off += alignUp(msgLen, nlMsgAligned)

		switch msgType {
		case nlMsgDone:
			return out, true, nil
		case nlMsgError:
			return nil, false, decodeNlMsgError(msg)
		}
		if msgType != rtmNewTFilter {
			continue
		}
		if len(msg) < nlMsgHdrLen+sizeofTcMsg {
			return nil, false, errors.New("nlroute: truncated filter tcmsg")
		}
		info := native.Uint32(msg[nlMsgHdrLen+16 : nlMsgHdrLen+20])
		rawProto := uint16(info & 0xFFFF)
		tf := TFilter{
			IfIndex: int(int32(native.Uint32(msg[nlMsgHdrLen+4 : nlMsgHdrLen+8]))),
			Handle:  native.Uint32(msg[nlMsgHdrLen+8 : nlMsgHdrLen+12]),
			Parent:  native.Uint32(msg[nlMsgHdrLen+12 : nlMsgHdrLen+16]),
			Prio:    uint16(info >> 16),
			Proto:   (rawProto << 8) | (rawProto >> 8),
		}
		var opts []byte
		for aoff := nlMsgHdrLen + sizeofTcMsg; aoff < len(msg); {
			aremain := len(msg) - aoff
			if aremain < 4 {
				return nil, false, errors.New("nlroute: truncated filter tca header")
			}
			attrLen := int(native.Uint16(msg[aoff : aoff+2]))
			attrType := native.Uint16(msg[aoff+2:aoff+4]) & nlaTypeMask
			if attrLen < 4 || attrLen > aremain {
				return nil, false, fmt.Errorf("nlroute: bad filter tca len %d (rest %d)", attrLen, aremain)
			}
			val := msg[aoff+4 : aoff+attrLen]
			switch attrType {
			case tcaKind:
				tf.Kind = cString(val)
			case tcaOptions:
				opts = val
			}
			aoff += alignUp(attrLen, nlMsgAligned)
		}
		if len(opts) > 0 {
			if err := parseFilterOptions(tf.Kind, opts, &tf); err != nil {
				return nil, false, err
			}
		}
		out = append(out, tf)
	}
	return out, false, nil
}

func parseFilterOptions(kind string, opts []byte, tf *TFilter) error {
	var wantActAttr uint16
	switch kind {
	case "matchall":
		wantActAttr = tcaMatchallAct
	case "u32":
		wantActAttr = tcaU32Act
	case "flower":
		wantActAttr = tcaFlowerAct
	case "basic":
		wantActAttr = tcaBasicAct
	case "fw":
		wantActAttr = tcaFwAct
	case "bpf":
		wantActAttr = tcaBPFAct
	default:
		return nil
	}

	native := binary.LittleEndian
	for aoff := 0; aoff < len(opts); {
		aremain := len(opts) - aoff
		if aremain < 4 {
			return errors.New("nlroute: truncated tca_options header")
		}
		attrLen := int(native.Uint16(opts[aoff : aoff+2]))
		attrType := native.Uint16(opts[aoff+2:aoff+4]) & nlaTypeMask
		if attrLen < 4 || attrLen > aremain {
			return fmt.Errorf("nlroute: bad tca_options len %d (rest %d)", attrLen, aremain)
		}
		val := opts[aoff+4 : aoff+attrLen]
		if kind == "bpf" && attrType == tcaBPFName {
			tf.BPFName = cString(val)
		}
		if attrType == wantActAttr && len(val) > 0 {
			if err := parseActTab(val, tf); err != nil {
				return err
			}
		}
		aoff += alignUp(attrLen, nlMsgAligned)
	}
	return nil
}

func parseActTab(tab []byte, tf *TFilter) error {
	native := binary.LittleEndian
	for aoff := 0; aoff < len(tab); {
		aremain := len(tab) - aoff
		if aremain < 4 {
			return errors.New("nlroute: truncated act_tab header")
		}
		attrLen := int(native.Uint16(tab[aoff : aoff+2]))
		if attrLen < 4 || attrLen > aremain {
			return fmt.Errorf("nlroute: bad act_tab len %d (rest %d)", attrLen, aremain)
		}
		slot := tab[aoff+4 : aoff+attrLen]
		if err := parseOneAction(slot, tf); err != nil {
			return err
		}
		aoff += alignUp(attrLen, nlMsgAligned)
	}
	return nil
}

func parseOneAction(slot []byte, tf *TFilter) error {
	native := binary.LittleEndian
	var actKind string
	var actOpts []byte
	for aoff := 0; aoff < len(slot); {
		aremain := len(slot) - aoff
		if aremain < 4 {
			return errors.New("nlroute: truncated act header")
		}
		attrLen := int(native.Uint16(slot[aoff : aoff+2]))
		attrType := native.Uint16(slot[aoff+2:aoff+4]) & nlaTypeMask
		if attrLen < 4 || attrLen > aremain {
			return fmt.Errorf("nlroute: bad act len %d (rest %d)", attrLen, aremain)
		}
		val := slot[aoff+4 : aoff+attrLen]
		switch attrType {
		case tcaActKind:
			actKind = cString(val)
		case tcaActOptions:
			actOpts = val
		}
		aoff += alignUp(attrLen, nlMsgAligned)
	}
	if actKind != "mirred" || len(actOpts) == 0 {
		return nil
	}
	for aoff := 0; aoff < len(actOpts); {
		aremain := len(actOpts) - aoff
		if aremain < 4 {
			return errors.New("nlroute: truncated mirred opts header")
		}
		attrLen := int(native.Uint16(actOpts[aoff : aoff+2]))
		attrType := native.Uint16(actOpts[aoff+2:aoff+4]) & nlaTypeMask
		if attrLen < 4 || attrLen > aremain {
			return fmt.Errorf("nlroute: bad mirred opts len %d (rest %d)", attrLen, aremain)
		}
		val := actOpts[aoff+4 : aoff+attrLen]
		if attrType == tcaMirredParms {
			if len(val) < sizeofTcMirred {
				return fmt.Errorf("nlroute: truncated tc_mirred (%d < %d)", len(val), sizeofTcMirred)
			}
			eaction := int(int32(native.Uint32(val[20:24])))
			targetIdx := int(int32(native.Uint32(val[24:28])))
			if targetIdx > 0 {
				tf.MirredIfIndex = targetIdx
				tf.MirredEAction = eaction
			}
		}
		aoff += alignUp(attrLen, nlMsgAligned)
	}
	return nil
}

// keepIfIndex 只留属于 ifindex 的条目(内核 dump 回的是全部网卡)。
func keepIfIndex(qs []Qdisc, ifindex int) []Qdisc {
	var out []Qdisc
	for _, q := range qs {
		if q.IfIndex == ifindex {
			out = append(out, q)
		}
	}
	return out
}

func keepFilterIfIndex(fs []TFilter, ifindex int) []TFilter {
	var out []TFilter
	for _, f := range fs {
		if f.IfIndex == ifindex {
			out = append(out, f)
		}
	}
	return out
}

// alignUp v 到 align 的倍数(netlink NLMSG_ALIGN)。
func alignUp(v, a int) int {
	return (v + a - 1) &^ (a - 1)
}

// cString 取 NUL 结尾字符串(截尾, 无 NUL 就整段)。
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
