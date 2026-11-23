package nlroute

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildMsg 构造一条 netlink 消息: type, payload(已含 tcmsg), 属性自动 4 对齐。
func buildMsg(msgType uint16, payload []byte) []byte {
	n := 16 + len(payload)
	pad := alignUp(n, 4) - n
	out := make([]byte, n+pad)
	binary.LittleEndian.PutUint32(out[0:4], uint32(n))
	binary.LittleEndian.PutUint16(out[4:6], msgType)
	copy(out[16:], payload)
	return out
}

// buildTcMsg handle/parent 的 tcmsg(ifindex 固定 7)。
func buildTcMsg(handle, parent uint32) []byte {
	return buildTcMsgIf(7, handle, parent)
}

func buildTcMsgIf(ifindex int, handle, parent uint32) []byte {
	p := make([]byte, sizeofTcMsg)
	binary.LittleEndian.PutUint32(p[4:8], uint32(int32(ifindex)))
	binary.LittleEndian.PutUint32(p[8:12], handle)
	binary.LittleEndian.PutUint32(p[12:16], parent)
	return p
}

// buildAttr kind 字符串的 TCA_KIND 属性。
func buildAttr(kind string) []byte {
	n := 4 + len(kind) + 1
	pad := alignUp(n, 4) - n
	out := make([]byte, n+pad)
	binary.LittleEndian.PutUint16(out[0:2], uint16(n))
	binary.LittleEndian.PutUint16(out[2:4], tcaKind)
	copy(out[4:], kind+"\x00")
	return out
}

func TestParseQdiscMsgsRootHTB(t *testing.T) {
	msg := append(buildTcMsg(0x00010000, TC_H_ROOT), buildAttr("htb")...)
	buf := buildMsg(rtmNewQdisc, msg)
	qs, done, err := parseQdiscMsgs(buf)
	if err != nil || done {
		t.Fatalf("err=%v done=%v", err, done)
	}
	if len(qs) != 1 || qs[0].Kind != "htb" || qs[0].Handle != 0x00010000 || qs[0].Parent != TC_H_ROOT {
		t.Fatalf("got %+v", qs)
	}
}

func TestParseQdiscMsgsMultipleWithDone(t *testing.T) {
	m1 := append(buildTcMsg(0, TC_H_ROOT), buildAttr("mq")...)
	m2 := append(buildTcMsg(0x00010000, 1), buildAttr("htb")...) // mq 子队列: parent :1
	buf := append(append(buildMsg(rtmNewQdisc, m1), buildMsg(rtmNewQdisc, m2)...), buildMsg(nlMsgDone, nil)...)
	qs, done, err := parseQdiscMsgs(buf)
	if err != nil || !done {
		t.Fatalf("err=%v done=%v", err, done)
	}
	if len(qs) != 2 || qs[0].Kind != "mq" || qs[1].Kind != "htb" || qs[1].Parent != 1 {
		t.Fatalf("got %+v", qs)
	}
}

func TestParseQdiscMsgsTruncated(t *testing.T) {
	cases := [][]byte{
		[]byte{0x10, 0}, // 头都不够
		buildMsg(rtmNewQdisc, buildTcMsg(0, 0))[:18], // nlmsg_len 完整但数据被截
	}
	msg := append(buildTcMsg(0, 0), buildAttr("htb")...)
	bad := buildMsg(rtmNewQdisc, msg)
	binary.LittleEndian.PutUint32(bad[0:4], 4) // len < 头长
	cases = append(cases, bad)
	for i, b := range cases {
		if _, _, err := parseQdiscMsgs(b); err == nil {
			t.Errorf("case %d: 截断报文应报错", i)
		}
	}
	// 属性长度越界
	m := append(buildTcMsg(0, 0), 0x08, 0x00, 0x01, 0x00) // 声称 8 字节但没有载荷
	if _, _, err := parseQdiscMsgs(buildMsg(rtmNewQdisc, m)); err == nil {
		t.Error("属性 len 越界应报错")
	}
}

func TestParseQdiscMsgsError(t *testing.T) {
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint32(payload, 22) // EINVAL
	buf := buildMsg(nlMsgError, payload)
	if _, _, err := parseQdiscMsgs(buf); err == nil {
		t.Fatal("NLMSG_ERROR 应报错")
	}
}

func TestParseQdiscMsgsSkipOtherTypes(t *testing.T) {
	// RTM_NEWTCLASS(18) 混进来应跳过而不是报错
	buf := append(buildMsg(18, buildTcMsg(0, 0)), buildMsg(nlMsgDone, nil)...)
	qs, done, err := parseQdiscMsgs(buf)
	if err != nil || !done || len(qs) != 0 {
		t.Fatalf("err=%v done=%v qs=%v", err, done, qs)
	}
}

// TestQdiscListLiveSmoke 本机(容器内核)dump 一次 lo: 只要求不报错、
// 返回里 lo(ifindex=1)的回环 qdisc noqueue 或根 qdisc 结构合法。
// 在无 NETLINK_ROUTE 权限的环境(罕见)下允许 err, 不允许 panic。
func TestQdiscListLiveSmoke(t *testing.T) {
	qs, err := QdiscList(1)
	if err != nil {
		t.Skipf("live netlink 不可用(权限?): %v", err)
	}
	for _, q := range qs {
		if q.Kind == "" && q.Handle == 0 && q.Parent == 0 {
			t.Errorf("空 qdisc 条目: %+v", q)
		}
	}
}

// TestQdiscDumpFilteredByIfIndex 内核 dump 回全部网卡的 qdisc(不按请求的
// ifindex 过滤)。别的口(ifindex 3)有 root htb、热点口(ifindex 7)只剩
// fq_codel 时, 查 7 不能被 3 的 htb 冒充成「有 htb」。
func TestQdiscDumpFilteredByIfIndex(t *testing.T) {
	m1 := append(buildTcMsgIf(3, 0x00010000, TC_H_ROOT), buildAttr("htb")...)
	m2 := append(buildTcMsgIf(7, 0, TC_H_ROOT), buildAttr("fq_codel")...)
	buf := append(append(buildMsg(rtmNewQdisc, m1), buildMsg(rtmNewQdisc, m2)...), buildMsg(nlMsgDone, nil)...)
	qs, done, err := parseQdiscMsgs(buf)
	if err != nil || !done || len(qs) != 2 {
		t.Fatalf("err=%v done=%v qs=%+v", err, done, qs)
	}
	if qs[0].IfIndex != 3 || qs[1].IfIndex != 7 {
		t.Fatalf("ifindex 没解析出来: %+v", qs)
	}
	got := keepIfIndex(qs, 7)
	if len(got) != 1 || got[0].Kind != "fq_codel" {
		t.Fatalf("查 ifindex 7 应只剩 fq_codel, got %+v", got)
	}
}

// TestQdiscListLiveOnlyRequestedIf 本机真 dump: 每个网卡查回来的条目都必须
// 属于该网卡。
func TestQdiscListLiveOnlyRequestedIf(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Skip("no interfaces")
	}
	for _, ifc := range ifs {
		qs, err := QdiscList(ifc.Index)
		if err != nil {
			t.Skipf("live netlink 不可用: %v", err)
		}
		for _, q := range qs {
			if q.IfIndex != ifc.Index {
				t.Errorf("%s(%d) 查回了别的口的 qdisc: %+v", ifc.Name, ifc.Index, q)
			}
		}
	}
}

func TestAlignUp(t *testing.T) {
	for _, c := range []struct{ v, a, w int }{{0, 4, 0}, {1, 4, 4}, {4, 4, 4}, {5, 4, 8}, {9, 4, 12}} {
		if got := alignUp(c.v, c.a); got != c.w {
			t.Errorf("alignUp(%d,%d)=%d want %d", c.v, c.a, got, c.w)
		}
	}
}

func buildRawAttr(attrType uint16, val []byte) []byte {
	n := 4 + len(val)
	pad := alignUp(n, 4) - n
	out := make([]byte, n+pad)
	binary.LittleEndian.PutUint16(out[0:2], uint16(n))
	binary.LittleEndian.PutUint16(out[2:4], attrType)
	copy(out[4:], val)
	return out
}

func buildMirredActionSlot(slotIdx uint16, targetIfIndex int, eaction int32, nestedBit bool) []byte {
	const nlaNested = 0x8000
	parms := make([]byte, sizeofTcMirred)
	binary.LittleEndian.PutUint32(parms[8:12], 4) // TC_ACT_STOLEN
	binary.LittleEndian.PutUint32(parms[20:24], uint32(eaction))
	binary.LittleEndian.PutUint32(parms[24:28], uint32(int32(targetIfIndex)))

	actOptsType := uint16(tcaActOptions)
	slotType := slotIdx
	if nestedBit {
		actOptsType |= nlaNested
		slotType |= nlaNested
	}
	actKind := buildRawAttr(tcaActKind, []byte("mirred\x00"))
	actOpts := buildRawAttr(actOptsType, buildRawAttr(tcaMirredParms, parms))
	return buildRawAttr(slotType, append(actKind, actOpts...))
}

func buildTcFilterMsg(ifindex int, parent, handle uint32, prio, protoBE uint16) []byte {
	p := make([]byte, sizeofTcMsg)
	binary.LittleEndian.PutUint32(p[4:8], uint32(int32(ifindex)))
	binary.LittleEndian.PutUint32(p[8:12], handle)
	binary.LittleEndian.PutUint32(p[12:16], parent)
	info := (uint32(prio) << 16) | uint32(protoBE)
	binary.LittleEndian.PutUint32(p[16:20], info)
	return p
}

func TestParseFilterMsgsMirredVariants(t *testing.T) {
	const nlaNested = 0x8000
	// 1. matchall (prio 2, NLA_F_NESTED 置位) -> ifb0(ifindex=12)
	maOpts := buildRawAttr(tcaMatchallAct|nlaNested, buildMirredActionSlot(1, 12, 1, true))
	m1 := append(buildTcFilterMsg(7, TC_H_CLSACT_INGRESS, 1, 2, 0x0300),
		append(buildAttr("matchall"), buildRawAttr(tcaOptions|nlaNested, maOpts)...)...)

	// 2. u32 (parent ffff:, 无 NLA_F_NESTED) -> ifb0(ifindex=12)
	u32Opts := buildRawAttr(tcaU32Act, buildMirredActionSlot(1, 12, 1, false))
	m2 := append(buildTcFilterMsg(7, TC_H_INGRESS_MAJ, 0x80000800, 2, 0x0008),
		append(buildAttr("u32"), buildRawAttr(tcaOptions, u32Opts)...)...)

	// 3. flower -> 别的口(ifindex=99)
	flOpts := buildRawAttr(tcaFlowerAct, buildMirredActionSlot(1, 99, 1, true))
	m3 := append(buildTcFilterMsg(7, TC_H_INGRESS, 1, 1, 0x0008),
		append(buildAttr("flower"), buildRawAttr(tcaOptions, flOpts)...)...)

	buf := append(append(append(
		buildMsg(rtmNewTFilter, m1),
		buildMsg(rtmNewTFilter, m2)...),
		buildMsg(rtmNewTFilter, m3)...),
		buildMsg(nlMsgDone, nil)...)

	fs, done, err := parseFilterMsgs(buf)
	if err != nil || !done || len(fs) != 3 {
		t.Fatalf("err=%v done=%v len=%d fs=%+v", err, done, len(fs), fs)
	}
	if fs[0].Kind != "matchall" || fs[0].MirredIfIndex != 12 || fs[0].Prio != 2 || fs[0].Proto != 0x0003 {
		t.Fatalf("matchall parsed wrong: %+v", fs[0])
	}
	if fs[1].Kind != "u32" || fs[1].MirredIfIndex != 12 || fs[1].Proto != 0x0800 {
		t.Fatalf("u32 parsed wrong: %+v", fs[1])
	}
	if fs[2].Kind != "flower" || fs[2].MirredIfIndex != 99 {
		t.Fatalf("flower parsed wrong: %+v", fs[2])
	}
}

func TestParseFilterMsgsClsactBPF(t *testing.T) {
	bpfOpts := buildRawAttr(tcaBPFName, []byte("hnc_clsact\x00"))
	mIng := append(buildTcFilterMsg(7, TC_H_CLSACT_INGRESS, 1, 1, 0x0300),
		append(buildAttr("bpf"), buildRawAttr(tcaOptions|0x8000, bpfOpts)...)...)
	mEg := append(buildTcFilterMsg(7, TC_H_CLSACT_EGRESS, 1, 1, 0x0300),
		append(buildAttr("bpf"), buildRawAttr(tcaOptions, buildRawAttr(tcaBPFName, []byte("hnc_clsact_eg\x00")))...)...)

	buf := append(append(buildMsg(rtmNewTFilter, mIng), buildMsg(rtmNewTFilter, mEg)...), buildMsg(nlMsgDone, nil)...)
	fs, done, err := parseFilterMsgs(buf)
	if err != nil || !done || len(fs) != 2 {
		t.Fatalf("err=%v done=%v fs=%+v", err, done, fs)
	}
	if fs[0].Kind != "bpf" || fs[0].Parent != TC_H_CLSACT_INGRESS || fs[0].BPFName != "hnc_clsact" {
		t.Fatalf("ingress bpf wrong: %+v", fs[0])
	}
	if fs[1].Kind != "bpf" || fs[1].Parent != TC_H_CLSACT_EGRESS || fs[1].BPFName != "hnc_clsact_eg" {
		t.Fatalf("egress bpf wrong: %+v", fs[1])
	}
}

func TestParseFilterMsgsTruncatedNeverPanics(t *testing.T) {
	// 构造截断的 tc_mirred(仅 12 字节 < 28 字节)
	shortParms := make([]byte, 12)
	act := buildRawAttr(1, append(buildRawAttr(tcaActKind, []byte("mirred\x00")),
		buildRawAttr(tcaActOptions, buildRawAttr(tcaMirredParms, shortParms))...))
	mShort := append(buildTcFilterMsg(7, TC_H_CLSACT_INGRESS, 1, 2, 0x0300),
		append(buildAttr("matchall"), buildRawAttr(tcaOptions, buildRawAttr(tcaMatchallAct, act))...)...)

	// 构造内部属性越界的 TCA_OPTIONS
	badNested := []byte{0x20, 0x00, 0x02, 0x00, 0x01, 0x02}
	mBadOpt := append(buildTcFilterMsg(7, TC_H_CLSACT_INGRESS, 1, 2, 0x0300),
		append(buildAttr("matchall"), buildRawAttr(tcaOptions, badNested)...)...)

	for i, raw := range [][]byte{
		buildMsg(rtmNewTFilter, mShort),
		buildMsg(rtmNewTFilter, mBadOpt),
		buildMsg(rtmNewTFilter, buildTcFilterMsg(7, 0, 0, 1, 0)[:10]),
	} {
		if _, _, err := parseFilterMsgs(raw); err == nil {
			t.Errorf("case %d: 截断嵌套属性必须返回 error", i)
		}
	}
}

func TestClsactStatusOK(t *testing.T) {
	if (ClsactStatus{Qdisc: true, IngressBPF: true, MapOK: true}).OK() != true {
		t.Fatal("三项齐备应 OK")
	}
	if (ClsactStatus{Qdisc: true, IngressBPF: true, MapOK: false}).OK() {
		t.Fatal("缺 map 不应 OK")
	}
	if (ClsactStatus{Qdisc: true, IngressBPF: false, EgressBPF: true, MapOK: true}).OK() {
		t.Fatal("缺 ingress bpf 不应 OK")
	}
}
