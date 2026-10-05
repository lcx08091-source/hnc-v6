package nlroute

import (
	"encoding/binary"
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

// buildTcMsg handle/parent 的 tcmsg。
func buildTcMsg(handle, parent uint32) []byte {
	p := make([]byte, sizeofTcMsg)
	binary.LittleEndian.PutUint32(p[4:8], 7) // ifindex
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

func TestAlignUp(t *testing.T) {
	for _, c := range []struct{ v, a, w int }{{0, 4, 0}, {1, 4, 4}, {4, 4, 4}, {5, 4, 8}, {9, 4, 12}} {
		if got := alignUp(c.v, c.a); got != c.w {
			t.Errorf("alignUp(%d,%d)=%d want %d", c.v, c.a, got, c.w)
		}
	}
}
