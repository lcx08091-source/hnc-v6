package neigh

import (
	"encoding/binary"
	"net"
	"strings"
	"syscall"
	"testing"
)

// ─── 手工构造报文 ────────────────────────────────────────────────────────

func nla(typ uint16, v []byte) []byte {
	b := make([]byte, 4+len(v))
	binary.LittleEndian.PutUint16(b[0:2], uint16(4+len(v)))
	binary.LittleEndian.PutUint16(b[2:4], typ)
	copy(b[4:], v)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func nlmsg(typ uint16, payload []byte) []byte {
	b := make([]byte, nlMsgHdrLen+len(payload))
	binary.LittleEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.LittleEndian.PutUint16(b[4:6], typ)
	copy(b[nlMsgHdrLen:], payload)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func ndmsg(family byte, ifindex int, state uint16) []byte {
	b := make([]byte, sizeofNdMsg)
	b[0] = family
	binary.LittleEndian.PutUint32(b[4:8], uint32(int32(ifindex)))
	binary.LittleEndian.PutUint16(b[8:10], state)
	return b
}

func neighMsg(typ uint16, ifindex int, state uint16, ip string, mac string) []byte {
	p := ndmsg(syscall.AF_INET, ifindex, state)
	if ip != "" {
		p = append(p, nla(ndaDst, net.ParseIP(ip).To4())...)
	}
	if mac != "" {
		hw, _ := net.ParseMAC(mac)
		p = append(p, nla(ndaLLAddr, hw)...)
	}
	return nlmsg(typ, p)
}

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

var doneMsg = nlmsg(nlMsgDone, []byte{0, 0, 0, 0})

// ─── 用例 ────────────────────────────────────────────────────────────────

func TestParseMultiAndDone(t *testing.T) {
	b := cat(
		neighMsg(rtmNewNeigh, 5, NUDReachable, "192.168.43.10", "aa:bb:cc:dd:ee:01"),
		neighMsg(rtmNewNeigh, 5, NUDStale, "192.168.43.11", "aa:bb:cc:dd:ee:02"),
		neighMsg(rtmNewNeigh, 2, NUDReachable, "10.0.0.1", "11:22:33:44:55:66"),
		doneMsg,
		neighMsg(rtmNewNeigh, 5, NUDReachable, "192.168.43.99", "aa:bb:cc:dd:ee:99"), // DONE 之后不再解析
	)
	es, done, err := ParseMsgs(b)
	if err != nil || !done || len(es) != 3 {
		t.Fatalf("es=%v done=%v err=%v", es, done, err)
	}
	if es[0].IfIndex != 5 || es[0].IP.String() != "192.168.43.10" || es[0].MAC != "aa:bb:cc:dd:ee:01" ||
		es[0].State != NUDReachable || es[0].Family != syscall.AF_INET {
		t.Fatalf("entry0 = %+v", es[0])
	}
}

func TestParseNoDoneYet(t *testing.T) {
	es, done, err := ParseMsgs(neighMsg(rtmNewNeigh, 5, NUDReachable, "192.168.43.10", "aa:bb:cc:dd:ee:01"))
	if err != nil || done || len(es) != 1 {
		t.Fatalf("es=%v done=%v err=%v", es, done, err)
	}
}

// 内核 dump 不按 ifindex 过滤 → 用户态筛。
func TestKeepIfIndex(t *testing.T) {
	es, _, _ := ParseMsgs(cat(
		neighMsg(rtmNewNeigh, 5, NUDReachable, "192.168.43.10", "aa:bb:cc:dd:ee:01"),
		neighMsg(rtmNewNeigh, 2, NUDReachable, "10.0.0.1", "11:22:33:44:55:66"),
		neighMsg(rtmNewNeigh, 5, NUDStale, "192.168.43.11", "aa:bb:cc:dd:ee:02"),
	))
	got := KeepIfIndex(es, 5)
	if len(got) != 2 || got[0].MAC != "aa:bb:cc:dd:ee:01" || got[1].MAC != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("KeepIfIndex = %+v", got)
	}
	if len(KeepIfIndex(es, 9)) != 0 {
		t.Fatal("别的网卡不应留下")
	}
}

func TestParseError(t *testing.T) {
	e := make([]byte, 4+nlMsgHdrLen)
	code := -int32(syscall.EPERM)
	binary.LittleEndian.PutUint32(e[0:4], uint32(code))
	_, _, err := ParseMsgs(nlmsg(nlMsgError, e))
	if err == nil || !strings.Contains(err.Error(), "netlink error") {
		t.Fatalf("err = %v", err)
	}
	ack := make([]byte, 4+nlMsgHdrLen) // code 0
	if _, _, err := ParseMsgs(nlmsg(nlMsgError, ack)); err == nil {
		t.Fatal("dump 里出现 ACK 应报错")
	}
	if _, _, err := ParseMsgs(nlmsg(nlMsgError, []byte{1})); err == nil {
		t.Fatal("截断的 nlmsgerr 应报错")
	}
}

// 各种截断: 报错, 不 panic。
func TestParseTruncatedNoPanic(t *testing.T) {
	full := cat(neighMsg(rtmNewNeigh, 5, NUDReachable, "192.168.43.10", "aa:bb:cc:dd:ee:01"), doneMsg)
	for i := 1; i < len(full); i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("截断到 %d 字节时 panic: %v", i, r)
				}
			}()
			_, _, _ = ParseMsgs(full[:i])
		}()
	}
	// nlmsg_len 声明比实际长
	bad := neighMsg(rtmNewNeigh, 5, NUDReachable, "192.168.43.10", "aa:bb:cc:dd:ee:01")
	binary.LittleEndian.PutUint32(bad[0:4], uint32(len(bad)+8))
	if _, _, err := ParseMsgs(bad); err == nil {
		t.Fatal("nlmsg_len 越界应报错")
	}
	// ndmsg 不完整
	if _, _, err := ParseMsgs(nlmsg(rtmNewNeigh, []byte{2, 0, 0, 0})); err == nil {
		t.Fatal("ndmsg 截断应报错")
	}
	// 属性 len < 4
	p := cat(ndmsg(syscall.AF_INET, 5, NUDReachable), []byte{2, 0, 1, 0})
	if _, _, err := ParseMsgs(nlmsg(rtmNewNeigh, p)); err == nil {
		t.Fatal("属性 len<4 应报错")
	}
	// 属性越界
	p = cat(ndmsg(syscall.AF_INET, 5, NUDReachable), []byte{40, 0, 1, 0, 1, 2, 3, 4})
	if _, _, err := ParseMsgs(nlmsg(rtmNewNeigh, p)); err == nil {
		t.Fatal("属性越界应报错")
	}
}

func TestParseSkipsOtherTypesAndOddAttrs(t *testing.T) {
	odd := cat(ndmsg(syscall.AF_INET, 5, NUDReachable),
		nla(ndaDst, net.ParseIP("192.168.43.12").To4()),
		nla(ndaLLAddr, []byte{1, 2, 3}), // 不是 6 字节 → 不认 MAC
		nla(9, []byte{1, 2, 3, 4, 5}))   // 未知属性(含对齐填充)跳过
	es, _, err := ParseMsgs(cat(nlmsg(24, []byte{0, 0, 0, 0}) /* RTM_NEWROUTE */, nlmsg(rtmNewNeigh, odd)))
	if err != nil || len(es) != 1 || es[0].MAC != "" || es[0].IP.String() != "192.168.43.12" {
		t.Fatalf("es=%+v err=%v", es, err)
	}
	if es[0].Usable() {
		t.Fatal("没有 MAC 不算可用")
	}
}

func TestUsableStatesAndDelete(t *testing.T) {
	cases := map[uint16]bool{
		NUDReachable: true, NUDStale: true, NUDDelay: true, NUDProbe: true,
		NUDIncomplete: false, NUDFailed: false, NUDNoARP: false, NUDPermanent: false, 0: false,
	}
	for st, want := range cases {
		e := Entry{MAC: "aa:bb:cc:dd:ee:01", State: st}
		if e.Usable() != want {
			t.Errorf("state 0x%02x Usable=%v want %v", st, e.Usable(), want)
		}
	}
	es, _, _ := ParseMsgs(neighMsg(rtmDelNeigh, 5, NUDReachable, "192.168.43.10", "aa:bb:cc:dd:ee:01"))
	if len(es) != 1 || !es[0].Deleted || es[0].Usable() {
		t.Fatalf("RTM_DELNEIGH: %+v", es)
	}
	if (Entry{MAC: "00:00:00:00:00:00", State: NUDReachable}).Usable() {
		t.Fatal("全零 MAC 不算")
	}
}

func TestBuildDumpReq(t *testing.T) {
	req := buildDumpReq(syscall.AF_INET, 0)
	le := binary.LittleEndian
	if int(le.Uint32(req[0:4])) != len(req) || le.Uint16(req[4:6]) != rtmGetNeigh ||
		le.Uint16(req[6:8]) != nlmFRequest|nlmFDump || req[nlMsgHdrLen] != syscall.AF_INET {
		t.Fatalf("req = % x", req)
	}
}
