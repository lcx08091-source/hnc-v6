// Package nlroute —— v5.29 T1(M2): 只读 NETLINK_ROUTE 查询, 纯 syscall 无依赖。
//
// 用途: 看门狗的原生健康检查(native.go)要回答「某网卡的根 qdisc 是不是
// htb」, 现在靠每轮 fork `tc qdisc show`。本包直接发 RTM_GETQDISC +
// NLM_F_DUMP, 解析 tcmsg 与 TCA_KIND 属性。
//
// 约束:
//   - 只读。不做任何写操作(加 / 删 qdisc 仍走 tc 二进制 / shell 修复路径);
//   - 报文解析拆成 parseQdiscMsgs(测试直接喂手工构造的字节, 含截断 /
//     NLMSG_ERROR / 属性对齐用例, 截断必须返回错误不能 panic);
//   - 嵌套过滤器 action 的解析本版不做(照抄 shell 判断用 tc filter 文本)。
package nlroute

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
)

// ─── netlink 常量(不引 golang.org/x/net) ─────────────────────────────

const (
	nlMsgAligned = 4 // NLMSG_ALIGNTO

	nlMsgHdrLen = 16 // len(4) type(2) flags(2) seq(4) pid(4)

	nlMsgError = 2
	nlMsgDone  = 3

	rtmNewQdisc = 16
	rtmGetQdisc = 26

	nlmFRequest = 0x001
	nlmFDump    = 0x300 // NLM_F_ROOT | NLM_F_MATCH

	tcaKind = 1 // TCA_KIND

	sizeofTcMsg = 20 // family(1)+pad(1)+ifindex(4)+handle(4)+parent(4)+info(4)
)

// TC_H_ROOT 根 parent 的值(qdisc "root")。
const TC_H_ROOT = 0xFFFFFFFF

// TC_H_INGRESS ingress parent 的值("parent ffff:")。
const TC_H_INGRESS = 0xFFFF0000

// TC_HMaj(handle "1:")的数值 —— handle = major<<16。
func TC_HMaj(major uint32) uint32 { return major << 16 }

// Qdisc 一条排队规则。
type Qdisc struct {
	IfIndex int    // tcmsg.tcm_ifindex(所属网卡)
	Kind    string // TCA_KIND, 如 "htb" / "fq_codel" / "mq"
	Handle  uint32 // 句柄, 如 0x00010000 = "1:"
	Parent  uint32 // parent, 0xFFFFFFFF = root; 0xFFFFFFF1 = ingress 特例
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
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("nlroute: socket: %w", err)
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("nlroute: bind: %w", err)
	}

	// 请求: nlmsghdr + tcmsg(ifindex 填好, 其余 0)
	req := make([]byte, nlMsgHdrLen+sizeofTcMsg)
	native := binary.LittleEndian
	native.PutUint32(req[0:4], uint32(len(req)))
	native.PutUint16(req[4:6], rtmGetQdisc)
	native.PutUint16(req[6:8], nlmFRequest|nlmFDump)
	native.PutUint32(req[8:12], 1) // seq
	native.PutUint32(req[16:20], uint32(int32(ifindex)))
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("nlroute: send: %w", err)
	}

	var out []Qdisc
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
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

// parseQdiscMsgs 解析一段 netlink 报文(可能含多条消息)。
// 返回 (qdisc 列表, 是否见到 NLMSG_DONE, error)。
// 规则:
//   - 每条消息按 NLMSG_ALIGN 对齐前进;
//   - nlmsg_len 必须 ≥ 头长且不超过剩余字节, 否则视为截断报错;
//   - NLMSG_ERROR → err(dump 场景不应出现, 内核错误码带出);
//   - NLMSG_DONE → done=true, 停止;
//   - RTM_NEWQDISC 数据长度 < sizeof(tcmsg) → 截断报错;
//   - 属性走 TLV: len 含头 4 字节、按 4 对齐前进, len < 4 或越界 → 报错。
func parseQdiscMsgs(b []byte) ([]Qdisc, bool, error) {
	var out []Qdisc
	for off := 0; off < len(b); {
		rest := len(b) - off
		if rest < nlMsgHdrLen {
			return nil, false, errors.New("nlroute: truncated nlmsg header")
		}
		native := binary.LittleEndian
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
			if len(msg) < nlMsgHdrLen+4 {
				return nil, false, errors.New("nlroute: truncated nlmsgerr")
			}
			code := int32(native.Uint32(msg[nlMsgHdrLen : nlMsgHdrLen+4]))
			if code == 0 {
				return nil, false, errors.New("nlroute: unexpected ACK")
			}
			return nil, false, fmt.Errorf("nlroute: netlink error %d", code)
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
			attrType := native.Uint16(msg[aoff+2 : aoff+4])
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
