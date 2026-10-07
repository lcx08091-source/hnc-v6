// Package neigh —— v5.30 T3(迁移 M4 第一步): 只读邻居表(ARP / NDP), 纯 syscall 无依赖。
//
// 用途: 设备发现目前由 hotspotd(C)读 /proc/net/arp + netlink 维护
// data/devices.json。M4 要把它搬进 Go; 第一步只做「影子」—— Go 看门狗用本包
// 读邻居表, 与 hotspotd 的结果比对, 不写 devices.json、不替换任何功能。
//
//   - Dump: RTM_GETNEIGH + NLM_F_DUMP, 一次读完到 NLMSG_DONE;
//   - Subscribe: 订阅 RTNLGRP_NEIGH(RTM_NEWNEIGH / RTM_DELNEIGH 事件), 给 M4
//     第二步(替换 hotspotd)用; 影子本版只按 5 分钟节拍 Dump(省电: 邻居表
//     状态迁移很频繁, 常驻订阅每次都会唤醒看门狗);
//   - ParseMsgs: 解析一段 netlink 报文(多条消息、DONE、ERROR、截断返回错误
//     不 panic、属性按 4 字节对齐), 测试直接喂手工构造的字节;
//   - 内核 dump 不按请求里的 ifindex 过滤(与 RTM_GETQDISC 一样), 调用方用
//     KeepIfIndex / DumpIf 在用户态筛。
package neigh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ─── netlink / neighbour 常量(不引 golang.org/x/net) ────────────────────

const (
	nlMsgAlign  = 4
	nlMsgHdrLen = 16 // len(4) type(2) flags(2) seq(4) pid(4)

	nlMsgError = 2
	nlMsgDone  = 3

	rtmNewNeigh = 28
	rtmDelNeigh = 29
	rtmGetNeigh = 30

	nlmFRequest = 0x001
	nlmFDump    = 0x300 // NLM_F_ROOT | NLM_F_MATCH

	sizeofNdMsg = 12 // family(1) pad1(1) pad2(2) ifindex(4) state(2) flags(1) type(1)

	ndaDst    = 1 // NDA_DST
	ndaLLAddr = 2 // NDA_LLADDR

	rtmgrpNeigh = 1 << (3 - 1) // RTNLGRP_NEIGH = 3
)

// NUD 状态位(linux/neighbour.h)。
const (
	NUDIncomplete = 0x01
	NUDReachable  = 0x02
	NUDStale      = 0x04
	NUDDelay      = 0x08
	NUDProbe      = 0x10
	NUDFailed     = 0x20
	NUDNoARP      = 0x40
	NUDPermanent  = 0x80
)

// nudValid 有可用链路层地址的动态状态(= /proc/net/arp 里 flags 0x2 的那些)。
const nudValid = NUDReachable | NUDStale | NUDDelay | NUDProbe

// Entry 一条邻居表项。
type Entry struct {
	IfIndex int
	Family  int    // syscall.AF_INET / AF_INET6
	IP      net.IP // NDA_DST
	MAC     string // NDA_LLADDR, "aa:bb:cc:dd:ee:ff"; 没有 / 不是 6 字节 → ""
	State   uint16
	Deleted bool // 订阅事件里的 RTM_DELNEIGH
}

// Usable 有 MAC、且处于有效动态状态(INCOMPLETE / FAILED / NOARP / PERMANENT 不算:
// 前两个没有可用地址, 后两个是静态 / 本机表项, 不是热点客户端)。
func (e Entry) Usable() bool {
	return !e.Deleted && e.MAC != "" && e.MAC != "00:00:00:00:00:00" && e.State&nudValid != 0
}

// ParseMsgs 解析一段 netlink 报文(可能含多条消息)。
// 返回 (表项, 是否见到 NLMSG_DONE, error)。规则同 nlroute.parseQdiscMsgs:
//   - 每条消息按 NLMSG_ALIGN 对齐前进; nlmsg_len 必须 ≥ 头长且不超过剩余字节;
//   - NLMSG_ERROR → err(code 0 = 意外 ACK); NLMSG_DONE → done=true 并停止;
//   - RTM_NEWNEIGH / RTM_DELNEIGH 数据 < sizeof(ndmsg) → 截断报错;
//   - 属性 TLV: len 含头 4 字节、按 4 对齐前进, len < 4 或越界 → 报错;
//   - 其他消息类型跳过。
func ParseMsgs(b []byte) ([]Entry, bool, error) {
	var out []Entry
	le := binary.LittleEndian
	for off := 0; off < len(b); {
		rest := len(b) - off
		if rest < nlMsgHdrLen {
			return nil, false, errors.New("neigh: truncated nlmsg header")
		}
		msgLen := int(le.Uint32(b[off : off+4]))
		msgType := le.Uint16(b[off+4 : off+6])
		if msgLen < nlMsgHdrLen || msgLen > rest {
			return nil, false, fmt.Errorf("neigh: bad nlmsg len %d (rest %d)", msgLen, rest)
		}
		msg := b[off : off+msgLen]
		off += alignUp(msgLen)

		switch msgType {
		case nlMsgDone:
			return out, true, nil
		case nlMsgError:
			if len(msg) < nlMsgHdrLen+4 {
				return nil, false, errors.New("neigh: truncated nlmsgerr")
			}
			code := int32(le.Uint32(msg[nlMsgHdrLen : nlMsgHdrLen+4]))
			if code == 0 {
				return nil, false, errors.New("neigh: unexpected ACK")
			}
			return nil, false, fmt.Errorf("neigh: netlink error %d", code)
		case rtmNewNeigh, rtmDelNeigh:
		default:
			continue
		}
		if len(msg) < nlMsgHdrLen+sizeofNdMsg {
			return nil, false, errors.New("neigh: truncated ndmsg")
		}
		nd := msg[nlMsgHdrLen:]
		e := Entry{
			Family:  int(nd[0]),
			IfIndex: int(int32(le.Uint32(nd[4:8]))),
			State:   le.Uint16(nd[8:10]),
			Deleted: msgType == rtmDelNeigh,
		}
		for aoff := nlMsgHdrLen + sizeofNdMsg; aoff < len(msg); {
			arest := len(msg) - aoff
			if arest < 4 {
				return nil, false, errors.New("neigh: truncated nda header")
			}
			alen := int(le.Uint16(msg[aoff : aoff+2]))
			atype := le.Uint16(msg[aoff+2:aoff+4]) & 0x3fff // 去 NLA_F_NESTED / NET_BYTEORDER
			if alen < 4 || alen > arest {
				return nil, false, fmt.Errorf("neigh: bad nda len %d (rest %d)", alen, arest)
			}
			v := msg[aoff+4 : aoff+alen]
			switch atype {
			case ndaDst:
				if len(v) == 4 || len(v) == 16 {
					e.IP = append(net.IP(nil), v...)
				}
			case ndaLLAddr:
				if len(v) == 6 {
					e.MAC = net.HardwareAddr(v).String()
				}
			}
			aoff += alignUp(alen)
		}
		out = append(out, e)
	}
	return out, false, nil
}

// KeepIfIndex 只留属于 ifindex 的表项(内核 dump 回的是全部网卡)。
func KeepIfIndex(es []Entry, ifindex int) []Entry {
	var out []Entry
	for _, e := range es {
		if e.IfIndex == ifindex {
			out = append(out, e)
		}
	}
	return out
}

func alignUp(v int) int { return (v + nlMsgAlign - 1) &^ (nlMsgAlign - 1) }

// buildDumpReq RTM_GETNEIGH dump 请求(nlmsghdr + ndmsg, family 填好)。
func buildDumpReq(family, ifindex int) []byte {
	req := make([]byte, nlMsgHdrLen+sizeofNdMsg)
	le := binary.LittleEndian
	le.PutUint32(req[0:4], uint32(len(req)))
	le.PutUint16(req[4:6], rtmGetNeigh)
	le.PutUint16(req[6:8], nlmFRequest|nlmFDump)
	le.PutUint32(req[8:12], 1) // seq
	req[nlMsgHdrLen] = byte(family)
	le.PutUint32(req[nlMsgHdrLen+4:nlMsgHdrLen+8], uint32(int32(ifindex)))
	return req
}

// Dump 读全部网卡的邻居表(family = syscall.AF_INET / AF_INET6 / AF_UNSPEC)。
func Dump(family int) ([]Entry, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("neigh: socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("neigh: bind: %w", err)
	}
	if err := syscall.Sendto(fd, buildDumpReq(family, 0), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("neigh: send: %w", err)
	}
	var out []Entry
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("neigh: recv: %w", err)
		}
		if n <= 0 {
			return nil, errors.New("neigh: empty recv")
		}
		es, done, err := ParseMsgs(buf[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, es...)
		if done {
			return out, nil
		}
	}
}

// DumpIf 某网卡的 IPv4 邻居表(= /proc/net/arp 里该网卡的部分)。
func DumpIf(ifindex int) ([]Entry, error) {
	if ifindex <= 0 {
		return nil, errors.New("neigh: bad ifindex")
	}
	es, err := Dump(syscall.AF_INET)
	if err != nil {
		return nil, err
	}
	return KeepIfIndex(es, ifindex), nil
}

// Sub 邻居表事件订阅(RTNLGRP_NEIGH)。
type Sub struct{ fd int }

// Subscribe 订阅邻居表增删改事件。用完 Close。
func Subscribe() (*Sub, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("neigh: socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: rtmgrpNeigh}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("neigh: bind groups: %w", err)
	}
	return &Sub{fd: fd}, nil
}

// Read 阻塞读一批事件(RTM_DELNEIGH 的 Deleted=true)。
func (s *Sub) Read() ([]Entry, error) {
	buf := make([]byte, 1<<16)
	n, _, err := syscall.Recvfrom(s.fd, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("neigh: recv: %w", err)
	}
	es, _, err := ParseMsgs(buf[:n])
	return es, err
}

// Close 关闭订阅。
func (s *Sub) Close() error { return syscall.Close(s.fd) }
