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
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
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

	ndaDst       = 1 // NDA_DST
	ndaLLAddr    = 2 // NDA_LLADDR
	ndaCacheinfo = 3 // NDA_CACHEINFO: struct nda_cacheinfo{confirmed, used, updated, refcnt} (u32, clock_t, 距今)

	// userHZ clock_t 的单位(Linux / Android 的 USER_HZ 都是 100)。只用来比新旧, 差一点无所谓。
	userHZTick = 10 * time.Millisecond

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
	// ConfirmedAgo 距内核最近一次确认它可达多久(NDA_CACHEINFO.ndm_confirmed; 没有该属性为 0)。
	// v5.31 审查: 同一 MAC 换 IP 后新旧两条都是 STALE 时, 靠它分新旧。
	ConfirmedAgo time.Duration
	UpdatedAgo   time.Duration
	HasCacheInfo bool
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
			case ndaCacheinfo:
				if len(v) >= 16 {
					e.HasCacheInfo = true
					if c := int32(le.Uint32(v[0:4])); c > 0 {
						e.ConfirmedAgo = time.Duration(c) * userHZTick
					}
					if u := int32(le.Uint32(v[8:12])); u > 0 {
						e.UpdatedAgo = time.Duration(u) * userHZTick
					}
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
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 3})
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("neigh: bind: %w", err)
	}
	for {
		err := syscall.Sendto(fd, buildDumpReq(family, 0), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("neigh: send: %w", err)
		}
		break
	}
	var out []Entry
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
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

const (
	subRcvBufBytes = 512 << 10 // 512 KiB 接收缓冲, 降低突发 ARP/NDP 广播溢出概率
	subReadBufSize = 1 << 16   // 64 KiB 复用接收缓冲, 空闲零超时轮询、零堆内存分配
)

// Sub 邻居表事件订阅(RTNLGRP_NEIGH)。
// 经 os.NewFile + SyscallConn 托管给 Go runtime netpoll(internal/poll.fdMutex 引用计数锁):
// 空闲期 0 次超时唤醒, Close 微秒级唤醒阻塞中的 Read, 100% 消除整数 FD 复用竞态。
// Read 由单协程顺序调用, Close 支持并发幂等调用; 结构体无 64 位原子字段, 32 位 ARM 安全。
type Sub struct {
	file      *os.File
	raw       syscall.RawConn
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
	buf       []byte
}

// Subscribe 订阅邻居表增删改事件。用完 Close。
func Subscribe() (*Sub, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("neigh: socket: %w", err)
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, subRcvBufBytes)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: rtmgrpNeigh}); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("neigh: bind groups: %w", err)
	}
	f := os.NewFile(uintptr(fd), "neigh-netlink")
	if f == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("neigh: os.NewFile returned nil")
	}
	if err := f.SetReadDeadline(time.Time{}); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("neigh: netpoll: %w", err)
	}
	raw, err := f.SyscallConn()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("neigh: syscallconn: %w", err)
	}
	return &Sub{
		file: f,
		raw:  raw,
		buf:  make([]byte, subReadBufSize),
	}, nil
}

// Read 读一批事件(RTM_DELNEIGH 的 Deleted=true)。
// 经 netpoll 挂起等待可读事件; 信号中断(EINTR)返回 nil, nil; 已关闭或 EBADF 返回 os.ErrClosed;
// 内核接收缓冲溢出(ENOBUFS)原样包装返回供上层 errors.Is 识别。
func (s *Sub) Read() ([]Entry, error) {
	if s == nil || s.raw == nil || s.closed.Load() || len(s.buf) == 0 {
		return nil, os.ErrClosed
	}
	var (
		n       int
		recvErr error
	)
	rerr := s.raw.Read(func(fd uintptr) bool {
		n, _, recvErr = syscall.Recvfrom(int(fd), s.buf, 0)
		if errors.Is(recvErr, syscall.EAGAIN) || errors.Is(recvErr, syscall.EWOULDBLOCK) {
			recvErr = nil
			return false
		}
		if errors.Is(recvErr, syscall.EINTR) {
			recvErr = nil
			n = 0
			return true
		}
		return true
	})
	if s.closed.Load() || errors.Is(rerr, os.ErrClosed) || errors.Is(rerr, net.ErrClosed) || errors.Is(recvErr, syscall.EBADF) {
		return nil, os.ErrClosed
	}
	if rerr != nil {
		return nil, fmt.Errorf("neigh: rawconn: %w", rerr)
	}
	if recvErr != nil {
		return nil, fmt.Errorf("neigh: recv: %w", recvErr)
	}
	if n <= 0 {
		return nil, nil
	}
	es, _, err := ParseMsgs(s.buf[:n])
	return es, err
}

// Close 幂等关闭订阅, 由 sync.Once + os.File fdMutex 序列化底层关闭并微秒级唤醒阻塞中的 Read。
func (s *Sub) Close() error {
	if s == nil {
		return nil
	}
	s.closed.Store(true)
	s.closeOnce.Do(func() {
		if s.file != nil {
			if err := s.file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				s.closeErr = err
			}
		}
	})
	return s.closeErr
}
