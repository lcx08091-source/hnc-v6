// ct_events.go — conntrack DESTROY 事件订阅(按应用流量「精确模式」)
//
// 为什么: app_usage.go 每 10 秒读一次 /proc/net/nf_conntrack 做字节差分, 两类字节
// 会丢: (1) 两次采样之间开始又结束的短连接; (2) 连接结束前最后不到 10 秒的尾巴。
// 内核在连接销毁时会向 NFNLGRP_CONNTRACK_DESTROY 组广播一条 IPCTNL_MSG_CT_DELETE,
// 其中带最终累计计数器(CTA_COUNTERS_ORIG / CTA_COUNTERS_REPLY, 需要
// nf_conntrack_acct=1 —— conntrackSnapshot 首次调用时已尝试打开)。
// 拿到它: 最终字节 − 上次快照字节 = 丢掉的尾巴; 从没在快照里出现过的连接 = 全部字节。
//
// 实现: 纯 Go(标准库 syscall 的 AF_NETLINK/NETLINK_NETFILTER 原始 socket), 不用 cgo,
// CGO_ENABLED=0 GOOS=android GOARCH=arm64 可直接编。订阅失败(无权限 / 内核没编
// CONFIG_NF_CONNTRACK_EVENTS / SELinux 拒绝)时静默退回原来的纯轮询, API 里
// precise=false。事件只做缓冲, 记账统一在 appUsageTick 里做(同一把锁, 同一份
// 设备/应用归属), 避免与轮询差分交叉重复计数 —— 规则见 appUsageAcctStep。
//
// 丢事件: socket 接收队列溢出(ENOBUFS)时内核会丢广播, 此时记一次 lost, 当轮之后
// 退化为轮询口径(仍不会重复计数, 只是可能少算), precise 置 false 直到下个干净周期。

package main

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

// netlink / nfnetlink 常量(字面量, 与 linux uapi 一致; syscall 包未全部导出)
const (
	nlNetfilter              = 12     // NETLINK_NETFILTER
	nfnlGrpConntrackDestroy  = 3      // NFNLGRP_CONNTRACK_DESTROY
	nfnlSubsysCtnetlink      = 1      // NFNL_SUBSYS_CTNETLINK
	ipctnlMsgCtDelete        = 2      // IPCTNL_MSG_CT_DELETE
	nlaFNested               = 0x8000 // NLA_F_NESTED
	nlaFNetByteorder         = 0x4000 // NLA_F_NET_BYTEORDER
	nlaTypeMask              = ^uint16(nlaFNested | nlaFNetByteorder)
	ctaTupleOrig             = 1
	ctaCountersOrig          = 9
	ctaCountersReply         = 10
	ctaTupleIP               = 1
	ctaTupleProto            = 2
	ctaIPv4Src               = 1
	ctaIPv4Dst               = 2
	ctaIPv6Src               = 3
	ctaIPv6Dst               = 4
	ctaProtoNum              = 1
	ctaProtoSrcPort          = 2
	ctaProtoDstPort          = 3
	ctaCountersBytes         = 2
	ctaCounters32Bytes       = 4 // 老内核的 32 位计数器
	ctEventMaxBuffered       = 1 << 16
	ctEventRcvBuf            = 4 << 20
	ctEventRetryAfterFailure = 60 * time.Second
)

// ctDestroy 一条连接销毁事件(原方向五元组 + 最终双向字节)
type ctDestroy struct {
	Key    string // 与 ctEntry.key() 同格式
	Src    string
	Dst    string
	UpB    uint64
	DnB    uint64
	HasCnt bool      // 事件里带计数器(acct 开着)
	At     time.Time // 收到事件的时间(用于判断快照是否已过期)
}

var ctEvents struct {
	mu      sync.Mutex
	buf     []ctDestroy
	active  bool // 订阅成功且在收
	lost    bool // 自上次 drain 以来发生过丢事件/缓冲溢出
	lastErr string
	// v5.21: 给 /api/stats_health 的累计计数(进程内单调递增, 不随 drain 清零)
	received uint64
	lostN    uint64
}

// ctProtoName 协议号 → /proc/net/nf_conntrack 里的 l4 名字(key 必须对得上)
func ctProtoName(n uint8) string {
	switch n {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 33:
		return "dccp"
	case 47:
		return "gre"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	case 136:
		return "udplite"
	}
	return "unknown"
}

// nlAttrs 遍历一段 netlink 属性, 回调 (type, payload)
func nlAttrs(b []byte, fn func(t uint16, v []byte)) {
	for len(b) >= 4 {
		l := int(binary.LittleEndian.Uint16(b[0:2]))
		t := binary.LittleEndian.Uint16(b[2:4]) & nlaTypeMask
		if l < 4 || l > len(b) {
			return
		}
		fn(t, b[4:l])
		al := (l + 3) &^ 3
		if al > len(b) {
			return
		}
		b = b[al:]
	}
}

// parseCtDestroy 解析一条 nfnetlink conntrack 消息体(nlmsghdr 之后的部分:
// nfgenmsg(4B) + 属性)。只接受 IPCTNL_MSG_CT_DELETE; 其余返回 false。
func parseCtDestroy(msgType uint16, payload []byte, at time.Time) (ctDestroy, bool) {
	if msgType != nfnlSubsysCtnetlink<<8|ipctnlMsgCtDelete || len(payload) < 4 {
		return ctDestroy{}, false
	}
	ev := ctDestroy{At: at}
	var proto uint8
	var sport, dport uint16
	var src, dst net.IP
	readCounters := func(v []byte) (uint64, bool) {
		var n uint64
		ok := false
		nlAttrs(v, func(t uint16, x []byte) {
			switch {
			case t == ctaCountersBytes && len(x) >= 8:
				n, ok = binary.BigEndian.Uint64(x[:8]), true
			case t == ctaCounters32Bytes && len(x) >= 4 && !ok:
				n, ok = uint64(binary.BigEndian.Uint32(x[:4])), true
			}
		})
		return n, ok
	}
	nlAttrs(payload[4:], func(t uint16, v []byte) {
		switch t {
		case ctaTupleOrig:
			nlAttrs(v, func(t2 uint16, v2 []byte) {
				switch t2 {
				case ctaTupleIP:
					nlAttrs(v2, func(t3 uint16, v3 []byte) {
						switch {
						case t3 == ctaIPv4Src && len(v3) >= 4:
							src = net.IP(append([]byte(nil), v3[:4]...))
						case t3 == ctaIPv4Dst && len(v3) >= 4:
							dst = net.IP(append([]byte(nil), v3[:4]...))
						case t3 == ctaIPv6Src && len(v3) >= 16:
							src = net.IP(append([]byte(nil), v3[:16]...))
						case t3 == ctaIPv6Dst && len(v3) >= 16:
							dst = net.IP(append([]byte(nil), v3[:16]...))
						}
					})
				case ctaTupleProto:
					nlAttrs(v2, func(t3 uint16, v3 []byte) {
						switch {
						case t3 == ctaProtoNum && len(v3) >= 1:
							proto = v3[0]
						case t3 == ctaProtoSrcPort && len(v3) >= 2:
							sport = binary.BigEndian.Uint16(v3[:2])
						case t3 == ctaProtoDstPort && len(v3) >= 2:
							dport = binary.BigEndian.Uint16(v3[:2])
						}
					})
				}
			})
		case ctaCountersOrig:
			if n, ok := readCounters(v); ok {
				ev.UpB, ev.HasCnt = n, true
			}
		case ctaCountersReply:
			if n, ok := readCounters(v); ok {
				ev.DnB, ev.HasCnt = n, true
			}
		}
	})
	if src == nil || dst == nil {
		return ctDestroy{}, false
	}
	ev.Src, ev.Dst = src.String(), dst.String()
	e := ctEntry{Proto: ctProtoName(proto), Src: ev.Src, Dst: ev.Dst, Sport: int(sport), Dport: int(dport)}
	ev.Key = e.key()
	return ev, true
}

// ctEventsDrain 取走缓冲的事件; 返回 (事件, 订阅是否在线, 本周期是否丢过)
func ctEventsDrain() ([]ctDestroy, bool, bool) {
	ctEvents.mu.Lock()
	defer ctEvents.mu.Unlock()
	evs := ctEvents.buf
	ctEvents.buf = nil
	lost := ctEvents.lost
	ctEvents.lost = false
	return evs, ctEvents.active, lost
}

// ctEventsPrecise 给 API 用: 订阅在线即精确模式
func ctEventsPrecise() bool {
	ctEvents.mu.Lock()
	defer ctEvents.mu.Unlock()
	return ctEvents.active
}

func ctEventsPush(ev ctDestroy) {
	ctEvents.mu.Lock()
	ctEvents.received++
	if len(ctEvents.buf) >= ctEventMaxBuffered {
		ctEvents.lost = true // appUsageTick 长时间没 drain(不应发生), 丢弃并标记
		ctEvents.lostN++
	} else {
		ctEvents.buf = append(ctEvents.buf, ev)
	}
	ctEvents.mu.Unlock()
}

func ctEventsSetState(active bool, errStr string) {
	ctEvents.mu.Lock()
	ctEvents.active = active
	if errStr != "" {
		ctEvents.lastErr = errStr
	}
	if !active {
		ctEvents.buf = nil
	}
	ctEvents.mu.Unlock()
}

// openCtDestroySocket 打开并订阅 DESTROY 组; 设置 1s 接收超时以便响应 stop
func openCtDestroySocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, nlNetfilter)
	if err != nil {
		return -1, err
	}
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1 << (nfnlGrpConntrackDestroy - 1)}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	// 大接收缓冲: 下载高峰短连接销毁风暴时减少 ENOBUFS。FORCE 需 CAP_NET_ADMIN, 失败退普通。
	if syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, ctEventRcvBuf) != nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, ctEventRcvBuf)
	}
	tv := syscall.Timeval{Sec: 1}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	return fd, nil
}

// CtEventLoop 后台订阅 conntrack 销毁事件; 失败则每 60s 重试一次(便宜), 期间
// app_usage 自动走纯轮询。
func (s *server) CtEventLoop(stop <-chan struct{}) {
	buf := make([]byte, 256*1024)
	lastErr := ""
	for {
		fd, err := openCtDestroySocket()
		if err != nil {
			ctEventsSetState(false, err.Error())
			// v5.20: 老内核(无 CONFIG_NF_CONNTRACK_EVENTS / nfnetlink)每 60s 重试都失败,
			// 只在首次与错误变化时记一行, 不再每天刷 1440 行。
			if err.Error() != lastErr {
				lastErr = err.Error()
				log.Printf("app_usage: conntrack destroy events unavailable (%v), polling only (retry every %s, logged once)", err, ctEventRetryAfterFailure)
			}
			select {
			case <-stop:
				return
			case <-time.After(ctEventRetryAfterFailure):
				continue
			}
		}
		ctEventsSetState(true, "")
		lastErr = ""
		fatal := false
		for !fatal {
			select {
			case <-stop:
				_ = syscall.Close(fd)
				ctEventsSetState(false, "")
				return
			default:
			}
			n, _, rerr := syscall.Recvfrom(fd, buf, 0)
			now := time.Now()
			if rerr != nil {
				switch {
				case errors.Is(rerr, syscall.EAGAIN), errors.Is(rerr, syscall.EINTR):
					continue
				case errors.Is(rerr, syscall.ENOBUFS):
					ctEvents.mu.Lock()
					ctEvents.lost = true
					ctEvents.lostN++
					ctEvents.mu.Unlock()
					continue
				default:
					log.Printf("app_usage: conntrack event recv: %v, resubscribing", rerr)
					fatal = true
					continue
				}
			}
			msgs, perr := syscall.ParseNetlinkMessage(buf[:n])
			if perr != nil {
				continue
			}
			for _, m := range msgs {
				if ev, ok := parseCtDestroy(m.Header.Type, m.Data, now); ok {
					ctEventsPush(ev)
				}
			}
		}
		_ = syscall.Close(fd)
		ctEventsSetState(false, "recv error")
		select {
		case <-stop:
			return
		case <-time.After(5 * time.Second):
		}
	}
}
