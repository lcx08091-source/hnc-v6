// ct_new_events.go — v5.21 conntrack NEW 事件(连接建立的精确时间)
//
// 用途: traffic_ident.go 的「共现推断」要知道同一台设备的两条连接是不是在 ±5 秒内
// 先后建立的。/proc 轮询只有 10 秒粒度(只知道「这一轮新出现」), 订阅
// NFNLGRP_CONNTRACK_NEW 后能拿到每条连接被内核确认的时刻(误差 < 1 秒)。
//
// 与 ct_events.go(DESTROY)分开用独立 socket: NEW 事件量更大, 接收队列溢出只影响
// 这里(退回 10 秒粒度), 不会让按应用流量的「精确模式」掉成 precise=false。
// 失败(无 CONFIG_NF_CONNTRACK_EVENTS / SELinux)静默, 60 秒重试一次, 只记一次日志。
// 缓冲是 key → 首次时间的 map, 上限 ctNewMaxBuffered, 每 10 秒被 appUsageTick 取走。

package main

import (
	"errors"
	"log"
	"sync"
	"syscall"
	"time"
)

const (
	nfnlGrpConntrackNew = 1 // NFNLGRP_CONNTRACK_NEW
	ipctnlMsgCtNew      = 0 // IPCTNL_MSG_CT_NEW
	ctNewMaxBuffered    = 1 << 15
	ctNewRcvBuf         = 2 << 20
)

var ctNewEvents struct {
	mu     sync.Mutex
	buf    map[string]time.Time
	active bool
}

// parseCtNew 解析一条 IPCTNL_MSG_CT_NEW(属性布局与 DELETE 相同, 复用 parseCtDestroy)
func parseCtNew(msgType uint16, payload []byte, at time.Time) (ctDestroy, bool) {
	if msgType != nfnlSubsysCtnetlink<<8|ipctnlMsgCtNew {
		return ctDestroy{}, false
	}
	return parseCtDestroy(nfnlSubsysCtnetlink<<8|ipctnlMsgCtDelete, payload, at)
}

func ctNewPush(key string, at time.Time) {
	ctNewEvents.mu.Lock()
	if ctNewEvents.buf == nil {
		ctNewEvents.buf = map[string]time.Time{}
	}
	if _, ok := ctNewEvents.buf[key]; !ok && len(ctNewEvents.buf) < ctNewMaxBuffered {
		ctNewEvents.buf[key] = at
	}
	ctNewEvents.mu.Unlock()
}

// ctNewDrain 取走缓冲: key → 建立时间; 第二个返回值 = 订阅是否在线
func ctNewDrain() (map[string]time.Time, bool) {
	ctNewEvents.mu.Lock()
	defer ctNewEvents.mu.Unlock()
	m := ctNewEvents.buf
	ctNewEvents.buf = nil
	return m, ctNewEvents.active
}

func ctNewSetActive(v bool) {
	ctNewEvents.mu.Lock()
	ctNewEvents.active = v
	if !v {
		ctNewEvents.buf = nil
	}
	ctNewEvents.mu.Unlock()
}

func openCtNewSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, nlNetfilter)
	if err != nil {
		return -1, err
	}
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1 << (nfnlGrpConntrackNew - 1)}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	if syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, ctNewRcvBuf) != nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, ctNewRcvBuf)
	}
	tv := syscall.Timeval{Sec: 1}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	return fd, nil
}

// CtNewEventLoop 后台订阅 conntrack NEW 事件(失败每 60s 重试)
func (s *server) CtNewEventLoop(stop <-chan struct{}) {
	buf := make([]byte, 256*1024)
	lastErr := ""
	for {
		fd, err := openCtNewSocket()
		if err != nil {
			ctNewSetActive(false)
			if err.Error() != lastErr {
				lastErr = err.Error()
				log.Printf("ident: conntrack NEW events unavailable (%v), co-occurrence uses 10s poll granularity", err)
			}
			select {
			case <-stop:
				return
			case <-time.After(ctEventRetryAfterFailure):
				continue
			}
		}
		ctNewSetActive(true)
		lastErr = ""
		fatal := false
		for !fatal {
			select {
			case <-stop:
				_ = syscall.Close(fd)
				ctNewSetActive(false)
				return
			default:
			}
			n, _, rerr := syscall.Recvfrom(fd, buf, 0)
			now := time.Now()
			if rerr != nil {
				switch {
				case errors.Is(rerr, syscall.EAGAIN), errors.Is(rerr, syscall.EINTR), errors.Is(rerr, syscall.ENOBUFS):
					continue // 溢出只丢这批事件: 那些连接退回 10 秒粒度
				default:
					fatal = true
					continue
				}
			}
			msgs, perr := syscall.ParseNetlinkMessage(buf[:n])
			if perr != nil {
				continue
			}
			for _, m := range msgs {
				if ev, ok := parseCtNew(m.Header.Type, m.Data, now); ok {
					ctNewPush(ev.Key, now)
				}
			}
		}
		_ = syscall.Close(fd)
		ctNewSetActive(false)
		select {
		case <-stop:
			return
		case <-time.After(5 * time.Second):
		}
	}
}
