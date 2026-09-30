// neigh_v6.go — v5.20 IPv6 邻居事件驱动的 v6 filter 同步
//
// 问题: IPv6 上行限速靠 ifb0 上的 u32 src 过滤器(ifb 在 netfilter 之前, 拿不到
// iptables 的 MAC mark), 过滤器由 bin/v6_sync.sh 按 `ip -6 neigh` 的地址逐条装。
// 客户端按 RFC 4941 轮换临时地址后, 新地址在下次周期同步(watchdog 每 60s)之前
// 完全不受上行限速。
//
// 方案(选 b: httpd 内的 Go netlink 监听, 而不是改 C 的 hotspotd):
//   - hotspotd 目前只处理 AF_INET 邻居, 要加 v6 需改 C + NDK 重编 + CI 重打二进制;
//     它的 netlink 回调是单线程主循环, 注释里明确"绝对不能阻塞"(否则 ENOBUFS 丢
//     设备上下线事件)——在里面 fork shell 去跑 tc 风险更高;
//   - httpd 已有同样模式的纯 Go netlink 订阅(ct_events.go, CGO_ENABLED=0), 能直接
//     读 rules.json / limit_policies.json 判断哪些 MAC 有规则, 失败只影响本功能,
//     退化为原来的 60s 周期同步(周期同步不变, 作为兜底对账)。
//
// 流程: 订阅 RTMGRP_NEIGH → 只看 AF_INET6 + 热点口 + REACHABLE/STALE/DELAY + 非
// fe80:: + MAC 有限速/拉黑/配额规则 → (MAC, 地址) 是新的才触发 → 500ms 固定窗口
// 合并 → 一次 `v6_sync.sh sync_macs <mac>...`(串行执行, 执行期间来的事件并入下一批)。
// 接收队列溢出(ENOBUFS)→ 请求一次全量 `v6_sync.sh sync`。
//
// 拉黑: ip6tables HNC_CTRL 里是 `-m mac --mac-source <mac> -j DROP`(+ TCP RESET),
// 与地址无关, 新地址天然被拦, 不依赖本同步(这里仍触发是为了限速过滤器)。
//
// 状态: run/v6_neigh.json(订阅是否在线、事件/触发/执行计数、最近一次执行结果)。

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	rtmgrpNeigh        = 0x4 // RTMGRP_NEIGH
	ndaDst             = 1   // NDA_DST
	ndaLLAddr          = 2   // NDA_LLADDR
	nudReachable       = 0x02
	nudStale           = 0x04
	nudDelay           = 0x08
	nudIncomplete      = 0x01
	nudFailed          = 0x20
	v6Debounce         = 500 * time.Millisecond
	v6KnownTTL         = 10 * time.Minute
	v6KnownMax         = 4096
	v6InterestTTL      = 2 * time.Second
	v6RunTimeout       = 30 * time.Second
	v6NeighRetry       = 60 * time.Second
	v6NeighRcvBuf      = 1 << 20
	v6IfindexRefresh   = 5 * time.Second
	v6StatusWriteEvery = 30 * time.Second
)

// neighEvent 解析后的一条邻居消息
type neighEvent struct {
	Del     bool
	Family  uint8
	Ifindex int
	State   uint16
	IP      net.IP
	MAC     string
}

// parseNeighMsg 解析 RTM_NEWNEIGH / RTM_DELNEIGH 的消息体(nlmsghdr 之后):
// struct ndmsg { u8 family; u8 pad1; u16 pad2; s32 ifindex; u16 state; u8 flags; u8 type; } + rtattr
func parseNeighMsg(msgType uint16, b []byte) (neighEvent, bool) {
	if msgType != syscall.RTM_NEWNEIGH && msgType != syscall.RTM_DELNEIGH {
		return neighEvent{}, false
	}
	if len(b) < 12 {
		return neighEvent{}, false
	}
	ev := neighEvent{
		Del:     msgType == syscall.RTM_DELNEIGH,
		Family:  b[0],
		Ifindex: int(int32(binary.LittleEndian.Uint32(b[4:8]))),
		State:   binary.LittleEndian.Uint16(b[8:10]),
	}
	nlAttrs(b[12:], func(t uint16, v []byte) {
		switch {
		case t == ndaDst && len(v) == 16:
			ev.IP = net.IP(append([]byte(nil), v...))
		case t == ndaDst && len(v) == 4:
			ev.IP = net.IP(append([]byte(nil), v...))
		case t == ndaLLAddr && len(v) == 6:
			ev.MAC = net.HardwareAddr(v).String()
		}
	})
	return ev, ev.IP != nil
}

// neighUsable 这条 v6 邻居是否是「设备正在用的全局地址」
func neighUsable(ev neighEvent) bool {
	if ev.Del || ev.Family != syscall.AF_INET6 || ev.IP.To4() != nil || ev.MAC == "" {
		return false
	}
	if ev.IP.IsLinkLocalUnicast() || ev.IP.IsMulticast() || ev.IP.IsUnspecified() || ev.IP.IsLoopback() {
		return false
	}
	return ev.State&(nudReachable|nudStale|nudDelay) != 0
}

// ─── 合并/去抖队列 ───────────────────────────────────────────────

// v6SyncQueue 把一段时间内的触发合并成一次执行; 执行串行, 执行期间的触发并入下一批。
// 固定窗口(从本批第一个触发起算 debounce), 不是滑动窗口 —— 事件风暴里延迟也有上界。
type v6SyncQueue struct {
	debounce time.Duration
	run      func(full bool, macs []string)

	mu      sync.Mutex
	pending map[string]bool
	full    bool
	kick    chan struct{}
}

func newV6SyncQueue(debounce time.Duration, run func(full bool, macs []string)) *v6SyncQueue {
	return &v6SyncQueue{debounce: debounce, run: run, pending: map[string]bool{}, kick: make(chan struct{}, 1)}
}

func (q *v6SyncQueue) signal() {
	select {
	case q.kick <- struct{}{}:
	default:
	}
}

// Add 请求同步一台设备
func (q *v6SyncQueue) Add(mac string) {
	q.mu.Lock()
	q.pending[strings.ToLower(mac)] = true
	q.mu.Unlock()
	q.signal()
}

// AddFull 请求一次全量同步(丢事件后)
func (q *v6SyncQueue) AddFull() {
	q.mu.Lock()
	q.full = true
	q.mu.Unlock()
	q.signal()
}

func (q *v6SyncQueue) take() (bool, []string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	full := q.full
	macs := make([]string, 0, len(q.pending))
	for m := range q.pending {
		macs = append(macs, m)
	}
	sort.Strings(macs)
	q.pending, q.full = map[string]bool{}, false
	return full, macs
}

// Loop 运行到 stop 关闭
func (q *v6SyncQueue) Loop(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-q.kick:
		}
		t := time.NewTimer(q.debounce)
	wait:
		for {
			select {
			case <-stop:
				t.Stop()
				return
			case <-q.kick: // 同一窗口内的触发: 已在 pending 里, 不延长窗口
			case <-t.C:
				break wait
			}
		}
		full, macs := q.take()
		if !full && len(macs) == 0 {
			continue
		}
		q.run(full, macs)
	}
}

// ─── 事件过滤(有规则的 MAC、新地址才触发)──────────────────────

type v6NeighFilter struct {
	hncDir string
	now    func() time.Time // 单调比较用(time.Now 带 monotonic)
	iface  func() string

	mu         sync.Mutex
	known      map[string]time.Time // "mac|ip" → 最近一次触发
	interest   map[string]bool
	interestAt time.Time
	ifName     string
	ifIndex    int
	ifAt       time.Time
	// 测试注入
	interestFn func() map[string]bool
	ifindexFn  func(name string) int
}

func newV6NeighFilter(hncDir string, iface func() string) *v6NeighFilter {
	return &v6NeighFilter{hncDir: hncDir, now: time.Now, iface: iface, known: map[string]time.Time{}}
}

// v6InterestMACs 有限速 / 拉黑 / 配额或分时段策略的 MAC(小写)
func v6InterestMACs(hncDir string) map[string]bool {
	out := map[string]bool{}
	if obs, _, ok := readObserved(hncDir); ok {
		for mac, r := range obs {
			if r.DownKbit > 0 || r.UpKbit > 0 || r.Blocked {
				out[mac] = true
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(hncDir, "data", "limit_policies.json")); err == nil {
		var pf policyFile
		if json.Unmarshal(b, &pf) == nil {
			for mac, p := range pf.Devices {
				if p != nil && (p.Quota != nil || len(p.Schedule) > 0) {
					out[strings.ToLower(mac)] = true
				}
			}
		}
	}
	// 已有 v6 快照的设备(v6_sync 正在为它维护过滤器)也算
	if ents, err := os.ReadDir(filepath.Join(hncDir, "run", "v6")); err == nil {
		for _, e := range ents {
			if n := strings.ToLower(e.Name()); validMAC(n) {
				out[n] = true
			}
		}
	}
	return out
}

func sysIfindex(name string) int {
	b, err := os.ReadFile(filepath.Join("/sys/class/net", name, "ifindex"))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func (f *v6NeighFilter) hotspotIfindexLocked(now time.Time) int {
	if f.ifAt.IsZero() || now.Sub(f.ifAt) >= v6IfindexRefresh || now.Before(f.ifAt) {
		name := ""
		if f.iface != nil {
			name = f.iface()
		}
		idx := 0
		if name != "" {
			if f.ifindexFn != nil {
				idx = f.ifindexFn(name)
			} else {
				idx = sysIfindex(name)
			}
		}
		if name != f.ifName || idx != f.ifIndex {
			f.known = map[string]time.Time{} // 热点口换了: 地址记录作废
		}
		f.ifName, f.ifIndex, f.ifAt = name, idx, now
	}
	return f.ifIndex
}

func (f *v6NeighFilter) interestLocked(now time.Time) map[string]bool {
	if f.interest == nil || now.Sub(f.interestAt) >= v6InterestTTL || now.Before(f.interestAt) {
		if f.interestFn != nil {
			f.interest = f.interestFn()
		} else {
			f.interest = v6InterestMACs(f.hncDir)
		}
		f.interestAt = now
	}
	return f.interest
}

// Handle 处理一条邻居事件; 返回需要触发同步的 MAC(空串 = 不触发)
func (f *v6NeighFilter) Handle(ev neighEvent) string {
	if ev.Family != syscall.AF_INET6 || ev.IP == nil {
		return ""
	}
	now := f.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := f.hotspotIfindexLocked(now)
	if idx == 0 || ev.Ifindex != idx {
		return ""
	}
	key := strings.ToLower(ev.MAC) + "|" + ev.IP.String()
	if !neighUsable(ev) {
		// 删除 / FAILED / INCOMPLETE: 忘掉这条, 地址再出现时重新触发
		if ev.Del || ev.State&(nudFailed|nudIncomplete) != 0 {
			if ev.MAC != "" {
				delete(f.known, key)
			} else {
				ip := "|" + ev.IP.String()
				for k := range f.known {
					if strings.HasSuffix(k, ip) {
						delete(f.known, k)
					}
				}
			}
		}
		return ""
	}
	mac := strings.ToLower(ev.MAC)
	if !f.interestLocked(now)[mac] {
		return ""
	}
	if t, ok := f.known[key]; ok && now.Sub(t) < v6KnownTTL && !now.Before(t) {
		return "" // 已同步过的地址: REACHABLE↔STALE 来回切换不重复触发
	}
	if len(f.known) >= v6KnownMax {
		for k, t := range f.known {
			if now.Sub(t) >= v6KnownTTL || now.Before(t) {
				delete(f.known, k)
			}
		}
		if len(f.known) >= v6KnownMax {
			f.known = map[string]time.Time{}
		}
	}
	f.known[key] = now
	return mac
}

// ─── 状态 / 执行 ─────────────────────────────────────────────────

var v6NeighStat struct {
	mu        sync.Mutex
	Active    bool   `json:"active"`
	Err       string `json:"err,omitempty"`
	Events    uint64 `json:"events"`
	Triggers  uint64 `json:"triggers"`
	Runs      uint64 `json:"runs"`
	FullRuns  uint64 `json:"full_runs"`
	Lost      uint64 `json:"lost"`
	LastRunAt int64  `json:"last_run_at,omitempty"`
	LastMACs  string `json:"last_macs,omitempty"`
	LastRC    int    `json:"last_rc"`
	LastMs    int64  `json:"last_ms,omitempty"`
	writtenAt time.Time
}

func v6NeighStatWrite(hncDir string, force bool) {
	v6NeighStat.mu.Lock()
	defer v6NeighStat.mu.Unlock()
	now := time.Now()
	if !force && now.Sub(v6NeighStat.writtenAt) < v6StatusWriteEvery {
		return
	}
	v6NeighStat.writtenAt = now
	b, err := json.Marshal(map[string]interface{}{
		"active": v6NeighStat.Active, "err": v6NeighStat.Err, "events": v6NeighStat.Events,
		"triggers": v6NeighStat.Triggers, "runs": v6NeighStat.Runs, "full_runs": v6NeighStat.FullRuns,
		"lost": v6NeighStat.Lost, "last_run_at": v6NeighStat.LastRunAt, "last_macs": v6NeighStat.LastMACs,
		"last_rc": v6NeighStat.LastRC, "last_ms": v6NeighStat.LastMs, "debounce_ms": v6Debounce.Milliseconds(),
		"updated": now.Unix(),
	})
	if err == nil {
		_ = discoverWriteAtomic(filepath.Join(hncDir, "run", "v6_neigh.json"), b)
	}
}

// runV6SyncScript 执行 v6_sync.sh(全量: sync; 否则 sync_macs <mac>...)
func runV6SyncScript(hncDir string, full bool, macs []string) {
	args := []string{hncDir + "/bin/v6_sync.sh"}
	if full {
		args = append(args, "sync")
	} else {
		args = append(args, "sync_macs")
		args = append(args, macs...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), v6RunTimeout)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, "sh", args...))
	cmd.Env = []string{
		"HNC_DIR=" + hncDir,
		"HNC=" + hncDir,
		"PATH=/system/bin:/system/xbin:/vendor/bin:/usr/bin:/bin",
	}
	cmd.Stdout, cmd.Stderr = nil, nil // /dev/null: 脚本日志自己写 logs/v6_sync.log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	start := time.Now()
	err := cmd.Run()
	rc := 0
	if err != nil {
		rc = -1
		var ee *exec.ExitError
		if ctx.Err() == context.DeadlineExceeded {
			rc = 124
		} else if errors.As(err, &ee) {
			rc = ee.ExitCode()
		}
		log.Printf("v6neigh: v6_sync.sh %v rc=%d: %v", args[1:], rc, err)
	}
	v6NeighStat.mu.Lock()
	v6NeighStat.Runs++
	if full {
		v6NeighStat.FullRuns++
	}
	v6NeighStat.LastRunAt = start.Unix()
	v6NeighStat.LastMACs = strings.Join(macs, " ")
	if full {
		v6NeighStat.LastMACs = "*"
	}
	v6NeighStat.LastRC = rc
	v6NeighStat.LastMs = time.Since(start).Milliseconds()
	v6NeighStat.mu.Unlock()
	v6NeighStatWrite(hncDir, false)
}

func v6NeighSetState(hncDir string, active bool, errStr string) {
	v6NeighStat.mu.Lock()
	changed := v6NeighStat.Active != active || v6NeighStat.Err != errStr
	v6NeighStat.Active, v6NeighStat.Err = active, errStr
	v6NeighStat.mu.Unlock()
	v6NeighStatWrite(hncDir, changed)
}

func openNeighSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: rtmgrpNeigh}); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}
	if syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, v6NeighRcvBuf) != nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, v6NeighRcvBuf)
	}
	tv := syscall.Timeval{Sec: 1}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	return fd, nil
}

// V6NeighLoop 订阅邻居事件并驱动 v6 同步; 订阅失败每 60s 重试, 期间只有周期同步。
func (s *server) V6NeighLoop(stop <-chan struct{}) {
	if os.Getenv("HNC_V6_NEIGH_DISABLE") == "1" {
		v6NeighSetState(s.hncDir, false, "disabled by HNC_V6_NEIGH_DISABLE")
		return
	}
	q := newV6SyncQueue(v6Debounce, func(full bool, macs []string) { runV6SyncScript(s.hncDir, full, macs) })
	go q.Loop(stop)
	filter := newV6NeighFilter(s.hncDir, s.currentHotspotIface)
	buf := make([]byte, 64*1024)
	for {
		fd, err := openNeighSocket()
		if err != nil {
			v6NeighSetState(s.hncDir, false, err.Error())
			log.Printf("v6neigh: neighbor events unavailable (%v), periodic v6 sync only", err)
			select {
			case <-stop:
				return
			case <-time.After(v6NeighRetry):
				continue
			}
		}
		v6NeighSetState(s.hncDir, true, "")
		log.Printf("v6neigh: subscribed to RTMGRP_NEIGH (event-driven IPv6 filter sync, debounce %s)", v6Debounce)
		failed := false
		for !failed {
			select {
			case <-stop:
				_ = syscall.Close(fd)
				return
			default:
			}
			n, _, rerr := syscall.Recvfrom(fd, buf, 0)
			if rerr != nil {
				switch rerr {
				case syscall.EAGAIN, syscall.EINTR:
					continue
				case syscall.ENOBUFS:
					// 内核丢了事件: 不知道漏了哪些地址 → 全量同步一次
					v6NeighStat.mu.Lock()
					v6NeighStat.Lost++
					v6NeighStat.mu.Unlock()
					q.AddFull()
					continue
				}
				v6NeighSetState(s.hncDir, false, rerr.Error())
				log.Printf("v6neigh: recv: %v, resubscribing in %s", rerr, v6NeighRetry)
				failed = true
				continue
			}
			msgs, perr := syscall.ParseNetlinkMessage(buf[:n])
			if perr != nil {
				continue
			}
			for _, m := range msgs {
				ev, ok := parseNeighMsg(m.Header.Type, m.Data)
				if !ok || ev.Family != syscall.AF_INET6 {
					continue
				}
				v6NeighStat.mu.Lock()
				v6NeighStat.Events++
				v6NeighStat.mu.Unlock()
				if mac := filter.Handle(ev); mac != "" {
					v6NeighStat.mu.Lock()
					v6NeighStat.Triggers++
					v6NeighStat.mu.Unlock()
					q.Add(mac)
				}
			}
		}
		_ = syscall.Close(fd)
		select {
		case <-stop:
			return
		case <-time.After(v6NeighRetry):
		}
	}
}
