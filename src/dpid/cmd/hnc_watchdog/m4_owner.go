// m4_owner.go — 设备发现写者(v5.31 迁移 M4 方案 A 起; v5.33 起唯一一份)。
//
// v5.31–v5.32 有两个写者: hotspotd(C)与本看门狗(Go), 开关 data/m4_owner 决定
// 谁写 data/devices.json, 另有影子比对(m4_shadow.go)和只写 run/devices.go.json 的
// 演练写者。v5.33 起 C 版发现删除(hotspotd 只剩硬件加速兜底和控制接口), 这里是唯一
// 的写者: 热点开着就跑, 关了就停。开关、切换、纠偏、影子、演练都已删; 旧版本留下的
// data/m4_owner / run/m4_owner.current / run/wd_m4_drill 不再读(post-fs-data 清掉)。
//
// 写节奏沿用 hotspotd rc30.9 的 sub-second de-bounce: 距上次写 ≥500ms 的首个事件
// 立即写; 否则等合并窗口(200ms 无新事件)或 30s 兜底; 距上次写 <200ms 硬限速不写。
// 内容没变不写(省电)。rx/tx 在写前经 `sh bin/iptables_manager.sh stats_all` 刷新
// (参数分开传, 3s 超时, 5s TTL), TTL 内沿用上一次的数字。
//
// v6.0 RC2 加固:
//   - 纯 Go 2s 进程组超时流式解析 iptables/ip6tables -nvxL HNC_STATS(兼容 legacy 9 列与
//     iptables-nft 8 列) + stats_v6_map / stats_v6_retired 聚合, 消灭每 5s 约 90 子进程风暴;
//   - writeDevicesAtomic 写完 data/devices.json 后同步原子写出 run/devices.flat;
//   - 生产默认 dumpIfFn 内置 SELinux AF_NETLINK 权限受限时的 /proc/net/arp 兜底, 主循环与
//     订阅重连遇权限错误退避 30s 并去重日志, 消灭 1Hz AVC 审计风暴;
//   - m4_go_write.log 封顶 256 KiB, 防止撑爆 32M tmpfs。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"hnc.io/dpid/devname"
	"hnc.io/dpid/devscan"
	"hnc.io/dpid/neigh"
)

const (
	m4WriteHardRateMS    = 200              // 距上次写 <200ms 永不写(rc30.9 硬限速)
	m4IdleTickMS         = 500              // v5.32 T4: 空闲(无 dirty/待解析名字/在途解析)时主循环 500ms 醒一次(REFRESH 要在 1 秒内响应)
	m4WriteIdleMS        = 500              // 空闲后首事件立即写(rc30.9)
	m4WriteMergeMS       = 200              // 合并窗口: 200ms 无新事件(rc30.9)
	m4WriteMaxDirtyMS    = 30000            // dirty 兜底 30s(rc30.9)
	m4StatsTTL           = 5 * time.Second  // 流量字节 5s TTL(C update_traffic_stats)
	m4StatsTimeout       = 3 * time.Second  // 脚本兜底超时 hnc_run_cmd_timeout(..., 3000)
	m4IptablesTimeout    = 2 * time.Second  // 纯 Go 单次 iptables/ip6tables 进程组硬超时
	m4FullSyncEvery      = 30 * time.Second // 全量 dump 兜底(WORK T1)
	m4NonceMax           = 64               // run/devices.refresh 里 nonce 的长度上限
	m4GoWriteLogMaxBytes = 256 << 10        // m4_go_write.log 256 KiB 封顶(防撑爆 32M tmpfs)
)

// 路径与策略做成变量(单测重定向到临时目录)。
var (
	m4DevicesJSON  = dataDir + "/devices.json"        // 输出(唯一写者)
	m4DevicesTmpGo = dataDir + "/devices.json.tmp.go" // 临时文件
	m4DevicesFlat  = runDir + "/devices.flat"         // 同步原子写出的三列纯文本(<mac>\t<ipv4>\t<iface>)
	// v5.31 T4 / v5.33: 「立刻扫一次」的请求与回执(见文件头)。
	m4RefreshFile    = runDir + "/devices.refresh"
	m4RefreshAckFile = runDir + "/devices.refresh.ack"
	// v5.31 T5: 写出日志(每写一行时间戳; 排查「谁在什么时候写了 devices.json」)。
	m4GoWriteLog = runDir + "/m4_go_write.log"

	// v5.31 T2 / v6.0 RC2: devname 解析用到的路径(devname.Resolver 的注入字段)。
	m4NamesPath     = dataDir + "/device_names.json"
	m4DevIDPath     = runDir + "/dpi_devid.json"
	m4CachePath     = dataDir + "/hostname_cache.json"
	m4OverridesPath = dataDir + "/oui_overrides.json"
	m4MDNSBin       = binDir + "/mdns_resolve"

	// 双栈 IPv6 流量归属与退役临时地址结转文件(由 ensure_stats_online 维护, 纯 Go 流量统计只读聚合)。
	m4StatsV6Map     = runDir + "/stats_v6_map"
	m4StatsV6Retired = runDir + "/stats_v6_retired"

	// SELinux 拦截 AF_NETLINK 时的 /proc/net/arp 兜底与退避参数。
	m4ProcNetARP      = "/proc/net/arp"
	m4NetlinkDumpIfFn = neigh.DumpIf
	m4PermErrBackoff  = 30 * time.Second

	m4ReconnectBaseBackoff = time.Second
	m4ReconnectMaxBackoff  = 30 * time.Second
	m4StopWaitMax          = 2500 * time.Millisecond
)

// 看门狗动作 / 自检可见(actionstats 带出)。
var (
	m4GoWrites     atomic.Uint64
	m4GoWriteFails atomic.Uint64
)

// m4WriterStats 供 actionstats.snapshot 带出(写出次数 / 失败次数)。
func m4WriterStats() (writes, fails uint64) {
	return m4GoWrites.Load(), m4GoWriteFails.Load()
}

// wdActionsM4WriterExtra actionstats.snapshot 带出的设备发现字段(测试可替换)。
var wdActionsM4WriterExtra = m4WriterStats

// ─── 写者生命周期 ──────────────────────────────────────────────────

type m4WriterMgr struct {
	mu     sync.Mutex
	runner *m4GoRunner
}

var (
	m4Writer          = &m4WriterMgr{}
	newM4RunnerFn     = newM4GoRunner
	m4WriteMu         sync.Mutex
	m4CurrentWriteGen uint64
	errM4StaleGen     = errors.New("m4_owner: stale runner generation")
)

func isWatchdogStopping() bool {
	select {
	case <-stopCh:
		return true
	default:
		return false
	}
}

// tick 主循环每轮调用(热点 ACTIVE 时 iface 非空): 起 / 换网卡重起 / 停写者并幂等归零在线态。
func (m *m4WriterMgr) tick(iface string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if iface == "" {
		m.stopGoRunnerWithModeLocked("热点未激活", true)
		clearOnlineDevicesIfNonEmpty()
		return
	}
	m.ensureGoRunnerLocked(iface)
}

// hotspotDown 热点没开(主循环探测失败 / PENDING / 退出)时调: 停写者并幂等归零非空在线态(待机已空则零写盘)。
func (m *m4WriterMgr) hotspotDown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	// 若看门狗自身收到信号退出(onExit)且热点仍处于 ACTIVE, 保留最后一次脏数据补写而不抹空在线态;
	// 其余所有关热点 / PENDING 路径均幂等归零非空在线态。
	clearOnline := !(isWatchdogStopping() && readState().kind == stateActive)
	m.stopGoRunnerWithModeLocked("热点未激活", clearOnline)
	if clearOnline {
		clearOnlineDevicesIfNonEmpty()
	}
}

// ─── Go 写者运行器 ────────────────────────────────────────────────

// m4NeighSource 订阅源(neigh.Sub 满足; 单测注入假实现)。
type m4NeighSource interface {
	Read() ([]neigh.Entry, error)
	Close() error
}

type m4GoRunner struct {
	// v5.32 T4: 主循环醒来次数(严格置于 offset 0 保 32 位 ARM 原子对齐)
	tickN atomic.Int64

	iface      string
	ifIdx      int
	stopCh     chan struct{}
	doneCh     chan struct{}
	stopCtx    context.Context
	stopCancel context.CancelFunc
	table      *devscan.Table

	// v5.31 T2: devname 全链解析(手动 → dpi_devid → DHCP → mDNS → 缓存 → 厂商 → MAC)。
	resolver *devname.Resolver

	// 名字解析钩子(测试注入; 生产在 newM4GoRunner 里由 resolver 提供)
	hooks struct {
		Fast func(mac string) (hostname, src string)
		Full func(mac, ip string) (hostname, src string)
	}

	// 注入点(单测替换)
	subscribeFn func() (m4NeighSource, error)
	dumpIfFn    func(int) ([]neigh.Entry, error)
	ifIndexFn   func(string) (int, error)
	statsCmdFn  func() (map[string][2]int64, error)
	statsFn     func() (map[string][2]int64, error) // 单测可选覆写钩子别名
	blacklistFn func() map[string]bool

	arpFallbackMu    sync.Mutex
	netlinkDenyUntil time.Time
	lastArpFallback  string

	// 新增字段一律置于结构体尾部(无 64 位原子字段, 严守 32 位 ARMv7 8 字节原子对齐铁律)
	atomicIfIdx atomic.Int32
	clearOnStop atomic.Bool
	stopMu      sync.Mutex
	writeGen    uint64
}

func m4NextTickMS(dirty, hasPending, resolving bool) time.Duration {
	if dirty || hasPending || resolving {
		return m4WriteHardRateMS * time.Millisecond
	}
	return m4IdleTickMS * time.Millisecond
}

// newM4GoRunner 生产构造: 真订阅 / 真 dump(含 /proc/net/arp 兜底) / 纯 Go 流量统计。
func newM4GoRunner(iface string) *m4GoRunner {
	stopCtx, stopCancel := context.WithCancel(context.Background())
	m4WriteMu.Lock()
	m4CurrentWriteGen++
	gen := m4CurrentWriteGen
	m4WriteMu.Unlock()
	r := &m4GoRunner{
		iface:      iface,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
		stopCtx:    stopCtx,
		stopCancel: stopCancel,
		writeGen:   gen,
	}
	r.subscribeFn = func() (m4NeighSource, error) { return neigh.Subscribe() }
	r.dumpIfFn = r.defaultDumpIf
	r.ifIndexFn = func(name string) (int, error) {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return 0, err
		}
		return ifi.Index, nil
	}
	r.statsCmdFn = r.collectStats
	r.blacklistFn = readBlacklist
	r.resolver = &devname.Resolver{
		NamesPath:     m4NamesPath,
		DevIDPath:     m4DevIDPath,
		CachePath:     m4CachePath,
		OverridesPath: m4OverridesPath,
		MDNSBin:       m4MDNSBin,
	}
	r.table = devscan.NewTable(iface, 0)
	r.applyHooks()
	return r
}

// applyHooks 名字解析钩子注入(T2: devname 全链; 测试可整体替换)。
func (r *m4GoRunner) applyHooks() {
	fast, full := r.hooks.Fast, r.hooks.Full
	if fast == nil && r.resolver != nil {
		res := r.resolver
		fast = func(mac string) (string, string) {
			if hn, ok := devname.LookupManual(mac, res.NamesPath); ok {
				return hn, "manual"
			}
			return devname.MACFallback(mac), "mac"
		}
	}
	if full == nil && r.resolver != nil {
		res := r.resolver
		ctx := r.stopCtx
		if ctx == nil {
			ctx = context.Background()
		}
		full = func(mac, ip string) (string, string) {
			return res.ResolveContext(ctx, mac, ip)
		}
	}
	if fast == nil {
		fast = func(mac string) (string, string) { return macFallback(mac), "mac" }
	}
	if full == nil {
		full = func(mac, ip string) (string, string) { return fast(mac) }
	}
	r.table.Fast = fast
	r.table.Full = full
	if r.table.Quiet == nil {
		r.table.Quiet = func() bool {
			s := actSnapshotFn()
			return s.OK && s.Quiet
		}
	}
}

func (r *m4GoRunner) start() {
	if r.ifIndexFn != nil {
		if idx, err := r.ifIndexFn(r.iface); err == nil {
			r.ifIdx = idx
		}
	}
	r.atomicIfIdx.Store(int32(r.ifIdx))
	r.table.SetIface(r.iface, r.ifIdx)
	go r.run()
}

// Stop 幂等停止运行器: 先调 stopCancel() 立即中断在途子进程与阻塞解析, 再关闭 stopCh。
func (r *m4GoRunner) Stop() {
	if r == nil {
		return
	}
	if r.stopCancel != nil {
		r.stopCancel()
	}
	r.stopMu.Lock()
	defer r.stopMu.Unlock()
	if r.stopCh != nil {
		select {
		case <-r.stopCh:
		default:
			close(r.stopCh)
		}
	}
}

func (m *m4WriterMgr) ensureGoRunnerLocked(iface string) {
	if m.runner != nil && m.runner.iface == iface {
		select {
		case <-m.runner.doneCh:
			// 旧写者已退出, 置空重建以恢复首屏与持续刷新
			m.runner = nil
		default:
			return
		}
	}
	m.stopGoRunnerWithModeLocked("网卡变了", false)
	r := newM4RunnerFn(iface)
	m.runner = r
	r.start()
}

func (m *m4WriterMgr) stopGoRunnerLocked(reason string) {
	m.stopGoRunnerWithModeLocked(reason, false)
}

func (m *m4WriterMgr) stopGoRunnerWithModeLocked(reason string, clearOnline bool) {
	if m.runner == nil {
		return
	}
	r := m.runner
	if clearOnline {
		r.clearOnStop.Store(true)
	}
	logf("m4_owner: 停 Go 写者(%s)", reason)
	r.Stop()
	tmr := time.NewTimer(m4StopWaitMax)
	defer tmr.Stop()
	select {
	case <-r.doneCh: // 等它当前这次写完
	case <-tmr.C:
		logf("m4_owner: 停 Go 写者等待超时(%v), 推进写代际锁拦截旧运行器残留写盘", m4StopWaitMax)
	}
	m4WriteMu.Lock()
	if m4CurrentWriteGen <= r.writeGen {
		m4CurrentWriteGen = r.writeGen + 1
	}
	m4WriteMu.Unlock()
	m.runner = nil
}

// run 主循环: 订阅事件 + 200ms tick(去抖 / 30s 全量 + 离线检查 /
// 1s pending 派发)。退出前把 dirty 的内容补写一次(对齐 C 关机行为)。
func (r *m4GoRunner) run() {
	defer close(r.doneCh)
	if r.stopCancel != nil {
		defer r.stopCancel()
	}
	bootAt := time.Now()
	monoMs := func() int64 {
		d := time.Since(bootAt).Milliseconds()
		if d < 0 {
			return 1
		}
		return 1 + d
	}
	events := make(chan []neigh.Entry, 64)
	resyncCh := make(chan struct{}, 1)
	var (
		subMu      sync.Mutex
		stopping   bool
		closeSub   func()
		readWG     sync.WaitGroup
		needResync bool
	)
	bindSub := func(src m4NeighSource) (func(), bool) {
		once := sync.OnceFunc(func() { _ = src.Close() })
		subMu.Lock()
		if stopping {
			subMu.Unlock()
			once()
			return once, false
		}
		closeSub = once
		subMu.Unlock()
		return once, true
	}
	stopSub := func() {
		subMu.Lock()
		stopping = true
		fn := closeSub
		closeSub = nil
		subMu.Unlock()
		if fn != nil {
			fn()
		}
	}
	isStopping := func() bool {
		subMu.Lock()
		s := stopping
		subMu.Unlock()
		return s
	}
	triggerResync := func() {
		select {
		case resyncCh <- struct{}{}:
		default:
		}
	}

	initSrc, err := r.subscribeFn()
	initSubErrMsg := ""
	if err != nil {
		initSubErrMsg = err.Error()
		logf("m4_owner: 初始订阅邻居表失败: %v(转入后台退避重连 + 全量兜底)", err)
	}
	readWG.Add(1)
	go func(src m4NeighSource, initErr error, firstErrMsg string) {
		defer readWG.Done()
		var closeCurr func()
		if src != nil {
			var ok bool
			closeCurr, ok = bindSub(src)
			if !ok {
				return
			}
		}
		defer func() {
			if closeCurr != nil {
				closeCurr()
			}
			subMu.Lock()
			closeSub = nil
			subMu.Unlock()
		}()

		backoff := m4ReconnectBaseBackoff
		if isNetlinkPermErr(initErr) {
			backoff = m4PermErrBackoff
		}
		lastSubErrMsg := firstErrMsg
		var lastEnobufsLog time.Time
		for {
			select {
			case <-r.stopCh:
				return
			default:
			}
			if isStopping() {
				return
			}
			if src == nil {
				wait := backoff
				if backoff < m4ReconnectMaxBackoff {
					backoff *= 2
					if backoff > m4ReconnectMaxBackoff {
						backoff = m4ReconnectMaxBackoff
					}
				}
				tmr := time.NewTimer(wait)
				select {
				case <-tmr.C:
				case <-r.stopCh:
					tmr.Stop()
					return
				}
				if isStopping() {
					return
				}
				next, sErr := r.subscribeFn()
				if sErr != nil {
					if isNetlinkPermErr(sErr) {
						backoff = m4PermErrBackoff
					}
					if msg := sErr.Error(); msg != lastSubErrMsg {
						lastSubErrMsg = msg
						logf("m4_owner: 重连邻居表订阅失败(wait=%v): %v", wait, sErr)
					}
					continue
				}
				lastSubErrMsg = ""
				var ok bool
				closeCurr, ok = bindSub(next)
				if !ok {
					return
				}
				src = next
				logf("m4_owner: 邻居表订阅已恢复, 触发全量重同步")
				triggerResync()
			}

			es, rErr := src.Read()
			if rErr != nil {
				select {
				case <-r.stopCh:
					return
				default:
				}
				if isStopping() {
					return
				}
				if errors.Is(rErr, syscall.ENOBUFS) {
					if now := time.Now(); now.Sub(lastEnobufsLog) >= 5*time.Second {
						lastEnobufsLog = now
						logf("m4_owner: 邻居订阅缓冲区溢出(ENOBUFS), 原位触发 1Hz 全量重同步")
					}
					triggerResync()
					tmr := time.NewTimer(100 * time.Millisecond)
					select {
					case <-tmr.C:
					case <-r.stopCh:
						tmr.Stop()
						return
					}
					continue
				}
				logf("m4_owner: 邻居订阅读取异常: %v(关闭旧连接并退避重连)", rErr)
				closeCurr()
				subMu.Lock()
				closeSub = nil
				subMu.Unlock()
				src, closeCurr = nil, nil
				if isNetlinkPermErr(rErr) {
					backoff = m4PermErrBackoff
				}
				continue
			}
			backoff = m4ReconnectBaseBackoff
			es = filterHotspotNeighEvents(es, int(r.atomicIfIdx.Load()))
			if len(es) == 0 {
				continue
			}
			select {
			case events <- es:
			case <-r.stopCh:
				return
			}
		}
	}(initSrc, err, initSubErrMsg)

	var (
		dirty           bool
		firstDirtyMs    int64 // 首次 dirty 的毫秒时刻(0 = 无)
		lastEventMs     int64
		lastWriteMs     int64
		lastWritten     []byte
		lastStatsAt     time.Time
		lastStatsMap    = map[string][2]int64{}
		lastSync        time.Time
		lastSyncAttempt time.Time
		syncRetryWait   = time.Second
		lastDumpErrMsg  string
		initialWritten  bool
		lastPending     time.Time
		inFlightMu      sync.Mutex
		inFlight        = map[string]bool{}
		resolved        = make(chan struct{}, 1)
		resolveWG       sync.WaitGroup
	)
	markDirty := func() {
		dirty = true
		lastEventMs = monoMs()
		if firstDirtyMs == 0 {
			firstDirtyMs = lastEventMs
		}
	}
	period := m4WriteHardRateMS * time.Millisecond
	tick := time.NewTicker(period)
	defer tick.Stop()
	retune := func(onlyFaster bool) {
		inFlightMu.Lock()
		n := len(inFlight)
		inFlightMu.Unlock()
		want := m4NextTickMS(dirty || needResync, r.table.HasPending(), n > 0)
		if want == period || (onlyFaster && want > period) {
			return
		}
		tick.Reset(want)
		period = want
	}
	var (
		lastRefreshNano     int64
		lastRefreshNonce    string
		hasInitRefresh      bool
		lastRefreshTryAt    time.Time
		lastRefreshTryNano  int64
		lastRefreshTryNonce string
	)
	if fi, err := os.Stat(m4RefreshFile); err == nil {
		reqNonce := readNonce(m4RefreshFile)
		ackNonce := readNonce(m4RefreshAckFile)
		// 仅当该请求已被回执(或无 nonce 的旧 touch 残留)才记为已消费,
		// 防止写者刚启动时吞掉 UI/scan 已写入的首屏刷新请求。
		if reqNonce == "" || reqNonce == ackNonce {
			hasInitRefresh = true
			lastRefreshNano = fi.ModTime().UnixNano()
			lastRefreshNonce = reqNonce
		}
	}
	refreshDue := func(now time.Time) (nonce string, modNano int64, due bool) {
		fi, err := os.Stat(m4RefreshFile)
		if err != nil {
			return "", 0, false
		}
		modNano = fi.ModTime().UnixNano()
		curNonce := readNonce(m4RefreshFile)
		if hasInitRefresh && modNano == lastRefreshNano && curNonce == lastRefreshNonce {
			return "", 0, false
		}
		if modNano == lastRefreshTryNano && curNonce == lastRefreshTryNonce &&
			!lastRefreshTryAt.IsZero() && now.Sub(lastRefreshTryAt) < time.Second {
			return "", 0, false
		}
		lastRefreshTryAt = now
		lastRefreshTryNano = modNano
		lastRefreshTryNonce = curNonce
		return curNonce, modNano, true
	}

	for {
		ticked := false
		select {
		case <-r.stopCh:
			if r.stopCancel != nil {
				r.stopCancel()
			}
			stopSub()
			readWG.Wait()
			resolveWG.Wait()
			select {
			case <-resolved:
				dirty = true
			default:
			}
			if dirty && !r.clearOnStop.Load() {
				lastWritten, _ = r.writeOutErr(lastWritten, &lastStatsAt, &lastStatsMap, false)
			}
			return
		case <-resyncCh:
			needResync = true
		case <-resolved:
			markDirty()
		case es := <-events:
			if r.ifIdx == 0 {
				r.refreshIface()
			}
			if r.ifIdx != 0 {
				changed := false
				for _, e := range es {
					if r.table.Apply(e, time.Now()) {
						changed = true
					}
				}
				if changed {
					markDirty()
				}
			}
		case <-tick.C:
			ticked = true
			r.tickN.Add(1)
			now := time.Now()
			if nonce, modNano, due := refreshDue(now); due {
				r.refreshIface()
				var (
					es      []neigh.Entry
					dumpErr error
				)
				if r.ifIdx != 0 {
					es, dumpErr = r.dumpIfFn(r.ifIdx)
					if dumpErr == nil {
						r.table.FullSync(es, now)
					}
				} else {
					dumpErr = errors.New("ifindex unavailable")
				}
				if dumpErr == nil {
					r.table.EvictOffline(now)
					var writeErr error
					lastWritten, writeErr = r.writeOutErr(lastWritten, &lastStatsAt, &lastStatsMap, true)
					needResync = false
					lastSync = now
					lastSyncAttempt = now
					if writeErr == nil {
						dirty = false
						firstDirtyMs = 0
						lastWriteMs = monoMs()
						initialWritten = true
						hasInitRefresh = true
						lastRefreshNano = modNano
						lastRefreshNonce = nonce
						if nonce != "" {
							if err := writeAtomic(m4RefreshAckFile, []byte(nonce+"\n")); err != nil {
								logf("m4_owner: 写刷新回执失败: %v", err)
							}
						}
					}
				}
			}
			syncDue := false
			if lastSync.IsZero() {
				syncDue = lastSyncAttempt.IsZero() || now.Sub(lastSyncAttempt) >= syncRetryWait
			} else if now.Sub(lastSync) >= m4FullSyncEvery {
				syncDue = now.Sub(lastSyncAttempt) >= syncRetryWait
			} else if needResync && now.Sub(lastSync) >= time.Second {
				syncDue = now.Sub(lastSyncAttempt) >= syncRetryWait
			}
			if syncDue {
				lastSyncAttempt = now
				r.refreshIface()
				if r.ifIdx != 0 {
					if es, dumpErr := r.dumpIfFn(r.ifIdx); dumpErr == nil {
						needResync = false
						lastSync = now
						syncRetryWait = time.Second
						lastDumpErrMsg = ""
						if r.table.FullSync(es, now) || !initialWritten {
							markDirty()
						}
					} else if isNetlinkPermErr(dumpErr) {
						syncRetryWait = m4PermErrBackoff
						if msg := dumpErr.Error(); msg != lastDumpErrMsg {
							lastDumpErrMsg = msg
							logf("m4_owner: 邻居表全量同步受限(退避 %v): %v", m4PermErrBackoff, dumpErr)
						}
					} else {
						syncRetryWait = time.Second
					}
				}
				if r.table.EvictOffline(now) > 0 {
					dirty = true
					if firstDirtyMs == 0 {
						firstDirtyMs = monoMs()
					}
				}
			}
			if now.Sub(lastPending) >= time.Second {
				lastPending = now
				if r.ifIdx == 0 {
					r.refreshIface()
				}
				if mac, ip, ok := r.table.PendingDue(now); ok {
					inFlightMu.Lock()
					busy := inFlight[mac]
					if !busy {
						inFlight[mac] = true
					}
					inFlightMu.Unlock()
					if !busy {
						resolveWG.Add(1)
						go func(mac, ip string) {
							defer resolveWG.Done()
							defer func() {
								inFlightMu.Lock()
								delete(inFlight, mac)
								inFlightMu.Unlock()
							}()
							hn, src := r.table.Full(mac, ip)
							if r.stopCtx != nil && r.stopCtx.Err() != nil && r.hooks.Full == nil {
								return
							}
							if r.table.ApplyResolution(mac, hn, src, time.Now()) {
								select {
								case resolved <- struct{}{}:
								default:
								}
							}
							if r.resolver != nil {
								if err := r.resolver.CacheSave(); err != nil {
									logf("m4_owner: hostname_cache 落盘失败: %v", err)
								}
							}
						}(mac, ip)
					}
				}
			}
			if dirty {
				if nowMs := monoMs(); m4ShouldWrite(firstDirtyMs, lastEventMs, lastWriteMs, nowMs) {
					var writeErr error
					lastWritten, writeErr = r.writeOutErr(lastWritten, &lastStatsAt, &lastStatsMap, false)
					if writeErr == nil {
						dirty = false
						firstDirtyMs = 0
						lastWriteMs = monoMs()
						initialWritten = true
					}
				}
			}
		}
		retune(!ticked)
	}
}

// filterHotspotNeighEvents 在订阅读协程按动态原子热点 ifIdx(>0)预筛非热点口蜂窝/上游 NDP 事件,
// 空闲时零唤醒主循环, 同时避免内核固定 BPF 在同名热点口重建换 ifindex 后失明。
func filterHotspotNeighEvents(es []neigh.Entry, hotIfIdx int) []neigh.Entry {
	if hotIfIdx <= 0 || len(es) == 0 {
		return es
	}
	n := 0
	for _, e := range es {
		if e.IfIndex == 0 || e.IfIndex == hotIfIdx {
			es[n] = e
			n++
		}
	}
	return es[:n]
}

func (r *m4GoRunner) refreshIface() {
	if r.ifIndexFn == nil {
		return
	}
	idx, err := r.ifIndexFn(r.iface)
	if err != nil || idx == r.ifIdx {
		return
	}
	r.ifIdx = idx
	r.atomicIfIdx.Store(int32(idx))
	r.table.SetIface(r.iface, idx)
	logf("m4_owner: 热点网卡重建 %s ifindex=%d", r.iface, idx)
}

func (r *m4GoRunner) writeOut(lastWritten []byte, lastStatsAt *time.Time, lastStatsMap *map[string][2]int64, force bool) []byte {
	b, _ := r.writeOutErr(lastWritten, lastStatsAt, lastStatsMap, force)
	return b
}

func (r *m4GoRunner) writeOutErr(lastWritten []byte, lastStatsAt *time.Time, lastStatsMap *map[string][2]int64, force bool) ([]byte, error) {
	now := time.Now()
	stopping := r.stopCtx != nil && r.stopCtx.Err() != nil
	if !stopping && (force || now.Sub(*lastStatsAt) >= m4StatsTTL) {
		statsFn := r.statsFn
		if statsFn == nil {
			statsFn = r.statsCmdFn
		}
		if statsFn != nil {
			if s, err := statsFn(); err == nil {
				*lastStatsMap, *lastStatsAt = s, now
			}
		}
	}
	b := r.table.RenderJSON(*lastStatsMap, r.blacklistFn())
	if !force && string(b) == string(lastWritten) {
		if m4DevicesFlat != "" {
			if _, err := os.Stat(m4DevicesFlat); err != nil {
				r.writeDevicesFlatAtomic()
			}
		}
		return lastWritten, nil
	}
	if err := r.writeDevicesAtomic(b); err != nil {
		return lastWritten, err
	}
	return b, nil
}

// writeDevicesAtomic 在代际写锁保护下原子写出唯一权威设备表 data/devices.json, 随后同步原子写出 run/devices.flat。
func (r *m4GoRunner) writeDevicesAtomic(b []byte) error {
	m4WriteMu.Lock()
	defer m4WriteMu.Unlock()
	if r != nil && r.writeGen != 0 && r.writeGen < m4CurrentWriteGen {
		return errM4StaleGen
	}
	var flat []byte
	if m4DevicesFlat != "" && r != nil && r.table != nil {
		flat = r.table.RenderFlat()
	}
	return writeDevicesPayloadLocked(b, flat)
}

func writeDevicesPayloadLocked(b, flat []byte) error {
	out := m4DevicesJSON
	tmp := fmt.Sprintf("%s.%d.%d", m4DevicesTmpGo, os.Getpid(), wdAtomicSeq.Add(1))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		m4GoWriteFails.Add(1)
		logf("m4_owner: 打开 %s 失败: %v", tmp, err)
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		m4GoWriteFails.Add(1)
		logf("m4_owner: 写 %s 失败: %v", tmp, err)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		m4GoWriteFails.Add(1)
		logf("m4_owner: sync %s 失败: %v", tmp, err)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		m4GoWriteFails.Add(1)
		logf("m4_owner: close %s 失败: %v", tmp, err)
		return err
	}
	m4Log(time.Now().Format("2006-01-02T15:04:05") + ": " + out)
	if err := os.Rename(tmp, out); err != nil {
		_ = os.Remove(tmp)
		m4GoWriteFails.Add(1)
		logf("m4_owner: rename %s 失败: %v", out, err)
		return err
	}
	m4GoWrites.Add(1)
	if m4DevicesFlat != "" {
		if err := wdWriteAtomic(m4DevicesFlat, flat, 0o644); err != nil {
			logf("m4_owner: 写 %s 失败: %v", m4DevicesFlat, err)
		}
	}
	return nil
}

func (r *m4GoRunner) writeDevicesFlatAtomic() {
	if m4DevicesFlat == "" || r == nil || r.table == nil {
		return
	}
	m4WriteMu.Lock()
	defer m4WriteMu.Unlock()
	if r.writeGen != 0 && r.writeGen < m4CurrentWriteGen {
		return
	}
	flat := r.table.RenderFlat()
	if err := wdWriteAtomic(m4DevicesFlat, flat, 0o644); err != nil {
		logf("m4_owner: 写 %s 失败: %v", m4DevicesFlat, err)
	}
}

func isDevicesJSONAlreadyEmpty(b []byte) bool {
	s := bytes.TrimSpace(b)
	if string(s) == "{}" {
		return true
	}
	if len(s) < 2 || s[0] != '{' {
		return false
	}
	var m map[string]json.RawMessage
	return json.Unmarshal(s, &m) == nil && len(m) == 0
}

// clearOnlineDevicesIfNonEmpty 关热点时由 m4_owner 唯一写者幂等归零非空在线态;
// 若待机已空(文件不存在或已为 "{}" 且 devices.flat 已空)则零写盘。
func clearOnlineDevicesIfNonEmpty() {
	m4WriteMu.Lock()
	defer m4WriteMu.Unlock()
	m4CurrentWriteGen++

	needWriteJSON := false
	if m4DevicesJSON != "" {
		if b, err := os.ReadFile(m4DevicesJSON); err == nil {
			if !isDevicesJSONAlreadyEmpty(b) {
				needWriteJSON = true
			}
		}
	}
	needClearFlat := false
	if m4DevicesFlat != "" {
		if fi, err := os.Stat(m4DevicesFlat); err == nil && fi.Size() > 0 {
			needClearFlat = true
		}
	}
	if !needWriteJSON && !needClearFlat {
		return
	}
	if needWriteJSON {
		_ = writeDevicesPayloadLocked([]byte("{}"), nil)
		return
	}
	if needClearFlat {
		if err := wdWriteAtomic(m4DevicesFlat, nil, 0o644); err != nil {
			logf("m4_owner: 归零 %s 失败: %v", m4DevicesFlat, err)
		}
	}
}

// m4Log 写入 m4_go_write.log 并封顶 256 KiB(超限时保留最近一半完整行或原地截断, 防撑爆 32M tmpfs)。
func m4Log(line string) {
	if m4GoWriteLog == "" {
		return
	}
	payload := []byte(line + "\n")
	if err := appendCappedLines(m4GoWriteLog, payload, m4GoWriteLogMaxBytes); err != nil {
		_ = wdWriteAtomic(m4GoWriteLog, payload, 0o644)
	}
}

// ─── SELinux AF_NETLINK 权限识别与 /proc/net/arp 兜底 ──────────────

func isNetlinkPermErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EPROTONOSUPPORT) ||
		errors.Is(err, syscall.EAFNOSUPPORT) ||
		errors.Is(err, syscall.ESOCKTNOSUPPORT) ||
		errors.Is(err, os.ErrPermission) {
		return true
	}
	msg := err.Error()
	return strings.HasSuffix(msg, "netlink error -1") ||
		strings.HasSuffix(msg, "netlink error -13") ||
		strings.HasSuffix(msg, "netlink error -93")
}

// defaultDumpIf 生产默认邻居表全量读取: 仅在 neigh.DumpIf 遭遇权限/不支持错误时
// 回退读取 /proc/net/arp(单测覆写 r.dumpIfFn 时不经过本函数, 保持错误门控语义)。
func (r *m4GoRunner) defaultDumpIf(ifIdx int) ([]neigh.Entry, error) {
	now := time.Now()
	r.arpFallbackMu.Lock()
	inCooldown := !r.netlinkDenyUntil.IsZero() && now.Before(r.netlinkDenyUntil)
	r.arpFallbackMu.Unlock()

	var nlErr error
	if !inCooldown {
		es, err := m4NetlinkDumpIfFn(ifIdx)
		if err == nil {
			r.arpFallbackMu.Lock()
			r.netlinkDenyUntil = time.Time{}
			r.lastArpFallback = ""
			r.arpFallbackMu.Unlock()
			return es, nil
		}
		if !isNetlinkPermErr(err) {
			return nil, err
		}
		nlErr = err
		r.arpFallbackMu.Lock()
		r.netlinkDenyUntil = now.Add(m4PermErrBackoff)
		if msg := err.Error(); msg != r.lastArpFallback {
			r.lastArpFallback = msg
			logf("m4_owner: netlink 邻居表受限, 回退 %s: %v", m4ProcNetARP, err)
		}
		r.arpFallbackMu.Unlock()
	}

	es, arpErr := readProcNetARP(m4ProcNetARP, r.iface, ifIdx)
	if arpErr != nil {
		if nlErr != nil {
			return nil, fmt.Errorf("%w (arp fallback: %v)", nlErr, arpErr)
		}
		return nil, fmt.Errorf("netlink denied (%w) and arp fallback failed: %v", syscall.EACCES, arpErr)
	}
	return es, nil
}

func isValidClientMAC(mac string) bool {
	if len(mac) != 17 || mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
		return false
	}
	for i := 0; i < 17; i++ {
		c := mac[i]
		if i%3 == 2 {
			if c != ':' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func readProcNetARP(path, iface string, ifIdx int) ([]neigh.Entry, error) {
	if iface == "" {
		return nil, errors.New("arp fallback: empty iface")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []neigh.Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "IP ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[5] != iface {
			continue
		}
		flags, fErr := strconv.ParseUint(fields[2], 0, 32)
		if fErr != nil || flags == 0 || (flags&0x2) == 0 {
			continue
		}
		mac := strings.ToLower(fields[3])
		if !isValidClientMAC(mac) {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil || ip.To4() == nil {
			continue
		}
		out = append(out, neigh.Entry{
			IfIndex: ifIdx,
			Family:  syscall.AF_INET,
			IP:      ip.To4(),
			MAC:     mac,
			State:   neigh.NUDReachable,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ─── 纯函数 / 流量统计(纯 Go 流式解析 + 平滑兜底) ─────────────────

func m4ShouldWrite(firstDirtyMs, lastEventMs, lastWriteMs, nowMs int64) bool {
	if firstDirtyMs == 0 {
		return false
	}
	if lastWriteMs == 0 {
		return true
	}
	if nowMs-lastWriteMs < m4WriteHardRateMS {
		return false
	}
	if nowMs-lastWriteMs >= m4WriteIdleMS {
		return true
	}
	if nowMs-lastEventMs >= m4WriteMergeMS {
		return true
	}
	return nowMs-firstDirtyMs >= m4WriteMaxDirtyMS
}

func macFallback(mac string) string {
	nc := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(mac)), ":", "")
	if len(nc) > 8 {
		return nc[len(nc)-8:]
	}
	return nc
}

// resolveM4ShellPath 动态探测当前环境可用的 POSIX sh 解释器:
// 若单测显式覆写了 shBin 且存在则优先使用, 否则依次探测 shellPath()(含 /system/bin/sh
// 与 /data/local/hnc/bin/sh Magic Mount 兜底副本)、/bin/sh、/usr/bin/sh 与 PATH。
func resolveM4ShellPath() string {
	if shBin != "" && shBin != "/system/bin/sh" {
		if _, err := os.Stat(shBin); err == nil {
			return shBin
		}
	}
	for _, cand := range []string{shellPath(), "/system/bin/sh", binDir + "/sh", "/bin/sh", "/usr/bin/sh"} {
		if cand == "" {
			continue
		}
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	if p, err := exec.LookPath("sh"); err == nil && p != "" {
		return p
	}
	return shellPath()
}

func resolveIptablesBin(name string) string {
	for _, cand := range []string{
		"/system/bin/" + name,
		"/system/xbin/" + name,
		"/vendor/bin/" + name,
		binDir + "/" + name,
		"/sbin/" + name,
		"/usr/sbin/" + name,
		"/bin/" + name,
		"/usr/bin/" + name,
	} {
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand
		}
	}
	if p, err := exec.LookPath(name); err == nil && p != "" {
		return p
	}
	return ""
}

// m4IptablesExecFn 执行单次 iptables / ip6tables 子进程(单测可注入替换)。
var m4IptablesExecFn = execIptablesRaw

func execIptablesRaw(parentCtx context.Context, nameOrPath string, args ...string) (stdout, stderr string, rc int, err error) {
	binPath := nameOrPath
	if !strings.Contains(binPath, "/") {
		binPath = resolveIptablesBin(binPath)
	}
	if binPath == "" {
		return "", "binary not found", -1, os.ErrNotExist
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(parentCtx, m4IptablesTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 500 * time.Millisecond

	runErr := cmd.Run()
	stdout, stderr = outBuf.String(), errBuf.String()
	if ctx.Err() != nil {
		return stdout, stderr, -1, ctx.Err()
	}
	if runErr == nil {
		return stdout, stderr, 0, nil
	}
	if ee, ok := runErr.(*exec.ExitError); ok {
		return stdout, stderr, ee.ExitCode(), runErr
	}
	return stdout, stderr, -1, runErr
}

func isIptablesUnsupportedWaitOpt(rc int, stderr string) bool {
	if rc != 2 && rc != 1 {
		return false
	}
	s := strings.ToLower(stderr)
	if strings.Contains(s, "no chain") || strings.Contains(s, "does not exist") || strings.Contains(s, "xtables lock") {
		return false
	}
	return strings.Contains(s, "unknown option") ||
		strings.Contains(s, "unrecognized option") ||
		strings.Contains(s, "invalid option") ||
		strings.Contains(s, "bad argument") ||
		strings.Contains(s, "try '") ||
		strings.Contains(s, "usage:")
}

// runIptablesChainStats 带 2s 进程组硬超时读取 iptables/ip6tables -t mangle -L HNC_STATS -nvx,
// 自动按 `-w 2` → `-w` → 无 `-w` 回退; 链或表尚未创建时返回空字符串与 nil 错误。
func runIptablesChainStats(ctx context.Context, name string) (string, error) {
	variants := [][]string{
		{"-w", "2"},
		{"-w"},
		{},
	}
	var lastErr error
	for idx, wArgs := range variants {
		args := make([]string, 0, len(wArgs)+5)
		args = append(args, wArgs...)
		args = append(args, "-t", "mangle", "-L", "HNC_STATS", "-nvx")
		stdout, stderr, rc, err := m4IptablesExecFn(ctx, name, args...)
		if err == nil && rc == 0 {
			return stdout, nil
		}
		if ctx != nil && ctx.Err() != nil {
			return "", ctx.Err()
		}
		if rc < 0 {
			return "", err
		}
		errLC := strings.ToLower(stderr)
		if strings.Contains(errLC, "no chain/target/match") || strings.Contains(errLC, "does not exist") {
			return "", nil
		}
		if idx+1 < len(variants) && isIptablesUnsupportedWaitOpt(rc, stderr) {
			lastErr = err
			continue
		}
		return "", fmt.Errorf("%s rc=%d: %s", name, rc, strings.TrimSpace(stderr))
	}
	return "", lastErr
}

func (r *m4GoRunner) collectStats() (map[string][2]int64, error) {
	ctx := r.stopCtx
	if ctx == nil {
		ctx = context.Background()
	}
	return collectStatsWithTable(ctx, r.table)
}

// runStatsAll 兼容入口: STATS_ALL_CMD 非空时保持测试命令钩子; 否则走纯 Go 双栈采样, 失败平滑回退脚本。
func runStatsAll() (map[string][2]int64, error) {
	return collectStatsWithTable(context.Background(), nil)
}

func collectStatsWithTable(parentCtx context.Context, table *devscan.Table) (map[string][2]int64, error) {
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	if cmdStr := strings.TrimSpace(os.Getenv("STATS_ALL_CMD")); cmdStr != "" {
		return runStatsAllOverrideCmd(parentCtx, cmdStr)
	}

	v4Out, v4Err := runIptablesChainStats(parentCtx, "iptables")
	if v4Err != nil {
		if parentCtx.Err() == nil && iptablesMgrPath != "" {
			if fi, err := os.Stat(iptablesMgrPath); err == nil && !fi.IsDir() {
				return runStatsAllScript(parentCtx)
			}
		}
		return nil, v4Err
	}

	v6Out, _ := runIptablesChainStats(parentCtx, "ip6tables")

	macIP := map[string]string{}
	if table != nil {
		macIP = table.SnapshotMACIP()
	}
	if m4DevicesJSON != "" {
		if b, err := os.ReadFile(m4DevicesJSON); err == nil && len(b) > 0 && len(b) <= 4<<20 {
			var diskDevs map[string]struct {
				IP string `json:"ip"`
			}
			if json.Unmarshal(b, &diskDevs) == nil {
				for mac, d := range diskDevs {
					m := strings.ToLower(strings.TrimSpace(mac))
					if m != "" && d.IP != "" {
						if _, exists := macIP[m]; !exists {
							macIP[m] = d.IP
						}
					}
				}
			}
		}
	}

	var v6MapBytes, v6RetBytes []byte
	if m4StatsV6Map != "" {
		v6MapBytes, _ = os.ReadFile(m4StatsV6Map)
	}
	if m4StatsV6Retired != "" {
		v6RetBytes, _ = os.ReadFile(m4StatsV6Retired)
	}

	return aggregateDualStackStats(v4Out, v6Out, macIP, string(v6MapBytes), string(v6RetBytes)), nil
}

func addSatInt64(a, b int64) int64 {
	if b <= 0 {
		return a
	}
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

func parseStatsCountInt64(s string) (int64, bool) {
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		if v < 0 {
			return 0, false
		}
		return v, true
	}
	if fv, err := strconv.ParseFloat(s, 64); err == nil && fv >= 0 && fv <= float64(math.MaxInt64) {
		return int64(fv), true
	}
	return 0, false
}

// canonIP6 规范化 IPv6 字符串为 8 段小写无前导零形式, 与 bin/iptables_manager.sh canon_ip6 完全一致。
func canonIP6(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.IndexByte(s, '%'); idx >= 0 {
		s = s[:idx]
	}
	if !strings.Contains(s, ":") {
		return s
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil || len(ip) != net.IPv6len {
		return s
	}
	var parts [8]string
	for i := 0; i < 8; i++ {
		w := binary.BigEndian.Uint16(ip[i*2 : i*2+2])
		parts[i] = strconv.FormatUint(uint64(w), 16)
	}
	return strings.Join(parts[:], ":")
}

// aggregateDualStackStats 流式解析 IPv4/IPv6 HNC_STATS 输出(兼容 legacy 9 列与 iptables-nft 8 列无 opt 列),
// 结合当前设备表 MAC→IPv4、stats_v6_map 与 stats_v6_retired 精确汇总每台设备的上下行字节。
func aggregateDualStackStats(v4Out, v6Out string, macIP map[string]string, v6MapRaw, v6RetRaw string) map[string][2]int64 {
	rx := map[string]int64{}
	tx := map[string]int64{}
	seen := map[string]bool{}

	if v4Out != "" {
		sc := bufio.NewScanner(strings.NewReader(v4Out))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 8 || f[2] != "RETURN" {
				continue
			}
			if _, err := strconv.ParseUint(f[0], 10, 64); err != nil {
				continue
			}
			b, ok := parseStatsCountInt64(f[1])
			if !ok {
				continue
			}
			var src, dst string
			if len(f) >= 9 && strings.HasPrefix(f[4], "-") {
				src, dst = f[7], f[8]
			} else {
				src, dst = f[6], f[7]
			}
			src = strings.TrimSuffix(src, "/32")
			dst = strings.TrimSuffix(dst, "/32")
			if src != "0.0.0.0/0" && dst == "0.0.0.0/0" {
				tx[src] = addSatInt64(tx[src], b)
				seen[src] = true
			} else if src == "0.0.0.0/0" && dst != "0.0.0.0/0" {
				rx[dst] = addSatInt64(rx[dst], b)
				seen[dst] = true
			}
		}
	}

	ip6Owner := map[string]string{}
	if v6MapRaw != "" {
		sc := bufio.NewScanner(strings.NewReader(v6MapRaw))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) >= 2 && f[0] != "" && f[1] != "" {
				ip6Owner[canonIP6(f[0])] = strings.ToLower(f[1])
			}
		}
	}

	if v6Out != "" && len(macIP) > 0 {
		sc := bufio.NewScanner(strings.NewReader(v6Out))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 8 || f[2] != "RETURN" {
				continue
			}
			if _, err := strconv.ParseUint(f[0], 10, 64); err != nil {
				continue
			}
			b, ok := parseStatsCountInt64(f[1])
			if !ok {
				continue
			}
			mac := ""
			for i := 3; i+1 < len(f); i++ {
				if f[i] == "MAC" {
					mac = strings.ToLower(f[i+1])
					break
				}
			}
			if mac != "" {
				if ip4 := macIP[mac]; ip4 != "" {
					tx[ip4] = addSatInt64(tx[ip4], b)
					seen[ip4] = true
				}
				continue
			}
			for i := 3; i+1 < len(f); i++ {
				if f[i] == "::/0" && f[i+1] != "::/0" && strings.Contains(f[i+1], ":") {
					dst6 := canonIP6(f[i+1])
					if own := ip6Owner[dst6]; own != "" {
						if ip4 := macIP[own]; ip4 != "" {
							rx[ip4] = addSatInt64(rx[ip4], b)
							seen[ip4] = true
						}
					}
					break
				}
			}
		}
	}

	if v6RetRaw != "" && len(macIP) > 0 {
		sc := bufio.NewScanner(strings.NewReader(v6RetRaw))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 2 {
				continue
			}
			m := strings.ToLower(f[0])
			ip4 := macIP[m]
			if ip4 == "" {
				continue
			}
			rRx, _ := parseStatsCountInt64(f[1])
			var rTx int64
			if len(f) >= 3 {
				rTx, _ = parseStatsCountInt64(f[2])
			}
			rx[ip4] = addSatInt64(rx[ip4], rRx)
			tx[ip4] = addSatInt64(tx[ip4], rTx)
			seen[ip4] = true
		}
	}

	stats := make(map[string][2]int64, len(seen))
	for ip := range seen {
		stats[ip] = [2]int64{rx[ip], tx[ip]}
	}
	return stats
}

func runStatsAllOverrideCmd(parentCtx context.Context, cmdStr string) (map[string][2]int64, error) {
	fields := strings.Fields(cmdStr)
	if len(fields) == 0 {
		return map[string][2]int64{}, nil
	}
	ctx, cancel := context.WithTimeout(parentCtx, m4StatsTimeout)
	defer cancel()

	var cmd *exec.Cmd
	if p, err := exec.LookPath(fields[0]); err == nil && p != "" {
		cmd = exec.CommandContext(ctx, p, fields[1:]...)
	} else {
		cmd = exec.CommandContext(ctx, resolveM4ShellPath(), "-c", cmdStr)
	}
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseStatsAllLines(string(out)), nil
}

func runStatsAllScript(parentCtx context.Context) (map[string][2]int64, error) {
	ctx, cancel := context.WithTimeout(parentCtx, m4StatsTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolveM4ShellPath(), iptablesMgrPath, "stats_all")
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseStatsAllLines(string(out)), nil
}

func parseStatsAllLines(raw string) map[string][2]int64 {
	stats := map[string][2]int64{}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 {
			continue
		}
		rx, ok1 := parseStatsCountInt64(f[1])
		tx, ok2 := parseStatsCountInt64(f[2])
		if !ok1 || !ok2 {
			continue
		}
		stats[f[0]] = [2]int64{rx, tx}
	}
	return stats
}

// readBlacklist 读 rules.json 的 blacklist(JSON 解析, 失败 = 空)。
func readBlacklist() map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(rulesJSONPath)
	if err != nil {
		return out
	}
	var rules struct {
		Blacklist []string `json:"blacklist"`
	}
	if json.Unmarshal(b, &rules) != nil {
		return out
	}
	for _, m := range rules.Blacklist {
		out[strings.ToLower(strings.TrimSpace(m))] = true
	}
	return out
}

// ─── 生产接线用的小工具 ──────────────────────────────────────────

var (
	shBin           = "/system/bin/sh"
	iptablesMgrPath = binDir + "/iptables_manager.sh"
	rulesJSONPath   = dataDir + "/rules.json"
)

func appendLine(p, line string) error {
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

func readNonce(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	n := string(b)
	if i := strings.IndexAny(n, "\r\n"); i >= 0 {
		n = n[:i]
	}
	n = strings.TrimSpace(n)
	if len(n) > m4NonceMax {
		n = n[:m4NonceMax]
	}
	return n
}

func writeAtomic(p string, b []byte) error {
	return wdWriteAtomic(p, b, 0o644)
}
