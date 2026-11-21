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
// v6.0 加固: 修复 runStatsAll 硬编码 /system/bin/sh 为动态探测可用 sh 解释器路径,
// 并补齐独立进程组 SIGKILL + WaitDelay 超时收尾保护, 防止孙进程持管道挂死写者协程!
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
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
	m4WriteHardRateMS = 200              // 距上次写 <200ms 永不写(rc30.9 硬限速)
	m4IdleTickMS      = 500              // v5.32 T4: 空闲(无 dirty/待解析名字/在途解析)时主循环 500ms 醒一次(REFRESH 要在 1 秒内响应)
	m4WriteIdleMS     = 500              // 空闲后首事件立即写(rc30.9)
	m4WriteMergeMS    = 200              // 合并窗口: 200ms 无新事件(rc30.9)
	m4WriteMaxDirtyMS = 30000            // dirty 兜底 30s(rc30.9)
	m4StatsTTL        = 5 * time.Second  // 流量字节 5s TTL(C update_traffic_stats)
	m4StatsTimeout    = 3 * time.Second  // hnc_run_cmd_timeout(..., 3000)
	m4FullSyncEvery   = 30 * time.Second // 全量 dump 兜底(WORK T1)
	m4NonceMax        = 64               // run/devices.refresh 里 nonce 的长度上限
)

// 路径做成变量(单测重定向到临时目录)。
var (
	m4DevicesJSON  = dataDir + "/devices.json"        // 输出
	m4DevicesTmpGo = dataDir + "/devices.json.tmp.go" // 临时文件
	// v5.31 T4 / v5.33: 「立刻扫一次」的请求与回执(见文件头)。
	m4RefreshFile    = runDir + "/devices.refresh"
	m4RefreshAckFile = runDir + "/devices.refresh.ack"
	// v5.31 T5: 写出日志(每写一行时间戳; 排查「谁在什么时候写了 devices.json」)。
	m4GoWriteLog = runDir + "/m4_go_write.log"

	// v5.31 T2: devname 解析用到的路径(devname.Resolver 的注入字段)。
	m4NamesPath     = dataDir + "/device_names.json"
	m4CachePath     = dataDir + "/hostname_cache.json"
	m4OverridesPath = dataDir + "/oui_overrides.json"
	m4MDNSBin       = binDir + "/mdns_resolve"

	m4ReconnectBaseBackoff = time.Second
	m4ReconnectMaxBackoff  = 30 * time.Second
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
	m4Writer      = &m4WriterMgr{}
	newM4RunnerFn = newM4GoRunner
)

// tick 主循环每轮调用(热点 ACTIVE 时 iface 非空): 起 / 换网卡重起 / 停写者。
func (m *m4WriterMgr) tick(iface string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if iface == "" {
		m.stopGoRunnerLocked("热点未激活")
		return
	}
	m.ensureGoRunnerLocked(iface)
}

// hotspotDown 热点没开(主循环探测失败 / PENDING / 退出)时调: 停写者。
func (m *m4WriterMgr) hotspotDown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopGoRunnerLocked("热点未激活")
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

	iface  string
	ifIdx  int
	stopCh chan struct{}
	doneCh chan struct{}
	table  *devscan.Table

	// v5.31 T2: devname 全链解析(手动 → DHCP → mDNS → 缓存 → 厂商 → MAC)。
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
	blacklistFn func() map[string]bool
}

func m4NextTickMS(dirty, hasPending, resolving bool) time.Duration {
	if dirty || hasPending || resolving {
		return m4WriteHardRateMS * time.Millisecond
	}
	return m4IdleTickMS * time.Millisecond
}

// newM4GoRunner 生产构造: 真订阅 / 真 dump / 真命令。
func newM4GoRunner(iface string) *m4GoRunner {
	r := &m4GoRunner{
		iface:  iface,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	r.subscribeFn = func() (m4NeighSource, error) { return neigh.Subscribe() }
	r.dumpIfFn = neigh.DumpIf
	r.ifIndexFn = func(name string) (int, error) {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return 0, err
		}
		return ifi.Index, nil
	}
	r.statsCmdFn = runStatsAll
	r.blacklistFn = readBlacklist
	r.resolver = &devname.Resolver{
		NamesPath:     m4NamesPath,
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
		full = res.Resolve
	}
	if fast == nil {
		fast = func(mac string) (string, string) { return macFallback(mac), "mac" }
	}
	if full == nil {
		full = func(mac, ip string) (string, string) { return fast(mac) }
	}
	r.table.Fast = fast
	r.table.Full = full
}

func (r *m4GoRunner) start() {
	if r.ifIndexFn != nil {
		if idx, err := r.ifIndexFn(r.iface); err == nil {
			r.ifIdx = idx
		}
	}
	r.table.SetIface(r.iface, r.ifIdx)
	go r.run()
}

func (m *m4WriterMgr) ensureGoRunnerLocked(iface string) {
	if m.runner != nil && m.runner.iface == iface {
		return
	}
	m.stopGoRunnerLocked("网卡变了")
	r := newM4RunnerFn(iface)
	m.runner = r
	r.start()
}

func (m *m4WriterMgr) stopGoRunnerLocked(reason string) {
	if m.runner == nil {
		return
	}
	logf("m4_owner: 停 Go 写者(%s)", reason)
	close(m.runner.stopCh)
	<-m.runner.doneCh // 等它当前这次写完
	m.runner = nil
}

// run 主循环: 订阅事件 + 200ms tick(去抖 / 30s 全量 + 离线检查 /
// 1s pending 派发)。退出前把 dirty 的内容补写一次(对齐 C 关机行为)。
func (r *m4GoRunner) run() {
	defer close(r.doneCh)
	monoMs := func() int64 { return time.Now().UnixNano() / int64(time.Millisecond) }
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
	if err != nil {
		logf("m4_owner: 初始订阅邻居表失败: %v(转入后台指数退避重连 + 30s 全量兜底)", err)
	}
	readWG.Add(1)
	go func(src m4NeighSource) {
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
					logf("m4_owner: 重连邻居表订阅失败(wait=%v): %v", wait, sErr)
					continue
				}
				var ok bool
				closeCurr, ok = bindSub(next)
				if !ok {
					return
				}
				src = next
				backoff = m4ReconnectBaseBackoff
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
					continue
				}
				logf("m4_owner: 邻居订阅读取异常: %v(关闭旧连接并退避重连)", rErr)
				closeCurr()
				subMu.Lock()
				closeSub = nil
				subMu.Unlock()
				src, closeCurr = nil, nil
				continue
			}
			backoff = m4ReconnectBaseBackoff
			if len(es) == 0 {
				continue
			}
			select {
			case events <- es:
			case <-r.stopCh:
				return
			}
		}
	}(initSrc)

	var (
		dirty        bool
		firstDirtyMs int64 // 首次 dirty 的毫秒时刻(0 = 无)
		lastEventMs  int64
		lastWriteMs  int64
		lastWritten  []byte
		lastStatsAt  time.Time
		lastStatsMap = map[string][2]int64{}
		lastSync     time.Time
		lastPending  time.Time
		inFlightMu   sync.Mutex
		inFlight     = map[string]bool{}
		resolved     = make(chan struct{}, 1)
		resolveWG    sync.WaitGroup
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
	var lastRefreshM = monoMs()
	refreshDue := func() (nonce string, due bool) {
		fi, err := os.Stat(m4RefreshFile)
		if err != nil {
			return "", false
		}
		m := fi.ModTime().UnixNano() / int64(time.Millisecond)
		if m <= lastRefreshM {
			return "", false
		}
		lastRefreshM = m
		return readNonce(m4RefreshFile), true
	}

	for {
		ticked := false
		select {
		case <-r.stopCh:
			stopSub()
			readWG.Wait()
			resolveWG.Wait()
			select {
			case <-resolved:
				dirty = true
			default:
			}
			if dirty {
				lastWritten = r.writeOut(lastWritten, &lastStatsAt, &lastStatsMap, true)
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
			if nonce, due := refreshDue(); due {
				if r.ifIdx == 0 {
					r.refreshIface()
				}
				if es, err := r.dumpIfFn(r.ifIdx); err == nil && r.ifIdx != 0 {
					r.table.FullSync(es, now)
				}
				r.table.EvictOffline(now)
				lastWritten = r.writeOut(lastWritten, &lastStatsAt, &lastStatsMap, true)
				dirty = false
				firstDirtyMs = 0
				needResync = false
				lastSync = now
				if err := writeAtomic(m4RefreshAckFile, []byte(nonce+"\n")); err != nil {
					logf("m4_owner: 写刷新回执失败: %v", err)
				}
			}
			if now.Sub(lastSync) >= m4FullSyncEvery || (needResync && now.Sub(lastSync) >= time.Second) {
				needResync = false
				lastSync = now
				r.refreshIface()
				if es, err := r.dumpIfFn(r.ifIdx); err == nil && r.ifIdx != 0 {
					if r.table.FullSync(es, now) {
						markDirty()
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
							hn, src := r.table.Full(mac, ip)
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
							inFlightMu.Lock()
							delete(inFlight, mac)
							inFlightMu.Unlock()
						}(mac, ip)
					}
				}
			}
			if dirty {
				if nowMs := monoMs(); m4ShouldWrite(firstDirtyMs, lastEventMs, lastWriteMs, nowMs) {
					lastWritten = r.writeOut(lastWritten, &lastStatsAt, &lastStatsMap, false)
					dirty = false
					firstDirtyMs = 0
					lastWriteMs = monoMs()
				}
			}
		}
		retune(!ticked)
	}
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
	r.table.SetIface(r.iface, idx)
	logf("m4_owner: 热点网卡重建 %s ifindex=%d", r.iface, idx)
}

func (r *m4GoRunner) writeOut(lastWritten []byte, lastStatsAt *time.Time, lastStatsMap *map[string][2]int64, force bool) []byte {
	now := time.Now()
	if force || now.Sub(*lastStatsAt) >= m4StatsTTL {
		if s, err := r.statsCmdFn(); err == nil {
			*lastStatsMap, *lastStatsAt = s, now
		}
	}
	b := r.table.RenderJSON(*lastStatsMap, r.blacklistFn())
	if !force && string(b) == string(lastWritten) {
		return lastWritten
	}
	out, tmp := m4DevicesJSON, m4DevicesTmpGo
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		m4GoWriteFails.Add(1)
		logf("m4_owner: 写 %s 失败: %v", tmp, err)
		return lastWritten
	}
	_ = appendLine(m4GoWriteLog, time.Now().Format("2006-01-02T15:04:05")+": "+out)
	if err := os.Rename(tmp, out); err != nil {
		m4GoWriteFails.Add(1)
		logf("m4_owner: rename %s 失败: %v", out, err)
		return lastWritten
	}
	m4GoWrites.Add(1)
	return b
}

// ─── 纯函数 / 小工具(单测直接测) ─────────────────────────────────

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

// runStatsAll `sh bin/iptables_manager.sh stats_all`(参数分开传, 3s 超时 + 进程组 SIGKILL 隔离),
// 输出每行 "<ip> <rx> <tx>"。
func runStatsAll() (map[string][2]int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m4StatsTimeout)
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
	stats := map[string][2]int64{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		var rx, tx int64
		if _, err := fmt.Sscanf(f[1], "%d", &rx); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(f[2], "%d", &tx); err != nil {
			continue
		}
		stats[f[0]] = [2]int64{rx, tx}
	}
	return stats, nil
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
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
