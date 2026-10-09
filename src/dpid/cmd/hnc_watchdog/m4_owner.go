// m4_owner.go — v5.31 T1/T3(迁移 M4 方案 A): 谁拥有设备发现。
//
// 两个写者, 任何时刻只许一个在写 data/devices.json:
//   - owner = "c" : hotspotd(C)照旧发现(邻居表 netlink + /proc/net/arp),
//     Go 看门狗只跑 v5.30 的影子(m4_shadow.go, 只比对);
//   - owner = "go": Go 看门狗用 devscan 包发现并写 devices.json,
//     hotspotd 带 --no-discovery 跑(只留硬件加速兜底和控制接口)。
//
// 开关 data/m4_owner(放 data/ 是要跨重启): 内容 go / c, 双向都能强制;
// 文件不存在 = 用默认; 内容不认识 = 用默认 + 记一行日志。看门狗每轮读
// (60 秒内生效), 切换按 WORK-v5.31 §4 T3 的顺序「先停后起」:
//   - c → go: 先让 hotspotd 带参重启并确认真的停了(STATUS 回 discovery:0),
//     再启动 Go 写者;
//   - go → c: 先停 Go 写者(等当前这次写完), 再按原参数重启 hotspotd。
//     中间几秒没人写可以, devices.json 保留上一版。
//
// 写节奏对齐 hotspotd rc30.9 的 sub-second de-bounce(hotspotd.c 主循环注释):
// 距上次写 ≥500ms 的首个事件立即写; 否则等合并窗口(200ms 无新事件)或 30s
// 兜底; 距上次写 <200ms 硬限速不写。内容没变不写(省电)。rx/tx 在写前经
// `sh bin/iptables_manager.sh stats_all` 刷新(参数分开传, 3s 超时, 5s TTL ——
// 与 C 的 update_traffic_stats / hnc_run_cmd_timeout(…, 3000) 一致),
// TTL 内沿用上一次的数字(对齐 C: 设备字段里存的是上次结果)。
package main

import (
	"context"
	"encoding/json"
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

// m4OwnerDefault —— 默认值只写这一处(WORK-v5.31 §4 T3)。
// T2(名字解析)完成后 rc 默认 go —— 就是要在 rc 上验它; T2 没做完时必须
// 是 "c"。真机出现 §8 任一问题, v5.32 正式版改回 "c"。
const m4OwnerDefault = "go"

const (
	m4WriteHardRateMS = 200              // 距上次写 <200ms 永不写(rc30.9 硬限速)
	m4WriteIdleMS     = 500              // 空闲后首事件立即写(rc30.9)
	m4WriteMergeMS    = 200              // 合并窗口: 200ms 无新事件(rc30.9)
	m4WriteMaxDirtyMS = 30000            // dirty 兜底 30s(rc30.9)
	m4StatsTTL        = 5 * time.Second  // 流量字节 5s TTL(C update_traffic_stats)
	m4StatsTimeout    = 3 * time.Second  // hnc_run_cmd_timeout(..., 3000)
	m4FullSyncEvery   = 30 * time.Second // 全量 dump 兜底(WORK T1)
	m4SwitchBackoff   = 5 * time.Minute  // 切换失败后的退避窗口(真实时钟)
)

// 路径做成变量(单测重定向到临时目录; 仿 m4_shadow 的 m4RunDir/m4DataDir)。
var (
	m4OwnerFile        = dataDir + "/m4_owner"            // 用户开关(跨重启)
	m4OwnerCurrentFile = runDir + "/m4_owner.current"     // 看门狗每轮写出, 调用方只读这里
	m4DevicesJSON      = dataDir + "/devices.json"        // 正式输出
	m4DevicesTmpGo     = dataDir + "/devices.json.tmp.go" // Go 写者的临时文件(与 C 的 .tmp.<pid> 区分开)
	m4DrillOut         = runDir + "/devices.go.json"      // 演练输出(只比对不接管)
	m4GoOutTmp         = runDir + "/devices.go.json.tmp"
	m4DrillFile        = runDir + "/wd_m4_drill" // 存在 → 演练模式
	// v5.31 T4: hotspotd(--no-discovery)收到 REFRESH / SIGUSR1 时 touch 这个
	// 文件, Go 写者看到 mtime 变化就立刻全量扫一次。
	m4RefreshFile = runDir + "/devices.refresh"
	// v5.31 T5: Go 写者的写出日志(每写一行时间戳; 运行中切换场景用它证明
	// 「没有两个写者交替写」)。与 hotspotd.log 的 "JSON written" 行对照。
	m4GoWriteLog = runDir + "/m4_go_write.log"

	// v5.31 T2: devname 解析用到的路径(devname.Resolver 的注入字段)。
	m4NamesPath     = dataDir + "/device_names.json"
	m4CachePath     = dataDir + "/hostname_cache.json"
	m4OverridesPath = dataDir + "/oui_overrides.json"
	m4MDNSBin       = binDir + "/mdns_resolve"
)

// 看门狗动作 / 自检可见(actionstats 带出)。
var (
	m4GoWrites     atomic.Uint64
	m4GoWriteFails atomic.Uint64
	m4Switches     atomic.Uint64
	// m4OwnerCur 生效 owner 的无锁快照(hotspotdDaemon() 在持锁的切换路径里
	// 也会被调, 不能回拿 m.mu; 永远 ≥ m.owner 一步)。
	m4OwnerCur atomic.Value
)

// m4OwnerStats 供 actionstats.snapshot 带出(写者、Go 写次数 / 失败次数、切换次数)。
func m4OwnerStats() (owner string, writes, fails, switches uint64) {
	return m4Owner.currentOwner(), m4GoWrites.Load(), m4GoWriteFails.Load(), m4Switches.Load()
}

// wdActionsM4OwnerExtra actionstats.snapshot 带出的 M4 方案 A 字段(测试可替换)。
var wdActionsM4OwnerExtra = m4OwnerStats

// ─── owner 状态机 ──────────────────────────────────────────────────

type m4OwnerMgr struct {
	mu      sync.Mutex
	owner   string // 生效中: "go" / "c"; "" = 首轮之前
	runner  *m4GoRunner
	lastBad string // 上一次读到的坏内容(同一个只记一次日志)

	// 切换失败退避(真实时钟): 确认失败后 5 分钟内不重试同一切换 ——
	// budget_test 用假时钟连续驱动 tick, 没有退避会每轮都走一遍
	// confirmDiscoveryOff 的真实 sleep, 测试直接超时; 生产上也是
	// 防止热点未起来时每 60 秒折腾一次 hotspotd。
	failBackoffUntil time.Time

	// 注入点(单测替换; 生产为真实现)
	quitHotspotdFn   func() error           // 让 hotspotd 退出(sock QUIT → 等 pid 消失)
	hotspotdStatusFn func() (string, error) // 问 hotspotd STATUS
	ensureHotspotdFn func() error           // 按当前 owner 参数(重新)拉起 hotspotd
	wired            bool
}

var m4Owner = &m4OwnerMgr{}

// wireProd 接上生产实现(幂等; 单测在 tick 之前替换注入点)。
func (m *m4OwnerMgr) wireProd() {
	if m.wired {
		return
	}
	m.wired = true
	m.quitHotspotdFn = m4QuitHotspotd
	m.hotspotdStatusFn = m4HotspotdStatus
	m.ensureHotspotdFn = func() error {
		ensureDaemonRunning(hotspotdDaemon())
		return nil
	}
}

// readM4Owner 读开关。文件不存在 = 默认; 内容不认识 = 默认 + 日志(去重)。
func (m *m4OwnerMgr) readM4Owner() string {
	b, err := os.ReadFile(m4OwnerFile)
	v := strings.TrimSpace(string(b))
	switch v {
	case "go", "c":
		return v
	default:
		if os.IsNotExist(err) {
			return m4OwnerDefault
		}
		if v != m.lastBad {
			m.lastBad = v
			logf("m4_owner: 不认识的内容 %q, 用默认 %q", v, m4OwnerDefault)
		}
		return m4OwnerDefault
	}
}

// tick 主循环每轮调用(热点 ACTIVE 时 iface 非空)。
func (m *m4OwnerMgr) tick(iface string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wireProd()
	want := m.readM4Owner()
	// 每轮把生效值落到 run/, 调用方(device_detect.sh 等)只读这个文件,
	// 默认值的判断只存在于 Go 这一处(m4OwnerDefault)。
	_ = os.WriteFile(m4OwnerCurrentFile, []byte(want+"\n"), 0o644)
	if m.owner == "" {
		// 首拍: want=go 也走切换路径(先停后起) —— 开机时序里
		// service.sh/device_detect.sh 可能先拉起了不带 --no-discovery 的
		// hotspotd(读不到 m4_owner.current 或文件是上一次会话的), 这里
		// 统一纠偏, 保证任何时刻只有一个写者。
		if want == "go" && time.Now().After(m.failBackoffUntil) {
			m.owner = "c" // 占位成 c, switchOwnerLocked 走 c→go
			m.switchOwnerLocked("go", now)
		} else if want == "go" {
			m.owner = "c" // 退避窗口内: 先按 c(保守, 不动 hotspotd)
		} else {
			m.owner = want
		}
	} else if want != m.owner {
		if time.Now().Before(m.failBackoffUntil) {
			// 退避窗口内不重试(见 failBackoffUntil 注释); devices.json
			// 保留当前写者的版本, 下一轮再看。
		} else {
			m.switchOwnerLocked(want, now)
		}
	}
	m4OwnerCur.Store(m.owner)
	// 演练模式(run/wd_m4_drill 存在, T5 场景用): owner=c 时 Go 写者也跑,
	// 但 writeOut 只写 run/devices.go.json, 不碰 data/devices.json ——
	// 用于「全字段影子比对」, hotspotd 保持唯一正式写者。
	drill := fileExists(m4DrillFile)
	if m.owner != "go" && !drill {
		m.stopGoRunnerLocked("owner != go")
		return
	}
	if iface == "" {
		m.stopGoRunnerLocked("热点未激活")
		return
	}
	m.ensureGoRunnerLocked(iface)
}

// currentOwner 当前生效 owner(无锁读; 未初始化按 c 算, 保守)。
func (m *m4OwnerMgr) currentOwner() string {
	if v, ok := m4OwnerCur.Load().(string); ok && v == "go" {
		return "go"
	}
	return "c"
}

// isGo 当前生效 owner 是否为 go。
func (m *m4OwnerMgr) isGo() bool { return m.currentOwner() == "go" }

// switchOwnerLocked 切换(先停后起, 不重叠)。确认失败回滚并保持原 owner。
func (m *m4OwnerMgr) switchOwnerLocked(to string, now time.Time) {
	from := m.owner
	logf("m4_owner: 切换 %s → %s", from, to)
	if to == "go" {
		// 1) 先停 C 写者: hotspotd 退出, 换 --no-discovery 参数拉起
		if err := m.quitHotspotdFn(); err != nil {
			logf("m4_owner: 停 hotspotd 失败: %v, 保持 %s", err, from)
			m.failBackoffUntil = time.Now().Add(m4SwitchBackoff)
			return
		}
		m.owner = "go" // hotspotdDaemon() 从无锁快照取参数, 必须同步更新
		m4OwnerCur.Store(m.owner)
		_ = m.ensureHotspotdFn()
		// 2) 确认它真的停了(STATUS 回 discovery:0), 不行就回滚
		if !m.confirmDiscoveryOff() {
			logf("m4_owner: hotspotd 未确认停发现(STATUS 无 discovery:0), 回滚为 %s", from)
			m.owner = from
			m4OwnerCur.Store(from)
			_ = m.quitHotspotdFn()
			_ = m.ensureHotspotdFn()
			m.failBackoffUntil = time.Now().Add(m4SwitchBackoff)
			return
		}
		m.failBackoffUntil = time.Time{}
		m4Switches.Add(1)
		return
	}
	// to == "c": 先停 Go 写者(等当前这次写完), 再按原参数重启 hotspotd
	m.stopGoRunnerLocked("切换回 c")
	_ = m.quitHotspotdFn()
	m.owner = "c"
	m4OwnerCur.Store(m.owner)
	_ = m.ensureHotspotdFn()
	m.failBackoffUntil = time.Time{}
	m4Switches.Add(1)
}

// confirmDiscoveryOff 确认 hotspotd 真的停止发现(STATUS 带 discovery:0)。
func (m *m4OwnerMgr) confirmDiscoveryOff() bool {
	for i := 0; i < 5; i++ {
		if s, err := m.hotspotdStatusFn(); err == nil && strings.Contains(s, "discovery:0") {
			return true
		}
		if i < 4 {
			time.Sleep(300 * time.Millisecond)
		}
	}
	return false
}

// ─── Go 写者运行器 ────────────────────────────────────────────────

// m4NeighSource 订阅源(neigh.Sub 满足; 单测注入假实现)。
type m4NeighSource interface {
	Read() ([]neigh.Entry, error)
	Close() error
}

type m4GoRunner struct {
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

// start 由 owner 管理器调用(先解析 ifindex, 失败也照跑 —— 事件不按
// ifindex 过滤时全量兜底会跟上)。
func (r *m4GoRunner) start() {
	if r.ifIndexFn != nil {
		if idx, err := r.ifIndexFn(r.iface); err == nil {
			r.ifIdx = idx
		}
	}
	r.table.SetIface(r.iface, r.ifIdx)
	go r.run()
}

func (m *m4OwnerMgr) ensureGoRunnerLocked(iface string) {
	if m.runner != nil && m.runner.iface == iface {
		return
	}
	m.stopGoRunnerLocked("网卡变了")
	r := newM4GoRunner(iface)
	m.runner = r
	r.start()
}

func (m *m4OwnerMgr) stopGoRunnerLocked(reason string) {
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
	events := make(chan []neigh.Entry, 64)
	src, err := r.subscribeFn()
	if err != nil {
		logf("m4_owner: 订阅邻居表失败: %v(只靠 30s 全量兜底)", err)
	} else {
		go func() {
			defer src.Close()
			for {
				es, err := src.Read()
				if err != nil {
					return
				}
				select {
				case events <- es:
				case <-r.stopCh:
					return
				}
			}
		}()
	}

	var (
		dirty        bool
		firstDirtyMs int64 // 首次 dirty 的毫秒时刻(0 = 无)
		lastEventMs  int64
		lastWriteMs  int64
		lastWritten  []byte
		lastStatsAt  time.Time
		lastStatsMap = map[string][2]int64{}
		lastSync     = time.Now()
		lastPending  time.Time
		inFlightMu   sync.Mutex
		inFlight     = map[string]bool{}
	)
	tick := time.NewTicker(m4WriteHardRateMS * time.Millisecond)
	defer tick.Stop()
	monoMs := func() int64 { return time.Now().UnixNano() / int64(time.Millisecond) }
	// v5.31 T4: REFRESH / SIGUSR1 转发 —— hotspotd(--no-discovery)收到就
	// touch run/devices.refresh, 这里每拍(200ms)看一次 mtime, 变了立刻
	// 全量扫一次。device_detect.sh scan 的「1 秒内 devices.json mtime
	// 变了」判断因此照旧成立。
	var lastRefreshM = monoMs()
	refreshDue := func(now time.Time) bool {
		fi, err := os.Stat(m4RefreshFile)
		if err != nil {
			return false
		}
		m := fi.ModTime().UnixNano() / int64(time.Millisecond)
		if m > lastRefreshM { // 比上次见过的更新 = 有新的 REFRESH / SIGUSR1
			lastRefreshM = m
			return true
		}
		return false
	}

	for {
		select {
		case <-r.stopCh:
			if dirty {
				lastWritten = r.writeOut(lastWritten, &lastStatsAt, &lastStatsMap, true)
			}
			return
		case es := <-events:
			changed := false
			for _, e := range es {
				if r.table.Apply(e, time.Now()) {
					changed = true
				}
			}
			if changed {
				dirty = true
				lastEventMs = monoMs()
				if firstDirtyMs == 0 {
					firstDirtyMs = lastEventMs
				}
			}
		case <-tick.C:
			now := time.Now()
			// REFRESH / SIGUSR1(hotspotd touch)→ 立刻全量扫一次并强制写
			if refreshDue(now) {
				if es, err := r.dumpIfFn(r.ifIdx); err == nil {
					r.table.FullSync(es, now)
				}
				r.table.EvictOffline(now)
				lastWritten = r.writeOut(lastWritten, &lastStatsAt, &lastStatsMap, true)
				dirty = false
				firstDirtyMs = 0
				continue
			}
			// 30s: 全量兜底 + 离线检查 + 网卡重建跟上
			if now.Sub(lastSync) >= m4FullSyncEvery {
				lastSync = now
				r.refreshIface()
				if es, err := r.dumpIfFn(r.ifIdx); err == nil {
					if r.table.FullSync(es, now) {
						dirty = true
						lastEventMs = monoMs()
						if firstDirtyMs == 0 {
							firstDirtyMs = lastEventMs
						}
					}
				}
				if r.table.EvictOffline(now) > 0 {
					dirty = true
					if firstDirtyMs == 0 {
						firstDirtyMs = monoMs()
					}
				}
			}
			// 1s: pending 派发(最老优先, 喘息 ≥1s, 一次一台 —— 对齐
			// hotspotd process_pending_mdns; 解析在 goroutine 里, 不挡事件)
			if now.Sub(lastPending) >= time.Second {
				lastPending = now
				if mac, ip, ok := r.table.PendingDue(now); ok {
					inFlightMu.Lock()
					busy := inFlight[mac]
					if !busy {
						inFlight[mac] = true
					}
					inFlightMu.Unlock()
					if !busy {
						go func(mac, ip string) {
							hn, src := r.table.Full(mac, ip)
							r.table.ApplyResolution(mac, hn, src, time.Now())
							// v5.31 T2: 解析命中 dhcp/mdns 时缓存已
							// 在 Resolver 里标脏, 这里落一次盘(小文件,
							// 原子替换; 失败只记日志不计 devices 写失败)
							if err := r.resolver.CacheSave(); err != nil {
								logf("m4_owner: hostname_cache 落盘失败: %v", err)
							}
							inFlightMu.Lock()
							delete(inFlight, mac)
							inFlightMu.Unlock()
						}(mac, ip)
					}
				}
			}
			// 去抖写(rc30.9 算法, 见文件头)
			if dirty {
				if nowMs := monoMs(); m4ShouldWrite(firstDirtyMs, lastEventMs, lastWriteMs, nowMs) {
					lastWritten = r.writeOut(lastWritten, &lastStatsAt, &lastStatsMap, false)
					dirty = false
					firstDirtyMs = 0
					lastWriteMs = monoMs()
				}
			}
		}
	}
}

// refreshIface 同名网卡重建要跟上(hotspotd refresh_hotspot_iface 的教训):
// ifindex 变了就换表 + 全量跟上。
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

// writeOut 渲染 + 原子写。演练开关(run/wd_m4_drill)下写 run/devices.go.json,
// 只比对不接管。内容没变不写(省电)。
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
	if fileExists(m4DrillFile) {
		out, tmp = m4DrillOut, m4GoOutTmp
	}
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		m4GoWriteFails.Add(1)
		logf("m4_owner: 写 %s 失败: %v", tmp, err)
		return lastWritten
	}
	// 演练模式下也记(演练是给 T5 场景对照用的, 正式 / 演练都要可追溯)
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

// m4ShouldWrite rc30.9 de-bounce 的纯函数形态(hotspotd.c 主循环注释):
// 距上次写 ≥500ms 的首个事件立即写; 合并窗口 200ms 无新事件; 30s 兜底;
// <200ms 硬限速。
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

// macFallback hnc_mac_fallback 的等价实现: 去冒号取后 8 位。
func macFallback(mac string) string {
	nc := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(mac)), ":", "")
	if len(nc) > 8 {
		return nc[len(nc)-8:]
	}
	return nc
}

// runStatsAll `sh bin/iptables_manager.sh stats_all`(参数分开传, 3s 超时),
// 输出每行 "<ip> <rx> <tx>"。
func runStatsAll() (map[string][2]int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m4StatsTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, shBin, iptablesMgrPath, "stats_all")
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
	hotspotdSockP   = runDir + "/hotspotd.sock"
	hotspotdPidP    = runDir + "/hotspotd.pid"
)

// appendLine 追加一行(小文件, O_APPEND 单行原子; 失败忽略 —— 只是审计日志)。
func appendLine(p, line string) error {
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// m4QuitHotspotd sock QUIT → 等 pid 退出(≤5s)→ 兜底 SIGTERM。
func m4QuitHotspotd() error {
	if c, err := net.DialTimeout("unix", hotspotdSockP, time.Second); err == nil {
		_, _ = c.Write([]byte("QUIT\n"))
		buf := make([]byte, 16)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Read(buf)
		c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(hotspotdPidP)
		if err != nil {
			return nil
		}
		pid := 0
		fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid)
		if pid <= 0 {
			return nil
		}
		if err := syscall.Kill(pid, 0); err != nil {
			return nil // 进程不在了
		}
		time.Sleep(200 * time.Millisecond)
	}
	b, _ := os.ReadFile(hotspotdPidP)
	pid := 0
	fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid)
	if pid > 0 {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	return fmt.Errorf("hotspotd 5 秒内未退出, 已发 SIGTERM")
}

// m4HotspotdStatus 问 STATUS(2s 超时)。
func m4HotspotdStatus() (string, error) {
	c, err := net.DialTimeout("unix", hotspotdSockP, time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("STATUS\n")); err != nil {
		return "", err
	}
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}
