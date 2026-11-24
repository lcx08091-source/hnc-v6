// Package devscan —— v5.31 T1(迁移 M4 方案 A): Go 版设备发现的核心表逻辑。
//
// 语义与 hotspotd(C)对齐: 在线语义(条目可用就刷新 last_seen)、90 秒离线、
// devices.json 的字段与取值。同一 MAC 多个表项(换 IP 期间旧表项还在)挑 IP:
// 内核最近一次确认可达的那条(NDA_CACHEINFO 的 confirmed), 打平时才看状态
// REACHABLE > DELAY > PROBE > STALE。v5.32 审查前是「状态优先」—— 模拟设备上
// 换 IP 后网关还有流量去找旧 IP 时, 旧表项进 PROBE(排在 STALE 前)就把 IP 抢回去,
// 旧表项随后 FAILED 的通知不带 MAC、认不出是谁, 设备就一直报着那个失效的 IP。
// PROBE / DELAY 只说明网关在怀疑这条表项, 不是设备在用它的证据; 只有「确认」是。
// v5.32 起 hotspotd 的事件路径与全量重扫也按同一条规则(hotspotd.c ip_should_switch)。
//
// 本包只做表逻辑(纯内存 + 可注入的解析钩子), 不碰 socket / 文件 / 时钟:
//   - Apply: 一条邻居表事件(netlink 订阅)→ 表更新;
//   - FullSync: 一次全量 dump → 补漏(事件丢了也能追上)。只把「新表项 /
//     状态变了」当事件 —— 静默 STALE 不刷 last_seen, 否则设备永远不 offline,
//     90 秒离线语义(hotspotd OFFLINE_THRESHOLD)就被破坏了;
//   - EvictOffline: 每 30 秒一次的离线检查(90 秒未活跃 → 移出);
//   - RenderJSON: 渲染 devices.json 内容(只含在线设备, 字段与 C 相同)。
//
// 名字解析通过钩子注入(Fast / Full), 由看门狗的 m4_owner.go 提供(T2 起接
// src/dpid/devname); 单测注入假实现。订阅 / 去抖 / 写文件都在看门狗侧,
// 本包保持纯逻辑。
package devscan

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"hnc.io/dpid/neigh"
)

// 与 hotspotd 同名同值的语义常量(这是跨文件约定, 改动需同时改 C 侧并过 T5 影子比对)。
const (
	// OfflineThreshold 90 秒未活跃 = 离线(hotspotd.c OFFLINE_THRESHOLD)。
	OfflineThreshold = 90 * time.Second
	// MaxDevices 设备表上限(hotspotd.c MAX_DEVICES); 满了淘汰最旧条目。
	MaxDevices = 128
	// ReResolveWindow 已知设备重新解析名字的窗口(hnc_should_re_resolve: >= 60 秒)。
	ReResolveWindow = 60 * time.Second
	// PendingBreathingRoom pending 设备派发异步解析前的喘息
	// (hnc_helpers.h HNC_PENDING_BREATHING_ROOM_SEC = 1 秒, 给 netlink 事件留缓冲)。
	PendingBreathingRoom = 1 * time.Second
	// MaxAsyncResolveRetries 同 IP 下针对 mac/oui/cache-* 设备的后台异步重查上限(换 IP 或清手动名重置)。
	MaxAsyncResolveRetries = 2
)

// Linux 邻居表状态(netlink ndmsg.ndm_state, 内核 ABI 值)。neigh 包只导出了
// Usable() 一个判断, 这里的值与 include/uapi/linux/neighbour.h 一致。
const (
	nudReachable = 0x02
	nudStale     = 0x04
	nudDelay     = 0x08
	nudProbe     = 0x10
	nudFailed    = 0x20
)

// Device devices.json 里一台设备的字段(顺序、名字与 hotspotd.c write_json 相同)。
type Device struct {
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Hostname    string `json:"hostname"`
	HostnameSrc string `json:"hostname_src"`
	Iface       string `json:"iface"`
	RXBytes     int64  `json:"rx_bytes"`
	TXBytes     int64  `json:"tx_bytes"`
	Status      string `json:"status"`
	LastSeen    int64  `json:"last_seen"`
}

// device Device 加上不进 JSON 的记账字段。
type device struct {
	Device
	lastResolve     int64  // 上次发起解析(unix 秒)
	pendingSince    int64  // 进入 pending 的时刻(unix 秒; >= PendingBreathingRoom 才派发)
	reResolveForce  bool   // 手动名被删除后允许用新解析结果替换
	resolveRetryIP  string // 当前异步重查计数绑定的主 IP
	resolveRetries  int    // 同 IP 下已消耗的后台异步重试次数(<= MaxAsyncResolveRetries)
	initialResolved bool   // 是否已完成首次全链解析(区分新设备首次解析与非首次后台重查)
}

// cand 一个 (MAC, IP) 表项的候选状态(换 IP 期间旧表项还在)。
type cand struct {
	state     uint16
	lastEvent time.Time // 同状态取最近一次确认的(内核 NDA_CACHEINFO 的 confirmed; 没有就是事件时刻)
}

// Table 设备表: MAC(小写)→ 设备, 外加每个 MAC 的候选表项集合。
type Table struct {
	mu      sync.Mutex
	iface   string
	ifIndex int
	devs    map[string]*device
	cands   map[string]map[string]cand

	// Fast 新设备的快速解析(manual → MAC 兜底), 对齐 hnc_resolve_hostname_fast:
	// 事件回调里同步调, 必须快(不许碰网络 / 子进程)。
	Fast func(mac string) (hostname, src string)
	// Full pending 设备的完整解析链(manual → DHCP → mDNS → 缓存 → 厂商 → MAC,
	// 对齐 resolve_hostname 的 1–6 级)。异步调用, 不在事件循环里。
	Full func(mac, ip string) (hostname, src string)
	// Quiet 息屏静默期判断钩子: 返回 true 时暂停非首次后台重查(新设备首次解析不受影响)。
	Quiet func() bool
}

// NewTable 建表。iface 是热点网卡名; ifIndex 0 = 还不知道(事件不按 ifindex 过滤)。
func NewTable(iface string, ifIndex int) *Table {
	return &Table{
		iface:   iface,
		ifIndex: ifIndex,
		devs:    map[string]*device{},
		cands:   map[string]map[string]cand{},
	}
}

// SetIface 热点网卡重建(同名不同 ifindex)时跟上(hotspotd refresh_hotspot_iface 的教训)。
func (t *Table) SetIface(iface string, ifIndex int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.iface, t.ifIndex = iface, ifIndex
}

// Iface 返回当前网卡名与 ifindex。
func (t *Table) Iface() (string, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.iface, t.ifIndex
}

// Count 当前在线设备数(给 STATUS 用, 对齐 hotspotd 的 g_ndev)。
func (t *Table) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.devs)
}

// normMAC 事件里的 MAC 规范化: 小写、去空白; 非法(长度不对 / 全零)返回空串。
func normMAC(mac string) string {
	m := strings.ToLower(strings.TrimSpace(mac))
	if len(m) != 17 || m == "00:00:00:00:00:00" {
		return ""
	}
	return m
}

// entryIP 事件的 IPv4(字符串); 非 IPv4 / 空 → ""(主条目 IP 只认 IPv4)。
func entryIP(e neigh.Entry) string {
	if e.IP == nil || e.IP.To4() == nil {
		return ""
	}
	return e.IP.To4().String()
}

func isIPv6Entry(e neigh.Entry) bool {
	return len(e.IP) > 0 && e.IP.To4() == nil && e.IP.To16() != nil && !e.IP.IsUnspecified() && !e.IP.IsMulticast()
}

// refreshIPv6OnlineLocked 对同热点口可达(NUD_REACHABLE)IPv6 邻居刷新已有 IPv4 在线设备的 LastSeen;
// 严禁为尚未获得 IPv4 的纯 IPv6 邻居新建空 IP 条目。
func (t *Table) refreshIPv6OnlineLocked(mac string, e neigh.Entry, now time.Time) bool {
	if mac == "" || e.State&nudReachable == 0 || e.ConfirmedAgo > OfflineThreshold {
		return false
	}
	d := t.devs[mac]
	if d == nil || d.IP == "" {
		return false
	}
	seen := now
	if e.ConfirmedAgo > 0 {
		seen = now.Add(-e.ConfirmedAgo)
	}
	seenUnix := seen.Unix()
	if seenUnix <= d.LastSeen {
		return false
	}
	d.LastSeen = seenUnix
	d.Iface = t.iface
	return true
}

func (d *device) syncMainIP(best string) bool {
	if best == "" || best == d.IP {
		if d.resolveRetryIP == "" && best != "" {
			d.resolveRetryIP = best
		}
		return false
	}
	prev := d.IP
	d.IP = best
	if prev != "" {
		d.resolveRetryIP = best
		d.resolveRetries = 0
	} else if d.resolveRetryIP == "" {
		d.resolveRetryIP = best
	}
	return true
}

// stateRank 状态优先级(WORK-v5.31 §4 T1): REACHABLE > DELAY > PROBE > STALE。
// v5.32 审查起只在确认时刻打平时用(见 pickIP)。
func stateRank(s uint16) int {
	switch s {
	case nudReachable:
		return 4
	case nudStale:
		return 3
	case nudDelay:
		return 2
	case nudProbe:
		return 1
	}
	return 0
}

// pickIP 从候选表项里挑 IP: 内核最近一次确认可达的那条; 确认时刻相同再看状态,
// 再相同取 IP 字典序小的(只为结果确定, 与 map 遍历顺序无关)。
func pickIP(cs map[string]cand) string {
	best, bestRank, bestAt := "", -1, time.Time{}
	for ip, c := range cs {
		r := stateRank(c.state)
		if best == "" || c.lastEvent.After(bestAt) ||
			(c.lastEvent.Equal(bestAt) && (r > bestRank || (r == bestRank && ip < best))) {
			best, bestRank, bestAt = ip, r, c.lastEvent
		}
	}
	return best
}

// Apply 一条邻居表事件(来自订阅)。返回表是否变化(变化 = 该写 devices.json)。
//
// 语义对齐 hotspotd.c nl_process:
//   - 非热点 ifindex 忽略; 全零 MAC 忽略;
//   - 同热点口可达 IPv6 邻居仅刷新已有 IPv4 在线设备的 LastSeen(禁建空 IP 条目);
//   - IPv4 表项可用(REACHABLE / STALE / DELAY / PROBE)→ 上线或更新: 刷新
//     last_seen、重挑 IP、按 60 秒窗口与同 IP 重试上限重解析名字;
//   - FAILED → 去掉这条候选, 一条不剩才下线(通知不带 MAC 时按 IP 找, 见
//     failIPLocked; v5.32 审查);
//   - 表项被回收(RTM_DELNEIGH, 非 FAILED)→ 只去掉这条候选, 不下线, 剩余候选重挑主 IP。
func (t *Table) Apply(e neigh.Entry, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ifIndex != 0 && e.IfIndex != 0 && e.IfIndex != t.ifIndex {
		return false // 非热点网卡
	}
	mac := normMAC(e.MAC)
	ip := entryIP(e)
	if !e.Deleted && e.Usable() {
		if mac == "" {
			return false
		}
		if ip == "" {
			if isIPv6Entry(e) && e.State&nudReachable != 0 {
				return t.refreshIPv6OnlineLocked(mac, e, now)
			}
			return false
		}
		seen := t.candidateSeenTimeLocked(mac, ip, e, now)
		return t.applyOnlineLocked(mac, ip, e.State, now, seen)
	}
	// 下线路径: FAILED(网关去找它, 没人应答)移除候选并按需下线/切 IP。
	if e.State&nudFailed != 0 {
		return t.failIPLocked(mac, ip)
	}
	// 表项被回收(RTM_DELNEIGH, 内核常不带 NDA_LLADDR 即 mac==""): 按 IP 清理所有候选并重挑主 IP。
	if e.Deleted && ip != "" {
		changed := false
		for m, cs := range t.cands {
			if mac != "" && m != mac {
				continue
			}
			if _, ok := cs[ip]; ok {
				delete(cs, ip)
				if d := t.devs[m]; d != nil && len(cs) > 0 {
					if best := pickIP(cs); d.syncMainIP(best) {
						changed = true
					}
				}
			}
		}
		return changed
	}
	return false
}

// failIPLocked 一条 FAILED(调用方持锁)。v5.32 审查: 内核在表项失效时不带链路地址,
// 通知里没有 MAC(模拟设备上实测)—— 原来按 MAC 找、找不到就丢, FAILED 从没生效过,
// 走了的设备只能等 90 秒离线; 换 IP 后旧 IP 被网关探测失效也认不出是谁。现在没有
// MAC 时按 IP 找: 当前 IP 或候选里有这个 IP 的设备都去掉这条候选; 一条不剩就下线,
// 否则重挑(典型: 刚换了 IP, 旧 IP 失效 → 用新 IP)。与 hotspotd 的 mark_ip_failed +
// 核实扫描同一语义。
func (t *Table) failIPLocked(mac, ip string) bool {
	if ip == "" {
		return false
	}
	var macs []string
	if mac != "" {
		if t.devs[mac] != nil {
			macs = append(macs, mac)
		}
	} else {
		for m, d := range t.devs {
			if _, ok := t.cands[m][ip]; ok || d.IP == ip {
				macs = append(macs, m)
			}
		}
	}
	changed := false
	for _, m := range macs {
		d, cs := t.devs[m], t.cands[m]
		delete(cs, ip)
		if len(cs) == 0 {
			delete(t.devs, m)
			delete(t.cands, m)
			changed = true
			continue
		}
		// 还有别的表项(典型: 刚换了 IP, 旧表项 FAILED): 重挑, 不下线。
		if best := pickIP(cs); d.syncMainIP(best) {
			changed = true
		}
	}
	return changed
}

// applyOnlineLocked 上线或更新(调用方持锁)。seen = 内核最近一次确认该表项的时刻。
// v5.31 审查修复: 原来一律记成 now —— 全量扫(起写者 / 30 秒兜底)时新旧两条 STALE 表项
// 「同状态同时刻」, 挑哪个 IP 看 map 遍历顺序, 换过 IP 的设备随机报旧 IP。
// candidateSeenTimeLocked 解决免费 ARP 新表项 ndm_confirmed=-60s 惩罚与旧表项 DELAY/PROBE 时钟抖动反超问题:
// 1. 新建 NUD_STALE 表项(如设备换 IP 发的免费 ARP): 内核 neigh_alloc 把 confirmed 设在 60 秒前, 改用 UpdatedAgo 还原真实到包时刻;
// 2. 已存在表项进入 STALE/DELAY/PROBE(老化或网关单向探测, 无对端应答): 严格冻结已有 lastEvent, 绝不因通道调度延迟推进时间戳。
func (t *Table) candidateSeenTimeLocked(mac, ip string, e neigh.Entry, now time.Time) time.Time {
	prev, exists := t.cands[mac][ip]
	if e.State&nudReachable != 0 {
		seen := now.Add(-e.ConfirmedAgo)
		if exists && seen.Sub(prev.lastEvent) > 0 && seen.Sub(prev.lastEvent) < 250*time.Millisecond && prev.state&nudReachable != 0 {
			return prev.lastEvent
		}
		return seen
	}
	if !exists {
		if e.State&nudStale != 0 && e.HasCacheInfo {
			return now.Add(-e.UpdatedAgo)
		}
		return now.Add(-e.ConfirmedAgo)
	}
	return prev.lastEvent
}

// hostnameSrcRank 主机名来源优先级(数值越高越可信), 用于重解析防降级。
func hostnameSrcRank(src string) int {
	switch {
	case src == "manual":
		return 5
	case src == "dhcp", src == "dhcpv6", src == "mdns", src == "nbns":
		return 4
	case strings.HasPrefix(src, "cache-"):
		return 3
	case src == "oui":
		return 2
	case src == "mac":
		return 1
	default: // "", "pending"
		return 0
	}
}

func (d *device) isPending() bool {
	return d.HostnameSrc == "pending" || d.pendingSince > 0
}

func (t *Table) applyOnlineLocked(mac, ip string, state uint16, now, seen time.Time) bool {
	nowUnix := now.Unix()
	cs := t.cands[mac]
	if cs == nil {
		cs = map[string]cand{}
		t.cands[mac] = cs
	}
	cs[ip] = cand{state: state, lastEvent: seen}
	best := pickIP(cs)

	d := t.devs[mac]
	if d == nil {
		if len(t.devs) >= MaxDevices {
			t.evictOldestLocked()
		}
		d = &device{Device: Device{MAC: mac, Iface: t.iface}}
		if best != "" {
			d.IP = best
			d.resolveRetryIP = best
		}
		hn, src := "00000000", "mac"
		if t.Fast != nil {
			hn, src = t.Fast(mac)
		}
		if src == "mac" {
			src = "pending" // 对齐 C: mac 兜底 → 挂 pending, 等首次异步解析
			d.pendingSince = nowUnix
			d.initialResolved = false
		} else {
			d.initialResolved = true
		}
		d.Hostname, d.HostnameSrc = hn, src
		d.lastResolve = nowUnix
		t.devs[mac] = d
	} else {
		if best != "" {
			d.syncMainIP(best)
		}
		if now.Sub(time.Unix(d.lastResolve, 0)) >= ReResolveWindow {
			quiet := t.Quiet != nil && t.Quiet()
			// 严格遵守 60s ReResolveWindow 冷却; 已有有效主机名时不降级为 MAC 兜底/pending。
			hn, src := "00000000", "mac"
			if t.Fast != nil {
				hn, src = t.Fast(mac)
			}
			if src != "mac" {
				d.Hostname, d.HostnameSrc = hn, src
				d.pendingSince = 0
				d.reResolveForce = false
				d.initialResolved = true
				d.resolveRetries = 0
				d.resolveRetryIP = d.IP
			} else if d.HostnameSrc == "" || d.HostnameSrc == "pending" {
				d.Hostname, d.HostnameSrc = hn, "pending"
				if d.pendingSince == 0 {
					d.pendingSince = nowUnix
				}
			} else if d.HostnameSrc == "manual" {
				// 用户已删除手动名: 重置同 IP 重试计数, 保留当前展示名不闪烁 MAC, 异步重解析后允许替换
				d.reResolveForce = true
				d.resolveRetries = 0
				d.resolveRetryIP = d.IP
				if d.pendingSince == 0 {
					d.pendingSince = nowUnix
				}
			} else if d.HostnameSrc == "mac" || hostnameSrcRank(d.HostnameSrc) < 4 {
				// mac / oui / cache-* 后台重查: 同 IP 最多重试 MaxAsyncResolveRetries(2) 次, 息屏静默期暂停非首次重查
				if d.resolveRetryIP != d.IP {
					d.resolveRetryIP = d.IP
					d.resolveRetries = 0
				}
				if !quiet && d.resolveRetries < MaxAsyncResolveRetries {
					if d.pendingSince == 0 {
						d.pendingSince = nowUnix
					}
				}
			}
			d.lastResolve = nowUnix
		}
	}
	d.Iface = t.iface
	d.LastSeen = nowUnix
	return true
}

// evictOldestLocked 表满淘汰最旧条目(对齐 alloc_device 的表满路径)。
func (t *Table) evictOldestLocked() {
	oldestMac := ""
	var oldest int64 = -1
	for mac, d := range t.devs {
		if oldest == -1 || d.LastSeen < oldest {
			oldestMac, oldest = mac, d.LastSeen
		}
	}
	if oldestMac != "" {
		delete(t.devs, oldestMac)
		delete(t.cands, oldestMac)
	}
}

// FullSync 一次全量 dump 补漏(每 30 秒; 事件丢了也能追上)。
//
// 只有「新表项 / 状态变了」按事件处理; 已知且未变的表项完全跳过 —— 不刷
// last_seen, 这样静默 STALE 的设备 90 秒后仍会离线(C 没有全量兜底, 这个
// 行为与 C 一致)。dump 里的 FAILED 表项走下线路径(丢事件兜底); 快照中已消失的
// 旧 IPv4 候选从 cands 剔除并重挑剩余有效主 IP。
func (t *Table) FullSync(es []neigh.Entry, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := false
	present := make(map[string]map[string]struct{})
	sawIPv4 := false
	sawIPv6 := false
	for _, e := range es {
		mac := normMAC(e.MAC)
		if t.ifIndex != 0 && e.IfIndex != 0 && e.IfIndex != t.ifIndex {
			continue
		}
		ip := entryIP(e)
		if ip != "" {
			sawIPv4 = true
		} else if isIPv6Entry(e) {
			sawIPv6 = true
		}
		if e.Deleted || !e.Usable() {
			// FAILED 且还有设备认这个 IP → 补一次 FAILED(事件丢了也能追上; FAILED
			// 表项不带 MAC, 按 IP 找, 见 failIPLocked)。已处理过的再遇到是空操作。
			if e.State&nudFailed != 0 && t.failIPLocked(mac, ip) {
				changed = true
			}
			continue
		}
		if mac == "" {
			continue
		}
		if ip == "" {
			if isIPv6Entry(e) && e.State&nudReachable != 0 && t.refreshIPv6OnlineLocked(mac, e, now) {
				changed = true
			}
			continue
		}
		pm := present[mac]
		if pm == nil {
			pm = make(map[string]struct{})
			present[mac] = pm
		}
		pm[ip] = struct{}{}
		if c, ok := t.cands[mac][ip]; ok && c.state == e.State {
			continue // 已知且未变: 静默 STALE 不刷 last_seen
		}
		seen := t.candidateSeenTimeLocked(mac, ip, e, now)
		if t.applyOnlineLocked(mac, ip, e.State, now, seen) {
			changed = true
		}
	}

	// 剔除本次 IPv4 快照中已消失的候选 cands 并重挑剩余有效主 IP(纯 IPv6 单栈切片不误删 IPv4 候选)。
	if !(sawIPv6 && !sawIPv4) {
		for m, cs := range t.cands {
			pm := present[m]
			removed := false
			for cip := range cs {
				if _, ok := pm[cip]; !ok {
					delete(cs, cip)
					removed = true
				}
			}
			if len(cs) == 0 {
				delete(t.cands, m)
				continue
			}
			if removed {
				if d := t.devs[m]; d != nil {
					if best := pickIP(cs); d.syncMainIP(best) {
						changed = true
					}
				}
			}
		}
	}
	return changed
}

// EvictOffline 离线检查(每 30 秒一次; 语义 = hotspotd 主循环
// R-13: now - last_seen > OfflineThreshold 的设备移出)。返回移出数量。
func (t *Table) EvictOffline(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for mac, d := range t.devs {
		if now.Sub(time.Unix(d.LastSeen, 0)) > OfflineThreshold {
			delete(t.devs, mac)
			delete(t.cands, mac)
			n++
		}
	}
	return n
}

// PendingDue 找一个该派发异步解析的 pending 设备(对齐 process_pending_mdns:
// 挂 pending >= 1 秒、取最老的; 一次只派一个)。返回 (mac, ip, ok)。
func (t *Table) PendingDue(now time.Time) (string, string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	quiet := t.Quiet != nil && t.Quiet()
	mac, ip := "", ""
	var oldest int64 = -1
	for m, d := range t.devs {
		if !d.isPending() {
			continue
		}
		if quiet && d.initialResolved && !d.reResolveForce {
			// 息屏静默期停非首次重查, 撤销排队恢复慢拍且不消耗重试配额
			d.pendingSince = 0
			continue
		}
		if now.Sub(time.Unix(d.pendingSince, 0)) < PendingBreathingRoom {
			continue
		}
		if oldest == -1 || d.pendingSince < oldest {
			oldest, mac, ip = d.pendingSince, m, d.IP
		}
	}
	return mac, ip, mac != ""
}

// HasPending 表里是否还有 pending 设备(还没解析出名字的)。
// v5.32 T4: 写者主循环用它判断「有待解析的名字」→ 保持 200ms 快拍。
func (t *Table) HasPending() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	quiet := t.Quiet != nil && t.Quiet()
	for _, d := range t.devs {
		if !d.isPending() {
			continue
		}
		if quiet && d.initialResolved && !d.reResolveForce {
			continue
		}
		return true
	}
	return false
}

// ApplyResolution 异步解析完成回填(一次一条)。名字级别 / 取值由调用方
// (devname)保证与本表语义一致(manual/dhcp/mdns/cache-*/oui/mac)。
func (t *Table) ApplyResolution(mac, hostname, src string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := normMAC(mac)
	d := t.devs[m]
	if d == nil {
		return false
	}
	wasInitial := !d.initialResolved
	wasForce := d.reResolveForce
	if hostname == "" || src == "" {
		if !wasInitial {
			d.pendingSince = 0
			d.lastResolve = now.Unix()
			if !wasForce && d.resolveRetryIP == d.IP && d.resolveRetries < MaxAsyncResolveRetries {
				d.resolveRetries++
			}
		}
		return false // 设备已走 / 结果为空: 丢弃
	}
	d.pendingSince = 0
	d.lastResolve = now.Unix()
	d.initialResolved = true
	if d.resolveRetryIP == "" {
		d.resolveRetryIP = d.IP
	}
	if !wasInitial && !wasForce {
		if hostnameSrcRank(src) >= 4 {
			d.resolveRetries = 0
		} else if d.resolveRetryIP == d.IP {
			d.resolveRetries++
		}
	} else {
		d.resolveRetries = 0
		d.resolveRetryIP = d.IP
	}
	if !d.reResolveForce && hostnameSrcRank(d.HostnameSrc) >= 2 && hostnameSrcRank(src) < hostnameSrcRank(d.HostnameSrc) {
		return false // 重解析不降级已有有效主机名
	}
	d.reResolveForce = false
	changed := d.Hostname != hostname || d.HostnameSrc != src
	d.Hostname, d.HostnameSrc = hostname, src
	return changed
}

// RenderJSON 渲染 devices.json 内容(只含在线设备; 字段与 hotspotd.c write_json
// 相同; MAC 小写; 按 MAC 排序输出 —— C 是槽位序, JSON 对象无序, 解析方不受
// 影响, 排序是为了「内容没变不写」的去抖比对确定)。stats 按 IP 填 rx/tx
// (对齐 C 的 update_traffic_stats 匹配方式), blacklist 命中 → status=blocked。
func (t *Table) RenderJSON(stats map[string][2]int64, blacklist map[string]bool) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]Device, len(t.devs))
	for mac, d := range t.devs {
		c := d.Device
		if s, ok := stats[c.IP]; ok {
			c.RXBytes, c.TXBytes = s[0], s[1]
		}
		if blacklist[mac] {
			c.Status = "blocked"
		} else {
			c.Status = "allowed"
		}
		out[mac] = c
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // C 的 hnc_json_escape 不转义 <>&, 保持一致
	if err := enc.Encode(out); err != nil {
		return []byte("{}")
	}
	b := buf.Bytes()
	return b[:len(b)-1] // Encoder 会补一个换行, 去掉(C 的输出没有)
}

// SnapshotMACIP 拷贝当前在线设备的 MAC(小写) → IPv4 映射, 供纯 Go 流量统计聚合双栈字节。
func (t *Table) SnapshotMACIP() map[string]string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]string, len(t.devs))
	for mac, d := range t.devs {
		if mac != "" && d.IP != "" {
			out[mac] = d.IP
		}
	}
	return out
}

// RenderFlat 渲染三列纯文本 "<mac>\t<ipv4>\t<iface>\n"(按 MAC 字典序排序, 过滤非法控制字符),
// 供 Shell 脚本经 read 零正则高速读取。
func (t *Table) RenderFlat() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.devs) == 0 {
		return nil
	}
	macs := make([]string, 0, len(t.devs))
	for mac := range t.devs {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	var buf bytes.Buffer
	for _, mac := range macs {
		d := t.devs[mac]
		cm := sanitizeFlatField(mac)
		cip := sanitizeFlatField(d.IP)
		cif := sanitizeFlatField(d.Iface)
		if cm == "" || cip == "" {
			continue
		}
		buf.WriteString(cm)
		buf.WriteByte('\t')
		buf.WriteString(cip)
		buf.WriteByte('\t')
		buf.WriteString(cif)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func sanitizeFlatField(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
