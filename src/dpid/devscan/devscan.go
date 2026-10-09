// Package devscan —— v5.31 T1(迁移 M4 方案 A): Go 版设备发现的核心表逻辑。
//
// 语义与 hotspotd(C)对齐: 在线语义(条目可用就刷新 last_seen)、90 秒离线、
// devices.json 的字段与取值。唯一按 WORK-v5.31 §4 T1 明确要求与 C 不同的地方:
// 同一 MAC 多个表项(换 IP 期间旧表项还在)按状态挑 IP ——
// REACHABLE > DELAY > PROBE > STALE, 同状态取最近一次事件
// (C 是「最后一个事件直接覆盖」, 见 hotspotd.c nl_process)。
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
	// OfflineCheckInterval 每 30 秒检查一次离线(hotspotd.c OFFLINE_CHECK_INTERVAL)。
	OfflineCheckInterval = 30 * time.Second
	// OfflineThreshold 90 秒未活跃 = 离线(hotspotd.c OFFLINE_THRESHOLD)。
	OfflineThreshold = 90 * time.Second
	// MaxDevices 设备表上限(hotspotd.c MAX_DEVICES); 满了淘汰最旧条目。
	MaxDevices = 128
	// ReResolveWindow 已知设备重新解析名字的窗口(hnc_should_re_resolve: >= 60 秒)。
	ReResolveWindow = 60 * time.Second
	// PendingBreathingRoom pending 设备派发异步解析前的喘息
	// (hnc_helpers.h HNC_PENDING_BREATHING_ROOM_SEC = 1 秒, 给 netlink 事件留缓冲)。
	PendingBreathingRoom = 1 * time.Second
)

// Linux 邻居表状态(netlink ndmsg.ndm_state, 内核 ABI 值)。neigh 包只导出了
// Usable() 一个判断, 这里的值与 include/uapi/linux/neighbour.h 一致。
const (
	nudIncomplete = 0x01
	nudReachable  = 0x02
	nudStale      = 0x04
	nudDelay      = 0x08
	nudProbe      = 0x10
	nudFailed     = 0x20
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
	lastResolve  int64 // 上次发起解析(unix 秒)
	pendingSince int64 // 进入 pending 的时刻(unix 秒; >= PendingBreathingRoom 才派发)
}

// cand 一个 (MAC, IP) 表项的候选状态(换 IP 期间旧表项还在)。
type cand struct {
	state     uint16
	lastEvent time.Time // 同状态取最近一次事件
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

// entryIP 事件的 IPv4(字符串); 非 IPv4 / 空 → ""(与 C 一样只认 IPv4)。
func entryIP(e neigh.Entry) string {
	if e.IP == nil || e.IP.To4() == nil {
		return ""
	}
	return e.IP.To4().String()
}

// stateRank 状态优先级(WORK-v5.31 §4 T1): REACHABLE > DELAY > PROBE > STALE。
func stateRank(s uint16) int {
	switch s {
	case nudReachable:
		return 4
	case nudDelay:
		return 3
	case nudProbe:
		return 2
	case nudStale:
		return 1
	}
	return 0
}

// pickIP 从候选表项里挑 IP: 状态优先级, 同状态取最近一次事件。
func pickIP(cs map[string]cand) string {
	best, bestRank, bestAt := "", -1, time.Time{}
	for ip, c := range cs {
		r := stateRank(c.state)
		if r > bestRank || (r == bestRank && c.lastEvent.After(bestAt)) {
			best, bestRank, bestAt = ip, r, c.lastEvent
		}
	}
	return best
}

// Apply 一条邻居表事件(来自订阅)。返回表是否变化(变化 = 该写 devices.json)。
//
// 语义对齐 hotspotd.c nl_process:
//   - 非热点 ifindex 忽略; 全零 MAC / 非 IPv4 忽略;
//   - 表项可用(REACHABLE / STALE / DELAY / PROBE)→ 上线或更新: 刷新
//     last_seen、重挑 IP、按 60 秒窗口重解析名字;
//   - 表项不可用(含 RTM_DELNEIGH)→ 只有 FAILED / INCOMPLETE 才真正下线;
//     其余不动。
func (t *Table) Apply(e neigh.Entry, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ifIndex != 0 && e.IfIndex != 0 && e.IfIndex != t.ifIndex {
		return false // 非热点网卡
	}
	mac := normMAC(e.MAC)
	if mac == "" {
		return false
	}
	ip := entryIP(e)
	if !e.Deleted && e.Usable() {
		if ip == "" {
			return false
		}
		return t.applyOnlineLocked(mac, ip, e.State, now)
	}
	// 下线路径
	if e.State&(nudFailed|nudIncomplete) == 0 {
		return false // hotspotd: 只有 FAILED / INCOMPLETE 才真正下线
	}
	d := t.devs[mac]
	if d == nil {
		return false
	}
	cs := t.cands[mac]
	if ip != "" {
		delete(cs, ip)
	}
	if len(cs) == 0 {
		delete(t.devs, mac)
		delete(t.cands, mac)
		return true
	}
	// 还有别的表项(典型: 换 IP 后新表项在, 旧表项 FAILED): 重挑, 不下线。
	if best := pickIP(cs); best != "" && best != d.IP {
		d.IP = best
		return true
	}
	return false
}

// applyOnlineLocked 上线或更新(调用方持锁)。
func (t *Table) applyOnlineLocked(mac, ip string, state uint16, now time.Time) bool {
	nowUnix := now.Unix()
	cs := t.cands[mac]
	if cs == nil {
		cs = map[string]cand{}
		t.cands[mac] = cs
	}
	cs[ip] = cand{state: state, lastEvent: now}

	d := t.devs[mac]
	if d == nil {
		if len(t.devs) >= MaxDevices {
			t.evictOldestLocked()
		}
		d = &device{Device: Device{MAC: mac, Iface: t.iface}}
		hn, src := "00000000", "mac"
		if t.Fast != nil {
			hn, src = t.Fast(mac)
		}
		if src == "mac" {
			src = "pending" // 对齐 C: mac 兜底 → 挂 pending, 等异步解析
			d.pendingSince = nowUnix
		}
		d.Hostname, d.HostnameSrc = hn, src
		d.lastResolve = nowUnix
		t.devs[mac] = d
	} else if d.HostnameSrc == "mac" || now.Sub(time.Unix(d.lastResolve, 0)) >= ReResolveWindow {
		// 对齐 C: dhcp_only 先把名字降回 manual/mac, 命中更好来源时异步升级。
		hn, src := "00000000", "mac"
		if t.Fast != nil {
			hn, src = t.Fast(mac)
		}
		if src == "mac" {
			src = "pending"
			d.pendingSince = nowUnix
		}
		d.Hostname, d.HostnameSrc = hn, src
		d.lastResolve = nowUnix
	}
	if best := pickIP(cs); best != "" {
		d.IP = best
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
// 行为与 C 一致)。dump 里的 FAILED / INCOMPLETE 表项走下线路径(丢事件兜底)。
func (t *Table) FullSync(es []neigh.Entry, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := false
	for _, e := range es {
		mac := normMAC(e.MAC)
		if mac == "" {
			continue
		}
		if t.ifIndex != 0 && e.IfIndex != 0 && e.IfIndex != t.ifIndex {
			continue
		}
		ip := entryIP(e)
		if e.Deleted || !e.Usable() {
			// FAILED / INCOMPLETE 且该设备当前确实在线 → 补一次下线事件
			if e.State&(nudFailed|nudIncomplete) == 0 || ip == "" {
				continue
			}
			if d := t.devs[mac]; d != nil {
				delete(t.cands[mac], ip)
				if len(t.cands[mac]) == 0 {
					delete(t.devs, mac)
					delete(t.cands, mac)
				} else if best := pickIP(t.cands[mac]); best != "" && best != d.IP {
					d.IP = best
				}
				changed = true
			}
			continue
		}
		if ip == "" {
			continue
		}
		if c, ok := t.cands[mac][ip]; ok && c.state == e.State {
			continue // 已知且未变: 静默 STALE 不刷 last_seen
		}
		if t.applyOnlineLocked(mac, ip, e.State, now) {
			changed = true
		}
	}
	return changed
}

// EvictOffline 离线检查(每 OfflineCheckInterval 一次; 语义 = hotspotd 主循环
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
	mac, ip := "", ""
	var oldest int64 = -1
	for m, d := range t.devs {
		if d.HostnameSrc != "pending" {
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

// ApplyResolution 异步解析完成回填(一次一条)。名字级别 / 取值由调用方
// (devname)保证与本表语义一致(manual/dhcp/mdns/cache-*/oui/mac)。
func (t *Table) ApplyResolution(mac, hostname, src string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := normMAC(mac)
	d := t.devs[m]
	if d == nil || hostname == "" || src == "" {
		return false // 设备已走 / 结果为空: 丢弃
	}
	d.Hostname, d.HostnameSrc = hostname, src
	d.lastResolve = now.Unix()
	return true
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

// SortedMACs 在线设备 MAC 列表(排序), 给测试与演练比对用。
func (t *Table) SortedMACs() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.devs))
	for mac := range t.devs {
		out = append(out, mac)
	}
	sort.Strings(out)
	return out
}
