// Package output - discover.go: v5.15 未知应用自动发现。
//
// 目标: 把规则库认不出的域名自动聚成"同一个 App"的组, 并借 ja4family.go
// 学到的"JA4 → 公司家族"给组打上疑似归属, 输出 run/dpi_discover.json 供
// WebUI 生成规则建议。
//
// 模型:
//   - 节点 = 未识别主机名的"可注册域"(eTLD+1, 内置常见多级后缀表, 与
//     WebUI guessSuffix 同口径)。
//   - 共现边: 同一台设备 5 秒滑动窗口内先后出现的不同可注册域两两 +1;
//     两边在窗口里用过同一个 JA4 再额外 +1。窗口按设备维护, 每设备最多
//     32 条, 同一可注册域在窗口内只占一条(再次出现只刷新时间, 不重复加
//     权 —— 一个 App 冷启动连发十几个请求不该一次就把边刷过阈值)。
//   - 边权 24 小时半衰; 聚类时有效权重 ≥3 的边用并查集合并。度数过高的
//     "枢纽"节点(和太多域名都强共现, 多半是共享 SDK/CDN)不参与合并, 避免
//     把整台设备的流量糊成一个组。
//   - 节点最多 2000、边最多 20000, 都按 LRU 淘汰; Flush 时顺带 prune
//     (衰减到可忽略的边、7 天没见过的节点)。
//
// 并发: Discoverer 自带锁。Writer 只在释放 w.mu 之后调用 Observe, 重活
// (聚类、序列化、写盘)都在 Flush 里, 不占 Writer 的锁。

package output

import (
	"container/list"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultDiscoverPath 输出/持久化默认路径。
	DefaultDiscoverPath = "/data/local/hnc/run/dpi_discover.json"

	discWindowSec      = 5     // 共现窗口(秒)
	discWindowMax      = 32    // 每设备窗口最多保留条数
	discMaxWindows     = 512   // 同时跟踪窗口的设备数上限
	discEdgeThreshold  = 3.0   // 聚类边权阈值
	discHalfLifeSec    = 86400 // 边权半衰期(秒)
	discMaxNodes       = 2000
	discMaxEdges       = 20000
	discNodeMaxHosts   = 32 // 每节点记录的完整主机名上限
	discNodeMaxDevs    = 16 // 每节点记录的设备上限
	discNodeMaxJA4     = 8  // 每节点记录的 JA4 上限
	discNodeMaxAgeSec  = 7 * 86400
	discEdgePruneBelow = 0.5 // 衰减后低于此值的边直接删
	discHubDegree      = 24  // 强边度数超过此值的节点视为枢纽, 不参与合并
	discRestoreEdgeW   = 6.0 // 读回时组内星形边的初始权重(约 24h 后衰减到阈值)

	discMinHits         = 5
	discMinDevices      = 2
	discMaxGroups       = 50
	discMaxSuffixes     = 12
	discMaxDomains      = 15
	discMaxGroupDevices = 8
	discMaxJA4Out       = 3
	discMaxMembers      = 64
)

// ─── 可注册域 ──────────────────────────────────────────────────────────

// discMultiSuffixes 常见多级公共后缀。与 WebUI guessSuffix 同口径:
// (com|net|org|gov|edu).cn、co.(uk|jp)、com.(au|br|hk|tw)、(ne|or).jp。
var discMultiSuffixes = map[string]bool{
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"co.uk": true, "co.jp": true,
	"com.au": true, "com.br": true, "com.hk": true, "com.tw": true,
	"ne.jp": true, "or.jp": true,
}

// registrableDomain 取主机名的可注册域(eTLD+1)。纯 IP / 空名返回 ""。
func registrableDomain(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	host = strings.TrimPrefix(host, "*.")
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	parts := strings.Split(host, ".")
	n := 0
	for _, p := range parts {
		if p != "" {
			parts[n] = p
			n++
		}
	}
	parts = parts[:n]
	if n == 0 {
		return ""
	}
	if n <= 2 {
		return strings.Join(parts, ".")
	}
	two := parts[n-2] + "." + parts[n-1]
	if discMultiSuffixes[two] {
		return strings.Join(parts[n-3:], ".")
	}
	return two
}

// ─── 内部结构 ──────────────────────────────────────────────────────────

type discCount struct {
	n    int64
	last int64
}

type discNode struct {
	reg   string
	hits  int64
	first int64
	last  int64
	hosts map[string]*discCount
	devs  map[string]int64 // mac → last seen
	ja4   map[string]*discCount
	elem  *list.Element
}

type discEdgeKey struct{ a, b string } // a < b

type discEdge struct {
	key  discEdgeKey
	w    float64
	t    int64 // w 对应的时刻; 有效权重 = w × 0.5^((now-t)/半衰期)
	elem *list.Element
}

type discWinEntry struct {
	reg string
	ja4 string
	ts  int64
}

type discWindow struct {
	ev   []discWinEntry
	last int64
}

// Discoverer 未知应用自动发现器。零值不可用, 用 NewDiscoverer 创建。
// 所有方法对 nil 接收者安全(no-op)。
type Discoverer struct {
	mu      sync.Mutex
	path    string
	famPath string

	nodes   map[string]*discNode
	nodeLRU *list.List // Front = 最近
	edges   map[discEdgeKey]*discEdge
	edgeLRU *list.List
	adj     map[string]map[string]*discEdge
	wins    map[string]*discWindow

	fam *ja4FamilyTable

	dirty    bool
	famDirty bool

	// flushMu 串行化 Flush(ticker 与退出时的最后一次 Flush 可能并发);
	// lastGroups 为上次写出的 groups 序列化结果, 只在 flushMu 下读写。
	flushMu    sync.Mutex
	lastGroups string
}

// NewDiscoverer 创建发现器, 路径为默认值。
func NewDiscoverer() *Discoverer {
	return &Discoverer{
		path:    DefaultDiscoverPath,
		famPath: DefaultJA4FamilyPath,
		nodes:   make(map[string]*discNode),
		nodeLRU: list.New(),
		edges:   make(map[discEdgeKey]*discEdge),
		edgeLRU: list.New(),
		adj:     make(map[string]map[string]*discEdge),
		wins:    make(map[string]*discWindow),
		fam:     newJA4FamilyTable(),
	}
}

// SetPath 设置 dpi_discover.json 路径。
func (d *Discoverer) SetPath(p string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.path = p
	d.mu.Unlock()
}

// SetFamilyPath 设置 dpi_ja4family.json 路径。
func (d *Discoverer) SetFamilyPath(p string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.famPath = p
	d.mu.Unlock()
}

// Observe 投递一次 DNS/SNI 事件。known=true 表示规则已命中(ruleID/category
// 为命中规则), 此时只用于 JA4 家族学习; known=false 的域名进入聚类。
func (d *Discoverer) Observe(mac, host, ja4 string, ts time.Time, known bool, ruleID, category string) {
	if d == nil {
		return
	}
	host = normalizeName(host)
	if host == "" {
		return
	}
	now := ts.Unix()
	if known {
		// 只从"用户能感知的应用"学: 广告/CDN/系统服务的 JA4 往往是系统栈或
		// 第三方 SDK, 学进来只会污染家族表。
		if ja4 == "" || ruleID == "" || AppTier(category) != TierApp {
			return
		}
		company := companyOfRule(ruleID)
		d.mu.Lock()
		if d.fam.learn(ja4, company, now) {
			d.famDirty = true
		}
		d.mu.Unlock()
		return
	}
	if !reportableUnknown(host) {
		return
	}
	reg := registrableDomain(host)
	if reg == "" {
		return
	}
	dev := normalizeMAC(mac)
	if dev == "" {
		dev = strings.ToLower(strings.TrimSpace(mac))
	}
	if dev == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.touchNodeLocked(reg, host, dev, ja4, now)
	d.windowLocked(dev, reg, ja4, now)
	d.dirty = true
}

func (d *Discoverer) touchNodeLocked(reg, host, dev, ja4 string, now int64) {
	n := d.nodes[reg]
	if n == nil {
		n = &discNode{reg: reg, first: now, last: now,
			hosts: make(map[string]*discCount, 2), devs: make(map[string]int64, 1)}
		n.elem = d.nodeLRU.PushFront(n)
		d.nodes[reg] = n
		for d.nodeLRU.Len() > discMaxNodes {
			d.removeNodeLocked(d.nodeLRU.Back().Value.(*discNode))
		}
	} else {
		d.nodeLRU.MoveToFront(n.elem)
	}
	n.hits++
	if now < n.first {
		n.first = now
	}
	if now > n.last {
		n.last = now
	}
	bumpDiscCount(n.hosts, host, 1, now, discNodeMaxHosts)
	n.devs[dev] = maxI64(n.devs[dev], now)
	capDiscDevs(n.devs, discNodeMaxDevs)
	if ja4 != "" {
		if n.ja4 == nil {
			n.ja4 = make(map[string]*discCount, 1)
		}
		bumpDiscCount(n.ja4, ja4, 1, now, discNodeMaxJA4)
	}
}

// windowLocked 把事件放进设备窗口, 并与窗口内其他可注册域连边。
func (d *Discoverer) windowLocked(dev, reg, ja4 string, now int64) {
	w := d.wins[dev]
	if w == nil {
		if len(d.wins) >= discMaxWindows {
			d.evictStalestWindowLocked()
		}
		w = &discWindow{}
		d.wins[dev] = w
	}
	w.last = maxI64(w.last, now)
	// 只和前后 5 秒内的事件比较。按时间差绝对值判断: 乱序到达的早事件仍能
	// 和窗口内的事件配对, 但时间戳倒退很多(时钟调整、读回旧窗口)不会误连。
	keep := w.ev[:0]
	for _, e := range w.ev {
		if dt := now - e.ts; dt <= discWindowSec && dt >= -discWindowSec {
			keep = append(keep, e)
		}
	}
	w.ev = keep
	// 同一可注册域已在窗口里: 只刷新(移到末尾), 不重复加权。
	for i, e := range w.ev {
		if e.reg == reg {
			e.ts = maxI64(e.ts, now)
			if ja4 != "" {
				e.ja4 = ja4
			}
			copy(w.ev[i:], w.ev[i+1:])
			w.ev[len(w.ev)-1] = e
			return
		}
	}
	for _, e := range w.ev {
		inc := 1.0
		if ja4 != "" && e.ja4 == ja4 {
			inc++ // 同 JA4 额外 +1
		}
		d.addEdgeLocked(reg, e.reg, inc, now)
	}
	w.ev = append(w.ev, discWinEntry{reg: reg, ja4: ja4, ts: now})
	if len(w.ev) > discWindowMax {
		w.ev = append(w.ev[:0], w.ev[len(w.ev)-discWindowMax:]...)
	}
}

func (d *Discoverer) evictStalestWindowLocked() {
	var oldK string
	var oldT int64 = math.MaxInt64
	for k, w := range d.wins {
		if w.last < oldT || (w.last == oldT && k < oldK) {
			oldK, oldT = k, w.last
		}
	}
	delete(d.wins, oldK)
}

func discDecay(w float64, t, now int64) float64 {
	if now <= t {
		return w
	}
	return w * math.Exp2(-float64(now-t)/discHalfLifeSec)
}

func discKey(a, b string) discEdgeKey {
	if b < a {
		a, b = b, a
	}
	return discEdgeKey{a, b}
}

func (d *Discoverer) addEdgeLocked(a, b string, inc float64, now int64) {
	if a == b || d.nodes[a] == nil || d.nodes[b] == nil {
		return
	}
	k := discKey(a, b)
	e := d.edges[k]
	if e == nil {
		e = &discEdge{key: k, w: inc, t: now}
		e.elem = d.edgeLRU.PushFront(e)
		d.edges[k] = e
		d.adjAdd(k.a, k.b, e)
		d.adjAdd(k.b, k.a, e)
		for d.edgeLRU.Len() > discMaxEdges {
			d.removeEdgeLocked(d.edgeLRU.Back().Value.(*discEdge))
		}
		return
	}
	e.w = discDecay(e.w, e.t, now) + inc
	if now > e.t {
		e.t = now
	}
	d.edgeLRU.MoveToFront(e.elem)
}

func (d *Discoverer) adjAdd(a, b string, e *discEdge) {
	m := d.adj[a]
	if m == nil {
		m = make(map[string]*discEdge, 2)
		d.adj[a] = m
	}
	m[b] = e
}

func (d *Discoverer) removeEdgeLocked(e *discEdge) {
	d.edgeLRU.Remove(e.elem)
	delete(d.edges, e.key)
	for _, p := range [2][2]string{{e.key.a, e.key.b}, {e.key.b, e.key.a}} {
		if m := d.adj[p[0]]; m != nil {
			delete(m, p[1])
			if len(m) == 0 {
				delete(d.adj, p[0])
			}
		}
	}
}

func (d *Discoverer) removeNodeLocked(n *discNode) {
	for _, e := range d.adj[n.reg] {
		d.removeEdgeLocked(e)
	}
	delete(d.adj, n.reg)
	d.nodeLRU.Remove(n.elem)
	delete(d.nodes, n.reg)
}

// pruneLocked 删掉衰减到可忽略的边、长期未见的节点和空闲窗口。返回是否删了东西。
func (d *Discoverer) pruneLocked(now int64) bool {
	changed := false
	for _, e := range d.edges {
		if discDecay(e.w, e.t, now) < discEdgePruneBelow {
			d.removeEdgeLocked(e)
			changed = true
		}
	}
	for _, n := range d.nodes {
		if now-n.last > discNodeMaxAgeSec {
			d.removeNodeLocked(n)
			changed = true
		}
	}
	for k, w := range d.wins {
		if now-w.last > discWindowSec {
			delete(d.wins, k)
		}
	}
	return changed
}

func bumpDiscCount(m map[string]*discCount, k string, inc, now int64, max int) {
	c := m[k]
	if c == nil {
		if len(m) >= max {
			var oldK string
			var oldT int64 = math.MaxInt64
			for kk, v := range m {
				if v.last < oldT || (v.last == oldT && kk < oldK) {
					oldK, oldT = kk, v.last
				}
			}
			delete(m, oldK)
		}
		c = &discCount{}
		m[k] = c
	}
	c.n += inc
	if now > c.last {
		c.last = now
	}
}

func capDiscDevs(m map[string]int64, max int) {
	for len(m) > max {
		var oldK string
		var oldT int64 = math.MaxInt64
		for k, t := range m {
			if t < oldT || (t == oldT && k < oldK) {
				oldK, oldT = k, t
			}
		}
		delete(m, oldK)
	}
}

// ─── 输出格式 dpi_discover.json ────────────────────────────────────────

type discoverFile struct {
	Schema      int             `json:"schema"`
	GeneratedAt int64           `json:"generated_at"`
	Groups      []DiscoverGroup `json:"groups"`
}

// DiscoverGroup 一个疑似"同一 App"的未识别域名组。
type DiscoverGroup struct {
	ID         string           `json:"id"`
	Suffixes   []string         `json:"suffixes"`
	Domains    []DiscoverDomain `json:"domains"`
	Devices    []string         `json:"devices"`
	Hits       int64            `json:"hits"`
	FirstSeen  int64            `json:"first_seen"`
	LastSeen   int64            `json:"last_seen"`
	JA4        []DiscoverJA4    `json:"ja4"`
	Family     string           `json:"family"`
	FamilyName string           `json:"family_name"`
	FamilyConf float64          `json:"family_conf"`
	// Members 组内每个可注册域的明细(最多 64, 按命中降序)。用于重启读回
	// 恢复节点, WebUI 也可用来展示。
	Members []DiscoverMember `json:"members"`
}

// DiscoverDomain 组内完整主机名。
type DiscoverDomain struct {
	Name     string `json:"name"`
	Count    int64  `json:"count"`
	LastSeen int64  `json:"last_seen"`
}

// DiscoverJA4 组内 JA4 及命中数; family 为该 JA4 已学到的公司家族(未学到为空)。
type DiscoverJA4 struct {
	JA4    string `json:"ja4"`
	Count  int64  `json:"count"`
	Family string `json:"family,omitempty"`
}

// DiscoverMember 组内一个可注册域。
type DiscoverMember struct {
	Suffix    string   `json:"suffix"`
	Hits      int64    `json:"hits"`
	FirstSeen int64    `json:"first_seen"`
	LastSeen  int64    `json:"last_seen"`
	Devices   []string `json:"devices"`
}

// Groups 返回当前聚类结果(已过滤、排序、截断)。供测试与调试。
func (d *Discoverer) Groups(now time.Time) []DiscoverGroup {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.groupsLocked(now.Unix())
}

func discGroupID(minReg string) string {
	sum := sha1.Sum([]byte(minReg))
	return "g_" + hex.EncodeToString(sum[:])[:10]
}

func (d *Discoverer) groupsLocked(now int64) []DiscoverGroup {
	// 1. 强边 + 度数
	parent := make(map[string]string, len(d.nodes))
	var find func(string) string
	find = func(x string) string {
		p, ok := parent[x]
		if !ok || p == x {
			return x
		}
		r := find(p)
		parent[x] = r
		return r
	}
	var strong []discEdgeKey
	deg := make(map[string]int)
	for k, e := range d.edges {
		if discDecay(e.w, e.t, now) >= discEdgeThreshold {
			strong = append(strong, k)
			deg[k.a]++
			deg[k.b]++
		}
	}
	for _, k := range strong {
		if deg[k.a] > discHubDegree || deg[k.b] > discHubDegree {
			continue
		}
		ra, rb := find(k.a), find(k.b)
		if ra != rb {
			if rb < ra {
				ra, rb = rb, ra
			}
			parent[rb] = ra
		}
	}
	// 2. 按根分组
	byRoot := make(map[string][]*discNode)
	for reg, n := range d.nodes {
		r := find(reg)
		byRoot[r] = append(byRoot[r], n)
	}
	// 3. 汇总
	groups := make([]DiscoverGroup, 0, 16)
	for _, ns := range byRoot {
		g, devCount := d.buildGroupLocked(ns)
		if g.Hits < discMinHits && devCount < discMinDevices {
			continue
		}
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].LastSeen != groups[j].LastSeen {
			return groups[i].LastSeen > groups[j].LastSeen
		}
		return groups[i].ID < groups[j].ID
	})
	if len(groups) > discMaxGroups {
		groups = groups[:discMaxGroups]
	}
	return groups
}

func (d *Discoverer) buildGroupLocked(ns []*discNode) (DiscoverGroup, int) {
	sort.Slice(ns, func(i, j int) bool {
		if ns[i].hits != ns[j].hits {
			return ns[i].hits > ns[j].hits
		}
		return ns[i].reg < ns[j].reg
	})
	g := DiscoverGroup{}
	minReg := ""
	hosts := make(map[string]*discCount)
	devs := make(map[string]int64)
	ja4s := make(map[string]int64)
	for i, n := range ns {
		if minReg == "" || n.reg < minReg {
			minReg = n.reg
		}
		g.Hits += n.hits
		if g.FirstSeen == 0 || n.first < g.FirstSeen {
			g.FirstSeen = n.first
		}
		if n.last > g.LastSeen {
			g.LastSeen = n.last
		}
		if i < discMaxSuffixes {
			g.Suffixes = append(g.Suffixes, n.reg)
		}
		if i < discMaxMembers {
			g.Members = append(g.Members, DiscoverMember{Suffix: n.reg, Hits: n.hits,
				FirstSeen: n.first, LastSeen: n.last, Devices: topDevs(n.devs, discNodeMaxDevs)})
		}
		for h, c := range n.hosts {
			hc := hosts[h]
			if hc == nil {
				hc = &discCount{}
				hosts[h] = hc
			}
			hc.n += c.n
			hc.last = maxI64(hc.last, c.last)
		}
		for m, t := range n.devs {
			devs[m] = maxI64(devs[m], t)
		}
		for f, c := range n.ja4 {
			ja4s[f] += c.n
		}
	}
	g.ID = discGroupID(minReg)

	// domains top 15(按次数降序)
	g.Domains = make([]DiscoverDomain, 0, len(hosts))
	for h, c := range hosts {
		g.Domains = append(g.Domains, DiscoverDomain{Name: h, Count: c.n, LastSeen: c.last})
	}
	sort.Slice(g.Domains, func(i, j int) bool {
		if g.Domains[i].Count != g.Domains[j].Count {
			return g.Domains[i].Count > g.Domains[j].Count
		}
		return g.Domains[i].Name < g.Domains[j].Name
	})
	if len(g.Domains) > discMaxDomains {
		g.Domains = g.Domains[:discMaxDomains]
	}
	g.Devices = topDevs(devs, discMaxGroupDevices)

	// JA4 top 3 + 家族投票(用全部 JA4, 不只 top 3)
	type fc struct {
		fp string
		n  int64
	}
	all := make([]fc, 0, len(ja4s))
	votes := make(map[string]int64)
	confSum := make(map[string]float64)
	var labeled int64
	for f, n := range ja4s {
		all = append(all, fc{f, n})
		if fam, conf, ok := d.fam.familyOf(f); ok {
			votes[fam] += n
			confSum[fam] += float64(n) * conf
			labeled += n
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].fp < all[j].fp
	})
	g.JA4 = make([]DiscoverJA4, 0, discMaxJA4Out)
	for i := 0; i < len(all) && i < discMaxJA4Out; i++ {
		fam, _, _ := d.fam.familyOf(all[i].fp)
		g.JA4 = append(g.JA4, DiscoverJA4{JA4: all[i].fp, Count: all[i].n, Family: fam})
	}
	best, bestN := "", int64(0)
	for f, n := range votes {
		if n > bestN || (n == bestN && f < best) {
			best, bestN = f, n
		}
	}
	if best != "" && labeled > 0 {
		// family_conf = 支持该家族的 JA4 的平均学习占比(按命中加权)×
		//               该家族在"有家族标签的 JA4 命中"中的票数占比
		//             = Σ(命中×占比)[该家族] / Σ命中[有家族标签]。
		g.Family = best
		g.FamilyName = companyName(best)
		g.FamilyConf = round2(confSum[best] / float64(labeled))
	}
	if g.Suffixes == nil {
		g.Suffixes = []string{}
	}
	return g, len(devs)
}

// topDevs 按 last seen 降序取前 max 个 MAC。
func topDevs(m map[string]int64, max int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// ─── 落盘 / 读回 ───────────────────────────────────────────────────────

// Flush prune 后把 dpi_discover.json 与 dpi_ja4family.json 按需写盘(各自
// 有变化才写)。签名与 flushEvery 一致。
func (d *Discoverer) Flush(now time.Time) error {
	if d == nil {
		return nil
	}
	d.flushMu.Lock()
	defer d.flushMu.Unlock()
	ts := now.Unix()
	d.mu.Lock()
	if d.pruneLocked(ts) {
		d.dirty = true
	}
	var groups []DiscoverGroup
	var fam *ja4FamilyFile
	// 家族表变了, 组的 family 标注也可能变 —— 两种脏都重算组; 组内容与上次
	// 写出的一致则不写(下面按序列化结果比较)。
	regroup := d.dirty || d.famDirty
	if regroup {
		groups = d.groupsLocked(ts)
		d.dirty = false
	}
	if d.famDirty {
		f := d.fam.snapshot(ts)
		fam = &f
		d.famDirty = false
	}
	path, famPath := d.path, d.famPath
	d.mu.Unlock()

	var firstErr error
	if regroup {
		if groups == nil {
			groups = []DiscoverGroup{}
		}
		gb, err := json.Marshal(groups)
		if err == nil && string(gb) != d.lastGroups {
			err = writeJSONFile(path, &discoverFile{Schema: 1, GeneratedAt: ts, Groups: groups})
			if err == nil {
				d.lastGroups = string(gb)
			}
		}
		if err != nil {
			firstErr = err
			d.mu.Lock()
			d.dirty = true
			d.mu.Unlock()
		}
	}
	if fam != nil {
		if err := writeJSONFile(famPath, fam); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			d.mu.Lock()
			d.famDirty = true
			d.mu.Unlock()
		}
	}
	return firstErr
}

func writeJSONFile(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return atomicWrite(path, b, 0o644)
}

// Load 启动时读回两个文件。不存在/损坏/schema 不符一律忽略(返回 nil)。
// 恢复节点与组: 组内节点之间补一组星形边(权重 discRestoreEdgeW, 时间取
// generated_at), 重启后组保持合并, 没有新共现则约 24h 后自然散开。
func (d *Discoverer) Load() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	path, famPath := d.path, d.famPath
	d.mu.Unlock()

	var ff ja4FamilyFile
	if readJSONFile(famPath, &ff) && ff.Schema == 1 {
		d.mu.Lock()
		d.fam.restore(ff)
		d.mu.Unlock()
	}
	var df discoverFile
	if !readJSONFile(path, &df) || df.Schema != 1 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	// 旧的在前: 按 last_seen 升序恢复, 让最新的组处在 LRU 前端。
	groups := append([]DiscoverGroup(nil), df.Groups...)
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].LastSeen < groups[j].LastSeen })
	for _, g := range groups {
		d.restoreGroupLocked(g, df.GeneratedAt)
	}
	return nil
}

func (d *Discoverer) restoreGroupLocked(g DiscoverGroup, genAt int64) {
	members := g.Members
	if len(members) == 0 {
		for _, s := range g.Suffixes {
			members = append(members, DiscoverMember{Suffix: s, FirstSeen: g.FirstSeen, LastSeen: g.LastSeen, Devices: g.Devices})
		}
	}
	var regs []string
	for i := len(members) - 1; i >= 0; i-- { // 命中少的先插, 多的最终在前
		m := members[i]
		reg := registrableDomain(m.Suffix)
		if reg == "" || d.nodes[reg] != nil {
			continue
		}
		n := &discNode{reg: reg, hits: m.Hits, first: m.FirstSeen, last: m.LastSeen,
			hosts: make(map[string]*discCount), devs: make(map[string]int64)}
		for _, mac := range m.Devices {
			if len(n.devs) >= discNodeMaxDevs {
				break
			}
			n.devs[mac] = m.LastSeen
		}
		n.elem = d.nodeLRU.PushFront(n)
		d.nodes[reg] = n
		regs = append(regs, reg)
		for d.nodeLRU.Len() > discMaxNodes {
			d.removeNodeLocked(d.nodeLRU.Back().Value.(*discNode))
		}
	}
	if len(regs) == 0 {
		return
	}
	for _, dm := range g.Domains {
		if n := d.nodes[registrableDomain(dm.Name)]; n != nil && dm.Name != "" {
			bumpDiscCount(n.hosts, dm.Name, dm.Count, dm.LastSeen, discNodeMaxHosts)
		}
	}
	// JA4 无法拆回到节点, 归到组内命中最多的节点上。
	var top *discNode
	for _, r := range regs {
		if n := d.nodes[r]; n != nil && (top == nil || n.hits > top.hits) {
			top = n
		}
	}
	if top != nil {
		for _, j := range g.JA4 {
			if j.JA4 == "" || j.Count <= 0 {
				continue
			}
			if top.ja4 == nil {
				top.ja4 = make(map[string]*discCount, 1)
			}
			bumpDiscCount(top.ja4, j.JA4, j.Count, g.LastSeen, discNodeMaxJA4)
		}
	}
	sort.Strings(regs)
	anchor := regs[0]
	for _, r := range regs[1:] {
		if d.nodes[anchor] == nil || d.nodes[r] == nil {
			continue
		}
		k := discKey(anchor, r)
		if d.edges[k] != nil {
			continue
		}
		e := &discEdge{key: k, w: discRestoreEdgeW, t: genAt}
		e.elem = d.edgeLRU.PushFront(e)
		d.edges[k] = e
		d.adjAdd(k.a, k.b, e)
		d.adjAdd(k.b, k.a, e)
		for d.edgeLRU.Len() > discMaxEdges {
			d.removeEdgeLocked(d.edgeLRU.Back().Value.(*discEdge))
		}
	}
}

func readJSONFile(path string, v any) bool {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 || len(b) > 8<<20 {
		return false
	}
	return json.Unmarshal(b, v) == nil
}
