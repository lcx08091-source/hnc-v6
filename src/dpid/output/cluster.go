// cluster.go — v5.28 B1: 把 discover.go 的「建图 + 聚类」核心抽成可复用件。
//
// 两个使用者, 同一套规则:
//  1. Discoverer(线上, 行为不变): groupsLocked 的「强边过滤 + 枢纽排除 +
//     并查集合并」抽成 discClusterCore, Discoverer 改为调用它;
//  2. httpd 识别自评(dpi_eval.go 的 discover 段): 把本机带标签样本当成
//     一台设备的 SNI 序列, 用 ClusterUnknowns 复算一遍, 量化「新发现应用」
//     的纯度 / 完整度。输入过滤与线上一致(normalizeName +
//     reportableUnknown + registrableDomain, 即只看规则库认不出的可上报
//     域名)。
//
// 与 Discoverer 的差异(有意为之, 文档化在 dpi_eval.go):
//   - 无 LRU / 节点数 / 边数上限(输入是有界的样本集);
//   - 无持久化;
//   - 不做 discMinHits / discMinDevices / discMaxGroups 输出过滤(单设备
//     评估下 min-devices 必然过滤光; 小组保留, 由指标自己说话)。
package output

import "sort"

// ── 导出的可复用聚类 API(供 httpd 识别自评) ─────────────────────────────

// ClusterEvent 一次未知域名的观测(与 Discoverer.Observe 的未知路径同输入)。
type ClusterEvent struct {
	Dev  string // 设备标识; 共现窗口按它隔离
	Host string // 完整主机名(如 cdn.example.com)
	JA4  string // 可空
	TS   int64  // 秒级时间戳(乱序会先排序)
}

// ClusterParams 聚类参数, 零值 = 线上默认(窗口 5s / 阈值 3.0 / 枢纽度 24)。
type ClusterParams struct {
	WindowSec     int
	EdgeThreshold float64
	HubDegree     int
}

// DefaultClusterParams 返回线上默认参数(评估端展示用, 避免各自硬编码)。
func DefaultClusterParams() (windowSec int, edgeThreshold float64, hubDegree int) {
	return discWindowSec, discEdgeThreshold, discHubDegree
}

// RegistrableDomain 导出可注册域推导(评估端需要与聚类同一口径的
// 主机名 → 可注册域换算)。纯 IP / 空名 / 不可注册返回 ""。
func RegistrableDomain(host string) string { return registrableDomain(host) }

// ClusterGroup 聚出的一个组。
type ClusterGroup struct {
	Suffixes []string // 组内可注册域(hits 降序, 同数按字典序 —— 与 DiscoverGroup.Members 同序)
	Hits     int64    // 组内总命中
}

// ClusterOutcome 聚类结果。
type ClusterOutcome struct {
	Groups []ClusterGroup
	Hubs   []string // 强边度数超过 HubDegree、被排除出合并的可注册域(升序)
}

// ClusterUnknowns 对一串观测跑与 Discoverer 相同的「共现建图 + 聚类」。
// 纯函数: 无 I/O、无状态、无锁。
func ClusterUnknowns(events []ClusterEvent, p ClusterParams) ClusterOutcome {
	if len(events) == 0 {
		return ClusterOutcome{}
	}
	if p.WindowSec <= 0 {
		p.WindowSec = discWindowSec
	}
	if p.EdgeThreshold <= 0 {
		p.EdgeThreshold = discEdgeThreshold
	}
	if p.HubDegree <= 0 {
		p.HubDegree = discHubDegree
	}

	// 乱序输入先按时间排序(样本文件按天聚合, 天内不保证有序)。
	evs := append([]ClusterEvent(nil), events...)
	sort.SliceStable(evs, func(i, j int) bool {
		if evs[i].TS != evs[j].TS {
			return evs[i].TS < evs[j].TS
		}
		return evs[i].Host < evs[j].Host
	})

	nodes := make(map[string]*discNode)
	edges := make(map[discEdgeKey]*discEdge)
	wins := make(map[string][]clWinEntry)
	var lastTS int64

	for _, e := range evs {
		host := normalizeName(e.Host)
		if host == "" || !reportableUnknown(host) {
			continue
		}
		reg := registrableDomain(host)
		if reg == "" {
			continue
		}
		now := e.TS
		if now > lastTS {
			lastTS = now
		}

		// 节点(只记聚类需要的字段; hosts/devs/ja4 元数据评估用不到)
		n := nodes[reg]
		if n == nil {
			n = &discNode{reg: reg, hosts: make(map[string]*discCount, 2), devs: make(map[string]int64, 1)}
			nodes[reg] = n
		}
		n.hits++
		if n.first == 0 || now < n.first {
			n.first = now
		}
		if now > n.last {
			n.last = now
		}

		// 窗口配对(与 windowLocked 相同: ±WindowSec、同域只刷新、+1 / 同 JA4 再 +1)
		w := wins[e.Dev]
		keep := w[:0]
		for _, x := range w {
			if dt := now - x.ts; dt <= int64(p.WindowSec) && dt >= -int64(p.WindowSec) {
				keep = append(keep, x)
			}
		}
		w = keep
		refreshed := false
		for i, x := range w {
			if x.reg == reg {
				x.ts = maxI64(x.ts, now)
				if e.JA4 != "" {
					x.ja4 = e.JA4
				}
				w[i] = w[len(w)-1]
				w[len(w)-1] = x
				refreshed = true
				break
			}
		}
		if !refreshed {
			for _, x := range w {
				inc := 1.0
				if e.JA4 != "" && x.ja4 == e.JA4 {
					inc++ // 同 JA4 额外 +1
				}
				clAddEdge(edges, reg, x.reg, inc, now)
			}
			w = append(w, clWinEntry{reg: reg, ja4: e.JA4, ts: now})
		}
		wins[e.Dev] = w
	}

	if len(nodes) == 0 {
		return ClusterOutcome{}
	}

	byRoot, hubs := discClusterCore(nodes, edges, lastTS, p.EdgeThreshold, p.HubDegree)

	out := ClusterOutcome{Groups: make([]ClusterGroup, 0, len(byRoot))}
	for _, ns := range byRoot {
		sort.Slice(ns, func(i, j int) bool {
			if ns[i].hits != ns[j].hits {
				return ns[i].hits > ns[j].hits
			}
			return ns[i].reg < ns[j].reg
		})
		g := ClusterGroup{Hits: 0}
		for _, m := range ns {
			g.Suffixes = append(g.Suffixes, m.reg)
			g.Hits += m.hits
		}
		out.Groups = append(out.Groups, g)
	}
	sort.Slice(out.Groups, func(i, j int) bool {
		if out.Groups[i].Hits != out.Groups[j].Hits {
			return out.Groups[i].Hits > out.Groups[j].Hits
		}
		return out.Groups[i].Suffixes[0] < out.Groups[j].Suffixes[0]
	})
	for h := range hubs {
		out.Hubs = append(out.Hubs, h)
	}
	sort.Strings(out.Hubs)
	return out
}

// ── Discoverer 与 ClusterUnknowns 共用的聚类核心 ────────────────────────

type clWinEntry struct {
	reg, ja4 string
	ts       int64
}

// clAddEdge 与 Discoverer.addEdgeLocked 同规则(无 LRU): 新建 w=inc;
// 已有则先衰减再加。nodes 由调用方保证已建。
func clAddEdge(edges map[discEdgeKey]*discEdge, a, b string, inc float64, now int64) {
	if a == b {
		return
	}
	k := discKey(a, b)
	if e := edges[k]; e == nil {
		edges[k] = &discEdge{key: k, w: inc, t: now}
	} else {
		e.w = discDecay(e.w, e.t, now) + inc
		if now > e.t {
			e.t = now
		}
	}
}

// discClusterCore 纯函数: 节点 + 边(以 now 时刻的有效权重)→ 按并查集根分组。
// 强边 = 衰减后权重 ≥ threshold; 强边度数 > hubDeg 的节点是枢纽, 其边
// 不参与合并(枢纽回到自己的根, 形成单独一组 —— 与线上语义一致)。
// v5.28 B1 抽自 Discoverer.groupsLocked(行为不变; Discoverer 改为调用)。
func discClusterCore(nodes map[string]*discNode, edges map[discEdgeKey]*discEdge, now int64, threshold float64, hubDeg int) (byRoot map[string][]*discNode, hubs map[string]bool) {
	parent := make(map[string]string, len(nodes))
	var find func(string) string
	find = func(x string) string {
		if parent[x] == "" {
			return x
		}
		parent[x] = find(parent[x])
		return parent[x]
	}

	deg := make(map[string]int, len(nodes))
	strong := make([]discEdgeKey, 0, len(edges))
	for k, e := range edges {
		if discDecay(e.w, e.t, now) >= threshold {
			strong = append(strong, k)
			deg[k.a]++
			deg[k.b]++
		}
	}
	hubs = make(map[string]bool)
	for r, n := range deg {
		if n > hubDeg {
			hubs[r] = true
		}
	}
	for _, k := range strong {
		if deg[k.a] > hubDeg || deg[k.b] > hubDeg {
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
	byRoot = make(map[string][]*discNode, len(nodes))
	for reg, n := range nodes {
		r := find(reg)
		byRoot[r] = append(byRoot[r], n)
	}
	return byRoot, hubs
}
