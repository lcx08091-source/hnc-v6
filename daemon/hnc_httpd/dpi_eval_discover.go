// dpi_eval_discover.go — v5.28 B1: 给「新发现的应用」量化准确率(影子)。
//
// 做什么: 把本机带标签样本(run/label_samples.*.jsonl, 评估窗口内)当成
// 一台设备的 SNI 序列, 用与线上 Discoverer 同一套聚类核心
// (hnc.io/dpid/output.ClusterUnknowns, 只看规则库认不出的域名, 与线上一致)
// 复算一遍, 用样本里的包名当真值, 给出:
//   - 纯度(purity): 每个组里占比最多的包名的比例, 按组成员数加权平均;
//   - 完整度(completeness): 同一个包名的未知域名被聚进同一个组的比例
//     (每个包取它命中数最多的那个组, 分母 = 该包的全部未知域名);
//   - 组数、平均组大小、被判枢纽丢掉的域名数;
//   - 三组参数(当前 / 更松 / 更紧)并排, 只展示不自动改 —— 维护者看数据
//     再决定(工作文档 B1)。
//
// 差异(与线上 Discoverer, 文档化): 单设备评估, 不做 min-devices/min-hits
// 输出过滤(小样本下会过滤光), 小组保留、指标自己说话。
package main

import (
	"fmt"

	"hnc.io/dpid/output"
)

// dpiEvalDiscoverVariant 一组聚类参数下的指标。
type dpiEvalDiscoverVariant struct {
	Label         string  `json:"label"`          // 当前 / 更松 / 更紧
	WindowSec     int     `json:"window_sec"`     // 共现窗口
	EdgeThreshold float64 `json:"edge_threshold"` // 强边阈值
	HubDegree     int     `json:"hub_degree"`     // 枢纽度数上限
	Samples       int     `json:"samples"`        // 参与的未知域名样本数
	Groups        int     `json:"groups"`         // 组数(含单域组)
	AvgSize       float64 `json:"avg_size"`       // 平均组大小(域名数)
	Purity        float64 `json:"purity"`
	Completeness  float64 `json:"completeness"`
	Hubs          int     `json:"hubs"` // 被判枢纽丢掉的域名数
}

// dpiEvalDiscover 「新发现的应用」的量化准确率。Variants[0] 是当前线上
// 参数的指标(与顶层 Purity/Completeness/Groups 相同), 其余为对照。
type dpiEvalDiscover struct {
	Samples      int                      `json:"samples"`
	Groups       int                      `json:"groups"`
	AvgSize      float64                  `json:"avg_size"`
	Purity       float64                  `json:"purity"`
	Completeness float64                  `json:"completeness"`
	Hubs         int                      `json:"hubs"`
	Variants     []dpiEvalDiscoverVariant `json:"variants"`
	Note         string                   `json:"note,omitempty"`
}

// discoverParamSets 三组参数: 当前 = 线上默认; 更松 = 更容易合并(窗口 ×2、
// 阈值 -1、枢纽容忍 +8); 更紧 = 更难合并。只影响展示, 不改线上行为。
var discoverParamSets = []struct {
	label string
	p     output.ClusterParams
}{
	{"当前", output.ClusterParams{}},
	{"更松", output.ClusterParams{WindowSec: 10, EdgeThreshold: 2, HubDegree: 32}},
	{"更紧", output.ClusterParams{WindowSec: 3, EdgeThreshold: 5, HubDegree: 16}},
}

// evalDiscover 纯函数(测试直接调): 样本 → discover 段。
// si: 共享基础设施名单(v5.30 T1c, 线上 Discoverer 不让它们成组; 这里同样
// 不进事件流也不进真值表)。nil = 不过滤。
func evalDiscover(samples []evalSample, si *output.SharedInfra) *dpiEvalDiscover {
	d := &dpiEvalDiscover{}

	// 1. 未知样本(规则没认出)→ 事件流; 同时累计 域名→包名 计数(真值)。
	//    与线上一致: 只看规则库认不出的域名(dpid 只为 rule_id 为空的
	//    连接调 Discoverer.Observe)。
	var events []output.ClusterEvent
	regPkg := map[string]map[string]int{} // 可注册域 → 包名 → 样本数
	for _, s := range samples {
		if s.RuleID != "" || s.SNI == "" || s.Pkg == "" || si.Match(s.SNI) {
			continue
		}
		events = append(events, output.ClusterEvent{Dev: "self", Host: s.SNI, JA4: s.JA4, TS: s.Ts})
		reg := output.RegistrableDomain(s.SNI)
		if reg != "" {
			if regPkg[reg] == nil {
				regPkg[reg] = map[string]int{}
			}
			regPkg[reg][s.Pkg]++
		}
	}
	d.Samples = len(events)
	if len(events) == 0 {
		d.Note = "窗口内没有「规则库认不出」的样本, 无法评估聚类(需要开着 DPI 自学习跑几天)。"
		return d
	}

	// 2. 三组参数各跑一遍
	//    真值表: 每个可注册域 → 样本数最多的包名(该域上的多数真值)。
	regTruth := make(map[string]string, len(regPkg))
	for reg, m := range regPkg {
		best, bestN := "", 0
		for pkg, n := range m {
			if n > bestN || (n == bestN && pkg < best) {
				best, bestN = pkg, n
			}
		}
		regTruth[reg] = best
	}
	// 每个包的全部未知域名(完整度分母)
	pkgRegs := map[string]map[string]bool{}
	for reg, pkg := range regTruth {
		if pkgRegs[pkg] == nil {
			pkgRegs[pkg] = map[string]bool{}
		}
		pkgRegs[pkg][reg] = true
	}

	for _, ps := range discoverParamSets {
		out := output.ClusterUnknowns(events, ps.p)
		v := dpiEvalDiscoverVariant{
			Label:         ps.label,
			WindowSec:     ps.p.WindowSec,
			EdgeThreshold: ps.p.EdgeThreshold,
			HubDegree:     ps.p.HubDegree,
			Samples:       len(events),
			Groups:        len(out.Groups),
			Hubs:          len(out.Hubs),
		}
		if v.WindowSec == 0 || v.EdgeThreshold == 0 || v.HubDegree == 0 {
			// 零值 = 线上默认, 展示实际值
			v.WindowSec, v.EdgeThreshold, v.HubDegree = output.DefaultClusterParams()
		}

		// 域 → 组号
		regGroup := map[string]int{}
		totalDomains := 0
		for i, g := range out.Groups {
			for _, s := range g.Suffixes {
				regGroup[s] = i
				totalDomains++
			}
		}
		if totalDomains > 0 {
			v.AvgSize = float64(totalDomains) / float64(len(out.Groups))
		}

		// 纯度: 各组多数包名的成员占比(按组大小加权 = Σ多数 / Σ全部)
		var maj, tot int64
		for _, g := range out.Groups {
			cnt := map[string]int{}
			for _, s := range g.Suffixes {
				if pkg := regTruth[s]; pkg != "" {
					cnt[pkg]++
				}
			}
			top := 0
			for _, n := range cnt {
				if n > top {
					top = n
				}
			}
			maj += int64(top)
			tot += int64(len(g.Suffixes))
		}
		if tot > 0 {
			v.Purity = float64(maj) / float64(tot)
		}

		// 完整度: 每个包取命中数最多的组, Σ命中 / Σ该包全部未知域名
		var hit, all int64
		for _, regs := range pkgRegs {
			best := 0
			groupCnt := map[int]int{}
			for reg := range regs {
				if gi, ok := regGroup[reg]; ok {
					groupCnt[gi]++
				}
			}
			for _, n := range groupCnt {
				if n > best {
					best = n
				}
			}
			hit += int64(best)
			all += int64(len(regs))
		}
		if all > 0 {
			v.Completeness = float64(hit) / float64(all)
		}

		d.Variants = append(d.Variants, v)
	}

	// 顶层 = 当前参数(第一组)
	if len(d.Variants) > 0 {
		cur := d.Variants[0]
		d.Groups, d.AvgSize, d.Purity, d.Completeness, d.Hubs = cur.Groups, cur.AvgSize, cur.Purity, cur.Completeness, cur.Hubs
	}
	d.Note = fmt.Sprintf("共 %d 个未知域名样本聚成 %d 组(含单域组); 参数对照只展示, 不自动调整。", d.Samples, d.Groups)
	return d
}
