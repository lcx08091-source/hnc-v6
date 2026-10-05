// api_discover_suggest.go — v5.28 B2: 新发现应用的自动起名(建议, 不自动确认)。
//
// 在既有 enrichGroup 的 apk / 证书 / JA4 家族线索之上, 给每个组算一个结构化
// 「建议」: 建议名称 + 置信度 + 依据列表(每个来源一条人话)。来源按可信度:
//  1. apk_domains.json —— 本机安装包里写死了这些域名 → App 名(最强);
//  2. 启动指纹(v5.27 T3 学到的应用)的特征 token 与组内域名重合 ≥ 2 个;
//  3. 证书组织名(现有证书线索);
//  4. JA4 家族(网络库, 不是应用本身);
//  5. 组内域名的可注册域本身(最弱)。
//
// 多个「中等以上」来源一致 → 置信度叠加到 high; 两个中等以上来源名字不同 →
// 取优先级最高的并标「有分歧」。确认仍需用户点, 确认框预填建议名(前端)。
//
// suggestForGroup 是纯函数(测试直接喂候选); enrichGroup 负责把各来源收集成
// 候选。旧的 out["guess"] 保留(前端旧逻辑兼容), 新增 out["suggest"]。
package main

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// discSuggestSrc 一个来源的建议。
type discSuggestSrc struct {
	Src   string `json:"src"`   // apk / startup / cert / ja4 / domain
	Name  string `json:"name"`  // 该来源给的名字
	Basis string `json:"basis"` // 人话依据
}

// discSuggestOut 结构化建议(/api/discover 每组新字段 suggest)。
type discSuggestOut struct {
	Name     string           `json:"name"`
	Conf     string           `json:"conf"`               // low / medium / high
	Conflict bool             `json:"conflict,omitempty"` // 有分歧(两个中等以上来源名字不同)
	Pkg      string           `json:"pkg,omitempty"`
	Sources  []discSuggestSrc `json:"sources"`
}

// sugCand 建议候选(某来源对某组的一个提名)。
type sugCand struct {
	src    string // apk / startup / cert / ja4 / domain
	name   string
	basis  string
	pkg    string
	rank   int  // 来源优先级, 小 = 可信(见 suggestRank)
	strong bool // 强信号(apk 分数高 / startup 重合 ≥ 4)
	medium bool // 中等及以上可信(参与叠加 / 分歧判定)
}

var suggestRank = map[string]int{"apk": 0, "startup": 1, "cert": 2, "ja4": 3, "domain": 4}

// suggestForGroup 纯函数: 候选 → 建议。
//   - 按名字分组: 每个名字的 medium 来源数、是否有强信号、最佳 rank;
//   - 赢家 = 有强信号 > medium 来源多 > 来源优先级高;
//   - 置信度: 强信号或 ≥2 个中等来源一致 → high; 1 个中等 → medium; 否则 low;
//   - 分歧: 另有名字也有中等以上来源 → conflict(仍取赢家, 依据全列出)。
func suggestForGroup(cands []sugCand) discSuggestOut {
	out := discSuggestOut{}
	if len(cands) == 0 {
		return out
	}
	type byName struct {
		srcs    []discSuggestSrc
		pkg     string
		best    int
		strong  bool
		mediumN int
	}
	by := map[string]*byName{}
	var order []string
	for _, c := range cands {
		if c.name == "" {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(c.name))
		b := by[key]
		if b == nil {
			b = &byName{best: 99}
			by[key] = b
			order = append(order, key)
		}
		b.srcs = append(b.srcs, discSuggestSrc{Src: c.src, Name: c.name, Basis: c.basis})
		if c.pkg != "" {
			b.pkg = c.pkg
		}
		if r, ok := suggestRank[c.src]; ok && r < b.best {
			b.best = r
		}
		if c.strong {
			b.strong = true
		}
		if c.medium {
			b.mediumN++
		}
	}
	if len(by) == 0 {
		return out
	}
	// 赢家
	win := ""
	for _, k := range order {
		if win == "" {
			win = k
			continue
		}
		a, b := by[k], by[win]
		switch {
		case a.strong != b.strong:
			if a.strong {
				win = k
			}
		case a.mediumN != b.mediumN:
			if a.mediumN > b.mediumN {
				win = k
			}
		case a.best < b.best:
			win = k
		}
	}
	w := by[win]
	out.Name = w.srcs[0].Name
	out.Pkg = w.pkg
	sort.SliceStable(w.srcs, func(i, j int) bool {
		return suggestRank[w.srcs[i].Src] < suggestRank[w.srcs[j].Src]
	})
	out.Sources = w.srcs
	switch {
	case w.strong, w.mediumN >= 2:
		out.Conf = "high"
	case w.mediumN == 1:
		out.Conf = "medium"
	default:
		out.Conf = "low"
	}
	// 分歧: 其他名字也有中等以上来源
	for _, k := range order {
		if k == win {
			continue
		}
		if by[k].mediumN >= 1 {
			out.Conflict = true
			break
		}
	}
	return out
}

// startupFeatApp 一个可用应用的特征 token 集(供 discover 建议名)。
type startupFeatApp struct {
	AppID string
	Name  string
	Feat  map[string]bool
}

// featApps 可用(特征 token ≥ 2)的应用列表。learnedView 只读内存表并
// lazy-load data/startup_fp.json, 无写盘。
func (st *startupStore) featApps(now time.Time) []startupFeatApp {
	apps, _ := st.learnedView(now)
	var out []startupFeatApp
	for _, a := range apps {
		if !a.Usable {
			continue
		}
		fa := startupFeatApp{AppID: a.AppID, Name: a.Name, Feat: map[string]bool{}}
		for _, t := range a.Tokens {
			if t.Feat {
				fa.Feat[t.T] = true
			}
		}
		if len(fa.Feat) >= 2 {
			out = append(out, fa)
		}
	}
	return out
}

// suggestStartupCands 纯函数: 组内域名(全名)tokenize 后与各应用的
// 特征 token 求重合, ≥ 2 的应用成为候选。重合 ≥ 4 算强信号。
func suggestStartupCands(gtoks map[string]bool, apps []startupFeatApp) []sugCand {
	var out []sugCand
	for _, a := range apps {
		n := 0
		for tok := range a.Feat {
			if gtoks[tok] {
				n++
			}
		}
		if n < 2 {
			continue
		}
		name := a.Name
		if name == "" {
			name = a.AppID
		}
		c := sugCand{
			src:    "startup",
			name:   name,
			rank:   suggestRank["startup"],
			medium: true,
			strong: n >= 4,
			basis:  "启动指纹:「" + name + "」启动时常连的域名里, " + itoaStartup(n) + " 个在这个组里",
		}
		out = append(out, c)
	}
	return out
}

func itoaStartup(n int) string { return strconv.Itoa(n) }

// buildSuggest enrichGroup 用: 收集本组所有来源的候选 → suggestForGroup。
// 现有 enrichGroup 已算好 apks / company / fam / sufs(域名), 这里只补
// 启动指纹这个新来源。
func (s *server) buildSuggest(g map[string]interface{}, ix apkIndex, apks []map[string]interface{},
	company, fam string, sufs []string, now time.Time) discSuggestOut {
	var cands []sugCand
	// 1. 本机安装包(与旧 guess 同口径: 分数 ≥ 2 且唯一或领先)
	if len(apks) > 0 {
		sc, _ := apks[0]["score"].(int)
		leading := len(apks) == 1
		if len(apks) > 1 {
			sc2, _ := apks[1]["score"].(int)
			leading = sc > sc2
		}
		if sc >= 2 && leading {
			lbl := asString(apks[0]["label"])
			if lbl == "" {
				lbl = asString(apks[0]["pkg"])
			}
			cands = append(cands, sugCand{
				src:    "apk",
				name:   lbl,
				pkg:    asString(apks[0]["pkg"]),
				rank:   suggestRank["apk"],
				strong: sc >= 4,
				medium: true,
				basis:  "本机已安装的「" + lbl + "」(" + asString(apks[0]["pkg"]) + ")里写死了这些域名",
			})
		}
	}
	// 2. 启动指纹: 组内域名(全名)→ token, 与可用应用的特征 token 重合 ≥ 2
	gtoks := map[string]bool{}
	for _, d := range strList(g["domains"]) {
		if tok := startupToken(d); tok != "" {
			gtoks[tok] = true
		}
	}
	if len(gtoks) > 0 {
		if st := startupFor(s.hncDir); st != nil {
			cands = append(cands, suggestStartupCands(gtoks, st.featApps(now))...)
		}
	}
	// 3. 证书组织名
	if company != "" {
		cands = append(cands, sugCand{
			src: "cert", name: company + " 旗下应用", rank: suggestRank["cert"], medium: true,
			basis: "服务器证书的组织名是「" + company + "」",
		})
	}
	// 4. JA4 家族(网络库线索, 弱)
	if fam != "" {
		cands = append(cands, sugCand{
			src: "ja4", name: "疑似" + fam + "应用", rank: suggestRank["ja4"],
			basis: "组内的 TLS 指纹像 " + fam + " 系网络库",
		})
	}
	// 5. 组内主可注册域(最弱)
	if len(sufs) > 0 {
		cands = append(cands, sugCand{
			src: "domain", name: sufs[0], rank: suggestRank["domain"],
			basis: "组内命中最多的可注册域",
		})
	}
	return suggestForGroup(cands)
}
