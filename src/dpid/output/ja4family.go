// Package output - ja4family.go: v5.15 JA4 → 公司家族学习。
//
// 思路: 同一家公司的 App 往往共用同一套网络库(字节的 TTNet、腾讯的
// mars/QUIC 栈、阿里的 ANet…), TLS ClientHello 的 JA4 因此高度一致。
// 我们从"规则已认出的应用"那里学: 每次命中 TierApp 规则且带 JA4 的 TLS
// 事件, 给 (JA4 → 该规则所属公司) 计数 +1。某个 JA4 样本足够多、且一家
// 公司占比过线, 就认为它属于该公司家族; 之后规则认不出的域名如果也用这个
// JA4, 就能给出"疑似 XX 系"的归属。
//
// 浏览器 / 系统 WebView / okhttp 这类通用 JA4 会被很多公司的应用混用,
// 占比不过线 → 不标, 这正是想要的。不在公司表里的应用也计入 total
// (记为 "_other"), 否则"只看表内公司"会把混用 JA4 误判成单一家族。
//
// 本表本身不带锁, 由 Discoverer 在自己的 d.mu 下读写。

package output

import (
	"container/list"
	"sort"
	"strings"
	"sync"
)

const (
	// DefaultJA4FamilyPath 学习表持久化默认路径(与 dpi_discover.json 同目录)。
	DefaultJA4FamilyPath = "/data/local/hnc/run/dpi_ja4family.json"

	ja4FamMinSamples = 20     // 样本数下限
	ja4FamMinShare   = 0.70   // 单一公司占比下限
	ja4FamMaxEntries = 512    // 最多跟踪的 JA4 数(LRU)
	ja4FamTotalCap   = 100000 // 单个 JA4 的 total 超过即全体减半, 保持可适应
	ja4OtherCompany  = "_other"
)

// ja4Company 一家公司: 规则 id 精确表 + 前缀表。写成数据表便于扩展。
// 规则 id 以 data/dpi_rules.json + data/dpi_rules.d/*.json + 内置规则为准
// (v5.15 逐条 grep 核对过, 不存在的 id 已删)。
type ja4Company struct {
	ID       string
	Name     string
	Exact    []string
	Prefixes []string
}

var ja4Companies = []ja4Company{
	{ID: "bytedance", Name: "字节跳动", Exact: []string{
		"douyin", "toutiao", "xigua", "feishu", "doubao", "volcengine", "pangle",
		"qishui_music", "bytedance_group", "bytedance_dig", "bytedance_ads_extra",
		"tiktok", "ixigua_disambiguation", "douyin_p2p_inferred",
		"fanqie_novel", "dongchedi",
	}},
	{ID: "tencent", Name: "腾讯", Exact: []string{
		"wechat", "wechat_pcdn_heartbeat", "qq_im", "qq_extra", "qq_music", "qywechat", "gdt",
		"bugly", "kugou", "kuwo",
	}, Prefixes: []string{"tencent_"}},
	{ID: "alibaba", Name: "阿里巴巴", Exact: []string{
		"taobao", "alibaba_group", "amap", "eleme", "aliyun_cloud", "aliyun_drive", "dingding",
		"xianyu", "uc_browser", "quark", "tongyi", "youku", "umeng",
	}, Prefixes: []string{"alibaba_doh"}},
	{ID: "baidu", Name: "百度", Exact: []string{"wenxin"}, Prefixes: []string{"baidu_"}},
	{ID: "kuaishou", Name: "快手", Exact: []string{"kuaishou", "kuaishou_ad_sdk"}},
	{ID: "netease", Name: "网易", Prefixes: []string{"netease_"}},
	{ID: "xiaomi", Name: "小米", Exact: []string{"xiaomi"}, Prefixes: []string{"xiaomi_"}},
	{ID: "huawei", Name: "华为", Prefixes: []string{"huawei"}},
	{ID: "oppo", Name: "OPPO 系", Prefixes: []string{"oppo", "coloros_", "realme_"}},
	{ID: "vivo", Name: "vivo", Prefixes: []string{"vivo"}},
	{ID: "meituan", Name: "美团", Exact: []string{"meituan"}},
	{ID: "pinduoduo", Name: "拼多多", Prefixes: []string{"pinduoduo"}},
	{ID: "mihoyo", Name: "米哈游", Exact: []string{"hoyoplay_launcher"}, Prefixes: []string{"mihoyo"}},
	{ID: "apple", Name: "Apple", Prefixes: []string{"apple"}},
	{ID: "google", Name: "Google", Exact: []string{"youtube", "gemini"}, Prefixes: []string{"google"}},
	{ID: "microsoft", Name: "Microsoft", Exact: []string{"teams", "xbox", "copilot", "minecraft"},
		Prefixes: []string{"microsoft_", "ms_"}},
}

var (
	ja4CompanyOnce   sync.Once
	ja4CompanyExact  map[string]string // 规则 id → 公司 id
	ja4CompanyPrefix []ja4Prefix       // 按前缀长度降序
	ja4CompanyNames  map[string]string // 公司 id → 中文名
)

type ja4Prefix struct{ prefix, company string }

func initJA4Companies() {
	ja4CompanyExact = make(map[string]string)
	ja4CompanyNames = make(map[string]string)
	for _, c := range ja4Companies {
		ja4CompanyNames[c.ID] = c.Name
		for _, id := range c.Exact {
			ja4CompanyExact[id] = c.ID
		}
		for _, p := range c.Prefixes {
			ja4CompanyPrefix = append(ja4CompanyPrefix, ja4Prefix{p, c.ID})
		}
	}
	sort.SliceStable(ja4CompanyPrefix, func(i, j int) bool {
		return len(ja4CompanyPrefix[i].prefix) > len(ja4CompanyPrefix[j].prefix)
	})
}

// companyOfRule 返回规则 id 所属公司 id; 不在表里返回 ""。精确表优先, 其次最长前缀。
func companyOfRule(ruleID string) string {
	ja4CompanyOnce.Do(initJA4Companies)
	ruleID = strings.ToLower(strings.TrimSpace(ruleID))
	if ruleID == "" {
		return ""
	}
	if c, ok := ja4CompanyExact[ruleID]; ok {
		return c
	}
	for _, p := range ja4CompanyPrefix {
		if strings.HasPrefix(ruleID, p.prefix) {
			return p.company
		}
	}
	return ""
}

// companyName 公司 id → 中文名(未知 id 原样返回)。
func companyName(id string) string {
	ja4CompanyOnce.Do(initJA4Companies)
	if n, ok := ja4CompanyNames[id]; ok {
		return n
	}
	return id
}

// ─── 学习表 ────────────────────────────────────────────────────────────

type ja4FamStat struct {
	ja4       string
	companies map[string]int64 // 公司 id(或 "_other") → 样本数; 键数 ≤ 公司数+1
	total     int64
	lastSeen  int64
	elem      *list.Element
}

type ja4FamilyTable struct {
	m   map[string]*ja4FamStat
	lru *list.List // Front = 最近
	max int
}

func newJA4FamilyTable() *ja4FamilyTable {
	return &ja4FamilyTable{m: make(map[string]*ja4FamStat), lru: list.New(), max: ja4FamMaxEntries}
}

// learn 记一次样本。company 为空记作 "_other"。返回是否有变化。
func (t *ja4FamilyTable) learn(ja4, company string, now int64) bool {
	if ja4 == "" {
		return false
	}
	if company == "" {
		company = ja4OtherCompany
	}
	s := t.m[ja4]
	if s == nil {
		s = &ja4FamStat{ja4: ja4, companies: make(map[string]int64, 2)}
		s.elem = t.lru.PushFront(s)
		t.m[ja4] = s
		for t.lru.Len() > t.max {
			old := t.lru.Back().Value.(*ja4FamStat)
			t.lru.Remove(old.elem)
			delete(t.m, old.ja4)
		}
	} else {
		t.lru.MoveToFront(s.elem)
	}
	s.companies[company]++
	s.total++
	if now > s.lastSeen {
		s.lastSeen = now
	}
	if s.total > ja4FamTotalCap {
		var tot int64
		for k, v := range s.companies {
			v /= 2
			if v == 0 {
				delete(s.companies, k)
				continue
			}
			s.companies[k] = v
			tot += v
		}
		s.total = tot
	}
	// 每 20 个样本才算"有变化"(触发落盘) —— 否则只要有流量就每 30 秒写一次闪存。
	// 家族判定本身在内存里实时生效, 不受影响。
	return s.total%ja4FamMinSamples == 0
}

// familyOf 返回 (公司 id, 占比, 是否已学到)。"_other" 占多数不算家族。
func (t *ja4FamilyTable) familyOf(ja4 string) (string, float64, bool) {
	s := t.m[ja4]
	if s == nil {
		return "", 0, false
	}
	return s.family()
}

func (s *ja4FamStat) family() (string, float64, bool) {
	if s.total < ja4FamMinSamples {
		return "", 0, false
	}
	best, bestN := "", int64(0)
	for c, n := range s.companies {
		if n > bestN || (n == bestN && c < best) {
			best, bestN = c, n
		}
	}
	if best == "" || best == ja4OtherCompany {
		return "", 0, false
	}
	share := float64(bestN) / float64(s.total)
	if share < ja4FamMinShare {
		return "", 0, false
	}
	return best, share, true
}

// ─── 持久化格式 dpi_ja4family.json ─────────────────────────────────────

type ja4FamilyFile struct {
	Schema      int              `json:"schema"`
	GeneratedAt int64            `json:"generated_at"`
	Entries     []ja4FamilyEntry `json:"entries"`
}

type ja4FamilyEntry struct {
	JA4        string           `json:"ja4"`
	Total      int64            `json:"total"`
	LastSeen   int64            `json:"last_seen"`
	Companies  map[string]int64 `json:"companies"`
	Family     string           `json:"family"`
	FamilyName string           `json:"family_name"`
	FamilyConf float64          `json:"family_conf"`
}

// snapshot 生成落盘结构(按 total 降序)。
func (t *ja4FamilyTable) snapshot(now int64) ja4FamilyFile {
	out := ja4FamilyFile{Schema: 1, GeneratedAt: now, Entries: make([]ja4FamilyEntry, 0, len(t.m))}
	for _, s := range t.m {
		e := ja4FamilyEntry{JA4: s.ja4, Total: s.total, LastSeen: s.lastSeen,
			Companies: make(map[string]int64, len(s.companies))}
		for k, v := range s.companies {
			e.Companies[k] = v
		}
		if fam, conf, ok := s.family(); ok {
			e.Family, e.FamilyName, e.FamilyConf = fam, companyName(fam), round2(conf)
		}
		out.Entries = append(out.Entries, e)
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		if out.Entries[i].Total != out.Entries[j].Total {
			return out.Entries[i].Total > out.Entries[j].Total
		}
		return out.Entries[i].JA4 < out.Entries[j].JA4
	})
	return out
}

// restore 从落盘结构恢复(按 last_seen 升序 PushFront, 保持 LRU 顺序)。
func (t *ja4FamilyTable) restore(f ja4FamilyFile) {
	ents := append([]ja4FamilyEntry(nil), f.Entries...)
	sort.SliceStable(ents, func(i, j int) bool { return ents[i].LastSeen < ents[j].LastSeen })
	for _, e := range ents {
		if e.JA4 == "" || len(e.Companies) == 0 {
			continue
		}
		if old := t.m[e.JA4]; old != nil {
			t.lru.Remove(old.elem)
		}
		s := &ja4FamStat{ja4: e.JA4, companies: make(map[string]int64, len(e.Companies)), lastSeen: e.LastSeen}
		for k, v := range e.Companies {
			if k == "" || v <= 0 || len(s.companies) >= len(ja4Companies)+1 {
				continue
			}
			s.companies[k] = v
			s.total += v
		}
		if s.total == 0 {
			delete(t.m, e.JA4)
			continue
		}
		s.elem = t.lru.PushFront(s)
		t.m[e.JA4] = s
		for t.lru.Len() > t.max {
			old := t.lru.Back().Value.(*ja4FamStat)
			t.lru.Remove(old.elem)
			delete(t.m, old.ja4)
		}
	}
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}
