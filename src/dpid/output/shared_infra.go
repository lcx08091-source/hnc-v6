// shared_infra.go — v5.30 T1c: 「新发现的应用」排除公共基础设施。
//
// 用户截图: alibabadns.com(公共 DNS)、cdngslb.com / qtlcdn.com / ksyuncdn.com /
// lanniao.com(CDN / GSLB)、tencentcos.cn(对象存储)、wechatpay.cn(支付 SDK)
// 被当成「新发现的应用」, 还被起了「Apple 旗下应用」「网易云音乐」之类的名字。
// 这些域名被很多应用共用, 和谁共现都不说明它属于谁。两道防线:
//
//  1. 名单: etc/dpi_rules.d/shared_infra.txt(随规则目录由 dpi_rules_sync.sh
//     从模块同步, 模块升级即更新)。每行一个域名后缀: 主机名等于它或以 ".它"
//     结尾即命中; 含 * 的行是通配, * 只匹配一个标签里的若干字符(不跨点),
//     对可注册域比较(cdnhwc*.com 命中 cdnhwc1.com / cdnhwcprov.com)。
//     节点(可注册域)本身命中, 或节点上见过的主机名全部命中 → 共享基础设施。
//  2. 按设备频度兜底(不靠名单): 最近 discSharedWindowSec 内被
//     ≥ discSharedMinDevices 台不同设备访问, 且与 ≥ discSharedMinGroups 个
//     互不相关的组共现(边的有效权重 ≥ discSharedEdgeMin)的可注册域。
//     判定结果记 discSharedStickySec(写进 dpi_discover.json 的 shared_infra,
//     重启读回), 免得重启后边还没攒够时它又单独冒出来。
//
// 被判为共享基础设施的节点: 不参与合并、不单独成组、不当组名; 与某组有强边
// 时挂在该组的 shared 字段里(WebUI 标「公共服务」), 只作附属证据。
package output

import (
	"bufio"
	"bytes"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// SharedInfraFileName 共享基础设施名单文件名(放在规则目录 etc/dpi_rules.d/,
	// 模块里是 data/dpi_rules.d/; 规则加载器只读 *.json, 不会把它当规则)。
	SharedInfraFileName = "shared_infra.txt"

	discSharedMinDevices = 3           // 频度兜底: 窗口内至少这么多台不同设备
	discSharedMinGroups  = 4           // 频度兜底: 至少与这么多个互不相关的组共现
	discSharedWindowSec  = 86400       // 频度兜底: 设备计数的时间窗(秒)
	discSharedEdgeMin    = 1.0         // 频度兜底: 算「共现」的边有效权重下限
	discSharedStickySec  = 7 * 86400   // 频度判定结果保留时长(秒)
	discSharedMaxPerGrp  = 8           // 每组挂的共享域上限
	discSharedMaxOut     = 200         // shared_infra 落盘上限
	sharedInfraRecheck   = time.Minute // 名单文件 mtime 复查间隔
	sharedInfraMaxBytes  = 256 << 10   // 名单文件大小上限
	sharedReasonList     = "list"      // 命中名单
	sharedReasonFreq     = "freq"      // 频度兜底
)

// SharedInfra 解析后的名单(httpd 也用它过滤 / 标注, 同一份实现)。
type SharedInfra struct {
	suffix map[string]bool // 普通行: 主机名 == 它 或以 ".它" 结尾
	globs  []string        // 含 * 的行: 对可注册域按标签通配
}

// ParseSharedInfra 解析名单文本: # 起注释, 空行忽略, 统一小写、去首尾点。
func ParseSharedInfra(b []byte) *SharedInfra {
	s := &SharedInfra{suffix: map[string]bool{}}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		ln := sc.Text()
		if i := strings.IndexByte(ln, '#'); i >= 0 {
			ln = ln[:i]
		}
		ln = strings.Trim(strings.ToLower(strings.TrimSpace(ln)), ".")
		if ln == "" || strings.ContainsAny(ln, " \t/") {
			continue
		}
		if strings.Contains(ln, "*") {
			s.globs = append(s.globs, ln)
		} else {
			s.suffix[ln] = true
		}
	}
	return s
}

// Match 主机名(或可注册域)是否命中名单。nil 名单恒 false。
func (s *SharedInfra) Match(host string) bool {
	if s == nil {
		return false
	}
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return false
	}
	for h := host; ; {
		if s.suffix[h] {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	if len(s.globs) > 0 {
		reg := registrableDomain(host)
		for _, g := range s.globs {
			if globLabels(g, reg) {
				return true
			}
		}
	}
	return false
}

// globLabels 按标签逐个比较, 标签内 * 匹配任意个非点字符。标签数必须相同。
func globLabels(pat, s string) bool {
	pl, sl := strings.Split(pat, "."), strings.Split(s, ".")
	if len(pl) != len(sl) {
		return false
	}
	for i := range pl {
		if !globLabel(pl[i], sl[i]) {
			return false
		}
	}
	return true
}

func globLabel(p, s string) bool {
	if !strings.Contains(p, "*") {
		return p == s
	}
	parts := strings.Split(p, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, last)
}

// sharedInfraFile 名单文件 + mtime 缓存(Discoverer 持有, 在 d.mu 下使用)。
type sharedInfraFile struct {
	path    string
	checked time.Time
	mtime   time.Time
	size    int64
	cur     *SharedInfra
}

// get 每 sharedInfraRecheck 复查一次 mtime / size, 变了才重读。文件不存在 → nil
// (只剩频度兜底)。
func (f *sharedInfraFile) get(now time.Time) *SharedInfra {
	if f.path == "" {
		return nil
	}
	if !f.checked.IsZero() && now.Sub(f.checked) < sharedInfraRecheck && now.Sub(f.checked) >= 0 {
		return f.cur
	}
	f.checked = now
	st, err := os.Stat(f.path)
	if err != nil {
		f.cur, f.mtime, f.size = nil, time.Time{}, 0
		return nil
	}
	if f.cur != nil && st.ModTime().Equal(f.mtime) && st.Size() == f.size {
		return f.cur
	}
	if st.Size() > sharedInfraMaxBytes {
		return f.cur
	}
	b, err := os.ReadFile(f.path)
	if err != nil {
		return f.cur
	}
	f.cur, f.mtime, f.size = ParseSharedInfra(b), st.ModTime(), st.Size()
	return f.cur
}

// DiscoverShared 被判为共享基础设施的可注册域(组的附属证据 / 文件顶层清单)。
type DiscoverShared struct {
	Suffix  string `json:"suffix"`
	Reason  string `json:"reason"` // list / freq
	Hits    int64  `json:"hits,omitempty"`
	Devices int    `json:"devices,omitempty"`
	Since   int64  `json:"since,omitempty"` // freq: 判定时刻(顶层清单用, 重启读回保留)
}

// nodeListShared 节点本身命中名单, 或节点上见过的主机名全部命中(如名单写的是
// bugly.qq.com 这种子域、节点是 qq.com)。
func nodeListShared(n *discNode, si *SharedInfra) bool {
	if _, ok := IsAutoDetectedInfra(n.reg, si); ok {
		return true
	}
	if si == nil || len(n.hosts) == 0 {
		return false
	}
	for h := range n.hosts {
		if _, ok := IsAutoDetectedInfra(h, si); !ok {
			return false
		}
	}
	return true
}

// devsInWindow 最近 discSharedWindowSec 内见过的不同设备数。
func devsInWindow(n *discNode, now int64) int {
	c := 0
	for _, t := range n.devs {
		if now-t <= discSharedWindowSec {
			c++
		}
	}
	return c
}

// subsetNodes 去掉 exclude 后的节点 / 边(边两端都在才保留)。
func subsetNodes(nodes map[string]*discNode, edges map[discEdgeKey]*discEdge, exclude map[string]bool) (map[string]*discNode, map[discEdgeKey]*discEdge) {
	if len(exclude) == 0 {
		return nodes, edges
	}
	ns := make(map[string]*discNode, len(nodes))
	for k, n := range nodes {
		if !exclude[k] {
			ns[k] = n
		}
	}
	es := make(map[discEdgeKey]*discEdge, len(edges))
	for k, e := range edges {
		if !exclude[k.a] && !exclude[k.b] {
			es[k] = e
		}
	}
	return ns, es
}

// classifyShared 返回 reg → 原因(list / freq)。纯函数(sticky 为上次判定的
// freq 结果, reg → 判定时刻; 函数会把本次新判定的写进 sticky)。
//
// 频度兜底: 先把「名单命中」与「设备够多的候选」都拿掉跑一遍聚类(候选自己
// 往往是把几个应用糊在一起的桥, 留在图里数不出「几个互不相关的组」), 再数
// 每个候选的邻居落在几个不同的组里。
func classifyShared(nodes map[string]*discNode, edges map[discEdgeKey]*discEdge, adj map[string]map[string]*discEdge,
	now int64, si *SharedInfra, sticky map[string]int64) map[string]string {
	out := map[string]string{}
	excl := map[string]bool{}
	for reg, n := range nodes {
		if nodeListShared(n, si) {
			out[reg] = sharedReasonList
			excl[reg] = true
		}
	}
	cands := map[string]bool{}
	for reg, n := range nodes {
		if excl[reg] || hasDirectionalityVeto(reg) {
			continue
		}
		// 兼容 1~2 台设备的手机热点常态：多设备候选(>=3 台) 或 单/双设备超高连接度数星型枢纽(>=6 独立簇)进入拓扑检验
		const discSharedStarMinGroups = 6
		if devsInWindow(n, now) >= discSharedMinDevices || len(adj[reg]) >= discSharedStarMinGroups {
			cands[reg] = true
		}
	}
	if len(cands) > 0 {
		pass := make(map[string]bool, len(excl)+len(cands))
		for k := range excl {
			pass[k] = true
		}
		for k := range cands {
			pass[k] = true
		}
		ns, es := subsetNodes(nodes, edges, pass)
		byRoot, _ := discClusterCore(ns, es, now, discEdgeThreshold, discHubDegree)
		rootOf := make(map[string]string, len(ns))
		for r, members := range byRoot {
			for _, m := range members {
				rootOf[m.reg] = r
			}
		}
		rootAdj := map[string]map[string]bool{}
		for k, e := range es {
			if discDecay(e.w, e.t, now) < discSharedEdgeMin {
				continue
			}
			ra, rb := rootOf[k.a], rootOf[k.b]
			if ra != "" && rb != "" && ra != rb {
				if rootAdj[ra] == nil {
					rootAdj[ra] = map[string]bool{}
				}
				if rootAdj[rb] == nil {
					rootAdj[rb] = map[string]bool{}
				}
				rootAdj[ra][rb] = true
				rootAdj[rb][ra] = true
			}
		}
		for c := range cands {
			groups := map[string]bool{}
			for nb, e := range adj[c] {
				r, ok := rootOf[nb]
				if !ok || discDecay(e.w, e.t, now) < discSharedEdgeMin {
					continue
				}
				groups[r] = true
			}
			if len(groups) < discSharedMinGroups {
				continue
			}
			gList := make([]string, 0, len(groups))
			for g := range groups {
				gList = append(gList, g)
			}
			// 多设备(>=3 台, >=4 组)直接通过；单/双设备要求连接 >=6 个独立应用簇且邻居互不粘连（LCC < 0.20）
			if devsInWindow(nodes[c], now) >= discSharedMinDevices || (len(groups) >= 6 && neighborLCC(gList, rootAdj) < 0.20) {
				out[c] = sharedReasonFreq
				sticky[c] = now
			}
		}
	}
	for reg, t := range sticky {
		if now-t > discSharedStickySec {
			delete(sticky, reg)
			continue
		}
		if _, ok := out[reg]; !ok && nodes[reg] != nil {
			out[reg] = sharedReasonFreq
		}
	}
	return out
}

// attachShared 每组挂上与组内成员有强边的共享域(按命中降序, 最多
// discSharedMaxPerGrp 个)。
func attachShared(members []*discNode, shared map[string]string, nodes map[string]*discNode,
	adj map[string]map[string]*discEdge, now int64) []DiscoverShared {
	seen := map[string]bool{}
	var out []DiscoverShared
	for _, m := range members {
		for nb, e := range adj[m.reg] {
			reason, ok := shared[nb]
			if !ok || seen[nb] || discDecay(e.w, e.t, now) < discEdgeThreshold {
				continue
			}
			seen[nb] = true
			n := nodes[nb]
			if n == nil {
				continue
			}
			out = append(out, DiscoverShared{Suffix: nb, Reason: reason, Hits: n.hits, Devices: len(n.devs)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].Suffix < out[j].Suffix
	})
	if len(out) > discSharedMaxPerGrp {
		out = out[:discSharedMaxPerGrp]
	}
	return out
}

// sharedTopList 文件顶层 shared_infra: 本次判定的全部共享域(名单 + 频度),
// 按命中降序, 最多 discSharedMaxOut。freq 的带判定时刻(重启读回)。
func sharedTopList(shared map[string]string, nodes map[string]*discNode, sticky map[string]int64) []DiscoverShared {
	out := make([]DiscoverShared, 0, len(shared))
	for reg, reason := range shared {
		ds := DiscoverShared{Suffix: reg, Reason: reason}
		if n := nodes[reg]; n != nil {
			ds.Hits, ds.Devices = n.hits, len(n.devs)
		}
		if reason == sharedReasonFreq {
			ds.Since = sticky[reg]
		}
		out = append(out, ds)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].Suffix < out[j].Suffix
	})
	if len(out) > discSharedMaxOut {
		out = out[:discSharedMaxOut]
	}
	return out
}

// ── v7 四维零手动公共 CDN / 共享 SDK 自动识别扩展 ─────────────────────────
//
// 融合四路正交信号：
//   1) 统一静态知识库：shared_infra.txt + entity_db.json + auto_expand_blocklist.json + 词法结构启发式；
//   2) CNAME 跨域有向图汇点晋升（>=2 个异构外部主域 CNAME 指向同一目标主域 → 立即晋升公共 CDN）；
//   3) 源点方向否决护栏（Directionality Veto：自身子域向外 CNAME 到 CDN 且从不承接外部异构 CNAME 的主域，
//      一票否决晋升为公共 CDN，彻底防止误伤 qq.com / taobao.com 等甲方业务母域）；
//   4) 单设备热点星型共现拓扑（邻居簇 >= 4 且局部聚类系数 LCC < 0.20，1 台设备在线即可自动识别共享 SDK）。

var dynCNAMEInfra = struct {
	sync.RWMutex
	inboundSources map[string]map[string]bool // targetApex -> set of foreign srcApex
	outboundCDN    map[string]bool            // srcApex -> true (甲方业务源点保护标记)
	promotedApex   map[string]int64           // 自动晋升为公共 CDN 的 targetApex -> ts
	cnameSubHost   map[string]int64           // 具体业务子域(如 img.app.com -> *.kunlun.com) -> ts
}{
	inboundSources: map[string]map[string]bool{},
	outboundCDN:    map[string]bool{},
	promotedApex:   map[string]int64{},
	cnameSubHost:   map[string]int64{},
}

func sameBrandStem(apexA, apexB string) bool {
	a := strings.Split(apexA, ".")[0]
	b := strings.Split(apexB, ".")[0]
	if a == "" || b == "" {
		return false
	}
	return a == b || (len(a) >= 4 && strings.Contains(b, a)) || (len(b) >= 4 && strings.Contains(a, b))
}

// MatchLexicalInfra 词法启发式捕获未入库的通用 GSLB / 动态编号 CDN 节点（严控误报，不匹配业务主域）。
func MatchLexicalInfra(host string) bool {
	h := strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return false
	}
	reg := registrableDomain(h)
	if strings.Contains(reg, "cdngslb") || strings.Contains(reg, "wsglb") ||
		strings.Contains(reg, "ksyungslb") || strings.Contains(reg, "qiniudns") {
		return true
	}
	if strings.HasPrefix(reg, "kunlun") || strings.HasPrefix(reg, "cdnhwc") ||
		strings.HasPrefix(reg, "tdnsv") || strings.HasPrefix(reg, "smtcdns") {
		return true
	}
	return false
}

// RecordDNSChainForInfra 在 dpid 捕获 DNS 应答时调用，实时维护跨域 CNAME 拓扑。
func RecordDNSChainForInfra(qname string, recs []DNSAnswer, si *SharedInfra, now int64) {
	qn := normalizeName(qname)
	srcApex := registrableDomain(qn)
	if qn == "" || srcApex == "" || len(recs) == 0 {
		return
	}
	entityDB := loadEntityDB()
	blocklist, _ := loadBlocklist()

	isKnownInfra := func(h string) bool {
		ap := registrableDomain(h)
		if (si != nil && si.Match(h)) || MatchLexicalInfra(h) || entityIsShared(ap, entityDB) {
			return true
		}
		_, blk := blocklist[ap]
		return blk
	}

	dynCNAMEInfra.Lock()
	defer dynCNAMEInfra.Unlock()

	for _, r := range recs {
		if r.Type != 5 { // CNAME
			continue
		}
		tgt := normalizeName(r.Value)
		tgtApex := registrableDomain(tgt)
		if tgt == "" || tgtApex == "" || tgtApex == srcApex {
			continue
		}
		if isKnownInfra(tgt) || dynCNAMEInfra.promotedApex[tgtApex] > 0 {
			// 甲方业务源点向外指向已知 CDN：保护源点主域不被误判，同时标记该具体子域为 CDN 承载子域
			dynCNAMEInfra.outboundCDN[srcApex] = true
			if len(dynCNAMEInfra.cnameSubHost) < 4096 {
				dynCNAMEInfra.cnameSubHost[qn] = now
			}
		}
		if !sameBrandStem(srcApex, tgtApex) {
			srcs := dynCNAMEInfra.inboundSources[tgtApex]
			if srcs == nil {
				if len(dynCNAMEInfra.inboundSources) >= 2048 {
					continue
				}
				srcs = map[string]bool{}
				dynCNAMEInfra.inboundSources[tgtApex] = srcs
			}
			if len(srcs) < 16 {
				srcs[srcApex] = true
			}
			// 两个及以上互不隶属的外部业务主域 CNAME 汇入同一目标主域(且目标本身不是已观测到的纯甲方出站源) → 晋升公共 CDN
			if len(srcs) >= 2 && (!dynCNAMEInfra.outboundCDN[tgtApex] || len(srcs) >= 6) {
				dynCNAMEInfra.promotedApex[tgtApex] = now
				dynCNAMEInfra.outboundCDN[srcApex] = true
				if len(dynCNAMEInfra.cnameSubHost) < 4096 {
					dynCNAMEInfra.cnameSubHost[qn] = now
				}
			}
		}
	}
}

// IsAutoDetectedInfra 综合统一实体库、黑名单、词法规则与 CNAME 汇点拓扑判断主机是否属于共享基础设施。
func IsAutoDetectedInfra(host string, si *SharedInfra) (string, bool) {
	h := normalizeName(host)
	if h == "" {
		return "", false
	}
	if si != nil && si.Match(h) {
		return sharedReasonList, true
	}
	if MatchLexicalInfra(h) {
		return "lexical", true
	}
	ap := registrableDomain(h)
	if entityIsShared(ap, loadEntityDB()) {
		return "entity_db", true
	}
	if blk, _ := loadBlocklist(); blk != nil {
		if _, ok := blk[ap]; ok {
			return "blocklist", true
		}
	}
	dynCNAMEInfra.RLock()
	_, isProm := dynCNAMEInfra.promotedApex[ap]
	_, isSub := dynCNAMEInfra.cnameSubHost[h]
	dynCNAMEInfra.RUnlock()
	if isProm {
		return "cname_sink", true
	}
	if isSub {
		return "cname_sub", true
	}
	return "", false
}

// hasDirectionalityVeto 护栏 A：纯甲方源点主域（向外使用 CDN 但从不承接外部异构 CNAME）禁止误判为公共 CDN。
func hasDirectionalityVeto(apex string) bool {
	dynCNAMEInfra.RLock()
	defer dynCNAMEInfra.RUnlock()
	inCnt := len(dynCNAMEInfra.inboundSources[apex])
	return inCnt == 0 && dynCNAMEInfra.outboundCDN[apex]
}

// neighborLCC 计算候选节点邻居簇之间的局部聚类系数，星型公共 SDK/CDN 趋近于 0，同集团业务矩阵偏高。
func neighborLCC(groupRoots []string, rootAdj map[string]map[string]bool) float64 {
	k := len(groupRoots)
	if k < 2 {
		return 1.0
	}
	links := 0
	for i := 0; i < k; i++ {
		for j := i + 1; j < k; j++ {
			if rootAdj[groupRoots[i]][groupRoots[j]] {
				links++
			}
		}
	}
	return float64(2*links) / float64(k*(k-1))
}
