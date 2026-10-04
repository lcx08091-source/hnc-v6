// rulepack.go — v5.27 T6 导出 / 导入「我的规则包」(hnc-rulepack, schema 1)
//
// 把这台手机自己学到的 / 用户自己加的高可信规则打包导出(不含模块自带规则), 可备份、
// 可分享给另一台 HNC; 另一台导入后立即生效(只用来给流量贴应用标签)。
//
// 「我的」规则从哪来(导出时汇总, 全部只读):
//
//	etc/dpi_rules.d/_auto_expanded.json  自动扩展的子域名        全部
//	etc/dpi_rules.d/_auto_promoted.json  新应用晋升              全部
//	etc/dpi_rules.d/99-user-custom.json  用户自定义 / 新发现确认  全部; 与出厂规则同 id 时只导出出厂没有的后缀
//	data/dpi_user_rules.json             用户纠正                kind=domain / ja4(ip 不导出: 会过期、与网络环境有关)
//	data/fp_learned.json                 学到的 JA4(+QTP)指纹   可用、非通用、置信度 ≥ 0.8、支持度 ≥ 50
//	data/startup_fp.json                 启动指纹(T3)           可用的应用, 只导出特征 token 及频率
//	_imported.json / fp_imported.json / startup_fp_imported.json  已导入的别人的包: 默认不导出
//
// 隐私: 包里不出现 MAC、IP、UID、包名、设备散列(fp_learned 的 devs)、_evidence 的任何字段、
// 精确到秒的时间(只有日期)。导出时按白名单字段逐个拷贝, 不整条转存原始记录。
//
// 导入(包可能来自别人, 当不可信输入处理):
//
//	校验  format / schema 必须匹配; 未知顶层字段忽略; 条数上限(后缀 ≤ 5000、指纹 ≤ 2000、
//	      启动指纹 ≤ 500), 超了整包拒绝; id ^[a-z0-9_]{1,64}$; 后缀: 合法主机名、≥ 2 段、
//	      ≤ 253、不是公共后缀本身、不是 auto_expand_blocklist 里的共享 apex 本身; 类别必须是
//	      本机规则里出现过的; JA4 用 dpiJA4RE; qtp ^qtp1_[0-9a-f]{12}$。
//	冲突  后缀在本机规则(不含已导入的)里按最长后缀匹配已归给别的应用 → 跳过; 本机别的应用
//	      的子域名落在这个后缀下面(会被它「盖住」)→ 也跳过。防止别人的包把关键域名(如微信)
//	      挂到被限时的应用上。
//	落地  按 id / key 合并, 重复导入幂等, 原子写:
//	      域名规则 → etc/dpi_rules.d/_imported.json, id 改成 imp_<原 id>, attach_to 写成
//	      _parent_rule_id(T1 挂靠: 后缀并进本机同名应用), _source = "rulepack:<note>@<created>";
//	      指纹 → data/fp_imported.json(fp_learn.go 在学习表之后、种子表之前查);
//	      启动指纹 → data/startup_fp_imported.json(startup_fp.go 识别时并入, 本机学到的优先)。
//	生效  dpid 不需要重启 / rebind: rule.go 的 loadL3RulesFromDir 每次查询都 stat 规则目录,
//	      (最大 mtime, 总大小)变了就重编译; httpd 的应用目录同样按文件 mtime 缓存。
//
// 接口:
//
//	GET  /api/dpi_rulepack[?summary=1] → 各来源可导出条数 + 已导入条数
//	POST /api/dpi_rulepack {pack: "<json 文本>"} → 导入报告
//	action dpi_rulepack_export {note?, include_imported?} → exports/hnc-rulepack-YYYYMMDD-HHMMSS.json
//	action dpi_rulepack_clear → 删除全部已导入内容
package main

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	rulepackFormat        = "hnc-rulepack"
	rulepackSchema        = 1
	rulepackMaxBody       = 1258291 // 1.2 MB
	rulepackMaxSuffixes   = 5000
	rulepackMaxFP         = 2000
	rulepackMaxStartup    = 500
	rulepackMinFPConf     = 0.8
	rulepackMinFPSupport  = 50.0
	rulepackMaxStartupTok = 64
	rulepackImportedFile  = "_imported.json"
	autoExpandedFileName  = "_auto_expanded.json" // dpid output/auto_expand.go
	autoPromotedFileName  = "_auto_promoted.json" // dpid output/candidate.go
	rulepackIDPrefix      = "imp_"
)

var (
	rulepackIDRE   = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	rulepackDateRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	rulepackTokRE  = regexp.MustCompile(`^[a-z0-9#_-]+(\.[a-z0-9#_-]+)+$`)
	rulepackMu     sync.Mutex // 导入 / 清除 串行
)

// 多租户托管后缀: 子域属于各不相同的用户, 后缀本身不能归给任何一个应用
var rulepackSharedSuffixes = map[string]bool{
	"github.io": true, "githubusercontent.com": true, "blogspot.com": true, "appspot.com": true,
	"herokuapp.com": true, "netlify.app": true, "vercel.app": true, "pages.dev": true, "workers.dev": true,
	"azurewebsites.net": true, "cloudfront.net": true, "amazonaws.com": true, "fastly.net": true,
	"akamaized.net": true, "akamaihd.net": true, "web.app": true, "firebaseapp.com": true,
}

// ─── 包格式 ───────────────────────────────────────────────────────────

type rulepackCounts struct {
	DomainRules  int `json:"domain_rules"`
	Suffixes     int `json:"suffixes"`
	Fingerprints int `json:"fingerprints"`
	Startup      int `json:"startup"`
}

type rulepackDomain struct {
	ID       string   `json:"id"`
	App      string   `json:"app"`
	Category string   `json:"category"`
	AttachTo string   `json:"attach_to,omitempty"`
	Suffixes []string `json:"suffixes"`
	Source   string   `json:"source"`
}

type rulepackFP struct {
	JA4      string  `json:"ja4"`
	ALPN     string  `json:"alpn"`
	Port     string  `json:"port"`
	QTP      string  `json:"qtp,omitempty"`
	AppID    string  `json:"app_id"`
	App      string  `json:"app"`
	Category string  `json:"category"`
	Purity   float64 `json:"purity"`
	Support  float64 `json:"support"`
	Source   string  `json:"source"`
}

type rulepack struct {
	Format       string             `json:"format"`
	Schema       int                `json:"schema"`
	Created      string             `json:"created"`
	HNCVersion   string             `json:"hnc_version"`
	Note         string             `json:"note"`
	Counts       rulepackCounts     `json:"counts"`
	DomainRules  []rulepackDomain   `json:"domain_rules"`
	Fingerprints []rulepackFP       `json:"fingerprints"`
	Startup      []startupPackEntry `json:"startup"`
}

// ─── 本机规则 ─────────────────────────────────────────────────────────

type rpRawRule struct {
	ID       string   `json:"id"`
	App      string   `json:"app"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Suffixes []string `json:"suffixes"`
	Domains  []string `json:"domains"`
	Parent   string   `json:"_parent_rule_id"`
}

func (r rpRawRule) appName() string {
	if n := strings.TrimSpace(r.App); n != "" {
		return n
	}
	if n := strings.TrimSpace(r.Name); n != "" {
		return n
	}
	return r.ID
}

func (r rpRawRule) allSuffixes() []string {
	var out []string
	for _, s := range append(append([]string{}, r.Suffixes...), r.Domains...) {
		if h := rpNormHost(s); h != "" {
			out = append(out, h)
		}
	}
	return out
}

func rpNormHost(s string) string {
	h := strings.ToLower(strings.TrimSpace(s))
	h = strings.TrimPrefix(h, "*.")
	h = strings.TrimPrefix(h, ".")
	return strings.TrimSuffix(h, ".")
}

// rpReadRuleFile 读一个规则文件({"rules":[...]} 或裸数组), 上限 2 MB
func rpReadRuleFile(path string) ([]rpRawRule, bool) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 2<<20 {
		return nil, false
	}
	var wrap struct {
		Rules []rpRawRule `json:"rules"`
	}
	if json.Unmarshal(b, &wrap) == nil && wrap.Rules != nil {
		return wrap.Rules, true
	}
	var arr []rpRawRule
	if json.Unmarshal(b, &arr) == nil {
		return arr, true
	}
	return nil, false
}

func rpRulesDir(hncDir string) string { return filepath.Join(hncDir, "etc", "dpi_rules.d") }

// rpIsFactoryFile 运行目录里的出厂 bucket: 数字开头, 不是 97(在线更新)/ 99(用户自定义)
func rpIsFactoryFile(base string) bool {
	if base == "" || base[0] < '0' || base[0] > '9' || !strings.HasSuffix(base, ".json") {
		return false
	}
	return !strings.HasPrefix(base, "97-") && !strings.HasPrefix(base, "99-")
}

// rpLocal 本机规则视图(不含已导入的 _imported.json)
type rpLocal struct {
	byID       map[string]rpRawRule // 同 id 后写覆盖
	factory    map[string]map[string]bool
	owner      map[string]string   // 后缀 → 根应用 id
	childOwner map[string][]string // 后缀 p → 本机落在 p 下面(真子域)的后缀的根应用 id
	cats       map[string]bool
	blocked    map[string]bool
}

func (l *rpLocal) root(id string) string {
	seen := map[string]bool{}
	for {
		r, ok := l.byID[id]
		if !ok || r.Parent == "" || seen[id] {
			return id
		}
		p := strings.ToLower(strings.TrimSpace(r.Parent))
		if _, ok := l.byID[p]; !ok {
			return id
		}
		seen[id] = true
		id = p
	}
}

func rpLoadLocal(hncDir string) *rpLocal {
	l := &rpLocal{byID: map[string]rpRawRule{}, factory: map[string]map[string]bool{}, owner: map[string]string{},
		childOwner: map[string][]string{}, cats: map[string]bool{}, blocked: map[string]bool{}}
	files, _ := filepath.Glob(filepath.Join(rpRulesDir(hncDir), "*.json"))
	if len(files) == 0 {
		// 运行目录还没同步(或单测): 用 data/ 下的出厂副本
		files, _ = filepath.Glob(filepath.Join(hncDir, "data", "dpi_rules.d", "*.json"))
	}
	sort.Strings(files)
	order := []string{}
	for _, f := range files {
		base := filepath.Base(f)
		if base == rulepackImportedFile {
			continue
		}
		rules, ok := rpReadRuleFile(f)
		if !ok {
			continue
		}
		for _, r := range rules {
			id := strings.ToLower(strings.TrimSpace(r.ID))
			if id == "" {
				continue
			}
			r.ID = id
			if _, seen := l.byID[id]; !seen {
				order = append(order, id)
			}
			l.byID[id] = r
			if c := strings.ToLower(strings.TrimSpace(r.Category)); c != "" {
				l.cats[c] = true
			}
			if rpIsFactoryFile(base) {
				set := l.factory[id]
				if set == nil {
					set = map[string]bool{}
					l.factory[id] = set
				}
				for _, s := range r.allSuffixes() {
					set[s] = true
				}
			}
		}
	}
	for _, id := range order {
		owner := l.root(id)
		for _, s := range l.byID[id].allSuffixes() {
			if _, ok := l.owner[s]; !ok {
				l.owner[s] = owner
			}
			// 父域 → 子域归属(「盖住别的应用」检查用)
			for p := s; ; {
				i := strings.IndexByte(p, '.')
				if i < 0 {
					break
				}
				p = p[i+1:]
				if !strings.Contains(p, ".") {
					break
				}
				l.childOwner[p] = append(l.childOwner[p], owner)
			}
		}
	}
	for _, p := range []string{filepath.Join(hncDir, "etc", "auto_expand_blocklist.json"), filepath.Join(hncDir, "data", "auto_expand_blocklist.json")} {
		b, err := os.ReadFile(p)
		if err != nil || len(b) > 1<<20 {
			continue
		}
		var f struct {
			Blocked []string `json:"blocked_apex"`
		}
		if json.Unmarshal(b, &f) == nil {
			for _, x := range f.Blocked {
				l.blocked[rpNormHost(x)] = true
			}
			break
		}
	}
	return l
}

// longestOwner h 自身或父域在本机规则里的最长匹配 → 根应用 id
func (l *rpLocal) longestOwner(h string) (string, bool) {
	for cur := h; ; {
		if o, ok := l.owner[cur]; ok {
			return o, true
		}
		i := strings.IndexByte(cur, '.')
		if i < 0 {
			return "", false
		}
		cur = cur[i+1:]
	}
}

func rpPublicSuffix(h string) bool {
	return !strings.Contains(h, ".") || dpiNameTooBroad(h) || rulepackSharedSuffixes[h] ||
		h == "com.cn" || h == "net.cn" || h == "org.cn" || h == "gov.cn" || h == "edu.cn"
}

func rpValidHost(h string) bool {
	if len(h) > 253 || !dpiDomainRE.MatchString(h) || !strings.Contains(h, ".") {
		return false
	}
	for _, lab := range strings.Split(h, ".") {
		if lab == "" || len(lab) > 63 {
			return false
		}
	}
	return true
}

// rpCleanText 备注 / 应用名: 去控制字符、截断
func rpCleanText(s string, maxRunes int) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if unicode.IsControl(r) {
			continue
		}
		if n >= maxRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// ─── 导出 ─────────────────────────────────────────────────────────────

type rpSources struct {
	autoExpanded, autoPromoted, userCustom, userDomain []rulepackDomain
	fps, userJA4                                       []rulepackFP
	startup                                            []startupPackEntry
	impDomain                                          []rulepackDomain
	impFP                                              []rulepackFP
	impStartup                                         []startupPackEntry
}

func rpDomainFromRule(r rpRawRule, source string, suffixes []string, attach string, l *rpLocal) rulepackDomain {
	cat := strings.ToLower(strings.TrimSpace(r.Category))
	app := r.appName()
	if attach != "" {
		if p, ok := l.byID[attach]; ok {
			app = p.appName() // 用父应用的名字(自动扩展规则名带「(自动扩展: …)」)
			if cat == "" {
				cat = strings.ToLower(strings.TrimSpace(p.Category))
			}
		}
	}
	sort.Strings(suffixes)
	return rulepackDomain{ID: r.ID, App: app, Category: cat, AttachTo: attach, Suffixes: suffixes, Source: source}
}

func rpCollect(hncDir string, now time.Time) rpSources {
	var src rpSources
	l := rpLoadLocal(hncDir)
	dir := rpRulesDir(hncDir)
	readOwn := func(file, source string) []rulepackDomain {
		rules, _ := rpReadRuleFile(filepath.Join(dir, file))
		var out []rulepackDomain
		for _, r := range rules {
			id := strings.ToLower(strings.TrimSpace(r.ID))
			if !rulepackIDRE.MatchString(id) {
				continue
			}
			r.ID = id
			sufs := r.allSuffixes()
			attach := strings.ToLower(strings.TrimSpace(r.Parent))
			if source == "user_custom" {
				if fs, ok := l.factory[id]; ok {
					// 与出厂规则同 id: 只导出出厂没有的后缀, 挂靠到出厂规则
					var extra []string
					for _, s := range sufs {
						if !fs[s] {
							extra = append(extra, s)
						}
					}
					sufs, attach = extra, id
				}
			}
			if len(sufs) == 0 {
				continue
			}
			out = append(out, rpDomainFromRule(r, source, sufs, attach, l))
		}
		return out
	}
	src.autoExpanded = readOwn(autoExpandedFileName, "auto_expanded")
	src.autoPromoted = readOwn(autoPromotedFileName, "auto_promoted")
	src.userCustom = readOwn("99-user-custom.json", "user_custom")

	// 用户纠正: domain / ja4(ip 不导出)
	now64 := now.Unix()
	for _, u := range readDPIUserRules(hncDir) {
		if !u.live(now64) || !rulepackIDRE.MatchString(u.AppID) {
			continue
		}
		cat := strings.ToLower(strings.TrimSpace(u.Category))
		name := u.AppName
		if name == "" {
			name = u.AppID
		}
		switch u.Kind {
		case "domain":
			h := rpNormHost(u.Value)
			if !rpValidHost(h) {
				continue
			}
			attach := ""
			if _, ok := l.byID[u.AppID]; ok {
				attach = u.AppID
			}
			src.userDomain = append(src.userDomain, rulepackDomain{ID: u.AppID, App: name, Category: cat, AttachTo: attach,
				Suffixes: []string{h}, Source: "user_correction"})
		case "ja4":
			if !dpiJA4RE.MatchString(u.Value) {
				continue
			}
			src.userJA4 = append(src.userJA4, rulepackFP{JA4: u.Value, AppID: u.AppID, App: name, Category: cat,
				Purity: 1, Support: 0, Source: "user_correction"})
		}
	}
	// 合并同一应用的多条域名纠正
	src.userDomain = rpMergeDomains(src.userDomain)

	// 学到的指纹
	st := fpFor(hncDir)
	st.mu.Lock()
	st.loadLocked()
	for _, e := range st.m {
		v := e.verdict(now64)
		if !v.Usable || v.Generic || v.Conf < rulepackMinFPConf || v.Support < rulepackMinFPSupport ||
			!rulepackIDRE.MatchString(v.Top) || appTier(v.TopCat) == tierHidden {
			continue
		}
		name := v.TopName
		if name == "" {
			name = v.Top
		}
		src.fps = append(src.fps, rulepackFP{JA4: e.JA4, ALPN: e.ALPN, Port: e.Port, QTP: e.QTP, AppID: v.Top, App: name,
			Category: strings.ToLower(v.TopCat), Purity: round2(v.Purity), Support: math.Round(v.Support), Source: "learned"})
	}
	st.mu.Unlock()
	sort.Slice(src.fps, func(i, j int) bool { return rpFPKey(src.fps[i]) < rpFPKey(src.fps[j]) })

	// 启动指纹: 可用的应用, 只导出特征 token 及频率
	learned, _ := startupFor(hncDir).learnedView(now)
	cat := loadAppCatalog(hncDir)
	for _, a := range learned {
		if !a.Usable || !rulepackIDRE.MatchString(a.AppID) {
			continue
		}
		e := startupPackEntry{AppID: a.AppID, App: a.Name, Starts: int(math.Round(a.Starts))}
		if c := cat.apps[a.AppID]; c != nil {
			e.Category = c.Category
		}
		for _, t := range a.Tokens {
			if t.Feat {
				e.Tokens = append(e.Tokens, startupPackTok{T: t.T, F: t.F})
			}
		}
		if len(e.Tokens) > 0 {
			src.startup = append(src.startup, e)
		}
	}

	// 已导入的(默认不导出)
	if rules, ok := rpReadRuleFile(filepath.Join(dir, rulepackImportedFile)); ok {
		for _, r := range rules {
			id := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(r.ID)), rulepackIDPrefix)
			if !rulepackIDRE.MatchString(id) {
				continue
			}
			sufs := r.allSuffixes()
			if len(sufs) == 0 {
				continue
			}
			sort.Strings(sufs)
			src.impDomain = append(src.impDomain, rulepackDomain{ID: id, App: r.appName(), Category: strings.ToLower(r.Category),
				AttachTo: strings.ToLower(strings.TrimSpace(r.Parent)), Suffixes: sufs, Source: "imported"})
		}
	}
	for _, f := range rpReadImportedFP(hncDir) {
		f.Source = "imported"
		src.impFP = append(src.impFP, f)
	}
	src.impStartup = rpReadImportedStartup(hncDir)
	return src
}

func rpMergeDomains(in []rulepackDomain) []rulepackDomain {
	idx := map[string]int{}
	var out []rulepackDomain
	for _, d := range in {
		k := d.ID + "|" + d.Source
		if i, ok := idx[k]; ok {
			seen := map[string]bool{}
			for _, s := range out[i].Suffixes {
				seen[s] = true
			}
			for _, s := range d.Suffixes {
				if !seen[s] {
					out[i].Suffixes = append(out[i].Suffixes, s)
				}
			}
			sort.Strings(out[i].Suffixes)
			continue
		}
		idx[k] = len(out)
		out = append(out, d)
	}
	return out
}

func rpFPKey(f rulepackFP) string { return fpKeyQ(f.JA4, f.ALPN, f.Port, f.QTP) }

// buildRulepack 生成规则包(纯读)
func buildRulepack(hncDir, note string, includeImported bool, version string, now time.Time) rulepack {
	src := rpCollect(hncDir, now)
	p := rulepack{Format: rulepackFormat, Schema: rulepackSchema, Created: now.Format("2006-01-02"),
		HNCVersion: version, Note: rpCleanText(note, 200),
		DomainRules: []rulepackDomain{}, Fingerprints: []rulepackFP{}, Startup: []startupPackEntry{}}
	p.DomainRules = append(p.DomainRules, src.autoExpanded...)
	p.DomainRules = append(p.DomainRules, src.autoPromoted...)
	p.DomainRules = append(p.DomainRules, src.userCustom...)
	p.DomainRules = append(p.DomainRules, src.userDomain...)
	p.Fingerprints = append(p.Fingerprints, src.userJA4...)
	p.Fingerprints = append(p.Fingerprints, src.fps...)
	p.Startup = append(p.Startup, src.startup...)
	if includeImported {
		p.DomainRules = append(p.DomainRules, src.impDomain...)
		p.Fingerprints = append(p.Fingerprints, src.impFP...)
		have := map[string]bool{}
		for _, s := range p.Startup {
			have[s.AppID] = true
		}
		for _, s := range src.impStartup {
			if !have[s.AppID] {
				p.Startup = append(p.Startup, s)
			}
		}
	}
	p.Counts.DomainRules = len(p.DomainRules)
	for _, d := range p.DomainRules {
		p.Counts.Suffixes += len(d.Suffixes)
	}
	p.Counts.Fingerprints = len(p.Fingerprints)
	p.Counts.Startup = len(p.Startup)
	return p
}

func rpSuffixCount(l []rulepackDomain) int {
	n := 0
	for _, d := range l {
		n += len(d.Suffixes)
	}
	return n
}

// rulepackSummary 各来源可导出条数(给前端显示)
func rulepackSummary(hncDir string, now time.Time) map[string]interface{} {
	src := rpCollect(hncDir, now)
	part := func(l []rulepackDomain) map[string]int {
		return map[string]int{"rules": len(l), "suffixes": rpSuffixCount(l)}
	}
	domain := len(src.autoExpanded) + len(src.autoPromoted) + len(src.userCustom) + len(src.userDomain)
	return map[string]interface{}{
		"ok": true,
		"sources": map[string]interface{}{
			"auto_expanded":    part(src.autoExpanded),
			"auto_promoted":    part(src.autoPromoted),
			"user_custom":      part(src.userCustom),
			"user_corrections": map[string]int{"domain": len(src.userDomain), "ja4": len(src.userJA4)},
			"fingerprints":     len(src.fps),
			"startup":          len(src.startup),
		},
		"exportable": rulepackCounts{DomainRules: domain,
			Suffixes:     rpSuffixCount(src.autoExpanded) + rpSuffixCount(src.autoPromoted) + rpSuffixCount(src.userCustom) + rpSuffixCount(src.userDomain),
			Fingerprints: len(src.fps) + len(src.userJA4), Startup: len(src.startup)},
		"imported": rulepackCounts{DomainRules: len(src.impDomain), Suffixes: rpSuffixCount(src.impDomain),
			Fingerprints: len(src.impFP), Startup: len(src.impStartup)},
	}
}

func rulepackExportName(now time.Time) string {
	return "hnc-rulepack-" + now.Format("20060102-150405") + ".json"
}

func isRulepackExport(n string) bool {
	return strings.HasPrefix(n, "hnc-rulepack-") && strings.HasSuffix(n, ".json") && !strings.ContainsAny(n, "/\\")
}

// actionDPIRulepackExport 生成规则包到 exports/, 返回文件名(前端照抄 debugBundle 的下载方式)
func actionDPIRulepackExport(s *server, p map[string]string) actionResp {
	now := time.Now()
	inc := p["include_imported"] == "1" || p["include_imported"] == "true"
	pack := buildRulepack(s.hncDir, p["note"], inc, s.detectHNCVersion(), now)
	b, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return actionResp{OK: false, Error: "marshal failed", Detail: err.Error()}
	}
	dir := filepath.Join(s.hncDir, "exports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return actionResp{OK: false, Error: "mkdir failed", Detail: err.Error()}
	}
	name := rulepackExportName(now)
	path := filepath.Join(dir, name)
	if err := writeFileAtomic(path, b); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	_ = os.Chmod(path, 0o600)
	d, _ := json.Marshal(map[string]interface{}{"name": name, "path": path, "counts": pack.Counts, "bytes": len(b)})
	return actionResp{OK: true, Detail: string(d)}
}

// ─── 导入 ─────────────────────────────────────────────────────────────

type rulepackReport struct {
	OK        bool           `json:"ok"`
	Added     rulepackCounts `json:"added"`     // 新增(域名规则 = 新的 imp_ id)
	Merged    rulepackCounts `json:"merged"`    // 并进已导入的同 id / 同 key
	Unchanged rulepackCounts `json:"unchanged"` // 已有, 没有变化(重复导入)
	Skipped   map[string]int `json:"skipped"`
	Conflicts []string       `json:"conflicts,omitempty"` // 前 20 条「后缀 → 已归 应用」
	Source    string         `json:"source"`
}

func (r *rulepackReport) skip(reason string, n int) {
	if n > 0 {
		r.Skipped[reason] += n
	}
}

type rpImportedFPFile struct {
	Schema  int          `json:"schema"`
	Entries []rulepackFP `json:"entries"`
}

func fpImportedPath(hncDir string) string { return filepath.Join(hncDir, "data", "fp_imported.json") }

func rpReadImportedFP(hncDir string) []rulepackFP {
	b, err := os.ReadFile(fpImportedPath(hncDir))
	if err != nil || len(b) > 4<<20 {
		return nil
	}
	var f rpImportedFPFile
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	return f.Entries
}

func rpReadImportedStartup(hncDir string) []startupPackEntry {
	b, err := os.ReadFile(startupImportedPath(hncDir))
	if err != nil || len(b) > startupFileMaxBytes {
		return nil
	}
	var f struct {
		Startup []startupPackEntry `json:"startup"`
	}
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	return f.Startup
}

var errRulepackFormat = errors.New("不是 HNC 规则包(format / schema 不匹配)")

// importRulepack 校验并落地一个规则包(不可信输入)
func importRulepack(hncDir string, body []byte, now time.Time) (rulepackReport, error) {
	rep := rulepackReport{Skipped: map[string]int{}}
	var pack struct {
		Format       string            `json:"format"`
		Schema       int               `json:"schema"`
		Created      string            `json:"created"`
		Note         string            `json:"note"`
		DomainRules  []json.RawMessage `json:"domain_rules"`
		Fingerprints []json.RawMessage `json:"fingerprints"`
		Startup      []json.RawMessage `json:"startup"`
	}
	if err := json.Unmarshal(body, &pack); err != nil {
		return rep, errors.New("JSON 解析失败")
	}
	if pack.Format != rulepackFormat || pack.Schema != rulepackSchema {
		return rep, errRulepackFormat
	}
	doms := make([]rulepackDomain, 0, len(pack.DomainRules))
	nSuf := 0
	for _, raw := range pack.DomainRules {
		var d rulepackDomain
		if json.Unmarshal(raw, &d) != nil {
			rep.skip("bad_entry", 1)
			continue
		}
		nSuf += len(d.Suffixes)
		doms = append(doms, d)
	}
	if nSuf > rulepackMaxSuffixes || len(pack.DomainRules) > rulepackMaxSuffixes {
		return rep, errors.New("域名后缀超过 " + strconv.Itoa(rulepackMaxSuffixes) + " 条, 整包拒绝")
	}
	if len(pack.Fingerprints) > rulepackMaxFP {
		return rep, errors.New("指纹超过 " + strconv.Itoa(rulepackMaxFP) + " 条, 整包拒绝")
	}
	if len(pack.Startup) > rulepackMaxStartup {
		return rep, errors.New("启动指纹超过 " + strconv.Itoa(rulepackMaxStartup) + " 个应用, 整包拒绝")
	}
	created := ""
	if rulepackDateRE.MatchString(pack.Created) {
		created = pack.Created
	}
	rep.Source = "rulepack:" + rpCleanText(strings.NewReplacer("@", "_", ":", "_").Replace(pack.Note), 64) + "@" + created

	rulepackMu.Lock()
	defer rulepackMu.Unlock()
	l := rpLoadLocal(hncDir)

	// ── 域名规则 ──
	type impRule struct {
		ID       string   `json:"id"`
		App      string   `json:"app"`
		Category string   `json:"category"`
		Suffixes []string `json:"suffixes"`
		Parent   string   `json:"_parent_rule_id,omitempty"`
		Source   string   `json:"_source,omitempty"`
	}
	impPath := filepath.Join(rpRulesDir(hncDir), rulepackImportedFile)
	var existing []impRule
	if b, err := os.ReadFile(impPath); err == nil && len(b) <= 2<<20 {
		var f struct {
			Rules []impRule `json:"rules"`
		}
		if json.Unmarshal(b, &f) == nil {
			existing = f.Rules
		}
	}
	exIdx := map[string]int{}
	for i, r := range existing {
		exIdx[r.ID] = i
	}
	domChanged := false
	for _, d := range doms {
		id := strings.TrimSpace(d.ID)
		if !rulepackIDRE.MatchString(id) {
			rep.skip("bad_id", len(d.Suffixes))
			continue
		}
		cat := strings.ToLower(strings.TrimSpace(d.Category))
		if !l.cats[cat] {
			rep.skip("bad_category", len(d.Suffixes))
			continue
		}
		attach := strings.TrimSpace(d.AttachTo)
		if attach != "" && !rulepackIDRE.MatchString(attach) {
			rep.skip("bad_attach", len(d.Suffixes))
			continue
		}
		// 归属目标: 挂靠到本机已有应用(的根), 否则是一个新应用 imp_<id>
		impID := rulepackIDPrefix + id
		if len(impID) > 64 {
			impID = impID[:64]
		}
		target := impID
		if attach != "" {
			if _, ok := l.byID[attach]; ok {
				target = l.root(attach)
			}
		}
		var keep []string
		seen := map[string]bool{}
		for _, raw := range d.Suffixes {
			h := rpNormHost(raw)
			switch {
			case !rpValidHost(h):
				rep.skip("bad_suffix", 1)
				continue
			case rpPublicSuffix(h):
				rep.skip("public_suffix", 1)
				continue
			case l.blocked[h]:
				rep.skip("shared_apex", 1)
				continue
			case seen[h]:
				continue
			}
			if o, ok := l.longestOwner(h); ok {
				if o == target {
					rep.skip("already_local", 1)
				} else {
					rep.skip("conflict", 1)
					if len(rep.Conflicts) < 20 {
						rep.Conflicts = append(rep.Conflicts, h+" → 已归 "+o)
					}
				}
				continue
			}
			if covered := rpOtherOwner(l.childOwner[h], target); covered != "" {
				rep.skip("conflict", 1)
				if len(rep.Conflicts) < 20 {
					rep.Conflicts = append(rep.Conflicts, h+" → 会盖住 "+covered+" 的子域名")
				}
				continue
			}
			seen[h] = true
			keep = append(keep, h)
		}
		if len(keep) == 0 {
			continue
		}
		app := rpCleanText(d.App, 64)
		if app == "" {
			app = id
		}
		if i, ok := exIdx[impID]; ok {
			have := map[string]bool{}
			for _, s := range existing[i].Suffixes {
				have[s] = true
			}
			added := 0
			for _, s := range keep {
				if !have[s] {
					existing[i].Suffixes = append(existing[i].Suffixes, s)
					added++
				}
			}
			if added > 0 {
				sort.Strings(existing[i].Suffixes)
				existing[i].Source = rep.Source
				rep.Merged.DomainRules++
				rep.Merged.Suffixes += added
				domChanged = true
			} else {
				rep.Unchanged.DomainRules++
			}
			rep.Unchanged.Suffixes += len(keep) - added
			continue
		}
		sort.Strings(keep)
		r := impRule{ID: impID, App: app, Category: cat, Suffixes: keep, Source: rep.Source}
		if attach != "" {
			r.Parent = attach
		}
		exIdx[impID] = len(existing)
		existing = append(existing, r)
		rep.Added.DomainRules++
		rep.Added.Suffixes += len(keep)
		domChanged = true
	}

	// ── 指纹 ──
	fpList := rpReadImportedFP(hncDir)
	fpIdx := map[string]int{}
	for i, f := range fpList {
		fpIdx[rpFPKey(f)] = i
	}
	fpChanged := false
	for _, raw := range pack.Fingerprints {
		var f rulepackFP
		if json.Unmarshal(raw, &f) != nil {
			rep.skip("bad_entry", 1)
			continue
		}
		f.Port = strings.TrimSpace(f.Port)
		if f.Port == "" {
			f.Port = "443"
		}
		cat := strings.ToLower(strings.TrimSpace(f.Category))
		switch {
		case !dpiJA4RE.MatchString(f.JA4):
			rep.skip("bad_ja4", 1)
			continue
		case f.QTP != "" && !fpQTPRE.MatchString(f.QTP):
			rep.skip("bad_qtp", 1)
			continue
		case !rulepackIDRE.MatchString(f.AppID):
			rep.skip("bad_id", 1)
			continue
		case !l.cats[cat] || appTier(cat) == tierHidden:
			rep.skip("bad_category", 1)
			continue
		case f.Port != "443" && f.Port != "80" && f.Port != "other":
			rep.skip("bad_port", 1)
			continue
		case len(f.ALPN) > 32 || strings.ContainsAny(f.ALPN, "|\"\\") || rpCleanText(f.ALPN, 32) != f.ALPN:
			rep.skip("bad_alpn", 1)
			continue
		case math.IsNaN(f.Purity) || f.Purity < 0 || f.Purity > 1 || math.IsNaN(f.Support) || f.Support < 0 || f.Support > 1e9:
			rep.skip("bad_value", 1)
			continue
		}
		f.Category = cat
		f.App = rpCleanText(f.App, 64)
		if f.App == "" {
			f.App = f.AppID
		}
		f.Source = rep.Source
		f.Support = math.Round(f.Support)
		f.Purity = round2(f.Purity)
		k := rpFPKey(f)
		if i, ok := fpIdx[k]; ok {
			old := fpList[i]
			if old.AppID == f.AppID && old.App == f.App && old.Category == f.Category && old.Purity == f.Purity && old.Support == f.Support {
				rep.Unchanged.Fingerprints++
				continue
			}
			fpList[i] = f
			rep.Merged.Fingerprints++
			fpChanged = true
			continue
		}
		fpIdx[k] = len(fpList)
		fpList = append(fpList, f)
		rep.Added.Fingerprints++
		fpChanged = true
	}

	// ── 启动指纹 ──
	suList := rpReadImportedStartup(hncDir)
	suIdx := map[string]int{}
	for i, s := range suList {
		suIdx[s.AppID] = i
	}
	suChanged := false
	for _, raw := range pack.Startup {
		var s startupPackEntry
		if json.Unmarshal(raw, &s) != nil {
			rep.skip("bad_entry", 1)
			continue
		}
		cat := strings.ToLower(strings.TrimSpace(s.Category))
		if !rulepackIDRE.MatchString(s.AppID) {
			rep.skip("bad_id", 1)
			continue
		}
		if cat != "" && !l.cats[cat] {
			rep.skip("bad_category", 1)
			continue
		}
		if s.Starts < 0 || s.Starts > 1e6 {
			rep.skip("bad_value", 1)
			continue
		}
		var toks []startupPackTok
		seen := map[string]bool{}
		for _, t := range s.Tokens {
			tt := strings.ToLower(strings.TrimSpace(t.T))
			if len(tt) > 253 || !rulepackTokRE.MatchString(tt) || seen[tt] || math.IsNaN(t.F) || t.F <= 0 || t.F > 1 {
				rep.skip("bad_token", 1)
				continue
			}
			seen[tt] = true
			toks = append(toks, startupPackTok{T: tt, F: round2(t.F)})
			if len(toks) >= rulepackMaxStartupTok {
				break
			}
		}
		if len(toks) < startupMinFeat {
			rep.skip("too_few_tokens", 1)
			continue
		}
		e := startupPackEntry{AppID: s.AppID, App: rpCleanText(s.App, 64), Category: cat, Starts: s.Starts, Tokens: toks}
		if e.App == "" {
			e.App = e.AppID
		}
		if i, ok := suIdx[e.AppID]; ok {
			ob, _ := json.Marshal(suList[i])
			nb, _ := json.Marshal(e)
			if string(ob) == string(nb) {
				rep.Unchanged.Startup++
				continue
			}
			suList[i] = e
			rep.Merged.Startup++
			suChanged = true
			continue
		}
		suIdx[e.AppID] = len(suList)
		suList = append(suList, e)
		rep.Added.Startup++
		suChanged = true
	}

	// ── 落地(原子写)──
	if domChanged {
		sort.Slice(existing, func(i, j int) bool { return existing[i].ID < existing[j].ID })
		doc := map[string]interface{}{
			"schema_version": "2.0", "subset": "_imported",
			"rules_version": "imported-" + now.Format("20060102"), "rules": existing,
		}
		b, _ := json.MarshalIndent(doc, "", "  ")
		if err := os.MkdirAll(rpRulesDir(hncDir), 0o755); err != nil {
			return rep, err
		}
		if err := writeFileAtomic(impPath, b); err != nil {
			return rep, err
		}
		_ = os.Chmod(impPath, 0o644)
	}
	if fpChanged {
		sort.Slice(fpList, func(i, j int) bool { return rpFPKey(fpList[i]) < rpFPKey(fpList[j]) })
		b, _ := json.Marshal(rpImportedFPFile{Schema: 1, Entries: fpList})
		if err := writeFileAtomic(fpImportedPath(hncDir), b); err != nil {
			return rep, err
		}
	}
	if suChanged {
		sort.Slice(suList, func(i, j int) bool { return suList[i].AppID < suList[j].AppID })
		b, _ := json.Marshal(map[string]interface{}{"schema": 1, "startup": suList})
		if err := writeFileAtomic(startupImportedPath(hncDir), b); err != nil {
			return rep, err
		}
	}
	rep.OK = true
	return rep, nil
}

// rpOtherOwner 子域名归属里第一个不是 target 的应用
func rpOtherOwner(owners []string, target string) string {
	for _, o := range owners {
		if o != target {
			return o
		}
	}
	return ""
}

// actionDPIRulepackClear 删除全部已导入内容
func actionDPIRulepackClear(hncDir string) actionResp {
	rulepackMu.Lock()
	defer rulepackMu.Unlock()
	n := 0
	for _, p := range []string{filepath.Join(rpRulesDir(hncDir), rulepackImportedFile), fpImportedPath(hncDir), startupImportedPath(hncDir)} {
		if err := os.Remove(p); err == nil {
			n++
		} else if !os.IsNotExist(err) {
			return actionResp{OK: false, Error: "remove failed", Detail: err.Error()}
		}
	}
	return actionResp{OK: true, Detail: "removed " + strconv.Itoa(n) + " file(s)"}
}

// ─── HTTP ─────────────────────────────────────────────────────────────

// apiDPIRulepack GET → 摘要; POST {pack} → 导入
func (s *server) apiDPIRulepack(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, rulepackSummary(s.hncDir, time.Now()))
		return
	}
	s.requireMutationN(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Pack json.RawMessage `json:"pack"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Pack) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "bad json"})
			return
		}
		body := []byte(req.Pack)
		// pack 可以是 JSON 文本(字符串)或直接是对象
		var txt string
		if json.Unmarshal(body, &txt) == nil {
			body = []byte(strings.TrimSpace(txt))
		}
		if len(body) == 0 || len(body) > rulepackMaxBody || !json.Valid(body) {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "pack must be valid JSON ≤ 1.2 MB"})
			return
		}
		rep, err := importRulepack(s.hncDir, body, time.Now())
		res := "ok"
		detail := "added " + strconv.Itoa(rep.Added.Suffixes) + " suffixes, " + strconv.Itoa(rep.Added.Fingerprints) + " fp, " + strconv.Itoa(rep.Added.Startup) + " startup"
		if err != nil {
			res, detail = "error", err.Error()
		}
		auditLog(s.hncDir, writeRateKey(r), "dpi_rulepack_import", map[string]string{"bytes": strconv.Itoa(len(body))}, res, detail)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": err.Error(), "report": rep})
			return
		}
		writeJSON(w, http.StatusOK, rep)
	}, rulepackMaxRequest)(w, r)
}

// rulepackMaxRequest 请求体上限: pack 作为 JSON 字符串传时引号 / 反斜杠 / 非 ASCII 都会被转义
// (最坏 \uXXXX 六倍), 按 6 倍 + 余量放行, 解出来的规则包本身仍按 1.2 MB 校验。
const rulepackMaxRequest = 6*rulepackMaxBody + 64*1024
