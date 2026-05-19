// Package output - rule.go: rc29 L3 rule library.
//
// rc20.1 only matched DNS/SNI suffixes. rc28.1.x added schema fields
// (ip_matchers/ipv6_matchers/priority/sub_categories/ground_truth) but the
// rc20.1->rc28.1.1 binary never read them. rc29 finally reads them so the
// rule library actually does what its schema promises.
//
// External rule path:  /data/local/hnc/etc/dpi_rules.json
// On parse error or missing file we fall back to a small built-in set.

package output

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
)

const externalRulesPath = "/data/local/hnc/etc/dpi_rules.json"

// PriorityClass orders matches when several rules hit the same flow/host.
// "specific" rules win over "fallback" rules; rules without an explicit
// priority are treated as "specific" so legacy rule files keep working.
type PriorityClass int

const (
	PrioritySpecific PriorityClass = 0
	PriorityFallback PriorityClass = 1
)

func priorityFromString(s string) PriorityClass {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "fallback":
		return PriorityFallback
	default:
		return PrioritySpecific
	}
}

// l3Rule is the compiled in-memory form. We keep the external file format
// flexible (see externalRule below) but compile each rule once into this
// stricter shape so classify hot-path doesn't re-parse strings.
type l3Rule struct {
	ID            string
	Name          string
	Category      string
	Priority      PriorityClass
	Suffixes      []string
	IPMatchers    []ipMatcher
	IPv6Matchers  []ipMatcher
	SubCategories []subCategory
	Verified      bool // ground_truth.verified
}

// ipMatcher is a compiled CIDR + (proto, ports) tuple. Used for both IPv4
// and IPv6 — for IPv6 we just store the v6 *net.IPNet.
type ipMatcher struct {
	Net   *net.IPNet
	Proto matchProto
	Ports []uint16
	// PortsPattern is a coarse fallback when explicit ports aren't known
	// (e.g. "dynamic_high"). Empty if not used.
	PortsPattern string
	Purpose      string // free-form, for telemetry only
}

type matchProto uint8

const (
	protoAny  matchProto = 0
	protoTCP  matchProto = 1
	protoUDP  matchProto = 2
	protoBoth matchProto = 3 // "tcp+udp"
)

func protoFromString(s string) matchProto {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp":
		return protoTCP
	case "udp":
		return protoUDP
	case "tcp+udp", "udp+tcp", "both":
		return protoBoth
	default:
		return protoAny
	}
}

// matches returns true if the matcher fires on this flow.
// proto==protoAny in the matcher means "any L4 proto"; an empty Ports list
// means "any port within the CIDR" (still must match proto).
func (m *ipMatcher) matches(ip net.IP, proto matchProto, port uint16) bool {
	if m.Net == nil {
		return false
	}
	if !m.Net.Contains(ip) {
		return false
	}
	if m.Proto != protoAny && proto != protoAny {
		if !protoCompatible(m.Proto, proto) {
			return false
		}
	}
	if len(m.Ports) == 0 {
		return true
	}
	for _, p := range m.Ports {
		if p == port {
			return true
		}
	}
	return false
}

func protoCompatible(want, got matchProto) bool {
	if want == got {
		return true
	}
	if want == protoBoth && (got == protoTCP || got == protoUDP) {
		return true
	}
	if got == protoBoth && (want == protoTCP || want == protoUDP) {
		return true
	}
	return false
}

// subCategory is a finer label that fires when a parent rule's flow exhibits
// a specific behavioural pattern (e.g. wechat -> voice_call when UDP
// 183.232.84.0/24:8000 sustains > 200 pps).
type subCategory struct {
	Key      string
	Name     string
	Category string
	// Behavioural detector. For rc29 we support a single rate-based detector.
	DetectIP     *net.IPNet
	DetectPort   uint16
	DetectProto  matchProto
	DetectPPSMin float64
}

// ─── external file shape ──────────────────────────────────────────────
// We accept rc28.1.x schema in full but also keep rc20.1 compatibility:
// rc20.1 used "suffixes" / "domains" / "matchers[type=domain_suffix]".

type externalRuleFile struct {
	SchemaVersion string         `json:"schema_version"`
	RulesVersion  string         `json:"rules_version"`
	Rules         []externalRule `json:"rules"`
}

type externalRule struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	App           string                 `json:"app"`
	Category      string                 `json:"category"`
	Priority      string                 `json:"priority"`
	Suffixes      []string               `json:"suffixes"`
	Domains       []string               `json:"domains"`
	Matchers      []externalMatcher      `json:"matchers"`
	IPMatchers    []externalIPMatcher    `json:"ip_matchers"`
	IPv6Matchers  []externalIPMatcher    `json:"ipv6_matchers"`
	SubCategories map[string]externalSub `json:"sub_categories"`
	GroundTruth   *externalGT            `json:"ground_truth"`
}

type externalMatcher struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type externalIPMatcher struct {
	CIDR         string `json:"cidr"`
	Proto        string `json:"proto"`
	Ports        []int  `json:"ports"`
	PortsPattern string `json:"ports_pattern"`
	Purpose      string `json:"purpose"`
	Note         string `json:"note"`
	// Evidence fields are advisory and ignored by classifier:
	EvidencePackets int     `json:"evidence_packets"`
	RatePPSActive   float64 `json:"rate_pps_active"`
}

type externalSub struct {
	Name     string `json:"name"`
	Detect   string `json:"detect"`
	Category string `json:"category"`
}

type externalGT struct {
	Verified        bool   `json:"verified"`
	Date            string `json:"date"`
	PacketsObserved int    `json:"packets_observed"`
}

// loadedRules is the compiled rule set + a version tag for telemetry.
type loadedRules struct {
	version string
	rules   []l3Rule
}

var ruleCache = struct {
	sync.Mutex
	mtime int64
	size  int64
	val   loadedRules
}{val: loadedRules{version: "builtin-rc29", rules: builtinRules}}

// currentL3RuleVersion returns the version tag (refreshing if mtime changed).
func currentL3RuleVersion() string {
	lr := loadL3Rules()
	if lr.version == "" {
		return "builtin-rc29"
	}
	return lr.version
}

// loadL3Rules reads /data/local/hnc/etc/dpi_rules.json with mtime-based
// caching. Falls back to builtinRules on any error.
func loadL3Rules() loadedRules {
	st, err := os.Stat(externalRulesPath)
	if err != nil {
		ruleCache.Lock()
		defer ruleCache.Unlock()
		ruleCache.mtime = 0
		ruleCache.size = 0
		ruleCache.val = loadedRules{version: "builtin-rc29", rules: builtinRules}
		return ruleCache.val
	}
	mtime := st.ModTime().UnixNano()
	size := st.Size()

	ruleCache.Lock()
	if ruleCache.mtime == mtime && ruleCache.size == size && len(ruleCache.val.rules) > 0 {
		v := ruleCache.val
		ruleCache.Unlock()
		return v
	}
	ruleCache.Unlock()

	b, err := os.ReadFile(externalRulesPath)
	if err != nil || len(b) == 0 || len(b) > 1024*1024 {
		ruleCache.Lock()
		defer ruleCache.Unlock()
		ruleCache.val = loadedRules{version: "builtin-rc29", rules: builtinRules}
		ruleCache.mtime = mtime
		ruleCache.size = size
		return ruleCache.val
	}

	var f externalRuleFile
	if err := json.Unmarshal(b, &f); err != nil {
		ruleCache.Lock()
		defer ruleCache.Unlock()
		ruleCache.val = loadedRules{version: "builtin-rc29+invalid-external", rules: builtinRules}
		ruleCache.mtime = mtime
		ruleCache.size = size
		return ruleCache.val
	}

	compiled := compileExternalRules(f.Rules)

	version := strings.TrimSpace(f.RulesVersion)
	if version == "" {
		version = "external"
	}
	merged := make([]l3Rule, 0, len(compiled)+len(builtinRules))
	// External rules first so they win on equal-length suffix matches.
	merged = append(merged, compiled...)
	merged = append(merged, builtinRules...)
	lr := loadedRules{version: "external:" + version, rules: merged}

	ruleCache.Lock()
	ruleCache.mtime = mtime
	ruleCache.size = size
	ruleCache.val = lr
	ruleCache.Unlock()
	return lr
}

// compileExternalRules turns the loose external schema into compiled l3Rule.
// Invalid rules are silently dropped so a typo doesn't kill the whole load.
func compileExternalRules(in []externalRule) []l3Rule {
	out := make([]l3Rule, 0, len(in))
	for _, r := range in {
		id := normalizeRuleID(r.ID)
		name := strings.TrimSpace(r.Name)
		if name == "" {
			name = strings.TrimSpace(r.App)
		}
		cat := normalizeCategory(r.Category)
		if id == "" || cat == "" {
			continue
		}
		if name == "" {
			name = id
		}

		// Suffixes: from .Suffixes, .Domains, and legacy .Matchers entries.
		suffixes := normalizeSuffixList(r.Suffixes)
		suffixes = append(suffixes, normalizeSuffixList(r.Domains)...)
		for _, m := range r.Matchers {
			t := strings.ToLower(strings.TrimSpace(m.Type))
			if t == "domain_suffix" || t == "sni_suffix" || t == "suffix" || t == "domain" || t == "exact_domain" {
				suffixes = append(suffixes, normalizeSuffixList([]string{m.Value})...)
			}
		}
		suffixes = uniqueStrings(suffixes)

		ipms := compileIPMatchers(r.IPMatchers, false)
		ipv6ms := compileIPMatchers(r.IPv6Matchers, true)
		subs := compileSubCategories(r.SubCategories)

		if len(suffixes) == 0 && len(ipms) == 0 && len(ipv6ms) == 0 {
			continue
		}

		verified := r.GroundTruth != nil && r.GroundTruth.Verified
		rule := l3Rule{
			ID:            id,
			Name:          name,
			Category:      cat,
			Priority:      priorityFromString(r.Priority),
			Suffixes:      suffixes,
			IPMatchers:    ipms,
			IPv6Matchers:  ipv6ms,
			SubCategories: subs,
			Verified:      verified,
		}
		out = append(out, rule)
		if len(out) >= 1024 {
			break
		}
	}
	return out
}

func compileIPMatchers(in []externalIPMatcher, wantV6 bool) []ipMatcher {
	out := make([]ipMatcher, 0, len(in))
	for _, m := range in {
		cidr := strings.TrimSpace(m.CIDR)
		if cidr == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil || ipnet == nil {
			continue
		}
		// Verify family matches what we expect.
		is4 := ipnet.IP.To4() != nil
		if wantV6 && is4 {
			continue
		}
		if !wantV6 && !is4 {
			continue
		}
		ports := make([]uint16, 0, len(m.Ports))
		for _, p := range m.Ports {
			if p > 0 && p <= 0xffff {
				ports = append(ports, uint16(p))
			}
		}
		out = append(out, ipMatcher{
			Net:          ipnet,
			Proto:        protoFromString(m.Proto),
			Ports:        ports,
			PortsPattern: strings.TrimSpace(m.PortsPattern),
			Purpose:      strings.TrimSpace(m.Purpose),
		})
		if len(out) >= 32 {
			break
		}
	}
	return out
}

// compileSubCategories parses the schema:
//
//	"sub_categories": {
//	  "voice_call": {
//	    "name":     "微信电话",
//	    "detect":   "UDP 183.232.84.0/24:8000 rate > 200 pps",
//	    "category": "social_voip"
//	  }
//	}
//
// The "detect" string is human-readable, so we parse it best-effort.
// Unparseable detectors are kept (with name + category) but won't fire.
func compileSubCategories(in map[string]externalSub) []subCategory {
	if len(in) == 0 {
		return nil
	}
	out := make([]subCategory, 0, len(in))
	for key, v := range in {
		key = strings.TrimSpace(strings.ToLower(key))
		if key == "" {
			continue
		}
		sc := subCategory{
			Key:      key,
			Name:     strings.TrimSpace(v.Name),
			Category: normalizeCategory(v.Category),
		}
		if sc.Name == "" {
			sc.Name = key
		}
		parseDetectExpr(v.Detect, &sc)
		out = append(out, sc)
		if len(out) >= 8 {
			break
		}
	}
	return out
}

// parseDetectExpr extracts (proto, cidr, port, ppsMin) from a string like:
//
//	"UDP 183.232.84.0/24:8000 rate > 200 pps"
//
// Robust to extra whitespace and case. Anything we can't parse just stays
// empty on the sub-category and that detector simply never fires.
func parseDetectExpr(s string, sc *subCategory) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	tokens := strings.Fields(s)
	if len(tokens) == 0 {
		return
	}
	// Token 0: proto (optional).
	idx := 0
	switch strings.ToLower(tokens[0]) {
	case "tcp":
		sc.DetectProto = protoTCP
		idx++
	case "udp":
		sc.DetectProto = protoUDP
		idx++
	case "tcp+udp", "any":
		sc.DetectProto = protoAny
		idx++
	}
	if idx >= len(tokens) {
		return
	}
	// Token N: CIDR:port (may also be just CIDR or just port).
	cidrPort := tokens[idx]
	idx++
	colon := strings.LastIndex(cidrPort, ":")
	var cidrStr, portStr string
	if colon > 0 && !strings.Contains(cidrPort[colon+1:], "/") {
		cidrStr = cidrPort[:colon]
		portStr = cidrPort[colon+1:]
	} else {
		cidrStr = cidrPort
	}
	if cidrStr != "" {
		if _, ipnet, err := net.ParseCIDR(cidrStr); err == nil {
			sc.DetectIP = ipnet
		}
	}
	if portStr != "" {
		var p int
		for _, c := range portStr {
			if c < '0' || c > '9' {
				p = 0
				break
			}
			p = p*10 + int(c-'0')
			if p > 0xffff {
				p = 0
				break
			}
		}
		if p > 0 {
			sc.DetectPort = uint16(p)
		}
	}
	// Remaining tokens: look for "rate > N pps" or "> N pps" or "N pps".
	for i := idx; i < len(tokens); i++ {
		t := strings.ToLower(tokens[i])
		if t == "pps" && i > 0 {
			// previous token should be a number
			var f float64
			n := 0
			for _, c := range tokens[i-1] {
				if c == '.' && n != 0 {
					continue
				}
				if c < '0' || c > '9' {
					n = -1
					break
				}
				n++
			}
			if n > 0 {
				// best-effort: use strconv-equivalent inline
				f = parseFloatSafe(tokens[i-1])
				if f > 0 {
					sc.DetectPPSMin = f
				}
			}
		}
	}
}

// parseFloatSafe is a tiny strconv.ParseFloat replacement that avoids the
// dependency cycle / import bloat (we already pulled strconv in via stdlib).
func parseFloatSafe(s string) float64 {
	var whole, frac float64
	var seenDot bool
	var div float64 = 1
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			if seenDot {
				frac = frac*10 + float64(c-'0')
				div *= 10
			} else {
				whole = whole*10 + float64(c-'0')
			}
		case c == '.':
			if seenDot {
				return 0
			}
			seenDot = true
		default:
			return 0
		}
	}
	return whole + frac/div
}

// ─── normalization helpers ─────────────────────────────────────────────

func normalizeRuleID(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || len(s) > 64 {
		return ""
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return ""
	}
	return s
}

func normalizeCategory(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, "-", "_")
	if s == "" || len(s) > 40 {
		return ""
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return ""
	}
	return s
}

func normalizeSuffixList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = normalizeName(strings.TrimPrefix(strings.TrimSpace(s), "."))
		if s == "" || strings.Contains(s, "/") || strings.Contains(s, "*") {
			continue
		}
		out = append(out, s)
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// builtinRules is a tiny fallback set used only when no external rules file
// is present. The real curated rule library ships as data/dpi_rules.json.
var builtinRules = []l3Rule{
	{ID: "youtube", Name: "YouTube", Category: "video", Suffixes: []string{"youtube.com", "googlevideo.com", "ytimg.com"}},
	{ID: "bilibili", Name: "哔哩哔哩", Category: "video", Suffixes: []string{"bilibili.com", "bilivideo.com", "biliapi.net", "biliapi.com"}},
	{ID: "mihoyo", Name: "米哈游 / HoYoverse", Category: "game", Suffixes: []string{"mihoyo.com", "mhystatic.com", "hoyoverse.com", "hoyolab.com", "genshinimpact.com", "honkaiimpact3.com", "bhsr.com"}},
	{ID: "netease_game", Name: "网易游戏", Category: "game", Suffixes: []string{"netease.com", "163.com", "126.net", "easebar.com", "gameyw.netease.com"}},
	{ID: "tencent_game", Name: "腾讯游戏", Category: "game", Suffixes: []string{"tencentgames.com", "iegcom.com", "myapp.com"}},
	{ID: "huawei", Name: "华为系统服务", Category: "system", Suffixes: []string{"huawei.com", "hicloud.com", "dbankcloud.cn", "dbankcdn.com", "dbankcdn.cn"}},
	{ID: "douyin", Name: "抖音", Category: "video", Priority: PrioritySpecific, Suffixes: []string{"douyin.com", "douyinpic.com", "amemv.com"}},
	{ID: "bytedance_group", Name: "字节系服务", Category: "social", Priority: PriorityFallback, Suffixes: []string{"bytedance.com", "byteimg.com"}},
	{ID: "wechat", Name: "微信/腾讯", Category: "social", Suffixes: []string{"weixin.qq.com", "wechat.com", "qpic.cn", "gtimg.cn", "qq.com"}},
	{ID: "apple", Name: "Apple 服务", Category: "system", Suffixes: []string{"apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com"}},
	{ID: "google", Name: "Google 服务", Category: "system", Suffixes: []string{"google.com", "gstatic.com", "googleapis.com", "googleusercontent.com"}},
}
