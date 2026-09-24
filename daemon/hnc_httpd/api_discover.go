// api_discover.go — v5.15 未知应用自动发现
//
//   GET  /api/discover            规则库认不出的"应用"(dpid 聚类出的域名组)+ 身份线索
//   动作 discover_confirm         确认并写入用户规则库(etc/dpi_rules.d/99-user-custom.json)
//   动作 discover_ignore          忽略一组(不再出现在列表里)
//   动作 discover_probe           立即对一组取服务器证书
//   动作 apk_scan                 请求 dpid 立即重扫本机安装包
//
// 线索来源(都在本机完成, 不把域名发给第三方):
//   1. run/dpi_discover.json  —— dpid: 同设备 5 秒内共现的陌生域名聚成组 + JA4 学到的公司家族
//   2. run/apk_domains.json   —— dpid: 本机已装 App 安装包里写死的域名 → 包名 / App 名
//   3. 证书 —— 本文件: 主动连一次组里的主机 443 端口, 读服务器证书的组织名(O=)与
//      SAN 域名列表(TLS 1.3 下被动抓包看不到证书, 只能主动取)。结果缓存在
//      run/cert_cache.json; 后台每 20 秒最多探测一组, 失败 6 小时后才重试。

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── 证书探测 ─────────────────────────────────────────────────────────

type certInfo struct {
	Host   string   `json:"host"`
	Org    string   `json:"org,omitempty"`
	CN     string   `json:"cn,omitempty"`
	SANs   []string `json:"sans,omitempty"`
	Issuer string   `json:"issuer,omitempty"`
	Ts     int64    `json:"ts"`
	Err    string   `json:"err,omitempty"`
}

var certState struct {
	mu     sync.Mutex
	loaded bool
	m      map[string]certInfo // 组 id → 证书
	dirty  bool
}

const (
	certRetryAfterErr = 6 * 3600
	certMaxSANs       = 40
)

// certProbeFunc 可在测试里替换(不真的连网)
var certProbeFunc = probeCert

func certCachePath(hncDir string) string { return filepath.Join(hncDir, "run", "cert_cache.json") }

func certLoadLocked(hncDir string) {
	if certState.loaded {
		return
	}
	certState.loaded = true
	certState.m = map[string]certInfo{}
	if b, err := os.ReadFile(certCachePath(hncDir)); err == nil {
		_ = json.Unmarshal(b, &certState.m)
		if certState.m == nil {
			certState.m = map[string]certInfo{}
		}
	}
}

func certGet(hncDir, id string) (certInfo, bool) {
	certState.mu.Lock()
	defer certState.mu.Unlock()
	certLoadLocked(hncDir)
	c, ok := certState.m[id]
	return c, ok
}

func certPut(hncDir, id string, c certInfo) {
	certState.mu.Lock()
	certLoadLocked(hncDir)
	certState.m[id] = c
	// 上限 500 组, 超出按时间淘汰最旧的
	if len(certState.m) > 500 {
		var oldK string
		var oldT int64 = 1 << 62
		for k, v := range certState.m {
			if v.Ts < oldT {
				oldK, oldT = k, v.Ts
			}
		}
		delete(certState.m, oldK)
	}
	b, _ := json.Marshal(certState.m)
	certState.mu.Unlock()
	_ = discoverWriteAtomic(certCachePath(hncDir), b)
}

func discoverWriteAtomic(path string, b []byte) error {
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// probeCert 连 host:443 读证书。只读取、不信任(InsecureSkipVerify): 我们要的是
// 证书上写的组织名, 不是建立可信连接; 不发送任何应用数据。
// 地址优先用 dpid 反查表里该主机最近解析到的 IP —— CGO_ENABLED=0 的 Go 在
// Android 上没有 /etc/resolv.conf, 系统解析器不可用; 查不到再走公共 DNS。
func probeCert(host string, ips []string) certInfo {
	ci := certInfo{Host: host, Ts: time.Now().Unix()}
	var addrs []string
	for _, ip := range ips {
		addrs = append(addrs, net.JoinHostPort(ip, "443"))
	}
	if len(addrs) == 0 {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", "223.5.5.5:53")
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		res, err := r.LookupHost(ctx, host)
		cancel()
		if err != nil || len(res) == 0 {
			ci.Err = "解析失败"
			return ci
		}
		for _, ip := range res {
			addrs = append(addrs, net.JoinHostPort(ip, "443"))
		}
	}
	var lastErr error
	for i, a := range addrs {
		if i >= 3 {
			break
		}
		d := &net.Dialer{Timeout: 4 * time.Second}
		conn, err := tls.DialWithDialer(d, "tcp", a, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // #nosec G402 -- 只读证书字段, 不传数据
		if err != nil {
			lastErr = err
			continue
		}
		st := conn.ConnectionState()
		_ = conn.Close()
		if len(st.PeerCertificates) == 0 {
			lastErr = errors.New("无证书")
			continue
		}
		c := st.PeerCertificates[0]
		if len(c.Subject.Organization) > 0 {
			ci.Org = c.Subject.Organization[0]
		}
		ci.CN = c.Subject.CommonName
		if len(c.Issuer.Organization) > 0 {
			ci.Issuer = c.Issuer.Organization[0]
		} else {
			ci.Issuer = c.Issuer.CommonName
		}
		for _, s := range c.DNSNames {
			if len(ci.SANs) >= certMaxSANs {
				break
			}
			ci.SANs = append(ci.SANs, strings.ToLower(s))
		}
		return ci
	}
	if lastErr != nil {
		ci.Err = shortNetErr(lastErr)
	}
	return ci
}

func shortNetErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout"):
		return "连接超时"
	case strings.Contains(s, "refused"):
		return "连接被拒绝"
	case strings.Contains(s, "handshake"):
		return "TLS 握手失败"
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// ─── 线索: 公司名 ─────────────────────────────────────────────────────

// 证书组织名(英文) → 中文公司名。子串匹配, 不区分大小写, 先长后短。
var certOrgCN = [][2]string{
	{"bytedance", "字节跳动"}, {"beijing douyin", "字节跳动"}, {"douyin", "字节跳动"}, {"toutiao", "字节跳动"},
	{"kuaishou", "快手"}, {"beijing kuaishou", "快手"},
	{"tencent", "腾讯"}, {"alibaba", "阿里巴巴"}, {"taobao", "阿里巴巴"}, {"alipay", "阿里巴巴(支付宝)"},
	{"baidu", "百度"}, {"netease", "网易"}, {"xiaomi", "小米"}, {"huawei", "华为"},
	{"meituan", "美团"}, {"sankuai", "美团"}, {"pinduoduo", "拼多多"}, {"hangzhou weimi", "拼多多"}, {"xunmeng", "拼多多"},
	{"jingdong", "京东"}, {"jd.com", "京东"}, {"xingin", "小红书"}, {"xiaohongshu", "小红书"},
	{"bilibili", "哔哩哔哩"}, {"hode", "哔哩哔哩"}, {"kuanyu", "哔哩哔哩"}, {"zhihu", "知乎"}, {"weibo", "微博"}, {"sina", "新浪/微博"},
	{"ctrip", "携程"}, {"ximalaya", "喜马拉雅"}, {"didi", "滴滴"}, {"xiaoju", "滴滴"}, {"mihoyo", "米哈游"}, {"miHoYo", "米哈游"},
	{"oppo", "OPPO"}, {"heytap", "OPPO"}, {"vivo", "vivo"}, {"apple", "Apple"}, {"google", "Google"}, {"microsoft", "Microsoft"},
	{"iqiyi", "爱奇艺"}, {"youku", "优酷"}, {"kingsoft", "金山"}, {"zhipin", "BOSS 直聘"}, {"kanzhun", "BOSS 直聘"},
	{"dewu", "得物"}, {"shizhuang", "得物"}, {"vipshop", "唯品会"}, {"58", "58 同城"},
}

func companyFromOrg(org string) string {
	o := strings.ToLower(org)
	best, bestLen := "", 0
	for _, kv := range certOrgCN {
		k := strings.ToLower(kv[0])
		if len(k) > bestLen && strings.Contains(o, k) {
			if k == "58" && !strings.Contains(o, "58.com") && !strings.HasPrefix(o, "58") {
				continue
			}
			best, bestLen = kv[1], len(k)
		}
	}
	return best
}

// 通用 CA / CDN 的证书组织名不代表网站主体
var genericCertOrg = regexp.MustCompile(`(?i)cloudflare|akamai|fastly|amazon|let's encrypt|digicert|globalsign|sectigo|wangsu|chinanetcenter|aliyun cdn|verisign`)

// ─── 汇总 ─────────────────────────────────────────────────────────────

type apkIndex struct {
	labels map[string]string   // pkg → label
	suffix map[string][]string // 可注册域 → pkgs
	sdk    map[string]bool
	at     int64
	apps   int
}

func (s *server) loadAPKIndex() apkIndex {
	ix := apkIndex{labels: map[string]string{}, suffix: map[string][]string{}, sdk: map[string]bool{}}
	raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "apk_domains.json"))
	if err != nil {
		return ix
	}
	root, _ := raw.(map[string]interface{})
	if v, ok := root["generated_at"].(float64); ok {
		ix.at = int64(v)
	}
	if apps, ok := root["apps"].(map[string]interface{}); ok {
		ix.apps = len(apps)
		for pkg, v := range apps {
			m, _ := v.(map[string]interface{})
			l := asString(m["label"])
			if l == "" {
				l = pkg
			}
			ix.labels[pkg] = l
		}
	}
	if si, ok := root["suffix_index"].(map[string]interface{}); ok {
		for suf, v := range si {
			if list, ok := v.([]interface{}); ok {
				for _, p := range list {
					ix.suffix[strings.ToLower(suf)] = append(ix.suffix[strings.ToLower(suf)], asString(p))
				}
			}
		}
	}
	if sd, ok := root["sdk_suffixes"].([]interface{}); ok {
		for _, x := range sd {
			ix.sdk[strings.ToLower(asString(x))] = true
		}
	}
	return ix
}

// registrable 可注册域(eTLD+1), 与 dpid / WebUI guessSuffix 同口径
func registrable(host string) string {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".")
	host = strings.TrimPrefix(host, "*.")
	p := strings.Split(host, ".")
	if len(p) <= 2 {
		return host
	}
	two := p[len(p)-2] + "." + p[len(p)-1]
	switch two {
	case "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "com.tw", "co.jp", "co.uk", "com.au", "ne.jp", "or.jp", "com.br":
		return p[len(p)-3] + "." + two
	}
	return two
}

type discoverList struct {
	IDs []string `json:"ids"`
}

func readIDList(path string) map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var l discoverList
	if json.Unmarshal(b, &l) == nil {
		for _, id := range l.IDs {
			out[id] = true
		}
	}
	return out
}

func addIDList(path, id string) error {
	m := readIDList(path)
	m[id] = true
	l := discoverList{}
	for k := range m {
		l.IDs = append(l.IDs, k)
	}
	sort.Strings(l.IDs)
	if len(l.IDs) > 1000 {
		l.IDs = l.IDs[len(l.IDs)-1000:]
	}
	b, _ := json.Marshal(l)
	return discoverWriteAtomic(path, b)
}

// v5.16: 已忽略的组(仍在 dpid 聚类结果里的)与用户规则库, 供「管理」页撤销/删除
func (s *server) ignoredGroups() []map[string]interface{} {
	raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "dpi_discover.json"))
	ign := readIDList(filepath.Join(s.hncDir, "run", "discover_ignored.json"))
	out := []map[string]interface{}{}
	seen := map[string]bool{}
	if err == nil {
		root, _ := raw.(map[string]interface{})
		gs, _ := root["groups"].([]interface{})
		for _, g := range gs {
			m, _ := g.(map[string]interface{})
			id := asString(m["id"])
			if ign[id] {
				seen[id] = true
				out = append(out, map[string]interface{}{"id": id, "suffixes": uniqStrings(strList(m["suffixes"]), 4), "hits": m["hits"]})
			}
		}
	}
	for id := range ign { // 聚类里已经没有的也列出来, 允许撤销
		if !seen[id] {
			out = append(out, map[string]interface{}{"id": id, "suffixes": []string{}, "gone": true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return asString(out[i]["id"]) < asString(out[j]["id"]) })
	return out
}

func (s *server) userRules() []map[string]interface{} {
	out := []map[string]interface{}{}
	b, err := os.ReadFile(userRulesPath(s.hncDir))
	if err != nil {
		return out
	}
	var doc map[string]interface{}
	if json.Unmarshal(b, &doc) != nil {
		return out
	}
	rules, _ := doc["rules"].([]interface{})
	for _, r := range rules {
		m, _ := r.(map[string]interface{})
		if id := asString(m["id"]); id != "" {
			out = append(out, map[string]interface{}{"id": id, "app": asString(m["app"]), "category": asString(m["category"]), "suffixes": strList(m["suffixes"])})
		}
	}
	return out
}

func actionDiscoverUnignore(s *server, p map[string]string) actionResp {
	id := strings.TrimSpace(p["id"])
	path := filepath.Join(s.hncDir, "run", "discover_ignored.json")
	m := readIDList(path)
	if !m[id] {
		return actionResp{OK: false, Error: "not found", Detail: "not ignored"}
	}
	delete(m, id)
	l := discoverList{IDs: []string{}}
	for k := range m {
		l.IDs = append(l.IDs, k)
	}
	sort.Strings(l.IDs)
	b, _ := json.Marshal(l)
	if err := discoverWriteAtomic(path, b); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true}
}

// actionUserRuleDel 从 99-user-custom.json 删一条规则(dpid 按 mtime 自动重载)
func actionUserRuleDel(s *server, p map[string]string) actionResp {
	id := strings.TrimSpace(p["id"])
	if id == "" {
		return actionResp{OK: false, Error: "bad params", Detail: "id required"}
	}
	path := userRulesPath(s.hncDir)
	b, err := os.ReadFile(path)
	if err != nil {
		return actionResp{OK: false, Error: "not found", Detail: "no user rules"}
	}
	var doc map[string]interface{}
	if json.Unmarshal(b, &doc) != nil {
		return actionResp{OK: false, Error: "user rules corrupt"}
	}
	rules, _ := doc["rules"].([]interface{})
	kept := make([]interface{}, 0, len(rules))
	found := false
	for _, r := range rules {
		m, _ := r.(map[string]interface{})
		if asString(m["id"]) == id {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if !found {
		return actionResp{OK: false, Error: "not found", Detail: "rule not found"}
	}
	doc["rules"] = kept
	doc["rules_version"] = "user-" + time.Now().Format("20060102")
	nb, _ := json.MarshalIndent(doc, "", "  ")
	if err := discoverWriteAtomic(path, nb); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: "已删除规则 " + id + " · dpid 自动重载"}
}

func (s *server) discoverGroups() []map[string]interface{} {
	raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "dpi_discover.json"))
	if err != nil {
		return nil
	}
	root, _ := raw.(map[string]interface{})
	gs, _ := root["groups"].([]interface{})
	ign := readIDList(filepath.Join(s.hncDir, "run", "discover_ignored.json"))
	done := readIDList(filepath.Join(s.hncDir, "run", "discover_confirmed.json"))
	var out []map[string]interface{}
	for _, g := range gs {
		m, _ := g.(map[string]interface{})
		id := asString(m["id"])
		if id == "" || ign[id] || done[id] {
			continue
		}
		out = append(out, m)
	}
	return out
}

func strList(v interface{}) []string {
	var out []string
	if l, ok := v.([]interface{}); ok {
		for _, x := range l {
			if s := asString(x); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// firstHost 组里命中最多的完整主机名(证书探测目标)
func firstHost(g map[string]interface{}) string {
	if ds, ok := g["domains"].([]interface{}); ok {
		for _, d := range ds {
			m, _ := d.(map[string]interface{})
			if n := asString(m["name"]); n != "" {
				return n
			}
		}
	}
	if s := strList(g["suffixes"]); len(s) > 0 {
		return s[0]
	}
	return ""
}

// enrich 给一组加上证书 / 本机 App / 家族线索, 并得出最可能的名字
func (s *server) enrichGroup(g map[string]interface{}, ix apkIndex) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range g {
		out[k] = v
	}
	id := asString(g["id"])
	sufs := strList(g["suffixes"])
	sufSet := map[string]bool{}
	for _, x := range sufs {
		sufSet[strings.ToLower(x)] = true
	}
	company := ""
	if ci, ok := certGet(s.hncDir, id); ok {
		out["cert"] = ci
		if ci.Org != "" && !genericCertOrg.MatchString(ci.Org) {
			company = companyFromOrg(ci.Org)
		}
		// SAN 里的可注册域也拿来查本机 App(同一证书覆盖的兄弟域名)
		var sib []string
		for _, san := range ci.SANs {
			r := registrable(san)
			if r != "" && !sufSet[r] {
				sufSet[r] = false // false = 来自证书, 不是组内观测
				sib = append(sib, r)
			}
		}
		if len(sib) > 0 {
			sort.Strings(sib)
			out["cert_siblings"] = uniqStrings(sib, 12)
		}
	}
	// 本机 App 命中: 组内域权重 2, 证书兄弟域权重 1; SDK 域不计
	score := map[string]int{}
	hitSuf := map[string][]string{}
	for suf, observed := range sufSet {
		if ix.sdk[suf] {
			continue
		}
		for _, pkg := range ix.suffix[suf] {
			w := 1
			if observed {
				w = 2
			}
			score[pkg] += w
			hitSuf[pkg] = append(hitSuf[pkg], suf)
		}
	}
	var apks []map[string]interface{}
	for pkg, sc := range score {
		sort.Strings(hitSuf[pkg])
		apks = append(apks, map[string]interface{}{"pkg": pkg, "label": ix.labels[pkg], "score": sc, "suffixes": hitSuf[pkg]})
	}
	sort.Slice(apks, func(i, j int) bool {
		if apks[i]["score"].(int) != apks[j]["score"].(int) {
			return apks[i]["score"].(int) > apks[j]["score"].(int)
		}
		return asString(apks[i]["pkg"]) < asString(apks[j]["pkg"])
	})
	if len(apks) > 4 {
		apks = apks[:4]
	}
	if len(apks) > 0 {
		out["apk"] = apks
	}
	if company != "" {
		out["company"] = company
	}

	// 结论: 本机 App > 证书公司 > JA4 家族 > 主域名
	guess := map[string]interface{}{}
	fam := asString(g["family_name"])
	switch {
	case len(apks) > 0 && (apks[0]["score"].(int) >= 2) && (len(apks) == 1 || apks[0]["score"].(int) > apks[1]["score"].(int)):
		lbl := asString(apks[0]["label"])
		if lbl == "" {
			lbl = asString(apks[0]["pkg"])
		}
		conf := "medium"
		if apks[0]["score"].(int) >= 4 || company != "" {
			conf = "high"
		}
		guess = map[string]interface{}{"name": lbl, "src": "apk", "conf": conf, "pkg": apks[0]["pkg"]}
	case company != "":
		guess = map[string]interface{}{"name": company + " 旗下应用", "src": "cert", "conf": "medium", "company": company}
	case fam != "":
		guess = map[string]interface{}{"name": "疑似" + fam + "应用", "src": "ja4", "conf": "low"}
	default:
		name := ""
		if len(sufs) > 0 {
			name = sufs[0]
		}
		guess = map[string]interface{}{"name": name, "src": "domain", "conf": "low"}
	}
	out["guess"] = guess
	return out
}

func uniqStrings(in []string, max int) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= max {
			break
		}
	}
	return out
}

func (s *server) apiDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	ix := s.loadAPKIndex()
	gs := s.discoverGroups()
	list := make([]map[string]interface{}, 0, len(gs))
	for _, g := range gs {
		list = append(list, s.enrichGroup(g, ix))
	}
	_, statErr := os.Stat(filepath.Join(s.hncDir, "run", "dpi_discover.json"))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":          true,
		"available":   statErr == nil,
		"groups":      list,
		"apk_scan":    map[string]interface{}{"generated_at": ix.at, "app_count": ix.apps, "requested": fileExists(filepath.Join(s.hncDir, "run", "apk_scan.request"))},
		"cert_probe":  certProbeEnabled(s.hncDir),
		"ignored_n":   len(readIDList(filepath.Join(s.hncDir, "run", "discover_ignored.json"))),
		"confirmed_n": len(readIDList(filepath.Join(s.hncDir, "run", "discover_confirmed.json"))),
		"ignored":     s.ignoredGroups(),
		"user_rules":  s.userRules(),
	})
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// certProbeEnabled: rules.json 顶层 discover_cert_probe, 缺省开启
func certProbeEnabled(hncDir string) bool {
	b, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json"))
	if err != nil {
		return true
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return true
	}
	if v, ok := m["discover_cert_probe"].(bool); ok {
		return v
	}
	return true
}

// ipsForHost 从 dpid 反查表里找该主机名最近解析到的 IP(最多 3 个)
func (s *server) ipsForHost(host string) []string {
	var out []string
	for ip, n := range s.loadIPNames() {
		if strings.EqualFold(n.Name, host) {
			out = append(out, ip)
			if len(out) >= 3 {
				break
			}
		}
	}
	return out
}

func (s *server) probeGroup(g map[string]interface{}) certInfo {
	host := firstHost(g)
	ci := certProbeFunc(host, s.ipsForHost(host))
	certPut(s.hncDir, asString(g["id"]), ci)
	return ci
}

// CertProbeLoop 后台: 每 20 秒最多给一组取证书(还没取过的优先, 失败 6 小时后重试)
func (s *server) CertProbeLoop(stop <-chan struct{}) {
	tk := time.NewTicker(20 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
		}
		if !certProbeEnabled(s.hncDir) {
			continue
		}
		now := time.Now().Unix()
		for _, g := range s.discoverGroups() {
			id := asString(g["id"])
			if ci, ok := certGet(s.hncDir, id); ok && (ci.Err == "" || now-ci.Ts < certRetryAfterErr) {
				continue
			}
			ci := s.probeGroup(g)
			if ci.Err != "" {
				log.Printf("discover: cert probe %s (%s): %s", id, ci.Host, ci.Err)
			}
			break
		}
	}
}

// ─── 动作 ─────────────────────────────────────────────────────────────

var suffixRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

var validCategories = map[string]bool{
	"video": true, "social": true, "game": true, "shopping": true, "music": true, "office": true, "ai": true,
	"travel": true, "navigation": true, "reading": true, "news": true, "life_service": true, "download": true,
	"browser": true, "photo": true, "tool": true, "finance": true, "education": true, "unknown": true,
}

func (s *server) findGroup(id string) map[string]interface{} {
	for _, g := range s.discoverGroups() {
		if asString(g["id"]) == id {
			return g
		}
	}
	return nil
}

func userRulesPath(hncDir string) string {
	return filepath.Join(hncDir, "etc", "dpi_rules.d", "99-user-custom.json")
}

func actionDiscoverConfirm(s *server, p map[string]string) actionResp {
	id := strings.TrimSpace(p["id"])
	name := strings.TrimSpace(p["name"])
	cat := strings.TrimSpace(p["category"])
	if id == "" || name == "" || len([]rune(name)) > 40 {
		return actionResp{OK: false, Error: "bad params", Detail: "id and name(≤40 chars) required"}
	}
	if cat == "" {
		cat = "unknown"
	}
	if !validCategories[cat] {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid category"}
	}
	var sufs []string
	for _, x := range strings.Split(p["suffixes"], ",") {
		x = strings.ToLower(strings.TrimSpace(x))
		if x == "" {
			continue
		}
		if !suffixRe.MatchString(x) || len(x) > 253 {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid suffix: " + x}
		}
		sufs = append(sufs, x)
	}
	if len(sufs) == 0 {
		if g := s.findGroup(id); g != nil {
			sufs = strList(g["suffixes"])
		}
	}
	if len(sufs) == 0 || len(sufs) > 30 {
		return actionResp{OK: false, Error: "bad params", Detail: "1-30 suffixes required"}
	}
	path := userRulesPath(s.hncDir)
	doc := map[string]interface{}{}
	if b, err := os.ReadFile(path); err == nil {
		if json.Unmarshal(b, &doc) != nil {
			return actionResp{OK: false, Error: "user rules corrupt", Detail: "99-user-custom.json 不是合法 JSON, 先在规则库里修复或恢复内置"}
		}
	}
	if _, ok := doc["schema_version"]; !ok {
		doc["schema_version"] = "2.0"
	}
	doc["subset"] = "99-user-custom"
	doc["rules_version"] = "user-" + time.Now().Format("20060102")
	rules, _ := doc["rules"].([]interface{})
	ruleID := "user_" + strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(sufs[0]), "_"), "_")
	if len(ruleID) > 48 {
		ruleID = ruleID[:48]
	}
	// 同 id 已存在 → 合并后缀、更新名字
	merged := false
	for _, rr := range rules {
		m, _ := rr.(map[string]interface{})
		if asString(m["id"]) != ruleID {
			continue
		}
		have := strList(m["suffixes"])
		m["suffixes"] = uniqStrings(append(have, sufs...), 60)
		m["app"] = name
		m["category"] = cat
		merged = true
	}
	if !merged {
		rules = append(rules, map[string]interface{}{
			"id": ruleID, "app": name, "category": cat, "confidence": "user", "suffixes": sufs,
			"note": "v5.15 未知应用发现 · 用户确认 " + time.Now().Format("2006-01-02"),
		})
	}
	doc["rules"] = rules
	b, _ := json.MarshalIndent(doc, "", "  ")
	if len(b) > 512*1024 {
		return actionResp{OK: false, Error: "too large", Detail: "用户规则超过 512 KB"}
	}
	if err := discoverWriteAtomic(path, b); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	_ = addIDList(filepath.Join(s.hncDir, "run", "discover_confirmed.json"), id)
	return actionResp{OK: true, Detail: fmt.Sprintf("已加入规则库: %s (%s) · %d 个域名 · dpid 自动重载", name, ruleID, len(sufs))}
}

func actionDiscoverIgnore(s *server, p map[string]string) actionResp {
	id := strings.TrimSpace(p["id"])
	if id == "" || len(id) > 64 {
		return actionResp{OK: false, Error: "bad params", Detail: "id required"}
	}
	if err := addIDList(filepath.Join(s.hncDir, "run", "discover_ignored.json"), id); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true}
}

func actionDiscoverProbe(s *server, p map[string]string) actionResp {
	g := s.findGroup(strings.TrimSpace(p["id"]))
	if g == nil {
		return actionResp{OK: false, Error: "not found", Detail: "group not found"}
	}
	ci := s.probeGroup(g)
	b, _ := json.Marshal(ci)
	if ci.Err != "" {
		return actionResp{OK: false, Error: "probe failed", Detail: ci.Err}
	}
	return actionResp{OK: true, Detail: string(b)}
}

func actionAPKScan(hncDir string) actionResp {
	p := filepath.Join(hncDir, "run", "apk_scan.request")
	if err := discoverWriteAtomic(p, []byte(fmt.Sprintf("%d\n", time.Now().Unix()))); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: "已请求扫描, 约 1 分钟内开始"}
}
