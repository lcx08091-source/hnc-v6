// fp_user_rules.go — v6.x DPI v2: 用户纠正(「这条连接其实是 X」)→ 高优先级归属规则
//
// 存储 data/dpi_user_rules.json:
//
//	{"schema":1,"rules":[{"id","kind":"domain|ip|ja4","value","port","app_id","app_name",
//	  "category","mac","created","expires"}]}
//
// 三种规则:
//   - domain: 后缀匹配连接目的 IP 的反查域名(dpi_ipname)。永久。
//   - ip:     目的 IP 精确匹配(/32 或 /128), port 可选(0 = 任意端口)。CDN 会轮换 IP,
//     所以 7 天后过期(dpiUserIPTTL)。
//   - ja4:    ClientHello 指纹。只用于「没有域名」的连接(不压过有域名的规则库命中);
//     学习表显示该指纹被多个应用/浏览器共用(纯度不够)时拒绝保存, 生效时也再查一次。
//
// 优先级(appForIPSrc / fpStore.attribute):
//
//	用户 ip+port / ip / domain 规则 > 规则库(ip_app_map、域名归类) > 用户 ja4 规则 >
//	学习到的指纹 > 种子指纹 > 共现推断 / VPN 启发式
//
// 生效: 规则集是包级原子指针(appForIP 无 server 上下文); 动作写盘后立即刷新,
// app_usage 每轮也按 mtime 重新加载(手工改文件也能跟上)。
//
// 动作(/api/action):
//
//	dpi_correct      {mac?, dst_ip?, dst_port?, name?, ja4?, app_id, app_name?, category?, kinds?}
//	dpi_correct_list {}            → detail = JSON 数组(同 /api/dpi_fp 的 user_rules)
//	dpi_correct_del  {id} | {all:"true"}
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dpiUserIPTTL     = 7 * 24 * time.Hour
	dpiUserMaxRules  = 512
	dpiUserMaxPerApp = 64
)

type dpiUserRule struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"` // domain | ip | ja4
	Value    string `json:"value"`
	Port     int    `json:"port,omitempty"`
	AppID    string `json:"app_id"`
	AppName  string `json:"app_name,omitempty"`
	Category string `json:"category,omitempty"`
	MAC      string `json:"mac,omitempty"` // 纠正时所在的设备(仅记录, 规则对所有设备生效)
	Created  int64  `json:"created"`
	Expires  int64  `json:"expires,omitempty"`
}

func (r *dpiUserRule) app() ipApp {
	n := r.AppName
	if n == "" {
		n = r.AppID
	}
	return ipApp{ID: r.AppID, Name: n, Category: r.Category}
}

func (r *dpiUserRule) live(now int64) bool { return r.Expires == 0 || r.Expires > now }

type dpiUserRuleFile struct {
	Schema int           `json:"schema"`
	Rules  []dpiUserRule `json:"rules"`
}

type dpiUserRuleSet struct {
	domain map[string]*dpiUserRule
	ip     map[string][]*dpiUserRule
	ja4    map[string]*dpiUserRule
	n      int
}

var dpiUserRulesCur atomic.Pointer[dpiUserRuleSet]

var dpiUserRulesCache struct {
	mu  sync.Mutex
	key string
}

func dpiUserRulesPath(hncDir string) string {
	return filepath.Join(hncDir, "data", "dpi_user_rules.json")
}

func readDPIUserRules(hncDir string) []dpiUserRule {
	b, err := os.ReadFile(dpiUserRulesPath(hncDir))
	if err != nil || len(b) > 1<<20 {
		return nil
	}
	var f dpiUserRuleFile
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	return f.Rules
}

func buildDPIUserRuleSet(rules []dpiUserRule) *dpiUserRuleSet {
	set := &dpiUserRuleSet{domain: map[string]*dpiUserRule{}, ip: map[string][]*dpiUserRule{}, ja4: map[string]*dpiUserRule{}}
	for i := range rules {
		r := &rules[i]
		if r.AppID == "" || r.Value == "" {
			continue
		}
		switch r.Kind {
		case "domain":
			set.domain[r.Value] = r
		case "ip":
			set.ip[r.Value] = append(set.ip[r.Value], r)
		case "ja4":
			set.ja4[r.Value] = r
		default:
			continue
		}
		set.n++
	}
	return set
}

// dpiUserRulesRefresh 按 mtime/size 重载并发布到全局(无变化不重建)。
func dpiUserRulesRefresh(hncDir string) {
	p := dpiUserRulesPath(hncDir)
	key := p + ":-"
	if st, err := os.Stat(p); err == nil {
		key = p + ":" + strconv.FormatInt(st.ModTime().UnixNano(), 10) + ":" + strconv.FormatInt(st.Size(), 10)
	}
	dpiUserRulesCache.mu.Lock()
	defer dpiUserRulesCache.mu.Unlock()
	if key == dpiUserRulesCache.key && dpiUserRulesCur.Load() != nil {
		return
	}
	dpiUserRulesCache.key = key
	set := buildDPIUserRuleSet(readDPIUserRules(hncDir))
	if set.n == 0 {
		dpiUserRulesCur.Store(&dpiUserRuleSet{})
		return
	}
	dpiUserRulesCur.Store(set)
}

// dpiUserRulesReset 测试用: 清掉全局规则集
func dpiUserRulesReset() {
	dpiUserRulesCache.mu.Lock()
	dpiUserRulesCache.key = ""
	dpiUserRulesCache.mu.Unlock()
	dpiUserRulesCur.Store(nil)
}

// dpiUserMatchIP: port > 0 时端口专属规则与任意端口规则都算; port == 0 只看任意端口规则。
func dpiUserMatchIP(ip string, port int, now time.Time) (ipApp, bool) {
	set := dpiUserRulesCur.Load()
	if set == nil || set.n == 0 || len(set.ip) == 0 {
		return ipApp{}, false
	}
	ts := now.Unix()
	var any *dpiUserRule
	for _, r := range set.ip[ip] {
		if !r.live(ts) {
			continue
		}
		if r.Port != 0 && r.Port == port {
			return r.app(), true // 端口专属更具体
		}
		if r.Port == 0 && any == nil {
			any = r
		}
	}
	if any != nil {
		return any.app(), true
	}
	return ipApp{}, false
}

// dpiUserMatchName 后缀匹配(最长者胜)
func dpiUserMatchName(name string) (ipApp, bool) {
	set := dpiUserRulesCur.Load()
	if set == nil || len(set.domain) == 0 || name == "" {
		return ipApp{}, false
	}
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	for {
		if r, ok := set.domain[n]; ok {
			return r.app(), true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return ipApp{}, false
		}
		n = n[i+1:]
	}
}

func dpiUserMatchJA4(ja4 string) (*dpiUserRule, bool) {
	set := dpiUserRulesCur.Load()
	if set == nil || len(set.ja4) == 0 || ja4 == "" {
		return nil, false
	}
	r, ok := set.ja4[ja4]
	return r, ok
}

// ─── 动作 ─────────────────────────────────────────────────────────────

var (
	dpiAppIDRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	dpiJA4RE   = regexp.MustCompile(`^[A-Za-z0-9]{10}_[0-9a-f]{12}_[0-9a-f]{12}$`)
	// v5.27 T2: QUIC 传输参数指纹(src/dpid/output/qtp.go)
	fpQTPRE     = regexp.MustCompile(`^qtp1_[0-9a-f]{12}$`)
	dpiDomainRE = regexp.MustCompile(`^[a-z0-9_-]+(\.[a-z0-9_-]+)+$`)
)

// 与 dpid output/ipname.go echPublicNames 同步: ECH 外层名不代表真实站点
var dpiECHPublicNames = map[string]bool{"cloudflare-ech.com": true, "crypto.cloudflare.com": true, "encryptedsni.com": true}

// dpiNameTooBroad: 形如 com.cn / co.uk 的公共后缀本身(后缀匹配会吞掉整个国家域)
func dpiNameTooBroad(name string) bool {
	parts := strings.Split(name, ".")
	if len(parts) != 2 || len(parts[1]) != 2 {
		return false
	}
	switch parts[0] {
	case "com", "net", "org", "gov", "edu", "co", "ac":
		return true
	}
	return false
}

func newDPIUserRuleID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "c" + hex.EncodeToString(b[:])
}

func writeDPIUserRules(hncDir string, rules []dpiUserRule) error {
	if rules == nil {
		rules = []dpiUserRule{}
	}
	b, _ := json.MarshalIndent(dpiUserRuleFile{Schema: 1, Rules: rules}, "", "  ")
	if err := discoverWriteAtomic(dpiUserRulesPath(hncDir), b); err != nil {
		return err
	}
	dpiUserRulesRefresh(hncDir)
	return nil
}

var dpiUserRulesWriteMu sync.Mutex

func actionDPICorrect(s *server, p map[string]string) actionResp {
	now := time.Now()
	mac := strings.ToLower(strings.TrimSpace(p["mac"]))
	if mac != "" {
		if !validMAC(mac) {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
		}
		if isSimMAC(mac) {
			return actionResp{OK: false, Error: "bad params", Detail: "模拟设备的连接不能用来纠正识别"}
		}
	}
	appID := strings.TrimSpace(p["app_id"])
	if !dpiAppIDRE.MatchString(appID) || strings.HasPrefix(appID, "_") {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid app_id"}
	}
	appName := strings.TrimSpace(p["app_name"])
	cat := strings.ToLower(strings.TrimSpace(p["category"]))
	if len([]rune(appName)) > 40 || len(cat) > 40 {
		return actionResp{OK: false, Error: "bad params", Detail: "app_name/category too long"}
	}
	if ca := loadAppCatalog(s.hncDir).apps[appID]; ca != nil {
		if appName == "" {
			appName = ca.Name
		}
		if cat == "" {
			cat = ca.Category
		}
	} else if appName == "" {
		return actionResp{OK: false, Error: "bad params", Detail: "unknown app_id (规则库里没有, 需同时给 app_name)"}
	}
	if appTier(cat) == tierHidden {
		return actionResp{OK: false, Error: "bad params", Detail: "不能纠正为广告/统计/CDN 类"}
	}
	kinds := map[string]bool{"domain": true, "ip": true, "ja4": true}
	if k := strings.TrimSpace(p["kinds"]); k != "" {
		kinds = map[string]bool{}
		for _, x := range strings.Split(k, ",") {
			kinds[strings.TrimSpace(x)] = true
		}
	}
	dstIP := ""
	if v := strings.TrimSpace(p["dst_ip"]); v != "" {
		ip := net.ParseIP(v)
		if ip == nil {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid dst_ip"}
		}
		dstIP = ip.String()
	}
	port := 0
	if v := strings.TrimSpace(p["dst_port"]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid dst_port"}
		}
		port = n
	}
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p["name"])), ".")
	if name != "" && (!dpiDomainRE.MatchString(name) || len(name) > 253) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid name"}
	}
	ja4 := strings.TrimSpace(p["ja4"])
	if ja4 != "" && !dpiJA4RE.MatchString(ja4) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid ja4"}
	}
	st := fpFor(s.hncDir)
	if ja4 == "" && dstIP != "" && kinds["ja4"] {
		ja4 = st.findJA4(mac, dstIP, port, now)
	}

	var add []dpiUserRule
	var notes []string
	base := dpiUserRule{AppID: appID, AppName: appName, Category: cat, MAC: mac, Created: now.Unix()}
	if name != "" && kinds["domain"] {
		switch {
		case dpiECHPublicNames[name]:
			notes = append(notes, "域名是 ECH 外层名, 未保存域名规则")
		case dpiNameTooBroad(name):
			notes = append(notes, "域名过于宽泛(公共后缀), 未保存域名规则")
		default:
			r := base
			r.Kind, r.Value = "domain", name
			add = append(add, r)
		}
	}
	if dstIP != "" && kinds["ip"] {
		if isPrivateIP(dstIP) {
			notes = append(notes, "局域网地址不保存 IP 规则")
		} else {
			r := base
			r.Kind, r.Value, r.Port = "ip", dstIP, port
			r.Expires = now.Add(dpiUserIPTTL).Unix()
			add = append(add, r)
		}
	}
	if ja4 != "" && kinds["ja4"] {
		if generic, why := st.ja4Generic(ja4, appID, now); generic {
			notes = append(notes, "指纹 "+ja4+" 被多个应用共用("+why+"), 未保存指纹规则")
		} else {
			r := base
			r.Kind, r.Value = "ja4", ja4
			add = append(add, r)
		}
	}
	if len(add) == 0 {
		d := "没有可保存的规则(需要 name / dst_ip / ja4 之一)"
		if len(notes) > 0 {
			d = strings.Join(notes, "; ")
		}
		return actionResp{OK: false, Error: "nothing to save", Detail: d}
	}

	dpiUserRulesWriteMu.Lock()
	defer dpiUserRulesWriteMu.Unlock()
	cur := readDPIUserRules(s.hncDir)
	kept := make([]dpiUserRule, 0, len(cur)+len(add))
	ts := now.Unix()
	for _, r := range cur {
		if !r.live(ts) {
			continue
		}
		dup := false
		for _, a := range add {
			if r.Kind == a.Kind && r.Value == a.Value && r.Port == a.Port {
				dup = true // 同一对象重新纠正: 新的覆盖旧的
				break
			}
		}
		if !dup {
			kept = append(kept, r)
		}
	}
	perApp := 0
	for _, r := range kept {
		if r.AppID == appID {
			perApp++
		}
	}
	if perApp+len(add) > dpiUserMaxPerApp {
		return actionResp{OK: false, Error: "too many rules", Detail: fmt.Sprintf("该应用已有 %d 条纠正规则", perApp)}
	}
	var saved []string
	for _, a := range add {
		a.ID = newDPIUserRuleID()
		kept = append(kept, a)
		switch a.Kind {
		case "domain":
			saved = append(saved, "域名 "+a.Value)
		case "ip":
			v := "IP " + a.Value
			if a.Port > 0 {
				v += ":" + strconv.Itoa(a.Port)
			}
			saved = append(saved, v+"(7 天)")
		case "ja4":
			saved = append(saved, "指纹 "+a.Value)
		}
	}
	if len(kept) > dpiUserMaxRules {
		// 超上限: 丢最旧的
		sort.SliceStable(kept, func(i, j int) bool { return kept[i].Created > kept[j].Created })
		kept = kept[:dpiUserMaxRules]
	}
	if err := writeDPIUserRules(s.hncDir, kept); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	d := "已保存: " + strings.Join(saved, ", ")
	if len(notes) > 0 {
		d += "; " + strings.Join(notes, "; ")
	}
	return actionResp{OK: true, Detail: d}
}

// dpiUserRulesView 给 UI 的列表(按创建时间倒序, 已过期不列)
func dpiUserRulesView(hncDir string, now time.Time) []map[string]interface{} {
	rules := readDPIUserRules(hncDir)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Created > rules[j].Created })
	out := make([]map[string]interface{}, 0, len(rules))
	for _, r := range rules {
		if !r.live(now.Unix()) {
			continue
		}
		m := map[string]interface{}{"id": r.ID, "kind": r.Kind, "value": r.Value, "app_id": r.AppID,
			"app_name": r.app().Name, "category": r.Category, "created": r.Created}
		if r.Port > 0 {
			m["port"] = r.Port
		}
		if r.Expires > 0 {
			m["expires"] = r.Expires
		}
		if r.MAC != "" {
			m["mac"] = r.MAC
		}
		out = append(out, m)
	}
	return out
}

func actionDPICorrectList(s *server) actionResp {
	b, _ := json.Marshal(dpiUserRulesView(s.hncDir, time.Now()))
	return actionResp{OK: true, Detail: string(b)}
}

func actionDPICorrectDel(s *server, p map[string]string) actionResp {
	id := strings.TrimSpace(p["id"])
	all := p["all"] == "true"
	if id == "" && !all {
		return actionResp{OK: false, Error: "bad params", Detail: "id or all=true required"}
	}
	dpiUserRulesWriteMu.Lock()
	defer dpiUserRulesWriteMu.Unlock()
	cur := readDPIUserRules(s.hncDir)
	kept := make([]dpiUserRule, 0, len(cur))
	found := false
	for _, r := range cur {
		if all || r.ID == id {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if !found {
		return actionResp{OK: false, Error: "not found", Detail: "rule not found"}
	}
	if err := writeDPIUserRules(s.hncDir, kept); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true}
}
