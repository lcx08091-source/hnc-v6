// app_time.go — v6.x DPI 增强: 应用使用时长 / 每日时长上限 / 按类别封锁 / 未识别流量
//
// 1. 使用时长(使用时长): app_usage.go 每 10 秒一轮的连接表差分里, 某 (设备, 应用)
//    本轮字节 ≥ appActiveMinBytes(按实际间隔折算, 10 秒 8 KB ≈ 0.8 KB/s)且应用属于
//    「真应用」档(appTier == tierApp; 广告/SDK/CDN/系统服务不算)→ 这一轮记为活跃,
//    活跃秒数按 (mac, app, 小时) 累加进同一个日文件(appUsageDay.Active/Seen, 可选字段,
//    旧文件照常加载)。
// 2. 每日时长上限(应用时长上限): data/app_controls.json 的 time_limits。今天活跃秒数
//    达到上限 → 这台设备的这个应用被封锁到本地次日 0 点: 不写 conn_blocks.json, 而是
//    展开时现算「派生封锁项」(connBlock.Source="app_time", Until=次日 0 点), 由现有
//    conn_blocks 机制(IP 层 + DNS 层)落地; 过了 0 点当天用量归零, 派生项自然消失,
//    后台 10 秒一次的 connBlockRefresh 发现展开结果变了就重跑脚本 → 自动解封。
//    告警: 用完一次、提前 5 分钟预警一次, 每 (设备, 应用, 天) 各一次。
// 3. 按类别封锁(按类别封锁): category_blocks, 同样是派生封锁项(Source="category")。
// 4. 未识别流量: app 归不上的连接按目的(反查名的基础域名, 否则 IP)聚合今天的字节,
//    条数有上限, 给用户「教规则」用。
//
// 模拟设备(MAC 前缀 02:5e:00, 模拟 agent 造的假设备)永远不下发 iptables。
//
//   GET /api/app_time?mac=&days=1..31
//   GET /api/dpi_unknown?days=1..31
//   动作 app_time_limit_set {mac, app_id, minutes}   minutes=0 等同删除
//        app_time_limit_del {mac, app_id}
//        category_block_set {mac, category, enabled}

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hnc.io/dpid/alert"
)

const (
	// 活跃阈值: 每 10 秒 8 KB。微信/QQ 等后台心跳通常 < 1 KB/分钟, 推送偶发几 KB;
	// 刷短视频/看视频/打游戏远超此值; 前台文字聊天、看图文一般也能过(图片/表情包)。
	appActiveMinBytes = 8 * 1024
	appTimeMaxTickSec = 20     // 两轮间隔异常长(休眠/卡顿)时最多记 20 秒, 不凭空多算
	appTimeWarnSec    = 5 * 60 // 提前 5 分钟预警
	appTimeMaxMinutes = 24 * 60

	appUnknownMax     = 300 // 每天最多聚合多少个未识别目的
	appUnknownPruneTo = 200 // 满了裁到多少(按字节保留大的)
	appUnknownMaxMACs = 8   // 每个目的最多记几台设备

	appCtlMaxLimits    = 200
	appCtlMaxCatBlocks = 100

	appBlockMaxDomains    = 64  // 单个应用最多展开多少个规则后缀
	appCatMaxDomains      = 200 // 单个类别最多展开多少个规则后缀
	appBlockMaxExtraNames = 32  // 反查表里归到该应用、但规则后缀没覆盖的名字
	appBlockMaxIPs        = 64  // ip_app_map(IP 规则命中)里归到该应用的 IP

	connBlockSrcAppTime  = "app_time"
	connBlockSrcCategory = "category"
)

// 模拟设备: 永不下发 iptables
func dpiCtlSkipMAC(mac string) bool {
	return strings.HasPrefix(strings.ToLower(mac), "02:5e:00:")
}

// ─── 1. 使用时长记账 ───────────────────────────────────────────────────

type appUnknownAgg struct {
	B  uint64   `json:"b"`
	M  []string `json:"m,omitempty"`
	S  string   `json:"s,omitempty"`  // 示例主机名(第一次看到的完整名字)
	IP bool     `json:"ip,omitempty"` // true = 没有反查名, key 是 IP
}

var appTimeLastTick time.Time // 受 appUsage.mu 保护

// appTimeTickSec 本轮代表多少秒(调用方持 appUsage.mu)
func appTimeTickSec(now time.Time) int {
	last := appTimeLastTick
	appTimeLastTick = now
	def := int(appUsageEvery / time.Second)
	if last.IsZero() || !now.After(last) {
		return def
	}
	sec := int((now.Sub(last) + time.Second/2) / time.Second)
	if sec < 1 {
		sec = 1
	}
	if c := appTimeTickCap(); sec > c { // v5.22: 后台 30s 档时上限随之放宽(power_sched.go)
		sec = c
	}
	return sec
}

// appTimeActive 本轮字节是否算「在用」(阈值按间隔折算)
func appTimeActive(bytes uint64, tickSec int) bool {
	if tickSec <= 0 {
		return false
	}
	per := uint64(appUsageEvery / time.Second)
	return bytes*per >= uint64(appActiveMinBytes)*uint64(tickSec)
}

// appTimeStep tick: "mac|app" → 本轮字节; cats: app → 类别。调用方持锁。
func appTimeStep(d *appUsageDay, tick map[string]uint64, cats map[string]string, now time.Time, tickSec int) {
	hour := strconv.Itoa(now.Hour())
	ts := now.Unix()
	for mk, b := range tick {
		sep := strings.IndexByte(mk, '|')
		if sep < 0 {
			continue
		}
		id := mk[sep+1:]
		if id == appUnknownID || id == appLocalID || id == tunnelAppID || appTier(cats[id]) != tierApp { // v5.21: VPN/代理隧道不算应用时长
			continue
		}
		if !appTimeActive(b, tickSec) {
			continue
		}
		if d.Active == nil {
			d.Active = map[string]map[string]uint32{}
		}
		if d.Active[hour] == nil {
			d.Active[hour] = map[string]uint32{}
		}
		d.Active[hour][mk] += uint32(tickSec)
		if d.Seen == nil {
			d.Seen = map[string][2]int64{}
		}
		v, ok := d.Seen[mk]
		if !ok || v[0] == 0 {
			v[0] = ts
		}
		v[1] = ts
		d.Seen[mk] = v
	}
}

// baseDomain 粗略的「可注册域名」: 末两段; 形如 xx.com.cn / xx.co.uk 取末三段
func baseDomain(name string) string {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	parts := strings.Split(n, ".")
	if len(parts) <= 2 {
		return n
	}
	k := 2
	if len(parts[len(parts)-1]) == 2 {
		switch parts[len(parts)-2] {
		case "com", "net", "org", "gov", "edu", "co", "ac":
			k = 3
		}
	}
	return strings.Join(parts[len(parts)-k:], ".")
}

// appUnknownAdd 未识别流量聚合(调用方持锁)
func appUnknownAdd(d *appUsageDay, dst, name, mac string, bytes uint64) {
	if bytes == 0 || dst == "" {
		return
	}
	key, sample, isIP := dst, "", true
	if name != "" {
		key, sample, isIP = baseDomain(name), strings.ToLower(name), false
	}
	if d.Unknown == nil {
		d.Unknown = map[string]*appUnknownAgg{}
	}
	a := d.Unknown[key]
	if a == nil {
		if len(d.Unknown) >= appUnknownMax {
			appUnknownPrune(d.Unknown, appUnknownPruneTo)
		}
		a = &appUnknownAgg{S: sample, IP: isIP}
		d.Unknown[key] = a
	}
	a.B += bytes
	if mac != "" && len(a.M) < appUnknownMaxMACs {
		found := false
		for _, m := range a.M {
			if m == mac {
				found = true
				break
			}
		}
		if !found {
			a.M = append(a.M, mac)
		}
	}
}

func appUnknownPrune(m map[string]*appUnknownAgg, keep int) {
	type kv struct {
		k string
		b uint64
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v.B})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].b != all[j].b {
			return all[i].b > all[j].b
		}
		return all[i].k < all[j].k
	})
	for _, e := range all[min(keep, len(all)):] {
		delete(m, e.k)
	}
}

// appUsageDayCopy 某天的数据(今天取内存里的副本, 其余读文件); 没有返回 nil
func appUsageDayCopy(hncDir, date string) *appUsageDay {
	appUsage.mu.Lock()
	var d *appUsageDay
	if appUsage.day != nil && appUsage.day.Date == date {
		b, _ := json.Marshal(appUsage.day)
		d = &appUsageDay{}
		_ = json.Unmarshal(b, d)
	}
	appUsage.mu.Unlock()
	if d != nil {
		return d
	}
	if _, err := os.Stat(appUsagePath(hncDir, date)); err != nil {
		return nil
	}
	return loadAppUsageDay(hncDir, date)
}

// aliasUsedKeys v5.21: 把 "mac|app" 键里合并过的旧 MAC 换成新 MAC 并累加 ——
// 换了随机 MAC 的设备, 今天在旧 MAC 上用掉的时长也计入新 MAC 的时长上限。
func aliasUsedKeys(hncDir string, used map[string]int) map[string]int {
	al := loadMACAliases(hncDir)
	if len(al) == 0 {
		return used
	}
	out := make(map[string]int, len(used))
	for k, v := range used {
		if sep := strings.IndexByte(k, '|'); sep > 0 {
			k = resolveMACAlias(al, k[:sep]) + k[sep:]
		}
		out[k] += v
	}
	return out
}

// appTimeUsedToday 今天各 "mac|app" 的活跃秒数(内存里的当天; 跨过 0 点尚未滚动时视为 0)
func appTimeUsedToday(now time.Time) map[string]int {
	out := map[string]int{}
	appUsage.mu.Lock()
	defer appUsage.mu.Unlock()
	d := appUsage.day
	if d == nil || d.Date != now.Format("20060102") {
		return out
	}
	for _, cells := range d.Active {
		for mk, sec := range cells {
			out[mk] += int(sec)
		}
	}
	return out
}

func nextLocalMidnight(now time.Time) time.Time {
	y, m, d := now.Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, now.Location())
}

// ─── 规则库(应用 → 域名后缀 / 类别)────────────────────────────────────

type catalogApp struct {
	ID, Name, Category string
	Suffixes           []string
}

type appCatalog struct {
	apps  map[string]*catalogApp
	byCat map[string][]string // category → 排好序的 app id
}

var appCatalogCache struct {
	mu  sync.Mutex
	key string
	cat *appCatalog
}

// appCatalogFiles 与 dpid 同源: etc/dpi_rules.d/*.json 优先, 否则 etc/dpi_rules.json,
// 再否则 data/dpi_rules.json(模块自带的派生文件)
func appCatalogFiles(hncDir string) []string {
	if fs, _ := filepath.Glob(filepath.Join(hncDir, "etc", "dpi_rules.d", "*.json")); len(fs) > 0 {
		sort.Strings(fs)
		return fs
	}
	for _, p := range []string{filepath.Join(hncDir, "etc", "dpi_rules.json"), filepath.Join(hncDir, "data", "dpi_rules.json")} {
		if _, err := os.Stat(p); err == nil {
			return []string{p}
		}
	}
	return nil
}

type catalogRawRule struct {
	ID        string   `json:"id"`
	App       string   `json:"app"`
	Category  string   `json:"category"`
	Suffixes  []string `json:"suffixes"`
	NoAttr    bool     `json:"do_not_attribute_to_app"`
	NoAttrUsr bool     `json:"do_not_attribute_to_user_app"`
}

func loadAppCatalog(hncDir string) *appCatalog {
	files := appCatalogFiles(hncDir)
	var kb strings.Builder
	for _, f := range files {
		if st, err := os.Stat(f); err == nil {
			kb.WriteString(f + ":" + strconv.FormatInt(st.ModTime().UnixNano(), 10) + ":" + strconv.FormatInt(st.Size(), 10) + ";")
		}
	}
	key := kb.String()
	appCatalogCache.mu.Lock()
	defer appCatalogCache.mu.Unlock()
	if appCatalogCache.cat != nil && appCatalogCache.key == key {
		return appCatalogCache.cat
	}
	c := &appCatalog{apps: map[string]*catalogApp{}, byCat: map[string][]string{}}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil || len(b) > 2<<20 {
			continue
		}
		var rules []catalogRawRule
		var wrap struct {
			Rules []catalogRawRule `json:"rules"`
		}
		if json.Unmarshal(b, &wrap) == nil && len(wrap.Rules) > 0 {
			rules = wrap.Rules
		} else {
			_ = json.Unmarshal(b, &rules)
		}
		for _, r := range rules {
			id := strings.TrimSpace(r.ID)
			if id == "" {
				continue
			}
			if r.NoAttr || r.NoAttrUsr {
				delete(c.apps, id) // 后写覆盖: 用户规则把它改成不归属时也要去掉
				continue
			}
			a := &catalogApp{ID: id, Name: strings.TrimSpace(r.App), Category: strings.ToLower(strings.TrimSpace(r.Category))}
			if a.Name == "" {
				a.Name = id
			}
			seen := map[string]bool{}
			for _, sfx := range r.Suffixes {
				sfx = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(sfx)), "*."), "."), ".")
				if sfx == "" || seen[sfx] || !domainRe.MatchString(sfx) || len(sfx) > 253 || !strings.Contains(sfx, ".") {
					continue
				}
				seen[sfx] = true
				a.Suffixes = append(a.Suffixes, sfx)
			}
			c.apps[id] = a
		}
	}
	for id, a := range c.apps {
		c.byCat[a.Category] = append(c.byCat[a.Category], id)
	}
	for k := range c.byCat {
		sort.Strings(c.byCat[k])
	}
	appCatalogCache.key, appCatalogCache.cat = key, c
	return c
}

// ─── 配置文件 ──────────────────────────────────────────────────────────

type appTimeLimit struct {
	MAC     string `json:"mac"`
	AppID   string `json:"app_id"`
	Minutes int    `json:"minutes"`
	Ts      int64  `json:"ts"`
}

type categoryBlock struct {
	MAC      string `json:"mac"`
	Category string `json:"category"`
	Ts       int64  `json:"ts"`
}

type appControlsFile struct {
	TimeLimits     []appTimeLimit  `json:"time_limits"`
	CategoryBlocks []categoryBlock `json:"category_blocks"`
}

var appCtlMu sync.Mutex

func appControlsPath(hncDir string) string { return filepath.Join(hncDir, "data", "app_controls.json") }

func loadAppControls(hncDir string) appControlsFile {
	var f appControlsFile
	if b, err := os.ReadFile(appControlsPath(hncDir)); err == nil {
		_ = json.Unmarshal(b, &f)
	}
	return f
}

func saveAppControls(hncDir string, f appControlsFile) error {
	if f.TimeLimits == nil {
		f.TimeLimits = []appTimeLimit{}
	}
	if f.CategoryBlocks == nil {
		f.CategoryBlocks = []categoryBlock{}
	}
	b, _ := json.MarshalIndent(f, "", "  ")
	return discoverWriteAtomic(appControlsPath(hncDir), b)
}

// ─── 派生封锁项 ────────────────────────────────────────────────────────

// appBlockItems 把一组应用展开成 conn_blocks 项:
//   - 规则后缀 → domain 项(IP 层按反查表展开, DNS 层按后缀丢查询)
//   - 反查表里归到这些应用、但后缀没覆盖的名字 → domain 项
//   - ip_app_map(IP 规则命中)里归到这些应用的公网 IP → ip 项
//
// 结果确定(排序后截断), 否则每 10 秒展开结果都不同会反复重跑脚本。
func appBlockItems(mac, source, ref, label string, until int64, apps []*catalogApp,
	match func(appID, category string) bool, names map[string]ipName, ipApps map[string]ipApp, maxDomains int) []connBlock {
	var sfx []string
	seen := map[string]bool{}
	for _, a := range apps {
		for _, s := range a.Suffixes {
			if !seen[s] {
				seen[s] = true
				sfx = append(sfx, s)
			}
		}
	}
	sort.Strings(sfx)
	if len(sfx) > maxDomains {
		sfx = sfx[:maxDomains]
	}
	covered := func(h string) bool {
		for _, s := range sfx {
			if h == s || strings.HasSuffix(h, "."+s) {
				return true
			}
		}
		return false
	}
	extraSet := map[string]bool{}
	for _, n := range names {
		if n.App == "" || !match(n.App, strings.ToLower(n.Category)) {
			continue
		}
		h := strings.TrimSuffix(strings.ToLower(n.Name), ".")
		if h == "" || covered(h) || !domainRe.MatchString(h) || len(h) > 253 {
			continue
		}
		extraSet[h] = true
	}
	extra := make([]string, 0, len(extraSet))
	for h := range extraSet {
		extra = append(extra, h)
	}
	sort.Strings(extra)
	if len(extra) > appBlockMaxExtraNames {
		extra = extra[:appBlockMaxExtraNames]
	}
	var ips []string
	for ip, a := range ipApps {
		if a.ID == "" || !match(a.ID, strings.ToLower(a.Category)) || isPrivateIP(ip) || net.ParseIP(ip) == nil {
			continue
		}
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	if len(ips) > appBlockMaxIPs {
		ips = ips[:appBlockMaxIPs]
	}
	out := make([]connBlock, 0, len(sfx)+len(extra)+len(ips))
	mk := func(kind, v string) connBlock {
		return connBlock{MAC: mac, Kind: kind, Value: v, Label: label, Source: source, Ref: ref, Until: until}
	}
	for _, s := range sfx {
		out = append(out, mk("domain", s))
	}
	for _, h := range extra {
		out = append(out, mk("domain", h))
	}
	for _, ip := range ips {
		out = append(out, mk("ip", net.ParseIP(ip).String()))
	}
	return out
}

// appTimeExhausted 今天已用完的 (mac, app) → 已用秒数
func appTimeExhausted(ctl appControlsFile, used map[string]int) map[string]int {
	out := map[string]int{}
	for _, l := range ctl.TimeLimits {
		if l.Minutes <= 0 {
			continue
		}
		if u := used[l.MAC+"|"+l.AppID]; u >= l.Minutes*60 {
			out[l.MAC+"|"+l.AppID] = u
		}
	}
	return out
}

// connBlockDerived 当前生效的派生封锁项(时长用完 + 类别封锁)
func (s *server) connBlockDerived(now time.Time) []connBlock {
	ctl := loadAppControls(s.hncDir)
	if len(ctl.TimeLimits) == 0 && len(ctl.CategoryBlocks) == 0 {
		return nil
	}
	return s.connBlockDerivedFrom(ctl, aliasUsedKeys(s.hncDir, appTimeUsedToday(now)), now)
}

func (s *server) connBlockDerivedFrom(ctl appControlsFile, used map[string]int, now time.Time) []connBlock {
	exh := appTimeExhausted(ctl, used)
	if len(exh) == 0 && len(ctl.CategoryBlocks) == 0 {
		return nil
	}
	cat := loadAppCatalog(s.hncDir)
	names := s.loadIPNames()
	ipApps := s.loadIPApps()
	var out []connBlock
	until := nextLocalMidnight(now).Unix()
	for _, l := range ctl.TimeLimits {
		if _, ok := exh[l.MAC+"|"+l.AppID]; !ok {
			continue
		}
		var apps []*catalogApp
		label := l.AppID
		if a := cat.apps[l.AppID]; a != nil {
			apps, label = []*catalogApp{a}, a.Name
		}
		id := l.AppID
		out = append(out, appBlockItems(l.MAC, connBlockSrcAppTime, id, label, until, apps,
			func(appID, _ string) bool { return appID == id }, names, ipApps, appBlockMaxDomains)...)
	}
	for _, cb := range ctl.CategoryBlocks {
		var apps []*catalogApp
		for _, id := range cat.byCat[cb.Category] {
			apps = append(apps, cat.apps[id])
		}
		c := cb.Category
		out = append(out, appBlockItems(cb.MAC, connBlockSrcCategory, c, "类别:"+c, 0, apps,
			func(appID, category string) bool {
				if a := cat.apps[appID]; a != nil {
					return a.Category == c
				}
				return category == c
			}, names, ipApps, appCatMaxDomains)...)
	}
	return out
}

// connBlocksEffective 用户封锁项 + 派生项, 去掉模拟设备(永不下发 iptables)
func (s *server) connBlocksEffective(now time.Time) connBlockFile {
	f := readConnBlocks(s.hncDir)
	f.Items = append(f.Items, s.connBlockDerived(now)...)
	kept := f.Items[:0]
	for _, it := range f.Items {
		if !dpiCtlSkipMAC(it.MAC) {
			kept = append(kept, it)
		}
	}
	f.Items = kept
	return f
}

// connBlocksForWithDerived 某台设备的全部封锁项(显示用, 派生项带 source)
func (s *server) connBlocksForWithDerived(mac string, now time.Time) []connBlock {
	out := connBlocksFor(s.hncDir, mac)
	for _, it := range s.connBlockDerived(now) {
		if it.MAC == mac {
			out = append(out, it)
		}
	}
	return out
}

// ─── 告警 ──────────────────────────────────────────────────────────────

var appTimeAlerts struct {
	mu     sync.Mutex
	loaded bool
	Date   string           `json:"date"`
	Sent   map[string]int64 `json:"sent"`
}

func appTimeAlertStatePath(hncDir string) string {
	return filepath.Join(hncDir, "run", "app_time_alerts.json")
}

// appTimeEnforce 检查时长上限, 发预警/用完告警(每 (设备, 应用, 天, 种类) 一次)。
// 封锁本身不在这里做: connBlockRefresh 展开时现算派生项。
func (s *server) appTimeEnforce(now time.Time) {
	ctl := loadAppControls(s.hncDir)
	if len(ctl.TimeLimits) == 0 {
		return
	}
	// v5.20: 时钟不可信时不判定/不写 app_time_alerts.json(日期会错成 1970 等,
	// 把当天已发告警的去重表冲掉)
	if !clockSane(s.hncDir, now) {
		return
	}
	used := aliasUsedKeys(s.hncDir, appTimeUsedToday(now))
	date := now.Format("20060102")
	cat := loadAppCatalog(s.hncDir)
	appTimeAlerts.mu.Lock()
	defer appTimeAlerts.mu.Unlock()
	if !appTimeAlerts.loaded {
		appTimeAlerts.loaded = true
		if b, err := os.ReadFile(appTimeAlertStatePath(s.hncDir)); err == nil {
			var st struct {
				Date string           `json:"date"`
				Sent map[string]int64 `json:"sent"`
			}
			if json.Unmarshal(b, &st) == nil {
				appTimeAlerts.Date, appTimeAlerts.Sent = st.Date, st.Sent
			}
		}
	}
	if appTimeAlerts.Date != date || appTimeAlerts.Sent == nil {
		appTimeAlerts.Date, appTimeAlerts.Sent = date, map[string]int64{}
	}
	changed := false
	cfg := alert.NewConfig(s.hncDir)
	enabled := alert.LoadConfig(cfg.AlertsConfigPath).Enabled
	for _, l := range ctl.TimeLimits {
		if l.Minutes <= 0 {
			continue
		}
		u := used[l.MAC+"|"+l.AppID]
		lim := l.Minutes * 60
		kind := ""
		switch {
		case u >= lim:
			kind = "app_time_exhausted"
		case lim > appTimeWarnSec && u >= lim-appTimeWarnSec:
			kind = "app_time_warn"
		default:
			continue
		}
		sk := l.MAC + "|" + l.AppID + "|" + kind
		if _, sent := appTimeAlerts.Sent[sk]; sent {
			continue
		}
		// 用完时若预警没发过, 就不补发预警了(直接标记)
		if kind == "app_time_exhausted" {
			appTimeAlerts.Sent[l.MAC+"|"+l.AppID+"|app_time_warn"] = now.Unix()
		}
		appTimeAlerts.Sent[sk] = now.Unix()
		changed = true
		if !enabled {
			continue
		}
		name := l.AppID
		if a := cat.apps[l.AppID]; a != nil {
			name = a.Name
		}
		detail := "「" + name + "」今天已用 " + strconv.Itoa(u/60) + " 分钟, 达到上限 " + strconv.Itoa(l.Minutes) + " 分钟, 已封锁到今晚 24:00"
		if kind == "app_time_warn" {
			detail = "「" + name + "」今天已用 " + strconv.Itoa(u/60) + " 分钟, 还剩约 " + strconv.Itoa((lim-u+59)/60) + " 分钟达到上限"
		}
		a := alert.Alert{
			ID:     kind + "_" + strings.ReplaceAll(l.MAC, ":", "") + "_" + l.AppID + "_" + date,
			Ts:     now.Unix(),
			Kind:   kind,
			MAC:    l.MAC,
			Detail: detail,
			Extra: map[string]interface{}{"app_id": l.AppID, "app_name": name, "minutes": l.Minutes,
				"used_sec": u, "until": nextLocalMidnight(now).Unix()},
		}
		_ = appendAlertJSONL(cfg.AlertsJSONLPath, a)
	}
	if changed {
		b, _ := json.Marshal(map[string]interface{}{"date": appTimeAlerts.Date, "sent": appTimeAlerts.Sent})
		_ = discoverWriteAtomic(appTimeAlertStatePath(s.hncDir), b)
	}
}

func appendAlertJSONL(path string, a alert.Alert) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// ─── 动作 ──────────────────────────────────────────────────────────────

func validCtlID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// appKnownUserApp app_id 是否是「真应用」: 规则库里有, 或今天的用量里见过(类别属于应用档)
func (s *server) appKnownUserApp(appID string) (string, bool) {
	if a := loadAppCatalog(s.hncDir).apps[appID]; a != nil {
		return a.Name, appTier(a.Category) == tierApp
	}
	appUsage.mu.Lock()
	defer appUsage.mu.Unlock()
	if appUsage.day != nil {
		if m, ok := appUsage.day.Apps[appID]; ok && appID != appUnknownID && appID != appLocalID && appID != tunnelAppID {
			return m.Name, appTier(m.Category) == tierApp
		}
	}
	return "", false
}

// appCtlResync 配置变了: 重新展开(结果没变不跑脚本)
func (s *server) appCtlResync() actionResp {
	connBlockMu.Lock()
	defer connBlockMu.Unlock()
	out, err := s.connBlockSyncLocked(false)
	if err != nil {
		return actionResp{OK: false, Error: "sync failed", Detail: out}
	}
	return actionResp{OK: true, Detail: out}
}

// appCtlResyncFor 模拟设备(sim.go 放行的配置类动作)只存配置、不重跑同步: 它的派生项
// 在 connBlocksEffective 里本来就被滤掉, 真实设备的展开结果不会变。
func (s *server) appCtlResyncFor(mac string) actionResp {
	if dpiCtlSkipMAC(mac) {
		return actionResp{OK: true, Detail: "模拟设备: 已保存(只显示, 不下发)"}
	}
	return s.appCtlResync()
}

func actionAppTimeLimitSet(s *server, p map[string]string) actionResp {
	mac := canonMAC(p["mac"])
	if mac == "" || !validMAC(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	appID := strings.TrimSpace(p["app_id"])
	if !validCtlID(appID) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid app_id"}
	}
	minutes, err := strconv.Atoi(strings.TrimSpace(p["minutes"]))
	if err != nil || minutes < 0 || minutes > appTimeMaxMinutes {
		return actionResp{OK: false, Error: "bad params", Detail: "minutes must be 0..1440"}
	}
	if minutes == 0 {
		return actionAppTimeLimitDel(s, p)
	}
	if _, ok := s.appKnownUserApp(appID); !ok && !(dpiCtlSkipMAC(mac) && s.simKnownApp(appID)) {
		return actionResp{OK: false, Error: "bad params", Detail: "unknown app_id (或属于系统/SDK 类, 不计时长)"}
	}
	appCtlMu.Lock()
	f := loadAppControls(s.hncDir)
	found := false
	for i := range f.TimeLimits {
		if f.TimeLimits[i].MAC == mac && f.TimeLimits[i].AppID == appID {
			f.TimeLimits[i].Minutes, f.TimeLimits[i].Ts = minutes, time.Now().Unix()
			found = true
		}
	}
	if !found {
		if len(f.TimeLimits) >= appCtlMaxLimits {
			appCtlMu.Unlock()
			return actionResp{OK: false, Error: "too many", Detail: "时长上限条目已达上限 200"}
		}
		f.TimeLimits = append(f.TimeLimits, appTimeLimit{MAC: mac, AppID: appID, Minutes: minutes, Ts: time.Now().Unix()})
	}
	err = saveAppControls(s.hncDir, f)
	appCtlMu.Unlock()
	if err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return s.appCtlResyncFor(mac)
}

func actionAppTimeLimitDel(s *server, p map[string]string) actionResp {
	mac := canonMAC(p["mac"])
	appID := strings.TrimSpace(p["app_id"])
	if mac == "" || !validMAC(mac) || !validCtlID(appID) {
		return actionResp{OK: false, Error: "bad params", Detail: "mac/app_id required"}
	}
	appCtlMu.Lock()
	f := loadAppControls(s.hncDir)
	kept := f.TimeLimits[:0]
	found := false
	for _, l := range f.TimeLimits {
		if l.MAC == mac && l.AppID == appID {
			found = true
			continue
		}
		kept = append(kept, l)
	}
	if !found {
		appCtlMu.Unlock()
		return actionResp{OK: false, Error: "not found"}
	}
	f.TimeLimits = kept
	err := saveAppControls(s.hncDir, f)
	appCtlMu.Unlock()
	if err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return s.appCtlResyncFor(mac)
}

func parseBoolParam(v string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes":
		return true, true
	case "0", "false", "off", "no":
		return false, true
	}
	return false, false
}

// appBlockableCategories 可封锁的类别(规则库里「真应用」档的类别)→ app id
func appBlockableCategories(cat *appCatalog) map[string][]string {
	out := map[string][]string{}
	for c, ids := range cat.byCat {
		if c != "" && appTier(c) == tierApp {
			out[c] = ids
		}
	}
	return out
}

func actionCategoryBlockSet(s *server, p map[string]string) actionResp {
	mac := canonMAC(p["mac"])
	if mac == "" || !validMAC(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	c := strings.ToLower(strings.TrimSpace(p["category"]))
	if !validCtlID(c) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid category"}
	}
	en, ok := parseBoolParam(p["enabled"])
	if !ok {
		return actionResp{OK: false, Error: "bad params", Detail: "enabled must be true|false"}
	}
	if en {
		if _, ok := appBlockableCategories(loadAppCatalog(s.hncDir))[c]; !ok && !(dpiCtlSkipMAC(mac) && s.simKnownCategory(c)) {
			return actionResp{OK: false, Error: "bad params", Detail: "unknown category (或属于系统/SDK 类, 不可封锁)"}
		}
	}
	appCtlMu.Lock()
	f := loadAppControls(s.hncDir)
	idx := -1
	for i, cb := range f.CategoryBlocks {
		if cb.MAC == mac && cb.Category == c {
			idx = i
		}
	}
	switch {
	case en && idx >= 0, !en && idx < 0:
		appCtlMu.Unlock()
		return actionResp{OK: true, Detail: "no change"}
	case en:
		if len(f.CategoryBlocks) >= appCtlMaxCatBlocks {
			appCtlMu.Unlock()
			return actionResp{OK: false, Error: "too many", Detail: "类别封锁条目已达上限 100"}
		}
		f.CategoryBlocks = append(f.CategoryBlocks, categoryBlock{MAC: mac, Category: c, Ts: time.Now().Unix()})
	default:
		f.CategoryBlocks = append(f.CategoryBlocks[:idx], f.CategoryBlocks[idx+1:]...)
	}
	err := saveAppControls(s.hncDir, f)
	appCtlMu.Unlock()
	if err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return s.appCtlResyncFor(mac)
}

// ─── 设备 API 附加字段 ─────────────────────────────────────────────────

// appControlsByMAC mac → {"app_time_limits":[...], "category_blocks":[...]}(只含有配置的设备)
func (s *server) appControlsByMAC(now time.Time) map[string]map[string]interface{} {
	ctl := loadAppControls(s.hncDir)
	if len(ctl.TimeLimits) == 0 && len(ctl.CategoryBlocks) == 0 {
		return nil
	}
	cat := loadAppCatalog(s.hncDir)
	used := aliasUsedKeys(s.hncDir, appTimeUsedToday(now))
	s.simAddAppTimeUsed(used, now) // 模拟设备的已用量(只显示; 关闭时空操作)
	until := nextLocalMidnight(now).Unix()
	out := map[string]map[string]interface{}{}
	get := func(mac string) map[string]interface{} {
		if out[mac] == nil {
			out[mac] = map[string]interface{}{"app_time_limits": []map[string]interface{}{}, "category_blocks": []map[string]interface{}{}}
		}
		return out[mac]
	}
	for _, l := range ctl.TimeLimits {
		m := get(l.MAC)
		u := used[l.MAC+"|"+l.AppID]
		name, category := l.AppID, ""
		if a := cat.apps[l.AppID]; a != nil {
			name, category = a.Name, a.Category
		} else if dpiCtlSkipMAC(l.MAC) {
			if a, ok := simFindApp(s.hncDir, l.AppID); ok {
				name, category = a.Name, a.Cat
			}
		}
		exhausted := l.Minutes > 0 && u >= l.Minutes*60
		it := map[string]interface{}{"app_id": l.AppID, "name": name, "category": category,
			"minutes": l.Minutes, "used_sec": u, "used_min": u / 60, "exhausted": exhausted,
			"enforced": exhausted && !dpiCtlSkipMAC(l.MAC)}
		if dpiCtlSkipMAC(l.MAC) {
			it["sim"] = true
		}
		if exhausted {
			it["until"] = until
		}
		m["app_time_limits"] = append(m["app_time_limits"].([]map[string]interface{}), it)
	}
	for _, cb := range ctl.CategoryBlocks {
		m := get(cb.MAC)
		m["category_blocks"] = append(m["category_blocks"].([]map[string]interface{}), map[string]interface{}{
			"category": cb.Category, "app_count": len(cat.byCat[cb.Category]), "ts": cb.Ts,
			"enforced": !dpiCtlSkipMAC(cb.MAC)})
	}
	return out
}

// ─── 查询 API ──────────────────────────────────────────────────────────

func parseDaysParam(r *http.Request) int {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 {
		days = 1
	}
	if days > 31 {
		days = 31
	}
	return days
}

// GET /api/app_time?mac=&days=
func (s *server) apiAppTime(w http.ResponseWriter, r *http.Request) {
	days := parseDaysParam(r)
	mac := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mac")))
	if mac != "" && !validMAC(mac) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mac"})
		return
	}
	resolve := macAliasResolver(s.hncDir) // v5.21: 合并过的旧 MAC 时长归到新 MAC
	if mac != "" {
		mac = resolve(mac)
	}
	now := time.Now()
	type acc struct {
		sec         uint64
		first, last int64
		hours       [24]uint64
	}
	byApp := map[string]*acc{}
	meta := map[string]appUsageMeta{}
	var byHour [24]uint64
	var total uint64
	since := ""
	simSec := map[string]uint64{} // 模拟设备贡献的秒数(sim_merge.go)
	for i := days - 1; i >= 0; i-- {
		date := now.AddDate(0, 0, -i).Format("20060102")
		d := s.simMergeAppUsageDay(appUsageDayCopy(s.hncDir, date), date) // 模拟环境: 今天叠加; 关闭时原样
		if d == nil {
			continue
		}
		if since == "" {
			since = date
		}
		for id, m := range d.Apps {
			meta[id] = m
		}
		for h, cells := range d.Active {
			hi, err := strconv.Atoi(h)
			if err != nil || hi < 0 || hi > 23 {
				continue
			}
			for mk, sec := range cells {
				sep := strings.IndexByte(mk, '|')
				if sep < 0 || (mac != "" && resolve(mk[:sep]) != mac) {
					continue
				}
				id := mk[sep+1:]
				a := byApp[id]
				if a == nil {
					a = &acc{}
					byApp[id] = a
				}
				a.sec += uint64(sec)
				if isSimMAC(mk[:sep]) {
					simSec[id] += uint64(sec)
				}
				a.hours[hi] += uint64(sec)
				byHour[hi] += uint64(sec)
				total += uint64(sec)
			}
		}
		for mk, v := range d.Seen {
			sep := strings.IndexByte(mk, '|')
			if sep < 0 || (mac != "" && resolve(mk[:sep]) != mac) {
				continue
			}
			a := byApp[mk[sep+1:]]
			if a == nil {
				continue
			}
			if v[0] > 0 && (a.first == 0 || v[0] < a.first) {
				a.first = v[0]
			}
			if v[1] > a.last {
				a.last = v[1]
			}
		}
	}
	apps := make([]map[string]interface{}, 0, len(byApp))
	for id, a := range byApp {
		m := meta[id]
		name := m.Name
		if name == "" {
			name = id
		}
		it := map[string]interface{}{"id": id, "name": name, "category": m.Category,
			"active_sec": a.sec, "first_seen": a.first, "last_seen": a.last, "by_hour": a.hours[:]}
		if n := simSec[id]; n > 0 { // 含模拟设备的时长: sim_active_sec; 全部来自模拟设备再加 sim:true
			it["sim_active_sec"] = n
			if n == a.sec {
				it["sim"] = true
			}
		}
		apps = append(apps, it)
	}
	sort.Slice(apps, func(i, j int) bool {
		si, sj := apps[i]["active_sec"].(uint64), apps[j]["active_sec"].(uint64)
		if si != sj {
			return si > sj
		}
		return apps[i]["id"].(string) < apps[j]["id"].(string)
	})
	hours := make([]map[string]interface{}, 24)
	for h := 0; h < 24; h++ {
		hours[h] = map[string]interface{}{"h": h, "active_sec": byHour[h]}
	}
	cat := loadAppCatalog(s.hncDir)
	cats := []map[string]interface{}{}
	bc := appBlockableCategories(cat)
	ck := make([]string, 0, len(bc))
	for c := range bc {
		ck = append(ck, c)
	}
	sort.Strings(ck)
	for _, c := range ck {
		list := make([]map[string]string, 0, len(bc[c]))
		for _, id := range bc[c] {
			list = append(list, map[string]string{"id": id, "name": cat.apps[id].Name})
		}
		cats = append(cats, map[string]interface{}{"id": c, "apps": list})
	}
	resp := map[string]interface{}{
		"ok": true, "days": days, "mac": mac, "since": since,
		"total_active_sec": total, "apps": apps, "by_hour": hours,
		"categories":      cats,
		"threshold_bytes": appActiveMinBytes, "tick_sec": int(appUsageEvery / time.Second),
	}
	if len(simSec) > 0 {
		resp["sim_included"] = true
	}
	if mac != "" {
		c := s.appControlsByMAC(now)[mac]
		if c == nil {
			c = map[string]interface{}{"app_time_limits": []map[string]interface{}{}, "category_blocks": []map[string]interface{}{}}
		}
		resp["app_time_limits"], resp["category_blocks"] = c["app_time_limits"], c["category_blocks"]
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/dpi_unknown?days=1
func (s *server) apiDPIUnknown(w http.ResponseWriter, r *http.Request) {
	days := parseDaysParam(r)
	now := time.Now()
	agg := map[string]*appUnknownAgg{}
	var total, tunnelTotal, inferredTotal uint64
	for i := days - 1; i >= 0; i-- {
		date := now.AddDate(0, 0, -i).Format("20060102")
		d := s.simMergeAppUsageDay(appUsageDayCopy(s.hncDir, date), date) // 模拟环境: 今天叠加; 关闭时原样
		if d == nil {
			continue
		}
		for _, cells := range d.Hours { // 总量按字节账算(聚合表有条数上限, 尾部被裁掉的也算进来)
			for mk, v := range cells {
				if strings.HasSuffix(mk, "|"+appUnknownID) {
					total += v[0] + v[1]
				} else if strings.HasSuffix(mk, "|"+tunnelAppID) {
					tunnelTotal += v[0] + v[1]
				}
			}
		}
		for _, v := range d.Inferred { // v5.21: 共现推断归到应用的字节(原本会是未识别)
			inferredTotal += v[0] + v[1]
		}
		for k, v := range d.Unknown {
			if v == nil {
				continue
			}
			a := agg[k]
			if a == nil {
				a = &appUnknownAgg{S: v.S, IP: v.IP}
				agg[k] = a
			}
			a.B += v.B
			for _, m := range v.M {
				dup := false
				for _, x := range a.M {
					if x == m {
						dup = true
						break
					}
				}
				if !dup && len(a.M) < appUnknownMaxMACs {
					a.M = append(a.M, m)
				}
			}
		}
	}
	keys := make([]string, 0, len(agg))
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if agg[keys[i]].B != agg[keys[j]].B {
			return agg[keys[i]].B > agg[keys[j]].B
		}
		return keys[i] < keys[j]
	})
	if len(keys) > 100 {
		keys = keys[:100]
	}
	items := make([]map[string]interface{}, 0, len(keys))
	simIncluded := false
	for _, k := range keys {
		a := agg[k]
		kind := "domain"
		if a.IP {
			kind = "ip"
		}
		macs := a.M
		if macs == nil {
			macs = []string{}
		}
		it := map[string]interface{}{"name_or_ip": k, "kind": kind, "sample": a.S,
			"bytes": a.B, "devices": len(macs), "macs": macs}
		if simOnlyMACs(macs) { // 只来自模拟设备的目的(sim_merge.go 造的)
			it["sim"] = true
			simIncluded = true
		}
		items = append(items, it)
	}
	resp := map[string]interface{}{"ok": true, "days": days, "items": items,
		"total_unknown_bytes": total, "cap_per_day": appUnknownMax,
		// v5.21: 已从「未识别」里分出去的两块: 走 VPN/代理隧道的字节、按共现推断归到应用的字节
		"tunnel_bytes": tunnelTotal, "inferred_bytes": inferredTotal}
	if simIncluded {
		resp["sim_included"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}
