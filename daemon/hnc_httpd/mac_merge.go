// mac_merge.go — v5.21 随机 MAC(MAC 地址随机化)识别 + 「疑似同一设备」建议
//
// 背景: Android 10+/iOS 14+ 默认对每个 Wi-Fi 使用随机 MAC(本地管理位 = 首字节
// bit 0x02), 且可能定期/重置网络后更换。换 MAC 后 HNC 视其为新设备, 用户给旧 MAC
// 配的名字/限速/配额/封锁全部"丢失"。这里做两件事:
//
//  1. 识别: 首字节 bit 0x02 置位(且非组播、非模拟设备 02:5e:00)= 随机 MAC。
//  2. 建议: 新 MAC 出现后(之后 24 小时内每轮重算, 证据会陆续到齐), 在已知设备
//     (最近 30 天见过的)里按多路信号打分 0-100, 带理由:
//     DHCP 主机名 / mDNS 名 / DHCP 指纹(option 55)/ 厂商类(option 60)(dpid 的
//     run/dpi_devid.json)/ 设备识别(类型/品牌/型号/系统, 含用户手动纠正)/
//     TLS 指纹 JA4 集合(run/dpi_state.json clients[].top_ja4)/ 常用应用集合
//     (dpi_state top_apps + 今日 app_usage)/ 时间接近(旧 MAC 离线不久新 MAC 出现)。
//     两者同时在线过 = 不是同一台, 直接排除; 型号/品牌/系统明确不同 = 重扣分。
//     只靠"时间接近"不够, 身份信号合计 < 15 分的不给建议。
//
// 状态: data/mac_merge_suggestions.json(只由 httpd 写, tmp+rename)
//
//	{"version":1, "bootstrapped":true,
//	 "profiles":   {"<mac>": {first_seen,last_seen,dhcp_name,mdns_name,dhcp_fp,vendor_class,
//	                          type,brand,model,os,ja4[],apps[],new}},
//	 "suggestions":{"<new_mac>": [{old_mac,score,reasons[],ts}, ...最多 3 个]},
//	 "dismissed":  {"<new_mac>|<old_mac>": ts},
//	 "alerted":    {"<new_mac>": ts}}
//
// profiles 是每个 MAC 的"指纹快照": dpid 的 dpi_state 只保留 128 个客户端、
// devices.json 只有在线设备, 旧 MAC 离线后它的信号要靠这里留住。首轮(文件不存在)
// 只登记现有设备为已知(不产生建议), 之后新出现的 MAC 标记 new。
//
// 告警: 新 MAC 的最佳候选分数首次 ≥ 60 时发一条 kind=mac_merge_suggest(每个新 MAC
// 一次), 走现有 run/alerts.jsonl(/api/alerts)。
//
//	GET /api/mac_merge → {suggestions:[{new_mac,old_mac,score,reasons[],new_name,old_name,
//	                      old_last_seen,new_first_seen,new_online,randomized:true}], aliases:{old:new}}
//	/api/devices 每行: randomized_mac(bool); 有建议时 merge_suggestion(最佳候选);
//	                   已被合并走的旧 MAC 再出现时 merged_into。
package main

import (
	"encoding/json"
	"fmt"
	"math"
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
	macMergeRelPath     = "data/mac_merge_suggestions.json"
	macMergeEvery       = 30 * time.Second
	macMergeMinScore    = 40         // 低于此分不作为建议
	macMergeAlertScore  = 60         // 首次达到此分发告警
	macMergeNewWindow   = 24 * 3600  // 新 MAC 出现后多久内持续重算建议
	macMergeCandMaxAge  = 30 * 86400 // 候选旧设备: 最近 30 天见过
	macMergeOverlapSlop = 120        // 旧 MAC 在新 MAC 出现后仍活跃超过此秒数 = 同时在线
	macMergeProfileTTL  = 90 * 86400 // 画像保留 90 天
	macMergeMaxProfiles = 512        // 画像上限(按 last_seen 淘汰最旧)
	macMergeTopN        = 3          // 每个新 MAC 最多保留几个候选
	macMergeMaxJA4      = 16         // 画像里最多记几个 JA4
	macMergeMaxApps     = 24         // 画像里最多记几个应用
	macMergeAlertKind   = "mac_merge_suggest"
	macMergeIdentMin    = 15 // 身份信号(不含时间)至少这么多分才给建议
	macMergeDismissTTL  = 180 * 86400
)

type macProfile struct {
	FirstSeen   int64    `json:"first_seen"`
	LastSeen    int64    `json:"last_seen"`
	DHCPName    string   `json:"dhcp_name,omitempty"`
	MDNSName    string   `json:"mdns_name,omitempty"`
	DHCPFP      string   `json:"dhcp_fp,omitempty"`
	VendorClass string   `json:"vendor_class,omitempty"`
	Type        string   `json:"type,omitempty"`
	Brand       string   `json:"brand,omitempty"`
	Model       string   `json:"model,omitempty"`
	OS          string   `json:"os,omitempty"`
	JA4         []string `json:"ja4,omitempty"`
	Apps        []string `json:"apps,omitempty"`
	New         bool     `json:"new,omitempty"` // 首轮登记之后才出现的 MAC
}

type macMergeCand struct {
	OldMAC  string   `json:"old_mac"`
	Score   int      `json:"score"`
	Reasons []string `json:"reasons"`
	Ts      int64    `json:"ts"`
}

type macMergeFile struct {
	Version      int                       `json:"version"`
	Bootstrapped bool                      `json:"bootstrapped"`
	Profiles     map[string]*macProfile    `json:"profiles"`
	Suggestions  map[string][]macMergeCand `json:"suggestions"`
	Dismissed    map[string]int64          `json:"dismissed"`
	Alerted      map[string]int64          `json:"alerted"`
}

// macMergeMu 串行化 mac_merge_suggestions.json 的读改写(后台 tick 与动作)。
var macMergeMu sync.Mutex

func macMergePath(hncDir string) string { return filepath.Join(hncDir, macMergeRelPath) }

func loadMacMergeFile(hncDir string) *macMergeFile {
	f := &macMergeFile{}
	if b, err := os.ReadFile(macMergePath(hncDir)); err == nil {
		_ = json.Unmarshal(b, f)
	}
	f.Version = 1
	if f.Profiles == nil {
		f.Profiles = map[string]*macProfile{}
	}
	if f.Suggestions == nil {
		f.Suggestions = map[string][]macMergeCand{}
	}
	if f.Dismissed == nil {
		f.Dismissed = map[string]int64{}
	}
	if f.Alerted == nil {
		f.Alerted = map[string]int64{}
	}
	for k, p := range f.Profiles {
		if p == nil {
			delete(f.Profiles, k)
		}
	}
	return f
}

func saveMacMergeFile(hncDir string, f *macMergeFile) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return discoverWriteAtomic(macMergePath(hncDir), b)
}

func macMergeDismissKey(newMAC, oldMAC string) string { return newMAC + "|" + oldMAC }

// isRandomizedMAC 本地管理位(首字节 bit 0x02)置位的单播 MAC; 模拟设备不算。
func isRandomizedMAC(mac string) bool {
	mac = strings.ToLower(mac)
	if len(mac) < 2 || isSimMACPrefix(mac) {
		return false
	}
	b, err := strconv.ParseUint(mac[:2], 16, 8)
	if err != nil {
		return false
	}
	return b&0x02 != 0 && b&0x01 == 0
}

// isSimMACPrefix 模拟设备前缀(不做完整格式校验; 设备合并对任何 02:5e:00 一律拒绝)
func isSimMACPrefix(mac string) bool { return strings.HasPrefix(strings.ToLower(mac), "02:5e:00") }

// ─── 观测: 从各数据源收集每个 MAC 的当前信号 ───────────────────────────

type macObs struct {
	inDevices   bool // 出现在 devices.json(= hotspotd 认为在线/刚离线 < 90s)
	lastSeen    int64
	dhcpName    string
	mdnsName    string
	dhcpFP      string
	vendorClass string
	typ         string
	brand       string
	model       string
	os          string
	ja4         []string
	apps        []string
}

// hostnameKind 把各来源的 hostname_src 归成 dhcp / mdns / ""(其它: mac/oui/pending/manual 不算信号)
func hostnameKind(src string) string {
	switch strings.ToLower(strings.TrimSpace(src)) {
	case "dhcp", "dhcpv6", "lease", "dnsmasq":
		return "dhcp"
	case "mdns", "nbns", "llmnr":
		return "mdns"
	}
	return ""
}

func (o *macObs) setHostname(name, src string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	switch hostnameKind(src) {
	case "dhcp":
		if o.dhcpName == "" {
			o.dhcpName = name
		}
	case "mdns":
		if o.mdnsName == "" {
			o.mdnsName = name
		}
	}
}

func readJSONMap(path string) map[string]interface{} {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

// collectMacObs 汇总 devices.json / dpi_devid.json / 手动识别纠正 / dpi_state.json /
// 今日应用用量(appDay, 可为 nil)。模拟设备跳过。
func collectMacObs(hncDir string, appDay *appUsageDay) map[string]*macObs {
	out := map[string]*macObs{}
	get := func(mac string) *macObs {
		mac = strings.ToLower(strings.TrimSpace(mac))
		if !validMAC(mac) || isSimMACPrefix(mac) {
			return nil
		}
		o := out[mac]
		if o == nil {
			o = &macObs{}
			out[mac] = o
		}
		return o
	}
	// 1) hotspotd devices.json
	for mac, raw := range readJSONMap(filepath.Join(hncDir, "data", "devices.json")) {
		d, _ := raw.(map[string]interface{})
		o := get(mac)
		if d == nil || o == nil {
			continue
		}
		o.inDevices = true
		if ls, ok := toInt64(d["last_seen"]); ok && ls > o.lastSeen {
			o.lastSeen = ls
		}
		o.setHostname(asString(d["hostname"]), asString(d["hostname_src"]))
	}
	// 2) dpid 被动识别 run/dpi_devid.json(含 DHCP opt55 指纹 / opt60 厂商类)
	if root := readJSONMap(filepath.Join(hncDir, "run", "dpi_devid.json")); root != nil {
		devs, _ := root["devices"].(map[string]interface{})
		for mac, raw := range devs {
			d, _ := raw.(map[string]interface{})
			o := get(mac)
			if d == nil || o == nil {
				continue
			}
			o.setHostname(asString(d["hostname"]), asString(d["hostname_src"]))
			o.dhcpFP = strings.TrimSpace(asString(d["dhcp_fp"]))
			o.vendorClass = strings.TrimSpace(asString(d["vendor_class"]))
			if t := asString(d["type"]); t != "unknown" {
				o.typ = t
			}
			o.brand, o.model, o.os = asString(d["brand"]), asString(d["model"]), asString(d["os"])
			// dpid 的 last_seen 只用于离线设备的"最近见过"(不让它把 devices.json 的更新值拉低)
			if ls, ok := toInt64(d["last_seen"]); ok && ls > o.lastSeen && !o.inDevices {
				o.lastSeen = ls
			}
		}
	}
	// 3) 用户手动纠正的识别结果(把握 100%)
	for mac, ov := range readIdentOverrides(hncDir) {
		o := get(mac)
		if o == nil {
			continue
		}
		for k, dst := range map[string]*string{"type": &o.typ, "brand": &o.brand, "model": &o.model, "os": &o.os} {
			if v, set := ov[k]; set {
				*dst = asString(v)
			}
		}
		if o.typ == "unknown" {
			o.typ = ""
		}
	}
	// 4) dpid 客户端画像: JA4 集合 + 识别到的应用
	if root := readJSONMap(filepath.Join(hncDir, "run", "dpi_state.json")); root != nil {
		clients, _ := root["clients"].(map[string]interface{})
		for _, raw := range clients {
			c, _ := raw.(map[string]interface{})
			if c == nil {
				continue
			}
			o := get(asString(c["client_mac"]))
			if o == nil {
				continue
			}
			if arr, ok := c["top_ja4"].([]interface{}); ok {
				for _, x := range arr {
					if m, ok := x.(map[string]interface{}); ok {
						if j := strings.TrimSpace(asString(m["ja4"])); j != "" {
							o.ja4 = appendUniq(o.ja4, j)
						}
					}
				}
			}
			if arr, ok := c["top_apps"].([]interface{}); ok {
				for _, x := range arr {
					if m, ok := x.(map[string]interface{}); ok {
						id := strings.TrimSpace(asString(m["id"]))
						if id != "" && appTier(asString(m["category"])) == tierApp {
							o.apps = appendUniq(o.apps, id)
						}
					}
				}
			}
		}
	}
	// 5) 今日按应用真实流量(只算「真应用」档)
	if appDay != nil {
		for _, cells := range appDay.Hours {
			for mk := range cells {
				sep := strings.IndexByte(mk, '|')
				if sep < 0 {
					continue
				}
				id := mk[sep+1:]
				if id == appUnknownID || id == appLocalID {
					continue
				}
				if appTier(appDay.Apps[id].Category) != tierApp {
					continue
				}
				if o := get(mk[:sep]); o != nil {
					o.apps = appendUniq(o.apps, id)
				}
			}
		}
	}
	for _, o := range out {
		sort.Strings(o.ja4)
		sort.Strings(o.apps)
	}
	return out
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// mergeStrSet 把 add 并进 base(去重), 超过 max 时丢掉最早的(base 头部)。
func mergeStrSet(base, add []string, max int) []string {
	for _, v := range add {
		found := false
		for i, x := range base {
			if x == v {
				// 挪到末尾 = 最近见过
				base = append(append(base[:i:i], base[i+1:]...), v)
				found = true
				break
			}
		}
		if !found {
			base = append(base, v)
		}
	}
	if len(base) > max {
		base = append([]string(nil), base[len(base)-max:]...)
	}
	return base
}

// applyObs 把一次观测并入画像(非空信号覆盖旧值; 集合做并集)。
func (p *macProfile) applyObs(o *macObs) {
	if o.lastSeen > p.LastSeen {
		p.LastSeen = o.lastSeen
	}
	if p.FirstSeen == 0 && o.lastSeen > 0 {
		p.FirstSeen = o.lastSeen
	}
	set := func(dst *string, v string) {
		if v = strings.TrimSpace(v); v != "" {
			*dst = v
		}
	}
	set(&p.DHCPName, o.dhcpName)
	set(&p.MDNSName, o.mdnsName)
	set(&p.DHCPFP, o.dhcpFP)
	set(&p.VendorClass, o.vendorClass)
	set(&p.Type, o.typ)
	set(&p.Brand, o.brand)
	set(&p.Model, o.model)
	set(&p.OS, o.os)
	p.JA4 = mergeStrSet(p.JA4, o.ja4, macMergeMaxJA4)
	p.Apps = mergeStrSet(p.Apps, o.apps, macMergeMaxApps)
}

// ─── 打分(纯函数) ───────────────────────────────────────────────────────

// 通用主机名: 同型号/同系统的设备普遍一样, 相同也说明不了是同一台
var genericHostnames = map[string]bool{
	"android": true, "iphone": true, "ipad": true, "localhost": true, "unknown": true,
	"android-device": true, "windows": true, "desktop": true, "laptop": true, "pc": true,
	"macbook": true, "macbook-pro": true, "macbook-air": true, "galaxy": true, "redmi": true,
	"xiaomi": true, "huawei": true, "honor": true, "oppo": true, "vivo": true, "realme": true,
	"oneplus": true, "iphone-2": true, "*": true,
}

func isGenericHostname(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	return h == "" || genericHostnames[h] || len(h) <= 2
}

func jaccard(a, b []string) (float64, []string) {
	if len(a) == 0 || len(b) == 0 {
		return 0, nil
	}
	set := make(map[string]bool, len(a))
	for _, x := range a {
		set[x] = true
	}
	var common []string
	union := len(set)
	for _, x := range b {
		if set[x] {
			common = append(common, x)
		} else {
			union++
		}
	}
	sort.Strings(common)
	return float64(len(common)) / float64(union), common
}

func humanGap(sec int64) string {
	switch {
	case sec < 60:
		return "不到 1 分钟"
	case sec < 3600:
		return fmt.Sprintf("%d 分钟", sec/60)
	case sec < 86400:
		return fmt.Sprintf("%d 小时", sec/3600)
	}
	return fmt.Sprintf("%d 天", sec/86400)
}

// scoreMacPair 给 (新 MAC 画像 np, 旧 MAC 画像 op) 打 0-100 分。ok=false 表示明确
// 不是同一台(同时在线)或身份证据不足。
func scoreMacPair(np, op *macProfile) (score int, reasons []string, ok bool) {
	if np == nil || op == nil {
		return 0, nil, false
	}
	// 同时在线过 → 不可能是同一台设备换了 MAC
	if np.FirstSeen > 0 && op.LastSeen > np.FirstSeen+macMergeOverlapSlop {
		return 0, nil, false
	}
	ident := 0 // 正向身份分(不含时间)
	add := func(n int, why string) {
		score += n
		if n > 0 {
			ident += n
		}
		reasons = append(reasons, why)
	}
	eq := func(a, b string) bool {
		return a != "" && b != "" && strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	diff := func(a, b string) bool {
		return a != "" && b != "" && !strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}

	// 主机名
	nameHit := false
	if eq(np.DHCPName, op.DHCPName) {
		nameHit = true
		if isGenericHostname(np.DHCPName) {
			add(8, "DHCP 主机名相同(通用名「"+np.DHCPName+"」, 参考价值低)")
		} else {
			add(35, "DHCP 主机名相同: "+np.DHCPName)
		}
	}
	if eq(np.MDNSName, op.MDNSName) {
		nameHit = true
		if isGenericHostname(np.MDNSName) {
			add(6, "mDNS 名称相同(通用名「"+np.MDNSName+"」)")
		} else {
			add(25, "mDNS 名称相同: "+np.MDNSName)
		}
	}
	if !nameHit {
		for _, pair := range [][2]string{{np.DHCPName, op.MDNSName}, {np.MDNSName, op.DHCPName}} {
			if eq(pair[0], pair[1]) && !isGenericHostname(pair[0]) {
				add(20, "主机名相同(DHCP/mDNS): "+pair[0])
				break
			}
		}
	}
	// DHCP 指纹
	if eq(np.DHCPFP, op.DHCPFP) {
		add(15, "DHCP 指纹(option 55)相同")
	} else if diff(np.DHCPFP, op.DHCPFP) {
		add(-15, "DHCP 指纹(option 55)不同")
	}
	if eq(np.VendorClass, op.VendorClass) {
		add(10, "DHCP 厂商类(option 60)相同: "+np.VendorClass)
	} else if diff(np.VendorClass, op.VendorClass) {
		add(-10, "DHCP 厂商类(option 60)不同")
	}
	// 设备识别
	if eq(np.Model, op.Model) {
		add(15, "型号相同: "+np.Model)
	} else if diff(np.Model, op.Model) {
		add(-30, "型号不同("+op.Model+" / "+np.Model+")")
	}
	if eq(np.Brand, op.Brand) {
		add(5, "品牌相同: "+np.Brand)
	} else if diff(np.Brand, op.Brand) {
		add(-30, "品牌不同("+op.Brand+" / "+np.Brand+")")
	}
	if eq(np.OS, op.OS) {
		add(3, "系统相同: "+np.OS)
	} else if diff(np.OS, op.OS) {
		add(-25, "系统不同("+op.OS+" / "+np.OS+")")
	}
	if eq(np.Type, op.Type) {
		add(2, "设备类型相同")
	} else if diff(np.Type, op.Type) {
		add(-20, "设备类型不同")
	}
	// TLS 指纹集合
	if len(np.JA4) >= 2 && len(op.JA4) >= 2 {
		j, _ := jaccard(np.JA4, op.JA4)
		if pts := int(math.Round(20 * j)); pts >= 3 {
			add(pts, fmt.Sprintf("TLS 指纹(JA4)重合 %d%%", int(math.Round(j*100))))
		}
	}
	// 常用应用集合
	if len(np.Apps) >= 3 && len(op.Apps) >= 3 {
		j, common := jaccard(np.Apps, op.Apps)
		if pts := int(math.Round(20 * j)); pts >= 3 {
			if len(common) > 4 {
				common = common[:4]
			}
			add(pts, fmt.Sprintf("常用应用重合 %d%%(%s)", int(math.Round(j*100)), strings.Join(common, "、")))
		}
	}
	if ident < macMergeIdentMin {
		return 0, nil, false
	}
	// 时间接近: 旧 MAC 最后出现 → 新 MAC 首次出现
	if np.FirstSeen > 0 && op.LastSeen > 0 {
		gap := np.FirstSeen - op.LastSeen
		if gap < 0 {
			gap = 0
		}
		switch {
		case gap <= 600:
			add(15, "旧 MAC 离线 "+humanGap(gap)+"后新 MAC 出现")
		case gap <= 3600:
			add(10, "旧 MAC 离线 "+humanGap(gap)+"后新 MAC 出现")
		case gap <= 86400:
			add(5, "旧 MAC 离线 "+humanGap(gap)+"后新 MAC 出现")
		}
	}
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score, reasons, true
}

// macMergeCandidates 为新 MAC 在画像里找候选(已按分数降序, 最多 TopN)。
// aliases: 已被合并走的旧 MAC 不再作为候选; dismissed 过滤。
func macMergeCandidates(f *macMergeFile, newMAC string, aliases map[string]string, now int64) []macMergeCand {
	np := f.Profiles[newMAC]
	if np == nil {
		return nil
	}
	var out []macMergeCand
	for mac, op := range f.Profiles {
		if mac == newMAC || isSimMACPrefix(mac) {
			continue
		}
		if _, gone := aliases[mac]; gone {
			continue
		}
		if op.LastSeen == 0 || now-op.LastSeen > macMergeCandMaxAge {
			continue
		}
		if _, d := f.Dismissed[macMergeDismissKey(newMAC, mac)]; d {
			continue
		}
		sc, why, ok := scoreMacPair(np, op)
		if !ok || sc < macMergeMinScore {
			continue
		}
		out = append(out, macMergeCand{OldMAC: mac, Score: sc, Reasons: why, Ts: now})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].OldMAC < out[j].OldMAC
	})
	if len(out) > macMergeTopN {
		out = out[:macMergeTopN]
	}
	return out
}

// ─── 后台循环 ──────────────────────────────────────────────────────────

func (s *server) MacMergeLoop(stop <-chan struct{}) {
	// 启动后稍等, 让 hotspotd/dpid 先把文件刷新一轮
	first := time.NewTimer(10 * time.Second)
	select {
	case <-stop:
		first.Stop()
		return
	case <-first.C:
	}
	// v5.22: 基准 macMergeEvery(30s), 按活动状态放慢(power_sched.go mac_merge)
	for last := time.Now(); ; last = time.Now() {
		s.macMergeTick(last)
		if !powerWait(stop, "mac_merge", last, nil) {
			return
		}
	}
}

// rulesAndNamesMACs 已有用户配置的 MAC(规则/黑名单/命名)及其 rules.json last_seen_persist。
func rulesAndNamesMACs(hncDir string) map[string]int64 {
	out := map[string]int64{}
	if root := readJSONMap(filepath.Join(hncDir, "data", "rules.json")); root != nil {
		devs, _ := root["devices"].(map[string]interface{})
		for mac, raw := range devs {
			d, _ := raw.(map[string]interface{})
			ls, _ := toInt64(d["last_seen_persist"])
			out[strings.ToLower(mac)] = ls
		}
		bl, _ := root["blacklist"].([]interface{})
		for _, v := range bl {
			m := strings.ToLower(asString(v))
			if _, ok := out[m]; !ok {
				out[m] = 0
			}
		}
	}
	if names, err := loadDeviceNames(filepath.Join(hncDir, deviceNamesRelPath)); err == nil {
		for mac := range names {
			m := strings.ToLower(mac)
			if _, ok := out[m]; !ok {
				out[m] = 0
			}
		}
	}
	return out
}

// macMergeTick 一轮: 观测 → 更新画像 → 为新随机 MAC 重算建议 → 告警。
func (s *server) macMergeTick(now time.Time) {
	if !clockSane(s.hncDir, now) {
		return // 时钟不可信: 时间接近信号与画像时间戳都会错
	}
	appUsage.mu.Lock()
	var day *appUsageDay
	if appUsage.day != nil {
		// 只读 Hours 的键与 Apps 元数据: 浅拷贝足够(持锁期间拷贝)
		day = &appUsageDay{Hours: map[string]map[string][2]uint64{}, Apps: map[string]appUsageMeta{}}
		for h, cells := range appUsage.day.Hours {
			cp := make(map[string][2]uint64, len(cells))
			for k, v := range cells {
				cp[k] = v
			}
			day.Hours[h] = cp
		}
		for k, v := range appUsage.day.Apps {
			day.Apps[k] = v
		}
	}
	appUsage.mu.Unlock()
	obs := collectMacObs(s.hncDir, day)
	s.macMergeStep(now, obs)
}

// macMergeStep 纯状态推进(测试直接调)。
func (s *server) macMergeStep(now time.Time, obs map[string]*macObs) {
	nowU := now.Unix()
	aliases := loadMACAliases(s.hncDir)
	macMergeMu.Lock()
	defer macMergeMu.Unlock()
	f := loadMacMergeFile(s.hncDir)
	before, _ := json.Marshal(f)

	if !f.Bootstrapped {
		// 首轮: 现有设备全部登记为已知, 不产生建议
		for mac, o := range obs {
			p := &macProfile{FirstSeen: o.lastSeen}
			if p.FirstSeen == 0 {
				p.FirstSeen = nowU
			}
			p.applyObs(o)
			if p.LastSeen == 0 {
				p.LastSeen = p.FirstSeen
			}
			f.Profiles[mac] = p
		}
		for mac, ls := range rulesAndNamesMACs(s.hncDir) {
			if isSimMACPrefix(mac) || !validMAC(mac) || f.Profiles[mac] != nil {
				continue
			}
			f.Profiles[mac] = &macProfile{FirstSeen: ls, LastSeen: ls}
		}
		f.Bootstrapped = true
	} else {
		for mac, o := range obs {
			p := f.Profiles[mac]
			if p == nil {
				if !o.inDevices && nowU-o.lastSeen > 600 {
					// 只在 dpid 历史里出现过(且不是最近 10 分钟): 记为已知, 不是"新出现"。
					// (dpid 可能比 hotspotd 先看到新 MAC 的 DHCP, 最近见过的仍按新设备处理)
					p = &macProfile{FirstSeen: o.lastSeen}
				} else {
					p = &macProfile{FirstSeen: nowU, New: true}
					if o.lastSeen > 0 && o.lastSeen < nowU {
						p.FirstSeen = o.lastSeen
					}
				}
				f.Profiles[mac] = p
			}
			p.applyObs(o)
		}
	}

	// 为新出现的随机 MAC 重算建议(出现后 24h 内; 已被合并走的不算)
	for mac, p := range f.Profiles {
		if !p.New || !isRandomizedMAC(mac) {
			continue
		}
		if _, gone := aliases[mac]; gone {
			delete(f.Suggestions, mac)
			continue
		}
		if nowU-p.FirstSeen > macMergeNewWindow {
			continue // 窗口已过: 保留已有建议, 不再重算
		}
		if c := macMergeCandidates(f, mac, aliases, nowU); len(c) > 0 {
			f.Suggestions[mac] = c
		} else {
			delete(f.Suggestions, mac)
		}
	}
	// 告警: 每个新 MAC 一次
	var toAlert []string
	for mac, cs := range f.Suggestions {
		if len(cs) == 0 || cs[0].Score < macMergeAlertScore {
			continue
		}
		if _, sent := f.Alerted[mac]; sent {
			continue
		}
		f.Alerted[mac] = nowU
		toAlert = append(toAlert, mac)
	}
	s.macMergePruneLocked(f, nowU, aliases)

	after, _ := json.Marshal(f)
	if string(before) != string(after) {
		if err := saveMacMergeFile(s.hncDir, f); err != nil {
			return
		}
	}
	if len(toAlert) > 0 {
		s.macMergeAlert(f, toAlert, now)
	}
}

// macMergePruneLocked 淘汰过期画像/建议/忽略记录, 画像数封顶。
func (s *server) macMergePruneLocked(f *macMergeFile, now int64, aliases map[string]string) {
	for mac, p := range f.Profiles {
		if p.LastSeen > 0 && now-p.LastSeen > macMergeProfileTTL {
			delete(f.Profiles, mac)
		}
	}
	if len(f.Profiles) > macMergeMaxProfiles {
		type kv struct {
			mac string
			ls  int64
		}
		all := make([]kv, 0, len(f.Profiles))
		for m, p := range f.Profiles {
			all = append(all, kv{m, p.LastSeen})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].ls < all[j].ls })
		for _, x := range all[:len(all)-macMergeMaxProfiles] {
			delete(f.Profiles, x.mac)
		}
	}
	for mac, cs := range f.Suggestions {
		if f.Profiles[mac] == nil {
			delete(f.Suggestions, mac)
			continue
		}
		kept := cs[:0]
		for _, c := range cs {
			if _, gone := aliases[c.OldMAC]; gone {
				continue
			}
			if _, d := f.Dismissed[macMergeDismissKey(mac, c.OldMAC)]; d {
				continue
			}
			kept = append(kept, c)
		}
		if len(kept) == 0 {
			delete(f.Suggestions, mac)
		} else {
			f.Suggestions[mac] = kept
		}
	}
	for k, ts := range f.Dismissed {
		if now-ts > macMergeDismissTTL {
			delete(f.Dismissed, k)
		}
	}
	for k, ts := range f.Alerted {
		if f.Profiles[k] == nil && now-ts > macMergeNewWindow {
			delete(f.Alerted, k)
		}
	}
}

// macDisplayName 手动名 > 画像里的 DHCP / mDNS 名 > ""
func macDisplayName(names map[string]string, f *macMergeFile, mac string) string {
	if n := names[mac]; n != "" {
		return n
	}
	if f != nil {
		if p := f.Profiles[mac]; p != nil {
			if p.DHCPName != "" {
				return p.DHCPName
			}
			return p.MDNSName
		}
	}
	return ""
}

func (s *server) macMergeAlert(f *macMergeFile, macs []string, now time.Time) {
	cfg := alert.NewConfig(s.hncDir)
	if !alert.LoadConfig(cfg.AlertsConfigPath).Enabled {
		return
	}
	names, _ := loadDeviceNames(filepath.Join(s.hncDir, deviceNamesRelPath))
	for _, mac := range macs {
		best := f.Suggestions[mac][0]
		newName, oldName := macDisplayName(names, f, mac), macDisplayName(names, f, best.OldMAC)
		if newName == "" {
			newName = mac
		}
		if oldName == "" {
			oldName = best.OldMAC
		}
		a := alert.Alert{
			ID:     macMergeAlertKind + "_" + strings.ReplaceAll(mac, ":", ""),
			Ts:     now.Unix(),
			Kind:   macMergeAlertKind,
			MAC:    mac,
			Detail: "新设备「" + newName + "」使用随机 MAC, 疑似是「" + oldName + "」(可信度 " + strconv.Itoa(best.Score) + "), 可合并以沿用名称与规则",
			Extra: map[string]interface{}{"old_mac": best.OldMAC, "score": best.Score, "reasons": best.Reasons,
				"new_name": newName, "old_name": oldName},
		}
		_ = alert.Append(cfg.AlertsJSONLPath, a)
	}
}

// ─── API ───────────────────────────────────────────────────────────────

func (s *server) apiMacMerge(w http.ResponseWriter, r *http.Request) {
	aliases := loadMACAliases(s.hncDir)
	macMergeMu.Lock()
	f := loadMacMergeFile(s.hncDir)
	macMergeMu.Unlock()
	names, _ := loadDeviceNames(filepath.Join(s.hncDir, deviceNamesRelPath))
	online := map[string]bool{}
	for mac, raw := range readJSONMap(filepath.Join(s.hncDir, "data", "devices.json")) {
		if d, _ := raw.(map[string]interface{}); d != nil && asString(d["ip"]) != "" {
			online[strings.ToLower(mac)] = true
		}
	}
	list := make([]map[string]interface{}, 0)
	newMACs := make([]string, 0, len(f.Suggestions))
	for m := range f.Suggestions {
		newMACs = append(newMACs, m)
	}
	sort.Strings(newMACs)
	for _, nm := range newMACs {
		if _, gone := aliases[nm]; gone {
			continue
		}
		np := f.Profiles[nm]
		for _, c := range f.Suggestions[nm] {
			if _, gone := aliases[c.OldMAC]; gone {
				continue
			}
			if _, d := f.Dismissed[macMergeDismissKey(nm, c.OldMAC)]; d {
				continue
			}
			it := map[string]interface{}{
				"new_mac": nm, "old_mac": c.OldMAC, "score": c.Score, "reasons": c.Reasons,
				"new_name": macDisplayName(names, f, nm), "old_name": macDisplayName(names, f, c.OldMAC),
				"old_last_seen": int64(0), "new_first_seen": int64(0),
				"new_online": online[nm], "randomized": isRandomizedMAC(nm),
				"old_randomized": isRandomizedMAC(c.OldMAC),
			}
			if op := f.Profiles[c.OldMAC]; op != nil {
				it["old_last_seen"] = op.LastSeen
			}
			if np != nil {
				it["new_first_seen"] = np.FirstSeen
			}
			list = append(list, it)
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i]["score"].(int) > list[j]["score"].(int) })
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "suggestions": list, "aliases": aliases,
		"min_score": macMergeMinScore, "alert_score": macMergeAlertScore,
	})
}

// annotateMacMerge 给 /api/devices 行加 randomized_mac / merge_suggestion / merged_into。
// 读 jsonCache(mtime 缓存), 高频轮询零解析开销。
func (s *server) annotateMacMerge(rows []map[string]interface{}, names map[string]interface{}) {
	aliases := loadMACAliases(s.hncDir)
	var sugg map[string]interface{}
	var profiles map[string]interface{}
	if raw, err := s.jsonCache.read(macMergePath(s.hncDir)); err == nil {
		if root, ok := raw.(map[string]interface{}); ok {
			sugg, _ = root["suggestions"].(map[string]interface{})
			profiles, _ = root["profiles"].(map[string]interface{})
		}
	}
	nameOf := func(mac string) string {
		if n := asString(names[mac]); n != "" {
			return n
		}
		if p, ok := profiles[mac].(map[string]interface{}); ok {
			if n := asString(p["dhcp_name"]); n != "" {
				return n
			}
			return asString(p["mdns_name"])
		}
		return ""
	}
	for _, d := range rows {
		mac := strings.ToLower(asString(d["mac"]))
		if b, _ := d["sim"].(bool); b {
			d["randomized_mac"] = false
			continue
		}
		d["randomized_mac"] = isRandomizedMAC(mac)
		if to, ok := aliases[mac]; ok {
			d["merged_into"] = resolveMACAlias(aliases, to)
			continue
		}
		cs, _ := sugg[mac].([]interface{})
		for _, c := range cs {
			cm, _ := c.(map[string]interface{})
			if cm == nil {
				continue
			}
			old := asString(cm["old_mac"])
			if _, gone := aliases[old]; gone || old == "" {
				continue
			}
			best := map[string]interface{}{
				"old_mac": old, "score": cm["score"], "reasons": cm["reasons"], "old_name": nameOf(old),
			}
			if p, ok := profiles[old].(map[string]interface{}); ok {
				best["old_last_seen"] = p["last_seen"]
			}
			d["merge_suggestion"] = best
			break
		}
	}
}
