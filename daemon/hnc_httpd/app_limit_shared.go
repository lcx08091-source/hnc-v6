// app_limit_shared.go — v5.20 应用限速 vs 共享 CDN IP
//
// 应用限速按"目的 IP"分类: apply_app_limits.sh 把 run/ip_app_map.flat 里归到
// 该应用的 IP 全部打上 mark。ip_app_map 是"后写者胜", 一个 CDN IP 往往同时服务
// 多个 App —— 把这种 IP 也算进 A 的限速, B 会被一起限速。
//
// 共享判据(与 bin/apply_app_limits.sh 的 split_app_ips 同一套规则, 两边同步改):
//
//	dpid 的 IP→域名反查表 run/dpi_ipname.json 对该 IP 归出的 app 非空且 ≠ 本应用
//	→ 该 IP 至少被 2 个不同应用使用(ip_app_map 一个 + 反查表一个), 视为共享。
//	规则库里 category=cdn/cloud 的条目(Akamai / Cloudflare / 阿里云 / 腾讯云 …)
//	本身就是独立"应用", 反查到它们的 IP 同样命中该判据。
//
// 逃生口: rules.json 顶层 "app_limit_include_shared_ips": true → 不过滤(v5.19 行为)。
// 统计: GET /api/app_limits 每条限速带 {ips_total, ips_shared_skipped, ips_limited}。
package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

const (
	appLimitIncludeSharedKey = "app_limit_include_shared_ips"
	ipAppMapFlatRelPath      = "run/ip_app_map.flat"
)

// appLimitIncludeShared 读 rules.json 顶层逃生口(缺省 false = 跳过共享 IP)。
func appLimitIncludeShared(hncDir string) bool {
	b, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json"))
	if err != nil {
		return false
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	switch v := m[appLimitIncludeSharedKey].(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "on":
			return true
		}
	case float64:
		return v == 1
	}
	return false
}

// loadIPAppFlat 读 dpid 写的 run/ip_app_map.flat("<ip> <app_id>" 每行一条),
// 返回 app_id → IP 列表(去重, 保持文件顺序)。与 shell 读的是同一个文件。
func loadIPAppFlat(hncDir string) map[string][]string {
	out := map[string][]string{}
	f, err := os.Open(filepath.Join(hncDir, ipAppMapFlatRelPath))
	if err != nil {
		return out
	}
	defer f.Close()
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 2 || strings.HasPrefix(fs[0], "#") {
			continue
		}
		k := fs[1] + " " + fs[0]
		if seen[k] {
			continue
		}
		seen[k] = true
		out[fs[1]] = append(out[fs[1]], fs[0])
	}
	return out
}

// ipNameAppMap 把反查表压成 ip → app(只保留归到应用的条目)。
func ipNameAppMap(names map[string]ipName) map[string]string {
	out := make(map[string]string, len(names))
	for ip, n := range names {
		if n.App != "" {
			out[ip] = n.App
		}
	}
	return out
}

// appLimitSplitShared 把 app 的候选 IP 分成 kept(会被限速)与 shared(跳过)。
// includeShared=true 时全部 kept。
func appLimitSplitShared(appID string, ips []string, nameApp map[string]string, includeShared bool) (kept, shared []string) {
	for _, ip := range ips {
		if !includeShared {
			if other := nameApp[ip]; other != "" && other != appID {
				shared = append(shared, ip)
				continue
			}
		}
		kept = append(kept, ip)
	}
	return kept, shared
}

// appLimitView 是 /api/app_limits 的条目: 原配置 + v5.20 IP 统计。
type appLimitView struct {
	AppLimitItem
	IPsTotal         int    `json:"ips_total"`
	IPsSharedSkipped int    `json:"ips_shared_skipped"`
	IPsLimited       int    `json:"ips_limited"`
	IPStatsSource    string `json:"ip_stats_source"` // computed | sim
}

// appLimitViews 给每条限速算 IP 统计。items 中下标 >= realN 的是模拟环境条目(不统计)。
func appLimitViews(items []AppLimitItem, realN int, appIPs map[string][]string, nameApp map[string]string, includeShared bool) []appLimitView {
	out := make([]appLimitView, 0, len(items))
	for i, it := range items {
		v := appLimitView{AppLimitItem: it, IPStatsSource: "computed"}
		if i >= realN {
			v.IPStatsSource = "sim"
			out = append(out, v)
			continue
		}
		ips := appIPs[it.AppID]
		kept, shared := appLimitSplitShared(it.AppID, ips, nameApp, includeShared)
		v.IPsTotal = len(ips)
		v.IPsSharedSkipped = len(shared)
		v.IPsLimited = len(kept)
		out = append(out, v)
	}
	return out
}

// actionAppLimitSharedIPsSet · 逃生口开关
//
//	enabled  true = 共享 CDN IP 也纳入应用限速(旧行为, 可能误伤其他应用)
func actionAppLimitSharedIPsSet(hncDir string, p map[string]string) actionResp {
	enabled, ok := parseEnabledParam(p)
	if !ok {
		return actionResp{OK: false, Error: "bad params", Detail: "enabled must be true/false"}
	}
	val := "false"
	if enabled {
		val = "true"
	}
	if rc, out := runBin(hncDir, "json_set.sh", "top", appLimitIncludeSharedKey, val); rc != 0 {
		return actionResp{OK: false, Error: "rules.json write failed", Detail: strings.TrimSpace(out)}
	}
	triggerAppLimitApply(hncDir)
	return actionResp{OK: true, Detail: appLimitIncludeSharedKey + "=" + val}
}
