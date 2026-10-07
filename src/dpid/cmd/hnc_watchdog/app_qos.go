// app_qos.go — v5.30 T4: 应用感知 QoS 初版的「计划」(默认关, 逐台开)。
//
// 每 30 秒(随 appLimitApplyLoop, 改设置后 dirty 标记即时)读:
//   - data/rules.json  devices[mac].app_qos(缺省 = 关)与 mark_id;
//   - data/devices.json 设备当前 IP;
//   - run/ip_app_map.json dpid 已有的识别结果(IP → 应用 / 类别; 只读, 不改识别)。
//
// 生成 run/app_qos.plan 交给 bin/apply_app_qos.sh 下发(结构、mark 位分配见该脚本头)。
//
// 关闭(没有设备开, 也没有 run/app_qos.state 残留)时不写计划、不起脚本 ——
// tc / iptables 一条命令都不多(与 v5.29 一致)。
//
// 类别 → 档位(appQosTier, 纯函数):
//
//	实时 1: game*、*voip*、call(通话 / 游戏)
//	后台 3: download、cloud、p2p*、system / system-* / system_*(系统更新)、
//	        *telemetry*、ads、ad-sdk、sdk*(游戏 SDK 除外)
//	交互 2: 其余(视频、浏览、社交、购物 …)以及认不出的 —— 交互档是默认档,
//	        计划里不列(apply 脚本的兜底过滤器把没打档位的包送进交互档)。
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	qosTierRealtime    = 1
	qosTierInteractive = 2
	qosTierBackground  = 3

	appQosMaxIPs = 1000 // 计划里 IP 行上限(ip_app_map 本身封顶 2000)
)

var (
	appQosRunDir, appQosDataDir, appQosBinDir = runDir, dataDir, binDir
)

// appQosTier 识别类别 → 档位。
func appQosTier(category string) int {
	c := strings.ToLower(strings.TrimSpace(category))
	switch {
	case c == "":
		return qosTierInteractive
	case strings.HasPrefix(c, "game"), strings.Contains(c, "voip"), c == "call", strings.HasPrefix(c, "sdk-tencent-game"):
		return qosTierRealtime
	case c == "download", c == "cloud", c == "update", strings.HasPrefix(c, "p2p"),
		c == "system", strings.HasPrefix(c, "system-"), strings.HasPrefix(c, "system_"),
		strings.Contains(c, "telemetry"), c == "ads", c == "ad-sdk", strings.HasPrefix(c, "sdk"):
		return qosTierBackground
	}
	return qosTierInteractive
}

// boolish rules.json 里的布尔可能是 true / "true"。
func boolish(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "true" || s == "1" || s == "on"
	case float64:
		return x != 0
	}
	return false
}

func intish(v interface{}) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	}
	return 0
}

// buildAppQosPlan 纯函数: 三份输入 → 计划文本与开着的设备数。
// 设备: app_qos 为真且 mark_id 在 1..99; IP 取 devices.json(没有就不写, 脚本
// 只建 tc 不加 iptables 选择)。IP 行: 只列实时 / 后台档的 IPv4, 去重排序。
func buildAppQosPlan(rules, devices, ipmap []byte, iface string) (string, int) {
	if iface == "" {
		return "", 0
	}
	var r struct {
		Devices map[string]map[string]interface{} `json:"devices"`
	}
	if json.Unmarshal(rules, &r) != nil {
		return "", 0
	}
	var devs map[string]map[string]interface{}
	_ = json.Unmarshal(devices, &devs)
	devIP := map[string]string{}
	for mac, d := range devs {
		if ip, _ := d["ip"].(string); net.ParseIP(ip).To4() != nil {
			devIP[strings.ToLower(mac)] = ip
		}
	}
	type dl struct {
		mid     int
		mac, ip string
	}
	var ds []dl
	seenMid := map[int]bool{}
	for mac, d := range r.Devices {
		if !boolish(d["app_qos"]) {
			continue
		}
		mid := intish(d["mark_id"])
		if mid < 1 || mid > 99 || seenMid[mid] {
			continue
		}
		seenMid[mid] = true
		m := strings.ToLower(mac)
		ds = append(ds, dl{mid, m, devIP[m]})
	}
	if len(ds) == 0 {
		return "", 0
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].mid < ds[j].mid })
	var b strings.Builder
	fmt.Fprintf(&b, "iface %s\n", iface)
	for _, d := range ds {
		if d.ip != "" {
			fmt.Fprintf(&b, "dev %d %s %s\n", d.mid, d.mac, d.ip)
		} else {
			fmt.Fprintf(&b, "dev %d %s\n", d.mid, d.mac)
		}
	}
	var m struct {
		Entries []struct {
			IP       string `json:"ip"`
			Category string `json:"category"`
		} `json:"entries"`
	}
	_ = json.Unmarshal(ipmap, &m)
	tierOf := map[string]int{}
	for _, e := range m.Entries {
		if net.ParseIP(e.IP).To4() == nil {
			continue
		}
		if t := appQosTier(e.Category); t != qosTierInteractive {
			tierOf[e.IP] = t
		}
	}
	ips := make([]string, 0, len(tierOf))
	for ip := range tierOf {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	if len(ips) > appQosMaxIPs {
		ips = ips[:appQosMaxIPs]
	}
	for _, ip := range ips {
		fmt.Fprintf(&b, "ip %d %s\n", tierOf[ip], ip)
	}
	return b.String(), len(ds)
}

// appQosTick appLimitApplyLoop 每轮调: 关闭 → 什么都不做; 有设备开(或有残留
// 状态要拆)→ 写计划、起 apply_app_qos.sh。
func appQosTick(iface string) {
	rules, _ := os.ReadFile(filepath.Join(appQosDataDir, "rules.json"))
	devs, _ := os.ReadFile(filepath.Join(appQosDataDir, "devices.json"))
	ipmap, _ := os.ReadFile(filepath.Join(appQosRunDir, "ip_app_map.json"))
	plan, n := buildAppQosPlan(rules, devs, ipmap, iface)
	planPath := filepath.Join(appQosRunDir, "app_qos.plan")
	if n == 0 {
		if _, err := os.Stat(filepath.Join(appQosRunDir, "app_qos.state")); err != nil {
			_ = os.Remove(planPath)
			return
		}
	}
	tmp := planPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(plan), 0o644); err != nil || os.Rename(tmp, planPath) != nil {
		return
	}
	runScriptFn(filepath.Join(appQosBinDir, "apply_app_qos.sh"))
}
