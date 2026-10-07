// hostname_junk.go — v5.30 T1b: 垃圾主机名当作「没有名字」。
//
// 有些设备的 DHCP option 12 / mDNS 上报的就是字符串 "null" 之类, 以前全链路
// 没人过滤 → WebUI 显示设备名 "null"。hotspotd / dpid 已在源头挡掉, 这里挡
// 存量: 升级前已经写进 devices.json / dpi_devid.json 的 "null"。
// 与 hotspotd hnc_hostname_is_junk、dpid capture.IsJunkHostname、前端 isJunkName
// 同一张表(test/unit/test_v530_junk_table_sync.sh 核对四处一致)。
// 用户手动命名(hostname_src == "manual")不过滤。
package main

import "strings"

// junkHostnames 去首尾空白、转小写后命中即垃圾。
var junkHostnames = map[string]bool{
	"null": true, "(null)": true, "nil": true, "none": true, "(none)": true,
	"undefined": true, "unknown": true, "localhost": true,
	"localhost.localdomain": true, "*": true, "-": true,
}

// isJunkHostname 空串 / 纯空白 / 纯数字 / 名单里的(大小写不敏感)→ true。
func isJunkHostname(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	digits := true
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			digits = false
			break
		}
	}
	return digits || junkHostnames[strings.ToLower(s)]
}

// dropJunkHostname 设备对象里非手动的垃圾主机名删掉(连同来源), 返回是否删了。
func dropJunkHostname(dev map[string]interface{}) bool {
	if asString(dev["hostname_src"]) == "manual" {
		return false
	}
	if _, ok := dev["hostname"]; !ok || !isJunkHostname(asString(dev["hostname"])) {
		return false
	}
	delete(dev, "hostname")
	delete(dev, "hostname_src")
	return true
}
