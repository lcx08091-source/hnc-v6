// hostname_junk.go — v5.30 T1b: 垃圾主机名当作「没有名字」。
//
// hotspotd / dpid 已在源头挡掉, 这里挡存量: 升级前已经写进 devices.json /
// dpi_devid.json 的 "null"。名单与判定在 hnc.io/dpid/hostname(Go 侧唯一权威)。
// 用户手动命名(hostname_src == "manual")不过滤。
package main

import "hnc.io/dpid/hostname"

// isJunkHostname = hostname.IsJunk(本包里的短名)。
func isJunkHostname(s string) bool { return hostname.IsJunk(s) }

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
