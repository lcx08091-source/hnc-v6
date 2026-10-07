// Package hostname — v5.30 T1b: 垃圾主机名当作「没有名字」(Go 侧唯一权威)。
//
// 有些设备的 DHCP option 12 / mDNS 上报的就是字符串 "null" 之类, 以前全链路
// 没人过滤 → WebUI 显示设备名 "null"。dpid(capture.cleanHostname)与 httpd
// (/api/devices 挡存量)都用这里; hotspotd(C, hnc_hostname_is_junk)与前端
// (isJunkName)各有一份同表, test/unit/test_v530_junk_table_sync.sh 核对一致。
package hostname

import "strings"

// junk 去首尾空白、转小写后命中即垃圾。
var junk = map[string]bool{
	"null": true, "(null)": true, "nil": true, "none": true, "(none)": true,
	"undefined": true, "unknown": true, "localhost": true,
	"localhost.localdomain": true, "*": true, "-": true,
}

// IsJunk 空串 / 纯空白 / 纯数字 / 名单里的(大小写不敏感)→ true。
func IsJunk(s string) bool {
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
	return digits || junk[strings.ToLower(s)]
}
