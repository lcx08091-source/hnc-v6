// iface_patterns.go — 接口名分类表(v5.20), 与 shell 侧 bin/hnc_iface.sh 共用同一份。
//
// 这些字符串必须与 bin/hnc_iface.sh 里同名 HNC_*_ERE 变量逐字相同(POSIX ERE 写法,
// RE2 同样可用: 只用 [0-9] / [a-z] / 分组 / 交替, 不用 \d)。iface_patterns_test.go
// 直接解析 ../../bin/hnc_iface.sh 做比对 —— 只改一边, go test 就会失败。
//
// 蜂窝上游(跨 SoC): 高通 rmnet_dataN、三星 Exynos / Google Tensor rmnetN、联发科 ccmniN、
// 展锐 seth_lteN / sipa_ethN(老三星展锐 seth_wN 等)、通用 wwanN。
// 不计: v4-*(clat)、r_rmnet*(反向)、rmnet_ipa/mhi/usb*(高通物理聚合口)。
package main

import "regexp"

const (
	hncCellIfaceERE    = `^(rmnet_data[0-9]+|rmnet[0-9]+|ccmni[0-9]+|seth_[a-z]+[0-9]+|sipa_eth[0-9]+|wwan[0-9]+)$`
	hncAPIfaceERE      = `^(ap[0-9]*|ap_br_[a-z0-9_]+|softap[0-9]+|swlan[0-9]+)$`
	hncAPMaybeIfaceERE = `^(wlan[1-9][0-9]*|wigig[0-9]+)$`
	hncUSBTetherERE    = `^(rndis[0-9]+|usb[0-9]+|ncm[0-9]+)$`
	hncBTTetherERE     = `^bt-pan[0-9]*$`
	// v5.20.1: VPN 虚拟口 —— 可能是本机出口(root 在 VPN uid 范围内), 但永远不是热点上游
	hncVPNIfaceERE = `^(tun[0-9]+|tap[0-9]+|ppp[0-9]+|wg[0-9]+|ipsec[0-9a-z_]*|xfrm[0-9]+)$`
)

var (
	hncCellIfaceRE    = regexp.MustCompile(hncCellIfaceERE)
	hncAPIfaceRE      = regexp.MustCompile(hncAPIfaceERE)
	hncAPMaybeIfaceRE = regexp.MustCompile(hncAPMaybeIfaceERE)
	hncUSBTetherRE    = regexp.MustCompile(hncUSBTetherERE)
	hncBTTetherRE     = regexp.MustCompile(hncBTTetherERE)
	hncVPNIfaceRE     = regexp.MustCompile(hncVPNIfaceERE)
)

// isVPNIface VPN 虚拟口(tun/tap/ppp/wg/ipsec/xfrm)
func isVPNIface(name string) bool { return hncVPNIfaceRE.MatchString(name) }

// isCellIface 蜂窝上游口(跨 SoC)
func isCellIface(name string) bool { return hncCellIfaceRE.MatchString(name) }

// isAPIfaceName 名字明确是 AP 的接口(ap0 / ap_br_* / swlan0 / softap0)
func isAPIfaceName(name string) bool { return hncAPIfaceRE.MatchString(name) }
