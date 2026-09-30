package main

import (
	"os"
	"regexp"
	"testing"
)

// shell 与 Go 的接口名模式必须逐字一致(单一来源, 两边各持一份拷贝, 由本测试锁死)
func TestIfacePatternsMatchShell(t *testing.T) {
	b, err := os.ReadFile("../../bin/hnc_iface.sh")
	if err != nil {
		t.Skipf("bin/hnc_iface.sh not reachable: %v", err)
	}
	want := map[string]string{
		"HNC_CELL_IFACE_ERE":     hncCellIfaceERE,
		"HNC_AP_IFACE_ERE":       hncAPIfaceERE,
		"HNC_AP_MAYBE_IFACE_ERE": hncAPMaybeIfaceERE,
		"HNC_USB_TETHER_ERE":     hncUSBTetherERE,
		"HNC_BT_TETHER_ERE":      hncBTTetherERE,
		"HNC_VPN_IFACE_ERE":      hncVPNIfaceERE,
	}
	for name, goVal := range want {
		re := regexp.MustCompile(`(?m)^` + name + `='([^']*)'$`)
		m := re.FindSubmatch(b)
		if m == nil {
			t.Errorf("%s not found in bin/hnc_iface.sh", name)
			continue
		}
		if string(m[1]) != goVal {
			t.Errorf("%s drift:\n shell=%s\n go   =%s", name, m[1], goVal)
		}
	}
}

func TestIfacePatternClassification(t *testing.T) {
	cell := []string{"rmnet_data0", "rmnet_data11", "rmnet0", "rmnet7", "ccmni0", "ccmni2",
		"seth_lte0", "seth_w0", "sipa_eth0", "wwan0"}
	notCell := []string{"v4-rmnet_data0", "r_rmnet_data0", "rmnet_ipa0", "rmnet_mhi0", "rmnet_usb0",
		"wlan0", "wlan2", "ap0", "rndis0", "ifb0", "dummy0", "ccmni", "rmnet_data"}
	for _, n := range cell {
		if !isCellIface(n) {
			t.Errorf("%s should be cell", n)
		}
	}
	for _, n := range notCell {
		if isCellIface(n) {
			t.Errorf("%s should NOT be cell", n)
		}
	}
	ap := []string{"ap0", "ap1", "ap", "ap_br_wlan2", "softap0", "swlan0"}
	notAP := []string{"wlan0", "wlan1", "apple0", "rmnet0", "ap0x"}
	for _, n := range ap {
		if !isAPIfaceName(n) {
			t.Errorf("%s should be AP name", n)
		}
	}
	for _, n := range notAP {
		if isAPIfaceName(n) {
			t.Errorf("%s should NOT be AP name", n)
		}
	}
	if !hncUSBTetherRE.MatchString("rndis0") || !hncUSBTetherRE.MatchString("ncm0") || !hncBTTetherRE.MatchString("bt-pan") {
		t.Error("usb/bt tether patterns")
	}
	// phone_usage 分类: 新增的 SoC 名字归蜂窝, 热点口未知时 ap_br_* 按热点兜底
	cases := []struct{ name, hs, want string }{
		{"sipa_eth0", "wlan2", "cell"},
		{"seth_w0", "wlan2", "cell"},
		{"rmnet3", "", "cell"},
		{"ap_br_wlan2", "", "hotspot"},
		{"rmnet_usb0", "wlan2", ""},
	}
	for _, c := range cases {
		if got := puClassifyIface(c.name, c.hs); got != c.want {
			t.Errorf("puClassifyIface(%q,%q)=%q want %q", c.name, c.hs, got, c.want)
		}
	}
}
