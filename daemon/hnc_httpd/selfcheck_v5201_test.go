package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// v5.20.1 真机自检(RMX5010 / ColorOS 16.1 / SukiSU ksud "KernelSU ksud 4.2.0-rc1 (uapi: 2)" / 开着 VPN / 开机 3 分钟)
func fixtureRMX5010VPN(hnc string) *fakeSys {
	f := fixtureColorOSQualcomm(hnc)
	// root: 版本串不含 suki, 只有 SuSFS
	f.cmds["/data/adb/ksud -V"] = "KernelSU ksud 4.2.0-rc1 (uapi: 2)\n"
	// VPN: 本机出口 tun0, 共享上游 rmnet_data3
	f.cmds["ip route get 1.1.1.1"] = "1.1.1.1 dev tun0 table 1045 src 172.19.0.1 uid 0 \n    cache \n"
	f.cmds["dumpsys tethering"] = "Tethering:\n  Tether state:\n    wlan2 - TetheredState - lastError = 0\n" +
		"  Upstream wanted: true\n  Current upstream interface(s): [rmnet_data3, v4-rmnet_data3]\n"
	// 开机 3 分钟: dpid 启动 2 分钟, 还没有映射文件
	f.files["/proc/uptime"] = "180.50 900.00\n"
	f.seq["/proc/5151/stat"] = []string{procStat(5151, "hnc_dpid", 100, 20), procStat(5151, "hnc_dpid", 102, 21)}
	delete(f.files, f.h("run", "dpi_ipname.json"))
	f.files[f.h("run", "dpi_state.json")] = fmt.Sprintf(`{"generated_at":%d,"mode":"af_packet","interface":"wlan2","stats":{"dns_events":0,"tls_events":0}}`, f.now.Unix())
	// 旧版探针写坏的 capabilities.json(真机根因: "0\n0")
	f.files[f.h("run", "capabilities.json")] = "{\n  \"schema\": 2,\n  \"selinux_avc_denied_recent\": 0\n0,\n  \"tc_htb\": true\n}\n"
	return f
}

func TestSelfcheckV5201RealDevice(t *testing.T) {
	f := fixtureRMX5010VPN("/data/local/hnc")
	r := runSelfcheck(f.scEnv(), scOptions{})

	// 1. 损坏的 capabilities.json: 报"存在但不是合法 JSON"(无 capability_probe.sh → 不重探)
	cp := expectStatus(t, r, "shaping", "cap_probe", scFail)
	mustContain(t, "cap corrupt", cp.Detail, "存在但不是合法 JSON")

	// 2. VPN: 热点上游与本机出口分开
	u := expectStatus(t, r, "network", "upstream", scOK)
	if u.Value != "热点上游 rmnet_data3(蜂窝) · 本机走 VPN tun0" {
		t.Errorf("upstream=%q", u.Value)
	}
	mustContain(t, "vpn detail", u.Detail, "VPN")

	// 3. root: 只有弱证据
	root := expectStatus(t, r, "system", "root", scOK)
	if root.Value != "KernelSU 系(可能为 SukiSU)" {
		t.Errorf("root=%q", root.Value)
	}
	mustContain(t, "evidence", root.Detail, "susfs")
	mustContain(t, "evidence", root.Detail, "ksud_major_ge3")
	expectStatus(t, r, "system", "webui_entry", scOK)

	// 4. dpid 刚启动, 没有映射文件
	n := expectStatus(t, r, "ident", "ipname_entries", scInfo)
	if n.Value != "暂无(还没有设备产生 DNS/TLS 流量)" {
		t.Errorf("ipname=%q", n.Value)
	}
	mustContain(t, "ipname detail", n.Detail, "dpid 已运行")
}

func TestSelfcheckRootSukiSUManager(t *testing.T) {
	f := fixtureRMX5010VPN("/data/local/hnc")
	f.exists["/data/data/com.sukisu.ultra"] = true
	r := runSelfcheck(f.scEnv(), scOptions{})
	if v := findItem(t, r, "system", "root").Value; v != "SukiSU" {
		t.Errorf("root with manager = %q", v)
	}
	// kpm 子命令也算(中等证据)
	f2 := fixtureRMX5010VPN("/data/local/hnc")
	f2.cmds["/data/adb/ksud --help"] = "Usage: ksud <COMMAND>\n\nCommands:\n  module  Manage modules\n  kpm     KPM\n"
	r2 := runSelfcheck(f2.scEnv(), scOptions{})
	if v := findItem(t, r2, "system", "root").Value; v != "SukiSU" {
		t.Errorf("root with kpm = %q", v)
	}
	// 没有任何 SukiSU 痕迹的官方 KernelSU
	f3 := fixtureRMX5010VPN("/data/local/hnc")
	f3.cmds["/data/adb/ksud -V"] = "ksud 1.0.5\n"
	delete(f3.files, "/data/adb/ksu/bin/ksu_susfs")
	f3.dirs["/data/adb/modules"] = []string{"hotspot_network_control"}
	r3 := runSelfcheck(f3.scEnv(), scOptions{})
	if v := findItem(t, r3, "system", "root").Value; v != "KernelSU" {
		t.Errorf("plain ksu = %q", v)
	}
}

func TestSelfcheckIPNamePathMismatch(t *testing.T) {
	f := fixtureRMX5010VPN("/data/local/hnc")
	f.files[f.h("etc", "dpi_config.json")] = `{"run_dir":"/data/local/tmp/hnc_run"}`
	r := runSelfcheck(f.scEnv(), scOptions{})
	n := expectStatus(t, r, "ident", "ipname_entries", scWarn)
	if n.Value != "文件路径异常" {
		t.Errorf("ipname=%q", n.Value)
	}
	mustContain(t, "detail", n.Detail, "/data/local/tmp/hnc_run")

	// dpid 跑了很久、见过事件却没有文件 → 警告
	f2 := fixtureRMX5010VPN("/data/local/hnc")
	f2.files["/proc/uptime"] = "99999.0 1.0\n"
	f2.files[f2.h("run", "dpi_state.json")] = fmt.Sprintf(`{"generated_at":%d,"mode":"af_packet","stats":{"dns_events":12,"tls_events":30}}`, f2.now.Unix())
	r2 := runSelfcheck(f2.scEnv(), scOptions{})
	n2 := expectStatus(t, r2, "ident", "ipname_entries", scWarn)
	mustContain(t, "missing", n2.Detail, "42 个 DNS/TLS 事件")
}

func TestSelfcheckV5201NewItems(t *testing.T) {
	f := fixtureColorOSQualcomm("/data/local/hnc")
	now := f.now
	f.files[f.h("run", "v6_neigh.json")] = fmt.Sprintf(`{"active":true,"events":57,"triggers":9,"runs":9,"last_run_at":%d,"last_rc":0}`, now.Add(-2*time.Minute).Unix())
	f.files[f.h("run", "clock_state.json")] = fmt.Sprintf(`{"sane":true,"now":%d,"high_water":%d,"jumps":1,"last_jump_at":%d,"last_jump_secs":-3600}`,
		now.Unix(), now.Unix(), now.Add(-time.Hour).Unix())
	r := runSelfcheck(f.scEnv(), scOptions{})

	sub := expectStatus(t, r, "ipv6", "v6_neigh_sub", scOK)
	if sub.Value != "在线 · 事件 57 · 触发 9" {
		t.Errorf("v6 sub=%q", sub.Value)
	}
	mustContain(t, "v6 sub", sub.Detail, "最近一次同步 2 分钟前")

	cg := expectStatus(t, r, "time", "clock_guard", scInfo)
	mustContain(t, "clock", cg.Value, "跳变 1 次")
	mustContain(t, "clock", cg.Detail, "-3600 秒")

	lat := findItem(t, r, "shaping", "low_latency")
	mustContain(t, "tried", lat.Detail, "cake(modprobe 失败)")
	mustContain(t, "tried", lat.Detail, "sfq(? 成功)")

	bp := expectStatus(t, r, "offload", "hotspot_counter_bypass", scInfo)
	mustContain(t, "bypass", bp.Detail, "rmnet_offload")
	mustContain(t, "bypass", bp.Fix, "统计校准")

	// 离线订阅 + 不可信时钟
	f.files[f.h("run", "v6_neigh.json")] = `{"active":false,"err":"netlink: permission denied","events":0,"triggers":0}`
	f.files[f.h("run", "clock_state.json")] = `{"sane":false,"jumps":0}`
	r2 := runSelfcheck(f.scEnv(), scOptions{})
	s2 := expectStatus(t, r2, "ipv6", "v6_neigh_sub", scWarn)
	mustContain(t, "offline", s2.Detail, "permission denied")
	expectStatus(t, r2, "time", "clock_guard", scWarn)

	// 状态文件都没有
	delete(f.files, f.h("run", "v6_neigh.json"))
	delete(f.files, f.h("run", "clock_state.json"))
	r3 := runSelfcheck(f.scEnv(), scOptions{})
	expectStatus(t, r3, "ipv6", "v6_neigh_sub", scInfo)
	expectStatus(t, r3, "time", "clock_guard", scInfo)
}

func TestScUpstreamItem(t *testing.T) {
	cases := []struct {
		local, teth string
		det         ifaceDetect
		want        string
	}{
		{"tun0", "rmnet_data3", ifaceDetect{}, "热点上游 rmnet_data3(蜂窝) · 本机走 VPN tun0"},
		{"rmnet_data1", "rmnet_data1", ifaceDetect{}, "热点上游 rmnet_data1(蜂窝)"},
		{"wlan0", "rmnet_data1", ifaceDetect{}, "热点上游 rmnet_data1(蜂窝) · 本机出口 wlan0(Wi-Fi)"},
		{"rmnet_data0", "", ifaceDetect{}, "rmnet_data0"},
		// 热点关着 + VPN: 物理口来自 iface_detect.json
		{"tun0", "", ifaceDetect{Upstream: "wlan0", UpstreamSource: "route_physical", VPNActive: true}, "本机走 VPN tun0(物理出口 wlan0(Wi-Fi))"},
		// dumpsys 不可用时用 iface_detect 的 tether_upstream
		{"tun0", "", ifaceDetect{TetherUpstream: "rmnet_data3", VPNActive: true}, "热点上游 rmnet_data3(蜂窝) · 本机走 VPN tun0"},
	}
	for _, c := range cases {
		if got := scUpstreamItem(c.local, c.teth, c.det).Value; got != c.want {
			t.Errorf("scUpstreamItem(%q,%q) = %q, want %q", c.local, c.teth, got, c.want)
		}
	}
	if it := scUpstreamItem("", "", ifaceDetect{}); it.Status != scWarn || !strings.Contains(it.Value, "无默认路由") {
		t.Errorf("no route = %+v", it)
	}
	if scFirstUpstreamIface("[v4-rmnet_data3, rmnet_data3]") != "rmnet_data3" || scFirstUpstreamIface("null") != "" {
		t.Error("scFirstUpstreamIface")
	}
}
