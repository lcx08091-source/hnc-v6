package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPuPickUpstreamVPN(t *testing.T) {
	now := int64(1_800_000_000)
	// 真机: iface_detect(新版)报 tethering 上游 rmnet_data3, 本机出口 tun0
	d := ifaceDetect{Ts: now - 30, Upstream: "rmnet_data3", UpstreamClass: "cell", UpstreamSource: "tethering",
		TetherUpstream: "rmnet_data3", LocalUpstream: "tun0", LocalUpstreamClass: "vpn", VPNActive: true}
	u := puPickUpstream(d, now, "tun0")
	if u.Tether != "rmnet_data3" || u.Local != "tun0" || !u.VPN || u.routeIface() != "rmnet_data3" {
		t.Fatalf("vpn+tether = %+v", u)
	}
	// 热点关着(无 tethering 上游), VPN 下的物理口
	d2 := ifaceDetect{Ts: now, Upstream: "wlan0", UpstreamSource: "route_physical", LocalUpstream: "tun0", VPNActive: true}
	if u := puPickUpstream(d2, now, "tun0"); u.Tether != "wlan0" || !u.VPN {
		t.Fatalf("route_physical = %+v", u)
	}
	// iface_detect 过期 → 只剩实时本机出口 tun0 → 不作为热点上游(交给增量判定)
	if u := puPickUpstream(d, now+3600, "tun0"); u.Tether != "" || !u.VPN || u.routeIface() != "" {
		t.Fatalf("stale = %+v", u)
	}
	// 无 VPN: 实时本机出口就是上游
	d3 := ifaceDetect{Ts: now, Upstream: "rmnet_data0", UpstreamSource: "route", LocalUpstream: "rmnet_data0"}
	if u := puPickUpstream(d3, now, "rmnet_data0"); u.VPN || u.routeIface() != "rmnet_data0" {
		t.Fatalf("no vpn = %+v", u)
	}
	// tether 字段被写成 VPN 口也不采信
	if u := puPickUpstream(ifaceDetect{Ts: now, TetherUpstream: "tun0"}, now, "rmnet_data0"); u.Tether != "" || u.routeIface() != "rmnet_data0" {
		t.Fatalf("tun tether = %+v", u)
	}
}

// 开 VPN: 热点按 tethering 上游(蜂窝)扣减; tun0 不计数(本机字节已在 rmnet 上), 不重复计
func TestPuEngineVPNUpstream(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	loc := time.FixedZone("CST", 8*3600)
	t0 := time.Date(2026, 9, 30, 10, 0, 0, 0, loc)
	f := &puFake{boot: "b", route: "tun0", sim: puSIM{Slot: 1, Carrier: "中国移动"},
		ctr: map[string][2]uint64{"rmnet_data3": {0, 0}, "wlan0": {0, 0}, "wlan2": {0, 0}, "tun0": {0, 0}}}
	env := f.env()
	env.upstreamInfo = func() puUpInfo {
		return puPickUpstream(ifaceDetect{Ts: t0.Unix(), Upstream: "rmnet_data3", UpstreamSource: "tethering",
			TetherUpstream: "rmnet_data3", LocalUpstream: "tun0", VPNActive: true}, t0.Unix(), f.route)
	}
	e := newPuEngine(dir, env)
	e.tick(t0)
	// wlan0 也有流量(足以让增量启发式误判成 Wi-Fi 上游), 必须以 tethering 上游为准
	// 本机经 VPN: tun0 rx 2000/tx 500, 承载它的 rmnet 多出 2100/560(含隧道开销);
	// 热点客户端下载 6000 上传 1000 → rmnet 再 +6000/+1000
	f.ctr = map[string][2]uint64{"rmnet_data3": {8100, 1560}, "wlan0": {7000, 7000}, "wlan2": {1000, 6000}, "tun0": {2000, 500}}
	out := e.tick(t0.Add(time.Minute))
	if out["cell"] != [2]uint64{8100, 1560} {
		t.Fatalf("cell = %v (tun0 must not be added)", out["cell"])
	}
	if out["local_cell"] != [2]uint64{2100, 560} || out["local_wifi"] != [2]uint64{7000, 7000} {
		t.Fatalf("local split = %v / %v", out["local_cell"], out["local_wifi"])
	}
	if e.day.HsVia["cell"] != [2]uint64{6000, 1000} {
		t.Fatalf("hotspot_via = %v", e.day.HsVia)
	}
	rep := e.report("today", t0.Add(2*time.Minute))
	src := rep["sources"].(map[string]interface{})
	if src["vpn_active"] != true || src["tether_upstream"] != "rmnet_data3" || src["local_upstream"] != "tun0" || src["upstream"] != "cell" {
		t.Fatalf("sources = %v", src)
	}
	for _, it := range e.lastIfs {
		if it.Name == "tun0" {
			t.Fatal("tun0 must not be classified/counted")
		}
	}

	// 只有路由出口 tun0(旧 env.upstream)时: 标记 VPN, 不拿 tun0 当热点上游
	if u := (puUpInfo{Local: "tun0"}).normalized(); !u.VPN || u.routeIface() != "" {
		t.Fatalf("legacy normalized = %+v", u)
	}
}
