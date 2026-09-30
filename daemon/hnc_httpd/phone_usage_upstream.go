// phone_usage_upstream.go — v5.20.1: 热点上游 vs 本机出口(VPN)
//
// 真机(RMX5010)开着 VPN: `ip route get 1.1.1.1` → tun0(root 在 VPN 的 uid 范围内),
// 而 `dumpsys tethering` 的共享上游是 rmnet_data3。热点流量走 tethering 上游、不进手机
// 的 VPN, 所以"热点走哪条路"(hotspot_via / 本机=上游−热点)必须按 tethering 上游算。
// 数据来源: bin/hnc_iface.sh 写的 run/iface_detect.json(upstream 已是 tethering 上游 /
// VPN 时的物理口; local_upstream 是本机出口; vpn_active)。
package main

import "strings"

// puIfaceDetectMaxAge iface_detect.json 超过这么久(秒)视为过期, 不用它的 upstream
const puIfaceDetectMaxAge = 15 * 60

// puUpInfo 热点上游 / 本机出口
type puUpInfo struct {
	Tether string // 热点流量实际走的上游(非 VPN)
	Local  string // 本机默认路由出口(可能是 tun0)
	VPN    bool   // 本机出口是 VPN
}

// normalized 本机出口是 VPN 口时置 VPN; Tether 误填成 VPN 口时丢弃
func (u puUpInfo) normalized() puUpInfo {
	if isVPNIface(u.Local) {
		u.VPN = true
	}
	if isVPNIface(u.Tether) {
		u.Tether = ""
	}
	return u
}

// routeIface 用来判定热点上游类别的接口: tethering 上游优先; 否则本机出口(VPN 口除外 → "")
func (u puUpInfo) routeIface() string {
	if u.Tether != "" {
		return u.Tether
	}
	if isVPNIface(u.Local) {
		return ""
	}
	return u.Local
}

// puPickUpstream 由 iface_detect.json + 本机路由出口得出 puUpInfo。
// iface_detect 过期(或没写 ts)时只用实时的本机出口; upstream_source=route(无 VPN、
// 没有 tethering 上游)时也以实时本机出口为准。
func puPickUpstream(d ifaceDetect, now int64, local string) puUpInfo {
	u := puUpInfo{Local: strings.TrimSpace(local)}
	fresh := d.Ts > 0 && now-d.Ts >= -60 && now-d.Ts <= puIfaceDetectMaxAge
	if fresh {
		switch {
		case d.TetherUpstream != "":
			u.Tether = d.TetherUpstream
		case d.Upstream != "" && d.UpstreamSource != "route":
			// route_physical(VPN 下的物理口) / 旧版没有 upstream_source 的文件
			u.Tether = d.Upstream
		}
		if d.VPNActive {
			u.VPN = true
		}
		if u.Local == "" {
			u.Local = d.LocalUpstream
		}
	}
	return u.normalized()
}
