// Package output - flywheel_exclude.go (v5.7.0-rc33)
//
// VPN / proxy app exclusion for the auto-learn flywheel (走法1 + 走法2).
//
// ── Why ───────────────────────────────────────────────────────────────
// dpid attributes SNIs to apps via the kernel uid ground truth (/proc/net
// socket owner). That's normally rock-solid — EXCEPT when a VPN/proxy app
// (Clash / v2rayNG / sing-box / WireGuard ...) is active: it re-originates
// every other app's traffic, so at the socket level ALL proxied flows are
// owned by the VPN app's uid. The flywheel then mis-learns rules like
// "capcom.co.jp -> FlClash", locking unrelated domains onto the VPN app.
//
// ── Two layers ────────────────────────────────────────────────────────
//  1. Explicit package list: a built-in seed of well-known VPN/proxy apps
//     plus a user-editable /data/local/hnc/etc/flywheel_exclude.json. uids
//     resolving to these packages never accumulate candidates and never get
//     auto-promotions (existing bad ones are demoted). Deterministic, takes
//     effect from the first sighting.
//  2. Conduit auto-detection (see candidate.go): a uid that accumulates an
//     unusually large number of DISTINCT brand-new apexes is a generic
//     conduit (VPN/proxy/browser) regardless of whether it's on the list.
//     Such a uid is blocked from AUTO-promotion (manual promote still wins).
//
// The exclusion is scoped to the flywheel ONLY. VPN apps still show up
// normally in the "我的应用" list with their real connection counts — we
// just don't mint app-specific rules from their (proxied) traffic.

package output

import (
	"encoding/json"
	"os"
	"strings"
)

const (
	// flywheelExcludeFile is the user-editable exclusion list, merged with the
	// built-in seed. Shape: {"exclude_pkgs": ["com.foo.bar", ...]}. Missing or
	// malformed = built-in seed only (best-effort, never fatal).
	flywheelExcludeFile = "/data/local/hnc/etc/flywheel_exclude.json"

	// conduitApexThreshold: a single uid associated with >= this many distinct
	// brand-new apexes in the accumulator is treated as a generic conduit
	// (VPN/proxy/browser) and blocked from AUTO-promotion. Brand-new apexes
	// (matching no curated rule) under one uid are rare for a normal app, so a
	// high count strongly indicates proxied/aggregated traffic.
	conduitApexThreshold = 8
)

// builtinFlywheelExcludePkgs seeds the exclusion with well-known VPN / proxy
// client packages (CN proxy clients first, then mainstream VPNs). Not meant
// to be exhaustive — conduit auto-detection covers the long tail; this just
// gives common apps immediate, deterministic exclusion.
var builtinFlywheelExcludePkgs = map[string]struct{}{
	// ── Clash family ──
	"com.follow.clash":                {}, // FlClash
	"com.github.kr328.clash":          {}, // Clash for Android (Kr328)
	"com.github.metacubex.clash.meta": {}, // Clash Meta for Android (MetaCubeX)
	// ── v2ray / Xray ──
	"com.v2ray.ang":      {}, // v2rayNG (verified)
	"com.v2ray.actinium": {}, // Actinium
	// ── sing-box / SagerNet family ──
	"io.nekohasekai.sfa":      {}, // sing-box for Android / SFA (verified)
	"io.nekohasekai.sagernet": {}, // SagerNet
	"moe.nb4a":                {}, // NekoBox for Android
	"moe.matsuri.lite":        {}, // Matsuri
	// ── shadowsocks / trojan ──
	"com.github.shadowsocks":       {}, // shadowsocks-android (verified)
	"io.github.trojan_gfw.igniter": {}, // Igniter / trojan-gfw (verified)
	// ── other proxy front-ends ──
	"com.getsurfboard":    {}, // Surfboard
	"com.hiddify.hiddify": {}, // Hiddify (older id)
	"app.hiddify.com":     {}, // Hiddify (verified)
	// ── WireGuard / OpenVPN / Tor ──
	"com.wireguard.android":  {}, // WireGuard
	"net.openvpn.openvpn":    {}, // OpenVPN Connect
	"de.blinkt.openvpn":      {}, // OpenVPN for Android (ics-openvpn)
	"org.torproject.android": {}, // Orbot (Tor)
	// ── mesh / mainstream VPNs ──
	"com.tailscale.ipn":                    {}, // Tailscale
	"net.mullvad.mullvadvpn":               {}, // Mullvad VPN (open source, verified)
	"org.outline.android.client":           {}, // Outline (Jigsaw)
	"ch.protonvpn.android":                 {}, // ProtonVPN
	"com.nordvpn.android":                  {}, // NordVPN
	"com.expressvpn.vpn":                   {}, // ExpressVPN
	"com.windscribe.vpn":                   {}, // Windscribe
	"com.surfshark.vpnclient.android":      {}, // Surfshark
	"com.cloudflare.onedotonedotonedotone": {}, // Cloudflare 1.1.1.1 / WARP
	// ── local-VPN firewalls / DNS (own the tun → re-originate traffic) ──
	"eu.faircode.netguard": {}, // NetGuard (open source, verified)
	"com.celzero.bravedns": {}, // Rethink DNS + Firewall (open source, verified)
	"com.adguard.android":  {}, // AdGuard
}

// flywheelExcludeFileData is the on-disk shape of flywheel_exclude.json.
type flywheelExcludeFileData struct {
	ExcludePkgs []string `json:"exclude_pkgs"`
	Comment     string   `json:"_comment,omitempty"`
}

// loadFlywheelExcludePkgs returns the union of the built-in seed and the
// user-editable file. Always non-nil and always contains the seed (so a
// missing/garbage user file degrades to the built-in behavior, never to
// "exclude nothing").
func loadFlywheelExcludePkgs() map[string]struct{} {
	out := make(map[string]struct{}, len(builtinFlywheelExcludePkgs)+8)
	for p := range builtinFlywheelExcludePkgs {
		out[p] = struct{}{}
	}
	data, err := os.ReadFile(flywheelExcludeFile)
	if err != nil {
		return out
	}
	var d flywheelExcludeFileData
	if err := json.Unmarshal(data, &d); err != nil {
		return out
	}
	for _, p := range d.ExcludePkgs {
		p = strings.TrimSpace(p)
		if p != "" {
			out[p] = struct{}{}
		}
	}
	return out
}
