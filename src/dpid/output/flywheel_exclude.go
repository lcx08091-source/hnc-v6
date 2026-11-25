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
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// flywheelExcludeFile is the user-editable exclusion list, merged with the
// built-in seed. Shape: {"exclude_pkgs": ["com.foo.bar", ...]}. Missing or
// malformed = built-in seed only (best-effort, never fatal). var (not const)
// so tests can point it at a temp file.
var flywheelExcludeFile = "/data/local/hnc/etc/flywheel_exclude.json"

// Dynamic TUN / VPN OwnerUid probe hooks (overridable in unit tests).
var (
	sysClassNetDir        = "/sys/class/net"
	dumpsysVPNTimeout     = 3 * time.Second
	dumpsysVPNRetryPeriod = 30 * time.Second
	runDumpsysVPNFn       = defaultRunDumpsysVPN
)

// conduitApexThreshold: a single uid associated with >= this many distinct
// brand-new apexes in the accumulator is treated as a generic conduit
// (VPN/proxy/browser) and blocked from AUTO-promotion. Brand-new apexes
// (matching no curated rule) under one uid are rare for a normal app, so a
// high count strongly indicates proxied/aggregated traffic.
const conduitApexThreshold = 8

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

type excludeFastSnapshot struct {
	pkgs        map[string]struct{}
	dynUIDs     map[int]struct{}
	dynPkgs     map[string]struct{}
	conduitUIDs map[int]struct{}
}

var (
	liveExcludeSnap atomic.Pointer[excludeFastSnapshot]

	dynVPNMu         sync.Mutex
	dynVPNProbeMu    sync.Mutex
	dynVPNLastSig    string
	dynVPNLastErrSig string
	dynVPNLastErrAt  time.Time
	dynVPNUIDs       map[int]struct{}
	dynVPNPkgs       map[string]struct{}

	vpnOwnerUIDRe = regexp.MustCompile(`(?i)\b(?:m?owner_?uid)\s*[:=]\s*(\d+)\b`)
	vpnPkgRe      = regexp.MustCompile(`(?i)\b(?:m?package)\s*[:=]\s*([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)\b`)
)

func init() {
	liveExcludeSnap.Store(&excludeFastSnapshot{
		pkgs: builtinFlywheelExcludePkgs,
	})
}

func updateLiveExcludeSnapshot(pkgs map[string]struct{}, dynUIDs map[int]struct{}, dynPkgs map[string]struct{}, conduitUIDs map[int]struct{}) {
	prev := liveExcludeSnap.Load()
	next := &excludeFastSnapshot{}
	if pkgs != nil {
		cp := make(map[string]struct{}, len(pkgs))
		for k := range pkgs {
			cp[k] = struct{}{}
		}
		next.pkgs = cp
	} else if prev != nil {
		next.pkgs = prev.pkgs
	} else {
		next.pkgs = builtinFlywheelExcludePkgs
	}
	if dynUIDs != nil {
		cp := make(map[int]struct{}, len(dynUIDs))
		for u := range dynUIDs {
			cp[u] = struct{}{}
		}
		next.dynUIDs = cp
	} else if prev != nil {
		next.dynUIDs = prev.dynUIDs
	}
	if dynPkgs != nil {
		cp := make(map[string]struct{}, len(dynPkgs))
		for p := range dynPkgs {
			cp[p] = struct{}{}
		}
		next.dynPkgs = cp
	} else if prev != nil {
		next.dynPkgs = prev.dynPkgs
	}
	if conduitUIDs != nil {
		cp := make(map[int]struct{}, len(conduitUIDs))
		for u := range conduitUIDs {
			cp[u] = struct{}{}
		}
		next.conduitUIDs = cp
	} else if prev != nil {
		next.conduitUIDs = prev.conduitUIDs
	}
	liveExcludeSnap.Store(next)
}

func clearLiveDynamicVPNSnapshot() {
	prev := liveExcludeSnap.Load()
	next := &excludeFastSnapshot{pkgs: builtinFlywheelExcludePkgs}
	if prev != nil {
		if prev.pkgs != nil {
			next.pkgs = prev.pkgs
		}
		next.conduitUIDs = prev.conduitUIDs
	}
	liveExcludeSnap.Store(next)
}

// isExcludedFromLabelSamples performs a lock-free O(1) check in the capture
// callback hot path so VPN/proxy conduits never pollute label_samples.
func isExcludedFromLabelSamples(uid int, pkg string) bool {
	snap := liveExcludeSnap.Load()
	if snap == nil {
		if pkg != "" {
			_, ok := builtinFlywheelExcludePkgs[pkg]
			return ok
		}
		return false
	}
	if pkg != "" {
		if _, ok := snap.pkgs[pkg]; ok {
			return true
		}
		if snap.dynPkgs != nil {
			if _, ok := snap.dynPkgs[pkg]; ok {
				return true
			}
		}
	}
	if uid > 0 {
		if snap.dynUIDs != nil {
			if _, ok := snap.dynUIDs[uid]; ok {
				return true
			}
		}
		if snap.conduitUIDs != nil {
			if _, ok := snap.conduitUIDs[uid]; ok {
				return true
			}
		}
	}
	return false
}

func isNonVPNTunIface(name string) bool {
	lc := strings.ToLower(strings.TrimSpace(name))
	if lc == "" || lc == "lo" {
		return true
	}
	for _, p := range []string{
		"vgate", "clat", "v4-", "dummy", "ifb",
		"rmnet", "r_rmnet", "ccmni", "wwan", "sipa_eth", "seth_", "gti",
	} {
		if strings.HasPrefix(lc, p) {
			return true
		}
	}
	return false
}

// scanActiveTunSignature inspects /sys/class/net/*/tun_flags (excluding OEM vgate*
// and cellular/464XLAT interfaces, covering tun0, Meta, sing_tun*, etc.) and returns
// a deterministic "name:ifindex,..." signature. Pure sysfs stat/read, zero fork.
func scanActiveTunSignature(netDir string) string {
	if strings.TrimSpace(netDir) == "" {
		return ""
	}
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return ""
	}
	var parts []string
	for _, e := range entries {
		name := e.Name()
		if isNonVPNTunIface(name) {
			continue
		}
		ifaceDir := filepath.Join(netDir, name)
		if _, err := os.Stat(filepath.Join(ifaceDir, "tun_flags")); err != nil {
			continue
		}
		if fb, ferr := os.ReadFile(filepath.Join(ifaceDir, "flags")); ferr == nil {
			if flags, perr := strconv.ParseUint(strings.TrimSpace(string(fb)), 0, 32); perr == nil && (flags&0x1) == 0 {
				continue
			}
		}
		ifidx := "?"
		if ib, ierr := os.ReadFile(filepath.Join(ifaceDir, "ifindex")); ierr == nil {
			if s := strings.TrimSpace(string(ib)); s != "" {
				ifidx = s
			}
		}
		parts = append(parts, name+":"+ifidx)
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func defaultRunDumpsysVPN() (string, error) {
	cmd, cancel := pmCommandWithTimeout(dumpsysVPNTimeout, "dumpsys", "vpn_management")
	defer cancel()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func parseDumpsysVPNOwnerUIDs(raw string) (map[int]struct{}, map[string]struct{}) {
	uids := make(map[int]struct{})
	pkgs := make(map[string]struct{})
	for _, m := range vpnOwnerUIDRe.FindAllStringSubmatch(raw, -1) {
		if len(m) < 2 {
			continue
		}
		uid, err := strconv.Atoi(m[1])
		if err != nil || uid < 10000 || (uid%100000) < 10000 {
			continue
		}
		uids[uid] = struct{}{}
	}
	for _, m := range vpnPkgRe.FindAllStringSubmatch(raw, -1) {
		if len(m) < 2 {
			continue
		}
		pkg := strings.TrimSpace(m[1])
		if pkg == "" || pkg == "com.android.vpndialogs" || pkg == "android" {
			continue
		}
		pkgs[pkg] = struct{}{}
	}
	return uids, pkgs
}

// refreshDynamicVPNConduits uses the /sys/class/net/*/tun_flags ifindex signature
// as a zero-fork gate and invokes dumpsys vpn_management ONLY when TUN interfaces
// appear or change ifindex.
func refreshDynamicVPNConduits() (map[int]struct{}, map[string]struct{}) {
	sig := scanActiveTunSignature(sysClassNetDir)
	if sig == "" {
		dynVPNMu.Lock()
		hadAny := dynVPNLastSig != "" || len(dynVPNUIDs) > 0 || len(dynVPNPkgs) > 0
		dynVPNLastSig = ""
		dynVPNLastErrSig = ""
		dynVPNLastErrAt = time.Time{}
		dynVPNUIDs = nil
		dynVPNPkgs = nil
		dynVPNMu.Unlock()
		if hadAny {
			clearLiveDynamicVPNSnapshot()
		}
		return nil, nil
	}

	dynVPNMu.Lock()
	if sig == dynVPNLastSig {
		u, p := copyIntSet(dynVPNUIDs), copyStringSet(dynVPNPkgs)
		dynVPNMu.Unlock()
		return u, p
	}
	if sig == dynVPNLastErrSig && !dynVPNLastErrAt.IsZero() && time.Since(dynVPNLastErrAt) < dumpsysVPNRetryPeriod {
		u, p := copyIntSet(dynVPNUIDs), copyStringSet(dynVPNPkgs)
		dynVPNMu.Unlock()
		return u, p
	}
	dynVPNMu.Unlock()

	dynVPNProbeMu.Lock()
	defer dynVPNProbeMu.Unlock()

	dynVPNMu.Lock()
	if sig == dynVPNLastSig {
		u, p := copyIntSet(dynVPNUIDs), copyStringSet(dynVPNPkgs)
		dynVPNMu.Unlock()
		return u, p
	}
	dynVPNMu.Unlock()

	raw, err := runDumpsysVPNFn()
	now := time.Now()
	dynVPNMu.Lock()
	if err != nil {
		dynVPNLastErrSig = sig
		dynVPNLastErrAt = now
		u, p := copyIntSet(dynVPNUIDs), copyStringSet(dynVPNPkgs)
		dynVPNMu.Unlock()
		return u, p
	}
	u, p := parseDumpsysVPNOwnerUIDs(raw)
	dynVPNLastSig = sig
	dynVPNLastErrSig = ""
	dynVPNLastErrAt = time.Time{}
	dynVPNUIDs = u
	dynVPNPkgs = p
	cu, cp := copyIntSet(u), copyStringSet(p)
	dynVPNMu.Unlock()

	updateLiveExcludeSnapshot(nil, cu, cp, nil)
	return cu, cp
}

func resetDynamicVPNConduitCacheForTest() {
	dynVPNMu.Lock()
	dynVPNLastSig = ""
	dynVPNLastErrSig = ""
	dynVPNLastErrAt = time.Time{}
	dynVPNUIDs = nil
	dynVPNPkgs = nil
	dynVPNMu.Unlock()
	clearLiveDynamicVPNSnapshot()
}

func copyIntSet(in map[int]struct{}) map[int]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[int]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}

func copyStringSet(in map[string]struct{}) map[string]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
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
		updateLiveExcludeSnapshot(out, nil, nil, nil)
		return out
	}
	var d flywheelExcludeFileData
	if err := json.Unmarshal(data, &d); err != nil {
		updateLiveExcludeSnapshot(out, nil, nil, nil)
		return out
	}
	for _, p := range d.ExcludePkgs {
		p = strings.TrimSpace(p)
		if p != "" {
			out[p] = struct{}{}
		}
	}
	updateLiveExcludeSnapshot(out, nil, nil, nil)
	return out
}
