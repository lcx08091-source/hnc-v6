// Package capture - self_iface.go (v5.5)
//
// Enumerates "self" interfaces — the ones that carry THIS phone's own
// outbound traffic. Symmetric counterpart to DiscoverAPCandidates which
// finds the hotspot AP interface.
//
// What counts as a self interface:
//
//   ✓ rmnet_data0, rmnet_data1, ... (Qualcomm cellular)
//   ✓ ccmni0, ccmni1, ... (MediaTek cellular)
//   ✓ wwan0, wwan1, ... (generic cellular)
//   ✓ wlan0 (STA mode, NOT the AP wlanX)
//   ✓ eth0 (rare; tethered or test devices)
//
// What does NOT count:
//
//   ✗ lo, dummy*, ifb*, tun*, vpn*, gre*, sit*, ip_vti*, ip6_vti*
//   ✗ wlan1, wlan2, ap*, softap*, swlan* (these are the AP-side)
//   ✗ The interface HNC's main capture is currently using (read from
//     /data/local/hnc/run/hotspot_iface) — that's the AP, double-attaching
//     would just produce duplicate events.
//
// The picker also excludes interfaces with operstate=down and rx_bytes
// near zero, to avoid attaching to phantom interfaces.

package capture

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// selfPositivePatterns: a name matches one of these → eligible (subject to
// up/rx-bytes check).
var selfPositivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^rmnet(_data)?\d+$`),
	regexp.MustCompile(`^ccmni\d+$`),
	regexp.MustCompile(`^wwan\d+$`),
	regexp.MustCompile(`^wlan0$`), // STA mode WiFi
	regexp.MustCompile(`^eth\d+$`),
	// v5.6.0-rc3: VPN tun interfaces. These carry decrypted in-app
	// traffic (TLS ClientHello with plaintext SNI), which is exactly
	// what self-attribution needs. Without these, users running Clash /
	// WireGuard / Tailscale would only see the encrypted uplink on
	// rmnet — useless for SNI extraction. Link type ARPHRD_NONE (65534)
	// for tun, handled by rawsocket.go's RawIP dispatch.
	regexp.MustCompile(`^tun\d+$`),
	regexp.MustCompile(`^vpn\d+$`),
	regexp.MustCompile(`^wg\d+$`),
	regexp.MustCompile(`^tailscale\d+$`),
	regexp.MustCompile(`^utun\d+$`), // iOS-style naming, occasionally seen
}

// selfNegativePatterns: name matches one of these → never picked, even if
// up. These are virtual / loopback / AP-side. (VPN tun/vpn/wg/tailscale
// moved to positives in rc3; see above.)
var selfNegativePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^lo$`),
	regexp.MustCompile(`^dummy\d*$`),
	regexp.MustCompile(`^ifb\d*$`),
	regexp.MustCompile(`^gre\d*$`),
	regexp.MustCompile(`^sit\d*$`),
	regexp.MustCompile(`^ip6?_vti\d*$`),
	regexp.MustCompile(`^erspan\d*$`),
	regexp.MustCompile(`^gretap\d*$`),
	regexp.MustCompile(`^docker\d*$`),
	regexp.MustCompile(`^br-`),
	regexp.MustCompile(`^ap\d*$`),
	regexp.MustCompile(`^softap\d*$`),
	regexp.MustCompile(`^swlan\d+$`),
	regexp.MustCompile(`^wlan[1-9]\d*$`),
}

// SelfIfaceCandidate describes one eligible self interface.
type SelfIfaceCandidate struct {
	Name      string `json:"name"`
	OperState string `json:"oper_state"`
	RxBytes   uint64 `json:"rx_bytes"`
	IsWiFi    bool   `json:"is_wifi"`
	IsCell    bool   `json:"is_cellular"`
}

// DiscoverSelfCandidates enumerates self-eligible interfaces. The
// returned list is sorted by descending rx_bytes (busiest first) so
// callers that want to limit can do so meaningfully.
//
// The currentAP arg is the AP interface name HNC's main capture is
// using; if non-empty, it will not appear in results even if it would
// otherwise match (paranoia; AP names shouldn't match positive patterns
// anyway, but belt + suspenders).
func DiscoverSelfCandidates(currentAP string) ([]SelfIfaceCandidate, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var out []SelfIfaceCandidate
	for _, e := range entries {
		name := e.Name()
		if name == currentAP {
			continue
		}
		if matchAny(selfNegativePatterns, name) {
			continue
		}
		if !matchAny(selfPositivePatterns, name) {
			continue
		}
		// operstate must be "up" or "unknown" (some Android ifaces never
		// transition out of unknown — kernel quirk).
		st := readTrim(filepath.Join("/sys/class/net", name, "operstate"))
		if st != "up" && st != "unknown" {
			continue
		}
		rx, _ := strconv.ParseUint(readTrim(filepath.Join("/sys/class/net", name, "statistics/rx_bytes")), 10, 64)
		if rx < 1000 {
			// Phantom interface — UP but no real traffic
			continue
		}
		out = append(out, SelfIfaceCandidate{
			Name:      name,
			OperState: st,
			RxBytes:   rx,
			IsWiFi:    strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "eth"),
			IsCell:    strings.HasPrefix(name, "rmnet") || strings.HasPrefix(name, "ccmni") || strings.HasPrefix(name, "wwan"),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RxBytes > out[j].RxBytes })
	return out, nil
}

func matchAny(patterns []*regexp.Regexp, name string) bool {
	for _, p := range patterns {
		if p.MatchString(name) {
			return true
		}
	}
	return false
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// IsSelfBPFFilter returns the BPF filter expression to apply to a
// self-capture handle. Currently identical to the main HNC capture
// because rule matching needs both DNS and TLS regardless of which
// side of the conversation we're on. Kept as a function so it can be
// customized later (e.g. drop DNS on cellular if proven redundant).
func IsSelfBPFFilter() string {
	// Empty string = no extra BPF; the capture handle's default filter
	// already targets TCP/443 + UDP/53 + UDP/443 via cBPF.
	return ""
}
