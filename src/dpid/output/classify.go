// Package output - classify.go: rule lookup hot-path.
//
// Three classifiers, all returning (matched l3Rule, ok).
// Priority semantics:
//   - PrioritySpecific rules always win over PriorityFallback.
//   - Within the same priority bucket, suffix matching uses longest-suffix-wins;
//     IP matching uses first-hit-wins.
//
// rc20.1 only had classifyHost(suffix); rc29 adds classifyFlowIP and
// classifyFlowIPv6 driven by ip_matchers/ipv6_matchers.

package output

import (
	"net"
	"strings"
)

// classifyHost looks up a DNS qname or TLS SNI string against rule suffixes.
// Returns the longest-matching suffix in the highest priority bucket.
func classifyHost(host string) (l3Rule, bool) {
	host = normalizeName(host)
	if host == "" {
		return l3Rule{}, false
	}
	rules := loadL3Rules().rules

	// Two-pass: first try PrioritySpecific, fall back to PriorityFallback.
	for _, want := range []PriorityClass{PrioritySpecific, PriorityFallback} {
		bestLen := -1
		var best l3Rule
		for _, r := range rules {
			if r.Priority != want {
				continue
			}
			for _, suf := range r.Suffixes {
				suf = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(suf), "."))
				if suf == "" {
					continue
				}
				if host == suf || strings.HasSuffix(host, "."+suf) {
					if len(suf) > bestLen {
						bestLen = len(suf)
						best = r
					}
				}
			}
		}
		if bestLen >= 0 {
			return best, true
		}
	}
	return l3Rule{}, false
}

// classifyFlowIP looks up an IPv4 endpoint against rule ip_matchers.
// remoteIP is the non-client side of the flow (server). proto/port describe
// the L4 tuple; pass protoAny / 0 if unknown.
func classifyFlowIP(remoteIP net.IP, proto matchProto, port uint16) (l3Rule, bool) {
	if remoteIP == nil {
		return l3Rule{}, false
	}
	v4 := remoteIP.To4()
	if v4 == nil {
		return l3Rule{}, false
	}
	rules := loadL3Rules().rules

	for _, want := range []PriorityClass{PrioritySpecific, PriorityFallback} {
		for _, r := range rules {
			if r.Priority != want {
				continue
			}
			for i := range r.IPMatchers {
				if r.IPMatchers[i].matches(v4, proto, port) {
					return r, true
				}
			}
		}
	}
	return l3Rule{}, false
}

// classifyFlowIPv6 looks up an IPv6 endpoint against rule ipv6_matchers.
func classifyFlowIPv6(remoteIP net.IP, proto matchProto, port uint16) (l3Rule, bool) {
	if remoteIP == nil {
		return l3Rule{}, false
	}
	if remoteIP.To4() != nil {
		return l3Rule{}, false // it's actually v4
	}
	rules := loadL3Rules().rules

	for _, want := range []PriorityClass{PrioritySpecific, PriorityFallback} {
		for _, r := range rules {
			if r.Priority != want {
				continue
			}
			for i := range r.IPv6Matchers {
				if r.IPv6Matchers[i].matches(remoteIP, proto, port) {
					return r, true
				}
			}
		}
	}
	return l3Rule{}, false
}

// classifySubCategory checks if a parent rule has a sub-category that fires
// on the given flow telemetry. Returns the sub-category key (e.g. "voice_call")
// and true if a behavioural detector matched.
//
// pps is the observed packets-per-second on this flow (caller measures it).
// proto/port describe the flow; remoteIP is the server side.
func classifySubCategory(r l3Rule, remoteIP net.IP, proto matchProto, port uint16, pps float64) (string, string, bool) {
	if len(r.SubCategories) == 0 {
		return "", "", false
	}
	for _, sc := range r.SubCategories {
		if sc.DetectIP == nil || sc.DetectPort == 0 || sc.DetectPPSMin <= 0 {
			continue
		}
		if !sc.DetectIP.Contains(remoteIP) {
			continue
		}
		if sc.DetectPort != port {
			continue
		}
		if sc.DetectProto != protoAny && !protoCompatible(sc.DetectProto, proto) {
			continue
		}
		if pps < sc.DetectPPSMin {
			continue
		}
		cat := sc.Category
		if cat == "" {
			cat = r.Category
		}
		return sc.Key, cat, true
	}
	return "", "", false
}
