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
	"sync/atomic"
)

// classifyHost looks up a DNS qname or TLS SNI string against rule suffixes.
// Returns the longest-matching suffix in the highest priority bucket.
//
// v5.13: 由"每次线性扫全部规则的全部后缀"改为后缀索引查找(见 hostIndex)。
// 语义与旧实现(classifyHostLinear, 仅测试保留)逐条等价:
//   - PrioritySpecific 优先于 PriorityFallback;
//   - 同优先级最长后缀胜出;
//   - 同一后缀被多条规则声明时, 规则列表中靠前的胜出(旧实现 len > bestLen
//     严格大于, 先到先得)。
func classifyHost(host string) (l3Rule, bool) {
	host = normalizeName(host)
	if host == "" {
		return l3Rule{}, false
	}
	lr := loadL3Rules()
	idx := hostIndexFor(lr.rules)
	if i, ok := idx.lookup(host); ok {
		return lr.rules[i], true
	}
	return l3Rule{}, false
}

// hostIndex 是规则后缀的倒排索引: 规范化后缀 → 各优先级下声明该后缀的
// 第一条规则下标。查找时对 host 自身及每个 "." 之后的尾串(从长到短)查
// map, 第一个命中的即最长后缀 —— 与 host == suf || HasSuffix(host, "."+suf)
// 完全同构(后者成立当且仅当 suf 等于 host 在某个 '.' 之后的尾串)。
type hostIndex struct {
	rulesPtr *l3Rule // 构建时 rules[0] 的地址 + 长度, 用来判定规则集是否换了
	rulesLen int
	bySuffix map[string][2]int32 // [PrioritySpecific, PriorityFallback] → 规则下标, -1 = 无
}

var hostIndexCache atomic.Pointer[hostIndex]

// hostIndexFor 返回与 rules 对应的索引; 规则重载(loadL3Rules 返回了新切片)
// 时重建。并发重建是幂等的, 谁后写谁留下, 不影响正确性。
func hostIndexFor(rules []l3Rule) *hostIndex {
	var p *l3Rule
	if len(rules) > 0 {
		p = &rules[0]
	}
	if cur := hostIndexCache.Load(); cur != nil && cur.rulesPtr == p && cur.rulesLen == len(rules) {
		return cur
	}
	idx := buildHostIndex(rules)
	hostIndexCache.Store(idx)
	return idx
}

func buildHostIndex(rules []l3Rule) *hostIndex {
	idx := &hostIndex{rulesLen: len(rules), bySuffix: make(map[string][2]int32, 1024)}
	if len(rules) > 0 {
		idx.rulesPtr = &rules[0]
	}
	for i := range rules {
		r := &rules[i]
		pri := 0
		switch r.Priority {
		case PrioritySpecific:
			pri = 0
		case PriorityFallback:
			pri = 1
		default:
			continue // 旧实现只遍历这两个桶, 其余优先级永不命中
		}
		for _, suf := range r.Suffixes {
			// 与旧实现相同的逐后缀规范化。
			suf = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(suf), "."))
			if suf == "" {
				continue
			}
			slot, ok := idx.bySuffix[suf]
			if !ok {
				slot = [2]int32{-1, -1}
			}
			if slot[pri] < 0 { // 先到先得
				slot[pri] = int32(i)
			}
			idx.bySuffix[suf] = slot
		}
	}
	return idx
}

// lookup 返回命中规则下标。先在 Specific 桶里找最长后缀, 找不到再找 Fallback。
func (idx *hostIndex) lookup(host string) (int, bool) {
	for pri := 0; pri < 2; pri++ {
		tail := host
		for {
			if slot, ok := idx.bySuffix[tail]; ok && slot[pri] >= 0 {
				return int(slot[pri]), true
			}
			dot := strings.IndexByte(tail, '.')
			if dot < 0 {
				break
			}
			tail = tail[dot+1:]
		}
	}
	return -1, false
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
