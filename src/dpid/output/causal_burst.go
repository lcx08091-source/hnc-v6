// Package output - causal_burst.go: HNC v5.38.0 零样本 120ms 门控时间因果突发传播引擎 (Gated Temporal Causal Burst Propagation)
//
// 核心机制 (完全零训练样本!):
//
//	当热点客户端点开某个 App 瞬间, 主业务控制流往往率先命中 1 条高置信度 SNI/DNS 规则锚点(如 aweme.snssdk.com),
//	随后 [-15ms, +120ms] 极窄突发窗口内会并发拉起多条无 SNI 直连 IP 流、ECH 遮蔽流或公共 CDN QUIC 流。
//	本引擎为每台客户端维护零堆分配的 8 槽环形锚点缓冲, 并在满足以下安全门控时将应用身份传播给同突发盲流:
//	  1) 80ms 多源冲突一票否决: 同客户端窗口内若同时出现 >=2 个不同前台应用的确定性锚点, 立即终止传染防串味;
//	  2) 协议栈家族 / 目的 /24 前缀 / 手游战斗 UDP 亲和度加权 + 指数时间衰减 w(dt)=exp(-dt/60ms);
//	  3) 一旦绑定成功即将 (ClientMAC, FlowKey) 记入连接级短缓存, 后续数据包 O(1) 命中!
package output

import (
	"math"
	"net/netip"
	"strings"
	"sync"
)

const (
	causalForwardWindowMs  = 120
	causalConflictWindowMs = 80
	causalDecayTauMs       = 60.0
	causalMinScore         = 0.56
	causalFlowTTLSec       = 180
	causalRingSlots        = 8
	causalFlowCacheMax     = 128
)

type CausalAnchor struct {
	TsMs      int64
	Rule      l3Rule
	TLSFP     string
	QTP       string
	DstPrefix netip.Prefix
}

type causalBoundFlow struct {
	Rule   l3Rule
	ExpSec int64
}

type clientCausalRing struct {
	anchors [causalRingSlots]CausalAnchor
	head    int
	count   int
	bound   map[string]causalBoundFlow
}

type CausalBurstEngine struct {
	mu      sync.Mutex
	clients map[string]*clientCausalRing
	hits    uint64
}

func NewCausalBurstEngine() *CausalBurstEngine {
	return &CausalBurstEngine{
		clients: make(map[string]*clientCausalRing, 16),
	}
}

func ipToCausalPrefix(ipStr string) netip.Prefix {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || !addr.IsValid() {
		return netip.Prefix{}
	}
	if addr.Is4() {
		p, _ := addr.Prefix(24)
		return p
	}
	p, _ := addr.Prefix(48)
	return p
}

// RecordAnchor 在客户端命中非底层 SDK/非隧道的真实应用规则时登记时间因果锚点
func (e *CausalBurstEngine) RecordAnchor(clientKey string, tsMs int64, rule l3Rule, remoteIPStr, tlsfp, qtp string) {
	if e == nil || clientKey == "" || rule.ID == "" || strings.HasPrefix(rule.ID, "_") || AppTier(rule.Category) == TierHidden {
		return
	}
	pfx := ipToCausalPrefix(remoteIPStr)
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.clients[clientKey]
	if st == nil {
		if len(e.clients) >= 512 {
			for k := range e.clients {
				delete(e.clients, k)
				break
			}
		}
		st = &clientCausalRing{bound: make(map[string]causalBoundFlow, 16)}
		e.clients[clientKey] = st
	}
	st.anchors[st.head] = CausalAnchor{
		TsMs:      tsMs,
		Rule:      rule,
		TLSFP:     tlsfp,
		QTP:       qtp,
		DstPrefix: pfx,
	}
	st.head = (st.head + 1) % causalRingSlots
	if st.count < causalRingSlots {
		st.count++
	}
}

// LookupOrPropagate 先查已绑定的流级归因缓存; 未命中则在 120ms 门控窗口内执行时间因果传播
func (e *CausalBurstEngine) LookupOrPropagate(
	clientKey, flowKey string, tsMs int64, remoteIPStr, tlsfp, qtp string, isUDP bool, port uint16,
) (l3Rule, bool) {
	if e == nil || clientKey == "" || flowKey == "" {
		return l3Rule{}, false
	}
	nowSec := tsMs / 1000
	pfx := ipToCausalPrefix(remoteIPStr)

	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.clients[clientKey]
	if st == nil {
		return l3Rule{}, false
	}
	if bf, ok := st.bound[flowKey]; ok {
		if bf.ExpSec > nowSec {
			bf.ExpSec = nowSec + causalFlowTTLSec
			st.bound[flowKey] = bf
			return bf.Rule, true
		}
		delete(st.bound, flowKey)
	}
	if st.count == 0 {
		return l3Rule{}, false
	}

	var best *CausalAnchor
	conflictApp := ""
	for i := 0; i < st.count; i++ {
		idx := (st.head - 1 - i + causalRingSlots) % causalRingSlots
		anc := &st.anchors[idx]
		dt := tsMs - anc.TsMs
		if dt < -15 || dt > causalForwardWindowMs {
			continue
		}
		absDt := dt
		if absDt < 0 {
			absDt = -absDt
		}
		if absDt <= causalConflictWindowMs {
			if conflictApp == "" {
				conflictApp = anc.Rule.ID
			} else if conflictApp != anc.Rule.ID {
				// 同窗口多前台 App 并发冲突 -> 一票否决防止误传染!
				return l3Rule{}, false
			}
		}
		if best == nil {
			best = anc
		}
	}
	if best == nil {
		return l3Rule{}, false
	}

	dt := math.Abs(float64(tsMs - best.TsMs))
	score := 0.42 * math.Exp(-dt/causalDecayTauMs)

	// 1. 目的子网亲和度 (同 /24 或 /48 边缘集群)
	if pfx.IsValid() && pfx == best.DstPrefix {
		score += 0.34
	}
	// 2. 握手栈亲和度
	if tlsfp != "" && best.TLSFP != "" {
		if tlsfp == best.TLSFP {
			score += 0.40
		} else if sameTLSStackFamily(tlsfp, best.TLSFP) {
			score += 0.26
		}
	}
	if qtp != "" && qtp == best.QTP {
		score += 0.22
	}
	// 3. QUIC 443 并发媒体流或手游登录锚点后紧跟非 443 战斗 UDP 流
	if isUDP && port == 443 && dt <= 65 {
		score += 0.24
	} else if isUDP && port >= 1024 && best.Rule.Category == "game" && dt <= 95 {
		score += 0.32
	} else if !isUDP && port == 443 && dt <= 55 {
		score += 0.22
	}

	if score < causalMinScore {
		return l3Rule{}, false
	}

	if len(st.bound) >= causalFlowCacheMax {
		for k, v := range st.bound {
			if v.ExpSec <= nowSec {
				delete(st.bound, k)
			}
		}
		if len(st.bound) >= causalFlowCacheMax {
			for k := range st.bound {
				delete(st.bound, k)
				break
			}
		}
	}
	st.bound[flowKey] = causalBoundFlow{Rule: best.Rule, ExpSec: nowSec + causalFlowTTLSec}
	e.hits++
	return best.Rule, true
}

func (e *CausalBurstEngine) Hits() uint64 {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.hits
}

func sameTLSStackFamily(a, b string) bool {
	pa, pb := strings.Split(a, "_"), strings.Split(b, "_")
	if len(pa) >= 4 && len(pb) >= 4 && pa[3] != "" && pa[3] == pb[3] {
		return true
	}
	return len(pa) >= 2 && len(pb) >= 2 && pa[1] == pb[1]
}
