// Package output - evidence_ledger.go: accumulates evidence per (clientMAC, appID) pair.
//
// Why: app attribution is probabilistic — multiple signals (flow, TLS, DNS, SNI)
// contribute evidence toward attributing a client's traffic to a specific app.
// The ledger provides a bounded, thread-safe store of these evidence entries,
// supporting log-odds scoring and parent event linkage for debugging.
//
// 回移自 5.9.91 分叉(v5.9.6 评估时未收, 本版补全语义后合入), 修复其两处缺陷:
//  1. maxTotal 从未强制 —— Add 只看 per-key 上限, 键数无界。现在超总量时
//     丢弃"最久没有新证据"的 key(按各 key 最后一条 Ts 排序);
//  2. LogOddsDelta 从未被写入 —— 分叉只声明了字段, 权重表从未设计。现在
//     Add 按来源自动填(调用方传零值), 初值经人工标定:
//     tls=2.0(SNI 强信号,domain 级) dns=1.5(解析请求,弱一级)
//     sni=1.0(self_attrib 侧保留) flow=0.5(IP/端口级,最弱)。
//     自然对数底,累计 log-odds 过阈(如 ≥3.0 ≈ 后验 95%)即可视为高置信。
//
// Implementation: per-key 滚动窗口(满员丢最旧) + 全局总量上限。Thread-safe
// via RWMutex。Snapshot 供 JSON 导出,Trim 按时间裁剪(Flush 低频调用)。

package output

import (
	"sort"
	"sync"
	"time"
)

// EvidenceSource identifies where evidence came from
type EvidenceSource string

const (
	SrcFlow EvidenceSource = "flow"
	SrcTLS  EvidenceSource = "tls"
	SrcDNS  EvidenceSource = "dns"
	SrcSNI  EvidenceSource = "sni"
)

// evidenceLogOdds 是每个证据来源的 log-odds 权重(v5.9.7 自定义语义,
// 分叉从未实现)。Add 按来源自动填充 LogOddsDelta。
var evidenceLogOdds = map[EvidenceSource]float64{
	SrcTLS: 2.0, // SNI 命中: domain 级强信号
	SrcDNS: 1.5, // DNS 解析请求: 弱一级(可能只是预解析/CNAME 链)
	SrcSNI: 1.0, // self_attrib 侧 SNI(self-capture, 保留档)
	SrcFlow: 0.5, // IP/端口级命中: 最弱(CDN 共享 IP 会误伤)
}

// EvidenceEntry is a single piece of evidence for app attribution
type EvidenceEntry struct {
	Ts            time.Time      `json:"ts"`
	Source        EvidenceSource `json:"src"`
	RuleID        string         `json:"rule_id,omitempty"`
	LogOddsDelta  float64        `json:"lod,omitempty"` // log-odds contribution (Add 自动填)
	ParentEventID string         `json:"pid,omitempty"` // 父事件指纹(flowKey / host)
	Detail        string         `json:"detail,omitempty"`
}

// EvidenceLedger accumulates evidence per (clientMAC, appID) pair
type EvidenceLedger struct {
	mu        sync.RWMutex
	entries   map[string][]EvidenceEntry // key: "mac:appid"
	maxPerKey int
	maxTotal  int
}

func NewEvidenceLedger(maxPerKey, maxTotal int) *EvidenceLedger {
	return &EvidenceLedger{
		entries:   make(map[string][]EvidenceEntry),
		maxPerKey: maxPerKey,
		maxTotal:  maxTotal,
	}
}

func (el *EvidenceLedger) Add(clientMAC, appID string, e EvidenceEntry) {
	el.mu.Lock()
	defer el.mu.Unlock()
	// 分叉遗留缺陷修复: LogOddsDelta 按来源自动补权(调用方零值即可)
	if e.LogOddsDelta == 0 {
		e.LogOddsDelta = evidenceLogOdds[e.Source]
	}
	key := clientMAC + ":" + appID
	entries := el.entries[key]
	if len(entries) >= el.maxPerKey {
		entries = entries[1:] // drop oldest
	}
	el.entries[key] = append(entries, e)

	// 分叉遗留缺陷修复: 全局总量上限(原 maxTotal 是死参数)
	el.enforceTotalLocked()
}

// enforceTotalLocked 超总量时丢"最久没有新证据"的 key。
// 只在 Add 后调用, 摊销后每条证据 O(1)~O(keys)(超限才扫)。
func (el *EvidenceLedger) enforceTotalLocked() {
	if el.maxTotal <= 0 {
		return
	}
	total := 0
	for _, v := range el.entries {
		total += len(v)
	}
	if total <= el.maxTotal {
		return
	}
	// 按 key 的最后一条证据时间从旧到新丢, 直到回到限内
	type keyLast struct {
		key  string
		last time.Time
	}
	keys := make([]keyLast, 0, len(el.entries))
	for k, v := range el.entries {
		keys = append(keys, keyLast{k, v[len(v)-1].Ts})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].last.Before(keys[j].last) })
	for _, kl := range keys {
		if total <= el.maxTotal {
			break
		}
		total -= len(el.entries[kl.key])
		delete(el.entries, kl.key)
	}
}

func (el *EvidenceLedger) Snapshot() map[string][]EvidenceEntry {
	el.mu.RLock()
	defer el.mu.RUnlock()
	result := make(map[string][]EvidenceEntry, len(el.entries))
	for k, v := range el.entries {
		cp := make([]EvidenceEntry, len(v))
		copy(cp, v)
		result[k] = cp
	}
	return result
}

func (el *EvidenceLedger) Size() int {
	el.mu.RLock()
	defer el.mu.RUnlock()
	total := 0
	for _, v := range el.entries {
		total += len(v)
	}
	return total
}

func (el *EvidenceLedger) Trim(maxAge time.Duration) {
	el.mu.Lock()
	defer el.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, entries := range el.entries {
		i := 0
		for _, e := range entries {
			if e.Ts.After(cutoff) {
				entries[i] = e
				i++
			}
		}
		if i == 0 {
			delete(el.entries, key)
		} else {
			el.entries[key] = entries[:i]
		}
	}
}
