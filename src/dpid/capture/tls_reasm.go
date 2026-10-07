// Package capture - tls_reasm.go: v5.18 TCP ClientHello 首轮重组。
//
// 背景: Chrome 131+ / Android WebView 默认带 X25519MLKEM768 密钥交换, ClientHello
// 约 1.8KB, 必然拆成两个 TCP 段; 且 Chrome 会随机打乱扩展顺序, server_name
// 大约一半概率落在第二段。以前 dpid 只看第一段且要求 record 完整, 这类连接
// 的 SNI 全部丢失。现在分三层处理:
//
//  1. BPF 对客户端 ClientHello 首段返回 tlsSnaplen(4096), 不再被默认 snaplen
//     1024 截断(GRO 把两段合并成一个大包时也能完整拿到);
//  2. 首段不完整时先做 lenient 解析 —— SNI 在首段里就直接产出(无 JA4);
//  3. SNI 不在首段: 把首段挂进本重组表, 等末段。BPF 用 BoringSSL 的固定
//     结尾特征放行末段: ClientHello 最后一个扩展是 1 字节内容为 0 的 GREASE
//     扩展(xAxA 0001 00), 见 bpf.go。末段 seq 必须正好接上, 拼齐后走完整
//     解析(SNI + ALPN + JA4)。中间段丢失(三段以上的 ClientHello)就放弃 ——
//     IP→域名表仍有 DNS 兜底。
//
// 内存: 最多 tlsAsmMaxEntries 个待重组连接, 每个最多 tlsAsmMaxBytes 字节,
// 条目 tlsAsmTTL 后过期, 满了淘汰最旧的。包级单例(多个 Handle 并发), 全部
// 操作在 mutex 内。

package capture

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// tlsSnaplen: BPF 对客户端 ClientHello 首段 / 末段 / HTTP 请求返回的抓取长度。
	tlsSnaplen = 4096

	tlsAsmMaxEntries = 256
	tlsAsmMaxBytes   = 16 << 10
	tlsAsmTTL        = 3 * time.Second
)

var tlsStats struct {
	partial     atomic.Uint64 // 截断的 ClientHello 里直接取到 SNI
	pending     atomic.Uint64 // 首段挂起等待后续段
	reassembled atomic.Uint64 // 多段重组成功
	gaveUp      atomic.Uint64 // 段不连续 / 超限 / 过期放弃
}

type tlsAsmEntry struct {
	next  uint32 // 期待的下一个 TCP seq
	need  int    // ClientHello record 总字节数(含 5 字节 record 头)
	data  []byte
	first time.Time
}

type tlsReassembler struct {
	mu         sync.Mutex
	maxEntries int
	maxBytes   int
	ttl        time.Duration
	m          map[string]*tlsAsmEntry
	lastSweep  time.Time
}

func newTLSReassembler(maxEntries, maxBytes int, ttl time.Duration) *tlsReassembler {
	return &tlsReassembler{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		ttl:        ttl,
		m:          make(map[string]*tlsAsmEntry),
	}
}

var tlsAsm = newTLSReassembler(tlsAsmMaxEntries, tlsAsmMaxBytes, tlsAsmTTL)

func tcpFlowKey(src net.IP, sport uint16, dst net.IP, dport uint16) string {
	var b [36]byte
	copy(b[0:16], src.To16())
	binary.BigEndian.PutUint16(b[16:], sport)
	copy(b[18:34], dst.To16())
	binary.BigEndian.PutUint16(b[34:], dport)
	return string(b[:])
}

func (r *tlsReassembler) expired(e *tlsAsmEntry, now time.Time) bool {
	return now.Sub(e.first) > r.ttl || now.Before(e.first)
}

func (r *tlsReassembler) sweepLocked(now time.Time) {
	for k, e := range r.m {
		if r.expired(e, now) {
			delete(r.m, k)
			tlsStats.gaveUp.Add(1)
		}
	}
	r.lastSweep = now
}

func (r *tlsReassembler) evictOldestLocked() {
	var oldK string
	var oldT time.Time
	first := true
	for k, e := range r.m {
		if first || e.first.Before(oldT) {
			oldK, oldT, first = k, e.first, false
		}
	}
	if !first {
		delete(r.m, oldK)
		tlsStats.gaveUp.Add(1)
	}
}

func (r *tlsReassembler) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m)
}

// handleSegment 处理一个客户端 → 443 的 TCP 数据段。产出 ClientHello 信息
// 时返回 ok=true。ev 只读(用其 5 元组与 capTrunc)。
func (r *tlsReassembler) handleSegment(ev *Event, seq uint32, data []byte, now time.Time) (TLSInfo, bool) {
	if len(data) == 0 {
		return TLSInfo{}, false
	}
	if data[0] == 0x16 {
		return r.handleFirst(ev, seq, data, now)
	}
	return r.handleCont(ev, seq, data, now)
}

func (r *tlsReassembler) handleFirst(ev *Event, seq uint32, data []byte, now time.Time) (TLSInfo, bool) {
	// 1) 完整 ClientHello: 原路径。
	if info, ok := parseTLSClientHelloFull(data); ok {
		r.drop(ev)
		return info, true
	}
	// 2) 不完整: lenient 解析。不是 ClientHello(比如 TLS1.2 的第二轮握手)
	//    在这里就返回 false。
	ch, ok := parseClientHello(data, true)
	if !ok || ch.complete {
		return TLSInfo{}, false
	}
	if ch.sni != "" {
		tlsStats.partial.Add(1)
		r.drop(ev)
		return TLSInfo{SNI: ch.sni, ALPN: ch.alpn, ECH: ch.ech, Partial: true}, true
	}
	// 3) SNI 不在首段: 挂起等末段。被 snaplen 截断的包后面缺字节, 接不上。
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	need := 5 + recLen
	if ev.capTrunc || need > r.maxBytes || len(data) >= need {
		return TLSInfo{}, false
	}
	key := tcpFlowKey(ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort)
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.lastSweep) > r.ttl || now.Before(r.lastSweep) {
		r.sweepLocked(now)
	}
	if _, exists := r.m[key]; !exists && len(r.m) >= r.maxEntries {
		r.sweepLocked(now)
		for len(r.m) >= r.maxEntries {
			r.evictOldestLocked()
		}
	}
	buf := make([]byte, len(data), need)
	copy(buf, data)
	r.m[key] = &tlsAsmEntry{next: seq + uint32(len(data)), need: need, data: buf, first: now}
	tlsStats.pending.Add(1)
	ev.asmPending = true
	return TLSInfo{}, false
}

func (r *tlsReassembler) handleCont(ev *Event, seq uint32, data []byte, now time.Time) (TLSInfo, bool) {
	key := tcpFlowKey(ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort)
	r.mu.Lock()
	e, ok := r.m[key]
	if !ok {
		r.mu.Unlock()
		return TLSInfo{}, false
	}
	if r.expired(e, now) {
		delete(r.m, key)
		r.mu.Unlock()
		tlsStats.gaveUp.Add(1)
		return TLSInfo{}, false
	}
	if seq != e.next {
		// 重传(完全落在已收范围内)忽略; 其他(中间段丢失 / 乱序)放弃。
		if d := e.next - seq; d != 0 && d < 1<<31 && uint32(len(data)) <= d {
			r.mu.Unlock()
			return TLSInfo{}, false
		}
		delete(r.m, key)
		r.mu.Unlock()
		tlsStats.gaveUp.Add(1)
		return TLSInfo{}, false
	}
	if ev.capTrunc {
		delete(r.m, key)
		r.mu.Unlock()
		tlsStats.gaveUp.Add(1)
		return TLSInfo{}, false
	}
	room := e.need - len(e.data)
	if len(data) > room {
		data = data[:room] // ClientHello 之后紧跟的字节(early data 等)不要
	}
	e.data = append(e.data, data...)
	e.next += uint32(len(data))
	if len(e.data) < e.need {
		r.mu.Unlock()
		return TLSInfo{}, false
	}
	full := e.data
	delete(r.m, key)
	r.mu.Unlock()

	info, ok := parseTLSClientHelloFull(full)
	if !ok {
		tlsStats.gaveUp.Add(1)
		return TLSInfo{}, false
	}
	info.Reassembled = true
	tlsStats.reassembled.Add(1)
	return info, true
}

// drop 移除 ev 所在连接的挂起条目(同一连接又来了新的首段)。
func (r *tlsReassembler) drop(ev *Event) {
	key := tcpFlowKey(ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort)
	r.mu.Lock()
	delete(r.m, key)
	r.mu.Unlock()
}
