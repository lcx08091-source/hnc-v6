// Package capture - quic.go: QUIC(HTTP/3) Initial 包 SNI / JA4 提取。
//
// v5.14: 以前 cBPF 不放行 UDP/443, HTTP/3 流量的域名完全不可见(Chrome /
// Android Cronet / 抖音等大量走 QUIC)。现在 BPF 放行"目的端口 443 且首字节
// 为 long header"的包, 这里在用户态:
//
//  1. 解析 long header(version / DCID / SCID / token / length);
//  2. 按 RFC 9001 / RFC 9369 由 DCID 派生客户端 Initial 密钥(HKDF 手写,
//     go.mod 是 1.22, 没有 crypto/hkdf), 去 header protection、AES-128-GCM
//     解密 payload;
//  3. 解析 frames 收集 CRYPTO 帧, 按 (客户端IP, 端口, DCID) 重组 —— Chrome
//     的 ClientHello 常跨 2~3 个 Initial 且 CRYPTO 帧被故意切碎乱序
//     ("chaos protection");
//  4. ClientHello 完整后包一层 5 字节 TLS record 头, 复用 TCP 路径的
//     parseTLSClientHelloFull(SNI/ALPN/JA4), JA4 首字符改 'q'。
//
// gQUIC Q046 的 CHLO 是明文, 直接在包里找 "CHLO" 消息取 SNI / UAID;
// Q050 及以后是加密的, 只计数跳过。
//
// 解析失败 / 未完整的 Initial 一律 ParseIgnore, 不产出 EventFlow ——
// 以前 BPF 根本不放行这些包, 保持"不计 QUIC 字节"的行为不变。
//
// 重组表是包级单例, 可能被多个 Handle(主抓包 + 自身流量抓包)的 Run
// goroutine 并发调用, 全部操作在 mutex 内完成。

package capture

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// quicSnaplen: QUIC Initial 至少 1200 字节 UDP 载荷(RFC 9000 §14.1), 默认
// snaplen=1024 会截断导致 GCM 认证必然失败。BPF 对 QUIC 分支单独返回
// max(snaplen, quicSnaplen), Handle 的接收缓冲也按它分配。
const quicSnaplen = 2048

// QUIC 版本号。
const (
	quicV1       uint32 = 0x00000001
	quicV2       uint32 = 0x6b3343cf
	quicDraft29  uint32 = 0xff00001d
	quicMaxCIDLn        = 20
)

// v5.14: QUIC 计数。包级原子量(多个 Handle 共用同一份, Stats() 读出的是
// 进程级总数)。
var quicStats struct {
	initial      atomic.Uint64 // 识别为客户端 Initial 的 QUIC 包
	decryptOK    atomic.Uint64
	decryptFail  atomic.Uint64
	sni          atomic.Uint64 // IETF QUIC 成功产出带 SNI 的 ClientHello
	gquicSNI     atomic.Uint64 // gQUIC 明文 CHLO 取到 SNI
	gquicSkipped atomic.Uint64 // gQUIC Q050+ 加密 CHLO, 跳过
}

type quicVersionParams struct {
	salt        []byte
	keyLabel    string
	ivLabel     string
	hpLabel     string
	initialType byte // long header 类型位 (b0>>4)&3 中代表 Initial 的值
}

var (
	quicParamsV1 = &quicVersionParams{
		salt:     []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
		keyLabel: "quic key", ivLabel: "quic iv", hpLabel: "quic hp",
		initialType: 0,
	}
	quicParamsV2 = &quicVersionParams{
		salt:     []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
		keyLabel: "quicv2 key", ivLabel: "quicv2 iv", hpLabel: "quicv2 hp",
		initialType: 1, // RFC 9369 §3.2: v2 的 Initial 类型位是 0b01
	}
	quicParamsDraft29 = &quicVersionParams{
		salt:     []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
		keyLabel: "quic key", ivLabel: "quic iv", hpLabel: "quic hp",
		initialType: 0,
	}
)

func quicParamsFor(v uint32) *quicVersionParams {
	switch v {
	case quicV1:
		return quicParamsV1
	case quicV2:
		return quicParamsV2
	case quicDraft29:
		return quicParamsDraft29
	}
	return nil
}

// ── HKDF(RFC 5869 + TLS 1.3 HKDF-Expand-Label, 仅 SHA-256) ──────────────

func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpand(prk, info []byte, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	var t []byte
	for ctr := byte(1); len(out) < n; ctr++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{ctr})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

// hkdfExpandLabel: struct HkdfLabel { uint16 length; opaque label<7..255> =
// "tls13 " + Label; opaque context<0..255> = "" }。
func hkdfExpandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(n>>8), byte(n), byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	return hkdfExpand(secret, info, n)
}

// quicKeys 是客户端 Initial 方向的保护密钥。原始字节留着给测试断言。
type quicKeys struct {
	secret []byte // client_initial_secret
	key    []byte
	iv     []byte
	hpKey  []byte
	aead   cipher.AEAD
	hp     cipher.Block
}

func deriveQUICClientKeys(p *quicVersionParams, dcid []byte) (*quicKeys, bool) {
	initial := hkdfExtract(p.salt, dcid)
	secret := hkdfExpandLabel(initial, "client in", sha256.Size)
	k := &quicKeys{
		secret: secret,
		key:    hkdfExpandLabel(secret, p.keyLabel, 16),
		iv:     hkdfExpandLabel(secret, p.ivLabel, 12),
		hpKey:  hkdfExpandLabel(secret, p.hpLabel, 16),
	}
	blk, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, false
	}
	k.aead, err = cipher.NewGCM(blk)
	if err != nil {
		return nil, false
	}
	k.hp, err = aes.NewCipher(k.hpKey)
	if err != nil {
		return nil, false
	}
	return k, true
}

// ── Long header ─────────────────────────────────────────────────────────

// quicReadVarint 读 RFC 9000 §16 变长整数。
func quicReadVarint(b []byte) (uint64, int, bool) {
	if len(b) < 1 {
		return 0, 0, false
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, false
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, true
}

type quicLongHeader struct {
	version  uint32
	typ      byte // (b0>>4)&3, 未受 header protection 保护
	dcid     []byte
	scid     []byte
	token    []byte
	pnOffset int // packet number 起始偏移
	end      int // 本 QUIC 包在 UDP 载荷中的结束偏移(pnOffset + Length)
}

// parseQUICLongHeader 解析 v1/v2/draft-29 的 long header(RFC 8999 不变式 +
// RFC 9000 §17.2)。只对 Initial 解析 token; 非 Initial 类型也返回 end,
// 以便跳过 coalesced 包。Retry / 版本协商 / 未知版本返回 ok=false。
func parseQUICLongHeader(b []byte, p *quicVersionParams) (quicLongHeader, bool) {
	var h quicLongHeader
	if len(b) < 7 || b[0]&0x80 == 0 {
		return h, false
	}
	h.version = binary.BigEndian.Uint32(b[1:5])
	h.typ = (b[0] >> 4) & 0x03
	off := 5
	dl := int(b[off])
	off++
	if dl > quicMaxCIDLn || len(b) < off+dl+1 {
		return h, false
	}
	h.dcid = b[off : off+dl]
	off += dl
	sl := int(b[off])
	off++
	if sl > quicMaxCIDLn || len(b) < off+sl {
		return h, false
	}
	h.scid = b[off : off+sl]
	off += sl

	// Retry 没有 Length 字段, 且只由服务器发出。v1: Retry=3; v2: Retry=0。
	retryType := byte(3)
	if p == quicParamsV2 {
		retryType = 0
	}
	if h.typ == retryType {
		return h, false
	}
	if h.typ == p.initialType {
		tl, n, ok := quicReadVarint(b[off:])
		if !ok || tl > uint64(len(b)) {
			return h, false
		}
		off += n
		if len(b) < off+int(tl) {
			return h, false
		}
		h.token = b[off : off+int(tl)]
		off += int(tl)
	}
	ln, n, ok := quicReadVarint(b[off:])
	if !ok || ln > uint64(len(b)) {
		return h, false
	}
	off += n
	if len(b) < off+int(ln) {
		return h, false
	}
	h.pnOffset = off
	h.end = off + int(ln)
	return h, true
}

// quicOpenInitial 去 header protection 并解密一个 Initial 包。pkt 是从
// long header 首字节到 h.end 的切片, 不会被修改(抓包缓冲区会复用)。
func quicOpenInitial(pkt []byte, h *quicLongHeader, k *quicKeys) ([]byte, uint64, bool) {
	// RFC 9001 §5.4.2: sample 取自假定 pn 长 4 字节之后的 16 字节。
	if h.end > len(pkt) || h.pnOffset+4+16 > h.end {
		return nil, 0, false
	}
	var mask [aes.BlockSize]byte
	k.hp.Encrypt(mask[:], pkt[h.pnOffset+4:h.pnOffset+4+16])
	b0 := pkt[0] ^ (mask[0] & 0x0f) // long header 只保护低 4 位
	pnLen := int(b0&0x03) + 1
	if h.pnOffset+pnLen+k.aead.Overhead() > h.end {
		return nil, 0, false
	}
	hdr := make([]byte, h.pnOffset+pnLen)
	copy(hdr, pkt[:h.pnOffset+pnLen])
	hdr[0] = b0
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[h.pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[h.pnOffset+i])
	}
	// 客户端最初几个 Initial 的 pn 很小, 截断值即完整值, 不做 largest_pn 还原。
	nonce := make([]byte, len(k.iv))
	copy(nonce, k.iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	plain, err := k.aead.Open(nil, nonce, pkt[h.pnOffset+pnLen:h.end], hdr)
	if err != nil {
		return nil, 0, false
	}
	return plain, pn, true
}

// ── Frames ──────────────────────────────────────────────────────────────

type quicCryptoFrag struct {
	off  uint64
	data []byte
}

// parseQUICFrames 从解密后的 Initial payload 中收集 CRYPTO 帧。Initial 里
// 合法的帧只有 PADDING/PING/ACK/CRYPTO/CONNECTION_CLOSE; 遇到未知类型就
// 停止(保留已收集的)。帧格式错误返回 ok=false。
func parseQUICFrames(p []byte) ([]quicCryptoFrag, bool) {
	var frags []quicCryptoFrag
	skipVarints := func(n int) bool {
		for i := 0; i < n; i++ {
			_, l, ok := quicReadVarint(p)
			if !ok {
				return false
			}
			p = p[l:]
		}
		return true
	}
	for len(p) > 0 {
		ft, l, ok := quicReadVarint(p)
		if !ok {
			return frags, false
		}
		p = p[l:]
		switch ft {
		case 0x00: // PADDING
			for len(p) > 0 && p[0] == 0 {
				p = p[1:]
			}
		case 0x01: // PING
		case 0x02, 0x03: // ACK / ACK_ECN
			// Largest Acknowledged, ACK Delay, ACK Range Count, First ACK Range
			if !skipVarints(2) {
				return frags, false
			}
			cnt, l, ok := quicReadVarint(p)
			if !ok || cnt > uint64(len(p)) {
				return frags, false
			}
			p = p[l:]
			if !skipVarints(1 + 2*int(cnt)) {
				return frags, false
			}
			if ft == 0x03 && !skipVarints(3) {
				return frags, false
			}
		case 0x06: // CRYPTO
			off, l, ok := quicReadVarint(p)
			if !ok {
				return frags, false
			}
			p = p[l:]
			ln, l, ok := quicReadVarint(p)
			if !ok {
				return frags, false
			}
			p = p[l:]
			if ln > uint64(len(p)) {
				return frags, false
			}
			frags = append(frags, quicCryptoFrag{off: off, data: p[:ln]})
			p = p[ln:]
		case 0x1c, 0x1d: // CONNECTION_CLOSE
			n := 2 // error code, frame type
			if ft == 0x1d {
				n = 1
			}
			if !skipVarints(n) {
				return frags, false
			}
			rl, l, ok := quicReadVarint(p)
			if !ok || rl > uint64(len(p)-l) {
				return frags, false
			}
			p = p[l+int(rl):]
		default:
			return frags, true
		}
	}
	return frags, true
}

// ── 重组 ────────────────────────────────────────────────────────────────

const (
	quicAsmMaxEntries = 256
	quicAsmMaxBytes   = 16 << 10
	quicAsmTTL        = 3 * time.Second
)

type quicAsmEntry struct {
	keys      *quicKeys
	data      []byte   // 按 CRYPTO offset 就位的字节
	ivs       [][2]int // 已覆盖区间 [start,end), 有序且不相交
	firstSeen time.Time
	lastSeen  time.Time
	done      bool // ClientHello 已产出或已放弃, 后续同 key 包直接忽略
}

// addFrag 把一段 CRYPTO 数据放到位并合并覆盖区间。超过 maxBytes 返回 false。
func (e *quicAsmEntry) addFrag(off uint64, data []byte, maxBytes int) bool {
	if off > uint64(maxBytes) || off+uint64(len(data)) > uint64(maxBytes) {
		return false
	}
	if len(data) == 0 {
		return true
	}
	s, t := int(off), int(off)+len(data)
	if t > len(e.data) {
		if t > cap(e.data) {
			nd := make([]byte, t, max(t, 2*cap(e.data)))
			copy(nd, e.data)
			e.data = nd
		} else {
			e.data = e.data[:t]
		}
	}
	copy(e.data[s:t], data)
	// 合并区间: 把与 [s,t) 相交或相邻的都并进来。
	out := e.ivs[:0:0]
	inserted := false
	for _, iv := range e.ivs {
		switch {
		case iv[1] < s:
			out = append(out, iv)
		case iv[0] > t:
			if !inserted {
				out = append(out, [2]int{s, t})
				inserted = true
			}
			out = append(out, iv)
		default:
			s = min(s, iv[0])
			t = max(t, iv[1])
		}
	}
	if !inserted {
		out = append(out, [2]int{s, t})
	}
	e.ivs = out
	return true
}

// clientHello 返回从 offset 0 起连续且完整的 ClientHello handshake 消息
// (裸 handshake, 不含 record 头)。bad=true 表示数据不可能是 ClientHello
// 或声明长度超限, 调用方应放弃该 entry。
func (e *quicAsmEntry) clientHello(maxBytes int) (hello []byte, bad bool) {
	if len(e.ivs) == 0 || e.ivs[0][0] != 0 {
		return nil, false
	}
	prefix := e.ivs[0][1]
	if prefix < 1 {
		return nil, false
	}
	if e.data[0] != 0x01 {
		return nil, true
	}
	if prefix < 4 {
		return nil, false
	}
	total := 4 + (int(e.data[1])<<16 | int(e.data[2])<<8 | int(e.data[3]))
	if total > maxBytes {
		return nil, true
	}
	if prefix < total {
		return nil, false
	}
	return e.data[:total], false
}

type quicReassembler struct {
	mu         sync.Mutex
	maxEntries int
	maxBytes   int
	ttl        time.Duration
	m          map[string]*quicAsmEntry
	// finished: (IP, 端口) → ClientHello 完成时刻。服务器回 Initial 后客户端
	// 改用服务器选的 DCID 发 ACK 用的 Initial, 但密钥仍由原始 DCID 派生,
	// 用新 DCID 派生必然解密失败 —— 同一四元组已完成就直接忽略, 避免误计
	// QUICDecryptFail 和白做 HKDF。
	finished  map[string]time.Time
	lastSweep time.Time
}

func newQUICReassembler(maxEntries, maxBytes int, ttl time.Duration) *quicReassembler {
	return &quicReassembler{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		ttl:        ttl,
		m:          make(map[string]*quicAsmEntry),
		finished:   make(map[string]time.Time),
	}
}

var quicAsm = newQUICReassembler(quicAsmMaxEntries, quicAsmMaxBytes, quicAsmTTL)

// sweepLocked 清掉过期 entry / finished 记录。
func (r *quicReassembler) sweepLocked(now time.Time) {
	for k, e := range r.m {
		if now.Sub(e.firstSeen) > r.ttl || now.Before(e.firstSeen) {
			delete(r.m, k)
		}
	}
	for k, t := range r.finished {
		if now.Sub(t) > r.ttl || now.Before(t) {
			delete(r.finished, k)
		}
	}
	r.lastSweep = now
}

// evictLRULocked 淘汰最久未更新的 entry。
func (r *quicReassembler) evictLRULocked() {
	var oldK string
	var oldT time.Time
	first := true
	for k, e := range r.m {
		if first || e.lastSeen.Before(oldT) {
			oldK, oldT, first = k, e.lastSeen, false
		}
	}
	if !first {
		delete(r.m, oldK)
	}
}

func (r *quicReassembler) markFinishedLocked(tuple string, now time.Time) {
	if _, ok := r.finished[tuple]; !ok && len(r.finished) >= r.maxEntries {
		var oldK string
		var oldT time.Time
		first := true
		for k, t := range r.finished {
			if first || t.Before(oldT) {
				oldK, oldT, first = k, t, false
			}
		}
		delete(r.finished, oldK)
	}
	r.finished[tuple] = now
}

func quicTupleKey(ip net.IP, port uint16) string {
	var b [18]byte
	copy(b[:16], ip.To16())
	binary.BigEndian.PutUint16(b[16:], port)
	return string(b[:])
}

// handleInitial 处理一个客户端 Initial 包。ClientHello 完整时返回它的拷贝。
func (r *quicReassembler) handleInitial(ip net.IP, port uint16, h *quicLongHeader, pkt []byte, p *quicVersionParams, now time.Time) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()

	if now.Sub(r.lastSweep) > r.ttl || now.Before(r.lastSweep) {
		r.sweepLocked(now)
	}
	tuple := quicTupleKey(ip, port)
	key := tuple + string(h.dcid)
	e := r.m[key]
	if e != nil && (now.Sub(e.firstSeen) > r.ttl || now.Before(e.firstSeen)) {
		delete(r.m, key)
		e = nil
	}
	if e == nil {
		if t, ok := r.finished[tuple]; ok && now.Sub(t) <= r.ttl && !now.Before(t) {
			return nil
		}
	} else if e.done {
		return nil
	}

	created := false
	if e == nil {
		k, ok := deriveQUICClientKeys(p, h.dcid)
		if !ok {
			return nil
		}
		if len(r.m) >= r.maxEntries {
			r.sweepLocked(now)
			for len(r.m) >= r.maxEntries {
				r.evictLRULocked()
			}
		}
		e = &quicAsmEntry{keys: k, firstSeen: now}
		r.m[key] = e
		created = true
	}
	e.lastSeen = now

	plain, _, ok := quicOpenInitial(pkt, h, e.keys)
	if !ok {
		quicStats.decryptFail.Add(1)
		// 首包就失败(伪造 / 非客户端首个 DCID)不留 entry, 免得垃圾包占满表。
		if created {
			delete(r.m, key)
		}
		return nil
	}
	quicStats.decryptOK.Add(1)

	frags, _ := parseQUICFrames(plain)
	for _, f := range frags {
		if !e.addFrag(f.off, f.data, r.maxBytes) {
			e.done, e.data, e.ivs = true, nil, nil
			return nil
		}
	}
	hello, bad := e.clientHello(r.maxBytes)
	if bad {
		e.done, e.data, e.ivs = true, nil, nil
		return nil
	}
	if hello == nil {
		return nil
	}
	out := append([]byte(nil), hello...)
	// 完成后由 finished(四元组级)挡住后续 Initial, entry 本身不再占表位。
	delete(r.m, key)
	r.markFinishedLocked(tuple, now)
	return out
}

// ── 入口 ────────────────────────────────────────────────────────────────

// parseQUIC 处理目的端口 443、首字节为 long header 的 UDP 载荷。只有拿到
// 完整 ClientHello(或 gQUIC 明文 CHLO)才产出 EventTLSClientHello, 其余一律
// ParseIgnore。
func parseQUIC(ev Event, udp []byte) (Event, ParseResult) {
	if len(udp) < 7 || udp[0]&0x80 == 0 {
		return ev, ParseIgnore
	}
	if udp[1] == 'Q' {
		return parseGQUIC(ev, udp)
	}

	b := udp
	// 一个 UDP 数据报可能 coalesce 多个 QUIC 包(Initial + 0-RTT 等)。
	for i := 0; i < 4 && len(b) >= 7 && b[0]&0x80 != 0; i++ {
		p := quicParamsFor(binary.BigEndian.Uint32(b[1:5]))
		if p == nil {
			break
		}
		h, ok := parseQUICLongHeader(b, p)
		if !ok {
			break
		}
		pkt := b[:h.end]
		b = b[h.end:]
		if h.typ != p.initialType {
			continue
		}
		quicStats.initial.Add(1)
		hello := quicAsm.handleInitial(ev.SrcIP, ev.SrcPort, &h, pkt, p, ev.Time)
		if hello == nil {
			continue
		}
		// parseTLSClientHelloFull / extractJA4Inputs 期望 TLS record 层数据,
		// QUIC CRYPTO 流里是裸 handshake, 包一层 5 字节 record 头。
		rec := make([]byte, 5+len(hello))
		rec[0], rec[1], rec[2] = 0x16, 0x03, 0x01
		binary.BigEndian.PutUint16(rec[3:5], uint16(len(hello)))
		copy(rec[5:], hello)
		sni, alpn, ja4, ok := parseTLSClientHelloFull(rec)
		if !ok {
			return ev, ParseIgnore
		}
		ev.Kind = EventTLSClientHello
		ev.TLS = TLSInfo{SNI: sni, ALPN: alpn, JA4: quicJA4(ja4), IsQUIC: true}
		if sni != "" {
			quicStats.sni.Add(1)
		}
		assignClient(&ev, false)
		return ev, ParseOK
	}
	return ev, ParseIgnore
}

// quicJA4: JA4 规范里 QUIC 的协议位是 'q'(TCP 为 't')。output.ComputeJA4
// 固定输出 't' 开头, 在这里替换首字符, 不改 output 包。
func quicJA4(ja4 string) string {
	if ja4 == "" || ja4[0] != 't' {
		return ja4
	}
	return "q" + ja4[1:]
}

// parseGQUIC 处理 Google QUIC。Q046 的 Initial 以 NULL 加密(明文 + 12 字节
// FNV 哈希), CHLO 消息在 crypto stream 里明文可见: 直接定位 "CHLO" 标签
// 再按 tag 表取值, 无需精确解析 gQUIC 帧格式。Q047+ (Q050 等) 已改为 Initial
// 加密, 只计数跳过。Q043 用旧的 public header(首字节无 0x80), BPF 层就不会放行。
func parseGQUIC(ev Event, udp []byte) (Event, ParseResult) {
	ver := udp[1:5]
	for _, c := range ver[1:] {
		if c < '0' || c > '9' {
			return ev, ParseIgnore
		}
	}
	n := int(ver[1]-'0')*100 + int(ver[2]-'0')*10 + int(ver[3]-'0')
	if n < 43 {
		return ev, ParseIgnore
	}
	if n > 46 {
		quicStats.gquicSkipped.Add(1)
		return ev, ParseIgnore
	}
	idx := bytes.Index(udp[5:], []byte("CHLO"))
	if idx < 0 {
		return ev, ParseIgnore
	}
	tags, ok := parseGQUICMessage(udp[5+idx:])
	if !ok {
		return ev, ParseIgnore
	}
	sni := strings.ToLower(string(tags["SNI\x00"]))
	if !validHostname(sni) {
		return ev, ParseIgnore
	}
	ev.Kind = EventTLSClientHello
	ev.TLS = TLSInfo{SNI: sni, IsQUIC: true}
	if ua := tags["UAID"]; len(ua) > 0 && len(ua) <= 256 {
		ev.TLS.UserAgent = string(ua)
	}
	quicStats.gquicSNI.Add(1)
	assignClient(&ev, false)
	return ev, ParseOK
}

// parseGQUICMessage 解析 gQUIC crypto handshake 消息:
// tag(4) | num_entries(uint16 LE) | padding(2) | {tag(4), end_offset(uint32 LE)}* | values。
// 只返回 SNI / UAID 两个关心的 tag。
func parseGQUICMessage(b []byte) (map[string][]byte, bool) {
	if len(b) < 8 || string(b[:4]) != "CHLO" {
		return nil, false
	}
	num := int(binary.LittleEndian.Uint16(b[4:6]))
	if num == 0 || num > 128 {
		return nil, false
	}
	tbl := 8
	vals := tbl + num*8
	if len(b) < vals {
		return nil, false
	}
	out := make(map[string][]byte, 2)
	prev := 0
	for i := 0; i < num; i++ {
		ent := b[tbl+i*8 : tbl+i*8+8]
		end := int(binary.LittleEndian.Uint32(ent[4:8]))
		if end < prev || vals+end > len(b) {
			// 值区被截断(超出本包)时, 只要已拿到 SNI 就够用。
			break
		}
		tag := string(ent[:4])
		if tag == "SNI\x00" || tag == "UAID" {
			out[tag] = b[vals+prev : vals+end]
		}
		prev = end
	}
	if len(out["SNI\x00"]) == 0 {
		return nil, false
	}
	return out, true
}

func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	return true
}
