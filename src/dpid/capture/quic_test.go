package capture

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"
)

// v5.14: QUIC Initial 解密 / 重组 / gQUIC CHLO 测试。

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	s = strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s)
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// resetQUICState 给每个测试一张干净的重组表, 返回恢复函数。
func resetQUICState(t testing.TB) {
	t.Helper()
	old := quicAsm
	quicAsm = newQUICReassembler(quicAsmMaxEntries, quicAsmMaxBytes, quicAsmTTL)
	t.Cleanup(func() { quicAsm = old })
}

// ── RFC 9001 Appendix A ────────────────────────────────────────────────

const rfc9001DCID = "8394c8f03e515708"

// RFC 9001 A.2: 客户端 Initial 的 CRYPTO 帧(ClientHello, SNI=example.com)。
const rfc9001CryptoFrame = `
060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868
04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578
616d706c652e636f6dff01000100000a00080006001d00170018001000070005
04616c706e000500050100000000003300260024001d00209370b2c9caa47fba
baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400
0d0010000e0403050306030203080408050806002d00020101001c0002400100
3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000
75300901100f088394c8f03e51570806048000ffff`

// RFC 9001 A.2: 未保护的 header 与最终受保护的完整 1200 字节报文。
const rfc9001UnprotHeader = "c300000001088394c8f03e5157080000449e00000002"

const rfc9001ProtectedPacket = `
c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11
d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399
1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c
8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212
30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5
457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208
4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec
4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3
485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db
059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c
7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8
9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556
be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74
68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a
c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00
f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632
291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964
25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd
14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff
ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198
e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd
c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73
203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f
cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e
fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade
a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047
90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2
162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4
40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0
6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e
8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0
be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400
54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab
760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9
f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4
056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064
7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241
e221af44860018ab0856972e194cd934`

func TestQUICKeyDerivationRFC9001(t *testing.T) {
	dcid := mustHex(t, rfc9001DCID)
	// A.1 initial_secret
	initial := hkdfExtract(quicParamsV1.salt, dcid)
	if got, want := hex.EncodeToString(initial), "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"; got != want {
		t.Fatalf("initial_secret=%s want %s", got, want)
	}
	k, ok := deriveQUICClientKeys(quicParamsV1, dcid)
	if !ok {
		t.Fatal("derive failed")
	}
	checks := []struct{ name, got, want string }{
		{"client_initial_secret", hex.EncodeToString(k.secret), "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"},
		{"key", hex.EncodeToString(k.key), "1f369613dd76d5467730efcbe3b1a22d"},
		{"iv", hex.EncodeToString(k.iv), "fa044b2f42a3fd3b46fb255c"},
		{"hp", hex.EncodeToString(k.hpKey), "9f50449e04a0e810283a1e9933adedd2"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s=%s want %s", c.name, c.got, c.want)
		}
	}
	// A.1 服务器方向(同一 HKDF-Expand-Label, 标签 "server in"), 顺带校验。
	ss := hkdfExpandLabel(initial, "server in", 32)
	if got, want := hex.EncodeToString(ss), "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"; got != want {
		t.Errorf("server_initial_secret=%s want %s", got, want)
	}
	if got, want := hex.EncodeToString(hkdfExpandLabel(ss, "quic key", 16)), "cf3a5331653c364c88f0f379b6067e37"; got != want {
		t.Errorf("server key=%s want %s", got, want)
	}
}

func TestQUICKeyDerivationRFC9369(t *testing.T) {
	k, ok := deriveQUICClientKeys(quicParamsV2, mustHex(t, rfc9001DCID))
	if !ok {
		t.Fatal("derive failed")
	}
	checks := []struct{ name, got, want string }{
		{"client_initial_secret", hex.EncodeToString(k.secret), "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b"},
		{"key", hex.EncodeToString(k.key), "8b1a0bc121284290a29e0971b5cd045d"},
		{"iv", hex.EncodeToString(k.iv), "91f73e2351d8fa91660e909f"},
		{"hp", hex.EncodeToString(k.hpKey), "45b95e15235d6f45a6b19cbcb0294ba9"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("v2 %s=%s want %s", c.name, c.got, c.want)
		}
	}
}

// rfc9001Plaintext: A.2 的 payload = CRYPTO 帧 + PADDING 到 1162 字节。
func rfc9001Plaintext(t testing.TB) []byte {
	cf := mustHex(t, rfc9001CryptoFrame)
	if len(cf) != 245 {
		t.Fatalf("crypto frame len=%d want 245", len(cf))
	}
	p := make([]byte, 1162)
	copy(p, cf)
	return p
}

func TestQUICDecryptRFC9001ClientInitial(t *testing.T) {
	resetQUICState(t)
	pkt := mustHex(t, rfc9001ProtectedPacket)
	if len(pkt) != 1200 {
		t.Fatalf("packet len=%d want 1200", len(pkt))
	}
	h, ok := parseQUICLongHeader(pkt, quicParamsV1)
	if !ok {
		t.Fatal("long header parse failed")
	}
	if h.version != quicV1 || h.typ != 0 || hex.EncodeToString(h.dcid) != rfc9001DCID ||
		len(h.scid) != 0 || len(h.token) != 0 || h.pnOffset != 18 || h.end != 1200 {
		t.Fatalf("header mismatch: %+v", h)
	}
	k, _ := deriveQUICClientKeys(quicParamsV1, h.dcid)
	plain, pn, ok := quicOpenInitial(pkt, &h, k)
	if !ok {
		t.Fatal("GCM open failed on RFC 9001 A.2 packet")
	}
	if pn != 2 {
		t.Errorf("pn=%d want 2", pn)
	}
	if !bytes.Equal(plain, rfc9001Plaintext(t)) {
		t.Errorf("plaintext mismatch")
	}
	frags, ok := parseQUICFrames(plain)
	if !ok || len(frags) != 1 || frags[0].off != 0 || len(frags[0].data) != 241 {
		t.Fatalf("frames: ok=%v %+v", ok, frags)
	}
	// 加密方向(测试用 sealQUICInitial)必须逐字节复现 RFC 报文。
	sealed := sealQUICInitial(t, quicParamsV1, h.dcid, nil, nil, 2, 4, rfc9001Plaintext(t))
	if !bytes.Equal(sealed, pkt) {
		t.Errorf("seal mismatch vs RFC 9001 A.2")
	}
	if !bytes.HasPrefix(unprotectedHeaderForTest(t, sealed, &h, k), mustHex(t, rfc9001UnprotHeader)) {
		t.Errorf("unprotected header mismatch")
	}

	// 走完整 parsePacket 路径: 以太网 + IPv4 + UDP。
	before := quicStats.sni.Load()
	ev, res := parsePacket(withEther(udp4(50000, 443, pkt), false), time.Unix(1000, 0))
	if res != ParseOK || ev.Kind != EventTLSClientHello {
		t.Fatalf("res=%v kind=%v", res, ev.Kind)
	}
	if ev.TLS.SNI != "example.com" || !ev.IsUDP || !ev.TLS.IsQUIC {
		t.Errorf("SNI=%q udp=%v quic=%v", ev.TLS.SNI, ev.IsUDP, ev.TLS.IsQUIC)
	}
	if len(ev.TLS.ALPN) != 1 || ev.TLS.ALPN[0] != "alpn" {
		t.Errorf("ALPN=%v", ev.TLS.ALPN)
	}
	if !strings.HasPrefix(ev.TLS.JA4, "q13d") {
		t.Errorf("JA4=%q want q13d prefix", ev.TLS.JA4)
	}
	if !ev.ClientIP.Equal(net.IPv4(192, 168, 43, 10)) || ev.SrcPort != 50000 {
		t.Errorf("client=%v:%d", ev.ClientIP, ev.SrcPort)
	}
	if quicStats.sni.Load() != before+1 {
		t.Errorf("QUICSNI counter not bumped")
	}
	// 同一连接重复的 Initial(重传)不再产出事件。
	if _, res := parsePacket(withEther(udp4(50000, 443, pkt), false), time.Unix(1000, 0)); res != ParseIgnore {
		t.Errorf("duplicate Initial res=%v want ParseIgnore", res)
	}
}

// ── 测试用加密方向 ───────────────────────────────────────────────────────

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	}
	return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// sealQUICInitial 构造受保护的客户端 Initial: AEAD 加密 + header protection。
// Length 固定用 2 字节 varint(与 RFC 9001 A.2 一致)。
func sealQUICInitial(t testing.TB, p *quicVersionParams, dcid, scid, token []byte, pn uint64, pnLen int, payload []byte) []byte {
	t.Helper()
	k, ok := deriveQUICClientKeys(p, dcid)
	if !ok {
		t.Fatal("derive")
	}
	var ver uint32
	switch p {
	case quicParamsV1:
		ver = quicV1
	case quicParamsV2:
		ver = quicV2
	case quicParamsDraft29:
		ver = quicDraft29
	}
	b0 := byte(0xc0) | p.initialType<<4 | byte(pnLen-1)
	hdr := []byte{b0}
	hdr = binary.BigEndian.AppendUint32(hdr, ver)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = appendVarint(hdr, uint64(len(token)))
	hdr = append(hdr, token...)
	length := pnLen + len(payload) + 16
	hdr = append(hdr, byte(length>>8)|0x40, byte(length))
	pnOffset := len(hdr)
	for i := pnLen - 1; i >= 0; i-- {
		hdr = append(hdr, byte(pn>>(8*i)))
	}
	nonce := append([]byte(nil), k.iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	out := k.aead.Seal(append([]byte(nil), hdr...), nonce, payload, hdr)
	var mask [16]byte
	k.hp.Encrypt(mask[:], out[pnOffset+4:pnOffset+20])
	out[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		out[pnOffset+i] ^= mask[1+i]
	}
	return out
}

func unprotectedHeaderForTest(t testing.TB, pkt []byte, h *quicLongHeader, k *quicKeys) []byte {
	var mask [16]byte
	k.hp.Encrypt(mask[:], pkt[h.pnOffset+4:h.pnOffset+20])
	out := append([]byte(nil), pkt[:h.pnOffset+4]...)
	out[0] ^= mask[0] & 0x0f
	pnLen := int(out[0]&3) + 1
	for i := 0; i < pnLen; i++ {
		out[h.pnOffset+i] ^= mask[1+i]
	}
	return out[:h.pnOffset+pnLen]
}

// ── 构造 Chrome 风格的大 ClientHello ─────────────────────────────────────

func tlsExt(typ uint16, data []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// buildQUICClientHello 返回裸 handshake 消息(类型 1 + 3 字节长度 + body),
// 带 SNI / ALPN h3 / supported_versions / sig_algs / quic_transport_parameters
// 和把总长撑过单个 Initial 的 padding 扩展。
func buildQUICClientHello(sni string, padLen int) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, bytes.Repeat([]byte{0xab}, 32)...)
	body = append(body, 0)                                              // session id
	body = append(body, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03) // ciphers
	body = append(body, 0x01, 0x00)                                     // compression
	var ext []byte
	ext = append(ext, tlsExt(0x0a0a, nil)...) // GREASE
	sn := []byte{0}
	sn = binary.BigEndian.AppendUint16(sn, uint16(len(sni)))
	sn = append(sn, sni...)
	ext = append(ext, tlsExt(0x0000, append(binary.BigEndian.AppendUint16(nil, uint16(len(sn))), sn...))...)
	ext = append(ext, tlsExt(0x0010, []byte{0x00, 0x03, 0x02, 'h', '3'})...)
	ext = append(ext, tlsExt(0x002b, []byte{0x02, 0x03, 0x04})...)
	ext = append(ext, tlsExt(0x000d, []byte{0x00, 0x04, 0x04, 0x03, 0x08, 0x04})...)
	ext = append(ext, tlsExt(0x0039, []byte{0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x04, 0x04, 0x80, 0x10, 0x00, 0x00})...)
	ext = append(ext, tlsExt(0x0015, make([]byte, padLen))...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

func cryptoFrame(off int, data []byte) []byte {
	b := appendVarint([]byte{0x06}, uint64(off))
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

// padTo 把 frames 用 PADDING 补到 n 字节(Initial 至少 1200 字节的要求)。
func padTo(b []byte, n int) []byte {
	for len(b) < n {
		b = append(b, 0)
	}
	return b
}

// ── 重组 ────────────────────────────────────────────────────────────────

func TestQUICReassemblyChaos(t *testing.T) {
	resetQUICState(t)
	ch := buildQUICClientHello("rr1---sn-abc.googlevideo.com", 1400)
	if len(ch) < 1500 {
		t.Fatalf("CH too small: %d", len(ch))
	}
	// 切成 9 段并打乱(模拟 Chrome chaos protection), 分到两个 Initial 包,
	// 夹杂 PING / PADDING 帧。
	cuts := []int{0, 7, 150, 151, 400, 777, 900, 1200, 1350, len(ch)}
	var segs [][]byte
	for i := 0; i+1 < len(cuts); i++ {
		segs = append(segs, cryptoFrame(cuts[i], ch[cuts[i]:cuts[i+1]]))
	}
	rng := rand.New(rand.NewSource(7))
	rng.Shuffle(len(segs), func(i, j int) { segs[i], segs[j] = segs[j], segs[i] })
	// 保证 offset 0 那段落在第二个包里 —— 第一个包到达时前缀不连续。
	for i, s := range segs {
		if bytes.HasPrefix(s, []byte{0x06, 0x00}) {
			segs[i], segs[len(segs)-1] = segs[len(segs)-1], segs[i]
			break
		}
	}
	var p1, p2 []byte
	p1 = append(p1, 0x01) // PING
	for i, s := range segs {
		if i < 5 {
			p1 = append(p1, s...)
			p1 = append(p1, 0x00, 0x00) // PADDING
		} else {
			p2 = append(p2, s...)
		}
	}
	// 重复一段(重叠数据)也不应影响结果。
	p2 = append(p2, cryptoFrame(100, ch[100:300])...)
	p1 = padTo(p1, 1162)
	p2 = padTo(append([]byte{0x01}, p2...), 1162)

	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	scid := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	pk1 := sealQUICInitial(t, quicParamsV1, dcid, scid, nil, 0, 1, p1)
	pk2 := sealQUICInitial(t, quicParamsV1, dcid, scid, nil, 1, 1, p2)

	ts := time.Unix(2000, 0)
	failBefore := quicStats.decryptFail.Load()
	ev, res := parseRawIPPacket(udp6(51000, 443, pk1), ts)
	if res != ParseIgnore {
		t.Fatalf("first packet res=%v kind=%v, want ParseIgnore (incomplete)", res, ev.Kind)
	}
	ev, res = parseRawIPPacket(udp6(51000, 443, pk2), ts.Add(30*time.Millisecond))
	if res != ParseOK || ev.Kind != EventTLSClientHello {
		t.Fatalf("second packet res=%v kind=%v", res, ev.Kind)
	}
	if ev.TLS.SNI != "rr1---sn-abc.googlevideo.com" || !ev.IsIPv6 || !ev.IsUDP {
		t.Errorf("SNI=%q v6=%v udp=%v", ev.TLS.SNI, ev.IsIPv6, ev.IsUDP)
	}
	if !strings.HasPrefix(ev.TLS.JA4, "q13d") || len(ev.TLS.ALPN) != 1 || ev.TLS.ALPN[0] != "h3" {
		t.Errorf("JA4=%q ALPN=%v", ev.TLS.JA4, ev.TLS.ALPN)
	}
	// JA4 中间段: 3 个 cipher, 扩展数去掉 GREASE/SNI/ALPN 后为 4, ALPN "h3"。
	if !strings.HasPrefix(ev.TLS.JA4, "q13d0304h3_") {
		t.Errorf("JA4=%q want q13d0304h3_ prefix", ev.TLS.JA4)
	}

	// 服务器回 Initial 后, 客户端用服务器选的新 DCID 发 ACK Initial ——
	// 同一四元组已完成, 直接忽略, 不计解密失败。
	ack := padTo([]byte{0x02, 0x00, 0x00, 0x00, 0x00}, 1162)
	pk3 := sealQUICInitial(t, quicParamsV1, []byte{9, 9, 9, 9, 9, 9, 9, 9}, scid, nil, 2, 1, ack)
	if _, res := parseRawIPPacket(udp6(51000, 443, pk3), ts.Add(80*time.Millisecond)); res != ParseIgnore {
		t.Errorf("post-handshake Initial res=%v", res)
	}
	if got := quicStats.decryptFail.Load() - failBefore; got != 0 {
		t.Errorf("decryptFail delta=%d want 0", got)
	}
}

func TestQUICv2AndDraft29(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *quicVersionParams
	}{{"v2", quicParamsV2}, {"draft29", quicParamsDraft29}} {
		t.Run(tc.name, func(t *testing.T) {
			resetQUICState(t)
			ch := buildQUICClientHello("cdn."+tc.name+".example.org", 100)
			payload := padTo(cryptoFrame(0, ch), 1162)
			pkt := sealQUICInitial(t, tc.p, []byte{7, 7, 7, 7, 7, 7, 7, 7}, nil, []byte("tok"), 0, 2, payload)
			if tc.p == quicParamsV2 && (pkt[0]>>4)&3 != 1 {
				t.Fatalf("v2 Initial type bits should be 0b01, b0=%#x", pkt[0])
			}
			ev, res := parsePacket(withEther(udp4(40000, 443, pkt), false), time.Unix(3000, 0))
			if res != ParseOK || ev.TLS.SNI != "cdn."+tc.name+".example.org" || !strings.HasPrefix(ev.TLS.JA4, "q") {
				t.Fatalf("res=%v SNI=%q JA4=%q", res, ev.TLS.SNI, ev.TLS.JA4)
			}
		})
	}
	// v1 类型位(0b00)打在 v2 版本上就不是 Initial(v2 的 0b00 = 0-RTT), 必须忽略。
	resetQUICState(t)
	pkt := sealQUICInitial(t, quicParamsV2, []byte{7, 7, 7, 7}, nil, nil, 0, 1, padTo(cryptoFrame(0, buildQUICClientHello("x.y", 0)), 1162))
	pkt[0] &^= 0x30
	if _, res := parsePacket(withEther(udp4(40000, 443, pkt), false), time.Unix(3000, 0)); res != ParseIgnore {
		t.Errorf("v2 0-RTT res=%v want ParseIgnore", res)
	}
}

func TestQUICCoalescedAndNonInitial(t *testing.T) {
	resetQUICState(t)
	// Handshake 类型(v1 = 0b10) long header + 后面 coalesce 一个真正的 Initial。
	hs := []byte{0xe0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 0, 0x40, 0x05, 1, 2, 3, 4, 5}
	ini := sealQUICInitial(t, quicParamsV1, []byte{5, 5, 5, 5, 5, 5, 5, 5}, nil, nil, 0, 1,
		padTo(cryptoFrame(0, buildQUICClientHello("coalesced.test", 0)), 1162))
	ev, res := parsePacket(withEther(udp4(40001, 443, append(hs, ini...)), false), time.Unix(4000, 0))
	if res != ParseOK || ev.TLS.SNI != "coalesced.test" {
		t.Errorf("coalesced: res=%v SNI=%q", res, ev.TLS.SNI)
	}
	// 单独的 Handshake 包: 忽略, 不产出 EventFlow。
	if ev, res := parsePacket(withEther(udp4(40002, 443, hs), false), time.Unix(4000, 0)); res != ParseIgnore {
		t.Errorf("handshake-only res=%v kind=%v", res, ev.Kind)
	}
	// short header 仍按旧行为走 EventFlow(BPF 本就丢弃它们)。
	if ev, res := parsePacket(withEther(udp4(40003, 443, []byte{0x40, 1, 2, 3}), false), time.Unix(4000, 0)); res != ParseOK || ev.Kind != EventFlow {
		t.Errorf("short header res=%v kind=%v", res, ev.Kind)
	}
	// 未知版本 / 版本协商(0): 忽略。
	vn := []byte{0xc0, 0, 0, 0, 0, 4, 1, 2, 3, 4, 0, 0, 0, 0, 1}
	if _, res := parsePacket(withEther(udp4(40004, 443, vn), false), time.Unix(4000, 0)); res != ParseIgnore {
		t.Errorf("version negotiation res=%v", res)
	}
}

func TestQUICReassemblerEviction(t *testing.T) {
	r := newQUICReassembler(4, 16<<10, 3*time.Second)
	t0 := time.Unix(5000, 0)
	ch := buildQUICClientHello("evict.test", 1400)
	dcid := []byte{1, 1, 1, 1, 1, 1, 1, 1}
	half := len(ch) / 2
	mk := func(pn uint64, frame []byte) ([]byte, quicLongHeader) {
		pkt := sealQUICInitial(t, quicParamsV1, dcid, nil, nil, pn, 1, padTo(frame, 1162))
		h, ok := parseQUICLongHeader(pkt, quicParamsV1)
		if !ok {
			t.Fatal("hdr")
		}
		return pkt, h
	}
	a, ha := mk(0, cryptoFrame(0, ch[:half]))
	b, hb := mk(1, cryptoFrame(half, ch[half:]))
	ip := net.ParseIP("192.168.43.20")

	// 超时: 前半段在 t0, 后半段 4s 后到 → 旧 entry 已过期, 不得拼出 CH。
	if r.handleInitial(ip, 1000, &ha, a, quicParamsV1, t0) != nil {
		t.Fatal("unexpected hello from half")
	}
	if r.handleInitial(ip, 1000, &hb, b, quicParamsV1, t0.Add(4*time.Second)) != nil {
		t.Fatal("expired entry should not complete")
	}
	// 未超时则能拼出。
	if r.handleInitial(ip, 1001, &ha, a, quicParamsV1, t0) != nil {
		t.Fatal("unexpected hello")
	}
	if got := r.handleInitial(ip, 1001, &hb, b, quicParamsV1, t0.Add(time.Second)); !bytes.Equal(got, ch) {
		t.Fatalf("reassembled CH mismatch (len=%d)", len(got))
	}

	// 数量上限: 灌 20 个不同端口的半包, 表不超过 4 个。
	t1 := t0.Add(5 * time.Second)
	for i := 0; i < 20; i++ {
		r.handleInitial(ip, uint16(2000+i), &ha, a, quicParamsV1, t1.Add(time.Duration(i)*time.Millisecond))
		if len(r.m) > 4 {
			t.Fatalf("entries=%d exceeds cap", len(r.m))
		}
	}
	// LRU: 最后插入的 4 个在, 最早的被淘汰。
	if _, ok := r.m[quicTupleKey(ip, 2019)+string(dcid)]; !ok {
		t.Error("most recent entry evicted")
	}
	if _, ok := r.m[quicTupleKey(ip, 2000)+string(dcid)]; ok {
		t.Error("oldest entry not evicted")
	}

	// 字节上限: offset 超过 16KB 的 CRYPTO 帧 → entry 放弃, 不 panic。
	big, hbig := mk(0, cryptoFrame(16<<10-10, bytes.Repeat([]byte{1}, 50)))
	if r.handleInitial(ip, 3000, &hbig, big, quicParamsV1, t1.Add(time.Second)) != nil {
		t.Fatal("oversize should not produce hello")
	}
	if e := r.m[quicTupleKey(ip, 3000)+string(dcid)]; e == nil || !e.done || e.data != nil {
		t.Errorf("oversize entry should be marked done with data released")
	}
	// 声明长度超过 16KB 的 ClientHello 同样放弃。
	fake := []byte{0x01, 0x01, 0x00, 0x00, 0x03, 0x03}
	fk, hfk := mk(0, cryptoFrame(0, fake))
	if r.handleInitial(ip, 3001, &hfk, fk, quicParamsV1, t1.Add(time.Second)) != nil {
		t.Fatal("oversize declared CH should not produce hello")
	}
}

// ── 截断 / 篡改 / 随机输入 不 panic ──────────────────────────────────────

func TestQUICTamperAndTruncate(t *testing.T) {
	pkt := mustHex(t, rfc9001ProtectedPacket)
	ts := time.Unix(6000, 0)
	// 截断到每一个长度: 不 panic, 不产出事件。
	for n := 0; n < len(pkt); n++ {
		resetQUICState(t)
		if ev, res := parseRawIPPacket(udp4(50000, 443, pkt[:n]), ts); ev.Kind == EventTLSClientHello {
			t.Fatalf("truncated to %d produced kind=%v res=%v", n, ev.Kind, res)
		}
	}
	// 逐字节篡改: GCM 认证失败(或头部不再可解析), 不产出事件。
	failBefore := quicStats.decryptFail.Load()
	for i := 0; i < len(pkt); i++ {
		resetQUICState(t)
		bad := append([]byte(nil), pkt...)
		bad[i] ^= 0x01
		if ev, _ := parseRawIPPacket(udp4(50000, 443, bad), ts); ev.Kind == EventTLSClientHello {
			t.Fatalf("tampered byte %d still produced ClientHello", i)
		}
	}
	if quicStats.decryptFail.Load() == failBefore {
		t.Error("tampering should bump QUICDecryptFail")
	}
	// 随机 long header 垃圾。
	rng := rand.New(rand.NewSource(1))
	resetQUICState(t)
	for i := 0; i < 5000; i++ {
		b := make([]byte, rng.Intn(1400))
		rng.Read(b)
		if len(b) > 0 {
			b[0] |= 0x80
		}
		if len(b) > 5 && i%3 == 0 {
			binary.BigEndian.PutUint32(b[1:5], []uint32{quicV1, quicV2, quicDraft29}[i%9/3])
			b[5] = byte(rng.Intn(24))
		}
		parseRawIPPacket(udp4(uint16(1024+i), 443, b), ts)
	}
	if len(quicAsm.m) > quicAsmMaxEntries {
		t.Errorf("reassembler grew past cap: %d", len(quicAsm.m))
	}
}

func FuzzParseQUIC(f *testing.F) {
	f.Add(mustHex(f, rfc9001ProtectedPacket))
	f.Add(buildGQUICPacket("Q046", "www.google.com", "Chrome/120"))
	f.Add([]byte{0xc0, 0, 0, 0, 1, 20})
	f.Fuzz(func(t *testing.T, b []byte) {
		parseQUIC(Event{SrcIP: net.IPv4(10, 0, 0, 1), SrcPort: 1, Time: time.Unix(1, 0)}, b)
		parseQUICFrames(b)
	})
}

// ── gQUIC ───────────────────────────────────────────────────────────────

// buildGQUICPacket 构造 Q046 风格的 Initial: long header(0xc3) + 版本 +
// CID 长度半字节(DCIL=8) + 8 字节 CID + 1 字节 pn + 12 字节 NULL 加密哈希
// + STREAM 帧(stream 1) 承载明文 CHLO。
func buildGQUICPacket(ver, sni, uaid string) []byte {
	type tv struct {
		tag string
		val []byte
	}
	tags := []tv{
		{"PAD\x00", bytes.Repeat([]byte{'-'}, 600)},
		{"SNI\x00", []byte(sni)},
		{"VER\x00", []byte(ver)},
		{"UAID", []byte(uaid)},
	}
	msg := []byte("CHLO")
	msg = binary.LittleEndian.AppendUint16(msg, uint16(len(tags)))
	msg = append(msg, 0, 0)
	end := 0
	for _, e := range tags {
		end += len(e.val)
		msg = append(msg, e.tag...)
		msg = binary.LittleEndian.AppendUint32(msg, uint32(end))
	}
	for _, e := range tags {
		msg = append(msg, e.val...)
	}
	pkt := []byte{0xc3}
	pkt = append(pkt, ver...)
	pkt = append(pkt, 0x50)
	pkt = append(pkt, 1, 2, 3, 4, 5, 6, 7, 8)
	pkt = append(pkt, 1)
	pkt = append(pkt, bytes.Repeat([]byte{0x5a}, 12)...)
	// STREAM 帧: 0xa0 = stream | 有数据长度 | 无 offset | 1 字节 stream id
	pkt = append(pkt, 0xa0, 0x01)
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(len(msg)))
	pkt = append(pkt, msg...)
	return padTo(pkt, 1350)
}

func TestGQUICQ046CHLO(t *testing.T) {
	pkt := buildGQUICPacket("Q046", "WWW.Google.com", "Chrome/120.0.6099.230 Android 14")
	before := quicStats.gquicSNI.Load()
	ev, res := parsePacket(withEther(udp4(42000, 443, pkt), false), time.Unix(7000, 0))
	if res != ParseOK || ev.Kind != EventTLSClientHello {
		t.Fatalf("res=%v kind=%v", res, ev.Kind)
	}
	if ev.TLS.SNI != "www.google.com" || ev.TLS.UserAgent != "Chrome/120.0.6099.230 Android 14" || !ev.TLS.IsQUIC || ev.TLS.JA4 != "" {
		t.Errorf("SNI=%q UA=%q quic=%v JA4=%q", ev.TLS.SNI, ev.TLS.UserAgent, ev.TLS.IsQUIC, ev.TLS.JA4)
	}
	if quicStats.gquicSNI.Load() != before+1 {
		t.Error("GQUICSNI counter not bumped")
	}
	// Q050 加密: 跳过并计数。
	sk := quicStats.gquicSkipped.Load()
	if _, res := parsePacket(withEther(udp4(42000, 443, buildGQUICPacket("Q050", "a.b", "")), false), time.Unix(7000, 0)); res != ParseIgnore {
		t.Errorf("Q050 res=%v want ParseIgnore", res)
	}
	if quicStats.gquicSkipped.Load() != sk+1 {
		t.Error("GQUICSkipped counter not bumped")
	}
	// 截断的 CHLO 标签表 / 非法 SNI 字符不产出事件。
	for n := 0; n < len(pkt); n += 7 {
		parsePacket(withEther(udp4(42000, 443, pkt[:n]), false), time.Unix(7000, 0))
	}
	bad := buildGQUICPacket("Q046", "evil\x00host", "")
	if _, res := parsePacket(withEther(udp4(42000, 443, bad), false), time.Unix(7000, 0)); res != ParseIgnore {
		t.Errorf("invalid SNI res=%v", res)
	}
}

// 多个 Handle(主抓包 + 自身流量抓包)的 Run goroutine 共用包级重组表,
// -race 下并发喂包必须无数据竞争。
func TestQUICConcurrentHandles(t *testing.T) {
	resetQUICState(t)
	pkt := mustHex(t, rfc9001ProtectedPacket)
	done := make(chan int, 8)
	for g := 0; g < 8; g++ {
		go func(g int) {
			n := 0
			for i := 0; i < 50; i++ {
				ev, _ := parseRawIPPacket(udp4(uint16(10000+g*100+i), 443, pkt), time.Now())
				if ev.TLS.SNI == "example.com" {
					n++
				}
			}
			done <- n
		}(g)
	}
	total := 0
	for g := 0; g < 8; g++ {
		total += <-done
	}
	// 每个源端口是独立四元组, 单包即完整 ClientHello, 应全部成功。
	if total != 400 {
		t.Fatalf("extracted %d/400 ClientHello under concurrency", total)
	}
}
