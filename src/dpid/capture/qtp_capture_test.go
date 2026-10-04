package capture

import (
	"testing"
	"time"

	"hnc.io/dpid/output"
)

// v5.27 T2: QUIC 路径填 TLSInfo.QTP; RFC 9001 A.2 测试向量里的 ClientHello
// 带 quic_transport_parameters, 指纹非空且多次解析稳定。
func TestQTPFromRFC9001Initial(t *testing.T) {
	var fps []string
	for i, port := range []uint16{50101, 50102} {
		resetQUICState(t)
		pkt := mustHex(t, rfc9001ProtectedPacket)
		ev, res := parsePacket(withEther(udp4(port, 443, pkt), false), time.Unix(int64(1000+i), 0))
		if res != ParseOK || ev.Kind != EventTLSClientHello {
			t.Fatalf("res=%v kind=%v", res, ev.Kind)
		}
		if !output.ValidQTP(ev.TLS.QTP) {
			t.Fatalf("QTP=%q", ev.TLS.QTP)
		}
		fps = append(fps, ev.TLS.QTP)
	}
	if fps[0] != fps[1] {
		t.Fatalf("QTP 不稳定: %v", fps)
	}
}

// 合成的 Chrome 风格 ClientHello: QTP 等于对扩展原文直接计算的指纹。
func TestQTPFromSynthesizedHello(t *testing.T) {
	ch := buildQUICClientHello("www.example.com", 100)
	rec := make([]byte, 5+len(ch))
	rec[0], rec[1], rec[2] = 0x16, 0x03, 0x01
	rec[3], rec[4] = byte(len(ch)>>8), byte(len(ch))
	copy(rec[5:], ch)
	in, ok := extractJA4Inputs(rec)
	if !ok || len(in.QUICTP) == 0 {
		t.Fatalf("extract: ok=%v qtp=%x", ok, in.QUICTP)
	}
	want := output.QUICTPFingerprint([]byte{0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x04, 0x04, 0x80, 0x10, 0x00, 0x00})
	if got := output.QUICTPFingerprint(in.QUICTP); got != want || got == "" {
		t.Fatalf("got %q want %q", got, want)
	}
	// TCP 的 TLS ClientHello 不填 QTP(只在 QUIC 路径填)
	info, ok := parseTLSClientHelloFull(rec)
	if !ok || info.QTP != "" {
		t.Fatalf("TCP 路径 QTP=%q ok=%v", info.QTP, ok)
	}
}
