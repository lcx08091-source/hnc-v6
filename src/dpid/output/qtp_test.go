package output

import (
	"bytes"
	"strings"
	"testing"
)

func qtpVarint(v uint64) []byte {
	switch {
	case v < 1<<6:
		return []byte{byte(v)}
	case v < 1<<14:
		return []byte{0x40 | byte(v>>8), byte(v)}
	case v < 1<<30:
		return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
	default:
		return []byte{0xc0 | byte(v>>56), byte(v >> 48), byte(v >> 40), byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
}

type tp struct {
	id  uint64
	val []byte
}

func qtpEncode(ps ...tp) []byte {
	var b bytes.Buffer
	for _, p := range ps {
		b.Write(qtpVarint(p.id))
		b.Write(qtpVarint(uint64(len(p.val))))
		b.Write(p.val)
	}
	return b.Bytes()
}

func intTP(id, v uint64) tp { return tp{id, qtpVarint(v)} }

// 一个 Chrome 风格的参数集
func chromeLike(grease uint64, scid []byte, idle uint64) []byte {
	return qtpEncode(
		intTP(0x01, idle),
		intTP(0x03, 1472),
		intTP(0x04, 15728640),
		intTP(0x05, 6291456),
		intTP(0x06, 6291456),
		intTP(0x07, 6291456),
		intTP(0x08, 100),
		intTP(0x09, 103),
		tp{0x0f, scid},
		tp{grease, []byte{1, 2, 3}},
		tp{0x11, []byte{0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf, 0, 0, 0, 1}},
		tp{0x3127, []byte("Chrome/120 UA string")},
		intTP(0x20, 65536),
	)
}

func TestQTPStableAcrossGreaseOrderAndSCID(t *testing.T) {
	a := QUICTPFingerprint(chromeLike(27, []byte{1, 2, 3, 4}, 30000))
	if a == "" || !strings.HasPrefix(a, "qtp1_") || !ValidQTP(a) {
		t.Fatalf("fingerprint = %q", a)
	}
	// 不同 GREASE id(31*N+27)
	if b := QUICTPFingerprint(chromeLike(31*1000+27, []byte{1, 2, 3, 4}, 30000)); b != a {
		t.Errorf("GREASE id 变了指纹也变: %s vs %s", a, b)
	}
	// 0x0f 的值(每次随机)
	if b := QUICTPFingerprint(chromeLike(27, []byte{9, 9, 9, 9, 9, 9, 9, 9}, 30000)); b != a {
		t.Errorf("initial_source_connection_id 变了指纹也变")
	}
	// 参数顺序打乱
	shuffled := qtpEncode(
		intTP(0x20, 65536),
		tp{0x3127, []byte("another UA")}, // UA 文本不入指纹
		tp{0x11, []byte{0, 0, 0, 1, 0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf}}, // 可用版本列表顺序 + chosen 不同
		intTP(0x09, 103),
		tp{0x0f, []byte{7}},
		intTP(0x08, 100),
		intTP(0x07, 6291456),
		tp{31*5 + 27, nil},
		tp{31*9 + 27, []byte{1}}, // 多个 GREASE 只算一个 G
		intTP(0x06, 6291456),
		intTP(0x05, 6291456),
		intTP(0x04, 15728640),
		intTP(0x03, 1472),
		intTP(0x01, 30000),
	)
	if b := QUICTPFingerprint(shuffled); b != a {
		t.Errorf("顺序打乱后指纹变了: %s vs %s\n%s\n%s", a, b, QUICTPSummary(chromeLike(27, []byte{1}, 30000)), QUICTPSummary(shuffled))
	}
	// max_idle_timeout 变 → 不同指纹
	if b := QUICTPFingerprint(chromeLike(27, []byte{1, 2, 3, 4}, 60000)); b == a {
		t.Errorf("max_idle_timeout 变了指纹应不同")
	}
	s := QUICTPSummary(chromeLike(27, []byte{1, 2, 3, 4}, 30000))
	if strings.Contains(s, "Chrome") || !strings.Contains(s, "1=30000") || !strings.HasSuffix(s, "-G") || !strings.Contains(s, "11=1,6b3343cf") {
		t.Errorf("summary = %q", s)
	}
}

func TestQTPMalformed(t *testing.T) {
	good := chromeLike(27, []byte{1, 2, 3, 4}, 30000)
	for name, b := range map[string][]byte{
		"empty":            nil,
		"truncated value":  good[:len(good)-1],
		"len over":         {0x01, 0x10, 0x00},
		"truncated varint": {0x40},
		"truncated len":    {0x01, 0x80, 0x00},
		"8-byte id cut":    {0xc0, 0, 0, 0},
	} {
		if fp := QUICTPFingerprint(b); fp != "" {
			t.Errorf("%s: fingerprint = %q, want empty", name, fp)
		}
		if s := QUICTPSummary(b); s != "" {
			t.Errorf("%s: summary = %q", name, s)
		}
	}
	// 整数参数值不是合法 varint 不算整体失败, 记成 id=!
	if fp := QUICTPFingerprint(qtpEncode(tp{0x01, []byte{0x40}})); fp == "" {
		t.Error("坏的整数值不应让整体失败")
	}
}

func TestQTPSummaryCap(t *testing.T) {
	var ps []tp
	for i := uint64(0x1000); i < 0x1000+200; i++ {
		ps = append(ps, tp{i, nil})
	}
	if s := QUICTPSummary(qtpEncode(ps...)); len(s) != 256 {
		t.Fatalf("summary len = %d", len(s))
	}
}

func TestValidQTP(t *testing.T) {
	for s, want := range map[string]bool{
		"qtp1_0123456789ab": true,
		"qtp1_0123456789AB": false,
		"qtp1_0123456789a":  false,
		"qtp2_0123456789ab": false,
		"":                  false,
	} {
		if ValidQTP(s) != want {
			t.Errorf("ValidQTP(%q) != %v", s, want)
		}
	}
}
