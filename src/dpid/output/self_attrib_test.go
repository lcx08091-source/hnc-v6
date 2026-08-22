package output

import (
	"testing"
)

// v6 review fix 回归测试: sampleOnly 的变更检测依赖 connsSignature —— 同一
// 连接集不同顺序必须得到同一签名 (parseProcNet 的遍历顺序不稳定), 否则会
// 误判"变了"导致写放大修复失效。
func TestConnsSignatureOrderIndependent(t *testing.T) {
	a := []SelfAttribConnRow{
		{Proto: "tcp", Local: "10.0.0.1:44444", Remote: "93.0.0.1:443", UID: 10100},
		{Proto: "udp", Local: "10.0.0.1:5353", Remote: "8.8.8.8:53", UID: 10200},
	}
	b := []SelfAttribConnRow{
		{Proto: "udp", Local: "10.0.0.1:5353", Remote: "8.8.8.8:53", UID: 10200},
		{Proto: "tcp", Local: "10.0.0.1:44444", Remote: "93.0.0.1:443", UID: 10100},
	}
	if connsSignature(a) != connsSignature(b) {
		t.Fatal("same conn set in different order must produce the same signature")
	}

	c := append(b[:1:1], SelfAttribConnRow{Proto: "tcp", Local: "10.0.0.2:55555", Remote: "1.1.1.1:443", UID: 10100})
	if connsSignature(a) == connsSignature(c) {
		t.Fatal("different conn sets must produce different signatures")
	}

	// Pkg/State 等非 key 字段不参与签名 (连接集相同即跳过 append 的依据)。
	a[0].Pkg = "com.example.changed"
	if connsSignature(a) != connsSignature(b) {
		t.Fatal("non-key fields must not affect the signature")
	}
}
