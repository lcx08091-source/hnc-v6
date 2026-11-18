package output

import "testing"

func TestBestClassifiedCNAMEHopAndCausalBurst(t *testing.T) {
	ce := NewCausalBurstEngine()
	douyin := l3Rule{ID: "douyin", Name: "抖音", Category: "video", Priority: PrioritySpecific, Verified: true}
	wechat := l3Rule{ID: "wechat", Name: "微信", Category: "social", Priority: PrioritySpecific, Verified: true}

	// 1. 单锚点 40ms 内并发 QUIC 443 盲流 -> 高置信度传播成功
	ce.RecordAnchor("aa:bb:cc:00:11:22", 10000, douyin, "111.225.88.10", "t13d0312h2_aaa_bbb_ccc", "")
	got, ok := ce.LookupOrPropagate("aa:bb:cc:00:11:22", "U|111.225.88.99:443", 10035, "111.225.88.99", "q13i0312h3_aaa_ddd_ccc", "", true, 443)
	if !ok || got.ID != "douyin" {
		t.Fatalf("expected causal burst propagation to douyin, got ok=%v id=%q", ok, got.ID)
	}

	// 2. 脱离窗口(500ms后)的新未知流不应误传染
	if _, ok2 := ce.LookupOrPropagate("aa:bb:cc:00:11:22", "U|203.0.113.9:443", 10550, "203.0.113.9", "", "", true, 443); ok2 {
		t.Fatalf("expected flow outside 120ms window not to propagate")
	}

	// 3. 80ms 内出现第二个不同 App 锚点 -> 多源冲突一票否决!
	ce.RecordAnchor("aa:bb:cc:00:11:33", 20000, douyin, "111.225.88.10", "", "")
	ce.RecordAnchor("aa:bb:cc:00:11:33", 20030, wechat, "183.3.226.35", "", "")
	if _, ok3 := ce.LookupOrPropagate("aa:bb:cc:00:11:33", "U|111.225.88.55:443", 20045, "111.225.88.55", "", "", true, 443); ok3 {
		t.Fatalf("expected multi-anchor conflict veto within 80ms")
	}
}
