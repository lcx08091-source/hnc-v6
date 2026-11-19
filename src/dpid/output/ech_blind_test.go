package output

import (
	"slices"
	"testing"
	"time"
)

func TestIsECHBlindOrOuterSNI(t *testing.T) {
	cases := []struct {
		sni    string
		hasECH bool
		want   bool
	}{
		{"cloudflare-ech.com", true, true},
		{"sub.cloudflare-ech.com", false, true},
		{"crypto.cloudflare.com", true, true},
		{"encryptedsni.com", false, true},
		{"", true, true},
		{"", false, true},
		{"ech.example.org", true, true},
		{"ech.example.org", false, false},
		{"api.bilibili.com", true, false},
	}
	for _, tc := range cases {
		if got := IsECHBlindOrOuterSNI(tc.sni, tc.hasECH); got != tc.want {
			t.Errorf("IsECHBlindOrOuterSNI(%q, %v)=%v want %v", tc.sni, tc.hasECH, got, tc.want)
		}
	}
}

// TestECHBlindSVCBAndMultiClientIsolation 验证:
// 两台不同热点客户端连接同一个 Cloudflare Anycast IP 且外层 SNI 均为 cloudflare-ech.com 时,
// 联合 DNS Type 65 HTTPS 记录与 8 跳 CNAME 链 + ECHConfigID 能按客户端精准区分不同真实应用!
func TestECHBlindSVCBAndMultiClientIsolation(t *testing.T) {
	eng := NewECHBlindEngine(256)
	now := time.Unix(1700000000, 0)
	sharedAnycastIP := "104.18.32.77"

	// 设备 A 请求陌生边缘域名 edge-gw.disp.example.net -> CNAME mcdn.bilivideo.com -> cdn.cloudflare.net
	eng.RecordSVCB(ECHSVCBHint{
		ClientIP: "192.168.43.10",
		QName:    "edge-gw.disp.example.net",
		Records: []DNSAnswer{
			{Name: "edge-gw.disp.example.net", Type: 5, TTL: 120, Value: "mcdn.bilivideo.com"},
			{Name: "mcdn.bilivideo.com", Type: 5, TTL: 120, Value: "cdn.cloudflare.net"},
			{Name: "cdn.cloudflare.net", Type: 65, TTL: 120, Value: sharedAnycastIP},
		},
		ECHConfigIDs: []uint8{0x41},
		ALPNs:        []string{"h3", "h2"},
		TTL:          120,
		ObservedAt:   now,
	})

	// 设备 B 请求 api.douyin.com -> Type 65 HTTPS 指向同一个 Anycast IP
	eng.RecordSVCB(ECHSVCBHint{
		ClientIP:     "192.168.43.22",
		QName:        "api.douyin.com",
		TargetIPs:    []string{sharedAnycastIP},
		ECHConfigIDs: []uint8{0x7b},
		ALPNs:        []string{"h3"},
		TTL:          300,
		ObservedAt:   now,
	})

	// 设备 A 发起 ECH 加密握手: 外层 SNI = cloudflare-ech.com
	vA, okA := eng.Infer(ECHBlindQuery{
		ClientIP:    "192.168.43.10",
		RemoteIP:    sharedAnycastIP,
		DstPort:     443,
		IsUDP:       true,
		OuterSNI:    "cloudflare-ech.com",
		HasECHExt:   true,
		ECHConfigID: 0x41,
		HasConfigID: true,
		ALPNs:       []string{"h3"},
		Now:         now.Add(2 * time.Second),
	})
	if !okA || vA.AppID != "bilibili" || vA.CNAMEHop != "mcdn.bilivideo.com" {
		t.Fatalf("device A ECH unblinding failed: ok=%v verdict=%+v", okA, vA)
	}
	if vA.ConfidenceLevel != "high" || !slices.Contains(vA.Sources, "svcb_https") || !slices.Contains(vA.Sources, "cname_chain") {
		t.Errorf("device A confidence/sources unexpected: %+v", vA)
	}

	// 设备 B 同一时刻连接同一 Anycast IP, 外层同样是 cloudflare-ech.com -> 精准归因给 douyin!
	vB, okB := eng.Infer(ECHBlindQuery{
		ClientIP:    "192.168.43.22",
		RemoteIP:    sharedAnycastIP,
		DstPort:     443,
		IsUDP:       true,
		OuterSNI:    "cloudflare-ech.com",
		HasECHExt:   true,
		ECHConfigID: 0x7b,
		HasConfigID: true,
		ALPNs:       []string{"h3"},
		Now:         now.Add(2 * time.Second),
	})
	if !okB || vB.AppID != "douyin" {
		t.Fatalf("device B ECH unblinding failed: ok=%v verdict=%+v", okB, vB)
	}

	// 验证联合 IPNameTable (未落盘前 CNAME 链) 兜底反解
	ipNames := NewIPNameTable()
	ipNames.RecordDNSAnswers("sched-ech.unknown-edge.org", []DNSAnswer{
		{Name: "sched-ech.unknown-edge.org", Type: 5, TTL: 180, Value: "p3.douyinpic.com"},
		{Name: "p3.douyinpic.com", Type: 5, TTL: 180, Value: "cdn.cloudflare.net"},
		{Name: "cdn.cloudflare.net", Type: 1, TTL: 180, Value: "172.64.10.20"},
	}, now)
	vC, okC := eng.Infer(ECHBlindQuery{
		ClientIP:  "192.168.43.88",
		RemoteIP:  "172.64.10.20",
		DstPort:   443,
		IsUDP:     false,
		OuterSNI:  "cloudflare-ech.com",
		HasECHExt: true,
		IPNames:   ipNames,
		Now:       now.Add(3 * time.Second),
	})
	if !okC || vC.AppID != "douyin" || !slices.Contains(vC.Sources, "cname_chain") {
		t.Fatalf("IPNameTable CNAME fallback failed: ok=%v verdict=%+v", okC, vC)
	}
}

// TestECHBlindDoHBypassJA4AndSPLTFusion 验证极端无 DNS 场景(客户端内置加密 DoH + ECH 缺失明文 SNI):
// 联合已学习的 JA4 指纹家族 + SPLT 前 10 包序列形态完成游戏与视频应用消歧。
func TestECHBlindDoHBypassJA4AndSPLTFusion(t *testing.T) {
	eng := NewECHBlindEngine(256)
	now := time.Unix(1700001000, 0)
	tencentMarsJA4 := "q13d0311h3_55b375c5d22e_a1b2c3d4e5f6"

	// 先喂 22 个已验证腾讯系样本使 JA4 家族学习收敛 (占比 100% >= 0.70, 样本 >= 20)
	for i := 0; i < 22; i++ {
		eng.ObserveVerifiedFlow("wechat", "微信", "im", tencentMarsJA4, true, 443, nil, now)
	}

	// 构造一条典型的 UDP 实时小包双向对称帧同步序列 (SPLTShapeGameSync: 无满 MTU 包, 双向小包交替)
	var gameSPLT FlowSPLTTracker
	tNs := now.UnixNano()
	pktLens := []int{64, 72, 58, 80, 62, 76, 60, 84}
	for i, pl := range pktLens {
		gameSPLT.ObserveL4Packet(pl, i%2 == 1, tNs+int64(i)*12_000_000)
	}
	if gotShape := gameSPLT.InferShape(true); gotShape != SPLTShapeGameSync {
		t.Fatalf("expected SPLTShapeGameSync, got %v", gotShape)
	}

	// 完全无 DNS / SVCB 命中且无明文 SNI: 靠 JA4 家族(tencent) + SPLT(game_sync) 推断出腾讯游戏!
	verdict, ok := eng.Infer(ECHBlindQuery{
		ClientIP:  "192.168.43.55",
		RemoteIP:  "203.0.113.88",
		DstPort:   443,
		IsUDP:     true,
		OuterSNI:  "",
		HasECHExt: true,
		JA4:       tencentMarsJA4,
		SPLT:      &gameSPLT,
		Now:       now.Add(5 * time.Second),
	})
	if !ok {
		t.Fatal("expected JA4 + SPLT blind inference hit, got false")
	}
	if verdict.Company != "tencent" || verdict.Category != "game" || verdict.SPLTShape != "game_sync" {
		t.Fatalf("unexpected JA4+SPLT verdict: %+v", verdict)
	}
	if !slices.Contains(verdict.Sources, "ja4_family") || !slices.Contains(verdict.Sources, "splt_seq") {
		t.Errorf("missing expected sources in %+v", verdict.Sources)
	}

	// 再验证已学得 SPLT 精确原型匹配 (字节跳动视频 ABR 流)
	var videoSPLT FlowSPLTTracker
	videoSteps := []struct {
		ln   int
		down bool
	}{
		{180, false}, {220, false}, {160, false},
		{1400, true}, {1400, true}, {1400, true},
	}
	for i, st := range videoSteps {
		videoSPLT.ObserveL4Packet(st.ln, st.down, tNs+int64(i)*8_000_000)
	}
	eng.ObserveVerifiedFlow("douyin", "抖音", "video", "", true, 443, &videoSPLT, now)

	vProto, okProto := eng.Infer(ECHBlindQuery{
		ClientIP:  "192.168.43.55",
		RemoteIP:  "198.51.100.99",
		DstPort:   443,
		IsUDP:     true,
		OuterSNI:  "cloudflare-ech.com",
		HasECHExt: true,
		SPLT:      &videoSPLT,
		Now:       now.Add(6 * time.Second),
	})
	if !okProto || vProto.AppID != "douyin" || !slices.Contains(vProto.Sources, "splt_proto") {
		t.Fatalf("expected SPLT prototype match for douyin, got ok=%v verdict=%+v", okProto, vProto)
	}

	st := eng.Stats()
	if st.InferHits < 2 || st.JA4FamilyHits < 1 || st.SPLTRefined < 2 {
		t.Errorf("stats counters unexpected: %+v", st)
	}
}
