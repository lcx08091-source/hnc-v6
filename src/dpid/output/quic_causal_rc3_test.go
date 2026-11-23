package output

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRecordTLSBlindQUICCausalPropagationAndQTPAnchor(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(filepath.Join(dir, "dpi_state.json"), "v6.1.0-rc.3")

	mac := "aa:bb:cc:11:22:33"
	clientIP := "192.168.43.21"
	anchorIP := "111.225.88.10"
	blindQUICIP := "203.0.113.77"   // 跨 /24 子网, 验证必须靠 QTP 锚点亲和度(+0.22)跨过 0.56 门控阈值
	cascadeQUICIP := "203.0.113.88" // 验证次级因果传播结果绝不喂回 RecordAnchor 造成级联传染
	qtp := "qtp1_0123456789ab"
	anchorJA4 := "q13d0310h3_aa11bb22cc33_111111111111"
	blindJA4 := "q13d0310h3_aa11bb22cc33_999999999999"

	t0 := time.Unix(1_795_000_000, 0)

	// 1. 确定性 QUIC 握手(www.douyin.com)写入锚点(含真实 QTP)
	w.RecordTLS(mac, clientIP, anchorIP, "www.douyin.com", anchorJA4, t0, qtp)

	// 75ms 后(<80ms 且 >65ms)紧跟一条无明文 SNI 的跨子网盲 QUIC 握手:
	// dt=75ms -> 0.42*exp(-75/60)=0.1203, 同栈家族 +0.26, 同 QTP +0.22 -> 总分 0.6003 >= 0.56;
	// 若 RecordAnchor 把 QTP 硬编码为空串 "", 则总分仅 0.3803 < 0.56 会归属失败。
	w.RecordTLS(mac, clientIP, blindQUICIP, "", blindJA4, t0.Add(75*time.Millisecond), qtp)

	w.IPAppMap.mu.Lock()
	blindObs := w.IPAppMap.entries[blindQUICIP]
	w.IPAppMap.mu.Unlock()
	if blindObs == nil || blindObs.AppID != "douyin" {
		t.Fatalf("expected blind QUIC IP %s attributed to douyin via 120ms causal burst + QTP, got %+v", blindQUICIP, blindObs)
	}

	w.mu.Lock()
	cl := w.clients[mac]
	var appCount uint64
	if cl != nil && cl.Apps["douyin"] != nil {
		appCount = cl.Apps["douyin"].Count
	}
	hits := w.causal.Hits()
	w.mu.Unlock()
	if appCount < 2 {
		t.Fatalf("expected douyin count >= 2 (anchor + blind QUIC propagation), got %d", appCount)
	}
	if hits != 1 {
		t.Fatalf("expected causal engine hits == 1, got %d", hits)
	}

	// 2. 防级联传染 + 超出 120ms 窗口严格不误传:
	// t0+135ms 距原始锚点已超 120ms, 虽然距 t0+75ms 的次级流仅 60ms 且同 /24 + 同 JA4 + 同 QTP,
	// 因次级流未写入 RecordAnchor, 必须严格拒绝归属。
	w.RecordTLS(mac, clientIP, cascadeQUICIP, "", blindJA4, t0.Add(135*time.Millisecond), qtp)

	w.IPAppMap.mu.Lock()
	cascadeObs := w.IPAppMap.entries[cascadeQUICIP]
	w.IPAppMap.mu.Unlock()
	if cascadeObs != nil {
		t.Fatalf("expected blind QUIC outside 120ms window (and no secondary anchor cascade) not to propagate, got %+v", cascadeObs)
	}
}

func TestRecordTLSBlindQUICConflictVetoAndOutOfWindow(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(filepath.Join(dir, "dpi_state.json"), "v6.1.0-rc.3")

	qtp := "qtp1_fedcba987654"
	ja4A := "q13d0310h3_ccddeeff0011_aaaaaaaaaaaa"
	ja4B := "q13d0310h3_ccddeeff0011_bbbbbbbbbbbb"
	t0 := time.Unix(1_795_000_100, 0)

	// 场景 A: 超过 120ms 窗口(150ms)的无 SNI 盲 QUIC 握手(即便同 /24、同 JA4、同 QTP)严格不误传
	mac1 := "aa:bb:cc:44:55:01"
	cip1 := "192.168.43.31"
	w.RecordTLS(mac1, cip1, "198.51.100.10", "www.douyin.com", ja4A, t0, qtp)
	w.RecordTLS(mac1, cip1, "198.51.100.11", "", ja4A, t0.Add(150*time.Millisecond), qtp)

	w.IPAppMap.mu.Lock()
	lateObs := w.IPAppMap.entries["198.51.100.11"]
	w.IPAppMap.mu.Unlock()
	if lateObs != nil {
		t.Fatalf("expected blind QUIC at +150ms (>120ms window) not to propagate, got %+v", lateObs)
	}

	// 场景 B: 80ms 内同时出现两个不同前景 App 锚点(douyin 与 wechat) -> 一票否决不误传
	mac2 := "aa:bb:cc:44:55:02"
	cip2 := "192.168.43.32"
	w.RecordTLS(mac2, cip2, "198.51.100.20", "www.douyin.com", ja4A, t0, qtp)
	w.RecordTLS(mac2, cip2, "183.3.226.35", "weixin.qq.com", ja4B, t0.Add(35*time.Millisecond), qtp)
	// t0+55ms 与两个锚点均在 80ms 冲突窗口内(|55-0|<=80 且 |55-35|<=80), 即使同子网+同JA4+同QTP也必须否决
	w.RecordTLS(mac2, cip2, "198.51.100.29", "", ja4A, t0.Add(55*time.Millisecond), qtp)

	w.IPAppMap.mu.Lock()
	conflictObs := w.IPAppMap.entries["198.51.100.29"]
	w.IPAppMap.mu.Unlock()
	if conflictObs != nil {
		t.Fatalf("expected 80ms multi-app conflict veto to block propagation, got %+v", conflictObs)
	}
	if hits := w.causal.Hits(); hits != 0 {
		t.Fatalf("expected 0 causal hits under timeout and conflict veto, got %d", hits)
	}
}
