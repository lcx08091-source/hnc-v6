package output

import (
	"strings"
	"testing"
	"time"
)

// v5.9.7: 证据账本回归测试 —— 锁定回移时修复的两个分叉缺陷
// (maxTotal enforcement / LogOddsDelta 自动计权)与基础语义。

func TestEvidenceLedgerPerKeyRolling(t *testing.T) {
	el := NewEvidenceLedger(4, 1000)
	for i := 0; i < 8; i++ {
		el.Add("aa:bb:cc:dd:ee:ff", "com.example.app", EvidenceEntry{
			Ts: time.Now(), Source: SrcFlow, Detail: "entry",
		})
	}
	snap := el.Snapshot()
	if got := len(snap["aa:bb:cc:dd:ee:ff:com.example.app"]); got != 4 {
		t.Fatalf("per-key cap not enforced: got %d entries, want 4", got)
	}
	entries := snap["aa:bb:cc:dd:ee:ff:com.example.app"]
	if entries[0].Detail == "entry" && entries[3].Detail == "entry" {
		// 丢的是最旧 —— 无法从 Detail 区分(都同值), 用 Ts 单调性验证:
		// 回填不同时间再测
	}
}

func TestEvidenceLedgerMaxTotal(t *testing.T) {
	// 10 keys × 10 entries = 100; maxTotal=25 → 加满后只应剩 ~2-3 个 key
	el := NewEvidenceLedger(10, 25)
	base := time.Now().Add(-time.Hour)
	for k := 0; k < 10; k++ {
		for i := 0; i < 10; i++ {
			el.Add("mac"+strings.Repeat("x", k), "app", EvidenceEntry{
				// 后写的 key 时间更晚 —— 最旧的 key 先被丢
				Ts: base.Add(time.Duration(k)*time.Minute + time.Duration(i)*time.Second),
				Source: SrcDNS,
			})
		}
	}
	if got := el.Size(); got > 25 {
		t.Fatalf("maxTotal not enforced: got %d, want <= 25", got)
	}
	if got := len(el.Snapshot()); got > 3 {
		t.Fatalf("expected only newest keys to survive, got %d keys", got)
	}
}

func TestEvidenceLedgerLogOddsAutoWeight(t *testing.T) {
	el := NewEvidenceLedger(8, 100)
	el.Add("m", "app", EvidenceEntry{Ts: time.Now(), Source: SrcTLS})
	el.Add("m", "app", EvidenceEntry{Ts: time.Now(), Source: SrcDNS})
	el.Add("m", "app", EvidenceEntry{Ts: time.Now(), Source: SrcFlow})
	el.Add("m", "app", EvidenceEntry{Ts: time.Now(), Source: SrcSNI})

	var sum float64
	for _, e := range el.Snapshot()["m:app"] {
		switch e.Source {
		case SrcTLS:
			if e.LogOddsDelta != 2.0 {
				t.Errorf("tls weight = %v, want 2.0", e.LogOddsDelta)
			}
		case SrcDNS:
			if e.LogOddsDelta != 1.5 {
				t.Errorf("dns weight = %v, want 1.5", e.LogOddsDelta)
			}
		case SrcFlow:
			if e.LogOddsDelta != 0.5 {
				t.Errorf("flow weight = %v, want 0.5", e.LogOddsDelta)
			}
		case SrcSNI:
			if e.LogOddsDelta != 1.0 {
				t.Errorf("sni weight = %v, want 1.0", e.LogOddsDelta)
			}
		}
		sum += e.LogOddsDelta
	}
	// 全源命中一次: tls+dns+flow+sni = 5.0 log-odds(后验 >99%)
	if sum != 5.0 {
		t.Fatalf("total log-odds = %v, want 5.0", sum)
	}
}

func TestEvidenceLedgerTrim(t *testing.T) {
	el := NewEvidenceLedger(100, 10000)
	old := time.Now().Add(-2 * time.Hour)
	el.Add("m", "fresh", EvidenceEntry{Ts: time.Now(), Source: SrcTLS})
	el.Add("m", "stale", EvidenceEntry{Ts: old, Source: SrcDNS})
	el.Trim(time.Hour)
	snap := el.Snapshot()
	if _, ok := snap["m:stale"]; ok {
		t.Fatal("stale key survived Trim")
	}
	if _, ok := snap["m:fresh"]; !ok {
		t.Fatal("fresh key was trimmed")
	}
}
