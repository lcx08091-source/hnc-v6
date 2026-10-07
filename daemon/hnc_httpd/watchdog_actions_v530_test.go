package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// v5.30 T3: 自检「看门狗动作」行带出 M4 影子计数, 只观察、不改变状态。
// 「改动前会失败」: v5.29 不读 m4_checks / m4_mismatch, Detail 里没有这段。
func TestScWatchdogActionsShowsM4Shadow(t *testing.T) {
	now := time.Unix(1791000000, 0)
	b, _ := json.Marshal(map[string]interface{}{
		"schema": 1, "generated_at": now.Unix() - 30,
		"actions":   map[string]interface{}{"check_health": map[string]interface{}{"calls_1h": 60.0, "fails_1h": 0.0, "avg_ms": 10.0}},
		"order":     []string{"check_health"},
		"m4_checks": 12, "m4_mismatch": 3,
	})
	it := scWatchdogActionsItem(fixtureWA(t, string(b), now))
	if it.Status != scOK {
		t.Fatalf("影子不一致只观察, 不应改状态: %s", it.Status)
	}
	if !strings.Contains(it.Detail, "设备发现影子: 比对 12 轮, 不一致 3 轮") {
		t.Fatalf("Detail = %q", it.Detail)
	}
}
