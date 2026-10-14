package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// v5.33: 自检「看门狗动作」行带出设备发现写者的写出 / 失败次数, 只观察、不改变状态;
// v5.30–v5.32 的影子比对(m4_checks)与写者开关(m4_owner)随 C 版发现一起删了,
// 旧文件里残留这些字段也不再显示。
// 「改动前会失败」: v5.32 只在有 m4_owner 时才显示写出次数(写成「设备发现: Go 版
// (看门狗)(开关 data/m4_owner; …)」), 且照旧显示影子比对。
func TestScWatchdogActionsShowsDevWriter(t *testing.T) {
	now := time.Unix(1791000000, 0)
	b, _ := json.Marshal(map[string]interface{}{
		"schema": 1, "generated_at": now.Unix() - 30,
		"actions":      map[string]interface{}{"check_health": map[string]interface{}{"calls_1h": 60.0, "fails_1h": 0.0, "avg_ms": 10.0}},
		"order":        []string{"check_health"},
		"m4_go_writes": 40, "m4_go_write_fails": 1,
		"m4_checks": 12, "m4_mismatch": 3, // v5.32 留下的旧字段
	})
	it := scWatchdogActionsItem(fixtureWA(t, string(b), now))
	if it.Status != scOK {
		t.Fatalf("写出次数只观察, 不应改状态: %s", it.Status)
	}
	if !strings.Contains(it.Detail, "设备发现(Go 看门狗): 写 40 次 / 失败 1 次") {
		t.Fatalf("Detail = %q", it.Detail)
	}
	if strings.Contains(it.Detail, "影子") || strings.Contains(it.Detail, "m4_owner") {
		t.Fatalf("影子 / 开关已删, 不应再显示: %q", it.Detail)
	}
}
