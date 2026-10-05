package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixtureWA 构造带 run/watchdog_actions.json 的假环境(内容 = 看门狗侧
// actionstats.go flush 出的同一格式), 返回 (fakeSys, scCtx)。
func fixtureWA(t *testing.T, content string, now time.Time) *scCtx {
	f := newFakeSys("/data/local/hnc")
	f.now = now
	if content != "" {
		f.files[f.h("run", "watchdog_actions.json")] = content
	}
	env := f.scEnv()
	return &scCtx{env: env, ctx: t.Context()}
}

// waJSON 生成与看门狗 actionstats.go 相同 schema 的记账 JSON(原生 map 构造,
// 字段名与 run/watchdog_actions.json 一致)。
func waJSON(gen int64, actions map[string]interface{}, order []string) string {
	if order == nil {
		names := make([]string, 0, len(actions))
		for n := range actions {
			names = append(names, n)
		}
		order = names
	}
	b, _ := json.Marshal(map[string]interface{}{
		"schema":       1,
		"generated_at": gen,
		"actions":      actions,
		"order":        order,
	})
	return string(b)
}

// TestScWatchdogActionsNoData 文件缺失 → info(看门狗未运行/刚启动)。
func TestScWatchdogActionsNoData(t *testing.T) {
	now := time.Unix(1791000000, 0)
	c := fixtureWA(t, "", now)
	it := scWatchdogActionsItem(c)
	if it.Status != scInfo {
		t.Fatalf("无数据应 info, got %s", it.Status)
	}
	if !strings.Contains(it.Value, "暂无") {
		t.Errorf("Value = %q, 应提示暂无数据", it.Value)
	}
}

// TestScWatchdogActionsAllNormal 全正常 → ok + 「N 次/小时 · 平均 x 毫秒」。
func TestScWatchdogActionsAllNormal(t *testing.T) {
	now := time.Unix(1791000000, 0)
	doc := waJSON(now.Unix()-30, map[string]interface{}{
		"check_health":     map[string]interface{}{"calls_1h": 60.0, "fails_1h": 0.0, "last_rc": 0.0, "avg_ms": 120.5, "max_ms": 300.0},
		"probe_hotspot":    map[string]interface{}{"calls_1h": 60.0, "fails_1h": 0.0, "last_rc": 0.0, "avg_ms": 40.0, "max_ms": 90.0},
		"capability_probe": map[string]interface{}{"calls_1h": 1.0, "fails_1h": 0.0, "last_rc": 0.0, "avg_ms": 900.0, "max_ms": 900.0},
	}, []string{"check_health", "probe_hotspot", "capability_probe"})
	c := fixtureWA(t, doc, now)
	it := scWatchdogActionsItem(c)
	if it.Status != scOK {
		t.Fatalf("全正常应 ok, got %s(%s)", it.Status, it.Detail)
	}
	if !strings.Contains(it.Value, "121") { // 60+60+1 = 121 次
		t.Errorf("Value = %q, 应含合计次数 121", it.Value)
	}
	if !strings.Contains(it.Value, "毫秒") {
		t.Errorf("Value = %q, 应含平均毫秒", it.Value)
	}
}

// TestScWatchdogActions127 有动作 1 小时内失败(127)→ 警告并列出动作名。
// 这正是 v5.26 真机事故场景(tc_uplink_healthy 一直 exit 127 没人发现)。
func TestScWatchdogActions127(t *testing.T) {
	now := time.Unix(1791000000, 0)
	doc := waJSON(now.Unix()-30, map[string]interface{}{
		"check_health":      map[string]interface{}{"calls_1h": 60.0, "fails_1h": 0.0, "last_rc": 0.0, "avg_ms": 100.0, "max_ms": 200.0},
		"tc_uplink_healthy": map[string]interface{}{"calls_1h": 20.0, "fails_1h": 20.0, "last_rc": 127.0, "last_fail_at": now.Unix() - 60, "avg_ms": 15.0, "max_ms": 30.0},
	}, []string{"check_health", "tc_uplink_healthy"})
	c := fixtureWA(t, doc, now)
	it := scWatchdogActionsItem(c)
	if it.Status != scWarn {
		t.Fatalf("有 127 失败应 warn, got %s", it.Status)
	}
	if !strings.Contains(it.Detail, "tc_uplink_healthy") {
		t.Errorf("Detail = %q, 应列出失败动作名", it.Detail)
	}
	if !strings.Contains(it.Detail, "127") {
		t.Errorf("Detail = %q, 应提示返回码 126/127", it.Detail)
	}
}

// TestScWatchdogActionsTooManyCalls 外部进程合计 > 400 次/小时 → 警告。
func TestScWatchdogActionsTooManyCalls(t *testing.T) {
	now := time.Unix(1791000000, 0)
	doc := waJSON(now.Unix()-30, map[string]interface{}{
		"check_health": map[string]interface{}{"calls_1h": 450.0, "fails_1h": 0.0, "last_rc": 0.0, "avg_ms": 10.0, "max_ms": 20.0},
	}, []string{"check_health"})
	c := fixtureWA(t, doc, now)
	it := scWatchdogActionsItem(c)
	if it.Status != scWarn {
		t.Fatalf("调用过多应 warn, got %s", it.Status)
	}
	if !strings.Contains(it.Detail, "偏多") {
		t.Errorf("Detail = %q, 应说明看门狗调用偏多", it.Detail)
	}
}

// TestScWatchdogActionsStale 记账 > 3 分钟未刷新 → 降 info 提示看门狗可能没在跑。
func TestScWatchdogActionsStale(t *testing.T) {
	now := time.Unix(1791000000, 0)
	doc := waJSON(now.Unix()-6*60, map[string]interface{}{
		"check_health": map[string]interface{}{"calls_1h": 60.0, "fails_1h": 0.0, "last_rc": 0.0, "avg_ms": 100.0, "max_ms": 200.0},
	}, []string{"check_health"})
	c := fixtureWA(t, doc, now)
	it := scWatchdogActionsItem(c)
	if it.Status != scInfo {
		t.Fatalf("过期记账应 info, got %s", it.Status)
	}
	if !strings.Contains(it.Detail, "未刷新") {
		t.Errorf("Detail = %q, 应提示记账未刷新", it.Detail)
	}
}

// TestReadWatchdogActionsRaw /api/power 段: 原样转出 + stale 标记(临时目录真文件)。
func TestReadWatchdogActionsRaw(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	doc := `{"schema":1,"generated_at":1790999970,"order":["a"],"actions":{"a":{"calls_1h":9}}}`
	os.WriteFile(filepath.Join(dir, "run", "watchdog_actions.json"), []byte(doc), 0o644)

	now := time.Unix(1791000000, 0) // 30s 后
	m := readWatchdogActionsRaw(dir, now)
	if m == nil || m["stale"] != false {
		t.Fatalf("新鲜文件应原样转出且 stale=false, got %#v", m)
	}
	if a, _ := m["actions"].(map[string]interface{}); a == nil || a["a"] == nil {
		t.Errorf("actions 应原样转出, got %#v", m["actions"])
	}

	now = time.Unix(1791000000+240, 0) // 4 分钟后
	m = readWatchdogActionsRaw(dir, now)
	if m["stale"] != true {
		t.Fatalf("超 3 分钟应 stale=true, got %#v", m)
	}

	// 文件不存在 → nil
	if m := readWatchdogActionsRaw(t.TempDir(), now); m != nil {
		t.Fatalf("无文件应 nil, got %#v", m)
	}
}

// TestScSectionProcessContainsWatchdogActions 全量自检里「进程与资源」含新行。
func TestScSectionProcessContainsWatchdogActions(t *testing.T) {
	now := time.Unix(1791000000, 0)
	doc := waJSON(now.Unix()-30, map[string]interface{}{
		"check_health": map[string]interface{}{"calls_1h": 60.0, "fails_1h": 0.0, "last_rc": 0.0, "avg_ms": 100.0, "max_ms": 200.0},
	}, []string{"check_health"})
	f := newFakeSys("/data/local/hnc")
	f.now = now
	f.files[f.h("run", "watchdog_actions.json")] = doc
	env := f.scEnv()
	c := &scCtx{env: env, ctx: t.Context()}
	items := scSectionProcess(c)
	found := false
	for _, it := range items {
		if it.ID == "watchdog_actions" {
			found = true
			if it.Status != scOK {
				t.Errorf("watchdog_actions 行状态 = %s, want ok", it.Status)
			}
		}
	}
	if !found {
		t.Fatal("scSectionProcess 应含 watchdog_actions 行")
	}
}
