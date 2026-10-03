package main

// v5.26 T4 单测: 全局告警月度配额(有/无设备配额、warn→over 升档、
// 同月不重复、跨计费月重置)与 usage_month 权威口径/回退。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// nowBase 今天正午(本地)。MonthUsage/MonthUsageSplit 内部用 time.Now(),
// 测试必须用同一天的受控时间喂 tick, 否则计费月对不上。
func nowBase() time.Time {
	n := time.Now()
	return time.Date(n.Year(), n.Month(), n.Day(), 12, 0, 0, 0, n.Location())
}

// gqFixture: 在 ctlFixture 基础上启用全局月度配额。
func gqSetup(t *testing.T, limitBytes int64, warnPct int) *ctlFixture {
	f := newFixture(t)
	cfg := map[string]interface{}{
		"enabled": true,
		"monthly_quota": map[string]interface{}{
			"enabled":     true,
			"limit_bytes": limitBytes,
			"warn_at_pct": warnPct,
		},
	}
	b, _ := json.Marshal(cfg)
	os.WriteFile(filepath.Join(f.dir, "data", "alerts_config.json"), b, 0o644)
	return f
}

// gqFeed: 两次 tick 把 from→to 的计数器增量喂进 MonthBytes。
func gqFeed(f *ctlFixture, mac string, rx1, rx2 int64, at time.Time) {
	f.writeDevices(map[string][2]int64{mac: {rx1, 0}})
	f.c.tick(at)
	f.writeDevices(map[string][2]int64{mac: {rx2, 0}})
	f.c.tick(at.Add(time.Minute))
}

func gqAlerts(f *ctlFixture) []string {
	b, _ := os.ReadFile(filepath.Join(f.dir, "run", "alerts.jsonl"))
	var out []string
	for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if ln == "" || !strings.Contains(ln, "monthly_quota") {
			continue
		}
		out = append(out, ln)
	}
	return out
}

func TestGlobalQuotaWarnOverNoDevicePolicy(t *testing.T) {
	f := gqSetup(t, 1000, 80)
	mid := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)

	// 无设备配额: 跨过 warn(800) → 1 条 warn
	gqFeed(f, tMAC, 0, 850, mid)
	if a := gqAlerts(f); len(a) != 1 || !strings.Contains(a[0], `"warn_level":"warn"`) {
		t.Fatalf("want 1 warn alert, got %v", a)
	}
	// 同月再 tick: 不重复
	f.writeDevices(map[string][2]int64{tMAC: {900, 0}})
	f.c.tick(mid.Add(2 * time.Minute))
	if a := gqAlerts(f); len(a) != 1 {
		t.Fatalf("same month should not duplicate warn: %v", a)
	}
	// 超过 limit(1000) → 升档 over(同月第 2 条)
	f.writeDevices(map[string][2]int64{tMAC: {1200, 0}})
	f.c.tick(mid.Add(3 * time.Minute))
	a := gqAlerts(f)
	if len(a) != 2 || !strings.Contains(a[1], `"warn_level":"over"`) {
		t.Fatalf("want warn+over upgrade, got %v", a)
	}
	if !strings.Contains(a[1], "超出配额") || !strings.Contains(a[0], "达到配额") {
		t.Fatalf("detail 文案应沿用 quota.go 写法: %v", a)
	}
	// over 同月也不重复
	f.writeDevices(map[string][2]int64{tMAC: {1300, 0}})
	f.c.tick(mid.Add(4 * time.Minute))
	if a := gqAlerts(f); len(a) != 2 {
		t.Fatalf("same month should not duplicate over: %v", a)
	}
	// ID 带档位 + mac 去冒号
	if !strings.Contains(a[0], `"id":"monthly_quotawarn_aabbccdde`) {
		t.Fatalf("ID 应为 makeAlertID(monthly_quota+kind, mac): %v", a)
	}
}

func TestGlobalQuotaSkipsDeviceWithQuota(t *testing.T) {
	f := gqSetup(t, 1000, 80)
	mid := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	// tMAC 设置设备级月配额 → 不发全局告警(设备配额自己会告警)
	if r := f.c.actionQuotaSet(map[string]string{"mac": tMAC, "monthly_gb": "1", "action": "block"}); !r.OK {
		t.Fatalf("quota set: %+v", r)
	}
	gqFeed(f, tMAC, 0, 2000, mid)
	if a := gqAlerts(f); len(a) != 0 {
		t.Fatalf("有设备配额的设备不应发全局告警: %v", a)
	}
	// 未设配额的其它设备照发
	other := "aa:bb:cc:dd:ee:02"
	gqFeed(f, other, 0, 2000, mid.Add(10*time.Minute))
	if a := gqAlerts(f); len(a) != 1 {
		t.Fatalf("无设备配额的设备应发全局告警: %v", a)
	}
}

func TestGlobalQuotaNewMonthResets(t *testing.T) {
	f := gqSetup(t, 1000, 80)
	m1 := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	gqFeed(f, tMAC, 0, 850, m1)
	if a := gqAlerts(f); len(a) != 1 {
		t.Fatalf("want 1 warn: %v", a)
	}
	// 下个计费月(自然月 10 月): 新 monKey → warn 重新可发
	m2 := time.Date(2026, 10, 15, 12, 0, 0, 0, time.Local)
	gqFeed(f, tMAC, 0, 900, m2)
	a := gqAlerts(f)
	if len(a) != 2 {
		t.Fatalf("跨计费月应重置去重: %v", a)
	}
}

func TestMonthUsageAndFallback(t *testing.T) {
	f := gqSetup(t, 1000, 80)
	mid := nowBase()

	// 未 tick 过: histMon 没算 → MonthUsageSplit 报未就绪(调用方回退 DPI 合计)
	if _, _, _, ok := f.c.MonthUsageSplit(); ok {
		t.Fatal("fresh ctl should not be ready")
	}
	// 有全局配额 → tick 会算 histMon → 就绪
	gqFeed(f, tMAC, 0, 500, mid)
	if _, _, _, ok := f.c.MonthUsageSplit(); !ok {
		t.Fatal("after tick with global quota, should be ready")
	}
	// 合计 = 自有累加(500), rx/tx 拆分一致
	mu := f.c.MonthUsage()
	if mu[tMAC] != 500 {
		t.Fatalf("MonthUsage = %v, want 500", mu)
	}
	split, _, _, _ := f.c.MonthUsageSplit()
	if split[tMAC].RX+split[tMAC].TX != 500 || split[tMAC].RX != 500 {
		t.Fatalf("split = %+v, want rx=500 tx=0", split[tMAC])
	}
}

func TestMonthUsagePrefersBiggerSource(t *testing.T) {
	f := gqSetup(t, 1000, 80)
	mid := nowBase()
	// 自有累加 300; DPI 历史文件里 900 → 权威取 max=900
	ts := mid.Add(-time.Hour).Unix()
	os.WriteFile(filepath.Join(f.dir, "run", "stats."+mid.Format("20060102")+".jsonl"),
		[]byte(`{"t":`+strconv.FormatInt(ts, 10)+`,"mac":"`+tMAC+`","tx":400,"rx":500}`+"\n"), 0o644)
	gqFeed(f, tMAC, 0, 300, mid)
	if mu := f.c.MonthUsage(); mu[tMAC] != 900 {
		t.Fatalf("MonthUsage = %v, want 900 (DPI 下限更大)", mu)
	}
	split, _, _, _ := f.c.MonthUsageSplit()
	if split[tMAC].RX+split[tMAC].TX != 900 {
		t.Fatalf("split 合计应等于权威口径: %+v", split[tMAC])
	}
}

// 审查补测: 没有设备配额、也没开全局配额时, 只靠 /api/usage_month 被请求触发计算。
// 请求后下一轮 tick 就要就绪(不能等 15 分钟的刷新点), 且 5 分钟后再刷新仍保持就绪。
func TestUsageMonthRequestTriggersHist(t *testing.T) {
	f := newFixture(t)
	mid := nowBase()
	gqFeed(f, tMAC, 0, 500, mid) // 无策略、无全局配额 → 不算 DPI 下限
	if _, _, _, ok := f.c.MonthUsageSplit(); ok {
		t.Fatal("no policy / no quota / no request: should not be ready")
	}
	f.c.NoteUsageMonthRequest()
	f.c.mu.Lock()
	f.c.usageMonthAt = mid.Add(90 * time.Second) // 与喂给 tick 的受控时间对齐(Note 内部用 time.Now)
	f.c.mu.Unlock()
	f.c.tick(mid.Add(2 * time.Minute)) // 远未到 limitHistEvery
	if _, _, _, ok := f.c.MonthUsageSplit(); !ok {
		t.Fatal("request should force the next tick to compute the DPI floor")
	}
	// 下一个 15 分钟刷新点时(请求已过去 ~17 分钟)仍在保持窗口内, 不应退回未就绪
	f.c.mu.Lock()
	f.c.usageMonthAt = mid.Add(2 * time.Minute)
	f.c.mu.Unlock()
	f.c.tick(mid.Add(2*time.Minute + limitHistEvery))
	if _, _, _, ok := f.c.MonthUsageSplit(); !ok {
		t.Fatal("still within limitUsageMonthKeep: should stay ready")
	}
}
