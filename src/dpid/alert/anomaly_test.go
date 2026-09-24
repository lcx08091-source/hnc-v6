package alert

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var cst = time.FixedZone("CST", 8*3600)

// writeRows 按 dpid 的写法(UTC 日期命名)把行追加进 stats.YYYYMMDD.jsonl。
func writeRows(t *testing.T, dir string, rows ...[3]int64) {
	t.Helper()
	for _, r := range rows { // r = {ts, macSuffix, bytes}
		ts := time.Unix(r[0], 0)
		p := filepath.Join(dir, "stats."+ts.UTC().Format("20060102")+".jsonl")
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(f, `{"t":%d,"mac":"aa:bb:cc:dd:ee:%02x","app_id":"x","tx":%d,"rx":0}`+"\n", r[0], r[1], r[2])
		f.Close()
	}
}

// 线索 1 回归: 东八区凌晨 03:xx, 当前小时的数据在前一个 UTC 日文件里。
func TestSumByMAC_EarlyMorningUTCFile(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 24, 3, 30, 0, 0, cst) // UTC 2026-09-23 19:30
	hourStart := time.Date(2026, 9, 24, 3, 0, 0, 0, cst)
	writeRows(t, dir,
		[3]int64{now.Add(-10 * time.Minute).Unix(), 1, 100},
		[3]int64{hourStart.Add(-time.Second).Unix(), 1, 7}, // 上一小时, 不计
	)
	got := map[string]uint64{}
	if err := sumByMAC(dir, hourStart.Unix(), now.Unix()+1, got); err != nil {
		t.Fatal(err)
	}
	if got["aa:bb:cc:dd:ee:01"] != 100 {
		t.Fatalf("凌晨当前小时应读到 UTC 前一日文件的 100B, got %v", got)
	}
}

// 左闭右开: 恰在边界秒的行只属于后一个窗口。
func TestSumByMAC_HalfOpenBoundary(t *testing.T) {
	dir := t.TempDir()
	b := time.Date(2026, 9, 24, 0, 0, 0, 0, cst).Unix()
	writeRows(t, dir, [3]int64{b, 1, 5})
	a1, a2 := map[string]uint64{}, map[string]uint64{}
	_ = sumByMAC(dir, b-3600, b, a1)
	_ = sumByMAC(dir, b, b+3600, a2)
	if a1["aa:bb:cc:dd:ee:01"]+a2["aa:bb:cc:dd:ee:01"] != 5 {
		t.Fatalf("边界行应只计一次: %v %v", a1, a2)
	}
}

func withNow(t *testing.T, now time.Time) {
	old := nowLocal
	nowLocal = func() time.Time { return now }
	t.Cleanup(func() { nowLocal = old })
}

// 月度配额: 本地 1 号 02:00(= UTC 上月最后一天 18:00)的行必须计入本月,
// 本地上月最后一天 23:00 的行不得计入。
func TestDetectMonthlyQuota_LocalMonthBoundary(t *testing.T) {
	hnc := t.TempDir()
	run := filepath.Join(hnc, "run")
	os.MkdirAll(run, 0o755)
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, cst)
	withNow(t, now)
	writeRows(t, run,
		[3]int64{time.Date(2026, 9, 1, 2, 0, 0, 0, cst).Unix(), 1, 600},
		[3]int64{time.Date(2026, 8, 31, 23, 0, 0, 0, cst).Unix(), 1, 10000},
		[3]int64{time.Date(2026, 9, 10, 0, 0, 0, 0, cst).Unix(), 1, 500}, // 本地零点边界行
	)
	cfg := NewConfig(hnc)
	cfg.DisableNotify = true
	uc := DefaultConfig()
	uc.MonthlyQuota = QuotaCfg{Enabled: true, LimitBytes: 1000, WarnAtPct: 80}
	n, err := detectMonthlyQuota(cfg, uc)
	if err != nil || n != 1 {
		t.Fatalf("应恰好 1 条告警, n=%d err=%v", n, err)
	}
	b, _ := os.ReadFile(cfg.AlertsJSONLPath)
	if !strings.Contains(string(b), `"used_bytes":1100`) || !strings.Contains(string(b), `"warn_level":"over"`) {
		t.Fatalf("本月用量应为 1100(不含上月、边界行只计一次): %s", b)
	}
}

func TestInQuietHours_UsesGivenLocalHour(t *testing.T) {
	u := UnknownDevice{QuietHourStart: 23, QuietHourEnd: 7}
	// 北京时间 02:00 = UTC 18:00: 按本地判断应在免打扰内。
	if !inQuietHours(time.Date(2026, 9, 24, 2, 0, 0, 0, cst), u) {
		t.Fatal("本地 02:00 应处于免打扰")
	}
	if inQuietHours(time.Date(2026, 9, 24, 10, 0, 0, 0, cst), u) {
		t.Fatal("本地 10:00 不应处于免打扰")
	}
}

func TestDayFileKeys(t *testing.T) {
	from := time.Date(2026, 9, 24, 3, 0, 0, 0, cst)
	to := time.Date(2026, 9, 24, 3, 59, 59, 0, cst)
	got := strings.Join(dayFileKeys(from, to), ",")
	if got != "20260923,20260924" {
		t.Fatalf("got %s", got)
	}
}
