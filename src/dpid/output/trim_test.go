package output

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mkDaily creates an empty <prefix>YYYYMMDD<suffix> file for `back` days ago.
func mkDaily(t *testing.T, dir, prefix, suffix string, now time.Time, back int, utc bool) string {
	t.Helper()
	d := now.AddDate(0, 0, -back)
	day := d.Format("20060102")
	if utc {
		day = d.UTC().Format("20060102")
	}
	p := filepath.Join(dir, prefix+day+suffix)
	if err := os.WriteFile(p, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("create %s: %v", p, err)
	}
	return p
}

func TestTrimDailyFiles_LocalTZ(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	var keep, drop []string
	// Retention window (0..retain days back) must survive.
	for back := 0; back <= SelfAttribRetainDays; back++ {
		keep = append(keep, mkDaily(t, dir, "self_attrib.", ".jsonl", now, back, false))
	}
	// (retain+1 .. 30) days back must be deleted.
	for _, back := range []int{SelfAttribRetainDays + 1, 15, 30} {
		drop = append(drop, mkDaily(t, dir, "self_attrib.", ".jsonl", now, back, false))
	}
	// Older than the 30-day sweep window: the glob-based trimmer (v5.9.6)
	// now catches these too — the old "manual cleanup territory" policy is
	// gone; the 30-day leak was the very bug this rewrite fixes.
	tooOld := mkDaily(t, dir, "self_attrib.", ".jsonl", now, 31, false)
	// Foreign prefix in the same dir must never be touched.
	foreign := mkDaily(t, dir, "stats.", ".jsonl", now, 15, false)

	trimDailyFiles(dir, "self_attrib.", SelfAttribRetainDays)

	for _, p := range keep {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("retained file was deleted: %s", p)
		}
	}
	for _, p := range drop {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expired file survived: %s", p)
		}
	}
	if _, err := os.Stat(tooOld); !os.IsNotExist(err) {
		t.Errorf(">30d file should now be deleted by the glob-based trimmer: %s", tooOld)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("foreign-prefix file must not be touched: %s", foreign)
	}
}

// v5.12: 月度配额(alert/quota.go)要读整个自然月的 stats.*.jsonl, 保留期必须
// 覆盖最长自然月(31 天)再加 1 天 UTC/本地日期错位余量。
func TestHistoryRetainCoversCalendarMonth(t *testing.T) {
	for m := time.January; m <= time.December; m++ {
		// 取闰年, 覆盖 2 月 29 天
		daysInMonth := time.Date(2024, m+1, 0, 0, 0, 0, 0, time.UTC).Day()
		if HistoryRetainDays < daysInMonth+1 {
			t.Fatalf("HistoryRetainDays=%d < %d 月天数 %d + 1, 月度配额会少算",
				HistoryRetainDays, m, daysInMonth)
		}
	}

	// 实跑一次 trim: 最坏情况(本地 31 号)要回看 31 天前的 UTC 日文件, 必须保留。
	dir := t.TempDir()
	now := time.Now()
	var keep []string
	for back := 0; back <= 31; back++ {
		keep = append(keep, mkDaily(t, dir, "stats.", ".jsonl", now, back, true))
	}
	trimDailyFiles(dir, "stats.", HistoryRetainDays)
	for _, p := range keep {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("月度配额窗口内的文件被删: %s", p)
		}
	}
}

func TestTrimDailyFiles_UTC(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	kept := mkDaily(t, dir, "stats.", ".jsonl", now, HistoryRetainDays, true)
	dropped := mkDaily(t, dir, "stats.", ".jsonl", now, HistoryRetainDays+1, true)

	trimDailyFiles(dir, "stats.", HistoryRetainDays)

	if _, err := os.Stat(kept); err != nil {
		t.Errorf("retained UTC file was deleted: %s", kept)
	}
	if _, err := os.Stat(dropped); !os.IsNotExist(err) {
		t.Errorf("expired UTC file survived: %s", dropped)
	}
}
