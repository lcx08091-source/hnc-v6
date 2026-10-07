// online_minutes_v530_test.go — v5.30 T1a: /api/online_hours 按分钟累计。
//
// 「改动前会失败」: v5.29 的 onlineHoursByMAC 一行算 1 小时, 只在一次采样时
// 在线的设备(watchdog 落盘 "m":5)在 hours 里是 1 —— TestAPIOnlineHoursMinutes
// 断言 hours 里没有它、online_min 是 5, 旧代码下两条都失败。
package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var ohNow = time.Date(2026, 10, 7, 15, 0, 0, 0, time.Local)

const (
	ohA, ohB, ohC = "aa:bb:cc:dd:ee:0a", "aa:bb:cc:dd:ee:0b", "aa:bb:cc:dd:ee:0c"
	ohToday       = "20261007"
	ohYesterday   = "20261006"
)

func writeOnlineHours(t *testing.T, dir string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "online_hours.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ohFixture(t *testing.T) string {
	dir := t.TempDir()
	writeOnlineHours(t, dir,
		`{"t":1,"day":"`+ohToday+`","mac":"`+ohA+`","m":5}`, // 只赶上一次采样
		`{"t":1,"day":"`+ohToday+`","mac":"`+ohB+`"}`,       // 旧格式: 60
		`{"t":,"day":"`+ohToday+`","mac":"`+ohB+`"}`,        // 旧坏行: 60
		`{"t":2,"day":"`+ohYesterday+`","mac":"`+ohC+`","m":7}`,
		`{"t":2,"day":"`+ohToday+`","mac":"`+ohC+`","m":3}`, // 跨日拆成两行
		`{"t":3,"day":"`+ohToday+`","mac":"`+ohC+`","m":55}`,
		`{"t":,"day":"`+ohToday+`","mac":"`+ohA+`","m":10}`,  // 坏行也认 m
		`{"t":4,"day":"`+ohToday+`","mac":"`+ohA+`","m":-3}`, // 负数忽略
	)
	return dir
}

func TestOnlineMinutesNewAndLegacyRows(t *testing.T) {
	got := onlineMinutesByMAC(ohFixture(t), 7, ohNow)
	want := map[string]map[string]int{
		ohA: {ohToday: 15},
		ohB: {ohToday: 120},
		ohC: {ohYesterday: 7, ohToday: 58},
	}
	gb, _ := json.Marshal(got)
	wb, _ := json.Marshal(want)
	if string(gb) != string(wb) {
		t.Fatalf("minutes = %s, want %s", gb, wb)
	}
}

func TestOnlineMinutesDayCapAndCutoff(t *testing.T) {
	dir := t.TempDir()
	var lines []string
	for i := 0; i < 30; i++ { // 30 行旧格式 = 30 小时 → 封顶 24 小时
		lines = append(lines, `{"t":1,"day":"`+ohToday+`","mac":"`+ohA+`"}`)
	}
	lines = append(lines, `{"t":1,"day":"20260901","mac":"`+ohB+`","m":30}`) // 超出 7 天窗口
	writeOnlineHours(t, dir, lines...)
	got := onlineMinutesByMAC(dir, 7, ohNow)
	if got[ohA][ohToday] != 1440 || got[ohB] != nil {
		t.Fatalf("got %v", got)
	}
	if h := onlineHoursFromMinutes(got); h[ohA][ohToday] != 24 {
		t.Fatalf("hours = %v", h)
	}
}

// 接线: 走真实 handler /api/online_hours。
func TestAPIOnlineHoursMinutes(t *testing.T) {
	old := onlineNowFn
	onlineNowFn = func() time.Time { return ohNow }
	t.Cleanup(func() { onlineNowFn = old })
	s := newServer(ohFixture(t))
	rec := httptest.NewRecorder()
	s.apiOnlineHours(rec, httptest.NewRequest("GET", "/api/online_hours", nil))
	var r struct {
		Hours map[string]map[string]int `json:"hours"`
		Min   map[string]map[string]int `json:"online_min"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	if r.Min[ohA][ohToday] != 15 {
		t.Errorf("online_min[A] = %v, want 15", r.Min[ohA])
	}
	if _, ok := r.Hours[ohA]; ok {
		t.Errorf("15 分钟不应出现在 hours(旧代码一行算 1 小时): %v", r.Hours[ohA])
	}
	if r.Hours[ohB][ohToday] != 2 || r.Min[ohB][ohToday] != 120 {
		t.Errorf("旧格式两行: hours=%v min=%v, want 2 / 120", r.Hours[ohB], r.Min[ohB])
	}
	if r.Hours[ohC][ohToday] != 0 || r.Min[ohC][ohToday] != 58 || r.Min[ohC][ohYesterday] != 7 {
		t.Errorf("C: hours=%v min=%v", r.Hours[ohC], r.Min[ohC])
	}
}
