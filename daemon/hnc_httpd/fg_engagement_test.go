// fg_engagement_test.go — v5.28 B4: 交互节拍(影子)行为锁定。
package main

import (
	"testing"
	"time"
)

func TestFgEngagementOf(t *testing.T) {
	cases := []struct {
		f    fgFeat
		want string
		note string
	}{
		{fgFeat{NewPerMin: 8, DnBps: 900_000}, "interactive", "新建连接频繁 = 人在操作"},
		{fgFeat{RR: 10}, "interactive", "请求-响应突发多 = 人在操作"},
		{fgFeat{Bulk: true, DnBps: 3_000_000}, "background", "大文件下载特征 = 后台"},
		{fgFeat{HBShare: 0.85}, "background", "心跳占比高 = 后台"},
		{fgFeat{DnBps: 1000, UpBps: 500}, "background", "速率低于心跳级 = 后台"},
		{fgFeat{DnBps: 300_000, NewPerMin: 1}, "passive", "下行持续无新请求 = 在看/在听"},
		{fgFeat{DnBps: 40_000, NewPerMin: 1}, "unknown", "量级不足三态 = 未知"},
		{fgFeat{}, "background", "零流量 = 心跳级以下"},
	}
	for _, c := range cases {
		if got := fgEngagementOf(c.f); got != c.want {
			t.Errorf("%s: got %s, want %s (DnBps=%.0f NewPerMin=%.1f RR=%d HB=%.2f Bulk=%v)",
				c.note, got, c.want, c.f.DnBps, c.f.NewPerMin, c.f.RR, c.f.HBShare, c.f.Bulk)
		}
	}
}

func TestFgEngDominant(t *testing.T) {
	if got := fgEngDominant([3]int{1, 3, 2}); got != "passive" {
		t.Errorf("want passive, got %s", got)
	}
	if got := fgEngDominant([3]int{2, 2, 1}); got != "interactive" {
		t.Errorf("平票应按 interactive > passive > background, got %s", got)
	}
	if got := fgEngDominant([3]int{}); got != "" {
		t.Errorf("空直方图应为空标签, got %s", got)
	}
}

// TestFgSessionEngagementExtend extendSessionLocked 每轮累计节拍, 主导标签更新。
func TestFgSessionEngagementExtend(t *testing.T) {
	m := newFgModel()
	m.day = &fgDay{Date: time.Now().Format("20060102"), Devices: map[string][]fgSession{}}
	mac := "aa:bb:cc:dd:ee:01"
	m.day.Devices[mac] = []fgSession{{App: "pkg:a", Name: "A", Start: 100, End: 100}}
	end := time.Unix(200, 0)
	// 5 轮 passive, 2 轮 interactive → 主导 passive
	for i := 0; i < 5; i++ {
		m.extendSessionLocked(mac, end, 0.5, "passive")
	}
	for i := 0; i < 2; i++ {
		m.extendSessionLocked(mac, end, 0.5, "interactive")
	}
	s := m.day.Devices[mac][0]
	if s.Eng != "passive" || s.EngN != [3]int{2, 5, 0} {
		t.Fatalf("主导=%q 直方图=%v, want passive/[2 5 0]", s.Eng, s.EngN)
	}
	if s.End != 200 || s.N != 7 {
		t.Fatalf("原有行为不应改变: End=%d N=%d", s.End, s.N)
	}
	// unknown 不计数
	m.extendSessionLocked(mac, end, 0.5, "unknown")
	if s2 := m.day.Devices[mac][0]; s2.EngN != [3]int{2, 5, 0} {
		t.Fatalf("unknown 不应计入: %v", s2.EngN)
	}
}

// TestFgViewEngagementField buildViewLocked 给前台应用带上节拍字段(轻量冒烟)。
func TestFgViewEngagementField(t *testing.T) {
	m := newFgModel()
	d := &fgDev{apps: map[string]*fgApp{}, shown: "pkg:a"}
	a := &fgApp{id: "pkg:a", name: "A", smooth: 100, inst: 100}
	a.f = fgFeat{NewPerMin: 9, DnBps: 500_000}
	d.apps["pkg:a"] = a
	v := m.buildViewLocked(d, []*fgApp{a}, time.Now(), 10, "ok")
	if v.Engagement != "interactive" {
		t.Fatalf("view.engagement = %q, want interactive", v.Engagement)
	}
}
