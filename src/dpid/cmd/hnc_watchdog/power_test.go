package main

import (
	"syscall"
	"testing"
	"time"
)

func TestParseScheduleCfg(t *testing.T) {
	c := parseScheduleCfg([]byte(`{"hotspot_time_enable":true,"hotspot_time_start":"22:00","hotspot_time_end":"07:30","hotspot_charging_only":false,"devices":{}}`))
	if !c.TimeOn || c.Start != 22*60 || c.End != 7*60+30 || c.ChargeOn {
		t.Fatalf("cfg = %+v", c)
	}
	if c := parseScheduleCfg([]byte(`{"hotspot_time_enable":true,"hotspot_time_start":"25:00","hotspot_time_end":"x"}`)); c.Start != -1 || c.End != -1 {
		t.Fatalf("非法时间应为 -1: %+v", c)
	}
	if c := parseScheduleCfg([]byte(`not json`)); c.TimeOn || c.ChargeOn {
		t.Fatalf("坏 JSON 应全关: %+v", c)
	}
}

func TestScheduleNextBoundary(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	c := scheduleCfg{TimeOn: true, Start: 22 * 60, End: 7 * 60}
	now := time.Date(2026, 10, 3, 21, 0, 0, 0, loc)
	if d := c.nextBoundary(now); d != time.Hour+2*time.Second {
		t.Fatalf("21:00 → 22:00:02, got %v", d)
	}
	now = time.Date(2026, 10, 3, 23, 0, 0, 0, loc) // 下一个是次日 07:00
	if d := c.nextBoundary(now); d != 8*time.Hour+2*time.Second {
		t.Fatalf("23:00 → 次日 07:00:02, got %v", d)
	}
	if d := (scheduleCfg{TimeOn: false, Start: 1, End: 2}).nextBoundary(now); d != -1 {
		t.Fatalf("未开启应为 -1, got %v", d)
	}
	// 跨过边界判定
	last := time.Date(2026, 10, 3, 21, 59, 0, 0, loc)
	if !crossedBoundary(c, last, time.Date(2026, 10, 3, 22, 0, 5, 0, loc)) {
		t.Fatal("21:59 → 22:00:05 应跨过开始边界")
	}
	if crossedBoundary(c, last, time.Date(2026, 10, 3, 21, 59, 50, 0, loc)) {
		t.Fatal("21:59 → 21:59:50 不应跨过")
	}
}

func TestSchedulerMaxSleepCharge(t *testing.T) {
	h := &hotspotScheduler{cfg: scheduleCfg{ChargeOn: true, Start: -1, End: -1}, cfgAt: time.Now(), cfgMod: time.Time{}}
	// config() 会因 rules.json 不存在而重置为全关 → maxSleep = -1, 不约束
	if d := h.maxSleep(time.Now()); d != -1 {
		t.Fatalf("无 rules.json 时不应约束睡眠, got %v", d)
	}
}

func TestNetlinkHasLinkOrAddr(t *testing.T) {
	mk := func(typ uint16) []byte {
		b := make([]byte, syscall.NLMSG_HDRLEN)
		*(*uint32)(ptr(b, 0)) = uint32(syscall.NLMSG_HDRLEN)
		*(*uint16)(ptr(b, 4)) = typ
		return b
	}
	if !netlinkHasLinkOrAddr(mk(syscall.RTM_NEWADDR)) || !netlinkHasLinkOrAddr(mk(syscall.RTM_DELLINK)) {
		t.Fatal("地址 / 网卡事件应唤醒")
	}
	if netlinkHasLinkOrAddr(mk(syscall.RTM_NEWROUTE)) {
		t.Fatal("路由事件不应唤醒")
	}
}

func TestOnlineMACs(t *testing.T) {
	now := int64(1_800_000_000)
	b := []byte(`{"aa:bb:cc:dd:ee:01":{"status":"allowed","last_seen":1799999990},
	"aa:bb:cc:dd:ee:02":{"status":"blocked","last_seen":1799999990},
	"aa:bb:cc:dd:ee:03":{"status":"allowed","last_seen":1799990000},
	"AA:BB:CC:DD:EE:04":{"online":true}}`)
	got := map[string]bool{}
	for _, m := range onlineMACs(b, now) {
		got[m] = true
	}
	if len(got) != 2 || !got["aa:bb:cc:dd:ee:01"] || !got["aa:bb:cc:dd:ee:04"] {
		t.Fatalf("online = %v", got)
	}
}

func TestClockSaneNow(t *testing.T) {
	if clockSaneNow(time.Unix(1_000_000_000, 0)) {
		t.Fatal("2001 年不可信")
	}
}
