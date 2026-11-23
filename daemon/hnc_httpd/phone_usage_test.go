package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hnc.io/dpid/alert"
)

func TestPuClassifyIface(t *testing.T) {
	cases := []struct {
		name, hs, want string
	}{
		{"rmnet_data0", "wlan2", "cell"},
		{"rmnet_data11", "", "cell"},
		{"rmnet0", "wlan2", "cell"},
		{"ccmni1", "wlan2", "cell"},
		{"seth_lte0", "wlan2", "cell"},
		{"v4-rmnet_data0", "wlan2", ""}, // clat: 与 rmnet_data 重复, 不计
		{"r_rmnet_data0", "wlan2", ""},
		{"rmnet_ipa0", "wlan2", ""}, // 物理聚合口, 不计
		{"rmnet_mhi0", "wlan2", ""},
		{"wlan0", "wlan2", "wifi"},
		{"wlan0", "wlan0", "hotspot"}, // wlan0 本身是热点口时不能算 STA
		{"wlan2", "wlan2", "hotspot"},
		{"wlan1", "wlan2", ""},
		{"ap0", "", "hotspot"},    // 热点口未知时按命名兜底
		{"swlan0", "", "hotspot"}, // 同上
		{"ap0", "wlan2", ""},      // 已知热点口时不猜
		{"lo", "wlan2", ""},
		{"dummy0", "wlan2", ""},
		{"tun0", "wlan2", ""},
		{"ifb0", "wlan2", ""},
		{"p2p0", "wlan2", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := puClassifyIface(c.name, c.hs); got != c.want {
			t.Errorf("classify(%q, hs=%q) = %q, want %q", c.name, c.hs, got, c.want)
		}
	}
}

const puNetDevFixture = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  123456     100    0    0    0     0          0         0   123456     100    0    0    0     0       0          0
rmnet_data0: 1000000    900    0    0    0     0          0         0   200000     500    0    0    0     0       0          0
v4-rmnet_data0:  500000   400    0    0    0     0          0         0   100000     300    0    0    0     0       0          0
 wlan0: 3000000    2000    0    0    0     0          0         0   400000     900    0    0    0     0       0          0
 wlan2:   50000     300    0    0    0     0          0         0   700000     600    0    0    0     0       0          0
rmnet_ipa0: 9999999    1    0    0    0     0          0         0   9999999     1    0    0    0     0       0          0
`

func TestPuParseNetDev(t *testing.T) {
	m := puParseNetDev([]byte(puNetDevFixture))
	if len(m) != 6 {
		t.Fatalf("want 6 ifaces, got %d: %v", len(m), m)
	}
	if m["rmnet_data0"] != [2]uint64{1000000, 200000} {
		t.Errorf("rmnet_data0 = %v", m["rmnet_data0"])
	}
	if m["wlan0"] != [2]uint64{3000000, 400000} {
		t.Errorf("wlan0 = %v", m["wlan0"])
	}
	if m["lo"] != [2]uint64{123456, 123456} {
		t.Errorf("lo = %v", m["lo"])
	}
	// 行首无空格的长接口名 + 冒号紧贴数字
	m2 := puParseNetDev([]byte("rmnet_data10:12 1 0 0 0 0 0 0 34 1 0 0 0 0 0 0\ngarbage line\n"))
	if m2["rmnet_data10"] != [2]uint64{12, 34} {
		t.Errorf("tight format = %v", m2)
	}
}

func TestPuCounterReset(t *testing.T) {
	if d := puCounterDelta(100, 150); d != 50 {
		t.Errorf("normal delta = %d", d)
	}
	if d := puCounterDelta(1000, 30); d != 30 {
		t.Errorf("reset delta = %d, want 30", d)
	}
	if d := puCounterDelta(7, 7); d != 0 {
		t.Errorf("equal = %d", d)
	}

	prev := map[string]puCtr{
		"a": {Ifindex: 5, Rx: 100, Tx: 100},
		"b": {Ifindex: 6, Rx: 1000, Tx: 1000},
		"c": {Ifindex: 7, Rx: 10, Tx: 10},
	}
	cur := map[string]puCtr{
		"a": {Ifindex: 5, Rx: 150, Tx: 120}, // 正常
		"b": {Ifindex: 6, Rx: 20, Tx: 5000}, // rx 复位, tx 正常
		"c": {Ifindex: 9, Rx: 500, Tx: 600}, // 重建: 新 ifindex, 值还更大 —— 仍按重建算
		"d": {Ifindex: 10, Rx: 40, Tx: 60},  // 新出现
	}
	d, next := puStepCounters(prev, cur, true)
	want := map[string][2]uint64{"a": {50, 20}, "b": {20, 4000}, "c": {500, 600}, "d": {40, 60}}
	for k, w := range want {
		if d[k] != w {
			t.Errorf("delta[%s] = %v, want %v", k, d[k], w)
		}
	}
	if len(next) != 4 || next["b"].Rx != 20 {
		t.Errorf("next = %v", next)
	}
	// 未建基线: 不出增量
	d0, _ := puStepCounters(nil, cur, false)
	if len(d0) != 0 {
		t.Errorf("baseline-only produced deltas: %v", d0)
	}
	// ifindex 未知(0)时退回数值比较
	d1, _ := puStepCounters(map[string]puCtr{"x": {Rx: 10, Tx: 10}}, map[string]puCtr{"x": {Ifindex: 3, Rx: 15, Tx: 12}}, true)
	if d1["x"] != [2]uint64{5, 2} {
		t.Errorf("ifindex-unknown delta = %v", d1["x"])
	}
}

func TestPuCycleMath(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	d := func(y int, m time.Month, day, h int) time.Time { return time.Date(y, m, day, h, 0, 0, 0, loc) }
	cases := []struct {
		now        time.Time
		bd         int
		start, end time.Time
	}{
		{d(2026, 9, 30, 12), 1, d(2026, 9, 1, 0), d(2026, 10, 1, 0)},
		{d(2026, 9, 14, 23), 15, d(2026, 8, 15, 0), d(2026, 9, 15, 0)},
		{d(2026, 9, 15, 0), 15, d(2026, 9, 15, 0), d(2026, 10, 15, 0)},
		{d(2026, 1, 10, 5), 20, d(2025, 12, 20, 0), d(2026, 1, 20, 0)}, // 跨年
		{d(2026, 3, 1, 1), 28, d(2026, 2, 28, 0), d(2026, 3, 28, 0)},   // 平年 2 月
		{d(2028, 2, 29, 1), 28, d(2028, 2, 28, 0), d(2028, 3, 28, 0)},  // 闰年 2/29
		{d(2026, 2, 27, 1), 28, d(2026, 1, 28, 0), d(2026, 2, 28, 0)},  // 1/28 → 2/28(周期仅 31 天)
		{d(2026, 12, 31, 23), 1, d(2026, 12, 1, 0), d(2027, 1, 1, 0)},
		{d(2026, 5, 5, 5), 0, d(2026, 5, 1, 0), d(2026, 6, 1, 0)},  // 非法 → 1
		{d(2026, 5, 5, 5), 31, d(2026, 5, 1, 0), d(2026, 6, 1, 0)}, // 非法 → 1
	}
	for i, c := range cases {
		s := puCycleStart(c.now, c.bd)
		if !s.Equal(c.start) {
			t.Errorf("#%d start = %v, want %v", i, s, c.start)
		}
		if e := puCycleEnd(s); !e.Equal(c.end) {
			t.Errorf("#%d end = %v, want %v", i, e, c.end)
		}
	}
	now := d(2026, 3, 3, 10)
	for p, want := range map[string]time.Time{
		"month": d(2026, 3, 1, 0), "today": d(2026, 3, 3, 0),
		"7d": d(2026, 2, 25, 0), "30d": d(2026, 2, 2, 0), "": d(2026, 2, 5, 0), "cycle": d(2026, 2, 5, 0),
	} {
		_, got := puPeriodStart(p, now, 5)
		if !got.Equal(want) {
			t.Errorf("period %q start = %v, want %v", p, got, want)
		}
	}
}

func TestPuSplitAndUpstream(t *testing.T) {
	// 热点比上游还多(帧头/本机访问) → 截 0
	if got := puSplitLocal([2]uint64{100, 50}, [2]uint64{150, 20}, true); got != [2]uint64{0, 30} {
		t.Errorf("clamp = %v", got)
	}
	if got := puSplitLocal([2]uint64{100, 50}, [2]uint64{150, 20}, false); got != [2]uint64{100, 50} {
		t.Errorf("non-upstream = %v", got)
	}
	cases := []struct {
		route          string
		cell, wifi, hs uint64
		want           string
	}{
		{"cell", 1000, 0, 900, "cell"},
		{"wifi", 1000, 50, 900, "cell"}, // 路由说 Wi-Fi 但 Wi-Fi 承载不了 → 蜂窝
		{"wifi", 1000, 950, 900, "wifi"},
		{"wifi", 10, 10, 900, "wifi"}, // 都不像 → 信路由
		{"", 100, 2000, 900, "wifi"},  // 路由未知 → 增量大的
		{"", 0, 0, 900, ""},
		{"", 5, 0, 0, ""},
		{"cell", 5, 0, 0, "cell"},
	}
	for _, c := range cases {
		if got := puResolveUpstream(c.route, c.cell, c.wifi, c.hs); got != c.want {
			t.Errorf("upstream(%q,%d,%d,%d) = %q, want %q", c.route, c.cell, c.wifi, c.hs, got, c.want)
		}
	}
}

func TestPuSIMParsing(t *testing.T) {
	if puParseSubID("1\n") != 1 || puParseSubID("null") != 0 || puParseSubID("-1") != 0 {
		t.Error("parseSubID")
	}
	isub := "SubscriptionManagerService:\n  defaultSubId=2\n  defaultDataSubId=3\n  defaultVoiceSubId=2\n"
	if puParseIsubDefaultData(isub) != 3 {
		t.Errorf("isub = %d", puParseIsubDefaultData(isub))
	}
	out := "Row: 0 _id=1, sim_id=0, display_name=中国移动, carrier_name=CMCC\n" +
		"Row: 1 _id=2, sim_id=-1, display_name=旧卡, carrier_name=NULL\n" +
		"Row: 2 _id=3, sim_id=1, display_name=联通, 副卡, carrier_name=China Unicom\n"
	subs := puParseSiminfo(out)
	if len(subs) != 3 || subs[2].DisplayName != "联通, 副卡" || subs[1].CarrierName != "" || subs[2].SlotIndex != 1 {
		t.Fatalf("siminfo = %+v", subs)
	}
	alpha := puParseAlpha("中国移动,中国联通")
	s := puResolveSIM(3, "settings", subs, alpha)
	if s.Slot != 2 || s.Carrier != "联通, 副卡" || s.key() != "2|联通, 副卡" {
		t.Errorf("resolve = %+v key=%s", s, s.key())
	}
	// subId 对应的卡已拔出 → 无法确定, 两张卡都有名 → 未知
	s = puResolveSIM(2, "settings", subs, alpha)
	if s.Slot != 0 || s.key() != "0|"+puUnknownSIM {
		t.Errorf("removed sim = %+v", s)
	}
	// siminfo 失败, 只有一张卡 → 直接归它
	s = puResolveSIM(0, "", nil, puParseAlpha(",中国电信"))
	if s.Slot != 2 || s.Carrier != "中国电信" {
		t.Errorf("single sim = %+v", s)
	}
	// display_name 为空 → alpha → carrier_name
	s = puResolveSIM(9, "isub", []puSubInfo{{SubID: 9, SlotIndex: 0, CarrierName: "X"}}, nil)
	if s.Carrier != "X" || s.Slot != 1 {
		t.Errorf("fallback name = %+v", s)
	}
	if puParseRouteGet("1.1.1.1 dev rmnet_data2 table 1003 src 10.1.2.3 uid 0\n    cache\n") != "rmnet_data2" {
		t.Error("route get")
	}
}

// fakeNetDev 拼一份 /proc/net/dev
func fakeNetDev(c map[string][2]uint64) []byte {
	s := "Inter-|   Receive |  Transmit\n face |bytes    packets|bytes    packets\n"
	for k, v := range c {
		s += fmt.Sprintf("%s: %d 0 0 0 0 0 0 0 %d 0 0 0 0 0 0 0\n", k, v[0], v[1])
	}
	return []byte(s)
}

type puFake struct {
	ctr   map[string][2]uint64
	boot  string
	sim   puSIM
	route string
	alrts []alert.Alert
}

func (f *puFake) env() puEnv {
	return puEnv{
		readNetDev:   func() ([]byte, error) { return fakeNetDev(f.ctr), nil },
		hotspotIface: func() string { return "wlan2" },
		upstream:     func() string { return f.route },
		sim:          func() puSIM { return f.sim },
		bootID:       func() string { return f.boot },
		emitAlert:    func(a alert.Alert) error { f.alrts = append(f.alrts, a); return nil },
		alertsOn:     func() bool { return true },
	}
}

func TestPuEngineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	loc := time.FixedZone("CST", 8*3600)
	t0 := time.Date(2026, 9, 30, 10, 0, 0, 0, loc)

	f := &puFake{boot: "boot-A", route: "rmnet_data0",
		sim: puSIM{Slot: 1, Carrier: "中国移动", SubID: 1, Source: "settings"},
		ctr: map[string][2]uint64{"rmnet_data0": {1000, 1000}, "wlan0": {0, 0}, "wlan2": {0, 0},
			"v4-rmnet_data0": {500, 500}, "lo": {9, 9}}}
	e := newPuEngine(dir, f.env())
	// 首次安装: 只建基线
	if out := e.tick(t0); out["cell"] != ([2]uint64{}) {
		t.Fatalf("first tick counted history: %v", out)
	}
	// 蜂窝 +10000/+2000, 热点口 rx 1000(客户端上传) tx 6000(客户端下载)
	f.ctr = map[string][2]uint64{"rmnet_data0": {11000, 3000}, "wlan0": {0, 0}, "wlan2": {1000, 6000},
		"v4-rmnet_data0": {99999, 99999}, "lo": {99, 99}}
	out := e.tick(t0.Add(time.Minute))
	if out["cell"] != [2]uint64{10000, 2000} || out["hotspot"] != [2]uint64{6000, 1000} ||
		out["local_cell"] != [2]uint64{4000, 1000} || out["local_wifi"] != ([2]uint64{}) {
		t.Fatalf("tick2 = %v", out)
	}
	e.flush(t0.Add(time.Minute))

	// 进程重启(同一 boot): 续上差分
	e2 := newPuEngine(dir, f.env())
	f.ctr["rmnet_data0"] = [2]uint64{12000, 3500}
	if out := e2.tick(t0.Add(2 * time.Minute)); out["cell"] != [2]uint64{1000, 500} {
		t.Fatalf("same-boot resume = %v", out)
	}
	e2.flush(t0.Add(2 * time.Minute))

	// 手机重启: 计数器从头来, 开机以来的全算
	f.boot = "boot-B"
	f.sim = puSIM{Slot: 2, Carrier: "中国联通", SubID: 2}
	f.ctr = map[string][2]uint64{"rmnet_data0": {300, 100}, "wlan0": {5000, 700}, "wlan2": {0, 0}}
	e3 := newPuEngine(dir, f.env())
	if out := e3.tick(t0.Add(3 * time.Minute)); out["cell"] != [2]uint64{300, 100} || out["wifi"] != [2]uint64{5000, 700} {
		t.Fatalf("reboot = %v", out)
	}
	e3.flush(t0.Add(3 * time.Minute))

	// 从磁盘读回
	d, ok := puLoadDay(dir, "20260930")
	if !ok {
		t.Fatal("day file missing")
	}
	if d.Cell["1|中国移动"] != [2]uint64{11000, 2500} || d.Cell["2|中国联通"] != [2]uint64{300, 100} {
		t.Errorf("cell buckets = %v", d.Cell)
	}
	if d.Hotspot != [2]uint64{6000, 1000} || d.LocalCell != [2]uint64{5300, 1600} || d.LocalWifi != [2]uint64{5000, 700} {
		t.Errorf("day = %+v", d)
	}
	if d.LocalSIM["1|中国移动"] != [2]uint64{5000, 1500} {
		t.Errorf("local by sim = %v", d.LocalSIM)
	}
	if h := d.Hours["10"]; h == nil || h.Cell != [2]uint64{11300, 2600} {
		t.Errorf("hour = %+v", d.Hours)
	}
	if d.HsVia["cell"] != [2]uint64{6000, 1000} {
		t.Errorf("via = %v", d.HsVia)
	}

	// 往前造一天历史, 覆盖 period 聚合
	old := newPuDay("20260925")
	old.Cell["1|中国移动"] = [2]uint64{1 << 30, 0}
	old.Wifi = [2]uint64{7, 3}
	if err := puSaveDay(dir, old); err != nil {
		t.Fatal(err)
	}
	now := t0.Add(4 * time.Minute)
	rep := e3.report("cycle", now)
	tot := rep["totals"].(map[string]puRxTx)
	if tot["cellular"].Total != (1<<30)+11000+2500+300+100 || tot["wifi"].Total != 5710 || tot["hotspot"].Total != 7000 {
		t.Errorf("totals = %+v", tot)
	}
	if bd := rep["by_day"]; len(fmt.Sprint(bd)) == 0 {
		t.Error("by_day empty")
	}
	rep = e3.report("today", now)
	if tot := rep["totals"].(map[string]puRxTx); tot["cellular"].Total != 11000+2500+300+100 {
		t.Errorf("today totals = %+v", tot)
	}
	if _, ok := rep["by_hour"]; !ok {
		t.Error("today missing by_hour")
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]interface{}
	if json.Unmarshal(b, &back) != nil || back["sources"].(map[string]interface{})["sim_detect"] != "ok" {
		t.Errorf("json = %s", b)
	}
}

func TestPuConfigAndAlerts(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	if c := puLoadConfig(dir); c.BillingDay != 1 || c.WarnPercent != 80 || c.planBytes(1) != 0 {
		t.Fatalf("default = %+v", c)
	}
	for _, bad := range []map[string]string{{"billing_day": "29"}, {"billing_day": "0"}, {"warn_percent": "101"},
		{"plan_sim1_gb": "-1"}, {"plan_sim2_gb": "abc"}, {}} {
		if r := actionPhoneUsageSet(dir, bad); r.OK {
			t.Errorf("accepted bad %v", bad)
		}
	}
	if r := actionPhoneUsageSet(dir, map[string]string{"billing_day": "15", "plan_sim1_gb": "10", "warn_percent": "50"}); !r.OK {
		t.Fatalf("set: %+v", r)
	}
	if r := actionPhoneUsageSet(dir, map[string]string{"plan_sim2_gb": "0.5"}); !r.OK { // 部分更新
		t.Fatalf("set2: %+v", r)
	}
	c := puLoadConfig(dir)
	if c.BillingDay != 15 || c.WarnPercent != 50 || c.planBytes(1) != 10*puGiB || c.planBytes(2) != puGiB/2 {
		t.Fatalf("config = %+v", c)
	}

	loc := time.FixedZone("CST", 8*3600)
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, loc) // 周期 9/15 起
	f := &puFake{boot: "b"}
	e := newPuEngine(dir, f.env())
	day := newPuDay("20260914") // 上个周期, 不计
	day.Cell["1|中国移动"] = [2]uint64{20 * puGiB, 0}
	_ = puSaveDay(dir, day)
	day = newPuDay("20260916")
	day.Cell["1|中国移动"] = [2]uint64{5*puGiB + 1, 0} // 50% 刚过
	day.Cell["2|中国联通"] = [2]uint64{puGiB, 0}       // 200% 直接超
	_ = puSaveDay(dir, day)

	if n := e.checkAlerts(now); n != 2 {
		t.Fatalf("alerts = %d (%+v)", n, f.alrts)
	}
	lv := map[string]bool{}
	for _, a := range f.alrts {
		lv[fmt.Sprintf("%v %v", a.Extra["slot"], a.Extra["level"])] = true
		if a.Kind != puAlertKind {
			t.Errorf("kind = %s", a.Kind)
		}
	}
	if !lv["1 warn"] || !lv["2 over"] {
		t.Errorf("levels = %v", lv)
	}
	// 同周期同档不重发(卡 2 超限后也不补发预警)
	if n := e.checkAlerts(now.Add(time.Hour)); n != 0 {
		t.Errorf("repeat alerts = %d", n)
	}
	// 去重记录持久化: 新进程也不重发
	e2 := newPuEngine(dir, f.env())
	if n := e2.checkAlerts(now.Add(2 * time.Hour)); n != 0 {
		t.Errorf("repeat after restart = %d", n)
	}
	// 卡 1 越过 100% → 发超限
	day.Cell["1|中国移动"] = [2]uint64{10 * puGiB, 0}
	_ = puSaveDay(dir, day)
	if n := e2.checkAlerts(now.Add(3 * time.Hour)); n != 1 {
		t.Errorf("over alert = %d", n)
	}
	// 新周期重新计
	day = newPuDay("20261016")
	day.Cell["1|中国移动"] = [2]uint64{6 * puGiB, 0}
	_ = puSaveDay(dir, day)
	if n := e2.checkAlerts(time.Date(2026, 10, 16, 12, 0, 0, 0, loc)); n != 1 {
		t.Errorf("new cycle alert = %d", n)
	}
	// 周期报表里的百分比
	rep := e2.report("cycle", time.Date(2026, 10, 16, 12, 0, 0, 0, loc))
	sims := rep["by_sim"].([]map[string]interface{})
	found := false
	for _, s := range sims {
		if s["slot"] == 1 {
			found = true
			if s["used_pct"] != 60.0 || s["plan_bytes"] != uint64(10*puGiB) {
				t.Errorf("sim1 = %v", s)
			}
		}
	}
	if !found {
		t.Errorf("by_sim = %v", sims)
	}
}

func TestPuPrune(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	oldDate := now.AddDate(0, 0, -401).Format("20060102")
	keepDate := now.AddDate(0, 0, -399).Format("20060102")
	_ = puSaveDay(dir, newPuDay(oldDate))
	_ = puSaveDay(dir, newPuDay(keepDate))
	e := newPuEngine(dir, (&puFake{}).env())
	e.flush(now)
	if _, err := os.Stat(puDayPath(dir, oldDate)); err == nil {
		t.Error("old file not pruned")
	}
	if _, err := os.Stat(puDayPath(dir, keepDate)); err != nil {
		t.Error("recent file pruned")
	}
}

func TestPhoneUsageRC2DualDirAndMigration(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	yday := now.AddDate(0, 0, -1).Format("20060102")

	// Legacy file only in run/ must be readable via puLoadDay and migrated to data/ on flush
	leg := newPuDay(yday)
	leg.Wifi = [2]uint64{1024, 2048}
	raw, _ := json.Marshal(leg)
	if err := os.WriteFile(puLegacyDayPath(dir, yday), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, ok := puLoadDay(dir, yday)
	if !ok || loaded.Wifi != ([2]uint64{1024, 2048}) {
		t.Fatalf("legacy run/ fallback read failed: ok=%v wifi=%v", ok, loaded.Wifi)
	}

	// New writes go to data/ (auto MkdirAll)
	today := now.Format("20060102")
	cur := newPuDay(today)
	cur.Wifi = [2]uint64{4096, 8192}
	if err := puSaveDay(dir, cur); err != nil {
		t.Fatalf("puSaveDay auto-mkdir data/: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "phone_usage."+today+".json")); err != nil {
		t.Fatalf("expected new day file in data/: %v", err)
	}

	e := newPuEngine(dir, (&puFake{}).env())
	e.flush(now)
	if _, err := os.Stat(puDayPath(dir, yday)); err != nil {
		t.Fatalf("legacy run/ file was not migrated to data/: %v", err)
	}
	if _, err := os.Stat(puLegacyDayPath(dir, yday)); !os.IsNotExist(err) {
		t.Fatalf("legacy run/ file should be removed after migration, err=%v", err)
	}
}

// rmx5010IsubSample 源自 realme RMX5010 / ColorOS 16 (Android 16) 真机脱敏 dumpsys isub:
//   - id=1,3,4,5,6,7,8 为历史拔出卡(simSlotIndex=-1)
//   - id=2 为物理卡1 中国联通(carrierName=China Unicom, mccmnc=46001, imsi=460011898[****])
//   - id=9 为物理卡2 中国移动, 用户自定义卡名 "中国移不动"(displayNameSource=2, carrierName=中国移动 — giffgaff)
//   - id=10 为 ColorOS 逍遥游云虚拟流量卡(simSlotIndex=2, isOpportunistic=1, ORoaming)
//   - id=11 为伪装在槽位 1 的红茶移动远程云卡(subscriptionType=1, mcc=001)
//   - defaultDataSubId=2, activeDataSubId=9(双卡智能切换/通话临时上网切到卡2)
const rmx5010IsubSample = `SubscriptionManagerService:
  Active modem count=2
  Logical SIM slot 0: subId=2
  Logical SIM slot 1: subId=9
  defaultSubId=9
  defaultDataSubId=2
  activeDataSubId=9
  defaultVoiceSubId=2
  defaultSmsSubId=2

Active subscriptions:
  [SubscriptionInfo: id=2 iccId=898601208[****] simSlotIndex=0 carrierId=1435 displayName=China Unicom carrierName=China Unicom displayNameSource=0 iconTint=-16746133 number=[****] dataRoaming=0 mcc=460 mnc=01 countryIso=cn isEmbedded=false cardString=898601208[****] cardId=0 portIndex=0 isOpportunistic=false groupUUID=null subscriptionType=0]
  [SubscriptionInfo: id=9 iccId=898600981[****] simSlotIndex=1 carrierId=1434 displayName=中国移不动 carrierName=中国移动 — giffgaff displayNameSource=2 iconTint=-16746133 number=[****] dataRoaming=0 mcc=460 mnc=00 countryIso=cn isEmbedded=false cardString=898600981[****] cardId=1 portIndex=0 isOpportunistic=false groupUUID=null subscriptionType=0]
  [SubscriptionInfo: id=10 iccId=898699000[****] simSlotIndex=2 carrierId=-1 displayName=逍遥游 carrierName=ORoaming displayNameSource=0 mcc=460 mnc=01 isEmbedded=true cardString=vsim_oroaming isOpportunistic=true subscriptionType=0]

All subscriptions:
  [SubscriptionInfoInternal: id=1 iccId=898600111[****] simSlotIndex=-1 carrierId=1434 displayName=CMCC carrierName=中国移动 displayNameSource=0 mccmnc=46000 cardString=898600111[****] isOpportunistic=0 subscriptionType=0 imsi=460001391[****]]
  [SubscriptionInfoInternal: id=2 iccId=898601208[****] simSlotIndex=0 carrierId=1435 displayName=China Unicom carrierName=China Unicom displayNameSource=0 mccmnc=46001 cardString=898601208[****] isOpportunistic=0 subscriptionType=0 imsi=460011898[****]]
  [SubscriptionInfoInternal: id=3 iccId=898603333[****] simSlotIndex=-1 carrierId=2125 displayName=中国电信 carrierName=CHN-CT displayNameSource=0 mccmnc=46011 cardString=898603333[****] isOpportunistic=0 subscriptionType=0 imsi=460110555[****]]
  [SubscriptionInfoInternal: id=4 iccId=898600444[****] simSlotIndex=-1 carrierId=1434 displayName=中国移动 carrierName=CMCC displayNameSource=0 mccmnc=46002 cardString=898600444[****] isOpportunistic=0 subscriptionType=0 imsi=460028888[****]]
  [SubscriptionInfoInternal: id=5 iccId=898615555[****] simSlotIndex=-1 carrierId=2501 displayName=中国广电 carrierName=CBN displayNameSource=0 mccmnc=46015 cardString=898615555[****] isOpportunistic=0 subscriptionType=0 imsi=460150123[****]]
  [SubscriptionInfoInternal: id=6 iccId=898601666[****] simSlotIndex=-1 carrierId=1435 displayName=China Unicom carrierName=CUCC displayNameSource=0 mccmnc=46001 cardString=898601666[****] isOpportunistic=0 subscriptionType=0 imsi=460016666[****]]
  [SubscriptionInfoInternal: id=7 iccId=898600777[****] simSlotIndex=-1 carrierId=1434 displayName=中国移动 carrierName=中国移动 displayNameSource=0 mccmnc=46007 cardString=898600777[****] isOpportunistic=0 subscriptionType=0 imsi=460077777[****]]
  [SubscriptionInfoInternal: id=8 iccId=898603888[****] simSlotIndex=-1 carrierId=2125 displayName=中国电信 carrierName=China Telecom displayNameSource=0 mccmnc=46003 cardString=898603888[****] isOpportunistic=0 subscriptionType=0 imsi=460038888[****]]
  [SubscriptionInfoInternal: id=9 iccId=898600981[****] simSlotIndex=1 carrierId=1434 displayName=中国移不动 carrierName=中国移动 — giffgaff displayNameSource=2 mccmnc=46000 cardString=898600981[****] isOpportunistic=0 subscriptionType=0 imsi=460001380[****]]
  [SubscriptionInfoInternal: id=10 iccId=898699000[****] simSlotIndex=2 carrierId=-1 displayName=逍遥游 carrierName=ORoaming displayNameSource=0 mccmnc=46001 cardString=vsim_oroaming isOpportunistic=1 subscriptionType=0 imsi=460019999[****]]
  [SubscriptionInfoInternal: id=11 iccId=890010101[****] simSlotIndex=1 carrierId=-1 displayName=RedteaGO carrierName=红茶移动 displayNameSource=0 mccmnc=00101 cardString=redtea_vsim isOpportunistic=0 subscriptionType=1 imsi=001010000[****]]

Local logs:
  2026-11-20T10:00:00 - activeDataSubId=2 defaultDataSubId=1
`

func TestPhoneUsageSanitizedAndroidEnv(t *testing.T) {
	raw := []string{
		"PATH=/data/local/tmp/hijack:/bin",
		"BOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar:/system/framework/framework.jar",
		"DEX2OATBOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar",
		"SYSTEMSERVERCLASSPATH=/system/framework/services.jar",
		"STANDALONE_SYSTEMSERVER_JARS=/apex/com.android.tethering/javalib/service-connectivity.jar",
		"ANDROID_ROOT=/system",
		"ANDROID_DATA=/data",
		"ANDROID_STORAGE=/storage",
		"ANDROID_ASSETS=/system/app",
		"ANDROID_ART_ROOT=/apex/com.android.art",
		"ANDROID_I18N_ROOT=/apex/com.android.i18n",
		"ANDROID_TZDATA_ROOT=/apex/com.android.tzdata",
		"TZ=Asia/Shanghai",
		"LD_PRELOAD=/data/local/tmp/evil.so",
		"SECRET_TOKEN=123456",
	}
	got := puSanitizedAndroidEnvFrom(raw)
	m := map[string]string{}
	for _, kv := range got {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			t.Fatalf("malformed env entry %q", kv)
		}
		m[kv[:eq]] = kv[eq+1:]
	}
	if m["PATH"] != "/system/bin:/system/xbin:/vendor/bin:/usr/bin:/bin" {
		t.Fatalf("unexpected PATH: %q", m["PATH"])
	}
	for _, k := range puAndroidEnvAllowKeys {
		if m[k] == "" {
			t.Errorf("missing allowlisted Android env %s", k)
		}
	}
	if _, bad := m["LD_PRELOAD"]; bad {
		t.Error("LD_PRELOAD must not leak into sanitized env")
	}
	if _, bad := m["SECRET_TOKEN"]; bad {
		t.Error("SECRET_TOKEN must not leak into sanitized env")
	}
}

func TestIsubParseRMX5010AndFiveGates(t *testing.T) {
	snap := puParseIsubDump(rmx5010IsubSample)
	if snap.MaxSlots != 2 || snap.ModemCount != 2 {
		t.Fatalf("MaxSlots=%d ModemCount=%d, want 2/2", snap.MaxSlots, snap.ModemCount)
	}
	if snap.ActiveDataSubID != 9 || snap.DefaultDataSubID != 2 {
		t.Fatalf("activeDataSubId=%d defaultDataSubId=%d, want 9/2", snap.ActiveDataSubID, snap.DefaultDataSubID)
	}
	if snap.LogicalSlotSubID[0] != 2 || snap.LogicalSlotSubID[1] != 9 {
		t.Fatalf("LogicalSlotSubID=%v", snap.LogicalSlotSubID)
	}
	if len(snap.Subs) != 2 {
		t.Fatalf("expected exactly 2 physical SIMs after 5 gates, got %d: %+v", len(snap.Subs), snap.Subs)
	}

	s1 := snap.Subs[0]
	if s1.Slot != 1 || s1.SubID != 2 || s1.Carrier != "中国联通" || s1.CustomName != "" || s1.IMSI != "460011898" {
		t.Errorf("slot1 mismatch: %+v", s1)
	}
	s2 := snap.Subs[1]
	if s2.Slot != 2 || s2.SubID != 9 || s2.Carrier != "中国移动" || s2.CustomName != "中国移不动" || s2.IMSI != "460001380" ||
		s2.RawCarrierName != "中国移动 — giffgaff" {
		t.Errorf("slot2 mismatch: %+v", s2)
	}

	// 验证原生链路零 app_process 开销(绝不调用 settings 或 content query), 且 activeDataSubId=9 优先于 defaultDataSubId=2
	calledAppProcess := false
	probe := puDetectSIMProbeWith(func(name string, args ...string) (string, bool) {
		switch name {
		case "dumpsys":
			if len(args) == 1 && args[0] == "isub" {
				return rmx5010IsubSample, true
			}
			if len(args) == 1 && args[0] == "telephony.registry" {
				return "mActiveDataSubId=9\nPhone Id=0\n  mSubId=2\n  mDataConnectionState=0\nPhone Id=1\n  mSubId=9\n  mDataConnectionState=2\n", true
			}
		case "content", "settings":
			calledAppProcess = true
		}
		return "", false
	})
	if calledAppProcess {
		t.Fatal("native dumpsys isub path must not spawn app_process (content/settings)")
	}
	if probe.Active.Slot != 2 || probe.Active.SubID != 9 || probe.Active.Carrier != "中国移动" ||
		probe.Active.CustomName != "中国移不动" || probe.Active.key() != "2|中国移动" {
		t.Fatalf("active SIM mismatch: %+v key=%s", probe.Active, probe.Active.key())
	}
	if !probe.SlotsKnown || len(probe.Slots) != 2 || probe.Slots[1].Carrier != "中国联通" || probe.Slots[2].CustomName != "中国移不动" {
		t.Fatalf("probe slots mismatch: %+v", probe)
	}

	// 验证 dumpsys isub 失败时自动回退 content query
	fbProbe := puDetectSIMProbeWith(func(name string, args ...string) (string, bool) {
		switch name {
		case "dumpsys":
			return "", false
		case "settings":
			return "9\n", true
		case "content":
			return "Row: 0 _id=2, sim_id=0, display_name=China Unicom, carrier_name=China Unicom, mcc_string=460, mnc_string=01, name_source=0\n" +
				"Row: 1 _id=9, sim_id=1, display_name=中国移不动, carrier_name=CMCC, mcc_string=460, mnc_string=00, name_source=2\n", true
		}
		return "", false
	})
	if fbProbe.Active.Slot != 2 || fbProbe.Active.Carrier != "中国移动" || fbProbe.Active.CustomName != "中国移不动" {
		t.Fatalf("fallback probe mismatch: %+v", fbProbe)
	}
}

func TestPhoneUsageNoGhostThirdCardAndZeroSlotReconcile(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	defer clockForget(dir)

	loc := time.FixedZone("CST", 8*3600)
	t0 := time.Date(2026, 9, 20, 10, 0, 0, 0, loc)

	curProbe := puSIMProbe{
		Active:     puSIM{Slot: 0, Carrier: puUnknownSIM},
		SlotsKnown: false,
		MaxSlots:   2,
	}
	ctr := map[string][2]uint64{"rmnet_data2": {1000, 1000}, "wlan2": {0, 0}}
	e := newPuEngine(dir, puEnv{
		readNetDev:   func() ([]byte, error) { return fakeNetDev(ctr), nil },
		hotspotIface: func() string { return "wlan2" },
		upstream:     func() string { return "rmnet_data2" },
		simProbe:     func() puSIMProbe { return curProbe },
		bootID:       func() string { return "boot-rmx5010" },
		alertsOn:     func() bool { return true },
	})

	// 1) 首轮建基线, 第 1 分钟 Modem 尚未就绪(Slot=0), 产生 10MB 蜂窝流量落入 "0|蜂窝(未知卡)"
	e.tick(t0)
	ctr["rmnet_data2"] = [2]uint64{1000 + 8*(1<<20), 1000 + 2*(1<<20)}
	e.tick(t0.Add(time.Minute))

	// 2) 第 2 分钟 RMX5010 双卡识别就绪: 卡1 联通(id=2), 卡2 移动(id=9, 自定义名 "中国移不动", activeDataSubId=9), 再产生 20MB
	snap := puParseIsubDump(rmx5010IsubSample)
	curProbe, _ = puResolveProbeFromIsub(snap, puRegistryDataState{ActiveDataSubID: 9})
	ctr["rmnet_data2"] = [2]uint64{1000 + 24*(1<<20), 1000 + 6*(1<<20)}
	e.tick(t0.Add(2 * time.Minute))
	e.flush(t0.Add(2 * time.Minute))

	// 今日记录中的 "0|蜂窝(未知卡)" 必须已被自动归并进 "2|中国移动" 并彻底删除
	d, ok := puLoadDay(dir, "20260920")
	if !ok {
		t.Fatal("missing saved day")
	}
	if _, exists := d.Cell["0|"+puUnknownSIM]; exists {
		t.Fatalf("unknown SIM bucket was not reconciled in tick: %v", d.Cell)
	}
	if got := d.Cell["2|中国移动"]; got[0]+got[1] != 30*(1<<20) {
		t.Fatalf("slot2 reconciled cell=%v, want 30MiB", got)
	}

	// 校验报表: 最多只有卡1、卡2 两张卡片, 严禁出现第 3 张卡片, 且卡2 输出 custom_name="中国移不动"
	rep := e.report("cycle", t0.Add(2*time.Minute))
	if rep["max_slots"] != 2 {
		t.Fatalf("max_slots=%v, want 2", rep["max_slots"])
	}
	bySim := rep["by_sim"].([]map[string]interface{})
	if len(bySim) != 2 {
		t.Fatalf("by_sim must have strictly 2 cards on dual-SIM phone, got %d: %+v", len(bySim), bySim)
	}
	if bySim[0]["slot"] != 1 || bySim[0]["carrier"] != "中国联通" {
		t.Errorf("card1 mismatch: %+v", bySim[0])
	}
	if _, hasCustom := bySim[0]["custom_name"]; hasCustom {
		t.Errorf("card1 should not have custom_name: %+v", bySim[0])
	}
	if bySim[1]["slot"] != 2 || bySim[1]["carrier"] != "中国移动" || bySim[1]["custom_name"] != "中国移不动" ||
		bySim[1]["cycle_used"] != uint64(30*(1<<20)) || bySim[1]["is_default_data"] != true {
		t.Errorf("card2 mismatch: %+v", bySim[1])
	}
	if rep["unattributed_cell_bytes"] != uint64(0) || rep["unattributed_cycle_bytes"] != uint64(0) {
		t.Errorf("unexpected unattributed bytes: cell=%v cycle=%v", rep["unattributed_cell_bytes"], rep["unattributed_cycle_bytes"])
	}

	// 3) 历史遗留双卡同周期均大量耗流 + 历史 "0|蜂窝(未知卡)" + 脏槽位 "3|逍遥游":
	// 硬护栏严禁渲染第 3 张卡, 未归属字节汇总在 unattributed_*
	legacyDay := newPuDay("20260918")
	legacyDay.Cell["0|"+puUnknownSIM] = [2]uint64{5 * (1 << 20), 0}
	legacyDay.Cell["1|中国联通"] = [2]uint64{100 * (1 << 20), 0}
	legacyDay.Cell["2|中国移动"] = [2]uint64{200 * (1 << 20), 0}
	legacyDay.Cell["3|逍遥游"] = [2]uint64{3 * (1 << 20), 0}
	if err := puSaveDay(dir, legacyDay); err != nil {
		t.Fatal(err)
	}
	rep2 := e.report("cycle", t0.Add(3*time.Minute))
	bySim2 := rep2["by_sim"].([]map[string]interface{})
	if len(bySim2) != 2 {
		t.Fatalf("hard guardrail violated: want 2 cards, got %d (%+v)", len(bySim2), bySim2)
	}
	for _, card := range bySim2 {
		s := card["slot"].(int)
		if s < 1 || s > 2 {
			t.Fatalf("illegal slot %d leaked into by_sim", s)
		}
	}
	wantUnattrib := uint64(8 * (1 << 20))
	if rep2["unattributed_cycle_bytes"] != wantUnattrib || rep2["unattributed_cell_bytes"] != wantUnattrib {
		t.Fatalf("unattributed bytes got cell=%v cycle=%v, want %d",
			rep2["unattributed_cell_bytes"], rep2["unattributed_cycle_bytes"], wantUnattrib)
	}

	// 4) 单物理卡在位确定性归并: 拔掉卡1仅留卡2在位时, 历史 "0|蜂窝(未知卡)" 自动归并进唯一在位物理卡2
	singleDay := newPuDay("20260919")
	singleDay.Cell["0|"+puUnknownSIM] = [2]uint64{12 * (1 << 20), 0}
	_ = os.Remove(puDayPath(dir, "20260918"))
	if err := puSaveDay(dir, singleDay); err != nil {
		t.Fatal(err)
	}
	curProbe = puSIMProbe{
		Active:     puSIM{Slot: 2, Carrier: "中国移动", CustomName: "中国移不动", SubID: 9, Source: "isub"},
		Slots:      map[int]puSIM{2: {Slot: 2, Carrier: "中国移动", CustomName: "中国移不动", SubID: 9, Source: "isub"}},
		SlotsKnown: true,
		MaxSlots:   2,
	}
	e.tick(t0.Add(10 * time.Minute))
	rep3 := e.report("cycle", t0.Add(10*time.Minute))
	bySim3 := rep3["by_sim"].([]map[string]interface{})
	if len(bySim3) != 1 || bySim3[0]["slot"] != 2 || bySim3[0]["cycle_used"] != uint64(42*(1<<20)) {
		t.Fatalf("single-SIM deterministic reconcile failed: %+v", bySim3)
	}
	if rep3["unattributed_cycle_bytes"] != uint64(0) {
		t.Fatalf("expected 0 unattributed after single-SIM reconcile, got %v", rep3["unattributed_cycle_bytes"])
	}
}

func TestPhoneUsageLockFreeSubprocessAndPendingDaysRetry(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	defer clockForget(dir)

	loc := time.FixedZone("CST", 8*3600)
	tDay1 := time.Date(2026, 9, 30, 23, 58, 0, 0, loc)
	tDay2 := time.Date(2026, 10, 1, 0, 1, 0, 0, loc)

	ctr := map[string][2]uint64{"rmnet_data0": {100, 100}, "wlan2": {0, 0}}
	var eng *puEngine
	upstreamChecks := 0
	simChecks := 0

	eng = newPuEngine(dir, puEnv{
		readNetDev:   func() ([]byte, error) { return fakeNetDev(ctr), nil },
		hotspotIface: func() string { return "wlan2" },
		upstreamInfo: func() puUpInfo {
			upstreamChecks++
			if !eng.mu.TryLock() {
				t.Errorf("dead-law-4 violation: upstreamInfo() called while holding eng.mu")
			} else {
				eng.mu.Unlock()
			}
			return puUpInfo{Local: "rmnet_data0"}
		},
		simProbe: func() puSIMProbe {
			simChecks++
			if !eng.mu.TryLock() {
				t.Errorf("dead-law-4 violation: simProbe() called while holding eng.mu")
			} else {
				eng.mu.Unlock()
			}
			return puSIMProbe{
				Active:     puSIM{Slot: 1, Carrier: "中国联通", SubID: 2, Source: "isub"},
				Slots:      map[int]puSIM{1: {Slot: 1, Carrier: "中国联通", SubID: 2, Source: "isub"}},
				SlotsKnown: true,
				MaxSlots:   2,
			}
		},
		bootID: func() string { return "boot-lockfree" },
	})

	// 23:58 建基线 + 23:59 记一笔流量(尚未 flush 落盘)
	eng.tick(tDay1)
	ctr["rmnet_data0"] = [2]uint64{100 + 4096, 100 + 2048}
	eng.tick(tDay1.Add(time.Minute))
	if upstreamChecks == 0 || simChecks == 0 {
		t.Fatalf("expected callbacks to run: upstream=%d sim=%d", upstreamChecks, simChecks)
	}

	// 制造磁盘写失败(在目标文件路径建一个同名非空目录, 使 os.Rename 必败), 验证:
	// 1. 跨零点 tick 不会丢失 20260930 脏账(保留在 pendingDays 中);
	// 2. puWriteAtomic 失败后立即清理 .tmp.* 孤儿文件!
	blockerDir := puDayPath(dir, "20260930")
	if err := os.MkdirAll(filepath.Join(blockerDir, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctr["rmnet_data0"] = [2]uint64{100 + 8192, 100 + 4096}
	eng.tick(tDay2)

	ents, _ := os.ReadDir(filepath.Join(dir, "data"))
	for _, en := range ents {
		if strings.Contains(en.Name(), ".tmp.") {
			t.Fatalf("orphan tmp file leaked on write failure: %s", en.Name())
		}
	}
	// 即使未落盘, 内存查询 days 仍能完整读出昨日 20260930 的 4096+2048 字节
	gotDays := eng.days(tDay1, tDay2)
	if len(gotDays) != 2 || gotDays[0].Date != "20260930" || gotDays[0].Cell["1|中国联通"] != ([2]uint64{4096, 2048}) {
		t.Fatalf("pendingDays lost across midnight write failure: %+v", gotDays)
	}

	// 解除写阻碍后, 下一轮 flush 重试成功落盘并清空 pendingDays
	_ = os.RemoveAll(blockerDir)
	eng.flush(tDay2.Add(time.Minute))
	persisted, ok := puLoadDay(dir, "20260930")
	if !ok || persisted.Cell["1|中国联通"] != ([2]uint64{4096, 2048}) {
		t.Fatalf("retry flush failed to persist 20260930: ok=%v day=%+v", ok, persisted)
	}
	eng.mu.Lock()
	pendLeft := len(eng.pendingDays)
	eng.mu.Unlock()
	if pendLeft != 0 {
		t.Fatalf("pendingDays should be empty after successful retry, got %d", pendLeft)
	}
}


