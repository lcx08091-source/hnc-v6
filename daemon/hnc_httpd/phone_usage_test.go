package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
