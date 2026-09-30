package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var tzCST = time.FixedZone("CST", 8*3600)

// 2026-09-28 是周一。
func at(day, hh, mm int) time.Time { return time.Date(2026, 9, day, hh, mm, 0, 0, tzCST) }

func TestEffectiveRulePrecedence(t *testing.T) {
	manual := limitRule{DownKbit: 10000, UpKbit: 5000}
	night := []schedWindow{{Start: "22:00", End: "07:00", DownMbps: 2, UpMbps: 1}}
	bedBlock := []schedWindow{{Start: "22:00", End: "07:00", Block: true}}
	freeNight := []schedWindow{{Start: "22:00", End: "07:00"}}
	thr := quotaVerdict{Exceeded: true, Action: "throttle", ThrottleDownKbit: 1000, ThrottleUpKbit: 500}
	thrLoose := quotaVerdict{Exceeded: true, Action: "throttle", ThrottleDownKbit: 50000, ThrottleUpKbit: 50000}
	blk := quotaVerdict{Exceeded: true, Action: "block"}
	in, out := at(28, 23, 0), at(28, 12, 0)
	cases := []struct {
		name   string
		base   limitRule
		q      quotaVerdict
		ws     []schedWindow
		now    time.Time
		want   limitRule
		reason string
		idx    int
	}{
		{"manual only", manual, quotaVerdict{}, nil, in, manual, "manual", -1},
		{"no rule", limitRule{}, quotaVerdict{}, nil, in, limitRule{}, "manual", -1},
		{"schedule outside window", manual, quotaVerdict{}, night, out, manual, "manual", -1},
		{"schedule inside window replaces manual", manual, quotaVerdict{}, night, in, limitRule{DownKbit: 2000, UpKbit: 1000}, "schedule", 0},
		{"schedule 0/0 = unlimited window", manual, quotaVerdict{}, freeNight, in, limitRule{}, "schedule", 0},
		{"quota throttle over manual", manual, thr, nil, out, limitRule{DownKbit: 1000, UpKbit: 500}, "quota", -1},
		{"quota throttle over schedule", manual, thr, night, in, limitRule{DownKbit: 1000, UpKbit: 500}, "quota", 0},
		{"quota throttle never loosens", limitRule{DownKbit: 300, UpKbit: 0}, thrLoose, nil, out, limitRule{DownKbit: 300, UpKbit: 50000}, "quota", -1},
		{"quota block keeps base limits", manual, blk, night, in, limitRule{DownKbit: 10000, UpKbit: 5000, Blocked: true}, "quota", 0},
		{"schedule block beats quota throttle", manual, thr, bedBlock, in, limitRule{DownKbit: 10000, UpKbit: 5000, Blocked: true}, "schedule", 0},
		{"manual block beats all", limitRule{DownKbit: 10000, Blocked: true}, thr, night, in, limitRule{DownKbit: 10000, Blocked: true}, "block", 0},
		{"manual block + quota block", limitRule{Blocked: true}, blk, nil, out, limitRule{Blocked: true}, "block", -1},
	}
	for _, c := range cases {
		got := effectiveRule(c.base, c.q, c.ws, c.now)
		if got.Rule != c.want || got.Reason != c.reason || got.WindowIndex != c.idx {
			t.Errorf("%s: got %+v %s %d, want %+v %s %d", c.name, got.Rule, got.Reason, got.WindowIndex, c.want, c.reason, c.idx)
		}
	}
}

func TestActiveWindow(t *testing.T) {
	// 工作日晚 22:00 → 次日 07:00(跨零点, 属于开始那天); 周末白天 09:00-18:00
	ws := []schedWindow{
		{Days: []int{1, 2, 3, 4, 5}, Start: "22:00", End: "07:00"},
		{Days: []int{0, 6}, Start: "09:00", End: "18:00"},
	}
	cases := []struct {
		now  time.Time
		want int
	}{
		{at(28, 21, 59), -1}, // 周一 21:59
		{at(28, 22, 0), 0},   // 周一 22:00 起
		{at(29, 6, 59), 0},   // 周二 06:59 属于周一晚的窗口
		{at(29, 7, 0), -1},   // 结束边界不含
		{at(27, 23, 0), -1},  // 周日晚: 周日不在第 0 窗口
		{at(28, 3, 0), -1},   // 周一凌晨: 前一天周日不在 → 不命中
		{at(3, 2, 0), 0},     // 09-03 周四 02:00, 前一天周三 → 命中
		{at(26, 9, 0), 1},    // 周六 09:00
		{at(26, 18, 0), -1},  // 周六 18:00 结束
		{at(26, 1, 0), 0},    // 周六 01:00 属于周五晚窗口
	}
	for _, c := range cases {
		if got := activeWindow(ws, c.now); got != c.want {
			t.Errorf("%s: got %d want %d", c.now.Format("Mon 01-02 15:04"), got, c.want)
		}
	}
	// start==end = 全天; 无效时间被跳过; 第一个命中者优先
	ws2 := []schedWindow{{Start: "bad", End: "07:00"}, {Days: []int{1}, Start: "00:00", End: "00:00"}, {Start: "00:00", End: "00:00"}}
	if got := activeWindow(ws2, at(28, 13, 0)); got != 1 {
		t.Errorf("all-day monday: got %d", got)
	}
	if got := activeWindow(ws2, at(29, 13, 0)); got != 2 {
		t.Errorf("fallthrough to every-day: got %d", got)
	}
	// 本地时区: 同一 UTC 时刻在 UTC+8 下已进入窗口
	utc := time.Date(2026, 9, 28, 14, 30, 0, 0, time.UTC) // = CST 22:30 周一
	if activeWindow(ws, utc) != -1 || activeWindow(ws, utc.In(tzCST)) != 0 {
		t.Errorf("window must be evaluated in the local zone of now")
	}
}

func TestUsageAccCounterReset(t *testing.T) {
	var u usageAcc
	u.add(1000, 500, "d1", "m1") // 首次: 仅基线
	if u.DayBytes != 0 {
		t.Fatalf("baseline counted: %d", u.DayBytes)
	}
	u.add(3000, 1500, "d1", "m1") // +2000 +1000
	if u.DayBytes != 3000 || u.MonthBytes != 3000 {
		t.Fatalf("delta: %+v", u)
	}
	u.add(200, 100, "d1", "m1") // 计数器复位(-F HNC_STATS / 换 IP): 复位后新增 = 当前值
	if u.DayBytes != 3300 {
		t.Fatalf("reset: %+v", u)
	}
	u.add(700, 100, "d1", "m1") // rx 继续 +500, tx 不变
	if u.DayBytes != 3800 {
		t.Fatalf("after reset: %+v", u)
	}
	u.add(900, 100, "d2", "m1") // 新的一天: 日清零, 月继续
	if u.DayBytes != 200 || u.MonthBytes != 4000 {
		t.Fatalf("day rollover: %+v", u)
	}
	u.add(1000, 100, "d3", "m2")
	if u.DayBytes != 100 || u.MonthBytes != 100 {
		t.Fatalf("month rollover: %+v", u)
	}
}

func TestEvalQuota(t *testing.T) {
	q := &quotaPolicy{DailyGB: 1, MonthlyGB: 10}
	g := uint64(bytesPerGB)
	cases := []struct {
		d, m   uint64
		state  string
		exc    bool
		period string
	}{
		{0, 0, "ok", false, ""},
		{g*8/10 + 1, 0, "warn", false, ""},
		{g, 0, "exceeded", true, "daily"},
		{0, 10 * g, "exceeded", true, "monthly"},
		{0, 8 * g, "warn", false, ""},
	}
	for _, c := range cases {
		s, e, p := evalQuota(q, c.d, c.m)
		if s != c.state || e != c.exc || p != c.period {
			t.Errorf("%d/%d: %s %v %s", c.d, c.m, s, e, p)
		}
	}
	if s, e, _ := evalQuota(&quotaPolicy{MonthlyGB: 1}, 100*g, 0); e || s != "ok" {
		t.Errorf("daily 0 = no daily limit")
	}
}

func TestBillingPeriodStart(t *testing.T) {
	cases := []struct {
		now  time.Time
		bd   int
		want string
	}{
		{time.Date(2026, 9, 30, 12, 0, 0, 0, tzCST), 1, "2026-09-01"},
		{time.Date(2026, 9, 30, 12, 0, 0, 0, tzCST), 15, "2026-09-15"},
		{time.Date(2026, 9, 10, 12, 0, 0, 0, tzCST), 15, "2026-08-15"},
		{time.Date(2026, 1, 3, 0, 0, 0, 0, tzCST), 5, "2025-12-05"},
		{time.Date(2026, 2, 28, 1, 0, 0, 0, tzCST), 31, "2026-02-28"}, // 月末钳位
		{time.Date(2026, 3, 10, 1, 0, 0, 0, tzCST), 31, "2026-02-28"},
		{time.Date(2026, 9, 30, 12, 0, 0, 0, tzCST), 0, "2026-09-01"},
	}
	for _, c := range cases {
		if got := billingPeriodStart(c.now, c.bd).Format("2006-01-02"); got != c.want {
			t.Errorf("%v bd=%d: %s want %s", c.now, c.bd, got, c.want)
		}
	}
}

func TestParseWindows(t *testing.T) {
	ws, err := parseWindows(`[{"days":[5,1,1],"start":"22:00","end":"07:00","down_mbps":2,"up_mbps":0.5}]`)
	if err != nil || len(ws) != 1 || len(ws[0].Days) != 2 || ws[0].Days[0] != 1 {
		t.Fatalf("parse: %v %+v", err, ws)
	}
	for _, bad := range []string{`[]`, `{}`, `[{"start":"25:00","end":"07:00"}]`, `[{"days":[7],"start":"01:00","end":"02:00"}]`,
		`[{"start":"01:00","end":"02:00","down_mbps":0.01}]`, `[{"start":"01:00","end":"02:00","x":1}]`} {
		if _, err := parseWindows(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// ── 控制器集成(假 apply 模拟 apply_device_rule.sh 对 rules.json 的写入) ──

type ctlFixture struct {
	t     *testing.T
	dir   string
	rules map[string]limitRule
	calls []string
	c     *limitCtl
}

func newFixture(t *testing.T) *ctlFixture {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	f := &ctlFixture{t: t, dir: dir, rules: map[string]limitRule{}}
	f.writeRules()
	f.newCtl()
	return f
}

func (f *ctlFixture) newCtl() {
	f.c = newLimitCtl(f.dir, nil)
	f.c.apply = func(mac string, from, to limitRule) error {
		f.calls = append(f.calls, mac)
		f.rules[mac] = to
		f.writeRules()
		return nil
	}
}

func (f *ctlFixture) writeRules() {
	devs := map[string]interface{}{}
	bl := []string{}
	for mac, r := range f.rules {
		devs[mac] = map[string]interface{}{"limit_enabled": r.DownKbit > 0 || r.UpKbit > 0,
			"down_mbps": float64(r.DownKbit) / 1000, "up_mbps": float64(r.UpKbit) / 1000, "mark_id": 5}
		if r.Blocked {
			bl = append(bl, mac)
		}
	}
	b, _ := json.Marshal(map[string]interface{}{"devices": devs, "blacklist": bl})
	os.WriteFile(filepath.Join(f.dir, "data", "rules.json"), b, 0o644)
}

func (f *ctlFixture) writeDevices(counters map[string][2]int64) {
	m := map[string]interface{}{}
	for mac, c := range counters {
		m[mac] = map[string]interface{}{"ip": "192.168.43.10", "rx_bytes": c[0], "tx_bytes": c[1]}
	}
	b, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(f.dir, "data", "devices.json"), b, 0o644)
}

func (f *ctlFixture) tickExpect(now time.Time, wantCalls int, why string) {
	f.t.Helper()
	f.calls = nil
	f.c.tick(now)
	if len(f.calls) != wantCalls {
		f.t.Fatalf("%s: apply called %d times (%v), want %d", why, len(f.calls), f.calls, wantCalls)
	}
}

func (f *ctlFixture) alerts() int {
	b, _ := os.ReadFile(filepath.Join(f.dir, "run", "alerts.jsonl"))
	return strings.Count(string(b), `"kind":"device_quota"`)
}

const tMAC = "aa:bb:cc:dd:ee:01"

func TestLimitCtlScheduleIdempotent(t *testing.T) {
	f := newFixture(t)
	f.rules[tMAC] = limitRule{DownKbit: 10000, UpKbit: 5000}
	f.writeRules()
	f.writeDevices(map[string][2]int64{tMAC: {0, 0}})
	if r := f.c.actionScheduleSet(map[string]string{"mac": tMAC, "windows": `[{"start":"22:00","end":"07:00","down_mbps":2,"up_mbps":1}]`}); !r.OK {
		t.Fatalf("schedule_set: %+v", r)
	}
	f.tickExpect(at(28, 21, 0), 0, "before window")
	f.tickExpect(at(28, 22, 0), 1, "enter window")
	if f.rules[tMAC] != (limitRule{DownKbit: 2000, UpKbit: 1000}) {
		t.Fatalf("window rule not applied: %+v", f.rules[tMAC])
	}
	for m := 1; m <= 5; m++ {
		f.tickExpect(at(28, 22, m), 0, "desired == applied must not re-apply")
	}
	f.tickExpect(at(29, 7, 0), 1, "leave window")
	if f.rules[tMAC] != (limitRule{DownKbit: 10000, UpKbit: 5000}) {
		t.Fatalf("manual base not restored: %+v", f.rules[tMAC])
	}
	f.tickExpect(at(29, 7, 1), 0, "steady")
	// 视图
	rows := []map[string]interface{}{{"mac": tMAC}}
	f.tickExpect(at(29, 23, 0), 1, "enter again")
	f.c.annotateDevices(rows)
	eff := rows[0]["effective"].(map[string]interface{})
	sch := rows[0]["schedule"].(map[string]interface{})
	if eff["reason"] != "schedule" || eff["down_mbps"] != 2.0 || sch["active_window_index"] != 0 {
		t.Fatalf("view: %+v %+v", eff, sch)
	}
	// schedule_clear → 恢复基线, 之后不再触碰
	f.c.actionScheduleClear(map[string]string{"mac": tMAC})
	f.tickExpect(at(29, 23, 1), 1, "clear restores base")
	if f.rules[tMAC] != (limitRule{DownKbit: 10000, UpKbit: 5000}) {
		t.Fatalf("clear did not restore: %+v", f.rules[tMAC])
	}
	f.tickExpect(at(29, 23, 2), 0, "no policy, no churn")
}

func TestLimitCtlQuotaRolloverRestoresManual(t *testing.T) {
	f := newFixture(t)
	g := int64(bytesPerGB)
	f.rules[tMAC] = limitRule{DownKbit: 10000}
	f.writeRules()
	f.writeDevices(map[string][2]int64{tMAC: {5 * g, 0}}) // 旧累计, 不应计入
	if r := f.c.actionQuotaSet(map[string]string{"mac": tMAC, "daily_gb": "1"}); !r.OK {
		t.Fatalf("quota_set: %+v", r)
	}
	f.tickExpect(at(29, 10, 0), 0, "baseline only")
	f.writeDevices(map[string][2]int64{tMAC: {5*g + g/2, 0}})
	f.tickExpect(at(29, 10, 1), 0, "under quota")
	// 计数器复位后又跑了 0.6GB: 累计 1.1GB > 1GB
	f.writeDevices(map[string][2]int64{tMAC: {g * 6 / 10, 0}})
	f.tickExpect(at(29, 10, 2), 1, "exceeded → throttle")
	if f.rules[tMAC] != (limitRule{DownKbit: 1000, UpKbit: 500}) {
		t.Fatalf("throttle: %+v", f.rules[tMAC])
	}
	f.tickExpect(at(29, 10, 3), 0, "still exceeded, no churn")
	if n := f.alerts(); n != 1 {
		t.Fatalf("want exactly 1 alert, got %d", n)
	}
	// 用户在超限期间改了手动限速 → 采纳为新基线, 配额仍然优先
	f.rules[tMAC] = limitRule{DownKbit: 20000}
	f.writeRules()
	f.tickExpect(at(29, 10, 4), 1, "manual change during throttle → re-throttle")
	if f.rules[tMAC] != (limitRule{DownKbit: 1000, UpKbit: 500}) {
		t.Fatalf("re-throttle: %+v", f.rules[tMAC])
	}
	// httpd 重启: 从持久状态重算, 不误把限流值当基线, 不重复告警
	f.c.saveStateLocked(at(29, 10, 5), true)
	f.newCtl()
	f.tickExpect(at(29, 10, 6), 0, "restart: nothing to do")
	// 次日零点: 新周期 → 恢复用户最新手动值 20Mbps
	f.tickExpect(at(30, 0, 0), 1, "period rollover")
	if f.rules[tMAC] != (limitRule{DownKbit: 20000}) {
		t.Fatalf("rollover restore: %+v", f.rules[tMAC])
	}
	if n := f.alerts(); n != 1 {
		t.Fatalf("alerts after restart/rollover: %d", n)
	}
	rows := []map[string]interface{}{{"mac": tMAC}}
	f.c.annotateDevices(rows)
	q := rows[0]["quota"].(map[string]interface{})
	if q["state"] != "ok" || q["applied"] != false || q["used_today"] != uint64(0) {
		t.Fatalf("quota view: %+v", q)
	}
}

func TestLimitCtlQuotaBlockMonthly(t *testing.T) {
	f := newFixture(t)
	g := int64(bytesPerGB)
	f.writeDevices(map[string][2]int64{tMAC: {0, 0}})
	f.c.actionQuotaSet(map[string]string{"mac": tMAC, "monthly_gb": "2", "action": "block"})
	f.tickExpect(at(29, 10, 0), 0, "baseline")
	f.writeDevices(map[string][2]int64{tMAC: {g, g}})
	f.tickExpect(at(29, 10, 1), 1, "monthly exceeded → block")
	if !f.rules[tMAC].Blocked {
		t.Fatalf("not blocked: %+v", f.rules[tMAC])
	}
	f.tickExpect(at(30, 0, 0), 0, "day rollover does not lift monthly")
	f.tickExpect(time.Date(2026, 10, 1, 0, 0, 0, 0, tzCST), 1, "new month lifts block")
	if f.rules[tMAC].Blocked {
		t.Fatalf("still blocked")
	}
}

func TestLimitCtlSimMACNeverApplied(t *testing.T) {
	f := newFixture(t)
	sim := "02:5e:00:00:00:07"
	f.writeDevices(map[string][2]int64{sim: {0, 0}})
	f.c.actionScheduleSet(map[string]string{"mac": sim, "windows": `[{"start":"00:00","end":"00:00","block":true}]`})
	f.tickExpect(at(28, 12, 0), 0, "sim mac must not reach apply")
	f.tickExpect(at(28, 12, 1), 0, "sim mac must not reach apply")
	rows := []map[string]interface{}{{"mac": sim}}
	f.c.annotateDevices(rows)
	if eff := rows[0]["effective"].(map[string]interface{}); eff["blocked"] != true || eff["reason"] != "schedule" {
		t.Fatalf("sim view: %+v", eff)
	}
	if _, ok := f.c.st.Devices[sim]; ok {
		t.Fatalf("sim mac persisted in state")
	}
}

func TestLimitCtlUnreadableRulesSkips(t *testing.T) {
	f := newFixture(t)
	f.rules[tMAC] = limitRule{DownKbit: 10000}
	f.writeRules()
	f.writeDevices(map[string][2]int64{tMAC: {0, 0}})
	f.c.actionScheduleSet(map[string]string{"mac": tMAC, "windows": `[{"start":"22:00","end":"07:00","down_mbps":2}]`})
	f.tickExpect(at(28, 22, 0), 1, "enter")
	os.WriteFile(filepath.Join(f.dir, "data", "rules.json"), []byte("{half"), 0o644)
	f.tickExpect(at(29, 7, 0), 0, "rules.json unreadable → skip, do not adopt")
	f.writeRules()
	f.tickExpect(at(29, 7, 1), 1, "recovered → restore base")
	if f.rules[tMAC] != (limitRule{DownKbit: 10000}) {
		t.Fatalf("base lost: %+v", f.rules[tMAC])
	}
}

func TestLimitCtlOfflineDefersLimit(t *testing.T) {
	f := newFixture(t)
	f.rules[tMAC] = limitRule{DownKbit: 10000}
	f.writeRules()
	os.WriteFile(filepath.Join(f.dir, "data", "devices.json"), []byte(`{}`), 0o644)
	f.c.actionScheduleSet(map[string]string{"mac": tMAC, "windows": `[{"start":"22:00","end":"07:00","down_mbps":2}]`})
	f.tickExpect(at(28, 22, 0), 0, "offline: limit change deferred")
	f.tickExpect(at(28, 22, 1), 0, "offline: still deferred")
	f.writeDevices(map[string][2]int64{tMAC: {0, 0}})
	f.tickExpect(at(28, 22, 2), 1, "online → applied")
}

func TestQuotaSetValidation(t *testing.T) {
	f := newFixture(t)
	for _, p := range []map[string]string{
		{"mac": "bad"},
		{"mac": tMAC},
		{"mac": tMAC, "daily_gb": "-1"},
		{"mac": tMAC, "daily_gb": "1", "action": "nuke"},
		{"mac": tMAC, "daily_gb": "1", "throttle_mbps": "0.01"},
		{"mac": "ff:ff:ff:ff:ff:ff", "daily_gb": "1"},
	} {
		if r := f.c.actionQuotaSet(p); r.OK {
			t.Errorf("accepted %v", p)
		}
	}
	r := f.c.actionQuotaSet(map[string]string{"mac": strings.ToUpper(tMAC), "monthly_gb": "30", "throttle_mbps": "2"})
	if !r.OK {
		t.Fatalf("%+v", r)
	}
	q := f.c.policies[tMAC].Quota
	if q.Action != "throttle" || q.ThrottleDownMbps != 2 || q.ThrottleUpMbps != 1 {
		t.Fatalf("defaults: %+v", q)
	}
	f.c.actionQuotaSet(map[string]string{"mac": tMAC, "daily_gb": "1"})
	if q := f.c.policies[tMAC].Quota; q.ThrottleDownMbps != 1 || q.ThrottleUpMbps != 0.5 {
		t.Fatalf("default throttle 1/0.5: %+v", q)
	}
	// 持久化
	b, _ := os.ReadFile(filepath.Join(f.dir, "data", "limit_policies.json"))
	if !strings.Contains(string(b), `"daily_gb": 1`) {
		t.Fatalf("not persisted: %s", b)
	}
}
