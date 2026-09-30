package main

// v5.19 模拟环境合并: /api/app_time, /api/dpi_unknown, /api/phone_usage, 配额/时段视图。
// 每个合并点: 字段齐全、带 sim 标记、关闭后与未开启时逐字节一致、不跑任何脚本。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func getBody(t *testing.T, h http.HandlerFunc, url string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, url, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", url, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// simPresetAndWarm 载入 busy 预设, 并把累计往后推 2 分钟(实时段), 保证有活跃秒数。
// 返回一台在跑、没限速、有应用的设备和一台被拉黑的设备。
func simPresetAndWarm(t *testing.T, s *server) (active, blocked, appID string) {
	t.Helper()
	mustOK(t, dispatchAction(s, "sim_preset", map[string]string{"preset": "busy"}, false), "preset")
	st := simFor(s.hncDir)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.advanceLocked(time.Now())
	st.advanceLocked(time.Now().Add(2 * time.Minute))
	for _, d := range st.f.Devices {
		switch {
		case d.Blocked:
			blocked = d.MAC
		case active == "" && !d.Offline && d.LimitDownMbps == 0 && d.RxBps > 1<<20 && simCountsAppTime(&d):
			active, appID = d.MAC, d.AppID
		}
	}
	if active == "" || blocked == "" {
		t.Fatalf("preset busy lacks active/blocked device: %+v", st.f.Devices)
	}
	return
}

func TestSimMergeAppTime(t *testing.T) {
	s, marker := simTestEnv(t)
	base := getBody(t, s.apiAppTime, "/api/app_time?days=1")
	if strings.Contains(base, `"sim_included"`) || strings.Contains(base, `"sim":`) {
		t.Fatalf("disabled output has sim fields: %s", base)
	}
	active, _, appID := simPresetAndWarm(t, s)

	all := getJSON(t, s.apiAppTime, "/api/app_time?days=1")
	if all["sim_included"] != true || all["total_active_sec"].(float64) <= 0 {
		t.Fatalf("app_time not merged: %v", all)
	}
	var found map[string]interface{}
	for _, x := range all["apps"].([]interface{}) {
		a := x.(map[string]interface{})
		if a["id"] == appID {
			found = a
		}
	}
	if found == nil {
		t.Fatalf("sim app %s missing: %v", appID, all["apps"])
	}
	for _, k := range []string{"id", "name", "category", "active_sec", "first_seen", "last_seen", "by_hour", "sim_active_sec", "sim"} {
		if _, ok := found[k]; !ok {
			t.Errorf("app entry missing %q: %v", k, found)
		}
	}
	if found["sim"] != true || found["active_sec"].(float64) < 120 || len(found["by_hour"].([]interface{})) != 24 ||
		found["last_seen"].(float64) < found["first_seen"].(float64) || found["first_seen"].(float64) <= 0 {
		t.Errorf("sim app entry: %v", found)
	}
	var hsum float64
	for _, h := range all["by_hour"].([]interface{}) {
		hsum += h.(map[string]interface{})["active_sec"].(float64)
	}
	if hsum != all["total_active_sec"].(float64) {
		t.Errorf("by_hour sum %v != total %v", hsum, all["total_active_sec"])
	}
	// 活跃秒数不超过已过去的时间
	if sec := found["active_sec"].(float64); sec > float64(time.Now().Unix()-localDayStart(time.Now()).Unix()+300) {
		t.Errorf("active_sec %v exceeds elapsed day", sec)
	}

	// 时长上限: 模拟设备可配置(1 分钟 → 用完), 只显示不下发
	mustOK(t, dispatchAction(s, "app_time_limit_set", map[string]string{"mac": active, "app_id": appID, "minutes": "1"}, false), "limit set")
	one := getJSON(t, s.apiAppTime, "/api/app_time?days=1&mac="+active)
	lims, _ := one["app_time_limits"].([]interface{})
	if len(lims) != 1 {
		t.Fatalf("app_time_limits = %v", one["app_time_limits"])
	}
	l := lims[0].(map[string]interface{})
	if l["exhausted"] != true || l["enforced"] != false || l["sim"] != true || l["used_sec"].(float64) < 60 || l["until"] == nil {
		t.Errorf("sim limit view: %v", l)
	}
	for _, x := range one["apps"].([]interface{}) {
		if x.(map[string]interface{})["sim"] != true {
			t.Errorf("mac filter leaked non-sim app: %v", x)
		}
	}
	// /api/devices 也带上
	_, dp := s.buildDevicesPayload()
	seen := false
	for _, d := range dp["devices"].([]map[string]interface{}) {
		if d["mac"] == active {
			ls, _ := d["app_time_limits"].([]map[string]interface{})
			seen = len(ls) == 1 && ls[0]["exhausted"] == true && ls[0]["enforced"] == false
		}
	}
	if !seen {
		t.Error("devices row lacks exhausted sim app_time_limits")
	}
	// 永不下发: 派生封锁不含模拟设备, 没跑脚本
	for _, it := range s.connBlocksEffective(time.Now()).Items {
		if isSimMAC(it.MAC) {
			t.Errorf("sim mac in effective conn blocks: %+v", it)
		}
	}
	if l := execLog(marker); l != "" {
		t.Fatalf("scripts executed: %q", l)
	}
	mustOK(t, dispatchAction(s, "app_time_limit_del", map[string]string{"mac": active, "app_id": appID}, false), "limit del")

	// 关闭 → 与未开启时一致
	mustOK(t, dispatchAction(s, "sim_set", map[string]string{"enabled": "false"}, false), "off")
	if off := getBody(t, s.apiAppTime, "/api/app_time?days=1"); off != base {
		t.Errorf("disabled output differs:\n%s\n%s", base, off)
	}
}

func TestSimMergeDPIUnknown(t *testing.T) {
	s, marker := simTestEnv(t)
	base := getBody(t, s.apiDPIUnknown, "/api/dpi_unknown?days=1")
	active, _, _ := simPresetAndWarm(t, s)

	r := getJSON(t, s.apiDPIUnknown, "/api/dpi_unknown?days=1")
	if r["sim_included"] != true {
		t.Fatalf("dpi_unknown not merged: %v", r)
	}
	items := r["items"].([]interface{})
	kinds := map[string]bool{}
	var simSum float64
	sawActive := false
	for _, x := range items {
		it := x.(map[string]interface{})
		for _, k := range []string{"name_or_ip", "kind", "sample", "bytes", "devices", "macs"} {
			if _, ok := it[k]; !ok {
				t.Errorf("item missing %q: %v", k, it)
			}
		}
		if it["sim"] != true {
			t.Errorf("non-sim item with no real data: %v", it)
			continue
		}
		kinds[it["kind"].(string)] = true
		simSum += it["bytes"].(float64)
		for _, m := range it["macs"].([]interface{}) {
			if m == active {
				sawActive = true
			}
		}
	}
	if !kinds["domain"] || !kinds["ip"] || !sawActive {
		t.Errorf("want domain+ip items incl. active device: kinds=%v sawActive=%v", kinds, sawActive)
	}
	if tot := r["total_unknown_bytes"].(float64); tot <= 0 || simSum > tot*1.0001 || simSum < tot*0.999 {
		t.Errorf("total_unknown_bytes %v vs items %v", tot, simSum)
	}
	// /api/app_usage 的「未识别」与之同源
	au := getJSON(t, s.apiAppUsage, "/api/app_usage?days=1")
	unk := false
	for _, x := range au["by_app"].([]interface{}) {
		if x.(map[string]interface{})["id"] == appUnknownID {
			unk = true
		}
	}
	if !unk {
		t.Error("app_usage lacks sim unknown bytes")
	}
	if l := execLog(marker); l != "" {
		t.Fatalf("scripts executed: %q", l)
	}
	mustOK(t, dispatchAction(s, "sim_set", map[string]string{"enabled": "false"}, false), "off")
	if off := getBody(t, s.apiDPIUnknown, "/api/dpi_unknown?days=1"); off != base {
		t.Errorf("disabled output differs:\n%s\n%s", base, off)
	}
}

func TestSimMergePhoneUsage(t *testing.T) {
	s, _ := simTestEnv(t)
	now := time.Now()
	f := &puFake{boot: "b", route: "rmnet_data0", sim: puSIM{Slot: 1, Carrier: "中国移动", SubID: 1, Source: "settings"},
		ctr: map[string][2]uint64{"rmnet_data0": {1000, 1000}, "wlan0": {0, 0}, "wlan2": {0, 0}}}
	env := f.env()
	env.simHotspot = s.simHotspotHours
	e := newPuEngine(s.hncDir, env)
	e.tick(now.Add(-2 * time.Minute))
	f.ctr = map[string][2]uint64{"rmnet_data0": {21000, 5000}, "wlan0": {0, 0}, "wlan2": {1000, 8000}}
	e.tick(now.Add(-time.Minute))

	js := func(v interface{}) string { b, _ := json.Marshal(v); return string(b) }
	baseToday, baseCycle := js(e.report("today", now)), js(e.report("cycle", now))
	if strings.Contains(baseToday, "sim_included") {
		t.Fatal("disabled report has sim_included")
	}

	simPresetAndWarm(t, s)
	hours, ok := s.simHotspotHours(now)
	if !ok {
		t.Fatal("simHotspotHours not ok while enabled")
	}
	var want [2]uint64
	for h := range hours {
		puAdd2(&want, hours[h])
	}
	if want[0] == 0 {
		t.Fatal("no sim bytes")
	}
	for _, period := range []string{"today", "cycle"} {
		var a, b map[string]interface{}
		_ = json.Unmarshal([]byte(map[string]string{"today": baseToday, "cycle": baseCycle}[period]), &a)
		_ = json.Unmarshal([]byte(js(e.report(period, now))), &b)
		if b["sim_included"] != true || b["sim_hotspot"] == nil {
			t.Fatalf("%s: not merged: %v", period, b)
		}
		sh := b["sim_hotspot"].(map[string]interface{})["total"].(float64)
		if sh < float64(want[0]+want[1]) { // 报告时刻略晚, 只会更多
			t.Errorf("%s: sim_hotspot %v < %v", period, sh, want[0]+want[1])
		}
		tot := func(m map[string]interface{}, k string) float64 {
			return m["totals"].(map[string]interface{})[k].(map[string]interface{})["total"].(float64)
		}
		for _, k := range []string{"hotspot", "cellular"} {
			if d := tot(b, k) - tot(a, k); d != sh {
				t.Errorf("%s: %s delta %v != sim %v", period, k, d, sh)
			}
		}
		if tot(b, "local") != tot(a, "local") || tot(b, "wifi") != tot(a, "wifi") {
			t.Errorf("%s: local/wifi changed", period)
		}
		var cyc float64
		for _, x := range b["by_sim"].([]interface{}) {
			if r := x.(map[string]interface{}); r["slot"].(float64) == 1 {
				cyc = r["cycle_used"].(float64)
			}
		}
		if cyc < sh {
			t.Errorf("%s: by_sim slot1 cycle_used %v < sim %v", period, cyc, sh)
		}
		if period == "today" {
			var hs float64
			for _, x := range b["by_hour"].([]interface{}) {
				hs += x.(map[string]interface{})["hotspot"].(float64)
			}
			if hs != tot(b, "hotspot") {
				t.Errorf("by_hour hotspot %v != total %v", hs, tot(b, "hotspot"))
			}
		}
	}
	// 不落盘: 日文件只有真实的 8000+1000
	e.flush(now)
	d, ok := puLoadDay(s.hncDir, now.Format("20060102"))
	if !ok || d.Hotspot != [2]uint64{8000, 1000} {
		t.Errorf("day file hotspot = %v (sim bytes persisted?)", d.Hotspot)
	}
	if e.checkAlerts(now) != 0 {
		t.Error("sim bytes triggered alerts")
	}
	mustOK(t, dispatchAction(s, "sim_set", map[string]string{"enabled": "false"}, false), "off")
	if got := js(e.report("today", now)); got != baseToday {
		t.Errorf("disabled report differs:\n%s\n%s", baseToday, got)
	}
}

func TestSimQuotaScheduleViews(t *testing.T) {
	s, marker := simTestEnv(t)
	var applied []string
	s.limitCtl.apply = func(mac string, from, to limitRule) error {
		applied = append(applied, mac)
		return nil
	}
	s.limitCtl.tick(time.Now())
	_, base := s.buildDevicesPayload()
	bj, _ := json.Marshal(base)

	active, blocked, _ := simPresetAndWarm(t, s)
	st := simFor(s.hncDir)
	st.mu.Lock()
	var sched string
	for _, d := range st.f.Devices {
		if d.MAC != active && d.MAC != blocked && !d.Blocked && d.LimitDownMbps == 0 {
			sched = d.MAC
			break
		}
	}
	st.mu.Unlock()

	// 1 KB 日配额 → 必然 exceeded; 被拉黑的设备配额很宽 → reason=block; 第三台全天时段
	mustOK(t, dispatchAction(s, "quota_set", map[string]string{"mac": active, "daily_gb": "0.000001", "monthly_gb": "100", "action": "throttle"}, false), "quota active")
	mustOK(t, dispatchAction(s, "quota_set", map[string]string{"mac": blocked, "monthly_gb": "100000"}, false), "quota blocked")
	mustOK(t, dispatchAction(s, "schedule_set", map[string]string{"mac": sched, "windows": `[{"start":"00:00","end":"00:00","down_mbps":2,"up_mbps":1}]`}, false), "schedule")
	s.limitCtl.tick(time.Now())

	_, dp := s.buildDevicesPayload()
	rows := map[string]map[string]interface{}{}
	for _, d := range dp["devices"].([]map[string]interface{}) {
		rows[asString(d["mac"])] = d
	}
	q, _ := rows[active]["quota"].(map[string]interface{})
	eff, _ := rows[active]["effective"].(map[string]interface{})
	if q == nil || eff == nil {
		t.Fatalf("active sim row lacks quota/effective: %v", rows[active])
	}
	if q["state"] != "exceeded" || q["exceeded_period"] != "daily" || q["used_today"].(uint64) == 0 ||
		q["used_month"].(uint64) < q["used_today"].(uint64) || q["enforced"] != false || q["sim"] != true {
		t.Errorf("sim quota view: %v", q)
	}
	if eff["reason"] != "quota" || eff["down_mbps"] != 1.0 || eff["enforced"] != false || eff["sim"] != true {
		t.Errorf("sim effective (quota): %v", eff)
	}
	if e := rows[blocked]["effective"].(map[string]interface{}); e["reason"] != "block" || e["blocked"] != true {
		t.Errorf("blocked sim effective: %v", e)
	}
	if bq := rows[blocked]["quota"].(map[string]interface{}); bq["state"] != "ok" {
		t.Errorf("blocked sim quota state: %v", bq)
	}
	se := rows[sched]["effective"].(map[string]interface{})
	ss := rows[sched]["schedule"].(map[string]interface{})
	if se["reason"] != "schedule" || se["down_mbps"] != 2.0 || ss["active_window_index"] != 0 || ss["sim"] != true {
		t.Errorf("sim schedule view: %v %v", se, ss)
	}
	// 没有策略的模拟设备: effective 也带 sim/enforced
	for mac, r := range rows {
		if isSimMAC(mac) && r["quota"] == nil && r["schedule"] == nil {
			if e := r["effective"].(map[string]interface{}); e["sim"] != true || e["enforced"] != false {
				t.Errorf("plain sim row effective: %v", e)
			}
		}
	}
	// 永不下发
	if len(applied) != 0 {
		t.Errorf("controller applied to %v", applied)
	}
	if l := execLog(marker); l != "" {
		t.Fatalf("scripts executed: %q", l)
	}
	if b, err := os.ReadFile(filepath.Join(s.hncDir, "data", "limit_ctl_state.json")); err == nil && strings.Contains(string(b), simMACPrefix) {
		t.Errorf("sim state persisted: %s", b)
	}

	// 模拟设备的手动限速 = 基线: 解除配额后 reason=manual, 速率取模拟设备自己的限速
	mustOK(t, dispatchAction(s, "rule_set", map[string]string{"mac": active, "rate_down": "20mbit"}, false), "sim rule_set")
	mustOK(t, dispatchAction(s, "quota_set", map[string]string{"mac": active, "daily_gb": "1000"}, false), "quota wide")
	s.limitCtl.tick(time.Now())
	_, dp = s.buildDevicesPayload()
	for _, d := range dp["devices"].([]map[string]interface{}) {
		if d["mac"] == active {
			if e := d["effective"].(map[string]interface{}); e["reason"] != "manual" || e["down_mbps"] != 20.0 {
				t.Errorf("sim manual base: %v", e)
			}
		}
	}

	// 关闭 → 与未开启时一致(策略文件里残留的模拟 MAC 不影响真实输出)
	mustOK(t, dispatchAction(s, "sim_set", map[string]string{"enabled": "false"}, false), "off")
	s.limitCtl.tick(time.Now())
	_, off := s.buildDevicesPayload()
	if oj, _ := json.Marshal(off); string(oj) != string(bj) {
		t.Errorf("disabled payload differs:\n%s\n%s", bj, oj)
	}
	if len(applied) != 0 || execLog(marker) != "" {
		t.Errorf("disabled tick applied/executed: %v %q", applied, execLog(marker))
	}
}
