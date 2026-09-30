package main

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

// simTestEnv 建一个临时 hncDir, bin/ 下放「探针」脚本: 同名替身, 被执行就往
// run/exec.log 追加一行。覆盖仓库 bin/*.sh 全部脚本名 + runExe 调的二进制名,
// 因此任何 runBin / runExe / runBinDetached 触达都会留下痕迹。
func simTestEnv(t *testing.T) (*server, string) {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"bin", "run", "data", "logs"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(dir, "run", "exec.log")
	names := map[string]bool{"hnc_ipc": true, "hnc_clsact_ctl": true}
	repoBins, _ := filepath.Glob(filepath.Join("..", "..", "bin", "*.sh"))
	for _, p := range repoBins {
		names[filepath.Base(p)] = true
	}
	for _, n := range []string{"apply_device_rule.sh", "device_detect.sh", "json_set.sh", "json_set_batch.sh",
		"tc_manager.sh", "iptables_manager.sh", "connblock_sync.sh", "whitelist_sync.sh"} {
		names[n] = true
	}
	script := "#!/bin/sh\necho \"$0 $*\" >> '" + marker + "'\necho 1\nexit 0\n"
	for n := range names {
		if err := os.WriteFile(filepath.Join(dir, "bin", n), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return newServer(dir), marker
}

func execLog(marker string) string {
	b, _ := os.ReadFile(marker)
	return string(b)
}

func mustOK(t *testing.T, r actionResp, what string) {
	t.Helper()
	if !r.OK {
		t.Fatalf("%s: %+v", what, r)
	}
}

func simAddOne(t *testing.T, s *server, p map[string]string) string {
	t.Helper()
	r := dispatchAction(s, "sim_device_add", p, false)
	mustOK(t, r, "sim_device_add")
	var out map[string]string
	if err := json.Unmarshal([]byte(r.Detail), &out); err != nil || !isSimMAC(out["mac"]) {
		t.Fatalf("add detail = %q", r.Detail)
	}
	return out["mac"]
}

func TestSimMACValidation(t *testing.T) {
	good := []string{"02:5e:00:00:00:01", "02:5e:00:ab:cd:ef"}
	bad := []string{"02:5e:01:00:00:01", "aa:bb:cc:dd:ee:ff", "02:5E:00:00:00:01", "02:5e:00:00:00", "02:5e:00:gg:00:01", ""}
	for _, m := range good {
		if !isSimMAC(m) {
			t.Errorf("isSimMAC(%q) = false", m)
		}
	}
	for _, m := range bad {
		if isSimMAC(m) {
			t.Errorf("isSimMAC(%q) = true", m)
		}
	}
	if simNormMAC("02-5E-00-0A-0B-0C") != "02:5e:00:0a:0b:0c" {
		t.Error("simNormMAC should canonicalize")
	}
}

func TestSimRateBounds(t *testing.T) {
	d := simDevice{MAC: "02:5e:00:00:00:01", RxBps: 2 << 20, TxBps: 300 << 10, Jitter: 1}
	const seed = 12345
	var prev int64 = -1
	maxStep := int64(0)
	for i := 0; i < 20000; i++ {
		tt := 1.7e9 + float64(i)
		rx, tx := simRate(&d, seed, tt)
		if rx < 0 || rx > 2*d.RxBps || tx < 0 || tx > 2*d.TxBps {
			t.Fatalf("t=%v rate out of bounds rx=%d tx=%d", tt, rx, tx)
		}
		if rx2, _ := simRate(&d, seed, tt); rx2 != rx {
			t.Fatal("not deterministic")
		}
		if prev >= 0 {
			if st := abs64(rx - prev); st > maxStep {
				maxStep = st
			}
		}
		prev = rx
	}
	// 平滑: 1 秒内最大跳变不超过基准的 60%(纯随机会接近 200%)
	if maxStep > d.RxBps*6/10 {
		t.Errorf("rate not smooth: max 1s step %d vs base %d", maxStep, d.RxBps)
	}
	// jitter=0 → 恒等于基准
	d0 := d
	d0.Jitter = 0
	if rx, tx := simRate(&d0, seed, 1.7e9); rx != d.RxBps || tx != d.TxBps {
		t.Errorf("jitter=0 rx=%d tx=%d", rx, tx)
	}
	// 限速: 永不超过上限
	dl := d
	dl.LimitDownMbps, dl.LimitUpMbps = 4, 1 // 500000 B/s, 125000 B/s
	for i := 0; i < 5000; i++ {
		rx, tx := simRate(&dl, seed, 1.7e9+float64(i))
		if rx > 500000 || tx > 125000 {
			t.Fatalf("limit exceeded rx=%d tx=%d", rx, tx)
		}
	}
	// 按应用限速作用于主应用
	da := d
	da.AppID, da.AppLimits = "douyin", map[string]float64{"douyin": 1}
	if rx, _ := simRate(&da, seed, 1.7e9); rx > 125000 {
		t.Errorf("app limit not applied rx=%d", rx)
	}
	// 黑名单 / 离线 → 0
	db := d
	db.Blocked = true
	if rx, tx := simRate(&db, seed, 1.7e9); rx != 0 || tx != 0 {
		t.Error("blocked must be 0")
	}
	do := d
	do.Offline = true
	if rx, tx := simRate(&do, seed, 1.7e9); rx != 0 || tx != 0 {
		t.Error("offline must be 0")
	}
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// 核心安全保证: 模拟 MAC 的所有设备级动作都不触达任何脚本。
func TestSimDeviceActionsNeverExec(t *testing.T) {
	s, marker := simTestEnv(t)

	// 对照组: 真实 MAC 的 rule_set 会跑脚本 → 证明探针有效
	mustOK(t, dispatchAction(s, "rule_set", map[string]string{"mac": "aa:bb:cc:dd:ee:01", "rate_down": "10mbit"}, false), "control rule_set")
	if !strings.Contains(execLog(marker), "apply_device_rule.sh") {
		t.Fatalf("probe harness broken: control action did not hit the fake script; log=%q", execLog(marker))
	}
	_ = os.Remove(marker)

	// 模拟环境关闭 + 未登记的模拟前缀 MAC: 与无此功能时一致(照常走原逻辑)
	mustOK(t, dispatchAction(s, "rule_clear", map[string]string{"mac": "02:5e:00:99:99:99"}, false), "disabled passthrough")
	if !strings.Contains(execLog(marker), "apply_device_rule.sh") {
		t.Fatal("disabled + unregistered sim-prefix mac should pass through unchanged")
	}
	_ = os.Remove(marker)

	mustOK(t, dispatchAction(s, "sim_set", map[string]string{"enabled": "true"}, false), "sim_set")
	mac := simAddOne(t, s, map[string]string{"type": "phone", "app": "douyin"})
	upper := strings.ToUpper(strings.ReplaceAll(mac, ":", "-"))

	cases := []struct {
		action string
		p      map[string]string
	}{
		{"rule_set", map[string]string{"mac": mac, "rate_down": "8mbit", "rate_up": "2mbit"}},
		{"template_apply", map[string]string{"mac": mac, "rate_down": "16mbit"}},
		{"rule_clear", map[string]string{"mac": mac}},
		{"rule_set", map[string]string{"mac": mac, "rate_down": "4mbit"}},
		{"bl_add", map[string]string{"mac": mac}},
		{"bl_del", map[string]string{"mac": mac}},
		{"bl_add", map[string]string{"mac": mac}},
		{"delay_set", map[string]string{"mac": mac, "delay_ms": "120", "jitter_ms": "10", "loss_pct": "1.5"}},
		{"rule_sqm", map[string]string{"mac": mac, "enabled": "true"}},
		{"device_whitelist_set", map[string]string{"mac": mac, "enabled": "true"}},
		{"device_rename", map[string]string{"mac": mac, "name": "模拟-改名"}},
		{"device_ident_set", map[string]string{"mac": mac, "type": "tablet", "brand": "Test"}},
		{"conn_block_add", map[string]string{"mac": mac, "kind": "domain", "value": "douyin.com"}},
		{"conn_block_add", map[string]string{"mac": mac, "kind": "ip", "value": "8.8.8.8"}},
		{"conn_block_del", map[string]string{"mac": mac, "kind": "ip", "value": "8.8.8.8"}},
		{"app_limit_set", map[string]string{"mac": upper, "app_id": "douyin", "down_mbps": "3"}},
		{"app_limit_set", map[string]string{"mac": mac, "app_id": "weixin", "down_mbps": "1"}},
		{"app_limit_clear", map[string]string{"mac": mac, "app_id": "weixin"}},
		{"alert_mark_known", map[string]string{"mac": mac}},
		// 其它 agent 新增的设备级动作也被通用闸门截走(空操作)
		{"quota_set", map[string]string{"mac": mac, "limit_gb": "5"}},
		{"schedule_set", map[string]string{"mac": mac}},
		{"app_time_limit_set", map[string]string{"mac": mac, "app_id": "douyin"}},
		{"category_block_set", map[string]string{"mac": mac}},
	}
	for _, c := range cases {
		r := dispatchAction(s, c.action, c.p, false)
		if !r.OK {
			t.Errorf("%s on sim mac: %+v", c.action, r)
		}
		if l := execLog(marker); l != "" {
			t.Fatalf("%s on sim mac executed a script: %q", c.action, l)
		}
	}
	// 模拟环境开启时, 未登记的模拟前缀 MAC 也不放行
	r := dispatchAction(s, "rule_set", map[string]string{"mac": "02:5e:00:77:77:77", "rate_down": "8mbit"}, false)
	if r.OK || r.Error != "not found" {
		t.Errorf("unknown sim mac while enabled: %+v", r)
	}
	// 校验沿用原动作规则: 非法值被拒且不执行
	if r := dispatchAction(s, "rule_set", map[string]string{"mac": mac, "rate_down": "1kbit"}, false); r.OK {
		t.Error("rule_set below min rate accepted for sim")
	}
	if r := dispatchAction(s, "delay_set", map[string]string{"mac": mac, "delay_ms": "9999", "jitter_ms": "0", "loss_pct": "0"}, false); r.OK {
		t.Error("delay_set out of range accepted for sim")
	}
	if l := execLog(marker); l != "" {
		t.Fatalf("sim actions executed scripts: %q", l)
	}
	// 模拟环境关闭后, 已登记的模拟设备依然被截走(不会漏到脚本)
	mustOK(t, dispatchAction(s, "sim_set", map[string]string{"enabled": "false"}, false), "sim_set off")
	mustOK(t, dispatchAction(s, "bl_del", map[string]string{"mac": mac}, false), "bl_del registered while disabled")
	mustOK(t, dispatchAction(s, "bl_add", map[string]string{"mac": mac}, false), "bl_add registered while disabled")
	if l := execLog(marker); l != "" {
		t.Fatalf("registered sim mac leaked to scripts while disabled: %q", l)
	}
	// 没有写任何真实状态文件
	for _, f := range []string{"data/app_limits.json", "data/conn_blocks.json", "data/device_names.json", "data/device_ident_override.json"} {
		if _, err := os.Stat(filepath.Join(s.hncDir, f)); err == nil {
			t.Errorf("sim action wrote real state file %s", f)
		}
	}

	// sim 状态确实被更新
	st := simFor(s.hncDir)
	st.mu.Lock()
	d := *st.findLocked(mac)
	st.mu.Unlock()
	if d.LimitDownMbps != 4 || d.LimitUpMbps != 0 || !d.Blocked || d.DelayMs != 120 || d.JitterMs != 10 || d.LossPct != 1.5 ||
		!d.SQM || !d.Whitelist || d.Name != "模拟-改名" || d.Ident["type"] != "tablet" || len(d.ConnBlocks) != 1 ||
		d.AppLimits["douyin"] != 3 || len(d.AppLimits) != 1 {
		t.Errorf("sim device state not updated: %+v", d)
	}
	// 落盘且可重新加载
	b, err := os.ReadFile(simPath(s.hncDir))
	if err != nil || !strings.Contains(string(b), mac) {
		t.Fatalf("sim.json not written: %v", err)
	}
}

func TestSimActionValidation(t *testing.T) {
	s, marker := simTestEnv(t)
	bad := []struct {
		action string
		p      map[string]string
	}{
		{"sim_set", map[string]string{"enabled": "maybe"}},
		{"sim_set", map[string]string{}},
		{"sim_device_add", map[string]string{"type": "fridge"}},
		{"sim_device_add", map[string]string{"rx": "-5"}},
		{"sim_device_add", map[string]string{"rx": "99999m"}},
		{"sim_device_add", map[string]string{"app": "Bad App!"}},
		{"sim_device_add", map[string]string{"bogus": "1"}},
		{"sim_device_add", map[string]string{"name": "a\nb"}},
		{"sim_device_add", map[string]string{"ip": "8.8.8.8"}},
		{"sim_device_update", map[string]string{"mac": "aa:bb:cc:dd:ee:ff", "rx": "1"}},
		{"sim_device_update", map[string]string{"mac": "02:5e:00:00:00:01", "rx": "1"}},
		{"sim_device_del", map[string]string{"mac": "aa:bb:cc:dd:ee:ff"}},
		{"sim_preset", map[string]string{"preset": "party"}},
	}
	for _, c := range bad {
		if r := dispatchAction(s, c.action, c.p, false); r.OK {
			t.Errorf("%s %v accepted", c.action, c.p)
		}
	}
	mac := simAddOne(t, s, map[string]string{"name": "模拟-测试", "type": "tv", "rx": "2m", "tx": "100k", "jitter": "0.3"})
	for _, p := range []map[string]string{
		{"mac": mac, "jitter": "1.5"}, {"mac": mac, "limit_down_mbps": "abc"}, {"mac": mac, "delay_ms": "6000"},
		{"mac": mac, "blocked": "yes please"}, {"mac": mac, "type": "car"},
	} {
		if r := dispatchAction(s, "sim_device_update", p, false); r.OK {
			t.Errorf("update %v accepted", p)
		}
	}
	mustOK(t, dispatchAction(s, "sim_device_update", map[string]string{"mac": mac, "rx": "512k", "blocked": "true",
		"limit_down_mbps": "2.5", "category": "video", "offline": "false"}, false), "update")
	st := simFor(s.hncDir)
	st.mu.Lock()
	d := *st.findLocked(mac)
	st.mu.Unlock()
	if d.RxBps != 512<<10 || !d.Blocked || d.LimitDownMbps != 2.5 || d.TxBps != 100<<10 || d.Name != "模拟-测试" {
		t.Errorf("update not applied: %+v", d)
	}
	for _, preset := range []string{"home", "busy", "idle"} {
		mustOK(t, dispatchAction(s, "sim_preset", map[string]string{"preset": preset}, false), preset)
		st.mu.Lock()
		n := len(st.f.Devices)
		for _, dv := range st.f.Devices {
			if !isSimMAC(dv.MAC) || !simValidType(dv.Type) || dv.Name == "" || dv.AppID == "" {
				t.Errorf("preset %s bad device %+v", preset, dv)
			}
		}
		st.mu.Unlock()
		if n < 4 || n > 8 {
			t.Errorf("preset %s: %d devices", preset, n)
		}
	}
	mustOK(t, dispatchAction(s, "sim_device_del", map[string]string{"mac": st.f.Devices[0].MAC}, false), "del")
	mustOK(t, dispatchAction(s, "sim_clear", map[string]string{}, false), "clear")
	if len(st.f.Devices) != 0 {
		t.Error("clear left devices")
	}
	if l := execLog(marker); l != "" {
		t.Fatalf("sim_* actions executed scripts: %q", l)
	}
}

func getJSON(t *testing.T, h http.HandlerFunc, url string) map[string]interface{} {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, url, nil))
	var m map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("%s: bad json %v: %s", url, err, rec.Body.String())
	}
	return m
}

func TestSimMergeReadAPIs(t *testing.T) {
	s, marker := simTestEnv(t)
	real := `{"aa:bb:cc:dd:ee:01":{"ip":"192.168.43.2","mac":"aa:bb:cc:dd:ee:01","hostname":"real","hostname_src":"dhcp","iface":"wlan2","rx_bytes":1,"tx_bytes":1,"status":"allowed","last_seen":1}}`
	if err := os.WriteFile(filepath.Join(s.hncDir, "data", "devices.json"), []byte(real), 0o644); err != nil {
		t.Fatal(err)
	}
	// 关闭时: 输出与无此功能一致(没有模拟设备, 没有 sim 字段)
	_, before := s.buildDevicesPayload()
	bj, _ := json.Marshal(before)
	if strings.Contains(string(bj), "02:5e:00") || strings.Contains(string(bj), `"sim"`) {
		t.Fatalf("disabled sim leaked into devices: %s", bj)
	}
	if cfg := getJSON(t, s.apiConfig, "/api/config"); cfg["sim_enabled"] != false {
		t.Errorf("config sim_enabled = %v", cfg["sim_enabled"])
	}

	mustOK(t, dispatchAction(s, "sim_preset", map[string]string{"preset": "busy"}, false), "preset")
	st := simFor(s.hncDir)
	st.mu.Lock()
	var activeMAC, blockedMAC string
	for _, d := range st.f.Devices {
		if d.Blocked {
			blockedMAC = d.MAC
		} else if !d.Offline && activeMAC == "" && d.RxBps > 1<<20 && d.LimitDownMbps == 0 {
			activeMAC = d.MAC
		}
	}
	nSim := len(st.f.Devices)
	st.mu.Unlock()

	// /api/devices
	_, after := s.buildDevicesPayload()
	devs := after["devices"].([]map[string]interface{})
	if len(devs) != 1+nSim {
		t.Fatalf("devices = %d, want %d", len(devs), 1+nSim)
	}
	requiredKeys := []string{"mac", "ip", "hostname", "hostname_src", "rx_bytes", "tx_bytes", "status", "last_seen", "online",
		"down_mbps", "up_mbps", "limit_enabled", "delay_ms", "jitter_ms", "loss_pct", "delay_enabled", "sqm_enabled",
		"whitelist", "rx_bps", "tx_bps", "ident"}
	for _, d := range devs {
		mac := asString(d["mac"])
		if !isSimMAC(mac) {
			if _, has := d["sim"]; has {
				t.Error("real device got sim flag")
			}
			continue
		}
		if d["sim"] != true {
			t.Errorf("%s missing sim:true", mac)
		}
		for _, k := range requiredKeys {
			if _, ok := d[k]; !ok {
				t.Errorf("sim device %s missing %q", mac, k)
			}
		}
		if mac == blockedMAC && (d["status"] != "blocked" || d["rx_bps"].(int64) != 0) {
			t.Errorf("blocked sim device: status=%v rx=%v", d["status"], d["rx_bps"])
		}
	}

	// /api/live
	live := getJSON(t, s.apiLive, "/api/live")
	if live["sim"] != true || live["hotspot_active"] != true || live["rx_bps"].(float64) <= 0 {
		t.Errorf("live not merged: %v", live)
	}

	// /api/connections 汇总 + 明细
	cc := getJSON(t, s.apiConnections, "/api/connections")
	counts, _ := cc["counts"].(map[string]interface{})
	if counts[activeMAC] == nil || counts[blockedMAC] != nil {
		t.Errorf("conn counts: %v", counts)
	}
	cd := getJSON(t, s.apiConnections, "/api/connections?mac="+activeMAC)
	conns, _ := cd["conns"].([]interface{})
	if cd["sim"] != true || len(conns) < 2 || cd["mac"] != activeMAC {
		t.Fatalf("conn detail: %v", cd)
	}
	c0 := conns[0].(map[string]interface{})
	for _, k := range []string{"proto", "dst", "dport", "sport", "up_bytes", "down_bytes", "up_bps", "down_bps", "v6", "ttl", "name", "name_src"} {
		if _, ok := c0[k]; !ok {
			t.Errorf("conn missing %q: %v", k, c0)
		}
	}
	for _, k := range []string{"ips", "blocks", "total", "groups", "up_bytes", "down_bytes", "bps"} {
		if _, ok := cd[k]; !ok {
			t.Errorf("conn detail missing %q", k)
		}
	}

	// /api/app_usage: 今日按应用/设备/小时都有模拟流量
	au := getJSON(t, s.apiAppUsage, "/api/app_usage?days=1")
	if au["total_down"].(float64) <= 0 {
		t.Errorf("app_usage total_down = %v", au["total_down"])
	}
	foundDev := false
	for _, x := range au["by_device"].([]interface{}) {
		if x.(map[string]interface{})["mac"] == activeMAC {
			foundDev = true
		}
	}
	if !foundDev || len(au["by_app"].([]interface{})) == 0 {
		t.Errorf("app_usage missing sim device/apps: %v", au)
	}

	// /api/stats today
	stt := getJSON(t, s.apiStats, "/api/stats?range=today")
	var sum float64
	for _, b := range stt["buckets"].([]interface{}) {
		sum += b.(map[string]interface{})["rx"].(float64)
	}
	if sum <= 0 {
		t.Error("stats today has no sim bytes")
	}
	// usage_month / online_hours / dpi_history / app_limits / sim / config
	um := getJSON(t, s.apiUsageMonth, "/api/usage_month")
	if um["devices"].(map[string]interface{})[activeMAC] == nil {
		t.Error("usage_month missing sim device")
	}
	oh := getJSON(t, s.apiOnlineHours, "/api/online_hours")
	if oh["hours"].(map[string]interface{})[activeMAC] == nil {
		t.Error("online_hours missing sim device")
	}
	dh := getJSON(t, s.apiDPIHistory, "/api/dpi_history?days=1&mac="+activeMAC)
	if dh["total_rx"].(float64) <= 0 {
		t.Errorf("dpi_history not merged: %v", dh["total_rx"])
	}
	simSt := getJSON(t, s.apiSim, "/api/sim")
	if simSt["enabled"] != true || int(simSt["count"].(float64)) != nSim {
		t.Errorf("/api/sim = %v", simSt)
	}
	if cfg := getJSON(t, s.apiConfig, "/api/config"); cfg["sim_enabled"] != true {
		t.Errorf("config sim_enabled = %v", cfg["sim_enabled"])
	}

	// 累计随时间单调增长
	st.mu.Lock()
	before1 := st.acc[activeMAC].hours
	st.advanceLocked(time.Now().Add(30 * time.Second))
	after1 := st.acc[activeMAC].hours
	st.mu.Unlock()
	var s0, s1 uint64
	for h := 0; h < 24; h++ {
		s0 += before1[h][0]
		s1 += after1[h][0]
	}
	if s1 <= s0 {
		t.Errorf("accumulation not increasing: %d → %d", s0, s1)
	}

	// 关闭后一切回到原样
	mustOK(t, dispatchAction(s, "sim_set", map[string]string{"enabled": "false"}, false), "off")
	_, off := s.buildDevicesPayload()
	oj, _ := json.Marshal(off)
	if string(oj) != string(bj) {
		t.Errorf("disabled payload differs:\n%s\n%s", bj, oj)
	}
	if l := execLog(marker); l != "" {
		t.Fatalf("read path executed scripts: %q", l)
	}
}

func TestSimAppLibraryFromRules(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	repo, _ := filepath.Abs(filepath.Join("..", ".."))
	if _, err := os.Stat(filepath.Join(repo, "data", "dpi_rules.json")); err != nil {
		t.Skip("repo rules not available")
	}
	_ = os.WriteFile(filepath.Join(dir, "run", "service.path"), []byte(repo), 0o644)
	lib := simAppLibrary(dir)
	if len(lib) < 20 {
		t.Fatalf("expected rules from library, got %d", len(lib))
	}
	for _, a := range lib {
		if !validAppID(a.ID) || len(a.Domains) == 0 || appTier(a.Cat) != tierApp {
			t.Errorf("bad lib app %+v", a)
		}
	}
}
