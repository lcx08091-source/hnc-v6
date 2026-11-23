package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ─── 识别 + 打分 ───────────────────────────────────────────────────────

func TestIsRandomizedMAC(t *testing.T) {
	cases := map[string]bool{
		"da:a1:19:00:00:01": true,  // 0xda = 1101 1010 → 本地管理位
		"a6:00:00:00:00:01": true,  // 0xa6
		"3a:12:34:56:78:9a": true,  // 0x3a
		"00:1a:11:22:33:44": false, // 厂商 OUI
		"f0:18:98:00:00:01": false, // Apple OUI
		"02:5e:00:00:00:01": false, // 模拟设备
		"03:00:00:00:00:01": false, // 组播
		"":                  false,
	}
	for mac, want := range cases {
		if got := isRandomizedMAC(mac); got != want {
			t.Errorf("isRandomizedMAC(%q)=%v want %v", mac, got, want)
		}
	}
}

func TestScoreMacPair(t *testing.T) {
	base := int64(1_790_000_000)
	old := &macProfile{
		FirstSeen: base - 86400*10, LastSeen: base - 180,
		DHCPName: "Xiaoming-Mi-10", DHCPFP: "1,3,6,15,26,28,51,58,59,43", VendorClass: "android-dhcp-13",
		Type: "phone", Brand: "Xiaomi", Model: "Mi 10", OS: "Android",
		JA4:  []string{"t13d1516h2_8daaf6152771_02713d6af862", "t13d1517h2_8daaf6152771_b1ff8ab2d16f", "t13d0912h2_f91f431d341e_dc6acd6c4d7e"},
		Apps: []string{"weixin", "douyin", "bilibili", "taobao", "qq"},
	}
	cases := []struct {
		name    string
		np      macProfile
		ok      bool
		min     int
		max     int
		reason  string
		noReaso string
	}{
		{"全部吻合: 主机名+指纹+型号+JA4+应用+3 分钟", macProfile{
			FirstSeen: base, LastSeen: base + 60, DHCPName: "xiaoming-mi-10", DHCPFP: old.DHCPFP,
			VendorClass: old.VendorClass, Type: "phone", Brand: "Xiaomi", Model: "Mi 10", OS: "Android",
			JA4: old.JA4, Apps: []string{"weixin", "douyin", "bilibili", "taobao"}}, true, 95, 100, "DHCP 主机名相同", ""},
		{"只有通用主机名 + 时间接近 = 证据不足", macProfile{FirstSeen: base, DHCPName: "android"}, false, 0, 0, "", ""},
		{"通用主机名但 DHCP 指纹/厂商类吻合", macProfile{FirstSeen: base, DHCPName: "android", DHCPFP: old.DHCPFP,
			VendorClass: old.VendorClass, Brand: "Xiaomi"}, true, 40, 60, "DHCP 指纹(option 55)相同", ""},
		{"同时在线过 → 排除", macProfile{FirstSeen: old.LastSeen - 600, DHCPName: old.DHCPName, Model: "Mi 10"}, false, 0, 0, "", ""},
		{"型号/品牌不同 → 重扣分", macProfile{FirstSeen: base, DHCPName: "Xiaoming-Mi-10", Brand: "Apple",
			Model: "iPhone 15", OS: "iOS"}, true, 0, 30, "品牌不同", ""},
		{"只靠应用 + JA4 重合(无主机名)", macProfile{FirstSeen: base + 3*3600, JA4: old.JA4[:2],
			Apps: []string{"weixin", "douyin", "bilibili", "zhihu"}}, true, 20, 45, "常用应用重合", ""},
		{"间隔超过 1 天不加时间分", macProfile{FirstSeen: base + 3*86400, DHCPName: "Xiaoming-Mi-10"}, true, 35, 35, "", "离线"},
	}
	for _, c := range cases {
		np := c.np
		sc, why, ok := scoreMacPair(&np, old)
		if ok != c.ok {
			t.Errorf("%s: ok=%v want %v (score=%d reasons=%v)", c.name, ok, c.ok, sc, why)
			continue
		}
		if !ok {
			continue
		}
		if sc < c.min || sc > c.max {
			t.Errorf("%s: score=%d want [%d,%d] reasons=%v", c.name, sc, c.min, c.max, why)
		}
		all := strings.Join(why, "|")
		if c.reason != "" && !strings.Contains(all, c.reason) {
			t.Errorf("%s: reasons %v missing %q", c.name, why, c.reason)
		}
		if c.noReaso != "" && strings.Contains(all, c.noReaso) {
			t.Errorf("%s: reasons %v should not contain %q", c.name, why, c.noReaso)
		}
	}
}

func TestScoreMacPairAnonymousRotatingResonance(t *testing.T) {
	base := int64(1_790_500_000)
	oldIPhone := &macProfile{
		FirstSeen: base - 86400*5, LastSeen: base - 120,
		DHCPName: "", DHCPFP: "1,121,3,6,15,108,114,119,252",
		Type: "phone", Brand: "Apple", Model: "iPhone", OS: "iOS",
		JA4:  []string{"t13d2014h2_a09f3c656075_14788d8d241b", "q13d0312h3_55b375c5d22e_08f83d9b1e90"},
		Apps: []string{"weixin", "bilibili", "genshin", "tailscale"},
	}
	reconnected := &macProfile{
		FirstSeen: base, LastSeen: base + 30,
		DHCPName: "", DHCPFP: oldIPhone.DHCPFP,
		Type: "phone", Brand: "Apple", Model: "iPhone", OS: "iOS",
		JA4:  oldIPhone.JA4,
		Apps: []string{"weixin", "genshin", "tailscale"},
	}
	sc, why, ok := scoreMacPair(reconnected, oldIPhone)
	if !ok || sc < 85 {
		t.Fatalf("anonymous iOS rotating MAC reconnect should reach >=85 via multimodal resonance, got ok=%v score=%d reasons=%v", ok, sc, why)
	}

	// 同家庭出现两台几乎一模一样的离线 iPhone 时, Top-2 分差保护应将首选压回 <85 提示人工确认
	twinIPhone := *oldIPhone
	twinIPhone.LastSeen = base - 240
	f := &macMergeFile{
		Profiles: map[string]*macProfile{
			"da:a1:19:00:00:99": reconnected,
			"da:a1:19:00:00:01": oldIPhone,
			"da:a1:19:00:00:02": &twinIPhone,
		},
		Dismissed: map[string]int64{},
	}
	cands := macMergeCandidates(f, "da:a1:19:00:00:99", nil, base+30)
	if len(cands) < 2 || cands[0].Score >= 85 {
		t.Fatalf("expected twin-device ambiguity guard to cap score <85, got %+v", cands)
	}
}

// ─── 夹具 ──────────────────────────────────────────────────────────────

const (
	mmOld = "00:1a:11:22:33:44" // 旧(厂商)MAC
	mmNew = "da:a1:19:5b:00:07" // 新随机 MAC
	mmSim = "02:5e:00:00:00:09"
)

func mmWrite(t *testing.T, dir, rel string, v interface{}) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	var b []byte
	switch x := v.(type) {
	case string:
		b = []byte(x)
	default:
		b, _ = json.Marshal(v)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mmRead(t *testing.T, dir, rel string) map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	return m
}

// fakeMergeOps 模拟 apply_device_rule.sh / json_set.sh 对 rules.json 的写入(不碰 tc/iptables)。
type fakeMergeOps struct {
	t         *testing.T
	dir       string
	calls     []string
	failOn    map[string]bool // "action mac"
	connSyncs int
	appSyncs  int
}

func (f *fakeMergeOps) rule(action string, p map[string]string) actionResp {
	mac := p["mac"]
	f.calls = append(f.calls, action+" "+mac)
	if f.failOn[action+" "+mac] {
		return actionResp{OK: false, Error: "apply failed", Detail: "injected"}
	}
	root := mmRead(f.t, f.dir, "data/rules.json")
	devs, _ := root["devices"].(map[string]interface{})
	if devs == nil {
		devs = map[string]interface{}{}
		root["devices"] = devs
	}
	bl, _ := root["blacklist"].([]interface{})
	dev := func() map[string]interface{} {
		d, _ := devs[mac].(map[string]interface{})
		if d == nil {
			d = map[string]interface{}{"mark_id": float64(42)}
			devs[mac] = d
		}
		return d
	}
	kb := func(s string) float64 {
		n, _ := strconv.Atoi(strings.TrimSuffix(s, "kbit"))
		return float64(n) / 1000
	}
	switch action {
	case "rule_set":
		d := dev()
		d["limit_enabled"], d["down_mbps"], d["up_mbps"] = true, kb(p["rate_down"]), kb(p["rate_up"])
	case "rule_clear":
		d := dev()
		d["limit_enabled"], d["down_mbps"], d["up_mbps"] = false, float64(0), float64(0)
	case "delay_set":
		d := dev()
		dm, _ := strconv.Atoi(p["delay_ms"])
		jm, _ := strconv.Atoi(p["jitter_ms"])
		lp, _ := strconv.ParseFloat(p["loss_pct"], 64)
		// 与真动作一致(action_v5.go actionDelaySet): 开着按应用分优先级时拒绝设延迟
		if (dm > 0 || jm > 0 || lp > 0) && truthy(d["app_qos"]) {
			return actionResp{OK: false, Error: "conflict", Detail: "app_qos on"}
		}
		d["delay_enabled"], d["delay_ms"], d["jitter_ms"], d["loss_pct"] = true, float64(dm), float64(jm), lp
	case "delay_clear":
		d := dev()
		d["delay_enabled"], d["delay_ms"], d["jitter_ms"], d["loss_pct"] = false, float64(0), float64(0), float64(0)
	case "rule_sqm":
		dev()["sqm_enabled"] = p["enabled"] == "true"
	case "device_whitelist_set":
		dev()["whitelist"] = p["enabled"] == "true"
	case "app_qos_set": // v5.32 T1: 按应用分优先级(rules.json 设备键)
		d := dev()
		// 与真动作一致(action_app_qos.go actionAppQosSet): 开着延迟模拟时拒绝开启
		if p["enabled"] == "true" && (truthy(d["delay_enabled"]) || numOf(d["delay_ms"]) > 0 ||
			numOf(d["jitter_ms"]) > 0 || numOf(d["loss_pct"]) > 0) {
			return actionResp{OK: false, Error: "conflict", Detail: "delay on"}
		}
		d["app_qos"] = p["enabled"] == "true"
	case "bl_add":
		bl = append(bl, mac)
	case "bl_del":
		kept := []interface{}{}
		for _, v := range bl {
			if v != mac {
				kept = append(kept, v)
			}
		}
		bl = kept
	case "rules_device_remove":
		delete(devs, mac)
	default:
		return actionResp{OK: false, Error: "unknown action"}
	}
	root["blacklist"] = bl
	mmWrite(f.t, f.dir, "data/rules.json", root)
	return actionResp{OK: true}
}

func (f *fakeMergeOps) persistOfflineRule(mac string, r ruleState) error {
	f.calls = append(f.calls, "persist_offline_rule "+mac)
	if f.failOn["persist_offline_rule "+mac] {
		return fmt.Errorf("injected offline persist failure")
	}
	root := mmRead(f.t, f.dir, "data/rules.json")
	devs, _ := root["devices"].(map[string]interface{})
	if devs == nil {
		devs = map[string]interface{}{}
		root["devices"] = devs
	}
	blRaw, _ := root["blacklist"].([]interface{})
	keptBL := []interface{}{}
	for _, v := range blRaw {
		if asString(v) != mac {
			keptBL = append(keptBL, v)
		}
	}
	if r.bl {
		keptBL = append(keptBL, mac)
	}
	root["blacklist"] = keptBL

	hasDev := r.exists || r.limit || r.delay || r.sqm || r.wl || r.appQos
	if !hasDev {
		delete(devs, mac)
	} else {
		d, _ := devs[mac].(map[string]interface{})
		if d == nil {
			d = map[string]interface{}{"mark_id": float64(42)}
			devs[mac] = d
		}
		if r.limit {
			d["limit_enabled"] = true
			d["down_mbps"] = float64(r.down) / 1000
			d["up_mbps"] = float64(r.up) / 1000
		} else {
			d["limit_enabled"] = false
			d["down_mbps"] = float64(0)
			d["up_mbps"] = float64(0)
		}
		lp, _ := strconv.ParseFloat(r.loss, 64)
		d["delay_enabled"] = r.delay
		d["delay_ms"] = float64(r.delayMs)
		d["jitter_ms"] = float64(r.jitterMs)
		d["loss_pct"] = lp
		d["sqm_enabled"] = r.sqm
		d["whitelist"] = r.wl
		d["app_qos"] = r.appQos
	}
	mmWrite(f.t, f.dir, "data/rules.json", root)
	return nil
}

func (f *fakeMergeOps) syncConnBlocks() error { f.connSyncs++; return nil }
func (f *fakeMergeOps) syncAppLimits()        { f.appSyncs++ }

// mmFixture 一台"旧 MAC 上配了一切"的设备 + 刚连上的新随机 MAC + 一台无关设备。
func mmFixture(t *testing.T) (string, *server, *fakeMergeOps) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now().Unix()
	other := "11:22:33:44:55:66"
	mmWrite(t, dir, "data/rules.json", map[string]interface{}{
		"version": 1, "whitelist_mode": false,
		"devices": map[string]interface{}{
			// 配额节流中: rules.json 里是 1/0.5 Mbps, 手动基线(控制器 state)是 5/2 Mbps
			mmOld: map[string]interface{}{"mark_id": 7, "ip": "192.168.43.20", "down_mbps": 1, "up_mbps": 0.5,
				"limit_enabled": true, "delay_enabled": true, "delay_ms": 80, "jitter_ms": 10, "loss_pct": 0.5,
				"sqm_enabled": true, "whitelist": true, "last_seen_persist": now - 200},
			other: map[string]interface{}{"mark_id": 9, "down_mbps": 3, "up_mbps": 0, "limit_enabled": true},
		},
		"blacklist": []interface{}{mmOld},
		"whitelist": []interface{}{},
	})
	mmWrite(t, dir, "data/devices.json", map[string]interface{}{
		mmNew: map[string]interface{}{"ip": "192.168.43.31", "mac": mmNew, "hostname": "Xiaoming-Mi-10",
			"hostname_src": "dhcp", "iface": "wlan1", "rx_bytes": 100, "tx_bytes": 50, "status": "allowed", "last_seen": now},
	})
	mmWrite(t, dir, "data/device_names.json", map[string]string{mmOld: "小明的手机", other: "电视"})
	mmWrite(t, dir, "data/device_ident_override.json", map[string]interface{}{
		mmOld: map[string]interface{}{"type": "phone", "brand": "Xiaomi", "model": "Mi 10", "ts": 1}})
	mmWrite(t, dir, "data/app_limits.json", AppLimitFile{Version: 1, Items: []AppLimitItem{
		{MAC: mmOld, AppID: "douyin", DownMbps: 1}, {MAC: other, AppID: "bilibili", DownMbps: 2}}})
	mmWrite(t, dir, "data/app_limits.flat", mmOld+" douyin 1\n"+other+" bilibili 2\n")
	mmWrite(t, dir, "data/app_controls.json", appControlsFile{
		TimeLimits:     []appTimeLimit{{MAC: mmOld, AppID: "wangzhe", Minutes: 60, Ts: 1}},
		CategoryBlocks: []categoryBlock{{MAC: mmOld, Category: "game", Ts: 1}}})
	mmWrite(t, dir, "data/conn_blocks.json", connBlockFile{Items: []connBlock{
		{MAC: mmOld, Kind: "domain", Value: "example-game.com", Ts: 1}, {MAC: other, Kind: "ip", Value: "8.8.8.8", Ts: 1}}})
	day := time.Now().Format("2006-01-02")
	mmWrite(t, dir, "data/limit_policies.json", policyFile{Version: 1, Devices: map[string]*devicePolicy{
		mmOld: {Quota: &quotaPolicy{DailyGB: 2, Action: "throttle", ThrottleDownMbps: 1, ThrottleUpMbps: 0.5},
			Schedule: []schedWindow{{Start: "22:00", End: "07:00", Block: true}}}}})
	mmWrite(t, dir, "data/limit_ctl_state.json", ctlStateFile{Version: 1, Devices: map[string]*ctlDevState{
		mmOld: {Adopted: true, Base: limitRule{DownKbit: 5000, UpKbit: 2000, Blocked: true},
			LastDesired: limitRule{DownKbit: 1000, UpKbit: 500, Blocked: true}, LastObserved: limitRule{DownKbit: 1000, UpKbit: 500, Blocked: true},
			Usage: usageAcc{DayKey: day, DayBytes: 3 << 30, MonthKey: "m", MonthBytes: 5 << 30}, AlertedDay: day},
		mmNew: {Usage: usageAcc{HavePrev: true, PrevRx: 100, PrevTx: 50, DayKey: day, DayBytes: 1 << 20}},
	}})
	mmWrite(t, dir, "data/known_devices.json", map[string]interface{}{"version": 1,
		"macs": map[string]interface{}{mmOld: map[string]interface{}{"first_seen": 1, "marked_known_at": 2}}})
	s := newServer(dir)
	ops := &fakeMergeOps{t: t, dir: dir, failOn: map[string]bool{}}
	orig := macMergeOpsFor
	macMergeOpsFor = func(*server) mergeOps { return ops }
	t.Cleanup(func() { macMergeOpsFor = orig; macMergeFailStep = "" })
	return dir, s, ops
}

// ─── 合并: 全部存储迁移 ────────────────────────────────────────────────

func TestDeviceMergeMigratesAllStores(t *testing.T) {
	dir, s, ops := mmFixture(t)
	// 画像/建议(让我们检查合并后清理)
	macMergeMu.Lock()
	f := loadMacMergeFile(dir)
	f.Bootstrapped = true
	f.Profiles[mmOld] = &macProfile{FirstSeen: 1, LastSeen: 2, DHCPName: "Xiaoming-Mi-10", Apps: []string{"weixin"}}
	f.Profiles[mmNew] = &macProfile{FirstSeen: 3, LastSeen: 4, New: true, Apps: []string{"douyin"}}
	f.Suggestions[mmNew] = []macMergeCand{{OldMAC: mmOld, Score: 90}}
	_ = saveMacMergeFile(dir, f)
	macMergeMu.Unlock()

	r := dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew}, false)
	if !r.OK {
		t.Fatalf("merge failed: %+v (calls=%v)", r, ops.calls)
	}
	// rules.json: 新 MAC 拿到手动基线 5/2 Mbps(不是节流中的 1/0.5)、延迟、低延迟、白名单、黑名单
	rules := mmRead(t, dir, "data/rules.json")
	devs := rules["devices"].(map[string]interface{})
	nd, _ := devs[mmNew].(map[string]interface{})
	if nd == nil {
		t.Fatalf("new mac has no rules entry: %v", devs)
	}
	if nd["down_mbps"] != 5.0 || nd["up_mbps"] != 2.0 || nd["limit_enabled"] != true {
		t.Errorf("limit not migrated from ctl base: %v", nd)
	}
	if nd["delay_ms"] != 80.0 || nd["jitter_ms"] != 10.0 || nd["loss_pct"] != 0.5 || nd["delay_enabled"] != true {
		t.Errorf("delay not migrated: %v", nd)
	}
	if nd["sqm_enabled"] != true || nd["whitelist"] != true {
		t.Errorf("sqm/whitelist not migrated: %v", nd)
	}
	if _, still := devs[mmOld]; still {
		t.Errorf("old rules entry not removed")
	}
	if bl := rules["blacklist"].([]interface{}); len(bl) != 1 || bl[0] != mmNew {
		t.Errorf("blacklist = %v, want [new]", bl)
	}
	// 正常动作路径: 新 MAC 先写(bl_add 在限速前), 旧 MAC 后拆
	joined := strings.Join(ops.calls, ",")
	for _, want := range []string{"bl_add " + mmNew, "rule_set " + mmNew, "delay_set " + mmNew, "rule_sqm " + mmNew,
		"device_whitelist_set " + mmNew, "bl_del " + mmOld, "rule_clear " + mmOld, "delay_clear " + mmOld,
		"rules_device_remove " + mmOld} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing op %q in %v", want, ops.calls)
		}
	}
	if strings.Index(joined, "device_whitelist_set "+mmNew) > strings.Index(joined, "bl_del "+mmOld) {
		t.Errorf("old state torn down before new state was complete: %v", ops.calls)
	}
	// 名称 / 识别纠正
	names := mmRead(t, dir, "data/device_names.json")
	if names[mmNew] != "小明的手机" || names[mmOld] != nil || names["11:22:33:44:55:66"] != "电视" {
		t.Errorf("names = %v", names)
	}
	ids := readIdentOverrides(dir)
	if ids[mmNew]["model"] != "Mi 10" || ids[mmOld] != nil {
		t.Errorf("ident = %v", ids)
	}
	// 应用限速(JSON + flat)
	al := loadAppLimits(dir)
	if !reflect.DeepEqual(al.Items, []AppLimitItem{{MAC: "11:22:33:44:55:66", AppID: "bilibili", DownMbps: 2}, {MAC: mmNew, AppID: "douyin", DownMbps: 1}}) {
		t.Errorf("app_limits = %+v", al.Items)
	}
	flat, _ := os.ReadFile(filepath.Join(dir, "data/app_limits.flat"))
	if strings.Contains(string(flat), mmOld) || !strings.Contains(string(flat), mmNew+" douyin 1") {
		t.Errorf("app_limits.flat = %q", flat)
	}
	// 时长上限 / 类别封锁
	ac := loadAppControls(dir)
	if len(ac.TimeLimits) != 1 || ac.TimeLimits[0].MAC != mmNew || ac.TimeLimits[0].Minutes != 60 ||
		len(ac.CategoryBlocks) != 1 || ac.CategoryBlocks[0].MAC != mmNew {
		t.Errorf("app_controls = %+v", ac)
	}
	// 封锁项
	cb := readConnBlocks(dir)
	var cbm []string
	for _, it := range cb.Items {
		cbm = append(cbm, it.MAC+"/"+it.Value)
	}
	if !reflect.DeepEqual(cbm, []string{"11:22:33:44:55:66/8.8.8.8", mmNew + "/example-game.com"}) {
		t.Errorf("conn_blocks = %v", cbm)
	}
	if ops.connSyncs < 2 || ops.appSyncs < 2 {
		t.Errorf("sync not triggered: conn=%d app=%d", ops.connSyncs, ops.appSyncs)
	}
	// 配额 / 时段: 内存 + 文件
	s.limitCtl.mu.Lock()
	pol := s.limitCtl.policies[mmNew]
	_, oldPol := s.limitCtl.policies[mmOld]
	st := s.limitCtl.st.Devices[mmNew]
	_, oldSt := s.limitCtl.st.Devices[mmOld]
	s.limitCtl.mu.Unlock()
	if pol == nil || pol.Quota == nil || pol.Quota.DailyGB != 2 || len(pol.Schedule) != 1 || oldPol {
		t.Errorf("policies not migrated: new=%+v oldStill=%v", pol, oldPol)
	}
	pf := mmRead(t, dir, "data/limit_policies.json")["devices"].(map[string]interface{})
	if pf[mmNew] == nil || pf[mmOld] != nil {
		t.Errorf("limit_policies.json = %v", pf)
	}
	if st == nil || st.Usage.DayBytes != 3<<30+1<<20 || st.Usage.PrevRx != 100 || st.AlertedDay == "" || oldSt {
		t.Errorf("ctl usage not merged: %+v oldStill=%v", st, oldSt)
	}
	// 陌生设备账本
	kd := mmRead(t, dir, "data/known_devices.json")["macs"].(map[string]interface{})
	if e, _ := kd[mmNew].(map[string]interface{}); e == nil || e["marked_known_at"] == nil {
		t.Errorf("known_devices: new not marked known: %v", kd)
	}
	// 别名表
	if al := readMACAliasesFile(macAliasesPath(dir)); al[mmOld] != mmNew {
		t.Errorf("aliases = %v", al)
	}
	// 画像并入 / 建议清掉
	f = loadMacMergeFile(dir)
	if f.Profiles[mmOld] != nil || f.Profiles[mmNew] == nil || f.Profiles[mmNew].DHCPName != "Xiaoming-Mi-10" ||
		f.Profiles[mmNew].FirstSeen != 1 || len(f.Suggestions) != 0 {
		t.Errorf("profiles/suggestions after merge: %+v %+v", f.Profiles, f.Suggestions)
	}
	// 审计
	audit, _ := os.ReadFile(filepath.Join(dir, "logs", "audit.log"))
	if !strings.Contains(string(audit), "action=device_merge_commit") || !strings.Contains(string(audit), "migrated=") {
		t.Errorf("audit missing commit entry: %s", audit)
	}
	// /api/devices: 旧 MAC 的虚行不再出现, 新 MAC 带 randomized_mac
	_, payload := s.buildDevicesPayload()
	for _, d := range payload["devices"].([]map[string]interface{}) {
		if d["mac"] == mmOld {
			t.Errorf("old mac still listed: %v", d)
		}
		if d["mac"] == mmNew && d["randomized_mac"] != true {
			t.Errorf("new row randomized_mac = %v", d["randomized_mac"])
		}
	}
}

// ─── 回滚 ──────────────────────────────────────────────────────────────

func mmSnapshot(t *testing.T, dir string) map[string]string {
	out := map[string]string{}
	for _, rel := range []string{"data/device_names.json", "data/device_ident_override.json", "data/app_limits.json",
		"data/app_limits.flat", "data/app_controls.json", "data/conn_blocks.json", "data/limit_policies.json",
		"data/mac_aliases.json", "data/known_devices.json"} {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			out[rel] = "<absent>"
		} else {
			out[rel] = string(b)
		}
	}
	return out
}

func TestDeviceMergeRollbackOnInjectedFailure(t *testing.T) {
	for _, step := range []string{"device_names", "app_limits", "conn_blocks", "limit_policies", "mac_aliases"} {
		t.Run(step, func(t *testing.T) {
			dir, s, ops := mmFixture(t)
			before := mmSnapshot(t, dir)
			rulesBefore := mmRead(t, dir, "data/rules.json")
			macMergeFailStep = step
			r := dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew}, false)
			if r.OK || r.Error != "merge failed" || !strings.Contains(r.Detail, step) {
				t.Fatalf("want failure at %s, got %+v", step, r)
			}
			if after := mmSnapshot(t, dir); !reflect.DeepEqual(before, after) {
				for k := range before {
					if before[k] != after[k] {
						t.Errorf("%s not restored:\n before=%s\n after =%s", k, before[k], after[k])
					}
				}
			}
			// 规则: 新 MAC 上做过的动作全部逆向撤销, 旧 MAC 一个都没动
			if rulesAfter := mmRead(t, dir, "data/rules.json"); !reflect.DeepEqual(rulesBefore, rulesAfter) {
				t.Errorf("rules.json not restored:\n before=%v\n after =%v", rulesBefore, rulesAfter)
			}
			for _, c := range ops.calls {
				if strings.HasSuffix(c, mmOld) {
					t.Errorf("old mac touched during failed merge: %v", ops.calls)
				}
			}
			s.limitCtl.mu.Lock()
			_, hasNew := s.limitCtl.policies[mmNew]
			_, hasOld := s.limitCtl.policies[mmOld]
			s.limitCtl.mu.Unlock()
			if hasNew || !hasOld {
				t.Errorf("limit policies in memory not restored: new=%v old=%v", hasNew, hasOld)
			}
			if al := loadMACAliases(dir); len(al) != 0 {
				t.Errorf("aliases after rollback = %v", al)
			}
		})
	}
}

func TestDeviceMergeRollbackOnRuleFailure(t *testing.T) {
	dir, s, ops := mmFixture(t)
	rulesBefore := mmRead(t, dir, "data/rules.json")
	ops.failOn["delay_set "+mmNew] = true // bl_add、rule_set 已成功, delay_set 失败
	r := dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew}, false)
	if r.OK || !strings.Contains(r.Detail, "rules") {
		t.Fatalf("want rules failure, got %+v", r)
	}
	if rulesAfter := mmRead(t, dir, "data/rules.json"); !reflect.DeepEqual(rulesBefore, rulesAfter) {
		t.Errorf("rules.json not restored:\n before=%v\n after =%v\n calls=%v", rulesBefore, rulesAfter, ops.calls)
	}
	joined := strings.Join(ops.calls, ",")
	for _, want := range []string{"rule_clear " + mmNew, "bl_del " + mmNew, "rules_device_remove " + mmNew} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing undo %q: %v", want, ops.calls)
		}
	}
}

// ─── 拒绝 / 冲突 ───────────────────────────────────────────────────────

func TestDeviceMergeRefusals(t *testing.T) {
	_, s, ops := mmFixture(t)
	for _, c := range []struct {
		p    map[string]string
		code string
	}{
		{map[string]string{"from_mac": mmOld, "to_mac": mmOld}, "bad params"},
		{map[string]string{"from_mac": mmSim, "to_mac": mmNew}, "bad params"},
		{map[string]string{"from_mac": mmOld, "to_mac": mmSim}, "bad params"},
		{map[string]string{"from_mac": "zz", "to_mac": mmNew}, "bad params"},
		{map[string]string{"from_mac": mmOld, "to_mac": mmNew, "force": "maybe"}, "bad params"},
		{map[string]string{"from_mac": mmOld, "to_mac": "ff:ff:ff:ff:ff:ff"}, "protected mac"},
	} {
		r := dispatchAction(s, "device_merge", c.p, false)
		if r.OK || r.Error != c.code {
			t.Errorf("%v: got %+v want %s", c.p, r, c.code)
		}
	}
	if len(ops.calls) != 0 {
		t.Errorf("refused merges must not touch rules: %v", ops.calls)
	}
}

func TestDeviceMergeOfflineTargetRefused(t *testing.T) {
	dir, s, ops := mmFixture(t)
	mmWrite(t, dir, "data/devices.json", map[string]interface{}{})
	r := dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew}, false)
	if r.OK || r.Error != "device offline" || len(ops.calls) != 0 {
		t.Fatalf("got %+v calls=%v", r, ops.calls)
	}
}

func TestDeviceMergeConflictAndForce(t *testing.T) {
	dir, s, _ := mmFixture(t)
	// 新 MAC 已有自己的名字和不同限速
	names := mmRead(t, dir, "data/device_names.json")
	names[mmNew] = "新手机"
	mmWrite(t, dir, "data/device_names.json", names)
	rules := mmRead(t, dir, "data/rules.json")
	rules["devices"].(map[string]interface{})[mmNew] = map[string]interface{}{"mark_id": 12, "down_mbps": 20,
		"up_mbps": 10, "limit_enabled": true}
	mmWrite(t, dir, "data/rules.json", rules)

	r := dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew}, false)
	if r.OK || r.Error != "conflict" || !strings.Contains(r.Detail, "限速") || !strings.Contains(r.Detail, "名称") {
		t.Fatalf("want conflict, got %+v", r)
	}
	r = dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew, "force": "true"}, false)
	if !r.OK {
		t.Fatalf("force merge failed: %+v", r)
	}
	// force: 旧设备设置为准
	if n := mmRead(t, dir, "data/device_names.json"); n[mmNew] != "小明的手机" {
		t.Errorf("force: name = %v", n[mmNew])
	}
	nd := mmRead(t, dir, "data/rules.json")["devices"].(map[string]interface{})[mmNew].(map[string]interface{})
	if nd["down_mbps"] != 5.0 || nd["up_mbps"] != 2.0 || nd["mark_id"] != 12.0 {
		t.Errorf("force: new rules = %v", nd)
	}
}

func TestDeviceMergeConflictHTTPStatus(t *testing.T) {
	dir, s, _ := mmFixture(t)
	names := mmRead(t, dir, "data/device_names.json")
	names[mmNew] = "别的名字"
	mmWrite(t, dir, "data/device_names.json", names)
	body := `{"action":"device_merge","params":{"from_mac":"` + mmOld + `","to_mac":"` + mmNew + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/action", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HNC-CSRF", "1")
	req.RemoteAddr = "127.0.0.1:5555"
	w := httptest.NewRecorder()
	s.handleAction(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

// ─── 建议: tick / 告警 / 忽略 / API ─────────────────────────────────────

func TestMacMergeSuggestAlertDismiss(t *testing.T) {
	dir := t.TempDir()
	s := newServer(dir)
	now := time.Unix(1_790_000_000, 0)
	// 首轮: 旧设备在线 → 只登记, 不建议
	s.macMergeStep(now, map[string]*macObs{
		mmOld: {inDevices: true, lastSeen: now.Unix(), dhcpName: "Xiaoming-Mi-10", dhcpFP: "1,3,6,15", model: "Mi 10",
			apps: []string{"bilibili", "douyin", "weixin"}},
	})
	f := loadMacMergeFile(dir)
	if !f.Bootstrapped || f.Profiles[mmOld] == nil || f.Profiles[mmOld].New || len(f.Suggestions) != 0 {
		t.Fatalf("bootstrap state: %+v", f)
	}
	// 旧 MAC 离线, 5 分钟后新随机 MAC 出现, 同主机名 + 同指纹
	t2 := now.Add(5 * time.Minute)
	obs := map[string]*macObs{
		mmNew: {inDevices: true, lastSeen: t2.Unix(), dhcpName: "Xiaoming-Mi-10", dhcpFP: "1,3,6,15"},
		mmOld: {lastSeen: now.Unix(), dhcpName: "Xiaoming-Mi-10"}, // 仅 dpid 历史
	}
	s.macMergeStep(t2, obs)
	f = loadMacMergeFile(dir)
	cs := f.Suggestions[mmNew]
	if len(cs) != 1 || cs[0].OldMAC != mmOld || cs[0].Score < macMergeAlertScore {
		t.Fatalf("suggestions = %+v", f.Suggestions)
	}
	s.macMergeStep(t2.Add(30*time.Second), obs) // 再一轮: 不重复告警
	b, _ := os.ReadFile(filepath.Join(dir, "run", "alerts.jsonl"))
	if n := strings.Count(string(b), `"kind":"mac_merge_suggest"`); n != 1 {
		t.Errorf("alerts = %d, want 1: %s", n, b)
	}
	// API
	rec := httptest.NewRecorder()
	s.apiMacMerge(rec, httptest.NewRequest(http.MethodGet, "/api/mac_merge", nil))
	var resp struct {
		Suggestions []map[string]interface{} `json:"suggestions"`
		Aliases     map[string]string        `json:"aliases"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Suggestions) != 1 || resp.Suggestions[0]["new_mac"] != mmNew || resp.Suggestions[0]["old_mac"] != mmOld ||
		resp.Suggestions[0]["randomized"] != true || resp.Suggestions[0]["old_name"] != "Xiaoming-Mi-10" ||
		resp.Suggestions[0]["old_last_seen"].(float64) != float64(now.Unix()) || resp.Aliases == nil {
		t.Errorf("api = %s", rec.Body.String())
	}
	// /api/devices 标注
	rows := []map[string]interface{}{{"mac": mmNew}, {"mac": mmOld}, {"mac": mmSim, "sim": true}}
	s.annotateMacMerge(rows, map[string]interface{}{})
	if rows[0]["randomized_mac"] != true || rows[0]["merge_suggestion"] == nil || rows[1]["randomized_mac"] != false ||
		rows[2]["randomized_mac"] != false {
		t.Errorf("annotate = %v", rows)
	}
	// 忽略: 建议消失, 后续 tick 也不再出现
	if r := actionDeviceMergeDismiss(s, map[string]string{"from_mac": mmOld, "to_mac": mmNew}); !r.OK {
		t.Fatal(r)
	}
	s.macMergeStep(t2.Add(time.Minute), obs)
	if f := loadMacMergeFile(dir); len(f.Suggestions[mmNew]) != 0 {
		t.Errorf("dismissed suggestion came back: %+v", f.Suggestions)
	}
}

func TestMacMergeNoSuggestionWhenOverlapping(t *testing.T) {
	dir := t.TempDir()
	s := newServer(dir)
	now := time.Unix(1_790_000_000, 0)
	s.macMergeStep(now, map[string]*macObs{mmOld: {inDevices: true, lastSeen: now.Unix(), dhcpName: "Pad-Pro"}})
	t2 := now.Add(time.Minute)
	// 新 MAC 出现后旧 MAC 仍在线 10 分钟 = 两台设备
	s.macMergeStep(t2.Add(10*time.Minute), map[string]*macObs{
		mmNew: {inDevices: true, lastSeen: t2.Unix(), dhcpName: "Pad-Pro"},
		mmOld: {inDevices: true, lastSeen: t2.Add(10 * time.Minute).Unix(), dhcpName: "Pad-Pro"},
	})
	if f := loadMacMergeFile(dir); len(f.Suggestions) != 0 {
		t.Errorf("overlapping devices suggested: %+v", f.Suggestions)
	}
}

func TestCollectMacObs(t *testing.T) {
	dir := t.TempDir()
	mmWrite(t, dir, "data/devices.json", map[string]interface{}{
		mmNew: map[string]interface{}{"ip": "10.0.0.2", "hostname": "Mi-10", "hostname_src": "dhcp", "last_seen": 100},
		mmSim: map[string]interface{}{"ip": "10.0.0.9", "hostname": "sim", "hostname_src": "dhcp", "last_seen": 100},
	})
	mmWrite(t, dir, "run/dpi_devid.json", map[string]interface{}{"schema": 1, "devices": map[string]interface{}{
		mmNew: map[string]interface{}{"hostname": "mi10.local", "hostname_src": "mdns", "dhcp_fp": "1,3,6",
			"vendor_class": "android-dhcp-13", "type": "phone", "brand": "Xiaomi", "model": "", "os": "Android", "last_seen": 90},
	}})
	mmWrite(t, dir, "data/device_ident_override.json", map[string]interface{}{mmNew: map[string]interface{}{"model": "Mi 10"}})
	mmWrite(t, dir, "run/dpi_state.json", map[string]interface{}{"clients": map[string]interface{}{
		"10.0.0.2": map[string]interface{}{"client_mac": strings.ToUpper(mmNew),
			"top_ja4":  []interface{}{map[string]interface{}{"ja4": "t13d_a"}, map[string]interface{}{"ja4": "t13d_b"}},
			"top_apps": []interface{}{map[string]interface{}{"id": "weixin", "category": "social"}, map[string]interface{}{"id": "umeng", "category": "sdk-analytics"}}},
	}})
	day := &appUsageDay{Hours: map[string]map[string][2]uint64{"9": {mmNew + "|douyin": {1, 2}, mmNew + "|_unknown": {1, 1}}},
		Apps: map[string]appUsageMeta{"douyin": {Name: "抖音", Category: "video"}}}
	obs := collectMacObs(dir, day)
	o := obs[mmNew]
	if o == nil || obs[mmSim] != nil {
		t.Fatalf("obs = %+v", obs)
	}
	if !o.inDevices || o.lastSeen != 100 || o.dhcpName != "Mi-10" || o.mdnsName != "mi10.local" || o.dhcpFP != "1,3,6" ||
		o.vendorClass != "android-dhcp-13" || o.model != "Mi 10" || o.brand != "Xiaomi" ||
		!reflect.DeepEqual(o.ja4, []string{"t13d_a", "t13d_b"}) || !reflect.DeepEqual(o.apps, []string{"douyin", "weixin"}) {
		t.Errorf("obs = %+v", o)
	}
}

// ─── 别名聚合 ──────────────────────────────────────────────────────────

func TestMACAliasChainAndResolve(t *testing.T) {
	m := map[string]string{}
	addMACAlias(m, "aa:00:00:00:00:01", "aa:00:00:00:00:02")
	addMACAlias(m, "aa:00:00:00:00:02", "aa:00:00:00:00:03")
	if m["aa:00:00:00:00:01"] != "aa:00:00:00:00:03" || m["aa:00:00:00:00:02"] != "aa:00:00:00:00:03" {
		t.Errorf("chain not flattened: %v", m)
	}
	addMACAlias(m, "aa:00:00:00:00:03", "aa:00:00:00:00:01") // 反向合并不成环
	for i := 1; i <= 3; i++ {
		if got := resolveMACAlias(m, "aa:00:00:00:00:0"+strconv.Itoa(i)); got != "aa:00:00:00:00:01" {
			t.Errorf("resolve %d = %s (%v)", i, got, m)
		}
	}
}

func TestAliasAggregationInUsageReads(t *testing.T) {
	dir := t.TempDir()
	s := newServer(dir)
	now := time.Now()
	ts := now.Add(-time.Minute).Unix()
	if localDayStart(now).Unix() > ts {
		ts = localDayStart(now).Unix() + 1
	}
	uk := time.Unix(ts, 0).UTC().Format("20060102")
	var lines []string
	for _, r := range []struct {
		mac    string
		tx, rx int
	}{{mmOld, 100, 1000}, {mmNew, 10, 200}, {"11:22:33:44:55:66", 1, 1}} {
		lines = append(lines, `{"t":`+strconv.FormatInt(ts, 10)+`,"mac":"`+r.mac+`","app_id":"douyin","app":"抖音","tx":`+
			strconv.Itoa(r.tx)+`,"rx":`+strconv.Itoa(r.rx)+`}`)
	}
	mmWrite(t, dir, "run/stats."+uk+".jsonl", strings.Join(lines, "\n")+"\n")
	today := now.Format("20060102")
	mmWrite(t, dir, "run/online_hours.jsonl",
		`{"t":1,"day":"`+today+`","mac":"`+mmOld+`"}`+"\n"+`{"t":2,"day":"`+today+`","mac":"`+mmOld+`"}`+"\n"+
			`{"t":3,"day":"`+today+`","mac":"`+mmNew+`"}`+"\n")
	mmWrite(t, dir, "run/app_usage."+today+".json", appUsageDay{Date: today,
		Hours:  map[string]map[string][2]uint64{"10": {mmOld + "|douyin": {5, 50}, mmNew + "|douyin": {1, 10}}},
		Apps:   map[string]appUsageMeta{"douyin": {Name: "抖音", Category: "video"}},
		Active: map[string]map[string]uint32{"10": {mmOld + "|douyin": 600, mmNew + "|douyin": 60}}})
	appUsage.mu.Lock()
	savedDay := appUsage.day
	appUsage.day = nil
	appUsage.mu.Unlock()
	t.Cleanup(func() { appUsage.mu.Lock(); appUsage.day = savedDay; appUsage.mu.Unlock() })

	if err := saveMACAliases(dir, map[string]string{mmOld: mmNew}); err != nil {
		t.Fatal(err)
	}
	get := func(h http.HandlerFunc, url string) map[string]interface{} {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, url, nil))
		var m map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("%s: %v %s", url, err, rec.Body.String())
		}
		return m
	}
	// /api/usage_month
	usageCache.mu.Lock()
	usageCache.out = nil
	usageCache.mu.Unlock()
	um := get(s.apiUsageMonth, "/api/usage_month")["devices"].(map[string]interface{})
	if d := um[mmNew].(map[string]interface{}); d["rx"] != 1200.0 || d["tx"] != 110.0 || um[mmOld] != nil {
		t.Errorf("usage_month = %v", um)
	}
	usageCache.mu.Lock()
	usageCache.out = nil
	usageCache.mu.Unlock()
	// /api/online_hours
	oh := get(s.apiOnlineHours, "/api/online_hours")["hours"].(map[string]interface{})
	if d := oh[mmNew].(map[string]interface{}); d[today] != 3.0 || oh[mmOld] != nil {
		t.Errorf("online_hours = %v", oh)
	}
	// /api/app_usage?mac=new(及用旧 MAC 查也归到新 MAC)
	for _, q := range []string{mmNew, mmOld} {
		au := get(s.apiAppUsage, "/api/app_usage?days=1&mac="+q)
		if au["total_down"] != 60.0 || au["total_up"] != 6.0 {
			t.Errorf("app_usage mac=%s = %v/%v", q, au["total_up"], au["total_down"])
		}
	}
	au := get(s.apiAppUsage, "/api/app_usage?days=1")
	if devs := au["by_device"].([]interface{}); len(devs) != 1 || devs[0].(map[string]interface{})["mac"] != mmNew {
		t.Errorf("app_usage by_device = %v", devs)
	}
	// /api/app_time?mac=new
	at := get(s.apiAppTime, "/api/app_time?days=1&mac="+mmNew)
	if at["total_active_sec"] != 660.0 {
		t.Errorf("app_time total = %v", at["total_active_sec"])
	}
	// /api/dpi_history?mac=new
	dh := get(s.apiDPIHistory, "/api/dpi_history?days=1&mac="+mmNew)
	if dh["total_rx"] != 1200.0 || dh["total_tx"] != 110.0 {
		t.Errorf("dpi_history = rx %v tx %v", dh["total_rx"], dh["total_tx"])
	}
	// 配额历史下限
	h := sumStatsHistory(dir, localDayStart(now), now.Add(time.Second))
	if h[mmNew] != 1310 || h[mmOld] != 0 {
		t.Errorf("sumStatsHistory = %v", h)
	}
	// 时长上限今日用量
	if u := aliasUsedKeys(dir, map[string]int{mmOld + "|douyin": 600, mmNew + "|douyin": 60}); u[mmNew+"|douyin"] != 660 || len(u) != 1 {
		t.Errorf("aliasUsedKeys = %v", u)
	}
}

// TestDeviceMergeMigratesAppQos v5.32 T1: 设备合并要迁 app_qos(按应用分优先级)。
// v5.32 之前 ruleState 没这个字段, 旧设备开着 app_qos 合并后静默丢 —— 旧代码下
// 本测试在「新 MAC 的 rules.json 里找 app_qos」一步失败。
func TestDeviceMergeMigratesAppQos(t *testing.T) {
	dir, s, ops := mmFixture(t)
	// 在 fixture 之上只给旧设备加 app_qos(其余不动)
	root := mmRead(t, dir, "data/rules.json")
	od, _ := root["devices"].(map[string]interface{})[mmOld].(map[string]interface{})
	if od == nil {
		t.Fatal("fixture: old device entry missing")
	}
	od["app_qos"] = true
	// 审查修复: 按应用分优先级与延迟模拟互斥(两个真动作都拒绝另一项开着时开启),
	// fixture 的旧设备开着延迟 —— 「两项都开」是真机上到不了的状态, 这里关掉延迟。
	od["delay_enabled"], od["delay_ms"], od["jitter_ms"], od["loss_pct"] = false, 0, 0, 0
	mmWrite(t, dir, "data/rules.json", root)

	r := dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew}, false)
	if !r.OK {
		t.Fatalf("merge failed: %+v (calls=%v)", r, ops.calls)
	}
	rules := mmRead(t, dir, "data/rules.json")
	devs, _ := rules["devices"].(map[string]interface{})
	nd, _ := devs[mmNew].(map[string]interface{})
	if nd == nil {
		t.Fatalf("new mac has no rules entry")
	}
	if v, _ := nd["app_qos"].(bool); !v {
		t.Fatalf("app_qos 应迁移到新 MAC: %v", nd)
	}
	// 动作清单里要有下发与旧设备清理两条
	setNew, clearOld := false, false
	for _, c := range ops.calls {
		if c == "app_qos_set "+mmNew {
			setNew = true
		}
		if c == "app_qos_set "+mmOld {
			clearOld = true
		}
	}
	if !setNew || !clearOld {
		t.Errorf("app_qos_set 调用缺: 新 %v / 旧 %v (calls=%v)", setNew, clearOld, ops.calls)
	}
}

// mmSetDev 改 rules.json 里某台设备的若干键(测试辅助)。
func mmSetDev(t *testing.T, dir, mac string, kv map[string]interface{}) {
	t.Helper()
	root := mmRead(t, dir, "data/rules.json")
	devs, _ := root["devices"].(map[string]interface{})
	d, _ := devs[mac].(map[string]interface{})
	if d == nil {
		d = map[string]interface{}{"mark_id": 12}
		devs[mac] = d
	}
	for k, v := range kv {
		d[k] = v
	}
	mmWrite(t, dir, "data/rules.json", root)
}

// TestDeviceMergeAppQosVsDelay v5.32 审查修复: 按应用分优先级与延迟模拟互斥。
// 旧设备开着一项、新 MAC 开着另一项时, 原实现照样去开 —— 真动作拒绝(conflict),
// 整个合并回滚成「merge failed」, 带 force 也合并不了。现在先报冲突;
// force 时以旧设备为准: 先关掉新 MAC 上互斥的那一项再迁。
func TestDeviceMergeAppQosVsDelay(t *testing.T) {
	noDelay := map[string]interface{}{"delay_enabled": false, "delay_ms": 0, "jitter_ms": 0, "loss_pct": 0}
	newDev := func(t *testing.T, dir string) map[string]interface{} {
		d, _ := mmRead(t, dir, "data/rules.json")["devices"].(map[string]interface{})[mmNew].(map[string]interface{})
		if d == nil {
			t.Fatal("new mac has no rules entry")
		}
		return d
	}
	delayOn := func(d map[string]interface{}) bool {
		return truthy(d["delay_enabled"]) || numOf(d["delay_ms"]) > 0
	}

	t.Run("旧 app_qos / 新 延迟", func(t *testing.T) {
		dir, s, _ := mmFixture(t)
		mmSetDev(t, dir, mmOld, noDelay)
		mmSetDev(t, dir, mmOld, map[string]interface{}{"app_qos": true})
		mmSetDev(t, dir, mmNew, map[string]interface{}{"delay_enabled": true, "delay_ms": 50, "jitter_ms": 0, "loss_pct": 0})
		r := dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew}, false)
		if r.OK || r.Error != "conflict" || !strings.Contains(r.Detail, "按应用分优先级") {
			t.Fatalf("应先报冲突, got %+v", r)
		}
		r = dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew, "force": "true"}, false)
		if !r.OK {
			t.Fatalf("force 合并应成功(以旧设备为准), got %+v", r)
		}
		if d := newDev(t, dir); !truthy(d["app_qos"]) || delayOn(d) {
			t.Fatalf("force 后新 MAC 应 app_qos 开、延迟关: %v", d)
		}
	})
	t.Run("旧 延迟 / 新 app_qos", func(t *testing.T) {
		dir, s, _ := mmFixture(t)
		mmSetDev(t, dir, mmNew, map[string]interface{}{"app_qos": true})
		r := dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew}, false)
		if r.OK || r.Error != "conflict" || !strings.Contains(r.Detail, "按应用分优先级") {
			t.Fatalf("应先报冲突, got %+v", r)
		}
		r = dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew, "force": "true"}, false)
		if !r.OK {
			t.Fatalf("force 合并应成功(以旧设备为准), got %+v", r)
		}
		if d := newDev(t, dir); truthy(d["app_qos"]) || numOf(d["delay_ms"]) != 80 {
			t.Fatalf("force 后新 MAC 应延迟 80ms、app_qos 关: %v", d)
		}
	})
	t.Run("force 失败回滚: 新 MAC 的延迟恢复", func(t *testing.T) {
		dir, s, ops := mmFixture(t)
		mmSetDev(t, dir, mmOld, noDelay)
		mmSetDev(t, dir, mmOld, map[string]interface{}{"app_qos": true})
		mmSetDev(t, dir, mmNew, map[string]interface{}{"delay_enabled": true, "delay_ms": 50, "jitter_ms": 0, "loss_pct": 0})
		ops.failOn["app_qos_set "+mmNew] = true
		r := dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew, "force": "true"}, false)
		if r.OK {
			t.Fatalf("注入失败后合并应失败")
		}
		if d := newDev(t, dir); numOf(d["delay_ms"]) != 50 {
			t.Fatalf("回滚后新 MAC 的延迟应恢复 50ms: %v", d)
		}
	})
}

// ─── RC2: 双胞胎 MUTEX_APART + 无损秒拆(手动在线/离线、旧别名、重连自动) + 容量裁剪 + action 加固 ───

func TestMutexApartTwinConcurrentTrafficAndFullChainBlock(t *testing.T) {
	dir, s, _ := mmFixture(t)
	now := time.Unix(1_791_000_000, 0)
	twinOld := "da:a1:19:00:11:01"
	twinNew := "da:a1:19:00:22:02"

	// t0: 双胞胎设备同时在线且有 IP, 建立流量采样基线
	mmWrite(t, dir, "data/devices.json", map[string]interface{}{
		twinOld: map[string]interface{}{
			"ip": "192.168.43.11", "mac": twinOld, "hostname": "Family-iPhone", "hostname_src": "dhcp",
			"rx_bytes": 1000, "tx_bytes": 500, "last_seen": now.Unix(),
		},
		twinNew: map[string]interface{}{
			"ip": "192.168.43.12", "mac": twinNew, "hostname": "Family-iPhone", "hostname_src": "dhcp",
			"rx_bytes": 2000, "tx_bytes": 800, "last_seen": now.Unix(),
		},
	})
	s.macMergeStep(now, collectMacObs(dir, nil))
	if f0 := loadMacMergeFile(dir); isMacMutexApart(f0, twinOld, twinNew, now.Unix()) {
		t.Fatalf("首轮仅建基线不应写入 MutexApart: %+v", f0.MutexApart)
	}

	// t0+60s (180s 窗口内): 双方各自产生 >= 512 字节真实正增长 → 写入规范键 MutexApart
	t1 := now.Add(60 * time.Second)
	mmWrite(t, dir, "data/devices.json", map[string]interface{}{
		twinOld: map[string]interface{}{
			"ip": "192.168.43.11", "mac": twinOld, "hostname": "Family-iPhone", "hostname_src": "dhcp",
			"rx_bytes": 1400, "tx_bytes": 700, "last_seen": t1.Unix(), // +600 >= 512
		},
		twinNew: map[string]interface{}{
			"ip": "192.168.43.12", "mac": twinNew, "hostname": "Family-iPhone", "hostname_src": "dhcp",
			"rx_bytes": 2500, "tx_bytes": 1000, "last_seen": t1.Unix(), // +700 >= 512
		},
	})
	s.macMergeStep(t1, collectMacObs(dir, nil))

	f1 := loadMacMergeFile(dir)
	canonKey := twinOld + "|" + twinNew
	if f1.MutexApart[canonKey] != t1.Unix() {
		t.Fatalf("want canonical MutexApart[%q]=%d, got %+v", canonKey, t1.Unix(), f1.MutexApart)
	}

	// 即使后续 twinOld 离线、画像时间调整为不重叠且预塞高分建议, 全链路仍拦截 MutexApart
	t2 := t1.Add(10 * time.Minute)
	macMergeMu.Lock()
	f2 := loadMacMergeFile(dir)
	f2.Profiles[twinOld] = &macProfile{FirstSeen: now.Unix() - 3600, LastSeen: now.Unix() - 300, DHCPName: "Unique-Twin-Phone", DHCPFP: "1,3,6,15", Model: "Mi 14"}
	f2.Profiles[twinNew] = &macProfile{FirstSeen: now.Unix(), LastSeen: t2.Unix(), DHCPName: "Unique-Twin-Phone", DHCPFP: "1,3,6,15", Model: "Mi 14", New: true}
	f2.Suggestions[twinNew] = []macMergeCand{{OldMAC: twinOld, Score: 96, Reasons: []string{"test"}, Ts: t2.Unix()}}
	_ = saveMacMergeFile(dir, f2)
	macMergeMu.Unlock()

	// 1) macMergeCandidates 拦截
	if cands := macMergeCandidates(loadMacMergeFile(dir), twinNew, nil, t2.Unix()); len(cands) != 0 {
		t.Fatalf("macMergeCandidates should block MutexApart pair, got %+v", cands)
	}

	// 2) apiMacMerge 拦截并返回 mutex_apart_count
	rec := httptest.NewRecorder()
	s.apiMacMerge(rec, httptest.NewRequest(http.MethodGet, "/api/mac_merge", nil))
	var apiResp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &apiResp); err != nil {
		t.Fatal(err)
	}
	if gotCnt := int(numOf(apiResp["mutex_apart_count"])); gotCnt != 1 {
		t.Fatalf("want mutex_apart_count=1, got %v (%s)", apiResp["mutex_apart_count"], rec.Body.String())
	}
	if sg, _ := apiResp["suggestions"].([]interface{}); len(sg) != 0 {
		t.Fatalf("apiMacMerge leaked MutexApart suggestion: %v", sg)
	}

	// 3) annotateMacMerge 拦截
	rows := []map[string]interface{}{{"mac": twinNew}}
	s.annotateMacMerge(rows, map[string]interface{}{})
	if rows[0]["merge_suggestion"] != nil {
		t.Fatalf("annotateMacMerge leaked MutexApart suggestion: %+v", rows[0])
	}

	// 4) rmacReconcile 拦截自动继承(twinOld 离线、twinNew 在线且预塞 96 分建议)
	mmWrite(t, dir, "data/devices.json", map[string]interface{}{
		twinNew: map[string]interface{}{"ip": "192.168.43.12", "mac": twinNew, "rx_bytes": 3000, "tx_bytes": 1200, "last_seen": t2.Unix()},
	})
	_ = saveRMACPolicy(dir, rmacPolicy{AutoInherit: true, AutoInheritScore: 85, EphemeralGCMinutes: 30})
	s.rmacReconcile(t2)
	if al := loadMACAliases(dir); al[twinOld] != "" {
		t.Fatalf("rmacReconcile must not auto-inherit MutexApart pair, got aliases=%v", al)
	}

	// 5) macMergePruneLocked 清除预塞建议
	macMergeMu.Lock()
	fp := loadMacMergeFile(dir)
	s.macMergePruneLocked(fp, t2.Unix(), nil)
	_ = saveMacMergeFile(dir, fp)
	macMergeMu.Unlock()
	if len(loadMacMergeFile(dir).Suggestions) != 0 {
		t.Fatalf("macMergePruneLocked did not prune MutexApart suggestion")
	}

	// 6) deviceMerge 非 force 返回 HTTP 409 conflict
	body := `{"action":"device_merge","params":{"from_mac":"` + twinOld + `","to_mac":"` + twinNew + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/action", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HNC-CSRF", "1")
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.handleAction(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 conflict on MutexApart device_merge without force, got status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMutexApartStaleLeaseZeroTrafficNotLocked(t *testing.T) {
	dir := t.TempDir()
	s := newServer(dir)
	now := time.Unix(1_791_100_000, 0)

	// t0: 旧 MAC 在线建基线
	mmWrite(t, dir, "data/devices.json", map[string]interface{}{
		mmOld: map[string]interface{}{"ip": "192.168.43.20", "mac": mmOld, "rx_bytes": 50000, "tx_bytes": 20000, "last_seen": now.Unix()},
	})
	s.macMergeStep(now, collectMacObs(dir, nil))

	// t0+30s: 同一部手机刚切换新随机 MAC, 旧租约仍留在 devices.json 90s 内但流量不再增长(或不足 512B); 新 MAC 刚建基线
	t1 := now.Add(30 * time.Second)
	mmWrite(t, dir, "data/devices.json", map[string]interface{}{
		mmOld: map[string]interface{}{"ip": "192.168.43.20", "mac": mmOld, "rx_bytes": 50100, "tx_bytes": 20000, "last_seen": now.Unix()}, // +100 < 512
		mmNew: map[string]interface{}{"ip": "192.168.43.21", "mac": mmNew, "rx_bytes": 1000, "tx_bytes": 500, "last_seen": t1.Unix()},
	})
	s.macMergeStep(t1, collectMacObs(dir, nil))

	// t0+60s: 新 MAC 大幅走流(+20KB >= 512B), 旧租约依然静默残留(+0B)
	t2 := now.Add(60 * time.Second)
	mmWrite(t, dir, "data/devices.json", map[string]interface{}{
		mmOld: map[string]interface{}{"ip": "192.168.43.20", "mac": mmOld, "rx_bytes": 50100, "tx_bytes": 20000, "last_seen": now.Unix()},
		mmNew: map[string]interface{}{"ip": "192.168.43.21", "mac": mmNew, "rx_bytes": 16000, "tx_bytes": 5500, "last_seen": t2.Unix()},
	})
	s.macMergeStep(t2, collectMacObs(dir, nil))

	if f := loadMacMergeFile(dir); len(f.MutexApart) != 0 {
		t.Fatalf("90s stale lease without >=512B growth must NOT trigger MutexApart, got %+v", f.MutexApart)
	}
}

func TestMutexApartAndLongRunCapacityPruning(t *testing.T) {
	dir := t.TempDir()
	s := newServer(dir)
	nowU := int64(1_792_000_000)

	// 1) MutexApart: 512 上限 + 90 天 TTL
	mf := loadMacMergeFile(dir)
	mf.MutexApart[macMutexApartKey("aa:bb:cc:00:00:01", "aa:bb:cc:99:99:99")] = nowU - macMergeMutexApartTTL - 10 // 过期
	for i := 1; i <= 540; i++ {
		m1 := fmt.Sprintf("02:11:22:33:%02x:%02x", (i>>8)&0xff, i&0xff)
		m2 := fmt.Sprintf("fe:11:22:33:%02x:%02x", (i>>8)&0xff, i&0xff)
		mf.MutexApart[macMutexApartKey(m1, m2)] = nowU - int64(1000-i)
	}
	s.macMergePruneLocked(mf, nowU, nil)
	if len(mf.MutexApart) != macMergeMaxMutexApart {
		t.Fatalf("want MutexApart capped at %d, got %d", macMergeMaxMutexApart, len(mf.MutexApart))
	}
	if isMacMutexApart(mf, "aa:bb:cc:00:00:01", "aa:bb:cc:99:99:99", nowU) {
		t.Fatalf("expired MutexApart entry not pruned")
	}
	if !isMacMutexApart(mf, "02:11:22:33:02:1c", "fe:11:22:33:02:1c", nowU) { // i=540 最新条目应保留
		t.Fatalf("newest MutexApart entry unexpectedly evicted")
	}

	// 2) mac_merge_archives.json: 64 上限 + 90 天 TTL
	upsertMacMergeArchive(dir, &macMergeArchive{
		FromMAC: "02:aa:00:00:00:01", ToMAC: "02:bb:00:00:00:01", MergedAt: nowU - macMergeArchiveTTL - 5,
	}, nowU)
	for i := 1; i <= 70; i++ {
		upsertMacMergeArchive(dir, &macMergeArchive{
			FromMAC:  fmt.Sprintf("02:aa:11:00:%02x:%02x", (i>>8)&0xff, i&0xff),
			ToMAC:    fmt.Sprintf("02:bb:11:00:%02x:%02x", (i>>8)&0xff, i&0xff),
			MergedAt: nowU - int64(100-i),
		}, nowU)
	}
	macArchiveMu.Lock()
	archF := loadMacMergeArchivesUnlocked(dir, nowU)
	macArchiveMu.Unlock()
	if len(archF.Archives) != macMergeArchiveMax {
		t.Fatalf("want archives capped at %d, got %d", macMergeArchiveMax, len(archF.Archives))
	}
	if findArchiveInSlice(archF.Archives, "02:aa:00:00:00:01", "") != nil {
		t.Fatalf("expired archive not pruned")
	}

	// 3) rmacStateFile.AutoInherited: 1024 上限 + 90 天 TTL
	st := rmacStateFile{Version: 2, AutoInherited: map[string]rmacAutoInheritRec{}}
	st.AutoInherited["da:00:99:00:00:01"] = rmacAutoInheritRec{OldMAC: "00:11:22:33:44:55", Score: 90, Ts: nowU - rmacAutoInheritedTTL - 1}
	for i := 1; i <= 1050; i++ {
		k := fmt.Sprintf("da:22:33:44:%02x:%02x", (i>>8)&0xff, i&0xff)
		st.AutoInherited[k] = rmacAutoInheritRec{OldMAC: "00:11:22:33:44:55", Score: 90, Ts: nowU - int64(2000-i)}
	}
	saveRMACStateAt(dir, st, nowU)
	stLoaded := loadRMACState(dir)
	if len(stLoaded.AutoInherited) != rmacAutoInheritedMax {
		t.Fatalf("want AutoInherited capped at %d, got %d", rmacAutoInheritedMax, len(stLoaded.AutoInherited))
	}
	if _, exists := stLoaded.AutoInherited["da:00:99:00:00:01"]; exists {
		t.Fatalf("expired AutoInherited entry not pruned")
	}

	// 4) mac_aliases.json: 1024 上限 + 90 天 TTL 且保持扁平映射返回
	alMap := map[string]string{"00:aa:99:00:00:01": "da:bb:99:00:00:01"}
	tsMap := map[string]int64{"00:aa:99:00:00:01": nowU - macAliasesTTL - 1}
	for i := 1; i <= 1050; i++ {
		oldM := fmt.Sprintf("02:cc:dd:ee:%02x:%02x", (i>>8)&0xff, i&0xff)
		newM := fmt.Sprintf("da:cc:dd:ee:%02x:%02x", (i>>8)&0xff, i&0xff)
		alMap[oldM] = newM
		tsMap[oldM] = nowU - int64(2000-i)
	}
	if err := saveMACAliasesAt(dir, alMap, nowU, tsMap); err != nil {
		t.Fatal(err)
	}
	loadedAl := loadMACAliases(dir)
	if len(loadedAl) != macAliasesMax {
		t.Fatalf("want mac_aliases capped at %d, got %d", macAliasesMax, len(loadedAl))
	}
	if _, exists := loadedAl["00:aa:99:00:00:01"]; exists {
		t.Fatalf("expired mac_alias entry not pruned")
	}
	for k := range loadedAl {
		if strings.HasPrefix(k, "@ts:") {
			t.Fatalf("metadata key leaked into loadMACAliases: %s", k)
		}
	}
}

func TestDeviceUnmergeOnlineAndOfflineRestoresAllStores(t *testing.T) {
	t.Run("offline_old_mac_restores_all_stores_and_deducts_transferred_usage", func(t *testing.T) {
		dir, s, ops := mmFixture(t)
		now := time.Now()
		day := now.Format("2006-01-02")

		// 给合并前的 to(mmNew) 也设置原有独立状态, 验证拆分后双方各自回到合并前快照
		names := mmRead(t, dir, "data/device_names.json")
		names[mmNew] = "平板原本的名字"
		mmWrite(t, dir, "data/device_names.json", names)

		mmSetDev(t, dir, mmNew, map[string]interface{}{
			"mark_id": 15, "down_mbps": 12, "up_mbps": 4, "limit_enabled": true,
			"delay_enabled": false, "sqm_enabled": false, "whitelist": false,
		})
		mmWrite(t, dir, "data/encdns.json", map[string]interface{}{
			"policy": "off",
			"devices": map[string]string{
				mmOld: "strict",
				mmNew: "dot",
			},
			"ts": now.Unix(),
		})
		s.limitCtl.mu.Lock()
		s.limitCtl.policies[mmNew] = &devicePolicy{Quota: &quotaPolicy{DailyGB: 10, Action: "block"}}
		_ = s.limitCtl.savePoliciesLocked()
		s.limitCtl.st.Devices[mmNew] = &ctlDevState{
			Adopted: true,
			Base:    limitRule{DownKbit: 12000, UpKbit: 4000, Blocked: false},
			Usage:   usageAcc{HavePrev: true, PrevRx: 100, PrevTx: 50, DayKey: day, DayBytes: 100 << 20, MonthKey: "m", MonthBytes: 200 << 20},
		}
		s.limitCtl.saveStateLocked(now, true)
		s.limitCtl.mu.Unlock()

		macMergeMu.Lock()
		mf := loadMacMergeFile(dir)
		mf.Bootstrapped = true
		mf.Profiles[mmOld] = &macProfile{FirstSeen: 10, LastSeen: 20, DHCPName: "Xiaoming-Mi-10", Apps: []string{"weixin"}}
		mf.Profiles[mmNew] = &macProfile{FirstSeen: 30, LastSeen: 40, DHCPName: "Guest-Pad", Apps: []string{"bilibili"}, New: true}
		_ = saveMacMergeFile(dir, mf)
		macMergeMu.Unlock()

		// 强制合并(以旧 MAC 为准)
		rMerge := dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew, "force": "true"}, false)
		if !rMerge.OK {
			t.Fatalf("force merge failed: %+v", rMerge)
		}

		// 模拟记录一条 AutoInherited, 验证拆分后一并清理
		saveRMACStateAt(dir, rmacStateFile{
			Version: 2,
			AutoInherited: map[string]rmacAutoInheritRec{
				mmNew: {OldMAC: mmOld, OldName: "小明的手机", Score: 92, Ts: now.Unix()},
			},
		}, now.Unix())

		// 验证 /api/mac_merge 返回 merged_list, 且 annotateMacMerge 标注 merged_from / merged_from_name
		rec := httptest.NewRecorder()
		s.apiMacMerge(rec, httptest.NewRequest(http.MethodGet, "/api/mac_merge", nil))
		var mmAPI map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &mmAPI); err != nil {
			t.Fatal(err)
		}
		ml, _ := mmAPI["merged_list"].([]interface{})
		if len(ml) != 1 {
			t.Fatalf("want merged_list len=1, got %v", mmAPI["merged_list"])
		}
		ml0 := ml[0].(map[string]interface{})
		if ml0["from_mac"] != mmOld || ml0["to_mac"] != mmNew || ml0["from_name"] != "小明的手机" || ml0["has_archive"] != true {
			t.Fatalf("unexpected merged_list[0]: %+v", ml0)
		}
		rows := []map[string]interface{}{{"mac": mmNew}}
		s.annotateMacMerge(rows, map[string]interface{}{})
		if rows[0]["merged_from"] != mmOld || rows[0]["merged_from_name"] != "小明的手机" {
			t.Fatalf("annotateMacMerge missing merged_from/merged_from_name: %+v", rows[0])
		}

		// 模拟合并期间 mmNew 自己又新增了 50MB 流量
		s.limitCtl.mu.Lock()
		s.limitCtl.st.Devices[mmNew].Usage.DayBytes += 50 << 20
		s.limitCtl.st.Devices[mmNew].Usage.MonthBytes += 50 << 20
		s.limitCtl.saveStateLocked(now, true)
		s.limitCtl.mu.Unlock()

		// 执行手动拆分(此时 mmOld 不在 devices.json 中 = 离线, mmNew 在线)
		ops.calls = nil
		rUnmerge := dispatchAction(s, "device_unmerge", map[string]string{"from_mac": mmOld, "to_mac": mmNew}, false)
		if !rUnmerge.OK {
			t.Fatalf("device_unmerge failed: %+v", rUnmerge)
		}

		// 离线旧 MAC 走了 persist_offline_rule, 在线新 MAC 走了 ops.rule
		joinedCalls := strings.Join(ops.calls, ",")
		if !strings.Contains(joinedCalls, "persist_offline_rule "+mmOld) {
			t.Errorf("expected offline mmOld to use persist_offline_rule, calls=%v", ops.calls)
		}
		if strings.Contains(joinedCalls, "persist_offline_rule "+mmNew) {
			t.Errorf("online mmNew should use ops.rule instead of persist_offline_rule, calls=%v", ops.calls)
		}

		// 1) rules.json 还原
		rules := mmRead(t, dir, "data/rules.json")
		devs := rules["devices"].(map[string]interface{})
		od := devs[mmOld].(map[string]interface{})
		nd := devs[mmNew].(map[string]interface{})
		if od["down_mbps"] != 5.0 || od["up_mbps"] != 2.0 || od["delay_ms"] != 80.0 || od["sqm_enabled"] != true || od["whitelist"] != true {
			t.Errorf("mmOld rules not restored: %+v", od)
		}
		if nd["down_mbps"] != 12.0 || nd["up_mbps"] != 4.0 || truthy(nd["delay_enabled"]) || truthy(nd["sqm_enabled"]) {
			t.Errorf("mmNew rules not restored to ToBefore: %+v", nd)
		}
		bl := rules["blacklist"].([]interface{})
		if len(bl) != 1 || bl[0] != mmOld {
			t.Errorf("blacklist not restored to [mmOld], got %v", bl)
		}

		// 2) 名称 / 识别纠正 / 应用限速 / 应用控制 / 封锁项 / encdns / 已知设备还原
		namesAfter := mmRead(t, dir, "data/device_names.json")
		if namesAfter[mmOld] != "小明的手机" || namesAfter[mmNew] != "平板原本的名字" {
			t.Errorf("device_names not restored: %v", namesAfter)
		}
		idsAfter := readIdentOverrides(dir)
		if idsAfter[mmOld]["model"] != "Mi 10" || idsAfter[mmNew] != nil {
			t.Errorf("ident_override not restored: %v", idsAfter)
		}
		alAfter := loadAppLimits(dir)
		if !hasAppLimitFor(alAfter, mmOld) || hasAppLimitFor(alAfter, mmNew) {
			t.Errorf("app_limits not restored: %+v", alAfter.Items)
		}
		acAfter := loadAppControls(dir)
		if !hasAppCtlFor(acAfter, mmOld) || hasAppCtlFor(acAfter, mmNew) {
			t.Errorf("app_controls not restored: %+v", acAfter)
		}
		cbAfter := readConnBlocks(dir)
		if !hasConnBlockFor(cbAfter, mmOld) || hasConnBlockFor(cbAfter, mmNew) {
			t.Errorf("conn_blocks not restored: %+v", cbAfter.Items)
		}
		encAfter := loadEncdns(dir)
		if encAfter.Devices[mmOld] != "strict" || encAfter.Devices[mmNew] != "dot" {
			t.Errorf("encdns not restored: %+v", encAfter.Devices)
		}
		_, _, newMarked := readKnownDeviceSnap(dir, mmNew)
		_, _, oldMarked := readKnownDeviceSnap(dir, mmOld)
		if oldMarked == 0 || newMarked != 0 {
			t.Errorf("known_devices not restored: oldMarked=%d newMarked=%d", oldMarked, newMarked)
		}

		// 3) 配额策略与 UsageTransferred 安全扣回验证(100MB + 50MB = 150MB, 扣回旧 MAC 的 3GB)
		s.limitCtl.mu.Lock()
		polOld := s.limitCtl.policies[mmOld]
		polNew := s.limitCtl.policies[mmNew]
		stOld := s.limitCtl.st.Devices[mmOld]
		stNew := s.limitCtl.st.Devices[mmNew]
		s.limitCtl.mu.Unlock()
		if polOld == nil || polOld.Quota == nil || polOld.Quota.DailyGB != 2 || polNew == nil || polNew.Quota == nil || polNew.Quota.DailyGB != 10 {
			t.Errorf("limit_policies not restored: old=%+v new=%+v", polOld, polNew)
		}
		if stOld == nil || stOld.Usage.DayBytes != 3<<30 || stOld.Base.DownKbit != 5000 {
			t.Errorf("mmOld ctl state not restored: %+v", stOld)
		}
		if stNew == nil || stNew.Usage.DayBytes != 150<<20 || stNew.Usage.MonthBytes != 250<<20 || stNew.Base.DownKbit != 12000 {
			t.Errorf("mmNew ctl usage/base not safely reverted: %+v", stNew)
		}

		// 4) 别名解绑、AutoInherited 清理、MutexApart 与双向 Dismissed 写入
		if al := loadMACAliases(dir); len(al) != 0 {
			t.Errorf("aliases should be empty after unmerge, got %v", al)
		}
		if len(loadRMACState(dir).AutoInherited) != 0 {
			t.Errorf("AutoInherited[to] should be cleared after unmerge")
		}
		mfAfter := loadMacMergeFile(dir)
		if !isMacMutexApart(mfAfter, mmOld, mmNew, now.Unix()) {
			t.Errorf("unmerge must write MutexApart")
		}
		if mfAfter.Dismissed[macMergeDismissKey(mmNew, mmOld)] == 0 || mfAfter.Dismissed[macMergeDismissKey(mmOld, mmNew)] == 0 {
			t.Errorf("unmerge must write bidirectional Dismissed: %+v", mfAfter.Dismissed)
		}
		if mfAfter.Profiles[mmOld] == nil || mfAfter.Profiles[mmNew] == nil || mfAfter.Profiles[mmNew].DHCPName != "Guest-Pad" {
			t.Errorf("profiles not restored cleanly: old=%+v new=%+v", mfAfter.Profiles[mmOld], mfAfter.Profiles[mmNew])
		}
	})

	t.Run("real_rulesStore_persistOfflineRule_roundtrip", func(t *testing.T) {
		dir := t.TempDir()
		mmWrite(t, dir, "data/rules.json", map[string]interface{}{
			"version": 1, "devices": map[string]interface{}{}, "blacklist": []interface{}{}, "whitelist": []interface{}{},
		})
		s := newServer(dir)
		ro := realMergeOps{s: s}
		want := ruleState{
			exists: true, limit: true, down: 8000, up: 2500,
			delay: true, delayMs: 45, jitterMs: 5, loss: "0.2",
			sqm: true, wl: true, bl: true, appQos: false,
		}
		if err := ro.persistOfflineRule(mmOld, want); err != nil {
			t.Fatalf("realMergeOps.persistOfflineRule failed: %v", err)
		}
		gotRS, err := readRuleStates(dir)
		if err != nil {
			t.Fatal(err)
		}
		got := gotRS[mmOld]
		if !got.limit || got.down != 8000 || got.up != 2500 || !got.delay || got.delayMs != 45 || !got.sqm || !got.wl || !got.bl {
			t.Fatalf("rulesStore offline persist mismatch: got=%+v want=%+v", got, want)
		}
	})

	t.Run("online_old_mac_uses_live_rule_ops", func(t *testing.T) {
		dir, s, ops := mmFixture(t)
		rMerge := dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew}, false)
		if !rMerge.OK {
			t.Fatalf("merge failed: %+v", rMerge)
		}
		// 让旧 MAC 重新在线有 IP 后手动拆分, 应走实时 ops.rule 挂载而非离线写回
		now := time.Now().Unix()
		mmWrite(t, dir, "data/devices.json", map[string]interface{}{
			mmOld: map[string]interface{}{"ip": "192.168.43.20", "mac": mmOld, "last_seen": now},
			mmNew: map[string]interface{}{"ip": "192.168.43.31", "mac": mmNew, "last_seen": now},
		})
		ops.calls = nil
		rUn := dispatchAction(s, "device_unmerge", map[string]string{"from_mac": mmOld, "to_mac": mmNew}, false)
		if !rUn.OK {
			t.Fatalf("online unmerge failed: %+v", rUn)
		}
		joined := strings.Join(ops.calls, ",")
		for _, wantOp := range []string{"bl_add " + mmOld, "rule_set " + mmOld, "delay_set " + mmOld, "rule_sqm " + mmOld, "device_whitelist_set " + mmOld} {
			if !strings.Contains(joined, wantOp) {
				t.Errorf("online unmerge missing live rule op %q in %v", wantOp, ops.calls)
			}
		}
		if strings.Contains(joined, "persist_offline_rule "+mmOld) {
			t.Errorf("online mmOld should not fall back to persist_offline_rule: %v", ops.calls)
		}
	})
}

func TestDeviceUnmergeLegacyAliasWithoutArchive(t *testing.T) {
	dir, s, _ := mmFixture(t)
	now := time.Now().Unix()

	// 模拟老版本遗留状态: 只有 mac_aliases.json 和 AutoInherited, 没有 mac_merge_archives.json
	if err := saveMACAliasesAt(dir, map[string]string{mmOld: mmNew}, now-3600, nil); err != nil {
		t.Fatal(err)
	}
	saveRMACStateAt(dir, rmacStateFile{
		Version: 2,
		AutoInherited: map[string]rmacAutoInheritRec{
			mmNew: {OldMAC: mmOld, OldName: "旧版手机", Score: 90, Ts: now - 3600},
		},
	}, now)
	names := mmRead(t, dir, "data/device_names.json")
	names[mmNew] = "保留的新手机名"
	mmWrite(t, dir, "data/device_names.json", names)

	r := dispatchAction(s, "device_unmerge", map[string]string{"from_mac": mmOld}, false)
	if !r.OK {
		t.Fatalf("legacy unmerge failed: %+v", r)
	}
	if al := loadMACAliases(dir); len(al) != 0 {
		t.Fatalf("legacy alias not removed: %v", al)
	}
	if len(loadRMACState(dir).AutoInherited) != 0 {
		t.Fatalf("AutoInherited not cleared on legacy unmerge")
	}
	if gotName := mmRead(t, dir, "data/device_names.json")[mmNew]; gotName != "保留的新手机名" {
		t.Fatalf("legacy unmerge should keep target existing config intact, got name=%v", gotName)
	}
	mf := loadMacMergeFile(dir)
	if !isMacMutexApart(mf, mmOld, mmNew, now) {
		t.Fatalf("legacy unmerge must set MutexApart")
	}
}

func TestRMACReconnectAutoLosslessUnmerge(t *testing.T) {
	dir, s, _ := mmFixture(t)
	t0 := time.Now().Truncate(time.Second)

	// 合并时刻旧 MAC 刚断开还残留在 devices.json 中(记录合并时刻水位)
	mmWrite(t, dir, "data/devices.json", map[string]interface{}{
		mmOld: map[string]interface{}{
			"ip": "192.168.43.20", "mac": mmOld, "rx_bytes": 5000, "tx_bytes": 2000, "last_seen": t0.Unix() - 30,
		},
		mmNew: map[string]interface{}{
			"ip": "192.168.43.31", "mac": mmNew, "rx_bytes": 1000, "tx_bytes": 500, "last_seen": t0.Unix(),
		},
	})
	res, err := s.deviceMerge(mmOld, mmNew, false, t0)
	if err != nil {
		t.Fatalf("merge failed: %v (res=%+v)", err, res)
	}

	// 1) t0+10s: 旧 MAC 在 devices.json 中仍是合并时刻的死残留(last_seen 与 rx+tx 均未增长) → 绝不误拆
	s.rmacReconcile(t0.Add(10 * time.Second))
	if al := loadMACAliases(dir); al[mmOld] != mmNew {
		t.Fatalf("stale lease at merge watermark must NOT trigger auto-unmerge, aliases=%v", al)
	}

	// 2) t0+45s: 旧 MAC 真实重新发包上线(last_seen > MergedAt 且 rx+tx > OldBytesAtMerge) → 自动秒拆 + 告警
	t2 := t0.Add(45 * time.Second)
	mmWrite(t, dir, "data/devices.json", map[string]interface{}{
		mmOld: map[string]interface{}{
			"ip": "192.168.43.20", "mac": mmOld, "rx_bytes": 9000, "tx_bytes": 3500, "last_seen": t2.Unix(),
		},
		mmNew: map[string]interface{}{
			"ip": "192.168.43.31", "mac": mmNew, "rx_bytes": 4000, "tx_bytes": 1500, "last_seen": t2.Unix(),
		},
	})
	s.rmacReconcile(t2)

	if al := loadMACAliases(dir); len(al) != 0 {
		t.Fatalf("expected auto-unmerge on real old MAC reconnect, still got aliases=%v", al)
	}
	namesAfter := mmRead(t, dir, "data/device_names.json")
	if namesAfter[mmOld] != "小明的手机" || namesAfter[mmNew] != nil {
		t.Fatalf("auto-unmerge did not restore device names: %v", namesAfter)
	}
	alertsBytes, _ := os.ReadFile(filepath.Join(dir, "run", "alerts.jsonl"))
	if !strings.Contains(string(alertsBytes), `"kind":"mac_merge_unmerge_auto"`) {
		t.Fatalf("expected mac_merge_unmerge_auto alert, got %s", alertsBytes)
	}
	mf := loadMacMergeFile(dir)
	if !isMacMutexApart(mf, mmOld, mmNew, t2.Unix()) {
		t.Fatalf("auto-unmerge must lock MutexApart to prevent rebound re-merge")
	}
}

func TestMacMergeActionHardeningLoopbackAndIsolatedDebugBundle(t *testing.T) {
	dir := t.TempDir()
	mmWrite(t, dir, "data/rules.json", map[string]interface{}{"version": 1, "devices": map[string]interface{}{}, "blacklist": []interface{}{}})
	s := newServer(dir)

	// 1) Magisk 本机浏览器 127.0.0.1:8444(已认证 Cookie, tid="tok_local_1" != "loopback", 带 Origin)
	// 执行 loopback-only 动作 pair_revoke 不再被误拒 403 forbidden
	body := `{"action":"pair_revoke","params":{"id":"nonexistent_id"}}`
	reqLocal := httptest.NewRequest(http.MethodPost, "/api/action", strings.NewReader(body))
	reqLocal.Header.Set("Content-Type", "application/json")
	reqLocal.Header.Set("X-HNC-CSRF", "1")
	reqLocal.Header.Set("Origin", "https://127.0.0.1:8444")
	reqLocal.RemoteAddr = "127.0.0.1:51234"
	reqLocal = reqLocal.WithContext(context.WithValue(reqLocal.Context(), ctxKeyTokenID, "tok_local_1"))
	wLocal := httptest.NewRecorder()
	s.handleAction(wLocal, reqLocal)
	if wLocal.Code == http.StatusForbidden {
		t.Fatalf("authenticated loopback browser should not get 403 forbidden, body=%s", wLocal.Body.String())
	}

	// 而局域网远程设备带 Cookie 调 loopback-only 动作仍然严格返回 403 forbidden
	reqRemote := httptest.NewRequest(http.MethodPost, "/api/action", strings.NewReader(body))
	reqRemote.Header.Set("Content-Type", "application/json")
	reqRemote.Header.Set("X-HNC-CSRF", "1")
	reqRemote.RemoteAddr = "192.168.43.88:51234"
	reqRemote = reqRemote.WithContext(context.WithValue(reqRemote.Context(), ctxKeyTokenID, "tok_remote_1"))
	wRemote := httptest.NewRecorder()
	s.handleAction(wRemote, reqRemote)
	if wRemote.Code != http.StatusForbidden {
		t.Fatalf("remote LAN request must get 403 forbidden on pair_revoke, got %d body=%s", wRemote.Code, wRemote.Body.String())
	}

	// 2) debug_bundle 在全局 s.actionMu 被占住时仍可独立完成, 零阻塞实时控制锁
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	fakeScript := "#!/system/bin/sh\nout=\"$1/hnc_diag_test.tar.gz\"\necho ok > \"$out\"\necho \"$out\"\n"
	if err := os.WriteFile(filepath.Join(dir, "bin", "debug_bundle.sh"), []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	s.actionMu.Lock()
	done := make(chan int, 1)
	go func() {
		reqDB := httptest.NewRequest(http.MethodPost, "/api/action", strings.NewReader(`{"action":"debug_bundle","params":{}}`))
		reqDB.Header.Set("Content-Type", "application/json")
		reqDB.Header.Set("X-HNC-CSRF", "1")
		reqDB.RemoteAddr = "127.0.0.1:51235"
		wDB := httptest.NewRecorder()
		s.handleAction(wDB, reqDB)
		done <- wDB.Code
	}()
	select {
	case code := <-done:
		s.actionMu.Unlock()
		if code != http.StatusOK {
			t.Fatalf("isolated debug_bundle returned status %d, want 200", code)
		}
	case <-time.After(3 * time.Second):
		s.actionMu.Unlock()
		t.Fatalf("debug_bundle blocked on global s.actionMu")
	}
}
