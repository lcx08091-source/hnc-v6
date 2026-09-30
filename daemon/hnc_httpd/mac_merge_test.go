package main

import (
	"encoding/json"
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
		d["delay_enabled"], d["delay_ms"], d["jitter_ms"], d["loss_pct"] = true, float64(dm), float64(jm), lp
	case "delay_clear":
		d := dev()
		d["delay_enabled"], d["delay_ms"], d["jitter_ms"], d["loss_pct"] = false, float64(0), float64(0), float64(0)
	case "rule_sqm":
		dev()["sqm_enabled"] = p["enabled"] == "true"
	case "device_whitelist_set":
		dev()["whitelist"] = p["enabled"] == "true"
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
