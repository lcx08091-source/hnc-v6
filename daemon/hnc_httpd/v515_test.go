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

func TestRegistrableAndCompany(t *testing.T) {
	for in, want := range map[string]string{"img.xhscdn.com": "xhscdn.com", "a.b.sina.com.cn": "sina.com.cn", "x.com": "x.com", "*.kuaishou.com": "kuaishou.com"} {
		if got := registrable(in); got != want {
			t.Errorf("registrable(%q)=%q want %q", in, got, want)
		}
	}
	if c := companyFromOrg("Beijing Kuaishou Technology Co., Ltd."); c != "快手" {
		t.Fatalf("company = %q", c)
	}
	if c := companyFromOrg("Some Random Org"); c != "" {
		t.Fatalf("unknown org should map to empty, got %q", c)
	}
}

func TestDiscoverFlow(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "run"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	w := func(p, s string) {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("run/dpi_discover.json", `{"schema":1,"groups":[
	 {"id":"g_a","suffixes":["kwaicdn.com","gifshow.com"],"domains":[{"name":"p1.kwaicdn.com","count":40}],"devices":["aa:bb:cc:00:00:01"],"hits":40},
	 {"id":"g_b","suffixes":["weirdapp.io"],"domains":[{"name":"api.weirdapp.io","count":9}],"hits":9,"family_name":"字节跳动"},
	 {"id":"g_c","suffixes":["mystery.net"],"domains":[{"name":"x.mystery.net","count":6}],"hits":6}]}`)
	w("run/apk_domains.json", `{"schema":1,"generated_at":100,"apps":{"com.kuaishou.nebula":{"label":"快手极速版"},"com.x":{"label":"X"}},
	 "suffix_index":{"kwaicdn.com":["com.kuaishou.nebula"],"gifshow.com":["com.kuaishou.nebula"],"umeng.com":["com.x"]},"sdk_suffixes":["umeng.com"]}`)
	certState.mu.Lock()
	certState.loaded, certState.m = false, nil
	certState.mu.Unlock()
	certProbeFunc = func(host string, ips []string) certInfo {
		if host == "x.mystery.net" {
			return certInfo{Host: host, Org: "Beijing Kuaishou Technology Co., Ltd.", SANs: []string{"*.mystery.net"}, Ts: 1}
		}
		return certInfo{Host: host, Err: "连接超时", Ts: 1}
	}
	defer func() { certProbeFunc = probeCert }()
	s := newServer(dir)
	if r := actionDiscoverProbe(s, map[string]string{"id": "g_c"}); !r.OK {
		t.Fatalf("probe: %+v", r)
	}
	get := func() map[string]map[string]interface{} {
		rr := httptest.NewRecorder()
		s.apiDiscover(rr, httptest.NewRequest("GET", "/api/discover", nil))
		var out struct {
			Groups []map[string]interface{} `json:"groups"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		m := map[string]map[string]interface{}{}
		for _, g := range out.Groups {
			m[asString(g["id"])] = g
		}
		return m
	}
	gs := get()
	guess := func(id string) map[string]interface{} { g, _ := gs[id]["guess"].(map[string]interface{}); return g }
	if g := guess("g_a"); g["src"] != "apk" || g["name"] != "快手极速版" {
		t.Fatalf("g_a guess = %v", g)
	}
	if g := guess("g_b"); g["src"] != "ja4" || g["name"] != "疑似字节跳动应用" {
		t.Fatalf("g_b guess = %v", g)
	}
	if g := guess("g_c"); g["src"] != "cert" || g["company"] != "快手" {
		t.Fatalf("g_c guess = %v", g)
	}

	// 确认: 写入用户规则, 组从列表消失
	r := actionDiscoverConfirm(s, map[string]string{"id": "g_a", "name": "快手极速版", "category": "video", "suffixes": "kwaicdn.com, gifshow.com"})
	if !r.OK {
		t.Fatalf("confirm: %+v", r)
	}
	b, err := os.ReadFile(userRulesPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []map[string]interface{} `json:"rules"`
	}
	if json.Unmarshal(b, &doc) != nil || len(doc.Rules) != 1 || doc.Rules[0]["app"] != "快手极速版" || doc.Rules[0]["category"] != "video" {
		t.Fatalf("user rules = %s", b)
	}
	// 再确认同一主后缀 → 合并, 不重复加规则
	_ = addIDList(filepath.Join(dir, "run", "discover_confirmed.json"), "none")
	if r := actionDiscoverConfirm(s, map[string]string{"id": "g_x", "name": "快手", "category": "video", "suffixes": "kwaicdn.com,kuaishou.com"}); !r.OK {
		t.Fatal(r)
	}
	b, _ = os.ReadFile(userRulesPath(dir))
	_ = json.Unmarshal(b, &doc)
	if len(doc.Rules) != 1 || len(strList(doc.Rules[0]["suffixes"])) != 3 {
		t.Fatalf("merge failed: %s", b)
	}
	// 非法输入
	if r := actionDiscoverConfirm(s, map[string]string{"id": "g_b", "name": "x", "category": "evil", "suffixes": "a.com"}); r.OK {
		t.Fatal("bad category accepted")
	}
	if r := actionDiscoverConfirm(s, map[string]string{"id": "g_b", "name": "x", "category": "video", "suffixes": "../../etc"}); r.OK {
		t.Fatal("bad suffix accepted")
	}
	// 忽略
	if r := actionDiscoverIgnore(s, map[string]string{"id": "g_b"}); !r.OK {
		t.Fatal(r)
	}
	gs = get()
	if _, ok := gs["g_a"]; ok {
		t.Fatal("confirmed group still listed")
	}
	if _, ok := gs["g_b"]; ok {
		t.Fatal("ignored group still listed")
	}
	if _, ok := gs["g_c"]; !ok {
		t.Fatal("g_c should remain")
	}
	if r := actionAPKScan(dir); !r.OK || !fileExists(filepath.Join(dir, "run", "apk_scan.request")) {
		t.Fatal("apk scan request not written")
	}
}

// v5.16: 按应用真实流量 —— 连接表字节差分按 (设备, 应用, 小时) 累加
func TestAppUsageAccounting(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "run"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	w := func(p, s string) {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("data/devices.json", `{"aa:bb:cc:00:00:01":{"ip":"192.168.43.12"}}`)
	w("run/dpi_ipname.json", `{"schema":1,"entries":{"9.9.9.9":{"name":"upos.bilivideo.com","src":"dns","app":"bilibili","app_name":"哔哩哔哩","category":"video"}}}`)
	t.Setenv("HNC_CONNTRACK_PATH", filepath.Join(dir, "ct"))
	t.Setenv("HNC_CONNTRACK_ACCT_PATH", filepath.Join(dir, "acct"))
	line := func(dst string, sport, up, dn int) string {
		return "ipv4 2 tcp 6 300 ESTABLISHED src=192.168.43.12 dst=" + dst + " sport=" + itoa(sport) + " dport=443 packets=1 bytes=" + itoa(up) +
			" src=" + dst + " dst=10.0.0.1 sport=443 dport=" + itoa(sport) + " packets=1 bytes=" + itoa(dn) + " mark=0 use=1\n"
	}
	reset := func() {
		ctState.mu.Lock()
		ctState.snap, ctState.prev, ctState.acctTried = nil, nil, true
		ctState.mu.Unlock()
	}
	appUsage.mu.Lock()
	appUsage.day, appUsage.prev, appUsage.init, appUsage.dirty = nil, nil, false, false
	appUsage.mu.Unlock()
	s := newServer(dir)
	now := time.Date(2026, 9, 24, 14, 5, 0, 0, time.Local)
	// 第一轮: 已存在的连接只建立基线, 历史字节不算
	w("ct", line("9.9.9.9", 1000, 5000, 1_000_000)+line("5.5.5.5", 1001, 100, 200))
	reset()
	if got := s.appUsageTick(now); got != 0 {
		t.Fatalf("baseline tick counted %d bytes", got)
	}
	// 第二轮: 增量 + 一条新连接(全部字节算进来) + 一条局域网
	w("ct", line("9.9.9.9", 1000, 6000, 3_000_000)+line("5.5.5.5", 1001, 100, 200)+line("7.7.7.7", 1002, 50, 950)+line("192.168.43.1", 1003, 10, 20))
	reset()
	if got := s.appUsageTick(now.Add(10 * time.Second)); got != 1000+2_000_000+1000+30 {
		t.Fatalf("delta bytes = %d", got)
	}
	s.appUsageFlush(now.Add(time.Minute))
	if _, err := os.Stat(appUsagePath(dir, "20260924")); err != nil {
		t.Fatal("usage file not written")
	}
	// 连接计数器归零(连接重建同 key) → 不产生负数/巨大值
	w("ct", line("9.9.9.9", 1000, 10, 10))
	reset()
	if got := s.appUsageTick(now.Add(20 * time.Second)); got != 0 {
		t.Fatalf("counter reset should add 0, got %d", got)
	}
}

// v5.16: 通话检测 —— 双向持续的 UDP 媒体流 ≥8 秒才算; 单向下载、443 不算
func TestLiveCallDetection(t *testing.T) {
	up, dn := 40000.0, 50000.0
	e := ctEntry{Proto: "udp", Dst: "183.232.84.10", Dport: 8000}
	c, ok := callCandidate(e, up, dn, map[string]ipApp{}, map[string]ipName{})
	if !ok || c.label != "微信 · 语音通话" {
		t.Fatalf("wechat voip = %+v %v", c, ok)
	}
	if c, ok := callCandidate(ctEntry{Proto: "udp", Dst: "8.8.8.8", Dport: 3478}, 400000, 500000, nil, nil); !ok || c.label != "视频通话" {
		t.Fatalf("generic video call = %+v %v", c, ok)
	}
	for _, bad := range []struct {
		e      ctEntry
		up, dn float64
	}{
		{ctEntry{Proto: "udp", Dst: "8.8.8.8", Dport: 443}, 40000, 50000},   // QUIC 网页/视频
		{ctEntry{Proto: "tcp", Dst: "8.8.8.8", Dport: 8000}, 40000, 50000},  // TCP
		{ctEntry{Proto: "udp", Dst: "8.8.8.8", Dport: 9000}, 1000, 3e6},     // 单向下载
		{ctEntry{Proto: "udp", Dst: "192.168.43.5", Dport: 9000}, 4e4, 4e4}, // 局域网
	} {
		if _, ok := callCandidate(bad.e, bad.up, bad.dn, nil, nil); ok {
			t.Fatalf("should not be a call: %+v", bad)
		}
	}
	liveAppState.mu.Lock()
	liveAppState.calls = nil
	t0 := time.Unix(1_800_000_000, 0)
	updateCallsLocked(map[string]liveCall{"aa": c}, t0)
	liveAppState.mu.Unlock()
	if len(liveCallsByMAC()) != 0 {
		t.Fatal("call shorter than 8s must not show")
	}
	liveAppState.mu.Lock()
	updateCallsLocked(map[string]liveCall{"aa": c}, t0.Add(9*time.Second))
	liveAppState.mu.Unlock()
	if lc := liveCallsByMAC()["aa"]; lc == nil {
		t.Fatal("sustained call should show")
	}
	liveAppState.mu.Lock()
	updateCallsLocked(map[string]liveCall{}, t0.Add(20*time.Second))
	liveAppState.mu.Unlock()
	if len(liveCallsByMAC()) != 0 {
		t.Fatal("ended call should disappear")
	}
}

func TestDiscoverManage(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "run", "dpi_discover.json"), []byte(`{"groups":[{"id":"g_a","suffixes":["a.io"],"hits":9}]}`), 0o644)
	s := newServer(dir)
	if r := actionDiscoverIgnore(s, map[string]string{"id": "g_a"}); !r.OK {
		t.Fatal(r)
	}
	if ig := s.ignoredGroups(); len(ig) != 1 || ig[0]["id"] != "g_a" {
		t.Fatalf("ignored = %v", ig)
	}
	if r := actionDiscoverUnignore(s, map[string]string{"id": "g_a"}); !r.OK || len(s.ignoredGroups()) != 0 {
		t.Fatalf("unignore failed: %+v", r)
	}
	if r := actionDiscoverConfirm(s, map[string]string{"id": "g_a", "name": "A", "category": "tool", "suffixes": "a.io"}); !r.OK {
		t.Fatal(r)
	}
	ur := s.userRules()
	if len(ur) != 1 || ur[0]["app"] != "A" {
		t.Fatalf("user rules = %v", ur)
	}
	if r := actionUserRuleDel(s, map[string]string{"id": asString(ur[0]["id"])}); !r.OK || len(s.userRules()) != 0 {
		t.Fatalf("delete failed: %+v", r)
	}
	if r := actionUserRuleDel(s, map[string]string{"id": "nope"}); r.OK {
		t.Fatal("deleting missing rule should fail")
	}
}

func TestDeviceIdentOverride(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "run"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	_ = os.WriteFile(filepath.Join(dir, "run", "dpi_devid.json"), []byte(`{"devices":{"aa:bb:cc:00:00:01":{"os":"Android","type":"phone","brand":"小米","confidence":60}}}`), 0o644)
	s := newServer(dir)
	if r := actionDeviceIdentSet(dir, map[string]string{"mac": "AA:BB:CC:00:00:01", "type": "tablet", "model": "Pad 6", "brand": ""}); !r.OK {
		t.Fatal(r)
	}
	id := s.dpiIdentByMAC()["aa:bb:cc:00:00:01"]
	if id["type"] != "tablet" || id["model"] != "Pad 6" || id["os"] != "Android" || id["confidence"] != 100 || id["manual"] != true {
		t.Fatalf("override = %v", id)
	}
	if _, has := id["brand"]; has {
		t.Fatal("explicitly cleared brand should be removed")
	}
	if r := actionDeviceIdentSet(dir, map[string]string{"mac": "aa:bb:cc:00:00:01", "type": "spaceship"}); r.OK {
		t.Fatal("invalid type accepted")
	}
	// 没有自动识别结果的设备也能手动设
	_ = actionDeviceIdentSet(dir, map[string]string{"mac": "aa:bb:cc:00:00:02", "type": "tv"})
	if s.dpiIdentByMAC()["aa:bb:cc:00:00:02"]["type"] != "tv" {
		t.Fatal("override for unknown device missing")
	}
	_ = actionDeviceIdentSet(dir, map[string]string{"mac": "aa:bb:cc:00:00:01", "clear": "true"})
	if id := s.dpiIdentByMAC()["aa:bb:cc:00:00:01"]; id["type"] != "phone" || id["manual"] == true {
		t.Fatalf("clear should restore auto result: %v", id)
	}
}

func TestConnBlocks(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "run", "bin"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	// 假脚本: 把收到的 flat 复制一份, 输出最后一行
	_ = os.WriteFile(filepath.Join(dir, "bin", "connblock_sync.sh"), []byte("cp \"$HNC_DIR/run/conn_blocks.flat\" \"$HNC_DIR/run/synced\" 2>/dev/null; echo CONN_BLOCK=on rules=$(wc -l < \"$HNC_DIR/run/conn_blocks.flat\")\n"), 0o755)
	t.Setenv("HNC_DIR", dir)
	_ = os.WriteFile(filepath.Join(dir, "run", "dpi_ipname.json"), []byte(`{"entries":{"1.1.1.1":{"name":"v26.douyinvod.com"},"2.2.2.2":{"name":"douyinvod.com"},"3.3.3.3":{"name":"notdouyinvod.com"}}}`), 0o644)
	s := newServer(dir)
	mac := "aa:bb:cc:00:00:01"
	if r := actionConnBlockAdd(s, map[string]string{"mac": mac, "kind": "domain", "value": "douyinvod.com", "label": "抖音"}); !r.OK {
		t.Fatalf("add domain: %+v", r)
	}
	b, _ := os.ReadFile(connBlocksFlat(dir))
	if string(b) != mac+" 1.1.1.1\n"+mac+" 2.2.2.2\n" {
		t.Fatalf("flat = %q", b)
	}
	if r := actionConnBlockAdd(s, map[string]string{"mac": mac, "kind": "ip", "value": "192.168.43.1"}); r.OK {
		t.Fatal("LAN ip must be rejected")
	}
	if r := actionConnBlockAdd(s, map[string]string{"mac": mac, "kind": "domain", "value": "x.com; rm -rf /"}); r.OK {
		t.Fatal("bad domain accepted")
	}
	// 反查表出现新 IP → 后台刷新后跟上
	_ = os.WriteFile(filepath.Join(dir, "run", "dpi_ipname.json"), []byte(`{"entries":{"1.1.1.1":{"name":"v26.douyinvod.com"},"4.4.4.4":{"name":"v9.douyinvod.com"}}}`), 0o644)
	s.jsonCache = newJSONFileCache()
	s.connBlockRefresh()
	b, _ = os.ReadFile(connBlocksFlat(dir))
	if !strings.Contains(string(b), "4.4.4.4") || strings.Contains(string(b), "2.2.2.2") {
		t.Fatalf("refresh did not follow ipname: %q", b)
	}
	if r := actionConnBlockDel(s, map[string]string{"mac": mac, "kind": "domain", "value": "douyinvod.com"}); !r.OK {
		t.Fatal(r)
	}
	if b, _ := os.ReadFile(connBlocksFlat(dir)); len(b) != 0 {
		t.Fatalf("flat should be empty after delete: %q", b)
	}
}
