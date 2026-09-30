package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 测试之间隔离 app_usage / 告警的全局状态
func resetAppTimeGlobals(t *testing.T) {
	t.Helper()
	appUsage.mu.Lock()
	appUsage.day, appUsage.dirty, appUsage.prev, appUsage.init = nil, false, nil, false
	appTimeLastTick = time.Time{}
	appUsage.mu.Unlock()
	appTimeAlerts.mu.Lock()
	appTimeAlerts.loaded, appTimeAlerts.Date, appTimeAlerts.Sent = false, "", nil
	appTimeAlerts.mu.Unlock()
	t.Cleanup(func() {
		appUsage.mu.Lock()
		appUsage.day, appUsage.dirty, appUsage.prev, appUsage.init = nil, false, nil, false
		appTimeLastTick = time.Time{}
		appUsage.mu.Unlock()
		appTimeAlerts.mu.Lock()
		appTimeAlerts.loaded, appTimeAlerts.Date, appTimeAlerts.Sent = false, "", nil
		appTimeAlerts.mu.Unlock()
	})
}

func newDay(date string) *appUsageDay {
	return &appUsageDay{Date: date, Hours: map[string]map[string][2]uint64{}, Apps: map[string]appUsageMeta{}}
}

func TestAppTimeActiveThreshold(t *testing.T) {
	now := time.Date(2026, 9, 30, 14, 5, 0, 0, time.Local)
	d := newDay("20260930")
	m := "aa:bb:cc:00:00:01"
	tick := map[string]uint64{
		m + "|douyin":    appActiveMinBytes,     // 刚好达标
		m + "|kuaishou":  appActiveMinBytes - 1, // 差 1 字节
		m + "|ads_sdk":   1 << 20,               // 广告 SDK: 不计时长
		m + "|coloros":   1 << 20,               // 系统服务: 不计时长
		m + "|_unknown":  1 << 20,
		m + "|_local":    1 << 20,
		"bad-key-no-sep": 1 << 20,
	}
	cats := map[string]string{"douyin": "video", "kuaishou": "video", "ads_sdk": "ads", "coloros": "system-oppo"}
	appTimeStep(d, tick, cats, now, 10)
	if got := d.Active["14"]; len(got) != 1 || got[m+"|douyin"] != 10 {
		t.Fatalf("active = %v", d.Active)
	}
	if s := d.Seen[m+"|douyin"]; s[0] != now.Unix() || s[1] != now.Unix() {
		t.Fatalf("seen = %v", s)
	}
	// 20 秒间隔: 阈值按比例折算
	later := now.Add(20 * time.Second)
	appTimeStep(d, map[string]uint64{m + "|douyin": 2*appActiveMinBytes - 1}, cats, later, 20)
	if d.Active["14"][m+"|douyin"] != 10 {
		t.Fatal("below scaled threshold must not count")
	}
	appTimeStep(d, map[string]uint64{m + "|douyin": 2 * appActiveMinBytes}, cats, later, 20)
	if d.Active["14"][m+"|douyin"] != 30 || d.Seen[m+"|douyin"][0] != now.Unix() || d.Seen[m+"|douyin"][1] != later.Unix() {
		t.Fatalf("scaled: %v %v", d.Active, d.Seen)
	}
	// 间隔秒数: 首轮 10, 正常 10, 异常长的封顶 20
	appTimeLastTick = time.Time{}
	if s := appTimeTickSec(now); s != 10 {
		t.Fatal(s)
	}
	if s := appTimeTickSec(now.Add(11 * time.Second)); s != 11 {
		t.Fatal(s)
	}
	if s := appTimeTickSec(now.Add(10 * time.Minute)); s != appTimeMaxTickSec {
		t.Fatal(s)
	}
	appTimeLastTick = time.Time{}
}

func TestAppUsageRecordActiveAndUnknown(t *testing.T) {
	now := time.Date(2026, 9, 30, 9, 0, 0, 0, time.Local)
	d := newDay("20260930")
	m := "aa:bb:cc:00:00:01"
	owner := map[string]string{"192.168.43.10": m}
	names := map[string]ipName{
		"1.1.1.1": {Name: "v26.douyinvod.com", App: "douyin", AppName: "抖音", Category: "video"},
		"5.5.5.5": {Name: "edge-7.cdn.example.com.cn"},
	}
	deltas := []appUsageDelta{
		{Src: "192.168.43.10", Dst: "1.1.1.1", Up: 1000, Dn: 20000},
		{Src: "192.168.43.10", Dst: "5.5.5.5", Up: 10, Dn: 90},
		{Src: "192.168.43.10", Dst: "6.6.6.6", Up: 0, Dn: 500},
		{Src: "192.168.43.10", Dst: "192.168.43.1", Up: 50, Dn: 50},
	}
	added := appUsageRecord(d, deltas, owner, map[string]ipApp{}, names, now, 10)
	if added != 21700 {
		t.Fatal(added)
	}
	if d.Hours["9"][m+"|douyin"] != [2]uint64{1000, 20000} || d.Active["9"][m+"|douyin"] != 10 {
		t.Fatalf("bytes/active: %v %v", d.Hours, d.Active)
	}
	if u := d.Unknown["example.com.cn"]; u == nil || u.B != 100 || u.S != "edge-7.cdn.example.com.cn" || u.IP || len(u.M) != 1 {
		t.Fatalf("unknown by domain: %+v", d.Unknown)
	}
	if u := d.Unknown["6.6.6.6"]; u == nil || u.B != 500 || !u.IP {
		t.Fatalf("unknown by ip: %+v", d.Unknown)
	}
	if _, ok := d.Unknown["192.168.43.1"]; ok {
		t.Fatal("LAN must not be unknown")
	}
	for in, want := range map[string]string{"a.b.qq.com": "qq.com", "x.y.co.uk": "y.co.uk", "qq.com": "qq.com", "WWW.Foo.NET.": "foo.net"} {
		if got := baseDomain(in); got != want {
			t.Fatalf("baseDomain(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAppUnknownCaps(t *testing.T) {
	d := newDay("20260930")
	for i := 0; i < 1000; i++ {
		appUnknownAdd(d, fmt.Sprintf("9.9.%d.%d", i/256, i%256), "", "aa:bb:cc:00:00:01", uint64(i+1))
		if len(d.Unknown) > appUnknownMax {
			t.Fatalf("cap exceeded: %d", len(d.Unknown))
		}
	}
	// 最大的几个一定还在
	if d.Unknown["9.9.3.231"] == nil || d.Unknown["9.9.3.231"].B != 1000 {
		t.Fatal("largest entry pruned")
	}
	for i := 0; i < 20; i++ {
		appUnknownAdd(d, "9.9.3.231", "", fmt.Sprintf("aa:bb:cc:00:01:%02x", i), 1)
	}
	if n := len(d.Unknown["9.9.3.231"].M); n != appUnknownMaxMACs {
		t.Fatalf("macs = %d", n)
	}
	appUnknownAdd(d, "9.9.9.9", "", "m", 0) // 0 字节不建条目
	if d.Unknown["9.9.9.9"] != nil {
		t.Fatal("zero bytes created entry")
	}
}

// 旧版日文件(没有 active/seen/unknown)照常加载、继续记账、API 输出 active_sec=0
func TestAppUsageOldDayFileCompat(t *testing.T) {
	resetAppTimeGlobals(t)
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	date := time.Now().AddDate(0, 0, -1).Format("20060102")
	old := `{"date":"` + date + `","hours":{"10":{"aa:bb:cc:00:00:01|douyin":[100,900]}},"apps":{"douyin":{"name":"抖音","category":"video"}}}`
	_ = os.WriteFile(appUsagePath(dir, date), []byte(old), 0o644)
	d := loadAppUsageDay(dir, date)
	if d.Hours["10"]["aa:bb:cc:00:00:01|douyin"] != [2]uint64{100, 900} || d.Active != nil {
		t.Fatalf("old load: %+v", d)
	}
	appTimeStep(d, map[string]uint64{"aa:bb:cc:00:00:01|douyin": 1 << 20}, map[string]string{"douyin": "video"},
		time.Now(), 10)
	if err := saveAppUsageDay(dir, d); err != nil {
		t.Fatal(err)
	}
	d2 := loadAppUsageDay(dir, date)
	if d2.Active["10"] == nil && len(d2.Active) == 0 {
		t.Fatal("active not persisted")
	}
	s := newServer(dir)
	rec := httptest.NewRecorder()
	s.apiAppUsage(rec, httptest.NewRequest("GET", "/api/app_usage?days=2", nil))
	var resp struct {
		ByApp []map[string]interface{} `json:"by_app"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.ByApp) != 1 || resp.ByApp[0]["active_sec"].(float64) != 10 {
		t.Fatalf("app_usage: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.apiAppTime(rec, httptest.NewRequest("GET", "/api/app_time?days=2&mac=aa:bb:cc:00:00:01", nil))
	var at struct {
		Apps  []map[string]interface{} `json:"apps"`
		Total float64                  `json:"total_active_sec"`
		Lims  []interface{}            `json:"app_time_limits"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &at)
	if at.Total != 10 || len(at.Apps) != 1 || at.Apps[0]["id"] != "douyin" || at.Apps[0]["first_seen"].(float64) == 0 || at.Lims == nil {
		t.Fatalf("app_time: %s", rec.Body.String())
	}
}

// 规则库 + 反查表 + 假脚本
func setupAppCtlDir(t *testing.T) (string, *server) {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"data", "run", "bin", "etc/dpi_rules.d"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	_ = os.WriteFile(filepath.Join(dir, "etc", "dpi_rules.d", "30-video.json"), []byte(`{"rules":[
	 {"id":"douyin","app":"抖音","category":"video","suffixes":["douyin.com","douyinvod.com","*.amemv.com"]},
	 {"id":"kuaishou","app":"快手","category":"video","suffixes":["kuaishou.com"]},
	 {"id":"ads_x","app":"广告","category":"ads","suffixes":["adx.com"]},
	 {"id":"oppo_sys","app":"系统","category":"system","suffixes":["heytapmobi.com"]},
	 {"id":"alidns","app":"DoH","category":"video","suffixes":["alidns.com"],"do_not_attribute_to_app":true}]}`), 0o644)
	// 99 覆盖 kuaishou 的后缀(后写覆盖)
	_ = os.WriteFile(filepath.Join(dir, "etc", "dpi_rules.d", "99-user-custom.json"), []byte(`[
	 {"id":"kuaishou","app":"快手","category":"video","suffixes":["kuaishou.com","gifshow.com"]}]`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "dpi_ipname.json"), []byte(`{"entries":{
	 "1.1.1.1":{"name":"v26.douyinvod.com","app":"douyin","category":"video"},
	 "2.2.2.2":{"name":"p3.dy-cname-cdn.net","app":"douyin","category":"video"},
	 "3.3.3.3":{"name":"api.kuaishou.com","app":"kuaishou","category":"video"},
	 "4.4.4.4":{"name":"notdouyin.com"}}}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "ip_app_map.json"), []byte(`{"entries":[{"ip":"7.7.7.7","app_id":"douyin","category":"video"},{"ip":"10.0.0.9","app_id":"douyin","category":"video"}]}`), 0o644)
	writeStub(t, dir, "connblock_sync.sh", "echo CONN_BLOCK=on rules=$(wc -l < \"$HNC_DIR/run/conn_blocks.flat\")\n")
	t.Setenv("HNC_DIR", dir)
	return dir, newServer(dir)
}

func setTodayActive(now time.Time, mk string, sec uint32) {
	appUsage.mu.Lock()
	defer appUsage.mu.Unlock()
	d := newDay(now.Format("20060102"))
	d.Active = map[string]map[string]uint32{"8": {mk: sec}}
	appUsage.day = d
}

func readFileStr(p string) string { b, _ := os.ReadFile(p); return string(b) }

func TestAppTimeLimitExhaustAndMidnightExpiry(t *testing.T) {
	resetAppTimeGlobals(t)
	dir, s := setupAppCtlDir(t)
	mac := "aa:bb:cc:00:00:01"
	now := time.Now()
	if r := actionAppTimeLimitSet(s, map[string]string{"mac": mac, "app_id": "ads_x", "minutes": "30"}); r.OK {
		t.Fatal("hidden-tier app accepted")
	}
	if r := actionAppTimeLimitSet(s, map[string]string{"mac": mac, "app_id": "douyin", "minutes": "1441"}); r.OK {
		t.Fatal("minutes > 1440 accepted")
	}
	if r := actionAppTimeLimitSet(s, map[string]string{"mac": mac, "app_id": "nope", "minutes": "30"}); r.OK {
		t.Fatal("unknown app accepted")
	}
	// 还没用 → 设上限不产生封锁
	setTodayActive(now, mac+"|douyin", 55*60)
	if r := actionAppTimeLimitSet(s, map[string]string{"mac": mac, "app_id": "douyin", "minutes": "60"}); !r.OK {
		t.Fatalf("set: %+v", r)
	}
	if f := readFileStr(connBlocksFlat(dir)); f != "" {
		t.Fatalf("flat before exhaustion: %q", f)
	}
	// 55/60 分钟 → 预警一次
	s.appTimeEnforce(now)
	s.appTimeEnforce(now)
	al := readFileStr(filepath.Join(dir, "run", "alerts.jsonl"))
	if strings.Count(al, `"app_time_warn"`) != 1 || strings.Contains(al, "app_time_exhausted") {
		t.Fatalf("warn alerts: %s", al)
	}
	// 用完
	setTodayActive(now, mac+"|douyin", 60*60)
	s.connBlockRefresh()
	flat := readFileStr(connBlocksFlat(dir))
	for _, want := range []string{mac + " 1.1.1.1", mac + " 2.2.2.2", mac + " 7.7.7.7"} {
		if !strings.Contains(flat, want) {
			t.Fatalf("flat missing %q: %q", want, flat)
		}
	}
	if strings.Contains(flat, "3.3.3.3") || strings.Contains(flat, "4.4.4.4") || strings.Contains(flat, "10.0.0.9") {
		t.Fatalf("flat over-blocks: %q", flat)
	}
	dns := readFileStr(connBlocksDNS(dir))
	for _, want := range []string{mac + " douyin.com", mac + " douyinvod.com", mac + " amemv.com", mac + " p3.dy-cname-cdn.net"} {
		if !strings.Contains(dns, want+"\n") {
			t.Fatalf("dns missing %q: %q", want, dns)
		}
	}
	items := s.connBlockDerived(now)
	for _, it := range items {
		if it.Source != connBlockSrcAppTime || it.Ref != "douyin" || it.Until != nextLocalMidnight(now).Unix() || it.Label != "抖音" {
			t.Fatalf("derived item tag: %+v", it)
		}
	}
	// 派生项不写进用户的 conn_blocks.json
	if len(readConnBlocks(dir).Items) != 0 {
		t.Fatal("derived items leaked into conn_blocks.json")
	}
	s.appTimeEnforce(now)
	s.appTimeEnforce(now)
	al = readFileStr(filepath.Join(dir, "run", "alerts.jsonl"))
	if strings.Count(al, `"app_time_exhausted"`) != 1 {
		t.Fatalf("exhausted alerts: %s", al)
	}
	// 重启(内存状态丢了)也不重复告警
	appTimeAlerts.mu.Lock()
	appTimeAlerts.loaded, appTimeAlerts.Sent = false, nil
	appTimeAlerts.mu.Unlock()
	s.appTimeEnforce(now)
	if strings.Count(readFileStr(filepath.Join(dir, "run", "alerts.jsonl")), `"app_time_exhausted"`) != 1 {
		t.Fatal("duplicate alert after restart")
	}
	// 设备 API
	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"), []byte(`{"`+mac+`":{"ip":"192.168.43.10","last_seen":1}}`), 0o644)
	_, payload := s.buildDevicesPayload()
	devs := payload["devices"].([]map[string]interface{})
	lims, _ := devs[0]["app_time_limits"].([]map[string]interface{})
	if len(lims) != 1 || lims[0]["exhausted"] != true || lims[0]["used_min"] != 60 || lims[0]["name"] != "抖音" {
		t.Fatalf("devices app_time_limits: %v", devs[0])
	}
	// 过了 0 点: 明天的用量为 0 → 派生项消失
	if got := s.connBlockDerived(nextLocalMidnight(now).Add(time.Second)); len(got) != 0 {
		t.Fatalf("not expired after midnight: %v", got)
	}
	// 当天日文件滚动到新的一天 → 后台刷新后 flat 清空
	appUsage.mu.Lock()
	appUsage.day = newDay(nextLocalMidnight(now).Format("20060102"))
	appUsage.mu.Unlock()
	s.connBlockRefresh()
	if f := readFileStr(connBlocksFlat(dir)); f != "" {
		t.Fatalf("flat after midnight: %q", f)
	}
	// 删除
	if r := actionAppTimeLimitDel(s, map[string]string{"mac": mac, "app_id": "douyin"}); !r.OK {
		t.Fatal(r)
	}
	if r := actionAppTimeLimitDel(s, map[string]string{"mac": mac, "app_id": "douyin"}); r.OK {
		t.Fatal("double delete should be not found")
	}
}

func TestCategoryBlockExpansion(t *testing.T) {
	resetAppTimeGlobals(t)
	dir, s := setupAppCtlDir(t)
	mac := "aa:bb:cc:00:00:02"
	fake := "02:5e:00:00:00:01"
	for _, c := range []string{"ads", "system", "nosuch"} {
		if r := actionCategoryBlockSet(s, map[string]string{"mac": mac, "category": c, "enabled": "true"}); r.OK {
			t.Fatalf("category %s accepted", c)
		}
	}
	if r := actionCategoryBlockSet(s, map[string]string{"mac": mac, "category": "video", "enabled": "maybe"}); r.OK {
		t.Fatal("bad enabled accepted")
	}
	if r := actionCategoryBlockSet(s, map[string]string{"mac": mac, "category": "Video", "enabled": "true"}); !r.OK {
		t.Fatalf("set: %+v", r)
	}
	if r := actionCategoryBlockSet(s, map[string]string{"mac": fake, "category": "video", "enabled": "1"}); !r.OK {
		t.Fatalf("fake set: %+v", r)
	}
	dns := readFileStr(connBlocksDNS(dir))
	for _, want := range []string{"douyin.com", "kuaishou.com", "gifshow.com", "p3.dy-cname-cdn.net"} {
		if !strings.Contains(dns, mac+" "+want+"\n") {
			t.Fatalf("dns missing %q: %q", want, dns)
		}
	}
	if strings.Contains(dns, "adx.com") || strings.Contains(dns, "alidns.com") || strings.Contains(dns, "heytapmobi.com") {
		t.Fatalf("category over-blocks: %q", dns)
	}
	flat := readFileStr(connBlocksFlat(dir))
	if !strings.Contains(flat, mac+" 3.3.3.3") || !strings.Contains(flat, mac+" 1.1.1.1") {
		t.Fatalf("flat: %q", flat)
	}
	// 模拟设备: 配置保留, 但不下发
	if strings.Contains(flat, fake) || strings.Contains(dns, fake) {
		t.Fatalf("fake mac enforced: %q %q", flat, dns)
	}
	for _, it := range s.connBlocksForWithDerived(mac, time.Now()) {
		if it.Source != connBlockSrcCategory || it.Ref != "video" || it.Until != 0 {
			t.Fatalf("tag: %+v", it)
		}
	}
	ctl := s.appControlsByMAC(time.Now())
	cbs := ctl[mac]["category_blocks"].([]map[string]interface{})
	if len(cbs) != 1 || cbs[0]["app_count"] != 2 || cbs[0]["enforced"] != true {
		t.Fatalf("controls: %v", ctl[mac])
	}
	if ctl[fake]["category_blocks"].([]map[string]interface{})[0]["enforced"] != false {
		t.Fatal("fake enforced flag")
	}
	// 反查表长出新名字 → 下次刷新跟上
	_ = os.WriteFile(filepath.Join(dir, "run", "dpi_ipname.json"), []byte(`{"entries":{"8.8.4.4":{"name":"x.newvideo-cdn.org","app":"kuaishou","category":"video"}}}`), 0o644)
	s.jsonCache = newJSONFileCache()
	s.connBlockRefresh()
	if !strings.Contains(readFileStr(connBlocksFlat(dir)), mac+" 8.8.4.4") {
		t.Fatalf("refresh: %q", readFileStr(connBlocksFlat(dir)))
	}
	// 关闭
	if r := actionCategoryBlockSet(s, map[string]string{"mac": mac, "category": "video", "enabled": "false"}); !r.OK {
		t.Fatal(r)
	}
	if r := actionCategoryBlockSet(s, map[string]string{"mac": fake, "category": "video", "enabled": "false"}); !r.OK {
		t.Fatal(r)
	}
	if f := readFileStr(connBlocksFlat(dir)); f != "" {
		t.Fatalf("flat after disable: %q", f)
	}
	// /api/app_time 列出可封锁类别(不含 ads/system)
	rec := httptest.NewRecorder()
	s.apiAppTime(rec, httptest.NewRequest("GET", "/api/app_time", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `"id":"video"`) || strings.Contains(body, `"id":"ads"`) || strings.Contains(body, `"id":"system"`) {
		t.Fatalf("categories: %s", body)
	}
}

func TestAppBlockItemsCapsDeterministic(t *testing.T) {
	var sfx []string
	for i := 0; i < 300; i++ {
		sfx = append(sfx, fmt.Sprintf("s%03d.com", i))
	}
	apps := []*catalogApp{{ID: "a", Name: "A", Category: "game", Suffixes: sfx}}
	names := map[string]ipName{}
	ipApps := map[string]ipApp{}
	for i := 0; i < 200; i++ {
		names[fmt.Sprintf("9.0.%d.%d", i/200, i%200)] = ipName{Name: fmt.Sprintf("h%03d.other.net", i), App: "a"}
		ipApps[fmt.Sprintf("8.0.%d.%d", i/200, i%200)] = ipApp{ID: "a", Category: "game"}
	}
	match := func(id, _ string) bool { return id == "a" }
	x := appBlockItems("aa:bb:cc:00:00:01", "app_time", "a", "A", 1, apps, match, names, ipApps, appBlockMaxDomains)
	y := appBlockItems("aa:bb:cc:00:00:01", "app_time", "a", "A", 1, apps, match, names, ipApps, appBlockMaxDomains)
	if len(x) != appBlockMaxDomains+appBlockMaxExtraNames+appBlockMaxIPs {
		t.Fatalf("len %d", len(x))
	}
	for i := range x {
		if x[i] != y[i] {
			t.Fatal("expansion not deterministic")
		}
	}
}

func TestDPIUnknownAPI(t *testing.T) {
	resetAppTimeGlobals(t)
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	now := time.Now()
	d := newDay(now.Format("20060102"))
	d.Hours["3"] = map[string][2]uint64{"aa:bb:cc:00:00:01|_unknown": {100, 5000}}
	appUnknownAdd(d, "1.2.3.4", "a.foo.com", "aa:bb:cc:00:00:01", 3000)
	appUnknownAdd(d, "1.2.3.5", "b.foo.com", "aa:bb:cc:00:00:02", 1000)
	appUnknownAdd(d, "5.6.7.8", "", "aa:bb:cc:00:00:01", 1100)
	appUsage.mu.Lock()
	appUsage.day = d
	appUsage.mu.Unlock()
	s := newServer(dir)
	rec := httptest.NewRecorder()
	s.apiDPIUnknown(rec, httptest.NewRequest("GET", "/api/dpi_unknown?days=1", nil))
	var resp struct {
		Items []map[string]interface{} `json:"items"`
		Total float64                  `json:"total_unknown_bytes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Items) != 2 || resp.Items[0]["name_or_ip"] != "foo.com" || resp.Items[0]["bytes"].(float64) != 4000 ||
		resp.Items[0]["devices"].(float64) != 2 || resp.Items[1]["kind"] != "ip" || resp.Total != 5100 {
		t.Fatalf("dpi_unknown: %s", rec.Body.String())
	}
}
