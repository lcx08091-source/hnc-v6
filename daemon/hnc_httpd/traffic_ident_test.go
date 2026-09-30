package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// v5.21 traffic_ident.go: VPN/代理检测、隧道归属、共现推断

const tiMAC = "aa:bb:cc:00:00:01"
const tiIP = "192.168.43.10"

func tiKey(proto string, sport int, dst string, dport int) string {
	return proto + "|" + tiIP + "|" + strconv.Itoa(sport) + "|" + dst + "|" + strconv.Itoa(dport)
}

func tiDelta(key string, up, dn uint64) appUsageDelta {
	p := strings.Split(key, "|")
	return appUsageDelta{Src: p[1], Dst: p[3], Up: up, Dn: dn, Key: key}
}

type tiEnv struct {
	st    *identState
	d     *appUsageDay
	owner map[string]string
	apps  map[string]ipApp
	names map[string]ipName
}

func newTiEnv(t *testing.T) *tiEnv {
	t.Helper()
	identReset()
	t.Cleanup(identReset)
	return &tiEnv{
		st: identSt, d: newDay("20260930"),
		owner: map[string]string{tiIP: tiMAC},
		apps:  map[string]ipApp{},
		names: map[string]ipName{
			"1.1.1.1": {Name: "v26.douyinvod.com", App: "douyin", AppName: "抖音", Category: "video"},
			"2.2.2.2": {Name: "p3.douyinpic.com", App: "douyin", AppName: "抖音", Category: "video"},
			"3.3.3.3": {Name: "api.kuaishou.com", App: "kuaishou", AppName: "快手", Category: "video"},
			"4.4.4.4": {Name: "sdk.adx.com", App: "ads_x", AppName: "广告", Category: "ads"},
		},
	}
}

func (e *tiEnv) tick(now time.Time, newStarts map[string]time.Time, deltas ...appUsageDelta) {
	ix := e.st.observe(now, deltas, newStarts, nil, e.owner, e.apps, e.names)
	appUsageRecordIdent(e.d, deltas, e.owner, e.apps, e.names, now, 10, ix)
}

func (e *tiEnv) bytes(now time.Time, app string) uint64 {
	v := e.d.Hours[strconv.Itoa(now.Hour())][tiMAC+"|"+app]
	return v[0] + v[1]
}

func TestTunnelSignatureAndSuspect(t *testing.T) {
	cases := []struct {
		proto string
		port  int
		name  string
		want  string
	}{
		{"udp", 51820, "", "WireGuard"}, {"udp", 1194, "", "OpenVPN"}, {"tcp", 1194, "", "OpenVPN"},
		{"udp", 4500, "", "IPsec"}, {"udp", 500, "", "IPsec"}, {"unknown", 0, "", "ESP"},
		{"gre", 0, "", "PPTP"}, {"tcp", 1723, "", "PPTP"}, {"udp", 2408, "", "WARP"},
		{"tcp", 443, "api.nordvpn.com", "nordvpn.com"}, {"tcp", 443, "notnordvpn.com", ""},
		{"tcp", 443, "", ""}, {"udp", 443, "", ""}, {"udp", 53, "", ""},
	}
	for _, c := range cases {
		got := tunnelSignature(c.proto, c.port, c.name, ipApp{}, false)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("sig(%s/%d %q)=%q want ~%q", c.proto, c.port, c.name, got, c.want)
		}
	}
	if r := tunnelSignature("tcp", 443, "x.com", ipApp{ID: "clash", Name: "Clash", Category: "proxy"}, true); !strings.Contains(r, "Clash") {
		t.Fatal(r)
	}
	sus := []struct {
		proto string
		port  int
		name  string
		app   bool
		want  bool
	}{
		{"tcp", 443, "", false, true}, {"tcp", 443, "a.com", false, false}, {"tcp", 8388, "a.com", false, true},
		{"tcp", 5228, "", false, false}, {"udp", 443, "", false, true}, {"udp", 123, "", false, false},
		{"udp", 30000, "", false, true}, {"udp", 30000, "game.com", false, false}, {"tcp", 8388, "", true, false},
	}
	for _, c := range sus {
		if got := tunnelSuspect(c.proto, c.port, c.name, c.app) != ""; got != c.want {
			t.Errorf("suspect(%s/%d %q app=%v)=%v want %v", c.proto, c.port, c.name, c.app, got, c.want)
		}
	}
	if p, d, ok := ctKeyParts("udp|1.2.3.4|5|6.7.8.9|51820"); !ok || p != "udp" || d != 51820 {
		t.Fatal(p, d, ok)
	}
	if _, _, ok := ctKeyParts("bad"); ok {
		t.Fatal("bad key parsed")
	}
}

// WireGuard 占绝大多数字节 → certain; 这些字节记 _tunnel, 不算应用时长
func TestVPNCertainWireGuardAttributedToTunnel(t *testing.T) {
	e := newTiEnv(t)
	now := time.Date(2026, 9, 30, 10, 0, 0, 0, time.Local)
	wg := tiKey("udp", 40000, "9.9.9.1", 51820)
	dy := tiKey("tcp", 40001, "1.1.1.1", 443)
	e.tick(now, nil, tiDelta(wg, 100<<10, 900<<10), tiDelta(dy, 1000, 1000))
	v := identVPNVerdicts()[tiMAC]
	if v.Level != "certain" || !strings.Contains(v.Reason, "WireGuard") || v.Share < 0.99 || v.WindowSec != 300 {
		t.Fatalf("verdict: %+v", v)
	}
	if got := e.bytes(now, tunnelAppID); got != 1000<<10 {
		t.Fatalf("tunnel bytes %d", got)
	}
	if m := e.d.Apps[tunnelAppID]; m.Name != tunnelAppName || m.Category != tunnelCategory {
		t.Fatalf("meta %+v", m)
	}
	for _, cells := range e.d.Active {
		for mk := range cells {
			if strings.HasSuffix(mk, "|"+tunnelAppID) {
				t.Fatal("tunnel must not accrue app time")
			}
		}
	}
	if e.bytes(now, appUnknownID) != 0 {
		t.Fatal("wg bytes leaked into unknown")
	}
	// 窗口过去, 没新流量 → 设备从判定里消失
	e.tick(now.Add(6*time.Minute), nil)
	if _, ok := identVPNVerdicts()[tiMAC]; ok {
		t.Fatalf("stale verdict kept: %+v", identVPNVerdicts())
	}
}

// 无域名 TLS 单一目的承载 >90%、持续 ≥2 分钟、别的目的很少 → likely, 之后未识别字节记 _tunnel
func TestVPNLikelyHeuristicSingleLongFlow(t *testing.T) {
	e := newTiEnv(t)
	t0 := time.Date(2026, 9, 30, 11, 0, 0, 0, time.Local)
	px := tiKey("tcp", 41000, "8.8.9.9", 443)
	dy := tiKey("tcp", 41001, "1.1.1.1", 443)
	var before uint64
	for i := 0; i <= 13; i++ {
		now := t0.Add(time.Duration(i) * 10 * time.Second)
		e.tick(now, nil, tiDelta(px, 20<<10, 180<<10), tiDelta(dy, 2<<10, 18<<10))
		v := identVPNVerdicts()[tiMAC]
		if i < 12 && v.Level != "none" {
			t.Fatalf("tick %d: too early %+v", i, v)
		}
		if i == 11 {
			before = e.bytes(now, appUnknownID)
		}
	}
	last := t0.Add(130 * time.Second)
	v := identVPNVerdicts()[tiMAC]
	if v.Level != "likely" || v.Dst != "8.8.9.9" || !strings.Contains(v.Reason, "无域名的 TLS") || v.Share < 0.9 {
		t.Fatalf("verdict: %+v", v)
	}
	if before == 0 || e.bytes(last, tunnelAppID) != 2*(200<<10) {
		t.Fatalf("unknown before=%d tunnel=%d", before, e.bytes(last, tunnelAppID))
	}
	if e.bytes(last, "douyin") != 14*(20<<10) {
		t.Fatalf("named app bytes must stay with the app: %d", e.bytes(last, "douyin"))
	}
}

// 正常上网: 很多目的、或主目的不可疑 → none
func TestVPNNoneForNormalBrowsing(t *testing.T) {
	e := newTiEnv(t)
	t0 := time.Date(2026, 9, 30, 12, 0, 0, 0, time.Local)
	for i := 0; i < 20; i++ {
		now := t0.Add(time.Duration(i) * 10 * time.Second)
		var ds []appUsageDelta
		// 1 个大头无名目的(60%) + 5 个各 8% 的无名目的 → 「其它有量目的」超过 3 个
		ds = append(ds, tiDelta(tiKey("tcp", 42000, "7.7.7.1", 443), 0, 600<<10))
		for j := 0; j < 5; j++ {
			ds = append(ds, tiDelta(tiKey("tcp", 42001+j, "7.7.8."+strconv.Itoa(j), 443), 0, 80<<10))
		}
		e.tick(now, nil, ds...)
	}
	if v := identVPNVerdicts()[tiMAC]; v.Level != "none" || v.Bytes == 0 {
		t.Fatalf("verdict: %+v", v)
	}
	// 大量视频流量走已识别应用 → 不可疑
	e2 := newTiEnv(t)
	for i := 0; i < 20; i++ {
		e2.tick(t0.Add(time.Duration(i)*10*time.Second), nil, tiDelta(tiKey("tcp", 43000, "1.1.1.1", 443), 0, 1<<20))
	}
	if v := identVPNVerdicts()[tiMAC]; v.Level != "none" {
		t.Fatalf("app traffic flagged: %+v", v)
	}
}

func TestCoocCandidateRules(t *testing.T) {
	t0 := time.Date(2026, 9, 30, 13, 0, 0, 0, time.Local)
	dy := ipApp{ID: "douyin", Name: "抖音", Category: "video"}
	ks := ipApp{ID: "kuaishou", Name: "快手", Category: "video"}
	at := func(sec float64, app ipApp, precise bool) identStart {
		return identStart{at: t0.Add(time.Duration(sec * float64(time.Second))), app: app, precise: precise}
	}
	cases := []struct {
		name    string
		precise bool
		starts  []identStart
		want    string
	}{
		{"precise unique within +3s", true, []identStart{at(3, dy, true)}, "douyin"},
		{"precise unique within -5s", true, []identStart{at(-5, dy, true)}, "douyin"},
		{"precise outside window", true, []identStart{at(5.5, dy, true)}, ""},
		{"precise ambiguous 1v1", true, []identStart{at(1, dy, true), at(2, ks, true)}, ""},
		{"precise dominant 2v1", true, []identStart{at(1, dy, true), at(-1, dy, true), at(2, ks, true)}, "douyin"},
		{"precise 3v2 not dominant", true, []identStart{at(1, dy, true), at(1, dy, true), at(1, dy, true), at(2, ks, true), at(2, ks, true)}, ""},
		{"poll single start not enough", false, []identStart{at(0, dy, false)}, ""},
		{"poll two starts same tick", false, []identStart{at(0, dy, false), at(0, dy, false)}, "douyin"},
		{"poll other tick ignored", false, []identStart{at(-10, dy, false), at(-10, dy, false)}, ""},
		{"poll two apps", false, []identStart{at(0, dy, false), at(0, dy, false), at(0, ks, false)}, ""},
		{"mixed precise+poll needs poll rule", true, []identStart{at(2, dy, false)}, ""},
		{"none", true, nil, ""},
	}
	for _, c := range cases {
		a, ok := coocCandidate(t0, c.precise, c.starts, 10*time.Second)
		if (c.want == "") == ok || a.ID != c.want {
			t.Errorf("%s: got %q ok=%v want %q", c.name, a.ID, ok, c.want)
		}
	}
}

// 轮询粒度: 同一轮里抖音新建了 2 条连接 + 一条无名连接 → 无名连接的字节推测为抖音(inferred 计数)
func TestCoocInferencePollMode(t *testing.T) {
	e := newTiEnv(t)
	t0 := time.Date(2026, 9, 30, 14, 0, 0, 0, time.Local)
	a := tiKey("tcp", 44000, "1.1.1.1", 443)
	b := tiKey("tcp", 44001, "2.2.2.2", 443)
	u := tiKey("tcp", 44002, "6.6.6.6", 443)
	ad := tiKey("tcp", 44003, "4.4.4.4", 443) // 广告 SDK 的建连不算证据
	e.tick(t0, nil, tiDelta(a, 100, 900), tiDelta(b, 100, 900), tiDelta(u, 300, 700), tiDelta(ad, 10, 10))
	if e.bytes(t0, appUnknownID) != 0 || e.bytes(t0, "douyin") != 2000 {
		t.Fatalf("new unnamed flow must be held one tick: unk=%d dy=%d", e.bytes(t0, appUnknownID), e.bytes(t0, "douyin"))
	}
	t1 := t0.Add(10 * time.Second)
	e.tick(t1, nil, tiDelta(u, 0, 500))
	if e.bytes(t1, "douyin") != 2000+1500 || e.bytes(t1, appUnknownID) != 0 {
		t.Fatalf("inference: dy=%d unk=%d", e.bytes(t1, "douyin"), e.bytes(t1, appUnknownID))
	}
	if iv := e.d.Inferred[tiMAC+"|douyin"]; iv != [2]uint64{300, 1200} {
		t.Fatalf("inferred counter %v", iv)
	}
	if len(e.d.Unknown) != 0 {
		t.Fatalf("unknown agg polluted: %v", e.d.Unknown)
	}
	// 推测缓存: 之后到同一 IP 的新连接直接归抖音
	u2 := tiKey("tcp", 44010, "6.6.6.6", 443)
	t2 := t1.Add(10 * time.Second)
	e.tick(t2, nil, tiDelta(u2, 0, 100))
	t3 := t2.Add(10 * time.Second)
	e.tick(t3, nil)
	if iv := e.d.Inferred[tiMAC+"|douyin"]; iv[1] != 1300 {
		t.Fatalf("cache not applied: %v", iv)
	}
	// 该 IP 之后有了真名字 → 以规则为准, 不再算推测
	e.names["6.6.6.6"] = ipName{Name: "x.kuaishou.com", App: "kuaishou", AppName: "快手", Category: "video"}
	e.tick(t3.Add(10*time.Second), nil, tiDelta(u, 0, 50))
	if iv := e.d.Inferred[tiMAC+"|douyin"]; iv[1] != 1300 || e.bytes(t3, "kuaishou") != 50 {
		t.Fatalf("named IP must win: %v ks=%d", iv, e.bytes(t3, "kuaishou"))
	}
}

// 轮询粒度下两个应用同时建连 → 不推测, 字节回到未识别
func TestCoocInferenceAmbiguousStaysUnknown(t *testing.T) {
	e := newTiEnv(t)
	t0 := time.Date(2026, 9, 30, 15, 0, 0, 0, time.Local)
	e.tick(t0, nil,
		tiDelta(tiKey("tcp", 45000, "1.1.1.1", 443), 1, 1), tiDelta(tiKey("tcp", 45001, "2.2.2.2", 443), 1, 1),
		tiDelta(tiKey("tcp", 45002, "3.3.3.3", 443), 1, 1), tiDelta(tiKey("tcp", 45003, "3.3.3.3", 443), 1, 1),
		tiDelta(tiKey("tcp", 45004, "6.6.6.6", 443), 100, 100))
	t1 := t0.Add(10 * time.Second)
	e.tick(t1, nil)
	if e.bytes(t1, appUnknownID) != 200 || len(e.d.Inferred) != 0 {
		t.Fatalf("unk=%d inferred=%v", e.bytes(t1, appUnknownID), e.d.Inferred)
	}
	if u := e.d.Unknown["6.6.6.6"]; u == nil || u.B != 200 {
		t.Fatalf("unknown agg %v", e.d.Unknown)
	}
}

// 精确模式(conntrack NEW 事件时间): 单条建连、±5 秒内即可推测; 窗口外不推测
func TestCoocInferencePreciseMode(t *testing.T) {
	e := newTiEnv(t)
	t0 := time.Date(2026, 9, 30, 16, 0, 0, 0, time.Local)
	a := tiKey("tcp", 46000, "1.1.1.1", 443)
	u := tiKey("udp", 46001, "6.6.6.6", 443)
	far := tiKey("tcp", 46002, "6.6.6.7", 443)
	ns := map[string]time.Time{a: t0.Add(-7 * time.Second), u: t0.Add(-4 * time.Second), far: t0.Add(-1 * time.Second)}
	// far 的建连与抖音差 6 秒 → 不算
	e.tick(t0, ns, tiDelta(a, 10, 10), tiDelta(u, 100, 100), tiDelta(far, 5, 5))
	if e.bytes(t0, appUnknownID) != 0 {
		t.Fatalf("held flows recorded early: %d", e.bytes(t0, appUnknownID))
	}
	t1 := t0.Add(10 * time.Second)
	e.tick(t1, nil)
	if iv := e.d.Inferred[tiMAC+"|douyin"]; iv != [2]uint64{100, 100} {
		t.Fatalf("precise inference: %v", e.d.Inferred)
	}
	if e.bytes(t1, appUnknownID) != 10 {
		t.Fatalf("far flow should stay unknown: %d", e.bytes(t1, appUnknownID))
	}
	// 建连超过 5 秒才第一次有字节的精确流: 当轮直接裁决, 不暂缓
	e2 := newTiEnv(t)
	b := tiKey("tcp", 46100, "1.1.1.1", 443)
	v := tiKey("tcp", 46101, "6.6.6.8", 443)
	e2.tick(t0, map[string]time.Time{b: t0.Add(-9 * time.Second), v: t0.Add(-8 * time.Second)}, tiDelta(b, 1, 1), tiDelta(v, 7, 7))
	if iv := e2.d.Inferred[tiMAC+"|douyin"]; iv != [2]uint64{7, 7} {
		t.Fatalf("immediate decision: %v", e2.d.Inferred)
	}
}

// 本地流量、没有 Key 的旧式差分(单测/老调用方)行为不变
func TestIdentNilCtxCompat(t *testing.T) {
	d := newDay("20260930")
	now := time.Date(2026, 9, 30, 9, 0, 0, 0, time.Local)
	owner := map[string]string{tiIP: tiMAC}
	n := appUsageRecordIdent(d, []appUsageDelta{{Src: tiIP, Dst: "6.6.6.6", Up: 1, Dn: 2}, {Src: tiIP, Dst: "192.168.43.1", Up: 3, Dn: 4}},
		owner, map[string]ipApp{}, map[string]ipName{}, now, 10, nil)
	if n != 10 || d.Hours["9"][tiMAC+"|"+appUnknownID] != [2]uint64{1, 2} || d.Inferred != nil {
		t.Fatalf("n=%d %v", n, d.Hours)
	}
}

// API: /api/devices 带 vpn 字段; /api/app_usage 带 inferred_bytes; /api/dpi_unknown 带 tunnel/inferred 总量
func TestIdentAPIShapes(t *testing.T) {
	resetAppTimeGlobals(t)
	identReset()
	t.Cleanup(identReset)
	dir := t.TempDir()
	for _, sub := range []string{"data", "run", "bin"} {
		_ = os.MkdirAll(filepath.Join(dir, sub), 0o755)
	}
	t.Setenv("HNC_CONNTRACK_PATH", filepath.Join(dir, "no_conntrack"))
	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"), []byte(`{"`+tiMAC+`":{"ip":"`+tiIP+`","last_seen":1},"aa:bb:cc:00:00:02":{"ip":"192.168.43.11"}}`), 0o644)
	identPub.mu.Lock()
	identPub.v = map[string]vpnVerdict{tiMAC: {Level: "likely", Reason: "x", Share: 0.8, Bytes: 5 << 20, Dst: "8.8.9.9", WindowSec: 300}}
	identPub.mu.Unlock()
	s := newServer(dir)
	_, payload := s.buildDevicesPayload()
	devs := payload["devices"].([]map[string]interface{})
	b, _ := json.Marshal(devs)
	var got []map[string]interface{}
	_ = json.Unmarshal(b, &got)
	seen := 0
	for _, d := range got {
		v, ok := d["vpn"].(map[string]interface{})
		if !ok {
			t.Fatalf("vpn missing: %v", d)
		}
		switch d["mac"] {
		case tiMAC:
			seen++
			if v["level"] != "likely" || v["share"].(float64) != 0.8 || v["dst"] != "8.8.9.9" || v["window_sec"].(float64) != 300 {
				t.Fatalf("vpn: %v", v)
			}
		case "aa:bb:cc:00:00:02":
			seen++
			if v["level"] != "none" {
				t.Fatalf("vpn default: %v", v)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("devices: %s", b)
	}

	now := time.Now()
	d := newDay(now.Format("20060102"))
	h := strconv.Itoa(now.Hour())
	d.Hours[h] = map[string][2]uint64{
		tiMAC + "|douyin": {100, 900}, tiMAC + "|_tunnel": {50, 450}, tiMAC + "|_unknown": {10, 90},
	}
	d.Apps["douyin"] = appUsageMeta{Name: "抖音", Category: "video"}
	d.Apps["_tunnel"] = tunnelMeta
	d.Inferred = map[string][2]uint64{tiMAC + "|douyin": {30, 270}}
	appUsage.mu.Lock()
	appUsage.day = d
	appUsage.mu.Unlock()
	rec := httptest.NewRecorder()
	s.apiAppUsage(rec, httptest.NewRequest("GET", "/api/app_usage?days=1", nil))
	var au struct {
		Inferred float64                  `json:"inferred_bytes"`
		ByApp    []map[string]interface{} `json:"by_app"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &au)
	if au.Inferred != 300 {
		t.Fatalf("app_usage: %s", rec.Body.String())
	}
	found := 0
	for _, a := range au.ByApp {
		switch a["id"] {
		case "douyin":
			found++
			if a["inferred_bytes"].(float64) != 300 {
				t.Fatalf("douyin: %v", a)
			}
		case "_tunnel":
			found++
			if a["name"] != "VPN/代理隧道" || a["category"] != "tunnel" || a["inferred_bytes"].(float64) != 0 {
				t.Fatalf("tunnel: %v", a)
			}
		}
	}
	if found != 2 {
		t.Fatalf("by_app: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.apiDPIUnknown(rec, httptest.NewRequest("GET", "/api/dpi_unknown?days=1", nil))
	var du map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &du)
	if du["tunnel_bytes"].(float64) != 500 || du["inferred_bytes"].(float64) != 300 || du["total_unknown_bytes"].(float64) != 100 {
		t.Fatalf("dpi_unknown: %s", rec.Body.String())
	}
}

func TestCtNewParse(t *testing.T) {
	// 复用 ct_events_test 的 DELETE 报文构造: 同一布局换成 NEW 类型
	msg := synthDestroy("192.168.43.12", "9.9.9.9", 6, 40000, 443, 0, 0, false)
	if _, ok := parseCtNew(nfnlSubsysCtnetlink<<8|ipctnlMsgCtDelete, msg, time.Now()); ok {
		t.Fatal("DELETE must not parse as NEW")
	}
	if ev, ok := parseCtNew(nfnlSubsysCtnetlink<<8|ipctnlMsgCtNew, msg, time.Now()); !ok || ev.Key != "tcp|192.168.43.12|40000|9.9.9.9|443" {
		t.Fatalf("NEW parse: %+v %v", ev, ok)
	}
	ctNewPush("tcp|a|1|b|2", time.Unix(100, 0))
	ctNewPush("tcp|a|1|b|2", time.Unix(200, 0))
	m, _ := ctNewDrain()
	if len(m) != 1 || !m["tcp|a|1|b|2"].Equal(time.Unix(100, 0)) {
		t.Fatalf("drain: %v", m)
	}
	if m2, _ := ctNewDrain(); len(m2) != 0 {
		t.Fatal("drain not reset")
	}
}
