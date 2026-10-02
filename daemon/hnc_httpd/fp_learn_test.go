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

const (
	fptJA4A   = "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb" // 某 App 自带栈
	fptJA4Gen = "t13d1517h2_8daaf6152771_b0da82dd1658" // 通用(浏览器/Cronet)
	fptMAC1   = "aa:bb:cc:00:10:01"
	fptMAC2   = "aa:bb:cc:00:10:02"
)

func fptDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"data", "run", "etc"} {
		_ = os.MkdirAll(filepath.Join(dir, sub), 0o755)
	}
	t.Cleanup(dpiUserRulesReset)
	return dir
}

type fptFlows struct {
	boot int64
	seq  int64
	recs []fpFlowRec
}

func (f *fptFlows) add(mac, cip string, sport int, dip string, dport int, ja4, sni, app, cat string, ts int64) {
	f.seq++
	f.recs = append(f.recs, fpFlowRec{Seq: f.seq, Ts: ts, MAC: mac, CIP: cip, Sport: sport, DIP: dip, Dport: dport,
		Proto: "tcp", JA4: ja4, ALPN: "h2", SNI: sni, App: app, AppName: app + "名", Category: cat})
}

func (f *fptFlows) write(t *testing.T, dir string) {
	t.Helper()
	b, _ := json.Marshal(map[string]interface{}{"schema": 1, "boot": f.boot, "seq": f.seq, "flows": f.recs})
	p := filepath.Join(dir, "run", "dpi_flows.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	// 同一秒内重写: 改 mtime 保证 tick 认为文件变了
	mt := time.Unix(1_000_000+f.seq, 0)
	_ = os.Chtimes(p, mt, mt)
}

// 单设备 49 条不够, 50 条可用; 20 条 × 2 台设备可用
func TestFPLearnSupportThresholds(t *testing.T) {
	dir := fptDir(t)
	st := fpFor(dir)
	now := time.Unix(1_800_000_000, 0)
	f := &fptFlows{boot: 1}
	for i := 0; i < 49; i++ {
		f.add(fptMAC1, "192.168.43.10", 30000+i, "203.0.113.1", 443, fptJA4A, "api.app-a.com", "app_a", "video", now.Unix())
	}
	f.write(t, dir)
	st.tick(now, nil)
	k := fpKeyOf(fptJA4A, "h2", "443")
	v := st.m[k].verdict(now.Unix())
	if v.Usable || v.Top != "app_a" || v.Purity != 1 {
		t.Fatalf("49 flows single device must not be usable: %+v", v)
	}
	f.add(fptMAC1, "192.168.43.10", 31000, "203.0.113.1", 443, fptJA4A, "api.app-a.com", "app_a", "video", now.Unix())
	f.write(t, dir)
	st.tick(now, nil)
	v = st.m[k].verdict(now.Unix())
	if !v.Usable || v.Conf < 0.8 || v.Conf > 0.85 {
		t.Fatalf("50 flows should be usable with conf≈0.83: %+v", v)
	}
	if st.stats.FlowsSeen != 50 || st.stats.FlowsLearned != 50 {
		t.Fatalf("stats: %+v", st.stats)
	}

	// 多设备: 10 + 10 条, 两台设备
	ja4B := "t13d0909h2_cccccccccccc_dddddddddddd"
	for i := 0; i < 10; i++ {
		f.add(fptMAC1, "192.168.43.10", 32000+i, "203.0.113.2", 443, ja4B, "x.app-b.com", "app_b", "game", now.Unix())
	}
	f.write(t, dir)
	st.tick(now, nil)
	kb := fpKeyOf(ja4B, "h2", "443")
	if st.m[kb].verdict(now.Unix()).Usable {
		t.Fatal("10 flows must not be usable")
	}
	for i := 0; i < 10; i++ {
		f.add(fptMAC2, "192.168.43.11", 33000+i, "203.0.113.2", 443, ja4B, "x.app-b.com", "app_b", "game", now.Unix())
	}
	f.write(t, dir)
	st.tick(now, nil)
	if v := st.m[kb].verdict(now.Unix()); !v.Usable || v.Devices != 2 {
		t.Fatalf("20 flows / 2 devices should be usable: %+v", v)
	}
	// 同一文件再 tick 一次(游标): 不重复计数
	st.flowsKey = ""
	st.tick(now, nil)
	if st.stats.FlowsSeen != 70 {
		t.Fatalf("cursor broken, flows_seen=%d", st.stats.FlowsSeen)
	}
	// dpid 重启(boot 变), seq 从 1 开始: 新条目照常摄入
	f2 := &fptFlows{boot: 2}
	f2.add(fptMAC1, "192.168.43.10", 34000, "203.0.113.2", 443, ja4B, "x.app-b.com", "app_b", "game", now.Unix())
	f2.write(t, dir)
	st.tick(now, nil)
	if st.stats.FlowsSeen != 71 {
		t.Fatalf("boot change not handled, flows_seen=%d", st.stats.FlowsSeen)
	}
}

// 通用指纹: 多个应用 + 规则库认不出的网站(_other)混用 → 纯度不够, 不用; 计 generic_skipped
func TestFPLearnGenericPurityRejected(t *testing.T) {
	dir := fptDir(t)
	st := fpFor(dir)
	now := time.Unix(1_800_000_000, 0)
	f := &fptFlows{boot: 1}
	for i := 0; i < 120; i++ {
		var sni, app, cat string
		switch i % 4 {
		case 0:
			sni, app, cat = "a.app-a.com", "app_a", "video"
		case 1:
			sni, app, cat = "b.app-b.com", "app_b", "social"
		case 2:
			sni, app, cat = "news.example.org", "", "" // 规则库认不出 → _other
		case 3:
			sni, app, cat = "ads.adnet.com", "adnet", "ads" // 广告类不计
		}
		mac := fptMAC1
		if i%2 == 0 {
			mac = fptMAC2
		}
		f.add(mac, "192.168.43.10", 30000+i, "198.51.100."+strconv.Itoa(i%200+1), 443, fptJA4Gen, sni, app, cat, now.Unix())
	}
	// 一条无域名连接用同一个通用指纹
	f.add(fptMAC1, "192.168.43.10", 39999, "198.51.100.250", 443, fptJA4Gen, "", "", "", now.Unix())
	f.write(t, dir)
	st.tick(now, nil)
	e := st.m[fpKeyOf(fptJA4Gen, "h2", "443")]
	if e == nil || e.Apps["adnet"] != nil {
		t.Fatalf("entry/ads: %+v", e)
	}
	v := e.verdict(now.Unix())
	if v.Usable || !v.Generic || v.Purity > 0.4 {
		t.Fatalf("generic fp must be rejected: %+v", v)
	}
	key := "tcp|192.168.43.10|39999|198.51.100.250|443"
	fa, ok := st.attribute(key, nil, map[string]ipName{}, now)
	if ok || fa.JA4 != fptJA4Gen {
		t.Fatalf("generic fp attributed: %+v %v", fa, ok)
	}
	st.attribute(key, nil, map[string]ipName{}, now) // 同一连接只计一次
	if st.stats.GenericSkipped != 1 || st.stats.FlowsAttributed != 0 {
		t.Fatalf("stats: %+v", st.stats)
	}
	// 种子表里有这个指纹也不用(学习表判为通用优先)
	seed := `{"entries":[{"ja4":"` + fptJA4Gen + `","app_id":"chrome","name":"Chrome","category":"browser"}]}`
	_ = os.WriteFile(fpSeedPath(dir), []byte(seed), 0o644)
	if _, ok := st.attribute(key, nil, map[string]ipName{}, now); ok {
		t.Fatal("seed must not override a learned-generic fingerprint")
	}
}

// 衰减: 14 天半衰期; 60 条 → 14 天后 30, 低于单设备门槛
func TestFPLearnDecay(t *testing.T) {
	e := &fpEntry{JA4: fptJA4A, Port: "443"}
	t0 := int64(1_800_000_000)
	for i := 0; i < 60; i++ {
		e.learn("app_a", "A", "video", 1, fpDevKey(fptMAC1), t0)
	}
	if v := e.verdict(t0); !v.Usable || v.Support != 60 {
		t.Fatalf("t0: %+v", v)
	}
	t1 := t0 + fpHalfLifeSec
	v := e.verdict(t1)
	if v.Usable || v.Support < 29.9 || v.Support > 30.1 || v.Purity != 1 {
		t.Fatalf("after one half-life: %+v", v)
	}
	// 新学习时惰性衰减到 t1
	e.learn("app_a", "A", "video", 1, fpDevKey(fptMAC1), t1)
	if e.Total < 30.9 || e.Total > 31.1 || e.Upd != t1 {
		t.Fatalf("lazy decay: total=%v upd=%d", e.Total, e.Upd)
	}
	// 总量上限: 超过即减半
	for i := 0; i < int(fpTotalCap)+10; i++ {
		e.learn("app_a", "A", "video", 1, fpDevKey(fptMAC1), t1)
	}
	if e.Total > fpTotalCap {
		t.Fatalf("total not capped: %v", e.Total)
	}
	// 设备上限
	for i := 0; i < 40; i++ {
		e.learn("app_a", "A", "video", 1, fpDevKey("aa:bb:cc:dd:ee:"+strconv.Itoa(10+i)), t1+int64(i))
	}
	if len(e.Devs) > fpMaxDevs {
		t.Fatalf("devs not bounded: %d", len(e.Devs))
	}
}

// 优先级: 用户规则 > 规则库 > 学习指纹; 指纹只用于无域名(或 ECH 外层)的连接
func TestFPAttributionPrecedence(t *testing.T) {
	dir := fptDir(t)
	st := fpFor(dir)
	now := time.Unix(1_800_000_000, 0)
	f := &fptFlows{boot: 1}
	for i := 0; i < 60; i++ {
		f.add(fptMAC1, "192.168.43.10", 30000+i, "203.0.113.1", 443, fptJA4A, "api.app-a.com", "app_a", "video", now.Unix())
	}
	// 目标连接: 无域名, 同一指纹
	f.add(fptMAC1, "192.168.43.10", 40000, "203.0.113.50", 443, fptJA4A, "", "", "", now.Unix())
	// 有域名(规则库认不出)的连接
	f.add(fptMAC1, "192.168.43.10", 40001, "203.0.113.51", 443, fptJA4A, "", "", "", now.Unix())
	// ECH 外层 SNI 的连接(反查表里只有 DNS 名, 认不出)
	f.recs = append(f.recs, fpFlowRec{Seq: 1000, Ts: now.Unix(), MAC: fptMAC1, CIP: "192.168.43.10", Sport: 40002, DIP: "203.0.113.52",
		Dport: 443, Proto: "tcp", JA4: fptJA4A, ALPN: "h2", SNI: "cloudflare-ech.com", ECHOuter: true})
	f.seq = 1000
	f.write(t, dir)
	names := map[string]ipName{
		"203.0.113.51": {Name: "unknown-site.net", Src: "dns"},
		"203.0.113.52": {Name: "real.example.net", Src: "dns"},
	}
	st.tick(now, names)
	k50 := "tcp|192.168.43.10|40000|203.0.113.50|443"
	fa, ok := st.attribute(k50, nil, names, now)
	if !ok || fa.Src != "fp" || fa.App.ID != "app_a" || fa.App.Name != "app_a名" || fa.Conf < 0.8 {
		t.Fatalf("fp attribution: %+v %v", fa, ok)
	}
	if _, ok := st.attribute("tcp|192.168.43.10|40001|203.0.113.51|443", nil, names, now); ok {
		t.Fatal("named flow must not be fp-attributed")
	}
	if fa, ok := st.attribute("tcp|192.168.43.10|40002|203.0.113.52|443", nil, names, now); !ok || fa.Src != "fp" {
		t.Fatalf("ECH-outer flow should be fp-attributed: %+v", fa)
	}
	// 同设备同目的同端口的新连接(dpid 没抓到它的 ClientHello)走 pair 兜底
	if fa, ok := st.attribute("tcp|192.168.43.10|40099|203.0.113.50|443", nil, names, now); !ok || fa.Src != "fp" {
		t.Fatalf("pair fallback: %+v", fa)
	}
	// 规则库(ip_app_map)压过指纹
	apps := map[string]ipApp{"203.0.113.50": {ID: "lib_app", Name: "库应用", Category: "video"}}
	if fa, ok := st.attribute(k50, apps, names, now); !ok || fa.Src != "rule" || fa.App.ID != "lib_app" {
		t.Fatalf("rule library should win: %+v", fa)
	}
	// 用户 IP 规则压过规则库
	s := newServer(dir)
	r := actionDPICorrect(s, map[string]string{"mac": fptMAC1, "dst_ip": "203.0.113.50", "app_id": "user_app", "app_name": "用户应用", "category": "game", "kinds": "ip"})
	if !r.OK {
		t.Fatalf("correct: %+v", r)
	}
	if fa, ok := st.attribute(k50, apps, names, now); !ok || fa.Src != "user" || fa.App.ID != "user_app" || fa.Conf != 1 {
		t.Fatalf("user rule should win: %+v", fa)
	}
	if a, ok := appForIP("203.0.113.50", apps, names); !ok || a.ID != "user_app" {
		t.Fatalf("appForIP should apply user rule: %+v", a)
	}
}

// 纠正: IP 规则 7 天过期; 域名规则后缀匹配; 指纹规则(非通用)对无域名连接生效; 通用指纹拒绝; 删除
func TestDPICorrectApplyExpireDelete(t *testing.T) {
	dir := fptDir(t)
	s := newServer(dir)
	now := time.Now()
	names := map[string]ipName{"198.51.100.7": {Name: "cdn7.video-x.com", Src: "dns"}}
	r := actionDPICorrect(s, map[string]string{"dst_ip": "198.51.100.7", "dst_port": "443", "name": "video-x.com",
		"app_id": "video_x", "app_name": "视频X", "category": "video", "kinds": "domain,ip"})
	if !r.OK || !strings.Contains(r.Detail, "域名 video-x.com") || !strings.Contains(r.Detail, "IP 198.51.100.7:443") {
		t.Fatalf("correct: %+v", r)
	}
	// 域名规则: 反查到子域名的任何 IP 都归过去
	if a, src, ok := appForIPSrc("198.51.100.99", nil, map[string]ipName{"198.51.100.99": {Name: "img.video-x.com"}}); !ok || src != "user" || a.ID != "video_x" {
		t.Fatalf("domain rule: %+v %s", a, src)
	}
	// 端口专属 IP 规则: 只在带端口的流级归属里生效
	if a, ok := dpiUserMatchIP("198.51.100.7", 443, now); !ok || a.ID != "video_x" {
		t.Fatal("ip+port rule not applied")
	}
	if _, ok := dpiUserMatchIP("198.51.100.7", 8443, now); ok {
		t.Fatal("ip+port rule applied to another port")
	}
	// 7 天后过期
	if _, ok := dpiUserMatchIP("198.51.100.7", 443, now.Add(dpiUserIPTTL+time.Hour)); ok {
		t.Fatal("ip rule should expire")
	}
	_ = names

	// 无效参数
	for _, p := range []map[string]string{
		{"app_id": "x y", "dst_ip": "1.2.3.4"},
		{"app_id": "_unknown", "dst_ip": "1.2.3.4"},
		{"app_id": "nope", "dst_ip": "1.2.3.4"}, // 规则库没有且没给名字
		{"app_id": "a", "app_name": "A", "dst_ip": "not-ip"},
		{"app_id": "a", "app_name": "A", "name": "bad name"},
		{"app_id": "a", "app_name": "A", "ja4": "zzz"},
		{"app_id": "a", "app_name": "A", "category": "ads", "dst_ip": "1.2.3.4"},
		{"app_id": "a", "app_name": "A", "name": "com.cn"},     // 公共后缀 → 无可保存
		{"app_id": "a", "app_name": "A", "dst_ip": "10.0.0.5"}, // 局域网 → 无可保存
		{"app_id": "a", "app_name": "A"},
	} {
		if r := actionDPICorrect(s, p); r.OK {
			t.Fatalf("should reject %v: %+v", p, r)
		}
	}

	// 指纹规则: 学习表显示是通用指纹 → 拒绝
	st := fpFor(dir)
	st.mu.Lock()
	ge := &fpEntry{JA4: fptJA4Gen, ALPN: "h2", Port: "443", Upd: now.Unix()}
	for i := 0; i < 30; i++ {
		ge.learn([]string{"app_a", fpOtherApp, "app_b"}[i%3], "", "video", 1, fpDevKey(fptMAC1), now.Unix())
	}
	st.m[fpKeyOf(fptJA4Gen, "h2", "443")] = ge
	st.loaded = true
	st.mu.Unlock()
	r = actionDPICorrect(s, map[string]string{"ja4": fptJA4Gen, "app_id": "app_a", "app_name": "A", "category": "video"})
	if r.OK || !strings.Contains(r.Detail, "共用") {
		t.Fatalf("generic ja4 must be refused: %+v", r)
	}
	// 非通用指纹: 保存, 且对无域名连接生效(从连接绑定里自动找 ja4)
	st.mu.Lock()
	st.binds["tcp|192.168.43.20|50000|198.51.100.80|443"] = &fpBind{fpKey: fpKeyOf(fptJA4A, "h2", "443"), ja4: fptJA4A, mac: fptMAC2, dip: "198.51.100.80", dport: 443, ts: now.Unix(), seen: now.Unix()}
	st.mu.Unlock()
	r = actionDPICorrect(s, map[string]string{"mac": fptMAC2, "dst_ip": "198.51.100.80", "dst_port": "443", "app_id": "game_y", "app_name": "游戏Y", "category": "game", "kinds": "ja4"})
	if !r.OK || !strings.Contains(r.Detail, "指纹 "+fptJA4A) {
		t.Fatalf("ja4 correct: %+v", r)
	}
	st.mu.Lock()
	st.binds["tcp|192.168.43.21|50001|198.51.100.81|443"] = &fpBind{fpKey: fpKeyOf(fptJA4A, "h2", "443"), ja4: fptJA4A, dip: "198.51.100.81", dport: 443, ts: now.Unix(), seen: now.Unix()}
	st.mu.Unlock()
	if fa, ok := st.attribute("tcp|192.168.43.21|50001|198.51.100.81|443", nil, map[string]ipName{}, now); !ok || fa.Src != "user" || fa.App.ID != "game_y" {
		t.Fatalf("ja4 user rule: %+v", fa)
	}
	// 有域名的连接不受指纹规则影响
	if _, ok := st.attribute("tcp|192.168.43.21|50001|198.51.100.81|443", nil, map[string]ipName{"198.51.100.81": {Name: "some.site.com"}}, now); ok {
		t.Fatal("ja4 user rule must not apply to named flows")
	}

	// 列表 + 删除
	lr := actionDPICorrectList(s)
	var list []map[string]interface{}
	if !lr.OK || json.Unmarshal([]byte(lr.Detail), &list) != nil || len(list) != 3 {
		t.Fatalf("list: %+v", lr)
	}
	id := ""
	for _, m := range list {
		if m["kind"] == "domain" {
			id = m["id"].(string)
		}
	}
	if r := actionDPICorrectDel(s, map[string]string{"id": id}); !r.OK {
		t.Fatalf("del: %+v", r)
	}
	if _, ok := dpiUserMatchName("img.video-x.com"); ok {
		t.Fatal("deleted domain rule still applies")
	}
	if r := actionDPICorrectDel(s, map[string]string{"id": id}); r.OK {
		t.Fatal("double delete should fail")
	}
	if r := actionDPICorrectDel(s, map[string]string{"all": "true"}); !r.OK {
		t.Fatalf("del all: %+v", r)
	}
	if rules := readDPIUserRules(dir); len(rules) != 0 {
		t.Fatalf("rules left: %+v", rules)
	}
}

// 模拟设备: 纠正被拒, 它的 ClientHello 不进学习
func TestFPSimMACIgnored(t *testing.T) {
	dir := fptDir(t)
	s := newServer(dir)
	simMAC := simMACPrefix + "12:34:56"
	if r := dispatchAction(s, "dpi_correct", map[string]string{"mac": simMAC, "dst_ip": "203.0.113.9", "app_id": "a", "app_name": "A"}, true); r.OK && !strings.Contains(r.Detail, "模拟") {
		t.Fatalf("sim mac correction should not save: %+v", r)
	}
	if rules := readDPIUserRules(dir); len(rules) != 0 {
		t.Fatalf("sim correction saved: %+v", rules)
	}
	st := fpFor(dir)
	now := time.Unix(1_800_000_000, 0)
	f := &fptFlows{boot: 1}
	for i := 0; i < 80; i++ {
		f.add(simMAC, "192.168.43.200", 30000+i, "203.0.113.1", 443, fptJA4A, "api.app-a.com", "app_a", "video", now.Unix())
	}
	f.write(t, dir)
	st.tick(now, nil)
	if len(st.m) != 0 || st.stats.FlowsSeen != 0 || len(st.binds) != 0 {
		t.Fatalf("sim flows learned: entries=%d stats=%+v", len(st.m), st.stats)
	}
}

// 记账: 指纹/用户纠正的字节另计, /api/app_usage 带 fp_bytes / fp_conf / user_bytes;
// 学习表落盘后重启能读回; /api/dpi_fp 输出
func TestFPAppUsageAndAPI(t *testing.T) {
	dir := fptDir(t)
	s := newServer(dir)
	st := fpFor(dir)
	now := time.Now()
	f := &fptFlows{boot: 1}
	for i := 0; i < 60; i++ {
		f.add(fptMAC1, "192.168.43.10", 30000+i, "203.0.113.1", 443, fptJA4A, "api.app-a.com", "app_a", "video", now.Unix())
	}
	f.add(fptMAC1, "192.168.43.10", 40000, "203.0.113.50", 443, fptJA4A, "", "", "", now.Unix())
	f.write(t, dir)
	st.tick(now, nil)

	owner := map[string]string{"192.168.43.10": fptMAC1}
	d := newDay(now.Format("20060102"))
	ix := &identCtx{st: newIdentState(), now: now, owner: owner, apps: map[string]ipApp{}, names: map[string]ipName{}, sigKey: map[string]bool{}, fp: st}
	deltas := []appUsageDelta{
		{Src: "192.168.43.10", Dst: "203.0.113.50", Up: 100, Dn: 900, Key: "tcp|192.168.43.10|40000|203.0.113.50|443"},
		{Src: "192.168.43.10", Dst: "203.0.113.60", Up: 10, Dn: 90, Key: "tcp|192.168.43.10|40010|203.0.113.60|443"},
	}
	appUsageRecordIdent(d, deltas, owner, ix.apps, ix.names, now, 10, ix)
	mk := fptMAC1 + "|app_a"
	h := strconv.Itoa(now.Hour())
	if d.Hours[h][mk] != [2]uint64{100, 900} || d.FP[mk] != [2]uint64{100, 900} || d.FPW[mk] < 800 {
		t.Fatalf("fp accounting: hours=%v fp=%v fpw=%v", d.Hours[h], d.FP, d.FPW)
	}
	if d.Hours[h][fptMAC1+"|"+appUnknownID] != [2]uint64{10, 90} {
		t.Fatalf("unbound flow should stay unknown: %v", d.Hours[h])
	}
	appUsage.mu.Lock()
	old := appUsage.day
	appUsage.day = d
	appUsage.mu.Unlock()
	t.Cleanup(func() { appUsage.mu.Lock(); appUsage.day = old; appUsage.mu.Unlock() })
	rec := httptest.NewRecorder()
	s.apiAppUsage(rec, httptest.NewRequest("GET", "/api/app_usage?days=1", nil))
	var au struct {
		FP    float64                  `json:"fp_bytes"`
		ByApp []map[string]interface{} `json:"by_app"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &au)
	found := false
	for _, a := range au.ByApp {
		if a["id"] == "app_a" {
			found = true
			if a["fp_bytes"].(float64) != 1000 || a["fp_conf"].(float64) < 0.8 {
				t.Fatalf("by_app: %v", a)
			}
		}
	}
	if au.FP != 1000 || !found {
		t.Fatalf("app_usage: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.apiDPIFP(rec, httptest.NewRequest("GET", "/api/dpi_fp", nil))
	var fp struct {
		OK      bool                     `json:"ok"`
		Learned []map[string]interface{} `json:"learned"`
		Stats   map[string]float64       `json:"stats"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &fp); err != nil || !fp.OK || len(fp.Learned) != 1 {
		t.Fatalf("dpi_fp: %s", rec.Body.String())
	}
	l := fp.Learned[0]
	if l["ja4"] != fptJA4A || l["app_id"] != "app_a" || l["usable"] != true || l["purity"].(float64) != 1 || l["devices"].(float64) != 1 {
		t.Fatalf("learned row: %v", l)
	}
	if fp.Stats["flows_seen"] != 61 || fp.Stats["flows_attributed_by_fp"] != 1 {
		t.Fatalf("stats: %v", fp.Stats)
	}

	// 落盘 + 新进程读回
	st.mu.Lock()
	if err := st.saveLocked(now); err != nil {
		t.Fatal(err)
	}
	st.mu.Unlock()
	st2 := &fpStore{hncDir: dir, m: map[string]*fpEntry{}, binds: map[string]*fpBind{}, pairs: map[string]*fpBind{}}
	st2.mu.Lock()
	st2.loadLocked()
	st2.mu.Unlock()
	if e := st2.m[fpKeyOf(fptJA4A, "h2", "443")]; e == nil || !e.verdict(now.Unix()).Usable || st2.stats.FlowsSeen != 61 {
		t.Fatalf("reload: %+v", e)
	}
	b, _ := os.ReadFile(fpLearnedPath(dir))
	if strings.Contains(string(b), fptMAC1) {
		t.Fatal("learned table must not store raw MACs")
	}
}

// 绑定表有界
func TestFPBindsBounded(t *testing.T) {
	dir := fptDir(t)
	st := fpFor(dir)
	now := time.Unix(1_800_000_000, 0)
	st.mu.Lock()
	defer st.mu.Unlock()
	recs := make([]fpFlowRec, 0, fpMaxBinds+500)
	for i := 0; i < fpMaxBinds+500; i++ {
		recs = append(recs, fpFlowRec{Seq: int64(i + 1), Ts: now.Unix(), CIP: "192.168.43." + strconv.Itoa(i%250+1), Sport: 1024 + i,
			DIP: "203.0.113.1", Dport: 443, Proto: "tcp", JA4: fptJA4A})
	}
	st.ingestLocked(1, recs, nil, now)
	if len(st.binds) > fpMaxBinds {
		t.Fatalf("binds not bounded: %d", len(st.binds))
	}
}
