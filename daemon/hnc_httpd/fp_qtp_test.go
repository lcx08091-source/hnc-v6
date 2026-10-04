package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	fpqJA4  = "q13d0310h3_aaaaaaaaaaaa_bbbbbbbbbbbb" // 同一 QUIC 栈(JA4 相同), 两个 App
	fpqQTPA = "qtp1_aaaaaaaaaaaa"
	fpqQTPB = "qtp1_bbbbbbbbbbbb"
)

func (f *fptFlows) addQUIC(cip string, sport int, dip, sni, app, qtp string, ts int64) {
	f.seq++
	f.recs = append(f.recs, fpFlowRec{Seq: f.seq, Ts: ts, MAC: fptMAC1, CIP: cip, Sport: sport, DIP: dip, Dport: 443,
		Proto: "udp", JA4: fpqJA4, ALPN: "h3", SNI: sni, App: app, AppName: app + "名", Category: "video", QTP: qtp})
}

// JA4 相同、传输参数不同的两个 App: 仅 JA4 时是通用(纯度不够), 带 QTP 后各自可用。
func TestFPQTPLearnAndLookup(t *testing.T) {
	dir := fptDir(t)
	st := fpFor(dir)
	now := time.Unix(1_800_000_000, 0)
	f := &fptFlows{boot: 1}
	for i := 0; i < 60; i++ {
		f.addQUIC("192.168.43.10", 30000+i, "203.0.113.1", "api.app-a.com", "app_a", fpqQTPA, now.Unix())
		f.addQUIC("192.168.43.10", 31000+i, "203.0.113.2", "api.app-b.com", "app_b", fpqQTPB, now.Unix())
	}
	// 目标连接: 无域名, 分别带 A / B 的传输参数; 第三条带一个没学过的 qtp
	f.addQUIC("192.168.43.10", 40000, "203.0.113.50", "", "", fpqQTPA, now.Unix())
	f.addQUIC("192.168.43.10", 40001, "203.0.113.51", "", "", fpqQTPB, now.Unix())
	f.addQUIC("192.168.43.10", 40002, "203.0.113.52", "", "", "qtp1_cccccccccccc", now.Unix())
	f.write(t, dir)
	st.tick(now, nil)

	if _, ok := st.m[fpKeyOf(fpqJA4, "h3", "443")]; ok {
		t.Fatal("带 qtp 的记录不应再学到旧 key")
	}
	ka := fpKeyQ(fpqJA4, "h3", "443", fpqQTPA)
	if e := st.m[ka]; e == nil || e.QTP != fpqQTPA || !e.verdict(now.Unix()).Usable {
		t.Fatalf("qtp A entry: %+v", e)
	}
	fa, ok := st.attribute("udp|192.168.43.10|40000|203.0.113.50|443", nil, nil, now)
	if !ok || fa.Src != "fp" || fa.App.ID != "app_a" {
		t.Fatalf("A: %+v %v", fa, ok)
	}
	fb, ok := st.attribute("udp|192.168.43.10|40001|203.0.113.51|443", nil, nil, now)
	if !ok || fb.App.ID != "app_b" {
		t.Fatalf("B: %+v %v", fb, ok)
	}
	if st.stats.FlowsByQTP != 2 || st.stats.FlowsAttributed != 2 {
		t.Fatalf("stats: %+v", st.stats)
	}
	// 没学过的 qtp、也没有旧 key → 不归属
	if _, ok := st.attribute("udp|192.168.43.10|40002|203.0.113.52|443", nil, nil, now); ok {
		t.Fatal("unknown qtp without legacy entry must not attribute")
	}

	// 回落: 旧版学到的 QUIC 条目(无 qtp)在 qtp 条目缺失时兜底
	st.mu.Lock()
	st.m[fpKeyOf(fpqJA4, "h3", "443")] = &fpEntry{JA4: fpqJA4, ALPN: "h3", Port: "443",
		Apps: map[string]*fpAppCount{"legacy_app": {N: 80, Name: "旧应用", Category: "video"}}, Total: 80, Upd: now.Unix()}
	st.mu.Unlock()
	if fc, ok := st.attribute("udp|192.168.43.10|40002|203.0.113.52|443", nil, nil, now); !ok || fc.App.ID != "legacy_app" {
		t.Fatalf("fallback to legacy key: %+v %v", fc, ok)
	}
	// 有可用 qtp 条目时不回落
	if fa, _ := st.attribute("udp|192.168.43.10|40000|203.0.113.50|443", nil, nil, now); fa.App.ID != "app_a" {
		t.Fatalf("qtp entry should win: %+v", fa)
	}
	// 落盘 → 新进程加载: qtp 条目 key 不变
	st.mu.Lock()
	if err := st.saveLocked(now); err != nil {
		t.Fatal(err)
	}
	st.mu.Unlock()
	st2 := &fpStore{hncDir: dir, m: map[string]*fpEntry{}, binds: map[string]*fpBind{}, pairs: map[string]*fpBind{}}
	st2.loadLocked()
	if e := st2.m[ka]; e == nil || e.QTP != fpqQTPA {
		t.Fatalf("reload qtp entry: %+v", e)
	}
}

// qtp 条目判为通用 → 回落旧 key; 旧 key 也没有 → 计 generic_skipped(不用种子)
func TestFPQTPGenericFallsBack(t *testing.T) {
	dir := fptDir(t)
	st := fpFor(dir)
	now := time.Unix(1_800_000_000, 0)
	f := &fptFlows{boot: 1}
	for i := 0; i < 30; i++ {
		f.addQUIC("192.168.43.10", 30000+i, "203.0.113.1", "api.app-a.com", "app_a", fpqQTPA, now.Unix())
		f.addQUIC("192.168.43.10", 31000+i, "203.0.113.2", "www.random-site.net", "", fpqQTPA, now.Unix()) // _other
	}
	f.addQUIC("192.168.43.10", 40000, "203.0.113.50", "", "", fpqQTPA, now.Unix())
	f.write(t, dir)
	st.tick(now, nil)
	if _, ok := st.attribute("udp|192.168.43.10|40000|203.0.113.50|443", nil, nil, now); ok {
		t.Fatal("generic qtp must not attribute")
	}
	if st.stats.GenericSkipped != 1 {
		t.Fatalf("generic_skipped=%d", st.stats.GenericSkipped)
	}
}

// 旧版 fp_learned.json(没有 qtp 字段)照常加载, key 与旧版一致
func TestFPLoadOldLearnedFile(t *testing.T) {
	dir := fptDir(t)
	old := `{"schema":1,"saved_at":1,"stats":{"flows_seen":3},"entries":[
	 {"ja4":"` + fptJA4A + `","alpn":"h2","port":"443","apps":{"app_a":{"n":60,"name":"A","category":"video"}},"total":60,"first":1,"last":1,"upd":1800000000}]}`
	if err := os.WriteFile(filepath.Join(dir, "data", "fp_learned.json"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	st := &fpStore{hncDir: dir, m: map[string]*fpEntry{}, binds: map[string]*fpBind{}, pairs: map[string]*fpBind{}}
	st.loadLocked()
	e := st.m[fpKeyOf(fptJA4A, "h2", "443")]
	if e == nil || e.QTP != "" || !e.verdict(1_800_000_000).Usable || st.stats.FlowsSeen != 3 {
		t.Fatalf("old file: %+v", e)
	}
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), `"qtp"`) {
		t.Fatalf("无 qtp 的条目不应写出 qtp 字段: %s", b)
	}
}

// 识别自评 quic 段: 只统计 quic 样本; 「仅 JA4」认不出(通用), 「含传输参数」认得出。
func TestEvalQUICSection(t *testing.T) {
	dir := evalDir(t)
	now := time.Unix(1_800_000_000, 0)
	writePkgMap(t, dir, map[string]string{"com.a": "app_a", "com.b": "app_b"})
	writeRules(t, dir, map[string]string{"app_a": "A", "app_b": "B"})
	st := fpFor(dir)
	st.mu.Lock()
	st.loaded = true
	mk := func(qtp, app string, n float64) *fpEntry {
		return &fpEntry{JA4: fpqJA4, ALPN: "h3", Port: "443", QTP: qtp,
			Apps: map[string]*fpAppCount{app: {N: n, Name: app, Category: "video"}}, Total: n, Upd: now.Unix()}
	}
	st.m[fpKeyQ(fpqJA4, "h3", "443", fpqQTPA)] = mk(fpqQTPA, "app_a", 100)
	st.m[fpKeyQ(fpqJA4, "h3", "443", fpqQTPB)] = mk(fpqQTPB, "app_b", 100)
	legacy := mk("", "app_a", 50)
	legacy.Apps["app_b"] = &fpAppCount{N: 50, Name: "app_b", Category: "video"}
	legacy.Total = 100
	st.m[fpKeyOf(fpqJA4, "h3", "443")] = legacy // 仅 JA4: 两家各半 → 通用
	st.mu.Unlock()

	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.a", UID: 10100, JA4: fpqJA4, ALPN: "h3", DPort: 443, QUIC: true, QTP: fpqQTPA})
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.b", UID: 10101, JA4: fpqJA4, ALPN: "h3", DPort: 443, QUIC: true, QTP: fpqQTPB})
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.b", UID: 10101, JA4: fpqJA4, ALPN: "h3", DPort: 443, QUIC: true}) // 旧样本无 qtp
	appendSample(t, dir, now, evalSample{Ts: now.Unix(), Pkg: "com.a", UID: 10100, JA4: fptJA4A, ALPN: "h2", DPort: 443})            // TCP 不计

	res := evalDPI(dir, 1, now)
	q := res.QUIC
	if q.Samples != 3 || q.QTPSeen != 2 {
		t.Fatalf("quic: %+v", q)
	}
	if q.JA4Only.Coverage != 0 || q.JA4Only.Judged != 0 {
		t.Fatalf("ja4 only: %+v", q.JA4Only)
	}
	if q.WithQTP.Coverage != round2(2.0/3.0) || q.WithQTP.Accuracy != 1 || q.WithQTP.Judged != 2 {
		t.Fatalf("with qtp: %+v", q.WithQTP)
	}
	if fp := res.Methods["fp"]; fp.Predicted != 2 || fp.Correct != 2 {
		t.Fatalf("fp method should use qtp: %+v", fp)
	}
	b, _ := json.Marshal(res)
	if !strings.Contains(string(b), `"fp_ja4_only"`) || !strings.Contains(string(b), `"fp_with_qtp"`) {
		t.Fatalf("json: %s", b)
	}
}
