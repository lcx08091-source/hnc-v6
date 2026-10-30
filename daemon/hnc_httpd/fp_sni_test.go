package main

// fp_sni_test.go — v5.34 连接自己的 SNI 优先归属 + 共享 IP 统计。
// 「改动前会失败」: 归属只看「目的 IP → 域名」全局表, 同一个 CDN IP 上两个 App 的连接
// 都算成表里那个; fpBind 不带 SNI, 没有 connSNI / 共享 IP 统计。

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

const (
	sniCDN   = "203.0.113.80" // 两个 App 共用的 CDN IP
	sniKeyDY = "tcp|192.168.43.10|41000|203.0.113.80|443"
	sniKeyTB = "tcp|192.168.43.11|41001|203.0.113.80|443"
)

// 两台设备、两个 App 连同一个 CDN IP; 全局表里这个 IP 记的是淘宝的名字
func sniFixture(t *testing.T) (string, *fpStore, map[string]ipName, time.Time) {
	t.Helper()
	dir := fptDir(t)
	st := fpFor(dir)
	// 真实当前时间: 用户 IP 规则的 7 天有效期与 /api/dpi_fp 的统计窗口都按真实时间算
	now := time.Unix(time.Now().Unix(), 0)
	f := &fptFlows{boot: 1}
	f.add(fptMAC1, "192.168.43.10", 41000, sniCDN, 443, fptJA4A, "v3-dy.douyinvod.com", "douyin", "video", now.Unix())
	f.add(fptMAC2, "192.168.43.11", 41001, sniCDN, 443, fptJA4Gen, "img.alicdn-tb.com", "taobao", "shopping", now.Unix())
	// SNI 规则库认不出
	f.add(fptMAC1, "192.168.43.10", 41002, sniCDN, 443, fptJA4A, "x.unknown-cdn.net", "", "", now.Unix())
	// ECH 外层
	f.seq++
	f.recs = append(f.recs, fpFlowRec{Seq: f.seq, Ts: now.Unix(), MAC: fptMAC1, CIP: "192.168.43.10", Sport: 41003, DIP: sniCDN,
		Dport: 443, Proto: "tcp", JA4: fptJA4A, ALPN: "h2", SNI: "cloudflare-ech.com", ECHOuter: true, App: "cf", Category: "cdn"})
	f.write(t, dir)
	names := map[string]ipName{sniCDN: {Name: "img.alicdn-tb.com", Src: "sni", App: "taobao", AppName: "淘宝", Category: "shopping"}}
	st.tick(now, names)
	return dir, st, names, now
}

func TestSNIAttrBeatsSharedIPTable(t *testing.T) {
	_, st, names, now := sniFixture(t)
	fa, ok := st.attribute(sniKeyDY, nil, names, now)
	if !ok || fa.Src != "sni" || fa.App.ID != "douyin" || fa.App.Name != "douyin名" {
		t.Fatalf("抖音的连接应按它自己的 SNI 归抖音: %+v %v", fa, ok)
	}
	if fa, ok := st.attribute(sniKeyTB, nil, names, now); !ok || fa.Src != "sni" || fa.App.ID != "taobao" {
		t.Fatalf("淘宝的连接: %+v %v", fa, ok)
	}
	// SNI 认不出 / ECH 外层 → 照旧走全局表
	if fa, ok := st.attribute("tcp|192.168.43.10|41002|203.0.113.80|443", nil, names, now); !ok || fa.Src != "name" || fa.App.ID != "taobao" {
		t.Fatalf("SNI 认不出时应退回全局表: %+v", fa)
	}
	if fa, ok := st.attribute("tcp|192.168.43.10|41003|203.0.113.80|443", nil, names, now); !ok || fa.Src != "name" || fa.App.ID != "taobao" {
		t.Fatalf("ECH 外层不能当真实 SNI: %+v", fa)
	}
	// 同设备同目的同端口、但不是这条连接的 ClientHello(只有近似绑定)→ 不按别人的 SNI 归
	if fa, ok := st.attribute("tcp|192.168.43.10|41099|203.0.113.80|443", nil, names, now); !ok || fa.Src != "name" {
		t.Fatalf("近似绑定不应借用别的连接的 SNI: %+v", fa)
	}
	// 规则库的 IP 规则(ip_app_map)也排在连接自己的 SNI 后面
	apps := map[string]ipApp{sniCDN: {ID: "ip_rule_app", Name: "IP规则", Category: "video"}}
	if fa, ok := st.attribute(sniKeyDY, apps, names, now); !ok || fa.App.ID != "douyin" {
		t.Fatalf("连接 SNI 应压过全局 IP 规则: %+v", fa)
	}
	// 连接列表显示这条连接自己的域名
	if st.connSNI(sniKeyDY) != "v3-dy.douyinvod.com" || st.connSNI("tcp|192.168.43.10|41003|203.0.113.80|443") != "" {
		t.Fatal("connSNI")
	}
}

func TestSNIAttrUserRules(t *testing.T) {
	dir, st, names, now := sniFixture(t)
	s := newServer(dir)
	// 用户域名规则匹配连接自己的 SNI → user
	r := actionDPICorrect(s, map[string]string{"name": "douyinvod.com", "app_id": "dy_user", "app_name": "我的抖音", "category": "video", "kinds": "domain"})
	if !r.OK {
		t.Fatalf("correct: %+v", r)
	}
	if fa, ok := st.attribute(sniKeyDY, nil, names, now); !ok || fa.Src != "user" || fa.App.ID != "dy_user" || fa.Conf != 1 {
		t.Fatalf("SNI 上的用户域名规则: %+v", fa)
	}
	// 用户 IP 规则仍然最先
	r = actionDPICorrect(s, map[string]string{"dst_ip": sniCDN, "app_id": "ip_user", "app_name": "IP纠正", "category": "game", "kinds": "ip"})
	if !r.OK {
		t.Fatalf("correct ip: %+v", r)
	}
	if fa, ok := st.attribute(sniKeyDY, nil, names, now); !ok || fa.App.ID != "ip_user" {
		t.Fatalf("用户 IP 规则应最先: %+v", fa)
	}
}

func TestSNIAttrStatsAndSharedIP(t *testing.T) {
	dir, st, names, now := sniFixture(t)
	for i := 0; i < 3; i++ { // 每轮都会调; 每条连接只计一次
		st.attribute(sniKeyDY, nil, names, now)
		st.attribute(sniKeyTB, nil, names, now)
	}
	st.mu.Lock()
	by, ov := st.stats.FlowsBySNI, st.stats.SNIOverrodeIP
	st.mu.Unlock()
	if by != 2 || ov != 1 {
		t.Fatalf("by_sni=%d overrode=%d, 期望 2 / 1(只有抖音那条和全局表结论不同)", by, ov)
	}
	// 另一个 IP 只有一个 App; 广告 / CDN 档与过期的不算
	f := &fptFlows{boot: 1, seq: 100}
	f.add(fptMAC1, "192.168.43.10", 42000, "203.0.113.90", 443, fptJA4A, "api.wechat-x.com", "wechat", "social", now.Unix())
	f.add(fptMAC1, "192.168.43.10", 42001, "203.0.113.90", 443, fptJA4A, "ad.track-x.com", "adx", "ads", now.Unix())
	f.add(fptMAC1, "192.168.43.10", 42002, "203.0.113.90", 443, fptJA4A, "old.game-x.com", "game_x", "game", now.Unix()-fpSharedWindowSec-60)
	f.write(t, dir)
	st.tick(now, names)
	st.mu.Lock()
	ips, conflicts, ex := st.sharedIPLocked(now.Unix())
	st.mu.Unlock()
	if ips != 2 || conflicts != 1 || len(ex) != 1 || ex[0]["ip"] != sniCDN {
		t.Fatalf("shared ip: ips=%d conflicts=%d ex=%v", ips, conflicts, ex)
	}

	rec := httptest.NewRecorder()
	newServer(dir).apiDPIFP(rec, httptest.NewRequest("GET", "/api/dpi_fp", nil))
	var resp struct {
		Stats    map[string]float64 `json:"stats"`
		SharedIP struct {
			IPs, ConflictIPs int
			Share            float64
			Examples         []struct {
				IP   string   `json:"ip"`
				Apps []string `json:"apps"`
			}
		} `json:"shared_ip"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("dpi_fp: %v %s", err, rec.Body.String())
	}
	if resp.Stats["flows_attributed_by_sni"] != 2 || resp.Stats["sni_overrode_ip"] != 1 {
		t.Fatalf("stats: %v", resp.Stats)
	}
	if resp.SharedIP.Share != 0.5 || len(resp.SharedIP.Examples) != 1 || len(resp.SharedIP.Examples[0].Apps) != 2 {
		t.Fatalf("shared_ip: %s", rec.Body.String())
	}
}

// 记账: 同一个 CDN IP 上两台设备的字节分别记到各自真正的 App
func TestSNIAttrAppUsageAccounting(t *testing.T) {
	_, st, names, now := sniFixture(t)
	owner := map[string]string{"192.168.43.10": fptMAC1, "192.168.43.11": fptMAC2}
	d := newDay(now.Format("20060102"))
	ix := &identCtx{st: newIdentState(), now: now, owner: owner, apps: map[string]ipApp{}, names: names, sigKey: map[string]bool{}, fp: st}
	deltas := []appUsageDelta{
		{Src: "192.168.43.10", Dst: sniCDN, Up: 100, Dn: 5000, Key: sniKeyDY},
		{Src: "192.168.43.11", Dst: sniCDN, Up: 50, Dn: 700, Key: sniKeyTB},
	}
	appUsageRecordIdent(d, deltas, owner, ix.apps, ix.names, now, 10, ix)
	h := strconv.Itoa(now.Hour())
	if d.Hours[h][fptMAC1+"|douyin"] != [2]uint64{100, 5000} || d.Hours[h][fptMAC2+"|taobao"] != [2]uint64{50, 700} {
		t.Fatalf("记账: %v", d.Hours[h])
	}
	if _, bad := d.Hours[h][fptMAC1+"|taobao"]; bad {
		t.Fatalf("抖音的字节不应记到淘宝: %v", d.Hours[h])
	}
}
