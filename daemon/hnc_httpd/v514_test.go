package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppTierMatchesDpid(t *testing.T) {
	cases := map[string]int{"video": tierApp, "": tierApp, "ads": tierHidden, "sdk-tencent-game": tierHidden,
		"cdn": tierHidden, "cloud": tierHidden, "system": tierSystem, "system-oppo": tierSystem, "system_chipset": tierHidden}
	for c, want := range cases {
		if got := appTier(c); got != want {
			t.Errorf("appTier(%q)=%d want %d", c, got, want)
		}
	}
}

func resetConnState() {
	ctState.mu.Lock()
	ctState.snap, ctState.prev, ctState.acctTried = nil, nil, true
	ctState.mu.Unlock()
	liveAppState.mu.Lock()
	liveAppState.m, liveAppState.snapAt, liveAppState.lastAt = nil, time.Time{}, time.Time{}
	liveAppState.mu.Unlock()
}

// 把快照与速率基线往回拨 dt, 模拟"过了 dt 秒再读 conntrack"
func ageConnState(dt time.Duration) {
	ctState.mu.Lock()
	ctState.snap.at = ctState.snap.at.Add(-dt)
	for k, p := range ctState.prev {
		p.at = p.at.Add(-dt)
		ctState.prev[k] = p
	}
	ctState.mu.Unlock()
	liveAppState.mu.Lock()
	liveAppState.lastAt = liveAppState.lastAt.Add(-dt)
	liveAppState.mu.Unlock()
}

func TestLiveAppsAndDNSCorrelation(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "run"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	w := func(p, s string) {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("data/devices.json", `{"aa:bb:cc:00:00:01":{"ip":"192.168.43.12","last_seen":1}}`)
	// 9.9.9.9: 只有 DNS 反查 → 靠 DNS 关联归到哔哩哔哩(典型: QUIC 看不到 SNI)
	// 1.1.1.1: 规则直接命中的 SDK(友盟) → 不算应用
	// 2.2.2.2: 系统服务 → 有真应用时不显示
	w("run/dpi_ipname.json", `{"schema":1,"entries":{"9.9.9.9":{"name":"upos.bilivideo.com","src":"dns","ts":1,"app":"bilibili","app_name":"哔哩哔哩","category":"video"}}}`)
	w("run/ip_app_map.json", `{"entries":[{"ip":"1.1.1.1","app_id":"umeng","name":"友盟","category":"third_party_telemetry"},{"ip":"2.2.2.2","app_id":"oppo","name":"OPPO 系统","category":"system"}]}`)
	w("run/dpi_state.json", `{"clients":{"k":{"client_mac":"aa:bb:cc:00:00:01","top_apps":[
		{"id":"umeng","name":"友盟","category":"third_party_telemetry","count":900,"last_seen":1},
		{"id":"douyin","name":"抖音","category":"video","count":500,"last_seen":1},
		{"id":"oppo","name":"OPPO 系统","category":"system","count":800,"last_seen":1},
		{"id":"wechat","name":"微信","category":"social","count":10,"last_seen":`+itoa(int(time.Now().Unix()))+`}]}}}`)
	t.Setenv("HNC_CONNTRACK_PATH", filepath.Join(dir, "ct"))
	t.Setenv("HNC_CONNTRACK_ACCT_PATH", filepath.Join(dir, "acct"))
	ct := func(bili, sdk, sys int) {
		l := func(dst string, dport, dn int) string {
			return "ipv4 2 udp 17 100 src=192.168.43.12 dst=" + dst + " sport=5000 dport=" + itoa(dport) +
				" packets=1 bytes=100 src=" + dst + " dst=10.0.0.1 sport=" + itoa(dport) + " dport=5000 packets=1 bytes=" + itoa(dn) + " mark=0 use=1\n"
		}
		w("ct", l("9.9.9.9", 443, bili)+l("1.1.1.1", 443, sdk)+l("2.2.2.2", 443, sys))
	}
	resetConnState()
	s := newServer(dir)
	ct(0, 0, 0)
	_ = s.liveAppsByMAC()
	for i := 1; i <= 15; i++ { // 30 秒: 哔哩哔哩 500KB/s, SDK 50KB/s, 系统 20KB/s
		ageConnState(2 * time.Second)
		ct(i*1_000_000, i*100_000, i*40_000)
		_ = s.liveAppsByMAC()
	}
	la := s.liveAppsByMAC()["aa:bb:cc:00:00:01"]
	if len(la) != 1 || la[0]["id"] != "bilibili" {
		t.Fatalf("live apps = %v, want only bilibili (SDK hidden, system suppressed)", la)
	}
	if bps := la[0]["bps"].(int64); bps < 2_000_000 || bps > 4_200_000 {
		t.Fatalf("bilibili ewma bps = %d, want ~2.8M after 1.5 tau", bps)
	}
	// 停止流量 2 分钟以上 → 衰减消失
	for i := 0; i < 70; i++ {
		ageConnState(2 * time.Second)
		_ = s.liveAppsByMAC()
	}
	if la := s.liveAppsByMAC()["aa:bb:cc:00:00:01"]; len(la) != 0 {
		t.Fatalf("idle apps should decay away, got %v", la)
	}

	// dpi_apps: SDK 过滤, 真应用在系统服务前, 最近出现的排前
	apps := s.dpiAppsByMAC()["aa:bb:cc:00:00:01"]
	var ids []string
	for _, a := range apps {
		ids = append(ids, asString(a["id"]))
	}
	if len(ids) != 3 || ids[0] != "wechat" || ids[1] != "douyin" || ids[2] != "oppo" {
		t.Fatalf("dpi_apps order = %v", ids)
	}
}
