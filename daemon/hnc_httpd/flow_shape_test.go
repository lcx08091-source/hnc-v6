package main

import (
	"fmt"
	"testing"
	"time"
)

// smp 一个完整样本: dt 秒内 上/下行字节与包数
func smp(dt float64, up, dn, upP, dnP uint64) fsSample {
	return fsSample{dt: dt, up: up, dn: dn, upP: upP, dnP: dnP, hasPkts: true}
}

// series 按下行字节序列造样本: 上行 = 下行 × upRatio, 下行包长 psz, 上行包数 = 下行包数/2(ACK)
func series(dt float64, dn []uint64, upRatio float64, psz uint64) []fsSample {
	var out []fsSample
	for _, d := range dn {
		dp := d / psz
		up := uint64(float64(d) * upRatio)
		out = append(out, smp(dt, up, d, dp/2+1, dp+1))
	}
	return out
}

func repeat(s fsSample, n int) []fsSample {
	out := make([]fsSample, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func TestClassifyFlowShapeTable(t *testing.T) {
	tcp443 := fsHint{proto: "tcp", dport: 443}
	quic := fsHint{proto: "udp", dport: 443}
	rtp := fsHint{proto: "udp", dport: 31000}
	steady3M := series(10, []uint64{3_750_000, 3_600_000, 3_900_000, 3_700_000, 3_800_000, 3_650_000}, 0.02, 1400)
	chunky := series(10, []uint64{6_000_000, 100_000, 5_000_000, 50_000, 6_000_000, 100_000}, 0.02, 1400)
	onOff := series(10, []uint64{6_000_000, 0, 5_500_000, 0, 6_000_000, 0}, 0.02, 1400)
	cases := []struct {
		name    string
		ss      []fsSample
		h       fsHint
		want    string
		minConf float64
	}{
		{"video chunked", chunky, tcp443, ttVideo, 0.6},
		{"video on/off + category", onOff, fsHint{proto: "tcp", dport: 443, category: "video"}, ttVideo, 0.85},
		{"video over QUIC (acks ≪ 0.3)", chunky, quic, ttVideo, 0.6},
		{"live steady 3 Mbps", steady3M, tcp443, ttLive, 0.5},
		{"live + video category", steady3M, fsHint{proto: "tcp", dport: 443, category: "video"}, ttLive, 0.7},
		{"steady 3 Mbps download category", steady3M, fsHint{proto: "tcp", dport: 443, category: "download"}, ttDownload, 0.6},
		{"live over UDP (one-way RTP)", steady3M, rtp, ttLive, 0.5},
		{"bulk download 40 Mbps", series(10, []uint64{50e6, 52e6, 49e6, 51e6, 50e6, 50e6}, 0.02, 1450), tcp443, ttDownload, 0.8},
		{"fast VOD prebuffer (video cat)", series(10, []uint64{50e6, 52e6, 49e6}, 0.02, 1450), fsHint{proto: "tcp", category: "video"}, ttVideo, 0.6},
		{"upload 2 Mbps", repeat(smp(10, 2_500_000, 60_000, 1800, 900), 6), tcp443, ttUpload, 0.6},
		{"voice call 50pps×140B", repeat(smp(10, 70_000, 70_000, 500, 500), 6), rtp, ttVoice, 0.7},
		{"voice call social", repeat(smp(10, 70_000, 70_000, 500, 500), 6), fsHint{proto: "udp", dport: 8000, category: "social"}, ttVoice, 0.85},
		{"video call 1.2/0.6 Mbps", repeat(smp(10, 750_000, 1_500_000, 750, 1500), 6), rtp, ttVideoCall, 0.75},
		{"video call asymmetric (cam off one side)", repeat(smp(10, 250_000, 1_500_000, 400, 1500), 6), rtp, ttVideoCall, 0.65},
		{"gaming 20pps×80B", repeat(smp(10, 16_000, 16_000, 200, 200), 6), fsHint{proto: "udp", dport: 10012}, ttGaming, 0.65},
		{"gaming by category (voice-like shape)", repeat(smp(10, 70_000, 70_000, 500, 500), 6), fsHint{proto: "udp", dport: 10012, category: "game"}, ttGaming, 0.85},
		{"gaming over TCP (category)", repeat(smp(10, 8_000, 12_000, 100, 100), 6), fsHint{proto: "tcp", dport: 9000, category: "game"}, ttGaming, 0.6},
		{"background heartbeat", []fsSample{smp(10, 100, 100, 1, 1), smp(10, 0, 0, 0, 0), smp(10, 100, 100, 1, 1), smp(10, 0, 0, 0, 0), smp(10, 100, 100, 1, 1), smp(10, 0, 0, 0, 0)}, tcp443, ttBackground, 0.8},
		{"browsing bursty", series(10, []uint64{200_000, 0, 50_000, 300_000, 0, 10_000}, 0.1, 1000), tcp443, ttBrowsing, 0.6},
		{"browsing image-heavy (below video avg)", series(10, []uint64{600_000, 0, 0, 0, 0, 0}, 0.05, 1200), tcp443, ttBrowsing, 0.4},
		{"DNS bidirectional is not a call", repeat(smp(10, 30_000, 30_000, 300, 300), 6), fsHint{proto: "udp", dport: 53}, ttBrowsing, 0.5},
		{"one complete sample → unknown", series(10, []uint64{3_000_000}, 0.02, 1400), tcp443, ttUnknown, 0},
		{"steady but < 30 s → not yet live", steady3M[:2], tcp443, ttBrowsing, 0.4},
		{"partial-only huge burst", []fsSample{{dt: 10, dn: 40_000_000, partial: true}}, tcp443, ttDownload, 0.4},
		{"no samples", nil, tcp443, ttUnknown, 0},
	}
	for _, c := range cases {
		got, conf := classifyFlowShape(fsFeaturesOf(c.ss), c.h)
		t.Logf("%-42s → %s %.2f", c.name, got, conf)
		if got != c.want || conf < c.minConf || conf > 0.95 {
			f := fsFeaturesOf(c.ss)
			t.Errorf("%s: got %s/%.2f want %s/≥%.2f (feat %+v)", c.name, got, conf, c.want, c.minConf, f)
		}
	}
}

// 采样慢(省电档 60 s)时同样能判, 但置信度打折
func TestClassifyFlowShapeSlowTicks(t *testing.T) {
	fast := series(10, []uint64{6_000_000, 100_000, 5_000_000, 50_000, 6_000_000, 100_000}, 0.02, 1400)
	slow := series(60, []uint64{36_000_000, 600_000, 30_000_000, 300_000, 36_000_000, 600_000}, 0.02, 1400)
	t1, c1 := classifyFlowShape(fsFeaturesOf(fast), fsHint{proto: "tcp", dport: 443})
	t2, c2 := classifyFlowShape(fsFeaturesOf(slow), fsHint{proto: "tcp", dport: 443})
	if t1 != ttVideo || t2 != ttVideo || !(c2 < c1) {
		t.Fatalf("fast %s/%.2f slow %s/%.2f", t1, c1, t2, c2)
	}
	// 不等间隔(10/30/10 s 混合)仍按速率算
	mixed := []fsSample{smp(10, 70_000, 70_000, 500, 500), smp(30, 210_000, 210_000, 1500, 1500), smp(10, 70_000, 70_000, 500, 500)}
	if tt, _ := classifyFlowShape(fsFeaturesOf(mixed), fsHint{proto: "udp", dport: 40000}); tt != ttVoice {
		t.Fatalf("mixed dt voice: %s", tt)
	}
}

// ─── 状态机 ───────────────────────────────────────────────────────────

const fsMAC = "aa:bb:cc:dd:ee:01"

var fsOwner = map[string]string{"192.168.43.10": fsMAC}

type fsFlowSim struct {
	e ctEntry
}

func newSimFlow(proto, dst string, sport, dport int) *fsFlowSim {
	return &fsFlowSim{e: ctEntry{Family: "ipv4", Proto: proto, Src: "192.168.43.10", Dst: dst, Sport: sport, Dport: dport, Acct: true}}
}

func (f *fsFlowSim) add(up, dn, upP, dnP uint64) ctEntry {
	f.e.UpB += up
	f.e.DnB += dn
	f.e.UpPkts += upP
	f.e.DnPkts += dnP
	return f.e
}

func TestFlowShapeStateVideoAndHysteresis(t *testing.T) {
	st := newFSState()
	t0 := time.Unix(1_800_000_000, 0)
	v := newSimFlow("tcp", "20.0.0.1", 40000, 443)
	cat := func(string) string { return "" }
	// 第 0 轮: 基线
	st.observe(t0, []ctEntry{v.add(1000, 1000, 10, 10)}, nil, fsOwner, cat)
	// 8 轮稳定 3 Mbps → 直播
	at := t0
	for i := 0; i < 8; i++ {
		at = at.Add(10 * time.Second)
		st.observe(at, []ctEntry{v.add(75_000, 3_750_000, 1300, 2680)}, nil, fsOwner, cat)
	}
	fl := st.flows[v.e.key()]
	if fl == nil || fl.typ != ttLive {
		t.Fatalf("flow type %+v", fl)
	}
	d := st.devs[fsMAC]
	if d.typ != ttLive {
		t.Fatalf("device %s", d.typ)
	}
	liveSince := d.since
	// 切到 40 Mbps 下载: 第一轮只是候选(防抖), 之后才切换
	sw := 0
	for i := 0; i < 8; i++ {
		at = at.Add(10 * time.Second)
		st.observe(at, []ctEntry{v.add(1_000_000, 50_000_000, 17000, 34500)}, nil, fsOwner, cat)
		if st.devs[fsMAC].typ == ttDownload && sw == 0 {
			sw = i + 1
		}
	}
	if st.devs[fsMAC].typ != ttDownload {
		t.Fatalf("device should become download, is %s", st.devs[fsMAC].typ)
	}
	if !st.devs[fsMAC].since.After(liveSince) {
		t.Fatal("since must move on switch")
	}
	// 窗口里新旧混合时 cv 高 → 中间会出现别的候选; 但单轮的候选不会立刻替换
	st2 := newFSState()
	d2 := &fsDev{typ: ttLive, since: t0}
	st2.devStep(d2, ttVideo, 0.7, t0.Add(10*time.Second))
	if d2.typ != ttLive {
		t.Fatal("one tick must not switch")
	}
	st2.devStep(d2, ttDownload, 0.7, t0.Add(20*time.Second)) // 候选变了: 重新计数
	if d2.typ != ttLive {
		t.Fatal("changing candidate must restart count")
	}
	st2.devStep(d2, ttDownload, 0.7, t0.Add(30*time.Second))
	if d2.typ != ttDownload || !d2.since.Equal(t0.Add(20*time.Second)) {
		t.Fatalf("switch after 2 consistent ticks, since = first: %s %v", d2.typ, d2.since)
	}
	st2.devStep(d2, ttUnknown, 0, t0.Add(40*time.Second))
	if d2.typ != ttDownload {
		t.Fatal("unknown must not override")
	}
}

// 视频 App 每个分片新开一条连接、拉完就销毁(DESTROY): 单条连接判不出, 设备级序列判得出
func TestFlowShapeShortChunkConnectionsWithDestroy(t *testing.T) {
	st := newFSState()
	t0 := time.Unix(1_800_000_000, 0)
	st.observe(t0, nil, nil, fsOwner, nil)
	at := t0
	var types []string
	for i := 0; i < 8; i++ {
		at = at.Add(10 * time.Second)
		f := newSimFlow("tcp", fmt.Sprintf("20.0.1.%d", i), 41000+i, 443)
		var ents []ctEntry
		var evs []ctDestroy
		if i%2 == 0 {
			// 本轮新建并在快照前就结束: 只有 DESTROY 事件(从没被快照看到)
			e := f.add(60_000, 5_000_000, 1800, 3600)
			evs = append(evs, ctDestroy{Key: e.key(), Src: e.Src, Dst: e.Dst, UpB: e.UpB, DnB: e.DnB, HasCnt: true, At: at.Add(-2 * time.Second)})
			if i == 4 {
				ents = append(ents, e) // 快照里残留的旧读数: 不得重复计
			}
		} else {
			ents = append(ents, f.add(2_000, 80_000, 40, 60))
		}
		st.observe(at, ents, evs, fsOwner, nil)
		types = append(types, st.devs[fsMAC].typ)
	}
	if got := st.devs[fsMAC].typ; got != ttVideo {
		t.Fatalf("device type = %s (history %v, samples %+v)", got, types, st.devs[fsMAC].samples)
	}
	var dn uint64
	for _, s := range st.devs[fsMAC].samples {
		dn += s.dn
	}
	if dn != 3*5_000_000+3*80_000 { // 第 2..7 轮; 第 4 轮快照残留的旧读数不得重复计
		t.Fatalf("device window dn = %d", dn)
	}
	// 每条单独的连接都是 1–2 个部分样本: 不会被误判成别的
	for k, fl := range st.flows {
		if fl.typ != ttUnknown && fl.typ != "" {
			t.Errorf("short flow %s typed %s", k, fl.typ)
		}
	}
}

func TestFlowShapeDestroyFreezesAndExpires(t *testing.T) {
	st := newFSState()
	t0 := time.Unix(1_800_000_000, 0)
	g := newSimFlow("udp", "20.0.0.9", 50000, 10012)
	st.observe(t0, []ctEntry{g.add(100, 100, 1, 1)}, nil, fsOwner, func(string) string { return "game" })
	at := t0
	for i := 0; i < 5; i++ {
		at = at.Add(10 * time.Second)
		st.observe(at, []ctEntry{g.add(16_000, 16_000, 200, 200)}, nil, fsOwner, nil)
	}
	k := g.e.key()
	if st.flows[k].typ != ttGaming || st.devs[fsMAC].typ != ttGaming {
		t.Fatalf("gaming: flow %s dev %s", st.flows[k].typ, st.devs[fsMAC].typ)
	}
	// 连接结束: DESTROY 带最终字节, 快照里还残留旧读数
	at = at.Add(10 * time.Second)
	fin := g.add(3_000, 3_000, 40, 40)
	stale := fin
	stale.UpB, stale.DnB = fin.UpB-3_000, fin.DnB-3_000
	st.observe(at, []ctEntry{stale}, []ctDestroy{{Key: k, Src: fin.Src, Dst: fin.Dst, UpB: fin.UpB, DnB: fin.DnB, HasCnt: true, At: at.Add(-time.Second)}}, fsOwner, nil)
	fl := st.flows[k]
	if fl == nil || !fl.ended || fl.typ != ttGaming {
		t.Fatalf("ended flow must keep its type: %+v", fl)
	}
	if n := len(fl.samples); n == 0 || !fl.samples[n-1].partial || fl.samples[n-1].up != 3_000 {
		t.Fatalf("tail sample %+v", fl.samples)
	}
	// 窗口过后丢弃; 设备回到空闲
	for i := 0; i < 8; i++ {
		at = at.Add(10 * time.Second)
		st.observe(at, nil, nil, fsOwner, nil)
	}
	if _, ok := st.flows[k]; ok {
		t.Fatal("ended flow must expire")
	}
	if d := st.devs[fsMAC]; d != nil && d.typ != ttIdle {
		t.Fatalf("device after silence: %s", d.typ)
	}
}

func TestFlowShapeDevicePriorityAndIdle(t *testing.T) {
	st := newFSState()
	t0 := time.Unix(1_800_000_000, 0)
	call := newSimFlow("udp", "20.0.0.5", 50001, 31000)
	dl := newSimFlow("tcp", "20.0.0.6", 50002, 443)
	st.observe(t0, []ctEntry{call.add(1, 1, 1, 1), dl.add(1, 1, 1, 1)}, nil, fsOwner, nil)
	at := t0
	for i := 0; i < 6; i++ {
		at = at.Add(10 * time.Second)
		st.observe(at, []ctEntry{call.add(70_000, 70_000, 500, 500), dl.add(1_000_000, 50_000_000, 17000, 34500)}, nil, fsOwner, nil)
	}
	if got := st.devs[fsMAC].typ; got != ttVoice {
		t.Fatalf("a call outranks a bigger background download: %s", got)
	}
	if st.flows[dl.e.key()].typ != ttDownload {
		t.Fatalf("download flow: %s", st.flows[dl.e.key()].typ)
	}
}

func TestFlowShapeRobustness(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	// 计数器回退(五元组复用) → 该连接重建基线
	st := newFSState()
	f := newSimFlow("tcp", "20.0.0.1", 40000, 443)
	st.observe(t0, []ctEntry{f.add(1000, 1_000_000, 10, 700)}, nil, fsOwner, nil)
	st.observe(t0.Add(10*time.Second), []ctEntry{f.add(1000, 1_000_000, 10, 700)}, nil, fsOwner, nil)
	reset := f.e
	reset.UpB, reset.DnB, reset.UpPkts, reset.DnPkts = 10, 10, 1, 1
	st.observe(t0.Add(20*time.Second), []ctEntry{reset}, nil, fsOwner, nil)
	if n := len(st.flows[f.e.key()].samples); n != 0 {
		t.Fatalf("counter regression must drop samples, have %d", n)
	}
	// 同一份快照喂两次: 无变化
	before := len(st.flows)
	st.observe(t0.Add(20*time.Second), nil, nil, fsOwner, nil)
	if len(st.flows) != before || st.flows[f.e.key()].ended {
		t.Fatal("duplicate snapshot must be a no-op")
	}
	// 时钟跳变 / 长时间没采样 → 全部重建
	st.observe(t0.Add(20*time.Second+fsMaxDT+time.Second), []ctEntry{reset}, nil, fsOwner, nil)
	if fl := st.flows[f.e.key()]; fl == nil || len(fl.samples) != 0 {
		t.Fatalf("rebaseline after gap: %+v", fl)
	}
	st.observe(t0.Add(-time.Hour), nil, nil, fsOwner, nil) // 时间倒退
	if len(st.flows) != 0 {
		t.Fatal("clock going backwards must rebaseline")
	}
	// 局域网/非客户端连接不跟踪
	st = newFSState()
	lan := newSimFlow("tcp", "192.168.43.1", 1, 80)
	other := ctEntry{Proto: "tcp", Src: "10.9.9.9", Dst: "1.2.3.4", Sport: 1, Dport: 443}
	st.observe(t0, []ctEntry{lan.add(1, 1, 1, 1), other}, nil, fsOwner, nil)
	if len(st.flows) != 0 {
		t.Fatalf("tracked %d non-client/LAN flows", len(st.flows))
	}
	// 上界
	st = newFSState()
	var ents []ctEntry
	for i := 0; i < fsMaxFlows+50; i++ {
		ents = append(ents, ctEntry{Proto: "udp", Src: "192.168.43.10", Dst: fmt.Sprintf("20.%d.%d.%d", i>>16&255, i>>8&255, i&255), Sport: 1, Dport: 9})
	}
	st.observe(t0, ents, nil, fsOwner, nil)
	if len(st.flows) > fsMaxFlows {
		t.Fatalf("flows %d > cap", len(st.flows))
	}
}

// flowShapeTick → 发布给 /api/devices 与 /api/connections
func TestFlowShapePublish(t *testing.T) {
	defer flowShapeReset()
	flowShapeReset()
	t0 := time.Unix(1_800_000_000, 0)
	v := newSimFlow("tcp", "20.0.0.1", 40000, 443)
	at := t0
	for i := 0; i < 8; i++ {
		e := v.add(75_000, 3_750_000, 1300, 2680)
		flowShapeTick(at, &ctSnapshot{at: at, readable: true, acct: true, entries: []ctEntry{e}}, nil, fsOwner,
			map[string]ipApp{"20.0.0.1": {ID: "douyin", Name: "抖音", Category: "video"}}, nil)
		at = at.Add(10 * time.Second)
	}
	tts := trafficTypesByMAC()
	tt := tts[fsMAC]
	if tt.Type != ttLive || tt.Label != "看直播" || tt.Confidence < 0.7 || tt.Since == 0 {
		t.Fatalf("published %+v (%v)", tt, sortedTrafficTypes(tts))
	}
	if typ, conf, ok := flowTrafficType(v.e.key()); !ok || typ != ttLive || conf < 0.7 {
		t.Fatalf("flow pub %s %.2f %v", typ, conf, ok)
	}
	// acct 关掉 → 清空
	flowShapeTick(at, &ctSnapshot{at: at, readable: true, acct: false}, nil, fsOwner, nil, nil)
	if len(trafficTypesByMAC()) != 0 {
		t.Fatal("no acct → nothing published")
	}
}
