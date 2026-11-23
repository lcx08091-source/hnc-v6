package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDNSFakeIPFilterAndNoServeStale(t *testing.T) {
	// 1. 验证 isFakeIPAddr 精确匹配 198.18.0.0/15 与 fc00::/18, 严禁误伤 fd00::/8 ULA
	trueCases := []string{
		"198.18.0.0",
		"198.18.0.1",
		"198.19.123.45",
		"198.19.255.255",
		"::ffff:198.18.1.9",
		"fc00::1",
		"fc00:3fff:ffff:ffff:ffff:ffff:ffff:ffff",
	}
	for _, s := range trueCases {
		if !isFakeIPAddr(net.ParseIP(s)) {
			t.Fatalf("expected Fake-IP true for %s", s)
		}
	}
	falseCases := []string{
		"",
		"198.17.255.255",
		"198.20.0.0",
		"192.168.43.1",
		"100.64.0.1",
		"fd00::1",
		"fd12:3456:789a::1",
		"fc00:4000::1",
		"fc01::1",
		"fe80::1",
		"2409:8a00::1",
	}
	for _, s := range falseCases {
		if isFakeIPAddr(net.ParseIP(s)) {
			t.Fatalf("expected Fake-IP false for %s", s)
		}
	}
	if isFakeIPAddr(nil) {
		t.Fatal("nil IP must not be Fake-IP")
	}

	// 2. 验证 dns_forwarder: 含 Fake-IP 的响应不写入长 TTL 缓存、不启用 180s Serve-Stale, 且清除同键旧缓存
	u := startControllableUpstream(t)
	f := newDNSForwarder()
	f.SetUpstream(u.addr)

	// 先种一条真实公网 IP 缓存(TTL=60s)
	u.mu.Lock()
	u.ip = net.IPv4(8, 8, 4, 4)
	u.ttl = 60
	u.mu.Unlock()
	q := dnsBuildQuery(0x301, "api.example.org", dnsTypeA, 0, false)
	_ = mustResp(t, f.handle(q, dnsTestClient, "udp"))
	if f.cache.Len() != 1 {
		t.Fatalf("real IP must be cached, got len=%d", f.cache.Len())
	}

	// 强制刷新后模拟透明代理返回 Fake-IP 198.18.0.25 (即使上游给 TTL=300s)
	f.FlushCache()
	u.mu.Lock()
	u.ip = net.IPv4(198, 18, 0, 25)
	u.ttl = 300
	u.mu.Unlock()
	hitsBefore := u.hits.Load()
	m1 := mustResp(t, f.handle(dnsBuildQuery(0x302, "fake4.example.org", dnsTypeA, 0, false), dnsTestClient, "udp"))
	if len(m1.Answers) != 1 || m1.Answers[0].Value != "198.18.0.25" {
		t.Fatalf("unexpected fake4 reply: %+v", m1)
	}
	if f.cache.Len() != 0 {
		t.Fatalf("Fake-IP v4 response must NOT be stored in cache, got len=%d", f.cache.Len())
	}
	// 紧接着另一个客户端查询同一域名: 必须穿透缓存重新问上游(不能发缓存的回收 Fake-IP)
	u.mu.Lock()
	u.ip = net.IPv4(198, 18, 0, 26)
	u.mu.Unlock()
	m2 := mustResp(t, f.handle(dnsBuildQuery(0x303, "fake4.example.org", dnsTypeA, 0, false), net.ParseIP("192.168.43.11"), "udp"))
	if u.hits.Load()-hitsBefore != 2 || m2.Answers[0].Value != "198.18.0.26" {
		t.Fatalf("second client must bypass cache for Fake-IP: hitsDelta=%d ans=%+v", u.hits.Load()-hitsBefore, m2.Answers)
	}

	// 验证 IPv6 fc00::/18 Fake-IP 同样不缓存且无 Serve-Stale, 而 fd00::/8 ULA 正常缓存
	c := newDNSCache(16, 1<<20)
	t0 := time.Unix(1_800_000_000, 0)
	q6 := dnsBuildQuery(1, "fake6.example.org", dnsTypeAAAA, 0, false)
	pq6, _ := dnsParseQuery(q6)
	// 先放一条旧真实 v6 记录, 再写入 fc00::1234 Fake-IP 应答 -> 旧记录也应被清掉
	realV6 := buildTestAReply(q6, pq6, net.ParseIP("2409:8a00::88"), 30, true)
	c.put(dnsCacheKey(pq6), realV6, mustResp(t, realV6), t0)
	fakeV6 := buildTestAReply(q6, pq6, net.ParseIP("fc00::1234"), 300, true)
	c.put(dnsCacheKey(pq6), fakeV6, mustResp(t, fakeV6), t0.Add(time.Second))
	if c.Len() != 0 {
		t.Fatalf("fc00::/18 Fake-IP must clear old key and not enter cache, len=%d", c.Len())
	}
	if s, _ := c.getStale(dnsCacheKey(pq6), q6, pq6, t0.Add(40*time.Second)); s != nil {
		t.Fatal("fc00::/18 Fake-IP must have zero Serve-Stale")
	}

	qULA := dnsBuildQuery(2, "nas.lan", dnsTypeAAAA, 0, false)
	pqULA, _ := dnsParseQuery(qULA)
	ulaResp := buildTestAReply(qULA, pqULA, net.ParseIP("fd12:3456::9"), 120, true)
	c.put(dnsCacheKey(pqULA), ulaResp, mustResp(t, ulaResp), t0)
	if c.Len() != 1 {
		t.Fatal("normal fd00::/8 ULA must still be cached")
	}

	// 3. 验证 dnsIPNames.record 跳过记录 Fake-IP, 防止按域名限速/封锁误伤共享 Fake-IP 池
	names := newDNSIPNames()
	names.record(dnsAnswerEvent{
		MAC: "aa:bb:cc:00:00:01", QName: "blocked.example.com", Ts: t0,
		IPs: []dnsRR{
			{Type: dnsTypeA, TTL: 60, Value: "198.18.1.100"},
			{Type: dnsTypeAAAA, TTL: 60, Value: "fc00::abcd"},
			{Type: dnsTypeAAAA, TTL: 60, Value: "fd00::abcd"},
			{Type: dnsTypeA, TTL: 60, Value: "93.184.216.34"},
		},
	})
	snap := names.snapshot(t0.Unix() + 10)
	if _, bad := snap["198.18.1.100"]; bad {
		t.Fatal("198.18.0.0/15 Fake-IP must not enter dnsIPNames")
	}
	if _, bad := snap["fc00::abcd"]; bad {
		t.Fatal("fc00::/18 Fake-IP must not enter dnsIPNames")
	}
	if _, ok := snap["fd00::abcd"]; !ok {
		t.Fatal("fd00::/8 ULA should remain in dnsIPNames")
	}
	if _, ok := snap["93.184.216.34"]; !ok {
		t.Fatal("public IPv4 should remain in dnsIPNames")
	}
}

func TestDNSTakeoverYieldTProxyAndPureIPv6Ifaces(t *testing.T) {
	h := newTKHarness(t)
	h.conf(`{"enabled":true}`)

	yieldMode := true
	h.tk.runScript = func(args ...string) (int, string) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.calls = append(h.calls, strings.Join(args, " "))
		switch args[0] {
		case "apply":
			forced := len(args) > 1 && args[1] == "--force"
			if yieldMode && !forced {
				return 0, "DNSTK=yield_tproxy chain=BOX_EXTERNAL"
			}
			ifaceIdx := 1
			if forced {
				ifaceIdx = 2
			}
			h.present = true
			return 0, "DNSTK=on iface=" + args[ifaceIdx] + " port=" + args[ifaceIdx+1] + " rules=2 v6=0"
		case "remove":
			h.present = false
			return 0, "DNSTK=off"
		case "counters":
			b, _ := json.Marshal(map[string]interface{}{"present": h.present, "pkts": h.pkts})
			return 0, string(b)
		}
		return 2, "usage"
	}

	// 首次 tick: 识别透明代理优雅礼让态, 不计错误故障, 不发告警
	h.tk.tick()
	calls := h.takeCalls()
	if len(calls) != 1 || !strings.HasPrefix(calls[0], "apply ") {
		t.Fatalf("expected single apply call, got %v", calls)
	}
	st, act := h.state()
	if st != "yield_tproxy" || act {
		t.Fatalf("expected state=yield_tproxy active=false, got state=%s active=%v", st, act)
	}
	if h.tk.lastErr != "" || h.tk.foCount != 0 || len(h.alerts) != 0 {
		t.Fatalf("yield_tproxy must not record error or alert: lastErr=%q foCount=%d alerts=%v", h.tk.lastErr, h.tk.foCount, h.alerts)
	}

	// 连续 4 次 10s tick(共 +40s, 仍在 60s 礼让驻留窗口内): 严禁反复执行 apply 强插 PREROUTING 1
	for i := 0; i < 4; i++ {
		h.advance(10 * time.Second)
		h.tk.tick()
	}
	if c := h.takeCalls(); len(c) != 0 {
		t.Fatalf("must NOT re-run apply every 10s while yielding, got calls=%v", c)
	}

	// 验证 /api/dns 状态 JSON 暴露友好中文礼让说明且 last_error 为空
	rec := httptest.NewRecorder()
	h.s.apiDNS(rec, httptest.NewRequest("GET", "/api/dns", nil))
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["state"] != "yield_tproxy" || resp["yield_tproxy"] != true || resp["last_error"] != "" {
		t.Fatalf("unexpected /api/dns yield payload: %v", resp)
	}
	note, _ := resp["yield_reason"].(string)
	if !strings.Contains(note, "BOX_EXTERNAL") || !strings.Contains(note, "礼让") {
		t.Fatalf("expected friendly Chinese yield note mentioning BOX_EXTERNAL, got %q", note)
	}

	// 验证透明代理仍在运行但用户显式配置 force_takeover=true 时, 传递 --force 强制覆盖礼让
	h.conf(`{"enabled":true,"force_takeover":true}`)
	h.tk.tick()
	forceCalls := h.takeCalls()
	sawForce := false
	for _, fc := range forceCalls {
		if strings.HasPrefix(fc, "apply --force ") {
			sawForce = true
		}
	}
	if !sawForce {
		t.Fatalf("expected apply --force when force_takeover=true, got %v", forceCalls)
	}
	// 切回礼让配置验证透明代理退出后满 60s 复查自动恢复 active
	h.present = false
	h.conf(`{"enabled":true}`)
	h.tk.tick()
	_ = h.takeCalls()
	yieldMode = false
	h.advance(65 * time.Second)
	h.tk.tick()
	if st, act := h.state(); st != "active" || !act {
		t.Fatalf("expected auto-recovery to active after tproxy exit, got state=%s active=%v", st, act)
	}

	// 验证 fastFlagUpIfacesFrom 补读假 /sys/class/net 识别纯 IPv6 蜂窝接口
	fakeSysNet := t.TempDir()
	for name, fl := range map[string]string{
		"rmnet_data9": "0x1091\n", // UP, 非 loopback
		"ccmni8":      "0x1090\n", // DOWN
		"ap0":         "0x1003\n", // 热点口, 默认忽略
		"lo":          "0x0049\n", // 回环, 忽略
	} {
		_ = os.MkdirAll(filepath.Join(fakeSysNet, name), 0o755)
		_ = os.WriteFile(filepath.Join(fakeSysNet, name, "flags"), []byte(fl), 0o644)
	}
	ifs, ok := fastFlagUpIfacesFrom(fakeSysNet, map[string]bool{"ap0": true})
	if !ok {
		t.Fatal("fastFlagUpIfacesFrom should succeed")
	}
	foundV6Only := false
	for _, x := range ifs {
		if x == "rmnet_data9" {
			foundV6Only = true
		}
		if x == "ccmni8" || x == "ap0" || x == "lo" {
			t.Fatalf("unexpected ignored/down iface %s in %v", x, ifs)
		}
	}
	if !foundV6Only {
		t.Fatalf("pure-IPv6 interface rmnet_data9 missing from %v", ifs)
	}
}

func buildTestNLA(typ uint16, val []byte) []byte {
	l := 4 + len(val)
	al := (l + 3) &^ 3
	b := make([]byte, al)
	binary.LittleEndian.PutUint16(b[0:2], uint16(l))
	binary.LittleEndian.PutUint16(b[2:4], typ)
	copy(b[4:], val)
	return b
}

func buildTestNLANest(typ uint16, attrs ...[]byte) []byte {
	var body []byte
	for _, a := range attrs {
		body = append(body, a...)
	}
	return buildTestNLA(typ|nlaFNested, body)
}

func wrapTestNLMsg(msgType, flags uint16, seq uint32, payload []byte) []byte {
	l := 16 + len(payload)
	al := (l + 3) &^ 3
	b := make([]byte, al)
	binary.NativeEndian.PutUint32(b[0:4], uint32(l))
	binary.NativeEndian.PutUint16(b[4:6], msgType)
	binary.NativeEndian.PutUint16(b[6:8], flags)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	copy(b[16:], payload)
	return b
}

func TestConntrackNetlinkParseAndFallbackGuard(t *testing.T) {
	be16 := func(v uint16) []byte { var b [2]byte; binary.BigEndian.PutUint16(b[:], v); return b[:] }
	be32 := func(v uint32) []byte { var b [4]byte; binary.BigEndian.PutUint32(b[:], v); return b[:] }
	be64 := func(v uint64) []byte { var b [8]byte; binary.BigEndian.PutUint64(b[:], v); return b[:] }

	// 1. 构造 IPv4 TCP ESTABLISHED + ASSURED + 64位计数器 CTNETLINK 消息
	p4 := []byte{syscall.AF_INET, 0, 0, 0}
	p4 = append(p4,
		buildTestNLANest(ctaTupleOrig,
			buildTestNLANest(ctaTupleIP,
				buildTestNLA(ctaIPv4Src, []byte{192, 168, 43, 20}),
				buildTestNLA(ctaIPv4Dst, []byte{1, 1, 1, 1}),
			),
			buildTestNLANest(ctaTupleProto,
				buildTestNLA(ctaProtoNum, []byte{6}),
				buildTestNLA(ctaProtoSrcPort, be16(51234)),
				buildTestNLA(ctaProtoDstPort, be16(443)),
			),
		)...,
	)
	p4 = append(p4, buildTestNLA(ctnlAttrStatus, be32(ctnlIPSSeenReply|ctnlIPSAssured))...)
	p4 = append(p4, buildTestNLA(ctnlAttrTimeout, be32(3600))...)
	p4 = append(p4, buildTestNLANest(ctnlAttrProtoInfo,
		buildTestNLANest(ctnlProtoInfoTCP, buildTestNLA(ctnlProtoInfoTCPState, []byte{3})),
	)...)
	p4 = append(p4, buildTestNLANest(ctaCountersOrig,
		buildTestNLA(ctnlCountersPackets, be64(12)),
		buildTestNLA(ctaCountersBytes, be64(2400)),
	)...)
	p4 = append(p4, buildTestNLANest(ctaCountersReply,
		buildTestNLA(ctnlCountersPackets, be64(18)),
		buildTestNLA(ctaCountersBytes, be64(16000)),
	)...)

	// 2. 构造 IPv6 UDP UNREPLIED + 32位老计数器 CTNETLINK 消息
	p6 := []byte{syscall.AF_INET6, 0, 0, 0}
	src6 := net.ParseIP("2409:8a00:0000:0000:0000:0000:0000:0009").To16()
	dst6 := net.ParseIP("2400:3200::1").To16()
	p6 = append(p6,
		buildTestNLANest(ctaTupleOrig,
			buildTestNLANest(ctaTupleIP,
				buildTestNLA(ctaIPv6Src, src6),
				buildTestNLA(ctaIPv6Dst, dst6),
			),
			buildTestNLANest(ctaTupleProto,
				buildTestNLA(ctaProtoNum, []byte{17}),
				buildTestNLA(ctaProtoSrcPort, be16(60000)),
				buildTestNLA(ctaProtoDstPort, be16(53)),
			),
		)...,
	)
	p6 = append(p6, buildTestNLA(ctnlAttrStatus, be32(0))...) // 未见应答 -> Unrepl=true
	p6 = append(p6, buildTestNLA(ctnlAttrTimeout, be32(29))...)
	p6 = append(p6, buildTestNLANest(ctaCountersOrig,
		buildTestNLA(ctnlCounters32Packets, be32(2)),
		buildTestNLA(ctaCounters32Bytes, be32(140)),
	)...)

	msgTypeNew := uint16(nfnlSubsysCtnetlink<<8 | ipctnlMsgCtNew)
	var stream []byte
	stream = append(stream, wrapTestNLMsg(msgTypeNew, syscall.NLM_F_MULTI, 1, p4)...)
	stream = append(stream, wrapTestNLMsg(msgTypeNew, syscall.NLM_F_MULTI, 1, p6)...)
	stream = append(stream, wrapTestNLMsg(syscall.NLMSG_DONE, syscall.NLM_F_MULTI, 1, []byte{0, 0, 0, 0})...)

	v6Intern := map[string]string{}
	entries, hasAcct, sawV6, done, err := parseCtNetlinkDumpChunk(stream, "", v6Intern, nil)
	if err != nil || !done || !hasAcct || !sawV6 || len(entries) != 2 {
		t.Fatalf("parseCtNetlinkDumpChunk failed: err=%v done=%v acct=%v sawV6=%v len=%d", err, done, hasAcct, sawV6, len(entries))
	}
	e0, e1 := entries[0], entries[1]
	if e0.Family != "ipv4" || e0.Proto != "tcp" || e0.State != "ESTABLISHED" || !e0.Assured || e0.Unrepl ||
		e0.Src != "192.168.43.20" || e0.Dst != "1.1.1.1" || e0.Sport != 51234 || e0.Dport != 443 ||
		e0.UpPkts != 12 || e0.UpB != 2400 || e0.DnPkts != 18 || e0.DnB != 16000 || e0.TTL != 3600 {
		t.Fatalf("unexpected ipv4 ctEntry: %+v", e0)
	}
	if e1.Family != "ipv6" || e1.Proto != "udp" || !e1.Unrepl || e1.Assured ||
		e1.Src != "2409:8a00::9" || e1.Dst != "2400:3200::1" || e1.UpPkts != 2 || e1.UpB != 140 || !e1.Acct {
		t.Fatalf("unexpected ipv6 ctEntry: %+v", e1)
	}

	// 验证 wantFamily="ipv6" 过滤重复的 ipv4 条目
	onlyV6, _, _, _, err := parseCtNetlinkDumpChunk(stream, "ipv6", v6Intern, nil)
	if err != nil || len(onlyV6) != 1 || onlyV6[0].Family != "ipv6" {
		t.Fatalf("wantFamily=ipv6 filter failed: %+v err=%v", onlyV6, err)
	}

	// 验证请求构造头部字段
	req := buildCtNetlinkGetDumpReq(syscall.AF_INET6, 7)
	if len(req) != 20 || req[16] != syscall.AF_INET6 ||
		binary.NativeEndian.Uint16(req[4:6]) != uint16(nfnlSubsysCtnetlink<<8|ctnlMsgCtGet) {
		t.Fatalf("bad buildCtNetlinkGetDumpReq: %x", req)
	}

	// 3. 验证防雷铁律: HNC_CONNTRACK_PATH 非空时严禁调用 ctNetlinkDumpFn!
	origDump := ctNetlinkDumpFn
	defer func() {
		ctNetlinkDumpFn = origDump
		ctState.mu.Lock()
		ctState.snap, ctState.prev = nil, nil
		ctState.mu.Unlock()
	}()

	nlCalled := 0
	ctNetlinkDumpFn = func() ([]ctEntry, bool, error) {
		nlCalled++
		return entries, true, nil
	}
	ctState.mu.Lock()
	ctState.snap, ctState.prev = nil, nil
	ctState.mu.Unlock()

	t.Setenv("HNC_CONNTRACK_PATH", filepath.Join(t.TempDir(), "missing_nf_conntrack"))
	sn := conntrackSnapshot()
	if sn.readable || nlCalled != 0 {
		t.Fatalf("HNC_CONNTRACK_PATH!=empty MUST NOT fallback to CTNETLINK: readable=%v nlCalled=%d", sn.readable, nlCalled)
	}
}

func TestV513RC2TailFileAndCGNATOffload(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "logs"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)

	// 1. 空文件与不存在文件
	if got := tailFile(filepath.Join(dir, "nope.log"), 10); got != "" {
		t.Fatalf("nonexistent file got %q", got)
	}
	emptyPath := filepath.Join(dir, "empty.log")
	_ = os.WriteFile(emptyPath, nil, 0o644)
	if got := tailFile(emptyPath, 10); got != "" {
		t.Fatalf("empty file got %q", got)
	}

	// 2. 用极小分块(chunkSize=13B)压测跨块倒序换行扫描(含末尾有换行与无换行)
	var lines []string
	for i := 1; i <= 50; i++ {
		lines = append(lines, "log-entry-number-"+itoa(i))
	}
	withNL := filepath.Join(dir, "logs", "service.log")
	_ = os.WriteFile(withNL, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	wantLast5 := strings.Join(lines[45:], "\n") + "\n"
	if got := tailFileWithCap(withNL, 5, 13, 1<<20); got != wantLast5 {
		t.Fatalf("chunked tail with trailing NL mismatch:\ngot:  %q\nwant: %q", got, wantLast5)
	}

	noNL := filepath.Join(dir, "no_nl.log")
	_ = os.WriteFile(noNL, []byte(strings.Join(lines, "\n")), 0o644)
	wantNoNL := strings.Join(lines[47:], "\n")
	if got := tailFileWithCap(noNL, 3, 11, 1<<20); got != wantNoNL {
		t.Fatalf("chunked tail without trailing NL mismatch:\ngot:  %q\nwant: %q", got, wantNoNL)
	}

	// 3. 超长无换行文件单次最大字节保护防 OOM
	giantNoNL := filepath.Join(dir, "giant.log")
	_ = os.WriteFile(giantNoNL, []byte(strings.Repeat("X", 4096)+"TAILEND"), 0o644)
	capped := tailFileWithCap(giantNoNL, 100, 64, 256)
	if len(capped) != 256 || !strings.HasSuffix(capped, "TAILEND") {
		t.Fatalf("maxBytes cap failed: len=%d suffix=%q", len(capped), capped[len(capped)-10:])
	}

	// 4. combinedLog 纯 Go 合并
	_ = os.WriteFile(filepath.Join(dir, "logs", "watchdog.log"), []byte("wd-ok\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "logs", "detect.log"), []byte("det-ok"), 0o644)
	comb := combinedLog(dir, 15)
	if !strings.Contains(comb, "wd-ok\n") || !strings.Contains(comb, "det-ok\n") || !strings.Contains(comb, "log-entry-number-50\n") {
		t.Fatalf("unexpected combinedLog: %q", comb)
	}

	// 5. RFC6598 100.64.0.0/10 热点网关识别
	for ip, want := range map[string]bool{
		"192.168.43.1":    true,
		"10.0.0.1":        true,
		"172.20.0.1":      true,
		"100.64.0.1":      true,
		"100.100.88.1":    true,
		"100.127.255.254": true,
		"100.63.255.255":  false,
		"100.128.0.1":     false,
		"8.8.8.8":         false,
	} {
		if got := isHotspotPrivateIPv4(net.ParseIP(ip)); got != want {
			t.Fatalf("isHotspotPrivateIPv4(%s) = %v, want %v", ip, got, want)
		}
	}

	// 6. /api/offload_status 联动天玑 detected_no_knob 硬件直通提示
	_ = os.WriteFile(filepath.Join(dir, "run", "mtk_hwnat.json"),
		[]byte(`{"experimental":true,"detected":true,"action":"detected_no_knob","detail":"no knob"}`), 0o644)
	s := newServer(dir)
	rec := httptest.NewRecorder()
	s.apiOffloadStatus(rec, httptest.NewRequest("GET", "/api/offload_status", nil))
	var off map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &off); err != nil {
		t.Fatal(err)
	}
	if off["active"] != true || off["hwnat"] != "detected_no_knob" || !strings.Contains(asString(off["hint"]), "tether_offload_disabled=1") {
		t.Fatalf("expected MediaTek detected_no_knob offload hint, got %v", off)
	}
}

func TestSelfcheckRC2NativeAndCompat(t *testing.T) {
	// 1. 透明代理共存与高 16 位 fwmark 冲突纯函数测试
	// 1a: 低 16 位 mark (0x0162/0x0000ffff) + 53 端口接管 + HNC 自身高 16 位规则 + Android 系统链 -> 零冲突且识别共存
	mangleOK := strings.Join([]string{
		"-N HNC_MARK",
		"-N BOX_EXTERNAL",
		"-A PREROUTING -j HNC_MARK",
		"-A PREROUTING -j BOX_EXTERNAL",
		"-A HNC_MARK -m mac --mac-source aa:bb:cc:00:00:01 -j MARK --set-xmark 0x00810000/0x00ff0000",
		"-A bw_INPUT -j MARK --set-xmark 0x100000/0x100000",
		"-A BOX_EXTERNAL -p udp --dport 53 -j TPROXY --on-port 7893 --tproxy-mark 0x162/0x0000ffff",
		"-A BOX_EXTERNAL -j MARK --set-xmark 0x0162/0x0000ffff",
	}, "\n")
	natOK := "-N CLASH_DNS\n-A PREROUTING -p udp --dport 53 -j CLASH_DNS\n"
	d1 := scAnalyzeTProxyAndFwmark(mangleOK, natOK)
	if len(d1.MarkConflicts) != 0 || !d1.DNS53Intercepted || len(d1.Chains) != 2 {
		t.Fatalf("expected clean coexist, got %+v", d1)
	}

	// 1b: 透明代理写入高 16 位(0x01000000) 或全掩码覆盖(0x1/0xffffffff) -> 精准告警
	mangleBad := strings.Join([]string{
		"-N MIHOMO_TP",
		"-A MIHOMO_TP -j MARK --set-xmark 0x01000000/0xff000000",
		"-A PREROUTING -j MARK --set-mark 0x1",
	}, "\n")
	d2 := scAnalyzeTProxyAndFwmark(mangleBad, "")
	if len(d2.MarkConflicts) != 2 {
		t.Fatalf("expected 2 high-16-bit fwmark conflicts, got %+v", d2.MarkConflicts)
	}

	// 2. 天玑 detected_no_knob 自检 scWarn + 重开热点使 tether_offload_disabled=1 生效指引 + app_usage data/ 优先读取 + 短 loadavg 不越界
	f := fixtureMediaTek("/data/local/hnc")
	f.files[f.h("run", "mtk_hwnat.json")] = `{"experimental":true,"detected":true,"paths":["/dev/mddp"],"action":"detected_no_knob","detail":"MDDP active"}`
	f.files["/proc/loadavg"] = "1.25\n" // 仅 1 个字段, 验证不触发 [:3] 越界 panic
	f.files[f.h("data", "app_usage."+f.now.Format("20060102")+".json")] = `{"date":"20260930","hours":{"9":{"aa:bb:cc:00:00:01|bilibili":[200,800],"aa:bb:cc:00:00:01|_unknown":[100,100]}},"apps":{}}`
	f.files[f.h("data", "dns_takeover.json")] = `{"enabled":true}`
	f.cmds["iptables -t mangle -S"] = mangleOK
	f.cmds["iptables -t nat -S"] = natOK

	r := runSelfcheck(f.scEnv(), scOptions{})
	mt := expectStatus(t, r, "offload", "mtk_hwnat", scWarn)
	mustContain(t, "mtk value", mt.Value, "需重开热点生效")
	mustContain(t, "mtk fix", mt.Fix, "tether_offload_disabled=1")
	tp := expectStatus(t, r, "firewall", "tproxy_coexist", scOK)
	mustContain(t, "tproxy coexist", tp.Value, "DNS 已自动礼让")
	mustContain(t, "loadavg 1-field", findItem(t, r, "process", "loadavg").Value, "1.25")
	mustContain(t, "app_usage from data/", expectStatus(t, r, "ident", "unknown_ratio", scOK).Value, "17%")

	// 3. 三星 DIT (/sys/devices/platform/dit & /sys/module/dit) + APatch /data/adb/ap/bin/apd + RealSystem procfind ipacm(零 pidof)
	fsam := newFakeSys("/data/local/hnc")
	fsam.now = f.now
	fsam.cmds["getprop"] = props(
		"ro.product.brand", "samsung", "ro.product.model", "SM-S9280",
		"ro.build.version.release", "15", "ro.build.version.sdk", "35",
		"ro.build.version.oneui", "70000", "ro.soc.manufacturer", "Samsung", "ro.board.platform", "s5e9945",
		"persist.sys.timezone", "Asia/Shanghai",
	)
	fsam.exists["/sys/devices/platform/dit"] = true
	fsam.exists["/sys/module/dit"] = true
	fsam.exists["/data/adb/ap/bin/apd"] = true
	fsam.cmds["/data/adb/ap/bin/apd -V"] = "apd 11022\n"
	fsam.dirs["/data/adb/modules/hotspot_network_control"] = []string{"module.prop"}
	fsam.dirs["/data/local/hnc"] = []string{"bin", "run", "data"}
	// 注入假 /proc 中的 ipacm, 并开启 RealSystem=true 验证不调用 pidof 也能识别 ipacm
	fsam.dirs["/proc"] = []string{"901"}
	fsam.files["/proc/901/stat"] = procStat(901, "ipacm", 5, 2)
	fsam.files["/proc/901/cmdline"] = "/vendor/bin/ipacm\x00"

	envSam := fsam.scEnv()
	envSam.RealSystem = true
	rSam := runSelfcheck(envSam, scOptions{})
	rootSam := expectStatus(t, rSam, "system", "root", scOK)
	if rootSam.Value != "APatch" {
		t.Fatalf("expected APatch, got %q", rootSam.Value)
	}
	mustContain(t, "apatch ver", rootSam.Detail, "11022")
	dit := findItem(t, rSam, "offload", "samsung_offload")
	mustContain(t, "samsung dit", dit.Detail, "/sys/devices/platform/dit")
	mustContain(t, "samsung mod dit", dit.Detail, "/sys/module/dit")
	ipa := findItem(t, rSam, "offload", "qcom_ipa")
	mustContain(t, "procfind ipacm", ipa.Detail, "ipacm 运行中")
	for _, call := range fsam.calls {
		if strings.HasPrefix(call, "pidof ") {
			t.Fatalf("RealSystem must not invoke pidof, got call %q", call)
		}
	}
}
