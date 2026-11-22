package main

import (
	"encoding/binary"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// DPI v2 dns_forwarder.go / dns_wire.go: 假上游(UDP+TCP 同端口)上的转发、缓存 TTL、
// 截断 → TCP 重取、EDNS 透传、封锁应答、限速、上游故障。

type fakeUpstream struct {
	// udpN/tcpN 置顶保证 32 位 ARM 下 8 字节对齐
	udpN     atomic.Int64
	tcpN     atomic.Int64
	addr     string
	udp      *net.UDPConn
	tcp      net.Listener
	mu       sync.Mutex
	sawOPT   bool
	sawDO    bool
	ttl      uint32
	wrongID1 bool // 第一条 UDP 应答先发一个错 ID 的(防串包)
}

// fakeAnswer: A 1.2.3.4(qname = big.test 时 40 条 A), 带 OPT 时回 OPT; NXDOMAIN for nx.test(带 SOA)
func (u *fakeUpstream) answer(q []byte, proto string) []byte {
	pq, err := dnsParseQuery(q)
	if err != nil {
		return nil
	}
	u.mu.Lock()
	if pq.HasOPT {
		u.sawOPT = true
	}
	if pq.DO {
		u.sawDO = true
	}
	ttl := u.ttl
	u.mu.Unlock()
	if pq.QName == "nx.test" {
		out := dnsReplyHeader(q, pq, dnsRcodeNXDomain, 0)
		binary.BigEndian.PutUint16(out[8:10], 1) // NS 段 1 条 SOA
		out = append(out, 0xC0, 0x0C)
		out = binary.BigEndian.AppendUint16(out, dnsTypeSOA)
		out = binary.BigEndian.AppendUint16(out, 1)
		out = binary.BigEndian.AppendUint32(out, 900)
		rd := append(dnsEncodeName("ns.test"), dnsEncodeName("h.test")...)
		for _, v := range []uint32{1, 2, 3, 4, 120} {
			rd = binary.BigEndian.AppendUint32(rd, v)
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(rd)))
		out = append(out, rd...)
		return dnsAppendOPT(out, pq)
	}
	n := 1
	if pq.QName == "big.test" {
		n = 40
		if proto == "udp" {
			out := dnsReplyHeader(q, pq, 0, 0)
			binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])|dnsFlagTC)
			return out
		}
	}
	out := dnsReplyHeader(q, pq, 0, 0)
	if pq.QName == "cn.test" { // CNAME 链: cn.test → real.test → 5.6.7.8
		binary.BigEndian.PutUint16(out[6:8], 2)
		out = append(out, 0xC0, 0x0C)
		out = binary.BigEndian.AppendUint16(out, dnsTypeCNAME)
		out = binary.BigEndian.AppendUint16(out, 1)
		out = binary.BigEndian.AppendUint32(out, ttl)
		nm := dnsEncodeName("real.test")
		out = binary.BigEndian.AppendUint16(out, uint16(len(nm)))
		out = append(out, nm...)
		out = append(out, nm...)
		out = binary.BigEndian.AppendUint16(out, dnsTypeA)
		out = binary.BigEndian.AppendUint16(out, 1)
		out = binary.BigEndian.AppendUint32(out, ttl)
		out = binary.BigEndian.AppendUint16(out, 4)
		out = append(out, 5, 6, 7, 8)
		return dnsAppendOPT(out, pq)
	}
	binary.BigEndian.PutUint16(out[6:8], uint16(n))
	for i := 0; i < n; i++ {
		out = append(out, 0xC0, 0x0C)
		out = binary.BigEndian.AppendUint16(out, dnsTypeA)
		out = binary.BigEndian.AppendUint16(out, 1)
		out = binary.BigEndian.AppendUint32(out, ttl)
		out = binary.BigEndian.AppendUint16(out, 4)
		out = append(out, 1, 2, 3, byte(4+i))
	}
	return dnsAppendOPT(out, pq)
}

func freeDualPort(t *testing.T) (*net.UDPConn, net.Listener, int) {
	t.Helper()
	for i := 0; i < 50; i++ {
		uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		port := uc.LocalAddr().(*net.UDPAddr).Port
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err == nil {
			return uc, ln, port
		}
		uc.Close()
	}
	t.Fatal("no free dual port")
	return nil, nil, 0
}

func startFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	uc, ln, port := freeDualPort(t)
	u := &fakeUpstream{addr: "127.0.0.1:" + strconv.Itoa(port), udp: uc, tcp: ln, ttl: 300}
	go func() {
		buf := make([]byte, 4096)
		first := true
		for {
			n, src, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			u.udpN.Add(1)
			resp := u.answer(append([]byte(nil), buf[:n]...), "udp")
			if resp == nil {
				continue
			}
			u.mu.Lock()
			wrong := u.wrongID1 && first
			first = false
			u.mu.Unlock()
			if wrong {
				bad := append([]byte(nil), resp...)
				binary.BigEndian.PutUint16(bad[0:2], binary.BigEndian.Uint16(bad[0:2])+1)
				_, _ = uc.WriteToUDP(bad, src)
			}
			_, _ = uc.WriteToUDP(resp, src)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					_ = c.SetDeadline(time.Now().Add(3 * time.Second))
					q, err := dnsReadTCPMsg(c)
					if err != nil {
						return
					}
					u.tcpN.Add(1)
					if err := dnsWriteTCPMsg(c, u.answer(q, "tcp")); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() { uc.Close(); ln.Close() })
	return u
}

var dnsTestClient = net.ParseIP("192.168.43.10")

func newTestFwd(u *fakeUpstream) *dnsForwarder {
	f := newDNSForwarder()
	f.SetUpstream(u.addr)
	f.timeout = 800 * time.Millisecond
	return f
}

func mustResp(t *testing.T, b []byte) dnsMsgInfo {
	t.Helper()
	if b == nil {
		t.Fatal("nil response")
	}
	m, err := dnsParseResponse(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return m
}

func TestDNSForwarderUDPForwardAndCache(t *testing.T) {
	u := startFakeUpstream(t)
	f := newTestFwd(u)
	var logs []dnsLogEntry
	var ans []dnsAnswerEvent
	f.onLog = func(e dnsLogEntry) { logs = append(logs, e) }
	f.onAnswer = func(e dnsAnswerEvent) { ans = append(ans, e) }
	f.macOf = func(ip net.IP) string { return "aa:bb:cc:00:00:01" }

	m := mustResp(t, f.handle(dnsBuildQuery(0x1111, "www.example.com", dnsTypeA, 0, false), dnsTestClient, "udp"))
	if m.ID != 0x1111 || m.Rcode != 0 || len(m.Answers) != 1 || m.Answers[0].Value != "1.2.3.4" {
		t.Fatalf("answer: %+v", m)
	}
	m = mustResp(t, f.handle(dnsBuildQuery(0x2222, "WWW.Example.COM", dnsTypeA, 0, false), dnsTestClient, "udp"))
	if m.ID != 0x2222 || len(m.Answers) != 1 {
		t.Fatalf("cached answer: %+v", m)
	}
	if n := u.udpN.Load(); n != 1 {
		t.Fatalf("upstream hits = %d, want 1 (second from cache)", n)
	}
	st := f.Stats()
	if st.Queries != 2 || st.Cached != 1 || st.Upstream != 1 || st.Errors != 0 {
		t.Fatalf("stats %+v", st)
	}
	if len(logs) != 2 || logs[0].MAC != "aa:bb:cc:00:00:01" || logs[0].QType != "A" || logs[0].Rcode != "NOERROR" ||
		!logs[1].Cached || logs[0].IP != "192.168.43.10" || len(logs[0].Answers) != 1 {
		t.Fatalf("logs %+v", logs)
	}
	if len(ans) != 1 || ans[0].QName != "www.example.com" || ans[0].IPs[0].Value != "1.2.3.4" {
		t.Fatalf("answer events %+v", ans)
	}
	if p50, p95 := f.Percentiles(); p50 < 0 || p95 < p50 {
		t.Fatalf("percentiles %v %v", p50, p95)
	}
}

func TestDNSForwarderCasePreservedOnCacheHit(t *testing.T) {
	u := startFakeUpstream(t)
	f := newTestFwd(u)
	f.handle(dnsBuildQuery(1, "mixed.test", dnsTypeA, 0, false), dnsTestClient, "udp")
	q := dnsBuildQuery(2, "MiXeD.TeSt", dnsTypeA, 0, false)
	resp := f.handle(q, dnsTestClient, "udp")
	pq, _ := dnsParseQuery(q)
	if string(resp[12:pq.QEnd]) != string(q[12:pq.QEnd]) {
		t.Fatal("question bytes (0x20 case) must be the client's")
	}
}

func TestDNSCacheTTLDecrementAndExpiry(t *testing.T) {
	u := startFakeUpstream(t)
	u.mu.Lock()
	u.ttl = 30
	u.mu.Unlock()
	q := dnsBuildQuery(7, "ttl.test", dnsTypeA, 0, false)
	pq, _ := dnsParseQuery(q)
	resp, err := dnsExchangeUDP(u.addr, q, pq, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	m := mustResp(t, resp)
	c := newDNSCache(10, 1<<20)
	t0 := time.Unix(1_700_000_000, 0)
	c.put(dnsCacheKey(pq), resp, m, t0)
	got, _ := c.get(dnsCacheKey(pq), q, pq, t0.Add(12*time.Second))
	if mm := mustResp(t, got); mm.Answers[0].TTL != 18 {
		t.Fatalf("ttl after 12s = %d, want 18", mm.Answers[0].TTL)
	}
	if got, _ := c.get(dnsCacheKey(pq), q, pq, t0.Add(31*time.Second)); got != nil {
		t.Fatal("expired entry must miss fresh get")
	}
	if c.Len() != 1 {
		t.Fatal("positive expired entry must stay in 180s stale window")
	}
	if sgot, _ := c.getStale(dnsCacheKey(pq), q, pq, t0.Add(31*time.Second)); sgot == nil {
		t.Fatal("stale get must hit within 180s window")
	}
	if got, _ := c.get(dnsCacheKey(pq), q, pq, t0.Add(30*time.Second+dnsStaleMaxAge)); got != nil {
		t.Fatal("past staleUntil must miss")
	}
	if c.Len() != 0 {
		t.Fatal("entry past staleUntil must be evicted")
	}
	// TTL 0 不缓存; 超大 TTL 封顶
	if dnsCacheTTL(dnsMsgInfo{ANCount: 1, HaveTTL: true, MinTTL: 0}) != 0 ||
		dnsCacheTTL(dnsMsgInfo{ANCount: 1, HaveTTL: true, MinTTL: 999999}) != dnsCacheMaxTTL ||
		dnsCacheTTL(dnsMsgInfo{Rcode: dnsRcodeServFail, ANCount: 1, HaveTTL: true, MinTTL: 60}) != 0 ||
		dnsCacheTTL(dnsMsgInfo{Rcode: dnsRcodeNXDomain}) != 0 {
		t.Fatal("cache ttl policy")
	}
	// LRU 上限
	c2 := newDNSCache(2, 1<<20)
	for i, n := range []string{"a.test", "b.test", "c.test"} {
		qq := dnsBuildQuery(uint16(i), n, dnsTypeA, 0, false)
		pqq, _ := dnsParseQuery(qq)
		r, _ := dnsExchangeUDP(u.addr, qq, pqq, time.Second)
		c2.put(dnsCacheKey(pqq), r, mustResp(t, r), t0)
	}
	if c2.Len() != 2 {
		t.Fatalf("lru len %d", c2.Len())
	}
	qa := dnsBuildQuery(9, "a.test", dnsTypeA, 0, false)
	pqa, _ := dnsParseQuery(qa)
	if got, _ := c2.get(dnsCacheKey(pqa), qa, pqa, t0); got != nil {
		t.Fatal("oldest entry must be evicted")
	}
}

func TestDNSForwarderNegativeCacheSOA(t *testing.T) {
	u := startFakeUpstream(t)
	f := newTestFwd(u)
	m := mustResp(t, f.handle(dnsBuildQuery(1, "nx.test", dnsTypeA, 0, false), dnsTestClient, "udp"))
	if m.Rcode != dnsRcodeNXDomain || !m.HaveSOA || m.NegTTL != 120 {
		t.Fatalf("nx: %+v", m)
	}
	f.handle(dnsBuildQuery(2, "nx.test", dnsTypeA, 0, false), dnsTestClient, "udp")
	if u.udpN.Load() != 1 {
		t.Fatal("NXDOMAIN with SOA must be cached")
	}
}

func TestDNSForwarderTruncationTCPRetry(t *testing.T) {
	u := startFakeUpstream(t)
	f := newTestFwd(u)
	// 客户端 UDP 无 EDNS(512): 上游 UDP 回 TC → 转发器 TCP 重取完整应答 → 超 512 截断给客户端
	resp := f.handle(dnsBuildQuery(0x55, "big.test", dnsTypeA, 0, false), dnsTestClient, "udp")
	m := mustResp(t, resp)
	if m.Flags&dnsFlagTC == 0 || len(resp) > 512 || m.ANCount != 0 {
		t.Fatalf("client must get truncated reply: len=%d %+v", len(resp), m)
	}
	if u.tcpN.Load() != 1 || f.Stats().UpstreamTCP != 1 {
		t.Fatalf("upstream tcp retry missing: tcp=%d", u.tcpN.Load())
	}
	// 客户端改走 TCP: 缓存里的完整应答, 不再问上游
	m = mustResp(t, f.handle(dnsBuildQuery(0x56, "big.test", dnsTypeA, 0, false), dnsTestClient, "tcp"))
	if m.Flags&dnsFlagTC != 0 || len(m.Answers) != 40 || m.ID != 0x56 {
		t.Fatalf("tcp full answer: %+v", m)
	}
	if u.tcpN.Load() != 1 || u.udpN.Load() != 1 {
		t.Fatalf("tcp retry should come from cache: udp=%d tcp=%d", u.udpN.Load(), u.tcpN.Load())
	}
	// 客户端 EDNS 4096: 一次 UDP 就能装下(仍然先 TC → TCP 重取, 但不再截断)
	f2 := newTestFwd(u)
	resp = f2.handle(dnsBuildQuery(0x57, "big.test", dnsTypeA, 4096, false), dnsTestClient, "udp")
	if m := mustResp(t, resp); m.Flags&dnsFlagTC != 0 || len(m.Answers) != 40 {
		t.Fatalf("edns client should get full reply: %+v", m)
	}
}

func TestDNSForwarderEDNSPassthrough(t *testing.T) {
	u := startFakeUpstream(t)
	f := newTestFwd(u)
	q := dnsBuildQuery(9, "edns.test", dnsTypeA, 1232, true)
	m := mustResp(t, f.handle(q, dnsTestClient, "udp"))
	if !m.Q.HasOPT {
		t.Fatal("response must carry OPT for EDNS client")
	}
	u.mu.Lock()
	saw, do := u.sawOPT, u.sawDO
	u.mu.Unlock()
	if !saw || !do {
		t.Fatalf("upstream must see client's OPT/DO: opt=%v do=%v", saw, do)
	}
	// 同名不带 EDNS: 缓存键不同, 应答不能带 OPT
	m = mustResp(t, f.handle(dnsBuildQuery(10, "edns.test", dnsTypeA, 0, false), dnsTestClient, "udp"))
	if m.Q.HasOPT {
		t.Fatal("non-EDNS client must not get the cached EDNS reply")
	}
	if u.udpN.Load() != 2 {
		t.Fatalf("upstream hits %d, want 2", u.udpN.Load())
	}
}

func TestDNSForwarderBlockModes(t *testing.T) {
	u := startFakeUpstream(t)
	f := newTestFwd(u)
	f.macOf = func(ip net.IP) string { return "aa:bb:cc:00:00:01" }
	bs := buildDNSBlockSet([]string{"aa:bb:cc:00:00:01 ads.example.com"}, encdnsConf{Policy: "off"}, nil)
	f.blocked = bs.match
	m := mustResp(t, f.handle(dnsBuildQuery(1, "x.ads.example.com", dnsTypeA, 0, false), dnsTestClient, "udp"))
	if m.Rcode != dnsRcodeNXDomain || m.ID != 1 {
		t.Fatalf("nxdomain block: %+v", m)
	}
	f.SetBlockMode("zero")
	m = mustResp(t, f.handle(dnsBuildQuery(2, "ads.example.com", dnsTypeA, 0, false), dnsTestClient, "udp"))
	if m.Rcode != 0 || len(m.Answers) != 1 || m.Answers[0].Value != "0.0.0.0" {
		t.Fatalf("zero A: %+v", m)
	}
	m = mustResp(t, f.handle(dnsBuildQuery(3, "ads.example.com", dnsTypeAAAA, 0, false), dnsTestClient, "udp"))
	if len(m.Answers) != 1 || m.Answers[0].Value != "::" {
		t.Fatalf("zero AAAA: %+v", m)
	}
	m = mustResp(t, f.handle(dnsBuildQuery(4, "ads.example.com", dnsTypeTXT, 0, false), dnsTestClient, "udp"))
	if m.Rcode != 0 || m.ANCount != 0 {
		t.Fatalf("zero TXT → NODATA: %+v", m)
	}
	// 不是父域的同后缀名不拦; 别的设备不拦
	f.handle(dnsBuildQuery(5, "notads.example.com", dnsTypeA, 0, false), dnsTestClient, "udp")
	f.macOf = func(ip net.IP) string { return "aa:bb:cc:00:00:02" }
	f.handle(dnsBuildQuery(6, "ads.example.com", dnsTypeA, 0, false), dnsTestClient, "udp")
	if st := f.Stats(); st.Blocked != 4 || st.Upstream != 2 {
		t.Fatalf("stats %+v", st)
	}
	if u.udpN.Load() != 2 {
		t.Fatal("blocked queries must not reach upstream")
	}
}

func TestDNSBlockSetEncdnsStrict(t *testing.T) {
	hosts := []string{"dns.google", "doh.pub"}
	b := buildDNSBlockSet(nil, encdnsConf{Policy: "strict", Devices: map[string]string{
		"aa:bb:cc:00:00:02": "off", "aa:bb:cc:00:00:03": "strict"}}, hosts)
	if !b.match("aa:bb:cc:00:00:01", "dns.google") || !b.match("", "x.doh.pub") {
		t.Fatal("global strict must block resolver names for everyone (incl. unknown mac)")
	}
	if b.match("aa:bb:cc:00:00:02", "dns.google") {
		t.Fatal("device override off must be exempt")
	}
	if !b.match("aa:bb:cc:00:00:03", "dns.google") {
		t.Fatal("device strict must block")
	}
	b2 := buildDNSBlockSet([]string{"02:5e:00:00:00:01 a.com", "bad line"}, encdnsConf{Policy: "dot",
		Devices: map[string]string{"aa:bb:cc:00:00:03": "strict"}}, hosts)
	if b2.match("02:5e:00:00:00:01", "a.com") || b2.match("aa:bb:cc:00:00:01", "dns.google") || !b2.match("aa:bb:cc:00:00:03", "doh.pub") {
		t.Fatal("sim skipped / dot global does not block names / device strict blocks")
	}
	var nilSet *dnsBlockSet
	if nilSet.match("x", "y") {
		t.Fatal("nil set")
	}
}

func TestDNSForwarderRateLimit(t *testing.T) {
	u := startFakeUpstream(t)
	f := newTestFwd(u)
	f.limiter = newDNSRateLimiter(0.001, 2, 10)
	for i := 0; i < 2; i++ {
		if m := mustResp(t, f.handle(dnsBuildQuery(uint16(i), "rl.test", dnsTypeA, 0, false), dnsTestClient, "udp")); m.Rcode != 0 {
			t.Fatalf("within burst rcode %d", m.Rcode)
		}
	}
	if m := mustResp(t, f.handle(dnsBuildQuery(3, "rl.test", dnsTypeA, 0, false), dnsTestClient, "udp")); m.Rcode != dnsRcodeRefused {
		t.Fatalf("over limit must be REFUSED, got %d", m.Rcode)
	}
	// 另一个客户端不受影响; 本机自检不限速
	if m := mustResp(t, f.handle(dnsBuildQuery(4, "rl.test", dnsTypeA, 0, false), net.ParseIP("192.168.43.11"), "udp")); m.Rcode != 0 {
		t.Fatal("other client limited")
	}
	for i := 0; i < 5; i++ {
		if m := mustResp(t, f.handle(dnsBuildQuery(5, "rl.test", dnsTypeA, 0, false), net.ParseIP("127.0.0.1"), "udp")); m.Rcode != 0 {
			t.Fatal("local selftest must not be limited")
		}
	}
	if st := f.Stats(); st.RateLimited != 1 || st.Queries != 4 {
		t.Fatalf("stats %+v (local queries must not count)", st)
	}
}

func TestDNSForwarderUpstreamDownServfail(t *testing.T) {
	f := newDNSForwarder()
	f.timeout = 300 * time.Millisecond
	uc, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}) // 收了不回
	defer uc.Close()
	f.SetUpstream(uc.LocalAddr().String())
	m := mustResp(t, f.handle(dnsBuildQuery(1, "down.test", dnsTypeA, 0, false), dnsTestClient, "udp"))
	if m.Rcode != dnsRcodeServFail {
		t.Fatalf("rcode %d", m.Rcode)
	}
	if st := f.Stats(); st.Errors != 1 || st.UpstreamErrs != 1 {
		t.Fatalf("stats %+v", st)
	}
	f.SetUpstream("")
	if m := mustResp(t, f.handle(dnsBuildQuery(2, "down.test", dnsTypeA, 0, false), dnsTestClient, "udp")); m.Rcode != dnsRcodeServFail {
		t.Fatal("no upstream → SERVFAIL")
	}
	// 不可解析的包 / 应答包直接丢
	if f.handle([]byte{1, 2, 3}, dnsTestClient, "udp") != nil {
		t.Fatal("garbage must be dropped")
	}
	resp := dnsRcodeReply(dnsBuildQuery(3, "x.test", dnsTypeA, 0, false), dnsQuery{QEnd: 12 + len(dnsEncodeName("x.test")) + 4}, 0)
	if f.handle(resp, dnsTestClient, "udp") != nil {
		t.Fatal("responses (QR=1) must be dropped")
	}
}

func TestDNSExchangeIgnoresWrongID(t *testing.T) {
	u := startFakeUpstream(t)
	u.mu.Lock()
	u.wrongID1 = true
	u.mu.Unlock()
	f := newTestFwd(u)
	m := mustResp(t, f.handle(dnsBuildQuery(0x4242, "spoof.test", dnsTypeA, 0, false), dnsTestClient, "udp"))
	if m.ID != 0x4242 || len(m.Answers) != 1 {
		t.Fatalf("%+v", m)
	}
}

func TestDNSForwarderCNAMEChainAnswerEvent(t *testing.T) {
	u := startFakeUpstream(t)
	f := newTestFwd(u)
	var ev dnsAnswerEvent
	f.onAnswer = func(e dnsAnswerEvent) { ev = e }
	f.handle(dnsBuildQuery(1, "cn.test", dnsTypeA, 0, false), dnsTestClient, "udp")
	if ev.QName != "cn.test" || ev.CNAME != "real.test" || len(ev.IPs) != 1 || ev.IPs[0].Value != "5.6.7.8" {
		t.Fatalf("%+v", ev)
	}
}

func TestDNSForwarderListenUDPTCPAndProbe(t *testing.T) {
	u := startFakeUpstream(t)
	f := newTestFwd(u)
	uc, ln, port := freeDualPort(t)
	uc.Close()
	ln.Close()
	if err := f.Listen([]string{"127.0.0.1"}, port); err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	addr := "127.0.0.1:" + strconv.Itoa(port)
	if _, rc, err := dnsProbe(addr, time.Second); err != nil || rc != 0 {
		t.Fatalf("probe via forwarder: rc=%d err=%v", rc, err)
	}
	q := dnsBuildQuery(0x77, "tcp.test", dnsTypeA, 0, false)
	resp, err := dnsExchangeTCP(addr, q, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if m := mustResp(t, resp); m.ID != 0x77 || len(m.Answers) != 1 {
		t.Fatalf("%+v", m)
	}
	if st := f.Stats(); st.Queries != 0 {
		t.Fatalf("loopback probes are local, must not count: %+v", st)
	}
	if got := f.ListenAddrs(); len(got) != 1 || got[0] != addr {
		t.Fatalf("listen %v", got)
	}
	f.Close()
	if _, _, err := dnsProbe(addr, 300*time.Millisecond); err == nil {
		t.Fatal("closed forwarder must not answer")
	}
}

func TestDNSWireTruncateAndParse(t *testing.T) {
	q := dnsBuildQuery(1, "a.b", dnsTypeA, 0, false)
	pq, err := dnsParseQuery(q)
	if err != nil || pq.QName != "a.b" || pq.HasOPT || pq.UDPSize != 512 {
		t.Fatalf("%+v %v", pq, err)
	}
	q2 := dnsBuildQuery(1, "a.b", dnsTypeA, 100, false)
	if p2, _ := dnsParseQuery(q2); !p2.HasOPT || p2.UDPSize != 512 {
		t.Fatalf("edns size below 512 must clamp: %+v", p2)
	}
	big := make([]byte, 600)
	copy(big, dnsReplyHeader(q, pq, 0, 3))
	tr := dnsTruncate(big, 512)
	if len(tr) != pq.QEnd || binary.BigEndian.Uint16(tr[2:4])&dnsFlagTC == 0 || binary.BigEndian.Uint16(tr[6:8]) != 0 {
		t.Fatal("truncate")
	}
	// 压缩指针环 / 越界不 panic
	bad := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1}
	if _, err := dnsParseQuery(bad); err == nil {
		t.Fatal("pointer loop must fail")
	}
	if _, err := dnsParseResponse([]byte{1, 2}); err == nil {
		t.Fatal("short")
	}
}

func TestDNSForwarderAtomicAlignment(t *testing.T) {
	var f dnsForwarder
	if off := unsafe.Offsetof(f.st); off != 0 {
		t.Fatalf("dnsForwarder.st offset = %d, want 0", off)
	}
	base := uintptr(unsafe.Pointer(&f))
	fields := map[string]uintptr{
		"queries":    uintptr(unsafe.Pointer(&f.st.queries)) - base,
		"cached":     uintptr(unsafe.Pointer(&f.st.cached)) - base,
		"blocked":    uintptr(unsafe.Pointer(&f.st.blocked)) - base,
		"errors":     uintptr(unsafe.Pointer(&f.st.errors)) - base,
		"limited":    uintptr(unsafe.Pointer(&f.st.limited)) - base,
		"dropped":    uintptr(unsafe.Pointer(&f.st.dropped)) - base,
		"upstream":   uintptr(unsafe.Pointer(&f.st.upstream)) - base,
		"upErrs":     uintptr(unsafe.Pointer(&f.st.upErrs)) - base,
		"upTCP":      uintptr(unsafe.Pointer(&f.st.upTCP)) - base,
		"servfail":   uintptr(unsafe.Pointer(&f.st.servfail)) - base,
		"stale":      uintptr(unsafe.Pointer(&f.st.stale)) - base,
		"staleFlush": uintptr(unsafe.Pointer(&f.st.staleFlush)) - base,
		"netCheckNs": uintptr(unsafe.Pointer(&f.st.netCheckNs)) - base,
	}
	for name, off := range fields {
		if off%8 != 0 {
			t.Fatalf("atomic.Int64 field %s offset = %d (not 8-byte aligned)", name, off)
		}
	}
}

func buildTestAReply(q []byte, pq dnsQuery, ip net.IP, ttl uint32, aa bool) []byte {
	out := dnsReplyHeader(q, pq, dnsRcodeNoError, 1)
	if aa {
		binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])|dnsFlagAA)
	}
	out = append(out, 0xC0, 0x0C)
	if ip4 := ip.To4(); ip4 != nil {
		out = binary.BigEndian.AppendUint16(out, dnsTypeA)
		out = binary.BigEndian.AppendUint16(out, 1)
		out = binary.BigEndian.AppendUint32(out, ttl)
		out = binary.BigEndian.AppendUint16(out, 4)
		out = append(out, ip4...)
	} else {
		out = binary.BigEndian.AppendUint16(out, dnsTypeAAAA)
		out = binary.BigEndian.AppendUint16(out, 1)
		out = binary.BigEndian.AppendUint32(out, ttl)
		out = binary.BigEndian.AppendUint16(out, 16)
		out = append(out, ip.To16()...)
	}
	return dnsAppendOPT(out, pq)
}

func buildTestSOAReply(q []byte, pq dnsQuery, rcode int, soaTTL uint32) []byte {
	out := dnsReplyHeader(q, pq, rcode, 0)
	binary.BigEndian.PutUint16(out[8:10], 1)
	out = append(out, 0xC0, 0x0C)
	out = binary.BigEndian.AppendUint16(out, dnsTypeSOA)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint32(out, soaTTL)
	rd := append(dnsEncodeName("ns.test"), dnsEncodeName("h.test")...)
	for _, v := range []uint32{1, 2, 3, 4, soaTTL} {
		rd = binary.BigEndian.AppendUint32(rd, v)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(len(rd)))
	out = append(out, rd...)
	return dnsAppendOPT(out, pq)
}

func TestDNSCacheStale180sCapRewriteAndPoisonGuard(t *testing.T) {
	c := newDNSCache(16, 1<<20)
	t0 := time.Unix(1_750_000_000, 0)

	// 1. 正向应答(带 CNAME + A + EDNS OPT + AA=1): 180s 保活窗口, 重写 TTL=5 且清除 AA
	q := dnsBuildQuery(0x10, "cn.test", dnsTypeA, 1232, false)
	pq, _ := dnsParseQuery(q)
	u := startFakeUpstream(t)
	u.mu.Lock()
	u.ttl = 10
	u.mu.Unlock()
	raw := u.answer(q, "udp")
	binary.BigEndian.PutUint16(raw[2:4], binary.BigEndian.Uint16(raw[2:4])|dnsFlagAA)
	m := mustResp(t, raw)
	key := dnsCacheKey(pq)
	c.put(key, raw, m, t0)

	// 未过期前 getStale 不命中
	if s, _ := c.getStale(key, q, pq, t0.Add(5*time.Second)); s != nil {
		t.Fatal("fresh entry must not be returned via getStale")
	}
	// 过期后 179s 内命中 Stale: TTL 全改 5s, AA 清除, OPT 完好, 0x20 大小写保留
	qClient := dnsBuildQuery(0x9988, "Cn.TeSt", dnsTypeA, 1232, false)
	pqClient, _ := dnsParseQuery(qClient)
	sresp, _ := c.getStale(key, qClient, pqClient, t0.Add(10*time.Second+179*time.Second))
	sm := mustResp(t, sresp)
	if sm.ID != 0x9988 || sm.Flags&dnsFlagAA != 0 || !sm.Q.HasOPT {
		t.Fatalf("stale flags/id/opt mismatch: id=%x flags=%x opt=%v", sm.ID, sm.Flags, sm.Q.HasOPT)
	}
	if string(sresp[12:pqClient.QEnd]) != string(qClient[12:pqClient.QEnd]) {
		t.Fatal("stale reply must preserve client 0x20 question case")
	}
	if len(sm.Answers) != 2 || sm.Answers[0].TTL != 5 || sm.Answers[1].TTL != 5 {
		t.Fatalf("all non-OPT RRs must have TTL=5, got %+v", sm.Answers)
	}
	// 满 180s 立即失效并驱逐
	if s, _ := c.getStale(key, qClient, pqClient, t0.Add(10*time.Second+180*time.Second)); s != nil {
		t.Fatal("entry at expire+180s must not serve stale")
	}
	if c.Len() != 0 {
		t.Fatalf("evicted cache len = %d, want 0", c.Len())
	}

	// 2. NXDOMAIN / NODATA / 全零黑洞(0.0.0.0, ::) 一律 0s 保活宽限
	for _, tc := range []struct {
		name string
		qtyp uint16
		msg  func([]byte, dnsQuery) []byte
	}{
		{"nx-soa.test", dnsTypeA, func(qb []byte, pq dnsQuery) []byte { return buildTestSOAReply(qb, pq, dnsRcodeNXDomain, 20) }},
		{"nodata-soa.test", dnsTypeA, func(qb []byte, pq dnsQuery) []byte { return buildTestSOAReply(qb, pq, dnsRcodeNoError, 20) }},
		{"zero4.test", dnsTypeA, func(qb []byte, pq dnsQuery) []byte { return buildTestAReply(qb, pq, net.IPv4zero, 20, true) }},
		{"zero6.test", dnsTypeAAAA, func(qb []byte, pq dnsQuery) []byte { return buildTestAReply(qb, pq, net.IPv6zero, 20, true) }},
	} {
		qb := dnsBuildQuery(1, tc.name, tc.qtyp, 0, false)
		pqb, _ := dnsParseQuery(qb)
		rb := tc.msg(qb, pqb)
		c.put(dnsCacheKey(pqb), rb, mustResp(t, rb), t0)
		if s, _ := c.getStale(dnsCacheKey(pqb), qb, pqb, t0.Add(20*time.Second)); s != nil {
			t.Fatalf("%s must have 0s stale grace", tc.name)
		}
	}

	// 3. 防旧 IP 诈尸: 无 SOA 的 NXDOMAIN / NODATA 或 TTL=0 必须 deleteKey; SERVFAIL 则保留保活记录
	seedStale := func() (string, []byte, dnsQuery) {
		qb := dnsBuildQuery(2, "zombie.test", dnsTypeA, 0, false)
		pqb, _ := dnsParseQuery(qb)
		rb := buildTestAReply(qb, pqb, net.IPv4(9, 8, 7, 6), 10, true)
		k := dnsCacheKey(pqb)
		c.put(k, rb, mustResp(t, rb), t0)
		return k, qb, pqb
	}
	// 3a: SERVFAIL 不删旧保活
	zk, zq, zpq := seedStale()
	sf := dnsRcodeReply(zq, zpq, dnsRcodeServFail)
	c.put(zk, sf, mustResp(t, sf), t0.Add(15*time.Second))
	if s, _ := c.getStale(zk, zq, zpq, t0.Add(15*time.Second)); s == nil {
		t.Fatal("SERVFAIL must not evict existing stale entry")
	}
	// 3b: 无 SOA NXDOMAIN 删除旧保活
	nxNoSOA := dnsRcodeReply(zq, zpq, dnsRcodeNXDomain)
	c.put(zk, nxNoSOA, mustResp(t, nxNoSOA), t0.Add(16*time.Second))
	if s, _ := c.getStale(zk, zq, zpq, t0.Add(16*time.Second)); s != nil {
		t.Fatal("SOAless NXDOMAIN must delete stale entry")
	}
	// 3c: 无 SOA NODATA 删除旧保活
	zk, zq, zpq = seedStale()
	nodataNoSOA := dnsRcodeReply(zq, zpq, dnsRcodeNoError)
	c.put(zk, nodataNoSOA, mustResp(t, nodataNoSOA), t0.Add(16*time.Second))
	if s, _ := c.getStale(zk, zq, zpq, t0.Add(16*time.Second)); s != nil {
		t.Fatal("SOAless NODATA must delete stale entry")
	}
	// 3d: TTL=0 正向应答删除旧保活
	zk, zq, zpq = seedStale()
	ttlZero := buildTestAReply(zq, zpq, net.IPv4(1, 1, 1, 1), 0, false)
	c.put(zk, ttlZero, mustResp(t, ttlZero), t0.Add(16*time.Second))
	if s, _ := c.getStale(zk, zq, zpq, t0.Add(16*time.Second)); s != nil {
		t.Fatal("TTL=0 answer must delete stale entry")
	}
}

func TestDNSExchangeUDPRandomTXID(t *testing.T) {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	const clientID = uint16(0x4242)
	seenDiff := false
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pq, err := dnsParseQuery(buf[:n])
			if err != nil {
				continue
			}
			// 若上游收到的随机 TXID 不等于客户端原 ID, 先注入一包用客户端原 ID 伪造的黑洞包验证抗投毒
			if pq.ID != clientID {
				fakeQ := append([]byte(nil), buf[:n]...)
				binary.BigEndian.PutUint16(fakeQ[0:2], clientID)
				fpq := pq
				fpq.ID = clientID
				spoof := buildTestAReply(fakeQ, fpq, net.IPv4(6, 6, 6, 6), 60, false)
				_, _ = uc.WriteToUDP(spoof, src)
			}
			realResp := buildTestAReply(buf[:n], pq, net.IPv4(8, 8, 4, 4), 60, false)
			if pq.ID != clientID {
				// 通过不同 TTL 标记观测到了随机 TXID
				binary.BigEndian.PutUint32(realResp[pq.QEnd+6:pq.QEnd+10], 61)
			}
			_, _ = uc.WriteToUDP(realResp, src)
		}
	}()

	q := dnsBuildQuery(clientID, "txid.test", dnsTypeA, 0, false)
	pq, _ := dnsParseQuery(q)
	for i := 0; i < 8; i++ {
		resp, err := dnsExchangeUDP(uc.LocalAddr().String(), q, pq, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		m := mustResp(t, resp)
		if m.ID != clientID || len(m.Answers) != 1 || m.Answers[0].Value != "8.8.4.4" {
			t.Fatalf("got spoiled or wrong ID response: %+v", m)
		}
		if m.Answers[0].TTL == 61 {
			seenDiff = true
		}
	}
	if !seenDiff {
		t.Fatal("expected crypto/rand upstream TXID to differ from fixed client TXID")
	}
}

type controllableUpstream struct {
	hits atomic.Int64 // 置顶 8 字节对齐

	addr  string
	udp   *net.UDPConn
	mu    sync.Mutex
	delay time.Duration
	rcode int
	ip    net.IP
	ttl   uint32
	drop  bool
}

func startControllableUpstream(t *testing.T) *controllableUpstream {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	u := &controllableUpstream{
		addr: uc.LocalAddr().String(),
		udp:  uc,
		ip:   net.IPv4(1, 1, 1, 1),
		ttl:  1,
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			u.hits.Add(1)
			pkt := append([]byte(nil), buf[:n]...)
			go func(pkt []byte, src *net.UDPAddr) {
				u.mu.Lock()
				delay, rcode, ip, ttl, drop := u.delay, u.rcode, u.ip, u.ttl, u.drop
				u.mu.Unlock()
				if drop {
					return
				}
				if delay > 0 {
					time.Sleep(delay)
				}
				pq, err := dnsParseQuery(pkt)
				if err != nil {
					return
				}
				var resp []byte
				if rcode == dnsRcodeNoError {
					resp = buildTestAReply(pkt, pq, ip, ttl, true)
				} else {
					resp = dnsRcodeReply(pkt, pq, rcode)
				}
				_, _ = uc.WriteToUDP(resp, src)
			}(pkt, src)
		}
	}()
	t.Cleanup(func() { uc.Close() })
	return u
}

func TestDNSForwarderServeStale800msFallbackAndRedlines(t *testing.T) {
	u := startControllableUpstream(t)
	f := newDNSForwarder() // 默认 timeout=2500ms, staleWait=800ms
	f.SetUpstream(u.addr)

	var answerCalls atomic.Int64
	f.onAnswer = func(ev dnsAnswerEvent) { answerCalls.Add(1) }
	f.macOf = func(ip net.IP) string { return "aa:bb:cc:00:00:09" }

	// 1. 预热缓存(TTL=1s, IP=1.1.1.1)
	q1 := dnsBuildQuery(0x101, "fast.test", dnsTypeA, 0, false)
	m1 := mustResp(t, f.handle(q1, dnsTestClient, "udp"))
	if m1.Answers[0].Value != "1.1.1.1" || answerCalls.Load() != 1 {
		t.Fatalf("warm cache failed: %+v calls=%d", m1, answerCalls.Load())
	}

	// 等 1.1s 使新鲜记录过期进入 180s 保活期; 将上游设为慢速 1100ms 返回新 IP 2.2.2.2(TTL=60)
	time.Sleep(1100 * time.Millisecond)
	u.mu.Lock()
	u.delay = 1100 * time.Millisecond
	u.ip = net.IPv4(2, 2, 2, 2)
	u.ttl = 60
	u.mu.Unlock()

	// 2. 发起查询: 前台必须在 ~800ms 快速回退 Stale(1.1.1.1, TTL=5, 清 AA), 且绝不调用 onAnswer
	start := time.Now()
	m2 := mustResp(t, f.handle(dnsBuildQuery(0x102, "fast.test", dnsTypeA, 0, false), dnsTestClient, "udp"))
	elapsed := time.Since(start)
	if elapsed < 700*time.Millisecond || elapsed > 1050*time.Millisecond {
		t.Fatalf("800ms fast fallback took %v (want ~800ms, well below 1100ms/2500ms)", elapsed)
	}
	if m2.ID != 0x102 || m2.Rcode != 0 || len(m2.Answers) != 1 || m2.Answers[0].Value != "1.1.1.1" ||
		m2.Answers[0].TTL != 5 || m2.Flags&dnsFlagAA != 0 {
		t.Fatalf("stale reply mismatch: %+v", m2)
	}
	if answerCalls.Load() != 1 {
		t.Fatalf("onAnswer called %d times, stale hit must NOT extend DPI lease", answerCalls.Load())
	}
	if st := f.Stats(); st.Stale != 1 {
		t.Fatalf("stats.Stale = %d, want 1", st.Stale)
	}

	// 3. 等在途单次查询完成(剩余 ~300ms + 缓冲): 新 IP 2.2.2.2 已静默刷入缓存
	time.Sleep(500 * time.Millisecond)
	m3 := mustResp(t, f.handle(dnsBuildQuery(0x103, "fast.test", dnsTypeA, 0, false), dnsTestClient, "udp"))
	if len(m3.Answers) != 1 || m3.Answers[0].Value != "2.2.2.2" || m3.Answers[0].TTL < 50 {
		t.Fatalf("background refresh did not update cache: %+v", m3)
	}

	// 4. RCODE 策略边界: SERVFAIL 回退 Stale; REFUSED / FORMERR / NXDOMAIN 绝不回退!
	seed := func(domain string) {
		u.mu.Lock()
		u.delay, u.rcode, u.ip, u.ttl, u.drop = 0, dnsRcodeNoError, net.IPv4(3, 3, 3, 3), 1, false
		u.mu.Unlock()
		f.handle(dnsBuildQuery(1, domain, dnsTypeA, 0, false), dnsTestClient, "udp")
	}
	seed("sf.test")
	seed("refused.test")
	seed("formerr.test")
	seed("nxnow.test")
	time.Sleep(1100 * time.Millisecond)

	u.mu.Lock()
	u.rcode = dnsRcodeServFail
	u.mu.Unlock()
	if m := mustResp(t, f.handle(dnsBuildQuery(2, "sf.test", dnsTypeA, 0, false), dnsTestClient, "udp")); m.Rcode != 0 || m.Answers[0].Value != "3.3.3.3" || m.Answers[0].TTL != 5 {
		t.Fatalf("SERVFAIL must fallback to stale: %+v", m)
	}

	u.mu.Lock()
	u.rcode = dnsRcodeRefused
	u.mu.Unlock()
	if m := mustResp(t, f.handle(dnsBuildQuery(3, "refused.test", dnsTypeA, 0, false), dnsTestClient, "udp")); m.Rcode != dnsRcodeRefused {
		t.Fatalf("REFUSED must NOT fallback to stale, got rcode=%d", m.Rcode)
	}

	u.mu.Lock()
	u.rcode = 1 // FORMERR
	u.mu.Unlock()
	if m := mustResp(t, f.handle(dnsBuildQuery(4, "formerr.test", dnsTypeA, 0, false), dnsTestClient, "udp")); m.Rcode != 1 {
		t.Fatalf("FORMERR must NOT fallback to stale, got rcode=%d", m.Rcode)
	}

	u.mu.Lock()
	u.rcode = dnsRcodeNXDomain
	u.mu.Unlock()
	if m := mustResp(t, f.handle(dnsBuildQuery(5, "nxnow.test", dnsTypeA, 0, false), dnsTestClient, "udp")); m.Rcode != dnsRcodeNXDomain {
		t.Fatalf("NXDOMAIN must NOT fallback to stale, got rcode=%d", m.Rcode)
	}
	// 无 SOA NXDOMAIN 已清掉旧保活, 后续即使上游断网也不能诈尸
	u.mu.Lock()
	u.drop = true
	u.mu.Unlock()
	f.timeout = 120 * time.Millisecond
	f.staleWait = 60 * time.Millisecond
	if m := mustResp(t, f.handle(dnsBuildQuery(6, "nxnow.test", dnsTypeA, 0, false), dnsTestClient, "udp")); m.Rcode != dnsRcodeServFail {
		t.Fatalf("deleted stale entry must not resurrect, got rcode=%d", m.Rcode)
	}

	// 5. 安全红线: blocked、limiter 严格排在 Serve-Stale 之前; 本机自检(internal / dnsProbe)绝不走 Serve-Stale
	// sf.test 此时仍在 180s 保活窗口内且上游 drop=true
	if m := mustResp(t, f.handle(dnsBuildQuery(7, "sf.test", dnsTypeA, 0, false), dnsTestClient, "udp")); m.Rcode != 0 {
		t.Fatalf("precheck stale sf.test failed: %+v", m)
	}
	// 本机自检来源(127.0.0.1 及 AddLocal 地址)必须旁路 Serve-Stale, 真实返回 SERVFAIL
	f.AddLocal([]string{"192.168.43.1"})
	for _, localIP := range []string{"127.0.0.1", "192.168.43.1"} {
		if m := mustResp(t, f.handle(dnsBuildQuery(8, "sf.test", dnsTypeA, 0, false), net.ParseIP(localIP), "udp")); m.Rcode != dnsRcodeServFail {
			t.Fatalf("internal source %s must bypass Serve-Stale, got rcode=%d", localIP, m.Rcode)
		}
	}
	// 封锁优先于 Serve-Stale
	f.blocked = func(mac, qname string) bool { return qname == "sf.test" }
	if m := mustResp(t, f.handle(dnsBuildQuery(9, "sf.test", dnsTypeA, 0, false), dnsTestClient, "udp")); m.Rcode != dnsRcodeNXDomain {
		t.Fatalf("blocked domain must not serve stale, got rcode=%d", m.Rcode)
	}
	f.blocked = nil
	// 限速优先于 Serve-Stale
	f.limiter = newDNSRateLimiter(0.001, 1, 10)
	_ = f.handle(dnsBuildQuery(10, "sf.test", dnsTypeA, 0, false), dnsTestClient, "udp") // 消耗唯一令牌
	if m := mustResp(t, f.handle(dnsBuildQuery(11, "sf.test", dnsTypeA, 0, false), dnsTestClient, "udp")); m.Rcode != dnsRcodeRefused {
		t.Fatalf("rate-limited client must get REFUSED before Serve-Stale, got rcode=%d", m.Rcode)
	}
}

func TestDNSForwarderFlushAndZeroBackgroundGoroutines(t *testing.T) {
	u1 := startFakeUpstream(t)
	u2 := startFakeUpstream(t)

	runtime.GC()
	time.Sleep(30 * time.Millisecond)
	gBase := runtime.NumGoroutine()

	f := newDNSForwarder()
	f.SetUpstream(u1.addr)
	// 首次从空地址设上游且缓存为空, stale_flushes 应为 0
	if st := f.Stats(); st.StaleFlushes != 0 {
		t.Fatalf("initial SetUpstream StaleFlushes = %d, want 0", st.StaleFlushes)
	}
	f.handle(dnsBuildQuery(1, "sw.test", dnsTypeA, 0, false), dnsTestClient, "udp")
	if f.cache.Len() != 1 {
		t.Fatal("expected 1 cached entry")
	}
	// 相同上游地址重复设置不清缓存
	f.SetUpstream(u1.addr)
	if f.cache.Len() != 1 || f.Stats().StaleFlushes != 0 {
		t.Fatal("same upstream must not flush")
	}
	// 切换上游地址立即清空缓存
	f.SetUpstream(u2.addr)
	if f.cache.Len() != 0 || f.Stats().StaleFlushes != 1 {
		t.Fatalf("upstream switch must flush immediately: len=%d flushes=%d", f.cache.Len(), f.Stats().StaleFlushes)
	}

	// SyncNetSig: 首次基线不清; 完全断网("")不清保活缓存; 换网签名立即秒清
	f.SyncNetSig("192.168.1.5|wlan0")
	f.handle(dnsBuildQuery(2, "net.test", dnsTypeA, 0, false), dnsTestClient, "udp")
	if f.cache.Len() != 1 || f.Stats().StaleFlushes != 1 {
		t.Fatal("baseline netSig must keep cache")
	}
	if f.SyncNetSig("") || f.cache.Len() != 1 {
		t.Fatal("offline empty netSig must NOT flush stale cache")
	}
	if !f.SyncNetSig("10.20.30.40|rmnet_data0") || f.cache.Len() != 0 || f.Stats().StaleFlushes != 2 {
		t.Fatalf("network switch must flush cache immediately: len=%d flushes=%d", f.cache.Len(), f.Stats().StaleFlushes)
	}

	// 验证零新增常驻后台 goroutine(含走过 Stale 快回退路径后)
	q := dnsBuildQuery(3, "goro.test", dnsTypeA, 0, false)
	pq, _ := dnsParseQuery(q)
	tPast := time.Now().Add(-10 * time.Second)
	raw := buildTestAReply(q, pq, net.IPv4(4, 4, 4, 4), 5, false)
	f.cache.put(dnsCacheKey(pq), raw, mustResp(t, raw), tPast)

	ucDrop, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer ucDrop.Close()
	f.upstream.Store(ucDrop.LocalAddr().String())
	f.staleWait = 50 * time.Millisecond
	f.timeout = 150 * time.Millisecond

	m := mustResp(t, f.handle(q, dnsTestClient, "udp"))
	if m.Answers[0].Value != "4.4.4.4" {
		t.Fatalf("expected stale 4.4.4.4, got %+v", m)
	}
	// 等在途单次上游 150ms 超时退出
	time.Sleep(220 * time.Millisecond)
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	if gNow := runtime.NumGoroutine(); gNow > gBase+1 {
		t.Fatalf("unexpected persistent goroutines: before=%d after=%d", gBase, gNow)
	}
}

func TestDNSLoopbackPoisonZeroStaleGrace(t *testing.T) {
	c := newDNSCache(16, 1<<20)
	t0 := time.Unix(1_760_000_000, 0)

	for _, tc := range []struct {
		name string
		qtyp uint16
		ip   net.IP
	}{
		{"loop4-1.test", dnsTypeA, net.IPv4(127, 0, 0, 1)},
		{"loop4-53.test", dnsTypeA, net.IPv4(127, 0, 0, 53)},
		{"loop6.test", dnsTypeAAAA, net.IPv6loopback},
	} {
		qb := dnsBuildQuery(1, tc.name, tc.qtyp, 0, false)
		pqb, _ := dnsParseQuery(qb)
		rb := buildTestAReply(qb, pqb, tc.ip, 15, true)
		m := mustResp(t, rb)
		if !dnsHasZeroAnswer(m) {
			t.Fatalf("expected dnsHasZeroAnswer=true for loopback %s (%s)", tc.name, tc.ip.String())
		}
		key := dnsCacheKey(pqb)
		c.put(key, rb, m, t0)
		if s, _ := c.getStale(key, qb, pqb, t0.Add(15*time.Second)); s != nil {
			t.Fatalf("loopback poison answer %s (%s) must have 0s Serve-Stale grace", tc.name, tc.ip.String())
		}
	}
}

func TestDNSForwarderPutIfSeqAcrossFlushInHandleAndFastStale(t *testing.T) {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	var replyIP atomic.Value
	replyIP.Store(net.IPv4(9, 9, 9, 9))

	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, rErr := uc.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			select {
			case arrived <- struct{}{}:
			default:
			}
			go func(pkt []byte, src *net.UDPAddr) {
				<-release
				pq, pErr := dnsParseQuery(pkt)
				if pErr != nil {
					return
				}
				ip, _ := replyIP.Load().(net.IP)
				resp := buildTestAReply(pkt, pq, ip, 60, true)
				_, _ = uc.WriteToUDP(resp, src)
			}(pkt, src)
		}
	}()

	f := newDNSForwarder()
	f.timeout = time.Second
	f.staleWait = 500 * time.Millisecond
	f.SetUpstream(uc.LocalAddr().String())

	// 1. 验证普通冷未命中 handle(): 在途期间发生 FlushCache(), 旧网在途包绝不能写回缓存!
	done1 := make(chan []byte, 1)
	go func() {
		done1 <- f.handle(dnsBuildQuery(0x21, "race-cold.test", dnsTypeA, 0, false), dnsTestClient, "udp")
	}()
	<-arrived
	f.FlushCache()
	close(release)
	_ = mustResp(t, <-done1)
	if f.cache.Len() != 0 {
		t.Fatalf("in-flight pre-flush response in handle() must NOT pollute flushed cache, len=%d", f.cache.Len())
	}

	// 2. 验证 handleWithStale `<800ms` 前台快速返回分支: 在途期间发生 FlushCache(), 同样受 putIfSeq 保护!
	q2 := dnsBuildQuery(0x22, "race-stale.test", dnsTypeA, 0, false)
	pq2, _ := dnsParseQuery(q2)
	seedResp := buildTestAReply(q2, pq2, net.IPv4(1, 2, 3, 4), 1, false)
	f.cache.put(dnsCacheKey(pq2), seedResp, mustResp(t, seedResp), time.Now().Add(-5*time.Second))

	release = make(chan struct{})
	replyIP.Store(net.IPv4(5, 5, 5, 5))
	done2 := make(chan []byte, 1)
	go func() {
		done2 <- f.handle(q2, dnsTestClient, "udp")
	}()
	<-arrived
	f.FlushCache() // 模拟切网清空缓存 (此时上游响应尚在 <500ms 前台等待窗口内)
	close(release)
	m2 := mustResp(t, <-done2)
	if len(m2.Answers) != 1 || m2.Answers[0].Value != "5.5.5.5" {
		t.Fatalf("expected foreground reply 5.5.5.5, got %+v", m2)
	}
	if f.cache.Len() != 0 {
		t.Fatalf("in-flight pre-flush response in <800ms handleWithStale must NOT pollute flushed cache, len=%d", f.cache.Len())
	}
}

func TestDNSForwarderStaleBgSemBoundsDetachedGoroutines(t *testing.T) {
	ucDrop, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ucDrop.Close()

	f := newDNSForwarder()
	if cap(f.bgSem) != dnsFwdMaxStaleBg {
		t.Fatalf("expected default bgSem cap=%d, got %d", dnsFwdMaxStaleBg, cap(f.bgSem))
	}
	// 缩窄测试配额为 4, staleWait=25ms, timeout=500ms, 模拟 32 并发弱网超时风暴
	f.bgSem = make(chan struct{}, 4)
	f.staleWait = 25 * time.Millisecond
	f.timeout = 500 * time.Millisecond
	f.SetUpstream(ucDrop.LocalAddr().String())

	tPast := time.Now().Add(-5 * time.Second)
	for i := 0; i < 32; i++ {
		domain := "storm-" + strconv.Itoa(i) + ".test"
		q := dnsBuildQuery(uint16(100+i), domain, dnsTypeA, 0, false)
		pq, _ := dnsParseQuery(q)
		raw := buildTestAReply(q, pq, net.IPv4(8, 8, 8, byte(i+1)), 1, false)
		f.cache.put(dnsCacheKey(pq), raw, mustResp(t, raw), tPast)
	}

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	gBefore := runtime.NumGoroutine()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			domain := "storm-" + strconv.Itoa(idx) + ".test"
			q := dnsBuildQuery(uint16(200+idx), domain, dnsTypeA, 0, false)
			ip := net.IPv4(192, 168, 43, byte(10+idx))
			m := mustResp(t, f.handle(q, ip, "udp"))
			if m.Rcode != dnsRcodeNoError || len(m.Answers) != 1 {
				t.Errorf("expected stale fallback for %s, got %+v", domain, m)
			}
		}(i)
	}
	wg.Wait()

	// 给被 bgSem 拒绝并 cancelExch() 的 28 个协程 30ms 收敛退出, 此时仍在 500ms timeout 窗口内:
	// 驻留后台等待的孤儿协程严禁超过 bgSem 上限(4) + 少量调度余量!
	time.Sleep(35 * time.Millisecond)
	if len(f.bgSem) > 4 {
		t.Fatalf("bgSem len=%d exceeded cap 4", len(f.bgSem))
	}
	if gMid := runtime.NumGoroutine(); gMid > gBefore+8 {
		t.Fatalf("detached stale goroutine explosion detected: before=%d mid=%d (want <= %d)", gBefore, gMid, gBefore+8)
	}

	// 等剩余 4 个后台刷新自然超时归零
	time.Sleep(550 * time.Millisecond)
	if len(f.bgSem) != 0 {
		t.Fatalf("expected bgSem drained to 0 after timeout, got %d", len(f.bgSem))
	}
}

func TestDNSRateLimiterTableFullFailClosedAndSweepThrottle(t *testing.T) {
	lim := newDNSRateLimiter(10, 4, 1024)
	t0 := time.Unix(1_770_000_000, 0)

	// 填满 1024 个合法客户端桶
	for i := 0; i < 1024; i++ {
		ip := "10.0." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256)
		if !lim.allow(ip, t0) {
			t.Fatalf("initial client %d (%s) should be allowed", i, ip)
		}
	}

	// 未满 1 分钟清扫周期(t0+15s): 新增第 1025..1050 个伪造源 IP 必须全部返回 false (拒绝放行且不撑爆 map),
	// 同时已有合法客户端桶仍正常放行!
	for i := 0; i < 32; i++ {
		spoof := "172.16.99." + strconv.Itoa(i+1)
		if lim.allow(spoof, t0.Add(15*time.Second)) {
			t.Fatalf("unknown spoofed IP %s MUST be rejected (return false) when table is at 1024 cap", spoof)
		}
	}
	lim.mu.Lock()
	mapSize := len(lim.m)
	lim.mu.Unlock()
	if mapSize != 1024 {
		t.Fatalf("expected limiter map capped at 1024, got %d", mapSize)
	}
	if !lim.allow("10.0.0.1", t0.Add(15*time.Second)) {
		t.Fatal("existing tracked client 10.0.0.1 must continue to be allowed within burst")
	}

	// 满 1 分钟清扫间隔后(t0+61s): 闲置满 60s 的旧桶被回收(10.0.0.1 在 +15s 活跃过故保留, 其余 1023 个回收), 新客户端恢复放行!
	if !lim.allow("192.168.43.250", t0.Add(61*time.Second)) {
		t.Fatal("new client should be admitted after 1m idle sweep frees stale buckets")
	}
	lim.mu.Lock()
	afterSweepSize := len(lim.m)
	lim.mu.Unlock()
	if afterSweepSize != 2 {
		t.Fatalf("expected 2 active buckets (10.0.0.1 + 192.168.43.250) after 61s sweep, got %d", afterSweepSize)
	}
}
