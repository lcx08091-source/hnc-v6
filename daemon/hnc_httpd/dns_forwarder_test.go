package main

import (
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// DPI v2 dns_forwarder.go / dns_wire.go: 假上游(UDP+TCP 同端口)上的转发、缓存 TTL、
// 截断 → TCP 重取、EDNS 透传、封锁应答、限速、上游故障。

type fakeUpstream struct {
	addr     string
	udp      *net.UDPConn
	tcp      net.Listener
	udpN     int64
	tcpN     int64
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
			atomic.AddInt64(&u.udpN, 1)
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
					atomic.AddInt64(&u.tcpN, 1)
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
	if n := atomic.LoadInt64(&u.udpN); n != 1 {
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
		t.Fatal("expired entry must miss")
	}
	if c.Len() != 0 {
		t.Fatal("expired entry must be evicted")
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
	if atomic.LoadInt64(&u.udpN) != 1 {
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
	if atomic.LoadInt64(&u.tcpN) != 1 || f.Stats().UpstreamTCP != 1 {
		t.Fatalf("upstream tcp retry missing: tcp=%d", u.tcpN)
	}
	// 客户端改走 TCP: 缓存里的完整应答, 不再问上游
	m = mustResp(t, f.handle(dnsBuildQuery(0x56, "big.test", dnsTypeA, 0, false), dnsTestClient, "tcp"))
	if m.Flags&dnsFlagTC != 0 || len(m.Answers) != 40 || m.ID != 0x56 {
		t.Fatalf("tcp full answer: %+v", m)
	}
	if atomic.LoadInt64(&u.tcpN) != 1 || atomic.LoadInt64(&u.udpN) != 1 {
		t.Fatalf("tcp retry should come from cache: udp=%d tcp=%d", u.udpN, u.tcpN)
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
	if atomic.LoadInt64(&u.udpN) != 2 {
		t.Fatalf("upstream hits %d, want 2", u.udpN)
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
	if atomic.LoadInt64(&u.udpN) != 2 {
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
