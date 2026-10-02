// dns_forwarder.go — DNS 接管的转发器核心(与 iptables / 配置无关, 可单测)
//
// 监听 <热点网关 IP>:15353 的 UDP + TCP。客户端发往网关 53 的查询被 nat/PREROUTING
// DNAT 到这里(bin/dns_takeover.sh), 转发器:
//   1. 解析问题; 非本机来源按客户端 IP 限速(令牌桶, 超限回 REFUSED);
//   2. 查封锁表(按 MAC, 域名或其父域)→ 直接回 NXDOMAIN / 0.0.0.0;
//   3. 查缓存(LRU, 尊重 TTL, 命中时按已过时间递减 TTL, 问题段用客户端原字节以兼容 0x20);
//   4. 未命中: 原样(含 EDNS)转发给上游(默认 = 网关 IP:53, 即系统给热点用的解析器),
//      UDP 应答带 TC 时改走 TCP 重取; 校验 ID + 问题一致才采纳;
//   5. 应答超过客户端 UDP 上限(无 EDNS 512, 有 EDNS 按其声明)时截断置 TC, 客户端会改走 TCP。
//
// 防环: 转发器自身发往上游的包是本机产生的, 只经过 OUTPUT, 不经过 PREROUTING,
// 永远不会被自己的 DNAT 规则再次改写; DNAT 规则也只匹配 -i <热点口>。
//
// 钩子(dns_takeover.go 注入): macOf(客户端 IP→MAC)、blocked(mac,qname)、
// onAnswer(给 IP→域名表喂数据)、onLog(查询日志 / 今日热门域名)。

package main

import (
	"container/list"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dnsFwdDefaultPort    = 15353
	dnsFwdUpTimeout      = 2500 * time.Millisecond
	dnsFwdTCPIdle        = 10 * time.Second
	dnsFwdMaxInflight    = 256
	dnsFwdMaxTCPConns    = 64
	dnsCacheMaxEntries   = 2048
	dnsCacheMaxBytes     = 4 << 20
	dnsCacheMaxTTL       = 3600
	dnsCacheMaxNegTTL    = 300
	dnsRateDefaultPerSec = 50
	dnsRateDefaultBurst  = 200
	dnsRateMaxClients    = 1024
	dnsLatRing           = 512
)

// dnsLogEntry 一条客户端查询(内存环 / 日志文件 / API 共用)
type dnsLogEntry struct {
	Ts      int64    `json:"ts"` // 毫秒
	MAC     string   `json:"mac,omitempty"`
	IP      string   `json:"ip"`
	QName   string   `json:"qname"`
	QType   string   `json:"qtype"`
	Rcode   string   `json:"rcode"`
	Answers []string `json:"answers,omitempty"`
	Cached  bool     `json:"cached,omitempty"`
	Blocked bool     `json:"blocked,omitempty"`
	Limited bool     `json:"limited,omitempty"`
	MS      float64  `json:"ms"`
	Proto   string   `json:"proto"`
}

// dnsAnswerEvent 一次成功解析(给 IP→域名表)
type dnsAnswerEvent struct {
	MAC   string
	QName string
	CNAME string
	IPs   []dnsRR
	Ts    time.Time
}

type dnsFwdStats struct {
	Queries      int64 `json:"queries"`       // 客户端查询(不含本机自检)
	Cached       int64 `json:"cached"`        // 缓存命中
	Blocked      int64 `json:"blocked"`       // 封锁应答
	Errors       int64 `json:"errors"`        // 回给客户端 SERVFAIL 的次数(上游失败 / 应答不合法)
	RateLimited  int64 `json:"ratelimited"`   // 限速回 REFUSED
	Dropped      int64 `json:"dropped"`       // 过载 / 不可解析丢弃
	Upstream     int64 `json:"upstream"`      // 发往上游的查询
	UpstreamErrs int64 `json:"upstream_errs"` // 上游超时 / 网络错误 / 串包
	UpstreamTCP  int64 `json:"upstream_tcp"`  // TC 后改走 TCP 的次数
	ServFail     int64 `json:"servfail"`      // 上游自己回的 SERVFAIL
}

type dnsForwarder struct {
	upstream  atomic.Value // string "ip:port"
	blockMode atomic.Value // string
	timeout   time.Duration

	macOf    func(ip net.IP) string
	blocked  func(mac, qname string) bool
	onAnswer func(ev dnsAnswerEvent)
	onLog    func(e dnsLogEntry)

	cache   *dnsCache
	limiter *dnsRateLimiter

	mu       sync.Mutex
	udp      []*net.UDPConn
	tcp      []net.Listener
	local    map[string]bool // 本机地址(自检来源, 不计统计/不限速/不封锁)
	listen   []string
	closed   bool
	wg       sync.WaitGroup
	sem      chan struct{}
	tcpSem   chan struct{}
	tcpConns map[net.Conn]bool

	st struct {
		queries, cached, blocked, errors, limited, dropped int64
		upstream, upErrs, upTCP, servfail                  int64
	}
	latMu  sync.Mutex
	lat    [dnsLatRing]float64
	latN   int
	latPos int
}

func newDNSForwarder() *dnsForwarder {
	f := &dnsForwarder{
		timeout:  dnsFwdUpTimeout,
		cache:    newDNSCache(dnsCacheMaxEntries, dnsCacheMaxBytes),
		limiter:  newDNSRateLimiter(dnsRateDefaultPerSec, dnsRateDefaultBurst, dnsRateMaxClients),
		local:    map[string]bool{},
		sem:      make(chan struct{}, dnsFwdMaxInflight),
		tcpSem:   make(chan struct{}, dnsFwdMaxTCPConns),
		tcpConns: map[net.Conn]bool{},
	}
	f.upstream.Store("")
	f.blockMode.Store("nxdomain")
	return f
}

func (f *dnsForwarder) SetUpstream(addr string) { f.upstream.Store(addr) }
func (f *dnsForwarder) Upstream() string        { s, _ := f.upstream.Load().(string); return s }
func (f *dnsForwarder) SetBlockMode(m string) {
	if m != "zero" {
		m = "nxdomain"
	}
	f.blockMode.Store(m)
}

// Listen 在每个地址的 port 上开 UDP + TCP。任何一个失败则全部关闭并返回错误。
func (f *dnsForwarder) Listen(addrs []string, port int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errors.New("forwarder closed")
	}
	for _, a := range addrs {
		hp := net.JoinHostPort(a, strconv.Itoa(port))
		ua, err := net.ResolveUDPAddr("udp", hp)
		if err != nil {
			f.closeLocked()
			return err
		}
		uc, err := net.ListenUDP("udp", ua)
		if err != nil {
			f.closeLocked()
			return err
		}
		ln, err := net.Listen("tcp", hp)
		if err != nil {
			uc.Close()
			f.closeLocked()
			return err
		}
		f.udp = append(f.udp, uc)
		f.tcp = append(f.tcp, ln)
		f.listen = append(f.listen, hp)
		if ip := net.ParseIP(a); ip != nil {
			f.local[ip.String()] = true
		}
		f.wg.Add(2)
		go f.serveUDP(uc)
		go f.serveTCP(ln)
	}
	return nil
}

// AddLocal 额外登记本机地址(热点口其它地址), 来自这些地址的查询视为自检
func (f *dnsForwarder) AddLocal(ips []string) {
	f.mu.Lock()
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil {
			f.local[ip.String()] = true
		}
	}
	f.mu.Unlock()
}

func (f *dnsForwarder) ListenAddrs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.listen...)
}

func (f *dnsForwarder) closeLocked() {
	for _, c := range f.udp {
		c.Close()
	}
	for _, l := range f.tcp {
		l.Close()
	}
	for c := range f.tcpConns {
		c.Close()
	}
	f.udp, f.tcp, f.listen = nil, nil, nil
}

// Close 关闭所有监听并等待 goroutine 退出(最多 3 秒)
func (f *dnsForwarder) Close() {
	f.mu.Lock()
	f.closed = true
	f.closeLocked()
	f.mu.Unlock()
	done := make(chan struct{})
	go func() { f.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

func (f *dnsForwarder) isLocal(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.local[ip.String()]
}

func (f *dnsForwarder) serveUDP(c *net.UDPConn) {
	defer f.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, src, err := c.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if n < 12 {
			atomic.AddInt64(&f.st.dropped, 1)
			continue
		}
		select {
		case f.sem <- struct{}{}:
		default:
			atomic.AddInt64(&f.st.dropped, 1)
			continue
		}
		msg := append([]byte(nil), buf[:n]...)
		f.wg.Add(1)
		go func(msg []byte, src *net.UDPAddr) {
			defer func() { <-f.sem; f.wg.Done() }()
			if resp := f.handle(msg, src.IP, "udp"); resp != nil {
				_, _ = c.WriteToUDP(resp, src)
			}
		}(msg, src)
	}
}

func (f *dnsForwarder) serveTCP(ln net.Listener) {
	defer f.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		select {
		case f.tcpSem <- struct{}{}:
		default:
			atomic.AddInt64(&f.st.dropped, 1)
			conn.Close()
			continue
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			conn.Close()
			<-f.tcpSem
			return
		}
		f.tcpConns[conn] = true
		f.mu.Unlock()
		f.wg.Add(1)
		go func(conn net.Conn) {
			defer func() {
				conn.Close()
				f.mu.Lock()
				delete(f.tcpConns, conn)
				f.mu.Unlock()
				<-f.tcpSem
				f.wg.Done()
			}()
			var src net.IP
			if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				src = ta.IP
			}
			for {
				_ = conn.SetDeadline(time.Now().Add(dnsFwdTCPIdle))
				msg, err := dnsReadTCPMsg(conn)
				if err != nil {
					return
				}
				resp := f.handle(msg, src, "tcp")
				if resp == nil {
					return
				}
				if err := dnsWriteTCPMsg(conn, resp); err != nil {
					return
				}
			}
		}(conn)
	}
}

func dnsReadTCPMsg(r io.Reader) ([]byte, error) {
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return nil, err
	}
	l := int(binary.BigEndian.Uint16(lb[:]))
	if l < 12 {
		return nil, errDNSShort
	}
	b := make([]byte, l)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func dnsWriteTCPMsg(w io.Writer, msg []byte) error {
	if len(msg) > 65535 {
		return errDNSBad
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	_, err := w.Write(out)
	return err
}

// handle 处理一条查询, 返回要回给客户端的报文(nil = 不回)
func (f *dnsForwarder) handle(query []byte, src net.IP, proto string) []byte {
	t0 := time.Now()
	q, err := dnsParseQuery(query)
	if err != nil || q.Flags&dnsFlagQR != 0 {
		atomic.AddInt64(&f.st.dropped, 1)
		return nil
	}
	internal := f.isLocal(src)
	var mac, ipStr string
	if src != nil {
		ipStr = src.String()
	}
	logIt := func(resp []byte, e dnsLogEntry) {
		if internal || f.onLog == nil {
			return
		}
		e.Ts, e.MAC, e.IP, e.QName, e.QType, e.Proto = t0.UnixMilli(), mac, ipStr, q.QName, dnsTypeName(q.QType), proto
		e.MS = float64(time.Since(t0).Microseconds()) / 1000
		if e.Rcode == "" && len(resp) >= 4 {
			e.Rcode = dnsRcodeName(int(binary.BigEndian.Uint16(resp[2:4]) & 0xF))
		}
		f.onLog(e)
	}
	limit := q.UDPSize
	finish := func(resp []byte) []byte {
		if proto == "udp" {
			resp = dnsTruncate(resp, limit)
		}
		if !internal {
			f.addLat(float64(time.Since(t0).Microseconds()) / 1000)
		}
		return resp
	}
	if !internal {
		atomic.AddInt64(&f.st.queries, 1)
		if !f.limiter.allow(ipStr, t0) {
			atomic.AddInt64(&f.st.limited, 1)
			resp := dnsRcodeReply(query, q, dnsRcodeRefused)
			logIt(resp, dnsLogEntry{Limited: true})
			return resp
		}
		if f.macOf != nil {
			mac = f.macOf(src)
		}
		if f.blocked != nil && q.QName != "" && f.blocked(mac, q.QName) {
			atomic.AddInt64(&f.st.blocked, 1)
			mode, _ := f.blockMode.Load().(string)
			resp := dnsBlockReply(query, q, mode)
			logIt(resp, dnsLogEntry{Blocked: true})
			return finish(resp)
		}
	}
	opcode := (q.Flags >> 11) & 0xF
	cacheable := opcode == 0 && q.QClass == 1 && q.OptLen == 0
	key := ""
	if cacheable {
		key = dnsCacheKey(q)
		if resp, info := f.cache.get(key, query, q, t0); resp != nil {
			if !internal {
				atomic.AddInt64(&f.st.cached, 1)
			}
			logIt(resp, dnsLogEntry{Cached: true, Answers: dnsLogAnswers(info)})
			return finish(resp)
		}
	}
	resp, err := f.exchange(query, q, proto)
	if err != nil {
		atomic.AddInt64(&f.st.errors, 1)
		out := dnsRcodeReply(query, q, dnsRcodeServFail)
		logIt(out, dnsLogEntry{})
		return finish(out)
	}
	m, perr := dnsParseResponse(resp)
	if perr != nil || !dnsSameQuestion(q, m) {
		atomic.AddInt64(&f.st.errors, 1)
		atomic.AddInt64(&f.st.upErrs, 1)
		out := dnsRcodeReply(query, q, dnsRcodeServFail)
		logIt(out, dnsLogEntry{})
		return finish(out)
	}
	if m.Rcode == dnsRcodeServFail {
		atomic.AddInt64(&f.st.servfail, 1)
	}
	if cacheable && m.Flags&dnsFlagTC == 0 {
		f.cache.put(key, resp, m, t0)
	}
	if !internal && f.onAnswer != nil && m.Rcode == dnsRcodeNoError {
		if ips, cn := dnsAnswerIPs(q.QName, m.Answers); len(ips) > 0 {
			f.onAnswer(dnsAnswerEvent{MAC: mac, QName: q.QName, CNAME: cn, IPs: ips, Ts: t0})
		}
	}
	logIt(resp, dnsLogEntry{Answers: dnsLogAnswers(m)})
	return finish(resp)
}

func dnsLogAnswers(m dnsMsgInfo) []string {
	var out []string
	for _, r := range m.Answers {
		if len(out) >= 8 {
			break
		}
		if r.Type == dnsTypeCNAME {
			out = append(out, "CNAME:"+r.Value)
		} else {
			out = append(out, r.Value)
		}
	}
	return out
}

// exchange 发往上游: UDP(TC → TCP 重取)或 TCP
func (f *dnsForwarder) exchange(query []byte, q dnsQuery, proto string) ([]byte, error) {
	up := f.Upstream()
	if up == "" {
		atomic.AddInt64(&f.st.upErrs, 1)
		return nil, errors.New("no upstream")
	}
	atomic.AddInt64(&f.st.upstream, 1)
	if proto == "tcp" {
		resp, err := dnsExchangeTCP(up, query, f.timeout)
		if err != nil {
			atomic.AddInt64(&f.st.upErrs, 1)
		}
		return resp, err
	}
	resp, err := dnsExchangeUDP(up, query, q, f.timeout)
	if err != nil {
		atomic.AddInt64(&f.st.upErrs, 1)
		return nil, err
	}
	if len(resp) >= 4 && binary.BigEndian.Uint16(resp[2:4])&dnsFlagTC != 0 {
		atomic.AddInt64(&f.st.upTCP, 1)
		if full, terr := dnsExchangeTCP(up, query, f.timeout); terr == nil {
			return full, nil
		}
		// TCP 重取失败: 把截断应答原样给客户端, 客户端自己会再走 TCP
	}
	return resp, nil
}

// dnsExchangeUDP 用一次性 connected UDP socket(随机源端口)问上游; 只采纳 ID+问题一致的应答
func dnsExchangeUDP(up string, query []byte, q dnsQuery, timeout time.Duration) ([]byte, error) {
	c, err := net.DialTimeout("udp", up, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline := time.Now().Add(timeout)
	_ = c.SetDeadline(deadline)
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 12 || binary.BigEndian.Uint16(buf[0:2]) != q.ID {
			continue
		}
		if m, perr := dnsParseResponse(buf[:n]); perr == nil && !dnsSameQuestion(q, m) {
			continue
		}
		return append([]byte(nil), buf[:n]...), nil
	}
}

func dnsExchangeTCP(up string, query []byte, timeout time.Duration) ([]byte, error) {
	c, err := net.DialTimeout("tcp", up, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if err := dnsWriteTCPMsg(c, query); err != nil {
		return nil, err
	}
	resp, err := dnsReadTCPMsg(c)
	if err != nil {
		return nil, err
	}
	if len(query) >= 2 && binary.BigEndian.Uint16(resp[0:2]) != binary.BigEndian.Uint16(query[0:2]) {
		return nil, errors.New("tcp id mismatch")
	}
	return resp, nil
}

func (f *dnsForwarder) addLat(ms float64) {
	f.latMu.Lock()
	f.lat[f.latPos] = ms
	f.latPos = (f.latPos + 1) % dnsLatRing
	if f.latN < dnsLatRing {
		f.latN++
	}
	f.latMu.Unlock()
}

// Percentiles 最近 512 次客户端查询的 p50 / p95(毫秒)
func (f *dnsForwarder) Percentiles() (p50, p95 float64) {
	f.latMu.Lock()
	v := append([]float64(nil), f.lat[:f.latN]...)
	f.latMu.Unlock()
	if len(v) == 0 {
		return 0, 0
	}
	sort.Float64s(v)
	pick := func(p float64) float64 {
		i := int(p*float64(len(v)-1) + 0.5)
		return float64(int(v[i]*100+0.5)) / 100
	}
	return pick(0.50), pick(0.95)
}

func (f *dnsForwarder) Stats() dnsFwdStats {
	return dnsFwdStats{
		Queries: atomic.LoadInt64(&f.st.queries), Cached: atomic.LoadInt64(&f.st.cached),
		Blocked: atomic.LoadInt64(&f.st.blocked), Errors: atomic.LoadInt64(&f.st.errors),
		RateLimited: atomic.LoadInt64(&f.st.limited), Dropped: atomic.LoadInt64(&f.st.dropped),
		Upstream: atomic.LoadInt64(&f.st.upstream), UpstreamErrs: atomic.LoadInt64(&f.st.upErrs),
		UpstreamTCP: atomic.LoadInt64(&f.st.upTCP), ServFail: atomic.LoadInt64(&f.st.servfail),
	}
}

// dnsProbe 自检: 向 addr 发一个随机名字的 A 查询(.invalid, 不会被缓存命中),
// 收到 ID 一致的任何应答(含 NXDOMAIN)即视为通。返回往返时间与 rcode。
func dnsProbe(addr string, timeout time.Duration) (time.Duration, int, error) {
	var rb [6]byte
	_, _ = rand.Read(rb[:])
	id := binary.BigEndian.Uint16(rb[:2])
	name := "hnc-health-" + hex.EncodeToString(rb[2:]) + ".invalid"
	query := dnsBuildQuery(id, name, dnsTypeA, 0, false)
	q, _ := dnsParseQuery(query)
	t0 := time.Now()
	resp, err := dnsExchangeUDP(addr, query, q, timeout)
	if err != nil {
		return 0, -1, err
	}
	return time.Since(t0), int(binary.BigEndian.Uint16(resp[2:4]) & 0xF), nil
}

// ─── 缓存 ───────────────────────────────────────────────────────────────

type dnsCacheEnt struct {
	key     string
	msg     []byte
	ttlOffs []int
	ttls    []uint32
	stored  time.Time
	expire  time.Time
	info    dnsMsgInfo
}

type dnsCache struct {
	mu       sync.Mutex
	ll       *list.List
	m        map[string]*list.Element
	bytes    int
	maxN     int
	maxBytes int
}

func newDNSCache(maxN, maxBytes int) *dnsCache {
	return &dnsCache{ll: list.New(), m: map[string]*list.Element{}, maxN: maxN, maxBytes: maxBytes}
}

func dnsCacheKey(q dnsQuery) string {
	k := q.QName + "|" + strconv.Itoa(int(q.QType)) + "|" + strconv.Itoa(int(q.QClass))
	if q.HasOPT {
		k += "|e"
	}
	if q.DO {
		k += "|do"
	}
	if q.Flags&dnsFlagCD != 0 {
		k += "|cd"
	}
	return k
}

// dnsCacheTTL 应答可缓存秒数(0 = 不缓存)
func dnsCacheTTL(m dnsMsgInfo) uint32 {
	switch m.Rcode {
	case dnsRcodeNoError:
		if m.ANCount > 0 {
			if !m.HaveTTL || m.MinTTL == 0 {
				return 0
			}
			if m.MinTTL > dnsCacheMaxTTL {
				return dnsCacheMaxTTL
			}
			return m.MinTTL
		}
		fallthrough // NODATA: 按 SOA 否定缓存
	case dnsRcodeNXDomain:
		if !m.HaveSOA || m.NegTTL == 0 {
			return 0
		}
		if m.NegTTL > dnsCacheMaxNegTTL {
			return dnsCacheMaxNegTTL
		}
		return m.NegTTL
	}
	return 0
}

func (c *dnsCache) put(key string, msg []byte, m dnsMsgInfo, now time.Time) {
	ttl := dnsCacheTTL(m)
	if ttl == 0 || len(msg) > 8192 {
		return
	}
	e := &dnsCacheEnt{key: key, msg: append([]byte(nil), msg...), ttlOffs: m.TTLOffsets,
		stored: now, expire: now.Add(time.Duration(ttl) * time.Second), info: m}
	for _, off := range m.TTLOffsets {
		t := binary.BigEndian.Uint32(msg[off : off+4])
		if t > 0x7FFFFFFF {
			t = 0
		}
		e.ttls = append(e.ttls, t)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		c.bytes -= len(el.Value.(*dnsCacheEnt).msg)
		c.ll.Remove(el)
		delete(c.m, key)
	}
	c.m[key] = c.ll.PushFront(e)
	c.bytes += len(e.msg)
	for (c.ll.Len() > c.maxN || c.bytes > c.maxBytes) && c.ll.Len() > 0 {
		b := c.ll.Back()
		be := b.Value.(*dnsCacheEnt)
		c.bytes -= len(be.msg)
		c.ll.Remove(b)
		delete(c.m, be.key)
	}
}

// get 命中返回改写过 ID / 问题段 / TTL 的应答副本
func (c *dnsCache) get(key string, query []byte, q dnsQuery, now time.Time) ([]byte, dnsMsgInfo) {
	c.mu.Lock()
	el, ok := c.m[key]
	if !ok {
		c.mu.Unlock()
		return nil, dnsMsgInfo{}
	}
	e := el.Value.(*dnsCacheEnt)
	if !now.Before(e.expire) {
		c.bytes -= len(e.msg)
		c.ll.Remove(el)
		delete(c.m, key)
		c.mu.Unlock()
		return nil, dnsMsgInfo{}
	}
	c.ll.MoveToFront(el)
	out := append([]byte(nil), e.msg...)
	offs, ttls, stored, info := e.ttlOffs, e.ttls, e.stored, e.info
	c.mu.Unlock()

	binary.BigEndian.PutUint16(out[0:2], q.ID)
	// RD / CD 跟随本次查询
	fl := binary.BigEndian.Uint16(out[2:4])&^(dnsFlagRD|dnsFlagCD) | q.Flags&(dnsFlagRD|dnsFlagCD)
	binary.BigEndian.PutUint16(out[2:4], fl)
	if q.QEnd == info.Q.QEnd && q.QEnd <= len(out) && q.QEnd <= len(query) {
		copy(out[12:q.QEnd], query[12:q.QEnd]) // 保留客户端问题段大小写(0x20)
	}
	el2 := uint32(now.Sub(stored) / time.Second)
	for i, off := range offs {
		t := ttls[i]
		if t > el2 {
			t -= el2
		} else {
			t = 0
		}
		binary.BigEndian.PutUint32(out[off:off+4], t)
	}
	return out, info
}

func (c *dnsCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

func (c *dnsCache) Flush() {
	c.mu.Lock()
	c.ll.Init()
	c.m = map[string]*list.Element{}
	c.bytes = 0
	c.mu.Unlock()
}

// ─── 按客户端限速(令牌桶)──────────────────────────────────────────────

type dnsBucket struct {
	tokens float64
	last   time.Time
}

type dnsRateLimiter struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	max   int
	m     map[string]*dnsBucket
}

func newDNSRateLimiter(rate, burst float64, max int) *dnsRateLimiter {
	return &dnsRateLimiter{rate: rate, burst: burst, max: max, m: map[string]*dnsBucket{}}
}

func (l *dnsRateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.m[key]
	if !ok {
		if len(l.m) >= l.max {
			for k, v := range l.m { // 回收闲置 60 秒以上的
				if now.Sub(v.last) > time.Minute {
					delete(l.m, k)
				}
			}
			if len(l.m) >= l.max {
				return true // 表满: 不跟踪(宁可放行也不误伤)
			}
		}
		b = &dnsBucket{tokens: l.burst, last: now}
		l.m[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
