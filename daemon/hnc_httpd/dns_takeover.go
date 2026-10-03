// dns_takeover.go — DPI v2 · 「HNC DNS 接管」(可选, 默认关闭)
//
// 配置 data/dns_takeover.json:
//   {"enabled":false,"block_mode":"nxdomain"|"zero","log_queries":false,"log_redact":false,
//    "upstream":"" (空 = 自动), "ts":N}
//
// 打开后(热点在线时):
//   1. httpd 内的转发器(dns_forwarder.go)监听 <热点口 IPv4>:15353(UDP+TCP),
//      以及热点口的每个全局 IPv6 地址:15353;
//   2. bin/dns_takeover.sh apply 在 nat/PREROUTING 挂 HNC_DNSTK:
//      -i <热点口> -d <热点口自身地址> --dport 53 → DNAT 到转发器(只接管「发给网关」的
//      DNS, 设备写死的 8.8.8.8 等不改, 仍由 dpid 被动嗅探); filter/INPUT 挂
//      HNC_DNSTK_IN 放行 15353。IPv6 仅在 ip6tables nat 可用时接管, 否则不动(状态里报告)。
//   3. 上游选择(按序探测, 任何非 REFUSED 应答即可用):
//        custom  —— 配置里写死的 upstream
//        tether  —— 热点口各 IPv4 地址的 :53(= 热点设备原本在问的那个系统解析器:
//                   dnsmasq / netd DNS 代理), 答案与接管前完全一致, 首选
//        system  —— getprop net.dns1..4 / dumpsys connectivity 里默认网络的 DNS
//                   (仅当网关 :53 不回本机查询时兜底; 状态里 upstream_kind 标明)
//      防环: 转发器发往上游的包是本机发出的, 只走 OUTPUT, 不经过 PREROUTING; DNAT
//      规则又只匹配 -i <热点口> 的入包 —— 本机自身流量永远不会被 DNAT。
//   4. 每 10 秒健康检查: 自检查询(经转发器 → 上游)无应答(重试一次)、上游错误率
//      ≥50%(窗口内 ≥20 次)、或 DNAT 计数在涨而转发器一条客户端查询都没收到 →
//      立即删除 DNAT 规则(fail-open, 设备回到系统 DNS), 发 dns_takeover_failopen 告警,
//      退避 1 分钟起翻倍(上限 30 分钟)后再试。规则被别人清掉会自动补回。
//      httpd 收到 SIGTERM 时同步删规则; httpd 被杀 / 崩溃时 watchdog 发现 pid 死掉
//      即调 dns_takeover.sh remove; cleanup.sh 也会删。
//
// 带来的能力:
//   · 精确的逐设备查询日志(时间/MAC/IP/域名/类型/应答/rcode/耗时), 内存环 2000 条 +
//     logs/dns/queries-YYYYMMDD.jsonl(保留 3 天, 单日 32MB 封顶), log_redact 时只记
//     主域名、不记应答;
//   · 解析结果直接写进 IP→域名表(loadIPNames 合并, src = "dns", 解析器给出的答案
//     即权威; 未过期的 sni/http 连接名仍优先);
//   · 解析器层按设备封锁: conn_blocks(含应用时长 / 类别封锁派生项)的域名封锁项、
//     加密 DNS strict 档的 DoH 解析器主机名 —— DNAT 后 iptables 的 xt_string DNS 层
//     (目标端口 53)不再匹配, 由这里接管, 回 NXDOMAIN 或 0.0.0.0/::。
//
// 动作 dns_takeover_set {enabled?, block_mode?, log_queries?, log_redact?, upstream?}
//   至少带一个; 写配置后立即同步一次, detail 为当前状态摘要。
//
// GET /api/dns →
//   {ok, enabled, active, healthy, state, iface, listen:[..], port, upstream, upstream_kind,
//    v6:{status, reason}, block_mode, log_queries, log_redact,
//    stats:{queries, cached, blocked, errors, ratelimited, dropped, upstream, upstream_errs,
//           upstream_tcp, servfail, p50_ms, p95_ms, cache_entries},
//    top_domains_today:[{name,count}], recent:[...](仅 log_queries 时), blocklist:{devices, global},
//    failopen:{count, last_ts, reason, retry_at}, last_error, last_check, selftest_ms, ip_names}
// GET /api/dns/log?mac=&limit= → {ok, log_queries, entries:[...] (新→旧)}

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hnc.io/dpid/alert"
)

const (
	dnsTKTick          = 10 * time.Second
	dnsTKProbeTimeout  = 1500 * time.Millisecond
	dnsTKBackoffMin    = time.Minute
	dnsTKBackoffMax    = 30 * time.Minute
	dnsTKRingSize      = 2000
	dnsTKRecentN       = 50
	dnsTKTopMax        = 5000
	dnsTKTopN          = 20
	dnsTKLogRetainDays = 3
	dnsTKLogMaxBytes   = 32 << 20
	dnsTKNamesMax      = 4096
	dnsTKNameMinKeep   = 600
	dnsTKNameMaxKeep   = 6 * 3600
	dnsTKAlertKind     = "dns_takeover_failopen"
)

type dnsTKConf struct {
	Enabled    bool   `json:"enabled"`
	BlockMode  string `json:"block_mode"`
	LogQueries bool   `json:"log_queries"`
	LogRedact  bool   `json:"log_redact"`
	Upstream   string `json:"upstream,omitempty"`
	Ts         int64  `json:"ts,omitempty"`
}

func dnsTKPath(hncDir string) string { return filepath.Join(hncDir, "data", "dns_takeover.json") }

func loadDNSTKConf(hncDir string) dnsTKConf {
	c := dnsTKConf{BlockMode: "nxdomain"}
	b, err := os.ReadFile(dnsTKPath(hncDir))
	if err != nil {
		return c
	}
	var x dnsTKConf
	if json.Unmarshal(b, &x) != nil {
		return c
	}
	c.Enabled, c.LogQueries, c.LogRedact, c.Ts = x.Enabled, x.LogQueries, x.LogRedact, x.Ts
	if x.BlockMode == "zero" {
		c.BlockMode = "zero"
	}
	if validDNSUpstream(x.Upstream) {
		c.Upstream = x.Upstream
	}
	return c
}

// validDNSUpstream "ip" 或 "ip:port" / "[v6]:port"
func validDNSUpstream(s string) bool {
	return dnsNormUpstream(s) != ""
}

func dnsNormUpstream(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return ""
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return ""
		}
		return net.JoinHostPort(ip.String(), "53")
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(h)
	n, err := strconv.Atoi(p)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || err != nil || n < 1 || n > 65535 {
		return ""
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(n))
}

// ─── 健康判定(纯函数, 单测)────────────────────────────────────────────

type dnsHealthIn struct {
	SelfOK  bool
	DUp     int64 // 窗口内发往上游的查询
	DUpErr  int64 // 窗口内上游错误
	DPkts   int64 // 窗口内 DNAT 规则命中包数(-1 = 读不到)
	DClient int64 // 窗口内转发器收到的客户端查询
}

func dnsHealthEval(in dnsHealthIn) (bool, string) {
	if !in.SelfOK {
		return false, "selftest"
	}
	if in.DUp >= 20 && in.DUpErr*2 >= in.DUp {
		return false, "upstream_errors"
	}
	if in.DPkts >= 10 && in.DClient == 0 {
		return false, "dnat_path"
	}
	return true, ""
}

func dnsTKReasonText(r string) string {
	switch r {
	case "selftest":
		return "转发器自检查询无应答"
	case "upstream_errors":
		return "上游解析器错误率过高"
	case "dnat_path":
		return "DNAT 规则在命中但转发器收不到查询(防火墙 / 内核路径异常)"
	case "no_upstream":
		return "找不到可用的上游解析器"
	}
	return r
}

// ─── 封锁表 ─────────────────────────────────────────────────────────────

type dnsBlockSet struct {
	perMAC map[string]map[string]bool // mac → 域名集合
	global map[string]bool            // 全部设备(除 exempt)
	exempt map[string]bool            // 不受 global 影响的 MAC
}

func (b *dnsBlockSet) match(mac, qname string) bool {
	if b == nil {
		return false
	}
	set := b.perMAC[mac]
	useGlobal := len(b.global) > 0 && !b.exempt[mac]
	if set == nil && !useGlobal {
		return false
	}
	n := strings.TrimSuffix(strings.ToLower(qname), ".")
	for n != "" {
		if set[n] || (useGlobal && b.global[n]) {
			return true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			break
		}
		n = n[i+1:]
	}
	return false
}

func (b *dnsBlockSet) counts() (int, int) {
	if b == nil {
		return 0, 0
	}
	n := 0
	for _, s := range b.perMAC {
		n += len(s)
	}
	return n, len(b.global)
}

// dnsResolverHosts 加密 DNS 解析器主机名名单(与 encdns_sync.sh 同一份文件与查找顺序)
func dnsResolverHosts(hncDir string) []string {
	cands := []string{filepath.Join(hncDir, "etc", "encdns_resolvers.txt")}
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "service.path")); err == nil {
		if p := strings.TrimSpace(string(b)); p != "" {
			cands = append(cands, filepath.Join(p, "data", "encdns_resolvers.txt"))
		}
	}
	cands = append(cands, filepath.Join(hncDir, "data", "encdns_resolvers.txt"))
	for _, f := range cands {
		b, err := os.ReadFile(f)
		if err != nil || len(b) == 0 {
			continue
		}
		var out []string
		for _, ln := range strings.Split(string(b), "\n") {
			if i := strings.IndexByte(ln, '#'); i >= 0 {
				ln = ln[:i]
			}
			fs := strings.Fields(ln)
			if len(fs) == 0 {
				continue
			}
			h := strings.ToLower(fs[0])
			if net.ParseIP(h) != nil || strings.Contains(h, "/") || !domainRe.MatchString(h) {
				continue
			}
			out = append(out, h)
		}
		return out
	}
	return []string{"dns.google", "cloudflare-dns.com", "dns.alidns.com", "doh.pub", "dns.quad9.net"}
}

// buildDNSBlockSet conn_blocks(含派生项)域名 + 加密 DNS strict 的 DoH 主机名
func buildDNSBlockSet(connDNS []string, enc encdnsConf, resolverHosts []string) *dnsBlockSet {
	b := &dnsBlockSet{perMAC: map[string]map[string]bool{}, global: map[string]bool{}, exempt: map[string]bool{}}
	add := func(mac, d string) {
		if dpiCtlSkipMAC(mac) {
			return
		}
		s := b.perMAC[mac]
		if s == nil {
			s = map[string]bool{}
			b.perMAC[mac] = s
		}
		s[d] = true
	}
	for _, ln := range connDNS {
		f := strings.Fields(ln)
		if len(f) == 2 && validMAC(f[0]) {
			add(f[0], f[1])
		}
	}
	if enc.Policy == "strict" {
		for _, h := range resolverHosts {
			b.global[h] = true
		}
	}
	for mac, p := range enc.Devices {
		switch p {
		case "strict":
			b.exempt[mac] = true
			for _, h := range resolverHosts {
				add(mac, h)
			}
		default: // off / dot: 按设备覆盖 = 不受全局 strict 影响
			b.exempt[mac] = true
		}
	}
	return b
}

// ─── IP → 域名(解析器权威答案)──────────────────────────────────────────

type dnsIPName struct {
	name, cname, mac string
	ts, expire       int64
}

type dnsIPNames struct {
	mu sync.Mutex
	m  map[string]*dnsIPName
}

func newDNSIPNames() *dnsIPNames { return &dnsIPNames{m: map[string]*dnsIPName{}} }

func (t *dnsIPNames) record(ev dnsAnswerEvent) {
	now := ev.Ts.Unix()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, r := range ev.IPs {
		ip := net.ParseIP(r.Value)
		if ip == nil {
			continue
		}
		keep := int64(r.TTL)
		if keep < dnsTKNameMinKeep {
			keep = dnsTKNameMinKeep
		}
		if keep > dnsTKNameMaxKeep {
			keep = dnsTKNameMaxKeep
		}
		k := ip.String()
		if e, ok := t.m[k]; ok {
			e.name, e.cname, e.mac, e.ts = ev.QName, ev.CNAME, ev.MAC, now
			if now+keep > e.expire {
				e.expire = now + keep
			}
			continue
		}
		if len(t.m) >= dnsTKNamesMax {
			t.evictLocked(now)
		}
		t.m[k] = &dnsIPName{name: ev.QName, cname: ev.CNAME, mac: ev.MAC, ts: now, expire: now + keep}
	}
}

// evictLocked 先删过期, 仍满则删最旧的 1/8
func (t *dnsIPNames) evictLocked(now int64) {
	for k, e := range t.m {
		if e.expire <= now {
			delete(t.m, k)
		}
	}
	if len(t.m) < dnsTKNamesMax {
		return
	}
	type kv struct {
		k  string
		ts int64
	}
	all := make([]kv, 0, len(t.m))
	for k, e := range t.m {
		all = append(all, kv{k, e.ts})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ts < all[j].ts })
	for _, x := range all[:len(all)/8+1] {
		delete(t.m, x.k)
	}
}

func (t *dnsIPNames) snapshot(now int64) map[string]dnsIPName {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]dnsIPName, len(t.m))
	for k, e := range t.m {
		if e.expire > now {
			out[k] = *e
		}
	}
	return out
}

func (t *dnsIPNames) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// mergeIPNames 把解析器答案并进 loadIPNames 的结果: 未过期的连接名(sni/http)优先;
// 同名时保留 dpid 的应用归类; 名字不同(dpid 嗅探的是旧答案)以解析器为准。
func dnsMergeIPNames(out map[string]ipName, snap map[string]dnsIPName) {
	for ip, e := range snap {
		cur, ok := out[ip]
		if ok && (cur.Src == "sni" || cur.Src == "http") {
			continue
		}
		if ok && strings.EqualFold(cur.Name, e.name) {
			cur.Src = "dns"
			out[ip] = cur
			continue
		}
		out[ip] = ipName{Name: e.name, Src: "dns"}
	}
}

// ─── 查询日志: 内存环 + 今日热门 + 按日文件 ──────────────────────────────

type dnsLogRing struct {
	mu  sync.Mutex
	buf []dnsLogEntry
	pos int
	n   int
}

func newDNSLogRing(n int) *dnsLogRing { return &dnsLogRing{buf: make([]dnsLogEntry, n)} }

func (r *dnsLogRing) add(e dnsLogEntry) {
	r.mu.Lock()
	r.buf[r.pos] = e
	r.pos = (r.pos + 1) % len(r.buf)
	if r.n < len(r.buf) {
		r.n++
	}
	r.mu.Unlock()
}

func (r *dnsLogRing) clear() {
	r.mu.Lock()
	r.pos, r.n = 0, 0
	for i := range r.buf {
		r.buf[i] = dnsLogEntry{}
	}
	r.mu.Unlock()
}

// latest 新→旧, mac 非空时只要该设备
func (r *dnsLogRing) latest(mac string, limit int) []dnsLogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []dnsLogEntry{}
	for i := 0; i < r.n && len(out) < limit; i++ {
		e := r.buf[(r.pos-1-i+len(r.buf))%len(r.buf)]
		if mac == "" || e.MAC == mac {
			out = append(out, e)
		}
	}
	return out
}

type dnsTopDomains struct {
	mu  sync.Mutex
	day string
	m   map[string]int64
}

func (t *dnsTopDomains) add(day, name string) {
	if name == "" {
		return
	}
	t.mu.Lock()
	if t.day != day || t.m == nil {
		t.day, t.m = day, map[string]int64{}
	}
	if _, ok := t.m[name]; ok || len(t.m) < dnsTKTopMax {
		t.m[name]++
	}
	t.mu.Unlock()
}

func (t *dnsTopDomains) top(day string, n int) []map[string]interface{} {
	t.mu.Lock()
	type kv struct {
		k string
		v int64
	}
	var all []kv
	if t.day == day {
		for k, v := range t.m {
			all = append(all, kv{k, v})
		}
	}
	t.mu.Unlock()
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	out := []map[string]interface{}{}
	for i := 0; i < len(all) && i < n; i++ {
		out = append(out, map[string]interface{}{"name": all[i].k, "count": all[i].v})
	}
	return out
}

// dnsRedactName 只留主域名(最后两段; 常见二级后缀如 com.cn 留三段)
func dnsRedactName(n string) string {
	parts := strings.Split(n, ".")
	if len(parts) <= 2 {
		return n
	}
	k := 2
	switch parts[len(parts)-2] {
	case "com", "net", "org", "gov", "edu", "co", "ac":
		if len(parts[len(parts)-1]) == 2 {
			k = 3
		}
	}
	if k > len(parts) {
		k = len(parts)
	}
	return strings.Join(parts[len(parts)-k:], ".")
}

// dnsLogWriter 按日文件 logs/dns/queries-YYYYMMDD.jsonl, 后台 goroutine 写, 满了丢
type dnsLogWriter struct {
	dir  string
	ch   chan dnsLogEntry
	stop chan struct{}
	done chan struct{}
}

func newDNSLogWriter(dir string) *dnsLogWriter {
	w := &dnsLogWriter{dir: dir, ch: make(chan dnsLogEntry, 4096), stop: make(chan struct{}), done: make(chan struct{})}
	go w.loop()
	return w
}

func (w *dnsLogWriter) push(e dnsLogEntry) {
	select {
	case w.ch <- e:
	default:
	}
}

func (w *dnsLogWriter) close() {
	close(w.stop)
	select {
	case <-w.done:
	case <-time.After(3 * time.Second):
	}
}

func dnsLogFileName(t time.Time) string { return "queries-" + t.Format("20060102") + ".jsonl" }

// dnsLogPrune 删 retainDays 天之前的日志文件(按文件名日期)
func dnsLogPrune(dir string, now time.Time, retainDays int) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cut := now.AddDate(0, 0, -(retainDays - 1)).Format("20060102")
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, "queries-") || !strings.HasSuffix(n, ".jsonl") {
			continue
		}
		d := strings.TrimSuffix(strings.TrimPrefix(n, "queries-"), ".jsonl")
		if len(d) == 8 && d < cut {
			_ = os.Remove(filepath.Join(dir, n))
		}
	}
}

func (w *dnsLogWriter) loop() {
	defer close(w.done)
	var f *os.File
	var bw *bufio.Writer
	var day string
	var size int64
	tk := time.NewTicker(2 * time.Second)
	defer tk.Stop()
	closeF := func() {
		if bw != nil {
			_ = bw.Flush()
		}
		if f != nil {
			_ = f.Close()
		}
		f, bw = nil, nil
	}
	defer closeF()
	for {
		select {
		case <-w.stop:
			for {
				select {
				case e := <-w.ch:
					w.write(&f, &bw, &day, &size, e)
				default:
					return
				}
			}
		case <-tk.C:
			if bw != nil {
				_ = bw.Flush()
			}
		case e := <-w.ch:
			w.write(&f, &bw, &day, &size, e)
		}
	}
}

func (w *dnsLogWriter) write(f **os.File, bw **bufio.Writer, day *string, size *int64, e dnsLogEntry) {
	t := time.UnixMilli(e.Ts)
	d := t.Format("20060102")
	if *day != d || *f == nil {
		if *bw != nil {
			_ = (*bw).Flush()
		}
		if *f != nil {
			_ = (*f).Close()
		}
		*f, *bw = nil, nil
		*day = d
		_ = os.MkdirAll(w.dir, 0o755)
		dnsLogPrune(w.dir, t, dnsTKLogRetainDays)
		nf, err := os.OpenFile(filepath.Join(w.dir, dnsLogFileName(t)), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		st, _ := nf.Stat()
		*size = 0
		if st != nil {
			*size = st.Size()
		}
		*f, *bw = nf, bufio.NewWriterSize(nf, 32<<10)
	}
	if *size >= dnsTKLogMaxBytes {
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	n, _ := (*bw).Write(b)
	*size += int64(n)
}

// ─── 控制器 ─────────────────────────────────────────────────────────────

type dnsTakeover struct {
	s      *server
	hncDir string

	tickMu sync.Mutex // 串行化 tick / 动作 / 停机
	mu     sync.Mutex // 保护下面的状态字段(API 读)

	fwd          *dnsForwarder
	listen       []string // 监听 IP
	port         int
	iface        string
	dst4, dst6   []string
	ruleSig      string
	upstream     string
	upstreamKind string
	upCheckedAt  time.Time
	active       bool
	healthy      bool
	state        string
	lastErr      string
	v6Status     string
	v6Reason     string
	foCount      int
	foLast       int64
	foReason     string
	retryAt      time.Time
	backoff      time.Duration
	healthySince time.Time
	lastCheck    int64
	selftestMS   float64
	prevStats    dnsFwdStats
	prevPkts     int64
	havePrev     bool
	cfg          dnsTKConf
	booted       bool

	blkMu sync.RWMutex
	blk   *dnsBlockSet

	names *dnsIPNames
	ring  *dnsLogRing
	top   *dnsTopDomains
	logw  *dnsLogWriter

	arpMu sync.Mutex
	arp   map[string]string
	arpAt time.Time

	// 可替换(测试)
	runScript    func(args ...string) (int, string)
	probe        func(addr string, timeout time.Duration) (time.Duration, int, error)
	ifaceAddrs   func(iface string) (v4, v6 []string)
	hotspotIface func() string
	systemDNS    func() []string
	blockSources func(now time.Time) *dnsBlockSet
	emitAlert    func(a alert.Alert)
	now          func() time.Time
}

var dnsTKReg = struct {
	sync.Mutex
	m map[*server]*dnsTakeover
}{m: map[*server]*dnsTakeover{}}

// dnsTK 每个 server 一个控制器(不改 server 结构体)
func (s *server) dnsTK() *dnsTakeover {
	dnsTKReg.Lock()
	defer dnsTKReg.Unlock()
	if t, ok := dnsTKReg.m[s]; ok {
		return t
	}
	t := newDNSTakeover(s)
	dnsTKReg.m[s] = t
	return t
}

func newDNSTakeover(s *server) *dnsTakeover {
	t := &dnsTakeover{s: s, hncDir: s.hncDir, port: dnsFwdDefaultPort, state: "off",
		names: newDNSIPNames(), ring: newDNSLogRing(dnsTKRingSize), top: &dnsTopDomains{},
		backoff: dnsTKBackoffMin, now: time.Now, v6Status: "untouched"}
	t.runScript = func(args ...string) (int, string) { return runBin(s.hncDir, "dns_takeover.sh", args...) }
	t.probe = dnsProbe
	t.ifaceAddrs = dnsIfaceAddrs
	t.hotspotIface = func() string { return readHotspotIfaceName(s.hncDir) }
	t.systemDNS = dnsSystemServers
	t.blockSources = func(now time.Time) *dnsBlockSet {
		return buildDNSBlockSet(expandConnBlockDomains(s.connBlocksEffective(now)), loadEncdns(s.hncDir), dnsResolverHosts(s.hncDir))
	}
	t.emitAlert = func(a alert.Alert) {
		cfg := alert.NewConfig(s.hncDir)
		if err := alert.Append(cfg.AlertsJSONLPath, a); err != nil {
			log.Printf("dns_takeover: append alert failed: %v", err)
		}
	}
	return t
}

// dnsIfaceAddrs 热点口的 IPv4(非链路本地) / IPv6(全局单播, 含 ULA)地址
func dnsIfaceAddrs(iface string) (v4, v6 []string) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, nil
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, nil
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipn.IP
		if ip4 := ip.To4(); ip4 != nil {
			if !ip4.IsLinkLocalUnicast() && !ip4.IsLoopback() {
				v4 = append(v4, ip4.String())
			}
		} else if ip.IsGlobalUnicast() {
			v6 = append(v6, ip.String())
		}
	}
	return v4, v6
}

var dumpsysDNSRe = regexp.MustCompile(`DnsAddresses: \[([^\]]*)\]`)

// parseDumpsysDNS 从 dumpsys connectivity 输出取 DNS 地址(按出现顺序去重)
func parseDumpsysDNS(out string) []string {
	var res []string
	seen := map[string]bool{}
	for _, m := range dumpsysDNSRe.FindAllStringSubmatch(out, -1) {
		for _, f := range strings.Split(m[1], ",") {
			f = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(f), "/"))
			if ip := net.ParseIP(f); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				s := ip.String()
				if !seen[s] {
					seen[s] = true
					res = append(res, s)
				}
			}
		}
	}
	return res
}

// dnsSystemServers 默认网络的 DNS: getprop net.dns1..4(老系统), 再 dumpsys connectivity
func dnsSystemServers() []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !seen[ip.String()] {
			seen[ip.String()] = true
			out = append(out, ip.String())
		}
	}
	run := func(name string, args ...string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		b, _ := hardenCmd(exec.CommandContext(ctx, name, args...)).Output()
		return string(b)
	}
	for i := 1; i <= 4; i++ {
		add(run("getprop", "net.dns"+strconv.Itoa(i)))
	}
	if len(out) == 0 {
		for _, s := range parseDumpsysDNS(run("dumpsys", "connectivity")) {
			add(s)
			if len(out) >= 4 {
				break
			}
		}
	}
	return out
}

func (t *dnsTakeover) macOf(ip net.IP) string {
	if ip == nil {
		return ""
	}
	var mac string
	if ip4 := ip.To4(); ip4 != nil {
		t.arpMu.Lock()
		if t.arp == nil || time.Since(t.arpAt) > 5*time.Second {
			m := map[string]string{}
			if f, err := os.Open(neighArpPath); err == nil {
				parseArpTable(bufio.NewScanner(f), m)
				f.Close()
			}
			t.arp, t.arpAt = m, time.Now()
		}
		mac = t.arp[ip4.String()]
		t.arpMu.Unlock()
	} else {
		mac = neighborMAC(ip)
	}
	if isSimMAC(mac) {
		return ""
	}
	return mac
}

func (t *dnsTakeover) blocked(mac, qname string) bool {
	t.blkMu.RLock()
	b := t.blk
	t.blkMu.RUnlock()
	return b.match(mac, qname)
}

func (t *dnsTakeover) onLog(e dnsLogEntry) {
	t.mu.Lock()
	cfg := t.cfg
	w := t.logw
	t.mu.Unlock()
	if cfg.LogRedact {
		e.QName = dnsRedactName(e.QName)
		e.Answers = nil
	}
	t.top.add(time.UnixMilli(e.Ts).Format("20060102"), e.QName)
	if !cfg.LogQueries {
		return
	}
	t.ring.add(e)
	if w != nil {
		w.push(e)
	}
}

// mergeInto loadIPNames 调用: 接管在跑(或刚停, 条目未过期)时合并解析器答案
func (t *dnsTakeover) mergeInto(out map[string]ipName) {
	if t == nil || t.names.size() == 0 {
		return
	}
	dnsMergeIPNames(out, t.names.snapshot(t.now().Unix()))
}

// dnsTKMergeIPNames loadIPNames 的钩子(没建过控制器时零开销)
func dnsTKMergeIPNames(s *server, out map[string]ipName) {
	dnsTKReg.Lock()
	t := dnsTKReg.m[s]
	dnsTKReg.Unlock()
	t.mergeInto(out)
}

func (t *dnsTakeover) setState(st, errStr string) {
	t.mu.Lock()
	t.state, t.lastErr = st, errStr
	if st != "active" {
		t.healthy = false
	}
	t.mu.Unlock()
}

// removeRulesLocked 删 DNAT(幂等)。tickMu 已持有。
func (t *dnsTakeover) removeRulesLocked() {
	rc, out := t.runScript("remove")
	if rc != 0 {
		log.Printf("dns_takeover: remove rc=%d %s", rc, lastLine(strings.TrimSpace(out)))
	}
	t.mu.Lock()
	t.active, t.ruleSig, t.havePrev = false, "", false
	t.mu.Unlock()
}

// stopLocked 删规则 + 关转发器
func (t *dnsTakeover) stopLocked(state, errStr string) {
	t.mu.Lock()
	wasActive, fwd := t.active, t.fwd
	t.fwd, t.listen = nil, nil
	t.mu.Unlock()
	if wasActive {
		t.removeRulesLocked()
	}
	if fwd != nil {
		fwd.Close()
	}
	t.setState(state, errStr)
}

func (t *dnsTakeover) setLogging(cfg dnsTKConf) {
	t.mu.Lock()
	prev := t.cfg
	t.cfg = cfg
	var closeW *dnsLogWriter
	if cfg.LogQueries && cfg.Enabled && t.logw == nil {
		t.logw = newDNSLogWriter(filepath.Join(t.hncDir, "logs", "dns"))
	} else if (!cfg.LogQueries || !cfg.Enabled) && t.logw != nil {
		closeW, t.logw = t.logw, nil
	}
	t.mu.Unlock()
	if closeW != nil {
		closeW.close()
	}
	if prev.LogQueries && !cfg.LogQueries {
		t.ring.clear() // 关日志 = 内存里的明细也清掉
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// chooseUpstream custom > tether(各 v4 地址 :53)> system。返回 ("", "") = 都不通
func (t *dnsTakeover) chooseUpstream(cfg dnsTKConf, v4 []string) (string, string) {
	ok := func(addr string) bool {
		_, rc, err := t.probe(addr, dnsTKProbeTimeout)
		return err == nil && rc != dnsRcodeRefused
	}
	if cfg.Upstream != "" {
		if up := dnsNormUpstream(cfg.Upstream); up != "" && ok(up) {
			return up, "custom"
		}
		return "", ""
	}
	for _, a := range v4 {
		up := net.JoinHostPort(a, "53")
		if ok(up) {
			return up, "tether"
		}
	}
	local := map[string]bool{}
	for _, a := range v4 {
		local[a] = true
	}
	for _, s := range t.systemDNS() {
		if local[s] {
			continue
		}
		up := net.JoinHostPort(s, "53")
		if ok(up) {
			return up, "system"
		}
	}
	return "", ""
}

func (t *dnsTakeover) refreshBlocklist(now time.Time) {
	b := t.blockSources(now)
	t.blkMu.Lock()
	t.blk = b
	t.blkMu.Unlock()
}

// parseDNSTKCounters 解析 dns_takeover.sh counters 的 JSON
func parseDNSTKCounters(out string) (present bool, pkts int64, ok bool) {
	var c struct {
		Present bool  `json:"present"`
		Pkts    int64 `json:"pkts"`
		PktsV6  int64 `json:"pkts_v6"`
	}
	if json.Unmarshal([]byte(lastLine(strings.TrimSpace(out))), &c) != nil {
		return false, -1, false
	}
	return c.Present, c.Pkts + c.PktsV6, true
}

// tick 一次对账 + 健康检查
func (t *dnsTakeover) tick() {
	t.tickMu.Lock()
	defer t.tickMu.Unlock()
	t.tickLocked()
}

func (t *dnsTakeover) tickLocked() {
	now := t.now()
	cfg := loadDNSTKConf(t.hncDir)
	t.setLogging(cfg)
	t.mu.Lock()
	first := !t.booted
	t.booted = true
	t.lastCheck = now.Unix()
	t.mu.Unlock()

	if !cfg.Enabled {
		if first {
			t.removeRulesLocked() // 上一个 httpd 崩掉留下的规则
		}
		t.stopLocked("off", "")
		return
	}
	iface := t.hotspotIface()
	var v4, v6 []string
	if iface != "" {
		v4, v6 = t.ifaceAddrs(iface)
	}
	if iface == "" || len(v4) == 0 {
		if first {
			t.removeRulesLocked()
		}
		t.stopLocked("waiting_hotspot", "")
		return
	}
	listen := append([]string{v4[0]}, v6...)

	// 1. 转发器: 监听地址变了就重开
	t.mu.Lock()
	fwd := t.fwd
	needRestart := fwd == nil || !sameStrings(t.listen, listen)
	t.mu.Unlock()
	if needRestart {
		if fwd != nil {
			fwd.Close()
		}
		t.mu.Lock()
		t.fwd, t.listen = nil, nil
		t.upstream, t.upstreamKind = "", ""
		t.mu.Unlock()
		nf, got, err := t.openForwarder(listen)
		if err != nil {
			t.failOpenLocked("listen: "+err.Error(), false)
			return
		}
		nf.AddLocal(v4)
		nf.AddLocal(v6)
		t.mu.Lock()
		t.fwd, t.listen = nf, listen // listen 保持「期望值」, 地址不变就不反复重开
		t.mu.Unlock()
		fwd = nf
		if len(got) == 1 {
			v6 = nil
		}
	} else if len(fwd.ListenAddrs()) == 1 {
		v6 = nil // v6 监听没开成(DAD 中等), 只接管 v4
	}
	fwd.SetBlockMode(cfg.BlockMode)
	t.refreshBlocklist(now)

	// 2. 上游: 没选过 / 非 tether 每分钟重探(优先回到 tether)
	t.mu.Lock()
	up, kind, checked := t.upstream, t.upstreamKind, t.upCheckedAt
	t.mu.Unlock()
	wantUp := ""
	if cfg.Upstream != "" {
		wantUp = dnsNormUpstream(cfg.Upstream)
	}
	if up == "" || (wantUp != "" && up != wantUp) || (wantUp == "" && kind == "custom") ||
		(kind != "tether" && now.Sub(checked) > time.Minute) {
		nu, nk := t.chooseUpstream(cfg, v4)
		t.mu.Lock()
		t.upCheckedAt = now
		if nu != "" {
			t.upstream, t.upstreamKind = nu, nk
		}
		up = t.upstream
		t.mu.Unlock()
		if nu != "" {
			fwd.SetUpstream(nu)
		}
	}
	if up == "" {
		t.failOpenLocked("no_upstream", true)
		return
	}

	// 3. fail-open 冷却中
	t.mu.Lock()
	cooling := now.Before(t.retryAt)
	active := t.active
	t.mu.Unlock()
	if cooling && !active {
		t.setState("failopen", t.lastErrSnapshot())
		return
	}

	// 4. 自检(经转发器 → 上游), 失败重试一次
	self := net.JoinHostPort(listen[0], strconv.Itoa(t.port))
	rtt, _, perr := t.probe(self, dnsTKProbeTimeout)
	if perr != nil {
		rtt, _, perr = t.probe(self, dnsTKProbeTimeout)
	}
	t.mu.Lock()
	if perr == nil {
		t.selftestMS = float64(rtt.Microseconds()) / 1000
	}
	t.mu.Unlock()

	sig := strings.Join([]string{iface, listen[0], strings.Join(v4, ","), strings.Join(v6, ","), strconv.Itoa(t.port)}, "|")
	if !active {
		if perr != nil {
			t.setState("error", "selftest: "+perr.Error())
			return
		}
		t.applyLocked(iface, listen[0], v4, v6, sig, now)
		return
	}

	// 5. 已接管: 规则签名变了 / 规则被清 → 重下; 否则做健康判定
	t.mu.Lock()
	curSig := t.ruleSig
	t.mu.Unlock()
	if curSig != sig {
		t.applyLocked(iface, listen[0], v4, v6, sig, now)
		return
	}
	rc, out := t.runScript("counters")
	present, pkts, cok := parseDNSTKCounters(out)
	if rc == 0 && cok && !present {
		log.Printf("dns_takeover: rules missing, re-applying")
		t.applyLocked(iface, listen[0], v4, v6, sig, now)
		return
	}
	st := fwd.Stats()
	in := dnsHealthIn{SelfOK: perr == nil, DPkts: -1}
	t.mu.Lock()
	if t.havePrev {
		in.DUp = st.Upstream - t.prevStats.Upstream
		in.DUpErr = st.UpstreamErrs - t.prevStats.UpstreamErrs
		in.DClient = st.Queries - t.prevStats.Queries
		if cok && t.prevPkts >= 0 && pkts >= t.prevPkts {
			in.DPkts = pkts - t.prevPkts
		}
	}
	t.prevStats, t.havePrev = st, true
	if cok {
		t.prevPkts = pkts
	} else {
		t.prevPkts = -1
	}
	t.mu.Unlock()
	if ok, reason := dnsHealthEval(in); !ok {
		t.failOpenLocked(reason, true)
		return
	}
	t.mu.Lock()
	t.healthy, t.state, t.lastErr = true, "active", ""
	if !t.healthySince.IsZero() && now.Sub(t.healthySince) > 10*time.Minute {
		t.backoff = dnsTKBackoffMin
	}
	t.mu.Unlock()
}

// openForwarder 开转发器; v6 地址绑不上(还在 DAD 等)时退回只监听 v4。
// 返回实际监听的 IP 列表。
func (t *dnsTakeover) openForwarder(listen []string) (*dnsForwarder, []string, error) {
	mk := func() *dnsForwarder {
		nf := newDNSForwarder()
		nf.macOf, nf.blocked, nf.onLog, nf.onAnswer = t.macOf, t.blocked, t.onLog, t.names.record
		return nf
	}
	nf := mk()
	err := nf.Listen(listen, t.port)
	if err == nil {
		return nf, listen, nil
	}
	nf.Close()
	if len(listen) == 1 {
		return nil, nil, err
	}
	nf = mk()
	if err := nf.Listen(listen[:1], t.port); err != nil {
		nf.Close()
		return nil, nil, err
	}
	return nf, listen[:1], nil
}

func (t *dnsTakeover) lastErrSnapshot() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastErr
}

func (t *dnsTakeover) applyLocked(iface, listen4 string, v4, v6 []string, sig string, now time.Time) {
	args := []string{"apply", iface, strconv.Itoa(t.port), listen4, strings.Join(v4, ",")}
	if len(v6) > 0 {
		args = append(args, strings.Join(v6, ","))
	}
	rc, out := t.runScript(args...)
	last := lastLine(strings.TrimSpace(out))
	if rc != 0 || !strings.HasPrefix(last, "DNSTK=on") {
		t.removeRulesLocked()
		t.setState("error", "apply failed: "+last)
		return
	}
	v6st, v6r := "untouched", "热点口没有全局 IPv6 地址, IPv6 DNS 未接管"
	for _, f := range strings.Fields(last) {
		if strings.HasPrefix(f, "v6=") {
			switch strings.TrimPrefix(f, "v6=") {
			case "0", "":
			case "unsupported":
				v6r = "内核/ip6tables 不支持 nat DNAT, IPv6 DNS 未接管(仍由系统处理, dpid 被动嗅探照常)"
			default:
				v6st, v6r = "active", ""
			}
		}
	}
	if len(v6) == 0 && v6st == "untouched" && v6r == "" {
		v6r = "热点口没有全局 IPv6 地址"
	}
	t.mu.Lock()
	t.active, t.healthy, t.state, t.lastErr = true, true, "active", ""
	t.ruleSig, t.iface, t.dst4, t.dst6 = sig, iface, v4, v6
	t.v6Status, t.v6Reason = v6st, v6r
	t.havePrev = false
	t.healthySince = now
	t.mu.Unlock()
	log.Printf("dns_takeover: active iface=%s listen=%s:%d upstream=%s(%s) %s", iface, listen4, t.port, t.upstream, t.upstreamKind, last)
}

// failOpenLocked 删 DNAT(设备回到系统 DNS), 告警, 退避
func (t *dnsTakeover) failOpenLocked(reason string, alertIt bool) {
	t.mu.Lock()
	wasActive := t.active
	now := t.now()
	t.retryAt = now.Add(t.backoff)
	retry := t.retryAt
	if t.backoff < dnsTKBackoffMax {
		t.backoff *= 2
		if t.backoff > dnsTKBackoffMax {
			t.backoff = dnsTKBackoffMax
		}
	}
	t.healthySince = time.Time{}
	t.mu.Unlock()
	if wasActive {
		t.removeRulesLocked()
	}
	t.mu.Lock()
	if wasActive {
		t.foCount++
		t.foLast = now.Unix()
		t.foReason = reason
	}
	t.mu.Unlock()
	t.setState("failopen", reason)
	log.Printf("dns_takeover: fail-open reason=%s was_active=%v retry_at=%s", reason, wasActive, retry.Format(time.RFC3339))
	if wasActive && alertIt && t.emitAlert != nil {
		t.emitAlert(alert.Alert{
			ID:     dnsTKAlertKind + "_" + strconv.FormatInt(now.Unix(), 10),
			Ts:     now.Unix(),
			Kind:   dnsTKAlertKind,
			Detail: "HNC DNS 接管已自动撤销(" + dnsTKReasonText(reason) + "), 热点设备已回到系统 DNS, 上网不受影响; " + retry.Format("15:04") + " 后自动重试",
			Extra:  map[string]interface{}{"reason": reason, "retry_at": retry.Unix()},
		})
	}
}

// Shutdown httpd 停机: 同步删规则、关转发器、落盘日志
func (t *dnsTakeover) Shutdown() {
	t.tickMu.Lock()
	defer t.tickMu.Unlock()
	t.stopLocked("stopped", "")
	t.mu.Lock()
	w := t.logw
	t.logw = nil
	t.mu.Unlock()
	if w != nil {
		w.close()
	}
}

// DNSTakeoverLoop 每 10 秒对账(关闭时也只是读一次配置文件)
func (s *server) DNSTakeoverLoop(stop <-chan struct{}) {
	t := s.dnsTK()
	t.tick()
	tk := time.NewTicker(dnsTKTick)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			t.tick()
		}
	}
}

// dnsTakeoverShutdown main.go 停机路径调用
func (s *server) dnsTakeoverShutdown() {
	dnsTKReg.Lock()
	t := dnsTKReg.m[s]
	dnsTKReg.Unlock()
	if t != nil {
		t.Shutdown()
	}
}

// ─── 动作 ───────────────────────────────────────────────────────────────

// (parseBoolParam 复用 app_time.go 的)
func actionDNSTakeoverSet(s *server, p map[string]string) actionResp {
	t := s.dnsTK()
	t.tickMu.Lock()
	defer t.tickMu.Unlock()
	c := loadDNSTKConf(s.hncDir)
	touched := false
	if v, ok := p["enabled"]; ok {
		b, valid := parseBoolParam(v)
		if !valid {
			return actionResp{OK: false, Error: "bad params", Detail: "enabled must be true|false"}
		}
		c.Enabled, touched = b, true
	}
	if v, ok := p["block_mode"]; ok {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "nxdomain" && v != "zero" {
			return actionResp{OK: false, Error: "bad params", Detail: "block_mode must be nxdomain|zero"}
		}
		c.BlockMode, touched = v, true
	}
	if v, ok := p["log_queries"]; ok {
		b, valid := parseBoolParam(v)
		if !valid {
			return actionResp{OK: false, Error: "bad params", Detail: "log_queries must be true|false"}
		}
		c.LogQueries, touched = b, true
	}
	if v, ok := p["log_redact"]; ok {
		b, valid := parseBoolParam(v)
		if !valid {
			return actionResp{OK: false, Error: "bad params", Detail: "log_redact must be true|false"}
		}
		c.LogRedact, touched = b, true
	}
	if v, ok := p["upstream"]; ok {
		v = strings.TrimSpace(v)
		switch {
		case v == "" || strings.EqualFold(v, "auto"):
			c.Upstream = ""
		case validDNSUpstream(v):
			c.Upstream = dnsNormUpstream(v)
		default:
			return actionResp{OK: false, Error: "bad params", Detail: "upstream must be auto | ip | ip:port"}
		}
		touched = true
	}
	if !touched {
		return actionResp{OK: false, Error: "bad params", Detail: "nothing to set (enabled|block_mode|log_queries|log_redact|upstream)"}
	}
	c.Ts = time.Now().Unix()
	b, _ := json.Marshal(c)
	if err := discoverWriteAtomic(dnsTKPath(s.hncDir), b); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	// 用户主动操作: 清掉 fail-open 退避, 立刻重试
	t.mu.Lock()
	t.retryAt, t.backoff = time.Time{}, dnsTKBackoffMin
	t.mu.Unlock()
	t.tickLocked()
	t.mu.Lock()
	detail := "state=" + t.state
	if t.upstream != "" {
		detail += " upstream=" + t.upstream + "(" + t.upstreamKind + ")"
	}
	if t.lastErr != "" {
		detail += " error=" + t.lastErr
	}
	t.mu.Unlock()
	return actionResp{OK: true, Detail: detail}
}

// ─── API ───────────────────────────────────────────────────────────────

func (s *server) apiDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	t := s.dnsTK()
	cfg := loadDNSTKConf(s.hncDir)
	t.mu.Lock()
	fwd := t.fwd
	listen := []string{}
	for _, a := range t.listen {
		listen = append(listen, net.JoinHostPort(a, strconv.Itoa(t.port)))
	}
	resp := map[string]interface{}{
		"ok": true, "enabled": cfg.Enabled, "active": t.active, "healthy": t.active && t.healthy,
		"state": t.state, "iface": t.iface, "listen": listen, "port": t.port,
		"upstream": t.upstream, "upstream_kind": t.upstreamKind,
		"v6":         map[string]interface{}{"status": t.v6Status, "reason": t.v6Reason},
		"block_mode": cfg.BlockMode, "log_queries": cfg.LogQueries, "log_redact": cfg.LogRedact,
		"upstream_config": cfg.Upstream,
		"failopen": map[string]interface{}{"count": t.foCount, "last_ts": t.foLast, "reason": t.foReason,
			"retry_at": dnsUnixOrZero(t.retryAt)},
		"last_error": t.lastErr, "last_check": t.lastCheck, "selftest_ms": t.selftestMS,
	}
	t.mu.Unlock()
	stats := map[string]interface{}{"queries": 0, "cached": 0, "blocked": 0, "errors": 0, "ratelimited": 0,
		"dropped": 0, "upstream": 0, "upstream_errs": 0, "upstream_tcp": 0, "servfail": 0,
		"p50_ms": 0, "p95_ms": 0, "cache_entries": 0}
	if fwd != nil {
		st := fwd.Stats()
		p50, p95 := fwd.Percentiles()
		stats = map[string]interface{}{"queries": st.Queries, "cached": st.Cached, "blocked": st.Blocked,
			"errors": st.Errors, "ratelimited": st.RateLimited, "dropped": st.Dropped, "upstream": st.Upstream,
			"upstream_errs": st.UpstreamErrs, "upstream_tcp": st.UpstreamTCP, "servfail": st.ServFail,
			"p50_ms": p50, "p95_ms": p95, "cache_entries": fwd.cache.Len()}
	}
	resp["stats"] = stats
	resp["top_domains_today"] = t.top.top(time.Now().Format("20060102"), dnsTKTopN)
	t.blkMu.RLock()
	nd, ng := t.blk.counts()
	t.blkMu.RUnlock()
	resp["blocklist"] = map[string]int{"devices": nd, "global": ng}
	resp["ip_names"] = t.names.size()
	if cfg.LogQueries {
		resp["recent"] = t.ring.latest("", dnsTKRecentN)
	}
	writeJSON(w, http.StatusOK, resp)
}

func dnsUnixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func (s *server) apiDNSLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	mac := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mac")))
	if mac != "" && !validMAC(mac) {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "invalid mac"})
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "invalid limit"})
			return
		}
		if n > dnsTKRingSize {
			n = dnsTKRingSize
		}
		limit = n
	}
	cfg := loadDNSTKConf(s.hncDir)
	entries := []dnsLogEntry{}
	if cfg.LogQueries {
		entries = s.dnsTK().ring.latest(mac, limit)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "log_queries": cfg.LogQueries,
		"log_redact": cfg.LogRedact, "mac": mac, "entries": entries})
}
