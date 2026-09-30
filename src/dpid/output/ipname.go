// Package output - ipname.go: v5.13 域名反查表(IP → 域名)。
//
// v5.18: nDPI 实验删除后, 这张表是 httpd 唯一的 IP→域名来源(以前
// run/ip_to_host.json 兜底)。数据来源:
//   - DNS 响应: A/AAAA(以及 HTTPS/SVCB 记录里的 ipv4hint/ipv6hint)映射到
//     用户请求的原始 qname; CNAME 链会被跟随(最多 8 跳), 只有链上名字拥有
//     的地址才入表, 链末端的规范名记在 cname 字段(qname 规则认不出时用它
//     归类, 例如 foo.com → CNAME foo.douyincdn.com);
//   - TLS ClientHello / QUIC Initial 的 SNI, 以及明文 HTTP 请求的 Host 头
//     ("连接名", 客户端真正发起连接时声明的名字)。连接名优先级高于 DNS
//     (DNS 可能是预取/共享 CDN IP), 未过期的连接名条目不会被 DNS 覆盖;
//   - ECH: 外层 SNI 若是已知的 ECH public_name(如 cloudflare-ech.com)就
//     不入表 —— 它不是真实目的站点, DNS 查到的名字更准确。
//
// 时效: DNS 条目保留 max(TTL, 10 分钟), 上限 24 小时; 连接名条目 30 分钟。
// KeepAlive(由 main.go 按 conntrack 活跃远端 IP 调用)给仍有活跃连接的条目
// 顺延 10 分钟, 但距最后一次 DNS/SNI 证据超过 24 小时的不再顺延 —— 长连接
// (推送 / 视频 / 游戏)不会因 DNS TTL 到期丢名字, 过期映射也不会永久保留。
//
// 容量: 最多 4096 条, LRU 淘汰。输出 run/dpi_ipname.json, 仅在有变化时写。
//
// 并发: 自带锁, 与 Writer.mu 无关; main.go 的 capture 回调直接调用。

package output

import (
	"container/list"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	DefaultIPNamePath = "/data/local/hnc/run/dpi_ipname.json"

	ipNameMaxEntries = 4096
	ipNameMinTTL     = 600   // 秒: 至少保留 10 分钟
	ipNameMaxTTL     = 86400 // 秒: DNS TTL 上限 24h(防超长 TTL 让映射近乎永久)
	ipNameSNITTL     = 1800  // 秒: SNI / HTTP Host 映射保留 30 分钟
	// KeepAlive 每次顺延的时长, 以及"最后一次证据"之后最多还能顺延多久。
	ipNameKeepAliveSec = 600
	ipNameMaxIdleSec   = 86400
	// ts 刷新超过该秒数才算"变化"(只刷新 ts 不必每次都重写文件)。
	ipNameTsDirtySec = 60
	// 过期时间比上次写盘时延后超过该秒数才算变化(exp 字段别落后太多)。
	ipNameExpDirtySec = 300
	// CNAME 链最多跟随的跳数。
	ipNameMaxCNAMEHops = 8
)

// 名字来源。sni / http 是"连接名", 优先级高于 dns。
const (
	IPNameSrcDNS  = "dns"
	IPNameSrcSNI  = "sni"
	IPNameSrcHTTP = "http"
)

func ipNameStrongSrc(src string) bool { return src == IPNameSrcSNI || src == IPNameSrcHTTP }

// echPublicNames 是已知的 ECH client-facing server 名字(ECH 外层 SNI)。
// 这些名字只说明"连到了某个 ECH 前端", 不能代表真实站点。
var echPublicNames = map[string]bool{
	"cloudflare-ech.com":    true,
	"crypto.cloudflare.com": true,
	"encryptedsni.com":      true,
}

// IsECHPublicName 报告 name 是否是已知的 ECH 外层 public_name。
func IsECHPublicName(name string) bool {
	return echPublicNames[normalizeName(name)]
}

// IPNameEntry 是 dpi_ipname.json 里的一条。
type IPNameEntry struct {
	Name string `json:"name"`
	Src  string `json:"src"` // "dns" | "sni" | "http"
	Ts   int64  `json:"ts"`
	// v5.18: DNS 条目的 CNAME 链末端规范名(与 name 不同时才有)。
	CNAME string `json:"cname,omitempty"`
	// v5.14: 域名按规则库归类的结果(Flush 时计算, 规则热更新后自动跟上)。
	// httpd 用它把 DNS 解析出的 IP 上的流量(尤其是看不到 SNI 的 QUIC)
	// 算给对应应用 —— 即"DNS 关联"。name 认不出时退回用 cname 归类。
	App      string `json:"app,omitempty"`
	AppName  string `json:"app_name,omitempty"`
	Category string `json:"category,omitempty"`
	// v5.18: 该映射的过期时间(unix 秒, 写盘时的值; 可能因 KeepAlive 实际更晚)。
	Exp int64 `json:"exp,omitempty"`
}

// DNSAnswer 是 DNS 应答里的一条资源记录(capture 解析后交给 RecordDNSAnswers)。
// Type: 1=A, 28=AAAA, 5=CNAME, 64/65=SVCB/HTTPS(Value 为地址提示 IP)。
type DNSAnswer struct {
	Name  string // 记录的 owner 名
	Type  uint16
	TTL   uint32
	Value string // A/AAAA/HTTPS 提示: IP 字符串; CNAME: 目标名
}

type ipNameFile struct {
	Schema      int                    `json:"schema"`
	GeneratedAt int64                  `json:"generated_at"`
	Entries     map[string]IPNameEntry `json:"entries"`
}

type ipNameItem struct {
	ip      string
	e       IPNameEntry
	expire  int64
	seen    int64 // 最后一次 DNS/SNI 证据时间
	fileExp int64 // 上次写盘时的 expire
}

// IPNameTable 是并发安全的 IP → 域名 LRU 表。
type IPNameTable struct {
	mu    sync.Mutex
	path  string
	max   int
	ll    *list.List // Front = 最近写入/刷新
	m     map[string]*list.Element
	dirty bool
}

func NewIPNameTable() *IPNameTable {
	return &IPNameTable{
		path: DefaultIPNamePath,
		max:  ipNameMaxEntries,
		ll:   list.New(),
		m:    make(map[string]*list.Element),
	}
}

// SetPath 设置输出文件路径(默认 DefaultIPNamePath)。
func (t *IPNameTable) SetPath(p string) {
	t.mu.Lock()
	t.path = p
	t.mu.Unlock()
}

// canonIP 把 IP 字符串规范化(net.IP.String(), IPv4-mapped IPv6 折叠成
// 点分 IPv4); 非法/未指定/回环/组播地址返回空。
func canonIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		return ""
	}
	return ip.String()
}

func dnsKeepSec(ttl uint32) int64 {
	keep := int64(ttl)
	if keep > ipNameMaxTTL {
		keep = ipNameMaxTTL
	}
	if keep < ipNameMinTTL {
		keep = ipNameMinTTL
	}
	return keep
}

// RecordDNS 是旧接口: answers 形如 "1.2.3.4" / "CNAME:xxx", 全部地址映射到
// qname, 统一使用 ttl; 最后一个 CNAME 目标作为 cname。
func (t *IPNameTable) RecordDNS(qname string, answers []string, ttl uint32, ts time.Time) {
	var cname string
	recs := make([]DNSAnswer, 0, len(answers))
	for _, a := range answers {
		if strings.HasPrefix(a, "CNAME:") {
			cname = normalizeName(a[len("CNAME:"):])
			continue
		}
		recs = append(recs, DNSAnswer{Type: 1, TTL: ttl, Value: a})
	}
	t.recordDNS(normalizeName(qname), recs, cname, ts)
}

// RecordDNSAnswers 按记录 owner 名跟随 CNAME 链: 链上(qname 或其 CNAME
// 目标)拥有的地址映射到原始 qname, cname 字段记链末端规范名。不在链上的
// 地址记录(异常/附加数据)忽略。每条地址按自己的 TTL 计算保留期。
func (t *IPNameTable) RecordDNSAnswers(qname string, recs []DNSAnswer, ts time.Time) {
	qn := normalizeName(qname)
	if qn == "" || len(recs) == 0 {
		return
	}
	cn := map[string]string{}
	for _, r := range recs {
		if r.Type == 5 {
			if o, v := normalizeName(r.Name), normalizeName(r.Value); o != "" && v != "" {
				if _, dup := cn[o]; !dup {
					cn[o] = v
				}
			}
		}
	}
	inChain := map[string]bool{qn: true}
	final := qn
	for i := 0; i < ipNameMaxCNAMEHops; i++ {
		nx, ok := cn[final]
		if !ok || inChain[nx] {
			break
		}
		inChain[nx] = true
		final = nx
	}
	cname := ""
	if final != qn {
		cname = final
	}
	addrs := make([]DNSAnswer, 0, len(recs))
	for _, r := range recs {
		if r.Type == 5 {
			continue
		}
		owner := normalizeName(r.Name)
		if owner == "" {
			owner = qn
		}
		if !inChain[owner] {
			continue
		}
		addrs = append(addrs, r)
	}
	t.recordDNS(qn, addrs, cname, ts)
}

func (t *IPNameTable) recordDNS(name string, addrs []DNSAnswer, cname string, ts time.Time) {
	if name == "" || len(addrs) == 0 {
		return
	}
	now := ts.Unix()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, a := range addrs {
		ip := canonIP(a.Value)
		if ip == "" {
			continue
		}
		t.putLocked(ip, IPNameEntry{Name: name, Src: IPNameSrcDNS, Ts: now, CNAME: cname}, now+dnsKeepSec(a.TTL), now)
	}
}

// RecordSNI 记录 TLS ClientHello / QUIC 的 remoteIP → SNI。
func (t *IPNameTable) RecordSNI(remoteIP, sni string, ts time.Time) {
	t.RecordConnName(remoteIP, sni, IPNameSrcSNI, ts)
}

// RecordConnName 记录一次连接声明的名字(src = "sni" | "http")。已知的 ECH
// public_name(ECH 外层 SNI)不入表 —— Chrome 对所有连接都发 GREASE ECH 扩展,
// "带 ECH 扩展"本身区分不了真假 ECH, 只能按外层名字判断。
func (t *IPNameTable) RecordConnName(remoteIP, name, src string, ts time.Time) {
	n := normalizeName(name)
	ip := canonIP(remoteIP)
	if n == "" || ip == "" || !ipNameStrongSrc(src) {
		return
	}
	if echPublicNames[n] {
		return
	}
	now := ts.Unix()
	t.mu.Lock()
	t.putLocked(ip, IPNameEntry{Name: n, Src: src, Ts: now}, now+ipNameSNITTL, now)
	t.mu.Unlock()
}

func (t *IPNameTable) putLocked(ip string, e IPNameEntry, expire, now int64) {
	if el, ok := t.m[ip]; ok {
		it := el.Value.(*ipNameItem)
		// 未过期的连接名条目不被 DNS 覆盖(同名则只顺延, 不降级 src)。
		if e.Src == IPNameSrcDNS && ipNameStrongSrc(it.e.Src) && it.expire > now {
			if it.e.Name == e.Name {
				it.seen = maxI64(it.seen, now)
				t.extendLocked(it, expire)
			}
			return
		}
		changed := it.e.Name != e.Name || it.e.Src != e.Src || it.e.CNAME != e.CNAME ||
			e.Ts-it.e.Ts >= ipNameTsDirtySec
		it.seen = maxI64(it.seen, now)
		if !changed {
			// 仅顺延过期时间, ts 保持原值。
			t.extendLocked(it, expire)
			t.ll.MoveToFront(el)
			return
		}
		if it.e.Name != e.Name || it.e.Src != e.Src {
			it.expire = expire // 名字/来源换了: 按新来源的时效重算
		} else {
			it.expire = maxI64(it.expire, expire)
		}
		it.e = e
		t.ll.MoveToFront(el)
		t.dirty = true
		return
	}
	for t.ll.Len() >= t.max {
		back := t.ll.Back()
		if back == nil {
			break
		}
		delete(t.m, back.Value.(*ipNameItem).ip)
		t.ll.Remove(back)
	}
	t.m[ip] = t.ll.PushFront(&ipNameItem{ip: ip, e: e, expire: expire, seen: now})
	t.dirty = true
}

// extendLocked 把过期时间顺延到 expire(只增不减); 比上次写盘的值延后很多
// 时标脏, 让文件里的 exp 跟上。
func (t *IPNameTable) extendLocked(it *ipNameItem, expire int64) {
	if expire <= it.expire {
		return
	}
	it.expire = expire
	if it.expire-it.fileExp >= ipNameExpDirtySec {
		t.dirty = true
	}
}

// KeepAlive 给仍有活跃连接的远端 IP 顺延映射(见文件头)。ips 的键须是
// net.IP.String() 规范形式。返回被顺延的条目数。
func (t *IPNameTable) KeepAlive(ips map[string]struct{}, ts time.Time) int {
	if len(ips) == 0 {
		return 0
	}
	now := ts.Unix()
	n := 0
	t.mu.Lock()
	defer t.mu.Unlock()
	// 以小集合为外层循环。
	visit := func(it *ipNameItem) {
		if it.expire <= now || now-it.seen > ipNameMaxIdleSec {
			return
		}
		if exp := now + ipNameKeepAliveSec; exp > it.expire {
			t.extendLocked(it, exp)
			n++
		}
	}
	if len(ips) < len(t.m) {
		for ip := range ips {
			if el, ok := t.m[ip]; ok {
				visit(el.Value.(*ipNameItem))
			}
		}
	} else {
		for ip, el := range t.m {
			if _, ok := ips[ip]; ok {
				visit(el.Value.(*ipNameItem))
			}
		}
	}
	return n
}

func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// Lookup 返回 ip 的当前映射(过期的不返回)。
func (t *IPNameTable) Lookup(ip string, now time.Time) (IPNameEntry, bool) {
	ip = canonIP(ip)
	t.mu.Lock()
	defer t.mu.Unlock()
	el, ok := t.m[ip]
	if !ok {
		return IPNameEntry{}, false
	}
	it := el.Value.(*ipNameItem)
	if it.expire <= now.Unix() {
		return IPNameEntry{}, false
	}
	e := it.e
	e.Exp = it.expire
	return e, true
}

// Len 返回当前条目数(含尚未被 Flush 清理的过期条目)。
func (t *IPNameTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ll.Len()
}

// Flush 清理过期条目, 有变化时原子写 JSON。无变化直接返回 nil。
func (t *IPNameTable) Flush(now time.Time) error {
	n := now.Unix()
	t.mu.Lock()
	for el := t.ll.Back(); el != nil; {
		prev := el.Prev()
		it := el.Value.(*ipNameItem)
		if it.expire <= n {
			delete(t.m, it.ip)
			t.ll.Remove(el)
			t.dirty = true
		}
		el = prev
	}
	if !t.dirty {
		t.mu.Unlock()
		return nil
	}
	out := ipNameFile{Schema: 1, GeneratedAt: n, Entries: make(map[string]IPNameEntry, t.ll.Len())}
	oldExp := make(map[*ipNameItem]int64, len(t.m))
	for ip, el := range t.m {
		it := el.Value.(*ipNameItem)
		e := it.e
		r, ok := classifyHost(e.Name)
		if (!ok || r.ID == "") && e.CNAME != "" {
			r, ok = classifyHost(e.CNAME)
		}
		if ok && r.ID != "" {
			e.App, e.AppName, e.Category = r.ID, r.Name, r.Category
		}
		e.Exp = it.expire
		oldExp[it] = it.fileExp
		it.fileExp = it.expire
		out.Entries[ip] = e
	}
	path := t.path
	t.dirty = false
	t.mu.Unlock()

	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if err := atomicWrite(path, b, 0o644); err != nil {
		// 写失败: 恢复 dirty 与 fileExp, 下个周期重试。
		t.mu.Lock()
		t.dirty = true
		for it, fe := range oldExp {
			it.fileExp = fe
		}
		t.mu.Unlock()
		return err
	}
	return nil
}
