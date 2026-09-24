// Package output - ipname.go: v5.13 域名反查表(IP → 域名)。
//
// 数据来源:
//   - DNS 响应: Answers 里的 A/AAAA 映射到用户请求的原始 qname(CNAME 链
//     中间名不上报 —— 用户关心的是"访问了什么", 不是 CDN 的别名);
//   - TLS ClientHello: remoteIP → SNI。SNI 优先级高于 DNS(它是客户端真正
//     发起连接时声明的名字, DNS 可能是预取/共享 CDN IP), 未过期的 SNI 条目
//     不会被 DNS 覆盖。
//
// 容量/时效: 最多 4096 条, LRU 淘汰; 每条保留 max(10 分钟, min(DNS TTL, 1h)),
// SNI 条目保留 30 分钟。输出 run/dpi_ipname.json, 仅在有变化时写(5 秒一次)。
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
	ipNameMinTTL     = 600  // 秒: 至少保留 10 分钟
	ipNameMaxTTL     = 3600 // 秒: DNS TTL 上限(防 1 天 TTL 把过期映射留太久)
	ipNameSNITTL     = 1800 // 秒: SNI 映射保留 30 分钟
	// ts 刷新超过该秒数才算"变化"(只刷新 ts 不必每 5 秒重写文件)。
	ipNameTsDirtySec = 60
)

// IPNameEntry 是 dpi_ipname.json 里的一条。
type IPNameEntry struct {
	Name string `json:"name"`
	Src  string `json:"src"` // "dns" | "sni"
	Ts   int64  `json:"ts"`
	// v5.14: 域名按规则库归类的结果(Flush 时计算, 规则热更新后自动跟上)。
	// httpd 用它把 DNS 解析出的 IP 上的流量(尤其是看不到 SNI 的 QUIC)
	// 算给对应应用 —— 即"DNS 关联"。
	App      string `json:"app,omitempty"`
	AppName  string `json:"app_name,omitempty"`
	Category string `json:"category,omitempty"`
}

type ipNameFile struct {
	Schema      int                    `json:"schema"`
	GeneratedAt int64                  `json:"generated_at"`
	Entries     map[string]IPNameEntry `json:"entries"`
}

type ipNameItem struct {
	ip     string
	e      IPNameEntry
	expire int64
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

// canonIP 把 IP 字符串规范化; 非法/未指定/回环地址返回空。
func canonIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return ""
	}
	return ip.String()
}

// RecordDNS 把一次 DNS 响应的 A/AAAA 答案映射到原始 qname。answers 形如
// parse.go 的 DNSInfo.Answers: IP 字符串或 "CNAME:xxx"(后者跳过)。
func (t *IPNameTable) RecordDNS(qname string, answers []string, ttl uint32, ts time.Time) {
	name := normalizeName(qname)
	if name == "" || len(answers) == 0 {
		return
	}
	keep := int64(ttl)
	if keep > ipNameMaxTTL {
		keep = ipNameMaxTTL
	}
	if keep < ipNameMinTTL {
		keep = ipNameMinTTL
	}
	now := ts.Unix()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, a := range answers {
		if strings.HasPrefix(a, "CNAME:") {
			continue
		}
		ip := canonIP(a)
		if ip == "" {
			continue
		}
		t.putLocked(ip, IPNameEntry{Name: name, Src: "dns", Ts: now}, now+keep, now)
	}
}

// RecordSNI 记录 TLS ClientHello 的 remoteIP → SNI。
func (t *IPNameTable) RecordSNI(remoteIP, sni string, ts time.Time) {
	name := normalizeName(sni)
	ip := canonIP(remoteIP)
	if name == "" || ip == "" {
		return
	}
	now := ts.Unix()
	t.mu.Lock()
	t.putLocked(ip, IPNameEntry{Name: name, Src: "sni", Ts: now}, now+ipNameSNITTL, now)
	t.mu.Unlock()
}

func (t *IPNameTable) putLocked(ip string, e IPNameEntry, expire, now int64) {
	if el, ok := t.m[ip]; ok {
		it := el.Value.(*ipNameItem)
		// 未过期的 SNI 条目不被 DNS 覆盖(同名则只顺延, 不降级 src)。
		if e.Src == "dns" && it.e.Src == "sni" && it.expire > now {
			if it.e.Name == e.Name && expire > it.expire {
				it.expire = expire
			}
			return
		}
		changed := it.e.Name != e.Name || it.e.Src != e.Src || e.Ts-it.e.Ts >= ipNameTsDirtySec
		if !changed {
			// 仅顺延过期时间, ts 保持原值(文件不必重写)。
			if expire > it.expire {
				it.expire = expire
			}
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
	t.m[ip] = t.ll.PushFront(&ipNameItem{ip: ip, e: e, expire: expire})
	t.dirty = true
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
	return it.e, true
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
	for ip, el := range t.m {
		e := el.Value.(*ipNameItem).e
		if r, ok := classifyHost(e.Name); ok && r.ID != "" {
			e.App, e.AppName, e.Category = r.ID, r.Name, r.Category
		}
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
		// 写失败: 恢复 dirty, 下个周期重试。
		t.mu.Lock()
		t.dirty = true
		t.mu.Unlock()
		return err
	}
	return nil
}
