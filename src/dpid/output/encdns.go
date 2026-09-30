// Package output - encdns.go: v5.21 加密 DNS 观测计数(写进 dpi_state.json 的 "encdns")。
//
// 被动观测, 与 httpd 的「加密 DNS 策略」(bin/encdns_sync.sh)无关, 用来回答:
// 「热点上有多少解析是明文可见的, 有多少设备在试图走加密 DNS」。
//
//	dns_seen      抓到的 DNS 报文数(查询 + 应答; 明文可见的解析量)
//	dot_attempts  新出现的 853 端口连接数(DoT/DoQ; 来自 15 秒一次的 conntrack 扫描,
//	              被 REJECT 的连接存活很短, 可能漏计 —— 精确的拦截数看 /api/encdns 的
//	              iptables 计数)。cBPF 不放行 853 的包, 所以不是按 SYN 数的。
//	dot_flows     最近一次扫描时仍在的 853 连接数
//	doh_suspect   TLS/QUIC ClientHello 的 SNI 是已知 DoH 主机名, 或目的是已知 DoH 地址
//	recent_doh    最近几次 DoH 疑似事件 {client_mac, name, ts}
//
// 名单与 data/encdns_resolvers.txt 一致(encdns_test.go 逐条对齐)。

package output

import (
	"net"
	"strings"
)

// DoHHosts 已知 DoH/DoT 解析器主机名(后缀匹配: 子域名也算)。
var DoHHosts = []string{
	"dns.google", "dns.google.com", "cloudflare-dns.com", "one.one.one.one",
	"dns.alidns.com", "doh.pub", "dot.pub", "sm2.doh.pub", "doh.360.cn", "dot.360.cn",
	"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
	"doh.opendns.com", "doh.familyshield.opendns.com", "dns.umbrella.com",
	"dns.adguard.com", "dns.adguard-dns.com", "family.adguard-dns.com", "unfiltered.adguard-dns.com",
	"dns.nextdns.io", "dns.controld.com", "freedns.controld.com", "doh.cleanbrowsing.org",
	"doh.dns.sb", "dns.mullvad.net", "doh.mullvad.net", "dns.twnic.tw",
}

// DoHAddrs 只提供 DNS 服务的解析器地址 / 网段。
var DoHAddrs = []string{
	"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
	"1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
	"2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112", "2606:4700:4700::1002",
	"223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1",
	"1.12.12.12", "120.53.53.53", "2402:4e00::",
	"9.9.9.9", "149.112.112.112", "9.9.9.11", "149.112.112.11", "2620:fe::fe", "2620:fe::9",
	"208.67.222.222", "208.67.220.220", "2620:119:35::35", "2620:119:53::53",
	"94.140.14.14", "94.140.15.15", "94.140.14.140", "94.140.14.141", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
	"45.90.28.0/24", "45.90.30.0/24", "76.76.2.0/24",
	"185.222.222.222", "45.11.45.11", "194.242.2.2", "101.101.101.101",
}

var dohNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, a := range DoHAddrs {
		s := a
		if !strings.Contains(s, "/") {
			if strings.Contains(s, ":") {
				s += "/128"
			} else {
				s += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// IsDoHHost 名字是否是已知 DoH 主机名(或其子域名)。
func IsDoHHost(name string) bool {
	n := normalizeName(name)
	if n == "" {
		return false
	}
	for _, h := range DoHHosts {
		if n == h || strings.HasSuffix(n, "."+h) {
			return true
		}
	}
	return false
}

// IsDoHAddr 地址是否是已知 DoH 解析器地址。
func IsDoHAddr(ip string) bool {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return false
	}
	for _, n := range dohNets {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

// ConntrackDoTKey 一行 conntrack 记录若原方向目的端口是 853, 返回连接标识
// (proto|src|sport|dst), 否则 ""。
func ConntrackDoTKey(line string) string {
	f := strings.Fields(line)
	if len(f) < 4 {
		return ""
	}
	var src, dst, sport, dport string
scan:
	for _, t := range f[3:] {
		eq := strings.IndexByte(t, '=')
		if eq < 0 {
			continue
		}
		k, v := t[:eq], t[eq+1:]
		switch k {
		case "src":
			if src != "" {
				break scan // 进入应答方向
			}
			src = v
		case "dst":
			if dst == "" {
				dst = v
			}
		case "sport":
			if sport == "" {
				sport = v
			}
		case "dport":
			if dport == "" {
				dport = v
			}
		}
	}
	if dport != "853" || src == "" || dst == "" {
		return ""
	}
	return f[2] + "|" + src + "|" + sport + "|" + dst
}

const (
	encdnsRecentMax = 8
	encdnsDoTKeyMax = 4096
)

// EncDNSRecent 一次 DoH 疑似事件。
type EncDNSRecent struct {
	ClientMAC string `json:"client_mac,omitempty"`
	Name      string `json:"name"`
	Ts        int64  `json:"ts"`
}

// EncDNSState 是 dpi_state.json 的 "encdns" 块。
type EncDNSState struct {
	DNSSeen     uint64         `json:"dns_seen"`
	DoTAttempts uint64         `json:"dot_attempts"`
	DoTFlows    int            `json:"dot_flows"`
	DoHSuspect  uint64         `json:"doh_suspect"`
	RecentDoH   []EncDNSRecent `json:"recent_doh,omitempty"`
	Since       int64          `json:"since"`
}

// encdnsStats 由 Writer 持有, 全部在 w.mu 内读写。
type encdnsStats struct {
	dnsSeen, dotAttempts, dohSuspect uint64
	dotFlows                         int
	dotKeys                          map[string]struct{}
	recent                           []EncDNSRecent
}

func (e *encdnsStats) observeTLS(host, remoteIP, mac string, now int64) {
	name := host
	switch {
	case host != "" && IsDoHHost(host):
	case IsDoHAddr(remoteIP):
		if name == "" {
			name = remoteIP
		}
	default:
		return
	}
	e.dohSuspect++
	e.recent = append(e.recent, EncDNSRecent{ClientMAC: mac, Name: name, Ts: now})
	if len(e.recent) > encdnsRecentMax {
		e.recent = e.recent[len(e.recent)-encdnsRecentMax:]
	}
}

// observeDoT 一次扫描看到的 853 连接; 上次扫描没有的记为新尝试。
func (e *encdnsStats) observeDoT(keys map[string]struct{}) {
	for k := range keys {
		if _, ok := e.dotKeys[k]; !ok {
			e.dotAttempts++
		}
	}
	e.dotFlows = len(keys)
	if len(keys) > encdnsDoTKeyMax {
		// 防御: 超大表只保留计数, 下一轮可能重复计入(不影响正确性太多)
		e.dotKeys = nil
		return
	}
	e.dotKeys = keys
}

func (e *encdnsStats) snapshot(since int64) *EncDNSState {
	s := &EncDNSState{DNSSeen: e.dnsSeen, DoTAttempts: e.dotAttempts, DoTFlows: e.dotFlows,
		DoHSuspect: e.dohSuspect, Since: since}
	if len(e.recent) > 0 {
		s.RecentDoH = append([]EncDNSRecent(nil), e.recent...)
	}
	return s
}

// ObserveDoTFlows 由 main.go 的 conntrack 扫描调用(keys 来自 ConntrackDoTKey)。
func (w *Writer) ObserveDoTFlows(keys map[string]struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.encdns.observeDoT(keys)
}

// ConntrackOrigDst 导出 conntrackOrigDst(main.go 的单次扫描用)。
func ConntrackOrigDst(line string) string { return conntrackOrigDst(line) }
