// api_conn.go — v5.13 实时连接查看 + 设备识别合并
//
//   GET /api/connections?mac=aa:bb:..  某台设备当前的连接列表(conntrack)
//   GET /api/connections               每台设备的连接数(设备列表角标用)
//
// 数据源: /proc/net/nf_conntrack —— 内核对每条经过热点 NAT 的连接都有记录,
// 比 dpid 的抓包更全(dpid 的 BPF 只放行 DNS/TLS 握手, 看不到一般数据流)。
// 富化:
//   - 域名: run/dpi_ipname.json(dpid 从 DNS 应答 / TLS SNI 建的 IP→域名表)
//           → run/ip_to_host.json(nDPI 持续模式, 若开着)
//   - 应用: run/ip_app_map.json(dpid 规则命中的 IP→应用)
//   - 服务: 常见端口兜底(DNS / NTP / QUIC / 推送 ...)
// 速率: 两次读 conntrack 的字节差 / 时间差(需要 nf_conntrack_acct=1; 首次
// 访问时若为 0 会尝试打开, 只对之后新建的连接生效)。
// 开销: conntrack 全表解析 1 秒内共享一次结果, 多个请求不重复读。

package main

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 测试钩子: 覆盖 conntrack / acct 路径
func conntrackPath() string {
	if p := os.Getenv("HNC_CONNTRACK_PATH"); p != "" {
		return p
	}
	return "/proc/net/nf_conntrack"
}

func conntrackAcctPath() string {
	if p := os.Getenv("HNC_CONNTRACK_ACCT_PATH"); p != "" {
		return p
	}
	return "/proc/sys/net/netfilter/nf_conntrack_acct"
}

type ctEntry struct {
	Family  string // ipv4 / ipv6
	Proto   string // tcp / udp / icmp / ...
	State   string // TCP 状态, UDP/ICMP 为空
	Src     string
	Dst     string
	Sport   int
	Dport   int
	UpPkts  uint64
	UpB     uint64
	DnPkts  uint64
	DnB     uint64
	Acct    bool // 行里带 bytes= 字段
	Assured bool
	Unrepl  bool
	TTL     int // 剩余超时秒数
}

func (e *ctEntry) key() string {
	return e.Proto + "|" + e.Src + "|" + strconv.Itoa(e.Sport) + "|" + e.Dst + "|" + strconv.Itoa(e.Dport)
}

// parseConntrackLine 解析 /proc/net/nf_conntrack 的一行:
//
//	ipv4 2 tcp 6 431999 ESTABLISHED src=A dst=B sport=1 dport=443 packets=3 bytes=180 src=B dst=N sport=443 dport=1 packets=2 bytes=120 [ASSURED] mark=0 zone=0 use=2
//
// 第一组 src/dst/... 是原方向(客户端发起), 第二组是应答方向。
func parseConntrackLine(line string) (ctEntry, bool) {
	f := strings.Fields(line)
	if len(f) < 6 {
		return ctEntry{}, false
	}
	e := ctEntry{Family: f[0], Proto: f[2]}
	if e.Family != "ipv4" && e.Family != "ipv6" {
		return ctEntry{}, false
	}
	e.TTL, _ = strconv.Atoi(f[4])
	grp := 0 // 0 = 原方向, 1 = 应答方向
	seen := map[string]bool{}
	for _, t := range f[5:] {
		switch t {
		case "[ASSURED]":
			e.Assured = true
			continue
		case "[UNREPLIED]":
			e.Unrepl = true
			continue
		}
		eq := strings.IndexByte(t, '=')
		if eq < 0 {
			if grp == 0 && len(seen) == 0 && e.State == "" && t == strings.ToUpper(t) {
				e.State = t
			}
			continue
		}
		k, v := t[:eq], t[eq+1:]
		if seen[k] && (k == "src" || k == "dst" || k == "sport" || k == "dport" || k == "packets" || k == "bytes") {
			grp = 1
			seen = map[string]bool{}
		}
		seen[k] = true
		switch k {
		case "src":
			if grp == 0 {
				e.Src = v
			}
		case "dst":
			if grp == 0 {
				e.Dst = v
			}
		case "sport":
			if grp == 0 {
				e.Sport, _ = strconv.Atoi(v)
			}
		case "dport":
			if grp == 0 {
				e.Dport, _ = strconv.Atoi(v)
			}
		case "packets":
			n, _ := strconv.ParseUint(v, 10, 64)
			if grp == 0 {
				e.UpPkts = n
			} else {
				e.DnPkts = n
			}
		case "bytes":
			n, _ := strconv.ParseUint(v, 10, 64)
			e.Acct = true
			if grp == 0 {
				e.UpB = n
			} else {
				e.DnB = n
			}
		}
	}
	if e.Src == "" || e.Dst == "" {
		return ctEntry{}, false
	}
	// IPv6 地址统一成压缩格式, 与 devices.json / dpid 的写法对齐
	if e.Family == "ipv6" {
		if ip := net.ParseIP(e.Src); ip != nil {
			e.Src = ip.String()
		}
		if ip := net.ParseIP(e.Dst); ip != nil {
			e.Dst = ip.String()
		}
	}
	return e, true
}

// ─── conntrack 快照(1s 共享) + 速率差分 ───────────────────────────────

type ctPrev struct {
	up, dn uint64
	at     time.Time
}

type ctSnapshot struct {
	at       time.Time
	entries  []ctEntry
	upBps    map[string]float64
	dnBps    map[string]float64
	readable bool
	acct     bool
	err      string
}

var ctState struct {
	mu        sync.Mutex
	snap      *ctSnapshot
	prev      map[string]ctPrev
	acctTried bool
}

const ctMaxLines = 1 << 16

func conntrackSnapshot() *ctSnapshot {
	ctState.mu.Lock()
	defer ctState.mu.Unlock()
	now := time.Now()
	if ctState.snap != nil && now.Sub(ctState.snap.at) < time.Second {
		return ctState.snap
	}
	if !ctState.acctTried {
		ctState.acctTried = true
		// 没开字节计数就打开(root 可写; 失败无所谓, 只是没有字节/速率)
		ap := conntrackAcctPath()
		if b, err := os.ReadFile(ap); err == nil && strings.TrimSpace(string(b)) == "0" {
			_ = os.WriteFile(ap, []byte("1\n"), 0o644)
		}
	}
	sn := &ctSnapshot{at: now, upBps: map[string]float64{}, dnBps: map[string]float64{}}
	f, err := os.Open(conntrackPath())
	if err != nil {
		sn.err = err.Error()
		ctState.snap = sn
		return sn
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	n := 0
	for sc.Scan() {
		if n++; n > ctMaxLines {
			break
		}
		if e, ok := parseConntrackLine(sc.Text()); ok {
			sn.entries = append(sn.entries, e)
			if e.Acct {
				sn.acct = true
			}
		}
	}
	_ = f.Close()
	sn.readable = true
	if ctState.prev == nil {
		ctState.prev = map[string]ctPrev{}
	}
	next := make(map[string]ctPrev, len(sn.entries))
	for _, e := range sn.entries {
		k := e.key()
		if p, ok := ctState.prev[k]; ok {
			if dt := now.Sub(p.at).Seconds(); dt > 0.2 && dt < 120 {
				if e.UpB >= p.up {
					sn.upBps[k] = float64(e.UpB-p.up) * 8 / dt
				}
				if e.DnB >= p.dn {
					sn.dnBps[k] = float64(e.DnB-p.dn) * 8 / dt
				}
			}
		}
		next[k] = ctPrev{up: e.UpB, dn: e.DnB, at: now}
	}
	ctState.prev = next // 消失的连接自然被丢弃, map 不会无限增长
	ctState.snap = sn
	return sn
}

// ─── 富化数据 ─────────────────────────────────────────────────────────

// wellKnownSvc 常见端口的兜底服务名(没有域名/应用时显示)
func wellKnownSvc(proto string, port int) string {
	switch port {
	case 53:
		return "DNS"
	case 853:
		return "DNS over TLS"
	case 123:
		return "NTP 对时"
	case 80, 8080:
		return "HTTP"
	case 443:
		if proto == "udp" {
			return "QUIC / HTTP3"
		}
		return "HTTPS"
	case 5228, 5229, 5230:
		return "Google 推送"
	case 5223:
		return "Apple 推送"
	case 3478, 3479, 19302:
		return "STUN / 语音通话"
	case 8000, 8001:
		if proto == "udp" {
			return "QQ / 微信 语音"
		}
	case 1935:
		return "RTMP 直播"
	case 22:
		return "SSH"
	case 25, 465, 587, 993, 995, 143, 110:
		return "邮件"
	}
	if proto == "icmp" || proto == "ipv6-icmp" || proto == "icmpv6" {
		return "Ping"
	}
	return ""
}

type ipName struct {
	Name string
	Src  string
}

// loadIPNames 汇总 IP→域名: dpid 的 dpi_ipname.json 优先, nDPI 的 ip_to_host.json 兜底
func (s *server) loadIPNames() map[string]ipName {
	out := map[string]ipName{}
	if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "ip_to_host.json")); err == nil {
		if root, ok := raw.(map[string]interface{}); ok {
			var list []interface{}
			switch v := root["entries"].(type) {
			case []interface{}:
				list = v
			}
			for _, it := range list {
				m, _ := it.(map[string]interface{})
				ip, host := asString(m["ip"]), asString(m["host"])
				if ip != "" && host != "" {
					out[ip] = ipName{host, "ndpi"}
				}
			}
		}
	}
	if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "dpi_ipname.json")); err == nil {
		if root, ok := raw.(map[string]interface{}); ok {
			if ents, ok := root["entries"].(map[string]interface{}); ok {
				for ip, v := range ents {
					m, _ := v.(map[string]interface{})
					if name := asString(m["name"]); name != "" {
						src := asString(m["src"])
						if src == "" {
							src = "dns"
						}
						out[ip] = ipName{name, src}
					}
				}
			}
		}
	}
	return out
}

type ipApp struct{ ID, Name string }

func (s *server) loadIPApps() map[string]ipApp {
	out := map[string]ipApp{}
	raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "ip_app_map.json"))
	if err != nil {
		return out
	}
	root, _ := raw.(map[string]interface{})
	list, _ := root["entries"].([]interface{})
	for _, it := range list {
		m, _ := it.(map[string]interface{})
		ip := asString(m["ip"])
		if ip == "" {
			continue
		}
		name := asString(m["name"])
		if name == "" {
			name = asString(m["app_id"])
		}
		out[ip] = ipApp{asString(m["app_id"]), name}
	}
	return out
}

// deviceIPsByMAC: MAC(小写) → 该设备所有已知 IP(devices.json 的 ip + dpid 见过的 client_ips)
func (s *server) deviceIPsByMAC() map[string][]string {
	out := map[string][]string{}
	add := func(mac, ip string) {
		mac = strings.ToLower(strings.TrimSpace(mac))
		ip = strings.TrimSpace(ip)
		if mac == "" || ip == "" || ip == "-" {
			return
		}
		if p := net.ParseIP(ip); p != nil {
			ip = p.String()
		} else {
			return
		}
		for _, x := range out[mac] {
			if x == ip {
				return
			}
		}
		out[mac] = append(out[mac], ip)
	}
	if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "data", "devices.json")); err == nil {
		if m, ok := raw.(map[string]interface{}); ok {
			for mac, v := range m {
				d, _ := v.(map[string]interface{})
				add(mac, asString(d["ip"]))
			}
		}
	}
	if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "dpi_state.json")); err == nil {
		root, _ := raw.(map[string]interface{})
		cl, _ := root["clients"].(map[string]interface{})
		for _, v := range cl {
			c, _ := v.(map[string]interface{})
			mac := asString(c["client_mac"])
			add(mac, asString(c["client_ip"]))
			if ips, ok := c["client_ips"].([]interface{}); ok {
				for _, ip := range ips {
					add(mac, asString(ip))
				}
			}
		}
	}
	return out
}

// ─── handler ──────────────────────────────────────────────────────────

const connListCap = 150

func (s *server) apiConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	sn := conntrackSnapshot()
	base := map[string]interface{}{
		"ok":       true,
		"ts":       sn.at.Unix(),
		"readable": sn.readable,
		"acct":     sn.acct,
	}
	if !sn.readable {
		base["error"] = "conntrack 不可读: " + sn.err
	}
	ipsBy := s.deviceIPsByMAC()
	mac := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mac")))

	if mac == "" {
		// 汇总模式: 每台设备的连接数与总速率
		owner := map[string]string{}
		for m, ips := range ipsBy {
			for _, ip := range ips {
				owner[ip] = m
			}
		}
		counts := map[string]map[string]interface{}{}
		for _, e := range sn.entries {
			m, ok := owner[e.Src]
			if !ok {
				continue
			}
			c := counts[m]
			if c == nil {
				c = map[string]interface{}{"n": 0, "bps": 0.0}
				counts[m] = c
			}
			c["n"] = c["n"].(int) + 1
			k := e.key()
			c["bps"] = c["bps"].(float64) + sn.upBps[k] + sn.dnBps[k]
		}
		base["counts"] = counts
		writeJSON(w, http.StatusOK, base)
		return
	}

	ips := ipsBy[mac]
	if q := strings.TrimSpace(r.URL.Query().Get("ip")); q != "" {
		if p := net.ParseIP(q); p != nil {
			ips = append(ips, p.String())
		}
	}
	mine := map[string]bool{}
	for _, ip := range ips {
		mine[ip] = true
	}
	names := s.loadIPNames()
	apps := s.loadIPApps()

	type row struct {
		m     map[string]interface{}
		score float64
		total uint64
	}
	var rows []row
	appAgg := map[string]*struct {
		n     int
		b     uint64
		bps   float64
		label string
	}{}
	var totUp, totDn uint64
	var totBps float64
	for _, e := range sn.entries {
		if !mine[e.Src] {
			continue
		}
		k := e.key()
		up, dn := sn.upBps[k], sn.dnBps[k]
		item := map[string]interface{}{
			"proto": e.Proto, "dst": e.Dst, "dport": e.Dport, "sport": e.Sport,
			"up_bytes": e.UpB, "down_bytes": e.DnB, "up_bps": int64(up), "down_bps": int64(dn),
			"v6": e.Family == "ipv6", "ttl": e.TTL,
		}
		if e.State != "" {
			item["state"] = e.State
		}
		if e.Unrepl {
			item["unreplied"] = true
		}
		label := ""
		if n, ok := names[e.Dst]; ok {
			item["name"] = n.Name
			item["name_src"] = n.Src
			label = n.Name
		}
		if a, ok := apps[e.Dst]; ok {
			item["app"] = a.Name
			item["app_id"] = a.ID
			label = a.Name
		}
		if svc := wellKnownSvc(e.Proto, e.Dport); svc != "" {
			item["svc"] = svc
			if label == "" {
				label = svc
			}
		}
		if mine[e.Dst] || isPrivateIP(e.Dst) {
			item["local"] = true
		}
		if label == "" {
			label = "未识别"
		}
		ag := appAgg[label]
		if ag == nil {
			ag = &struct {
				n     int
				b     uint64
				bps   float64
				label string
			}{label: label}
			appAgg[label] = ag
		}
		ag.n++
		ag.b += e.UpB + e.DnB
		ag.bps += up + dn
		totUp += e.UpB
		totDn += e.DnB
		totBps += up + dn
		rows = append(rows, row{item, up + dn, e.UpB + e.DnB})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].score != rows[j].score {
			return rows[i].score > rows[j].score
		}
		return rows[i].total > rows[j].total
	})
	list := make([]map[string]interface{}, 0, len(rows))
	for i, rw := range rows {
		if i >= connListCap {
			break
		}
		list = append(list, rw.m)
	}
	groups := make([]map[string]interface{}, 0, len(appAgg))
	for _, ag := range appAgg {
		groups = append(groups, map[string]interface{}{"label": ag.label, "n": ag.n, "bytes": ag.b, "bps": int64(ag.bps)})
	}
	sort.Slice(groups, func(i, j int) bool {
		bi, bj := groups[i]["bps"].(int64), groups[j]["bps"].(int64)
		if bi != bj {
			return bi > bj
		}
		return groups[i]["bytes"].(uint64) > groups[j]["bytes"].(uint64)
	})
	if len(groups) > 12 {
		groups = groups[:12]
	}
	base["mac"] = mac
	base["ips"] = ips
	base["total"] = len(rows)
	base["conns"] = list
	base["groups"] = groups
	base["up_bytes"] = totUp
	base["down_bytes"] = totDn
	base["bps"] = int64(totBps)
	writeJSON(w, http.StatusOK, base)
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast()
}

// ─── 设备识别(dpid 被动指纹, run/dpi_devid.json)────────────────────────

// dpiIdentByMAC 读 dpid 输出的被动识别结果, 按小写 MAC 索引。只挑前端要的字段,
// 证据列表最多 8 条。文件缺失/损坏 = 空 map。
func (s *server) dpiIdentByMAC() map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "dpi_devid.json"))
	if err != nil {
		return out
	}
	root, _ := raw.(map[string]interface{})
	devs, _ := root["devices"].(map[string]interface{})
	for mac, v := range devs {
		d, _ := v.(map[string]interface{})
		if d == nil {
			continue
		}
		id := map[string]interface{}{}
		for _, k := range []string{"hostname", "hostname_src", "os", "os_ver", "brand", "model", "type",
			"confidence", "vendor_class", "services", "last_seen"} {
			if x, ok := d[k]; ok && x != nil && x != "" {
				id[k] = x
			}
		}
		if ev, ok := d["evidence"].([]interface{}); ok && len(ev) > 0 {
			if len(ev) > 8 {
				ev = ev[:8]
			}
			id["evidence"] = ev
		}
		if len(id) > 0 {
			out[strings.ToLower(strings.TrimSpace(mac))] = id
		}
	}
	return out
}
