// Package capture - devhint.go: v5.13 被动设备识别协议解析。
//
// 覆盖五种热点客户端会主动广播/组播的协议, 只做"忠实提取", 不做语义判断
// (OS/品牌/类型投票在 output/devid.go):
//   - DHCP (v4, UDP 68→67):  BOOTREQUEST 里的 chaddr + opt12/55/60/81
//   - DHCPv6 (UDP 546→547):  客户端→服务器消息里的 opt39 FQDN / opt16 vendor class
//   - mDNS (UDP 5353):       响应/公告里的 A/AAAA owner、TXT model=、PTR/SRV 服务类型
//   - SSDP (UDP 1900):       SERVER: / USER-AGENT: 头
//   - NBNS (UDP 137):        名字注册/刷新请求、名字查询正响应里的 NetBIOS 名
//
// 安全约束: 所有读取前做长度检查, 畸形包返回 ParseMalformed, 绝不 panic
// (devhint_test.go 对每个样例报文做逐字节截断 + 随机翻转的 fuzz 风格测试)。
// Run() 外层虽有 recover 兜底, 但那是最后防线, 不应依赖。

package capture

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	devHintMaxServices = 8
	devHintMaxStr      = 160 // UA / vendor class 等自由文本截断长度
	devHintMaxHostname = 63
	devHintMaxRecords  = 128 // mDNS 单包最多处理的 RR 数(防病态计数)
)

// localMACs 是本机(热点 AP 接口)自己的 MAC, 由 main.go 启动时设置。
// 本机也会发 mDNS/SSDP 公告, 不能把自己识别成一台客户端。
var localMACs atomic.Pointer[map[string]bool]

// SetLocalMACs 安装本机 MAC 表(v5.13)。传 nil 清空。
func SetLocalMACs(macs []net.HardwareAddr) {
	if len(macs) == 0 {
		localMACs.Store(nil)
		return
	}
	m := make(map[string]bool, len(macs))
	for _, mac := range macs {
		if len(mac) == 6 {
			m[mac.String()] = true
		}
	}
	localMACs.Store(&m)
}

// isLocalMAC: 抓包 goroutine(含 self-capture)并发读, 故用 atomic.Pointer 存表。
func isLocalMAC(mac string) bool {
	m := localMACs.Load()
	return m != nil && (*m)[mac]
}

// isDevHintPort 判断 UDP 端口对是否属于设备识别协议(与 bpf.go 的端口表一致,
// 53 除外)。
func isDevHintPort(v6 bool, sport, dport uint16) bool {
	has := func(p uint16) bool { return sport == p || dport == p }
	if v6 {
		return has(546) || has(547) || has(5353)
	}
	return has(67) || has(68) || has(137) || has(1900) || has(5353)
}

// parseDevHint 按端口分派到具体协议解析器。成功返回 EventDevHint;
// 与识别无关的方向/消息类型返回 ParseIgnore; 越界/格式错返回 ParseMalformed。
func parseDevHint(ev Event, udp []byte) (Event, ParseResult) {
	var (
		h   *DevHint
		res ParseResult
	)
	switch {
	case !ev.IsIPv6 && (ev.SrcPort == 67 || ev.SrcPort == 68 || ev.DstPort == 67 || ev.DstPort == 68):
		// 只要客户端→服务器(68→67); 服务器应答(67→68)没有客户端自报信息。
		if ev.SrcPort != 68 || ev.DstPort != 67 {
			return ev, ParseIgnore
		}
		h, res = parseDHCPv4(udp)
	case ev.IsIPv6 && (ev.SrcPort == 546 || ev.SrcPort == 547 || ev.DstPort == 546 || ev.DstPort == 547):
		if ev.SrcPort != 546 || ev.DstPort != 547 {
			return ev, ParseIgnore
		}
		if !hintSrcMACOK(ev) {
			return ev, ParseIgnore
		}
		h, res = parseDHCPv6(udp)
		if h != nil {
			h.MAC = ev.SrcMAC.String()
		}
	case ev.SrcPort == 5353 || ev.DstPort == 5353:
		if !hintSrcMACOK(ev) || !hintSrcIPOK(ev) {
			return ev, ParseIgnore
		}
		h, res = parseMDNS(udp)
		if h != nil {
			h.MAC = ev.SrcMAC.String()
		}
	case !ev.IsIPv6 && (ev.SrcPort == 1900 || ev.DstPort == 1900):
		if !hintSrcMACOK(ev) || !hintSrcIPOK(ev) {
			return ev, ParseIgnore
		}
		h, res = parseSSDP(udp)
		if h != nil {
			h.MAC = ev.SrcMAC.String()
		}
	case !ev.IsIPv6 && (ev.SrcPort == 137 || ev.DstPort == 137):
		if !hintSrcMACOK(ev) || !hintSrcIPOK(ev) {
			return ev, ParseIgnore
		}
		h, res = parseNBNS(udp)
		if h != nil {
			h.MAC = ev.SrcMAC.String()
		}
	default:
		return ev, ParseIgnore
	}
	if res != ParseOK || h == nil {
		return ev, res
	}
	if h.MAC == "" || isLocalMAC(h.MAC) {
		return ev, ParseIgnore
	}
	ev.Kind = EventDevHint
	ev.Dev = h
	// ClientMAC 仅供 debug 日志; 其余 Client*/Remote* 字段有意留空。
	if mac, err := net.ParseMAC(h.MAC); err == nil {
		ev.ClientMAC = mac
	}
	return ev, ParseOK
}

// hintSrcMACOK: 以太网源 MAC 必须是 6 字节单播、非全零、非本机。
// RawIP/tun 链路没有 MAC, 直接不做设备识别。
func hintSrcMACOK(ev Event) bool {
	mac := ev.SrcMAC
	if len(mac) != 6 {
		return false
	}
	if mac[0]&0x01 != 0 { // 组播/广播源 MAC 不合法
		return false
	}
	zero := true
	for _, b := range mac {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		return false
	}
	return !isLocalMAC(mac.String())
}

// hintSrcIPOK: IPv4 且配置了热点网段时, 源 IP 必须在热点网段内(即确实来自
// 热点客户端, 而不是上游网络经桥接漏进来的组播)。IPv6 mDNS 源通常是
// fe80:: 链路本地地址, 不在热点前缀里, 只靠 MAC 判断。
func hintSrcIPOK(ev Event) bool {
	if ev.IsIPv6 || len(hotspotNets) == 0 {
		return true
	}
	return ipInHotspot(ev.SrcIP)
}

// ─── DHCPv4 ────────────────────────────────────────────────────────────

const dhcpMagic = 0x63825363

func parseDHCPv4(b []byte) (*DevHint, ParseResult) {
	// BOOTP 固定头 236 字节 + magic cookie 4 字节。
	if len(b) < 240 {
		return nil, ParseMalformed
	}
	if b[0] != 1 { // op: 只要 BOOTREQUEST
		return nil, ParseIgnore
	}
	if binary.BigEndian.Uint32(b[236:240]) != dhcpMagic {
		return nil, ParseMalformed
	}
	htype, hlen := b[1], b[2]
	if htype != 1 || hlen != 6 {
		return nil, ParseIgnore // 非以太网硬件地址, 无法关联到 MAC
	}
	chaddr := net.HardwareAddr(b[28:34])
	if chaddr[0]&0x01 != 0 {
		return nil, ParseMalformed
	}

	h := &DevHint{Source: "dhcp", MAC: chaddr.String()}
	var msgType byte
	var fqdn string
	opts := b[240:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == 0 { // pad
			i++
			continue
		}
		if code == 255 { // end
			break
		}
		if i+1 >= len(opts) {
			return nil, ParseMalformed
		}
		l := int(opts[i+1])
		if i+2+l > len(opts) {
			return nil, ParseMalformed
		}
		v := opts[i+2 : i+2+l]
		i += 2 + l
		switch code {
		case 53:
			if l != 1 {
				return nil, ParseMalformed
			}
			msgType = v[0]
		case 12:
			h.Hostname = cleanHostname(string(v))
		case 60:
			h.VendorClass = cleanText(string(v), devHintMaxStr)
		case 55:
			var sb strings.Builder
			for j, p := range v {
				if j > 0 {
					sb.WriteByte(',')
				}
				sb.WriteString(strconv.Itoa(int(p)))
			}
			h.ParamList = sb.String()
		case 81:
			// Client FQDN: flags(1) rcode1(1) rcode2(1) + name。flags 的 E 位
			// (0x04) 表示 DNS wire 编码, 否则是 ASCII(已废弃但仍有设备用)。
			if l >= 3 {
				if v[0]&0x04 != 0 {
					fqdn = readWireNameLoose(v[3:])
				} else {
					fqdn = string(v[3:])
				}
			}
		}
	}
	// 只处理 DISCOVER(1) / REQUEST(3); 其余(RELEASE/INFORM/...)忽略。
	if msgType != 1 && msgType != 3 {
		return nil, ParseIgnore
	}
	if h.Hostname == "" && fqdn != "" {
		h.Hostname = cleanHostname(firstLabel(fqdn))
	}
	return h, ParseOK
}

// ─── DHCPv6 ────────────────────────────────────────────────────────────

func parseDHCPv6(b []byte) (*DevHint, ParseResult) {
	if len(b) < 4 {
		return nil, ParseMalformed
	}
	switch b[0] {
	case 1, 3, 4, 5, 6, 8, 9, 11:
		// SOLICIT / REQUEST / CONFIRM / RENEW / REBIND / RELEASE / DECLINE /
		// INFORMATION-REQUEST —— 客户端→服务器消息。
	default:
		return nil, ParseIgnore
	}
	h := &DevHint{Source: "dhcpv6"}
	opts := b[4:]
	for len(opts) > 0 {
		if len(opts) < 4 {
			return nil, ParseMalformed
		}
		code := binary.BigEndian.Uint16(opts[0:2])
		l := int(binary.BigEndian.Uint16(opts[2:4]))
		if 4+l > len(opts) {
			return nil, ParseMalformed
		}
		v := opts[4 : 4+l]
		opts = opts[4+l:]
		switch code {
		case 39: // Client FQDN: flags(1) + DNS wire 名(可为不带根的部分名)
			if l >= 2 {
				h.Hostname = cleanHostname(firstLabel(readWireNameLoose(v[1:])))
			}
		case 16: // Vendor Class: enterprise-number(4) + n × (len(2) + data)
			if l < 4 {
				return nil, ParseMalformed
			}
			d := v[4:]
			var parts []string
			for len(d) > 0 {
				if len(d) < 2 {
					return nil, ParseMalformed
				}
				dl := int(binary.BigEndian.Uint16(d[0:2]))
				if 2+dl > len(d) {
					return nil, ParseMalformed
				}
				if s := cleanText(string(d[2:2+dl]), devHintMaxStr); s != "" {
					parts = append(parts, s)
				}
				d = d[2+dl:]
			}
			h.VendorClass = cleanText(strings.Join(parts, " "), devHintMaxStr)
		}
	}
	if h.Hostname == "" && h.VendorClass == "" {
		return nil, ParseIgnore
	}
	return h, ParseOK
}

// readWireNameLoose 读 DNS wire 格式的名字, 允许缺少结尾 0(RFC 4704 部分名)。
// 不支持压缩指针(FQDN 选项里不允许); 遇到非法标签长度就截止返回已读部分。
func readWireNameLoose(b []byte) string {
	var labels []string
	for i := 0; i < len(b) && len(labels) < 16; {
		l := int(b[i])
		if l == 0 || l > 63 || i+1+l > len(b) {
			break
		}
		labels = append(labels, string(b[i+1:i+1+l]))
		i += 1 + l
	}
	return strings.Join(labels, ".")
}

// ─── mDNS ──────────────────────────────────────────────────────────────

func parseMDNS(b []byte) (*DevHint, ParseResult) {
	if len(b) < 12 {
		return nil, ParseMalformed
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	if flags&0x8000 == 0 {
		// 查询包里的问题名是"它在找谁", 不是它自己, 忽略。
		return nil, ParseIgnore
	}
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	rr := int(binary.BigEndian.Uint16(b[6:8])) + int(binary.BigEndian.Uint16(b[8:10])) + int(binary.BigEndian.Uint16(b[10:12]))
	if qd+rr > devHintMaxRecords {
		return nil, ParseMalformed
	}
	p := 12
	for i := 0; i < qd; i++ {
		_, np, ok := dnsReadName(b, p)
		if !ok || np+4 > len(b) {
			return nil, ParseMalformed
		}
		p = np + 4
	}

	h := &DevHint{Source: "mdns"}
	var ptrHost string // 反向 PTR / SRV target 给出的主机名(优先级低于 A/AAAA owner)
	for i := 0; i < rr; i++ {
		owner, np, ok := dnsReadName(b, p)
		if !ok || np+10 > len(b) {
			return nil, ParseMalformed
		}
		p = np
		rtype := binary.BigEndian.Uint16(b[p : p+2])
		rdlen := int(binary.BigEndian.Uint16(b[p+8 : p+10]))
		p += 10
		if p+rdlen > len(b) {
			return nil, ParseMalformed
		}
		rdStart, rdEnd := p, p+rdlen
		p = rdEnd
		lowOwner := strings.ToLower(owner)

		switch rtype {
		case 1, 28: // A / AAAA: owner 即主机名 xxx.local
			if hn := localHostname(owner); hn != "" && h.Hostname == "" {
				h.Hostname = hn
			}
		case 12: // PTR
			target, _, ok := dnsReadName(b, rdStart)
			if !ok {
				return nil, ParseMalformed
			}
			switch {
			case lowOwner == "_services._dns-sd._udp.local":
				addService(h, mdnsServiceType(target))
			case strings.HasSuffix(lowOwner, ".arpa"):
				if hn := localHostname(target); hn != "" && ptrHost == "" {
					ptrHost = hn
				}
			default:
				addService(h, mdnsServiceType(owner))
			}
		case 33: // SRV: priority(2) weight(2) port(2) target
			if rdlen < 7 {
				return nil, ParseMalformed
			}
			addService(h, mdnsServiceType(owner))
			target, _, ok := dnsReadName(b, rdStart+6)
			if !ok {
				return nil, ParseMalformed
			}
			if hn := localHostname(target); hn != "" && ptrHost == "" {
				ptrHost = hn
			}
		case 16: // TXT: n × (len(1) + "key=value")
			addService(h, mdnsServiceType(owner))
			d := b[rdStart:rdEnd]
			for len(d) > 0 {
				l := int(d[0])
				if 1+l > len(d) {
					return nil, ParseMalformed
				}
				kv := string(d[1 : 1+l])
				d = d[1+l:]
				eq := strings.IndexByte(kv, '=')
				if eq <= 0 {
					continue
				}
				key := strings.ToLower(kv[:eq])
				val := cleanText(kv[eq+1:], 64)
				if val == "" {
					continue
				}
				switch key {
				case "model", "md", "am":
					if h.Model == "" {
						h.Model = val
					}
				case "osxvers":
					h.OSHint = "macOS"
				}
			}
		}
	}
	if h.Hostname == "" {
		h.Hostname = ptrHost
	}
	if h.Hostname == "" && h.Model == "" && len(h.Services) == 0 && h.OSHint == "" {
		return nil, ParseIgnore
	}
	return h, ParseOK
}

// localHostname: "MacBook-Pro.local" → "MacBook-Pro"; 非 .local 名返回空。
func localHostname(name string) string {
	low := strings.ToLower(name)
	if !strings.HasSuffix(low, ".local") {
		return ""
	}
	base := name[:len(name)-len(".local")]
	// 服务实例名(含 "._tcp" 等)不是主机名。
	if strings.Contains(base, "._") || strings.HasPrefix(base, "_") {
		return ""
	}
	return cleanHostname(firstLabel(base))
}

// mdnsServiceType 从 "Living Room._googlecast._tcp.local" 之类的名字里取出
// "_googlecast._tcp"; 取不到返回空。子类型("_printer._sub._http._tcp")取
// 紧贴 _tcp/_udp 前的那个标签。
func mdnsServiceType(name string) string {
	labels := strings.Split(strings.ToLower(name), ".")
	for i := 1; i < len(labels); i++ {
		if labels[i] != "_tcp" && labels[i] != "_udp" {
			continue
		}
		svc := labels[i-1]
		if len(svc) < 2 || svc[0] != '_' || svc == "_dns-sd" || svc == "_services" || len(svc) > 40 {
			return ""
		}
		for _, r := range svc[1:] {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
				return ""
			}
		}
		return svc + "." + labels[i]
	}
	return ""
}

func addService(h *DevHint, svc string) {
	if svc == "" || len(h.Services) >= devHintMaxServices {
		return
	}
	for _, s := range h.Services {
		if s == svc {
			return
		}
	}
	h.Services = append(h.Services, svc)
}

// ─── SSDP ──────────────────────────────────────────────────────────────

func parseSSDP(b []byte) (*DevHint, ParseResult) {
	if len(b) < 8 {
		return nil, ParseMalformed
	}
	if len(b) > 4096 {
		b = b[:4096]
	}
	s := string(b)
	lineEnd := strings.IndexByte(s, '\n')
	if lineEnd < 0 {
		return nil, ParseMalformed
	}
	first := strings.ToUpper(strings.TrimSpace(s[:lineEnd]))
	if !strings.HasPrefix(first, "NOTIFY ") && !strings.HasPrefix(first, "M-SEARCH ") && !strings.HasPrefix(first, "HTTP/1.") {
		return nil, ParseMalformed
	}
	h := &DevHint{Source: "ssdp"}
	var server, ua string
	for _, line := range strings.Split(s[lineEnd+1:], "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break // 头结束
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(line[:colon]))
		val := cleanText(line[colon+1:], devHintMaxStr)
		switch key {
		case "SERVER":
			server = val
		case "USER-AGENT":
			ua = val
		}
	}
	// SERVER 优先(设备自报), 其次 USER-AGENT(M-SEARCH 发起方)。
	h.UserAgent = server
	if h.UserAgent == "" {
		h.UserAgent = ua
	}
	if h.UserAgent == "" {
		return nil, ParseIgnore
	}
	return h, ParseOK
}

// ─── NBNS ──────────────────────────────────────────────────────────────

func parseNBNS(b []byte) (*DevHint, ParseResult) {
	if len(b) < 12 {
		return nil, ParseMalformed
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	isResp := flags&0x8000 != 0
	opcode := (flags >> 11) & 0x0f
	qd := binary.BigEndian.Uint16(b[4:6])
	an := binary.BigEndian.Uint16(b[6:8])
	ar := binary.BigEndian.Uint16(b[10:12])

	// 只取"名字属于发送方"的两类报文:
	//   - 请求: 名字注册(5) / 刷新(8, 9), 问题名 = 自己要注册的名, 附加记录带 NB_FLAGS
	//   - 响应: 查询(0)正响应, 应答记录的 owner = 回答者自己的名
	// 普通查询请求(opcode 0, QR=0)问的是别人的名字, 故意不取。
	var needRR bool
	switch {
	case !isResp && (opcode == 5 || opcode == 8 || opcode == 9) && qd == 1 && ar >= 1:
		needRR = false
	case isResp && opcode == 0 && qd == 0 && an >= 1:
		needRR = true
	default:
		return nil, ParseIgnore
	}

	raw, np, ok := dnsReadName(b, 12)
	if !ok {
		return nil, ParseMalformed
	}
	enc := raw
	if dot := strings.IndexByte(enc, '.'); dot >= 0 {
		enc = enc[:dot] // 去掉 NetBIOS scope
	}
	name, suffix, ok := decodeNetBIOSName(enc)
	if !ok {
		return nil, ParseMalformed
	}
	p := np
	if !needRR {
		// 跳过问题的 type(2) + class(2), 然后读附加记录的名字(通常是指针)。
		if p+4 > len(b) {
			return nil, ParseMalformed
		}
		_, np2, ok := dnsReadName(b, p+4)
		if !ok {
			return nil, ParseMalformed
		}
		p = np2
	}
	// RR: type(2) class(2) ttl(4) rdlen(2) rdata(NB_FLAGS(2) + IPv4(4) ...)
	if p+10 > len(b) {
		return nil, ParseMalformed
	}
	rdlen := int(binary.BigEndian.Uint16(b[p+8 : p+10]))
	if rdlen < 2 || p+10+rdlen > len(b) {
		return nil, ParseMalformed
	}
	nbFlags := binary.BigEndian.Uint16(b[p+10 : p+12])
	if nbFlags&0x8000 != 0 {
		return nil, ParseIgnore // G 位 = 组名(如 WORKGROUP), 不是主机名
	}
	// 后缀 0x00 = 工作站服务, 0x20 = 文件服务器服务; 其余(域控/浏览器等)不是主机名。
	if suffix != 0x00 && suffix != 0x20 {
		return nil, ParseIgnore
	}
	hn := cleanHostname(name)
	if hn == "" {
		return nil, ParseIgnore
	}
	return &DevHint{Source: "nbns", Hostname: hn}, ParseOK
}

// decodeNetBIOSName 解 RFC 1001 一级编码: 32 个 'A'..'P' 字符 → 16 字节,
// 前 15 字节为名字(右侧空格填充), 第 16 字节为后缀类型。
func decodeNetBIOSName(enc string) (string, byte, bool) {
	if len(enc) != 32 {
		return "", 0, false
	}
	var out [16]byte
	for i := 0; i < 16; i++ {
		hi, lo := enc[2*i], enc[2*i+1]
		if hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P' {
			return "", 0, false
		}
		out[i] = (hi-'A')<<4 | (lo - 'A')
	}
	name := strings.TrimRight(string(out[:15]), " \x00")
	if name == "" || name[0] == 0x01 || name[0] == '*' {
		return "", 0, false
	}
	return name, out[15], true
}

// ─── 文本清洗 ──────────────────────────────────────────────────────────

// cleanText 去掉控制字符和首尾空白, 截断到 max 字节(按 rune 边界)。
func cleanText(s string, max int) string {
	var sb strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			continue
		}
		if sb.Len()+len(string(r)) > max {
			break
		}
		sb.WriteRune(r)
	}
	return strings.TrimSpace(sb.String())
}

// cleanHostname: 主机名只保留可打印字符, 最长 63 字节。
func cleanHostname(s string) string {
	return cleanText(strings.TrimSuffix(strings.TrimSpace(s), "."), devHintMaxHostname)
}

func firstLabel(s string) string {
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return s[:i]
	}
	return s
}
