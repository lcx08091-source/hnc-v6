// Package capture - parse.go: packet parser.
//
// rc20.1 parsed IPv4 only and emitted only EventDNS and EventTLSClientHello.
// rc29 adds:
//   - IPv6 parsing (etherType 0x86dd)
//   - EventFlow for non-DNS/non-TLS TCP/UDP packets (carries 5-tuple+payload size)
//   - JA4 fingerprint computed inline for every TLS ClientHello

package capture

import (
	"encoding/binary"
	"net"
	"strings"
	"time"

	"hnc.io/dpid/output"
)

type EventKind int

const (
	EventUnknown EventKind = iota
	EventDNS
	EventTLSClientHello
	EventFlow
	// v5.13: 被动设备识别线索(DHCP/DHCPv6/mDNS/SSDP/NBNS)。这些包多为
	// 广播/组播, 不走 assignClient, 调用方也不得把它们喂给 RecordFlow /
	// clientLocked —— 客户端身份只取 DevHint.MAC。
	EventDevHint
	// v5.18: 明文 HTTP 请求(TCP/80)的 Host 头。复用 Event.TLS: SNI = Host,
	// UserAgent = User-Agent, 其余为空。
	EventHTTP
)

// DevHint 是一条被动设备识别线索(v5.13)。字段按协议能提供的尽量填,
// 语义解释(OS/品牌/类型投票)在 output/devid.go 完成, 这里只做忠实提取。
type DevHint struct {
	MAC         string   // 小写冒号格式; DHCP 取 chaddr, 其余取以太网源 MAC
	Source      string   // "dhcp" / "dhcpv6" / "mdns" / "ssdp" / "nbns"
	Hostname    string   // DHCP opt12/opt81、DHCPv6 opt39 首标签、mDNS xxx.local、NBNS 名
	VendorClass string   // DHCP opt60 / DHCPv6 opt16
	ParamList   string   // DHCP opt55 十进制逗号串, 如 "1,3,6,15"
	Model       string   // mDNS TXT model= / md= / am=
	OSHint      string   // 协议自带的 OS 线索(如 mDNS osxvers → "macOS")
	UserAgent   string   // SSDP SERVER: / USER-AGENT:
	Services    []string // mDNS 服务类型, 如 "_airplay._tcp"(去重, 最多 8 个)
}

type DNSInfo struct {
	IsResponse bool
	QName      string
	QType      uint16
	// Answers: A/AAAA 的 IP 字符串与 "CNAME:目标名"(旧格式, 保持兼容)。
	Answers []string
	// v5.18: 带 owner 名 / 类型 / 各自 TTL 的应答记录(含 CNAME 与 HTTPS/SVCB
	// 地址提示), 供 IP→域名表跟随 CNAME 链。最多 dnsMaxRecords 条。
	Records []output.DNSAnswer
	// TTL: 地址记录中的最小 TTL(没有地址记录时为 0)。
	TTL uint32
}

type TLSInfo struct {
	SNI  string
	ALPN []string
	JA4  string // rc29: pre-computed JA4 fingerprint
	// v5.14: 来自 QUIC(HTTP/3) Initial / gQUIC CHLO。此时 Event.IsUDP=true,
	// JA4 首字符为 'q'(gQUIC 没有 TLS ClientHello, JA4 为空)。
	IsQUIC bool
	// v5.14: gQUIC CHLO 的 UAID 标签(客户端 User-Agent), 仅 gQUIC 填。
	// v5.18: EventHTTP 时为 HTTP User-Agent 头。
	UserAgent string
	// v5.18: ClientHello 带 ECH / ESNI 扩展(可能是 GREASE, 仅作提示)。
	ECH bool
	// v5.18: SNI 取自被截断/未收全的 ClientHello(无 JA4)。
	Partial bool
	// v5.18: ClientHello 由多个 TCP 段重组而来。
	Reassembled bool
	// v5.27 T2: QUIC 传输参数指纹(output.QUICTPFingerprint), 只在 QUIC 路径填。
	QTP string
}

type Event struct {
	Kind    EventKind
	Time    time.Time
	SrcMAC  net.HardwareAddr
	DstMAC  net.HardwareAddr
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	IsUDP   bool
	IsIPv6  bool // rc29
	Bytes   int  // rc29: full IP packet length (for flow byte accounting)

	// Direction-aware fields.
	ClientMAC net.HardwareAddr
	ClientIP  net.IP
	RemoteMAC net.HardwareAddr
	RemoteIP  net.IP

	DNS DNSInfo
	TLS TLSInfo
	// v5.13: 仅 Kind == EventDevHint 时非 nil。用指针避免每包 Event 值拷贝变大。
	Dev *DevHint

	// v5.18: IP 头声明的长度超过实际抓到的字节(被 snaplen 截断)。
	capTrunc bool
	// v5.29: 本包是握手的前段, 已挂进重组表等后续段(TCP ClientHello 首段 /
	// QUIC Initial 未凑齐)。只给流量录制用(recorder.go): 这类包本身不产出
	// 事件, 不录的话回放拼不出分段的 ClientHello。
	asmPending bool
}

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	ipProtoTCP    = 6
	ipProtoUDP    = 17
)

type ParseResult int

const (
	ParseOK ParseResult = iota
	ParseIgnore
	ParseMalformed
)

// parsePacket returns event metadata and a result code.
//
// Assumes Ethernet link layer (14-byte ether header at start). For
// link types without Ethernet headers (ARPHRD_RAWIP=519 on Qualcomm
// cellular, ARPHRD_NONE=65534 on tun VPN), use parseRawIPPacket instead.
func parsePacket(b []byte, ts time.Time) (Event, ParseResult) {
	if len(b) < 14 {
		return Event{}, ParseMalformed
	}
	etherType := binary.BigEndian.Uint16(b[12:14])
	dstMAC := append(net.HardwareAddr(nil), b[0:6]...)
	srcMAC := append(net.HardwareAddr(nil), b[6:12]...)

	switch etherType {
	case etherTypeIPv4:
		return parseIPv4(b[14:], dstMAC, srcMAC, ts)
	case etherTypeIPv6:
		return parseIPv6(b[14:], dstMAC, srcMAC, ts)
	default:
		return Event{}, ParseIgnore
	}
}

// parseRawIPPacket parses a packet that has no Ethernet header. This is
// the case for link types ARPHRD_RAWIP=519 (Qualcomm rmnet on cellular)
// and ARPHRD_NONE=65534 (tun device used by VPN apps like Clash,
// WireGuard, Tailscale). The first byte's high nibble distinguishes
// IPv4 (4) from IPv6 (6).
//
// We pass empty MACs to the downstream parsers — there is no L2 identity
// on these links. For self-attribution this is fine: callers use the IP
// 5-tuple + /proc/net to look up uid, not MAC.
func parseRawIPPacket(b []byte, ts time.Time) (Event, ParseResult) {
	if len(b) < 1 {
		return Event{}, ParseMalformed
	}
	var emptyMAC net.HardwareAddr
	switch b[0] >> 4 {
	case 4:
		return parseIPv4(b, emptyMAC, emptyMAC, ts)
	case 6:
		return parseIPv6(b, emptyMAC, emptyMAC, ts)
	default:
		// Not an IPv4 or IPv6 packet — could be a tunneled non-IP
		// protocol (rare). Drop silently.
		return Event{}, ParseIgnore
	}
}

// parseIPv4 handles an IPv4 packet (no Ethernet header).
func parseIPv4(ip []byte, dstMAC, srcMAC net.HardwareAddr, ts time.Time) (Event, ParseResult) {
	if len(ip) < 20 {
		return Event{}, ParseMalformed
	}
	if ip[0]>>4 != 4 {
		return Event{}, ParseMalformed
	}
	ipHL := int(ip[0]&0x0f) * 4
	if ipHL < 20 || len(ip) < ipHL {
		return Event{}, ParseMalformed
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen == 0 || totalLen > len(ip) {
		totalLen = len(ip)
	}
	if totalLen < ipHL {
		return Event{}, ParseMalformed
	}
	proto := ip[9]
	srcIP := net.IPv4(ip[12], ip[13], ip[14], ip[15])
	dstIP := net.IPv4(ip[16], ip[17], ip[18], ip[19])
	payload := ip[ipHL:totalLen]

	ev := Event{
		Time: ts, SrcMAC: srcMAC, DstMAC: dstMAC,
		SrcIP: srcIP, DstIP: dstIP, Bytes: totalLen,
		capTrunc: int(binary.BigEndian.Uint16(ip[2:4])) > len(ip),
	}
	return parseL4(ev, proto, payload)
}

// parseIPv6 handles an IPv6 packet (no Ethernet header).
// Skips well-known extension headers to find the L4 payload.
func parseIPv6(ip []byte, dstMAC, srcMAC net.HardwareAddr, ts time.Time) (Event, ParseResult) {
	if len(ip) < 40 {
		return Event{}, ParseMalformed
	}
	if ip[0]>>4 != 6 {
		return Event{}, ParseMalformed
	}
	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	nextHdr := ip[6]
	srcIP := make(net.IP, 16)
	copy(srcIP, ip[8:24])
	dstIP := make(net.IP, 16)
	copy(dstIP, ip[24:40])

	totalLen := 40 + payloadLen
	capTrunc := totalLen > len(ip)
	if capTrunc {
		totalLen = len(ip)
	}
	payload := ip[40:totalLen]

	// Skip extension headers: hop-by-hop (0), routing (43), dest opts (60),
	// fragment (44). Cap at 4 to avoid pathological loops.
	for skipped := 0; skipped < 4; skipped++ {
		switch nextHdr {
		case 0, 43, 60:
			if len(payload) < 2 {
				return Event{}, ParseMalformed
			}
			extLen := (int(payload[1]) + 1) * 8
			if len(payload) < extLen {
				return Event{}, ParseMalformed
			}
			nextHdr = payload[0]
			payload = payload[extLen:]
		case 44:
			if len(payload) < 8 {
				return Event{}, ParseMalformed
			}
			fragOffset := binary.BigEndian.Uint16(payload[2:4]) & 0xfff8
			if fragOffset != 0 {
				return Event{}, ParseIgnore
			}
			nextHdr = payload[0]
			payload = payload[8:]
		default:
			goto done
		}
	}
	// v5.9.6 (回移自 5.9.91 分叉): 扩展头循环走满仍是指示扩展类型的 nextHdr
	// (0/43/44/60 = Hop-by-Hop/Routing/Fragment/Destination) —— 病态包,
	// 跳过而非带着错误的上层协议号继续解析。
	switch nextHdr {
	case 0, 43, 44, 60:
		return Event{}, ParseIgnore // too many extension headers
	}
done:

	ev := Event{
		Time: ts, SrcMAC: srcMAC, DstMAC: dstMAC,
		SrcIP: srcIP, DstIP: dstIP, IsIPv6: true, Bytes: totalLen,
		capTrunc: capTrunc,
	}
	return parseL4(ev, nextHdr, payload)
}

// parseL4 handles UDP/TCP after the L3 header has been stripped.
func parseL4(ev Event, proto byte, payload []byte) (Event, ParseResult) {
	switch proto {
	case ipProtoUDP:
		if len(payload) < 8 {
			return ev, ParseMalformed
		}
		ev.IsUDP = true
		ev.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		ev.DstPort = binary.BigEndian.Uint16(payload[2:4])

		// DNS over UDP.
		if ev.SrcPort == 53 || ev.DstPort == 53 {
			dnsPayload := payload[8:]
			if d, ok := parseDNS(dnsPayload); ok {
				ev.Kind = EventDNS
				ev.DNS = d
				assignClient(&ev, d.IsResponse)
				return ev, ParseOK
			}
			return ev, ParseMalformed
		}

		// v5.13: 设备识别协议(DHCP/DHCPv6/mDNS/SSDP/NBNS)。无论解析成败都
		// 在这里返回, 绝不落到下面的 EventFlow —— 这些包大多是广播/组播,
		// 进 Flow 会把 255.255.255.255 / ff02::fb 之类当成"客户端"。
		if isDevHintPort(ev.IsIPv6, ev.SrcPort, ev.DstPort) {
			return parseDevHint(ev, payload[8:])
		}

		// v5.14: QUIC 客户端 long header(目的 443)。只在拿到完整 ClientHello
		// 时产出 EventTLSClientHello, 其余 ParseIgnore —— 不落到 EventFlow,
		// 与以前 BPF 不放行 UDP/443 时的字节统计口径一致。
		if ev.DstPort == 443 && len(payload) > 8 && payload[8]&0x80 != 0 {
			return parseQUIC(ev, payload[8:])
		}

		// Other UDP -> emit as Flow event (rc29).
		ev.Kind = EventFlow
		assignClient(&ev, false)
		return ev, ParseOK

	case ipProtoTCP:
		if len(payload) < 20 {
			return ev, ParseMalformed
		}
		ev.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		ev.DstPort = binary.BigEndian.Uint16(payload[2:4])
		tcpHL := int(payload[12]>>4) * 4
		if tcpHL < 20 || len(payload) < tcpHL {
			return ev, ParseMalformed
		}
		tcpData := payload[tcpHL:]
		seq := binary.BigEndian.Uint32(payload[4:8])

		// DNS over TCP(2 字节长度前缀)。SYN/ACK 等空段、以及长应答的续段
		// 不是错误, 计 ParseIgnore。
		if ev.DstPort == 53 || ev.SrcPort == 53 {
			if len(tcpData) == 0 {
				return ev, ParseIgnore
			}
			if d, ok := parseDNSTCP(tcpData); ok {
				ev.Kind = EventDNS
				ev.DNS = d
				assignClient(&ev, d.IsResponse)
				return ev, ParseOK
			}
			return ev, ParseIgnore
		}

		// v5.18: 客户端 → 443 的 ClientHello(含跨段重组 / 截断容错)。
		if ev.DstPort == 443 && len(tcpData) > 0 {
			if info, ok := tlsAsm.handleSegment(&ev, seq, tcpData, ev.Time); ok {
				ev.Kind = EventTLSClientHello
				ev.TLS = info
				assignClient(&ev, false)
				return ev, ParseOK
			}
			if tcpData[0] != 0x16 {
				// BPF 只为"可能是 ClientHello 末段"的包放行非 0x16 段; 没接上
				// 重组的直接忽略, 不计入 Flow(与以前 BPF 丢弃它们时口径一致)。
				return ev, ParseIgnore
			}
		}

		// v5.18: 明文 HTTP 请求的 Host 头(BPF 只放行 TCP/80 且载荷以常见
		// 方法开头的包)。
		if ev.DstPort == 80 {
			if host, ua, ok := parseHTTPRequestHost(tcpData); ok {
				ev.Kind = EventHTTP
				ev.TLS = TLSInfo{SNI: host, UserAgent: ua}
				assignClient(&ev, false)
				return ev, ParseOK
			}
			return ev, ParseIgnore
		}

		// Anything else TCP (e.g. server→client 0x16 handshake) -> Flow event (rc29).
		ev.Kind = EventFlow
		assignClient(&ev, false)
		return ev, ParseOK
	}

	return ev, ParseIgnore
}

// hotspotNets is set by SetHotspotNets at startup. When non-empty, assignClient
// uses it as the authoritative direction signal: whichever endpoint sits
// inside one of these nets is the hotspot client.
//
// rc20.1 -> rc28.1.1 had a latent bug where EventFlow's reverse-direction
// packets (server -> client) were attributed with the SERVER side as
// ClientIP, polluting the clients map with one fake "client" per remote
// server IP. The fix is direction-by-membership: if RemoteIP is in
// hotspotNets, swap so SrcIP/DstIP refer to client.
var hotspotNets []*net.IPNet

// SetHotspotNets installs the hotspot's IP membership table. Caller passes
// every IPv4 subnet and every IPv6 prefix configured on the AP interface.
// Pass nil to disable direction inference (rc20.1 fallback).
func SetHotspotNets(nets []*net.IPNet) {
	hotspotNets = nets
}

// ipInHotspot reports whether ip is in any configured hotspot net.
// Returns false if hotspotNets is nil (rc20.1 fallback, accept whatever
// the caller decided).
func ipInHotspot(ip net.IP) bool {
	for _, n := range hotspotNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// assignClient fills client/remote direction fields.
//
// rc29 priority order:
//  1. hotspotNets membership (most reliable) — whichever side is in the
//     hotspot's own IP range is the client.
//  2. isResponseToClient flag (DNS responses, where the L7 payload tells
//     us the direction unambiguously).
//  3. Fallback: SrcIP is the client (rc20.1 behaviour; works for outbound
//     flows from client but mislabels reverse-direction packets).
func assignClient(ev *Event, isResponseToClient bool) {
	if len(hotspotNets) > 0 {
		srcInHS := ipInHotspot(ev.SrcIP)
		dstInHS := ipInHotspot(ev.DstIP)
		switch {
		case srcInHS && !dstInHS:
			// src is the client (uplink).
			ev.ClientMAC = ev.SrcMAC
			ev.ClientIP = ev.SrcIP
			ev.RemoteMAC = ev.DstMAC
			ev.RemoteIP = ev.DstIP
			return
		case dstInHS && !srcInHS:
			// dst is the client (downlink/reverse).
			ev.ClientMAC = ev.DstMAC
			ev.ClientIP = ev.DstIP
			ev.RemoteMAC = ev.SrcMAC
			ev.RemoteIP = ev.SrcIP
			return
		}
		// If both or neither are in hotspot range, fall through to old
		// heuristics. This handles edge cases like client-to-client
		// (no good answer, pick by L7 hint), broadcast/multicast (we'll
		// drop later), or pre-DHCP traffic.
	}

	if isResponseToClient {
		ev.ClientMAC = ev.DstMAC
		ev.ClientIP = ev.DstIP
		ev.RemoteMAC = ev.SrcMAC
		ev.RemoteIP = ev.SrcIP
	} else {
		ev.ClientMAC = ev.SrcMAC
		ev.ClientIP = ev.SrcIP
		ev.RemoteMAC = ev.DstMAC
		ev.RemoteIP = ev.DstIP
	}
}

// dnsMaxRecords 限制单条 DNS 消息解析的记录数(防恶意包放大 CPU/内存)。
const dnsMaxRecords = 64

func parseDNS(b []byte) (DNSInfo, bool) {
	if len(b) < 12 {
		return DNSInfo{}, false
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	qdcount := binary.BigEndian.Uint16(b[4:6])
	ancount := binary.BigEndian.Uint16(b[6:8])
	if qdcount != 1 {
		return DNSInfo{}, false
	}
	out := DNSInfo{IsResponse: flags&0x8000 != 0}

	p := 12
	qname, np, ok := dnsReadName(b, p)
	if !ok {
		return DNSInfo{}, false
	}
	p = np
	if len(b) < p+4 {
		return DNSInfo{}, false
	}
	out.QName = strings.ToLower(qname)
	out.QType = binary.BigEndian.Uint16(b[p : p+2])
	p += 4

	if !out.IsResponse {
		return out, true
	}

	// 应答可能被 snaplen 截断: 能解析多少算多少, 遇到截断就停。
	var minTTL uint32
	haveTTL := false
	addr := func(owner string, typ uint16, ttl uint32, ip net.IP) {
		if len(out.Records) >= dnsMaxRecords {
			return
		}
		s := ip.String()
		if typ == 1 || typ == 28 {
			out.Answers = append(out.Answers, s)
		}
		out.Records = append(out.Records, output.DNSAnswer{Name: owner, Type: typ, TTL: ttl, Value: s})
		if !haveTTL || ttl < minTTL {
			minTTL, haveTTL = ttl, true
		}
	}
	n := int(ancount)
	if n > dnsMaxRecords {
		n = dnsMaxRecords
	}
	for i := 0; i < n; i++ {
		owner, np, ok := dnsReadName(b, p)
		if !ok {
			break
		}
		p = np
		if len(b) < p+10 {
			break
		}
		atype := binary.BigEndian.Uint16(b[p : p+2])
		ttl := binary.BigEndian.Uint32(b[p+4 : p+8])
		rdlen := int(binary.BigEndian.Uint16(b[p+8 : p+10]))
		p += 10
		if len(b) < p+rdlen {
			break
		}
		rd := b[p : p+rdlen]
		rdataStart := p
		p += rdlen
		owner = strings.ToLower(owner)

		switch atype {
		case 1: // A
			if rdlen == 4 {
				addr(owner, 1, ttl, net.IPv4(rd[0], rd[1], rd[2], rd[3]))
			}
		case 28: // AAAA
			if rdlen == 16 {
				ip := make(net.IP, 16)
				copy(ip, rd)
				addr(owner, 28, ttl, ip)
			}
		case 5: // CNAME(rdata 可能用压缩指针指回消息前部, 必须在整条消息上解析)
			if name, _, ok := dnsReadName(b, rdataStart); ok && name != "" {
				name = strings.ToLower(name)
				out.Answers = append(out.Answers, "CNAME:"+name)
				if len(out.Records) < dnsMaxRecords {
					out.Records = append(out.Records, output.DNSAnswer{Name: owner, Type: 5, TTL: ttl, Value: name})
				}
			}
		case 64, 65: // SVCB / HTTPS: ipv4hint(4) / ipv6hint(6) 里的地址
			for _, ip := range svcbAddrHints(rd) {
				addr(owner, atype, ttl, ip)
			}
		}
	}
	out.TTL = minTTL
	return out, true
}

// svcbAddrHints 从 SVCB/HTTPS RDATA 中取 ipv4hint / ipv6hint 地址(RFC 9460)。
// RDATA: SvcPriority(2) | TargetName(未压缩) | SvcParams{key(2) len(2) value}*。
// AliasMode(priority 0)没有参数。任何格式问题返回已取到的部分。
func svcbAddrHints(rd []byte) []net.IP {
	if len(rd) < 3 || binary.BigEndian.Uint16(rd[0:2]) == 0 {
		return nil
	}
	p := 2
	// TargetName: RFC 9460 禁止压缩, 按标签序列跳过。
	for i := 0; ; i++ {
		if p >= len(rd) || i > 127 {
			return nil
		}
		l := int(rd[p])
		p++
		if l == 0 {
			break
		}
		if l > 63 {
			return nil
		}
		p += l
	}
	var out []net.IP
	for len(rd)-p >= 4 && len(out) < 16 {
		key := binary.BigEndian.Uint16(rd[p : p+2])
		vl := int(binary.BigEndian.Uint16(rd[p+2 : p+4]))
		p += 4
		if len(rd)-p < vl {
			break
		}
		v := rd[p : p+vl]
		p += vl
		switch key {
		case 4:
			for len(v) >= 4 && len(out) < 16 {
				out = append(out, net.IPv4(v[0], v[1], v[2], v[3]))
				v = v[4:]
			}
		case 6:
			for len(v) >= 16 && len(out) < 16 {
				ip := make(net.IP, 16)
				copy(ip, v[:16])
				out = append(out, ip)
				v = v[16:]
			}
		}
	}
	return out
}

// parseDNSTCP 解析 TCP 上的 DNS(RFC 1035 §4.2.2: 2 字节长度前缀)。只解析
// 段内第一条消息; 前缀声明的长度超出本段时按截断消息尽力解析。续段(不以
// 长度前缀开头)通常通不过 qdcount==1 + 名字合法性检查。
func parseDNSTCP(b []byte) (DNSInfo, bool) {
	if len(b) < 2+12 {
		return DNSInfo{}, false
	}
	l := int(binary.BigEndian.Uint16(b[0:2]))
	if l < 12 {
		return DNSInfo{}, false
	}
	msg := b[2:]
	if len(msg) > l {
		msg = msg[:l]
	}
	return parseDNS(msg)
}

func dnsReadName(b []byte, off int) (string, int, bool) {
	var sb strings.Builder
	nextOff := off
	jumped := false
	jumps := 0
	for i := 0; i < 256; i++ {
		if off >= len(b) {
			return "", 0, false
		}
		l := b[off]
		if l == 0 {
			if !jumped {
				nextOff = off + 1
			}
			return sb.String(), nextOff, true
		}
		if l&0xc0 == 0xc0 {
			if off+1 >= len(b) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3fff)
			if !jumped {
				nextOff = off + 2
				jumped = true
			}
			if ptr >= len(b) || ptr == off {
				return "", 0, false
			}
			off = ptr
			jumps++
			if jumps > 8 {
				return "", 0, false
			}
			continue
		}
		if l > 63 {
			return "", 0, false
		}
		off++
		if off+int(l) > len(b) {
			return "", 0, false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(b[off : off+int(l)])
		off += int(l)
	}
	return "", 0, false
}

// parseTLSClientHelloFull extracts SNI + ALPN + JA4 (+ ECH 标记) in one pass.
// b 必须以 TLS record 头开始且包含完整 ClientHello。
func parseTLSClientHelloFull(b []byte) (TLSInfo, bool) {
	ch, ok := parseClientHello(b, false)
	if !ok || (ch.sni == "" && len(ch.alpn) == 0 && !ch.ech) {
		return TLSInfo{}, false
	}
	info := TLSInfo{SNI: ch.sni, ALPN: ch.alpn, ECH: ch.ech}
	if in, ok2 := extractJA4Inputs(b); ok2 {
		info.JA4 = output.ComputeJA4(in)
	}
	return info, true
}

// parseTLSClientHello (rc20.1 接口, 保留给只要 SNI/ALPN 的调用方)。
func parseTLSClientHello(b []byte) (string, []string, bool) {
	ch, ok := parseClientHello(b, false)
	if !ok || (ch.sni == "" && len(ch.alpn) == 0) {
		return "", nil, false
	}
	return ch.sni, ch.alpn, true
}

// clientHello 是 ClientHello 中我们关心的字段。
type clientHello struct {
	sni  string
	alpn []string
	// ech: 带 encrypted_client_hello(0xfe0d)或旧 ESNI(0xffce)扩展。注意 Chrome
	// 对所有连接都发 GREASE ECH, 所以它只是"可能是 ECH 外层"的提示。
	ech bool
	// complete: 整个 ClientHello 都在 b 里(否则是 lenient 模式下的截断解析)。
	complete bool
}

// TLS 扩展类型。
const (
	tlsExtServerName = 0x0000
	tlsExtALPN       = 0x0010
	tlsExtECH        = 0xfe0d
	tlsExtESNI       = 0xffce
)

// parseClientHello 解析以 TLS record 头开始的 ClientHello。
//
// lenient=false: 要求 record / handshake / 扩展区都完整(旧行为)。
// lenient=true (v5.18): 允许数据被截断 —— ClientHello 跨多个 TCP 段(Chrome
// 带 X25519MLKEM768 后 ~1.8KB, 必然拆成两段)或被 snaplen 截断时, 只要
// server_name 扩展完整落在已有字节里就能取到 SNI。扩展走到截断处就停。
// 任何越界都只返回 ok=false, 不会 panic。
func parseClientHello(b []byte, lenient bool) (clientHello, bool) {
	var ch clientHello
	if len(b) < 9 || b[0] != 0x16 || b[5] != 0x01 {
		return ch, false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 4 {
		return ch, false
	}
	hsLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	avail := b[9:]
	end := hsLen
	ch.complete = true
	if recLen < 4+hsLen { // handshake 跨多个 record(极少见)
		if !lenient {
			return ch, false
		}
		end, ch.complete = recLen-4, false
	}
	if len(avail) < end {
		if !lenient {
			return ch, false
		}
		end, ch.complete = len(avail), false
	}
	body := avail[:end]

	p := 2 + 32 // legacy_version + random
	if len(body) < p+1 {
		return ch, false
	}
	sidLen := int(body[p])
	p += 1 + sidLen
	if len(body) < p+2 {
		return ch, false
	}
	csLen := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2 + csLen
	if len(body) < p+1 {
		return ch, false
	}
	cmLen := int(body[p])
	p += 1 + cmLen
	if len(body) < p+2 {
		return ch, false
	}
	extLen := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	ext := body[p:]
	if len(ext) < extLen {
		if !lenient {
			return ch, false
		}
		ch.complete = false
	} else {
		ext = ext[:extLen]
	}

	for len(ext) >= 4 {
		etype := binary.BigEndian.Uint16(ext[0:2])
		elen := int(binary.BigEndian.Uint16(ext[2:4]))
		ext = ext[4:]
		if len(ext) < elen {
			break
		}
		data := ext[:elen]
		ext = ext[elen:]

		switch etype {
		case tlsExtServerName:
			// server_name_list<2> { name_type(1) HostName<2> }
			if len(data) < 5 {
				continue
			}
			data = data[2:]
			if data[0] != 0 {
				continue
			}
			nameLen := int(binary.BigEndian.Uint16(data[1:3]))
			if len(data) < 3+nameLen {
				continue
			}
			ch.sni = sanitizeServerName(string(data[3 : 3+nameLen]))
		case tlsExtALPN:
			if len(data) < 2 {
				continue
			}
			list := data[2:]
			for len(list) >= 1 && len(ch.alpn) < 16 {
				n := int(list[0])
				if len(list) < 1+n {
					break
				}
				ch.alpn = append(ch.alpn, string(list[1:1+n]))
				list = list[1+n:]
			}
		case tlsExtECH, tlsExtESNI:
			ch.ech = true
		}
	}
	return ch, true
}

// sanitizeServerName 小写化、去尾点, 不是合法主机名字符集的返回空(防止
// 恶意/损坏的 SNI 进入输出文件)。
func sanitizeServerName(s string) string {
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if !validHostname(s) {
		return ""
	}
	return s
}
