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
)

type DNSInfo struct {
	IsResponse bool
	QName      string
	QType      uint16
	Answers    []string
	TTL        uint32
}

type TLSInfo struct {
	SNI  string
	ALPN []string
	JA4  string // rc29: pre-computed JA4 fingerprint
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
	if totalLen > len(ip) {
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
done:

	ev := Event{
		Time: ts, SrcMAC: srcMAC, DstMAC: dstMAC,
		SrcIP: srcIP, DstIP: dstIP, IsIPv6: true, Bytes: totalLen,
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

		// DNS over TCP.
		if ev.DstPort == 53 || ev.SrcPort == 53 {
			if len(tcpData) > 2 {
				if d, ok := parseDNS(tcpData[2:]); ok {
					ev.Kind = EventDNS
					ev.DNS = d
					assignClient(&ev, d.IsResponse)
					return ev, ParseOK
				}
			}
			return ev, ParseMalformed
		}

		// TLS ClientHello (port 443 + first byte 0x16).
		if (ev.DstPort == 443 || ev.SrcPort == 443) && len(tcpData) > 0 && tcpData[0] == 0x16 {
			if sni, alpn, ja4, ok := parseTLSClientHelloFull(tcpData); ok {
				ev.Kind = EventTLSClientHello
				ev.TLS.SNI = sni
				ev.TLS.ALPN = alpn
				ev.TLS.JA4 = ja4
				assignClient(&ev, false)
				return ev, ParseOK
			}
			// Fall through to Flow event for byte accounting.
		}

		// Anything else TCP -> Flow event (rc29).
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

	var minTTL uint32
	for i := uint16(0); i < ancount; i++ {
		_, np, ok := dnsReadName(b, p)
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
		rdataStart := p
		p += rdlen

		switch atype {
		case 1: // A
			if rdlen == 4 {
				out.Answers = append(out.Answers, net.IPv4(b[rdataStart], b[rdataStart+1], b[rdataStart+2], b[rdataStart+3]).String())
			}
		case 28: // AAAA
			if rdlen == 16 {
				ip := make(net.IP, 16)
				copy(ip, b[rdataStart:rdataStart+16])
				out.Answers = append(out.Answers, ip.String())
			}
		case 5: // CNAME
			if name, _, ok := dnsReadName(b, rdataStart); ok {
				out.Answers = append(out.Answers, "CNAME:"+strings.ToLower(name))
			}
		}
		if minTTL == 0 || ttl < minTTL {
			minTTL = ttl
		}
	}
	out.TTL = minTTL
	return out, true
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

// parseTLSClientHelloFull extracts SNI + ALPN + JA4 in one pass.
func parseTLSClientHelloFull(b []byte) (string, []string, string, bool) {
	sni, alpn, ok := parseTLSClientHello(b)
	if !ok {
		return "", nil, "", false
	}
	in, ok2 := extractJA4Inputs(b)
	if !ok2 {
		return sni, alpn, "", true
	}
	return sni, alpn, output.ComputeJA4(in), true
}

// parseTLSClientHello (rc20.1 logic, kept for SNI/ALPN-only callers).
func parseTLSClientHello(b []byte) (string, []string, bool) {
	if len(b) < 5 || b[0] != 0x16 {
		return "", nil, false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 4 || len(b) < 5+recLen {
		return "", nil, false
	}
	hs := b[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 0x01 {
		return "", nil, false
	}
	bodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+bodyLen {
		return "", nil, false
	}
	body := hs[4 : 4+bodyLen]

	p := 0
	if len(body) < p+2+32+1 {
		return "", nil, false
	}
	p += 2 + 32
	sidLen := int(body[p])
	p++
	if len(body) < p+sidLen+2 {
		return "", nil, false
	}
	p += sidLen
	csLen := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2 + csLen
	if len(body) < p+1 {
		return "", nil, false
	}
	cmLen := int(body[p])
	p += 1 + cmLen
	if len(body) < p+2 {
		return "", nil, false
	}
	extLen := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	if len(body) < p+extLen {
		return "", nil, false
	}
	ext := body[p : p+extLen]

	var sni string
	var alpn []string
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
		case 0x0000: // server_name
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
			sni = strings.ToLower(string(data[3 : 3+nameLen]))
		case 0x0010: // ALPN
			if len(data) < 2 {
				continue
			}
			list := data[2:]
			for len(list) >= 1 {
				n := int(list[0])
				if len(list) < 1+n {
					break
				}
				alpn = append(alpn, string(list[1:1+n]))
				list = list[1+n:]
			}
		}
	}

	if sni == "" && len(alpn) == 0 {
		return "", nil, false
	}
	return sni, alpn, true
}
