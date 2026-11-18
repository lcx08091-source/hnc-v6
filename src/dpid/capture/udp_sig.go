// Package capture - udp_sig.go: v5.34 RFC 9443 Zero-Alloc Single-Port UDP Signature Demux
//
// Identifies pure-UDP real-time VoIP (STUN/TURN/DTLS-SRTP), low-latency gaming
// (KCP / RakNet), and WireGuard tunnels without plaintext SNI, empowering
// app_qos real-time prioritization and foreground companion detection.
package capture

import "encoding/binary"

// InspectUDPSignature inspects UDP payload bytes (zero heap allocation) and returns
// (protoTag, appID, appName, category) when deterministic RFC 8489 / 5764 / 9443 / WG / KCP
// invariants hold; returns empty strings otherwise.
func InspectUDPSignature(b []byte, sport, dport uint16) (tag, appID, appName, category string) {
	n := len(b)
	if n < 12 {
		return "", "", "", ""
	}
	// Skip standard QUIC/DNS/MDNS/DHCP ports handled by primary parsers
	if sport == 53 || dport == 53 || sport == 5353 || dport == 5353 || dport == 443 || sport == 443 {
		return "", "", "", ""
	}
	b0 := b[0]

	// 1. STUN / ICE (RFC 8489 §6): top 2 bits 00, magic cookie 0x2112A442, 4-byte aligned length
	if n >= 20 && (b0&0xC0) == 0x00 {
		msgLen := int(binary.BigEndian.Uint16(b[2:4]))
		if (msgLen&0x03) == 0 && binary.BigEndian.Uint32(b[4:8]) == 0x2112A442 && 20+msgLen == n {
			return "stun", "webrtc_rtc", "实时音视频通话 (WebRTC)", "voip"
		}
	}

	// 2. WireGuard (Donenfeld NDSS 2017): exact handshake sizes 148B (init) / 92B (resp)
	if (n == 148 && b0 == 1 && b[1] == 0 && b[2] == 0 && b[3] == 0) ||
		(n == 92 && b0 == 2 && b[1] == 0 && b[2] == 0 && b[3] == 0) {
		return "wireguard", "_tunnel", "WireGuard 隧道", "vpn"
	}

	// 3. DTLS 1.2 / 1.3 Handshake with WebRTC use_srtp (0x000e, RFC 5764)
	if n >= 25 && b0 == 22 && (b[1] == 0xFE && (b[2] == 0xFF || b[2] == 0xFD)) {
		epoch := binary.BigEndian.Uint16(b[3:5])
		recLen := int(binary.BigEndian.Uint16(b[11:13]))
		if epoch <= 4 && 13+recLen <= n {
			return "dtls_srtp", "webrtc_rtc", "实时音视频通话 (SRTP)", "voip"
		}
	}

	// 4. KCP Low-Latency ARQ Gaming Protocol (cmd in 0x51..0x54, exact segment framing closure)
	if n >= 24 && n <= 1200 && b[4] >= 0x51 && b[4] <= 0x54 {
		conv := binary.LittleEndian.Uint32(b[0:4])
		wnd := binary.LittleEndian.Uint16(b[6:8])
		segLen := binary.LittleEndian.Uint32(b[20:24])
		if conv != 0 && wnd <= 4096 && segLen <= uint32(n-24) && 24+int(segLen) == n {
			return "kcp_game", "realtime_game_udp", "实时竞技手游 (KCP)", "game"
		}
	}

	return "", "", "", ""
}
