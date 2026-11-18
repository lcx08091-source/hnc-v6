// Package capture - tlsfp_qgeom.go: HNC v5.38.0 去瞬态扩展稳定 TLS 指纹 (TLSFP) 与 QUIC Initial 几何特征提取
package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// QUICGeom 记录不依赖明文内层 SNI 的 QUIC Initial 首包几何指纹(即使开启 ECH 依然 100% 可见, 零堆分配)
type QUICGeom struct {
	DCIDLen       uint8  `json:"dcid_len"`
	SCIDLen       uint8  `json:"scid_len"`
	HasToken      bool   `json:"has_token"`
	PayloadBucket uint16 `json:"payload_bucket"`
	PaddingBucket uint16 `json:"padding_bucket"`
	FrameSeqMask  uint8  `json:"frame_seq_mask"`
}

const (
	QFramePadding     uint8 = 1 << 0
	QFramePing        uint8 = 1 << 1
	QFrameAck         uint8 = 1 << 2
	QFrameCrypto      uint8 = 1 << 3
	QFrameMultiCrypto uint8 = 1 << 4
)

func (g QUICGeom) CompactToken() string {
	if g.DCIDLen == 0 && g.PayloadBucket == 0 {
		return ""
	}
	return fmt.Sprintf("qg:%d_%d_%d_%d_%02x",
		g.DCIDLen, g.SCIDLen, g.PayloadBucket, g.PaddingBucket, g.FrameSeqMask)
}

// isEphemeralTLSExt 剔除 TLS 1.3 会话恢复/填充导致的自裂变瞬态扩展(参考 nDPI 6.0 TLSFP 设计)
func isEphemeralTLSExt(ext uint16) bool {
	switch ext {
	case 0x0015, // padding
		0x0023, // session_ticket
		0x0029, // pre_shared_key
		0x002a, // early_data
		0x002c, // cookie
		0x002d: // psk_key_exchange_modes
		return true
	default:
		return false
	}
}

func isGREASEVal(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}

// ComputeTLSFP 计算跨会话恢复恒定一致的四段式 TLSFP 指纹
func ComputeTLSFP(isQUIC bool, tlsVer uint16, hasSNI bool, alpn string,
	ciphers, exts, sigAlgs, supportedGroups []uint16) string {

	proto := byte('t')
	if isQUIC {
		proto = 'q'
	}
	sniFlag := byte('i')
	if hasSNI {
		sniFlag = 'd'
	}

	var cleanCiphers []uint16
	for _, c := range ciphers {
		if !isGREASEVal(c) {
			cleanCiphers = append(cleanCiphers, c)
		}
	}
	cCnt := min(len(cleanCiphers), 99)
	slices.Sort(cleanCiphers)

	var hashExts []uint16
	eCntRaw := 0
	for _, e := range exts {
		if isGREASEVal(e) || isEphemeralTLSExt(e) {
			continue
		}
		eCntRaw++
		if e != 0x0000 && e != 0x0010 {
			hashExts = append(hashExts, e)
		}
	}
	eCnt := min(eCntRaw, 99)
	slices.Sort(hashExts)

	var cleanGroups []uint16
	for _, g := range supportedGroups {
		if !isGREASEVal(g) {
			cleanGroups = append(cleanGroups, g)
		}
	}
	slices.Sort(cleanGroups)

	alpn2 := "00"
	if len(alpn) >= 2 {
		alpn2 = string([]byte{alpn[0], alpn[len(alpn)-1]})
	} else if len(alpn) == 1 {
		alpn2 = string([]byte{alpn[0], alpn[0]})
	}
	verStr := "13"
	if tlsVer == 0x0303 {
		verStr = "12"
	}

	partB := tlsfpShortHash(cleanCiphers, nil)
	partC := tlsfpShortHash(hashExts, sigAlgs)
	partD := ""
	if len(cleanGroups) > 0 {
		partD = tlsfpShortHash(cleanGroups, nil)
	}
	return fmt.Sprintf("%c%s%c%02d%02d%s_%s_%s_%s",
		proto, verStr, sniFlag, cCnt, eCnt, alpn2, partB, partC, partD)
}

func tlsfpShortHash(primary, secondary []uint16) string {
	if len(primary) == 0 && len(secondary) == 0 {
		return "000000000000"
	}
	var sb strings.Builder
	for i, v := range primary {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, "%04x", v)
	}
	if len(secondary) > 0 {
		sb.WriteByte('_')
		for i, v := range secondary {
			if i > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, "%04x", v)
		}
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:6])
}
