// Package output - qtp.go (v5.27 T2): QUIC 传输参数指纹。
//
// HTTP/3(QUIC)的 ClientHello 里有扩展 quic_transport_parameters(0x0039,
// 草案版 0xffa5)。不同网络库(Cronet / quiche / OkHttp-QUIC / 各家自研)给的
// 参数组合与取值不同, 比 JA4 更能区分「这是哪个 App 的网络栈」。
//
// 指纹只看参数「有哪些 + 几个稳定的整数取值」, 规范化规则:
//   - 参数 id 升序排序(不依赖发送顺序);
//   - GREASE / 保留 id(id % 31 == 27)合并成一个 G(几次、具体 id 都不管);
//   - 整数型参数(qtpIntParams)写成 id=值;
//   - 0x11 version_information 只取「可用版本列表」排序后拼接(不取 chosen);
//   - 其余一律只记「出现过」(含每次随机的 0x0f initial_source_connection_id,
//     以及 Google 私有参数里的 User-Agent 字符串 —— 不存原文)。
//
// 只读 ClientHello 里的这个扩展, 不涉及任何其他 QUIC 包(隐私边界见工作文档 §2)。

package output

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// QTPPrefix 是指纹前缀; 版本号随规范化规则变化而变化(旧指纹自然淘汰)。
const QTPPrefix = "qtp1_"

// qtpSummaryMax 调试接口显示的规范串上限。
const qtpSummaryMax = 256

// qtpIntParams 是带值的整数型参数(RFC 9000 §18.2 + RFC 9221)。
var qtpIntParams = map[uint64]bool{
	0x01: true, // max_idle_timeout
	0x03: true, // max_udp_payload_size
	0x04: true, // initial_max_data
	0x05: true, // initial_max_stream_data_bidi_local
	0x06: true, // initial_max_stream_data_bidi_remote
	0x07: true, // initial_max_stream_data_uni
	0x08: true, // initial_max_streams_bidi
	0x09: true, // initial_max_streams_uni
	0x0a: true, // ack_delay_exponent
	0x0b: true, // max_ack_delay
	0x0e: true, // active_connection_id_limit
	0x20: true, // max_datagram_frame_size
}

const qtpVersionInformation = 0x11

// qtpReadVarint 读 QUIC 变长整数(RFC 9000 §16)。
func qtpReadVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, false
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, true
}

type qtpToken struct {
	id  uint64
	tok string
}

// quicTPCanonical 返回规范串; 任何越界 / 截断 → ok=false。
func quicTPCanonical(raw []byte) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var toks []qtpToken
	grease := false
	b := raw
	for len(b) > 0 {
		id, n, ok := qtpReadVarint(b)
		if !ok {
			return "", false
		}
		b = b[n:]
		l, n, ok := qtpReadVarint(b)
		if !ok {
			return "", false
		}
		b = b[n:]
		if l > uint64(len(b)) {
			return "", false
		}
		val := b[:l]
		b = b[l:]

		if id%31 == 27 {
			grease = true
			continue
		}
		hid := strconv.FormatUint(id, 16)
		switch {
		case qtpIntParams[id]:
			v, vn, ok := qtpReadVarint(val)
			if !ok || vn != len(val) {
				toks = append(toks, qtpToken{id, hid + "=!"})
			} else {
				toks = append(toks, qtpToken{id, hid + "=" + strconv.FormatUint(v, 10)})
			}
		case id == qtpVersionInformation:
			// chosen_version(4) + available_versions(4 × n)
			if len(val) < 4 || len(val)%4 != 0 {
				toks = append(toks, qtpToken{id, hid + "=!"})
				break
			}
			var vs []uint32
			for p := 4; p+4 <= len(val); p += 4 {
				vs = append(vs, binary.BigEndian.Uint32(val[p:p+4]))
			}
			sort.Slice(vs, func(i, j int) bool { return vs[i] < vs[j] })
			parts := make([]string, 0, len(vs))
			for _, v := range vs {
				parts = append(parts, strconv.FormatUint(uint64(v), 16))
			}
			toks = append(toks, qtpToken{id, hid + "=" + strings.Join(parts, ",")})
		default:
			toks = append(toks, qtpToken{id, hid})
		}
	}
	sort.SliceStable(toks, func(i, j int) bool {
		if toks[i].id != toks[j].id {
			return toks[i].id < toks[j].id
		}
		return toks[i].tok < toks[j].tok
	})
	parts := make([]string, 0, len(toks)+1)
	for i, t := range toks {
		if i > 0 && t.tok == toks[i-1].tok {
			continue // 重复参数(协议错误)只记一次
		}
		parts = append(parts, t.tok)
	}
	if grease {
		parts = append(parts, "G")
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, "-"), true
}

// QUICTPFingerprint 返回 "qtp1_" + sha256(规范串) 前 12 位十六进制;
// 解析失败(越界 / 截断 / 空)返回 ""。
func QUICTPFingerprint(raw []byte) string {
	c, ok := quicTPCanonical(raw)
	if !ok {
		return ""
	}
	sum := sha256.Sum256([]byte(c))
	return QTPPrefix + hex.EncodeToString(sum[:])[:12]
}

// QUICTPSummary 返回规范串本身(≤ 256 字符, 超出截断), 仅供调试接口显示。
func QUICTPSummary(raw []byte) string {
	c, ok := quicTPCanonical(raw)
	if !ok {
		return ""
	}
	if len(c) > qtpSummaryMax {
		c = c[:qtpSummaryMax]
	}
	return c
}

// ValidQTP 校验指纹字符串形状(^qtp1_[0-9a-f]{12}$)。
func ValidQTP(s string) bool {
	if len(s) != len(QTPPrefix)+12 || !strings.HasPrefix(s, QTPPrefix) {
		return false
	}
	for _, c := range s[len(QTPPrefix):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
