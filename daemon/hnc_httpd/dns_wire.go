// dns_wire.go — DNS 接管(dns_takeover.go)用的最小 DNS 报文解析/构造
//
// 只做转发器需要的部分: 头部、单个问题、EDNS(OPT)探测、应答里的 A/AAAA/CNAME、
// 缓存要改写的 TTL 字段位置、阻断应答 / 截断应答 / REFUSED 应答的构造。
// 不引第三方库(golang.org/x/net/dns/dnsmessage 不在 go.mod 里)。

package main

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
)

const (
	dnsTypeA     = 1
	dnsTypeNS    = 2
	dnsTypeCNAME = 5
	dnsTypeSOA   = 6
	dnsTypePTR   = 12
	dnsTypeMX    = 15
	dnsTypeTXT   = 16
	dnsTypeAAAA  = 28
	dnsTypeSRV   = 33
	dnsTypeOPT   = 41
	dnsTypeSVCB  = 64
	dnsTypeHTTPS = 65

	dnsRcodeNoError  = 0
	dnsRcodeServFail = 2
	dnsRcodeNXDomain = 3
	dnsRcodeRefused  = 5

	dnsFlagQR = 0x8000
	dnsFlagTC = 0x0200
	dnsFlagRD = 0x0100
	dnsFlagRA = 0x0080
	dnsFlagCD = 0x0010

	dnsMaxWireRecords = 128 // 单条消息最多走多少条记录(防恶意包)
)

var errDNSShort = errors.New("dns: short message")
var errDNSBad = errors.New("dns: malformed message")

// dnsQuery 解析后的查询(或应答的问题部分)
type dnsQuery struct {
	ID      uint16
	Flags   uint16
	QName   string // 小写, 无尾点; 根 = ""
	QType   uint16
	QClass  uint16
	QEnd    int  // 问题段结束偏移(header 12 + name + 4)
	HasOPT  bool // 带 EDNS
	UDPSize int  // EDNS 声明的 UDP 载荷上限(无 EDNS = 512)
	DO      bool // DNSSEC OK
	OptLen  int  // OPT RDATA 长度(>0 = 带 EDNS 选项, 如 ECS/cookie, 不走缓存)
}

func dnsTypeName(t uint16) string {
	switch t {
	case dnsTypeA:
		return "A"
	case dnsTypeNS:
		return "NS"
	case dnsTypeCNAME:
		return "CNAME"
	case dnsTypeSOA:
		return "SOA"
	case dnsTypePTR:
		return "PTR"
	case dnsTypeMX:
		return "MX"
	case dnsTypeTXT:
		return "TXT"
	case dnsTypeAAAA:
		return "AAAA"
	case dnsTypeSRV:
		return "SRV"
	case dnsTypeSVCB:
		return "SVCB"
	case dnsTypeHTTPS:
		return "HTTPS"
	}
	return "TYPE" + strconv.Itoa(int(t))
}

func dnsRcodeName(r int) string {
	switch r {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	}
	return "RCODE" + strconv.Itoa(r)
}

// dnsReadName 读(可能压缩的)域名, 返回小写无尾点名字与名字之后的偏移
func dnsReadName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	next := -1
	for hops := 0; ; hops++ {
		if hops > 127 || off >= len(b) {
			return "", 0, errDNSBad
		}
		l := int(b[off])
		switch {
		case l == 0:
			if next < 0 {
				next = off + 1
			}
			return strings.ToLower(sb.String()), next, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(b) {
				return "", 0, errDNSBad
			}
			ptr := int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3FFF)
			if next < 0 {
				next = off + 2
			}
			if ptr >= off { // 只允许向前指, 防环
				return "", 0, errDNSBad
			}
			off = ptr
		case l&0xC0 != 0:
			return "", 0, errDNSBad
		default:
			if off+1+l > len(b) {
				return "", 0, errDNSBad
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.Write(b[off+1 : off+1+l])
			if sb.Len() > 255 {
				return "", 0, errDNSBad
			}
			off += 1 + l
		}
	}
}

// dnsSkipName 跳过一个名字, 返回之后偏移
func dnsSkipName(b []byte, off int) (int, error) {
	for hops := 0; hops < 128; hops++ {
		if off >= len(b) {
			return 0, errDNSBad
		}
		l := int(b[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(b) {
				return 0, errDNSBad
			}
			return off + 2, nil
		case l&0xC0 != 0:
			return 0, errDNSBad
		default:
			off += 1 + l
		}
	}
	return 0, errDNSBad
}

// dnsParseQuery 解析查询: 必须恰好 1 个问题。顺带找 additional 段里的 OPT。
func dnsParseQuery(b []byte) (dnsQuery, error) {
	var q dnsQuery
	if len(b) < 12 {
		return q, errDNSShort
	}
	q.ID = binary.BigEndian.Uint16(b[0:2])
	q.Flags = binary.BigEndian.Uint16(b[2:4])
	if binary.BigEndian.Uint16(b[4:6]) != 1 {
		return q, errDNSBad
	}
	name, p, err := dnsReadName(b, 12)
	if err != nil {
		return q, err
	}
	if p+4 > len(b) {
		return q, errDNSShort
	}
	q.QName = name
	q.QType = binary.BigEndian.Uint16(b[p : p+2])
	q.QClass = binary.BigEndian.Uint16(b[p+2 : p+4])
	q.QEnd = p + 4
	q.UDPSize = 512
	an := int(binary.BigEndian.Uint16(b[6:8]))
	ns := int(binary.BigEndian.Uint16(b[8:10]))
	ar := int(binary.BigEndian.Uint16(b[10:12]))
	if an+ns+ar > dnsMaxWireRecords {
		return q, nil // 怪查询: 不找 OPT, 照常转发
	}
	p = q.QEnd
	for i := 0; i < an+ns+ar; i++ {
		np, err := dnsSkipName(b, p)
		if err != nil || np+10 > len(b) {
			return q, nil
		}
		typ := binary.BigEndian.Uint16(b[np : np+2])
		rdl := int(binary.BigEndian.Uint16(b[np+8 : np+10]))
		if np+10+rdl > len(b) {
			return q, nil
		}
		if i >= an+ns && typ == dnsTypeOPT {
			q.HasOPT = true
			sz := int(binary.BigEndian.Uint16(b[np+2 : np+4]))
			if sz < 512 {
				sz = 512
			}
			if sz > 4096 {
				sz = 4096
			}
			q.UDPSize = sz
			q.DO = binary.BigEndian.Uint16(b[np+6:np+8])&0x8000 != 0
			q.OptLen = rdl
		}
		p = np + 10 + rdl
	}
	return q, nil
}

// dnsRR 应答里的一条记录(只保留转发器关心的)
type dnsRR struct {
	Name  string
	Type  uint16
	TTL   uint32
	Value string // A/AAAA: IP 文本; CNAME: 目标名
}

// dnsMsgInfo 应答解析结果
type dnsMsgInfo struct {
	ID         uint16
	Flags      uint16
	Rcode      int
	Q          dnsQuery
	Answers    []dnsRR // 答案段 A/AAAA/CNAME
	ANCount    int
	TTLOffsets []int  // 所有非 OPT 记录 TTL 字段偏移(缓存改写用)
	MinTTL     uint32 // 非 OPT 记录最小 TTL(无记录 = 0)
	HaveTTL    bool
	NegTTL     uint32 // 否定应答: min(SOA TTL, SOA MINIMUM); 无 SOA = 0
	HaveSOA    bool
}

// dnsParseResponse 解析应答(问题段必须 1 个)
func dnsParseResponse(b []byte) (dnsMsgInfo, error) {
	var m dnsMsgInfo
	if len(b) < 12 {
		return m, errDNSShort
	}
	m.ID = binary.BigEndian.Uint16(b[0:2])
	m.Flags = binary.BigEndian.Uint16(b[2:4])
	m.Rcode = int(m.Flags & 0x000F)
	if binary.BigEndian.Uint16(b[4:6]) != 1 {
		return m, errDNSBad
	}
	name, p, err := dnsReadName(b, 12)
	if err != nil {
		return m, err
	}
	if p+4 > len(b) {
		return m, errDNSShort
	}
	m.Q = dnsQuery{ID: m.ID, Flags: m.Flags, QName: name,
		QType: binary.BigEndian.Uint16(b[p : p+2]), QClass: binary.BigEndian.Uint16(b[p+2 : p+4]), QEnd: p + 4, UDPSize: 512}
	an := int(binary.BigEndian.Uint16(b[6:8]))
	ns := int(binary.BigEndian.Uint16(b[8:10]))
	ar := int(binary.BigEndian.Uint16(b[10:12]))
	m.ANCount = an
	if an+ns+ar > dnsMaxWireRecords {
		return m, errDNSBad
	}
	p = m.Q.QEnd
	for i := 0; i < an+ns+ar; i++ {
		owner, np, err := dnsReadName(b, p)
		if err != nil {
			return m, err
		}
		if np+10 > len(b) {
			return m, errDNSShort
		}
		typ := binary.BigEndian.Uint16(b[np : np+2])
		ttl := binary.BigEndian.Uint32(b[np+4 : np+8])
		rdl := int(binary.BigEndian.Uint16(b[np+8 : np+10]))
		rdStart := np + 10
		if rdStart+rdl > len(b) {
			return m, errDNSShort
		}
		rd := b[rdStart : rdStart+rdl]
		p = rdStart + rdl
		if typ == dnsTypeOPT {
			m.Q.HasOPT = true
			continue
		}
		if ttl > 0x7FFFFFFF { // RFC 2181: 高位置 1 视为 0
			ttl = 0
		}
		m.TTLOffsets = append(m.TTLOffsets, np+4)
		if !m.HaveTTL || ttl < m.MinTTL {
			m.MinTTL, m.HaveTTL = ttl, true
		}
		switch {
		case i < an && typ == dnsTypeA && rdl == 4:
			m.Answers = append(m.Answers, dnsRR{owner, typ, ttl, net.IP(append([]byte(nil), rd...)).String()})
		case i < an && typ == dnsTypeAAAA && rdl == 16:
			m.Answers = append(m.Answers, dnsRR{owner, typ, ttl, net.IP(append([]byte(nil), rd...)).String()})
		case i < an && typ == dnsTypeCNAME:
			if cn, _, err := dnsReadName(b, rdStart); err == nil {
				m.Answers = append(m.Answers, dnsRR{owner, typ, ttl, cn})
			}
		case i >= an && i < an+ns && typ == dnsTypeSOA:
			// MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM
			q, err := dnsSkipName(b, rdStart)
			if err == nil {
				q, err = dnsSkipName(b, q)
			}
			if err == nil && q+20 <= rdStart+rdl {
				min := binary.BigEndian.Uint32(b[q+16 : q+20])
				if ttl < min {
					min = ttl
				}
				if !m.HaveSOA || min < m.NegTTL {
					m.NegTTL, m.HaveSOA = min, true
				}
			}
		}
	}
	return m, nil
}

// dnsAnswerIPs 跟随 CNAME 链: 链上(qname 或其 CNAME 目标)拥有的 A/AAAA 地址,
// 以及链末端规范名(无 CNAME 时 = "")。
func dnsAnswerIPs(qname string, rrs []dnsRR) (ips []dnsRR, cname string) {
	cn := map[string]string{}
	for _, r := range rrs {
		if r.Type == dnsTypeCNAME {
			if _, dup := cn[r.Name]; !dup {
				cn[r.Name] = r.Value
			}
		}
	}
	in := map[string]bool{qname: true}
	final := qname
	for i := 0; i < 16; i++ {
		nx, ok := cn[final]
		if !ok || in[nx] {
			break
		}
		in[nx] = true
		final = nx
	}
	if final != qname {
		cname = final
	}
	for _, r := range rrs {
		if (r.Type == dnsTypeA || r.Type == dnsTypeAAAA) && in[r.Name] {
			ips = append(ips, r)
		}
	}
	return ips, cname
}

// dnsEncodeName 名字 → 线格式(未压缩)
func dnsEncodeName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	var out []byte
	if name != "" {
		for _, lab := range strings.Split(name, ".") {
			if len(lab) == 0 || len(lab) > 63 {
				return nil
			}
			out = append(out, byte(len(lab)))
			out = append(out, lab...)
		}
	}
	return append(out, 0)
}

// dnsBuildQuery 构造一个查询(测试 / 自检用), edns > 0 时附 OPT(UDP size = edns)
func dnsBuildQuery(id uint16, name string, qtype uint16, edns int, do bool) []byte {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], dnsFlagRD)
	binary.BigEndian.PutUint16(b[4:6], 1)
	b = append(b, dnsEncodeName(name)...)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1)
	if edns > 0 {
		binary.BigEndian.PutUint16(b[10:12], 1)
		b = append(b, 0) // root
		b = binary.BigEndian.AppendUint16(b, dnsTypeOPT)
		b = binary.BigEndian.AppendUint16(b, uint16(edns))
		var fl uint32
		if do {
			fl = 0x8000
		}
		b = binary.BigEndian.AppendUint32(b, fl)
		b = binary.BigEndian.AppendUint16(b, 0)
	}
	return b
}

// dnsReplyHeader 以查询为模板构造应答头 + 原样问题段(保留客户端大小写, 0x20 兼容)
func dnsReplyHeader(query []byte, q dnsQuery, rcode int, ancount int) []byte {
	out := make([]byte, q.QEnd, q.QEnd+64)
	copy(out, query[:q.QEnd])
	fl := dnsFlagQR | dnsFlagRA | (q.Flags & (dnsFlagRD | dnsFlagCD)) | (q.Flags & 0x7800) | uint16(rcode&0xF)
	binary.BigEndian.PutUint16(out[2:4], fl)
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], uint16(ancount))
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	return out
}

// dnsAppendOPT 客户端带 EDNS 时应答也带一个空 OPT(RFC 6891 §7)
func dnsAppendOPT(out []byte, q dnsQuery) []byte {
	if !q.HasOPT {
		return out
	}
	binary.BigEndian.PutUint16(out[10:12], binary.BigEndian.Uint16(out[10:12])+1)
	out = append(out, 0)
	out = binary.BigEndian.AppendUint16(out, dnsTypeOPT)
	out = binary.BigEndian.AppendUint16(out, 1232)
	var fl uint32
	if q.DO {
		fl = 0x8000
	}
	out = binary.BigEndian.AppendUint32(out, fl)
	return binary.BigEndian.AppendUint16(out, 0)
}

// dnsRcodeReply REFUSED / SERVFAIL / NXDOMAIN 等无数据应答
func dnsRcodeReply(query []byte, q dnsQuery, rcode int) []byte {
	return dnsAppendOPT(dnsReplyHeader(query, q, rcode, 0), q)
}

// dnsBlockTTL 阻断应答 TTL(秒): 短一点, 解封后客户端很快恢复
const dnsBlockTTL = 60

// dnsBlockReply 阻断应答: mode=nxdomain → NXDOMAIN; mode=zero → A 0.0.0.0 / AAAA ::,
// 其它类型 NOERROR 无数据。
func dnsBlockReply(query []byte, q dnsQuery, mode string) []byte {
	if mode != "zero" {
		return dnsRcodeReply(query, q, dnsRcodeNXDomain)
	}
	var rd []byte
	switch q.QType {
	case dnsTypeA:
		rd = make([]byte, 4)
	case dnsTypeAAAA:
		rd = make([]byte, 16)
	}
	if rd == nil || q.QClass != 1 {
		return dnsRcodeReply(query, q, dnsRcodeNoError)
	}
	out := dnsReplyHeader(query, q, dnsRcodeNoError, 1)
	out = append(out, 0xC0, 0x0C) // 指回问题名
	out = binary.BigEndian.AppendUint16(out, q.QType)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint32(out, dnsBlockTTL)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rd)))
	out = append(out, rd...)
	return dnsAppendOPT(out, q)
}

// dnsTruncate 应答超过客户端 UDP 上限: 只留头 + 问题段, 置 TC, 让客户端改走 TCP
func dnsTruncate(resp []byte, limit int) []byte {
	if len(resp) <= limit {
		return resp
	}
	end, err := dnsSkipName(resp, 12)
	if err != nil || end+4 > len(resp) || binary.BigEndian.Uint16(resp[4:6]) != 1 {
		end = 8 // 解析不了: 只给头
		out := make([]byte, 12)
		copy(out, resp[:12])
		binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])|dnsFlagTC)
		binary.BigEndian.PutUint16(out[4:6], 0)
		binary.BigEndian.PutUint16(out[6:8], 0)
		binary.BigEndian.PutUint16(out[8:10], 0)
		binary.BigEndian.PutUint16(out[10:12], 0)
		return out
	}
	end += 4
	out := make([]byte, end)
	copy(out, resp[:end])
	binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])|dnsFlagTC)
	binary.BigEndian.PutUint16(out[6:8], 0)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	return out
}

// dnsSameQuestion 应答的问题与查询一致(防串包)。名字大小写不敏感。
func dnsSameQuestion(q dnsQuery, m dnsMsgInfo) bool {
	return m.ID == q.ID && m.Q.QName == q.QName && m.Q.QType == q.QType && m.Q.QClass == q.QClass
}
