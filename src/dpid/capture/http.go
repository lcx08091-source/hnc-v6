// Package capture - http.go: v5.18 / v6.0.0 明文 HTTP 请求元数据与载荷提取。
//
// v6.0.0 Vector 扩展:
//   - cBPF 放行所有非 443 TCP 端口上以常见 HTTP 方法开头的首包(截断至 tlsSnaplen=4096B);
//   - parseHTTPRequestFull 提取完整 Method、Path(含 Query)、Host(域名或 IP 字面量)、
//     User-Agent 以及前 4096B 原始载荷拷贝, 供主程序同时喂给域名归因与 LeakGuard 引擎;
//   - 保留原有 parseHTTPRequestHost 签名与语义不变(仅域名 Host 返回 ok=true)。

package capture

import (
	"bytes"
	"net"
	"strings"
)

// httpMethods 与 bpf.go 的 httpMethodWords 对应(BPF 按前 4 字节比较)。
var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "DELETE ", "PATCH "}

const (
	httpMaxScan        = 8 << 10
	httpPayloadSnapMax = tlsSnaplen // 4096 bytes
	httpMaxTargetLen   = 2048
)

// HTTPInfo 保存单条明文 HTTP 请求行的完整字段与前 4096B 原始载荷拷贝(供 LeakGuard 嗅探)。
type HTTPInfo struct {
	Method     string
	Path       string
	Host       string // 规范化后的合法域名(若 Host 头为 IP 字面量或缺失则为空)
	RawHost    string // 剥离端口后的域名或 IP 字面量(供无域名直连归因)
	UserAgent  string
	RawPayload []byte
}

func hasHTTPMethodPrefix(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

// parseHTTPRequestFull 解析完整请求行 Method、Path、Host、User-Agent 并拷贝前 4096B 载荷。
func parseHTTPRequestFull(raw []byte) (HTTPInfo, bool) {
	if !hasHTTPMethodPrefix(raw) {
		return HTTPInfo{}, false
	}
	b := raw
	if len(b) > httpMaxScan {
		b = b[:httpMaxScan]
	}
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return HTTPInfo{}, false
	}
	line0 := bytes.TrimRight(b[:i], "\r")
	verIdx := bytes.Index(line0, []byte(" HTTP/1."))
	if verIdx <= 0 {
		return HTTPInfo{}, false
	}
	sp := bytes.IndexByte(line0[:verIdx], ' ')
	if sp <= 0 {
		return HTTPInfo{}, false
	}
	method := string(line0[:sp])
	reqPath := string(bytes.TrimSpace(line0[sp+1 : verIdx]))
	if reqPath == "" {
		return HTTPInfo{}, false
	}
	if len(reqPath) > httpMaxTargetLen {
		reqPath = reqPath[:httpMaxTargetLen]
	}

	rem := b[i+1:]
	var domainHost, rawHost, ua string
	var sawEndOfHeaders bool
	var hasBody bool

	for len(rem) > 0 {
		j := bytes.IndexByte(rem, '\n')
		if j < 0 {
			break // 截断的最后一行不可信
		}
		line := bytes.TrimRight(rem[:j], "\r")
		rem = rem[j+1:]
		if len(line) == 0 {
			sawEndOfHeaders = true
			hasBody = len(rem) > 0
			break // 头部结束
		}
		c := bytes.IndexByte(line, ':')
		if c <= 0 {
			continue
		}
		name := string(bytes.TrimSpace(line[:c]))
		val := string(bytes.TrimSpace(line[c+1:]))
		switch {
		case rawHost == "" && strings.EqualFold(name, "host"):
			dh, rh, ok := parseHostDomainOrIP(val)
			if !ok {
				return HTTPInfo{}, false
			}
			domainHost = dh
			rawHost = rh
		case ua == "" && strings.EqualFold(name, "user-agent"):
			if len(val) > 256 {
				val = val[:256]
			}
			ua = val
		}
	}

	// 无 Host 头且既无查询参数也无请求体(如裸 "GET / HTTP/1.1\r\n\r\n"): 保持忽略语义。
	if rawHost == "" {
		if !sawEndOfHeaders || (!strings.ContainsRune(reqPath, '?') && !hasBody) {
			return HTTPInfo{}, false
		}
	}

	snapN := len(raw)
	if snapN > httpPayloadSnapMax {
		snapN = httpPayloadSnapMax
	}
	payloadCopy := make([]byte, snapN)
	copy(payloadCopy, raw[:snapN])

	return HTTPInfo{
		Method:     method,
		Path:       reqPath,
		Host:       domainHost,
		RawHost:    rawHost,
		UserAgent:  ua,
		RawPayload: payloadCopy,
	}, true
}

// parseHTTPRequestHost 返回 (host, userAgent, ok)。ok 仅在拿到合法域名 Host 时为 true。
func parseHTTPRequestHost(b []byte) (string, string, bool) {
	if len(b) > httpMaxScan {
		b = b[:httpMaxScan]
	}
	if !hasHTTPMethodPrefix(b) {
		return "", "", false
	}
	// 跳过请求行。
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return "", "", false
	}
	line0 := b[:i]
	if !bytes.Contains(line0, []byte(" HTTP/1.")) {
		return "", "", false
	}
	b = b[i+1:]
	var host, ua string
	for len(b) > 0 {
		j := bytes.IndexByte(b, '\n')
		if j < 0 {
			break // 截断的最后一行不可信
		}
		line := bytes.TrimRight(b[:j], "\r")
		b = b[j+1:]
		if len(line) == 0 {
			break // 头部结束
		}
		c := bytes.IndexByte(line, ':')
		if c <= 0 {
			continue
		}
		name := string(bytes.TrimSpace(line[:c]))
		val := string(bytes.TrimSpace(line[c+1:]))
		switch {
		case host == "" && strings.EqualFold(name, "host"):
			host = httpHostName(val)
			if host == "" {
				return "", "", false
			}
		case ua == "" && strings.EqualFold(name, "user-agent"):
			if len(val) > 256 {
				val = val[:256]
			}
			ua = val
		}
	}
	if host == "" {
		return "", "", false
	}
	return host, ua, true
}

// parseHostDomainOrIP 同时支持域名 Host 与 IP 字面量 Host(如摄像头直连 120.78.1.2:8080)。
func parseHostDomainOrIP(v string) (domainHost, rawHost string, ok bool) {
	if v == "" {
		return "", "", false
	}
	if dh := httpHostName(v); dh != "" {
		return dh, dh, true
	}
	// 尝试解析 IPv4(:port) 或 [IPv6](:port) 字面量。
	cand := v
	if cand[0] == '[' {
		closeIdx := strings.IndexByte(cand, ']')
		if closeIdx <= 1 {
			return "", "", false
		}
		if closeIdx+1 < len(cand) {
			if cand[closeIdx+1] != ':' || !allDecimalDigits(cand[closeIdx+2:]) {
				return "", "", false
			}
		}
		cand = cand[1:closeIdx]
	} else if c := strings.LastIndexByte(cand, ':'); c >= 0 {
		if !allDecimalDigits(cand[c+1:]) {
			return "", "", false
		}
		cand = cand[:c]
	}
	if ip := net.ParseIP(cand); ip != nil {
		return "", ip.String(), true
	}
	return "", "", false
}

func allDecimalDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// httpHostName 规范化 Host 头的值: 去端口、小写、去尾点; IP 字面量或非法
// 字符返回空。
func httpHostName(v string) string {
	if v == "" || v[0] == '[' { // IPv6 字面量
		return ""
	}
	if c := strings.LastIndexByte(v, ':'); c >= 0 {
		port := v[c+1:]
		for k := 0; k < len(port); k++ {
			if port[k] < '0' || port[k] > '9' {
				return ""
			}
		}
		v = v[:c]
	}
	v = sanitizeServerName(v)
	if v == "" || net.ParseIP(v) != nil {
		return ""
	}
	return v
}
