// Package capture - http.go: v5.18 明文 HTTP 请求 Host 头提取。
//
// BPF 只放行"目的端口 80 且 TCP 载荷以常见 HTTP 方法开头"的包(每个请求
// 一个包, 量很小), 这里在其中找 Host 头。Host 是 IP 字面量的忽略(它不提供
// 域名信息)。只看 BPF 抓到的字节(tlsSnaplen), 头部被截断且还没见到 Host 就放弃。

package capture

import (
	"bytes"
	"net"
	"strings"
)

// httpMethods 与 bpf.go 的 httpMethodWords 对应(BPF 按前 4 字节比较)。
var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "DELETE ", "PATCH "}

const httpMaxScan = 8 << 10

// parseHTTPRequestHost 返回 (host, userAgent, ok)。ok 仅在拿到合法域名 Host 时为 true。
func parseHTTPRequestHost(b []byte) (string, string, bool) {
	if len(b) > httpMaxScan {
		b = b[:httpMaxScan]
	}
	isReq := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, []byte(m)) {
			isReq = true
			break
		}
	}
	if !isReq {
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
