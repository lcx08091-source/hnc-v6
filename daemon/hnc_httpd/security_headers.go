// security_headers.go — v5.22 安全响应头(配合 middleware.go securityHeaders)
//
// 所有响应:
//   X-Content-Type-Options: nosniff
//   X-Frame-Options: DENY            (+ CSP frame-ancestors 'none', 新旧浏览器都覆盖)
//   Referrer-Policy: same-origin     —— 不是 no-referrer: authMiddleware 用"loopback 请求
//                                       是否带 Origin/Referer"区分浏览器与 ksu.exec curl
//                                       (rc3 N-6 防 DNS rebinding), 本机浏览器同源 GET 只
//                                       带 Referer 不带 Origin; no-referrer 会让本机浏览器
//                                       请求被当成 curl 走 secret 校验而 401。same-origin
//                                       对跨站一律不发 Referer, 隐私效果相同。
//   Cross-Origin-Opener-Policy: same-origin
//   /api/* 未显式设置时 Cache-Control: no-store(设备/流量数据不进浏览器磁盘缓存)
//
// HTML 响应的 CSP:
//   script-src 不再用 'unsafe-inline': 在首个 Write 时扫描整页 body 里的内联
//   <script>(无 src), 计算 sha256 → 'sha256-…' 放行这些且只放行这些。WebUI 的
//   事件处理全是 JS 属性赋值(el.onclick = …), 没有 onclick="" 这类内联属性, 所以
//   hash 白名单足够。注入进 DOM 的 <script>/on* 属性 / javascript: URL 都会被拦。
//   style-src 仍保留 'unsafe-inline': 页面有数百个 style="" 属性(hash 不覆盖属性,
//   需要 'unsafe-hashes' 且逐个列出), CSS 注入的危害远小于脚本注入。
//   兜底: 若 HTML 不是一次写完(首块里没有 </html>)或在 body 之前就 WriteHeader
//   (重定向除外), 无法得到完整内联脚本集, 回退到旧 CSP('unsafe-inline'), 保证
//   页面不白屏。处理器自己设的 CSP(如 serveIndex 里的旧串)对 HTML 一律被覆盖。
//   KSU 管理器自身(mui.kernelsu.org 的 WebView 直接读 webroot)不经过 httpd,
//   不受本 CSP 影响; 经 httpd 的 127.0.0.1:8444 KSU 页面同样走 hash。

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
)

const cspCommonTail = "style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"connect-src 'self' http://127.0.0.1:8444; object-src 'none'; base-uri 'self'; " +
	"form-action 'self'; frame-ancestors 'none'"

// cspLegacy 旧 CSP(带 'unsafe-inline' 脚本), 只作无法计算 hash 时的兜底。
const cspLegacy = "default-src 'self'; script-src 'self' 'unsafe-inline'; " + cspCommonTail

// cspAPI 非 HTML 响应(JSON/JS/CSS/zip): 它们不会被当文档渲染, 给最严格的。
const cspAPI = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// inlineScriptHashes 返回 html 中所有内联 <script>(无 src 属性)内容的 CSP hash 源。
// 换行按 HTML 解析器规则归一(CRLF/CR → LF)后再算, 与浏览器一致。
func inlineScriptHashes(html []byte) []string {
	var out []string
	seen := map[string]bool{}
	lower := bytes.ToLower(html)
	pos := 0
	for {
		i := bytes.Index(lower[pos:], []byte("<script"))
		if i < 0 {
			break
		}
		start := pos + i
		// 标签名必须到此为止(排除 <scripts 之类)
		after := start + len("<script")
		if after >= len(lower) {
			break
		}
		if c := lower[after]; c != '>' && c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '/' && c != '\f' {
			pos = after
			continue
		}
		gt := bytes.IndexByte(lower[after:], '>')
		if gt < 0 {
			break
		}
		tagEnd := after + gt + 1
		attrs := lower[after : tagEnd-1]
		end := bytes.Index(lower[tagEnd:], []byte("</script"))
		if end < 0 {
			break
		}
		bodyEnd := tagEnd + end
		pos = bodyEnd + len("</script")
		if bytes.Contains(attrs, []byte("src=")) || bytes.Contains(attrs, []byte("src =")) {
			continue
		}
		content := html[tagEnd:bodyEnd]
		content = bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))
		content = bytes.ReplaceAll(content, []byte("\r"), []byte("\n"))
		sum := sha256.Sum256(content)
		h := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

var (
	cspCacheMu sync.Mutex
	cspCache   = map[[32]byte]string{}
)

// htmlCSP 为一个完整 HTML 文档生成 CSP(按文档 sha256 缓存, 有界)。
func htmlCSP(doc []byte) string {
	key := sha256.Sum256(doc)
	cspCacheMu.Lock()
	if v, ok := cspCache[key]; ok {
		cspCacheMu.Unlock()
		return v
	}
	cspCacheMu.Unlock()
	src := "'self'"
	if hs := inlineScriptHashes(doc); len(hs) > 0 {
		src += " " + strings.Join(hs, " ")
	}
	v := "default-src 'self'; script-src " + src + "; " + cspCommonTail
	cspCacheMu.Lock()
	if len(cspCache) >= 32 {
		cspCache = map[[32]byte]string{}
	}
	cspCache[key] = v
	cspCacheMu.Unlock()
	return v
}

func isHTMLContentType(ct string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "text/html")
}

// secHeaderWriter 在响应头真正发出前(首个 Write / WriteHeader / Flush)定稿 CSP。
type secHeaderWriter struct {
	http.ResponseWriter
	api  bool
	done bool
}

func (w *secHeaderWriter) finalize(body []byte, viaWrite bool, code int) {
	if w.done {
		return
	}
	w.done = true
	h := w.Header()
	if isHTMLContentType(h.Get("Content-Type")) {
		if viaWrite && bytes.Contains(bytes.ToLower(body), []byte("</html>")) {
			h.Set("Content-Security-Policy", htmlCSP(body))
		} else if !viaWrite && code >= 300 && code < 400 {
			// 重定向: 正文只是 net/http 生成的一个链接, 不需要任何脚本
			h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; "+cspCommonTail)
		} else {
			h.Set("Content-Security-Policy", cspLegacy)
		}
	} else if h.Get("Content-Security-Policy") == "" {
		h.Set("Content-Security-Policy", cspAPI)
	}
	if w.api && h.Get("Cache-Control") == "" {
		h.Set("Cache-Control", "no-store")
	}
}

func (w *secHeaderWriter) WriteHeader(code int) {
	w.finalize(nil, false, code)
	w.ResponseWriter.WriteHeader(code)
}

func (w *secHeaderWriter) Write(p []byte) (int, error) {
	if !w.done {
		// net/http 在首个 Write 时才嗅探 Content-Type; HTML 处理器都显式设置了,
		// 这里只在缺失时补一次嗅探, 让判定与最终发出的类型一致。
		if w.Header().Get("Content-Type") == "" && len(p) > 0 {
			w.Header().Set("Content-Type", http.DetectContentType(p))
		}
		w.finalize(p, true, http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (w *secHeaderWriter) Flush() {
	w.finalize(nil, false, http.StatusOK)
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap 让 http.NewResponseController(SSE 的 SetWriteDeadline 等)穿透本包装。
func (w *secHeaderWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// setStaticSecurityHeaders 与正文无关的安全头。
func setStaticSecurityHeaders(h http.Header) {
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
}
