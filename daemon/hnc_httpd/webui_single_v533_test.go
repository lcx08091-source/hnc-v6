package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// v5.33: WebUI 只剩 webroot/index.html 一份 —— 编进二进制的旧版远程界面
// (web/app.html / app.js / style.css)与 /static/ 路由已删。磁盘页面读不到
// (测试环境就是这样)时回 503 说明安装不完整, 不再退回旧页面。
// 「改动前会失败」: v5.32 对远程 / 本机浏览器回 200 + 旧版 app.html, /static/app.js 回 200。
func TestServeIndexNoEmbeddedFallback(t *testing.T) {
	s := newServer(t.TempDir())
	h := s.handler()
	for _, c := range []struct{ addr, ua string }{
		{"192.168.43.9:1234", "Mozilla/5.0 (Linux; Android 16) Chrome/130.0 Mobile Safari/537.36"},
		{"127.0.0.1:1234", "Mozilla/5.0 (Linux; Android 16) Chrome/130.0 Mobile Safari/537.36"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = c.addr
		req.Header.Set("User-Agent", c.ua)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "安装不完整") {
			t.Fatalf("%s: 磁盘页面缺失应回 503 说明, 得 %d %.80q", c.addr, rec.Code, rec.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	req.RemoteAddr = "192.168.43.9:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("/static/app.js 已删, 不应回 200")
	}
}

// v5.33: /api/stats 只剩一个统计源(iptables 采样)。source=dpi(v5.10 起, 界面从没用过)
// 与历史的 shadow 一样按 legacy 处理。「改动前会失败」: v5.32 回 source=dpi 的另一套聚合。
func TestStatsSingleSource(t *testing.T) {
	s := newServer(t.TempDir())
	for _, src := range []string{"dpi", "shadow", ""} {
		rec := httptest.NewRecorder()
		s.apiStats(rec, httptest.NewRequest(http.MethodGet, "/api/stats?range=today&source="+src, nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"source":"legacy"`) {
			t.Fatalf("source=%q: 应按 legacy 处理, 得 %d %.120s", src, rec.Code, rec.Body.String())
		}
	}
}
