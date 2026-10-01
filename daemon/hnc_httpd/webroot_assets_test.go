package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// v5.22: WebUI 拆分后的 /css/*.css、/js/*.js —— 免鉴权、类型正确、nosniff、
// Cache-Control: no-cache + Last-Modified(304 回源校验); 未登记的文件 404。
func TestWebUIAssetsServed(t *testing.T) {
	dir := t.TempDir()
	old := webrootDiskDir
	webrootDiskDir = dir + "/"
	t.Cleanup(func() { webrootDiskDir = old })
	for _, a := range webuiAssets {
		p := filepath.Join(dir, a)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("/* "+a+" */\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := newServer(t.TempDir()).handler()
	get := func(path string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "192.168.43.9:1234" // 远程、无 cookie
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	cases := map[string]string{"/js/core.js": "application/javascript", "/css/base.css": "text/css"}
	for _, a := range webuiAssets {
		if strings.HasSuffix(a, ".js") {
			cases["/"+a] = "application/javascript"
		} else {
			cases["/"+a] = "text/css"
		}
	}
	for path, want := range cases {
		rec := get(path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d (want 200 without auth)", path, rec.Code)
		}
		hd := rec.Header()
		if ct := hd.Get("Content-Type"); !strings.HasPrefix(ct, want) {
			t.Errorf("%s: Content-Type %q, want %s", path, ct, want)
		}
		if hd.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing nosniff", path)
		}
		if hd.Get("Cache-Control") != "no-cache" || hd.Get("Last-Modified") == "" {
			t.Errorf("%s: Cache-Control=%q Last-Modified=%q", path, hd.Get("Cache-Control"), hd.Get("Last-Modified"))
		}
		if !strings.Contains(rec.Body.String(), strings.TrimPrefix(path, "/")) {
			t.Errorf("%s: unexpected body %q", path, rec.Body.String())
		}
		if rec2 := get(path, map[string]string{"If-Modified-Since": hd.Get("Last-Modified")}); rec2.Code != http.StatusNotModified {
			t.Errorf("%s: revalidation status %d, want 304", path, rec2.Code)
		}
	}
	for _, path := range []string{"/js/evil.js", "/css/x.css", "/js/../index.html"} {
		if rec := get(path, nil); rec.Code == http.StatusOK {
			t.Errorf("%s: unregistered asset served", path)
		}
	}
}

// webuiAssets 与 webroot/index.html 实际引用的文件一致, 且都在仓库里。
func TestWebUIAssetsMatchIndex(t *testing.T) {
	idx, err := os.ReadFile("../../webroot/index.html")
	if err != nil {
		t.Skip("webroot/index.html not found: ", err)
	}
	re := regexp.MustCompile(`<(?:link rel="stylesheet" href|script src)="((?:css|js)/[^"]+)"`)
	var refs []string
	for _, m := range re.FindAllStringSubmatch(string(idx), -1) {
		refs = append(refs, m[1])
	}
	if strings.Join(refs, " ") != strings.Join(webuiAssets, " ") {
		t.Fatalf("index.html references %v, webuiAssets %v", refs, webuiAssets)
	}
	for _, a := range webuiAssets {
		if _, err := os.Stat(filepath.Join("../../webroot", a)); err != nil {
			t.Errorf("webroot/%s missing", a)
		}
	}
}
