package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"hnc.io/dpid/procfind"
)

// 1. 本机明文 http://127.0.0.1:8444 配对 Cookie Secure=false vs 远程 :8443 Secure=true 回归测试。
func TestAuthActionRC2_LoopbackPlainCookieVsRemoteTLS(t *testing.T) {
	// 陷阱守卫: 零参/单参原函数必须保持 Secure=true
	if c := issuedCookie("tok.secret"); !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("issuedCookie must stay Secure=true: %+v", c)
	}
	if c := clearCookie(); !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("clearCookie must stay Secure=true: %+v", c)
	}

	// 明文 loopback (IPv4 & IPv6) → Secure=false
	for _, addr := range []string{"127.0.0.1:54321", "[::1]:54321", "[::ffff:127.0.0.1]:54321"} {
		req := httptest.NewRequest(http.MethodPost, "/api/pair/verify", nil)
		req.RemoteAddr = addr
		req.TLS = nil
		if c := issuedCookieForReq(req, "tok.secret"); c.Secure {
			t.Fatalf("plain loopback %s issuedCookieForReq Secure=true, want false", addr)
		}
		if c := clearCookieForReq(req); c.Secure {
			t.Fatalf("plain loopback %s clearCookieForReq Secure=true, want false", addr)
		}
	}

	// TLS loopback / 远程非回环(含明文或 TLS) / nil req → 严格保持 Secure=true
	tlsLoop := httptest.NewRequest(http.MethodPost, "/api/pair/verify", nil)
	tlsLoop.RemoteAddr = "127.0.0.1:54321"
	tlsLoop.TLS = &tls.ConnectionState{}
	remotePlain := httptest.NewRequest(http.MethodPost, "/api/pair/verify", nil)
	remotePlain.RemoteAddr = "192.168.43.25:54321"
	for name, r := range map[string]*http.Request{
		"nil":         nil,
		"tlsLoopback": tlsLoop,
		"remote":      remotePlain,
	} {
		if c := issuedCookieForReq(r, "tok.secret"); !c.Secure {
			t.Fatalf("%s issuedCookieForReq Secure=false, want true", name)
		}
		if c := clearCookieForReq(r); !c.Secure {
			t.Fatalf("%s clearCookieForReq Secure=false, want true", name)
		}
	}

	// 端到端: 本机浏览器访问 http://127.0.0.1:8444/pair 配对 → 拿非 Secure Cookie → 带 Origin 访问受保护接口不再 302/401 死循环
	resetPairGuard(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"auth_required":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	writePending(t, dir, "246810", "sidLOOP8444A", time.Now().Unix()+120)
	s := newServer(dir)
	h := s.handler()

	pairReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8444/api/pair/verify", strings.NewReader("pin=246810"))
	pairReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pairReq.Header.Set("Origin", "http://127.0.0.1:8444")
	pairReq.RemoteAddr = "127.0.0.1:51000"
	pairRec := httptest.NewRecorder()
	h.ServeHTTP(pairRec, pairReq)
	if pairRec.Code != http.StatusFound {
		t.Fatalf("loopback pair status = %d, want 302: %s", pairRec.Code, pairRec.Body.String())
	}
	cookies := pairRec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != CookieName || cookies[0].Secure {
		t.Fatalf("loopback pair Set-Cookie = %+v, want single non-Secure hnc_token", cookies)
	}

	// 携带刚签发的 Cookie 从本机浏览器(带 Origin 头)访问受保护接口 /api/whoami
	apiReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8444/api/whoami", nil)
	apiReq.Header.Set("Origin", "http://127.0.0.1:8444")
	apiReq.RemoteAddr = "127.0.0.1:51001"
	apiReq.AddCookie(cookies[0])
	apiRec := httptest.NewRecorder()
	h.ServeHTTP(apiRec, apiReq)
	if apiRec.Code != http.StatusOK {
		t.Fatalf("authenticated loopback browser GET /api/whoami = %d, want 200: %s", apiRec.Code, apiRec.Body.String())
	}

	// 本机明文登出同样下发非 Secure 清除 Cookie 并吊销服务端 token
	logoutReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8444/api/logout", nil)
	logoutReq.RemoteAddr = "127.0.0.1:51002"
	logoutReq.AddCookie(cookies[0])
	logoutRec := httptest.NewRecorder()
	h.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout status = %d", logoutRec.Code)
	}
	if lc := logoutRec.Result().Cookies(); len(lc) != 1 || lc[0].Secure || lc[0].MaxAge != -1 {
		t.Fatalf("loopback logout cookie = %+v, want Secure=false MaxAge=-1", lc)
	}

	// writePairSuccess: 陈旧 pair_success.tmp GC 与 rename 失败清理
	staleTmp := filepath.Join(dir, "run", "pair_success.tmp")
	if err := os.WriteFile(staleTmp, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(staleTmp, oldTime, oldTime)
	// 把目标路径占成非空目录迫使 os.Rename 失败, 验证失败后不留 pair_success.tmp
	badFinal := filepath.Join(dir, "run", "pair_success.sidFAILDIR01")
	if err := os.MkdirAll(filepath.Join(badFinal, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writePairSuccess(dir, "sidFAILDIR01", "tid1", "Safari on iPhone"); err == nil {
		t.Fatal("expected writePairSuccess rename into non-empty dir to fail")
	}
	if _, err := os.Stat(staleTmp); !os.IsNotExist(err) {
		t.Fatalf("pair_success.tmp must be cleaned up after failure, stat err=%v", err)
	}
}

// 2. CSP 允许 blob: 本地选图壁纸预览。
func TestAuthActionRC2_CSPAllowsBlobWallpaper(t *testing.T) {
	s := newServer(t.TempDir())
	h := s.handler()
	for _, p := range []string{"/pair", "/"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.RemoteAddr = "127.0.0.1:52000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "img-src 'self' data: blob:;") {
			t.Fatalf("%s CSP = %q, want img-src 'self' data: blob:;", p, csp)
		}
	}
}

// 3. Apple Safari <=398 天(397 天)自签证书、IPv6 ::1 SAN 与旧 10 年证书自动轮换。
func TestAuthActionRC2_TLS397DaysSANsAndLegacyRotation(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "httpd_cert.pem")
	keyPath := filepath.Join(dir, "httpd_key.pem")

	if err := ensureCert(certPath, keyPath, "192.168.43.1"); err != nil {
		t.Fatalf("ensureCert: %v", err)
	}

	parseCert := func() *x509.Certificate {
		t.Helper()
		b, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			t.Fatal("pem decode failed")
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	c1 := parseCert()
	span := c1.NotAfter.Sub(c1.NotBefore)
	if span > 398*24*time.Hour || span < 396*24*time.Hour {
		t.Fatalf("cert span = %v (%.2f days), want ~397 days (<=398d Apple limit)", span, span.Hours()/24)
	}
	hasIP := func(c *x509.Certificate, want net.IP) bool {
		for _, ip := range c.IPAddresses {
			if ip.Equal(want) {
				return true
			}
		}
		return false
	}
	for _, want := range []net.IP{net.ParseIP("192.168.43.1"), net.IPv4(127, 0, 0, 1), net.IPv6loopback} {
		if !hasIP(c1, want) {
			t.Fatalf("cert IP SANs %v missing %s", c1.IPAddresses, want)
		}
	}

	// 再次调用应复用同一张 397 天证书
	if err := ensureCert(certPath, keyPath, "192.168.43.1"); err != nil {
		t.Fatal(err)
	}
	if c2 := parseCert(); c2.SerialNumber.Cmp(c1.SerialNumber) != 0 {
		t.Fatal("valid 397-day cert was unexpectedly regenerated")
	}

	// 构造存量旧版 10 年证书(>825 天), 验证升级后首次 ensureCert 自动轮换重签
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	legacySerial := big.NewInt(987654321)
	now := time.Now()
	legacyTmpl := x509.Certificate{
		SerialNumber:          legacySerial,
		Subject:               pkix.Name{CommonName: "Legacy 10y Cert"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &legacyTmpl, &legacyTmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	if reason := certNeedsRegen(certPath, "0.0.0.0"); !strings.Contains(reason, "825") {
		t.Fatalf("certNeedsRegen on 10-year cert = %q, want >825-day reason", reason)
	}
	if err := ensureCert(certPath, keyPath, "0.0.0.0"); err != nil {
		t.Fatalf("ensureCert rotation failed: %v", err)
	}
	rotated := parseCert()
	if rotated.SerialNumber.Cmp(legacySerial) == 0 || rotated.NotAfter.Sub(rotated.NotBefore) > 398*24*time.Hour {
		t.Fatalf("legacy 10-year cert was not rotated to 397-day cert (span=%v)", rotated.NotAfter.Sub(rotated.NotBefore))
	}
	if !hasIP(rotated, net.IPv6loopback) {
		t.Fatalf("rotated cert missing ::1 SAN: %v", rotated.IPAddresses)
	}
}

// 4. remoteListener "auto"/"0.0.0.0" 双栈监听(同时可达 127.0.0.1 与 [::1])。
func TestAuthActionRC2_RemoteListenerDualStack(t *testing.T) {
	dir := t.TempDir()
	rlRules(t, dir, `{"remote_enabled":true,"auth_required":true}`)
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "dual-ok") })
	rl := newRemoteListener(dir, "auto", 0, 0, false, h)
	rl.sync()
	defer rl.stop("test")

	addr := rl.Addr()
	if addr == "" {
		t.Fatal("remoteListener failed to start with bind=auto")
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}

	certPEM, err := os.ReadFile(filepath.Join(dir, "data", "httpd_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to load generated cert into RootCAs")
	}
	// 不开 InsecureSkipVerify, 直接校验证书 SAN(127.0.0.1 与 ::1)!
	cl := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		Timeout:   3 * time.Second,
	}

	resp4, err := cl.Get("https://127.0.0.1:" + portStr + "/")
	if err != nil {
		t.Fatalf("IPv4 HTTPS GET failed: %v", err)
	}
	b4, _ := io.ReadAll(resp4.Body)
	resp4.Body.Close()
	if string(b4) != "dual-ok" {
		t.Fatalf("IPv4 body = %q", b4)
	}

	// 若宿主环境支持 IPv6 loopback, 同一端口必须能经 [::1] 通过完整 TLS SAN 校验连接
	if probe, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		probe.Close()
		resp6, err := cl.Get("https://[::1]:" + portStr + "/")
		if err != nil {
			t.Fatalf("IPv6 HTTPS GET on dual-stack listener failed: %v", err)
		}
		b6, _ := io.ReadAll(resp6.Body)
		resp6.Body.Close()
		if string(b6) != "dual-ok" {
			t.Fatalf("IPv6 body = %q", b6)
		}
	}
}

// 5. webui_access 纯 Go IPv6 邻居查询 + 拦截上游公共 Wi-Fi(wlan0)/非热点下游子网越权访问。
func TestAuthActionRC2_WebUIAccessWANGuardAndPureGoNeigh(t *testing.T) {
	// 5a: 验证生产路径(neighV6Dump == nil)走纯 Go neighV6Native, 不跑外部命令
	oldDump, oldNative, oldTTL := neighV6Dump, neighV6Native, neighCacheTTL
	neighV6Dump = nil
	nativeCalled := 0
	neighV6Native = func(into map[string]string) {
		nativeCalled++
		into["fd00:43::88"] = "aa:bb:cc:11:22:88"
	}
	neighCacheTTL = 0
	neighMu.Lock()
	neighSnap = nil
	neighMu.Unlock()
	t.Cleanup(func() {
		neighV6Dump, neighV6Native, neighCacheTTL = oldDump, oldNative, oldTTL
		neighMu.Lock()
		neighSnap = nil
		neighMu.Unlock()
	})

	if got := neighborMAC(net.ParseIP("fd00:43::88")); got != "aa:bb:cc:11:22:88" || nativeCalled == 0 {
		t.Fatalf("pure-Go neighV6Native got=%q called=%d", got, nativeCalled)
	}

	// 5b: 验证上游公共 Wi-Fi wlan0 与非热点下游子网拦截
	mustCIDR := func(s string) *net.IPNet {
		ip, ipn, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		ipn.IP = ip
		return ipn
	}
	oldIfaces, oldBoundTTL := webuiListIfaces, webuiBoundaryTTL
	webuiListIfaces = func() []webuiIfaceInfo {
		return []webuiIfaceInfo{
			{Name: "wlan0", Up: true, Addrs: []*net.IPNet{mustCIDR("10.18.0.55/24"), mustCIDR("2409:8888::55/64")}},
			{Name: "rmnet_data0", Up: true, Addrs: []*net.IPNet{mustCIDR("100.64.1.9/24")}},
			{Name: "ap0", Up: true, Addrs: []*net.IPNet{mustCIDR("192.168.43.1/24"), mustCIDR("fd00:43::1/64")}},
		}
	}
	webuiBoundaryTTL = 0
	t.Cleanup(func() {
		webuiListIfaces, webuiBoundaryTTL = oldIfaces, oldBoundTTL
		webuiBoundaryMu.Lock()
		webuiBoundarySnap = map[string]webuiBoundaryEntry{}
		webuiBoundaryMu.Unlock()
	})

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:ap0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	detJSON := fmt.Sprintf(`{"iface":"ap0","upstream":"wlan0","ts":%d}`, time.Now().Unix())
	if err := os.WriteFile(filepath.Join(dir, "run", "iface_detect.json"), []byte(detJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	s := newServer(dir)
	h := s.handler()
	doReq := func(remoteAddr, localAddr string) int {
		req := httptest.NewRequest(http.MethodGet, "/pair", nil)
		req.RemoteAddr = remoteAddr
		if localAddr != "" {
			tcpAddr, err := net.ResolveTCPAddr("tcp", localAddr)
			if err != nil {
				t.Fatal(err)
			}
			req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, tcpAddr))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// 公共 Wi-Fi wlan0 上的攻击者请求手机 wlan0 IP :8443 → 403
	if code := doReq("10.18.0.99:40000", "10.18.0.55:8443"); code != http.StatusForbidden {
		t.Fatalf("WAN wlan0 target IP must be rejected with 403, got %d", code)
	}
	// 蜂窝 rmnet_data0 目标 IP → 403
	if code := doReq("192.168.43.20:40000", "100.64.1.9:8443"); code != http.StatusForbidden {
		t.Fatalf("cell rmnet_data0 target IP must be rejected with 403, got %d", code)
	}
	// 无 LocalAddr 但源 IP 不在活跃热点下游子网(192.168.43.0/24 / fd00:43::/64) → 403
	if code := doReq("10.18.0.99:40000", ""); code != http.StatusForbidden {
		t.Fatalf("non-downstream IPv4 source must be rejected when hotspot active, got %d", code)
	}
	if code := doReq("[2409:8888::99]:40000", ""); code != http.StatusForbidden {
		t.Fatalf("non-downstream IPv6 source must be rejected when hotspot active, got %d", code)
	}
	// 活跃热点下游客户端(IPv4 与 IPv6) → 200 放行
	if code := doReq("192.168.43.20:40000", "192.168.43.1:8443"); code != http.StatusOK {
		t.Fatalf("downstream hotspot IPv4 client got %d, want 200", code)
	}
	if code := doReq("[fd00:43::88]:40000", "[fd00:43::1]:8443"); code != http.StatusOK {
		t.Fatalf("downstream hotspot IPv6 client got %d, want 200", code)
	}
	// 本机 loopback → 永远 200 放行
	if code := doReq("127.0.0.1:40000", "127.0.0.1:8444"); code != http.StatusOK {
		t.Fatalf("loopback client got %d, want 200", code)
	}
}

// 6. 纯 Go apiRunStatus(修复无 awk 时 VmRSS=0)与纯 Go 在线更新 DPI 规则(SHA-256 + 防 ZipSlip)。
func TestAuthActionRC2_PureGoRunStatusAndDPIRulesUpdate(t *testing.T) {
	// 6a: apiRunStatus 纯 Go 解析 VmRSS 与运行状态
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:ap0\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "hotspotd.pid"), []byte("2468\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "watchdog.pid"), []byte("1357\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "watchdog.heartbeat"), []byte(strconv.FormatInt(now.Unix()-12, 10)), 0o644)

	fakeProc := map[string]string{
		"/proc/2468/stat":    "2468 (hotspotd) S 1 0 0 0 0 0 0 0 0 0 5 2 0 0 0 0 0 0 200",
		"/proc/2468/cmdline": "/data/local/hnc/bin/hotspotd\x00",
		"/proc/2468/status":  "Name:\thotspotd\nState:\tS (sleeping)\nVmSize:\t   32768 kB\nVmRSS:\t   14336 kB\n",
		"/proc/1357/stat":    "1357 (hnc_watchdog) S 1 0 0 0 0 0 0 0 0 0 3 1 0 0 0 0 0 0 150",
		"/proc/1357/cmdline": "/data/local/hnc/bin/hnc_watchdog\x00",
	}
	oldProc, oldTC, oldIpt := watchdogProcFS, runStatusTCFn, runStatusIptFn
	watchdogProcFS = func() procfind.FS {
		return procfind.FS{
			ReadFile: func(p string) ([]byte, error) {
				if v, ok := fakeProc[p]; ok {
					return []byte(v), nil
				}
				if strings.HasPrefix(p, "/proc/") {
					return nil, os.ErrNotExist
				}
				return os.ReadFile(p)
			},
			ReadDir: func(string) ([]string, error) { return []string{"2468", "1357"}, nil },
		}
	}
	runStatusTCFn = func(iface string) int {
		if iface == "ap0" {
			return 18
		}
		return 0
	}
	runStatusIptFn = func() int { return 7 }
	t.Cleanup(func() {
		watchdogProcFS, runStatusTCFn, runStatusIptFn = oldProc, oldTC, oldIpt
	})

	srv := newServer(dir)
	rec := httptest.NewRecorder()
	srv.apiRunStatus(rec, httptest.NewRequest(http.MethodGet, "/api/run_status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("apiRunStatus status = %d", rec.Code)
	}
	var rs struct {
		Hotspotd      string `json:"hotspotd"`
		HotspotdPID   int    `json:"hotspotd_pid"`
		HotspotdRSSKB int    `json:"hotspotd_rss_kb"`
		TCRules       int    `json:"tc_rules"`
		IptRules      int    `json:"ipt_rules"`
		Watchdog      int    `json:"watchdog"`
		WatchdogKind  string `json:"watchdog_kind"`
		WatchdogPID   int    `json:"watchdog_pid"`
		Iface         string `json:"iface"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rs); err != nil {
		t.Fatal(err)
	}
	if rs.Hotspotd != "up" || rs.HotspotdPID != 2468 || rs.HotspotdRSSKB != 14336 ||
		rs.TCRules != 18 || rs.IptRules != 7 || rs.Watchdog != 1 || rs.WatchdogKind != "go" ||
		rs.WatchdogPID != 1357 || rs.Iface != "ap0" {
		t.Fatalf("unexpected apiRunStatus payload: %+v", rs)
	}

	// 6b: 纯 Go actionDPIRulesUpdate(HTTPS TLS 模拟服 + SHA-256 + ZipSlip 拦截 + 正常落盘与重绑)
	buildZip := func(entries map[string]string) ([]byte, string) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for name, content := range entries {
			w, err := zw.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte(content)); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		raw := buf.Bytes()
		sum := sha256.Sum256(raw)
		return raw, hex.EncodeToString(sum[:])
	}

	var curZip []byte
	var curSHA string
	var srvURL string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"tag_name": "v6.2.0-rc2",
				"assets": []map[string]string{
					{"name": "dpi-rules.zip", "browser_download_url": srvURL + "/dl/dpi-rules.zip"},
					{"name": "dpi-rules.zip.sha256", "browser_download_url": srvURL + "/dl/dpi-rules.zip.sha256"},
				},
			})
		case "/dl/dpi-rules.zip":
			_, _ = w.Write(curZip)
		case "/dl/dpi-rules.zip.sha256":
			_, _ = io.WriteString(w, curSHA+"  dpi-rules.zip\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	srvURL = ts.URL

	oldURL, oldClient := dpiRulesReleaseURL, dpiRulesHTTPClient
	dpiRulesReleaseURL = ts.URL + "/releases/latest"
	dpiRulesHTTPClient = ts.Client()
	t.Cleanup(func() {
		dpiRulesReleaseURL, dpiRulesHTTPClient = oldURL, oldClient
	})

	updDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(updDir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(updDir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(updDir, "run", "hotspot_iface"), []byte("ap0\n"), 0o644)
	rebindMarker := filepath.Join(updDir, "run", "rebind.arg")
	rebindScript := "#!" + testShellBin() + "\nprintf '%s' \"$1\" > \"" + rebindMarker + "\"\n"
	if err := os.WriteFile(filepath.Join(updDir, "bin", "dpi_rebind.sh"), []byte(rebindScript), 0o755); err != nil {
		t.Fatal(err)
	}
	// 同时放入带真实签名头的生产 dpi_rules_update.sh 副本, 验证即使文件存在也走纯 Go 路径而不依赖 curl/unzip
	_ = os.WriteFile(filepath.Join(updDir, "bin", "dpi_rules_update.sh"), []byte("#!/system/bin/sh\n# dpi_rules_update.sh — DPI\nexit 99\n"), 0o755)

	// check
	chk := actionDPIRulesUpdate(updDir, map[string]string{"mode": "check"})
	if !chk.OK || !strings.Contains(chk.Detail, `"update_available":"yes"`) || !strings.Contains(chk.Detail, `"remote":"v6.2.0-rc2"`) {
		t.Fatalf("check = %+v", chk)
	}

	// ZipSlip 路径穿越包必须被整包拒绝
	curZip, curSHA = buildZip(map[string]string{
		"../../evil.json": `{"rules_version":"evil","rules":[]}`,
		"dpi_rules.json":  `{"rules_version":"2026.11.22","rules":[]}`,
	})
	if res := actionDPIRulesUpdate(updDir, map[string]string{"mode": "install"}); res.OK || !strings.Contains(res.Detail, "unsafe zip entry") {
		t.Fatalf("ZipSlip archive must be rejected, got %+v", res)
	}

	// SHA-256 不匹配必须被拒绝
	validRules := `{"schema_version":"1.0","rules_version":"2026.11.22-rc2","rules":[{"id":"wechat","app":"WeChat","domains":["weixin.qq.com"]}]}`
	curZip, _ = buildZip(map[string]string{"sub/dpi_rules.json": validRules})
	curSHA = strings.Repeat("0", 64)
	if res := actionDPIRulesUpdate(updDir, map[string]string{"mode": "install"}); res.OK || !strings.Contains(res.Detail, "sha256 mismatch") {
		t.Fatalf("SHA256 mismatch must be rejected, got %+v", res)
	}

	// 合法 ZIP 安装 → 原子落盘 97-online-update.json + 版本记录 + 触发 dpi_rebind.sh ap0
	curZip, curSHA = buildZip(map[string]string{"sub/dpi_rules.json": validRules})
	ins := actionDPIRulesUpdate(updDir, map[string]string{"mode": "install"})
	if !ins.OK || !strings.Contains(ins.Detail, "2026.11.22-rc2") {
		t.Fatalf("install failed: %+v", ins)
	}
	installedBytes, err := os.ReadFile(filepath.Join(updDir, "etc", "dpi_rules.d", "97-online-update.json"))
	if err != nil || string(installedBytes) != validRules {
		t.Fatalf("installed 97-online-update.json mismatch: err=%v body=%q", err, string(installedBytes))
	}
	verBytes, err := os.ReadFile(filepath.Join(updDir, "etc", "dpi_rules_online.version"))
	if err != nil || string(verBytes) != "2026.11.22-rc2" {
		t.Fatalf("dpi_rules_online.version = %q, err=%v", string(verBytes), err)
	}
	rebindArg, err := os.ReadFile(rebindMarker)
	if err != nil || string(rebindArg) != "ap0" {
		t.Fatalf("dpi_rebind.sh not triggered with ap0: arg=%q err=%v", string(rebindArg), err)
	}
}
