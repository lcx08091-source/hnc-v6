// security_v522_test.go — v5.22 安全加固测试:
// PIN 限流/锁定/指数退避时序、配对失败审计/告警/熔断、恒定时间比对路径、
// WebUI 访问白名单(IPv4/IPv6、MAC→IP 邻居表 fixture、自锁拒绝)、安全响应头。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ── fake clock ────────────────────────────────────────────────

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func withFakeClock(t *testing.T) *fakeClock {
	t.Helper()
	c := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	old := rlNow
	rlNow = c.now
	t.Cleanup(func() { rlNow = old })
	return c
}

func burnAttempts(t *testing.T, rl *RateLimiter, ip string) int64 {
	t.Helper()
	for i := 1; i <= rlPinAttemptsMax-1; i++ {
		if ok, _, rem := rl.ConsumePinAttempt(ip); !ok || rem != rlPinAttemptsMax-i {
			t.Fatalf("attempt %d rejected early (rem %d)", i, rem)
		}
	}
	ok, retry, _ := rl.ConsumePinAttempt(ip)
	if ok {
		t.Fatalf("attempt %d must trigger lockout", rlPinAttemptsMax)
	}
	return retry
}

// 5 次 / 10 分钟 / IP: 慢速(每 2 分钟一次)也会累计到锁定。
func TestPinWindowTenMinutesCatchesSlowBruteforce(t *testing.T) {
	c := withFakeClock(t)
	rl := NewRateLimiter()
	for i := 1; i <= rlPinAttemptsMax-1; i++ {
		if ok, _, _ := rl.ConsumePinAttempt("10.0.0.5"); !ok {
			t.Fatalf("attempt %d rejected", i)
		}
		c.advance(2 * time.Minute)
	}
	if ok, _, _ := rl.ConsumePinAttempt("10.0.0.5"); ok {
		t.Fatal("5th attempt within 10 minutes must lock (old 1-minute window let slow guessing through)")
	}
}

// 锁定时长精确 + 到期解锁 + 指数退避 + 封顶。
func TestPinLockoutTimingExponentialBackoff(t *testing.T) {
	c := withFakeClock(t)
	rl := NewRateLimiter()
	ip := "192.168.43.50"
	want := int64(rlPinLockDuration.Seconds())
	for round := 1; round <= 7; round++ {
		retry := burnAttempts(t, rl, ip)
		if retry != want {
			t.Fatalf("round %d: lock %ds, want %ds", round, retry, want)
		}
		// 锁定期内: 入口检查与消费都拒, retry 递减
		c.advance(time.Duration(retry-1) * time.Second)
		if ok, r := rl.CheckPinVerify(ip); ok || r != 1 {
			t.Fatalf("round %d: 1s before unlock CheckPinVerify=(%v,%d), want (false,1)", round, ok, r)
		}
		if ok, _, _ := rl.ConsumePinAttempt(ip); ok {
			t.Fatalf("round %d: consume allowed while locked", round)
		}
		c.advance(1 * time.Second)
		if ok, _ := rl.CheckPinVerify(ip); !ok {
			t.Fatalf("round %d: still locked at expiry", round)
		}
		// 跳出全局 1 分钟窗口, 避免与全局上限互相干扰
		c.advance(rlPinGlobalWindow)
		want *= 2
		if max := int64(rlPinLockMax.Seconds()); want > max {
			want = max
		}
	}
}

// 退避记忆不被 GC 回收(否则等 15 分钟 TTL 就能清零退避)。
func TestPinBackoffSurvivesGC(t *testing.T) {
	c := withFakeClock(t)
	rl := NewRateLimiter()
	ip := "fd00::50"
	first := burnAttempts(t, rl, ip)
	c.advance(time.Duration(first)*time.Second + time.Hour) // 远超 rlEntryTTL
	rl.gc()
	if rl.Size() != 1 {
		t.Fatalf("entry with backoff history GC'd (size=%d)", rl.Size())
	}
	if second := burnAttempts(t, rl, ip); second != 2*first {
		t.Fatalf("second lock %ds, want %ds (backoff lost)", second, 2*first)
	}
	// 记忆期过后才回收
	c.advance(rlPinBackoffMemory + 2*rlPinLockDuration*2)
	rl.gc()
	if rl.Size() != 0 {
		t.Fatalf("entry not reclaimed after backoff memory window (size=%d)", rl.Size())
	}
}

// 成功配对清零退避。
func TestPinResetClearsBackoff(t *testing.T) {
	c := withFakeClock(t)
	rl := NewRateLimiter()
	ip := "10.9.9.9"
	first := burnAttempts(t, rl, ip)
	c.advance(time.Duration(first)*time.Second + rlPinGlobalWindow)
	rl.ResetPin(ip)
	if again := burnAttempts(t, rl, ip); again != first {
		t.Fatalf("after ResetPin lock %ds, want base %ds", again, first)
	}
}

// 全局上限独立 1 分钟窗口, 跨源地址生效, 窗口滑过后恢复。
func TestPinGlobalCapWindowSlides(t *testing.T) {
	c := withFakeClock(t)
	rl := NewRateLimiter()
	for i := 0; i < rlPinGlobalMaxPerWindow; i++ {
		if ok, _, _ := rl.ConsumePinAttempt(fmt.Sprintf("10.1.%d.1", i)); !ok {
			t.Fatalf("attempt %d rejected before cap", i)
		}
	}
	ok, retry, _ := rl.ConsumePinAttempt("10.2.0.1")
	if ok || retry < 1 || retry > int64(rlPinGlobalWindow.Seconds()) {
		t.Fatalf("over cap = (%v,%d)", ok, retry)
	}
	if _, gh := rl.PinCounters(); gh != 1 {
		t.Fatalf("global hit counter = %d, want 1", gh)
	}
	c.advance(rlPinGlobalWindow)
	if ok, _, _ := rl.ConsumePinAttempt("10.2.0.1"); !ok {
		t.Fatal("global window did not slide")
	}
}

// ── 配对 handler: 审计 / 告警 / 熔断 / expiry 上界 ─────────────

func resetPairGuard(t *testing.T) {
	t.Helper()
	old := pairGuard
	pairGuard = &pairGuardState{sidFails: map[string]int{}}
	t.Cleanup(func() { pairGuard = old })
}

func writePending(t *testing.T, dir, pin, sid string, expiry int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o700); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("%s\n%s\n%d\n", pin, sid, expiry)
	if err := os.WriteFile(filepath.Join(dir, "run", "pair_pending"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func postPin(s *server, ip, pin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/pair/verify", strings.NewReader("pin="+pin))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip + ":40000"
	rec := httptest.NewRecorder()
	s.handlePairVerify(rec, req)
	return rec
}

func secReadFile(t *testing.T, p string) string {
	t.Helper()
	b, _ := os.ReadFile(p)
	return string(b)
}

func TestPairVerifyFailuresAuditedAlertedAndBurned(t *testing.T) {
	resetPairGuard(t)
	dir := t.TempDir()
	writePending(t, dir, "123456", "sidABCDEFGH", time.Now().Unix()+120)
	s := newServer(dir)

	// 轮换源地址(每个只猜 1 次, per-IP 锁永远不触发) —— 熔断仍在第 10 次生效
	var last *httptest.ResponseRecorder
	for i := 0; i < pairBurnAfter; i++ {
		last = postPin(s, fmt.Sprintf("192.168.43.%d", 100+i), fmt.Sprintf("%06d", 900000+i))
		if i < pairBurnAfter-1 && last.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: status %d, want 400 wrong pin", i, last.Code)
		}
	}
	if last.Code != http.StatusGone {
		t.Fatalf("attempt %d: status %d, want 410 (pairing code burned)", pairBurnAfter, last.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "pair_pending")); !os.IsNotExist(err) {
		t.Fatal("pair_pending must be deleted after burn")
	}
	// 正确 PIN 也不能再用
	if rec := postPin(s, "192.168.43.200", "123456"); rec.Code == http.StatusFound {
		t.Fatal("burned PIN still accepted")
	}

	audit := secReadFile(t, filepath.Join(dir, "logs", "audit.log"))
	if n := strings.Count(audit, "action=pair_verify ip=192.168.43.1"); n < pairBurnAfter {
		t.Fatalf("audit has %d failed pair_verify lines, want >= %d:\n%s", n, pairBurnAfter, audit)
	}
	if !strings.Contains(audit, "wrong pin") || !strings.Contains(audit, "pairing code burned") {
		t.Fatalf("audit missing reasons:\n%s", audit)
	}
	if strings.Contains(audit, "123456") {
		t.Fatal("audit must never contain the PIN")
	}
	alerts := secReadFile(t, filepath.Join(dir, "run", "alerts.jsonl"))
	if c := strings.Count(alerts, `"kind":"auth_bruteforce"`); c != 1 {
		t.Fatalf("auth_bruteforce alerts = %d, want exactly 1 per window:\n%s", c, alerts)
	}
}

func TestPairVerifyIPLockoutAuditedOnce(t *testing.T) {
	resetPairGuard(t)
	dir := t.TempDir()
	writePending(t, dir, "123456", "sidLOCKOUT01", time.Now().Unix()+120)
	s := newServer(dir)
	ip := "192.168.43.77"
	for i := 0; i < rlPinAttemptsMax-1; i++ {
		if rec := postPin(s, ip, "000000"); rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d status %d", i, rec.Code)
		}
	}
	rec := postPin(s, ip, "000000")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "600" {
		t.Fatalf("lockout status=%d retry=%q, want 429/600", rec.Code, rec.Header().Get("Retry-After"))
	}
	// 锁定期间继续撞: 入口短路, 不逐条写审计
	for i := 0; i < 5; i++ {
		postPin(s, ip, "000000")
	}
	audit := secReadFile(t, filepath.Join(dir, "logs", "audit.log"))
	if c := strings.Count(audit, "ip locked out for 600s"); c != 1 {
		t.Fatalf("lockout audit lines = %d, want 1:\n%s", c, audit)
	}
	if !strings.Contains(secReadFile(t, filepath.Join(dir, "run", "alerts.jsonl")), `"ip":"192.168.43.77"`) {
		t.Fatal("lockout alert missing ip")
	}
	// 正确 PIN 在锁定期内同样被拒(先查锁再比对)
	if rec := postPin(s, ip, "123456"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("correct pin during lockout: %d, want 429", rec.Code)
	}
}

func TestPairPendingExpiryUpperBound(t *testing.T) {
	dir := t.TempDir()
	writePending(t, dir, "123456", "sidFARFUTURE", time.Now().Unix()+3600)
	if _, err := readPairPending(dir); err == nil || !strings.Contains(err.Error(), "too far") {
		t.Fatalf("err = %v, want expiry-too-far rejection", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "pair_pending")); !os.IsNotExist(err) {
		t.Fatal("over-long pair_pending must be removed")
	}
	writePending(t, dir, "123456", "sidNORMAL0001", time.Now().Unix()+120)
	if _, err := readPairPending(dir); err != nil {
		t.Fatalf("normal 120s pending rejected: %v", err)
	}
}

// 恒定时间比对路径: PIN 与 local admin secret 都必须走 subtle.ConstantTimeCompare,
// 不允许出现 == 直接比较(源码级守卫, 防回归)。
func TestConstantTimeComparePaths(t *testing.T) {
	pairSrc := secReadFile(t, "pair.go")
	if !strings.Contains(pairSrc, "subtle.ConstantTimeCompare([]byte(submitted), []byte(pending.PIN))") {
		t.Fatal("PIN comparison must use subtle.ConstantTimeCompare")
	}
	if regexp.MustCompile(`submitted\s*[!=]=\s*pending\.PIN|pending\.PIN\s*[!=]=\s*submitted`).MatchString(pairSrc) {
		t.Fatal("PIN compared with ==/!= (timing leak)")
	}
	mwSrc := secReadFile(t, "middleware.go")
	if !strings.Contains(mwSrc, "subtle.ConstantTimeCompare([]byte(got), []byte(want))") {
		t.Fatal("local admin secret must use subtle.ConstantTimeCompare")
	}
	// 行为: 前缀相同 / 长度相同的错误 PIN 一律拒
	resetPairGuard(t)
	dir := t.TempDir()
	writePending(t, dir, "123456", "sidCTCOMPARE", time.Now().Unix()+120)
	s := newServer(dir)
	for i, pin := range []string{"123457", "023456", "12345 "} {
		if rec := postPin(s, fmt.Sprintf("10.3.0.%d", i+1), pin); rec.Code == http.StatusFound {
			t.Fatalf("pin %q accepted", pin)
		}
	}
	if rec := postPin(s, "10.3.0.9", "123456"); rec.Code != http.StatusFound {
		t.Fatalf("correct pin status %d, want 302", rec.Code)
	}
	if !strings.Contains(secReadFile(t, filepath.Join(dir, "logs", "audit.log")), "result=ok detail=paired") {
		t.Fatal("successful pairing not audited")
	}
}

// ── WebUI 访问白名单 ───────────────────────────────────────────

func withNeighFixture(t *testing.T) {
	t.Helper()
	oldArp, oldV6, oldTTL := neighArpPath, neighV6Dump, neighCacheTTL
	neighArpPath = "testdata/webui/arp"
	neighV6Dump = func() (string, error) {
		b, err := os.ReadFile("testdata/webui/neigh6")
		return string(b), err
	}
	neighCacheTTL = 0
	neighMu.Lock()
	neighSnap = nil
	neighMu.Unlock()
	t.Cleanup(func() {
		neighArpPath, neighV6Dump, neighCacheTTL = oldArp, oldV6, oldTTL
		neighMu.Lock()
		neighSnap = nil
		neighMu.Unlock()
	})
}

func TestNeighborMACResolution(t *testing.T) {
	withNeighFixture(t)
	cases := map[string]string{
		"192.168.43.7":              "aa:bb:cc:dd:ee:07",
		"192.168.43.8":              "aa:bb:cc:dd:ee:08", // 大写归一
		"192.168.43.9":              "",                  // flags 0x0(incomplete)
		"192.168.43.250":            "",
		"2408:8456:1234::7":         "aa:bb:cc:dd:ee:07",
		"fe80::a8bb:ccff:fedd:ee07": "aa:bb:cc:dd:ee:07",
		"2408:8456:1234::99":        "", // FAILED
	}
	for ip, want := range cases {
		if got := neighborMAC(net.ParseIP(ip)); got != want {
			t.Errorf("neighborMAC(%s) = %q, want %q", ip, got, want)
		}
	}
}

func TestClientIPNormalization(t *testing.T) {
	cases := map[string]string{
		"192.168.43.7:5000":                     "192.168.43.7",
		"[::ffff:192.168.43.7]:5000":            "192.168.43.7",
		"[fe80::a8bb:ccff:fedd:ee07%wlan2]:443": "fe80::a8bb:ccff:fedd:ee07",
		"[2408:8456:1234::7]:1":                 "2408:8456:1234::7",
		"[::1]:8444":                            "::1",
	}
	for in, want := range cases {
		if got := clientIP(in); got == nil || got.String() != want {
			t.Errorf("clientIP(%q) = %v, want %s", in, got, want)
		}
	}
}

func TestWebUIAllowlistDecisionV4V6(t *testing.T) {
	withNeighFixture(t)
	dir := t.TempDir()
	// 缺省(无文件) = all
	if !webuiAccessDecision(dir, net.ParseIP("192.168.43.250")) {
		t.Fatal("default mode must allow LAN clients")
	}
	if err := saveWebUIAccess(dir, webuiAccessCfg{Mode: webuiModeAllowlist,
		Macs: []string{"aa:bb:cc:dd:ee:07", "192.168.43.20", "fd00::20"}}); err != nil {
		t.Fatal(err)
	}
	allow := []string{
		"192.168.43.7",              // v4 经 MAC
		"192.168.43.20",             // v4 直接 IP
		"2408:8456:1234::7",         // v6 全局地址经 MAC
		"fe80::a8bb:ccff:fedd:ee07", // v6 链路本地经 MAC
		"fd00::20",                  // v6 直接 IP
		"127.0.0.1", "::1",          // loopback 永远放行
	}
	for _, ip := range allow {
		if !webuiAccessDecision(dir, net.ParseIP(ip)) {
			t.Errorf("%s must be allowed", ip)
		}
	}
	deny := []string{"192.168.43.8", "192.168.43.250", "2408:8456:1234::66", "fd00::21", "10.0.0.1"}
	for _, ip := range deny {
		if webuiAccessDecision(dir, net.ParseIP(ip)) {
			t.Errorf("%s must be denied", ip)
		}
	}
	// v4-mapped 形式的 RemoteAddr 走同一判定
	if !webuiAccessDecision(dir, clientIP("[::ffff:192.168.43.20]:1")) {
		t.Error("v4-mapped allowlisted IP denied")
	}
}

func TestWebUILocalOnlyAndCorruptFailClosed(t *testing.T) {
	dir := t.TempDir()
	if err := saveWebUIAccess(dir, webuiAccessCfg{Mode: webuiModeLocalOnly}); err != nil {
		t.Fatal(err)
	}
	if webuiAccessDecision(dir, net.ParseIP("192.168.43.7")) || !webuiAccessDecision(dir, net.ParseIP("127.0.0.1")) {
		t.Fatal("local_only: remote must be denied, loopback allowed")
	}
	// 损坏 → local_only
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(webuiAccessPath(dir), []byte(`{"mode":"allowlist","macs":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := loadWebUIAccess(dir); c.Mode != webuiModeLocalOnly {
		t.Fatalf("corrupt config mode = %s, want local_only", c.Mode)
	}
	if err := os.WriteFile(webuiAccessPath(dir), []byte(`{"mode":"everyone"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := loadWebUIAccess(dir); c.Mode != webuiModeLocalOnly {
		t.Fatalf("unknown mode = %s, want local_only", c.Mode)
	}
}

func TestNormalizeAllowEntries(t *testing.T) {
	got, bad := normalizeAllowEntries(" AA-BB-CC-DD-EE-07, 192.168.43.20 ;fd00::20\n::ffff:10.0.0.1,aa:bb:cc:dd:ee:07")
	want := []string{"aa:bb:cc:dd:ee:07", "192.168.43.20", "fd00::20", "10.0.0.1"}
	if bad != "" || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v bad %q, want %v", got, bad, want)
	}
	for _, b := range []string{"ff:ff:ff:ff:ff:ff", "0.0.0.0", "224.0.0.1", "fe80::1%wlan0", "10.0.0.1/24", "aa:bb", "$(reboot)", "-j ACCEPT"} {
		if _, bad := normalizeAllowEntries(b); bad == "" {
			t.Errorf("entry %q must be rejected", b)
		}
	}
}

// 自锁拒绝: 远程请求提交不含自己的白名单 / local_only → self_lockout; 本机可以。
func TestWebUIAccessSetSelfLockout(t *testing.T) {
	withNeighFixture(t)
	dir := t.TempDir()
	s := newServer(dir)
	set := func(ip, mode, macs string) actionResp {
		p := map[string]string{"mode": mode, webuiClientIPParam: ip}
		if macs != "-" {
			p["macs"] = macs
		}
		return actionWebUIAccessSet(s, p)
	}
	if r := set("192.168.43.8", "allowlist", "aa:bb:cc:dd:ee:07"); r.OK || r.Error != "self_lockout" ||
		!strings.Contains(r.Detail, "aa:bb:cc:dd:ee:08") {
		t.Fatalf("remote allowlist without self = %+v, want self_lockout naming own mac", r)
	}
	if r := set("2408:8456:1234::66", "local_only", "-"); r.OK || r.Error != "self_lockout" {
		t.Fatalf("remote local_only = %+v, want self_lockout", r)
	}
	if _, err := os.Stat(webuiAccessPath(dir)); !os.IsNotExist(err) {
		t.Fatal("refused change must not be persisted")
	}
	// 自己的 MAC 在列表里 → 允许(防火墙脚本在临时目录不存在 → OK 但提示 firewall 失败)
	if r := set("192.168.43.8", "allowlist", "aa:bb:cc:dd:ee:08"); !r.OK {
		t.Fatalf("allowlist incl. own MAC refused: %+v", r)
	}
	if c := loadWebUIAccess(dir); c.Mode != webuiModeAllowlist || len(c.Macs) != 1 {
		t.Fatalf("persisted = %+v", c)
	}
	// IPv6 客户端用自己的 v6 地址
	if r := set("fd00::20", "allowlist", "fd00::20,aa:bb:cc:dd:ee:08"); !r.OK {
		t.Fatalf("v6 self allowlist refused: %+v", r)
	}
	// 本机: 空白名单 / local_only 都允许
	if r := set("127.0.0.1", "allowlist", ""); !r.OK {
		t.Fatalf("local empty allowlist refused: %+v", r)
	}
	if r := set("::1", "local_only", "-"); !r.OK {
		t.Fatalf("local local_only refused: %+v", r)
	}
	if r := set("127.0.0.1", "bogus", "-"); r.OK || r.Error != "bad params" {
		t.Fatalf("bad mode = %+v", r)
	}
	if r := set("127.0.0.1", "allowlist", "1.2.3.4,not-a-mac"); r.OK || r.Error != "bad params" {
		t.Fatalf("bad entry = %+v", r)
	}
}

// handleAction 注入 _client_ip, 覆盖客户端伪造的同名参数; self_lockout → 409。
func TestHandleActionWebUIAccessSetInjectsClientIP(t *testing.T) {
	withNeighFixture(t)
	dir := t.TempDir()
	s := newServer(dir)
	body := `{"action":"webui_access_set","params":{"mode":"local_only","_client_ip":"127.0.0.1"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/action", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HNC-CSRF", "1")
	req.RemoteAddr = "192.168.43.8:5555"
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyTokenID, "TESTTOKEN01"))
	rec := httptest.NewRecorder()
	s.handleAction(rec, req)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "self_lockout") {
		t.Fatalf("spoofed _client_ip: status %d body %s, want 409 self_lockout", rec.Code, rec.Body.String())
	}
}

// 中间件: 防火墙之外的 HTTP 层同样拒绝(403, Connection: close), loopback 不受影响。
func TestWebUIAccessGuardMiddleware(t *testing.T) {
	withNeighFixture(t)
	dir := t.TempDir()
	s := newServer(dir)
	h := s.handler()
	get := func(remote, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := get("192.168.43.250:1", "/pair"); rec.Code != http.StatusOK {
		t.Fatalf("mode all: /pair status %d", rec.Code)
	}
	if err := saveWebUIAccess(dir, webuiAccessCfg{Mode: webuiModeAllowlist, Macs: []string{"aa:bb:cc:dd:ee:07"}}); err != nil {
		t.Fatal(err)
	}
	rec := get("192.168.43.250:1", "/pair")
	if rec.Code != http.StatusForbidden || rec.Header().Get("Connection") != "close" {
		t.Fatalf("non-allowlisted /pair: %d conn=%q", rec.Code, rec.Header().Get("Connection"))
	}
	if rec := get("[2408:8456:1234::7]:1", "/pair"); rec.Code != http.StatusOK {
		t.Fatalf("allowlisted v6 via MAC: %d", rec.Code)
	}
	if rec := get("127.0.0.1:1", "/api/health"); rec.Code != http.StatusOK {
		t.Fatalf("loopback health: %d", rec.Code)
	}
}

func TestAPIConfigIncludesWebUIAccess(t *testing.T) {
	dir := t.TempDir()
	s := newServer(dir)
	if err := saveWebUIAccess(dir, webuiAccessCfg{Mode: webuiModeAllowlist, Macs: []string{"aa:bb:cc:dd:ee:07"}}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.apiConfig(rec, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	var out struct {
		WebUIAccess struct {
			Mode string   `json:"mode"`
			Macs []string `json:"macs"`
			Port int      `json:"port"`
		} `json:"webui_access"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.WebUIAccess.Mode != "allowlist" || len(out.WebUIAccess.Macs) != 1 || out.WebUIAccess.Port != 8443 {
		t.Fatalf("webui_access = %+v", out.WebUIAccess)
	}
}

// ── 安全响应头 ─────────────────────────────────────────────────

func TestSecurityHeadersPresent(t *testing.T) {
	s := newServer(t.TempDir())
	h := s.handler()
	for _, path := range []string{"/api/health", "/pair", "/api/devices", "/", "/static/app.js", "/nope"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "192.168.43.9:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		hd := rec.Header()
		if hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("X-Frame-Options") != "DENY" ||
			hd.Get("Referrer-Policy") != "same-origin" {
			t.Errorf("%s: missing static security headers: %v", path, hd)
		}
		csp := hd.Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: CSP lacks frame-ancestors: %q", path, csp)
		}
		if strings.HasPrefix(path, "/api/") && !strings.Contains(hd.Get("Cache-Control"), "no-store") {
			t.Errorf("%s: Cache-Control = %q", path, hd.Get("Cache-Control"))
		}
	}
}

func TestHTMLCSPUsesScriptHashesNotUnsafeInline(t *testing.T) {
	s := newServer(t.TempDir())
	req := httptest.NewRequest(http.MethodGet, "/pair", nil)
	req.RemoteAddr = "192.168.43.9:1234"
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, req)
	csp := rec.Header().Get("Content-Security-Policy")
	m := regexp.MustCompile(`script-src ([^;]*)`).FindStringSubmatch(csp)
	if m == nil || strings.Contains(m[1], "unsafe-inline") {
		t.Fatalf("script-src must not allow unsafe-inline: %q", csp)
	}
	// 独立计算 pair.html 内联脚本 hash
	body := rec.Body.String()
	sm := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindStringSubmatch(body)
	if sm == nil {
		t.Fatal("pair.html has no inline script (test precondition)")
	}
	sum := sha256.Sum256([]byte(sm[1]))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(m[1], want) {
		t.Fatalf("script-src %q lacks hash %s", m[1], want)
	}
}

func TestInlineScriptHashes(t *testing.T) {
	doc := []byte("<html><script src=\"a.js\"></script><SCRIPT type=\"text/javascript\">a()\r\nb()</SCRIPT>" +
		"<scripts>x</scripts><script>var s='<script>';</script></html>")
	hs := inlineScriptHashes(doc)
	h := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	want := []string{h("a()\nb()"), h("var s='<script>';")}
	if strings.Join(hs, " ") != strings.Join(want, " ") {
		t.Fatalf("hashes = %v, want %v", hs, want)
	}
	// 不完整 HTML(首块无 </html>)→ 回退旧 CSP, 不白屏
	rec := httptest.NewRecorder()
	sw := &secHeaderWriter{ResponseWriter: rec}
	sw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = sw.Write([]byte("<html><script>x()</script>"))
	if rec.Header().Get("Content-Security-Policy") != cspLegacy {
		t.Fatalf("partial html CSP = %q, want legacy fallback", rec.Header().Get("Content-Security-Policy"))
	}
}

func TestCookiesHttpOnlySameSiteStrict(t *testing.T) {
	for _, c := range []*http.Cookie{issuedCookie("x.y"), clearCookie()} {
		if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || !c.Secure {
			t.Fatalf("cookie flags wrong: %+v", c)
		}
	}
	resetPairGuard(t)
	dir := t.TempDir()
	writePending(t, dir, "654321", "sidCOOKIE001", time.Now().Unix()+120)
	rec := postPin(newServer(dir), "10.4.0.1", "654321")
	sc := rec.Header().Get("Set-Cookie")
	if rec.Code != http.StatusFound || !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "SameSite=Strict") {
		t.Fatalf("pair success Set-Cookie = %q (status %d)", sc, rec.Code)
	}
}

// SSE 经过安全头包装后仍能 Flush(ResponseController 穿透)。
func TestSecHeaderWriterFlushUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &secHeaderWriter{ResponseWriter: rec, api: true}
	if err := http.NewResponseController(sw).Flush(); err != nil {
		t.Fatalf("flush through wrapper: %v", err)
	}
	if !rec.Flushed || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("flushed=%v cache=%q", rec.Flushed, rec.Header().Get("Cache-Control"))
	}
}

// pair_new 的 Detail(含明文 PIN)不进审计。
func TestPairNewPINNotAudited(t *testing.T) {
	src := secReadFile(t, "action.go")
	if !strings.Contains(src, `if req.Action == "pair_new" {`) {
		t.Fatal("pair_new audit redaction missing")
	}
}
