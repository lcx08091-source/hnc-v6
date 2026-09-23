package main

// v5.11 审计修复的回归测试。每个用例对应 audit 清单中的一条(A1…A9),
// 在修复前的代码上都会失败。

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A1: SSE 必须能穿过 accessLogMiddleware 的 ResponseWriter 包装。
// 修复前 loggingResponseWriter 没有 Unwrap(), SetWriteDeadline 失败 → 500。
func TestSSEWorksThroughAccessLogMiddleware(t *testing.T) {
	s := newServer(t.TempDir())
	ts := httptest.NewServer(accessLogMiddleware(http.HandlerFunc(s.apiEvents)))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/events: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (SSE blocked by middleware wrapper)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q", ct)
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatalf("read first event line: %v", err)
	}
	if strings.TrimSpace(line) != "event: changed" {
		t.Fatalf("first line = %q, want \"event: changed\"", line)
	}
}

// A2: 超时后孙进程仍持有 stdout 管道时, hardenCmd 必须让 CombinedOutput 在
// WaitDelay 内返回, 而不是等孙进程(sleep 30)自然退出。
func TestHardenCmdDoesNotHangOnGrandchild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	// "sleep 30; echo x" 迫使 sh fork 出 sleep 子进程(不会被 exec 优化掉)
	cmd := hardenCmd(exec.CommandContext(ctx, "sh", "-c", "sleep 30; echo x"))
	start := time.Now()
	_, _ = cmd.CombinedOutput()
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("CombinedOutput blocked %v after ctx timeout (WaitDelay not applied)", el)
	}
}

// A2(集成): runExe 超时必须返回 124 + "timeout after 5s", 且不被孙进程拖住。
func TestRunExeTimeoutWithGrandchild(t *testing.T) {
	if testing.Short() {
		t.Skip("takes ~7s")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nsleep 30\necho never\n"
	if err := os.WriteFile(filepath.Join(dir, "bin", "hang"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	rc, out := runExe(dir, "hang")
	el := time.Since(start)
	if el > 5*time.Second+execWaitDelay+3*time.Second {
		t.Fatalf("runExe returned after %v, want ≈5s+WaitDelay", el)
	}
	if rc != 124 || !strings.Contains(out, "timeout") {
		t.Fatalf("runExe = (%d, %q), want (124, timeout…)", rc, out)
	}
}

// A3: 速率整数溢出不得绕过上限。
func TestValidateRateOverflowAndBounds(t *testing.T) {
	// 2305843009213693960 = 8 + 2^61; ×1000 ≡ 8000 (mod 2^64) —— 修复前通过校验
	bad := []string{"2305843009213693960mbit", "10486mbit", "10485761kbit", "63kbit", "1.5mbit", "10mbps", ""}
	for _, r := range bad {
		if err := validateRate(r); err == nil {
			t.Errorf("validateRate(%q) = nil, want error", r)
		}
	}
	good := []string{"0", "64kbit", "10mbit", "10485mbit", "10485760kbit"}
	for _, r := range good {
		if err := validateRate(r); err != nil {
			t.Errorf("validateRate(%q) = %v, want nil", r, err)
		}
	}
}

// withLocal 临时把 time.Local 换成 UTC+8(真机时区), 测完恢复。
func withLocal(t *testing.T, loc *time.Location) {
	old := time.Local
	time.Local = loc
	t.Cleanup(func() { time.Local = old })
}

func writeStatsRow(t *testing.T, runDir string, ts time.Time, mac string, rx, tx uint64) {
	t.Helper()
	// 与 dpid output/history.go pathFor 一致: 按 UTC 日期命名
	p := filepath.Join(runDir, "stats."+ts.UTC().Format("20060102")+".jsonl")
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fmt.Fprintf(f, `{"t":%d,"mac":%q,"app":"抖音","app_id":"douyin","cat":"video","tx":%d,"rx":%d}`+"\n",
		ts.Unix(), mac, tx, rx)
}

// A4 + A5: source=dpi&range=today 必须统计今天(本地)已发生的行, 包括落在
// 前一个 UTC 日文件里的本地凌晨行; 昨天的行不得计入。
func TestDPIAggregateTodayAndUTCFileBoundary(t *testing.T) {
	withLocal(t, time.FixedZone("CST", 8*3600))
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	todayStart := localDayStart(now)
	// 今天本地 01:00(或今天已过时间的一半, 取较早者): 本地 <08:00 → UTC 日期是昨天
	off := now.Sub(todayStart) / 2
	if off > time.Hour {
		off = time.Hour
	}
	early := todayStart.Add(off)
	writeStatsRow(t, runDir, early, "aa:bb:cc:dd:ee:01", 1000, 10)
	// 昨天本地 23:00 —— 不属于 today
	writeStatsRow(t, runDir, todayStart.Add(-time.Hour), "aa:bb:cc:dd:ee:01", 5, 5)

	s := newServer(dir)
	buckets, _ := s.dpiAggregate("today", "")
	var rx, tx int64
	for _, b := range buckets {
		rx += b.RX
		tx += b.TX
	}
	if rx != 1000 || tx != 10 {
		t.Fatalf("today totals rx=%d tx=%d, want rx=1000 tx=10 (today's rows dropped or yesterday's counted)", rx, tx)
	}

	// week: 6 天前本地 00:30 的行必须进首日桶(修复前下界是 6 天前的"此刻")
	sixAgo := todayStart.AddDate(0, 0, -6).Add(30 * time.Minute)
	writeStatsRow(t, runDir, sixAgo, "aa:bb:cc:dd:ee:02", 777, 0)
	wk, daily := s.dpiAggregate("week", "")
	if len(wk) != 7 {
		t.Fatalf("week buckets = %d, want 7", len(wk))
	}
	if wk[0].RX != 777 {
		t.Fatalf("week first bucket rx=%d, want 777 (label %s)", wk[0].RX, wk[0].Label)
	}
	if len(daily) == 0 {
		t.Fatalf("week daily buckets empty")
	}
}

// A5: dpi_history 与 dayFileKeys 的窗口 / 文件集合。
func TestDayFileKeysUnionLocalAndUTC(t *testing.T) {
	cst := time.FixedZone("CST", 8*3600)
	from := time.Date(2026, 9, 23, 0, 0, 0, 0, cst)
	to := time.Date(2026, 9, 23, 10, 0, 0, 0, cst)
	got := strings.Join(dayFileKeys(from, to), ",")
	if got != "20260922,20260923" {
		t.Fatalf("dayFileKeys = %s, want 20260922,20260923", got)
	}
	// 反向参数也应工作且至少一个 key
	if k := dayFileKeys(to, to); len(k) == 0 {
		t.Fatalf("dayFileKeys single instant returned no keys")
	}
}

func TestDPIHistoryTodayWindow(t *testing.T) {
	withLocal(t, time.FixedZone("CST", 8*3600))
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	todayStart := localDayStart(now)
	off := now.Sub(todayStart) / 2
	if off > time.Hour {
		off = time.Hour
	}
	writeStatsRow(t, runDir, todayStart.Add(off), "aa:bb:cc:dd:ee:01", 100, 1)
	writeStatsRow(t, runDir, todayStart.Add(-2*time.Hour), "aa:bb:cc:dd:ee:01", 9999, 9999)

	s := newServer(dir)
	rec := httptest.NewRecorder()
	s.apiDPIHistory(rec, httptest.NewRequest(http.MethodGet, "/api/dpi_history?days=1", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `"total_rx":100`) || !strings.Contains(body, `"sample_count":1`) {
		t.Fatalf("dpi_history days=1 body = %s", body)
	}
	if !strings.Contains(body, `"window_start":"`+todayStart.Format("2006-01-02")+`"`) {
		t.Fatalf("window_start not local today: %s", body)
	}
}

// A9: watchdog 写出的坏行 {"t":,...} 必须被兜底解析。
func TestOnlineHoursToleratesBrokenWatchdogLines(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	day := time.Now().Format("20060102")
	content := fmt.Sprintf(`{"t":,"day":"%s","mac":"aa:bb:cc:dd:ee:01"}
{"t":,"day":"%s","mac":"aa:bb:cc:dd:ee:01"}
{"t":1790000000,"day":"%s","mac":"aa:bb:cc:dd:ee:01"}
{"t":,"day":"%s"}
garbage-line-without-fields
`, day, day, day, day)
	if err := os.WriteFile(filepath.Join(runDir, "online_hours.jsonl"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got := onlineHoursByMAC(dir, 7)
	if n := got["aa:bb:cc:dd:ee:01"][day]; n != 3 {
		t.Fatalf("hours = %d, want 3 (broken lines dropped?) map=%v", n, got)
	}
}

// A6: PIN 尝试全局上限 —— 换源地址不能绕过。
func TestPinAttemptGlobalCapAcrossIPs(t *testing.T) {
	rl := NewRateLimiter()
	for i := 0; i < rlPinGlobalMaxPerWindow; i++ {
		ok, _, _ := rl.ConsumePinAttempt(fmt.Sprintf("192.168.43.%d", 10+i))
		if !ok {
			t.Fatalf("attempt %d from fresh IP rejected before global cap", i)
		}
	}
	ok, retry, rem := rl.ConsumePinAttempt("fe80::dead:beef")
	if ok || retry <= 0 || rem != 0 {
		t.Fatalf("attempt beyond global cap = (%v,%d,%d), want (false,>0,0)", ok, retry, rem)
	}
}

// A6: 单 IP 行为不变 —— 4 次可比对, 第 5 次锁定。
func TestPinAttemptPerIPUnchanged(t *testing.T) {
	rl := NewRateLimiter()
	for i := 1; i <= rlPinAttemptsMax-1; i++ {
		ok, _, rem := rl.ConsumePinAttempt("10.0.0.2")
		if !ok || rem != rlPinAttemptsMax-i {
			t.Fatalf("attempt %d = (%v, rem %d)", i, ok, rem)
		}
	}
	if ok, retry, _ := rl.ConsumePinAttempt("10.0.0.2"); ok || retry <= 0 {
		t.Fatalf("5th attempt must lock, got ok=%v retry=%d", ok, retry)
	}
}

// A7: requireMutation 端点接入写频率限制。
func TestRequireMutationWriteRateLimited(t *testing.T) {
	s := newServer(t.TempDir())
	h := s.requireMutation(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	do := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/self/toggle", strings.NewReader(`{"enabled":true}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-HNC-CSRF", "1")
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec.Code
	}
	for i := 0; i < writeMaxPerWin; i++ {
		if c := do(); c != http.StatusOK {
			t.Fatalf("request %d status %d", i, c)
		}
	}
	if c := do(); c != http.StatusTooManyRequests {
		t.Fatalf("request beyond limit status %d, want 429", c)
	}
}

// A7: 并发导出 → 409。
func TestExportBusyReturns409(t *testing.T) {
	s := newServer(t.TempDir())
	exportMu.Lock()
	defer exportMu.Unlock()
	rec := httptest.NewRecorder()
	s.apiExport(rec, httptest.NewRequest(http.MethodPost, "/api/export", strings.NewReader(`{}`)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", rec.Code)
	}
}

// A8: cert 与 key 不配对时 ensureCert 必须重生。
func TestEnsureCertRegeneratesOnKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "httpd_cert.pem")
	keyPath := filepath.Join(dir, "httpd_key.pem")
	if err := ensureCert(certPath, keyPath, "192.168.43.1"); err != nil {
		t.Fatal(err)
	}
	// 模拟"新 cert + 旧 key": 换一把无关私钥
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(other)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		t.Fatal("precondition: mismatched pair should not load")
	}
	if err := ensureCert(certPath, keyPath, "192.168.43.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("after ensureCert pair still invalid: %v", err)
	}
}

// A10: 同一 PIN 的并发正确请求只能签出一个 token(一次性 PIN)。
func TestPairVerifyOneTimeUnderConcurrency(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	pending := fmt.Sprintf("123456\nabcdEFGH1234\n%d\n", time.Now().Unix()+120)
	if err := os.WriteFile(filepath.Join(dir, "run", "pair_pending"), []byte(pending), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newServer(dir)
	const n = 6
	codes := make(chan int, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(i int) {
			req := httptest.NewRequest(http.MethodPost, "/api/pair/verify", strings.NewReader("pin=123456"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = fmt.Sprintf("192.168.43.%d:5000", 100+i)
			rec := httptest.NewRecorder()
			<-start
			s.handlePairVerify(rec, req)
			codes <- rec.Code
		}(i)
	}
	close(start)
	ok := 0
	for i := 0; i < n; i++ {
		if c := <-codes; c == http.StatusFound {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d concurrent verifies succeeded with one PIN, want exactly 1", ok)
	}
	if got := len(s.tokens.Snapshot()); got != 1 {
		t.Fatalf("issued %d tokens, want 1", got)
	}
}

// app_limit_set: "NaN" 必须 400 bad params(修复前 500 write failed)。
func TestAppLimitSetRejectsNaN(t *testing.T) {
	resp := actionAppLimitSet(t.TempDir(), map[string]string{
		"mac": "aa:bb:cc:dd:ee:01", "app_id": "douyin", "down_mbps": "NaN",
	})
	if resp.OK || resp.Error != "bad params" {
		t.Fatalf("resp = %+v, want bad params", resp)
	}
}
