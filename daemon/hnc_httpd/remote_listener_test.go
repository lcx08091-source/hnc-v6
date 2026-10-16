package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// v5.33: 远程端口由 httpd 按 remote_enabled 自己开关(remote_listener.go)。
// 「改动前会失败」: v5.32 没有 remoteListener —— 远程端口只在启动参数带 -bind 时开,
// 之后切 remote_enabled 没人管(本文件编译不过); 看门狗重启 httpd 不带参数, 远程端口丢。

func rlRules(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// rlWait 等 Addr() 满足 cond(最多 3 秒)。
func rlWait(t *testing.T, rl *remoteListener, cond func(string) bool, what string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		a := rl.Addr()
		if cond(a) {
			return a
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: 3 秒内没等到(Addr=%q)", what, a)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func newTestRL(t *testing.T, dir string) (*remoteListener, chan struct{}) {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "hnc") })
	rl := newRemoteListener(dir, "127.0.0.1", 0, 0, true, h) // 端口 0 = 随机; no-tls 免生成证书
	stop := make(chan struct{})
	go rl.Loop(stop)
	t.Cleanup(func() {
		select {
		case <-stop:
		default:
			close(stop)
		}
	})
	return rl, stop
}

func TestRemoteListenerFollowsRemoteEnabled(t *testing.T) {
	dir := t.TempDir()
	rlRules(t, dir, `{"remote_enabled":false,"auth_required":true}`)
	rl, stop := newTestRL(t, dir)
	time.Sleep(100 * time.Millisecond)
	if a := rl.Addr(); a != "" {
		t.Fatalf("remote_enabled=false 不该开远程端口, Addr=%q", a)
	}

	rlRules(t, dir, `{"remote_enabled":true,"auth_required":true}`)
	rl.Kick()
	addr := rlWait(t, rl, func(a string) bool { return a != "" }, "remote_enabled=true 后开端口")
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "hnc" {
		t.Fatalf("body=%q", b)
	}

	rlRules(t, dir, `{"remote_enabled":false,"auth_required":true}`)
	rl.Kick()
	rlWait(t, rl, func(a string) bool { return a == "" }, "remote_enabled=false 后关端口")
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		c.Close()
		t.Fatalf("关掉后 %s 仍可连", addr)
	}

	// 再开再停 httpd: Loop 退出时关端口
	rlRules(t, dir, `{"remote_enabled":true,"auth_required":true}`)
	rl.Kick()
	rlWait(t, rl, func(a string) bool { return a != "" }, "再次开端口")
	close(stop)
	rlWait(t, rl, func(a string) bool { return a == "" }, "httpd 退出时关端口")
}

// rules.json 写到一半 / 读坏 → 沿用上一次结论, 不把远程端口关了又开。
func TestRemoteListenerBadRulesKeepsState(t *testing.T) {
	dir := t.TempDir()
	rlRules(t, dir, `{"remote_enabled":true}`)
	rl, _ := newTestRL(t, dir)
	addr := rlWait(t, rl, func(a string) bool { return a != "" }, "开端口")
	rlRules(t, dir, `{"remote_enabled":tr`)
	rl.Kick()
	time.Sleep(150 * time.Millisecond)
	if a := rl.Addr(); a != addr {
		t.Fatalf("坏文件不该改变监听状态: %q → %q", addr, a)
	}
	os.Remove(filepath.Join(dir, "data", "rules.json"))
	rl.Kick()
	time.Sleep(150 * time.Millisecond)
	if a := rl.Addr(); a != addr {
		t.Fatalf("文件暂时不在不该改变监听状态: %q → %q", addr, a)
	}
}

// 端口被占: 只记日志、下一轮重试, 不退出进程(v5.32 是 log.Fatalf, 本机 8444 也跟着没了)。
func TestRemoteListenerPortBusyRetries(t *testing.T) {
	busy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := busy.Addr().(*net.TCPAddr).Port
	dir := t.TempDir()
	rlRules(t, dir, `{"remote_enabled":true}`)
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})
	rl := newRemoteListener(dir, "127.0.0.1", port, 0, true, h)
	rl.sync()
	if a := rl.Addr(); a != "" {
		t.Fatalf("端口被占时不该显示已监听: %q", a)
	}
	busy.Close()
	rl.sync()
	if a := rl.Addr(); !strings.HasSuffix(a, ":"+strconv.Itoa(port)) {
		t.Fatalf("端口空出来后下一轮应监听上, Addr=%q", a)
	}
	rl.stop("test")
}

// 设置页切 remote_enabled → 写 rules.json 后立刻 Kick(不等 10 秒轮询)。
func TestRemoteEnabledSetKicksListener(t *testing.T) {
	dir := t.TempDir()
	rlRules(t, dir, `{"remote_enabled":false}`)
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// 假 json_set.sh: 只认 `top remote_enabled <v>`, 整个重写 rules.json
	fake := "#!/bin/sh\n[ \"$1\" = top ] && [ \"$2\" = remote_enabled ] || exit 1\nprintf '{\"remote_enabled\":%s}' \"$3\" > \"$HNC_DIR/data/rules.json\"\n"
	if err := os.WriteFile(filepath.Join(dir, "bin", "json_set.sh"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	rl, _ := newTestRL(t, dir)
	time.Sleep(100 * time.Millisecond)
	s := &server{hncDir: dir, remote: rl}
	if r := actionRemoteEnabledSet(s, map[string]string{"enabled": "true"}); !r.OK {
		t.Fatalf("action: %+v", r)
	}
	// 轮询间隔是 10 秒, 1 秒内开起来只能是 Kick 生效
	deadline := time.Now().Add(time.Second)
	for rl.Addr() == "" {
		if time.Now().After(deadline) {
			t.Fatal("remote_enabled_set 后 1 秒内没开远程端口(没有 Kick)")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if r := actionRemoteEnabledSet(&server{hncDir: dir}, map[string]string{"enabled": "false"}); !r.OK {
		t.Fatalf("没有 remoteListener(-bind none)时也应正常写开关: %+v", r)
	}
}

// TLS 路径: 首次开端口时自签证书(ensureCert), 走 HTTPS。
func TestRemoteListenerTLS(t *testing.T) {
	dir := t.TempDir()
	rlRules(t, dir, `{"remote_enabled":true}`)
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "tls") })
	rl := newRemoteListener(dir, "127.0.0.1", 0, 0, false, h)
	rl.sync()
	defer rl.stop("test")
	addr := rl.Addr()
	if addr == "" {
		t.Fatal("TLS 模式没开起来")
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "httpd_cert.pem")); err != nil {
		t.Fatalf("应自签证书: %v", err)
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 3 * time.Second}
	resp, err := cl.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "tls" {
		t.Fatalf("body=%q", b)
	}
}
