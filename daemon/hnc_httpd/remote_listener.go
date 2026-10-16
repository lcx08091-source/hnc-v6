// remote_listener.go — v5.33: 远程访问端口(:8443 HTTPS + :8080 跳转)由 httpd 自己
// 按 rules.json 的 remote_enabled 开 / 关。
//
// 之前有两份「谁来决定开不开远程端口」:
//   - service.sh launch_httpd_safe 按 remote_enabled 决定带不带 `-bind 0.0.0.0`;
//   - Go 看门狗重启 httpd 时不带任何参数(= 只有本机 8444)——httpd 崩一次远程访问就没了;
//   - 设置页切 remote_enabled 后没有任何人重启 httpd(shell 的 httpd 漂移检查靠
//     run/httpd_bind_ip, v5.26 起就没人写这个文件, 两份漂移检查都是空转),
//     「约 1 分钟内生效」的提示从来不成立。
//
// 现在 httpd 启动参数只有一套(service.sh 与看门狗相同), 远程端口由本文件的
// remoteListener 管: 每 remoteCheckEvery 看一次 rules.json(mtime + size 没变就不重读),
// remote_enabled=true 就监听、false 就关; remote_enabled_set 动作写完立刻 Kick, 不等轮询。
// 监听失败(端口被占等)只记日志, 下一轮再试 —— 不再像旧版 log.Fatalf 让整个 httpd 退出
// (那样本机 8444 也跟着没了)。
//
// -bind 参数(main.go):
//
//	auto(默认) remote_enabled=true 时监听 0.0.0.0(热点网关 IP 会漂移, 见 validateBindAddress)
//	<私网 IP>  同上, 但只监听该地址
//	none       从不开远程端口(只有本机 127.0.0.1:8444)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// remoteCheckEvery 轮询 rules.json 的间隔(一次 stat; 内容变了才读)。
const remoteCheckEvery = 10 * time.Second

type remoteListener struct {
	hncDir   string
	bind     string // 监听地址(auto → 0.0.0.0)
	port     int    // HTTPS 端口(-port)
	httpPort int    // HTTP→HTTPS 跳转端口(-http-port, 0 = 不开)
	noTLS    bool   // -no-tls(开发用)
	handler  http.Handler

	kick chan struct{}

	mu       sync.Mutex
	https    *http.Server
	redir    *http.Server
	mainAddr string // 实际监听地址(测试用端口 0 时取真实端口)
	gen      int    // 每次 start +1; Serve 意外退出时只清理同一代

	// rules.json 读取缓存(只在 Loop 的 goroutine 里用)
	rulesMod  time.Time
	rulesSize int64
	want      bool
}

func newRemoteListener(hncDir, bind string, port, httpPort int, noTLS bool, h http.Handler) *remoteListener {
	if bind == "auto" || bind == "" {
		bind = "0.0.0.0"
	}
	return &remoteListener{
		hncDir: hncDir, bind: bind, port: port, httpPort: httpPort, noTLS: noTLS,
		handler: h, kick: make(chan struct{}, 1),
	}
}

// Kick 让 Loop 立刻重看一次 remote_enabled(remote_enabled_set 写完调用)。
func (rl *remoteListener) Kick() {
	if rl == nil {
		return
	}
	select {
	case rl.kick <- struct{}{}:
	default:
	}
}

// Loop 按 remote_enabled 开关远程端口, stopCh 关闭时关掉并返回。
func (rl *remoteListener) Loop(stopCh <-chan struct{}) {
	t := time.NewTicker(remoteCheckEvery)
	defer t.Stop()
	for {
		rl.sync()
		select {
		case <-stopCh:
			rl.stop("httpd 退出")
			return
		case <-t.C:
		case <-rl.kick:
		}
	}
}

// sync 读一次 remote_enabled, 让监听状态与之一致。
func (rl *remoteListener) sync() {
	want := rl.wantRemote()
	rl.mu.Lock()
	running := rl.https != nil
	rl.mu.Unlock()
	switch {
	case want && !running:
		if err := rl.start(); err != nil {
			log.Printf("remote listener: start failed: %v (retry in %v)", err, remoteCheckEvery)
		}
	case !want && running:
		rl.stop("remote_enabled=false")
	}
}

// wantRemote rules.json 的 remote_enabled(bool true 才算开)。文件读不到 / 坏了 →
// 沿用上一次的结论(写 rules.json 的瞬间可能读到半截, 不能因此把远程端口关掉又开);
// 进程刚启动还没有结论时按关处理。
func (rl *remoteListener) wantRemote() bool {
	p := filepath.Join(rl.hncDir, "data", "rules.json")
	st, err := os.Stat(p)
	if err != nil {
		return rl.want
	}
	if st.ModTime().Equal(rl.rulesMod) && st.Size() == rl.rulesSize {
		return rl.want
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return rl.want
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return rl.want
	}
	rl.rulesMod, rl.rulesSize = st.ModTime(), st.Size()
	v, _ := m["remote_enabled"].(bool)
	rl.want = v
	return v
}

// start 监听远程端口。先同步 Listen(端口被占当场报错, 下一轮重试), 再后台 Serve。
func (rl *remoteListener) start() error {
	addr := net.JoinHostPort(rl.bind, fmt.Sprint(rl.port))
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	certPath := rl.hncDir + "/data/httpd_cert.pem"
	keyPath := rl.hncDir + "/data/httpd_key.pem"
	if !rl.noTLS {
		if err := ensureCert(certPath, keyPath, rl.bind); err != nil {
			ln.Close()
			return fmt.Errorf("cannot ensure cert: %w", err)
		}
	}
	hs := &http.Server{
		Handler:           rl.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	var redir *http.Server
	var redirLn net.Listener
	if rl.httpPort > 0 && !rl.noTLS {
		// 跳转端口失败只记日志, 不影响 HTTPS(v4.0 Patch 2.b 起的约定)
		if l, err := net.Listen("tcp4", net.JoinHostPort(rl.bind, fmt.Sprint(rl.httpPort))); err != nil {
			log.Printf("remote listener: HTTP redirect :%d not started: %v (HTTPS continues)", rl.httpPort, err)
		} else {
			redirLn = l
			redir = &http.Server{
				Handler:           http.HandlerFunc(rl.redirect),
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       10 * time.Second,
				WriteTimeout:      10 * time.Second,
			}
		}
	}

	rl.mu.Lock()
	rl.gen++
	gen := rl.gen
	rl.https, rl.redir, rl.mainAddr = hs, redir, ln.Addr().String()
	rl.mu.Unlock()

	if ip := net.ParseIP(rl.bind); ip != nil && ip.IsUnspecified() && !readAuthRequired(rl.hncDir) {
		// rc3.1.14 起的提示: 0.0.0.0 + auth_required=false。rc30.12.18 起中间件默认拒绝,
		// 远程客户端照样要 cookie; 本机 KSU 走 loopback 的 X-HNC-Local-Admin。
		log.Printf("SECURITY: bind=0.0.0.0 with auth_required=false — rc30.12.18 default-deny enforces cookie auth on remote clients. Local KSU loopback bypass remains via X-HNC-Local-Admin secret.")
	}
	log.Printf("remote listener: serving %s (tls=%v, redirect=%v)", ln.Addr(), !rl.noTLS, redir != nil)
	go func() {
		var err error
		if rl.noTLS {
			err = hs.Serve(ln)
		} else {
			err = hs.ServeTLS(ln, certPath, keyPath)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("remote listener: HTTPS server exited: %v (retry in %v)", err, remoteCheckEvery)
			rl.mu.Lock()
			if rl.gen == gen {
				r := rl.redir
				rl.https, rl.redir, rl.mainAddr = nil, nil, ""
				rl.mu.Unlock()
				if r != nil {
					_ = r.Close()
				}
				return
			}
			rl.mu.Unlock()
		}
	}()
	if redir != nil {
		go func() {
			if err := redir.Serve(redirLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("remote listener: HTTP redirect server exited: %v (HTTPS continues)", err)
			}
		}()
	}
	return nil
}

// stop 关掉远程端口(进行中的请求最多等 5 秒)。
func (rl *remoteListener) stop(why string) {
	rl.mu.Lock()
	hs, redir := rl.https, rl.redir
	rl.https, rl.redir, rl.mainAddr = nil, nil, ""
	rl.gen++
	rl.mu.Unlock()
	if hs == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(ctx)
	if redir != nil {
		_ = redir.Shutdown(ctx)
	}
	log.Printf("remote listener: closed (%s)", why)
}

// Addr 当前远程端口的监听地址(没开 = "")。
func (rl *remoteListener) Addr() string {
	if rl == nil {
		return ""
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.mainAddr
}

// redirect HTTP → HTTPS。v6 review fix: 不信任 r.Host 构造目标(Host: evil.com 会变成
// 开放重定向), 用连接实际到达的本地地址; 拿不到时仅当 Host 是合法 IP 才采用。
func (rl *remoteListener) redirect(w http.ResponseWriter, r *http.Request) {
	target := fmt.Sprintf("https://%s:%d", rl.redirHost(r), rl.port) + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}

func (rl *remoteListener) redirHost(r *http.Request) string {
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if h, _, err := net.SplitHostPort(la.String()); err == nil && h != "" {
			return h
		}
	}
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		if ip := net.ParseIP(h); ip != nil {
			return h
		}
	} else if ip := net.ParseIP(r.Host); ip != nil {
		return r.Host
	}
	if ip := net.ParseIP(rl.bind); ip != nil && !ip.IsUnspecified() {
		return rl.bind
	}
	return "127.0.0.1"
}
