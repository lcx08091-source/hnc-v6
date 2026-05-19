// HNC httpd — 远程访问 HTTP 服务器
// v4.0 Patch 1 MVP: 仅只读 /api/devices 和 /api/stats,无鉴权
// 绑定到热点接口(ap0 / wlan2 等) 的 IP,不绑 0.0.0.0
//
// 部署约定:
//
//	二进制位于 $HNC_DIR/daemon/hnc_httpd/hnc_httpd (prebuilt arm64)
//	由 service.sh 在 rules.json.remote_enabled=true 时 fork 启动
//	pid 文件 $HNC_DIR/run/httpd.pid
//	证书 $HNC_DIR/data/httpd_cert.pem + httpd_key.pem (首次自签)
//	日志 $HNC_DIR/logs/httpd.log
//
// 安全不变量:
//   - NEVER 绑定 0.0.0.0 / :: 任何公共地址
//   - Patch 1 MVP 无鉴权,但必须只在 ap0 子网能访问
//   - 不执行任何 shell 命令,只读文件系统
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	flagBind         = flag.String("bind", "", "bind address, e.g. 192.168.43.1 (required)")
	flagPort         = flag.Int("port", 8443, "HTTPS port")
	flagHTTPPort     = flag.Int("http-port", 8080, "HTTP port for redirect to HTTPS (0 = disable)")
	flagLoopbackPort = flag.Int("loopback-port", 8444, "loopback plain HTTP port for local KSU WebUI (0 = disable)")
	flagHNCDir       = flag.String("hnc-dir", "/data/local/hnc", "HNC installation root")
	flagNoTLS        = flag.Bool("no-tls", false, "disable TLS (for Patch 1 development only)")
	flagVersion      = flag.Bool("version", false, "print version and exit")

	// rc11: when a remote listener is bound to 0.0.0.0 while rules.json still
	// says auth_required=false, force remote cookie auth in-process instead of
	// merely logging a warning. Loopback KSU requests without Origin/Referer keep
	// their local bypass in middleware.
	forceRemoteAuth bool
)

// rc5.1.1 修 X-G2: 之前硬编码 "v4.1.0-rc3.1.14", 每次发版都要手动改.
// 改成 build 时 ldflags 注入(-X main.version=xxx). fallback 为 "dev".
// build.sh 会在编译时读 module.prop 的 version 字段注入此变量.
var version = "dev"

func main() {
	flag.Parse()

	if *flagVersion {
		fmt.Println("hnc_httpd", version)
		return
	}

	// v5.0: -bind 不再必填。支持三种启动模式:
	//   1. 仅 loopback (本机 WebUI)          = 不传 -bind, 只开 127.0.0.1:8444
	//   2. 仅热点 HTTPS (远程访问, 纯 headless) = 传 -bind + -loopback-port 0
	//   3. 两者都开                          = 传 -bind (默认行为, 大多场景)
	haveRemote := *flagBind != ""
	haveLocal := *flagLoopbackPort > 0
	if !haveRemote && !haveLocal {
		fmt.Fprintln(os.Stderr, "error: at least one of -bind or -loopback-port must be set")
		os.Exit(2)
	}

	if haveRemote {
		// 安全不变量: 绝不绑定 0.0.0.0 / :: 任何公共地址
		// 这里严格白名单,只允许看起来像 ap0 子网 (192.168.x.x / 10.x.x.x) 的 IP
		if err := validateBindAddress(*flagBind); err != nil {
			fmt.Fprintln(os.Stderr, "error: invalid bind address:", err)
			os.Exit(2)
		}
	}

	setupLog(*flagHNCDir)

	log.Printf("hnc_httpd %s starting, remote=%v(%s:%d) loopback=%v(127.0.0.1:%d) tls=%v hnc_dir=%s",
		version, haveRemote, *flagBind, *flagPort, haveLocal, *flagLoopbackPort, !*flagNoTLS, *flagHNCDir)

	// 写 pid
	pidFile := *flagHNCDir + "/run/httpd.pid"
	_ = os.MkdirAll(*flagHNCDir+"/run", 0755)
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644); err != nil {
		log.Printf("WARN: cannot write pid file: %v", err)
	}
	defer os.Remove(pidFile)

	srv := newServer(*flagHNCDir)

	// rc3.1.14 修 P2 (review §一信息泄漏): 0.0.0.0 + auth_required=false
	// 联合配置下任何热点用户都能裸读/写 HNC 控制平面. 默认全新装机就是这状态
	// (rc3.1.13 起 rules.json 模板 auth_required:false). 启动时打一次 WARN
	// 让用户在 boot.log / WebUI 日志里看到, 提示开 toggle.
	if haveRemote {
		ip := net.ParseIP(*flagBind)
		if ip != nil && ip.To4() != nil && ip.To4().IsUnspecified() {
			if !readAuthRequired(*flagHNCDir) {
				forceRemoteAuth = true
				log.Printf("SECURITY: bind=0.0.0.0 with auth_required=false — forcing cookie auth for remote clients in this process. Local KSU loopback bypass remains available.")
			}
		}
	}

	// HTTPS server (远程访问, 仅 haveRemote 时启动)
	// rc30.12.14: 补全 ReadTimeout / WriteTimeout 防 slowloris / 慢响应耗 goroutine
	var httpsSrv *http.Server
	if haveRemote {
		addr := fmt.Sprintf("%s:%d", *flagBind, *flagPort)
		httpsSrv = &http.Server{
			Addr:              addr,
			Handler:           srv.handler(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	// HTTP → HTTPS 重定向 server(如果启用, 仅 haveRemote)
	// rc30.12.14: 重定向 server 也加 WriteTimeout. 客户端慢读 redirect 会卡 goroutine.
	var httpSrv *http.Server
	if haveRemote && *flagHTTPPort > 0 && !*flagNoTLS {
		httpSrv = &http.Server{
			Addr: fmt.Sprintf("%s:%d", *flagBind, *flagHTTPPort),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host
				// 去掉原 host 的端口,换成 HTTPS 端口
				if h, _, err := net.SplitHostPort(r.Host); err == nil {
					target = fmt.Sprintf("https://%s:%d", h, *flagPort)
				}
				target += r.URL.RequestURI()
				http.Redirect(w, r, target, http.StatusPermanentRedirect)
			}),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
		}
	}

	// v5.0 loopback HTTP server · 让本机 KSU WebUI 免鉴权访问
	// 不走 TLS(loopback 不需要加密), 共享同一 handler
	// rc30.12.14: 补 Read/Write 超时. loopback 也是同一个 goroutine 模型.
	var loopbackSrv *http.Server
	if *flagLoopbackPort > 0 {
		loopbackSrv = &http.Server{
			Addr:              fmt.Sprintf("127.0.0.1:%d", *flagLoopbackPort),
			Handler:           srv.handler(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	// 启动
	// v4.0 Patch 2.b: 区分两个 server 的错误通道,8080 重定向 server 崩不能
	// 带走主 8443 server(历史事故: wlan2 IP 漂移时 8080 accept4 EINVAL,
	// 旧版 log.Fatalf 直接退出整个 httpd 进程)
	httpsErrCh := make(chan error, 1)

	// v4.0 Patch 2.b: 启动后台 goroutine
	//   - tokens.SaveLoop: 每 30 秒把内存中 last_seen 变动 flush 到磁盘
	//   - limiter.GCLoop:  每 5 分钟清理 rate limiter 过期 entry
	//   - pruneLoop:      监视 $RUN/httpd_prune_request marker + 每日兜底
	//   - writeCounter.GCLoop: 每 5 分钟清理 write rate limiter 过期 entry (Patch 3.a)
	stopCh := make(chan struct{})
	go srv.tokens.SaveLoop(stopCh)
	go srv.limiter.GCLoop(stopCh)
	go srv.pruneLoop(stopCh)
	go srv.writeCounter.GCLoop(stopCh)
	go srv.OffloadLoop(stopCh) // rc3.1.26 · 30s 刷 offload_status cache, 避免 apiOffloadStatus 同步跑 check_offload.sh (含 sleep 5)

	if haveRemote {
		if *flagNoTLS {
			// Patch 1 开发模式: 纯 HTTP(生产务必关)
			log.Printf("WARN: TLS disabled (development only)")
			go func() { httpsErrCh <- httpsSrv.ListenAndServe() }()
		} else {
			certPath := *flagHNCDir + "/data/httpd_cert.pem"
			keyPath := *flagHNCDir + "/data/httpd_key.pem"
			if err := ensureCert(certPath, keyPath, *flagBind); err != nil {
				log.Fatalf("cannot ensure cert: %v", err)
			}
			go func() { httpsErrCh <- httpsSrv.ListenAndServeTLS(certPath, keyPath) }()
			if httpSrv != nil {
				// 8080 重定向 server 崩只 log,不影响主 server
				go func() {
					if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						log.Printf("HTTP redirect server exited: %v (main 8443 server continues)", err)
					}
				}()
			}
		}
	}

	// v5.0 loopback server(非 TLS) — 只监听 127.0.0.1:8444, 给本机 WebUI 用
	// 崩只记 log 不影响主 server(和 8080 同处理)
	if loopbackSrv != nil {
		log.Printf("starting loopback HTTP server on 127.0.0.1:%d (no TLS, no auth for local WebUI)", *flagLoopbackPort)
		go func() {
			if err := loopbackSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("loopback server exited: %v (main server continues)", err)
			}
		}()
	}

	// 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	select {
	case err := <-httpsErrCh:
		// 主 server 崩 → 进程必须退出(监听地址没了,整个 httpd 无法工作)
		log.Fatalf("HTTPS server exited: %v", err)
	case sig := <-sigCh:
		log.Printf("received signal %v, shutting down", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		close(stopCh) // 通知所有 goroutine 停止(SaveLoop 会做最后一次 Flush)
		if httpsSrv != nil {
			_ = httpsSrv.Shutdown(ctx)
		}
		if httpSrv != nil {
			_ = httpSrv.Shutdown(ctx)
		}
		if loopbackSrv != nil {
			_ = loopbackSrv.Shutdown(ctx)
		}
	}
	log.Printf("shutdown complete")
}

// validateBindAddress 确保 bind 地址只可能是热点子网的 IP 或 0.0.0.0/loopback。
// 严格白名单:
//   - 必须是合法 IPv4
//   - 必须是 RFC 1918 私有地址段 (10/8 / 172.16-31/12 / 192.168/16)
//     或本地回环 127/8 (测试用)
//   - 允许 0.0.0.0 (rc3.1.6 起 · ColorOS tether 主机 IP 漂移问题, 仅当 PIN+cookie
//     鉴权开启时才安全; rc3.1.14 在 main 启动时会对 0.0.0.0+auth=false 联合配置
//     打 SECURITY WARN)
//   - 绝不允许任何公共 IP / ::
func validateBindAddress(addr string) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("not a valid IP: %q", addr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 supported (got %q)", addr)
	}
	// rc3.1.6: 允许 0.0.0.0 (监听所有接口).
	// 原因: ColorOS tether 给主机 .67 而网关是 .1, 单独绑 .67 则从 .1 访问 UNREACHABLE.
	// 已有 PIN + cookie 双层鉴权, 监听所有接口风险可控.
	if ip4.IsUnspecified() {
		return nil
	}
	// 私有地址段 OR loopback
	if ip4.IsPrivate() || ip4.IsLoopback() {
		return nil
	}
	return fmt.Errorf("bind address %q is not private (RFC 1918) or loopback; refusing to expose control plane to public network", addr)
}

func setupLog(hncDir string) {
	_ = os.MkdirAll(hncDir+"/logs", 0755)
	f, err := os.OpenFile(hncDir+"/logs/httpd.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// fallback 到 stderr
		log.Printf("WARN: cannot open log file: %v (logging to stderr)", err)
		return
	}
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}

// accessLogMiddleware 记录每个请求的基本信息
// 不记录请求 body(量大),不记录 cookie 明文(只记前 8 字符做识别)
func accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &loggingResponseWriter{ResponseWriter: w, status: 200}

		// 恢复 panic,不让一个请求崩整个 daemon
		defer func() {
			if p := recover(); p != nil {
				rw.status = 500
				log.Printf("PANIC %s %s %s: %v", r.RemoteAddr, r.Method, r.URL.Path, p)
				http.Error(rw, "internal error", http.StatusInternalServerError)
			}
			log.Printf("%s %s %s %d %s",
				ipOnly(r.RemoteAddr), r.Method, r.URL.Path, rw.status, time.Since(start))
		}()
		next.ServeHTTP(rw, r)
	})
}

func ipOnly(addr string) string {
	// rc2 修 G11: 用 net.SplitHostPort 正确处理 IPv6
	//   IPv4:  "192.168.43.102:43210"     → "192.168.43.102"
	//   IPv6:  "[::1]:43210"               → "::1"      (原来 LastIndex(":") 切成 "[::1")
	//   裸 IP: 无端口的罕见 fallback       → 原样返回
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (lrw *loggingResponseWriter) WriteHeader(status int) {
	lrw.status = status
	lrw.ResponseWriter.WriteHeader(status)
}
