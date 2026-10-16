// HNC httpd — 本机 WebUI(127.0.0.1:8444)+ 远程访问(:8443 HTTPS / :8080 跳转)
//
// 部署约定:
//
//	二进制位于 $HNC_DIR/daemon/hnc_httpd/hnc_httpd
//	service.sh 开机拉起、Go 看门狗挂了重拉, 两处参数相同(只有 -hnc-dir)
//	远程端口按 rules.json 的 remote_enabled 由本进程自己开关(remote_listener.go)
//	pid 文件 $HNC_DIR/run/httpd.pid
//	证书 $HNC_DIR/data/httpd_cert.pem + httpd_key.pem (首次自签)
//	日志 $HNC_DIR/logs/httpd.log
//
// 安全不变量:
//   - 远程端口只绑 0.0.0.0 / 私网 IP / loopback, 绝不绑公网 IP 或 ::(validateBindAddress)
//   - 远程客户端默认拒绝, 要 cookie(rc30.12.18); 本机 loopback 走 X-HNC-Local-Admin
package main

import (
	"context"
	"flag"
	"fmt"
	"hnc.io/dpid/tzlocal"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	flagBind         = flag.String("bind", "auto", "remote listener address: auto (0.0.0.0 while rules.json remote_enabled=true) | <private IPv4> | none")
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
	//
	// rc30.12.30 (P0.3): forceRemoteAuth 删除. rc30.12.18 默认拒绝重构后没人读它,
	// 启动时给它赋 true 的代码也一并删. 只保留 SECURITY log 提醒.
)

// rc5.1.1 修 X-G2: 之前硬编码 "v4.1.0-rc3.1.14", 每次发版都要手动改.
// 改成 build 时 ldflags 注入(-X main.version=xxx). fallback 为 "dev".
// build.sh 会在编译时读 module.prop 的 version 字段注入此变量.
var version = "dev"

// v5.9.9: build.sh 用 -X main.versionCode 从 module.prop 注入。
// 关于页据此显示真实 versionCode(此前前端把它硬编码在 data-vcode 属性)。
var versionCode = "0"

func main() {
	flag.Parse()
	// v5.12: GOOS=android 时 Go 标准库不读系统时区, time.Local 恒为 UTC ——
	// "今日"统计、本月流量、在线时长、导出时间窗的"本地零点"在东八区全都偏 8 小时。
	// 进程启动即换成真实本地时区(tzlocal 读 persist.sys.timezone / APEX tzdata)。
	time.Local = tzlocal.Location()

	if *flagVersion {
		fmt.Println("hnc_httpd", version)
		return
	}

	// v5.33: 远程端口只由 remote_enabled 决定(remote_listener.go), 启动参数只有一套。
	//   -bind auto(默认)/ <私网 IP>: remote_enabled=true 时开远程端口
	//   -bind none: 从不开远程端口
	haveRemote := *flagBind != "none"
	haveLocal := *flagLoopbackPort > 0
	if !haveRemote && !haveLocal {
		fmt.Fprintln(os.Stderr, "error: -bind none needs -loopback-port > 0")
		os.Exit(2)
	}
	if haveRemote && *flagBind != "auto" && *flagBind != "" {
		// 只允许私网 / loopback / 0.0.0.0, 绝不绑公网
		if err := validateBindAddress(*flagBind); err != nil {
			fmt.Fprintln(os.Stderr, "error: invalid bind address:", err)
			os.Exit(2)
		}
	}

	setupLog(*flagHNCDir)

	log.Printf("hnc_httpd %s starting, remote=%s(:%d, follows remote_enabled) loopback=%v(127.0.0.1:%d) tls=%v hnc_dir=%s",
		version, *flagBind, *flagPort, haveLocal, *flagLoopbackPort, !*flagNoTLS, *flagHNCDir)

	// 写 pid
	pidFile := *flagHNCDir + "/run/httpd.pid"
	_ = os.MkdirAll(*flagHNCDir+"/run", 0755)
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644); err != nil {
		log.Printf("WARN: cannot write pid file: %v", err)
	}
	defer os.Remove(pidFile)

	srv := newServer(*flagHNCDir)

	// v5.9.0: httpd 停机期间 CLI 写入的撤销请求(run/token_revoke.request)
	// 在启动时补处理 —— httpd 不在时无人能用 token 鉴权,故不存在生效窗口。
	srv.consumeTokenRevokeRequests("startup")

	// 远程端口(:8443 + :8080 跳转): 按 remote_enabled 开关, 见 remote_listener.go。
	// rc3.1.14 的「0.0.0.0 + auth_required=false」SECURITY 提示随之搬到开端口时打。
	if haveRemote {
		srv.remote = newRemoteListener(*flagHNCDir, *flagBind, *flagPort, *flagHTTPPort, *flagNoTLS, srv.handler())
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
	go srv.OffloadLoop(stopCh)  // rc3.1.26 · 30s 刷 offload_status cache, 避免 apiOffloadStatus 同步跑 check_offload.sh (含 sleep 5)
	go srv.AppUsageLoop(stopCh) // v5.16: 按应用真实流量统计(conntrack 字节差分)
	go srv.CtEventLoop(stopCh)  // v5.18: conntrack DESTROY 事件, 补短连接/连接尾巴(失败退纯轮询)
	// v5.21: conntrack NEW 事件, 共现推断用的精确建连时间(失败退 10s 粒度)
	go srv.CtNewEventLoop(stopCh)
	go srv.CertProbeLoop(stopCh)        // v5.15: 未知应用发现 · 后台取证书
	go srv.limitCtl.Loop(stopCh)        // 设备配额 + 分时段限速(每分钟对齐)
	go srv.RateLoop(stopCh)             // 单一后台速率采样器 · 2s 刷 s.rates, /api/devices 与 /api/live 同源一致
	go srv.PhoneUsageLoop(stopCh)       // 本机/热点月度流量: 60s 采 /proc/net/dev, 停机补采落盘
	go srv.StatsCalibrationLoop(stopCh) // v5.21: 与系统 NetworkStats 对账 + 分流漏计检测(15 分钟)
	go srv.V6NeighLoop(stopCh)          // v5.20: IPv6 新邻居(临时地址轮换)→ 500ms 内 v6_sync.sh sync_macs(失败退 60s 周期)
	go srv.MacMergeLoop(stopCh)         // v5.21: 随机 MAC 画像 + 疑似同一设备建议(30s)
	go srv.ActivityLoop(stopCh)         // v5.22: 亮屏/热点/在线设备/界面 → 活动档位 + run/activity.json(15s)
	go srv.PowerSamplerLoop(stopCh)     // v5.22: 自测 CPU/唤醒 → run/power_stats.json(5 分钟)
	go srv.DNSTakeoverLoop(stopCh)      // DPI v2: 可选 DNS 接管(默认关; 开启时 10s 健康检查, 异常自动撤 DNAT)
	go srv.fgTruthLoop(stopCh)          // v5.24 T2: 本机前台真值采集(仅本机抓包开启且亮屏时, 10s 探测, 只记变化)

	if srv.remote != nil {
		if *flagNoTLS {
			log.Printf("WARN: TLS disabled (development only)")
		}
		go srv.remote.Loop(stopCh)
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

	// 远程端口的监听失败由 remoteListener 自己重试(v5.33 前 8443 起不来会 log.Fatalf
	// 让整个进程退出, 本机 8444 也跟着没了), 这里只等信号。
	sig := <-sigCh
	log.Printf("received signal %v, shutting down", sig)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	close(stopCh) // 通知所有 goroutine 停止(SaveLoop 会做最后一次 Flush; remoteListener 关远程端口)
	// DPI v2: 同步撤掉 DNS 接管的 DNAT(不等 goroutine —— 进程马上退出, 规则留着会让热点设备解析失败)
	srv.dnsTakeoverShutdown()
	if srv.remote != nil {
		srv.remote.stop("httpd 退出")
	}
	if loopbackSrv != nil {
		_ = loopbackSrv.Shutdown(ctx)
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

// v5.11: 暴露被包装的底层 ResponseWriter。http.NewResponseController 靠
// Unwrap() 逐层找到真正的连接; 缺了它, /api/events 的 SetWriteDeadline/Flush
// 恒返回 ErrNotSupported → SSE 端点永远 500 "sse unsupported", 远程 SPA 一直
// 退回轮询 (api_events.go 注释"middleware 不包裹 w"与事实不符)。
func (lrw *loggingResponseWriter) Unwrap() http.ResponseWriter {
	return lrw.ResponseWriter
}
