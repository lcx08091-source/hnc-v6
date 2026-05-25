// middleware.go — Patch 2.b auth + rate-limit middleware (v4_0_design_v2.1 §4)
//
// 请求流程:
//   accessLog → (若 public path) unauthRateLimit → handler
//              → (若 protected) authMiddleware → handler
//
// authMiddleware:
//   1. public 路径直接放行(/pair, /api/pair/verify, /static/*)
//   2. 读 cookie hnc_token,无则 302 /pair(或 API 401)
//   3. VerifyCookie → O(1) 查 tokens + 单次 bcrypt
//   4. 失败 → 清 cookie(MaxAge=-1 + Expires=1970 双保险) + 302/401
//   5. 成功 → 更新 last_seen + 把 TokenID 塞进 context + 放行
//
// remote_auth_required 开关(v2.1 §10.3):
//   rules.json.remote_auth_required=false 时, 无 cookie 也放行(过渡期友好)
//   true 时强制鉴权(Patch 3 会强升 true)
//   2.b 默认 false, 用户 opt-in 启用

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ctxKey context 里存 Token 信息的 key
type ctxKey int

const (
	ctxKeyTokenID ctxKey = iota
	ctxKeyToken
)

// CookieName hnc token cookie 名字
const CookieName = "hnc_token"

// isPublicPath 不需要 auth 的路径
//
// rc30.12.18 重构: 之前 "敏感读白名单 + 其他默认放行" 改成 "公共路径白名单 + 默认拒绝".
// 设计理由: 新加 API 默认是 401, 忘记反而是安全的, 而不是默认匿名可读. 我们之前
// 已经被 3 次 (alerts / dpi_history / app_limits 都漏过敏感读白名单).
//
// 公共路径分类:
//  1. UI 入口 (没鉴权就看不到登录页) - /, /pair, /changelog.html, /static/*
//  2. 鉴权流程本身              - /api/pair/verify, /api/pairing/status
//  3. 健康检查 / 探活            - /api/health (返回 version + watchdog_passive,
//     远程 WebUI 顶部探活. rc30.12.30 P0.4 后已删
//     session_label 死代码 — 那是 isPublicPath 下永远
//     拿不到的字段)
//  4. 登出 (idempotent, handler 自己处理 cookie revoke) - /api/logout
//
// 注意: /api/logout 仍在白名单, 但不再依赖 authMiddleware inject ctx —
// handleLogout 已改为自己解 cookie + VerifyCookie + revoke (见 pair.go).
// 这样登出对 cookie 过期/无效场景仍是 idempotent (返回 200), 同时 cookie 有效
// 时真正 revoke server-side token.
//
// 注意: "/" SPA 主页放行是为了让 JS 加载, JS 加载后会自己判断登录态并 fetch /api/*,
// 第一个 fetch 会拿到 401, WebUI 收到 401 后跳转到 /pair. 这是 SPA 标准流程.
func isPublicPath(p string) bool {
	switch p {
	case "/",
		"/pair",
		"/changelog.html",
		"/api/pair/verify",
		"/api/pairing/status",
		"/api/health",
		"/api/logout":
		return true
	}
	if strings.HasPrefix(p, "/static/") {
		return true
	}
	return false
}

// readAuthRequired 读 rules.json.auth_required
// rc3.1.13: config.json 已弃用 (post-fs-data.sh 启动时单向迁移并删除),
// 字段单源化在 rules.json. rc3.1.9~12 的 P0 故事:
//
//	原本 middleware 读 remote_auth_required (rc3.1.9 改 auth_required),
//	但前端 toggle 走 cfg_set 实际写 config.json (rc3.1.12 加 config 覆盖兜底),
//	两次都是"对齐读法"不是治本. 真正的治本是字段单源, 这就是 rc3.1.13.
//
// rc3.1.13.1 (review §2 P1): I/O / 解析 / 类型错误一律 fail-closed (return true 强制鉴权)
//
//	并打 log. 之前 fail-open 在 toggle 已 ON 用户那里, 偶发文件错误瞬间会
//	短暂打开匿名读权限. 安全方向以"出错时严"为正.
func readAuthRequired(hncDir string) bool {
	data, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json"))
	if err != nil {
		log.Printf("readAuthRequired: read rules.json failed, fail-closed: %v", err)
		return true
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("readAuthRequired: parse rules.json failed, fail-closed: %v", err)
		return true
	}
	v, ok := raw["auth_required"].(bool)
	if !ok {
		// hotfix17.8: 字段缺失/非 bool 视为配置损坏, fail-closed。
		// 全新安装由 post-fs-data.sh 写入显式 auth_required:false, 不应走到这里。
		log.Printf("readAuthRequired: auth_required missing/non-bool, fail-closed")
		return true
	}
	return v
}

// clearCookie 构造一个清除 hnc_token 的 Cookie
// Gemini v2 审查 3.1: MaxAge=-1 + Expires=time.Unix(0,0) 双保险
func clearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

// issuedCookie 构造一个 30 天有效期的 hnc_token cookie
func issuedCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   30 * 86400, // 30 天
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

// authMiddleware 要求请求带合法 token,否则 redirect/401
func (s *server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// v5.0 loopback bypass: 本地 KSU WebUI 走 loopback 不需要鉴权
		// 热点段的远程访问仍然需要 PIN + cookie
		// rc3 修 N-6: 防 DNS rebinding · 浏览器 fetch 必带 Origin/Referer,
		// ksu.exec curl 不带. 有 Origin/Referer 的 loopback 请求视为浏览器来源,
		// 强制走 cookie 鉴权路径 (而不是无条件放行).
		//
		// rc30.12.14 加固: GPT 报告指出 "本机任意能发 HTTP 请求的低信任 App 也走 loopback",
		// 单凭 loopback + 无 Origin/Referer 信任过宽. 加 root-only secret 文件校验:
		//   - service.sh 启动时生成 /data/local/hnc/run/local_admin.secret (mode 0600, owner root)
		//   - WebUI 通过 ksu.exec 读 secret 注入到 X-HNC-Local-Admin header
		//   - 普通 App (uid != root, 无 root 框架) 读不到该文件
		//
		// 向后兼容: secret 不存在 (老版本 / 没装好) 仍 fallback 到老行为, 不破坏现有部署.
		// 后续版本可以 enforce.
		if isLoopbackRequest(r) {
			if r.Header.Get("Origin") == "" && r.Header.Get("Referer") == "" {
				if s.checkLocalAdminSecret(r) {
					// 带正确 X-HNC-Local-Admin → 信任 (root-only secret)
					next.ServeHTTP(w, r)
					return
				}
				// rc30.12.16 P1-2: secret 不存在时 (老部署 / service.sh 没生成) 的兼容策略.
				// 之前: 一律 fallback 老 loopback 行为, 全放行.
				// 现在: 分级 fallback —
				//   - 写接口 (/api/action) 永远 fail-closed, 不允许 secret 缺失时通过
				//   - 敏感读接口同样 fail-closed
				//   - 其他读接口 (/, /api/health, 静态资源等) 兼容旧行为放行
				// 这样升级中 secret 临时不存在时, 用户 WebUI 仍能看到首页和健康状态,
				// 但任何变更操作必须 secret 就绪后才能执行.
				if !s.localAdminSecretExists() {
					if isWritePath(r.URL.Path) || isSensitiveReadPath(r.URL.Path) {
						log.Printf("loopback without secret + write/sensitive path → fail-closed (path=%s)", r.URL.Path)
						respondUnauthorized(w, r, false)
						return
					}
					// 非敏感路径 → 兼容老行为放行 (首页 / 健康检查 / 静态)
					next.ServeHTTP(w, r)
					return
				}
				// secret 存在但请求没带, 或带错 → 拒绝
				log.Printf("loopback without valid X-HNC-Local-Admin → reject (path=%s)", r.URL.Path)
				respondUnauthorized(w, r, false)
				return
			}
			log.Printf("loopback with Origin/Referer → cookie auth required: origin=%q ref=%q",
				r.Header.Get("Origin"), r.Header.Get("Referer"))
			// 不 return · 继续走下面 cookie 鉴权路径
		}

		// 同步 tokens.json 如果被外部修改过(json_set.sh revoke)
		_ = s.tokens.SyncIfChanged()

		cookie, err := r.Cookie(CookieName)
		if err != nil || cookie.Value == "" {
			// rc30.12.18: 默认拒绝重构.
			//
			// 之前: !readAuthRequired() && !isWritePath() && !isSensitiveReadPath() → 放行
			//       (即 auth_required=false 时, 写接口和敏感读以外全放行匿名)
			//
			// 现在: 任何到这里的请求都必须有 cookie. 公共路径已在 isPublicPath()
			//       提前放行, 其他全拒.
			//
			// 行为变化: 老用户 (rules.json auth_required=false) 升级后远程访问
			// 会被强制要求登录. SPA 客户端收到 401 应自动跳转 /pair, 用户走一遍
			// 配对流程即可. 配对配置本身仍由 /api/pairing/status 公开查询.
			//
			// 兼容性: auth_required 字段保留在 rules.json (不报错), 但不再有
			// "放行匿名" 的语义.
			//
			// rc30.12.30 (P0.3): forceRemoteAuth 全局变量删除 — 没有任何代码读它,
			// rc30.12.18 默认拒绝重构后就语义死了, 但变量留着误导读者. 已从 main.go 删.
			if !readAuthRequired(s.hncDir) {
				// 老用户 rules.json 还是 false. 打 log 一次性提醒, 但仍 fail-closed.
				log.Printf("auth: anonymous request to %s (auth_required=false in rules.json, but rc30.12.18 enforces default-deny → 401)", r.URL.Path)
			}
			respondUnauthorized(w, r, false)
			return
		}

		tokenID, tok, err := VerifyCookie(s.tokens, cookie.Value)
		if err != nil {
			// cookie 无效,清掉
			respondUnauthorized(w, r, true)
			return
		}

		// 成功:更新 last_seen + 塞 context
		s.tokens.UpdateLastSeen(tokenID)
		log.Printf("auth ok: %s %s tid=%s ip=%s",
			r.Method, r.URL.Path, TokenIDLogPrefix(tokenID), ipOnly(r.RemoteAddr))

		ctx := context.WithValue(r.Context(), ctxKeyTokenID, tokenID)
		ctx = context.WithValue(ctx, ctxKeyToken, tok)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// v4.0 Patch 3.a: 写操作路径 - 永不放行匿名,即使过渡期也强制鉴权。
// 也用于 loopback-secret 缺失时的分级 fail-closed(见 authMiddleware)。
// v5.8.2 (audit P2-2): 把 self toggles + export 也归类为写路径 —— 它们都是
// 状态变更端点, 之前漏在这里, 导致 secret 缺失的 loopback 兜底把它们当普通
// 路径放行。
func isWritePath(p string) bool {
	switch p {
	case "/api/action",
		"/api/self/toggle",
		"/api/self/auto_expand/toggle",
		"/api/self/auto_promote/toggle",
		"/api/export":
		return true
	}
	return false
}

// mutatingMaxBytes caps request bodies for state-changing endpoints.
const mutatingMaxBytes = 16384

// requireMutation wraps a state-changing handler with the same guards
// /api/action enforces inline: POST only, Content-Type application/json, and an
// X-HNC-CSRF: 1 header (defence-in-depth on top of SameSite=Strict cookies —
// cross-site fetch can't set custom headers without a CORS preflight we never
// allow), plus a body-size cap so an authenticated (or cookie-stolen) client
// can't OOM us with a giant body.
//
// v5.8.2 (audit P2-2): centralised after the api_self toggles and /api/export
// were found to skip these checks (no MaxBytesReader, no CSRF/content-type).
func (s *server) requireMutation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "content-type must be application/json"})
			return
		}
		if r.Header.Get("X-HNC-CSRF") != "1" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "csrf header missing"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, mutatingMaxBytes)
		next(w, r)
	}
}

// hotfix17.8: 敏感只读接口。
//
// rc30.12.18 重构后用途变化: 主鉴权流程改为"默认拒绝"后, 这个白名单不再用于
// "remote_auth_required=false 时哪些读接口仍需 cookie" 的判断 (因为现在所有
// 非 isPublicPath 都需要 cookie).
//
// 仍保留是因为 loopback secret 缺失场景仍需要分级判断:
//   - secret 不存在 + 是写接口 / 敏感读 → fail-closed
//   - secret 不存在 + 普通读 (主页/静态) → 兼容放行
//
// 这避免升级窗口期 (secret 还没生成) WebUI 完全瘫痪.
//
// 注: rc30.12.16 加了 alerts/dpi_history/app_limits 3 个之前漏的;
//
//	logout 不该算敏感, 登出永远应该允许 (现已移到 isPublicPath).
func isSensitiveReadPath(p string) bool {
	// 导出 zip 下载 /api/exports/<name> 是前缀路由, switch 精确匹配兜不住.
	if strings.HasPrefix(p, "/api/exports/") {
		return true
	}
	switch p {
	case "/api/logs",
		"/api/devices",
		"/api/live",
		"/api/capabilities",
		"/api/tokens",
		"/api/config",
		"/api/stats",
		"/api/templates",
		"/api/metrics",
		"/api/iface_info",
		"/api/offload_status",
		"/api/dpi_state",
		"/api/dpi_probe",
		"/api/alerts",
		"/api/dpi_history",
		"/api/app_limits",
		// v5.8.9: secret 缺失兼容窗口里这些只读端点之前漏归类, 会被任意本机
		// 低信任 App 经 loopback 读取(导出列表/自归因/运行健康/SSE 变更流).
		"/api/exports",
		"/api/self",
		"/api/self/attrib",
		"/api/self/ifaces",
		"/api/sla",
		"/api/events":
		return true
	default:
		return false
	}
}

// respondUnauthorized 拒绝无效/缺失 token 的请求
// clearExisting=true 时下发过期 cookie 清浏览器
func respondUnauthorized(w http.ResponseWriter, r *http.Request, clearExisting bool) {
	if clearExisting {
		http.SetCookie(w, clearCookie())
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"auth required"}`))
	} else {
		http.Redirect(w, r, "/pair", http.StatusFound)
	}
}

// unauthRateLimitMiddleware 包裹公开路径(/pair, /api/pair/verify),
// 每 IP 20 req/s token bucket。
// 目的: 防止爬虫 + 恶意请求耗资源。PIN 自己的 5 次/分锁在 handlePairVerify 里做。
func (s *server) unauthRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ipOnly(r.RemoteAddr)
		allowed, retry := s.limiter.CheckUnauth(ip)
		if !allowed {
			w.Header().Set("Retry-After", int64ToStr(retry))
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func int64ToStr(n int64) string {
	// 避免 import strconv 多一次
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// isLoopbackRequest 判定请求是否来自 loopback 接口。
// v5.0 新增: KSU WebUI 在本机通过 http://127.0.0.1:<port>/ 访问时免鉴权。
// 注: RemoteAddr 格式 "ip:port", 可能是 IPv4 "127.0.0.1:xxx" 或 IPv6 "[::1]:xxx"。
func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	// rc3 修 N-14: IPv4-mapped IPv6 (如 "::ffff:127.0.0.1") 也算 loopback
	// Android bionic 某些场景下 curl 127.0.0.1 会通过 IPv4-in-IPv6 到达,
	// 直接 ip.IsLoopback() 返 false, 导致 ksu.exec 请求偶尔被判远程.
	if v4 := ip.To4(); v4 != nil {
		return v4.IsLoopback()
	}
	return ip.IsLoopback()
}

// ─── rc30.12.14 加固: loopback 本机管理员密钥 ───────────────────────────────
//
// 设计目的: 防止"本机任意能发 HTTP 请求的低信任 App 直接调用管理面" (GPT 报告 P0).
//
// 工作原理:
//   1. service.sh 启动时生成 /data/local/hnc/run/local_admin.secret (mode 0600, owner root)
//   2. 32 字节随机, hex 编码
//   3. KSU WebUI 通过 ksu.exec (有 root 权限) 读 secret 注入 X-HNC-Local-Admin header
//   4. 普通 App (无 root) 读不到该文件 → 无法构造 valid header → 走 cookie 鉴权流程
//
// 向后兼容: secret 不存在时 (老部署 / service.sh 没生成) 仍 fallback 到 v5.0 行为.

const localAdminSecretRelPath = "run/local_admin.secret"

// localAdminSecretExists 检查 secret 文件是否存在
func (s *server) localAdminSecretExists() bool {
	p := filepath.Join(s.hncDir, localAdminSecretRelPath)
	_, err := os.Stat(p)
	return err == nil
}

// checkLocalAdminSecret 比对请求 header 跟磁盘 secret.
// 用 constant-time compare 防 timing attack.
//
// rc30.12.30 (P0.2): 加 64 字符 hex 严格校验.
//
// 之前只比较长度是否相等. 如果磁盘 secret 被部分写入 (截断/写半), 后端会接受同样
// 截断长度的伪 secret. service.sh 生成的是 32 字节 hex = 64 字符, 不应接受任何
// 其他形式. 前端 (hf2 已修) 明确 /^[0-9a-fA-F]{64}$/.test(s), 后端必须对齐.
//
// 威胁面有限 (文件 mode 0600 + owner root, 普通进程写不进), 但前端做了后端必须严,
// 否则下一次某个写者把文件写坏, 整条防线松动. 这是 defense-in-depth.
func (s *server) checkLocalAdminSecret(r *http.Request) bool {
	got := strings.TrimSpace(r.Header.Get("X-HNC-Local-Admin"))
	if !isValid64Hex(got) {
		return false
	}
	p := filepath.Join(s.hncDir, localAdminSecretRelPath)
	wantB, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	want := strings.TrimSpace(string(wantB))
	if !isValid64Hex(want) {
		// 磁盘 secret 不是合法 64 hex (被截断/写坏), 拒绝. service.sh 应重新生成.
		log.Printf("checkLocalAdminSecret: on-disk secret invalid (not 64 hex), rejecting all requests until regenerated")
		return false
	}
	// 现在 got 和 want 都是 64 字符 hex, 长度天然相等 (不再需要单独 len check).
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// isValid64Hex 检查字符串是否恰好 64 字符且全为 hex.
// rc30.12.30 (P0.2): 跟前端 /^[0-9a-fA-F]{64}$/.test(s) 对齐.
func isValid64Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F')
		if !ok {
			return false
		}
	}
	return true
}
