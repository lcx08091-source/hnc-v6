// pair.go — Patch 2.b PIN pairing flow (v4_0_design_v2.1 §6)
//
// 流程:
//   1. 主人本机用 WebUI "生成配对码" → kexec 调 shell 写 $RUN/pair_pending
//      (三行文本: pin / session_id / expiry_unix),tmp+rename 原子写
//   2. 远端设备访问 https://<热点IP>:8443 → 未鉴权 → 302 /pair
//   3. /pair 页显示 6 位 PIN 输入框
//   4. 用户输入 PIN → POST /api/pair/verify (form-urlencoded)
//   5. 服务端: constant-time 比 PIN → 发 Set-Cookie hnc_token=... + 302 /app
//   6. 写 $RUN/pair_success.<session_id> (tmp+rename 原子写)
//      让主人本机 WebUI 感知到"配对成功"
//   7. rm pair_pending
//
// 只有两个 HTTP endpoint (GET /pair, POST /api/pair/verify)。
// 生成/查状态/取消都由主人本机 WebUI 通过 kexec 操作文件,不经 HTTP。
//
// 速率限制(v2.1 §5.1):
//   - unauthRateLimitMiddleware 包在外:每 IP 20 req/s token bucket
//   - handlePairVerify 内部: PIN 错 5 次/分钟 锁 10 分钟

package main

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// pairPending 从 $RUN/pair_pending 读出的配对记录
type pairPending struct {
	PIN       string
	SessionID string
	Expiry    int64 // Unix ts
}

// readPairPending 读 $RUN/pair_pending 三行文本
// 容错: 文件不存在 / 格式错误 / 过期,返回不同的 error 让调用者决定响应码
func readPairPending(hncDir string) (*pairPending, error) {
	path := filepath.Join(hncDir, "run", "pair_pending")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("no active pairing") // 让 handler 返 400
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	var lines []string
	for sc.Scan() {
		lines = append(lines, strings.TrimSpace(sc.Text()))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read pair_pending: %w", err)
	}
	if len(lines) < 3 {
		return nil, fmt.Errorf("malformed pair_pending (need 3 lines)")
	}

	pin := lines[0]
	sid := lines[1]
	expiryStr := lines[2]

	// PIN 基本校验(6 位数字)
	if len(pin) != 6 {
		return nil, fmt.Errorf("malformed pair_pending (bad pin len)")
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("malformed pair_pending (non-digit pin)")
		}
	}

	// session_id 格式校验
	if !isPairSessionID(sid) {
		return nil, fmt.Errorf("malformed pair_pending (bad sid)")
	}

	expiry, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("malformed pair_pending (bad expiry)")
	}

	now := time.Now().Unix()
	if now >= expiry {
		// rc3 修 N-16: 过期顺手清, 否则下次 /api/pair/verify 仍返 expired
		// 导致用户"刚生成就过期"死循环
		_ = os.Remove(path)
		return nil, fmt.Errorf("pairing expired")
	}

	return &pairPending{PIN: pin, SessionID: sid, Expiry: expiry}, nil
}

// isPairSessionID 校验 session_id 格式: 8-64 字符 base64url-like
// (防路径穿越: 文件名用 pair_success.<sid> 所以必须严格)
func isPairSessionID(s string) bool {
	if len(s) < 8 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// handlePair 返回 GET /pair 页面
func (s *server) handlePair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(pairHTML)
}

// handlePairVerify 处理 POST /api/pair/verify
// form body: pin=<6 digits>
func (s *server) handlePairVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := ipOnly(r.RemoteAddr)

	// PIN 专用速率限制(独立于 unauth bucket)
	allowed, retry := s.limiter.CheckPinVerify(ip)
	if !allowed {
		w.Header().Set("Retry-After", int64ToStr(retry))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"too many pin attempts","locked_for_sec":` +
			int64ToStr(retry) + `}`))
		return
	}

	// rc2 修 G7: 4KB 上限, 防止 malicious client 喂大 body 耗内存
	//          PIN 验证只用 pin= 字段 (6 位数字), 4KB 远远够
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		writePairError(w, http.StatusBadRequest, "bad form")
		return
	}
	submitted := r.FormValue("pin")
	if len(submitted) != 6 {
		_, rem := s.limiter.RegisterPinFail(ip)
		writePairErrorWithRem(w, http.StatusBadRequest, "bad pin format", rem)
		return
	}
	for _, c := range submitted {
		if c < '0' || c > '9' {
			_, rem := s.limiter.RegisterPinFail(ip)
			writePairErrorWithRem(w, http.StatusBadRequest, "bad pin format", rem)
			return
		}
	}

	pending, err := readPairPending(s.hncDir)
	if err != nil {
		// 无活动配对 / 已过期 / 文件损坏
		msg := err.Error()
		status := http.StatusBadRequest
		if strings.Contains(msg, "expired") {
			status = http.StatusGone // 410 语义更准
		}
		// 不 RegisterPinFail(没可错的目标)
		writePairError(w, status, msg)
		return
	}

	// constant-time 比较 PIN 防 timing attack
	if subtle.ConstantTimeCompare([]byte(submitted), []byte(pending.PIN)) != 1 {
		locked, remaining := s.limiter.RegisterPinFail(ip)
		if locked {
			_, rt := s.limiter.CheckPinVerify(ip)
			w.Header().Set("Retry-After", int64ToStr(rt))
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"too many pin attempts","locked_for_sec":` +
				int64ToStr(rt) + `}`))
			return
		}
		writePairErrorWithRem(w, http.StatusBadRequest, "wrong pin", remaining)
		return
	}

	// PIN 对!颁发 token
	label := labelFromUA(r.UserAgent())
	cookieValue, tokenID, err := IssueToken(s.tokens, label, ip)
	if err != nil {
		log.Printf("IssueToken error: %v", err)
		writePairError(w, http.StatusInternalServerError, "token issue failed")
		return
	}

	// 写 pair_success marker 让本机 WebUI 感知
	if err := writePairSuccess(s.hncDir, pending.SessionID, tokenID, label); err != nil {
		log.Printf("writePairSuccess warn: %v", err)
		// 不阻止用户登入,只是本机 UI 少了通知
	}

	// 删 pair_pending(防止重用) - 一次性 PIN
	// rc3.1.34 修 #6: 之前 `_ = os.Remove(...)` 静默. 如果 remove 失败 (磁盘满 /
	// 文件被并发改名 / 权限错), 同一个 PIN 文件仍能被下一个请求读到 → 理论上
	// PIN 重放 (rate limit 5 次/分钟内). 本是一次性 PIN 的安全契约破裂.
	// 现在: log + 强制 truncate 兜底. truncate 把文件清空, 即使 Remove 没成功
	// 也让 readPending 走 "expired" 路径拒绝.
	pendingPath := filepath.Join(s.hncDir, "run", "pair_pending")
	if err := os.Remove(pendingPath); err != nil && !os.IsNotExist(err) {
		log.Printf("WARN: pair_pending remove failed (PIN replay risk): %v, attempting truncate", err)
		// 兜底: 清空文件内容. readPending 会因 unmarshal 失败拒绝.
		if tErr := os.WriteFile(pendingPath, []byte(""), 0600); tErr != nil {
			log.Printf("CRIT: pair_pending truncate also failed: %v · subsequent PINs may replay until next genPair", tErr)
		}
	}

	// 清 rate limit 计数
	s.limiter.ResetPin(ip)

	http.SetCookie(w, issuedCookie(cookieValue))
	// 302 到首页(dashboard 会用 cookie 走 authMiddleware 进入)
	http.Redirect(w, r, "/", http.StatusFound)
}

// writePairError 统一错误响应(form 提交用 JSON,方便前端提示)
func writePairError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	// 手工 json 避免依赖,msg 已经在我们控制下
	escaped := strings.ReplaceAll(msg, `"`, `\"`)
	_, _ = w.Write([]byte(`{"error":"` + escaped + `"}`))
}

// v4.0 Patch 2.d: 带剩余尝试次数的错误响应
// 前端用这个提示"还有 N 次机会"
func writePairErrorWithRem(w http.ResponseWriter, status int, msg string, remaining int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	escaped := strings.ReplaceAll(msg, `"`, `\"`)
	_, _ = w.Write([]byte(`{"error":"` + escaped + `","attempts_remaining":` + int64ToStr(int64(remaining)) + `}`))
}

// writePairSuccess 把配对结果写到 $RUN/pair_success.<sid>
// 本机 WebUI 轮询这个文件感知"有新设备配对成功"
// tmp + rename 原子写
// rc3.1.14 修 P2 (review §资源泄漏): 顺手清理 60 分钟以前的 pair_success.* 残留.
// 之前依赖 pair_gen.sh 触发清理, 但用户如果配对一次后再不配对, 旧文件永留.
func writePairSuccess(hncDir, sid, tokenID, label string) error {
	runDir := filepath.Join(hncDir, "run")
	tmp := filepath.Join(runDir, "pair_success.tmp")
	final := filepath.Join(runDir, "pair_success."+sid)

	// 顺手 GC 旧 pair_success.* 残留 (>60min)
	cutoff := time.Now().Add(-60 * time.Minute)
	if entries, err := os.ReadDir(runDir); err == nil {
		for _, ent := range entries {
			name := ent.Name()
			if !strings.HasPrefix(name, "pair_success.") || name == "pair_success.tmp" {
				continue
			}
			full := filepath.Join(runDir, name)
			if info, err := ent.Info(); err == nil && info.ModTime().Before(cutoff) {
				_ = os.Remove(full)
			}
		}
	}

	// 三行: token_id / label / now_unix
	body := fmt.Sprintf("%s\n%s\n%d\n", tokenID,
		strings.ReplaceAll(label, "\n", " "), // 防换行注入
		time.Now().Unix())
	if err := os.WriteFile(tmp, []byte(body), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// labelFromUA 从 User-Agent 猜一个可读设备名
// 只用于审计日志展示,不作安全判断
func labelFromUA(ua string) string {
	if ua == "" {
		return "Unknown Device"
	}
	uaLow := strings.ToLower(ua)

	browser := "Browser"
	switch {
	case strings.Contains(uaLow, "edg/"):
		browser = "Edge"
	case strings.Contains(uaLow, "chrome/") && !strings.Contains(uaLow, "edg/"):
		browser = "Chrome"
	case strings.Contains(uaLow, "firefox/"):
		browser = "Firefox"
	case strings.Contains(uaLow, "safari/") && !strings.Contains(uaLow, "chrome/"):
		browser = "Safari"
	}

	os := "Unknown"
	switch {
	case strings.Contains(uaLow, "iphone"):
		os = "iPhone"
	case strings.Contains(uaLow, "ipad"):
		os = "iPad"
	case strings.Contains(uaLow, "android"):
		os = "Android"
	case strings.Contains(uaLow, "windows"):
		os = "Windows"
	case strings.Contains(uaLow, "mac os x") || strings.Contains(uaLow, "macintosh"):
		os = "Mac"
	case strings.Contains(uaLow, "linux"):
		os = "Linux"
	}

	label := browser + " on " + os
	if len(label) > 64 {
		label = label[:64]
	}
	return label
}

// handleLogout 处理 POST /api/logout
//
// rc30.12.30 (P0.1): 自己解 cookie + VerifyCookie + revoke, 不依赖 authMiddleware ctx.
//
// 之前的实现假设 authMiddleware 已 inject ctxKeyTokenID, 但 /api/logout 在 isPublicPath
// 里, middleware 早期就 next.ServeHTTP 跳过验证不会 inject. 结果 tidVal 永远 nil,
// revoke 那段死代码永不执行, 只清浏览器 cookie. cookie 被偷过的攻击者照样能用
// server-side token 直到 60 天硬过期. 这是 GPT 三审 P0.
//
// 设计选择: 仍保留 /api/logout 在 isPublicPath 而非走 auth middleware. 因为 logout
// 应是 idempotent — cookie 过期/无效场景也应返回 200, 不应让用户在"我都要登出了"
// 时还看到 401. 服务端自己读 cookie, 有效就 revoke, 无效就只清浏览器 cookie. 无论
// 何种情况 status 200.
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 自己解 cookie. cookie 不存在或无效都 fall-through 到清浏览器 cookie + 200.
	cookie, err := r.Cookie(CookieName)
	if err == nil && cookie != nil && cookie.Value != "" {
		tokenID, _, verr := VerifyCookie(s.tokens, cookie.Value)
		if verr == nil && tokenID != "" {
			// 标记 revoked 并持久化.
			// rc2 修 G5: Put 内部已调 saveAtomicLocked (见 tokens.go:350), 再 Flush
			// 是第二次 saveAtomicLocked + fsync, 纯浪费. logout 单次请求原来要两次
			// fsync, 在慢盘上对用户可见.
			if tok, ok := s.tokens.Get(tokenID); ok {
				tok.Revoked = true
				_ = s.tokens.Put(tokenID, tok)
				log.Printf("logout: revoked tid=%s", TokenIDLogPrefix(tokenID))
			}
		} else if verr != nil {
			log.Printf("logout: cookie present but verify failed (%v), still clearing", verr)
		}
	}

	http.SetCookie(w, clearCookie())
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}
