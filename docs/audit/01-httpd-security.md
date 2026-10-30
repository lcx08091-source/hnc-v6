# A1 审查记录：hnc_httpd 安全面

- 基线版本：v5.33.0-rc2
- 审查员前缀：A1
- 范围：`daemon/hnc_httpd/` 下 main.go、server.go（路由与鉴权接线）、middleware.go、auth.go、tokens.go、security_headers.go、webui_access.go、pair.go、pair_guard.go、web/pair.html、remote_listener.go、tls.go、ratelimit.go、writelimit.go、audit.go、embed.go、capability.go、detached_linux.go、hnc_paths.go
- 重点：路由鉴权、本机/远程区分能否伪造、token/配对码、CSRF/Origin/CORS/Cookie、写接口限流、路径穿越、TLS 证书、错误信息泄露、并发 map
- 只记录、不改代码

## 已审文件

- main.go（全文）
- middleware.go（全文）
- auth.go（全文）
- tokens.go（全文）
- pair.go（全文）
- pair_guard.go（全文）
- web/pair.html（全文）
- ratelimit.go（全文）
- remote_listener.go（全文）
- tls.go（全文）
- webui_access.go（全文）
- security_headers.go（全文）
- embed.go（全文）

## Bug

### A1-001 [P2][确认] 撤销/清理写盘失败后不置 dirty，SaveLoop 不会重试，httpd 非正常退出后已撤销的 token 复活
- **位置**：`daemon/hnc_httpd/tokens.go:264-300`（Revoke / RevokeAll）、`daemon/hnc_httpd/tokens.go:368-378`（Prune）、`daemon/hnc_httpd/tokens.go:320-328`（FlushIfDirty）、`daemon/hnc_httpd/server.go:1321-1324`
- **触发 / 现象**：用户在设备丢失后执行 `json_set.sh token_revoke_all`（或 WebUI pair_revoke），httpd 消费 request 时 `saveAtomicLocked()` 失败（/data 满、写 tmp 失败、rename 失败等）。撤销只在内存生效，`.working` 文件照样被删；之后 SaveLoop 的 `FlushIfDirty` 看到 `dirty=false` 直接返回，永远不重写。若随后 httpd 被看门狗 kill -9 / 崩溃 / 掉电重启，`NewTokensStore` 从磁盘读回未撤销的旧状态，被盗设备的 cookie 重新有效。RevokeAll 后没有任何活跃 token 会调用 UpdateLastSeen 把 dirty 置 true，所以连“顺带落盘”的机会都没有。
- **原因**：
  ```go
  // tokens.go Revoke
  t.Revoked = true
  s.tokens[id] = t
  if err := s.saveAtomicLocked(); err != nil {
      fmt.Fprintf(os.Stderr, "tokens: revoke %s persisted in memory, save failed (SaveLoop retries): %v\n", id, err)
  }
  // FlushIfDirty
  if !s.dirty { return nil }
  ```
  `saveAtomicLocked` 只在成功时 `s.dirty = false`，失败路径既不置 true 也不返回给调用方；注释“SaveLoop retries”与代码不符。Prune 同理（注释“下次 SaveLoop 会重试 flush”）。
- **建议修复**：Revoke/RevokeAll/Prune 改内存后先 `s.dirty = true` 再调 `saveAtomicLocked()`（成功时它会清掉）；request 文件消费在保存失败时保留 `.working` 以便下轮重放。

### A1-002 [P3][确认] PIN 剩余次数差一：提示“最后 1 次机会”时，下一次提交无论对错都直接锁定，不做比对
- **位置**：`daemon/hnc_httpd/ratelimit.go:242-252`、`daemon/hnc_httpd/pair.go:209-228`、`daemon/hnc_httpd/web/pair.html:233-240`
- **触发 / 现象**：远程用户连续输错 4 次 PIN，第 4 次响应 `attempts_remaining:1`，配对页显示“最后 1 次机会”。第 5 次输入正确 PIN 后，`ConsumePinAttempt` 把计数加到 5 立刻锁定并返回 allowed=false，handler 直接 429，正确 PIN 根本没被比对，用户被锁 10 分钟（再犯指数退避）。实际每个窗口只有 4 次可比对机会，文件头注释“5 次 / 10 分钟”与提示文案都多算了一次（`security_v522_test.go:39-49` 已固化“第 5 次必锁”的行为）。另外同一处提示文本 `'⚠ PIN 错误,<b>最后 1 次机会</b>,再错就锁 10 分钟'` 经 `showMsg` 的 `textContent` 输出，`<b>` 标签会原样显示给用户。
- **原因**：
  ```go
  e.pinAttempts++
  if e.pinAttempts >= rlPinAttemptsMax {   // 第 5 次：锁定并拒绝，不进入比对
      ...
      return false, e.pinLockTS - now, 0
  }
  return true, 0, rlPinAttemptsMax - e.pinAttempts   // 第 4 次返回 1，实际已无可比对次数
  ```
- **建议修复**：remaining 改为 `rlPinAttemptsMax - 1 - e.pinAttempts`（或把锁定判定改为“比对失败后达到上限才锁”，让第 5 次真正可比对）；pair.html 去掉 `<b>` 或改用 DOM 构造。

### A1-003 [P3][确认] 未鉴权请求也会把 WebUI 标成“有人在看”，陌生客户端可让后台循环一直保持高频
- **位置**：`daemon/hnc_httpd/power_activity.go:169-176`、`daemon/hnc_httpd/middleware.go:174-177`、`daemon/hnc_httpd/server.go:207`、`daemon/hnc_httpd/power_sched.go:96,138-152`
- **触发 / 现象**：热点上任一未配对客户端（或本机任意无 root 应用访问 127.0.0.1:8444）每 <60s 请求一次 `/`、`/api/health`、`/pair`、`/css/x` 等公开路径，`powerNoteAPIHit` 都会刷新 `webuiLastHit`，`WebUIActive` 恒为 true：RateLoop 维持 2s、offload_status 维持基准周期，熄屏 `quiet` 判定也失效，省电降频永远不生效。注释声称“只有鉴权通过的请求才算有人在看（热点上的陌生客户端扫端口不会让后台一直保持高频）”，与代码不符。
- **原因**：链路是 `authMiddleware(activityTouchMiddleware(mux))`，而 authMiddleware 对公开路径直接调用 `next`：
  ```go
  if isPublicPath(r.URL.Path) {
      next.ServeHTTP(w, r)   // next = activityTouchMiddleware(mux)，未鉴权也会 powerNoteAPIHit
      return
  }
  ```
  loopback 缺 secret 时的 `/api/health` 放行分支同理。
- **建议修复**：在 activityTouchMiddleware 里只对 context 带 TokenID 或已通过 loopback secret 的请求调用 `powerNoteAPIHit`（例如 authMiddleware 在鉴权成功分支设置一个 ctx 标记），公开路径不计入。

