package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type rateSample struct {
	rxBytes int64
	txBytes int64
	ts      int64 // unix seconds
	// rc3.1.34 修 #5: 缓存上次成功计算的速率值. 高频请求 (两 client 同时刷, 或
	// 前端 2.5s 轮询撞 stats_sample 30s 周期) 会让 dt<2, 之前直接返 0 → UI 速率
	// 间歇掉零. 现在 dt<2 时保留 prev sample 不覆盖, 同时返回 lastRxBps/Bps,
	// UI 看到的就是上轮的真实速率, 平滑过渡到下次正常差分.
	lastRxBps int64
	lastTxBps int64
}

type server struct {
	hncDir       string
	tokens       *TokensStore
	limiter      *RateLimiter
	writeCounter *WriteCounter // Patch 3.a per-token write rate limit
	// hotfix4: serialize state-changing actions and keep /api/devices from
	// reading rules.json/devices.json while an httpd-originated write chain is running.
	// This is deliberately coarse-grained: tc/iptables/json_set actions are short,
	// and preserving operation order is safer than introducing parallel shell workers.
	stateMu sync.RWMutex
	// v5.1 · P1-1 修复: 速率差分. 每次 /api/devices 被调用时用当前
	// rx_bytes/tx_bytes 和上一轮做差, 得到 rx_bps/tx_bps.
	rateMu      sync.Mutex
	lastSamples map[string]rateSample
	// rc3.1.26 · offload_status 缓存 (check_offload.sh 含 sleep 5, 避免每请求阻塞)
	// OffloadLoop 每 30s 跑一次脚本更新 offloadCache, apiOffloadStatus 直接读
	offloadMu    sync.RWMutex
	offloadCache offloadResp
	offloadReady bool // false 时返回 {active:false, detail:"PENDING"}, 避免首次启动 30s 窗口内假报 IDLE
}

func newServer(hncDir string) *server {
	return &server{
		hncDir:       hncDir,
		tokens:       NewTokensStore(filepath.Join(hncDir, "data", "remote_tokens.json")),
		limiter:      NewRateLimiter(),
		writeCounter: NewWriteCounter(),
		lastSamples:  make(map[string]rateSample),
	}
}

// checkWriteRate 限每 TokenID 60 写/分钟
// 返回 true 允许, false 拒绝
func (s *server) checkWriteRate(key string) bool {
	return s.writeCounter.CheckAndIncr(key)
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()

	// 静态页(/ = dashboard,走 authMiddleware 保护)
	mux.HandleFunc("/", s.serveIndex)
	// 静态资源 /static/* 在 authMiddleware 里是 public,无需登录
	mux.HandleFunc("/static/", s.serveStatic)

	// v4.0 Patch 2.b: 配对页 + 配对 endpoint
	// 外层 unauthRateLimit 每 IP 20 req/s; PIN 5 次/分钟 锁在 handlePairVerify 内部
	mux.Handle("/pair", s.unauthRateLimitMiddleware(http.HandlerFunc(s.handlePair)))
	mux.Handle("/api/pair/verify", s.unauthRateLimitMiddleware(http.HandlerFunc(s.handlePairVerify)))

	// 只读 API(被 authMiddleware 保护,2.b 默认 remote_auth_required=false 放行)
	mux.HandleFunc("/api/health", s.apiHealth)
	mux.HandleFunc("/api/devices", s.apiDevices)
	mux.HandleFunc("/api/live", s.apiLive)
	mux.HandleFunc("/api/capabilities", s.apiCapabilities)
	mux.HandleFunc("/api/sqm", s.apiSQMStatus) // v5.3.0-rc5 Smart Queue status
	mux.HandleFunc("/api/metrics", s.apiMetrics)
	mux.HandleFunc("/api/stats", s.apiStats)
	mux.HandleFunc("/api/templates", s.apiTemplates)
	// v5.3.0-rc12: DPI passive observability (hnc_dpid daemon)
	mux.HandleFunc("/api/dpi_state", s.apiDPIState)
	mux.HandleFunc("/api/dpi_probe", s.apiDPIProbe)
	// rc30.4: traffic history (per-app pie + per-hour line chart)
	mux.HandleFunc("/api/dpi_history", s.apiDPIHistory)
	// rc30.5: alert log (unknown device detection)
	mux.HandleFunc("/api/alerts", s.apiAlerts)
	// rc30.6: per-app rate limit config
	mux.HandleFunc("/api/app_limits", s.apiAppLimits)
	// logout: 需要已鉴权才能 revoke 自己(无鉴权也能清 cookie)
	mux.HandleFunc("/api/logout", s.handleLogout)

	// v5.0 新增 GET endpoint (B 路线 · 修 Bug 2/A/C)
	mux.HandleFunc("/api/config", s.apiConfig)
	mux.HandleFunc("/api/tokens", s.apiTokens)
	mux.HandleFunc("/api/iface_info", s.apiIfaceInfo)
	mux.HandleFunc("/api/logs", s.apiLogs)
	mux.HandleFunc("/api/offload_status", s.apiOffloadStatus) // v5.1 P2-6
	// v5.0 serve 磁盘 webroot/changelog.html
	mux.HandleFunc("/changelog.html", s.serveChangelog)

	// v4.0 Patch 3.a: 写操作统一 endpoint, 内部白名单 + per-token rate limit + CSRF
	// 必经 authMiddleware(不允许过渡期匿名写)
	mux.HandleFunc("/api/action", s.handleAction)

	// 中间件链: accessLog → authMiddleware → mux
	return accessLogMiddleware(s.authMiddleware(mux))
}

// ═══ 静态资源 ═══════════════════════════════════════════════════

// rc2 修 G8: serveIndex loopback 路径每请求 os.ReadFile 222KB, 前端 2.5s 轮询压榨 I/O.
// 模块路径下的 index.html 在 httpd 生命周期内不变(reinstall 会重启 httpd), 启动后
// 第一次读缓存即可. atomic.Value 避免多 goroutine 首读竞态, sync.Once 确保只读一次.
var (
	indexDiskOnce  sync.Once
	indexDiskBytes []byte
)

func loadIndexDiskOnce() []byte {
	indexDiskOnce.Do(func() {
		const diskPath = "/data/adb/modules/hotspot_network_control/webroot/index.html"
		if data, err := os.ReadFile(diskPath); err == nil && len(data) > 0 {
			indexDiskBytes = data
		}
	})
	return indexDiskBytes
}

func (s *server) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// rc3.1.13.2 P0-A 深度防御: CSP 限定 script/style 源头, 减小 XSS 爆炸半径.
	// 内联 script/style 由 webroot/index.html 大量使用, unsafe-inline 必须保留.
	// 但禁掉 object/base/frame 还是能挡掉一部分 XSS payload (如 <object data=javascript:>).
	// 真正修法是 esc() (已在 webroot/index.html 全部 ${d.xxx} 注入点加上).
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' 'unsafe-inline'; "+
			"style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; "+
			"connect-src 'self' http://127.0.0.1:8444; "+
			"object-src 'none'; "+
			"base-uri 'self'; "+
			"frame-ancestors 'none'")
	// rc3.1.8 修: 远端浏览器和本地 KSU WebView 必须 serve 不同 HTML
	//  - loopback 8444  → webroot/index.html (依赖 window.ksu.exec curl bridge)
	//  - 远端 0.0.0.0:8443 → embed 的 web/app.html (用同源 fetch 直连 /api/*)
	// 之前统一 serve webroot/index.html 导致远端加载后 detectKsuLike 失败,
	// 用户看到 "需要 KernelSU/Magisk WebUI" 卡死页, 硬编码显示 v4.0.0-patch5.0
	// (rc3.1.x 以来一直没更新). app.html + app.js 原本就是 embed 且能独立工作的
	// 远端 UI, 只是从未挂到路由上.
	//
	// rc30.12.28 修: 本地手机浏览器访问 127.0.0.1:8443 时也是 loopback, 之前同样 serve
	// KSU 版导致 "需要 KernelSU 或 Magisk WebUI" 白屏. 现在加 UA 检测: loopback 但 UA
	// 不像 KSU/Magisk WebView 时, 也 serve 浏览器版本.
	// KSU/SukiSU WebView 的 UA 包含 "KernelSU" 或 file:// 来源, 没有 "Mozilla/5.0";
	// 而手机浏览器 UA 都带 "Mozilla/5.0" + "Mobile".
	if !isLoopbackRequest(r) {
		_, _ = w.Write(indexHTML) // embed: web/app.html
		return
	}
	if !looksLikeKSUWebView(r) {
		// loopback 但是普通浏览器 (Chrome / Safari / 系统浏览器), 给浏览器版本
		_, _ = w.Write(indexHTML) // embed: web/app.html
		return
	}
	// 本地 loopback + KSU WebView UA: serve 磁盘上的 KSU bridge 版 UI
	// 注: 模块实际 install 路径是 /data/adb/modules/hotspot_network_control/webroot/,
	// 但 data dir (s.hncDir) 是 /data/local/hnc, 两者不同。用 post-fs-data.sh 建 symlink 或
	// 直接硬编码模块路径(更简单)
	// rc2 修 G8: 首次 os.ReadFile 后缓存, 后续直接 memcpy 到 response (快 ~100x).
	if data := loadIndexDiskOnce(); data != nil {
		_, _ = w.Write(data)
		return
	}
	// fallback: 本地也读不到磁盘版就退化到 embed (比丢白屏强)
	_, _ = w.Write(indexHTML)
}

// looksLikeKSUWebView 判断请求是不是来自 KSU/SukiSU/Magisk 的内嵌 WebView.
// rc30.12.28: 之前只看 loopback IP, 把"本机浏览器访问 127.0.0.1"也判成 KSU,
// 用户看到"需要 KernelSU 或 Magisk WebUI"白屏. 现在加 UA 检测.
//
// KSU/SukiSU WebView 的特征:
//   - UA 含 "Android" 但不像普通浏览器 (没 Chrome 完整 token)
//   - 部分管理器加 X-KernelSU-Version 之类自定义 header (不强求)
//   - 没有 Referer (file:// 加载) — 但浏览器首次访问也可能没 Referer
//
// 最简单可靠的启发式: 如果 UA 带完整的 Chrome/Safari/Firefox 标识, 一定是浏览器;
// 否则可能是 WebView (这里宽松一点, 不能确认是浏览器就给 KSU 版兜底, 因为浏览器
// 还会自动跳 /pair, 不会卡死).
//
// rc30.12.28: 反转策略 - 默认假设 loopback 客户端是浏览器 (现在浏览器 WebUI 能用),
// 只有 UA 明确像 WebView 时才给 KSU 版. KSU WebView 通常 UA 是 "Mozilla/5.0 (Linux; ..."
// 而手机浏览器是 "Mozilla/5.0 (Linux; Android XX; ... Chrome/..." 含 "Chrome" 关键字.
func looksLikeKSUWebView(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		// 没 UA 当 WebView (curl/wget 也可能这样, 但它们应该走 API 不是 /)
		return true
	}
	// 浏览器特征: 含 Chrome / Edg / Firefox / Safari (不含 wv 的)
	// WebView 特征: UA 含 "wv" (Android WebView 标识) 或非常短没有 Chrome token
	if strings.Contains(ua, "; wv)") || strings.Contains(ua, "wv)") {
		return true
	}
	// 标识为完整 Chrome/Firefox 浏览器
	if strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "; wv") {
		return false
	}
	if strings.Contains(ua, "Firefox/") {
		return false
	}
	if strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome/") {
		return false
	}
	// 其他情况默认 WebView (保守)
	return true
}

// serveChangelog · v5.0 新增, serve 磁盘 webroot/changelog.html 给 lazy load 用
func (s *server) serveChangelog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	diskPath := "/data/adb/modules/hotspot_network_control/webroot/changelog.html"
	if data, err := os.ReadFile(diskPath); err == nil && len(data) > 0 {
		_, _ = w.Write(data)
		return
	}
	http.NotFound(w, r)
}

func (s *server) serveStatic(w http.ResponseWriter, r *http.Request) {
	// MVP 阶段静态资源也嵌入二进制,未来可以支持从磁盘 serve
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	switch name {
	case "app.js":
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write(appJS)
	case "style.css":
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write(styleCSS)
	default:
		http.NotFound(w, r)
	}
}

// ═══ API: health check ═════════════════════════════════════════

func (s *server) apiHealth(w http.ResponseWriter, r *http.Request) {
	// v4.0.0-patch1.3: 暴露 watchdog passive mode 状态
	// watchdog 在 check_health 反复失败时进入 passive,touch 这个 marker 文件
	// 远端 dashboard 读到 watchdog_passive=true 时显示 warning 让用户知情
	passive := false
	if _, err := os.Stat(filepath.Join(s.hncDir, "run", "watchdog_passive.marker")); err == nil {
		passive = true
	}

	// rc30.12.30 (P0.4): 删 session_label 死代码.
	// 之前从 ctx 取 Token 拿 Label 写进 resp, 但 /api/health 在 isPublicPath,
	// authMiddleware 不会 inject ctxKeyToken, tokVal 永远 nil. 这段代码从来没跑过.
	// 选项:
	//   (a) 移出 isPublicPath - 但远程 WebUI 顶部 fetch('/api/health') 探活会拿
	//       version 和 watchdog_passive (app.js:974), 移走会破坏匿名探活. 不可接受.
	//   (b) 删 session_label 死代码 - 保留匿名探活, 失去 session label UX (次要功能).
	// 选了 (b). 如果未来想恢复 session label, 走独立 /api/whoami 端点 (鉴权).
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":           "ok",
		"version":          version,
		"hnc_dir":          s.hncDir,
		"watchdog_passive": passive,
	})
}

// ═══ API: devices ═══════════════════════════════════════════════
// 读取 devices.json 和 rules.json,合并成 dashboard 用的结构
// 跟 WebUI 的 readAndRender 做同样的事,但在后端合并,前端只渲染

func (s *server) apiDevices(w http.ResponseWriter, r *http.Request) {
	status, payload := s.buildDevicesPayload()
	writeJSON(w, status, payload)
}

func (s *server) buildDevicesPayload() (int, map[string]interface{}) {
	// hotfix5: build the whole snapshot under the RW lock, but do not hold the
	// lock while writing the HTTP response. A slow remote client should not block
	// later /api/action writes. External writers such as hotspotd/watchdog can
	// still update files, but httpd no longer races with its own shell write chain.
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()

	devicesPath := filepath.Join(s.hncDir, "data", "devices.json")
	rulesPath := filepath.Join(s.hncDir, "data", "rules.json")
	namesPath := filepath.Join(s.hncDir, "data", "device_names.json")

	devicesRaw, err := readJSON(devicesPath)
	if err != nil {
		// hotfix5: devices.json can be temporarily missing while hotspotd starts or
		// when the hotspot is off. Still return persistent rules/blacklist entries
		// so the remote and on-device UI can show and clear configured state.
		log.Printf("apiDevices: read devices.json failed, using empty device snapshot: %v", err)
		devicesRaw = map[string]interface{}{}
	}
	devicesMap, _ := devicesRaw.(map[string]interface{})
	if devicesMap == nil {
		log.Printf("apiDevices: devices.json root is not an object, using empty device snapshot")
		devicesMap = map[string]interface{}{}
	}

	rulesRaw, _ := readJSON(rulesPath)
	rulesMap, _ := rulesRaw.(map[string]interface{})
	if rulesMap == nil {
		rulesMap = map[string]interface{}{}
	}

	namesRaw, _ := readJSON(namesPath)
	namesMap, _ := namesRaw.(map[string]interface{})
	if namesMap == nil {
		namesMap = map[string]interface{}{}
	}

	deviceRules, _ := rulesMap["devices"].(map[string]interface{})
	blacklist, _ := rulesMap["blacklist"].([]interface{})
	blSet := make(map[string]bool)
	for _, m := range blacklist {
		if s, ok := m.(string); ok {
			blSet[strings.ToLower(s)] = true
		}
	}

	nowSec := float64(time.Now().Unix())
	nowUnix := time.Now().Unix()

	// v5.1 P1-1: 计算速率差分
	// 锁一次, 读写快照 map 都在内部
	s.rateMu.Lock()
	newSamples := make(map[string]rateSample, len(devicesMap))

	// 合并
	out := make([]map[string]interface{}, 0, len(devicesMap))
	seen := make(map[string]bool, len(devicesMap))
	for mac, devRaw := range devicesMap {
		dev, _ := devRaw.(map[string]interface{})
		if dev == nil {
			continue
		}
		macKey := strings.ToLower(mac)
		seen[macKey] = true
		merged := map[string]interface{}{
			"mac": mac,
		}
		// 复制 devices.json 所有字段
		for k, v := range dev {
			merged[k] = v
		}
		// 叠加 rules.json 里的规则
		if deviceRules != nil {
			ruleRaw, ok := deviceRules[mac]
			if !ok {
				ruleRaw = deviceRules[macKey]
			}
			if rule, ok := ruleRaw.(map[string]interface{}); ok {
				for _, k := range []string{"mark_id", "down_mbps", "up_mbps", "delay_ms",
					"jitter_ms", "loss_pct", "limit_enabled", "delay_enabled"} {
					if v, exists := rule[k]; exists {
						merged[k] = v
					}
				}
			}
		}
		// manual name 覆盖(最高优先级). hotfix5: tolerate case differences
		// between hotspotd's devices.json key and rules/names JSON keys.
		nmRaw, ok := namesMap[mac]
		if !ok {
			nmRaw = namesMap[macKey]
		}
		if nm, ok := nmRaw.(string); ok && nm != "" {
			merged["hostname"] = nm
			merged["hostname_src"] = "manual"
		}
		// 黑名单状态
		if blSet[strings.ToLower(mac)] {
			merged["status"] = "blocked"
		} else {
			merged["status"] = "allowed"
		}
		// online 判断(跟 WebUI 一致: last_seen 在 90s 内)
		lastSeen, _ := merged["last_seen"].(float64)
		merged["online"] = lastSeen > 0 && (nowSec-lastSeen) < 90

		// v5.1 P1-1: rx_bps / tx_bps 差分计算
		// rc3.1.34 修 #5: 之前无条件 newSamples[mac]=now, 高频请求 (两 client 同时
		// 刷 / 前端 2.5s 轮询碰巧错位) 让 dt<2, 走 "if dt>=2" else 分支 → rxBps=0,
		// 然后覆盖 prev → 下一次还是 dt 小 → 速率永远 0. 修法: dt<2 时保留 prev
		// sample 不覆盖, 返回缓存的 lastRxBps/Bps. 这样 UI 看到上轮真实速率而不是 0.
		rxB, _ := toInt64(merged["rx_bytes"])
		txB, _ := toInt64(merged["tx_bytes"])

		var rxBps, txBps int64
		if prev, ok := s.lastSamples[mac]; ok {
			dt := nowUnix - prev.ts
			if dt >= 2 && dt <= 120 {
				// 正常差分窗口: 计算速率 + 推进 sample, 缓存最新结果
				drx := rxB - prev.rxBytes
				dtx := txB - prev.txBytes
				if drx < 0 {
					drx = 0
				}
				if dtx < 0 {
					dtx = 0
				}
				rxBps = drx / dt
				txBps = dtx / dt
				newSamples[mac] = rateSample{
					rxBytes:   rxB,
					txBytes:   txB,
					ts:        nowUnix,
					lastRxBps: rxBps,
					lastTxBps: txBps,
				}
			} else if dt < 2 {
				// 高频请求: 保留 prev 不覆盖, 让下次 GET dt 足够大. 速率沿用上次缓存值.
				newSamples[mac] = prev
				rxBps = prev.lastRxBps
				txBps = prev.lastTxBps
			} else {
				// dt > 120: 长间隔(stats_sample 中断 / counter reset), 重新初始化
				newSamples[mac] = rateSample{rxBytes: rxB, txBytes: txB, ts: nowUnix}
			}
		} else {
			// 首次见此 MAC: 初始化, 不计算速率
			newSamples[mac] = rateSample{rxBytes: rxB, txBytes: txB, ts: nowUnix}
		}
		merged["rx_bps"] = rxBps
		merged["tx_bps"] = txBps

		out = append(out, merged)
	}

	// UI sync hotfix: devices.json only contains currently discovered clients.
	// A device with persistent rules/blacklist can disappear from devices.json after
	// disconnect, making the remote UI look out of sync with rules.json. Append
	// rule-only / blacklist-only entries as offline rows so the UI still shows the
	// configured state and can clear it.
	appendRuleOnly := func(mac string, rule map[string]interface{}) {
		mac = strings.ToLower(strings.TrimSpace(mac))
		if mac == "" || seen[mac] {
			return
		}
		seen[mac] = true
		merged := map[string]interface{}{
			"mac":    mac,
			"ip":     "-",
			"online": false,
			"rx_bps": int64(0),
			"tx_bps": int64(0),
		}
		if rule != nil {
			for _, k := range []string{"ip", "mark_id", "down_mbps", "up_mbps", "delay_ms",
				"jitter_ms", "loss_pct", "limit_enabled", "delay_enabled"} {
				if v, exists := rule[k]; exists {
					merged[k] = v
				}
			}
		}
		nmRaw, ok := namesMap[mac]
		if !ok {
			nmRaw = namesMap[strings.ToUpper(mac)]
		}
		if nm, ok := nmRaw.(string); ok && nm != "" {
			merged["hostname"] = nm
			merged["hostname_src"] = "manual"
		}
		if blSet[mac] {
			merged["status"] = "blocked"
		} else {
			merged["status"] = "allowed"
		}
		out = append(out, merged)
	}
	if deviceRules != nil {
		for mac, ruleRaw := range deviceRules {
			rule, _ := ruleRaw.(map[string]interface{})
			appendRuleOnly(mac, rule)
		}
	}
	for mac := range blSet {
		appendRuleOnly(mac, nil)
	}

	// 更新快照 (只保留本轮真实出现的 MAC, 过期的自动丢弃)
	s.lastSamples = newSamples
	s.rateMu.Unlock()

	// 按 ip 排序稳定前端显示 · rc3 N-9: 数值序 (避免 .10 < .2 字符串序)
	ipSortKey := func(s string) [4]int {
		var k [4]int
		parts := strings.Split(s, ".")
		if len(parts) == 4 {
			for i := 0; i < 4; i++ {
				n, _ := strconv.Atoi(parts[i])
				k[i] = n
			}
		}
		return k
	}
	sort.Slice(out, func(i, j int) bool {
		ki, kj := ipSortKey(asString(out[i]["ip"])), ipSortKey(asString(out[j]["ip"]))
		for x := 0; x < 4; x++ {
			if ki[x] != kj[x] {
				return ki[x] < kj[x]
			}
		}
		return false
	})

	return http.StatusOK, map[string]interface{}{
		"devices":        out,
		"whitelist_mode": rulesMap["whitelist_mode"],
		"remote_enabled": rulesMap["remote_enabled"],
	}
}

// ═══ API: stats ═════════════════════════════════════════════════
// 读 stats_raw.jsonl(今日)+ stats_daily.jsonl(历史)
// Query: ?range=today|week|month|all&mac=<optional>
// 聚合逻辑跟 WebUI v3.9.1 的 aggregateStats 等价,在后端算,前端只画图

func (s *server) apiStats(w http.ResponseWriter, r *http.Request) {
	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "today"
	}
	macFilter := strings.ToLower(r.URL.Query().Get("mac"))
	sourceParam := strings.ToLower(r.URL.Query().Get("source"))
	if sourceParam == "" {
		sourceParam = "legacy"
	}

	if !validRange(rangeParam) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid range"})
		return
	}
	if macFilter != "" && !validMAC(macFilter) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mac"})
		return
	}
	if !validStatsSource(sourceParam) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid stats source"})
		return
	}

	rawName := "stats_raw.jsonl"
	dailyName := "stats_daily.jsonl"
	if sourceParam == "shadow" {
		rawName = "stats_shadow_raw.jsonl"
		dailyName = "stats_shadow_daily.jsonl"
	}
	rawPath := filepath.Join(s.hncDir, "data", rawName)
	dailyPath := filepath.Join(s.hncDir, "data", dailyName)

	raw := readJSONL(rawPath)
	daily := readJSONL(dailyPath)

	// 过滤 mac
	if macFilter != "" {
		raw = filterByMAC(raw, macFilter)
		daily = filterByMAC(daily, macFilter)
	}

	buckets := aggregate(rangeParam, raw, daily)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"range":   rangeParam,
		"mac":     macFilter,
		"source":  sourceParam,
		"buckets": buckets,
	})
}

// ═══ API: templates(只读) ══════════════════════════════════════

func (s *server) apiTemplates(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.hncDir, "data", "templates.json")
	data, err := readJSON(path)
	if err != nil {
		// 文件不存在视为空
		data = map[string]interface{}{}
	}
	writeJSON(w, http.StatusOK, data)
}

// ═══ 辅助 ═══════════════════════════════════════════════════════

func readJSON(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// readJSONL 按行解析,容忍损坏行(rollup 的 awk 也这么做)
func readJSONL(path string) []map[string]interface{} {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []map[string]interface{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue // 跳过损坏行
		}
		out = append(out, m)
	}
	return out
}

func setNoStore(w http.ResponseWriter) {
	// UI sync hotfix: all API responses are live state. Do not let WebView/browser
	// heuristic caching serve stale devices/rules/stats after writes.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		log.Printf("writeJSON encode: %v", err)
	}
}

func asString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// toInt64 · JSON 数字 (encoding/json 解出 float64) → int64
func toInt64(v interface{}) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case int64:
		return x, true
	case int:
		return int64(x), true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil
	}
	return 0, false
}

func validRange(r string) bool {
	switch r {
	case "today", "week", "month", "all":
		return true
	}
	return false
}

func validStatsSource(source string) bool {
	switch source {
	case "legacy", "shadow":
		return true
	}
	return false
}

// validMAC 严格匹配 xx:xx:xx:xx:xx:xx 小写
// 注意: 这是只读 API 的校验,作用是防 query param 被拿来做路径穿越
// 虽然我们不会把 mac 拼到 shell,但保持风格统一和防御性
func validMAC(m string) bool {
	if len(m) != 17 {
		return false
	}
	for i, c := range m {
		if i%3 == 2 {
			if c != ':' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func filterByMAC(rows []map[string]interface{}, mac string) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(rows))
	for _, r := range rows {
		if m, _ := r["mac"].(string); strings.ToLower(m) == mac {
			out = append(out, r)
		}
	}
	return out
}

// Bucket 聚合结果:label + rx + tx
type Bucket struct {
	Label string `json:"label"`
	RX    int64  `json:"rx"`
	TX    int64  `json:"tx"`
}

// aggregate 按 range 聚合 raw + daily 到桶数组
// 算法跟 WebUI 的 aggregateStats 等价
func aggregate(rangeParam string, raw, daily []map[string]interface{}) []Bucket {
	now := time.Now()
	loc := now.Location()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	todayStr := todayStart.Format("2006-01-02")

	// 今日从 raw 实时算 delta
	// 历史从 daily 读
	if rangeParam == "today" {
		return aggregateToday(raw, todayStart)
	}

	// week / month / all
	var dates []string
	switch rangeParam {
	case "week":
		dates = lastNDates(now, 7)
	case "month":
		dates = lastNDates(now, 30)
	case "all":
		// 从最早 daily 日期到今天,最多 90 天
		earliest := todayStr
		for _, d := range daily {
			if ds, _ := d["date"].(string); ds != "" && ds < earliest {
				earliest = ds
			}
		}
		dates = datesFromTo(earliest, todayStr)
		if len(dates) > 90 {
			dates = dates[len(dates)-90:]
		}
	}

	// 按 date 聚合 daily
	dmap := make(map[string]*Bucket)
	for _, d := range daily {
		date, _ := d["date"].(string)
		if date == "" {
			continue
		}
		b, ok := dmap[date]
		if !ok {
			b = &Bucket{}
			dmap[date] = b
		}
		b.RX += int64(getFloat(d, "rx"))
		b.TX += int64(getFloat(d, "tx"))
	}

	// 今日用 raw 实时覆盖 daily
	todayBuckets := aggregateToday(raw, todayStart)
	var todayRx, todayTx int64
	for _, b := range todayBuckets {
		todayRx += b.RX
		todayTx += b.TX
	}
	if todayRx > 0 || todayTx > 0 {
		dmap[todayStr] = &Bucket{RX: todayRx, TX: todayTx}
	}

	out := make([]Bucket, 0, len(dates))
	for _, d := range dates {
		b := dmap[d]
		label := d[5:] // MM-DD
		if b == nil {
			out = append(out, Bucket{Label: label})
		} else {
			out = append(out, Bucket{Label: label, RX: b.RX, TX: b.TX})
		}
	}
	return out
}

// aggregateToday 把今日 raw 按小时分桶,每 MAC 独立算 delta 后汇总
func aggregateToday(raw []map[string]interface{}, todayStart time.Time) []Bucket {
	t0 := todayStart.Unix()
	t1 := t0 + 86400
	buckets := make([]Bucket, 24)
	for i := 0; i < 24; i++ {
		buckets[i].Label = twoDigit(i) + ":00"
	}

	// 按 mac 分组,时间排序,算 delta
	byMac := make(map[string][]map[string]interface{})
	for _, r := range raw {
		ts := int64(getFloat(r, "ts"))
		if ts < t0 || ts >= t1 {
			continue
		}
		mac, _ := r["mac"].(string)
		byMac[mac] = append(byMac[mac], r)
	}
	for _, arr := range byMac {
		sort.Slice(arr, func(i, j int) bool {
			return getFloat(arr[i], "ts") < getFloat(arr[j], "ts")
		})
		for i := 1; i < len(arr); i++ {
			curRx := int64(getFloat(arr[i], "rx"))
			prevRx := int64(getFloat(arr[i-1], "rx"))
			curTx := int64(getFloat(arr[i], "tx"))
			prevTx := int64(getFloat(arr[i-1], "tx"))
			dRx := curRx - prevRx
			if dRx < 0 {
				dRx = 0
			}
			dTx := curTx - prevTx
			if dTx < 0 {
				dTx = 0
			}
			ts := int64(getFloat(arr[i], "ts"))
			hour := time.Unix(ts, 0).In(todayStart.Location()).Hour()
			if hour >= 0 && hour < 24 {
				buckets[hour].RX += dRx
				buckets[hour].TX += dTx
			}
		}
	}
	return buckets
}

func getFloat(m map[string]interface{}, k string) float64 {
	if v, ok := m[k]; ok {
		if f, ok2 := v.(float64); ok2 {
			return f
		}
	}
	return 0
}

func twoDigit(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func lastNDates(now time.Time, n int) []string {
	out := make([]string, n)
	base := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	for i := 0; i < n; i++ {
		d := base.AddDate(0, 0, -(n - 1 - i))
		out[i] = d.Format("2006-01-02")
	}
	return out
}

func datesFromTo(start, end string) []string {
	ts, err1 := time.Parse("2006-01-02", start)
	te, err2 := time.Parse("2006-01-02", end)
	if err1 != nil || err2 != nil || ts.After(te) {
		return []string{end}
	}
	var out []string
	for d := ts; !d.After(te); d = d.AddDate(0, 0, 1) {
		out = append(out, d.Format("2006-01-02"))
	}
	return out
}

// pruneLoop Patch 2.b: 监视 $RUN/httpd_prune_request marker 触发 tokens.Prune()
// 也每 24 小时无条件跑一次。
// json_set.sh token_prune 命令会 touch 这个 marker 通知 httpd 清理过期 token。
func (s *server) pruneLoop(stop <-chan struct{}) {
	markerPath := filepath.Join(s.hncDir, "run", "httpd_prune_request")
	pollTicker := time.NewTicker(60 * time.Second)
	defer pollTicker.Stop()
	dailyTicker := time.NewTicker(24 * time.Hour)
	defer dailyTicker.Stop()

	doPrune := func(reason string) {
		n, err := s.tokens.Prune()
		if err != nil {
			log.Printf("prune (%s): error: %v", reason, err)
			return
		}
		if n > 0 {
			log.Printf("prune (%s): removed %d expired tokens", reason, n)
		}
	}

	for {
		select {
		case <-stop:
			return
		case <-pollTicker.C:
			if _, err := os.Stat(markerPath); err == nil {
				doPrune("marker")
				_ = os.Remove(markerPath)
			}
		case <-dailyTicker.C:
			doPrune("daily")
		}
	}
}
