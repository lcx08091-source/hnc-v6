// api_v5.go — v5.0 新增 GET 接口, 给前端读取聚合数据
//   /api/config        → 配置项 (auth_required, whitelist_mode, hotspot_*)
//   /api/tokens        → 授权设备列表 (tokens.json 聚合)
//   /api/iface_info    → 热点接口信息 (iface/ip/gateway/ssid) · 修 Bug A
//   /api/logs?file=xxx → 读日志 (白名单校验) · 修 Bug C
//
// 前端用 fetch() 获取, 不再通过 kexec cat 文件.

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ── /api/config ────────────────────────────────────────────────

type configResp struct {
	AuthRequired  bool `json:"auth_required"`
	WhitelistMode bool `json:"whitelist_mode"`
	RemoteEnabled bool `json:"remote_enabled"`
	// v5.1 P2-1: 字段对齐 shell (rules.json 里实际用 hotspot_auto/_pass/_delay)
	// 前端/JSON 输出保持向前兼容的 hotspot_autostart/hotspot_delay_sec 名字
	HotspotAutostart bool   `json:"hotspot_autostart"`
	HotspotSSID      string `json:"hotspot_ssid,omitempty"`
	HotspotDelaySec  int    `json:"hotspot_delay_sec,omitempty"`
	// rc3.1.13.1 删 OffloadWarn (review §3 P0): 历史上后端读 rules.json
	// 但从无写路径, 前端 toggle 只写 localStorage 自管, 字段始终死值 false.
	// rc3.1.12 config.json 兜底分支删除后, 死状况暴露 — 不如直接清掉
	// 让前端 toggle 完全 client-side, 后端不假装关心这字段.
}

func (s *server) apiConfig(w http.ResponseWriter, r *http.Request) {
	resp := configResp{}
	// rules.json 一次读全部字段 (v5.1: rules.json 同时存 top-level hotspot_* 和 remote_enabled/auth_required)
	// 兼容两套命名: shell 写 hotspot_auto/_pass/_delay, 旧版 Go 写 hotspot_autostart/_delay_sec
	if rulesData, err := os.ReadFile(s.hncDir + "/data/rules.json"); err == nil {
		var m map[string]interface{}
		if json.Unmarshal(rulesData, &m) == nil {
			resp.AuthRequired = boolField(m, "auth_required")
			resp.WhitelistMode = boolField(m, "whitelist_mode")
			resp.RemoteEnabled = boolField(m, "remote_enabled")
			// Autostart: 优先读 hotspot_auto (shell 名), 回退到 hotspot_autostart
			resp.HotspotAutostart = boolField(m, "hotspot_auto") || boolField(m, "hotspot_autostart")
			if ssid, ok := m["hotspot_ssid"].(string); ok {
				resp.HotspotSSID = ssid
			}
			// Delay: 优先读 hotspot_delay (shell), 回退到 hotspot_delay_sec
			if d, ok := m["hotspot_delay"].(float64); ok {
				resp.HotspotDelaySec = int(d)
			} else if d, ok := m["hotspot_delay_sec"].(float64); ok {
				resp.HotspotDelaySec = int(d)
			}
		}
	}
	// rc3.1.13: 删除 config.json 覆盖分支. config.json 已弃用, 由 post-fs-data.sh
	// 启动时单向迁移 auth_required 到 rules.json 后删除. 字段单源化让 toggle / 后端
	// 视角永远一致, 杜绝 rc3.1.9~12 那种"前端 ON 但 middleware 不认"的 skew.
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(resp)
}

func boolField(m map[string]interface{}, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true"
	}
	return false
}

// ── /api/tokens ────────────────────────────────────────────────

type tokenInfo struct {
	TokenID  string `json:"token_id"`
	Label    string `json:"label,omitempty"`
	IPHint   string `json:"ip_hint,omitempty"`
	Created  int64  `json:"created,omitempty"`
	LastSeen int64  `json:"last_seen,omitempty"`
	Revoked  bool   `json:"revoked,omitempty"`
}

type tokensResp struct {
	Version int         `json:"version"`
	Tokens  []tokenInfo `json:"tokens"`
}

func (s *server) apiTokens(w http.ResponseWriter, r *http.Request) {
	// rc3.1.14 修 P2 (review §一致性): 改用 TokensStore.Snapshot, 不再读磁盘.
	// 原实现 ReadFile remote_tokens.json + 手动 unmarshal, last_seen 字段会
	// 落后内存最多 30s (saveLoop 周期). 现在直接拿内存最新值, UI 实时.
	resp := tokensResp{Version: 1, Tokens: []tokenInfo{}}
	snap := s.tokens.Snapshot()
	for tid, t := range snap {
		if t.Revoked {
			continue
		}
		resp.Tokens = append(resp.Tokens, tokenInfo{
			TokenID:  tid,
			Label:    t.Label,
			IPHint:   t.IPHint,
			Created:  t.Created,
			LastSeen: t.LastSeen,
			Revoked:  t.Revoked,
		})
	}
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(resp)
}

// ── /api/iface_info ────────────────────────────────────────────

type ifaceInfoResp struct {
	Iface   string `json:"iface,omitempty"`
	IP      string `json:"ip,omitempty"`
	Gateway string `json:"gateway,omitempty"`
	Network string `json:"network,omitempty"`
}

// apiIfaceInfo · 直接用 Go 查询热点接口 IP, 替代前端猜测
// 对应 Bug A · 解决 URL 显示 192.168.1.1 的问题
func (s *server) apiIfaceInfo(w http.ResponseWriter, r *http.Request) {
	resp := ifaceInfoResp{}
	// 1. device_detect.sh iface → 接口名
	rc, out := runBin(s.hncDir, "device_detect.sh", "iface")
	if rc == 0 {
		resp.Iface = strings.TrimSpace(out)
	}
	// 2. 如果没拿到 iface, 尝试从 devices.json 找有活设备的 iface
	if resp.Iface == "" {
		if data, err := os.ReadFile(s.hncDir + "/data/devices.json"); err == nil {
			var m map[string]map[string]interface{}
			if json.Unmarshal(data, &m) == nil {
				for _, d := range m {
					if s, ok := d["iface"].(string); ok && s != "" {
						resp.Iface = s
						break
					}
				}
			}
		}
	}
	// 3. 拿 iface IP
	if resp.Iface != "" {
		ifaces, _ := net.InterfaceByName(resp.Iface)
		if ifaces != nil {
			addrs, _ := ifaces.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					ip4 := ipnet.IP.To4()
					// rc3 修 N-13: 用 net.IP.IsPrivate() 代替手写子网判定
					// 覆盖 10/8, 172.16/12, 192.168/16 (RFC 1918)
					if ip4 != nil && ip4.IsPrivate() {
						resp.IP = ip4.String()
						resp.Network = ipnet.String()
						break
					}
				}
			}
		}
	}
	// 4. rc3.1.7 修: AP 模式下主机 wlan IP 即 gateway, 不要推 .1
	// 背景: ColorOS tether 给主机随机 IP (.67/.252/.188 每次不同), 非 .1
	// 从客户端视角, gateway = 主机 wlan 接口 IP, 直接回显即可
	// 之前硬推 "x.y.z.1" 导致 WebUI 显示的 URL 打不开 (ERR_ADDRESS_UNREACHABLE),
	// rc3.1.6 改 httpd 绑 0.0.0.0 只修了监听侧, 这里修显示侧. 配套修复.
	if resp.IP != "" {
		resp.Gateway = resp.IP
	}
	// 5. fallback: resp.IP 为空但 devices.json 有客户端记录时
	// 不能从客户端 IP 推出主机 IP (客户端 .188 不代表主机 .1),
	// 保留 iface/ip 为空, 让前端 fetchHnIp 回退到 '192.168.1.1' 兜底告知
	// (用户会看到明显不对的值, 比无法访问更容易定位)
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(resp)
}

// ── /api/offload_status ────────────────────────────────────────
// v5.1 P2-6: 取代前端直接 kexec check_offload.sh
// 返回 { active: bool, detail: "IDLE"/"bpf_on"/... }
//
// rc3.1.26 · 改用内存 cache (OffloadLoop goroutine 每 30s 刷一次).
// 原因 · check_offload.sh 含 sleep 5 (BPF stats_map 两次采样 5s 间隔),
// 前端 init 每次都调会同步阻塞 ksu.exec bridge 5 秒 · 占着 bridge 锁
// 导致其他 API 排队等, 是 Ling 真机"加载 5 秒"的根因.

type offloadResp struct {
	Active bool   `json:"active"`
	Detail string `json:"detail"`
}

// runOffloadCheck · 跑一次 check_offload.sh 并把结果写入 s.offloadCache
// 由 OffloadLoop 周期调用 · 30s 一次
func (s *server) runOffloadCheck() {
	rc, out := runBin(s.hncDir, "check_offload.sh")
	_ = rc // check_offload.sh 约定 stdout 带状态关键字, rc 不重要
	out = strings.TrimSpace(out)
	if out == "" {
		out = "IDLE"
	}
	active := false
	low := strings.ToLower(out)
	for _, kw := range []string{"active", "warning", "bpf_on", "offload_on"} {
		if strings.Contains(low, kw) {
			active = true
			break
		}
	}
	s.offloadMu.Lock()
	s.offloadCache = offloadResp{Active: active, Detail: out}
	s.offloadReady = true
	s.offloadMu.Unlock()
}

// OffloadLoop · 后台 goroutine, 每 30s 刷一次 offload 状态到 cache.
// 启动时先跑一次 (不阻塞 main, 但 30s 内 apiOffloadStatus 会返回 PENDING).
// 30s 这个周期覆盖 BPF 采样 5s + 缓冲 · offload 状态变化不频繁 · 误差可接受.
func (s *server) OffloadLoop(stop <-chan struct{}) {
	// 启动时立刻跑一次 (异步, 不阻塞 OffloadLoop 外的 main)
	s.runOffloadCheck()
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			s.runOffloadCheck()
		}
	}
}

func (s *server) apiOffloadStatus(w http.ResponseWriter, r *http.Request) {
	s.offloadMu.RLock()
	ready := s.offloadReady
	resp := s.offloadCache
	s.offloadMu.RUnlock()
	if !ready {
		resp = offloadResp{Active: false, Detail: "PENDING"}
	}
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(resp)
}

// ── /api/logs?file=xxx ─────────────────────────────────────────

// allowedLogs · 白名单校验, 修 Bug C · 防路径遍历
// rc29: dpid + dpid_guard 加入(让用户从 WebUI 直接看 DPI 守护日志, 不必 su)
var allowedLogs = map[string]bool{
	"service.log":    true,
	"watchdog.log":   true,
	"detect.log":     true,
	"iptables.log":   true,
	"tc.log":         true,
	"apply.log":      true,
	"audit.log":      true,
	"httpd.log":      true,
	"hotspot.log":    true,
	"stats.log":      true,
	"hotspotd.log":   true,
	"dpid.log":       true,
	"dpid_guard.log": true,
}

type logResp struct {
	File    string `json:"file"`
	Content string `json:"content"`
	Tail    int    `json:"tail"`
}

func (s *server) apiLogs(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	tailN := r.URL.Query().Get("tail")
	n := 300
	if tailN != "" {
		if v, ok := atoiClamp(tailN, 10, 2000); ok {
			n = v
		}
	}
	// 特殊: combined = 多个 log 合并
	if file == "combined" {
		combined := combinedLog(s.hncDir, n)
		setNoStore(w)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_ = json.NewEncoder(w).Encode(logResp{File: "combined", Content: combined, Tail: n})
		return
	}
	if !allowedLogs[file] {
		setNoStore(w)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		http.Error(w, `{"error":"log file not in whitelist"}`, http.StatusBadRequest)
		return
	}
	// 绝对路径 + 再 Clean 一次兜底 · 防 ../
	abs := filepath.Join(s.hncDir, "logs", file)
	if !strings.HasPrefix(abs, s.hncDir+"/logs/") {
		setNoStore(w)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		http.Error(w, `{"error":"path escape detected"}`, http.StatusBadRequest)
		return
	}
	content := tailFile(abs, n)
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(logResp{File: file, Content: content, Tail: n})
}

// tailFile · 读文件末尾 N 行
// rc2 修 G10: 加 3 秒 context 超时. 原代码无 timeout, 如果磁盘卡/fuse 挂起,
// tail 子进程会永久 hang, 前端 /api/logs 请求就跟着挂, goroutine 泄漏到重启.
// 3s 对正常 tail 绰绰有余 (就算 10MB 日志也远远够), 卡住的立即放行.
func tailFile(path string, n int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "tail", "-n", intToStr(n), path)
	out, err := cmd.Output()
	if err != nil {
		// 读不到或文件不存在或超时 - 返回空而不是 error
		return ""
	}
	return string(out)
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
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

// combinedLog · 合并多个 log
func combinedLog(hncDir string, n int) string {
	// rc3.1.11 perf: 并发 tail 避免串行 fork 3 次 exec 累加延迟.
	// 中端机 fork+exec 各 ~30-80ms, 串行 ≈200ms; 并发 ≈ max(80) + goroutine 开销.
	// KSU bridge curl 10s 超时下这个差距能避免用户感知"卡死".
	files := []string{"service.log", "watchdog.log", "detect.log"}
	per := n / 3
	outs := make([]string, len(files))
	var wg sync.WaitGroup
	for i, f := range files {
		wg.Add(1)
		go func(idx int, name string) {
			defer wg.Done()
			outs[idx] = tailFile(hncDir+"/logs/"+name, per)
		}(i, f)
	}
	wg.Wait()
	var buf strings.Builder
	for i, f := range files {
		buf.WriteString("─── " + f + " ───\n")
		buf.WriteString(outs[i])
		if !strings.HasSuffix(outs[i], "\n") {
			buf.WriteString("\n")
		}
	}
	return buf.String()
}

// 占位引用防 "imported and not used" 错
var _ = io.Discard
