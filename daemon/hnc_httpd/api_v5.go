// api_v5.go — v5.0 新增 GET 接口, 给前端读取聚合数据
//   /api/config        → 配置项 (auth_required, whitelist_mode, hotspot_*)
//   /api/tokens        → 授权设备列表 (tokens.json 聚合)
//   /api/iface_info    → 热点接口信息 (iface/ip/gateway/ssid) · 修 Bug A
//   /api/logs?file=xxx → 读日志 (白名单校验) · 修 Bug C
//
// 前端用 fetch() 获取, 不再通过 kexec cat 文件.

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ── /api/config ────────────────────────────────────────────────

type configResp struct {
	AuthRequired       bool `json:"auth_required"`
	RemoteAuthRequired bool `json:"remote_auth_required"`
	WhitelistMode      bool `json:"whitelist_mode"`
	RemoteEnabled      bool `json:"remote_enabled"`
	// v5.1 P2-1: 字段对齐 shell (rules.json 里实际用 hotspot_auto/_pass/_delay)
	// 前端/JSON 输出保持向前兼容的 hotspot_autostart/hotspot_delay_sec 名字
	HotspotAutostart bool   `json:"hotspot_autostart"`
	HotspotSSID      string `json:"hotspot_ssid,omitempty"`
	HotspotDelaySec  int    `json:"hotspot_delay_sec,omitempty"`
	// rc32: 全局带宽整形器 (opt-in, 默认关)。down/up 为 tc 速率字符串 "<n>mbit"/"<n>kbit"。
	GlobalShaperEnabled bool            `json:"global_shaper_enabled"`
	GlobalShaperDown    string          `json:"global_shaper_down,omitempty"`
	GlobalShaperUp      string          `json:"global_shaper_up,omitempty"`
	Autorate            *autorateStatus `json:"autorate,omitempty"`
	RMACPolicy          *rmacPolicy     `json:"rmac_policy,omitempty"`
	// rc35: 用户维护的飞轮排除名单(VPN/代理),不含内置清单。供设置页展示/增删。
	FlywheelExcludeUser []string `json:"flywheel_exclude_user,omitempty"`
	// v5.18: offload 旁路兜底模式 auto(默认)| on | off, 见 bin/hnc_offload_guard.sh。
	// v5.33: 删只读兼容字段 clsact_bpf_enabled(旧键开机迁移后删除)。
	ClsactBpfMode string `json:"clsact_bpf_mode"`
	// v5.20: 设备默认叶子队列 auto(默认)| on | off, 见 action_qdisc.go / tc_manager.sh
	TcLeafAqm string `json:"tc_leaf_aqm"`
	// v5.18: run/offload_guard.json 原样透出(守护进程每 60s 写一次); 没有则 null。
	OffloadGuard map[string]interface{} `json:"offload_guard"`
	// v5.18: 按设备域名封锁的 DNS 层(xt_string)能力: "available" | "unavailable" | "unknown"
	// (unknown = 还没探测过, connblock_sync.sh 首次有域名封锁时探测)。
	ConnBlockDNSLayer string `json:"conn_block_dns_layer"`
	// 模拟环境(sim.go)是否开启
	SimEnabled bool `json:"sim_enabled"`
	// v5.11: 旧前端一直在读但后端从没返回的字段(刷新后总显示 auto / 默认值)。
	HotspotIface string `json:"hotspot_iface"`
	// v5.22: WebUI 访问白名单 {mode, macs, port, firewall}(webui_access.go)
	WebUIAccess webuiAccessView `json:"webui_access"`
	TcQosMode   string          `json:"tc_qos_mode"`
	TcQosScale  int             `json:"tc_qos_scale"`
	QosFallback bool            `json:"qos_fallback"`
	// v5.12: 定时 / 充电热点 与 过期规则清理天数
	HotspotTimeEnable   bool   `json:"hotspot_time_enable"`
	HotspotTimeStart    string `json:"hotspot_time_start"`
	HotspotTimeEnd      string `json:"hotspot_time_end"`
	HotspotChargingOnly bool   `json:"hotspot_charging_only"`
	StaleRuleTTLDays    int    `json:"stale_rule_ttl_days"`
	QUICBlock           bool   `json:"quic_block"`          // v5.14
	DiscoverCertProbe   bool   `json:"discover_cert_probe"` // v5.15, 缺省 true
	// rc3.1.13.1 删 OffloadWarn (review §3 P0): 历史上后端读 rules.json
	// 但从无写路径, 前端 toggle 只写 localStorage 自管, 字段始终死值 false.
	// rc3.1.12 config.json 兜底分支删除后, 死状况暴露 — 不如直接清掉
	// 让前端 toggle 完全 client-side, 后端不假装关心这字段.
}

func (s *server) apiConfig(w http.ResponseWriter, r *http.Request) {
	resp := configResp{ClsactBpfMode: "auto", TcLeafAqm: "auto"}
	resp.OffloadGuard = readOffloadGuard(s.hncDir)
	resp.ConnBlockDNSLayer = connBlockDNSLayer(s.hncDir)
	// rules.json 一次读全部字段 (v5.1: rules.json 同时存 top-level hotspot_* 和 remote_enabled/auth_required)
	// 兼容两套命名: shell 写 hotspot_auto/_pass/_delay, 旧版 Go 写 hotspot_autostart/_delay_sec
	if rulesData, err := os.ReadFile(s.hncDir + "/data/rules.json"); err == nil {
		var m map[string]interface{}
		if json.Unmarshal(rulesData, &m) == nil {
			resp.AuthRequired = boolField(m, "auth_required")
			resp.RemoteAuthRequired = resp.AuthRequired
			resp.WhitelistMode = boolField(m, "whitelist_mode")
			resp.RemoteEnabled = boolField(m, "remote_enabled")
			resp.ClsactBpfMode = clsactModeFromRules(m)
			if v, ok := m["tc_leaf_aqm"].(string); ok && (v == "on" || v == "off" || v == "auto") {
				resp.TcLeafAqm = v
			}
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
			resp.HotspotTimeEnable = boolField(m, "hotspot_time_enable")
			resp.HotspotChargingOnly = boolField(m, "hotspot_charging_only")
			resp.QUICBlock = boolField(m, "quic_block")
			resp.DiscoverCertProbe = true
			if v, ok := m["discover_cert_probe"].(bool); ok {
				resp.DiscoverCertProbe = v
			}
			resp.HotspotTimeStart, _ = m["hotspot_time_start"].(string)
			resp.HotspotTimeEnd, _ = m["hotspot_time_end"].(string)
			resp.StaleRuleTTLDays = 30 // 与 cleanup_stale_rules.sh 缺省一致
			if v, ok := m["stale_rule_ttl_days"].(float64); ok {
				resp.StaleRuleTTLDays = int(v)
			}
			if v, ok := m["hotspot_iface"].(string); ok {
				resp.HotspotIface = v
			}
			if v, ok := m["tc_qos_mode"].(string); ok {
				resp.TcQosMode = v
			}
			if v, ok := m["tc_qos_scale"].(float64); ok {
				resp.TcQosScale = int(v)
			} else if v, ok := m["tc_qos_scale"].(string); ok {
				resp.TcQosScale, _ = strconv.Atoi(v)
			}
			// rc32: 全局带宽整形器状态
			resp.GlobalShaperEnabled = boolField(m, "global_shaper_enabled")
			if v, ok := m["global_shaper_down"].(string); ok {
				resp.GlobalShaperDown = v
			}
			if v, ok := m["global_shaper_up"].(string); ok {
				resp.GlobalShaperUp = v
			}
		}
	}
	// v5.11: run/ 下的 QoS 文件优先(与 tc_manager.sh qos_mode_raw 同一优先级)
	if b, err := os.ReadFile(s.hncDir + "/run/tc_qos_mode"); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			resp.TcQosMode = v
		}
	}
	if b, err := os.ReadFile(s.hncDir + "/run/tc_qos_scale"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			resp.TcQosScale = n
		}
	}
	if resp.TcQosMode != "precise" {
		resp.TcQosMode = "compat"
	}
	if resp.TcQosScale < 50 || resp.TcQosScale > 120 {
		resp.TcQosScale = 100
	}
	if _, err := os.Stat(s.hncDir + "/run/tc_qos_fallback"); err == nil {
		resp.QosFallback = true
	}
	// rc35: 用户维护的飞轮排除名单(VPN/代理),从 etc/flywheel_exclude.json 读。
	resp.FlywheelExcludeUser = loadFlywheelExcludeUser(s.hncDir)
	resp.SimEnabled = s.simOn()
	resp.WebUIAccess = webuiAccessForConfig(s.hncDir)
	if s.autorate != nil {
		ar := s.autorate.Snapshot()
		resp.Autorate = &ar
	}
	rp := loadRMACPolicy(s.hncDir)
	resp.RMACPolicy = &rp
	// rc3.1.13: 删除 config.json 覆盖分支. config.json 已弃用, 由 post-fs-data.sh
	// 启动时单向迁移 auth_required 到 rules.json 后删除. 字段单源化让 toggle / 后端
	// 视角永远一致, 杜绝 rc3.1.9~12 那种"前端 ON 但 middleware 不认"的 skew.
	writeJSON(w, http.StatusOK, resp)
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
	writeJSON(w, http.StatusOK, resp)
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
	// 1. 接口名: v5.12 先走 currentHotspotIface(读 run/hnc_state / iface.cache, 无 fork);
	//    拿不到才 fork device_detect.sh(最长 10s)—— 此前每次调用都 fork, 远程页轮询时放大。
	resp.Iface = s.currentHotspotIface()
	if resp.Iface == "" {
		if rc, out := runBin(s.hncDir, "device_detect.sh", "iface"); rc == 0 {
			resp.Iface = strings.TrimSpace(out)
		}
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
					// 覆盖 RFC 1918 (10/8, 172.16/12, 192.168/16) 与部分 ROM 热点使用的 RFC 6598 (100.64.0.0/10)
					if isHotspotPrivateIPv4(ip4) {
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
	writeJSON(w, http.StatusOK, resp)
}

// isHotspotPrivateIPv4 识别热点接口私网 IPv4 地址: RFC 1918 及 RFC 6598 CGNAT (100.64.0.0/10)
func isHotspotPrivateIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4.IsPrivate() {
		return true
	}
	return ip4[0] == 100 && (ip4[1]&0xc0) == 64
}

// ── /api/offload_status ────────────────────────────────────────
// v5.1 P2-6: 取代前端直接 kexec check_offload.sh
// 返回 { active: bool, detail: "IDLE"/"bpf_on"/... }
//
// rc3.1.26 · 改用内存 cache (OffloadLoop goroutine 每 30s 刷一次).
// 原因 · check_offload.sh 含 sleep 5 (BPF stats_map 两次采样 5s 间隔),
// 前端 init 每次都调会同步阻塞 ksu.exec bridge 5 秒 · 占着 bridge 锁
// 导致其他 API 排队等, 是 Ling 真机"加载 5 秒"的根因.

const mtkHwnatNoKnobHintText = "检测到天玑 MDDP/HWNAT 硬件直通且无运行期开关；HNC 已设置 tether_offload_disabled=1，请关闭并重新开启一次手机热点使其生效"

type offloadResp struct {
	Active bool   `json:"active"`
	Detail string `json:"detail"`
	HWNAT  string `json:"hwnat,omitempty"`
	Hint   string `json:"hint,omitempty"`
	// v5.18: 兜底状态(同 /api/config 的 offload_guard), 无则 null
	Guard map[string]interface{} `json:"offload_guard"`
}

func detectMtkHwnatNoKnob(hncDir string, guard map[string]interface{}) bool {
	if guard != nil && strings.EqualFold(asString(guard["hwnat"]), "detected_no_knob") {
		return true
	}
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "mtk_hwnat.json")); err == nil && len(b) > 0 {
		var m map[string]interface{}
		if json.Unmarshal(b, &m) == nil && strings.EqualFold(asString(m["action"]), "detected_no_knob") {
			return true
		}
	}
	return false
}

func applyMtkNoKnobHint(resp *offloadResp, hncDir string, guard map[string]interface{}) {
	if strings.EqualFold(resp.Detail, "detected_no_knob") || detectMtkHwnatNoKnob(hncDir, guard) {
		resp.Active = true
		resp.HWNAT = "detected_no_knob"
		resp.Hint = mtkHwnatNoKnobHintText
		switch strings.ToUpper(strings.TrimSpace(resp.Detail)) {
		case "", "IDLE", "NOMAP", "CAPABLE", "PENDING":
			resp.Detail = "detected_no_knob"
		}
	}
}

// runOffloadCheck · 跑一次 check_offload.sh 并把结果写入 s.offloadCache
// 由 OffloadLoop 周期调用 · 30s 一次
func (s *server) runOffloadCheck() {
	// v5.18: offload guard 守护进程已在 60s 内采样过就直接复用, 不再并行再跑一遍
	// check_offload.sh(两路同时 sleep 5 采样 stats_map, 白费 CPU)。兜底生效时
	// guard 报的是被压下去之后的状态(IDLE/CAPABLE), 横幅随之消失 —— 旁路已被打掉。
	var out string
	if st, ok := offloadGuardFreshState(s.hncDir, 90*time.Second); ok {
		out = st
	} else {
		rc, o := runBin(s.hncDir, "check_offload.sh")
		_ = rc // check_offload.sh 约定 stdout 带状态关键字, rc 不重要
		out = o
	}
	out = strings.TrimSpace(out)
	if out == "" {
		out = "IDLE"
	}
	// v5.9.1: 整词判定取代子串 contains; 额外联动天玑 detected_no_knob 硬件直通提示。
	low := strings.ToLower(strings.TrimSpace(out))
	active := false
	for _, kw := range []string{"active", "warning", "bpf_on", "offload_on", "detected_no_knob"} {
		if low == kw {
			active = true
			break
		}
	}
	cached := offloadResp{Active: active, Detail: out}
	applyMtkNoKnobHint(&cached, s.hncDir, readOffloadGuard(s.hncDir))
	s.offloadMu.Lock()
	s.offloadCache = cached
	s.offloadReady = true
	s.offloadMu.Unlock()
}

// OffloadLoop · 后台 goroutine, 每 30s 刷一次 offload 状态到 cache.
// 启动时先跑一次 (不阻塞 main, 但 30s 内 apiOffloadStatus 会返回 PENDING).
// 30s 这个周期覆盖 BPF 采样 5s + 缓冲 · offload 状态变化不频繁 · 误差可接受.
func (s *server) OffloadLoop(stop <-chan struct{}) {
	// 启动时立刻跑一次 (异步, 不阻塞 OffloadLoop 外的 main)
	// v5.22: 基准 30s; 无界面 120s、热点未开 300s(power_sched.go offload_status)。
	// 这里只是横幅缓存, 真正的兜底由 hnc_offload_guard.sh 执行, 不受影响。
	for last := time.Now(); ; last = time.Now() {
		s.runOffloadCheck()
		if !powerWait(stop, "offload_status", last, nil) {
			return
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
	resp.Guard = readOffloadGuard(s.hncDir)
	applyMtkNoKnobHint(&resp, s.hncDir, resp.Guard)
	writeJSON(w, http.StatusOK, resp)
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
		writeJSON(w, http.StatusOK, logResp{File: "combined", Content: combined, Tail: n})
		return
	}
	if !allowedLogs[file] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "log file not in whitelist"})
		return
	}
	// 绝对路径 + 再 Clean 一次兜底 · 防 ../
	abs := filepath.Join(s.hncDir, "logs", file)
	if !strings.HasPrefix(abs, s.hncDir+"/logs/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path escape detected"})
		return
	}
	content := tailFile(abs, n)
	writeJSON(w, http.StatusOK, logResp{File: file, Content: content, Tail: n})
}

const (
	tailChunkSize    = 64 * 1024
	tailMaxReadBytes = 4 << 20 // 单次最大读取 4MB 保护, 防超长无换行文件 OOM
)

// tailFile 纯 Go 读文件末尾 N 行(尾部 Seek 64KB 分块倒序扫换行符, 零 fork 子进程)
func tailFile(path string, n int) string {
	return tailFileWithCap(path, n, tailChunkSize, tailMaxReadBytes)
}

func tailFileWithCap(path string, n int, chunkSize, maxBytes int64) string {
	if n <= 0 || chunkSize <= 0 || maxBytes <= 0 {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	endPos, err := f.Seek(0, io.SeekEnd)
	if err != nil || endPos <= 0 {
		return ""
	}

	var chunks [][]byte
	var totalRead int64
	offset := endPos
	needNewlines := n
	checkedTrailingNL := false

	for offset > 0 && totalRead < maxBytes {
		toRead := chunkSize
		if toRead > offset {
			toRead = offset
		}
		if rem := maxBytes - totalRead; toRead > rem {
			toRead = rem
		}
		offset -= toRead
		buf := make([]byte, int(toRead))
		nr, rerr := f.ReadAt(buf, offset)
		if nr <= 0 {
			if rerr != nil {
				break
			}
			break
		}
		buf = buf[:nr]
		totalRead += int64(nr)

		scanEnd := len(buf)
		if !checkedTrailingNL {
			checkedTrailingNL = true
			if buf[len(buf)-1] == '\n' {
				scanEnd--
			}
		}

		cutInBuf := -1
		sub := buf[:scanEnd]
		for len(sub) > 0 {
			idx := bytes.LastIndexByte(sub, '\n')
			if idx < 0 {
				break
			}
			needNewlines--
			if needNewlines == 0 {
				cutInBuf = idx + 1
				break
			}
			sub = sub[:idx]
		}

		if cutInBuf >= 0 {
			buf = buf[cutInBuf:]
			if len(chunks) == 0 {
				return string(buf)
			}
			chunks = append(chunks, buf)
			break
		}
		chunks = append(chunks, buf)
	}

	if len(chunks) == 0 {
		return ""
	}
	if len(chunks) == 1 {
		return string(chunks[0])
	}
	totalLen := 0
	for _, c := range chunks {
		totalLen += len(c)
	}
	var sb strings.Builder
	sb.Grow(totalLen)
	for i := len(chunks) - 1; i >= 0; i-- {
		sb.Write(chunks[i])
	}
	return sb.String()
}

// combinedLog · 纯 Go 合并多个日志文件尾部, 零 tail 子进程 fork
func combinedLog(hncDir string, n int) string {
	files := []string{"service.log", "watchdog.log", "detect.log"}
	per := n / 3
	var buf strings.Builder
	for _, f := range files {
		out := tailFile(filepath.Join(hncDir, "logs", f), per)
		buf.WriteString("─── " + f + " ───\n")
		buf.WriteString(out)
		if !strings.HasSuffix(out, "\n") {
			buf.WriteString("\n")
		}
	}
	return buf.String()
}
