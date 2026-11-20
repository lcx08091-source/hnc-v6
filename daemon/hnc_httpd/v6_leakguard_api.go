// v6_leakguard_api.go — HNC v6.0.0 · Vector (T4 模块 1):
// LeakGuard 实时明文隐私泄露预警、SSE 推送、防注入状态栏通知与双栈一键反制 + v6 统一路由总入口。
//
// 核心工程保证:
//   - 零外部第三方库, 纯字节编解码, 64 位 atomic 字段严格置于结构体 offset 0 (兼容 GOARCH=arm)。
//   - Android 原生通知严格通过 exec.CommandContext 纯参数数组直调 /system/bin/cmd + 2s 硬超时 + 控制字符/元字符清洗。
//   - 锁屏脱敏: lockscreen_mask=true 时对通知正文 raw_value 中间位打码; WebUI API 与 SSE 始终返回 100% 完整原文。
//   - 系统告警统一经由 hnc.io/dpid/alert.Append 原子落盘。

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"hnc.io/dpid/alert"
)

// ── v6.0.0 统一挂载入口与按 server 隔离的运行时状态池（零侵入 server.go） ───────

type v6ServerState struct {
	// 64 位原子计数严格置于 offset 0, 保证 32 位 ARM (armeabi-v7a) 8 字节对齐
	summaryCalls atomic.Uint64

	leakGuard *leakGuardEngine
	express   *vectorExpressEngine
	leash     *updateLeashEngine
	scalpel   *flowScalpelEngine
	thermo    *thermoCruiseEngine
}

var v6Registry sync.Map // map[*server]*v6ServerState

func (s *server) v6State() *v6ServerState {
	if v, ok := v6Registry.Load(s); ok {
		return v.(*v6ServerState)
	}
	st := &v6ServerState{
		leakGuard: newLeakGuardEngine(s),
		express:   newVectorExpressEngine(s),
		leash:     newUpdateLeashEngine(s),
		scalpel:   newFlowScalpelEngine(s),
		thermo:    newThermoCruiseEngine(s),
	}
	actual, _ := v6Registry.LoadOrStore(s, st)
	return actual.(*v6ServerState)
}

// registerV6FeatureRoutes 供总装阶段在 server.handler() 内一键挂载五大 v6 核心路由。
func (s *server) registerV6FeatureRoutes(mux *http.ServeMux) {
	if s == nil || mux == nil {
		return
	}
	_ = s.v6State()

	// 模块 1: LeakGuard 隐私防泄露哨兵
	mux.HandleFunc("/api/leakguard/events", s.apiLeakGuardEvents)
	mux.HandleFunc("/api/leakguard/stream", s.apiLeakGuardStream)
	mux.HandleFunc("/api/leakguard/clear", s.requireMutation(s.apiLeakGuardClear))
	mux.HandleFunc("/api/leakguard/config", s.requireMutation(s.apiLeakGuardConfig))
	mux.HandleFunc("/api/leakguard/block-domain", s.requireMutation(s.apiLeakGuardBlockDomain))

	// 模块 2: Vector Express 跨设备微秒级零排队护航
	mux.HandleFunc("/api/v6/express", s.apiVectorExpress)

	// 模块 3: UpdateLeash 200MB 免死缓冲 + 后台巨兽温柔拴绳
	mux.HandleFunc("/api/v6/update_leash", s.apiUpdateLeash)

	// 模块 4: FlowScalpel 五元组实时透视 + 免断网单流秒斩手术刀
	mux.HandleFunc("/api/v6/scalpel/flows", s.apiScalpelFlows)
	mux.HandleFunc("/api/v6/scalpel/cut", s.requireMutation(s.apiScalpelCut))

	// 模块 5: ThermoCruise sysfs 零开销温控与电量自适应巡航
	mux.HandleFunc("/api/v6/thermo", s.apiThermoCruise)
}

// registerV6FeatureRoutes 包级同名包装, 兼容 registerV6FeatureRoutes(mux, s) 与 s.registerV6FeatureRoutes(mux) 两种总装调用签名。
func registerV6FeatureRoutes(mux *http.ServeMux, s *server) {
	if s != nil && mux != nil {
		s.registerV6FeatureRoutes(mux)
	}
}

// v6FeaturesSummary 供 /api/vector_sync 或全局驾驶舱一键拉取五大模块轻量实时摘要。
func (s *server) v6FeaturesSummary() map[string]any {
	if s == nil {
		return map[string]any{}
	}
	st := s.v6State()
	st.summaryCalls.Add(1)
	return map[string]any{
		"leakguard":    st.leakGuard.summary(),
		"express":      st.express.summary(),
		"update_leash": st.leash.summary(),
		"scalpel":      st.scalpel.summary(),
		"thermo":       st.thermo.summary(),
	}
}

// StartV6FeatureLoops 启动五大模块后台自适应巡检协程（幂等安全, stop 关闭时全部干净退出）。
func (s *server) StartV6FeatureLoops(stop <-chan struct{}) {
	if s == nil {
		return
	}
	st := s.v6State()
	go st.leakGuard.runLoop(stop)
	go st.express.runLoop(stop)
	go st.leash.runLoop(stop)
	go st.scalpel.runLoop(stop)
	go st.thermo.runLoop(stop)
}

// ── 模块 1: LeakGuard 核心结构与常量 ─────────────────────────────────────────

const (
	leakDefaultCapacity     = 300
	leakMinCapacity         = 10
	leakMaxCapacity         = 2000
	leakDefaultCooldownSec  = 300
	leakMinCooldownSec      = 0
	leakMaxCooldownSec      = 86400
	leakNotifyTimeout       = 2 * time.Second
	leakCmdBinPath          = "/system/bin/cmd"
	leakMaxSSEClients       = 32
	leakSSEHeartbeatDefault = 15 * time.Second
)

var leakSSEActiveConns atomic.Int64

// LeakGuardConfig 用户持久化与运行时控制配置。
type LeakGuardConfig struct {
	Capacity       int  `json:"capacity"`
	CooldownSec    int  `json:"cooldown_sec"`
	NotifyEnabled  bool `json:"notify_enabled"`
	LockscreenMask bool `json:"lockscreen_mask"`
}

func defaultLeakGuardConfig() LeakGuardConfig {
	return LeakGuardConfig{
		Capacity:       leakDefaultCapacity,
		CooldownSec:    leakDefaultCooldownSec,
		NotifyEnabled:  true,
		LockscreenMask: true,
	}
}

// LeakEvent 明文隐私泄露事件（WebUI 与 SSE 始终返回 100% 未打码的 RawValue 与 RawSnippet）。
type LeakEvent struct {
	ID         string `json:"id"`
	Ts         int64  `json:"ts"`
	MAC        string `json:"mac"`
	SrcIP      string `json:"src_ip"`
	DeviceName string `json:"device_name"`
	DstHost    string `json:"dst_host"`
	DstIP      string `json:"dst_ip,omitempty"`
	DstPort    int    `json:"dst_port,omitempty"`
	Proto      string `json:"proto,omitempty"`
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	LeakType   string `json:"leak_type"`
	LeakLabel  string `json:"leak_label,omitempty"`
	RawValue   string `json:"raw_value"`
	RawSnippet string `json:"raw_snippet"`
	HitCount   int64  `json:"hit_count,omitempty"`
	IsBlocked  bool   `json:"is_blocked"`
}

type leakGuardCtrlFile struct {
	Capacity       int             `json:"capacity"`
	CooldownSec    int             `json:"cooldown_sec"`
	NotifyEnabled  bool            `json:"notify_enabled"`
	LockscreenMask bool            `json:"lockscreen_mask"`
	ClearSeq       int64           `json:"clear_seq"`
	ClearedAt      int64           `json:"cleared_at"`
	BlockedTargets map[string]bool `json:"blocked_targets,omitempty"`
	UpdatedAt      int64           `json:"updated_at"`
}

type leakGuardPersistFile struct {
	Config         LeakGuardConfig `json:"config"`
	BlockedTargets map[string]bool `json:"blocked_targets,omitempty"`
	ClearSeq       int64           `json:"clear_seq,omitempty"`
	ClearedAt      int64           `json:"cleared_at,omitempty"`
}

type leakNotifyFunc func(ctx context.Context, bin string, args ...string) error

type leakGuardEngine struct {
	// 64 位原子字段严格置于 offset 0
	totalHits atomic.Int64
	clearSeq  atomic.Int64

	srv            *server
	mu             sync.Mutex
	cfg            LeakGuardConfig
	clearedAt      int64
	maxSeenTs      int64
	events         []LeakEvent // 按时间升序存储, 容量受 cfg.Capacity 约束
	seenIDs        map[string]int64
	cooldownLedger map[string]int64
	blockedTargets map[string]bool
	subs           map[chan LeakEvent]struct{}
	notifyExec     leakNotifyFunc
	sseHeartbeat   time.Duration
}

func defaultLeakNotifyExec(ctx context.Context, bin string, args ...string) error {
	// 安全铁律: 纯参数切片直调目标二进制 + hardenCmd 2s WaitDelay 防管道悬挂
	cmd := hardenCmd(exec.CommandContext(ctx, bin, args...))
	return cmd.Run()
}

func newLeakGuardEngine(s *server) *leakGuardEngine {
	eng := &leakGuardEngine{
		srv:            s,
		cfg:            defaultLeakGuardConfig(),
		seenIDs:        make(map[string]int64),
		cooldownLedger: make(map[string]int64),
		blockedTargets: make(map[string]bool),
		subs:           make(map[chan LeakEvent]struct{}),
		notifyExec:     defaultLeakNotifyExec,
		sseHeartbeat:   leakSSEHeartbeatDefault,
	}
	eng.loadPersistedLocked()
	return eng
}

func (e *leakGuardEngine) persistPath() string {
	return filepath.Join(e.srv.hncDir, "data", "leakguard_config.json")
}

func (e *leakGuardEngine) ctrlPath() string {
	return filepath.Join(e.srv.hncDir, "run", "leakguard_ctrl.json")
}

func (e *leakGuardEngine) dpidEventsPath() string {
	return filepath.Join(e.srv.hncDir, "run", "leakguard_events.json")
}

func (e *leakGuardEngine) loadPersistedLocked() {
	if e.srv == nil || e.srv.hncDir == "" {
		return
	}
	b, err := os.ReadFile(e.persistPath())
	if err != nil {
		return
	}
	var pf leakGuardPersistFile
	if json.Unmarshal(b, &pf) != nil {
		return
	}
	if pf.Config.Capacity >= leakMinCapacity && pf.Config.Capacity <= leakMaxCapacity {
		e.cfg = pf.Config
	}
	if pf.BlockedTargets != nil {
		for k, v := range pf.BlockedTargets {
			if v {
				e.blockedTargets[strings.ToLower(strings.TrimSpace(k))] = true
			}
		}
	}
	if pf.ClearSeq > 0 {
		e.clearSeq.Store(pf.ClearSeq)
	}
	if pf.ClearedAt > 0 {
		e.clearedAt = pf.ClearedAt
	}
}

func (e *leakGuardEngine) saveStateLocked() error {
	if e.srv == nil || e.srv.hncDir == "" {
		return nil
	}
	now := time.Now().Unix()
	pf := leakGuardPersistFile{
		Config:         e.cfg,
		BlockedTargets: e.blockedTargets,
		ClearSeq:       e.clearSeq.Load(),
		ClearedAt:      e.clearedAt,
	}
	if pb, err := json.MarshalIndent(pf, "", "  "); err == nil {
		_ = discoverWriteAtomic(e.persistPath(), pb)
	}
	ctrl := leakGuardCtrlFile{
		Capacity:       e.cfg.Capacity,
		CooldownSec:    e.cfg.CooldownSec,
		NotifyEnabled:  e.cfg.NotifyEnabled,
		LockscreenMask: e.cfg.LockscreenMask,
		ClearSeq:       e.clearSeq.Load(),
		ClearedAt:      e.clearedAt,
		BlockedTargets: e.blockedTargets,
		UpdatedAt:      now,
	}
	cb, err := json.MarshalIndent(ctrl, "", "  ")
	if err != nil {
		return err
	}
	return discoverWriteAtomic(e.ctrlPath(), cb)
}

// ── 防注入参数清洗与防锁屏社死打码器 ─────────────────────────────────────────

// sanitizeLeakNotifyArg 严格剥离所有控制字符、换行符、制表符、引号及危险元字符。
func sanitizeLeakNotifyArg(in string, maxRunes int) string {
	if maxRunes <= 0 {
		maxRunes = 160
	}
	var b strings.Builder
	b.Grow(len(in))
	lastSpace := false
	count := 0
	for _, r := range in {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			if !lastSpace && count > 0 {
				b.WriteByte(' ')
				lastSpace = true
				count++
			}
			continue
		}
		switch r {
		case '`', '$', ';', '|', '&', '<', '>', '\\', '"', '\'', '\u0000':
			continue
		}
		if unicode.IsSpace(r) {
			if !lastSpace && count > 0 {
				b.WriteByte(' ')
				lastSpace = true
				count++
			}
		} else {
			b.WriteRune(r)
			lastSpace = false
			count++
		}
		if count >= maxRunes {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// maskLeakRawValue 对敏感值中间位脱敏以防锁屏通知窥探（如 13812345678 -> 138****5678）。
func maskLeakRawValue(raw string) string {
	rs := []rune(strings.TrimSpace(raw))
	n := len(rs)
	switch {
	case n == 0:
		return "****"
	case n <= 2:
		return "****"
	case n <= 5:
		return string(rs[:1]) + "****" + string(rs[n-1:])
	case n <= 10:
		return string(rs[:2]) + "****" + string(rs[n-2:])
	case n == 11:
		return string(rs[:3]) + "****" + string(rs[7:])
	default:
		maskLen := n - 8
		if maskLen > 8 {
			maskLen = 8
		}
		return string(rs[:4]) + strings.Repeat("*", maskLen) + string(rs[n-4:])
	}
}

func leakTypeDisplayName(leakType string) string {
	switch strings.ToLower(strings.TrimSpace(leakType)) {
	case "phone", "mobile":
		return "手机号"
	case "id_card", "idcard", "cn_id":
		return "身份证号"
	case "password", "passwd", "pwd":
		return "明文密码"
	case "token", "bearer", "api_key", "apikey", "jwt":
		return "认证凭据/Token"
	case "bank_card", "card":
		return "银行卡号"
	case "email":
		return "邮箱地址"
	case "imei", "imsi", "oaid", "android_id":
		return "设备唯一标识"
	case "cookie", "session":
		return "会话 Cookie"
	default:
		if leakType == "" {
			return "敏感字段"
		}
		return leakType
	}
}

func formatLeakNotificationBody(ev LeakEvent, lockscreenMask bool) string {
	dev := sanitizeLeakNotifyArg(ev.DeviceName, 40)
	if dev == "" {
		if ev.MAC != "" {
			dev = sanitizeLeakNotifyArg(ev.MAC, 24)
		} else {
			dev = sanitizeLeakNotifyArg(ev.SrcIP, 40)
		}
	}
	if dev == "" {
		dev = "未知设备"
	}
	host := sanitizeLeakNotifyArg(ev.DstHost, 64)
	if host == "" {
		host = sanitizeLeakNotifyArg(ev.DstIP, 45)
	}
	if host == "" {
		host = "未知目标"
	}
	lt := sanitizeLeakNotifyArg(ev.LeakType, 32)
	if lt == "" {
		lt = "sensitive"
	}
	val := ev.RawValue
	if lockscreenMask {
		val = maskLeakRawValue(val)
	}
	safeVal := sanitizeLeakNotifyArg(val, 80)
	raw := fmt.Sprintf("[%s] 向 [%s] 明文泄露 [%s]: [%s]", dev, host, lt, safeVal)
	return sanitizeLeakNotifyArg(raw, 220)
}

func (e *leakGuardEngine) postAndroidNotificationAsync(ev LeakEvent, lockscreenMask bool) {
	execFn := e.notifyExec
	if execFn == nil {
		return
	}
	title := sanitizeLeakNotifyArg("HNC LeakGuard · 明文隐私泄露预警", 48)
	tag := "hnc_leakguard"
	body := formatLeakNotificationBody(ev, lockscreenMask)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), leakNotifyTimeout)
		defer cancel()
		_ = execFn(ctx, leakCmdBinPath, "notification", "post", "-t", title, tag, body)
	}()
}

// ── 事件解析、设备名实时补齐与封锁状态联动 ──────────────────────────────────

func computeLeakEventID(ev LeakEvent) string {
	if id := strings.TrimSpace(ev.ID); id != "" {
		return id
	}
	sum := sha1.Sum([]byte(fmt.Sprintf("%d|%s|%s|%s|%s|%s",
		ev.Ts, strings.ToLower(ev.MAC), ev.SrcIP, strings.ToLower(ev.DstHost), ev.LeakType, ev.RawValue)))
	return "lg_" + hex.EncodeToString(sum[:8])
}

func parseFlexibleLeakEvent(m map[string]any) (LeakEvent, bool) {
	if len(m) == 0 {
		return LeakEvent{}, false
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok && v != nil {
				if s, ok2 := v.(string); ok2 && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
		return ""
	}
	i64 := func(keys ...string) int64 {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				if n, ok2 := toInt64(v); ok2 && n > 0 {
					return n
				}
			}
		}
		return 0
	}
	ev := LeakEvent{
		ID:         str("id", "event_id"),
		Ts:         i64("ts", "timestamp", "time"),
		MAC:        strings.ToLower(str("mac", "client_mac")),
		SrcIP:      str("src_ip", "client_ip", "ip", "src"),
		DeviceName: str("device_name", "hostname", "device"),
		DstHost:    strings.ToLower(str("dst_host", "host", "domain", "dst")),
		DstIP:      str("dst_ip", "dst"),
		DstPort:    int(i64("dst_port", "dport", "port")),
		Proto:      strings.ToLower(str("proto", "protocol")),
		Method:     strings.ToUpper(str("method", "http_method")),
		Path:       str("path", "url", "uri"),
		LeakType:   str("leak_type", "type", "kind"),
		LeakLabel:  str("leak_label", "label"),
		RawValue:   str("raw_value", "value", "secret"),
		RawSnippet: str("raw_snippet", "snippet", "payload"),
		HitCount:   i64("hit_count", "hits"),
	}
	if b, ok := m["is_blocked"].(bool); ok {
		ev.IsBlocked = b
	}
	if ev.DstHost == "" && ev.DstIP != "" {
		ev.DstHost = ev.DstIP
	}
	if ev.DstHost == "" && ev.RawValue == "" && ev.RawSnippet == "" {
		return LeakEvent{}, false
	}
	if ev.Ts <= 0 {
		ev.Ts = time.Now().Unix()
	}
	if ev.LeakType == "" {
		ev.LeakType = "plaintext"
	}
	if ev.LeakLabel == "" {
		ev.LeakLabel = leakTypeDisplayName(ev.LeakType)
	}
	ev.ID = computeLeakEventID(ev)
	return ev, true
}

func decodeLeakEventsPayload(raw []byte) []LeakEvent {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	var out []LeakEvent
	if trimmed[0] == '{' {
		var obj map[string]any
		if json.Unmarshal(trimmed, &obj) == nil {
			for _, key := range []string{"events", "items", "records"} {
				if arr, ok := obj[key].([]any); ok {
					for _, item := range arr {
						if m, ok2 := item.(map[string]any); ok2 {
							if ev, ok3 := parseFlexibleLeakEvent(m); ok3 {
								out = append(out, ev)
							}
						}
					}
					return out
				}
			}
		}
	}
	if trimmed[0] == '[' {
		var arr []map[string]any
		if json.Unmarshal(trimmed, &arr) == nil {
			for _, m := range arr {
				if ev, ok := parseFlexibleLeakEvent(m); ok {
					out = append(out, ev)
				}
			}
			return out
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(trimmed))
	sc.Buffer(make([]byte, 4096), 512*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if json.Unmarshal(line, &m) == nil {
			if ev, ok := parseFlexibleLeakEvent(m); ok {
				out = append(out, ev)
			}
		}
	}
	return out
}

// buildDeviceDirectory 实时关联 s.hncDir 下的 device_names.json / devices.json / dpi_devid.json。
func (s *server) buildDeviceDirectory() (nameByMAC map[string]string, macByIP map[string]string) {
	nameByMAC = make(map[string]string)
	macByIP = make(map[string]string)
	if s == nil || s.hncDir == "" {
		return nameByMAC, macByIP
	}

	for mac, ips := range s.deviceIPsByMAC() {
		m := strings.ToLower(strings.TrimSpace(mac))
		for _, ip := range ips {
			macByIP[ip] = m
		}
	}

	for mac, id := range s.dpiIdentByMAC() {
		if hn := strings.TrimSpace(asString(id["hostname"])); hn != "" {
			nameByMAC[strings.ToLower(mac)] = hn
		}
	}

	if raw, err := os.ReadFile(filepath.Join(s.hncDir, "data", "devices.json")); err == nil {
		var dm map[string]map[string]any
		if json.Unmarshal(raw, &dm) == nil {
			for mac, d := range dm {
				m := strings.ToLower(strings.TrimSpace(mac))
				if ip := strings.TrimSpace(asString(d["ip"])); ip != "" && ip != "-" {
					if parsed := net.ParseIP(ip); parsed != nil {
						macByIP[parsed.String()] = m
					}
				}
				dropJunkHostname(d)
				if hn := strings.TrimSpace(asString(d["hostname"])); hn != "" {
					nameByMAC[m] = hn
				}
			}
		}
	}

	if raw, err := os.ReadFile(filepath.Join(s.hncDir, "data", "device_names.json")); err == nil {
		var nm map[string]string
		if json.Unmarshal(raw, &nm) == nil {
			for mac, label := range nm {
				if trimmed := strings.TrimSpace(label); trimmed != "" {
					nameByMAC[strings.ToLower(strings.TrimSpace(mac))] = trimmed
				}
			}
		}
	}
	return nameByMAC, macByIP
}

func normalizeBlockTarget(raw string) (kind, val string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", false
	}
	if strings.HasPrefix(s, "[") {
		if host, _, err := net.SplitHostPort(s); err == nil {
			s = host
		} else {
			s = strings.Trim(s, "[]")
		}
	} else if strings.Count(s, ":") == 1 {
		if host, port, err := net.SplitHostPort(s); err == nil && port != "" {
			if _, perr := strconv.Atoi(port); perr == nil {
				s = host
			}
		}
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() || isPrivateIP(ip.String()) {
			return "", "", false
		}
		return "ip", ip.String(), true
	}
	d := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(s), "*."), ".")
	if domainRe.MatchString(d) && len(d) <= 253 {
		return "domain", d, true
	}
	return "", "", false
}

func matchBlockedHost(hostOrIP string, mac string, cb connBlockFile, lgBlocked map[string]bool) bool {
	_, normVal, ok := normalizeBlockTarget(hostOrIP)
	if !ok {
		normVal = strings.ToLower(strings.TrimSpace(hostOrIP))
	}
	if normVal == "" {
		return false
	}
	for tgt := range lgBlocked {
		if normVal == tgt || strings.HasSuffix(normVal, "."+tgt) {
			return true
		}
	}
	mac = strings.ToLower(strings.TrimSpace(mac))
	for _, it := range cb.Items {
		if mac != "" && it.MAC != "" && it.MAC != mac {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(it.Value))
		if v == "" {
			continue
		}
		if it.Kind == "ip" && normVal == v {
			return true
		}
		if it.Kind == "domain" && (normVal == v || strings.HasSuffix(normVal, "."+v)) {
			return true
		}
	}
	return false
}

func (e *leakGuardEngine) syncFromDisk() []LeakEvent {
	if e.srv == nil || e.srv.hncDir == "" {
		return nil
	}
	raw, err := os.ReadFile(e.dpidEventsPath())
	if err != nil || len(raw) == 0 {
		return nil
	}
	parsed := decodeLeakEventsPayload(raw)
	if len(parsed) == 0 {
		return nil
	}
	return e.IngestEvents(parsed)
}

// IngestEvents 线程安全地摄入一批 LeakEvent（支持单测直接喂入或从 run/leakguard_events.json 合并）。
func (e *leakGuardEngine) IngestEvents(incoming []LeakEvent) []LeakEvent {
	if len(incoming) == 0 {
		return nil
	}
	nameByMAC, macByIP := e.srv.buildDeviceDirectory()

	e.mu.Lock()
	cfg := e.cfg
	clearedAt := e.clearedAt
	var added []LeakEvent
	var toNotify []LeakEvent

	for _, ev := range incoming {
		if ev.Ts <= 0 {
			ev.Ts = time.Now().Unix()
		}
		if clearedAt > 0 && ev.Ts < clearedAt {
			continue
		}
		if ev.Ts > e.maxSeenTs {
			e.maxSeenTs = ev.Ts
		}
		if ev.MAC == "" && ev.SrcIP != "" {
			if m := macByIP[ev.SrcIP]; m != "" {
				ev.MAC = m
			}
		}
		ev.MAC = strings.ToLower(strings.TrimSpace(ev.MAC))
		if ev.MAC != "" {
			if nm := nameByMAC[ev.MAC]; nm != "" {
				ev.DeviceName = nm
			}
		}
		if ev.DeviceName == "" {
			if ev.MAC != "" {
				ev.DeviceName = ev.MAC
			} else {
				ev.DeviceName = ev.SrcIP
			}
		}
		if ev.LeakLabel == "" {
			ev.LeakLabel = leakTypeDisplayName(ev.LeakType)
		}
		if ev.HitCount <= 0 {
			ev.HitCount = 1
		}
		ev.ID = computeLeakEventID(ev)
		if _, dup := e.seenIDs[ev.ID]; dup {
			for idx := len(e.events) - 1; idx >= 0; idx-- {
				if e.events[idx].ID == ev.ID {
					if ev.HitCount > e.events[idx].HitCount {
						delta := ev.HitCount - e.events[idx].HitCount
						e.events[idx].HitCount = ev.HitCount
						e.events[idx].Ts = ev.Ts
						e.totalHits.Add(delta)
					}
					break
				}
			}
			continue
		}
		e.seenIDs[ev.ID] = ev.Ts
		e.events = append(e.events, ev)
		e.totalHits.Add(ev.HitCount)
		added = append(added, ev)

		devKey := ev.MAC
		if devKey == "" {
			devKey = ev.SrcIP
		}
		cdKey := devKey + "|" + strings.ToLower(ev.DstHost) + "|" + strings.ToLower(ev.LeakType)
		lastTs, had := e.cooldownLedger[cdKey]
		inCooldown := had && cfg.CooldownSec > 0 && (ev.Ts-lastTs) < int64(cfg.CooldownSec)
		if !inCooldown {
			e.cooldownLedger[cdKey] = ev.Ts
			toNotify = append(toNotify, ev)
		}
	}

	if len(e.events) > cfg.Capacity {
		drop := len(e.events) - cfg.Capacity
		e.events = append([]LeakEvent(nil), e.events[drop:]...)
	}
	seenLimit := cfg.Capacity * 4
	if seenLimit < 2048 {
		seenLimit = 2048
	}
	if len(e.seenIDs) > seenLimit {
		keep := make(map[string]int64, len(e.events))
		for _, it := range e.events {
			keep[it.ID] = it.Ts
		}
		e.seenIDs = keep
	}

	var subs []chan LeakEvent
	if len(added) > 0 && len(e.subs) > 0 {
		subs = make([]chan LeakEvent, 0, len(e.subs))
		for ch := range e.subs {
			subs = append(subs, ch)
		}
	}
	e.mu.Unlock()

	for _, ev := range added {
		for _, ch := range subs {
			select {
			case ch <- ev:
			default:
			}
		}
	}
	for _, ev := range toNotify {
		if e.srv != nil && e.srv.hncDir != "" {
			acfg := alert.NewConfig(e.srv.hncDir)
			_ = alert.Append(acfg.AlertsJSONLPath, alert.Alert{
				ID:     ev.ID,
				Ts:     ev.Ts,
				Kind:   "leakguard",
				MAC:    ev.MAC,
				IP:     ev.SrcIP,
				Detail: fmt.Sprintf("%s 向 %s 明文传输 %s", ev.DeviceName, ev.DstHost, ev.LeakLabel),
				Extra: map[string]interface{}{
					"dst_host":  ev.DstHost,
					"leak_type": ev.LeakType,
				},
			})
		}
		if cfg.NotifyEnabled {
			e.postAndroidNotificationAsync(ev, cfg.LockscreenMask)
		}
	}
	return added
}

func (e *leakGuardEngine) snapshotPayload() map[string]any {
	e.syncFromDisk()

	nameByMAC, macByIP := e.srv.buildDeviceDirectory()
	cb := readConnBlocks(e.srv.hncDir)

	e.mu.Lock()
	cfg := e.cfg
	lgBlocked := make(map[string]bool, len(e.blockedTargets))
	for k, v := range e.blockedTargets {
		if v {
			lgBlocked[k] = true
		}
	}
	list := make([]LeakEvent, len(e.events))
	copy(list, e.events)
	e.mu.Unlock()

	devSet := make(map[string]bool)
	blockedHostSet := make(map[string]bool)
	for k := range lgBlocked {
		blockedHostSet[k] = true
	}
	for _, it := range cb.Items {
		if strings.HasPrefix(it.Label, "LeakGuard") {
			blockedHostSet[strings.ToLower(it.Value)] = true
		}
	}

	out := make([]LeakEvent, 0, len(list))
	for i := len(list) - 1; i >= 0; i-- {
		ev := list[i]
		if ev.MAC == "" && ev.SrcIP != "" {
			if m := macByIP[ev.SrcIP]; m != "" {
				ev.MAC = m
			}
		}
		if ev.MAC != "" {
			if nm := nameByMAC[ev.MAC]; nm != "" {
				ev.DeviceName = nm
			}
			devSet[ev.MAC] = true
		} else if ev.SrcIP != "" {
			devSet[ev.SrcIP] = true
		}
		blocked := matchBlockedHost(ev.DstHost, ev.MAC, cb, lgBlocked)
		if !blocked && ev.DstIP != "" {
			blocked = matchBlockedHost(ev.DstIP, ev.MAC, cb, lgBlocked)
		}
		ev.IsBlocked = blocked
		if blocked && ev.DstHost != "" {
			blockedHostSet[strings.ToLower(ev.DstHost)] = true
		}
		out = append(out, ev)
	}

	totalHits := e.totalHits.Load()
	if int64(len(out)) > totalHits {
		totalHits = int64(len(out))
	}
	affectedDevs := len(devSet)
	blockedDomains := len(blockedHostSet)

	return map[string]any{
		"ok":               true,
		"events":           out,
		"total_hits":       totalHits,
		"affected_devices": affectedDevs,
		"blocked_domains":  blockedDomains,
		"stats": map[string]any{
			"total_hits":       totalHits,
			"affected_devices": affectedDevs,
			"blocked_domains":  blockedDomains,
		},
		"config": cfg,
	}
}

func (e *leakGuardEngine) summary() map[string]any {
	e.mu.Lock()
	cfg := e.cfg
	cnt := len(e.events)
	blockedCnt := len(e.blockedTargets)
	e.mu.Unlock()
	return map[string]any{
		"total_hits":      e.totalHits.Load(),
		"buffered_events": cnt,
		"blocked_domains": blockedCnt,
		"notify_enabled":  cfg.NotifyEnabled,
		"lockscreen_mask": cfg.LockscreenMask,
	}
}

func (e *leakGuardEngine) runLoop(stop <-chan struct{}) {
	tk := time.NewTicker(3 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			e.syncFromDisk()
		}
	}
}

// ── LeakGuard HTTP 路由处理器 ────────────────────────────────────────────────

// apiLeakGuardEvents GET /api/leakguard/events
func (s *server) apiLeakGuardEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "GET only"})
		return
	}
	writeJSON(w, http.StatusOK, s.v6State().leakGuard.snapshotPayload())
}

// apiLeakGuardStream GET /api/leakguard/stream — SSE 实时流推送新捕获的 LeakEvent + 保活心跳帧
func (s *server) apiLeakGuardStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "GET only"})
		return
	}
	if n := leakSSEActiveConns.Add(1); n > leakMaxSSEClients {
		leakSSEActiveConns.Add(-1)
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "too many leakguard SSE streams"})
		return
	}
	defer leakSSEActiveConns.Add(-1)

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	flusher, canFlush := w.(http.Flusher)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	flushOut := func() error {
		if err := rc.Flush(); err == nil {
			return nil
		}
		if canFlush {
			flusher.Flush()
			return nil
		}
		return nil
	}

	writeFrame := func(frame string) bool {
		if _, err := io.WriteString(w, frame); err != nil {
			return false
		}
		return flushOut() == nil
	}

	eng := s.v6State().leakGuard
	subCh := make(chan LeakEvent, 64)
	eng.mu.Lock()
	eng.subs[subCh] = struct{}{}
	hbDur := eng.sseHeartbeat
	eng.mu.Unlock()
	defer func() {
		eng.mu.Lock()
		delete(eng.subs, subCh)
		eng.mu.Unlock()
	}()

	if !writeFrame(": leakguard-stream-ready\nevent: ready\ndata: {\"ok\":true}\n\n") {
		return
	}

	if hbDur <= 0 {
		hbDur = leakSSEHeartbeatDefault
	}
	hbTicker := time.NewTicker(hbDur)
	defer hbTicker.Stop()
	pollTicker := time.NewTicker(1500 * time.Millisecond)
	defer pollTicker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-subCh:
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			if !writeFrame("event: leak\ndata: " + string(b) + "\n\n") {
				return
			}
		case <-pollTicker.C:
			eng.syncFromDisk()
		case <-hbTicker.C:
			if !writeFrame(": heartbeat\n\n") {
				return
			}
		}
	}
}

// apiLeakGuardClear POST /api/leakguard/clear
func (s *server) apiLeakGuardClear(w http.ResponseWriter, r *http.Request) {
	eng := s.v6State().leakGuard
	now := time.Now().Unix()

	eng.mu.Lock()
	clrTs := now
	if eng.maxSeenTs >= clrTs {
		clrTs = eng.maxSeenTs + 1
	}
	eng.events = nil
	eng.seenIDs = make(map[string]int64)
	eng.cooldownLedger = make(map[string]int64)
	eng.clearedAt = clrTs
	eng.maxSeenTs = clrTs
	seq := eng.clearSeq.Add(1)
	eng.totalHits.Store(0)
	if s.hncDir != "" {
		_ = discoverWriteAtomic(eng.dpidEventsPath(), []byte("{\"events\":[]}\n"))
	}
	err := eng.saveStateLocked()
	eng.mu.Unlock()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write ctrl failed", "detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"clear_seq":  seq,
		"cleared_at": now,
	})
}

// apiLeakGuardConfig POST /api/leakguard/config
func (s *server) apiLeakGuardConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Capacity       *int  `json:"capacity"`
		CooldownSec    *int  `json:"cooldown_sec"`
		NotifyEnabled  *bool `json:"notify_enabled"`
		LockscreenMask *bool `json:"lockscreen_mask"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json", "detail": err.Error()})
		return
	}

	eng := s.v6State().leakGuard
	eng.mu.Lock()
	next := eng.cfg
	if req.Capacity != nil {
		if *req.Capacity < leakMinCapacity || *req.Capacity > leakMaxCapacity {
			eng.mu.Unlock()
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "capacity must be 10..2000"})
			return
		}
		next.Capacity = *req.Capacity
	}
	if req.CooldownSec != nil {
		if *req.CooldownSec < leakMinCooldownSec || *req.CooldownSec > leakMaxCooldownSec {
			eng.mu.Unlock()
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "cooldown_sec must be 0..86400"})
			return
		}
		next.CooldownSec = *req.CooldownSec
	}
	if req.NotifyEnabled != nil {
		next.NotifyEnabled = *req.NotifyEnabled
	}
	if req.LockscreenMask != nil {
		next.LockscreenMask = *req.LockscreenMask
	}

	eng.cfg = next
	if len(eng.events) > next.Capacity {
		eng.events = append([]LeakEvent(nil), eng.events[len(eng.events)-next.Capacity:]...)
	}
	err := eng.saveStateLocked()
	eng.mu.Unlock()

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write ctrl failed", "detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"config": next,
	})
}

// apiLeakGuardBlockDomain POST /api/leakguard/block-domain
// 支持 action: "block" | "unblock", 自动识别域名或纯 IPv4/IPv6 并直联 conn_blocks.go 双栈拦截。
func (s *server) apiLeakGuardBlockDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action  string `json:"action"`
		DstHost string `json:"dst_host"`
		MAC     string `json:"mac"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json", "detail": err.Error()})
		return
	}
	act := strings.ToLower(strings.TrimSpace(req.Action))
	if act == "" {
		act = "block"
	}
	if act != "block" && act != "unblock" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "action must be block|unblock"})
		return
	}
	kind, normVal, ok := normalizeBlockTarget(req.DstHost)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "invalid dst_host (domain or public IP required)"})
		return
	}

	eng := s.v6State().leakGuard
	reqMAC := strings.ToLower(strings.TrimSpace(req.MAC))
	var targetMACs []string
	if reqMAC != "" && reqMAC != "all" && reqMAC != "*" {
		if !validMAC(reqMAC) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "invalid mac"})
			return
		}
		targetMACs = []string{reqMAC}
	} else {
		macSet := make(map[string]bool)
		eng.mu.Lock()
		for _, ev := range eng.events {
			if validMAC(ev.MAC) {
				_, evHost, hok := normalizeBlockTarget(ev.DstHost)
				if !hok {
					evHost = strings.ToLower(ev.DstHost)
				}
				if evHost == normVal || strings.HasSuffix(evHost, "."+normVal) || ev.DstIP == normVal {
					macSet[ev.MAC] = true
				}
			}
		}
		eng.mu.Unlock()
		for mac := range s.deviceIPsByMAC() {
			if validMAC(mac) && !isProtectedMAC(s.hncDir, mac) {
				macSet[mac] = true
			}
		}
		if act == "unblock" {
			for _, it := range readConnBlocks(s.hncDir).Items {
				if it.Kind == kind && strings.EqualFold(it.Value, normVal) && validMAC(it.MAC) {
					macSet[it.MAC] = true
				}
			}
		}
		for m := range macSet {
			targetMACs = append(targetMACs, m)
		}
		sort.Strings(targetMACs)
	}

	scriptExists := false
	if st, err := os.Stat(filepath.Join(s.hncDir, "bin", "connblock_sync.sh")); err == nil && !st.IsDir() {
		scriptExists = true
	}

	applied := 0
	var lastDetail string
	for _, mac := range targetMACs {
		params := map[string]string{
			"mac":   mac,
			"kind":  kind,
			"value": normVal,
			"label": "LeakGuard 反制",
		}
		var resp actionResp
		if act == "block" {
			resp = actionConnBlockAdd(s, params)
		} else {
			resp = actionConnBlockDel(s, params)
		}
		if resp.OK {
			applied++
			lastDetail = resp.Detail
			continue
		}
		if resp.Error == "sync failed" && !scriptExists {
			applied++
			lastDetail = "saved (sandbox no connblock_sync.sh)"
			continue
		}
		if act == "unblock" && resp.Error == "not found" {
			continue
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":     false,
			"error":  resp.Error,
			"detail": resp.Detail,
		})
		return
	}

	eng.mu.Lock()
	if act == "block" {
		eng.blockedTargets[normVal] = true
	} else {
		delete(eng.blockedTargets, normVal)
	}
	for i := range eng.events {
		_, evHost, hok := normalizeBlockTarget(eng.events[i].DstHost)
		if !hok {
			evHost = strings.ToLower(eng.events[i].DstHost)
		}
		if evHost == normVal || strings.HasSuffix(evHost, "."+normVal) || eng.events[i].DstIP == normVal {
			if reqMAC == "" || reqMAC == "all" || reqMAC == "*" || eng.events[i].MAC == reqMAC {
				eng.events[i].IsBlocked = (act == "block")
			}
		}
	}
	_ = eng.saveStateLocked()
	eng.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"action":      act,
		"kind":        kind,
		"dst_host":    normVal,
		"is_blocked":  act == "block",
		"macs":        targetMACs,
		"applied_cnt": applied,
		"detail":      lastDetail,
	})
}
