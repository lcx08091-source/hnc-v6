// quick_health_v61.go — v6.1 按需零唤醒一句话省电与健康体检 (GET /api/health_check)
//
// 设计原则:
//  1. 零常驻开销: 0 后台 goroutine、0 Ticker、0 外部子进程 fork; 仅在前端显式请求时毫秒级只读聚合。
//  2. 四维大白话卡片:
//     - hotspot_forward    热点与转发通畅度 (网卡/网关 IPv4/ip_forward/看门狗被动保护态)
//     - zero_wakeup_power  待机零唤醒省电状态 (活动档位/后台 CPU 秒数/看门狗动作频率)
//     - shaping_offload    限速与加速规则一致性 (受控策略数/HTB 能力/硬件加速旁路/修复失败计数)
//     - tmpfs_config       内存盘与配置文件健康度 (run/ 32M tmpfs syscall.Statfs + 核心 JSON 完整性)
//  3. 闭环自愈动作: 每张卡片均输出标准化 fix_kind ("none"|"action"|"nav") 及一键修复参数。
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	qhStatusOK   = "ok"
	qhStatusWarn = "warn"
	qhStatusFail = "fail"

	qhFixNone   = "none"
	qhFixAction = "action"
	qhFixNav    = "nav"

	qhTmpfsWarnPct  = 75.0
	qhTmpfsFailPct  = 92.0
	qhCPUFailSec1H  = 360.0 // 单核 10% 持续占用红线
	qhTCRepairLimit = 3
)

type quickStatfsInfo struct {
	Supported  bool
	FSType     uint64
	IsTmpfs    bool
	TotalBytes uint64
	FreeBytes  uint64
	UsedBytes  uint64
}

// QuickHealthCheckItem 单张大白话体检卡 JSON 契约。
type QuickHealthCheckItem struct {
	ID        string            `json:"id"`
	Title     string            `json:"title"`
	Status    string            `json:"status"` // "ok" | "warn" | "fail"
	Badge     string            `json:"badge"`
	Verdict   string            `json:"verdict"`
	Detail    string            `json:"detail"`
	FixKind   string            `json:"fix_kind"` // "none" | "action" | "nav"
	FixLabel  string            `json:"fix_label"`
	FixAction string            `json:"fix_action"`
	FixParams map[string]string `json:"fix_params"`
	NavTarget string            `json:"nav_target"`
	Metrics   map[string]any    `json:"metrics"`
}

// QuickHealthCheckReport GET /api/health_check 顶层响应契约。
type QuickHealthCheckReport struct {
	OK              bool                   `json:"ok"`
	CheckedAt       int64                  `json:"checked_at"`
	DurationMs      int64                  `json:"duration_ms"`
	Version         string                 `json:"version,omitempty"`
	VersionCode     string                 `json:"version_code,omitempty"`
	DPIDVersion     string                 `json:"dpid_version,omitempty"`
	WatchdogVersion string                 `json:"watchdog_version,omitempty"`
	Overall         string                 `json:"overall"` // "ok" | "warn" | "fail"
	Headline        string                 `json:"headline"`
	Subline         string                 `json:"subline"`
	Items           []QuickHealthCheckItem `json:"items"`
}

// quickHealthEnv 外部内核节点与系统调用可替换探针(供单测确定性覆盖全部分支)。
type quickHealthEnv struct {
	Now           func() time.Time
	IPForwardPath string
	Statfs        func(path string) (quickStatfsInfo, error)
	IfaceIPv4     func(iface string) string
	EnforceTmpfs  bool // 为 true 时非 /data/local/hnc 目录也校验 tmpfs 挂载态(供单测注入)
}

func defaultQuickHealthEnv() quickHealthEnv {
	return quickHealthEnv{
		Now:           time.Now,
		IPForwardPath: "/proc/sys/net/ipv4/ip_forward",
		Statfs:        queryDirStatfsPlatform,
		IfaceIPv4:     ifaceIPv4,
	}
}

// apiQuickHealthCheck 处理 GET /api/health_check。
func (s *server) apiQuickHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"ok":    false,
			"error": "GET only",
		})
		return
	}
	rep := s.buildQuickHealthReport(defaultQuickHealthEnv())
	writeJSON(w, http.StatusOK, rep)
}

func (s *server) buildQuickHealthReport(env quickHealthEnv) QuickHealthCheckReport {
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.IPForwardPath == "" {
		env.IPForwardPath = "/proc/sys/net/ipv4/ip_forward"
	}
	if env.Statfs == nil {
		env.Statfs = queryDirStatfsPlatform
	}
	if env.IfaceIPv4 == nil {
		env.IfaceIPv4 = ifaceIPv4
	}

	start := time.Now()
	now := env.Now()

	var hncDir string
	if s != nil {
		hncDir = s.hncDir
	}

	itemHotspot, hotspotActive := s.evalHotspotForwardCard(hncDir, now, env)
	itemPower := s.evalZeroWakeupPowerCard(hncDir, hotspotActive)
	itemShaping := s.evalShapingOffloadCard(hncDir, hotspotActive)
	itemTmpfs := s.evalTmpfsConfigCard(hncDir, env)

	items := []QuickHealthCheckItem{
		itemHotspot,
		itemPower,
		itemShaping,
		itemTmpfs,
	}

	var okCnt, warnCnt, failCnt int
	var firstFail, firstWarn string
	for i := range items {
		if items[i].FixParams == nil {
			items[i].FixParams = map[string]string{}
		}
		if items[i].Metrics == nil {
			items[i].Metrics = map[string]any{}
		}
		switch items[i].Status {
		case qhStatusFail:
			failCnt++
			if firstFail == "" {
				firstFail = items[i].Verdict
			}
		case qhStatusWarn:
			warnCnt++
			if firstWarn == "" {
				firstWarn = items[i].Verdict
			}
		default:
			items[i].Status = qhStatusOK
			okCnt++
		}
	}

	overall := qhStatusOK
	var headline, subline string
	switch {
	case failCnt > 0:
		overall = qhStatusFail
		if failCnt == 1 && firstFail != "" {
			headline = firstFail
		} else {
			headline = fmt.Sprintf("发现 %d 项关键异常，建议立即一键处理", failCnt)
		}
		subline = fmt.Sprintf("共体检 4 项核心指标：正常 %d · 留意 %d · 异常 %d", okCnt, warnCnt, failCnt)
	case warnCnt > 0:
		overall = qhStatusWarn
		if warnCnt == 1 && firstWarn != "" {
			headline = firstWarn
		} else {
			headline = fmt.Sprintf("整体运行可用，有 %d 项细节建议留意", warnCnt)
		}
		subline = fmt.Sprintf("共体检 4 项核心指标：正常 %d · 留意 %d，基础热点上网不受影响", okCnt, warnCnt)
	default:
		if hotspotActive {
			headline = "热点转发通畅，零唤醒省电与限速规则全部健康"
		} else {
			headline = "全栈健康就绪，当前待机零唤醒几乎不耗电"
		}
		subline = "4 项核心指标全部通过：转发通畅 · 省电休眠 · 规则一致 · 闪存零擦写"
	}

	durMs := time.Since(start).Milliseconds()
	if durMs < 0 {
		durMs = 0
	}

	return QuickHealthCheckReport{
		OK:              true,
		CheckedAt:       now.Unix(),
		DurationMs:      durMs,
		Version:         s.serverVersion(),
		VersionCode:     s.serverVersionCode(),
		DPIDVersion:     s.dpidVersion(),
		WatchdogVersion: s.watchdogVersion(),
		Overall:         overall,
		Headline:        headline,
		Subline:         subline,
		Items:           items,
	}
}

// ─── 卡片 1: 热点与转发通畅度 ─────────────────────────────────────────

func (s *server) evalHotspotForwardCard(hncDir string, now time.Time, env quickHealthEnv) (QuickHealthCheckItem, bool) {
	item := QuickHealthCheckItem{
		ID:        "hotspot_forward",
		Title:     "热点与转发通畅度",
		Status:    qhStatusOK,
		FixKind:   qhFixNone,
		FixParams: map[string]string{},
		Metrics:   map[string]any{},
	}

	var iface string
	var simLive bool
	if s != nil {
		iface = s.currentHotspotIface()
		simLive = s.simActive()
	}
	ip := env.IfaceIPv4(iface)

	onlineCount := 0
	if hncDir != "" {
		nowSec := float64(now.Unix())
		if raw, err := s.readCachedJSON(filepath.Join(hncDir, "data", "devices.json")); err == nil {
			if dm, ok := raw.(map[string]any); ok {
				for _, v := range dm {
					if dev, ok2 := v.(map[string]any); ok2 {
						ls, _ := dev["last_seen"].(float64)
						if ls > 0 && (nowSec-ls) < 90 {
							onlineCount++
						}
					}
				}
			}
		}
	}

	hotspotActive := hotspotActiveFromState(hncDir, iface, ip, onlineCount)
	if simLive {
		hotspotActive = true
	}

	det := readIfaceDetect(hncDir)
	upstream := det.TetherUpstream
	if upstream == "" {
		upstream = det.Upstream
	}

	ipForward := -1
	ipForwardKnown := false
	if b, err := os.ReadFile(env.IPForwardPath); err == nil {
		v := strings.TrimSpace(string(b))
		if v == "0" || v == "1" {
			ipForward, _ = strconv.Atoi(v)
			ipForwardKnown = true
		}
	}

	watchdogPassive := false
	if hncDir != "" {
		if _, err := os.Stat(filepath.Join(hncDir, "run", "watchdog_passive.marker")); err == nil {
			watchdogPassive = true
		}
	}

	item.Metrics = map[string]any{
		"hotspot_active":   hotspotActive,
		"iface":            iface,
		"hotspot_ip":       ip,
		"online_devices":   onlineCount,
		"upstream":         upstream,
		"ip_forward":       ipForward,
		"ip_forward_known": ipForwardKnown,
		"watchdog_passive": watchdogPassive,
	}

	switch {
	case hotspotActive && ipForwardKnown && ipForward == 0:
		item.Status = qhStatusFail
		item.Badge = "转发中断"
		item.Verdict = "热点已开启，但系统网络转发未打开，连接设备可能无法上网"
		item.Detail = "检测到内核 IPv4 转发开关为关闭状态，点击下方按钮即可重新开启并恢复网关转发"
		item.FixKind = qhFixAction
		item.FixLabel = "一键恢复转发"
		item.FixAction = "refresh"
	case watchdogPassive:
		item.Status = qhStatusWarn
		item.Badge = "守护暂停"
		item.Verdict = "后台守护因连续重试失败已进入保护暂停模式"
		item.Detail = "自动恢复巡检暂时挂起，建议一键重启后台服务恢复全自动守护"
		item.FixKind = qhFixAction
		item.FixLabel = "重启后台服务"
		item.FixAction = "restart_service"
	case hotspotActive && ip == "" && !simLive:
		item.Status = qhStatusWarn
		item.Badge = "地址待就绪"
		item.Verdict = "热点已开启，但尚未识别到网关内网地址"
		item.Detail = "常见于刚开热点或网卡切换瞬间，可点击重新识别热点网卡"
		item.FixKind = qhFixAction
		item.FixLabel = "重新识别网卡"
		item.FixAction = "refresh"
	case !hotspotActive:
		item.Status = qhStatusOK
		item.Badge = "待机就绪"
		item.Verdict = "当前手机热点未开启，网关静默待机中"
		item.Detail = "打开系统个人热点后会自动识别网卡并接管转发，平时不占网络资源"
	default:
		item.Status = qhStatusOK
		item.Badge = "转发通畅"
		if onlineCount > 0 {
			item.Verdict = fmt.Sprintf("热点转发通畅，当前 %d 台设备在线上网", onlineCount)
		} else {
			item.Verdict = "热点网关已就绪，转发通道畅通，等待设备连接"
		}
		parts := make([]string, 0, 3)
		if iface != "" {
			parts = append(parts, "热点口 "+iface)
		}
		if ip != "" {
			parts = append(parts, "网关 "+ip)
		}
		if upstream != "" {
			parts = append(parts, "上游 "+upstream)
		}
		if len(parts) > 0 {
			item.Detail = strings.Join(parts, " · ")
		} else {
			item.Detail = "网关内网与上游转发状态正常"
		}
	}

	return item, hotspotActive
}

// ─── 卡片 2: 待机零唤醒省电状态 ───────────────────────────────────────

func (s *server) evalZeroWakeupPowerCard(hncDir string, hotspotActive bool) QuickHealthCheckItem {
	item := QuickHealthCheckItem{
		ID:        "zero_wakeup_power",
		Title:     "待机零唤醒省电状态",
		Status:    qhStatusOK,
		FixKind:   qhFixNone,
		FixParams: map[string]string{},
		Metrics:   map[string]any{},
	}

	act := activityNow()
	lvl := act.computeLevel()
	if !act.Known && hncDir != "" {
		if raw, err := s.readCachedJSON(filepath.Join(hncDir, "run", "activity.json")); err == nil {
			if m, ok := raw.(map[string]any); ok {
				if v := strings.TrimSpace(asString(m["level"])); v != "" {
					lvl = v
				}
				if b, ok2 := m["screen_on"].(bool); ok2 {
					act.ScreenOn = b
					act.ScreenKnown = true
				}
				if c, ok2 := toInt64(m["clients_online"]); ok2 {
					act.ClientsOnline = int(c)
				}
			}
		}
	}
	if lvl == lvlUnknown {
		if !hotspotActive {
			lvl = lvlHotspotOff
		} else {
			lvl = lvlActive
		}
	}

	var cpuSec1H, wakeupsPerMin float64
	powerSampled := false
	if hncDir != "" {
		if raw, err := s.readCachedJSON(filepath.Join(hncDir, "run", "power_stats.json")); err == nil {
			if m, ok := raw.(map[string]any); ok {
				if tot, ok2 := m["total"].(map[string]any); ok2 {
					cpuSec1H, _ = tot["cpu_sec_per_hour"].(float64)
					wakeupsPerMin, _ = tot["wakeups_per_min"].(float64)
					powerSampled = true
				}
			}
		}
	}

	var wdCalls1H, wdFails1H int64
	if hncDir != "" {
		if raw, err := s.readCachedJSON(filepath.Join(hncDir, "run", "watchdog_actions.json")); err == nil {
			if m, ok := raw.(map[string]any); ok {
				if acts, ok2 := m["actions"].(map[string]any); ok2 {
					for _, ar := range acts {
						if am, ok3 := ar.(map[string]any); ok3 {
							if c, ok4 := toInt64(am["calls_1h"]); ok4 {
								wdCalls1H += c
							}
							if f, ok4 := toInt64(am["fails_1h"]); ok4 {
								wdFails1H += f
							}
						}
					}
				}
			}
		}
	}

	item.Metrics = map[string]any{
		"activity_level":    lvl,
		"screen_on":         act.ScreenOn,
		"clients_online":    act.ClientsOnline,
		"power_sampled":     powerSampled,
		"cpu_sec_per_hour":  math.Round(cpuSec1H*10) / 10,
		"wakeups_per_min":   math.Round(wakeupsPerMin*10) / 10,
		"watchdog_calls_1h": wdCalls1H,
		"watchdog_fails_1h": wdFails1H,
	}

	switch {
	case powerSampled && cpuSec1H >= qhCPUFailSec1H:
		item.Status = qhStatusFail
		item.Badge = "耗电偏高"
		item.Verdict = fmt.Sprintf("后台组件每小时消耗约 %.0f 秒 CPU，高于省电安全线", cpuSec1H)
		item.Detail = "可能存在频繁重试或持续高负载抓包，建议打开分析页查看各进程功耗占比"
		item.FixKind = qhFixNav
		item.FixLabel = "查看功耗详情"
		item.NavTarget = "stats"
	case (powerSampled && cpuSec1H >= powerWarnSecPerHour) || wdCalls1H > scWatchdogActionsMaxCalls1H || wdFails1H > 0:
		item.Status = qhStatusWarn
		item.Badge = "唤醒偏多"
		if wdFails1H > 0 {
			item.Verdict = fmt.Sprintf("近 1 小时后台有 %d 次巡检动作重试，唤醒略微增多", wdFails1H)
		} else {
			item.Verdict = "后台调度频率略高于日常静默基线，建议留意"
		}
		item.Detail = fmt.Sprintf("当前每小时约 %.1f 秒 CPU · 看门狗外部调用 %d 次/小时", cpuSec1H, wdCalls1H)
		item.FixKind = qhFixNav
		item.FixLabel = "打开功耗面板"
		item.NavTarget = "stats"
	default:
		item.Status = qhStatusOK
		switch lvl {
		case lvlHotspotOff, lvlNoClients:
			item.Badge = "零唤醒休眠"
			item.Verdict = "无活跃设备自动进入零唤醒休眠，待机几乎不掉电"
		case lvlBackground:
			item.Badge = "熄屏省电"
			item.Verdict = "熄屏后台自动降频节拍生效中，兼顾限速稳定与省电"
		default:
			item.Badge = "按需省电"
			item.Verdict = "动态省电调度正常，熄屏或关热点后将自动转入静默休眠"
		}
		if powerSampled {
			item.Detail = fmt.Sprintf("实测后台每小时仅用 %.1f 秒 CPU（约 %.1f 次调度/分钟），不拖累手机续航", cpuSec1H, wakeupsPerMin)
		} else {
			item.Detail = "本体检亦采用按需零常驻设计，不额外增加任何后台轮询与唤醒"
		}
	}

	return item
}

// ─── 卡片 3: 限速与加速规则一致性 ─────────────────────────────────────

func (s *server) evalShapingOffloadCard(hncDir string, hotspotActive bool) QuickHealthCheckItem {
	item := QuickHealthCheckItem{
		ID:        "shaping_offload",
		Title:     "限速与加速规则一致性",
		Status:    qhStatusOK,
		FixKind:   qhFixNone,
		FixParams: map[string]string{},
		Metrics:   map[string]any{},
	}

	controlledDevices := 0
	blacklistedCount := 0
	globalShaper := false
	clsactMode := "auto"
	appLimitsCount := 0

	if hncDir != "" {
		if raw, err := s.readCachedJSON(filepath.Join(hncDir, "data", "rules.json")); err == nil {
			if m, ok := raw.(map[string]any); ok {
				clsactMode = clsactModeFromRules(m)
				globalShaper = boolField(m, "global_shaper_enabled")
				if bl, ok2 := m["blacklist"].([]any); ok2 {
					blacklistedCount = len(bl)
				}
				if devs, ok2 := m["devices"].(map[string]any); ok2 {
					for _, dr := range devs {
						dm, ok3 := dr.(map[string]any)
						if !ok3 {
							continue
						}
						dn, _ := dm["down_mbps"].(float64)
						up, _ := dm["up_mbps"].(float64)
						limOn := boolField(dm, "limit_enabled") || dn > 0 || up > 0
						dlyOn := boolField(dm, "delay_enabled")
						sqmOn := boolField(dm, "sqm_enabled")
						if limOn || dlyOn || sqmOn {
							controlledDevices++
						}
					}
				}
			}
		}
		if raw, err := s.readCachedJSON(filepath.Join(hncDir, "data", "app_limits.json")); err == nil {
			if m, ok := raw.(map[string]any); ok {
				if arr, ok2 := m["items"].([]any); ok2 {
					appLimitsCount = len(arr)
				}
			}
		}
	}

	totalPolicies := controlledDevices + blacklistedCount + appLimitsCount
	if globalShaper {
		totalPolicies++
	}

	htbSupported := true
	htbKnown := false
	if hncDir != "" {
		if sup, known := tcHTBSupported(hncDir); known {
			htbSupported = sup
			htbKnown = true
		}
	}

	var tcRepairFails int64
	qosFallback := false
	restorePending := false
	if hncDir != "" {
		if b, err := os.ReadFile(filepath.Join(hncDir, "run", "tc_repair_fail_count")); err == nil {
			if n, nerr := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); nerr == nil && n > 0 {
				tcRepairFails = n
			}
		}
		if _, err := os.Stat(filepath.Join(hncDir, "run", "tc_qos_fallback")); err == nil {
			qosFallback = true
		}
		if _, err := os.Stat(filepath.Join(hncDir, "run", "tc_restore_pending")); err == nil {
			restorePending = true
		}
	}

	offloadState := "UNKNOWN"
	offloadBypass := false
	if hncDir != "" {
		if og := readOffloadGuard(hncDir); og != nil {
			if st := asString(og["offload_state"]); st != "" {
				offloadState = st
			} else if st := asString(og["state"]); st != "" {
				offloadState = st
			}
			fb, _ := toInt64(og["fallback"])
			// 硬件卸载处于 ACTIVE 且用户把兜底强制关成 off 时, 限速会被硬件直通绕过
			if offloadState == "ACTIVE" && clsactMode == "off" && fb == 0 && (controlledDevices > 0 || appLimitsCount > 0 || globalShaper) {
				offloadBypass = true
			}
		}
	}

	item.Metrics = map[string]any{
		"controlled_devices": controlledDevices,
		"blacklisted_count":  blacklistedCount,
		"app_limits_count":   appLimitsCount,
		"global_shaper":      globalShaper,
		"total_policies":     totalPolicies,
		"clsact_mode":        clsactMode,
		"offload_state":      offloadState,
		"tc_htb_supported":   htbSupported,
		"tc_htb_known":       htbKnown,
		"tc_repair_fails":    tcRepairFails,
		"qos_fallback":       qosFallback,
		"restore_pending":    restorePending,
	}

	switch {
	case (controlledDevices > 0 || appLimitsCount > 0 || globalShaper) && htbKnown && !htbSupported:
		item.Status = qhStatusFail
		item.Badge = "内核受限"
		item.Verdict = "当前手机内核未开启 HTB 流量整形支持，限速规则无法挂入内核"
		item.Detail = "拉黑与统计仍可正常工作；可前往设置页打开兼容性自检查看当前 ROM 支持详情"
		item.FixKind = qhFixNav
		item.FixLabel = "查看兼容自检"
		item.NavTarget = "settings"
	case hotspotActive && tcRepairFails >= qhTCRepairLimit:
		item.Status = qhStatusFail
		item.Badge = "规则失步"
		item.Verdict = fmt.Sprintf("限速规则同步连续失败 %d 次，部分限速可能未生效", tcRepairFails)
		item.Detail = "点击一键重同步将立即校准硬件卸载慢路径并重新挂载全部设备限速队列"
		item.FixKind = qhFixAction
		item.FixLabel = "一键重同步规则"
		item.FixAction = "dataplane_verify_run"
		item.FixParams = map[string]string{"resync": "1"}
	case hotspotActive && offloadBypass:
		item.Status = qhStatusWarn
		item.Badge = "加速抢跑"
		item.Verdict = "系统硬件加速处于活跃态且防旁路兜底已关闭，测速可能绕过限速"
		item.Detail = "建议将防旁路模式切回自动，或点击一键校准让受控设备流量走限速队列"
		item.FixKind = qhFixAction
		item.FixLabel = "开启自动防旁路"
		item.FixAction = "clsact_mode_set"
		item.FixParams = map[string]string{"mode": "auto"}
	case hotspotActive && (tcRepairFails > 0 || restorePending):
		item.Status = qhStatusWarn
		item.Badge = "待重校准"
		item.Verdict = "检测到限速队列有待恢复标记，建议执行一次规则校准"
		item.Detail = "点击下方按钮可立即核验内核命中计数并补齐缺失规则"
		item.FixKind = qhFixAction
		item.FixLabel = "一键校准规则"
		item.FixAction = "dataplane_verify_run"
		item.FixParams = map[string]string{"resync": "1"}
	case totalPolicies == 0:
		item.Status = qhStatusOK
		item.Badge = "满速直通"
		item.Verdict = "当前未开启设备限速或拉黑规则，接入设备享受原速转发"
		item.Detail = "需要限制某台设备网速或应用流量时，可在设备页随时开启，立即生效"
	default:
		item.Status = qhStatusOK
		item.Badge = "规则一致"
		item.Verdict = fmt.Sprintf("已配置 %d 项管控策略，限速队列与硬件加速协同正常", totalPolicies)
		if qosFallback {
			item.Detail = fmt.Sprintf("当前运行于兼容限速模式（防旁路模式：%s），上下行限速稳定生效", clsactMode)
		} else {
			item.Detail = fmt.Sprintf("防旁路模式：%s · 规则树健康无报错", clsactMode)
		}
	}

	return item
}

// ─── 卡片 4: 32M 内存盘 syscall.Statfs 与核心 JSON 健康度 ──────────────

var quickManagedJSONFiles = []struct {
	name     string
	required bool
}{
	{"rules.json", true},
	{"device_names.json", false},
	{"templates.json", false},
	{"remote_tokens.json", false},
	{"devices.json", false},
	{"limit_policies.json", false},
	{"app_limits.json", false},
}

func (s *server) evalTmpfsConfigCard(hncDir string, env quickHealthEnv) QuickHealthCheckItem {
	item := QuickHealthCheckItem{
		ID:        "tmpfs_config",
		Title:     "内存盘与配置文件健康度",
		Status:    qhStatusOK,
		FixKind:   qhFixNone,
		FixParams: map[string]string{},
		Metrics:   map[string]any{},
	}

	var st quickStatfsInfo
	var statfsErr string
	if hncDir != "" {
		runDir := filepath.Join(hncDir, "run")
		info, err := env.Statfs(runDir)
		if err != nil {
			statfsErr = err.Error()
		} else {
			st = info
		}
	}

	var totalMB, usedMB, freeMB, usedPct float64
	if st.Supported && st.TotalBytes > 0 {
		totalMB = float64(st.TotalBytes) / (1024.0 * 1024.0)
		usedMB = float64(st.UsedBytes) / (1024.0 * 1024.0)
		freeMB = float64(st.FreeBytes) / (1024.0 * 1024.0)
		usedPct = float64(st.UsedBytes) * 100.0 / float64(st.TotalBytes)
	}

	checkedFiles := 0
	badFiles := make([]string, 0)
	if hncDir != "" {
		dataDir := filepath.Join(hncDir, "data")
		for _, mf := range quickManagedJSONFiles {
			full := filepath.Join(dataDir, mf.name)
			b, err := os.ReadFile(full)
			if err != nil {
				if os.IsNotExist(err) && !mf.required {
					continue
				}
				checkedFiles++
				badFiles = append(badFiles, mf.name)
				continue
			}
			checkedFiles++
			trimmed := bytes.TrimSpace(b)
			if len(trimmed) == 0 || !json.Valid(trimmed) {
				badFiles = append(badFiles, mf.name)
			}
		}
	}

	backupCount := 0
	if hncDir != "" {
		if ents, err := os.ReadDir(filepath.Join(hncDir, "data", ".json_backups")); err == nil {
			for _, e := range ents {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".bak") {
					backupCount++
				}
			}
		}
	}

	expectTmpfs := env.EnforceTmpfs || (hncDir != "" && filepath.Clean(hncDir) == "/data/local/hnc")

	item.Metrics = map[string]any{
		"statfs_supported": st.Supported,
		"run_is_tmpfs":     st.IsTmpfs,
		"run_fs_magic":     fmt.Sprintf("0x%x", st.FSType),
		"run_total_bytes":  st.TotalBytes,
		"run_used_bytes":   st.UsedBytes,
		"run_free_bytes":   st.FreeBytes,
		"run_used_pct":     math.Round(usedPct*10) / 10,
		"json_checked":     checkedFiles,
		"json_bad_count":   len(badFiles),
		"json_bad_files":   badFiles,
		"backup_count":     backupCount,
	}
	if statfsErr != "" {
		item.Metrics["statfs_error"] = statfsErr
	}

	spaceFail := st.Supported && st.TotalBytes > 0 &&
		((st.IsTmpfs && usedPct >= qhTmpfsFailPct && st.FreeBytes < 16<<20) || st.FreeBytes < 2<<20)
	spaceWarn := !spaceFail && st.Supported && st.TotalBytes > 0 &&
		((st.IsTmpfs && usedPct >= qhTmpfsWarnPct && st.FreeBytes < 32<<20) || st.FreeBytes < 8<<20)

	switch {
	case len(badFiles) > 0:
		item.Status = qhStatusFail
		item.Badge = "配置损坏"
		item.Verdict = fmt.Sprintf("检测到 %d 个核心配置文件异常（%s），可能导致规则丢失", len(badFiles), strings.Join(badFiles, "、"))
		if backupCount > 0 {
			item.Detail = fmt.Sprintf("系统保留了 %d 份历史完好备份，点击下方按钮即可自动恢复损坏的 JSON 文件", backupCount)
		} else {
			item.Detail = "点击一键修复可调用配置医生校验并尝试恢复损坏的核心配置文件"
		}
		item.FixKind = qhFixAction
		item.FixLabel = "一键修复配置"
		item.FixAction = "json_doctor_repair"
	case spaceFail:
		item.Status = qhStatusFail
		item.Badge = "空间告急"
		if st.IsTmpfs {
			item.Verdict = fmt.Sprintf("运行态内存盘已占用 %.0f%%（仅剩 %.1f MB），随时可能写满", usedPct, freeMB)
		} else {
			item.Verdict = fmt.Sprintf("运行目录可用空间仅剩 %.1f MB，随时可能写满报错", freeMB)
		}
		item.Detail = "空间不足会导致实时速率与状态快照无法更新，建议立即清理运行缓存"
		item.FixKind = qhFixAction
		item.FixLabel = "一键释放空间"
		item.FixAction = "cache_clear"
	case spaceWarn:
		item.Status = qhStatusWarn
		item.Badge = "空间偏紧"
		if st.IsTmpfs {
			item.Verdict = fmt.Sprintf("运行态内存盘已用 %.1f / %.0f MB（%.0f%%），剩余空间偏少", usedMB, totalMB, usedPct)
		} else {
			item.Verdict = fmt.Sprintf("运行目录可用空间仅剩 %.1f MB，剩余余量偏少", freeMB)
		}
		item.Detail = "可一键清理临时缓存与探测残留，保障长时间稳定挂机"
		item.FixKind = qhFixAction
		item.FixLabel = "清理运行缓存"
		item.FixAction = "cache_clear"
	case st.Supported && expectTmpfs && !st.IsTmpfs:
		item.Status = qhStatusWarn
		item.Badge = "未挂内存盘"
		item.Verdict = "运行态目录未挂载到 32M 内存盘，高频状态正直接读写手机闪存"
		item.Detail = "重启后台服务可重新挂载 32M 内存盘，让实时状态读写零闪存损耗"
		item.FixKind = qhFixAction
		item.FixLabel = "重启服务挂载"
		item.FixAction = "restart_service"
	default:
		item.Status = qhStatusOK
		item.Badge = "零擦写健康"
		if st.Supported && st.IsTmpfs && totalMB > 0 {
			item.Verdict = fmt.Sprintf("32M 内存盘余量充足（已用 %.1f / %.0f MB），核心配置文件全部完好", usedMB, totalMB)
		} else {
			item.Verdict = "核心 JSON 配置文件全部完好，运行目录剩余空间充足"
		}
		item.Detail = fmt.Sprintf("已校验 %d 个核心配置文件无损坏，高频运行态驻留内存保护手机闪存", checkedFiles)
	}

	return item
}

func (s *server) readCachedJSON(path string) (any, error) {
	if s != nil && s.jsonCache != nil {
		return s.jsonCache.read(path)
	}
	return (*jsonFileCache)(nil).read(path)
}

// invalidateServerJSONCaches 清空 httpd 进程内 JSON 文件缓存与 rulesStore 快照缓存。
func (s *server) invalidateServerJSONCaches() {
	if s != nil && s.jsonCache != nil {
		s.jsonCache.mu.Lock()
		clear(s.jsonCache.entries)
		s.jsonCache.mu.Unlock()
	}
	rulesStore.mu.Lock()
	rulesStore.cachedSnapshot = nil
	rulesStore.cachedPath = ""
	rulesStore.cachedModNano = 0
	rulesStore.cachedSize = 0
	rulesStore.mu.Unlock()
	if s != nil && s.tokens != nil {
		_ = s.tokens.SyncIfChanged()
	}
}

// actionJSONDoctorRepair 调用 ./bin/json_doctor.sh repair 从最近有效备份修复损坏 JSON 并刷新内存缓存。
func actionJSONDoctorRepair(s *server) actionResp {
	if s == nil || s.hncDir == "" {
		return actionResp{OK: false, Error: "server unavailable"}
	}
	rc, out := runBin(s.hncDir, "json_doctor.sh", "repair")
	s.invalidateServerJSONCaches()
	detail := strings.TrimSpace(out)
	if rc != 0 {
		if detail == "" {
			detail = fmt.Sprintf("json_doctor.sh repair exited with rc=%d", rc)
		}
		return actionResp{OK: false, Error: "repair failed", Detail: detail}
	}
	if detail == "" {
		detail = "repair complete"
	}
	return actionResp{OK: true, Detail: detail}
}
