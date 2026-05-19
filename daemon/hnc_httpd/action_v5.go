// action_v5.go — v5.0 B 路线新 action handlers
// 取代前端 kexec 直接调 shell 的 13 个 backend. 所有 shell exec 走 runBin
// 所有用户输入走严格白名单校验 (macRE / 整数 / 数值范围等).
//
// 设计原则:
//   - 每个 action 独立, 参数类型/范围在 Go 层验证
//   - shell 命令字符串绝不由 Go 拼接, runBin 直接 argv exec
//   - 错误 detail 带原始 stdout/stderr, 让前端 toast 显示有用信息

package main

import (
	"log"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ────────────────────────────────────────────────────────────────
// 延迟注入
// ────────────────────────────────────────────────────────────────

// 整数范围校验 (前端不可信)
var intRE = regexp.MustCompile(`^[0-9]+$`)
var floatRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

func lookupCurrentDeviceIP(hncDir, mac string) string {
	raw, err := readJSON(hncDir + "/data/devices.json")
	if err != nil {
		return ""
	}
	devices, _ := raw.(map[string]interface{})
	dev, _ := devices[mac].(map[string]interface{})
	if dev == nil {
		return ""
	}
	ip, _ := dev["ip"].(string)
	ip = strings.TrimSpace(ip)
	if ip != "" && ipv4RE.MatchString(ip) {
		return ip
	}
	return ""
}

func lookupRuleDeviceField(hncDir, mac, field string) string {
	rc, out := runBin(hncDir, "json_set.sh", "device_get", mac, field)
	if rc != 0 {
		return ""
	}
	return strings.TrimSpace(out)
}

func ruleNumberPositive(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.Trim(s, `"`)
	s = strings.TrimSuffix(s, "mbit")
	s = strings.TrimSuffix(s, "kbit")
	s = strings.TrimSuffix(s, "m")
	s = strings.TrimSuffix(s, "k")
	if s == "" {
		return false
	}
	v, err := strconv.ParseFloat(s, 64)
	return err == nil && v > 0
}

func deviceHasPositiveLimit(hncDir, mac string) bool {
	if lookupRuleDeviceField(hncDir, mac, "limit_enabled") != "true" {
		return false
	}
	return ruleNumberPositive(lookupRuleDeviceField(hncDir, mac, "down_mbps")) ||
		ruleNumberPositive(lookupRuleDeviceField(hncDir, mac, "up_mbps"))
}

func notifyOffloadLimit(hncDir, mac string, enabled bool) {
	flag := "0"
	if enabled {
		flag = "1"
	}
	if rc, out := runExe(hncDir, "hnc_ipc", "OFFLOAD_NOTIFY_LIMIT", mac, flag); rc != 0 {
		log.Printf("WARN: OFFLOAD_NOTIFY_LIMIT mac=%s flag=%s failed rc=%d out=%q", mac, flag, rc, out)
	}
}

func atoiClamp(s string, min, max int) (int, bool) {
	if !intRE.MatchString(s) {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < min || n > max {
		return 0, false
	}
	return n, true
}

// actionDelaySet · 延迟注入
// params: mac, delay_ms(0-5000), jitter_ms(0-5000), loss_pct(0-100)
func actionDelaySet(hncDir string, p map[string]string) actionResp {
	mac := p["mac"]
	if !macRE.MatchString(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	delay, ok1 := atoiClamp(p["delay_ms"], 0, 5000)
	jitter, ok2 := atoiClamp(p["jitter_ms"], 0, 5000)
	if !ok1 || !ok2 {
		return actionResp{OK: false, Error: "bad params", Detail: "delay_ms/jitter_ms out of range (0-5000)"}
	}
	lossStr := p["loss_pct"]
	if !floatRE.MatchString(lossStr) {
		return actionResp{OK: false, Error: "bad params", Detail: "loss_pct must be number"}
	}
	loss, err := strconv.ParseFloat(lossStr, 64)
	if err != nil || loss < 0 || loss > 100 {
		return actionResp{OK: false, Error: "bad params", Detail: "loss_pct out of range (0-100)"}
	}

	// hotfix16.9: fail fast when netem/HTB path is known unsupported.
	// The current tc_manager netem implementation needs HTB leaf classes.
	if delay > 0 || jitter > 0 || loss > 0 {
		if supported, known := tcHTBSupported(hncDir); known && !supported {
			return actionResp{OK: false, Error: "unsupported", Detail: "tc_htb=false; delay path requires HTB leaf classes"}
		}
		if supported, known := tcNetemSupported(hncDir); known && !supported {
			return actionResp{OK: false, Error: "unsupported", Detail: "tc_netem=false; current kernel/TC does not support netem"}
		}
	}

	// 需要 iface + mark_id — 从 device_detect.sh iface + rules.json 查
	rc, out := runBin(hncDir, "device_detect.sh", "iface")
	if rc != 0 {
		return actionResp{OK: false, Error: "iface detect failed", Detail: out}
	}
	iface := strings.TrimSpace(out)
	if iface == "" {
		return actionResp{OK: false, Error: "no hotspot iface"}
	}

	// rc3 修 N-1: mark_id 是 per-device, 不是顶层. 用新加的 device_get.
	rcM, outM := runBin(hncDir, "json_set.sh", "device_get", mac, "mark_id")
	mid := strings.TrimSpace(outM)
	newMid := false
	if rcM != 0 || mid == "" {
		// rc2 修 G3: 没分配过 → 调 alloc_mid 专用子命令, 只分配 mid + iptables mark,
		//          不触 tc 也不写 limit_enabled/down_mbps/up_mbps (之前借 "limit 0 0"
		//          会污染 rules.json, UI 显示"已限速到 0" 误导用户).
		rc0, out0 := runBin(hncDir, "apply_device_rule.sh", "alloc_mid", mac)
		if rc0 != 0 {
			return actionResp{OK: false, Error: "mid assign failed", Detail: out0}
		}
		mid = strings.TrimSpace(out0)
		newMid = true
		// rc3.1.33 修 #2: alloc_mid stdout 应为纯整数 mid, 白名单确认 (防 awk 错位输出).
		if !intRE.MatchString(mid) {
			return actionResp{OK: false, Error: "mid assign failed",
				Detail: "alloc_mid returned non-integer mid: " + mid}
		}
	}

	// rc3 修 N-1: tc_manager.sh 实际子命令是 set_delay, 不是 set_netem
	// 签名: set_delay <iface> <mark_id> <delay_ms> <jitter_ms> <loss_pct> [ip]
	// v5.1.0-rc1 hotfix: delay-only 场景也传当前 IP,确保 ifb0 u32 src filter 能创建。
	ip := lookupCurrentDeviceIP(hncDir, mac)
	rc3, out3 := runBin(hncDir, "tc_manager.sh", "set_delay", iface, mid,
		strconv.Itoa(delay), strconv.Itoa(jitter), lossStr, ip)
	if rc3 != 0 {
		if newMid {
			rollbackIP := ip
			if rollbackIP == "" {
				rollbackIP = lookupRuleDeviceField(hncDir, mac, "ip")
			}
			runBin(hncDir, "iptables_manager.sh", "unmark", rollbackIP, mac, mid)
			runBin(hncDir, "json_set.sh", "device", mac, "mark_id", "0")
		}
		return actionResp{OK: false, Error: "netem apply failed", Detail: out3}
	}
	notifyOffloadLimit(hncDir, mac, true)
	// rc3.1.13.2 修 P1 (review §一致性-1): 之前 4 次 json_set 用 _, _= 吞错,
	// 任意一次失败 → JSON 半状态 (tc 应用了但 rules.json 部分字段没更新),
	// 下次 watchdog restore 行为不可预测. 现在累计失败再上报.
	jsonWrites := []struct{ field, value string }{
		{"delay_enabled", "true"},
		{"delay_ms", strconv.Itoa(delay)},
		{"jitter_ms", strconv.Itoa(jitter)},
		{"loss_pct", lossStr},
	}
	var failed []string
	for _, w := range jsonWrites {
		if rc, out := runBin(hncDir, "json_set.sh", "device", mac, w.field, w.value); rc != 0 {
			failed = append(failed, w.field+":"+strings.TrimSpace(out))
		}
	}
	if len(failed) > 0 {
		// tc 已应用但 JSON 部分字段写失败。返回失败让 UI 不显示“假成功”，
		// 用户可再次点击应用来收敛 rules.json。
		return actionResp{OK: false, Error: "partial json write failed", Detail: strings.Join(failed, "; ")}
	}
	return actionResp{OK: true, Detail: "delay injected"}
}

// actionDelayClear · 清除延迟
func actionDelayClear(hncDir string, p map[string]string) actionResp {
	mac := p["mac"]
	if !macRE.MatchString(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	rc, out := runBin(hncDir, "device_detect.sh", "iface")
	if rc != 0 {
		return actionResp{OK: false, Error: "iface detect failed", Detail: out}
	}
	iface := strings.TrimSpace(out)
	// rc3 修 N-1: 读 per-device mark_id
	rcM, outM := runBin(hncDir, "json_set.sh", "device_get", mac, "mark_id")
	if rcM != 0 {
		log.Printf("WARN: delay_clear device_get mark_id rc=%d out=%q", rcM, outM)
	}
	mid := strings.TrimSpace(outM)
	if mid == "" {
		return actionResp{OK: true, Detail: "already cleared (no mid)"}
	}
	// rc3.1.33 修 #2: 同 delay_set, 防垃圾 mid 传给 tc
	if !intRE.MatchString(mid) {
		return actionResp{OK: false, Error: "mid invalid",
			Detail: "device_get returned non-integer mid: " + mid}
	}
	hasLimit := deviceHasPositiveLimit(hncDir, mac)
	ip := lookupCurrentDeviceIP(hncDir, mac)
	if ip == "" {
		ip = lookupRuleDeviceField(hncDir, mac, "ip")
	}

	// 有限速时只清 netem，保留 class/rate；delay-only 时清理整套 tc/iptables，避免残留 mark/class。
	if hasLimit {
		rc2, out2 := runBin(hncDir, "tc_manager.sh", "set_delay", iface, mid, "0", "0", "0", ip)
		if rc2 != 0 {
			return actionResp{OK: false, Error: "netem clear failed", Detail: out2}
		}
	} else {
		if rc2, out2 := runBin(hncDir, "tc_manager.sh", "remove", iface, mid); rc2 != 0 {
			log.Printf("WARN: delay_clear remove tc failed rc=%d out=%q", rc2, out2)
		}
		runBin(hncDir, "iptables_manager.sh", "unmark", ip, mac, mid)
		notifyOffloadLimit(hncDir, mac, false)
	}

	clearFields := []struct{ key, val string }{
		{"delay_enabled", "false"},
		{"delay_ms", "0"},
		{"jitter_ms", "0"},
		{"loss_pct", "0"},
	}
	var failed []string
	for _, f := range clearFields {
		if rcJ, outJ := runBin(hncDir, "json_set.sh", "device", mac, f.key, f.val); rcJ != 0 {
			failed = append(failed, f.key+":"+strings.TrimSpace(outJ))
		}
	}
	if len(failed) > 0 {
		return actionResp{OK: false, Error: "partial json write failed", Detail: strings.Join(failed, "; ")}
	}
	return actionResp{OK: true, Detail: "delay cleared"}
}

// ────────────────────────────────────────────────────────────────
// 模板 (单设备 apply) — 修 Bug S
// ────────────────────────────────────────────────────────────────

// actionTemplateApply · 单设备应用模板
// params: mac, rate_down, rate_up (前端已展开模板字段, 复用 rule_set 逻辑)
// 这里直接委托 rule_set, 方便日后前端切到 template_id 不需要改 server
func actionTemplateApply(hncDir string, p map[string]string) actionResp {
	return actionRuleSet(hncDir, p)
}

// ────────────────────────────────────────────────────────────────
// 热点控制 · 修 Bug M
// ────────────────────────────────────────────────────────────────

// rc5.1.1 UTF-8 支持: 原 ssidRE/passRE 正则只接受 ASCII, 中文/日文/emoji SSID
// 全部被拒. IEEE 802.11 实际允许 SSID 为 32 字节任意 UTF-8, WPA 密码为 8-63
// 字节 UTF-8, Android 从 4.x 起就支持中文 SSID.
func validSSID(s string) bool {
	b := []byte(s)
	if len(b) == 0 || len(b) > 32 {
		return false
	}
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 { // 拒绝控制字符
			return false
		}
	}
	return true
}

func validPass(s string) bool {
	b := []byte(s)
	if len(b) < 8 || len(b) > 63 {
		return false
	}
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 {
			return false
		}
	}
	return true
}

func actionHotspotStart(hncDir string) actionResp {
	rc, out := runBin(hncDir, "hotspot_autostart.sh", "start")
	if rc != 0 {
		return actionResp{OK: false, Error: "hotspot start failed", Detail: out}
	}
	return actionResp{OK: true, Detail: "hotspot started"}
}

func actionHotspotStop(hncDir string) actionResp {
	rc, out := runBin(hncDir, "hotspot_autostart.sh", "stop")
	if rc != 0 {
		return actionResp{OK: false, Error: "hotspot stop failed", Detail: out}
	}
	return actionResp{OK: true, Detail: "hotspot stopped"}
}

// actionHotspotSave · 保存热点配置
// params: ssid, password, delay_sec, autostart("true"/"false")
func actionHotspotSave(hncDir string, p map[string]string) actionResp {
	ssid := p["ssid"]
	pass := p["password"]
	delayStr := p["delay_sec"]
	autostart := p["autostart"]
	if ssid != "" && !validSSID(ssid) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid ssid"}
	}
	if pass != "" && !validPass(pass) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid password (8-63 UTF-8 chars, no control characters)"}
	}
	delay, ok := atoiClamp(delayStr, 0, 3600)
	if delayStr != "" && !ok {
		return actionResp{OK: false, Error: "bad params", Detail: "delay_sec out of range (0-3600)"}
	}
	if autostart != "" && autostart != "true" && autostart != "false" {
		return actionResp{OK: false, Error: "bad params", Detail: "autostart must be true/false"}
	}
	// rc3 修 N-3: hotspot_autostart.sh 没有 save 子命令, 直接写 rules.json.
	// 字段名用 hotspot_auto / hotspot_ssid / hotspot_pass / hotspot_delay
	// (这是 service.sh:141 + watchdog 实际读的名字, 开机自启动才能生效)
	if ssid != "" {
		if rc, out := runBin(hncDir, "json_set.sh", "top", "hotspot_ssid", ssid); rc != 0 {
			return actionResp{OK: false, Error: "save ssid failed", Detail: out}
		}
	}
	if pass != "" {
		if rc, out := runBin(hncDir, "json_set.sh", "top", "hotspot_pass", pass); rc != 0 {
			return actionResp{OK: false, Error: "save pass failed", Detail: out}
		}
	}
	if delayStr != "" {
		if rc, out := runBin(hncDir, "json_set.sh", "top", "hotspot_delay", strconv.Itoa(delay)); rc != 0 {
			return actionResp{OK: false, Error: "save delay failed", Detail: out}
		}
	}
	if autostart != "" {
		if rc, out := runBin(hncDir, "json_set.sh", "top", "hotspot_auto", autostart); rc != 0 {
			return actionResp{OK: false, Error: "save autostart failed", Detail: out}
		}
	}
	return actionResp{OK: true, Detail: "config saved"}
}

// ────────────────────────────────────────────────────────────────
// 白名单 / 鉴权 toggle · 修 Bug 2
// ────────────────────────────────────────────────────────────────

func actionWhitelistSet(hncDir string, p map[string]string) actionResp {
	v := p["enabled"]
	if v != "true" && v != "false" {
		return actionResp{OK: false, Error: "bad params", Detail: "enabled must be true/false"}
	}
	rc, out := runBin(hncDir, "json_set.sh", "top", "whitelist_mode", v)
	if rc != 0 {
		return actionResp{OK: false, Error: "write failed", Detail: out}
	}
	return actionResp{OK: true}
}

func actionAuthRequiredSet(hncDir string, p map[string]string) actionResp {
	v := p["enabled"]
	if v != "true" && v != "false" {
		return actionResp{OK: false, Error: "bad params", Detail: "enabled must be true/false"}
	}
	// rc3.1.13: cfg_set (config.json) → top (rules.json) 单源化, 见 middleware.go 注释
	rc, out := runBin(hncDir, "json_set.sh", "top", "auth_required", v)
	if rc != 0 {
		return actionResp{OK: false, Error: "write failed", Detail: out}
	}
	return actionResp{OK: true}
}

// rc3.1.3 修: actionRemoteEnabledSet · 启停远程访问 :8443.
// 之前缺这个 action, rules.json 永远无 remote_enabled 字段, httpd 从未绑过 :8443,
// 导致远程 URL ERR_ADDRESS_UNREACHABLE. 前端"运行中"徽章还是静态虚假状态.
// 修复: 写 rules.json 顶层 remote_enabled = v.  watchdog 60s 内轮询 check_httpd_bind_drift
// 检测到 loopback-only -> 热点 IP 漂移后重启 httpd 绑新 IP.
func actionRemoteEnabledSet(hncDir string, p map[string]string) actionResp {
	v := p["enabled"]
	if v != "true" && v != "false" {
		return actionResp{OK: false, Error: "bad params", Detail: "enabled must be true/false"}
	}
	rc, out := runBin(hncDir, "json_set.sh", "top", "remote_enabled", v)
	if rc != 0 {
		return actionResp{OK: false, Error: "write failed", Detail: out}
	}
	// 写完后等 watchdog 自然触发. 返回提示给用户
	detail := "remote access enabled · 约 1 分钟内远程 URL 可访问"
	if v == "false" {
		detail = "remote access disabled · 约 1 分钟内 :8443 关闭"
	}
	return actionResp{OK: true, Detail: detail}
}

// ────────────────────────────────────────────────────────────────
// 其他 · refresh / pair / cleanup
// ────────────────────────────────────────────────────────────────

func actionRefresh(hncDir string) actionResp {
	rc, out := runBin(hncDir, "device_detect.sh", "scan")
	if rc != 0 {
		return actionResp{OK: false, Error: "scan failed", Detail: out}
	}
	return actionResp{OK: true, Detail: strings.TrimSpace(out)}
}

func actionPairNew(hncDir string) actionResp {
	rc, out := runBin(hncDir, "pair_gen.sh")
	if rc != 0 {
		return actionResp{OK: false, Error: "pair_gen failed", Detail: out}
	}
	// pair_gen.sh 返回 JSON, 直接透传给前端
	return actionResp{OK: true, Detail: strings.TrimSpace(out)}
}

func actionPairRevoke(hncDir string, p map[string]string) actionResp {
	token := p["token"]
	// rc3.1.14 修 P2 (review §校验): 加长度上下界, 防滥用 (空字符串绕过 / 超长输入).
	// rc2 修 G12: TokenID 实际是 8 字节 random → base64url ~11 字符 (见 auth.go:5),
	// 不是注释原说的 "16 字节 hex = 32 字符". 但 token 参数可能是完整 cookie
	// (<TokenID>.<Secret> 形式, ~44 字符) 所以上界 256 仍合理, 下界 8 保留.
	if len(token) < 8 || len(token) > 256 {
		return actionResp{OK: false, Error: "bad params", Detail: "token length out of range (8-256)"}
	}
	// token 是 base64url [A-Za-z0-9_-]+
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(token) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid token format"}
	}
	rc, out := runBin(hncDir, "json_set.sh", "token_revoke", token)
	if rc != 0 {
		return actionResp{OK: false, Error: "revoke failed", Detail: out}
	}
	return actionResp{OK: true}
}

func actionCleanupRules(hncDir string) actionResp {
	rc, out := runBin(hncDir, "cleanup.sh", "rules")
	if rc != 0 {
		return actionResp{OK: false, Error: "cleanup failed", Detail: out}
	}
	return actionResp{OK: true}
}

// actionCleanupOfflineDevices · rc29
// WebUI "清理离线设备" 按钮。
// params:
//
//	include_rules · "1" 时连带规则一起清(否则保留有规则的设备)
//
// 返回 Detail 透传脚本的 JSON {removed, kept_with_rules, skipped_online}
// 给前端 toast 用。
func actionCleanupOfflineDevices(hncDir string, p map[string]string) actionResp {
	args := []string{}
	if p["include_rules"] == "1" || p["include_rules"] == "true" {
		args = append(args, "--include-with-rules")
	}
	rc, out := runBin(hncDir, "cleanup_offline_devices.sh", args...)
	if rc != 0 {
		return actionResp{OK: false, Error: "cleanup_offline failed", Detail: out}
	}
	// stdout is JSON {"ok":true,"removed":N,...}. Pass it through as Detail.
	return actionResp{OK: true, Detail: strings.TrimSpace(out)}
}

func actionCleanupAll(hncDir string) actionResp {
	// v5.3.0-rc13: WebUI 的“释放所有资源”不能再执行纯 all。
	// 纯 all 会杀掉 hnc_httpd/watchdog/hotspotd，退出重进后前端仍在但后端死亡。
	// 对用户入口改成 safe_release/restart：先清 tc/iptables + 停子进程，再由
	// cleanup.sh 直接 fork service.sh 拉起后端。卸载/禁用模块仍可手动调用 cleanup.sh all。
	if err := runBinDetached(hncDir, "cleanup.sh", "safe_release"); err != nil {
		return actionResp{OK: false, Error: "spawn failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: "safe release scheduled · service will be restarted automatically"}
}

func actionRestartService(hncDir string) actionResp {
	// rc3 修 N-15: 同上, 异步跑防止自杀前响应丢失
	if err := runBinDetached(hncDir, "cleanup.sh", "restart"); err != nil {
		return actionResp{OK: false, Error: "spawn failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: "restart scheduled · 30s 内 watchdog 重启所有服务"}
}
