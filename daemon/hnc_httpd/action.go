// action.go — Patch 3.a · 远程写操作白名单分发
//
// 安全模型(v4_0_design Patch 3):
//   1. 所有写操作统一走 POST /api/action, 便于加 auth / rate limit / audit
//   2. 严格 action 白名单,不允许任意操作
//   3. 每个 action 的参数用正则校验,拒绝任何未通过的请求
//   4. 参数通过后 exec 固定 shell 命令(复用 WebUI-tested 脚本链),
//      参数作为独立 argv element 传递,不走字符串拼接
//   5. 所有尝试(成功/失败/拒绝)都写 audit.log
//
// Action 列表(3.a 初版,4 个):
//   rule_set       · 设置限速      params: mac, rate_down, rate_up
//   rule_clear     · 清除限速      params: mac
//   bl_add         · 加入黑名单    params: mac
//   bl_del         · 移出黑名单    params: mac
//
// 留给 3.b / 3.c 的未来 action:
//   template_apply, device_name_set, refresh

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ── 参数校验正则 ───────────────────────────────────────────────

// MAC 严格格式: 小写 hex, 冒号分隔
// 强制小写防止 aa:bb... 和 AA:BB... 被当两个 key 写入 rules.json
var macRE = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// Rate 格式: 数字 + 单位, 或 "0" 表示不限速
// 不允许指数/小数/kbps(历史上 tc 不支持).  最小 64kbit 防打脚
var rateRE = regexp.MustCompile(`^[0-9]+(kbit|mbit)$`)

// IP v4, 宽松一点(只校验基础格式)
var ipv4RE = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

// v4.0 Patch 3.a Gemini: 受保护的特殊 MAC
// broadcast/null MAC 永远不能被 bl_add / rule_set
var protectedSpecialMACs = map[string]bool{
	"ff:ff:ff:ff:ff:ff": true, // broadcast
	"00:00:00:00:00:00": true, // null
}

// isProtectedMAC 返回 true 表示该 MAC 受保护 (不能被 bl_add / rule_set)
// 1. 写死的特殊 MAC(broadcast/multicast/null)
// 2. 热点 iface 自己的 MAC (即主人手机网卡,被加黑=主人自己断网)
// 读 sysfs 不缓存 — iface 可能切换(patch 1.5 Defer Init 场景)
// 读失败时 fail-open(允许通过),这是业务风险权衡:宁可少保护也不能因为 sysfs 问题
// 让所有写操作瘫痪
func isProtectedMAC(hncDir, mac string) bool {
	if protectedSpecialMACs[mac] {
		return true
	}
	// 读当前热点 iface 的 MAC
	ifaceMAC := readHotspotIfaceMAC(hncDir)
	if ifaceMAC != "" && strings.EqualFold(ifaceMAC, mac) {
		return true
	}
	return false
}

// readHotspotIfaceMAC 读当前活跃热点 iface 的 MAC
// $HNC_DIR/run/hnc_state 格式是 "PENDING" 或 "ACTIVE:<iface>"
// 活跃时读 /sys/class/net/<iface>/address
// 任何一步失败返 "" (caller 会 fail-open)
func readHotspotIfaceMAC(hncDir string) string {
	stateBytes, err := os.ReadFile(filepath.Join(hncDir, "run", "hnc_state"))
	if err != nil {
		return ""
	}
	state := strings.TrimSpace(string(stateBytes))
	if !strings.HasPrefix(state, "ACTIVE:") {
		return ""
	}
	iface := strings.TrimPrefix(state, "ACTIVE:")
	// iface 必须是 [a-z0-9] 的简单格式,防 ../../path/传入
	for _, c := range iface {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return ""
		}
	}
	macBytes, err := os.ReadFile("/sys/class/net/" + iface + "/address")
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(string(macBytes)))
}

// ── 最小速率阈值(防自锁) ────────────────────────────────────

const (
	minRateKbit    = 64               // 不允许设成 < 64kbit, 防用户把自己限速到 0
	maxRateKbit    = 10 * 1024 * 1024 // 10 Gbit 上限, 防整数溢出 + tc 爆参数 (Gemini 审查建议)
	execTimeoutSec = 10               // exec shell 最长等待秒数
)

// ── action 请求/响应 struct ──────────────────────────────────

type actionReq struct {
	Action string            `json:"action"`
	Params map[string]string `json:"params"`
}

type actionResp struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// handleAction POST /api/action
// 已经被 authMiddleware 保护,这里只管参数校验 + dispatch
func (s *server) handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// rc3 修 N-6 配套: 强制 application/json
	// 防 text/plain 绕过 CORS preflight (不需要 preflight 的 simple request)
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		writeActionResp(w, http.StatusUnsupportedMediaType, actionResp{
			OK: false, Error: "content-type must be application/json",
		})
		return
	}

	// CSRF 简单防御: 要求 X-HNC-CSRF: 1 header
	// SameSite=Strict cookie 已经防了大部分 CSRF, 这里多一层
	// 跨域网页发 fetch 时默认不带自定义 header; 有自定义 header 的 POST
	// 必须经过 CORS preflight, 我们没声明 allow 所以会被浏览器拒
	if r.Header.Get("X-HNC-CSRF") != "1" {
		writeActionResp(w, http.StatusBadRequest, actionResp{
			OK: false, Error: "csrf header missing",
		})
		return
	}

	// 取 TokenID 给 audit 用(authMiddleware 放到 context 里)
	// v3.a: /api/action 已经被 authMiddleware 的 isWritePath 强制要求有 cookie,
	// tid 必定非空. 若为空属于 bug, 这里额外防御.
	// v5.1: loopback 在 authMiddleware 里已经放行(免 cookie), context 没 tid,
	// 这里用 "loopback" 作为伪 tid 给 audit, 不再挡下。
	tid := ""
	if v := r.Context().Value(ctxKeyTokenID); v != nil {
		if s, ok := v.(string); ok {
			tid = s
		}
	}
	if tid == "" {
		// rc3 修 N-6: 只有"无 Origin/Referer 的 loopback"才回退 tid=loopback,
		// 否则走正常鉴权失败路径. 防 DNS rebinding 攻击.
		if isLoopbackRequest(r) && r.Header.Get("Origin") == "" && r.Header.Get("Referer") == "" {
			tid = "loopback"
		} else {
			writeActionResp(w, http.StatusUnauthorized, actionResp{
				OK: false, Error: "auth required for write",
			})
			return
		}
	}

	// 解码 body
	// rc2 修 G7: 16KB 上限, 防止大 body 耗内存
	//          action 请求最大的是 hotspot_save (SSID/pass + 其他字段), 远 <1KB
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	var req actionReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		auditLog(s.hncDir, tid, "?", nil, "error", "bad json: "+err.Error())
		writeActionResp(w, http.StatusBadRequest, actionResp{
			OK: false, Error: "bad json",
		})
		return
	}
	if req.Params == nil {
		req.Params = map[string]string{}
	}

	// write rate limit: 用 TokenID 作 key
	// tid 此处必定非空(见上面强制校验)
	rlKey := "wr-" + tid
	if !s.checkWriteRate(rlKey) {
		auditLog(s.hncDir, tid, req.Action, nil, "error", "write rate limited")
		writeActionResp(w, http.StatusTooManyRequests, actionResp{
			OK: false, Error: "write rate limited (60/min)",
		})
		return
	}

	// hotfix4: serialize state-changing actions. The underlying shell scripts mutate
	// tc, iptables and JSON files in several steps; concurrent writes from two
	// remote clients can interleave and leave UI/API state out of sync. Keep reads
	// via /api/devices behind the same RW lock in server.go.
	waitStart := time.Now()
	s.stateMu.Lock()
	waited := time.Since(waitStart)
	if waited > 200*time.Millisecond {
		log.Printf("handleAction: queued action=%s waited=%s", req.Action, waited)
	}
	resp := func() actionResp {
		defer s.stateMu.Unlock()
		return dispatchAction(s.hncDir, req.Action, req.Params, tid == "loopback")
	}()
	if resp.OK {
		// hotfix15: a successful write usually changes rules/devices-derived UI state.
		// Trigger the snapshot loop now instead of waiting for the next tick.
		s.requestSnapshotRefresh()
	}
	result := "ok"
	if !resp.OK {
		result = "error"
	}
	// rc3 修 N-5: 敏感字段(password/secret/token/pin)脱敏后再记 audit
	// 避免 WiFi 密码明文落盘, 减少 MDLP / 云备份泄漏风险
	auditParams := redactSensitive(req.Params)
	auditLog(s.hncDir, tid, req.Action, auditParams, result, resp.Error+resp.Detail)

	status := http.StatusOK
	if !resp.OK {
		switch {
		case resp.Error == "unknown action",
			resp.Error == "bad params",
			resp.Error == "protected mac",
			isBadParamErr(resp.Error):
			status = http.StatusBadRequest
		default:
			status = http.StatusInternalServerError
		}
	}
	writeActionResp(w, status, resp)
}

// dispatchAction 按 action 白名单分发(已通过 auth + rate limit + CSRF)
func dispatchAction(hncDir, action string, p map[string]string, isLoopback bool) actionResp {
	// rc2 修 G1: loopback-only guard 合并为单 switch (rc5.1.1 只合了注释没合代码)
	switch action {
	case "pair_revoke", "auth_required_set", "remote_enabled_set":
		if !isLoopback {
			return actionResp{OK: false, Error: "forbidden", Detail: "this action is loopback-only (use the on-device KSU WebUI)"}
		}
	}

	switch action {
	case "rule_set":
		return actionRuleSet(hncDir, p)
	case "rule_clear":
		return actionRuleClear(hncDir, p)
	case "bl_add":
		return actionBLAdd(hncDir, p)
	case "bl_del":
		return actionBLDel(hncDir, p)
	// v5.0 新增 action (B 路线 · 取代前端 kexec shell 的 13 个 backend)
	case "delay_set":
		return actionDelaySet(hncDir, p)
	case "delay_clear":
		return actionDelayClear(hncDir, p)
	case "rule_sqm": // rc20: per-device low-latency (smart queue) toggle
		return actionDeviceSQMSet(hncDir, p)
	case "template_apply":
		return actionTemplateApply(hncDir, p)
	case "hotspot_start":
		return actionHotspotStart(hncDir)
	case "hotspot_stop":
		return actionHotspotStop(hncDir)
	case "hotspot_save":
		return actionHotspotSave(hncDir, p)
	case "whitelist_set":
		return actionWhitelistSet(hncDir, p)
	case "auth_required_set":
		return actionAuthRequiredSet(hncDir, p)
	case "remote_enabled_set":
		return actionRemoteEnabledSet(hncDir, p)
	case "hotspot_iface_set":
		return actionHotspotIfaceSet(hncDir, p)
	case "sqm_set":
		return actionSQMSet(hncDir, p)
	case "refresh":
		return actionRefresh(hncDir)
	case "pair_new":
		return actionPairNew(hncDir)
	case "pair_revoke":
		return actionPairRevoke(hncDir, p)
	case "cleanup_rules":
		return actionCleanupRules(hncDir)
	case "cleanup_all":
		return actionCleanupAll(hncDir)
	case "cleanup_offline_devices":
		return actionCleanupOfflineDevices(hncDir, p)
	case "restart_service":
		return actionRestartService(hncDir)
	case "dpi_rebind":
		return actionDPIRebind(hncDir, p)
	case "device_rename":
		return actionDeviceRename(hncDir, p)
	case "alert_mark_seen":
		return actionAlertMarkSeen(hncDir, p)
	case "alert_mark_known":
		return actionAlertMarkKnown(hncDir, p)
	case "alert_dismiss_all":
		return actionAlertDismissAll(hncDir, p)
	case "app_limit_set":
		return actionAppLimitSet(hncDir, p)
	case "app_limit_clear":
		return actionAppLimitClear(hncDir, p)
	// v5.7.0-rc2: candidate approval (走法2). promote → user-approved apex
	// list dpid force-promotes; reject → shared-infra blocklist.
	case "candidate_promote":
		return actionCandidatePromote(hncDir, p)
	case "candidate_reject":
		return actionCandidateReject(hncDir, p)
	default:
		return actionResp{OK: false, Error: "unknown action"}
	}
}

// ── action 实现 ───────────────────────────────────────────────

// readUplinkCapability returns (supported, known). Unknown keeps legacy best-effort behavior.
func readUplinkCapability(hncDir string) (bool, bool) {
	return readCapabilityBool(hncDir, "uplink_supported")
}

func numberStringPositive(s string) bool {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return err == nil && v > 0
}

func rateStringPositive(r string) bool {
	r = strings.TrimSpace(strings.ToLower(r))
	if r == "" || r == "0" {
		return false
	}
	for _, suf := range []string{"kbit", "mbit"} {
		if strings.HasSuffix(r, suf) {
			n, err := strconv.Atoi(strings.TrimSuffix(r, suf))
			return err == nil && n > 0
		}
	}
	return numberStringPositive(r)
}

// actionRuleSet · 设置限速
// params: mac(必需), rate_down(可选, 如"10mbit"/"5120kbit"), rate_up(可选)
// 行为: exec apply_device_rule.sh limit, 一次完成 iptables mark + tc set_limit + rules.json 更新
//
// v4.0 Patch 3.b.1 hotfix: 之前(3.a/3.b)只写 rules.json 没调 tc/iptables,
// 错误假设 watchdog 60s 内会 sync. 实际 watchdog check_health 不读 rules.json,
// 只验证 HTB qdisc + iptables 链存在,不应用具体限速规则. 真机症状:Toast 显示
// "限速已设置" 但实际网速没变. 修法:封装 apply_device_rule.sh 完成完整链路.
func actionRuleSet(hncDir string, p map[string]string) actionResp {
	mac := p["mac"]
	if !macRE.MatchString(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	if isProtectedMAC(hncDir, mac) {
		return actionResp{OK: false, Error: "protected mac",
			Detail: "cannot modify host/broadcast/null mac"}
	}
	rateDown := p["rate_down"]
	rateUp := p["rate_up"]
	if rateDown == "" && rateUp == "" {
		return actionResp{OK: false, Error: "bad params", Detail: "at least one of rate_down/rate_up required"}
	}
	if rateDown != "" {
		if err := validateRate(rateDown); err != nil {
			return actionResp{OK: false, Error: "bad params", Detail: "rate_down: " + err.Error()}
		}
	}
	if rateUp != "" {
		if err := validateRate(rateUp); err != nil {
			return actionResp{OK: false, Error: "bad params", Detail: "rate_up: " + err.Error()}
		}
	}

	// 转 "10mbit" / "5120kbit" → mbps 字符串传给 shell (v5.1 P2-8 修: 精度保留)
	// 没填的方向 = "0" (不限速)
	dnMbps, err := rateToMbpsStr(rateDown)
	if err != nil {
		return actionResp{OK: false, Error: "bad params", Detail: "rate_down: " + err.Error()}
	}
	upMbps, err := rateToMbpsStr(rateUp)
	if err != nil {
		return actionResp{OK: false, Error: "bad params", Detail: "rate_up: " + err.Error()}
	}

	// hotfix16.9: capabilities.json is authoritative for unsupported HTB too.
	// Do not call shell/tc paths that would block/timeout on ROMs where HTB probing failed.
	if supported, known := tcHTBSupported(hncDir); known && !supported && (numberStringPositive(dnMbps) || numberStringPositive(upMbps)) {
		return actionResp{OK: false, Error: "unsupported", Detail: "tc_htb=false; current kernel/TC does not support HTB downlink shaping"}
	}

	// hotfix16.5: capabilities.json is authoritative for unsupported uplink.
	// Do not call shell paths that would try IFB/mirred and block/timeout on MIUI14.
	if supported, known := readUplinkCapability(hncDir); known && !supported && numberStringPositive(upMbps) {
		upMbps = "0"
		if !numberStringPositive(dnMbps) {
			return actionResp{OK: true, Detail: "uplink unsupported on this ROM; no downlink rate requested, skipped"}
		}
		log.Printf("rule_set: uplink unsupported; applying downlink-only mac=%s down=%s", mac, dnMbps)
	}

	// 一次 exec 完成完整链路 · 传字符串(整数或小数)
	rc, out := runBin(hncDir, "apply_device_rule.sh", "limit", mac, dnMbps, upMbps)
	detail := strings.TrimSpace(out)
	if rc != 0 {
		return actionResp{OK: false, Error: "apply failed", Detail: detail}
	}
	if strings.Contains(detail, "partial_tc_fail=uplink") || strings.Contains(detail, "limit_apply_mode=down_only") {
		return actionResp{OK: true, Detail: "download limit applied; uplink unsupported/disabled on this ROM, kept up=0"}
	}
	if supported, known := readUplinkCapability(hncDir); known && !supported && rateStringPositive(p["rate_up"]) {
		return actionResp{OK: true, Detail: "download limit applied; uplink unsupported on this ROM, kept up=0"}
	}
	return actionResp{OK: true, Detail: "limit applied"}
}

// actionRuleClear · 清除限速
// params: mac
func actionRuleClear(hncDir string, p map[string]string) actionResp {
	mac := p["mac"]
	if !macRE.MatchString(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	rc, out := runBin(hncDir, "apply_device_rule.sh", "clear", mac)
	if rc != 0 {
		return actionResp{OK: false, Error: "apply failed", Detail: strings.TrimSpace(out)}
	}
	return actionResp{OK: true, Detail: "limit cleared"}
}

// rateToKbit · 把 "10mbit" / "5120kbit" 标准化成 kbit 整数字符串传给 shell.
// v5.1 P2-8 修: 之前 rateToMbps 向上取整把 500kbit 取成 1 mbps, 丢精度.
// shell 侧 apply_device_rule.sh 期望 mbps 数值, 但 tc_manager.sh:mbps_to_rate
// 会 tr -d 'kK' 把 "500k" 当 500kbit 处理, 所以我们传 "500k" 字符串 shell 也认.
func rateToKbit(r string) (string, error) {
	if r == "" || r == "0" {
		return "0", nil
	}
	for i, c := range r {
		if c < '0' || c > '9' {
			n, err := strconv.Atoi(r[:i])
			if err != nil {
				return "", err
			}
			unit := r[i:]
			switch unit {
			case "mbit":
				// mbit * 1000 = kbit
				return strconv.Itoa(n*1000) + "k", nil
			case "kbit":
				return strconv.Itoa(n) + "k", nil
			default:
				return "", fmt.Errorf("unknown unit: %s", unit)
			}
		}
	}
	return "", fmt.Errorf("no unit in %q", r)
}

// rateToMbpsStr · v5.1 P2-8: 保留小数精度把速率转 mbps 字符串.
//
//	"500kbit"  → "0.5"
//	"5120kbit" → "5.12"
//	"10mbit"   → "10"
//	"" 或 "0"  → "0"
//
// shell 侧 mbps_to_rate 用 awk 浮点能接 "0.5" → 500kbit, 精度无损.
// 前端 rules.json.down_mbps 也保持小数 (0.5 mbps), 读取时 Number() 直接用.
func rateToMbpsStr(r string) (string, error) {
	if r == "" || r == "0" {
		return "0", nil
	}
	for i, c := range r {
		if c < '0' || c > '9' {
			nStr := r[:i]
			unit := r[i:]
			switch unit {
			case "mbit":
				return nStr, nil
			case "kbit":
				n, err := strconv.Atoi(nStr)
				if err != nil {
					return "", err
				}
				// kbit → mbps: n / 1000, 保留 3 位小数
				if n == 0 {
					return "0", nil
				}
				if n%1000 == 0 {
					return strconv.Itoa(n / 1000), nil
				}
				// 小数: 避免 float 科学计数, 手工拼
				integer := n / 1000
				frac := n % 1000
				// 去末尾 0: 500 → 5, 250 → 25, 100 → 1
				fracStr := fmt.Sprintf("%03d", frac)
				// trim trailing zeros
				for len(fracStr) > 1 && fracStr[len(fracStr)-1] == '0' {
					fracStr = fracStr[:len(fracStr)-1]
				}
				return strconv.Itoa(integer) + "." + fracStr, nil
			default:
				return "", fmt.Errorf("unknown unit: %s", unit)
			}
		}
	}
	return "", fmt.Errorf("no unit in %q", r)
}

// rateToMbps 转 "10mbit" / "5120kbit" / "0" / "" → mbps 整数
// 空字符串 → 0 (不限速)
// 不足 1 mbps 的速率向上取整(64kbit 也等于 1 mbps)
// validateRate 已经卡了格式 + 边界,这里只做单位转换
// v5.1: 保留为 legacy, 新路径用 rateToKbit 保留精度
func rateToMbps(r string) (int, error) {
	if r == "" || r == "0" {
		return 0, nil
	}
	// 已知格式: ^[0-9]+(kbit|mbit)$
	for i, c := range r {
		if c < '0' || c > '9' {
			n, err := strconv.Atoi(r[:i])
			if err != nil {
				return 0, err
			}
			unit := r[i:]
			switch unit {
			case "mbit":
				if n < 1 {
					return 1, nil
				}
				return n, nil
			case "kbit":
				// 向上取整: 64kbit → 1mbps, 5120kbit → 5mbps, 1023kbit → 1mbps
				m := (n + 1023) / 1024
				if m < 1 {
					m = 1
				}
				return m, nil
			default:
				return 0, fmt.Errorf("unknown unit: %s", unit)
			}
		}
	}
	return 0, fmt.Errorf("missing unit in rate: %q", r)
}

// actionBLAdd · 加入黑名单
// params: mac
// v4.0 Patch 3.b.1 hotfix: 之前只写 rules.json,iptables drop 规则没挂,设备其实没断网.
// 走 apply_device_rule.sh bl_add 完成 iptables blacklist_add + json 维护.
func actionBLAdd(hncDir string, p map[string]string) actionResp {
	mac := p["mac"]
	if !macRE.MatchString(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	if isProtectedMAC(hncDir, mac) {
		return actionResp{OK: false, Error: "protected mac",
			Detail: "cannot blacklist host/broadcast/null mac"}
	}
	rc, out := runBin(hncDir, "apply_device_rule.sh", "bl_add", mac)
	if rc != 0 {
		return actionResp{OK: false, Error: "apply failed", Detail: strings.TrimSpace(out)}
	}
	return actionResp{OK: true, Detail: "blacklisted"}
}

// actionBLDel · 移出黑名单
// params: mac
func actionBLDel(hncDir string, p map[string]string) actionResp {
	mac := p["mac"]
	if !macRE.MatchString(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	rc, out := runBin(hncDir, "apply_device_rule.sh", "bl_del", mac)
	if rc != 0 {
		return actionResp{OK: false, Error: "apply failed", Detail: strings.TrimSpace(out)}
	}
	return actionResp{OK: true, Detail: "removed from blacklist"}
}

// ── helper ─────────────────────────────────────────────────────

// validateRate 校验速率格式 + 最小值
// "0" 视为不限速(允许), 其它必须 >= 64kbit
func validateRate(r string) error {
	if r == "0" {
		return nil
	}
	if !rateRE.MatchString(r) {
		return fmt.Errorf("format must be <n>kbit or <n>mbit")
	}
	// 提取数字部分算 kbit
	var num int
	var unit string
	for i, c := range r {
		if c < '0' || c > '9' {
			n, err := strconv.Atoi(r[:i])
			if err != nil {
				return fmt.Errorf("bad number")
			}
			num = n
			unit = r[i:]
			break
		}
	}
	var kbit int
	switch unit {
	case "kbit":
		kbit = num
	case "mbit":
		// rc2 修 G4: 1000 不是 1024. tc k/m 后缀是十进制 (iproute2 约定),
		//          且本文件 line 382 的 mbit→k 转换也是 *1000, 统一.
		kbit = num * 1000
	default:
		return fmt.Errorf("unit must be kbit or mbit")
	}
	if kbit < minRateKbit {
		return fmt.Errorf("minimum rate is %dkbit", minRateKbit)
	}
	// v4.0 Patch 3.a Gemini: 防 integer overflow / tc 参数爆
	if kbit > maxRateKbit {
		return fmt.Errorf("maximum rate is %dkbit (~10 Gbit)", maxRateKbit)
	}
	return nil
}

// runExe execs a binary helper directly from <hncDir>/bin/<name>.
// Do not route ELF helpers through "sh"; Android will report syntax/ELF errors
// and callers may silently lose important side effects such as offload notify.
func runExe(hncDir, name string, args ...string) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := filepath.Join(hncDir, "bin", name)
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{
		"HNC_DIR=" + hncDir,
		"HNC=" + hncDir,
		"PATH=/system/bin:/system/xbin:/vendor/bin:/usr/bin:/bin",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), string(out)
		}
		if ctx.Err() == context.DeadlineExceeded {
			return 124, "timeout after 5s"
		}
		return -1, err.Error() + "\n" + string(out)
	}
	return 0, string(out)
}

// runBin exec "sh <hncDir>/bin/<script>" with args, 返回 (rc, combined_output)
// 绝对不做 shell 字符串拼接, args 直接作为 argv 传入
func runBin(hncDir, script string, args ...string) (int, string) {
	// rc3 修 N-7: 按 script 分级超时. cleanup / hotspot 整条链耗时 30s+,
	// 默认 10s 会在高负载下误杀 (比如并发 apply 多台设备时)
	timeoutSec := execTimeoutSec
	switch script {
	case "cleanup.sh":
		timeoutSec = 60
	case "hotspot_autostart.sh":
		timeoutSec = 30
	case "dpi_rebind.sh":
		timeoutSec = 30
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()
	cmdArgs := append([]string{hncDir + "/bin/" + script}, args...)
	cmd := exec.CommandContext(ctx, "sh", cmdArgs...)
	cmd.Env = []string{
		"HNC_DIR=" + hncDir,
		"HNC=" + hncDir, // rc3: json_set.sh / 其他脚本用 $HNC 不是 $HNC_DIR
		"PATH=/system/bin:/system/xbin:/vendor/bin:/usr/bin:/bin",
	}
	out, err := cmd.CombinedOutput()
	rc := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			return 124, "timeout after " + strconv.Itoa(timeoutSec) + "s"
		} else {
			rc = -1
		}
	}
	s := string(out)
	// rc3.1.14 修 P3 (review): 1024 字节硬切可能切坏多字节 UTF-8 (中文 3B/字),
	// 前端 JSON.parse 撞到无效 UTF-8 序列直接报 "JSON parse error", 用户看不到本应的
	// 中文错误信息. 改成往左退到合法 RuneStart.
	if len(s) > 1024 {
		cut := 1024
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		// rc2 修 G6: cut==0 极端 fallback (病态输入前 1024 全是 continuation bytes,
		// 实际上几乎不可能发生, 但 let's be defensive). 原代码 s[:0]+"..." = "...",
		// 用户看到纯 "...", 诊断价值为零. 改用 ToValidUTF8 把无效序列替换成 U+FFFD
		// 后硬切 1024, 至少保留可读前缀.
		if cut == 0 {
			s = strings.ToValidUTF8(s[:1024], "\uFFFD") + "..."
		} else {
			s = s[:cut] + "..."
		}
	}
	return rc, s
}

// actionDPIRebind · v5.3.0-rc17
// Manually restart the passive DPI guard/capture path.  This is intentionally
// low-risk: hnc_dpid is observe-only and does not touch tc/iptables.
func actionDPIRebind(hncDir string, p map[string]string) actionResp {
	iface := strings.TrimSpace(p["iface"])
	args := []string{}
	if iface != "" {
		if !regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,32}$`).MatchString(iface) {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid iface"}
		}
		args = append(args, iface)
	}
	rc, out := runBin(hncDir, "dpi_rebind.sh", args...)
	if rc != 0 {
		return actionResp{OK: false, Error: "dpi rebind failed", Detail: strings.TrimSpace(out)}
	}
	return actionResp{OK: true, Detail: strings.TrimSpace(out)}
}

// writeActionResp 响应 JSON
func writeActionResp(w http.ResponseWriter, status int, r actionResp) {
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(r)
}

func isBadParamErr(msg string) bool {
	return msg == "bad params" || msg == "invalid mac" || msg == "invalid rate"
}

// rc3 N-5: 敏感字段白名单. 记 audit log 前对 key 匹配的 value 替换成 <redacted>.
// 覆盖: password / pass / secret / token / pin.
// key 比较大小写不敏感.
var sensitiveKeys = map[string]bool{
	"password": true, "pass": true,
	"secret": true, "token": true,
	"pin": true,
}

func redactSensitive(p map[string]string) map[string]string {
	if len(p) == 0 {
		return p
	}
	out := make(map[string]string, len(p))
	for k, v := range p {
		if sensitiveKeys[strings.ToLower(k)] && v != "" {
			out[k] = "<redacted>"
		} else {
			out[k] = v
		}
	}
	return out
}

// runBinDetached · rc3 N-15: fork shell 脚本到后台, Go 立即返回.
// 用于会 kill httpd 自己的场景 (cleanup all/restart). nohup + setsid 让子进程
// 脱离父进程 session, httpd 被 kill 时子进程还活着继续跑完.
func runBinDetached(hncDir, script string, args ...string) error {
	cmdArgs := append([]string{hncDir + "/bin/" + script}, args...)
	cmd := exec.Command("sh", cmdArgs...)
	cmd.Env = []string{
		"HNC_DIR=" + hncDir,
		"HNC=" + hncDir, // rc3: json_set.sh 等脚本读 $HNC
		"PATH=/system/bin:/system/xbin:/vendor/bin:/usr/bin:/bin",
	}
	// 重定向 stdout/stderr 到 cleanup.log · 脱离 httpd
	logPath := hncDir + "/logs/cleanup_async.log"
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		cmd.Stdout = f
		cmd.Stderr = f
		defer f.Close()
	}
	// SysProcAttr.Setsid 让子进程成新 session leader, httpd kill 不影响它
	cmd.SysProcAttr = detachedSysProcAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	// 不等, 让子进程继续
	// rc2 修 G9: goroutine 里 cmd.Wait() 返回的 error 被丢弃没问题, 但如果 Wait 本身
	// panic (已知的 Go runtime race — Windows 不会, Linux 罕见但可能在 exec.Cmd 内部
	// state 被并发访问时 panic), 会杀掉整个 httpd 进程. 加 defer recover 隔离.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("runBinDetached: cmd.Wait panicked: %v", r)
			}
		}()
		_ = cmd.Wait()
	}()
	return nil
}
