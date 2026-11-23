// mac_merge_action.go — v5.21 设备合并(随机 MAC 换了之后, 把旧 MAC 的一切搬到新 MAC)
//
//	device_merge          {from_mac, to_mac, force?}   from = 旧 MAC, to = 新 MAC
//	device_merge_dismiss  {from_mac, to_mac}           不再建议这一对
//
// 迁移的按 MAC 存储(全部):
//
//	rules.json 设备规则      限速 / 延迟 / 低延迟(sqm) / 白名单 / 黑名单 —— 经正常动作路径
//	                         (rule_set / delay_set / rule_sqm / device_whitelist_set / bl_add
//	                         → apply_device_rule.sh / tc_manager.sh / iptables_manager.sh /
//	                         whitelist_sync.sh), 所以 tc / iptables 跟着走; 旧 MAC 用
//	                         rule_clear / delay_clear / bl_del … 拆掉, 最后 json_set.sh
//	                         device_remove 删掉旧条目(释放 mark_id)
//	data/device_names.json   手动名称
//	data/device_ident_override.json  设备识别手动纠正
//	data/app_limits.json(+.flat)     按应用限速(之后触发 apply_app_limits.sh)
//	data/app_controls.json   应用时长上限 / 类别封锁
//	data/conn_blocks.json    连接/域名封锁(之后 connblock_sync.sh 重新同步)
//	data/limit_policies.json 流量配额 / 分时段限速(控制器内存 + 文件)
//	data/limit_ctl_state.json 控制器状态: 旧 MAC 的今日/本周期已用量并入新 MAC
//	data/known_devices.json  旧 MAC 已被标记"认识" → 新 MAC 也标记(不再报陌生设备)
//	data/mac_merge_suggestions.json  画像并入新 MAC, 相关建议清掉
//	data/mac_aliases.json    写 old→new, 历史用量读路径据此把旧 MAC 的历史算到新 MAC 上
//
// 原子性(尽力而为): 阶段一先写所有"新 MAC"状态(旧的保留), 最后写别名表 = 提交点;
// 阶段一任何一步失败 → 逆序回滚已做的步骤(文件恢复快照, 规则用反向动作撤销),
// 旧 MAC 状态从未动过。提交后阶段二再逐项拆掉旧 MAC 的状态; 这一阶段的失败只记
// 警告(新 MAC 已完整生效, 旧 MAC 残留的规则无害, 可在设备卡上手动清)。
//
// 冲突: to_mac 已有与旧 MAC 不同的同类设置(限速值不同、延迟不同、名称不同、识别
// 纠正不同、配额/时段不同、同一应用的限速/时长上限不同)时拒绝(error=conflict,
// HTTP 409), 除非 force=true。force 时【以旧 MAC 的设置为准】—— 那是用户花时间
// 配出来的; 旧 MAC 没设置的项保留新 MAC 自己的(集合类如封锁项、类别封锁取并集)。
// 黑名单/白名单/低延迟这类开关只会"加", 不构成冲突。
//
// 拒绝: 任一方是模拟设备(02:5e:00)、两者相同、MAC 非法、受保护 MAC(本机热点
// 网卡/广播); 旧 MAC 有限速/延迟/低延迟而新 MAC 不在线(这些下发需要在线 IP)。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hnc.io/dpid/alert"
)

const (
	macMergeAuditTID        = "macmerge"
	macMergeArchivesRelPath = "data/mac_merge_archives.json"
	macMergeArchiveMax      = 64
	macMergeArchiveTTL      = int64(90 * 86400)
)

// macArchiveMu 串行化 mac_merge_archives.json 的读改写。
var macArchiveMu sync.Mutex

// mergeOps 把"系统副作用"抽出来(规则动作 / 离线规则写回 / 同步脚本), 测试注入假的实现。
type mergeOps interface {
	// rule 走正常动作路径: rule_set / rule_clear / bl_add / bl_del / delay_set /
	// delay_clear / rule_sqm / device_whitelist_set / rules_device_remove
	rule(action string, p map[string]string) actionResp
	// persistOfflineRule 当目标设备离线无 IP 时, 直接经 rulesStore 将完整规则状态写回 rules.json
	persistOfflineRule(mac string, r ruleState) error
	// syncConnBlocks 重新展开 conn_blocks(含 app_controls 派生项)并跑同步脚本; 调用方持 connBlockMu
	syncConnBlocks() error
	// syncAppLimits 让 apply_app_limits.sh 按新 app_limits 重新下发
	syncAppLimits()
}

type realMergeOps struct{ s *server }

func (o realMergeOps) rule(action string, p map[string]string) actionResp {
	h := o.s.hncDir
	var r actionResp
	switch action {
	case "rule_set":
		r = actionRuleSet(h, p)
	case "rule_clear":
		r = actionRuleClear(h, p)
	case "bl_add":
		r = actionBLAdd(h, p)
	case "bl_del":
		r = actionBLDel(h, p)
	case "delay_set":
		r = actionDelaySet(h, p)
	case "delay_clear":
		r = actionDelayClear(h, p)
	case "rule_sqm":
		r = actionDeviceSQMSet(h, p)
	case "device_whitelist_set":
		r = actionDeviceWhitelistSet(h, p)
	case "app_qos_set":
		r = actionAppQosSet(h, p)
	case "rules_device_remove":
		rc, out := runBin(h, "json_set.sh", "device_remove", p["mac"])
		r = actionResp{OK: rc == 0, Detail: strings.TrimSpace(out)}
		if rc != 0 {
			r.Error = "write failed"
		}
	default:
		r = actionResp{OK: false, Error: "unknown action"}
	}
	auditLog(h, macMergeAuditTID, action, p, map[bool]string{true: "ok", false: "error"}[r.OK], r.Error+" "+r.Detail)
	return r
}

func (o realMergeOps) persistOfflineRule(mac string, r ruleState) error {
	h := o.s.hncDir
	if err := rulesStore.SetBlacklist(h, mac, r.bl); err != nil {
		return err
	}
	hasDevRule := r.exists || r.limit || r.delay || r.sqm || r.wl || r.appQos
	if !hasDevRule {
		_ = rulesStore.SetWhitelist(h, mac, false)
		return rulesStore.RemoveDevice(h, mac)
	}
	dnMbps, upMbps := "0", "0"
	if r.limit {
		if r.down > 0 {
			if s, err := rateToMbpsStr(kbitRateStr(r.down)); err == nil {
				dnMbps = s
			}
		}
		if r.up > 0 {
			if s, err := rateToMbpsStr(kbitRateStr(r.up)); err == nil {
				upMbps = s
			}
		}
	}
	if _, err := rulesStore.UpdateDeviceLimit(h, mac, "", dnMbps, upMbps, r.limit); err != nil {
		return err
	}
	if err := rulesStore.SetWhitelist(h, mac, r.wl); err != nil {
		return err
	}
	if r.appQos {
		if _, err := rulesStore.SetDeviceAppQoS(h, mac, true); err != nil {
			return err
		}
	} else if r.delay || r.sqm {
		_, _ = rulesStore.AllocMarkID(h, mac)
	}
	lossPct := 0.0
	if r.loss != "" {
		lossPct, _ = strconv.ParseFloat(r.loss, 64)
	}
	batch := map[string]interface{}{
		"delay_enabled": r.delay,
		"delay_ms":      r.delayMs,
		"jitter_ms":     r.jitterMs,
		"loss_pct":      lossPct,
		"sqm_enabled":   r.sqm,
		"app_qos":       r.appQos,
	}
	if err := rulesStore.SetDeviceBatch(h, mac, batch); err != nil {
		return err
	}
	if r.appQos {
		_ = os.WriteFile(filepath.Join(h, "run", "app_limit.dirty"), []byte("1\n"), 0o644)
	}
	auditLog(h, macMergeAuditTID, "persist_offline_rule", map[string]string{"mac": mac}, "ok", "")
	return nil
}

func (o realMergeOps) syncConnBlocks() error {
	out, err := o.s.connBlockSyncLocked(true)
	if err != nil {
		return fmt.Errorf("connblock_sync: %s", out)
	}
	return nil
}

func (o realMergeOps) syncAppLimits() { go triggerAppLimitApply(o.s.hncDir) }

// macMergeOpsFor / macMergeFailStep: 测试钩子(注入假副作用 / 在某一步注入失败)
var macMergeOpsFor = func(s *server) mergeOps { return realMergeOps{s} }
var macMergeFailStep string

// ─── rules.json 视图 ────────────────────────────────────────────────────

type ruleState struct {
	exists   bool
	limit    bool // limit_enabled 且有正速率
	down, up int  // kbit
	delay    bool
	delayMs  int
	jitterMs int
	loss     string
	sqm      bool
	wl       bool
	bl       bool
	appQos   bool // v5.32 T1: 按应用分优先级(此前合并会丢)
}

func (r ruleState) delayEq(o ruleState) bool {
	return r.delayMs == o.delayMs && r.jitterMs == o.jitterMs && r.loss == o.loss
}

func truthy(v interface{}) bool {
	b, ok := v.(bool)
	return (ok && b) || asString(v) == "true"
}

func readRuleStates(hncDir string) (map[string]ruleState, error) {
	b, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]ruleState{}, nil
		}
		return nil, err
	}
	var root map[string]interface{}
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("rules.json malformed: %v", err)
	}
	out := map[string]ruleState{}
	devs, _ := root["devices"].(map[string]interface{})
	for mac, raw := range devs {
		d, _ := raw.(map[string]interface{})
		if d == nil {
			continue
		}
		r := ruleState{exists: true}
		if truthy(d["limit_enabled"]) {
			r.down, r.up = mbpsToKbit(numOf(d["down_mbps"])), mbpsToKbit(numOf(d["up_mbps"]))
			r.limit = r.down > 0 || r.up > 0
		}
		r.delayMs, r.jitterMs = int(numOf(d["delay_ms"])), int(numOf(d["jitter_ms"]))
		loss := numOf(d["loss_pct"])
		r.loss = strconv.FormatFloat(loss, 'f', -1, 64)
		r.delay = truthy(d["delay_enabled"]) || r.delayMs > 0 || r.jitterMs > 0 || loss > 0
		if !r.delay {
			r.delayMs, r.jitterMs, r.loss = 0, 0, "0"
		}
		r.sqm, r.wl = truthy(d["sqm_enabled"]), truthy(d["whitelist"])
		r.appQos = truthy(d["app_qos"])
		out[strings.ToLower(mac)] = r
	}
	bl, _ := root["blacklist"].([]interface{})
	for _, v := range bl {
		m := strings.ToLower(strings.TrimSpace(asString(v)))
		if m == "" {
			continue
		}
		r := out[m]
		r.bl = true
		out[m] = r
	}
	return out, nil
}

// ctlBase 配额/时段控制器记录的"手动基线"(控制器可能正施加着节流/封锁, rules.json
// 里看到的是覆盖后的值; 搬家要搬的是用户手动设的那份)。没有采纳过则 ok=false。
func (s *server) ctlBase(mac string) (limitRule, bool) {
	c := s.limitCtl
	if c == nil {
		return limitRule{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.st.Devices[mac]
	if st == nil || !st.Adopted {
		return limitRule{}, false
	}
	return st.Base, true
}

func withBase(r ruleState, b limitRule) ruleState {
	r.down, r.up, r.bl = b.DownKbit, b.UpKbit, b.Blocked
	r.limit = r.down > 0 || r.up > 0
	return r
}

// ─── 事务 ──────────────────────────────────────────────────────────────

type fileSnap struct {
	path    string
	data    []byte
	existed bool
}

func snapFile(path string) fileSnap {
	b, err := os.ReadFile(path)
	return fileSnap{path: path, data: b, existed: err == nil}
}

func (f fileSnap) restore() error {
	if !f.existed {
		if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return discoverWriteAtomic(f.path, f.data)
}

type mergeStep struct {
	name string
	do   func() error
	undo func() // 只撤销本步已经做了的部分; 可在 do 失败后调用
}

type mergeResult struct {
	Migrated  []string
	Warnings  []string
	Conflicts []string
}

type mergeErr struct {
	code   string // actionResp.Error
	detail string
}

func (e *mergeErr) Error() string { return e.code + ": " + e.detail }

// ─── 动作入口 ──────────────────────────────────────────────────────────

func actionDeviceMerge(s *server, p map[string]string) actionResp {
	from, to := normalizeMAC(p["from_mac"]), normalizeMAC(p["to_mac"])
	if from == "" || to == "" {
		return actionResp{OK: false, Error: "bad params", Detail: "from_mac / to_mac 必须是 aa:bb:cc:dd:ee:ff"}
	}
	if from == to {
		return actionResp{OK: false, Error: "bad params", Detail: "from_mac 与 to_mac 相同"}
	}
	if isSimMACPrefix(from) || isSimMACPrefix(to) {
		return actionResp{OK: false, Error: "bad params", Detail: "模拟设备(02:5e:00)不能参与合并"}
	}
	if isProtectedMAC(s.hncDir, from) || isProtectedMAC(s.hncDir, to) {
		return actionResp{OK: false, Error: "protected mac", Detail: "cannot merge host/broadcast/null mac"}
	}
	force := false
	switch strings.ToLower(strings.TrimSpace(p["force"])) {
	case "", "false", "0":
	case "true", "1":
		force = true
	default:
		return actionResp{OK: false, Error: "bad params", Detail: "force must be true/false"}
	}
	res, err := s.deviceMerge(from, to, force, time.Now())
	if err != nil {
		var me *mergeErr
		if errors.As(err, &me) {
			return actionResp{OK: false, Error: me.code, Detail: me.detail}
		}
		return actionResp{OK: false, Error: "merge failed", Detail: err.Error()}
	}
	detail := "已合并 " + from + " → " + to + "; 迁移: " + strings.Join(res.Migrated, ",")
	if len(res.Warnings) > 0 {
		detail += "; 旧 MAC 清理未完成: " + strings.Join(res.Warnings, " | ")
	}
	return actionResp{OK: true, Detail: detail}
}

func actionDeviceMergeDismiss(s *server, p map[string]string) actionResp {
	from, to := normalizeMAC(p["from_mac"]), normalizeMAC(p["to_mac"])
	if from == "" || to == "" || from == to {
		return actionResp{OK: false, Error: "bad params", Detail: "from_mac / to_mac 非法"}
	}
	macMergeMu.Lock()
	defer macMergeMu.Unlock()
	f := loadMacMergeFile(s.hncDir)
	f.Dismissed[macMergeDismissKey(to, from)] = time.Now().Unix()
	if cs, ok := f.Suggestions[to]; ok {
		kept := cs[:0]
		for _, c := range cs {
			if c.OldMAC != from {
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			delete(f.Suggestions, to)
		} else {
			f.Suggestions[to] = kept
		}
	}
	if err := saveMacMergeFile(s.hncDir, f); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: "不再建议 " + from + " → " + to}
}

// deviceMerge 调用方持 s.actionMu(经 dispatchAction)。
func (s *server) deviceMerge(from, to string, force bool, now time.Time) (*mergeResult, error) {
	h := s.hncDir
	ops := macMergeOpsFor(s)
	res := &mergeResult{}

	// ── 读取双方现状 ──
	rs, err := readRuleStates(h)
	if err != nil {
		return nil, &mergeErr{"read failed", err.Error()}
	}
	oldObs, newObs := rs[from], rs[to]
	oldWant, newBase := oldObs, newObs
	if b, ok := s.ctlBase(from); ok {
		oldWant = withBase(oldObs, b)
	}
	if b, ok := s.ctlBase(to); ok {
		newBase = withBase(newObs, b)
	}
	namesPath := filepath.Join(h, deviceNamesRelPath)
	names, err := loadDeviceNames(namesPath)
	if err != nil {
		return nil, &mergeErr{"read failed", err.Error()}
	}
	idents := readIdentOverrides(h)
	var oldPol, newPol *devicePolicy
	if c := s.limitCtl; c != nil {
		c.mu.Lock()
		if p := c.policies[from]; p != nil {
			cp := clonePolicy(p)
			oldPol = cp
		}
		if p := c.policies[to]; p != nil {
			newPol = clonePolicy(p)
		}
		c.mu.Unlock()
	}
	appLim := loadAppLimits(h)
	appCtl := loadAppControls(h)

	// ── 冲突检查 ──
	var conflicts []string
	macMergeMu.Lock()
	mfPre := loadMacMergeFile(h)
	apartLocked := isMacMutexApart(mfPre, from, to, now.Unix())
	macMergeMu.Unlock()
	if apartLocked {
		conflicts = append(conflicts, "双端曾同时在线产生真实流量(互斥锁保护中)")
	}
	if oldWant.limit && newBase.limit && (oldWant.down != newBase.down || oldWant.up != newBase.up) {
		conflicts = append(conflicts, "限速")
	}
	if oldWant.delay && newBase.delay && !oldWant.delayEq(newBase) {
		conflicts = append(conflicts, "延迟")
	}
	// v5.32 审查修复: 按应用分优先级与延迟模拟互斥(都占设备的下行叶子队列; app_qos_set /
	// delay_set 在另一项开着时都拒绝)。旧设备开着一项、新 MAC 开着另一项, 照搬过去会被
	// 动作拒绝、整个合并回滚 —— 先报冲突; force 时以旧设备为准, 先关掉新 MAC 那一项。
	qosOffNew := oldWant.delay && !oldWant.appQos && newObs.appQos
	delayOffNew := oldWant.appQos && !oldWant.delay && newObs.delay
	if qosOffNew || delayOffNew {
		conflicts = append(conflicts, "按应用分优先级 / 延迟模拟(两者互斥)")
	}
	if names[from] != "" && names[to] != "" && names[from] != names[to] {
		conflicts = append(conflicts, "名称")
	}
	if ov, nv := idents[from], idents[to]; ov != nil && nv != nil && !identEq(ov, nv) {
		conflicts = append(conflicts, "设备识别纠正")
	}
	if oldPol != nil && newPol != nil {
		if oldPol.Quota != nil && newPol.Quota != nil && !reflect.DeepEqual(oldPol.Quota, newPol.Quota) {
			conflicts = append(conflicts, "流量配额")
		}
		if len(oldPol.Schedule) > 0 && len(newPol.Schedule) > 0 && !reflect.DeepEqual(oldPol.Schedule, newPol.Schedule) {
			conflicts = append(conflicts, "分时段限速")
		}
	}
	for _, o := range appLim.Items {
		if o.MAC != from {
			continue
		}
		for _, n := range appLim.Items {
			if n.MAC == to && n.AppID == o.AppID && n.DownMbps != o.DownMbps {
				conflicts = append(conflicts, "应用限速("+o.AppID+")")
			}
		}
	}
	for _, o := range appCtl.TimeLimits {
		if o.MAC != from {
			continue
		}
		for _, n := range appCtl.TimeLimits {
			if n.MAC == to && n.AppID == o.AppID && n.Minutes != o.Minutes {
				conflicts = append(conflicts, "应用时长上限("+o.AppID+")")
			}
		}
	}
	res.Conflicts = conflicts
	if len(conflicts) > 0 && !force {
		return res, &mergeErr{"conflict", "新 MAC 已有不同的设置: " + strings.Join(conflicts, "、") +
			"; 确认以旧设备的设置为准请带 force=true"}
	}

	// 限速/延迟/低延迟需要新 MAC 在线(apply_device_rule.sh 要它的 IP)
	needOnline := (oldWant.limit && !(newObs.limit && oldWant.down == newObs.down && oldWant.up == newObs.up)) ||
		(oldWant.delay && !(newObs.delay && oldWant.delayEq(newObs))) ||
		(oldWant.sqm && !newObs.sqm)
	if needOnline && lookupCurrentDeviceIP(h, to) == "" {
		return res, &mergeErr{"device offline", "新 MAC 当前不在线: 限速/延迟/低延迟需要设备在线才能下发, 请等它连上热点后再合并"}
	}

	// 采集轻量合并前完整快照与旧 MAC 水位(仅在阶段一提交成功后才写入 mac_merge_archives.json)
	pendingArchive := s.buildMergeArchiveBeforeCommit(from, to, oldWant, oldObs, newBase, newObs, names, idents, appLim, appCtl, oldPol, newPol, now)

	// ── 阶段一: 写新 MAC 状态 ──
	var steps []mergeStep
	mig := map[string]bool{}

	// 1) rules.json + tc/iptables(正常动作路径)
	{
		var undos []func()
		touched := false
		run := func(action string, p map[string]string) error {
			r := ops.rule(action, p)
			if !r.OK {
				return fmt.Errorf("%s %s: %s %s", action, p["mac"], r.Error, strings.TrimSpace(r.Detail))
			}
			return nil
		}
		limitParams := func(mac string, r ruleState) map[string]string {
			p := map[string]string{"mac": mac}
			if r.down > 0 {
				p["rate_down"] = kbitRateStr(r.down)
			}
			if r.up > 0 {
				p["rate_up"] = kbitRateStr(r.up)
			}
			return p
		}
		delayParams := func(mac string, r ruleState) map[string]string {
			return map[string]string{"mac": mac, "delay_ms": strconv.Itoa(r.delayMs),
				"jitter_ms": strconv.Itoa(r.jitterMs), "loss_pct": r.loss}
		}
		steps = append(steps, mergeStep{name: "rules", do: func() error {
			if !newObs.exists && (oldWant.bl || oldWant.limit || oldWant.delay || oldWant.sqm || oldWant.wl || oldWant.appQos) {
				// 新 MAC 原来没有规则条目: 回滚最后把我们建的条目删掉(释放 mark_id)
				undos = append(undos, func() { ops.rule("rules_device_remove", map[string]string{"mac": to}) })
			}
			if oldWant.bl && !newObs.bl {
				if err := run("bl_add", map[string]string{"mac": to}); err != nil {
					return err
				}
				touched = true
				undos = append(undos, func() { ops.rule("bl_del", map[string]string{"mac": to}) })
			}
			if oldWant.limit && !(newObs.limit && oldWant.down == newObs.down && oldWant.up == newObs.up) {
				if err := run("rule_set", limitParams(to, oldWant)); err != nil {
					return err
				}
				touched = true
				undos = append(undos, func() {
					if newObs.limit {
						ops.rule("rule_set", limitParams(to, newObs))
					} else {
						ops.rule("rule_clear", map[string]string{"mac": to})
					}
				})
			}
			if qosOffNew { // force 才走到这里(见冲突检查): 先关新 MAC 的按应用分优先级
				if err := run("app_qos_set", map[string]string{"mac": to, "enabled": "false"}); err != nil {
					return err
				}
				touched = true
				undos = append(undos, func() {
					ops.rule("app_qos_set", map[string]string{"mac": to, "enabled": "true"})
				})
			}
			if oldWant.delay && !(newObs.delay && oldWant.delayEq(newObs)) {
				if err := run("delay_set", delayParams(to, oldWant)); err != nil {
					return err
				}
				touched = true
				undos = append(undos, func() {
					if newObs.delay {
						ops.rule("delay_set", delayParams(to, newObs))
					} else {
						ops.rule("delay_clear", map[string]string{"mac": to})
					}
				})
			}
			if oldWant.sqm && !newObs.sqm {
				if err := run("rule_sqm", map[string]string{"mac": to, "enabled": "true"}); err != nil {
					return err
				}
				touched = true
				undos = append(undos, func() { ops.rule("rule_sqm", map[string]string{"mac": to, "enabled": "false"}) })
			}
			if oldWant.wl && !newObs.wl {
				if err := run("device_whitelist_set", map[string]string{"mac": to, "enabled": "true"}); err != nil {
					return err
				}
				touched = true
				undos = append(undos, func() {
					ops.rule("device_whitelist_set", map[string]string{"mac": to, "enabled": "false"})
				})
			}
			// v5.32 T1: 按应用分优先级此前不在 ruleState 里, 合并会静默丢。
			// 下发走 app_qos_set(只写 rules.json + run/app_limit.dirty, 看门狗
			// 3 秒内重排计划, 不需要设备在线); 与延迟模拟的互斥见冲突检查。
			if delayOffNew { // force 才走到这里(见冲突检查): 先关新 MAC 的延迟模拟
				if err := run("delay_clear", map[string]string{"mac": to}); err != nil {
					return err
				}
				touched = true
				undos = append(undos, func() { ops.rule("delay_set", delayParams(to, newObs)) })
			}
			if oldWant.appQos && !newObs.appQos {
				if err := run("app_qos_set", map[string]string{"mac": to, "enabled": "true"}); err != nil {
					return err
				}
				touched = true
				undos = append(undos, func() {
					ops.rule("app_qos_set", map[string]string{"mac": to, "enabled": "false"})
				})
			}
			if touched || oldObs.exists || oldObs.bl {
				mig["rules"] = true
			}
			return nil
		}, undo: func() {
			for i := len(undos) - 1; i >= 0; i-- {
				undos[i]()
			}
		}})
	}

	// 2) 设备名称
	if nm := names[from]; nm != "" && (names[to] == "" || force) && names[to] != nm {
		var snap fileSnap
		steps = append(steps, mergeStep{name: "device_names", do: func() error {
			deviceNamesWriteMu.Lock()
			defer deviceNamesWriteMu.Unlock()
			snap = snapFile(namesPath)
			cur, err := loadDeviceNames(namesPath)
			if err != nil {
				return err
			}
			cur[to] = nm
			mig["device_names"] = true
			return saveDeviceNames(namesPath, cur)
		}, undo: func() {
			deviceNamesWriteMu.Lock()
			defer deviceNamesWriteMu.Unlock()
			if snap.path != "" {
				_ = snap.restore()
			}
		}})
	} else if names[from] != "" {
		mig["device_names"] = true
	}

	// 3) 设备识别纠正
	if ov := idents[from]; ov != nil && (idents[to] == nil || force) {
		var snap fileSnap
		steps = append(steps, mergeStep{name: "ident_override", do: func() error {
			snap = snapFile(identOverridePath(h))
			all := readIdentOverrides(h)
			cp := map[string]interface{}{}
			for k, v := range ov {
				cp[k] = v
			}
			cp["ts"] = now.Unix()
			all[to] = cp
			b, _ := json.MarshalIndent(all, "", "  ")
			mig["ident_override"] = true
			return discoverWriteAtomic(identOverridePath(h), b)
		}, undo: func() {
			if snap.path != "" {
				_ = snap.restore()
			}
		}})
	}

	// 4) 按应用限速
	if hasAppLimitFor(appLim, from) {
		var sj, sf fileSnap
		steps = append(steps, mergeStep{name: "app_limits", do: func() error {
			appLimitMu.Lock()
			defer appLimitMu.Unlock()
			sj = snapFile(filepath.Join(h, appLimitsJSONRelPath))
			sf = snapFile(filepath.Join(h, appLimitsFlatRelPath))
			f := loadAppLimits(h)
			var add []AppLimitItem
			for _, o := range f.Items {
				if o.MAC != from {
					continue
				}
				found := false
				for i := range f.Items {
					if f.Items[i].MAC == to && f.Items[i].AppID == o.AppID {
						found = true
						if force {
							f.Items[i].DownMbps = o.DownMbps
						}
					}
				}
				if !found {
					add = append(add, AppLimitItem{MAC: to, AppID: o.AppID, DownMbps: o.DownMbps})
				}
			}
			f.Items = append(f.Items, add...)
			mig["app_limits"] = true
			if err := saveAppLimits(h, f); err != nil {
				return err
			}
			ops.syncAppLimits()
			return nil
		}, undo: func() {
			appLimitMu.Lock()
			defer appLimitMu.Unlock()
			if sj.path != "" {
				_ = sj.restore()
				_ = sf.restore()
				ops.syncAppLimits()
			}
		}})
	}

	// 5) 应用时长上限 / 类别封锁(conn_blocks 同步时展开派生项, 所以排在 conn_blocks 之前)
	if hasAppCtlFor(appCtl, from) {
		var snap fileSnap
		steps = append(steps, mergeStep{name: "app_controls", do: func() error {
			appCtlMu.Lock()
			defer appCtlMu.Unlock()
			snap = snapFile(appControlsPath(h))
			f := loadAppControls(h)
			var addL []appTimeLimit
			for _, o := range f.TimeLimits {
				if o.MAC != from {
					continue
				}
				found := false
				for i := range f.TimeLimits {
					if f.TimeLimits[i].MAC == to && f.TimeLimits[i].AppID == o.AppID {
						found = true
						if force {
							f.TimeLimits[i].Minutes, f.TimeLimits[i].Ts = o.Minutes, now.Unix()
						}
					}
				}
				if !found {
					addL = append(addL, appTimeLimit{MAC: to, AppID: o.AppID, Minutes: o.Minutes, Ts: now.Unix()})
				}
			}
			f.TimeLimits = append(f.TimeLimits, addL...)
			var addC []categoryBlock
			for _, o := range f.CategoryBlocks {
				if o.MAC != from {
					continue
				}
				found := false
				for _, n := range f.CategoryBlocks {
					if n.MAC == to && n.Category == o.Category {
						found = true
					}
				}
				if !found {
					addC = append(addC, categoryBlock{MAC: to, Category: o.Category, Ts: now.Unix()})
				}
			}
			f.CategoryBlocks = append(f.CategoryBlocks, addC...)
			mig["app_controls"] = true
			return saveAppControls(h, f)
		}, undo: func() {
			appCtlMu.Lock()
			defer appCtlMu.Unlock()
			if snap.path != "" {
				_ = snap.restore()
			}
		}})
	}

	// 6) 连接/域名封锁 + 同步(派生项也在这次同步里跟到新 MAC)
	cbFile := readConnBlocks(h)
	if hasConnBlockFor(cbFile, from) || hasAppCtlFor(appCtl, from) {
		var snap fileSnap
		synced := false
		steps = append(steps, mergeStep{name: "conn_blocks", do: func() error {
			connBlockMu.Lock()
			defer connBlockMu.Unlock()
			snap = snapFile(connBlocksPath(h))
			f := readConnBlocks(h)
			var add []connBlock
			for _, o := range f.Items {
				if o.MAC != from {
					continue
				}
				dup := false
				for _, n := range f.Items {
					if n.MAC == to && n.Kind == o.Kind && n.Value == o.Value {
						dup = true
					}
				}
				if !dup {
					cp := o
					cp.MAC, cp.Ts = to, now.Unix()
					add = append(add, cp)
				}
			}
			if len(f.Items)+len(add) > connBlockMaxItems {
				return fmt.Errorf("封锁项将超过上限 %d", connBlockMaxItems)
			}
			if len(add) > 0 {
				f.Items = append(f.Items, add...)
				b, _ := json.MarshalIndent(f, "", "  ")
				if err := discoverWriteAtomic(connBlocksPath(h), b); err != nil {
					return err
				}
				mig["conn_blocks"] = true
			}
			synced = true
			return ops.syncConnBlocks()
		}, undo: func() {
			connBlockMu.Lock()
			defer connBlockMu.Unlock()
			if snap.path != "" {
				_ = snap.restore()
			}
			if synced {
				_ = ops.syncConnBlocks()
			}
		}})
	}

	// 7) 流量配额 / 分时段限速(控制器内存 + data/limit_policies.json)
	if oldPol != nil && s.limitCtl != nil {
		c := s.limitCtl
		var prev *devicePolicy
		var hadPrev bool
		var snap fileSnap
		steps = append(steps, mergeStep{name: "limit_policies", do: func() error {
			c.mu.Lock()
			defer c.mu.Unlock()
			snap = snapFile(c.policyPath())
			prev, hadPrev = c.policies[to]
			np := &devicePolicy{}
			if prev != nil {
				np = clonePolicy(prev)
			}
			if oldPol.Quota != nil && (np.Quota == nil || force) {
				q := *oldPol.Quota
				np.Quota = &q
			}
			if len(oldPol.Schedule) > 0 && (len(np.Schedule) == 0 || force) {
				np.Schedule = append([]schedWindow(nil), oldPol.Schedule...)
			}
			c.policies[to] = np
			mig["limit_policies"] = true
			return c.savePoliciesLocked()
		}, undo: func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if snap.path == "" {
				return
			}
			if hadPrev {
				c.policies[to] = prev
			} else {
				delete(c.policies, to)
			}
			_ = snap.restore()
		}})
	}

	// 7b) 加密 DNS 按设备豁免/覆盖策略 (data/encdns.json)
	encCfg := loadEncdns(h)
	if oldEncPol, hasOldEnc := encCfg.Devices[from]; hasOldEnc {
		_, hasNewEnc := encCfg.Devices[to]
		if !hasNewEnc || force {
			var snapEnc fileSnap
			steps = append(steps, mergeStep{name: "encdns", do: func() error {
				encdnsMu.Lock()
				defer encdnsMu.Unlock()
				snapEnc = snapFile(encdnsPath(h))
				c := loadEncdns(h)
				if c.Devices == nil {
					c.Devices = map[string]string{}
				}
				c.Devices[to] = oldEncPol
				c.Ts = now.Unix()
				b, _ := json.Marshal(c)
				if err := discoverWriteAtomic(encdnsPath(h), b); err != nil {
					return err
				}
				encdnsCountersInvalidate()
				mig["encdns"] = true
				return nil
			}, undo: func() {
				encdnsMu.Lock()
				defer encdnsMu.Unlock()
				if snapEnc.path != "" {
					_ = snapEnc.restore()
					encdnsCountersInvalidate()
				}
			}})
		}
	}

	// 8) 别名表 = 提交点
	{
		var snap fileSnap
		steps = append(steps, mergeStep{name: "mac_aliases", do: func() error {
			snap = snapFile(macAliasesPath(h))
			m := map[string]string{}
			for k, v := range loadMACAliases(h) {
				m[k] = v
			}
			addMACAlias(m, from, to)
			mig["mac_aliases"] = true
			return saveMACAliases(h, m)
		}, undo: func() {
			if snap.path != "" {
				_ = snap.restore()
				macAliasCache.mu.Lock()
				macAliasCache.m = nil
				macAliasCache.mu.Unlock()
			}
		}})
	}

	for i, st := range steps {
		var err error
		if macMergeFailStep == st.name {
			err = errors.New("injected failure")
		} else {
			err = st.do()
		}
		if err != nil {
			for j := i; j >= 0; j-- {
				steps[j].undo()
			}
			auditLog(h, macMergeAuditTID, "device_merge_rollback",
				map[string]string{"from_mac": from, "to_mac": to, "failed_step": st.name}, "error", err.Error())
			return res, &mergeErr{"merge failed", "步骤 " + st.name + " 失败, 已回滚: " + err.Error()}
		}
	}

	// ── 阶段二: 拆掉旧 MAC(失败只记警告) ──
	warn := func(format string, a ...interface{}) { res.Warnings = append(res.Warnings, fmt.Sprintf(format, a...)) }
	clearOld := func(action string, p map[string]string) {
		if r := ops.rule(action, p); !r.OK {
			warn("%s: %s %s", action, r.Error, strings.TrimSpace(r.Detail))
		}
	}
	if oldObs.bl {
		clearOld("bl_del", map[string]string{"mac": from})
	}
	if oldObs.wl {
		clearOld("device_whitelist_set", map[string]string{"mac": from, "enabled": "false"})
	}
	if oldObs.sqm {
		clearOld("rule_sqm", map[string]string{"mac": from, "enabled": "false"})
	}
	if oldObs.limit {
		clearOld("rule_clear", map[string]string{"mac": from})
	}
	if oldObs.delay {
		clearOld("delay_clear", map[string]string{"mac": from})
	}
	// v5.32 T1: 旧设备的按应用分优先级也一并关掉(与 sqm/wl 同款清理)
	if oldObs.appQos {
		clearOld("app_qos_set", map[string]string{"mac": from, "enabled": "false"})
	}
	if oldObs.exists {
		clearOld("rules_device_remove", map[string]string{"mac": from})
	}
	if names[from] != "" {
		deviceNamesWriteMu.Lock()
		if cur, err := loadDeviceNames(namesPath); err == nil {
			delete(cur, from)
			if err := saveDeviceNames(namesPath, cur); err != nil {
				warn("device_names: %v", err)
			}
		} else {
			warn("device_names: %v", err)
		}
		deviceNamesWriteMu.Unlock()
	}
	if idents[from] != nil {
		all := readIdentOverrides(h)
		delete(all, from)
		b, _ := json.MarshalIndent(all, "", "  ")
		if err := discoverWriteAtomic(identOverridePath(h), b); err != nil {
			warn("ident_override: %v", err)
		}
		mig["ident_override"] = true
	}
	if hasAppLimitFor(appLim, from) {
		appLimitMu.Lock()
		f := loadAppLimits(h)
		kept := f.Items[:0]
		for _, it := range f.Items {
			if it.MAC != from {
				kept = append(kept, it)
			}
		}
		f.Items = kept
		if err := saveAppLimits(h, f); err != nil {
			warn("app_limits: %v", err)
		}
		appLimitMu.Unlock()
		ops.syncAppLimits()
	}
	if hasAppCtlFor(appCtl, from) {
		appCtlMu.Lock()
		f := loadAppControls(h)
		kl := f.TimeLimits[:0]
		for _, l := range f.TimeLimits {
			if l.MAC != from {
				kl = append(kl, l)
			}
		}
		f.TimeLimits = kl
		kc := f.CategoryBlocks[:0]
		for _, c := range f.CategoryBlocks {
			if c.MAC != from {
				kc = append(kc, c)
			}
		}
		f.CategoryBlocks = kc
		if err := saveAppControls(h, f); err != nil {
			warn("app_controls: %v", err)
		}
		appCtlMu.Unlock()
	}
	if hasConnBlockFor(cbFile, from) || hasAppCtlFor(appCtl, from) {
		connBlockMu.Lock()
		f := readConnBlocks(h)
		kept := f.Items[:0]
		for _, it := range f.Items {
			if it.MAC != from {
				kept = append(kept, it)
			}
		}
		f.Items = kept
		b, _ := json.MarshalIndent(f, "", "  ")
		if err := discoverWriteAtomic(connBlocksPath(h), b); err != nil {
			warn("conn_blocks: %v", err)
		} else if err := ops.syncConnBlocks(); err != nil {
			warn("conn_blocks sync: %v", err)
		}
		connBlockMu.Unlock()
	}
	if _, hadEnc := encCfg.Devices[from]; hadEnc {
		encdnsMu.Lock()
		c := loadEncdns(h)
		if _, ok := c.Devices[from]; ok {
			delete(c.Devices, from)
			c.Ts = now.Unix()
			b, _ := json.Marshal(c)
			if err := discoverWriteAtomic(encdnsPath(h), b); err != nil {
				warn("encdns: %v", err)
			} else {
				encdnsCountersInvalidate()
				_, _ = runBin(h, "encdns_sync.sh")
			}
		}
		encdnsMu.Unlock()
	}
	if c := s.limitCtl; c != nil {
		c.mu.Lock()
		if _, ok := c.policies[from]; ok {
			delete(c.policies, from)
			if err := c.savePoliciesLocked(); err != nil {
				warn("limit_policies: %v", err)
			}
		}
		if so := c.st.Devices[from]; so != nil {
			pendingArchive.UsageTransferred = mergeCtlUsageWithTransfer(c.devState(to), so)
			delete(c.st.Devices, from)
			c.dirty = true
			c.saveStateLocked(now, true)
			mig["limit_ctl_state"] = true
		}
		delete(c.logged, from)
		c.mu.Unlock()
		c.Poke()
	}
	if s.markKnownIfOldKnown(from, to) {
		mig["known_devices"] = true
	}
	s.macMergeAfterMerge(from, to)
	upsertMacMergeArchive(h, pendingArchive, now.Unix())
	mig["mac_merge_suggestions"] = true
	usageCache.mu.Lock()
	usageCache.out = nil
	usageCache.mu.Unlock()

	for k := range mig {
		res.Migrated = append(res.Migrated, k)
	}
	sort.Strings(res.Migrated)
	auditLog(h, macMergeAuditTID, "device_merge_commit", map[string]string{
		"from_mac": from, "to_mac": to, "force": strconv.FormatBool(force),
		"migrated": strings.Join(res.Migrated, ","), "conflicts": strings.Join(res.Conflicts, ","),
	}, map[bool]string{true: "ok", false: "partial"}[len(res.Warnings) == 0], strings.Join(res.Warnings, " | "))
	return res, nil
}

func clonePolicy(p *devicePolicy) *devicePolicy {
	if p == nil {
		return nil
	}
	cp := &devicePolicy{}
	if p.Quota != nil {
		q := *p.Quota
		cp.Quota = &q
	}
	for _, w := range p.Schedule {
		w.Days = append([]int(nil), w.Days...)
		cp.Schedule = append(cp.Schedule, w)
	}
	return cp
}

func identEq(a, b map[string]interface{}) bool {
	for _, k := range []string{"type", "os", "os_ver", "brand", "model"} {
		if asString(a[k]) != asString(b[k]) {
			return false
		}
	}
	return true
}

func hasAppLimitFor(f AppLimitFile, mac string) bool {
	for _, it := range f.Items {
		if it.MAC == mac {
			return true
		}
	}
	return false
}

func hasAppCtlFor(f appControlsFile, mac string) bool {
	for _, l := range f.TimeLimits {
		if l.MAC == mac {
			return true
		}
	}
	for _, c := range f.CategoryBlocks {
		if c.MAC == mac {
			return true
		}
	}
	return false
}

func hasConnBlockFor(f connBlockFile, mac string) bool {
	for _, it := range f.Items {
		if it.MAC == mac {
			return true
		}
	}
	return false
}

// mergeCtlUsage 把旧 MAC 的当日/当周期已用量并入新 MAC(同一周期才加), 告警去重标记沿用。
func mergeCtlUsage(dst, src *ctlDevState) {
	_ = mergeCtlUsageWithTransfer(dst, src)
}

func mergeCtlUsageWithTransfer(dst, src *ctlDevState) macUsageTransfer {
	var tr macUsageTransfer
	if dst == nil || src == nil {
		return tr
	}
	u, o := &dst.Usage, src.Usage
	if o.DayKey != "" {
		if u.DayKey == "" {
			u.DayKey = o.DayKey
		}
		if u.DayKey == o.DayKey && o.DayBytes > 0 {
			u.DayBytes += o.DayBytes
			tr.DayKey = o.DayKey
			tr.DayBytes = o.DayBytes
		}
	}
	if o.MonthKey != "" {
		if u.MonthKey == "" {
			u.MonthKey = o.MonthKey
		}
		if u.MonthKey == o.MonthKey && (o.MonthBytes > 0 || o.MonthRx > 0 || o.MonthTx > 0) {
			u.MonthBytes += o.MonthBytes
			u.MonthRx += o.MonthRx
			u.MonthTx += o.MonthTx
			tr.MonthKey = o.MonthKey
			tr.MonthBytes = o.MonthBytes
			tr.MonthRx = o.MonthRx
			tr.MonthTx = o.MonthTx
		}
	}
	if dst.AlertedDay == "" && src.AlertedDay != "" {
		dst.AlertedDay = src.AlertedDay
		tr.InheritedDay = true
	}
	if dst.AlertedMonth == "" && src.AlertedMonth != "" {
		dst.AlertedMonth = src.AlertedMonth
		tr.InheritedMonth = true
	}
	return tr
}

func revertCtlUsageTransfer(dst *ctlDevState, tr macUsageTransfer) {
	if dst == nil {
		return
	}
	subU64 := func(cur, delta uint64) uint64 {
		if cur >= delta {
			return cur - delta
		}
		return 0
	}
	if tr.DayKey != "" && dst.Usage.DayKey == tr.DayKey {
		dst.Usage.DayBytes = subU64(dst.Usage.DayBytes, tr.DayBytes)
	}
	if tr.MonthKey != "" && dst.Usage.MonthKey == tr.MonthKey {
		dst.Usage.MonthBytes = subU64(dst.Usage.MonthBytes, tr.MonthBytes)
		dst.Usage.MonthRx = subU64(dst.Usage.MonthRx, tr.MonthRx)
		dst.Usage.MonthTx = subU64(dst.Usage.MonthTx, tr.MonthTx)
	}
	if tr.InheritedDay {
		dst.AlertedDay = ""
	}
	if tr.InheritedMonth {
		dst.AlertedMonth = ""
	}
}

// markKnownIfOldKnown 旧 MAC 在陌生设备账本里被标记过"认识" → 新 MAC 也标记。
func (s *server) markKnownIfOldKnown(from, to string) bool {
	cfg := alert.NewConfig(s.hncDir)
	b, err := os.ReadFile(cfg.KnownDevicesPath)
	if err != nil {
		return false
	}
	var kf struct {
		MACs map[string]struct {
			MarkedKnownAt int64 `json:"marked_known_at"`
		} `json:"macs"`
	}
	if json.Unmarshal(b, &kf) != nil {
		return false
	}
	if e, ok := kf.MACs[from]; !ok || e.MarkedKnownAt == 0 {
		return false
	}
	return alert.MarkKnown(cfg, to) == nil
}

// macMergeAfterMerge 画像并入新 MAC; 与这两个 MAC 相关的建议清掉。
func (s *server) macMergeAfterMerge(from, to string) {
	macMergeMu.Lock()
	defer macMergeMu.Unlock()
	f := loadMacMergeFile(s.hncDir)
	op, np := f.Profiles[from], f.Profiles[to]
	switch {
	case op != nil && np == nil:
		cp := *op
		cp.New = false
		f.Profiles[to] = &cp
	case op != nil && np != nil:
		if op.FirstSeen > 0 && (np.FirstSeen == 0 || op.FirstSeen < np.FirstSeen) {
			np.FirstSeen = op.FirstSeen
		}
		fill := func(dst *string, v string) {
			if *dst == "" {
				*dst = v
			}
		}
		fill(&np.DHCPName, op.DHCPName)
		fill(&np.MDNSName, op.MDNSName)
		fill(&np.DHCPFP, op.DHCPFP)
		fill(&np.VendorClass, op.VendorClass)
		fill(&np.Type, op.Type)
		fill(&np.Brand, op.Brand)
		fill(&np.Model, op.Model)
		fill(&np.OS, op.OS)
		np.JA4 = mergeStrSet(append([]string(nil), op.JA4...), np.JA4, macMergeMaxJA4)
		np.Apps = mergeStrSet(append([]string(nil), op.Apps...), np.Apps, macMergeMaxApps)
		np.New = false // 已确认身份, 不再为它找候选
	}
	delete(f.Profiles, from)
	delete(f.Suggestions, to)
	delete(f.Suggestions, from)
	delete(f.MutexApart, macMutexApartKey(from, to))
	delete(f.Dismissed, macMergeDismissKey(to, from))
	delete(f.Dismissed, macMergeDismissKey(from, to))
	for mac, cs := range f.Suggestions {
		kept := cs[:0]
		for _, c := range cs {
			if c.OldMAC != from && c.OldMAC != to {
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			delete(f.Suggestions, mac)
		} else {
			f.Suggestions[mac] = kept
		}
	}
	_ = saveMacMergeFile(s.hncDir, f)
}

// ─── 合并归档快照 & 无损秒拆 (device_unmerge / 旧 MAC 重连自动秒拆) ──────────

type macRuleSnap struct {
	Exists   bool   `json:"exists"`
	Limit    bool   `json:"limit,omitempty"`
	DownKbit int    `json:"down_kbit,omitempty"`
	UpKbit   int    `json:"up_kbit,omitempty"`
	Delay    bool   `json:"delay,omitempty"`
	DelayMs  int    `json:"delay_ms,omitempty"`
	JitterMs int    `json:"jitter_ms,omitempty"`
	Loss     string `json:"loss,omitempty"`
	SQM      bool   `json:"sqm,omitempty"`
	WL       bool   `json:"wl,omitempty"`
	BL       bool   `json:"bl,omitempty"`
	AppQos   bool   `json:"app_qos,omitempty"`
}

type macDeviceSnap struct {
	Rule           macRuleSnap            `json:"rule"`
	DeviceName     string                 `json:"device_name,omitempty"`
	IdentOverride  map[string]interface{} `json:"ident_override,omitempty"`
	AppLimits      []AppLimitItem         `json:"app_limits,omitempty"`
	TimeLimits     []appTimeLimit         `json:"time_limits,omitempty"`
	CategoryBlocks []categoryBlock        `json:"category_blocks,omitempty"`
	ConnBlocks     []connBlock            `json:"conn_blocks,omitempty"`
	LimitPolicy    *devicePolicy          `json:"limit_policy,omitempty"`
	CtlState       *ctlDevState           `json:"ctl_state,omitempty"`
	EncdnsPolicy   string                 `json:"encdns_policy,omitempty"`
	KnownExisted   bool                   `json:"known_existed,omitempty"`
	KnownFirstSeen int64                  `json:"known_first_seen,omitempty"`
	KnownMarkedAt  int64                  `json:"known_marked_at,omitempty"`
	Profile        *macProfile            `json:"profile,omitempty"`
}

type macUsageTransfer struct {
	DayKey         string `json:"day_key,omitempty"`
	DayBytes       uint64 `json:"day_bytes,omitempty"`
	MonthKey       string `json:"month_key,omitempty"`
	MonthBytes     uint64 `json:"month_bytes,omitempty"`
	MonthRx        uint64 `json:"month_rx,omitempty"`
	MonthTx        uint64 `json:"month_tx,omitempty"`
	InheritedDay   bool   `json:"inherited_day,omitempty"`
	InheritedMonth bool   `json:"inherited_month,omitempty"`
}

type macMergeArchive struct {
	FromMAC             string           `json:"from_mac"`
	ToMAC               string           `json:"to_mac"`
	FromName            string           `json:"from_name,omitempty"`
	ToName              string           `json:"to_name,omitempty"`
	MergedAt            int64            `json:"merged_at"`
	OldInDevicesAtMerge bool             `json:"old_in_devices_at_merge"`
	OldLastSeenAtMerge  int64            `json:"old_last_seen_at_merge,omitempty"`
	OldBytesAtMerge     int64            `json:"old_bytes_at_merge,omitempty"`
	FromSnap            macDeviceSnap    `json:"from_snap"`
	ToBefore            macDeviceSnap    `json:"to_before"`
	UsageTransferred    macUsageTransfer `json:"usage_transferred"`
}

type macMergeArchiveFile struct {
	Version  int                `json:"version"`
	Archives []*macMergeArchive `json:"archives"`
}

type unmergeResult struct {
	Restored       []string
	Warnings       []string
	LegacyFallback bool
}

func macMergeArchivesPath(hncDir string) string {
	return filepath.Join(hncDir, macMergeArchivesRelPath)
}

func ruleStateToSnap(want, obs ruleState) macRuleSnap {
	loss := want.loss
	if !want.delay {
		loss = "0"
	}
	return macRuleSnap{
		Exists:   obs.exists,
		Limit:    want.limit,
		DownKbit: want.down,
		UpKbit:   want.up,
		Delay:    want.delay,
		DelayMs:  want.delayMs,
		JitterMs: want.jitterMs,
		Loss:     loss,
		SQM:      want.sqm,
		WL:       want.wl,
		BL:       want.bl,
		AppQos:   want.appQos,
	}
}

func snapToRuleState(s macRuleSnap) ruleState {
	loss := s.Loss
	if loss == "" || !s.Delay {
		loss = "0"
	}
	return ruleState{
		exists:   s.Exists,
		limit:    s.Limit && (s.DownKbit > 0 || s.UpKbit > 0),
		down:     s.DownKbit,
		up:       s.UpKbit,
		delay:    s.Delay,
		delayMs:  s.DelayMs,
		jitterMs: s.JitterMs,
		loss:     loss,
		sqm:      s.SQM,
		wl:       s.WL,
		bl:       s.BL,
		appQos:   s.AppQos,
	}
}

func cloneCtlDevState(st *ctlDevState) *ctlDevState {
	if st == nil {
		return nil
	}
	cp := *st
	return &cp
}

func cloneMacProfile(p *macProfile) *macProfile {
	if p == nil {
		return nil
	}
	cp := *p
	cp.JA4 = append([]string(nil), p.JA4...)
	cp.Apps = append([]string(nil), p.Apps...)
	return &cp
}

func cloneIdentMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	cp := make(map[string]interface{}, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func readKnownDeviceSnap(hncDir, mac string) (existed bool, firstSeen, markedAt int64) {
	cfg := alert.NewConfig(hncDir)
	b, err := os.ReadFile(cfg.KnownDevicesPath)
	if err != nil {
		return false, 0, 0
	}
	var kf struct {
		MACs map[string]struct {
			FirstSeen     int64 `json:"first_seen"`
			MarkedKnownAt int64 `json:"marked_known_at"`
		} `json:"macs"`
	}
	if json.Unmarshal(b, &kf) != nil || kf.MACs == nil {
		return false, 0, 0
	}
	e, ok := kf.MACs[mac]
	if !ok {
		return false, 0, 0
	}
	return true, e.FirstSeen, e.MarkedKnownAt
}

func restoreKnownDevicesAfterUnmerge(hncDir, from string, fromSnap macDeviceSnap, to string, toBefore macDeviceSnap) {
	cfg := alert.NewConfig(hncDir)
	raw := readJSONMap(cfg.KnownDevicesPath)
	if raw == nil {
		if !fromSnap.KnownExisted && !toBefore.KnownExisted {
			return
		}
		raw = map[string]interface{}{"version": 1, "macs": map[string]interface{}{}}
	}
	macs, _ := raw["macs"].(map[string]interface{})
	if macs == nil {
		macs = map[string]interface{}{}
		raw["macs"] = macs
	}
	applyOne := func(mac string, sn macDeviceSnap) {
		if !sn.KnownExisted {
			delete(macs, mac)
			return
		}
		entry := map[string]interface{}{}
		if prev, ok := macs[mac].(map[string]interface{}); ok && prev != nil {
			for k, v := range prev {
				entry[k] = v
			}
		}
		if sn.KnownFirstSeen > 0 {
			entry["first_seen"] = sn.KnownFirstSeen
		}
		if sn.KnownMarkedAt > 0 {
			entry["marked_known_at"] = sn.KnownMarkedAt
		} else {
			delete(entry, "marked_known_at")
		}
		macs[mac] = entry
	}
	applyOne(to, toBefore)
	applyOne(from, fromSnap)
	if b, err := json.Marshal(raw); err == nil {
		_ = discoverWriteAtomic(cfg.KnownDevicesPath, b)
	}
}

func (s *server) buildMergeArchiveBeforeCommit(
	from, to string,
	oldWant, oldObs, newBase, newObs ruleState,
	names map[string]string,
	idents map[string]map[string]interface{},
	appLim AppLimitFile,
	appCtl appControlsFile,
	oldPol, newPol *devicePolicy,
	now time.Time,
) *macMergeArchive {
	h := s.hncDir
	cbFile := readConnBlocks(h)
	encCfg := loadEncdns(h)

	var oldCtl, newCtl *ctlDevState
	if c := s.limitCtl; c != nil {
		c.mu.Lock()
		oldCtl = cloneCtlDevState(c.st.Devices[from])
		newCtl = cloneCtlDevState(c.st.Devices[to])
		c.mu.Unlock()
	}

	macMergeMu.Lock()
	mf := loadMacMergeFile(h)
	fromProf := cloneMacProfile(mf.Profiles[from])
	toProf := cloneMacProfile(mf.Profiles[to])
	fromDisp := macDisplayName(names, mf, from)
	toDisp := macDisplayName(names, mf, to)
	macMergeMu.Unlock()

	snapFor := func(mac string, want, obs ruleState, pol *devicePolicy, ctl *ctlDevState, prof *macProfile) macDeviceSnap {
		sn := macDeviceSnap{
			Rule:          ruleStateToSnap(want, obs),
			DeviceName:    names[mac],
			IdentOverride: cloneIdentMap(idents[mac]),
			LimitPolicy:   clonePolicy(pol),
			CtlState:      ctl,
			EncdnsPolicy:  encCfg.Devices[mac],
			Profile:       prof,
		}
		for _, it := range appLim.Items {
			if it.MAC == mac {
				sn.AppLimits = append(sn.AppLimits, it)
			}
		}
		for _, tl := range appCtl.TimeLimits {
			if tl.MAC == mac {
				sn.TimeLimits = append(sn.TimeLimits, tl)
			}
		}
		for _, cb := range appCtl.CategoryBlocks {
			if cb.MAC == mac {
				sn.CategoryBlocks = append(sn.CategoryBlocks, cb)
			}
		}
		for _, it := range cbFile.Items {
			if it.MAC == mac {
				sn.ConnBlocks = append(sn.ConnBlocks, it)
			}
		}
		sn.KnownExisted, sn.KnownFirstSeen, sn.KnownMarkedAt = readKnownDeviceSnap(h, mac)
		return sn
	}

	var oldInDevs bool
	var oldLS, oldBytes int64
	if devsMap := readJSONMap(filepath.Join(h, "data", "devices.json")); devsMap != nil {
		if raw, ok := devsMap[from]; ok {
			if dm, ok2 := raw.(map[string]interface{}); ok2 && dm != nil {
				oldInDevs = true
				oldLS, _ = toInt64(dm["last_seen"])
				rx, _ := toInt64(dm["rx_bytes"])
				tx, _ := toInt64(dm["tx_bytes"])
				if rx < 0 {
					rx = 0
				}
				if tx < 0 {
					tx = 0
				}
				oldBytes = rx + tx
			}
		}
	}

	return &macMergeArchive{
		FromMAC:             from,
		ToMAC:               to,
		FromName:            fromDisp,
		ToName:              toDisp,
		MergedAt:            now.Unix(),
		OldInDevicesAtMerge: oldInDevs,
		OldLastSeenAtMerge:  oldLS,
		OldBytesAtMerge:     oldBytes,
		FromSnap:            snapFor(from, oldWant, oldObs, oldPol, oldCtl, fromProf),
		ToBefore:            snapFor(to, newBase, newObs, newPol, newCtl, toProf),
	}
}

func pruneMacMergeArchivesList(list []*macMergeArchive, now int64) []*macMergeArchive {
	kept := make([]*macMergeArchive, 0, len(list))
	for _, a := range list {
		if a == nil || !validMAC(a.FromMAC) || !validMAC(a.ToMAC) || a.FromMAC == a.ToMAC {
			continue
		}
		if now > 0 && a.MergedAt > 0 && now-a.MergedAt > macMergeArchiveTTL {
			continue
		}
		kept = append(kept, a)
	}
	sort.SliceStable(kept, func(i, j int) bool {
		return kept[i].MergedAt < kept[j].MergedAt
	})
	if len(kept) > macMergeArchiveMax {
		kept = append([]*macMergeArchive(nil), kept[len(kept)-macMergeArchiveMax:]...)
	}
	return kept
}

func loadMacMergeArchivesUnlocked(hncDir string, now int64) *macMergeArchiveFile {
	f := &macMergeArchiveFile{Version: 1}
	if b, err := os.ReadFile(macMergeArchivesPath(hncDir)); err == nil {
		_ = json.Unmarshal(b, f)
	}
	f.Version = 1
	f.Archives = pruneMacMergeArchivesList(f.Archives, now)
	return f
}

func loadMacMergeArchives(hncDir string) *macMergeArchiveFile {
	macArchiveMu.Lock()
	defer macArchiveMu.Unlock()
	return loadMacMergeArchivesUnlocked(hncDir, time.Now().Unix())
}

func saveMacMergeArchivesUnlocked(hncDir string, f *macMergeArchiveFile, now int64) error {
	f.Version = 1
	f.Archives = pruneMacMergeArchivesList(f.Archives, now)
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return discoverWriteAtomic(macMergeArchivesPath(hncDir), b)
}

func upsertMacMergeArchive(hncDir string, arch *macMergeArchive, now int64) {
	if arch == nil {
		return
	}
	macArchiveMu.Lock()
	defer macArchiveMu.Unlock()
	f := loadMacMergeArchivesUnlocked(hncDir, now)
	kept := make([]*macMergeArchive, 0, len(f.Archives)+1)
	for _, a := range f.Archives {
		if a.FromMAC == arch.FromMAC {
			continue
		}
		kept = append(kept, a)
	}
	kept = append(kept, arch)
	f.Archives = kept
	_ = saveMacMergeArchivesUnlocked(hncDir, f, now)
}

func removeMacMergeArchive(hncDir, from, to string, now int64) {
	macArchiveMu.Lock()
	defer macArchiveMu.Unlock()
	if _, err := os.Stat(macMergeArchivesPath(hncDir)); err != nil {
		return
	}
	f := loadMacMergeArchivesUnlocked(hncDir, now)
	kept := make([]*macMergeArchive, 0, len(f.Archives))
	for _, a := range f.Archives {
		if a.FromMAC == from && (to == "" || a.ToMAC == to) {
			continue
		}
		kept = append(kept, a)
	}
	f.Archives = kept
	_ = saveMacMergeArchivesUnlocked(hncDir, f, now)
}

func findArchiveInSlice(list []*macMergeArchive, from, to string) *macMergeArchive {
	var fallback *macMergeArchive
	for i := len(list) - 1; i >= 0; i-- {
		a := list[i]
		if a == nil || a.FromMAC != from {
			continue
		}
		if to != "" && a.ToMAC == to {
			return a
		}
		if fallback == nil {
			fallback = a
		}
	}
	return fallback
}

func findMacMergeArchive(hncDir, from, to string, now int64) *macMergeArchive {
	macArchiveMu.Lock()
	defer macArchiveMu.Unlock()
	f := loadMacMergeArchivesUnlocked(hncDir, now)
	return findArchiveInSlice(f.Archives, from, to)
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func applyRuleStateOnline(ops mergeOps, cur, want ruleState, mac string, warnings *[]string) {
	run := func(action string, p map[string]string) bool {
		r := ops.rule(action, p)
		if !r.OK {
			*warnings = append(*warnings, fmt.Sprintf("%s %s: %s %s", action, mac, r.Error, strings.TrimSpace(r.Detail)))
			return false
		}
		return true
	}
	limitParams := func(m string, r ruleState) map[string]string {
		p := map[string]string{"mac": m}
		if r.down > 0 {
			p["rate_down"] = kbitRateStr(r.down)
		}
		if r.up > 0 {
			p["rate_up"] = kbitRateStr(r.up)
		}
		return p
	}
	delayParams := func(m string, r ruleState) map[string]string {
		return map[string]string{
			"mac": m, "delay_ms": strconv.Itoa(r.delayMs),
			"jitter_ms": strconv.Itoa(r.jitterMs), "loss_pct": r.loss,
		}
	}

	allOK := true
	if want.bl && !cur.bl {
		allOK = run("bl_add", map[string]string{"mac": mac}) && allOK
	} else if !want.bl && cur.bl {
		allOK = run("bl_del", map[string]string{"mac": mac}) && allOK
	}
	// 先关闭互斥对立项, 避免后续开启另一项时报 conflict
	if cur.appQos && !want.appQos {
		allOK = run("app_qos_set", map[string]string{"mac": mac, "enabled": "false"}) && allOK
	}
	if cur.delay && !want.delay {
		allOK = run("delay_clear", map[string]string{"mac": mac}) && allOK
	}
	if want.limit && !(cur.limit && want.down == cur.down && want.up == cur.up) {
		allOK = run("rule_set", limitParams(mac, want)) && allOK
	} else if !want.limit && cur.limit {
		allOK = run("rule_clear", map[string]string{"mac": mac}) && allOK
	}
	if want.delay && !(cur.delay && want.delayEq(cur)) {
		allOK = run("delay_set", delayParams(mac, want)) && allOK
	}
	if want.appQos && !cur.appQos {
		allOK = run("app_qos_set", map[string]string{"mac": mac, "enabled": "true"}) && allOK
	}
	if want.sqm != cur.sqm {
		allOK = run("rule_sqm", map[string]string{"mac": mac, "enabled": strconv.FormatBool(want.sqm)}) && allOK
	}
	if want.wl != cur.wl {
		allOK = run("device_whitelist_set", map[string]string{"mac": mac, "enabled": strconv.FormatBool(want.wl)}) && allOK
	}
	hasDev := want.exists || want.limit || want.delay || want.sqm || want.wl || want.appQos
	if !hasDev && cur.exists {
		allOK = run("rules_device_remove", map[string]string{"mac": mac}) && allOK
	}
	if !allOK {
		_ = ops.persistOfflineRule(mac, want)
	}
}

func actionDeviceUnmerge(s *server, p map[string]string) actionResp {
	from := normalizeMAC(firstNonEmptyStr(p["from_mac"], p["old_mac"]))
	to := normalizeMAC(firstNonEmptyStr(p["to_mac"], p["new_mac"]))
	aliases := loadMACAliases(s.hncDir)
	if from == "" && to == "" {
		if m := normalizeMAC(p["mac"]); m != "" {
			if _, isFrom := aliases[m]; isFrom {
				from = m
			} else {
				to = m
			}
		}
	}
	if from != "" && to == "" {
		if rawTo, ok := aliases[from]; ok {
			to = resolveMACAlias(aliases, rawTo)
		} else if arch := findMacMergeArchive(s.hncDir, from, "", time.Now().Unix()); arch != nil {
			to = arch.ToMAC
		}
	} else if from == "" && to != "" {
		var bestOld string
		var bestTs int64 = -1
		archFile := loadMacMergeArchives(s.hncDir)
		for oldMAC, rawTo := range aliases {
			if resolveMACAlias(aliases, rawTo) != to {
				continue
			}
			var ts int64
			if a := findArchiveInSlice(archFile.Archives, oldMAC, to); a != nil {
				ts = a.MergedAt
			}
			if bestOld == "" || ts > bestTs || (ts == bestTs && oldMAC < bestOld) {
				bestOld, bestTs = oldMAC, ts
			}
		}
		from = bestOld
	}
	if from == "" || to == "" {
		return actionResp{OK: false, Error: "bad params", Detail: "from_mac / to_mac 必须是有效的已合并 MAC"}
	}
	if from == to {
		return actionResp{OK: false, Error: "bad params", Detail: "from_mac 与 to_mac 相同"}
	}
	if isSimMACPrefix(from) || isSimMACPrefix(to) {
		return actionResp{OK: false, Error: "bad params", Detail: "模拟设备(02:5e:00)不能参与拆分"}
	}
	if isProtectedMAC(s.hncDir, from) || isProtectedMAC(s.hncDir, to) {
		return actionResp{OK: false, Error: "protected mac", Detail: "cannot unmerge host/broadcast/null mac"}
	}
	res, err := s.deviceUnmerge(from, to, false, time.Now())
	if err != nil {
		var me *mergeErr
		if errors.As(err, &me) {
			return actionResp{OK: false, Error: me.code, Detail: me.detail}
		}
		return actionResp{OK: false, Error: "unmerge failed", Detail: err.Error()}
	}
	var detail string
	if res.LegacyFallback {
		detail = "已解除旧版合并别名 " + from + " → " + to + " 并写入双端互斥锁(历史旧别名无归档快照, 保持现有规则不变)"
	} else {
		detail = "已无损拆分 " + from + " 与 " + to + "; 还原: " + strings.Join(res.Restored, ",")
	}
	if len(res.Warnings) > 0 {
		detail += "; 警告: " + strings.Join(res.Warnings, " | ")
	}
	return actionResp{OK: true, Detail: detail}
}

// deviceUnmerge 调用方持 s.actionMu:
//   - 若存在 mac_merge_archives.json 快照: 还原 to 至 ToBefore(安全扣回 UsageTransferred), 完整恢复 from 至 FromSnap;
//   - 若为无快照历史旧别名: 优雅降级解绑;
//   - 统一移除 mac_aliases.json 别名、清理 rmac_guard_state.json AutoInherited[to]、写入 MutexApart 与双向 Dismissed。
func (s *server) deviceUnmerge(from, to string, auto bool, now time.Time) (*unmergeResult, error) {
	h := s.hncDir
	nowU := now.Unix()
	ops := macMergeOpsFor(s)
	res := &unmergeResult{}
	warn := func(format string, a ...interface{}) {
		res.Warnings = append(res.Warnings, fmt.Sprintf(format, a...))
	}

	aliases := loadMACAliases(h)
	arch := findMacMergeArchive(h, from, to, nowU)
	if _, hasAlias := aliases[from]; !hasAlias && arch == nil {
		return nil, &mergeErr{"not merged", "设备对 " + from + " → " + to + " 当前未处于已合并状态"}
	}
	if to == "" {
		if rawTo, ok := aliases[from]; ok {
			to = resolveMACAlias(aliases, rawTo)
		} else if arch != nil {
			to = arch.ToMAC
		}
	}

	restoredSet := map[string]bool{}
	if arch != nil {
		// 1) 还原双方规则(在线走 ops.rule 实时挂载, 离线走 ops.persistOfflineRule 经 rulesStore 写回)
		curRS, err := readRuleStates(h)
		if err != nil {
			warn("read rules: %v", err)
			curRS = map[string]ruleState{}
		}
		wantTo := snapToRuleState(arch.ToBefore.Rule)
		if lookupCurrentDeviceIP(h, to) != "" {
			applyRuleStateOnline(ops, curRS[to], wantTo, to, &res.Warnings)
		} else if err := ops.persistOfflineRule(to, wantTo); err != nil {
			warn("persist_offline_rule %s: %v", to, err)
		}

		wantFrom := snapToRuleState(arch.FromSnap.Rule)
		if lookupCurrentDeviceIP(h, from) != "" {
			applyRuleStateOnline(ops, curRS[from], wantFrom, from, &res.Warnings)
		} else if err := ops.persistOfflineRule(from, wantFrom); err != nil {
			warn("persist_offline_rule %s: %v", from, err)
		}
		restoredSet["rules"] = true

		// 2) 还原设备名称
		{
			namesPath := filepath.Join(h, deviceNamesRelPath)
			deviceNamesWriteMu.Lock()
			curNames, err := loadDeviceNames(namesPath)
			if err == nil {
				if arch.ToBefore.DeviceName != "" {
					curNames[to] = arch.ToBefore.DeviceName
				} else {
					delete(curNames, to)
				}
				if arch.FromSnap.DeviceName != "" {
					curNames[from] = arch.FromSnap.DeviceName
				} else {
					delete(curNames, from)
				}
				if err := saveDeviceNames(namesPath, curNames); err != nil {
					warn("device_names: %v", err)
				} else {
					restoredSet["device_names"] = true
				}
			} else {
				warn("device_names load: %v", err)
			}
			deviceNamesWriteMu.Unlock()
		}

		// 3) 还原设备识别手动纠正
		{
			all := readIdentOverrides(h)
			_, hadFile := os.Stat(identOverridePath(h))
			if arch.ToBefore.IdentOverride != nil {
				all[to] = cloneIdentMap(arch.ToBefore.IdentOverride)
			} else {
				delete(all, to)
			}
			if arch.FromSnap.IdentOverride != nil {
				all[from] = cloneIdentMap(arch.FromSnap.IdentOverride)
			} else {
				delete(all, from)
			}
			if len(all) > 0 || hadFile == nil {
				b, _ := json.MarshalIndent(all, "", "  ")
				if err := discoverWriteAtomic(identOverridePath(h), b); err != nil {
					warn("ident_override: %v", err)
				} else {
					restoredSet["ident_override"] = true
				}
			}
		}

		// 4) 还原按应用限速(JSON + flat)
		{
			appLimitMu.Lock()
			f := loadAppLimits(h)
			hadAny := hasAppLimitFor(f, from) || hasAppLimitFor(f, to) || len(arch.ToBefore.AppLimits) > 0 || len(arch.FromSnap.AppLimits) > 0
			if hadAny {
				kept := make([]AppLimitItem, 0, len(f.Items))
				for _, it := range f.Items {
					if it.MAC != from && it.MAC != to {
						kept = append(kept, it)
					}
				}
				kept = append(kept, arch.ToBefore.AppLimits...)
				kept = append(kept, arch.FromSnap.AppLimits...)
				f.Items = kept
				if err := saveAppLimits(h, f); err != nil {
					warn("app_limits: %v", err)
				} else {
					restoredSet["app_limits"] = true
				}
			}
			appLimitMu.Unlock()
			if hadAny {
				ops.syncAppLimits()
			}
		}

		// 5) 还原应用时长上限与类别封锁
		hadAppCtl := false
		{
			appCtlMu.Lock()
			f := loadAppControls(h)
			hadAppCtl = hasAppCtlFor(f, from) || hasAppCtlFor(f, to) ||
				len(arch.ToBefore.TimeLimits) > 0 || len(arch.ToBefore.CategoryBlocks) > 0 ||
				len(arch.FromSnap.TimeLimits) > 0 || len(arch.FromSnap.CategoryBlocks) > 0
			if hadAppCtl {
				kl := make([]appTimeLimit, 0, len(f.TimeLimits))
				for _, l := range f.TimeLimits {
					if l.MAC != from && l.MAC != to {
						kl = append(kl, l)
					}
				}
				kl = append(kl, arch.ToBefore.TimeLimits...)
				kl = append(kl, arch.FromSnap.TimeLimits...)
				f.TimeLimits = kl

				kc := make([]categoryBlock, 0, len(f.CategoryBlocks))
				for _, c := range f.CategoryBlocks {
					if c.MAC != from && c.MAC != to {
						kc = append(kc, c)
					}
				}
				kc = append(kc, arch.ToBefore.CategoryBlocks...)
				kc = append(kc, arch.FromSnap.CategoryBlocks...)
				f.CategoryBlocks = kc

				if err := saveAppControls(h, f); err != nil {
					warn("app_controls: %v", err)
				} else {
					restoredSet["app_controls"] = true
				}
			}
			appCtlMu.Unlock()
		}

		// 6) 还原连接/域名封锁并同步
		{
			connBlockMu.Lock()
			f := readConnBlocks(h)
			hadCB := hasConnBlockFor(f, from) || hasConnBlockFor(f, to) ||
				len(arch.ToBefore.ConnBlocks) > 0 || len(arch.FromSnap.ConnBlocks) > 0 || hadAppCtl
			if hadCB {
				kept := make([]connBlock, 0, len(f.Items))
				for _, it := range f.Items {
					if it.MAC != from && it.MAC != to {
						kept = append(kept, it)
					}
				}
				kept = append(kept, arch.ToBefore.ConnBlocks...)
				kept = append(kept, arch.FromSnap.ConnBlocks...)
				f.Items = kept
				b, _ := json.MarshalIndent(f, "", "  ")
				if err := discoverWriteAtomic(connBlocksPath(h), b); err != nil {
					warn("conn_blocks: %v", err)
				} else if err := ops.syncConnBlocks(); err != nil {
					warn("conn_blocks sync: %v", err)
				} else {
					restoredSet["conn_blocks"] = true
				}
			}
			connBlockMu.Unlock()
		}

		// 7) 还原加密 DNS 按设备策略
		{
			encdnsMu.Lock()
			c := loadEncdns(h)
			_, hadTo := c.Devices[to]
			_, hadFrom := c.Devices[from]
			if hadTo || hadFrom || arch.ToBefore.EncdnsPolicy != "" || arch.FromSnap.EncdnsPolicy != "" {
				if c.Devices == nil {
					c.Devices = map[string]string{}
				}
				if arch.ToBefore.EncdnsPolicy != "" {
					c.Devices[to] = arch.ToBefore.EncdnsPolicy
				} else {
					delete(c.Devices, to)
				}
				if arch.FromSnap.EncdnsPolicy != "" {
					c.Devices[from] = arch.FromSnap.EncdnsPolicy
				} else {
					delete(c.Devices, from)
				}
				c.Ts = nowU
				b, _ := json.Marshal(c)
				if err := discoverWriteAtomic(encdnsPath(h), b); err != nil {
					warn("encdns: %v", err)
				} else {
					encdnsCountersInvalidate()
					if _, err := os.Stat(filepath.Join(h, "bin", "encdns_sync.sh")); err == nil {
						_, _ = runBin(h, "encdns_sync.sh")
					}
					restoredSet["encdns"] = true
				}
			}
			encdnsMu.Unlock()
		}

		// 8) 还原配额/时段策略与控制器状态(对 to 安全扣回 UsageTransferred, 对 from 恢复原状态)
		if c := s.limitCtl; c != nil {
			c.mu.Lock()
			if arch.ToBefore.LimitPolicy != nil {
				c.policies[to] = clonePolicy(arch.ToBefore.LimitPolicy)
			} else {
				delete(c.policies, to)
			}
			if arch.FromSnap.LimitPolicy != nil {
				c.policies[from] = clonePolicy(arch.FromSnap.LimitPolicy)
			} else {
				delete(c.policies, from)
			}
			if err := c.savePoliciesLocked(); err != nil {
				warn("limit_policies: %v", err)
			} else {
				restoredSet["limit_policies"] = true
			}

			if stTo := c.st.Devices[to]; stTo != nil {
				revertCtlUsageTransfer(stTo, arch.UsageTransferred)
				if arch.ToBefore.CtlState != nil {
					stTo.Adopted = arch.ToBefore.CtlState.Adopted
					stTo.Base = arch.ToBefore.CtlState.Base
				} else {
					stTo.Adopted = false
					stTo.Base = limitRule{}
					stTo.LastDesired = limitRule{}
					stTo.LastObserved = limitRule{}
				}
			} else if arch.ToBefore.CtlState != nil {
				c.st.Devices[to] = cloneCtlDevState(arch.ToBefore.CtlState)
			}

			if arch.FromSnap.CtlState != nil {
				c.st.Devices[from] = cloneCtlDevState(arch.FromSnap.CtlState)
			} else {
				delete(c.st.Devices, from)
			}
			c.dirty = true
			c.saveStateLocked(now, true)
			restoredSet["limit_ctl_state"] = true
			c.mu.Unlock()
			c.Poke()
		}

		// 9) 还原陌生设备已知账本
		restoreKnownDevicesAfterUnmerge(h, from, arch.FromSnap, to, arch.ToBefore)
		restoredSet["known_devices"] = true

		// 10) 移除已消费的归档快照
		removeMacMergeArchive(h, from, to, nowU)
	} else {
		res.LegacyFallback = true
	}

	// 公共收尾 A: 移除 mac_aliases.json 中的别名绑定
	{
		m := map[string]string{}
		for k, v := range loadMACAliases(h) {
			if k != from {
				m[k] = v
			}
		}
		if err := saveMACAliasesAt(h, m, nowU, nil); err != nil {
			warn("mac_aliases: %v", err)
		} else {
			restoredSet["mac_aliases"] = true
		}
	}

	// 公共收尾 B: 清理 rmac_guard_state.json AutoInherited[to]
	{
		rmacMu.Lock()
		st := loadRMACState(h)
		if rec, ok := st.AutoInherited[to]; ok && (rec.OldMAC == "" || rec.OldMAC == from) {
			delete(st.AutoInherited, to)
			saveRMACState(h, st)
		}
		rmacMu.Unlock()
	}

	// 公共收尾 C: 恢复画像并写入 MutexApart + 双向 Dismissed 防反弹重合并
	{
		macMergeMu.Lock()
		f := loadMacMergeFile(h)
		if arch != nil {
			if arch.FromSnap.Profile != nil {
				f.Profiles[from] = cloneMacProfile(arch.FromSnap.Profile)
			}
			if arch.ToBefore.Profile != nil {
				f.Profiles[to] = cloneMacProfile(arch.ToBefore.Profile)
			}
		}
		if k := macMutexApartKey(from, to); k != "" {
			f.MutexApart[k] = nowU
			pruneMutexApartMap(f.MutexApart, nowU)
		}
		f.Dismissed[macMergeDismissKey(to, from)] = nowU
		f.Dismissed[macMergeDismissKey(from, to)] = nowU
		for mac, cs := range f.Suggestions {
			kept := cs[:0]
			for _, c := range cs {
				if (mac == to && c.OldMAC == from) || (mac == from && c.OldMAC == to) {
					continue
				}
				kept = append(kept, c)
			}
			if len(kept) == 0 {
				delete(f.Suggestions, mac)
			} else {
				f.Suggestions[mac] = kept
			}
		}
		if err := saveMacMergeFile(h, f); err != nil {
			warn("mac_merge_suggestions: %v", err)
		} else {
			restoredSet["mac_merge_suggestions"] = true
		}
		macMergeMu.Unlock()
	}

	usageCache.mu.Lock()
	usageCache.out = nil
	usageCache.mu.Unlock()

	for k := range restoredSet {
		res.Restored = append(res.Restored, k)
	}
	sort.Strings(res.Restored)
	auditLog(h, macMergeAuditTID, "device_unmerge", map[string]string{
		"from_mac": from, "to_mac": to, "auto": strconv.FormatBool(auto),
		"legacy": strconv.FormatBool(res.LegacyFallback), "restored": strings.Join(res.Restored, ","),
	}, map[bool]string{true: "ok", false: "partial"}[len(res.Warnings) == 0], strings.Join(res.Warnings, " | "))
	return res, nil
}
