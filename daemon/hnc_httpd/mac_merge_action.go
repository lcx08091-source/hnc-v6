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
	"time"

	"hnc.io/dpid/alert"
)

const macMergeAuditTID = "macmerge"

// mergeOps 把"系统副作用"抽出来(规则动作 / 同步脚本), 测试注入假的实现。
type mergeOps interface {
	// rule 走正常动作路径: rule_set / rule_clear / bl_add / bl_del / delay_set /
	// delay_clear / rule_sqm / device_whitelist_set / rules_device_remove
	rule(action string, p map[string]string) actionResp
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
	if oldWant.limit && newBase.limit && (oldWant.down != newBase.down || oldWant.up != newBase.up) {
		conflicts = append(conflicts, "限速")
	}
	if oldWant.delay && newBase.delay && !oldWant.delayEq(newBase) {
		conflicts = append(conflicts, "延迟")
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
			if !newObs.exists && (oldWant.bl || oldWant.limit || oldWant.delay || oldWant.sqm || oldWant.wl) {
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
	if c := s.limitCtl; c != nil {
		c.mu.Lock()
		if _, ok := c.policies[from]; ok {
			delete(c.policies, from)
			if err := c.savePoliciesLocked(); err != nil {
				warn("limit_policies: %v", err)
			}
		}
		if so := c.st.Devices[from]; so != nil {
			mergeCtlUsage(c.devState(to), so)
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
	u, o := &dst.Usage, src.Usage
	if o.DayKey != "" {
		if u.DayKey == "" {
			u.DayKey = o.DayKey
		}
		if u.DayKey == o.DayKey {
			u.DayBytes += o.DayBytes
		}
	}
	if o.MonthKey != "" {
		if u.MonthKey == "" {
			u.MonthKey = o.MonthKey
		}
		if u.MonthKey == o.MonthKey {
			u.MonthBytes += o.MonthBytes
		}
	}
	if dst.AlertedDay == "" {
		dst.AlertedDay = src.AlertedDay
	}
	if dst.AlertedMonth == "" {
		dst.AlertedMonth = src.AlertedMonth
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
