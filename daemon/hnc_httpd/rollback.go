// rollback.go — v5.29 T3: 升级自动回滚的界面侧(只读转出 + ack)。
//
// 数据来源(全由 bin/hnc_rollback.sh 写, 原子 tmp+rename):
//
//	data/rollback.json  {"from","to","reason","at","action"} — 回滚已发生
//	                    from = 启动失败的新版, to = 退回到的上一版(versionCode);
//	                    action = rolled_back / recorded_only / no_snapshot
//	data/rollback.ack   用户点过「知道了」(横幅消失)
//
// 判定逻辑不在本文件: 触发条件(连续 6 次 / 崩溃 ≥ 5)在 hnc_rollback.sh,
// 本文件只把结果带给前端(横幅「检测到 vX 启动失败, 已自动退回 vY; 请把
// 诊断包发给开发者」+「知道了」按钮)。
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// rollbackJSON hnc_rollback.sh 写的文件结构(字段名与 shell printf 一致)。
type rollbackJSON struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
	At     int64  `json:"at"`
	Action string `json:"action"`
}

// rollbackOut /api/health 的 rollback 段。rolled=false 且无文件时整个为
// nil(前端不显示)。acknowledged = data/rollback.ack 存在。
type rollbackOut struct {
	Rolled       bool   `json:"rolled"`
	From         string `json:"from,omitempty"`
	To           string `json:"to,omitempty"`
	FromName     string `json:"from_name,omitempty"` // 5290001 → 5.29.0-rc1(横幅显示用)
	ToName       string `json:"to_name,omitempty"`
	Reason       string `json:"reason,omitempty"`
	At           int64  `json:"at,omitempty"`
	Action       string `json:"action,omitempty"`
	Acknowledged bool   `json:"acknowledged"`
	Pinned       bool   `json:"pinned"`
}

// rollbackStatus 读文件构造输出(文件缺失 / 坏 JSON → nil, 不报错:
// 横幅是增强功能, 不能影响探活)。
func (s *server) rollbackStatus() *rollbackOut {
	b, err := os.ReadFile(filepath.Join(s.hncDir, "data", "rollback.json"))
	if err != nil {
		return nil
	}
	var r rollbackJSON
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	out := &rollbackOut{
		Rolled:   true,
		From:     r.From,
		To:       r.To,
		FromName: vcName(r.From),
		ToName:   vcName(r.To),
		Reason:   r.Reason,
		At:       r.At,
		Action:   r.Action,
	}
	if _, err := os.Stat(filepath.Join(s.hncDir, "data", "rollback.ack")); err == nil {
		out.Acknowledged = true
	}
	if _, err := os.Stat(filepath.Join(s.hncDir, "data", "rollback.pinned")); err == nil {
		out.Pinned = true
	}
	return out
}

// vcName versionCode(5MMPRRR: 主.次.补丁 + rc 序号, 000 = 正式版)转成
// 版本名: 5290001 → "5.29.0-rc1", 5180000 → "5.18.0"。认不出的原样返回。
func vcName(code string) string {
	if len(code) != 7 {
		return code
	}
	if _, err := strconv.Atoi(code); err != nil {
		return code
	}
	minor, _ := strconv.Atoi(code[1:3])
	rc, _ := strconv.Atoi(code[4:7])
	name := fmt.Sprintf("%c.%d.%c", code[0], minor, code[3])
	if rc > 0 {
		name += fmt.Sprintf("-rc%d", rc)
	}
	return name
}

// apiRollbackAck 横幅「知道了」: 写 data/rollback.ack(空文件, 存在即语义)。
// 走鉴权(不在 isPublicPath); POST / 空 body 均可。
func (s *server) apiRollbackAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	ack := filepath.Join(s.hncDir, "data", "rollback.ack")
	if _, err := os.Stat(ack); err != nil {
		if err := os.WriteFile(ack, nil, 0o600); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "write failed"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"acknowledged": true})
}

// scRollbackItem 自检「升级状态」行(rollback.go 顶部注释同源)。
func scRollbackItem(c *scCtx) scItem {
	it := scItem{ID: "rollback", Label: "升级状态"}
	m := c.readJSON(c.hnc("data", "rollback.json"))
	if m == nil {
		it.Status, it.Value = scOK, "正常"
		it.Detail = "没有发生过自动回滚(rollback.json 不存在)"
		return it
	}
	from, _ := m["from"].(string)
	to, _ := m["to"].(string)
	reason, _ := m["reason"].(string)
	action, _ := m["action"].(string)
	from, to = vcName(from), vcName(to)
	if _, err := os.Stat(c.hnc("data", "rollback.ack")); err != nil {
		it.Status = scWarn
		switch action {
		case "recorded_only":
			it.Value = fmt.Sprintf("%s 启动失败(仅记录)", from)
			it.Detail = fmt.Sprintf("检测到 %s 启动失败(%s); 自动回滚已关闭(data/rollback.disabled), 本次只记录未回滚", from, reason)
		case "no_snapshot":
			it.Value = fmt.Sprintf("%s 启动失败(无快照)", from)
			it.Detail = fmt.Sprintf("检测到 %s 启动失败(%s), 但没有上一版的快照, 无法自动退回", from, reason)
		default:
			it.Value = fmt.Sprintf("已自动退回 %s", to)
			it.Detail = fmt.Sprintf("检测到 %s 启动失败(%s), 已退回 %s; 刷入更新的版本后自动解除钉住", from, reason, to)
		}
		it.Fix = "点顶部横幅的「知道了」;请把诊断包发给开发者"
		return it
	}
	it.Status, it.Value = scOK, fmt.Sprintf("%s 启动失败(已确认)", from)
	it.Detail = fmt.Sprintf("%s 启动失败, 处理结果 %s, 用户已确认", from, action)
	return it
}
