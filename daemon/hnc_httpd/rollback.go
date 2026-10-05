// rollback.go — v5.29 T3: 升级自动回滚的界面侧(只读转出 + ack)。
//
// 数据来源(全由 bin/hnc_rollback.sh 写, 原子 tmp+rename):
//
//	data/rollback.json  {"from","to","reason","at","action"} — 回滚已发生
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
		Rolled: true,
		From:   r.From,
		To:     r.To,
		Reason: r.Reason,
		At:     r.At,
		Action: r.Action,
	}
	if _, err := os.Stat(filepath.Join(s.hncDir, "data", "rollback.ack")); err == nil {
		out.Acknowledged = true
	}
	if _, err := os.Stat(filepath.Join(s.hncDir, "data", "rollback.pinned")); err == nil {
		out.Pinned = true
	}
	return out
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
	if _, err := os.Stat(c.hnc("data", "rollback.ack")); err != nil {
		it.Status = scWarn
		it.Value = fmt.Sprintf("已自动退回 %s", to)
		it.Detail = fmt.Sprintf("检测到 %s 启动失败(%s), 已退回 %s。请在界面顶部确认横幅并导出诊断包", from, reason, to)
		if action != "" {
			it.Detail += ";本次仅记录未回滚(rollback.disabled)"
		}
		it.Fix = "点顶部横幅的「知道了」;请把诊断包发给开发者"
		return it
	}
	it.Status, it.Value = scOK, fmt.Sprintf("已退回 %s(已确认)", to)
	it.Detail = fmt.Sprintf("%s 启动失败已自动回滚, 用户已确认", from)
	return it
}
