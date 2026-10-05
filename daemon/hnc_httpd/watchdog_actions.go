// watchdog_actions.go — v5.28 A2: 看门狗动作记账的转出与判读。
//
// 数据来源: Go 看门狗(src/dpid/cmd/hnc_watchdog/actionstats.go)每分钟原子写
// run/watchdog_actions.json:
//
//	{schema:1, generated_at, order:[...按 calls_1h 降序...],
//	 actions:{name:{calls_1h, fails_1h, last_rc, last_fail_at, avg_ms, max_ms}}}
//
// 本文件:
//   - readWatchdogActionsRaw: /api/power 的 watchdog_actions 段(原样转出,
//     文件 > 3 分钟没更新 → stale:true);
//   - scWatchdogActionsItem: 自检「进程与资源」的「看门狗动作」行 —— 有动作
//     1 小时内失败(126/127/超时等, 分类在看门狗侧)→ 警告并列名(v5.26 的
//     tc_uplink_healthy exit 127 几个版本没人发现, 就是这行的靶子); 所有动作
//     外部进程合计 > 400 次/小时 → 警告「看门狗调用偏多」; 否则正常, 显示
//     「N 次 / 小时 · 平均 x 毫秒」。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// wdActionsStale 记账文件多久没刷新就算不新鲜(看门狗每分钟写一次)。
const wdActionsStale = 3 * time.Minute

// scWatchdogActionsMaxCalls1H 自检的「看门狗调用偏多」阈值(次 / 小时)。
// 预算测试(看门狗侧 budget_test)的 ACTIVE 健康场景外部进程合计 ≤ 300,
// 400 是留了余量的告警线。
const scWatchdogActionsMaxCalls1H = 400

// readWatchdogActionsRaw 读 run/watchdog_actions.json, 原样转出; 不存在 /
// 损坏 / generated_at 距 now 超过 wdActionsStale → 顶层 stale:true(否则
// stale:false)。返回 nil 表示文件不存在(调用方决定怎么呈现)。
func readWatchdogActionsRaw(hncDir string, now time.Time) map[string]interface{} {
	p := filepath.Join(hncDir, "run", "watchdog_actions.json")
	b, err := os.ReadFile(p)
	if err != nil || len(b) == 0 || len(b) > 1<<20 {
		return nil
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	stale := true
	if gen, ok := m["generated_at"].(float64); ok && int64(gen) > 0 {
		stale = now.Sub(time.Unix(int64(gen), 0)) > wdActionsStale
	}
	m["stale"] = stale
	return m
}

// scWatchdogActionsItem 自检「进程与资源 → 看门狗动作」(v5.28 A2)。
func scWatchdogActionsItem(c *scCtx) scItem {
	it := scItem{ID: "watchdog_actions", Label: "看门狗动作"}
	m := c.readJSON(c.hnc("run", "watchdog_actions.json"))
	if m == nil {
		it.Status, it.Value = scInfo, "暂无数据"
		it.Detail = "Go 看门狗每分钟写一次 run/watchdog_actions.json; 看门狗未运行时无数据"
		return it
	}
	acts, _ := m["actions"].(map[string]interface{})
	gen, _ := m["generated_at"].(float64)

	var totalCalls, totalFails float64
	var weightedMS float64
	var failedNames []string
	names := make([]string, 0, len(acts))
	for name, raw := range acts {
		a, _ := raw.(map[string]interface{})
		if a == nil {
			continue
		}
		names = append(names, name)
		calls, _ := a["calls_1h"].(float64)
		fails, _ := a["fails_1h"].(float64)
		avg, _ := a["avg_ms"].(float64)
		totalCalls += calls
		totalFails += fails
		weightedMS += avg * calls
		if fails > 0 {
			failedNames = append(failedNames, name)
		}
	}
	sort.Strings(failedNames)

	switch {
	case len(failedNames) > 0:
		it.Status = scWarn
		it.Value = fmt.Sprintf("%d 个动作失败", len(failedNames))
		it.Detail = "1 小时内失败: " + strings.Join(failedNames, " / ") + "(返回码 126/127 或超时)"
		it.Fix = "查看 watchdog.log 与 bin/watchdog.sh 对应动作; 127 = 脚本内命令不存在"
	case totalCalls > scWatchdogActionsMaxCalls1H:
		it.Status = scWarn
		it.Value = fmt.Sprintf("%.0f 次 / 小时", totalCalls)
		it.Detail = "看门狗调用偏多(阈值 " + fmt.Sprint(scWatchdogActionsMaxCalls1H) + " 次 / 小时)"
		it.Fix = "打开「功耗」详情(/api/power)看 watchdog_actions 各动作的次数与耗时"
	default:
		it.Status = scOK
		avg := 0.0
		if totalCalls > 0 {
			avg = weightedMS / totalCalls
		}
		it.Value = fmt.Sprintf("%.0f 次 / 小时 · 平均 %.0f 毫秒", totalCalls, avg)
		if gen > 0 {
			age := c.env.Now().Sub(time.Unix(int64(gen), 0))
			if age > wdActionsStale {
				it.Detail = fmt.Sprintf("记账已 %.0f 分钟未刷新(看门狗未运行?)", age.Minutes())
				it.Status = scInfo
			} else {
				it.Detail = fmt.Sprintf("%d 个动作, 失败 %d 次", len(names), int64(totalFails))
			}
		}
	}
	return it
}
