// alert_config.go — 告警配置的读/写端点 (v5.10.0)。
//
// 背景: dpid 的 alert.Run 每 tick 都 LoadConfig(data/alerts_config.json),
// 写文件即生效——但在 v5.10.0 之前没有任何写入方, 用户只能手改 JSON 且
// 必须满足 LoadConfig 的哨兵语义(section 配置过 = 对应数值字段 > 0)。
// 本文件提供:
//   GET /api/alert_config   默认值 + 用户文件覆盖的合并结果(UI 渲染用)
//   action alert_config_set 按 section 写入(读现有 → 改一段 → 原子写回),
//                           服务端补齐哨兵数值字段, UI 侧无需关心哨兵语义。
//
// 复用 hnc.io/dpid/alert 的 DefaultConfig 作为默认值来源, 保证与 dpid
// 读侧的语义永远一致(不会出现 UI 默认值和检测器默认值漂移)。

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"hnc.io/dpid/alert"
)

func alertConfigPath(hncDir string) string {
	return filepath.Join(hncDir, "data", "alerts_config.json")
}

// readAlertsConfigRaw 读现有配置文件原文, 缺失/损坏返回空 map。
func readAlertsConfigRaw(hncDir string) map[string]interface{} {
	out := map[string]interface{}{}
	b, err := os.ReadFile(alertConfigPath(hncDir))
	if err != nil {
		return out
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) == nil && m != nil {
		return m
	}
	return out
}

// writeAlertsConfigRaw 原子写回(tmp+rename, 与仓库其他 JSON 写者一致)。
func writeAlertsConfigRaw(hncDir string, m map[string]interface{}) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	dst := alertConfigPath(hncDir)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// apiAlertConfig GET /api/alert_config — dpid 默认配置为底、用户文件覆盖。
// 返回结构即 AlertConfig 的 JSON 形态, 前端直接按 section 渲染。
func (s *server) apiAlertConfig(w http.ResponseWriter, r *http.Request) {
	def := alert.DefaultConfig()
	out := map[string]interface{}{
		"enabled":         def.Enabled,
		"unknown_device":  def.UnknownDevice,
		"anomaly_traffic": def.AnomalyTraffic,
		"monthly_quota":   def.MonthlyQuota,
	}
	user := readAlertsConfigRaw(s.hncDir)
	// 用户文件的同名 section 整体覆盖默认(与 dpid LoadConfig 的哨兵语义不同——
	// 这里是给 UI 展示"文件里写了什么", 不做哨兵合并; dpid 读侧自己会判断)。
	for _, k := range []string{"enabled", "unknown_device", "anomaly_traffic", "monthly_quota"} {
		if v, ok := user[k]; ok {
			out[k] = v
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// actionAlertConfigSet 处理 alert_config_set action。
//
// params:
//
//	section  必填: "monthly_quota" | "anomaly_traffic" | "unknown_device" | "master"
//	enabled  必填: "true"/"false"
//	月度配额附加:  limit_gb (float>0, 转字节), warn_pct (1-99, 默认 80)
//	异常流量附加:  ratio (float>0, 默认 3.0), min_mb (int>=0, 默认 50)
//	未知设备附加:  quiet_start/quiet_end (0-23), min_interval_sec (>0, 默认 1800)
func actionAlertConfigSet(hncDir string, p map[string]string) actionResp {
	section := strings.TrimSpace(p["section"])
	enabled := p["enabled"]
	if enabled != "true" && enabled != "false" {
		return actionResp{OK: false, Error: "bad params", Detail: "enabled must be true/false"}
	}

	m := readAlertsConfigRaw(hncDir)
	var sec map[string]interface{}

	switch section {
	case "master":
		m["enabled"] = (enabled == "true")
		// master 开关也要求至少一个 section 有哨兵, 否则 dpid 忽略;
		// 若全空则顺手把 monthly_quota 哨兵补上(enabled=false + limit 1GB),
		// 保证 master 关闭真的生效。
		if _, ok := m["monthly_quota"]; !ok {
			m["monthly_quota"] = map[string]interface{}{
				"enabled": false, "limit_bytes": 1073741824, "warn_at_pct": 80,
			}
		}
	case "monthly_quota":
		limitGB, err := strconv.ParseFloat(strings.TrimSpace(p["limit_gb"]), 64)
		if err != nil || limitGB <= 0 || limitGB > 10240 {
			return actionResp{OK: false, Error: "bad params", Detail: "limit_gb must be 0.01..10240"}
		}
		warnPct := intFromParams(p, "warn_pct", 80)
		if warnPct < 1 || warnPct > 99 {
			return actionResp{OK: false, Error: "bad params", Detail: "warn_pct must be 1..99"}
		}
		sec = map[string]interface{}{
			"enabled":     enabled == "true",
			"limit_bytes": uint64(limitGB * 1073741824),
			"warn_at_pct": warnPct,
		}
		m["monthly_quota"] = sec
	case "anomaly_traffic":
		ratio, err := strconv.ParseFloat(strings.TrimSpace(p["ratio"]), 64)
		if err != nil || ratio <= 0 || ratio > 1000 {
			return actionResp{OK: false, Error: "bad params", Detail: "ratio must be 0..1000"}
		}
		minMB := int64FromParams(p, "min_mb", 50)
		if minMB < 0 {
			return actionResp{OK: false, Error: "bad params", Detail: "min_mb must be >= 0"}
		}
		sec = map[string]interface{}{
			"enabled":         enabled == "true",
			"ratio_threshold": ratio,
			"min_bytes":       minMB * 1024 * 1024,
		}
		m["anomaly_traffic"] = sec
	case "unknown_device":
		qs := intFromParams(p, "quiet_start", 23)
		qe := intFromParams(p, "quiet_end", 7)
		interval := int64FromParams(p, "min_interval_sec", 1800)
		if qs < 0 || qs > 23 || qe < 0 || qe > 23 {
			return actionResp{OK: false, Error: "bad params", Detail: "quiet hours must be 0..23"}
		}
		if interval <= 0 {
			return actionResp{OK: false, Error: "bad params", Detail: "min_interval_sec must be > 0"}
		}
		sec = map[string]interface{}{
			"enabled":          enabled == "true",
			"quiet_hour_start": qs,
			"quiet_hour_end":   qe,
			"min_interval_sec": interval,
		}
		m["unknown_device"] = sec
	default:
		return actionResp{OK: false, Error: "bad params", Detail: fmt.Sprintf("unknown section: %s", section)}
	}

	if err := writeAlertsConfigRaw(hncDir, m); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: section + " → " + enabled + " · dpid 下一 tick 生效"}
}

func intFromParams(p map[string]string, key string, def int) int {
	v := strings.TrimSpace(p[key])
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func int64FromParams(p map[string]string, key string, def int64) int64 {
	v := strings.TrimSpace(p[key])
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}
