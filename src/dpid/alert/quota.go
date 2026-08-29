// Package alert · monthly quota detection (v5.9.92).
//
// 实现 alert.go 里悬置了三个版本的 "Future: detectMonthlyQuota" ——
// JSON schema(QuotaCfg)、默认配置(LimitBytes:0 + WarnAtPct:80)、前端
// 渲染分支(index.html 的 monthly_quota 图标 📈)早已全部就位, 唯独这个
// 检测函数从未被写出来, 用户设了配额也永远收不到告警。
//
// 语义:
//   - 统计自然月(本地时区 1 号 0 点至今)每台设备的 tx+rx 合计(数据源与
//     anomaly 检测相同: run/stats.YYYYMMDD.jsonl);
//   - 超过 LimitBytes 告警一次; 超过 WarnAtPct%(默认 80)提前预警一次;
//   - 每台设备每月每档(预警/超限)最多一条 —— 用月粒度 dedup 键
//     "monthly_quota:<warn|over>:<YYYYMM>:<mac>";
//   - 每月文件最多 31 个 × ~400KB ≈ 12MB, 与 anomaly 的 7 天窗口同款
//     行级手解析, 5min tick 摊销成本可忽略。
package alert

import (
	"fmt"
	"path/filepath"
	"time"
)

// detectMonthlyQuota walks the current calendar month's history JSONL
// and emits a monthly_quota alert for each MAC that crosses the quota
// (WarnAtPct% pre-warning + 100% over-limit, each at most once per month).
//
// Returns the number of alerts emitted. Called from Run() under the
// MonthlyQuota.Enabled flag (default off — the user must set LimitBytes).
func detectMonthlyQuota(cfg Config, uc AlertConfig) (int, error) {
	q := uc.MonthlyQuota
	if !q.Enabled || q.LimitBytes <= 0 {
		return 0, nil
	}

	now := time.Now()
	// 自然月窗口(本地时区): 1 号 00:00 至今。
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	monthKey := now.Format("200601")

	// 本月合计, 按天滚 sumByMAC(它一次最多跨 2 个文件, 按天迭代覆盖整月)。
	monthly := map[string]uint64{}
	for day := monthStart; !day.After(now); day = day.AddDate(0, 0, 1) {
		dayEnd := day.AddDate(0, 0, 1)
		if dayEnd.After(now) {
			dayEnd = now
		}
		if err := sumByMAC(filepath.Join(cfg.HNCDir, "run"), day, day.Unix(), dayEnd.Unix(), monthly); err != nil {
			return 0, err
		}
	}

	// 月粒度 dedup: loadRecentAlerts 只读文件尾 50KB(月度告警频率极低,
	// 一条 ~300B, 50KB 足够覆盖整个月), since 传月起点即可。
	recentAlerts := loadRecentAlerts(cfg.AlertsJSONLPath, monthStart.Unix())
	emitted := 0

	limit := uint64(q.LimitBytes)
	warnBytes := limit * uint64(q.WarnAtPct) / 100

	for mac, used := range monthly {
		if used < warnBytes {
			continue
		}

		hostname := lookupHostname(cfg.DevicesJSON, mac)
		if hostname == "" {
			hostname = mac
		}

		// 档位判定: over(≥100%) 优先于 warn(≥WarnAtPct%)。
		var kind, detail string
		var extraPct float64
		if used >= limit {
			kind = "over"
			detail = fmt.Sprintf("%s 本月已用 %s, 超出配额 %s",
				hostname, formatBytes(used), formatBytes(limit))
		} else {
			kind = "warn"
			detail = fmt.Sprintf("%s 本月已用 %s, 达到配额 %s 的 %d%%",
				hostname, formatBytes(used), formatBytes(limit), q.WarnAtPct)
		}
		extraPct = float64(used) / float64(limit) * 100

		// 每月每档最多一条。
		// v5.9.93: dedup 键去掉月段 —— 月粒度已由 loadRecentAlerts 的 since=月起点
		// 天然保证; 原四段键与读回侧的两段键永不相等 → 每 tick 重复告警(雪崩)。
		dedupKey := "monthly_quota:" + kind + ":" + mac
		if _, alerted := recentAlerts[dedupKey]; alerted {
			continue
		}

		a := Alert{
			// v5.9.93: ID 带档位 —— warn/over 同小时跨档时 makeAlertID 相同会让
			// MarkSeen 一条双标已读。
			ID:     makeAlertID("monthly_quota"+kind, mac, now.Unix()),
			Ts:     now.Unix(),
			Kind:   "monthly_quota",
			MAC:    mac,
			Detail: detail,
			Extra: map[string]interface{}{
				"used_bytes":  used,
				"limit_bytes": limit,
				"pct":         extraPct,
				"month":       monthKey,
				"warn_level":  kind,
			},
		}
		if err := appendAlert(cfg.AlertsJSONLPath, a); err != nil {
			continue
		}
		emitted++

		// 通知(best-effort, 遵守免打扰时段)。超档不受免打扰限制 —— 配额
		// 超限是用户明确设置的硬约束; 预警档遵守。
		if !cfg.DisableNotify && (kind == "over" || !inQuietHours(now, uc.UnknownDevice)) {
			title := "HNC · 月度配额"
			_ = postNotification(title, a.Detail)
		}
	}
	return emitted, nil
}
