package main

// v5.26 T4 · 「本月流量」与「月度配额」只留一个口径。
//
// 此前三处月用量各自统计: limitCtl(防火墙计数器 + DPI 下限, 计费月)、
// dpid alert 包 quota.go(sumByMAC DPI 历史, 自然月)、/api/usage_month
// (DPI 增量, 自然月) —— 用户在设备卡、配额进度条、告警里看到三个不同
// 数字。本文件把月用量的唯一权威定为 limitCtl(它对非模拟设备全量累加,
// 且是配额判定已用的口径), 全局告警与 API 都从它取数。

import (
	"fmt"
	"strings"
	"time"

	"hnc.io/dpid/alert"
)

// globalQuotaOn 全局告警月度配额是否生效(读 alert 配置)。
func (c *limitCtl) globalQuotaOn() bool {
	acfg := alert.NewConfig(c.hncDir)
	uc := alert.LoadConfig(acfg.AlertsConfigPath)
	return uc.MonthlyQuota.Enabled && uc.MonthlyQuota.LimitBytes > 0
}

// NoteUsageMonthRequest 记录 /api/usage_month 被请求过: 近 5 分钟内 tick
// 会计算 DPI 下限(histMon), 供该接口与全局配额告警取数。
func (c *limitCtl) NoteUsageMonthRequest() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.usageMonthAt = time.Now()
	c.mu.Unlock()
}

// monthUsageLocked 本计费月每设备 rx+tx 合计 = max(自有累加, DPI 合计)。
// 自有累加的 MonthKey 不是本计费月时视为 0(rollover 尚未发生, 旧值属于
// 上个周期)。调用方持 mu。
func (c *limitCtl) monthUsageLocked(ms time.Time) map[string]uint64 {
	monKey := ms.Format("2006-01-02")
	out := map[string]uint64{}
	for mac, s := range c.st.Devices {
		var own uint64
		if s.Usage.MonthKey == monKey {
			own = s.Usage.MonthBytes
		}
		out[mac] = maxU(own, c.histMon[mac])
	}
	// limitCtl 尚无状态的设备(刚出现在 DPI 历史里): 用 DPI 合计
	for mac, v := range c.histMon {
		if v > out[mac] {
			out[mac] = v
		}
	}
	return out
}

// MonthUsage 本计费月每设备 rx+tx 合计(字节), 只读线程安全。
// v5.26 T4: 月用量的唯一权威出口(全局配额告警与 /api/usage_month 同源)。
func (c *limitCtl) MonthUsage() map[string]uint64 {
	if c == nil {
		return nil
	}
	_, billingDay, _ := readObserved(c.hncDir)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.monthUsageLocked(billingPeriodStart(time.Now(), billingDay))
}

// MonthUsageSplit 与 MonthUsage 同源, 但保留所选权威来源的 rx/tx 拆分:
// 每台设备按合计整体二选一(自有累加 或 DPI 合计), 拆分来自同一来源,
// 保证 rx+tx 恰等于 MonthUsage 的合计(配额进度条与设备卡数字一致)。
// ok=false 表示本计费月的 DPI 下限还没算过(刚安装/刚开启, tick 未跑),
// 调用方应回退到直接扫 DPI 文件的旧路径。
func (c *limitCtl) MonthUsageSplit() (devices map[string]rxTxPair, periodStart time.Time, oldest int64, ok bool) {
	if c == nil {
		return nil, time.Time{}, 0, false
	}
	_, billingDay, _ := readObserved(c.hncDir)
	now := time.Now()
	ms := billingPeriodStart(now, billingDay)
	c.mu.Lock()
	defer c.mu.Unlock()
	monKey := ms.Format("2006-01-02")
	if c.histMonKey != monKey {
		return nil, ms, 0, false
	}
	out := map[string]rxTxPair{}
	for mac, s := range c.st.Devices {
		var own rxTxPair
		var ownSum uint64
		if s.Usage.MonthKey == monKey {
			ownSum = s.Usage.MonthBytes
			if s.Usage.MonthRx+s.Usage.MonthTx == ownSum {
				own = rxTxPair{s.Usage.MonthRx, s.Usage.MonthTx}
			} else {
				// 升级过渡: 旧状态文件没有拆分, 合计优先(rx 记满, tx=0)
				own = rxTxPair{ownSum, 0}
			}
		}
		hs := c.histMonSplit[mac]
		if ownSum >= hs.RX+hs.TX {
			out[mac] = own
		} else {
			out[mac] = hs
		}
	}
	for mac, hs := range c.histMonSplit {
		if _, seen := out[mac]; !seen {
			out[mac] = hs
		}
	}
	return out, ms, c.histOldest, true
}

// checkGlobalQuotaLocked 全局告警月度配额(从 dpid alert 包的
// detectMonthlyQuota 迁来): 对没有设备级月配额的设备, 用权威月用量与
// alert 配置里的 monthly_quota 比较, 生成 kind=monthly_quota 告警。
// ID/Detail 文案/档位沿用 quota.go 的写法; 去重用状态里的
// GlobalAlertWarn/GlobalAlertOver(存计费月 key, 跨月自动重置)。
// 调用方持 mu(tick 内, saveState 之前)。
func (c *limitCtl) checkGlobalQuotaLocked(monKey string, ms time.Time, now time.Time) {
	acfg := alert.NewConfig(c.hncDir)
	uc := alert.LoadConfig(acfg.AlertsConfigPath)
	q := uc.MonthlyQuota
	if !q.Enabled || q.LimitBytes <= 0 || !uc.Enabled {
		return
	}
	used := c.monthUsageLocked(ms)
	limit := uint64(q.LimitBytes)
	warnBytes := limit * uint64(q.WarnAtPct) / 100
	monthLabel := ms.Format("2006-01")
	for mac, u := range used {
		if limitSkipMAC(mac) || u < warnBytes {
			continue
		}
		mac = strings.ToLower(mac)
		// 有设备级月配额的设备不重复发全局告警(设备配额自己会告警)
		if pol := c.policies[mac]; pol != nil && pol.Quota != nil && pol.Quota.MonthlyGB > 0 {
			continue
		}
		hostname := alert.LookupHostname(acfg.DevicesJSON, mac)
		if hostname == "" {
			hostname = mac
		}
		var kind, detail string
		if u >= limit {
			kind = "over"
			detail = fmt.Sprintf("%s 本月已用 %s, 超出配额 %s", hostname, alert.FormatBytes(u), alert.FormatBytes(limit))
		} else {
			kind = "warn"
			detail = fmt.Sprintf("%s 本月已用 %s, 达到配额 %s 的 %d%%", hostname, alert.FormatBytes(u), alert.FormatBytes(limit), q.WarnAtPct)
		}
		if kind == "warn" && c.st.GlobalAlertWarn[mac] == monKey {
			continue
		}
		if kind == "over" && c.st.GlobalAlertOver[mac] == monKey {
			continue
		}
		a := alert.Alert{
			// 档位入 ID: warn/over 同小时跨档时同一 ID 会让读回侧一条双标已读
			ID:     alert.MakeAlertID("monthly_quota"+kind, mac, now.Unix()),
			Ts:     now.Unix(),
			Kind:   "monthly_quota",
			MAC:    mac,
			Detail: detail,
			Extra: map[string]interface{}{
				"used_bytes":  u,
				"limit_bytes": limit,
				"pct":         float64(u) / float64(limit) * 100,
				"month":       monthLabel,
				"warn_level":  kind,
			},
		}
		if err := alert.Append(acfg.AlertsJSONLPath, a); err != nil { // v5.26 T7: 唯一权威(带 flock)
			continue
		}
		if kind == "warn" {
			if c.st.GlobalAlertWarn == nil {
				c.st.GlobalAlertWarn = map[string]string{}
			}
			c.st.GlobalAlertWarn[mac] = monKey
		} else {
			if c.st.GlobalAlertOver == nil {
				c.st.GlobalAlertOver = map[string]string{}
			}
			c.st.GlobalAlertOver[mac] = monKey
		}
		c.dirty = true
		// 通知(best-effort)。超档不受免打扰限制; 预警档遵守。
		if kind == "over" || !alert.InQuietHours(now, uc.UnknownDevice) {
			_ = alert.PostNotification("HNC · 月度配额", a.Detail)
		}
	}
}
