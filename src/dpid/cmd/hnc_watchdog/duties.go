// duties.go — v5.25: 补齐 Go 版 watchdog 相对 shell 版缺失 / 走样的日常职责。
//
// rc30 把主循环从 bin/watchdog.sh 搬到 Go 时漏了几项, 真机(跑 Go 版)上一直没生效:
//   - 在线时长采样(v5.10 F5): 热点开着时每小时把在线设备记一行到 run/online_hours.jsonl,
//     /api/online_hours 据此按天计小时数。Go 版从没写过 → 「在线时长」恒为空。
//     (v5.30 T1a 起改为 5 分钟采样、按分钟累计, 见 online_minutes.go)
//   - 流量统计采样节拍: shell 版 300 秒(热点开着但无设备 900 秒), Go 版写成每轮(60 秒)一次,
//     多跑 5 倍 stats_sample.sh。
//   - 定时开关热点(见 power.go)。
package main

import (
	"encoding/json"
	"strings"
	"time"

	"hnc.io/dpid/activity"

	"hnc.io/dpid/clockhwm" // v5.26 T6: 时钟可信规则唯一权威
)

const (
	statsSampleEvery = 300 * time.Second // 与 watchdog.sh STATS_INTERVAL / power_sched.go stats_sample 一致
	onlineWindowSec  = 90                // 与 httpd activityOnlineWindow 一致
	onlineHoursFile  = runDir + "/online_hours.jsonl"
)

// statsSampleDue 是否该跑 stats_sample.sh: 300 秒; 热点开着但没有在线设备时 ×3。
// v5.28 A1: activity 快照经由 actSnapshotFn(可注入), budget_test 能模拟「无在线设备」。
func statsSampleDue(last, now time.Time) bool {
	iv := statsSampleEvery
	if s := actSnapshotFn(); s.OK && s.Level == activity.LevelNoClients {
		iv *= 3
	}
	return now.Sub(last) >= iv
}

// clockSaneNow 与 bin/hnc_clock.sh sane 同规则: ≥2025 且不早于高水位 − 600 秒。
// 时钟不可信时不写在线时长(否则 day 字段会是 1970 之类的错日)。
func clockSaneNow(now time.Time) bool {
	// v5.26 T6: 委托 clockhwm(唯一权威, 与 httpd clockSaneAt 同一份)。
	return clockhwm.Sane(now.Unix(), clockhwm.ReadHWM(dataDir+"/clock_hwm"))
}

// onlineMACs devices.json 里此刻在线且未被拉黑的设备(纯函数, 便于测试)。
// 在线 = online:true 或 last_seen 在 onlineWindowSec 秒内(与 httpd 判定一致)。
func onlineMACs(b []byte, now int64) []string {
	var devs map[string]map[string]interface{}
	if json.Unmarshal(b, &devs) != nil {
		return nil
	}
	var out []string
	for mac, d := range devs {
		if st, _ := d["status"].(string); st == "blocked" {
			continue
		}
		on := false
		if ls, ok := d["last_seen"].(float64); ok {
			on = ls > 0 && now-int64(ls) < onlineWindowSec
		} else if v, ok := d["online"].(bool); ok {
			on = v
		}
		if on && len(mac) == 17 {
			out = append(out, strings.ToLower(mac))
		}
	}
	return out
}
