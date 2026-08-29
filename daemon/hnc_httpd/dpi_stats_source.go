// dpi_stats_source.go — 统计链路收口 (v5.10.0, O2)。
//
// 背景: "今日流量"柱状图与"应用历史"页此前走两条独立链路 ——
//   legacy: bin/stats_sample.sh 每 5min 从 iptables 计数采样 →
//           data/stats_raw.jsonl → /api/stats
//   dpi:    HistorySampler 每 15min 按应用归因写 →
//           run/stats.YYYYMMDD.jsonl → /api/dpi_history
// 两个口径对不上(iptables 全量 vs DPI 只算被归因流量), 用户困惑。
// 本文件让 /api/stats?source=dpi 直接聚合 DPI 归因链, 统计页默认切到它,
// 数字与应用历史/设备曲线完全同源; legacy 链保留可选。
//
// 关键语义: 不能复用 aggregate()/aggregateToday() —— 它们是【计数器 delta
// 语义】(legacy raw 是 iptables 累计计数器, 按 mac 排序后相邻做差), 而
// HistorySampler 的行本身就是 15min 流量增量, 直接按小时/按天累加即可。

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// apiStatsDPI 处理 /api/stats?source=dpi。
func (s *server) apiStatsDPI(w http.ResponseWriter, r *http.Request, rangeParam, macFilter string) {
	buckets, daily := s.dpiAggregate(rangeParam, macFilter)
	resp := map[string]interface{}{
		"range":         rangeParam,
		"mac":           macFilter,
		"source":        "dpi",
		"buckets":       buckets,
		"daily_buckets": daily,
	}
	if len(daily) > 0 {
		var tr, tx int64
		for _, b := range daily {
			tr += b.RX
			tx += b.TX
		}
		resp["total_rx"] = tr
		resp["total_tx"] = tx
	}
	writeJSON(w, http.StatusOK, resp)
}

// dayBucket 按天聚合的流量桶(内部使用)。
type dayBucket struct {
	RX int64
	TX int64
}

// dpiAggregate 按 range 聚合 DPI 归因链, 产出与 legacy /api/stats 同形的
// buckets。today → 24 个小时桶(行是 15min 增量, 直接按小时累加);
// week/month/all → 按日期桶。daily 桶同时返回供调用方使用。
func (s *server) dpiAggregate(rangeParam, macFilter string) ([]Bucket, []Bucket) {
	days := 1
	switch rangeParam {
	case "week":
		days = 7
	case "month":
		days = 30
	case "all":
		days = 90
	}

	now := time.Now()
	loc := now.Location()
	statsDir := filepath.Join(s.hncDir, "run")

	byHour := make([]Bucket, 24)
	for i := range byHour {
		byHour[i].Label = fmt.Sprintf("%02d:00", i)
	}
	byDate := map[string]*dayBucket{}

	for d := 0; d < days; d++ {
		day := now.AddDate(0, 0, -d)
		dayKey := day.Format("20060102")
		path := filepath.Join(statsDir, "stats."+dayKey+".jsonl")
		f, err := os.Open(path)
		if err != nil {
			continue // 缺失的天 = 零贡献
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) < 10 {
				continue
			}
			var row struct {
				T     int64  `json:"t"`
				MAC   string `json:"mac"`
				AppID string `json:"app_id"`
				TX    uint64 `json:"tx"`
				RX    uint64 `json:"rx"`
			}
			if err := json.Unmarshal(line, &row); err != nil {
				continue
			}
			if macFilter != "" && strings.ToLower(row.MAC) != macFilter {
				continue
			}
			ts := time.Unix(row.T, 0).In(loc)
			if ts.Before(now.AddDate(0, 0, -(days - 1))) || ts.After(now) {
				continue
			}
			if rangeParam == "today" {
				h := ts.Hour()
				byHour[h].RX += int64(row.RX)
				byHour[h].TX += int64(row.TX)
			}
			dk := ts.Format("2006-01-02")
			if byDate[dk] == nil {
				byDate[dk] = &dayBucket{}
			}
			byDate[dk].RX += int64(row.RX)
			byDate[dk].TX += int64(row.TX)
		}
		f.Close()
	}

	if rangeParam == "today" {
		return byHour, nil
	}

	out := make([]Bucket, 0, days)
	for d := days - 1; d >= 0; d-- {
		dk := now.AddDate(0, 0, -d).Format("2006-01-02")
		b := Bucket{Label: dk[5:]}
		if agg, ok := byDate[dk]; ok {
			b.RX = agg.RX
			b.TX = agg.TX
		}
		out = append(out, b)
	}
	daily := make([]Bucket, 0, len(byDate))
	for dk, agg := range byDate {
		daily = append(daily, Bucket{Label: dk, RX: agg.RX, TX: agg.TX})
	}
	sort.Slice(daily, func(i, j int) bool { return daily[i].Label < daily[j].Label })
	return out, daily
}

// onlineHoursByMAC 读取 run/online_hours.jsonl(watchdog 每小时采样), 按天
// 去重后返回每个 mac 的在线小时数: {mac: {day: 小时数}}。
func onlineHoursByMAC(hncDir string, days int) map[string]map[string]int {
	out := map[string]map[string]int{}
	path := filepath.Join(hncDir, "run", "online_hours.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	cutoff := time.Now().AddDate(0, 0, -days).Format("20060102")
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 8192), 256*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) < 10 {
			continue
		}
		var row struct {
			Day string `json:"day"`
			MAC string `json:"mac"`
		}
		if err := json.Unmarshal(line, &row); err != nil || row.MAC == "" {
			continue
		}
		if row.Day < cutoff {
			continue
		}
		if out[row.MAC] == nil {
			out[row.MAC] = map[string]int{}
		}
		out[row.MAC][row.Day]++ // 每天最多 24 次采样 → 计数即小时数
	}
	return out
}

// apiOnlineHours GET /api/online_hours?days=7 — 设备在线小时数
// (F5: 家长管控场景"今日在线 X 小时")。
func (s *server) apiOnlineHours(w http.ResponseWriter, r *http.Request) {
	days := 7
	if d := r.URL.Query().Get("days"); d == "30" {
		days = 30
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"days":  days,
		"hours": onlineHoursByMAC(s.hncDir, days),
	})
}
