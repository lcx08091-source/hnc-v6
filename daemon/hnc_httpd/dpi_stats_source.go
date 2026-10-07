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
	"regexp"
	"sort"
	"strconv"
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
	// v5.11: 窗口下界取"本地零点"。旧代码用 now.AddDate(0,0,-(days-1)) 当下界
	// —— 那是 N 天前的【此刻】: days=1 时下界就是 now 本身, 今天所有已发生
	// 的行都被丢弃 → range=today 恒全 0(统计页默认源就是 dpi); week/month
	// 首日也只剩当前时刻之后的部分。
	windowStart := localDayStart(now).AddDate(0, 0, -(days - 1))

	byHour := make([]Bucket, 24)
	for i := range byHour {
		byHour[i].Label = fmt.Sprintf("%02d:00", i)
	}
	byDate := map[string]*dayBucket{}
	resolve := macAliasResolver(s.hncDir) // v5.21: mac= 过滤包含合并进来的旧 MAC
	if macFilter != "" {
		macFilter = resolve(macFilter)
	}

	// v5.11: dpid 以 UTC 日期命名 stats.YYYYMMDD.jsonl(output/history.go
	// pathFor), 旧代码按本地日期找文件 → UTC+8 下本地 0-8 点的行落在前一个
	// UTC 日文件里读不到。改为按窗口覆盖的(本地∪UTC)日期集合找文件, 每个
	// 文件只读一次, 再按行时间戳过滤, 不会重复计数。
	for _, dayKey := range dayFileKeys(windowStart, now) {
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
			if macFilter != "" && resolve(row.MAC) != macFilter {
				continue
			}
			ts := time.Unix(row.T, 0).In(loc)
			if ts.Before(windowStart) || ts.After(now) {
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

// localDayStart 返回 t 所在本地日的零点。
func localDayStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// dayFileKeys v5.11: 返回覆盖 [from, to] 时间窗所需的按日文件名键(YYYYMMDD),
// 取本地日期与 UTC 日期的并集并去重、升序。
//
// 背景: dpid 的 stats.YYYYMMDD.jsonl 按 UTC 日期命名, self_attrib.* 按本地
// 日期命名(见 src/dpid/output/history.go trimDailyFiles 注释)。读侧只按
// 其中一种算日期, 在非 UTC 时区必然漏掉窗口一端的文件。并集最多多打开一个
// 文件, 调用方再按行时间戳过滤, 因此既不漏也不重复计数。
func dayFileKeys(from, to time.Time) []string {
	if to.Before(from) {
		from, to = to, from
	}
	seen := map[string]bool{}
	var keys []string
	add := func(start, end time.Time) {
		d := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, start.Location())
		for !d.After(end) {
			k := d.Format("20060102")
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
			d = d.AddDate(0, 0, 1)
		}
	}
	add(from, to)
	add(from.UTC(), to.UTC())
	sort.Strings(keys)
	return keys
}

// onlineHoursDayRE / onlineHoursMACRE v5.11: online_hours.jsonl 坏行兜底解析。
// bin/watchdog.sh 的 `_oh_ts=$(_now_s)` 把变量当命令执行, 写出的行是
// {"t":,"day":"YYYYMMDD","mac":"…"} —— 不是合法 JSON, 旧读侧 Unmarshal 失败
// 即丢弃, /api/online_hours 因此恒为空。聚合只需要 day / mac(/ m)字段,
// 这里对坏行按字段正则提取, 已落盘的历史数据也能恢复。
var (
	onlineHoursDayRE = regexp.MustCompile(`"day"\s*:\s*"([0-9]{8})"`)
	onlineHoursMACRE = regexp.MustCompile(`"mac"\s*:\s*"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"`)
	onlineHoursMinRE = regexp.MustCompile(`"m"\s*:\s*([0-9]+)`)
)

const (
	// onlineLegacyRowMin v5.30 之前的行没有 m 字段: 那时一行 = 一次 ~55 分钟的
	// 采样, 按 60 分钟算(与旧读侧「一行 1 小时」一致, 历史数据不变)。
	onlineLegacyRowMin = 60
	// onlineDayMaxMin 一天最多 24 小时(别名合并后新旧 MAC 同一时段都有记录时不超)。
	onlineDayMaxMin = 24 * 60
)

// onlineMinutesByMAC v5.30 T1a: 读取 run/online_hours.jsonl, 返回每个 mac
// 每天的在线分钟数 {mac: {day: 分钟}}。watchdog 5 分钟采样、按分钟累计,
// 每 ~55 分钟 / 跨日 / 退出时落一行 {"t","day","mac","m"}; 有 m 按 m 算,
// 旧行没有 m 按 onlineLegacyRowMin 算。now 注入(测试不读真实时钟)。
func onlineMinutesByMAC(hncDir string, days int, now time.Time) map[string]map[string]int {
	out := map[string]map[string]int{}
	path := filepath.Join(hncDir, "run", "online_hours.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	cutoff := now.AddDate(0, 0, -days).Format("20060102")
	resolve := macAliasResolver(hncDir) // v5.21: 合并过的旧 MAC 在线时长算到新 MAC 上
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
			M   *int   `json:"m"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			// v5.11: 坏行兜底(见 onlineHoursDayRE 注释)
			dm := onlineHoursDayRE.FindSubmatch(line)
			mm := onlineHoursMACRE.FindSubmatch(line)
			if dm == nil || mm == nil {
				continue
			}
			row.Day = string(dm[1])
			row.MAC = strings.ToLower(string(mm[1]))
			row.M = nil
			if m := onlineHoursMinRE.FindSubmatch(line); m != nil {
				if v, err := strconv.Atoi(string(m[1])); err == nil {
					row.M = &v
				}
			}
		}
		if row.MAC == "" || row.Day < cutoff {
			continue
		}
		mins := onlineLegacyRowMin
		if row.M != nil {
			mins = *row.M
		}
		if mins <= 0 {
			continue
		}
		row.MAC = resolve(strings.ToLower(row.MAC))
		if out[row.MAC] == nil {
			out[row.MAC] = map[string]int{}
		}
		v := out[row.MAC][row.Day] + mins
		if v > onlineDayMaxMin {
			v = onlineDayMaxMin
		}
		out[row.MAC][row.Day] = v
	}
	return out
}

// onlineNowFn /api/online_hours 的「现在」(测试注入, 不读真实时钟)。
var onlineNowFn = time.Now

// onlineHoursFromMinutes /api/online_hours 的 hours 字段(兼容旧前端): 分钟 / 60
// 向下取整 —— 不再「有一行就是 1 小时」; 不足 1 小时的天不出现。
func onlineHoursFromMinutes(mins map[string]map[string]int) map[string]map[string]int {
	out := make(map[string]map[string]int, len(mins))
	for mac, days := range mins {
		for day, m := range days {
			if m < 60 {
				continue
			}
			if out[mac] == nil {
				out[mac] = map[string]int{}
			}
			out[mac][day] = m / 60
		}
	}
	return out
}

// onlineHoursByMAC 按天的在线小时数(= onlineHoursFromMinutes(onlineMinutesByMAC))。
func onlineHoursByMAC(hncDir string, days int) map[string]map[string]int {
	return onlineHoursFromMinutes(onlineMinutesByMAC(hncDir, days, onlineNowFn()))
}

// apiOnlineHours GET /api/online_hours?days=7 — 设备在线时长
// (F5: 家长管控场景"今日在线 X 小时")。
func (s *server) apiOnlineHours(w http.ResponseWriter, r *http.Request) {
	days := 7
	if d := r.URL.Query().Get("days"); d == "30" {
		days = 30
	}
	// v5.30 T1a: online_min = 按天在线分钟(新); hours = 分钟 / 60 向下取整(兼容旧前端)。
	mins := s.simMergeOnlineMinutes(onlineMinutesByMAC(s.hncDir, days, onlineNowFn())) // 模拟环境; 关闭时原样
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"days":       days,
		"hours":      onlineHoursFromMinutes(mins),
		"online_min": mins,
	})
}
