// stats_days.go — 按天文件的统计辅助(本地日零点 / UTC 命名的 run/stats.YYYYMMDD.jsonl
// 文件集合 / 在线分钟)。
//
// v5.10.0 曾让 /api/stats?source=dpi 直接聚合 DPI 归因链(本文件原名
// dpi_stats_source.go), 但界面一直用 legacy(iptables 采样, data/stats_raw.jsonl),
// dpi 那条只有测试在调。v5.33 删掉了第二个统计源, source=dpi 与历史的
// source=shadow 一样按 legacy 处理; 应用口径的流量走 /api/dpi_history。

package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

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
