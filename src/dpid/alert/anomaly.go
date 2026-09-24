// Package alert · anomaly traffic detection (rc30.7).
//
// Compares each MAC's traffic in the CURRENT clock-hour against that same
// MAC's average across the SAME clock-hour over the last N days.
//
// Trigger condition:
//
//   current_bytes > baseline_bytes * RatioThreshold
//     AND
//   current_bytes > MinBytes
//
// The MinBytes floor (default 50 MB) prevents tiny absolute volumes from
// firing alerts — early-morning idle traffic can easily be 100× last week
// in ratio but only a few hundred KB, which is noise.
//
// Data source: rc30.4 stats.YYYYMMDD.jsonl files written every 15 min by
// the HistorySampler. Each line:
//   {"t":1700000000,"mac":"aa:bb:cc:...","app_id":"douyin","tx":...,"rx":...}
//
// Read cost: 7 daily files × ~400KB each = ~3 MB worst case. We walk them
// once per 5-min alert tick, so amortized cost is negligible.

package alert

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"hnc.io/dpid/tzlocal"
)

const (
	// How many days of history to use for the baseline. 7 days = a full
	// week; covers the weekday/weekend pattern of a typical user.
	anomalyBaselineDays = 7
)

// historyRow mirrors the JSONL shape from history.go. We don't import that
// package because the alert package must stay free of capture-side deps.
type historyRow struct {
	T     int64  `json:"t"`
	MAC   string `json:"mac"`
	AppID string `json:"app_id"`
	TX    uint64 `json:"tx"`
	RX    uint64 `json:"rx"`
}

// detectAnomalyTraffic walks the last N days of history JSONL files and
// emits unknown_device-style alerts for any MAC whose current-hour total
// exceeds (baseline × ratio) AND a minimum-bytes floor.
//
// Returns the number of alerts emitted. Called from alert.Run() under the
// AnomalyTraffic.Enabled flag.
func detectAnomalyTraffic(cfg Config, uc AlertConfig) (int, error) {
	an := uc.AnomalyTraffic
	if !an.Enabled || an.RatioThreshold <= 0 {
		return 0, nil
	}
	// v5.12: 用真实本地时区(Android 上 time.Local 恒为 UTC, 见 tzlocal 包)。
	now := nowLocal()
	hour := now.Hour()

	// Resolve the history directory. The history sampler writes to
	// HNCDir/run by default in rc30.4, so we mirror that.
	historyDir := filepath.Join(cfg.HNCDir, "run")

	// Step 1: current-hour totals (MAC → bytes summed across all apps).
	curHourStart := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location()).Unix()
	curHourEnd := now.Unix()
	current := map[string]uint64{}
	// v5.12: 窗口改为左闭右开, 右端 +1 让 t==now 的行仍计入当前小时。
	if err := sumByMAC(historyDir, curHourStart, curHourEnd+1, current); err != nil {
		// Probably "today's file doesn't exist yet". Not fatal —
		// nothing to compare against, just exit cleanly.
		return 0, nil
	}
	if len(current) == 0 {
		return 0, nil
	}

	// Step 2: build baseline for the SAME clock-hour over the last 7 days.
	// (Skip "today" — we don't want to bias the baseline with the very
	// observation we're testing.)
	//
	// baseline[mac] = average of per-day sums for that mac's same-hour window.
	dayCounts := map[string]int{}
	dayTotals := map[string]uint64{}
	for offset := 1; offset <= anomalyBaselineDays; offset++ {
		dayStart := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location()).
			AddDate(0, 0, -offset)
		dayEnd := dayStart.Add(time.Hour)
		perDay := map[string]uint64{}
		if err := sumByMAC(historyDir, dayStart.Unix(), dayEnd.Unix(), perDay); err != nil {
			// Day file missing — that day's contribution is zero, just skip
			// (don't count it in the denominator).
			continue
		}
		for mac, b := range perDay {
			dayTotals[mac] += b
			dayCounts[mac]++
		}
	}
	baseline := map[string]float64{}
	for mac, total := range dayTotals {
		n := dayCounts[mac]
		if n == 0 {
			continue
		}
		baseline[mac] = float64(total) / float64(n)
	}

	// Step 3: evaluate. To keep the alert log from getting hammered when a
	// user is genuinely watching Netflix for hours, we use a per-MAC daily
	// dedup ("kind:anomaly_traffic:<mac>:<YYYYMMDD>") via the existing
	// loadRecentAlerts machinery — but with a 24h window instead of the
	// 30min unknown-device cooldown.
	dayBucketCutoff := now.Unix() - 24*3600
	recentAlerts := loadRecentAlerts(cfg.AlertsJSONLPath, dayBucketCutoff)
	emitted := 0
	for mac, curBytes := range current {
		// Need a baseline to compare against. A device that's NEW (no
		// history at all) won't fire here — that's the unknown_device
		// detector's job. We only flag established devices.
		base, ok := baseline[mac]
		if !ok || base <= 0 {
			continue
		}
		minBytes := uint64(an.MinBytes)
		if curBytes < minBytes {
			continue
		}
		ratio := float64(curBytes) / base
		if ratio < an.RatioThreshold {
			continue
		}
		// Per-MAC, per-day dedup.
		if _, alerted := recentAlerts["anomaly_traffic:"+mac]; alerted {
			continue
		}

		// Pull a friendly hostname if hotspotd's devices.json knows one.
		hostname := lookupHostname(cfg.DevicesJSON, mac)
		if hostname == "" {
			hostname = mac
		}
		a := Alert{
			ID:   makeAlertID("anomaly_traffic", mac, now.Unix()),
			Ts:   now.Unix(),
			Kind: "anomaly_traffic",
			MAC:  mac,
			Detail: fmt.Sprintf("%s 当前小时 %s, 比 7 日同时段均值高 %.1f×",
				hostname, formatBytes(curBytes), ratio),
			Extra: map[string]interface{}{
				"current_bytes":  curBytes,
				"baseline_bytes": uint64(base),
				"ratio":          ratio,
				"hour":           hour,
			},
		}
		if err := appendAlert(cfg.AlertsJSONLPath, a); err != nil {
			continue
		}
		emitted++

		// Notification (best-effort, respects quiet hours).
		if !cfg.DisableNotify && !inQuietHours(now, uc.UnknownDevice) {
			title := "HNC · 异常流量"
			body := a.Detail
			_ = postNotification(title, body)
		}
	}
	return emitted, nil
}

// nowLocal v5.12: 告警侧的"现在", 带真实本地时区。可在测试中替换。
var nowLocal = func() time.Time { return time.Now().In(tzlocal.Location()) }

// dayFileKeys v5.12: 返回覆盖 [from, to] 所需的 stats 日文件键(YYYYMMDD),
// 取本地日期与 UTC 日期的并集、去重、升序(与 hnc_httpd v5.11 dayFileKeys 同款)。
// stats.*.jsonl 按 UTC 日期命名(output/history.go pathFor), 调用方只按本地
// 日期找文件时, UTC+8 下本地 0-8 点的行落在前一个 UTC 日文件里就读不到。
// 并集最多多开一个文件, 行再按时间戳过滤, 不漏也不重复计数。
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

// sumByMAC walks the history file(s) that overlap [startTs, endTs) and
// accumulates (tx + rx) by MAC.
//
// v5.12: 旧实现按调用方传入的 dayHint 的"本地日期"找文件, 而文件按 UTC 日期
// 命名 → 东八区本地 0-8 点的窗口读错天(当前小时读不到数据、基线取到别的
// 时段)。改为按窗口覆盖的本地∪UTC 日期集合找文件(dayFileKeys), 并把窗口
// 改为左闭右开 —— 旧的两端闭区间会让恰好落在边界秒的行在相邻两个窗口里各算
// 一次(配额按天分段累加时重复计数)。
func sumByMAC(dir string, startTs, endTs int64, out map[string]uint64) error {
	if endTs <= startTs {
		return nil
	}
	loc := tzlocal.Location()
	from := time.Unix(startTs, 0).In(loc)
	to := time.Unix(endTs-1, 0).In(loc)
	for _, key := range dayFileKeys(from, to) {
		p := filepath.Join(dir, "stats."+key+".jsonl")
		f, err := os.Open(p)
		if err != nil {
			continue // missing day = zero contribution
		}
		// We could use json.Decoder, but JSONL is line-oriented and lots
		// of rows are small; a bufio.Scanner over the file with a hand
		// parser is materially faster for the volumes involved.
		sc := bufio.NewScanner(f)
		// Bump max line size: history rows are small (~120 bytes) but
		// guard against future schema growth.
		sc.Buffer(make([]byte, 0, 8192), 64*1024)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) < 10 {
				continue
			}
			t := jsonExtractInt(line, `"t":`)
			if t < startTs || t >= endTs { // v5.12: 左闭右开
				continue
			}
			mac := jsonExtractString(line, `"mac":"`)
			if mac == "" {
				continue
			}
			tx := jsonExtractUint(line, `"tx":`)
			rx := jsonExtractUint(line, `"rx":`)
			out[mac] += tx + rx
		}
		f.Close()
	}
	return nil
}

// jsonExtractString returns the value of the first occurrence of `key` in
// the form `"key":"value"`. Returns "" if not present. Tolerant of
// surrounding spaces. Does NOT handle escape sequences — none of our
// fields contain them (MACs and IDs are [a-z0-9_:-]).
//
// CR-3 fix: After finding a match with strings.Index, verify that the
// preceding non-whitespace character is '{' or ',' to confirm the match
// is a real JSON key position, not a substring inside a string value.
// When a false match is rejected, we also skip past the enclosing string
// value (looking for the next unescaped '"') so that escaped quotes like
// \" inside JSON values cannot fool subsequent searches.
func jsonExtractString(buf []byte, key string) string {
	s := string(buf)
	searchFrom := 0
	for {
		i := strings.Index(s[searchFrom:], key)
		if i < 0 {
			return ""
		}
		i += searchFrom
		// Verify this is a key position: preceding non-whitespace char
		// should be '{' or ',' (i.e. we are at a real object key, not
		// inside a string value).
		j := i - 1
		if j >= 0 {
			for j >= 0 && (s[j] == ' ' || s[j] == '\n' || s[j] == '\r' || s[j] == '\t') {
				j--
			}
		}
		if j < 0 || s[j] == '{' || s[j] == ',' {
			// This is a key position, extract the value.
			i += len(key)
			end := strings.IndexByte(s[i:], '"')
			if end < 0 {
				return ""
			}
			return s[i : i+end]
		}
		// False match — likely inside a string value. Skip past the
		// match, then advance to the closing '"' of the surrounding
		// string so escaped quotes (\") within values cannot produce
		// false positives on subsequent iterations.
		searchFrom = i + len(key)
		for searchFrom < len(s) && s[searchFrom] != '"' {
			searchFrom++
		}
		if searchFrom < len(s) {
			searchFrom++ // skip past closing '"'
		}
	}
}

// jsonExtractInt returns the value of the first occurrence of `key:` (no
// closing quote, since it's a number). Returns 0 if not present or unparsable.
func jsonExtractInt(buf []byte, key string) int64 {
	s := string(buf)
	i := strings.Index(s, key)
	if i < 0 {
		return 0
	}
	i += len(key)
	// Walk forward to the end of the number.
	j := i
	for j < len(s) && (s[j] == '-' || (s[j] >= '0' && s[j] <= '9')) {
		j++
	}
	if j == i {
		return 0
	}
	v := int64(0)
	neg := false
	for k := i; k < j; k++ {
		if s[k] == '-' {
			// L-4 fix: only accept '-' at the very first position of
			// the number. A '-' anywhere else is invalid — stop parsing.
			if k == i {
				neg = true
				continue
			}
			break // invalid character, stop parsing
		}
		v = v*10 + int64(s[k]-'0')
	}
	if neg {
		return -v
	}
	return v
}

func jsonExtractUint(buf []byte, key string) uint64 {
	v := jsonExtractInt(buf, key)
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// lookupHostname best-effort reads hotspotd's devices.json and returns the
// hostname for the given MAC. Used to make the alert text human-readable.
func lookupHostname(devicesPath, mac string) string {
	b, err := os.ReadFile(devicesPath)
	if err != nil {
		return ""
	}
	// Find `"<mac>":{...` and pull "hostname":"..." within the block.
	key := `"` + mac + `":{`
	i := strings.Index(string(b), key)
	if i < 0 {
		return ""
	}
	tail := string(b[i+len(key):])
	// CR-4 fix: use brace-depth counting to find the correct closing '}'.
	// The device object may contain nested structures (e.g. "ips":[...])
	// so a naive strings.Index(tail, "}") could truncate the block early.
	// String-aware: braces inside JSON string values (e.g. hostname "my}device")
	// are skipped so they cannot corrupt the depth counter.
	depth := 1
	j := 0
	inStr := false
	esc := false
	for j < len(tail) && depth > 0 {
		c := tail[j]
		if inStr {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
		} else {
			if c == '"' {
				inStr = true
			} else if c == '{' {
				depth++
			} else if c == '}' {
				depth--
			}
		}
		if depth > 0 {
			j++
		}
	}
	if depth != 0 {
		return ""
	}
	block := "{" + tail[:j] + "}"
	return jsonExtractString([]byte(block), `"hostname":"`)
}

func formatBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
