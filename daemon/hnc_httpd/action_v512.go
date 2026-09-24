// action_v512.go — v5.12 补齐的功能接口:
//   - hotspot_schedule_set: 定时开关热点 / 只在充电时开热点(执行见 bin/hotspot_schedule.sh)
//   - stale_ttl_set:        离线设备规则的自动清理天数(执行见 bin/cleanup_stale_rules.sh)
//   - GET /api/usage_month: 每台设备本自然月的流量(与月度配额告警同一数据源)

package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var hhmmRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

func actionHotspotScheduleSet(hncDir string, p map[string]string) actionResp {
	for _, k := range []string{"time_enable", "charging_only"} {
		if v, ok := p[k]; ok && v != "true" && v != "false" {
			return actionResp{OK: false, Error: "bad params", Detail: k + " must be true/false"}
		}
	}
	for _, k := range []string{"start", "end"} {
		if v, ok := p[k]; ok && !hhmmRe.MatchString(v) {
			return actionResp{OK: false, Error: "bad params", Detail: k + " must be HH:MM"}
		}
	}
	if p["time_enable"] == "true" && (p["start"] == "" || p["end"] == "") {
		return actionResp{OK: false, Error: "bad params", Detail: "start and end required when time_enable=true"}
	}
	for _, kv := range [][2]string{{"start", "hotspot_time_start"}, {"end", "hotspot_time_end"},
		{"time_enable", "hotspot_time_enable"}, {"charging_only", "hotspot_charging_only"}} {
		v, ok := p[kv[0]]
		if !ok {
			continue
		}
		if rc, out := runBin(hncDir, "json_set.sh", "top", kv[1], v); rc != 0 {
			return actionResp{OK: false, Error: "write failed", Detail: strings.TrimSpace(out)}
		}
	}
	// 规则变了: 清掉边沿状态, 下一轮 watchdog 按新规则重新记录(不会立刻开/关热点)
	_ = os.Remove(filepath.Join(hncDir, "run", "hotspot_schedule.last"))
	return actionResp{OK: true}
}

func actionStaleTTLSet(hncDir string, p map[string]string) actionResp {
	n, err := strconv.Atoi(strings.TrimSpace(p["days"]))
	if err != nil || n < 0 || n > 3650 {
		return actionResp{OK: false, Error: "bad params", Detail: "days must be 0-3650 (0 = never)"}
	}
	if rc, out := runBin(hncDir, "json_set.sh", "top", "stale_rule_ttl_days", strconv.Itoa(n)); rc != 0 {
		return actionResp{OK: false, Error: "write failed", Detail: strings.TrimSpace(out)}
	}
	return actionResp{OK: true}
}

// ── /api/usage_month ─────────────────────────────────────────

type usageCacheT struct {
	mu  sync.Mutex
	at  time.Time
	out map[string]interface{}
}

var usageCache usageCacheT

// apiUsageMonth 汇总本自然月(本地时区 1 号 0 点至今)每台设备 rx/tx。
// 数据源与 src/dpid/alert/quota.go 的月度配额相同: run/stats.YYYYMMDD.jsonl
// (按 UTC 日期命名, 用 dayFileKeys 覆盖本地∪UTC 日期再按行时间戳过滤)。
// 读一个月的文件有一定开销, 结果缓存 60 秒。
func (s *server) apiUsageMonth(w http.ResponseWriter, r *http.Request) {
	usageCache.mu.Lock()
	defer usageCache.mu.Unlock()
	if usageCache.out != nil && time.Since(usageCache.at) < 60*time.Second {
		writeJSON(w, http.StatusOK, usageCache.out)
		return
	}
	now := time.Now()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	type acc struct {
		RX uint64 `json:"rx"`
		TX uint64 `json:"tx"`
	}
	per := map[string]*acc{}
	oldest := int64(0)
	for _, dk := range dayFileKeys(start, now) {
		f, err := os.Open(filepath.Join(s.hncDir, "run", "stats."+dk+".jsonl"))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			var row struct {
				T   int64  `json:"t"`
				MAC string `json:"mac"`
				TX  uint64 `json:"tx"`
				RX  uint64 `json:"rx"`
			}
			if json.Unmarshal(sc.Bytes(), &row) != nil || row.MAC == "" {
				continue
			}
			if row.T < start.Unix() || row.T > now.Unix() {
				continue
			}
			if oldest == 0 || row.T < oldest {
				oldest = row.T
			}
			m := strings.ToLower(row.MAC)
			if per[m] == nil {
				per[m] = &acc{}
			}
			per[m].RX += row.RX
			per[m].TX += row.TX
		}
		f.Close()
	}
	out := map[string]interface{}{
		"month":       now.Format("2006-01"),
		"since":       start.Unix(),
		"oldest_data": oldest, // 若明显晚于 since, 说明月初的数据已被清理(前端据此提示"不完整")
		"devices":     per,
	}
	usageCache.out, usageCache.at = out, now
	writeJSON(w, http.StatusOK, out)
}
