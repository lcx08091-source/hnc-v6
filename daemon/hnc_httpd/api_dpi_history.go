// rc30.4: traffic history readout.
//
// dpid emits one JSONL row per (15-min tick, client, app) to:
//
//	$HNC_DIR/run/stats.YYYYMMDD.jsonl
//
// This handler reads the requested number of days (default: today only,
// max: 7), aggregates rows server-side into two views the UI uses directly:
//
//  1. by_app:  pie-chart input { app_id -> {name, cat, tx, rx} }
//  2. by_hour: 24-hour line-chart input [{hour, tx, rx}, ...] (hour-of-day,
//     local time, summed across all clients)
//  3. by_client_app: per-client breakdown { mac -> { app_id -> {name, tx, rx} } }
//
// The raw samples are NOT returned by default (would be ~5000 rows for a
// week × small household). Pass `raw=1` to include them — useful for tools.
package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	statsFilePrefix = "stats."
	statsFileSuffix = ".jsonl"
	statsDirRel     = "run"
	defaultDays     = 1
	maxDays         = 7
)

// histRow matches the on-disk JSONL schema written by dpid/output/history.go
type histRow struct {
	Ts    int64  `json:"t"`
	MAC   string `json:"mac"`
	App   string `json:"app,omitempty"`
	AppID string `json:"app_id,omitempty"`
	Cat   string `json:"cat,omitempty"`
	TX    uint64 `json:"tx,omitempty"`
	RX    uint64 `json:"rx,omitempty"`
}

type appBucket struct {
	Name string `json:"name"`
	Cat  string `json:"cat,omitempty"`
	TX   uint64 `json:"tx"`
	RX   uint64 `json:"rx"`
}

type hourBucket struct {
	Hour int    `json:"hour"`
	TX   uint64 `json:"tx"`
	RX   uint64 `json:"rx"`
}

type clientAppRow struct {
	AppID string `json:"app_id"`
	Name  string `json:"name"`
	Cat   string `json:"cat,omitempty"`
	TX    uint64 `json:"tx"`
	RX    uint64 `json:"rx"`
}

type clientBucket struct {
	MAC   string         `json:"mac"`
	Total uint64         `json:"total"`
	Apps  []clientAppRow `json:"apps"`
}

func (s *server) apiDPIHistory(w http.ResponseWriter, r *http.Request) {
	// Parse `days` (default 1, capped to maxDays).
	days := defaultDays
	if q := strings.TrimSpace(r.URL.Query().Get("days")); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 {
			days = v
		}
	}
	if days > maxDays {
		days = maxDays
	}

	includeRaw := r.URL.Query().Get("raw") == "1"

	now := time.Now()
	statsDir := filepath.Join(s.hncDir, statsDirRel)

	// Collect rows across the requested window.
	rows := make([]histRow, 0, 1024)
	for d := 0; d < days; d++ {
		t := now.AddDate(0, 0, -d)
		path := filepath.Join(statsDir, statsFilePrefix+t.UTC().Format("20060102")+statsFileSuffix)
		readRows := readHistJSONL(path)
		rows = append(rows, readRows...)
	}

	// Aggregation pass.
	byApp := map[string]*appBucket{} // app_id -> bucket
	byHour := make([]hourBucket, 24) // hour-of-day local time
	for i := range byHour {
		byHour[i].Hour = i
	}
	byClient := map[string]map[string]*appBucket{} // mac -> app_id -> bucket
	var totalTx, totalRx uint64

	for _, row := range rows {
		// by_app
		if row.AppID != "" {
			b := byApp[row.AppID]
			if b == nil {
				b = &appBucket{Name: row.App, Cat: row.Cat}
				byApp[row.AppID] = b
			}
			b.TX += row.TX
			b.RX += row.RX
		}
		// by_hour: local-time hour of the row's timestamp
		t := time.Unix(row.Ts, 0).Local()
		h := t.Hour()
		if h >= 0 && h < 24 {
			byHour[h].TX += row.TX
			byHour[h].RX += row.RX
		}
		// by_client.app
		if row.MAC != "" && row.AppID != "" {
			perClient := byClient[row.MAC]
			if perClient == nil {
				perClient = map[string]*appBucket{}
				byClient[row.MAC] = perClient
			}
			b := perClient[row.AppID]
			if b == nil {
				b = &appBucket{Name: row.App, Cat: row.Cat}
				perClient[row.AppID] = b
			}
			b.TX += row.TX
			b.RX += row.RX
		}
		totalTx += row.TX
		totalRx += row.RX
	}

	// Convert by_client to a sorted, capped slice for serialization.
	clientList := make([]clientBucket, 0, len(byClient))
	for mac, apps := range byClient {
		cb := clientBucket{MAC: mac}
		for id, b := range apps {
			cb.Apps = append(cb.Apps, clientAppRow{AppID: id, Name: b.Name, Cat: b.Cat, TX: b.TX, RX: b.RX})
			cb.Total += b.TX + b.RX
		}
		sort.Slice(cb.Apps, func(i, j int) bool {
			return (cb.Apps[i].TX + cb.Apps[i].RX) > (cb.Apps[j].TX + cb.Apps[j].RX)
		})
		// Cap per-client app list at 10 to keep payload small. The UI shows
		// the top-N anyway; clients with 50+ apps don't render well.
		if len(cb.Apps) > 10 {
			cb.Apps = cb.Apps[:10]
		}
		clientList = append(clientList, cb)
	}
	sort.Slice(clientList, func(i, j int) bool {
		return clientList[i].Total > clientList[j].Total
	})

	// by_app as a sorted slice with the app_id as the key field.
	type appRow struct {
		ID   string `json:"app_id"`
		Name string `json:"name"`
		Cat  string `json:"cat,omitempty"`
		TX   uint64 `json:"tx"`
		RX   uint64 `json:"rx"`
	}
	appList := make([]appRow, 0, len(byApp))
	for id, b := range byApp {
		appList = append(appList, appRow{ID: id, Name: b.Name, Cat: b.Cat, TX: b.TX, RX: b.RX})
	}
	sort.Slice(appList, func(i, j int) bool {
		return (appList[i].TX + appList[i].RX) > (appList[j].TX + appList[j].RX)
	})

	resp := map[string]interface{}{
		"ok":             true,
		"generated_at":   now.Unix(),
		"days_requested": days,
		"window_start":   now.AddDate(0, 0, -days+1).UTC().Format("2006-01-02"),
		"window_end":     now.UTC().Format("2006-01-02"),
		"sample_count":   len(rows),
		"total_tx":       totalTx,
		"total_rx":       totalRx,
		"by_app":         appList,
		"by_hour":        byHour,
		"by_client":      clientList,
	}
	if includeRaw {
		resp["raw"] = rows
	}
	writeJSON(w, http.StatusOK, resp)
}

// readHistJSONL streams the JSONL file line-by-line, parsing each row.
// Returns an empty slice on missing file / parse errors — never panics.
// Bounded by file size, not row count: a 10 MB cap is enforced (typical
// is <500 KB/day).
func readHistJSONL(path string) []histRow {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil {
		if st.Size() > 10*1024*1024 {
			// Truncate read at 10 MB. Better to under-report than OOM.
			return nil
		}
	}
	out := make([]histRow, 0, 256)
	sc := bufio.NewScanner(f)
	// Allow longer lines than the default 64 KB — paranoid; rows are ~100 B.
	sc.Buffer(make([]byte, 0, 4096), 256*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r histRow
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out
}
