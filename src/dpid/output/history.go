// Package output - history.go: per-client, per-app traffic byte counters
// sampled and appended to daily JSONL files for trend visualization.
//
// Why JSONL (one JSON object per line) instead of a single growing JSON file:
//   1. Append is one write() call, no read-modify-write race
//   2. Reader can stream line-by-line, parse incrementally, no memory spike
//   3. Trivial to rotate by date and trim old files (just delete the file)
//   4. Resilient: a corrupt line (rare, ENOSPC mid-write) doesn't ruin the day
//
// Why deltas instead of cumulative counters:
//   1. Sampler is restart-safe — fresh dpid skips first tick, no baseline issue
//   2. Reader doesn't need to know dpid boot identity to compute reset gaps
//   3. Aggregation is trivial: sum across rows for the time bucket
//
// Per-sample line format:
//   {"t":1700000000,"mac":"aa:bb:cc:dd:ee:ff","app":"douyin","app_id":"douyin","cat":"video","tx":12345,"rx":98765}
//
// t   = sample wall-clock time in seconds since epoch
// mac = client MAC (canonical lower-case)
// app = display name of the app
// app_id = stable rule ID (preferred for joins)
// cat = category (video/im/game/...)
// tx  = bytes the client transmitted during the past sample window
// rx  = bytes the client received during the past sample window
//
// Sampler interval: 15 minutes (96 ticks/day). On a typical 5-client × 10-app
// household this is ~4800 rows/day, ~400 KB. Seven-day retention ≈ 3 MB.

package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Tunables. Exported so the main entrypoint can override for tests, but the
// defaults are what production uses.
var (
	HistoryDir          = "/data/local/hnc/run"
	HistorySampleEvery  = 15 * time.Minute
	HistoryRetainDays   = 7
	HistoryFilePrefix   = "stats."
	HistoryFileSuffix   = ".jsonl"
)

// historySample matches what we serialize to JSONL. Field tags are short to
// keep file size small; we serialize a lot of these.
type historySample struct {
	Ts    int64  `json:"t"`
	MAC   string `json:"mac"`
	App   string `json:"app,omitempty"`
	AppID string `json:"app_id,omitempty"`
	Cat   string `json:"cat,omitempty"`
	TX    uint64 `json:"tx,omitempty"`
	RX    uint64 `json:"rx,omitempty"`
}

// HistorySampler walks Writer.clients on a fixed cadence and writes per-app
// byte deltas to the current day's JSONL file.
type HistorySampler struct {
	w *Writer

	mu       sync.Mutex
	lastSnap map[string]uint64 // composite key "mac\x00app_id" → last cumulative bytes (tx+rx)
	lastTx   map[string]uint64 // separate trackers because we report tx/rx individually
	lastRx   map[string]uint64
	lastTick time.Time
	enabled  bool
}

func NewHistorySampler(w *Writer) *HistorySampler {
	return &HistorySampler{
		w:        w,
		lastSnap: make(map[string]uint64),
		lastTx:   make(map[string]uint64),
		lastRx:   make(map[string]uint64),
		enabled:  true,
	}
}

func (h *HistorySampler) SetEnabled(v bool) {
	h.mu.Lock()
	h.enabled = v
	h.mu.Unlock()
}

// Tick is called by the main ticker goroutine. On the FIRST tick after dpid
// starts (or after this sampler was just created) we only snapshot, don't
// write — we have no baseline to compute deltas against.
func (h *HistorySampler) Tick(now time.Time) {
	h.mu.Lock()
	enabled := h.enabled
	firstTick := h.lastTick.IsZero()
	h.mu.Unlock()

	if !enabled {
		return
	}

	samples := h.collect(now)

	if firstTick {
		// Establish baseline only.
		h.mu.Lock()
		h.lastTick = now
		h.mu.Unlock()
		return
	}

	if len(samples) > 0 {
		if err := h.append(samples, now); err != nil {
			// Log via the writer's path: write a tiny error breadcrumb
			// to a side-channel file so a borked /data partition doesn't
			// stop the sampler. Don't go through standard log.Print because
			// that's already noisy.
			_ = os.WriteFile(filepath.Join(HistoryDir, "stats.write_err"),
				[]byte(now.Format(time.RFC3339)+": "+err.Error()+"\n"), 0o644)
		}
	}

	h.mu.Lock()
	h.lastTick = now
	h.mu.Unlock()

	// Garbage-collect old files cheap: stat-only of recent expected paths,
	// not a full readdir scan.
	h.trimOldFiles(now)
}

// collect walks the Writer's per-client app aggregates, computes byte deltas
// since the last tick, and returns the rows to append. Holds the writer's
// mutex for as little time as possible.
func (h *HistorySampler) collect(now time.Time) []historySample {
	h.w.mu.Lock()
	type snapRow struct {
		mac, appID, app, cat string
		tx, rx               uint64
	}
	rows := make([]snapRow, 0, 64)
	for _, c := range h.w.clients {
		if c == nil {
			continue
		}
		mac := normalizeHistMAC(c.ClientMAC)
		if mac == "" {
			continue
		}
		if c.Apps == nil {
			continue
		}
		for appID, ls := range c.Apps {
			if ls == nil {
				continue
			}
			rows = append(rows, snapRow{
				mac:   mac,
				appID: appID,
				app:   ls.Name,
				cat:   ls.Category,
				tx:    ls.TxBytes,
				rx:    ls.RxBytes,
			})
		}
	}
	h.w.mu.Unlock()

	ts := now.Unix()
	out := make([]historySample, 0, len(rows))

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range rows {
		key := r.mac + "\x00" + r.appID
		prevTx := h.lastTx[key]
		prevRx := h.lastRx[key]
		var dTx, dRx uint64
		switch {
		case r.tx >= prevTx:
			dTx = r.tx - prevTx
		default:
			// Counter went backwards — client gone and re-attached, or
			// dpid's per-client struct was rebuilt. Treat as fresh:
			// don't emit a backwards delta, just reset baseline.
			dTx = 0
		}
		switch {
		case r.rx >= prevRx:
			dRx = r.rx - prevRx
		default:
			dRx = 0
		}
		h.lastTx[key] = r.tx
		h.lastRx[key] = r.rx
		if dTx == 0 && dRx == 0 {
			// Skip rows with no activity in the window. Saves bytes.
			continue
		}
		out = append(out, historySample{
			Ts:    ts,
			MAC:   r.mac,
			App:   r.app,
			AppID: r.appID,
			Cat:   r.cat,
			TX:    dTx,
			RX:    dRx,
		})
	}
	return out
}

// append writes a batch of samples to today's JSONL file.
func (h *HistorySampler) append(samples []historySample, now time.Time) error {
	if len(samples) == 0 {
		return nil
	}
	if err := os.MkdirAll(HistoryDir, 0o755); err != nil {
		return err
	}
	path := h.pathFor(now)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := bufio.NewWriter(f)
	for _, s := range samples {
		b, err := json.Marshal(s)
		if err != nil {
			continue
		}
		bw.Write(b)
		bw.WriteByte('\n')
	}
	return bw.Flush()
}

// pathFor returns the day's JSONL path. Day boundary is local-time midnight
// (Asia/Shanghai for typical use). We use UTC to match other HNC files —
// the visualization layer is timezone-aware.
func (h *HistorySampler) pathFor(t time.Time) string {
	day := t.UTC().Format("20060102")
	return filepath.Join(HistoryDir, HistoryFilePrefix+day+HistoryFileSuffix)
}

// trimOldFiles deletes JSONL files older than HistoryRetainDays. Iterates
// HistoryRetainDays+1 → 30 by name — bounded constant work, no readdir.
func (h *HistorySampler) trimOldFiles(now time.Time) {
	// Walk a safe window: anything from (retain+1) up to 30 days back.
	// We don't go further back; if dpid crashed for a month, manual cleanup.
	for back := HistoryRetainDays + 1; back <= 30; back++ {
		t := now.UTC().AddDate(0, 0, -back)
		p := h.pathFor(t)
		// Best-effort, no error handling — missing is the common case.
		_ = os.Remove(p)
	}
}

var histMacRe = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)

// normalizeHistMAC lower-cases and validates the MAC address. Bad MACs are
// dropped (return "") so we never have inconsistent keys in history files.
func normalizeHistMAC(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !histMacRe.MatchString(mac) {
		return ""
	}
	return mac
}

// PathForDate is exported for the hnc_httpd reader. Takes a UTC date and
// returns the expected file path.
func PathForDate(t time.Time) string {
	day := t.UTC().Format("20060102")
	return filepath.Join(HistoryDir, HistoryFilePrefix+day+HistoryFileSuffix)
}

// _unused silences "fmt imported but not used" once we drop debug helpers.
var _ = fmt.Sprintf
