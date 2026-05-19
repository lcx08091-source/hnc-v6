// Package alert handles HNC unauthorized-device detection and notification
// persistence. It is consumed by hnc_watchdog on a 5-minute cadence:
//
//  1. Read hotspotd's devices.json (current active MACs).
//  2. Diff against data/known_devices.json (everything ever observed).
//  3. For each new MAC, emit an "unknown_device" alert.
//  4. Append the alert to run/alerts.jsonl.
//  5. Best-effort: post an Android system notification via `cmd notification`.
//
// Why JSONL for alerts: append-only, no read-modify-write races, easy to
// stream from /api/alerts, trivial to truncate when older than 30 days.
//
// Why a separate known_devices.json instead of inferring "known" from
// device_names.json (rc30.2 manual rename) and hostname_cache.json (DHCP
// observations)? Those answer "have we ever resolved a name for this MAC?"
// — not "has the user explicitly acknowledged this device?". An unnamed
// device discovered via OUI fallback ("Xiaomi 设备") is still unknown
// until the user confirms it.
//
// MVP scope (rc30.5): unknown-device detection only. The anomalyTraffic
// and monthlyQuota functions exist as no-op stubs so the JSON schema and
// supervisor wiring don't need to change when those land in a later rc.
package alert

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ──────────── config and storage paths ────────────

type Config struct {
	HNCDir string
	// Path overrides (mostly for tests). Defaults are derived from HNCDir.
	DevicesJSON      string // hotspotd output
	KnownDevicesPath string // our acknowledged-MAC ledger
	AlertsJSONLPath  string // append-only alert log
	AlertsConfigPath string // user prefs (enabled, quiet hours, etc.)
	// Notification posting can be disabled in tests / when running outside Android.
	DisableNotify bool
}

func NewConfig(hncDir string) Config {
	return Config{
		HNCDir:           hncDir,
		DevicesJSON:      filepath.Join(hncDir, "data", "devices.json"),
		KnownDevicesPath: filepath.Join(hncDir, "data", "known_devices.json"),
		AlertsJSONLPath:  filepath.Join(hncDir, "run", "alerts.jsonl"),
		AlertsConfigPath: filepath.Join(hncDir, "data", "alerts_config.json"),
	}
}

// ──────────── alert record ────────────

type Alert struct {
	ID     string                 `json:"id"`
	Ts     int64                  `json:"ts"`
	Kind   string                 `json:"kind"` // "unknown_device" | "anomaly_traffic" | "monthly_quota"
	MAC    string                 `json:"mac,omitempty"`
	IP     string                 `json:"ip,omitempty"`
	Detail string                 `json:"detail,omitempty"`
	Extra  map[string]interface{} `json:"extra,omitempty"`
}

// ──────────── user preferences ────────────

type AlertConfig struct {
	Enabled        bool          `json:"enabled"`
	UnknownDevice  UnknownDevice `json:"unknown_device"`
	AnomalyTraffic AnomalyCfg    `json:"anomaly_traffic"`
	MonthlyQuota   QuotaCfg      `json:"monthly_quota"`
}

type UnknownDevice struct {
	Enabled bool `json:"enabled"`
	// QuietHours suppresses notifications during this hour window
	// (local time). Inclusive start, exclusive end. [0,0] = no quiet time.
	QuietHourStart int `json:"quiet_hour_start"`
	QuietHourEnd   int `json:"quiet_hour_end"`
	// Per-MAC re-alert cooldown. Default 30 min — if user dismissed an
	// unknown device once but didn't mark it known, don't spam again.
	MinIntervalSec int `json:"min_interval_sec"`
}

type AnomalyCfg struct {
	Enabled        bool    `json:"enabled"`
	RatioThreshold float64 `json:"ratio_threshold"` // current / baseline
	MinBytes       int64   `json:"min_bytes"`       // floor to avoid alerts on tiny absolute volumes
}

type QuotaCfg struct {
	Enabled    bool  `json:"enabled"`
	LimitBytes int64 `json:"limit_bytes"`
	WarnAtPct  int   `json:"warn_at_pct"`
}

// DefaultConfig is what we ship: notifications on for unknown devices,
// 30-minute per-MAC cooldown, quiet 23:00–07:00 (so a midnight visitor
// connecting doesn't ping you in your sleep).
func DefaultConfig() AlertConfig {
	return AlertConfig{
		Enabled: true,
		UnknownDevice: UnknownDevice{
			Enabled:        true,
			QuietHourStart: 23,
			QuietHourEnd:   7,
			MinIntervalSec: 1800,
		},
		AnomalyTraffic: AnomalyCfg{
			Enabled:        true, // rc30.7: default on now that the detector is field-tested
			RatioThreshold: 3.0,
			MinBytes:       52 * 1024 * 1024, // 50 MB
		},
		MonthlyQuota: QuotaCfg{
			Enabled:    false, // off by default — user has to set their cap
			LimitBytes: 0,
			WarnAtPct:  80,
		},
	}
}

func LoadConfig(path string) AlertConfig {
	cfg := DefaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	var stored AlertConfig
	if err := json.Unmarshal(b, &stored); err != nil {
		return cfg
	}
	// Detection of "user has configured this section" uses a sentinel
	// non-zero numeric field. Because Go can't distinguish a JSON-absent
	// bool from a JSON-false bool without going to *bool everywhere, we
	// require the user to write at least one positive numeric value to
	// signal "I configured this section" — then we trust their flags.
	//
	//   UnknownDevice  → MinIntervalSec > 0
	//   AnomalyTraffic → RatioThreshold > 0
	//   MonthlyQuota   → LimitBytes > 0
	//
	// In practice this is enforced by the WebUI: when the user toggles a
	// section on/off the WebUI writes the full section (with defaults if
	// it had to fill them in), so the sentinel is always present.
	if stored.UnknownDevice.MinIntervalSec > 0 {
		cfg.UnknownDevice = stored.UnknownDevice
	}
	if stored.AnomalyTraffic.RatioThreshold > 0 {
		cfg.AnomalyTraffic = stored.AnomalyTraffic
	}
	if stored.MonthlyQuota.LimitBytes > 0 {
		cfg.MonthlyQuota = stored.MonthlyQuota
	}
	// Top-level "Enabled" is a master switch. Default is true, so we only
	// turn it off if the user explicitly disabled it AND configured at
	// least one section (proving it's a deliberate file, not a zero-value
	// accident on a brand new install).
	if !stored.Enabled && (stored.UnknownDevice.MinIntervalSec > 0 ||
		stored.AnomalyTraffic.RatioThreshold > 0 || stored.MonthlyQuota.LimitBytes > 0) {
		cfg.Enabled = false
	}
	return cfg
}

// ──────────── known-devices ledger ────────────

type knownEntry struct {
	FirstSeen     int64 `json:"first_seen"`
	MarkedKnownAt int64 `json:"marked_known_at,omitempty"`
}

type knownFile struct {
	Version int                    `json:"version"`
	MACs    map[string]*knownEntry `json:"macs"`
}

var ledgerMu sync.Mutex

func loadKnownLedger(path string) *knownFile {
	b, err := os.ReadFile(path)
	if err != nil {
		return &knownFile{Version: 1, MACs: map[string]*knownEntry{}}
	}
	var f knownFile
	if err := json.Unmarshal(b, &f); err != nil {
		return &knownFile{Version: 1, MACs: map[string]*knownEntry{}}
	}
	if f.MACs == nil {
		f.MACs = map[string]*knownEntry{}
	}
	return &f
}

func saveKnownLedger(path string, f *knownFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// MarkKnown adds the given MAC to the known-devices ledger. Idempotent.
// Used by the WebUI ack flow ("起名" / "忽略" buttons).
func MarkKnown(cfg Config, mac string) error {
	mac = normalizeMAC(mac)
	if mac == "" {
		return errors.New("invalid mac")
	}
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	f := loadKnownLedger(cfg.KnownDevicesPath)
	if e, ok := f.MACs[mac]; ok {
		if e.MarkedKnownAt == 0 {
			e.MarkedKnownAt = time.Now().Unix()
		}
	} else {
		now := time.Now().Unix()
		f.MACs[mac] = &knownEntry{FirstSeen: now, MarkedKnownAt: now}
	}
	return saveKnownLedger(cfg.KnownDevicesPath, f)
}

// ──────────── devices.json reader ────────────

type hotspotDev struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	HostSrc  string `json:"hostname_src"`
	LastSeen int64  `json:"last_seen"`
	Status   string `json:"status"`
}

func readDevicesJSON(path string) map[string]hotspotDev {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil
	}
	m := map[string]hotspotDev{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

// ──────────── alert log writer ────────────

func appendAlert(path string, a Alert) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

// makeAlertID derives a stable-ish ID from kind+mac+coarse-timestamp.
// Used for dedup if the WebUI gets two GETs at once.
func makeAlertID(kind, mac string, ts int64) string {
	// One-hour resolution is fine: two alerts of the same kind for the
	// same MAC within the same hour are functionally the same event.
	bucket := ts - (ts % 3600)
	return fmt.Sprintf("%s_%s_%d", kind, strings.ReplaceAll(mac, ":", ""), bucket)
}

// ──────────── notification posting (Android best-effort) ────────────

// postNotification tries to surface the alert as an Android system
// notification. Returns nil on success, error on failure — the caller
// must NOT treat failure as fatal; we always have the in-app alert log.
//
// We try `cmd notification post` first (Android 8+, root required, works on
// AOSP/Pixel and most GKI ROMs). Some MIUI / ColorOS builds reject this
// call. There's no clean fallback that works everywhere, so we just log
// and rely on the WebUI's bell-badge UX.
func postNotification(title, body string) error {
	cmd := exec.Command("cmd", "notification", "post",
		"-S", "bigtext",
		"-t", title,
		"hnc_alert",
		body)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cmd notification: %v (out=%q)", err, string(out))
	}
	return nil
}

// ──────────── main detection entry point ────────────

// Run executes one detection pass. Idempotent. Returns the number of new
// alerts emitted (useful for tests and watchdog logging).
//
// Designed to be cheap when nothing has changed (no new MACs) — that's the
// common case, called every 5 min.
func Run(cfg Config) (int, error) {
	uc := LoadConfig(cfg.AlertsConfigPath)
	if !uc.Enabled {
		return 0, nil
	}

	emitted := 0
	if uc.UnknownDevice.Enabled {
		n, err := detectUnknownDevices(cfg, uc)
		if err != nil {
			return emitted, err
		}
		emitted += n
	}
	// rc30.7: anomaly traffic detection (off by default, opt-in).
	if uc.AnomalyTraffic.Enabled {
		n, err := detectAnomalyTraffic(cfg, uc)
		if err != nil {
			return emitted, err
		}
		emitted += n
	}
	// Future: detectMonthlyQuota.
	return emitted, nil
}

func detectUnknownDevices(cfg Config, uc AlertConfig) (int, error) {
	devs := readDevicesJSON(cfg.DevicesJSON)
	if len(devs) == 0 {
		return 0, nil
	}

	ledgerMu.Lock()
	ledger := loadKnownLedger(cfg.KnownDevicesPath)
	ledgerMu.Unlock()

	now := time.Now().Unix()
	emitted := 0
	dirty := false

	// First, find the cooldown window for re-alerting the same MAC.
	cooldown := int64(uc.UnknownDevice.MinIntervalSec)
	if cooldown <= 0 {
		cooldown = 1800
	}
	recentAlerts := loadRecentAlerts(cfg.AlertsJSONLPath, now-cooldown)

	for mac, d := range devs {
		mac = normalizeMAC(mac)
		if mac == "" {
			continue
		}
		// Don't alert on blocked devices — user has already taken action.
		if d.Status == "blocked" {
			continue
		}
		// Already in ledger? Not unknown.
		if e, exists := ledger.MACs[mac]; exists {
			// Refresh first-seen if missing.
			if e.FirstSeen == 0 {
				e.FirstSeen = now
				dirty = true
			}
			continue
		}
		// New to us. Add to ledger (so we only alert once for this MAC
		// even before user explicitly marks-known).
		ledger.MACs[mac] = &knownEntry{FirstSeen: now}
		dirty = true

		// Recently alerted? Skip the noise.
		if _, alerted := recentAlerts["unknown_device:"+mac]; alerted {
			continue
		}

		// Build alert.
		hostname := d.Hostname
		if hostname == "" || d.HostSrc == "mac" {
			hostname = "未识别设备"
		}
		a := Alert{
			ID:     makeAlertID("unknown_device", mac, now),
			Ts:     now,
			Kind:   "unknown_device",
			MAC:    mac,
			IP:     d.IP,
			Detail: hostname,
			Extra: map[string]interface{}{
				"hostname_src": d.HostSrc,
			},
		}
		if err := appendAlert(cfg.AlertsJSONLPath, a); err != nil {
			// Best-effort. Continue with next MAC.
			continue
		}
		emitted++

		// Try to post system notification — only if not in quiet hours.
		if !cfg.DisableNotify && !inQuietHours(time.Now(), uc.UnknownDevice) {
			title := "HNC · 陌生设备"
			body := fmt.Sprintf("%s (%s) 已连入热点", hostname, mac)
			_ = postNotification(title, body)
			// We intentionally ignore the error: the in-app alert is
			// the source of truth; system notifications are bonus.
		}
	}

	if dirty {
		ledgerMu.Lock()
		_ = saveKnownLedger(cfg.KnownDevicesPath, ledger)
		ledgerMu.Unlock()
	}
	return emitted, nil
}

// loadRecentAlerts streams the last ~50 KB of the alerts file and returns
// a set of (kind:mac) keys that were alerted on after `since`. Used for
// per-MAC cooldown. We read from the tail so the cost is bounded regardless
// of how large the alerts file has grown.
func loadRecentAlerts(path string, since int64) map[string]struct{} {
	out := map[string]struct{}{}
	st, err := os.Stat(path)
	if err != nil {
		return out
	}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	const tailWindow = 50 * 1024
	offset := int64(0)
	if st.Size() > tailWindow {
		offset = st.Size() - tailWindow
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return out
	}
	buf := make([]byte, st.Size()-offset)
	if _, err := f.Read(buf); err != nil {
		return out
	}
	// We may have started mid-line if offset > 0. Skip until the first newline.
	start := 0
	if offset > 0 {
		for start < len(buf) && buf[start] != '\n' {
			start++
		}
		if start < len(buf) {
			start++
		}
	}
	for start < len(buf) {
		nl := -1
		for j := start; j < len(buf); j++ {
			if buf[j] == '\n' {
				nl = j
				break
			}
		}
		if nl < 0 {
			nl = len(buf)
		}
		line := buf[start:nl]
		start = nl + 1
		if len(line) == 0 {
			continue
		}
		var a Alert
		if err := json.Unmarshal(line, &a); err != nil {
			continue
		}
		if a.Ts < since {
			continue
		}
		out[a.Kind+":"+a.MAC] = struct{}{}
	}
	return out
}

func inQuietHours(now time.Time, u UnknownDevice) bool {
	if u.QuietHourStart == u.QuietHourEnd {
		return false
	}
	h := now.Hour()
	// Wrap-around (e.g. 23 → 7).
	if u.QuietHourStart > u.QuietHourEnd {
		return h >= u.QuietHourStart || h < u.QuietHourEnd
	}
	return h >= u.QuietHourStart && h < u.QuietHourEnd
}

func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 17 {
		return ""
	}
	for i, c := range s {
		switch i {
		case 2, 5, 8, 11, 14:
			if c != ':' && c != '-' {
				return ""
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return ""
			}
		}
	}
	return strings.ReplaceAll(s, "-", ":")
}

// ──────────── helpers exported for hnc_httpd ────────────

// ListRecent reads alerts from the JSONL file, newest first, up to `limit`.
// Bounded read (4 MB cap). Used by /api/alerts.
func ListRecent(cfg Config, limit int) ([]Alert, error) {
	if limit <= 0 {
		limit = 100
	}
	st, err := os.Stat(cfg.AlertsJSONLPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	const maxRead = 4 * 1024 * 1024
	offset := int64(0)
	if st.Size() > maxRead {
		offset = st.Size() - maxRead
	}
	f, err := os.Open(cfg.AlertsJSONLPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, 0); err != nil {
		return nil, err
	}
	buf := make([]byte, st.Size()-offset)
	if _, err := f.Read(buf); err != nil {
		return nil, err
	}
	start := 0
	if offset > 0 {
		for start < len(buf) && buf[start] != '\n' {
			start++
		}
		if start < len(buf) {
			start++
		}
	}
	var out []Alert
	for start < len(buf) {
		nl := -1
		for j := start; j < len(buf); j++ {
			if buf[j] == '\n' {
				nl = j
				break
			}
		}
		if nl < 0 {
			nl = len(buf)
		}
		line := buf[start:nl]
		start = nl + 1
		if len(line) == 0 {
			continue
		}
		var a Alert
		if err := json.Unmarshal(line, &a); err != nil {
			continue
		}
		out = append(out, a)
	}
	// Reverse so newest is first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// SeenSet returns the set of alert IDs the user has marked read.
type SeenFile struct {
	IDs []string `json:"ids"`
}

func LoadSeen(cfg Config) map[string]struct{} {
	path := filepath.Join(cfg.HNCDir, "run", "alerts_seen.json")
	out := map[string]struct{}{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var f SeenFile
	if err := json.Unmarshal(b, &f); err != nil {
		return out
	}
	for _, id := range f.IDs {
		out[id] = struct{}{}
	}
	return out
}

func MarkSeen(cfg Config, ids []string) error {
	path := filepath.Join(cfg.HNCDir, "run", "alerts_seen.json")
	seen := LoadSeen(cfg)
	for _, id := range ids {
		seen[id] = struct{}{}
	}
	// Cap at 1000 to avoid unbounded growth.
	list := make([]string, 0, len(seen))
	for id := range seen {
		list = append(list, id)
	}
	if len(list) > 1000 {
		list = list[len(list)-1000:]
	}
	b, _ := json.Marshal(SeenFile{IDs: list})
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// _ keeps the strconv import used even if we drop one helper later.
var _ = strconv.Itoa
