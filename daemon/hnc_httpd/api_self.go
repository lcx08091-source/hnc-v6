// api_self.go — v5.5 self-capture endpoints.
//
//   GET    /api/self                    self block from dpi_state.json (shortcut)
//   POST   /api/self/toggle             body {enabled:bool} → touch/rm flag file
//   GET    /api/self/ifaces             enumerate eligible self interfaces (preview)
//   GET    /api/self/attrib             today's self_attrib.YYYYMMDD.jsonl (last N rows)
//
// The toggle endpoint flips /data/local/hnc/run/self_capture.enabled.
// dpid checks this flag on every 5s sampler tick, so the change takes
// effect within 5s without dpid restart.
//
// All endpoints use the standard middleware chain (auth + rate limit);
// /api/self/toggle requires write permissions.

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
)

func (s *server) selfFlagPath() string {
	return filepath.Join(s.hncDir, "run", "self_capture.enabled")
}

// v5.6.0-rc6: separate flag from self_capture.enabled — auto-expand
// writes rule files, different risk profile from read-only sampling.
func (s *server) autoExpandFlagPath() string {
	return filepath.Join(s.hncDir, "run", "auto_expand.enabled")
}

// apiSelf returns just the `self` block from dpi_state.json. Cheaper
// than the full /api/dpi_state for WebUI tabs that only need self.
func (s *server) apiSelf(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.hncDir, "run", "dpi_state.json")
	raw, err := readJSON(path)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"available": false,
			"error":     err.Error(),
		})
		return
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"available": false,
			"error":     "dpi_state.json: top-level not an object",
		})
		return
	}
	selfBlock, _ := m["self"]
	// v5.6.0-rc6: include the auto-expand flag state so the WebUI can
	// reflect it in the settings toggle on initial load (without an extra
	// round-trip).
	_, aeErr := os.Stat(s.autoExpandFlagPath())
	autoExpandEnabled := aeErr == nil
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"available":           true,
		"self":                selfBlock, // may be nil if disabled / not yet populated
		"auto_expand_enabled": autoExpandEnabled,
	})
}

// flipFlagFile is the shared implementation for any "POST /api/x/toggle"
// endpoint that maps a boolean to the presence/absence of a flag file.
// Centralized in v5.6.0-rc6 so adding more toggle endpoints (auto-expand,
// future v5.7 candidate-approval, etc) doesn't grow boilerplate.
//
// note: short human-readable hint for the response (e.g. "dpid picks up
// the change within 5s on its next sampler tick").
func (s *server) flipFlagFile(w http.ResponseWriter, r *http.Request, flagPath, note string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if body.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing 'enabled' field"})
		return
	}
	if *body.Enabled {
		f, err := os.OpenFile(flagPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		_, _ = f.WriteString("enabled\n")
		_ = f.Close()
	} else {
		if err := os.Remove(flagPath); err != nil && !os.IsNotExist(err) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"enabled": *body.Enabled,
		"note":    note,
	})
}

// apiSelfToggle is the POST endpoint that flips the self_capture flag.
// body: {"enabled": true | false}. Empty body / missing key is rejected.
func (s *server) apiSelfToggle(w http.ResponseWriter, r *http.Request) {
	s.flipFlagFile(w, r, s.selfFlagPath(),
		"dpid will pick up the change within 5s on its next sampler tick")
}

// v5.6.0-rc6: apiAutoExpandToggle flips auto_expand.enabled. Sister
// endpoint to apiSelfToggle. Separate flag so users can run pure self-
// capture observation (read-only) without enabling the rule-file writer.
func (s *server) apiAutoExpandToggle(w http.ResponseWriter, r *http.Request) {
	s.flipFlagFile(w, r, s.autoExpandFlagPath(),
		"auto-expander goroutine will pick up the change within 60s on its next tick")
}

// apiSelfIfaces returns the current /sys/class/net enumeration filtered
// against the v5.5 self-interface picker rules. Useful as a preview
// before flipping the toggle.
//
// Implemented directly here (vs. calling into capture.DiscoverSelfCandidates)
// to avoid taking a dependency on the dpid package from hnc_httpd —
// they ship as separate binaries.
var selfPositive = []*regexp.Regexp{
	regexp.MustCompile(`^rmnet(_data)?\d+$`),
	regexp.MustCompile(`^ccmni\d+$`),
	regexp.MustCompile(`^wwan\d+$`),
	regexp.MustCompile(`^wlan0$`),
	regexp.MustCompile(`^eth\d+$`),
}
var selfNegative = []*regexp.Regexp{
	regexp.MustCompile(`^lo$`),
	regexp.MustCompile(`^dummy\d*$`),
	regexp.MustCompile(`^ap\d*$`),
	regexp.MustCompile(`^softap\d*$`),
	regexp.MustCompile(`^swlan\d+$`),
	regexp.MustCompile(`^wlan[1-9]\d*$`),
}

func (s *server) apiSelfIfaces(w http.ResponseWriter, r *http.Request) {
	type item struct {
		Name      string `json:"name"`
		OperState string `json:"oper_state"`
		RxBytes   uint64 `json:"rx_bytes"`
		Eligible  bool   `json:"eligible"`
		Reason    string `json:"reason,omitempty"`
	}
	var out []item

	// Read the currently-bound AP iface so we can mark it explicitly.
	apIface := ""
	if b, err := os.ReadFile(filepath.Join(s.hncDir, "run", "hotspot_iface")); err == nil {
		apIface = strings.TrimSpace(string(b))
	}

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"error": err.Error()})
		return
	}
	for _, e := range entries {
		name := e.Name()
		it := item{Name: name}
		st, _ := os.ReadFile(filepath.Join("/sys/class/net", name, "operstate"))
		it.OperState = strings.TrimSpace(string(st))
		rxRaw, _ := os.ReadFile(filepath.Join("/sys/class/net", name, "statistics/rx_bytes"))
		it.RxBytes, _ = strconv.ParseUint(strings.TrimSpace(string(rxRaw)), 10, 64)

		// Eligibility check
		switch {
		case name == apIface:
			it.Reason = "is hotspot AP (already captured by main HNC)"
		case matchAnyRE(selfNegative, name):
			it.Reason = "name matches AP/virtual exclude pattern"
		case !matchAnyRE(selfPositive, name):
			it.Reason = "name does not match any self-iface positive pattern"
		case it.OperState != "up" && it.OperState != "unknown":
			it.Reason = "operstate=" + it.OperState
		case it.RxBytes < 1000:
			it.Reason = "rx_bytes too low (likely phantom)"
		default:
			it.Eligible = true
		}
		out = append(out, it)
	}
	// Eligible first, then by rx desc within each group
	sort.Slice(out, func(i, j int) bool {
		if out[i].Eligible != out[j].Eligible {
			return out[i].Eligible
		}
		return out[i].RxBytes > out[j].RxBytes
	})
	// Also report the toggle state
	_, ferr := os.Stat(s.selfFlagPath())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":   ferr == nil,
		"ifaces":    out,
		"ap_iface":  apIface,
		"flag_path": s.selfFlagPath(),
	})
}

func matchAnyRE(rs []*regexp.Regexp, name string) bool {
	for _, re := range rs {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// apiSelfAttrib returns the most recent N rows from today's
// self_attrib.YYYYMMDD.jsonl. Default N=200; ?limit=N overrides up to 2000.
func (s *server) apiSelfAttrib(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	// Find most recent self_attrib.*.jsonl
	runDir := filepath.Join(s.hncDir, "run")
	entries, err := os.ReadDir(runDir)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"error": err.Error()})
		return
	}
	var files []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "self_attrib.") && strings.HasSuffix(n, ".jsonl") {
			files = append(files, n)
		}
	}
	if len(files) == 0 {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"observations": []interface{}{},
			"note":         "no self_attrib JSONL files yet (sampler may not have run)",
		})
		return
	}
	sort.Strings(files)
	latest := files[len(files)-1]
	f, err := os.Open(filepath.Join(runDir, latest))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer f.Close()
	// Read all lines (typical daily file is small; we cap by limit)
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20) // up to 16MB per line just in case
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	// Take the last `limit` lines
	start := len(lines) - limit
	if start < 0 {
		start = 0
	}
	tail := lines[start:]
	// Parse each as JSON to validate (and produce structured response)
	out := make([]interface{}, 0, len(tail))
	for _, l := range tail {
		var obj interface{}
		if err := json.Unmarshal([]byte(l), &obj); err == nil {
			out = append(out, obj)
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"file":         latest,
		"observations": out,
		"shown":        len(out),
		"total":        len(lines),
	})
}
