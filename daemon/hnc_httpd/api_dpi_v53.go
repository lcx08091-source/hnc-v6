package main

// hnc_dpid (DPI passive capture daemon) exposes two state files in /data/local/hnc/run/:
//   dpid.probe.json — one-shot capability snapshot written at daemon startup
//   dpi_state.json  — live state, refreshed every 5s with stats counters
//
// This file adds two read-only HTTP endpoints so the WebUI can render a DPI
// page without needing direct filesystem access. Both endpoints are file-backed
// and fall back to a well-formed "unavailable" shape when the dpid daemon is
// not running or has not yet written its first snapshot.
//
// Route registration is in server.go (apiDPIState, apiDPIProbe) and the
// unauth-readable allow list is in middleware.go.
//
// v5.3.0-rc12 (rc11 + dpid integration).

import (
	"net/http"
	"path/filepath"
)

func (s *server) apiDPIState(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.hncDir, "run", "dpi_state.json")
	raw, err := readJSON(path)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"available": false,
			"error":     err.Error(),
			"hint":      "hnc_dpid not running or no state yet; check $HNC_DIR/logs/dpid.log",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"available": true,
		"state":     raw,
	})
}

func (s *server) apiDPIProbe(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.hncDir, "run", "dpid.probe.json")
	raw, err := readJSON(path)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"available": false,
			"error":     err.Error(),
			"hint":      "hnc_dpid not running or capability probe failed; check $HNC_DIR/logs/dpid.log",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"available": true,
		"probe":     raw,
	})
}
