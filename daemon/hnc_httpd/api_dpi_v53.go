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
	"strings"
)

//go:noinline
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
		"state":     s.simMergeDPIState(raw), // 模拟环境: clients 追加模拟客户端; 关闭时原样
	})
}

// normalizeDPIProbeOffloadHint 结合当前热点活跃态与 offload_guard.json 实时压制状态修正静态 offload_hint,
// 避免关热点或守卫已压制慢路径(fallback_active==true)时将常驻 /sys/fs/bpf/tethering 目录误报为失控硬件分流。
func normalizeDPIProbeOffloadHint(hncDir string, raw interface{}) interface{} {
	src, ok := raw.(map[string]interface{})
	if !ok || src == nil {
		return raw
	}
	out := make(map[string]interface{}, len(src)+1)
	for k, v := range src {
		out[k] = v
	}
	staticHint := dpJSONBool(out["offload_hint"])
	if staticHint {
		out["offload_static_hint"] = true
	}

	clearHint := func() {
		out["offload_hint"] = false
		if ev, hasEv := out["offload_evidence"]; hasEv {
			out["offload_static_evidence"] = ev
			delete(out, "offload_evidence")
		}
	}

	if hncDir == "" || readHotspotIfaceName(hncDir) == "" {
		if staticHint {
			clearHint()
		}
		return out
	}

	og := readOffloadGuard(hncDir)
	if len(og) == 0 {
		return out
	}
	fbActive := dpJSONBool(og["fallback_active"]) || dpJSONBool(og["fallback"])
	spStr := strings.ToLower(strings.TrimSpace(asString(og["slowpath"])))
	spActive := spStr == "ok" || dpJSONBool(og["slowpath_active"])
	tetherDisabled := dpJSONBool(og["tether_offload_disabled"])
	if fbActive || spActive || tetherDisabled {
		clearHint()
		return out
	}

	st := strings.ToUpper(strings.TrimSpace(asString(og["offload_state"])))
	if st == "" {
		st = strings.ToUpper(strings.TrimSpace(asString(og["state"])))
	}
	switch st {
	case "ACTIVE":
		out["offload_hint"] = true
	case "IDLE", "CAPABLE", "NOMAP", "NOHOTSPOT":
		clearHint()
	}
	return out
}

//go:noinline
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
		"probe":     normalizeDPIProbeOffloadHint(s.hncDir, raw),
	})
}
