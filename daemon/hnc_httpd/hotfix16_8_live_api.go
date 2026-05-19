package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// hotfix16.8: WebUI in hotfix15+ polls these lightweight endpoints.
// Some merged branches shipped a WebUI that calls /api/live and /api/capabilities
// while the bundled hnc_httpd only knew the older API set, causing repeated
// "invalid JSON: 404 page not found" toasts. Keep the endpoints small and
// file-based so they work even without the full snapshot-cache branch.

func (s *server) apiCapabilities(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.hncDir, "run", "capabilities.json")
	capRaw, err := readJSON(path)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"available": false,
			"error":     err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"available":    true,
		"capabilities": capRaw,
	})
}

func (s *server) apiMetrics(w http.ResponseWriter, r *http.Request) {
	// Compatibility shape expected by WebUI diagnostics. These counters are zero
	// when the full snapshot-cache implementation is not compiled in.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"snapshot_age_ms":        0,
		"snapshot_refresh_count": 0,
		"json_cache_hits":        0,
		"json_cache_misses":      0,
		"shell_fallback_count":   0,
		"offload_check_count":    0,
		"backend_version":        version,
		"compat":                "hotfix16.8-live-api",
	})
}

func (s *server) apiLive(w http.ResponseWriter, r *http.Request) {
	status, payload := s.buildDevicesPayload()
	if status != http.StatusOK {
		writeJSON(w, status, payload)
		return
	}

	devices, _ := payload["devices"].([]map[string]interface{})
	total := len(devices)
	online := 0
	var rxBps, txBps int64
	for _, d := range devices {
		if b, _ := d["online"].(bool); b {
			online++
		}
		if v, ok := toInt64(d["rx_bps"]); ok {
			rxBps += v
		}
		if v, ok := toInt64(d["tx_bps"]); ok {
			txBps += v
		}
	}

	iface := currentHotspotIface(s.hncDir)
	ip := ifaceIPv4(iface)
	active := hotspotActiveFromState(s.hncDir, iface, ip, online)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"hotspot_active":  active,
		"iface":           iface,
		"hotspot_iface":   iface,
		"hotspot_ip":      ip,
		"online":          online,
		"total":           total,
		"rx_bps":          rxBps,
		"tx_bps":          txBps,
		"devices_sig":     liveDevicesSig(devices, active, iface),
		"snapshot_age_ms": 0,
		"snapshot_stale":  false,
		"backend_version": version,
	})
}

func currentHotspotIface(hncDir string) string {
	// Prefer explicit runtime state written by service/watchdog.
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "hnc_state")); err == nil {
		line := strings.TrimSpace(string(b))
		if strings.HasPrefix(line, "ACTIVE:") {
			if v := strings.TrimSpace(strings.TrimPrefix(line, "ACTIVE:")); v != "" {
				return v
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "iface.cache")); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v
		}
	}
	if raw, err := readJSON(filepath.Join(hncDir, "data", "rules.json")); err == nil {
		if m, ok := raw.(map[string]interface{}); ok {
			if v, ok := m["hotspot_iface"].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

func ifaceIPv4(iface string) string {
	if iface == "" {
		return ""
	}
	ifc, err := net.InterfaceByName(iface)
	if err != nil || ifc == nil {
		return ""
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			ip4 := ipn.IP.To4()
			if ip4 != nil && ip4.IsPrivate() {
				return ip4.String()
			}
		}
	}
	return ""
}

func hotspotActiveFromState(hncDir, iface, ip string, online int) bool {
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "hnc_state")); err == nil {
		line := strings.TrimSpace(string(b))
		if strings.HasPrefix(line, "INACTIVE") || strings.HasPrefix(line, "OFF") || strings.HasPrefix(line, "DOWN") {
			return false
		}
		if strings.HasPrefix(line, "ACTIVE") {
			return true
		}
	}
	if iface != "" && ip != "" {
		return true
	}
	return online > 0
}

func liveDevicesSig(devices []map[string]interface{}, active bool, iface string) string {
	parts := make([]string, 0, len(devices)+1)
	parts = append(parts, fmt.Sprintf("active=%t iface=%s", active, iface))
	for _, d := range devices {
		mac := strings.ToLower(asString(d["mac"]))
		if mac == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s|ip=%s|on=%v|st=%s|lim=%v|del=%v|down=%v|up=%v|dms=%v|j=%v|loss=%v",
			mac,
			asString(d["ip"]),
			d["online"],
			asString(d["status"]),
			d["limit_enabled"],
			d["delay_enabled"],
			d["down_mbps"],
			d["up_mbps"],
			d["delay_ms"],
			d["jitter_ms"],
			d["loss_pct"],
		))
	}
	sort.Strings(parts[1:])
	h := sha1.Sum([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(h[:])
}

// Keep the symbol alive for future cache branches without forcing a dependency.
var _ = time.Now
