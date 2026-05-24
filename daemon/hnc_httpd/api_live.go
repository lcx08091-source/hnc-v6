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
)

// rc30.12.30 (P2.11): merged from hotfix16_8_live_api.go.
// 按功能命名 (轻量级 live/capabilities/metrics API), 跟 api_v5.go / api_dpi_v53.go
// 等文件风格对齐.
//
// WebUI (hotfix15+) polls these lightweight endpoints. /api/live 是 devices 的
// 浓缩摘要 (用于状态条 / 流量条); /api/capabilities 暴露内核能力检测结果;
// /api/metrics 诚实上报 instrumented:false (本构建实时读状态文件, 无快照缓存,
// 没有可报告的 cache/fallback 计数), 不再伪造恒为 0 的计数让前端误当真实指标.

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
	// This build has no snapshot cache: every request reads the state files live,
	// so there are genuinely no cache/fallback/offload counters to report. Report
	// instrumented:false honestly instead of emitting fake all-zero counters that
	// the WebUI would render as if they were measured.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"instrumented":    false,
		"mode":            "live-read",
		"backend_version": version,
		"compat":          "hotfix16.8-live-api",
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
