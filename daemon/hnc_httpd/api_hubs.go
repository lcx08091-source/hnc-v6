// api_hubs.go — HNC v5.38.0: 前后端双区高内聚只读聚合接口 (/api/apps_overview, /api/rules_hub, /api/dpi_cockpit)
// 将 KSU WebView 下切换「应用」与「分析」时的 5~6 次串行 exec curl 压缩为单次内存聚合返回。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
)

func captureGETHandlerJSON(fn http.HandlerFunc, target string) map[string]interface{} {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	fn(rec, req)
	if rec.Code != http.StatusOK {
		return nil
	}
	var out map[string]interface{}
	if json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		return nil
	}
	return out
}

func snapshotSelfPolicy(s *server) selfStudioPolicy {
	studioMu.Lock()
	defer studioMu.Unlock()
	ensureStudioPolicyLocked(s)
	return studioPolicy
}

func (s *server) apiAppsOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dpiRaw, _ := s.jsonCache.read(filepath.Join(s.hncDir, "run", "dpi_state.json"))
	fwExcl := loadFlywheelExcludeUser(s.hncDir)
	usageToday := captureGETHandlerJSON(s.apiAppUsage, "/api/app_usage?days=1")
	disc := captureGETHandlerJSON(s.apiDiscover, "/api/discover")
	pending := 0
	if disc != nil {
		if gs, ok := disc["groups"].([]interface{}); ok {
			pending = len(gs)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":                    true,
		"dpi_state":             dpiRaw,
		"app_usage_today":       usageToday,
		"flywheel_exclude_user": fwExcl,
		"discover_pending":      pending,
	})
}

func (s *server) apiRulesHub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	disc := captureGETHandlerJSON(s.apiDiscover, "/api/discover")
	unk := captureGETHandlerJSON(s.apiDPIUnknown, "/api/dpi_unknown?days=7")
	rp := captureGETHandlerJSON(s.apiDPIRulepack, "/api/dpi_rulepack")
	dpiRaw, _ := s.jsonCache.read(filepath.Join(s.hncDir, "run", "dpi_state.json"))
	protoCnt := loadPrototypeStore(s.hncDir).AppCount()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":             true,
		"discover":       disc,
		"unknown":        unk,
		"rulepack":       rp,
		"dpi_state":      dpiRaw,
		"prototype_apps": protoCnt,
		"self_policy":    snapshotSelfPolicy(s),
	})
}

func (s *server) apiDPICockpit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	days := 7
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && (v == 1 || v == 3 || v == 7) {
		days = v
	}
	dpiRaw, _ := s.jsonCache.read(filepath.Join(s.hncDir, "run", "dpi_state.json"))
	studio := captureGETHandlerJSON(s.apiSelfStudio, "/api/self/studio")
	evalDays := days
	if evalDays == 3 {
		evalDays = 7
	}
	eval := captureGETHandlerJSON(s.apiDPIEval, "/api/dpi_eval?days="+strconv.Itoa(evalDays))
	hist := captureGETHandlerJSON(s.apiDPIHistory, "/api/dpi_history?days="+strconv.Itoa(days))
	protoCnt := loadPrototypeStore(s.hncDir).AppCount()
	var sig interface{}
	if s.signalCtl != nil {
		sig = s.signalCtl.Snapshot(s)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":             true,
		"days":           days,
		"dpi_state":      dpiRaw,
		"studio":         studio,
		"dpi_eval":       eval,
		"dpi_history":    hist,
		"prototype_apps": protoCnt,
		"signal":         sig,
	})
}
