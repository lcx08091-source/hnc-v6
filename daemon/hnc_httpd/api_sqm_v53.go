package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// apiSQMStatus · v5.3.0-rc5
// Read-only Smart Queue / SQM status endpoint. It intentionally delegates to
// bin/sqm_manager.sh so local WebUI, remote WebUI and shell diagnostics share one
// source of truth. The endpoint is lightweight and never mutates tc state.
func (s *server) apiSQMStatus(w http.ResponseWriter, r *http.Request) {
	iface := strings.TrimSpace(r.URL.Query().Get("iface"))
	args := []string{s.hncDir + "/bin/sqm_manager.sh", "status"}
	if iface != "" {
		args = append(args, iface)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", args...)
	cmd.Env = []string{
		"HNC_DIR=" + s.hncDir,
		"HNC=" + s.hncDir,
		"PATH=/system/bin:/system/xbin:/vendor/bin:/usr/bin:/bin",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if ee, ok := err.(*exec.ExitError); ok && detail == "" {
			detail = strings.TrimSpace(string(ee.Stderr))
		}
		if ctx.Err() == context.DeadlineExceeded {
			detail = "timeout after 4s"
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"available": false,
			"error":     "sqm status failed",
			"detail":    detail,
		})
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(out, &payload); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"available": false,
			"error":     "invalid sqm status json",
			"detail":    err.Error(),
		})
		return
	}
	payload["available"] = true
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(payload)
}
