// rc30.5: alert read API and acknowledgement actions.
//
// Endpoints:
//   GET  /api/alerts              -> recent alerts + unread count
//
// Action verbs (via /api/action):
//   alert_mark_seen   {ids:[...]}  -> mark alert IDs as read by user
//   alert_mark_known  {mac:"..."}  -> add MAC to known_devices.json,
//                                     suppresses future unknown_device alerts
//   alert_dismiss_all              -> mark every current alert as seen
package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"

	"hnc.io/dpid/alert"
)

// apiAlerts is a read-only handler returning the recent alert log and
// the count of unread alerts. Polled by the WebUI bell badge.
func (s *server) apiAlerts(w http.ResponseWriter, r *http.Request) {
	cfg := alert.NewConfig(s.hncDir)

	list, err := alert.ListRecent(cfg, 100)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":         true,
			"alerts":     []alert.Alert{},
			"unread":     0,
			"total":      0,
			"error_hint": err.Error(),
		})
		return
	}
	seen := alert.LoadSeen(cfg)
	unread := 0
	for _, a := range list {
		if _, ok := seen[a.ID]; !ok {
			unread++
		}
	}
	// Annotate each alert with a `seen` boolean so the UI can render the
	// "unread" pill without re-fetching the set.
	type annotatedAlert struct {
		alert.Alert
		Seen bool `json:"seen"`
	}
	annotated := make([]annotatedAlert, 0, len(list))
	for _, a := range list {
		_, ok := seen[a.ID]
		annotated = append(annotated, annotatedAlert{Alert: a, Seen: ok})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":     true,
		"alerts": annotated,
		"unread": unread,
		"total":  len(annotated),
	})
}

// actionAlertMarkSeen accepts `ids: [str, ...]` (alert IDs) and records
// them as read by the user. Used by the WebUI when the alerts drawer is
// opened or a single alert row is dismissed.
func actionAlertMarkSeen(hncDir string, p map[string]string) actionResp {
	// p only carries flat string fields, but ids is a JSON array. The
	// caller serializes it as `{"ids":"a,b,c"}` — comma-separated. This
	// is consistent with how rule_set handles multi-value fields in the
	// existing action contract.
	raw := strings.TrimSpace(p["ids"])
	if raw == "" {
		// Also accept JSON-array-as-string for safety.
		raw = strings.TrimSpace(p["ids_json"])
	}
	if raw == "" {
		return actionResp{OK: false, Error: "bad params", Detail: "ids required"}
	}
	var ids []string
	if strings.HasPrefix(raw, "[") {
		if err := json.Unmarshal([]byte(raw), &ids); err != nil {
			return actionResp{OK: false, Error: "bad params", Detail: "ids must be JSON array or comma-separated"}
		}
	} else {
		for _, part := range strings.Split(raw, ",") {
			id := strings.TrimSpace(part)
			if id != "" {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return actionResp{OK: false, Error: "bad params", Detail: "no ids provided"}
	}
	cfg := alert.NewConfig(hncDir)
	if err := alert.MarkSeen(cfg, ids); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: "marked " + plural(len(ids), "alert") + " as seen"}
}

// actionAlertMarkKnown adds a MAC to known_devices.json. After this:
//   - All current unknown_device alerts for this MAC remain visible in
//     the log (user can still review history)
//   - No future alerts will fire for this MAC unless the ledger is reset
func actionAlertMarkKnown(hncDir string, p map[string]string) actionResp {
	mac := strings.TrimSpace(p["mac"])
	if mac == "" {
		return actionResp{OK: false, Error: "bad params", Detail: "mac required"}
	}
	cfg := alert.NewConfig(hncDir)
	if err := alert.MarkKnown(cfg, mac); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: "marked " + mac + " as known"}
}

// actionAlertDismissAll marks every currently-listed alert as seen. The
// log file is not truncated — historical alerts remain inspectable but
// the bell badge clears.
func actionAlertDismissAll(hncDir string, p map[string]string) actionResp {
	cfg := alert.NewConfig(hncDir)
	list, err := alert.ListRecent(cfg, 1000)
	if err != nil {
		return actionResp{OK: false, Error: "read failed", Detail: err.Error()}
	}
	if len(list) == 0 {
		return actionResp{OK: true, Detail: "nothing to dismiss"}
	}
	ids := make([]string, 0, len(list))
	for _, a := range list {
		ids = append(ids, a.ID)
	}
	if err := alert.MarkSeen(cfg, ids); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: "dismissed " + plural(len(ids), "alert")}
}

func plural(n int, base string) string {
	if n == 1 {
		return "1 " + base
	}
	// English plural is fine here; UI overrides the wording in any case.
	return jsonInt(n) + " " + base + "s"
}

func jsonInt(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// _ keeps filepath import alive if we move to a path-based helper later.
var _ = filepath.Join
