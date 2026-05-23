// action_candidate.go — v5.7.0-rc2 · candidate approval (走法2 收尾)
//
// Two WebUI write actions for the brand-new-apex candidate flywheel:
//
//   candidate_promote  params: apex   → append to etc/candidate_decisions.json
//                                        ("promote" list). dpid force-promotes
//                                        the apex (to its single uid's app) on
//                                        its next tick, even in shadow mode.
//   candidate_reject   params: apex   → append to etc/auto_expand_blocklist.json
//                                        ("blocked_apex"). dpid already reads
//                                        this every tick → apex becomes "shared"
//                                        → never attributed + any existing
//                                        promotion is auto-demoted.
//
// Both are tiny load-modify-store JSON files; serialized + atomic (tmp+rename),
// matching action_device_rename.go.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const (
	candidateDecisionsRelPath  = "etc/candidate_decisions.json"
	autoExpandBlocklistRelPath = "etc/auto_expand_blocklist.json"
)

// apex domain: lowercase labels, must contain a dot, <=253 chars.
var apexRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

func validApex(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < 3 || len(s) > 253 || !strings.Contains(s, ".") {
		return "", false
	}
	if strings.Contains(s, "..") || !apexRE.MatchString(s) {
		return "", false
	}
	return s, true
}

// Serialize writes per-file to avoid lost updates from concurrent clicks.
var (
	candidateDecisionsMu  sync.Mutex
	autoExpandBlocklistMu sync.Mutex
)

// candidateDecisionsFile mirrors dpid's on-disk shape (output/candidate.go).
type candidateDecisionsFile struct {
	Promote []string `json:"promote"`
	Comment string   `json:"_comment,omitempty"`
}

// blocklistFile mirrors dpid's auto_expand_blocklist.json shape (output/auto_expand.go).
type blocklistFile struct {
	BlockedApex []string `json:"blocked_apex"`
	Comment     string   `json:"_comment,omitempty"`
}

// actionCandidatePromote appends an apex to the user-approved promote list.
func actionCandidatePromote(hncDir string, p map[string]string) actionResp {
	apex, ok := validApex(p["apex"])
	if !ok {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid apex (expected a lowercase domain like example.com)"}
	}
	path := filepath.Join(hncDir, candidateDecisionsRelPath)

	candidateDecisionsMu.Lock()
	defer candidateDecisionsMu.Unlock()

	var f candidateDecisionsFile
	if err := readJSONInto(path, &f); err != nil {
		return actionResp{OK: false, Error: "read failed", Detail: err.Error()}
	}
	if contains(f.Promote, apex) {
		return actionResp{OK: true, Detail: fmt.Sprintf("%s already approved", apex)}
	}
	f.Promote = append(f.Promote, apex)
	f.Comment = "用户从 WebUI 一键 promote 批准的 apex; dpid 每 tick 读取并强制晋级。"
	if err := writeJSONAtomic(path, &f); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: fmt.Sprintf("approved %s — dpid promotes within 60s", apex)}
}

// actionCandidateReject appends an apex to the shared-infra blocklist.
func actionCandidateReject(hncDir string, p map[string]string) actionResp {
	apex, ok := validApex(p["apex"])
	if !ok {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid apex (expected a lowercase domain like example.com)"}
	}
	path := filepath.Join(hncDir, autoExpandBlocklistRelPath)

	autoExpandBlocklistMu.Lock()
	defer autoExpandBlocklistMu.Unlock()

	var f blocklistFile
	if err := readJSONInto(path, &f); err != nil {
		return actionResp{OK: false, Error: "read failed", Detail: err.Error()}
	}
	if contains(f.BlockedApex, apex) {
		return actionResp{OK: true, Detail: fmt.Sprintf("%s already blocklisted", apex)}
	}
	f.BlockedApex = append(f.BlockedApex, apex)
	if f.Comment == "" {
		f.Comment = "共享基础设施 / 用户拒绝的 apex; 不自动归到任何 app。"
	}
	if err := writeJSONAtomic(path, &f); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: fmt.Sprintf("blocklisted %s — any existing promotion is demoted within 60s", apex)}
}

// ── small JSON file helpers ───────────────────────────────────────────

// readJSONInto reads path into out. Missing file = leave out at zero value
// (not an error). Malformed existing file IS an error (don't clobber).
func readJSONInto(path string, out interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s malformed: %v", filepath.Base(path), err)
	}
	return nil
}

func writeJSONAtomic(path string, v interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
