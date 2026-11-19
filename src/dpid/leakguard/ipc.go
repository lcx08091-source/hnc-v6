package leakguard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	DefaultRunDir  = "/data/local/hnc/run"
	EventsFileName = "leakguard_events.json"
	CtrlFileName   = "leakguard_ctrl.json"
)

var ipcWriteSeq atomic.Uint64
var ctrlUpdateMu sync.Mutex

// EventsSnapshot is the volatile tmpfs mirror at run/leakguard_events.json
// consumed by daemon/hnc_httpd.
type EventsSnapshot struct {
	UpdatedAt      int64       `json:"updated_at"`
	Enabled        bool        `json:"enabled"`
	Capacity       int         `json:"capacity"`
	CooldownSec    int         `json:"cooldown_sec"`
	TotalLeaks     uint64      `json:"total_leaks"`
	UniqueEvents   int         `json:"unique_events"`
	SubmittedPkts  uint64      `json:"submitted_packets"`
	ScannedPkts    uint64      `json:"scanned_packets"`
	DroppedCount   uint64      `json:"dropped_count"`
	ClearSeq       int64       `json:"clear_seq,omitempty"`
	BlockedDomains []string    `json:"blocked_domains,omitempty"`
	Events         []LeakEvent `json:"events"`
}

// ControlState is the dynamic control channel at run/leakguard_ctrl.json
// written by daemon/hnc_httpd and synced dynamically by dpid's LeakGuard Engine.
type ControlState struct {
	Enabled        *bool           `json:"enabled,omitempty"`
	Capacity       int             `json:"capacity,omitempty"`
	CooldownSec    int             `json:"cooldown_sec,omitempty"`
	NotifyEnabled  *bool           `json:"notify_enabled,omitempty"`
	LockscreenMask *bool           `json:"lockscreen_mask,omitempty"`
	ClearSeq       int64           `json:"clear_seq,omitempty"`
	ClearedAt      int64           `json:"cleared_at,omitempty"`
	BlockedDomains []string        `json:"blocked_domains,omitempty"`
	BlockedTargets map[string]bool `json:"blocked_targets,omitempty"`
	UpdatedAt      int64           `json:"updated_at,omitempty"`
}

// EventsPath returns filepath.Join(runDir, "leakguard_events.json").
func EventsPath(runDir string) string {
	if strings.TrimSpace(runDir) == "" {
		runDir = DefaultRunDir
	}
	return filepath.Join(runDir, EventsFileName)
}

// CtrlPath returns filepath.Join(runDir, "leakguard_ctrl.json").
func CtrlPath(runDir string) string {
	if strings.TrimSpace(runDir) == "" {
		runDir = DefaultRunDir
	}
	return filepath.Join(runDir, CtrlFileName)
}

// WriteEvents atomically writes snap to runDir/leakguard_events.json (tmpfs).
func WriteEvents(runDir string, snap EventsSnapshot) error {
	if snap.Events == nil {
		snap.Events = []LeakEvent{}
	}
	if snap.UpdatedAt <= 0 {
		snap.UpdatedAt = time.Now().Unix()
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return writeTmpfsAtomic(EventsPath(runDir), b)
}

// ReadEvents loads runDir/leakguard_events.json; missing file returns an empty
// default snapshot without error so cold-start WebUI queries stay clean.
func ReadEvents(runDir string) (EventsSnapshot, error) {
	b, err := os.ReadFile(EventsPath(runDir))
	if err != nil {
		if os.IsNotExist(err) {
			return EventsSnapshot{
				Enabled:     true,
				Capacity:    DefaultCapacity,
				CooldownSec: DefaultCooldownSec,
				Events:      []LeakEvent{},
			}, nil
		}
		return EventsSnapshot{}, err
	}
	var snap EventsSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return EventsSnapshot{}, err
	}
	if snap.Events == nil {
		snap.Events = []LeakEvent{}
	}
	return snap, nil
}

// ReadControl reads runDir/leakguard_ctrl.json (and merges blocked_targets from
// ../data/leakguard_config.json when present so httpd blocklists stay unified).
func ReadControl(runDir string) (ControlState, error) {
	if strings.TrimSpace(runDir) == "" {
		runDir = DefaultRunDir
	}
	var ctrl ControlState
	b, err := os.ReadFile(CtrlPath(runDir))
	if err != nil && !os.IsNotExist(err) {
		return ControlState{}, err
	}
	if len(b) > 0 {
		if uerr := json.Unmarshal(b, &ctrl); uerr != nil {
			return ControlState{}, uerr
		}
	}

	merged := append([]string(nil), ctrl.BlockedDomains...)
	for tgt, active := range ctrl.BlockedTargets {
		if active {
			merged = append(merged, tgt)
		}
	}
	// Also absorb hnc_httpd persisted blocked_targets from ../data/leakguard_config.json if available.
	persistPath := filepath.Join(filepath.Dir(filepath.Clean(runDir)), "data", "leakguard_config.json")
	if pb, perr := os.ReadFile(persistPath); perr == nil && len(pb) > 0 {
		var persisted struct {
			BlockedTargets map[string]bool `json:"blocked_targets"`
		}
		if json.Unmarshal(pb, &persisted) == nil {
			for tgt, active := range persisted.BlockedTargets {
				if active {
					merged = append(merged, tgt)
				}
			}
		}
	}
	ctrl.BlockedDomains = normalizeDomainSlice(merged)
	return ctrl, nil
}

// WriteControl atomically persists ctrl to runDir/leakguard_ctrl.json.
func WriteControl(runDir string, ctrl ControlState) error {
	ctrl.BlockedDomains = normalizeDomainSlice(ctrl.BlockedDomains)
	if ctrl.UpdatedAt <= 0 {
		ctrl.UpdatedAt = time.Now().Unix()
	}
	b, err := json.Marshal(ctrl)
	if err != nil {
		return err
	}
	return writeTmpfsAtomic(CtrlPath(runDir), b)
}

// UpdateControl performs a cross-process flock-serialized read-modify-write on
// runDir/leakguard_ctrl.json for hnc_httpd control endpoints.
func UpdateControl(runDir string, mutate func(*ControlState)) (ControlState, error) {
	ctrlUpdateMu.Lock()
	defer ctrlUpdateMu.Unlock()

	if strings.TrimSpace(runDir) == "" {
		runDir = DefaultRunDir
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return ControlState{}, err
	}

	lockPath := CtrlPath(runDir) + ".lock"
	lf, lerr := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if lerr == nil {
		_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_EX)
		defer func() {
			_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
			_ = lf.Close()
		}()
	}

	cur, _ := ReadControl(runDir)
	if mutate != nil {
		mutate(&cur)
	}
	cur.UpdatedAt = time.Now().Unix()
	if err := WriteControl(runDir, cur); err != nil {
		return ControlState{}, err
	}
	return cur, nil
}

// RequestClear issues an atomic clear signal via leakguard_ctrl.json.
func RequestClear(runDir string) (ControlState, error) {
	return UpdateControl(runDir, func(c *ControlState) {
		now := time.Now().Unix()
		next := c.ClearSeq + 1
		if next <= 0 {
			next = 1
		}
		c.ClearSeq = next
		c.ClearedAt = now
	})
}

// AddBlockedDomain adds a domain (or IP) to the LeakGuard blocklist in leakguard_ctrl.json.
func AddBlockedDomain(runDir, domain string) (ControlState, error) {
	d := normalizeDomain(domain)
	if d == "" {
		return ReadControl(runDir)
	}
	return UpdateControl(runDir, func(c *ControlState) {
		c.BlockedDomains = append(c.BlockedDomains, d)
		c.BlockedDomains = normalizeDomainSlice(c.BlockedDomains)
	})
}

// RemoveBlockedDomain removes a domain from the LeakGuard blocklist in leakguard_ctrl.json.
func RemoveBlockedDomain(runDir, domain string) (ControlState, error) {
	d := normalizeDomain(domain)
	return UpdateControl(runDir, func(c *ControlState) {
		filtered := make([]string, 0, len(c.BlockedDomains))
		for _, item := range c.BlockedDomains {
			if normalizeDomain(item) != d {
				filtered = append(filtered, item)
			}
		}
		c.BlockedDomains = normalizeDomainSlice(filtered)
	})
}

func normalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	return s
}

func normalizeDomainSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		d := normalizeDomain(raw)
		if d == "" {
			continue
		}
		if _, exists := seen[d]; !exists {
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

func writeTmpfsAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d.%d", path, os.Getpid(), ipcWriteSeq.Add(1))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
