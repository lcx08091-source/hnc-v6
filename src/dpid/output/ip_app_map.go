// Package output - ip_app_map.go: writes a (remote_ip → app_id) mapping
// derived from the live classifier hits, for downstream consumption by
// the apply_app_limits.sh shell tool that maintains per-(mac, app)
// iptables MARK + tc class rules.
//
// Data shape (run/ip_app_map.json):
//
//   {
//     "generated_ts": 1700000000,
//     "entries": [
//       {"ip": "1.2.3.4", "app_id": "douyin", "name": "抖音", "last_seen": 1699999990},
//       ...
//     ]
//   }
//
// Update cadence: written every 30 seconds by the IPAppMapFlusher goroutine
// in main.go. Entries older than 5 minutes are pruned — by then the IP
// likely belongs to a different CDN tenant and re-marking would mislead.
//
// CDN tenant collisions are unavoidable: one IP can serve multiple apps.
// Last-writer-wins is the chosen policy — this is a pragmatic LIFO that
// matches user mental model ("I just hit Douyin, the limit should kick in"),
// at the cost of brief mis-marking when an IP is rapidly multiplexed.

package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	// Default output path. main.go can override via SetIPAppMapPath.
	defaultIPAppMapPath = "/data/local/hnc/run/ip_app_map.json"

	// Entries older than this on flush are dropped. 5 min matches the
	// shell sync cadence: longer windows risk stale mis-mapping.
	ipAppMapMaxAge = 5 * time.Minute

	// Cap on entries written. Above this the file becomes a perf concern
	// for the shell readers; we drop the oldest.
	ipAppMapMaxEntries = 2000
)

type IPAppObs struct {
	IP       string `json:"ip"`
	AppID    string `json:"app_id"`
	Name     string `json:"name,omitempty"`
	LastSeen int64  `json:"last_seen"`
}

type ipAppMapFile struct {
	GeneratedTs int64      `json:"generated_ts"`
	Entries     []IPAppObs `json:"entries"`
}

// IPAppMap is a thread-safe in-memory store updated on the hot path
// (every classified flow) and flushed periodically.
type IPAppMap struct {
	mu      sync.Mutex
	entries map[string]*IPAppObs // ip → most recent observation
	path    string
}

func NewIPAppMap() *IPAppMap {
	return &IPAppMap{
		entries: map[string]*IPAppObs{},
		path:    defaultIPAppMapPath,
	}
}

func (m *IPAppMap) SetPath(p string) {
	m.mu.Lock()
	m.path = p
	m.mu.Unlock()
}

// Record updates the map. Called from EventFlow / applyRuleHitLocked
// hot path; must be cheap. Last-writer-wins for the IP.
func (m *IPAppMap) Record(ip, appID, name string, now int64) {
	if ip == "" || appID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[ip]
	if e == nil {
		e = &IPAppObs{IP: ip}
		m.entries[ip] = e
	}
	e.AppID = appID
	e.Name = name
	e.LastSeen = now
}

// Flush writes the current map to disk atomically. Prunes stale entries
// and caps total size. Writes both the JSON file (for tools / future use)
// and a flat plain-text file (ip<space>app_id, one per line) that shell
// scripts can read without a JSON parser — Android base doesn't ship jq.
func (m *IPAppMap) Flush(now time.Time) error {
	m.mu.Lock()
	cutoff := now.Add(-ipAppMapMaxAge).Unix()
	out := make([]IPAppObs, 0, len(m.entries))
	for ip, e := range m.entries {
		if e.LastSeen < cutoff {
			delete(m.entries, ip)
			continue
		}
		out = append(out, *e)
	}
	path := m.path
	m.mu.Unlock()

	// Sort newest-first (clearer for shell reader debug).
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen > out[j].LastSeen })
	if len(out) > ipAppMapMaxEntries {
		out = out[:ipAppMapMaxEntries]
	}

	f := ipAppMapFile{
		GeneratedTs: now.Unix(),
		Entries:     out,
	}
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}

	// Flat companion file (ip app_id, one per line). Used by
	// apply_app_limits.sh — no JSON parser dependency.
	// Path: same dir, ".flat" replacing ".json" suffix
	// (e.g. /run/ip_app_map.json → /run/ip_app_map.flat).
	flatPath := path
	if l := len(flatPath); l > 5 && flatPath[l-5:] == ".json" {
		flatPath = flatPath[:l-5] + ".flat"
	} else {
		flatPath = flatPath + ".flat"
	}
	var flat []byte
	for _, e := range out {
		flat = append(flat, []byte(e.IP+" "+e.AppID+"\n")...)
	}
	tmpFlat := flatPath + ".tmp"
	if err := os.WriteFile(tmpFlat, flat, 0o644); err != nil {
		return nil // best-effort
	}
	return os.Rename(tmpFlat, flatPath)
}

// Size returns the current map cardinality. Used for stats.
func (m *IPAppMap) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// Used to keep fmt import alive without exposing a debug helper.
var _ = fmt.Sprintf
