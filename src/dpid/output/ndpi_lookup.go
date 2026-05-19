// Package output - ndpi_lookup.go: nDPI external SNI/QUIC observation injection.
//
// rc30.3: integrate the existing hnc_ndpi_probe pipeline into the main DPI
// classification path. nDPI runs as a long-lived background process (started
// by hnc_watchdog) and dumps recent SNI/QUIC observations to:
//
//   /data/local/hnc/run/ip_to_host.json
//
// File format (produced by ndpi_parse_observations.sh, written every 60s):
//
//   {
//     "schema_version": "1.0",
//     "generated_ts": 1700000000,
//     "rotate_window_sec": 60,
//     "entries": [
//       {"ip":"142.250.x.x", "host":"foo.googleapis.com", "last_seen":"..."},
//       ...
//     ]
//   }
//
// Integration philosophy: nDPI is *additive*, never overrides.
//   - The builtin/external IP matchers still win.
//   - Only when IP classification fails do we ask nDPI "what hostname did
//     you recently see at this IP?" and feed that back into classifyHost.
//   - This lifts the recognition floor for new apps / cdn-shared IPs that
//     the builtin tables haven't enumerated, without changing existing
//     match precision.
//
// Threading: file is read on-demand from EventFlow hot path. We mtime-cache
// the parse result to avoid re-parsing every flow event. EventFlow holds
// Writer.mu, so the cache itself uses its own dedicated lock to avoid
// reentrant acquisition.

package output

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	ndpiIPToHostPath = "/data/local/hnc/run/ip_to_host.json"
	// Entries older than this are ignored even if the file is still warm.
	// ndpi_continuous.sh rotates every 60s, so anything older than ~5min is
	// definitely stale (probe must have stopped).
	ndpiEntryMaxAge = 300 * time.Second
)

type ndpiEntry struct {
	IP       string `json:"ip"`
	Host     string `json:"host"`
	LastSeen string `json:"last_seen"`
}

type ndpiFile struct {
	SchemaVersion   string      `json:"schema_version"`
	GeneratedTs     int64       `json:"generated_ts"`
	RotateWindowSec int         `json:"rotate_window_sec"`
	Entries         []ndpiEntry `json:"entries"`
}

type ndpiLookupCache struct {
	mu        sync.RWMutex
	mtime     int64
	size      int64
	loadedAt  time.Time
	generated int64
	ipToHost  map[string]string // remoteIP → hostname (last observation wins)
	available bool              // true after at least one successful load
}

var ndpiCache ndpiLookupCache

// reloadNDPIIfChanged checks the file's mtime/size and re-parses on change.
// Cheap to call repeatedly: stat-only when unchanged.
//
// Returns the populated ipToHost map (may be empty/nil if file missing).
func reloadNDPIIfChanged() map[string]string {
	st, err := os.Stat(ndpiIPToHostPath)
	if err != nil {
		// File missing — clear cache if previously populated.
		ndpiCache.mu.Lock()
		if ndpiCache.available && time.Since(ndpiCache.loadedAt) > ndpiEntryMaxAge {
			ndpiCache.ipToHost = nil
			ndpiCache.available = false
		}
		ndpiCache.mu.Unlock()
		ndpiCache.mu.RLock()
		m := ndpiCache.ipToHost
		ndpiCache.mu.RUnlock()
		return m
	}

	mtime := st.ModTime().UnixNano()
	size := st.Size()

	// Fast path: unchanged file, return cached map.
	ndpiCache.mu.RLock()
	if ndpiCache.mtime == mtime && ndpiCache.size == size {
		m := ndpiCache.ipToHost
		ndpiCache.mu.RUnlock()
		return m
	}
	ndpiCache.mu.RUnlock()

	// Slow path: read + parse.
	b, err := os.ReadFile(ndpiIPToHostPath)
	if err != nil || len(b) == 0 || len(b) > 4*1024*1024 {
		// Don't trust an oversized file. Treat as missing.
		ndpiCache.mu.Lock()
		ndpiCache.mtime = mtime
		ndpiCache.size = size
		ndpiCache.mu.Unlock()
		return nil
	}

	var f ndpiFile
	if err := json.Unmarshal(b, &f); err != nil {
		// Malformed — keep the old cache, but bump mtime so we don't retry
		// every flow event until the next file rotation.
		ndpiCache.mu.Lock()
		ndpiCache.mtime = mtime
		ndpiCache.size = size
		m := ndpiCache.ipToHost
		ndpiCache.mu.Unlock()
		return m
	}

	// Build IP → host map. ndpi_parse_observations.sh emits one entry per
	// (ip, host, last_seen) seen in the current 60s window. Later entries
	// in the array are typically more recent — we let them overwrite earlier
	// ones for the same IP (last-write-wins).
	m := make(map[string]string, len(f.Entries))
	for _, e := range f.Entries {
		ip := strings.TrimSpace(e.IP)
		host := strings.ToLower(strings.TrimSpace(e.Host))
		if ip == "" || host == "" {
			continue
		}
		// Skip obviously bogus entries (some ndpiReader builds emit "0.0.0.0"
		// or "(null)" when SNI was advertised in an early packet before the
		// connection got an IP).
		if ip == "0.0.0.0" || strings.HasPrefix(ip, "(") {
			continue
		}
		m[ip] = host
	}

	ndpiCache.mu.Lock()
	ndpiCache.mtime = mtime
	ndpiCache.size = size
	ndpiCache.loadedAt = time.Now()
	ndpiCache.generated = f.GeneratedTs
	ndpiCache.ipToHost = m
	ndpiCache.available = true
	ndpiCache.mu.Unlock()
	return m
}

// lookupNDPIHost returns the hostname most recently observed by nDPI at
// the given remote IP, or ("", false) if nothing matched.
//
// Hot path: called from EventFlow ONLY when builtin/external IP rules
// didn't match. Cheap (map lookup + occasional file stat).
func lookupNDPIHost(remoteIP string) (string, bool) {
	if remoteIP == "" {
		return "", false
	}
	m := reloadNDPIIfChanged()
	if len(m) == 0 {
		return "", false
	}
	h, ok := m[remoteIP]
	return h, ok
}

// ndpiAvailable returns true if nDPI's ip_to_host.json was read successfully
// at least once in the recent past. Used by /api/state to report nDPI status
// up to the UI.
func ndpiAvailable() bool {
	ndpiCache.mu.RLock()
	defer ndpiCache.mu.RUnlock()
	if !ndpiCache.available {
		return false
	}
	// Stale-after window. nDPI rotates every 60s; if we haven't seen a fresh
	// update in 5 minutes, ndpi_continuous.sh is probably stopped.
	if !ndpiCache.loadedAt.IsZero() && time.Since(ndpiCache.loadedAt) > ndpiEntryMaxAge {
		return false
	}
	return true
}

// ndpiEntryCount reports how many (ip, host) pairs are currently cached.
// Diagnostic for /api/state.
func ndpiEntryCount() int {
	ndpiCache.mu.RLock()
	defer ndpiCache.mu.RUnlock()
	return len(ndpiCache.ipToHost)
}
