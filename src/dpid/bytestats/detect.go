// Package bytestats - detect.go.
//
// Selects the best available ByteSampler at startup. Tried in order:
//
//   1. eBPF — direct read of the netd-shared map. Real-time, ~free.
//   2. dumpsys — text parser of `dumpsys netstats detail`. Slow but works.
//   3. None — graceful degradation, all uids report 0 bytes.
//
// Each backend's constructor does its own "is this viable?" check, so
// Detect() just tries them in order and uses the first one that succeeds.
//
// The user sees which backend won via SelfState.ByteSamplerSource in
// dpi_state.json ("ebpf" | "dumpsys" | "none"). This is intentionally
// surfaced so they can debug "why is YouTube showing 0 bytes" without
// reading dpid.log.

package bytestats

import "log"

// NoneSampler is the always-available zero-data fallback. It exists so
// callers don't need nil checks: ByteSampler is never nil, just sometimes
// reports zeros.
type NoneSampler struct{}

func (n *NoneSampler) Source() string                          { return "none" }
func (n *NoneSampler) Close() error                            { return nil }
func (n *NoneSampler) Sample() (map[int]ByteCounts, error)     { return map[int]ByteCounts{}, nil }

// Detect picks a backend, logs which one won, returns it. Never returns
// nil — at worst, NoneSampler. Callers should still check Source() to
// decide whether to surface byte data in the UI.
func Detect() ByteSampler {
	if s, err := NewEBPFSampler(); err == nil {
		log.Printf("bytestats: eBPF backend active (map_netd_app_uid_stats_map)")
		return s
	} else {
		log.Printf("bytestats: eBPF unavailable (%v), trying dumpsys", err)
	}

	if s, err := NewDumpsysSampler(); err == nil {
		log.Printf("bytestats: dumpsys backend active (fork+parse mode)")
		return s
	} else {
		log.Printf("bytestats: dumpsys unavailable (%v), using none", err)
	}

	log.Printf("bytestats: ⚠ no backend available, per-uid byte stats disabled")
	return &NoneSampler{}
}
