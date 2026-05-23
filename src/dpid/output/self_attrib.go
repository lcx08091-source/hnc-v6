// Package output - self_attrib.go: v5.5 /proc/net/* sampler + uid→pkg
// resolution for self-capture mode.
//
// Architecture:
//
//   Every SelfAttribInterval (5s), walk /proc/net/{tcp,tcp6,udp,udp6},
//   dedupe by 5-tuple, look up each socket's uid in a cached map from
//   `pm list packages -U`. Result is a snapshot of "right now, app X
//   has connections to remote IPs Y...". The snapshot is JOIN-able with
//   TLS/DNS events coming from the capture path (which give the SNI
//   side of those remote IPs).
//
// State publication:
//
//   The aggregator's primary output is the SelfState block (state.go).
//   On each tick it builds a new SelfState and hands it to
//   Writer.SetSelf(). The writer takes a deep copy under its lock, so
//   subsequent mutations here are safe.
//
//   Historical JSONL: every tick also appends one line to
//   /data/local/hnc/run/self_attrib.YYYYMMDD.jsonl for offline analysis.
//
// Trade-offs:
//
//   - Cumulative TotalConns increments only when a new (proto, local,
//     remote, uid) tuple appears. Long-lived sessions don't inflate it.
//   - pm cache TTL is 5 min; reduces pm subprocess churn.
//   - We skip TCP LISTEN sockets and all-zero remotes (UDP server
//     sockets bound to 0.0.0.0). These add noise without value.

package output

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// SelfAttribInterval is how often /proc/net is sampled.
	SelfAttribInterval = 5 * time.Second

	// SelfPkgCacheTTL is how often pm list packages -U is re-run.
	SelfPkgCacheTTL = 5 * time.Minute

	// MaxSNIsPerApp caps the TopSNIs slice per app.
	MaxSNIsPerApp = 8

	// MaxRulesPerApp caps the TopRules slice per app.
	MaxRulesPerApp = 4

	// ruleHitCounterMax caps how high a single (uid, ruleID) counter
	// can grow. v5.6.0-rc2: keeps a hot rule from making the counter
	// unbounded; 100,000 is comfortably above the auto-expand threshold
	// (10) and large enough that sort-by-count remains meaningful.
	ruleHitCounterMax = 100000

	// maxUnmatchedSNIs is the hard cap on the auto-expand candidate
	// queue. Exceeded → silently drop new entries until the expander
	// goroutine drains. 4096 covers ~8 hours of normal usage.
	maxUnmatchedSNIs = 4096
)

// SelfAttribObservation is one record written to the historical JSONL.
type SelfAttribObservation struct {
	T     int64               `json:"t"`
	Conns []SelfAttribConnRow `json:"conns"`
}

// uint64BytePair holds the (rx, tx) cumulative byte counts for one
// uid at one sample time. v5.7.0-m1 byte tracking; the aggregator
// keeps two of these per uid (current + previous sample) and the
// Snapshot exports both the cumulative and the delta.
type uint64BytePair struct {
	Rx uint64
	Tx uint64
}

// SelfAttribConnRow is one connection from /proc/net joined with uid→pkg.
type SelfAttribConnRow struct {
	Proto  string `json:"proto"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
	UID    int    `json:"uid"`
	Pkg    string `json:"pkg,omitempty"`
	State  string `json:"state,omitempty"`
}

// SelfAttribAggregator owns the per-uid aggregation. Lives for the
// lifetime of dpid. Construct one with NewSelfAttribAggregator.
type SelfAttribAggregator struct {
	mu sync.Mutex

	// appsByUID is the live aggregation, by uid → SelfApp pointer.
	// Mutated under mu. Cleared (or filtered) when a uid hasn't been
	// seen for staleEvictAge.
	appsByUID map[int]*SelfApp

	// remoteToUID maps "ip:port" → uid for the most recent sample.
	// The capture-side (TLS/DNS events) consults this on every event
	// to attribute SNIs to apps.
	remoteToUID map[string]int

	// snisByUID tracks distinct SNIs per uid, capped to MaxSNIsPerApp.
	snisByUID map[int]map[string]struct{}
	// rulesByUID counts hits per (uid, ruleID). v5.6.0-rc2: upgraded from
	// set to counter so auto-expansion can use "uid hit rule R >= N times"
	// as the evidence requirement #2 (see auto_expand.go). The count is
	// capped per-key at some reasonable max to prevent unbounded growth
	// from a single hot rule on a long-lived uid.
	rulesByUID map[int]map[string]int

	// unmatchedSNIs tracks SNIs observed for some uid that DID NOT match
	// any existing rule. v5.6.0-rc2: feeds the auto-expand candidate
	// queue. Key is sni (normalized), value is the set of uids that have
	// observed this sni since last expander tick.
	unmatchedSNIs map[string]map[int]struct{}

	// pkgCache is the resolved uid→pkg map (TTL'd, refreshed lazily).
	pkgCache         map[int]string
	pkgCacheLoadedAt time.Time
	pkgCacheErr      string

	// ifaceState is the per-iface child status, owned by the
	// reconciler (see self_capture goroutines in main.go).
	ifaceState []SelfIfaceState

	// v5.7.0-m1: per-uid cumulative byte counters from the kernel.
	// Indexed by uid. Updated by RecordBytes on each byteSampler tick.
	// Delta = current cumulative − prevByteCounters[uid] at sample time.
	currByteCounters     map[int]uint64BytePair // (rx, tx) cumulative this sample
	prevByteCounters     map[int]uint64BytePair // (rx, tx) cumulative last sample
	byteSamplerSource    string                 // "ebpf" | "dumpsys" | "none"
	byteSamplerUpdatedAt int64                  // last successful sample time (unix s)

	// v5.7.0-m2: package→display-name resolver. Optional; nil means
	// Snapshot leaves DisplayName empty (UI shows raw pkg fallback).
	// Set via SetAppMetaResolver after construction so output/ stays
	// independent of appmeta/ package.
	appMeta AppMetaResolver

	// counters
	lastTick     int64
	unknownConns int
	enabled      bool
	reason       string

	// File paths
	jsonlDir string

	// Persistent dedupe set for cumulative TotalConns counting. Keyed by
	// "proto|local|remote|uid". Bounded to avoid memory leak; on overflow,
	// the oldest half is dropped (simple ring-style purge).
	seenTuples    map[string]int64 // tuple → first-seen unix
	maxSeenTuples int
}

// NewSelfAttribAggregator constructs one. jsonlDir is the directory
// to write the daily JSONL into (usually cfg.RunDir).
func NewSelfAttribAggregator(jsonlDir string) *SelfAttribAggregator {
	return &SelfAttribAggregator{
		appsByUID:        make(map[int]*SelfApp),
		remoteToUID:      make(map[string]int),
		snisByUID:        make(map[int]map[string]struct{}),
		rulesByUID:       make(map[int]map[string]int),
		unmatchedSNIs:    make(map[string]map[int]struct{}),
		pkgCache:         make(map[int]string),
		currByteCounters: make(map[int]uint64BytePair),
		prevByteCounters: make(map[int]uint64BytePair),
		seenTuples:       make(map[string]int64),
		maxSeenTuples:    4096,
		jsonlDir:         jsonlDir,
	}
}

// SetAppMetaResolver wires the package→display-name resolver. v5.7.0-m2.
// Called once at startup from main.go; safe to skip if not set (Snapshot
// just leaves DisplayName empty in that case). Separate from the
// constructor so the output package doesn't need to import appmeta at
// construction time (it only needs the interface for resolution).
func (a *SelfAttribAggregator) SetAppMetaResolver(r AppMetaResolver) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.appMeta = r
}

// AppMetaResolver is the narrow interface the aggregator needs from
// appmeta. Defined here (in output/) rather than importing appmeta to
// avoid a layering edge — appmeta has its own dependencies (os, json)
// that output/ doesn't need.
type AppMetaResolver interface {
	Display(pkg string) string
}

// appMetaStatser is an optional capability: resolvers that can report
// live PackageManager label diagnostics implement it. Checked via type
// assertion in Snapshot so the narrow AppMetaResolver interface stays
// minimal and resolvers without live labels need not implement it.
type appMetaStatser interface {
	LiveLabelStats() (count int, source string)
}

// SetIfaceState publishes per-iface child status from the capture
// reconciler. Called from main.go whenever child supervisor state
// changes. Cheap; just stores the slice.
func (a *SelfAttribAggregator) SetIfaceState(s []SelfIfaceState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ifaceState = append([]SelfIfaceState(nil), s...)
}

// SetEnabled toggles the "self-capture is active" flag exposed in
// SelfState. Use reason="" to clear the disable explanation.
func (a *SelfAttribAggregator) SetEnabled(enabled bool, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
	a.reason = reason
	if !enabled {
		// Don't drop appsByUID — we want last-known state visible after
		// disable. But clear the live remote→uid map so capture events
		// stop attributing.
		a.remoteToUID = make(map[string]int)
	}
}

// LookupUID is called from the TLS/DNS capture path. Returns (uid, pkg,
// ok). Lock-free read of the snapshot map (a stale read is fine — at
// worst we miss one event; the next 5s tick will catch up).
//
// NOTE: This intentionally takes a quick lock; we could make
// remoteToUID a sync.Map but the cost-benefit at 5s replacement cadence
// is not worth the complexity.
func (a *SelfAttribAggregator) LookupUID(remoteIP string, remotePort uint16) (uid int, pkg string, ok bool) {
	key := fmt.Sprintf("%s:%d", remoteIP, remotePort)
	a.mu.Lock()
	defer a.mu.Unlock()
	uid, ok = a.remoteToUID[key]
	if !ok {
		return 0, "", false
	}
	pkg = a.pkgCache[uid]
	return uid, pkg, true
}

// ByteSample is the per-uid byte counts handed to RecordBytes. Defined
// here in output/ rather than imported from bytestats/ to avoid the
// reverse dependency edge — output/ already has many callers and we
// don't want to drag in the eBPF/dumpsys backends just to define types.
// Callers (cmd/dpid/main.go) translate from bytestats.ByteCounts to
// output.ByteSample. Cheap translation (4 uint64 copies).
type ByteSample struct {
	RxBytes uint64
	TxBytes uint64
}

// RecordBytes is called by the byteSampler goroutine on each tick
// (~5s) with a fresh map of cumulative per-uid byte counters from the
// kernel. We rotate curr→prev and install the new sample so the next
// Snapshot can compute deltas.
//
// source identifies the backend feeding data ("ebpf" | "dumpsys" |
// "none"), surfaced in dpi_state.json so the UI can show users where
// the numbers come from.
//
// now is the unix timestamp (seconds) of this sample, also surfaced
// per-app as ByteSamplerUpdatedAt.
func (a *SelfAttribAggregator) RecordBytes(samples map[int]ByteSample, source string, now int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Rotate: current cumulative → previous, install new as current.
	a.prevByteCounters = a.currByteCounters
	a.currByteCounters = make(map[int]uint64BytePair, len(samples))
	for uid, bs := range samples {
		a.currByteCounters[uid] = uint64BytePair{Rx: bs.RxBytes, Tx: bs.TxBytes}
	}
	a.byteSamplerSource = source
	a.byteSamplerUpdatedAt = now
}

// RecordSNI is called from the capture path when a TLS ClientHello
// extracted a SNI on a remote we have a uid for. Updates TopSNIs +
// LastSeen for the relevant SelfApp.
func (a *SelfAttribAggregator) RecordSNI(uid int, sni string, now int64) {
	if uid == 0 || sni == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	app := a.ensureAppLocked(uid, now)
	app.LastSeen = now
	if a.snisByUID[uid] == nil {
		a.snisByUID[uid] = make(map[string]struct{})
	}
	if len(a.snisByUID[uid]) < MaxSNIsPerApp {
		a.snisByUID[uid][sni] = struct{}{}
	}
}

// RecordRuleHit is called when the L3 classifier matched a rule for a
// flow that we have a uid for. ruleID is the matched rule (e.g.
// "tencent_jkmobile_tft"). v5.6.0-rc2: now a counter (was set), feeds
// the auto-expand evidence-#2 check via HitCount().
func (a *SelfAttribAggregator) RecordRuleHit(uid int, ruleID string, now int64) {
	if uid == 0 || ruleID == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	app := a.ensureAppLocked(uid, now)
	app.LastSeen = now
	if a.rulesByUID[uid] == nil {
		a.rulesByUID[uid] = make(map[string]int)
	}
	// MaxRulesPerApp guard: refuse NEW keys when full, but keep counting
	// existing ones (so a hot rule's count keeps growing while we don't
	// admit new ones we won't have room to display).
	if _, exists := a.rulesByUID[uid][ruleID]; exists {
		if a.rulesByUID[uid][ruleID] < ruleHitCounterMax {
			a.rulesByUID[uid][ruleID]++
		}
	} else if len(a.rulesByUID[uid]) < MaxRulesPerApp {
		a.rulesByUID[uid][ruleID] = 1
	}
}

// HitCount returns how many times (uid, ruleID) has been observed.
// Returns 0 if uid or rule unseen. Lifetime-of-process counter; no
// persistence across dpid restarts.
func (a *SelfAttribAggregator) HitCount(uid int, ruleID string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if m := a.rulesByUID[uid]; m != nil {
		return m[ruleID]
	}
	return 0
}

// ObserveSNI is the unified entry from self_capture: store the SNI,
// classify it against the rule set, and dispatch.
//   - If classify hits a rule → RecordRuleHit (counter ++).
//   - If classify misses → enqueue into unmatched queue for auto-expand.
//
// This must be called instead of (not in addition to) RecordSNI from
// self_capture. RecordSNI stays as a lower-level primitive for code paths
// (tests, future) that just want to register an SNI without classification.
func (a *SelfAttribAggregator) ObserveSNI(uid int, sni string, now int64) {
	if uid == 0 || sni == "" {
		return
	}
	a.RecordSNI(uid, sni, now)
	rule, hit := classifyHost(sni)
	if hit {
		a.RecordRuleHit(uid, rule.ID, now)
		return
	}
	// Unmatched — candidate for auto-expansion.
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.unmatchedSNIs[sni] == nil {
		if len(a.unmatchedSNIs) >= maxUnmatchedSNIs {
			// Hard cap to prevent runaway memory under SNI flood. New
			// candidates beyond this are silently dropped until the
			// expander goroutine drains the map. The number 4096 is
			// generous (a busy phone sees ~500 distinct SNIs/hour).
			return
		}
		a.unmatchedSNIs[sni] = make(map[int]struct{})
	}
	a.unmatchedSNIs[sni][uid] = struct{}{}
}

// drainUnmatchedSNIs atomically takes ownership of the unmatched queue
// and clears it. Called by the auto-expander goroutine each tick.
func (a *SelfAttribAggregator) drainUnmatchedSNIs() map[string]map[int]struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.unmatchedSNIs
	a.unmatchedSNIs = make(map[string]map[int]struct{})
	return out
}

// PkgForUID is a public accessor for the resolved package name (used by
// the auto-expander when writing evidence).
func (a *SelfAttribAggregator) PkgForUID(uid int) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pkgCache[uid]
}

func (a *SelfAttribAggregator) ensureAppLocked(uid int, now int64) *SelfApp {
	app := a.appsByUID[uid]
	if app != nil {
		return app
	}
	app = &SelfApp{
		UID:       uid,
		Pkg:       a.pkgCache[uid],
		FirstSeen: now,
		LastSeen:  now,
	}
	a.appsByUID[uid] = app
	return app
}

// Snapshot builds a SelfState from current aggregation. Caller owns the
// returned pointer (typically passes it to Writer.SetSelf).
func (a *SelfAttribAggregator) Snapshot() *SelfState {
	a.mu.Lock()
	defer a.mu.Unlock()

	s := &SelfState{
		Enabled:        a.enabled,
		Reason:         a.reason,
		Interfaces:     append([]SelfIfaceState(nil), a.ifaceState...),
		LastAttribTick: a.lastTick,
		UnknownConns:   a.unknownConns,
		PkgCacheSize:   len(a.pkgCache),
	}
	if len(a.appsByUID) > 0 {
		s.AppsByUID = make(map[string]*SelfApp, len(a.appsByUID))
		for uid, app := range a.appsByUID {
			cp := *app // shallow copy
			// Materialize SNI set as sorted slice (deterministic for diffing)
			if set := a.snisByUID[uid]; set != nil {
				snis := make([]string, 0, len(set))
				for k := range set {
					snis = append(snis, k)
				}
				sort.Strings(snis)
				cp.TopSNIs = snis
			}
			if hits := a.rulesByUID[uid]; hits != nil {
				// v5.6.0-rc2: sort by hit count descending (was
				// alphabetic). WebUI cares about "most-used rules",
				// not lex order; ties broken by rule ID for stability.
				rules := make([]string, 0, len(hits))
				for k := range hits {
					rules = append(rules, k)
				}
				sort.Slice(rules, func(i, j int) bool {
					if hits[rules[i]] != hits[rules[j]] {
						return hits[rules[i]] > hits[rules[j]]
					}
					return rules[i] < rules[j]
				})
				cp.TopRules = rules
				// v5.6.0-rc5: also export the raw counts so debugging
				// auto-expansion thresholds is possible from outside.
				cp.RuleHitCounts = make(map[string]int, len(hits))
				for k, v := range hits {
					cp.RuleHitCounts[k] = v
				}
			}
			// v5.7.0-m1: per-uid byte counters + delta. omitempty in the
			// struct tag means uids with no byte data drop these fields
			// entirely from the JSON (vs reporting zeros that confuse the
			// UI into thinking the app is idle).
			if curr, ok := a.currByteCounters[uid]; ok {
				cp.RxBytes = curr.Rx
				cp.TxBytes = curr.Tx
				if prev, hasPrev := a.prevByteCounters[uid]; hasPrev {
					// Diff against previous sample. If kernel counter
					// somehow went backwards (counter reset on reboot
					// reload, uid recycled, etc), clamp delta to 0
					// rather than underflow.
					if curr.Rx >= prev.Rx {
						cp.RxBytesDelta = curr.Rx - prev.Rx
					}
					if curr.Tx >= prev.Tx {
						cp.TxBytesDelta = curr.Tx - prev.Tx
					}
				}
				cp.ByteSamplerUpdatedAt = a.byteSamplerUpdatedAt
			}
			// v5.7.0-m2: resolve display name. Cheap (single map lookup
			// inside appmeta + optional reloadOverridesIfChanged stat).
			// Done here in Snapshot rather than at uid resolution time
			// so user override file edits take effect within ~5s without
			// dpid restart.
			if a.appMeta != nil && cp.Pkg != "" {
				cp.DisplayName = a.appMeta.Display(cp.Pkg)
			}
			s.AppsByUID[strconv.Itoa(uid)] = &cp
		}
	}
	// v5.6.0-rc5: surface auto-expand input queue size and a sample of
	// what's in it. Sample is capped to 20 SNIs alphabetically (stable
	// across calls so the WebUI doesn't churn).
	s.UnmatchedSNIsPending = len(a.unmatchedSNIs)
	if len(a.unmatchedSNIs) > 0 {
		snis := make([]string, 0, len(a.unmatchedSNIs))
		for k := range a.unmatchedSNIs {
			snis = append(snis, k)
		}
		sort.Strings(snis)
		if len(snis) > 20 {
			snis = snis[:20]
		}
		s.UnmatchedSNISamples = snis
	}
	// v5.7.0-m1: surface which byte sampler backend is feeding data
	// (ebpf/dumpsys/none). Empty string means RecordBytes was never
	// called (byteSampler goroutine not started yet, or no backend).
	s.ByteSamplerSource = a.byteSamplerSource

	// app-label diagnostics: report whether DisplayName came from the live
	// PackageManager helper or the curated fallback (best-effort capability).
	if st, ok := a.appMeta.(appMetaStatser); ok {
		s.LiveLabelCount, s.AppLabelSource = st.LiveLabelStats()
	}
	return s
}

// RunSampler is the goroutine main loop. Blocks until ctx done. Reads
// the enable flag every tick from a runtime hook callback (so the
// supervisor in main.go controls whether sampling runs).
func (a *SelfAttribAggregator) RunSampler(ctx context.Context, isEnabled func() bool) {
	t := time.NewTicker(SelfAttribInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !isEnabled() {
				continue
			}
			if err := a.sampleOnce(); err != nil {
				log.Printf("self-attrib: sample tick failed: %v", err)
			}
		}
	}
}

// sampleOnce is one /proc/net pass + JSONL write.
func (a *SelfAttribAggregator) sampleOnce() error {
	now := time.Now()
	pkgMap := a.getPkgCache()

	var rows []SelfAttribConnRow
	seen := make(map[string]bool)
	newRemoteToUID := make(map[string]int, 128)
	unknownConns := 0

	for _, src := range []struct {
		proto string
		path  string
		ipv6  bool
	}{
		{"tcp", "/proc/net/tcp", false},
		{"tcp", "/proc/net/tcp6", true},
		{"udp", "/proc/net/udp", false},
		{"udp", "/proc/net/udp6", true},
	} {
		entries, err := parseProcNet(src.path, src.proto, src.ipv6)
		if err != nil {
			// some kernels don't have all 4 — fine
			continue
		}
		for _, e := range entries {
			key := e.Proto + "|" + e.Local + "|" + e.Remote
			if seen[key] {
				continue
			}
			seen[key] = true
			if pkg, ok := pkgMap[e.UID]; ok {
				e.Pkg = pkg
			} else if e.UID > 0 {
				unknownConns++
			}
			newRemoteToUID[e.Remote] = e.UID
			rows = append(rows, e)
		}
	}

	// Append to JSONL
	if a.jsonlDir != "" {
		dayPath := filepath.Join(a.jsonlDir,
			fmt.Sprintf("self_attrib.%s.jsonl", now.Format("20060102")))
		if f, err := os.OpenFile(dayPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			obs := SelfAttribObservation{T: now.Unix(), Conns: rows}
			_ = json.NewEncoder(f).Encode(obs)
			_ = f.Close()
		}
	}

	// Update aggregator
	a.mu.Lock()
	a.remoteToUID = newRemoteToUID
	a.lastTick = now.Unix()
	a.unknownConns = unknownConns

	// Walk rows: bump active_conns + cumulative TotalConns counters per uid.
	activeByUID := make(map[int]int, 64)
	for _, r := range rows {
		activeByUID[r.UID]++
		// Cumulative dedupe by full tuple
		tupleKey := r.Proto + "|" + r.Local + "|" + r.Remote + "|" + strconv.Itoa(r.UID)
		if _, seen := a.seenTuples[tupleKey]; !seen {
			a.seenTuples[tupleKey] = now.Unix()
			if app := a.ensureAppLocked(r.UID, now.Unix()); app != nil {
				app.TotalConns++
				app.LastSeen = now.Unix()
				if r.Pkg != "" && app.Pkg == "" {
					app.Pkg = r.Pkg
				}
			}
		}
	}
	// Apply ActiveConns + backfill Pkg if pm just learned it
	for uid, n := range activeByUID {
		if app := a.appsByUID[uid]; app != nil {
			app.ActiveConns = n
			if app.Pkg == "" {
				if pkg, ok := pkgMap[uid]; ok {
					app.Pkg = pkg
				}
			}
		}
	}
	// Zero out ActiveConns on apps that didn't appear this tick
	for uid, app := range a.appsByUID {
		if _, ok := activeByUID[uid]; !ok {
			app.ActiveConns = 0
		}
	}
	a.purgeSeenTuplesIfFullLocked()
	a.mu.Unlock()

	return nil
}

// purgeSeenTuplesIfFullLocked keeps the dedupe set bounded.
func (a *SelfAttribAggregator) purgeSeenTuplesIfFullLocked() {
	if len(a.seenTuples) <= a.maxSeenTuples {
		return
	}
	// Drop half — keep newest by first-seen time.
	type tk struct {
		key string
		ts  int64
	}
	all := make([]tk, 0, len(a.seenTuples))
	for k, v := range a.seenTuples {
		all = append(all, tk{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ts < all[j].ts })
	cutoff := len(all) / 2
	for _, t := range all[:cutoff] {
		delete(a.seenTuples, t.key)
	}
}

// ─── pkg cache (TTL'd) ────────────────────────────────────────────────

func (a *SelfAttribAggregator) getPkgCache() map[int]string {
	a.mu.Lock()
	if a.pkgCache != nil && time.Since(a.pkgCacheLoadedAt) < SelfPkgCacheTTL {
		out := a.pkgCache
		a.mu.Unlock()
		return out
	}
	a.mu.Unlock()

	m, err := loadPkgUIDs()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.pkgCacheErr = err.Error()
		if a.pkgCache == nil {
			a.pkgCache = make(map[int]string)
		}
		return a.pkgCache
	}
	a.pkgCache = m
	a.pkgCacheLoadedAt = time.Now()
	a.pkgCacheErr = ""
	return m
}

// loadPkgUIDs runs `pm list packages -U` and parses output:
//
//	package:com.tencent.jkchess uid:10123
func loadPkgUIDs() (map[int]string, error) {
	cmd := exec.Command("pm", "list", "packages", "-U")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	m := make(map[int]string, 256)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "package:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		pkg := strings.TrimPrefix(parts[0], "package:")
		uidStr := strings.TrimPrefix(parts[1], "uid:")
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			continue
		}
		// Multiple packages can share a uid (sharedUserId). First wins —
		// in practice this is fine because shared uids are well-known
		// system ones (e.g. android.uid.system) and not what we want to
		// surface anyway.
		if _, ok := m[uid]; !ok {
			m[uid] = pkg
		}
	}
	return m, nil
}

// ─── /proc/net parser ────────────────────────────────────────────────

func parseProcNet(path, proto string, isIPv6 bool) ([]SelfAttribConnRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []SelfAttribConnRow
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue
		}
		local := parseHexAddr(fields[1], isIPv6)
		remote := parseHexAddr(fields[2], isIPv6)
		stateHex := fields[3]
		state := tcpStateName(stateHex)

		// Skip TCP LISTEN — meaningless for "who is my app talking to".
		if proto == "tcp" && stateHex == "0A" {
			continue
		}
		// Skip all-zero remote (UDP server sockets bound to 0.0.0.0:port,
		// etc.) — they have no remote peer.
		if strings.HasPrefix(remote, "0.0.0.0:") || strings.HasPrefix(remote, "[::]:") {
			continue
		}

		uid, _ := strconv.Atoi(fields[7])
		out = append(out, SelfAttribConnRow{
			Proto:  proto,
			Local:  local,
			Remote: remote,
			UID:    uid,
			State:  state,
		})
	}
	return out, sc.Err()
}

// parseHexAddr converts "0100007F:1F40" (IPv4 little-endian per byte
// pair) or "00000000000000000000000001000000:1F40" (IPv6, per-word LE)
// to a normal "ip:port" string. IPv6 is wrapped in [].
func parseHexAddr(s string, isIPv6 bool) string {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return s
	}
	portN, _ := strconv.ParseUint(parts[1], 16, 16)

	if !isIPv6 {
		if len(parts[0]) != 8 {
			return s
		}
		var b [4]byte
		for i := 0; i < 4; i++ {
			v, _ := strconv.ParseUint(parts[0][i*2:i*2+2], 16, 8)
			b[3-i] = byte(v) // little-endian
		}
		return fmt.Sprintf("%d.%d.%d.%d:%d", b[0], b[1], b[2], b[3], portN)
	}

	if len(parts[0]) != 32 {
		return s
	}
	var words [4]uint32
	for i := 0; i < 4; i++ {
		w, _ := strconv.ParseUint(parts[0][i*8:i*8+8], 16, 32)
		words[i] = uint32(w&0xff)<<24 | uint32((w>>8)&0xff)<<16 |
			uint32((w>>16)&0xff)<<8 | uint32((w>>24)&0xff)
	}
	return fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
		uint16(words[0]>>16), uint16(words[0]&0xffff),
		uint16(words[1]>>16), uint16(words[1]&0xffff),
		uint16(words[2]>>16), uint16(words[2]&0xffff),
		uint16(words[3]>>16), uint16(words[3]&0xffff),
		portN)
}

func tcpStateName(hex string) string {
	switch hex {
	case "01":
		return "ESTABLISHED"
	case "02":
		return "SYN_SENT"
	case "03":
		return "SYN_RECV"
	case "04":
		return "FIN_WAIT1"
	case "05":
		return "FIN_WAIT2"
	case "06":
		return "TIME_WAIT"
	case "07":
		return "CLOSE"
	case "08":
		return "CLOSE_WAIT"
	case "09":
		return "LAST_ACK"
	case "0A":
		return "LISTEN"
	case "0B":
		return "CLOSING"
	default:
		return hex
	}
}
