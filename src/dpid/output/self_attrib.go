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
//   /data/local/hnc/data/self_studio/self_attrib.YYYYMMDD.jsonl for offline analysis.
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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// DefaultSelfStudioSubdir is the persistent storage subdirectory under <hncDir>
	// for self_attrib.*.jsonl and label_samples.* (moved out of 32M tmpfs run/).
	DefaultSelfStudioSubdir = "data/self_studio"

	// SelfAttribInterval is how often /proc/net is sampled.
	SelfAttribInterval = 5 * time.Second

	// SelfAttribRetainDays is how many daily self_attrib.YYYYMMDD.jsonl
	// files are kept under persistent data/self_studio.
	SelfAttribRetainDays = 3

	// SelfAttribMaxDailyBytes caps each daily JSONL file at 4 MiB.
	SelfAttribMaxDailyBytes = 4 << 20 // 4 MiB per day cap

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
	// queue. Exceeded -> silently drop new entries until the expander
	// goroutine drains. 4096 covers ~8 hours of normal usage.
	maxUnmatchedSNIs = 4096
)

// SelfStudioDir resolves <hncDir>/data/self_studio from a given hncDir.
func SelfStudioDir(hncDir string) string {
	if strings.TrimSpace(hncDir) == "" {
		hncDir = "/data/local/hnc"
	}
	return filepath.Join(filepath.Clean(hncDir), "data", "self_studio")
}

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

// SelfAttribConnRow is one connection from /proc/net joined with uid->pkg.
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
	mu           sync.Mutex
	pkgRefreshMu sync.Mutex

	// lastJSONLSig is the sorted connection-set signature of the most recent
	// JSONL append (see sampleOnce). Owned by sampleMu.
	lastJSONLSig string

	// appsByUID is the live aggregation, by uid -> SelfApp pointer.
	// Mutated under mu. Cleared (or filtered) when a uid hasn't been
	// seen for staleEvictAge.
	appsByUID map[int]*SelfApp

	// remoteToUID maps "ip:port" -> uid for the most recent sample.
	// The capture-side (TLS/DNS events) consults this on every event
	// to attribute SNIs to apps.
	remoteToUID map[string]int

	// snisByUID tracks distinct SNIs per uid, capped to MaxSNIsPerApp.
	// v5.8.8 (audit): value is last-seen unix ts so the cap is LRU (evict
	// oldest) instead of "drop everything after the first 8" — the latter
	// froze an app's SNI set forever once it hit 8, distorting attribution.
	snisByUID map[int]map[string]int64
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

	// pkgCache is the resolved uid->pkg map (TTL'd, refreshed lazily).
	pkgCache         map[int]string
	pkgCacheLoadedAt time.Time
	pkgCacheErr      string
	// v5.7.0-rc9: set of system package names (pm list packages -s),
	// refreshed alongside pkgCache. Used to keep system apps out of the
	// flywheel and to collapse them in the WebUI.
	systemPkgs map[string]struct{}

	// v5.7.0-rc33: set of VPN/proxy package names excluded from the flywheel
	// (built-in seed U user file). Refreshed alongside pkgCache. uids resolving
	// to these never accumulate candidates / get auto-promotions, because a VPN
	// re-originates other apps' traffic and would mis-attribute their domains to
	// itself. Initialized to the built-in seed in the constructor so the guard
	// is live even before the first pkg-cache refresh.
	flywheelExcludePkgs map[string]struct{}

	// v5.7.0-rc35: uids the expander flagged as conduits (VPN/proxy/browser by
	// apex cardinality). Published by the expander each tick via SetConduitUIDs;
	// read in Snapshot to badge those apps as flywheel-excluded in the WebUI.
	conduitUIDs map[int]struct{}

	// ifaceState is the per-iface child status, owned by the
	// reconciler (see self_capture goroutines in main.go).
	ifaceState []SelfIfaceState

	// v5.7.0-m1: per-uid cumulative byte counters from the kernel.
	// Indexed by uid. Updated by RecordBytes on each byteSampler tick.
	// Delta = current cumulative - prevByteCounters[uid] at sample time.
	currByteCounters     map[int]uint64BytePair // (rx, tx) cumulative this sample
	prevByteCounters     map[int]uint64BytePair // (rx, tx) cumulative last sample
	byteSamplerSource    string                 // "ebpf" | "dumpsys" | "none"
	byteSamplerUpdatedAt int64                  // last successful sample time (unix s)

	// v5.7.0-m2: package->display-name resolver. Optional; nil means
	// Snapshot leaves DisplayName empty (UI shows raw pkg fallback).
	// Set via SetAppMetaResolver after construction so output/ stays
	// independent of appmeta/ package.
	appMeta AppMetaResolver

	// v5.7: brand-new-apex candidate accumulator summary, published by the
	// expander goroutine each tick (see candidate.go) and surfaced in
	// dpi_state for shadow calibration / auto-promote diagnostics.
	candidateSummary candidateSummary

	remoteIPToUID     map[string]int
	autoExpandedCount int
	expandKick        chan struct{}
	sampleMu          sync.Mutex

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
	seenTuples    map[string]int64 // tuple -> first-seen unix
	maxSeenTuples int
}

// NewSelfAttribAggregator constructs one. jsonlDir is the persistent directory
// to write the daily JSONL into (typically <hncDir>/data/self_studio; if a
// legacy <hncDir>/run path is passed, callers should prefer SelfStudioDir).
func NewSelfAttribAggregator(jsonlDir string) *SelfAttribAggregator {
	if jsonlDir != "" {
		_ = os.MkdirAll(jsonlDir, 0o755)
	}
	return &SelfAttribAggregator{
		appsByUID:        make(map[int]*SelfApp),
		remoteToUID:      make(map[string]int),
		remoteIPToUID:    make(map[string]int),
		expandKick:       make(chan struct{}, 1),
		snisByUID:        make(map[int]map[string]int64),
		rulesByUID:       make(map[int]map[string]int),
		unmatchedSNIs:    make(map[string]map[int]struct{}),
		pkgCache:         make(map[int]string),
		currByteCounters: make(map[int]uint64BytePair),
		prevByteCounters: make(map[int]uint64BytePair),
		seenTuples:       make(map[string]int64),
		maxSeenTuples:    4096,
		jsonlDir:         jsonlDir,
		// Seed the flywheel exclusion immediately so VPN/proxy guards are live
		// before the first pkg-cache refresh (and so existing bad promotions get
		// demoted on the very first expander tick by stored UIDPkg).
		flywheelExcludePkgs: loadFlywheelExcludePkgs(),
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
		a.remoteIPToUID = make(map[string]int)
	}
}

// SetAutoExpandedCount records confirmed _auto_expanded.json rule count for Studio telemetry.
func (a *SelfAttribAggregator) SetAutoExpandedCount(n int) {
	a.mu.Lock()
	a.autoExpandedCount = n
	a.mu.Unlock()
}

// TriggerExpandNow wakes RunAutoExpander immediately when Studio pokes dpid.
func (a *SelfAttribAggregator) TriggerExpandNow() {
	if a == nil || a.expandKick == nil {
		return
	}
	select {
	case a.expandKick <- struct{}{}:
	default:
	}
}

// SampleNow runs an immediate /proc/net attribution pass when Studio starts or distills.
func (a *SelfAttribAggregator) SampleNow() {
	if a == nil {
		return
	}
	_ = a.sampleOnce()
}

// LookupUID is called from the TLS/DNS capture path. Returns (uid, pkg,
// ok). Lock-free read of the snapshot map (a stale read is fine — at
// worst we miss one event; the next 5s tick will catch up).
//
// NOTE: This intentionally takes a quick lock; we could make
// remoteToUID a sync.Map but the cost-benefit at 5s replacement cadence
// is not worth the complexity.
func (a *SelfAttribAggregator) LookupUID(remoteIP string, remotePort uint16) (uid int, pkg string, ok bool) {
	// v5.12: 用与 sampleOnce 建表相同的规范化键(见 canonRemoteKey)。
	key := canonIPPort(remoteIP, strconv.Itoa(int(remotePort)))
	ipKey := canonIPOnly(remoteIP)
	a.mu.Lock()
	defer a.mu.Unlock()
	uid, ok = a.remoteToUID[key]
	if !ok && ipKey != "" {
		if u2, ok2 := a.remoteIPToUID[ipKey]; ok2 && u2 > 0 {
			uid, ok = u2, true
		}
	}
	if !ok || uid <= 0 {
		return 0, "", false
	}
	pkg = a.resolvePkgByUIDLocked(uid)
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
		a.snisByUID[uid] = make(map[string]int64)
	}
	// touchIP is a generic bounded last-seen LRU set (defined in state.go);
	// here it keeps the newest MaxSNIsPerApp SNIs per app, evicting the oldest.
	touchIP(a.snisByUID[uid], sni, now, MaxSNIsPerApp)
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
	return a.resolvePkgByUIDLocked(uid)
}

// DisplayForUID resolves a uid to its (package, human-label) via the pm cache
// + appMeta resolver. label is "" if pkg unknown or no resolver. v5.7.
func (a *SelfAttribAggregator) DisplayForUID(uid int) (pkg, label string) {
	a.mu.Lock()
	pkg = a.resolvePkgByUIDLocked(uid)
	m := a.appMeta
	a.mu.Unlock()
	if m != nil && pkg != "" {
		label = m.Display(pkg)
	}
	return pkg, label
}

// SetCandidateSummary publishes the expander goroutine's per-tick candidate
// summary so Snapshot can surface it in dpi_state. v5.7.
func (a *SelfAttribAggregator) SetCandidateSummary(s candidateSummary) {
	a.mu.Lock()
	a.candidateSummary = s
	a.mu.Unlock()
}

// SetConduitUIDs publishes the set of uids the expander flagged as conduits
// (VPN/proxy/browser by apex cardinality), so Snapshot can badge those apps as
// flywheel-excluded. Takes a copy; caller may mutate after the call. v5.7.0-rc35.
func (a *SelfAttribAggregator) SetConduitUIDs(uids map[int]struct{}) {
	cp := make(map[int]struct{}, len(uids))
	for u := range uids {
		cp[u] = struct{}{}
	}
	a.mu.Lock()
	a.conduitUIDs = cp
	a.mu.Unlock()
}

func (a *SelfAttribAggregator) resetUIDStateLocked(uid int) {
	delete(a.snisByUID, uid)
	delete(a.rulesByUID, uid)
	for sni, uidSet := range a.unmatchedSNIs {
		if _, has := uidSet[uid]; has {
			delete(uidSet, uid)
			if len(uidSet) == 0 {
				delete(a.unmatchedSNIs, sni)
			}
		}
	}
	if a.conduitUIDs != nil {
		delete(a.conduitUIDs, uid)
	}
	delete(a.currByteCounters, uid)
	delete(a.prevByteCounters, uid)
	suf := "|" + strconv.Itoa(uid)
	for k := range a.seenTuples {
		if strings.HasSuffix(k, suf) {
			delete(a.seenTuples, k)
		}
	}
	delete(a.appsByUID, uid)
}

func (a *SelfAttribAggregator) ensureAppLocked(uid int, now int64) *SelfApp {
	curPkg := a.resolvePkgByUIDLocked(uid)
	app := a.appsByUID[uid]
	if app != nil {
		if curPkg != "" && app.Pkg != "" && app.Pkg != curPkg {
			a.resetUIDStateLocked(uid)
			app = nil
		} else {
			if app.Pkg == "" && curPkg != "" {
				app.Pkg = curPkg
			}
			return app
		}
	}
	app = &SelfApp{
		UID:       uid,
		Pkg:       curPkg,
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
	resolver := a.appMeta
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
			if a.systemPkgs != nil && cp.Pkg != "" {
				_, cp.IsSystem = a.systemPkgs[cp.Pkg]
			}
			// v5.7.0-rc35: badge flywheel-excluded apps (VPN/proxy on the list, or
			// a detected conduit uid) so the WebUI can explain why they get no rules.
			if cp.Pkg != "" && a.flywheelExcludePkgs != nil {
				_, cp.FlywheelExcluded = a.flywheelExcludePkgs[cp.Pkg]
			}
			if !cp.FlywheelExcluded && a.conduitUIDs != nil {
				_, cp.FlywheelExcluded = a.conduitUIDs[uid]
			}
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
				cp.RuleHitCounts = make(map[string]int, len(hits))
				for k, v := range hits {
					cp.RuleHitCounts[k] = v
				}
			}
			if curr, ok := a.currByteCounters[uid]; ok {
				cp.RxBytes = curr.Rx
				cp.TxBytes = curr.Tx
				if prev, hasPrev := a.prevByteCounters[uid]; hasPrev {
					if curr.Rx >= prev.Rx {
						cp.RxBytesDelta = curr.Rx - prev.Rx
					}
					if curr.Tx >= prev.Tx {
						cp.TxBytesDelta = curr.Tx - prev.Tx
					}
				}
				cp.ByteSamplerUpdatedAt = a.byteSamplerUpdatedAt
			}
			s.AppsByUID[strconv.Itoa(uid)] = &cp
		}
	}
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
	s.ByteSamplerSource = a.byteSamplerSource

	cs := a.candidateSummary
	s.CandidatePending = cs.pending
	s.CandidateHigh = cs.high
	s.CandidateShared = cs.shared
	s.CandidatePromoted = cs.promoted
	s.AutoExpandedCount = a.autoExpandedCount
	s.AutoPromotedCount = cs.promoted
	s.CandidateEntityDB = cs.entityDBSize
	s.AutoPromoteOn = cs.autoPromoteOn
	if len(cs.samples) > 0 {
		s.CandidateSamples = append([]CandidateSample(nil), cs.samples...)
	}
	a.mu.Unlock()

	// 死定律四: 在释放 a.mu 之后再解析 DisplayName 与 LiveLabelStats(内部可能触发磁盘 Stat/ReadFile)。
	if resolver != nil {
		for _, cp := range s.AppsByUID {
			if cp.Pkg != "" {
				cp.DisplayName = resolver.Display(cp.Pkg)
			}
		}
		if st, ok := resolver.(appMetaStatser); ok {
			s.LiveLabelCount, s.AppLabelSource = st.LiveLabelStats()
		}
	}
	return s
}

// RunSampler is the goroutine main loop. Blocks until ctx done. Reads
// the enable flag every tick from a runtime hook callback (so the
// supervisor in main.go controls whether sampling runs).
func (a *SelfAttribAggregator) RunSampler(ctx context.Context, isEnabled func() bool) {
	t := time.NewTicker(SelfAttribInterval)
	defer t.Stop()

	lastTrimDay := ""

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if a.jsonlDir != "" {
				if day := time.Now().Format("20060102"); day != lastTrimDay {
					trimDailyFiles(a.jsonlDir, "self_attrib.", SelfAttribRetainDays)
					lastTrimDay = day
				}
			}
			if !isEnabled() {
				continue
			}
			if err := a.sampleOnce(); err != nil {
				log.Printf("self-attrib: sample tick failed: %v", err)
			}
		}
	}
}

// connsSignature builds an order-independent fingerprint of a connection set,
// deliberately omitting the ephemeral local address/port (r.Local) and keeping
// only "proto|uid|remote|pkg" deduplicated across short-lived reconnects.
// This eliminates 90%+ redundant JSONL write amplification when apps rotate
// ephemeral source ports against the same remote endpoint.
func connsSignature(rows []SelfAttribConnRow) string {
	if len(rows) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(rows))
	keys := make([]string, 0, len(rows))
	for _, r := range rows {
		rem := canonRemoteKey(r.Remote)
		if rem == "" {
			rem = r.Remote
		}
		k := r.Proto + "|" + strconv.Itoa(r.UID) + "|" + rem + "|" + r.Pkg
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, "\n")
}

// sampleOnce is one /proc/net pass + JSONL write.
func resolvePkgInMap(pkgMap map[int]string, uid int) string {
	if uid <= 0 || pkgMap == nil {
		return ""
	}
	if p := pkgMap[uid]; p != "" {
		return p
	}
	appID := uid % 100000
	if appID >= 20000 && appID <= 29999 {
		appID -= 10000
	}
	if appID >= 10000 && appID <= 19999 {
		return pkgMap[appID]
	}
	return ""
}

func (a *SelfAttribAggregator) sampleOnce() error {
	// 死定律四: getPkgCache() 可能在 packages.list 不可读时回退执行 pm 子进程,
	// 严格置于 sampleMu 与 a.mu 锁外执行。
	pkgMap := a.getPkgCache()

	a.sampleMu.Lock()
	defer a.sampleMu.Unlock()

	now := time.Now()

	var rows []SelfAttribConnRow
	seen := make(map[string]bool)
	newRemoteToUID := make(map[string]int, 128)
	newRemoteIPToUID := make(map[string]int, 128)
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
			if pkg := resolvePkgInMap(pkgMap, e.UID); pkg != "" {
				e.Pkg = pkg
			} else if e.UID > 0 {
				unknownConns++
			}
			// v5.36.0: FIN_WAIT1/2, CLOSE, CLOSING 常在内核释放孤儿 socket 后变为 uid=0;
			// 绝不允许 uid=0 覆盖同一远端 IP:Port 上已有的真实应用 UID (>0)。
			if k := canonRemoteKey(e.Remote); k != "" {
				if prev, exists := newRemoteToUID[k]; !exists || e.UID > 0 || prev <= 0 {
					if e.UID > 0 || !exists {
						newRemoteToUID[k] = e.UID
					}
				}
				if e.UID >= 10000 {
					if host, _, err := net.SplitHostPort(e.Remote); err == nil {
						if ipk := canonIPOnly(host); ipk != "" {
							if prevU, has := newRemoteIPToUID[ipk]; !has {
								newRemoteIPToUID[ipk] = e.UID
							} else if prevU != e.UID {
								newRemoteIPToUID[ipk] = -1 // 多应用共享同一远端 IP 时禁用纯 IP 兜底, 绝不串应用
							}
						}
					}
				}
			}
			rows = append(rows, e)
		}
	}

	// Append to persistent data/self_studio/self_attrib.YYYYMMDD.jsonl with
	// ephemeral-port-insensitive signature dedupe and strict 4 MiB daily cap.
	sig := connsSignature(rows)
	if a.jsonlDir != "" && sig != a.lastJSONLSig {
		if err := os.MkdirAll(a.jsonlDir, 0o755); err == nil {
			dayPath := filepath.Join(a.jsonlDir,
				fmt.Sprintf("self_attrib.%s.jsonl", now.Format("20060102")))
			obs := SelfAttribObservation{T: now.Unix(), Conns: rows}
			if line, merr := json.Marshal(obs); merr == nil {
				line = append(line, '\n')
				var curSize int64
				if info, serr := os.Stat(dayPath); serr == nil {
					curSize = info.Size()
				}
				if curSize < SelfAttribMaxDailyBytes && curSize+int64(len(line)) <= SelfAttribMaxDailyBytes {
					if f, oerr := os.OpenFile(dayPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); oerr == nil {
						_, werr := f.Write(line)
						cerr := f.Close()
						if werr == nil && cerr == nil {
							a.lastJSONLSig = sig
						}
					}
				}
			}
		}
	}

	// Update aggregator
	a.mu.Lock()
	a.remoteToUID = newRemoteToUID
	a.remoteIPToUID = newRemoteIPToUID
	a.lastTick = now.Unix()
	a.unknownConns = unknownConns

	// Evict stale per-UID cached state if an uninstalled UID was reassigned to a different package.
	for uid, app := range a.appsByUID {
		if app == nil {
			continue
		}
		if pkg := resolvePkgInMap(pkgMap, uid); pkg != "" && app.Pkg != "" && app.Pkg != pkg {
			a.resetUIDStateLocked(uid)
		}
	}

	// Walk rows: bump active_conns + cumulative TotalConns counters per uid.
	activeByUID := make(map[int]int, 64)
	for _, r := range rows {
		activeByUID[r.UID]++
		if r.Pkg != "" {
			if existing := a.appsByUID[r.UID]; existing != nil && existing.Pkg != "" && existing.Pkg != r.Pkg {
				a.resetUIDStateLocked(r.UID)
			}
		}
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
				if pkg := resolvePkgInMap(pkgMap, uid); pkg != "" {
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

var packagesListPath = "/data/system/packages.list"

func (a *SelfAttribAggregator) getPkgCache() map[int]string {
	a.mu.Lock()
	if a.pkgCache != nil && !a.pkgCacheLoadedAt.IsZero() && time.Since(a.pkgCacheLoadedAt) < SelfPkgCacheTTL {
		out := a.pkgCache
		a.mu.Unlock()
		return out
	}
	a.mu.Unlock()

	// Serialize slow refresh outside a.mu so concurrent callers never spawn duplicate pm subprocesses.
	a.pkgRefreshMu.Lock()
	defer a.pkgRefreshMu.Unlock()

	a.mu.Lock()
	if a.pkgCache != nil && !a.pkgCacheLoadedAt.IsZero() && time.Since(a.pkgCacheLoadedAt) < SelfPkgCacheTTL {
		out := a.pkgCache
		a.mu.Unlock()
		return out
	}
	a.mu.Unlock()

	var (
		m       map[int]string
		sysPkgs map[string]struct{}
		err     error
		sysErr  error
		excl    map[string]struct{}
	)
	// Primary: single pure-Go pass over /data/system/packages.list extracts both
	// uid->pkg and systemPkgs without forking app_process (`pm`).
	if lm, lsys, lerr := loadPackagesList(packagesListPath); lerr == nil && len(lm) > 0 {
		m, sysPkgs = lm, lsys
		excl = loadFlywheelExcludePkgs()
	} else {
		m, err = loadPkgUIDsViaPM()
		if err == nil {
			sysPkgs, sysErr = loadSystemPkgsViaPM()
			excl = loadFlywheelExcludePkgs()
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.pkgCacheErr = err.Error()
		if a.pkgCache == nil {
			a.pkgCache = make(map[int]string)
		}
		return a.pkgCache
	}
	for uid, app := range a.appsByUID {
		if app == nil {
			continue
		}
		if newPkg := resolvePkgInMap(m, uid); newPkg != "" && app.Pkg != "" && app.Pkg != newPkg {
			a.resetUIDStateLocked(uid)
		}
	}
	a.pkgCache = m
	a.pkgCacheLoadedAt = time.Now()
	a.pkgCacheErr = ""
	if sysErr == nil {
		a.systemPkgs = sysPkgs
	}
	a.flywheelExcludePkgs = excl
	return m
}

// pmTimeout v5.12: pm 调用上限。pm 走 binder 找 system_server, 开机早期或
// system_server 卡顿时可能长时间不返回; 加独立进程组 Setpgid + -pgid SIGKILL +
// WaitDelay 防止 pm/app_process 子孙进程持管道挂死采样 goroutine。
const pmTimeout = 20 * time.Second

func pmCommand(args ...string) (*exec.Cmd, context.CancelFunc) {
	return pmCommandWithTimeout(pmTimeout, "pm", args...)
}

func pmCommandWithTimeout(timeout time.Duration, bin string, args ...string) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err == nil {
				return nil
			}
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
	return cmd, cancel
}

// loadSystemPkgs prefers extracting system packages directly from
// /data/system/packages.list, and falls back to `pm list packages -s` only when
// packages.list is unreadable or empty.
func loadSystemPkgs() (map[string]struct{}, error) {
	if m, sys, err := loadPackagesList(packagesListPath); err == nil && len(m) > 0 {
		return sys, nil
	}
	return loadSystemPkgsViaPM()
}

func loadSystemPkgsViaPM() (map[string]struct{}, error) {
	// v5.12: 加超时与进程组强杀(见 pmCommand)。
	cmd, cancel := pmCommand("list", "packages", "-s")
	defer cancel()
	// rc39 (P2-23): nohup-launched dpid may inherit an incomplete Env; without
	// LD_LIBRARY_PATH the `pm` app_process wrapper can hit a linker error and
	// return nothing → system-app filtering breaks. Pin the standard lib paths.
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH=/system/lib64:/system/lib")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, 256)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "package:") {
			continue
		}
		pkg := strings.TrimSpace(strings.TrimPrefix(line, "package:"))
		if pkg != "" {
			set[pkg] = struct{}{}
		}
	}
	return set, nil
}

// IsSystemUID reports whether the package owning uid is a system package.
// Unknown uid / not-yet-loaded set → false (don't filter until we know).
func (a *SelfAttribAggregator) IsSystemUID(uid int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	pkg := a.resolvePkgByUIDLocked(uid)
	if pkg == "" || a.systemPkgs == nil {
		return false
	}
	_, ok := a.systemPkgs[pkg]
	return ok
}

// IsFlywheelExcludedUID reports whether uid resolves to a VPN/proxy package
// excluded from the flywheel. Unknown uid → false (we can't decide until pm
// resolves it; the stored-UIDPkg path in candidate.go covers demotion of
// already-promoted rules even before pkg resolution). v5.7.0-rc33.
func (a *SelfAttribAggregator) IsFlywheelExcludedUID(uid int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	pkg := a.resolvePkgByUIDLocked(uid)
	if pkg == "" || a.flywheelExcludePkgs == nil {
		return false
	}
	_, ok := a.flywheelExcludePkgs[pkg]
	return ok
}

// IsFlywheelExcludedPkg reports whether a package name is on the flywheel
// exclusion list. Used to demote already-promoted rules by their stored
// Evidence.UIDPkg (robust even if the uid was recycled). v5.7.0-rc33.
func (a *SelfAttribAggregator) IsFlywheelExcludedPkg(pkg string) bool {
	if pkg == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.flywheelExcludePkgs == nil {
		return false
	}
	_, ok := a.flywheelExcludePkgs[pkg]
	return ok
}

// parsePackagesListBytes parses /data/system/packages.list rows:
//
//	com.tencent.mm 10123 0 /data/user/0/com.tencent.mm default:targetSdkVersion=33 3003,9997
//
// Extracts both uid→pkg and systemPkgs (identified by uid < 10000, seinfo
// containing "platform"/"privapp", or non-/data/app system paths).
func parsePackagesListBytes(data []byte) (map[int]string, map[string]struct{}) {
	m := make(map[int]string, 512)
	sys := make(map[string]struct{}, 256)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		uid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		pkg := fields[0]
		if pkg == "" {
			continue
		}
		// First wins (shared uids); matches loadPkgUIDs behaviour.
		if _, ok := m[uid]; !ok {
			m[uid] = pkg
		}
		if isSystemPkgListRow(uid, fields) {
			sys[pkg] = struct{}{}
		}
	}
	return m, sys
}

func isSystemPkgListRow(uid int, fields []string) bool {
	if uid >= 0 && (uid < 10000 || uid%100000 < 10000) {
		return true
	}
	if len(fields) >= 5 {
		seinfo := strings.ToLower(fields[4])
		if strings.Contains(seinfo, "platform") || strings.Contains(seinfo, "privapp") {
			return true
		}
	}
	if len(fields) >= 4 && isSystemPkgPath(fields[3]) {
		return true
	}
	return false
}

func isSystemPkgPath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	if strings.HasPrefix(p, "/data/app") ||
		strings.HasPrefix(p, "/data/user/") ||
		strings.HasPrefix(p, "/data/data/") ||
		strings.HasPrefix(p, "/mnt/") ||
		strings.HasPrefix(p, "/sdcard/") ||
		strings.HasPrefix(p, "/storage/") {
		return false
	}
	for _, sysPrefix := range []string{
		"/system/",
		"/system_ext/",
		"/product/",
		"/vendor/",
		"/odm/",
		"/oem/",
		"/apex/",
		"/data/user_de/",
	} {
		if strings.HasPrefix(p, sysPrefix) {
			return true
		}
	}
	return false
}

func loadPackagesList(path string) (map[int]string, map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	m, sys := parsePackagesListBytes(data)
	return m, sys, nil
}

// loadPkgUIDsFromList parses /data/system/packages.list, the authoritative
// root-readable package↔uid table.
func loadPkgUIDsFromList() (map[int]string, error) {
	m, _, err := loadPackagesList(packagesListPath)
	return m, err
}

// loadPkgUIDs prefers /data/system/packages.list and falls back to
// `pm list packages -U` only when packages.list is unreadable or empty.
func loadPkgUIDs() (map[int]string, error) {
	if m, lerr := loadPkgUIDsFromList(); lerr == nil && len(m) > 0 {
		return m, nil
	}
	return loadPkgUIDsViaPM()
}

func loadPkgUIDsViaPM() (map[int]string, error) {
	cmd, cancel := pmCommand("list", "packages", "-U")
	defer cancel()
	// rc39 (P2-23): pin LD_LIBRARY_PATH so the pm fallback works under an
	// incomplete (nohup) Env.
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH=/system/lib64:/system/lib")
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

		// v5.35.0: Skip TCP LISTEN (0A) and TIME_WAIT (06, kernel emits uid=0 after sock release,
		// which otherwise overwrites active ESTABLISHED app UIDs on the same CDN IP:443).
		if proto == "tcp" && (stateHex == "0A" || stateHex == "06") {
			continue
		}
		// Skip all-zero remote (UDP server sockets bound to 0.0.0.0:port,
		// etc.) — they have no remote peer.
		// v5.12: parseHexAddr 的 IPv6 输出不做 :: 压缩, 全零地址是
		// "[0:0:0:0:0:0:0:0]:port", 旧的 "[::]:" 前缀永不匹配 → udp6/tcp6
		// 未连接 socket 全被当成连接写进 JSONL 并计入 TotalConns。
		if strings.HasPrefix(remote, "0.0.0.0:") || strings.HasPrefix(remote, "[::]:") ||
			strings.HasPrefix(remote, "[0:0:0:0:0:0:0:0]:") {
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

// canonRemoteKey v5.12: 把 parseHexAddr 产出的 "a.b.c.d:port" /
// "[v6]:port" 规范为 canonIPPort 形式; 解析失败返回 ""。
func canonRemoteKey(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return ""
	}
	return canonIPPort(host, port)
}

// canonIPPort v5.12: IPv4-mapped IPv6(::ffff:a.b.c.d)折叠成 IPv4, 其余 IPv6
// 用 net.IP.String() 的规范写法; 结果形如 "1.2.3.4:443" / "2409:8963::1:443"
// (键只用于 map 查找, 不需要可逆)。无法解析的 IP 原样保留。
func canonIPOnly(ip string) string {
	ip = strings.Trim(ip, "[]")
	if p := net.ParseIP(ip); p != nil {
		if v4 := p.To4(); v4 != nil {
			return v4.String()
		}
		p16 := p.To16()
		if len(p16) == 16 && p16[0] == 0x00 && p16[1] == 0x64 && p16[2] == 0xff && p16[3] == 0x9b {
			// RFC 6052 Well-Known Prefix 64:ff9b::/96 (bytes 4..11 == 0) AND
			// RFC 8215 Local-Use Translation Prefix 64:ff9b:1::/48 (bytes 4..5 == 0x0001, any subnet in 6..11)
			wellKnown := p16[4] == 0 && p16[5] == 0 && p16[6] == 0 && p16[7] == 0 && p16[8] == 0 && p16[9] == 0 && p16[10] == 0 && p16[11] == 0
			localUse := p16[4] == 0 && p16[5] == 1
			if wellKnown || localUse {
				return net.IPv4(p16[12], p16[13], p16[14], p16[15]).String()
			}
		}
		return p.String()
	}
	return ip
}

func canonIPPort(ip, port string) string {
	return canonIPOnly(ip) + ":" + port
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

// resolvePkgByUIDLocked v5.35.0: Supports Android multi-user / dual-app clone (user 999)
// and Android 13+ SDK Sandbox (20000..29999 -> appId - 10000) via UserHandle.PER_USER_RANGE = 100000.
func (a *SelfAttribAggregator) resolvePkgByUIDLocked(uid int) string {
	if uid <= 0 {
		return ""
	}
	if p := a.pkgCache[uid]; p != "" {
		return p
	}
	appID := uid % 100000
	if appID >= 20000 && appID <= 29999 {
		appID -= 10000
	}
	if appID >= 10000 && appID <= 19999 {
		return a.pkgCache[appID]
	}
	return ""
}
