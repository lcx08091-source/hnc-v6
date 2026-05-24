// Package output - candidate.go (v5.7)
//
// "走法 2" — brand-new-apex auto-promotion + shadow candidate accumulator.
//
// auto_expand.go ("走法 1") only expands subdomains of apexes that ALREADY
// match a known rule (same eTLD+1). This file handles the other case: a
// brand-new apex that matches NO rule, attributed to an app via the kernel
// uid ground truth.
//
// ── Why this can be safe + automatic ──────────────────────────────────
// The kernel tells us which uid (= which app) owns each socket — that's
// ground truth, not a guess. So the only hard question is "is this apex
// app-specific or shared infrastructure (CDN/analytics)?". The strongest
// signal for that is uid-cardinality: an apex seen under exactly ONE uid
// over a sustained window is app-specific; seen under many uids = shared.
//
// ── Tiers ─────────────────────────────────────────────────────────────
//   HIGH  : single uid + persistent (>=N windows, >=M hits) + not shared
//           → eligible for auto-promotion (attributed to that uid's app).
//   MED   : single uid but not yet persistent → wait for more evidence.
//   LOW   : 2 uids (ambiguous) → don't auto-attribute.
//   SHARED: in static blocklist, or >=K distinct uids, or learned-shared
//           → never attribute to a single app.
//
// ── Safety model ──────────────────────────────────────────────────────
//   - SHADOW by default. The accumulator + tiering always run (so the
//     summary in dpi_state can be used to calibrate thresholds in-vivo),
//     but rules are ONLY written when /data/local/hnc/run/auto_promote.enabled
//     exists. Default off.
//   - SELF-CORRECTING. If an already-promoted apex later shows up under a
//     2nd uid (contradiction → it was actually shared), it is auto-demoted:
//     the rule is removed and the apex is marked learned-shared so it won't
//     be re-promoted.
//   - LABEL-ONLY. Promoted rules only LABEL traffic; they never drive
//     blocklist/limiting. Promoted rules carry full provenance and live in
//     ONE file (_auto_promoted.json) so disabling = delete file + restart.
//   - BOUNDED. Per-day-ish caps on accumulator size and promoted-rule count;
//     stale candidates age out.

package output

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// autoPromoteFlagFile gates rule WRITING (separate from auto_expand.enabled).
	// Absent (default) = shadow only: accumulate + tier + publish summary, no writes.
	autoPromoteFlagFile = "auto_promote.enabled"

	// autoPromotedOutFile is the rule file brand-new-apex promotions go into.
	autoPromotedOutFile = "_auto_promoted.json"

	// candidateDecisionsFile holds user-approved apexes (manual "一键 promote"
	// from the WebUI). dpid force-promotes these even in shadow mode. Re-read
	// each tick (like the blocklist) so clicks take effect within 60s.
	candidateDecisionsFile = "/data/local/hnc/etc/candidate_decisions.json"

	// candidateAccumFile persists the accumulator across dpid restarts. dpid is
	// restarted on every hotspot-iface change (2-3x per toggle), which would
	// otherwise reset the per-apex window/uid progress so the flywheel could
	// never reach the promotion window threshold on hotspot-toggling devices.
	candidateAccumFile = "/data/local/hnc/run/candidate_accum.json"

	// candSharedUIDThreshold: an apex contacted by >= this many distinct uids
	// is treated as shared infrastructure (never attributed to one app).
	candSharedUIDThreshold = 3

	// candPromoteMinWindows / candPromoteMinHits: persistence floor for HIGH.
	candPromoteMinWindows = 3
	candPromoteMinHits    = 6

	candMaxApex     = 4096         // accumulator hard cap
	candMaxPromoted = 500          // promoted-rule hard cap
	candMaxSamples  = 40           // candidate samples surfaced in dpi_state (review queue)
	candMaxAgeSec   = 24 * 60 * 60 // drop candidates unseen for 24h
)

// apexCandidate accumulates evidence for one brand-new apex across ticks.
type apexCandidate struct {
	Apex          string
	UIDs          map[int]int // uid -> cumulative observation count
	FirstSeen     int64
	LastSeen      int64
	Windows       int    // distinct ticks this apex appeared in (persistence)
	TotalHits     int    // total observations across all uids
	SampleSNI     string // an example full SNI under this apex
	SharedLearned bool   // demoted once (multi-uid) → never re-promote
}

// candidateAccumulator is owned by the single expander goroutine (no locks).
type candidateAccumulator struct {
	byApex map[string]*apexCandidate
}

func newCandidateAccumulator() *candidateAccumulator {
	return &candidateAccumulator{byApex: map[string]*apexCandidate{}}
}

func (acc *candidateAccumulator) observe(apex, sni string, uid int, now int64) {
	c := acc.byApex[apex]
	if c == nil {
		if len(acc.byApex) >= candMaxApex {
			return
		}
		c = &apexCandidate{Apex: apex, UIDs: map[int]int{}, FirstSeen: now, SampleSNI: sni}
		acc.byApex[apex] = c
	}
	c.UIDs[uid]++
	c.TotalHits++
	c.LastSeen = now
}

func (acc *candidateAccumulator) age(now int64) {
	for apex, c := range acc.byApex {
		if now-c.LastSeen > candMaxAgeSec {
			delete(acc.byApex, apex)
		}
	}
}

// topUID returns the single uid (or the most-observed uid if >1).
func (c *apexCandidate) topUID() int {
	bestUID, best := 0, -1
	for uid, n := range c.UIDs {
		if n > best || (n == best && uid < bestUID) {
			best = n
			bestUID = uid
		}
	}
	return bestUID
}

// classifyTier decides an apex's tier + the uid it would be attributed to.
func classifyTier(c *apexCandidate, blocklist map[string]struct{}, entityDB map[string]entityRec) (tier string, uid int) {
	if c.SharedLearned {
		return "shared", 0
	}
	if _, blocked := blocklist[c.Apex]; blocked {
		return "shared", 0
	}
	// curated entity library: CDN / cloud / analytics / ads / push SDK apexes
	// are shared infrastructure from the first sighting (cold-start prior).
	if entityIsShared(c.Apex, entityDB) {
		return "shared", 0
	}
	if len(c.UIDs) >= candSharedUIDThreshold {
		return "shared", 0
	}
	if len(c.UIDs) == 1 {
		uid = c.topUID()
		if c.Windows >= candPromoteMinWindows && c.TotalHits >= candPromoteMinHits {
			return "high", uid
		}
		return "med", uid
	}
	// exactly 2 uids: ambiguous — wait, don't auto-attribute.
	return "low", c.topUID()
}

// apexHasRule reports whether any existing rule already owns this apex
// (those go through auto_expand's same-apex path, not brand-new promotion).
func apexHasRule(apex string, rules []l3Rule) bool {
	for _, r := range rules {
		for _, suf := range r.Suffixes {
			if eTLDPlus1(strings.ToLower(strings.TrimSpace(suf))) == apex {
				return true
			}
		}
	}
	return false
}

// candidateSummary is the compact view published into dpi_state (diagnostics).
type candidateSummary struct {
	pending       int
	high          int
	shared        int
	promoted      int
	entityDBSize  int
	autoPromoteOn bool
	samples       []CandidateSample
}

// processCandidates runs once per expander tick. It folds this tick's
// unmatched SNIs into the per-apex accumulator, computes tiers, publishes a
// shadow summary, and — only when auto_promote.enabled — writes HIGH-tier
// brand-new apexes as rules and auto-demotes contradicted ones.
func (a *SelfAttribAggregator) processCandidates(pending map[string]map[int]struct{}, acc *candidateAccumulator, promoted map[string]autoExpandedRule, runDir string, now int64) {
	rules := loadL3Rules().rules
	blocklist, _ := loadBlocklist()
	entityDB := loadEntityDB()

	touched := map[string]struct{}{}
	for sni, uidSet := range pending {
		apex := eTLDPlus1(sni)
		if apex == "" {
			continue
		}
		// same-apex (known app subdomain) is auto_expand's job; here we only
		// accumulate brand-new apexes that match no existing rule.
		if apexHasRule(apex, rules) {
			continue
		}
		for uid := range uidSet {
			if uid == 0 {
				continue
			}
			// v5.7.0-rc9: keep system apps out of the flywheel. Their domains
			// are OEM telemetry/services — useless as shareable app rules and
			// they clutter the candidate queue. An apex used only by system
			// uids never accumulates; if a real app also uses it, it still
			// accumulates under that (non-system) uid.
			if a.IsSystemUID(uid) {
				continue
			}
			// v5.7.0-rc33: keep VPN/proxy apps out of the flywheel. When a VPN is
			// active it re-originates other apps' traffic, so the socket uid is the
			// VPN's — accumulating here would mis-learn e.g. "capcom.co.jp -> FlClash".
			if a.IsFlywheelExcludedUID(uid) {
				continue
			}
			acc.observe(apex, sni, uid, now)
			touched[apex] = struct{}{}
		}
	}
	// one window-tick per apex that appeared this round (persistence signal).
	for apex := range touched {
		if c := acc.byApex[apex]; c != nil {
			c.Windows++
		}
	}
	acc.age(now)

	autoPromoteOn := false
	if _, err := os.Stat(filepath.Join(runDir, autoPromoteFlagFile)); err == nil {
		autoPromoteOn = true
	}

	// User-approved apexes (manual "一键 promote" from the WebUI). Re-read each
	// tick; force-promotion below works regardless of the auto_promote flag.
	decisions := loadCandidateDecisions()

	// v5.7.0-rc33: conduit auto-detection. A uid associated with many distinct
	// brand-new apexes is a generic conduit (VPN/proxy/browser) even if it's not
	// on the explicit exclude list — block it from AUTO-promotion. Computed from
	// the current accumulator (listed VPNs were already skipped at observe-time,
	// so this only catches the unlisted long tail).
	apexCountByUID := map[int]int{}
	for _, c := range acc.byApex {
		for uid := range c.UIDs {
			apexCountByUID[uid]++
		}
	}
	isConduitUID := func(uid int) bool { return apexCountByUID[uid] >= conduitApexThreshold }

	changed := false
	// v5.7.0-rc33: demote already-promoted rules whose attributed app is now a
	// VPN/proxy (explicit list) or a detected conduit. Cleans up bad rules like
	// "capcom.co.jp -> FlClash" that were minted before the exclusion existed.
	// Manual promotions (user clicked) are NEVER auto-demoted by the conduit
	// heuristic — only by the explicit list, since the user may knowingly want it.
	for apex, r := range promoted {
		excludedByList := a.IsFlywheelExcludedPkg(r.Evidence.UIDPkg) || a.IsFlywheelExcludedUID(r.Evidence.UID)
		conduit := r.Source == "auto_promoted" && isConduitUID(r.Evidence.UID)
		if excludedByList || conduit {
			delete(promoted, apex)
			if c := acc.byApex[apex]; c != nil {
				c.SharedLearned = true
			}
			changed = true
			log.Printf("flywheel-exclude: demoted %s -> %q (uid=%d pkg=%q reason=%s)",
				apex, r.App, r.Evidence.UID, r.Evidence.UIDPkg,
				map[bool]string{true: "vpn/proxy", false: "conduit"}[excludedByList])
		}
	}

	sum := candidateSummary{autoPromoteOn: autoPromoteOn, entityDBSize: len(entityDB)}
	for apex, c := range acc.byApex {
		tier, uid := classifyTier(c, blocklist, entityDB)
		sum.pending++
		switch tier {
		case "high":
			sum.high++
		case "shared":
			sum.shared++
		}

		if _, isProm := promoted[apex]; isProm {
			// self-correct: a promoted apex that became multi-uid / shared
			// was a mistake — remove the rule and never re-promote it. This
			// also fires when the user rejected it (→ blocklist → tier shared).
			if tier == "shared" || len(c.UIDs) > 1 {
				delete(promoted, apex)
				c.SharedLearned = true
				changed = true
				log.Printf("auto-promote: demoted %s (now multi-uid/shared, uids=%d)", apex, len(c.UIDs))
			}
		} else if (tier == "high" || tier == "med") && len(promoted) < candMaxPromoted {
			// HIGH auto-promotes when the flag is on; HIGH or MED can be
			// promoted manually (decisions file), which works even in shadow
			// mode. Both are single-uid, preserving the self-correct invariant.
			_, manual := decisions[apex]
			// v5.7.0-rc33: never AUTO-promote to a detected conduit uid
			// (VPN/proxy/browser). Manual promote still wins (user override).
			if !manual && isConduitUID(uid) {
				// conduit uid: suppress auto-promotion (no rule minted)
			} else if manual || (tier == "high" && autoPromoteOn) {
				pkg, label := a.DisplayForUID(uid)
				src := "auto_promoted"
				if manual {
					src = "manual_promoted"
				}
				promoted[apex] = buildPromotedRule(apex, uid, pkg, label, c, now, src)
				changed = true
				log.Printf("%s: promoted %s -> %q (uid=%d hits=%d windows=%d)", src, apex, label, uid, c.TotalHits, c.Windows)
			}
		}

		// surface only actionable candidates (high/med) in the review queue;
		// shared total is reported via sum.shared, low is too ambiguous.
		if len(sum.samples) < candMaxSamples && (tier == "high" || tier == "med") {
			_, label := a.DisplayForUID(uid)
			_, isProm := promoted[apex]
			sum.samples = append(sum.samples, CandidateSample{
				Apex: apex, Tier: tier, UID: uid, App: label,
				Hits: c.TotalHits, Windows: c.Windows, Promoted: isProm,
			})
		}
	}
	sort.Slice(sum.samples, func(i, j int) bool { return sum.samples[i].Apex < sum.samples[j].Apex })
	sum.promoted = len(promoted)
	a.SetCandidateSummary(sum)

	if changed {
		if err := writePromotedRules(promoted); err != nil {
			log.Printf("auto-promote: write %s failed: %v", autoPromotedOutFile, err)
		} else {
			invalidateRuleCache()
		}
	}

	// Persist the accumulator so window/uid progress survives dpid restarts
	// (hotspot toggles restart dpid 2-3x; without this the flywheel never
	// reaches the promotion window threshold on such devices).
	saveCandidateAccum(acc)
}

// buildPromotedRule materializes a brand-new-apex rule attributed to the
// uid's app (label from the live PackageManager resolver / curated map).
// source is "auto_promoted" (uid-cardinality heuristic) or "manual_promoted"
// (user clicked 一键 promote in the WebUI).
func buildPromotedRule(apex string, uid int, pkg, label string, c *apexCandidate, now int64, source string) autoExpandedRule {
	if strings.TrimSpace(label) == "" {
		label = pkg
	}
	if strings.TrimSpace(label) == "" {
		label = apex
	}
	idSuffix := strings.NewReplacer(".", "_", "-", "_").Replace(apex)
	if len(idSuffix) > 48 {
		idSuffix = idSuffix[:48]
	}
	tag, conf := "自动识别", "low"
	if source == "manual_promoted" {
		tag, conf = "已确认", "medium" // user-confirmed → higher confidence
	}
	return autoExpandedRule{
		ID:         "autopromo_" + idSuffix,
		Name:       label + " (" + tag + ")",
		App:        label,
		Category:   "auto_identified",
		Confidence: conf,
		Suffixes:   []string{apex},

		Source:       source,
		Apex:         apex,
		ParentRuleID: "",
		AddedAt:      now,
		Evidence: autoExpandedEvidence{
			UID:                      uid,
			UIDPkg:                   pkg,
			ParentHitsAtTimeOfExpand: c.TotalHits,
			ObservedHostname:         c.SampleSNI,
		},
	}
}

// writePromotedRules atomically rewrites _auto_promoted.json.
func writePromotedRules(promoted map[string]autoExpandedRule) error {
	rules := make([]autoExpandedRule, 0, len(promoted))
	for _, r := range promoted {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	file := autoExpandedFile{
		SchemaVersion: "2.0",
		Subset:        "_auto_promoted",
		RulesVersion:  fmt.Sprintf("auto-promoted-v5.7-%d", time.Now().Unix()),
		Rules:         rules,
	}
	body, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	dst := filepath.Join(externalRulesDir, autoPromotedOutFile)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, dst, err)
	}
	return nil
}

// candidateDecisionsData is the on-disk shape of candidate_decisions.json,
// written by the WebUI action candidate_promote.
type candidateDecisionsData struct {
	Promote []string `json:"promote"`
	Comment string   `json:"_comment,omitempty"`
}

// candidateAccumData is the on-disk shape of candidate_accum.json.
type candidateAccumData struct {
	SavedAt int64                     `json:"saved_at"`
	ByApex  map[string]*apexCandidate `json:"by_apex"`
}

// saveCandidateAccum atomically persists the accumulator so it survives dpid
// restarts. Best-effort: any error is silently ignored (we just lose this
// snapshot, next tick retries).
func saveCandidateAccum(acc *candidateAccumulator) {
	data := candidateAccumData{SavedAt: time.Now().Unix(), ByApex: acc.byApex}
	body, err := json.Marshal(&data)
	if err != nil {
		return
	}
	tmp := candidateAccumFile + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, candidateAccumFile)
}

// loadCandidateAccum repopulates acc.byApex from the on-disk snapshot at
// startup. Missing/malformed = empty (best-effort). Stale entries (older than
// candMaxAgeSec) are dropped so a long downtime doesn't resurrect dead apexes.
func loadCandidateAccum(acc *candidateAccumulator) int {
	body, err := os.ReadFile(candidateAccumFile)
	if err != nil {
		return 0
	}
	var data candidateAccumData
	if err := json.Unmarshal(body, &data); err != nil {
		return 0
	}
	now := time.Now().Unix()
	n := 0
	for apex, c := range data.ByApex {
		if c == nil || apex == "" {
			continue
		}
		if c.UIDs == nil {
			c.UIDs = map[int]int{}
		}
		if now-c.LastSeen > candMaxAgeSec {
			continue
		}
		if len(acc.byApex) >= candMaxApex {
			break
		}
		acc.byApex[apex] = c
		n++
	}
	return n
}

// loadCandidateDecisions reads the user-approved apex list. Missing or
// malformed file = empty set (best-effort, never an error to the caller).
func loadCandidateDecisions() map[string]struct{} {
	out := map[string]struct{}{}
	data, err := os.ReadFile(candidateDecisionsFile)
	if err != nil {
		return out
	}
	var d candidateDecisionsData
	if err := json.Unmarshal(data, &d); err != nil {
		return out
	}
	for _, a := range d.Promote {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" {
			out[a] = struct{}{}
		}
	}
	return out
}

// loadExistingPromoted reloads the previous run's promoted rules (keyed by apex).
func loadExistingPromoted() (map[string]autoExpandedRule, error) {
	dst := filepath.Join(externalRulesDir, autoPromotedOutFile)
	data, err := os.ReadFile(dst)
	if err != nil {
		return nil, err
	}
	var file autoExpandedFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	out := map[string]autoExpandedRule{}
	for _, r := range file.Rules {
		key := r.Apex
		if key == "" && len(r.Suffixes) > 0 {
			key = r.Suffixes[0]
		}
		if key != "" {
			out[key] = r
		}
	}
	return out, nil
}
