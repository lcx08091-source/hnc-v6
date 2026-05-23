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

	// candSharedUIDThreshold: an apex contacted by >= this many distinct uids
	// is treated as shared infrastructure (never attributed to one app).
	candSharedUIDThreshold = 3

	// candPromoteMinWindows / candPromoteMinHits: persistence floor for HIGH.
	candPromoteMinWindows = 3
	candPromoteMinHits    = 6

	candMaxApex     = 4096         // accumulator hard cap
	candMaxPromoted = 500          // promoted-rule hard cap
	candMaxSamples  = 12           // candidate samples surfaced in dpi_state
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
func classifyTier(c *apexCandidate, blocklist map[string]struct{}) (tier string, uid int) {
	if c.SharedLearned {
		return "shared", 0
	}
	if _, blocked := blocklist[c.Apex]; blocked {
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

	sum := candidateSummary{autoPromoteOn: autoPromoteOn}
	changed := false
	for apex, c := range acc.byApex {
		tier, uid := classifyTier(c, blocklist)
		sum.pending++
		switch tier {
		case "high":
			sum.high++
		case "shared":
			sum.shared++
		}

		if _, isProm := promoted[apex]; isProm {
			// self-correct: a promoted apex that became multi-uid / shared
			// was a mistake — remove the rule and never re-promote it.
			if tier == "shared" || len(c.UIDs) > 1 {
				delete(promoted, apex)
				c.SharedLearned = true
				changed = true
				log.Printf("auto-promote: demoted %s (now multi-uid/shared, uids=%d)", apex, len(c.UIDs))
			}
		} else if tier == "high" && autoPromoteOn && len(promoted) < candMaxPromoted {
			pkg, label := a.DisplayForUID(uid)
			promoted[apex] = buildPromotedRule(apex, uid, pkg, label, c, now)
			changed = true
			log.Printf("auto-promote: promoted %s -> %q (uid=%d hits=%d windows=%d)", apex, label, uid, c.TotalHits, c.Windows)
		}

		if len(sum.samples) < candMaxSamples && (tier == "high" || tier == "shared") {
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
}

// buildPromotedRule materializes a brand-new-apex rule attributed to the
// uid's app (label from the live PackageManager resolver / curated map).
func buildPromotedRule(apex string, uid int, pkg, label string, c *apexCandidate, now int64) autoExpandedRule {
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
	return autoExpandedRule{
		ID:         "autopromo_" + idSuffix,
		Name:       label + " (自动识别)",
		App:        label,
		Category:   "auto_identified",
		Confidence: "low", // auto-identified, not human-verified
		Suffixes:   []string{apex},

		Source:       "auto_promoted",
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
