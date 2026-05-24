// Package output - auto_expand.go (v5.6.0-rc2)
//
// "走法 1" subdomain auto-expansion. Watches SNIs that didn't match
// any existing rule, decides via three independent evidence requirements
// whether each one belongs to a known app, and writes confirmed expansions
// to /data/local/hnc/etc/dpi_rules.d/_auto_expanded.json so the next dpid
// rule reload picks them up.
//
// ── The three evidence requirements (must all hold) ───────────────────
//
//   1. APEX MATCH. The candidate SNI shares effective TLD+1 (eTLD+1)
//      with at least one suffix in some existing rule R. Example: a new
//      SNI `voice.weixin.qq.com` shares eTLD+1 `qq.com` with rule
//      `tencent_wechat`'s `weixin.qq.com`.
//
//      Implementation note: we use a hardcoded compound-TLD list rather
//      than golang.org/x/net/publicsuffix (no external deps in this
//      module). The list covers the high-frequency compound TLDs we see
//      in practice (co.uk, com.cn, com.au, etc); pure 2-label fallback
//      is correct for >95% of real-world cases.
//
//   2. UID EVIDENCE. The uid that observed the candidate SNI has hit
//      rule R at least autoExpandMinHits times (default 10). This is
//      what makes the inference safe: it's not just "some app uses qq.com",
//      it's "this specific uid is established as a heavy user of rule R".
//
//   3. APEX NOT BLOCKLISTED. The candidate's eTLD+1 is not in the
//      auto_expand_blocklist.json file (CDN, shared API gateways, SDK
//      providers — domains where multiple unrelated companies share infra,
//      so eTLD+1 isn't a reliable identity signal).
//
// ── Output format ─────────────────────────────────────────────────────
// One JSON file at $externalRulesDir/_auto_expanded.json, schema matches
// the regular dpi_rules.d/*.json format so the existing rule loader picks
// it up without changes. Underscore prefix sorts last alphabetically
// (assuming glob sort), so other rules load first.
//
// Each entry carries _source/_apex/_parent_rule_id/_added_at/_evidence
// fields for human inspection. These extra fields aren't in externalRule's
// JSON tags so the rule loader silently ignores them — exactly what we
// want (loader gets a clean rule, humans get full provenance).
//
// ── Failure / safety model ────────────────────────────────────────────
// - File is rewritten atomically (write to tmp, rename). Partial writes
//   never appear to readers.
// - If anything goes wrong (rule load fail, blocklist parse fail, file
//   write fail), log and continue. Worst case: expansions are delayed
//   one tick.
// - Gated by /data/local/hnc/run/auto_expand.enabled (SEPARATE flag from
//   self_capture.enabled, because this one writes rules and self_capture
//   is read-only — different risk profiles).
// - All expansions go into ONE file, so disabling = delete file + restart.
//   Human-written rules in other files are never touched.

package output

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// autoExpandMinHits is the floor for evidence #2 ("uid has hit
	// rule R at least N times before we trust the inference").
	autoExpandMinHits = 10

	// autoExpandTick is how often we drain unmatched SNIs and consider
	// expansion. 60s = candidates accumulate naturally; no need to
	// expand faster than humans read the WebUI.
	autoExpandTick = 60 * time.Second

	// autoExpandFlagFile is the SEPARATE flag from self_capture.enabled.
	// Path resolved relative to runDir at goroutine start.
	autoExpandFlagFile = "auto_expand.enabled"

	// autoExpandOutFile is the rule file we write. Underscore prefix
	// puts it last in alphabetical glob order so curated rules load first.
	autoExpandOutFile = "_auto_expanded.json"

	// blocklistFile is the human-maintained list of apex domains to
	// NOT auto-expand under. Looked up at $externalRulesDir/../auto_expand_blocklist.json
	// i.e. /data/local/hnc/etc/auto_expand_blocklist.json (one level up
	// from rules dir, so it doesn't accidentally get loaded as a rule).
	blocklistFile = "/data/local/hnc/etc/auto_expand_blocklist.json"
)

// compoundTLDs is a hardcoded list of two-label TLDs we know about.
// When a host's last 2 labels match one of these, we use the LAST 3
// labels as the eTLD+1 instead of the default 2. Order doesn't matter;
// this is checked via map lookup.
//
// To keep maintenance sane, this is intentionally a SHORT list covering
// only the high-frequency cases in our actual traffic. False negatives
// (treating co.foo as plain TLD+1) only matter if someone runs a popular
// app at example.co.foo where foo is some rare TLD — at which point we
// either add it here or swap in the proper publicsuffix lib.
var compoundTLDs = map[string]struct{}{
	// English-speaking
	"co.uk": {}, "co.nz": {}, "co.za": {}, "co.in": {}, "co.id": {},
	"co.kr": {}, "co.jp": {}, "co.th": {}, "co.il": {},
	"com.au": {}, "com.cn": {}, "com.hk": {}, "com.tw": {}, "com.sg": {},
	"com.br": {}, "com.mx": {}, "com.tr": {}, "com.ar": {}, "com.pe": {},
	"com.co": {}, "com.ph": {}, "com.my": {}, "com.vn": {},
	"org.uk": {}, "org.nz": {}, "org.cn": {}, "org.hk": {},
	"net.cn": {}, "net.au": {}, "net.nz": {}, "net.tw": {},
	"gov.cn": {}, "gov.uk": {}, "gov.au": {},
	"edu.cn": {}, "edu.au": {}, "edu.hk": {},
	"ac.uk": {}, "ac.jp": {}, "ac.kr": {}, "ac.cn": {},
	// Japan-specific (also reachable via ".jp" 2-label TLD)
	"ne.jp": {}, "or.jp": {}, "go.jp": {},
}

// eTLDPlus1 returns the "effective TLD plus one label" of a hostname.
// Examples:
//
//	voice.weixin.qq.com   → qq.com
//	api.example.co.uk     → example.co.uk
//	cdn.foo.com.cn        → foo.com.cn
//	bar.com               → bar.com
//	localhost             → localhost (no dot — pass through)
//	(empty)               → ""
func eTLDPlus1(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return ""
	}
	labels := strings.Split(host, ".")
	if len(labels) <= 1 {
		return host
	}
	// Check compound TLD: last 2 labels.
	if len(labels) >= 3 {
		lastTwo := labels[len(labels)-2] + "." + labels[len(labels)-1]
		if _, isCompound := compoundTLDs[lastTwo]; isCompound {
			return labels[len(labels)-3] + "." + lastTwo
		}
	}
	// Default: last 2 labels.
	return labels[len(labels)-2] + "." + labels[len(labels)-1]
}

// blocklistData is the on-disk JSON shape of auto_expand_blocklist.json.
type blocklistData struct {
	BlockedApex []string `json:"blocked_apex"`
	Comment     string   `json:"_comment,omitempty"`
}

// loadBlocklist reads + parses blocklistFile. Missing file is treated as
// empty (not an error) so deployment is just "drop in the file or don't".
// Lookups are case-insensitive.
func loadBlocklist() (map[string]struct{}, error) {
	out := map[string]struct{}{}
	data, err := os.ReadFile(blocklistFile)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	var bd blocklistData
	if err := json.Unmarshal(data, &bd); err != nil {
		return out, fmt.Errorf("parse %s: %w", blocklistFile, err)
	}
	for _, a := range bd.BlockedApex {
		out[strings.ToLower(strings.TrimSpace(a))] = struct{}{}
	}
	return out, nil
}

// autoExpandedRule is one entry in _auto_expanded.json. Embeds the same
// JSON shape as externalRule for fields the loader reads, plus extra
// underscore-prefixed fields for human/provenance use (silently ignored
// by the loader because they're not in externalRule's tag set).
type autoExpandedRule struct {
	ID           string               `json:"id"`
	Name         string               `json:"name,omitempty"`
	App          string               `json:"app,omitempty"`
	Category     string               `json:"category"`
	Confidence   string               `json:"confidence,omitempty"`
	Suffixes     []string             `json:"suffixes"`
	Source       string               `json:"_source"`
	Apex         string               `json:"_apex"`
	ParentRuleID string               `json:"_parent_rule_id"`
	AddedAt      int64                `json:"_added_at"`
	Evidence     autoExpandedEvidence `json:"_evidence"`
}

type autoExpandedEvidence struct {
	UID                      int    `json:"uid"`
	UIDPkg                   string `json:"uid_pkg,omitempty"`
	ParentHitsAtTimeOfExpand int    `json:"parent_hits_at_time_of_expand"`
	ObservedHostname         string `json:"observed_hostname"`
}

// autoExpandedFile is the top-level JSON shape, matching dpi_rules.d/*.json.
type autoExpandedFile struct {
	SchemaVersion string             `json:"schema_version"`
	Subset        string             `json:"subset"`
	RulesVersion  string             `json:"rules_version"`
	Rules         []autoExpandedRule `json:"rules"`
}

// autoExpandState is the persistent in-memory state of the expander goroutine.
// Not protected — only accessed from the single expander goroutine.
type autoExpandState struct {
	mu            sync.Mutex
	confirmed     map[string]autoExpandedRule // key: sni (acts as dedupe key + source of truth)
	lastWrittenAt int64
}

// RunAutoExpander is the auto-expansion goroutine. Started once from dpid
// main. Returns only when ctx is cancelled.
//
// Each tick:
//  1. Check flag file; if absent, drain queue + idle (no rule writes).
//  2. Drain unmatched SNI queue from selfAttrib.
//  3. For each candidate SNI: apex match → uid evidence → blocklist filter.
//  4. If all three pass: build autoExpandedRule, add to confirmed map.
//  5. If confirmed map grew: rewrite _auto_expanded.json atomically.
func (a *SelfAttribAggregator) RunAutoExpander(ctx context.Context, runDir string) {
	flagPath := filepath.Join(runDir, autoExpandFlagFile)
	st := &autoExpandState{confirmed: map[string]autoExpandedRule{}}

	// v5.6.0-rc3: unconditional startup log. Pre-rc3 we only logged when
	// existing _auto_expanded.json was loaded (or failed to load), so a
	// first-run install had zero indication the goroutine was alive at
	// all. This line makes "did the goroutine start?" trivial to check.
	log.Printf("auto-expand: goroutine started (tick=%v, flag=%s, out=%s/%s, min_hits=%d)",
		autoExpandTick, flagPath, externalRulesDir, autoExpandOutFile, autoExpandMinHits)

	// Load existing _auto_expanded.json on startup so we don't re-process
	// already-confirmed candidates after a dpid restart.
	if existing, err := loadExistingExpansions(); err == nil {
		st.confirmed = existing
		log.Printf("auto-expand: loaded %d existing expansions from %s", len(existing), autoExpandOutFile)
	} else if !os.IsNotExist(err) {
		log.Printf("auto-expand: failed to read existing %s: %v (starting fresh)", autoExpandOutFile, err)
	}

	// v5.7: brand-new-apex candidate accumulator ("走法 2", see candidate.go).
	// Runs every tick regardless of the auto_expand flag (shadow calibration);
	// only writes rules when auto_promote.enabled exists.
	acc := newCandidateAccumulator()
	if n := loadCandidateAccum(acc); n > 0 {
		log.Printf("auto-promote: restored %d candidate apexes from %s (survives hotspot-toggle restarts)", n, candidateAccumFile)
	}
	promoted := map[string]autoExpandedRule{}
	if existing, err := loadExistingPromoted(); err == nil {
		promoted = existing
		log.Printf("auto-promote: loaded %d existing promoted rules from %s", len(promoted), autoPromotedOutFile)
	} else if !os.IsNotExist(err) {
		log.Printf("auto-promote: failed to read existing %s: %v (starting fresh)", autoPromotedOutFile, err)
	}

	tk := time.NewTicker(autoExpandTick)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			// Drain once; feed BOTH the brand-new-apex candidate accumulator
			// (always, for shadow calibration) and the same-apex expander below.
			pending := a.drainUnmatchedSNIs()

			a.processCandidates(pending, acc, promoted, runDir, time.Now().Unix())

			// Same-apex auto-expand: gated by auto_expand.enabled.
			if _, err := os.Stat(flagPath); err != nil {
				continue
			}
			if len(pending) == 0 {
				continue
			}

			added := 0
			st.mu.Lock()
			rules := loadL3Rules().rules
			blocklist, err := loadBlocklist()
			if err != nil {
				log.Printf("auto-expand: blocklist load failed: %v (treating as empty)", err)
				// fallthrough — continue with empty blocklist
			}
			now := time.Now().Unix()
			for sni, uidSet := range pending {
				if _, already := st.confirmed[sni]; already {
					continue
				}
				if rule, uid, hits, ok := evaluateCandidate(sni, uidSet, rules, blocklist, a); ok {
					expanded := buildExpandedRule(sni, rule, uid, hits, a.PkgForUID(uid), now)
					st.confirmed[sni] = expanded
					added++
					log.Printf("auto-expand: confirmed %s under rule %s (uid=%d hits=%d apex=%s)",
						sni, rule.ID, uid, hits, expanded.Apex)
				}
			}
			needWrite := added > 0
			st.mu.Unlock()

			if needWrite {
				if err := writeExpansions(st); err != nil {
					log.Printf("auto-expand: write failed: %v", err)
				} else {
					log.Printf("auto-expand: wrote %s (+%d new, %d total)", autoExpandOutFile, added, len(st.confirmed))
					st.lastWrittenAt = now
					// Bust the rule cache so next classifyHost sees new rules.
					invalidateRuleCache()
				}
			}
		}
	}
}

// evaluateCandidate runs the three evidence checks for one candidate SNI.
// Returns the winning rule + winning uid + that uid's hit count + ok.
//
// Selection policy when multiple (rule, uid) combos qualify:
//  1. Highest hit count wins (strongest evidence).
//  2. Tie-break by rule ID alphabetical (deterministic across reboots).
func evaluateCandidate(sni string, uidSet map[int]struct{}, rules []l3Rule, blocklist map[string]struct{}, a *SelfAttribAggregator) (l3Rule, int, int, bool) {
	apex := eTLDPlus1(sni)
	if apex == "" {
		return l3Rule{}, 0, 0, false
	}
	// Evidence #3: blocklist (cheap, do first).
	if _, blocked := blocklist[apex]; blocked {
		return l3Rule{}, 0, 0, false
	}

	// Evidence #1: which rules share this apex via at least one suffix?
	var apexRules []l3Rule
	for _, r := range rules {
		for _, suf := range r.Suffixes {
			s := strings.ToLower(strings.TrimSpace(suf))
			if eTLDPlus1(s) == apex {
				apexRules = append(apexRules, r)
				break // one suffix is enough to qualify this rule
			}
		}
	}
	if len(apexRules) == 0 {
		return l3Rule{}, 0, 0, false
	}

	// Evidence #2: pick (rule, uid) with highest hit count, must be >= floor.
	bestHits := 0
	var bestRule l3Rule
	var bestUID int
	for _, r := range apexRules {
		for uid := range uidSet {
			h := a.HitCount(uid, r.ID)
			if h < autoExpandMinHits {
				continue
			}
			if h > bestHits || (h == bestHits && r.ID < bestRule.ID) {
				bestHits = h
				bestRule = r
				bestUID = uid
			}
		}
	}
	if bestHits == 0 {
		return l3Rule{}, 0, 0, false
	}
	return bestRule, bestUID, bestHits, true
}

// buildExpandedRule materializes the autoExpandedRule struct from a confirmed
// (sni, parent rule, uid, hit count) tuple.
func buildExpandedRule(sni string, parent l3Rule, uid int, hits int, pkg string, now int64) autoExpandedRule {
	subdomain := strings.TrimSuffix(sni, "."+eTLDPlus1(sni))
	if subdomain == "" {
		subdomain = sni
	}
	// Sanitize subdomain into a rule-id-safe suffix.
	idSuffix := strings.ReplaceAll(subdomain, ".", "_")
	idSuffix = strings.ReplaceAll(idSuffix, "-", "_")
	if len(idSuffix) > 40 {
		idSuffix = idSuffix[:40]
	}
	displayName := parent.Name
	if displayName == "" {
		displayName = parent.ID
	}
	return autoExpandedRule{
		ID:         parent.ID + "_autoexp_" + idSuffix,
		Name:       displayName + " (自动扩展: " + subdomain + ")",
		App:        displayName + " (自动扩展: " + subdomain + ")",
		Category:   parent.Category,
		Confidence: "medium", // auto-confirmed but not human-verified
		Suffixes:   []string{sni},

		Source:       "auto_expanded",
		Apex:         eTLDPlus1(sni),
		ParentRuleID: parent.ID,
		AddedAt:      now,
		Evidence: autoExpandedEvidence{
			UID:                      uid,
			UIDPkg:                   pkg,
			ParentHitsAtTimeOfExpand: hits,
			ObservedHostname:         sni,
		},
	}
}

// writeExpansions atomically rewrites _auto_expanded.json. Sort rules by
// ID for stable diffs across runs (helps human inspection via git).
func writeExpansions(st *autoExpandState) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	rules := make([]autoExpandedRule, 0, len(st.confirmed))
	for _, r := range st.confirmed {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	file := autoExpandedFile{
		SchemaVersion: "2.0",
		Subset:        "_auto_expanded",
		RulesVersion:  fmt.Sprintf("auto-expanded-v5.6-%d", time.Now().Unix()),
		Rules:         rules,
	}
	body, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	dst := filepath.Join(externalRulesDir, autoExpandOutFile)
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

// loadExistingExpansions reads the on-disk file if it exists, so the expander
// goroutine starts with the previous run's confirmed expansions in memory
// (avoids re-processing the same SNIs after a dpid restart).
func loadExistingExpansions() (map[string]autoExpandedRule, error) {
	dst := filepath.Join(externalRulesDir, autoExpandOutFile)
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
		// Key by the first suffix (which is always the SNI we expanded under).
		if len(r.Suffixes) > 0 {
			out[r.Suffixes[0]] = r
		}
	}
	return out, nil
}

// invalidateRuleCache forces classifyHost to reload rules from disk on its
// next call, picking up our new _auto_expanded.json entries.
//
// The cache in rule.go is keyed by mtime+size of the rules dir, but since
// we just wrote a file inside that dir, the dir's mtime updated and the
// next loadL3Rules() will recompile.
//
// We don't need a function here; loadL3Rules() handles it. This is a
// docstring placeholder for the design intent.
func invalidateRuleCache() {
	// Touch the rule cache's reset path. The cache invalidates by
	// stat-checking the dir each call, so writing a new file in the
	// dir is sufficient. This function exists as documentation of intent.
}
