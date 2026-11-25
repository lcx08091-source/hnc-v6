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
	candMaxSamples  = 40           // candidate samples surfaced in dpi_state (review queue)
	candMaxAgeSec   = 24 * 60 * 60 // drop candidates unseen for 24h
)

var (
	// candidateDecisionsFile holds user-approved apexes (manual "一键 promote"
	// from the WebUI). dpid force-promotes these even in shadow mode. Re-read
	// each tick (like the blocklist) so clicks take effect within 60s.
	candidateDecisionsFile = "/data/local/hnc/etc/candidate_decisions.json"

	// candidateAccumFile persists the accumulator across dpid restarts.
	candidateAccumFile = "/data/local/hnc/run/candidate_accum.json"

	// candPromotedRulesDir defaults to externalRulesDir (overridable in unit tests).
	candPromotedRulesDir = externalRulesDir
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

var (
	candSharedInfraPaths = []string{
		filepath.Join("/data/local/hnc/data/dpi_rules.d", SharedInfraFileName),
		filepath.Join("/data/adb/modules/hotspot_net_ctl/data/dpi_rules.d", SharedInfraFileName),
		filepath.Join("/data/adb/modules/hotspot_network_control/data/dpi_rules.d", SharedInfraFileName),
		filepath.Join(externalRulesDir, SharedInfraFileName),
	}
)

func loadCandidateSharedInfra(runDir string) *SharedInfra {
	var paths []string
	addUnique := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		for _, ex := range paths {
			if ex == p {
				return
			}
		}
		paths = append(paths, p)
	}
	if cleanRun := strings.TrimSpace(runDir); cleanRun != "" {
		hncRoot := filepath.Dir(filepath.Clean(cleanRun))
		addUnique(filepath.Join(hncRoot, "data", "dpi_rules.d", SharedInfraFileName))
		addUnique(filepath.Join(hncRoot, "etc", "dpi_rules.d", SharedInfraFileName))
	}
	for _, p := range candSharedInfraPaths {
		addUnique(p)
	}

	var combined []byte
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() || st.Size() <= 0 || st.Size() > sharedInfraMaxBytes {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil || len(b) == 0 {
			continue
		}
		combined = append(combined, b...)
		if combined[len(combined)-1] != '\n' {
			combined = append(combined, '\n')
		}
	}
	if len(combined) == 0 {
		return nil
	}
	return ParseSharedInfra(combined)
}

func isCandidateSharedInfra(host, apex string, si *SharedInfra) bool {
	if si != nil {
		if (apex != "" && si.Match(apex)) || (host != "" && si.Match(host)) {
			return true
		}
	}
	if apex != "" {
		if _, ok := IsAutoDetectedInfra(apex, si); ok {
			return true
		}
	}
	if host != "" && host != apex {
		if _, ok := IsAutoDetectedInfra(host, si); ok {
			return true
		}
	}
	return false
}

// processCandidates runs once per expander tick. It folds this tick's
// unmatched SNIs into the per-apex accumulator, computes tiers, publishes a
// shadow summary, and — only when auto_promote.enabled — writes HIGH-tier
// brand-new apexes as rules and auto-demotes contradicted ones.
func (a *SelfAttribAggregator) processCandidates(pending map[string]map[int]struct{}, acc *candidateAccumulator, promoted map[string]autoExpandedRule, runDir string, now int64) {
	rules := loadL3Rules().rules
	blocklist, _ := loadBlocklist()
	entityDB := loadEntityDB()
	sharedInfra := loadCandidateSharedInfra(runDir)

	touched := map[string]struct{}{}
	for sni, uidSet := range pending {
		apex := eTLDPlus1(sni)
		if apex == "" {
			continue
		}
		// C073: 候选入库前直接拦截 shared_infra.txt 与四维自动识别共享基建域名,
		// 严禁 CDN / 公共 DNS / 统计推送 SDK 进入候选池或污染飞轮。
		if isCandidateSharedInfra(sni, apex, sharedInfra) {
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
	for apex, c := range acc.byApex {
		if c != nil {
			for u := range c.UIDs {
				if a.IsFlywheelExcludedUID(u) {
					c.TotalHits -= c.UIDs[u]
					if c.TotalHits < 0 {
						c.TotalHits = 0
					}
					delete(c.UIDs, u)
				}
			}
			if len(c.UIDs) == 0 {
				delete(acc.byApex, apex)
				continue
			}
		}
		sampleHost := apex
		if c != nil && c.SampleSNI != "" {
			sampleHost = c.SampleSNI
		}
		if isCandidateSharedInfra(sampleHost, apex, sharedInfra) {
			delete(acc.byApex, apex)
		}
	}

	autoPromoteOn := false
	if _, err := os.Stat(filepath.Join(runDir, autoPromoteFlagFile)); err == nil {
		autoPromoteOn = true
	}

	// User-approved apexes (manual "一键 promote" from the WebUI). Re-read each
	// tick; force-promotion below works regardless of the auto_promote flag.
	decisions := loadCandidateDecisions()

	// v5.7.0-rc33 + B028: conduit auto-detection + dynamic TUN VPN OwnerUid guard.
	apexCountByUID := map[int]int{}
	for _, c := range acc.byApex {
		for uid := range c.UIDs {
			apexCountByUID[uid]++
		}
	}
	isConduitUID := func(uid int) bool {
		return apexCountByUID[uid] >= conduitApexThreshold || a.IsFlywheelExcludedUID(uid)
	}

	// v5.7.0-rc35: publish the detected conduit uids so Snapshot can badge those
	// apps as flywheel-excluded in the WebUI (alongside the explicit list).
	conduitSet := map[int]struct{}{}
	for uid, n := range apexCountByUID {
		if n >= conduitApexThreshold {
			conduitSet[uid] = struct{}{}
		}
	}
	a.SetConduitUIDs(conduitSet)

	changed := false
	// v5.7.0-rc33 + C073: demote already-promoted rules whose attributed app is now a
	// VPN/proxy (explicit or dynamic TUN OwnerUid), a detected conduit, or a shared_infra domain.
	for apex, r := range promoted {
		excludedByList := a.IsFlywheelExcludedPkg(r.Evidence.UIDPkg) || a.IsFlywheelExcludedUID(r.Evidence.UID)
		conduit := r.Source == "auto_promoted" && isConduitUID(r.Evidence.UID)
		infra := isCandidateSharedInfra(r.Evidence.ObservedHostname, apex, sharedInfra)
		if excludedByList || conduit || infra {
			delete(promoted, apex)
			if c := acc.byApex[apex]; c != nil {
				c.SharedLearned = true
			}
			changed = true
			reason := "conduit"
			if excludedByList {
				reason = "vpn/proxy"
			} else if infra {
				reason = "shared_infra"
			}
			log.Printf("flywheel-exclude: demoted %s -> %q (uid=%d pkg=%q reason=%s)",
				apex, r.App, r.Evidence.UID, r.Evidence.UIDPkg, reason)
		}
	}

	sum := candidateSummary{autoPromoteOn: autoPromoteOn, entityDBSize: len(entityDB)}
	for apex, c := range acc.byApex {
		tier, uid := classifyTier(c, blocklist, entityDB)
		if tier != "shared" && isCandidateSharedInfra(c.SampleSNI, apex, sharedInfra) {
			tier, uid = "shared", 0
		}

		if _, isProm := promoted[apex]; isProm {
			// self-correct: a promoted apex that became multi-uid / shared
			// was a mistake — remove the rule and never re-promote it. This
			// also fires when the user rejected it (→ blocklist → tier shared).
			if tier == "shared" || len(c.UIDs) > 1 {
				delete(promoted, apex)
				c.SharedLearned = true
				tier, uid = "shared", 0
				changed = true
				log.Printf("auto-promote: demoted %s (now multi-uid/shared, uids=%d)", apex, len(c.UIDs))
			}
		} else if (tier == "high" || tier == "med") && len(promoted) < candMaxPromoted {
			// HIGH auto-promotes when the flag is on; HIGH or MED can be
			// promoted manually (decisions file), which works even in shadow
			// mode. Both are single-uid, preserving the self-correct invariant.
			_, manual := decisions[apex]
			// v5.7.0-rc33 + B028: never AUTO-promote to a detected conduit or VPN uid.
			// Manual promote still wins (user override).
			if !manual && (isConduitUID(uid) || a.IsFlywheelExcludedUID(uid)) {
				// conduit/VPN uid: suppress auto-promotion (no rule minted)
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

		_, isProm := promoted[apex]
		sum.pending++
		if !isProm && tier == "high" {
			// B034: only unpromoted HIGH-tier items awaiting manual review count toward sum.high
			// so auto-promoted rules never falsely light up the Apps tab notification dot.
			sum.high++
		} else if tier == "shared" {
			sum.shared++
		}

		// surface only actionable candidates (high/med) in the review queue;
		// shared total is reported via sum.shared, low is too ambiguous.
		if len(sum.samples) < candMaxSamples && (tier == "high" || tier == "med") {
			_, label := a.DisplayForUID(uid)
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
		RulesVersion:  fmt.Sprintf("auto-promoted-%d", time.Now().Unix()),
		Rules:         rules,
	}
	body, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	dst := filepath.Join(candPromotedRulesDir, autoPromotedOutFile)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}
	if err := atomicWrite(dst, body, 0o644); err != nil {
		return fmt.Errorf("atomic write %s: %w", dst, err)
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
// snapshot, next tick retries), while atomicWrite guarantees no 0-byte .tmp orphan.
func saveCandidateAccum(acc *candidateAccumulator) {
	data := candidateAccumData{SavedAt: time.Now().Unix(), ByApex: acc.byApex}
	body, err := json.Marshal(&data)
	if err != nil {
		return
	}
	_ = atomicWrite(candidateAccumFile, body, 0o644)
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
	dst := filepath.Join(candPromotedRulesDir, autoPromotedOutFile)
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
