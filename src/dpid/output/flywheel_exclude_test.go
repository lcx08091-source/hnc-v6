package output

import (
	"os"
	"path/filepath"
	"testing"
)

// withTempExcludeFile points flywheelExcludeFile at a temp path containing
// body (or removes it when body=="") for the duration of fn, then restores.
func withTempExcludeFile(t *testing.T, body string, fn func()) {
	t.Helper()
	orig := flywheelExcludeFile
	defer func() { flywheelExcludeFile = orig }()
	dir := t.TempDir()
	p := filepath.Join(dir, "flywheel_exclude.json")
	if body != "" {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write temp: %v", err)
		}
	}
	flywheelExcludeFile = p
	fn()
}

func TestLoadFlywheelExcludePkgs_BuiltinAlwaysPresent(t *testing.T) {
	// No user file at all → still get the built-in seed.
	withTempExcludeFile(t, "", func() {
		got := loadFlywheelExcludePkgs()
		if got == nil {
			t.Fatal("expected non-nil map even without user file")
		}
		for _, want := range []string{"com.follow.clash", "com.github.metacubex.clash.meta", "net.mullvad.mullvadvpn"} {
			if _, ok := got[want]; !ok {
				t.Errorf("built-in seed missing %q", want)
			}
		}
	})
}

func TestLoadFlywheelExcludePkgs_UserMerge(t *testing.T) {
	body := `{"exclude_pkgs":["com.example.customvpn"," com.spaced.app "]}`
	withTempExcludeFile(t, body, func() {
		got := loadFlywheelExcludePkgs()
		if _, ok := got["com.example.customvpn"]; !ok {
			t.Error("user package not merged")
		}
		if _, ok := got["com.spaced.app"]; !ok {
			t.Error("user package not trimmed/merged")
		}
		// Built-in seed still present alongside the user list.
		if _, ok := got["com.follow.clash"]; !ok {
			t.Error("built-in seed dropped when user file present")
		}
	})
}

func TestLoadFlywheelExcludePkgs_MalformedDegradesToBuiltin(t *testing.T) {
	withTempExcludeFile(t, "{ this is not json", func() {
		got := loadFlywheelExcludePkgs()
		if _, ok := got["com.follow.clash"]; !ok {
			t.Error("malformed user file should degrade to built-in seed, not empty")
		}
	})
}

func TestIsFlywheelExcludedUIDAndPkg(t *testing.T) {
	a := NewSelfAttribAggregator("")
	// Seed the resolved pkg cache + exclusion set directly (bypassing pm).
	a.pkgCache = map[int]string{
		10599: "com.follow.clash",              // VPN
		10063: "com.suda.yzune.wakeupschedule", // normal app
	}
	a.flywheelExcludePkgs = map[string]struct{}{"com.follow.clash": {}}

	if !a.IsFlywheelExcludedUID(10599) {
		t.Error("VPN uid should be excluded")
	}
	if a.IsFlywheelExcludedUID(10063) {
		t.Error("normal app uid should NOT be excluded")
	}
	if a.IsFlywheelExcludedUID(99999) { // unknown uid
		t.Error("unknown uid should NOT be excluded")
	}
	if !a.IsFlywheelExcludedPkg("com.follow.clash") {
		t.Error("VPN pkg should be excluded")
	}
	if a.IsFlywheelExcludedPkg("com.suda.yzune.wakeupschedule") {
		t.Error("normal pkg should NOT be excluded")
	}
	if a.IsFlywheelExcludedPkg("") {
		t.Error("empty pkg should NOT be excluded")
	}
}

func TestConstructorSeedsExcludeList(t *testing.T) {
	// NewSelfAttribAggregator must seed flywheelExcludePkgs so the guard is live
	// before the first pkg-cache refresh.
	a := NewSelfAttribAggregator("")
	if a.flywheelExcludePkgs == nil {
		t.Fatal("constructor did not seed flywheelExcludePkgs")
	}
	if _, ok := a.flywheelExcludePkgs["com.follow.clash"]; !ok {
		t.Error("constructor seed missing built-in VPN package")
	}
}

func TestClassifyTier(t *testing.T) {
	empty := map[string]struct{}{}
	var noDB map[string]entityRec

	// single uid, persistent + enough hits → high
	c := &apexCandidate{Apex: "capcom.co.jp", UIDs: map[int]int{10599: 9}, Windows: 3, TotalHits: 9}
	if tier, uid := classifyTier(c, empty, noDB); tier != "high" || uid != 10599 {
		t.Errorf("expected high/10599, got %s/%d", tier, uid)
	}
	// single uid, not yet persistent → med
	c2 := &apexCandidate{Apex: "newgame.example", UIDs: map[int]int{10599: 2}, Windows: 1, TotalHits: 2}
	if tier, _ := classifyTier(c2, empty, noDB); tier != "med" {
		t.Errorf("expected med, got %s", tier)
	}
	// two uids → low (ambiguous)
	c3 := &apexCandidate{Apex: "shared2.example", UIDs: map[int]int{1: 5, 2: 5}, Windows: 5, TotalHits: 10}
	if tier, _ := classifyTier(c3, empty, noDB); tier != "low" {
		t.Errorf("expected low, got %s", tier)
	}
	// >= candSharedUIDThreshold uids → shared
	c4 := &apexCandidate{Apex: "cdn.example", UIDs: map[int]int{1: 1, 2: 1, 3: 1}, Windows: 5, TotalHits: 9}
	if tier, _ := classifyTier(c4, empty, noDB); tier != "shared" {
		t.Errorf("expected shared, got %s", tier)
	}
	// explicit blocklist → shared
	c5 := &apexCandidate{Apex: "blocked.example", UIDs: map[int]int{1: 9}, Windows: 5, TotalHits: 9}
	if tier, _ := classifyTier(c5, map[string]struct{}{"blocked.example": {}}, noDB); tier != "shared" {
		t.Errorf("expected shared (blocklist), got %s", tier)
	}
	// already learned-shared (demoted once) → shared, never re-promote
	c6 := &apexCandidate{Apex: "demoted.example", UIDs: map[int]int{1: 9}, Windows: 5, TotalHits: 9, SharedLearned: true}
	if tier, _ := classifyTier(c6, empty, noDB); tier != "shared" {
		t.Errorf("expected shared (SharedLearned), got %s", tier)
	}
}

func TestDynamicVPNConduitTunIfindexGateAndUnpromotedHighCount(t *testing.T) {
	oldNetDir := sysClassNetDir
	oldDumpFn := runDumpsysVPNFn
	oldAccum := candidateAccumFile
	oldDec := candidateDecisionsFile
	oldPromDir := candPromotedRulesDir
	t.Cleanup(func() {
		sysClassNetDir = oldNetDir
		runDumpsysVPNFn = oldDumpFn
		candidateAccumFile = oldAccum
		candidateDecisionsFile = oldDec
		candPromotedRulesDir = oldPromDir
		resetDynamicVPNConduitCacheForTest()
	})
	resetDynamicVPNConduitCacheForTest()

	fakeNet := t.TempDir()
	sysClassNetDir = fakeNet

	mkTun := func(name, ifidx, flags string) {
		d := filepath.Join(fakeNet, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(d, "tun_flags"), []byte("0x1001\n"), 0o644)
		_ = os.WriteFile(filepath.Join(d, "ifindex"), []byte(ifidx+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(d, "flags"), []byte(flags+"\n"), 0o644)
	}

	dumpCalls := 0
	runDumpsysVPNFn = func() (string, error) {
		dumpCalls++
		return "VPN for user 0:\n  mPackage: com.stealth.rebrandedvpn\n  OwnerUid: 10888\n", nil
	}

	// 1. OEM vgate0 and clat4 must be ignored with zero dumpsys invocations.
	mkTun("vgate0", "31", "0x1091")
	mkTun("clat4", "32", "0x1091")
	u0, _ := refreshDynamicVPNConduits()
	if dumpCalls != 0 || len(u0) != 0 {
		t.Fatalf("vgate0/clat4 must not trigger dumpsys: calls=%d uids=%v", dumpCalls, u0)
	}

	// 2. Active Meta TUN appears -> 1 dumpsys invocation, OwnerUid 10888 captured; repeated calls with unchanged ifindex = 0 new calls.
	mkTun("Meta", "45", "0x1091")
	u1, p1 := refreshDynamicVPNConduits()
	_, hasU1 := u1[10888]
	_, hasP1 := p1["com.stealth.rebrandedvpn"]
	if dumpCalls != 1 || !hasU1 || !hasP1 {
		t.Fatalf("expected 1 dumpsys call and uid 10888 excluded, got calls=%d uids=%v pkgs=%v", dumpCalls, u1, p1)
	}
	_, _ = refreshDynamicVPNConduits()
	if dumpCalls != 1 {
		t.Fatalf("unchanged TUN ifindex must not re-run dumpsys, calls=%d", dumpCalls)
	}

	a := NewSelfAttribAggregator("")
	a.pkgCache = map[int]string{
		10888: "com.stealth.rebrandedvpn",
		10200: "com.real.gameapp",
	}
	if !a.IsFlywheelExcludedUID(10888) || !a.IsFlywheelExcludedPkg("com.stealth.rebrandedvpn") {
		t.Fatal("dynamic VPN OwnerUid 10888 and package must be excluded")
	}

	// 3. Reconnecting VPN changes ifindex (45 -> 49) -> triggers exactly 1 refresh.
	_ = os.WriteFile(filepath.Join(fakeNet, "Meta", "ifindex"), []byte("49\n"), 0o644)
	_, _ = refreshDynamicVPNConduits()
	if dumpCalls != 2 {
		t.Fatalf("TUN ifindex change should trigger refresh once, calls=%d", dumpCalls)
	}

	// 4. B034: processCandidates must exclude dynamic VPN UID 10888 and count sum.high ONLY for unpromoted items.
	tmpHNC := t.TempDir()
	runDir := filepath.Join(tmpHNC, "run")
	_ = os.MkdirAll(runDir, 0o755)
	candidateAccumFile = filepath.Join(runDir, "candidate_accum.json")
	candidateDecisionsFile = filepath.Join(tmpHNC, "decisions.json")
	candPromotedRulesDir = filepath.Join(tmpHNC, "rules.d")

	acc := newCandidateAccumulator()
	promoted := map[string]autoExpandedRule{}
	now := int64(1764000000)

	// Accumulate 3 windows / 6 hits for real app (10200) and dynamic VPN (10888).
	for w := 0; w < 3; w++ {
		pending := map[string]map[int]struct{}{
			"api.realgame-unique.jp": {10200: {}, 10888: {}},
			"sub.onlyvpn-proxied.io": {10888: {}},
		}
		a.processCandidates(pending, acc, promoted, runDir, now+int64(w*60))
		// Add extra hits so TotalHits >= 6
		if c := acc.byApex["realgame-unique.jp"]; c != nil {
			c.UIDs[10200] += 2
			c.TotalHits += 2
		}
	}
	// Shadow mode (auto_promote.enabled absent): realgame-unique.jp is unpromoted HIGH -> CandidateHigh == 1; VPN domain absent.
	snapShadow := a.Snapshot()
	if snapShadow.CandidateHigh != 1 || snapShadow.CandidatePromoted != 0 {
		t.Fatalf("shadow mode want CandidateHigh=1 CandidatePromoted=0, got high=%d prom=%d", snapShadow.CandidateHigh, snapShadow.CandidatePromoted)
	}
	if _, leaked := acc.byApex["onlyvpn-proxied.io"]; leaked {
		t.Fatal("dynamic VPN UID must never accumulate candidates")
	}

	// Enable auto_promote.enabled -> realgame-unique.jp auto-promotes, so CandidateHigh MUST drop to 0 (no false red dot!).
	if err := os.WriteFile(filepath.Join(runDir, autoPromoteFlagFile), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a.processCandidates(nil, acc, promoted, runDir, now+300)
	snapProm := a.Snapshot()
	if snapProm.CandidatePromoted != 1 || snapProm.CandidateHigh != 0 {
		t.Fatalf("after auto-promotion want CandidatePromoted=1 CandidateHigh=0, got prom=%d high=%d", snapProm.CandidatePromoted, snapProm.CandidateHigh)
	}

	// 5. Removing TUN interface clears dynamic VPN exclusion with zero dumpsys calls.
	_ = os.RemoveAll(filepath.Join(fakeNet, "Meta"))
	uOff, _ := refreshDynamicVPNConduits()
	if len(uOff) != 0 || dumpCalls != 2 {
		t.Fatalf("removing TUN must clear dynamic VPN set without dumpsys, calls=%d uids=%v", dumpCalls, uOff)
	}
}
