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
