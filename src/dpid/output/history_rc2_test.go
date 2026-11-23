package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHistoryDefaultDirAndMigrateLegacy(t *testing.T) {
	if !strings.HasSuffix(HistoryDir, filepath.Join("data", "dpi_history")) {
		t.Fatalf("default HistoryDir must point to persistent data/dpi_history, got %q", HistoryDir)
	}

	root := t.TempDir()
	legacyRun := filepath.Join(root, "run")
	targetHist := filepath.Join(root, "data", "dpi_history")
	if err := os.MkdirAll(legacyRun, 0o755); err != nil {
		t.Fatal(err)
	}

	// Day 1 exists only in legacy run/; Day 2 exists in both legacy run/ and data/dpi_history/.
	row1 := `{"t":1700000100,"mac":"aa:bb:cc:dd:ee:01","app_id":"bili","tx":100,"rx":200}`
	row2Dup := `{"t":1700086500,"mac":"aa:bb:cc:dd:ee:01","app_id":"bili","tx":50,"rx":60}`
	row2New := `{"t":1700087400,"mac":"aa:bb:cc:dd:ee:01","app_id":"douyin","tx":300,"rx":400}`

	if err := os.WriteFile(filepath.Join(legacyRun, "stats.20231114.jsonl"), []byte(row1+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(targetHist, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetHist, "stats.20231115.jsonl"), []byte(row2Dup+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyRun, "stats.20231115.jsonl"), []byte(row2Dup+"\n"+row2New+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := MigrateLegacyHistory(legacyRun, targetHist); err != nil {
		t.Fatalf("MigrateLegacyHistory failed: %v", err)
	}

	// Legacy run/ must no longer hold stats.*.jsonl.
	rem, _ := filepath.Glob(filepath.Join(legacyRun, "stats.*.jsonl"))
	if len(rem) != 0 {
		t.Fatalf("residual stats files left in tmpfs run/: %v", rem)
	}

	b1, err := os.ReadFile(filepath.Join(targetHist, "stats.20231114.jsonl"))
	if err != nil || strings.TrimSpace(string(b1)) != row1 {
		t.Fatalf("day1 migrated content mismatch: err=%v body=%q", err, string(b1))
	}

	b2, err := os.ReadFile(filepath.Join(targetHist, "stats.20231115.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines2 := strings.Split(strings.TrimSpace(string(b2)), "\n")
	if len(lines2) != 2 || lines2[0] != row2Dup || lines2[1] != row2New {
		t.Fatalf("day2 merged content mismatch (expected dedup + append): %v", lines2)
	}
}

func TestHistorySamplerRespectsOverriddenHistoryDir(t *testing.T) {
	oldDir := HistoryDir
	tmpHist := t.TempDir()
	HistoryDir = tmpHist
	t.Cleanup(func() { HistoryDir = oldDir })

	w := NewWriter(filepath.Join(t.TempDir(), "dpi_state.json"), "test")
	tb := NewIPNameTable()
	w.SetIPNameTable(tb)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	tb.RecordDNS("upos-sz-mirrorcos.bilivideo.com", []string{"203.0.113.10"}, 300, now)
	w.RecordDNS("aa:bb:cc:dd:ee:02", "192.168.43.10", "192.168.43.1", "upos-sz-mirrorcos.bilivideo.com", now)
	w.RecordFlow("aa:bb:cc:dd:ee:02", "192.168.43.10", "203.0.113.10", false, 443, 4096, true, now)

	hs := NewHistorySampler(w)
	hs.Tick(now) // baseline

	t2 := now.Add(time.Minute)
	w.RecordFlow("aa:bb:cc:dd:ee:02", "192.168.43.10", "203.0.113.10", false, 443, 8192, false, t2)
	hs.Tick(t2)

	expectFile := filepath.Join(tmpHist, "stats.20261122.jsonl")
	b, err := os.ReadFile(expectFile)
	if err != nil || len(b) == 0 {
		t.Fatalf("expected history sample in %s, err=%v", expectFile, err)
	}
}
