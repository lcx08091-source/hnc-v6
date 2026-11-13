package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func recoveryTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"run", "data", "logs", "bin", "etc/dpi_rules.d"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A transient disk failure must not make security changes disappear on restart.
func TestTokenChangesRetryAfterPersistenceFailure(t *testing.T) {
	for _, operation := range []string{"revoke", "revoke_all", "prune"} {
		t.Run(operation, func(t *testing.T) {
			dir := recoveryTestDir(t)
			path := filepath.Join(dir, "data", "remote_tokens.json")
			s := NewTokensStore(path)
			for id, seen := range map[string]int64{
				"fresh": time.Now().Unix(),
				"old":   time.Now().Unix() - hardExpirePruneSec - 1,
			} {
				if err := s.PutIfAbsent(id, Token{Hash: "test-hash", LastSeen: seen}); err != nil {
					t.Fatal(err)
				}
			}
			// Block a commit without relying on root-ineffective chmod fixtures.
			if err := os.Mkdir(path+".tmp", 0o700); err != nil {
				t.Fatal(err)
			}
			switch operation {
			case "revoke":
				if !s.Revoke("fresh") {
					t.Fatal("fresh token missing")
				}
			case "revoke_all":
				if n := s.RevokeAll(); n != 2 {
					t.Fatalf("revoked %d tokens, want 2", n)
				}
			case "prune":
				if n, err := s.Prune(); n != 1 || err == nil {
					t.Fatalf("Prune = %d, %v; want 1 and persistence error", n, err)
				}
			}
			if err := os.Remove(path + ".tmp"); err != nil {
				t.Fatal(err)
			}
			// This is the same retry path as SaveLoop's periodic tick.
			if err := s.FlushIfDirty(); err != nil {
				t.Fatal(err)
			}
			restarted := NewTokensStore(path)
			if operation == "prune" {
				if _, ok := restarted.Get("old"); ok {
					t.Fatal("pruned token returned after restart")
				}
			} else if tok, ok := restarted.Get("fresh"); !ok || !tok.Revoked {
				t.Fatal("revocation lost after restart")
			}
		})
	}
}

func TestConnBlockFailedApplyRetriesAfterRestart(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty=%v", empty), func(t *testing.T) {
			dir := recoveryTestDir(t)
			f := connBlockFile{}
			if !empty {
				f.Items = []connBlock{{MAC: "aa:bb:cc:dd:ee:01", Kind: "ip", Value: "8.8.8.8"}}
			}
			body, _ := json.Marshal(f)
			if err := os.WriteFile(connBlocksPath(dir), body, 0o600); err != nil {
				t.Fatal(err)
			}
			fail := filepath.Join(dir, "run", "fail-apply")
			if err := os.WriteFile(fail, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			writeStub(t, dir, "connblock_sync.sh", "echo call >> \"$HNC_DIR/run/apply-calls\"\n[ -f \"$HNC_DIR/run/fail-apply\" ] && exit 1\nexit 0\n")
			s := newServer(dir)
			if _, err := s.connBlockSyncLocked(true); err == nil {
				t.Fatal("expected initial apply failure")
			}
			if err := os.Remove(fail); err != nil {
				t.Fatal(err)
			}
			s = newServer(dir)
			s.connBlockRefresh()
			if connBlockApplyPending(dir) {
				t.Fatal("successful retry did not clear dirty marker")
			}
			s.connBlockRefresh()
			calls, err := os.ReadFile(filepath.Join(dir, "run", "apply-calls"))
			if err != nil || string(calls) != "call\ncall\n" {
				t.Fatalf("apply calls = %q (%v), want failure then one retry", calls, err)
			}
		})
	}
}

func TestDPIRulesExportKeepsCompleteUserJSON(t *testing.T) {
	dir := recoveryTestDir(t)
	path := filepath.Join(dir, "etc", "dpi_rules.d", "99-user-custom.json")
	rules := `{"rules_version":"test","rules":[{"id":"test","name":"` + strings.Repeat("测", 700) + `"}]}`
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newServer(dir)
	w := httptest.NewRecorder()
	s.apiDPIRules(w, httptest.NewRequest(http.MethodGet, "/api/dpi_rules", nil))
	var out struct {
		OK    bool   `json:"ok"`
		Rules string `json:"rules"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.OK || out.Rules != rules {
		t.Fatalf("complete export failed: status=%d body=%s", w.Code, w.Body)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.apiDPIRules(w, httptest.NewRequest(http.MethodGet, "/api/dpi_rules", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `empty`) {
		t.Fatalf("missing user file should export empty rules: %d %s", w.Code, w.Body)
	}
	oversized := `{"rules":[],"padding":"` + strings.Repeat("x", 512*1024) + `"}`
	if err := os.WriteFile(path, []byte(oversized), 0o600); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.apiDPIRules(w, httptest.NewRequest(http.MethodGet, "/api/dpi_rules", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("oversized user file must fail bounded export: %d", w.Code)
	}
}

func TestDiagnosticExportIncludesEffectiveRules(t *testing.T) {
	dir := recoveryTestDir(t)
	rules := []byte(`{"rules":[{"id":"runtime-user-rule"}]}`)
	if err := os.WriteFile(filepath.Join(dir, "etc", "dpi_rules.d", "99-user-custom.json"), rules, 0o600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	track := newServer(dir).addDPIRulesToZip(zw)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if !track.Included || track.FileCount != 1 {
		t.Fatalf("effective runtime rules omitted: %+v", track)
	}
	zr, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil || len(zr.File) != 1 {
		t.Fatalf("archive: %v", err)
	}
	f, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil || !bytes.Equal(body, rules) || zr.File[0].Name != "dpi_rules.d/99-user-custom.json" {
		t.Fatalf("wrong rules snapshot: %s (%v)", body, err)
	}
}

func publishPairGeneration(t *testing.T, dir, pin, sid string) {
	t.Helper()
	path := filepath.Join(dir, "run", "pair_pending")
	body := fmt.Sprintf("%s\n%s\n%d\n", pin, sid, time.Now().Unix()+120)
	if err := os.WriteFile(path+".new", []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
}

func TestStalePairClaimRestoresNewGeneration(t *testing.T) {
	dir := recoveryTestDir(t)
	publishPairGeneration(t, dir, "123456", "old-session-123")
	old, err := readPairPending(dir)
	if err != nil {
		t.Fatal(err)
	}
	publishPairGeneration(t, dir, "654321", "new-session-456")
	if _, err := claimPairPending(dir, old.fileInfo); err == nil {
		t.Fatal("stale verification claimed a newer PIN")
	}
	current, err := readPairPending(dir)
	if err != nil || current.SessionID != "new-session-456" {
		t.Fatalf("new generation lost: %+v (%v)", current, err)
	}
}

func TestOldPairCompletionPreservesNewGeneration(t *testing.T) {
	resetPairGuard(t)
	dir := recoveryTestDir(t)
	publishPairGeneration(t, dir, "123456", "old-session-123")
	s := newServer(dir)
	s.tokens.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.tokens.mu.Unlock()
		}
	}()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- postPin(s, "192.168.43.42", "123456") }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		claims, err := filepath.Glob(filepath.Join(dir, "run", "pair_pending.claimed.*"))
		_, pendingErr := os.Stat(filepath.Join(dir, "run", "pair_pending"))
		if err == nil && len(claims) > 0 && os.IsNotExist(pendingErr) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pairing did not claim old generation")
		}
		time.Sleep(time.Millisecond)
	}
	publishPairGeneration(t, dir, "654321", "new-session-456")
	s.tokens.mu.Unlock()
	locked = false
	select {
	case w := <-done:
		if w.Code != http.StatusFound {
			t.Fatalf("old pairing failed: %d %s", w.Code, w.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pair completion timeout")
	}
	current, err := readPairPending(dir)
	if err != nil || current.SessionID != "new-session-456" {
		t.Fatalf("old completion deleted new PIN: %+v (%v)", current, err)
	}
}

func TestOldPairBurnPreservesNewGeneration(t *testing.T) {
	resetPairGuard(t)
	dir := recoveryTestDir(t)
	publishPairGeneration(t, dir, "654321", "new-session-456")
	s := newServer(dir)
	for i := 0; i < pairBurnAfter; i++ {
		s.pairRecordFailure("192.168.43.42", "old-session-123", "wrong pin")
	}
	current, err := readPairPending(dir)
	if err != nil || current.SessionID != "new-session-456" {
		t.Fatalf("old failure burned new PIN: %+v (%v)", current, err)
	}
}
