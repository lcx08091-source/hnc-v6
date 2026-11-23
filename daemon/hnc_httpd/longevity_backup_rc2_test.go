package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type rc2LimitFailWriter struct {
	path    string
	limit   int
	written int
}

func (w *rc2LimitFailWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.limit {
		return 0, errors.New("ENOSPC: simulated disk full")
	}
	w.written += len(p)
	return len(p), nil
}

func (w *rc2LimitFailWriter) Close() error { return nil }

func TestLongevityBackupRC2_ExportBuildPropTimeoutAndQuotaPrune(t *testing.T) {
	// 1. Pure-Go build.prop parser extracts static ro.* props without spawning getprop
	propDir := t.TempDir()
	p1 := filepath.Join(propDir, "system.build.prop")
	p2 := filepath.Join(propDir, "vendor.build.prop")
	_ = os.WriteFile(p1, []byte("# comment\nro.product.model=PHK110\nro.build.version.release=15\n"), 0o644)
	_ = os.WriteFile(p2, []byte("ro.product.model=OVERRIDE_IGNORED\nro.build.version.sdk=\"35\"\n"), 0o644)
	parsed := parseBuildPropFiles([]string{p1, p2})
	if parsed["ro.product.model"] != "PHK110" || parsed["ro.build.version.release"] != "15" || parsed["ro.build.version.sdk"] != "35" {
		t.Fatalf("parseBuildPropFiles mismatch: %+v", parsed)
	}

	// 2. Hanging getprop script that spawns a background child holding stdout open is killed within ~2s via -pgid
	shBin, lookErr := exec.LookPath("sh")
	if lookErr != nil {
		t.Skip("sh not found in PATH")
	}
	fakeGetprop := filepath.Join(propDir, "fake_getprop.sh")
	script := "#!/bin/sh\n(sleep 30) &\nsleep 30\n"
	if err := os.WriteFile(fakeGetprop, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	tStart := time.Now()
	val, gerr := runIsolatedGetpropBin(250*time.Millisecond, shBin, fakeGetprop, "ro.missing.prop")
	elapsed := time.Since(tStart)
	if gerr == nil || val != "" || elapsed > 2*time.Second {
		t.Fatalf("hanging getprop was not killed promptly: val=%q err=%v elapsed=%v", val, gerr, elapsed)
	}

	// 3. addSingleFileToZip & apiExport strictly propagate io.Copy ENOSPC errors and remove .tmp without leaving truncated ZIP
	incomp := make([]byte, 64*1024)
	var x uint32 = 0x12345678
	for i := range incomp {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		incomp[i] = byte(x)
	}
	srcBig := filepath.Join(propDir, "big_source.json")
	_ = os.WriteFile(srcBig, incomp, 0o644)
	fw := &rc2LimitFailWriter{limit: 512}
	zw := zip.NewWriter(fw)
	_, copyErr := addSingleFileToZip(zw, srcBig, "ip_app_map.json")
	if copyErr == nil {
		t.Fatal("addSingleFileToZip must propagate io.Copy ENOSPC error instead of silently producing a truncated entry")
	}

	enospcDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(enospcDir, "run"), 0o755)
	_ = os.WriteFile(filepath.Join(enospcDir, "run", "ip_app_map.json"), incomp, 0o644)
	origCreate := exportCreateZipFile
	exportCreateZipFile = func(path string) (io.WriteCloser, error) {
		_ = os.WriteFile(path, []byte("partial"), 0o600)
		return &rc2LimitFailWriter{path: path, limit: 256}, nil
	}
	enospcSrv := newServer(enospcDir)
	enospcRec := httptest.NewRecorder()
	enospcSrv.apiExport(enospcRec, httptest.NewRequest(http.MethodPost, "/api/export?days=1", nil))
	exportCreateZipFile = origCreate
	if enospcRec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on ENOSPC export failure, got %d (%s)", enospcRec.Code, enospcRec.Body.String())
	}
	expLeftovers, _ := os.ReadDir(enospcSrv.exportsDir())
	if len(expLeftovers) != 0 {
		t.Fatalf("expected zero .tmp or truncated .zip leftovers on ENOSPC, got %d files", len(expLeftovers))
	}

	// 4. pruneExportsDir cleans .tmp older than 1h, keeps fresh .tmp, and enforces <= 10 files & <= 128MB
	expDir := filepath.Join(propDir, "exports")
	_ = os.MkdirAll(expDir, 0o755)
	now := time.Now()

	oldTmp := filepath.Join(expDir, "stale.zip.tmp")
	freshTmp := filepath.Join(expDir, "active.zip.tmp")
	_ = os.WriteFile(oldTmp, []byte("stale"), 0o644)
	_ = os.Chtimes(oldTmp, now.Add(-2*time.Hour), now.Add(-2*time.Hour))
	_ = os.WriteFile(freshTmp, []byte("fresh"), 0o644)

	for i := 0; i < 14; i++ {
		p := filepath.Join(expDir, fmt.Sprintf("hnc_calib_%02d.zip", i))
		_ = os.WriteFile(p, []byte("zip-data"), 0o644)
		mt := now.Add(time.Duration(i-20) * time.Minute)
		_ = os.Chtimes(p, mt, mt)
	}
	pruneExportsDir(expDir, now, "")
	if _, err := os.Stat(oldTmp); !os.IsNotExist(err) {
		t.Fatalf("expected >1h .tmp removed, err=%v", err)
	}
	if _, err := os.Stat(freshTmp); err != nil {
		t.Fatalf("expected fresh .tmp preserved, err=%v", err)
	}
	ents, _ := os.ReadDir(expDir)
	zipCnt := 0
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".zip") {
			zipCnt++
		}
	}
	if zipCnt != exportMaxKeepFiles {
		t.Fatalf("zipCnt=%d, want capped at %d", zipCnt, exportMaxKeepFiles)
	}
	if _, err := os.Stat(filepath.Join(expDir, "hnc_calib_00.zip")); !os.IsNotExist(err) {
		t.Fatal("oldest export file should have been pruned")
	}
	if _, err := os.Stat(filepath.Join(expDir, "hnc_calib_13.zip")); err != nil {
		t.Fatal("newest export file must be retained")
	}

	// Also verify 128MB total size cap using sparse files (zero flash bloat, fast Stat().Size())
	expSizeDir := filepath.Join(propDir, "exports_size")
	_ = os.MkdirAll(expSizeDir, 0o755)
	for i := 0; i < 4; i++ {
		p := filepath.Join(expSizeDir, fmt.Sprintf("huge_%d.zip", i))
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Truncate(50 << 20) // 50MB logical size each -> 200MB > 128MB
		_ = f.Close()
		mt := now.Add(time.Duration(i-10) * time.Minute)
		_ = os.Chtimes(p, mt, mt)
	}
	pruneExportsDir(expSizeDir, now, "")
	entsSz, _ := os.ReadDir(expSizeDir)
	var keptBytes int64
	for _, e := range entsSz {
		st, err := e.Info()
		if err == nil {
			keptBytes += st.Size()
		}
	}
	if len(entsSz) != 2 || keptBytes > exportMaxKeepBytes {
		t.Fatalf("expected 2 files (100MB <= 128MB) retained, got %d files (%d bytes)", len(entsSz), keptBytes)
	}

	// 5. End-to-end /api/export merges data/dpi_history/stats.YYYYMMDD.jsonl + run/stats.YYYYMMDD.jsonl preferring data/dpi_history
	hncDir := t.TempDir()
	for _, sub := range []string{"data/dpi_history", "run", "etc/dpi_rules.d"} {
		_ = os.MkdirAll(filepath.Join(hncDir, sub), 0o755)
	}
	tFrom := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	tTo := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	yday := "20261002"
	today := "20261003"
	_ = os.WriteFile(filepath.Join(hncDir, "data", "dpi_history", "stats."+today+".jsonl"), []byte("{\"from\":\"data_dpi_history\"}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(hncDir, "run", "stats."+today+".jsonl"), []byte("{\"from\":\"stale_run\"}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(hncDir, "run", "stats."+yday+".jsonl"), []byte("{\"from\":\"legacy_run_yday\"}\n"), 0o644)

	srv := newServer(hncDir)
	rec := httptest.NewRecorder()
	reqBody := fmt.Sprintf(`{"from":%d,"to":%d}`, tFrom.Unix(), tTo.Unix())
	srv.apiExport(rec, httptest.NewRequest(http.MethodPost, "/api/export", strings.NewReader(reqBody)))
	if rec.Code != http.StatusOK {
		t.Fatalf("apiExport status=%d body=%s", rec.Code, rec.Body.String())
	}
	var expResp struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &expResp); err != nil || expResp.Name == "" {
		t.Fatalf("decode exportResp: err=%v body=%s", err, rec.Body.String())
	}
	zr, err := zip.OpenReader(filepath.Join(srv.exportsDir(), expResp.Name))
	if err != nil {
		t.Fatalf("open exported zip: %v", err)
	}
	defer zr.Close()
	gotZipEntries := map[string]string{}
	for _, zf := range zr.File {
		rc, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		_, _ = b.ReadFrom(rc)
		_ = rc.Close()
		gotZipEntries[zf.Name] = b.String()
	}
	if !strings.Contains(gotZipEntries["stats/stats."+today+".jsonl"], "data_dpi_history") {
		t.Fatalf("export zip did not prefer data/dpi_history for today: %q", gotZipEntries["stats/stats."+today+".jsonl"])
	}
	if !strings.Contains(gotZipEntries["stats/stats."+yday+".jsonl"], "legacy_run_yday") {
		t.Fatalf("export zip missed legacy run/ fallback for yesterday: %q", gotZipEntries["stats/stats."+yday+".jsonl"])
	}
}

func TestLongevityBackupRC2_BackupAllowlistLegacySchemaAndReload(t *testing.T) {
	srcDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(srcDir, "data"), 0o755)
	_ = os.MkdirAll(filepath.Join(srcDir, "run"), 0o755)

	files := map[string]string{
		"rules.json":             `{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[],"whitelist":[]}`,
		"dpi_fp_prototypes.json": `{"version":1,"apps":{"bilibili":{"samples":12}}}`,
		"self_policy.json":       `{"version":1,"enabled":true}`,
		"rmac_policy.json":       `{"mode":"warn","quarantine_down_mbps":2}`,
		"webui_access.json":      `{"mode":"allowlist","allowed_macs":["aa:bb:cc:dd:ee:01"]}`,
		"limit_policies.json":    `{"version":1,"devices":{"aa:bb:cc:dd:ee:01":{"quota":{"daily_gb":3.5,"action":"throttle","throttle_mbps":2,"throttle_up_mbps":1}}}}`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(srcDir, "data", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	bundle, err := ExportBackupBundle(srcDir)
	if err != nil {
		t.Fatalf("ExportBackupBundle: %v", err)
	}
	if bundle.SchemaVersion != v6BackupSchemaVersion {
		t.Fatalf("exported schema_version=%q, want %q", bundle.SchemaVersion, v6BackupSchemaVersion)
	}
	for _, wantKey := range []string{"dpi_fp_prototypes.json", "self_policy.json", "rmac_policy.json", "webui_access.json"} {
		if _, ok := bundle.Files[wantKey]; !ok {
			t.Fatalf("ExportBackupBundle missing newly allowlisted %s", wantKey)
		}
	}

	// Restore into a live server with schema_version="6.1" (forward compatibility) and verify limitCtl + cache reload + single-line webui_access.json
	dstDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dstDir, "data"), 0o755)
	_ = os.MkdirAll(filepath.Join(dstDir, "run"), 0o755)
	_ = os.WriteFile(filepath.Join(dstDir, "data", "rules.json"), []byte(`{"version":1,"whitelist_mode":true,"devices":{},"blacklist":[],"whitelist":[]}`), 0o600)

	srv := newServer(dstDir)
	srv.limitCtl = newLimitCtl(dstDir, &srv.actionMu)
	_, _ = srv.jsonCache.read(filepath.Join(dstDir, "data", "rules.json"))

	bundle61 := bundle
	bundle61.SchemaVersion = "6.1"
	canonMap, err := validateBackupBundle(bundle61)
	if err != nil {
		t.Fatalf("validateBackupBundle(schema_version=6.1) failed: %v", err)
	}
	if _, err := restoreValidatedBackupBundle(dstDir, canonMap, srv); err != nil {
		t.Fatalf("restoreValidatedBackupBundle: %v", err)
	}

	// Verify schema_version="6.0" is also accepted
	bundle60 := bundle
	bundle60.SchemaVersion = "6.0"
	if _, err := validateBackupBundle(bundle60); err != nil {
		t.Fatalf("validateBackupBundle(schema_version=6.0) failed: %v", err)
	}

	// Verify webui_access.json is written as single-line compact JSON (required by bin/webui_guard.sh)
	webuiBytes, err := os.ReadFile(filepath.Join(dstDir, "data", "webui_access.json"))
	if err != nil {
		t.Fatalf("read restored webui_access.json: %v", err)
	}
	if strings.Count(strings.TrimRight(string(webuiBytes), "\n"), "\n") != 0 {
		t.Fatalf("webui_access.json must be single-line JSON for webui_guard.sh, got:\n%s", webuiBytes)
	}

	// Verify limitCtl reloaded restored limit_policies.json into memory without daemon restart
	srv.limitCtl.mu.Lock()
	pol := srv.limitCtl.policies["aa:bb:cc:dd:ee:01"]
	srv.limitCtl.mu.Unlock()
	if pol == nil || pol.Quota == nil || pol.Quota.DailyGB != 3.5 {
		t.Fatalf("limitCtl did not reload limit_policies.json after backup restore: %+v", pol)
	}

	// Verify jsonCache was invalidated (whitelist_mode updated from true -> false)
	rawRules, err := srv.jsonCache.read(filepath.Join(dstDir, "data", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	if rm, _ := rawRules.(map[string]any); rm["whitelist_mode"] != false {
		t.Fatalf("jsonCache returned stale rules.json after restore: %+v", rm)
	}

	// Verify legacy keys ("fp_prototypes.json" & "dpi_self_config.json") in old v6.0 backups map to real files on restore
	legacyCanon := map[string][]byte{
		"rules.json":           []byte(`{"blacklist":[],"devices":{},"version":1,"whitelist":[],"whitelist_mode":false}`),
		"fp_prototypes.json":   []byte(`{"legacy_fp":1}`),
		"dpi_self_config.json": []byte(`{"legacy_self":true}`),
	}
	legacySHA, legacyPer := computeBackupManifestSHA256(legacyCanon)
	legacyBundle := V6BackupBundle{
		SchemaVersion: "6.0",
		FileCount:     3,
		Files: map[string]json.RawMessage{
			"rules.json":           legacyCanon["rules.json"],
			"fp_prototypes.json":   legacyCanon["fp_prototypes.json"],
			"dpi_self_config.json": legacyCanon["dpi_self_config.json"],
		},
		FileSHA256: legacyPer,
		SHA256:     legacySHA,
	}
	legDst := t.TempDir()
	if _, err := RestoreBackupBundle(legDst, legacyBundle); err != nil {
		t.Fatalf("RestoreBackupBundle legacy key bundle: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(legDst, "data", "dpi_fp_prototypes.json")); err != nil || !strings.Contains(string(b), `"legacy_fp"`) {
		t.Fatalf("fp_prototypes.json not mapped to dpi_fp_prototypes.json: err=%v body=%s", err, b)
	}
	if b, err := os.ReadFile(filepath.Join(legDst, "data", "self_policy.json")); err != nil || !strings.Contains(string(b), `"legacy_self"`) {
		t.Fatalf("dpi_self_config.json not mapped to self_policy.json: err=%v body=%s", err, b)
	}
}

func TestLongevityBackupRC2_RulesStoreSelfHealAndFastLockFallback(t *testing.T) {
	// 1. Corrupt rules.json + valid .json_backups/rules.json.*.bak -> auto restores latest valid backup
	dir1 := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir1, "data", ".json_backups"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir1, "run"), 0o755)
	oldBak := filepath.Join(dir1, "data", ".json_backups", "rules.json.20261101-000000.1.bak")
	newBak := filepath.Join(dir1, "data", ".json_backups", "rules.json.20261102-000000.2.bak")
	badBak := filepath.Join(dir1, "data", ".json_backups", "rules.json.20261103-000000.3.bak")
	_ = os.WriteFile(oldBak, []byte(`{"version":1,"hotspot_ssid":"OldSSID","devices":{},"blacklist":[],"whitelist":[]}`), 0o600)
	_ = os.WriteFile(newBak, []byte(`{"version":1,"hotspot_ssid":"RestoredSSID","devices":{},"blacklist":["aa:bb:cc:dd:ee:09"],"whitelist":[]}`), 0o600)
	_ = os.WriteFile(badBak, []byte(`{truncated`), 0o600)
	now := time.Now()
	_ = os.Chtimes(oldBak, now.Add(-3*time.Minute), now.Add(-3*time.Minute))
	_ = os.Chtimes(newBak, now.Add(-2*time.Minute), now.Add(-2*time.Minute))
	_ = os.Chtimes(badBak, now.Add(-1*time.Minute), now.Add(-1*time.Minute))

	_ = os.WriteFile(rulesFilePath(dir1), []byte(`{corrupt-half-written`), 0o644)
	rs := &rulesStoreEngine{}
	root1, err := rs.ReadAll(dir1)
	if err != nil {
		t.Fatalf("ReadAll should self-heal from .json_backups, got err=%v", err)
	}
	if anyToRuleString(root1["hotspot_ssid"]) != "RestoredSSID" {
		t.Fatalf("expected RestoredSSID from newest valid backup, got %+v", root1)
	}
	onDisk1, err := os.ReadFile(rulesFilePath(dir1))
	if err != nil || !strings.Contains(string(onDisk1), "RestoredSSID") {
		t.Fatalf("healed rules.json not written back to disk: err=%v body=%s", err, onDisk1)
	}

	// 2. Corrupt rules.json with NO valid backup -> renames to .corrupt.<ts> and self-heals to defaultRulesRoot()
	dir2 := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir2, "data"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir2, "run"), 0o755)
	_ = os.WriteFile(rulesFilePath(dir2), []byte(`<<<corrupt>>>`), 0o644)
	root2, err := rs.ReadAll(dir2)
	if err != nil {
		t.Fatalf("ReadAll without backup should self-heal to defaultRulesRoot, got err=%v", err)
	}
	if root2["whitelist_mode"] != false {
		t.Fatalf("unexpected default root: %+v", root2)
	}
	ents2, _ := os.ReadDir(filepath.Join(dir2, "data"))
	foundCorruptArchive := false
	for _, e := range ents2 {
		if strings.HasPrefix(e.Name(), "rules.json.corrupt.") {
			foundCorruptArchive = true
		}
	}
	if !foundCorruptArchive {
		t.Fatal("expected corrupt rules.json renamed to rules.json.corrupt.<ts>")
	}

	// 3. acquireCooperativeJSONLock fast fallback (< 150ms, NOT 1.5s spin) when os.Mkdir fails with !os.IsExist
	dir3 := t.TempDir()
	// Make "run" a regular file so Mkdir("run/json.lock") fails with ENOTDIR (!os.IsExist)
	_ = os.WriteFile(filepath.Join(dir3, "run"), []byte("not-a-dir"), 0o600)
	tLock := time.Now()
	unlock := acquireCooperativeJSONLock(dir3)
	unlock()
	if d := time.Since(tLock); d > 200*time.Millisecond {
		t.Fatalf("acquireCooperativeJSONLock spun for %v on non-IsExist error (want immediate fallback)", d)
	}
}

func TestLongevityBackupRC2_TokensTmpCleanupCorruptDebounceAndRollback(t *testing.T) {
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "remote_tokens.json")
	ts := NewTokensStore(tokPath)

	// 1. Valid PutIfAbsent persists cleanly
	if err := ts.PutIfAbsent("tok_good", Token{Hash: "h1", Created: 100, LastSeen: 100}); err != nil {
		t.Fatalf("PutIfAbsent valid: %v", err)
	}

	// 2. PutIfAbsent when saveAtomicLocked fails must roll back in-memory map!
	// Block tmp write by making remote_tokens.json.tmp a non-empty directory so os.WriteFile(tmp) fails and os.Remove(tmp) cannot delete non-empty dir
	tmpBlocker := tokPath + ".tmp"
	_ = os.MkdirAll(filepath.Join(tmpBlocker, "keep"), 0o755)
	if err := ts.PutIfAbsent("tok_should_rollback", Token{Hash: "h2", Created: 200, LastSeen: 200}); err == nil {
		t.Fatal("expected error when tmp path is blocked")
	}
	if _, exists := ts.Get("tok_should_rollback"); exists {
		t.Fatal("PutIfAbsent failed to roll back in-memory token after disk write failure")
	}
	_ = os.RemoveAll(tmpBlocker)

	// 3. Corrupt remote_tokens.json on disk: preserves in-memory valid token AND records mtime/size so subsequent SyncIfChanged calls don't storm disk
	time.Sleep(15 * time.Millisecond)
	if err := os.WriteFile(tokPath, []byte("{corrupt-tokens-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ts.SyncIfChanged(); err == nil {
		t.Fatal("first SyncIfChanged on corrupt JSON should report parse error")
	}
	if _, stillOK := ts.Get("tok_good"); !stillOK {
		t.Fatal("corrupt disk reload must preserve existing valid in-memory tokens")
	}
	// Second SyncIfChanged with unchanged mtime/size must short-circuit without re-reading/re-failing!
	if err := ts.SyncIfChanged(); err != nil {
		t.Fatalf("subsequent SyncIfChanged on unchanged corrupt file should be debounced by recorded mtime/size, got %v", err)
	}
}
