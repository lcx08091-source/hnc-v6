package appmeta

// Live PackageManager label resolution. Runs a tiny dex helper via
// app_process to read the real, localized application labels from the
// Android PackageManager (the launcher/settings names). This covers
// every app — user-installed, OEM, split APKs — not just the curated map.
//
// Everything here is best-effort: if app_process is missing, the helper
// is absent, SELinux blocks it, or parsing fails, the live map stays
// empty and Resolver.Display transparently falls back to the curated map
// + prettyFallback. dpid never depends on this succeeding.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// liveLabelTTL is how often the dex helper is re-run. Matched roughly to
// the pm package-uid cache cadence; app label changes are rare.
const liveLabelTTL = 10 * time.Minute

// liveLabelTimeout caps a single helper invocation.
const liveLabelTimeout = 30 * time.Second

// liveLabels holds PackageManager-resolved labels (pkg → label).
type liveLabels struct {
	mu        sync.RWMutex
	byPkg     map[string]string
	loadedAt  time.Time
	source    string // "pm_live" once a real run (or cache load) succeeds, else "none"
	lastErr   string
	dexPath   string
	persistTo string // optional JSON cache path (survives restart)
}

func newLiveLabels(dexPath, persistTo string) *liveLabels {
	l := &liveLabels{
		byPkg:     map[string]string{},
		source:    "none",
		dexPath:   dexPath,
		persistTo: persistTo,
	}
	l.loadPersisted()
	return l
}

// get returns the live label for pkg, if present and non-empty.
func (l *liveLabels) get(pkg string) (string, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	v, ok := l.byPkg[pkg]
	return v, ok && v != ""
}

// stats reports the current label count and source, for diagnostics.
func (l *liveLabels) stats() (count int, source string) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.byPkg), l.source
}

// refresh runs the helper once and, on success, replaces the map.
func (l *liveLabels) refresh(ctx context.Context) {
	if l.dexPath == "" {
		return
	}
	m, err := runAppLabelHelper(ctx, l.dexPath)
	if err != nil {
		l.mu.Lock()
		l.lastErr = err.Error()
		l.mu.Unlock()
		log.Printf("appmeta: live label refresh failed: %v", err)
		return
	}
	if len(m) == 0 {
		l.mu.Lock()
		l.lastErr = "helper returned no rows"
		l.mu.Unlock()
		return
	}
	l.mu.Lock()
	l.byPkg = m
	l.loadedAt = time.Now()
	l.source = "pm_live"
	l.lastErr = ""
	l.mu.Unlock()
	l.persist(m)
	log.Printf("appmeta: live labels refreshed (%d apps)", len(m))
}

// runAppLabelHelper invokes the dex helper and parses "uid\tpkg\tlabel".
func runAppLabelHelper(ctx context.Context, dexPath string) (map[string]string, error) {
	if _, err := os.Stat(dexPath); err != nil {
		return nil, fmt.Errorf("dex not found at %s: %w", dexPath, err)
	}
	cctx, cancel := context.WithTimeout(ctx, liveLabelTimeout)
	defer cancel()

	// "app_process" resolves to the 32/64-bit wrapper via PATH on device.
	// The "/" arg is the (unused) command directory app_process expects.
	cmd := exec.CommandContext(cctx, "app_process", "/", "io.hnc.applabel.AppLabel")
	cmd.Env = append(os.Environ(), "CLASSPATH="+dexPath)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			return nil, fmt.Errorf("%w: %s", err, firstLine(msg))
		}
		return nil, err
	}

	m := make(map[string]string, 256)
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 3)
		if len(parts) != 3 {
			continue
		}
		pkg := strings.TrimSpace(parts[1])
		label := strings.TrimSpace(parts[2])
		if pkg == "" || label == "" {
			continue
		}
		if _, ok := m[pkg]; !ok {
			m[pkg] = label
		}
	}
	return m, nil
}

func (l *liveLabels) persist(m map[string]string) {
	if l.persistTo == "" {
		return
	}
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	tmp := l.persistTo + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, l.persistTo)
}

func (l *liveLabels) loadPersisted() {
	if l.persistTo == "" {
		return
	}
	data, err := os.ReadFile(l.persistTo)
	if err != nil {
		return
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return
	}
	if len(m) > 0 {
		l.byPkg = m
		// Mark as live-sourced; a fresh refresh will overwrite shortly.
		l.source = "pm_live"
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
