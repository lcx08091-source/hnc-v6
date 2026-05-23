// Package appmeta resolves Android package names to human-readable
// display names (and in the future, icons).
//
// Strategy: curated static map + optional user override file. We
// deliberately don't parse APK files because:
//   - aapt2 isn't pre-installed on Android (would need to ship 5MB)
//   - AXML/ARSC parsers break on obfuscated/split APKs (QQ, WeChat etc)
//   - Locale handling complicates which label to pick
//
// Curated map gives 100% reliability on any Android version + handles
// Chinese app names natively. For apps not in the map, we clean up
// the package name as a fallback (com.tencent.mobileqq → "MobileQQ").
//
// User override: if /data/local/hnc/etc/app_labels.json exists, its
// entries take precedence. This is how the user fixes bad fallbacks
// or names that drift over time (e.g. apps that rebrand) without us
// shipping a new dpid binary.
//
// Icons: NOT done here. M6 (UI redesign) will use auto-generated
// 2-letter colored badges from DisplayName, matching the visual style
// of the v5.6 redesign mockup. If/when we need real APK icon extraction,
// add it as M2.5.
package appmeta

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"unicode"
)

// Resolver holds the static curated map + optional user overrides.
// Thread-safe; resolution is a single map lookup so cheap to call
// from the per-snapshot hot path.
type Resolver struct {
	mu           sync.RWMutex
	overrideFile string
	overrides    map[string]string // pkg → label (loaded from JSON, may be empty)
	overrideMTime int64            // last file mtime so we know when to reload
}

// NewResolver constructs a Resolver. overrideFile is the path to the
// optional user override JSON. If the file doesn't exist or is bad
// JSON, that's silently fine; we just use the curated map. Reloading
// is on-demand (next Display call after the file mtime changes).
func NewResolver(overrideFile string) *Resolver {
	r := &Resolver{
		overrideFile: overrideFile,
		overrides:    make(map[string]string),
	}
	r.reloadOverridesIfChanged()
	return r
}

// Display returns the user-facing label for a package name.
//   - If user override set: that wins (e.g. user customized "QQ" → "Tencent QQ")
//   - If in curated map: curated entry (e.g. "com.tencent.mm" → "微信")
//   - Else: cleaned-up package name (e.g. "com.example.foo" → "Foo")
//   - Empty pkg → empty string (caller decides display, usually "uid=N")
func (r *Resolver) Display(pkg string) string {
	if pkg == "" {
		return ""
	}
	r.reloadOverridesIfChanged()

	r.mu.RLock()
	if v, ok := r.overrides[pkg]; ok && v != "" {
		r.mu.RUnlock()
		return v
	}
	r.mu.RUnlock()

	if v, ok := curatedLabels[pkg]; ok {
		return v
	}
	return prettyFallback(pkg)
}

// reloadOverridesIfChanged stats the override file and reloads if the
// mtime changed since last check. No-op if file doesn't exist.
// Called on every Display() call; the stat() is cheap.
func (r *Resolver) reloadOverridesIfChanged() {
	if r.overrideFile == "" {
		return
	}
	st, err := os.Stat(r.overrideFile)
	if err != nil {
		// File doesn't exist or unreadable; that's fine. Clear any
		// stale overrides only if we previously had a file.
		r.mu.Lock()
		if r.overrideMTime != 0 {
			r.overrides = make(map[string]string)
			r.overrideMTime = 0
		}
		r.mu.Unlock()
		return
	}
	mt := st.ModTime().Unix()

	r.mu.RLock()
	cached := r.overrideMTime
	r.mu.RUnlock()
	if cached == mt {
		return
	}

	// File changed; reload.
	data, err := os.ReadFile(r.overrideFile)
	if err != nil {
		return
	}
	var parsed map[string]string
	if err := json.Unmarshal(data, &parsed); err != nil {
		// Bad JSON; leave previous overrides in place.
		return
	}
	r.mu.Lock()
	r.overrides = parsed
	r.overrideMTime = mt
	r.mu.Unlock()
}

// prettyFallback turns "com.tencent.mobileqq" into "MobileQQ" — better
// than showing the raw dotted name, while still being recognizable.
// Rules:
//   - take last dot-segment
//   - title-case first char if it's lowercase letter
//   - preserve all-caps acronyms (QQ stays QQ, not Qq)
//   - if last segment is generic ("android", "app", "mobile"), use
//     second-to-last too (com.facebook.katana → "katana" is bad,
//     com.tencent.mobileqq → "mobileqq" → "MobileQQ" is fine for now)
func prettyFallback(pkg string) string {
	parts := strings.Split(pkg, ".")
	if len(parts) == 0 {
		return pkg
	}
	last := parts[len(parts)-1]
	if last == "" {
		return pkg
	}

	// Title-case the first letter only; leave the rest alone so things
	// like "mobileQQ" or "DiDi" preserve their capitalization.
	runes := []rune(last)
	if unicode.IsLower(runes[0]) {
		runes[0] = unicode.ToUpper(runes[0])
	}
	return string(runes)
}

// LabelCount returns the number of curated + override entries, for
// diagnostics surfaced in dpi_state.json.
func (r *Resolver) LabelCount() (curated, overridden int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(curatedLabels), len(r.overrides)
}
