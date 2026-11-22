package leakguard

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	DefaultRunDir  = "/data/local/hnc/run"
	EventsFileName = "leakguard_events.json"
	CtrlFileName   = "leakguard_ctrl.json"

	ScopeHostType       = "host_type"
	ScopeHost           = "host"
	ScopeDeviceHostType = "device_host_type"
	MaxIgnoreRules      = 200
)

var ipcWriteSeq atomic.Uint64
var ctrlUpdateMu sync.Mutex

// IgnoreRule defines a persisted LeakGuard ignore whitelist rule shared between
// daemon/hnc_httpd and dpid's LeakGuard Engine.
type IgnoreRule struct {
	ID        string `json:"id"`
	Scope     string `json:"scope"`               // "host_type" | "host" | "device_host_type"
	DstHost   string `json:"dst_host"`            // validated ASCII domain (>=2 labels; >=3 for 2LD public suffixes) or public single IP
	LeakType  string `json:"leak_type,omitempty"` // canonical leak type (e.g. "PHONE", "DEVICE_ID", "GPS", "MAC_ADDR")
	MAC       string `json:"mac,omitempty"`       // lowercase colon-separated MAC (only for device_host_type)
	Note      string `json:"note,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

var twoPartPublicSuffixes = map[string]bool{
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true, "ac.cn": true, "mil.cn": true,
	"ah.cn": true, "bj.cn": true, "cq.cn": true, "fj.cn": true, "gd.cn": true, "gs.cn": true, "gx.cn": true,
	"gz.cn": true, "ha.cn": true, "hb.cn": true, "he.cn": true, "hi.cn": true, "hk.cn": true, "hl.cn": true,
	"hn.cn": true, "jl.cn": true, "js.cn": true, "jx.cn": true, "ln.cn": true, "mo.cn": true, "nm.cn": true,
	"nx.cn": true, "qh.cn": true, "sc.cn": true, "sd.cn": true, "sh.cn": true, "sn.cn": true, "sx.cn": true,
	"tj.cn": true, "tw.cn": true, "xj.cn": true, "xz.cn": true, "yn.cn": true, "zj.cn": true,
	"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true, "net.uk": true, "me.uk": true,
	"com.hk": true, "org.hk": true, "edu.hk": true, "gov.hk": true, "net.hk": true,
	"com.tw": true, "org.tw": true, "edu.tw": true, "gov.tw": true, "net.tw": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true, "go.jp": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
	"co.kr": true, "or.kr": true, "ne.kr": true, "go.kr": true,
	"com.sg": true, "org.sg": true, "edu.sg": true, "gov.sg": true,
	"com.my": true, "com.br": true, "co.nz": true, "org.nz": true, "co.in": true, "com.ru": true,
}

// CanonicalIgnoreLeakType normalizes leak_type strings across dpid and hnc_httpd.
func CanonicalIgnoreLeakType(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 32 || strings.ContainsAny(s, "* \t\r\n/|") {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return "", false
		}
	}
	low := strings.ToLower(s)
	if low == "all" || low == "any" {
		return "", false
	}
	switch low {
	case "phone", "mobile":
		return TypePhone, true
	case "device_id", "deviceid", "imei", "imsi", "meid", "oaid", "android_id", "androidid", "idfa", "idfv":
		return TypeDeviceID, true
	case "gps", "location", "latlng", "coord", "coords":
		return TypeGPS, true
	case "mac_addr", "macaddr", "mac", "bssid", "wifi_mac":
		return TypeMACAddr, true
	default:
		return strings.ToUpper(low), true
	}
}

// ValidateIgnoreTarget strictly validates a whitelist dst_host (ASCII domain or public single IP, 1..253 bytes).
// P0 anti-blinding guardrails:
//   - Rejects any '*' wildcard (e.g. "*", "*.qq.com")
//   - Rejects any '/' CIDR or URL path (e.g. "0.0.0.0/0", "1.2.3.0/24")
//   - Rejects loopback, unspecified, private, link-local, multicast, and broadcast IPs
//   - Rejects single-label TLDs (e.g. "com", "cn", "net"; requires >=2 labels)
//   - Requires >=3 labels when ending in a two-part public suffix (e.g. ".com.cn", ".co.uk")
func ValidateIgnoreTarget(raw string) (kind, normVal string, err error) {
	s := strings.TrimSpace(raw)
	if len(s) == 0 || len(s) > 253 {
		return "", "", errors.New("dst_host length must be 1..253 bytes")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f {
			return "", "", errors.New("dst_host must be printable ASCII without whitespace")
		}
		if c == '*' {
			return "", "", errors.New("wildcard '*' is forbidden in ignore whitelist")
		}
		if c == '/' {
			return "", "", errors.New("CIDR or path '/' is forbidden in ignore whitelist")
		}
	}

	if addr, perr := netip.ParseAddr(s); perr == nil {
		if addr.Zone() != "" {
			return "", "", errors.New("IPv6 zone identifier is forbidden")
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsPrivate() ||
			addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
			return "", "", errors.New("non-public IP address is forbidden in ignore whitelist")
		}
		if addr.Is4() {
			b4 := addr.As4()
			if b4[0] == 0 || b4[0] >= 224 || (b4[0] == 100 && b4[1] >= 64 && b4[1] <= 127) ||
				(b4[0] == 255 && b4[1] == 255 && b4[2] == 255 && b4[3] == 255) {
				return "", "", errors.New("reserved or broadcast IPv4 is forbidden in ignore whitelist")
			}
		}
		normIP := addr.String()
		if len(normIP) > 253 {
			return "", "", errors.New("IP string too long")
		}
		return "ip", normIP, nil
	}

	if strings.ContainsRune(s, ':') {
		return "", "", errors.New("invalid IPv6 address or port-qualified host")
	}

	d := strings.TrimSuffix(strings.ToLower(s), ".")
	if len(d) == 0 || len(d) > 253 || strings.HasPrefix(d, ".") || strings.Contains(d, "..") {
		return "", "", errors.New("invalid ASCII domain")
	}

	allDigitsAndDots := true
	for i := 0; i < len(d); i++ {
		c := d[i]
		if (c < '0' || c > '9') && c != '.' {
			allDigitsAndDots = false
			break
		}
	}
	if allDigitsAndDots {
		return "", "", errors.New("malformed numeric IPv4 address")
	}

	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", "", errors.New("single-label TLD is forbidden (at least 2 domain labels required)")
	}
	for _, lb := range labels {
		if len(lb) == 0 || len(lb) > 63 || lb[0] == '-' || lb[len(lb)-1] == '-' {
			return "", "", errors.New("invalid domain label")
		}
		for i := 0; i < len(lb); i++ {
			c := lb[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", "", errors.New("domain labels must contain only [a-z0-9-]")
			}
		}
	}

	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return "", "", errors.New("invalid TLD length")
	}
	tldHasAlpha := false
	for i := 0; i < len(tld); i++ {
		if tld[i] >= 'a' && tld[i] <= 'z' {
			tldHasAlpha = true
			break
		}
	}
	if !tldHasAlpha {
		return "", "", errors.New("numeric TLD is forbidden")
	}

	twoSuffix := labels[len(labels)-2] + "." + labels[len(labels)-1]
	if twoPartPublicSuffixes[twoSuffix] && len(labels) < 3 {
		return "", "", fmt.Errorf("bare two-part public suffix %q is forbidden (at least 3 labels required)", twoSuffix)
	}

	return "domain", d, nil
}

// NormalizeIgnoreRule validates and normalizes an IgnoreRule, generating a deterministic ID when omitted.
func NormalizeIgnoreRule(in IgnoreRule) (IgnoreRule, error) {
	scope := strings.ToLower(strings.TrimSpace(in.Scope))
	if scope == "" {
		hasMAC := strings.TrimSpace(in.MAC) != ""
		hasType := strings.TrimSpace(in.LeakType) != ""
		switch {
		case hasMAC && hasType:
			scope = ScopeDeviceHostType
		case hasType:
			scope = ScopeHostType
		default:
			scope = ScopeHost
		}
	}
	if scope != ScopeHostType && scope != ScopeHost && scope != ScopeDeviceHostType {
		return IgnoreRule{}, errors.New("scope must be host_type|host|device_host_type")
	}

	_, normHost, err := ValidateIgnoreTarget(in.DstHost)
	if err != nil {
		return IgnoreRule{}, err
	}

	var normType string
	var normMAC string
	switch scope {
	case ScopeHost:
		normType = ""
		normMAC = ""
	case ScopeHostType:
		lt, ok := CanonicalIgnoreLeakType(in.LeakType)
		if !ok {
			return IgnoreRule{}, errors.New("valid leak_type is required for scope=host_type")
		}
		normType = lt
		normMAC = ""
	case ScopeDeviceHostType:
		lt, ok := CanonicalIgnoreLeakType(in.LeakType)
		if !ok {
			return IgnoreRule{}, errors.New("valid leak_type is required for scope=device_host_type")
		}
		m := normalizeValidMAC(in.MAC)
		if m == "" {
			return IgnoreRule{}, errors.New("valid device mac is required for scope=device_host_type")
		}
		normType = lt
		normMAC = m
	}

	note := strings.TrimSpace(in.Note)
	if len([]rune(note)) > 80 {
		note = string([]rune(note)[:80])
	}
	createdAt := in.CreatedAt
	if createdAt <= 0 {
		createdAt = time.Now().Unix()
	}
	sum := sha1.Sum([]byte(scope + "|" + normMAC + "|" + normHost + "|" + normType))
	id := strings.TrimSpace(in.ID)
	if id == "" {
		id = "ig_" + hex.EncodeToString(sum[:8])
	}
	return IgnoreRule{
		ID:        id,
		Scope:     scope,
		DstHost:   normHost,
		LeakType:  normType,
		MAC:       normMAC,
		Note:      note,
		CreatedAt: createdAt,
	}, nil
}

// UniqueKey returns the canonical deduplication key for r.
func (r IgnoreRule) UniqueKey() string {
	return r.Scope + "|" + r.MAC + "|" + r.DstHost + "|" + r.LeakType
}

// MatchesEvent reports whether ev matches the ignore whitelist rule r.
func (r IgnoreRule) MatchesEvent(ev LeakEvent) bool {
	if r.DstHost == "" {
		return false
	}
	if r.Scope == ScopeDeviceHostType {
		if r.MAC == "" || normalizeValidMAC(ev.MAC) != r.MAC {
			return false
		}
	}
	if r.Scope == ScopeHostType || r.Scope == ScopeDeviceHostType {
		evCanon, ok := CanonicalIgnoreLeakType(ev.LeakType)
		if !ok {
			evCanon = strings.ToUpper(strings.TrimSpace(ev.LeakType))
		}
		if r.LeakType == "" || (evCanon != r.LeakType && !strings.EqualFold(ev.LeakType, r.LeakType)) {
			return false
		}
	}

	evHost := stripPortFromHost(ev.DstHost)
	evIP := strings.TrimSpace(ev.DstIP)
	if addr, err := netip.ParseAddr(r.DstHost); err == nil {
		normRuleIP := addr.Unmap().String()
		if a1, e1 := netip.ParseAddr(evHost); e1 == nil && a1.Unmap().String() == normRuleIP {
			return true
		}
		if a2, e2 := netip.ParseAddr(evIP); e2 == nil && a2.Unmap().String() == normRuleIP {
			return true
		}
		return false
	}
	if evHost == "" {
		return false
	}
	return evHost == r.DstHost || strings.HasSuffix(evHost, "."+r.DstHost)
}

func sanitizeIgnoreRuleSlice(in []IgnoreRule) []IgnoreRule {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]IgnoreRule, 0, len(in))
	for _, raw := range in {
		nr, err := NormalizeIgnoreRule(raw)
		if err != nil {
			continue
		}
		uk := nr.UniqueKey()
		if _, dup := seen[uk]; dup {
			continue
		}
		seen[uk] = struct{}{}
		out = append(out, nr)
		if len(out) >= MaxIgnoreRules {
			break
		}
	}
	return out
}

// EventsSnapshot is the volatile tmpfs mirror at run/leakguard_events.json
// consumed by daemon/hnc_httpd.
type EventsSnapshot struct {
	UpdatedAt      int64       `json:"updated_at"`
	Enabled        bool        `json:"enabled"`
	Capacity       int         `json:"capacity"`
	CooldownSec    int         `json:"cooldown_sec"`
	TotalLeaks     uint64      `json:"total_leaks"`
	IgnoredCount   uint64      `json:"ignored_count,omitempty"`
	UniqueEvents   int         `json:"unique_events"`
	SubmittedPkts  uint64      `json:"submitted_packets"`
	ScannedPkts    uint64      `json:"scanned_packets"`
	DroppedCount   uint64      `json:"dropped_count"`
	ClearSeq       int64       `json:"clear_seq,omitempty"`
	BlockedDomains []string    `json:"blocked_domains,omitempty"`
	Events         []LeakEvent `json:"events"`
}

// ControlState is the dynamic control channel at run/leakguard_ctrl.json
// written by daemon/hnc_httpd and synced dynamically by dpid's LeakGuard Engine.
type ControlState struct {
	Enabled        *bool           `json:"enabled,omitempty"`
	Capacity       int             `json:"capacity,omitempty"`
	CooldownSec    int             `json:"cooldown_sec,omitempty"`
	NotifyEnabled  *bool           `json:"notify_enabled,omitempty"`
	LockscreenMask *bool           `json:"lockscreen_mask,omitempty"`
	ClearSeq       int64           `json:"clear_seq,omitempty"`
	ClearedAt      int64           `json:"cleared_at,omitempty"`
	BlockedDomains []string        `json:"blocked_domains,omitempty"`
	BlockedTargets map[string]bool `json:"blocked_targets,omitempty"`
	IgnoreRules    []IgnoreRule    `json:"ignore_rules,omitempty"`
	UpdatedAt      int64           `json:"updated_at,omitempty"`
}

// EventsPath returns filepath.Join(runDir, "leakguard_events.json").
func EventsPath(runDir string) string {
	if strings.TrimSpace(runDir) == "" {
		runDir = DefaultRunDir
	}
	return filepath.Join(runDir, EventsFileName)
}

// CtrlPath returns filepath.Join(runDir, "leakguard_ctrl.json").
func CtrlPath(runDir string) string {
	if strings.TrimSpace(runDir) == "" {
		runDir = DefaultRunDir
	}
	return filepath.Join(runDir, CtrlFileName)
}

// WriteEvents atomically writes snap to runDir/leakguard_events.json (tmpfs, mode 0600).
func WriteEvents(runDir string, snap EventsSnapshot) error {
	if snap.Events == nil {
		snap.Events = []LeakEvent{}
	}
	if snap.UpdatedAt <= 0 {
		snap.UpdatedAt = time.Now().Unix()
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return writeTmpfsAtomic(EventsPath(runDir), b)
}

// ReadEvents loads runDir/leakguard_events.json; missing file returns an empty
// default snapshot without error so cold-start WebUI queries stay clean.
func ReadEvents(runDir string) (EventsSnapshot, error) {
	b, err := os.ReadFile(EventsPath(runDir))
	if err != nil {
		if os.IsNotExist(err) {
			return EventsSnapshot{
				Enabled:     true,
				Capacity:    DefaultCapacity,
				CooldownSec: DefaultCooldownSec,
				Events:      []LeakEvent{},
			}, nil
		}
		return EventsSnapshot{}, err
	}
	var snap EventsSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return EventsSnapshot{}, err
	}
	if snap.Events == nil {
		snap.Events = []LeakEvent{}
	}
	return snap, nil
}

// ReadControl reads runDir/leakguard_ctrl.json (and merges blocked_targets / ignore_rules
// from ../data/leakguard_config.json while honoring false tombstones so unblocked domains
// never resurrect).
func ReadControl(runDir string) (ControlState, error) {
	if strings.TrimSpace(runDir) == "" {
		runDir = DefaultRunDir
	}
	var ctrl ControlState
	hasCtrlIgnore := false
	b, err := os.ReadFile(CtrlPath(runDir))
	if err != nil && !os.IsNotExist(err) {
		return ControlState{}, err
	}
	if len(b) > 0 {
		if uerr := json.Unmarshal(b, &ctrl); uerr != nil {
			return ControlState{}, uerr
		}
		var rawKeys map[string]json.RawMessage
		if json.Unmarshal(b, &rawKeys) == nil {
			_, hasCtrlIgnore = rawKeys["ignore_rules"]
		}
	}

	tombstones := make(map[string]bool)
	for tgt, active := range ctrl.BlockedTargets {
		d := normalizeDomain(tgt)
		if d != "" && !active {
			tombstones[d] = true
		}
	}

	var merged []string
	for _, raw := range ctrl.BlockedDomains {
		d := normalizeDomain(raw)
		if d != "" && !tombstones[d] {
			merged = append(merged, d)
		}
	}
	for tgt, active := range ctrl.BlockedTargets {
		d := normalizeDomain(tgt)
		if active && d != "" && !tombstones[d] {
			merged = append(merged, d)
		}
	}

	// Absorb hnc_httpd persisted blocked_targets and cold-start ignore_rules from ../data/leakguard_config.json,
	// strictly skipping any target marked with a false tombstone in leakguard_ctrl.json.
	persistPath := filepath.Join(filepath.Dir(filepath.Clean(runDir)), "data", "leakguard_config.json")
	if pb, perr := os.ReadFile(persistPath); perr == nil && len(pb) > 0 {
		var persisted struct {
			BlockedTargets map[string]bool `json:"blocked_targets"`
			IgnoreRules    []IgnoreRule    `json:"ignore_rules"`
		}
		if json.Unmarshal(pb, &persisted) == nil {
			for tgt, active := range persisted.BlockedTargets {
				d := normalizeDomain(tgt)
				if d == "" {
					continue
				}
				if !active {
					tombstones[d] = true
					continue
				}
				if !tombstones[d] {
					merged = append(merged, d)
				}
			}
			if !hasCtrlIgnore && len(ctrl.IgnoreRules) == 0 && len(persisted.IgnoreRules) > 0 {
				ctrl.IgnoreRules = persisted.IgnoreRules
			}
		}
	}
	if len(tombstones) > 0 && len(merged) > 0 {
		filtered := merged[:0]
		for _, item := range merged {
			if !tombstones[normalizeDomain(item)] {
				filtered = append(filtered, item)
			}
		}
		merged = filtered
	}
	ctrl.BlockedDomains = normalizeDomainSlice(merged)
	ctrl.IgnoreRules = sanitizeIgnoreRuleSlice(ctrl.IgnoreRules)
	return ctrl, nil
}

// WriteControl atomically persists ctrl to runDir/leakguard_ctrl.json (mode 0600).
func WriteControl(runDir string, ctrl ControlState) error {
	ctrl.BlockedDomains = normalizeDomainSlice(ctrl.BlockedDomains)
	ctrl.IgnoreRules = sanitizeIgnoreRuleSlice(ctrl.IgnoreRules)
	if ctrl.UpdatedAt <= 0 {
		ctrl.UpdatedAt = time.Now().Unix()
	}
	b, err := json.Marshal(ctrl)
	if err != nil {
		return err
	}
	return writeTmpfsAtomic(CtrlPath(runDir), b)
}

// UpdateControl performs a cross-process flock-serialized read-modify-write on
// runDir/leakguard_ctrl.json for hnc_httpd control endpoints.
func UpdateControl(runDir string, mutate func(*ControlState)) (ControlState, error) {
	ctrlUpdateMu.Lock()
	defer ctrlUpdateMu.Unlock()

	if strings.TrimSpace(runDir) == "" {
		runDir = DefaultRunDir
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return ControlState{}, err
	}

	lockPath := CtrlPath(runDir) + ".lock"
	lf, lerr := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if lerr == nil {
		_ = lf.Chmod(0o600)
		_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_EX)
		defer func() {
			_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
			_ = lf.Close()
		}()
	}

	cur, _ := ReadControl(runDir)
	if mutate != nil {
		mutate(&cur)
	}
	cur.UpdatedAt = time.Now().Unix()
	if err := WriteControl(runDir, cur); err != nil {
		return ControlState{}, err
	}
	return cur, nil
}

// RequestClear issues an atomic clear signal via leakguard_ctrl.json.
func RequestClear(runDir string) (ControlState, error) {
	return UpdateControl(runDir, func(c *ControlState) {
		now := time.Now().Unix()
		next := c.ClearSeq + 1
		if next <= 0 {
			next = 1
		}
		c.ClearSeq = next
		c.ClearedAt = now
	})
}

// AddBlockedDomain adds a domain (or IP) to the LeakGuard blocklist in leakguard_ctrl.json.
func AddBlockedDomain(runDir, domain string) (ControlState, error) {
	d := normalizeDomain(domain)
	if d == "" {
		return ReadControl(runDir)
	}
	return UpdateControl(runDir, func(c *ControlState) {
		if c.BlockedTargets == nil {
			c.BlockedTargets = make(map[string]bool)
		}
		c.BlockedTargets[d] = true
		c.BlockedDomains = append(c.BlockedDomains, d)
		c.BlockedDomains = normalizeDomainSlice(c.BlockedDomains)
	})
}

// RemoveBlockedDomain removes a domain from the LeakGuard blocklist in leakguard_ctrl.json
// and records a false tombstone in BlockedTargets so ../data/leakguard_config.json cannot resurrect it.
func RemoveBlockedDomain(runDir, domain string) (ControlState, error) {
	d := normalizeDomain(domain)
	if d == "" {
		return ReadControl(runDir)
	}
	return UpdateControl(runDir, func(c *ControlState) {
		if c.BlockedTargets == nil {
			c.BlockedTargets = make(map[string]bool)
		}
		c.BlockedTargets[d] = false
		filtered := make([]string, 0, len(c.BlockedDomains))
		for _, item := range c.BlockedDomains {
			if normalizeDomain(item) != d {
				filtered = append(filtered, item)
			}
		}
		c.BlockedDomains = normalizeDomainSlice(filtered)
	})
}

func normalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	return s
}

func normalizeDomainSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		d := normalizeDomain(raw)
		if d == "" {
			continue
		}
		if _, exists := seen[d]; !exists {
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

func writeTmpfsAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d.%d", path, os.Getpid(), ipcWriteSeq.Add(1))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_ = f.Chmod(0o600)
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
