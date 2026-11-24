package leakguard

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	DefaultCapacity    = 300
	MinCapacity        = 10
	MaxCapacity        = 2000
	DefaultCooldownSec = 300

	TypePhone      = "PHONE"
	TypeDeviceID   = "DEVICE_ID"
	TypeGPS        = "GPS"
	TypeMACAddr    = "MAC_ADDR"
	TypeCredential = "CREDENTIAL"
	TypeIDCard     = "ID_CARD"

	OriginHotspot = "hotspot"
	OriginHost    = "host"
)

// LeakEvent represents a single cleartext privacy leak event (or aggregated
// cooldown burst). RawValue and RawSnippet preserve complete unmasked plaintext.
type LeakEvent struct {
	ID         string `json:"id"`
	FirstSeen  int64  `json:"first_seen"`
	LastSeen   int64  `json:"last_seen"`
	Ts         int64  `json:"ts"`
	Origin     string `json:"origin,omitempty"`
	UID        int    `json:"uid,omitempty"`
	Pkg        string `json:"pkg,omitempty"`
	AppName    string `json:"app_name,omitempty"`
	MAC        string `json:"mac"`
	ClientIP   string `json:"client_ip,omitempty"`
	SrcIP      string `json:"src_ip,omitempty"`
	DstIP      string `json:"dst_ip,omitempty"`
	DstPort    uint16 `json:"dst_port,omitempty"`
	DstHost    string `json:"dst_host"`
	Proto      string `json:"proto,omitempty"`
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	LeakType   string `json:"leak_type"`
	LeakLabel  string `json:"leak_label,omitempty"`
	FieldKey   string `json:"field_key,omitempty"`
	RawValue   string `json:"raw_value"`
	RawSnippet string `json:"raw_snippet"`
	HitCount   uint64 `json:"hit_count"`
	Blocked    bool   `json:"blocked,omitempty"`
	IsBlocked  bool   `json:"is_blocked,omitempty"`
}

func defaultLabelForType(leakType string) string {
	switch leakType {
	case TypePhone:
		return "手机号"
	case TypeDeviceID:
		return "设备唯一标识"
	case TypeGPS:
		return "精准定位坐标"
	case TypeMACAddr:
		return "硬件 MAC 地址"
	case TypeCredential:
		return "账号凭据/Token"
	case TypeIDCard:
		return "身份证号"
	default:
		return leakType
	}
}

// RingBuffer stores up to cap LeakEvents in memory with per-(mac, dst_host,
// leak_type, raw_value) cooldown window deduplication and hit_count aggregation.
type RingBuffer struct {
	mu          sync.RWMutex
	buf         []LeakEvent
	head        int // index of oldest element when count > 0
	count       int
	cap         int
	cooldownSec int
	seq         uint64
}

// NewRingBuffer creates an in-memory LeakGuard ring buffer.
func NewRingBuffer(capacity, cooldownSec int) *RingBuffer {
	capacity = clampCapacity(capacity)
	if cooldownSec < 0 {
		cooldownSec = DefaultCooldownSec
	}
	return &RingBuffer{
		buf:         make([]LeakEvent, capacity),
		cap:         capacity,
		cooldownSec: cooldownSec,
	}
}

func clampCapacity(c int) int {
	if c <= 0 {
		return DefaultCapacity
	}
	if c < MinCapacity {
		return MinCapacity
	}
	if c > MaxCapacity {
		return MaxCapacity
	}
	return c
}

// Capacity returns the current ring buffer capacity.
func (r *RingBuffer) Capacity() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cap
}

// CooldownSec returns the active deduplication cooldown window in seconds.
func (r *RingBuffer) CooldownSec() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cooldownSec
}

// Len returns the number of stored aggregated events.
func (r *RingBuffer) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count
}

// SetCooldownSec dynamically updates the aggregation cooldown window in seconds.
func (r *RingBuffer) SetCooldownSec(sec int) {
	if sec < 0 {
		return
	}
	r.mu.Lock()
	r.cooldownSec = sec
	r.mu.Unlock()
}

// Resize dynamically adjusts ring capacity while retaining the newest entries.
func (r *RingBuffer) Resize(newCap int) {
	newCap = clampCapacity(newCap)
	r.mu.Lock()
	defer r.mu.Unlock()
	if newCap == r.cap {
		return
	}
	nextBuf := make([]LeakEvent, newCap)
	keep := r.count
	if keep > newCap {
		keep = newCap
	}
	startLogical := r.count - keep
	for i := 0; i < keep; i++ {
		phys := (r.head + startLogical + i) % r.cap
		nextBuf[i] = r.buf[phys]
	}
	r.buf = nextBuf
	r.head = 0
	r.count = keep
	r.cap = newCap
}

// Clear removes all events from memory.
func (r *RingBuffer) Clear() {
	r.mu.Lock()
	clear(r.buf)
	r.head = 0
	r.count = 0
	r.mu.Unlock()
}

func canonicalOrigin(o string) string {
	if strings.EqualFold(strings.TrimSpace(o), OriginHost) {
		return OriginHost
	}
	return OriginHotspot
}

func sameEventSubject(a, b LeakEvent) bool {
	oa := canonicalOrigin(a.Origin)
	ob := canonicalOrigin(b.Origin)
	if oa != ob {
		return false
	}
	if oa == OriginHost && a.MAC == "" && b.MAC == "" {
		return a.UID == b.UID && a.Pkg == b.Pkg
	}
	return a.MAC == b.MAC
}

// Record inserts or aggregates ev using (mac + dst_host + leak_type + raw_value)
// for hotspot traffic or (uid/pkg + dst_host + leak_type + raw_value) for host
// traffic when MAC is empty, over the configured cooldown window.
// Returns the updated event and isNewAlert.
func (r *RingBuffer) Record(ev LeakEvent, now time.Time) (LeakEvent, bool) {
	nowUnix := now.Unix()
	if nowUnix <= 0 {
		nowUnix = time.Now().Unix()
	}
	switch strings.ToLower(strings.TrimSpace(ev.Origin)) {
	case OriginHost:
		ev.Origin = OriginHost
	case OriginHotspot:
		ev.Origin = OriginHotspot
	default:
		ev.Origin = ""
	}
	ev.Pkg = strings.TrimSpace(ev.Pkg)
	ev.AppName = strings.TrimSpace(ev.AppName)
	ev.MAC = strings.ToLower(strings.TrimSpace(ev.MAC))
	if ev.SrcIP == "" && ev.ClientIP != "" {
		ev.SrcIP = ev.ClientIP
	} else if ev.ClientIP == "" && ev.SrcIP != "" {
		ev.ClientIP = ev.SrcIP
	}
	ev.DstHost = strings.ToLower(strings.TrimSpace(ev.DstHost))
	if ev.DstHost == "" {
		ev.DstHost = strings.TrimSpace(ev.DstIP)
	}
	if ev.Proto == "" {
		ev.Proto = "http"
	}
	if ev.LeakLabel == "" {
		ev.LeakLabel = defaultLabelForType(ev.LeakType)
	}
	ev.IsBlocked = ev.Blocked
	inc := ev.HitCount
	if inc == 0 {
		inc = 1
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	window := int64(r.cooldownSec)
	if window > 0 {
		for i := r.count - 1; i >= 0; i-- {
			phys := (r.head + i) % r.cap
			cur := &r.buf[phys]
			if cur.LeakType == ev.LeakType &&
				sameEventSubject(*cur, ev) &&
				cur.DstHost == ev.DstHost &&
				sameRawValueForType(ev.LeakType, cur.RawValue, ev.RawValue) {
				dt := nowUnix - cur.LastSeen
				if dt < window && dt >= -5 {
					cur.HitCount += inc
					if nowUnix > cur.LastSeen {
						cur.LastSeen = nowUnix
						cur.Ts = nowUnix
					}
					if ev.Origin != "" {
						cur.Origin = ev.Origin
					}
					if ev.UID > 0 {
						cur.UID = ev.UID
					}
					if ev.Pkg != "" {
						cur.Pkg = ev.Pkg
					}
					if ev.AppName != "" {
						cur.AppName = ev.AppName
					}
					if ev.RawSnippet != "" {
						cur.RawSnippet = ev.RawSnippet
					}
					if ev.Path != "" {
						cur.Path = ev.Path
					}
					if ev.Method != "" {
						cur.Method = ev.Method
					}
					if ev.ClientIP != "" {
						cur.ClientIP = ev.ClientIP
						cur.SrcIP = ev.ClientIP
					}
					if ev.DstIP != "" {
						cur.DstIP = ev.DstIP
					}
					if ev.DstPort != 0 {
						cur.DstPort = ev.DstPort
					}
					if ev.UserAgent != "" {
						cur.UserAgent = ev.UserAgent
					}
					if ev.FieldKey != "" {
						cur.FieldKey = ev.FieldKey
					}
					cur.Blocked = ev.Blocked
					cur.IsBlocked = ev.Blocked
					return *cur, false
				}
				break
			}
		}
	}

	r.seq++
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("lg_%d_%d", nowUnix, r.seq)
	}
	ev.FirstSeen = nowUnix
	ev.LastSeen = nowUnix
	ev.Ts = nowUnix
	ev.HitCount = inc

	if r.count < r.cap {
		idx := (r.head + r.count) % r.cap
		r.buf[idx] = ev
		r.count++
	} else {
		r.buf[r.head] = ev
		r.head = (r.head + 1) % r.cap
	}
	return ev, true
}

// MarkBlockedDomains updates Blocked and IsBlocked badges on buffered events.
func (r *RingBuffer) MarkBlockedDomains(isBlocked func(host string) bool) bool {
	if isBlocked == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	for i := 0; i < r.count; i++ {
		phys := (r.head + i) % r.cap
		b := isBlocked(r.buf[phys].DstHost)
		if r.buf[phys].Blocked != b || r.buf[phys].IsBlocked != b {
			r.buf[phys].Blocked = b
			r.buf[phys].IsBlocked = b
			changed = true
		}
	}
	return changed
}

// PurgeIgnored removes buffered LeakEvents matching shouldIgnore in-place while
// preserving chronological order of remaining entries. Returns evicted count.
func (r *RingBuffer) PurgeIgnored(shouldIgnore func(LeakEvent) bool) int {
	if r == nil || shouldIgnore == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count == 0 {
		return 0
	}
	nextBuf := make([]LeakEvent, r.cap)
	kept := 0
	purged := 0
	for i := 0; i < r.count; i++ {
		phys := (r.head + i) % r.cap
		ev := r.buf[phys]
		if shouldIgnore(ev) {
			purged++
			continue
		}
		nextBuf[kept] = ev
		kept++
	}
	if purged > 0 {
		r.buf = nextBuf
		r.head = 0
		r.count = kept
	}
	return purged
}

// Snapshot returns a copy of all buffered events ordered newest-first.
func (r *RingBuffer) Snapshot() []LeakEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]LeakEvent, r.count)
	for i := 0; i < r.count; i++ {
		phys := (r.head + r.count - 1 - i) % r.cap
		out[i] = r.buf[phys]
	}
	return out
}

// SnapshotChronological returns buffered events ordered oldest-first for incremental tailing.
func (r *RingBuffer) SnapshotChronological() []LeakEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]LeakEvent, r.count)
	for i := 0; i < r.count; i++ {
		phys := (r.head + i) % r.cap
		out[i] = r.buf[phys]
	}
	return out
}

func sameRawValueForType(leakType, a, b string) bool {
	switch leakType {
	case TypeMACAddr:
		return normalizeMACCompare(a) == normalizeMACCompare(b)
	case TypeIDCard:
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	default:
		return a == b
	}
}

func normalizeMACCompare(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "-", ":")
}
