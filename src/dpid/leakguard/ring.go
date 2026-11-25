package leakguard

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultCapacity     = 300
	MinCapacity         = 10
	MaxCapacity         = 2000
	DefaultCooldownSec  = 300
	crossIfaceMergeSec  = 5

	TypePhone      = "PHONE"
	TypeDeviceID   = "DEVICE_ID"
	TypeGPS        = "GPS"
	TypeMACAddr    = "MAC_ADDR"
	TypeCredential = "CREDENTIAL"
	TypeIDCard     = "ID_CARD"

	OriginHotspot = "hotspot"
	OriginHost    = "host"
)

var builtinProxyConduitPkgs = map[string]struct{}{
	"com.follow.clash":                     {},
	"com.github.kr328.clash":               {},
	"com.github.metacubex.clash.meta":      {},
	"com.v2ray.ang":                        {},
	"com.v2ray.actinium":                   {},
	"io.nekohasekai.sfa":                   {},
	"io.nekohasekai.sagernet":              {},
	"moe.nb4a":                             {},
	"moe.matsuri.lite":                     {},
	"com.github.shadowsocks":               {},
	"io.github.trojan_gfw.igniter":         {},
	"com.getsurfboard":                     {},
	"com.hiddify.hiddify":                  {},
	"app.hiddify.com":                      {},
	"com.wireguard.android":                {},
	"net.openvpn.openvpn":                  {},
	"de.blinkt.openvpn":                    {},
	"org.torproject.android":               {},
	"com.tailscale.ipn":                    {},
	"net.mullvad.mullvadvpn":               {},
	"org.outline.android.client":           {},
	"ch.protonvpn.android":                 {},
	"com.nordvpn.android":                  {},
	"com.expressvpn.vpn":                   {},
	"com.windscribe.vpn":                   {},
	"com.surfshark.vpnclient.android":      {},
	"com.cloudflare.onedotonedotonedotone": {},
	"eu.faircode.netguard":                 {},
	"com.celzero.bravedns":                 {},
	"com.adguard.android":                  {},
}

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
	SrcPort    uint16 `json:"src_port,omitempty"`
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
	mu           sync.RWMutex
	buf          []LeakEvent
	head         int // index of oldest element when count > 0
	count        int
	cap          int
	cooldownSec  int
	seq          uint64
	conduitCheck atomic.Pointer[func(uid int, pkg string) bool]
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

// SetConduitCheck registers an optional callback reporting whether (uid, pkg)
// belongs to a local VPN/proxy conduit app (e.g. user-configured flywheel_exclude.json).
func (r *RingBuffer) SetConduitCheck(fn func(uid int, pkg string) bool) {
	if r == nil {
		return
	}
	if fn == nil {
		r.conduitCheck.Store(nil)
		return
	}
	r.conduitCheck.Store(&fn)
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

func isHostNoMAC(e LeakEvent) bool {
	return canonicalOrigin(e.Origin) == OriginHost && e.MAC == ""
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

func (r *RingBuffer) isProxyConduit(uid int, pkg string) bool {
	normPkg := strings.ToLower(strings.TrimSpace(pkg))
	if normPkg != "" {
		if _, ok := builtinProxyConduitPkgs[normPkg]; ok {
			return true
		}
	}
	if r != nil {
		if fn := r.conduitCheck.Load(); fn != nil && *fn != nil {
			return (*fn)(uid, normPkg)
		}
	}
	return false
}

// hostIdentityRank scores host attribution quality:
//   2 = real business app (UID > 0 and not a VPN/proxy conduit)
//   1 = VPN/proxy conduit app (UID > 0 on conduit list)
//   0 = unattributed / unknown (UID <= 0)
func (r *RingBuffer) hostIdentityRank(e LeakEvent) int {
	if e.UID <= 0 {
		return 0
	}
	if r.isProxyConduit(e.UID, e.Pkg) {
		return 1
	}
	return 2
}

func (r *RingBuffer) isUnattributedOrConduit(e LeakEvent) bool {
	return r.hostIdentityRank(e) < 2
}

func isFakeIPBenchmarkStr(ipStr string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	b4 := addr.As4()
	return b4[0] == 198 && (b4[1] == 18 || b4[1] == 19)
}

func (r *RingBuffer) mergeCrossIfaceHostLocked(cur *LeakEvent, ev LeakEvent, nowUnix int64) {
	if nowUnix > cur.LastSeen {
		cur.LastSeen = nowUnix
		cur.Ts = nowUnix
	}
	curRank := r.hostIdentityRank(*cur)
	evRank := r.hostIdentityRank(ev)

	if evRank > curRank {
		cur.UID = ev.UID
		cur.Pkg = ev.Pkg
		cur.AppName = ev.AppName
		if ev.SrcPort != 0 {
			cur.SrcPort = ev.SrcPort
		}
		if ev.ClientIP != "" {
			cur.ClientIP = ev.ClientIP
			cur.SrcIP = ev.ClientIP
		}
	} else if evRank == curRank {
		if cur.UID <= 0 && ev.UID > 0 {
			cur.UID = ev.UID
		}
		if cur.Pkg == "" && ev.Pkg != "" {
			cur.Pkg = ev.Pkg
		}
		if cur.AppName == "" && ev.AppName != "" {
			cur.AppName = ev.AppName
		}
		if cur.SrcPort == 0 && ev.SrcPort != 0 {
			cur.SrcPort = ev.SrcPort
		}
	}

	if ev.DstIP != "" && (cur.DstIP == "" || (isFakeIPBenchmarkStr(cur.DstIP) && !isFakeIPBenchmarkStr(ev.DstIP))) {
		cur.DstIP = ev.DstIP
	}
	if cur.DstPort == 0 && ev.DstPort != 0 {
		cur.DstPort = ev.DstPort
	}
	if cur.RawSnippet == "" && ev.RawSnippet != "" {
		cur.RawSnippet = ev.RawSnippet
	}
	if cur.Path == "" && ev.Path != "" {
		cur.Path = ev.Path
	}
	if cur.Method == "" && ev.Method != "" {
		cur.Method = ev.Method
	}
	if cur.UserAgent == "" && ev.UserAgent != "" {
		cur.UserAgent = ev.UserAgent
	}
	if cur.FieldKey == "" && ev.FieldKey != "" {
		cur.FieldKey = ev.FieldKey
	}
	if ev.Blocked {
		cur.Blocked = true
		cur.IsBlocked = true
	}
}

func (r *RingBuffer) foldUpgradedHostSlotLocked(slotIdx int, nowUnix int64) (LeakEvent, bool) {
	window := int64(r.cooldownSec)
	if window <= 0 || slotIdx < 0 || slotIdx >= r.count {
		return LeakEvent{}, false
	}
	upgraded := r.buf[(r.head+slotIdx)%r.cap]
	if r.hostIdentityRank(upgraded) != 2 {
		return LeakEvent{}, false
	}
	for j := r.count - 1; j >= 0; j-- {
		if j == slotIdx {
			continue
		}
		older := &r.buf[(r.head+j)%r.cap]
		if older.LeakType != upgraded.LeakType ||
			older.DstHost != upgraded.DstHost ||
			!sameRawValueForType(upgraded.LeakType, older.RawValue, upgraded.RawValue) {
			continue
		}
		if !sameEventSubject(*older, upgraded) || r.hostIdentityRank(*older) != 2 {
			continue
		}
		dt := nowUnix - older.LastSeen
		if dt < window && dt >= -5 {
			older.HitCount += upgraded.HitCount
			if upgraded.FirstSeen > 0 && (older.FirstSeen == 0 || upgraded.FirstSeen < older.FirstSeen) {
				older.FirstSeen = upgraded.FirstSeen
			}
			if upgraded.LastSeen > older.LastSeen {
				older.LastSeen = upgraded.LastSeen
				older.Ts = upgraded.LastSeen
			}
			if nowUnix > older.LastSeen {
				older.LastSeen = nowUnix
				older.Ts = nowUnix
			}
			if upgraded.Origin != "" {
				older.Origin = upgraded.Origin
			}
			if upgraded.UID > 0 {
				older.UID = upgraded.UID
			}
			if upgraded.Pkg != "" {
				older.Pkg = upgraded.Pkg
			}
			if upgraded.AppName != "" {
				older.AppName = upgraded.AppName
			}
			if upgraded.RawSnippet != "" {
				older.RawSnippet = upgraded.RawSnippet
			}
			if upgraded.Path != "" {
				older.Path = upgraded.Path
			}
			if upgraded.Method != "" {
				older.Method = upgraded.Method
			}
			if upgraded.ClientIP != "" {
				older.ClientIP = upgraded.ClientIP
				older.SrcIP = upgraded.ClientIP
			}
			if upgraded.DstIP != "" && (older.DstIP == "" || !isFakeIPBenchmarkStr(upgraded.DstIP) || isFakeIPBenchmarkStr(older.DstIP)) {
				older.DstIP = upgraded.DstIP
			}
			if upgraded.SrcPort != 0 {
				older.SrcPort = upgraded.SrcPort
			}
			if upgraded.DstPort != 0 {
				older.DstPort = upgraded.DstPort
			}
			if upgraded.UserAgent != "" {
				older.UserAgent = upgraded.UserAgent
			}
			if upgraded.FieldKey != "" {
				older.FieldKey = upgraded.FieldKey
			}
			older.Blocked = upgraded.Blocked
			older.IsBlocked = upgraded.Blocked
			folded := *older
			r.removeLogicalSlotLocked(slotIdx)
			return folded, true
		}
		break
	}
	return LeakEvent{}, false
}

func (r *RingBuffer) removeLogicalSlotLocked(slotIdx int) {
	if slotIdx < 0 || slotIdx >= r.count {
		return
	}
	for k := slotIdx; k < r.count-1; k++ {
		dstPhys := (r.head + k) % r.cap
		srcPhys := (r.head + k + 1) % r.cap
		r.buf[dstPhys] = r.buf[srcPhys]
	}
	lastPhys := (r.head + r.count - 1) % r.cap
	r.buf[lastPhys] = LeakEvent{}
	r.count--
	if r.count == 0 {
		r.head = 0
	}
}

// Record inserts or aggregates ev using (mac + dst_host + leak_type + raw_value)
// for hotspot traffic or (uid/pkg + dst_host + leak_type + raw_value) for host
// traffic when MAC is empty, over the configured cooldown window.
// Cross-interface host duplicates within <5s where at least one side is UID<=0 or
// a VPN/proxy conduit UID are merged onto the real business app without inflating HitCount.
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
	for i := r.count - 1; i >= 0; i-- {
		phys := (r.head + i) % r.cap
		cur := &r.buf[phys]
		if cur.LeakType != ev.LeakType ||
			cur.DstHost != ev.DstHost ||
			!sameRawValueForType(ev.LeakType, cur.RawValue, ev.RawValue) {
			continue
		}

		dt := nowUnix - cur.LastSeen
		sameSubj := sameEventSubject(*cur, ev)

		// Cross-interface host merge (<5s): tun/Meta + physical wlan/rmnet double-capture
		// where at least one side has UID<=0 or belongs to a VPN/proxy conduit app.
		// Never merges two distinct real business apps (both rank == 2).
		if isHostNoMAC(*cur) && isHostNoMAC(ev) && dt > -crossIfaceMergeSec && dt < crossIfaceMergeSec {
			if (!sameSubj && (r.isUnattributedOrConduit(*cur) || r.isUnattributedOrConduit(ev))) ||
				(sameSubj && r.isUnattributedOrConduit(*cur) &&
					cur.ClientIP != "" && ev.ClientIP != "" && cur.ClientIP != ev.ClientIP) {
				prevRank := r.hostIdentityRank(*cur)
				r.mergeCrossIfaceHostLocked(cur, ev, nowUnix)
				if prevRank < 2 && r.hostIdentityRank(*cur) == 2 {
					if folded, ok := r.foldUpgradedHostSlotLocked(i, nowUnix); ok {
						return folded, false
					}
				}
				return *cur, false
			}
		}

		if sameSubj && window > 0 {
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
				if ev.SrcPort != 0 {
					cur.SrcPort = ev.SrcPort
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
