package leakguard

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	DefaultQueueCap      = 256
	MaxPacketSnap        = 4096
	MaxDecompressedBytes = 16384
	SnippetRadiusBytes   = 80
	maxKnownMACs         = 512
)

var (
	phoneValRe        = regexp.MustCompile(`^(?:\+?86[- ]?)?(1[3-9]\d{9})$`)
	macTokenRe        = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|(?:[0-9a-f]{2}-){5}[0-9a-f]{2}`)
	coordValRe        = regexp.MustCompile(`^[+-]?\d{1,3}\.\d{4,12}$`)
	jwtTokenRe        = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}`)
	idCardKeyRe       = regexp.MustCompile(`(?i)(id_?card|id_?no|cert_?no|sfz|identity)`)
	idCardCandidateRe = regexp.MustCompile(`[1-9]\d{16}[0-9Xx]`)
)

// PacketInput describes a captured cleartext HTTP request fed into LeakGuard.
type PacketInput struct {
	Time       time.Time
	Origin     string
	UID        int
	Pkg        string
	AppName    string
	ClientMAC  string
	ClientIP   string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	Method     string
	Path       string
	DstHost    string
	UserAgent  string
	RawPayload []byte
}

type packetJob struct {
	ts        time.Time
	origin    string
	uid       int
	pkg       string
	appName   string
	clientMAC string
	clientIP  string
	dstIP     string
	srcPort   uint16
	dstPort   uint16
	method    string
	path      string
	dstHost   string
	userAgent string
	rawLen    int
	raw       [MaxPacketSnap]byte
}

var jobPool = sync.Pool{
	New: func() any {
		return &packetJob{}
	},
}

const (
	ctrlActiveEvery  = time.Second
	ctrlIdleEvery    = 60 * time.Second
	flushActiveEvery = 5 * time.Second
	flushIdleEvery   = 60 * time.Second
)

// Engine executes fast/slow-path decoupled cleartext privacy leak detection.
type Engine struct {
	// 64-bit atomic counters placed at offset 0 for 32-bit ARMv7 alignment.
	droppedCount     atomic.Uint64
	submittedCount   atomic.Uint64
	scannedCount     atomic.Uint64
	totalLeaks       atomic.Uint64
	ignoredCount     atomic.Uint64
	lastClearSeq     atomic.Int64
	lastClearedAt    atomic.Int64
	lastLazySyncUnix atomic.Int64

	enabled atomic.Bool
	closed  atomic.Bool

	runDir string
	pktCh  chan *packetJob
	ring   *RingBuffer

	knownMu   sync.RWMutex
	knownMACs map[string]struct{}

	ctrlMu         sync.RWMutex
	ctrlMtimeNs    int64
	ctrlSize       int64
	persistMtimeNs int64
	persistSize    int64
	blockedDomains map[string]struct{}
	blockedList    []string
	ignoreRules    []IgnoreRule

	workerMu   sync.Mutex
	workerStop context.CancelFunc
	workerDone chan struct{}

	onAlert   atomic.Pointer[func(LeakEvent)]
	idleCheck atomic.Pointer[func() bool]
}

// NewEngine constructs a LeakGuard Engine backed by a 256-slot async queue and
// a 300-entry / 300s-cooldown RingBuffer mirrored to runDir/leakguard_events.json.
func NewEngine(runDir string) *Engine {
	if strings.TrimSpace(runDir) == "" {
		runDir = DefaultRunDir
	}
	e := &Engine{
		runDir:         runDir,
		pktCh:          make(chan *packetJob, DefaultQueueCap),
		ring:           NewRingBuffer(DefaultCapacity, DefaultCooldownSec),
		knownMACs:      make(map[string]struct{}, 64),
		blockedDomains: make(map[string]struct{}),
	}
	e.enabled.Store(true)
	e.SyncControl()
	_ = e.FlushEvents()
	return e
}

// SetAlertHook registers an optional callback invoked on brand-new (non-cooled-down) leak alerts.
func (e *Engine) SetAlertHook(fn func(LeakEvent)) {
	if fn == nil {
		e.onAlert.Store(nil)
		return
	}
	e.onAlert.Store(&fn)
}

// SetConduitCheck registers an optional callback identifying local VPN/proxy conduit apps
// so <5s cross-interface host duplicates merge cleanly onto real business apps.
func (e *Engine) SetConduitCheck(fn func(uid int, pkg string) bool) {
	if e == nil || e.ring == nil {
		return
	}
	e.ring.SetConduitCheck(fn)
}

// SetIdleCheck registers an optional callback reporting whether LeakGuard can
// throttle background IPC polling (ctrlTk 1s->60s, flushTk 5s->60s when clean).
func (e *Engine) SetIdleCheck(fn func() bool) {
	if e == nil {
		return
	}
	if fn == nil {
		e.idleCheck.Store(nil)
		return
	}
	e.idleCheck.Store(&fn)
}

func (e *Engine) isIdle() bool {
	if e == nil {
		return false
	}
	if fn := e.idleCheck.Load(); fn != nil && *fn != nil {
		return (*fn)()
	}
	return false
}

// maybeLazySync triggers SyncControl at most once per second via lock-free CAS
// on lastLazySyncUnix so incoming packets after standby see fresh rules/toggles
// immediately without per-packet os.Stat overhead.
func (e *Engine) maybeLazySync() bool {
	if e == nil {
		return false
	}
	nowUnix := time.Now().Unix()
	prev := e.lastLazySyncUnix.Load()
	if nowUnix-prev < 1 && nowUnix >= prev {
		return false
	}
	if !e.lastLazySyncUnix.CompareAndSwap(prev, nowUnix) {
		return false
	}
	return e.SyncControl()
}

// Start launches the background slow-path analyzer and IPC sync goroutine.
func (e *Engine) Start(ctx context.Context) {
	e.workerMu.Lock()
	defer e.workerMu.Unlock()
	if e.workerDone != nil {
		return
	}
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	e.workerStop = cancel
	e.workerDone = done

	go func() {
		defer close(done)
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[leakguard] worker panic recovered: %v", rec)
			}
		}()
		ctrlCur := ctrlActiveEvery
		flushCur := flushActiveEvery
		if e.isIdle() {
			ctrlCur = ctrlIdleEvery
			flushCur = flushIdleEvery
		}
		ctrlTk := time.NewTicker(ctrlCur)
		defer ctrlTk.Stop()
		flushTk := time.NewTicker(flushCur)
		defer flushTk.Stop()
		dirty := false
		retime := func() {
			idle := e.isIdle()
			wantCtrl := ctrlActiveEvery
			if idle {
				wantCtrl = ctrlIdleEvery
			}
			if wantCtrl != ctrlCur {
				ctrlCur = wantCtrl
				ctrlTk.Reset(ctrlCur)
			}
			wantFlush := flushActiveEvery
			if idle && !dirty {
				wantFlush = flushIdleEvery
			}
			if wantFlush != flushCur {
				flushCur = wantFlush
				flushTk.Reset(flushCur)
			}
		}
		for {
			select {
			case <-wctx.Done():
				for {
					select {
					case job := <-e.pktCh:
						_, anyHit := e.processJob(job)
						if anyHit {
							dirty = true
						}
						jobPool.Put(job)
					default:
						if dirty {
							_ = e.FlushEvents()
						}
						return
					}
				}
			case job := <-e.pktCh:
				hasNew, hasAny := e.processJob(job)
				jobPool.Put(job)
				for i := 0; i < 32; i++ {
					select {
					case more := <-e.pktCh:
						n, a := e.processJob(more)
						if n {
							hasNew = true
						}
						if a {
							hasAny = true
						}
						jobPool.Put(more)
					default:
						i = 32
					}
				}
				if hasNew {
					_ = e.FlushEvents()
					dirty = false
				} else if hasAny {
					dirty = true
				}
				retime()
			case <-ctrlTk.C:
				if e.SyncControl() {
					_ = e.FlushEvents()
					dirty = false
				}
				retime()
			case <-flushTk.C:
				if dirty {
					_ = e.FlushEvents()
					dirty = false
				}
				retime()
			}
		}
	}()
}

// Close stops the background worker (if running) and flushes the latest snapshot.
func (e *Engine) Close() error {
	e.closed.Store(true)
	e.workerMu.Lock()
	cancel := e.workerStop
	done := e.workerDone
	e.workerStop = nil
	e.workerDone = nil
	e.workerMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	return e.FlushEvents()
}

// SubmitPacket truncates rawPayload to the first 4096 bytes and enqueues it via
// non-blocking select-default. When the 256-entry channel is full, the packet is
// dropped silently and DroppedCount is incremented without blocking capture.
func (e *Engine) SubmitPacket(clientMAC, clientIP, dstIP string, dstPort uint16, method, path, dstHost, userAgent string, rawPayload []byte, ts time.Time) bool {
	return e.Submit(PacketInput{
		Time:       ts,
		ClientMAC:  clientMAC,
		ClientIP:   clientIP,
		DstIP:      dstIP,
		DstPort:    dstPort,
		Method:     method,
		Path:       path,
		DstHost:    dstHost,
		UserAgent:  userAgent,
		RawPayload: rawPayload,
	})
}

// Submit enqueues PacketInput onto the non-blocking 256-entry channel.
func (e *Engine) Submit(in PacketInput) bool {
	if e == nil || e.closed.Load() || len(in.RawPayload) == 0 {
		return false
	}
	if !e.enabled.Load() {
		if e.maybeLazySync() {
			_ = e.FlushEvents()
		}
		if !e.enabled.Load() {
			return false
		}
	}
	job := jobPool.Get().(*packetJob)
	n := len(in.RawPayload)
	if n > MaxPacketSnap {
		n = MaxPacketSnap
	}
	copy(job.raw[:n], in.RawPayload[:n])
	job.rawLen = n
	job.ts = in.Time
	job.origin = in.Origin
	job.uid = in.UID
	job.pkg = in.Pkg
	job.appName = in.AppName
	job.clientMAC = in.ClientMAC
	job.clientIP = in.ClientIP
	job.dstIP = in.DstIP
	job.srcPort = in.SrcPort
	job.dstPort = in.DstPort
	job.method = in.Method
	job.path = in.Path
	job.dstHost = in.DstHost
	job.userAgent = in.UserAgent

	select {
	case e.pktCh <- job:
		e.submittedCount.Add(1)
		return true
	default:
		jobPool.Put(job)
		e.droppedCount.Add(1)
		return false
	}
}

// ProcessSync synchronously scans one packet, updates the ring buffer, mirrors
// leakguard_events.json when hits occur, and returns recorded events plus new alert count.
func (e *Engine) ProcessSync(in PacketInput) ([]LeakEvent, int) {
	if e == nil {
		return nil, 0
	}
	ctrlChanged := e.maybeLazySync()
	if !e.enabled.Load() {
		if ctrlChanged {
			_ = e.FlushEvents()
		}
		return nil, 0
	}
	raw := in.RawPayload
	if len(raw) > MaxPacketSnap {
		raw = raw[:MaxPacketSnap]
	}
	in.RawPayload = raw
	e.scannedCount.Add(1)
	if normMAC := normalizeValidMAC(in.ClientMAC); normMAC != "" {
		e.RegisterKnownMAC(normMAC)
	}

	candidates := e.ExtractLeaks(in)
	if len(candidates) == 0 {
		if ctrlChanged {
			_ = e.FlushEvents()
		}
		return nil, 0
	}
	now := in.Time
	if now.IsZero() {
		now = time.Now()
	}

	recorded := make([]LeakEvent, 0, len(candidates))
	newAlerts := 0
	for _, cand := range candidates {
		if e.IsIgnored(cand) {
			e.ignoredCount.Add(1)
			continue
		}
		cand.Blocked = e.IsDomainBlocked(cand.DstHost) || e.IsDomainBlocked(cand.DstIP)
		cand.IsBlocked = cand.Blocked
		ev, isNew := e.ring.Record(cand, now)
		e.totalLeaks.Add(1)
		if isNew {
			newAlerts++
			if hook := e.onAlert.Load(); hook != nil && *hook != nil {
				(*hook)(ev)
			}
		}
		recorded = append(recorded, ev)
	}
	if len(recorded) > 0 || ctrlChanged {
		_ = e.FlushEvents()
	}
	return recorded, newAlerts
}

func (e *Engine) processJob(job *packetJob) (newAlert bool, dirty bool) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[leakguard] job panic recovered: %v", rec)
		}
	}()
	ctrlChanged := e.maybeLazySync()
	if !e.enabled.Load() {
		return ctrlChanged, ctrlChanged
	}
	e.scannedCount.Add(1)
	if normMAC := normalizeValidMAC(job.clientMAC); normMAC != "" {
		e.RegisterKnownMAC(normMAC)
	}
	in := PacketInput{
		Time:       job.ts,
		Origin:     job.origin,
		UID:        job.uid,
		Pkg:        job.pkg,
		AppName:    job.appName,
		ClientMAC:  job.clientMAC,
		ClientIP:   job.clientIP,
		DstIP:      job.dstIP,
		SrcPort:    job.srcPort,
		DstPort:    job.dstPort,
		Method:     job.method,
		Path:       job.path,
		DstHost:    job.dstHost,
		UserAgent:  job.userAgent,
		RawPayload: job.raw[:job.rawLen],
	}
	candidates := e.ExtractLeaks(in)
	if len(candidates) == 0 {
		return ctrlChanged, ctrlChanged
	}
	now := job.ts
	if now.IsZero() {
		now = time.Now()
	}
	for _, cand := range candidates {
		if e.IsIgnored(cand) {
			e.ignoredCount.Add(1)
			continue
		}
		cand.Blocked = e.IsDomainBlocked(cand.DstHost) || e.IsDomainBlocked(cand.DstIP)
		cand.IsBlocked = cand.Blocked
		ev, isNew := e.ring.Record(cand, now)
		e.totalLeaks.Add(1)
		dirty = true
		if isNew {
			newAlert = true
			if hook := e.onAlert.Load(); hook != nil && *hook != nil {
				(*hook)(ev)
			}
		}
	}
	if ctrlChanged {
		newAlert = true
		dirty = true
	}
	return newAlert, dirty
}

// DroppedCount returns packets dropped due to backpressure on the 256-entry queue.
func (e *Engine) DroppedCount() uint64 { return e.droppedCount.Load() }

// SubmittedCount returns packets accepted onto the async channel.
func (e *Engine) SubmittedCount() uint64 { return e.submittedCount.Load() }

// ScannedCount returns packets inspected by the slow-path analyzer.
func (e *Engine) ScannedCount() uint64 { return e.scannedCount.Load() }

// TotalLeaks returns cumulative privacy leak hits observed since Engine start.
func (e *Engine) TotalLeaks() uint64 { return e.totalLeaks.Load() }

// IgnoredCount returns cumulative candidates skipped by persisted ignore whitelist rules.
func (e *Engine) IgnoredCount() uint64 { return e.ignoredCount.Load() }

// Ring exposes the underlying RingBuffer for direct in-process inspection.
func (e *Engine) Ring() *RingBuffer { return e.ring }

// IsIgnored reports whether ev matches any active ignore whitelist rule.
func (e *Engine) IsIgnored(ev LeakEvent) bool {
	if e == nil {
		return false
	}
	e.ctrlMu.RLock()
	rules := e.ignoreRules
	e.ctrlMu.RUnlock()
	for i := range rules {
		if rules[i].MatchesEvent(ev) {
			return true
		}
	}
	return false
}

// RegisterKnownMAC adds a downstream hotspot device MAC to the known-MAC table.
func (e *Engine) RegisterKnownMAC(mac string) {
	norm := normalizeValidMAC(mac)
	if norm == "" {
		return
	}
	e.knownMu.Lock()
	if _, exists := e.knownMACs[norm]; !exists {
		if len(e.knownMACs) >= maxKnownMACs {
			for k := range e.knownMACs {
				delete(e.knownMACs, k)
				break
			}
		}
		e.knownMACs[norm] = struct{}{}
	}
	e.knownMu.Unlock()
}

// IsKnownMAC checks whether mac belongs to a known downstream device.
func (e *Engine) IsKnownMAC(mac string) bool {
	norm := normalizeValidMAC(mac)
	if norm == "" {
		return false
	}
	e.knownMu.RLock()
	_, ok := e.knownMACs[norm]
	e.knownMu.RUnlock()
	return ok
}

// IsDomainBlocked checks whether host matches the synced LeakGuard blocklist.
func (e *Engine) IsDomainBlocked(host string) bool {
	h := normalizeDomain(host)
	if h == "" {
		return false
	}
	e.ctrlMu.RLock()
	defer e.ctrlMu.RUnlock()
	if len(e.blockedDomains) == 0 {
		return false
	}
	if _, ok := e.blockedDomains[h]; ok {
		return true
	}
	for {
		dot := strings.IndexByte(h, '.')
		if dot < 0 || dot+1 >= len(h) {
			break
		}
		h = h[dot+1:]
		if _, ok := e.blockedDomains[h]; ok {
			return true
		}
	}
	return false
}

// SyncControl checks runDir/leakguard_ctrl.json (plus ../data/leakguard_config.json)
// and applies dynamic changes (enabled, capacity, cooldown, clear, blocked domains, ignore rules).
func (e *Engine) SyncControl() bool {
	if e == nil {
		return false
	}
	e.lastLazySyncUnix.Store(time.Now().Unix())
	cpath := CtrlPath(e.runDir)
	persistPath := filepath.Join(filepath.Dir(filepath.Clean(e.runDir)), "data", "leakguard_config.json")

	var ctrlMtime, ctrlSz, persistMtime, persistSz int64
	if st, err := os.Stat(cpath); err == nil {
		ctrlMtime = st.ModTime().UnixNano()
		ctrlSz = st.Size()
	}
	if pst, perr := os.Stat(persistPath); perr == nil {
		persistMtime = pst.ModTime().UnixNano()
		persistSz = pst.Size()
	}
	if ctrlMtime == 0 && persistMtime == 0 {
		return false
	}

	e.ctrlMu.RLock()
	unchanged := ctrlMtime == e.ctrlMtimeNs && ctrlSz == e.ctrlSize &&
		persistMtime == e.persistMtimeNs && persistSz == e.persistSize
	e.ctrlMu.RUnlock()
	if unchanged {
		return false
	}

	ctrl, err := ReadControl(e.runDir)
	if err != nil {
		return false
	}

	changed := false
	if ctrl.Enabled != nil {
		prev := e.enabled.Swap(*ctrl.Enabled)
		if prev != *ctrl.Enabled {
			changed = true
		}
	}
	if ctrl.Capacity > 0 && ctrl.Capacity != e.ring.Capacity() {
		e.ring.Resize(ctrl.Capacity)
		changed = true
	}
	if ctrl.CooldownSec > 0 && ctrl.CooldownSec != e.ring.CooldownSec() {
		e.ring.SetCooldownSec(ctrl.CooldownSec)
		changed = true
	}
	if ctrl.ClearSeq > e.lastClearSeq.Load() || ctrl.ClearedAt > e.lastClearedAt.Load() {
		if ctrl.ClearSeq > e.lastClearSeq.Load() {
			e.lastClearSeq.Store(ctrl.ClearSeq)
		}
		if ctrl.ClearedAt > e.lastClearedAt.Load() {
			e.lastClearedAt.Store(ctrl.ClearedAt)
		}
		e.ring.Clear()
		changed = true
	}

	newSet := make(map[string]struct{}, len(ctrl.BlockedDomains))
	for _, d := range ctrl.BlockedDomains {
		newSet[d] = struct{}{}
	}
	rulesChanged := false
	e.ctrlMu.Lock()
	e.ctrlMtimeNs = ctrlMtime
	e.ctrlSize = ctrlSz
	e.persistMtimeNs = persistMtime
	e.persistSize = persistSz
	if !sameStringSlice(e.blockedList, ctrl.BlockedDomains) {
		e.blockedDomains = newSet
		e.blockedList = ctrl.BlockedDomains
		changed = true
	}
	if !sameIgnoreRules(e.ignoreRules, ctrl.IgnoreRules) {
		e.ignoreRules = append([]IgnoreRule(nil), ctrl.IgnoreRules...)
		rulesChanged = true
		changed = true
	}
	e.ctrlMu.Unlock()

	if rulesChanged && e.ring.PurgeIgnored(e.IsIgnored) > 0 {
		changed = true
	}
	if e.ring.MarkBlockedDomains(e.IsDomainBlocked) {
		changed = true
	}
	return changed
}

// Snapshot builds the current EventsSnapshot (chronological events array so
// hnc_httpd tailing preserves newest-first WebUI ordering).
func (e *Engine) Snapshot() EventsSnapshot {
	e.ctrlMu.RLock()
	blocked := append([]string(nil), e.blockedList...)
	e.ctrlMu.RUnlock()

	evs := e.ring.SnapshotChronological()
	return EventsSnapshot{
		UpdatedAt:      time.Now().Unix(),
		Enabled:        e.enabled.Load(),
		Capacity:       e.ring.Capacity(),
		CooldownSec:    e.ring.CooldownSec(),
		TotalLeaks:     e.totalLeaks.Load(),
		IgnoredCount:   e.ignoredCount.Load(),
		UniqueEvents:   len(evs),
		SubmittedPkts:  e.submittedCount.Load(),
		ScannedPkts:    e.scannedCount.Load(),
		DroppedCount:   e.droppedCount.Load(),
		ClearSeq:       e.lastClearSeq.Load(),
		BlockedDomains: blocked,
		Events:         evs,
	}
}

// FlushEvents mirrors the current RingBuffer snapshot to runDir/leakguard_events.json.
func (e *Engine) FlushEvents() error {
	return WriteEvents(e.runDir, e.Snapshot())
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameIgnoreRules(a, b []IgnoreRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].UniqueKey() != b[i].UniqueKey() || a[i].ID != b[i].ID {
			return false
		}
	}
	return true
}

// ─── HTTP Request Dissection & Four-Category Privacy Extraction ──────────

type parsedHTTP struct {
	method          string
	path            string
	rawQuery        string
	host            string
	userAgent       string
	contentType     string
	contentEncoding string
	headers         [][2]string
	body            []byte
}

func dissectHTTP(raw []byte) parsedHTTP {
	var out parsedHTTP
	if len(raw) == 0 {
		return out
	}
	nl := bytes.IndexByte(raw, '\n')
	if nl < 0 {
		return out
	}
	reqLine := string(bytes.TrimRight(raw[:nl], "\r"))
	sp1 := strings.IndexByte(reqLine, ' ')
	if sp1 > 0 {
		out.method = strings.ToUpper(reqLine[:sp1])
		rest := strings.TrimLeft(reqLine[sp1+1:], " ")
		sp2 := strings.IndexByte(rest, ' ')
		target := rest
		if sp2 >= 0 {
			target = rest[:sp2]
		}
		out.path = target
		if q := strings.IndexByte(target, '?'); q >= 0 {
			out.rawQuery = target[q+1:]
		}
	}

	rem := raw[nl+1:]
	for len(rem) > 0 {
		j := bytes.IndexByte(rem, '\n')
		if j < 0 {
			rem = nil
			break
		}
		line := bytes.TrimRight(rem[:j], "\r")
		rem = rem[j+1:]
		if len(line) == 0 {
			out.body = rem
			break
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		k := string(bytes.TrimSpace(line[:colon]))
		v := string(bytes.TrimSpace(line[colon+1:]))
		out.headers = append(out.headers, [2]string{k, v})
		switch {
		case out.host == "" && strings.EqualFold(k, "host"):
			out.host = stripPortFromHost(v)
		case out.userAgent == "" && strings.EqualFold(k, "user-agent"):
			out.userAgent = v
		case out.contentType == "" && strings.EqualFold(k, "content-type"):
			out.contentType = strings.ToLower(v)
		case out.contentEncoding == "" && strings.EqualFold(k, "content-encoding"):
			out.contentEncoding = strings.ToLower(v)
		}
	}
	return out
}

func stripPortFromHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "[") {
		if end := strings.IndexByte(h, ']'); end > 1 {
			return strings.ToLower(h[1:end])
		}
		return strings.ToLower(h)
	}
	if c := strings.LastIndexByte(h, ':'); c > 0 {
		portPart := h[c+1:]
		allDigits := len(portPart) > 0
		for i := 0; i < len(portPart); i++ {
			if portPart[i] < '0' || portPart[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			h = h[:c]
		}
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

func decompressBodySafe(body []byte, contentEncoding string) []byte {
	if len(body) == 0 {
		return nil
	}
	isGzip := strings.Contains(contentEncoding, "gzip") ||
		(len(body) >= 3 && body[0] == 0x1f && body[1] == 0x8b && body[2] == 0x08)
	if !isGzip {
		if len(body) > MaxDecompressedBytes {
			return body[:MaxDecompressedBytes]
		}
		return body
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return body
	}
	defer gz.Close()

	limited := io.LimitReader(gz, MaxDecompressedBytes)
	var out bytes.Buffer
	buf := make([]byte, 2048)
	for out.Len() < MaxDecompressedBytes {
		n, rerr := limited.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
		}
		if rerr != nil {
			break
		}
	}
	if out.Len() == 0 {
		return body
	}
	return out.Bytes()
}

// PercentDecode performs tolerant URL/Form percent-decoding (converting %3A to ':',
// '+' to ' ' when plusAsSpace is true) without failing on truncated trailing '%' sequences.
func PercentDecode(s string, plusAsSpace bool) string {
	if !strings.ContainsRune(s, '%') && (!plusAsSpace || !strings.ContainsRune(s, '+')) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) {
			hi, ok1 := hexNibble(s[i+1])
			lo, ok2 := hexNibble(s[i+2])
			if ok1 && ok2 {
				b.WriteByte((hi << 4) | lo)
				i += 2
				continue
			}
		} else if c == '+' && plusAsSpace {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// ValidLuhn reports whether a numeric string (such as a 15-digit IMEI) passes
// standard Luhn check-digit verification and is not trivially all-zero/constant.
func ValidLuhn(digits string) bool {
	if len(digits) == 0 {
		return false
	}
	allSame := true
	sum := 0
	parity := len(digits) % 2
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		if c != digits[0] {
			allSame = false
		}
		d := int(c - '0')
		if i%2 == parity {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	if allSame {
		return false
	}
	return sum%10 == 0
}

// ExtractLeaks scans an HTTP request (Query, Form, Headers, Gzip/JSON Body, and Path)
// and returns deduplicated LeakEvent candidates for this single packet.
func (e *Engine) ExtractLeaks(in PacketInput) []LeakEvent {
	raw := in.RawPayload
	if len(raw) > MaxPacketSnap {
		raw = raw[:MaxPacketSnap]
	}
	hp := dissectHTTP(raw)

	method := in.Method
	if method == "" {
		method = hp.method
	}
	path := in.Path
	if path == "" {
		path = hp.path
	}
	dstHost := in.DstHost
	if dstHost == "" {
		dstHost = hp.host
	}
	if dstHost == "" {
		dstHost = in.DstIP
	}
	ua := in.UserAgent
	if ua == "" {
		ua = hp.userAgent
	}

	bodyPlain := decompressBodySafe(hp.body, hp.contentEncoding)
	decodedPath := PercentDecode(path, false)

	var snippetSource []byte
	if len(bodyPlain) > 0 && !bytes.Equal(bodyPlain, hp.body) {
		hdrEnd := len(raw) - len(hp.body)
		if hdrEnd < 0 {
			hdrEnd = 0
		}
		snippetSource = make([]byte, 0, hdrEnd+len(bodyPlain))
		snippetSource = append(snippetSource, raw[:hdrEnd]...)
		snippetSource = append(snippetSource, bodyPlain...)
	} else {
		snippetSource = raw
	}

	seen := make(map[string]struct{}, 8)
	var out []LeakEvent

	var (
		hasLat bool
		latRaw string
		latKey string
		hasLon bool
		lonRaw string
	)

	pktKnownMAC := normalizeValidMAC(in.ClientMAC)
	isKnown := func(normMAC string) bool {
		if normMAC == "" {
			return false
		}
		if normMAC == pktKnownMAC {
			return true
		}
		if e != nil && e.IsKnownMAC(normMAC) {
			return true
		}
		return false
	}

	normOrigin := strings.ToLower(strings.TrimSpace(in.Origin))
	if normOrigin != OriginHost && normOrigin != OriginHotspot {
		normOrigin = ""
	}
	normPkg := strings.TrimSpace(in.Pkg)
	normAppName := strings.TrimSpace(in.AppName)

	addHit := func(leakType, fieldKey, rawVal, searchHint string) {
		if rawVal == "" {
			return
		}
		dedup := leakType + "\x00" + sameValueKey(leakType, rawVal)
		if _, dup := seen[dedup]; dup {
			return
		}
		seen[dedup] = struct{}{}
		hint := searchHint
		if hint == "" {
			hint = rawVal
		}
		out = append(out, LeakEvent{
			Origin:     normOrigin,
			UID:        in.UID,
			Pkg:        normPkg,
			AppName:    normAppName,
			MAC:        pktKnownMAC,
			ClientIP:   in.ClientIP,
			SrcIP:      in.ClientIP,
			DstIP:      in.DstIP,
			SrcPort:    in.SrcPort,
			DstPort:    in.DstPort,
			DstHost:    dstHost,
			Proto:      "http",
			Method:     method,
			Path:       truncateUTF8(path, 512),
			UserAgent:  truncateUTF8(ua, 256),
			LeakType:   leakType,
			LeakLabel:  defaultLabelForType(leakType),
			FieldKey:   fieldKey,
			RawValue:   rawVal,
			RawSnippet: buildReadableSnippet(snippetSource, rawVal, hint),
			HitCount:   1,
		})
	}

	inspectKV := func(key, val, rawHint string, inCookie bool) {
		keyTrim := strings.TrimSpace(key)
		valTrim := strings.TrimSpace(val)
		if valTrim == "" {
			return
		}

		// 1. PHONE: key word-tokens match phone/mobile/tel/msisdn/user_phone and 1[3-9]\d{9}.
		if keyTrim != "" && isPhoneKey(keyTrim) {
			if m := phoneValRe.FindStringSubmatch(valTrim); len(m) == 2 {
				addHit(TypePhone, keyTrim, m[1], rawHint)
			}
		}

		// 2. DEVICE_ID: strict per-kind validation (IMEI 15d+Luhn, IMEISV 16d, IMSI 14-15d,
		// MEID 14h/18d, ANDROID_ID 16h excluding 9774d56d682e549c, OAID/IDFA/IDFV UUID or 16-64h).
		if keyTrim != "" {
			if idKind := classifyDeviceIDKey(keyTrim); idKind != "" {
				if okDeviceIDValue(idKind, valTrim) {
					addHit(TypeDeviceID, keyTrim, valTrim, rawHint)
				}
			}
		}

		// 3. GPS: accumulate latitude & longitude across the same HTTP request.
		if keyTrim != "" {
			switch classifyGPSKey(keyTrim) {
			case "lat":
				if !hasLat && validCoordString(valTrim, 90.0) {
					hasLat, latRaw, latKey = true, valTrim, keyTrim
				}
			case "lon":
				if !hasLon && validCoordString(valTrim, 180.0) {
					hasLon, lonRaw = true, valTrim
				}
			case "pair":
				if la, lo, ok := parseCoordPair(valTrim); ok {
					if !hasLat {
						hasLat, latRaw, latKey = true, la, keyTrim
					}
					if !hasLon {
						hasLon, lonRaw = true, lo
					}
				}
			}
		}

		// 4. MAC_ADDR: in explicit MAC/BSSID key context OR matching known downstream MAC table.
		inMACCtx := keyTrim != "" && isMACKey(keyTrim)
		scanMACTokens(valTrim, func(macRaw, normMAC string) {
			if inMACCtx || isKnown(normMAC) {
				addHit(TypeMACAddr, keyTrim, macRaw, rawHint)
			}
		})

		// 5. CREDENTIAL: context-aware credential/token/session parameters (sid restricted to Cookie)
		// with length/entropy/anti-placeholder checks, or standard 3-part JWT.
		if keyTrim != "" && isValidCredentialKV(keyTrim, valTrim, inCookie) {
			addHit(TypeCredential, keyTrim, valTrim, rawHint)
		}
		scanJWTTokens(valTrim, func(jwt string) {
			addHit(TypeCredential, keyTrim, jwt, rawHint)
		})

		// 6. ID_CARD: parameter matching (?i)(id_?card|id_?no|cert_?no|sfz|identity) or standalone
		// 18-digit Mainland China ID card verified by birth date + ISO 7064:1983.MOD 11-2 check char.
		if keyTrim != "" && idCardKeyRe.MatchString(keyTrim) && ValidCNIDCard(valTrim) {
			addHit(TypeIDCard, keyTrim, valTrim, rawHint)
		}
		scanIDCardTokens(valTrim, func(idRaw string) {
			addHit(TypeIDCard, keyTrim, idRaw, rawHint)
		})
	}

	scanFormEncoded(hp.rawQuery, func(k, v, rawSeg string) {
		inspectKV(k, v, rawSeg, false)
		vt := strings.TrimSpace(v)
		if len(vt) >= 2 && (vt[0] == '{' || vt[0] == '[') {
			ScanJSON([]byte(vt), func(jk, jv string) {
				inspectKV(jk, jv, rawSeg, false)
			})
		}
	})

	pathOnly := decodedPath
	if q := strings.IndexByte(pathOnly, '?'); q >= 0 {
		pathOnly = pathOnly[:q]
	}
	scanMACTokens(pathOnly, func(macRaw, normMAC string) {
		if isKnown(normMAC) {
			addHit(TypeMACAddr, "url_path", macRaw, path)
		}
	})
	scanJWTTokens(pathOnly, func(jwt string) {
		addHit(TypeCredential, "url_path", jwt, path)
	})
	scanIDCardTokens(pathOnly, func(idRaw string) {
		addHit(TypeIDCard, "url_path", idRaw, path)
	})

	for _, hdr := range hp.headers {
		hk, hv := hdr[0], hdr[1]
		lowK := strings.ToLower(hk)
		if lowK == "host" || lowK == "user-agent" || lowK == "accept" ||
			lowK == "accept-encoding" || lowK == "accept-language" ||
			lowK == "connection" || lowK == "content-length" || lowK == "content-type" {
			continue
		}
		if lowK == "authorization" {
			decAuth := PercentDecode(hv, false)
			if cred, ok := extractAuthHeaderCredential(decAuth); ok {
				addHit(TypeCredential, hk, cred, hv)
				continue
			}
		}
		if lowK == "cookie" {
			for _, part := range strings.Split(hv, ";") {
				eq := strings.IndexByte(part, '=')
				if eq > 0 {
					ck := PercentDecode(strings.TrimSpace(part[:eq]), false)
					cv := PercentDecode(strings.TrimSpace(part[eq+1:]), false)
					inspectKV(ck, cv, strings.TrimSpace(part), true)
				}
			}
			continue
		}
		decHV := PercentDecode(hv, false)
		inspectKV(hk, decHV, hv, false)
	}

	if len(bodyPlain) > 0 {
		trimmedBody := bytes.TrimSpace(bodyPlain)
		if len(trimmedBody) >= 2 && (trimmedBody[0] == '{' || trimmedBody[0] == '[') {
			ScanJSON(trimmedBody, func(jk, jv string) {
				decV := PercentDecode(jv, false)
				inspectKV(jk, decV, jv, false)
			})
		} else if strings.Contains(hp.contentType, "urlencoded") || looksLikeFormBody(trimmedBody) {
			scanFormEncoded(string(trimmedBody), func(k, v, rawSeg string) {
				inspectKV(k, v, rawSeg, false)
				vt := strings.TrimSpace(v)
				if len(vt) >= 2 && (vt[0] == '{' || vt[0] == '[') {
					ScanJSON([]byte(vt), func(jk, jv string) {
						inspectKV(jk, jv, rawSeg, false)
					})
				}
			})
		}

		decodedBody := PercentDecode(string(bodyPlain), false)
		scanMACTokens(decodedBody, func(macRaw, normMAC string) {
			if isKnown(normMAC) {
				addHit(TypeMACAddr, "", macRaw, macRaw)
			}
		})
		scanJWTTokens(decodedBody, func(jwt string) {
			addHit(TypeCredential, "", jwt, jwt)
		})
		scanIDCardTokens(decodedBody, func(idRaw string) {
			addHit(TypeIDCard, "", idRaw, idRaw)
		})
	}

	if hasLat && hasLon && !isZeroOriginGPS(latRaw, lonRaw) {
		fk := latKey
		if fk == "" {
			fk = "gps"
		}
		addHit(TypeGPS, fk, latRaw+","+lonRaw, latRaw)
	}

	return out
}

func scanFormEncoded(raw string, fn func(key, val, rawPair string)) {
	if raw == "" {
		return
	}
	for len(raw) > 0 {
		var seg string
		if amp := strings.IndexAny(raw, "&;"); amp >= 0 {
			seg = raw[:amp]
			raw = raw[amp+1:]
		} else {
			seg = raw
			raw = ""
		}
		if seg == "" {
			continue
		}
		eq := strings.IndexByte(seg, '=')
		if eq < 0 {
			dec := PercentDecode(seg, true)
			fn("", dec, seg)
			continue
		}
		k := PercentDecode(seg[:eq], true)
		v := PercentDecode(seg[eq+1:], true)
		fn(k, v, seg)
	}
}

func looksLikeFormBody(b []byte) bool {
	if len(b) == 0 || b[0] == '{' || b[0] == '[' || b[0] == '<' {
		return false
	}
	eq := bytes.IndexByte(b, '=')
	if eq <= 0 || eq > 64 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := b[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '%') {
			return false
		}
	}
	return true
}

func isPhoneKey(k string) bool {
	for _, rawW := range splitKeyWords(k) {
		switch stripTrailingDigits(rawW) {
		case "phone", "userphone", "mobile", "mobilephone", "mobilenum",
			"cellphone", "phonenumber", "tel", "telephone", "telno", "telnum", "msisdn":
			return true
		}
	}
	return false
}

func splitKeyWords(k string) []string {
	var words []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			words = append(words, strings.ToLower(cur.String()))
			cur.Reset()
		}
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if c == '_' || c == '-' || c == '.' || c == '/' || c == ':' || c == ' ' {
			flush()
			continue
		}
		if c >= 'A' && c <= 'Z' && cur.Len() > 0 {
			prev := k[i-1]
			if prev >= 'a' && prev <= 'z' {
				flush()
			}
		}
		cur.WriteByte(c)
	}
	flush()
	return words
}

func stripTrailingDigits(w string) string {
	end := len(w)
	for end > 0 && w[end-1] >= '0' && w[end-1] <= '9' {
		end--
	}
	return w[:end]
}

func classifyDeviceIDKey(k string) string {
	words := splitKeyWords(k)
	for i, rawW := range words {
		w := stripTrailingDigits(rawW)
		switch w {
		case "imeisv":
			return "imeisv"
		case "imei":
			if i+1 < len(words) && stripTrailingDigits(words[i+1]) == "sv" {
				return "imeisv"
			}
			return "imei"
		case "imsi":
			return "imsi"
		case "meid":
			return "meid"
		case "oaid":
			return "oaid"
		case "idfa":
			return "idfa"
		case "idfv":
			return "idfv"
		case "androidid":
			return "android_id"
		case "android":
			if i+1 < len(words) && stripTrailingDigits(words[i+1]) == "id" {
				return "android_id"
			}
		}
	}
	return ""
}

func isAllDigitsASCII(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isAllHexASCII(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isAllSameChar(s string) bool {
	if len(s) == 0 {
		return true
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

func isStandardUUIDHex(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			c := s[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

func okDeviceIDValue(idKind, v string) bool {
	if len(v) < 14 || len(v) > 64 {
		return false
	}
	var compact strings.Builder
	compact.Grow(len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '-' {
			continue
		}
		if c >= '0' && c <= '9' {
			compact.WriteByte(c)
			continue
		}
		if c >= 'a' && c <= 'f' {
			compact.WriteByte(c)
			continue
		}
		if c >= 'A' && c <= 'F' {
			compact.WriteByte(c + ('a' - 'A'))
			continue
		}
		// Rejects '_', ':', whitespace, and [g-zG-Z] (e.g. "permission_denied", "unavailable", "unknown").
		return false
	}
	comp := compact.String()
	if len(comp) == 0 || isAllSameChar(comp) || comp == "9774d56d682e549c" {
		return false
	}

	switch idKind {
	case "imei":
		return len(v) == 15 && isAllDigitsASCII(v) && ValidLuhn(v)
	case "imeisv":
		return len(v) == 16 && isAllDigitsASCII(v)
	case "imsi":
		return (len(v) == 14 || len(v) == 15) && isAllDigitsASCII(v)
	case "meid":
		return (len(v) == 14 && isAllHexASCII(v)) || (len(v) == 18 && isAllDigitsASCII(v))
	case "android_id":
		return len(v) == 16 && isAllHexASCII(v)
	case "oaid", "idfa", "idfv":
		return isStandardUUIDHex(v) || (len(v) >= 16 && len(v) <= 64 && isAllHexASCII(v))
	default:
		return false
	}
}

func classifyGPSKey(k string) string {
	words := splitKeyWords(k)
	for _, rawW := range words {
		w := stripTrailingDigits(rawW)
		switch w {
		case "lat", "latitude":
			return "lat"
		case "lon", "lng", "long", "longitude":
			return "lon"
		case "latlng", "lnglat", "coord", "coords", "coordinate", "coordinates", "gps", "geo", "geolocation":
			return "pair"
		}
	}
	return ""
}

func validCoordString(s string, maxAbs float64) bool {
	if !coordValRe.MatchString(s) {
		return false
	}
	num := s
	if num[0] == '+' || num[0] == '-' {
		num = num[1:]
	}
	dot := strings.IndexByte(num, '.')
	if dot <= 0 {
		return false
	}
	intPart := num[:dot]
	if len(intPart) > 1 && intPart[0] == '0' {
		return false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return false
	}
	return math.Abs(f) <= maxAbs
}

func parseCoordPair(s string) (lat, lon string, ok bool) {
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return "", "", false
	}
	a := strings.TrimSpace(parts[0])
	b := strings.TrimSpace(parts[1])
	if validCoordString(a, 90.0) && validCoordString(b, 180.0) {
		return a, b, true
	}
	if validCoordString(a, 180.0) && validCoordString(b, 90.0) {
		return b, a, true
	}
	return "", "", false
}

func isZeroOriginGPS(latRaw, lonRaw string) bool {
	la, err1 := strconv.ParseFloat(latRaw, 64)
	lo, err2 := strconv.ParseFloat(lonRaw, 64)
	if err1 != nil || err2 != nil {
		return false
	}
	return math.Abs(la) < 1e-6 && math.Abs(lo) < 1e-6
}

func isMACKey(k string) bool {
	low := strings.ToLower(strings.TrimSpace(k))
	switch low {
	case "mac", "bssid", "wifi_mac", "wifimac", "client_mac", "clientmac", "device_mac", "devicemac", "wlan_mac", "wlanmac", "hwaddr", "mac_addr", "macaddr":
		return true
	}
	words := splitKeyWords(k)
	for i, rawW := range words {
		w := stripTrailingDigits(rawW)
		if w == "bssid" || w == "hwaddr" || w == "wifimac" || w == "clientmac" {
			return true
		}
		if w == "mac" {
			if i+1 < len(words) && words[i+1] == "os" {
				continue
			}
			return true
		}
	}
	return false
}

func scanMACTokens(s string, onMatch func(rawMAC, normMAC string)) {
	if len(s) < 17 {
		return
	}
	locs := macTokenRe.FindAllStringIndex(s, 8)
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		cand := s[start:end]
		sep := cand[2]
		if cand[5] != sep || cand[8] != sep || cand[11] != sep || cand[14] != sep {
			continue
		}
		if start > 0 && isHexOrMACJoin(s[start-1]) {
			continue
		}
		if end < len(s) && isHexOrMACJoin(s[end]) {
			continue
		}
		norm := normalizeValidMAC(cand)
		if norm == "" {
			continue
		}
		onMatch(cand, norm)
	}
}

func isHexOrMACJoin(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' || c == '-'
}

func normalizeValidMAC(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) != 17 {
		return ""
	}
	sep := s[2]
	if sep != ':' && sep != '-' {
		return ""
	}
	var b [6]byte
	for idx := 0; idx < 6; idx++ {
		pos := idx * 3
		if idx > 0 && s[pos-1] != sep {
			return ""
		}
		hi, ok1 := hexNibble(s[pos])
		lo, ok2 := hexNibble(s[pos+1])
		if !ok1 || !ok2 {
			return ""
		}
		b[idx] = (hi << 4) | lo
	}
	// Reject all-same-byte MACs (including 00:00:00:00:00:00 and ff:ff:ff:ff:ff:ff).
	if b[0] == b[1] && b[1] == b[2] && b[2] == b[3] && b[3] == b[4] && b[4] == b[5] {
		return ""
	}
	// Reject multicast/broadcast MACs (IEEE 802 I/G bit == 1).
	if b[0]&0x01 != 0 {
		return ""
	}
	// Reject Android 6.0+ privacy placeholder MAC 02:00:00:00:00:00 (while allowing 02:00:00:00:00:01 etc.).
	if b == [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00} {
		return ""
	}
	return strings.ReplaceAll(s, "-", ":")
}

var cnProvinceCodes = [100]bool{
	11: true, 12: true, 13: true, 14: true, 15: true,
	21: true, 22: true, 23: true,
	31: true, 32: true, 33: true, 34: true, 35: true, 36: true, 37: true,
	41: true, 42: true, 43: true, 44: true, 45: true, 46: true,
	50: true, 51: true, 52: true, 53: true, 54: true,
	61: true, 62: true, 63: true, 64: true, 65: true,
	71: true, 81: true, 82: true, 83: true,
}

var (
	idCardWeights   = [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	idCardCheckMods = [11]byte{'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'}
)

func isTrivialCredentialPlaceholder(v string) bool {
	if v == "" {
		return true
	}
	switch strings.ToLower(v) {
	case "true", "false", "null", "undefined", "nil", "none":
		return true
	default:
		return false
	}
}

func isAllAsterisksOrSpace(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '*' && s[i] != ' ' && s[i] != '\t' {
			return false
		}
	}
	return true
}

func hasControlOrSpaceASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func isSnakeVersionConstant(s string) bool {
	hasDigit := false
	hasLower := false
	hasUpper := false
	hasOther := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c == '_' || c == '-':
		default:
			hasOther = true
		}
	}
	// Pure single-case snake/kebab identifier without digits (e.g. "default_session_token").
	if !hasDigit && !hasOther && !(hasLower && hasUpper) {
		return true
	}
	if strings.ContainsRune(s, '_') {
		parts := strings.Split(s, "_")
		if len(parts) >= 3 {
			maxSeg := 0
			for _, p := range parts {
				if len(p) > maxSeg {
					maxSeg = len(p)
				}
			}
			// Multi-segment snake-case tag/version without any >=8-char secret segment (e.g. "da_wr_v13_g1").
			if maxSeg < 8 {
				return true
			}
		}
	}
	return false
}

func charDiversityAndEntropy(s string) (distinct int, entropy float64) {
	n := len(s)
	if n == 0 {
		return 0, 0
	}
	var counts [256]int
	for i := 0; i < n; i++ {
		b := s[i]
		if counts[b] == 0 {
			distinct++
		}
		counts[b]++
	}
	invN := 1.0 / float64(n)
	for _, c := range counts {
		if c > 0 {
			p := float64(c) * invN
			entropy -= p * math.Log2(p)
		}
	}
	return distinct, entropy
}

func okTokenOrSessionValue(val string, minLen int) bool {
	if len(val) < minLen || len(val) > 2048 {
		return false
	}
	if isTrivialCredentialPlaceholder(val) || hasControlOrSpaceASCII(val) || isAllDigitsASCII(val) || isAllSameChar(val) {
		return false
	}
	if isSnakeVersionConstant(val) {
		return false
	}
	distinct, entropy := charDiversityAndEntropy(val)
	return distinct >= 8 && entropy >= 3.3
}

func isValidCredentialKV(key, val string, inCookie bool) bool {
	lowKey := strings.ToLower(strings.TrimSpace(key))
	switch lowKey {
	case "password", "passwd", "pwd":
		if len(val) < 6 || len(val) > 128 {
			return false
		}
		if isTrivialCredentialPlaceholder(val) || isAllSameChar(val) || isAllAsterisksOrSpace(val) {
			return false
		}
		return true
	case "sid":
		if !inCookie {
			return false
		}
		return okTokenOrSessionValue(val, 16)
	case "session_id":
		minLen := 20
		if inCookie {
			minLen = 16
		}
		return okTokenOrSessionValue(val, minLen)
	case "access_token", "refresh_token", "auth_token", "api_key", "apikey", "app_secret", "client_secret":
		return okTokenOrSessionValue(val, 16)
	default:
		return false
	}
}

func extractAuthHeaderCredential(hv string) (string, bool) {
	v := strings.TrimSpace(hv)
	if v == "" {
		return "", false
	}
	sp := strings.IndexAny(v, " \t")
	if sp <= 0 {
		return "", false
	}
	scheme := v[:sp]
	if !strings.EqualFold(scheme, "basic") && !strings.EqualFold(scheme, "bearer") {
		return "", false
	}
	cred := strings.TrimSpace(v[sp+1:])
	if len(cred) < 8 || isTrivialCredentialPlaceholder(cred) || isAllSameChar(cred) || isAllAsterisksOrSpace(cred) {
		return "", false
	}
	return v, true
}

func isBase64URLChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}

func scanJWTTokens(s string, onMatch func(jwt string)) {
	if len(s) < 16 || !strings.Contains(s, "eyJ") {
		return
	}
	locs := jwtTokenRe.FindAllStringIndex(s, 8)
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		if start > 0 && isBase64URLChar(s[start-1]) {
			continue
		}
		if end < len(s) && isBase64URLChar(s[end]) {
			continue
		}
		cand := s[start:end]
		if isValidJWTToken(cand) {
			onMatch(cand)
		}
	}
}

func isValidJWTToken(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	if !strings.HasPrefix(parts[0], "eyJ") || len(parts[1]) < 4 || len(parts[2]) < 4 {
		return false
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	hdrTrim := bytes.TrimSpace(hdr)
	if len(hdrTrim) < 2 || hdrTrim[0] != '{' || hdrTrim[len(hdrTrim)-1] != '}' || !utf8.Valid(hdrTrim) {
		return false
	}
	hdrLow := strings.ToLower(string(hdrTrim))
	if !strings.Contains(hdrLow, `"alg"`) && !strings.Contains(hdrLow, `"typ"`) &&
		!strings.Contains(hdrLow, `"kid"`) && !strings.Contains(hdrLow, `"enc"`) {
		return false
	}
	pay, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(pay) == 0 {
		return false
	}
	if strings.HasPrefix(parts[1], "eyJ") {
		payTrim := bytes.TrimSpace(pay)
		if len(payTrim) < 2 || payTrim[0] != '{' || payTrim[len(payTrim)-1] != '}' {
			return false
		}
	}
	return true
}

// ValidCNIDCard validates an 18-character Mainland China second-generation resident ID card
// using province code checks, strict Gregorian birth date verification (including leap years),
// and ISO 7064:1983.MOD 11-2 check-character arithmetic.
func ValidCNIDCard(s string) bool {
	if len(s) != 18 {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		sum += int(c-'0') * idCardWeights[i]
	}
	last := s[17]
	if last == 'x' {
		last = 'X'
	}
	if !((last >= '0' && last <= '9') || last == 'X') {
		return false
	}
	if last != idCardCheckMods[sum%11] {
		return false
	}

	prov := int(s[0]-'0')*10 + int(s[1]-'0')
	if prov < 0 || prov >= len(cnProvinceCodes) || !cnProvinceCodes[prov] {
		return false
	}

	year := int(s[6]-'0')*1000 + int(s[7]-'0')*100 + int(s[8]-'0')*10 + int(s[9]-'0')
	month := int(s[10]-'0')*10 + int(s[11]-'0')
	day := int(s[12]-'0')*10 + int(s[13]-'0')
	maxYear := time.Now().Year()
	if maxYear < 2030 {
		maxYear = 2030
	}
	if year < 1900 || year > maxYear {
		return false
	}
	if month < 1 || month > 12 || day < 1 {
		return false
	}
	daysInMonth := [13]int{0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if (year%4 == 0 && year%100 != 0) || (year%400 == 0) {
		daysInMonth[2] = 29
	}
	if day > daysInMonth[month] {
		return false
	}
	return true
}

func isAlphaNumASCII(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func scanIDCardTokens(s string, onMatch func(idRaw string)) {
	if len(s) < 18 {
		return
	}
	locs := idCardCandidateRe.FindAllStringIndex(s, 8)
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		if start > 0 && isAlphaNumASCII(s[start-1]) {
			continue
		}
		if end < len(s) && isAlphaNumASCII(s[end]) {
			continue
		}
		cand := s[start:end]
		if ValidCNIDCard(cand) {
			onMatch(cand)
		}
	}
}

func sameValueKey(leakType, v string) string {
	switch leakType {
	case TypeMACAddr:
		return normalizeMACCompare(v)
	case TypeIDCard:
		return strings.ToUpper(strings.TrimSpace(v))
	default:
		return v
	}
}

func buildReadableSnippet(src []byte, rawVal, fallbackNeedle string) string {
	if len(src) == 0 {
		return rawVal
	}
	idx := -1
	matchLen := 0
	if rawVal != "" {
		idx = indexFoldASCII(src, rawVal)
		matchLen = len(rawVal)
	}
	if idx < 0 && fallbackNeedle != "" && fallbackNeedle != rawVal {
		idx = indexFoldASCII(src, fallbackNeedle)
		matchLen = len(fallbackNeedle)
	}
	if idx < 0 && strings.ContainsRune(rawVal, ':') {
		enc := strings.ReplaceAll(rawVal, ":", "%3A")
		idx = indexFoldASCII(src, enc)
		matchLen = len(enc)
	}

	var win []byte
	if idx >= 0 {
		start := idx - SnippetRadiusBytes
		if start < 0 {
			start = 0
		}
		end := idx + matchLen + SnippetRadiusBytes
		if end > len(src) {
			end = len(src)
		}
		if start > end {
			start = end
		}
		win = src[start:end]
	} else {
		limit := 2 * SnippetRadiusBytes
		if limit > len(src) {
			limit = len(src)
		}
		win = src[:limit]
	}
	return sanitizeReadableBytes(win)
}

func asciiFoldByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// indexFoldASCII performs strict 1:1 byte-length-preserving ASCII case-insensitive search.
// Never uses bytes.ToLower, which can expand invalid UTF-8 bytes to 3-byte U+FFFD and cause
// out-of-bounds slice indices on the original raw packet buffer.
func indexFoldASCII(haystack []byte, needle string) int {
	n := len(needle)
	if n == 0 || len(haystack) < n {
		return -1
	}
	if idx := bytes.Index(haystack, []byte(needle)); idx >= 0 {
		return idx
	}
	first := asciiFoldByte(needle[0])
	limit := len(haystack) - n
	for i := 0; i <= limit; i++ {
		if asciiFoldByte(haystack[i]) != first {
			continue
		}
		matched := true
		for j := 1; j < n; j++ {
			if asciiFoldByte(haystack[i+j]) != asciiFoldByte(needle[j]) {
				matched = false
				break
			}
		}
		if matched {
			return i
		}
	}
	return -1
}

func sanitizeReadableBytes(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for len(b) > 0 {
		r, width := utf8.DecodeRune(b)
		b = b[width:]
		if r == utf8.RuneError && width == 1 {
			sb.WriteByte('.')
			continue
		}
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			sb.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			sb.WriteByte('.')
		default:
			sb.WriteRune(r)
		}
	}
	return strings.TrimSpace(sb.String())
}

func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}
