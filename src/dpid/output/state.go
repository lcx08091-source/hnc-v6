// Package output - state.go: rc29 Writer + dpi_state.json schema.
//
// rc29 schema version = "2.0". Output is a strict superset of rc28.1.1's
// fields: every field rc28.1.1 wrote is still written by rc29 (sometimes
// as zero/empty values when the feature is not active yet), so WebUI built
// against rc28.1.1 keeps working without modification.

package output

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SchemaVersion is bumped to 2.0 because rc29 added several arrays
// (sub_categories, top_fingerprints) and several per-client byte counters.
const SchemaVersion = "2.0"

const (
	maxClients        = 128
	maxNamesPerClient = 64
	maxGlobalNames    = 256
	maxFlowsPerClient = 64
	maxGlobalFlows    = 512
	topN              = 8
)

// ─── shared types ──────────────────────────────────────────────────────

type Stats struct {
	Packets        uint64 `json:"packets"`
	KernelDrops    uint64 `json:"kernel_drops"`
	DNSEvents      uint64 `json:"dns_events"`
	TLSEvents      uint64 `json:"tls_events"`
	FlowEvents     uint64 `json:"flow_events"`
	IgnoredPackets uint64 `json:"ignored_packets"`
	ParseErrors    uint64 `json:"parse_errors"`
}

type Device struct {
	IPs       []string `json:"ips"`
	FirstSeen int64    `json:"first_seen"`
	LastSeen  int64    `json:"last_seen"`
	RxBps     uint64   `json:"rx_bps"`
	TxBps     uint64   `json:"tx_bps"`
}

type NameCount struct {
	Name     string `json:"name"`
	Count    uint64 `json:"count"`
	LastSeen int64  `json:"last_seen"`
}

type LabelCount struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category,omitempty"`
	Count    uint64 `json:"count"`
	LastSeen int64  `json:"last_seen"`
	Evidence string `json:"evidence,omitempty"`
	// Confidence is "high" / "medium" / "low" derived from whether the rule
	// is ground-truth verified and how many distinct evidence items hit it.
	Confidence string `json:"confidence,omitempty"`
	// SubCategory is set when a parent rule's behavioural detector fired
	// (e.g. wechat -> "voice_call").
	SubCategory string `json:"sub_category,omitempty"`
	// Bytes is total bytes attributed to this label (rc29 byte tracking).
	Bytes uint64 `json:"bytes,omitempty"`
}

// FingerprintCount is the JA4 / DFP top-N item (rc28.1.1 compatibility).
type FingerprintCount struct {
	JA4        string `json:"ja4"`
	Client     string `json:"client,omitempty"`
	Version    string `json:"version,omitempty"`
	Category   string `json:"category,omitempty"`
	Count      uint64 `json:"count"`
	LastSeen   int64  `json:"last_seen"`
	Confidence string `json:"confidence,omitempty"`
}

type ClientProfile struct {
	ClientIP      string             `json:"client_ip"`
	ClientMAC     string             `json:"client_mac,omitempty"`
	// rc29.2: every IP we've ever seen this client (this MAC) use, e.g.
	// ["10.117.193.52", "2409:8963:e03:4493:a090:ebab:827e:9558"]. Lets the
	// WebUI display "Mi-10 · 2 IPs" rather than two separate phantom clients.
	ClientIPs     []string           `json:"client_ips,omitempty"`
	RemoteIPs     []string           `json:"remote_ips,omitempty"`
	FirstSeen     int64              `json:"first_seen"`
	LastSeen      int64              `json:"last_seen"`
	DNSEvents     uint64             `json:"dns_events"`
	TLSEvents     uint64             `json:"tls_events"`
	FlowEvents    uint64             `json:"flow_events,omitempty"`
	LastHostname  string             `json:"last_hostname,omitempty"`
	LastSNI       string             `json:"last_sni,omitempty"`
	TopHostnames  []NameCount        `json:"top_hostnames,omitempty"`
	TopSNI        []NameCount        `json:"top_sni,omitempty"`
	TopApps       []LabelCount       `json:"top_apps,omitempty"`
	TopCategories []LabelCount       `json:"top_categories,omitempty"`
	TopJA4        []FingerprintCount `json:"top_ja4,omitempty"`
	// Per-client byte counters. Tx = client -> remote, Rx = remote -> client.
	TxBytes uint64 `json:"tx_bytes,omitempty"`
	RxBytes uint64 `json:"rx_bytes,omitempty"`
	// BackgroundFlowsPct: 0..1, share of flows whose 30s persistence > 80%.
	// Set by flow.go's persistence detector.
	BackgroundFlowsPct float64 `json:"background_flows_pct,omitempty"`
}

type State struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   int64  `json:"generated_at"`
	Version       string `json:"version"`
	Mode          string `json:"mode"`
	BlindReason   string `json:"blind_reason,omitempty"`
	Interface     string `json:"interface,omitempty"`
	TLSReassembly bool   `json:"tls_reassembly"`
	IPv6Capture   bool   `json:"ipv6_capture"`
	OffloadHint   bool   `json:"offload_hint"`
	UptimeS       int64  `json:"uptime_s"`
	Stats         Stats  `json:"stats"`

	// Devices is legacy / from arp+probe.
	Devices     map[string]Device        `json:"devices"`
	Clients     map[string]ClientProfile `json:"clients,omitempty"`
	ClientCount int                      `json:"client_count"`

	TopHostnames    []NameCount        `json:"top_hostnames,omitempty"`
	TopSNI          []NameCount        `json:"top_sni,omitempty"`
	TopApps         []LabelCount       `json:"top_apps,omitempty"`
	TopCategories   []LabelCount       `json:"top_categories,omitempty"`
	TopJA4          []FingerprintCount `json:"top_ja4,omitempty"`
	TopFingerprints []FingerprintCount `json:"top_fingerprints,omitempty"`
	UniqueHostnames int                `json:"unique_hostnames"`
	UniqueSNI       int                `json:"unique_sni"`
	UniqueJA4       int                `json:"unique_ja4"`

	// rc28.1.x feature gates and version tags.
	L3Enabled      bool   `json:"l3_enabled"`
	L3RuleVersion  string `json:"l3_rule_version,omitempty"`
	DFPEnabled     bool   `json:"dfp_enabled"`
	DFPRuleVersion string `json:"dfp_rule_version,omitempty"`

	// rc30.3: nDPI external classifier availability. NDPIAvailable means
	// ip_to_host.json was read successfully recently (file mtime <5 min old).
	// NDPIEntries is the count of (ip, host) pairs currently cached.
	NDPIAvailable bool `json:"ndpi_available"`
	NDPIEntries   int  `json:"ndpi_entries,omitempty"`

	// Conntrack telemetry.
	ConntrackAvailable bool   `json:"conntrack_available"`
	ConntrackReadable  bool   `json:"conntrack_readable"`
	ConntrackPath      string `json:"conntrack_path,omitempty"`
	ConntrackFlows     int    `json:"conntrack_flows"`

	// Global byte counters (sum across clients).
	TotalTxBytes uint64 `json:"total_tx_bytes,omitempty"`
	TotalRxBytes uint64 `json:"total_rx_bytes,omitempty"`
}

// ─── per-client aggregation ────────────────────────────────────────────

type nameStat struct {
	Count    uint64
	LastSeen int64
}

type labelStat struct {
	ID          string
	Name        string
	Category    string
	Count       uint64
	LastSeen    int64
	Evidence    string
	Verified    bool   // from rule.GroundTruth.Verified
	SubCategory string // set when behavioural detector fired
	Bytes       uint64 // total bytes attributed to this label
	// rc30.4: split byte counters per direction so the history sampler can
	// emit tx/rx deltas per (client, app). Bytes == TxBytes + RxBytes is an
	// invariant maintained by bumpLabelWithBytes.
	TxBytes uint64
	RxBytes uint64
}

type fpStat struct {
	JA4      string
	Client   string
	Version  string
	Category string
	Count    uint64
	LastSeen int64
	// Source = "library" if matched dpi_ja4_fingerprints.json, "observed" otherwise.
	Source string
}

type clientAgg struct {
	ClientIP     string
	ClientMAC    string
	// rc29.2: a single MAC may show up under multiple IPs simultaneously
	// (IPv4 DHCP + IPv6 SLAAC, IPv6 Privacy Extensions rotating, etc.).
	// ClientIPs collects every IP we've ever seen this MAC use, with last-seen
	// time. ClientIP is kept as the "primary" (most recent) for display.
	ClientIPs    map[string]int64
	FirstSeen    int64
	LastSeen     int64
	DNSEvents    uint64
	TLSEvents    uint64
	FlowEvents   uint64
	LastHostname string
	LastSNI      string
	Hostnames    map[string]*nameStat
	SNI          map[string]*nameStat
	Apps         map[string]*labelStat
	Categories   map[string]*labelStat
	JA4          map[string]*fpStat
	RemoteIPs    map[string]int64

	// rc29 byte tracking (per-client).
	TxBytes uint64
	RxBytes uint64

	// rc29 flow persistence tracker.
	Flows *flowTracker
}

// ─── Writer ────────────────────────────────────────────────────────────

type Writer struct {
	mu        sync.Mutex
	state     State
	startTime time.Time
	path      string

	clients          map[string]*clientAgg
	// rc29.2 mac→client-key index. Lets us look up a client by MAC even when
	// the same device has multiple IPs (IPv4 + IPv6 SLAAC/Privacy Extensions).
	// Without this, IPv4 and IPv6 of the same phone produced 2 separate client
	// entries in the map, polluting the active-client list with phantom dups.
	macIndex         map[string]string
	globalDNS        map[string]*nameStat
	globalSNI        map[string]*nameStat
	globalApps       map[string]*labelStat
	globalCategories map[string]*labelStat
	globalJA4        map[string]*fpStat

	// rc29 totals
	totalTx uint64
	totalRx uint64

	// rc30.6: ip→app reverse map for application-granularity rate limiting.
	// Updated on every classification hit; flushed to disk by main.go's
	// IPAppMap flusher goroutine every 30s.
	IPAppMap *IPAppMap
}

func NewWriter(path, version string) *Writer {
	return &Writer{
		path:      path,
		startTime: time.Now(),
		state: State{
			SchemaVersion:  SchemaVersion,
			Version:        version,
			IPv6Capture:    true, // rc29: BPF now passes both IPv4 and IPv6
			Devices:        map[string]Device{},
			L3Enabled:      true,
			L3RuleVersion:  currentL3RuleVersion(),
			DFPEnabled:     true,
			DFPRuleVersion: currentDFPRuleVersion(),
		},
		clients:          make(map[string]*clientAgg),
		macIndex:         make(map[string]string),
		globalDNS:        make(map[string]*nameStat),
		globalSNI:        make(map[string]*nameStat),
		globalApps:       make(map[string]*labelStat),
		globalCategories: make(map[string]*labelStat),
		globalJA4:        make(map[string]*fpStat),
		IPAppMap:         NewIPAppMap(),
	}
}

func (w *Writer) SetMode(mode, reason, iface string, tlsReassembly, offloadHint bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.state.Mode = mode
	w.state.BlindReason = reason
	w.state.Interface = iface
	w.state.TLSReassembly = tlsReassembly
	w.state.OffloadHint = offloadHint
}

func (w *Writer) UpdateStats(s Stats) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.state.Stats = s
}

// UpdateConntrack sets the conntrack telemetry block. Called from main.go
// on a slow ticker (every 15s) by reading /proc/net/nf_conntrack.
func (w *Writer) UpdateConntrack(available, readable bool, path string, flows int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.state.ConntrackAvailable = available
	w.state.ConntrackReadable = readable
	w.state.ConntrackPath = path
	w.state.ConntrackFlows = flows
}

// ─── ingest paths (DNS / TLS / Flow / JA4) ─────────────────────────────

// RecordDNS attributes a DNS qname to the hotspot client seen on the packet.
func (w *Writer) RecordDNS(clientMAC, clientIP, remoteIP, qname string, ts time.Time) {
	host := normalizeName(qname)
	if clientIP == "" && clientMAC == "" {
		return
	}
	now := ts.Unix()
	w.mu.Lock()
	defer w.mu.Unlock()
	c := w.clientLocked(clientMAC, clientIP, now)
	c.DNSEvents++
	c.LastSeen = now
	if remoteIP != "" {
		c.RemoteIPs[remoteIP] = now
	}
	if host != "" {
		c.LastHostname = host
		bumpName(c.Hostnames, host, now, maxNamesPerClient)
		bumpName(w.globalDNS, host, now, maxGlobalNames)
		w.bumpLabelLocked(c, host, now, 0)
	}
}

// RecordTLS attributes a TLS ClientHello SNI (and optional JA4) to a client.
func (w *Writer) RecordTLS(clientMAC, clientIP, remoteIP, sni, ja4 string, ts time.Time) {
	host := normalizeName(sni)
	if clientIP == "" && clientMAC == "" {
		return
	}
	now := ts.Unix()
	w.mu.Lock()
	defer w.mu.Unlock()
	c := w.clientLocked(clientMAC, clientIP, now)
	c.TLSEvents++
	c.LastSeen = now
	if remoteIP != "" {
		c.RemoteIPs[remoteIP] = now
	}
	if host != "" {
		c.LastSNI = host
		bumpName(c.SNI, host, now, maxNamesPerClient)
		bumpName(w.globalSNI, host, now, maxGlobalNames)
		w.bumpLabelLocked(c, host, now, 0)
	}
	if ja4 != "" {
		w.bumpJA4Locked(c, ja4, now)
	}
}

// RecordFlow ingests a TCP/UDP flow first-packet (or follow-up sample).
// remoteIPRaw is the non-client side. isUDP distinguishes the L4 proto;
// port is the destination port (server-side).
// bytes is the size of this packet contribution; pass 0 to only register
// the flow's existence without attributing bytes.
//
// txFromClient is true when bytes went client->remote (uplink); false for
// the reverse direction.
//
// rc29 safety rule: RecordFlow NEVER creates a new client entry. The client
// must already exist (registered by an earlier DNS or TLS event). This is
// the "C" half of the rc29 fix: even if direction inference (assignClient)
// has a bad day and misidentifies a server IP as the "client", we won't
// pollute the clients map — a server IP simply never matches an existing
// known client and the event is dropped silently.
func (w *Writer) RecordFlow(clientMAC, clientIP, remoteIPRaw string, isUDP bool, port uint16, bytes uint64, txFromClient bool, ts time.Time) {
	if clientIP == "" && clientMAC == "" {
		return
	}
	remoteIP := net.ParseIP(remoteIPRaw)
	if remoteIP == nil {
		return
	}
	proto := protoTCP
	if isUDP {
		proto = protoUDP
	}
	now := ts.Unix()
	w.mu.Lock()
	defer w.mu.Unlock()

	c, ok := w.clientLookupLocked(clientMAC, clientIP)
	if !ok {
		// rc29-C: refuse to create from EventFlow. Drop silently.
		return
	}
	c.FlowEvents++
	c.LastSeen = now
	c.RemoteIPs[remoteIPRaw] = now

	// Byte attribution.
	if bytes > 0 {
		if txFromClient {
			c.TxBytes += bytes
			w.totalTx += bytes
		} else {
			c.RxBytes += bytes
			w.totalRx += bytes
		}
	}

	// Classify by IP/IPv6 matchers.
	var rule l3Rule
	if remoteIP.To4() != nil {
		rule, ok = classifyFlowIP(remoteIP, proto, port)
	} else {
		rule, ok = classifyFlowIPv6(remoteIP, proto, port)
	}
	// Update flow persistence regardless of classification.
	if c.Flows == nil {
		c.Flows = newFlowTracker()
	}
	flowKey := remoteIPRaw + ":" + portStr(port)
	pps := c.Flows.observe(flowKey, now, bytes)

	if ok {
		w.applyRuleHitLocked(c, rule, remoteIPRaw, remoteIP, proto, port, bytes, now, pps, txFromClient)
	} else {
		// rc30.3: nDPI fallback. The remote IP didn't match our builtin or
		// external IP matchers — ask the long-running hnc_ndpi_probe pipeline
		// whether it recently observed a SNI/QUIC ServerName at this IP. If
		// so, classify by hostname against the same rule set; this lifts the
		// recognition floor for CDN-shared IPs and brand-new apps without
		// requiring rule maintenance.
		//
		// nDPI is additive: we never reach here when IP matching already won.
		if host, hostOK := lookupNDPIHost(remoteIPRaw); hostOK {
			if hostRule, hostRuleOK := classifyHost(host); hostRuleOK {
				w.applyRuleHitLocked(c, hostRule, "ndpi:"+host, remoteIP, proto, port, bytes, now, pps, txFromClient)
			}
		}
	}
}

// applyRuleHitLocked records a rule match against a client and updates the
// global app/category aggregates. Handles sub-category detection.
//
// rc30.4: txFromClient propagated so per-app byte counters track direction.
// rc30.6: feeds the IP→app reverse map used by application-granularity
// rate limiting (apply_app_limits.sh).
func (w *Writer) applyRuleHitLocked(c *clientAgg, r l3Rule, remoteEvidence string, remoteIP net.IP, proto matchProto, port uint16, bytes uint64, now int64, pps float64, txFromClient bool) {
	subKey, subCat, subHit := classifySubCategory(r, remoteIP, proto, port, pps)

	bumpLabelWithBytes(c.Apps, r.ID, r.Name, r.Category, remoteEvidence, now, bytes, r.Verified, subKey, txFromClient)
	bumpLabelWithBytes(w.globalApps, r.ID, r.Name, r.Category, remoteEvidence, now, bytes, r.Verified, subKey, txFromClient)

	cat := r.Category
	if subHit && subCat != "" {
		cat = subCat
	}
	catName := categoryLabel(cat)
	bumpLabelWithBytes(c.Categories, cat, catName, "", remoteEvidence, now, bytes, r.Verified, "", txFromClient)
	bumpLabelWithBytes(w.globalCategories, cat, catName, "", remoteEvidence, now, bytes, r.Verified, "", txFromClient)

	// rc30.6: record IP→app for downstream limiter. Only record real public
	// remote IPs (not the client itself); we use remoteIP from EventFlow which
	// is already the non-client side.
	if remoteIP != nil && w.IPAppMap != nil && r.ID != "" {
		w.IPAppMap.Record(remoteIP.String(), r.ID, r.Name, now)
	}
}

// bumpLabelLocked is the DNS/SNI path (no bytes, no flow tuple).
// Direction doesn't apply (DNS query is technically tx but bytes=0 here so
// no actual attribution). Pass false; bumpLabelWithBytes drops the rx side
// when bytes==0 anyway.
func (w *Writer) bumpLabelLocked(c *clientAgg, host string, now int64, bytes uint64) {
	r, ok := classifyHost(host)
	if !ok {
		return
	}
	bumpLabelWithBytes(c.Apps, r.ID, r.Name, r.Category, host, now, bytes, r.Verified, "", false)
	bumpLabelWithBytes(w.globalApps, r.ID, r.Name, r.Category, host, now, bytes, r.Verified, "", false)
	catName := categoryLabel(r.Category)
	bumpLabelWithBytes(c.Categories, r.Category, catName, "", host, now, bytes, r.Verified, "", false)
	bumpLabelWithBytes(w.globalCategories, r.Category, catName, "", host, now, bytes, r.Verified, "", false)
}

func (w *Writer) bumpJA4Locked(c *clientAgg, ja4 string, now int64) {
	if c.JA4 == nil {
		c.JA4 = make(map[string]*fpStat)
	}
	lib, libHit := lookupDFP(ja4)
	if c.JA4[ja4] == nil {
		c.JA4[ja4] = &fpStat{JA4: ja4}
		if libHit {
			c.JA4[ja4].Client = lib.Client
			c.JA4[ja4].Version = lib.Version
			c.JA4[ja4].Category = lib.Category
			c.JA4[ja4].Source = "library"
		} else {
			c.JA4[ja4].Source = "observed"
		}
	}
	c.JA4[ja4].Count++
	c.JA4[ja4].LastSeen = now

	if w.globalJA4[ja4] == nil {
		w.globalJA4[ja4] = &fpStat{JA4: ja4}
		if libHit {
			w.globalJA4[ja4].Client = lib.Client
			w.globalJA4[ja4].Version = lib.Version
			w.globalJA4[ja4].Category = lib.Category
			w.globalJA4[ja4].Source = "library"
		} else {
			w.globalJA4[ja4].Source = "observed"
		}
	}
	w.globalJA4[ja4].Count++
	w.globalJA4[ja4].LastSeen = now
}

// ─── per-client helpers ───────────────────────────────────────────────

// rc29.2: clientLocked treats MAC as the primary identity. A single MAC may
// show up under multiple IPs simultaneously (IPv4 + IPv6 SLAAC + Privacy
// Extensions), and we want them all to map to the same clientAgg so the
// active-device UI shows one device with multiple IPs, not 2-3 phantom
// duplicates of the same phone.
//
// Lookup order: macIndex[mac] → clients[ip] → clients[mac as key]. Creation
// uses MAC as the new client's map key when available, IP otherwise.
func (w *Writer) clientLocked(mac, ip string, now int64) *clientAgg {
	macKey := strings.ToLower(strings.TrimSpace(mac))
	ipKey := strings.TrimSpace(ip)

	// 1) prefer MAC index — same MAC, different IP → reuse existing client.
	if macKey != "" {
		if k, ok := w.macIndex[macKey]; ok {
			if c, ok2 := w.clients[k]; ok2 {
				return w.touchClientIPLocked(c, ip, now)
			}
			delete(w.macIndex, macKey) // stale index entry, fall through
		}
	}

	// 2) fall back to direct IP key (legacy behavior).
	if ipKey != "" {
		if c, ok := w.clients[ipKey]; ok {
			// Bind macIndex now if we have a MAC for the first time.
			if macKey != "" && c.ClientMAC == "" {
				c.ClientMAC = mac
				w.macIndex[macKey] = ipKey
			}
			return w.touchClientIPLocked(c, ip, now)
		}
	}

	// 3) create new. Map key preference: MAC > IP > "unknown".
	key := macKey
	if key == "" {
		key = ipKey
	}
	if key == "" {
		key = "unknown"
	}
	if len(w.clients) >= maxClients {
		if _, ok := w.clients[key]; !ok {
			w.evictOldestClientLocked()
		}
	}
	c := w.clients[key]
	if c == nil {
		c = &clientAgg{
			ClientIP:   ip,
			ClientMAC:  mac,
			ClientIPs:  make(map[string]int64),
			FirstSeen:  now,
			LastSeen:   now,
			Hostnames:  make(map[string]*nameStat),
			SNI:        make(map[string]*nameStat),
			Apps:       make(map[string]*labelStat),
			Categories: make(map[string]*labelStat),
			JA4:        make(map[string]*fpStat),
			RemoteIPs:  make(map[string]int64),
		}
		w.clients[key] = c
	}
	if c.ClientIPs == nil {
		c.ClientIPs = make(map[string]int64)
	}
	if ipKey != "" {
		c.ClientIPs[ipKey] = now
	}
	if c.ClientIP == "" && ip != "" {
		c.ClientIP = ip
	}
	if c.ClientMAC == "" && mac != "" {
		c.ClientMAC = mac
	}
	if macKey != "" {
		w.macIndex[macKey] = key
	}
	return c
}

// touchClientIPLocked records that this client was just seen under ip and
// updates ClientIP to the most recent IP (so display shows a stable, current
// address rather than a stale Privacy-Extensions IP from yesterday).
func (w *Writer) touchClientIPLocked(c *clientAgg, ip string, now int64) *clientAgg {
	if c.ClientIPs == nil {
		c.ClientIPs = make(map[string]int64)
	}
	ipKey := strings.TrimSpace(ip)
	if ipKey != "" {
		c.ClientIPs[ipKey] = now
		// Prefer IPv4 as the "primary" ClientIP for display when available;
		// otherwise the most recent IPv6.
		if c.ClientIP == "" {
			c.ClientIP = ip
		} else if !strings.Contains(c.ClientIP, ".") && strings.Contains(ip, ".") {
			// current primary is IPv6, new packet is IPv4 → prefer IPv4
			c.ClientIP = ip
		}
	}
	return c
}

// clientLookupLocked returns an existing client without creating one.
// rc29-C uses this from RecordFlow to refuse implicit creation by EventFlow.
// rc29.2 priority: MAC index → IP key → MAC scan. Returns (nil, false) if no match.
func (w *Writer) clientLookupLocked(mac, ip string) (*clientAgg, bool) {
	macKey := strings.ToLower(strings.TrimSpace(mac))
	if macKey != "" {
		if k, ok := w.macIndex[macKey]; ok {
			if c, ok2 := w.clients[k]; ok2 {
				return c, true
			}
		}
	}
	if ip != "" {
		if c, ok := w.clients[strings.TrimSpace(ip)]; ok {
			return c, true
		}
	}
	if mac != "" {
		// last-resort scan for a client whose MAC matches but isn't indexed.
		for _, c := range w.clients {
			if c.ClientMAC != "" && strings.EqualFold(c.ClientMAC, mac) {
				return c, true
			}
		}
	}
	return nil, false
}

func (w *Writer) evictOldestClientLocked() {
	var oldestKey string
	var oldest int64
	for k, c := range w.clients {
		if oldestKey == "" || c.LastSeen < oldest {
			oldestKey = k
			oldest = c.LastSeen
		}
	}
	if oldestKey != "" {
		// rc29.2: also drop any macIndex entries pointing at this key, otherwise
		// future lookups would hit a stale index and miss.
		if evicted, ok := w.clients[oldestKey]; ok && evicted.ClientMAC != "" {
			delete(w.macIndex, strings.ToLower(evicted.ClientMAC))
		}
		delete(w.clients, oldestKey)
	}
}

// normalizeName: lowercase, strip trailing dot, validate hostname charset.
// Used for DNS qnames and SNI strings (both should be valid hostnames).
func normalizeName(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return ""
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' || r == ':' {
			continue
		}
		return ""
	}
	return s
}

func bumpName(m map[string]*nameStat, name string, now int64, limit int) {
	if name == "" {
		return
	}
	st := m[name]
	if st == nil {
		if limit > 0 && len(m) >= limit {
			evictOldestName(m)
		}
		st = &nameStat{}
		m[name] = st
	}
	st.Count++
	st.LastSeen = now
}

func evictOldestName(m map[string]*nameStat) {
	var oldestKey string
	var oldest int64
	for k, v := range m {
		if oldestKey == "" || v.LastSeen < oldest {
			oldestKey = k
			oldest = v.LastSeen
		}
	}
	if oldestKey != "" {
		delete(m, oldestKey)
	}
}

// bumpLabelWithBytes records: verified (from ground_truth), sub-category key,
// byte attribution.
func bumpLabelWithBytes(m map[string]*labelStat, id, name, category, evidence string, now int64, bytes uint64, verified bool, subKey string, txFromClient bool) {
	if id == "" {
		return
	}
	st := m[id]
	if st == nil {
		st = &labelStat{ID: id, Name: name, Category: category, Verified: verified}
		m[id] = st
	}
	st.Count++
	st.LastSeen = now
	if evidence != "" {
		st.Evidence = evidence
	}
	if verified {
		st.Verified = true
	}
	if subKey != "" {
		st.SubCategory = subKey
	}
	st.Bytes += bytes
	// rc30.4: split attribution per direction. DNS/SNI events pass bytes=0
	// so direction is irrelevant for them; only EventFlow contributes here.
	if txFromClient {
		st.TxBytes += bytes
	} else {
		st.RxBytes += bytes
	}
}

// topNames sorts a name map by Count desc, then LastSeen desc, then Name asc.
func topNames(m map[string]*nameStat, n int) []NameCount {
	out := make([]NameCount, 0, len(m))
	for name, st := range m {
		out = append(out, NameCount{Name: name, Count: st.Count, LastSeen: st.LastSeen})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return out[i].Name < out[j].Name
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// topLabels emits LabelCount items including rc29 fields.
func topLabels(m map[string]*labelStat, n int) []LabelCount {
	out := make([]LabelCount, 0, len(m))
	for _, st := range m {
		conf := confidenceFor(st)
		out = append(out, LabelCount{
			ID:          st.ID,
			Name:        st.Name,
			Category:    st.Category,
			Count:       st.Count,
			LastSeen:    st.LastSeen,
			Evidence:    st.Evidence,
			Confidence:  conf,
			SubCategory: st.SubCategory,
			Bytes:       st.Bytes,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return out[i].Name < out[j].Name
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func topFingerprints(m map[string]*fpStat, n int) []FingerprintCount {
	out := make([]FingerprintCount, 0, len(m))
	for _, st := range m {
		conf := ""
		switch st.Source {
		case "library":
			conf = "high"
		case "observed":
			conf = "low"
		}
		out = append(out, FingerprintCount{
			JA4:        st.JA4,
			Client:     st.Client,
			Version:    st.Version,
			Category:   st.Category,
			Count:      st.Count,
			LastSeen:   st.LastSeen,
			Confidence: conf,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].LastSeen > out[j].LastSeen
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// confidenceFor returns "high"/"medium"/"low" per label, based on ground-truth
// + observed evidence count. This is read by WebUI for badge rendering.
func confidenceFor(st *labelStat) string {
	if st.Verified && st.Count >= 5 {
		return "high"
	}
	if st.Verified || st.Count >= 20 {
		return "medium"
	}
	return "low"
}

func categoryLabel(id string) string {
	switch id {
	case "video":
		return "视频"
	case "social":
		return "社交"
	case "social_voip":
		return "社交·通话"
	case "download":
		return "下载"
	case "system":
		return "系统服务"
	case "ads":
		return "广告/统计"
	case "game":
		return "游戏"
	case "cloud":
		return "云/CDN"
	case "music":
		return "音乐"
	case "education":
		return "教育"
	case "shopping":
		return "购物"
	case "dns":
		return "DNS"
	default:
		return id
	}
}

func recentRemoteIPs(m map[string]int64, n int) []string {
	type kv struct {
		ip   string
		last int64
	}
	arr := make([]kv, 0, len(m))
	for ip, last := range m {
		arr = append(arr, kv{ip, last})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].last > arr[j].last })
	if n > 0 && len(arr) > n {
		arr = arr[:n]
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		out = append(out, x.ip)
	}
	return out
}

func portStr(p uint16) string {
	// Inline base-10 itoa.
	if p == 0 {
		return "0"
	}
	var buf [6]byte
	i := len(buf)
	for p > 0 {
		i--
		buf[i] = byte('0' + p%10)
		p /= 10
	}
	return string(buf[i:])
}

// ─── Flush: build State snapshot and atomically write JSON ─────────────

func (w *Writer) Flush() error {
	w.mu.Lock()
	snap := w.state
	snap.SchemaVersion = SchemaVersion
	snap.GeneratedAt = time.Now().Unix()
	snap.UptimeS = int64(time.Since(w.startTime).Seconds())
	if len(w.state.Devices) > 0 {
		snap.Devices = make(map[string]Device, len(w.state.Devices))
		for k, v := range w.state.Devices {
			snap.Devices[k] = v
		}
	} else {
		snap.Devices = map[string]Device{}
	}
	snap.Clients = make(map[string]ClientProfile, len(w.clients))
	for key, c := range w.clients {
		bgPct := 0.0
		if c.Flows != nil {
			bgPct = c.Flows.backgroundShare(snap.GeneratedAt)
		}
		cp := ClientProfile{
			ClientIP:           c.ClientIP,
			ClientMAC:          c.ClientMAC,
			ClientIPs:          recentRemoteIPs(c.ClientIPs, 4), // rc29.2
			RemoteIPs:          recentRemoteIPs(c.RemoteIPs, 6),
			FirstSeen:          c.FirstSeen,
			LastSeen:           c.LastSeen,
			DNSEvents:          c.DNSEvents,
			TLSEvents:          c.TLSEvents,
			FlowEvents:         c.FlowEvents,
			LastHostname:       c.LastHostname,
			LastSNI:            c.LastSNI,
			TopHostnames:       topNames(c.Hostnames, topN),
			TopSNI:             topNames(c.SNI, topN),
			TopApps:            topLabels(c.Apps, topN),
			TopCategories:      topLabels(c.Categories, topN),
			TopJA4:             topFingerprints(c.JA4, topN),
			TxBytes:            c.TxBytes,
			RxBytes:            c.RxBytes,
			BackgroundFlowsPct: bgPct,
		}
		snap.Clients[key] = cp
	}
	snap.ClientCount = len(w.clients)
	snap.TopHostnames = topNames(w.globalDNS, topN)
	snap.TopSNI = topNames(w.globalSNI, topN)
	snap.TopApps = topLabels(w.globalApps, topN)
	snap.TopCategories = topLabels(w.globalCategories, topN)
	snap.TopJA4 = topFingerprints(w.globalJA4, topN)
	snap.TopFingerprints = snap.TopJA4 // alias for rc28.1.1 compatibility
	snap.UniqueHostnames = len(w.globalDNS)
	snap.UniqueSNI = len(w.globalSNI)
	snap.UniqueJA4 = len(w.globalJA4)
	snap.L3Enabled = true
	snap.L3RuleVersion = currentL3RuleVersion()
	snap.DFPEnabled = true
	snap.DFPRuleVersion = currentDFPRuleVersion()
	// rc30.3: nDPI status. ndpiAvailable() returns true only when ip_to_host.json
	// was loaded successfully and is fresh (<5min). Safe to call under w.mu —
	// ndpi_lookup.go uses its own dedicated lock.
	snap.NDPIAvailable = ndpiAvailable()
	snap.NDPIEntries = ndpiEntryCount()
	snap.TotalTxBytes = w.totalTx
	snap.TotalRxBytes = w.totalRx
	w.mu.Unlock()

	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(w.path, b, 0o644)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
