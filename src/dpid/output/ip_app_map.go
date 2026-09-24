// Package output - ip_app_map.go: writes a (remote_ip → app_id) mapping
// derived from the live classifier hits, for downstream consumption by
// the apply_app_limits.sh shell tool that maintains per-(mac, app)
// iptables MARK + tc class rules.
//
// Data shape (run/ip_app_map.json):
//
//   {
//     "generated_ts": 1700000000,
//     "entries": [
//       {"ip": "1.2.3.4", "app_id": "douyin", "name": "抖音", "last_seen": 1699999990},
//       ...
//     ]
//   }
//
// Update cadence: written every 30 seconds by the IPAppMapFlusher goroutine
// in main.go. Entries older than 5 minutes are pruned — by then the IP
// likely belongs to a different CDN tenant and re-marking would mislead.
//
// CDN tenant collisions are unavoidable: one IP can serve multiple apps.
// Last-writer-wins is the chosen policy — this is a pragmatic LIFO that
// matches user mental model ("I just hit Douyin, the limit should kick in"),
// at the cost of brief mis-marking when an IP is rapidly multiplexed.

package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// Default output path. main.go can override via SetIPAppMapPath.
	defaultIPAppMapPath = "/data/local/hnc/run/ip_app_map.json"

	// Entries older than this on flush are dropped. 5 min matches the
	// shell sync cadence: longer windows risk stale mis-mapping.
	ipAppMapMaxAge = 5 * time.Minute

	// Cap on entries written. Above this the file becomes a perf concern
	// for the shell readers; we drop the oldest.
	ipAppMapMaxEntries = 2000
)

type IPAppObs struct {
	IP       string `json:"ip"`
	AppID    string `json:"app_id"`
	Name     string `json:"name,omitempty"`
	LastSeen int64  `json:"last_seen"`
	Src      string `json:"src,omitempty"` // "flow", "tls", "dns"
	// v5.14: 规则分类。下游(httpd「正在用」、apply_app_limits)据此区分真应用与
	// 广告/统计 SDK/CDN 等共用基础设施。
	Category string `json:"category,omitempty"`
}

type ipAppMapFile struct {
	GeneratedTs int64      `json:"generated_ts"`
	Entries     []IPAppObs `json:"entries"`
}

// IPAppMap is a thread-safe in-memory store updated on the hot path
// (every classified flow) and flushed periodically.
type IPAppMap struct {
	mu      sync.Mutex
	entries map[string]*IPAppObs // ip → most recent observation
	path    string
}

func NewIPAppMap() *IPAppMap {
	return &IPAppMap{
		entries: map[string]*IPAppObs{},
		path:    defaultIPAppMapPath,
	}
}

func (m *IPAppMap) SetPath(p string) {
	m.mu.Lock()
	m.path = p
	m.mu.Unlock()
}

// Record updates the map. Called from EventFlow / applyRuleHitLocked
// hot path; must be cheap. Last-writer-wins for the IP.
// src indicates the attribution source: "flow", "tls", or "dns".
func (m *IPAppMap) Record(ip, appID, name, category string, now int64, src string) {
	if ip == "" || appID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[ip]
	if e == nil {
		e = &IPAppObs{IP: ip}
		m.entries[ip] = e
	}
	// v5.14: 共用 IP 上的 SDK/广告命中不覆盖近期的真应用归属。旧的"后写者胜"
	// 会让友盟/穿山甲这类几十个 App 共用的域名把抖音的 IP 抢走, 「正在用」
	// 与应用级限速都跟着错。真应用条目 2 分钟内只被真应用覆盖。
	if e.AppID != "" && e.AppID != appID && AppTier(e.Category) == TierApp &&
		AppTier(category) != TierApp && now-e.LastSeen < ipAppKeepRealSec {
		return
	}
	e.AppID = appID
	e.Name = name
	e.Category = category
	e.LastSeen = now
	e.Src = src
}

const ipAppKeepRealSec = 120

// 应用分级(v5.14)。httpd 的 appTier(daemon/hnc_httpd/api_conn.go)是同一张表的
// 副本, 改这里要同步改那边。
const (
	TierApp    = 0 // 用户能感知的应用: 视频/社交/游戏/购物…
	TierSystem = 1 // 系统/ROM 服务: 没有真应用时才显示
	TierHidden = 2 // 广告/统计 SDK、CDN、云厂商、基础设施: 不当成"在用的应用"
)

// AppTier 按规则 category 给出分级。
func AppTier(category string) int {
	c := strings.ToLower(strings.TrimSpace(category))
	switch c {
	case "ads", "ad-sdk", "infrastructure", "third_party_telemetry", "system_telemetry_baseline",
		"cloud", "cdn", "behavior-marker", "meta-warning", "p2p-unknown", "third_party_financial",
		"system_chipset":
		return TierHidden
	case "system":
		return TierSystem
	}
	if strings.HasPrefix(c, "sdk") {
		return TierHidden
	}
	if strings.HasPrefix(c, "system-") || strings.HasPrefix(c, "system_") {
		return TierSystem
	}
	return TierApp
}

// Flush writes the current map to disk atomically. Prunes stale entries
// and caps total size. Writes both the JSON file (for tools / future use)
// and a flat plain-text file (ip<space>app_id, one per line) that shell
// scripts can read without a JSON parser — Android base doesn't ship jq.
func (m *IPAppMap) Flush(now time.Time) error {
	m.mu.Lock()
	cutoff := now.Add(-ipAppMapMaxAge).Unix()
	out := make([]IPAppObs, 0, len(m.entries))
	for ip, e := range m.entries {
		if e.LastSeen < cutoff {
			delete(m.entries, ip)
			continue
		}
		out = append(out, *e)
	}
	path := m.path
	m.mu.Unlock()

	// Sort newest-first (clearer for shell reader debug).
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen > out[j].LastSeen })
	if len(out) > ipAppMapMaxEntries {
		out = out[:ipAppMapMaxEntries]
	}

	f := ipAppMapFile{
		GeneratedTs: now.Unix(),
		Entries:     out,
	}
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}

	// Flat companion file (ip app_id, one per line). Used by
	// apply_app_limits.sh — no JSON parser dependency.
	// Path: same dir, ".flat" replacing ".json" suffix
	// (e.g. /run/ip_app_map.json → /run/ip_app_map.flat).
	flatPath := path
	if l := len(flatPath); l > 5 && flatPath[l-5:] == ".json" {
		flatPath = flatPath[:l-5] + ".flat"
	} else {
		flatPath = flatPath + ".flat"
	}
	var flat []byte
	for _, e := range out {
		flat = append(flat, []byte(e.IP+" "+e.AppID+"\n")...)
	}
	tmpFlat := flatPath + ".tmp"
	if err := os.WriteFile(tmpFlat, flat, 0o644); err != nil {
		return nil // best-effort
	}
	return os.Rename(tmpFlat, flatPath)
}

// Size returns the current map cardinality. Used for stats.
func (m *IPAppMap) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// Used to keep fmt import alive without exposing a debug helper.
var _ = fmt.Sprintf
