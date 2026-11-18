// dpi_sidechan.go — v5.34: 桥接 dpid 亚秒级侧信道特征 + 热点外部客户端无真值一致性自检与 IPv6 限速逃逸检测
package main

import (
	"bufio"
	"encoding/json"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// fgMicroFeat 单个 (MAC, AppID) 在本采样周期 dt 内的亚秒级触控因果与挥手特征
type fgMicroFeat struct {
	CausalTurns int     // 本轮新增因果请求-响应微突发回合
	LightTurns  int     // 本轮新增轻量 IM 回合 (解决纯文字聊天漏判)
	D2CVerified int     // 本轮新增载荷确认的 <=150ms DNS->握手紧耦合次数
	CloseEvents int     // 本轮新增 TCP FIN/RST 主动挥手次数
	D2CImpulse  float64 // 指数衰减紧耦合脉冲强度
	IBTCV       float64 // 在线到达间隔变异系数 CV = σ/μ
	IBTEntropy  float64 // 8 档对数倍频程归一化香农熵 ∈ [0, 1]
	Periodicity float64 // 一阶/二阶等间隔周期定时器锁定度 ∈ [0, 1]
}

// fgDevSideHint 单台设备的无线/推送与双栈辅助状态
type fgDevSideHint struct {
	LastPushWakeAt int64
	V6RxBytes      uint64
	V6TxBytes      uint64
	AppLimitsMbps  map[string]float64 // app_id -> configured down_mbps (for IPv6 escape detection)
}

type dpiBurstRaw struct {
	CausalTurns uint32  `json:"causal_turns"`
	LightTurns  uint32  `json:"light_turns"`
	D2CVerified uint32  `json:"d2c_verified"`
	CloseEvents uint32  `json:"close_events"`
	D2CImpulse  float64 `json:"d2c_impulse"`
	IBTCV       float64 `json:"ibt_cv"`
	IBTEntropy  float64 `json:"ibt_entropy"`
	Periodicity float64 `json:"periodicity"`
}

type dpiClientSideRaw struct {
	ClientMAC      string                 `json:"client_mac"`
	ClientIPs      []string               `json:"client_ips"`
	TxBytes        uint64                 `json:"tx_bytes"`
	RxBytes        uint64                 `json:"rx_bytes"`
	V6TxBytes      uint64                 `json:"v6_tx_bytes"`
	V6RxBytes      uint64                 `json:"v6_rx_bytes"`
	LastPushWakeAt int64                  `json:"last_push_wake_at"`
	FlowDSCPClass  map[string]uint8       `json:"flow_dscp_class"`
	AppMicroBursts map[string]dpiBurstRaw `json:"app_micro_bursts"`
}

type dpiSideState struct {
	mu       sync.Mutex
	mtimeKey string
	byMAC    map[string]dpiClientSideRaw
	prevMB   map[string]dpiBurstRaw // key: mac + "|" + appID
}

var globalSideSt = &dpiSideState{
	byMAC:  map[string]dpiClientSideRaw{},
	prevMB: map[string]dpiBurstRaw{},
}

func satSubU32(cur, prev uint32) int {
	if cur >= prev {
		return int(cur - prev)
	}
	return int(cur) // dpid 重启回零时取当前值
}

// loadSidechanSnapshot 按 mtime+size 轻量读取 run/dpi_state.json 与 data/app_limits.flat
func loadSidechanSnapshot(hncDir string) (map[string]map[string]uint8, map[string]map[string]fgMicroFeat, map[string]fgDevSideHint) {
	if hncDir == "" {
		return nil, nil, nil
	}
	p := filepath.Join(hncDir, "run", "dpi_state.json")
	fi, err := os.Stat(p)
	if err != nil || fi.Size() <= 0 || fi.Size() > 8<<20 {
		return nil, nil, nil
	}
	mkey := strconv.FormatInt(fi.ModTime().UnixNano(), 10) + ":" + strconv.FormatInt(fi.Size(), 10)

	globalSideSt.mu.Lock()
	defer globalSideSt.mu.Unlock()

	if globalSideSt.mtimeKey != mkey {
		if b, err := os.ReadFile(p); err == nil {
			var doc struct {
				Clients map[string]dpiClientSideRaw `json:"clients"`
			}
			if json.Unmarshal(b, &doc) == nil && doc.Clients != nil {
				next := make(map[string]dpiClientSideRaw, len(doc.Clients))
				for _, c := range doc.Clients {
					mac := strings.ToLower(strings.TrimSpace(c.ClientMAC))
					if mac != "" {
						next[mac] = c
					}
				}
				globalSideSt.byMAC = next
				globalSideSt.mtimeKey = mkey
			}
		}
	}

	// 读取应用限速配置以供双栈逃逸检测对照
	limByMAC := map[string]map[string]float64{}
	if lf, err := os.Open(filepath.Join(hncDir, "data", "app_limits.flat")); err == nil {
		sc := bufio.NewScanner(lf)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) >= 3 && !strings.HasPrefix(fs[0], "#") {
				mac := strings.ToLower(fs[0])
				rate, err := strconv.ParseFloat(fs[2], 64)
				if err == nil && rate > 0 {
					if limByMAC[mac] == nil {
						limByMAC[mac] = map[string]float64{}
					}
					limByMAC[mac][fs[1]] = rate
				}
			}
		}
		_ = lf.Close()
	}

	dscpByMAC := make(map[string]map[string]uint8, len(globalSideSt.byMAC))
	microByMAC := make(map[string]map[string]fgMicroFeat, len(globalSideSt.byMAC))
	hintsByMAC := make(map[string]fgDevSideHint, len(globalSideSt.byMAC))

	for mac, c := range globalSideSt.byMAC {
		if len(c.FlowDSCPClass) > 0 {
			dscpByMAC[mac] = c.FlowDSCPClass
		}
		hintsByMAC[mac] = fgDevSideHint{
			LastPushWakeAt: c.LastPushWakeAt,
			V6RxBytes:      c.V6RxBytes,
			V6TxBytes:      c.V6TxBytes,
			AppLimitsMbps:  limByMAC[mac],
		}
		if len(c.AppMicroBursts) > 0 {
			mm := make(map[string]fgMicroFeat, len(c.AppMicroBursts))
			for appID, cur := range c.AppMicroBursts {
				pk := mac + "|" + appID
				prev, had := globalSideSt.prevMB[pk]
				globalSideSt.prevMB[pk] = cur
				mf := fgMicroFeat{
					D2CImpulse:  cur.D2CImpulse,
					IBTCV:       cur.IBTCV,
					IBTEntropy:  cur.IBTEntropy,
					Periodicity: cur.Periodicity,
				}
				if had {
					mf.CausalTurns = satSubU32(cur.CausalTurns, prev.CausalTurns)
					mf.LightTurns = satSubU32(cur.LightTurns, prev.LightTurns)
					mf.D2CVerified = satSubU32(cur.D2CVerified, prev.D2CVerified)
					mf.CloseEvents = satSubU32(cur.CloseEvents, prev.CloseEvents)
				} else {
					// 首次观测保守计入最近单回合上限
					if cur.CausalTurns > 0 {
						mf.CausalTurns = 1
					}
					if cur.LightTurns > 0 {
						mf.LightTurns = 1
					}
				}
				mm[appID] = mf
			}
			microByMAC[mac] = mm
		}
	}
	if len(globalSideSt.prevMB) > 4096 {
		globalSideSt.prevMB = map[string]dpiBurstRaw{}
	}
	return dscpByMAC, microByMAC, hintsByMAC
}

// dscpClassForDelta 匹配 conntrack 连接对应的上行 DSCP 等级 (1=Low, 2=Interactive, 3=Realtime)
func dscpClassForDelta(flowMap map[string]uint8, proto, dst string, dport int) uint8 {
	if len(flowMap) == 0 || dst == "" || dport <= 0 {
		return 0
	}
	pCh := "T"
	if proto == "udp" {
		pCh = "U"
	}
	return flowMap[pCh+"|"+dst+":"+strconv.Itoa(dport)]
}

// ─── 热点外部客户端无真值一致性自检 (GET /api/dpi_eval -> lan_self_consistency) ──

type dpiLANConflictItem struct {
	Host    string `json:"host"`
	DNSApp  string `json:"dns_app"`
	RuleApp string `json:"rule_app"`
}

type dpiLANSelfConsistency struct {
	CheckedIPs         int                  `json:"checked_ips"`
	PairedDualStack    int                  `json:"paired_dual_stack"`
	CMConflictRate     float64              `json:"cm_conflict_rate"`
	HEV4V6Parity       float64              `json:"he_v4v6_parity"`
	ActiveEscapeAlerts int                  `json:"active_escape_alerts"`
	TopConflicts       []dpiLANConflictItem `json:"top_conflicts,omitempty"`
}

func evalLANSelfConsistency(hncDir string, now time.Time) *dpiLANSelfConsistency {
	if hncDir == "" {
		return nil
	}
	ipMapRaw, err1 := os.ReadFile(filepath.Join(hncDir, "run", "ip_app_map.json"))
	ipNameRaw, err2 := os.ReadFile(filepath.Join(hncDir, "run", "dpi_ipname.json"))
	if err1 != nil && err2 != nil {
		return nil
	}
	var ipm struct {
		Entries []struct {
			IP    string `json:"ip"`
			AppID string `json:"app_id"`
		} `json:"entries"`
	}
	_ = json.Unmarshal(ipMapRaw, &ipm)
	type ipNameItem struct {
		Name string `json:"name"`
		App  string `json:"app"`
	}
	var ipnWrap struct {
		Entries map[string]ipNameItem `json:"entries"`
	}
	var ipn map[string]ipNameItem
	if json.Unmarshal(ipNameRaw, &ipnWrap) == nil && len(ipnWrap.Entries) > 0 {
		ipn = ipnWrap.Entries
	} else {
		_ = json.Unmarshal(ipNameRaw, &ipn)
	}

	shared := loadSharedInfra(hncDir)
	isSharedHost := func(h string) bool {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || strings.Contains(h, "cloudflare-ech") {
			return true
		}
		for sfx := range shared {
			if h == sfx || strings.HasSuffix(h, "."+sfx) {
				return true
			}
		}
		return false
	}

	checked := 0
	conflicts := 0
	var topC []dpiLANConflictItem
	byHost := map[string]struct{ v4App, v6App string }{}

	for _, e := range ipm.Entries {
		if e.IP == "" || e.AppID == "" {
			continue
		}
		nm, ok := ipn[e.IP]
		if !ok || nm.Name == "" || isSharedHost(nm.Name) {
			continue
		}
		if nm.App != "" {
			checked++
			if nm.App != e.AppID {
				conflicts++
				if len(topC) < 5 {
					topC = append(topC, dpiLANConflictItem{Host: nm.Name, DNSApp: nm.App, RuleApp: e.AppID})
				}
			}
		}
		rec := byHost[nm.Name]
		if nip := net.ParseIP(e.IP); nip != nil {
			if nip.To4() != nil {
				rec.v4App = e.AppID
			} else {
				rec.v6App = e.AppID
			}
			byHost[nm.Name] = rec
		}
	}

	pairedDS, sameDS := 0, 0
	for _, r := range byHost {
		if r.v4App != "" && r.v6App != "" {
			pairedDS++
			if r.v4App == r.v6App {
				sameDS++
			}
		}
	}

	cmRate := 0.0
	if checked > 0 {
		cmRate = math.Round(float64(conflicts)/float64(checked)*1000) / 1000
	}
	parity := 1.0
	if pairedDS > 0 {
		parity = math.Round(float64(sameDS)/float64(pairedDS)*1000) / 1000
	}

	escapes := fgSt.countActiveEscapes(now)
	return &dpiLANSelfConsistency{
		CheckedIPs:         checked,
		PairedDualStack:    pairedDS,
		CMConflictRate:     cmRate,
		HEV4V6Parity:       parity,
		ActiveEscapeAlerts: escapes,
		TopConflicts:       topC,
	}
}
