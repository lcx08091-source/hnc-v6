// v6_update_leash.go — HNC v6.0.0 · Vector (T4 模块 3):
// UpdateLeash 200MB 免死缓冲 + 后台系统/游戏巨兽温柔拴绳引擎。
//
// 核心机制:
//   1. 规则联动: 自动加载 data/dpi_rules.d/96-system-updates-v6.json (及 etc/dpi_rules.d 副本 + 内置兜底),
//      精准识别 Windows Update / Delivery Optimization、Apple 系统更新、Steam 大包更新及主机/ROM OTA。
//   2. 200MB 免死缓冲: 单向更新大流前 grace_mb (默认 200 MB) 100% 满速放行, 绝不误伤小补丁、插件与商店浏览。
//   3. 温柔拴绳: 累计下行达到或超过 grace_mb 后, 自动将该单向大流温和压制到 leash_kbps (默认 1500 Kbps),
//      同时支持一键 "bypass_once" 本次全速放行与一键 "pause_update" / "resume_update" 直联 conn_blocks 暂停!

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	leashDefaultGraceMB   = 200
	leashMinGraceMB       = 10
	leashMaxGraceMB       = 10240
	leashDefaultKbps      = 1500
	leashMinKbps          = 128
	leashMaxKbps          = 1000000
	leashFlowIdleExpire   = 10 * time.Minute
	leashUnidirMaxUpRatio = 0.25 // 上行/下行 < 25% 才视为单向大包下载, 绝不误伤双向联机游戏流

	leashStateGrace    = "grace_fullspeed"
	leashStateLeashed  = "leashed"
	leashStateBypassed = "bypassed"
	leashStatePaused   = "paused"

	leashMangleChainName = "HNC_V6_LEASH"
)

// 内置官方大包更新域名兜底集合（与 96-system-updates-v6.json 保持一致, 防测试空目录缺失规则文件）。
var builtinSystemUpdateSuffixes = []string{
	"dl.delivery.mp.microsoft.com",
	"do.dsp.mp.microsoft.com",
	"tlu.dl.delivery.mp.microsoft.com",
	"au.download.windowsupdate.com",
	"fg.ds.b1.download.windowsupdate.com",
	"emdl.ws.microsoft.com",
	"windowsupdate.com",
	"delivery.mp.microsoft.com",
	"swcdn.apple.com",
	"updates.cdn-apple.com",
	"updates-http.cdn-apple.com",
	"mesu.apple.com",
	"gdmf.apple.com",
	"oscdn.apple.com",
	"gg.apple.com",
	"gs.apple.com",
	"steamcontent.com",
	"lancache.steamcontent.com",
	"cache.steamcontent.com",
	"ota.googlezip.net",
	"assets1.xboxlive.com",
	"assets2.xboxlive.com",
	"gs2.ww.prod.dl.playstation.net",
}

var builtinUpdateRuleIDs = map[string]bool{
	"windows_update_v6":          true,
	"apple_system_update_v6":     true,
	"steam_bulk_update_v6":       true,
	"console_rom_ota_v6":         true,
	"playstation_xbox_update_v6": true,
	"android_rom_ota_v6":         true,
	"microsoft_update":           true,
	"apple_update":               true,
}

// UpdateLeashConfig 配置结构（直接数字型 grace_mb 与 leash_kbps）。
type UpdateLeashConfig struct {
	Enabled   bool `json:"enabled"`
	GraceMB   int  `json:"grace_mb"`
	LeashKbps int  `json:"leash_kbps"`
}

func defaultUpdateLeashConfig() UpdateLeashConfig {
	return UpdateLeashConfig{
		Enabled:   true,
		GraceMB:   leashDefaultGraceMB,
		LeashKbps: leashDefaultKbps,
	}
}

// UpdateFlowInput 单条观测流输入（支持 conntrack 自动采集与单元测试直接喂入）。
type UpdateFlowInput struct {
	FlowKey   string
	MAC       string
	SrcIP     string
	DstIP     string
	DstHost   string
	AppID     string
	AppName   string
	Proto     string
	UpBytes   uint64
	DownBytes uint64
	DownBps   int64
}

// UpdateLeashSession 单个更新会话跟踪记录。
type UpdateLeashSession struct {
	SessionKey      string `json:"session_key"`
	MAC             string `json:"mac"`
	DeviceName      string `json:"device_name"`
	SrcIP           string `json:"src_ip,omitempty"`
	DstHost         string `json:"dst_host"`
	DstIP           string `json:"dst_ip,omitempty"`
	VendorLabel     string `json:"vendor_label"`
	DownBytes       uint64 `json:"down_bytes"`
	UpBytes         uint64 `json:"up_bytes"`
	DownBps         int64  `json:"down_bps"`
	GraceLimitBytes uint64 `json:"grace_limit_bytes"`
	GraceRemainingB uint64 `json:"grace_remaining_bytes"`
	AppliedKbps     int    `json:"applied_kbps"` // 0 = 100% 满速无干预
	State           string `json:"state"`        // grace_fullspeed | leashed | bypassed | paused
	BypassOnce      bool   `json:"bypass_once"`
	Paused          bool   `json:"paused"`
	FirstSeen       int64  `json:"first_seen"`
	UpdatedAt       int64  `json:"updated_at"`

	lastFlowTotals map[string]uint64
	accumFromEnded uint64
	updatedTime    time.Time
}

type updateLeashEngine struct {
	// 64 位原子字段严格置于 offset 0 (兼容 32-bit ARM)
	leashedCount atomic.Int64
	totalSavedB  atomic.Uint64

	// 非 64 位原子字段、通道与钩子严格排在全部 64 位原子字段之后
	loopMode atomic.Int32
	wakeOnce sync.Once
	wakeCh   chan struct{}

	srv                *server
	mu                 sync.Mutex
	cfg                UpdateLeashConfig
	sessions           map[string]*UpdateLeashSession // key = mac + "|" + targetHostOrIP
	bypassedSet        map[string]bool
	pausedSet          map[string]bool
	suffixCache        []string
	applyHook          func(active []UpdateLeashSession)
	lastPersistedKey   string
	hasPersistedState  bool
	lastAppliedKbps    int
	lastMangleDigestV4 string
	lastMangleDigestV6 string
	cfgSaveMu          sync.Mutex
	cfgSaveSeq         uint64
	lastSavedCfgSeq    uint64

	pollInterval     time.Duration
	idleExpire       time.Duration
	activityHook     func() (<-chan struct{}, Activity)
	simActiveHook    func() bool
	flowsHook        func() []UpdateFlowInput
	applyDataplaneFn func(hncDir string, leashMark uint32, rateKbps int) error
	removeNativeFn   func(hncDir string, leashMark uint32) error
	mangleApplyFn    func(isIPv6 bool, payload string) error
	invalidateFn     func(hncDir, iface string)
}

func newUpdateLeashEngine(s *server) *updateLeashEngine {
	eng := &updateLeashEngine{
		wakeCh:      make(chan struct{}, 1),
		srv:         s,
		cfg:         defaultUpdateLeashConfig(),
		sessions:    make(map[string]*UpdateLeashSession),
		bypassedSet: make(map[string]bool),
		pausedSet:   make(map[string]bool),
	}
	eng.loadConfigLocked()
	eng.reloadRuleSuffixesLocked()
	return eng
}

func (e *updateLeashEngine) effectivePollInterval() time.Duration {
	if e != nil && e.pollInterval > 0 {
		return e.pollInterval
	}
	return 5 * time.Second
}

func (e *updateLeashEngine) effectiveIdleExpire() time.Duration {
	if e != nil && e.idleExpire > 0 {
		return e.idleExpire
	}
	return leashFlowIdleExpire
}

func (e *updateLeashEngine) ensureWakeCh() chan struct{} {
	if e == nil {
		return nil
	}
	e.wakeOnce.Do(func() {
		if e.wakeCh == nil {
			e.wakeCh = make(chan struct{}, 1)
		}
	})
	return e.wakeCh
}

// Wake 非阻塞唤醒更新拴绳协程（配置变更或手动放行/暂停后即时重算）。
func (e *updateLeashEngine) Wake() {
	ch := e.ensureWakeCh()
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

// LoopMode 返回当前更新拴绳协程的休眠/一次性释放定时器/活跃周期档位。
func (e *updateLeashEngine) LoopMode() v6EngineLoopMode {
	if e == nil {
		return v6EngineLoopModeSleepingFallback()
	}
	return v6EngineLoopMode(e.loopMode.Load())
}

func v6EngineLoopModeSleepingFallback() v6EngineLoopMode {
	return v6EngineModeSleeping
}

func (e *updateLeashEngine) sampleLiveFlows() []UpdateFlowInput {
	if e != nil && e.flowsHook != nil {
		return e.flowsHook()
	}
	return e.collectLiveFlows()
}

func (e *updateLeashEngine) configPath() string {
	return filepath.Join(e.srv.hncDir, "data", "update_leash.json")
}

func (e *updateLeashEngine) activeRunPath() string {
	return filepath.Join(e.srv.hncDir, "run", "update_leash_active.json")
}

func (e *updateLeashEngine) loadConfigLocked() {
	if e.srv == nil || e.srv.hncDir == "" {
		return
	}
	b, err := os.ReadFile(e.configPath())
	if err != nil {
		return
	}
	var c UpdateLeashConfig
	if json.Unmarshal(b, &c) != nil {
		return
	}
	if c.GraceMB >= leashMinGraceMB && c.GraceMB <= leashMaxGraceMB &&
		c.LeashKbps >= leashMinKbps && c.LeashKbps <= leashMaxKbps {
		e.cfg = c
	}
}

// ReloadFromDisk 在整机备份恢复后从磁盘重新加载 UpdateLeash 配置、更新规则后缀，并与 conn_blocks.json 对齐 pausedSet。
func (e *updateLeashEngine) ReloadFromDisk() {
	if e == nil {
		return
	}
	var (
		cbf        connBlockFile
		hasHncDir  bool
	)
	if e.srv != nil && e.srv.hncDir != "" {
		hasHncDir = true
		cbf = readConnBlocks(e.srv.hncDir)
	}
	now := time.Now()

	e.mu.Lock()
	e.cfg = defaultUpdateLeashConfig()
	e.loadConfigLocked()
	e.suffixCache = nil
	e.reloadRuleSuffixesLocked()
	e.lastMangleDigestV4 = ""
	e.lastMangleDigestV6 = ""
	e.hasPersistedState = false
	e.lastPersistedKey = ""

	if hasHncDir {
		newPaused := make(map[string]bool)
		for _, it := range cbf.Items {
			cm := canonMAC(it.MAC)
			if cm == "" || cm == "00:00:00:00:00:00" {
				continue
			}
			grpHost := canonicalUpdateHostGroup(it.Value, it.Value)
			if grpHost == "" {
				continue
			}
			skey := cm + "|" + grpHost
			matched, vendor := e.matchUpdateTargetLocked(it.Value, "")
			if !matched {
				matched, vendor = e.matchUpdateTargetLocked(grpHost, "")
			}
			if strings.Contains(it.Label, "UpdateLeash") || e.pausedSet[skey] || matched {
				newPaused[skey] = true
				delete(e.bypassedSet, skey)
				if sess, exists := e.sessions[skey]; exists {
					sess.Paused = true
					sess.BypassOnce = false
					sess.State = leashStatePaused
					sess.AppliedKbps = 0
				} else {
					if vendor == "" {
						vendor = "系统大包 OTA"
					}
					e.sessions[skey] = &UpdateLeashSession{
						SessionKey:     skey,
						MAC:            cm,
						DstHost:        grpHost,
						VendorLabel:    vendor,
						State:          leashStatePaused,
						Paused:         true,
						FirstSeen:      now.Unix(),
						UpdatedAt:      now.Unix(),
						updatedTime:    now,
						lastFlowTotals: make(map[string]uint64),
					}
				}
			}
		}
		for oldKey := range e.pausedSet {
			if newPaused[oldKey] {
				continue
			}
			if sess, exists := e.sessions[oldKey]; exists {
				if sess.DownBytes == 0 && len(sess.lastFlowTotals) == 0 {
					delete(e.sessions, oldKey)
				} else {
					sess.Paused = false
					if sess.State == leashStatePaused {
						sess.State = leashStateGrace
					}
				}
			}
		}
		e.pausedSet = newPaused
	}
	e.mu.Unlock()

	if !e.isHotspotOffReadOnly() {
		e.Wake()
	}
}

func (e *updateLeashEngine) persistConfigBytesUnlocked(seq uint64, b []byte) error {
	if e.srv == nil || e.srv.hncDir == "" || len(b) == 0 {
		return nil
	}
	e.cfgSaveMu.Lock()
	defer e.cfgSaveMu.Unlock()
	if seq < e.lastSavedCfgSeq {
		return nil
	}
	if err := discoverWriteAtomic(e.configPath(), b); err != nil {
		return err
	}
	e.lastSavedCfgSeq = seq
	return nil
}

func (e *updateLeashEngine) reloadRuleSuffixesLocked() {
	seen := make(map[string]bool)
	add := func(suf string) {
		s := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(suf)), "."), ".")
		if s != "" && !seen[s] {
			seen[s] = true
			e.suffixCache = append(e.suffixCache, s)
		}
	}
	for _, s := range builtinSystemUpdateSuffixes {
		add(s)
	}
	if e.srv == nil || e.srv.hncDir == "" {
		return
	}
	candidates := []string{
		filepath.Join(e.srv.hncDir, "etc", "dpi_rules.d", "96-system-updates-v6.json"),
		filepath.Join(e.srv.hncDir, "data", "dpi_rules.d", "96-system-updates-v6.json"),
	}
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var rf struct {
			Rules []struct {
				Suffixes []string `json:"suffixes"`
			} `json:"rules"`
		}
		if json.Unmarshal(b, &rf) == nil {
			for _, r := range rf.Rules {
				for _, suf := range r.Suffixes {
					add(suf)
				}
			}
		}
	}
}

func (e *updateLeashEngine) matchUpdateTargetLocked(host, appID string) (matched bool, vendor string) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	matchedSuffix := ""
	for _, suf := range e.suffixCache {
		if h == suf || strings.HasSuffix(h, "."+suf) {
			if len(suf) > len(matchedSuffix) {
				matchedSuffix = suf
			}
		}
	}
	aid := strings.ToLower(strings.TrimSpace(appID))
	if matchedSuffix == "" && !builtinUpdateRuleIDs[aid] {
		return false, ""
	}
	ref := matchedSuffix
	if ref == "" {
		ref = h + "|" + aid
	}
	switch {
	case strings.Contains(ref, "microsoft") || strings.Contains(ref, "windows"):
		return true, "Windows Update"
	case strings.Contains(ref, "apple"):
		return true, "Apple 系统更新"
	case strings.Contains(ref, "steam"):
		return true, "Steam 内容更新"
	case strings.Contains(ref, "xbox") || strings.Contains(ref, "playstation"):
		return true, "主机大包更新"
	default:
		return true, "系统大包 OTA"
	}
}

func canonicalUpdateHostGroup(host, dstIP string) string {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return strings.TrimSpace(dstIP)
	}
	for _, suf := range builtinSystemUpdateSuffixes {
		if h == suf || strings.HasSuffix(h, "."+suf) {
			return suf
		}
	}
	return h
}

// collectLiveFlows 从 conntrack 快照 + IP->域名/应用表提取候选流。
func (e *updateLeashEngine) collectLiveFlows() []UpdateFlowInput {
	if e.srv == nil {
		return nil
	}
	sn := conntrackSnapshot()
	if sn == nil || !sn.readable {
		return nil
	}
	ipsBy := e.srv.deviceIPsByMAC()
	owner := make(map[string]string)
	for mac, ips := range ipsBy {
		for _, ip := range ips {
			owner[ip] = mac
		}
	}
	names := e.srv.loadIPNames()
	apps := e.srv.loadIPApps()

	out := []UpdateFlowInput{}
	for _, ent := range sn.entries {
		mac := owner[ent.Src]
		if mac == "" || isPrivateIP(ent.Dst) {
			continue
		}
		k := ent.key()
		nm := names[ent.Dst]
		ap := apps[ent.Dst]
		appID := ap.ID
		appName := ap.Name
		if appID == "" {
			appID = nm.App
			appName = nm.AppName
		}
		out = append(out, UpdateFlowInput{
			FlowKey:   k,
			MAC:       mac,
			SrcIP:     ent.Src,
			DstIP:     ent.Dst,
			DstHost:   nm.Name,
			AppID:     appID,
			AppName:   appName,
			Proto:     ent.Proto,
			UpBytes:   ent.UpB,
			DownBytes: ent.DnB,
			DownBps:   int64(sn.dnBps[k] / 8),
		})
	}
	return out
}

// ObserveFlows 推演一轮 200MB 免死缓冲与 1500 Kbps 拴绳状态机。
func (e *updateLeashEngine) ObserveFlows(now time.Time, flows []UpdateFlowInput) []UpdateLeashSession {
	nameByMAC, _ := e.srv.buildDeviceDirectory()

	e.mu.Lock()
	cfg := e.cfg
	graceBytes := uint64(cfg.GraceMB) * 1024 * 1024
	nowUnix := now.Unix()

	// 按会话键 (mac + "|" + canonicalHost) 汇总当前活跃连接字节
	activeFlowSums := make(map[string]map[string]uint64)
	activeUpSums := make(map[string]uint64)
	activeBpsSums := make(map[string]int64)
	metaSample := make(map[string]UpdateFlowInput)
	metaVendor := make(map[string]string)

	for _, fl := range flows {
		mac := canonMAC(fl.MAC)
		if mac == "" {
			continue
		}
		matched, vendor := e.matchUpdateTargetLocked(fl.DstHost, fl.AppID)
		if !matched {
			continue
		}
		// 仅针对单向下行主导的流量生效, 保护双向交互流量
		if fl.DownBytes > 0 && fl.UpBytes > 0 {
			if float64(fl.UpBytes)/float64(fl.DownBytes) > leashUnidirMaxUpRatio {
				continue
			}
		}
		grpHost := canonicalUpdateHostGroup(fl.DstHost, fl.DstIP)
		if grpHost == "" {
			continue
		}
		skey := mac + "|" + grpHost
		fk := fl.FlowKey
		if fk == "" {
			fk = fl.Proto + "|" + fl.SrcIP + "|" + fl.DstIP
		}
		if activeFlowSums[skey] == nil {
			activeFlowSums[skey] = make(map[string]uint64)
		}
		activeFlowSums[skey][fk] = fl.DownBytes
		activeUpSums[skey] += fl.UpBytes
		activeBpsSums[skey] += fl.DownBps
		if _, exists := metaSample[skey]; !exists {
			metaSample[skey] = fl
			metaVendor[skey] = vendor
		}
	}

	for skey, flowMap := range activeFlowSums {
		fl := metaSample[skey]
		grpHost := canonicalUpdateHostGroup(fl.DstHost, fl.DstIP)
		sess, ok := e.sessions[skey]
		if !ok {
			sess = &UpdateLeashSession{
				SessionKey:     skey,
				MAC:            canonMAC(fl.MAC),
				SrcIP:          fl.SrcIP,
				DstHost:        grpHost,
				DstIP:          fl.DstIP,
				VendorLabel:    metaVendor[skey],
				FirstSeen:      nowUnix,
				lastFlowTotals: make(map[string]uint64),
			}
			e.sessions[skey] = sess
		}
		// 若某条旧子连接已关闭, 将其历史下行字节沉淀进 accumFromEnded, 支持分片多连接断点续传累计
		var curActiveDown uint64
		for prevFK, prevB := range sess.lastFlowTotals {
			if curB, stillHere := flowMap[prevFK]; !stillHere {
				sess.accumFromEnded += prevB
				delete(sess.lastFlowTotals, prevFK)
			} else if curB < prevB {
				sess.accumFromEnded += prevB
			}
		}
		for fk, curB := range flowMap {
			sess.lastFlowTotals[fk] = curB
			curActiveDown += curB
		}
		totalDown := sess.accumFromEnded + curActiveDown
		sess.DownBytes = totalDown
		sess.UpBytes = activeUpSums[skey]
		sess.DownBps = activeBpsSums[skey]
		sess.DstIP = fl.DstIP
		sess.UpdatedAt = nowUnix
		sess.updatedTime = now
	}

	prevLeashed := e.leashedCount.Load()
	idleExp := e.effectiveIdleExpire()

	// 清理超期空闲会话并刷新全部会话状态
	leashedList := []UpdateLeashSession{}
	var leashedCnt int64
	for skey, sess := range e.sessions {
		expired := false
		if !sess.updatedTime.IsZero() {
			expired = now.Sub(sess.updatedTime) >= idleExp
		} else {
			expired = nowUnix-sess.UpdatedAt >= int64(idleExp/time.Second)
		}
		if expired && !e.pausedSet[skey] {
			delete(e.sessions, skey)
			delete(e.bypassedSet, skey)
			continue
		}
		if nm := nameByMAC[sess.MAC]; nm != "" {
			sess.DeviceName = nm
		} else if sess.DeviceName == "" {
			sess.DeviceName = sess.MAC
		}
		sess.GraceLimitBytes = graceBytes
		if sess.DownBytes < graceBytes {
			sess.GraceRemainingB = graceBytes - sess.DownBytes
		} else {
			sess.GraceRemainingB = 0
		}
		sess.BypassOnce = e.bypassedSet[skey]
		sess.Paused = e.pausedSet[skey]

		switch {
		case sess.Paused:
			sess.State = leashStatePaused
			sess.AppliedKbps = 0
		case !cfg.Enabled || sess.BypassOnce:
			if sess.BypassOnce {
				sess.State = leashStateBypassed
			} else {
				sess.State = leashStateGrace
			}
			sess.AppliedKbps = 0
		case sess.DownBytes >= graceBytes:
			sess.State = leashStateLeashed
			sess.AppliedKbps = cfg.LeashKbps
			leashedCnt++
			leashedList = append(leashedList, *sess)
		default:
			// 前 200 MB 免死缓冲期: 100% 满速放行!
			sess.State = leashStateGrace
			sess.AppliedKbps = 0
		}
	}
	e.leashedCount.Store(leashedCnt)

	needApplyDP := cfg.Enabled && leashedCnt > 0 && (prevLeashed == 0 || e.lastAppliedKbps != cfg.LeashKbps)
	applyKbps := cfg.LeashKbps
	needRemoveDP := leashedCnt == 0 && (prevLeashed > 0 || e.lastAppliedKbps > 0)
	if needRemoveDP {
		e.lastAppliedKbps = 0
	}

	out := e.sortedSessionsLocked()
	hook := e.applyHook
	e.mu.Unlock()

	e.persistActiveLeash(leashedList)
	e.syncLeashMangleDataplane(leashedList)
	if needApplyDP {
		if e.applyLeashDataplane(applyKbps) == nil {
			e.mu.Lock()
			if e.cfg.Enabled && e.leashedCount.Load() > 0 && e.cfg.LeashKbps == applyKbps {
				e.lastAppliedKbps = applyKbps
			}
			e.mu.Unlock()
		}
	} else if needRemoveDP {
		e.removeLeashDataplane(false)
	}
	if hook != nil {
		hook(leashedList)
	}
	return out
}

// BuildUpdateLeashManglePayloads 构造双栈 *mangle 表 HNC_V6_LEASH 后台更新拴绳打标链载荷:
// 严格限定在 [25:24] 高位掩码 0x03000000 (值 0x03000000), 严守低 16 位 0x0000ffff 零触碰。
func BuildUpdateLeashManglePayloads(leashed []UpdateLeashSession, devIPsByMAC map[string][]string) (v4Payload, v6Payload string) {
	const low16 = uint32(0x0000ffff)
	markMask := DefaultAppQoSMarkMask &^ low16
	if markMask == 0 {
		markMask = 0x03000000
	}
	markVal := (v6LeashDefaultMark & markMask) &^ low16

	var b4, b6 strings.Builder
	b4.WriteString("*mangle\n:" + leashMangleChainName + " - [0:0]\n")
	b6.WriteString("*mangle\n:" + leashMangleChainName + " - [0:0]\n")

	if len(leashed) > 0 && markVal != 0 {
		xmark := fmt.Sprintf("0x%08x/0x%08x", markVal, markMask)
		fmt.Fprintf(&b4, "-A %s -m connmark --mark %s -j CONNMARK --restore-mark --nfmask 0x%08x --ctmask 0x%08x\n",
			leashMangleChainName, xmark, markMask, markMask)
		fmt.Fprintf(&b6, "-A %s -m connmark --mark %s -j CONNMARK --restore-mark --nfmask 0x%08x --ctmask 0x%08x\n",
			leashMangleChainName, xmark, markMask, markMask)

		sorted := make([]UpdateLeashSession, len(leashed))
		copy(sorted, leashed)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].MAC != sorted[j].MAC {
				return sorted[i].MAC < sorted[j].MAC
			}
			if sorted[i].DstIP != sorted[j].DstIP {
				return sorted[i].DstIP < sorted[j].DstIP
			}
			return sorted[i].SessionKey < sorted[j].SessionKey
		})

		seenUp := make(map[string]bool)
		seenDn := make(map[string]bool)
		for _, sess := range sorted {
			mac := canonMAC(sess.MAC)
			dstIP := net.ParseIP(strings.TrimSpace(sess.DstIP))
			if mac == "" || dstIP == nil || dstIP.IsLoopback() || dstIP.IsUnspecified() || dstIP.IsLinkLocalUnicast() || dstIP.IsMulticast() {
				continue
			}
			dstCanon := dstIP.String()
			isDstV4 := dstIP.To4() != nil

			var cliIPs []string
			if sIP := net.ParseIP(strings.TrimSpace(sess.SrcIP)); sIP != nil && (sIP.To4() != nil) == isDstV4 {
				cliIPs = append(cliIPs, sIP.String())
			}
			for _, rawCli := range devIPsByMAC[mac] {
				cIP := net.ParseIP(strings.TrimSpace(rawCli))
				if cIP == nil || (cIP.To4() != nil) != isDstV4 || cIP.IsLoopback() || cIP.IsUnspecified() || cIP.IsLinkLocalUnicast() {
					continue
				}
				cliIPs = append(cliIPs, cIP.String())
			}
			sort.Strings(cliIPs)

			if isDstV4 {
				d4 := dstIP.To4().String()
				upKey := "4|" + mac + "|" + d4
				if !seenUp[upKey] {
					seenUp[upKey] = true
					fmt.Fprintf(&b4, "-A %s -m mac --mac-source %s -d %s/32 -j MARK --set-xmark %s\n",
						leashMangleChainName, mac, d4, xmark)
				}
				for _, c4 := range cliIPs {
					dnKey := "4|" + d4 + "|" + c4
					if !seenDn[dnKey] {
						seenDn[dnKey] = true
						fmt.Fprintf(&b4, "-A %s -s %s/32 -d %s/32 -j MARK --set-xmark %s\n",
							leashMangleChainName, d4, c4, xmark)
					}
				}
			} else {
				upKey := "6|" + mac + "|" + dstCanon
				if !seenUp[upKey] {
					seenUp[upKey] = true
					fmt.Fprintf(&b6, "-A %s -m mac --mac-source %s -d %s/128 -j MARK --set-xmark %s\n",
						leashMangleChainName, mac, dstCanon, xmark)
				}
				for _, c6 := range cliIPs {
					dnKey := "6|" + dstCanon + "|" + c6
					if !seenDn[dnKey] {
						seenDn[dnKey] = true
						fmt.Fprintf(&b6, "-A %s -s %s/128 -d %s/128 -j MARK --set-xmark %s\n",
							leashMangleChainName, dstCanon, c6, xmark)
					}
				}
			}
		}

		fmt.Fprintf(&b4, "-A %s -m mark --mark %s -j CONNMARK --save-mark --nfmask 0x%08x --ctmask 0x%08x\n",
			leashMangleChainName, xmark, markMask, markMask)
		fmt.Fprintf(&b6, "-A %s -m mark --mark %s -j CONNMARK --save-mark --nfmask 0x%08x --ctmask 0x%08x\n",
			leashMangleChainName, xmark, markMask, markMask)
	}

	b4.WriteString("COMMIT\n")
	b6.WriteString("COMMIT\n")
	return b4.String(), b6.String()
}

func (e *updateLeashEngine) syncLeashMangleDataplane(leashed []UpdateLeashSession) {
	hncDir := ""
	if e.srv != nil {
		hncDir = e.srv.hncDir
	}
	if e.mangleApplyFn == nil && !useNativeDataplane(hncDir) {
		return
	}
	var devIPs map[string][]string
	if len(leashed) > 0 && e.srv != nil {
		devIPs = e.srv.deviceIPsByMAC()
	}
	v4Payload, v6Payload := BuildUpdateLeashManglePayloads(leashed, devIPs)

	e.mu.Lock()
	needV4 := e.lastMangleDigestV4 != v4Payload
	needV6 := e.lastMangleDigestV6 != v6Payload
	mangleFn := e.mangleApplyFn
	e.mu.Unlock()
	if !needV4 && !needV6 {
		return
	}

	if mangleFn != nil {
		if needV4 {
			if err := mangleFn(false, v4Payload); err == nil {
				e.mu.Lock()
				e.lastMangleDigestV4 = v4Payload
				e.mu.Unlock()
			}
		}
		if needV6 {
			if err := mangleFn(true, v6Payload); err == nil {
				e.mu.Lock()
				e.lastMangleDigestV6 = v6Payload
				e.mu.Unlock()
			}
		}
		return
	}

	if needV4 {
		if v4Bin := v6ResolveRestoreBinFn("iptables-restore"); v4Bin != "" {
			if err := pipeIptablesRestoreWithTimeout(v4Bin, []byte(v4Payload), iptRestoreTimeout); err == nil {
				if len(leashed) > 0 {
					ensureV6TacticalMangleHooksOnBin(v6ResolveRestoreBinFn("iptables"), leashMangleChainName, true)
				}
				e.mu.Lock()
				e.lastMangleDigestV4 = v4Payload
				e.mu.Unlock()
			}
		}
	}
	if needV6 {
		if v6Bin := v6ResolveRestoreBinFn("ip6tables-restore"); v6Bin != "" {
			if err := pipeIptablesRestoreWithTimeout(v6Bin, []byte(v6Payload), iptRestoreTimeout); err == nil {
				if len(leashed) > 0 {
					ensureV6TacticalMangleHooksOnBin(v6ResolveRestoreBinFn("ip6tables"), leashMangleChainName, true)
				}
				e.mu.Lock()
				e.lastMangleDigestV6 = v6Payload
				e.mu.Unlock()
			}
		}
	}
}

func (e *updateLeashEngine) sortedSessionsLocked() []UpdateLeashSession {
	out := make([]UpdateLeashSession, 0, len(e.sessions))
	for _, s := range e.sessions {
		cp := *s
		cp.lastFlowTotals = nil
		cp.updatedTime = time.Time{}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DownBytes != out[j].DownBytes {
			return out[i].DownBytes > out[j].DownBytes
		}
		return out[i].SessionKey < out[j].SessionKey
	})
	return out
}

func (e *updateLeashEngine) applyLeashDataplane(leashKbps int) error {
	hncDir := ""
	if e.srv != nil {
		hncDir = e.srv.hncDir
	}
	if hncDir == "" && e.applyDataplaneFn == nil {
		return nil
	}
	apFn := ApplyUpdateLeashNative
	if e.applyDataplaneFn != nil {
		apFn = e.applyDataplaneFn
	}
	return apFn(hncDir, 0, leashKbps)
}

func (e *updateLeashEngine) removeLeashDataplane(invalidate bool) {
	hncDir := ""
	if e.srv != nil {
		hncDir = e.srv.hncDir
	}
	if hncDir == "" && e.removeNativeFn == nil && e.invalidateFn == nil {
		return
	}
	rmFn := RemoveUpdateLeashNative
	if e.removeNativeFn != nil {
		rmFn = e.removeNativeFn
	}
	invFn := InvalidateDataplaneReconcileNative
	if e.invalidateFn != nil {
		invFn = e.invalidateFn
	}
	_ = rmFn(hncDir, 0)
	if invalidate {
		invFn(hncDir, "")
	}
}

// resetForHotspotOff 在热点关闭时即刻删除非 pausedSet 动态会话(严格保留 pausedSet 与 conn_blocks),
// 归零 leashedCount、刷新 active JSON 并调用原生接口移除 1:9990 限速类及清空对账缓存。
func (e *updateLeashEngine) resetForHotspotOff() {
	e.mu.Lock()
	hadLeashed := e.leashedCount.Load() > 0
	e.lastAppliedKbps = 0
	for skey, sess := range e.sessions {
		if !e.pausedSet[skey] {
			delete(e.sessions, skey)
			delete(e.bypassedSet, skey)
			continue
		}
		sess.State = leashStatePaused
		sess.Paused = true
		sess.AppliedKbps = 0
		sess.DownBps = 0
	}
	e.leashedCount.Store(0)
	hook := e.applyHook
	e.mu.Unlock()

	e.persistActiveLeash(nil)
	e.syncLeashMangleDataplane(nil)
	e.removeLeashDataplane(true)
	if hadLeashed && hook != nil {
		hook(nil)
	}
}

func (e *updateLeashEngine) needsHotspotOffCleanup() bool {
	if e.leashedCount.Load() > 0 {
		return true
	}
	e.mu.Lock()
	hasNonPaused := false
	for skey := range e.sessions {
		if !e.pausedSet[skey] {
			hasNonPaused = true
			break
		}
	}
	e.mu.Unlock()
	return hasNonPaused
}

func (e *updateLeashEngine) persistActiveLeash(leashed []UpdateLeashSession) {
	if e.srv == nil || e.srv.hncDir == "" {
		return
	}
	sorted := make([]UpdateLeashSession, len(leashed))
	copy(sorted, leashed)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].SessionKey < sorted[j].SessionKey
	})
	type leashDigestItem struct {
		SessionKey  string `json:"k"`
		MAC         string `json:"m"`
		SrcIP       string `json:"s"`
		DstHost     string `json:"h"`
		DstIP       string `json:"d"`
		AppliedKbps int    `json:"r"`
		State       string `json:"st"`
		BypassOnce  bool   `json:"b"`
		Paused      bool   `json:"p"`
	}
	digestList := make([]leashDigestItem, 0, len(sorted))
	for _, it := range sorted {
		digestList = append(digestList, leashDigestItem{
			SessionKey:  it.SessionKey,
			MAC:         it.MAC,
			SrcIP:       it.SrcIP,
			DstHost:     it.DstHost,
			DstIP:       it.DstIP,
			AppliedKbps: it.AppliedKbps,
			State:       it.State,
			BypassOnce:  it.BypassOnce,
			Paused:      it.Paused,
		})
	}
	digestBytes, err := json.Marshal(digestList)
	if err != nil {
		return
	}
	digestKey := string(digestBytes)
	e.mu.Lock()
	if e.hasPersistedState && e.lastPersistedKey == digestKey {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()

	payload := map[string]any{
		"updated_at": time.Now().Unix(),
		"leashed":    sorted,
	}
	if b, err := json.MarshalIndent(payload, "", "  "); err == nil {
		if discoverWriteAtomic(e.activeRunPath(), b) == nil {
			e.mu.Lock()
			e.lastPersistedKey = digestKey
			e.hasPersistedState = true
			e.mu.Unlock()
		}
	}
}

func (e *updateLeashEngine) snapshot(refreshLive bool) map[string]any {
	if refreshLive {
		e.ObserveFlows(time.Now(), e.sampleLiveFlows())
	} else {
		e.ObserveFlows(time.Now(), nil)
	}
	e.mu.Lock()
	cfg := e.cfg
	sessions := e.sortedSessionsLocked()
	e.mu.Unlock()

	return map[string]any{
		"ok":            true,
		"enabled":       cfg.Enabled,
		"grace_mb":      cfg.GraceMB,
		"grace_bytes":   uint64(cfg.GraceMB) * 1024 * 1024,
		"leash_kbps":    cfg.LeashKbps,
		"leashed_count": e.leashedCount.Load(),
		"sessions":      sessions,
		"config":        cfg,
	}
}

func (e *updateLeashEngine) summary() map[string]any {
	e.mu.Lock()
	cfg := e.cfg
	sessions := e.sortedSessionsLocked()
	e.mu.Unlock()
	return map[string]any{
		"enabled":         cfg.Enabled,
		"grace_mb":        cfg.GraceMB,
		"leash_kbps":      cfg.LeashKbps,
		"active_sessions": len(sessions),
		"leashed_count":   e.leashedCount.Load(),
		"sessions":        sessions,
	}
}

func (e *updateLeashEngine) readActivity() (<-chan struct{}, Activity, bool) {
	if e.activityHook != nil {
		ch, act := e.activityHook()
		sim := false
		if e.simActiveHook != nil {
			sim = e.simActiveHook()
		} else if e.srv != nil && e.srv.hncDir != "" {
			sim = e.srv.simActive()
		}
		return ch, act, sim
	}
	ch := activityChanged()
	act := activityNow()
	sim := false
	if e.simActiveHook != nil {
		sim = e.simActiveHook()
	} else if e.srv != nil && e.srv.hncDir != "" {
		sim = e.srv.simActive()
	}
	return ch, act, sim
}

func (e *updateLeashEngine) evalNoClientsRelease(now time.Time) (time.Duration, bool) {
	idleExp := e.effectiveIdleExpire()
	findEarliestRem := func(ref time.Time) (time.Duration, bool, bool) {
		e.mu.Lock()
		defer e.mu.Unlock()
		var (
			found      bool
			anyExpired bool
			minRem     time.Duration
		)
		for skey, sess := range e.sessions {
			if e.pausedSet[skey] || sess.State != leashStateLeashed {
				continue
			}
			baseTs := sess.updatedTime
			if baseTs.IsZero() {
				baseTs = time.Unix(sess.UpdatedAt, 0)
			}
			rem := idleExp - ref.Sub(baseTs)
			if rem <= 0 {
				anyExpired = true
				continue
			}
			if !found || rem < minRem {
				found = true
				minRem = rem
			}
		}
		return minRem, found, anyExpired
	}

	minRem, found, anyExpired := findEarliestRem(now)
	if anyExpired {
		e.ObserveFlows(now, nil)
		if e.leashedCount.Load() == 0 {
			e.removeLeashDataplane(true)
		}
		minRem, found, _ = findEarliestRem(now)
	}
	if !found && e.leashedCount.Load() > 0 {
		return 50 * time.Millisecond, true
	}
	if !found {
		return 0, false
	}
	return minRem + 15*time.Millisecond, true
}

func (e *updateLeashEngine) runLoop(stop <-chan struct{}) {
	if e == nil {
		<-stop
		return
	}
	wakeCh := e.ensureWakeCh()

	var (
		tk                *time.Ticker
		tkCh              <-chan time.Time
		relTimer          *time.Timer
		relTimerCh        <-chan time.Time
		wasActive         bool
		hotspotOffCleaned bool
	)
	stopTicker := func() {
		if tk != nil {
			tk.Stop()
			tk = nil
			tkCh = nil
		}
	}
	ensureTicker := func(d time.Duration) {
		if tk == nil {
			tk = time.NewTicker(d)
			tkCh = tk.C
		}
	}
	stopRelTimer := func() {
		if relTimer != nil {
			if !relTimer.Stop() {
				select {
				case <-relTimer.C:
				default:
				}
			}
			relTimer = nil
			relTimerCh = nil
		}
	}
	armRelTimer := func(d time.Duration) {
		stopRelTimer()
		if d <= 0 {
			d = time.Millisecond
		}
		relTimer = time.NewTimer(d)
		relTimerCh = relTimer.C
	}
	defer func() {
		stopTicker()
		stopRelTimer()
		e.loopMode.Store(int32(v6EngineModeSleeping))
	}()

	patrolOnce := func(now time.Time) {
		e.ObserveFlows(now, e.sampleLiveFlows())
	}

	for {
		actCh, act, simOn := e.readActivity()
		now := time.Now()

		if isV6EngineActive(act, simOn) {
			hotspotOffCleaned = false
			stopRelTimer()
			if !wasActive {
				patrolOnce(now)
				wasActive = true
			}
			ensureTicker(e.effectivePollInterval())
			e.loopMode.Store(int32(v6EngineModeActive))
		} else if !act.HotspotActive {
			wasActive = false
			stopTicker()
			stopRelTimer()
			if !hotspotOffCleaned || e.needsHotspotOffCleanup() {
				e.resetForHotspotOff()
				hotspotOffCleaned = true
			}
			e.loopMode.Store(int32(v6EngineModeSleeping))
		} else {
			wasActive = false
			hotspotOffCleaned = false
			stopTicker()
			if rem, pending := e.evalNoClientsRelease(now); pending {
				armRelTimer(rem)
				e.loopMode.Store(int32(v6EngineModeReleaseTimer))
			} else {
				stopRelTimer()
				e.loopMode.Store(int32(v6EngineModeSleeping))
			}
		}

		select {
		case <-stop:
			return
		case <-actCh:
		case <-wakeCh:
			hotspotOffCleaned = false
			if wasActive {
				patrolOnce(time.Now())
			}
		case tickNow := <-tkCh:
			patrolOnce(tickNow)
		case timerNow := <-relTimerCh:
			relTimer = nil
			relTimerCh = nil
			e.ObserveFlows(timerNow, nil)
			if e.leashedCount.Load() == 0 {
				e.removeLeashDataplane(true)
			}
		}
	}
}

// ── HTTP: GET & POST /api/v6/update_leash ────────────────────────────────────

func (e *updateLeashEngine) isHotspotOffReadOnly() bool {
	if e == nil {
		return false
	}
	_, act, sim := e.readActivity()
	return act.Known && !act.HotspotActive && !sim
}

// ReadOnlySnapshot 在 HotspotOff 期间返回零副作用的纯内存只读快照,
// 严禁采样 conntrack 或调用 ObserveFlows 覆写磁盘状态与触发数据面。
func (e *updateLeashEngine) ReadOnlySnapshot() map[string]any {
	e.mu.Lock()
	cfg := e.cfg
	sessions := e.sortedSessionsLocked()
	e.mu.Unlock()
	return map[string]any{
		"ok":            true,
		"enabled":       cfg.Enabled,
		"grace_mb":      cfg.GraceMB,
		"grace_bytes":   uint64(cfg.GraceMB) * 1024 * 1024,
		"leash_kbps":    cfg.LeashKbps,
		"leashed_count": int64(0),
		"sessions":      sessions,
		"config":        cfg,
	}
}

func (s *server) apiUpdateLeash(w http.ResponseWriter, r *http.Request) {
	eng := s.v6State().leash
	isOffReadOnly := func() bool {
		if eng.isHotspotOffReadOnly() {
			return true
		}
		if act := activityNow(); act.Known && !act.HotspotActive && (s == nil || !s.simActive()) {
			return true
		}
		return false
	}
	if r.Method == http.MethodGet {
		if isOffReadOnly() {
			writeJSON(w, http.StatusOK, eng.ReadOnlySnapshot())
			return
		}
		live := eng.sampleLiveFlows()
		if len(live) > 0 {
			eng.ObserveFlows(time.Now(), live)
		}
		writeJSON(w, http.StatusOK, eng.snapshot(false))
		return
	}
	s.requireMutation(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action     string `json:"action"` // "" | "config" | "bypass_once" | "pause_update" | "resume_update"
			Enabled    *bool  `json:"enabled"`
			GraceMB    *int   `json:"grace_mb"`
			LeashKbps  *int   `json:"leash_kbps"`
			SessionKey string `json:"session_key"`
			MAC        string `json:"mac"`
			DstHost    string `json:"dst_host"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json", "detail": err.Error()})
			return
		}

		act := strings.ToLower(strings.TrimSpace(req.Action))
		switch act {
		case "", "config":
			eng.mu.Lock()
			prevCfg := eng.cfg
			next := eng.cfg
			if req.Enabled != nil {
				next.Enabled = *req.Enabled
			}
			if req.GraceMB != nil {
				if *req.GraceMB < leashMinGraceMB || *req.GraceMB > leashMaxGraceMB {
					eng.mu.Unlock()
					writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "grace_mb must be 10..10240"})
					return
				}
				next.GraceMB = *req.GraceMB
			}
			if req.LeashKbps != nil {
				if *req.LeashKbps < leashMinKbps || *req.LeashKbps > leashMaxKbps {
					eng.mu.Unlock()
					writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "leash_kbps must be 128..1000000"})
					return
				}
				next.LeashKbps = *req.LeashKbps
			}
			eng.cfg = next
			eng.cfgSaveSeq++
			saveSeq := eng.cfgSaveSeq
			cfgBytes, mErr := json.MarshalIndent(eng.cfg, "", "  ")
			eng.mu.Unlock()
			if mErr != nil {
				eng.mu.Lock()
				if eng.cfgSaveSeq == saveSeq {
					eng.cfg = prevCfg
				}
				eng.mu.Unlock()
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write failed", "detail": mErr.Error()})
				return
			}
			if err := eng.persistConfigBytesUnlocked(saveSeq, cfgBytes); err != nil {
				eng.mu.Lock()
				if eng.cfgSaveSeq == saveSeq {
					eng.cfg = prevCfg
				}
				eng.mu.Unlock()
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write failed", "detail": err.Error()})
				return
			}
			if isOffReadOnly() {
				writeJSON(w, http.StatusOK, eng.ReadOnlySnapshot())
				return
			}
			resp := eng.snapshot(false)
			eng.Wake()
			writeJSON(w, http.StatusOK, resp)

		case "bypass_once":
			mac := canonMAC(req.MAC)
			rawHost := strings.TrimSpace(req.DstHost)
			host := canonicalUpdateHostGroup(rawHost, "")
			skey := strings.TrimSpace(req.SessionKey)
			if skey == "" && mac != "" && host != "" {
				skey = mac + "|" + host
			}
			type unpausePair struct {
				mac     string
				grpHost string
			}
			var unpaused []unpausePair

			eng.mu.Lock()
			matched := 0
			if skey != "" {
				wasPaused := eng.pausedSet[skey]
				eng.bypassedSet[skey] = true
				delete(eng.pausedSet, skey)
				if sess, ok := eng.sessions[skey]; ok {
					if sess.Paused {
						wasPaused = true
					}
					sess.BypassOnce = true
					sess.Paused = false
					sess.State = leashStateBypassed
					sess.AppliedKbps = 0
				}
				if parts := strings.SplitN(skey, "|", 2); len(parts) == 2 {
					pm := canonMAC(parts[0])
					ph := strings.TrimSpace(parts[1])
					if pm != "" && ph != "" && (wasPaused || rawHost != "" || ph != "") {
						unpaused = append(unpaused, unpausePair{mac: pm, grpHost: ph})
					}
				}
				matched++
			} else {
				for k, sess := range eng.sessions {
					if (mac == "" || sess.MAC == mac) && (host == "" || sess.DstHost == host) {
						wasPaused := eng.pausedSet[k] || sess.Paused
						eng.bypassedSet[k] = true
						delete(eng.pausedSet, k)
						sess.BypassOnce = true
						sess.Paused = false
						sess.State = leashStateBypassed
						sess.AppliedKbps = 0
						if wasPaused && sess.MAC != "" && sess.DstHost != "" {
							unpaused = append(unpaused, unpausePair{mac: sess.MAC, grpHost: sess.DstHost})
						}
						matched++
					}
				}
			}
			eng.mu.Unlock()

			// 同步清理底层 conn_blocks 中的暂停更新阻断项，防止 bypass_once 内存放行后内核仍继续 DROP
			if s != nil && s.hncDir != "" && len(unpaused) > 0 {
				delSeen := make(map[string]bool)
				tryDel := func(m, target string) {
					kind, normVal, ok := normalizeBlockTarget(target)
					if !ok || m == "" {
						return
					}
					dk := m + "|" + kind + "|" + normVal
					if delSeen[dk] {
						return
					}
					delSeen[dk] = true
					_ = actionConnBlockDel(s, map[string]string{
						"mac":   m,
						"kind":  kind,
						"value": normVal,
					})
				}
				cbf := readConnBlocks(s.hncDir)
				for _, up := range unpaused {
					if rawHost != "" && (mac == "" || mac == up.mac) {
						tryDel(up.mac, rawHost)
					}
					tryDel(up.mac, up.grpHost)
					for _, it := range cbf.Items {
						if canonMAC(it.MAC) != up.mac {
							continue
						}
						itGrp := canonicalUpdateHostGroup(it.Value, it.Value)
						if itGrp == up.grpHost || strings.EqualFold(strings.TrimSpace(it.Value), up.grpHost) {
							tryDel(up.mac, it.Value)
						}
					}
				}
			}

			var resp map[string]any
			if isOffReadOnly() {
				resp = eng.ReadOnlySnapshot()
			} else {
				resp = eng.snapshot(false)
				eng.Wake()
			}
			resp["action"] = "bypass_once"
			resp["bypassed_sessions"] = matched
			writeJSON(w, http.StatusOK, resp)

		case "pause_update", "resume_update":
			pause := act == "pause_update"
			mac := canonMAC(req.MAC)
			rawHost := strings.TrimSpace(req.DstHost)
			if skey := strings.TrimSpace(req.SessionKey); skey != "" && (mac == "" || rawHost == "") {
				if parts := strings.SplitN(skey, "|", 2); len(parts) == 2 {
					if mac == "" {
						mac = canonMAC(parts[0])
					}
					if rawHost == "" {
						rawHost = parts[1]
					}
				}
			}
			if mac == "" {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "valid mac required"})
				return
			}
			kind, normVal, ok := normalizeBlockTarget(rawHost)
			if !ok {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "valid dst_host required"})
				return
			}
			scriptExists := false
			if st, err := os.Stat(filepath.Join(s.hncDir, "bin", "connblock_sync.sh")); err == nil && !st.IsDir() {
				scriptExists = true
			}
			cbParams := map[string]string{
				"mac":   mac,
				"kind":  kind,
				"value": normVal,
				"label": "UpdateLeash 暂停更新",
			}
			var cbResp actionResp
			if pause {
				cbResp = actionConnBlockAdd(s, cbParams)
			} else {
				cbResp = actionConnBlockDel(s, cbParams)
			}
			if !cbResp.OK && !(cbResp.Error == "sync failed" && !scriptExists) && !(!pause && cbResp.Error == "not found") {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": cbResp.Error, "detail": cbResp.Detail})
				return
			}

			grpHost := canonicalUpdateHostGroup(normVal, normVal)
			skey := mac + "|" + grpHost
			now := time.Now()
			eng.mu.Lock()
			if pause {
				eng.pausedSet[skey] = true
				if _, exists := eng.sessions[skey]; !exists {
					_, vendor := eng.matchUpdateTargetLocked(grpHost, "")
					eng.sessions[skey] = &UpdateLeashSession{
						SessionKey:     skey,
						MAC:            mac,
						DstHost:        grpHost,
						VendorLabel:    vendor,
						State:          leashStatePaused,
						Paused:         true,
						FirstSeen:      now.Unix(),
						UpdatedAt:      now.Unix(),
						updatedTime:    now,
						lastFlowTotals: make(map[string]uint64),
					}
				}
			} else {
				delete(eng.pausedSet, skey)
			}
			eng.mu.Unlock()

			resp := eng.snapshot(false)
			resp["action"] = act
			resp["paused"] = pause
			resp["dst_host"] = normVal
			eng.Wake()
			writeJSON(w, http.StatusOK, resp)

		default:
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "action must be config|bypass_once|pause_update|resume_update"})
		}
	})(w, r)
}
