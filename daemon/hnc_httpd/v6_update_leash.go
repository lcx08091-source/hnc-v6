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
	"windows_update_v6":      true,
	"apple_system_update_v6": true,
	"steam_bulk_update_v6":   true,
	"console_rom_ota_v6":     true,
	"microsoft_update":       true,
	"apple_update":           true,
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
}

type updateLeashEngine struct {
	// 64 位原子字段严格置于 offset 0 (兼容 32-bit ARM)
	leashedCount atomic.Int64
	totalSavedB  atomic.Uint64

	srv         *server
	mu          sync.Mutex
	cfg         UpdateLeashConfig
	sessions    map[string]*UpdateLeashSession // key = mac + "|" + targetHostOrIP
	bypassedSet map[string]bool
	pausedSet   map[string]bool
	suffixCache []string
	applyHook   func(active []UpdateLeashSession)
}

func newUpdateLeashEngine(s *server) *updateLeashEngine {
	eng := &updateLeashEngine{
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

func (e *updateLeashEngine) saveConfigLocked() error {
	if e.srv == nil || e.srv.hncDir == "" {
		return nil
	}
	b, err := json.MarshalIndent(e.cfg, "", "  ")
	if err != nil {
		return err
	}
	return discoverWriteAtomic(e.configPath(), b)
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

	var out []UpdateFlowInput
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
			DownBps:   int64(sn.dnBps[k]),
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
	}

	// 清理超期空闲会话并刷新全部会话状态
	var leashedList []UpdateLeashSession
	var leashedCnt int64
	for skey, sess := range e.sessions {
		if nowUnix-sess.UpdatedAt > int64(leashFlowIdleExpire/time.Second) && !e.pausedSet[skey] {
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

	out := e.sortedSessionsLocked()
	hook := e.applyHook
	e.mu.Unlock()

	e.persistActiveLeash(leashedList)
	if hook != nil {
		hook(leashedList)
	}
	return out
}

func (e *updateLeashEngine) sortedSessionsLocked() []UpdateLeashSession {
	out := make([]UpdateLeashSession, 0, len(e.sessions))
	for _, s := range e.sessions {
		cp := *s
		cp.lastFlowTotals = nil
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

func (e *updateLeashEngine) persistActiveLeash(leashed []UpdateLeashSession) {
	if e.srv == nil || e.srv.hncDir == "" {
		return
	}
	payload := map[string]any{
		"updated_at": time.Now().Unix(),
		"leashed":    leashed,
	}
	if b, err := json.MarshalIndent(payload, "", "  "); err == nil {
		_ = discoverWriteAtomic(e.activeRunPath(), b)
	}
}

func (e *updateLeashEngine) snapshot(refreshLive bool) map[string]any {
	if refreshLive {
		e.ObserveFlows(time.Now(), e.collectLiveFlows())
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
	sessCnt := len(e.sessions)
	e.mu.Unlock()
	return map[string]any{
		"enabled":         cfg.Enabled,
		"grace_mb":        cfg.GraceMB,
		"leash_kbps":      cfg.LeashKbps,
		"active_sessions": sessCnt,
		"leashed_count":   e.leashedCount.Load(),
	}
}

func (e *updateLeashEngine) runLoop(stop <-chan struct{}) {
	tk := time.NewTicker(5 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-tk.C:
			e.ObserveFlows(now, e.collectLiveFlows())
		}
	}
}

// ── HTTP: GET & POST /api/v6/update_leash ────────────────────────────────────

func (s *server) apiUpdateLeash(w http.ResponseWriter, r *http.Request) {
	eng := s.v6State().leash
	if r.Method == http.MethodGet {
		live := eng.collectLiveFlows()
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
			err := eng.saveConfigLocked()
			eng.mu.Unlock()
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write failed", "detail": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, eng.snapshot(false))

		case "bypass_once":
			mac := canonMAC(req.MAC)
			host := canonicalUpdateHostGroup(req.DstHost, "")
			skey := strings.TrimSpace(req.SessionKey)
			if skey == "" && mac != "" && host != "" {
				skey = mac + "|" + host
			}
			eng.mu.Lock()
			matched := 0
			if skey != "" {
				eng.bypassedSet[skey] = true
				delete(eng.pausedSet, skey)
				if sess, ok := eng.sessions[skey]; ok {
					sess.BypassOnce = true
					sess.Paused = false
					sess.State = leashStateBypassed
					sess.AppliedKbps = 0
				}
				matched++
			} else {
				for k, sess := range eng.sessions {
					if (mac == "" || sess.MAC == mac) && (host == "" || sess.DstHost == host) {
						eng.bypassedSet[k] = true
						delete(eng.pausedSet, k)
						sess.BypassOnce = true
						sess.Paused = false
						sess.State = leashStateBypassed
						sess.AppliedKbps = 0
						matched++
					}
				}
			}
			eng.mu.Unlock()
			resp := eng.snapshot(false)
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
						FirstSeen:      time.Now().Unix(),
						UpdatedAt:      time.Now().Unix(),
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
			writeJSON(w, http.StatusOK, resp)

		default:
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "action must be config|bypass_once|pause_update|resume_update"})
		}
	})(w, r)
}
