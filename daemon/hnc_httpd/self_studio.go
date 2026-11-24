// self_studio.go — v5.37.0 「亮屏智能常驻 + 熄屏休眠自动增量蒸馏」统一 DPI 自训练控制器
//
// 彻底收口旧版 /api/self/* 三散装开关与 Studio 手动会话的锁竞态:
//  1. 支持三态统一策略 (持久化于 data/self_policy.json, 进程重启不丢失、不泄漏后台抓包):
//     - smart_screen (默认推荐): 亮屏智能常驻 — 手机亮屏时自动挂载双路真值采集与个人飞轮,
//     熄屏立即拆除抓包句柄(0 轮询耗电), 并在熄屏静默满 25 秒且有新增样本时自动执行增量蒸馏 + 编译下发 dpid;
//     - lease_15m (兼容旧参 full / observe): 15 分钟集中快训 — 到期自动增量蒸馏并无损退回原模式(smart_screen 或 off);
//     - off (兼容旧参 stop): 完全关闭, 0 唤醒。
//  2. 修复 countLocalUsableArtifacts 未调用 fpFor(hncDir) + fpSt.loadLocked() 的统计与编译隐患。
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type selfStudioPolicy struct {
	Mode            string `json:"mode"` // "smart_screen" | "lease_15m" | "off"
	PrevMode        string `json:"prev_mode,omitempty"`
	AutoExpand      bool   `json:"auto_expand"`
	AutoPromote     bool   `json:"auto_promote"`
	LeaseEndUnix    int64  `json:"lease_end_unix,omitempty"`
	LastDistillUnix int64  `json:"last_distill_unix,omitempty"`
	LastSampleSize  int64  `json:"last_sample_size,omitempty"`
	UpdatedUnix     int64  `json:"updated_unix"`
}

var (
	studioMu           sync.Mutex
	studioDistillRunMu sync.Mutex
	studioLoadedDir    string
	studioPolicy       selfStudioPolicy
	studioLeaseGen     uint64
	studioStopTimer    *time.Timer
	studioQuietTimer   *time.Timer
	studioDistilling   bool
	lastStudioDistill  *studioDistillSummary
)

type studioDistillSummary struct {
	Ts            int64    `json:"ts"`
	DurationMS    int64    `json:"duration_ms"`
	SamplesRead   int      `json:"samples_read"`
	ExclusiveFPs  int      `json:"exclusive_fps"`
	StartupUsable int      `json:"startup_usable"`
	PrototypeApps int      `json:"prototype_apps,omitempty"`
	NBTrained     int      `json:"nb_trained_samples"`
	NBClasses     int      `json:"nb_classes"`
	DPISynced     bool     `json:"dpi_synced"`
	Hints         []string `json:"hints,omitempty"`
}

func selfPolicyPath(hncDir string) string {
	return filepath.Join(hncDir, "data", "self_policy.json")
}

func selfOptInPath(hncDir string) string {
	return filepath.Join(hncDir, "data", "self_capture.optin")
}

func selfRuntimePath(hncDir string) string {
	return filepath.Join(hncDir, "run", "self_runtime.json")
}

func notifySelfCaptureWake(s *server) {
	if s != nil {
		if v, ok := v6Registry.Load(s); ok && v != nil {
			if st, ok2 := v.(*v6ServerState); ok2 && st != nil && st.leakGuard != nil {
				st.leakGuard.notifySSEChanged()
			}
		}
	}
	activityNotifySubscribers()
}

func ensureStudioPolicyLocked(s *server) {
	if studioLoadedDir == s.hncDir && studioPolicy.Mode != "" {
		return
	}
	studioLoadedDir = s.hncDir
	if b, err := os.ReadFile(selfPolicyPath(s.hncDir)); err == nil {
		var p selfStudioPolicy
		if json.Unmarshal(b, &p) == nil && p.Mode != "" {
			studioPolicy = p
			return
		}
	}
	_, selfErr := os.Stat(s.selfFlagPath())
	_, optErr := os.Stat(selfOptInPath(s.hncDir))
	_, expErr := os.Stat(s.autoExpandFlagPath())
	_, proErr := os.Stat(s.autoPromoteFlagPath())
	mode := "off"
	autoExp := true
	autoPro := true
	if selfErr == nil || optErr == nil {
		mode = "smart_screen"
		if selfErr == nil {
			autoExp = expErr == nil
			autoPro = proErr == nil
		}
	}
	studioPolicy = selfStudioPolicy{
		Mode:        mode,
		PrevMode:    mode,
		AutoExpand:  autoExp,
		AutoPromote: autoPro,
		UpdatedUnix: time.Now().Unix(),
	}
}

func saveStudioPolicyLocked(hncDir string) {
	if b, err := json.MarshalIndent(studioPolicy, "", "  "); err == nil {
		_ = discoverWriteAtomic(selfPolicyPath(hncDir), append(b, '\n'))
	}
}

func screenCurrentlyOn() bool {
	a := activityNow()
	if a.Known && a.ScreenKnown {
		return a.ScreenOn
	}
	return true
}

func reconcileStudioFlagsLocked(s *server, now time.Time) (captureActive bool, screenOn bool, remSec int64) {
	ensureStudioPolicyLocked(s)
	nowU := now.Unix()
	screenOn = screenCurrentlyOn()

	if studioPolicy.Mode == "lease_15m" && studioPolicy.LeaseEndUnix > 0 {
		if nowU >= studioPolicy.LeaseEndUnix {
			fb := studioPolicy.PrevMode
			if fb == "" || fb == "lease_15m" {
				fb = "smart_screen"
			}
			studioPolicy.Mode = fb
			studioPolicy.LeaseEndUnix = 0
			saveStudioPolicyLocked(s.hncDir)
		} else {
			remSec = studioPolicy.LeaseEndUnix - nowU
		}
	}

	switch studioPolicy.Mode {
	case "smart_screen":
		captureActive = screenOn
	case "lease_15m":
		captureActive = screenOn
	default:
		captureActive = false
	}

	_, prevSelfErr := os.Stat(s.selfFlagPath())
	prevCap := prevSelfErr == nil

	_ = setStudioFlagFile(selfOptInPath(s.hncDir), studioPolicy.Mode != "off")
	_ = setStudioFlagFile(s.selfFlagPath(), captureActive)
	_ = setStudioFlagFile(s.autoExpandFlagPath(), captureActive && studioPolicy.AutoExpand)
	_ = setStudioFlagFile(s.autoPromoteFlagPath(), captureActive && studioPolicy.AutoPromote)

	rt, _ := json.Marshal(map[string]interface{}{
		"mode":          studioPolicy.Mode,
		"capture_on":    captureActive,
		"screen_on":     screenOn,
		"auto_expand":   studioPolicy.AutoExpand,
		"auto_promote":  studioPolicy.AutoPromote,
		"lease_rem_sec": remSec,
		"updated_unix":  nowU,
	})
	_ = discoverWriteAtomic(selfRuntimePath(s.hncDir), rt)

	if prevCap != captureActive {
		notifySelfCaptureWake(s)
	}
	return captureActive, screenOn, remSec
}

// SelfResidentLoop 监听全局亮屏/熄屏状态变化: 亮屏自动恢复常驻真值采集, 熄屏立即挂起抓包并按需静默增量蒸馏。
func (s *server) SelfResidentLoop(stopCh <-chan struct{}) {
	studioMu.Lock()
	_, _, _ = reconcileStudioFlagsLocked(s, time.Now())
	studioMu.Unlock()

	for {
		actCh := activityChanged()
		select {
		case <-stopCh:
			studioMu.Lock()
			if studioStopTimer != nil {
				studioStopTimer.Stop()
				studioStopTimer = nil
			}
			if studioQuietTimer != nil {
				studioQuietTimer.Stop()
				studioQuietTimer = nil
			}
			studioMu.Unlock()
			return
		case <-actCh:
			now := time.Now()
			studioMu.Lock()
			ensureStudioPolicyLocked(s)
			wasCapErr := func() bool { _, e := os.Stat(s.selfFlagPath()); return e == nil }()
			capNow, screenOn, _ := reconcileStudioFlagsLocked(s, now)
			needQuietDistill := !screenOn && studioPolicy.Mode != "off" && !studioDistilling &&
				now.Unix()-studioPolicy.LastDistillUnix >= 900 && hasNewLabelSamplesLocked(s.hncDir)
			if needQuietDistill && studioQuietTimer == nil {
				studioQuietTimer = time.AfterFunc(25*time.Second, func() {
					studioMu.Lock()
					ensureStudioPolicyLocked(s)
					if studioDistilling || studioPolicy.Mode == "off" || screenCurrentlyOn() {
						studioQuietTimer = nil
						studioMu.Unlock()
						return
					}
					studioDistilling = true
					studioQuietTimer = nil
					studioMu.Unlock()

					_, _ = runStudioDistillPipeline(s)

					studioMu.Lock()
					studioDistilling = false
					studioPolicy.LastDistillUnix = time.Now().Unix()
					studioPolicy.LastSampleSize = todaySampleFileSize(s.hncDir)
					saveStudioPolicyLocked(s.hncDir)
					studioMu.Unlock()
				})
			} else if (screenOn || studioPolicy.Mode == "off") && studioQuietTimer != nil {
				studioQuietTimer.Stop()
				studioQuietTimer = nil
			}
			studioMu.Unlock()

			if wasCapErr != capNow {
				_ = pokeDPIDStudio(s.hncDir, 450*time.Millisecond)
			}
		}
	}
}

func todaySampleFileSize(hncDir string) int64 {
	name := "label_samples." + time.Now().Format("20060102") + ".jsonl"
	for _, dir := range selfStudioScanDirs(hncDir) {
		if st, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return st.Size()
		}
	}
	return 0
}

func readLabelSamplesStatsRaw(hncDir string) ([]byte, error) {
	var lastErr error
	for _, dir := range selfStudioScanDirs(hncDir) {
		b, err := os.ReadFile(filepath.Join(dir, "label_samples.stats.json"))
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func hasNewLabelSamplesLocked(hncDir string) bool {
	sz := todaySampleFileSize(hncDir)
	return sz-studioPolicy.LastSampleSize >= 2048
}

func pokeDPIDStudio(hncDir string, waitMax time.Duration) bool {
	poke := filepath.Join(hncDir, "run", "self_studio.poke")
	_ = discoverWriteAtomic(poke, []byte("1\n"))
	deadline := time.Now().Add(waitMax)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(poke); os.IsNotExist(err) {
			return true
		}
		time.Sleep(45 * time.Millisecond)
	}
	return false
}

func setStudioFlagFile(path string, on bool) error {
	if on {
		return discoverWriteAtomic(path, []byte("enabled\n"))
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func countLocalUsableArtifacts(hncDir string, rp rpSources, now time.Time) (usableFPs int, usableStartups int) {
	nowUnix := now.Unix()
	fpSt := fpFor(hncDir)
	fpSt.mu.Lock()
	fpSt.loadLocked()
	for _, e := range fpSt.m {
		if e != nil && e.verdict(nowUnix).Usable {
			usableFPs++
		}
	}
	fpSt.mu.Unlock()
	usableFPs += len(rp.userJA4)

	learned, _ := startupFor(hncDir).learnedView(now)
	for _, a := range learned {
		if a.Usable {
			usableStartups++
		}
	}
	if usableFPs < len(rp.fps)+len(rp.userJA4) {
		usableFPs = len(rp.fps) + len(rp.userJA4)
	}
	if usableStartups < len(rp.startup) {
		usableStartups = len(rp.startup)
	}
	return usableFPs, usableStartups
}

func (s *server) apiSelfStudio(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"ok": false, "error": "GET only"})
		return
	}
	now := time.Now()
	hncDir := s.hncDir

	studioMu.Lock()
	captureActive, screenOn, leaseRem := reconcileStudioFlagsLocked(s, now)
	curMode := studioPolicy.Mode
	expOn := studioPolicy.AutoExpand && curMode != "off"
	proOn := studioPolicy.AutoPromote && curMode != "off"
	lastD := lastStudioDistill
	studioMu.Unlock()

	var userApps, activeApps, tlsEvents, dnsEvents, candHigh, expRules, proRules int
	var activeIfaces []map[string]interface{}
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "dpi_state.json")); err == nil && len(b) < 8<<20 {
		var st struct {
			Self *struct {
				CandidateHigh     int `json:"candidate_high"`
				CandidatePromoted int `json:"candidate_promoted"`
				AutoExpandedCount int `json:"auto_expanded_count"`
				AutoPromotedCount int `json:"auto_promoted_count"`
				Interfaces        []struct {
					Name      string `json:"name"`
					RxBytes   uint64 `json:"rx_bytes"`
					TLSEvents uint64 `json:"tls_events"`
					DNSEvents uint64 `json:"dns_events"`
				} `json:"interfaces"`
				AppsByUID map[string]struct {
					IsSystem    bool `json:"is_system"`
					ActiveConns int  `json:"active_conns"`
				} `json:"apps_by_uid"`
			} `json:"self"`
		}
		if json.Unmarshal(b, &st) == nil && st.Self != nil {
			candHigh = st.Self.CandidateHigh
			expRules = st.Self.AutoExpandedCount
			proRules = st.Self.CandidatePromoted
			if st.Self.AutoPromotedCount > proRules {
				proRules = st.Self.AutoPromotedCount
			}
			for _, ifc := range st.Self.Interfaces {
				kind := "other"
				if strings.HasPrefix(ifc.Name, "wlan") {
					kind = "wifi"
				} else if strings.HasPrefix(ifc.Name, "rmnet") || strings.HasPrefix(ifc.Name, "ccmni") || strings.HasPrefix(ifc.Name, "wwan") {
					kind = "cellular"
				} else if strings.HasPrefix(ifc.Name, "tun") || strings.HasPrefix(ifc.Name, "wg") {
					kind = "tun"
				}
				tlsEvents += int(ifc.TLSEvents)
				dnsEvents += int(ifc.DNSEvents)
				activeIfaces = append(activeIfaces, map[string]interface{}{
					"name":       ifc.Name,
					"kind":       kind,
					"rx_bytes":   ifc.RxBytes,
					"tls_events": ifc.TLSEvents,
					"dns_events": ifc.DNSEvents,
				})
			}
			for _, ap := range st.Self.AppsByUID {
				if !ap.IsSystem {
					userApps++
				}
				if ap.ActiveConns > 0 {
					activeApps++
				}
			}
		}
	}

	samplesCnt := 0
	if stB, err := readLabelSamplesStatsRaw(hncDir); err == nil {
		var ls struct {
			Written int `json:"written"`
		}
		if json.Unmarshal(stB, &ls) == nil {
			samplesCnt = ls.Written
		}
	}
	rp := rpCollect(hncDir, now)
	if expRules == 0 && len(rp.autoExpanded) > 0 {
		expRules = len(rp.autoExpanded)
	}
	if proRules == 0 && len(rp.autoPromoted) > 0 {
		proRules = len(rp.autoPromoted)
	}
	localFPs, localStartups := countLocalUsableArtifacts(hncDir, rp, now)

	fcPoolMu.Lock()
	nbPool := len(fcPool)
	fcPoolMu.Unlock()
	fcModelMu.RLock()
	nbClasses := 0
	if fcLiveModel != nil {
		nbClasses = len(fcLiveModel.m.NCat)
	}
	fcModelMu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":           true,
		"generated_at": now.Unix(),
		"capture": map[string]interface{}{
			"mode":                 curMode,
			"enabled":              curMode != "off",
			"capturing_now":        captureActive,
			"screen_on":            screenOn,
			"lease_active":         curMode == "lease_15m" && leaseRem > 0,
			"auto_expand_enabled":  expOn,
			"auto_promote_enabled": proOn,
			"lease_rem_sec":        leaseRem,
			"active_ifaces":        activeIfaces,
			"tls_events":           tlsEvents,
			"dns_events":           dnsEvents,
		},
		"counters": map[string]interface{}{
			"user_apps":        userApps,
			"active_apps":      activeApps,
			"samples_written":  samplesCnt,
			"expanded_rules":   expRules,
			"promoted_rules":   proRules,
			"candidate_high":   candHigh,
			"usable_fps":       localFPs,
			"usable_startups":  localStartups,
			"nb_pool_samples":  nbPool,
			"nb_classes_ready": nbClasses,
		},
		"rulepack": map[string]interface{}{
			"domains":  len(rp.userCustom) + len(rp.userDomain) + len(rp.autoExpanded) + len(rp.autoPromoted),
			"fps":      len(rp.fps) + len(rp.userJA4),
			"startups": len(rp.startup),
		},
		"last_distill": lastD,
	})
}

func dispatchStudioAction(s *server, action string, p map[string]string) (actionResp, bool) {
	switch action {
	case "self_studio_start":
		return actionSelfStudioStart(s, p), true
	case "self_studio_distill":
		return actionSelfStudioDistill(s, p), true
	case "self_studio_export":
		return actionSelfStudioExport(s, p), true
	case "dpi_distill_now":
		return actionDPIDistillNow(s, p), true
	case "flow_cls_retrain":
		n, cls, ok := TriggerFlowClsRetrain(s.hncDir, time.Now())
		b, _ := json.Marshal(map[string]interface{}{"samples": n, "classes": cls, "retrained": ok})
		return actionResp{OK: true, Detail: string(b)}, true
	default:
		return actionResp{}, false
	}
}

func actionSelfStudioStart(s *server, p map[string]string) actionResp {
	rawMode := strings.TrimSpace(p["mode"])
	if rawMode == "" {
		rawMode = "smart_screen"
	}
	var normMode string
	observeOnly := false
	switch rawMode {
	case "smart_screen":
		normMode = "smart_screen"
	case "lease_15m", "full":
		normMode = "lease_15m"
	case "observe":
		normMode = "lease_15m"
		observeOnly = true
	case "off", "stop":
		normMode = "off"
	default:
		return actionResp{OK: false, Error: "bad params", Detail: "mode must be smart_screen, lease_15m, full, observe, or off"}
	}

	now := time.Now()
	studioMu.Lock()
	ensureStudioPolicyLocked(s)
	studioLeaseGen++
	gen := studioLeaseGen
	if studioStopTimer != nil {
		studioStopTimer.Stop()
		studioStopTimer = nil
	}
	if v := strings.TrimSpace(p["auto_expand"]); v != "" {
		if b, ok := parseBoolStr(v); ok {
			studioPolicy.AutoExpand = b
		}
	}
	if v := strings.TrimSpace(p["auto_promote"]); v != "" {
		if b, ok := parseBoolStr(v); ok {
			studioPolicy.AutoPromote = b
		}
	}

	if normMode == "off" {
		if studioQuietTimer != nil {
			studioQuietTimer.Stop()
			studioQuietTimer = nil
		}
		studioPolicy.Mode = "off"
		studioPolicy.PrevMode = "off"
		studioPolicy.LeaseEndUnix = 0
		studioPolicy.UpdatedUnix = now.Unix()
		saveStudioPolicyLocked(s.hncDir)
		_, _, _ = reconcileStudioFlagsLocked(s, now)
		studioMu.Unlock()
		if p["distill"] == "1" {
			_, _ = runStudioDistillPipeline(s)
		}
		woke := pokeDPIDStudio(s.hncDir, 900*time.Millisecond)
		b, _ := json.Marshal(map[string]interface{}{
			"mode":          "off",
			"auto_stop_min": 0,
			"lease_rem_sec": 0,
			"dpid_synced":   woke,
		})
		return actionResp{OK: true, Detail: string(b)}
	}

	if normMode == "smart_screen" {
		studioPolicy.Mode = "smart_screen"
		studioPolicy.PrevMode = "smart_screen"
		studioPolicy.LeaseEndUnix = 0
		studioPolicy.UpdatedUnix = now.Unix()
		saveStudioPolicyLocked(s.hncDir)
		_, _, _ = reconcileStudioFlagsLocked(s, now)
		studioMu.Unlock()
		woke := pokeDPIDStudio(s.hncDir, 900*time.Millisecond)
		b, _ := json.Marshal(map[string]interface{}{
			"mode":          "smart_screen",
			"auto_stop_min": 0,
			"lease_rem_sec": 0,
			"dpid_synced":   woke,
		})
		return actionResp{OK: true, Detail: string(b)}
	}

	// normMode == "lease_15m"
	if studioPolicy.Mode != "lease_15m" {
		studioPolicy.PrevMode = studioPolicy.Mode
		if studioPolicy.PrevMode == "" {
			studioPolicy.PrevMode = "smart_screen"
		}
	}
	studioPolicy.Mode = "lease_15m"
	if observeOnly {
		studioPolicy.AutoExpand = false
		studioPolicy.AutoPromote = false
	}
	autoMin := 15
	if m, err := strconv.Atoi(strings.TrimSpace(p["auto_stop_min"])); err == nil && m >= 1 && m <= 180 {
		autoMin = m
	}
	dur := time.Duration(autoMin) * time.Minute
	studioPolicy.LeaseEndUnix = now.Add(dur).Unix()
	studioPolicy.UpdatedUnix = now.Unix()
	saveStudioPolicyLocked(s.hncDir)
	_, _, rem := reconcileStudioFlagsLocked(s, now)

	studioStopTimer = time.AfterFunc(dur, func() {
		studioMu.Lock()
		if studioLeaseGen != gen {
			studioMu.Unlock()
			return
		}
		studioMu.Unlock()

		_, _ = runStudioDistillPipeline(s)

		studioMu.Lock()
		if studioLeaseGen == gen {
			fb := studioPolicy.PrevMode
			if fb == "" || fb == "lease_15m" {
				fb = "smart_screen"
			}
			studioPolicy.Mode = fb
			studioPolicy.LeaseEndUnix = 0
			saveStudioPolicyLocked(s.hncDir)
			_, _, _ = reconcileStudioFlagsLocked(s, time.Now())
		}
		studioMu.Unlock()
		_ = pokeDPIDStudio(s.hncDir, 600*time.Millisecond)
	})
	studioMu.Unlock()

	woke := pokeDPIDStudio(s.hncDir, 900*time.Millisecond)
	b, _ := json.Marshal(map[string]interface{}{
		"mode":          rawMode,
		"auto_stop_min": autoMin,
		"lease_rem_sec": rem,
		"dpid_synced":   woke,
	})
	return actionResp{OK: true, Detail: string(b)}
}

func runStudioDistillPipeline(s *server) (studioDistillSummary, error) {
	studioDistillRunMu.Lock()
	defer studioDistillRunMu.Unlock()

	t0 := time.Now()
	synced := pokeDPIDStudio(s.hncDir, 1200*time.Millisecond)
	now := time.Now()
	rep, err := s.DistillPersonalNow(now, DistillOptions{LookbackDays: 7, AllowUnmappedPkg: true})
	nbN, nbCls, _ := TriggerFlowClsRetrain(s.hncDir, now)
	protoApps := distillFewShotPrototypes(s.hncDir, now)
	_ = exportCompiledFPForDPID(s.hncDir, now)
	_ = os.Chtimes(rpRulesDir(s.hncDir), now, now)
	_ = discoverWriteAtomic(filepath.Join(s.hncDir, "run", "dpi_rules.reload"), []byte(strconv.FormatInt(now.UnixNano(), 10)+"\n"))

	sum := studioDistillSummary{
		Ts:            now.Unix(),
		DurationMS:    time.Since(t0).Milliseconds(),
		SamplesRead:   rep.SamplesScanned,
		ExclusiveFPs:  rep.ExclusiveCount,
		StartupUsable: rep.StartupUsable,
		PrototypeApps: protoApps,
		NBTrained:     nbN,
		NBClasses:     nbCls,
		DPISynced:     synced,
		Hints:         rep.Hints,
	}
	studioMu.Lock()
	lastStudioDistill = &sum
	studioPolicy.LastDistillUnix = now.Unix()
	studioPolicy.LastSampleSize = todaySampleFileSize(s.hncDir)
	saveStudioPolicyLocked(s.hncDir)
	studioMu.Unlock()
	return sum, err
}

func actionSelfStudioDistill(s *server, _ map[string]string) actionResp {
	sum, err := runStudioDistillPipeline(s)
	if err != nil {
		return actionResp{OK: false, Error: "distill failed", Detail: err.Error()}
	}
	b, _ := json.Marshal(sum)
	return actionResp{OK: true, Detail: string(b)}
}

func actionSelfStudioExport(s *server, p map[string]string) actionResp {
	if p["distill_first"] != "0" {
		_, _ = runStudioDistillPipeline(s)
	}
	return actionDPIRulepackExport(s, p)
}
