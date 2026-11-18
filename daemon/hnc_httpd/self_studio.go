// self_studio.go — v5.36.0 「本机真值采集与 DPI 自训练飞轮工作台」(Host Self-Capture Studio)
//
// 解决个人用户「手头零外部抓包数据集」痛点:
//  1) 一键开启本机 wlan0 + rmnet_data* 双路真值采集 + 走法 1(同主域子域扩充) + 走法 2(高纯度新域晋升),
//     内置可配置的智能省电租约倒计时(默认 15 分钟自动停采并自动触发蒸馏落盘, 停采时还原用户原有飞轮开关);
//  2) GET /api/self/studio 单次聚合已捕获本机 App 数、域名真值样本数、JA4/QTP 本机可用指纹数、冷启动序列数与流分类器状态;
//  3) POST /api/action 支持 self_studio_start / self_studio_distill / self_studio_export,
//     在全局 actionMu 之外异步唤醒 dpid 并调用 DistillPersonalNow + TriggerFlowClsRetrain + 规则库热刷新。
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

type studioSavedFlags struct {
	exp bool
	pro bool
}

var (
	studioMu          sync.Mutex
	studioLeaseGen    uint64
	studioAutoStopEnd int64 // unix timestamp; 0 = 常驻不倒计时
	studioStopTimer   *time.Timer
	studioSaved       *studioSavedFlags
	lastStudioDistill *studioDistillSummary
)

type studioDistillSummary struct {
	Ts            int64    `json:"ts"`
	DurationMS    int64    `json:"duration_ms"`
	SamplesRead   int      `json:"samples_read"`
	ExclusiveFPs  int      `json:"exclusive_fps"`
	StartupUsable int      `json:"startup_usable"`
	NBTrained     int      `json:"nb_trained_samples"`
	NBClasses     int      `json:"nb_classes"`
	DPISynced     bool     `json:"dpi_synced"`
	Hints         []string `json:"hints,omitempty"`
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

	_, selfErr := os.Stat(s.selfFlagPath())
	_, expErr := os.Stat(s.autoExpandFlagPath())
	_, proErr := os.Stat(s.autoPromoteFlagPath())
	enabled := selfErr == nil
	expOn := expErr == nil
	proOn := proErr == nil

	studioMu.Lock()
	leaseEnd := studioAutoStopEnd
	lastD := lastStudioDistill
	studioMu.Unlock()
	leaseRem := int64(0)
	if enabled && leaseEnd > now.Unix() {
		leaseRem = leaseEnd - now.Unix()
	}

	// 读取 dpi_state.json 中的 self 实时计数
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
			proRules = st.Self.AutoPromotedCount
			if proRules == 0 && st.Self.CandidatePromoted > 0 {
				proRules = st.Self.CandidatePromoted
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
	if stB, err := os.ReadFile(filepath.Join(hncDir, "run", "label_samples.stats.json")); err == nil {
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
			"enabled":              enabled,
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

func stopStudioCaptureLocked(s *server) {
	studioAutoStopEnd = 0
	_ = setStudioFlagFile(s.selfFlagPath(), false)
	if studioSaved != nil {
		_ = setStudioFlagFile(s.autoExpandFlagPath(), studioSaved.exp)
		_ = setStudioFlagFile(s.autoPromoteFlagPath(), studioSaved.pro)
		studioSaved = nil
	}
}

func actionSelfStudioStart(s *server, p map[string]string) actionResp {
	mode := strings.TrimSpace(p["mode"])
	if mode == "" {
		mode = "full"
	}
	if mode != "full" && mode != "observe" && mode != "stop" {
		return actionResp{OK: false, Error: "bad params", Detail: "mode must be full, observe, or stop"}
	}

	studioMu.Lock()
	studioLeaseGen++
	gen := studioLeaseGen
	if studioStopTimer != nil {
		studioStopTimer.Stop()
		studioStopTimer = nil
	}
	studioAutoStopEnd = 0

	if mode == "stop" {
		stopStudioCaptureLocked(s)
		studioMu.Unlock()
		woke := pokeDPIDStudio(s.hncDir, 900*time.Millisecond)
		b, _ := json.Marshal(map[string]interface{}{
			"mode":          "stop",
			"auto_stop_min": 0,
			"lease_rem_sec": 0,
			"dpid_synced":   woke,
		})
		return actionResp{OK: true, Detail: string(b)}
	}

	if studioSaved == nil {
		_, expErr := os.Stat(s.autoExpandFlagPath())
		_, proErr := os.Stat(s.autoPromoteFlagPath())
		studioSaved = &studioSavedFlags{exp: expErr == nil, pro: proErr == nil}
	}
	if err := setStudioFlagFile(s.selfFlagPath(), true); err != nil {
		studioMu.Unlock()
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	if err := setStudioFlagFile(s.autoExpandFlagPath(), mode == "full"); err != nil {
		studioMu.Unlock()
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	if err := setStudioFlagFile(s.autoPromoteFlagPath(), mode == "full"); err != nil {
		studioMu.Unlock()
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}

	autoMin := 0
	if m, err := strconv.Atoi(strings.TrimSpace(p["auto_stop_min"])); err == nil && m >= 1 && m <= 180 {
		autoMin = m
	} else if p["auto_stop_min"] == "" {
		autoMin = 15 // 默认 15 分钟智能省电保护: 到点自动停采并触发蒸馏落盘
	}
	if autoMin > 0 {
		dur := time.Duration(autoMin) * time.Minute
		studioAutoStopEnd = time.Now().Add(dur).Unix()
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
				stopStudioCaptureLocked(s)
			}
			studioMu.Unlock()
			_ = pokeDPIDStudio(s.hncDir, 600*time.Millisecond)
			s.requestSnapshotRefresh()
		})
	}
	leaseEnd := studioAutoStopEnd
	studioMu.Unlock()

	woke := pokeDPIDStudio(s.hncDir, 900*time.Millisecond)
	b, _ := json.Marshal(map[string]interface{}{
		"mode":          mode,
		"auto_stop_min": autoMin,
		"lease_rem_sec": maxInt64(0, leaseEnd-time.Now().Unix()),
		"dpid_synced":   woke,
	})
	return actionResp{OK: true, Detail: string(b)}
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func runStudioDistillPipeline(s *server) (studioDistillSummary, error) {
	t0 := time.Now()
	synced := pokeDPIDStudio(s.hncDir, 1200*time.Millisecond)
	now := time.Now()
	rep, err := s.DistillPersonalNow(now, DistillOptions{LookbackDays: 7, AllowUnmappedPkg: true})
	nbN, nbCls, _ := TriggerFlowClsRetrain(s.hncDir, now)
	_ = os.Chtimes(rpRulesDir(s.hncDir), now, now)
	_ = discoverWriteAtomic(filepath.Join(s.hncDir, "run", "dpi_rules.reload"), []byte(strconv.FormatInt(now.UnixNano(), 10)+"\n"))
	s.requestSnapshotRefresh()

	sum := studioDistillSummary{
		Ts:            now.Unix(),
		DurationMS:    time.Since(t0).Milliseconds(),
		SamplesRead:   rep.SamplesScanned,
		ExclusiveFPs:  rep.ExclusiveCount,
		StartupUsable: rep.StartupUsable,
		NBTrained:     nbN,
		NBClasses:     nbCls,
		DPISynced:     synced,
		Hints:         rep.Hints,
	}
	studioMu.Lock()
	lastStudioDistill = &sum
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
