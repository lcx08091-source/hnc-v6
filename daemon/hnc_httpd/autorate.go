// autorate.go — HNC v5.37.0: 上游 5G 信号波动自适应总带宽控制器 (CAKE/HTB Autorate)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	autorateDefaultDownMinMbps = 24.0
	autorateDefaultDownMaxMbps = 320.0
	autorateDefaultUpMinMbps   = 8.0
	autorateDefaultUpMaxMbps   = 80.0
	autorateDefaultDeltaMS     = 25.0

	autorateActiveTick   = 2 * time.Second
	autorateIdleTraffic  = 0.15
	autorateHighLoad     = 0.75
	autorateActiveBloat  = 0.25
	autorateRefractory   = 1500 * time.Millisecond
	autorateTuneDeadband = 0.03
)

var defaultAutorateReflectors = []string{
	"223.5.5.5:443",
	"119.29.29.29:443",
	"1.1.1.1:443",
	"8.8.8.8:53",
}

type autorateConfig struct {
	Enabled     bool     `json:"enabled"`
	DownMinMbps float64  `json:"down_min_mbps"`
	DownMaxMbps float64  `json:"down_max_mbps"`
	UpMinMbps   float64  `json:"up_min_mbps"`
	UpMaxMbps   float64  `json:"up_max_mbps"`
	RTTDeltaMs  float64  `json:"rtt_delta_ms"`
	Reflectors  []string `json:"reflectors,omitempty"`
}

type autorateStatus struct {
	Enabled        bool     `json:"enabled"`
	DownMinMbps    float64  `json:"down_min_mbps"`
	DownMaxMbps    float64  `json:"down_max_mbps"`
	UpMinMbps      float64  `json:"up_min_mbps"`
	UpMaxMbps      float64  `json:"up_max_mbps"`
	RTTDeltaMs     float64  `json:"rtt_delta_ms"`
	State          string   `json:"state"`
	SleepReason    string   `json:"sleep_reason,omitempty"`
	HotspotIface   string   `json:"hotspot_iface,omitempty"`
	UpstreamIface  string   `json:"upstream_iface,omitempty"`
	CurDownMbps    float64  `json:"cur_down_mbps"`
	CurUpMbps      float64  `json:"cur_up_mbps"`
	ActualDownMbps float64  `json:"actual_down_mbps"`
	ActualUpMbps   float64  `json:"actual_up_mbps"`
	LoadDown       float64  `json:"load_down"`
	LoadUp         float64  `json:"load_up"`
	BaseRTTMs      float64  `json:"base_rtt_ms"`
	RTTMs          float64  `json:"rtt_ms"`
	DeltaRTTMs     float64  `json:"delta_rtt_ms"`
	ScaleEventsUp  uint64   `json:"scale_events_up"`
	ScaleEventsDn  uint64   `json:"scale_events_down"`
	UpdatedAt       int64    `json:"updated_at"`
	SignalRAT       string   `json:"signal_rat,omitempty"`
	SignalDbm       int      `json:"signal_dbm,omitempty"`
	SignalQuality   string   `json:"signal_quality,omitempty"`
	RFCeilingFactor float64  `json:"rf_ceiling_factor,omitempty"`
	DiagnosisCode   string   `json:"diagnosis_code,omitempty"`
	Reflectors      []string `json:"reflectors,omitempty"`
}

type autorateCtl struct {
	hncDir        string
	mu            sync.RWMutex
	cfg           autorateConfig
	st            autorateStatus
	wakeCh        chan struct{}
	prevDev       map[string][2]uint64
	prevSampleAt  time.Time
	fastRTT       float64
	lastBackoffAt time.Time
	appliedIface  string
	appliedDown   float64
	appliedUp     float64
	refCursor     int
	lastSignalRAT string
}

func defaultAutorateConfig() autorateConfig {
	return autorateConfig{
		Enabled:     false,
		DownMinMbps: autorateDefaultDownMinMbps,
		DownMaxMbps: autorateDefaultDownMaxMbps,
		UpMinMbps:   autorateDefaultUpMinMbps,
		UpMaxMbps:   autorateDefaultUpMaxMbps,
		RTTDeltaMs:  autorateDefaultDeltaMS,
		Reflectors:  append([]string(nil), defaultAutorateReflectors...),
	}
}

func invalidFiniteFloat(v float64) bool {
	return math.IsNaN(v) || math.IsInf(v, 0)
}

func normalizeAutorateConfig(c autorateConfig) autorateConfig {
	if invalidFiniteFloat(c.DownMinMbps) || c.DownMinMbps < 1 || c.DownMinMbps > 10000 {
		c.DownMinMbps = autorateDefaultDownMinMbps
	}
	if invalidFiniteFloat(c.DownMaxMbps) || c.DownMaxMbps < c.DownMinMbps || c.DownMaxMbps > 10000 {
		c.DownMaxMbps = math.Max(c.DownMinMbps*2, autorateDefaultDownMaxMbps)
	}
	if invalidFiniteFloat(c.UpMinMbps) || c.UpMinMbps < 1 || c.UpMinMbps > 10000 {
		c.UpMinMbps = autorateDefaultUpMinMbps
	}
	if invalidFiniteFloat(c.UpMaxMbps) || c.UpMaxMbps < c.UpMinMbps || c.UpMaxMbps > 10000 {
		c.UpMaxMbps = math.Max(c.UpMinMbps*2, autorateDefaultUpMaxMbps)
	}
	if invalidFiniteFloat(c.RTTDeltaMs) || c.RTTDeltaMs < 5 || c.RTTDeltaMs > 250 {
		c.RTTDeltaMs = autorateDefaultDeltaMS
	}
	if len(c.Reflectors) == 0 {
		c.Reflectors = append([]string(nil), defaultAutorateReflectors...)
	}
	return c
}

func newAutorateCtl(hncDir string) *autorateCtl {
	c := &autorateCtl{
		hncDir: hncDir,
		wakeCh: make(chan struct{}, 1),
	}
	cfg := c.loadConfigFromDisk()
	c.cfg = cfg
	c.syncStatusConfigLocked(cfg)
	c.st.CurDownMbps = round2((cfg.DownMinMbps + cfg.DownMaxMbps) * 0.5)
	c.st.CurUpMbps = round2((cfg.UpMinMbps + cfg.UpMaxMbps) * 0.5)
	if cfg.Enabled {
		c.st.State = "sleeping"
	} else {
		c.st.State = "disabled"
	}
	c.st.UpdatedAt = time.Now().Unix()
	return c
}

func (c *autorateCtl) syncStatusConfigLocked(cfg autorateConfig) {
	c.st.Enabled = cfg.Enabled
	c.st.DownMinMbps = cfg.DownMinMbps
	c.st.DownMaxMbps = cfg.DownMaxMbps
	c.st.UpMinMbps = cfg.UpMinMbps
	c.st.UpMaxMbps = cfg.UpMaxMbps
	c.st.RTTDeltaMs = cfg.RTTDeltaMs
	c.st.Reflectors = append([]string(nil), cfg.Reflectors...)
}

func (c *autorateCtl) configPath() string {
	return filepath.Join(c.hncDir, "data", "autorate.json")
}

func (c *autorateCtl) loadConfigFromDisk() autorateConfig {
	def := defaultAutorateConfig()
	b, err := os.ReadFile(c.configPath())
	if err != nil {
		return def
	}
	var parsed autorateConfig
	if json.Unmarshal(b, &parsed) != nil {
		return def
	}
	return normalizeAutorateConfig(parsed)
}

func (c *autorateCtl) saveConfigToDisk(cfg autorateConfig) error {
	cfg = normalizeAutorateConfig(cfg)
	if err := os.MkdirAll(filepath.Dir(c.configPath()), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return discoverWriteAtomic(c.configPath(), append(b, '\n'))
}

func (c *autorateCtl) Poke() {
	select {
	case c.wakeCh <- struct{}{}:
	default:
	}
}

func (c *autorateCtl) Snapshot() autorateStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cp := c.st
	cp.Reflectors = append([]string(nil), c.st.Reflectors...)
	return cp
}

func (c *autorateCtl) Config() autorateConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cp := c.cfg
	cp.Reflectors = append([]string(nil), c.cfg.Reflectors...)
	return cp
}

func (c *autorateCtl) DisableFromStaticShaper() {
	c.mu.Lock()
	if !c.cfg.Enabled {
		c.mu.Unlock()
		return
	}
	c.cfg.Enabled = false
	c.syncStatusConfigLocked(c.cfg)
	c.st.State = "disabled"
	c.st.SleepReason = ""
	c.st.RTTMs = 0
	c.st.DeltaRTTMs = 0
	c.st.UpdatedAt = time.Now().Unix()
	cfgCopy := c.cfg
	c.mu.Unlock()
	_ = c.saveConfigToDisk(cfgCopy)
	c.Poke()
}

func mbpsToTcRate(mbps float64) string {
	if mbps <= 0 {
		return "0"
	}
	kbit := int(math.Round(mbps * 1000))
	if kbit < minRateKbit {
		kbit = minRateKbit
	}
	if kbit%1000 == 0 {
		return fmt.Sprintf("%dmbit", kbit/1000)
	}
	return fmt.Sprintf("%dkbit", kbit)
}

func parseBoolStr(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "on", "yes":
		return true, true
	case "false", "0", "off", "no":
		return false, true
	default:
		return false, false
	}
}

func (c *autorateCtl) ApplyConfig(next autorateConfig, hotspotIface string) actionResp {
	next = normalizeAutorateConfig(next)
	if next.Enabled {
		if supported, known := tcHTBSupported(c.hncDir); known && !supported {
			return actionResp{OK: false, Error: "unsupported", Detail: "tc_htb=false; 5G 自适应整形依赖内核 HTB"}
		}
	}
	initDown := round2((next.DownMinMbps + next.DownMaxMbps) * 0.6)
	initUp := round2((next.UpMinMbps + next.UpMaxMbps) * 0.6)
	downStr := mbpsToTcRate(initDown)
	upStr := mbpsToTcRate(initUp)

	if next.Enabled {
		if hotspotIface != "" {
			if rc, out := runBin(c.hncDir, "tc_manager.sh", "global_shaper", hotspotIface, "on", downStr, upStr); rc != 0 {
				return actionResp{OK: false, Error: "shaper apply failed", Detail: strings.TrimSpace(out)}
			}
		}
		InvalidateDataplaneReconcileNative(c.hncDir, "")
		_, _ = runBin(c.hncDir, "json_set.sh", "top", "global_shaper_down", downStr)
		_, _ = runBin(c.hncDir, "json_set.sh", "top", "global_shaper_up", upStr)
		_, _ = runBin(c.hncDir, "json_set.sh", "top", "global_shaper_enabled", "true")
	} else {
		if hotspotIface != "" {
			_, _ = runBin(c.hncDir, "tc_manager.sh", "global_shaper", hotspotIface, "off", "0", "0")
		}
		InvalidateDataplaneReconcileNative(c.hncDir, "")
		_, _ = runBin(c.hncDir, "json_set.sh", "top", "global_shaper_enabled", "false")
	}

	if err := c.saveConfigToDisk(next); err != nil {
		return actionResp{OK: false, Error: "autorate write failed", Detail: err.Error()}
	}

	c.mu.Lock()
	c.cfg = next
	c.syncStatusConfigLocked(next)
	c.st.CurDownMbps = initDown
	c.st.CurUpMbps = initUp
	c.appliedIface = hotspotIface
	c.appliedDown = initDown
	c.appliedUp = initUp
	if next.Enabled {
		c.st.State = "sleeping"
	} else {
		c.st.State = "disabled"
		c.st.SleepReason = ""
	}
	c.st.RTTMs = 0
	c.st.DeltaRTTMs = 0
	c.st.UpdatedAt = time.Now().Unix()
	c.mu.Unlock()
	c.Poke()

	if !next.Enabled {
		return actionResp{OK: true, Detail: "5G autorate off"}
	}
	return actionResp{
		OK:     true,
		Detail: fmt.Sprintf("5G autorate on down=[%.0f..%.0f]Mbps up=[%.0f..%.0f]Mbps delta=%.0fms", next.DownMinMbps, next.DownMaxMbps, next.UpMinMbps, next.UpMaxMbps, next.RTTDeltaMs),
	}
}

func (s *server) apiAutorate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.autorate.Snapshot())
}

func actionAutorateSet(s *server, p map[string]string) actionResp {
	cur := s.autorate.Config()
	if raw, ok := p["autorate_enabled"]; ok && strings.TrimSpace(raw) != "" {
		en, valid := parseBoolStr(raw)
		if !valid {
			return actionResp{OK: false, Error: "bad params", Detail: "autorate_enabled must be true/false"}
		}
		cur.Enabled = en
	} else if en, ok := parseEnabledParam(p); ok {
		cur.Enabled = en
	}

	badFloatKey := ""
	parseF := func(key string) (float64, bool) {
		v := strings.TrimSpace(p[key])
		if v == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(v, 64)
		if err == nil && invalidFiniteFloat(f) {
			if badFloatKey == "" {
				badFloatKey = key
			}
			return 0, false
		}
		if err != nil || invalidFiniteFloat(f) || f <= 0 || f > 10000 {
			return 0, false
		}
		return f, true
	}

	if f, ok := parseF("down_min_mbps"); ok {
		cur.DownMinMbps = f
	}
	if f, ok := parseF("down_max_mbps"); ok {
		cur.DownMaxMbps = f
	} else if f, ok := parseF("base_down_mbps"); ok {
		cur.DownMaxMbps = f * 1.8
		if mPct, err := strconv.Atoi(strings.TrimSpace(p["min_percent"])); err == nil && mPct >= 15 && mPct <= 90 {
			cur.DownMinMbps = math.Max(2, f*float64(mPct)/100.0)
		}
	}
	if f, ok := parseF("up_min_mbps"); ok {
		cur.UpMinMbps = f
	}
	if f, ok := parseF("up_max_mbps"); ok {
		cur.UpMaxMbps = f
	} else if f, ok := parseF("base_up_mbps"); ok {
		cur.UpMaxMbps = f * 1.8
		if mPct, err := strconv.Atoi(strings.TrimSpace(p["min_percent"])); err == nil && mPct >= 15 && mPct <= 90 {
			cur.UpMinMbps = math.Max(1, f*float64(mPct)/100.0)
		}
	}
	if f, ok := parseF("rtt_delta_ms"); ok {
		cur.RTTDeltaMs = f
	} else if f, ok := parseF("max_delta_rtt_ms"); ok {
		cur.RTTDeltaMs = f
	}
	if badFloatKey != "" {
		return actionResp{OK: false, Error: "bad params", Detail: badFloatKey + " must be a finite number"}
	}
	if cur.DownMinMbps > cur.DownMaxMbps || cur.UpMinMbps > cur.UpMaxMbps {
		return actionResp{OK: false, Error: "bad params", Detail: "min bandwidth cannot exceed max bandwidth"}
	}

	iface := s.currentHotspotIface()
	if iface == "" {
		_, out := runBin(s.hncDir, "device_detect.sh", "iface")
		iface = strings.TrimSpace(out)
	}
	return s.autorate.ApplyConfig(cur, iface)
}

func (s *server) resolvePhysicalUpstream(devMap map[string][2]uint64) string {
	det := readIfaceDetect(s.hncDir)
	for _, cand := range []string{det.TetherUpstream, det.Upstream} {
		if cand != "" && !isVPNIface(cand) && ifaceNameOK(cand) {
			return cand
		}
	}
	var bestIface string
	var bestBytes uint64
	for ifc, cnt := range devMap {
		if isCellIface(ifc) {
			sum := cnt[0] + cnt[1]
			if sum > bestBytes {
				bestBytes = sum
				bestIface = ifc
			}
		}
	}
	return bestIface
}

func probeReflectorRTT(upstreamIface string, reflectors []string, cursor *int) (float64, bool) {
	if len(reflectors) == 0 {
		reflectors = defaultAutorateReflectors
	}
	n := len(reflectors)
	targets := make([]string, 0, 2)
	for i := 0; i < 2 && i < n; i++ {
		targets = append(targets, reflectors[(*cursor+i)%n])
	}
	*cursor = (*cursor + len(targets)) % n

	type res struct {
		ms float64
		ok bool
	}
	ch := make(chan res, len(targets))
	for _, target := range targets {
		go func(addr string) {
			d := net.Dialer{
				Timeout: 900 * time.Millisecond,
				Control: func(network, address string, c syscall.RawConn) error {
					if upstreamIface == "" {
						return nil
					}
					var bindErr error
					if err := c.Control(func(fd uintptr) {
						bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, upstreamIface)
					}); err != nil {
						return err
					}
					return bindErr
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
			defer cancel()
			t0 := time.Now()
			conn, err := d.DialContext(ctx, "tcp4", addr)
			rtt := float64(time.Since(t0).Microseconds()) / 1000.0
			if err != nil {
				ch <- res{0, false}
				return
			}
			_ = conn.Close()
			if rtt <= 0.2 || rtt > 2000 {
				ch <- res{0, false}
				return
			}
			ch <- res{rtt, true}
		}(target)
	}

	best := math.MaxFloat64
	got := false
	for range targets {
		r := <-ch
		if r.ok && r.ms < best {
			best = r.ms
			got = true
		}
	}
	if !got {
		return 0, false
	}
	return best, true
}

func (s *server) AutorateLoop(stopCh <-chan struct{}) {
	ctl := s.autorate
	for {
		cfg := ctl.Config()
		if !cfg.Enabled {
			ctl.mu.Lock()
			ctl.st.State = "disabled"
			ctl.st.SleepReason = "autorate_disabled"
			ctl.st.RTTMs = 0
			ctl.st.DeltaRTTMs = 0
			ctl.prevSampleAt = time.Time{}
			ctl.mu.Unlock()
			select {
			case <-stopCh:
				return
			case <-ctl.wakeCh:
				continue
			}
		}

		actCh := activityChanged()
		act := activityNow()
		simOn := s.simActive()
		if !simOn && (!act.HotspotActive || act.ClientsOnline <= 0) {
			reason := "no_active_clients"
			if !act.HotspotActive {
				reason = "hotspot_off"
			}
			invalidateDP := false
			ctl.mu.Lock()
			if reason == "hotspot_off" && (ctl.st.SleepReason != "hotspot_off" || ctl.appliedIface != "") {
				ctl.appliedIface = ""
				ctl.appliedDown = 0
				ctl.appliedUp = 0
				invalidateDP = true
			}
			ctl.st.State = "sleeping"
			ctl.st.SleepReason = reason
			ctl.st.LoadDown = 0
			ctl.st.LoadUp = 0
			ctl.st.ActualDownMbps = 0
			ctl.st.ActualUpMbps = 0
			ctl.st.RTTMs = 0
			ctl.st.DeltaRTTMs = 0
			ctl.prevSampleAt = time.Time{}
			ctl.mu.Unlock()
			if invalidateDP {
				hncDir := ctl.hncDir
				if hncDir == "" {
					hncDir = s.hncDir
				}
				InvalidateDataplaneReconcileNative(hncDir, "")
			}

			select {
			case <-stopCh:
				return
			case <-ctl.wakeCh:
				continue
			case <-actCh:
				continue
			}
		}

		s.autorateStep(cfg)
		waitDur, reason := powerInterval("autorate", act, loopFlags{})
		if waitDur <= 0 || act.ClientsOnline > 0 || simOn {
			waitDur = autorateActiveTick
		}
		powerRecord("autorate", waitDur, reason, time.Now())

		timer := time.NewTimer(waitDur)
		select {
		case <-stopCh:
			timer.Stop()
			return
		case <-ctl.wakeCh:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (s *server) autorateStep(cfg autorateConfig) {
	ctl := s.autorate
	hotspotIface := s.currentHotspotIface()
	if hotspotIface == "" {
		return
	}
	rawDev, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	curDev := puParseNetDev(rawDev)
	now := time.Now()
	upstreamIface := s.resolvePhysicalUpstream(curDev)

	if ctl.prevSampleAt.IsZero() || now.Sub(ctl.prevSampleAt) <= 100*time.Millisecond {
		ctl.prevDev = curDev
		ctl.prevSampleAt = now
		return
	}
	dt := now.Sub(ctl.prevSampleAt).Seconds()
	hsPrev, hsOK := ctl.prevDev[hotspotIface]
	hsCur, hsCurOK := curDev[hotspotIface]
	ctl.prevDev = curDev
	ctl.prevSampleAt = now
	if !hsOK || !hsCurOK || dt <= 0 {
		return
	}

	var downBytes, upBytes uint64
	if hsCur[1] >= hsPrev[1] {
		downBytes = hsCur[1] - hsPrev[1]
	}
	if hsCur[0] >= hsPrev[0] {
		upBytes = hsCur[0] - hsPrev[0]
	}
	actualDownMbps := (float64(downBytes) * 8.0) / (dt * 1e6)
	actualUpMbps := (float64(upBytes) * 8.0) / (dt * 1e6)

	var sig hostSignalStatus
	if s.signalCtl != nil {
		sig = s.signalCtl.Snapshot(s)
	}
	effDownMax := cfg.DownMaxMbps
	effUpMax := cfg.UpMaxMbps
	if sig.Available && sig.RFCeilingFactor > 0 && sig.RFCeilingFactor < 1.0 {
		effDownMax = math.Max(cfg.DownMinMbps, cfg.DownMaxMbps*sig.RFCeilingFactor)
		effUpMax = math.Max(cfg.UpMinMbps, cfg.UpMaxMbps*sig.RFCeilingFactor)
	}

	ctl.mu.RLock()
	curDown := ctl.st.CurDownMbps
	curUp := ctl.st.CurUpMbps
	baseRTT := ctl.st.BaseRTTMs
	prevRAT := ctl.lastSignalRAT
	ctl.mu.RUnlock()

	// v6.0.0: 仅在跨代际制式切换 (5G <-> 4G LTE <-> Wi-Fi) 瞬间重锚定 BaseRTT, 避免 5G SA/NSA/5G-A 载波聚合跳变误清空基线!
	if sig.Available && sig.RAT != "" && prevRAT != "" && ratGeneration(sig.RAT) != ratGeneration(prevRAT) {
		baseRTT = 0
		ctl.fastRTT = 0
	}

	loadDown := actualDownMbps / math.Max(1.0, curDown)
	loadUp := actualUpMbps / math.Max(1.0, curUp)

	midDown := (cfg.DownMinMbps + effDownMax) * 0.55
	midUp := (cfg.UpMinMbps + effUpMax) * 0.55
	nextDown, nextUp := curDown, curUp
	newState := "active"
	var sampleRTT, deltaRTT float64
	var scaleUpInc, scaleDnInc uint64

	if math.Max(loadDown, loadUp) < autorateIdleTraffic {
		newState = "idle_traffic"
		nextDown = curDown + (midDown-curDown)*0.05
		nextUp = curUp + (midUp-curUp)*0.05
	} else if rtt, ok := probeReflectorRTT(upstreamIface, cfg.Reflectors, &ctl.refCursor); ok {
		sampleRTT = rtt
		if baseRTT <= 0 {
			baseRTT = rtt
			ctl.fastRTT = rtt
		} else {
			if rtt < baseRTT {
				baseRTT = 0.92*baseRTT + 0.08*rtt
			} else if math.Max(loadDown, loadUp) < 0.50 {
				baseRTT = 0.998*baseRTT + 0.002*rtt
			}
			ctl.fastRTT = 0.50*ctl.fastRTT + 0.50*rtt
		}
		deltaRTT = math.Max(0, ctl.fastRTT-baseRTT)

		if deltaRTT > cfg.RTTDeltaMs {
			newState = "backoff"
			if now.Sub(ctl.lastBackoffAt) >= autorateRefractory {
				excess := math.Min(1.0, (deltaRTT-cfg.RTTDeltaMs)/cfg.RTTDeltaMs)
				beta := 0.85 - 0.15*excess
				downBusy := loadDown >= autorateActiveBloat
				upBusy := loadUp >= autorateActiveBloat
				if downBusy || !upBusy {
					nextDown = math.Max(cfg.DownMinMbps, curDown*beta)
				}
				if upBusy || !downBusy {
					nextUp = math.Max(cfg.UpMinMbps, curUp*beta)
				}
				ctl.lastBackoffAt = now
				scaleDnInc = 1
			}
		} else if deltaRTT <= 0.60*cfg.RTTDeltaMs {
			if loadDown >= autorateHighLoad {
				nextDown = math.Min(effDownMax, curDown*1.08+1.0)
				scaleUpInc = 1
			}
			if loadUp >= autorateHighLoad {
				nextUp = math.Min(effUpMax, curUp*1.08+0.5)
				scaleUpInc = 1
			}
		}
	}

	nextDown = math.Max(cfg.DownMinMbps, math.Min(effDownMax, nextDown))
	nextUp = math.Max(cfg.UpMinMbps, math.Min(effUpMax, nextUp))

	ctl.mu.RLock()
	prevIface := ctl.appliedIface
	prevDown := ctl.appliedDown
	prevUp := ctl.appliedUp
	stillEnabled := ctl.cfg.Enabled
	ctl.mu.RUnlock()
	if !stillEnabled {
		return
	}

	needTune := prevIface != hotspotIface ||
		math.Abs(nextDown-prevDown) >= math.Max(0.5, prevDown*autorateTuneDeadband) ||
		math.Abs(nextUp-prevUp) >= math.Max(0.3, prevUp*autorateTuneDeadband)

	tunedOK := false
	if needTune {
		// 严格遵守全局锁序 s.actionMu -> ctl.mu, 防止与用户关闭/静态调速并发竞争
		s.actionMu.Lock()
		ctl.mu.RLock()
		stillEnabled = ctl.cfg.Enabled
		prevIface = ctl.appliedIface
		prevDown = ctl.appliedDown
		prevUp = ctl.appliedUp
		ctl.mu.RUnlock()
		if !stillEnabled {
			s.actionMu.Unlock()
			return
		}
		needTune = prevIface != hotspotIface ||
			math.Abs(nextDown-prevDown) >= math.Max(0.5, prevDown*autorateTuneDeadband) ||
			math.Abs(nextUp-prevUp) >= math.Max(0.3, prevUp*autorateTuneDeadband)
		if needTune {
			hncDir := ctl.hncDir
			if hncDir == "" {
				hncDir = s.hncDir
			}
			downKbps := int(math.Round(nextDown * 1000))
			upKbps := int(math.Round(nextUp * 1000))
			if downKbps < minRateKbit {
				downKbps = minRateKbit
			}
			if upKbps < minRateKbit {
				upKbps = minRateKbit
			}
			if useNativeDataplane(hncDir) {
				if err := TuneGlobalShaperNative(hncDir, downKbps, upKbps); err == nil {
					tunedOK = true
				}
			}
			if !tunedOK {
				rc, out := runBin(s.hncDir, "tc_manager.sh", "global_shaper_tune", hotspotIface, mbpsToTcRate(nextDown), mbpsToTcRate(nextUp))
				if rc == 0 {
					tunedOK = true
				} else {
					log.Printf("autorate: global_shaper_tune failed on %s: %s", hotspotIface, strings.TrimSpace(out))
				}
			}
		}
		ctl.mu.Lock()
		if !ctl.cfg.Enabled {
			ctl.mu.Unlock()
			s.actionMu.Unlock()
			return
		}
		if tunedOK {
			ctl.appliedIface = hotspotIface
			ctl.appliedDown = nextDown
			ctl.appliedUp = nextUp
		}
		ctl.mu.Unlock()
		s.actionMu.Unlock()
	}

	ctl.mu.Lock()
	if !ctl.cfg.Enabled {
		ctl.mu.Unlock()
		return
	}
	ctl.st.State = newState
	ctl.st.SleepReason = ""
	ctl.st.HotspotIface = hotspotIface
	ctl.st.UpstreamIface = upstreamIface
	ctl.st.CurDownMbps = round2(nextDown)
	ctl.st.CurUpMbps = round2(nextUp)
	ctl.st.ActualDownMbps = round2(actualDownMbps)
	ctl.st.ActualUpMbps = round2(actualUpMbps)
	ctl.st.LoadDown = round2(loadDown)
	ctl.st.LoadUp = round2(loadUp)
	ctl.st.BaseRTTMs = round2(baseRTT)
	if sampleRTT > 0 {
		ctl.st.RTTMs = round2(sampleRTT)
		ctl.st.DeltaRTTMs = round2(deltaRTT)
	} else if newState == "idle_traffic" {
		ctl.st.RTTMs = 0
		ctl.st.DeltaRTTMs = 0
	}
	ctl.st.ScaleEventsUp += scaleUpInc
	ctl.st.ScaleEventsDn += scaleDnInc
	if sig.Available {
		ctl.lastSignalRAT = sig.RAT
		ctl.st.SignalRAT = sig.RAT
		if sig.Mode == "wifi_sta" {
			ctl.st.SignalDbm = sig.WifiRSSIdBm
		} else {
			ctl.st.SignalDbm = sig.RSRPdBm
		}
		ctl.st.SignalQuality = sig.Quality
		ctl.st.RFCeilingFactor = sig.RFCeilingFactor
		ctl.st.DiagnosisCode = sig.Diagnosis
	}
	ctl.st.UpdatedAt = now.Unix()
	ctl.mu.Unlock()
}

func ratGeneration(rat string) string {
	u := strings.ToUpper(strings.TrimSpace(rat))
	switch {
	case strings.HasPrefix(u, "5G"):
		return "5G"
	case strings.HasPrefix(u, "4G") || strings.Contains(u, "LTE"):
		return "4G"
	case strings.Contains(u, "WI-FI") || strings.Contains(u, "WIFI"):
		return "WIFI"
	default:
		return u
	}
}
