package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withAutorateTestHooks(t *testing.T) {
	t.Helper()
	origInspect := autorateInspectIfaceFn
	origProbe := autorateProbeRTTFn
	origReadDev := autorateReadNetDevFn
	origNow := autorateNowFn
	t.Cleanup(func() {
		autorateInspectIfaceFn = origInspect
		autorateProbeRTTFn = origProbe
		autorateReadNetDevFn = origReadDev
		autorateNowFn = origNow
	})
}

func formatSyntheticProcNetDev(hsIface string, hsRx, hsTx uint64, cellIface string, cellRx, cellTx uint64) []byte {
	var b strings.Builder
	b.WriteString("Inter-|   Receive                                                |  Transmit\n")
	b.WriteString(" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n")
	fmt.Fprintf(&b, "  %s: %d 100 0 0 0 0 0 0 %d 100 0 0 0 0 0 0\n", hsIface, hsRx, hsTx)
	if cellIface != "" {
		fmt.Fprintf(&b, "  %s: %d 100 0 0 0 0 0 0 %d 100 0 0 0 0 0 0\n", cellIface, cellRx, cellTx)
	}
	return []byte(b.String())
}

func TestResolveProbeBindIface464XLATAndUpstreamPreservation(t *testing.T) {
	withAutorateTestHooks(t)

	ifaceMap := map[string]autorateIfaceState{
		"rmnet_data0":    {Exists: true, FlagUp: true, HasIPv4: false},
		"v4-rmnet_data0": {Exists: true, FlagUp: true, HasIPv4: true},
		"ccmni0":         {Exists: true, FlagUp: true, HasIPv4: false},
		"v4-ccmni0":      {Exists: true, FlagUp: true, HasIPv4: true},
		"rmnet1":         {Exists: true, FlagUp: true, HasIPv4: false},
		"v4-rmnet1":      {Exists: true, FlagUp: false, HasIPv4: true},
		"sipa_eth0":      {Exists: true, FlagUp: true, HasIPv4: true},
		"v4-sipa_eth0":   {Exists: true, FlagUp: true, HasIPv4: true},
		"wlan0":          {Exists: true, FlagUp: true, HasIPv4: false},
		"v4-wlan0":       {Exists: true, FlagUp: true, HasIPv4: true},
	}
	autorateInspectIfaceFn = func(name string) autorateIfaceState {
		return ifaceMap[name]
	}

	if got := resolveProbeBindIface("rmnet_data0"); got != "v4-rmnet_data0" {
		t.Fatalf("expected 5G SA pure-IPv6 rmnet_data0 to bind v4-rmnet_data0, got %q", got)
	}
	if got := resolveProbeBindIface("ccmni0"); got != "v4-ccmni0" {
		t.Fatalf("expected MTK ccmni0 to bind v4-ccmni0, got %q", got)
	}
	if got := resolveProbeBindIface("rmnet1"); got != "rmnet1" {
		t.Fatalf("expected down clat v4-rmnet1 to fall back to rmnet1, got %q", got)
	}
	if got := resolveProbeBindIface("sipa_eth0"); got != "sipa_eth0" {
		t.Fatalf("expected dual-stack sipa_eth0 with native IPv4 to stay on sipa_eth0, got %q", got)
	}
	if got := resolveProbeBindIface("wlan0"); got != "wlan0" {
		t.Fatalf("expected non-cellular wlan0 to stay on wlan0, got %q", got)
	}

	// 验证 autorateStep 将 "v4-rmnet_data0" 传给 probeReflectorRTT, 同时保持快照 UpstreamIface == "rmnet_data0"
	dir := t.TempDir()
	for _, sub := range []string{"bin", "run", "data"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "iface_detect.json"),
		[]byte(`{"iface":"wlan2","tether_upstream":"rmnet_data0","upstream":"rmnet_data0"}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "bin", "tc_manager.sh"), []byte("#!/system/bin/sh\nexit 0\n"), 0o755)

	ctl := newAutorateCtl(dir)
	cfg := defaultAutorateConfig()
	cfg.Enabled = true
	cfg.DownMinMbps = 20
	cfg.DownMaxMbps = 200
	cfg.UpMinMbps = 10
	cfg.UpMaxMbps = 80
	ctl.mu.Lock()
	ctl.cfg = cfg
	ctl.syncStatusConfigLocked(cfg)
	ctl.st.CurDownMbps = 100
	ctl.st.CurUpMbps = 40
	ctl.appliedIface = "wlan2"
	ctl.appliedDown = 100
	ctl.appliedUp = 40
	ctl.mu.Unlock()

	srv := &server{
		hncDir:   dir,
		autorate: ctl,
	}

	curT := time.Unix(1770000000, 0)
	var hsTx uint64
	var boundIface string
	autorateNowFn = func() time.Time { return curT }
	autorateReadNetDevFn = func() ([]byte, error) {
		return formatSyntheticProcNetDev("wlan2", 1000, hsTx, "rmnet_data0", 5000, 5000), nil
	}
	autorateProbeRTTFn = func(bindIfc string, _ []string, _ *int) (float64, bool) {
		boundIface = bindIfc
		return 24.0, true
	}

	// 第 1 拍建立采样基线
	srv.autorateStep(cfg)
	// 第 2 拍 (+2s, 下行 40Mbps -> loadDown=0.40 >= autorateIdleTraffic)
	curT = curT.Add(2 * time.Second)
	hsTx += 10_000_000
	srv.autorateStep(cfg)

	if boundIface != "v4-rmnet_data0" {
		t.Fatalf("probeReflectorRTT bound to %q, want v4-rmnet_data0", boundIface)
	}
	snap := ctl.Snapshot()
	if snap.UpstreamIface != "rmnet_data0" {
		t.Fatalf("status UpstreamIface = %q, want physical iface rmnet_data0", snap.UpstreamIface)
	}
}

func TestResolvePhysicalUpstreamDualSIMStaleCacheBypass(t *testing.T) {
	withAutorateTestHooks(t)

	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	// iface_detect.json 仍缓存旧卡 rmnet_data0 (60s 尚未刷新)
	_ = os.WriteFile(filepath.Join(dir, "run", "iface_detect.json"),
		[]byte(`{"iface":"wlan2","tether_upstream":"rmnet_data0","upstream":"rmnet_data0"}`), 0o644)

	autorateInspectIfaceFn = func(name string) autorateIfaceState {
		switch name {
		case "rmnet_data0", "v4-rmnet_data0":
			// 旧卡已断网 DOWN
			return autorateIfaceState{Exists: true, FlagUp: false, HasIPv4: false}
		case "rmnet_data1":
			// 新卡纯 IPv6 SA 自身未置 FlagUp 或仅 v4- 口 FlagUp 均可识别
			return autorateIfaceState{Exists: true, FlagUp: false, HasIPv4: false}
		case "v4-rmnet_data1":
			return autorateIfaceState{Exists: true, FlagUp: true, HasIPv4: true}
		default:
			return autorateIfaceState{}
		}
	}

	srv := &server{hncDir: dir}
	// 即使旧卡 rmnet_data0 历史累计流量远大于刚切换的新卡 rmnet_data1, 也绝不能选已 DOWN 的旧卡
	devMap := map[string][2]uint64{
		"rmnet_data0": {900_000_000, 900_000_000},
		"rmnet_data1": {2_000_000, 1_000_000},
	}
	if got := srv.resolvePhysicalUpstream(devMap); got != "rmnet_data1" {
		t.Fatalf("resolvePhysicalUpstream = %q, want active SIM2 iface rmnet_data1", got)
	}
}

func TestAutorateBaseRTTAntiPoisoningOnSwitch(t *testing.T) {
	withAutorateTestHooks(t)

	dir := t.TempDir()
	for _, sub := range []string{"bin", "run", "data"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "bin", "tc_manager.sh"), []byte("#!/system/bin/sh\nexit 0\n"), 0o755)

	activeUpstream := "rmnet_data0"
	autorateInspectIfaceFn = func(name string) autorateIfaceState {
		if name == activeUpstream {
			return autorateIfaceState{Exists: true, FlagUp: true, HasIPv4: true}
		}
		return autorateIfaceState{Exists: true, FlagUp: false}
	}

	sigMon := &signalMonitor{
		last: hostSignalStatus{
			Available:       true,
			Mode:            "cellular",
			RAT:             "5G SA",
			RFCeilingFactor: 1.0,
		},
		lastAt: time.Now(),
	}
	setRAT := func(rat string) {
		sigMon.mu.Lock()
		sigMon.last.RAT = rat
		sigMon.lastAt = time.Now()
		sigMon.mu.Unlock()
	}

	ctl := newAutorateCtl(dir)
	cfg := defaultAutorateConfig()
	cfg.Enabled = true
	cfg.DownMinMbps = 20
	cfg.DownMaxMbps = 200
	cfg.UpMinMbps = 10
	cfg.UpMaxMbps = 80
	cfg.RTTDeltaMs = 25
	ctl.mu.Lock()
	ctl.cfg = cfg
	ctl.syncStatusConfigLocked(cfg)
	ctl.st.CurDownMbps = 100
	ctl.st.CurUpMbps = 40
	ctl.appliedIface = "wlan2"
	ctl.appliedDown = 100
	ctl.appliedUp = 40
	ctl.mu.Unlock()

	srv := &server{
		hncDir:    dir,
		autorate:  ctl,
		signalCtl: sigMon,
	}

	curT := time.Unix(1770001000, 0)
	var hsTx uint64
	nextRTT := 20.0
	autorateNowFn = func() time.Time { return curT }
	autorateReadNetDevFn = func() ([]byte, error) {
		_ = os.WriteFile(filepath.Join(dir, "run", "iface_detect.json"),
			[]byte(fmt.Sprintf(`{"iface":"wlan2","tether_upstream":%q,"upstream":%q}`, activeUpstream, activeUpstream)), 0o644)
		return formatSyntheticProcNetDev("wlan2", 1000, hsTx, activeUpstream, 10000, 10000), nil
	}
	autorateProbeRTTFn = func(_ string, _ []string, _ *int) (float64, bool) {
		return nextRTT, true
	}

	stepWithMbps := func(downMbps, rttMs float64) autorateStatus {
		curT = curT.Add(2 * time.Second)
		hsTx += uint64((downMbps * 1e6 * 2.0) / 8.0)
		nextRTT = rttMs
		srv.autorateStep(cfg)
		return ctl.Snapshot()
	}

	// 初始化采样窗口
	srv.autorateStep(cfg)

	// 1. 5G SA 正常建基线: load=0.40, rtt=20ms -> baseRTT=20ms
	st1 := stepWithMbps(40, 20.0)
	if st1.BaseRTTMs != 20.0 {
		t.Fatalf("initial 5G baseRTT = %.2f, want 20.0", st1.BaseRTTMs)
	}

	// 2. 满载拥塞瞬间从 5G SA 掉到 4G LTE, 实测拥塞 RTT=240ms (load=85Mbps/100Mbps=0.85):
	//    严禁将 240ms 写入 baseRTT! 必须保持 baseRTT=20.0 并立即触发 backoff!
	setRAT("4G LTE")
	st2 := stepWithMbps(85, 240.0)
	if st2.BaseRTTMs != 20.0 {
		t.Fatalf("congested RAT switch poisoned baseRTT = %.2f, want 20.0 preserved", st2.BaseRTTMs)
	}
	if st2.State != "backoff" || st2.CurDownMbps >= 100.0 {
		t.Fatalf("expected immediate backoff on congested 240ms RTT, got state=%s curDown=%.2f", st2.State, st2.CurDownMbps)
	}

	// 3. 切物理口 rmnet_data0 -> rmnet_data1, 轻载 (load < 0.25) 且新链路正常空载 RTT=36ms (<= 20+25=45ms):
	//    允许安全重锚 baseRTT=36.0, deltaRTT=0, 不误触发退避!
	activeUpstream = "rmnet_data1"
	curDown := st2.CurDownMbps
	st3 := stepWithMbps(curDown*0.20, 36.0)
	if st3.BaseRTTMs != 36.0 || st3.DeltaRTTMs != 0 || st3.State == "backoff" {
		t.Fatalf("expected clean light-load reanchor to 36.0ms, got base=%.2f delta=%.2f state=%s",
			st3.BaseRTTMs, st3.DeltaRTTMs, st3.State)
	}

	// 4. 再次切口 rmnet_data1 -> rmnet_data2, 虽轻载 (load=0.20) 但遇尖峰拥塞 RTT=220ms (> 36+25):
	//    拒绝毒化基线, baseRTT 保持 36.0!
	activeUpstream = "rmnet_data2"
	st4 := stepWithMbps(st3.CurDownMbps*0.20, 220.0)
	if st4.BaseRTTMs != 36.0 || st4.State != "backoff" {
		t.Fatalf("light-load spike 220ms must not poison baseRTT: got base=%.2f state=%s", st4.BaseRTTMs, st4.State)
	}

	// 5. 从 4G LTE 切回 5G SA, 实测 RTT=16ms (< baseRTT 36ms): 即使高负载也立即向下重锚至 16.0ms!
	setRAT("5G SA")
	st5 := stepWithMbps(st4.CurDownMbps*0.80, 16.0)
	if st5.BaseRTTMs != 16.0 || st5.DeltaRTTMs != 0 {
		t.Fatalf("expected downward reanchor to 16.0ms on 4G->5G recovery, got base=%.2f delta=%.2f",
			st5.BaseRTTMs, st5.DeltaRTTMs)
	}
}

func TestDataplaneVerifyResyncUsesRestoreAndReplaysExpress18010(t *testing.T) {
	dir := setupNativeTierTestEnv(t, "wlan2")
	execLog := filepath.Join(dir, "run", "cmd.log")

	writeScript := func(name string) {
		p := filepath.Join(dir, "bin", name)
		body := fmt.Sprintf("#!/system/bin/sh\necho \"%s $*\" >> '%s'\nexit 0\n", name, execLog)
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeScript("hnc_offload_guard.sh")
	writeScript("tc_manager.sh")
	_ = os.WriteFile(filepath.Join(dir, "run", "vector_express_state.json"),
		[]byte(`{"active":true,"prio":0,"qdisc":"fq_codel","bg_pool_ceil_pct":85}`), 0o644)

	var replayed18010 bool
	withMockDPTierHooks(t, func(h *dpTierHooks) {
		h.openSocket = func() (int, error) { return 77, nil }
		h.closeSocket = func(_ int) {}
		h.ifaceIndex = func(name string) (int, error) {
			if name == "wlan2" {
				return 9, nil
			}
			return 0, errors.New("none")
		}
		h.applyBatchOnSock = func(_ int, msgs [][]byte) (int, error) {
			for _, m := range msgs {
				if binary.LittleEndian.Uint16(m[4:6]) == rtnlNewTClass &&
					binary.LittleEndian.Uint32(m[24:28]) == 0x00018010 {
					replayed18010 = true
				}
			}
			return len(msgs), nil
		}
	})
	t.Cleanup(func() {
		_ = ApplyVectorExpressNative(dir, false, 0, 0)
	})

	srv := &server{hncDir: dir}
	resp, handled := dispatchDataplaneVerifyAction(srv, "dataplane_verify_run", map[string]string{"resync": "1"})
	if !handled || !resp.OK {
		t.Fatalf("dispatchDataplaneVerifyAction(resync=1) failed: handled=%v resp=%+v", handled, resp)
	}
	logBytes, _ := os.ReadFile(execLog)
	logTxt := string(logBytes)
	if strings.Contains(logTxt, "sync_all") || !strings.Contains(logTxt, "tc_manager.sh restore") {
		t.Fatalf("expected tc_manager.sh restore (never sync_all), got log:\n%s", logTxt)
	}
	if !replayed18010 {
		t.Fatalf("expected active Vector Express 1:8010 to be replayed during resync")
	}
}
