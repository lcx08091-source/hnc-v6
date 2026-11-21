package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"hnc.io/dpid/shm"
)

func mustParseMAC6(t *testing.T, s string) [6]byte {
	t.Helper()
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		t.Fatalf("invalid test MAC %q: %v", s, err)
	}
	var out [6]byte
	copy(out[:], hw)
	return out
}

func mustParseIPv4Bytes(t *testing.T, s string) [4]byte {
	t.Helper()
	ip := net.ParseIP(s).To4()
	if ip == nil {
		t.Fatalf("invalid test IPv4 %q", s)
	}
	var out [4]byte
	copy(out[:], ip)
	return out
}

func writeTestShmFrame(t *testing.T, runDir string, slots []shm.DeviceSlot, activeFlows uint32, totalLeaks uint64) {
	t.Helper()
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("mkdir runDir: %v", err)
	}
	w, err := shm.OpenWriter(runDir)
	if err != nil {
		t.Fatalf("shm.OpenWriter(%q) failed: %v", runDir, err)
	}
	defer func() { _ = w.Close() }()

	if err := w.Write(shm.MonotonicNs(), activeFlows, totalLeaks, slots); err != nil {
		t.Fatalf("shm.Writer.Write failed: %v", err)
	}
}

func TestCoreHubDpiShmSeqlockReadAndStandbyFallback(t *testing.T) {
	srv, _ := setupTestV6Server(t)
	hub := srv.CoreHub()
	defer hub.Close()

	runDir := filepath.Join(srv.hncDir, "run")

	// 1. shm_vector.bin absent -> Healthy stays true, source=json_fallback
	_ = os.Remove(shm.FilePath(runDir))
	for i := 0; i < 5; i++ {
		snap := hub.RefreshSnapshotNow()
		if !snap.Healthy {
			t.Fatalf("refresh #%d: expected Healthy=true when shm_vector.bin absent, got false", i+1)
		}
		ext, ok := snap.Extensions["dpi_shm_vector"].(map[string]any)
		if !ok || ext["source"] != "json_fallback" {
			t.Fatalf("refresh #%d: unexpected dpi_shm_vector ext: %+v", i+1, snap.Extensions["dpi_shm_vector"])
		}
	}

	// 2. Valid 16KB shm_vector.bin written via shm.OpenWriter -> read via DpiShmBulkhead
	slotsV1 := []shm.DeviceSlot{
		{
			MAC:         mustParseMAC6(t, "AA:BB:CC:00:00:01"),
			IPv4:        mustParseIPv4Bytes(t, "192.168.43.20"),
			RxBytes:     128000,
			TxBytes:     64000,
			ActiveFlows: 7,
			Flags:       shm.FlagOnline | shm.FlagIPv4,
		},
		{
			MAC:         mustParseMAC6(t, "aa:bb:cc:00:00:02"),
			IPv4:        mustParseIPv4Bytes(t, "192.168.43.102"),
			RxBytes:     256000,
			TxBytes:     96000,
			ActiveFlows: 5,
			Flags:       shm.FlagOnline | shm.FlagIPv4,
		},
		{
			// 离线历史僵尸槽位(无 FlagOnline 且 ActiveFlows=0, 仅有历史累计字节与旧 IP)不得刷成在线
			MAC:         mustParseMAC6(t, "aa:bb:cc:00:00:99"),
			IPv4:        mustParseIPv4Bytes(t, "192.168.43.199"),
			RxBytes:     999999,
			TxBytes:     555555,
			ActiveFlows: 0,
			Flags:       shm.FlagIPv4,
		},
	}
	writeTestShmFrame(t, runDir, slotsV1, 12, 3)

	snap := hub.RefreshSnapshotNow()
	if !snap.Healthy {
		t.Fatalf("expected Healthy=true after valid shm write")
	}
	ext := snap.Extensions["dpi_shm_vector"].(map[string]any)
	if ext["source"] != "shm_seqlock" || ext["attached"] != true {
		t.Fatalf("expected source=shm_seqlock & attached=true, got %+v", ext)
	}
	if ext["device_count"] != uint32(3) || ext["active_flows"] != uint32(12) || ext["total_leaks"] != uint64(3) {
		t.Fatalf("unexpected shm telemetry summary: %+v", ext)
	}
	if snap.Live.Online != 2 {
		t.Fatalf("expected exactly 2 online devices (offline slot with RxBytes>0 must not resurrect), got %d", snap.Live.Online)
	}

	// 自定义未来假时间(偏离当前墙钟 >2s)自动回退 UpdatedUnixNs 判陈旧
	staleRes := hub.pollDpiShmVector(time.Now().Add(30 * time.Second))
	if !staleRes.Stale || staleRes.FallbackReason != "stale_snapshot" {
		t.Fatalf("expected fake future clock to trigger stale_snapshot fallback, got %+v", staleRes)
	}

	// 3. Re-create new inode -> automatic Reader reopen
	_ = os.Remove(shm.FilePath(runDir))
	writeTestShmFrame(t, runDir, slotsV1[:1], 21, 4)
	snapReopen := hub.RefreshSnapshotNow()
	extReopen := snapReopen.Extensions["dpi_shm_vector"].(map[string]any)
	if extReopen["source"] != "shm_seqlock" || extReopen["active_flows"] != uint32(21) {
		t.Fatalf("expected seamless reopen onto new inode with active_flows=21, got %+v", extReopen)
	}

	// 4. Corrupt short file -> safe fallback to json_fallback and LastError recorded on DpiShmBulkhead
	_ = os.WriteFile(shm.FilePath(runDir), []byte("corrupt-short-shm"), 0o644)
	corruptSnap := hub.RefreshSnapshotNow()
	cExt := corruptSnap.Extensions["dpi_shm_vector"].(map[string]any)
	if cExt["source"] != "json_fallback" {
		t.Fatalf("expected json_fallback on corrupt shm file, got %v", cExt["source"])
	}
	if corruptSnap.Bulkheads["dpi_shm"].LastError == "" {
		t.Fatalf("expected DpiShmBulkhead.LastError recorded on corrupt shm file")
	}

	hub.Close()
	if defaultGlobalHub.Load() == hub {
		t.Fatalf("expected CoreHub.Close() to clear defaultGlobalHub reference")
	}
	hub.shmMu.Lock()
	closedClean := hub.shmReader == nil && hub.shmInfo == nil
	hub.shmMu.Unlock()
	if !closedClean {
		t.Fatalf("expected CoreHub.Close() to release shmReader")
	}
}

func TestCoreHubNoStartZeroGoroutineLeak(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(dir, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestShmFrame(t, runDir, []shm.DeviceSlot{
		{
			MAC:         mustParseMAC6(t, "aa:bb:cc:11:22:33"),
			IPv4:        mustParseIPv4Bytes(t, "192.168.43.88"),
			RxBytes:     4096,
			TxBytes:     2048,
			ActiveFlows: 3,
			Flags:       shm.FlagOnline | shm.FlagIPv4,
		},
	}, 3, 0)

	func() {
		s := newServer(dir)
		hub := NewCoreHub(s)
		for i := 0; i < 4; i++ {
			snap := hub.RefreshSnapshotNow()
			if snap == nil || !snap.Healthy {
				t.Fatalf("refresh #%d failed: %+v", i+1, snap)
			}
		}
		if hub.DpiShmBulkhead.actorRunning.Load() != false {
			t.Fatalf("expected hub.DpiShmBulkhead.actorRunning == false when hub.Start() not called")
		}
		if hub.DataplaneBulkhead.actorRunning.Load() ||
			hub.AndroidBridgeBulkhead.actorRunning.Load() ||
			hub.StorageBulkhead.actorRunning.Load() {
			t.Fatalf("expected zero bulkhead actors started before hub.Start()")
		}
		bh := hub.DpiShmBulkhead.Health()
		if bh.Submitted == 0 || bh.Completed == 0 || !bh.Healthy {
			t.Fatalf("expected inline bulkhead counters updated accurately, got %+v", bh)
		}
		// 模拟调用方未调用 hub.Start() 亦未显式 Close() 即释放局部实例的场景(仅释放文件句柄与全局槽)
		hub.closeShmReader()
		defaultGlobalHub.CompareAndSwap(hub, nil)
		serverHubMap.Delete(s)
	}()

	runtime.GC()
	runtime.GC()
	leakSum := sampleGoroutineLeakProfile(true)
	if leakSum == nil {
		t.Fatal("expected non-nil GoroutineLeakSummary from sampleGoroutineLeakProfile(true)")
	}
	if leakSum.LeakedCount != 0 || (leakSum.Supported && leakSum.Status != "clean") {
		t.Fatalf("detected goroutine leak on unstarted CoreHub: %+v", leakSum)
	}
}

func TestBeta1Atomic64StructAlignmentAssertions(t *testing.T) {
	fields := []struct {
		name   string
		offset uintptr
	}{
		{"flowScalpelEngine.seqGen", unsafe.Offsetof(flowScalpelEngine{}.seqGen)},
		{"flowScalpelEngine.cutTotal", unsafe.Offsetof(flowScalpelEngine{}.cutTotal)},
		{"JitterBlackbox.totalTicks", unsafe.Offsetof(JitterBlackbox{}.totalTicks)},
		{"JitterBlackbox.totalIncidents", unsafe.Offsetof(JitterBlackbox{}.totalIncidents)},
		{"JitterBlackbox.lastTickUnixMs", unsafe.Offsetof(JitterBlackbox{}.lastTickUnixMs)},
		{"JitterBlackbox.lastSpikeUnixMs", unsafe.Offsetof(JitterBlackbox{}.lastSpikeUnixMs)},
		{"JitterBlackbox.latestJitterBits", unsafe.Offsetof(JitterBlackbox{}.latestJitterBits)},
		{"Bulkhead.actorBeatMonoNs", unsafe.Offsetof(Bulkhead{}.actorBeatMonoNs)},
		{"Bulkhead.circuitOpenUntil", unsafe.Offsetof(Bulkhead{}.circuitOpenUntil)},
		{"Bulkhead.totalSubmitted", unsafe.Offsetof(Bulkhead{}.totalSubmitted)},
		{"Bulkhead.totalCompleted", unsafe.Offsetof(Bulkhead{}.totalCompleted)},
		{"Bulkhead.totalErrors", unsafe.Offsetof(Bulkhead{}.totalErrors)},
		{"Bulkhead.totalTimeouts", unsafe.Offsetof(Bulkhead{}.totalTimeouts)},
		{"Bulkhead.totalPanics", unsafe.Offsetof(Bulkhead{}.totalPanics)},
		{"Bulkhead.totalRejected", unsafe.Offsetof(Bulkhead{}.totalRejected)},
		{"Bulkhead.totalCircuitTrips", unsafe.Offsetof(Bulkhead{}.totalCircuitTrips)},
		{"Bulkhead.lastExecNs", unsafe.Offsetof(Bulkhead{}.lastExecNs)},
		{"CoreHub.seq", unsafe.Offsetof(CoreHub{}.seq)},
		{"CoreHub.lastRefreshMono", unsafe.Offsetof(CoreHub{}.lastRefreshMono)},
		{"CoreHub.vectorSyncHits", unsafe.Offsetof(CoreHub{}.vectorSyncHits)},
		{"CoreHub.shmSeqlockHits", unsafe.Offsetof(CoreHub{}.shmSeqlockHits)},
		{"CoreHub.shmFallbackCount", unsafe.Offsetof(CoreHub{}.shmFallbackCount)},
	}
	for _, f := range fields {
		if f.offset%8 != 0 {
			t.Fatalf("64-bit atomic field %s offset=%d violates 8-byte alignment for 32-bit ARM", f.name, f.offset)
		}
	}
}

func TestNlTuneGlobalShaperIfbErrorInterceptAndRebuild(t *testing.T) {
	origSend := nlShaperSendAndWaitAckFn
	origEnsure := nlShaperEnsureHTBRootFn
	defer func() {
		nlShaperSendAndWaitAckFn = origSend
		nlShaperEnsureHTBRootFn = origEnsure
	}()

	const (
		fakeFD  = 99
		downIdx = 11
		ifbIdx  = 22
		downBps = 100_000_000 / 8
		upBps   = 40_000_000 / 8
	)

	ensureCalls := 0
	beforeErrs := dpStats.nlErrors.Load()

	nlShaperSendAndWaitAckFn = func(fd int, msg []byte, seq uint32) error {
		ifindex := int(int32(binary.LittleEndian.Uint32(msg[20:24])))
		if ifindex == ifbIdx {
			return syscall.ENOENT
		}
		return nil
	}
	nlShaperEnsureHTBRootFn = func(fd int, ifindex int, defMinor uint16, rateBps uint64) error {
		ensureCalls++
		return nil
	}

	sent, err := nlTuneGlobalShaperOnSocket(fakeFD, downIdx, downBps, ifbIdx, upBps)
	if err != nil || sent != 2 || ensureCalls != 1 {
		t.Fatalf("expected sent=2 ensureCalls=1 err=nil, got sent=%d ensureCalls=%d err=%v", sent, ensureCalls, err)
	}

	nlShaperEnsureHTBRootFn = func(_ int, _ int, _ uint16, _ uint64) error {
		return syscall.EPERM
	}
	sentFail, errFail := nlTuneGlobalShaperOnSocket(fakeFD, downIdx, downBps, ifbIdx, upBps)
	if !errors.Is(errFail, syscall.ENOENT) || sentFail != 1 {
		t.Fatalf("expected original ENOENT wrapped via %%w and sent=1, got sent=%d err=%v", sentFail, errFail)
	}
	if dpStats.nlErrors.Load() != beforeErrs+1 {
		t.Fatalf("expected dpStats.nlErrors incremented")
	}
}

func TestDataplaneReconcileInvalidationAndIfindexDrift(t *testing.T) {
	actor := NewDataplaneActor()
	defer actor.Close()

	hncDir := t.TempDir()
	const iface = "wlan0"
	applyCount := 0

	runSim := func(downIdx, ifbIdx, downKbps, upKbps int, failKernel bool) error {
		return actor.Do("tune_sim", func(a *DataplaneActor) error {
			a.trackIfindexLocked(hncDir, iface, downIdx)
			a.trackIfindexLocked(hncDir, "ifb0", ifbIdx)
			digestKey := "shaper:" + hncDir + ":" + iface
			digestVal := fmt.Sprintf("%d:%d:%d:%d", downIdx, ifbIdx, downKbps, upKbps)
			if prev, ok := a.reconcileMap[digestKey]; ok && prev == digestVal {
				a.dedupHits.Add(1)
				return nil
			}
			applyCount++
			if failKernel {
				return syscall.ENODEV
			}
			a.reconcileMap[digestKey] = digestVal
			a.reconcileMap["vector:"+hncDir+":"+iface] = "v1"
			a.reconcileMap["express:"+hncDir+":"+iface] = "e1"
			a.reconcileMap["leash:"+hncDir+":"+iface] = "l1"
			a.reconcileMap["shaper:"+hncDir+":rndis0"] = "other"
			return nil
		})
	}

	if err := runSim(41, 12, 100000, 50000, true); !errors.Is(err, syscall.ENODEV) {
		t.Fatalf("expected ENODEV, got %v", err)
	}
	if err := runSim(41, 12, 100000, 50000, false); err != nil || applyCount != 2 {
		t.Fatalf("expected retry to run (applyCount=2), got %d err=%v", applyCount, err)
	}
	if err := runSim(41, 12, 100000, 50000, false); err != nil || applyCount != 2 {
		t.Fatalf("expected dedup hit (applyCount=2), got %d", applyCount)
	}

	if reconcileKeyMatches("shaper:/tmp/hnc10:wlan00", "/tmp/hnc1", "") ||
		reconcileKeyMatches("shaper:/tmp/hnc10:wlan00", "/tmp/hnc10", "wlan0") {
		t.Fatal("reconcileKeyMatches must not false-match prefix substrings")
	}

	actor.InvalidateReconcile(iface)
	if err := runSim(41, 12, 100000, 50000, false); err != nil || applyCount != 3 {
		t.Fatalf("expected InvalidateReconcile to force re-apply (applyCount=3), got %d", applyCount)
	}

	actor.InvalidateReconcile("ifb0")
	_ = actor.Do("verify_ifb_clear", func(a *DataplaneActor) error {
		if _, ok := a.reconcileMap["express:"+hncDir+":"+iface]; ok {
			t.Fatal("expected InvalidateReconcile(ifb0) to clear express digest")
		}
		if _, ok := a.reconcileMap["leash:"+hncDir+":"+iface]; ok {
			t.Fatal("expected InvalidateReconcile(ifb0) to clear leash digest")
		}
		return nil
	})
	if err := runSim(41, 12, 100000, 50000, false); err != nil || applyCount != 4 {
		t.Fatalf("expected InvalidateReconcile(ifb0) to clear shaper digest (applyCount=4), got %d", applyCount)
	}

	_ = runSim(42, 12, 100000, 50000, true)
	_ = actor.Do("check_ifidx", func(a *DataplaneActor) error {
		if _, exists := a.reconcileMap["vector:"+hncDir+":"+iface]; exists {
			t.Fatalf("expected vector digest cleared on ifindex drift 41->42")
		}
		return nil
	})
}
