package main

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func setupNativeTierTestEnv(t *testing.T, iface string) string {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"bin", "data", "run", "logs"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	constContent := "HNC_DEV_MARK_BASE=0x00800000\nHNC_DEV_MARK_MASK=0x00ff0000\nHNC_DEV_MARK_SHIFT=16\n"
	if err := os.WriteFile(filepath.Join(dir, "bin", "hnc_constants.sh"), []byte(constContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if iface != "" {
		if err := os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:"+iface+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func withMockDPTierHooks(t *testing.T, custom func(h *dpTierHooks)) {
	t.Helper()
	dpTierHooksMu.Lock()
	orig := activeDPHooks
	mock := defaultDPTierHooks()
	mock.acquireLock = func(_, _ string) (func(), error) { return func() {}, nil }
	if custom != nil {
		custom(&mock)
	}
	activeDPHooks = mock
	dpTierHooksMu.Unlock()

	t.Cleanup(func() {
		dpTierHooksMu.Lock()
		activeDPHooks = orig
		dpTierHooksMu.Unlock()
	})
}

func TestProbeDataplaneTierSelectionMatrix(t *testing.T) {
	dir := setupNativeTierTestEnv(t, "wlan2")
	actor := NewDataplaneActor()
	defer actor.Close()

	// 1. Tier 1: offload 受控 + clsact BPF 就绪 + sch_fq 可用 + RTNetlink 可用
	withMockDPTierHooks(t, func(h *dpTierHooks) {
		h.ifaceIndex = func(name string) (int, error) {
			if name == "wlan2" {
				return 11, nil
			}
			return 0, errors.New("no iface")
		}
		h.probeKernel = func(ifidx int) (bool, bool, bool) {
			if ifidx != 11 {
				t.Fatalf("unexpected ifidx %d", ifidx)
			}
			return true, true, true
		}
		h.offloadControlled = func(_, _ string) bool { return true }
	})
	if got := probeDataplaneTierOnActor(actor, dir, "wlan2"); got != DataplaneTierEDT {
		t.Fatalf("expected %s, got %s", DataplaneTierEDT, got)
	}
	st1 := actor.Status()
	if st1.ActiveTier != DataplaneTierEDT || !st1.OffloadControlled || !st1.ClsactBPFReady || !st1.SchFQAvailable {
		t.Fatalf("unexpected tier1 status: %+v", st1)
	}

	// 2. Tier 2: 缺少 sch_fq 但 AF_NETLINK 可用 -> 自动选定 tier2_native_netlink
	withMockDPTierHooks(t, func(h *dpTierHooks) {
		h.ifaceIndex = func(_ string) (int, error) { return 11, nil }
		h.probeKernel = func(_ int) (bool, bool, bool) { return true, true, false }
		h.offloadControlled = func(_, _ string) bool { return true }
		h.schFQSysReady = func(_ string) bool { return false }
	})
	if got := probeDataplaneTierOnActor(actor, dir, "wlan2"); got != DataplaneTierNativeNetlink {
		t.Fatalf("expected %s, got %s", DataplaneTierNativeNetlink, got)
	}

	// 3. Tier 3: AF_NETLINK 被沙盒禁用 -> 自动降级至 tier3_atomic_batch
	withMockDPTierHooks(t, func(h *dpTierHooks) {
		h.ifaceIndex = func(_ string) (int, error) { return 11, nil }
		h.probeKernel = func(_ int) (bool, bool, bool) { return false, false, false }
		h.offloadControlled = func(_, _ string) bool { return false }
	})
	if got := probeDataplaneTierOnActor(actor, dir, "wlan2"); got != DataplaneTierAtomicBatch {
		t.Fatalf("expected %s, got %s", DataplaneTierAtomicBatch, got)
	}
}

func TestDataplaneActorSingleWriterAndLockFreeReads(t *testing.T) {
	dir := setupNativeTierTestEnv(t, "wlan2")
	actor := NewDataplaneActor()
	defer actor.Close()

	var inFlight atomic.Int32
	var maxConcurrent atomic.Int32
	var socketOpens atomic.Int32
	var tuneCalls atomic.Int32

	withMockDPTierHooks(t, func(h *dpTierHooks) {
		h.openSocket = func() (int, error) {
			socketOpens.Add(1)
			return 42, nil
		}
		h.closeSocket = func(_ int) {}
		h.ifaceIndex = func(name string) (int, error) {
			switch name {
			case "wlan2":
				return 7, nil
			case "ifb0":
				return 8, nil
			default:
				return 0, errors.New("unknown")
			}
		}
		h.tuneShaperOnSock = func(fd int, downIdx int, downBps uint64, ifbIdx int, upBps uint64) (int, error) {
			cur := inFlight.Add(1)
			for {
				prev := maxConcurrent.Load()
				if cur <= prev || maxConcurrent.CompareAndSwap(prev, cur) {
					break
				}
			}
			time.Sleep(300 * time.Microsecond)
			inFlight.Add(-1)
			if fd != 42 || downIdx != 7 || ifbIdx != 8 || downBps == 0 || upBps == 0 {
				t.Errorf("unexpected tune args fd=%d downIdx=%d ifbIdx=%d", fd, downIdx, ifbIdx)
			}
			tuneCalls.Add(1)
			return 2, nil
		}
	})

	var wg sync.WaitGroup
	stopReaders := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stopReaders:
				return
			default:
				st := actor.Status()
				if st.ActiveTier == "" {
					t.Errorf("empty ActiveTier during concurrent read")
				}
			}
		}
	}()

	for i := 1; i <= 24; i++ {
		wg.Add(1)
		kbps := 50000 + i*1000
		go func(k int) {
			defer wg.Done()
			if err := tuneGlobalShaperOnActor(actor, dir, k, k/2); err != nil {
				t.Errorf("tuneGlobalShaperOnActor(%d) failed: %v", k, err)
			}
		}(kbps)
	}
	wg.Wait()
	close(stopReaders)
	<-readerDone

	if maxConcurrent.Load() != 1 {
		t.Fatalf("DataplaneActor violated single-writer guarantee: maxConcurrent=%d", maxConcurrent.Load())
	}
	if socketOpens.Load() != 1 {
		t.Fatalf("expected persistent AF_NETLINK socket opened once, got %d", socketOpens.Load())
	}
	if tuneCalls.Load() != 24 {
		t.Fatalf("expected 24 distinct shaper updates, got %d", tuneCalls.Load())
	}

	// 验证重复同速率调速走 O(1) 增量对账去重(100% 经由 Actor 串行通道, -race 零竞争)
	if err := tuneGlobalShaperOnActor(actor, dir, 120000, 60000); err != nil {
		t.Fatalf("first 120Mbps tune failed: %v", err)
	}
	afterFirst := tuneCalls.Load()
	if err := tuneGlobalShaperOnActor(actor, dir, 120000, 60000); err != nil {
		t.Fatalf("second identical 120Mbps tune failed: %v", err)
	}
	if tuneCalls.Load() != afterFirst {
		t.Fatalf("expected O(1) dedup to skip duplicate kernel syscall")
	}
	st := actor.Status()
	if st.DedupHits == 0 || st.SavedForks < 26 || st.LastNetlinkUsec <= 0 {
		t.Fatalf("unexpected actor counters: %+v", st)
	}
}

func TestVectorExpressAndUpdateLeashNativeBatches(t *testing.T) {
	dir := setupNativeTierTestEnv(t, "wlan2")
	actor := NewDataplaneActor()
	defer actor.Close()

	var captured [][]byte
	withMockDPTierHooks(t, func(h *dpTierHooks) {
		h.openSocket = func() (int, error) { return 55, nil }
		h.closeSocket = func(_ int) {}
		h.ifaceIndex = func(name string) (int, error) {
			if name == "wlan2" {
				return 9, nil
			}
			if name == "ifb0" {
				return 10, nil
			}
			return 0, errors.New("missing")
		}
		h.applyBatchOnSock = func(_ int, msgs [][]byte) (int, error) {
			captured = append([][]byte(nil), msgs...)
			return len(msgs), nil
		}
	})

	// 1. 激活 Vector Express (1:10 prio 0 + fq_codel target=2000us interval=40000us quantum=300 + 背景上限 85Mbps)
	if err := applyVectorExpressOnActor(actor, dir, true, 0x01000000, 85000); err != nil {
		t.Fatalf("applyVectorExpressOnActor enable failed: %v", err)
	}
	if len(captured) == 0 {
		t.Fatal("expected Vector Express netlink messages")
	}

	found110 := false
	foundShallowFQ := false
	foundBg9999 := false
	for _, m := range captured {
		msgType := binary.LittleEndian.Uint16(m[4:6])
		handle := binary.LittleEndian.Uint32(m[24:28])
		parent := binary.LittleEndian.Uint32(m[28:32])
		if msgType == rtnlNewTClass && handle == (rtnlHtbRootMaj|uint32(v6ExpressClassMinor)) {
			found110 = true
			var dumpBuf []byte
			dumpBuf = append(dumpBuf, m...)
			doneHdr := make([]byte, rtnlMsgHdrLen)
			binary.LittleEndian.PutUint32(doneHdr[0:4], rtnlMsgHdrLen)
			binary.LittleEndian.PutUint16(doneHdr[4:6], rtnlMsgDone)
			dumpBuf = append(dumpBuf, doneHdr...)
			parsed, pErr := parseTCClassDumpMsgs(dumpBuf, 0)
			if pErr != nil {
				t.Fatalf("parse 1:10 class msg failed: %v", pErr)
			}
			cls, ok := parsed["1:10"]
			if !ok || cls.Prio != 0 {
				t.Fatalf("expected 1:10 prio 0, got %+v", cls)
			}
		}
		if msgType == rtnlNewQdisc && parent == (rtnlHtbRootMaj|uint32(v6ExpressClassMinor)) {
			var t2ms, i40ms, q300 [4]byte
			binary.LittleEndian.PutUint32(t2ms[:], 2000)
			binary.LittleEndian.PutUint32(i40ms[:], 40000)
			binary.LittleEndian.PutUint32(q300[:], 300)
			if strings.Contains(string(m), string(t2ms[:])) &&
				strings.Contains(string(m), string(i40ms[:])) &&
				strings.Contains(string(m), string(q300[:])) {
				foundShallowFQ = true
			}
		}
		if msgType == rtnlNewTClass && handle == (rtnlHtbRootMaj|uint32(rtnlDefMinor)) {
			foundBg9999 = true
		}
	}
	if !found110 || !foundShallowFQ || !foundBg9999 {
		t.Fatalf("missing expected Vector Express objects: 1:10=%v shallowFQ=%v bg9999=%v", found110, foundShallowFQ, foundBg9999)
	}
	if !actor.Status().ExpressActive {
		t.Fatal("expected ExpressActive=true in status")
	}

	// 2. 停用 Vector Express -> 幂等拆除 1:10 并恢复 1:9999
	captured = nil
	if err := applyVectorExpressOnActor(actor, dir, false, 0x01000000, 0); err != nil {
		t.Fatalf("applyVectorExpressOnActor disable failed: %v", err)
	}
	foundDel110 := false
	for _, m := range captured {
		if binary.LittleEndian.Uint16(m[4:6]) == rtnlDelTClass &&
			binary.LittleEndian.Uint32(m[24:28]) == (rtnlHtbRootMaj|uint32(v6ExpressClassMinor)) {
			foundDel110 = true
		}
	}
	if !foundDel110 || actor.Status().ExpressActive {
		t.Fatalf("expected 1:10 deleted and ExpressActive=false, foundDel110=%v", foundDel110)
	}

	// 3. 应用 UpdateLeash (rateKbps=0 -> 默认 1500 Kbps 维护 1:9990)
	captured = nil
	if err := applyUpdateLeashOnActor(actor, dir, 0, 0); err != nil {
		t.Fatalf("applyUpdateLeashOnActor default 1500kbps failed: %v", err)
	}
	found9990 := false
	for _, m := range captured {
		if binary.LittleEndian.Uint16(m[4:6]) == rtnlNewTClass &&
			binary.LittleEndian.Uint32(m[24:28]) == (rtnlHtbRootMaj|uint32(v6LeashClassMinor)) {
			var dumpBuf []byte
			dumpBuf = append(dumpBuf, m...)
			doneHdr := make([]byte, rtnlMsgHdrLen)
			binary.LittleEndian.PutUint32(doneHdr[0:4], rtnlMsgHdrLen)
			binary.LittleEndian.PutUint16(doneHdr[4:6], rtnlMsgDone)
			dumpBuf = append(dumpBuf, doneHdr...)
			parsed, pErr := parseTCClassDumpMsgs(dumpBuf, 0)
			if pErr != nil {
				t.Fatalf("parse 1:9990 failed: %v", pErr)
			}
			cls, ok := parsed["1:9990"]
			if !ok || cls.RateKbit != 1500 || cls.CeilKbit != 1500 {
				t.Fatalf("expected 1:9990 at 1500 kbit/s, got %+v", cls)
			}
			found9990 = true
		}
	}
	if !found9990 || actor.Status().UpdateLeashKbps != 1500 {
		t.Fatalf("expected 1:9990 active at 1500 kbps, status=%+v", actor.Status())
	}
}

func TestTier3AtomicBatchCapAndTestCompatGuardrail(t *testing.T) {
	// 1. 单测假目录(无 bin/hnc_constants.sh)必须拒绝原生直通以便回退假脚本
	fakeDir := t.TempDir()
	if err := TuneGlobalShaperNative(fakeDir, 50000, 20000); err == nil {
		t.Fatal("expected TuneGlobalShaperNative to fail fast in mock test dir without bin/hnc_constants.sh")
	}

	// 2. Tier 3 批处理管道严格封顶 <= 3 次子进程调用
	dir := setupNativeTierTestEnv(t, "wlan2")
	actor := NewDataplaneActor()
	defer actor.Close()

	var cmdCount int
	var gotBins []string
	withMockDPTierHooks(t, func(h *dpTierHooks) {
		h.ifaceIndex = func(name string) (int, error) {
			if name == "wlan2" {
				return 5, nil
			}
			if name == "ifb0" {
				return 6, nil
			}
			return 0, errors.New("none")
		}
		h.probeKernel = func(_ int) (bool, bool, bool) { return false, false, false }
		h.resolveBin = func(name string) string { return "/sbin/" + name }
		h.runTier3Cmd = func(bin string, args []string, stdin []byte) error {
			cmdCount++
			gotBins = append(gotBins, bin+" "+strings.Join(args, " "))
			if len(stdin) == 0 {
				t.Errorf("empty stdin passed to %s", bin)
			}
			return nil
		}
	})

	if tier := probeDataplaneTierOnActor(actor, dir, "wlan2"); tier != DataplaneTierAtomicBatch {
		t.Fatalf("expected tier3_atomic_batch, got %s", tier)
	}
	if err := applyVectorExpressOnActor(actor, dir, true, 0x01000000, 85000); err != nil {
		t.Fatalf("tier3 applyVectorExpressOnActor failed: %v", err)
	}
	if cmdCount != 1 || cmdCount > dpTier3MaxSubprocs {
		t.Fatalf("expected 1 tc -batch subprocess (<= %d), got %d (%v)", dpTier3MaxSubprocs, cmdCount, gotBins)
	}

	// 同时携带 tc + v4 + v6 restore 时总计恰好 3 次子进程(封顶值)
	cmdCount = 0
	h := getDPTierHooks()
	if err := execTier3AtomicBatch(h, []string{"qdisc show"}, []byte("*filter\nCOMMIT\n"), []byte("*filter\nCOMMIT\n")); err != nil {
		t.Fatalf("execTier3AtomicBatch 3-way failed: %v", err)
	}
	if cmdCount != 3 || cmdCount > dpTier3MaxSubprocs {
		t.Fatalf("expected exactly 3 subprocesses for tc+v4+v6 batch, got %d", cmdCount)
	}
}
