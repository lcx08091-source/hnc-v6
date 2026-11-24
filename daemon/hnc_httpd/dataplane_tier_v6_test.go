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

	// 1. 激活 Vector Express (1:8010 prio 0 + fq_codel target=2000us interval=40000us quantum=300 + 背景上限 85Mbps)
	if err := applyVectorExpressOnActor(actor, dir, true, 0x01000000, 85000); err != nil {
		t.Fatalf("applyVectorExpressOnActor enable failed: %v", err)
	}
	if len(captured) == 0 {
		t.Fatal("expected Vector Express netlink messages")
	}

	found18010 := false
	foundShallowFQ := false
	foundBg9999 := false
	foundLegacyCleanFW := false
	for _, m := range captured {
		msgType := binary.LittleEndian.Uint16(m[4:6])
		handle := binary.LittleEndian.Uint32(m[24:28])
		parent := binary.LittleEndian.Uint32(m[28:32])
		if msgType == rtnlDelTFilter && handle == 0x01000000 && strings.Contains(string(m[36:]), "fw\x00") {
			foundLegacyCleanFW = true
		}
		if msgType == rtnlNewTClass && handle == (rtnlHtbRootMaj|uint32(v6ExpressClassMinor)) {
			found18010 = true
			var dumpBuf []byte
			dumpBuf = append(dumpBuf, m...)
			doneHdr := make([]byte, rtnlMsgHdrLen)
			binary.LittleEndian.PutUint32(doneHdr[0:4], rtnlMsgHdrLen)
			binary.LittleEndian.PutUint16(doneHdr[4:6], rtnlMsgDone)
			dumpBuf = append(dumpBuf, doneHdr...)
			parsed, pErr := parseTCClassDumpMsgs(dumpBuf, 0)
			if pErr != nil {
				t.Fatalf("parse 1:8010 class msg failed: %v", pErr)
			}
			cls, ok := parsed["1:8010"]
			if !ok || cls.Prio != 0 {
				t.Fatalf("expected 1:8010 prio 0, got %+v", cls)
			}
		}
		if msgType == rtnlNewQdisc && parent == (rtnlHtbRootMaj|uint32(v6ExpressClassMinor)) {
			if handle != v6ExpressLeafDown && handle != v6ExpressLeafUp {
				t.Fatalf("unexpected Express leaf handle 0x%08x", handle)
			}
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
	if !found18010 || !foundShallowFQ || !foundBg9999 || !foundLegacyCleanFW {
		t.Fatalf("missing expected Vector Express objects: 1:8010=%v shallowFQ=%v bg9999=%v legacyFW=%v",
			found18010, foundShallowFQ, foundBg9999, foundLegacyCleanFW)
	}
	if !actor.Status().ExpressActive {
		t.Fatal("expected ExpressActive=true in status")
	}

	// 2. 停用 Vector Express -> 幂等拆除 1:8010 并恢复 1:9999
	captured = nil
	if err := applyVectorExpressOnActor(actor, dir, false, 0x01000000, 0); err != nil {
		t.Fatalf("applyVectorExpressOnActor disable failed: %v", err)
	}
	foundDel18010 := false
	for _, m := range captured {
		if binary.LittleEndian.Uint16(m[4:6]) == rtnlDelTClass &&
			binary.LittleEndian.Uint32(m[24:28]) == (rtnlHtbRootMaj|uint32(v6ExpressClassMinor)) {
			foundDel18010 = true
		}
	}
	if !foundDel18010 || actor.Status().ExpressActive {
		t.Fatalf("expected 1:8010 deleted and ExpressActive=false, foundDel18010=%v", foundDel18010)
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

	// 2. Tier 3 批处理管道严格封顶 <= 3 次子进程调用, 且同步迁至 1:8010 / 8010:/8110: / prio 4/5 与独立 rootUpKbps
	dir := setupNativeTierTestEnv(t, "wlan2")
	actor := NewDataplaneActor()
	defer actor.Close()

	var cmdCount int
	var gotBins []string
	var lastStdin string
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
			lastStdin = string(stdin)
			if len(stdin) == 0 {
				t.Errorf("empty stdin passed to %s", bin)
			}
			return nil
		}
	})

	if tier := probeDataplaneTierOnActor(actor, dir, "wlan2"); tier != DataplaneTierAtomicBatch {
		t.Fatalf("expected tier3_atomic_batch, got %s", tier)
	}
	// 先设定非对称全局整形: 下行 160Mbps, 上行 40Mbps
	if err := tuneGlobalShaperOnActor(actor, dir, 160000, 40000); err != nil {
		t.Fatalf("tier3 tuneGlobalShaperOnActor failed: %v", err)
	}
	cmdCount = 0
	gotBins = nil
	if err := applyVectorExpressOnActor(actor, dir, true, 0x01000000, 85000); err != nil {
		t.Fatalf("tier3 applyVectorExpressOnActor failed: %v", err)
	}
	if cmdCount != 1 || cmdCount > dpTier3MaxSubprocs {
		t.Fatalf("expected 1 tc -batch subprocess (<= %d), got %d (%v)", dpTier3MaxSubprocs, cmdCount, gotBins)
	}
	for _, wantSub := range []string{
		"class replace dev wlan2 parent 1:1 classid 1:8010 htb rate 40000kbit ceil 160000kbit prio 0",
		"qdisc replace dev wlan2 parent 1:8010 handle 8010: fq_codel",
		"class replace dev ifb0 parent 1:1 classid 1:8010 htb rate 20000kbit ceil 40000kbit prio 0",
		"qdisc replace dev ifb0 parent 1:8010 handle 8110: fq_codel",
		"prio 4 handle 0x1000000/0x3000000 fw flowid 1:8010",
		"prio 5 handle 0x1000000/0x3000000 fw flowid 1:8010",
		"filter del dev wlan2 parent 1: protocol ip prio 2 handle 0x1000000/0x3000000 fw",
	} {
		if !strings.Contains(lastStdin, wantSub) {
			t.Fatalf("missing expected tier3 line %q in:\n%s", wantSub, lastStdin)
		}
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

func TestVectorExpressAsymmetric5GUplinkScalingAndZeroUpGuard(t *testing.T) {
	// 1. 验证 computeUpBgCeilKbps 独立缩放优先级: autorate.json cur_up_mbps -> rules.json global_shaper_up -> 均未启用返回 0
	s, _, dir := newV6TestMux(t)
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "hnc_constants.sh"),
		[]byte("HNC_DEV_MARK_BASE=0x00800000\nHNC_DEV_MARK_MASK=0x00ff0000\nHNC_DEV_MARK_SHIFT=16\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)

	exp := s.v6State().express
	if got := exp.computeUpBgCeilKbps(85); got != 0 {
		t.Fatalf("expected 0 when neither autorate nor global_shaper_up is enabled, got %d", got)
	}

	// 写入静态非对称整形: 下行 300mbit, 上行 30mbit (10:1 典型 5G 非对称比例)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{
		"version": 1,
		"global_shaper_enabled": true,
		"global_shaper_down": "300mbit",
		"global_shaper_up": "30mbit",
		"devices": {}
	}`), 0o600)
	s.invalidateServerJSONCaches()
	if downGot, upGot := exp.computeBgCeilKbps(85), exp.computeUpBgCeilKbps(85); downGot != 255000 || upGot != 25500 {
		t.Fatalf("static 300/30mbit * 85%% mismatch: down=%d (want 255000), up=%d (want 25500)", downGot, upGot)
	}

	// 写入 run/autorate.json (cur_down_mbps=240, cur_up_mbps=20) -> 优先采用 Autorate 实时带宽
	_ = os.WriteFile(filepath.Join(dir, "run", "autorate.json"), []byte(`{
		"enabled": true,
		"cur_down_mbps": 240,
		"cur_up_mbps": 20
	}`), 0o600)
	if downGot, upGot := exp.computeBgCeilKbps(80), exp.computeUpBgCeilKbps(80); downGot != 192000 || upGot != 16000 {
		t.Fatalf("autorate 240/20mbit * 80%% mismatch: down=%d (want 192000), up=%d (want 16000)", downGot, upGot)
	}

	// 2. 验证 Tier 2 Netlink 在 5G 非对称带宽下独立收紧 ifb0 1:9999 至 25500kbit, 且在 upKbps==0 时强制保持 1000mbit 不乱锁上行!
	_ = os.Remove(filepath.Join(dir, "run", "autorate.json"))
	actor := NewDataplaneActor()
	defer actor.Close()

	var captured [][]byte
	withMockDPTierHooks(t, func(h *dpTierHooks) {
		h.openSocket = func() (int, error) { return 66, nil }
		h.closeSocket = func(_ int) {}
		h.ifaceIndex = func(name string) (int, error) {
			switch name {
			case "wlan2":
				return 11, nil
			case "ifb0":
				return 12, nil
			default:
				return 0, errors.New("missing")
			}
		}
		h.tuneShaperOnSock = func(_ int, _ int, _ uint64, _ int, _ uint64) (int, error) { return 2, nil }
		h.applyBatchOnSock = func(_ int, msgs [][]byte) (int, error) {
			captured = append([][]byte(nil), msgs...)
			return len(msgs), nil
		}
	})

	extractClassCeil := func(msgs [][]byte, wantIfidx int, minor uint16) int {
		for _, m := range msgs {
			if binary.LittleEndian.Uint16(m[4:6]) != rtnlNewTClass {
				continue
			}
			ifidx := int(int32(binary.LittleEndian.Uint32(m[20:24])))
			handle := binary.LittleEndian.Uint32(m[24:28])
			if ifidx != wantIfidx || handle != (rtnlHtbRootMaj|uint32(minor)) {
				continue
			}
			var dumpBuf []byte
			dumpBuf = append(dumpBuf, m...)
			doneHdr := make([]byte, rtnlMsgHdrLen)
			binary.LittleEndian.PutUint32(doneHdr[0:4], rtnlMsgHdrLen)
			binary.LittleEndian.PutUint16(doneHdr[4:6], rtnlMsgDone)
			dumpBuf = append(dumpBuf, doneHdr...)
			parsed, err := parseTCClassDumpMsgs(dumpBuf, 0)
			if err != nil {
				t.Fatalf("parseTCClassDumpMsgs failed: %v", err)
			}
			for _, cls := range parsed {
				return int(cls.CeilKbit)
			}
		}
		return -1
	}

	if err := tuneGlobalShaperOnActor(actor, dir, 300000, 30000); err != nil {
		t.Fatalf("tuneGlobalShaperOnActor(300000, 30000) failed: %v", err)
	}
	captured = nil
	if err := applyVectorExpressOnActor(actor, dir, true, 0x01000000, 255000, 25500); err != nil {
		t.Fatalf("applyVectorExpressOnActor asymmetric failed: %v", err)
	}
	downCeil := extractClassCeil(captured, 11, rtnlDefMinor)
	upCeil := extractClassCeil(captured, 12, rtnlDefMinor)
	if downCeil != 255000 || upCeil != 25500 {
		t.Fatalf("Tier 2 asymmetric 1:9999 ceil mismatch: downCeil=%d (want 255000), upCeil=%d (want 25500)", downCeil, upCeil)
	}

	// 当全局上行整形未启用(upKbps==0)时, 即使误传 optUpBgCeilKbps=25500, ifb0 1:9999 也必须保持 1000mbit(1000000kbit), 严禁锁上行!
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{
		"version": 1,
		"global_shaper_enabled": true,
		"global_shaper_down": "300mbit",
		"global_shaper_up": "",
		"devices": {}
	}`), 0o600)
	s.invalidateServerJSONCaches()
	if err := tuneGlobalShaperOnActor(actor, dir, 300000, 0); err != nil {
		t.Fatalf("tuneGlobalShaperOnActor(300000, 0) failed: %v", err)
	}
	captured = nil
	if err := applyVectorExpressOnActor(actor, dir, true, 0x01000000, 255000, 25500); err != nil {
		t.Fatalf("applyVectorExpressOnActor upKbps=0 guard failed: %v", err)
	}
	if upCeilReset := extractClassCeil(captured, 12, rtnlDefMinor); upCeilReset != dpDefaultRootRateKbp {
		t.Fatalf("when upKbps transitions to 0 after prior cap, Tier 2 must reset ifb0 1:9999 to %d kbit, got %d kbit", dpDefaultRootRateKbp, upCeilReset)
	}

	// 3. 验证 Tier 3 批处理管道与 resolveActiveVectorExpressParamsFull 同样遵循非对称上行收紧与 upKbps==0 复位 1000mbit 守卫
	linesAsym := strings.Join(buildTier3VectorExpressBatchLines("wlan2", true, true, false, false, 0x01000000, 0x03000000, 255000, 300000, 30000, 25500), "\n")
	if !strings.Contains(linesAsym, "class replace dev ifb0 parent 1:1 classid 1:9999 htb rate 25500kbit ceil 25500kbit prio 7") {
		t.Fatalf("expected Tier 3 ifb0 1:9999 ceil 25500kbit, got:\n%s", linesAsym)
	}
	linesUpOff := strings.Join(buildTier3VectorExpressBatchLines("wlan2", true, true, false, false, 0x01000000, 0x03000000, 255000, 300000, 0, 25500), "\n")
	if strings.Contains(linesUpOff, "class replace dev ifb0 parent 1:1 classid 1:9999 htb rate 25500kbit") ||
		!strings.Contains(linesUpOff, "class replace dev ifb0 parent 1:1 classid 1:9999 htb rate 1000000kbit ceil 1000000kbit prio 7") {
		t.Fatalf("when configuredUpKbps==0, Tier 3 must reset ifb0 1:9999 to 1000000kbit and NOT lock at 25500kbit, got:\n%s", linesUpOff)
	}

	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{
		"version": 1,
		"global_shaper_enabled": true,
		"global_shaper_down": "200mbit",
		"global_shaper_up": "20mbit",
		"devices": {}
	}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "run", "vector_express_state.json"), []byte(`{
		"active": true,
		"bg_pool_ceil_pct": 85
	}`), 0o600)
	s.invalidateServerJSONCaches()
	actExp, _, gotDownBg, gotUpBg := resolveActiveVectorExpressParamsFull(s, dir)
	if !actExp || gotDownBg != 170000 || gotUpBg != 17000 {
		t.Fatalf("resolveActiveVectorExpressParamsFull mismatch: active=%v downBg=%d (want 170000) upBg=%d (want 17000)",
			actExp, gotDownBg, gotUpBg)
	}
}

func TestIngressPolicePrioUnificationIPv6FallbackAndStatsPos3(t *testing.T) {
	if nativeIngressPolicePrioBase != 300 || legacyNativeIngressPolicePrioBase != 20000 {
		t.Fatalf("unexpected ingress police prio bases: cur=%d legacy=%d", nativeIngressPolicePrioBase, legacyNativeIngressPolicePrioBase)
	}

	dir := setupNativeTierTestEnv(t, "wlan2")

	origResolve := nativeResolveSystemBinFn
	origTCExec := nativeTCExecFn
	origTCShow := nativeTCQdiscShowFn
	origCollectV6 := nativeCollectDevIPv6Fn
	origIptRunner := nativeIptCmdRunner
	t.Cleanup(func() {
		nativeResolveSystemBinFn = origResolve
		nativeTCExecFn = origTCExec
		nativeTCQdiscShowFn = origTCShow
		nativeCollectDevIPv6Fn = origCollectV6
		nativeIptCmdRunner = origIptRunner
	})

	nativeResolveSystemBinFn = func(_ string) string { return "/system/bin/tc" }
	var tcCmds []string
	nativeTCExecFn = func(_ string, args ...string) error {
		tcCmds = append(tcCmds, strings.Join(args, " "))
		return nil
	}
	nativeTCQdiscShowFn = func(_, _ string) string { return "qdisc ingress ffff: parent ffff:fff1" }

	// (a) 无 clsact BPF 且客户端拥有全局 IPv6 地址时: applyNativeIngressPolice 必须报错触发调用方安全回退 ./bin/tc_manager.sh!
	nativeCollectDevIPv6Fn = func(_, _, _ string) []string { return []string{"2409:8a00:1234::88"} }
	if err := applyNativeIngressPolice(dir, "wlan2", 2, "aa:bb:cc:dd:ee:02", "192.168.43.20", 1_250_000, 0x00820000, 0x00ff0000); err == nil {
		t.Fatal("expected applyNativeIngressPolice to return error when !clsactActive and client has global IPv6")
	}
	if len(tcCmds) != 0 {
		t.Fatalf("expected zero tc mutations before IPv6 fallback error, got %v", tcCmds)
	}

	// (b) 纯 IPv4 客户端(或 clsact 就绪): 必须按 base=300 下发 prio 302 / 6302 / 7302, 并同时清理 300 基数与旧版 20000 基数残留!
	nativeCollectDevIPv6Fn = func(_, _, _ string) []string { return nil }
	tcCmds = nil
	if err := applyNativeIngressPolice(dir, "wlan2", 2, "aa:bb:cc:dd:ee:02", "192.168.43.20", 1_250_000, 0x00820000, 0x00ff0000); err != nil {
		t.Fatalf("applyNativeIngressPolice IPv4 failed: %v", err)
	}
	joinedTC := strings.Join(tcCmds, "\n")
	for _, want := range []string{
		"filter del dev wlan2 parent ffff: protocol ip prio 302",
		"filter del dev wlan2 parent ffff: protocol ipv6 prio 5302",
		"filter del dev wlan2 parent ffff: protocol ip prio 6302",
		"filter del dev wlan2 parent ffff: protocol ipv6 prio 7302",
		"filter del dev wlan2 parent ffff: protocol ip prio 20002",
		"filter del dev wlan2 parent ffff: protocol ipv6 prio 25002",
		"filter del dev wlan2 parent ffff: protocol ip prio 26002",
		"filter del dev wlan2 parent ffff: protocol ipv6 prio 27002",
		"filter add dev wlan2 parent ffff: protocol ip prio 302 u32 match ip src 192.168.43.20/32",
		"filter add dev wlan2 parent ffff: protocol ip prio 6302 handle 0x820000/0xff0000 fw",
		"filter add dev wlan2 parent ffff: protocol ipv6 prio 7302 handle 0x820000/0xff0000 fw",
	} {
		if !strings.Contains(joinedTC, want) {
			t.Fatalf("missing expected tc command %q in:\n%s", want, joinedTC)
		}
	}

	// (c) clsact BPF 已激活且有全局 IPv6 时: 正常下发 prio 5302 IPv6 u32 警察过滤器
	_ = os.WriteFile(filepath.Join(dir, "run", "clsact.state"), []byte("active\n"), 0o644)
	nativeTCQdiscShowFn = func(_, _ string) string { return "qdisc clsact ffff: parent ffff:fff1" }
	nativeCollectDevIPv6Fn = func(_, _, _ string) []string { return []string{"2409:8a00:1234::88"} }
	tcCmds = nil
	if err := applyNativeIngressPolice(dir, "wlan2", 2, "aa:bb:cc:dd:ee:02", "192.168.43.20", 1_250_000, 0x00820000, 0x00ff0000); err != nil {
		t.Fatalf("applyNativeIngressPolice clsact+IPv6 failed: %v", err)
	}
	if !strings.Contains(strings.Join(tcCmds, "\n"), "filter add dev wlan2 ingress protocol ipv6 prio 5302 u32 match ip6 src 2409:8a00:1234::88/128") {
		t.Fatalf("missing prio 5302 IPv6 u32 rule in:\n%s", strings.Join(tcCmds, "\n"))
	}

	// (d) 验证 ensureNativeIPv4StatsRule 优先挂载 `-I FORWARD 3 -j HNC_STATS` (对齐 MSS 钳制后第 3 位), 失败时安全回退 `-A FORWARD -j HNC_STATS`
	var iptCalls []string
	failInsertPos3 := false
	nativeIptCmdRunner = func(_ string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		iptCalls = append(iptCalls, line)
		if strings.Contains(line, " -C ") {
			return "missing", errors.New("exit 1")
		}
		if failInsertPos3 && strings.Contains(line, "-I FORWARD 3 -j HNC_STATS") {
			return "Index of insertion too big", errors.New("exit 1")
		}
		return "", nil
	}

	ensureNativeIPv4StatsRule("/system/bin/iptables", "192.168.43.55")
	joinedIpt1 := strings.Join(iptCalls, "\n")
	if !strings.Contains(joinedIpt1, "-t mangle -I FORWARD 3 -j HNC_STATS") || strings.Contains(joinedIpt1, "-t mangle -A FORWARD -j HNC_STATS") {
		t.Fatalf("expected `-I FORWARD 3 -j HNC_STATS` without `-A FORWARD` fallback when pos 3 succeeds, got:\n%s", joinedIpt1)
	}

	iptCalls = nil
	failInsertPos3 = true
	ensureNativeIPv4StatsRule("/system/bin/iptables", "192.168.43.56")
	joinedIpt2 := strings.Join(iptCalls, "\n")
	if !strings.Contains(joinedIpt2, "-t mangle -I FORWARD 3 -j HNC_STATS") || !strings.Contains(joinedIpt2, "-t mangle -A FORWARD -j HNC_STATS") {
		t.Fatalf("expected `-I FORWARD 3` followed by `-A FORWARD -j HNC_STATS` fallback when chain has <2 rules, got:\n%s", joinedIpt2)
	}
}
