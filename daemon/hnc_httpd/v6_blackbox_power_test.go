package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func waitBlackboxCond(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for condition: %s", desc)
	}
}

func TestAtomic64StructHeadAlignmentGuard(t *testing.T) {
	var (
		zSrv server
		zCH  CoreHub
		zDP  DataplaneActor
		zFS  flowScalpelEngine
		zJB  JitterBlackbox
	)
	offsets := []struct {
		name   string
		offset uintptr
	}{
		{"server.blackboxCaptureUntilUnix", unsafe.Offsetof(zSrv.blackboxCaptureUntilUnix)},
		{"server.blackboxLastActiveMs", unsafe.Offsetof(zSrv.blackboxLastActiveMs)},
		{"server.blackboxShortCircuits", unsafe.Offsetof(zSrv.blackboxShortCircuits)},
		{"server.blackboxRecordedTicks", unsafe.Offsetof(zSrv.blackboxRecordedTicks)},
		{"CoreHub.shmSeqlockHits", unsafe.Offsetof(zCH.shmSeqlockHits)},
		{"CoreHub.shmFallbackCount", unsafe.Offsetof(zCH.shmFallbackCount)},
		{"DataplaneActor.reconcileInvalidations", unsafe.Offsetof(zDP.reconcileInvalidations)},
		{"flowScalpelEngine.seqGen", unsafe.Offsetof(zFS.seqGen)},
		{"flowScalpelEngine.cutTotal", unsafe.Offsetof(zFS.cutTotal)},
		{"JitterBlackbox.totalTicks", unsafe.Offsetof(zJB.totalTicks)},
		{"JitterBlackbox.totalIncidents", unsafe.Offsetof(zJB.totalIncidents)},
		{"JitterBlackbox.lastTickUnixMs", unsafe.Offsetof(zJB.lastTickUnixMs)},
		{"JitterBlackbox.lastSpikeUnixMs", unsafe.Offsetof(zJB.lastSpikeUnixMs)},
		{"JitterBlackbox.latestJitterBits", unsafe.Offsetof(zJB.latestJitterBits)},
	}
	for _, item := range offsets {
		if item.offset%8 != 0 {
			t.Fatalf("field %s offset=%d is not 8-byte aligned for 32-bit GOARCH=arm", item.name, item.offset)
		}
	}
}

func TestBlackboxZeroTrafficShortCircuitPreserves300Frames(t *testing.T) {
	globalJitterBlackbox.Clear()
	t.Cleanup(globalJitterBlackbox.Clear)

	var nilSrv *server
	nilSrv.SampleBlackboxOnce(time.Now())
	globalJitterBlackbox.Clear()

	var sinkCalls atomic.Int64
	var spikeMu sync.Mutex
	curRTT := 22.0
	baseRTT := 20.0

	srv := &server{
		hncDir: t.TempDir(),
		rates: map[string]rateOut{
			"aa:bb:cc:dd:ee:01": {rxBps: 24_000_000, txBps: 3_000_000},
		},
		blackboxAutorateHook: func() (blackboxAutorateReading, bool) {
			spikeMu.Lock()
			defer spikeMu.Unlock()
			return blackboxAutorateReading{
				RTTMs:       curRTT,
				BaseRTTMs:   baseRTT,
				CapacityBps: 12_500_000,
			}, true
		},
		blackboxSampleOverride: func(in BlackboxTickInput, _ map[string]rateOut) (BlackboxFrame, *BlackboxIncident) {
			sinkCalls.Add(1)
			return globalJitterBlackbox.RecordSample(in)
		},
	}

	baseTime := time.Now().Add(-60 * time.Second)
	for i := 0; i < 300; i++ {
		ts := baseTime.Add(time.Duration(i*v6BlackboxIntervalMs) * time.Millisecond)
		srv.SampleBlackboxOnce(ts)
	}
	if got := sinkCalls.Load(); got != 300 {
		t.Fatalf("expected 300 recorded frames during active traffic, got %d", got)
	}

	srv.rateMu.Lock()
	srv.rates["aa:bb:cc:dd:ee:01"] = rateOut{rxBps: 0, txBps: 0}
	srv.rateMu.Unlock()

	idleStart := baseTime.Add(60 * time.Second)
	for i := 0; i < 500; i++ {
		ts := idleStart.Add(time.Duration(i*v6BlackboxIntervalMs) * time.Millisecond)
		srv.SampleBlackboxOnce(ts)
	}
	if got := sinkCalls.Load(); got != 300 {
		t.Fatalf("blank frames polluted blackbox ring: sinkCalls=%d want 300", got)
	}
	if got := srv.blackboxShortCircuits.Load(); got != 500 {
		t.Fatalf("expected 500 short-circuited idle ticks, got %d", got)
	}

	// 开启抓包录制但无流量且无 RTT 突刺时, 同样不得冲空已捕获的 300 帧卡顿现场
	srv.markBlackboxCaptureMinutes(5)
	for i := 0; i < 50; i++ {
		srv.SampleBlackboxOnce(idleStart.Add(time.Duration((500+i)*v6BlackboxIntervalMs) * time.Millisecond))
	}
	srv.clearBlackboxCapture()
	if got := sinkCalls.Load(); got != 300 {
		t.Fatalf("idle packet capture flushed blackbox ring: sinkCalls=%d want 300", got)
	}

	spikeMu.Lock()
	curRTT = baseRTT + float64(v6BlackboxSpikeDeltaRTTMs) + 8.0
	spikeMu.Unlock()

	srv.SampleBlackboxOnce(idleStart.Add(120 * time.Second))
	if got := sinkCalls.Load(); got != 301 {
		t.Fatalf("expected RTT spike to record frame 301, got %d", got)
	}

	// 手动快照 force=true 即使空载无突刺也立即采集一帧
	spikeMu.Lock()
	curRTT = baseRTT
	spikeMu.Unlock()
	srv.sampleBlackbox(idleStart.Add(121*time.Second), true)
	if got := sinkCalls.Load(); got != 302 {
		t.Fatalf("expected manual forced snapshot to record frame 302, got %d", got)
	}
}

func TestCaptureRecordGuardsAndSelectiveWake(t *testing.T) {
	globalJitterBlackbox.Clear()
	t.Cleanup(globalJitterBlackbox.Clear)

	if resp := actionCaptureRecord(nil, nil); resp.OK {
		t.Fatalf("expected nil server guard on actionCaptureRecord, got %+v", resp)
	}
	if resp := actionCaptureRecord(&server{}, nil); resp.OK {
		t.Fatalf("expected empty hncDir guard on actionCaptureRecord, got %+v", resp)
	}
	if resp := actionCaptureRecordStop(nil); resp.OK {
		t.Fatalf("expected nil server guard on actionCaptureRecordStop, got %+v", resp)
	}
	if resp := actionCaptureRecordStop(&server{}); resp.OK {
		t.Fatalf("expected empty hncDir guard on actionCaptureRecordStop, got %+v", resp)
	}

	srv := &server{hncDir: t.TempDir()}
	wakeCh := srv.ensureBlackboxWakeCh()
	srv.blackboxLoopMode.Store(int32(blackboxModeSleeping))
	srv.clearBlackboxCapture()
	select {
	case <-wakeCh:
		t.Fatal("clearBlackboxCapture must not wake sleeping blackbox loop")
	default:
	}

	srv.blackboxLoopMode.Store(int32(blackboxModeActive))
	srv.clearBlackboxCapture()
	select {
	case <-wakeCh:
	default:
		t.Fatal("clearBlackboxCapture must wake active blackbox loop to downshift")
	}
}

func TestBlackboxFlightLoopFourTierSleepAndWake(t *testing.T) {
	globalJitterBlackbox.Clear()
	t.Cleanup(globalJitterBlackbox.Clear)

	var actMu sync.Mutex
	curAct := Activity{Known: true, HotspotActive: false, ClientsOnline: 0}
	actCh := make(chan struct{})
	updateAct := func(next Activity) {
		actMu.Lock()
		curAct = next
		old := actCh
		actCh = make(chan struct{})
		actMu.Unlock()
		close(old)
	}

	var sampled atomic.Int64
	srv := &server{
		hncDir:            t.TempDir(),
		rates:             map[string]rateOut{},
		blackboxActiveDur: 15 * time.Millisecond,
		blackboxPatrolDur: 320 * time.Millisecond,
		blackboxHoldDur:   280 * time.Millisecond,
		blackboxActivityHook: func() (<-chan struct{}, Activity) {
			actMu.Lock()
			defer actMu.Unlock()
			return actCh, curAct
		},
		blackboxSampleOverride: func(in BlackboxTickInput, _ map[string]rateOut) (BlackboxFrame, *BlackboxIncident) {
			sampled.Add(1)
			return BlackboxFrame{}, nil
		},
	}

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		srv.StartBlackboxFlightLoop(stopCh)
	}()
	defer func() {
		select {
		case <-doneCh:
		default:
			close(stopCh)
			<-doneCh
		}
	}()

	waitBlackboxCond(t, time.Second, "enter G0_AP_OFF sleeping mode", func() bool {
		return srv.BlackboxLoopMode() == blackboxModeSleeping
	})
	// 空闲休眠态收到虚假唤醒信号不得误补采
	srv.wakeBlackboxLoop()
	time.Sleep(45 * time.Millisecond)
	if got := sampled.Load(); got != 0 {
		t.Fatalf("expected 0 samples in G0_AP_OFF, got %d", got)
	}

	updateAct(Activity{Known: true, HotspotActive: true, ClientsOnline: 0})
	time.Sleep(35 * time.Millisecond)
	if mode := srv.BlackboxLoopMode(); mode != blackboxModeSleeping {
		t.Fatalf("expected G1_NO_CLIENTS to remain sleeping, got mode=%d", mode)
	}

	updateAct(Activity{Known: true, HotspotActive: true, ClientsOnline: 2})
	waitBlackboxCond(t, time.Second, "enter G2_IDLE_PATROL mode", func() bool {
		return srv.BlackboxLoopMode() == blackboxModePatrol
	})

	srv.rateMu.Lock()
	srv.rates["aa:bb:cc:dd:ee:02"] = rateOut{rxBps: 15_000_000, txBps: 1_500_000}
	srv.rateMu.Unlock()
	srv.notifyBlackboxIfActiveRates()

	waitBlackboxCond(t, time.Second, "enter G3_ACTIVE_FLIGHT mode and record frames", func() bool {
		return srv.BlackboxLoopMode() == blackboxModeActive && sampled.Load() >= 2
	})

	srv.rateMu.Lock()
	srv.rates["aa:bb:cc:dd:ee:02"] = rateOut{rxBps: 0, txBps: 0}
	srv.rateMu.Unlock()

	waitBlackboxCond(t, 2*time.Second, "auto-downshift to G2_IDLE_PATROL", func() bool {
		return srv.BlackboxLoopMode() == blackboxModePatrol
	})

	updateAct(Activity{Known: true, HotspotActive: true, ClientsOnline: 0})
	waitBlackboxCond(t, time.Second, "return to G1_NO_CLIENTS sleeping mode", func() bool {
		return srv.BlackboxLoopMode() == blackboxModeSleeping
	})

	close(stopCh)
	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("StartBlackboxFlightLoop leaked goroutine after stop closed")
	}
}

func TestFlowScalpelZeroRuleSleepAndWakeResume(t *testing.T) {
	var activeRules atomic.Int32
	var sweeps atomic.Int64

	eng := &flowScalpelEngine{
		sweepInterval: 20 * time.Millisecond,
		ruleCountHook: func() int {
			return int(activeRules.Load())
		},
	}
	eng.sweepHook = func(_ time.Time) {
		sweeps.Add(1)
		for {
			cur := activeRules.Load()
			if cur <= 0 {
				return
			}
			if activeRules.CompareAndSwap(cur, cur-1) {
				return
			}
		}
	}

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		eng.runLoop(stopCh)
	}()
	defer func() {
		select {
		case <-doneCh:
		default:
			close(stopCh)
			<-doneCh
		}
	}()

	waitBlackboxCond(t, time.Second, "initial zero-rule ticker stopped", func() bool {
		return !eng.IsTickerActive()
	})
	time.Sleep(50 * time.Millisecond)
	if got := sweeps.Load(); got != 0 {
		t.Fatalf("expected 0 sweeps while active rule count is 0, got %d", got)
	}

	activeRules.Store(2)
	eng.notifyRuleAdded()
	waitBlackboxCond(t, time.Second, "all 2 rules swept and ticker auto-stopped", func() bool {
		return activeRules.Load() == 0 && !eng.IsTickerActive() && sweeps.Load() >= 2
	})

	close(stopCh)
	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("flowScalpelEngine.runLoop leaked goroutine after stop closed")
	}
}
