package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"hnc.io/dpid/neigh"
)

type scriptedStep struct {
	entries []neigh.Entry
	err     error
}

type scriptedNeighSource struct {
	stepsCh     chan scriptedStep
	stopSig     chan struct{}
	readEntered chan struct{}
	enterOnce   sync.Once
	readCount   atomic.Int32
	closeCount  atomic.Int32
}

func newScriptedNeighSource(bufCap int) *scriptedNeighSource {
	return &scriptedNeighSource{
		stepsCh:     make(chan scriptedStep, bufCap),
		stopSig:     make(chan struct{}),
		readEntered: make(chan struct{}),
	}
}

func (s *scriptedNeighSource) Read() ([]neigh.Entry, error) {
	s.enterOnce.Do(func() { close(s.readEntered) })
	select {
	case <-s.stopSig:
		return nil, os.ErrClosed
	case st := <-s.stepsCh:
		s.readCount.Add(1)
		if st.err != nil {
			return nil, st.err
		}
		return st.entries, nil
	}
}

func (s *scriptedNeighSource) Close() error {
	if n := s.closeCount.Add(1); n != 1 {
		panic(fmt.Sprintf("scriptedNeighSource.Close called multiple times: %d", n))
	}
	close(s.stopSig)
	return nil
}

func newBeta1TestRunner(t *testing.T, ifindex int, subFn func() (m4NeighSource, error), dumpFn func(int) ([]neigh.Entry, error)) *m4GoRunner {
	t.Helper()
	m4TestEnv(t)
	r := newM4GoRunner("wlan2")
	r.subscribeFn = subFn
	r.dumpIfFn = dumpFn
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.blacklistFn = func() map[string]bool { return nil }
	r.ifIndexFn = func(string) (int, error) { return ifindex, nil }
	r.hooks.Fast = func(mac string) (string, string) { return "client", "manual" }
	r.hooks.Full = func(mac, ip string) (string, string) { return "client", "manual" }
	r.applyHooks()
	return r
}

func TestRunnerEnobufsInPlaceResyncRateLimited(t *testing.T) {
	src := newScriptedNeighSource(32)
	var subCalls atomic.Int32
	var dumpCalls atomic.Int32

	const testIfindex = 7
	syncEntry := neigh.Entry{IfIndex: testIfindex, IP: net.IPv4(192, 168, 43, 20), MAC: "02:aa:bb:cc:dd:01", State: neigh.NUDReachable}
	liveEntry := neigh.Entry{IfIndex: testIfindex, IP: net.IPv4(192, 168, 43, 21), MAC: "02:aa:bb:cc:dd:02", State: neigh.NUDReachable}

	r := newBeta1TestRunner(t, testIfindex,
		func() (m4NeighSource, error) {
			subCalls.Add(1)
			return src, nil
		},
		func(idx int) ([]neigh.Entry, error) {
			if n := dumpCalls.Add(1); n >= 2 {
				return []neigh.Entry{syncEntry}, nil
			}
			return nil, nil
		},
	)

	r.start()
	t.Cleanup(func() {
		select {
		case <-r.doneCh:
		default:
			close(r.stopCh)
			<-r.doneCh
		}
	})

	<-src.readEntered
	// 先等待启动后首个 200ms 初始 FullSync 完成(dumpCalls >= 1), 防止 ENOBUFS 在 t=1ms 注入被初始同步吞掉
	if _, ok := m4WaitCount(&dumpCalls, 0, 2*time.Second); !ok {
		t.Fatalf("timed out waiting for initial FullSync: dumpCalls=%d", dumpCalls.Load())
	}
	if got := dumpCalls.Load(); got != 1 {
		t.Fatalf("initial FullSync dumpCalls=%d, want 1", got)
	}

	for i := 0; i < 12; i++ {
		src.stepsCh <- scriptedStep{err: fmt.Errorf("neigh: recv: %w", syscall.ENOBUFS)}
	}
	if _, ok := m4WaitCount(&src.readCount, 11, 2*time.Second); !ok {
		t.Fatalf("timed out draining 12 ENOBUFS steps: readCount=%d", src.readCount.Load())
	}

	// 1s 限频窗口期满后触发唯一一次原位重同步, dumpCalls 从 1 精确变为 2
	if _, ok := m4WaitCount(&dumpCalls, 1, 2500*time.Millisecond); !ok {
		t.Fatalf("timed out waiting for ENOBUFS 1Hz resync: dumpCalls=%d, want 2", dumpCalls.Load())
	}

	if got := dumpCalls.Load(); got != 2 {
		t.Fatalf("ENOBUFS 1Hz resync dumpCalls=%d, want 2", got)
	}
	if got := subCalls.Load(); got != 1 {
		t.Fatalf("ENOBUFS must not reconnect subscribeFn: subCalls=%d", got)
	}
	if got := src.closeCount.Load(); got != 0 {
		t.Fatalf("ENOBUFS must not close active subscription: closeCount=%d", got)
	}

	src.stepsCh <- scriptedStep{entries: []neigh.Entry{liveEntry}}
	if got, ok := waitDevices(t, 2*time.Second, func(s string) bool {
		return strings.Contains(s, "02:aa:bb:cc:dd:01") && strings.Contains(s, "02:aa:bb:cc:dd:02")
	}); !ok {
		t.Fatalf("expected both resynced and live entries in devices.json, got %q", got)
	}

	m4StopRunner(t, r)
	if got := src.closeCount.Load(); got != 1 {
		t.Fatalf("expected source closed once on stop, got %d", got)
	}
}

func TestRunnerDisconnectAutoReconnectBackoff(t *testing.T) {
	oldBase, oldMax := m4ReconnectBaseBackoff, m4ReconnectMaxBackoff
	m4ReconnectBaseBackoff = 60 * time.Millisecond
	m4ReconnectMaxBackoff = 500 * time.Millisecond
	t.Cleanup(func() {
		m4ReconnectBaseBackoff = oldBase
		m4ReconnectMaxBackoff = oldMax
	})

	src1 := newScriptedNeighSource(4)
	src3 := newScriptedNeighSource(4)
	var subCalls atomic.Int32
	var dumpCalls atomic.Int32

	recoveredEntry := neigh.Entry{IfIndex: 8, IP: net.IPv4(192, 168, 43, 55), MAC: "02:11:22:33:44:55", State: neigh.NUDReachable}
	r := newBeta1TestRunner(t, 8,
		func() (m4NeighSource, error) {
			switch subCalls.Add(1) {
			case 1:
				return src1, nil
			case 2:
				return nil, errors.New("simulated bind failure")
			default:
				return src3, nil
			}
		},
		func(idx int) ([]neigh.Entry, error) {
			dumpCalls.Add(1)
			return []neigh.Entry{recoveredEntry}, nil
		},
	)

	startAt := time.Now()
	r.start()
	t.Cleanup(func() {
		select {
		case <-r.doneCh:
		default:
			close(r.stopCh)
			<-r.doneCh
		}
	})

	<-src1.readEntered
	src1.stepsCh <- scriptedStep{err: errors.New("simulated socket reset")}

	select {
	case <-src3.readEntered:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for auto-reconnect: subCalls=%d", subCalls.Load())
	}

	if elapsed := time.Since(startAt); elapsed < 150*time.Millisecond {
		t.Fatalf("exponential backoff (60ms + 120ms) too short: %v", elapsed)
	}
	if got := src1.closeCount.Load(); got != 1 {
		t.Fatalf("src1 closeCount=%d, want 1", got)
	}
	if got := subCalls.Load(); got != 3 {
		t.Fatalf("subCalls=%d, want 3", got)
	}

	m4StopRunner(t, r)
	if got := src3.closeCount.Load(); got != 1 {
		t.Fatalf("src3 closeCount=%d, want 1", got)
	}
}

func TestRunnerStopWakesBlockedSourceNoGoroutineLeak(t *testing.T) {
	baseGoroutines := runtime.NumGoroutine()
	src := newScriptedNeighSource(1)
	r := newBeta1TestRunner(t, 9,
		func() (m4NeighSource, error) { return src, nil },
		func(idx int) ([]neigh.Entry, error) { return nil, nil },
	)

	r.start()
	<-src.readEntered

	m4StopRunner(t, r)
	if got := src.closeCount.Load(); got != 1 {
		t.Fatalf("src.Close count=%d, want 1", got)
	}

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) && runtime.NumGoroutine() > baseGoroutines {
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	if cur := runtime.NumGoroutine(); cur > baseGoroutines+1 {
		t.Fatalf("goroutine count grew after stop: before=%d after=%d", baseGoroutines, cur)
	}
}

func TestNeighSubConcurrentCloseWakesReadPromptly(t *testing.T) {
	sub, err := neigh.Subscribe()
	if err != nil {
		t.Skipf("skipping real AF_NETLINK RTMGRP_NEIGH Subscribe test in restricted container: %v", err)
	}
	t.Cleanup(func() { _ = sub.Close() })

	var closing atomic.Bool
	readEntered := make(chan struct{})
	readErrCh := make(chan error, 1)
	go func() {
		close(readEntered)
		for {
			_, rerr := sub.Read()
			if rerr != nil {
				if !closing.Load() && !errors.Is(rerr, os.ErrClosed) {
					continue
				}
				readErrCh <- rerr
				return
			}
		}
	}()

	<-readEntered
	time.Sleep(30 * time.Millisecond)

	startClose := make(chan struct{})
	var readyWG, closeWG sync.WaitGroup
	for i := 0; i < 4; i++ {
		readyWG.Add(1)
		closeWG.Add(1)
		go func() {
			defer closeWG.Done()
			readyWG.Done()
			<-startClose
			if cerr := sub.Close(); cerr != nil {
				t.Errorf("concurrent idempotent Sub.Close() unexpected error: %v", cerr)
			}
		}()
	}
	readyWG.Wait()
	closing.Store(true)
	t0 := time.Now()
	close(startClose)
	closeWG.Wait()

	select {
	case rerr := <-readErrCh:
		elapsed := time.Since(t0)
		if !errors.Is(rerr, os.ErrClosed) {
			t.Fatalf("Sub.Read() after Close() err=%v, want os.ErrClosed", rerr)
		}
		if elapsed >= 2*time.Second {
			t.Fatalf("Sub.Close() took %v to wake blocked Sub.Read(), want < 2s (netpoll wakeup)", elapsed)
		}
		t.Logf("Sub.Close() woke blocked Sub.Read() in %v", elapsed)
	case <-time.After(3 * time.Second):
		t.Fatal("Sub.Read() remained blocked 3s after Sub.Close()")
	}

	if _, rerr := sub.Read(); !errors.Is(rerr, os.ErrClosed) {
		t.Fatalf("subsequent Sub.Read() on closed Sub err=%v, want os.ErrClosed", rerr)
	}
}

func TestRefreshRecoversZeroIfIndex(t *testing.T) {
	m4TestEnv(t)
	src := newScriptedNeighSource(4)
	var ifReady atomic.Bool
	r := newM4GoRunner("wlan2")
	r.subscribeFn = func() (m4NeighSource, error) { return src, nil }
	r.ifIndexFn = func(string) (int, error) {
		if ifReady.Load() {
			return 7, nil
		}
		return 0, errors.New("iface not ready")
	}
	r.dumpIfFn = func(idx int) ([]neigh.Entry, error) {
		if idx <= 0 {
			return nil, errors.New("neigh: bad ifindex")
		}
		return []neigh.Entry{{
			IfIndex: 7,
			IP:      net.IPv4(192, 168, 43, 88),
			MAC:     "02:aa:bb:cc:dd:88",
			State:   neigh.NUDReachable,
		}}, nil
	}
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.blacklistFn = func() map[string]bool { return nil }
	r.hooks.Fast = func(mac string) (string, string) { return "client88", "manual" }
	r.hooks.Full = func(mac, ip string) (string, string) { return "client88", "manual" }
	r.applyHooks()

	r.start()
	t.Cleanup(func() {
		select {
		case <-r.doneCh:
		default:
			close(r.stopCh)
			<-r.doneCh
		}
	})

	<-src.readEntered
	time.Sleep(260 * time.Millisecond)
	ifReady.Store(true)
	if err := os.WriteFile(m4RefreshFile, []byte("recover-ifidx\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if b, err := os.ReadFile(m4RefreshAckFile); err == nil && strings.TrimSpace(string(b)) == "recover-ifidx" {
			devBytes, _ := os.ReadFile(m4DevicesJSON)
			if !strings.Contains(string(devBytes), "02:aa:bb:cc:dd:88") {
				t.Fatalf("refresh ack written before recovering ifIdx=0 device: %s", devBytes)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for recover-ifidx ack")
		}
		time.Sleep(20 * time.Millisecond)
	}
	m4StopRunner(t, r)
}

func TestOnExitStopsM4WriterGracefully(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 11, 21, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)

	m4Writer.tick("wlan0", clk.now)
	m4Writer.mu.Lock()
	r := m4Writer.runner
	m4Writer.mu.Unlock()
	if r == nil {
		t.Fatal("expected m4Writer runner active before onExit")
	}

	onExit()

	select {
	case <-r.doneCh:
	case <-time.After(time.Second):
		t.Fatal("onExit did not stop active m4GoRunner")
	}
	m4Writer.mu.Lock()
	after := m4Writer.runner
	m4Writer.mu.Unlock()
	if after != nil {
		t.Fatalf("expected m4Writer.runner == nil after onExit, got %v", after)
	}
}

func TestWatchdogPendingAndMigrateImmediateM4Tick(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 11, 21, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	rec.probeOut = "lo 192.168.43.1\n"
	withFakeEnv(t, clk, rec)

	var saved wdState
	oldWrite := writeStateFn
	writeStateFn = func(s wdState) { saved = s }
	t.Cleanup(func() { writeStateFn = oldWrite })

	// 1. handlePending -> full_init succeeds -> m4Writer must start on round 1 immediately!
	wait := handlePending(&restoreThrottle{})
	if wait != intervalNormal {
		t.Fatalf("handlePending wait=%v, want %v", wait, intervalNormal)
	}
	if saved.kind != stateActive || saved.iface != "lo" {
		t.Fatalf("saved state=%+v, want ACTIVE:lo", saved)
	}
	m4Writer.mu.Lock()
	r1 := m4Writer.runner
	m4Writer.mu.Unlock()
	if r1 == nil || r1.iface != "lo" {
		t.Fatalf("expected m4Writer started immediately after full_init, got %v", r1)
	}

	// 2. handleActive -> migrate lo -> ap0 -> m4Writer must switch to ap0 immediately!
	rec.probeOut = "ap0 192.168.42.129\n"
	wait2 := handleActive("lo", &restoreThrottle{}, &activeAux{})
	if wait2 != intervalNormal {
		t.Fatalf("handleActive migrate wait=%v, want %v", wait2, intervalNormal)
	}
	select {
	case <-r1.doneCh:
	case <-time.After(time.Second):
		t.Fatal("old m4GoRunner did not stop immediately on migrate")
	}
	m4Writer.mu.Lock()
	r2 := m4Writer.runner
	m4Writer.mu.Unlock()
	if r2 == nil || r2.iface != "ap0" {
		t.Fatalf("expected m4Writer switched to ap0 immediately on migrate, got %v", r2)
	}
}
