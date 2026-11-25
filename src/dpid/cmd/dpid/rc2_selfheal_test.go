package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"hnc.io/dpid/activity"
	"hnc.io/dpid/capture"
	"hnc.io/dpid/leakguard"
	"hnc.io/dpid/output"
	"hnc.io/dpid/probe"
)

type fakeCaptureHandle struct {
	mu      sync.Mutex
	iface   string
	ifindex int
	stats   capture.Stats
	rebound chan string
	runFn   func(ctx context.Context, onEvent func(capture.Event)) error
}

func (f *fakeCaptureHandle) Run(ctx context.Context, onEvent func(capture.Event)) error {
	if f.runFn != nil {
		return f.runFn(ctx, onEvent)
	}
	<-ctx.Done()
	return nil
}

func (f *fakeCaptureHandle) Close() {}

func (f *fakeCaptureHandle) Iface() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.iface
}

func (f *fakeCaptureHandle) CurrentIfindex() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ifindex
}

func (f *fakeCaptureHandle) Stats() capture.Stats {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats
}

func (f *fakeCaptureHandle) Rebind(newIface string) error {
	var newIdx int
	if ifc, err := ifaceByNameFn(newIface); err == nil && ifc != nil {
		newIdx = ifc.Index
	}
	f.mu.Lock()
	f.iface = newIface
	if newIdx > 0 {
		f.ifindex = newIdx
	}
	if f.rebound != nil {
		select {
		case f.rebound <- newIface:
		default:
		}
	}
	f.mu.Unlock()
	return nil
}

func TestCanCaptureDecouplesColdStartStandbyFromTrueBlind(t *testing.T) {
	if canCapture(Config{DisableCapture: true}, probe.Result{AFPacketAvailable: true, APIface: "wlan2"}) {
		t.Fatal("DisableCapture=true must NOT enter capture")
	}
	if canCapture(Config{}, probe.Result{AFPacketAvailable: false, AFPacketError: "EPERM"}) {
		t.Fatal("AFPacketAvailable=false must NOT enter capture")
	}
	// Cold boot with hotspot off (APIface == "") but AF_PACKET available MUST enter runCapture standby!
	if !canCapture(Config{}, probe.Result{AFPacketAvailable: true, APIface: ""}) {
		t.Fatal("cold-start empty APIface with AFPacketAvailable=true MUST enter runCapture standby")
	}
}

func TestRunCapture_ColdStartStandbyMillisecondWakeAndBandSwitch(t *testing.T) {
	oldOpen := openCaptureFn
	oldNets := ifaceNetsFn
	oldByName := ifaceByNameFn
	oldDiscover := discoverAPFn
	oldAct := actReader
	t.Cleanup(func() {
		openCaptureFn = oldOpen
		ifaceNetsFn = oldNets
		ifaceByNameFn = oldByName
		discoverAPFn = oldDiscover
		actReader = oldAct
		capture.SetHotspotNets(nil)
		capture.SetLocalMACs(nil)
	})

	root := t.TempDir()
	runDir := filepath.Join(root, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	actReader = activity.NewReader(runDir)

	discoverAPFn = func() ([]capture.IfaceCandidate, error) { return nil, nil }
	ifaceByNameFn = func(name string) (*net.Interface, error) {
		if name == "ap0" {
			return &net.Interface{
				Index:        12,
				Name:         "ap0",
				Flags:        net.FlagUp,
				HardwareAddr: net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
			}, nil
		}
		return nil, syscall.ENODEV
	}
	_, subnetAP0, _ := net.ParseCIDR("192.168.177.0/24")
	ifaceNetsFn = func(name string) []*net.IPNet {
		if name == "ap0" {
			return []*net.IPNet{subnetAP0}
		}
		return nil
	}

	openedCh := make(chan string, 4)
	openCaptureFn = func(opts capture.Options) (captureRunner, error) {
		if opts.Iface != "ap0" {
			return nil, fmt.Errorf("lookup iface %s: %w", opts.Iface, syscall.ENODEV)
		}
		openedCh <- opts.Iface
		return &fakeCaptureHandle{iface: "ap0", ifindex: 12}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wakeCaptureCh := make(chan struct{}, 1)
	wakeAll := func() {
		select {
		case wakeCaptureCh <- struct{}{}:
		default:
		}
	}
	startHotspotHintInotify(ctx, runDir, wakeAll)

	// Start with APIface == "" (cold boot hotspot off) and stale cfg.Iface = "wlan2".
	cfg := Config{RunDir: runDir, Iface: "wlan2", Snaplen: 1024}
	pr := probe.Result{AFPacketAvailable: true, APIface: ""}
	sw := output.NewWriter(filepath.Join(runDir, "dpi_state.json"), "test")
	devID := output.NewDeviceIdentifier()
	ipNames := output.NewIPNameTable()
	lg := leakguard.NewEngine(runDir)
	defer lg.Close()
	shmTr := newSHMRuntimeTracker()

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- runCapture(ctx, cfg, pr, sw, devID, ipNames, lg, shmTr, wakeCaptureCh, wakeAll)
	}()

	// Let runCapture enter backoff sleep on dead wlan2 (retry would normally be 2s+).
	time.Sleep(60 * time.Millisecond)

	// Hotspot turns on at 5GHz band with new interface "ap0": write fresh iface_detect.json and wake.
	wakeStart := time.Now()
	detectBody := fmt.Sprintf(`{"schema":1,"ts":%d,"iface":"ap0"}`, time.Now().Unix())
	if err := atomicWriteString(filepath.Join(runDir, "iface_detect.json"), detectBody); err != nil {
		t.Fatal(err)
	}
	wakeAll()

	select {
	case gotIface := <-openedCh:
		if gotIface != "ap0" {
			t.Fatalf("expected self-healed open on ap0, got %q", gotIface)
		}
		if elapsed := time.Since(wakeStart); elapsed > 600*time.Millisecond {
			t.Fatalf("expected millisecond wakeup, took %v", elapsed)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("runCapture failed to wake up and switch from dead wlan2 to ap0")
	}

	cancel()
	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("runCapture returned unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runCapture did not exit cleanly on cancel")
	}
}

func TestRebindCheckLoop_HotSwapsRandomizedSubnetAndIfindex(t *testing.T) {
	oldNets := ifaceNetsFn
	oldByName := ifaceByNameFn
	oldDiscover := discoverAPFn
	oldTick := rebindCheckTickEvery
	t.Cleanup(func() {
		ifaceNetsFn = oldNets
		ifaceByNameFn = oldByName
		discoverAPFn = oldDiscover
		rebindCheckTickEvery = oldTick
		capture.SetHotspotNets(nil)
		capture.SetLocalMACs(nil)
	})

	rebindCheckTickEvery = 20 * time.Millisecond
	discoverAPFn = func() ([]capture.IfaceCandidate, error) { return nil, nil }

	var mu sync.Mutex
	curIfindex := 10
	_, net1, _ := net.ParseCIDR("192.168.43.0/24")
	_, net2, _ := net.ParseCIDR("192.168.211.0/24")
	curSubnet := net1
	subnetRefreshes := 0

	ifaceByNameFn = func(name string) (*net.Interface, error) {
		mu.Lock()
		idx := curIfindex
		mu.Unlock()
		return &net.Interface{
			Index:        idx,
			Name:         name,
			Flags:        net.FlagUp,
			HardwareAddr: net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		}, nil
	}
	ifaceNetsFn = func(name string) []*net.IPNet {
		mu.Lock()
		n := curSubnet
		subnetRefreshes++
		mu.Unlock()
		return []*net.IPNet{n}
	}

	runDir := t.TempDir()
	detectBody := fmt.Sprintf(`{"schema":1,"ts":%d,"iface":"wlan2"}`, time.Now().Unix())
	if err := os.WriteFile(filepath.Join(runDir, "iface_detect.json"), []byte(detectBody), 0o644); err != nil {
		t.Fatal(err)
	}

	reboundCh := make(chan string, 4)
	fh := &fakeCaptureHandle{
		iface:   "wlan2",
		ifindex: 10,
		stats:   capture.Stats{Packets: 5},
		rebound: reboundCh,
	}
	refreshHotspotContext("wlan2")

	ctx, cancel := context.WithCancel(context.Background())
	sw := output.NewWriter(filepath.Join(runDir, "dpi_state.json"), "test")
	var rebindCount atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		rebindCheckLoop(ctx, fh, Config{RunDir: runDir}, probe.Result{AFPacketAvailable: true}, sw, &rebindCount)
	}()
	stopLoop := sync.OnceFunc(func() {
		cancel()
		<-done
	})
	t.Cleanup(stopLoop)

	// Step 1: Same interface & same ifindex, Android IpServer assigns new randomized subnet 192.168.211.0/24.
	mu.Lock()
	curSubnet = net2
	mu.Unlock()
	time.Sleep(80 * time.Millisecond)

	// Step 2: Same interface recreated with new ifindex 15 -> triggers Rebind + context refresh.
	mu.Lock()
	curIfindex = 15
	mu.Unlock()

	select {
	case rbIface := <-reboundCh:
		if rbIface != "wlan2" {
			t.Fatalf("unexpected rebound iface: %q", rbIface)
		}
	case <-time.After(time.Second):
		t.Fatal("expected Rebind when ifindex changed on wlan2")
	}

	// Stop background rebindCheckLoop completely before assertions & TempDir cleanup.
	stopLoop()

	if gotIdx := fh.CurrentIfindex(); gotIdx != 15 {
		t.Fatalf("expected fakeCaptureHandle ifindex updated to 15, got %d", gotIdx)
	}
	if gotCnt := rebindCount.Load(); gotCnt != 1 {
		t.Fatalf("expected rebindCount=1 after ifindex update, got %d", gotCnt)
	}

	mu.Lock()
	refreshes := subnetRefreshes
	mu.Unlock()
	if refreshes < 3 {
		t.Fatalf("expected repeated subnet probes/refreshes, got %d", refreshes)
	}
}

func TestHotspotOffStandby_IgnoresActivityHeartbeatAndPreservesBackoff(t *testing.T) {
	oldAct := actReader
	t.Cleanup(func() { actReader = oldAct })

	runDir := t.TempDir()
	actReader = activity.NewReader(runDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wakeCh := make(chan struct{}, 4)
	startHotspotHintInotify(ctx, runDir, func() {
		select {
		case wakeCh <- struct{}{}:
		default:
		}
	})
	// Give inotify watch a brief moment to arm.
	time.Sleep(20 * time.Millisecond)

	// 1. Hotspot OFF heartbeat / screen toggle atomic write (IN_MOVED_TO) must NOT wake standby.
	offBody := fmt.Sprintf(`{"ts":%d,"level":"hotspot_off","screen_on":true,"screen_known":true,"hotspot_active":false,"clients_online":0,"webui_active":false}`, time.Now().Unix())
	if err := atomicWriteString(filepath.Join(runDir, activity.FileName), offBody); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wakeCh:
		t.Fatal("hotspot_off activity.json write must NOT trigger wakeCaptureCh")
	case <-time.After(80 * time.Millisecond):
	}
	if isHotspotActiveOrUnknown(runDir) {
		t.Fatal("expected isHotspotActiveOrUnknown=false when hotspot is explicitly off")
	}

	// 2. Rapid hotspot ON (<5s reader cache TTL) atomic write MUST wake immediately and allow retry reset.
	onBody := fmt.Sprintf(`{"ts":%d,"level":"active","screen_on":true,"screen_known":true,"hotspot_active":true,"clients_online":1,"webui_active":false}`, time.Now().Unix())
	if err := atomicWriteString(filepath.Join(runDir, activity.FileName), onBody); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wakeCh:
	case <-time.After(600 * time.Millisecond):
		t.Fatal("hotspot_active=true activity.json write failed to wake standby within 600ms")
	}
	if !isHotspotActiveOrUnknown(runDir) {
		t.Fatal("expected isHotspotActiveOrUnknown=true immediately after hotspot turns on")
	}
}

func TestInitHistoryStorage_MovesOutOfTmpfsRunDir(t *testing.T) {
	oldHistDir := output.HistoryDir
	t.Cleanup(func() { output.HistoryDir = oldHistDir })

	hncDir := t.TempDir()
	runDir := filepath.Join(hncDir, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	legacyFile := filepath.Join(runDir, "stats.20261122.jsonl")
	row := `{"t":1763800000,"mac":"aa:bb:cc:dd:ee:ff","app_id":"wechat","tx":512,"rx":1024}` + "\n"
	if err := os.WriteFile(legacyFile, []byte(row), 0o644); err != nil {
		t.Fatal(err)
	}

	gotDir := initHistoryStorage(runDir)
	wantDir := filepath.Join(hncDir, "data", "dpi_history")
	if gotDir != wantDir || output.HistoryDir != wantDir {
		t.Fatalf("HistoryDir = %q (ret %q), want %q", output.HistoryDir, gotDir, wantDir)
	}
	if _, err := os.Stat(legacyFile); !os.IsNotExist(err) {
		t.Fatalf("legacy stats file still exists in run/: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(wantDir, "stats.20261122.jsonl"))
	if err != nil || strings.TrimSpace(string(b)) != strings.TrimSpace(row) {
		t.Fatalf("migrated file content mismatch: err=%v body=%q", err, string(b))
	}
}

func TestRunCapture_HotspotOffDeadIfaceSilentStandbyNoOpenWarn(t *testing.T) {
	oldOpen := openCaptureFn
	oldByName := ifaceByNameFn
	oldDiscover := discoverAPFn
	oldAct := actReader
	t.Cleanup(func() {
		openCaptureFn = oldOpen
		ifaceByNameFn = oldByName
		discoverAPFn = oldDiscover
		actReader = oldAct
		capture.SetHotspotNets(nil)
		capture.SetLocalMACs(nil)
	})

	runDir := t.TempDir()
	actReader = activity.NewReader(runDir)
	// Explicitly write hotspot_active=false + stale hotspot_iface="wlan2".
	offBody := fmt.Sprintf(`{"ts":%d,"level":"hotspot_off","screen_on":false,"screen_known":true,"hotspot_active":false,"clients_online":0,"webui_active":false}`, time.Now().Unix())
	if err := os.WriteFile(filepath.Join(runDir, activity.FileName), []byte(offBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "hotspot_iface"), []byte("wlan2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	discoverAPFn = func() ([]capture.IfaceCandidate, error) { return nil, nil }
	ifaceByNameFn = func(name string) (*net.Interface, error) { return nil, syscall.ENODEV }

	var openAttempts atomic.Int32
	openCaptureFn = func(opts capture.Options) (captureRunner, error) {
		openAttempts.Add(1)
		return nil, syscall.ENODEV
	}

	ctx, cancel := context.WithCancel(context.Background())
	wakeCh := make(chan struct{}, 1)
	sw := output.NewWriter(filepath.Join(runDir, "dpi_state.json"), "test")
	devID := output.NewDeviceIdentifier()
	ipNames := output.NewIPNameTable()
	lg := leakguard.NewEngine(runDir)
	defer lg.Close()
	shmTr := newSHMRuntimeTracker()

	done := make(chan error, 1)
	go func() {
		done <- runCapture(ctx, Config{RunDir: runDir, Iface: "wlan2", Snaplen: 1024}, probe.Result{AFPacketAvailable: true}, sw, devID, ipNames, lg, shmTr, wakeCh, nil)
	}()

	time.Sleep(80 * time.Millisecond)
	cancel()
	<-done

	if got := openAttempts.Load(); got != 0 {
		t.Fatalf("hotspot explicitly off + dead wlan2 must enter silent standby without openCaptureFn WARN spam, got %d open attempts", got)
	}
}
