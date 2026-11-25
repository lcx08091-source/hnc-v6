package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"hnc.io/dpid/bytestats"
)

const testGuardianLocalSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newGuardianTestEnv(t *testing.T) (*server, http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"data", "run", "etc/dpi_rules.d"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"auth_required":false}`), 0o644)
	s := newServer(dir)
	t.Cleanup(func() {
		s.guardianClose()
		s.CoreHub().Close()
	})
	return s, s.handler(), dir
}

func ensureGuardianTestSecret(t *testing.T, dir string) {
	t.Helper()
	secPath := filepath.Join(dir, "run", "local_admin.secret")
	if _, err := os.Stat(secPath); err != nil {
		if err := os.WriteFile(secPath, []byte(testGuardianLocalSecret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func doGuardianGET(t *testing.T, h http.Handler, dir, path string) (int, map[string]any) {
	t.Helper()
	ensureGuardianTestSecret(t, dir)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "127.0.0.1:43000"
	req.Header.Set("X-HNC-Local-Admin", testGuardianLocalSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("GET %s invalid JSON (%v): %s", path, err, rec.Body.String())
		}
	}
	return rec.Code, out
}

type fakeGuardianBPFSampler struct {
	// 64 位原子字段严格置于 offset 0, 确保通过 TestArm32HttpdPackageZeroWhitelistAlignmentGate
	sampleCalls atomic.Uint64
	closeCalls  atomic.Uint64

	mu   sync.Mutex
	snap *bytestats.NetdDetailSnapshot
	err  error
}

func (f *fakeGuardianBPFSampler) SampleDetail() (*bytestats.NetdDetailSnapshot, error) {
	f.sampleCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if f.snap == nil {
		return &bytestats.NetdDetailSnapshot{ByUID: map[int]bytestats.NetdUIDDetail{}}, nil
	}
	cpByUID := make(map[int]bytestats.NetdUIDDetail, len(f.snap.ByUID))
	for k, v := range f.snap.ByUID {
		cpByUID[k] = v
	}
	cpFg := make(map[int]bool, len(f.snap.ForegroundUIDs))
	for k, v := range f.snap.ForegroundUIDs {
		cpFg[k] = v
	}
	return &bytestats.NetdDetailSnapshot{
		ByUID:             cpByUID,
		ForegroundUIDs:    cpFg,
		HasStatsAB:        f.snap.HasStatsAB,
		HasCounterSetMap:  f.snap.HasCounterSetMap,
		HasIfaceNameMap:   f.snap.HasIfaceNameMap,
		StatsABTotalBytes: f.snap.StatsABTotalBytes,
	}, nil
}

func (f *fakeGuardianBPFSampler) Close() error {
	f.closeCalls.Add(1)
	return nil
}

func (f *fakeGuardianBPFSampler) setSnap(s *bytestats.NetdDetailSnapshot) {
	f.mu.Lock()
	f.snap = s
	f.mu.Unlock()
}

// 1. 验证 guardianHostEngine 所有 64 位原子字段偏移严格 8 字节对齐
func TestHostGuardianAtomic64Alignment(t *testing.T) {
	var z guardianHostEngine
	checks := []struct {
		name   string
		offset uintptr
	}{
		{"leaseUntilMonoNs", unsafe.Offsetof(z.leaseUntilMonoNs)},
		{"lastPowerFetchMono", unsafe.Offsetof(z.lastPowerFetchMono)},
		{"trafficHits", unsafe.Offsetof(z.trafficHits)},
		{"powerHits", unsafe.Offsetof(z.powerHits)},
		{"privacyHits", unsafe.Offsetof(z.privacyHits)},
		{"leaseStarts", unsafe.Offsetof(z.leaseStarts)},
		{"leaseStops", unsafe.Offsetof(z.leaseStops)},
		{"totalRxBpsSnap", unsafe.Offsetof(z.totalRxBpsSnap)},
		{"totalTxBpsSnap", unsafe.Offsetof(z.totalTxBpsSnap)},
		{"lastPrivacyRisky", unsafe.Offsetof(z.lastPrivacyRisky)},
	}
	if checks[0].offset != 0 {
		t.Fatalf("first 64-bit atomic field must sit at offset 0, got %d", checks[0].offset)
	}
	for _, c := range checks {
		if c.offset%8 != 0 {
			t.Fatalf("guardianHostEngine.%s offset=%d violates 8-byte alignment", c.name, c.offset)
		}
	}
	for i := 0; i < 16; i++ {
		_ = new(byte)
		he := newGuardianHostEngine(nil)
		if addr := uintptr(unsafe.Pointer(&he.leaseUntilMonoNs)); addr%8 != 0 {
			t.Fatalf("heap guardianHostEngine address 0x%x not 8-byte aligned", addr)
		}
		he.leaseUntilMonoNs.Store(123456789)
		if got := he.leaseUntilMonoNs.Load(); got != 123456789 {
			t.Fatalf("atomic load = %d, want 123456789", got)
		}
	}
}

// 2. 验证 vector_sync 中 host_guardian 提供者纯无副作用(不创建引擎、不续租、不拉起子进程、不写 run/)
func TestHostGuardianVectorSyncZeroSideEffect(t *testing.T) {
	s, _, dir := newGuardianTestEnv(t)

	snap := s.CoreHub().RefreshSnapshotNow()
	if snap == nil {
		t.Fatal("expected non-nil WorldSnapshot")
	}
	hgRaw, ok := snap.Extensions["host_guardian"]
	if !ok {
		t.Fatal("expected host_guardian provider in WorldSnapshot.Extensions")
	}
	hg, ok := hgRaw.(map[string]any)
	if !ok {
		t.Fatalf("unexpected host_guardian payload type: %T", hgRaw)
	}
	if hg["lease_active"] != false {
		t.Fatalf("expected lease_active=false when idle, got %v", hg["lease_active"])
	}
	// 严禁因 vector_sync 懒实例化引擎
	if guardianPeekEngine(s) != nil {
		t.Fatal("vector_sync must NOT instantiate guardianHostEngine when unused")
	}
	runEntries, _ := os.ReadDir(filepath.Join(dir, "run"))
	if len(runEntries) != 0 {
		t.Fatalf("expected 0 files written to run/ tmpfs, got %d", len(runEntries))
	}
}

// 3. 验证引擎一: 首帧基线 warming_up 防伪网速、2s 帧差分、netstats+BPF 前后台融合、翻转防回退与 8s 租约到期零协程泄漏
func TestLocalAppsTrafficLeaseWarmupHybridAndZeroGoroutineLeak(t *testing.T) {
	s, h, dir := newGuardianTestEnv(t)
	e := s.guardianEngine()

	// 准备零 app_process 的 packages.list 与空 proc/net
	pkgListPath := filepath.Join(dir, "packages.list")
	pkgListContent := strings.Join([]string{
		"com.tencent.mm 10245 0 /data/user/0/com.tencent.mm default:targetSdkVersion=34 3003",
		"com.ss.android.ugc.aweme 10288 0 /data/user/0/com.ss.android.ugc.aweme default:targetSdkVersion=34 3003",
		"com.android.providers.downloads 10055 0 /system/priv-app/DownloadProvider platform:privapp:targetSdkVersion=35 3003",
	}, "\n") + "\n"
	if err := os.WriteFile(pkgListPath, []byte(pkgListContent), 0o644); err != nil {
		t.Fatal(err)
	}
	procDir := filepath.Join(dir, "proc_net")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(procDir, "tcp"), []byte("  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode\n"), 0o644)

	fixedNow := time.Date(2026, 11, 23, 18, 0, 0, 0, time.UTC)
	e.nowFn = func() time.Time { return fixedNow }
	e.packagesListPath = pkgListPath
	e.procNetDir = procDir
	e.leaseTTL = 140 * time.Millisecond
	e.tickInterval = 25 * time.Millisecond

	fakeBPF := &fakeGuardianBPFSampler{}
	// 初始开机已有累计流量(微信 50MB, 抖音 120MB), 以及未归档 stats_map_A/B 基线
	snap0 := &bytestats.NetdDetailSnapshot{
		HasStatsAB:        true,
		HasCounterSetMap:  true,
		HasIfaceNameMap:   true,
		StatsABTotalBytes: 20_000,
		ForegroundUIDs:    map[int]bool{10288: true}, // 抖音在前台, 微信在后台
		ByUID: map[int]bytestats.NetdUIDDetail{
			10245: {
				Total:      bytestats.ByteCounts{RxBytes: 30_000_000, TxBytes: 20_000_000},
				BgAll:      bytestats.ByteCounts{RxBytes: 8_000, TxBytes: 2_000},
				BgMobile:   bytestats.ByteCounts{RxBytes: 8_000, TxBytes: 2_000},
				Foreground: false,
			},
			10288: {
				Total:      bytestats.ByteCounts{RxBytes: 100_000_000, TxBytes: 20_000_000},
				FgAll:      bytestats.ByteCounts{RxBytes: 9_000, TxBytes: 1_000},
				FgWiFi:     bytestats.ByteCounts{RxBytes: 9_000, TxBytes: 1_000},
				Foreground: true,
			},
		},
	}
	fakeBPF.setSnap(snap0)

	var openCalls atomic.Int32
	e.bpfSamplerFactory = func() (guardianBPFSampler, error) {
		openCalls.Add(1)
		return fakeBPF, nil
	}

	var netstatsCalls atomic.Int32
	netstatsBootDocV1 := strings.Join([]string{
		"UID stats:",
		"  History since boot:",
		"  ident=[{type=MOBILE, ratType=COMBINED, subscriberId=460001..., metered=true, subId=1}] uid=10245 set=DEFAULT tag=0x0",
		"    NetworkStatsHistory: bucketDuration=7200",
		"      st=1763913600 rb=20000000 rp=15000 tb=10000000 tp=9000",
		"  ident=[{type=MOBILE, ratType=COMBINED, subscriberId=460001..., metered=true, subId=1}] uid=10245 set=FOREGROUND tag=0x0",
		"    NetworkStatsHistory: bucketDuration=7200",
		"      st=1763913600 rb=5000000 rp=4000 tb=1000000 tp=1200",
		"  ident=[{type=WIFI, wifiNetworkKey=\"HomeWiFi\", metered=false}] uid=10288 set=FOREGROUND tag=0x0",
		"    NetworkStatsHistory: bucketDuration=7200",
		"      st=1763913600 rb=80000000 rp=60000 tb=10000000 tp=8000",
		"  ident=[{type=WIFI, wifiNetworkKey=\"HomeWiFi\", metered=false}] uid=10288 set=DEFAULT tag=0x0",
		"    NetworkStatsHistory: bucketDuration=7200",
		"      st=1763913600 rb=2000000 rp=1500 tb=500000 tp=500",
		"  ident=[{type=MOBILE, metered=true}] uid=10055 set=DEFAULT tag=0x0",
		"    NetworkStatsHistory: bucketDuration=7200",
		"      st=1763913600 rb=9000000 rp=7000 tb=100000 tp=200",
	}, "\n") + "\n"

	var nsMu sync.Mutex
	curBootDoc := netstatsBootDocV1
	fullDoc := strings.Replace(netstatsBootDocV1, "History since boot:", "Complete history:", 1)

	e.netstatsStreamFn = func(_ context.Context, full bool) (io.ReadCloser, error) {
		netstatsCalls.Add(1)
		nsMu.Lock()
		defer nsMu.Unlock()
		if full {
			return io.NopCloser(strings.NewReader(fullDoc)), nil
		}
		return io.NopCloser(strings.NewReader(curBootDoc)), nil
	}

	baseGoroutines := runtime.NumGoroutine()

	// (A) 首次请求: rate_warming_up 必须为 true, 且实时网速严禁拿开机累计值伪造(必须全为 0)!
	code, resp1 := doGuardianGET(t, h, dir, "/api/local_apps/traffic?sort=bg_bytes")
	if code != http.StatusOK || resp1["available"] != true {
		t.Fatalf("unexpected first traffic response: code=%d resp=%v", code, resp1)
	}
	if resp1["rate_warming_up"] != true {
		t.Fatalf("expected rate_warming_up=true on first baseline frame, got %v", resp1["rate_warming_up"])
	}
	apps1 := resp1["apps"].([]any)
	if len(apps1) != 2 {
		// 10055 是 priv-app 系统下载管理器, include_system=0 默认应过滤掉, 仅剩微信+抖音 2 个用户应用
		t.Fatalf("expected 2 non-system apps (WeChat + Douyin), got %d: %v", len(apps1), apps1)
	}
	topBgApp := apps1[0].(map[string]any)
	if int(topBgApp["uid"].(float64)) != 10245 || topBgApp["app_name"] != "微信" {
		t.Fatalf("expected top bg_bytes app to be WeChat (10245), got %v", topBgApp)
	}
	if topBgApp["rx_bps"].(float64) != 0 || topBgApp["tx_bps"].(float64) != 0 {
		t.Fatalf("warming_up frame must report 0 bps (no boot-average faking!), got rx=%v tx=%v", topBgApp["rx_bps"], topBgApp["tx_bps"])
	}
	if topBgApp["current_state"] != "background" {
		t.Fatalf("expected WeChat current_state=background, got %v", topBgApp["current_state"])
	}

	// (B) 推进 BPF 计数器(微信未归档后台增量 +50KB, 总字节增长触发实时网速差分)并等待 1 个采样周期
	snap1 := &bytestats.NetdDetailSnapshot{
		HasStatsAB:        true,
		HasCounterSetMap:  true,
		HasIfaceNameMap:   true,
		StatsABTotalBytes: 80_000,
		ForegroundUIDs:    map[int]bool{10288: true},
		ByUID: map[int]bytestats.NetdUIDDetail{
			10245: {
				Total:      bytestats.ByteCounts{RxBytes: 30_050_000, TxBytes: 20_010_000},
				BgAll:      bytestats.ByteCounts{RxBytes: 58_000, TxBytes: 12_000}, // 较基线 +50000 rx, +10000 tx
				BgMobile:   bytestats.ByteCounts{RxBytes: 58_000, TxBytes: 12_000},
				Foreground: false,
			},
			10288: {
				Total:      bytestats.ByteCounts{RxBytes: 100_200_000, TxBytes: 20_040_000},
				FgAll:      bytestats.ByteCounts{RxBytes: 9_000, TxBytes: 1_000},
				FgWiFi:     bytestats.ByteCounts{RxBytes: 9_000, TxBytes: 1_000},
				Foreground: true,
			},
		},
	}
	fakeBPF.setSnap(snap1)

	waitEngineCond(t, time.Second, "second BPF frame sampled", func() bool {
		return !e.rateWarmingUp.Load()
	})

	// 测 /api/v6/local_apps/traffic 路由别名 + 实时差分速率 + stats_map_A/B 未归档增量合并
	code2, resp2 := doGuardianGET(t, h, dir, "/api/v6/local_apps/traffic?sort=rate")
	if code2 != http.StatusOK || resp2["rate_warming_up"] != false {
		t.Fatalf("expected rate_warming_up=false after tick, got %v", resp2)
	}
	apps2 := resp2["apps"].([]any)
	douyin := apps2[0].(map[string]any)
	wechat := apps2[1].(map[string]any)
	if int(douyin["uid"].(float64)) != 10288 || douyin["current_state"] != "foreground" || douyin["rx_bps"].(float64) <= 0 {
		t.Fatalf("expected Douyin foreground with positive live rx_bps, got %v", douyin)
	}
	// 微信后台累计 = netstats 已归档(20_000_000 + 10_000_000) + BPF stats_map_A/B 未归档(58_000 + 12_000) = 30_070_000
	wantWechatBg := uint64(30_070_000)
	if uint64(wechat["bg_total_bytes"].(float64)) != wantWechatBg {
		t.Fatalf("WeChat hybrid bg_total_bytes = %v, want %d", wechat["bg_total_bytes"], wantWechatBg)
	}

	// (B2) 模拟系统 netstats poll 翻转清空了 BPF stats_map_A/B: 验证立即自动重拉 netstats 且绝不发生累计流量回退!
	nsMu.Lock()
	curBootDoc = strings.Replace(netstatsBootDocV1, "rb=20000000 rp=15000 tb=10000000", "rb=20058000 rp=15100 tb=10012000", 1)
	nsMu.Unlock()
	beforeNsCalls := netstatsCalls.Load()
	snapRotated := &bytestats.NetdDetailSnapshot{
		HasStatsAB:        true,
		HasCounterSetMap:  true,
		HasIfaceNameMap:   true,
		StatsABTotalBytes: 1_000, // 远小于已观测峰值 80_000, 立即触发翻转重拉 netstats
		ForegroundUIDs:    map[int]bool{10288: true},
		ByUID: map[int]bytestats.NetdUIDDetail{
			10245: {
				Total:    bytestats.ByteCounts{RxBytes: 30_059_000, TxBytes: 20_012_000},
				BgAll:    bytestats.ByteCounts{RxBytes: 1_000, TxBytes: 0},
				BgMobile: bytestats.ByteCounts{RxBytes: 1_000, TxBytes: 0},
			},
			10288: snap1.ByUID[10288],
		},
	}
	fakeBPF.setSnap(snapRotated)
	waitEngineCond(t, time.Second, "rotated BPF frame sampled", func() bool {
		e.trafficMu.Lock()
		defer e.trafficMu.Unlock()
		return e.latestBPFSnap != nil && e.latestBPFSnap.StatsABTotalBytes == 1_000
	})
	_, respRot := doGuardianGET(t, h, dir, "/api/local_apps/traffic?sort=bg_bytes")
	if netstatsCalls.Load() <= beforeNsCalls {
		t.Fatalf("expected stats_map_A/B rotation to trigger immediate netstats refresh")
	}
	wxRot := respRot["apps"].([]any)[0].(map[string]any)
	if uint64(wxRot["bg_total_bytes"].(float64)) != 30_071_000 {
		t.Fatalf("bg_total_bytes after rotation = %v, want 30071000", wxRot["bg_total_bytes"])
	}

	// (C) 测试 today + net=wifi + include_system=1
	code3, resp3 := doGuardianGET(t, h, dir, "/api/local_apps/traffic?period=today&net=wifi&include_system=1")
	if code3 != http.StatusOK || resp3["available"] != true || resp3["history_source"] != "netstats_full" {
		t.Fatalf("unexpected today wifi response: %v", resp3)
	}

	// (D) 停止请求, 等待 140ms 租约过期: 验证自动停止 Ticker、关闭 BPF fd、协程完全退出零泄漏!
	waitEngineCond(t, 2*time.Second, "8s short lease auto-stop and BPF fd close", func() bool {
		return !e.leaseRunning.Load() && fakeBPF.closeCalls.Load() >= 1
	})
	time.Sleep(25 * time.Millisecond)
	afterGoroutines := runtime.NumGoroutine()
	if afterGoroutines > baseGoroutines+2 {
		t.Fatalf("goroutine leak after lease expiry: before=%d after=%d", baseGoroutines, afterGoroutines)
	}

	// (E) 验证无权限时诚实返回 available=false + permission_denied, 严禁造假
	e.netstatsMu.Lock()
	e.bootCache = nil
	e.fullCache = nil
	e.netstatsMu.Unlock()
	e.bpfSamplerFactory = func() (guardianBPFSampler, error) {
		return nil, syscall.EACCES
	}
	e.netstatsStreamFn = func(_ context.Context, _ bool) (io.ReadCloser, error) {
		return nil, errors.New("permission_denied: dumpsys netstats denied")
	}
	codePerm, respPerm := doGuardianGET(t, h, dir, "/api/local_apps/traffic")
	if codePerm != http.StatusOK || respPerm["available"] != false || respPerm["reason_code"] != "permission_denied" {
		t.Fatalf("expected honest available=false permission_denied, got %v", respPerm)
	}
}

// 4. 验证引擎二: Android 16 / ColorOS 16 多状态流式解析器(含 History 跳过与 15s 刷新冷却) + Android 12 旧版 Sipper 诚实降级
func TestLocalAppsPowerAndroid16MultiStateAndLegacySipperHonesty(t *testing.T) {
	s, h, dir := newGuardianTestEnv(t)
	e := s.guardianEngine()

	pkgListPath := filepath.Join(dir, "packages.list")
	_ = os.WriteFile(pkgListPath, []byte(strings.Join([]string{
		"com.tencent.mm 10245 0 /data/user/0/com.tencent.mm default:targetSdkVersion=34 3003",
		"com.eg.android.AlipayGphone 10260 0 /data/user/0/com.eg.android.AlipayGphone default:targetSdkVersion=34 3003",
	}, "\n")+"\n"), 0o644)
	e.packagesListPath = pkgListPath

	// 构造含大量 History 行的真实 Android 16 / ColorOS 16 batterystats --charged 输出夹具
	var historyNoise strings.Builder
	historyNoise.WriteString("Battery History (24% used, 128KB):\n")
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&historyNoise, "                    +%ds120ms (2) 095 status=discharging temp=310 volt=4120 +wake_lock\n", i)
	}

	a16Fixture := historyNoise.String() + strings.Join([]string{
		"",
		"Per-PID Stats:",
		"  PID 2104 wake time: +14s200ms",
		"",
		"Statistics since last charge:",
		"  System starts: 0, currently on battery: true",
		"  Estimated battery capacity: 5500 mAh",
		"  Time on battery: 10h 20m 0s 0ms (96.0%) realtime, 3h 10m 0s 0ms (29.4%) uptime",
		"  Time on battery screen off: 7h 50m 0s 0ms (72.8%) realtime, 50m 0s 0ms (7.7%) uptime",
		"  Discharge: 1620 mAh",
		"  Screen off discharge: 340 mAh",
		"  Estimated power use (mAh):",
		"    Capacity: 5500, Computed drain: 1580.5, actual drain: 1560-1640",
		"    Screen: 480.0",
		"    UID u0a245: 185.6 fg: 52.0 bg: 98.4 fgs: 28.2 cached: 7.0 ( cpu=110.0 cpu:fg=35.0 cpu:bg=62.0 cpu:fgs=13.0 wakelock=18.6 wakelock:bg=18.0 mobile_radio=42.0 mobile_radio:fg=12.0 mobile_radio:bg=30.0 wifi=15.0 wifi:fg=5.0 wifi:bg=10.0 )",
		"    UID u0a260: 74.2 fg: 30.0 bg: 38.2 fgs: 6.0 cached: 0.0 ( cpu=48.0 cpu:fg=20.0 cpu:bg=28.0 mobile_radio=20.2 mobile_radio:bg=10.2 )",
		"    UID 1000: 92.0 fg: 12.0 bg: 65.0 fgs: 15.0 cached: 0.0 ( cpu=60.0 cpu:bg=45.0 wakelock=32.0 wakelock:bg=30.0 )",
		"  Estimated power use (mAh) (on battery, screen off/doze):",
		"    Capacity: 5500, Computed drain: 335.0, actual drain: 330-350",
		"    UID u0a245: 84.5 fg: 0.0 bg: 66.5 fgs: 15.0 cached: 3.0 ( cpu=42.0 cpu:bg=40.0 wakelock=16.5 wakelock:bg=16.5 mobile_radio=26.0 mobile_radio:bg=26.0 )",
		"    UID u0a260: 29.0 fg: 0.0 bg: 25.0 fgs: 4.0 cached: 0.0 ( cpu=19.0 cpu:bg=19.0 )",
		"  1000:",
		"    Wake lock ActivityManager-Sleep: 1m 20s 0ms partial (40 times) background: 1m 10s 0ms (36 times) realtime",
		"    Total cpu time: u=2m 0s 0ms s=1m 30s 0ms",
		"  u0a245:",
		"    Mobile network: 45.2MB received, 12.8MB sent; Mobile radio active: 8m 15s 400ms (18.2%) 54x @ 380 mspp",
		"    Wifi Running: 2h 10m 0s 0ms (20.1%)",
		"    Wifi Scan: 25s 100ms (0.1%) 21x background: 19s 0ms (16x)",
		"    Wake lock *job*/com.tencent.mm/.plugin.sync.NotifyService: 6m 10s 200ms partial (62 times) max=15000 background: 5m 50s 100ms (58 times) realtime",
		"    Wake lock MarsPushLock: 3m 20s 300ms partial (48 times) background: 3m 15s 0ms (46 times) realtime",
		"    Wake lock AudioMix: 40s 0ms partial (5 times) realtime",
		"    Wake lock MinorLock4: 5s 0ms partial (2 times) realtime",
		"    TOTAL wake: 9m 50s 500ms partial realtime",
		"    Proc com.tencent.mm:",
		"      CPU: 2m 0s 0ms usr + 1m 0s 0ms krnl ; 2m 10s 0ms fg",
		"    Proc com.tencent.mm:push:",
		"      CPU: 3m 30s 0ms usr + 1m 30s 0ms krnl ; 0ms fg",
		"    Apk com.tencent.mm:",
		"      Wakeups: 49",
		"      Wakeup alarm *walarm*:com.tencent.mm.HEARTBEAT: 31 times",
		"      Wakeup alarm *walarm*:com.tencent.mm.TRAFFIC_GUARD: 18 times",
		"      Job com.tencent.mm/.SyncJob: 2m 05s 100ms (19 times)",
		"  u0a260:",
		"    Mobile radio active: 2m 10s 0ms (4.5%) 19x",
		"    Wake lock AlipayPush: 1m 05s 0ms partial (14 times) background: 1m 00s 0ms (13 times) realtime",
		"    Proc com.eg.android.AlipayGphone:push:",
		"      CPU: 1m 10s 0ms usr + 20s 0ms krnl ; 0ms fg",
		"    Apk com.eg.android.AlipayGphone:",
		"      Wakeups: 12",
		"      Alarm *walarm*:com.eg.android.AlipayGphone.POLL:",
		"        12 times, 450ms (12 wakeups)",
		"      Job com.eg.android.AlipayGphone/.BgJob:",
		"        45s 200ms realtime (7 times)",
		"Statistics since last unplugged:",
		"  UID u0a245: 9999.0 fg: 9999.0 bg: 9999.0",
	}, "\n") + "\n"

	var streamCalls atomic.Int32
	curFixture := a16Fixture
	e.batterystatsStreamFn = func(_ context.Context) (io.ReadCloser, error) {
		streamCalls.Add(1)
		return io.NopCloser(strings.NewReader(curFixture)), nil
	}

	code, resp := doGuardianGET(t, h, dir, "/api/local_apps/power?sort=bg_mah")
	if code != http.StatusOK || resp["available"] != true {
		t.Fatalf("unexpected power response: code=%d resp=%v", code, resp)
	}
	if resp["bg_mah_available"] != true || resp["screen_off_mah_available"] != true || resp["power_model_format"] != "a14_multi_state" {
		t.Fatalf("expected Android 16 multi-state flags, got %v", resp)
	}

	devSum := resp["device_summary"].(map[string]any)
	if devSum["battery_capacity_mah"].(float64) != 5500 ||
		devSum["computed_drain_mah"].(float64) != 1580.5 ||
		devSum["actual_discharge_mah"].(float64) != 1600 ||
		devSum["screen_off_discharge_mah"].(float64) != 340 ||
		int64(devSum["time_on_battery_ms"].(float64)) != (10*3600+20*60)*1000 ||
		int64(devSum["screen_off_on_battery_ms"].(float64)) != (7*3600+50*60)*1000 {
		t.Fatalf("device_summary mismatch: %+v", devSum)
	}

	apps := resp["apps"].([]any)
	if len(apps) != 2 {
		t.Fatalf("expected 2 user apps (excluding UID 1000 by default), got %d", len(apps))
	}
	wx := apps[0].(map[string]any)
	if int(wx["uid"].(float64)) != 10245 ||
		wx["bg_mah"].(float64) != 98.4 ||
		wx["fg_mah"].(float64) != 52.0 ||
		wx["fgs_mah"].(float64) != 28.2 ||
		wx["screen_off_mah"].(float64) != 84.5 {
		t.Fatalf("WeChat multi-state mAh mismatch: %+v", wx)
	}
	bgComps := wx["bg_components_mah"].(map[string]any)
	if bgComps["cpu"].(float64) != 62.0 || bgComps["mobile_radio"].(float64) != 30.0 || bgComps["wakelock"].(float64) != 18.0 {
		t.Fatalf("bg_components_mah mismatch: %+v", bgComps)
	}
	if int64(wx["wakelock_partial_ms"].(float64)) != (9*60+50)*1000+500 ||
		int(wx["wakelock_count"].(float64)) != 117 ||
		int64(wx["mobile_radio_active_ms"].(float64)) != (8*60+15)*1000+400 ||
		int(wx["mobile_radio_wakeup_count"].(float64)) != 54 ||
		int(wx["wifi_bg_scan_count"].(float64)) != 16 ||
		int64(wx["cpu_total_ms"].(float64)) != 8*60*1000 ||
		int64(wx["cpu_fg_ms"].(float64)) != (2*60+10)*1000 ||
		int64(wx["cpu_bg_ms"].(float64)) != (5*60+50)*1000 ||
		int(wx["wakeup_alarms_count"].(float64)) != 49 ||
		int64(wx["bg_jobs_ms"].(float64)) != (2*60+5)*1000+100 ||
		int(wx["bg_jobs_count"].(float64)) != 19 {
		t.Fatalf("WeChat hardware wakeup counters mismatch: %+v", wx)
	}
	topWL := wx["top_wakelocks"].([]any)
	if len(topWL) != 3 || topWL[0].(map[string]any)["name"] != "*job*/com.tencent.mm/.plugin.sync.NotifyService" {
		t.Fatalf("expected colon-bearing top wakelock preserved and capped at top 3, got %+v", topWL)
	}

	// 验证 ?refresh=1 在 15s 冷却期内不重跑子进程且置 refresh_throttled=true
	_, respCool := doGuardianGET(t, h, dir, "/api/local_apps/power?refresh=1&sort=wakelock_ms")
	if respCool["cached"] != true || respCool["refresh_throttled"] != true || streamCalls.Load() != 1 {
		t.Fatalf("expected 15s refresh cooldown throttle (calls=%d), got %v", streamCalls.Load(), respCool)
	}

	// 子测试 2: Android 12 传统 BatterySipper 格式(无 fg:/bg: 拆分)必须诚实置 bg_mah_available=false!
	legacyA12Fixture := strings.Join([]string{
		"Statistics since last charge:",
		"  Time on battery: 4h 0m 0s 0ms (90.0%) realtime",
		"  Screen on: 1h 0m 0s 0ms (25.0%)",
		"  Estimated power use (mAh):",
		"    Capacity: 4500, Computed drain: 620.0, actual drain: 600-640",
		"    Uid u0a245: 55.8 ( cpu=32.0 wake=8.8 radio=15.0 )",
		"    Uid u0a260: 21.4 ( cpu=15.4 wake=6.0 )",
		"  u0a245:",
		"    Wake lock LegacyPushLock: 4m 0s 0ms partial (22 times) realtime",
		"    Total cpu time: u=2m 0s 0ms s=1m 0s 0ms",
	}, "\n") + "\n"

	curFixture = legacyA12Fixture
	e.powerMu.Lock()
	e.powerCache = nil
	e.powerMu.Unlock()

	codeLeg, respLeg := doGuardianGET(t, h, dir, "/api/v6/local_apps/power?sort=bg_mah")
	if codeLeg != http.StatusOK || respLeg["available"] != true {
		t.Fatalf("unexpected legacy power response: %v", respLeg)
	}
	if respLeg["bg_mah_available"] != false || respLeg["bg_mah_reason"] != "rom_uid_power_no_bg_split" {
		t.Fatalf("legacy sipper MUST set bg_mah_available=false and bg_mah_reason=rom_uid_power_no_bg_split, got %v", respLeg)
	}
	// 验证 Screen off time 未直接打印时能由 Time on battery (4h) - Screen on (1h) = 3h 算出
	legSum := respLeg["device_summary"].(map[string]any)
	if int64(legSum["screen_off_on_battery_ms"].(float64)) != 3*3600*1000 {
		t.Fatalf("expected derived screen_off_on_battery_ms=10800000, got %v", legSum["screen_off_on_battery_ms"])
	}
	legApps := respLeg["apps"].([]any)
	legWx := legApps[0].(map[string]any)
	if legWx["total_mah"].(float64) != 55.8 || legWx["bg_mah"].(float64) != 0 ||
		legWx["bg_mah_available"] != false || legWx["bg_mah_reason"] != "rom_uid_power_no_bg_split" {
		t.Fatalf("legacy app row must NOT fake bg_mah from wakelock/cpu ratios! got %+v", legWx)
	}
}

func encodeProcIPv4AddrPort(ipStr string, port int) string {
	addr := netip.MustParseAddr(ipStr).As4()
	v := binary.NativeEndian.Uint32(addr[:])
	return fmt.Sprintf("%08X:%04X", v, port)
}

func encodeProcIPv6MappedAddrPort(ipStr string, port int) string {
	v4 := netip.MustParseAddr(ipStr).As4()
	var b16 [16]byte
	b16[10] = 0xff
	b16[11] = 0xff
	copy(b16[12:16], v4[:])
	var out strings.Builder
	for i := 0; i < 4; i++ {
		w := binary.NativeEndian.Uint32(b16[i*4 : (i+1)*4])
		fmt.Fprintf(&out, "%08X", w)
	}
	fmt.Fprintf(&out, ":%04X", port)
	return out.String()
}

// 5. 验证引擎三: L1 零抓包隐私实时安检(http_cleartext + 系统连通性豁免 + TIME_WAIT 防误报 + dns_direct + tracker_sdk + bg_silent_uplink)
func TestLocalAppsPrivacyAuditL1ZeroCaptureRules(t *testing.T) {
	s, h, dir := newGuardianTestEnv(t)
	e := s.guardianEngine()

	pkgListPath := filepath.Join(dir, "packages.list")
	_ = os.WriteFile(pkgListPath, []byte(strings.Join([]string{
		"com.shady.reader 10301 0 /data/user/0/com.shady.reader default:targetSdkVersion=33 3003",
		"com.video.player 10302 0 /data/user/0/com.video.player default:targetSdkVersion=34 3003",
		"com.fg.browser 10303 0 /data/user/0/com.fg.browser default:targetSdkVersion=34 3003",
	}, "\n")+"\n"), 0o644)
	e.packagesListPath = pkgListPath

	// 写入 DPI 广告规则与 dpi_ipname.json
	_ = os.WriteFile(filepath.Join(dir, "etc", "dpi_rules.d", "80-ads-sdk.json"), []byte(`{
		"schema_version": "2.0",
		"rules": [
			{"id": "appsflyer", "app": "AppsFlyer 统计", "category": "ads", "suffixes": ["appsflyer.com"]},
			{"id": "sensorsdata", "app": "神策数据", "category": "ads", "suffixes": ["sensorsdata.cn"]}
		]
	}`), 0o644)

	_ = os.WriteFile(filepath.Join(dir, "run", "dpi_ipname.json"), []byte(`{
		"entries": {
			"203.0.113.10": {"name": "api.plain-ad.example.com", "src": "dns", "ts": 1763913600},
			"198.51.100.20": {"name": "connectivitycheck.gstatic.com", "src": "dns", "ts": 1763913600},
			"198.51.100.30": {"name": "t.appsflyer.com", "src": "sni", "ts": 1763913600, "category": "ads", "app_name": "AppsFlyer 统计"},
			"203.0.113.88": {"name": "upload.cloud-sync.example.net", "src": "sni", "ts": 1763913600}
		}
	}`), 0o644)

	// 构造真实小端 /proc/net/{tcp,tcp6,udp,udp6}
	procDir := filepath.Join(dir, "proc_net")
	_ = os.MkdirAll(procDir, 0o755)
	e.procNetDir = procDir

	tcpLines := []string{
		"  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode",
		// 1) 10301 明文 HTTP :80 连接 -> 必须检出 http_cleartext
		fmt.Sprintf("   0: %s %s 01 00000000:00000000 00:00000000 00000000 10301        0 10001",
			encodeProcIPv4AddrPort("10.0.0.2", 41001), encodeProcIPv4AddrPort("203.0.113.10", 80)),
		// 2) 系统网络栈 UID 1073 访问 connectivitycheck.gstatic.com:80 -> 必须豁免(即使 include_system=1 也不报)!
		fmt.Sprintf("   1: %s %s 01 00000000:00000000 00:00000000 00000000  1073        0 10002",
			encodeProcIPv4AddrPort("10.0.0.2", 41002), encodeProcIPv4AddrPort("198.51.100.20", 80)),
		// 3) TIME_WAIT (st=06, 内核将 uid 置 0) -> 必须过滤不误报!
		fmt.Sprintf("   2: %s %s 06 00000000:00000000 00:00000000 00000000     0        0 0",
			encodeProcIPv4AddrPort("10.0.0.2", 41003), encodeProcIPv4AddrPort("203.0.113.10", 80)),
		// 4) 前台应用 10303 HTTPS 443 正常浏览 -> 不应误报 bg_silent_uplink
		fmt.Sprintf("   3: %s %s 01 00000000:00000000 00:00000000 00000000 10303        0 10004",
			encodeProcIPv4AddrPort("10.0.0.2", 41004), encodeProcIPv4AddrPort("203.0.113.99", 443)),
	}
	_ = os.WriteFile(filepath.Join(procDir, "tcp"), []byte(strings.Join(tcpLines, "\n")+"\n"), 0o644)

	// 双栈 tcp6 (::ffff:x.x.x.x):
	// 5) 10302 连接 AppsFlyer 追踪器 198.51.100.30:443 -> 必须 Unmap 并检出 tracker_sdk
	// 6) 10302 在后台通过 203.0.113.88:443 静默上传 64KB 数据 -> 必须检出 bg_silent_uplink
	tcp6Lines := []string{
		"  sl  local_address                         rem_address                        st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode",
		fmt.Sprintf("   0: %s %s 01 00000000:00000000 00:00000000 00000000 10302        0 20001",
			encodeProcIPv6MappedAddrPort("10.0.0.2", 52001), encodeProcIPv6MappedAddrPort("198.51.100.30", 443)),
		fmt.Sprintf("   1: %s %s 01 00000800:00000000 00:00000000 00000000 10302        0 20002",
			encodeProcIPv6MappedAddrPort("10.0.0.2", 52002), encodeProcIPv6MappedAddrPort("203.0.113.88", 443)),
	}
	_ = os.WriteFile(filepath.Join(procDir, "tcp6"), []byte(strings.Join(tcp6Lines, "\n")+"\n"), 0o644)

	// udp:
	// 7) 第三方应用 10301 绕过系统 netd 直连 223.5.5.5:53 -> 必须检出 dns_direct
	// 8) 系统 netd (1051) 连 223.5.5.5:53 -> 正常系统解析, 绝不误报!
	// 9) 第三方应用 10301 连 127.0.0.1:53 -> 本地环回, 绝不误报!
	udpLines := []string{
		"  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode ref pointer drops",
		fmt.Sprintf("   0: %s %s 01 00000000:00000000 00:00000000 00000000 10301        0 30001 2 00000000 0",
			encodeProcIPv4AddrPort("10.0.0.2", 53001), encodeProcIPv4AddrPort("223.5.5.5", 53)),
		fmt.Sprintf("   1: %s %s 01 00000000:00000000 00:00000000 00000000  1051        0 30002 2 00000000 0",
			encodeProcIPv4AddrPort("10.0.0.2", 53002), encodeProcIPv4AddrPort("223.5.5.5", 53)),
		fmt.Sprintf("   2: %s %s 01 00000000:00000000 00:00000000 00000000 10301        0 30003 2 00000000 0",
			encodeProcIPv4AddrPort("127.0.0.1", 53003), encodeProcIPv4AddrPort("127.0.0.1", 53)),
	}
	_ = os.WriteFile(filepath.Join(procDir, "udp"), []byte(strings.Join(udpLines, "\n")+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procDir, "udp6"), []byte("  sl  local_address                         rem_address                        st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode ref pointer drops\n"), 0o644)

	// 注入 conntrack 快照供 bg_silent_uplink 字节关联
	ctPath := filepath.Join(dir, "nf_conntrack.mock")
	ctContent := strings.Join([]string{
		"ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.2 dst=203.0.113.88 sport=52002 dport=443 packets=45 bytes=65536 src=203.0.113.88 dst=10.0.0.2 sport=443 dport=52002 packets=30 bytes=12000 [ASSURED] mark=0 use=2",
		"ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.2 dst=203.0.113.99 sport=41004 dport=443 packets=50 bytes=90000 src=203.0.113.99 dst=10.0.0.2 sport=443 dport=41004 packets=80 bytes=200000 [ASSURED] mark=0 use=2",
	}, "\n") + "\n"
	_ = os.WriteFile(ctPath, []byte(ctContent), 0o644)
	t.Setenv("HNC_CONNTRACK_PATH", ctPath)
	ctState.mu.Lock()
	ctState.snap = nil
	ctState.prev = nil
	ctState.mu.Unlock()

	// 仅 10303 在前台; 10301 与 10302 均在后台
	e.fgUIDsFallbackFn = func() (map[int]bool, bool) {
		return map[int]bool{10303: true}, true
	}

	// 开启 include_system=1 同时验证系统 connectivitycheck.gstatic.com:80 依然被豁免!
	code, resp := doGuardianGET(t, h, dir, "/api/local_apps/privacy_audit?include_system=1")
	if code != http.StatusOK || resp["ok"] != true || resp["available"] != true {
		t.Fatalf("unexpected privacy_audit response: code=%d resp=%v", code, resp)
	}
	if resp["self_capture_enabled"] != false || resp["self_capture_mode"] != "off" {
		t.Fatalf("unexpected self_capture status: enabled=%v mode=%v", resp["self_capture_enabled"], resp["self_capture_mode"])
	}

	sum := resp["summary"].(map[string]any)
	if int(sum["cleartext_http_conns"].(float64)) != 1 {
		t.Fatalf("cleartext_http_conns = %v, want 1 (system captive portal & TIME_WAIT must be excluded): findings=%v", sum["cleartext_http_conns"], resp["findings"])
	}
	if int(sum["direct_dns_conns"].(float64)) != 1 {
		t.Fatalf("direct_dns_conns = %v, want 1 (netd & 127.0.0.1:53 must be excluded)", sum["direct_dns_conns"])
	}
	if int(sum["tracker_sdk_conns"].(float64)) != 1 {
		t.Fatalf("tracker_sdk_conns = %v, want 1", sum["tracker_sdk_conns"])
	}
	if int(sum["bg_active_conns"].(float64)) != 1 {
		t.Fatalf("bg_active_conns = %v, want 1 (foreground 10303 must not trigger): findings=%v", sum["bg_active_conns"], resp["findings"])
	}
	if int(sum["risky_apps_count"].(float64)) != 2 {
		t.Fatalf("risky_apps_count = %v, want 2 (UIDs 10301 & 10302)", sum["risky_apps_count"])
	}

	// 验证 /api/v6/local_apps/privacy_audit 别名一致
	codeV6, respV6 := doGuardianGET(t, h, dir, "/api/v6/local_apps/privacy_audit")
	if codeV6 != http.StatusOK || respV6["available"] != true {
		t.Fatalf("v6 privacy_audit alias failed: code=%d resp=%v", codeV6, respV6)
	}
}

func TestRC7GuardianLiveLabelsOrphanTCPFakeIPAndVPNConduitRateDedup(t *testing.T) {
	s, h, dir := newGuardianTestEnv(t)
	e := s.guardianEngine()

	// 1) B004: data/app_labels_live.json 优先于 run/app_labels_live.json, 且缺省回退 run/
	pkgListPath := filepath.Join(dir, "packages.list")
	_ = os.WriteFile(pkgListPath, []byte(strings.Join([]string{
		"com.custom.note 10311 0 /data/user/0/com.custom.note default:targetSdkVersion=34 3003",
		"com.follow.clash 10350 0 /data/user/0/com.follow.clash default:targetSdkVersion=34 3003",
	}, "\n")+"\n"), 0o644)
	e.packagesListPath = pkgListPath

	_ = os.WriteFile(filepath.Join(dir, "run", "app_labels_live.json"), []byte(`{"com.custom.note":"旧版运行态名"}`), 0o644)
	e.pkgLoadedMonoNs = 0
	if mRun := e.resolveAppMeta(10311); mRun.AppName != "旧版运行态名" {
		t.Fatalf("expected fallback to run/app_labels_live.json, got %+v", mRun)
	}
	_ = os.WriteFile(filepath.Join(dir, "data", "app_labels_live.json"), []byte(`{"com.custom.note":"云端笔记","com.follow.clash":"FlClash"}`), 0o644)
	e.pkgLoadedMonoNs = 0
	if mData := e.resolveAppMeta(10311); mData.AppName != "云端笔记" {
		t.Fatalf("expected data/app_labels_live.json priority over run/, got %+v", mData)
	}

	// 2) B026: uid%100000 >= 90000 隔离进程标记为系统组件
	for _, isoUID := range []int{90000, 99015, 99999015} {
		if !guardianIsSystemAppID(isoUID) {
			t.Fatalf("expected isolated UID %d marked as system app ID", isoUID)
		}
		metaIso := e.resolveAppMeta(isoUID)
		if !metaIso.IsSystem || !strings.HasPrefix(metaIso.Package, "isolated:") {
			t.Fatalf("unexpected isolated UID %d meta: %+v", isoUID, metaIso)
		}
	}

	// 3) B004 & B026: 过滤 /proc/net/tcp* 04/05/06/07/0B/0C 下 uid==0 或 inode==0 孤儿行, 且豁免 Fake-IP :53 dns_direct
	procDir := filepath.Join(dir, "proc_net")
	_ = os.MkdirAll(procDir, 0o755)
	e.procNetDir = procDir
	tcpLines := []string{
		"  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode",
		fmt.Sprintf("   0: %s %s 04 00000000:00000000 00:00000000 00000000     0        0 0",
			encodeProcIPv4AddrPort("10.0.0.2", 42001), encodeProcIPv4AddrPort("203.0.113.10", 80)),
		fmt.Sprintf("   1: %s %s 05 00000000:00000000 00:00000000 00000000     0        0 999",
			encodeProcIPv4AddrPort("10.0.0.2", 42002), encodeProcIPv4AddrPort("203.0.113.10", 80)),
		fmt.Sprintf("   2: %s %s 05 00000000:00000000 00:00000000 00000000 10311        0 0",
			encodeProcIPv4AddrPort("10.0.0.2", 42003), encodeProcIPv4AddrPort("203.0.113.10", 80)),
	}
	_ = os.WriteFile(filepath.Join(procDir, "tcp"), []byte(strings.Join(tcpLines, "\n")+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procDir, "tcp6"), []byte("  sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode\n"), 0o644)

	udpLines := []string{
		"  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode ref pointer drops",
		// Fake-IP 198.18.0.2:53 -> 豁免 dns_direct
		fmt.Sprintf("   0: %s %s 01 00000000:00000000 00:00000000 00000000 10311        0 50001 2 00000000 0",
			encodeProcIPv4AddrPort("10.0.0.2", 53101), encodeProcIPv4AddrPort("198.18.0.2", 53)),
		// 真直连 8.8.8.8:53 -> 仍正常报 dns_direct
		fmt.Sprintf("   1: %s %s 01 00000000:00000000 00:00000000 00000000 10311        0 50002 2 00000000 0",
			encodeProcIPv4AddrPort("10.0.0.2", 53102), encodeProcIPv4AddrPort("8.8.8.8", 53)),
	}
	_ = os.WriteFile(filepath.Join(procDir, "udp"), []byte(strings.Join(udpLines, "\n")+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procDir, "udp6"), []byte("  sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ref pointer drops\n"), 0o644)

	socks, ok := guardianScanProcSocketsDir(procDir)
	if !ok || len(socks) != 2 {
		t.Fatalf("expected 3 orphan TCP close rows filtered out leaving only 2 UDP sockets, got %d: %+v", len(socks), socks)
	}

	codePA, respPA := doGuardianGET(t, h, dir, "/api/local_apps/privacy_audit?include_system=1")
	if codePA != http.StatusOK {
		t.Fatalf("privacy_audit failed: %d", codePA)
	}
	paSum := respPA["summary"].(map[string]any)
	if int(paSum["cleartext_http_conns"].(float64)) != 0 {
		t.Fatalf("orphan FIN_WAIT rows must not trigger cleartext_http_conns, got %v", paSum["cleartext_http_conns"])
	}
	if int(paSum["direct_dns_conns"].(float64)) != 1 {
		t.Fatalf("expected Fake-IP 198.18.0.2:53 exempted and 8.8.8.8:53 reported (count=1), got %v", paSum["direct_dns_conns"])
	}

	// 4) B026: VPN 活跃时整机总速率剔除 VPN 导管 UID (com.follow.clash=10350), 防双倍计速
	e.vpnActiveFn = func() bool { return true }
	e.leaseTTL = 200 * time.Millisecond
	e.tickInterval = 20 * time.Millisecond
	fakeBPF := &fakeGuardianBPFSampler{}
	fakeBPF.setSnap(&bytestats.NetdDetailSnapshot{
		ByUID: map[int]bytestats.NetdUIDDetail{
			10311: {Total: bytestats.ByteCounts{RxBytes: 100_000, TxBytes: 50_000}},
			10350: {Total: bytestats.ByteCounts{RxBytes: 100_000, TxBytes: 50_000}},
		},
	})
	e.bpfSamplerFactory = func() (guardianBPFSampler, error) { return fakeBPF, nil }
	e.netstatsStreamFn = func(_ context.Context, _ bool) (io.ReadCloser, error) {
		return nil, errors.New("netstats disabled in unit test")
	}

	_, _ = doGuardianGET(t, h, dir, "/api/local_apps/traffic")
	fakeBPF.setSnap(&bytestats.NetdDetailSnapshot{
		ByUID: map[int]bytestats.NetdUIDDetail{
			10311: {Total: bytestats.ByteCounts{RxBytes: 140_000, TxBytes: 70_000}},
			10350: {Total: bytestats.ByteCounts{RxBytes: 140_000, TxBytes: 70_000}},
		},
	})
	waitEngineCond(t, time.Second, "BPF rate tick with active VPN conduit", func() bool {
		return !e.rateWarmingUp.Load()
	})

	codeTr, respTr := doGuardianGET(t, h, dir, "/api/local_apps/traffic")
	if codeTr != http.StatusOK || respTr["available"] != true {
		t.Fatalf("traffic failed: code=%d resp=%v", codeTr, respTr)
	}
	trApps := respTr["apps"].([]any)
	if len(trApps) != 2 {
		t.Fatalf("expected both app and FlClash rows visible (2), got %d", len(trApps))
	}
	var appRx int64
	for _, raw := range trApps {
		rm := raw.(map[string]any)
		if int(rm["uid"].(float64)) == 10311 {
			appRx = int64(rm["rx_bps"].(float64))
		}
	}
	trSum := respTr["summary"].(map[string]any)
	totRx := int64(trSum["total_rx_bps"].(float64))
	if appRx <= 0 || totRx != appRx || e.totalRxBpsSnap.Load() != appRx {
		t.Fatalf("expected summary total_rx_bps (%d) and snap (%d) to exclude FlClash double count and match appRx (%d)",
			totRx, e.totalRxBpsSnap.Load(), appRx)
	}
}
