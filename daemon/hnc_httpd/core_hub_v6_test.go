// core_hub_v6_test.go — HNC v6.0.0 · Vector: 四舱壁中枢、无锁 WorldSnapshot、JSONv2 编解码器与后台黑洞修复单测
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func setupTestV6Server(t *testing.T) (*server, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	nowStr := `{"aa:bb:cc:00:00:01":{"ip":"192.168.43.20","hostname":"Pixel-9","rx_bytes":2048,"tx_bytes":1024}}`
	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"), []byte(nowStr), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"devices":{"aa:bb:cc:00:00:01":{"limit_enabled":true,"down_mbps":50,"up_mbps":20}},"blacklist":[]}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)
	s := newServer(dir)
	t.Cleanup(func() {
		s.CoreHub().Close()
	})
	return s, dir
}

func TestWorldSnapshotLockFreeAndProviderHook(t *testing.T) {
	s, _ := setupTestV6Server(t)

	RegisterVectorSyncProvider("thermo_cruise", func() any {
		return map[string]any{
			"temp_c":    38.5,
			"throttled": false,
		}
	})
	RegisterVectorSyncProvider("faulty_mod", func() any {
		panic("simulated extension panic")
	})
	t.Cleanup(func() {
		UnregisterVectorSyncProvider("thermo_cruise")
		UnregisterVectorSyncProvider("faulty_mod")
	})

	hub := s.CoreHub()
	snap := hub.RefreshSnapshotNow()
	if snap == nil || !snap.OK || !snap.Healthy {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	if len(snap.Bulkheads) != 4 {
		t.Fatalf("want 4 bulkheads, got %d", len(snap.Bulkheads))
	}
	for _, k := range []string{"dataplane", "dpi_shm", "android_bridge", "storage"} {
		bh, ok := snap.Bulkheads[k]
		if !ok || !bh.Healthy || bh.CircuitState != "closed" {
			t.Fatalf("bulkhead %s unhealthy: %+v", k, bh)
		}
	}
	if snap.Live.Total != 1 || snap.Live.Online != 1 || snap.Live.HotspotIface != "wlan2" {
		t.Fatalf("live summary mismatch: %+v", snap.Live)
	}

	// 验证 panic 的 provider 被隔离罩兜住, 不影响正常 provider 与 HTTP 响应
	if _, ok := snap.Extensions["thermo_cruise"]; !ok {
		t.Fatalf("missing registered provider thermo_cruise: %+v", snap.Extensions)
	}
	fm, _ := snap.Extensions["faulty_mod"].(map[string]any)
	if fm == nil || fm["ok"] != false {
		t.Fatalf("expected isolated panic record for faulty_mod, got %+v", snap.Extensions["faulty_mod"])
	}

	// 验证 GET /api/vector_sync 走无锁快照直出
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/vector_sync", nil)
	s.apiVectorSync(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("apiVectorSync status=%d body=%s", rr.Code, rr.Body.String())
	}
	var decoded map[string]any
	if err := UnmarshalJSONv2(rr.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("UnmarshalJSONv2 failed: %v", err)
	}
	if decoded["ok"] != true {
		t.Fatalf("expected ok=true, got %+v", decoded)
	}
	exts, _ := decoded["extensions"].(map[string]any)
	if exts == nil || exts["thermo_cruise"] == nil {
		t.Fatalf("missing extensions.thermo_cruise in HTTP payload: %s", rr.Body.String())
	}
}

func TestWorldSnapshotConcurrentReadWriteRaceFree(t *testing.T) {
	s, _ := setupTestV6Server(t)
	hub := s.CoreHub()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// 写侧模拟高频推进快照
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			select {
			case <-stop:
				return
			default:
				hub.RefreshSnapshotNow()
			}
		}
	}()

	// 8 个并发读协程无锁高频 Load()
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				sn := hub.Snapshot()
				if sn == nil || !sn.OK || len(sn.Bulkheads) != 4 {
					t.Errorf("corrupted snapshot read: %+v", sn)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
}

func TestBulkheadCircuitBreakerTripAndHalfOpenRecovery(t *testing.T) {
	var fakeMono atomic.Int64
	fakeMono.Store(int64(10 * time.Second))
	oldMono := monoNowFn
	monoNowFn = fakeMono.Load
	t.Cleanup(func() { monoNowFn = oldMono })

	bh := NewBulkhead(BulkheadConfig{
		Name:             "android_bridge_test",
		QueueSize:        8,
		DefaultTimeout:   40 * time.Millisecond,
		TripThreshold:    2,
		CooldownDuration: 45 * time.Second,
	})
	t.Cleanup(bh.Close)

	slowTask := func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}

	// 第 1 次超时: 尚未触发熔断(1/2)
	if err := bh.Execute(context.Background(), 35*time.Millisecond, slowTask); !errors.Is(err, ErrBulkheadTimeout) {
		t.Fatalf("1st timeout want ErrBulkheadTimeout, got %v", err)
	}
	if st := bh.CircuitState(); st != "closed" {
		t.Fatalf("after 1 timeout circuit should stay closed, got %q", st)
	}

	// 第 2 次连续超时: 自动熔断退避 45s!
	if err := bh.Execute(context.Background(), 35*time.Millisecond, slowTask); !errors.Is(err, ErrBulkheadTimeout) {
		t.Fatalf("2nd timeout want ErrBulkheadTimeout, got %v", err)
	}
	if st := bh.CircuitState(); st != "open" {
		t.Fatalf("after 2 consecutive timeouts circuit should be open, got %q", st)
	}

	// 熔断开启期间: 后续调用立即快速失败(< 5ms), 绝不阻塞等待
	t0 := time.Now()
	if err := bh.Execute(context.Background(), 2*time.Second, func(ctx context.Context) error {
		return nil
	}); !errors.Is(err, ErrBulkheadCircuitOpen) {
		t.Fatalf("expected ErrBulkheadCircuitOpen while open, got %v", err)
	}
	if took := time.Since(t0); took > 50*time.Millisecond {
		t.Fatalf("open circuit should fail fast, took %v", took)
	}

	// 推进单调时钟跨过 45s 退避期 → 进入 half_open
	fakeMono.Add(int64(46 * time.Second))
	if st := bh.CircuitState(); st != "half_open" {
		t.Fatalf("after 45s cooldown want half_open, got %q", st)
	}

	// 半开探测成功 → 自动恢复为 closed
	if err := bh.Execute(context.Background(), 200*time.Millisecond, func(ctx context.Context) error {
		return nil
	}); err != nil {
		t.Fatalf("half-open probe failed: %v", err)
	}
	if st := bh.CircuitState(); st != "closed" {
		t.Fatalf("expected circuit closed after successful probe, got %q", st)
	}
}

func TestBulkheadPanicIsolationAndQueueFull(t *testing.T) {
	bh := NewBulkhead(BulkheadConfig{
		Name:           "panic_test",
		QueueSize:      2,
		DefaultTimeout: 500 * time.Millisecond,
	})
	t.Cleanup(bh.Close)

	err := bh.Execute(context.Background(), 200*time.Millisecond, func(ctx context.Context) error {
		panic("boom inside bulkhead")
	})
	if !errors.Is(err, ErrBulkheadPanic) {
		t.Fatalf("expected ErrBulkheadPanic, got %v", err)
	}
	// Panic 后舱壁依然存活, 后续任务正常执行
	if err := bh.Execute(context.Background(), 200*time.Millisecond, func(ctx context.Context) error {
		return nil
	}); err != nil {
		t.Fatalf("bulkhead should remain alive after panic, got %v", err)
	}
	if h := bh.Health(); h.Panics != 1 || h.Completed != 1 {
		t.Fatalf("unexpected bulkhead counters: %+v", h)
	}
}

func TestExecIsolatedAndroidCmdKillsProcessGroupOnTimeout(t *testing.T) {
	t0 := time.Now()
	// 子进程拉起持有管道的后台孙进程 sleep 30: 若无进程组 SIGKILL + WaitDelay 会卡满 30s
	_, err := ExecIsolatedAndroidCmd(context.Background(), 80*time.Millisecond, "sh", "-c", "sleep 30 & sleep 30")
	took := time.Since(t0)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	if took > 2*time.Second {
		t.Fatalf("ExecIsolatedAndroidCmd hung on grandchild for %v (want < 2s)", took)
	}

	// 验证禁止直接调 ps / pidof
	if _, err := ExecIsolatedAndroidCmd(context.Background(), time.Second, "ps", "-ef"); err == nil {
		t.Fatal("expected ps to be rejected by ExecIsolatedAndroidCmd")
	}
}

func TestJSONv2CodecAndDiagDumpEndpoint(t *testing.T) {
	s, _ := setupTestV6Server(t)

	// 验证空切片编码为 [] 而非 null, 且非法 UTF-8 字节不会导致 500 崩溃
	payload := struct {
		Name  string   `json:"name"`
		Items []string `json:"items"`
	}{
		Name:  "BadUTF8-\xff-Host",
		Items: nil,
	}
	rr := httptest.NewRecorder()
	WriteJSONv2(rr, http.StatusOK, &payload)
	if rr.Code != http.StatusOK {
		t.Fatalf("WriteJSONv2 status=%d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"items":[]`) {
		t.Fatalf("expected nil slice formatted as [], got %s", body)
	}

	// 验证流式键值提取器 ExtractJSONStringsStream
	streamRaw := `{"outer":{"meta":"x","imei":"861234567890123","phone":"13800138000"},"tail":true}`
	extracted := ExtractJSONStringsStream(strings.NewReader(streamRaw), 4096, map[string]bool{
		"imei":  true,
		"phone": true,
	})
	if extracted["imei"] != "861234567890123" || extracted["phone"] != "13800138000" {
		t.Fatalf("stream extraction mismatch: %+v", extracted)
	}

	// 验证 GET /api/v6/diag_dump 输出人类可读带缩进 JSON
	rrDiag := httptest.NewRecorder()
	s.apiCoreDiagDump(rrDiag, httptest.NewRequest(http.MethodGet, "/api/v6/diag_dump", nil))
	if rrDiag.Code != http.StatusOK {
		t.Fatalf("diag_dump status=%d body=%s", rrDiag.Code, rrDiag.Body.String())
	}
	diagStr := rrDiag.Body.String()
	if !strings.Contains(diagStr, "\n  \"ok\": true") || !strings.Contains(diagStr, "\"plaintext_configs\"") {
		t.Fatalf("diag_dump should be multiline human-readable JSON, got:\n%s", diagStr)
	}
	var parsed map[string]any
	if err := json.Unmarshal(rrDiag.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("diag_dump must be valid standard JSON: %v", err)
	}
}

func TestSignalMonitorNeverBlocksHTTPThread(t *testing.T) {
	s, _ := setupTestV6Server(t)
	blockCh := make(chan struct{})
	var sampleCalls atomic.Int32
	s.signalCtl.sampleFn = func(_ *server) hostSignalStatus {
		sampleCalls.Add(1)
		<-blockCh
		return hostSignalStatus{
			Available:       true,
			Mode:            "cellular",
			RAT:             "5G SA",
			RSRPdBm:         -86,
			SINRdB:          20,
			Bars:            4,
			Quality:         "excellent",
			QualityCN:       "5G 极佳",
			RFCeilingFactor: 1.0,
		}
	}

	// 即使底层采样卡住, Get() / apiSignal 必须在毫秒内立即返回初始缓存态!
	t0 := time.Now()
	rr := httptest.NewRecorder()
	s.apiSignal(rr, httptest.NewRequest(http.MethodGet, "/api/signal", nil))
	if took := time.Since(t0); took > 50*time.Millisecond {
		t.Fatalf("apiSignal blocked HTTP thread for %v", took)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("apiSignal code=%d", rr.Code)
	}

	// 放行后台异步采样并验证下一次读取拿到最新 5G SA 快照
	close(blockCh)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		st := s.signalCtl.Get(s)
		if st.Available && st.RAT == "5G SA" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("background signal refresh did not update cache (calls=%d)", sampleCalls.Load())
}

func TestLimitPolicyNotificationOutsideActionLock(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"devices":{},"blacklist":[]}`), 0o644)

	var actionMu sync.Mutex
	c := newLimitCtl(dir, &actionMu)
	c.apply = func(mac string, from, to limitRule) error { return nil }

	notifyEntered := make(chan struct{}, 1)
	releaseNotify := make(chan struct{})
	var notifyWG sync.WaitGroup
	notifyWG.Add(1)
	restoreExec := setQuotaNotifyExecFn(func(ctx context.Context, title, body string) error {
		defer notifyWG.Done()
		// 通知触发时如果 actionMu 仍被 tick 持有, 这里 TryLock 会失败(证明死锁风险)!
		if !actionMu.TryLock() {
			t.Errorf("CRITICAL: actionMu is STILL HELD while quota notification executes!")
		} else {
			actionMu.Unlock()
		}
		select {
		case notifyEntered <- struct{}{}:
		default:
		}
		select {
		case <-releaseNotify:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	t.Cleanup(func() {
		close(releaseNotify)
		notifyWG.Wait()
		restoreExec()
	})

	mac := "aa:bb:cc:dd:ee:99"
	_ = c.actionQuotaSet(map[string]string{"mac": mac, "daily_gb": "1", "action": "throttle"})
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.Local)

	devBytes, _ := json.Marshal(map[string]any{mac: map[string]any{"ip": "192.168.43.55", "rx_bytes": int64(0), "tx_bytes": int64(0)}})
	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"), devBytes, 0o644)
	c.tick(now)

	// 超出 1GB 配额 → 触发异步通知, tick 必须立即返回且释放 actionMu
	devBytes2, _ := json.Marshal(map[string]any{mac: map[string]any{"ip": "192.168.43.55", "rx_bytes": int64(2 << 30), "tx_bytes": int64(0)}})
	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"), devBytes2, 0o644)

	t0 := time.Now()
	c.tick(now.Add(time.Minute))
	if took := time.Since(t0); took > 200*time.Millisecond {
		t.Fatalf("c.tick blocked on slow notification for %v", took)
	}
	if !actionMu.TryLock() {
		t.Fatal("actionMu still locked after c.tick returned")
	}
	actionMu.Unlock()

	select {
	case <-notifyEntered:
	case <-time.After(time.Second):
		t.Fatal("expected async quota notification to be invoked")
	}
}

func TestConntrackAdaptiveTTL4sAnd8s(t *testing.T) {
	oldTouch := ctPanelTouchMonoNs.Load()
	t.Cleanup(func() { ctPanelTouchMonoNs.Store(oldTouch) })
	nowMono := int64(100 * time.Second)
	ctPanelTouchMonoNs.Store(0)
	if got := conntrackEffectiveTTL(nowMono); got != 8*time.Second {
		t.Fatalf("without panel open want 8s TTL, got %v", got)
	}
	ctPanelTouchMonoNs.Store(nowMono - int64(5*time.Second))
	if got := conntrackEffectiveTTL(nowMono); got != 4*time.Second {
		t.Fatalf("with active panel open want 4s TTL, got %v", got)
	}
	ctPanelTouchMonoNs.Store(nowMono - int64(20*time.Second))
	if got := conntrackEffectiveTTL(nowMono); got != 8*time.Second {
		t.Fatalf("after panel idle >15s want 8s TTL, got %v", got)
	}
}

func BenchmarkWorldSnapshotLoad(b *testing.B) {
	dir := b.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	s := newServer(dir)
	defer s.CoreHub().Close()
	hub := s.CoreHub()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if snap := hub.Snapshot(); snap == nil {
			b.Fatal("nil snapshot")
		}
	}
}
