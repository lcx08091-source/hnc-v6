package main

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"hnc.io/dpid/shm"
)

// C018: 验证 /api/health、/api/events 与免鉴权公开路径不触碰 WebUI 活跃度，且真实 TCP 连接设置 TCP_USER_TIMEOUT 无异常。
func TestWave4ControlplaneRC6_ActivityTouchExcludesHealthEventsAndPublicPaths(t *testing.T) {
	prevHit := webuiLastHit.Load()
	defer webuiLastHit.Store(prevHit)
	webuiLastHit.Store(0)

	dir := t.TempDir()
	for _, sub := range []string{"run", "data"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"auth_required":true}`), 0o644); err != nil {
		t.Fatal(err)
	}

	s := newServer(dir)
	noop := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	chain := s.authMiddleware(activityTouchMiddleware(noop))

	// 1. 无 local_admin.secret 时回环探活 /api/health、公开页 /pair、静态资源 /js/app.js 均不计入活跃命中
	for _, p := range []string{"/api/health", "/pair", "/js/app.js", "/api/logout"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.RemoteAddr = "127.0.0.1:41001"
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if got := webuiLastHit.Load(); got != 0 {
			t.Fatalf("path %s unexpectedly touched webuiLastHit=%d", p, got)
		}
	}

	// 2. 写入 local_admin.secret 后：带正确 64-hex secret 的 /api/health 与 /api/events 仍不刷 webuiLastHit
	secret := strings.Repeat("a1", 32)
	if err := os.WriteFile(filepath.Join(dir, "run", "local_admin.secret"), []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/api/health", "/api/events"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.RemoteAddr = "127.0.0.1:41002"
		req.Header.Set("X-HNC-Local-Admin", secret)
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if got := webuiLastHit.Load(); got != 0 {
			t.Fatalf("authenticated %s should not touch webuiLastHit, got %d", p, got)
		}
	}

	// 3. 真正鉴权通过的业务接口 /api/live 正常刷新 webuiLastHit
	liveReq := httptest.NewRequest(http.MethodGet, "/api/live", nil)
	liveReq.RemoteAddr = "127.0.0.1:41003"
	liveReq.Header.Set("X-HNC-Local-Admin", secret)
	liveRec := httptest.NewRecorder()
	chain.ServeHTTP(liveRec, liveReq)
	if liveRec.Code != http.StatusOK || webuiLastHit.Load() <= 0 {
		t.Fatalf("authenticated /api/live expected 200 and webuiLastHit > 0, got code=%d hit=%d", liveRec.Code, webuiLastHit.Load())
	}

	// 4. 真实 loopback TCP 连接设置 TCP_USER_TIMEOUT 不报错
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, aErr := ln.Accept(); aErr == nil {
			accepted <- c
		}
	}()
	cli, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	srvConn := <-accepted
	defer srvConn.Close()
	if err := setSSETCPUserTimeout(srvConn, sseTCPUserTimeoutMs); err != nil {
		t.Fatalf("setSSETCPUserTimeout failed: %v", err)
	}
}

// C019: 验证息屏 AOD 非零低亮度背光骤降复核与 mode="none" 恢复探测。
func TestWave4ControlplaneRC6_ScreenProberAODLowBacklightAndNoneRecovery(t *testing.T) {
	curNow := time.Unix(1700000000, 0)
	curBrightness := "220\n"
	curWake := dumpsysPowerAwake
	blAvail := true
	dumpAvail := true

	p := &screenProber{
		glob: func(_ string) ([]string, error) {
			if !blAvail {
				return nil, nil
			}
			return []string{"/fake/backlight/brightness"}, nil
		},
		readFile: func(_ string) ([]byte, error) {
			if !blAvail {
				return nil, os.ErrNotExist
			}
			return []byte(curBrightness), nil
		},
		dumpsys: func(service string, _ []string) (string, error) {
			if !dumpAvail {
				return "", errors.New("dumpsys unavailable")
			}
			if service == "power" {
				return curWake, nil
			}
			return "", nil
		},
		now: func() time.Time { return curNow },
	}

	// 初次探测: 亮屏且背光一致 -> 进入 backlight 模式
	on, ok, src := p.probe()
	if !ok || !on || src != "backlight" || p.mode != "backlight" {
		t.Fatalf("initial probe got on=%v ok=%v src=%q mode=%q", on, ok, src, p.mode)
	}

	// 20s 后切入息屏 AOD: 背光未归零但骤降到低值 12 (<=64), dumpsys power 为 Dozing -> 立即复核识破息屏
	curNow = curNow.Add(20 * time.Second)
	curBrightness = "12\n"
	curWake = dumpsysPowerDozing
	on, ok, src = p.probe()
	if !ok || on || src != "power" || p.mode != "power" {
		t.Fatalf("AOD sharp-drop recheck expected on=false ok=true src=power, got on=%v ok=%v src=%q mode=%q", on, ok, src, p.mode)
	}

	// 验证 mode="none" 在背光节点恢复后无需苦等 30 分钟即可重探恢复
	blAvail = false
	dumpAvail = false
	curNow = curNow.Add(screenVerifyEvery + time.Second)
	on, ok, src = p.probe()
	if ok || src != "none" || p.mode != "none" {
		t.Fatalf("expected mode=none when both probes fail, got on=%v ok=%v src=%q mode=%q", on, ok, src, p.mode)
	}

	blAvail = true
	dumpAvail = true
	curBrightness = "180\n"
	curWake = dumpsysPowerAwake
	curNow = curNow.Add(5 * time.Second)
	on, ok, src = p.probe()
	if !ok || !on || src != "backlight" {
		t.Fatalf("expected immediate recovery from mode=none when backlight returns, got on=%v ok=%v src=%q", on, ok, src)
	}
}

// C009/C010/C011: 验证 Bulkhead.ExecuteInline 半开探测失败延长冷却、快照单调 CAS 发布与陈旧 SHM 自动重开/有界关闭。
func TestWave4ControlplaneRC6_CoreHubBulkheadInlineProbeAndMonotonicSnapshot(t *testing.T) {
	bh := NewBulkhead(BulkheadConfig{
		Name:             "test_inline_probe",
		QueueSize:        8,
		DefaultTimeout:   100 * time.Millisecond,
		TripThreshold:    2,
		CooldownDuration: 5 * time.Second,
	})
	defer bh.Close()

	// 模拟已熔断且刚过冷却期进入 half_open
	bh.consecTimeouts.Store(2)
	bh.circuitOpenUntil.Store(monoNowNs() - int64(10*time.Millisecond))
	if st := bh.CircuitState(); st != "half_open" {
		t.Fatalf("expected half_open before probe, got %q", st)
	}

	// 半开探测失败: 不得误清 consecTimeouts/circuitOpenUntil, 必须延长冷却回到 open 且释放 halfOpenProbe
	probeErr := errors.New("probe failed")
	if err := bh.ExecuteInline(func() error { return probeErr }); !errors.Is(err, probeErr) {
		t.Fatalf("expected probeErr, got %v", err)
	}
	if bh.consecTimeouts.Load() != 2 {
		t.Fatalf("expected consecTimeouts preserved as 2, got %d", bh.consecTimeouts.Load())
	}
	if st := bh.CircuitState(); st != "open" {
		t.Fatalf("expected circuit re-opened after failed half-open inline probe, got %q", st)
	}
	if bh.halfOpenProbe.Load() {
		t.Fatalf("expected halfOpenProbe released after failed probe")
	}

	// 半开探测发生 panic 同样延长冷却并释放探针
	bh.circuitOpenUntil.Store(monoNowNs() - int64(10*time.Millisecond))
	pErr := bh.ExecuteInline(func() error { panic("boom") })
	if !errors.Is(pErr, ErrBulkheadPanic) || bh.CircuitState() != "open" || bh.halfOpenProbe.Load() {
		t.Fatalf("panic probe state mismatch: err=%v state=%s probe=%v", pErr, bh.CircuitState(), bh.halfOpenProbe.Load())
	}

	// 再次冷却到期后探测成功 -> 彻底恢复 closed
	bh.circuitOpenUntil.Store(monoNowNs() - int64(10*time.Millisecond))
	if err := bh.ExecuteInline(func() error { return nil }); err != nil {
		t.Fatalf("expected nil on healthy probe, got %v", err)
	}
	if bh.CircuitState() != "closed" || bh.consecTimeouts.Load() != 0 {
		t.Fatalf("expected closed & consecTimeouts=0 after healthy probe, got state=%s consec=%d", bh.CircuitState(), bh.consecTimeouts.Load())
	}

	// CoreHub 快照 Seq 单调性与陈旧 SHM 回退恢复 + Close() 有界等待
	srv, dir := setupTestV6Server(t)
	hub := srv.CoreHub()
	defer hub.Close()

	runDir := filepath.Join(dir, "run")
	shmPath := shm.FilePath(runDir)

	// 先写入新鲜 SHM 快照建立已缓存 reader
	w, err := shm.OpenWriter(runDir)
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Write(shm.MonotonicNs(), 3, 1, nil)
	_ = w.Close()

	snap1 := hub.RefreshSnapshotNow()
	ext1 := snap1.Extensions["dpi_shm_vector"].(map[string]any)
	if ext1["source"] != "shm_seqlock" {
		t.Fatalf("expected shm_seqlock, got %+v", ext1)
	}

	// 覆写为陈旧快照(单调时钟老化 60s) -> 关闭旧 reader 并无感回退 stale_snapshot
	staleMono := shm.MonotonicNs() - int64(60*time.Second)
	if staleMono <= 0 {
		staleMono = 1
	}
	w2, err := shm.OpenWriterPath(shmPath, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = w2.Write(staleMono, 3, 1, nil)
	_ = w2.Close()

	snap2 := hub.RefreshSnapshotNow()
	if snap2.Seq <= snap1.Seq {
		t.Fatalf("expected monotonic snapshot seq: snap2=%d <= snap1=%d", snap2.Seq, snap1.Seq)
	}
	ext2 := snap2.Extensions["dpi_shm_vector"].(map[string]any)
	if ext2["source"] != "json_fallback" || ext2["fallback_reason"] != "stale_snapshot" {
		t.Fatalf("expected stale_snapshot fallback, got %+v", ext2)
	}

	// 并发刷新快照: 最终 hub.World().Seq 必须等于最大 Seq
	var wg sync.WaitGroup
	var maxSeqMu sync.Mutex
	var maxSeq uint64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := hub.RefreshSnapshotNow()
			maxSeqMu.Lock()
			if s.Seq > maxSeq {
				maxSeq = s.Seq
			}
			maxSeqMu.Unlock()
		}()
	}
	wg.Wait()
	if got := hub.world.Load().Seq; got < maxSeq {
		t.Fatalf("hub.world.Load().Seq=%d regressed below maxSeq=%d", got, maxSeq)
	}

	// 模拟慢路径占用 shmLockCh 时 Close() 有界退出不死锁
	held := hub.tryLockShm()
	startClose := time.Now()
	hub.Close()
	if elapsed := time.Since(startClose); elapsed > 500*time.Millisecond {
		t.Fatalf("hub.Close() blocked too long while shm lock held: %v", elapsed)
	}
	if held {
		hub.unlockShm()
	}
}

// C023/C024: 验证 rulesStore 严格遵守 flock->json.lock 跨进程锁序、锁超时拒绝裸写、最多保留 5 份好备份及 jsonFileCache 即时失效。
func TestWave4ControlplaneRC6_RulesStoreCrossProcLockOrderBackupAndCacheInvalidate(t *testing.T) {
	oldTimeout := rulesCrossLockTimeout
	rulesCrossLockTimeout = 80 * time.Millisecond
	defer func() { rulesCrossLockTimeout = oldTimeout }()

	dir := t.TempDir()
	for _, sub := range []string{"run", "data"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rulesPath := filepath.Join(dir, "data", "rules.json")
	initialJSON := `{"version":1,"whitelist_mode":false,"hotspot_ssid":"InitAP","devices":{},"blacklist":[],"whitelist":[]}` + "\n"
	if err := os.WriteFile(rulesPath, []byte(initialJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. 预热 jsonFileCache
	cache := newJSONFileCache()
	v0, err := cache.read(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if v0.(map[string]interface{})["hotspot_ssid"] != "InitAP" {
		t.Fatalf("unexpected initial cached ssid: %+v", v0)
	}

	// 2. 模拟外部进程持有 flock(run/.json_fd): Mutate 必须返回 errRulesLockTimeout 且绝不脱锁覆盖磁盘文件
	fdFile, err := os.OpenFile(filepath.Join(dir, "run", ".json_fd"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer fdFile.Close()
	if flockErr := syscall.Flock(int(fdFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); flockErr == nil {
		err = rulesStore.SetTop(dir, "hotspot_ssid", "BlockedWrite")
		_ = syscall.Flock(int(fdFile.Fd()), syscall.LOCK_UN)
		if !errors.Is(err, errRulesLockTimeout) {
			t.Fatalf("expected errRulesLockTimeout when flock held, got %v", err)
		}
		diskBytes, rErr := os.ReadFile(rulesPath)
		if rErr != nil {
			t.Fatal(rErr)
		}
		if strings.Contains(string(diskBytes), "BlockedWrite") {
			t.Fatalf("rulesStore overwrote rules.json without holding flock: %s", string(diskBytes))
		}
	}

	// 3. 释放锁后连续写入 7 次不同等长字符串("AP0001".."AP0007"): 验证同长度写盘仍使 jsonFileCache 即时失效, 且 .json_backups 裁剪 <= 5 份
	for i := 1; i <= 7; i++ {
		wantSSID := fmt.Sprintf("AP%04d", i)
		if err := rulesStore.SetTop(dir, "hotspot_ssid", wantSSID); err != nil {
			t.Fatalf("SetTop(%s) failed: %v", wantSSID, err)
		}
		gotVal, rErr := cache.read(rulesPath)
		if rErr != nil {
			t.Fatal(rErr)
		}
		if gotSSID := gotVal.(map[string]interface{})["hotspot_ssid"]; gotSSID != wantSSID {
			t.Fatalf("round %d: jsonFileCache returned stale hotspot_ssid=%v, want %s", i, gotSSID, wantSSID)
		}
	}

	bakDir := filepath.Join(dir, "data", ".json_backups")
	ents, err := os.ReadDir(bakDir)
	if err != nil {
		t.Fatalf("expected .json_backups dir created: %v", err)
	}
	bakCount := 0
	for _, e := range ents {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "rules.json.") && strings.HasSuffix(e.Name(), ".bak") {
			bakCount++
		}
	}
	if bakCount == 0 || bakCount > rulesMaxGoodBackups {
		t.Fatalf("expected 1..%d good backups in %s, got %d", rulesMaxGoodBackups, bakDir, bakCount)
	}
}

// C074/C083: 验证显式 IDLE 与 eth*/wlan1 外部接口边界拦截, 以及 HTTPS Origin 降级防护与配对认领不误删新 PIN。
func TestWave4ControlplaneRC6_WebUIBoundaryIdleAndPairClaimSafety(t *testing.T) {
	oldList := webuiListIfaces
	defer func() {
		webuiListIfaces = oldList
		webuiBoundaryMu.Lock()
		webuiBoundarySnap = map[string]webuiBoundaryEntry{}
		webuiBoundaryMu.Unlock()
	}()

	mustCIDR := func(s string) *net.IPNet {
		ip, ipn, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		ipn.IP = ip
		return ipn
	}
	webuiListIfaces = func() []webuiIfaceInfo {
		return []webuiIfaceInfo{
			{Name: "wlan2", Up: true, Addrs: []*net.IPNet{mustCIDR("192.168.43.1/24")}},
			{Name: "wlan1", Up: true, Addrs: []*net.IPNet{mustCIDR("192.168.1.9/24")}},
			{Name: "eth0", Up: true, Addrs: []*net.IPNet{mustCIDR("10.0.0.5/24")}},
		}
	}

	dir := t.TempDir()
	for _, sub := range []string{"run", "data"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "run", "hotspot_iface"), []byte("wlan2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("IDLE\n"), 0o644)

	// 1. hnc_state=IDLE 时拒绝一切非回环远程访问(即便残留 hotspot_iface=wlan2)
	if webuiRemoteBoundaryAllowed(dir, net.ParseIP("192.168.43.20"), net.ParseIP("192.168.43.1")) {
		t.Fatalf("expected remote access rejected when hnc_state is explicit IDLE")
	}

	// 2. hnc_state=ACTIVE:wlan2 时放行 wlan2 下游子网, 但严厉拒绝到达 wlan1 / eth0 的外部请求
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)
	webuiBoundaryMu.Lock()
	delete(webuiBoundarySnap, dir)
	webuiBoundaryMu.Unlock()

	if !webuiRemoteBoundaryAllowed(dir, net.ParseIP("192.168.43.20"), net.ParseIP("192.168.43.1")) {
		t.Fatalf("expected active wlan2 client allowed")
	}
	if webuiRemoteBoundaryAllowed(dir, net.ParseIP("192.168.43.20"), net.ParseIP("192.168.1.9")) {
		t.Fatalf("expected secondary STA wlan1 local dst rejected as upstream WAN")
	}
	if webuiRemoteBoundaryAllowed(dir, net.ParseIP("192.168.43.20"), net.ParseIP("10.0.0.5")) {
		t.Fatalf("expected wired eth0 local dst rejected as upstream WAN")
	}

	// 3. C083: TLS 请求携带明文 http:// Origin(同 host)必须按跨源拦截
	tlsHttpOriginReq := httptest.NewRequest(http.MethodPost, "https://192.168.43.1:8443/api/pair/verify", nil)
	tlsHttpOriginReq.Host = "192.168.43.1:8443"
	tlsHttpOriginReq.TLS = &tls.ConnectionState{}
	tlsHttpOriginReq.Header.Set("Origin", "http://192.168.43.1:8443")
	if !isCrossSiteFormRequest(tlsHttpOriginReq) {
		t.Fatalf("expected http:// Origin on TLS request rejected as cross-site")
	}
	tlsHttpsOriginReq := httptest.NewRequest(http.MethodPost, "https://192.168.43.1:8443/api/pair/verify", nil)
	tlsHttpsOriginReq.Host = "192.168.43.1:8443"
	tlsHttpsOriginReq.TLS = &tls.ConnectionState{}
	tlsHttpsOriginReq.Header.Set("Origin", "https://192.168.43.1:8443")
	if isCrossSiteFormRequest(tlsHttpsOriginReq) {
		t.Fatalf("expected matching https:// Origin on TLS request allowed")
	}

	// 4. C083: handlePairVerify 认领旧 pair_pending 后在慢速 bcrypt(IssueToken)期间主人生成新 PIN, 绝不能被旧请求收尾误删
	resetPairGuard(t)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"auth_required":true}`), 0o644)
	pendingPath := filepath.Join(dir, "run", "pair_pending")
	exp := time.Now().Unix() + 120
	writePending(t, dir, "135790", "sidFIRST0001", exp)

	srv := newServer(dir)
	doneA := make(chan int, 1)
	go func() {
		reqA := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8444/api/pair/verify", strings.NewReader("pin=135790"))
		reqA.RemoteAddr = "127.0.0.1:51001"
		reqA.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		recA := httptest.NewRecorder()
		srv.handlePairVerify(recA, reqA)
		doneA <- recA.Code
	}()

	// 等待请求 A 通过 os.Rename 认领走旧 pair_pending(此时正执行 IssueToken 慢速 bcrypt), 立刻写入新配对码 PIN B
	deadline := time.Now().Add(2 * time.Second)
	wroteSecond := false
	for time.Now().Before(deadline) {
		if _, stErr := os.Stat(pendingPath); os.IsNotExist(stErr) {
			writePending(t, dir, "246810", "sidSECOND002", exp)
			wroteSecond = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if codeA := <-doneA; codeA != http.StatusFound {
		t.Fatalf("first pair verify expected 302 StatusFound, got %d", codeA)
	}
	if !wroteSecond {
		writePending(t, dir, "246810", "sidSECOND002", exp)
	}
	if _, stErr := os.Stat(pendingPath); stErr != nil {
		t.Fatalf("newly generated pair_pending was clobbered by concurrent handlePairVerify: %v", stErr)
	}
	reqB := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8444/api/pair/verify", strings.NewReader("pin=246810"))
	reqB.RemoteAddr = "127.0.0.1:51002"
	reqB.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recB := httptest.NewRecorder()
	srv.handlePairVerify(recB, reqB)
	if recB.Code != http.StatusFound {
		t.Fatalf("second pair verify expected 302 StatusFound, got %d body=%s", recB.Code, recB.Body.String())
	}
}

// C079/C080/C081: 验证导出防符号链接逃逸与头注入、清理孤儿 tmp 保留新鲜写盘文件、IDLE 重绑传 auto 及设备改名校验失效缓存。
func TestWave4ControlplaneRC6_ExportNoSymlinkOrphanTmpAndDeviceRename(t *testing.T) {
	// 1. C079: 文件名消毒与防符号链接泄露
	for _, bad := range []string{
		"",
		"../hnc-export-1.zip",
		"hnc-export-1.zip\r\nEvil: 1",
		"hnc-export-\"q\".zip",
		"hnc-export-a;b.zip",
		"C:hnc-export-1.zip",
	} {
		if _, ok := sanitizeExportDispositionFilename(bad); ok {
			t.Fatalf("expected malicious export filename %q rejected", bad)
		}
	}

	dir := t.TempDir()
	for _, sub := range []string{"run", "data", "exports", "bin"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secretTarget := filepath.Join(dir, "secret_outside.txt")
	_ = os.WriteFile(secretTarget, []byte("TOP_SECRET_DATA"), 0o600)
	symExport := filepath.Join(dir, "exports", "hnc-export-20261124-000000.zip")
	if err := os.Symlink(secretTarget, symExport); err != nil {
		t.Fatal(err)
	}

	srv := newServer(dir)
	// /api/exports 列表不暴露符号链接
	listReq := httptest.NewRequest(http.MethodGet, "/api/exports", nil)
	listRec := httptest.NewRecorder()
	srv.apiExportList(listRec, listReq)
	if strings.Contains(listRec.Body.String(), "hnc-export-20261124-000000.zip") {
		t.Fatalf("apiExportList leaked symlink archive: %s", listRec.Body.String())
	}
	// /api/exports/<symlink> 直接返回 403 Forbidden
	dlReq := httptest.NewRequest(http.MethodGet, "/api/exports/hnc-export-20261124-000000.zip", nil)
	dlRec := httptest.NewRecorder()
	srv.apiExportFile(dlRec, dlReq)
	if dlRec.Code != http.StatusForbidden || strings.Contains(dlRec.Body.String(), "TOP_SECRET_DATA") {
		t.Fatalf("apiExportFile expected 403 without secret leak, got code=%d body=%q", dlRec.Code, dlRec.Body.String())
	}
	// addSingleFileToZip 遇到符号链接安全跳过
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	ti, zErr := addSingleFileToZip(zw, symExport, "data/secret.zip")
	_ = zw.Close()
	if zErr != nil || ti.Included {
		t.Fatalf("addSingleFileToZip expected symlink skipped (Included=false, err=nil), got ti=%+v err=%v", ti, zErr)
	}

	// 2. C080: actionCacheClear 仅删 mtime > 10min 的陈旧孤儿 tmp, 保留新鲜在途 tmp; IDLE 下 dpi_rebind 传 auto
	freshTmp := filepath.Join(dir, "data", ".rules.json.tmp.fresh")
	staleTmp := filepath.Join(dir, "data", ".rules.json.tmp.stale")
	_ = os.WriteFile(freshTmp, []byte("{}"), 0o600)
	_ = os.WriteFile(staleTmp, []byte("{}"), 0o600)
	oldTime := time.Now().Add(-20 * time.Minute)
	_ = os.Chtimes(staleTmp, oldTime, oldTime)

	if resp := actionCacheClear(dir); !resp.OK {
		t.Fatalf("actionCacheClear failed: %+v", resp)
	}
	if _, err := os.Stat(freshTmp); err != nil {
		t.Fatalf("fresh in-flight tmp file was mistakenly deleted: %v", err)
	}
	if _, err := os.Stat(staleTmp); !os.IsNotExist(err) {
		t.Fatalf("stale orphan tmp file should have been deleted, stat err=%v", err)
	}

	rebindArgLog := filepath.Join(dir, "run", "rebind_arg.txt")
	rebindScript := filepath.Join(dir, "bin", "dpi_rebind.sh")
	_ = os.WriteFile(rebindScript, []byte("#!/system/bin/sh\nprintf '%s' \"$1\" > \""+rebindArgLog+"\"\n"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "run", "hotspot_iface"), []byte("wlan2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("IDLE\n"), 0o644)
	triggerDPIRulesRebind(dir)
	if gotArg, err := os.ReadFile(rebindArgLog); err != nil || string(gotArg) != "auto" {
		t.Fatalf("triggerDPIRulesRebind in IDLE expected 'auto', got %q (err=%v)", string(gotArg), err)
	}

	// 3. C081: validDeviceName UTF-8 校验与缓存主动失效
	if validDeviceName(string([]byte{0xff, 0xfe, 'a'})) || validDeviceName(`bad"quote`) || validDeviceName(`bad\slash`) {
		t.Fatalf("validDeviceName failed to reject invalid UTF-8 / quote / backslash")
	}
	if !validDeviceName("客厅/iPad Pro") {
		t.Fatalf("validDeviceName rejected valid UTF-8 name with slash")
	}
	namesPath := filepath.Join(dir, "data", "device_names.json")
	_ = os.WriteFile(namesPath, []byte(`{"aa:bb:cc:dd:ee:11":"OldPad"}`), 0o644)
	cache := newJSONFileCache()
	_, _ = cache.read(namesPath)
	if r := actionDeviceRename(dir, map[string]string{"mac": "aa:bb:cc:dd:ee:11", "name": "NewPad"}); !r.OK {
		t.Fatalf("actionDeviceRename failed: %+v", r)
	}
	vAfter, err := cache.read(namesPath)
	if err != nil || vAfter.(map[string]interface{})["aa:bb:cc:dd:ee:11"] != "NewPad" {
		t.Fatalf("expected device_names cache invalidated immediately, got %+v err=%v", vAfter, err)
	}
}

// C086: 验证 "0mbit"/双 0 速率转调 actionRuleClear 以及默认网关 IP/MAC 拉黑保护拦截。
func TestWave4ControlplaneRC6_ZeroRateClearAndGatewayBlacklistGuard(t *testing.T) {
	oldRoute := blProcNetRoutePath
	oldArp := neighArpPath
	defer func() {
		blProcNetRoutePath = oldRoute
		neighArpPath = oldArp
	}()

	dir := t.TempDir()
	for _, sub := range []string{"run", "data", "bin"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// 1. 桩脚本记录 apply_device_rule.sh 调用参数
	callLog := filepath.Join(dir, "run", "rule_calls.log")
	stubScript := filepath.Join(dir, "bin", "apply_device_rule.sh")
	scriptBody := "#!/system/bin/sh\nprintf '%s\\n' \"$*\" >> \"" + callLog + "\"\nexit 0\n"
	if err := os.WriteFile(stubScript, []byte(scriptBody), 0o755); err != nil {
		t.Fatal(err)
	}

	targetMAC := "aa:bb:cc:11:22:33"
	r1 := actionRuleSet(dir, map[string]string{"mac": targetMAC, "rate_down": "0mbit", "rate_up": "0kbit"})
	if !r1.OK || r1.Detail != "limit cleared" {
		t.Fatalf("actionRuleSet(0mbit,0kbit) expected 'limit cleared', got %+v", r1)
	}
	r2 := actionTemplateApply(dir, map[string]string{"mac": targetMAC, "rate_down": "0mbit", "rate_up": "0"})
	if !r2.OK || r2.Detail != "limit cleared" {
		t.Fatalf("actionTemplateApply(0mbit,0) expected 'limit cleared', got %+v", r2)
	}
	logBytes, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(logBytes)), "\n")
	if len(lines) != 2 || lines[0] != "clear "+targetMAC || lines[1] != "clear "+targetMAC {
		t.Fatalf("expected both zero-rate calls delegated to 'clear %s', got %q", targetMAC, lines)
	}

	// 2. 构造 fake /proc/net/route (默认网关 192.168.1.1) 与 fake ARP 表 + rules.json 网关设备
	gwIP := net.IPv4(192, 168, 1, 1).To4()
	gwHex := fmt.Sprintf("%08X", binary.NativeEndian.Uint32(gwIP))
	routeFixture := filepath.Join(dir, "run", "fake_route")
	routeText := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"wlan0\t00000000\t" + gwHex + "\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	if err := os.WriteFile(routeFixture, []byte(routeText), 0o644); err != nil {
		t.Fatal(err)
	}
	arpFixture := filepath.Join(dir, "run", "fake_arp")
	arpText := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        wlan0\n" +
		"192.168.43.88    0x1         0x2         aa:bb:cc:dd:ee:99     *        wlan2\n"
	if err := os.WriteFile(arpFixture, []byte(arpText), 0o644); err != nil {
		t.Fatal(err)
	}
	rulesJSON := map[string]interface{}{
		"version": 1,
		"devices": map[string]interface{}{
			"aa:bb:cc:dd:ee:02": map[string]interface{}{"ip": "192.168.1.1"},
		},
	}
	rb, _ := json.Marshal(rulesJSON)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), rb, 0o644)

	blProcNetRoutePath = routeFixture
	neighArpPath = arpFixture

	// ARP 中直接命中默认网关 MAC -> 拒绝拉黑
	if resp := actionBLAdd(dir, map[string]string{"mac": "aa:bb:cc:dd:ee:01"}); resp.OK || resp.Error != "protected mac" || !strings.Contains(resp.Detail, "default gateway") {
		t.Fatalf("expected ARP gateway MAC blocked, got %+v", resp)
	}
	// rules.json 持久化 IP 命中默认网关 IP -> 拒绝拉黑
	if resp := actionBLAdd(dir, map[string]string{"mac": "aa:bb:cc:dd:ee:02"}); resp.OK || resp.Error != "protected mac" || !strings.Contains(resp.Detail, "default gateway") {
		t.Fatalf("expected persisted gateway IP MAC blocked, got %+v", resp)
	}
	// 普通下游热点设备正常放行拉黑
	if resp := actionBLAdd(dir, map[string]string{"mac": "aa:bb:cc:dd:ee:99"}); !resp.OK {
		t.Fatalf("expected normal client MAC allowed for blacklist, got %+v", resp)
	}
}
