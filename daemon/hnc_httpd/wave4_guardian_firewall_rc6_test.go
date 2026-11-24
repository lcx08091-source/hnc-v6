package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hnc.io/dpid/bytestats"
)

type mockWave4BPFSampler struct {
	// 64 位原子字段严格置于 offset 0 (兼容 GOARCH=arm 对齐门禁)
	seq    atomic.Uint64
	closed atomic.Bool
}

func (m *mockWave4BPFSampler) SampleDetail() (*bytestats.NetdDetailSnapshot, error) {
	if m.closed.Load() {
		return nil, errors.New("sampler already closed")
	}
	n := m.seq.Add(1)
	return &bytestats.NetdDetailSnapshot{
		ByUID: map[int]bytestats.NetdUIDDetail{
			10245: {},
		},
		StatsABTotalBytes: n * 4096,
	}, nil
}

func (m *mockWave4BPFSampler) Close() error {
	m.closed.Store(true)
	return nil
}

// TestWave4GuardianC060LeaseRenewRaceAndDetachedSingleFlight 验证:
//  1. C060 SingleFlight DoCtx 独立后台 Context: 首请求中途断开取消绝不连坐后续并发请求;
//  2. C060 8s 短租约临界续期持锁复核: 到期边界续租绝不被旧循环误关新采样器;
//  3. C072 guardianReadSelfCaptureStatus 兼容 optin/enabled 持久化与 self_policy.json。
func TestWave4GuardianC060LeaseRenewRaceAndDetachedSingleFlight(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"data", "run", "etc"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	srv := &server{hncDir: dir, jsonCache: newJSONFileCache()}
	eng := srv.guardianEngine()
	t.Cleanup(func() {
		srv.guardianClose()
	})

	// 1) 验证 SingleFlight DoCtx 首请求取消不连坐并发请求
	startedCh := make(chan struct{})
	var streamCalls atomic.Int32
	eng.batterystatsStreamFn = func(sfCtx context.Context) (io.ReadCloser, error) {
		if streamCalls.Add(1) == 1 {
			close(startedCh)
		}
		select {
		case <-time.After(90 * time.Millisecond):
		case <-sfCtx.Done():
			return nil, sfCtx.Err()
		}
		sample := "Battery History (0% used)\n" +
			"Estimated power use (mAh):\n" +
			"  Capacity: 5000, Computed drain: 120, actual drain: 120\n" +
			"  Uid u0a245: 18.5 ( screen=0.0 cpu=12.5 wifi=6.0 ) Including smearing: 18.5\n" +
			"    bg: 11.2 mAh\n"
		return io.NopCloser(strings.NewReader(sample)), nil
	}

	ctxA, cancelA := context.WithCancel(context.Background())
	errChA := make(chan error, 1)
	go func() {
		_, _, _, err := eng.fetchPowerStatsCached(ctxA, true)
		errChA <- err
	}()

	<-startedCh
	ctxB, cancelB := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelB()
	type powerRes struct {
		entry *guardianPowerCacheEntry
		err   error
	}
	resChB := make(chan powerRes, 1)
	go func() {
		ent, _, _, err := eng.fetchPowerStatsCached(ctxB, false)
		resChB <- powerRes{entry: ent, err: err}
	}()

	// 让 callerB 进入同一合并调用后立即取消首请求 callerA
	time.Sleep(15 * time.Millisecond)
	cancelA()

	errA := <-errChA
	if !errors.Is(errA, context.Canceled) {
		t.Fatalf("expected callerA to receive context.Canceled, got %v", errA)
	}
	resB := <-resChB
	if resB.err != nil || resB.entry == nil || resB.entry.parsed == nil {
		t.Fatalf("callerB was collateral-canceled by callerA: err=%v entry=%+v", resB.err, resB.entry)
	}
	if streamCalls.Load() != 1 {
		t.Fatalf("expected exactly 1 coalesced batterystats execution, got %d", streamCalls.Load())
	}

	// 2) 验证租约临界续期绝不被旧循环误杀
	var createdSamplers []*mockWave4BPFSampler
	var samplerMu sync.Mutex
	eng.leaseTTL = 45 * time.Millisecond
	eng.tickInterval = 15 * time.Millisecond
	eng.bpfSamplerFactory = func() (guardianBPFSampler, error) {
		s := &mockWave4BPFSampler{}
		samplerMu.Lock()
		createdSamplers = append(createdSamplers, s)
		samplerMu.Unlock()
		return s, nil
	}

	for i := 0; i < 8; i++ {
		snap, _, _, err := eng.touchAndSampleTrafficLease()
		if err != nil || snap == nil {
			t.Fatalf("iter %d touchAndSampleTrafficLease failed: snap=%v err=%v", i, snap, err)
		}
		time.Sleep(18 * time.Millisecond)
	}
	// 刚续期完立刻核验: 当前活跃采样器绝不可处于 closed 状态且 leaseRunning 必须为 true
	eng.trafficMu.Lock()
	curSampler, _ := eng.bpfSampler.(*mockWave4BPFSampler)
	runningNow := eng.leaseRunning.Load()
	eng.trafficMu.Unlock()
	if !runningNow || curSampler == nil || curSampler.closed.Load() {
		t.Fatalf("active lease was killed prematurely during boundary renewal: running=%v sampler=%v", runningNow, curSampler)
	}

	// 停止续租等待自然到期回收 -> 归零空转
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && eng.leaseRunning.Load() {
		time.Sleep(15 * time.Millisecond)
	}
	if eng.leaseRunning.Load() {
		t.Fatal("expected traffic lease to auto-stop after leaseTTL elapsed")
	}

	// 3) 验证 guardianReadSelfCaptureStatus 兼容持久化 optin 与 self_policy.json
	if en, md := srv.guardianReadSelfCaptureStatus(); en || md != "off" {
		t.Fatalf("expected initial self_capture off, got enabled=%v mode=%q", en, md)
	}
	optInPath := filepath.Join(dir, "data", "self_capture.optin")
	if err := os.WriteFile(optInPath, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if en, md := srv.guardianReadSelfCaptureStatus(); !en || md != "smart_screen" {
		t.Fatalf("expected optin file to enable smart_screen status, got enabled=%v mode=%q", en, md)
	}
	_ = os.Remove(optInPath)
	if err := os.WriteFile(selfPolicyPath(dir), []byte(`{"mode":"always","self_capture_opt_in":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.jsonCache = newJSONFileCache()
	if en, md := srv.guardianReadSelfCaptureStatus(); !en || md != "always" {
		t.Fatalf("expected self_policy mode=always to report enabled=true, got enabled=%v mode=%q", en, md)
	}
}

// TestWave4GuardianC063C064C065SelfFirewallMultiUserSandboxAndDirtySync 验证:
//  1. C063: HNC_SELF_UID 仅保留 -o lo 链顶豁免, 彻底移除 8443/8444/8080 无目的 IP 公网穿透豁免;
//  2. C064: 多用户/双开 uid % 100000 系统进程保护、受保护包名反查及双开 SDK 沙盒 (+10000) 同步;
//  3. C065: 内核 restore / OUTPUT 挂载失败不吞错返回真实错误并置位 syncDirty, 后续 SyncIfDirty 自动补偿。
func TestWave4GuardianC063C064C065SelfFirewallMultiUserSandboxAndDirtySync(t *testing.T) {
	s, _, dir := newV6TestMux(t)
	sf := s.v6State().selfFirewall

	pkgListPath := filepath.Join(dir, "packages.list")
	pkgContent := strings.Join([]string{
		"com.agy 10205 0 /data/user/0/com.agy default:targetSdkVersion=34 none 0 1",
		"me.bmax.apatch 10209 0 /data/user/0/me.bmax.apatch default:targetSdkVersion=34 none 0 1",
		"com.example.dualapp 10288 0 /data/user/0/com.example.dualapp default:targetSdkVersion=34 none 0 1",
	}, "\n") + "\n"
	if err := os.WriteFile(pkgListPath, []byte(pkgContent), 0o600); err != nil {
		t.Fatal(err)
	}

	var (
		dpMu        sync.Mutex
		failHookV6  bool
		failDNSRest bool
		v4UIDLast   string
		v6UIDLast   string
		v4DNSLast   string
	)
	sf.mu.Lock()
	sf.packagesListPath = pkgListPath
	sf.forceDataplane = true
	sf.restoreExec = func(isIPv6 bool, payload string) error {
		dpMu.Lock()
		defer dpMu.Unlock()
		if strings.Contains(payload, ":HNC_SELF_DNS") && failDNSRest {
			return errors.New("xtables lock contention simulated")
		}
		if strings.Contains(payload, ":HNC_SELF_UID") {
			if isIPv6 {
				v6UIDLast = payload
			} else {
				v4UIDLast = payload
			}
		} else if strings.Contains(payload, ":HNC_SELF_DNS") && !isIPv6 {
			v4DNSLast = payload
		}
		return nil
	}
	sf.iptExec = func(isIPv6 bool, args ...string) (string, error) {
		dpMu.Lock()
		shouldFailV6 := failHookV6
		dpMu.Unlock()
		line := strings.Join(args, " ")
		if strings.Contains(line, "-C OUTPUT") {
			return "No chain/target/match", errors.New("not linked")
		}
		if isIPv6 && shouldFailV6 && strings.Contains(line, "-I OUTPUT") {
			return "resource temporarily unavailable", errors.New("exit 4")
		}
		return "", nil
	}
	sf.mu.Unlock()

	// C064a: 多用户系统守护进程 (user 10 / user 999, appId < 10000) 必须被拦截
	for _, sysCloneUID := range []int{1000000, 1001000, 99900000, 99901051, 99909999} {
		if _, _, err := sf.SetUIDRule(sysCloneUID, SelfFirewallModeBlockAll, "", "", nil); err == nil {
			t.Fatalf("expected multi-user system UID %d to be rejected", sysCloneUID)
		}
	}

	// C064b: 多用户及 SDK 沙盒受保护包名反查拦截 (不传 pkg 企图绕过)
	for _, protCloneUID := range []int{99910205, 99920205, 1020209, 20209} {
		if _, _, err := sf.SetUIDRule(protCloneUID, SelfFirewallModeBlockCleartext, "", "", nil); err == nil {
			t.Fatalf("expected protected package clone/sandbox UID %d to be rejected", protCloneUID)
		}
	}

	// C064c + C063: 双开普通应用 99910288 写入 block_cleartext -> 自动同步 99920288, 且链顶仅含 -o lo
	rule, _, err := sf.SetUIDRule(99910288, SelfFirewallModeBlockCleartext, "", "双开测试应用", nil)
	if err != nil {
		t.Fatalf("SetUIDRule for clone app 99910288 failed: %v", err)
	}
	if rule.SDKSandboxUID != 99920288 {
		t.Fatalf("expected SDKSandboxUID=99920288, got %d", rule.SDKSandboxUID)
	}
	dpMu.Lock()
	gotV4, gotV6 := v4UIDLast, v6UIDLast
	dpMu.Unlock()
	for fam, pl := range map[string]string{"v4": gotV4, "v6": gotV6} {
		if !strings.Contains(pl, "-A HNC_SELF_UID -o lo -j RETURN\n") {
			t.Fatalf("[%s] missing -o lo RETURN rule:\n%s", fam, pl)
		}
		if strings.Contains(pl, "8443") || strings.Contains(pl, "--dports 8443,8444,8080") || strings.Contains(pl, "--sports 8443,8444,8080") {
			t.Fatalf("[%s] C063 regression: public 8443/8444/8080 bypass leaked into HNC_SELF_UID:\n%s", fam, pl)
		}
		if !strings.Contains(pl, "--uid-owner 99910288") || !strings.Contains(pl, "--uid-owner 99920288") {
			t.Fatalf("[%s] C064 regression: missing clone app 99910288 or clone SDK sandbox 99920288:\n%s", fam, pl)
		}
	}
	if !sf.IsHostEventBlocked(99920288, "", "203.0.113.9", 8080, "tcp") {
		t.Fatal("expected clone SDK sandbox UID 99920288 cleartext :8080 to be marked blocked (no public 8080 bypass!)")
	}

	// C065: 模拟 ip6tables OUTPUT 挂载失败与 HNC_SELF_DNS restore 锁竞争失败 -> 不吞错 + syncDirty=true + SyncIfDirty 恢复
	dpMu.Lock()
	failHookV6 = true
	failDNSRest = true
	dpMu.Unlock()

	if _, _, _, berr := sf.BlockDomain("tracker.c065-verify.example", false); berr == nil {
		t.Fatal("expected BlockDomain to surface dataplane error instead of swallowing it")
	}
	if !sf.IsSyncDirty() {
		t.Fatal("expected syncDirty=true after dataplane sync failure")
	}

	dpMu.Lock()
	failHookV6 = false
	failDNSRest = false
	dpMu.Unlock()

	if serr := sf.SyncIfDirty(); serr != nil {
		t.Fatalf("expected SyncIfDirty recovery to succeed, got %v", serr)
	}
	if sf.IsSyncDirty() {
		t.Fatal("expected syncDirty=false after successful SyncIfDirty")
	}
	dpMu.Lock()
	gotDNS := v4DNSLast
	dpMu.Unlock()
	if !strings.Contains(gotDNS, "|07|tracker|0b|c065-verify|07|example|00|") {
		t.Fatalf("expected HNC_SELF_DNS payload restored after SyncIfDirty, got:\n%s", gotDNS)
	}
}

// TestWave4GuardianC057ScalpelBidirectionalHostSandboxPairing 验证:
//  1. 按 uid % 100000 拦截多用户系统 UID (<10000) 与隔离进程 (>=90000);
//  2. 主应用 (10000..19999) 与 SDK 沙盒 (20000..29999) 双向配对核验受保护包名 (防沙盒伪装包名绕过);
//  3. 冻结主应用或 SDK 沙盒任一方均同步写入配对双 UID OUTPUT 规则并原地去重, 30000..89999 不越界配对。
func TestWave4GuardianC057ScalpelBidirectionalHostSandboxPairing(t *testing.T) {
	dir := setupNativeTierTestEnv(t, "wlan2")
	for _, sub := range []string{"data", "run", "etc"} {
		_ = os.MkdirAll(filepath.Join(dir, sub), 0o755)
	}
	procDir, pkgListPath := hostConnSetupFakeHostEnv(t, dir)

	// 故意为 20814 写入伪装非保护包名 com.fake.sdkprovider, 验证双向配对门禁依然反查 10814 (com.agy) 拦截!
	pkgLines := strings.Join([]string{
		"com.tencent.mm 10245 0 /data/user/0/com.tencent.mm default:targetSdkVersion=34 3003 0 1",
		"com.agy 10814 0 /data/user/0/com.agy default:targetSdkVersion=34 3003 0 1",
		"com.fake.sdkprovider 20814 0 /data/misc_ce/0/sdksandbox/com.fake default:targetSdkVersion=34 3003 0 1",
		"com.vendor.oemext 30500 0 /data/user/0/com.vendor.oemext default:targetSdkVersion=34 3003 0 1",
	}, "\n") + "\n"
	if err := os.WriteFile(pkgListPath, []byte(pkgLines), 0o644); err != nil {
		t.Fatal(err)
	}

	// /proc/net/tcp:
	//   - 10.0.2.15:51000 -> 198.51.100.77:443 uid=10245 (主应用)
	//   - 10.0.2.15:51001 -> 198.51.100.77:443 uid=20245 (配对 SDK 沙盒)
	tcpLines := "  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0F02000A:C738 4D6433C6:01BB 01 00000000:00000000 00:00000000 00000000 10245        0 70001 1 0 0\n" +
		"   1: 0F02000A:C739 4D6433C6:01BB 01 00000000:00000000 00:00000000 00000000 20245        0 70002 1 0 0\n"
	if err := os.WriteFile(filepath.Join(procDir, "tcp"), []byte(tcpLines), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := &server{hncDir: dir, jsonCache: newJSONFileCache()}
	sc := srv.v6State().scalpel
	defer sc.stopStandaloneTimer()

	origResolve := scalpelResolveBinFn
	origExec := scalpelIptExecFn
	t.Cleanup(func() {
		scalpelResolveBinFn = origResolve
		scalpelIptExecFn = origExec
	})
	scalpelResolveBinFn = func(name string) string { return "/system/bin/" + name }
	scalpelIptExecFn = func(_ string, _ ...string) (string, error) { return "", nil }
	sc.sockDestroyRunner = func(_ ScalpelTuple, _ uint32) error { return nil }
	sc.ctDelRunner = func(_ ScalpelTuple, _ uint32) error { return nil }

	var (
		mu             sync.Mutex
		hostPayloadsV4 []string
	)
	sc.iptRunner = func(family int, payload string) error {
		if family == scalpelAfInet && strings.Contains(payload, ":HNC_SCALPEL_HOST") {
			mu.Lock()
			hostPayloadsV4 = append(hostPayloadsV4, payload)
			mu.Unlock()
		}
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v6/scalpel/cut", srv.apiScalpelCut)
	mux.HandleFunc("/api/v6/scalpel/flows", srv.apiScalpelFlows)

	postCut := func(body string) (*httptest.ResponseRecorder, map[string]any) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v6/scalpel/cut", strings.NewReader(body))
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}

	// 1) 多用户系统 UID 与 isolated UID (>=90000) 必须被 409 拦截
	for _, forbiddenUID := range []int{99901000, 1001051, 90001, 99123, 99995000} {
		for _, md := range []string{"cut_once", "cut_freeze_15m"} {
			rec, _ := postCut(fmt.Sprintf(`{"scope":"host","mode":%q,"uid":%d,"proto":"tcp","src_ip":"10.0.2.15","sport":52000,"dst_ip":"198.51.100.77","dport":443}`, md, forbiddenUID))
			if rec.Code != http.StatusConflict {
				t.Fatalf("expected 409 for forbidden host UID %d mode=%s, got %d: %s", forbiddenUID, md, rec.Code, rec.Body.String())
			}
		}
	}

	// 2) 受保护包名双向配对拦截: 即使传 SDK 沙盒 20814 / 双开沙盒 99920814 也必须 409 拦截
	for _, protSandboxUID := range []int{20814, 99910814, 99920814} {
		rec, resp := postCut(fmt.Sprintf(`{"scope":"host","mode":"cut_freeze_15m","uid":%d,"proto":"tcp","src_ip":"10.0.2.15","sport":52010,"dst_ip":"198.51.100.77","dport":443}`, protSandboxUID))
		if rec.Code != http.StatusConflict || resp["reason_code"] != "host_protected_package_blocked" {
			t.Fatalf("expected 409 host_protected_package_blocked for paired protected UID %d, got %d %+v", protSandboxUID, rec.Code, resp)
		}
	}

	// 3) 反向从 SDK 沙盒连接 (uid=20245, sport=51001) 发起 cut_freeze_15m -> 必须同时写入 10245 与 20245!
	recSb, respSb := postCut(`{"scope":"host","mode":"cut_freeze_15m","proto":"tcp","src_ip":"10.0.2.15","sport":51001,"dst_ip":"198.51.100.77","dport":443}`)
	if recSb.Code != http.StatusOK {
		t.Fatalf("expected 200 OK cutting SDK sandbox flow 20245, got %d: %s", recSb.Code, recSb.Body.String())
	}
	if respSb["peer_uid"] != float64(10245) {
		t.Fatalf("expected peer_uid=10245 in response, got %+v", respSb)
	}
	// 再从主应用连接 (uid=10245, sport=51000) 对同一目标端点发起 cut_freeze_15m -> freeze_15m 原地去重不重复生规则
	recMain, _ := postCut(`{"scope":"host","mode":"cut_freeze_15m","proto":"tcp","src_ip":"10.0.2.15","sport":51000,"dst_ip":"198.51.100.77","dport":443}`)
	if recMain.Code != http.StatusOK {
		t.Fatalf("expected 200 OK cutting main app flow 10245, got %d: %s", recMain.Code, recMain.Body.String())
	}

	// 再测多用户双开应用 99910245 与非沙盒区间 30500
	recClone, _ := postCut(`{"scope":"host","mode":"cut_freeze_15m","uid":99910245,"proto":"tcp","src_ip":"10.0.2.15","sport":52088,"dst_ip":"198.51.100.88","dport":8445}`)
	rec30k, _ := postCut(`{"scope":"host","mode":"cut_freeze_15m","uid":30500,"proto":"tcp","src_ip":"10.0.2.15","sport":52089,"dst_ip":"198.51.100.89","dport":8445}`)
	if recClone.Code != http.StatusOK || rec30k.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for clone 99910245 & oem 30500, got %d / %d", recClone.Code, rec30k.Code)
	}

	mu.Lock()
	latestPayload := hostPayloadsV4[len(hostPayloadsV4)-1]
	mu.Unlock()

	for _, mustContain := range []string{
		"-A HNC_SCALPEL_HOST -m owner --uid-owner 10245 -d 198.51.100.77 -p tcp --dport 443 -j REJECT --reject-with tcp-reset",
		"-A HNC_SCALPEL_HOST -m owner --uid-owner 20245 -d 198.51.100.77 -p tcp --dport 443 -j REJECT --reject-with tcp-reset",
		"-A HNC_SCALPEL_HOST -m owner --uid-owner 99910245 -d 198.51.100.88 -p tcp --dport 8445 -j REJECT --reject-with tcp-reset",
		"-A HNC_SCALPEL_HOST -m owner --uid-owner 99920245 -d 198.51.100.88 -p tcp --dport 8445 -j REJECT --reject-with tcp-reset",
		"-A HNC_SCALPEL_HOST -m owner --uid-owner 30500 -d 198.51.100.89 -p tcp --dport 8445 -j REJECT --reject-with tcp-reset",
	} {
		if cnt := strings.Count(latestPayload, mustContain); cnt != 1 {
			t.Fatalf("expected exactly 1 occurrence of %q, got %d in:\n%s", mustContain, cnt, latestPayload)
		}
	}
	if strings.Contains(latestPayload, "--uid-owner 20500") || strings.Contains(latestPayload, "--uid-owner 40500") {
		t.Fatalf("UID 30500 outside 10000..29999 must NOT pair with 20500/40500:\n%s", latestPayload)
	}

	// 4) 验证 GET /api/v6/scalpel/flows?scope=host&uid=10245 同时覆盖 10245 与 20245 且均携带 frozen_until
	flRec := httptest.NewRecorder()
	mux.ServeHTTP(flRec, httptest.NewRequest(http.MethodGet, "/api/v6/scalpel/flows?scope=host&uid=10245", nil))
	var flResp struct {
		Total int              `json:"total"`
		Flows []map[string]any `json:"flows"`
	}
	if err := json.Unmarshal(flRec.Body.Bytes(), &flResp); err != nil {
		t.Fatal(err)
	}
	if flResp.Total != 2 {
		t.Fatalf("expected ?uid=10245 to return both 10245 and paired 20245 flows (total=2), got %+v", flResp)
	}
	for _, row := range flResp.Flows {
		if fz, _ := row["frozen_until"].(float64); fz <= 0 {
			t.Fatalf("expected paired flow row to carry frozen_until > 0, got %+v", row)
		}
	}
}

// TestWave4GuardianC058HotspotTempPrivacyIPv6ScopeAndForwardCut 验证:
// 热点下游客户端使用尚未入 macByIP 的临时隐私 IPv6 时, 双域透视与手术刀秒断均精准归属 hotspot (FORWARD -> HNC_SCALPEL),
// 绝不误归为 host 错写 OUTPUT 链导致秒断失效!
func TestWave4GuardianC058HotspotTempPrivacyIPv6ScopeAndForwardCut(t *testing.T) {
	dir := setupNativeTierTestEnv(t, "wlan2")
	for _, sub := range []string{"data", "run", "etc"} {
		_ = os.MkdirAll(filepath.Join(dir, sub), 0o755)
	}
	procDir, pkgListPath := hostConnSetupFakeHostEnv(t, dir)
	hostConnInvalidateIfaceCache()

	_ = os.WriteFile(pkgListPath, []byte("com.tencent.mm 10245 0 /data/user/0/com.tencent.mm default:targetSdkVersion=34 3003 0 1\n"), 0o644)

	// 本机 /proc/net/tcp6 仅有一条手机本机 IPv6 连接: 2409:8a00::1:53000 -> 2400:3200::1:443 (uid=10245)
	tcp6Lines := "  sl  local_address                         remote_address                        st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 008A0924000000000000000001000000:CF08 00320024000000000000000001000000:01BB 01 00000000:00000000 00:00000000 00000000 10245        0 80001 1 0 0\n"
	_ = os.WriteFile(filepath.Join(procDir, "tcp"), []byte("  sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procDir, "tcp6"), []byte(tcp6Lines), 0o644)
	_ = os.WriteFile(filepath.Join(procDir, "udp"), []byte("  sl  local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ref pointer drops\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procDir, "udp6"), []byte("  sl  local_address                         remote_address                        st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode ref pointer drops\n"), 0o644)

	// 热点处于开启态, 在线客户端 aa:bb:cc:dd:ee:88 仅登记了 IPv4 192.168.43.88 与稳定 SLAAC IPv6 2409:8a00:1234:5678::88
	nowUnix := time.Now().Unix()
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"), []byte(fmt.Sprintf(
		`{"aa:bb:cc:dd:ee:88":{"ip":"192.168.43.88","ipv6":["2409:8a00:1234:5678::88"],"hostname":"MyPad","last_seen":%d}}`,
		nowUnix,
	)), 0o644)

	// conntrack 包含:
	//   1) 本机连接 2409:8a00::1:53000 -> 2400:3200::1:443
	//   2) 同 /64 未入 macByIP 的热点临时隐私 IPv6: 2409:8a00:1234:5678:dead:beef:cafe:7777:54321 -> 2001:4860:4860::8888:443
	//   3) 全新前缀未入 macByIP 的热点临时隐私 IPv6: 2408:8200:abcd:ef01:1122:3344:5566:7788:54322 -> 2606:4700:4700::1111:443
	fakeCT := filepath.Join(dir, "run", "fake_ct_v6")
	_ = os.WriteFile(fakeCT, []byte(
		"ipv6 10 tcp 6 300 ESTABLISHED src=2409:8a00::1 dst=2400:3200::1 sport=53000 dport=443 packets=6 bytes=1200 src=2400:3200::1 dst=2409:8a00::1 sport=443 dport=53000 packets=8 bytes=4800 [ASSURED]\n"+
			"ipv6 10 tcp 6 300 ESTABLISHED src=2409:8a00:1234:5678:dead:beef:cafe:7777 dst=2001:db8:8000::88 sport=54321 dport=443 packets=12 bytes=3600 src=2001:db8:8000::88 dst=2409:8a00:1234:5678:dead:beef:cafe:7777 sport=443 dport=54321 packets=20 bytes=18000 [ASSURED]\n"+
			"ipv6 10 tcp 6 300 ESTABLISHED src=2408:8200:abcd:ef01:1122:3344:5566:7788 dst=2001:db8:9000::99 sport=54322 dport=443 packets=9 bytes=2400 src=2001:db8:9000::99 dst=2408:8200:abcd:ef01:1122:3344:5566:7788 sport=443 dport=54322 packets=15 bytes=12000 [ASSURED]\n",
	), 0o644)
	t.Setenv("HNC_CONNTRACK_PATH", fakeCT)
	ctState.mu.Lock()
	ctState.snap = nil
	ctState.mu.Unlock()

	srv := newServer(dir)
	sc := srv.v6State().scalpel
	defer sc.stopStandaloneTimer()

	origResolve := scalpelResolveBinFn
	origExec := scalpelIptExecFn
	t.Cleanup(func() {
		scalpelResolveBinFn = origResolve
		scalpelIptExecFn = origExec
	})
	scalpelResolveBinFn = func(name string) string { return "/system/bin/" + name }

	var (
		mu              sync.Mutex
		forwardHooksV6  int
		outputHooksV6   int
		hotspotPayloads []string
		hostPayloads    []string
		sockDestroyCnt  int
	)
	scalpelIptExecFn = func(_ string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		mu.Lock()
		defer mu.Unlock()
		if strings.Contains(line, "-C FORWARD -j HNC_SCALPEL") || strings.Contains(line, "-C OUTPUT -j HNC_SCALPEL_HOST") {
			return "No chain/target/match", errors.New("exit 1")
		}
		if strings.Contains(line, "-I FORWARD 1 -j HNC_SCALPEL") {
			forwardHooksV6++
		}
		if strings.Contains(line, "-I OUTPUT 1 -j HNC_SCALPEL_HOST") {
			outputHooksV6++
		}
		return "", nil
	}
	sc.sockDestroyRunner = func(_ ScalpelTuple, _ uint32) error {
		mu.Lock()
		sockDestroyCnt++
		mu.Unlock()
		return nil
	}
	sc.ctDelRunner = func(_ ScalpelTuple, _ uint32) error { return nil }
	sc.iptRunner = func(family int, payload string) error {
		if family == scalpelAfInet6 {
			mu.Lock()
			if strings.Contains(payload, ":HNC_SCALPEL ") {
				hotspotPayloads = append(hotspotPayloads, payload)
			}
			if strings.Contains(payload, ":HNC_SCALPEL_HOST ") {
				hostPayloads = append(hostPayloads, payload)
			}
			mu.Unlock()
		}
		return nil
	}

	// 1) 验证 GET /api/v6/scalpel/flows?scope=all 正交归属: 2 条临时 IPv6 全部归入 hotspot, 1 条本机连接归入 host
	flRec := httptest.NewRecorder()
	srv.apiScalpelFlows(flRec, httptest.NewRequest(http.MethodGet, "/api/v6/scalpel/flows?scope=all", nil))
	var flBody struct {
		HotspotFlows int              `json:"hotspot_flows"`
		HostFlows    int              `json:"host_flows"`
		Total        int              `json:"total"`
		Flows        []map[string]any `json:"flows"`
	}
	if err := json.Unmarshal(flRec.Body.Bytes(), &flBody); err != nil {
		t.Fatal(err)
	}
	if flBody.HotspotFlows != 2 || flBody.HostFlows != 1 || flBody.Total != 3 {
		t.Fatalf("C058 flow split mismatch: want hotspot=2 host=1 total=3, got %+v", flBody)
	}
	for _, f := range flBody.Flows {
		src := fmt.Sprint(f["src_ip"])
		gotScope := fmt.Sprint(f["scope"])
		if strings.Contains(src, "dead:beef") {
			if gotScope != "hotspot" || f["mac"] != "aa:bb:cc:dd:ee:88" {
				t.Fatalf("expected same-/64 privacy IPv6 attributed to hotspot + MyPad MAC, got %+v", f)
			}
		} else if strings.Contains(src, "1122:3344") {
			if gotScope != "hotspot" {
				t.Fatalf("expected unprefixed privacy IPv6 forwarded flow attributed to hotspot, got %+v", f)
			}
		} else if src == "2409:8a00::1" && gotScope != "host" {
			t.Fatalf("expected local socket IPv6 flow attributed to host, got %+v", f)
		}
	}

	// 2) 秒断第 1 条临时隐私 IPv6 (不传 scope/mac) + 秒断第 2 条临时隐私 IPv6 (即便前端陈旧误带 scope="host" 无 uid)
	//    两者必须全部走 FORWARD -> HNC_SCALPEL, 零 OUTPUT 污染!
	cut1 := httptest.NewRecorder()
	srv.apiScalpelCut(cut1, httptest.NewRequest(http.MethodPost, "/api/v6/scalpel/cut", strings.NewReader(
		`{"mode":"cut_freeze_15m","proto":"tcp","src_ip":"2409:8a00:1234:5678:dead:beef:cafe:7777","sport":54321,"dst_ip":"2001:db8:8000::88","dport":443}`)))
	if cut1.Code != http.StatusOK || !strings.Contains(cut1.Body.String(), `"scope":"hotspot"`) {
		t.Fatalf("expected cut1 routed to hotspot scope 200 OK, got %d: %s", cut1.Code, cut1.Body.String())
	}

	cut2 := httptest.NewRecorder()
	srv.apiScalpelCut(cut2, httptest.NewRequest(http.MethodPost, "/api/v6/scalpel/cut", strings.NewReader(
		`{"scope":"host","mode":"cut_once","proto":"tcp","src_ip":"2408:8200:abcd:ef01:1122:3344:5566:7788","sport":54322,"dst_ip":"2001:db8:9000::99","dport":443}`)))
	if cut2.Code != http.StatusOK || !strings.Contains(cut2.Body.String(), `"scope":"hotspot"`) {
		t.Fatalf("expected stale scope=host without UID on temporary IPv6 tether flow rescued to hotspot 200 OK, got %d: %s", cut2.Code, cut2.Body.String())
	}

	mu.Lock()
	gotFwdHooks := forwardHooksV6
	gotOutHooks := outputHooksV6
	gotSD := sockDestroyCnt
	lastHotspotV6 := ""
	if len(hotspotPayloads) > 0 {
		lastHotspotV6 = hotspotPayloads[len(hotspotPayloads)-1]
	}
	gotHostCnt := len(hostPayloads)
	mu.Unlock()

	if gotFwdHooks < 2 || gotOutHooks != 0 || gotSD != 0 || gotHostCnt != 0 {
		t.Fatalf("C058 chain routing error: want forwardHooks>=2, outputHooks=0, sockDestroy=0, hostPayloads=0; got fwd=%d out=%d sd=%d hp=%d",
			gotFwdHooks, gotOutHooks, gotSD, gotHostCnt)
	}
	if !strings.Contains(lastHotspotV6, "-A HNC_SCALPEL -m mac --mac-source aa:bb:cc:dd:ee:88 -d 2001:db8:8000::88 -p tcp --dport 443") ||
		!strings.Contains(lastHotspotV6, "-A HNC_SCALPEL -p tcp ! --syn -s 2408:8200:abcd:ef01:1122:3344:5566:7788 -d 2001:db8:9000::99 --sport 54322 --dport 443 -j REJECT --reject-with tcp-reset") {
		t.Fatalf("unexpected HNC_SCALPEL IPv6 payload:\n%s", lastHotspotV6)
	}
}
