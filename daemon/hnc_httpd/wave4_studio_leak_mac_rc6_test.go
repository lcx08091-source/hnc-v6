package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"hnc.io/dpid/alert"
	dpidlg "hnc.io/dpid/leakguard"
)

// TestWave4RC6_LeakGuardHostCaptureAwakeWhenHotspotOff 验证 C066:
// 热点关闭(!HotspotActive)但亮屏开启本机自抓包(run/self_capture.enabled)时,
// LeakGuard 主循环保持唤醒并实时摄取本机应用明文泄漏事件; 关闭自抓包或息屏后恢复 0 唤醒休眠。
func TestWave4RC6_LeakGuardHostCaptureAwakeWhenHotspotOff(t *testing.T) {
	s, _, dir := newV6TestMux(t)
	lg := s.v6State().leakGuard
	lg.notifyExec = func(context.Context, string, ...string) error { return nil }

	act := Activity{
		Known:         true,
		HotspotActive: false,
		ClientsOnline: 0,
		WebUIActive:   false,
		ScreenKnown:   true,
		ScreenOn:      true,
	}
	if lg.hostCaptureAwake(act) {
		t.Fatal("expected hostCaptureAwake=false when self_capture.enabled is absent")
	}

	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.selfFlagPath(), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !lg.hostCaptureAwake(act) {
		t.Fatal("expected hostCaptureAwake=true when screen is on and self_capture.enabled exists")
	}
	actScreenOff := act
	actScreenOff.ScreenOn = false
	if lg.hostCaptureAwake(actScreenOff) {
		t.Fatal("expected hostCaptureAwake=false when screen is off")
	}

	// 强制电源状态为热点关闭 + 亮屏, 启动 LeakGuard runLoop 验证不休眠并摄取本机泄漏事件
	actBlockCh := make(chan struct{})
	lg.pollInterval = 15 * time.Millisecond
	lg.activityHook = func() (<-chan struct{}, Activity, bool) {
		return actBlockCh, act, false
	}

	nowU := time.Now().Unix()
	eventsPayload := map[string]any{
		"version": 1,
		"events": []dpidlg.LeakEvent{
			{
				ID:         "ev_host_plain_rc6",
				FirstSeen:  nowU,
				LastSeen:   nowU,
				Ts:         nowU,
				Origin:     "host",
				UID:        10234,
				Pkg:        "com.example.shop",
				AppName:    "示例商城",
				DstIP:      "198.51.100.55",
				DstPort:    80,
				DstHost:    "plain-api.shop-test.example",
				Proto:      "HTTP",
				LeakType:   "TOKEN",
				RawValue:   "Bearer ****",
				RawSnippet: "Authorization: Bearer ****",
				HitCount:   1,
			},
		},
	}
	rawEv, err := json.Marshal(eventsPayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "leakguard_events.json"), rawEv, 0o600); err != nil {
		t.Fatal(err)
	}

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		lg.runLoop(stopCh)
	}()
	t.Cleanup(func() {
		select {
		case <-stopCh:
		default:
			close(stopCh)
		}
		<-doneCh
	})

	waitLeakGuardCond(t, 2*time.Second, "host plaintext event ingested while hotspot off", func() bool {
		lg.mu.Lock()
		defer lg.mu.Unlock()
		return len(lg.events) == 1 && lg.events[0].ID == "ev_host_plain_rc6"
	})
}

// TestWave4RC6_LeakGuardBothScopeRollbackAndProtectedMACFilter 验证 C042 & C068:
//  1) C042: scope="global" 扫描历史事件 MAC 时必须跳过本机受保护 AP MAC;
//  2) C068: target_scope="both" 在本机防火墙 HNC_SELF_DNS 同步失败时必须回滚前半程已写入的热点 conn_blocks 与 DNS 接管表。
func TestWave4RC6_LeakGuardBothScopeRollbackAndProtectedMACFilter(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	lg := s.v6State().leakGuard
	lg.notifyExec = func(context.Context, string, ...string) error { return nil }

	apMAC := "02:1a:2b:3c:4d:5e"
	clientMAC := "aa:bb:cc:dd:ee:42"
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "ap_mac"), []byte(apMAC+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mmWrite(t, dir, "data/devices.json", map[string]any{
		clientMAC: map[string]any{"ip": "192.168.43.42", "mac": clientMAC, "last_seen": time.Now().Unix()},
	})

	lg.mu.Lock()
	lg.events = []LeakEvent{
		{
			ID:       "ev_ap_protected",
			Ts:       time.Now().Unix(),
			MAC:      apMAC,
			DstHost:  "leak-both.evil.example",
			DstIP:    "198.51.100.188",
			LeakType: "IMEI",
		},
		{
			ID:       "ev_client_norm",
			Ts:       time.Now().Unix(),
			MAC:      clientMAC,
			DstHost:  "leak-both.evil.example",
			DstIP:    "198.51.100.188",
			LeakType: "IMEI",
		},
	}
	lg.mu.Unlock()

	// 1) C042: 热点全局封禁不得把受保护 AP MAC 塞入 conn_blocks.json
	recHot := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		`{"action":"block","dst_host":"leak-ap-guard.evil.example","mac":"","scope":"global","target_scope":"hotspot"}`)
	if recHot.Code != http.StatusOK {
		t.Fatalf("hotspot global block failed: %d %s", recHot.Code, recHot.Body.String())
	}
	for _, it := range readConnBlocks(dir).Items {
		if strings.EqualFold(it.MAC, apMAC) {
			t.Fatalf("protected AP MAC %s must NOT be written into conn_blocks.json: %+v", apMAC, it)
		}
	}

	// 2) C068: target_scope="both" 后半段本机防火墙 HNC_SELF_DNS 下发失败时回滚前半段热点封锁(含 also_ip)
	sf := s.v6State().selfFirewall
	sf.mu.Lock()
	sf.forceDataplane = true
	sf.restoreExec = func(bool, string) error {
		return fmt.Errorf("mock iptables-restore HNC_SELF_DNS lock failure")
	}
	sf.iptExec = func(bool, ...string) (string, error) {
		return "mock err", fmt.Errorf("mock iptables OUTPUT mount failure")
	}
	sf.mu.Unlock()

	beforeItems := readConnBlocks(dir).Items
	recBothFail := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		fmt.Sprintf(`{"action":"block","dst_host":"rollback-both.evil.example","also_ip":"198.51.100.199","mac":%q,"target_scope":"both"}`, clientMAC))
	if recBothFail.Code == http.StatusOK {
		t.Fatalf("expected target_scope=both to fail when selfFirewall syncDataplane fails, got 200: %s", recBothFail.Body.String())
	}
	afterItems := readConnBlocks(dir).Items
	if len(afterItems) != len(beforeItems) {
		t.Fatalf("expected hotspot conn_blocks rollback after target_scope=both host failure: before=%+v after=%+v", beforeItems, afterItems)
	}
	for _, it := range afterItems {
		if it.Value == "rollback-both.evil.example" || it.Value == "198.51.100.199" {
			t.Fatalf("leaked unrolled-back hotspot conn_block item: %+v", it)
		}
	}
	if s.dnsTK().blocked(clientMAC, "rollback-both.evil.example") {
		t.Fatal("expected DNS takeover blocklist to be rolled back after target_scope=both failure")
	}
}

// TestWave4RC6_CandidateBlocklistAdditiveAndSharedInfraGuard 验证 C071 & C073:
//  1) C071: 拒绝单条候选生成 etc/auto_expand_blocklist.json 后, data/auto_expand_blocklist.json 出厂 CDN 黑名单绝不被遮蔽清零;
//  2) C073: 候选转正、手动连接纠偏、新应用确认三条路径统一拦截 shared_infra 与共享 CDN 黑名单域名。
func TestWave4RC6_CandidateBlocklistAdditiveAndSharedInfraGuard(t *testing.T) {
	dir := t.TempDir()
	s := newServer(dir)

	factoryBlocked := map[string]any{
		"_comment": "factory shared CDN blocklist",
		"blocked_apex": []string{
			"cloudfront.net",
			"alikunlun.com",
			"cdngslb.com",
		},
	}
	mmWrite(t, dir, "data/auto_expand_blocklist.json", factoryBlocked)
	if err := os.MkdirAll(filepath.Join(dir, "data", "dpi_rules.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "dpi_rules.d", "shared_infra.txt"), []byte("alipay.com\nsnssdk.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// C071: 用户拒绝 1 条陌生 apex → 生成 etc/auto_expand_blocklist.json
	rej := actionCandidateReject(dir, map[string]string{"apex": "custom-bad-cdn.example"})
	if !rej.OK {
		t.Fatalf("actionCandidateReject failed: %+v", rej)
	}

	mergedSet := loadMergedAutoExpandBlockSet(dir)
	for _, want := range []string{"cloudfront.net", "alikunlun.com", "cdngslb.com", "custom-bad-cdn.example"} {
		if !mergedSet[want] {
			t.Fatalf("C071 regression: expected %q in merged auto_expand_blocklist, got %v", want, mergedSet)
		}
	}
	rpLoc := rpLoadLocal(dir)
	for _, want := range []string{"cloudfront.net", "alikunlun.com", "cdngslb.com", "custom-bad-cdn.example"} {
		if !rpLoc.blocked[want] {
			t.Fatalf("C071 regression: rpLoadLocal shadowed factory blocklist entry %q: %v", want, rpLoc.blocked)
		}
	}

	// C073-a: 候选转正拦截 shared_infra 与 CDN 黑名单
	for _, apex := range []string{"alipay.com", "cloudfront.net"} {
		pro := actionCandidatePromote(dir, map[string]string{"apex": apex})
		if pro.OK || pro.Error != "shared infra" {
			t.Fatalf("expected actionCandidatePromote(%q) to fail with shared infra, got %+v", apex, pro)
		}
	}

	// C073-b: 手动连接纠偏拦截 shared_infra 域名(返回提示且不落盘污染域名规则)
	corr := actionDPICorrect(s, map[string]string{
		"app_id":   "taobao",
		"app_name": "淘宝",
		"category": "shopping",
		"name":     "mdap.alipay.com",
		"kinds":    "domain",
	})
	if corr.OK {
		t.Fatalf("expected actionDPICorrect on shared_infra domain only to refuse saving rule, got %+v", corr)
	}
	if !strings.Contains(corr.Detail, "公共基础设施") {
		t.Fatalf("expected shared infra note in actionDPICorrect detail, got %+v", corr)
	}

	// C073-c: 新应用确认拦截 shared_infra 后缀
	disc := actionDiscoverConfirm(s, map[string]string{
		"id":       "toutiao_custom",
		"name":     "自定义应用",
		"category": "news",
		"suffixes": "log.snssdk.com,cloudfront.net",
	})
	if disc.OK || disc.Error != "shared infra" {
		t.Fatalf("expected actionDiscoverConfirm on shared infra suffixes to fail with shared infra, got %+v", disc)
	}
}

// TestWave4RC6_SelfStudioModePreservesFlagsStopsQuietTimerAndOptIn 验证 C072:
//  1) 切换 smart_screen / lease_15m 保留用户设定的 auto_expand / auto_promote, 不重置覆盖;
//  2) 开启模式写 data/self_capture.optin 持久化意向, 切回 off 立即停掉 studioQuietTimer 并清理 optin。
func TestWave4RC6_SelfStudioModePreservesFlagsStopsQuietTimerAndOptIn(t *testing.T) {
	dir := t.TempDir()
	s := newServer(dir)

	resetStudioGlobals := func() {
		studioMu.Lock()
		if studioStopTimer != nil {
			studioStopTimer.Stop()
			studioStopTimer = nil
		}
		if studioQuietTimer != nil {
			studioQuietTimer.Stop()
			studioQuietTimer = nil
		}
		studioLoadedDir = ""
		studioPolicy = selfStudioPolicy{}
		studioDistilling = false
		studioMu.Unlock()
	}
	resetStudioGlobals()
	t.Cleanup(resetStudioGlobals)

	r1 := actionSelfStudioStart(s, map[string]string{
		"mode":         "smart_screen",
		"auto_expand":  "false",
		"auto_promote": "false",
	})
	if !r1.OK {
		t.Fatalf("smart_screen start failed: %+v", r1)
	}
	if _, err := os.Stat(selfOptInPath(dir)); err != nil {
		t.Fatalf("expected self_capture.optin to exist when mode != off: %v", err)
	}

	// 切到 lease_15m 再切回 smart_screen, 均不传 auto_expand/auto_promote, 原 false 配置必须保持
	r2 := actionSelfStudioStart(s, map[string]string{"mode": "lease_15m", "auto_stop_min": "5"})
	if !r2.OK {
		t.Fatalf("lease_15m start failed: %+v", r2)
	}
	studioMu.Lock()
	if studioPolicy.AutoExpand || studioPolicy.AutoPromote {
		studioMu.Unlock()
		t.Fatalf("switching to lease_15m reset AutoExpand/AutoPromote: %+v", studioPolicy)
	}
	studioMu.Unlock()

	r3 := actionSelfStudioStart(s, map[string]string{"mode": "smart_screen"})
	if !r3.OK {
		t.Fatalf("switch back to smart_screen failed: %+v", r3)
	}
	studioMu.Lock()
	if studioPolicy.AutoExpand || studioPolicy.AutoPromote {
		studioMu.Unlock()
		t.Fatalf("switching to smart_screen reset AutoExpand/AutoPromote: %+v", studioPolicy)
	}
	// 挂载一个未到期的 studioQuietTimer, 验证切 off 时立即停止并清零
	quietFired := false
	studioQuietTimer = time.AfterFunc(10*time.Second, func() { quietFired = true })
	studioMu.Unlock()

	rOff := actionSelfStudioStart(s, map[string]string{"mode": "off"})
	if !rOff.OK {
		t.Fatalf("mode=off failed: %+v", rOff)
	}
	studioMu.Lock()
	hasQuiet := studioQuietTimer != nil
	studioMu.Unlock()
	if hasQuiet || quietFired {
		t.Fatalf("expected studioQuietTimer stopped and nilled on mode=off (hasQuiet=%v quietFired=%v)", hasQuiet, quietFired)
	}
	if _, err := os.Stat(selfOptInPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("expected self_capture.optin removed on mode=off, err=%v", err)
	}
}

// TestWave4RC6_MACAliasConcurrentRMWAndDuplicateMergeGuard 验证 C016 & 重复合并快照保护:
//  1) 在 s.actionMu 内拦截对已合并 from_mac 的重复合并(含 force=true), 绝不用空 FromSnap 覆盖原归档快照;
//  2) 多协程并发执行 commitMACAliasStep / removeMACAliasFrom / loadMACAliasesWithTsSnapshot 零丢写零竞态。
func TestWave4RC6_MACAliasConcurrentRMWAndDuplicateMergeGuard(t *testing.T) {
	dir, s, _ := mmFixture(t)

	// 首次正常合并 mmOld -> mmNew
	r1 := dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew}, false)
	if !r1.OK {
		t.Fatalf("initial device_merge failed: %+v", r1)
	}
	arch1 := findMacMergeArchive(dir, mmOld, mmNew, time.Now().Unix())
	if arch1 == nil || arch1.FromSnap.DeviceName != "小明的手机" || !arch1.FromSnap.Rule.Limit {
		t.Fatalf("expected intact archive after first merge, got %+v", arch1)
	}

	// 重复合并(无论 force=false 还是 force=true)均须被 aliases[from] 守卫拦截
	for _, forceVal := range []string{"false", "true"} {
		rDup := dispatchAction(s, "device_merge", map[string]string{"from_mac": mmOld, "to_mac": mmNew, "force": forceVal}, false)
		if rDup.OK || rDup.Error != "conflict" {
			t.Fatalf("expected duplicate device_merge(force=%s) to return conflict, got %+v", forceVal, rDup)
		}
	}

	// 验证原归档快照未被空状态覆盖, 随后无损拆分仍能 100% 还原旧设备名称与规则
	archAfterDup := findMacMergeArchive(dir, mmOld, mmNew, time.Now().Unix())
	if archAfterDup == nil || archAfterDup.FromSnap.DeviceName != "小明的手机" || !archAfterDup.FromSnap.Rule.Limit {
		t.Fatalf("duplicate merge corrupted FromSnap archive: %+v", archAfterDup)
	}
	rUn := dispatchAction(s, "device_unmerge", map[string]string{"from_mac": mmOld, "to_mac": mmNew}, false)
	if !rUn.OK {
		t.Fatalf("device_unmerge after rejected duplicate merge failed: %+v", rUn)
	}
	if gotName := mmRead(t, dir, "data/device_names.json")[mmOld]; gotName != "小明的手机" {
		t.Fatalf("expected mmOld device name restored to 小明的手机, got %v", gotName)
	}

	// C016: 并发 RMW 压测 macAliasMu
	aliasDir := t.TempDir()
	nowU := time.Now().Unix()
	const workers = 16
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			oldM := fmt.Sprintf("02:aa:bb:cc:01:%02x", i)
			newM := fmt.Sprintf("da:aa:bb:cc:02:%02x", i)
			if _, err := commitMACAliasStep(aliasDir, oldM, newM, nowU); err != nil {
				t.Errorf("commitMACAliasStep(%d): %v", i, err)
				return
			}
			_, _ = loadMACAliasesWithTsSnapshot(aliasDir)
			pruneMACAliases(aliasDir, nowU)
			if i%2 == 1 {
				if err := removeMACAliasFrom(aliasDir, oldM, nowU); err != nil {
					t.Errorf("removeMACAliasFrom(%d): %v", i, err)
				}
			}
		}()
	}
	wg.Wait()

	finalAl, finalTs := loadMACAliasesWithTsSnapshot(aliasDir)
	for i := 0; i < workers; i++ {
		oldM := fmt.Sprintf("02:aa:bb:cc:01:%02x", i)
		newM := fmt.Sprintf("da:aa:bb:cc:02:%02x", i)
		if i%2 == 0 {
			if finalAl[oldM] != newM || finalTs[oldM] != nowU {
				t.Fatalf("concurrent RMW lost even alias %d: got=%q ts=%d", i, finalAl[oldM], finalTs[oldM])
			}
		} else if _, exists := finalAl[oldM]; exists {
			t.Fatalf("concurrent RMW left removed odd alias %d: %q", i, finalAl[oldM])
		}
	}
}

// TestWave4RC6_RMACPolicyClientIsolationErrorAndSerialAsyncWake 验证 C011, C017 & C083:
//  1) C011: client_isolation 走 rulesStore.SetTop 并校验脚本/写盘错误, 严禁吞错;
//  2) C017: 持 s.actionMu 调 rmac_policy_set 经单缓冲 channel 非阻塞唤醒(不反拿 rmacReconcileMu), AutoInherited 在 s.actionMu 内原子写入;
//  3) C083: restoreKnownDevicesAfterUnmerge 严格遵守 data/.known_devices.lock 跨进程/跨协程 flock。
func TestWave4RC6_RMACPolicyClientIsolationErrorAndSerialAsyncWake(t *testing.T) {
	// 1) C011: 正常写入 rulesStore + 脚本失败错误透传
	t.Run("client_isolation_rulesStore_and_error_check", func(t *testing.T) {
		dir := t.TempDir()
		s := newServer(dir)

		respOK := dispatchAction(s, "rmac_policy_set", map[string]string{"client_isolation": "true"}, true)
		if !respOK.OK {
			t.Fatalf("rmac_policy_set client_isolation=true failed: %+v", respOK)
		}
		gotTop, err := rulesStore.GetTop(dir, "client_isolation_enabled")
		if err != nil || gotTop != "true" {
			t.Fatalf("expected rulesStore client_isolation_enabled=true, got %q err=%v", gotTop, err)
		}

		// 注入失败的 json_set.sh 桩验证 C011 不吞错
		binDir := filepath.Join(dir, "bin")
		if err := os.MkdirAll(binDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(binDir, "json_set.sh"), []byte("#!/system/bin/sh\necho 'disk full' >&2\nexit 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		respFail := dispatchAction(s, "rmac_policy_set", map[string]string{"client_isolation": "false"}, true)
		if respFail.OK || respFail.Error != "write failed" {
			t.Fatalf("expected write failed when json_set.sh fails, got %+v", respFail)
		}
	})

	// 2) C017: 严守锁序 rmacReconcileMu -> s.actionMu, 单缓冲 channel 异步串行唤醒 + s.actionMu 内写 AutoInherited
	t.Run("lock_order_no_inversion_and_serial_wake", func(t *testing.T) {
		dir, s, _ := mmFixture(t)
		now := time.Now()
		mmWrite(t, dir, "data/devices.json", map[string]any{
			mmNew: map[string]any{"ip": "192.168.43.31", "mac": mmNew, "last_seen": now.Unix()},
		})
		macMergeMu.Lock()
		mf := loadMacMergeFile(dir)
		mf.Bootstrapped = true
		mf.Profiles[mmOld] = &macProfile{FirstSeen: now.Unix() - 600, LastSeen: now.Unix() - 180, DHCPName: "Xiaoming-Mi-10"}
		mf.Profiles[mmNew] = &macProfile{FirstSeen: now.Unix() - 10, LastSeen: now.Unix(), DHCPName: "Xiaoming-Mi-10", New: true}
		mf.Suggestions[mmNew] = []macMergeCand{{OldMAC: mmOld, Score: 93, Reasons: []string{"DHCP 主机名相同"}, Ts: now.Unix()}}
		_ = saveMacMergeFile(dir, mf)
		macMergeMu.Unlock()

		// 人为持住 rmacReconcileMu, 同时经 dispatchAction(持 s.actionMu) 调用 rmac_policy_set:
		// 若内部反拿 rmacReconcileMu 必死锁超时; 单缓冲 channel 非阻塞投递则微秒级立即返回!
		rmacReconcileMu.Lock()
		doneAction := make(chan actionResp, 1)
		go func() {
			doneAction <- dispatchAction(s, "rmac_policy_set", map[string]string{
				"auto_inherit":       "true",
				"auto_inherit_score": "85",
			}, true)
		}()

		select {
		case r := <-doneAction:
			if !r.OK {
				rmacReconcileMu.Unlock()
				t.Fatalf("rmac_policy_set failed: %+v", r)
			}
		case <-time.After(1500 * time.Millisecond):
			rmacReconcileMu.Unlock()
			t.Fatal("DEADLOCK: dispatchAction(s.actionMu) blocked on rmacReconcileMu!")
		}

		// 释放 rmacReconcileMu 后, 单缓冲后台串行协程自动消费唤醒信号完成无感继承并落盘 AutoInherited
		rmacReconcileMu.Unlock()

		waitLeakGuardCond(t, 2*time.Second, "async rmacReconcile auto-inherit completion", func() bool {
			al := loadMACAliases(dir)
			rmacMu.Lock()
			st := loadRMACState(dir)
			rmacMu.Unlock()
			rec, hasAuto := st.AutoInherited[mmNew]
			return al[mmOld] == mmNew && hasAuto && rec.OldMAC == mmOld && rec.Score == 93
		})
	})

	// 3) C083: known_devices.json 还原严格遵守 .known_devices.lock flock
	t.Run("known_devices_restore_respects_flock", func(t *testing.T) {
		dir := t.TempDir()
		cfg := alert.NewConfig(dir)
		if err := os.MkdirAll(filepath.Dir(cfg.KnownDevicesPath), 0o755); err != nil {
			t.Fatal(err)
		}
		otherMAC := "11:22:33:44:55:99"
		if err := alert.MarkKnown(cfg, otherMAC); err != nil {
			t.Fatal(err)
		}

		lockPath := filepath.Join(filepath.Dir(cfg.KnownDevicesPath), ".known_devices.lock")
		extLockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer extLockFile.Close()
		if err := syscall.Flock(int(extLockFile.Fd()), syscall.LOCK_EX); err != nil {
			t.Fatal(err)
		}

		restoreDone := make(chan struct{})
		go func() {
			defer close(restoreDone)
			restoreKnownDevicesAfterUnmerge(
				dir,
				mmOld,
				macDeviceSnap{KnownExisted: true, KnownFirstSeen: 100, KnownMarkedAt: 200},
				mmNew,
				macDeviceSnap{KnownExisted: false},
			)
		}()

		select {
		case <-restoreDone:
			_ = syscall.Flock(int(extLockFile.Fd()), syscall.LOCK_UN)
			t.Fatal("restoreKnownDevicesAfterUnmerge bypassed .known_devices.lock flock!")
		case <-time.After(60 * time.Millisecond):
		}

		if err := syscall.Flock(int(extLockFile.Fd()), syscall.LOCK_UN); err != nil {
			t.Fatal(err)
		}

		select {
		case <-restoreDone:
		case <-time.After(2 * time.Second):
			t.Fatal("restoreKnownDevicesAfterUnmerge did not complete after releasing .known_devices.lock")
		}

		exOld, fsOld, mkOld := readKnownDeviceSnap(dir, mmOld)
		exOther, _, mkOther := readKnownDeviceSnap(dir, otherMAC)
		if !exOld || fsOld != 100 || mkOld != 200 || !exOther || mkOther == 0 {
			t.Fatalf("known_devices ledger mismatch after flock restore: old=(%v,%d,%d) other=(%v,%d)",
				exOld, fsOld, mkOld, exOther, mkOther)
		}
	})
}
