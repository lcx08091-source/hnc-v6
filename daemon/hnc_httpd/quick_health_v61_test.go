package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const testAdminHexSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func setupQuickHealthTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"data", "data/.json_backups", "run", "bin", "logs"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteQH := func(rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteQH("module.prop", "id=hotspot_net_ctl\nversion=v6.1.0-beta.2\nversionCode=6009202\n")
	mustWriteQH("run/local_admin.secret", testAdminHexSecret+"\n")
	mustWriteQH("run/power_stats.json", `{"total":{"cpu_sec_per_hour":3.2,"wakeups_per_min":0.5}}`)
	mustWriteQH("run/fake_ip_forward_default", "1\n")
	mustWriteQH("data/rules.json", `{"version":1,"auth_required":true,"whitelist_mode":false,"clsact_bpf_mode":"auto","devices":{},"blacklist":[],"whitelist":[]}`)
	mustWriteQH("data/devices.json", `{}`)

	prevIPFwd := defaultQuickHealthIPForwardPath
	defaultQuickHealthIPForwardPath = filepath.Join(dir, "run", "fake_ip_forward_default")
	t.Cleanup(func() {
		defaultQuickHealthIPForwardPath = prevIPFwd
	})
	return dir
}

func TestQuickHealthEndpointAllGreenAndZeroGoroutineLeak(t *testing.T) {
	dir := setupQuickHealthTestDir(t)
	s := newServer(dir)
	h := s.handler()

	// 1. 未带本机密钥的匿名请求必须被拦截 (401), 证明敏感读白名单保护生效
	unauthReq := httptest.NewRequest(http.MethodGet, "/api/health_check", nil)
	unauthReq.RemoteAddr = "127.0.0.1:54321"
	unauthRec := httptest.NewRecorder()
	h.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET /api/health_check code=%d, want 401", unauthRec.Code)
	}

	// 2. 非 GET 请求返回 405
	postReq := httptest.NewRequest(http.MethodPost, "/api/health_check", nil)
	postReq.RemoteAddr = "127.0.0.1:54321"
	postReq.Header.Set("X-HNC-Local-Admin", testAdminHexSecret)
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/health_check code=%d, want 405", postRec.Code)
	}

	// 3. 记录前后 goroutine 数量, 证明请求纯按需执行、0 后台 goroutine 驻留
	baseG := runtime.NumGoroutine()
	req := httptest.NewRequest(http.MethodGet, "/api/health_check", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-HNC-Local-Admin", testAdminHexSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/health_check code=%d body=%s", rec.Code, rec.Body.String())
	}
	afterG := runtime.NumGoroutine()
	if afterG > baseG {
		t.Fatalf("goroutines grew after GET /api/health_check: before=%d after=%d", baseG, afterG)
	}

	// 4. 校验原始 JSON 顶层字段与 4 项体检卡全部必需键存在且完好
	var rawMap map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rawMap); err != nil {
		t.Fatalf("decode raw map: %v", err)
	}
	for _, topKey := range []string{"ok", "checked_at", "duration_ms", "overall", "headline", "subline", "items"} {
		if _, exists := rawMap[topKey]; !exists {
			t.Errorf("top-level JSON missing key %q", topKey)
		}
	}
	rawItems, ok := rawMap["items"].([]any)
	if !ok || len(rawItems) != 4 {
		t.Fatalf("items len=%d, want 4", len(rawItems))
	}
	wantIDs := []string{"hotspot_forward", "zero_wakeup_power", "shaping_offload", "tmpfs_config"}
	for idx, itAny := range rawItems {
		im, ok := itAny.(map[string]any)
		if !ok {
			t.Fatalf("item[%d] is not JSON object", idx)
		}
		for _, k := range []string{
			"id", "title", "status", "badge", "verdict", "detail",
			"fix_kind", "fix_label", "fix_action", "fix_params", "nav_target", "metrics",
		} {
			if _, exists := im[k]; !exists {
				t.Errorf("item[%d] missing required key %q", idx, k)
			}
		}
		if im["id"] != wantIDs[idx] {
			t.Errorf("item[%d].id=%v, want %q", idx, im["id"], wantIDs[idx])
		}
		if im["status"] != "ok" {
			t.Errorf("item[%d](%s) status=%v, want ok (detail=%v)", idx, wantIDs[idx], im["status"], im["detail"])
		}
	}
	if rawMap["overall"] != "ok" {
		t.Errorf("overall=%v, want ok", rawMap["overall"])
	}

	// 5. 校验平台真实 Statfs 可正常读取 run 目录
	stInfo, err := queryDirStatfsPlatform(filepath.Join(dir, "run"))
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		if err != nil || !stInfo.Supported || stInfo.TotalBytes == 0 {
			t.Errorf("queryDirStatfsPlatform failed on linux: info=%+v err=%v", stInfo, err)
		}
	}
}

func TestQuickHealthDegradedAndFailureBranches(t *testing.T) {
	dir := setupQuickHealthTestDir(t)
	now := time.Unix(1780000100, 0)

	// 写入活跃热点与受控设备规则
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{
		"version":1,
		"clsact_bpf_mode":"off",
		"devices":{"aa:bb:cc:dd:ee:01":{"down_mbps":20,"limit_enabled":true}},
		"blacklist":[]
	}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"), []byte(`{
		"aa:bb:cc:dd:ee:01":{"ip":"192.168.43.18","last_seen":1780000090}
	}`), 0o600)

	ipFwdFile := filepath.Join(dir, "ip_forward")
	_ = os.WriteFile(ipFwdFile, []byte("0\n"), 0o600)

	// 高耗电 power_stats + 硬件加速抢跑 offload_guard + 32M tmpfs 空间告急
	_ = os.WriteFile(filepath.Join(dir, "run", "power_stats.json"), []byte(`{
		"total":{"cpu_sec_per_hour":410.5,"wakeups_per_min":95.2}
	}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "run", "offload_guard.json"), []byte(`{
		"offload_state":"ACTIVE","fallback":0
	}`), 0o600)

	s := newServer(dir)
	env := quickHealthEnv{
		Now:           func() time.Time { return now },
		IPForwardPath: ipFwdFile,
		IfaceIPv4:     func(iface string) string { return "192.168.43.1" },
		Statfs: func(path string) (quickStatfsInfo, error) {
			total := uint64(32 << 20)
			used := uint64(30 << 20) // ~93.75% >= 92% fail
			return quickStatfsInfo{
				Supported:  true,
				FSType:     0x01021994,
				IsTmpfs:    true,
				TotalBytes: total,
				UsedBytes:  used,
				FreeBytes:  total - used,
			}, nil
		},
	}

	rep := s.buildQuickHealthReport(env)
	if rep.Overall != "fail" {
		t.Fatalf("overall=%q, want fail", rep.Overall)
	}
	byID := map[string]QuickHealthCheckItem{}
	for _, it := range rep.Items {
		byID[it.ID] = it
	}

	if g := byID["hotspot_forward"]; g.Status != "fail" || g.FixKind != "action" || g.FixAction != "refresh" {
		t.Errorf("hotspot_forward = %+v", g)
	}
	if g := byID["zero_wakeup_power"]; g.Status != "fail" || g.FixKind != "nav" || g.NavTarget != "stats" {
		t.Errorf("zero_wakeup_power = %+v", g)
	}
	if g := byID["shaping_offload"]; g.Status != "warn" || g.FixKind != "action" || g.FixAction != "clsact_mode_set" {
		t.Errorf("shaping_offload = %+v", g)
	}
	if g := byID["tmpfs_config"]; g.Status != "fail" || g.FixKind != "action" || g.FixAction != "cache_clear" {
		t.Errorf("tmpfs_config = %+v", g)
	}

	// 再测: ip_forward=1 + watchdog_passive + tc_repair_fail_count=4 + 未挂 tmpfs (warn)
	_ = os.WriteFile(ipFwdFile, []byte("1\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "run", "watchdog_passive.marker"), []byte("1\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "run", "tc_repair_fail_count"), []byte("4\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "run", "power_stats.json"), []byte(`{"total":{"cpu_sec_per_hour":12.0,"wakeups_per_min":2.0}}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "run", "watchdog_actions.json"), []byte(`{"actions":{"tc_sync":{"calls_1h":10,"fails_1h":2}}}`), 0o600)
	s.invalidateServerJSONCaches()

	env.EnforceTmpfs = true
	env.Statfs = func(path string) (quickStatfsInfo, error) {
		return quickStatfsInfo{
			Supported:  true,
			FSType:     0xef53, // ext4, not tmpfs
			IsTmpfs:    false,
			TotalBytes: 64 << 30,
			UsedBytes:  10 << 30,
			FreeBytes:  54 << 30,
		}, nil
	}

	rep2 := s.buildQuickHealthReport(env)
	byID2 := map[string]QuickHealthCheckItem{}
	for _, it := range rep2.Items {
		byID2[it.ID] = it
	}
	if g := byID2["hotspot_forward"]; g.Status != "warn" || g.FixAction != "restart_service" {
		t.Errorf("passive watchdog card = %+v", g)
	}
	if g := byID2["zero_wakeup_power"]; g.Status != "warn" || g.NavTarget != "stats" {
		t.Errorf("watchdog fails power card = %+v", g)
	}
	if g := byID2["shaping_offload"]; g.Status != "fail" || g.FixAction != "dataplane_verify_run" || g.FixParams["resync"] != "1" {
		t.Errorf("tc_repair_fail shaping card = %+v", g)
	}
	if g := byID2["tmpfs_config"]; g.Status != "warn" || g.FixAction != "restart_service" {
		t.Errorf("non-tmpfs card = %+v", g)
	}
}

func TestQuickHealthJSONDoctorRepairActionAndCacheInvalidation(t *testing.T) {
	dir := setupQuickHealthTestDir(t)
	s := newServer(dir)
	h := s.handler()

	// 预热缓存: rules.json 初始含 remote_enabled=false
	rulesPath := filepath.Join(dir, "data", "rules.json")
	if _, err := s.jsonCache.read(rulesPath); err != nil {
		t.Fatalf("warm jsonCache: %v", err)
	}

	// 准备完好备份与假 json_doctor.sh 脚本
	goodRules := `{"version":1,"auth_required":true,"whitelist_mode":true,"remote_enabled":false,"devices":{},"blacklist":[],"whitelist":[]}`
	bakPath := filepath.Join(dir, "data", ".json_backups", "rules.json.1.bak")
	if err := os.WriteFile(bakPath, []byte(goodRules), 0o600); err != nil {
		t.Fatal(err)
	}
	doctorScript := "#!/bin/sh\n" +
		"if [ \"$1\" != \"repair\" ]; then exit 2; fi\n" +
		"cp \"" + bakPath + "\" \"" + rulesPath + "\"\n" +
		"echo \"repair complete: repaired=1 failed=0\"\n"
	if err := os.WriteFile(filepath.Join(dir, "bin", "json_doctor.sh"), []byte(doctorScript), 0o755); err != nil {
		t.Fatal(err)
	}

	// 故意写坏 data/rules.json
	if err := os.WriteFile(rulesPath, []byte("{corrupt-json"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. 体检必须捕获 JSON 损坏并指向 json_doctor_repair
	repBad := s.buildQuickHealthReport(defaultQuickHealthEnv())
	if repBad.Overall != "fail" {
		t.Fatalf("expected fail on corrupt rules.json, got %q", repBad.Overall)
	}
	var tmpfsCard QuickHealthCheckItem
	for _, it := range repBad.Items {
		if it.ID == "tmpfs_config" {
			tmpfsCard = it
		}
	}
	if tmpfsCard.Status != "fail" || tmpfsCard.FixKind != "action" || tmpfsCard.FixAction != "json_doctor_repair" {
		t.Fatalf("unexpected tmpfs_config card on corrupt json: %+v", tmpfsCard)
	}

	// 2. 通过 POST /api/action 执行 json_doctor_repair
	actBody := bytes.NewBufferString(`{"action":"json_doctor_repair","params":{}}`)
	actReq := httptest.NewRequest(http.MethodPost, "/api/action", actBody)
	actReq.RemoteAddr = "127.0.0.1:54321"
	actReq.Header.Set("Content-Type", "application/json")
	actReq.Header.Set("X-HNC-CSRF", "1")
	actReq.Header.Set("X-HNC-Local-Admin", testAdminHexSecret)
	actRec := httptest.NewRecorder()
	h.ServeHTTP(actRec, actReq)
	if actRec.Code != http.StatusOK {
		t.Fatalf("POST /api/action json_doctor_repair code=%d body=%s", actRec.Code, actRec.Body.String())
	}
	var actOut actionResp
	if err := json.Unmarshal(actRec.Body.Bytes(), &actOut); err != nil || !actOut.OK {
		t.Fatalf("unexpected actionResp: %+v err=%v", actOut, err)
	}

	// 3. 验证缓存已刷新为备份中的 whitelist_mode=true 且体检恢复 ok
	afterRaw, err := s.jsonCache.read(rulesPath)
	if err != nil {
		t.Fatalf("read restored rules.json: %v", err)
	}
	if m, _ := afterRaw.(map[string]any); m["whitelist_mode"] != true {
		t.Fatalf("restored rules.json not reflected after cache clear: %+v", m)
	}
	repGood := s.buildQuickHealthReport(defaultQuickHealthEnv())
	if repGood.Overall != "ok" {
		t.Fatalf("expected overall=ok after repair, got %q (%s)", repGood.Overall, repGood.Headline)
	}
}

func TestQuickHealthUnifiedVersionAndComponentVersions(t *testing.T) {
	// 断言顶层默认初始值保持不变(兼容 TestCompatReportRedaction)
	if version != "dev" || versionCode != "0" {
		t.Fatalf("unexpected default globals: version=%q versionCode=%q", version, versionCode)
	}

	dir := setupQuickHealthTestDir(t)
	_ = os.WriteFile(filepath.Join(dir, "run", "dpi_state.json"), []byte(`{"version":"0.6.1-dpid-shm"}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "run", "watchdog_actions.json"), []byte(`{"schema":1,"version":"0.6.1-watchdog","actions":{}}`), 0o600)

	if got := ServerVersion(dir); got != "v6.1.0-beta.2" {
		t.Fatalf("ServerVersion(dir)=%q, want v6.1.0-beta.2", got)
	}
	if got := ServerVersionCode(dir); got != "6009202" {
		t.Fatalf("ServerVersionCode(dir)=%q, want 6009202", got)
	}

	// 验证 moduleDir(hncDir)/module.prop 回退链路
	subHNC := t.TempDir()
	modDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(subHNC, "run"), 0o755)
	_ = os.WriteFile(filepath.Join(subHNC, "run", "service.path"), []byte(modDir+"\n"), 0o600)
	_ = os.WriteFile(filepath.Join(modDir, "module.prop"), []byte("version=v6.1.0-rc1\nversionCode=6010001\n"), 0o644)
	if got := ServerVersion(subHNC); got != "v6.1.0-rc1" {
		t.Fatalf("ServerVersion fallback via service.path=%q, want v6.1.0-rc1", got)
	}
	if got := ServerVersionCode(subHNC); got != "6010001" {
		t.Fatalf("ServerVersionCode fallback via service.path=%q, want 6010001", got)
	}

	s := newServer(dir)
	if s.dpidVersion() != "0.6.1-dpid-shm" {
		t.Fatalf("dpidVersion=%q, want 0.6.1-dpid-shm", s.dpidVersion())
	}
	if s.watchdogVersion() != "0.6.1-watchdog" {
		t.Fatalf("watchdogVersion=%q, want 0.6.1-watchdog", s.watchdogVersion())
	}

	// 验证 dpi_state.json 缺失 version 时自动回退 capabilities.json["dpid_version"]
	_ = os.WriteFile(filepath.Join(dir, "run", "dpi_state.json"), []byte(`{}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "run", "capabilities.json"), []byte(`{"tc_htb":true,"dpid_version":"0.6.1-cap-fallback"}`), 0o600)
	s.invalidateServerJSONCaches()
	if s.dpidVersion() != "0.6.1-cap-fallback" {
		t.Fatalf("dpidVersion fallback=%q, want 0.6.1-cap-fallback", s.dpidVersion())
	}

	// 验证 /api/health
	recHealth := httptest.NewRecorder()
	s.apiHealth(recHealth, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	var healthOut map[string]any
	_ = json.Unmarshal(recHealth.Body.Bytes(), &healthOut)
	if healthOut["version"] != "v6.1.0-beta.2" || healthOut["version_code"] != "6009202" {
		t.Errorf("/api/health = %+v", healthOut)
	}

	// 验证 /api/metrics 保留 compat="hotfix16.8-live-api" 且统一 backend_version
	recMetrics := httptest.NewRecorder()
	s.apiMetrics(recMetrics, httptest.NewRequest(http.MethodGet, "/api/metrics", nil))
	var metricsOut map[string]any
	_ = json.Unmarshal(recMetrics.Body.Bytes(), &metricsOut)
	if metricsOut["backend_version"] != "v6.1.0-beta.2" || metricsOut["compat"] != "hotfix16.8-live-api" {
		t.Errorf("/api/metrics = %+v", metricsOut)
	}

	// 验证 /api/live
	recLive := httptest.NewRecorder()
	s.apiLive(recLive, httptest.NewRequest(http.MethodGet, "/api/live", nil))
	var liveOut map[string]any
	_ = json.Unmarshal(recLive.Body.Bytes(), &liveOut)
	if liveOut["backend_version"] != "v6.1.0-beta.2" || liveOut["backend_version_code"] != "6009202" {
		t.Errorf("/api/live = %+v", liveOut)
	}

	// 验证 CoreHub WorldSnapshot & BuildCoreDiagDump
	snap := s.CoreHub().RefreshSnapshotNow()
	if snap.Version != "v6.1.0-beta.2" || snap.VersionCode != "6009202" ||
		snap.DPIDVersion != "0.6.1-cap-fallback" || snap.WatchdogVersion != "0.6.1-watchdog" {
		t.Errorf("WorldSnapshot versions = %+v", snap)
	}
	dump := s.BuildCoreDiagDump()
	if dump.Version != "v6.1.0-beta.2" || dump.VersionCode != "6009202" || strings.Contains(dump.Note, "v6.0") {
		t.Errorf("BuildCoreDiagDump = %+v", dump)
	}

	// 验证 /api/selfcheck 外层版本透出 (无缓存态)
	resetSelfcheckState()
	t.Cleanup(resetSelfcheckState)
	recSC := httptest.NewRecorder()
	s.apiSelfcheck(recSC, httptest.NewRequest(http.MethodGet, "/api/selfcheck", nil))
	var scOut map[string]any
	_ = json.Unmarshal(recSC.Body.Bytes(), &scOut)
	if scOut["version"] != "v6.1.0-beta.2" || scOut["version_code"] != "6009202" ||
		scOut["dpid_version"] != "0.6.1-cap-fallback" || scOut["watchdog_version"] != "0.6.1-watchdog" {
		t.Errorf("/api/selfcheck outer versions = %+v", scOut)
	}

	// 验证 /api/discover 补 version 且无 v5.15 硬编码
	recDisc := httptest.NewRecorder()
	s.apiDiscover(recDisc, httptest.NewRequest(http.MethodGet, "/api/discover", nil))
	var discOut map[string]any
	_ = json.Unmarshal(recDisc.Body.Bytes(), &discOut)
	if discOut["version"] != "v6.1.0-beta.2" {
		t.Errorf("/api/discover version = %v", discOut["version"])
	}
}

func TestQuickHealthRC2Tmpfs32MAndPublicDNSGuard(t *testing.T) {
	dir := setupQuickHealthTestDir(t)
	ipFwdFile := filepath.Join(dir, "run", "fake_ip_forward")
	_ = os.WriteFile(ipFwdFile, []byte("1\n"), 0o600)
	s := newServer(dir)

	// 1. 32MB tmpfs with 20MB used (12MB free = 37.5% >= 15% and >= 4MB) must be ok, NOT false-alarm warn!
	env := quickHealthEnv{
		Now:           time.Now,
		IPForwardPath: ipFwdFile,
		IfaceIPv4:     func(string) string { return "192.168.43.1" },
		EnforceTmpfs:  true,
		Statfs: func(string) (quickStatfsInfo, error) {
			total := uint64(32 << 20)
			used := uint64(20 << 20)
			return quickStatfsInfo{
				Supported: true, FSType: 0x01021994, IsTmpfs: true,
				TotalBytes: total, UsedBytes: used, FreeBytes: total - used,
			}, nil
		},
	}
	repOK := s.buildQuickHealthReport(env)
	for _, it := range repOK.Items {
		if it.ID == "tmpfs_config" && it.Status != "ok" {
			t.Fatalf("32MB tmpfs with 12MB free should be ok, got %+v", it)
		}
	}

	// 2. 32MB tmpfs with 3.5MB free (< 4MB / < 15%) must trigger warn
	env.Statfs = func(string) (quickStatfsInfo, error) {
		total := uint64(32 << 20)
		free := uint64(3500 * 1024)
		return quickStatfsInfo{
			Supported: true, FSType: 0x01021994, IsTmpfs: true,
			TotalBytes: total, UsedBytes: total - free, FreeBytes: free,
		}, nil
	}
	repLow := s.buildQuickHealthReport(env)
	for _, it := range repLow.Items {
		if it.ID == "tmpfs_config" && (it.Status != "warn" || it.FixAction != "cache_clear") {
			t.Fatalf("32MB tmpfs with 3.5MB free should warn with cache_clear, got %+v", it)
		}
	}

	// 3. Kernel lacks tmpfs (run/tmpfs_unavailable exists): must report ok without restart_service loop!
	_ = os.WriteFile(filepath.Join(dir, "run", "tmpfs_unavailable"), []byte("1\n"), 0o600)
	env.Statfs = func(string) (quickStatfsInfo, error) {
		return quickStatfsInfo{
			Supported: true, FSType: 0xef53, IsTmpfs: false,
			TotalBytes: 64 << 30, UsedBytes: 58 << 30, FreeBytes: 6 << 30,
		}, nil
	}
	repNoTmpfs := s.buildQuickHealthReport(env)
	for _, it := range repNoTmpfs.Items {
		if it.ID == "tmpfs_config" {
			if it.Status != "ok" || it.FixAction == "restart_service" {
				t.Fatalf("tmpfs_unavailable must report ok without restart_service, got %+v", it)
			}
		}
	}

	// 4. Historically mis-blocked public base DNS (single 223.5.5.5 -> conn_block_del; multiple 223.5.5.5 + 119.29.29.29 -> nav devices)
	_ = os.WriteFile(filepath.Join(dir, "data", "conn_blocks.json"),
		[]byte(`{"items":[{"mac":"aa:bb:cc:dd:ee:01","kind":"ip","value":"223.5.5.5","label":"old"}]}`), 0o600)
	s.invalidateServerJSONCaches()
	repDNS1 := s.buildQuickHealthReport(env)
	for _, it := range repDNS1.Items {
		if it.ID == "tmpfs_config" {
			if it.Status != "warn" || it.FixAction != "conn_block_del" || !strings.Contains(it.Verdict, "223.5.5.5") {
				t.Fatalf("expected single misblocked DNS conn_block_del warning, got %+v", it)
			}
		}
	}

	_ = os.WriteFile(filepath.Join(dir, "data", "conn_blocks.json"),
		[]byte(`{"items":[{"mac":"aa:bb:cc:dd:ee:01","kind":"ip","value":"223.5.5.5","label":"old"},{"mac":"aa:bb:cc:dd:ee:01","kind":"ip","value":"119.29.29.29","label":"old"}]}`), 0o600)
	s.invalidateServerJSONCaches()
	repDNS2 := s.buildQuickHealthReport(env)
	for _, it := range repDNS2.Items {
		if it.ID == "tmpfs_config" {
			if it.Status != "warn" || it.FixKind != "nav" || it.NavTarget != "devices" || !strings.Contains(it.Verdict, "119.29.29.29") {
				t.Fatalf("expected multi misblocked DNS warning on tmpfs_config card, got %+v", it)
			}
		}
	}
}

func TestQuickHealthZeroFakeGreenOnMissingMetrics(t *testing.T) {
	dir := setupQuickHealthTestDir(t)
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o600)
	_ = os.Remove(filepath.Join(dir, "run", "power_stats.json"))
	_ = os.Remove(filepath.Join(dir, "run", "offload_guard.json"))

	s := newServer(dir)
	env := quickHealthEnv{
		Now:           func() time.Time { return time.Unix(1780005000, 0) },
		IPForwardPath: filepath.Join(dir, "run", "nonexistent_ip_forward"),
		IfaceIPv4:     func(string) string { return "192.168.43.1" },
		Statfs: func(string) (quickStatfsInfo, error) {
			return quickStatfsInfo{}, errors.New("statfs EACCES")
		},
	}

	rep := s.buildQuickHealthReport(env)
	if rep.Overall == "ok" {
		t.Fatalf("expected non-ok overall when all 4 underlying metrics are unreadable/missing, got %q", rep.Overall)
	}

	byID := map[string]QuickHealthCheckItem{}
	for _, it := range rep.Items {
		byID[it.ID] = it
	}

	// 1. ip_forward 不可读 -> 严禁返回 ok
	c1 := byID["hotspot_forward"]
	if c1.Status == "ok" || c1.ReasonCode != "ip_forward_unreadable" {
		t.Fatalf("hotspot_forward with unreadable ip_forward must NOT be ok: %+v", c1)
	}

	// 2. power_stats.json 缺失 -> 严禁返回 ok
	c2 := byID["zero_wakeup_power"]
	if c2.Status == "ok" || c2.ReasonCode != "power_stats_missing" {
		t.Fatalf("zero_wakeup_power without power_stats.json must NOT be ok: %+v", c2)
	}

	// 3. 热点活跃态下 offload_guard.json 缺失 -> 严禁返回 ok
	c3 := byID["shaping_offload"]
	if c3.Status == "ok" || c3.ReasonCode != "offload_guard_missing" {
		t.Fatalf("shaping_offload without offload_guard.json while hotspot active must NOT be ok: %+v", c3)
	}

	// 4. syscall.Statfs 失败 -> 严禁返回 ok 或伪造 0.0 / 32 MB
	c4 := byID["tmpfs_config"]
	if c4.Status == "ok" || c4.ReasonCode != "statfs_unavailable" {
		t.Fatalf("tmpfs_config on failed Statfs must NOT be ok: %+v", c4)
	}
	if strings.Contains(c4.Verdict, "0.0") || strings.Contains(c4.Verdict, "32 MB") || strings.Contains(c4.Verdict, "32M") {
		t.Fatalf("tmpfs_config on failed Statfs must NEVER fabricate 0.0 / 32 MB, got %q", c4.Verdict)
	}
}


