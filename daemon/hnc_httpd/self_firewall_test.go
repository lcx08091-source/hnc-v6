package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func doSelfFWAction(t *testing.T, mux *http.ServeMux, action string, params map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"action": action,
		"params": params,
	})
	if err != nil {
		t.Fatal(err)
	}
	return doGuardJSONReq(t, mux, http.MethodPost, "/api/action", string(b))
}

func TestSelfFirewall64BitAtomicHeadAlignment(t *testing.T) {
	var z selfFirewallEngine
	fields := []struct {
		name string
		off  uintptr
		want uintptr
	}{
		{"applyCommits", unsafe.Offsetof(z.applyCommits), 0},
		{"guardRejects", unsafe.Offsetof(z.guardRejects), 8},
	}
	for _, f := range fields {
		if f.off != f.want || f.off%8 != 0 {
			t.Fatalf("selfFirewallEngine.%s offset=%d want=%d (must be 8-byte aligned at struct head for GOARCH=arm)",
				f.name, f.off, f.want)
		}
	}
}

func TestSelfFirewallGuardrailsModesSDKSandboxAndZeroIdle(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	mux.HandleFunc("/api/action", s.handleAction)
	sf := s.v6State().selfFirewall

	// 准备模拟 /data/system/packages.list 供 UID -> 包名反查防绕过核验
	pkgListPath := filepath.Join(dir, "packages.list")
	pkgListContent := strings.Join([]string{
		"com.agy 10205 0 /data/user/0/com.agy default:targetSdkVersion=34 none 0 1",
		"me.weishu.kernelsu 10206 0 /data/user/0/me.weishu.kernelsu default:targetSdkVersion=34 none 0 1",
		"com.example.news 10150 0 /data/user/0/com.example.news default:targetSdkVersion=34 none 0 1",
		"com.example.video 10188 0 /data/user/0/com.example.video default:targetSdkVersion=34 none 0 1",
		"com.example.game 10199 0 /data/user/0/com.example.game default:targetSdkVersion=34 none 0 1",
	}, "\n") + "\n"
	if err := os.WriteFile(pkgListPath, []byte(pkgListContent), 0o600); err != nil {
		t.Fatal(err)
	}

	var dpMu sync.Mutex
	var v4Payloads, v6Payloads []string
	var iptCalls []string
	hookPresent := map[string]bool{}

	sf.mu.Lock()
	sf.packagesListPath = pkgListPath
	sf.forceDataplane = true
	sf.restoreExec = func(isIPv6 bool, payload string) error {
		dpMu.Lock()
		defer dpMu.Unlock()
		if isIPv6 {
			v6Payloads = append(v6Payloads, payload)
		} else {
			v4Payloads = append(v4Payloads, payload)
		}
		return nil
	}
	sf.iptExec = func(isIPv6 bool, args ...string) (string, error) {
		fam := "v4"
		if isIPv6 {
			fam = "v6"
		}
		cmdStr := fam + ":" + strings.Join(args, " ")
		dpMu.Lock()
		defer dpMu.Unlock()
		iptCalls = append(iptCalls, cmdStr)
		if len(args) >= 6 && args[0] == "-t" && args[1] == "filter" {
			op := args[2]
			parent := args[3]
			chain := args[len(args)-1]
			key := fam + "|" + parent + "|" + chain
			switch op {
			case "-C":
				if !hookPresent[key] {
					return "No chain/target/match", fmt.Errorf("not linked")
				}
				return "", nil
			case "-I":
				hookPresent[key] = true
				return "", nil
			case "-D":
				if !hookPresent[key] {
					return "No chain/target/match", fmt.Errorf("not linked")
				}
				delete(hookPresent, key)
				return "", nil
			}
		}
		return "", nil
	}
	sf.mu.Unlock()

	// 红线 1: 硬性拒绝 appId < 10000 (含多用户/双开系统 UID 如 99901000)
	for _, sysUID := range []int{0, 1000, 1001, 1051, 2000, 9999, 1001051, 99900000, 99901000} {
		if _, _, err := sf.SetUIDRule(sysUID, SelfFirewallModeBlockAll, "com.some.app", "", nil); err == nil {
			t.Fatalf("expected uid=%d (appId < 10000) to be rejected by guardrail 1", sysUID)
		}
	}

	// 红线 2: 硬性保护 9 个 Root 管理器、WebView 与宿主包名 (直接传包名 + 仅传 UID 借 packages.list 绕过 + SDK Sandbox / 双开 UID)
	for _, protPkg := range selfFirewallProtectedPackages {
		if _, _, err := sf.SetUIDRule(10300, SelfFirewallModeBlockCleartext, protPkg, "", nil); err == nil {
			t.Fatalf("expected protected package %q to be rejected by guardrail 2", protPkg)
		}
	}
	// 仅传 UID=10205 (com.agy)、SDK Sandbox UID=20205 或双开 UID=99910205/99920205, 不传 pkg 企图绕过 -> 必须被 packages.list 反查拦截!
	for _, disguisedUID := range []int{10205, 20205, 10206, 99910205, 99920205} {
		if _, _, err := sf.SetUIDRule(disguisedUID, SelfFirewallModeBlockAll, "", "", nil); err == nil {
			t.Fatalf("expected UID %d belonging to protected package to be rejected via packages.list reverse lookup", disguisedUID)
		}
	}

	// 四档管控模式 + Android 13+ SDK Sandbox (10000..19999 -> +10000) + block_targets:
	// 1) block_cleartext (UID 10150 -> 同步 20150): 仅拦 80,8080,8000,8008,8888, 保留 :443!
	if _, _, err := sf.SetUIDRule(10150, SelfFirewallModeBlockCleartext, "", "新闻客户端", nil); err != nil {
		t.Fatalf("SetUIDRule block_cleartext failed: %v", err)
	}
	// 2) block_cellular (UID 10188 -> 同步 20188): 匹配 rmnet+, ccmni+, seth_w+, clat4+, v4-+
	if _, _, err := sf.SetUIDRule(10188, SelfFirewallModeBlockCellular, "", "短视频", nil); err != nil {
		t.Fatalf("SetUIDRule block_cellular failed: %v", err)
	}
	// 3) block_all + block_targets (UID 10199 -> 同步 20199, 同时含 IPv4:port 与 IPv6 目标)
	if _, _, err := sf.SetUIDRule(10199, SelfFirewallModeBlockAll, "", "单机游戏", []string{"198.51.100.44:8090", "2001:db8::99"}); err != nil {
		t.Fatalf("SetUIDRule block_all with block_targets failed: %v", err)
	}

	// 校验 0600 原子持久化文件及零 run/ 常驻文件
	sfPersist := filepath.Join(dir, "data", "self_firewall.json")
	stFile, err := os.Stat(sfPersist)
	if err != nil {
		t.Fatalf("stat %s: %v", sfPersist, err)
	}
	if perm := stFile.Mode().Perm(); perm != 0o600 {
		t.Fatalf("data/self_firewall.json perm=%04o, want strict 0600", perm)
	}

	dpMu.Lock()
	lastV4 := v4Payloads[len(v4Payloads)-1]
	lastV6 := v6Payloads[len(v6Payloads)-1]
	dpMu.Unlock()

	// 红线 3: 验证 HNC_SELF_UID 子链首条仅放行 -o lo, 严禁无目的地址豁免 8443,8444,8080 导致公网端口穿透
	for fam, pl := range map[string]string{"v4": lastV4, "v6": lastV6} {
		var ruleLines []string
		for _, ln := range strings.Split(pl, "\n") {
			if strings.HasPrefix(ln, "-A "+selfFirewallUIDChain+" ") {
				ruleLines = append(ruleLines, ln)
			}
		}
		if len(ruleLines) < 1 {
			t.Fatalf("[%s] expected >= 1 anti-lockout rule in HNC_SELF_UID, got:\n%s", fam, pl)
		}
		if ruleLines[0] != "-A HNC_SELF_UID -o lo -j RETURN" {
			t.Fatalf("[%s] HNC_SELF_UID rule #1 = %q, want %q", fam, ruleLines[0], "-A HNC_SELF_UID -o lo -j RETURN")
		}
		if strings.Contains(pl, "--sports 8443,8444,8080") || strings.Contains(pl, "--dports 8443,8444,8080") {
			t.Fatalf("[%s] HNC_SELF_UID must NOT contain blanket 8443,8444,8080 RETURN bypass:\n%s", fam, pl)
		}
		// 验证明文拦截严格仅含 80,8080,8000,8008,8888, 绝不误杀 443, 且同时覆盖宿主 10150 与沙盒 20150
		if !strings.Contains(pl, "--dports 80,8080,8000,8008,8888 -m owner --uid-owner 10150 -j REJECT --reject-with tcp-reset") ||
			!strings.Contains(pl, "--dports 80,8080,8000,8008,8888 -m owner --uid-owner 20150 -j REJECT --reject-with tcp-reset") {
			t.Fatalf("[%s] missing cleartext or SDK sandbox rule for 10150/20150:\n%s", fam, pl)
		}
		if strings.Contains(pl, "443") && !strings.Contains(pl, "8443") {
			t.Fatalf("[%s] HNC_SELF_UID must NEVER block HTTPS :443:\n%s", fam, pl)
		}
		// 验证蜂窝网卡 5 类前缀 + SDK Sandbox 20188
		for _, ifc := range []string{"rmnet+", "ccmni+", "seth_w+", "clat4+", "v4-+"} {
			if !strings.Contains(pl, fmt.Sprintf("-A HNC_SELF_UID -o %s -m owner --uid-owner 10188 -j REJECT", ifc)) ||
				!strings.Contains(pl, fmt.Sprintf("-A HNC_SELF_UID -o %s -m owner --uid-owner 20188 -j REJECT", ifc)) {
				t.Fatalf("[%s] missing cellular rule for %s on 10188/20188:\n%s", fam, ifc, pl)
			}
		}
		// 验证 block_all + 20199
		if !strings.Contains(pl, "-A HNC_SELF_UID -m owner --uid-owner 10199 -j REJECT") ||
			!strings.Contains(pl, "-A HNC_SELF_UID -m owner --uid-owner 20199 -j REJECT") {
			t.Fatalf("[%s] missing block_all rule for 10199/20199:\n%s", fam, pl)
		}
	}
	if !strings.Contains(lastV4, "-A HNC_SELF_UID -d 198.51.100.44 -p tcp --dport 8090 -m owner --uid-owner 10199 -j REJECT --reject-with tcp-reset") {
		t.Fatalf("v4 payload missing ip:port block_target:\n%s", lastV4)
	}
	if !strings.Contains(lastV6, "-A HNC_SELF_UID -d 2001:db8::99 -m owner --uid-owner 10199 -j REJECT") {
		t.Fatalf("v6 payload missing IPv6 block_target:\n%s", lastV6)
	}

	// 本机 DNS 拦截 HNC_SELF_DNS: 三级守卫防误封 + 仅 UDP/TCP :53 -j DROP (零 REJECT, 零 :853, 零 mangle)
	if _, _, _, err := sf.BlockDomain("connectivitycheck.gstatic.com", true); err == nil {
		t.Fatal("expected Captive Portal domain to be hard-blocked even with force=true")
	}
	if _, _, _, err := sf.BlockDomain("qq.com", true); err == nil {
		t.Fatal("expected ecosystem root qq.com to be hard-blocked even with force=true")
	}
	if _, _, _, err := sf.BlockDomain("img.alicdn.com", false); err == nil {
		t.Fatal("expected shared CDN subdomain img.alicdn.com to require force=true confirmation")
	}
	if _, _, _, err := sf.BlockDomain("img.alicdn.com", true); err != nil {
		t.Fatalf("expected warn_confirm domain with force=true to succeed, got %v", err)
	}
	if _, _, _, err := sf.BlockDomain("ad-spy.evil-tracker.example", false); err != nil {
		t.Fatalf("expected tracker domain to block cleanly: %v", err)
	}

	dpMu.Lock()
	dnsV4 := v4Payloads[len(v4Payloads)-1]
	dpMu.Unlock()
	wantHex := "|06|ad-spy|0c|evil-tracker|07|example|00|"
	if !strings.Contains(dnsV4, fmt.Sprintf("-A HNC_SELF_DNS -p udp --dport 53 -m string --algo bm --icase --hex-string %q -j DROP", wantHex)) ||
		!strings.Contains(dnsV4, fmt.Sprintf("-A HNC_SELF_DNS -p tcp --dport 53 -m string --algo bm --icase --hex-string %q -j DROP", wantHex)) {
		t.Fatalf("HNC_SELF_DNS missing expected bm hex DROP rules:\n%s", dnsV4)
	}
	if strings.Contains(dnsV4, "REJECT") || strings.Contains(dnsV4, "853") || strings.Contains(dnsV4, "*mangle") || strings.Contains(dnsV4, "0x0000ffff") {
		t.Fatalf("SECURITY VIOLATION in HNC_SELF_DNS payload (forbidden REJECT / :853 / mangle / fwmark):\n%s", dnsV4)
	}

	// mode="allow" 移除单个 UID, 再 ClearAll("all") 清空全部规则 -> 必须摘除全部 OUTPUT 跳转钩子实现待机零规则开销!
	if _, removed, err := sf.SetUIDRule(10150, SelfFirewallModeAllow, "", "", nil); err != nil || !removed {
		t.Fatalf("mode=allow should remove UID 10150 rule: removed=%v err=%v", removed, err)
	}
	if rmU, rmD, err := sf.ClearAll("all"); err != nil || rmU != 2 || rmD != 2 {
		t.Fatalf("ClearAll failed: rmU=%d rmD=%d err=%v", rmU, rmD, err)
	}
	dpMu.Lock()
	remainingHooks := len(hookPresent)
	dpMu.Unlock()
	if remainingHooks != 0 {
		t.Fatalf("expected 0 OUTPUT hooks remaining when rules are empty, still linked: %+v", hookPresent)
	}
}

func TestSelfFirewallActionDispatchHTTPAPIAndShellSync(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	mux.HandleFunc("/api/action", s.handleAction)

	// 1. 验证只读查询 GET /api/local_apps/firewall 与 /api/v6/local_apps/firewall 初始结构
	for _, ep := range []string{"/api/local_apps/firewall", "/api/v6/local_apps/firewall"} {
		rec := doGuardJSONReq(t, mux, http.MethodGet, ep, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s failed: %d %s", ep, rec.Code, rec.Body.String())
		}
		var body struct {
			OK                bool                  `json:"ok"`
			UpdatedAt         int64                 `json:"updated_at"`
			UIDRules          []SelfFirewallUIDRule `json:"uid_rules"`
			BlockedDomains    []string              `json:"blocked_domains"`
			ProtectedPackages []string              `json:"protected_packages"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode GET %s: %v", ep, err)
		}
		if !body.OK || len(body.ProtectedPackages) < 9 || body.UIDRules == nil || body.BlockedDomains == nil {
			t.Fatalf("unexpected initial GET %s payload: %s", ep, rec.Body.String())
		}
	}

	// 2. 通过 POST /api/action 测试全部 5 个新增 action 及红线拦截码
	badUIDRec := doSelfFWAction(t, mux, "self_firewall_set", map[string]string{
		"uid":  "1000",
		"mode": "block_all",
	})
	if badUIDRec.Code != http.StatusBadRequest || !strings.Contains(badUIDRec.Body.String(), "protected_uid") {
		t.Fatalf("expected 400 protected_uid for uid=1000, got %d %s", badUIDRec.Code, badUIDRec.Body.String())
	}

	badPkgRec := doSelfFWAction(t, mux, "self_firewall_set", map[string]string{
		"uid":  "10555",
		"pkg":  "com.agy",
		"mode": "block_cleartext",
	})
	if badPkgRec.Code != http.StatusBadRequest || !strings.Contains(badPkgRec.Body.String(), "protected_package") {
		t.Fatalf("expected 400 protected_package for com.agy, got %d %s", badPkgRec.Code, badPkgRec.Body.String())
	}

	setOK := doSelfFWAction(t, mux, "self_firewall_set", map[string]string{
		"uid":           "10234",
		"pkg":           "com.demo.reader",
		"app_name":      "阅读器",
		"mode":          "block_cleartext",
		"block_targets": "203.0.113.55,198.51.100.66:9000",
	})
	if setOK.Code != http.StatusOK {
		t.Fatalf("self_firewall_set failed: %d %s", setOK.Code, setOK.Body.String())
	}

	dnsConflict := doSelfFWAction(t, mux, "self_dns_block", map[string]string{
		"domain": "wx.gtimg.com",
	})
	if dnsConflict.Code != http.StatusConflict {
		t.Fatalf("expected 409 conflict on warn_confirm shared CDN domain via /api/action, got %d %s",
			dnsConflict.Code, dnsConflict.Body.String())
	}

	dnsOK := doSelfFWAction(t, mux, "self_dns_block", map[string]string{
		"domain": "beacon.ad-sdk.example",
	})
	if dnsOK.Code != http.StatusOK {
		t.Fatalf("self_dns_block failed: %d %s", dnsOK.Code, dnsOK.Body.String())
	}

	// 3. 调用真实 POSIX 脚本 bin/self_firewall_sync.sh apply --dry-run 与 flush --dry-run 验证与 Go 引擎 100% 规则一致
	scriptPath, err := filepath.Abs(filepath.Join("..", "..", "bin", "self_firewall_sync.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmdApply := exec.Command("sh", scriptPath, "apply", "--dry-run")
	cmdApply.Env = append(hubSanitizedAndroidEnv(), "HNC_DIR="+dir, "HNC_TEST_MODE=1")
	outApplyBytes, err := cmdApply.CombinedOutput()
	outApply := string(outApplyBytes)
	if err != nil {
		t.Fatalf("self_firewall_sync.sh apply --dry-run failed: %v\nout=%s", err, outApply)
	}
	for _, wantFrag := range []string{
		"-A HNC_SELF_UID -o lo -j RETURN",
		"--dports 80,8080,8000,8008,8888 -m owner --uid-owner 10234 -j REJECT --reject-with tcp-reset",
		"--dports 80,8080,8000,8008,8888 -m owner --uid-owner 20234 -j REJECT --reject-with tcp-reset",
		"-A HNC_SELF_DNS -p udp --dport 53 -m string --algo bm --icase --hex-string \"|06|beacon|06|ad-sdk|07|example|00|\" -j DROP",
		"SELF_FIREWALL=on uid_rules=1 blocked_domains=1",
	} {
		if !strings.Contains(outApply, wantFrag) {
			t.Fatalf("self_firewall_sync.sh apply output missing %q:\n%s", wantFrag, outApply)
		}
	}

	cmdFlush := exec.Command("sh", scriptPath, "flush", "--dry-run")
	cmdFlush.Env = append(hubSanitizedAndroidEnv(), "HNC_DIR="+dir, "HNC_TEST_MODE=1")
	outFlushBytes, err := cmdFlush.CombinedOutput()
	if err != nil || !strings.Contains(string(outFlushBytes), "SELF_FIREWALL=off") {
		t.Fatalf("self_firewall_sync.sh flush --dry-run failed: err=%v out=%s", err, string(outFlushBytes))
	}

	// 4. 移除与全清动作验证
	unblkRec := doSelfFWAction(t, mux, "self_dns_unblock", map[string]string{"domain": "beacon.ad-sdk.example"})
	if unblkRec.Code != http.StatusOK {
		t.Fatalf("self_dns_unblock failed: %d %s", unblkRec.Code, unblkRec.Body.String())
	}
	rmRec := doSelfFWAction(t, mux, "self_firewall_remove", map[string]string{"uid": "10234"})
	if rmRec.Code != http.StatusOK {
		t.Fatalf("self_firewall_remove failed: %d %s", rmRec.Code, rmRec.Body.String())
	}
	clrRec := doSelfFWAction(t, mux, "self_firewall_clear", map[string]string{})
	if clrRec.Code != http.StatusOK {
		t.Fatalf("self_firewall_clear failed: %d %s", clrRec.Code, clrRec.Body.String())
	}

	getAfter := doGuardJSONReq(t, mux, http.MethodGet, "/api/local_apps/firewall", "")
	if !strings.Contains(getAfter.Body.String(), `"uid_rule_count":0`) || !strings.Contains(getAfter.Body.String(), `"blocked_domain_count":0`) {
		t.Fatalf("expected empty firewall state after remove/clear, got %s", getAfter.Body.String())
	}
}

func TestThermoDualSourceSpoofCalibrationAndHotspotOffIdleSummary(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	th := s.v6State().thermo
	th.idleSummaryMinGap = 60 * time.Millisecond

	// 构造模拟 sysfs: 用户安装了 fopbatt 将电芯温度压低 -10℃ 至 23.6℃ (236),
	// 同时 /sys/class/thermal 下存在机身壳温节点 shell_front (30.4℃) 与 shell_frame (31.0℃) 以及超上限 soc_max (82.0℃)
	sysBase := filepath.Join(dir, "mock_sys")
	psRoot := filepath.Join(sysBase, "power_supply")
	thRoot := filepath.Join(sysBase, "thermal")
	_ = os.MkdirAll(filepath.Join(psRoot, "battery"), 0o755)
	_ = os.WriteFile(filepath.Join(psRoot, "battery", "type"), []byte("Battery\n"), 0o644)
	_ = os.WriteFile(filepath.Join(psRoot, "battery", "temp"), []byte("236\n"), 0o644) // 23.6℃ (fopbatt 负偏置)
	_ = os.WriteFile(filepath.Join(psRoot, "battery", "capacity"), []byte("83\n"), 0o644)
	_ = os.WriteFile(filepath.Join(psRoot, "battery", "status"), []byte("Discharging\n"), 0o644)

	mkZone := func(name, ztype, temp string) {
		zdir := filepath.Join(thRoot, name)
		_ = os.MkdirAll(zdir, 0o755)
		_ = os.WriteFile(filepath.Join(zdir, "type"), []byte(ztype+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(zdir, "temp"), []byte(temp+"\n"), 0o644)
	}
	mkZone("thermal_zone0", "soc_max", "82000")
	mkZone("thermal_zone11", "shell_front", "30400")
	mkZone("thermal_zone12", "shell_frame", "31000")
	mkZone("thermal_zone19", "xo_therm", "29500")

	feed := newMockActivityFeed(Activity{Known: true, HotspotActive: false, ClientsOnline: 0})
	th.mu.Lock()
	th.sysfsRoot = psRoot
	th.thermalRoot = thRoot
	th.activityHook = feed.Read
	th.simActiveHook = func() bool { return false }
	// 模拟开机初始旧缓存 20.7℃
	th.lastReading = ThermoBatteryReading{
		Available:    true,
		SupplyNode:   "battery",
		TempC:        20.7,
		BatteryTempC: 20.7,
		CapacityPct:  95,
		Status:       "Discharging",
	}
	th.summaryReadAt = time.Time{}
	th.mu.Unlock()

	// 预置干净的 run/thermo_state.json 哨兵内容, 验证 HotspotOff 下 summary() 绝不覆写该文件、绝不改动 effectiveStage
	thermoStatePath := filepath.Join(dir, "run", "thermo_state.json")
	sentinel := `{"effective_stage":0,"sentinel":"hotspot_off_untouched"}`
	if err := os.WriteFile(thermoStatePath, []byte(sentinel), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. 缺陷 A + B 联调: HotspotOff 下调 summary() 必须立即只读采样刷新掉旧值 20.7℃,
	//    识别出 shell_frame(31.0℃) - battery(23.6℃) = 7.4℃ >= 6.5℃ => BatterySpoofSuspected=true, TempC=31.0℃!
	sum1 := th.summary()
	if sum1["temp_c"] != 31.0 || sum1["battery_temp_c"] != 23.6 || sum1["shell_temp_c"] != 31.0 ||
		sum1["shell_temp_available"] != true || sum1["shell_zone"] != "shell_frame" ||
		sum1["battery_spoof_suspected"] != true || sum1["capacity_pct"] != 83 {
		t.Fatalf("HotspotOff summary dual-temp calibration mismatch: %+v", sum1)
	}
	if th.effectiveStage.Load() != 0 {
		t.Fatalf("HotspotOff summary MUST NOT mutate effectiveStage, got %d", th.effectiveStage.Load())
	}
	if diskAfter, _ := os.ReadFile(thermoStatePath); string(diskAfter) != sentinel {
		t.Fatalf("HotspotOff summary MUST NOT write run/thermo_state.json, got %s", string(diskAfter))
	}

	// 2. 验证壳温路径缓存 + 3s(此处注入 60ms)内存节流:
	//    新增一个更高的假热区文件且修改壳温为 32.5℃:
	//    (a) 节流窗口内调用 summary() 必须直接命中内存缓存返回 31.0℃ (零 sysfs 读取);
	//    (b) 节流窗口过后调用 summary() 刷新为 32.5℃, 且不重扫 ReadDir 发现新建的 thermal_zone99!
	mkZone("thermal_zone99", "shell_back", "34500")
	_ = os.WriteFile(filepath.Join(thRoot, "thermal_zone12", "temp"), []byte("32500\n"), 0o644)

	sumThrottled := th.summary()
	if sumThrottled["temp_c"] != 31.0 {
		t.Fatalf("expected throttled summary within minGap to return cached 31.0C, got %+v", sumThrottled)
	}

	time.Sleep(75 * time.Millisecond)
	sumRefreshed := th.summary()
	if sumRefreshed["temp_c"] != 32.5 || sumRefreshed["shell_zone"] != "shell_frame" {
		t.Fatalf("expected cached shell_frame path read (32.5C) without re-running ReadDir, got %+v", sumRefreshed)
	}

	// 3. 验证 ReadOnlySnapshot (GET /api/v6/thermo under HotspotOff) 同样携带完整双温校准字段
	getOffRec := doGuardJSONReq(t, mux, http.MethodGet, "/api/v6/thermo", "")
	if getOffRec.Code != http.StatusOK || !strings.Contains(getOffRec.Body.String(), `"battery_spoof_suspected":true`) ||
		!strings.Contains(getOffRec.Body.String(), `"shell_temp_c":32.5`) {
		t.Fatalf("HotspotOff GET /api/v6/thermo missing dual-temp fields: %d %s", getOffRec.Code, getOffRec.Body.String())
	}

	// 4. 高温防伪装致盲验证: 热点开启后机身壳温飙升至 45.6℃, 而 fopbatt 仍将 battery/temp 压在 35.6℃ ->
	//    双源校准自动取 Max(35.6, 45.6) = 45.6℃, 成功触发二阶高温降速保护!
	var readHookCalls atomic.Int64
	_ = os.WriteFile(filepath.Join(psRoot, "battery", "temp"), []byte("356\n"), 0o644)
	_ = os.WriteFile(filepath.Join(thRoot, "thermal_zone12", "temp"), []byte("45600\n"), 0o644)
	feed.Set(Activity{Known: true, HotspotActive: true, ClientsOnline: 1})

	rdHot := th.ReadBatteryFromSysfs()
	_ = readHookCalls.Load()
	snapHot := th.Evaluate(time.Now(), rdHot, false)
	if snapHot["effective_stage"] != 2 || snapHot["stage2_shaper_active"] != true || snapHot["battery_spoof_suspected"] != true {
		t.Fatalf("battery spoof module blinded Stage 2 overheat protection: %+v", snapHot)
	}
	qs := th.PeekQuickState()
	if !qs.BatterySpoofSuspected || qs.TempC != 45.6 || qs.BatteryTempC != 35.6 || qs.ShellTempC != 45.6 || !qs.ShellTempAvailable || qs.ShellZone != "shell_frame" {
		t.Fatalf("PeekQuickState missing dual-temp fields: %+v", qs)
	}

	// 5. 正常无伪装场景: 电芯 30.8℃, 壳温 32.0℃ (差值 1.2℃ < 6.5℃) -> BatterySpoofSuspected=false, TempC=30.8℃
	_ = os.WriteFile(filepath.Join(psRoot, "battery", "temp"), []byte("308\n"), 0o644)
	_ = os.WriteFile(filepath.Join(thRoot, "thermal_zone12", "temp"), []byte("32000\n"), 0o644)
	rdNormal := th.ReadBatteryFromSysfs()
	if rdNormal.BatterySpoofSuspected || rdNormal.TempC != 30.8 || rdNormal.BatteryTempC != 30.8 || rdNormal.ShellTempC != 32.0 {
		t.Fatalf("normal phone falsely flagged battery spoof: %+v", rdNormal)
	}
}

func TestSelfFirewallReloadFromDiskWithUIDRulesNoDeadlock(t *testing.T) {
	// 1. 验证 WebUI 端口 8080 与 8443/8444 一致禁止被纳入 block_targets
	for _, port := range []int{8080, 8443, 8444} {
		if _, err := parseAndValidateSelfBlockTarget(fmt.Sprintf("198.51.100.25:%d", port)); err == nil {
			t.Fatalf("expected WebUI management port %d in block_target to be rejected", port)
		}
		if _, err := parseAndValidateSelfBlockTarget(fmt.Sprintf("[2001:db8::25]:%d", port)); err == nil {
			t.Fatalf("expected IPv6 WebUI management port %d in block_target to be rejected", port)
		}
	}

	// 2. 准备含多条 uid_rules 与 blocked_domains 的 data/self_firewall.json + 模拟 packages.list
	s, mux, dir := newV6TestMux(t)
	s.registerV6ScreenshotPackRoutes(mux)
	sf := s.v6State().selfFirewall

	pkgListPath := filepath.Join(dir, "packages.list")
	pkgListContent := strings.Join([]string{
		"com.agy 10205 0 /data/user/0/com.agy default:targetSdkVersion=34 none 0 1",
		"com.google.android.webview 10207 0 /data/user/0/com.google.android.webview default:targetSdkVersion=34 none 0 1",
		"com.example.alpha 10311 0 /data/user/0/com.example.alpha default:targetSdkVersion=34 none 0 1",
		"com.example.beta 10322 0 /data/user/0/com.example.beta default:targetSdkVersion=34 none 0 1",
		"com.example.gamma 10333 0 /data/user/0/com.example.gamma default:targetSdkVersion=34 none 0 1",
	}, "\n") + "\n"
	if err := os.WriteFile(pkgListPath, []byte(pkgListContent), 0o600); err != nil {
		t.Fatal(err)
	}

	var dpMu sync.Mutex
	var v4Restores, v6Restores []string
	sf.mu.Lock()
	sf.packagesListPath = pkgListPath
	sf.forceDataplane = true
	sf.restoreExec = func(isIPv6 bool, payload string) error {
		dpMu.Lock()
		defer dpMu.Unlock()
		if isIPv6 {
			v6Restores = append(v6Restores, payload)
		} else {
			v4Restores = append(v4Restores, payload)
		}
		return nil
	}
	sf.iptExec = func(_ bool, _ ...string) (string, error) {
		return "", nil
	}
	sf.mu.Unlock()

	seedJSON := `{
  "version": 1,
  "updated_at": 1760000123,
  "uid_rules": [
    {"uid": 10311, "pkg": "com.example.alpha", "app_name": "Alpha", "mode": "block_cleartext", "updated_at": 1760000100},
    {"uid": 10322, "pkg": "com.example.beta", "app_name": "Beta", "mode": "block_cellular", "block_targets": ["198.51.100.88:9443"], "updated_at": 1760000101},
    {"uid": 10333, "pkg": "com.example.gamma", "app_name": "Gamma", "mode": "block_all", "updated_at": 1760000102},
    {"uid": 10207, "pkg": "", "app_name": "DisguisedWebView", "mode": "block_all", "updated_at": 1760000103}
  ],
  "blocked_domains": [
    "telemetry.ad-tracker.example",
    "pixel.spyware-sdk.example"
  ]
}` + "\n"
	sfPath := filepath.Join(dir, "data", "self_firewall.json")
	if err := os.WriteFile(sfPath, []byte(seedJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	// 3. 连续多次调用 ReloadFromDisk() 并覆盖 newSelfFirewallEngine 构造路径, 验证零死锁且规则完整生效
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		for i := 0; i < 5; i++ {
			sf.ReloadFromDisk()
		}
		// 同时验证 newSelfFirewallEngine 在磁盘已存在含 uid_rules 的 self_firewall.json 时构造零死锁
		freshEng := newSelfFirewallEngine(&server{hncDir: dir, jsonCache: newJSONFileCache()})
		if freshEng.BlockedDomainCount() != 2 {
			t.Errorf("freshEng expected 2 blocked domains on init, got %d", freshEng.BlockedDomainCount())
		}
	}()
	select {
	case <-doneCh:
	case <-time.After(3 * time.Second):
		t.Fatal("DEADLOCK detected in ReloadFromDisk / newSelfFirewallEngine when uid_rules are present")
	}

	snap := sf.snapshotPayload()
	gotRules, _ := snap["uid_rules"].([]SelfFirewallUIDRule)
	gotDoms, _ := snap["blocked_domains"].([]string)
	// UID 10207 通过 packages.list 反查命中 com.google.android.webview 已被自动剔除, 其余 3 条合法规则 + 2 个域名全部生效
	if len(gotRules) != 3 || len(gotDoms) != 2 {
		t.Fatalf("unexpected rules/domains after ReloadFromDisk: rules=%+v domains=%+v", gotRules, gotDoms)
	}
	if !sf.IsHostEventBlocked(10333, "", "203.0.113.10", 443, "tcp") || !sf.IsDomainBlocked("sub.telemetry.ad-tracker.example") {
		t.Fatal("reloaded UID / DNS rules did not take effect")
	}
	dpMu.Lock()
	joinedV4 := strings.Join(v4Restores, "\n")
	if len(v4Restores) < 2 || len(v6Restores) < 2 ||
		!strings.Contains(joinedV4, "--uid-owner 10322") ||
		!strings.Contains(joinedV4, ":HNC_SELF_DNS") {
		dpMu.Unlock()
		t.Fatalf("dataplane was not synced after ReloadFromDisk: v4=%d v6=%d", len(v4Restores), len(v6Restores))
	}
	dpMu.Unlock()

	// 4. 整机备份 GET /api/backup 导出包含合法 self_firewall.json (先用干净合法配置落盘)
	cleanDoc := `{
  "version": 1,
  "updated_at": 1760000200,
  "uid_rules": [
    {"uid": 10311, "pkg": "com.example.alpha", "app_name": "Alpha", "mode": "block_cleartext", "updated_at": 1760000200},
    {"uid": 10322, "pkg": "com.example.beta", "app_name": "Beta", "mode": "block_all", "block_targets": ["198.51.100.88:9443"], "updated_at": 1760000200}
  ],
  "blocked_domains": ["telemetry.ad-tracker.example", "img.alicdn.com"]
}` + "\n"
	if err := os.WriteFile(sfPath, []byte(cleanDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	sf.ReloadFromDisk()

	expRec := doV6JSONReq(t, mux, http.MethodGet, "/api/backup", "")
	if expRec.Code != http.StatusOK {
		t.Fatalf("GET /api/backup failed: %d %s", expRec.Code, expRec.Body.String())
	}
	var exportedBundle V6BackupBundle
	if err := json.Unmarshal(expRec.Body.Bytes(), &exportedBundle); err != nil {
		t.Fatalf("decode GET /api/backup: %v", err)
	}
	if _, ok := exportedBundle.Files["self_firewall.json"]; !ok {
		t.Fatalf("GET /api/backup missing self_firewall.json in files: %v", exportedBundle.FileCount)
	}

	// 5. 构造恶意备份包 POST /api/backup 校验 400 语义拦截 (uid < 10000 / 受保护包名 / 非法 mode / hard_block 核心公共域名)
	buildSignedBundle := func(fileKey string, sfPayload string) string {
		t.Helper()
		rulesCanon, err := canonicalCompactJSON([]byte(`{"version":1,"whitelist_mode":false,"devices":{},"blacklist":[],"whitelist":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		sfCanon, err := canonicalCompactJSON([]byte(sfPayload))
		if err != nil {
			t.Fatal(err)
		}
		canonMap := map[string][]byte{
			"rules.json": rulesCanon,
			fileKey:      sfCanon,
		}
		manifestSHA, fileSHAs := computeBackupManifestSHA256(canonMap)
		b := V6BackupBundle{
			SchemaVersion: v6BackupSchemaVersion,
			ExportedAt:    time.Now().Unix(),
			FileCount:     len(canonMap),
			Files: map[string]json.RawMessage{
				"rules.json": rulesCanon,
				fileKey:      sfCanon,
			},
			FileSHA256: fileSHAs,
			SHA256:     manifestSHA,
		}
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}

	maliciousCases := []struct {
		name    string
		fileKey string
		payload string
	}{
		{
			name:    "system_uid_lt_10000",
			fileKey: "self_firewall.json",
			payload: `{"version":1,"uid_rules":[{"uid":1000,"pkg":"com.example.app","mode":"block_all"}],"blocked_domains":[]}`,
		},
		{
			name:    "protected_package_webview",
			fileKey: "self_firewall.json",
			payload: `{"version":1,"uid_rules":[{"uid":10450,"pkg":"com.google.android.webview","mode":"block_all"}],"blocked_domains":[]}`,
		},
		{
			name:    "invalid_mode",
			fileKey: "self_firewall.json",
			payload: `{"version":1,"uid_rules":[{"uid":10450,"pkg":"com.example.app","mode":"drop_everything"}],"blocked_domains":[]}`,
		},
		{
			name:    "hard_block_core_public_domain",
			fileKey: "self_firewall.json",
			payload: `{"version":1,"uid_rules":[],"blocked_domains":["connectivitycheck.gstatic.com"]}`,
		},
		{
			name:    "legacy_key_malicious_uid",
			fileKey: "v6_self_firewall.json",
			payload: `{"version":1,"uid_rules":[{"uid":0,"mode":"block_all"}],"blocked_domains":[]}`,
		},
	}
	for _, tc := range maliciousCases {
		badBody := buildSignedBundle(tc.fileKey, tc.payload)
		badRec := doV6JSONReq(t, mux, http.MethodPost, "/api/backup", badBody)
		if badRec.Code != http.StatusBadRequest || !strings.Contains(badRec.Body.String(), "self_firewall.json") {
			t.Fatalf("[%s] expected 400 Bad Request mentioning self_firewall.json, got %d %s",
				tc.name, badRec.Code, badRec.Body.String())
		}
	}

	// 6. 在全新服务端实例上通过 POST /api/backup 恢复导出的合法备份包 + 旧版键名 v6_self_firewall.json 映射验证 (零死锁)
	dstSrv, dstMux, dstDir := newV6TestMux(t)
	dstSrv.registerV6ScreenshotPackRoutes(dstMux)
	dstSF := dstSrv.v6State().selfFirewall
	dstSF.mu.Lock()
	dstSF.packagesListPath = pkgListPath
	dstSF.mu.Unlock()

	restoreDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		restoreDone <- doV6JSONReq(t, dstMux, http.MethodPost, "/api/backup", expRec.Body.String())
	}()
	var restRec *httptest.ResponseRecorder
	select {
	case restRec = <-restoreDone:
	case <-time.After(3 * time.Second):
		t.Fatal("DEADLOCK detected during POST /api/backup restore with self_firewall.json")
	}
	if restRec.Code != http.StatusOK {
		t.Fatalf("POST /api/backup valid restore failed: %d %s", restRec.Code, restRec.Body.String())
	}
	dstSnap := dstSF.snapshotPayload()
	dstRules, _ := dstSnap["uid_rules"].([]SelfFirewallUIDRule)
	dstDoms, _ := dstSnap["blocked_domains"].([]string)
	if len(dstRules) != 2 || len(dstDoms) != 2 {
		t.Fatalf("expected 2 restored uid_rules and 2 blocked_domains in memory after /api/backup POST, got rules=%+v doms=%+v", dstRules, dstDoms)
	}

	// 验证旧版备份键名 v6_self_firewall.json 自动映射落盘为 data/self_firewall.json 并热重载生效
	legacyValidBody := buildSignedBundle("v6_self_firewall.json",
		`{"version":1,"updated_at":1760000300,"uid_rules":[{"uid":10333,"pkg":"com.example.gamma","mode":"block_all"}],"blocked_domains":["legacy.tracker.example"]}`)
	legRec := doV6JSONReq(t, dstMux, http.MethodPost, "/api/backup", legacyValidBody)
	if legRec.Code != http.StatusOK {
		t.Fatalf("POST /api/backup legacy v6_self_firewall.json failed: %d %s", legRec.Code, legRec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dstDir, "data", "self_firewall.json")); err != nil {
		t.Fatalf("legacy v6_self_firewall.json was not mapped to data/self_firewall.json: %v", err)
	}
	if !dstSF.IsHostEventBlocked(10333, "", "203.0.113.1", 443, "tcp") || !dstSF.IsDomainBlocked("legacy.tracker.example") {
		t.Fatal("legacy v6_self_firewall.json rules not active after restore")
	}

	// 7. 验证子进程环境变量保留 BOOTCLASSPATH 以及 guardianVectorSyncSummary 补充 self_capture_enabled
	t.Setenv("BOOTCLASSPATH", "/apex/com.android.art/javalib/core-oj.jar")
	subEnv := subprocEnvWithFallbackPath()
	joinedSubEnv := strings.Join(subEnv, "\n")
	if !strings.Contains(joinedSubEnv, "BOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar") ||
		!strings.Contains(joinedSubEnv, "PATH=/system/bin:") {
		t.Fatalf("subprocEnvWithFallbackPath failed to preserve BOOTCLASSPATH and safe PATH: %v", subEnv)
	}

	vsSumOff, ok := guardianVectorSyncSummary(dstSrv).(map[string]any)
	if !ok || vsSumOff["self_capture_enabled"] != false {
		t.Fatalf("expected self_capture_enabled=false in guardianVectorSyncSummary initially, got %+v", vsSumOff)
	}
	if err := os.WriteFile(dstSrv.selfFlagPath(), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vsSumOn, ok := guardianVectorSyncSummary(dstSrv).(map[string]any)
	if !ok || vsSumOn["self_capture_enabled"] != true {
		t.Fatalf("expected self_capture_enabled=true in guardianVectorSyncSummary when self flag exists, got %+v", vsSumOn)
	}
	_ = dstSrv.guardianEngine()
	vsSumEngOn, ok := guardianVectorSyncSummary(dstSrv).(map[string]any)
	if !ok || vsSumEngOn["self_capture_enabled"] != true {
		t.Fatalf("expected self_capture_enabled=true in guardianVectorSyncSummary with active engine, got %+v", vsSumEngOn)
	}
}

func TestRC7SelfFirewallAllowBlockTargetsGuardrailsSyntheticPkgAndCellularVPN(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	mux.HandleFunc("/api/action", s.handleAction)
	sf := s.v6State().selfFirewall

	pkgListPath := filepath.Join(dir, "packages.list")
	if err := os.WriteFile(pkgListPath, []byte(strings.Join([]string{
		"com.example.news 10150 0 /data/user/0/com.example.news default:targetSdkVersion=34 none 0 1",
		"com.example.video 10188 0 /data/user/0/com.example.video default:targetSdkVersion=34 none 0 1",
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "app_labels_live.json"), []byte(`{"com.example.news":"澎湃早报","com.example.video":"极速影视"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var dpMu sync.Mutex
	var v4Payloads []string
	cellVPNActive := false
	sf.mu.Lock()
	sf.packagesListPath = pkgListPath
	sf.forceDataplane = true
	sf.cellularVPNHook = func() bool {
		dpMu.Lock()
		defer dpMu.Unlock()
		return cellVPNActive
	}
	sf.restoreExec = func(isIPv6 bool, payload string) error {
		if !isIPv6 {
			dpMu.Lock()
			v4Payloads = append(v4Payloads, payload)
			dpMu.Unlock()
		}
		return nil
	}
	sf.iptExec = func(_ bool, _ ...string) (string, error) { return "", nil }
	sf.mu.Unlock()

	// 1. B026: 拒绝隔离进程 UID (appId >= 90000) 返回 HTTP 400 protected_uid; 剥离 uid:<id>/isolated:<id> 合成包名并反查中文 display_name
	for _, isoUID := range []string{"90000", "99001", "1099001"} {
		recIso := doSelfFWAction(t, mux, "self_firewall_set", map[string]string{
			"uid":  isoUID,
			"pkg":  "isolated:99001",
			"mode": "block_all",
		})
		if recIso.Code != http.StatusBadRequest || !strings.Contains(recIso.Body.String(), "protected_uid") {
			t.Fatalf("expected 400 protected_uid for isolated uid=%s, got %d %s", isoUID, recIso.Code, recIso.Body.String())
		}
	}

	// 2. B007 & B027: mode="allow" + 非空 block_targets 独立生效 + 剥离合成包名 uid:10150 并补齐中文名
	recAllowTgt := doSelfFWAction(t, mux, "self_firewall_set", map[string]string{
		"uid":           "10150",
		"pkg":           "uid:10150",
		"mode":          "allow",
		"block_targets": "203.0.113.88",
	})
	if recAllowTgt.Code != http.StatusOK {
		t.Fatalf("mode=allow with block_targets failed: %d %s", recAllowTgt.Code, recAllowTgt.Body.String())
	}
	if !sf.IsHostEventBlocked(10150, "", "203.0.113.88", 80, "tcp") {
		t.Fatal("expected mode=allow + block_targets=[203.0.113.88] to block 203.0.113.88")
	}
	if sf.IsHostEventBlocked(10150, "", "198.51.100.77", 80, "tcp") {
		t.Fatal("mode=allow must NOT block other IPs")
	}

	// 切换模式但不传 block_targets 参数时必须自动继承已有 block_targets
	recSwitchMode := doSelfFWAction(t, mux, "self_firewall_set", map[string]string{
		"uid":  "10150",
		"mode": "block_cleartext",
	})
	if recSwitchMode.Code != http.StatusOK || !sf.IsHostEventBlocked(10150, "", "203.0.113.88", 443, "tcp") {
		t.Fatalf("switching mode without block_targets must inherit existing block_targets: %d %s",
			recSwitchMode.Code, recSwitchMode.Body.String())
	}
	recBackAllow := doSelfFWAction(t, mux, "self_firewall_set", map[string]string{
		"uid":  "10150",
		"mode": "allow",
	})
	if recBackAllow.Code != http.StatusOK || !sf.IsHostEventBlocked(10150, "", "203.0.113.88", 443, "tcp") {
		t.Fatalf("switching back to mode=allow without block_targets must retain inherited block_targets: %d %s",
			recBackAllow.Code, recBackAllow.Body.String())
	}

	getSnap := doGuardJSONReq(t, mux, http.MethodGet, "/api/local_apps/firewall", "")
	if !strings.Contains(getSnap.Body.String(), `"pkg":"com.example.news"`) ||
		!strings.Contains(getSnap.Body.String(), `"display_name":"澎湃早报"`) ||
		!strings.Contains(getSnap.Body.String(), `"203.0.113.88"`) {
		t.Fatalf("GET /api/local_apps/firewall missing resolved pkg/display_name/block_targets: %s", getSnap.Body.String())
	}

	// 显式传空 block_targets:"" 且 mode="allow" 时彻底移除该 UID 规则
	recClearAllow := doSelfFWAction(t, mux, "self_firewall_set", map[string]string{
		"uid":           "10150",
		"mode":          "allow",
		"block_targets": "",
	})
	if recClearAllow.Code != http.StatusOK || sf.IsHostEventBlocked(10150, "", "203.0.113.88", 80, "tcp") {
		t.Fatalf("explicit empty block_targets with mode=allow failed to remove rule: %d %s",
			recClearAllow.Code, recClearAllow.Body.String())
	}

	// 3. block_targets 严禁代理 Fake-IP (198.18.0.0/15)、DNS/DoT (:53/:853)、公共 DNS 与共享 CDN IP
	for _, badTgt := range []string{
		"198.18.0.2",
		"198.19.255.10:443",
		"203.0.113.88:53",
		"203.0.113.88:853",
		"223.5.5.5",
		"104.16.132.229",
	} {
		if _, err := parseAndValidateSelfBlockTarget(badTgt); err == nil {
			t.Fatalf("expected forbidden block_target %q to be rejected", badTgt)
		}
	}

	// 4. B027: 动态识别纯蜂窝上游 + VPN 活跃态 (避免 VPN 穿透蜂窝禁网，且绝不误杀 Wi-Fi + VPN)
	cellOnlyRoutes := strings.Join([]string{
		"0.0.0.0/1 dev Meta proto kernel scope link",
		"128.0.0.0/1 dev Meta proto kernel scope link",
		"default via 10.64.0.1 dev rmnet_data2 proto static metric 100",
		"192.168.43.0/24 dev wlan2 proto kernel scope link src 192.168.43.1",
	}, "\n")
	wifiPlusVPNRoutes := cellOnlyRoutes + "\ndefault via 192.168.1.1 dev wlan0 proto dhcp metric 200\n"

	if !evalCellularOnlyVPNFromRoutes([]string{"Meta", "rmnet_data2", "wlan2"}, nil, "wlan2") {
		t.Fatal("expected evalCellularOnlyVPNFromRoutes=true when VPN + cellular rmnet_data2 active and wlan2 is hotspot AP")
	}
	if evalCellularOnlyVPNFromRoutes([]string{"Meta", "rmnet_data2", "wlan0"}, nil, "wlan2") {
		t.Fatal("expected evalCellularOnlyVPNFromRoutes=false when Wi-Fi STA wlan0 default route is active")
	}

	dpMu.Lock()
	cellVPNActive = true
	dpMu.Unlock()
	if _, _, err := sf.SetUIDRule(10188, SelfFirewallModeBlockCellular, "isolated:99002", "", nil); err != nil {
		t.Fatalf("SetUIDRule block_cellular failed: %v", err)
	}
	dpMu.Lock()
	lastV4CellVPN := v4Payloads[len(v4Payloads)-1]
	dpMu.Unlock()
	for _, vpnIfc := range []string{"tun+", "Meta", "wg+", "utun+", "sing_tun+"} {
		if !strings.Contains(lastV4CellVPN, fmt.Sprintf("-A HNC_SELF_UID -o %s -m owner --uid-owner 10188 -j REJECT", vpnIfc)) {
			t.Fatalf("missing VPN tunnel cellular block rule for %s:\n%s", vpnIfc, lastV4CellVPN)
		}
	}

	// 验证 self_firewall_sync.sh 在纯蜂窝+VPN 与 Wi-Fi+VPN 两种路由下的同步一致性 (同时含 allow+block_targets)
	if _, _, err := sf.AddUIDBlockTarget(10150, "203.0.113.88", "", ""); err != nil {
		t.Fatalf("AddUIDBlockTarget failed: %v", err)
	}
	scriptPath, err := filepath.Abs(filepath.Join("..", "..", "bin", "self_firewall_sync.sh"))
	if err != nil {
		t.Fatal(err)
	}

	cmdCellVPN := exec.Command("sh", scriptPath, "apply", "--dry-run")
	cmdCellVPN.Env = append(hubSanitizedAndroidEnv(),
		"HNC_DIR="+dir,
		"HNC_TEST_MODE=1",
		"HNC_SELF_FW_ROUTES_TEXT="+cellOnlyRoutes,
	)
	outCellVPNBytes, err := cmdCellVPN.CombinedOutput()
	if err != nil {
		t.Fatalf("self_firewall_sync.sh cellular+VPN dry-run failed: %v\n%s", err, string(outCellVPNBytes))
	}
	outCellVPN := string(outCellVPNBytes)
	if !strings.Contains(outCellVPN, "-A HNC_SELF_UID -d 203.0.113.88 -m owner --uid-owner 10150 -j REJECT") ||
		!strings.Contains(outCellVPN, "-A HNC_SELF_UID -o Meta -m owner --uid-owner 10188 -j REJECT") {
		t.Fatalf("self_firewall_sync.sh missing allow+block_targets or Meta VPN rule:\n%s", outCellVPN)
	}

	cmdWifiVPN := exec.Command("sh", scriptPath, "apply", "--dry-run")
	cmdWifiVPN.Env = append(hubSanitizedAndroidEnv(),
		"HNC_DIR="+dir,
		"HNC_TEST_MODE=1",
		"HNC_SELF_FW_ROUTES_TEXT="+wifiPlusVPNRoutes,
	)
	outWifiVPNBytes, err := cmdWifiVPN.CombinedOutput()
	if err != nil {
		t.Fatalf("self_firewall_sync.sh wifi+VPN dry-run failed: %v\n%s", err, string(outWifiVPNBytes))
	}
	if strings.Contains(string(outWifiVPNBytes), "-o Meta -m owner --uid-owner 10188") {
		t.Fatalf("self_firewall_sync.sh must NOT block VPN tunnel when Wi-Fi STA default route is active:\n%s", string(outWifiVPNBytes))
	}
}

