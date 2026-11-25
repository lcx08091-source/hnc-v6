package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// Wave 4 (F08 / W08) RC6 回归单测:
// 1. C047/C020: 双卡机型过滤幽灵「卡3」(Phone Id=2)与云端虚拟卡, 支持 CLAT v4- 接口名剥离;
// 2. C050/C046: 手机流量账期校准锚点跨周期自动失效不串账, 设备/全局月度配额结算日对齐与跨月隔离;
// 3. C044: 应用时长/类别封禁展开与应用限速共享判定强制过滤 shared_infra.txt、github.io 等多租户后缀及异源支付根域(限制 taobao 绝不封杀 alipay.com);
// 4. C042/C043: encdns 改策略秒级同步内存 DNS 封锁表; DNS 接管 chooseUpstream 与自检拒绝 SERVFAIL/REFUSED 触发 fail-open,
//    SyncNetSig/onFlush 重置 upCheckedAt 并 wake(), handleWithStale 后台刷新纳入 wg 并随 Close 立即取消且保持 arm32 8 字节对齐。

func TestWave4RC6GhostSIM3FilterAndCLATIface(t *testing.T) {
	nowUnix := int64(1_800_000_100)

	// 双卡硬件(mActiveModemCount=2, 无 triple_sim), 但 ROM 吐出了幽灵 Phone Id=2(卡3) 和 Phone Id=0 云端虚拟卡(Redtea Mobile)
	dualSimGhostDump := strings.Join([]string{
		"mActiveDataSubId=2",
		"mActiveModemCount=2",
		"  Phone Id=0",
		"    mSubId=1",
		"    mOperatorAlphaLong=Redtea Mobile",
		"    mMcc=460 mMnc=00",
		"    mSignalStrength=SignalStrength:{ mNr=CellSignalStrengthNr:{ csiRsrp = 2147483647 ssRsrp = -72 ssRsrq = -8 ssSinr = 25 } }",
		"  Phone Id=1",
		"    mSubId=2",
		"    mOperatorAlphaLong=China Telecom",
		"    mMcc=460 mMnc=11",
		"    LinkProperties: {InterfaceName: v4-rmnet_data1 LinkAddresses: [ 192.0.0.4/32 ]}",
		"    mSignalStrength=SignalStrength:{ mNr=CellSignalStrengthNr:{ csiRsrp = 2147483647 ssRsrp = -86 ssRsrq = -10 ssSinr = 18 } }",
		"  Phone Id=2",
		"    mSubId=99",
		"    mOperatorAlphaLong=China Mobile",
		"    mMcc=460 mMnc=00",
		"    LinkProperties: {InterfaceName: rmnet_data9 LinkAddresses: [ 10.9.9.9/24 ]}",
		"    mSignalStrength=SignalStrength:{ mNr=CellSignalStrengthNr:{ csiRsrp = 2147483647 ssRsrp = -65 ssRsrq = -6 ssSinr = 30 } }",
		"local logs:",
		"  Phone Id=1 mSubId=2 ssRsrp=-120",
	}, "\n")

	// 即使未指定活动 SubId 走兜底或传入 CLAT v4-rmnet_data1, 都必须过滤幽灵卡3与云虚拟卡并选中真实卡2(RSRP=-86, 物理口 rmnet_data1)
	st := parseTelephonyRegistryDump(dualSimGhostDump, "v4-rmnet_data1", nowUnix)
	if !st.Available || st.RSRPdBm != -86 || st.UpstreamIface != "rmnet_data1" {
		t.Fatalf("expected real slot1 (-86 dBm, rmnet_data1) via CLAT strip, got %+v", st)
	}

	onlyGhostSlot3 := strings.Join([]string{
		"mActiveModemCount=2",
		"  Phone Id=2",
		"    mSubId=3",
		"    mOperatorAlphaLong=China Unicom",
		"    mMcc=460 mMnc=01",
		"    mSignalStrength=SignalStrength:{ mNr=CellSignalStrengthNr:{ csiRsrp = 2147483647 ssRsrp = -75 ssRsrq = -9 ssSinr = 20 } }",
	}, "\n")
	if ghostSt := parseTelephonyRegistryDump(onlyGhostSlot3, "", nowUnix); ghostSt.Available {
		t.Fatalf("ghost Phone Id=2 on dual-SIM device must be filtered out, got %+v", ghostSt)
	}

	// 真三卡硬件(multisim.config=tsts + mActiveModemCount=3)则允许 Phone Id=2
	trueTripleDump := "persist.radio.multisim.config=tsts\n" + strings.ReplaceAll(onlyGhostSlot3, "mActiveModemCount=2", "mActiveModemCount=3")
	if triSt := parseTelephonyRegistryDump(trueTripleDump, "", nowUnix); !triSt.Available || triSt.RSRPdBm != -75 {
		t.Fatalf("true triple-SIM hardware must allow Phone Id=2, got %+v", triSt)
	}
}

func TestWave4RC6BillingCycleAnchorAndCrossMonthQuota(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"data", "run"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	loc := time.FixedZone("CST", 8*3600)
	tOct := time.Date(2026, 10, 20, 12, 0, 0, 0, loc) // billing_day=15 -> 周期起于 2026-10-15
	if r := actionPhoneUsageSetAt(dir, map[string]string{
		"billing_day":    "15",
		"plan_sim1_gb":   "100",
		"anchor_sim1_gb": "42.5",
	}, tOct); !r.OK {
		t.Fatalf("actionPhoneUsageSetAt failed: %+v", r)
	}

	eng := newPuEngine(dir, puEnv{
		readNetDev: func() ([]byte, error) { return nil, nil },
	})
	repCur := eng.report("cycle", tOct)
	cfgCur := repCur["config"].(map[string]interface{})
	if cfgCur["anchor_sim1_gb"] != 42.5 {
		t.Fatalf("expected current cycle anchor_sim1_gb=42.5, got %v", cfgCur["anchor_sim1_gb"])
	}

	// 推进到下一个账期(2026-11-16, 新周期起于 2026-11-15 != 20261015): 旧账期锚点严禁继续展示或生效!
	tNov := time.Date(2026, 11, 16, 9, 0, 0, 0, loc)
	repNext := eng.report("cycle", tNov)
	cfgNext := repNext["config"].(map[string]interface{})
	if cfgNext["anchor_sim1_gb"] != nil {
		t.Fatalf("stale previous-cycle anchor_sim1_gb must be nil after cycle rollover, got %v", cfgNext["anchor_sim1_gb"])
	}

	// 验证 limitCtl 优先读取 phone_usage_config.json 的 billing_day=15 且跨计费月首轮不混入上月 histMon
	if err := os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"billing_day":1,"devices":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var actionMu sync.Mutex
	ctl := newLimitCtl(dir, &actionMu)
	if bd := ctl.readBillingDay(); bd != 15 {
		t.Fatalf("expected readBillingDay()=15 from phone_usage_config.json over rules.json=1, got %d", bd)
	}
	mac := "aa:bb:cc:dd:ee:11"
	msNov := billingPeriodStart(tNov, 15) // 2026-11-15
	ctl.mu.Lock()
	ctl.histMonKey = "2026-10-15" // 上一账期残留的 DPI 月度缓存键
	ctl.histMon = map[string]uint64{mac: 99 << 30}
	ctl.st.Devices[mac] = &ctlDevState{
		Usage: usageAcc{MonthKey: msNov.Format("2006-01-02"), MonthBytes: 128 << 20},
	}
	gotNov := ctl.monthUsageLocked(msNov)[mac]
	ctl.mu.Unlock()
	if gotNov != 128<<20 {
		t.Fatalf("cross-month histMon must not leak into new cycle: got %d, want %d", gotNov, 128<<20)
	}
}

func TestWave4RC6SharedInfraMultiTenantAndAlipayGuard(t *testing.T) {
	resetAppTimeGlobals(t)
	dir := t.TempDir()
	for _, sub := range []string{"data/dpi_rules.d", "etc/dpi_rules.d", "run", "bin"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HNC_DIR", dir)

	// 写入自定义 shared_infra.txt + 包含脏后缀(alipay.com / github.io / alicdn.com)的规则以模拟最严苛场景
	sharedTxt := "alicdn.com\nwechatpay.cn\nmdap.alipay.com\nmobilegw.alipay.com\ncustom-cdn.example.net\n"
	if err := os.WriteFile(filepath.Join(dir, "etc", "dpi_rules.d", "shared_infra.txt"), []byte(sharedTxt), 0o644); err != nil {
		t.Fatal(err)
	}
	rulesBody := `{"rules":[
		{"id":"taobao","app":"淘宝","category":"shopping","suffixes":["taobao.com","tmall.com","solo-shop.example.org","alipay.com","alicdn.com","github.io","custom-cdn.example.net"]},
		{"id":"alipay","app":"支付宝","category":"finance","suffixes":["alipay.com","mdap.alipay.com"]},
		{"id":"github","app":"GitHub","category":"dev","suffixes":["github.com","github.io","githubusercontent.com"]}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "etc", "dpi_rules.d", "10-test.json"), []byte(rulesBody), 0o644); err != nil {
		t.Fatal(err)
	}
	ipNameBody := `{"entries":{
		"203.0.113.10":{"name":"item.solo-shop.example.org","src":"sni","ts":10,"app":"taobao","category":"shopping"},
		"203.0.113.20":{"name":"cashier.alipay.com","src":"sni","ts":10,"app":"taobao","category":"shopping"},
		"203.0.113.21":{"name":"img.alipayobjects.com","src":"dns","ts":10,"app":"taobao","category":"shopping"},
		"203.0.113.30":{"name":"gw.alicdn.com","src":"dns","ts":10,"app":"taobao","category":"shopping"},
		"203.0.113.31":{"name":"pay.wechatpay.cn","src":"sni","ts":10,"app":"taobao","category":"shopping"},
		"203.0.113.40":{"name":"docs.github.io","src":"sni","ts":10,"app":"taobao","category":"shopping"},
		"203.0.113.41":{"name":"edge.custom-cdn.example.net","src":"dns","ts":10,"app":"taobao","category":"shopping"}
	}}`
	if err := os.WriteFile(filepath.Join(dir, "run", "dpi_ipname.json"), []byte(ipNameBody), 0o644); err != nil {
		t.Fatal(err)
	}
	ipAppJSON := `{"entries":[
		{"ip":"203.0.113.11","app_id":"taobao","category":"shopping"},
		{"ip":"203.0.113.20","app_id":"taobao","category":"shopping"},
		{"ip":"203.0.113.30","app_id":"taobao","category":"shopping"},
		{"ip":"203.0.113.40","app_id":"taobao","category":"shopping"}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "run", "ip_app_map.json"), []byte(ipAppJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	writeStub(t, dir, "connblock_sync.sh", "echo CONN_BLOCK=on\n")

	s := newServer(dir)
	mac := "aa:bb:cc:00:00:88"
	now := time.Now()
	setTodayActive(now, mac+"|taobao", 3600)
	if r := actionAppTimeLimitSet(s, map[string]string{"mac": mac, "app_id": "taobao", "minutes": "30"}); !r.OK {
		t.Fatalf("set taobao time limit failed: %+v", r)
	}
	s.connBlockRefresh()

	dnsRules := readFileStr(connBlocksDNS(dir))
	flatRules := readFileStr(connBlocksFlat(dir))

	for _, mustHave := range []string{mac + " taobao.com\n", mac + " tmall.com\n", mac + " solo-shop.example.org\n"} {
		if !strings.Contains(dnsRules, mustHave) {
			t.Fatalf("expected %q in conn_blocks.dns, got:\n%s", strings.TrimSpace(mustHave), dnsRules)
		}
	}
	for _, forbidden := range []string{"alipay.com", "alipayobjects.com", "alicdn.com", "wechatpay.cn", "github.io", "custom-cdn.example.net"} {
		if strings.Contains(dnsRules, forbidden) {
			t.Fatalf("limiting taobao MUST NOT block %q in conn_blocks.dns:\n%s", forbidden, dnsRules)
		}
	}
	if !strings.Contains(flatRules, mac+" 203.0.113.10") || !strings.Contains(flatRules, mac+" 203.0.113.11") {
		t.Fatalf("expected dedicated taobao IPs in conn_blocks.flat, got:\n%s", flatRules)
	}
	for _, forbiddenIP := range []string{"203.0.113.20", "203.0.113.21", "203.0.113.30", "203.0.113.31", "203.0.113.40", "203.0.113.41"} {
		if strings.Contains(flatRules, forbiddenIP) {
			t.Fatalf("limiting taobao MUST NOT block shared/alipay/github.io IP %s in conn_blocks.flat:\n%s", forbiddenIP, flatRules)
		}
	}

	// 验证显式限制 alipay 自身时允许封锁 alipay.com, 但仍排除 shared_infra.txt 中的 mdap.alipay.com
	setTodayActive(now, mac+"|alipay", 3600)
	if r := actionAppTimeLimitSet(s, map[string]string{"mac": mac, "app_id": "alipay", "minutes": "30"}); !r.OK {
		t.Fatalf("set alipay time limit failed: %+v", r)
	}
	derived := s.connBlockDerived(now)
	sawAlipayRoot, sawMdap := false, false
	for _, it := range derived {
		if it.Ref == "alipay" && it.Kind == "domain" {
			if it.Value == "alipay.com" {
				sawAlipayRoot = true
			}
			if it.Value == "mdap.alipay.com" {
				sawMdap = true
			}
		}
	}
	if !sawAlipayRoot || sawMdap {
		t.Fatalf("explicit alipay limit: want alipay.com=true mdap.alipay.com=false, got root=%v mdap=%v", sawAlipayRoot, sawMdap)
	}

	// 验证 app_limit_shared.go: 限速 taobao 与 github 时跳过 alipay.com、github.io、shared_infra.txt 对应 IP
	if err := os.WriteFile(filepath.Join(dir, "data", "app_limits.json"), []byte(
		`{"version":1,"items":[{"mac":"`+mac+`","app_id":"taobao","down_mbps":2},{"mac":"`+mac+`","app_id":"github","down_mbps":4}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ipAppFlat := strings.Join([]string{
		"203.0.113.10 taobao",
		"203.0.113.20 taobao", // cashier.alipay.com -> 异源支付, 跳过
		"203.0.113.30 taobao", // gw.alicdn.com -> shared_infra, 跳过
		"203.0.113.40 github", // docs.github.io -> 多租户托管后缀, 跳过
		"203.0.113.99 github", // 未在共享名单 -> 保留
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "run", "ip_app_map.flat"), []byte(ipAppFlat), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"devices":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.apiAppLimits(rec, httptest.NewRequest("GET", "/api/app_limits", nil))
	var alResp struct {
		Items []appLimitView `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &alResp); err != nil || len(alResp.Items) != 2 {
		t.Fatalf("apiAppLimits bad resp: %v %s", err, rec.Body.String())
	}
	if alResp.Items[0].IPsTotal != 3 || alResp.Items[0].IPsSharedSkipped != 2 || alResp.Items[0].IPsLimited != 1 {
		t.Fatalf("taobao app_limit stats mismatch: %+v", alResp.Items[0])
	}
	if alResp.Items[1].IPsTotal != 2 || alResp.Items[1].IPsSharedSkipped != 1 || alResp.Items[1].IPsLimited != 1 {
		t.Fatalf("github app_limit stats mismatch: %+v", alResp.Items[1])
	}
}

func TestWave4RC6EncdnsImmediateSyncAndDNSFailOpen(t *testing.T) {
	// 0. 保护 arm32 8 字节原子对齐
	var fAlign dnsForwarder
	if unsafe.Offsetof(fAlign.st) != 0 || unsafe.Offsetof(fAlign.wg) != 104 || unsafe.Offsetof(fAlign.wg)%8 != 0 {
		t.Fatalf("dnsForwarder arm32 atomic alignment broken: st=%d wg=%d", unsafe.Offsetof(fAlign.st), unsafe.Offsetof(fAlign.wg))
	}

	// 1. C042: actionEncdnsSet 改策略后立即同步 s.dnsTK() 内存拦截表(无需等 10s tick)
	dir, sEnc := setupEncdnsDir(t)
	_ = dir
	tkEnc := sEnc.dnsTK()
	t.Cleanup(tkEnc.Shutdown)
	tkEnc.refreshBlocklist(time.Now())
	if tkEnc.blocked("aa:bb:cc:00:00:01", "dns.google") {
		t.Fatal("dns.google should not be blocked when encdns=off")
	}
	if r := actionEncdnsSet(sEnc, map[string]string{"policy": "strict"}); !r.OK {
		t.Fatalf("actionEncdnsSet strict failed: %+v", r)
	}
	if !tkEnc.blocked("aa:bb:cc:00:00:01", "dns.google") {
		t.Fatal("C042: actionEncdnsSet(strict) must immediately refresh DNSTK blocklist in memory")
	}
	if r := actionEncdnsSet(sEnc, map[string]string{"policy": "off", "mac": "aa:bb:cc:00:00:01"}); !r.OK {
		t.Fatalf("actionEncdnsSet device off failed: %+v", r)
	}
	if tkEnc.blocked("aa:bb:cc:00:00:01", "dns.google") {
		t.Fatal("C042: device override off must immediately exempt MAC in DNSTK blocklist")
	}

	// 2. C043a: chooseUpstream 与自检探针拒绝 SERVFAIL/REFUSED 触发回退与 fail-open
	h := newTKHarness(t)
	// 默认恢复真实 blockSources 以防覆盖测试
	h.conf(`{"enabled":true}`)
	h.tk.systemDNS = func() []string { return []string{"10.88.88.88"} }

	var probeMu sync.Mutex
	tetherRcode := dnsRcodeServFail
	sysRcode := dnsRcodeNoError
	selfRcode := dnsRcodeNoError
	h.tk.probe = func(addr string, _ time.Duration) (time.Duration, int, error) {
		probeMu.Lock()
		defer probeMu.Unlock()
		switch addr {
		case "127.0.0.1:53":
			return time.Millisecond, tetherRcode, nil
		case "10.88.88.88:53":
			return time.Millisecond, sysRcode, nil
		default:
			if selfRcode < 0 {
				return 0, -1, errors.New("timeout")
			}
			return time.Millisecond, selfRcode, nil
		}
	}

	// tether 返回 SERVFAIL -> chooseUpstream 必须拒绝 tether 并回退 system(10.88.88.88:53)
	h.tk.tick()
	if st, act := h.state(); st != "active" || !act || h.tk.upstream != "10.88.88.88:53" || h.tk.upstreamKind != "system" {
		t.Fatalf("expected fallback to system DNS when tether returns SERVFAIL, got state=%s act=%v up=%s(%s)",
			st, act, h.tk.upstream, h.tk.upstreamKind)
	}

	// C043b: SyncNetSig 切网触发 FlushCache -> onFlush 重置 upCheckedAt 并 wake()
	select {
	case <-h.tk.wakeCh:
	default:
	}
	h.set(func() { h.netSig = "100.64.99.9@100.64.99.1@aa:bb:cc:dd:ee:ff|rmnet_data1" })
	if !h.tk.fwd.SyncNetSig("100.64.88.8|rmnet_data0") {
		// 首次非空仅建基线
		if !h.tk.fwd.SyncNetSig("100.64.99.9|rmnet_data1") {
			t.Fatal("second distinct SyncNetSig must trigger FlushCache")
		}
	}
	h.tk.mu.Lock()
	upCheckedAfterFlush := h.tk.upCheckedAt
	h.tk.mu.Unlock()
	if !upCheckedAfterFlush.IsZero() {
		t.Fatalf("onFlush after SyncNetSig must reset upCheckedAt to zero, got %v", upCheckedAfterFlush)
	}
	select {
	case <-h.tk.wakeCh:
	default:
		t.Fatal("onFlush after SyncNetSig must signal wakeCh")
	}

	// 自检探针返回 SERVFAIL / REFUSED -> 立即触发 selftest fail-open 删 DNAT
	probeMu.Lock()
	selfRcode = dnsRcodeServFail
	probeMu.Unlock()
	h.takeCalls()
	h.tk.tick()
	if st, act := h.state(); st != "failopen" || act || h.tk.foReason != "selftest" {
		t.Fatalf("selftest SERVFAIL must trigger failopen(selftest), got state=%s active=%v reason=%s", st, act, h.tk.foReason)
	}

	// 推进冷却恢复 active 后, 模拟窗口内 >=20 次上游查询且 >=50% 返回 REFUSED -> 计入 upErrs 触发 upstream_errors fail-open
	probeMu.Lock()
	selfRcode = dnsRcodeNoError
	probeMu.Unlock()
	h.advance(2 * time.Minute)
	h.tk.tick() // 重新接管
	h.tk.tick() // 建立 prevStats 基线

	uRefuse := startControllableUpstream(t)
	uRefuse.mu.Lock()
	uRefuse.rcode = dnsRcodeRefused
	uRefuse.mu.Unlock()
	h.tk.fwd.SetUpstream(uRefuse.addr)
	h.tk.mu.Lock()
	h.tk.upCheckedAt = h.now // 保持当前轮不重选覆盖 uRefuse
	h.tk.mu.Unlock()

	for i := 0; i < 24; i++ {
		q := dnsBuildQuery(uint16(0x600+i), "fail-"+string(rune('a'+i))+".example.com", dnsTypeA, 0, false)
		_ = h.tk.fwd.handle(q, net.ParseIP("192.168.43.55"), "udp")
	}
	h.tk.tick()
	if st, act := h.state(); st != "failopen" || act || h.tk.foReason != "upstream_errors" {
		t.Fatalf("expected upstream_errors fail-open when upstream returns REFUSED >=50%%, got state=%s act=%v reason=%s",
			st, act, h.tk.foReason)
	}

	// 3. C043c: handleWithStale 后台刷新协程纳入 wg 并随 Close() 立即取消(不等 2.5s/3s 超时)
	ucBlackhole, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ucBlackhole.Close()

	fwdBg := newDNSForwarder()
	fwdBg.staleWait = 40 * time.Millisecond
	fwdBg.timeout = 2500 * time.Millisecond
	fwdBg.SetUpstream(ucBlackhole.LocalAddr().String())

	qStale := dnsBuildQuery(0x701, "bg-cancel.test", dnsTypeA, 0, false)
	pqStale, _ := dnsParseQuery(qStale)
	rawStale := buildTestAReply(qStale, pqStale, net.IPv4(9, 9, 9, 9), 1, false)
	fwdBg.cache.put(dnsCacheKey(pqStale), rawStale, mustResp(t, rawStale), time.Now().Add(-5*time.Second))

	resp := fwdBg.handle(qStale, dnsTestClient, "udp")
	if m := mustResp(t, resp); len(m.Answers) != 1 || m.Answers[0].Value != "9.9.9.9" {
		t.Fatalf("expected stale fallback 9.9.9.9, got %+v", m)
	}
	// 此时后台静默刷新协程正在等 2500ms 黑洞超时; 调用 Close() 必须立即取消并在百毫秒内随 wg.Wait() 返回!
	closeStart := time.Now()
	fwdBg.Close()
	if closeCost := time.Since(closeStart); closeCost > 500*time.Millisecond {
		t.Fatalf("Close() did not cancel background stale refresh promptly: took %v (want <500ms)", closeCost)
	}
	if len(fwdBg.bgSem) != 0 {
		t.Fatalf("expected bgSem drained to 0 after Close() waited on wg, got %d", len(fwdBg.bgSem))
	}
}

func TestRC7DualSimBillingDayMigrationDNSKeepaliveAndUserAppRules(t *testing.T) {
	// 1. B032: 修改 billing_day 时仅淘汰 AnchorAt < newCycStart 的旧账期锚点,
	//    处于新账期内的有效锚点自动重算 AnchorBase 并更新 AnchorCycle, 且绝不误清另一张 SIM 卡有效锚点
	dir := t.TempDir()
	for _, sub := range []string{"data", "run", "bin"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	loc := time.FixedZone("CST", 8*3600)
	// 写入 10 月 12 日(2 GiB)与 10 月 18 日(3 GiB)的卡1蜂窝日计费记录
	writeSim1Day := func(date string, gib uint64) {
		day := &puDay{
			Date: date,
			Cell: map[string][2]uint64{"1|CMCC": {gib * puGiB, 0}},
		}
		b, _ := json.Marshal(day)
		if err := os.WriteFile(puDayPath(dir, date), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeSim1Day("20261012", 2)
	writeSim1Day("20261018", 3)

	// 10 月 5 日设 billing_day=1 + 卡2锚点 12 GB (AnchorAt=2026-10-05)
	tOct5 := time.Date(2026, 10, 5, 10, 0, 0, 0, loc)
	if r := actionPhoneUsageSetAt(dir, map[string]string{
		"billing_day":    "1",
		"plan_sim1_gb":   "100",
		"plan_sim2_gb":   "50",
		"anchor_sim2_gb": "12",
	}, tOct5); !r.OK {
		t.Fatalf("set sim2 anchor failed: %+v", r)
	}
	// 10 月 20 日设卡1锚点 30 GB (AnchorAt=2026-10-20, 此时 billing_day=1 下 AnchorBase=2+3=5 GiB)
	tOct20 := time.Date(2026, 10, 20, 15, 0, 0, 0, loc)
	if r := actionPhoneUsageSetAt(dir, map[string]string{
		"anchor_sim1_gb": "30",
	}, tOct20); !r.OK {
		t.Fatalf("set sim1 anchor failed: %+v", r)
	}
	cfgBefore := puLoadConfig(dir)
	if v2, ok := cfgBefore.AnchorGB["2"]; !ok || v2 != 12.0 {
		t.Fatalf("setting anchor_sim1_gb must NOT wipe SIM2 anchor, got %+v", cfgBefore.AnchorGB)
	}

	// 10 月 22 日修改 billing_day=15 (newCycStart=2026-10-15, newCyc="20261015"):
	//  - 卡2 AnchorAt(10-05) < 10-15 -> 淘汰清空;
	//  - 卡1 AnchorAt(10-20) >= 10-15 -> 保留 30 GB, AnchorCycle 更新为 "20261015", AnchorBase 重算为 [10-15..10-20] = 3 GiB!
	tOct22 := time.Date(2026, 10, 22, 9, 0, 0, 0, loc)
	if r := actionPhoneUsageSetAt(dir, map[string]string{
		"billing_day": "15",
	}, tOct22); !r.OK {
		t.Fatalf("change billing_day=15 failed: %+v", r)
	}
	cfgAfter := puLoadConfig(dir)
	if _, has2 := cfgAfter.AnchorGB["2"]; has2 {
		t.Fatalf("expired SIM2 anchor (10-05 < 10-15) must be evicted on billing_day change, got %+v", cfgAfter.AnchorGB)
	}
	if v1, has1 := cfgAfter.AnchorGB["1"]; !has1 || v1 != 30.0 || cfgAfter.AnchorCycle != "20261015" {
		t.Fatalf("in-cycle SIM1 anchor must survive billing_day=15 with cycle=20261015, got gb=%+v cycle=%q",
			cfgAfter.AnchorGB, cfgAfter.AnchorCycle)
	}
	if cfgAfter.AnchorBase["1"] != 3*puGiB {
		t.Fatalf("SIM1 AnchorBase must recompute for [10-15..10-20] = 3 GiB, got %d", cfgAfter.AnchorBase["1"])
	}

	// 验证 DPI 本机归因关闭态(!enabled)但热点存在 ip_app_map.json 时 evalDPI 仍填充 LANSelfConsistency
	if err := os.WriteFile(filepath.Join(dir, "run", "ip_app_map.json"), []byte(`{"entries":[{"ip":"203.0.113.50","app_id":"weixin"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	evRes := evalDPI(dir, 7, tOct22)
	if evRes.Enabled || evRes.LANSelfConsistency == nil {
		t.Fatalf("evalDPI(!enabled) must still populate LANSelfConsistency, got enabled=%v ptr=%v",
			evRes.Enabled, evRes.LANSelfConsistency)
	}

	// 2. B033: SetUpstream("") 弱网瞬断保留 180s 保活缓存, 切异源非空上游才清空; cooling && !active 前置不触发 chooseUpstream 探针
	fwd := newDNSForwarder()
	defer fwd.Close()
	fwd.SetUpstream("10.0.0.1:53")
	qKeep := dnsBuildQuery(0x801, "keepalive.rc7.test", dnsTypeA, 0, false)
	pqKeep, _ := dnsParseQuery(qKeep)
	rawKeep := buildTestAReply(qKeep, pqKeep, net.IPv4(1, 2, 3, 4), 60, false)
	nowDNS := time.Now()
	fwd.cache.put(dnsCacheKey(pqKeep), rawKeep, mustResp(t, rawKeep), nowDNS)

	fwd.SetUpstream("") // 弱网瞬断置空上游 -> 严禁清空保活缓存
	if !fwd.cache.hasStale(dnsCacheKey(pqKeep), nowDNS.Add(70*time.Second)) {
		t.Fatal("SetUpstream(\"\") must NOT flush 180s Serve-Stale cache during transient upstream loss")
	}
	fwd.SetUpstream("10.0.0.1:53") // 恢复同一上游 -> 仍保留缓存
	if !fwd.cache.hasStale(dnsCacheKey(pqKeep), nowDNS.Add(75*time.Second)) {
		t.Fatal("restoring identical upstream after empty gap must keep cache")
	}
	fwd.SetUpstream("10.0.0.2:53") // 切换不同非空上游 -> 清空旧网缓存
	if fwd.cache.hasStale(dnsCacheKey(pqKeep), nowDNS.Add(80*time.Second)) {
		t.Fatal("switching to a distinct non-empty upstream must flush cache")
	}

	hCool := newTKHarness(t)
	hCool.conf(`{"enabled":true}`)
	probeHits := 0
	hCool.tk.probe = func(string, time.Duration) (time.Duration, int, error) {
		probeHits++
		return time.Millisecond, dnsRcodeNoError, nil
	}
	hCool.tk.mu.Lock()
	hCool.tk.active = false
	hCool.tk.retryAt = hCool.now.Add(60 * time.Second)
	hCool.tk.foReason = "selftest"
	hCool.tk.mu.Unlock()
	hCool.tk.tick()
	if probeHits != 0 {
		t.Fatalf("cooling && !active must return before chooseUpstream probe, got probeHits=%d", probeHits)
	}

	// connBlocksFor 大小写 MAC 归一化验证
	if err := os.WriteFile(connBlocksPath(dir), []byte(`{"items":[{"mac":"AA:BB:CC:DD:EE:99","kind":"domain","value":"example.org"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	gotCB := connBlocksFor(dir, "AA:BB:CC:DD:EE:99")
	if len(gotCB) != 1 || gotCB[0].MAC != "aa:bb:cc:dd:ee:99" {
		t.Fatalf("connBlocksFor must normalize MAC to lowercase, got %+v", gotCB)
	}

	// 3. B036: user:xxx 自定义应用规则打通应用限速(actionAppLimitSet + apiAppLimits)与应用时长派生阻断(connBlockDerived)
	resetAppTimeGlobals(t)
	t.Setenv("HNC_DIR", dir)
	writeStub(t, dir, "connblock_sync.sh", "echo CONN_BLOCK=on\n")
	writeStub(t, dir, "apply_app_limits.sh", "exit 0\n")

	userRulesJSON := `{"schema":1,"rules":[
		{"id":"u1","kind":"domain","value":"erp.corp-rc7.example","app_id":"user:Corp.ERP-1","app_name":"企业ERP","category":"work","created":1800000000},
		{"id":"u2","kind":"ip","value":"198.51.100.77","app_id":"user:Corp.ERP-1","app_name":"企业ERP","category":"work","created":1800000000,"expires":4102444800}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "data", "dpi_user_rules.json"), []byte(userRulesJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "dpi_ipname.json"), []byte(
		`{"entries":{"198.51.100.78":{"name":"sso.erp.corp-rc7.example","src":"dns","ts":10}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"devices":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	sUser := newServer(dir)
	uMAC := "aa:bb:cc:11:22:33"
	if r := actionAppLimitSet(dir, map[string]string{"mac": uMAC, "app_id": "user:Corp.ERP-1", "down_mbps": "5"}); !r.OK {
		t.Fatalf("actionAppLimitSet must accept user:Corp.ERP-1, got %+v", r)
	}
	recAL := httptest.NewRecorder()
	sUser.apiAppLimits(recAL, httptest.NewRequest("GET", "/api/app_limits", nil))
	var alUser struct {
		Items []appLimitView `json:"items"`
	}
	if err := json.Unmarshal(recAL.Body.Bytes(), &alUser); err != nil || len(alUser.Items) != 1 {
		t.Fatalf("apiAppLimits user:Corp.ERP-1 bad resp: %v %s", err, recAL.Body.String())
	}
	if alUser.Items[0].IPsTotal != 2 || alUser.Items[0].IPsLimited != 2 {
		t.Fatalf("expected user:Corp.ERP-1 to match both explicit IP and domain->ipname IP (total=2), got %+v", alUser.Items[0])
	}

	nowU := time.Now()
	setTodayActive(nowU, uMAC+"|user:Corp.ERP-1", 3600)
	if r := actionAppTimeLimitSet(sUser, map[string]string{"mac": uMAC, "app_id": "user:Corp.ERP-1", "minutes": "15"}); !r.OK {
		t.Fatalf("actionAppTimeLimitSet must accept user:Corp.ERP-1, got %+v", r)
	}
	sUser.connBlockRefresh()
	uDNS := readFileStr(connBlocksDNS(dir))
	uFlat := readFileStr(connBlocksFlat(dir))
	if !strings.Contains(uDNS, uMAC+" erp.corp-rc7.example\n") {
		t.Fatalf("expected user:Corp.ERP-1 domain in conn_blocks.dns, got:\n%s", uDNS)
	}
	if !strings.Contains(uFlat, uMAC+" 198.51.100.77") || !strings.Contains(uFlat, uMAC+" 198.51.100.78") {
		t.Fatalf("expected user:Corp.ERP-1 explicit & domain-resolved IPs in conn_blocks.flat, got:\n%s", uFlat)
	}
}
