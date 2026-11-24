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
