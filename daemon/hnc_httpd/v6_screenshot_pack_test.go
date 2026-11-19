package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestV6MultiIfaceDiscoveryTun0GuardAndLANFastlane 覆盖:
//  1. Wi-Fi 7 MLO / 双频并发热点 (wlan1+wlan2) + USB 共享 (rndis0/ncm0) 多口识别与默认 WAN (wlan0/rmnet_data5) 排除;
//  2. 桥接从属口防双重限速判定 (ap_br_wlan 下挂 wlan1/wlan2 时仅对桥口启用 ShapeEnabled);
//  3. tun0 VPN 在线时的策略路由环路风险检出、ip rule 直连保护与 TCPMSS 钳制生成;
//  4. 1:fffe 2.5Gbps 局域网互传直通类 Netlink 报文(RATE64=312500000 B/s + 双键 u32 私网互传过滤)二进制校验。
func TestV6MultiIfaceDiscoveryTun0GuardAndLANFastlane(t *testing.T) {
	inputs := []V6IfaceProbeInput{
		{
			Name:         "wlan0",
			Ifindex:      3,
			OperUp:       true,
			IPv4CIDRs:    []string{"192.168.1.25/24"},
			IsDefaultWAN: true, // 上游 Wi-Fi STA, 绝不能误当热点口!
		},
		{
			Name:      "rmnet_data5",
			Ifindex:   4,
			OperUp:    true,
			IPv4CIDRs: []string{"10.88.12.3/30"},
		},
		{
			Name:      "wlan1",
			Ifindex:   11,
			OperUp:    true,
			PhyIndex:  0,
			IPv4CIDRs: []string{"192.168.43.1/24"},
		},
		{
			Name:      "wlan2",
			Ifindex:   12,
			OperUp:    true,
			PhyIndex:  0,
			IPv4CIDRs: []string{"192.168.44.1/24"},
		},
		{
			Name:      "rndis0",
			Ifindex:   15,
			OperUp:    true,
			IPv4CIDRs: []string{"192.168.42.129/24"},
		},
		{
			Name:    "tun0",
			Ifindex: 21,
			OperUp:  true,
			MTU:     1400,
		},
	}

	snap := AnalyzeMultiInterfaces(inputs, "wlan2", []string{"0: from all lookup local", "9000: from all uidrange 0-99999 lookup tun0"})
	if snap.PrimaryDownstream != "wlan2" {
		t.Fatalf("PrimaryDownstream=%q want wlan2", snap.PrimaryDownstream)
	}
	if !snap.DualBandOrMLO || !snap.USBTetherActive {
		t.Fatalf("expected DualBandOrMLO=true & USBTetherActive=true, got %+v", snap)
	}
	if got := strings.Join(snap.ShapeTargets, ","); got != "wlan2,wlan1,rndis0" {
		t.Fatalf("ShapeTargets=%q want wlan2,wlan1,rndis0 (wlan0 STA must be excluded)", got)
	}
	if !snap.Tun0Guard.VPNActive || !snap.Tun0Guard.LoopRiskDetected || !snap.Tun0Guard.Low16MarkSafe {
		t.Fatalf("unexpected Tun0Guard state: %+v", snap.Tun0Guard)
	}
	if len(snap.Tun0Guard.IPRuleSpecs) != 3 || len(snap.Tun0Guard.MangleGuardRules) == 0 {
		t.Fatalf("expected 3 subnet ip rules & mangle MSS rules, got %+v", snap.Tun0Guard)
	}

	// 验证桥接模式 (ap_br_wlan0 含成员 wlan1+wlan2): 只对主桥整形, 成员口不重复整形
	bridged := []V6IfaceProbeInput{
		{Name: "ap_br_wlan0", Ifindex: 30, OperUp: true, IPv4CIDRs: []string{"192.168.43.1/24"}},
		{Name: "wlan1", Ifindex: 31, OperUp: true, MasterBridge: "ap_br_wlan0"},
		{Name: "wlan2", Ifindex: 32, OperUp: true, MasterBridge: "ap_br_wlan0"},
		{Name: "ncm0", Ifindex: 33, OperUp: true, IPv4CIDRs: []string{"192.168.42.1/24"}},
	}
	bSnap := AnalyzeMultiInterfaces(bridged, "", nil)
	if !bSnap.DualBandOrMLO || strings.Join(bSnap.ShapeTargets, ",") != "ap_br_wlan0,ncm0" {
		t.Fatalf("bridged MLO ShapeTargets=%v want [ap_br_wlan0 ncm0]", bSnap.ShapeTargets)
	}

	// 验证 1:fffe 2.5Gbps 局域网直通类 Netlink 报文编码
	msgs, err := BuildLANFastlaneNetlinkBatch(12, []string{"192.168.43.1/24", "192.168.42.129/24"}, pschedDefaultTickUsec)
	if err != nil {
		t.Fatalf("BuildLANFastlaneNetlinkBatch failed: %v", err)
	}
	// 1 class + 1 fq_codel + 1 fw + 1 del_filter + 2x2 u32 = 8 条 Netlink 消息
	if len(msgs) != 8 {
		t.Fatalf("len(msgs)=%d want 8", len(msgs))
	}
	// 用现有 parseTCClassDumpMsgs 反向解码第 0 条 RTM_NEWTCLASS 报文验证 2.5Gbps RATE64 与 1:fffe handle!
	dumpStream := append([]byte(nil), msgs[0]...)
	dumpStream = append(dumpStream, testRTNLEncodeDone(1)...)
	parsed, err := parseTCClassDumpMsgs(dumpStream, 12)
	if err != nil {
		t.Fatalf("parseTCClassDumpMsgs on 1:fffe msg failed: %v", err)
	}
	st, ok := parsed["1:fffe"]
	if !ok {
		t.Fatalf("missing 1:fffe class in parsed dump: %+v", parsed)
	}
	if st.Parent != "1:1" || st.RateBps != v6LANFastlaneRateBps || st.CeilBps != v6LANFastlaneRateBps || st.Prio != 0 {
		t.Fatalf("1:fffe class params mismatch: %+v", st)
	}
}

// TestV6NativeSubtreesNetlinkAndDynamicQoS 覆盖:
//  1. 三档动态延迟联动比例计算 (平稳 50/35/15 -> 过渡平滑混合 -> 团战抗抖 70/20/10, 恒闭合 100%);
//  2. 1:a0XX 三档应用 QoS 子树 Netlink 二进制报文编码与解码校验;
//  3. 1:9001+ 单应用限速子树(ceil 钳制 <= 父设备上限 + 1:9eXX 防逃逸兜底类 + CONNMARK 先于 POSTROUTING 保存);
//  4. 原生 IPv6 128-bit u32 过滤器编码与 RTM_NEWNEIGH 邻居流解析。
func TestV6NativeSubtreesNetlinkAndDynamicQoS(t *testing.T) {
	calm := ComputeDynamicQoSRatios(4.0, 5.0)
	if calm.Tier1Pct != 50 || calm.Tier2Pct != 35 || calm.Tier3Pct != 15 || calm.Mode != "normal_50_35_15" {
		t.Fatalf("calm ratios=%+v want 50/35/15", calm)
	}
	combat := ComputeDynamicQoSRatios(42.0, 55.0)
	if combat.Tier1Pct != 70 || combat.Tier2Pct != 20 || combat.Tier3Pct != 10 || combat.Mode != "combat_70_20_10" {
		t.Fatalf("combat ratios=%+v want 70/20/10", combat)
	}
	midBlend := ComputeDynamicQoSRatios(23.5, 20.0)
	if midBlend.Tier1Pct+midBlend.Tier2Pct+midBlend.Tier3Pct != 100 || midBlend.Tier1Pct <= 50 || midBlend.Tier1Pct >= 70 {
		t.Fatalf("blend ratios must sum to 100 and sit between 50..70: %+v", midBlend)
	}

	// 验证 1:a0XX Netlink 报文编码 (mid=5, 父速率 100 Mbps = 12,500,000 B/s, 团战 70/20/10)
	devMark, devMask := readDeviceMarkSpec("", 5)
	qosMsgs, err := BuildAppQoSSubtreeNetlinkBatch(9, 5, 12_500_000, 12_500_000, devMark, devMask, combat, pschedDefaultTickUsec)
	if err != nil {
		t.Fatalf("BuildAppQoSSubtreeNetlinkBatch failed: %v", err)
	}
	var classStream []byte
	for _, m := range qosMsgs {
		if binary.LittleEndian.Uint16(m[4:6]) == rtnlNewTClass {
			classStream = append(classStream, m...)
		}
	}
	classStream = append(classStream, testRTNLEncodeDone(1)...)
	qosClasses, err := parseTCClassDumpMsgs(classStream, 9)
	if err != nil {
		t.Fatalf("parseTCClassDumpMsgs(qos) failed: %v", err)
	}
	// mid=5 -> parent "1:5", Tier1="1:a015"(70%=8,750,000 B/s), Tier2="1:a016"(20%=2,500,000 B/s), Tier3="1:a017"(10%=1,250,000 B/s)
	if qosClasses["1:a015"].RateBps != 8_750_000 || qosClasses["1:a015"].Parent != "1:5" || qosClasses["1:a015"].Prio != 0 {
		t.Fatalf("Tier 1 1:a015 mismatch: %+v", qosClasses["1:a015"])
	}
	if qosClasses["1:a016"].RateBps != 2_500_000 || qosClasses["1:a017"].RateBps != 1_250_000 {
		t.Fatalf("Tier 2/3 rates mismatch: t2=%+v t3=%+v", qosClasses["1:a016"], qosClasses["1:a017"])
	}

	// 验证 1:9001+ 单应用限速子树 (父设备限速 20 Mbps = 2,500,000 B/s, 应用配置 50 Mbps -> 必须钳制到 20 Mbps, 且自动创建 1:9e05 兜底子类!)
	asgs := []V6AppLimitSlotAssignment{
		{
			Slot:        1,
			MAC:         "aa:bb:cc:dd:ee:05",
			Mid:         5,
			RateBps:     6_250_000, // 50 Mbps > 父设备 20 Mbps, 必须钳制!
			CeilBps:     6_250_000,
			AppID:       "douyin",
			IPv4Targets: []string{"203.0.113.10"},
			IPv6Targets: []string{"2001:db8::10"},
		},
	}
	limMsgs, err := BuildAppLimitSubtreeNetlinkBatch(9, 5, 2_500_000, 2_500_000, devMark, devMask, asgs, false, pschedDefaultTickUsec)
	if err != nil {
		t.Fatalf("BuildAppLimitSubtreeNetlinkBatch failed: %v", err)
	}
	var limStream []byte
	for _, m := range limMsgs {
		if binary.LittleEndian.Uint16(m[4:6]) == rtnlNewTClass {
			limStream = append(limStream, m...)
		}
	}
	limStream = append(limStream, testRTNLEncodeDone(2)...)
	limClasses, err := parseTCClassDumpMsgs(limStream, 9)
	if err != nil {
		t.Fatalf("parseTCClassDumpMsgs(app_limit) failed: %v", err)
	}
	if limClasses["1:9001"].CeilBps != 2_500_000 || limClasses["1:9001"].Parent != "1:5" {
		t.Fatalf("1:9001 ceil clamp or parent failed: %+v", limClasses["1:9001"])
	}
	if _, hasDef := limClasses["1:9e05"]; !hasDef {
		t.Fatalf("expected anti-escape default child 1:9e05 when hasAppQoS=false, got %+v", limClasses)
	}

	v4FW, v6FW := BuildAppLimitFirewallPayloads(asgs, map[string]string{"aa:bb:cc:dd:ee:05": "192.168.43.55"}, map[string][]string{"aa:bb:cc:dd:ee:05": {"2409:8900::55"}})
	if !bytes.Contains(v4FW, []byte("CONNMARK --save-mark")) || !bytes.Contains(v4FW, []byte("HNC_QUIC_APPLIM")) || !bytes.Contains(v6FW, []byte("icmp6-port-unreachable")) {
		t.Fatalf("firewall payloads missing CONNMARK save or QUIC reject:\nv4=%s\nv6=%s", string(v4FW), string(v6FW))
	}

	// 验证原生 IPv6 128-bit u32 过滤器报文长度与 4-key 结构 + 邻居 dump 解析
	ip6 := net.ParseIP("2409:8963:e03:4493::abcd")
	v6FilterMsg, err := BuildU32IPv6FilterMsg(77, 9, rtnlHtbRootMaj, 205, ip6, false, 0x00010005)
	if err != nil || len(v6FilterMsg) < rtnlMsgHdrLen+rtnlTcMsgLen+80 {
		t.Fatalf("BuildU32IPv6FilterMsg err=%v len=%d", err, len(v6FilterMsg))
	}

	// 合成一条 RTM_NEWNEIGH (AF_INET6, REACHABLE, ifindex=9) + NLMSG_DONE 验证 parseIPv6NeighDumpMsgs
	var neighPayload []byte
	neighPayload = rtnlPutAttr(neighPayload, ndaDst, ip6.To16())
	neighPayload = rtnlPutAttr(neighPayload, ndaLLAddr, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x05})
	ndTotal := rtnlMsgHdrLen + 12 + len(neighPayload)
	ndMsg := make([]byte, ndTotal)
	binary.LittleEndian.PutUint32(ndMsg[0:4], uint32(ndTotal))
	binary.LittleEndian.PutUint16(ndMsg[4:6], uint16(syscall.RTM_NEWNEIGH))
	ndMsg[16] = uint8(syscall.AF_INET6)
	binary.LittleEndian.PutUint32(ndMsg[20:24], 9)
	binary.LittleEndian.PutUint16(ndMsg[24:26], nudReachable)
	copy(ndMsg[28:], neighPayload)
	ndStream := append(ndMsg, testRTNLEncodeDone(9)...)

	neighMap, done, err := parseIPv6NeighDumpMsgs(ndStream, map[int]bool{9: true})
	if err != nil || !done || len(neighMap["aa:bb:cc:dd:ee:05"]) != 1 || !neighMap["aa:bb:cc:dd:ee:05"][0].Equal(ip6) {
		t.Fatalf("parseIPv6NeighDumpMsgs failed: done=%v err=%v map=%+v", done, err, neighMap)
	}
}

// TestV6JitterBlackbox200msRingAndCulpritPinning 覆盖:
//  1. 200ms 粒度环形缓冲满容量循环覆盖无泄漏;
//  2. 平稳期不误报事件, 突刺瞬间精准定格元凶设备 MAC、IP、备注、峰值带宽占比与活跃应用!
func TestV6JitterBlackbox200msRingAndCulpritPinning(t *testing.T) {
	jb := NewJitterBlackbox(16, 4)
	baseTs := time.Unix(1710000000, 0)

	// 先喂 20 帧平稳流量 (超过环容量 16, 验证环形覆盖)
	for i := 0; i < 20; i++ {
		_, inc := jb.RecordSample(BlackboxTickInput{
			Now:         baseTs.Add(time.Duration(i*200) * time.Millisecond),
			RTTMs:       24.0,
			BaseRTTMs:   20.0,
			CapacityBps: 12_500_000, // 100 Mbps
			Devices: []BlackboxDeviceSample{
				{MAC: "aa:bb:cc:00:00:01", IP: "192.168.43.10", Name: "主力手机", RxBps: 120_000, TxBps: 30_000, ActiveAppID: "tencent_game", ActiveAppName: "王者荣耀"},
			},
		})
		if inc != nil {
			t.Fatalf("calm tick %d should not trigger incident: %+v", i, inc)
		}
	}

	// 第 21 帧 (t = +4.2s): 室友平板突发拉满 94 Mbps 下载 + RTT 从 24ms 暴涨到 118ms!
	spikeFrame, inc := jb.RecordSample(BlackboxTickInput{
		Now:         baseTs.Add(4200 * time.Millisecond),
		RTTMs:       118.0,
		BaseRTTMs:   20.0,
		CapacityBps: 12_500_000,
		Devices: []BlackboxDeviceSample{
			{MAC: "aa:bb:cc:00:00:01", IP: "192.168.43.10", Name: "主力手机", RxBps: 80_000, TxBps: 25_000, ActiveAppID: "tencent_game", ActiveAppName: "王者荣耀"},
			{MAC: "aa:bb:cc:00:00:99", IP: "192.168.43.99", Name: "室友平板", RxBps: 11_750_000, TxBps: 150_000, ActiveAppID: "douyin", ActiveAppName: "抖音"},
		},
	})
	if inc == nil {
		t.Fatal("expected spike incident to be pinned, got nil")
	}
	if inc.CulpritMAC != "aa:bb:cc:00:00:99" || inc.CulpritIP != "192.168.43.99" || inc.ActiveAppID != "douyin" {
		t.Fatalf("wrong culprit pinned: %+v (frame=%+v)", inc, spikeFrame)
	}
	if inc.Reason != "rtt_and_bw_spike" || inc.CulpritSharePct < 95.0 {
		t.Fatalf("unexpected incident reason/share: %+v", inc)
	}

	frames, incidents := jb.Snapshot(16, false)
	if len(frames) != 16 || len(incidents) != 1 {
		t.Fatalf("ring snapshot counts mismatch: frames=%d (want 16) incidents=%d (want 1)", len(frames), len(incidents))
	}
	if frames[len(frames)-1].Seq != 21 {
		t.Fatalf("latest frame seq=%d want 21", frames[len(frames)-1].Seq)
	}
}

// TestV6BackupExportRestoreRoundtripAndTamperGuard 覆盖:
//  1. GET /api/backup 一键打包导出 rules.json / device_names.json / templates.json / conn_blocks.json / app_limits.json / v6_*.json
//     并自动排除敏感会话密钥 remote_tokens.json;
//  2. 篡改任意 1 字节配置触发 SHA256 校验拦截且目标目录零脏写;
//  3. POST /api/backup 跨实例原子恢复全部配置 + 伴生 app_limits.flat 一致性核验 + 路由汇总入口自检。
func TestV6BackupExportRestoreRoundtripAndTamperGuard(t *testing.T) {
	srcDir := t.TempDir()
	mustWrite := func(base, rel, content string) {
		t.Helper()
		full := filepath.Join(base, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mustWrite(srcDir, "data/rules.json", `{
  "version": 1,
  "auth_required": false,
  "whitelist_mode": false,
  "hotspot_ssid": "RMX5010_5G",
  "devices": {
    "aa:bb:cc:dd:ee:01": {"ip": "192.168.43.10", "mark_id": 2, "limit_enabled": true, "down_mbps": "50", "up_mbps": "20", "app_qos": true}
  },
  "blacklist": ["aa:bb:cc:dd:ee:99"],
  "whitelist": []
}`)
	mustWrite(srcDir, "data/device_names.json", `{"aa:bb:cc:dd:ee:01": "一加平板 Pro"}`)
	mustWrite(srcDir, "data/templates.json", `{"gaming": {"down_mbps": 50, "up_mbps": 20}}`)
	mustWrite(srcDir, "data/conn_blocks.json", `{"items": [{"mac": "aa:bb:cc:dd:ee:01", "kind": "domain", "value": "ads.example.com", "ts": 1700000000}]}`)
	mustWrite(srcDir, "data/app_limits.json", `{"version": 1, "items": [{"mac": "aa:bb:cc:dd:ee:01", "app_id": "douyin", "down_mbps": 8.5}]}`)
	mustWrite(srcDir, "data/v6_qos_profile.json", `{"dynamic_enabled": true, "combat_ratio": [70, 20, 10]}`)
	// 敏感 token 文件绝不能出现在导出备份包中!
	mustWrite(srcDir, "data/remote_tokens.json", `{"tokens": {"secret_id": {"hash": "secret"}}}`)

	srcSrv := newServer(srcDir)
	srcMux := http.NewServeMux()
	srcSrv.registerV6ScreenshotPackRoutes(srcMux)

	// 1. 测试 GET /api/backup
	reqGet := httptest.NewRequest(http.MethodGet, "/api/backup?download=1", nil)
	recGet := httptest.NewRecorder()
	srcMux.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Fatalf("GET /api/backup status=%d body=%s", recGet.Code, recGet.Body.String())
	}
	if !strings.Contains(recGet.Header().Get("Content-Disposition"), "hnc-v6-backup.json") {
		t.Errorf("missing download Content-Disposition header")
	}

	var bundle V6BackupBundle
	if err := json.Unmarshal(recGet.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode backup bundle: %v", err)
	}
	if bundle.FileCount != 6 || len(bundle.SHA256) != 64 {
		t.Fatalf("unexpected bundle metadata: count=%d sha256=%q", bundle.FileCount, bundle.SHA256)
	}
	if _, leaked := bundle.Files["remote_tokens.json"]; leaked {
		t.Fatal("SECURITY: remote_tokens.json must never be exported in /api/backup")
	}
	if _, ok := bundle.Files["v6_qos_profile.json"]; !ok {
		t.Fatal("v6_qos_profile.json was not included in backup")
	}

	// 2. 准备干净目标目录, 先验证篡改内容但未改 SHA256 时被严格拒绝且零落盘
	dstDir := t.TempDir()
	mustWrite(dstDir, "data/rules.json", `{"version":1,"auth_required":false,"whitelist_mode":false,"devices":{},"blacklist":[],"whitelist":[]}`)
	dstSrv := newServer(dstDir)
	dstMux := http.NewServeMux()
	dstSrv.registerV6ScreenshotPackRoutes(dstMux)

	tampered := bundle
	tampered.Files = make(map[string]json.RawMessage, len(bundle.Files))
	for k, v := range bundle.Files {
		tampered.Files[k] = v
	}
	tampered.Files["device_names.json"] = json.RawMessage(`{"aa:bb:cc:dd:ee:01":"被篡改名称"}`)
	tamperedBytes, _ := json.Marshal(tampered)

	reqTamper := httptest.NewRequest(http.MethodPost, "/api/backup", bytes.NewReader(tamperedBytes))
	reqTamper.Header.Set("Content-Type", "application/json")
	reqTamper.Header.Set("X-HNC-CSRF", "1")
	recTamper := httptest.NewRecorder()
	dstMux.ServeHTTP(recTamper, reqTamper)
	if recTamper.Code != http.StatusBadRequest || !strings.Contains(recTamper.Body.String(), "sha256_mismatch") {
		t.Fatalf("tampered backup should fail with 400 sha256_mismatch, got %d %s", recTamper.Code, recTamper.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dstDir, "data", "device_names.json")); !os.IsNotExist(err) {
		t.Fatal("tampered restore must not write any files")
	}

	// 3. 提交合法未篡改备份包到 POST /api/backup, 验证原子恢复与往返哈希 100% 一致
	reqPost := httptest.NewRequest(http.MethodPost, "/api/backup", bytes.NewReader(recGet.Body.Bytes()))
	reqPost.Header.Set("Content-Type", "application/json")
	reqPost.Header.Set("X-HNC-CSRF", "1")
	recPost := httptest.NewRecorder()
	dstMux.ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusOK {
		t.Fatalf("POST /api/backup restore failed: code=%d body=%s", recPost.Code, recPost.Body.String())
	}

	// 再次在 dstSrv 上导出备份包, 顶层 SHA256 必须与源端完全一致!
	reExported, err := ExportBackupBundle(dstDir)
	if err != nil {
		t.Fatalf("re-export from restored dir failed: %v", err)
	}
	if reExported.SHA256 != bundle.SHA256 {
		t.Fatalf("roundtrip SHA256 mismatch: got %s want %s", reExported.SHA256, bundle.SHA256)
	}

	// 核验伴生 data/app_limits.flat 同步写出
	flatBytes, err := os.ReadFile(filepath.Join(dstDir, "data", "app_limits.flat"))
	if err != nil || !strings.Contains(string(flatBytes), "aa:bb:cc:dd:ee:01 douyin 8.5") {
		t.Fatalf("companion app_limits.flat not synced: err=%v content=%q", err, string(flatBytes))
	}

	// 4. 顺带核验 /api/v6/blackbox 路由与 v6ScreenshotPackSummary 汇总接口
	reqBB := httptest.NewRequest(http.MethodGet, "/api/v6/blackbox?limit=5", nil)
	recBB := httptest.NewRecorder()
	dstMux.ServeHTTP(recBB, reqBB)
	if recBB.Code != http.StatusOK {
		t.Fatalf("GET /api/v6/blackbox status=%d", recBB.Code)
	}
	summary := dstSrv.v6ScreenshotPackSummary()
	if summary["multi_iface"] == nil || summary["native_subtrees"] == nil || summary["blackbox"] == nil || summary["backup"] == nil {
		t.Fatalf("v6ScreenshotPackSummary missing keys: %+v", summary)
	}
}
