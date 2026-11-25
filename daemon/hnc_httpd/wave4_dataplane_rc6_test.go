//go:build linux || android

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func buildTestNLMsgDone(seq uint32) []byte {
	b := make([]byte, rtnlMsgHdrLen+4)
	binary.LittleEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.LittleEndian.PutUint16(b[4:6], rtnlMsgDone)
	binary.LittleEndian.PutUint32(b[8:12], seq)
	return b
}

// 1. Go 原生数据面: 单向 0 复位 1:1、ifb0 缺失回报、tc_leaf_aqm=off、Netlink seq 过滤、HNC_CTRL 源 MAC 绑定与空规则热回收
func TestWave4NativeDataplaneFixes(t *testing.T) {
	// (a) nlTuneGlobalShaperOnSocket: down=0, up>0 且 ifbIfindex<=0 必须返回 errGlobalShaperNeedIFBInit;
	//     单向 0 时必须将已建树的对应接口 1:1 复位回 DefaultHTBRootRateBps (1000mbit)
	if _, err := nlTuneGlobalShaperOnSocket(99, 7, 0, 0, 5_000_000); !errors.Is(err, errGlobalShaperNeedIFBInit) {
		t.Fatalf("expected errGlobalShaperNeedIFBInit when down=0 up>0 ifb<=0, got %v", err)
	}

	origSend := nlShaperSendAndWaitAckFn
	defer func() { nlShaperSendAndWaitAckFn = origSend }()
	var sentMsgs [][]byte
	nlShaperSendAndWaitAckFn = func(_ int, msg []byte, _ uint32) error {
		cp := append([]byte(nil), msg...)
		sentMsgs = append(sentMsgs, cp)
		return nil
	}
	cnt, err := nlTuneGlobalShaperOnSocket(99, 7, 25_000_000, 8, 0)
	if err != nil || cnt != 2 || len(sentMsgs) != 2 {
		t.Fatalf("nlTuneGlobalShaperOnSocket(down>0, up=0) = (%d, %v), msgs=%d", cnt, err, len(sentMsgs))
	}
	parsedUp, err := parseTCClassDumpMsgs(sentMsgs[1], 8)
	if err != nil || parsedUp["1:1"].RateBps != DefaultHTBRootRateBps {
		t.Fatalf("expected ifb 1:1 reset to DefaultHTBRootRateBps (%d), got %+v err=%v", DefaultHTBRootRateBps, parsedUp["1:1"], err)
	}

	// (b) tc_leaf_aqm=off 贯穿设备子树与 Tier3 批处理, 按速率比例挂载 pfifo limit
	dir := setupNativeTierTestEnv(t, "wlan2")
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"version":1,"tc_leaf_aqm":"off","devices":{}}`), 0o600)
	rulesStore.Invalidate(dir)
	if gotMode := readTCLeafAQMMode(dir); gotMode != "off" {
		t.Fatalf("expected readTCLeafAQMMode=off, got %q", gotMode)
	}
	if gotLeaf := resolveTier3LeafQdiscSpec(dir, false, 50_000); !strings.HasPrefix(gotLeaf, "pfifo limit ") {
		t.Fatalf("expected scaled pfifo leaf when tc_leaf_aqm=off, got %q", gotLeaf)
	}
	batchOff, err := buildAppLimitSubtreeNetlinkBatchWithAQM(
		7, 1, 10_000_000, 10_000_000, 0x00810000, 0x00ff0000,
		[]V6AppLimitSlotAssignment{{
			Slot: 1, MAC: "aa:bb:cc:dd:ee:01", Mid: 1, ParentMinor: 0x000b,
			ClassMinor: 0x9001, MarkVal: 0x04000000, AppID: "tv.danmaku.bili",
			RateBps: 1_000_000, CeilBps: 1_000_000,
		}},
		false, pschedDefaultTickUsec, "off",
	)
	if err != nil {
		t.Fatalf("buildAppLimitSubtreeNetlinkBatchWithAQM(off): %v", err)
	}
	hasPfifo, hasFqCodel := false, false
	for _, m := range batchOff {
		if bytes.Contains(m, []byte("pfifo\x00")) {
			hasPfifo = true
		}
		if bytes.Contains(m, []byte("fq_codel\x00")) {
			hasFqCodel = true
		}
	}
	if !hasPfifo || hasFqCodel {
		t.Fatalf("tc_leaf_aqm=off batch should attach pfifo without fq_codel: hasPfifo=%v hasFqCodel=%v", hasPfifo, hasFqCodel)
	}

	// (c) Netlink dump 严格校验 nlmsg_seq: 忽略错序旧 seq 的 NLMSG_DONE, 直到匹配当前 seq
	staleDone := buildTestNLMsgDone(111)
	goodClass := buildHTBClassUpsertMsg(222, 7, rtnlHtbRootMaj, rtnlHtbRootCls, 12_500_000, 12_500_000, 65536, 65536, 15000, 0, pschedDefaultTickUsec)
	goodDone := buildTestNLMsgDone(222)
	combinedClass := append(append([]byte{}, staleDone...), goodClass...)
	combinedClass = append(combinedClass, goodDone...)
	clsOut := make(map[string]HTBClassStat)
	doneCls, err := parseTCClassDumpChunkWithSeq(combinedClass, 222, 7, clsOut)
	if err != nil || !doneCls || clsOut["1:1"].RateBps != 12_500_000 {
		t.Fatalf("parseTCClassDumpChunkWithSeq failed to skip stale seq NLMSG_DONE: done=%v err=%v out=%+v", doneCls, err, clsOut)
	}

	goodQdisc := buildHTBRootQdiscMsg(333, 7, rtnlDefMinor)
	combinedQdisc := append(append([]byte{}, staleDone...), goodQdisc...)
	combinedQdisc = append(combinedQdisc, buildTestNLMsgDone(333)...)
	var qdiscs []rtnlQdiscBrief
	doneQd, err := parseQdiscBriefChunkWithSeq(combinedQdisc, 333, 7, &qdiscs)
	if err != nil || !doneQd || len(qdiscs) != 1 || qdiscs[0].kind != "htb" {
		t.Fatalf("parseQdiscBriefChunkWithSeq failed to skip stale seq: done=%v err=%v qdiscs=%+v", doneQd, err, qdiscs)
	}

	rtMsg := make([]byte, rtnlMsgHdrLen+rtnlRtMsgLen+8)
	binary.LittleEndian.PutUint32(rtMsg[0:4], uint32(len(rtMsg)))
	binary.LittleEndian.PutUint16(rtMsg[4:6], rtnlNewRoute)
	binary.LittleEndian.PutUint32(rtMsg[8:12], 444)
	rtMsg[16] = 2              // AF_INET
	rtMsg[16+7] = rtnlRtnUnicast
	binary.LittleEndian.PutUint16(rtMsg[28:30], 8)
	binary.LittleEndian.PutUint16(rtMsg[30:32], rtnlRtaOif)
	binary.LittleEndian.PutUint32(rtMsg[32:36], 19)
	combinedRt := append(append([]byte{}, staleDone...), rtMsg...)
	combinedRt = append(combinedRt, buildTestNLMsgDone(444)...)
	defIfs, doneRt, err := parseDefaultRouteIfindexesMsgsWithSeq(combinedRt, 444)
	if err != nil || !doneRt || !defIfs[19] {
		t.Fatalf("parseDefaultRouteIfindexesMsgsWithSeq failed: defIfs=%+v done=%v err=%v", defIfs, doneRt, err)
	}

	// (d) HNC_CTRL 上行源 IP 封禁强制绑定 -m mac --mac-source 防 DHCP 租期复用连坐断网
	v4Fw, _, err := buildDeviceFirewallRestorePayloads(dir, "wlan2", "aa:bb:cc:dd:ee:09", "192.168.43.99", 0, false, true, false)
	if err != nil {
		t.Fatalf("buildDeviceFirewallRestorePayloads: %v", err)
	}
	if !strings.Contains(string(v4Fw), "-A HNC_CTRL -s 192.168.43.99/32 -m mac --mac-source aa:bb:cc:dd:ee:09 -j DROP") {
		t.Fatalf("expected HNC_CTRL uplink IP rule bound to source MAC, got:\n%s", string(v4Fw))
	}
	fullV4, _ := BuildFirewallPayloads(dir, map[string]any{
		"blacklist": []any{"aa:bb:cc:dd:ee:09"},
	}, map[string]string{"aa:bb:cc:dd:ee:09": "192.168.43.99"}, false)
	if !strings.Contains(string(fullV4), "-A HNC_CTRL -s 192.168.43.99/32 -m mac --mac-source aa:bb:cc:dd:ee:09 -j DROP") {
		t.Fatalf("BuildFirewallPayloads HNC_CTRL uplink IP rule missing -m mac --mac-source:\n%s", string(fullV4))
	}

	// (e) 空规则热恢复生成逆序拆除残留 HTB 1:10+mid / 1:9001+ / 1:9e01 类与清空 HNC_APP_LIMIT* 载荷
	existingCls := map[string]HTBClassStat{
		"1:b":    {ClassID: "1:b", HandleRaw: 0x0001000b, ParentRaw: rtnlHtbRootCls},
		"1:9001": {ClassID: "1:9001", HandleRaw: 0x00019001, ParentRaw: 0x0001000b},
		"1:9e01": {ClassID: "1:9e01", HandleRaw: 0x00019e01, ParentRaw: 0x0001000b},
	}
	tdBatch := buildStaleHTBTeardownBatch(dir, 7, false, existingCls, map[uint16]bool{}, []int{1}, map[uint16]bool{}, nil, nil, 1)
	var delHandles []uint32
	for _, m := range tdBatch {
		if len(m) >= 28 && binary.LittleEndian.Uint16(m[4:6]) == rtnlDelTClass {
			delHandles = append(delHandles, binary.LittleEndian.Uint32(m[24:28]))
		}
	}
	indexOfHandle := func(h uint32) int {
		for i, v := range delHandles {
			if v == h {
				return i
			}
		}
		return -1
	}
	i9001, i9e01, iParent := indexOfHandle(0x00019001), indexOfHandle(0x00019e01), indexOfHandle(0x0001000b)
	if i9001 < 0 || i9e01 < 0 || iParent < 0 || i9001 >= iParent || i9e01 >= iParent {
		t.Fatalf("expected child classes 1:9001/1:9e01 deleted BEFORE parent 1:b (0x1000b), got %#x", delHandles)
	}
	emptyAL4, emptyAL6 := buildEmptyAppLimitFirewallPayloads()
	if !strings.Contains(string(emptyAL4), ":HNC_APP_LIMIT_UP - [0:0]") || !strings.Contains(string(emptyAL4), ":HNC_QUIC_APPLIM - [0:0]") ||
		!strings.Contains(string(emptyAL6), ":HNC_APP_LIMIT_DOWN - [0:0]") {
		t.Fatalf("unexpected empty app limit payloads:\nv4=%s\nv6=%s", string(emptyAL4), string(emptyAL6))
	}
}

// 2. VectorExpress 与 UpdateLeash: 双栈独立重试摘要、HotspotOff 只读快照、bypass_once 清理 conn_blocks 与 ReloadFromDisk 对齐 pausedSet
func TestWave4ExpressAndLeashFixes(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	exp := s.v6State().express
	leash := s.v6State().leash

	// (a) VectorExpress: IPv6 mangle 首次失败时绝不被 v4 成功掩盖, 下一轮仅精准重试 IPv6
	var v4Calls, v6Calls atomic.Int32
	failV6 := atomic.Bool{}
	failV6.Store(true)
	exp.mangleApplyFn = func(isIPv6 bool, _ string) error {
		if isIPv6 {
			v6Calls.Add(1)
			if failV6.Load() {
				return errors.New("mock ip6tables lock busy")
			}
			return nil
		}
		v4Calls.Add(1)
		return nil
	}
	exp.syncExpressMangleDataplane(dir, true, []string{"aa:bb:cc:dd:ee:01"})
	if v4Calls.Load() != 1 || v6Calls.Load() != 1 {
		t.Fatalf("expected 1st sync to call v4=1 v6=1, got v4=%d v6=%d", v4Calls.Load(), v6Calls.Load())
	}
	failV6.Store(false)
	exp.syncExpressMangleDataplane(dir, true, []string{"aa:bb:cc:dd:ee:01"})
	if v4Calls.Load() != 1 || v6Calls.Load() != 2 {
		t.Fatalf("expected 2nd sync to skip v4 and retry failed v6 (v4=1 v6=2), got v4=%d v6=%d", v4Calls.Load(), v6Calls.Load())
	}

	// (b) UpdateLeash: IPv6 mangle 失败后下一轮独立重试 IPv6
	var lV4Calls, lV6Calls atomic.Int32
	lFailV6 := atomic.Bool{}
	lFailV6.Store(true)
	leash.mangleApplyFn = func(isIPv6 bool, _ string) error {
		if isIPv6 {
			lV6Calls.Add(1)
			if lFailV6.Load() {
				return errors.New("mock ip6tables-restore failed")
			}
			return nil
		}
		lV4Calls.Add(1)
		return nil
	}
	sess := []UpdateLeashSession{{SessionKey: "aa:bb:cc:dd:ee:01|swcdn.apple.com", MAC: "aa:bb:cc:dd:ee:01", DstIP: "17.253.144.10", State: leashStateLeashed}}
	leash.syncLeashMangleDataplane(sess)
	lFailV6.Store(false)
	leash.syncLeashMangleDataplane(sess)
	if lV4Calls.Load() != 1 || lV6Calls.Load() != 2 {
		t.Fatalf("expected UpdateLeash mangle retry v4=1 v6=2, got v4=%d v6=%d", lV4Calls.Load(), lV6Calls.Load())
	}

	// (c) UpdateLeash: HotspotOff 期间 GET /api/v6/update_leash 走 ReadOnlySnapshot 零副作用短路
	feed := newMockActivityFeed(Activity{Known: true, HotspotActive: false})
	leash.activityHook = feed.Read
	var liveSampleCalls atomic.Int32
	leash.flowsHook = func() []UpdateFlowInput {
		liveSampleCalls.Add(1)
		return []UpdateFlowInput{{FlowKey: "f1", MAC: "aa:bb:cc:dd:ee:01", DstHost: "swcdn.apple.com", DownBytes: 300 << 20}}
	}
	getOff := doV6JSONReq(t, mux, http.MethodGet, "/api/v6/update_leash", "")
	if getOff.Code != http.StatusOK || liveSampleCalls.Load() != 0 {
		t.Fatalf("HotspotOff GET /api/v6/update_leash must not sample live flows: code=%d calls=%d", getOff.Code, liveSampleCalls.Load())
	}
	feed.Set(Activity{Known: true, HotspotActive: true, ClientsOnline: 1})

	// (d) UpdateLeash: pause_update 后执行 bypass_once 必须同步删除 conn_blocks.json 中的阻断项
	pauseRec := doV6JSONReq(t, mux, http.MethodPost, "/api/v6/update_leash",
		`{"action":"pause_update","mac":"aa:bb:cc:dd:ee:05","dst_host":"ios-ota.swcdn.apple.com"}`)
	if pauseRec.Code != http.StatusOK {
		t.Fatalf("pause_update failed: %d %s", pauseRec.Code, pauseRec.Body.String())
	}
	if len(readConnBlocks(dir).Items) != 1 {
		t.Fatalf("expected 1 conn_block after pause_update, got %+v", readConnBlocks(dir).Items)
	}
	bypassRec := doV6JSONReq(t, mux, http.MethodPost, "/api/v6/update_leash",
		`{"action":"bypass_once","session_key":"aa:bb:cc:dd:ee:05|swcdn.apple.com"}`)
	if bypassRec.Code != http.StatusOK {
		t.Fatalf("bypass_once failed: %d %s", bypassRec.Code, bypassRec.Body.String())
	}
	if gotCB := readConnBlocks(dir).Items; len(gotCB) != 0 {
		t.Fatalf("expected bypass_once to remove conn_block item, still got %+v", gotCB)
	}

	// (e) UpdateLeash: ReloadFromDisk 与恢复后的 conn_blocks.json 双向对齐 pausedSet
	_ = os.WriteFile(connBlocksPath(dir), []byte(`{"items":[{"mac":"aa:bb:cc:dd:ee:06","kind":"domain","value":"windowsupdate.microsoft.com","label":"UpdateLeash 暂停更新","ts":1800000000}]}`), 0o600)
	leash.ReloadFromDisk()
	leash.mu.Lock()
	hasPaused6 := leash.pausedSet["aa:bb:cc:dd:ee:06|windowsupdate.microsoft.com"]
	leash.mu.Unlock()
	if !hasPaused6 {
		t.Fatal("expected ReloadFromDisk to load pausedSet from restored conn_blocks.json")
	}
	_ = os.WriteFile(connBlocksPath(dir), []byte(`{"items":[]}`), 0o600)
	leash.ReloadFromDisk()
	leash.mu.Lock()
	stillPaused6 := leash.pausedSet["aa:bb:cc:dd:ee:06|windowsupdate.microsoft.com"]
	_, ghostSess6 := leash.sessions["aa:bb:cc:dd:ee:06|windowsupdate.microsoft.com"]
	leash.mu.Unlock()
	if stillPaused6 || ghostSess6 {
		t.Fatalf("expected ReloadFromDisk to clear stale pausedSet/session when conn_blocks is empty: paused=%v sess=%v", stillPaused6, ghostSess6)
	}
}

// 3. ThermoCruise: 毫摄氏度 500->0.5℃、空目录不锁死 shellZonesScanned、summary() 充电字段与 0 客户端完成爬坡解限
func TestWave4ThermoFixes(t *testing.T) {
	if got, reason, ok := parseSysfsTempCelsiusDetail("/sys/class/thermal/thermal_zone3/temp", "500"); !ok || reason != "" || got != 0.5 {
		t.Fatalf("winter thermal_zone raw=500 must be 0.5C, got %.2f reason=%q ok=%v", got, reason, ok)
	}
	if got, reason, ok := parseSysfsTempCelsiusDetail("/sys/class/power_supply/battery/temp", "85"); !ok || reason != "" || got != 8.5 {
		t.Fatalf("battery tenths ABI raw=85 must remain 8.5C, got %.2f reason=%q ok=%v", got, reason, ok)
	}

	s, _, dir := newV6TestMux(t)
	th := s.v6State().thermo
	emptyThRoot := filepath.Join(dir, "sys_thermal_boot")
	_ = os.MkdirAll(emptyThRoot, 0o755)
	if _, _, ok := th.readShellTempFromSysfs(emptyThRoot); ok {
		t.Fatal("expected empty thermal root to return ok=false")
	}
	// 驱动稍后注册 shell_front 节点: 因首次为空未死锁 shellZonesScanned, 二次读取必须成功发现!
	zDir := filepath.Join(emptyThRoot, "thermal_zone5")
	_ = os.MkdirAll(zDir, 0o755)
	_ = os.WriteFile(filepath.Join(zDir, "type"), []byte("shell_front\n"), 0o644)
	_ = os.WriteFile(filepath.Join(zDir, "temp"), []byte("33600\n"), 0o644)
	if c, zn, ok := th.readShellTempFromSysfs(emptyThRoot); !ok || c != 33.6 || zn != "shell_front" {
		t.Fatalf("expected late-registered shell_front discovered, got c=%.2f zn=%q ok=%v", c, zn, ok)
	}

	th.batteryReadHook = func() ThermoBatteryReading {
		return ThermoBatteryReading{
			Available:     true,
			TempC:         36.2,
			BatteryTempC:  36.2,
			CapacityPct:   82,
			Status:        "Charging",
			IsCharging:    true,
			ChargerOnline: true,
		}
	}
	sum := th.summary()
	if sum["is_charging"] != true || sum["charger_online"] != true || sum["bat_available"] != true {
		t.Fatalf("summary() missing charging/availability fields: %+v", sum)
	}

	// 验证二阶降温进入仲裁器渐进爬坡恢复期 (thermoRecovering=true) 后客户端归零时立即一步释放回满速!
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"version":1,"global_shaper_enabled":true,"global_shaper_down":"100mbit","devices":{}}`), 0o600)
	rulesStore.Invalidate(dir)
	arb := s.shaperArbiter()
	arb.applyHook = func(_ string, _ bool, _, _ int, _ bool) error { return nil }

	t0 := time.Unix(1800010000, 0)
	feed := newMockActivityFeed(Activity{Known: true, HotspotActive: true, HotspotIface: "wlan2", ClientsOnline: 1})
	th.activityHook = feed.Read
	th.coolHoldDur = 10 * time.Second
	th.Evaluate(t0, ThermoBatteryReading{Available: true, TempC: 47.0, BatteryTempC: 47.0, CapacityPct: 70, Status: "Discharging"}, false)
	th.Evaluate(t0.Add(time.Second), ThermoBatteryReading{Available: true, TempC: 35.0, BatteryTempC: 35.0, CapacityPct: 70, Status: "Discharging"}, false)
	th.Evaluate(t0.Add(12*time.Second), ThermoBatteryReading{Available: true, TempC: 35.0, BatteryTempC: 35.0, CapacityPct: 70, Status: "Discharging"}, false)
	if !arb.IsThermoRecovering() {
		t.Fatal("expected shaperArbiter to be in thermoRecovering ramp-up with 1 client online")
	}

	feed.Set(Activity{Known: true, HotspotActive: true, HotspotIface: "wlan2", ClientsOnline: 0})
	probed := false
	rem, pending := th.evalNoClientsRelease(t0.Add(13*time.Second), &probed)
	if pending || rem != 0 || arb.IsThermoRecovering() {
		t.Fatalf("expected 0-client evalNoClientsRelease to finish thermoRecovering immediately: pending=%v rem=%v recovering=%v",
			pending, rem, arb.IsThermoRecovering())
	}
}

// 4. Backup 恢复防线与 MultiIface tun0 防环路下发/幂等回收
func TestWave4BackupGuardsAndTun0Execution(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"bin", "data", "run"} {
		_ = os.MkdirAll(filepath.Join(dir, sub), 0o755)
	}
	fakeSysNet := filepath.Join(dir, "sys_class_net")
	_ = os.MkdirAll(filepath.Join(fakeSysNet, "wlan2"), 0o755)
	_ = os.WriteFile(filepath.Join(fakeSysNet, "wlan2", "address"), []byte("02:1a:2b:3c:4d:5e\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)

	origSysNet := v6BackupSysNetRoot
	v6BackupSysNetRoot = fakeSysNet
	defer func() { v6BackupSysNetRoot = origSysNet }()

	makeBundle := func(files map[string]string) V6BackupBundle {
		canonMap := make(map[string][]byte, len(files))
		rawMap := make(map[string]json.RawMessage, len(files))
		for k, v := range files {
			c, err := canonicalCompactJSON([]byte(v))
			if err != nil {
				t.Fatalf("canonical %s: %v", k, err)
			}
			canonMap[k] = c
			rawMap[k] = json.RawMessage(c)
		}
		mSHA, fSHAs := computeBackupManifestSHA256(canonMap)
		return V6BackupBundle{
			SchemaVersion: v6BackupSchemaVersion,
			FileCount:     len(rawMap),
			Files:         rawMap,
			FileSHA256:    fSHAs,
			SHA256:        mSHA,
		}
	}

	// (a) 拒绝在备份 rules.json blacklist 中注入热点宿主机自身 MAC
	hostMACBundle := makeBundle(map[string]string{
		"rules.json": `{"version":1,"blacklist":["02:1a:2b:3c:4d:5e"],"devices":{}}`,
	})
	if _, err := RestoreBackupBundle(dir, hostMACBundle); err == nil {
		t.Fatal("expected RestoreBackupBundle to reject protected host hotspot MAC in blacklist")
	}

	// (b) 拒绝多用户/双开空间下的系统 UID (如 99901000 -> 99901000 % 100000 == 1000 < 10000, 以及 100000)
	for _, badUID := range []string{"100000", "101000", "99901000"} {
		sfBundle := makeBundle(map[string]string{
			"self_firewall.json": `{"version":1,"uid_rules":[{"uid":` + badUID + `,"pkg":"com.demo.app","mode":"all"}]}`,
		})
		if _, err := RestoreBackupBundle(dir, sfBundle); err == nil {
			t.Fatalf("expected RestoreBackupBundle to reject multi-user system uid %s", badUID)
		}
	}

	// (c) 验证合法恢复后 rulesStore 缓存失效并生成 .json_backups 好快照
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"version":1,"global_shaper_down":"20mbit","devices":{}}`), 0o600)
	rulesStore.Invalidate(dir)
	_, _ = rulesStore.ReadAll(dir)

	goodBundle := makeBundle(map[string]string{
		"rules.json": `{"version":1,"global_shaper_down":"160mbit","devices":{}}`,
	})
	if _, err := RestoreBackupBundle(dir, goodBundle); err != nil {
		t.Fatalf("RestoreBackupBundle valid bundle failed: %v", err)
	}
	loadedRoot, err := rulesStore.ReadAll(dir)
	if err != nil || loadedRoot["global_shaper_down"] != "160mbit" {
		t.Fatalf("rulesStore returned stale snapshot after backup restore: %+v err=%v", loadedRoot, err)
	}
	bakEnts, _ := os.ReadDir(filepath.Join(dir, "data", ".json_backups"))
	if len(bakEnts) == 0 {
		t.Fatal("expected RestoreBackupBundle to write rulesStore .json_backups snapshot")
	}

	// (d) 验证子进程环境变量保留 BOOTCLASSPATH 且 ReconcileMultiDownstreamV6 幂等下发并完整回收 tun0 守卫规则(零 0x0000ffff 篡改)
	t.Setenv("BOOTCLASSPATH", "/apex/com.android.art/javalib/core-oj.jar")
	envList := subprocEnvWithFallbackPath()
	hasBootCP := false
	for _, kv := range envList {
		if kv == "BOOTCLASSPATH=/apex/com.android.art/javalib/core-oj.jar" {
			hasBootCP = true
			break
		}
	}
	if !hasBootCP {
		t.Fatalf("subprocEnvWithFallbackPath dropped BOOTCLASSPATH: %v", envList)
	}

	origProbe := v6CollectProbeInputsFn
	origReadRules := v6ReadLiveIPRulesFn
	origIPCmd := v6ExecTun0IPCmdFn
	origIptRestore := v6ExecTun0IptRestoreFn
	origIptCmd := v6ExecTun0IptCmdFn
	origForce := v6Tun0ForceDataplane
	defer func() {
		v6CollectProbeInputsFn = origProbe
		v6ReadLiveIPRulesFn = origReadRules
		v6ExecTun0IPCmdFn = origIPCmd
		v6ExecTun0IptRestoreFn = origIptRestore
		v6ExecTun0IptCmdFn = origIptCmd
		v6Tun0ForceDataplane = origForce
		globalV6MultiIface.tun0ApplyMu.Lock()
		globalV6MultiIface.appliedTun0Subnets = nil
		globalV6MultiIface.lastTun0MangleDigest = ""
		globalV6MultiIface.tun0MangleActive = false
		globalV6MultiIface.tun0ApplyMu.Unlock()
	}()

	var mu sync.Mutex
	var ipCmds []string
	var iptCmds []string
	var restoredPayloads []string
	liveRules := []string{"0:\tfrom all lookup local", "10500:\tfrom all uidrange 0-99999 lookup tun0"}
	chainExists := false
	fwdLinked := false
	preLinked := false

	v6Tun0ForceDataplane = true
	v6ReadLiveIPRulesFn = func() ([]string, string, bool) {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), liveRules...), "", true
	}
	v6ExecTun0IPCmdFn = func(args ...string) (string, error) {
		line := strings.Join(args, " ")
		if strings.Contains(line, "0x0000ffff") || strings.Contains(line, "fwmark") {
			t.Fatalf("forbidden fwmark/low16 mutation in ip command: %s", line)
		}
		mu.Lock()
		ipCmds = append(ipCmds, line)
		if len(args) >= 7 && args[1] == "rule" && args[2] == "add" {
			liveRules = append(liveRules, args[4]+":\tfrom all to "+args[6]+" lookup main")
		} else if len(args) >= 7 && args[1] == "rule" && args[2] == "del" {
			prefix := args[4] + ":"
			filtered := liveRules[:0]
			for _, r := range liveRules {
				if !(strings.HasPrefix(r, prefix) && strings.Contains(r, "to "+args[6])) {
					filtered = append(filtered, r)
				}
			}
			liveRules = filtered
		}
		mu.Unlock()
		return "", nil
	}
	v6ExecTun0IptRestoreFn = func(payload []byte) error {
		s := string(payload)
		if strings.Contains(strings.ToLower(s), "0x0000ffff") || strings.Contains(strings.ToLower(s), "--set-mark") {
			t.Fatalf("forbidden low16 mark mutation in HNC_TUN_GUARD payload:\n%s", s)
		}
		mu.Lock()
		restoredPayloads = append(restoredPayloads, s)
		chainExists = true
		mu.Unlock()
		return nil
	}
	v6ExecTun0IptCmdFn = func(args ...string) (string, error) {
		line := strings.Join(args, " ")
		mu.Lock()
		defer mu.Unlock()
		iptCmds = append(iptCmds, line)
		switch line {
		case "-t mangle -L HNC_TUN_GUARD -n":
			if !chainExists {
				return "", errors.New("No chain/target/match by that name")
			}
			return "Chain HNC_TUN_GUARD", nil
		case "-t mangle -C FORWARD -j HNC_TUN_GUARD":
			if !fwdLinked {
				return "", errors.New("missing")
			}
			return "", nil
		case "-t mangle -I FORWARD 1 -j HNC_TUN_GUARD":
			fwdLinked = true
			return "", nil
		case "-t mangle -D FORWARD -j HNC_TUN_GUARD":
			if !fwdLinked {
				return "", errors.New("missing")
			}
			fwdLinked = false
			return "", nil
		case "-t mangle -C PREROUTING -j HNC_TUN_GUARD":
			if !preLinked {
				return "", errors.New("missing")
			}
			return "", nil
		case "-t mangle -I PREROUTING 1 -j HNC_TUN_GUARD":
			preLinked = true
			return "", nil
		case "-t mangle -D PREROUTING -j HNC_TUN_GUARD":
			if !preLinked {
				return "", errors.New("missing")
			}
			preLinked = false
			return "", nil
		case "-t mangle -X HNC_TUN_GUARD":
			chainExists = false
			return "", nil
		}
		return "", nil
	}

	// 第 1 次对账: tun0 + wlan2 + rndis0 在线 -> 下发 8960/8961 私网绕行规则与 HNC_TUN_GUARD
	v6CollectProbeInputsFn = func(_ string) []V6IfaceProbeInput {
		return []V6IfaceProbeInput{
			{Name: "tun0", Ifindex: 31, OperUp: true, Carrier: true, MTU: 1400},
			{Name: "wlan2", Ifindex: 0, OperUp: true, Carrier: true, MTU: 1500, IPv4CIDRs: []string{"192.168.43.1/24"}},
			{Name: "rndis0", Ifindex: 0, OperUp: true, Carrier: true, MTU: 1500, IPv4CIDRs: []string{"192.168.42.129/24"}},
		}
	}
	srv := &server{hncDir: dir}
	snap1, err := srv.ReconcileMultiDownstreamV6()
	if err != nil || !snap1.Tun0Guard.VPNActive || snap1.Tun0Guard.LoopRiskDetected || !snap1.Tun0Guard.Low16MarkSafe {
		t.Fatalf("1st ReconcileMultiDownstreamV6 failed: snap=%+v err=%v", snap1.Tun0Guard, err)
	}
	if len(ipCmds) != 2 || len(restoredPayloads) != 1 || !fwdLinked || !preLinked {
		t.Fatalf("expected 2 ip rule adds and 1 iptables-restore, got ipCmds=%v restores=%d fwd=%v pre=%v",
			ipCmds, len(restoredPayloads), fwdLinked, preLinked)
	}

	// 第 2 次相同拓扑对账: 完全幂等零重复写
	_, err = srv.ReconcileMultiDownstreamV6()
	if err != nil || len(ipCmds) != 2 || len(restoredPayloads) != 1 {
		t.Fatalf("2nd ReconcileMultiDownstreamV6 must be idempotent: ipCmds=%v restores=%d err=%v", ipCmds, len(restoredPayloads), err)
	}

	// 第 3 次对账: tun0 断开 -> 完整删除 8960/8961 规则并解绑删除 HNC_TUN_GUARD
	v6CollectProbeInputsFn = func(_ string) []V6IfaceProbeInput {
		return []V6IfaceProbeInput{
			{Name: "wlan2", Ifindex: 0, OperUp: true, Carrier: true, MTU: 1500, IPv4CIDRs: []string{"192.168.43.1/24"}},
		}
	}
	_, err = srv.ReconcileMultiDownstreamV6()
	if err != nil || chainExists || fwdLinked || preLinked || len(liveRules) != 2 {
		t.Fatalf("tun0 off teardown incomplete: err=%v chain=%v fwd=%v pre=%v liveRules=%v",
			err, chainExists, fwdLinked, preLinked, liveRules)
	}
}

func TestRC7W06DeadlockOffloadAndSubtreeFixes(t *testing.T) {
	// 1. B022: 验证持 nativeDPLockMu 时调 resolveActiveVectorExpressParamsFull 并发 Actor.Do 绝不发生 AB-BA 死锁
	dir := setupNativeTierTestEnv(t, "wlan2")
	_ = DefaultDataplaneActor() // 确保 defaultDPActorReady == true
	s := newServer(dir)

	doneCh := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				unlock, err := acquireNativeDataplaneLock(dir, "test_lock_order")
				if err == nil {
					_, _, _, _ = resolveActiveVectorExpressParamsFull(s, dir)
					unlock()
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				_ = DefaultDataplaneActor().Do("test_actor_lock_order", func(a *DataplaneActor) error {
					unlock, err := acquireNativeDataplaneLock(dir, "actor_inner")
					if err == nil {
						a.expressSpec = v6ExpressDesiredState{
							active:       true,
							gameMark:     0x02000000,
							bgCeilKbps:   120000,
							upBgCeilKbps: 24000,
						}
						a.publishSnapshotLocked()
						unlock()
					}
					return nil
				})
			}
		}()
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("AB-BA deadlock detected between nativeDPLockMu and DefaultDataplaneActor().Do")
	}

	act, gm, bgDn, bgUp := resolveActiveVectorExpressParamsFull(s, dir)
	if !act || gm != 0x02000000 || bgDn != 120000 || bgUp != 24000 {
		t.Fatalf("lock-free express snapshot mismatch: act=%v gm=%#x bgDn=%d bgUp=%d", act, gm, bgDn, bgUp)
	}
	_ = DefaultDataplaneActor().Do("reset_test_express", func(a *DataplaneActor) error {
		a.expressSpec = v6ExpressDesiredState{}
		a.publishSnapshotLocked()
		return nil
	})

	// 2. B022: filter/FORWARD HNC_QUIC_APPLIM 错位排在 HNC_WHITELIST 之前时自动摘除并重插到锚点之后
	origRunner := nativeIptCmdRunner
	var quicCmds []string
	quicMisordered := true
	nativeIptCmdRunner = func(_ string, args ...string) (string, error) {
		cmdStr := strings.Join(args, " ")
		quicCmds = append(quicCmds, cmdStr)
		switch {
		case strings.Contains(cmdStr, "-t mangle -C FORWARD -j HNC_APP_LIMIT_UP"):
			return "", nil
		case strings.Contains(cmdStr, "-t filter -C FORWARD -j HNC_QUIC_APPLIM"):
			if quicMisordered {
				return "", nil
			}
			return "", errors.New("deleted")
		case strings.Contains(cmdStr, "-t filter -D FORWARD -j HNC_QUIC_APPLIM"):
			quicMisordered = false
			return "", nil
		case strings.Contains(cmdStr, "-t filter -L FORWARD -n --line-numbers"):
			if quicMisordered {
				return "Chain FORWARD (policy ACCEPT)\n1    HNC_QUIC_APPLIM  all  --  0.0.0.0/0  0.0.0.0/0\n2    HNC_CTRL         all  --  0.0.0.0/0  0.0.0.0/0\n3    HNC_WHITELIST    all  --  0.0.0.0/0  0.0.0.0/0\n", nil
			}
			return "Chain FORWARD (policy ACCEPT)\n1    HNC_CTRL       all  --  0.0.0.0/0  0.0.0.0/0\n2    HNC_WHITELIST  all  --  0.0.0.0/0  0.0.0.0/0\n", nil
		case strings.Contains(cmdStr, "-t mangle -C POSTROUTING -j HNC_APP_LIMIT_DOWN"):
			return "", nil
		}
		return "", nil
	}
	ensureAppLimitTopHooksOnBin("/system/bin/iptables")
	nativeIptCmdRunner = origRunner
	joinedQuic := strings.Join(quicCmds, "\n")
	if !strings.Contains(joinedQuic, "-t filter -D FORWARD -j HNC_QUIC_APPLIM") ||
		!strings.Contains(joinedQuic, "-t filter -I FORWARD 3 -j HNC_QUIC_APPLIM") {
		t.Fatalf("expected HNC_QUIC_APPLIM relocated after HNC_WHITELIST (pos 3), got:\n%s", joinedQuic)
	}

	// 3. B018/B019: /api/dpi_probe 结合热点活跃态与 offload_guard.json 动态修正 offload_hint
	probeSrv, mux, probeDir := newV6TestMux(t)
	mux.HandleFunc("/api/dpi_probe", probeSrv.apiDPIProbe)
	_ = os.WriteFile(filepath.Join(probeDir, "run", "dpid.probe.json"), []byte(`{"af_packet_available":true,"offload_hint":true,"offload_evidence":["tethering"]}`), 0o644)
	_ = os.Remove(filepath.Join(probeDir, "run", "hnc_state"))

	// (a) 热点关闭 -> offload_hint 必须为 false
	rOff := doV6JSONReq(t, mux, http.MethodGet, "/api/dpi_probe", "")
	if !strings.Contains(rOff.Body.String(), `"offload_hint":false`) {
		t.Fatalf("expected offload_hint:false when hotspot off, got %s", rOff.Body.String())
	}
	// (b) 热点开启 + fallback_active:true -> offload_hint 必须为 false
	_ = os.WriteFile(filepath.Join(probeDir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(probeDir, "run", "offload_guard.json"), []byte(`{"mode":"auto","offload_state":"CAPABLE","fallback_active":true,"slowpath":"ok"}`), 0o644)
	rGuarded := doV6JSONReq(t, mux, http.MethodGet, "/api/dpi_probe", "")
	if !strings.Contains(rGuarded.Body.String(), `"offload_hint":false`) {
		t.Fatalf("expected offload_hint:false when fallback_active=true, got %s", rGuarded.Body.String())
	}
	// (c) 热点开启 + ACTIVE 且未压制 -> offload_hint 为 true
	_ = os.WriteFile(filepath.Join(probeDir, "run", "offload_guard.json"), []byte(`{"mode":"off","offload_state":"ACTIVE","fallback_active":false,"slowpath":"n/a"}`), 0o644)
	rActive := doV6JSONReq(t, mux, http.MethodGet, "/api/dpi_probe", "")
	if !strings.Contains(rActive.Body.String(), `"offload_hint":true`) {
		t.Fatalf("expected offload_hint:true when ACTIVE and unguarded, got %s", rActive.Body.String())
	}

	// 4. B020: dpInspectOffloadGuard 补齐 Mode 字段并准确识别 slowpath="ok" vs "unavailable|error"
	env := &dpVerifyEnv{HNCDir: probeDir, ReadFile: os.ReadFile}
	_ = os.WriteFile(filepath.Join(probeDir, "run", "offload_guard.json"), []byte(`{"mode":"auto","offload_state":"ACTIVE","fallback_active":true,"slowpath":"ok"}`), 0o644)
	ogOK, _ := dpInspectOffloadGuard(env)
	if ogOK.Mode != "auto" || !ogOK.SlowpathActive {
		t.Fatalf("expected Mode=auto SlowpathActive=true for slowpath=ok, got %+v", ogOK)
	}
	_ = os.WriteFile(filepath.Join(probeDir, "run", "offload_guard.json"), []byte(`{"mode":"on","offload_state":"ACTIVE","fallback_active":true,"slowpath":"unavailable"}`), 0o644)
	ogUnavail, _ := dpInspectOffloadGuard(env)
	if ogUnavail.Mode != "on" || ogUnavail.SlowpathActive {
		t.Fatalf("expected Mode=on SlowpathActive=false for slowpath=unavailable, got %+v", ogUnavail)
	}
}
