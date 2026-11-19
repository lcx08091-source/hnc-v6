// dataplane_verify_test.go — v5.40.0 数据面命中自检与 Go 1.27 goroutineleak 单元测试
//
// 覆盖范围:
//   1. parseTCStatsText: 标准 iproute2 / Android 变体格式、多类并发、requeues 逗号兼容
//   2. 原生 RTNetlink 报文解析器 parseNLTClassBatch (零 unsafe 验证 TCA_STATS2 BASIC/QUEUE)
//   3. 四类根因诊断状态机: hit / idle / bypass_offload / missing_class & missing_rule + shell_compat 回退
//   4. 内存上一帧快照差分(delta_bytes / delta_drops / observed_kbps)与计数器回绕保护
//   5. 32 位正交掩码 0xffff0000 低 16 位 netd netId 保护校验 checkNetdLow16Protection
//   6. Go 1.27 runtime/pprof goroutineleak 按需零闲置开销采样、debug=2 (leaked) 精确过滤与 selfcheck 集成
//   7. GET /api/dataplane_verify HTTP 端点契约与方法白名单校验

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTCStatsText(t *testing.T) {
	sample := `
class htb 1:1 root rate 1000Mbit ceil 1000Mbit burst 1375b cburst 1375b
 Sent 987654321 bytes 654321 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
 lended: 0 borrowed: 0 giants: 0

class htb 1:100 parent 1:1 leaf 1100: prio 0 rate 20Mbit ceil 20Mbit burst 32Kb cburst 32Kb
 Sent 123456 bytes 789 pkt (dropped 12, overlimits 34 requeues 5)
 rate 19840Kbit 1420pps
 backlog 0b 0p requeues 5

class htb 1:2 parent 1:1 leaf 1002: prio 0 rate 5Mbit ceil 5Mbit burst 16Kb cburst 16Kb
 Sent 5242880 bytes 4096 pkts (dropped 99, overlimits 412, requeues 2)

class htb 1:9001 parent 1:2 prio 2 rate 1000Kbit ceil 1000Kbit burst 16Kb cburst 16Kb
 Sent 262144 bytes 210 pkt (dropped 7, overlimits 19 requeues 0)
`
	got := parseTCStatsText(sample)
	if len(got) != 4 {
		t.Fatalf("expected 4 HTB classes, got %d: %#v", len(got), got)
	}

	c100, ok := got["1:100"]
	if !ok {
		t.Fatalf("missing class 1:100")
	}
	if c100.ParentID != "1:1" || c100.SentBytes != 123456 || c100.SentPkts != 789 || c100.Drops != 12 || c100.Overlimits != 34 || c100.Requeues != 5 {
		t.Fatalf("unexpected 1:100 stats: %+v", c100)
	}

	c2, ok := got["1:2"]
	if !ok {
		t.Fatalf("missing class 1:2")
	}
	if c2.SentBytes != 5242880 || c2.SentPkts != 4096 || c2.Drops != 99 || c2.Overlimits != 412 || c2.Requeues != 2 {
		t.Fatalf("unexpected 1:2 stats: %+v", c2)
	}

	cApp, ok := got["1:9001"]
	if !ok || cApp.ParentID != "1:2" || cApp.SentBytes != 262144 || cApp.Drops != 7 || cApp.Overlimits != 19 {
		t.Fatalf("unexpected 1:9001 app class stats: %+v (ok=%v)", cApp, ok)
	}
}

func TestBridgeParseTCClassDumpMsgsAndLegacyStatsFallback(t *testing.T) {
	// 1. 验证 TCA_STATS2 报文经 parseTCClassDumpMsgs + dpConvertHTBClassStatsMap 桥接无损转换 (含 mid=59 -> 1:59 = 0x00010059)
	var stream []byte
	stream = append(stream, testRTNLEncodeClassMsg(1, synthTCClassSpec{
		ifIndex:    17,
		handle:     0x00010059, // mid=59 -> iproute2 十六进制字面量 1:59 (绝非 1:3b!)
		parent:     0x00010001,
		kind:       "htb",
		rate32:     1_250_000,
		ceil32:     1_250_000,
		sentBytes:  10_485_760,
		sentPkts:   8192,
		drops:      25,
		requeues:   3,
		overlimits: 88,
		nestedFlag: true,
	})...)

	// 2. 验证老内核仅返回顶层 TCA_STATS (20B struct tc_stats) 时的回退解析
	var legacyStats [24]byte
	binary.LittleEndian.PutUint64(legacyStats[0:8], 4_194_304)
	binary.LittleEndian.PutUint32(legacyStats[8:12], 3200)
	binary.LittleEndian.PutUint32(legacyStats[12:16], 11) // drops
	binary.LittleEndian.PutUint32(legacyStats[16:20], 42) // overlimits
	var legacyAttrs []byte
	legacyAttrs = rtnlPutAttrString(legacyAttrs, rtnlTcaKind, "htb")
	legacyAttrs = rtnlPutAttr(legacyAttrs, rtnlTcaStats, legacyStats[:])
	stream = append(stream, rtnlBuildTCMsg(rtnlNewTClass, rtnlFMulti, 1, 17, 0x00010100, 0x00010001, 0, legacyAttrs)...)
	stream = append(stream, testRTNLEncodeDone(1)...)

	rawMap, err := parseTCClassDumpMsgs(stream, 17)
	if err != nil {
		t.Fatalf("parseTCClassDumpMsgs failed: %v", err)
	}
	out := dpConvertHTBClassStatsMap(rawMap)

	st59, ok := out["1:59"]
	if !ok {
		t.Fatalf("missing bridged class 1:59 in %+v", out)
	}
	if st59.SentBytes != 10_485_760 || st59.SentPkts != 8192 || st59.Drops != 25 || st59.Overlimits != 88 || st59.Requeues != 3 {
		t.Fatalf("unexpected 1:59 bridged stats: %+v", st59)
	}
	if gotMark59 := dpMarkForDevice(59, "1:59", nil); gotMark59 != uint32(0x00bb0000) {
		t.Fatalf("dpMarkForDevice(59) = 0x%08x, want 0x00bb0000", gotMark59)
	}

	st100, ok := out["1:100"]
	if !ok || st100.SentBytes != 4_194_304 || st100.SentPkts != 3200 || st100.Drops != 11 || st100.Overlimits != 42 {
		t.Fatalf("legacy TCA_STATS fallback mismatch for 1:100: ok=%v st=%+v", ok, st100)
	}
}

func TestDataplaneVerifyFourVerdictsAndDelta(t *testing.T) {
	tmp := t.TempDir()
	mustWrite := func(rel, content string) {
		t.Helper()
		full := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mustWrite("run/hnc_state", "ACTIVE:wlan2\n")
	mustWrite("run/offload_guard.json", `{
		"mode": "on",
		"offload_state": "IDLE",
		"fallback_active": true,
		"slowpath": true,
		"tether_offload_disabled": true,
		"hwnat": "disabled"
	}`)
	mustWrite("data/device_names.json", `{
		"aa:bb:cc:dd:ee:01": "客厅平板-命中",
		"aa:bb:cc:dd:ee:02": "卧室手机-空闲",
		"aa:bb:cc:dd:ee:03": "游戏主机-旁路",
		"aa:bb:cc:dd:ee:04": "电视盒子-缺队列",
		"aa:bb:cc:dd:ee:05": "书房电脑-缺过滤器"
	}`)
	mustWrite("data/rules.json", `{
		"clsact_bpf_mode": "on",
		"quic_block": true,
		"devices": {
			"aa:bb:cc:dd:ee:01": {"mark_id": 1, "down_mbps": 20, "up_mbps": 10, "limit_enabled": true, "app_qos": true},
			"aa:bb:cc:dd:ee:02": {"mark_id": 2, "down_mbps": 15, "up_mbps": 5, "limit_enabled": true},
			"aa:bb:cc:dd:ee:03": {"mark_id": 3, "down_mbps": 10, "up_mbps": 5, "limit_enabled": true},
			"aa:bb:cc:dd:ee:04": {"mark_id": 4, "down_mbps": 8,  "up_mbps": 4, "limit_enabled": true},
			"aa:bb:cc:dd:ee:05": {"mark_id": 5, "down_mbps": 12, "up_mbps": 6, "limit_enabled": true}
		}
	}`)
	mustWrite("data/app_limits.json", `{
		"version": 1,
		"items": [
			{"mac": "aa:bb:cc:dd:ee:01", "app_id": "douyin", "down_mbps": 4.0}
		]
	}`)
	mustWrite("data/devices.json", `{
		"aa:bb:cc:dd:ee:01": {"ip": "192.168.43.101", "online": true, "rx_bytes": 5000000, "tx_bytes": 1000000},
		"aa:bb:cc:dd:ee:02": {"ip": "192.168.43.102", "online": true, "rx_bytes": 0, "tx_bytes": 0},
		"aa:bb:cc:dd:ee:03": {"ip": "192.168.43.103", "online": true, "rx_bytes": 9000000, "tx_bytes": 2000000},
		"aa:bb:cc:dd:ee:04": {"ip": "192.168.43.104", "online": true, "rx_bytes": 10000, "tx_bytes": 2000},
		"aa:bb:cc:dd:ee:05": {"ip": "192.168.43.105", "online": true, "rx_bytes": 0, "tx_bytes": 0}
	}`)

	tetherLimitPin := filepath.Join(tmp, "bpf_tether_limit")
	macPin := filepath.Join(tmp, "bpf_mac_map")
	ipPin := filepath.Join(tmp, "bpf_ip_map")
	mustWrite("bpf_tether_limit", "20: 0\n21: 0\n")
	mustWrite("bpf_mac_map", "01: 0x00810000\n02: 0x00820000\n03: 0x00830000\n")
	mustWrite("bpf_ip_map", "192.168.43.101: 0x00810000\n192.168.43.102: 0x00820000\n")

	curNow := time.Unix(1763520000, 0)
	downFrame := map[string]TCClassStats{
		"1:1":    {ClassID: "1:1", ParentID: "root", SentBytes: 8000000},
		"1:100":  {ClassID: "1:100", ParentID: "1:1", SentBytes: 2097152, SentPkts: 1600, Drops: 10, Overlimits: 45},
		"1:9001": {ClassID: "1:9001", ParentID: "1:100", SentBytes: 524288, SentPkts: 400, Drops: 3, Overlimits: 12},
		"1:2":    {ClassID: "1:2", ParentID: "1:1", SentBytes: 0, SentPkts: 0, Drops: 0, Overlimits: 0},
		"1:3":    {ClassID: "1:3", ParentID: "1:1", SentBytes: 0, SentPkts: 0, Drops: 0, Overlimits: 0},
		// 1:4 故意缺失 -> 触发 missing_class
		// 1:5 类存在但缺少 fw/u32 过滤器 -> 触发 missing_rule
		"1:5": {ClassID: "1:5", ParentID: "1:1", SentBytes: 0},
	}
	upFrame := map[string]TCClassStats{
		"1:1":   {ClassID: "1:1", ParentID: "root", SentBytes: 3000000},
		"1:100": {ClassID: "1:100", ParentID: "1:1", SentBytes: 512000, SentPkts: 500, Drops: 2, Overlimits: 8},
		"1:2":   {ClassID: "1:2", ParentID: "1:1", SentBytes: 0},
		"1:3":   {ClassID: "1:3", ParentID: "1:1", SentBytes: 0},
		"1:5":   {ClassID: "1:5", ParentID: "1:1", SentBytes: 0},
	}

	snaps := newDPVerifySnapshotStore()
	env := &dpVerifyEnv{
		HNCDir:            tmp,
		UplinkIface:       "ifb0",
		BPFMACMapPin:      macPin,
		BPFIPMapPin:       ipPin,
		BPFTetherLimitPin: tetherLimitPin,
		Now:               func() time.Time { return curNow },
		ReadFile:          os.ReadFile,
		Exists: func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		},
		Ifindex: func(ifc string) int {
			switch ifc {
			case "wlan2":
				return 11
			case "ifb0":
				return 12
			}
			return 0
		},
		DumpHTBNetlink: func(ifindex int) (map[string]TCClassStats, error) {
			if ifindex == 11 {
				cp := make(map[string]TCClassStats, len(downFrame))
				for k, v := range downFrame {
					cp[k] = v
				}
				return cp, nil
			}
			cp := make(map[string]TCClassStats, len(upFrame))
			for k, v := range upFrame {
				cp[k] = v
			}
			return cp, nil
		},
		RunCmd: func(_ context.Context, name string, args ...string) (string, error) {
			joined := name + " " + strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "hnc_clsact_ctl check wlan2"):
				return `{"iface":"wlan2","ok":true,"qdisc":true,"bpf_filter":true,"map":true,"mac_map":true,"egress_filter":true}`, nil
			case strings.Contains(joined, "tc filter show dev wlan2 ingress"):
				return "filter parent ffff: protocol all pref 1 bpf chain 0 handle 0x1 hnc_clsact direct-action\nfilter parent ffff: protocol all pref 2 u32 chain 0 action mirred (Egress Redirect to device ifb0)\n", nil
			case strings.Contains(joined, "tc filter show dev wlan2"):
				return "filter parent 1: protocol all pref 50 fw chain 0 handle 0x00810000/0x00ff0000 fw classid 1:100\n" +
					"filter parent 1: protocol all pref 50 fw chain 0 handle 0x00820000/0x00ff0000 fw classid 1:2\n" +
					"filter parent 1: protocol all pref 50 fw chain 0 handle 0x00830000/0x00ff0000 fw classid 1:3\n", nil
			case strings.Contains(joined, "tc filter show dev ifb0"):
				return "filter parent 1: protocol all pref 50 fw chain 0 handle 0x00810000/0x00ff0000 fw classid 1:100\n" +
					"filter parent 1: protocol all pref 50 fw chain 0 handle 0x00820000/0x00ff0000 fw classid 1:2\n" +
					"filter parent 1: protocol all pref 50 fw chain 0 handle 0x00830000/0x00ff0000 fw classid 1:3\n" +
					"filter parent 1: protocol all pref 50 fw chain 0 handle 0x00850000/0x00ff0000 fw classid 1:5\n", nil
			case strings.Contains(joined, "iptables -w 2 -t mangle -S"):
				return "-A HNC_MARK -m mac --mac-source AA:BB:CC:DD:EE:01 -j CONNMARK --set-xmark 0x00810000/0x00ff0000\n" +
					"-A HNC_RESTORE -j CONNMARK --restore-mark --nfmask 0xffff0000 --ctmask 0xffff0000\n", nil
			case strings.Contains(joined, "ip6tables -w 2 -t mangle -S"):
				return "-A HNC_MARK -m mac --mac-source AA:BB:CC:DD:EE:01 -j CONNMARK --set-xmark 0x00810000/0x00ff0000\n", nil
			case strings.Contains(joined, "ip6tables -w 2 -t filter -S"):
				return "-A HNC_QUIC -i wlan2 -p udp -m udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable\n", nil
			}
			return "", nil
		},
		Snaps: snaps,
	}

	// 第 1 帧采样: tether_limit_map 全 0 -> 设备 1 hit, 设备 2 idle, 设备 3 idle(快径已封堵), 设备 4 missing_class, 设备 5 missing_rule
	rep1 := runDataplaneVerify(env, dpVerifyOptions{})
	if !rep1.OK || rep1.EngineMode != dpEngineNativeNetlink || !rep1.NetdLow16Protected || rep1.MarkLayout != dpMarkLayoutV540 {
		t.Fatalf("unexpected top-level report1: %+v", rep1)
	}
	if !rep1.BPFMaps.ClsactAttached || !rep1.BPFMaps.IFBRedirectPrio2 || !rep1.BPFMaps.TetherLimitZeroed || rep1.BPFMaps.MACMarkEntries != 3 || rep1.BPFMaps.IPMarkEntries != 2 {
		t.Fatalf("unexpected bpf_maps in report1: %+v", rep1.BPFMaps)
	}
	if !rep1.IPv6QUICControlled {
		t.Fatalf("expected ipv6_quic_controlled=true")
	}

	// 第 2 帧(+2 秒): 模拟 system_server 改写 tether_limit_map 为非 0(U64_MAX), 设备 1 HTB 增长 +250KB, 设备 3 有客户端流量但 HTB 仍为 0 -> bypass_offload!
	curNow = curNow.Add(2 * time.Second)
	mustWrite("bpf_tether_limit", "20: 18446744073709551615\n")
	downFrame["1:100"] = TCClassStats{ClassID: "1:100", ParentID: "1:1", SentBytes: 2097152 + 250000, SentPkts: 1800, Drops: 15, Overlimits: 60}
	mustWrite("data/devices.json", `{
		"aa:bb:cc:dd:ee:01": {"ip": "192.168.43.101", "online": true, "rx_bytes": 5300000, "tx_bytes": 1000000},
		"aa:bb:cc:dd:ee:02": {"ip": "192.168.43.102", "online": true, "rx_bytes": 0, "tx_bytes": 0},
		"aa:bb:cc:dd:ee:03": {"ip": "192.168.43.103", "online": true, "rx_bytes": 12000000, "tx_bytes": 2500000},
		"aa:bb:cc:dd:ee:04": {"ip": "192.168.43.104", "online": true, "rx_bytes": 10000, "tx_bytes": 2000},
		"aa:bb:cc:dd:ee:05": {"ip": "192.168.43.105", "online": true, "rx_bytes": 0, "tx_bytes": 0}
	}`)

	rep2 := runDataplaneVerify(env, dpVerifyOptions{})
	if rep2.BPFMaps.TetherLimitZeroed {
		t.Fatalf("expected TetherLimitZeroed=false when limit_map was overwritten to U64_MAX")
	}

	byMAC := make(map[string]DataplaneDeviceEntry)
	for _, d := range rep2.Devices {
		byMAC[d.MAC] = d
	}

	// 校验 1: hit + 增量速率计算 (250000 bytes * 8 / 2s / 1000 = 1000 kbps)
	d1 := byMAC["aa:bb:cc:dd:ee:01"]
	if d1.Verdict != "hit" || d1.DownDeltaBytes != 250000 || d1.DownDeltaDrops != 5 || d1.DownObservedKbps != 1000 {
		t.Fatalf("device 1 hit/delta mismatch: %+v", d1)
	}
	if len(d1.AppClasses) != 1 || d1.AppClasses[0].ClassID != "1:9001" || d1.AppClasses[0].Verdict != "hit" {
		t.Fatalf("device 1 app_classes mismatch: %+v", d1.AppClasses)
	}

	// 校验 2: idle
	if d2 := byMAC["aa:bb:cc:dd:ee:02"]; d2.Verdict != "idle" {
		t.Fatalf("expected device 2 verdict=idle, got %+v", d2)
	}

	// 校验 3: bypass_offload
	if d3 := byMAC["aa:bb:cc:dd:ee:03"]; d3.Verdict != "bypass_offload" {
		t.Fatalf("expected device 3 verdict=bypass_offload, got %+v", d3)
	}

	// 校验 4: missing_class
	if d4 := byMAC["aa:bb:cc:dd:ee:04"]; d4.Verdict != "missing_class" {
		t.Fatalf("expected device 4 verdict=missing_class, got %+v", d4)
	}

	// 校验 5: missing_rule
	if d5 := byMAC["aa:bb:cc:dd:ee:05"]; d5.Verdict != "missing_rule" {
		t.Fatalf("expected device 5 verdict=missing_rule, got %+v", d5)
	}

	if rep2.Summary.ControlledDevices != 5 || rep2.Summary.HittingCount != 1 || rep2.Summary.IdleCount != 1 || rep2.Summary.BypassOrMissingCount != 3 || rep2.Summary.OverallStatus != "fail" {
		t.Fatalf("unexpected summary: %+v", rep2.Summary)
	}
	if rep2.GoroutineLeak != nil {
		t.Fatalf("expected goroutineleak=nil by default (zero idle overhead), got %+v", rep2.GoroutineLeak)
	}

	// 校验 6: 原生 Netlink 不可用时无缝回退 shell_compat (`tc -s class show dev wlan2`)
	env.DumpHTBNetlink = func(int) (map[string]TCClassStats, error) {
		return nil, errors.New("netlink disabled in test")
	}
	origRun := env.RunCmd
	env.RunCmd = func(ctx context.Context, name string, args ...string) (string, error) {
		joined := name + " " + strings.Join(args, " ")
		if strings.Contains(joined, "tc -s class show dev wlan2") {
			return "class htb 1:100 parent 1:1 rate 20Mbit ceil 20Mbit\n Sent 3000000 bytes 2100 pkt (dropped 20, overlimits 70 requeues 0)\n" +
				"class htb 1:9001 parent 1:100 rate 4Mbit ceil 4Mbit\n Sent 600000 bytes 450 pkt (dropped 4, overlimits 15 requeues 0)\n", nil
		}
		if strings.Contains(joined, "tc -s class show dev ifb0") {
			return "class htb 1:100 parent 1:1 rate 10Mbit ceil 10Mbit\n Sent 600000 bytes 550 pkt (dropped 3, overlimits 9 requeues 0)\n", nil
		}
		return origRun(ctx, name, args...)
	}
	curNow = curNow.Add(2 * time.Second)
	repFallback := runDataplaneVerify(env, dpVerifyOptions{})
	if repFallback.EngineMode != dpEngineShellCompat {
		t.Fatalf("expected engine_mode=%s on netlink fallback, got %s", dpEngineShellCompat, repFallback.EngineMode)
	}
}

func TestCheckNetdLow16Protection(t *testing.T) {
	layout, ok := checkNetdLow16Protection(
		"-A HNC_MARK -j CONNMARK --set-xmark 0x00820000/0x00ff0000\n-A HNC_RESTORE -j CONNMARK --restore-mark --nfmask 0xffff0000 --ctmask 0xffff0000\n",
		"-A HNC_APP_LIMIT_UP -j CONNMARK --set-xmark 0x01000000/0xff000000\n",
		"filter parent 1: protocol all pref 50 fw chain 0 handle 0x00820000/0x00ff0000 fw classid 1:2\n",
	)
	if !ok || layout != dpMarkLayoutV540 {
		t.Fatalf("expected v540 low16 protected, got layout=%s ok=%v", layout, ok)
	}

	layoutLegacy, okLegacy := checkNetdLow16Protection(
		"-A HNC_MARK -j MARK --set-xmark 0x800002/0xffffffff\n",
		"",
		"",
	)
	if okLegacy || layoutLegacy != dpMarkLayoutLegacy {
		t.Fatalf("expected legacy low16 overlap detection, got layout=%s ok=%v", layoutLegacy, okLegacy)
	}
}

func TestGoroutineLeakOnDemandSamplingAndHTTP(t *testing.T) {
	origDump := goroutineLeakDumpFn
	defer func() { goroutineLeakDumpFn = origDump }()

	calls := 0
	goroutineLeakDumpFn = func() (string, bool, error) {
		calls++
		// 模拟 Go 1.27 WriteTo(&buf, 2) 真实混合输出:
		// 包含普通运行中/IO 等待协程(不带 leaked 后缀)与 2 个永久阻塞泄漏协程(带 (leaked) 标记)
		return `goroutine 1 [running]:
runtime/pprof.writeGoroutineLeakStacks({0x1234, 0xc000100000})
	/usr/local/go/src/runtime/pprof/pprof.go:812 +0x94

goroutine 18 [IO wait]:
internal/poll.runtime_pollWait(0x7f001234, 0x72)
	/usr/local/go/src/runtime/netpoll.go:351 +0xa0

goroutine 25 [chan receive]:
main.(*server).RateLoop(0xc000200000, 0xc000180070)
	/data/local/hnc/daemon/hnc_httpd/server.go:698 +0x88

goroutine 41 [chan send (leaked)]:
main.leakyWorker.func1()
	/data/local/hnc/daemon/hnc_httpd/worker.go:54 +0x44
created by main.leakyWorker in goroutine 19
	/data/local/hnc/daemon/hnc_httpd/worker.go:52 +0x70

goroutine 42 [sync.Mutex.Lock (leaked), 5 minutes]:
sync.(*Mutex).Lock(...)
main.deadlockTask()
	/data/local/hnc/daemon/hnc_httpd/worker.go:89 +0x68
`, true, nil
	}

	// 1. 默认 run=false 必须完全零调用、零开销返回 nil
	if got := sampleGoroutineLeakProfile(false); got != nil || calls != 0 {
		t.Fatalf("sampleGoroutineLeakProfile(false) must be no-op: got=%+v calls=%d", got, calls)
	}

	// 2. 显式 run=true 必须仅识别 2 个带 (leaked) 头的协程, 绝不误报前 3 个正常协程
	sum := sampleGoroutineLeakProfile(true)
	if calls != 1 || sum == nil || !sum.Sampled || !sum.Supported {
		t.Fatalf("unexpected sample result: calls=%d sum=%+v", calls, sum)
	}
	if sum.LeakedCount != 2 || sum.Status != "leak_detected" || len(sum.PreviewStacks) != 2 {
		t.Fatalf("expected 2 leaked goroutines, got: %+v", sum)
	}
	if !strings.Contains(sum.PreviewStacks[0], "[chan send (leaked)]") || !strings.Contains(sum.PreviewStacks[1], "[sync.Mutex.Lock (leaked)") {
		t.Fatalf("unexpected preview stacks: %#v", sum.PreviewStacks)
	}

	// 3. 验证 selfcheck scGoroutineLeakItem 仅在 run/diag_goroutineleak.enabled 开关存在时触发
	tmp := t.TempDir()
	scC := &scCtx{
		env: &scEnv{
			HNCDir: tmp,
			Exists: func(p string) bool {
				_, err := os.Stat(p)
				return err == nil
			},
			Getenv: func(string) string { return "" },
		},
	}
	if _, ok := scGoroutineLeakItem(scC); ok || calls != 1 {
		t.Fatalf("scGoroutineLeakItem should skip when diag flag file is absent")
	}

	flagFile := filepath.Join(tmp, dpDiagLeakFlagRelPath)
	_ = os.MkdirAll(filepath.Dir(flagFile), 0o755)
	_ = os.WriteFile(flagFile, []byte("1\n"), 0o644)

	it, ok := scGoroutineLeakItem(scC)
	if !ok || it.ID != "proc_goroutineleak" || it.Status != scWarn || calls != 2 {
		t.Fatalf("expected proc_goroutineleak warn item when flag enabled, got ok=%v it=%+v calls=%d", ok, it, calls)
	}

	// 4. 验证 GET /api/dataplane_verify HTTP 处理与 POST 405 拦截
	_ = os.Remove(flagFile)
	srv := &server{hncDir: tmp}

	wPost := httptest.NewRecorder()
	rPost := httptest.NewRequest(http.MethodPost, "/api/dataplane_verify", nil)
	srv.apiDataplaneVerify(wPost, rPost)
	if wPost.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on POST /api/dataplane_verify, got %d", wPost.Code)
	}

	wGetNoLeak := httptest.NewRecorder()
	rGetNoLeak := httptest.NewRequest(http.MethodGet, "/api/dataplane_verify", nil)
	srv.apiDataplaneVerify(wGetNoLeak, rGetNoLeak)
	if wGetNoLeak.Code != http.StatusOK || calls != 2 {
		t.Fatalf("GET /api/dataplane_verify without param should not sample goroutineleak: code=%d calls=%d", wGetNoLeak.Code, calls)
	}

	wGetLeak := httptest.NewRecorder()
	rGetLeak := httptest.NewRequest(http.MethodGet, "/api/dataplane_verify?goroutineleak=1", nil)
	srv.apiDataplaneVerify(wGetLeak, rGetLeak)
	if wGetLeak.Code != http.StatusOK || calls != 3 {
		t.Fatalf("GET /api/dataplane_verify?goroutineleak=1 should sample once: code=%d calls=%d", wGetLeak.Code, calls)
	}
	var httpRep DataplaneVerifyReport
	if err := json.Unmarshal(wGetLeak.Body.Bytes(), &httpRep); err != nil {
		t.Fatalf("unmarshal GET response failed: %v", err)
	}
	if httpRep.GoroutineLeak == nil || httpRep.GoroutineLeak.LeakedCount != 2 || httpRep.GoroutineLeak.Trigger != "query_param" {
		t.Fatalf("unexpected GET goroutineleak payload: %+v", httpRep.GoroutineLeak)
	}

	// 5. 验证 dispatchDataplaneVerifyAction check_goroutineleak="1" JSON 契约序列化
	resp, handled := dispatchDataplaneVerifyAction(srv, "dataplane_verify_run", map[string]string{"check_goroutineleak": "1"})
	if !handled || !resp.OK || calls != 4 {
		t.Fatalf("dispatchDataplaneVerifyAction failed: handled=%v resp=%+v calls=%d", handled, resp, calls)
	}
	var parsed DataplaneVerifyReport
	if err := json.Unmarshal([]byte(resp.Detail), &parsed); err != nil {
		t.Fatalf("invalid action detail JSON: %v", err)
	}
	if parsed.GoroutineLeak == nil || parsed.GoroutineLeak.LeakedCount != 2 || parsed.GoroutineLeak.Trigger != "action_param" {
		t.Fatalf("expected goroutineleak in action report, got %+v", parsed.GoroutineLeak)
	}
}

func TestGoroutineLeakRealStdlibCall(t *testing.T) {
	// 直接调用真实标准库 runtime/pprof.Lookup("goroutineleak"):
	// 在 Go 1.27+ 下应返回 Supported=true 且健康无泄漏(LeakedCount == 0);
	// 在低版本 Go 工具链下亦优雅返回 Supported=false 不崩溃。
	sum := sampleGoroutineLeakProfile(true)
	if sum == nil || !sum.Sampled {
		t.Fatalf("real sampleGoroutineLeakProfile(true) failed: %+v", sum)
	}
	if sum.Supported && sum.Status != "clean" && sum.Status != "leak_detected" {
		t.Fatalf("unexpected real stdlib status on Go 1.27+: %+v", sum)
	}
}

func TestBlacklistedDeviceVerdictPrecedenceOverNeedsHTB(t *testing.T) {
	// [R-4] 当设备同时配置了 HTB 限速/应用 QoS/单应用限速且处于黑名单时,
	// HNC_CTRL 在转发层直接阻断包(不会进入 HTB 队列), 必须优先按黑名单阻断规则裁决而非误报 missing_class!
	sp := dpControlledSpec{
		mac:          "aa:bb:cc:dd:ee:66",
		name:         "拉黑但保留旧限速配置的设备",
		ip:           "192.168.43.166",
		online:       true,
		blacklisted:  true,
		limitEnabled: true,
		markID:       6,
		downMbps:     20,
		upMbps:       10,
		appQoS:       true,
		appLimits: []dpIndexedAppLimit{
			{globalIdx: 0, item: AppLimitItem{MAC: "aa:bb:cc:dd:ee:66", AppID: "douyin", DownMbps: 4}},
		},
	}

	// 场景 1: 双栈 HNC_CTRL 已挂载该 MAC, 即使 downClassPresent=false / anyAppMissing=true 也必须判为 hit("黑名单阻断生效")
	v1, lbl1, _, _ := dpComputeDeviceVerdict(
		true, sp, "1:6", false, false,
		TCClassStats{}, TCClassStats{}, 0, 0,
		true, false, false,
		nil, nil, nil, false,
		"-A HNC_CTRL -m mac --mac-source aa:bb:cc:dd:ee:66 -j DROP\n",
		"-A HNC_CTRL -m mac --mac-source aa:bb:cc:dd:ee:66 -j DROP\n",
		DataplaneBPFMaps{}, DataplaneOffloadGuard{}, "IDLE",
	)
	if v1 != "hit" || lbl1 != "黑名单阻断生效" {
		t.Fatalf("expected hit/黑名单阻断生效 when blacklisted + needsHTB, got verdict=%q label=%q", v1, lbl1)
	}

	// 场景 2: IPv4 HNC_CTRL 缺失该 MAC -> 判为 missing_rule("阻断规则缺失")
	v2, lbl2, _, _ := dpComputeDeviceVerdict(
		true, sp, "1:6", true, true,
		TCClassStats{SentBytes: 1024}, TCClassStats{}, 0, 0,
		false, false, false,
		map[string]uint32{"1:6": 0x00860000}, nil, map[string]bool{"1:6": true}, false,
		"-N HNC_CTRL\n-A FORWARD -j HNC_CTRL\n",
		"",
		DataplaneBPFMaps{}, DataplaneOffloadGuard{}, "IDLE",
	)
	if v2 != "missing_rule" || lbl2 != "阻断规则缺失" {
		t.Fatalf("expected missing_rule/阻断规则缺失 when v4 HNC_CTRL misses MAC, got verdict=%q label=%q", v2, lbl2)
	}

	// 场景 3: IPv4 已挂载但 ip6tables HNC_CTRL 缺失该 MAC -> 判为 missing_rule("IPv6 阻断缺失")
	v3, lbl3, _, _ := dpComputeDeviceVerdict(
		true, sp, "1:6", false, false,
		TCClassStats{}, TCClassStats{}, 0, 0,
		false, false, false,
		nil, nil, nil, false,
		"-A HNC_CTRL -m mac --mac-source AA:BB:CC:DD:EE:66 -j DROP\n",
		"-N HNC_CTRL\n-A FORWARD -j HNC_CTRL\n",
		DataplaneBPFMaps{}, DataplaneOffloadGuard{}, "IDLE",
	)
	if v3 != "missing_rule" || lbl3 != "IPv6 阻断缺失" {
		t.Fatalf("expected missing_rule/IPv6 阻断缺失 when v6 HNC_CTRL misses MAC, got verdict=%q label=%q", v3, lbl3)
	}
}
