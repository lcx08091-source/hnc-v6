// app_qos_test.go — v5.30 T4: 应用感知 QoS 的计划生成与「关闭时不起脚本」。
//
// 「改动前会失败」: v5.29 没有 appQosTier / buildAppQosPlan / appApplyOnce(编译
// 即失败); 接线用例走真实的 appApplyOnce(appLimitApplyLoop 每轮调的那一个)。
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppQosTierMapping(t *testing.T) {
	cases := map[string]int{
		"game": 1, "game-tools": 1, "social_voip": 1, "sdk-tencent-game": 1, "call": 1,
		"video": 2, "browser": 2, "social": 2, "shopping": 2, "cdn": 2, "": 2, "unknown": 2, "什么鬼": 2,
		"download": 3, "cloud": 3, "system": 3, "system-oppo": 3, "system_chipset": 3,
		"third_party_telemetry": 3, "ads": 3, "ad-sdk": 3, "p2p-unknown": 3, "sdk-umeng": 3, " Download ": 3,
	}
	for c, want := range cases {
		if got := appQosTier(c); got != want {
			t.Errorf("appQosTier(%q) = %d, want %d", c, got, want)
		}
	}
}

const qosRules = `{"devices":{
 "AA:BB:CC:00:00:05":{"mark_id":5,"app_qos":true,"down_mbps":20},
 "aa:bb:cc:00:00:07":{"mark_id":"7","app_qos":"true"},
 "aa:bb:cc:00:00:09":{"mark_id":9,"app_qos":false},
 "aa:bb:cc:00:00:0a":{"mark_id":10},
 "aa:bb:cc:00:00:0b":{"mark_id":0,"app_qos":true}}}`
const qosDevices = `{"aa:bb:cc:00:00:05":{"ip":"192.168.43.5"},"aa:bb:cc:00:00:09":{"ip":"192.168.43.9"}}`
const qosIPMap = `{"generated_ts":1,"entries":[
 {"ip":"1.1.1.1","app_id":"wzry","category":"game"},
 {"ip":"2.2.2.2","app_id":"bili","category":"video"},
 {"ip":"3.3.3.3","app_id":"cloud189","category":"cloud"},
 {"ip":"240e::1","app_id":"wzry","category":"game"},
 {"ip":"4.4.4.4","app_id":"x"},
 {"ip":"1.1.1.1","app_id":"wzry","category":"game"}]}`

func TestBuildAppQosPlan(t *testing.T) {
	plan, n := buildAppQosPlan([]byte(qosRules), []byte(qosDevices), []byte(qosIPMap), "wlan2")
	want := "iface wlan2\n" +
		"dev 5 aa:bb:cc:00:00:05 192.168.43.5\n" + // 在线, 带 IP
		"dev 7 aa:bb:cc:00:00:07\n" + // "true" / "7" 字符串也认; 不在线没有 IP
		"ip 1 1.1.1.1\n" + // 游戏 → 实时(重复去掉; IPv6 不进 IPv4 规则)
		"ip 3 3.3.3.3\n" // 云同步 → 后台; 视频 / 无类别 → 交互(默认档, 不列)
	if n != 2 || plan != want {
		t.Fatalf("n=%d plan=\n%s\nwant\n%s", n, plan, want)
	}
}

func TestBuildAppQosPlanOff(t *testing.T) {
	if p, n := buildAppQosPlan([]byte(`{"devices":{"aa:bb:cc:00:00:05":{"mark_id":5}}}`), nil, []byte(qosIPMap), "wlan2"); p != "" || n != 0 {
		t.Fatalf("没有设备开: plan=%q n=%d", p, n)
	}
	if p, n := buildAppQosPlan([]byte(qosRules), nil, nil, ""); p != "" || n != 0 {
		t.Fatal("热点没开(没有网卡)不出计划")
	}
}

type qosWorld struct {
	run, data, bin string
	scripts        []string
	idle           bool
	state          wdState
}

func withQosWorld(t *testing.T) *qosWorld {
	t.Helper()
	w := &qosWorld{run: t.TempDir(), data: t.TempDir(), bin: t.TempDir(), state: wdState{kind: stateActive, iface: "wlan2"}}
	oR, oD, oB, oS, oI, oSt := appQosRunDir, appQosDataDir, appQosBinDir, runScriptFn, hotspotIdleFn, appQosStateFn
	appQosRunDir, appQosDataDir, appQosBinDir = w.run, w.data, w.bin
	runScriptFn = func(p string, _ ...string) { w.scripts = append(w.scripts, filepath.Base(p)) }
	hotspotIdleFn = func() bool { return w.idle }
	appQosStateFn = func() wdState { return w.state }
	t.Cleanup(func() {
		appQosRunDir, appQosDataDir, appQosBinDir, runScriptFn, hotspotIdleFn, appQosStateFn = oR, oD, oB, oS, oI, oSt
	})
	_ = os.WriteFile(filepath.Join(w.bin, "apply_app_limits.sh"), []byte("#!/bin/sh\n"), 0o755)
	_ = os.WriteFile(filepath.Join(w.data, "devices.json"), []byte(qosDevices), 0o644)
	_ = os.WriteFile(filepath.Join(w.run, "ip_app_map.json"), []byte(qosIPMap), 0o644)
	return w
}

func (w *qosWorld) once() { appApplyOnce(filepath.Join(w.bin, "apply_app_limits.sh")) }

// 关闭(默认): 只跑应用限速, 不写计划、不起 apply_app_qos.sh。
func TestAppApplyOnceOffNoScript(t *testing.T) {
	w := withQosWorld(t)
	_ = os.WriteFile(filepath.Join(w.data, "rules.json"), []byte(`{"devices":{"aa:bb:cc:00:00:05":{"mark_id":5}}}`), 0o644)
	w.once()
	if strings.Join(w.scripts, ",") != "apply_app_limits.sh" {
		t.Fatalf("关闭时只应跑应用限速: %v", w.scripts)
	}
	if _, err := os.Stat(filepath.Join(w.run, "app_qos.plan")); err == nil {
		t.Fatal("关闭时不应写计划")
	}
}

func TestAppApplyOnceOnRunsScript(t *testing.T) {
	w := withQosWorld(t)
	_ = os.WriteFile(filepath.Join(w.data, "rules.json"), []byte(qosRules), 0o644)
	w.once()
	if strings.Join(w.scripts, ",") != "apply_app_limits.sh,apply_app_qos.sh" {
		t.Fatalf("scripts = %v", w.scripts)
	}
	b, _ := os.ReadFile(filepath.Join(w.run, "app_qos.plan"))
	if !strings.HasPrefix(string(b), "iface wlan2\ndev 5 aa:bb:cc:00:00:05 192.168.43.5\n") {
		t.Fatalf("plan = %q", b)
	}
}

// 全关了但还有残留状态(上次开过)→ 写空计划并起脚本去拆。
func TestAppApplyOnceTeardownLeftover(t *testing.T) {
	w := withQosWorld(t)
	_ = os.WriteFile(filepath.Join(w.data, "rules.json"), []byte(`{"devices":{}}`), 0o644)
	_ = os.WriteFile(filepath.Join(w.run, "app_qos.state"), []byte("wlan2 5\n"), 0o644)
	w.once()
	b, err := os.ReadFile(filepath.Join(w.run, "app_qos.plan"))
	if err != nil || len(b) != 0 || strings.Join(w.scripts, ",") != "apply_app_limits.sh,apply_app_qos.sh" {
		t.Fatalf("plan=%q err=%v scripts=%v", b, err, w.scripts)
	}
}

func TestAppApplyOnceHotspotIdle(t *testing.T) {
	w := withQosWorld(t)
	w.idle = true
	_ = os.WriteFile(filepath.Join(w.data, "rules.json"), []byte(qosRules), 0o644)
	w.once()
	if len(w.scripts) != 0 {
		t.Fatalf("热点没开不起任何脚本: %v", w.scripts)
	}
}
