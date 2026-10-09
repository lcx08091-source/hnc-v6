//go:build linux

// m4_sim_test.go — 模拟设备上的 M4 对照(由 test/sim/run_m4_sim.sh 调; 平时 go test 直接跳过)。
//
// test/sim/simnet.sh 造的假热点网桥上挂着若干台假设备(独立 netns, 真实出现在内核邻居表里),
// 本机编译的 hotspotd 盯着这块网桥写 devices.json。这里走看门狗真实的影子路径
// (m4Shadow.maybeRun: neigh.DumpIf 读邻居表 → 读 devices.json → compareM4 → 写 m4_shadow.json),
// 然后检查三件事:
//  1. 影子跑出了结果(checks = 1);
//  2. Go 和 hotspotd 没有差异(only_go / only_hotspotd / ip_diff 都空);
//  3. 两边都和场景期望一致(HNC_SIM_EXPECT = "mac ip;mac ip;..."): 防止两边一起错(比如都漏了同一台)。
//
// 环境变量: HNC_SIM_IFACE 网桥名; HNC_SIM_HNC_DIR hotspotd 的数据根(其下 data/devices.json);
// HNC_SIM_EXPECT 期望的设备; HNC_SIM_OUT 把本轮 m4_shadow.json 复制到这里(给场景脚本写报告)。
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"hnc.io/dpid/neigh"
)

func TestM4Sim(t *testing.T) {
	iface, hncDir := os.Getenv("HNC_SIM_IFACE"), os.Getenv("HNC_SIM_HNC_DIR")
	if iface == "" || hncDir == "" {
		t.Skip("只在 test/sim/run_m4_sim.sh 里跑(需要模拟设备)")
	}
	runDir := t.TempDir()
	oldRun, oldData, oldState := m4RunDir, m4DataDir, m4Shadow
	m4RunDir, m4DataDir, m4Shadow = runDir, filepath.Join(hncDir, "data"), &m4ShadowState{}
	defer func() { m4RunDir, m4DataDir, m4Shadow = oldRun, oldData, oldState }()

	m4Shadow.maybeRun(iface, time.Now())

	b, err := os.ReadFile(filepath.Join(runDir, m4ShadowFileName))
	if err != nil {
		t.Fatalf("影子没跑出结果(读不了邻居表或 devices.json): %v", err)
	}
	if out := os.Getenv("HNC_SIM_OUT"); out != "" {
		_ = os.WriteFile(out, b, 0o644)
	}
	var r struct {
		Checks       int      `json:"checks"`
		OnlyGo       []string `json:"only_go"`
		OnlyHotspotd []string `json:"only_hotspotd"`
		IPDiff       []string `json:"ip_diff"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("m4_shadow.json 解析失败: %v", err)
	}
	if r.Checks != 1 {
		t.Fatalf("checks = %d, 想要 1", r.Checks)
	}
	if len(r.OnlyGo)+len(r.OnlyHotspotd)+len(r.IPDiff) > 0 {
		t.Errorf("Go 和 hotspotd 不一致: 多 %v 少 %v IP %v", r.OnlyGo, r.OnlyHotspotd, r.IPDiff)
	}

	want := map[string]string{}
	for _, kv := range strings.Split(os.Getenv("HNC_SIM_EXPECT"), ";") {
		if f := strings.Fields(kv); len(f) == 2 {
			want[strings.ToLower(f[0])] = f[1]
		}
	}
	idx, err := m4IfIndexFn(iface)
	if err != nil {
		t.Fatalf("找不到网卡 %s: %v", iface, err)
	}
	es, err := neigh.DumpIf(idx)
	if err != nil {
		t.Fatalf("读邻居表: %v", err)
	}
	goSet := goDevices(es)
	hdb, _ := os.ReadFile(filepath.Join(hncDir, "data", "devices.json"))
	hd := parseHotspotdDevices(hdb, iface)
	if got, exp := simKeys(goSet), simKeysS(want); strings.Join(got, ",") != strings.Join(exp, ",") {
		t.Errorf("Go 看到的设备 %v, 场景期望 %v", got, exp)
	}
	if got, exp := simKeysH(hd), simKeysS(want); strings.Join(got, ",") != strings.Join(exp, ",") {
		t.Errorf("hotspotd 的设备 %v, 场景期望 %v", got, exp)
	}
	for mac, ip := range want {
		if !containsStr(goSet[mac], ip) {
			t.Errorf("%s: Go 看到的 IP %v 里没有期望的 %s", mac, goSet[mac], ip)
		}
		if h, ok := hd[mac]; ok && h.IP != ip {
			t.Errorf("%s: hotspotd 的 IP %s, 期望 %s", mac, h.IP, ip)
		}
	}
}

func simKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func simKeysH(m map[string]m4HDDev) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func simKeysS(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
