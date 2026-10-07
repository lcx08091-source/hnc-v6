// m4_shadow_test.go — v5.30 T3: 设备发现 Go 影子(只算只比对)。
//
// 「改动前会失败」: v5.29 没有影子(m4Shadow / compareM4 不存在, 编译即失败);
// 接线用例 TestM4ShadowWiredIntoActiveLoop 驱动真实调用方 loopState.tick →
// handleActive → m4Shadow.maybeRun, 去掉 main.go 里那一行调用即失败。
package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"hnc.io/dpid/neigh"
)

// withTempM4Shadow 影子的外部世界全部换成临时 / 假的: run、data 目录、
// ifindex 查询、邻居表 dump; 计数清零。返回 (run, data) 目录。
func withTempM4Shadow(t *testing.T) (string, string) {
	t.Helper()
	run, data := t.TempDir(), t.TempDir()
	oRun, oData, oDump, oIdx, oSh := m4RunDir, m4DataDir, neighDumpIfFn, m4IfIndexFn, m4Shadow
	m4RunDir, m4DataDir = run, data
	m4Shadow = &m4ShadowState{}
	neighDumpIfFn = func(int) ([]neigh.Entry, error) { return nil, errors.New("no netlink in test") }
	m4IfIndexFn = func(string) (int, error) { return 0, errors.New("no iface in test") }
	t.Cleanup(func() {
		m4RunDir, m4DataDir, neighDumpIfFn, m4IfIndexFn, m4Shadow = oRun, oData, oDump, oIdx, oSh
	})
	return run, data
}

func ne(mac, ip string, state uint16) neigh.Entry {
	return neigh.Entry{IfIndex: 5, MAC: mac, IP: net.ParseIP(ip), State: state}
}

const (
	mA, mB, mC = "aa:bb:cc:00:00:0a", "aa:bb:cc:00:00:0b", "aa:bb:cc:00:00:0c"
)

func TestCompareM4MoreLessIP(t *testing.T) {
	goSet := map[string][]string{mA: {"192.168.43.10"}, mB: {"192.168.43.11"}, mC: {"192.168.43.30"}}
	hd := map[string]m4HDDev{
		mA:                  {IP: "192.168.43.10"},
		mB:                  {IP: "192.168.43.99"}, // IP 变了
		"aa:bb:cc:00:00:0d": {IP: "192.168.43.40"}, // hotspotd 有、Go 没看到
	}
	got := compareM4(goSet, hd)
	want := m4Diff{
		OnlyGo:       []string{mC},
		OnlyHotspotd: []string{"aa:bb:cc:00:00:0d"},
		IPDiff:       []string{mB + " go=192.168.43.11 hotspotd=192.168.43.99"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if !compareM4(map[string][]string{mA: {"192.168.43.10"}}, map[string]m4HDDev{mA: {IP: "192.168.43.10"}}).empty() {
		t.Fatal("一致时应无差异")
	}
}

func TestGoDevicesFiltersStates(t *testing.T) {
	es := []neigh.Entry{
		ne(mA, "192.168.43.10", neigh.NUDReachable),
		ne(mA, "192.168.43.12", neigh.NUDStale), // 同一 MAC 两个 IP
		ne(mB, "192.168.43.11", neigh.NUDFailed),
		ne(mC, "192.168.43.13", neigh.NUDIncomplete),
		{IfIndex: 5, MAC: "aa:bb:cc:00:00:0e", IP: net.ParseIP("fe80::1"), State: neigh.NUDReachable}, // IPv6 不比
		{IfIndex: 5, MAC: "", IP: net.ParseIP("192.168.43.14"), State: neigh.NUDReachable},
	}
	got := goDevices(es)
	if !reflect.DeepEqual(got, map[string][]string{mA: {"192.168.43.10", "192.168.43.12"}}) {
		t.Fatalf("goDevices = %v", got)
	}
}

func TestParseHotspotdDevicesIface(t *testing.T) {
	b := []byte(`{"AA:BB:CC:00:00:0A":{"ip":"192.168.43.10","iface":"wlan2"},
	 "aa:bb:cc:00:00:0b":{"ip":"10.0.0.2","iface":"rndis0"},
	 "aa:bb:cc:00:00:0c":{"ip":"192.168.43.30"},
	 "bad":{"ip":"1.2.3.4"}}`)
	got := parseHotspotdDevices(b, "wlan2")
	if len(got) != 2 || got[mA].IP != "192.168.43.10" || got[mC].IP != "192.168.43.30" {
		t.Fatalf("got %v", got)
	}
	if parseHotspotdDevices([]byte("{bad"), "wlan2") != nil {
		t.Fatal("坏 JSON 应返回 nil(本轮不比)")
	}
}

// 去抖: 同一差异连续 2 轮才计; 消失后重新计轮。
func TestM4RecordDebounce(t *testing.T) {
	s := &m4ShadowState{}
	d1 := m4Diff{OnlyGo: []string{mA}}
	if s.record(d1) {
		t.Fatal("第 1 轮不计")
	}
	if !s.record(d1) {
		t.Fatal("连续第 2 轮应计")
	}
	if s.record(m4Diff{}) || s.record(d1) {
		t.Fatal("中断后从头计轮")
	}
	if s.record(m4Diff{OnlyHotspotd: []string{mA}}) {
		t.Fatal("种类变了(多 → 少)是新差异, 不应接着上一种计")
	}
	if c, m := s.counts(); c != 5 || m != 1 {
		t.Fatalf("checks=%d mismatch=%d", c, m)
	}
}

func m4WriteDevices(t *testing.T, data string, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(data, "devices.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestM4ShadowSwitchAndUnreadable(t *testing.T) {
	run, data := withTempM4Shadow(t)
	m4IfIndexFn = func(string) (int, error) { return 5, nil }
	neighDumpIfFn = func(int) ([]neigh.Entry, error) {
		return []neigh.Entry{ne(mA, "192.168.43.10", neigh.NUDReachable)}, nil
	}
	m4WriteDevices(t, data, `{}`)
	now := time.Unix(1_800_000_000, 0)
	_ = os.WriteFile(filepath.Join(run, m4SwitchFile), nil, 0o644)
	m4Shadow.maybeRun("wlan2", now)
	if c, _ := m4Shadow.counts(); c != 0 {
		t.Fatal("开关关闭时不应比对")
	}
	_ = os.Remove(filepath.Join(run, m4SwitchFile))
	m4Shadow.maybeRun("wlan2", now)
	m4Shadow.maybeRun("wlan2", now.Add(time.Minute)) // 不到 5 分钟
	if c, _ := m4Shadow.counts(); c != 1 {
		t.Fatalf("checks = %d, want 1(5 分钟一轮)", c)
	}
	neighDumpIfFn = func(int) ([]neigh.Entry, error) { return nil, errors.New("EPERM") }
	m4Shadow.maybeRun("wlan2", now.Add(6*time.Minute))
	if c, _ := m4Shadow.counts(); c != 1 {
		t.Fatal("读不了邻居表的轮次不计")
	}
}

// 接线: 走真实调用方 loopState.tick(ACTIVE)→ handleActive → m4Shadow.maybeRun,
// 跑 1 小时: hotspotd 漏了一台 → 每轮都有差异, 从第 2 轮起计数; 明细文件与
// watchdog_actions.json 快照都带出来; devices.json 一个字节都不改。
func TestM4ShadowWiredIntoActiveLoop(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)
	run, data := m4RunDir, m4DataDir
	m4IfIndexFn = func(name string) (int, error) {
		if name != "wlan0" {
			return 0, errors.New("unexpected iface " + name)
		}
		return 5, nil
	}
	neighDumpIfFn = func(idx int) ([]neigh.Entry, error) {
		if idx != 5 {
			return nil, errors.New("wrong ifindex")
		}
		return []neigh.Entry{ne(mA, "192.168.43.10", neigh.NUDReachable), ne(mB, "192.168.43.11", neigh.NUDStale)}, nil
	}
	devs := `{"aa:bb:cc:00:00:0a":{"ip":"192.168.43.10","iface":"wlan0","last_seen":1800000000}}`
	m4WriteDevices(t, data, devs)
	ls := newLoopState()
	driveHour(ls, clk, func(int) wdState { return wdState{kind: stateActive, iface: "wlan0"} }, 60*time.Second)
	checks, mm := m4Shadow.counts()
	if checks != 12 || mm != 11 {
		t.Fatalf("1 小时 checks=%d mismatch=%d, want 12 / 11", checks, mm)
	}
	snap := wdActions.snapshot(clk.now)
	if snap.M4Checks != 12 || snap.M4Mismatch != 11 {
		t.Fatalf("watchdog_actions 快照 m4 = %d / %d", snap.M4Checks, snap.M4Mismatch)
	}
	b, err := os.ReadFile(filepath.Join(run, m4ShadowFileName))
	if err != nil || !reflect.DeepEqual(mustJSON(t, b)["only_go"], []interface{}{mB}) {
		t.Fatalf("m4_shadow.json = %s err=%v", b, err)
	}
	if got, _ := os.ReadFile(filepath.Join(data, "devices.json")); string(got) != devs {
		t.Fatal("影子不许改 devices.json")
	}
}

func mustJSON(t *testing.T, b []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return m
}
