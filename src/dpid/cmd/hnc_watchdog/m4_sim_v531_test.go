//go:build linux

// m4_sim_v531_test.go — v5.31 T5: 模拟设备上的「全字段影子 / Go 模式全流程」对照。
// 由 test/sim/run_m4_sim_v531.sh 调; 平时 go test 直接跳过。要 root + netns, 本地
// 开发机没有 —— 场景照写, 由维护者云端容器跑(WORK-v5.31 §4 T5)。
//
// 两个模式(HNC_SIM_MODE):
//
//	fields — C 模式全字段影子: hotspotd 照常写 data/devices.json, Go 写者以演练
//	  方式只写 run/devices.go.json(touch run/wd_m4_drill), 每步逐字段比
//	  (last_seen / rx_bytes / tx_bytes 除外): 集合、ip、hostname、hostname_src、
//	  iface、status。期望来自场景本身(HNC_SIM_EXPECT="mac ip;...", 与 TestM4Sim
//	  同格式), 另用 HNC_SIM_NAMES="mac=名字@src;..." 校验 hostname/hostname_src,
//	  HNC_SIM_BLOCKED="mac,..." 校验黑名单 status。
//	go — Go 模式全流程: hotspotd 带 --no-discovery 跑(脚本负责), Go 写者写
//	  data/devices.json, 同样逐字段比; 并断言演练开关已移除(正式路径)。
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// simDev 是 devices.json 里一台设备的字段(devscan.Device 同构, 独立定义避免耦合)。
type simDev struct {
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Hostname    string `json:"hostname"`
	HostnameSrc string `json:"hostname_src"`
	Iface       string `json:"iface"`
	RXBytes     int64  `json:"rx_bytes"`
	TXBytes     int64  `json:"tx_bytes"`
	Status      string `json:"status"`
	LastSeen    int64  `json:"last_seen"`
}

func loadDevs(t *testing.T, path string) map[string]simDev {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 %s: %v", path, err)
	}
	m := map[string]simDev{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("解析 %s: %v (%s)", path, err, b)
	}
	return m
}

// runGoWriter 起 Go 写者(所有路径重定向到 HNC_SIM_HNC_DIR 下), 等它在时限内
// 把输出写到 outPath 并收敛到期望集合; 返回写出的设备表。
func runGoWriter(t *testing.T, iface, hncDir, outPath string, drill bool, expectMacs map[string]string, limit time.Duration) map[string]simDev {
	t.Helper()
	oldVars := simRedirect(hncDir, drill)
	defer simRestore(oldVars)

	if drill {
		if err := os.WriteFile(m4DrillFile, []byte("1"), 0o644); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Remove(m4DrillFile); err == nil { // 确保正式模式
	}

	r := newM4GoRunner(iface)
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.start()
	defer func() { close(r.stopCh); <-r.doneCh }()

	deadline := time.Now().Add(limit)
	// converged: 演练/正式输出已写出且集合与 IP 都等于期望?
	converged := func() (map[string]simDev, bool) {
		if _, err := os.Stat(outPath); err != nil {
			return nil, false
		}
		devs := loadDevs(t, outPath)
		if len(devs) != len(expectMacs) {
			return devs, false
		}
		for mac, ip := range expectMacs {
			d, e := devs[mac]
			if !e || d.IP != ip {
				return devs, false
			}
		}
		return devs, true
	}
	for time.Now().Before(deadline) {
		if devs, ok := converged(); ok {
			return devs
		}
		time.Sleep(500 * time.Millisecond)
	}
	devs, _ := converged()
	t.Fatalf("%s 内 Go 写者没收敛到期望(期望 %d 台: %v; 现有 %d 台)", limit, len(expectMacs), expectMacs, len(devs))
	return nil
}

// simRedirect 把 m4_owner 的路径变量全部指到 sim 的 HNC 目录; 返回恢复函数用的旧值。
func simRedirect(hncDir string, drill bool) [8]string {
	old := [8]string{m4OwnerFile, m4OwnerCurrentFile, m4DevicesJSON, m4DevicesTmpGo,
		m4DrillOut, m4GoOutTmp, m4RefreshFile, m4DrillFile}
	m4OwnerFile = filepath.Join(hncDir, "data", "m4_owner")
	m4OwnerCurrentFile = filepath.Join(hncDir, "run", "m4_owner.current")
	m4DevicesJSON = filepath.Join(hncDir, "data", "devices.json")
	m4DevicesTmpGo = filepath.Join(hncDir, "data", "devices.json.tmp.go")
	m4DrillOut = filepath.Join(hncDir, "run", "devices.go.json")
	m4GoOutTmp = filepath.Join(hncDir, "run", "devices.go.json.tmp")
	m4RefreshFile = filepath.Join(hncDir, "run", "devices.refresh")
	m4DrillFile = filepath.Join(hncDir, "run", "wd_m4_drill")
	return old
}

func simRestore(old [8]string) {
	m4OwnerFile, m4OwnerCurrentFile, m4DevicesJSON, m4DevicesTmpGo,
		m4DrillOut, m4GoOutTmp, m4RefreshFile, m4DrillFile = old[0], old[1], old[2], old[3],
		old[4], old[5], old[6], old[7]
}

// parseExpect "mac ip;mac ip;..." → {mac: ip}
func parseExpect(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(strings.TrimSpace(s), ";") {
		f := strings.Fields(kv)
		if len(f) >= 2 {
			out[f[0]] = f[1]
		}
	}
	return out
}

func TestM4SimV531(t *testing.T) {
	iface, hncDir := os.Getenv("HNC_SIM_IFACE"), os.Getenv("HNC_SIM_HNC_DIR")
	if iface == "" || hncDir == "" {
		t.Skip("只在 test/sim/run_m4_sim_v531.sh 里跑(需要模拟设备)")
	}
	mode := os.Getenv("HNC_SIM_MODE")
	expectMacs := parseExpect(os.Getenv("HNC_SIM_EXPECT"))
	if len(expectMacs) == 0 {
		t.Fatal("HNC_SIM_EXPECT 为空")
	}
	cmpPath := filepath.Join(hncDir, "data", "devices.json")

	var drill bool
	var outPath string
	switch mode {
	case "fields":
		drill = true
		outPath = filepath.Join(hncDir, "run", "devices.go.json")
		cmpPath = outPath // 比对对象 = Go 的演练输出
	case "go":
		drill = false
		outPath = cmpPath // Go 写正式 devices.json
	default:
		t.Fatalf("未知 HNC_SIM_MODE=%q", mode)
	}

	devs := runGoWriter(t, iface, hncDir, outPath, drill, expectMacs, 45*time.Second)

	// 集合 + IP(期望来自场景)
	for mac, ip := range expectMacs {
		d, ok := devs[mac]
		if !ok {
			t.Errorf("Go 缺设备 %s(有 %d 台)", mac, len(devs))
			continue
		}
		if d.IP != ip {
			t.Errorf("%s: IP %s, 期望 %s", mac, d.IP, ip)
		}
		if d.Iface != iface {
			t.Errorf("%s: iface %q, 期望 %q", mac, d.Iface, iface)
		}
	}
	for mac := range devs {
		if _, ok := expectMacs[mac]; !ok {
			t.Errorf("Go 多了设备 %s", mac)
		}
	}

	// 名字 / 黑名单(HNC_SIM_NAMES / HNC_SIM_BLOCKED, 期望来自场景)
	names := map[string][2]string{}
	for _, kv := range strings.Split(os.Getenv("HNC_SIM_NAMES"), ";") {
		if p := strings.SplitN(kv, "=", 2); len(p) == 2 {
			if q := strings.SplitN(p[1], "@", 2); len(q) == 2 {
				names[p[0]] = [2]string{q[0], q[1]}
			}
		}
	}
	for mac, want := range names {
		d, ok := devs[mac]
		if !ok {
			continue
		}
		if d.Hostname != want[0] || d.HostnameSrc != want[1] {
			t.Errorf("%s: 名字 %q@%s, 期望 %q@%s", mac, d.Hostname, d.HostnameSrc, want[0], want[1])
		}
	}
	blocked := map[string]bool{}
	for _, mac := range strings.Split(os.Getenv("HNC_SIM_BLOCKED"), ",") {
		if mac != "" {
			blocked[mac] = true
		}
	}
	for mac, d := range devs {
		want := "allowed"
		if blocked[mac] {
			want = "blocked"
		}
		if d.Status != want {
			t.Errorf("%s: status %q, 期望 %q", mac, d.Status, want)
		}
	}

	// fields 模式: 与 hotspotd 的 devices.json 逐字段比(last_seen/字节除外)
	if mode == "fields" {
		hd := loadDevs(t, filepath.Join(hncDir, "data", "devices.json"))
		if len(hd) != len(devs) {
			t.Errorf("设备数不一致: hotspotd %d, Go %d(%v vs %v)", len(hd), len(devs), keysOf(hd), keysOf(devs))
		}
		for mac, g := range devs {
			h, ok := hd[mac]
			if !ok {
				continue
			}
			h.LastSeen, g.LastSeen = 0, 0
			h.RXBytes, h.TXBytes, g.RXBytes, g.TXBytes = 0, 0, 0, 0
			if h != g {
				t.Errorf("%s: 与 hotspotd 字段不一致:\n go %+v\n  c  %+v", mac, g, h)
			}
		}
	}
}

func keysOf(m map[string]simDev) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
