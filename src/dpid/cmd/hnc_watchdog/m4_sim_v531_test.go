//go:build linux

// m4_sim_v531_test.go — v5.31 T5: 模拟设备上的 M4 方案 A 验收(由 test/sim/run_m4_sim_v531.sh 调;
// 平时 go test 直接跳过)。
//
// 运行环境(脚本保证): 在独立的网络 + 挂载命名空间里, 模拟目录已绑到 /data/local/hnc ——
// 所以这里一律走看门狗的正式路径(dataDir / runDir / binDir …), 不做任何重定向; PATH 里有
// test/sim/fake(假 dumpsys)。
//
// TestM4SimV531(HNC_SIM_MODE):
//
//	fields — C 模式全字段影子: hotspotd 照常写 data/devices.json, 一个演练写者(drill)
//	  只写 run/devices.go.json; 与 hotspotd 的输出逐字段比(last_seen / 字节除外)。
//	go     — Go 模式: hotspotd 带 --no-discovery(脚本负责), Go 写者写 data/devices.json。
//	两种模式都在时限内反复比到全部对上(名字是异步解析的), 期望来自场景:
//	HNC_SIM_EXPECT="mac ip;…"、HNC_SIM_NAMES="mac=名字@来源;…"、HNC_SIM_BLOCKED="mac,…"。
//
// TestM4SimOwner(v5.31 审查重写的「运行中切换」): 用看门狗真实的 owner 管理器(生产接线:
// 经控制接口 QUIT、ensureDaemonRunning 拉起 bin/hotspotd)在真进程上走一遍:
// 开机纠偏(c 但 hotspotd 是 --no-discovery)→ c→go(刚被拉起不到 60 秒)→ Go 模式下新设备
// 连上 → go→c; 用两边的写日志确认没有两个写者交替写。
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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

func readDevs(path string) (map[string]simDev, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]simDev{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("解析 %s: %v", path, err)
	}
	return m, nil
}

// parseExpect "mac ip;mac ip;..." → {mac: ip}
func parseExpect(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(strings.TrimSpace(s), ";") {
		if f := strings.Fields(kv); len(f) >= 2 {
			out[strings.ToLower(f[0])] = f[1]
		}
	}
	return out
}

// parseNames "mac=名字@来源;..." → {mac: [名字, 来源]}
func parseNames(s string) map[string][2]string {
	out := map[string][2]string{}
	for _, kv := range strings.Split(s, ";") {
		if p := strings.SplitN(kv, "=", 2); len(p) == 2 {
			if q := strings.SplitN(p[1], "@", 2); len(q) == 2 {
				out[strings.ToLower(p[0])] = [2]string{q[0], q[1]}
			}
		}
	}
	return out
}

// simProblems 一份设备表与场景期望(集合 / IP / iface / 名字 / 黑名单)的全部差异。
// blocked 为 nil 时不比 status。
func simProblems(devs map[string]simDev, iface string, expect map[string]string, names map[string][2]string, blocked map[string]bool) []string {
	var out []string
	for mac, ip := range expect {
		d, ok := devs[mac]
		if !ok {
			out = append(out, "缺设备 "+mac)
			continue
		}
		if d.IP != ip {
			out = append(out, fmt.Sprintf("%s: IP %s, 期望 %s", mac, d.IP, ip))
		}
		if d.Iface != iface {
			out = append(out, fmt.Sprintf("%s: iface %q, 期望 %q", mac, d.Iface, iface))
		}
		if want, ok := names[mac]; ok && (d.Hostname != want[0] || d.HostnameSrc != want[1]) {
			out = append(out, fmt.Sprintf("%s: 名字 %q@%s, 期望 %q@%s", mac, d.Hostname, d.HostnameSrc, want[0], want[1]))
		}
		if blocked != nil {
			st := "allowed"
			if blocked[mac] {
				st = "blocked"
			}
			if d.Status != st {
				out = append(out, fmt.Sprintf("%s: status %q, 期望 %q", mac, d.Status, st))
			}
		}
	}
	for mac := range devs {
		if _, ok := expect[mac]; !ok {
			out = append(out, "多了设备 "+mac)
		}
	}
	return out
}

func simEnv() (iface string, expect map[string]string, names map[string][2]string, blocked map[string]bool) {
	iface = os.Getenv("HNC_SIM_IFACE")
	expect = parseExpect(os.Getenv("HNC_SIM_EXPECT"))
	names = parseNames(os.Getenv("HNC_SIM_NAMES"))
	blocked = map[string]bool{}
	for _, mac := range strings.Split(os.Getenv("HNC_SIM_BLOCKED"), ",") {
		if mac = strings.ToLower(strings.TrimSpace(mac)); mac != "" {
			blocked[mac] = true
		}
	}
	return
}

func TestM4SimV531(t *testing.T) {
	if os.Getenv("HNC_SIM_IFACE") == "" || os.Getenv("HNC_SIM_MODE") == "" {
		t.Skip("只在 test/sim/run_m4_sim_v531.sh 里跑(需要模拟设备)")
	}
	iface, expect, names, blocked := simEnv()
	if len(expect) == 0 {
		t.Fatal("HNC_SIM_EXPECT 为空")
	}
	drill := false
	switch mode := os.Getenv("HNC_SIM_MODE"); mode {
	case "fields":
		drill = true
	case "go":
	default:
		t.Fatalf("未知 HNC_SIM_MODE=%q", mode)
	}
	out := m4DevicesJSON
	if drill {
		out = m4DrillOut
	}
	_ = os.Remove(out) // 只认本次写者写出的
	r := newM4GoRunner(iface, drill)
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.start()
	defer func() { close(r.stopCh); <-r.doneCh }()

	deadline := time.Now().Add(30 * time.Second)
	var probs []string
	for {
		devs, err := readDevs(out)
		if err != nil {
			probs = []string{err.Error()}
		} else if probs = simProblems(devs, iface, expect, names, blocked); drill && len(probs) == 0 {
			// 全字段影子: 再与 hotspotd 的正式输出逐字段比(last_seen / 字节除外)
			hd, err := readDevs(m4DevicesJSON)
			if err != nil {
				probs = append(probs, "读 hotspotd 的 devices.json: "+err.Error())
			} else if len(hd) != len(devs) {
				probs = append(probs, fmt.Sprintf("设备数: hotspotd %d, Go %d", len(hd), len(devs)))
			}
			for mac, g := range devs {
				h := hd[mac]
				h.LastSeen, g.LastSeen, h.RXBytes, h.TXBytes, g.RXBytes, g.TXBytes = 0, 0, 0, 0, 0, 0
				if h != g {
					probs = append(probs, fmt.Sprintf("%s 与 hotspotd 不一致: go %+v / c %+v", mac, g, h))
				}
			}
		}
		if len(probs) == 0 {
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	for _, p := range probs {
		t.Error(p)
	}
}

// ─── 运行中切换(真进程) ─────────────────────────────────────────────

func simStatus() string {
	s, err := m4HotspotdStatus()
	if err != nil {
		return "ERR " + err.Error()
	}
	return strings.TrimSpace(s)
}

// procDiag 失败时附上 hotspotd 进程管理的现场(pidfile / 活没活 / 按名字找 / 二进制在不在)。
func procDiag() string {
	b, _ := os.ReadFile(hotspotdPidP)
	pid := 0
	fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &pid)
	_, binErr := os.Stat(binDir + "/hotspotd")
	return fmt.Sprintf("pidfile=%d alive=%v findLive=%d bin=%v", pid, pid > 0 && processAlive(pid), findLiveByName("hotspotd"), binErr)
}

func discovering() bool {
	s := simStatus()
	return strings.HasPrefix(s, "running:1") && !strings.Contains(s, "discovery:0")
}

// waitFor 时限内反复检查 cond, 成立返回 true。
func waitFor(limit time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return cond()
}

// logTimes 日志里带 mark 的行的时间(秒级, 本地时区)。
func logTimes(path, layout, mark string, tsOf func(line string) string) []time.Time {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []time.Time
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, mark) {
			continue
		}
		if ts, err := time.ParseInLocation(layout, tsOf(line), time.Local); err == nil {
			out = append(out, ts)
		}
	}
	return out
}

func TestM4SimOwner(t *testing.T) {
	iface, simnet := os.Getenv("HNC_SIM_IFACE"), os.Getenv("HNC_SIM_SIMNET")
	if iface == "" || os.Getenv("HNC_SIM_OWNER") != "1" || simnet == "" {
		t.Skip("只在 test/sim/run_m4_sim_v531.sh 里跑(需要模拟设备)")
	}
	_, expect, names, _ := simEnv()
	// 写日志是秒级; 先等过 1 秒再记起点 —— 更早的行是前面场景(一次性写者)留下的, 不能与本场景同秒
	time.Sleep(1100 * time.Millisecond)
	tStart := time.Now().Truncate(time.Second)
	setOwner := func(v string) {
		t.Helper()
		if err := os.WriteFile(m4OwnerFile, []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := &m4OwnerMgr{}
	m4Owner = m // hotspotdDaemon() 读全局的 owner 快照
	defer func() {
		m.hotspotDown()
		_ = m4QuitHotspotd()
		m4OwnerCur.Store("c")
	}()
	devsOK := func(want map[string]string, wantNames map[string][2]string) func() bool {
		return func() bool {
			devs, err := readDevs(m4DevicesJSON)
			return err == nil && len(simProblems(devs, iface, want, wantNames, nil)) == 0
		}
	}
	fail := func(step string, want map[string]string, wantNames map[string][2]string) {
		t.Helper()
		devs, err := readDevs(m4DevicesJSON)
		t.Fatalf("%s: STATUS=%q 读=%v 差异=%v", step, simStatus(), err, simProblems(devs, iface, want, wantNames, nil))
	}

	// 1. 开机纠偏: 开关是 c, 但 hotspotd 是上次会话按 go(--no-discovery)拉起的 —— 没人发现设备。
	setOwner("c")
	if !strings.Contains(simStatus(), "discovery:0") {
		t.Fatalf("前置条件: 脚本应先以 --no-discovery 拉起 hotspotd, STATUS=%q", simStatus())
	}
	_ = os.Remove(m4DevicesJSON)
	m.tick(iface, time.Now())
	if !waitFor(10*time.Second, discovering) {
		t.Fatalf("1. owner=c 时应把 hotspotd 纠正为做发现, STATUS=%q %s", simStatus(), procDiag())
	}
	// C 版逐台异步解析名字(每秒一台, 没解析到的过一阵才从 pending 落到 mac), 给它 40 秒
	if !waitFor(40*time.Second, devsOK(expect, names)) {
		fail("1. 纠偏后 hotspotd 应重新写出设备表", expect, names)
	}
	t.Logf("1. 开机纠偏 ✓ STATUS=%q", simStatus())

	// 2. c → go, 且 hotspotd 刚被看门狗拉起(60 秒冷却内)。
	lastRestartMu.Lock()
	lastRestart["hotspotd"] = time.Now()
	lastRestartMu.Unlock()
	setOwner("go")
	_ = os.Remove(m4DevicesJSON) // 切换前删: 之后出现的只能是新写者写的
	tGo0 := time.Now()
	m.tick(iface, time.Now())
	if m.owner != "go" || !strings.Contains(simStatus(), "discovery:0") {
		t.Fatalf("2. 应切到 go 且 hotspotd 不做发现: owner=%q STATUS=%q", m.owner, simStatus())
	}
	tGo := time.Now()
	if !waitFor(15*time.Second, devsOK(expect, names)) {
		fail("2. Go 写者应写出全部设备(含名字)", expect, names)
	}
	t.Logf("2. c→go ✓(切换 %.1f 秒)STATUS=%q", tGo.Sub(tGo0).Seconds(), simStatus())

	// 3. Go 模式下新设备连上(DHCP 报名字)。
	if out, err := exec.Command("bash", simnet, "add", "pixel", "02:5a:00:00:00:21", "192.168.43.121", "Pixel-8").CombinedOutput(); err != nil {
		t.Fatalf("simnet add: %v %s", err, out)
	}
	expect3 := map[string]string{"02:5a:00:00:00:21": "192.168.43.121"}
	names3 := map[string][2]string{"02:5a:00:00:00:21": {"Pixel-8", "dhcp"}}
	for k, v := range expect {
		expect3[k] = v
	}
	for k, v := range names {
		names3[k] = v
	}
	if !waitFor(15*time.Second, devsOK(expect3, names3)) {
		fail("3. Go 模式下新连上的设备应写出(名字 Pixel-8@dhcp)", expect3, names3)
	}
	t.Log("3. Go 模式新设备 ✓")

	// 4. go → c。
	setOwner("c")
	_ = os.Remove(m4DevicesJSON)
	tC0 := time.Now()
	m.tick(iface, time.Now())
	if m.owner != "c" || m.runner != nil {
		t.Fatalf("4. 应切回 c 且 Go 写者已停: owner=%q runner=%v", m.owner, m.runner != nil)
	}
	if !waitFor(10*time.Second, discovering) {
		t.Fatalf("4. 切回 c 后 hotspotd 应做发现, STATUS=%q", simStatus())
	}
	tC := time.Now()
	// C 版重启时, 换过 IP 的设备若新旧表项都是 STALE, 挑哪个看 /proc/net/arp 的顺序(老问题,
	// 不在本版范围; Go 版已按内核的「最近确认」挑新的)。这一步只验「C 重新接管、写出全部
	// 设备与名字」: 该设备的 IP 是它用过的任何一个都算对(HNC_SIM_OLD_IPS="mac=ip,ip;…")。
	oldIPs := map[string]string{}
	for _, kv := range strings.Split(os.Getenv("HNC_SIM_OLD_IPS"), ";") {
		if p := strings.SplitN(kv, "=", 2); len(p) == 2 {
			oldIPs[strings.ToLower(p[0])] = "," + p[1] + ","
		}
	}
	cOK := func() bool {
		devs, err := readDevs(m4DevicesJSON)
		if err != nil {
			return false
		}
		want := map[string]string{}
		for mac, ip := range expect3 {
			want[mac] = ip
			if d, ok := devs[mac]; ok && strings.Contains(oldIPs[mac], ","+d.IP+",") {
				want[mac] = d.IP
			}
		}
		return len(simProblems(devs, iface, want, names3, nil)) == 0
	}
	if !waitFor(40*time.Second, cOK) {
		fail("4. 切回 c 后 hotspotd 应写出全部设备", expect3, names3)
	}
	t.Logf("4. go→c ✓(切换 %.1f 秒)", tC.Sub(tC0).Seconds())

	// 5. 没有两个写者交替写: Go 的写只在 [切到 go 开始, 切回 c 开始] 之间; hotspotd 的写
	// 不在 (切到 go 完成, 切回 c 开始) 之间。日志是秒级, 两头各放 1 秒。
	goWrites := logTimes(m4GoWriteLog, "2006-01-02T15:04:05", ": ", func(l string) string {
		if i := strings.Index(l, ": "); i > 0 {
			return l[:i]
		}
		return ""
	})
	cWrites := logTimes(filepath.Join(logDir, "hotspotd.log"), "2006-01-02 15:04:05", "JSON written", func(l string) string {
		if len(l) >= 21 && l[0] == '[' {
			return l[1:20]
		}
		return ""
	})
	nGo, nC := 0, 0
	for _, w := range goWrites {
		if !w.Before(tStart) {
			nGo++
		}
	}
	for _, w := range cWrites {
		if !w.Before(tStart) {
			nC++
		}
	}
	if nGo == 0 || nC == 0 {
		t.Fatalf("5. 写日志里本场景的写记录不全: Go %d 次, hotspotd %d 次", nGo, nC)
	}
	sec := time.Second
	for _, w := range goWrites {
		if w.Before(tStart) {
			continue
		}
		if w.Before(tGo0.Truncate(sec).Add(-sec)) || w.After(tC0.Add(sec)) {
			t.Errorf("5. Go 在它不是写者的时候写了 devices.json: %s(go 期间 %s – %s)", w.Format("15:04:05"), tGo0.Format("15:04:05"), tC0.Format("15:04:05"))
		}
	}
	for _, w := range cWrites {
		if w.Before(tStart) {
			continue
		}
		if w.After(tGo.Add(sec)) && w.Before(tC0.Truncate(sec).Add(-sec)) {
			t.Errorf("5. hotspotd 在 Go 是写者的时候写了 devices.json: %s", w.Format("15:04:05"))
		}
	}
	t.Logf("5. 写者不交错 ✓(本场景 Go 写 %d 次, hotspotd 写 %d 次)", nGo, nC)
}
