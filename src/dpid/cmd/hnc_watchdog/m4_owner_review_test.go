// m4_owner_review_test.go — v5.31 审查修复的回归用例(每条在审查前的代码上都失败,
// 见提交说明)。外部世界(hotspotd 控制、订阅、dump、命令)全部注入, 路径在临时目录。
package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hnc.io/dpid/neigh"
)

// withTempM4Owner 预算类测试用: 全局 m4Owner 换成注入版(owner=c、hotspotd 正常),
// 路径进临时目录 —— 不碰真实 /data/local/hnc, 也不走真实 socket(原来每个预算测试
// 都在确认切换时白等 1.2 秒)。
func withTempM4Owner(t *testing.T) {
	t.Helper()
	m4TestEnv(t)
	old, oldCur := m4Owner, m4OwnerCur.Load()
	m4Owner = &m4OwnerMgr{wired: true,
		quitHotspotdFn:   func() error { return nil },
		hotspotdStatusFn: func() (string, error) { return "running:1 devices:0 pid:1\n", nil },
		ensureHotspotdFn: func() error { return nil },
	}
	_ = os.WriteFile(m4OwnerFile, []byte("c\n"), 0o644)
	t.Cleanup(func() {
		m4Owner.hotspotDown()
		m4Owner = old
		if oldCur == nil {
			oldCur = "c"
		}
		m4OwnerCur.Store(oldCur)
	})
}

// fakeRunner 一个只会「被停」的写者(看 stop 有没有被调)。
func fakeRunner(iface string, drill bool) *m4GoRunner {
	r := &m4GoRunner{iface: iface, drill: drill, stopCh: make(chan struct{}), doneCh: make(chan struct{})}
	go func() { <-r.stopCh; close(r.doneCh) }()
	return r
}

// 审查修复 1: owner=c 但 hotspotd 在 --no-discovery 下跑(开机时按上次会话的
// run/m4_owner.current 拉起)→ 按原参数重启; owner=go 但 hotspotd 仍在发现 → 带参重启。
func TestOwnerReconcilesHotspotdMode(t *testing.T) {
	m4TestEnv(t)
	if err := os.WriteFile(m4OwnerFile, []byte("c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	status := "running:1 devices:3 pid:9 discovery:0\n" // 上次会话按 go 拉起的
	quits, ensures := 0, 0
	m := &m4OwnerMgr{wired: true}
	m.hotspotdStatusFn = func() (string, error) { return status, nil }
	m.quitHotspotdFn = func() error { quits++; return nil }
	m.ensureHotspotdFn = func() error {
		ensures++
		if m4OwnerCur.Load() == "go" {
			status = "running:1 devices:3 pid:10 discovery:0\n"
		} else {
			status = "running:1 devices:3 pid:10\n"
		}
		return nil
	}
	m.tick("", time.Now())
	if m.owner != "c" || quits != 1 || ensures != 1 {
		t.Fatalf("owner=c 而 hotspotd 不做发现: 应按原参数重启一次, owner=%q quit=%d ensure=%d", m.owner, quits, ensures)
	}
	m.tick("", time.Now()) // 已一致: 不再动
	if quits != 1 {
		t.Fatalf("一致后不应再重启, quit=%d", quits)
	}
	// owner=go 但 hotspotd 被别处按普通参数重拉了(两个写者)→ 带 --no-discovery 重启
	if err := os.WriteFile(m4OwnerFile, []byte("go\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.tick("", time.Now()) // c → go 正常切换
	if m.owner != "go" || !strings.Contains(status, "discovery:0") {
		t.Fatalf("应切到 go: owner=%q status=%q", m.owner, status)
	}
	status = "running:1 devices:3 pid:11\n"
	q0 := quits
	m.tick("", time.Now())
	if m.owner != "go" || quits != q0+1 || !strings.Contains(status, "discovery:0") {
		t.Fatalf("owner=go 而 hotspotd 在发现: 应带参重启, owner=%q quit=%d status=%q", m.owner, quits-q0, status)
	}
	m4OwnerCur.Store("c")
}

// 审查修复 2: 切换时重拉 hotspotd 不受 60 秒崩溃冷却限制(刚被看门狗拉起的也能切)。
func TestSwitchRestartBypassesCooldown(t *testing.T) {
	m4TestEnv(t)
	oldEnsure := ensureDaemonFn
	t.Cleanup(func() {
		ensureDaemonFn = oldEnsure
		m4ResetCooldown("hotspotd")
		m4OwnerCur.Store("c")
	})
	var allowed []bool
	ensureDaemonFn = func(d daemonSpec) { allowed = append(allowed, cooldownOK(d.name, d.cooldown)) }
	lastRestartMu.Lock()
	lastRestart["hotspotd"] = time.Now() // 看门狗刚拉起过它
	lastRestartMu.Unlock()

	m := &m4OwnerMgr{}
	m.wireProd() // 生产接线(只把拉起动作换成记录)
	m.quitHotspotdFn = func() error { return nil }
	m.hotspotdStatusFn = func() (string, error) { return "running:1 devices:0 pid:1 discovery:0\n", nil }
	m.owner = "c"
	m.switchOwnerLocked("go", time.Now())
	if len(allowed) == 0 || !allowed[0] {
		t.Fatalf("切换时重拉 hotspotd 被冷却挡住(allowed=%v): hotspotd 会停摆到下一轮", allowed)
	}
}

// 审查修复 3a: owner=c + 演练开关 → 演练写者; 中途删掉开关, 写者在下一轮被停之前
// 也不能写正式 devices.json(否则两个写者)。
func TestDrillFixedAtStartNoFormalWrite(t *testing.T) {
	m4TestEnv(t)
	if err := os.WriteFile(m4OwnerFile, []byte("c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m4DrillFile, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &m4OwnerMgr{wired: true,
		quitHotspotdFn:   func() error { return nil },
		hotspotdStatusFn: func() (string, error) { return "running:1 devices:0 pid:1\n", nil },
		ensureHotspotdFn: func() error { return nil },
	}
	m.tick("lo", time.Now())
	if m.runner == nil {
		t.Fatal("owner=c + 演练开关应起演练写者")
	}
	defer m.hotspotDown()
	_ = os.Remove(m4DrillFile) // 用户删了开关, 下一轮 tick 之前
	r := m.runner
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, errors.New("no") }
	at, sm := time.Time{}, map[string][2]int64{}
	r.writeOut(nil, &at, &sm, true)
	if _, err := os.Stat(m4DevicesJSON); err == nil {
		t.Fatal("演练写者写了正式 devices.json(hotspotd 也在写 → 两个写者)")
	}
	if _, err := os.Stat(m4DrillOut); err != nil {
		t.Fatalf("演练写者应写 run/devices.go.json: %v", err)
	}
}

// 审查修复 3b: owner=go 时残留的演练开关不生效 —— 正式 devices.json 必须有人写。
func TestDrillIgnoredWhenOwnerGo(t *testing.T) {
	m4TestEnv(t)
	if err := os.WriteFile(m4OwnerFile, []byte("go\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m4DrillFile, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &m4OwnerMgr{wired: true,
		quitHotspotdFn:   func() error { return nil },
		hotspotdStatusFn: func() (string, error) { return "running:1 devices:0 pid:1 discovery:0\n", nil },
		ensureHotspotdFn: func() error { return nil },
	}
	m.tick("lo", time.Now())
	defer func() { m.hotspotDown(); m4OwnerCur.Store("c") }()
	if m.owner != "go" || m.runner == nil {
		t.Fatalf("应是 go 且起了写者: owner=%q", m.owner)
	}
	r := m.runner
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, errors.New("no") }
	at, sm := time.Time{}, map[string][2]int64{}
	r.writeOut(nil, &at, &sm, true)
	if _, err := os.Stat(m4DevicesJSON); err != nil {
		t.Fatalf("owner=go 时应写正式 devices.json(hotspotd 已不发现): %v", err)
	}
}

// startTestRunner 起一个全注入的写者(订阅 / dump / 网卡 / 命令都是假的)。
func startTestRunner(t *testing.T, dump func() []neigh.Entry, idx func() (int, error), full func(mac, ip string) (string, string)) (*m4GoRunner, *fakeNeighSource) {
	t.Helper()
	r := newM4GoRunner("wlan2", false)
	src := &fakeNeighSource{ch: make(chan []neigh.Entry, 8), stop: make(chan struct{})}
	r.subscribeFn = func() (m4NeighSource, error) { return src, nil }
	r.dumpIfFn = func(int) ([]neigh.Entry, error) { return dump(), nil }
	r.ifIndexFn = func(string) (int, error) { return idx() }
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.blacklistFn = func() map[string]bool { return nil }
	r.hooks.Fast = func(mac string) (string, string) { return macFallback(mac), "mac" }
	r.hooks.Full = full
	r.applyHooks()
	r.start()
	return r, src
}

func stopRunner(t *testing.T, r *m4GoRunner) {
	t.Helper()
	close(r.stopCh)
	select {
	case <-r.doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("写者 5 秒内没退出")
	}
}

// waitDevices 轮询 devices.json 直到 pred 成立(带时限, 不裸 sleep 等结果)。
func waitDevices(t *testing.T, limit time.Duration, pred func(string) bool) (string, bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	last := ""
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(m4DevicesJSON); err == nil {
			last = string(b)
			if pred(last) {
				return last, true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return last, false
}

// 审查修复 4: 起写者后立刻全量扫(原来要等满 30 秒才认得已在线的设备)。
func TestRunnerInitialFullSync(t *testing.T) {
	m4TestEnv(t)
	r, _ := startTestRunner(t,
		func() []neigh.Entry {
			return []neigh.Entry{{IfIndex: 7, IP: net.ParseIP("192.168.43.101"), MAC: "02:5a:00:00:00:01", State: 0x04}}
		},
		func() (int, error) { return 7, nil },
		func(mac, ip string) (string, string) { return macFallback(mac), "mac" })
	defer stopRunner(t, r)
	if got, ok := waitDevices(t, 2*time.Second, func(s string) bool { return strings.Contains(s, "02:5a:00:00:00:01") }); !ok {
		t.Fatalf("起写者 2 秒内应写出已在线(STALE)的设备, 得 %q", got)
	}
}

// 审查修复 5: 异步名字解析的结果要写出去(原来只改表不置 dirty, 一直停在 pending)。
func TestResolvedNameIsWritten(t *testing.T) {
	m4TestEnv(t)
	r, src := startTestRunner(t,
		func() []neigh.Entry { return nil },
		func() (int, error) { return 7, nil },
		func(mac, ip string) (string, string) { return "Redmi-TV", "dhcp" })
	defer stopRunner(t, r)
	src.ch <- []neigh.Entry{{IfIndex: 7, IP: net.ParseIP("192.168.43.101"), MAC: "02:5a:00:00:00:01", State: 0x02}}
	if got, ok := waitDevices(t, 4*time.Second, func(s string) bool { return strings.Contains(s, `"hostname":"Redmi-TV","hostname_src":"dhcp"`) }); !ok {
		t.Fatalf("4 秒内解析出的名字应写进 devices.json, 得 %q", got)
	}
}

// 审查修复 6: 停写者要等在途的名字解析结束(否则停了以后它还写名字缓存)。
func TestStopWaitsForInflightResolve(t *testing.T) {
	m4TestEnv(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var finished atomic.Bool
	r, src := startTestRunner(t,
		func() []neigh.Entry { return nil },
		func() (int, error) { return 7, nil },
		func(mac, ip string) (string, string) {
			close(started)
			<-release
			finished.Store(true)
			return "pixel", "dhcp"
		})
	src.ch <- []neigh.Entry{{IfIndex: 7, IP: net.ParseIP("192.168.43.101"), MAC: "02:5a:00:00:00:01", State: 0x02}}
	select {
	case <-started:
	case <-time.After(4 * time.Second):
		t.Fatal("4 秒内没派发名字解析")
	}
	stopped := make(chan struct{})
	go func() { close(r.stopCh); <-r.doneCh; close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("名字解析还在跑, 写者就算停了(之后它还会写名字缓存)")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("解析结束后写者应停下")
	}
	if !finished.Load() {
		t.Fatal("停下时解析应已结束")
	}
}

// 审查修复 7: 热点网卡的 ifindex 还不知道时不收邻居事件(表的 0 = 不过滤, 会把上游
// 网卡的邻居当成热点设备)。
func TestRunnerIgnoresEventsUntilIfindexKnown(t *testing.T) {
	m4TestEnv(t)
	var known atomic.Bool
	r, src := startTestRunner(t,
		func() []neigh.Entry { return nil },
		func() (int, error) {
			if known.Load() {
				return 7, nil
			}
			return 0, errors.New("no such interface")
		},
		func(mac, ip string) (string, string) { return macFallback(mac), "mac" })
	defer stopRunner(t, r)
	// 上游 wlan0(ifindex 3)上的路由器
	src.ch <- []neigh.Entry{{IfIndex: 3, IP: net.ParseIP("192.168.1.1"), MAC: "02:00:00:00:01:01", State: 0x02}}
	time.Sleep(600 * time.Millisecond) // 让写者有机会(错误地)写出
	if b, err := os.ReadFile(m4DevicesJSON); err == nil && strings.Contains(string(b), "02:00:00:00:01:01") {
		t.Fatalf("网卡还没认出来时收了上游邻居: %s", b)
	}
	known.Store(true)
	src.ch <- []neigh.Entry{{IfIndex: 7, IP: net.ParseIP("192.168.43.101"), MAC: "02:5a:00:00:00:01", State: 0x02}}
	got, ok := waitDevices(t, 3*time.Second, func(s string) bool { return strings.Contains(s, "02:5a:00:00:00:01") })
	if !ok || strings.Contains(got, "02:00:00:00:01:01") {
		t.Fatalf("认出网卡后只收热点网卡的设备, 得 %q", got)
	}
}

// 审查修复 8(接线): 主循环探测到热点没开 → 停 Go 写者(原来写者照样每 200ms 醒一次)。
func TestHotspotDownStopsRunner(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 10, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)
	rec.probeRC, rec.probeOut = 1, "" // 热点关了
	fr := fakeRunner("wlan0", false)
	m4Owner.runner = fr
	ls := newLoopState()
	ls.tick(wdState{kind: stateActive, iface: "wlan0"})
	select {
	case <-fr.doneCh:
	default:
		t.Fatal("热点没开, Go 写者应被停")
	}
	if m4Owner.runner != nil {
		t.Fatal("停了以后 runner 应为 nil")
	}
}

// 审查修复 9: 僵尸进程(已退出、还没被回收)不算活着 —— 否则被 QUIT 的 hotspotd 没被及时
// 回收时, 看门狗按 pidfile 认为它还在, 切换 / 纠偏后不重新拉起。
func TestProcessAliveZombie(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Skipf("起不了子进程: %v", err)
	}
	defer func() { _ = cmd.Wait() }()
	pid := cmd.Process.Pid
	stat := "/proc/" + strconv.Itoa(pid) + "/stat"
	deadline := time.Now().Add(3 * time.Second)
	for {
		b, _ := os.ReadFile(stat)
		if i := strings.LastIndexByte(string(b), ')'); i >= 0 && i+2 < len(b) && b[i+2] == 'Z' {
			break // 已退出, 我们还没 Wait: 僵尸
		}
		if time.Now().After(deadline) {
			t.Skip("3 秒内没看到僵尸状态")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if processAlive(pid) {
		t.Fatal("僵尸进程被当成活着")
	}
}

// 审查修复 9b: 按名字找进程(findLiveByName)同样不认僵尸 —— 被 QUIT 的 hotspotd 还没被回收
// 时, 原来被当成「活着、只是丢了 pidfile」, 修好 pidfile 就返回, 不重新拉起。
func TestFindLiveByNameSkipsZombie(t *testing.T) {
	dir := t.TempDir()
	name := "hnczombie" + strconv.Itoa(os.Getpid()%1000)
	bin := filepath.Join(dir, name)
	if err := os.Symlink("/bin/true", bin); err != nil {
		t.Skipf("建不了符号链接: %v", err)
	}
	cmd := exec.Command(bin)
	if err := cmd.Start(); err != nil {
		t.Skipf("起不了子进程: %v", err)
	}
	defer func() { _ = cmd.Wait() }()
	pid := cmd.Process.Pid
	deadline := time.Now().Add(3 * time.Second)
	for {
		b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if i := strings.LastIndexByte(string(b), ')'); i >= 0 && i+2 < len(b) && b[i+2] == 'Z' {
			break
		}
		if time.Now().After(deadline) {
			t.Skip("3 秒内没看到僵尸状态")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := findLiveByName(name); got == pid {
		t.Fatalf("按名字找到了僵尸进程 %d", pid)
	}
}
