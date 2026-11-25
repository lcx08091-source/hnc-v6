// m4_owner_review_test.go — v5.31 审查修复的回归用例(每条在审查前的代码上都失败,
// 见提交说明)。外部世界(hotspotd 控制、订阅、dump、命令)全部注入, 路径在临时目录。
package main

import (
	"context"
	"encoding/json"
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

	"hnc.io/dpid/activity"
	"hnc.io/dpid/devname"
	"hnc.io/dpid/devscan"
	"hnc.io/dpid/neigh"
)

// newStubM4Runner 构造全内存隔离的轻量 M4 写者桩: 不开真实内核 Netlink 套接字、
// 不扫宿主网卡、不执行真实 sh bin/iptables_manager.sh 或 mdns_resolve。
func newStubM4Runner(iface string) *m4GoRunner {
	r := newM4GoRunner(iface)
	r.subscribeFn = func() (m4NeighSource, error) {
		return &fakeNeighSource{ch: make(chan []neigh.Entry), stop: make(chan struct{})}, nil
	}
	r.dumpIfFn = func(int) ([]neigh.Entry, error) { return nil, nil }
	r.ifIndexFn = func(string) (int, error) { return 0, os.ErrNotExist }
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.blacklistFn = func() map[string]bool { return nil }
	r.hooks.Fast = func(mac string) (string, string) { return macFallback(mac), "mac" }
	r.hooks.Full = func(mac, ip string) (string, string) { return macFallback(mac), "mac" }
	r.applyHooks()
	return r
}

// withTempM4Writer 预算与主循环类测试用: 全局 m4Writer 与 newM4RunnerFn 换成隔离桩(测试结束停掉并恢复),
// 路径进临时目录 —— 不碰真实 /data/local/hnc、不开真实 Netlink 套接字、不跑真实外部脚本。
func withTempM4Writer(t *testing.T) {
	t.Helper()
	m4TestEnv(t)
	oldWriter := m4Writer
	oldNewRunner := newM4RunnerFn
	m4Writer = &m4WriterMgr{}
	newM4RunnerFn = newStubM4Runner
	t.Cleanup(func() {
		m4Writer.hotspotDown()
		m4Writer = oldWriter
		newM4RunnerFn = oldNewRunner
	})
}

// fakeRunner 一个只会「被停」的写者(看 stop 有没有被调)。
func fakeRunner(iface string) *m4GoRunner {
	r := &m4GoRunner{iface: iface, stopCh: make(chan struct{}), doneCh: make(chan struct{})}
	go func() { <-r.stopCh; close(r.doneCh) }()
	return r
}

// startTestRunner 起一个全注入的写者(订阅 / dump / 网卡 / 命令都是假的)。
func startTestRunner(t *testing.T, dump func() []neigh.Entry, idx func() (int, error), full func(mac, ip string) (string, string)) (*m4GoRunner, *fakeNeighSource) {
	t.Helper()
	r := newM4GoRunner("wlan2")
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
			return []neigh.Entry{{IfIndex: 7, IP: net.ParseIP("192.168.43.101"), MAC: "02:5a:00:00:00:01", State: neigh.NUDStale}}
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
	src.ch <- []neigh.Entry{{IfIndex: 7, IP: net.ParseIP("192.168.43.101"), MAC: "02:5a:00:00:00:01", State: neigh.NUDReachable}}
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
	src.ch <- []neigh.Entry{{IfIndex: 7, IP: net.ParseIP("192.168.43.101"), MAC: "02:5a:00:00:00:01", State: neigh.NUDReachable}}
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
	src.ch <- []neigh.Entry{{IfIndex: 3, IP: net.ParseIP("192.168.1.1"), MAC: "02:00:00:00:01:01", State: neigh.NUDReachable}}
	time.Sleep(600 * time.Millisecond) // 让写者有机会(错误地)写出
	if b, err := os.ReadFile(m4DevicesJSON); err == nil && strings.Contains(string(b), "02:00:00:00:01:01") {
		t.Fatalf("网卡还没认出来时收了上游邻居: %s", b)
	}
	known.Store(true)
	src.ch <- []neigh.Entry{{IfIndex: 7, IP: net.ParseIP("192.168.43.101"), MAC: "02:5a:00:00:00:01", State: neigh.NUDReachable}}
	got, ok := waitDevices(t, 3*time.Second, func(s string) bool { return strings.Contains(s, "02:5a:00:00:00:01") })
	if !ok || strings.Contains(got, "02:00:00:00:01:01") {
		t.Fatalf("认出网卡后只收热点网卡的设备, 得 %q", got)
	}
}

// 审查修复 8(接线): 主循环探测到热点没开 → 停 Go 写者、写回 PENDING 并落盘在线时长。
func TestHotspotDownStopsRunner(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 10, 12, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)
	var saved wdState
	savedCalled := false
	oldWrite := writeStateFn
	writeStateFn = func(s wdState) {
		saved = s
		savedCalled = true
	}
	t.Cleanup(func() { writeStateFn = oldWrite })
	rec.probeRC, rec.probeOut = 1, "" // 热点关了
	fr := fakeRunner("wlan0")
	m4Writer.runner = fr
	ls := newLoopState()
	ls.tick(wdState{kind: stateActive, iface: "wlan0"})
	select {
	case <-fr.doneCh:
	default:
		t.Fatal("热点没开, Go 写者应被停")
	}
	if m4Writer.runner != nil {
		t.Fatal("停了以后 runner 应为 nil")
	}
	if !savedCalled || saved.kind != statePending {
		t.Fatalf("热点关闭后应写回 PENDING 状态, got called=%v state=%+v", savedCalled, saved)
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
	truePath := ""
	for _, cand := range []string{"/system/bin/true", "/bin/true", "/usr/bin/true"} {
		if _, err := os.Stat(cand); err == nil {
			truePath = cand
			break
		}
	}
	if truePath == "" {
		if p, err := exec.LookPath("true"); err == nil && p != "" {
			truePath = p
		}
	}
	if truePath == "" {
		t.Skip("找不到 true 可执行文件")
	}
	if err := os.Symlink(truePath, bin); err != nil {
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

func TestDevnameResolveContextSkipsExternalOnCancel(t *testing.T) {
	dir := t.TempDir()
	var called atomic.Int32
	r := &devname.Resolver{
		NamesPath:     filepath.Join(dir, "device_names.json"),
		CachePath:     filepath.Join(dir, "hostname_cache.json"),
		OverridesPath: filepath.Join(dir, "oui_overrides.json"),
		RunDumpsys: func() ([]byte, error) {
			called.Add(1)
			return []byte("02:5a:00:00:00:01 hostname: dhcp-dev\n"), nil
		},
		RunMDNS: func(string) ([]byte, error) {
			called.Add(1)
			return []byte("mdns-dev\n"), nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hn, src := r.ResolveContext(ctx, "02:5a:00:00:00:01", "192.168.43.10")
	if called.Load() != 0 {
		t.Fatalf("已取消的 ctx 不应触发外部解析, called=%d", called.Load())
	}
	if hn != "00000001" || src != "mac" {
		t.Fatalf("期望兜底 MAC, 得 %q %q", hn, src)
	}
}

func TestM4InitialEmptyFullSyncClearsZombieDevicesJSON(t *testing.T) {
	m4TestEnv(t)
	zombie := `{"02:de:ad:be:ef:01":{"ip":"192.168.43.99","mac":"02:de:ad:be:ef:01","hostname":"old-zombie","hostname_src":"dhcp","iface":"wlan2","rx_bytes":0,"tx_bytes":0,"status":"allowed","last_seen":1700000000}}`
	if err := os.WriteFile(m4DevicesJSON, []byte(zombie), 0o644); err != nil {
		t.Fatal(err)
	}
	r, _ := startTestRunner(t,
		func() []neigh.Entry { return nil },
		func() (int, error) { return 7, nil },
		func(mac, ip string) (string, string) { return macFallback(mac), "mac" })
	defer stopRunner(t, r)
	if got, ok := waitDevices(t, 2*time.Second, func(s string) bool { return strings.TrimSpace(s) == "{}" }); !ok {
		t.Fatalf("首轮 0 客户端全量扫应覆写 {} 清掉旧僵尸, 得 %q", got)
	}
}

func TestM4StartupUnackedRefreshNotSwallowed(t *testing.T) {
	m4TestEnv(t)
	// 启动写者前先写入未回执的首屏刷新请求
	if err := os.WriteFile(m4RefreshFile, []byte("boot-scan-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, _ := startTestRunner(t,
		func() []neigh.Entry {
			return []neigh.Entry{{IfIndex: 7, IP: net.ParseIP("192.168.43.22"), MAC: "02:5a:00:00:00:22", State: neigh.NUDReachable}}
		},
		func() (int, error) { return 7, nil },
		func(mac, ip string) (string, string) { return "boot-dev", "manual" })
	defer stopRunner(t, r)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if b, err := os.ReadFile(m4RefreshAckFile); err == nil && strings.TrimSpace(string(b)) == "boot-scan-1" {
			return
		}
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(m4RefreshAckFile)
			t.Fatalf("启动前写入的未回执刷新请求被吞掉, ack=%q", b)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestM4RefreshUnconditionallyRefreshesIfaceAndGatesAck(t *testing.T) {
	m4TestEnv(t)
	var curIfIdx atomic.Int32
	curIfIdx.Store(7)
	var failDump atomic.Bool
	failDump.Store(false)

	r := newM4GoRunner("wlan2")
	src := &fakeNeighSource{ch: make(chan []neigh.Entry, 8), stop: make(chan struct{})}
	r.subscribeFn = func() (m4NeighSource, error) { return src, nil }
	r.ifIndexFn = func(string) (int, error) { return int(curIfIdx.Load()), nil }
	r.dumpIfFn = func(idx int) ([]neigh.Entry, error) {
		if failDump.Load() {
			return nil, errors.New("simulated dump error")
		}
		if idx == 12 {
			return []neigh.Entry{{IfIndex: 12, IP: net.ParseIP("192.168.43.12"), MAC: "02:5a:00:00:00:12", State: neigh.NUDReachable}}, nil
		}
		return nil, nil
	}
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.blacklistFn = func() map[string]bool { return nil }
	r.hooks.Fast = func(mac string) (string, string) { return "rebuilt-dev", "manual" }
	r.hooks.Full = func(mac, ip string) (string, string) { return "rebuilt-dev", "manual" }
	r.applyHooks()
	r.start()
	defer stopRunner(t, r)

	if _, ok := waitDevices(t, 2*time.Second, func(s string) bool { return strings.TrimSpace(s) == "{}" }); !ok {
		t.Fatal("首轮应落盘 {}")
	}

	// 1. dump 失败时不得写 ack
	failDump.Store(true)
	if err := os.WriteFile(m4RefreshFile, []byte("fail-nonce\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(450 * time.Millisecond)
	if b, err := os.ReadFile(m4RefreshAckFile); err == nil && strings.TrimSpace(string(b)) == "fail-nonce" {
		t.Fatalf("dump 失败时不应写回执: %q", b)
	}

	// 2. 同名网卡重建(ifindex 7 -> 12, 非 0!)后恢复 dump: refreshDue 应无条件刷 refreshIface 并回执
	curIfIdx.Store(12)
	failDump.Store(false)
	if err := os.WriteFile(m4RefreshFile, []byte("rebuild-nonce\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if b, err := os.ReadFile(m4RefreshAckFile); err == nil && strings.TrimSpace(string(b)) == "rebuild-nonce" {
			devBytes, _ := os.ReadFile(m4DevicesJSON)
			if !strings.Contains(string(devBytes), "02:5a:00:00:00:12") {
				t.Fatalf("同名重建 ifindex=12 设备未写入: %s", devBytes)
			}
			return
		}
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(m4RefreshAckFile)
			t.Fatalf("未收到 rebuild-nonce 回执, ack=%q", b)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestM4StopTimeoutCapAllowsOnExitFlush(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 11, 21, 14, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)

	oldWait := m4StopWaitMax
	m4StopWaitMax = 150 * time.Millisecond
	t.Cleanup(func() { m4StopWaitMax = oldWait })

	// 构造一个 doneCh 永不关闭的卡死写者
	stuck := &m4GoRunner{iface: "wlan2", stopCh: make(chan struct{}), doneCh: make(chan struct{})}
	m4Writer.mu.Lock()
	m4Writer.runner = stuck
	m4Writer.mu.Unlock()

	setDevices(t, onlineAcc, clk.now, macA)
	onlineAcc.sample(clk.now)

	t0 := time.Now()
	onExit()
	if elapsed := time.Since(t0); elapsed > 1500*time.Millisecond {
		t.Fatalf("onExit 超时兜底未生效, 耗时 %v", elapsed)
	}
	lines := readLines(t, onlineAcc.file)
	if len(lines) != 1 || !strings.Contains(lines[0], macA) {
		t.Fatalf("停机兜底后应执行 onlineAcc.flush(), 得 %v", lines)
	}
}

func TestM4StopSkipsBlockingStatsAll(t *testing.T) {
	m4TestEnv(t)
	var statsCalls atomic.Int32
	r := newM4GoRunner("wlan2")
	src := &fakeNeighSource{ch: make(chan []neigh.Entry, 8), stop: make(chan struct{})}
	r.subscribeFn = func() (m4NeighSource, error) { return src, nil }
	r.dumpIfFn = func(int) ([]neigh.Entry, error) { return nil, nil }
	r.ifIndexFn = func(string) (int, error) { return 7, nil }
	r.statsCmdFn = func() (map[string][2]int64, error) {
		statsCalls.Add(1)
		return map[string][2]int64{}, nil
	}
	r.blacklistFn = func() map[string]bool { return nil }
	r.hooks.Fast = func(mac string) (string, string) { return "tv", "manual" }
	r.hooks.Full = func(mac, ip string) (string, string) { return "tv", "manual" }
	r.applyHooks()
	r.start()

	if _, ok := waitDevices(t, 2*time.Second, func(s string) bool { return strings.TrimSpace(s) == "{}" }); !ok {
		t.Fatal("首轮应落盘")
	}
	beforeStop := statsCalls.Load()
	// 注入脏事件后立即停机: 停机 writeOut(force=false) 且 stopping=true 不得再次调用 statsCmdFn
	src.ch <- []neigh.Entry{{IfIndex: 7, IP: net.ParseIP("192.168.43.88"), MAC: "02:5a:00:00:00:88", State: neigh.NUDReachable}}
	time.Sleep(30 * time.Millisecond)
	stopRunner(t, r)
	if after := statsCalls.Load(); after != beforeStop {
		t.Fatalf("停机落盘不应再调 statsCmdFn: before=%d after=%d", beforeStop, after)
	}
}

func TestIsDozeZeroForkBatteryAndQuiet(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 11, 21, 15, 0, 0, 0, time.Local)}
	rec := newActionRec()
	withFakeEnv(t, clk, rec)

	capFile := filepath.Join(t.TempDir(), "capacity")
	oldCapFn := batteryCapPathFn
	batteryCapPathFn = func() string { return capFile }
	t.Cleanup(func() {
		batteryCapPathFn = oldCapFn
		dozeCacheMu.Lock()
		dozeCheckTS = time.Time{}
		dozeCached = false
		dozeCacheMu.Unlock()
	})
	resetDozeCache := func() {
		dozeCacheMu.Lock()
		dozeCheckTS = time.Time{}
		dozeCached = false
		dozeCacheMu.Unlock()
	}

	// 1. 熄屏静默(Quiet=true) -> 直接 true, 0 fork
	actSnapshotFn = func() activity.Snapshot {
		return activity.Snapshot{OK: true, Level: activity.LevelBackground, Quiet: true}
	}
	if !isDoze() {
		t.Fatal("activity Quiet=true 时 isDoze 应返回 true")
	}

	// 2. 亮屏且电量 80% -> false
	actSnapshotFn = func() activity.Snapshot {
		return activity.Snapshot{OK: true, Level: activity.LevelActive, Quiet: false}
	}
	_ = os.WriteFile(capFile, []byte("80\n"), 0o644)
	resetDozeCache()
	if isDoze() {
		t.Fatal("亮屏且电量 80% 时不应为 Doze")
	}

	// 3. 电量 4% (<5%) -> true(保留低电降频)
	_ = os.WriteFile(capFile, []byte("4\n"), 0o644)
	clk.now = clk.now.Add(31 * time.Second)
	if !isDoze() {
		t.Fatal("电量 <5% 时应触发低电降频")
	}

	if rec.counts["is_doze"] != 0 {
		t.Fatalf("isDoze 必须纯 Go 0-fork, 但调用了 %d 次 runAction(is_doze)", rec.counts["is_doze"])
	}
}

func TestHandleActiveMigrateFailureStopsM4Writer(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 11, 21, 16, 0, 0, 0, time.Local)}
	rec := newActionRec()
	rec.probeOut = "ap0 192.168.43.1\n"
	rec.rc["migrate"] = 1
	withFakeEnv(t, clk, rec)

	fr := fakeRunner("wlan2")
	m4Writer.mu.Lock()
	m4Writer.runner = fr
	m4Writer.mu.Unlock()

	handleActive("wlan2", &restoreThrottle{}, &activeAux{})
	select {
	case <-fr.doneCh:
	case <-time.After(time.Second):
		t.Fatal("migrate 失败后应停掉旧网卡上的 m4Writer")
	}
	if m4Writer.runner != nil {
		t.Fatal("migrate 失败后 runner 应置空")
	}
}

func TestOnlineMinutesRollbackFlushFailAndHotspotDown(t *testing.T) {
	a := withTempOnlineAcc(t)
	t0 := time.Date(2026, 11, 21, 10, 0, 0, 0, cst)
	setDevices(t, a, t0, macA)
	a.sample(t0) // 首次记 5 分钟
	if got := a.pending[onlineKey{"20261121", macA}]; got != 5 {
		t.Fatalf("首次采样应为 5 分钟, 得 %d", got)
	}

	// 时钟回拨 3 分钟: 重置 a.last, 绝不白送 5 分钟
	tBack := t0.Add(-3 * time.Minute)
	setDevices(t, a, tBack, macA)
	a.sample(tBack)
	if got := a.pending[onlineKey{"20261121", macA}]; got != 5 {
		t.Fatalf("时钟回拨不应白送分钟, 得 %d", got)
	}
	if !a.last.Equal(tBack) {
		t.Fatalf("时钟回拨应重置 a.last=%v, 得 %v", tBack, a.last)
	}

	// 写入失败不得推进 a.flushed
	badFile := filepath.Join(t.TempDir(), "missing-dir", "online_hours.jsonl")
	goodFile := a.file
	a.file = badFile
	prevFlushed := a.flushed
	a.flush(t0.Add(time.Hour))
	if !a.flushed.Equal(prevFlushed) {
		t.Fatalf("写失败不应推进 a.flushed: prev=%v cur=%v", prevFlushed, a.flushed)
	}

	// 恢复文件路径后调 hotspotDown: 落盘并清空 a.last
	a.file = goodFile
	a.hotspotDown(t0.Add(time.Hour))
	if !a.last.IsZero() {
		t.Fatalf("hotspotDown 后应重置 a.last, 得 %v", a.last)
	}
	if len(a.pending) != 0 {
		t.Fatalf("hotspotDown 落盘后应清空 pending: %v", a.pending)
	}
	if lines := readLines(t, goodFile); len(lines) != 1 {
		t.Fatalf("hotspotDown 应落盘 1 行, 得 %v", lines)
	}
}

func TestAppLimitHasWorkAndNextWait(t *testing.T) {
	dataTmp, runTmp := t.TempDir(), t.TempDir()
	if appLimitHasWork(dataTmp, runTmp) {
		t.Fatal("空目录不应判定 hasWork")
	}
	if got := appLimitNextWait(true, false, false, 0); got != appLimitIdlePoll {
		t.Fatalf("热点空闲应放宽至 %v, 得 %v", appLimitIdlePoll, got)
	}
	if got := appLimitNextWait(false, false, true, 0); got != appLimitEmptyQuietPoll {
		t.Fatalf("空配置且静默应放宽至 %v, 得 %v", appLimitEmptyQuietPoll, got)
	}
	if got := appLimitNextWait(false, false, false, 0); got != appLimitDirtyPollFast {
		t.Fatalf("空配置且亮屏应 3s stat, 得 %v", got)
	}
	if err := os.WriteFile(filepath.Join(dataTmp, "app_limits.flat"), []byte("aa:bb:cc:dd:ee:01 game 1000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !appLimitHasWork(dataTmp, runTmp) {
		t.Fatal("app_limits.flat 非空应判定 hasWork")
	}
	if got := appLimitNextWait(false, true, true, 0); got != appLimitApplyEvery {
		t.Fatalf("有配置且静默应 30s 周期, 得 %v", got)
	}
}

func TestSleepOrWakeDebounceShortensInsteadOfDropping(t *testing.T) {
	oldLast := lastEventRound
	t.Cleanup(func() { lastEventRound = oldLast })
	// 清空可能残留的 linkWake
	select {
	case <-linkWake:
	default:
	}
	// 距离上次事件 4.85s (还在 5s 防抖期内, 剩余 150ms)
	lastEventRound = time.Now().Add(-eventMinGap + 150*time.Millisecond)
	go func() {
		time.Sleep(20 * time.Millisecond)
		wakeMain()
	}()
	t0 := time.Now()
	ok, woken := sleepOrWake(30 * time.Second)
	took := time.Since(t0)
	if !ok || !woken {
		t.Fatalf("防抖期内事件应被延后交付而非丢弃: ok=%v woken=%v", ok, woken)
	}
	if took > 4*time.Second {
		t.Fatalf("应缩短 30s 睡眠至防抖期满+settle, 实测耗时 %v", took)
	}
}

func TestNativeExecCommandTimeoutKillsPgrp(t *testing.T) {
	oldTimeout := nativeExecTimeout
	nativeExecTimeout = 200 * time.Millisecond
	t.Cleanup(func() { nativeExecTimeout = oldTimeout })

	t0 := time.Now()
	_, rc, err := execCommandFn(shellPath(), "-c", "sleep 10")
	took := time.Since(t0)
	if rc != -1 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("超时应返回 rc=-1 + DeadlineExceeded, 得 rc=%d err=%v", rc, err)
	}
	if took > 3*time.Second {
		t.Fatalf("超时回收过慢: %v", took)
	}
}

func TestDevscanReResolveCooldownAndNoDowngrade(t *testing.T) {
	tb := devscan.NewTable("wlan2", 7)
	tb.Fast = func(mac string) (string, string) { return macFallback(mac), "mac" }
	t0 := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	mac := "02:5a:00:00:00:55"
	e := neigh.Entry{IfIndex: 7, IP: net.ParseIP("192.168.43.55"), MAC: mac, State: neigh.NUDReachable}

	// 1. 首次上线 -> pending -> 解析结果为 mac 兜底
	tb.Apply(e, t0)
	if !tb.ApplyResolution(mac, "00000055", "mac", t0.Add(2*time.Second)) {
		t.Fatal("首次回填 mac 应成功")
	}
	// 5 秒内再收 ARP 事件: 不得因 HostnameSrc=="mac" 绕过 60s 冷却
	tb.Apply(e, t0.Add(5*time.Second))
	if tb.HasPending() {
		t.Fatal("mac 兜底在 60s 冷却期内不应重新触发 pending")
	}

	// 2. 升级为有效主机名 dhcp 后, 满 60s 收到 ARP 事件不得降级为 pending / MAC 兜底
	if !tb.ApplyResolution(mac, "LivingRoom-TV", "dhcp", t0.Add(10*time.Second)) {
		t.Fatal("升级为 dhcp 主机名应成功")
	}
	tb.Apply(e, t0.Add(80*time.Second))
	var got map[string]devscan.Device
	if err := json.Unmarshal(tb.RenderJSON(nil, nil), &got); err != nil {
		t.Fatal(err)
	}
	if d := got[mac]; d.Hostname != "LivingRoom-TV" || d.HostnameSrc != "dhcp" {
		t.Fatalf("满 60s 重扫不得降级已有有效主机名, 得 %+v", d)
	}
	// 即使外部回填低优先级 mac 兜底也不得覆盖已有有效主机名
	if tb.ApplyResolution(mac, "00000055", "mac", t0.Add(85*time.Second)) {
		t.Fatal("ApplyResolution 不得用低优先级 mac 降级已有有效主机名")
	}
	if err := json.Unmarshal(tb.RenderJSON(nil, nil), &got); err != nil {
		t.Fatal(err)
	}
	if d := got[mac]; d.Hostname != "LivingRoom-TV" || d.HostnameSrc != "dhcp" {
		t.Fatalf("有效主机名被降级: %+v", d)
	}
}

func TestM4ReaderCoroutinePreFiltersNonHotspotNDPByDynamicIfIdx(t *testing.T) {
	es := []neigh.Entry{
		{IfIndex: 21, IP: net.ParseIP("fe80::1"), MAC: "02:00:00:00:00:01", State: neigh.NUDReachable},
		{IfIndex: 7, IP: net.ParseIP("192.168.43.10"), MAC: "02:5a:00:00:00:10", State: neigh.NUDReachable},
		{IfIndex: 22, IP: net.ParseIP("2409:8a00::99"), MAC: "02:00:00:00:00:02", State: neigh.NUDStale},
	}
	// ifIdx=0 未知时不误拦
	if got := filterHotspotNeighEvents(append([]neigh.Entry(nil), es...), 0); len(got) != 3 {
		t.Fatalf("ifIdx=0 时不应预筛丢包, got=%d", len(got))
	}
	// ifIdx=7 时仅放行热点口事件
	got7 := filterHotspotNeighEvents(append([]neigh.Entry(nil), es...), 7)
	if len(got7) != 1 || got7[0].IfIndex != 7 {
		t.Fatalf("ifIdx=7 预筛异常: %+v", got7)
	}
	// 全蜂窝 NDP 批次预筛后为空切片(读协程直接 continue 零唤醒主循环)
	cellOnly := []neigh.Entry{
		{IfIndex: 21, IP: net.ParseIP("fe80::1"), MAC: "02:00:00:00:00:01", State: neigh.NUDReachable},
	}
	if gotCell := filterHotspotNeighEvents(cellOnly, 7); len(gotCell) != 0 {
		t.Fatalf("纯蜂窝口事件应被预筛为空, got=%+v", gotCell)
	}
}

func TestM4StopCancelsFirstGenerationLockAndIdempotentHotspotDownZeroing(t *testing.T) {
	m4TestEnv(t)

	// 1. 验证 Stop() 先调 stopCancel() 立即取消 stopCtx
	r1 := newStubM4Runner("wlan2")
	r1.Stop()
	if r1.stopCtx.Err() == nil {
		t.Fatal("r.Stop() 必须立即触发 stopCancel()")
	}
	r1.Stop() // 验证并发/重复调用幂等无 panic

	// 2. 验证代际写锁: 旧代际 runner 尝试晚到写盘被拦截, 绝不覆盖新代际数据
	rOld := newStubM4Runner("wlan2")
	rOld.table.Apply(neigh.Entry{IfIndex: 7, IP: net.ParseIP("192.168.43.88"), MAC: "02:5a:00:00:00:88", State: neigh.NUDReachable}, time.Now())
	rNew := newStubM4Runner("wlan2")
	rNew.table.Fast = func(string) (string, string) { return "new-dev", "manual" }
	rNew.table.Apply(neigh.Entry{IfIndex: 7, IP: net.ParseIP("192.168.43.99"), MAC: "02:5a:00:00:00:99", State: neigh.NUDReachable}, time.Now())
	if err := rNew.writeDevicesAtomic(rNew.table.RenderJSON(nil, nil)); err != nil {
		t.Fatalf("新代际写入应成功: %v", err)
	}
	if err := rOld.writeDevicesAtomic(rOld.table.RenderJSON(nil, nil)); !errors.Is(err, errM4StaleGen) {
		t.Fatalf("旧代际重叠写应被拦截并返回 errM4StaleGen, got %v", err)
	}
	b, err := os.ReadFile(m4DevicesJSON)
	if err != nil || !strings.Contains(string(b), "192.168.43.99") || strings.Contains(string(b), "192.168.43.88") {
		t.Fatalf("旧代际不得污染新代际 devices.json: %s (err=%v)", b, err)
	}

	// 3. 验证关热点幂等归零非空在线态, 且待机已空时反复调 hotspotDown() 零写盘
	mgr := &m4WriterMgr{}
	mgr.hotspotDown()
	afterDown, err := os.ReadFile(m4DevicesJSON)
	if err != nil || strings.TrimSpace(string(afterDown)) != "{}" {
		t.Fatalf("关热点后非空 devices.json 应被归零为 {}, got %q err=%v", afterDown, err)
	}
	flatAfter, _ := os.ReadFile(m4DevicesFlat)
	if len(flatAfter) != 0 {
		t.Fatalf("关热点后 devices.flat 应归零为空, got %q", flatAfter)
	}

	writesBeforeIdle := m4GoWrites.Load()
	fiBefore, err := os.Stat(m4DevicesJSON)
	if err != nil {
		t.Fatal(err)
	}
	mgr.hotspotDown()
	mgr.tick("", time.Now())
	writesAfterIdle := m4GoWrites.Load()
	fiAfter, err := os.Stat(m4DevicesJSON)
	if err != nil {
		t.Fatal(err)
	}
	if writesAfterIdle != writesBeforeIdle || !os.SameFile(fiBefore, fiAfter) {
		t.Fatalf("待机已空时应零写盘: writes %d -> %d", writesBeforeIdle, writesAfterIdle)
	}
}

func TestM4SameIfaceRebuildUpdatesAtomicIfIdxWithout30sBlindness(t *testing.T) {
	m4TestEnv(t)

	var curIfIdx atomic.Int32
	curIfIdx.Store(7)

	r, src := startTestRunner(
		t,
		func() []neigh.Entry { return nil },
		func() (int, error) { return int(curIfIdx.Load()), nil },
		func(mac, ip string) (string, string) { return "rebuilt-client", "dhcp" },
	)
	defer stopRunner(t, r)

	if _, ok := waitDevices(t, 2*time.Second, func(s string) bool { return strings.TrimSpace(s) == "{}" }); !ok {
		t.Fatal("initial empty devices.json should be written")
	}

	// Same hotspot interface name "wlan2" recreated by kernel with new ifindex 19 (no 30s full-sync yet).
	curIfIdx.Store(19)
	mgr := &m4WriterMgr{runner: r}
	mgr.tick("wlan2", time.Now())
	if got := r.atomicIfIdx.Load(); got != 19 {
		t.Fatalf("ensureGoRunnerLocked must atomically update atomicIfIdx to 19, got %d", got)
	}
	if _, tblIdx := r.table.Iface(); tblIdx != 19 {
		t.Fatalf("table.SetIface must update ifindex to 19, got %d", tblIdx)
	}

	// Simulate another rapid rebuild to ifindex 23 arriving first on the neighbor subscription stream before tick!
	curIfIdx.Store(23)
	src.ch <- []neigh.Entry{{
		IfIndex: 23,
		IP:      net.ParseIP("192.168.43.77"),
		MAC:     "02:5a:00:00:00:77",
		State:   neigh.NUDReachable,
	}}

	if _, ok := waitDevices(t, 2*time.Second, func(s string) bool { return strings.Contains(s, "192.168.43.77") }); !ok {
		b, _ := os.ReadFile(m4DevicesJSON)
		t.Fatalf("neighbor event on rebuilt ifindex=23 must not be dropped (30s blindness): %s", b)
	}
	if got := r.atomicIfIdx.Load(); got != 23 {
		t.Fatalf("subscription reader should atomically sync atomicIfIdx to 23, got %d", got)
	}
	mgr.runner = nil
}

