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

// withTempM4Writer 预算类测试用: 全局 m4Writer 换成新的(测试结束停掉并恢复),
// 路径进临时目录 —— 不碰真实 /data/local/hnc。
func withTempM4Writer(t *testing.T) {
	t.Helper()
	m4TestEnv(t)
	old := m4Writer
	m4Writer = &m4WriterMgr{}
	t.Cleanup(func() {
		m4Writer.hotspotDown()
		m4Writer = old
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
