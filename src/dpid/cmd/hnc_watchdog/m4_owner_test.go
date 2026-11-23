// m4_owner_test.go — 设备发现写者单测(v5.31 起): 去抖纯函数、生命周期、写出路径、
// 「立刻扫一次」与回执。路径 / 订阅 / 命令全部注入, 不碰真文件(临时目录)、真 socket。
// (v5.33: 写者开关 / 切换 / 默认值退路 / 演练的用例随功能一起删了。)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"hnc.io/dpid/neigh"
)

// m4TestEnv 重定向所有路径到临时目录(测试结束全部恢复)。
// v5.31 审查修复 / v6.0 RC2: 含 devices.flat、dpi_devid.json、stats_v6_map、
// stats_v6_retired、proc_net_arp 与 iptables 执行钩子一并隔离 —— 绝不碰真实宿主环境。
func m4TestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ptrs := []*string{
		&m4DevicesJSON, &m4DevicesTmpGo, &m4DevicesFlat,
		&m4RefreshFile, &m4RefreshAckFile, &m4GoWriteLog,
		&m4NamesPath, &m4DevIDPath, &m4CachePath, &m4OverridesPath, &m4MDNSBin,
		&m4StatsV6Map, &m4StatsV6Retired, &m4ProcNetARP,
		&rulesJSONPath, &iptablesMgrPath,
	}
	old := make([]string, len(ptrs))
	for i, p := range ptrs {
		old[i] = *p
	}
	oldIptFn := m4IptablesExecFn
	oldNlDumpFn := m4NetlinkDumpIfFn
	oldPermBackoff := m4PermErrBackoff
	t.Cleanup(func() {
		for i, p := range ptrs {
			*p = old[i]
		}
		m4IptablesExecFn = oldIptFn
		m4NetlinkDumpIfFn = oldNlDumpFn
		m4PermErrBackoff = oldPermBackoff
	})
	m4DevicesJSON = filepath.Join(dir, "devices.json")
	m4DevicesTmpGo = filepath.Join(dir, "devices.json.tmp.go")
	m4DevicesFlat = filepath.Join(dir, "run", "devices.flat")
	m4RefreshFile = filepath.Join(dir, "run", "devices.refresh")
	m4RefreshAckFile = filepath.Join(dir, "run", "devices.refresh.ack")
	m4GoWriteLog = filepath.Join(dir, "run", "m4_go_write.log")
	m4NamesPath = filepath.Join(dir, "device_names.json")
	m4DevIDPath = filepath.Join(dir, "run", "dpi_devid.json")
	m4CachePath = filepath.Join(dir, "hostname_cache.json")
	m4OverridesPath = filepath.Join(dir, "oui_overrides.json")
	m4MDNSBin = filepath.Join(dir, "no_mdns_resolve")
	m4StatsV6Map = filepath.Join(dir, "run", "stats_v6_map")
	m4StatsV6Retired = filepath.Join(dir, "run", "stats_v6_retired")
	m4ProcNetARP = filepath.Join(dir, "run", "proc_net_arp")
	rulesJSONPath = filepath.Join(dir, "rules.json")
	iptablesMgrPath = filepath.Join(dir, "bin", "no_iptables_manager.sh")
	m4IptablesExecFn = func(context.Context, string, ...string) (string, string, int, error) {
		return "", "isolated", -1, os.ErrNotExist
	}
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	return dir
}

func TestM4ShouldWrite(t *testing.T) {
	// rc30.9(hotspotd.c 主循环): 首写立即; 空闲 ≥500ms 立即; 合并窗口
	// 200ms 无新事件; 30s 兜底; <200ms 硬限速。
	cases := []struct {
		name                                  string
		firstDirty, lastEvent, lastWrite, now int64
		want                                  bool
	}{
		{"无 dirty", 0, 0, 0, 1100, false},
		{"首次写", 1000, 1000, 0, 1100, true},
		{"硬限速", 1000, 1050, 1000, 1100, false},
		{"空闲后首事件", 5000, 5000, 1000, 5100, true},
		{"合并窗口未满", 3000, 3100, 3000, 3150, false},
		{"合并窗口已过", 3000, 3000, 2800, 3200, true},
		{"30 秒兜底", 1000, 32950, 32800, 33000, true},
		{"未到 30 秒", 30000, 32950, 32800, 33000, false},
	}
	for _, c := range cases {
		if got := m4ShouldWrite(c.firstDirty, c.lastEvent, c.lastWrite, c.now); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// TestWriterTick v5.33: 没有开关了 —— 热点开着(iface 非空)就起写者, 网卡没变不重起,
// 热点没了就停。
func TestWriterTick(t *testing.T) {
	m4TestEnv(t)
	oldNew := newM4RunnerFn
	newM4RunnerFn = newStubM4Runner
	t.Cleanup(func() { newM4RunnerFn = oldNew })
	m := &m4WriterMgr{}
	m.tick("lo", time.Now())
	if m.runner == nil {
		t.Fatal("热点开着应起写者")
	}
	r := m.runner
	m.tick("lo", time.Now())
	if m.runner != r {
		t.Fatal("网卡没变不应重起写者")
	}
	m.tick("", time.Now())
	if m.runner != nil {
		t.Fatal("热点没了应停写者")
	}
}

// TestHotspotdDaemonArgs v5.33: hotspotd 本来就不发现了, 看门狗拉它只带 -d
// (v5.31–v5.32 写者是 Go 时带 --no-discovery)。
func TestHotspotdDaemonArgs(t *testing.T) {
	if got := hotspotdDaemon().args; len(got) != 1 || got[0] != "-d" {
		t.Fatalf("hotspotd 参数应只有 -d: %v", got)
	}
}

func TestRunnerWriteOut(t *testing.T) {
	m4TestEnv(t)
	r := newM4GoRunner("wlan2")
	r.statsCmdFn = func() (map[string][2]int64, error) {
		return map[string][2]int64{"192.168.43.101": {111, 222}}, nil
	}
	r.blacklistFn = func() map[string]bool { return map[string]bool{} }
	r.applyHooks() // 先装钩子, 再覆盖(顺序反了会被 resolver 兜底覆盖掉)
	r.table.Fast = func(mac string) (string, string) { return "tv", "manual" }

	// 直接构造事件走 Apply
	if !r.table.Apply(neigh.Entry{IfIndex: 7, IP: net.ParseIP("192.168.43.101"), MAC: "02:5a:00:00:00:01", State: neigh.NUDReachable}, time.Now()) {
		t.Fatal("事件应生效")
	}
	statsAt := time.Time{}
	statsMap := map[string][2]int64{}
	r.writeOut(nil, &statsAt, &statsMap, true)
	b, err := os.ReadFile(m4DevicesJSON)
	if err != nil {
		t.Fatalf("devices.json 应写出: %v", err)
	}
	got := map[string]map[string]interface{}{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("输出不可解析: %v (%s)", err, b)
	}
	d := got["02:5a:00:00:00:01"]
	if d == nil || d["hostname"] != "tv" || d["hostname_src"] != "manual" || d["status"] != "allowed" {
		t.Fatalf("写出内容不对: %s", b)
	}
	if d["rx_bytes"] != float64(111) || d["tx_bytes"] != float64(222) {
		t.Fatalf("字节数不对: %s", b)
	}
	// 内容没变不写(省电)
	before := m4GoWrites.Load()
	r.writeOut(b, &statsAt, &statsMap, false)
	if m4GoWrites.Load() != before {
		t.Fatal("内容没变不应再写")
	}
}

func TestRunnerLifecycle(t *testing.T) {
	m4TestEnv(t)
	r := newM4GoRunner("wlan2")
	src := &fakeNeighSource{ch: make(chan []neigh.Entry, 8), stop: make(chan struct{})}
	r.subscribeFn = func() (m4NeighSource, error) { return src, nil }
	r.dumpIfFn = func(int) ([]neigh.Entry, error) { return nil, nil }
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.blacklistFn = func() map[string]bool { return nil }
	r.ifIndexFn = func(string) (int, error) { return 7, nil }
	r.hooks.Fast = func(mac string) (string, string) { return "tv", "manual" }
	r.hooks.Full = func(mac, ip string) (string, string) { return "tv", "manual" }
	r.applyHooks()
	r.start()
	defer func() {
		close(r.stopCh)
		select {
		case <-r.doneCh:
		case <-time.After(3 * time.Second):
			t.Fatal("写者 3 秒内没退出")
		}
	}()
	// 送一条事件, 轮询等 devices.json 出现(带超时, 不裸 sleep)
	src.ch <- []neigh.Entry{{IfIndex: 7, IP: net.ParseIP("192.168.43.109"), MAC: "02:5a:00:00:00:09", State: neigh.NUDReachable}}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if b, err := os.ReadFile(m4DevicesJSON); err == nil {
			got := map[string]map[string]interface{}{}
			if json.Unmarshal(b, &got) == nil && got["02:5a:00:00:00:09"] != nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("3 秒内 devices.json 没写出事件设备")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestRefreshTriggersFullSync v5.31 T4 / v5.33: 「立刻扫一次」—— 往 run/devices.refresh
// 写 nonce 后, 写者应在 1 秒内全量扫、写 devices.json, 然后把同一个 nonce 写进
// run/devices.refresh.ack(bin/device_detect.sh scan 等的就是它; 回执出现时 devices.json
// 必须已经是这次扫描的结果)。「改动前会失败」: v5.32 没有回执文件。
func TestRefreshTriggersFullSync(t *testing.T) {
	dir := m4TestEnv(t)
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := newM4GoRunner("wlan2")
	src := &fakeNeighSource{ch: make(chan []neigh.Entry, 8), stop: make(chan struct{})}
	r.subscribeFn = func() (m4NeighSource, error) { return src, nil }
	var dumped atomic.Int32 // 写者 goroutine 加、测试主 goroutine 读
	// 审查修复后写者一起来就全量扫一次: 闸门打开(= 发 refresh)之前 dump 返回空,
	// 设备只可能经 refresh 触发的那次全量扫出现(30 秒兜底在 2 秒内不会到)。
	var gate atomic.Bool
	r.dumpIfFn = func(int) ([]neigh.Entry, error) {
		dumped.Add(1)
		if !gate.Load() {
			return nil, nil
		}
		return []neigh.Entry{{IfIndex: 7, IP: net.ParseIP("192.168.43.109"),
			MAC: "02:5a:00:00:00:09", State: neigh.NUDReachable}}, nil
	}
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.blacklistFn = func() map[string]bool { return nil }
	r.ifIndexFn = func(string) (int, error) { return 7, nil }
	r.applyHooks()
	r.start()
	defer func() {
		close(r.stopCh)
		select {
		case <-r.doneCh:
		case <-time.After(3 * time.Second):
		}
	}()
	// 没事件、没到 30s —— 只有 refresh 能触发写出。
	// 等过第一拍(200ms), 保证文件 mtime 严格晚于 lastRefreshM(同毫秒会漏判)。
	time.Sleep(300 * time.Millisecond)
	gate.Store(true)
	if err := os.WriteFile(m4RefreshFile, []byte("scan-4242\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	for {
		if b, err := os.ReadFile(m4RefreshAckFile); err == nil && strings.TrimSpace(string(b)) == "scan-4242" {
			d, _ := os.ReadFile(m4DevicesJSON)
			if !strings.Contains(string(d), "02:5a:00:00:00:09") {
				t.Fatalf("回执出现时 devices.json 还不是这次扫描的结果: %s", d)
			}
			if took := time.Since(t0); took > 1800*time.Millisecond {
				t.Fatalf("回执用了 %v(上限 1.8 秒)", took)
			}
			return
		}
		if time.Since(t0) > 2*time.Second {
			b, _ := os.ReadFile(m4RefreshAckFile)
			t.Fatalf("写 nonce 后 2 秒内没有回执(dumped=%d ack=%q)", dumped.Load(), b)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestReadNonce 回执内容: 只取第一行、去空白、超长截断; 没有文件 = 空(hotspotd touch 的)。
func TestReadNonce(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "refresh")
	if got := readNonce(p); got != "" {
		t.Fatalf("没有文件应为空, 得 %q", got)
	}
	for in, want := range map[string]string{
		"":                      "",
		"abc\n":                 "abc",
		"  x-1 \r\nsecond\n":    "x-1",
		strings.Repeat("z", 99): strings.Repeat("z", m4NonceMax),
	} {
		if err := os.WriteFile(p, []byte(in), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := readNonce(p); got != want {
			t.Fatalf("内容 %q: 得 %q 要 %q", in, got, want)
		}
	}
}

// fakeNeighSource 假订阅源: Read 从 channel 取一批事件, Close 幂等关闭。
type fakeNeighSource struct {
	ch   chan []neigh.Entry
	stop chan struct{}
	once sync.Once
}

func (f *fakeNeighSource) Read() ([]neigh.Entry, error) {
	select {
	case es := <-f.ch:
		return es, nil
	case <-f.stop:
		return nil, os.ErrClosed
	}
}

func (f *fakeNeighSource) Close() error {
	f.once.Do(func() { close(f.stop) })
	return nil
}

// TestM4NextTickMS v5.32 T4: 主循环下一拍间隔 —— 有事(dirty / 待解析名字 /
// 在途解析)200ms, 全空闲 m4IdleTickMS(500ms)。改动前固定 200ms(m4WriteHardRateMS)。
func TestM4NextTickMS(t *testing.T) {
	busy := m4WriteHardRateMS * time.Millisecond
	idle := m4IdleTickMS * time.Millisecond
	cases := []struct {
		name                string
		dirty, pending, res bool
		want                time.Duration
	}{
		{"全空闲 → 1s", false, false, false, idle},
		{"有待写 → 200ms", true, false, false, busy},
		{"有待解析名字 → 200ms", false, true, false, busy},
		{"在途解析 → 200ms", false, false, true, busy},
		{"组合 → 200ms", true, true, true, busy},
	}
	for _, c := range cases {
		if got := m4NextTickMS(c.dirty, c.pending, c.res); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	if idle <= busy {
		t.Fatalf("空闲拍(%v)必须比忙拍(%v)慢", idle, busy)
	}
}

// TestRunnerIdleWakeRate v5.32 T4: 空闲时主循环醒来次数有上限(注入计数,
// 不靠 sleep 精确计时 —— 只数醒拍, 不数事件)。3 秒观察窗:
// 降频前固定 200ms → 15+ 次; 空闲 500ms(审查改, 见 m4IdleTickMS)→ 约 6 次 ≤ 9。
func TestRunnerIdleWakeRate(t *testing.T) {
	m4TestEnv(t)
	r := newM4GoRunner("wlan2")
	src := &fakeNeighSource{ch: make(chan []neigh.Entry, 8), stop: make(chan struct{})}
	r.subscribeFn = func() (m4NeighSource, error) { return src, nil }
	r.dumpIfFn = func(int) ([]neigh.Entry, error) { return nil, nil } // 空表: 无 pending 无 dirty
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.blacklistFn = func() map[string]bool { return nil }
	r.ifIndexFn = func(string) (int, error) { return 7, nil }
	r.hooks.Fast = func(mac string) (string, string) { return "tv", "manual" }
	r.hooks.Full = func(mac, ip string) (string, string) { return "tv", "manual" }
	r.applyHooks()
	r.start()
	defer func() {
		close(r.stopCh)
		select {
		case <-r.doneCh:
		case <-time.After(3 * time.Second):
			t.Fatal("写者 3 秒内没退出")
		}
	}()
	time.Sleep(3 * time.Second)
	n := r.tickN.Load()
	// 空闲: 首拍 200ms + 之后每拍 m4IdleTickMS(500ms)→ 3 秒约 6 次; 上限 9 给
	// 调度余量。降频前(固定 200ms)3 秒至少 14 次, 上限 9 能把两者分开。
	if n > 9 {
		t.Fatalf("空闲 3 秒醒了 %d 次(上限 9)—— 空闲降频没生效", n)
	}
	if n < 2 {
		t.Fatalf("3 秒只醒 %d 次 —— 主循环疑似卡死", n)
	}
	t.Logf("空闲 3 秒醒 %d 次(旧代码约 15 次)", n)
}

// m4IdleRunner 测试辅助: 一个「空表、无事件」的写者(假订阅 / 假 dump / 假命令),
// 返回 runner、事件源和 dump 计数。调用方负责 defer 停写者(m4StopRunner)。
func m4IdleRunner(t *testing.T) (*m4GoRunner, *fakeNeighSource, *atomic.Int32) {
	t.Helper()
	dir := m4TestEnv(t)
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := newM4GoRunner("wlan2")
	src := &fakeNeighSource{ch: make(chan []neigh.Entry, 64), stop: make(chan struct{})}
	r.subscribeFn = func() (m4NeighSource, error) { return src, nil }
	dumped := &atomic.Int32{}
	r.dumpIfFn = func(int) ([]neigh.Entry, error) { dumped.Add(1); return nil, nil }
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.blacklistFn = func() map[string]bool { return nil }
	r.ifIndexFn = func(string) (int, error) { return 7, nil }
	r.hooks.Fast = func(mac string) (string, string) { return "tv", "manual" }
	r.hooks.Full = func(mac, ip string) (string, string) { return "tv", "manual" }
	r.applyHooks()
	return r, src, dumped
}

func m4StopRunner(t *testing.T, r *m4GoRunner) {
	close(r.stopCh)
	select {
	case <-r.doneCh:
	case <-time.After(3 * time.Second):
		t.Fatal("写者 3 秒内没退出")
	}
}

// m4WaitCount 等计数超过 base(最多 limit), 返回实际用时与是否等到。
func m4WaitCount(c *atomic.Int32, base int32, limit time.Duration) (time.Duration, bool) {
	t0 := time.Now()
	for time.Since(t0) < limit {
		if c.Load() > base {
			return time.Since(t0), true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return time.Since(t0), false
}

// TestRefreshLatencyWhenIdle v5.32 审查修复: 空闲降频后 REFRESH 仍要在 1 秒内反映到
// devices.json(bin/device_detect.sh do_scan_via_daemon: SIGUSR1 后 sleep 1 比 mtime,
// 没变就当 hotspotd 卡死、退回 shell 扫描)。最坏情况是 touch 刚好落在一拍之后 ——
// 这里等到一拍刚过再 touch, 量到全量扫的用时。GLM 版空闲拍 1 秒, 这一步要 ~1 秒,
// 加上 hotspotd 转发和写盘就超出 bin/device_detect.sh 的 1 秒窗口。
func TestRefreshLatencyWhenIdle(t *testing.T) {
	r, _, dumped := m4IdleRunner(t)
	r.start()
	defer m4StopRunner(t, r)
	// 等第一拍的全量扫(lastSync 零值), 之后表空、无事件 = 空闲
	if _, ok := m4WaitCount(dumped, 0, 2*time.Second); !ok {
		t.Fatal("第一拍没有全量扫")
	}
	// 再等两拍, 保证进入空闲周期; 然后卡在「一拍刚过」的时刻 touch
	n0 := r.tickN.Load()
	deadline := time.Now().Add(5 * time.Second)
	for r.tickN.Load() < n0+2 {
		if time.Now().After(deadline) {
			t.Fatal("主循环 5 秒内不到两拍")
		}
		time.Sleep(2 * time.Millisecond)
	}
	base := dumped.Load()
	ticksBefore := r.tickN.Load()
	if err := os.WriteFile(m4RefreshFile, []byte("refresh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	took, ok := m4WaitCount(dumped, base, 3*time.Second)
	if !ok {
		t.Fatal("touch refresh 后 3 秒内没有全量扫")
	}
	if tickDelta := r.tickN.Load() - ticksBefore; tickDelta > 3 {
		t.Fatalf("空闲时 REFRESH 跨越了 %d 拍才全量扫(期望 1~2 拍内响应)", tickDelta)
	}
	if took > 1800*time.Millisecond {
		t.Fatalf("空闲时 REFRESH 用了 %v 才全量扫(上限 1800ms)", took)
	}
	t.Logf("空闲时 REFRESH → 全量扫 %v", took)
}

// TestRunnerEventStormDoesNotStarveTick v5.32 审查修复: 邻居事件持续不断(间隔 <
// 200ms)时, 拍子照样要响 —— 去抖写、REFRESH、名字派发、30 秒兜底都在拍子分支里。
// GLM 版每圈(含事件分支)Reset 定时器, 事件一直来, 拍子就一直被往后推、永远不响:
// 这期间 touch refresh 不会被处理, devices.json 一次也写不出来。
func TestRunnerEventStormDoesNotStarveTick(t *testing.T) {
	r, src, dumped := m4IdleRunner(t)
	r.start()
	defer m4StopRunner(t, r)
	if _, ok := m4WaitCount(dumped, 0, 2*time.Second); !ok {
		t.Fatal("第一拍没有全量扫")
	}
	stopFeed := make(chan struct{})
	fed := make(chan struct{})
	go func() {
		defer close(fed)
		for i := 0; ; i++ {
			select {
			case <-stopFeed:
				return
			case <-time.After(40 * time.Millisecond):
			}
			ip := net.IPv4(192, 168, 43, byte(100+i%2))
			select {
			case src.ch <- []neigh.Entry{{IfIndex: 7, IP: ip, MAC: "02:5a:00:00:00:01", State: neigh.NUDReachable}}:
			case <-stopFeed:
				return
			}
		}
	}()
	defer func() { close(stopFeed); <-fed }()
	time.Sleep(300 * time.Millisecond) // 事件风暴进行中
	ticks0 := r.tickN.Load()
	base := dumped.Load()
	if err := os.WriteFile(m4RefreshFile, []byte("refresh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if took, ok := m4WaitCount(dumped, base, 1500*time.Millisecond); !ok {
		t.Fatalf("事件风暴中 touch refresh, %v 内没有全量扫(拍子被事件饿死; 期间醒拍 %d 次)",
			took, r.tickN.Load()-ticks0)
	}
	if _, err := os.Stat(m4DevicesJSON); err != nil {
		t.Fatalf("事件风暴中 devices.json 一次也没写出: %v", err)
	}
}

func TestM4PureGoStatsLegacyNftDualStackAndFallback(t *testing.T) {
	dir := m4TestEnv(t)
	r := newM4GoRunner("wlan2")
	r.blacklistFn = func() map[string]bool { return nil }
	r.hooks.Fast = func(mac string) (string, string) { return "dev", "manual" }
	r.applyHooks()

	// 在线设备 A(legacy 9 列测试) 与 B(iptables-nft 8 列测试)
	r.table.Apply(neigh.Entry{IfIndex: 7, IP: net.ParseIP("192.168.43.101"), MAC: "02:5a:00:00:00:01", State: neigh.NUDReachable}, time.Now())
	r.table.Apply(neigh.Entry{IfIndex: 7, IP: net.ParseIP("192.168.43.102"), MAC: "02:5a:00:00:00:02", State: neigh.NUDReachable}, time.Now())

	// 写入 stats_v6_map(含前导零与 :: 缩写混排)与 stats_v6_retired
	v6Map := "2408:8207:0000:0001::00ab 02:5a:00:00:00:01\n2408:8207:0:1::cd 02:5a:00:00:00:02\n"
	v6Ret := "02:5a:00:00:00:01 500 300\n"
	if err := os.WriteFile(m4StatsV6Map, []byte(v6Map), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m4StatsV6Retired, []byte(v6Ret), 0o644); err != nil {
		t.Fatal(err)
	}

	// 模拟 `-w 2` 与 `-w` 均报参数不支持, 自动回退到无 `-w`, 并混排 legacy 9 列与 nft 8 列输出
	var iptCalls atomic.Int32
	m4IptablesExecFn = func(_ context.Context, name string, args ...string) (string, string, int, error) {
		iptCalls.Add(1)
		if len(args) > 0 && args[0] == "-w" {
			return "", "iptables: unrecognized option '-w'", 2, errors.New("exit status 2")
		}
		if name == "iptables" {
			return "Chain HNC_STATS (1 references)\n" +
				" pkts bytes target prot opt in out source destination\n" +
				// legacy 9 列: A 上行 1000, A 下行 2000
				"   10  1000 RETURN all  --  *  *   192.168.43.101/32  0.0.0.0/0\n" +
				"   20  2000 RETURN all  --  *  *   0.0.0.0/0          192.168.43.101\n" +
				// Android 14-16 iptables-nft 8 列(无 opt 列): B 上行 4000, B 下行 8000
				"   40  4000 RETURN 0        *  *   192.168.43.102     0.0.0.0/0\n" +
				"   80  8000 RETURN 0        *  *   0.0.0.0/0          192.168.43.102\n", "", 0, nil
		}
		if name == "ip6tables" {
			return "Chain HNC_STATS (1 references)\n" +
				" pkts bytes target prot opt in out source destination\n" +
				// legacy 含 -- opt 列: A IPv6 MAC 上行 100 + DST 下行 200
				"    5   100 RETURN all  --  *  *   ::/0  ::/0  MAC 02:5A:00:00:00:01\n" +
				"    8   200 RETURN all  --  *  *   ::/0  2408:8207:0:1::ab/128\n" +
				// nft 无 opt 列: B IPv6 MAC 上行 600 + DST 下行 900
				"    6   600 RETURN 0        *  *   ::/0  ::/0  MAC 02:5a:00:00:00:02\n" +
				"    9   900 RETURN 0        *  *   ::/0  2408:8207:0000:0001:0000:0000:0000:00cd\n", "", 0, nil
		}
		return "", "unknown binary", -1, os.ErrNotExist
	}

	got, err := r.collectStats()
	if err != nil {
		t.Fatalf("collectStats 纯 Go 解析失败: %v", err)
	}
	// A: rx = 2000(v4) + 200(v6 dst) + 500(v6 retired) = 2700; tx = 1000(v4) + 100(v6 mac) + 300(v6 retired) = 1400
	if got["192.168.43.101"] != [2]int64{2700, 1400} {
		t.Fatalf("设备 A 聚合字节 = %v, want [2700 1400]", got["192.168.43.101"])
	}
	// B: rx = 8000(v4) + 900(v6 dst) = 8900; tx = 4000(v4) + 600(v6 mac) = 4600
	if got["192.168.43.102"] != [2]int64{8900, 4600} {
		t.Fatalf("设备 B 聚合字节 = %v, want [8900 4600]", got["192.168.43.102"])
	}

	// 验证 STATS_ALL_CMD 环境变量优先钩子保持 100% 兼容
	mockIn := filepath.Join(dir, "stats_all.in")
	if err := os.WriteFile(mockIn, []byte("192.168.43.101 777 888\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STATS_ALL_CMD", "cat "+mockIn)
	gotEnv, err := r.collectStats()
	if err != nil || gotEnv["192.168.43.101"] != [2]int64{777, 888} {
		t.Fatalf("STATS_ALL_CMD 钩子失效: got=%v err=%v", gotEnv, err)
	}
	t.Setenv("STATS_ALL_CMD", "")

	// 验证纯 Go iptables 失败时平滑回退原脚本兜底
	m4IptablesExecFn = func(context.Context, string, ...string) (string, string, int, error) {
		return "", "permission denied", -1, syscall.EACCES
	}
	fakeScript := filepath.Join(dir, "bin", "fake_iptables_manager.sh")
	_ = os.MkdirAll(filepath.Dir(fakeScript), 0o755)
	if err := os.WriteFile(fakeScript, []byte("#!/bin/sh\n[ \"$1\" = \"stats_all\" ] && echo '192.168.43.102 3333 4444'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	iptablesMgrPath = fakeScript
	gotFb, err := r.collectStats()
	if err != nil || gotFb["192.168.43.102"] != [2]int64{3333, 4444} {
		t.Fatalf("脚本兜底回退失败: got=%v err=%v", gotFb, err)
	}
}

func TestM4WriteDevicesAtomicSyncsDevicesFlatAndCapsWriteLog(t *testing.T) {
	m4TestEnv(t)
	// 预填超过 256 KiB 的 m4_go_write.log
	var bigLog strings.Builder
	for i := 0; bigLog.Len() < 300<<10; i++ {
		fmt.Fprintf(&bigLog, "2026-11-22T00:00:00: /tmp/old-%05d\n", i)
	}
	if err := os.WriteFile(m4GoWriteLog, []byte(bigLog.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	r := newM4GoRunner("wlan2")
	r.statsFn = func() (map[string][2]int64, error) {
		return map[string][2]int64{"192.168.43.101": {10, 20}}, nil
	}
	r.blacklistFn = func() map[string]bool { return nil }
	r.hooks.Fast = func(mac string) (string, string) { return "phone", "manual" }
	r.applyHooks()

	now := time.Now()
	r.table.Apply(neigh.Entry{IfIndex: 7, IP: net.ParseIP("192.168.43.101"), MAC: "02:5a:00:00:00:01", State: neigh.NUDReachable}, now)

	statsAt := time.Time{}
	statsMap := map[string][2]int64{}
	written := r.writeOut(nil, &statsAt, &statsMap, true)

	flatBytes, err := os.ReadFile(m4DevicesFlat)
	if err != nil {
		t.Fatalf("devices.flat 未同步写出: %v", err)
	}
	wantFlat := "02:5a:00:00:00:01\t192.168.43.101\twlan2\n"
	if string(flatBytes) != wantFlat {
		t.Fatalf("devices.flat = %q, want %q", string(flatBytes), wantFlat)
	}

	fi, err := os.Stat(m4GoWriteLog)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > m4GoWriteLogMaxBytes {
		t.Fatalf("m4_go_write.log 未封顶 256 KiB: size=%d", fi.Size())
	}

	// 设备下线后再次写出 → devices.flat 同步清空
	r.table.Apply(neigh.Entry{IfIndex: 7, IP: net.ParseIP("192.168.43.101"), State: neigh.NUDFailed}, now.Add(time.Second))
	r.writeOut(written, &statsAt, &statsMap, true)
	flatBytes2, err := os.ReadFile(m4DevicesFlat)
	if err != nil || len(flatBytes2) != 0 {
		t.Fatalf("全员离线后 devices.flat 应为空文件, got=%q err=%v", string(flatBytes2), err)
	}
}

func TestM4SELinuxNetlinkPermFallbackARPAnd30sBackoff(t *testing.T) {
	m4TestEnv(t)

	// 1. 验证生产默认 dumpIfFn 在 neigh.DumpIf 权限受限时回退 /proc/net/arp(过滤网卡 + 排除 00:00:00:00:00:00 / 0x0)
	arpContent := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.168.43.101   0x1         0x2         02:5a:00:00:00:01     *        wlan2\n" +
		"192.168.43.102   0x1         0x0         02:5a:00:00:00:02     *        wlan2\n" +
		"192.168.43.103   0x1         0x2         00:00:00:00:00:00     *        wlan2\n" +
		"10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n"
	if err := os.WriteFile(m4ProcNetARP, []byte(arpContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var nlCalls atomic.Int32
	m4NetlinkDumpIfFn = func(int) ([]neigh.Entry, error) {
		nlCalls.Add(1)
		return nil, fmt.Errorf("neigh: socket: %w", syscall.EACCES)
	}

	r := newM4GoRunner("wlan2")
	src := &fakeNeighSource{ch: make(chan []neigh.Entry, 4), stop: make(chan struct{})}
	r.subscribeFn = func() (m4NeighSource, error) { return src, nil }
	r.ifIndexFn = func(string) (int, error) { return 7, nil }
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.blacklistFn = func() map[string]bool { return nil }
	r.hooks.Fast = func(mac string) (string, string) { return "arp-client", "manual" }
	r.hooks.Full = func(mac, ip string) (string, string) { return "arp-client", "manual" }
	r.applyHooks()
	r.start()

	deadline := time.Now().Add(2 * time.Second)
	for {
		b, err := os.ReadFile(m4DevicesJSON)
		if err == nil && strings.Contains(string(b), "02:5a:00:00:00:01") {
			s := string(b)
			if strings.Contains(s, "02:5a:00:00:00:02") || strings.Contains(s, "aa:bb:cc:dd:ee:ff") || strings.Contains(s, "00:00:00:00:00:00") {
				t.Fatalf("/proc/net/arp 过滤错误, 混入无效或非热点网卡条目: %s", s)
			}
			break
		}
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(m4DevicesJSON)
			t.Fatalf("/proc/net/arp 兜底未在 2s 内写出有效设备: %q", b)
		}
		time.Sleep(25 * time.Millisecond)
	}
	m4StopRunner(t, r)
	if nlCalls.Load() != 1 {
		t.Fatalf("冷却期内不应重复触发 AF_NETLINK 系统调用, nlCalls=%d", nlCalls.Load())
	}

	// 2. 验证当 dumpIfFn 持续返回 EACCES 时, 主循环按 m4PermErrBackoff 退避而非 1Hz 风暴
	m4PermErrBackoff = 5 * time.Second
	var permDumpCalls atomic.Int32
	r2 := newM4GoRunner("wlan2")
	src2 := &fakeNeighSource{ch: make(chan []neigh.Entry, 4), stop: make(chan struct{})}
	r2.subscribeFn = func() (m4NeighSource, error) { return src2, nil }
	r2.ifIndexFn = func(string) (int, error) { return 7, nil }
	r2.dumpIfFn = func(int) ([]neigh.Entry, error) {
		permDumpCalls.Add(1)
		return nil, syscall.EACCES
	}
	r2.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r2.blacklistFn = func() map[string]bool { return nil }
	r2.applyHooks()
	r2.start()

	if _, ok := m4WaitCount(&permDumpCalls, 0, 2*time.Second); !ok {
		m4StopRunner(t, r2)
		t.Fatal("首轮 dump 未触发")
	}
	// 观察 1.6 秒: 旧代码 1Hz 重试至少触发 2 次; 退避后只允许首轮 1 次!
	time.Sleep(1600 * time.Millisecond)
	gotCalls := permDumpCalls.Load()
	m4StopRunner(t, r2)
	if gotCalls != 1 {
		t.Fatalf("EACCES 权限错误未退避, 1.6s 内触发了 %d 次(期望仅 1 次)", gotCalls)
	}
}
