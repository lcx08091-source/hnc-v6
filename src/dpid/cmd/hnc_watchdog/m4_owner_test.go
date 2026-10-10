// m4_owner_test.go — v5.31 T1/T3 单测: 去抖纯函数、开关读取、切换安全、
// 写出路径。路径 / 订阅 / 命令全部注入, 不碰真文件(临时目录)、真 socket。
package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hnc.io/dpid/neigh"
)

// m4TestEnv 重定向所有路径到临时目录(测试结束全部恢复)。
// v5.31 审查修复: 原来只恢复 m4OwnerFile, 其余变量留在已删的临时目录; 名字解析的
// 路径(device_names / hostname_cache / oui_overrides / mdns_resolve)和 Go 写日志
// 没重定向 —— 测试会读写真实的 /data/local/hnc。
func m4TestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ptrs := []*string{&m4OwnerFile, &m4OwnerCurrentFile, &m4DevicesJSON, &m4DevicesTmpGo,
		&m4DrillOut, &m4GoOutTmp, &m4DrillFile, &m4RefreshFile, &m4GoWriteLog,
		&m4NamesPath, &m4CachePath, &m4OverridesPath, &m4MDNSBin, &rulesJSONPath}
	old := make([]string, len(ptrs))
	for i, p := range ptrs {
		old[i] = *p
	}
	t.Cleanup(func() {
		for i, p := range ptrs {
			*p = old[i]
		}
	})
	m4OwnerFile = filepath.Join(dir, "m4_owner")
	m4OwnerCurrentFile = filepath.Join(dir, "m4_owner.current")
	m4DevicesJSON = filepath.Join(dir, "devices.json")
	m4DevicesTmpGo = filepath.Join(dir, "devices.json.tmp.go")
	m4DrillOut = filepath.Join(dir, "run", "devices.go.json")
	m4GoOutTmp = filepath.Join(dir, "run", "devices.go.json.tmp")
	m4DrillFile = filepath.Join(dir, "run", "wd_m4_drill")
	m4RefreshFile = filepath.Join(dir, "run", "devices.refresh")
	m4GoWriteLog = filepath.Join(dir, "run", "m4_go_write.log")
	m4NamesPath = filepath.Join(dir, "device_names.json")
	m4CachePath = filepath.Join(dir, "hostname_cache.json")
	m4OverridesPath = filepath.Join(dir, "oui_overrides.json")
	m4MDNSBin = filepath.Join(dir, "no_mdns_resolve")
	rulesJSONPath = filepath.Join(dir, "rules.json")
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	return dir
}

// newTestOwner 注入假的 hotspotd 控制(先 wired=true 挡掉 wireProd 覆盖)。
func newTestOwner(t *testing.T, statusReply string) *m4OwnerMgr {
	t.Helper()
	m := &m4OwnerMgr{wired: true}
	m.hotspotdStatusFn = func() (string, error) { return statusReply, nil }
	m.ensureHotspotdFn = func() error { return nil }
	m.quitHotspotdFn = func() error { return nil }
	return m
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

func TestReadM4Owner(t *testing.T) {
	dir := m4TestEnv(t)
	m := &m4OwnerMgr{}
	// 文件不存在 → 默认(rc 默认 go, 见 m4OwnerDefault)
	if got := m.readM4Owner(); got != m4OwnerDefault {
		t.Fatalf("缺文件应回默认 %q, 得 %q", m4OwnerDefault, got)
	}
	for _, c := range []struct{ content, want string }{
		{"go", "go"},
		{"c", "c"},
		{" go\n", "go"},
		{"garbage", m4OwnerDefault},
		{"", m4OwnerDefault},
	} {
		if err := os.WriteFile(filepath.Join(dir, "m4_owner"), []byte(c.content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := m.readM4Owner(); got != c.want {
			t.Fatalf("内容 %q: 得 %q 要 %q", c.content, got, c.want)
		}
	}
}

func TestHotspotdDaemonArgs(t *testing.T) {
	m4OwnerCur.Store("c")
	if got := hotspotdDaemon().args; len(got) != 1 || got[0] != "-d" {
		t.Fatalf("c 模式不应带 --no-discovery: %v", got)
	}
	m4OwnerCur.Store("go")
	got := hotspotdDaemon().args
	if len(got) != 2 || got[1] != "--no-discovery" {
		t.Fatalf("go 模式应带 --no-discovery: %v", got)
	}
	m4OwnerCur.Store("c")
}

func TestOwnerSwitchSafety(t *testing.T) {
	m4TestEnv(t)
	// 确认失败(STATUS 没有 discovery:0)→ 回滚, Go 写者不许起
	m := newTestOwner(t, "running:1 devices:0 pid:1\n")
	m.owner = "c"
	m.switchOwnerLocked("go", time.Now())
	if m.owner != "c" {
		t.Fatalf("确认失败应回滚, owner = %q", m.owner)
	}
	if m.runner != nil {
		t.Fatal("确认失败时 Go 写者不该启动")
	}
	// 确认成功 → owner=go
	m2 := newTestOwner(t, "running:1 devices:0 pid:1 discovery:0\n")
	m2.owner = "c"
	m2.switchOwnerLocked("go", time.Now())
	if m2.owner != "go" || m4OwnerCur.Load() != "go" {
		t.Fatalf("确认成功应切到 go, owner=%q cur=%v", m2.owner, m4OwnerCur.Load())
	}
	m2.tick("", time.Now()) // 空 iface: 停写者
	if m2.runner != nil {
		t.Fatal("空 iface 应停写者")
	}
	// go → c: 先停 Go 写者再退 hotspotd —— 退出时 runner 必须已经 nil
	m2.quitHotspotdFn = func() error {
		if m2.runner != nil {
			t.Fatal("切回 c 时, hotspotd 退出前 Go 写者应已停(先停后起)")
		}
		return nil
	}
	m2.switchOwnerLocked("c", time.Now())
	if m2.owner != "c" || m2.runner != nil {
		t.Fatalf("切回 c 失败: owner=%q runner=%v", m2.owner, m2.runner)
	}
}

func TestOwnerTickStartsRunner(t *testing.T) {
	dir := m4TestEnv(t)
	m := newTestOwner(t, "running:1 devices:0 pid:1 discovery:0\n")
	if err := os.WriteFile(filepath.Join(dir, "m4_owner"), []byte("go"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.tick("lo", time.Now())
	if m.owner != "go" {
		t.Fatalf("tick 应把 owner 定为 go, 得 %q", m.owner)
	}
	if m.runner == nil {
		t.Fatal("go + ACTIVE iface 应启动 Go 写者")
	}
	r := m.runner
	m.tick("lo", time.Now())
	if m.runner != r {
		t.Fatal("iface 没变不应重启写者")
	}
	// run/m4_owner.current 每轮都写
	b, err := os.ReadFile(filepath.Join(dir, "m4_owner.current"))
	if err != nil || string(b) != "go\n" {
		t.Fatalf("m4_owner.current 应为 go\\n: %q %v", string(b), err)
	}
	m.tick("", time.Now()) // 热点没了 → 停写者
	if m.runner != nil {
		t.Fatal("空 iface 应停 Go 写者")
	}
}

func TestRunnerWriteOut(t *testing.T) {
	m4TestEnv(t)
	r := newM4GoRunner("wlan2", false)
	r.statsCmdFn = func() (map[string][2]int64, error) {
		return map[string][2]int64{"192.168.43.101": {111, 222}}, nil
	}
	r.blacklistFn = func() map[string]bool { return map[string]bool{} }
	r.applyHooks() // 先装钩子, 再覆盖(顺序反了会被 resolver 兜底覆盖掉)
	r.table.Fast = func(mac string) (string, string) { return "tv", "manual" }

	// 直接构造事件走 Apply
	if !r.table.Apply(neigh.Entry{IfIndex: 7, IP: net.ParseIP("192.168.43.101"), MAC: "02:5a:00:00:00:01", State: 0x02}, time.Now()) {
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
	r := newM4GoRunner("wlan2", false)
	src := &fakeNeighSource{ch: make(chan []neigh.Entry, 8), stop: make(chan struct{})}
	r.subscribeFn = func() (m4NeighSource, error) { return src, nil }
	r.dumpIfFn = func(int) ([]neigh.Entry, error) { return nil, nil }
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.blacklistFn = func() map[string]bool { return nil }
	r.ifIndexFn = func(string) (int, error) { return 7, nil }
	r.table.Fast = func(mac string) (string, string) { return "tv", "manual" }
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
	src.ch <- []neigh.Entry{{IfIndex: 7, IP: net.ParseIP("192.168.43.109"), MAC: "02:5a:00:00:00:09", State: 0x02}}
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

// TestRefreshTriggersFullSync v5.31 T4: REFRESH/SIGUSR1 的转发 ——
// touch run/devices.refresh 后, 写者应在 1 秒内全量扫并写 devices.json
// (device_detect.sh scan 的「1 秒内 mtime 变了」判断依赖它)。
func TestRefreshTriggersFullSync(t *testing.T) {
	dir := m4TestEnv(t)
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := newM4GoRunner("wlan2", false)
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
			MAC: "02:5a:00:00:00:09", State: 0x02}}, nil
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
	// 没事件、没到 30s —— 只有 refresh 能触发写出(touch = 建文件, mtime=now)。
	// 等过第一拍(200ms), 保证文件 mtime 严格晚于 lastRefreshM(同毫秒会漏判)。
	time.Sleep(300 * time.Millisecond)
	gate.Store(true)
	if err := os.WriteFile(m4RefreshFile, []byte("refresh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if dumped.Load() > 0 {
			if b, err := os.ReadFile(m4DevicesJSON); err == nil &&
				strings.Contains(string(b), "02:5a:00:00:00:09") {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("touch refresh 后 2 秒内没有全量扫写出(dumped=%d)", dumped.Load())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// fakeNeighSource 假订阅源: Read 从 channel 取一批事件。
type fakeNeighSource struct {
	ch   chan []neigh.Entry
	stop chan struct{}
}

func (f *fakeNeighSource) Read() ([]neigh.Entry, error) {
	select {
	case es := <-f.ch:
		return es, nil
	case <-f.stop:
		return nil, os.ErrClosed
	}
}

func (f *fakeNeighSource) Close() error { close(f.stop); return nil }

// TestOwnerDefaultFallbackC v5.32 T3: 「默认值改回 c」这条路改了就能用。
// 模拟 v5.31 升级上来的手机: 没有 data/m4_owner, hotspotd 却以
// --no-discovery 跑着(开机时 device_detect.sh 照 run/m4_owner.current=go
// 拉起)。默认值换成 c 后: owner=c、hotspotd 被纠正回做发现、Go 写者不起。
// 「改动前会失败」: 基线(BASE=6dda4518)没有 m4OwnerDefaultOverride,
// 本测试编译失败(undefined: m4OwnerDefaultOverride)。
func TestOwnerDefaultFallbackC(t *testing.T) {
	dir := m4TestEnv(t)
	m4OwnerDefaultOverride = "c" // 模拟「正式版把 m4OwnerDefault 改成 c」
	t.Cleanup(func() { m4OwnerDefaultOverride = "" })

	// 1) 没有开关文件 → 默认 c
	if err := os.Remove(filepath.Join(dir, "m4_owner")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if got := (&m4OwnerMgr{}).readM4Owner(); got != "c" {
		t.Fatalf("默认换成 c 后, 缺开关文件应得 c, 得 %q", got)
	}

	// 2) 场景: hotspotd 以 --no-discovery 跑(STATUS 带 discovery:0),
	//    run/m4_owner.current 还是上一次会话的 go —— 开机窗口第一拍。
	quitN, ensureN := 0, 0
	m := &m4OwnerMgr{wired: true}
	m.hotspotdStatusFn = func() (string, error) { return "running:1 devices:0 pid:1 discovery:0\n", nil }
	m.ensureHotspotdFn = func() error { ensureN++; return nil }
	m.quitHotspotdFn = func() error { quitN++; return nil }
	m.tick("lo", time.Now())
	if m.owner != "c" {
		t.Fatalf("默认 c + 缺开关: owner 应为 c, 得 %q", m.owner)
	}
	if m.runner != nil {
		t.Fatal("默认 c 时 Go 写者不许起")
	}
	// owner=c 而 hotspotd 在 no-discovery → reconcile 纠偏(重启回发现模式)
	if quitN == 0 || ensureN == 0 {
		t.Fatalf("应重启 hotspotd 纠偏回发现模式(quit=%d ensure=%d)", quitN, ensureN)
	}
	// run/m4_owner.current 每轮都写, 供 device_detect.sh 读
	b, err := os.ReadFile(filepath.Join(dir, "m4_owner.current"))
	if err != nil || strings.TrimSpace(string(b)) != "c" {
		t.Fatalf("m4_owner.current 应为 c: %q %v", string(b), err)
	}
}

// TestM4NextTickMS v5.32 T4: 主循环下一拍间隔 —— 有事(dirty / 待解析名字 /
// 在途解析)200ms, 全空闲 1s。改动前固定 200ms(m4WriteHardRateMS)。
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
// 旧代码固定 200ms → 15+ 次; 新代码空闲 1s → 首拍(200ms) + 约 3 次 ≤ 6。
func TestRunnerIdleWakeRate(t *testing.T) {
	m4TestEnv(t)
	r := newM4GoRunner("wlan2", false)
	src := &fakeNeighSource{ch: make(chan []neigh.Entry, 8), stop: make(chan struct{})}
	r.subscribeFn = func() (m4NeighSource, error) { return src, nil }
	r.dumpIfFn = func(int) ([]neigh.Entry, error) { return nil, nil } // 空表: 无 pending 无 dirty
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.blacklistFn = func() map[string]bool { return nil }
	r.ifIndexFn = func(string) (int, error) { return 7, nil }
	r.table.Fast = func(mac string) (string, string) { return "tv", "manual" }
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
	// 空闲: 首拍 200ms + 之后每拍 1s → 3 秒约 3–4 次; 上限 6 给调度余量。
	// 旧代码(固定 200ms)3 秒至少 14 次, 上限 6 能把两者分开。
	if n > 6 {
		t.Fatalf("空闲 3 秒醒了 %d 次(上限 6)—— 空闲降频没生效", n)
	}
	if n < 2 {
		t.Fatalf("3 秒只醒 %d 次 —— 主循环疑似卡死", n)
	}
	t.Logf("空闲 3 秒醒 %d 次(旧代码约 15 次)", n)
}
