// m5_test.go — v5.30 T2: 迁移 M5(dpid 守护链收缩)。
//
// 全部走真实入口 superviseDpid()(= mainLoop 每轮调的那一个), 外部世界
// (run / logs / bin / etc 目录、/proc、拉起进程、时钟、记账)都注入到临时
// 目录与假实现, 不碰真实 /data/local/hnc、不起进程。
//
// 「改动前会失败」: v5.29 没有 superviseDpid / m5.go(编译即失败); 语义上
// v5.29 的看门狗不做救命路径(TestM5RescueBrokenLauncher)、拉起冷却固定 30 秒
// 不退避(TestM5SpawnBackoff)、pidfile 只看 kill(pid,0) 不看 cmdline
// (TestM5PidReuseNotAlive)。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type m5World struct {
	t        *testing.T
	run, log string
	bin, etc string
	proc     string
	clk      *fakeClock
	spawns   []string // "bin args… > pidfile"
	makeLive bool     // 假拉起后进程是否「活着」(写假 /proc)
	nextPID  int
	legacy   []string
	stats    map[string]int
	statErrs map[string]int
}

func withM5World(t *testing.T) *m5World {
	t.Helper()
	root := t.TempDir()
	w := &m5World{t: t, run: filepath.Join(root, "run"), log: filepath.Join(root, "logs"),
		bin: filepath.Join(root, "bin"), etc: filepath.Join(root, "etc"), proc: filepath.Join(root, "proc"),
		clk: &fakeClock{now: time.Unix(1_800_000_000, 0)}, nextPID: 900001,
		stats: map[string]int{}, statErrs: map[string]int{}}
	for _, d := range []string{w.run, w.log, w.bin, w.etc, w.proc} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, b := range []string{m5NameLauncher, m5NameDpid} {
		_ = os.WriteFile(filepath.Join(w.bin, b), []byte("#!fake"), 0o755)
	}
	oRun, oLog, oBin, oEtc, oProc := m5RunDir, m5LogDir, m5BinDir, m5EtcDir, m5ProcRoot
	oSpawn, oLegacy, oNow, oStats, oGates := m5SpawnFn, m5LegacyFn, nowFn, runStatsFn, m5Gates
	m5RunDir, m5LogDir, m5BinDir, m5EtcDir, m5ProcRoot = w.run, w.log, w.bin, w.etc, w.proc
	m5Gates = map[string]*spawnGate{}
	nowFn = w.clk.Now
	m5SpawnFn = func(bin string, args []string, logPath, pidFile string) error {
		w.spawns = append(w.spawns, fmt.Sprintf("%s %s > %s", filepath.Base(bin), strings.Join(args, " "), filepath.Base(pidFile)))
		pid := w.nextPID
		w.nextPID++
		_ = os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), 0o644)
		if w.makeLive {
			w.proc1(pid, append([]string{bin}, args...)...)
		}
		return nil
	}
	m5LegacyFn = func(choice string) { w.legacy = append(w.legacy, choice) }
	runStatsFn = func(name string, rc int, err error, _ float64, _ time.Time) {
		w.stats[name]++
		if err != nil {
			w.statErrs[name]++
		}
	}
	t.Cleanup(func() {
		m5RunDir, m5LogDir, m5BinDir, m5EtcDir, m5ProcRoot = oRun, oLog, oBin, oEtc, oProc
		m5SpawnFn, m5LegacyFn, nowFn, runStatsFn, m5Gates = oSpawn, oLegacy, oNow, oStats, oGates
	})
	return w
}

// proc1 假 /proc/<pid>: cmdline = argv(NUL 分隔), comm = 15 字节短名。
func (w *m5World) proc1(pid int, argv ...string) {
	d := filepath.Join(w.proc, strconv.Itoa(pid))
	_ = os.MkdirAll(d, 0o755)
	_ = os.WriteFile(filepath.Join(d, "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"), 0o644)
	comm := filepath.Base(argv[0])
	if len(comm) > 15 {
		comm = comm[:15]
	}
	_ = os.WriteFile(filepath.Join(d, "comm"), []byte(comm+"\n"), 0o644)
}

func (w *m5World) kill(pid int) { _ = os.RemoveAll(filepath.Join(w.proc, strconv.Itoa(pid))) }

func (w *m5World) write(rel, body string) {
	_ = os.WriteFile(filepath.Join(w.run, rel), []byte(body), 0o644)
}

func (w *m5World) choice() string {
	b, _ := os.ReadFile(filepath.Join(w.run, "dpid_launcher.choice"))
	return strings.TrimSpace(string(b))
}

// ── 两种形态下谁负责拉起 ───────────────────────────────────────────────

func TestM5OnLauncherAliveNothingToDo(t *testing.T) {
	w := withM5World(t)
	w.write("dpid_launcher.choice", "launcher\n")
	w.proc1(4242, "/data/local/hnc/bin/hnc_launcher")
	w.write("dpid_guard.pid", "4242") // service.sh / launcher 自己写的锁文件
	superviseDpid()
	if len(w.spawns) != 0 || len(w.legacy) != 0 {
		t.Fatalf("launcher 活着不该动: spawns=%v legacy=%v", w.spawns, w.legacy)
	}
}

func TestM5OnLauncherDeadWatchdogRelaunches(t *testing.T) {
	w := withM5World(t)
	w.makeLive = true
	w.write("dpid_launcher.choice", "launcher\n")
	superviseDpid()
	if len(w.spawns) != 1 || w.spawns[0] != "hnc_launcher  > launcher.pid" {
		t.Fatalf("launcher 死了应由看门狗拉起 launcher(不碰 dpid): %v", w.spawns)
	}
	w.clk.now = w.clk.now.Add(time.Minute)
	superviseDpid() // 拉起来了, 不再动
	if len(w.spawns) != 1 || w.stats[m5ActSpawnLauncher] != 1 {
		t.Fatalf("spawns=%v stats=%v", w.spawns, w.stats)
	}
}

func TestM5OffUsesLegacyThreeWay(t *testing.T) {
	w := withM5World(t)
	w.write(m5SwitchFile, "")
	for _, c := range []string{"launcher", "guard", "supervisor", "direct"} {
		w.write("dpid_launcher.choice", c+"\n")
		superviseDpid()
	}
	if strings.Join(w.legacy, ",") != "launcher,guard,supervisor,direct" || len(w.spawns) != 0 {
		t.Fatalf("开关关闭应全部走 v5.29 四路监管: legacy=%v spawns=%v", w.legacy, w.spawns)
	}
}

// 旧值兼容: 关着 M5 开机选的 guard / supervisor, 开关删了也维持 v5.29 监管。
func TestM5OnLegacyChoiceCompat(t *testing.T) {
	w := withM5World(t)
	for _, c := range []string{"guard", "supervisor", "bogus"} {
		w.write("dpid_launcher.choice", c+"\n")
		superviseDpid()
	}
	if strings.Join(w.legacy, ",") != "guard,supervisor" {
		t.Fatalf("legacy=%v(非法值按缺失处理, 不走 legacy)", w.legacy)
	}
	// "bogus" = 缺失: launcher 二进制在 → 拉 launcher
	if len(w.spawns) != 1 || !strings.HasPrefix(w.spawns[0], "hnc_launcher") {
		t.Fatalf("spawns=%v", w.spawns)
	}
}

func TestM5ChoiceMissingNoLauncherBinaryGoesDirect(t *testing.T) {
	w := withM5World(t)
	_ = os.Remove(filepath.Join(w.bin, m5NameLauncher))
	superviseDpid()
	if len(w.spawns) != 1 || !strings.HasPrefix(w.spawns[0], "hnc_dpid -config "+filepath.Join(w.etc, "dpi_config.json")) {
		t.Fatalf("没有 launcher 二进制 → 直拉 dpid: %v", w.spawns)
	}
}

func TestM5DirectMode(t *testing.T) {
	w := withM5World(t)
	w.write("dpid_launcher.choice", "direct\n")
	w.proc1(5555, "/data/local/hnc/bin/hnc_launcher") // launcher 还在(会拉 dpid)
	superviseDpid()
	if len(w.spawns) != 0 {
		t.Fatalf("launcher 还活着时 direct 模式不应再拉 dpid(两个守护者): %v", w.spawns)
	}
	w.kill(5555)
	superviseDpid()
	if len(w.spawns) != 1 || !strings.HasSuffix(w.spawns[0], "> dpid.pid") {
		t.Fatalf("direct 模式 dpid 不在 → 看门狗直拉: %v", w.spawns)
	}
}

// ── 救命路径 ──────────────────────────────────────────────────────────

func TestM5RescueBrokenLauncher(t *testing.T) {
	for _, logName := range []string{"launcher.log", "dpid_guard.log"} {
		t.Run(logName, func(t *testing.T) {
			w := withM5World(t)
			w.makeLive = true
			w.write("dpid_launcher.choice", "launcher\n")
			p := filepath.Join(w.log, logName)
			_ = os.WriteFile(p, []byte("start\nFATAL: executable's TLS segment is underaligned: alignment is 8, needs to be at least 64\nAborted\n"), 0o644)
			_ = os.Chtimes(p, w.clk.now, w.clk.now)
			superviseDpid()
			if len(w.spawns) != 1 || !strings.HasPrefix(w.spawns[0], "hnc_dpid -config") {
				t.Fatalf("launcher 坏了应直拉 dpid, 不再拉 launcher: %v", w.spawns)
			}
			if w.choice() != "direct" || w.stats[m5ActRescue] != 1 {
				t.Fatalf("choice=%q stats=%v", w.choice(), w.stats)
			}
			w.clk.now = w.clk.now.Add(time.Minute)
			superviseDpid() // 已是 direct 且 dpid 活着
			if len(w.spawns) != 1 {
				t.Fatalf("spawns=%v", w.spawns)
			}
		})
	}
}

func TestM5RescueIgnoresStaleLog(t *testing.T) {
	w := withM5World(t)
	w.write("dpid_launcher.choice", "launcher\n")
	p := filepath.Join(w.log, "dpid_guard.log")
	_ = os.WriteFile(p, []byte("Aborted\n"), 0o644)
	old := w.clk.now.Add(-rescueLogFresh - time.Minute)
	_ = os.Chtimes(p, old, old)
	superviseDpid()
	if w.choice() != "launcher" || len(w.spawns) != 1 || !strings.HasPrefix(w.spawns[0], "hnc_launcher") {
		t.Fatalf("几天前的旧 abort 不应触发救命路径: choice=%q spawns=%v", w.choice(), w.spawns)
	}
}

func TestM5RescueDpidAlreadyAlive(t *testing.T) {
	w := withM5World(t)
	w.write("dpid_launcher.choice", "launcher\n")
	w.proc1(7777, "/data/local/hnc/bin/hnc_dpid", "-config", "/data/local/hnc/etc/dpi_config.json")
	w.write("dpid.pid", "7777")
	p := filepath.Join(w.log, "launcher.log")
	_ = os.WriteFile(p, []byte("cannot execute binary file\n"), 0o644)
	_ = os.Chtimes(p, w.clk.now, w.clk.now)
	superviseDpid()
	if len(w.spawns) != 0 || w.choice() != "direct" {
		t.Fatalf("dpid 已活着: 只改 choice, 不再拉: spawns=%v choice=%q", w.spawns, w.choice())
	}
}

func TestRescueLineMatches(t *testing.T) {
	for _, l := range []string{"TLS segment is underaligned", "Aborted", "/x: cannot execute binary file",
		"error: \"hnc_launcher\": executable's TLS segment"} {
		if !rescueLineMatches(l) {
			t.Errorf("应命中: %q", l)
		}
	}
	for _, l := range []string{"started dpid pid=12", "error: open log", "executable ok"} {
		if rescueLineMatches(l) {
			t.Errorf("不应命中: %q", l)
		}
	}
}

// ── 进程风暴防线 ──────────────────────────────────────────────────────

// 拉起后马上又死: 冷却 30 → 60 → 120 → 240 秒翻倍(封顶 8 分钟), 10 分钟只拉 4 次。
func TestM5SpawnBackoff(t *testing.T) {
	w := withM5World(t)
	w.write("dpid_launcher.choice", "launcher\n")
	start := w.clk.now
	var at []int
	for s := 0; s < 600; s += 10 {
		w.clk.now = start.Add(time.Duration(s) * time.Second)
		n := len(w.spawns)
		superviseDpid()
		if len(w.spawns) > n {
			at = append(at, s)
		}
	}
	if fmt.Sprint(at) != "[0 60 180 420]" {
		t.Fatalf("拉起时刻 = %v, want [0 60 180 420]", at)
	}
	if g := m5Gates[m5NameLauncher]; g.fails != m5MaxBackoff || g.cooldown() != m5SpawnMax {
		t.Fatalf("4 次失败后冷却应到上限 %v: fails=%d cooldown=%v", m5SpawnMax, g.fails, g.cooldown())
	}
}

// 拉起后活过 2 分钟 → 退避清零; 再死就按基础冷却。
func TestM5BackoffResetsAfterHealthyRun(t *testing.T) {
	w := withM5World(t)
	w.write("dpid_launcher.choice", "launcher\n")
	g := m5Gate(m5NameLauncher)
	g.fails = 3
	w.makeLive = true
	superviseDpid()
	w.clk.now = w.clk.now.Add(3 * time.Minute)
	superviseDpid()
	if g.fails != 0 {
		t.Fatalf("活过 %v 应清零: fails=%d", m5QuickDeath, g.fails)
	}
}

// ps 只显示短名 / comm 被截断: 判活读 /proc/<pid>/cmdline, 不受影响。
func TestM5ShortNameProcessCountsAsAlive(t *testing.T) {
	w := withM5World(t)
	w.write("dpid_launcher.choice", "launcher\n")
	w.proc1(4300, "hnc_launcher") // 没有路径的短名 argv0, 也没有 pidfile
	for i := 0; i < 5; i++ {
		w.clk.now = w.clk.now.Add(30 * time.Second)
		superviseDpid()
	}
	if len(w.spawns) != 0 {
		t.Fatalf("短名进程应判活, 不应反复拉起: %v", w.spawns)
	}
	if b, _ := os.ReadFile(filepath.Join(w.run, "launcher.pid")); strings.TrimSpace(string(b)) != "4300" {
		t.Fatalf("扫到后应修好 pidfile: %q", b)
	}
	// comm 只有 15 字节的长名字(hnc_dpid_supervisor → hnc_dpid_superv)照样认得出
	w.proc1(4301, "/data/local/hnc/bin/hnc_dpid_supervisor")
	if pid := m5Alive("hnc_dpid_supervisor"); pid != 4301 {
		t.Fatalf("长名进程 = %d", pid)
	}
}

// pidfile 指向的 pid 被别的进程复用 → 不算活(v5.29 只看 kill(pid,0))。
// 用本测试进程自己的 pid: kill(pid,0) 一定成功(旧判法会说「活着」), 但
// cmdline 不是 hnc_launcher。
func TestM5PidReuseNotAlive(t *testing.T) {
	w := withM5World(t)
	w.write("dpid_launcher.choice", "launcher\n")
	me := os.Getpid()
	w.proc1(me, "/system/bin/surfaceflinger")
	w.write("dpid_guard.pid", strconv.Itoa(me))
	w.write("launcher.pid", strconv.Itoa(me))
	superviseDpid()
	if len(w.spawns) != 1 || !strings.HasPrefix(w.spawns[0], "hnc_launcher") {
		t.Fatalf("pid 被复用应判死并拉起: %v", w.spawns)
	}
}

func TestCmdlineHas(t *testing.T) {
	raw := []byte("/data/local/hnc/bin/hnc_dpid\x00-config\x00/data/local/hnc/etc/dpi_config.json\x00")
	if !cmdlineHas(raw, "hnc_dpid") || cmdlineHas(raw, "hnc_dpid_supervisor") || cmdlineHas(raw, "dpid") {
		t.Fatal("cmdlineHas 口径不对")
	}
	if !cmdlineHas([]byte("sh\x00/data/local/hnc/bin/hnc_dpid_guard.sh\x00"), "hnc_dpid_guard.sh") {
		t.Fatal("解释器起的脚本应按参数认")
	}
	if cmdlineHas(nil, "hnc_dpid") || cmdlineHas(raw, "") {
		t.Fatal("空 cmdline / 空名不算")
	}
}
