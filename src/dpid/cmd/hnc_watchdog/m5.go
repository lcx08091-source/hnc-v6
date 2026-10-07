// m5.go — v5.30 T2: 迁移 M5, dpid 守护链收缩(4 层 → 2 层)。
//
// v5.29 的现状: service.sh 开机在 C hnc_launcher / shell hnc_dpid_guard.sh /
// Go hnc_dpid_supervisor 里三选一(写 run/dpid_launcher.choice), 外面还有
// service.sh 的哨兵循环(30 秒, shell)和本看门狗各自判 dpid / launcher 死活,
// 「launcher 坏了 → 直拉 dpid」的救命路径在哨兵里。
//
// 目标形态(开关 run/wd_m5.disabled 不存在 = 默认):
//   - C hnc_launcher 负责拉起 / 重启 dpid(ColorOS 上 Go 进程起子进程可能被拦,
//     所以 launcher 必须是 C);
//   - 本看门狗只盯 launcher(launcher 也挂了 → 拉 launcher), 以及 choice=direct
//     时直接盯 dpid;
//   - 救命路径搬到这里(行为照抄哨兵: launcher 不在、它的日志末 50 行里有
//     "TLS segment is underaligned" / "Aborted" / "cannot execute" /
//     "error: … executable" → dpid 不在就直拉 dpid, 并把 choice 原子改写为
//     direct)。比哨兵多一个条件: 日志要是最近 rescueLogFresh 内写过的
//     (哨兵注释写的是「最近 60 秒」, 实现只看末 50 行, 几天前的旧 abort 也算);
//     同时看 launcher.log(看门狗拉起的 launcher 写这里)与 dpid_guard.log
//     (service.sh / dpi_rebind 拉起的写这里)。
//   - service.sh 开机不再选 shell guard / Go supervisor(C launcher 不能用就
//     direct), 哨兵循环不再判 dpid / launcher(只留看门狗兜底和回滚观察)。
//     两份代码保留, 开关打开(建 run/wd_m5.disabled)即恢复 v5.29 三选一。
//
// 进程风暴防线(v5.8.8 / v5.28 A3):
//   - 判活一律 pidfile + /proc/<pid>/cmdline(argv 某段等于名字或以 "/名字"
//     结尾, 与 bin/hnc_proc.sh pid_matches 同口径), pidfile 失效才扫 /proc,
//     从不调 ps(ColorOS 的 ps 只显示短名字, 当年让哨兵每 30 秒多拉一个进程);
//     /proc/<pid>/comm 只有 15 字节(hnc_dpid_supervisor → hnc_dpid_superv),
//     所以不认 comm;
//   - 任何「发现没活 → 拉起」都过 spawnGate: 基础冷却 m5SpawnBase, 拉起后
//     m5QuickDeath 内又死 = 一次失败, 冷却按 2^失败次数 翻倍, 封顶 m5SpawnMax;
//     活过 m5QuickDeath 清零。
//   - choice 是 guard / supervisor(关着 M5 开机选的, 之后又删了开关文件)→
//     维持 v5.29 的监管方式(那个守护者可能还在跑, 换人会两个守护者抢 dpid),
//     下次开机 service.sh 按 M5 重新选。
package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	m5SwitchFile = "wd_m5.disabled" // 在 run/ 下; 存在 = 退回 v5.29 三选一

	m5SpawnBase    = 30 * time.Second // 拉起基础冷却(与 dpidRestartCD 同)
	m5SpawnMax     = 8 * time.Minute  // 冷却上限
	m5QuickDeath   = 2 * time.Minute  // 拉起后这么快又死 = 一次失败
	m5MaxBackoff   = 4                // 冷却最多翻 2^4 倍(再封顶 m5SpawnMax)
	rescueLogFresh = 10 * time.Minute // 救命路径: launcher 日志要是最近写过的
	rescueTail     = 50               // 救命路径: 看日志末尾多少行(同哨兵 tail -50)

	m5NameLauncher = "hnc_launcher"
	m5NameDpid     = "hnc_dpid"

	// 记账动作名(进 run/watchdog_actions.json, 自检「看门狗动作」可见)
	m5ActSpawnLauncher = "m5_spawn_launcher"
	m5ActSpawnDpid     = "m5_spawn_dpid"
	m5ActRescue        = "m5_rescue"
)

// 路径根与外部调用点(测试注入; 默认 = 生产)。
var (
	m5RunDir, m5LogDir, m5BinDir, m5EtcDir = runDir, logDir, binDir, hncDir + "/etc"
	m5ProcRoot                             = "/proc"
	m5SpawnFn                              = spawnDaemon
	m5LegacyFn                             = superviseDpidLegacy
)

// m5Enabled 开关文件不存在 = 启用(默认)。每轮读一次, 退回旧做法不用重刷模块。
func m5Enabled() bool {
	_, err := os.Stat(filepath.Join(m5RunDir, m5SwitchFile))
	return err != nil
}

// rescuePatterns 与哨兵 grep -qE 'TLS segment is underaligned|Aborted|cannot execute|error:.*executable' 同。
func rescueLineMatches(line string) bool {
	if strings.Contains(line, "TLS segment is underaligned") || strings.Contains(line, "Aborted") ||
		strings.Contains(line, "cannot execute") {
		return true
	}
	if i := strings.Index(line, "error:"); i >= 0 && strings.Contains(line[i:], "executable") {
		return true
	}
	return false
}

// ── 判活: pidfile + /proc/<pid>/cmdline ─────────────────────────────────

// cmdlineHas argv(NUL 分隔)里某段恰为 name 或以 "/name" 结尾。
func cmdlineHas(raw []byte, name string) bool {
	if name == "" {
		return false
	}
	for _, a := range bytes.Split(raw, []byte{0}) {
		s := string(a)
		if s == name || strings.HasSuffix(s, "/"+name) {
			return true
		}
	}
	return false
}

func procCmdline(pid int) []byte {
	b, err := os.ReadFile(filepath.Join(m5ProcRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil
	}
	return b
}

// pidfileAlive pidfile 里的 pid 还活着且确实是 name(pid 被复用成别的进程 → 0)。
func pidfileAlive(pidFile, name string) int {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0
	}
	if cmdlineHas(procCmdline(pid), name) {
		return pid
	}
	return 0
}

// procScan 扫 /proc 找 cmdline 匹配 name 的进程(排除自己)。
func procScan(name string) int {
	ents, err := os.ReadDir(m5ProcRoot)
	if err != nil {
		return 0
	}
	self := os.Getpid()
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 || pid == self {
			continue
		}
		if cmdlineHas(procCmdline(pid), name) {
			return pid
		}
	}
	return 0
}

// m5Alive 先认 pidfiles(按序), 都失效再扫 /proc; 扫到就修第一个 pidfile。
func m5Alive(name string, pidFiles ...string) int {
	for _, pf := range pidFiles {
		if pid := pidfileAlive(pf, name); pid > 0 {
			return pid
		}
	}
	pid := procScan(name)
	if pid > 0 && len(pidFiles) > 0 {
		_ = os.WriteFile(pidFiles[0], []byte(strconv.Itoa(pid)), 0o644)
	}
	return pid
}

// ── 拉起闸门(冷却 + 连续失败退避) ──────────────────────────────────────

type spawnGate struct {
	last    time.Time // 上次拉起
	fails   int       // 连续「拉起后很快又死」次数
	counted bool      // 本次拉起是否已记过失败 / 成功
}

func (g *spawnGate) cooldown() time.Duration {
	n := g.fails
	if n > m5MaxBackoff {
		n = m5MaxBackoff
	}
	cd := m5SpawnBase << uint(n)
	if cd > m5SpawnMax {
		cd = m5SpawnMax
	}
	return cd
}

// observe 每轮先报告进程死活: 拉起后 m5QuickDeath 内死了 → 失败 +1;
// 活过 m5QuickDeath → 清零。
func (g *spawnGate) observe(alive bool, now time.Time) {
	if g.last.IsZero() || g.counted {
		return
	}
	age := now.Sub(g.last)
	switch {
	case !alive && age < m5QuickDeath:
		g.fails++
		g.counted = true
	case alive && age >= m5QuickDeath:
		g.fails = 0
		g.counted = true
	case !alive:
		g.counted = true // 活过了一阵才死, 不算拉起失败
	}
}

// allow 冷却到了才放行(时钟倒退视为到了)。
func (g *spawnGate) allow(now time.Time) bool {
	if g.last.IsZero() {
		return true
	}
	d := now.Sub(g.last)
	return d < 0 || d >= g.cooldown()
}

func (g *spawnGate) spawned(now time.Time) {
	g.last = now
	g.counted = false
}

var m5Gates = map[string]*spawnGate{}

func m5Gate(name string) *spawnGate {
	g := m5Gates[name]
	if g == nil {
		g = &spawnGate{}
		m5Gates[name] = g
	}
	return g
}

// ── 主入口 ────────────────────────────────────────────────────────────

func m5Pid(name string) string { return filepath.Join(m5RunDir, name) }

// superviseDpidM5 M5 形态下每轮的 dpid 守护(mainLoop 调)。
func superviseDpidM5(choice string, now time.Time) {
	switch choice {
	case "guard", "supervisor":
		m5LegacyFn(choice) // 旧值兼容(见文件头)
		return
	case "direct":
		m5EnsureDpid(now)
		return
	}
	// "launcher" / ""(choice 缺失: launcher 二进制在就按 launcher, 不在就 direct)
	if _, err := os.Stat(filepath.Join(m5BinDir, m5NameLauncher)); err != nil && choice == "" {
		m5EnsureDpid(now)
		return
	}
	g := m5Gate(m5NameLauncher)
	alive := m5Alive(m5NameLauncher, m5Pid("launcher.pid"), m5Pid("dpid_guard.pid")) > 0
	g.observe(alive, now)
	if alive {
		return
	}
	if m5Rescue(now) {
		return
	}
	bin := filepath.Join(m5BinDir, m5NameLauncher)
	if _, err := os.Stat(bin); err != nil || !g.allow(now) {
		return
	}
	logf("M5: hnc_launcher gone, launching (cooldown=%v fails=%d)", g.cooldown(), g.fails)
	err := m5SpawnFn(bin, nil, filepath.Join(m5LogDir, "launcher.log"), m5Pid("launcher.pid"))
	g.spawned(now)
	m5Record(m5ActSpawnLauncher, err, now)
}

// m5EnsureDpid choice=direct: dpid 不在(且 launcher 也不在 —— 在的话它会拉)就直拉。
func m5EnsureDpid(now time.Time) {
	g := m5Gate(m5NameDpid)
	alive := m5Alive(m5NameDpid, m5Pid("dpid.pid")) > 0
	g.observe(alive, now)
	if alive || m5Alive(m5NameLauncher, m5Pid("launcher.pid"), m5Pid("dpid_guard.pid")) > 0 {
		return
	}
	m5SpawnDpid(now, g)
}

func m5SpawnDpid(now time.Time, g *spawnGate) {
	bin := filepath.Join(m5BinDir, m5NameDpid)
	if _, err := os.Stat(bin); err != nil || !g.allow(now) {
		return
	}
	logf("M5: hnc_dpid gone (direct mode), launching (cooldown=%v fails=%d)", g.cooldown(), g.fails)
	err := m5SpawnFn(bin, []string{"-config", filepath.Join(m5EtcDir, "dpi_config.json")},
		filepath.Join(m5LogDir, "dpid.log"), m5Pid("dpid.pid"))
	g.spawned(now)
	m5Record(m5ActSpawnDpid, err, now)
}

// launcherBroken launcher 的日志(最近 rescueLogFresh 内写过)末 rescueTail 行有 abort 字样。
func launcherBroken(now time.Time) bool {
	for _, f := range []string{"launcher.log", "dpid_guard.log"} {
		p := filepath.Join(m5LogDir, f)
		st, err := os.Stat(p)
		if err != nil || now.Sub(st.ModTime()) > rescueLogFresh {
			continue
		}
		for _, ln := range tailLines(p, rescueTail) {
			if rescueLineMatches(ln) {
				return true
			}
		}
	}
	return false
}

// tailLines 文件末 n 行(只读最后 64 KiB)。
func tailLines(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	const maxTail = 64 << 10
	if st, err := f.Stat(); err == nil && st.Size() > maxTail {
		_, _ = f.Seek(st.Size()-maxTail, 0)
	}
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), maxTail)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return lines
}

// m5Rescue 救命路径(从哨兵搬来): launcher 坏了 → dpid 不在就直拉, choice 改写为 direct。
func m5Rescue(now time.Time) bool {
	if !launcherBroken(now) {
		return false
	}
	logf("M5: launcher broken (abort detected), fallback to direct dpid")
	g := m5Gate(m5NameDpid)
	if m5Alive(m5NameDpid, m5Pid("dpid.pid")) == 0 {
		m5SpawnDpid(now, g)
	}
	err := writeLauncherChoice("direct")
	if err != nil {
		logf("M5: write choice=direct: %v", err)
	}
	m5Record(m5ActRescue, err, now)
	return true
}

// writeLauncherChoice 原子改写 run/dpid_launcher.choice(tmp + rename, 同哨兵)。
func writeLauncherChoice(c string) error {
	p := m5Pid("dpid_launcher.choice")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(c+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func m5Record(name string, err error, now time.Time) {
	rc := 0
	if err != nil {
		rc = 1
		logf("M5: %s failed: %v", name, err)
	}
	runStatsFn(name, rc, err, 0, now)
}

// superviseDpidLegacy v5.29 的按 choice 四路监管(开关关闭时 / 旧值兼容时用)。
func superviseDpidLegacy(choice string) {
	superviseLauncher, superviseSupervisor, superviseShellGuard, superviseDpidDirect := dpidGuardPlan(choice)
	if superviseLauncher {
		// v5.5.0-rc6: launcher 监管必须在 dpid 之前, 因为 dpid 的 ensureDaemonRunning
		// 入口会 findLiveByName("hnc_launcher") 决定要不要 short-circuit. 这一行
		// 保证 launcher 死后下一 tick 就被拉起来, 紧接着 dpid 检查就能看到 launcher
		// 活了, 走 short-circuit, 让 launcher 接管 dpid (避免双重 spawn).
		ensureDaemonRunning(launcherDaemon())
	}
	if superviseSupervisor {
		ensureDaemonRunning(dpidDaemon())
	}
	if superviseShellGuard {
		ensureShellGuardRunning()
	}
	if superviseDpidDirect {
		ensureDaemonRunning(dpidDaemonDirect())
	}
}
