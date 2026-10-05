// hnc_watchdog — rc30.1
//
// Static Go replacement for the main loop and process management portions
// of bin/watchdog.sh. The shell script itself remains in the module as
// `watchdog.sh action <name>`, invoked by this binary to run individual
// business actions (check_health, full_restore, full_init, migrate, etc.)
// against iptables/tc. The shell business logic has been hardened over
// many rc cycles on real devices and is not worth rewriting in Go.
//
// What's Go-native here (rc30.1):
//   - Main loop and state machine (PENDING / ACTIVE:iface)
//   - Daemon lifecycle (hotspotd / hnc_httpd / hnc_dpid_supervisor)
//   - Heartbeat + log rotation + spawn lock
//   - Restart cooldown bookkeeping (no more silent restart storms)
//   - Doze detection, INTERVAL_DOZE handling
//   - PATH-independent / no /system/bin/* dependency in the supervision loop
//
// v5.26: the legacy shell main loop in watchdog.sh has been removed; the
// script only serves `action` subcommands forked by this binary. If this
// binary is missing, service.sh logs FATAL and no watchdog runs (no shell
// fallback anymore).
package main

import (
        "bufio"
        "context"
        "errors"
        "flag"
        "fmt"
        "hnc.io/dpid/tzlocal"
        "io"
        "os"
        "os/exec"
        "os/signal"
        "path/filepath"
        "strconv"
        "strings"
        "sync"
        "syscall"
        "time"

        "hnc.io/dpid/alert"
)

// ─── constants ───────────────────────────────────────────────────────────

const (
        hncDir   = "/data/local/hnc"
        runDir   = hncDir + "/run"
        logDir   = hncDir + "/logs"
        binDir   = hncDir + "/bin"
        dataDir  = hncDir + "/data"
        wdShell  = binDir + "/watchdog.sh"
        wdLog    = logDir + "/watchdog.log"
        stateFil = runDir + "/hnc_state"

        hbFile      = runDir + "/watchdog.heartbeat"
        wdPidFile   = runDir + "/watchdog.pid"
        spawnLock   = runDir + "/spawn.lock"
        doztMarker  = runDir + "/doze.marker"
        passiveMark = runDir + "/passive.marker"

        intervalNormal    = 60 * time.Second
        intervalRecovery  = 30 * time.Second
        intervalProbe     = 10 * time.Second // PENDING state probe
        intervalDoze      = 180 * time.Second
        heartbeatTick     = 20 * time.Second // v5.25: 5→20s(接管阈值 120s, 余量足够; 少 540 次写/小时)
        takeoverStaleSec  = 120
        logRotateInterval = 6 * time.Hour
        logMaxBytes       = 1 << 20 // 1 MiB

        // Restart cooldowns
        dpidRestartCD     = 30 * time.Second
        hotspotdRestartCD = 60 * time.Second
        httpdRestartCD    = 30 * time.Second

        // Restore window throttle (mirror watchdog.sh)
        restoreWindowSec    = 300
        restoreWindowSecMax = 3600
        restoreWindowMax    = 5

        actionTimeout = 30 * time.Second

        version = "0.1.0-rc30.1"
)

// ─── globals ─────────────────────────────────────────────────────────────

var (
        logFile *os.File
        logMu   sync.Mutex

        stopCh   = make(chan struct{})
        stopOnce sync.Once
)

// ─── log + heartbeat ─────────────────────────────────────────────────────

func openLog() {
        _ = os.MkdirAll(logDir, 0o755)
        f, err := os.OpenFile(wdLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
        if err == nil {
                logFile = f
        }
}

func logf(format string, args ...interface{}) {
        msg := fmt.Sprintf(format, args...)
        line := fmt.Sprintf("[%s] [WDG-GO] %s\n", time.Now().Format("15:04:05"), msg)
        logMu.Lock()
        defer logMu.Unlock()
        if logFile != nil {
                _, _ = logFile.WriteString(line)
        }
}

// rotateLogIfBig moves wdLog → wdLog.1 when it exceeds logMaxBytes.
func rotateLogIfBig() {
        st, err := os.Stat(wdLog)
        if err != nil || st.Size() < logMaxBytes {
                return
        }
        // v5.12: 自死锁修复。旧代码 defer Unlock 持着 logMu 调 logf, 而 logf 自己
        // 也要 logMu(Go Mutex 不可重入)→ watchdog.log 一旦 ≥1MiB, 6h 一次的轮转
        // 检查就把主循环永久卡死; 心跳 goroutine 不打日志照常刷新, 不会触发接管,
        // 于是 httpd/hotspotd/launcher 的拉起、规则恢复、告警扫描全部静默停摆。
        logMu.Lock()
        if logFile != nil {
                _ = logFile.Close()
        }
        _ = os.Rename(wdLog, wdLog+".1")
        f, _ := os.OpenFile(wdLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
        logFile = f
        logMu.Unlock()
        logf("log rotated (>%d bytes)", logMaxBytes)
}

func heartbeatLoop() {
        t := time.NewTicker(heartbeatTick)
        defer t.Stop()
        writeHeartbeat()
        for {
                select {
                case <-stopCh:
                        return
                case <-t.C:
                        writeHeartbeat()
                }
        }
}

func writeHeartbeat() {
        _ = os.WriteFile(hbFile, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o644)
}

// ─── lock with heartbeat takeover ───────────────────────────────────────

func acquireLock() bool {
        if data, err := os.ReadFile(wdPidFile); err == nil {
                oldPid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
                if oldPid > 0 && oldPid != os.Getpid() && processAlive(oldPid) {
                        age := readHeartbeatAge()
                        if age >= 0 && age < takeoverStaleSec {
                                logf("another watchdog already running pid=%d (heartbeat fresh, %ds)", oldPid, age)
                                return false
                        }
                        logf("watchdog pid=%d alive but heartbeat stale (age=%ds); taking over", oldPid, age)
                        _ = syscall.Kill(oldPid, syscall.SIGTERM)
                        time.Sleep(500 * time.Millisecond)
                        if processAlive(oldPid) {
                                _ = syscall.Kill(oldPid, syscall.SIGKILL)
                                time.Sleep(300 * time.Millisecond)
                        }
                }
        }
        _ = os.MkdirAll(runDir, 0o755)
        return os.WriteFile(wdPidFile, []byte(strconv.Itoa(os.Getpid())), 0o644) == nil
}

func releaseLock() {
        if data, err := os.ReadFile(wdPidFile); err == nil {
                owner, _ := strconv.Atoi(strings.TrimSpace(string(data)))
                if owner == os.Getpid() {
                        _ = os.Remove(wdPidFile)
                }
        }
}

func readHeartbeatAge() int64 {
        data, err := os.ReadFile(hbFile)
        if err != nil {
                return -1
        }
        hb, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
        if err != nil || hb <= 0 {
                return -1
        }
        return time.Now().Unix() - hb
}

func processAlive(pid int) bool {
        return syscall.Kill(pid, 0) == nil
}

// ─── action invocation (sh watchdog.sh action <name> [args...]) ─────────

type actionResult struct {
        exitCode int
        stdout   string
        err      error
}

// shellPath returns the shell interpreter to run business-logic scripts with.
// Prefers /system/bin/sh, but falls back to the /data mksh copy that
// service.sh provisions (/data is never unmounted) when SukiSU has transiently
// unmounted /system/bin at runtime. Evaluated per call (not cached) because
// /system/bin can come and go while we run. Scripts are mksh dialect, so the
// fallback must be the mksh copy at binDir/sh, not a busybox ash.
func shellPath() string {
        const sysSh = "/system/bin/sh"
        if _, err := os.Stat(sysSh); err == nil {
                return sysSh
        }
        if fb := binDir + "/sh"; func() bool { _, e := os.Stat(fb); return e == nil }() {
                return fb
        }
        return sysSh // last resort; let exec surface the real error
}

// runAction forks watchdog.sh with the action subcommand. Returns the
// subcommand's exit code, captured stdout, and any spawn-level error.
//
// Important: this is the *only* place where we shell out for business logic.
// All other supervision work (process management, heartbeats, state) is
// pure Go and doesn't touch /system/bin/* tools.
func runAction(name string, args ...string) actionResult {
        start := nowFn() // v5.28 A2: 耗时统计
        ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
        defer cancel()

        cmdArgs := append([]string{wdShell, "action", name}, args...)
        cmd := exec.CommandContext(ctx, shellPath(), cmdArgs...)
        cmd.Env = os.Environ()
        // Isolate from our own pgrp so action kills don't propagate to us.
        cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
        // v5.12: 超时时杀整个进程组, 并限定 sh 退出后等待 stdout 管道关闭的时间。
        // 旧代码只杀 sh 本身, 而 cmd.Output() 要等 stdout 管道的所有写端关闭:
        // watchdog.sh 的 do_full_init 末尾有未重定向的 "( sleep 15; ... ) &"
        // 子 shell 继承了这根管道 → 每次 full_init 主循环至少白等 15s+; 若子孙
        // 进程卡住, 30s 超时也救不回来(Wait 仍阻塞在管道上), 主循环整体停摆。
        cmd.Cancel = func() error {
                if cmd.Process != nil {
                        _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
                }
                return nil
        }
        cmd.WaitDelay = 2 * time.Second

        out, err := cmd.Output()
        rc := 0
        if err != nil {
                var ee *exec.ExitError
                if errors.As(err, &ee) {
                        rc = ee.ExitCode()
                        err = nil
                } else if errors.Is(err, exec.ErrWaitDelay) {
                        // v5.12: sh 已正常退出, 只是后台子孙仍持有 stdout —— 按成功处理。
                        if cmd.ProcessState != nil {
                                rc = cmd.ProcessState.ExitCode()
                        }
                        err = nil
                }
        }
        if ctx.Err() == context.DeadlineExceeded {
                err = fmt.Errorf("action %s timed out after %v", name, actionTimeout)
                rc = -1
        }
        // v5.28 A2: 记账(失败分类见 actionstats.go); runStatsFn 测试可替换。
        elapsed := nowFn().Sub(start).Seconds() * 1000
        runStatsFn(name, rc, err, elapsed, nowFn())
        return actionResult{exitCode: rc, stdout: strings.TrimSpace(string(out)), err: err}
}

// ─── state machine ──────────────────────────────────────────────────────

type stateKind int

const (
        statePending stateKind = iota
        stateActive
)

type wdState struct {
        kind  stateKind
        iface string
}

func readState() wdState {
        data, _ := os.ReadFile(stateFil)
        s := strings.TrimSpace(string(data))
        if strings.HasPrefix(s, "ACTIVE:") {
                return wdState{kind: stateActive, iface: strings.TrimPrefix(s, "ACTIVE:")}
        }
        return wdState{kind: statePending}
}

func writeState(s wdState) {
        var str string
        switch s.kind {
        case stateActive:
                str = "ACTIVE:" + s.iface
        default:
                str = "PENDING"
        }
        _ = os.WriteFile(stateFil, []byte(str), 0o644)
}

// ─── daemon process management ──────────────────────────────────────────

type daemonSpec struct {
        name     string
        binPath  string
        args     []string
        logFile  string
        pidFile  string
        cooldown time.Duration
        // dependsOnSupervisor: this binary is launched indirectly by the dpid
        // supervisor (which itself spawns dpid). If supervisor missing,
        // fall back to a direct binPath launch.
        guardBin string
}

func dpidDaemon() daemonSpec {
        return daemonSpec{
                name:     "hnc_dpid",
                binPath:  binDir + "/hnc_dpid",
                args:     []string{"-config", hncDir + "/etc/dpi_config.json"},
                logFile:  logDir + "/dpid.log",
                pidFile:  runDir + "/dpid.pid",
                cooldown: dpidRestartCD,
                guardBin: binDir + "/hnc_dpid_supervisor", // rc30.0 preferred
        }
}

func httpdDaemon() daemonSpec {
        return daemonSpec{
                name: "hnc_httpd",
                // v5.5.0-rc6 fix: 之前是 binDir + "/hnc_httpd" 但 httpd binary 实际装在
                // hncDir + "/daemon/hnc_httpd/hnc_httpd" (跟 watchdog.sh:655 + service.sh:74 一致).
                // 错配的后果: ensureDaemonRunning 走到 os.Stat(launcher) 时永远 fail,
                // 进入 "binary missing — silently skip" 的 silent return 分支, watchdog
                // 永远不会自动重启 httpd, 用户必须手动点 KSU 重新拉起服务. 修复一行.
                binPath:  hncDir + "/daemon/hnc_httpd/hnc_httpd",
                args:     nil,
                logFile:  logDir + "/httpd.log",
                pidFile:  runDir + "/httpd.pid",
                cooldown: httpdRestartCD,
        }
}

func hotspotdDaemon() daemonSpec {
        return daemonSpec{
                name:     "hotspotd",
                binPath:  binDir + "/hotspotd",
                args:     []string{"-d"},
                logFile:  logDir + "/hotspotd.log",
                pidFile:  runDir + "/hotspotd.pid",
                cooldown: hotspotdRestartCD,
        }
}

// v5.5.0-rc6: hnc_launcher 之前没有 daemon spec, 只在 ensureDaemonRunning
// 对 dpid 的 short-circuit 里被引用 (rc3 fix: "如果 launcher 活, dpid 不要 spawn").
// 但 launcher 自己死了**没人拉**. 所以一旦 launcher 在某次启动失败 / 被 OOM /
// 任何原因消失, Go watchdog 完全感知不到, dpid 也跟着死. 加上 spec 之后,
// watchdog 跟监管其他 daemon 一样监管 launcher, 死了自动用 spawnDaemon 拉.
// launcher 重新起来后, launcher 自己会接管 dpid 的 fork, 行为跟现状一致.
func launcherDaemon() daemonSpec {
        return daemonSpec{
                name:     "hnc_launcher",
                binPath:  binDir + "/hnc_launcher",
                args:     nil,
                logFile:  logDir + "/launcher.log",
                pidFile:  runDir + "/launcher.pid",
                cooldown: 30 * time.Second,
        }
}

// ── v5.26 T2: dpid 守护者唯一权威 = run/dpid_launcher.choice ──────────────
//
// service.sh 启动时按机型探测(C launcher > shell guard > Go supervisor >
// direct)把选择原子写入 run/dpid_launcher.choice; sentinel 的救命路径检测到
// launcher 反复 abort 时会把 choice 改写为 direct。看门狗每个 tick 读一次,
// 只监管 choice 指定的那一个守护者, 不再无条件重拉 hnc_launcher(即使
// service.sh 因兼容性选了别的)。文件缺失/非法时保持旧行为。

// parseLauncherChoice 校验 choice 文件内容, 非法值返回 ""(视同缺失)。
func parseLauncherChoice(raw string) string {
        c := strings.TrimSpace(raw)
        switch c {
        case "launcher", "guard", "supervisor", "direct":
                return c
        default:
                return ""
        }
}

// readLauncherChoiceAt 读取并校验指定路径的 choice 文件(路径可注入, 供单测)。
func readLauncherChoiceAt(path string) string {
        b, err := os.ReadFile(path)
        if err != nil {
                return ""
        }
        return parseLauncherChoice(string(b))
}

func readLauncherChoice() string {
        return readLauncherChoiceAt(runDir + "/dpid_launcher.choice")
}

// dpidGuardPlan 返回该 choice 下看门狗应监管的对象(纯函数, 供单测):
//   - launcher:   只监管 hnc_launcher(它负责 dpid)
//   - guard:      只确保 hnc_dpid_guard.sh 在跑
//   - supervisor: 只走 dpidDaemon(guardBin 优先启动 hnc_dpid_supervisor)
//   - direct:     dpidDaemonDirect 直管 dpid(不重拉任何 launcher)
//   - "":         保持旧行为(launcher + dpidDaemon 两个都管)
func dpidGuardPlan(choice string) (superviseLauncher, superviseSupervisor, superviseShellGuard, superviseDpidDirect bool) {
        switch choice {
        case "launcher":
                return true, false, false, false
        case "guard":
                return false, false, true, false
        case "supervisor":
                return false, true, false, false
        case "direct":
                return false, false, false, true
        default:
                return true, true, false, false
        }
}

// dpidDaemonDirect: choice=direct 时的 dpid spec —— 去掉 guardBin,
// 确保 ensureDaemonRunning 直接拉 hnc_dpid 而不是 hnc_dpid_supervisor。
func dpidDaemonDirect() daemonSpec {
        d := dpidDaemon()
        d.guardBin = ""
        return d
}

// ensureShellGuardRunning: choice=guard 时确保 bin/hnc_dpid_guard.sh 在跑。
func ensureShellGuardRunning() bool {
        return ensureGuardScriptAt(binDir+"/hnc_dpid_guard.sh", runDir+"/dpid_guard.pid",
                "hnc_dpid_guard", logDir+"/dpid_guard.log", dpidRestartCD)
}

// ensureGuardScriptAt 是路径可注入的 shell guard 启动器(供单测):
// 先认 pidfile, 再按 comm/argv0(cmdline 子串)找活进程并顺手修复 pidfile,
// 都没有才在冷却窗口允许时拉起。
func ensureGuardScriptAt(script, pidFile, name, logPath string, cd time.Duration) bool {
        if data, err := os.ReadFile(pidFile); err == nil {
                if pid, _ := strconv.Atoi(strings.TrimSpace(string(data))); pid > 0 && processAlive(pid) {
                        return true
                }
        }
        if live := findLiveByName(name); live > 0 {
                _ = os.WriteFile(pidFile, []byte(strconv.Itoa(live)), 0o644)
                return true
        }
        if live := findLiveByCmdlineSub(filepath.Base(script)); live > 0 {
                _ = os.WriteFile(pidFile, []byte(strconv.Itoa(live)), 0o644)
                return true
        }
        if _, err := os.Stat(script); err != nil {
                return false
        }
        if !cooldownOK(name, cd) {
                return false
        }
        logf("%s: process gone, launching shell guard", name)
        out, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
        if err != nil {
                out = nil
        }
        cmd := exec.Command(shellPath(), script)
        if out != nil {
                cmd.Stdout = out
                cmd.Stderr = out
        }
        // 与 spawnDaemon 相同的进程组隔离(Setsid 不能用, ColorOS+SukiSU 会 EPERM)。
        cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
        if err := cmd.Start(); err != nil {
                logf("%s: launch failed: %v", name, err)
                if out != nil {
                        _ = out.Close()
                }
                return false
        }
        go func() {
                _ = cmd.Wait()
                if out != nil {
                        _ = out.Close()
                }
        }()
        _ = os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
        return true
}

const alertScanEvery = 5 * time.Minute

// v5.18: nDPI 实验(ndpi_continuous.sh + hnc_ndpi_probe)已删除, hnc_dpid 自己
// 提供 IP→域名(dpi_ipname.json), watchdog 不再监管它。

// lastRestart tracks per-daemon restart timestamps for cooldown enforcement.
var (
        lastRestartMu sync.Mutex
        lastRestart   = map[string]time.Time{}
)

func cooldownOK(name string, cd time.Duration) bool {
        lastRestartMu.Lock()
        defer lastRestartMu.Unlock()
        last := lastRestart[name]
        if !last.IsZero() && time.Since(last) < cd {
                return false
        }
        lastRestart[name] = time.Now()
        return true
}

// ensureDaemonRunning checks the daemon's pidfile, repairs it if a live
// process matches, otherwise (re)launches under cooldown.
//
// For dpid specifically, prefer launching the supervisor binary (rc30.0)
// when available; supervisor itself manages the dpid child.
func ensureDaemonRunning(d daemonSpec) {
        // v5.5.0-rc3 fix: hnc_launcher (C binary, added in rc30.12) was created
        // specifically to manage dpid lifecycle, bypassing the ColorOS Go fork
        // EPERM issue. If launcher is running, IT owns dpid — watchdog must NOT
        // race it. Without this check, watchdog kept trying to spawn the legacy
        // hnc_dpid_supervisor (Go binary) which hits the SAME EPERM and crashes.
        if d.name == "hnc_dpid" {
                if findLiveByName("hnc_launcher") > 0 {
                        return // launcher is running, it handles dpid; we're done
                }
        }

        // Choose launcher: supervisor takes precedence over direct binary for dpid.
        launcher := d.binPath
        launcherArgs := d.args
        watchPidFile := d.pidFile
        if d.guardBin != "" {
                if _, err := os.Stat(d.guardBin); err == nil {
                        launcher = d.guardBin
                        launcherArgs = nil
                        watchPidFile = runDir + "/dpid_guard.pid"
                }
        }

        // Is the watched pidfile alive?
        if data, err := os.ReadFile(watchPidFile); err == nil {
                if pid, _ := strconv.Atoi(strings.TrimSpace(string(data))); pid > 0 {
                        if processAlive(pid) {
                                return // healthy
                        }
                }
        }
        // Pidfile missing or stale, but the actual process might still be alive
        // under a different name (e.g. user killed pidfile manually).
        if live := findLiveByName(filepath.Base(launcher)); live > 0 {
                _ = os.WriteFile(watchPidFile, []byte(strconv.Itoa(live)), 0o644)
                logf("%s: live without pidfile, repaired (pid=%d)", d.name, live)
                return
        }

        if _, err := os.Stat(launcher); err != nil {
                // Binary missing — silently skip. service.sh may install it later.
                return
        }
        if !cooldownOK(d.name, d.cooldown) {
                return
        }

        // v5.26 T1: DNS 接管 fail-open 从 watchdog.sh ensure_httpd_running 迁来。
        // httpd 被杀/崩溃时来不及撤 DNS 接管的 DNAT → 重拉前先撤掉(新 httpd 起来会按
        // 配置重下)。放在冷却之后: 每次重拉只撤一次, 不在冷却期每轮 fork。
        if d.name == "hnc_httpd" {
                cmd := exec.Command(shellPath(), hncDir+"/bin/dns_takeover.sh", "remove")
                cmd.Stdout = io.Discard
                cmd.Stderr = io.Discard
                _ = cmd.Run()
        }

        logf("%s: process gone, launching %s", d.name, launcher)
        if err := spawnDaemon(launcher, launcherArgs, d.logFile, watchPidFile); err != nil {
                logf("%s: launch failed: %v", d.name, err)
        }
}

// spawnDaemon forks the binary in its own session, redirecting stdout/stderr
// to the daemon's log file, and writes its pid to pidFile.
func spawnDaemon(bin string, args []string, logPath, pidFile string) error {
        out, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
        if err != nil {
                out = nil
        }
        cmd := exec.Command(bin, args...)
        cmd.Env = os.Environ()
        if out != nil {
                cmd.Stdout = out
                cmd.Stderr = out
        } else {
                cmd.Stdout = io.Discard
                cmd.Stderr = io.Discard
        }
        // v5.5.0-rc3 fix: previously this was {Setpgid: true, Setsid: true}.
        // `Setsid: true` triggers ColorOS + SukiSU Go-runtime fork EPERM
        // (same root cause as the rc30.12 hnc_launcher workaround for dpid).
        // Setpgid alone gives sufficient process-group isolation; when watchdog
        // dies, spawned daemons get reparented to init and keep running. They
        // don't need their own session — watchdog has no controlling terminal
        // so there's no SIGHUP propagation to defend against.
        // Without this fix, every spawnDaemon call fails ("operation not
        // permitted") and the failure cascades: watchdog can't restart httpd
        // when it dies, user has to manually click "重新拉起服务" in KSU.
        cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
        if err := cmd.Start(); err != nil {
                if out != nil {
                        _ = out.Close()
                }
                return err
        }
        // Reap zombie on exit but don't block here.
        go func() {
                _ = cmd.Wait()
                if out != nil {
                        _ = out.Close()
                }
        }()
        _ = os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
        return nil
}

// findLiveByName scans /proc for a process whose comm or exe basename matches.
func findLiveByName(name string) int {
        entries, err := os.ReadDir("/proc")
        if err != nil {
                return 0
        }
        mypid := os.Getpid()
        for _, e := range entries {
                if !e.IsDir() {
                        continue
                }
                pid, err := strconv.Atoi(e.Name())
                if err != nil || pid <= 0 || pid == mypid {
                        continue
                }
                // Try /proc/<pid>/comm (short name).
                if data, err := os.ReadFile("/proc/" + e.Name() + "/comm"); err == nil {
                        if strings.TrimSpace(string(data)) == name {
                                return pid
                        }
                }
                // Try /proc/<pid>/cmdline for nul-separated argv.
                if data, err := os.ReadFile("/proc/" + e.Name() + "/cmdline"); err == nil {
                        argv0 := strings.SplitN(string(data), "\x00", 2)[0]
                        if filepath.Base(argv0) == name {
                                return pid
                        }
                }
        }
        return 0
}

// findLiveByCmdlineSub 在 /proc/*/cmdline 的任意 argv 段里找执行 needle 的
// 活进程(排除自己)。findLiveByName 只匹配 comm/argv0, 找不到
// `sh /data/local/hnc/bin/hnc_dpid_guard.sh` 这种以解释器启动的脚本进程,
// shell guard 的存活检测必须走这里。
func findLiveByCmdlineSub(needle string) int {
        entries, err := os.ReadDir("/proc")
        if err != nil {
                return 0
        }
        mypid := os.Getpid()
        for _, e := range entries {
                if !e.IsDir() {
                        continue
                }
                pid, err := strconv.Atoi(e.Name())
                if err != nil || pid <= 0 || pid == mypid {
                        continue
                }
                data, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
                if err != nil {
                        continue
                }
                // 只认 argv 段恰为 needle 或以 "/needle" 结尾(真正执行该脚本的进程),
                // 不误认 `grep hnc_dpid_guard.sh`、`pgrep -f ...` 之类只是提到名字的进程。
                for _, arg := range strings.Split(string(data), "\x00") {
                        if arg == needle || strings.HasSuffix(arg, "/"+needle) {
                                return pid
                        }
                }
        }
        return 0
}

// ─── doze detection ─────────────────────────────────────────────────────

// isDoze defers to watchdog.sh action is_doze (which knows the ColorOS/MIUI
// shenanigans of finding the right dumpsys field). Result cached for 30s.
var (
        dozeCacheMu sync.Mutex
        dozeCached  bool
        dozeCheckTS time.Time
)

func isDoze() bool {
        // v5.25: 亮屏或有界面在看就不可能 Doze —— 不必每 30 秒 fork 一次 watchdog.sh 问系统。
        if screenAwake() {
                return false
        }
        dozeCacheMu.Lock()
        defer dozeCacheMu.Unlock()
        if !dozeCheckTS.IsZero() && time.Since(dozeCheckTS) < 30*time.Second {
                return dozeCached
        }
        res := runAction("is_doze")
        dozeCached = res.exitCode == 0
        dozeCheckTS = time.Now()
        return dozeCached
}

// ─── restore window throttle ────────────────────────────────────────────

type restoreThrottle struct {
        windowStart   time.Time
        windowCount   int
        consecutive   int
        passiveMode   bool
        passiveExitTS time.Time
        totalRestores int
        passiveLogged bool
}

func (r *restoreThrottle) currentWindowDur() time.Duration {
        dur := time.Duration(restoreWindowSec) * time.Second
        for i := 0; i < r.consecutive && dur < time.Duration(restoreWindowSecMax)*time.Second; i++ {
                dur *= 2
        }
        if dur > time.Duration(restoreWindowSecMax)*time.Second {
                dur = time.Duration(restoreWindowSecMax) * time.Second
        }
        return dur
}

// onHealthFail returns true if a restore should be attempted now,
// false if throttled into passive mode.
func (r *restoreThrottle) onHealthFail() bool {
        now := nowFn() // v5.28 A1: 经 nowFn(默认 time.Now), budget_test 可用假时钟驱动窗口滚动
        if r.windowStart.IsZero() || now.Sub(r.windowStart) >= r.currentWindowDur() {
                r.windowStart = now
                r.windowCount = 0
                if r.passiveMode {
                        if now.Sub(r.passiveExitTS) < time.Duration(restoreWindowSec*2)*time.Second {
                                r.consecutive++
                                logf("exiting passive but re-triggering soon (consec=%d)", r.consecutive)
                        } else {
                                r.consecutive = 0
                        }
                        logf("exiting passive mode")
                        r.passiveMode = false
                        r.passiveLogged = false
                        r.passiveExitTS = now
                        _ = os.Remove(passiveMark)
                }
        }
        if r.passiveMode {
                if !r.passiveLogged {
                        logf("health_fail in passive mode, skipping restore")
                        r.passiveLogged = true
                }
                return false
        }
        r.windowCount++
        r.totalRestores++
        return true
}

func (r *restoreThrottle) onRestoreDone() {
        if r.windowCount >= restoreWindowMax {
                logf("RESTORE window limit hit, entering passive mode")
                r.passiveMode = true
                // rc30.12.14: WriteFile 替代 os.Create, 不留 FD 悬挂
                _ = os.WriteFile(passiveMark, []byte{}, 0o644)
        }
}

// ─── signal handling ────────────────────────────────────────────────────

func handleSignals() {
        ch := make(chan os.Signal, 4)
        signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
        go func() {
                sig := <-ch
                logf("received signal %v, shutting down", sig)
                stopOnce.Do(func() { close(stopCh) })
                go func() {
                        <-ch
                        logf("second signal, forced exit")
                        os.Exit(2)
                }()
        }()
}

// ─── main loop ──────────────────────────────────────────────────────────

func mainLoop() {
        // v5.28 A1: 每轮可变状态收进 loopState(见 budget.go), tick() 可被
        // budget_test 用假时钟直接驱动; 睡眠与 daemon 保活仍留在本函数。
        ls := newLoopState()

        for {
                if !ls.firstRound {
                        interval := ls.currentInterval
                        if isDozeFn() {
                                interval = intervalDoze
                        }
                        // v5.25: 定时开关热点的边界 / 充电检查时刻不能睡过头
                        if d := hsSched.maxSleep(nowFn()); d >= 0 && d < interval {
                                interval = d
                        }
                        if ok, _ := sleepOrWake(interval); !ok {
                                return
                        }
                }
                ls.firstRound = false

                ls.tick(readState())

                // Daemon supervision (regardless of state)
                ensureDaemonRunning(hotspotdDaemon())
                ensureDaemonRunning(httpdDaemon())
                // v5.26 T2: 只监管 run/dpid_launcher.choice 指定的那一个 dpid 守护者
                // (service.sh 机型探测后落盘, sentinel 救命路径可改写为 direct);
                // 文件缺失/非法时保持旧行为(launcher + dpid 都管)。
                superviseLauncher, superviseSupervisor, superviseShellGuard, superviseDpidDirect := dpidGuardPlan(readLauncherChoice())
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
}

func handlePending(_ *restoreThrottle) time.Duration {
        res := runActionFn("probe_hotspot")
        if res.exitCode != 0 || res.stdout == "" {
                return intervalProbe
        }
        parts := strings.Fields(res.stdout)
        if len(parts) < 2 {
                logf("probe_hotspot returned unexpected output: %q", res.stdout)
                return intervalProbe
        }
        iface, ip := parts[0], parts[1]
        logf("STATE PENDING -> ACTIVE:%s (ip=%s); running full_init", iface, ip)
        res = runActionFn("full_init", iface, ip)
        if res.exitCode != 0 {
                logf("full_init returned rc=%d; staying PENDING", res.exitCode)
                return intervalProbe
        }
        writeStateFn(wdState{kind: stateActive, iface: iface})
        return intervalNormal
}

// handleActive ACTIVE:<iface> 状态每轮的职责。aux 携带每轮可变状态
// (v5.28 A1 抽出, budget_test 用假时钟驱动)。
func handleActive(activeIface string, throttle *restoreThrottle, aux *activeAux) time.Duration {
        probe := runActionFn("probe_hotspot")
        if probe.exitCode != 0 || probe.stdout == "" {
                // Hotspot down — keep ACTIVE state (user might just have toggled off),
                // don't migrate or full_restore. Next round will re-probe.
                return intervalNormal
        }
        parts := strings.Fields(probe.stdout)
        if len(parts) < 2 {
                return intervalNormal
        }
        newIface, newIP := parts[0], parts[1]

        // Iface changed → migrate
        if newIface != activeIface {
                logf("iface changed %s -> %s; migrating", activeIface, newIface)
                res := runActionFn("migrate", activeIface, newIface, newIP)
                if res.exitCode == 0 {
                        writeStateFn(wdState{kind: stateActive, iface: newIface})
                } else {
                        logf("migrate rc=%d", res.exitCode)
                }
                return intervalNormal
        }

        // Capability probe (lightweight) — v5.28 A1: 启动首轮 / 网卡变化 /
        // ≥6 小时才探测(原每轮)。shell 侧 capability_probe.sh 的节流保留作双保险。
        now := nowFn()
        if aux.cap.due(newIface, now) {
                _ = runActionFn("capability_probe", newIface)
                aux.cap.mark(newIface, now)
        }

        // Health check
        health := runActionFn("check_health")
        switch health.exitCode {
        case 0:
                // Healthy
                recovering := aux.recoveryRounds > 0
                if aux.recoveryRounds > 0 {
                        aux.recoveryRounds--
                }
                // Periodic side tasks
                now := nowFn()
                if now.Sub(aux.lastV6Sync) >= 60*time.Second {
                        runV6SyncFn()
                        aux.lastV6Sync = now
                }
                // v5.25: 300 秒(无在线设备 900 秒), 与 shell 版 / power_sched.go 一致; 原来每轮(60 秒)都跑
                if statsSampleDue(aux.lastStatsSample, now) {
                        runStatsSampleFn()
                        aux.lastStatsSample = now
                }
                // v5.25: 在线时长采样(Go 版从没做过, 「在线时长」因此恒为空)
                sampleOnlineHours(now)
                // v5.28 A1: 健康且不在恢复期 → httpd_drift 5 分钟一次、
                // tc_uplink_healthy 3 分钟一次(原每轮 60 秒); 恢复期照旧每轮。
                // 最坏影响: 上行 ingress 重定向丢失最长约 3 分钟被复核发现(原 1 分钟)。
                if recovering || now.Sub(aux.lastDrift) >= httpdDriftEvery {
                        _ = runActionFn("httpd_drift")
                        aux.lastDrift = now
                }
                if recovering || now.Sub(aux.lastUplink) >= tcUplinkEvery {
                        _ = runActionFn("tc_uplink_healthy")
                        aux.lastUplink = now
                }
                return intervalNormal

        case 2:
                // Transient error (xtables lock busy etc.), skip this round
                return intervalNormal

        default:
                // Rules truly lost → restore (subject to throttle)
                if !throttle.onHealthFail() {
                        return intervalNormal
                }
                res := runActionFn("full_restore",
                        fmt.Sprintf("health_fail (total=%d, window=%d/%d)",
                                throttle.totalRestores, throttle.windowCount, restoreWindowMax))
                if res.exitCode != 0 {
                        logf("full_restore rc=%d", res.exitCode)
                }
                throttle.onRestoreDone()
                aux.recoveryRounds = 3
                return intervalRecovery
        }
}

// runV6Sync forks bin/v6_sync.sh — independent of watchdog.sh, so just direct exec.
func runV6Sync() {
        cmd := exec.Command(shellPath(), binDir+"/v6_sync.sh", "sync")
        cmd.Env = os.Environ()
        // v5.12: nil = /dev/null。io.Discard 会让 exec 建管道 + 拷贝 goroutine,
        // 脚本里任何继承 stdout 的后台子进程都会让 Run() 阻塞到它退出, 主循环随之卡住。
        cmd.Stdout, cmd.Stderr = nil, nil
        cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
        _ = cmd.Run()
}

// runScript 执行一个 bin/ 下的脚本(stdout/stderr 丢弃, 独立进程组), 同 runV6Sync。
func runScript(path string, args ...string) {
        cmd := exec.Command(shellPath(), append([]string{path}, args...)...)
        cmd.Env = os.Environ()
        cmd.Stdout, cmd.Stderr = nil, nil
        cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
        _ = cmd.Run()
}

func runStatsSample() {
        cmd := exec.Command(shellPath(), binDir+"/stats_sample.sh")
        cmd.Env = os.Environ()
        // v5.12: nil = /dev/null。io.Discard 会让 exec 建管道 + 拷贝 goroutine,
        // 脚本里任何继承 stdout 的后台子进程都会让 Run() 阻塞到它退出, 主循环随之卡住。
        cmd.Stdout, cmd.Stderr = nil, nil
        cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
        _ = cmd.Run()
}

// ─── utility ─────────────────────────────────────────────────────────────

func sleepUntil(d time.Duration) bool {
        t := time.NewTimer(d)
        defer t.Stop()
        select {
        case <-stopCh:
                return false
        case <-t.C:
                return true
        }
}

// readFirstLine is unused right now but kept here as a known-clean helper
// for parsing /proc files when we eventually pull is_doze into Go.
func readFirstLine(path string) (string, error) {
        f, err := os.Open(path)
        if err != nil {
                return "", err
        }
        defer f.Close()
        sc := bufio.NewScanner(f)
        if sc.Scan() {
                return sc.Text(), nil
        }
        return "", sc.Err()
}

var _ = readFirstLine // keep helper available without compile warning

// ─── entrypoint ─────────────────────────────────────────────────────────

func main() {
        showVer := flag.Bool("version", false, "print version and exit")
        flag.Parse()
        if *showVer {
                fmt.Println(version)
                return
        }

        // v5.25: Android 上 Go 的 time.Local 恒为 UTC(见 tzlocal 包注释)。httpd 早就设了, 这里一直没设 →
        // 定时开关热点的时段边界、在线时长的日期、告警免打扰时段都按 UTC 算(东八区差 8 小时)。
        time.Local = tzlocal.Location()

        openLog()
        logf("hnc_watchdog %s starting, pid=%d", version, os.Getpid())

        if !acquireLock() {
                os.Exit(0)
        }
        defer releaseLock()

        if _, err := os.Stat(wdShell); err != nil {
                logf("FATAL: shell action driver missing at %s, cannot supervise", wdShell)
                os.Exit(3)
        }

        handleSignals()
        go heartbeatLoop()
        startLinkWatch() // v5.25: 网卡 / 地址事件即时唤醒主循环(热点开关不再靠 10 秒轮询)

        // rc30.5: alert scanner — detect unknown devices every 5 minutes.
        // Independent of the main supervision loop so a slow alert pass can't
        // block daemon restarts.
        go alertScanLoop()

        // rc30.6: per-app rate-limit applier — fork apply_app_limits.sh
        // every 30 seconds, or immediately when a dirty marker is present
        // (set by hnc_httpd after a successful POST /api/action app_limit_*).
        go appLimitApplyLoop()

        mainLoop()
        logf("hnc_watchdog exiting normally")
}

// appLimitApplyLoop runs apply_app_limits.sh on a 30s cadence. The shell
// script does a full iptables+tc rebuild each invocation; we just kick it.
// A dirty marker at /run/app_limit.dirty triggers an immediate re-apply
// — used by the WebUI for instant feedback after a rate change.
func appLimitApplyLoop() {
        script := binDir + "/apply_app_limits.sh"
        dirty := runDir + "/app_limit.dirty"
        // Initial delay: let dpid produce ip_app_map first.
        if !sleepUntil(45 * time.Second) {
                return
        }
        tk := time.NewTicker(30 * time.Second)
        defer tk.Stop()
        for {
                // v5.25: 热点未开时没有客户端流量可限, 不跑全量 iptables/tc 重建(每 30 秒一次 fork)。
                // 开热点后下一个 30 秒节拍内恢复; full_init 时规则本身也会重建。
                if _, err := os.Stat(script); err == nil && !hotspotIdle() {
                        cmd := exec.Command(shellPath(), script)
                        cmd.Env = os.Environ()
                        cmd.Stdout, cmd.Stderr = nil, nil // v5.12: 同 runV6Sync, 不建管道
                        cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
                        _ = cmd.Run()
                }
                // Wait for next tick OR an immediate dirty-marker request.
                select {
                case <-stopCh:
                        return
                case <-tk.C:
                case <-pollDirty(dirty):
                        // re-apply right away
                }
        }
}

// pollDirty returns a channel that fires once the dirty marker appears.
// We use polling rather than inotify because Android's filesystem layer
// is inconsistent across vendor kernels for inotify on /data.
func pollDirty(path string) <-chan struct{} {
        out := make(chan struct{}, 1)
        go func() {
                // v5.25: 1 秒 → 3 秒一查(30 秒窗口内唤醒 30 次 → 10 次); 界面改限速后最多慢 2 秒生效。
                for i := 0; i < 10; i++ {
                        time.Sleep(3 * time.Second)
                        if _, err := os.Stat(path); err == nil {
                                out <- struct{}{}
                                return
                        }
                }
                // Timed out without marker; channel closes silently. Tick path wins.
        }()
        return out
}

// alertScanLoop runs alert.Run() on a 5-minute cadence. It logs new alerts
// to the watchdog log so operators have a single timeline to read.
func alertScanLoop() {
        cfg := alert.NewConfig(hncDir)
        // Initial delay so we don't fire alerts before hotspotd has had a
        // chance to write devices.json on a cold boot.
        if !sleepUntil(30 * time.Second) {
                return
        }
        tk := time.NewTicker(alertScanEvery)
        defer tk.Stop()
        for {
                // Run once at entry, then every tick.
                n, err := alert.Run(cfg)
                if err != nil {
                        logf("alert scan error: %v", err)
                } else if n > 0 {
                        logf("alert scan: emitted %d new alert(s)", n)
                }
                select {
                case <-stopCh:
                        return
                case <-tk.C:
                }
        }
}
