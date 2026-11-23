// hnc_watchdog — rc30.1 / v6.0 Vector
//
// Static Go replacement for the main loop and process management portions
// of bin/watchdog.sh. The shell script itself remains in the module as
// `watchdog.sh action <name>`, invoked by this binary to run individual
// business actions (full_restore, full_init, migrate, tc_uplink_healthy,
// etc.) against iptables/tc. The shell business logic has been hardened over
// many rc cycles on real devices and is not worth rewriting in Go. The
// checks that decide when to act (hotspot probe, rules health, uplink) live
// only in Go since v5.33 (native.go).
//
// v6.0 Anti-Freeze Hardening:
//   - heartbeatLoop() is strictly bound to mainLoop()'s monotonic clock step:
//     watchdog.heartbeat is ONLY refreshed when mainLoop stall age < 90s;
//     if mainLoop stalls >= 120s, watchdog logs an alert and exits cleanly so
//     sentinel relaunches a fresh supervisor (ending "brain-dead normal pulse").
//   - dns_takeover.sh remove, runV6Sync, runStatsSample, and runScript all
//     enforce 15s context timeouts with Setpgid + -pgid SIGKILL + WaitDelay.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"hnc.io/dpid/activity"
	"hnc.io/dpid/alert"
	"hnc.io/dpid/tzlocal"
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
	passiveMark = runDir + "/watchdog_passive.marker"

	intervalNormal     = 60 * time.Second
	intervalRecovery   = 30 * time.Second
	intervalProbe      = 10 * time.Second // PENDING state probe
	intervalDoze       = 180 * time.Second
	heartbeatTick      = 20 * time.Second // v5.25: 5→20s(接管阈值 120s, 余量足够; 少 540 次写/小时)
	mainLoopHbMaxStale = 90 * time.Second
	mainLoopStallFatal = 120 * time.Second
	auxScriptTimeout   = 15 * time.Second
	takeoverStaleSec   = 120
	logRotateInterval  = 6 * time.Hour
	logMaxBytes        = 1 << 20 // 1 MiB

	// Restart cooldowns
	hotspotdRestartCD = 60 * time.Second
	httpdRestartCD    = 30 * time.Second

	// Restore window throttle (mirror watchdog.sh)
	restoreWindowSec    = 300
	restoreWindowSecMax = 3600
	restoreWindowMax    = 5

	actionTimeout = 30 * time.Second

	engineVersion = "0.6.0"
)

var (
	moduleVersion = "dev"
	versionCode   = "0"
	version       = engineVersion + "-" + moduleVersion
)

func readWatchdogModuleProp(baseDir string) (modVer, verCode string) {
	candidates := []string{
		hncDir + "/module.prop",
		"/data/adb/modules/hotspot_net_ctl/module.prop",
		"/data/adb/modules/hotspot_network_control/module.prop",
	}
	if cleanDir := strings.TrimSpace(baseDir); cleanDir != "" {
		candidates = append([]string{filepath.Join(cleanDir, "module.prop")}, candidates...)
	}
	seen := make(map[string]struct{}, len(candidates))
	for _, p := range candidates {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var fv, fc string
		for _, raw := range strings.Split(string(b), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if v, ok := strings.CutPrefix(line, "version="); ok && fv == "" {
				fv = strings.TrimSpace(v)
			} else if c, ok := strings.CutPrefix(line, "versionCode="); ok && fc == "" {
				fc = strings.TrimSpace(c)
			}
		}
		if fv != "" || fc != "" {
			return fv, fc
		}
	}
	return "", ""
}

func resolveWatchdogVersion(baseDir string) {
	modVer := strings.TrimSpace(moduleVersion)
	verCode := strings.TrimSpace(versionCode)
	if modVer == "" || modVer == "dev" || verCode == "" || verCode == "0" {
		fv, fc := readWatchdogModuleProp(baseDir)
		if (modVer == "" || modVer == "dev") && fv != "" {
			modVer = fv
		}
		if (verCode == "" || verCode == "0") && fc != "" {
			verCode = fc
		}
	}
	if modVer == "" {
		modVer = "dev"
	}
	if verCode == "" {
		verCode = "0"
	}
	if trimmed, ok := strings.CutPrefix(modVer, engineVersion+"-"); ok && trimmed != "" {
		modVer = trimmed
	}
	moduleVersion = modVer
	versionCode = verCode
	version = engineVersion + "-" + modVer
}

func currentWatchdogVersion() string {
	modVer := strings.TrimSpace(moduleVersion)
	if modVer == "" {
		return engineVersion + "-dev"
	}
	if strings.HasPrefix(modVer, engineVersion+"-") {
		return modVer
	}
	return engineVersion + "-" + modVer
}

// ─── globals & monotonic progress vector ────────────────────────────────

var (
	logFile *os.File
	logMu   sync.Mutex

	stopCh   = make(chan struct{})
	stopOnce sync.Once

	// v6.0: 单调时钟锚点与 mainLoop 活性绑定(不受 NTP 墙钟跳变影响)
	wdBootEpoch            = time.Now()
	wdMonoNowFn            = wdMonoSinceBootNs
	lastMainLoopStepMonoNs atomic.Int64
	mainLoopSleepEndMonoNs atomic.Int64

	// 单测注入钩子
	wdHeartbeatPath = hbFile
	wdAlertBaseDir  = hncDir
	wdStallExitFn   = os.Exit
)

func init() {
	lastMainLoopStepMonoNs.Store(wdMonoNowFn())
}

func wdMonoSinceBootNs() int64 {
	d := time.Since(wdBootEpoch)
	if d < 0 {
		return 0
	}
	return int64(d)
}

func touchMainLoopStep() {
	lastMainLoopStepMonoNs.Store(wdMonoNowFn())
}

func beginMainLoopSleep(d time.Duration) {
	nowM := wdMonoNowFn()
	lastMainLoopStepMonoNs.Store(nowM)
	if d > 0 {
		mainLoopSleepEndMonoNs.Store(nowM + int64(d) + int64(5*time.Second))
	}
}

func endMainLoopSleep() {
	mainLoopSleepEndMonoNs.Store(0)
	lastMainLoopStepMonoNs.Store(wdMonoNowFn())
}

func currentMainLoopStallAge(nowMono int64) time.Duration {
	if sleepEnd := mainLoopSleepEndMonoNs.Load(); sleepEnd > 0 {
		if nowMono <= sleepEnd {
			return 0
		}
		return time.Duration(nowMono - sleepEnd)
	}
	last := lastMainLoopStepMonoNs.Load()
	if last <= 0 || nowMono <= last {
		return 0
	}
	return time.Duration(nowMono - last)
}

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

var wdLogPath = wdLog

// rotateLogIfBig 采用 copytruncate 原地轮转日志(复制副本至 .1 后原地 Truncate(0)),
// 保持原文件 inode 不变, 避免长驻句柄继续写向被重命名的旧 inode。
func rotateLogIfBig() {
	st, err := os.Stat(wdLogPath)
	if err != nil || st.Size() < logMaxBytes {
		return
	}
	logMu.Lock()
	copied := copyLogBackup(wdLogPath, wdLogPath+".1")
	if copied || st.Size() >= 4*logMaxBytes {
		_ = os.Truncate(wdLogPath, 0)
		if logFile != nil && wdLogPath == wdLog {
			_ = logFile.Truncate(0)
		}
	}
	logMu.Unlock()
	if copied {
		logf("log rotated via copytruncate (>%d bytes)", logMaxBytes)
	}
}

func copyLogBackup(srcPath, dstPath string) bool {
	src, err := os.Open(srcPath)
	if err != nil {
		return false
	}
	defer src.Close()
	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return false
	}
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	return copyErr == nil && closeErr == nil
}

func heartbeatLoop() {
	t := time.NewTicker(heartbeatTick)
	defer t.Stop()
	heartbeatTickOnce()
	for {
		select {
		case <-stopCh:
			return
		case <-t.C:
			heartbeatTickOnce()
		}
	}
}

// heartbeatTickOnce 仅在 mainLoop 单调时钟进度停滞 < 90s 时刷新 watchdog.heartbeat;
// 若 mainLoop 卡死 >= 120s, 记录告警并主动退出交由外层哨兵干净重拉。
func heartbeatTickOnce() bool {
	stall := currentMainLoopStallAge(wdMonoNowFn())
	if stall < mainLoopHbMaxStale {
		writeHeartbeat()
		return true
	}
	if stall >= mainLoopStallFatal {
		logf("FATAL: mainLoop stalled for %v (>=%v), recording alert and exiting for clean relaunch",
			stall.Round(time.Second), mainLoopStallFatal)
		acfg := alert.NewConfig(wdAlertBaseDir)
		_ = alert.Append(acfg.AlertsJSONLPath, alert.Alert{
			ID:     alert.MakeAlertID("watchdog_stall", "host", time.Now().Unix()),
			Ts:     time.Now().Unix(),
			Kind:   "watchdog_stall",
			Detail: fmt.Sprintf("hnc_watchdog 主循环卡死 %v, 已主动退出由哨兵重拉恢复", stall.Round(time.Second)),
		})
		releaseLock()
		wdStallExitFn(1)
		return false
	}
	logf("WARN: mainLoop step stale (%v >= %v), withholding watchdog.heartbeat",
		stall.Round(time.Second), mainLoopHbMaxStale)
	return false
}

func writeHeartbeat() {
	_ = os.WriteFile(wdHeartbeatPath, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o644)
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
	data, err := os.ReadFile(wdHeartbeatPath)
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
	return syscall.Kill(pid, 0) == nil && !isZombie(pid)
}

// isZombie 进程已退出、只是还没被回收(/proc/<pid>/stat 状态 Z)。
func isZombie(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	s := string(b)
	if i := strings.LastIndexByte(s, ')'); i >= 0 && i+2 < len(s) {
		return s[i+2] == 'Z'
	}
	return false
}

// ─── action invocation (sh watchdog.sh action <name> [args...]) ─────────

type actionResult struct {
	exitCode int
	stdout   string
	err      error
}

// shellPath returns the shell interpreter to run business-logic scripts with.
// Prefers /system/bin/sh, falls back to binDir/sh, then /bin/sh or PATH sh.
func shellPath() string {
	const sysSh = "/system/bin/sh"
	if _, err := os.Stat(sysSh); err == nil {
		return sysSh
	}
	if fb := binDir + "/sh"; func() bool { _, e := os.Stat(fb); return e == nil }() {
		return fb
	}
	if _, err := os.Stat("/bin/sh"); err == nil {
		return "/bin/sh"
	}
	if p, err := exec.LookPath("sh"); err == nil && p != "" {
		return p
	}
	return sysSh
}

// runAction forks watchdog.sh with the action subcommand. Returns the
// subcommand's exit code, captured stdout, and any spawn-level error.
func runAction(name string, args ...string) actionResult {
	start := nowFn() // v5.28 A2: 耗时统计
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()

	cmdArgs := append([]string{wdShell, "action", name}, args...)
	cmd := exec.CommandContext(ctx, shellPath(), cmdArgs...)
	cmd.Env = os.Environ()
	// Isolate from our own pgrp so action kills don't propagate to us.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second

	touchMainLoopStep()
	out, err := cmd.Output()
	touchMainLoopStep()
	rc := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			rc = ee.ExitCode()
			err = nil
		} else if errors.Is(err, exec.ErrWaitDelay) {
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
	elapsed := nowFn().Sub(start).Seconds() * 1000
	runStatsFn(name, rc, err, elapsed, nowFn())
	return actionResult{exitCode: rc, stdout: strings.TrimSpace(string(out)), err: err}
}

// runBoundedShellScript 以独立进程组 + 硬超时(15s)执行辅助脚本, 超时瞬间连根 SIGKILL 整个进程组。
func runBoundedShellScript(timeout time.Duration, scriptPath string, args ...string) {
	if timeout <= 0 {
		timeout = auxScriptTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmdArgs := append([]string{scriptPath}, args...)
	cmd := exec.CommandContext(ctx, shellPath(), cmdArgs...)
	cmd.Env = os.Environ()
	// nil = /dev/null, 避免创建管道导致后台孙进程阻塞 Wait
	cmd.Stdout, cmd.Stderr = nil, nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
	_ = cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		logf("WARN: script %s timed out after %v (killed process group)", filepath.Base(scriptPath), timeout)
	}
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
}

func httpdDaemon() daemonSpec {
	return daemonSpec{
		name:     "hnc_httpd",
		binPath:  hncDir + "/daemon/hnc_httpd/hnc_httpd",
		args:     []string{"-hnc-dir", hncDir},
		logFile:  logDir + "/httpd.log",
		pidFile:  runDir + "/httpd.pid",
		cooldown: httpdRestartCD,
	}
}

func hotspotdDaemon() daemonSpec {
	args := []string{"-d"}
	return daemonSpec{
		name:     "hotspotd",
		binPath:  binDir + "/hotspotd",
		args:     args,
		logFile:  logDir + "/hotspotd.log",
		pidFile:  runDir + "/hotspotd.pid",
		cooldown: hotspotdRestartCD,
	}
}

// ── dpid 守护者 = run/dpid_launcher.choice(v5.26 T2 起唯一权威) ──────────────

func parseLauncherChoice(raw string) string {
	c := strings.TrimSpace(raw)
	switch c {
	case "launcher", "direct":
		return c
	default:
		return ""
	}
}

func readLauncherChoiceAt(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return parseLauncherChoice(string(b))
}

func readLauncherChoice() string {
	return readLauncherChoiceAt(m5RunDir + "/dpid_launcher.choice") // m5RunDir 默认 = runDir
}

func superviseDpid() {
	superviseDpidM5(readLauncherChoice(), nowFn())
}

const alertScanEvery = 5 * time.Minute

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

const (
	httpdHealthURL              = "http://127.0.0.1:8444/api/health"
	httpdHealthProbeTimeout     = 2 * time.Second
	httpdStartupGrace           = 15 * time.Second
	httpdFreezeTimeoutThreshold = 2
)

var (
	wdProcRoot              = "/proc"
	wdCgroupV2Root          = "/sys/fs/cgroup"
	wdDevFreezerRoot        = "/dev/freezer"
	protectDaemonProcessFn  = protectDaemonProcess
	dnsTakeoverRemoveFn     = runDNSTakeoverRemove
	terminateFrozenDaemonFn = terminateFrozenDaemon
	spawnDaemonFn           = spawnDaemon
	httpdStateFn            = readState
	httpdHealthProbeEnabled bool
	httpdHealthProbeFn      = probeHttpdHealth
	httpdLastSpawnAt        time.Time
	httpdUnresponsiveStreak int

	protectedPIDsMu sync.Mutex
	protectedPIDs   = map[int]struct{}{}
)

// protectDaemonProcess 尽力将守护进程 PID 迁出国产 ROM 的 App cgroup 冻结组,
// 并设置 oom_score_adj=-900 降低 LMK 误杀概率。
func protectDaemonProcess(pid int) {
	if pid <= 0 {
		return
	}
	pidStr := strconv.Itoa(pid)
	_ = os.WriteFile(filepath.Join(wdCgroupV2Root, "cgroup.procs"), []byte(pidStr), 0o644)
	_ = os.WriteFile(filepath.Join(wdDevFreezerRoot, "cgroup.procs"), []byte(pidStr), 0o644)
	_ = os.WriteFile(filepath.Join(wdCgroupV2Root, "freezer", "cgroup.procs"), []byte(pidStr), 0o644)
	_ = os.WriteFile(filepath.Join(wdProcRoot, pidStr, "oom_score_adj"), []byte("-900\n"), 0o644)
}

func hardenSelfProcess() {
	_ = os.WriteFile(filepath.Join(wdProcRoot, "self", "oom_score_adj"), []byte("-900\n"), 0o644)
	protectDaemonProcessFn(os.Getpid())
}

func ensureDaemonProtectedOnce(pid int) {
	if pid <= 0 {
		return
	}
	protectedPIDsMu.Lock()
	_, seen := protectedPIDs[pid]
	if !seen {
		if len(protectedPIDs) > 64 {
			protectedPIDs = map[int]struct{}{}
		}
		protectedPIDs[pid] = struct{}{}
	}
	protectedPIDsMu.Unlock()
	if !seen {
		protectDaemonProcessFn(pid)
	}
}

func forgetProtectedPID(pid int) {
	protectedPIDsMu.Lock()
	delete(protectedPIDs, pid)
	protectedPIDsMu.Unlock()
}

// isProcessCgroupFrozen 读取 /proc/<pid>/cgroup 检查进程是否被 ROM 置入 cgroup.freeze=1 或 FROZEN 墓碑态。
func isProcessCgroupFrozen(pid int) bool {
	if pid <= 0 {
		return false
	}
	raw, err := os.ReadFile(filepath.Join(wdProcRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return false
	}
	for _, ln := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(strings.TrimSpace(ln), ":", 3)
		if len(parts) != 3 {
			continue
		}
		rel := strings.TrimPrefix(strings.TrimSpace(parts[2]), "/")
		if rel == "" || rel == "." || strings.Contains(rel, "..") {
			continue
		}
		if parts[0] == "0" {
			if b, err := os.ReadFile(filepath.Join(wdCgroupV2Root, rel, "cgroup.freeze")); err == nil {
				if strings.TrimSpace(string(b)) == "1" {
					return true
				}
			}
			if b, err := os.ReadFile(filepath.Join(wdCgroupV2Root, rel, "cgroup.events")); err == nil {
				for _, ev := range strings.Split(string(b), "\n") {
					if strings.TrimSpace(ev) == "frozen 1" {
						return true
					}
				}
			}
		}
		if strings.Contains(parts[1], "freezer") {
			for _, base := range []string{wdDevFreezerRoot, filepath.Join(wdCgroupV2Root, "freezer")} {
				if b, err := os.ReadFile(filepath.Join(base, rel, "freezer.state")); err == nil {
					st := strings.TrimSpace(string(b))
					if st == "FROZEN" || st == "FREEZING" {
						return true
					}
				}
			}
		}
	}
	return false
}

func probeHttpdHealth() bool {
	client := &http.Client{
		Timeout:   httpdHealthProbeTimeout,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	resp, err := client.Get(httpdHealthURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

func checkHttpdFrozen(pid int) (bool, string) {
	if isProcessCgroupFrozen(pid) {
		return true, "cgroup_frozen"
	}
	if httpdHealthProbeEnabled && httpdStateFn().kind == stateActive {
		now := nowFn()
		if !httpdLastSpawnAt.IsZero() && now.Sub(httpdLastSpawnAt) >= 0 && now.Sub(httpdLastSpawnAt) < httpdStartupGrace {
			return false, ""
		}
		if httpdHealthProbeFn() {
			httpdUnresponsiveStreak = 0
			return false, ""
		}
		httpdUnresponsiveStreak++
		if httpdUnresponsiveStreak >= httpdFreezeTimeoutThreshold {
			return true, fmt.Sprintf("health_timeout_streak=%d", httpdUnresponsiveStreak)
		}
		return false, ""
	}
	httpdUnresponsiveStreak = 0
	return false, ""
}

func terminateFrozenDaemon(pid int) {
	if pid <= 0 {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	time.Sleep(200 * time.Millisecond)
	if processAlive(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		time.Sleep(100 * time.Millisecond)
	}
}

func runDNSTakeoverRemove() {
	ctx, cancel := context.WithTimeout(context.Background(), auxScriptTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, shellPath(), hncDir+"/bin/dns_takeover.sh", "remove")
	cmd.Env = os.Environ()
	cmd.Stdout, cmd.Stderr = nil, nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
	_ = cmd.Run()
}

// ensureDaemonRunning checks the daemon's pidfile, repairs it if a live
// process matches, detects frozen/unresponsive hnc_httpd to prevent DNS blackholes,
// otherwise (re)launches under cooldown.
func ensureDaemonRunning(d daemonSpec) {
	launcher := d.binPath
	launcherArgs := d.args
	watchPidFile := d.pidFile
	alivePid := 0

	// Is the watched pidfile alive? (Prefer kernel pidfd handle when spawned by us)
	if data, err := os.ReadFile(watchPidFile); err == nil {
		if pid, _ := strconv.Atoi(strings.TrimSpace(string(data))); pid > 0 {
			if proc := lookupSpawnedProcess(watchPidFile, pid); proc != nil {
				if alive, supported := pidfdProcessAlive(proc); supported {
					if alive {
						alivePid = pid
					} else {
						untrackSpawnedProcess(watchPidFile, proc)
					}
				} else if processAlive(pid) {
					alivePid = pid
				}
			} else if processAlive(pid) {
				alivePid = pid
			}
		}
	}
	if alivePid <= 0 {
		if live := findLiveByName(filepath.Base(launcher)); live > 0 {
			alivePid = live
			_ = os.WriteFile(watchPidFile, []byte(strconv.Itoa(live)), 0o644)
			logf("%s: live without pidfile, repaired (pid=%d)", d.name, live)
		}
	}

	dnsRemoved := false
	if alivePid > 0 {
		ensureDaemonProtectedOnce(alivePid)
		if d.name != "hnc_httpd" {
			return
		}
		frozen, reason := checkHttpdFrozen(alivePid)
		if !frozen {
			return
		}
		logf("WARN: hnc_httpd pid=%d frozen/unresponsive (%s); removing dns_takeover before restart", alivePid, reason)
		// 先跑 ./bin/dns_takeover.sh remove 解除 DNS 劫持保热点不断网, 再解冻并重拉 hnc_httpd
		dnsTakeoverRemoveFn()
		dnsRemoved = true
		protectDaemonProcessFn(alivePid)
		terminateFrozenDaemonFn(alivePid)
		if proc := lookupSpawnedProcess(watchPidFile, alivePid); proc != nil {
			untrackSpawnedProcess(watchPidFile, proc)
		}
		forgetProtectedPID(alivePid)
		_ = os.Remove(watchPidFile)
		httpdUnresponsiveStreak = 0
	}

	if _, err := os.Stat(launcher); err != nil {
		return
	}
	if !cooldownOK(d.name, d.cooldown) {
		return
	}

	if d.name == "hnc_httpd" && !dnsRemoved {
		dnsTakeoverRemoveFn()
	}

	logf("%s: process gone, launching %s", d.name, launcher)
	if err := spawnDaemonFn(launcher, launcherArgs, d.logFile, watchPidFile); err != nil {
		logf("%s: launch failed: %v", d.name, err)
	}
}

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
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		if out != nil {
			_ = out.Close()
		}
		return err
	}
	protectDaemonProcessFn(cmd.Process.Pid)
	ensureDaemonProtectedOnce(cmd.Process.Pid)
	if filepath.Base(bin) == "hnc_httpd" {
		httpdLastSpawnAt = nowFn()
		httpdUnresponsiveStreak = 0
	}
	trackSpawnedProcess(pidFile, cmd.Process)
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
		if data, err := os.ReadFile("/proc/" + e.Name() + "/comm"); err == nil {
			if strings.TrimSpace(string(data)) == name && !isZombie(pid) {
				return pid
			}
		}
		if data, err := os.ReadFile("/proc/" + e.Name() + "/cmdline"); err == nil {
			argv0 := strings.SplitN(string(data), "\x00", 2)[0]
			if filepath.Base(argv0) == name && !isZombie(pid) {
				return pid
			}
		}
	}
	return 0
}

// ─── doze detection ─────────────────────────────────────────────────────

const (
	dozeBatteryCapPath = "/sys/class/power_supply/battery/capacity"
	dozeLowBatteryPct  = 5
)

var (
	dozeCacheMu      sync.Mutex
	dozeCached       bool
	dozeCheckTS      time.Time
	batteryCapPathFn = func() string { return dozeBatteryCapPath }
)

// readBatteryCapacity 纯 Go 0-fork 读 /sys/class/power_supply/battery/capacity。
// 读不到或非合法 0..100 数值返回 (-1, false)。
func readBatteryCapacity() (int, bool) {
	b, err := os.ReadFile(batteryCapPathFn())
	if err != nil {
		return -1, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || v < 0 || v > 100 {
		return -1, false
	}
	return v, true
}

// isDoze 纯 Go 0-fork 低功耗判定:
//   - 不再 fork `./bin/watchdog.sh action is_doze` 唤醒 system_server;
//   - 复用 run/activity.json 的熄屏静默态 (s.OK && s.Quiet → 直接降频);
//   - 保留电量 <5% 低电降频 (读 /sys/class/power_supply/battery/capacity, 30s 缓存)。
func isDoze() bool {
	s := actSnapshotFn()
	if s.OK && s.Quiet {
		return true
	}
	dozeCacheMu.Lock()
	defer dozeCacheMu.Unlock()
	now := nowFn()
	if !dozeCheckTS.IsZero() {
		if el := now.Sub(dozeCheckTS); el >= 0 && el < 30*time.Second {
			return dozeCached
		}
	}
	lowBat := false
	if capPct, ok := readBatteryCapacity(); ok && capPct < dozeLowBatteryPct {
		lowBat = true
	}
	dozeCached = lowBat
	dozeCheckTS = now
	return dozeCached
}

// ─── restore window throttle ────────────────────────────────────────────

type restoreThrottle struct {
	windowStart     time.Time
	windowCount     int
	consecutive     int
	passiveMode     bool
	passiveExitTS   time.Time
	totalRestores   int
	passiveLogged   bool
	activeIface     string
	activeIfIndex   int
	exemptedIfIndex int
}

func (r *restoreThrottle) resetActiveIface() {
	r.activeIface = ""
	r.activeIfIndex = 0
	r.exemptedIfIndex = 0
}

func (r *restoreThrottle) recordHealthyIface(iface string, ifindex int) {
	if r.activeIface != "" && r.activeIface != iface {
		r.activeIfIndex = 0
		r.exemptedIfIndex = 0
	}
	r.activeIface = iface
	if ifindex > 0 {
		r.activeIfIndex = ifindex
		r.exemptedIfIndex = 0
	}
}

// tryExemptBandSwitch 仅当同热点口名下实测正整数 ifindex 相比上一轮健康值发生真实跳变
// (每次新 ifindex 仅豁免一次)时返回 (prevIfIndex, true), 将重建视为正常切频段而不计入熔断窗口。
func (r *restoreThrottle) tryExemptBandSwitch(iface string, curIfIndex int) (int, bool) {
	if iface == "" || r.activeIface != iface || r.activeIfIndex <= 0 || curIfIndex <= 0 {
		return 0, false
	}
	if curIfIndex == r.activeIfIndex || curIfIndex == r.exemptedIfIndex {
		return 0, false
	}
	prev := r.activeIfIndex
	r.exemptedIfIndex = curIfIndex
	return prev, true
}

func readPositiveIfIndex(iface string) int {
	if iface == "" || sysIfIndexFn == nil {
		return 0
	}
	s, err := sysIfIndexFn(iface)
	if err != nil {
		return 0
	}
	idx, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || idx <= 0 {
		return 0
	}
	return idx
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

func (r *restoreThrottle) onHealthFail() bool {
	now := nowFn()
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
	httpdHealthProbeEnabled = true
	ls := newLoopState()
	touchMainLoopStep()

	for {
		if !ls.firstRound {
			touchMainLoopStep()
			interval := ls.currentInterval
			if isDozeFn() {
				interval = intervalDoze
			}
			if d := hsSched.maxSleep(nowFn()); d >= 0 && d < interval {
				interval = d
			}
			beginMainLoopSleep(interval)
			ok, _ := sleepOrWake(interval)
			endMainLoopSleep()
			if !ok {
				return
			}
		}
		ls.firstRound = false
		touchMainLoopStep()

		ls.tick(readState())
		touchMainLoopStep()

		// Daemon supervision (regardless of state)
		ensureDaemonRunning(hotspotdDaemon())
		touchMainLoopStep()
		ensureDaemonRunning(httpdDaemon())
		touchMainLoopStep()
		superviseDpid()
		touchMainLoopStep()
	}
}

func handlePending(throttle *restoreThrottle) time.Duration {
	m4Writer.hotspotDown()
	if throttle != nil {
		throttle.resetActiveIface()
	}
	touchMainLoopStep()
	res := probeHotspotFn()
	touchMainLoopStep()
	if res.exitCode != 0 || res.stdout == "" {
		return intervalProbe
	}
	parts := strings.Fields(res.stdout)
	if len(parts) < 2 {
		logf("probe_hotspot: unexpected result %q", res.stdout)
		return intervalProbe
	}
	iface, ip := parts[0], parts[1]
	logf("STATE PENDING -> ACTIVE:%s (ip=%s); running full_init", iface, ip)
	res = runActionFn("full_init", iface, ip)
	touchMainLoopStep()
	if res.exitCode != 0 {
		logf("full_init returned rc=%d; staying PENDING", res.exitCode)
		return intervalProbe
	}
	if throttle != nil {
		throttle.recordHealthyIface(iface, readPositiveIfIndex(iface))
	}
	writeStateFn(wdState{kind: stateActive, iface: iface})
	m4Writer.tick(iface, nowFn())
	wakeAppLimitLoop()
	wakeOffloadSched()
	return intervalNormal
}

func handleActive(activeIface string, throttle *restoreThrottle, aux *activeAux) time.Duration {
	touchMainLoopStep()
	probe := probeHotspotFn()
	touchMainLoopStep()
	if probe.exitCode != 0 || probe.stdout == "" {
		logf("STATE ACTIVE:%s -> PENDING (hotspot closed)", activeIface)
		if throttle != nil {
			throttle.resetActiveIface()
		}
		m4Writer.hotspotDown()
		onlineAcc.hotspotDown(nowFn())
		writeStateFn(wdState{kind: statePending})
		return intervalProbe
	}
	parts := strings.Fields(probe.stdout)
	if len(parts) < 2 {
		return intervalNormal
	}
	newIface, newIP := parts[0], parts[1]

	if newIface != activeIface {
		logf("iface changed %s -> %s; migrating", activeIface, newIface)
		res := runActionFn("migrate", activeIface, newIface, newIP)
		touchMainLoopStep()
		if res.exitCode == 0 {
			if throttle != nil {
				throttle.recordHealthyIface(newIface, readPositiveIfIndex(newIface))
			}
			writeStateFn(wdState{kind: stateActive, iface: newIface})
			m4Writer.tick(newIface, nowFn())
			wakeAppLimitLoop()
			wakeOffloadSched()
		} else {
			if throttle != nil {
				throttle.resetActiveIface()
			}
			logf("migrate rc=%d; stopping stale m4 writer", res.exitCode)
			m4Writer.hotspotDown()
		}
		return intervalNormal
	}

	if throttle != nil && throttle.activeIface != "" && throttle.activeIface != newIface {
		throttle.resetActiveIface()
	}

	now := nowFn()
	onlineAcc.sample(now)
	m4Writer.tick(newIface, now)
	if aux.cap.due(newIface, now) {
		_ = runActionFn("capability_probe", newIface)
		touchMainLoopStep()
		aux.cap.mark(newIface, now)
	}

	healthRC := checkHealthFn(newIface)
	touchMainLoopStep()
	switch healthRC {
	case 0:
		if throttle != nil {
			throttle.recordHealthyIface(newIface, readPositiveIfIndex(newIface))
		}
		recovering := aux.recoveryRounds > 0
		if aux.recoveryRounds > 0 {
			aux.recoveryRounds--
		}
		now := nowFn()
		if now.Sub(aux.lastV6Sync) >= 60*time.Second {
			runV6SyncFn()
			touchMainLoopStep()
			aux.lastV6Sync = now
		}
		if statsSampleDue(aux.lastStatsSample, now) {
			runStatsSampleFn()
			touchMainLoopStep()
			aux.lastStatsSample = now
		}
		if recovering || now.Sub(aux.lastUplink) >= tcUplinkEvery {
			if ok, unknown := nativeUplinkOK(newIface); !ok || unknown {
				touchMainLoopStep()
				_ = runActionFn("tc_uplink_healthy")
			}
			touchMainLoopStep()
			aux.lastUplink = now
		}
		return intervalNormal

	case 2:
		return intervalNormal

	default:
		curIdx := readPositiveIfIndex(newIface)
		if throttle != nil {
			if prevIdx, exempt := throttle.tryExemptBandSwitch(newIface, curIdx); exempt {
				logf("iface %s ifindex jumped %d -> %d (band switch), restoring without throttle penalty",
					newIface, prevIdx, curIdx)
				res := runActionFn("full_restore",
					fmt.Sprintf("band_switch_ifindex (%s %d->%d)", newIface, prevIdx, curIdx))
				touchMainLoopStep()
				if res.exitCode != 0 {
					logf("full_restore (band switch) rc=%d", res.exitCode)
				}
				aux.recoveryRounds = 3
				return intervalRecovery
			}
		}
		if !throttle.onHealthFail() {
			return intervalNormal
		}
		res := runActionFn("full_restore",
			fmt.Sprintf("health_fail (total=%d, window=%d/%d)",
				throttle.totalRestores, throttle.windowCount, restoreWindowMax))
		touchMainLoopStep()
		if res.exitCode != 0 {
			logf("full_restore rc=%d", res.exitCode)
		}
		throttle.onRestoreDone()
		aux.recoveryRounds = 3
		return intervalRecovery
	}
}

// runV6Sync forks bin/v6_sync.sh with 15s hard timeout & process-group isolation.
func runV6Sync() {
	runBoundedShellScript(auxScriptTimeout, binDir+"/v6_sync.sh", "sync")
}

// runScript 执行一个 bin/ 下的脚本(stdout/stderr 丢弃, 独立进程组 + 15s 硬超时)。
func runScript(path string, args ...string) {
	runBoundedShellScript(auxScriptTimeout, path, args...)
}

// runStatsSample forks bin/stats_sample.sh with 15s hard timeout & process-group isolation.
func runStatsSample() {
	runBoundedShellScript(auxScriptTimeout, binDir+"/stats_sample.sh")
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

var _ = readFirstLine

// ─── entrypoint ─────────────────────────────────────────────────────────

func main() {
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	resolveWatchdogVersion(hncDir)
	if *showVer {
		fmt.Println("hnc_watchdog", version)
		return
	}

	// P1 时区门禁: Android 上 Go 默认 time.Local 恒为 UTC, 必须通过 tzlocal.Location() 对齐系统时区。
	time.Local = tzlocal.Location()

	openLog()
	hardenSelfProcess()
	logf("hnc_watchdog %s starting, pid=%d", version, os.Getpid())

	if !acquireLock() {
		os.Exit(0)
	}
	defer releaseLock()

	if _, err := os.Stat(wdShell); err != nil {
		logf("FATAL: shell action driver missing at %s, cannot supervise", wdShell)
		os.Exit(3)
	}

	if err := wdActionsFlushFn(actionsFile, nowFn()); err != nil {
		logf("action stats initial flush: %v", err)
	}

	touchMainLoopStep()
	handleSignals()
	go heartbeatLoop()
	startLinkWatch()
	startOffloadSched()

	go alertScanLoop()
	go appLimitApplyLoop()

	mainLoop()
	onExit()
	logf("hnc_watchdog exiting normally")
}

const (
	appLimitApplyEvery     = 30 * time.Second
	appLimitDirtyPollFast  = 3 * time.Second
	appLimitEmptyQuietPoll = 60 * time.Second
	appLimitIdlePoll       = 120 * time.Second
)

var appLimitWakeCh = make(chan struct{}, 1)

func wakeAppLimitLoop() {
	select {
	case appLimitWakeCh <- struct{}{}:
	default:
	}
}

// appLimitHasWork 判断当前是否存在单应用限速/应用感知 QoS 的有效配置或待清理残留状态。
// 全空时周期轮询无需每 30 秒 fork 千行 shell 脚本, 仅在检测到 dirty 标记或配置非空时下发。
func appLimitHasWork(dataPath, runPath string) bool {
	if fi, err := os.Stat(filepath.Join(dataPath, "app_limits.flat")); err == nil && fi.Size() > 0 {
		return true
	}
	for _, name := range []string{
		"app_limits.devs",
		"app_limits.tree",
		"app_limits.applied.sig",
		"app_limits.full_state.sig",
		"app_limits_inactive.marker",
		"app_qos.state",
	} {
		if _, err := os.Stat(filepath.Join(runPath, name)); err == nil {
			return true
		}
	}
	b, err := os.ReadFile(filepath.Join(dataPath, "rules.json"))
	if err == nil && len(b) < 8<<20 && bytes.Contains(b, []byte(`"app_qos"`)) {
		var r struct {
			Devices map[string]map[string]interface{} `json:"devices"`
		}
		if json.Unmarshal(b, &r) == nil {
			for _, d := range r.Devices {
				if boolish(d["app_qos"]) {
					return true
				}
			}
		}
	}
	return false
}

// appLimitNextWait 计算 appLimitApplyLoop 下一轮等待时长:
//   - 热点未开: 放宽至 120s(热点开启时由 appLimitWakeCh 即时唤醒);
//   - 空配置且熄屏/无客户端: 放宽至 60s(0 fork);
//   - 空配置且亮屏/有界面: 3s 轻量 stat 检查 app_limit.dirty(0 fork);
//   - 有配置: 亮屏 3s 响应 dirty / 30s 周期下发, 熄屏/无客户端 30s 周期下发。
func appLimitNextWait(idle, hasWork, quietOrNoClients bool, sinceLastApply time.Duration) time.Duration {
	if idle {
		return appLimitIdlePoll
	}
	if !hasWork {
		if quietOrNoClients {
			return appLimitEmptyQuietPoll
		}
		return appLimitDirtyPollFast
	}
	rem := appLimitApplyEvery - sinceLastApply
	if rem < appLimitDirtyPollFast {
		rem = appLimitDirtyPollFast
	}
	if quietOrNoClients {
		return rem
	}
	if appLimitDirtyPollFast < rem {
		return appLimitDirtyPollFast
	}
	return rem
}

func appLimitApplyLoop() {
	script := binDir + "/apply_app_limits.sh"
	dirty := runDir + "/app_limit.dirty"
	if !sleepUntil(45 * time.Second) {
		return
	}
	var lastApply time.Time
	for {
		idle := hotspotIdleFn()
		hasWork := false
		if !idle {
			hasDirty := false
			if _, err := os.Stat(dirty); err == nil {
				hasDirty = true
				_ = os.Remove(dirty)
			}
			hasWork = appLimitHasWork(dataDir, runDir)
			now := nowFn()
			if hasDirty || (hasWork && (lastApply.IsZero() || now.Sub(lastApply) >= appLimitApplyEvery || now.Sub(lastApply) < 0)) {
				appApplyOnce(script)
				lastApply = nowFn()
				hasWork = appLimitHasWork(dataDir, runDir)
			}
		}
		s := actSnapshotFn()
		quietOrNoClients := s.OK && (s.Quiet || s.Level == activity.LevelNoClients)
		sinceLast := time.Duration(0)
		if !lastApply.IsZero() {
			if d := nowFn().Sub(lastApply); d > 0 {
				sinceLast = d
			}
		}
		wait := appLimitNextWait(idle, hasWork, quietOrNoClients, sinceLast)
		tmr := time.NewTimer(wait)
		select {
		case <-stopCh:
			tmr.Stop()
			return
		case <-appLimitWakeCh:
			tmr.Stop()
		case <-tmr.C:
		}
	}
}

func appApplyOnce(script string) {
	if hotspotIdleFn() {
		return
	}
	if _, err := os.Stat(script); err == nil {
		runScriptFn(script)
	}
	iface := ""
	if st := appQosStateFn(); st.kind == stateActive {
		iface = st.iface
	}
	appQosTick(iface)
}

var appQosStateFn = readState

func alertScanLoop() {
	cfg := alert.NewConfig(hncDir)
	if !sleepUntil(30 * time.Second) {
		return
	}
	tk := time.NewTicker(alertScanEvery)
	defer tk.Stop()
	for {
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
