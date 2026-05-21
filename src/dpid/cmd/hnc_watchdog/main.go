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
// Falls back gracefully: if /data/local/hnc/bin/hnc_watchdog isn't present,
// service.sh / cleanup.sh still launch the legacy shell watchdog.sh.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
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
	heartbeatTick     = 5 * time.Second
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
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		_ = logFile.Close()
	}
	_ = os.Rename(wdLog, wdLog+".1")
	f, _ := os.OpenFile(wdLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	logFile = f
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

// runAction forks watchdog.sh with the action subcommand. Returns the
// subcommand's exit code, captured stdout, and any spawn-level error.
//
// Important: this is the *only* place where we shell out for business logic.
// All other supervision work (process management, heartbeats, state) is
// pure Go and doesn't touch /system/bin/* tools.
func runAction(name string, args ...string) actionResult {
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()

	cmdArgs := append([]string{wdShell, "action", name}, args...)
	cmd := exec.CommandContext(ctx, "/system/bin/sh", cmdArgs...)
	cmd.Env = os.Environ()
	// Isolate from our own pgrp so action kills don't propagate to us.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	out, err := cmd.Output()
	rc := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			rc = ee.ExitCode()
			err = nil
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("action %s timed out after %v", name, actionTimeout)
		rc = -1
	}
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
		name:     "hnc_httpd",
		binPath:  binDir + "/hnc_httpd",
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

// rc30.3: ndpi_continuous.sh is a shell daemon that fork-loops hnc_ndpi_probe.
// We supervise it from the Go watchdog instead of inlining it — keeping the
// CSV→JSON pipeline in shell preserves its battle-tested edge cases (column
// reordering across ndpiReader versions, awk parsing of QUIC SNI).
const (
	ndpiConfigPath  = dataDir + "/dpi_ndpi_config.json"
	ndpiScriptPath  = binDir + "/ndpi_continuous.sh"
	ndpiPidPath     = runDir + "/ndpi_continuous.pid"
	alertScanEvery  = 5 * time.Minute
)

// ndpiEnabledByConfig reads dpi_ndpi_config.json and reports whether nDPI
// continuous mode should be running. Cheap (file is <1KB).
func ndpiEnabledByConfig() bool {
	data, err := os.ReadFile(ndpiConfigPath)
	if err != nil {
		return false
	}
	// Minimal parse — we only need the `enabled` boolean. Avoid pulling in
	// encoding/json for a one-line lookup that runs every supervisor round.
	s := string(data)
	idx := strings.Index(s, `"enabled"`)
	if idx < 0 {
		return false
	}
	tail := s[idx+len(`"enabled"`):]
	// Skip past ":" and whitespace.
	for i := 0; i < len(tail); i++ {
		switch tail[i] {
		case ':', ' ', '\t', '\n', '\r':
			continue
		}
		// First non-whitespace token.
		return strings.HasPrefix(tail[i:], "true")
	}
	return false
}

// ensureNDPIRunning launches ndpi_continuous.sh when the config has nDPI
// enabled, and stops it cleanly when disabled. Driven by the main loop
// every supervision round.
func ensureNDPIRunning() {
	enabled := ndpiEnabledByConfig()

	// Check current run state.
	var alive bool
	if data, err := os.ReadFile(ndpiPidPath); err == nil {
		if pid, _ := strconv.Atoi(strings.TrimSpace(string(data))); pid > 0 && processAlive(pid) {
			alive = true
		}
	}

	if enabled && !alive {
		if _, err := os.Stat(ndpiScriptPath); err != nil {
			// Script missing (older zip without rc28 pipeline). Silent skip.
			return
		}
		if _, err := os.Stat(binDir + "/hnc_ndpi_probe"); err != nil {
			// Probe binary missing.
			return
		}
		if !cooldownOK("ndpi", 60*time.Second) {
			return
		}
		logf("nDPI: launching ndpi_continuous.sh")
		cmd := exec.Command("/system/bin/sh", ndpiScriptPath, "start")
		cmd.Env = os.Environ()
		out, _ := os.OpenFile(logDir+"/ndpi_continuous.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if out != nil {
			cmd.Stdout = out
			cmd.Stderr = out
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Setsid: true}
		if err := cmd.Start(); err != nil {
			logf("nDPI: launch failed: %v", err)
			if out != nil {
				out.Close()
			}
			return
		}
		// ndpi_continuous.sh writes its own pidfile; we don't track this Start()'s
		// pid because it's `sh start` which itself sets up the long-running shell.
		go func() {
			_ = cmd.Wait()
			if out != nil {
				out.Close()
			}
		}()
		return
	}

	if !enabled && alive {
		logf("nDPI: config disabled, stopping ndpi_continuous.sh")
		cmd := exec.Command("/system/bin/sh", ndpiScriptPath, "stop")
		cmd.Env = os.Environ()
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		_ = cmd.Run()
	}
}

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

// ─── doze detection ─────────────────────────────────────────────────────

// isDoze defers to watchdog.sh action is_doze (which knows the ColorOS/MIUI
// shenanigans of finding the right dumpsys field). Result cached for 30s.
var (
	dozeCacheMu sync.Mutex
	dozeCached  bool
	dozeCheckTS time.Time
)

func isDoze() bool {
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
	windowStart    time.Time
	windowCount    int
	consecutive    int
	passiveMode    bool
	passiveExitTS  time.Time
	totalRestores  int
	passiveLogged  bool
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
	now := time.Now()
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
	throttle := &restoreThrottle{}
	lastLogRotate := time.Now()
	lastV6Sync := time.Time{}
	lastStatsSample := time.Time{}
	recoveryRounds := 0
	currentInterval := intervalNormal
	firstRound := true

	for {
		if !firstRound {
			interval := currentInterval
			if isDoze() {
				interval = intervalDoze
			}
			if !sleepUntil(interval) {
				return
			}
		}
		firstRound = false

		// Log rotation, cheap so always run.
		if time.Since(lastLogRotate) > logRotateInterval {
			rotateLogIfBig()
			_ = runAction("cleanup_stale_rules")
			_ = runAction("rotate_logs")
			lastLogRotate = time.Now()
		}

		// State machine.
		state := readState()
		switch state.kind {
		case statePending:
			currentInterval = handlePending(throttle)

		case stateActive:
			currentInterval = handleActive(state.iface, throttle, &recoveryRounds, &lastV6Sync, &lastStatsSample)
		}

		// Daemon supervision (regardless of state)
		ensureDaemonRunning(hotspotdDaemon())
		ensureDaemonRunning(httpdDaemon())
		ensureDaemonRunning(dpidDaemon())
		ensureNDPIRunning()

		// rc17 hotspotd dedupe
		_ = runAction("prune_dup_hotspotd")
	}
}

func handlePending(_ *restoreThrottle) time.Duration {
	res := runAction("probe_hotspot")
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
	res = runAction("full_init", iface, ip)
	if res.exitCode != 0 {
		logf("full_init returned rc=%d; staying PENDING", res.exitCode)
		return intervalProbe
	}
	writeState(wdState{kind: stateActive, iface: iface})
	return intervalNormal
}

func handleActive(activeIface string, throttle *restoreThrottle, recoveryRounds *int, lastV6Sync, lastStatsSample *time.Time) time.Duration {
	probe := runAction("probe_hotspot")
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
		res := runAction("migrate", activeIface, newIface, newIP)
		if res.exitCode == 0 {
			writeState(wdState{kind: stateActive, iface: newIface})
		} else {
			logf("migrate rc=%d", res.exitCode)
		}
		return intervalNormal
	}

	// Capability probe (lightweight)
	_ = runAction("capability_probe", newIface)

	// Health check
	health := runAction("check_health")
	switch health.exitCode {
	case 0:
		// Healthy
		if *recoveryRounds > 0 {
			*recoveryRounds--
		}
		// Periodic side tasks
		now := time.Now()
		if now.Sub(*lastV6Sync) >= 60*time.Second {
			runV6Sync()
			*lastV6Sync = now
		}
		if now.Sub(*lastStatsSample) >= 30*time.Second {
			runStatsSample()
			*lastStatsSample = now
		}
		_ = runAction("httpd_drift")
		_ = runAction("tc_uplink_healthy")
		return intervalNormal

	case 2:
		// Transient error (xtables lock busy etc.), skip this round
		return intervalNormal

	default:
		// Rules truly lost → restore (subject to throttle)
		if !throttle.onHealthFail() {
			return intervalNormal
		}
		res := runAction("full_restore",
			fmt.Sprintf("health_fail (total=%d, window=%d/%d)",
				throttle.totalRestores, throttle.windowCount, restoreWindowMax))
		if res.exitCode != 0 {
			logf("full_restore rc=%d", res.exitCode)
		}
		throttle.onRestoreDone()
		*recoveryRounds = 3
		return intervalRecovery
	}
}

// runV6Sync forks bin/v6_sync.sh — independent of watchdog.sh, so just direct exec.
func runV6Sync() {
	cmd := exec.Command("/system/bin/sh", binDir+"/v6_sync.sh", "sync")
	cmd.Env = os.Environ()
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	_ = cmd.Run()
}

func runStatsSample() {
	cmd := exec.Command("/system/bin/sh", binDir+"/stats_sample.sh")
	cmd.Env = os.Environ()
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
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
		if _, err := os.Stat(script); err == nil {
			cmd := exec.Command("/system/bin/sh", script)
			cmd.Env = os.Environ()
			cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
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
		for i := 0; i < 30; i++ {
			time.Sleep(1 * time.Second)
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
