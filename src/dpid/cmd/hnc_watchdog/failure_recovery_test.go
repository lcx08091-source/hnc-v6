package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBoundedCommandFailureContract(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-interpreter")
	got := runBoundedCommand(time.Second, true, missing)
	if got.err == nil || got.exitCode == 0 || got.ok() {
		t.Fatalf("spawn failure reported success: %+v", got)
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	got = runBoundedCommand(time.Second, true, sh, "-c", "echo reason; exit 42")
	if got.exitCode != 42 || got.err != nil || got.stdout != "reason" || got.ok() {
		t.Fatalf("exit status/output lost: %+v", got)
	}
	got = runBoundedCommand(time.Second, true, sh, "-c", "echo ready")
	if !got.ok() || got.stdout != "ready" {
		t.Fatalf("successful command rejected: %+v", got)
	}
}

func TestBoundedCommandKillsDescendantsOnTimeout(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, capture := range []bool{false, true} {
		t.Run(fmt.Sprintf("capture=%v", capture), func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "child.pid")
			start := time.Now()
			got := runBoundedCommand(150*time.Millisecond, capture, sh, "-c", `sleep 10 & echo $! > "$1"; wait`, "watchdog-test", pidFile)
			if got.ok() || got.err == nil || got.exitCode == 0 {
				t.Fatalf("hung script reported success: %+v", got)
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("timeout failed to bound synchronous execution")
			}
			b, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatalf("child never started: %v", err)
			}
			pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
			deadline := time.Now().Add(time.Second)
			for processAlive(pid) && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if processAlive(pid) {
				_ = syscall.Kill(pid, syscall.SIGKILL) // Only the test-owned child.
				t.Fatalf("descendant %d survived process-group cancellation", pid)
			}
		})
	}
}

func TestPendingDoesNotCommitActionSpawnError(t *testing.T) {
	oldAct, oldProbe, oldWrite, oldWriter := runActionFn, probeHotspotFn, writeStateFn, m4Writer
	t.Cleanup(func() { runActionFn, probeHotspotFn, writeStateFn, m4Writer = oldAct, oldProbe, oldWrite, oldWriter })
	m4Writer = &m4WriterMgr{}
	probeHotspotFn = func() actionResult { return actionResult{stdout: "review0 192.0.2.1"} }
	runActionFn = func(string, ...string) actionResult {
		return actionResult{exitCode: 0, err: errors.New("fork/exec: operation not permitted")}
	}
	committed := false
	writeStateFn = func(wdState) { committed = true }
	if got := handlePending(&restoreThrottle{}); committed || got != intervalProbe {
		t.Fatalf("failed full_init committed ACTIVE: committed=%v interval=%s", committed, got)
	}
}

func TestMigrationDoesNotCommitActionSpawnError(t *testing.T) {
	oldAct, oldProbe, oldWrite := runActionFn, probeHotspotFn, writeStateFn
	t.Cleanup(func() { runActionFn, probeHotspotFn, writeStateFn = oldAct, oldProbe, oldWrite })
	probeHotspotFn = func() actionResult { return actionResult{stdout: "review1 192.0.2.1"} }
	runActionFn = func(string, ...string) actionResult {
		return actionResult{exitCode: 0, err: errors.New("fork/exec: operation not permitted")}
	}
	committed := false
	writeStateFn = func(wdState) { committed = true }
	handleActive("review0", &restoreThrottle{}, &activeAux{})
	if committed {
		t.Fatal("failed migrate committed new interface")
	}
}

func TestDaemonPIDReuseRepairsExpectedProcess(t *testing.T) {
	w := withM5World(t)
	w.proc1(42, "/system/bin/unrelated")
	w.proc1(43, "/data/local/hnc/daemon/hnc_httpd/hnc_httpd")
	pidPath := filepath.Join(w.run, "httpd.pid")
	w.write("httpd.pid", "42")
	ensureDaemonRunning(daemonSpec{name: "hnc_httpd", binPath: "/missing/hnc_httpd", pidFile: pidPath})
	b, err := os.ReadFile(pidPath)
	if err != nil || strings.TrimSpace(string(b)) != "43" {
		t.Fatalf("reused PID accepted as healthy: pid=%q err=%v", b, err)
	}
	_ = os.WriteFile(filepath.Join(w.proc, "43", "stat"), []byte("43 (hnc_httpd) Z 1"), 0o644)
	if got := pidfileAlive(pidPath, "hnc_httpd"); got != 0 {
		t.Fatalf("zombie accepted by identity check: %d", got)
	}
}
