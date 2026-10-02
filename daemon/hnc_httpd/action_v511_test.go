package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// v5.25: 看门狗状态按 pidfile + /proc/<pid>/cmdline 判断(旧版 toybox grep 不认 \| 恒为 0)。
func TestReadWatchdogState(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	now := time.Unix(1_800_000_000, 0)
	if st := readWatchdogState(dir, now); st.count() != 0 || st.HeartbeatAge != -1 {
		t.Fatalf("无 pidfile: %+v", st)
	}
	// pidfile 指向一个活着但不是看门狗的进程(测试进程自身) → 不算
	_ = os.WriteFile(filepath.Join(dir, "run", "watchdog.pid"), []byte(strconv.Itoa(os.Getpid())), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "watchdog.heartbeat"), []byte(strconv.FormatInt(now.Unix()-30, 10)), 0o644)
	if st := readWatchdogState(dir, now); st.count() != 0 || st.Kind != "" || st.HeartbeatAge != -1 {
		t.Fatalf("非看门狗进程不应算在跑: %+v", st)
	}
}
