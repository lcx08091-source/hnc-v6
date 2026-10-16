package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"hnc.io/dpid/procfind"
)

// v5.25: 看门狗状态按 pidfile + /proc/<pid>/cmdline 判断(旧版 toybox grep 不认 \| 恒为 0)。
// v5.33: 假 /proc(只有测试进程自己)—— 真 /proc 扫描会被命令行里恰好带 hnc_watchdog 字样的
// 无关进程(比如跑测试的 shell)干扰。
func TestReadWatchdogState(t *testing.T) {
	self := strconv.Itoa(os.Getpid())
	old := watchdogProcFS
	watchdogProcFS = func() procfind.FS {
		return procfind.FS{
			ReadFile: func(p string) ([]byte, error) {
				switch p {
				case "/proc/" + self + "/stat":
					return []byte(self + " (hnc_httpd.test) S 1 0 0 0 0 0 0 0 0 0 1 1 0 0 0 0 0 0 100"), nil
				case "/proc/" + self + "/cmdline":
					return []byte("/tmp/hnc_httpd.test\x00-test.v\x00"), nil
				}
				if strings.HasPrefix(p, "/proc/") {
					return nil, os.ErrNotExist
				}
				return os.ReadFile(p)
			},
			ReadDir: func(string) ([]string, error) { return []string{self}, nil },
		}
	}
	t.Cleanup(func() { watchdogProcFS = old })
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

// v5.33: 看门狗判活走 procfind(与自检 / 功耗统计同一份), 不再有「shell 版」。
// 「改动前会失败」: v5.32 没有 watchdogProcFS 注入点(本用例编译不过), 且自己读 /proc。
func TestReadWatchdogStateProcfind(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	now := time.Unix(1_800_000_000, 0)
	_ = os.WriteFile(filepath.Join(dir, "run", "watchdog.pid"), []byte("4321\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "watchdog.heartbeat"), []byte(strconv.FormatInt(now.Unix()-30, 10)), 0o644)
	fake := map[string]string{
		"/proc/4321/stat":    "4321 (hnc_watchdog) S 1 0 0 0 0 0 0 0 0 0 1 1 0 0 0 0 0 0 100",
		"/proc/4321/cmdline": "/data/local/hnc/bin/hnc_watchdog\x00",
	}
	old := watchdogProcFS
	watchdogProcFS = func() procfind.FS {
		return procfind.FS{
			ReadFile: func(p string) ([]byte, error) {
				if v, ok := fake[p]; ok {
					return []byte(v), nil
				}
				if strings.HasPrefix(p, "/proc/") {
					return nil, os.ErrNotExist
				}
				return os.ReadFile(p)
			},
			ReadDir: func(string) ([]string, error) { return []string{"4321"}, nil },
		}
	}
	t.Cleanup(func() { watchdogProcFS = old })
	st := readWatchdogState(dir, now)
	if st.PID != 4321 || st.Kind != "go" || st.HeartbeatAge != 30 || st.count() != 1 {
		t.Fatalf("got %+v", st)
	}
	delete(fake, "/proc/4321/stat") // 进程没了
	if st := readWatchdogState(dir, now); st.count() != 0 || st.HeartbeatAge != -1 {
		t.Fatalf("进程不在时应判没在跑: %+v", st)
	}
}
