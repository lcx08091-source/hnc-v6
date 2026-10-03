package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"hnc.io/dpid/procfind"
)

// v5.26 T3: /api/proc_health Go 实现的单测(与被删的 rc17_process_health.sh
// 字段/级联语义一致)。

type phFake struct {
	files map[string]string
}

func (f phFake) setStat(pid, ppid int, comm string) {
	f.files[fmt.Sprintf("/proc/%d/stat", pid)] =
		fmt.Sprintf("%d (%s) S %d 1 1 0 -1 4194624 0 0 0 0 5 5 0 0 0 0 1 0 100 0 0 0 0 0 0 0 0 0 0", pid, comm, ppid)
}

func (f phFake) setCmd(pid int, cl string) {
	f.files[fmt.Sprintf("/proc/%d/cmdline", pid)] = strings.ReplaceAll(cl, " ", "\x00")
}

func (f phFake) fs() procfind.FS {
	return procfind.FS{
		ReadFile: func(p string) ([]byte, error) {
			if s, ok := f.files[p]; ok {
				return []byte(s), nil
			}
			return nil, fmt.Errorf("no such file: %s", p)
		},
		ReadDir: func(p string) ([]string, error) {
			if p != "/proc" {
				return nil, fmt.Errorf("bad dir %s", p)
			}
			seen := map[string]bool{}
			for k := range f.files {
				if strings.HasPrefix(k, "/proc/") && strings.HasSuffix(k, "/stat") {
					seen[strings.TrimSuffix(strings.TrimPrefix(k, "/proc/"), "/stat")] = true
				}
			}
			out := make([]string, 0, len(seen))
			for n := range seen {
				out = append(out, n)
			}
			return out, nil
		},
		SelfPID: 7,
	}
}

// 正常场景: 单实例各就各位 → status=ok, detail=主实例正常
func TestBuildProcHealthOK(t *testing.T) {
	f := phFake{files: map[string]string{}}
	f.setStat(7, 1, "hnc_httpd") // self
	f.setCmd(7, "/data/local/hnc/daemon/hnc_httpd/hnc_httpd")
	f.setStat(10, 1, "hotspotd") // ppid=1
	f.setCmd(10, "/data/local/hnc/bin/hotspotd")
	f.setStat(11, 1, "hnc_dpid")
	f.setCmd(11, "/data/local/hnc/bin/hnc_dpid -config /data/local/hnc/etc/dpi_config.json")
	f.setStat(12, 1, "hnc_watchdog")
	f.setCmd(12, "/data/local/hnc/bin/hnc_watchdog")
	f.files["/data/local/hnc/run/hotspotd.pid"] = "10\n"
	f.files["/data/local/hnc/run/watchdog.pid"] = "12\n"
	f.files["/data/local/hnc/run/dpid.pid"] = "11\n"

	out := buildProcHealth(f.fs(), "/data/local/hnc", time.Unix(1700000000, 0))
	if out.Status != "ok" || out.Detail != "主实例正常" {
		t.Fatalf("status=%q detail=%q, want ok/主实例正常", out.Status, out.Detail)
	}
	if out.Counts.HncHTTPD != 1 || out.Counts.Hotspotd != 1 || out.Counts.HncDPID != 1 {
		t.Fatalf("counts = %+v", out.Counts)
	}
	if out.Counts.WatchdogMain != 1 {
		t.Fatalf("watchdog_main = %d, want 1(ppid=1 + 完整路径)", out.Counts.WatchdogMain)
	}
	if !out.Pidfiles["hotspotd"].Alive || out.Pidfiles["hotspotd"].Pid != "10" {
		t.Fatalf("hotspotd pidfile = %+v", out.Pidfiles["hotspotd"])
	}
	// JSON 字段快照(与旧 shell 版字段一致)
	b, _ := json.Marshal(out)
	for _, k := range []string{`"schema_version":1`, `"timestamp":1700000000`, `"status":"ok"`,
		`"watchdog_total"`, `"watchdog_main"`, `"dpid_guard_total"`, `"dpid_guard_main"`,
		`"hnc_httpd"`, `"hnc_dpid"`, `"hotspotd"`, `"dpid_child"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("JSON 缺字段 %s: %s", k, b)
		}
	}
}

// watchdog 主实例兜底: PPID≠1 但 pidfile 指向的进程 cmdline 含 watchdog → main=1
func TestBuildProcHealthWatchdogFallback(t *testing.T) {
	f := phFake{files: map[string]string{}}
	f.setStat(7, 1, "hnc_httpd")
	f.setCmd(7, "/data/local/hnc/daemon/hnc_httpd/hnc_httpd")
	f.setStat(10, 1, "hotspotd")
	f.setCmd(10, "hotspotd")
	f.setStat(11, 1, "hnc_dpid")
	f.setCmd(11, "hnc_dpid -config c")
	// watchdog 被 root 方案收养, ppid≠1
	f.setStat(20, 99, "hnc_watchdog")
	f.setCmd(20, "/data/local/hnc/bin/hnc_watchdog")
	f.files["/hnc/run/hotspotd.pid"] = "10\n"
	f.files["/hnc/run/watchdog.pid"] = "20\n"

	out := buildProcHealth(f.fs(), "/hnc", time.Unix(1, 0))
	if out.Counts.WatchdogMain != 1 {
		t.Fatalf("watchdog_main = %d, want 1(pidfile 兜底)", out.Counts.WatchdogMain)
	}
	if out.Status != "ok" {
		t.Fatalf("status = %q (%s), want ok", out.Status, out.Detail)
	}
}

// 级联: hotspotd 双实例 → warn "hotspotd 数量异常"(后面的 pidfile 检查不覆盖它)
func TestBuildProcHealthDupHotspotd(t *testing.T) {
	f := phFake{files: map[string]string{}}
	f.setStat(7, 1, "hnc_httpd")
	f.setCmd(7, "/x/hnc_httpd")
	f.setStat(10, 1, "hotspotd")
	f.setCmd(10, "hotspotd")
	f.setStat(30, 1, "hotspotd")
	f.setCmd(30, "hotspotd")
	f.setStat(11, 1, "hnc_dpid")
	f.setCmd(11, "hnc_dpid -config c")
	f.setStat(12, 1, "hnc_watchdog")
	f.setCmd(12, "/data/local/hnc/bin/hnc_watchdog")
	f.files["/hnc/run/hotspotd.pid"] = "10\n"
	f.files["/hnc/run/watchdog.pid"] = "12\n"

	out := buildProcHealth(f.fs(), "/hnc", time.Unix(1, 0))
	if out.Status != "warn" || out.Detail != "hotspotd 数量异常" {
		t.Fatalf("status=%q detail=%q, want warn/hotspotd 数量异常", out.Status, out.Detail)
	}
}

// shell 守护脚本不计数: "sh xxx.sh hnc_dpid" 这类包装行不进 argv0 计数
func TestBuildProcHealthScriptNotCounted(t *testing.T) {
	f := phFake{files: map[string]string{}}
	f.setStat(7, 1, "hnc_httpd")
	f.setCmd(7, "/x/hnc_httpd")
	f.setStat(10, 1, "hotspotd")
	f.setCmd(10, "hotspotd")
	f.setStat(11, 1, "hnc_dpid")
	f.setCmd(11, "hnc_dpid -config c")
	// 一个 sh 包装进程, cmdline 里带 .sh 与 hnc_dpid 字样
	f.setStat(50, 1, "sh")
	f.setCmd(50, "sh /data/local/hnc/bin/some_helper.sh hnc_dpid")
	f.setStat(12, 1, "hnc_watchdog")
	f.setCmd(12, "/data/local/hnc/bin/hnc_watchdog")
	f.files["/hnc/run/hotspotd.pid"] = "10\n"
	f.files["/hnc/run/watchdog.pid"] = "12\n"

	out := buildProcHealth(f.fs(), "/hnc", time.Unix(1, 0))
	if out.Counts.HncDPID != 1 {
		t.Fatalf("hnc_dpid count = %d, want 1(.sh 包装不计数)", out.Counts.HncDPID)
	}
	if out.Status != "ok" {
		t.Fatalf("status = %q (%s)", out.Status, out.Detail)
	}
}
