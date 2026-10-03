package main

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"hnc.io/dpid/procfind"
)

// v5.26 T3: /api/proc_health 的 Go 实现, 取代 bin/rc17_process_health.sh。
// JSON 字段与旧 shell 版完全一致(前端 webroot/js/stats.js 不改)。

type phPidfile struct {
	Pid   string `json:"pid"`
	Alive bool   `json:"alive"`
}

type phCounts struct {
	HncHTTPD      int `json:"hnc_httpd"`
	HncDPID       int `json:"hnc_dpid"`
	Hotspotd      int `json:"hotspotd"`
	WatchdogTotal int `json:"watchdog_total"`
	WatchdogMain  int `json:"watchdog_main"`
	GuardTotal    int `json:"dpid_guard_total"`
	GuardMain     int `json:"dpid_guard_main"`
}

type phOut struct {
	SchemaVersion int                  `json:"schema_version"`
	Timestamp     int64                `json:"timestamp"`
	Status        string               `json:"status"`
	Detail        string               `json:"detail"`
	Counts        phCounts             `json:"counts"`
	Pidfiles      map[string]phPidfile `json:"pidfiles"`
}

// buildProcHealth 用一次 /proc 扫描生成 proc_health 数据(语义与 rc17 相同):
//   - counts.*_main = PPID==1 的主实例; *_total = cmdline 含关键字的全部进程
//   - pidfile 只查存活(不校验 cmdline), 与旧版 kill -0 口径一致
//   - 状态级联顺序与旧版一致, 后命中覆盖先命中
func buildProcHealth(fs procfind.FS, hncDir string, now time.Time) phOut {
	tab := fs.Table()
	cl := map[int]string{} // pid → cmdline(只对本次要数的进程读一次)
	for pid := range tab {
		cl[pid] = fs.Cmdline(pid)
	}
	binPrefix := hncDir + "/bin/"

	argv0Base := func(s string) string {
		argv0 := strings.SplitN(s, " ", 2)[0]
		if i := strings.LastIndexByte(argv0, '/'); i >= 0 {
			return argv0[i+1:]
		}
		return argv0
	}
	countBase := func(name string) int { // 对应 rc17 count_proc_by_basename(排除 *.sh)
		n := 0
		for pid := range tab {
			c := cl[pid]
			if argv0Base(c) == name && !strings.Contains(c, ".sh") {
				n++
			}
		}
		return n
	}
	countContains := func(needle string) int { // 对应 count_lines
		n := 0
		for pid := range tab {
			if strings.Contains(cl[pid], needle) {
				n++
			}
		}
		return n
	}
	countMain := func(needles ...string) int { // 对应 count_main: cmdline 命中且 PPID==1
		n := 0
		for pid, r := range tab {
			if r.PPID != 1 {
				continue
			}
			for _, k := range needles {
				if strings.Contains(cl[pid], k) {
					n++
					break
				}
			}
		}
		return n
	}

	out := phOut{
		SchemaVersion: 1,
		Timestamp:     now.Unix(),
		Status:        "ok",
		Detail:        "主实例正常",
		Pidfiles:      map[string]phPidfile{},
	}
	c := &out.Counts
	c.HncHTTPD = countBase("hnc_httpd")
	c.HncDPID = countBase("hnc_dpid")
	c.Hotspotd = countBase("hotspotd")
	c.WatchdogTotal = countContains("watchdog.sh")
	c.WatchdogMain = countMain(binPrefix+"hnc_watchdog", binPrefix+"watchdog.sh")
	c.GuardTotal = countContains("hnc_dpid_guard.sh")
	c.GuardMain = countMain(binPrefix + "hnc_dpid_guard.sh")

	// 看门狗主实例兜底: 父进程不一定是 1(各家 root 的收养者不同),
	// PPID==1 没数到、但 pidfile 指向的进程活着且 cmdline 确实是看门狗 → 算 1。
	readPid := func(name string) (string, int) {
		b, err := fs.ReadFile(hncDir + "/run/" + name)
		if err != nil {
			return "", 0
		}
		s := strings.TrimSpace(string(b))
		pid, _ := strconv.Atoi(s)
		return s, pid
	}
	_, wPid := readPid("watchdog.pid")
	if c.WatchdogMain == 0 && wPid > 0 {
		if _, alive := tab[wPid]; alive && strings.Contains(fs.Cmdline(wPid), "watchdog") {
			c.WatchdogMain = 1
		}
	}

	pf := func(key, file string) {
		raw, pid := readPid(file)
		out.Pidfiles[key] = phPidfile{Pid: raw, Alive: pid > 0 && func() bool { _, ok := tab[pid]; return ok }()}
	}
	pf("httpd", "httpd.pid")
	pf("dpid", "dpid.pid")
	pf("dpid_child", "dpid.child.pid")
	pf("dpid_guard", "dpid_guard.pid")
	pf("hotspotd", "hotspotd.pid")
	pf("watchdog", "watchdog.pid")

	// 状态级联(顺序与 rc17 一致, 后命中覆盖)
	warn := func(d string) { out.Status, out.Detail = "warn", d }
	if c.HncHTTPD != 1 {
		warn("hnc_httpd 数量异常")
	}
	if c.HncDPID != 1 {
		warn("hnc_dpid 数量异常")
	}
	if c.Hotspotd != 1 {
		warn("hotspotd 数量异常")
	}
	if c.WatchdogMain > 1 {
		warn("watchdog 主实例重复")
	}
	if c.GuardMain > 1 {
		warn("dpid_guard 主实例重复")
	}
	if c.WatchdogTotal > 3 {
		warn("watchdog 子进程偏多")
	}
	if c.GuardTotal > 6 {
		warn("dpid_guard 子进程偏多")
	}
	// rc30.8: dpid_guard pidfile 缺失不升 warn(Go supervisor 可能替代了 guard)
	if !out.Pidfiles["hotspotd"].Alive {
		warn("hotspotd pidfile 不可用")
	}
	if !out.Pidfiles["watchdog"].Alive {
		warn("watchdog pidfile 不可用")
	}
	return out
}

// apiProcHealth GET /api/proc_health —— Go 实现(旧版透传 rc17_process_health.sh)。
func (s *server) apiProcHealth(w http.ResponseWriter, r *http.Request) {
	out := buildProcHealth(procfind.New(), s.hncDir, time.Now())
	writeJSON(w, http.StatusOK, out)
}
