// power_stats.go — v5.22 功耗自测: HNC 自己的进程花了多少 CPU / 唤醒了多少次。
//
// 每 5 分钟(以及活动档位变化时, 间隔 ≥60s; 以及 /api/power?refresh=1, 间隔 ≥10s)采一次
// /proc/<pid>/stat 的 utime+stime+cutime+cstime(含已回收子进程 —— shell 守护进程的开销几乎
// 全在它 fork 出的 sed/grep/ip 里)+ 仍存活后代进程的同样四项, 以及 /proc/<pid>/task/*/schedstat
// 第三列(被调度上 CPU 的次数, 近似唤醒次数)。环形保留最近 32 个样本(≥1.5 小时)。
//
// 输出 run/power_stats.json 与 GET /api/power:
//
//	{
//	  "ts", "sample_every_s", "samples",
//	  "activity": {...Activity...}, "level", "level_label",
//	  "processes": [{"name","label","pid","alive","cpu_pct_5m","cpu_pct_1h","cpu_pct_since_start",
//	                 "cpu_sec_per_hour","basis","wakeups_per_min","rss_kb","window_5m_s","window_1h_s"}],
//	  "total": {"cpu_pct_5m","cpu_pct_1h","cpu_sec_per_hour","wakeups_per_min"},
//	  "by_level": [{"level","label","seconds","cpu_sec","cpu_sec_per_hour"}],
//	  "loops": [...powerLoopView...],
//	  "tips": ["..."]
//	}
//
// cpu_pct 以「单核百分比」计(多核时可超过 100); cpu_sec_per_hour = 每小时消耗的 CPU 秒数
// (优先 1 小时窗口, 不足 30 分钟退 5 分钟窗口, 再退进程启动以来平均)。
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	powerSampleEvery    = 5 * time.Minute
	powerRingMax        = 32
	powerMinOnDemand    = 10 * time.Second
	powerMinOnChange    = 60 * time.Second
	powerWarnSecPerHour = 180.0 // 合计 ≥180 CPU 秒/小时(≈单核 5%)算偏高
)

type powerProcDef struct {
	Name     string
	Label    string
	Key      string   // pidfile 校验: cmdline 必含
	PIDFiles []string // run/ 下
	ScanKey  string   // pidfile 失效时扫 /proc: cmdline(NUL→空格)必含
	Self     bool
}

var powerProcDefs = []powerProcDef{
	{"hnc_httpd", "hnc_httpd(含它拉起的脚本)", "httpd", nil, "", true},
	{"hotspotd", "hotspotd", "hotspotd", []string{"hotspotd.pid"}, "bin/hotspotd", false},
	{"hnc_dpid", "hnc_dpid", "dpid", []string{"dpid.child.pid", "dpid.pid"}, "bin/hnc_dpid -config", false},
	{"dpid_guard", "dpid 守护(shell)", "hnc_dpid_guard", []string{"dpid_guard.pid"}, "hnc_dpid_guard.sh", false},
	{"watchdog", "watchdog(shell)", "watchdog", []string{"watchdog.pid"}, "bin/watchdog.sh", false},
	{"offload_guard", "offload 兜底(shell)", "hnc_offload_guard", []string{"offload_guard.pid"}, "hnc_offload_guard.sh daemon", false},
	{"clsact_wd", "clsact 守护(shell)", "hnc_clsact_watchdog", []string{"clsact_wd.pid"}, "hnc_clsact_watchdog.sh", false},
}

type powerProcSample struct {
	PID    int
	Start  uint64 // starttime(ticks), 与 PID 一起识别同一进程
	Ticks  uint64 // 自身 + 已回收子进程 + 存活后代
	Slices uint64 // 各线程被调度次数之和
	RSSKB  int64
}

type powerSample struct {
	At      time.Time // 含单调时钟
	Wall    int64
	UptimeS float64
	Level   string
	Procs   map[string]powerProcSample
}

// powerFS 读 /proc 的入口(测试注入)
type powerFS struct {
	ReadFile func(string) ([]byte, error)
	ReadDir  func(string) ([]string, error)
	SelfPID  int
}

func osPowerFS() powerFS {
	return powerFS{
		ReadFile: os.ReadFile,
		ReadDir: func(p string) ([]string, error) {
			ents, err := os.ReadDir(p)
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(ents))
			for _, e := range ents {
				out = append(out, e.Name())
			}
			return out, nil
		},
		SelfPID: os.Getpid(),
	}
}

// procStatFields /proc/<pid>/stat → ppid, utime+stime, cutime+cstime, starttime
func procStatFields(s string) (ppid int, own, child, start uint64, ok bool) {
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return
	}
	f := strings.Fields(s[i+1:])
	// f[0]=state(3) f[1]=ppid(4) f[11]=utime(14) f[12]=stime(15) f[13]=cutime(16) f[14]=cstime(17) f[19]=starttime(22)
	if len(f) < 20 {
		return
	}
	p, e0 := strconv.Atoi(f[1])
	u, e1 := strconv.ParseUint(f[11], 10, 64)
	st, e2 := strconv.ParseUint(f[12], 10, 64)
	cu, e3 := strconv.ParseInt(f[13], 10, 64) // cutime/cstime 是 long
	cs, e4 := strconv.ParseInt(f[14], 10, 64)
	sv, e5 := strconv.ParseUint(f[19], 10, 64)
	if e0 != nil || e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return
	}
	if cu < 0 {
		cu = 0
	}
	if cs < 0 {
		cs = 0
	}
	return p, u + st, uint64(cu + cs), sv, true
}

// parseSchedstatSlices /proc/<pid>/task/<tid>/schedstat "run_ns wait_ns timeslices" → timeslices
func parseSchedstatSlices(s string) (uint64, bool) {
	f := strings.Fields(s)
	if len(f) < 3 {
		return 0, false
	}
	n, err := strconv.ParseUint(f[2], 10, 64)
	return n, err == nil
}

func (fs powerFS) readTrim(p string) string {
	b, err := fs.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (fs powerFS) cmdline(pid int) string {
	b, err := fs.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

// procTable 一次扫描 /proc: pid → (ppid, own, child, start)
type procRow struct {
	ppid              int
	own, child, start uint64
}

func (fs powerFS) procTable() map[int]procRow {
	out := map[int]procRow{}
	names, err := fs.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, n := range names {
		pid, err := strconv.Atoi(n)
		if err != nil || pid <= 0 {
			continue
		}
		b, err := fs.ReadFile("/proc/" + n + "/stat")
		if err != nil {
			continue
		}
		if pp, own, ch, st, ok := procStatFields(string(b)); ok {
			out[pid] = procRow{pp, own, ch, st}
		}
	}
	return out
}

func (fs powerFS) findPID(d powerProcDef, hncDir string, tab map[int]procRow) int {
	if d.Self && fs.SelfPID > 0 {
		return fs.SelfPID
	}
	for _, f := range d.PIDFiles {
		pid, err := strconv.Atoi(fs.readTrim(filepath.Join(hncDir, "run", f)))
		if err != nil || pid <= 0 {
			continue
		}
		if _, ok := tab[pid]; !ok {
			continue
		}
		if cl := fs.cmdline(pid); cl == "" || strings.Contains(cl, d.Key) {
			return pid
		}
	}
	if d.ScanKey == "" {
		return 0
	}
	pids := make([]int, 0, len(tab))
	for pid := range tab {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	for _, pid := range pids {
		if strings.Contains(fs.cmdline(pid), d.ScanKey) {
			return pid
		}
	}
	return 0
}

// descTicks 存活后代进程的 own+child 之和(不含 root 自己)
func descTicks(root int, tab map[int]procRow) uint64 {
	kids := map[int][]int{}
	for pid, r := range tab {
		kids[r.ppid] = append(kids[r.ppid], pid)
	}
	var sum uint64
	seen := map[int]bool{root: true}
	stack := append([]int(nil), kids[root]...)
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[p] {
			continue
		}
		seen[p] = true
		r := tab[p]
		sum += r.own + r.child
		stack = append(stack, kids[p]...)
	}
	return sum
}

func (fs powerFS) threadSlices(pid int) uint64 {
	tids, err := fs.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		n, _ := parseSchedstatSlices(fs.readTrim(fmt.Sprintf("/proc/%d/schedstat", pid)))
		return n
	}
	var sum uint64
	for _, t := range tids {
		if n, ok := parseSchedstatSlices(fs.readTrim(fmt.Sprintf("/proc/%d/task/%s/schedstat", pid, t))); ok {
			sum += n
		}
	}
	return sum
}

// takePowerSample 采一次(纯 I/O, 无全局状态)
func takePowerSample(fs powerFS, hncDir string, now time.Time, level string) powerSample {
	tab := fs.procTable()
	smp := powerSample{At: now, Wall: now.Unix(), Level: level, Procs: map[string]powerProcSample{}}
	if f := strings.Fields(fs.readTrim("/proc/uptime")); len(f) > 0 {
		smp.UptimeS, _ = strconv.ParseFloat(f[0], 64)
	}
	for _, d := range powerProcDefs {
		pid := fs.findPID(d, hncDir, tab)
		r, ok := tab[pid]
		if pid <= 0 || !ok {
			continue
		}
		ps := powerProcSample{PID: pid, Start: r.start, Ticks: r.own + r.child + descTicks(pid, tab)}
		ps.Slices = fs.threadSlices(pid)
		ps.RSSKB = scParseVmRSS(fs.readTrim(fmt.Sprintf("/proc/%d/status", pid)))
		smp.Procs[d.Name] = ps
	}
	return smp
}

// ─── 计算 ─────────────────────────────────────────────────────────

// powerWindow 在 ring(旧→新)里找与 latest 同一进程、相隔约 span 的样本。
// 优先「最新的一个 ≤ latest-span」; 没有时退最老的同进程样本(要求 ≥60s)。
func powerWindow(ring []powerSample, name string, latest powerSample, span time.Duration) (dTicks, dSlices uint64, dt float64, ok bool) {
	cur, have := latest.Procs[name]
	if !have {
		return
	}
	var base *powerSample
	for i := len(ring) - 1; i >= 0; i-- {
		s := &ring[i]
		p, h := s.Procs[name]
		if !h || p.PID != cur.PID || p.Start != cur.Start || !s.At.Before(latest.At) {
			continue
		}
		if latest.At.Sub(s.At) >= span {
			base = s
			break
		}
	}
	if base == nil {
		for i := 0; i < len(ring); i++ {
			s := &ring[i]
			p, h := s.Procs[name]
			if h && p.PID == cur.PID && p.Start == cur.Start && latest.At.Sub(s.At) >= time.Minute {
				base = s
				break
			}
		}
	}
	if base == nil {
		return
	}
	p := base.Procs[name]
	if cur.Ticks < p.Ticks {
		return
	}
	dTicks = cur.Ticks - p.Ticks
	if cur.Slices >= p.Slices {
		dSlices = cur.Slices - p.Slices
	}
	dt = latest.At.Sub(base.At).Seconds()
	return dTicks, dSlices, dt, dt > 0
}

func round3(f float64) float64 { return float64(int64(f*1000+0.5)) / 1000 }

func cpuPct(dTicks uint64, dt float64) float64 {
	if dt <= 0 {
		return 0
	}
	return float64(dTicks) / userHZ / dt * 100
}

type powerProcView struct {
	Name          string  `json:"name"`
	Label         string  `json:"label"`
	PID           int     `json:"pid"`
	Alive         bool    `json:"alive"`
	CPU5m         float64 `json:"cpu_pct_5m"`
	CPU1h         float64 `json:"cpu_pct_1h"`
	CPUSinceStart float64 `json:"cpu_pct_since_start"`
	CPUSecPerHour float64 `json:"cpu_sec_per_hour"`
	Basis         string  `json:"basis"` // 1h | 5m | since_start | none
	WakeupsPerMin float64 `json:"wakeups_per_min"`
	RSSKB         int64   `json:"rss_kb"`
	Window5mS     int64   `json:"window_5m_s"`
	Window1hS     int64   `json:"window_1h_s"`
}

type powerTotal struct {
	CPU5m         float64 `json:"cpu_pct_5m"`
	CPU1h         float64 `json:"cpu_pct_1h"`
	CPUSecPerHour float64 `json:"cpu_sec_per_hour"`
	WakeupsPerMin float64 `json:"wakeups_per_min"`
	RSSKB         int64   `json:"rss_kb"`
}

type powerLevelView struct {
	Level         string  `json:"level"`
	Label         string  `json:"label"`
	Seconds       int64   `json:"seconds"`
	CPUSec        float64 `json:"cpu_sec"`
	CPUSecPerHour float64 `json:"cpu_sec_per_hour"`
}

// powerProcViews 由样本环算各进程视图(纯函数)
func powerProcViews(ring []powerSample) ([]powerProcView, powerTotal) {
	var tot powerTotal
	out := make([]powerProcView, 0, len(powerProcDefs))
	if len(ring) == 0 {
		for _, d := range powerProcDefs {
			out = append(out, powerProcView{Name: d.Name, Label: d.Label, Basis: "none"})
		}
		return out, tot
	}
	latest := ring[len(ring)-1]
	hist := ring[:len(ring)-1]
	for _, d := range powerProcDefs {
		v := powerProcView{Name: d.Name, Label: d.Label, Basis: "none"}
		cur, ok := latest.Procs[d.Name]
		if !ok {
			out = append(out, v)
			continue
		}
		v.PID, v.Alive, v.RSSKB = cur.PID, true, cur.RSSKB
		tot.RSSKB += cur.RSSKB
		var p5, p1, ps float64
		if dT, dS, dt, ok := powerWindow(hist, d.Name, latest, powerSampleEvery); ok {
			p5, v.Window5mS = cpuPct(dT, dt), int64(dt)
			v.WakeupsPerMin = round2(float64(dS) / dt * 60)
			tot.CPU5m += p5
			tot.WakeupsPerMin += float64(dS) / dt * 60
		}
		if dT, _, dt, ok := powerWindow(hist, d.Name, latest, time.Hour); ok {
			p1, v.Window1hS = cpuPct(dT, dt), int64(dt)
			tot.CPU1h += p1
		}
		life := -1.0
		if latest.UptimeS > 0 {
			if life = latest.UptimeS - float64(cur.Start)/userHZ; life > 0 {
				ps = float64(cur.Ticks) / userHZ / life * 100
			}
		}
		v.CPU5m, v.CPU1h, v.CPUSinceStart = round3(p5), round3(p1), round3(ps)
		var sph float64
		switch {
		case v.Window1hS >= 1800:
			sph, v.Basis = p1*36, "1h"
		case v.Window5mS > 0:
			sph, v.Basis = p5*36, "5m"
		case life > 0:
			sph, v.Basis = ps*36, "since_start"
		}
		v.CPUSecPerHour = round2(sph)
		tot.CPUSecPerHour += sph
		out = append(out, v)
	}
	tot.CPU5m, tot.CPU1h = round3(tot.CPU5m), round3(tot.CPU1h)
	tot.CPUSecPerHour, tot.WakeupsPerMin = round2(tot.CPUSecPerHour), round2(tot.WakeupsPerMin)
	return out, tot
}

// powerLevelAcc 按档位累计(相邻两样本的增量记到前一个样本的档位 —— 档位变化会触发采样)
type powerLevelAcc struct {
	Seconds float64
	Ticks   uint64
}

func powerAccumulate(acc map[string]*powerLevelAcc, prev, cur powerSample) {
	dt := cur.At.Sub(prev.At).Seconds()
	if dt <= 0 || prev.Level == "" {
		return
	}
	var dT uint64
	for name, c := range cur.Procs {
		p, ok := prev.Procs[name]
		if !ok || p.PID != c.PID || p.Start != c.Start || c.Ticks < p.Ticks {
			continue
		}
		dT += c.Ticks - p.Ticks
	}
	a := acc[prev.Level]
	if a == nil {
		a = &powerLevelAcc{}
		acc[prev.Level] = a
	}
	a.Seconds += dt
	a.Ticks += dT
}

func powerLevelViews(acc map[string]*powerLevelAcc) []powerLevelView {
	out := []powerLevelView{}
	for _, lvl := range []string{lvlActive, lvlBackground, lvlNoClients, lvlHotspotOff, lvlUnknown} {
		a := acc[lvl]
		if a == nil || a.Seconds <= 0 {
			continue
		}
		sec := float64(a.Ticks) / userHZ
		out = append(out, powerLevelView{Level: lvl, Label: activityLevelLabel[lvl], Seconds: int64(a.Seconds),
			CPUSec: round2(sec), CPUSecPerHour: round2(sec / a.Seconds * 3600)})
	}
	return out
}

// powerTips 建议(纯函数)
func powerTips(a Activity, procs []powerProcView, tot powerTotal, f loopFlags) []string {
	var tips []string
	if tot.CPUSecPerHour >= powerWarnSecPerHour {
		top := ""
		best := -1.0
		for _, p := range procs {
			if p.CPUSecPerHour > best {
				best, top = p.CPUSecPerHour, p.Label
			}
		}
		tips = append(tips, fmt.Sprintf("HNC 合计约 %.0f CPU 秒/小时, 偏高; 占用最多的是 %s", tot.CPUSecPerHour, top))
	}
	if a.Known && !a.ScreenKnown {
		tips = append(tips, "无法判断亮/熄屏(无背光节点且 dumpsys 不可用): 与熄屏相关的降频不生效(热点/设备相关的仍有效)")
	} else if a.ScreenSource == "power" || a.ScreenSource == "display" {
		tips = append(tips, "亮/熄屏靠 dumpsys 判定(背光节点缺失或与系统不一致), 每分钟多一次轻量进程开销")
	}
	if !f.CtPrecise {
		tips = append(tips, "conntrack 事件订阅不可用: 后台时按应用流量采样无法从 10s 放慢到 30s(放慢会漏短连接)")
	}
	if f.Enforcing && a.computeLevel() == lvlBackground {
		tips = append(tips, "已配置应用时长上限/封锁: 为保证执法及时, 后台时按应用采样保持 10s")
	}
	if a.WebUIActive {
		tips = append(tips, "界面打开时速率按 2s 刷新; 关掉界面 1 分钟后自动降到 20s")
	}
	for _, p := range procs {
		if p.Name == "hnc_dpid" && a.Known && !a.HotspotActive && p.CPU5m >= 1 {
			tips = append(tips, fmt.Sprintf("热点未开时 dpid 仍占 %.1f%% CPU, 可在 DPI 设置里关闭「本机流量归因」", p.CPU5m))
		}
	}
	if len(tips) == 0 {
		tips = append(tips, "功耗正常: 后台循环已按热点/设备/屏幕状态自动降频")
	}
	return tips
}

// ─── 采样器 + API ─────────────────────────────────────────────────

var powerSt struct {
	mu     sync.Mutex
	ring   []powerSample
	levels map[string]*powerLevelAcc
	fs     powerFS
}

func (s *server) powerSampleNow(now time.Time, minGap time.Duration) bool {
	powerSt.mu.Lock()
	defer powerSt.mu.Unlock()
	if n := len(powerSt.ring); n > 0 && now.Sub(powerSt.ring[n-1].At) < minGap {
		return false
	}
	if powerSt.fs.ReadFile == nil {
		powerSt.fs = osPowerFS()
	}
	if powerSt.levels == nil {
		powerSt.levels = map[string]*powerLevelAcc{}
	}
	smp := takePowerSample(powerSt.fs, s.hncDir, now, activityNow().computeLevel())
	if n := len(powerSt.ring); n > 0 {
		powerAccumulate(powerSt.levels, powerSt.ring[n-1], smp)
	}
	powerSt.ring = append(powerSt.ring, smp)
	if len(powerSt.ring) > powerRingMax {
		powerSt.ring = append([]powerSample(nil), powerSt.ring[len(powerSt.ring)-powerRingMax:]...)
	}
	return true
}

func (s *server) powerReport(now time.Time) map[string]interface{} {
	powerSt.mu.Lock()
	ring := append([]powerSample(nil), powerSt.ring...)
	levels := powerLevelViews(powerSt.levels)
	powerSt.mu.Unlock()
	a := activityNow()
	f := s.appUsageFlags()
	procs, tot := powerProcViews(ring)
	var sampledAt int64
	if len(ring) > 0 {
		sampledAt = ring[len(ring)-1].Wall
	}
	loops := powerLoopsView(a, f, now)
	// 镜像条目里只有 shell 知道的状态: offload guard 兜底中时永远 60s 重申
	if g := readOffloadGuard(s.hncDir); g != nil && g["fallback_active"] == true {
		for i := range loops {
			if loops[i].Name == "offload_guard" {
				loops[i].CurrentS, loops[i].Multiplier = loops[i].BaseS, 1
				loops[i].Reason = "兜底生效中: 每 60s 重申 limit_map(不随状态放慢)"
			}
		}
	}
	return map[string]interface{}{
		"ts":             now.Unix(),
		"sampled_at":     sampledAt,
		"sample_every_s": int(powerSampleEvery / time.Second),
		"samples":        len(ring),
		"activity":       a,
		"level":          a.computeLevel(),
		"level_label":    activityLevelLabel[a.computeLevel()],
		"processes":      procs,
		"total":          tot,
		"by_level":       levels,
		"loops":          loops,
		"tips":           powerTips(a, procs, tot, f),
	}
}

func (s *server) writePowerStats(now time.Time) {
	b, err := json.Marshal(s.powerReport(now))
	if err != nil {
		return
	}
	p := filepath.Join(s.hncDir, "run", "power_stats.json")
	if os.WriteFile(p+".tmp", b, 0o644) == nil {
		_ = os.Rename(p+".tmp", p)
	}
}

// PowerSamplerLoop 每 5 分钟采样; 活动档位变化时(间隔 ≥60s)也采, 让 by_level 分得清。
func (s *server) PowerSamplerLoop(stop <-chan struct{}) {
	now := time.Now()
	s.powerSampleNow(now, 0)
	s.writePowerStats(now)
	powerRecord("power_sampler", powerSampleEvery, "固定", now)
	for {
		ch := activityChanged()
		t := time.NewTimer(powerSampleEvery)
		minGap := time.Duration(0)
		select {
		case <-stop:
			t.Stop()
			return
		case <-t.C:
		case <-ch:
			t.Stop()
			minGap = powerMinOnChange
		}
		now := time.Now()
		if s.powerSampleNow(now, minGap) {
			s.writePowerStats(now)
			powerRecord("power_sampler", powerSampleEvery, "固定(档位变化时加采)", now)
		}
	}
}

// apiPower GET /api/power[?refresh=1]
func (s *server) apiPower(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	now := time.Now()
	if r.URL.Query().Get("refresh") == "1" {
		if s.powerSampleNow(now, powerMinOnDemand) {
			s.writePowerStats(now)
		}
	}
	writeJSON(w, http.StatusOK, s.powerReport(now))
}

// ─── 自检 ─────────────────────────────────────────────────────────

// scPowerItem 自检「进程与资源」里的「功耗」汇总(读 run/power_stats.json)
func scPowerItem(c *scCtx) scItem {
	it := scItem{ID: "power", Label: "功耗"}
	m := c.readJSON(c.hnc("run", "power_stats.json"))
	if m == nil {
		it.Status, it.Value = scInfo, "暂无数据"
		it.Detail = "httpd 启动后立即采第一份样本, 5 分钟后才有 CPU 占比"
		return it
	}
	tot, _ := m["total"].(map[string]interface{})
	sph, _ := tot["cpu_sec_per_hour"].(float64)
	wk, _ := tot["wakeups_per_min"].(float64)
	label := asString(m["level_label"])
	it.Status = scOK
	it.Value = fmt.Sprintf("约 %.0f CPU 秒/小时 · 唤醒 %.0f 次/分钟", sph, wk)
	if label != "" {
		it.Value += " · " + label
	}
	var parts []string
	if procs, ok := m["processes"].([]interface{}); ok {
		for _, raw := range procs {
			p, _ := raw.(map[string]interface{})
			if p == nil || p["alive"] != true {
				continue
			}
			v, _ := p["cpu_sec_per_hour"].(float64)
			parts = append(parts, fmt.Sprintf("%s %.0fs", asString(p["name"]), v))
		}
	}
	if len(parts) > 0 {
		it.Detail = "每小时 CPU 秒: " + strings.Join(parts, " / ")
	}
	if sph >= powerWarnSecPerHour {
		it.Status = scWarn
		it.Fix = "打开「功耗」详情(/api/power)查看占用最多的进程与各循环当前间隔"
	}
	if samples, _ := m["samples"].(float64); samples < 2 {
		it.Status = scInfo
		it.Detail = strings.TrimSpace(it.Detail + "(样本不足, 数值仅供参考)")
	}
	return it
}
