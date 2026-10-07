// offload_sched.go — v5.29 T2(M3): hnc_offload_guard.sh 与
// hnc_clsact_watchdog.sh 两个常驻 shell 循环改由 Go 看门狗调度。
//
// 只把「谁来按时调用」搬进 Go —— 检测 / 兜底逻辑全留在 shell:
//   - offload:  每 30 分钟由 `sh bin/hnc_offload_guard.sh plan`(30 秒
//     超时, 经动作记账, 动作名 offload_guard_plan)跑一轮并拿「下次睡
//     几秒 + 早醒条件」; 睡眠期间每 30 秒看一次 activity 快照, 早醒
//     条件满足就提前进入下一轮。解析失败按 60 秒。
//   - clsact:   rules.json 的 clsact_bpf_mode=on(含旧键兼容, 判断照抄
//     guard_mode)且 hnc_clsact.o / hnc_clsact_ctl 都在时, 每 10 秒 Go
//     直接 exec `hnc_clsact_ctl check <口>`(不经 sh), 输出不含
//     "ok":true 才调 `sh bin/hnc_clsact_watchdog.sh repair <口>`。
//     门控(clsact_wanted)结果缓存 60 秒, 不再每 10 秒起 sh。
//
// 常驻进程因此少 2 个(offload_guard / clsact_wd); service.sh 写
// run/offload_guard.owner=watchdog 之后, httpd 调 apply 也不会把 shell
// 循环拉回来(ensure_daemon / daemon 子命令开头认 owner)。
//
// 开关: run/wd_m3.disabled 存在 → 看门狗不接管(service.sh 照旧拉 shell
// 守护, 下次开机生效)。
//
// 可测性: 循环节拍抽成 offloadPlanner / clsactSched 两个纯状态机
// (advance(now) 决定「现在该不该跑」), 外部调用(plan 执行 / clsact
// check / activity / 时钟)全部包级变量注入, budget_test 直接驱动。
package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	offloadFirstDelay  = 20 * time.Second // 启动后 20 秒第一轮(照抄 shell daemon)
	offloadPlanTimeout = 30 * time.Second
	offloadFallback    = 60 * time.Second // plan 解析失败 / 空输出
	offloadWakeEvery   = 30 * time.Second // 早醒检查周期(照抄 hnc_act_sleep_until 的 IDLE_CHUNK)
	offloadMaxSec      = 900              // 与 shell INTERVAL/IDLE_INTERVAL 的上界一致
	clsactCheckEvery   = 10 * time.Second
	clsactGateEvery    = 60 * time.Second
)

// ── 可注入外部调用 ──────────────────────────────────────────────────
var (
	// runOffloadPlanFn 跑一轮 plan(默认 runOffloadPlan, 返回末行)。
	runOffloadPlanFn = runOffloadPlan
	// clsactCheckFn 直接 exec hnc_clsact_ctl check(默认 execClsactCheck)。
	clsactCheckFn = execClsactCheck
	// clsactGateFn 门控「clsact 想不想要」(默认读文件 + 直接 exec tc, 不起 sh)。
	clsactGateFn = clsactWanted
	// clsactIfaceFn 热点口(默认 clsactHotspotIface)。
	clsactIfaceFn = clsactHotspotIface
)

// runOffloadPlan 执行 `sh bin/hnc_offload_guard.sh plan`, 30 秒超时, 经
// 动作记账(动作名 offload_guard_plan), 返回输出末行(空 = 失败)。
func runOffloadPlan() string {
	start := nowFn()
	ctx, cancel := context.WithTimeout(context.Background(), offloadPlanTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, shellPath(), binDir+"/hnc_offload_guard.sh", "plan")
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return cmd.Process.Kill()
	}
	out, err := cmd.Output()
	rc := 0
	if ee, ok := err.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if err != nil {
		rc = -1
	}
	elapsed := nowFn().Sub(start).Seconds() * 1000
	runStatsFn("offload_guard_plan", rc, err, elapsed, nowFn())
	line := ""
	if rc == 0 {
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		line = strings.TrimSpace(lines[len(lines)-1])
	}
	return line
}

// parseOffloadPlan plan 的末行 "<秒> <早醒条件>"。
// 坏行 / 空 / 秒数超界 → 60 秒兜底(wake=none)。纯函数。
func parseOffloadPlan(line string) (time.Duration, string) {
	f := strings.Fields(line)
	if len(f) < 1 {
		return offloadFallback, "none"
	}
	sec, err := strconv.Atoi(f[0])
	if err != nil || sec <= 0 || sec > offloadMaxSec {
		return offloadFallback, "none"
	}
	wake := "none"
	if len(f) >= 2 && (f[1] == "hotspot" || f[1] == "clients") {
		wake = f[1]
	}
	return time.Duration(sec) * time.Second, wake
}

// offloadPlanner offload 调度状态机: 记录上一轮 plan 决定的睡眠计划,
// advance(now) 判断现在是否该跑下一轮(睡满 / 早醒 / 首轮)。
type offloadPlanner struct {
	started   bool
	nextAt    time.Time // 下一轮 plan 时刻(睡满时间)
	wakeMode  string    // hotspot | clients | none
	planCalls int
}

// advance 现在该不该跑 plan。early: activity 层面是否已满足早醒条件。
func (p *offloadPlanner) advance(now time.Time, early bool) bool {
	if !p.started {
		p.started = true
		return true // 启动后第一轮
	}
	if early {
		return true
	}
	return !now.Before(p.nextAt)
}

// observe 记录本轮 plan 的结论, 算下一轮时刻。
func (p *offloadPlanner) observe(dur time.Duration, wake string, now time.Time) {
	p.planCalls++
	p.nextAt = now.Add(dur)
	p.wakeMode = wake
}

// offloadEarlyWake 早醒条件是否满足(hotspot = 热点开了; clients = 有
// 在线设备)。level 是 activity 的 level 字符串。
func offloadEarlyWake(wake, level string, clients int) bool {
	switch wake {
	case "hotspot":
		return level != "" && level != "hotspot_off"
	case "clients":
		return clients > 0
	}
	return false
}

// startOffloadSched 常驻 goroutine: 20 秒后第一轮, 之后按 plan 睡。
func startOffloadSched() {
	if m3Disabled() {
		logf("M3 disabled: run/wd_m3.disabled, offload/clsact 由 shell 守护负责")
		return
	}
	go offloadLoop()
	go clsactLoop()
}

func m3Disabled() bool {
	_, err := os.Stat(runDir + "/wd_m3.disabled")
	return err == nil
}

func offloadLoop() {
	p := &offloadPlanner{}
	// 启动 20 秒后第一轮(让热点/hotspotd 就绪, 照抄 shell daemon)
	time.Sleep(offloadFirstDelay)
	last := nowFn()
	for {
		// 睡到下一检查点(早醒检查每 30 秒一次, 不会睡过头超过 30 秒)
		if d := time.Until(last); d > 0 {
			time.Sleep(d)
		}
		last = last.Add(offloadWakeEvery)
		now := nowFn()
		s := actSnapshotFn()
		early := s.OK && offloadEarlyWake(p.wakeMode, s.Level, s.Clients) // 同 shell: 快照不新鲜不早醒
		if p.advance(now, early) {
			dur, wake := parseOffloadPlan(runOffloadPlanFn())
			p.observe(dur, wake, now)
			last = now.Add(offloadWakeEvery)
		}
	}
}

// ── clsact 调度 ─────────────────────────────────────────────────────

// clsactSched clsact 检查状态机。
type clsactSched struct {
	lastGate  time.Time
	gateIface string
	gateOK    bool
	checks    int
	repairs   int // 修复调用次数(测试断言用)
}

func (c *clsactSched) gateDue(now time.Time) bool {
	return now.Sub(c.lastGate) >= clsactGateEvery
}

// execClsactCheck 直接 exec hnc_clsact_ctl check <口>(不经 sh)。
// 返回输出(空 = 失败)。
func execClsactCheck(iface string) string {
	b, err := exec.Command(binDir+"/hnc_clsact_ctl", "check", iface).CombinedOutput()
	if err != nil {
		return ""
	}
	return string(b)
}

// clsactWanted 门控, 照抄 hnc_clsact_watchdog.sh 的 clsact_enabled →
// hnc_offload_guard.sh clsact_wanted(on 模式那一支): hnc_clsact.o 与
// hnc_clsact_ctl 都在、clsact_bpf_mode=on(或旧键 clsact_bpf_enabled=true),
// 且热点口 ingress pref 1 没被 HNC 上行 mirred 占用(占用时装不上, 旧 shell
// 守护直接退出; 不判这一条的话 on 模式 + 上行限速会每 10 秒起一次 sh
// repair)。结果由调用方缓存 60 秒。
func clsactWanted(iface string) bool {
	if _, err := os.Stat(binDir + "/hnc_clsact.o"); err != nil {
		return false
	}
	if _, err := os.Stat(binDir + "/hnc_clsact_ctl"); err != nil {
		return false
	}
	if !rulesClsactModeOn() {
		return false
	}
	return iface == "" || !pref1HeldByMirred(iface)
}

// pref1HeldByMirred 同 shell pref1_held_by_mirred: 两种写法任一能看到
// `mirred.*redirect.*ifb0`(不区分大小写)即算占用。直接 exec tc, 不经 sh。
func pref1HeldByMirred(iface string) bool {
	for _, args := range [][]string{
		{"filter", "show", "dev", iface, "ingress"},
		{"filter", "show", "dev", iface, "parent", "ffff:"},
	} {
		if out, rc, _ := execCommandFn("tc", args...); rc == 0 && pref1MirredLine(out) {
			return true
		}
	}
	return false
}

// pref1MirredLine 同 `grep -qiE "mirred.*redirect.*ifb0"`(逐行)。
func pref1MirredLine(out string) bool {
	for _, ln := range strings.Split(strings.ToLower(out), "\n") {
		if i := strings.Index(ln, "mirred"); i >= 0 {
			if j := strings.Index(ln[i:], "redirect"); j >= 0 && strings.Contains(ln[i+j:], "ifb0") {
				return true
			}
		}
	}
	return false
}

// rulesClsactModeOn rules.json 的 clsact_bpf_mode(guard_mode 的 on 判定,
// 含旧键兼容)。
func rulesClsactModeOn() bool {
	b, err := os.ReadFile(natDataDir + "/rules.json")
	if err != nil {
		return false
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	if v, ok := m["clsact_bpf_mode"].(string); ok {
		return v == "on"
	}
	if v, ok := m["clsact_bpf_enabled"].(bool); ok { // 旧键兼容
		return v
	}
	return false
}

// clsactHotspotIface 热点口(hnc_state ACTIVE:<口> → hotspot_iface →
// wlan2/ap0/swlan0 探测, 照抄 hnc_clsact_watchdog.sh get_hotspot_iface)。
func clsactHotspotIface() string {
	if b, err := os.ReadFile(runDir + "/hnc_state"); err == nil {
		line := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
		if strings.HasPrefix(line, "ACTIVE:") {
			ifc := strings.TrimSpace(strings.TrimPrefix(line, "ACTIVE:"))
			if ifc != "" {
				return ifc
			}
		}
	}
	if b, err := os.ReadFile(runDir + "/hotspot_iface"); err == nil {
		if ifc := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0]); ifc != "" {
			return ifc
		}
	}
	for _, c := range []string{"wlan2", "ap0", "swlan0"} {
		if _, err := netInterfaceByNameFn(c); err == nil {
			return c
		}
	}
	return ""
}

// clsactLoop 每 10 秒一轮 clsactTick。
func clsactLoop() {
	c := &clsactSched{}
	tick := time.NewTicker(clsactCheckEvery)
	defer tick.Stop()
	for range tick.C {
		clsactTick(c, nowFn())
	}
}

// clsactTick 一轮: 门控(缓存 60 秒, 换口立即重判)过了才 exec check,
// 不 ok 才 `sh hnc_clsact_watchdog.sh repair <口>`(它自己还会再判一次闸门)。
func clsactTick(c *clsactSched, now time.Time) {
	iface := clsactIfaceFn()
	if c.gateDue(now) || iface != c.gateIface {
		c.gateOK = clsactGateFn(iface)
		c.lastGate, c.gateIface = now, iface
	}
	if !c.gateOK || iface == "" {
		return
	}
	c.checks++
	out := clsactCheckFn(iface)
	if !strings.Contains(out, `"ok":true`) {
		logf("clsact check not ok on %s, repair", iface)
		// 脚本路径与参数分开传(rc1 拼成一个字符串, sh 去找名叫
		// "hnc_clsact_watchdog.sh repair wlan2" 的文件, 修复从没执行过)
		runScriptFn(binDir+"/hnc_clsact_watchdog.sh", "repair", iface)
		c.repairs++
	}
}
