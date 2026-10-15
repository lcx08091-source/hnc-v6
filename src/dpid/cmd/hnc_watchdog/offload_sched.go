// offload_sched.go — offload / clsact 的调度(v5.29 T2 M3 起由 Go 看门狗负责;
// v5.33 起是唯一一份: hnc_offload_guard.sh 的 daemon 循环、hnc_clsact_watchdog.sh、
// 开关 run/wd_m3.disabled 与 run/offload_guard.owner 都删了)。
//
// 只把「谁来按时调用」放在 Go —— 检测 / 兜底 / clsact 闸门全在 hnc_offload_guard.sh:
//   - offload: `sh bin/hnc_offload_guard.sh plan`(30 秒超时, 经动作记账, 动作名
//     offload_guard_plan)跑一轮并拿「下次睡几秒 + 早醒条件」(60 或 300 秒);
//     睡眠期间每 30 秒看一次 activity 快照, 早醒条件满足就提前进入下一轮。
//     解析失败按 60 秒。
//   - clsact: plan / apply 写的状态 run/offload_guard.json 里 mode=on 且
//     clsact=installed(闸门 clsact_wanted 是 shell 那一份, Go 不再照抄一遍)时,
//     每 10 秒 Go 直接 exec `hnc_clsact_ctl check <口>`(不经 sh), 输出不含
//     "ok":true 才调 `sh bin/hnc_offload_guard.sh clsact_repair <口>`。
//     auto 模式由 plan 每轮顺带修复(与 v5.29 起的分工相同)。
//
// 可测性: 循环节拍抽成 offloadPlanner / clsactSched 两个纯状态机, 外部调用
// (plan 执行 / clsact check / 状态文件 / activity / 时钟)全部包级变量注入。
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
)

// ── 可注入外部调用 ──────────────────────────────────────────────────
var (
	// runOffloadPlanFn 跑一轮 plan(默认 runOffloadPlan, 返回末行)。
	runOffloadPlanFn = runOffloadPlan
	// clsactCheckFn 直接 exec hnc_clsact_ctl check(默认 execClsactCheck)。
	clsactCheckFn = execClsactCheck
	// clsactTargetFn 该盯哪个口(默认 clsactTarget: 读 offload guard 状态; "" = 不盯)。
	clsactTargetFn = clsactTarget
	// offloadGuardStatusPath plan / apply 写的状态文件(测试重定向)。
	offloadGuardStatusPath = runDir + "/offload_guard.json"
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
	go offloadLoop()
	go clsactLoop()
}

func offloadLoop() {
	p := &offloadPlanner{}
	// 启动 20 秒后第一轮(让热点 / hotspotd 就绪)
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
	checks  int
	repairs int // 修复调用次数(测试断言用)
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

// clsactTarget 读 run/offload_guard.json: mode=on 且 clsact=installed 时返回热点口,
// 否则 ""(不盯)。clsact 闸门(产物在、模式、pref 1 没被上行 mirred 占用、auto 下
// 兜底状态)只在 shell 的 clsact_wanted 里判一次, 结论体现在这个状态里。
func clsactTarget() string {
	b, err := os.ReadFile(offloadGuardStatusPath)
	if err != nil {
		return ""
	}
	var st struct {
		Mode   string `json:"mode"`
		Clsact string `json:"clsact"`
		Iface  string `json:"iface"`
	}
	if json.Unmarshal(b, &st) != nil {
		return ""
	}
	if st.Mode == "on" && st.Clsact == "installed" {
		return st.Iface
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

// clsactTick 一轮: offload guard 说 on 模式装着 clsact 才 exec check, 不 ok 才
// `sh hnc_offload_guard.sh clsact_repair <口>`(它会再过一遍 shell 的闸门)。
func clsactTick(c *clsactSched, now time.Time) {
	iface := clsactTargetFn()
	if iface == "" {
		return
	}
	c.checks++
	out := clsactCheckFn(iface)
	if !strings.Contains(out, `"ok":true`) {
		logf("clsact check not ok on %s, repair", iface)
		// 脚本路径与参数分开传(v5.29 rc1 拼成一个字符串, sh 去找名叫
		// "… repair wlan2" 的文件, 修复从没执行过)
		runScriptFn(binDir+"/hnc_offload_guard.sh", "clsact_repair", iface)
		c.repairs++
	}
}
