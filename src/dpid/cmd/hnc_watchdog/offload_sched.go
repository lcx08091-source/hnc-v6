// offload_sched.go — offload / clsact 的调度(v5.29 T2 M3 起由 Go 看门狗负责;
// v5.33 起是唯一一份: hnc_offload_guard.sh 的 daemon 循环、hnc_clsact_watchdog.sh、
// 开关 run/wd_m3.disabled 与 run/offload_guard.owner 都删了)。
//
// 只把「谁来按时调用」放在 Go —— 检测 / 兜底 / clsact 闸门全在 hnc_offload_guard.sh:
//   - offload: `sh bin/hnc_offload_guard.sh plan`(30 秒超时, 经动作记账, 动作名
//     offload_guard_plan)跑一轮并拿「下次睡几秒 + 早醒条件」(60 或 300 秒);
//     睡眠期间每 30 秒看一次 activity 快照, 早醒条件满足就提前进入下一轮。
//     解析失败按 60 秒。
//   - v6.0 修复 30 秒死循环 Bug: 记录进入睡眠时的 prevClients, 仅当
//     `prevClients <= 0 && curClients > 0`("从无客户端变为有客户端上线")时才触发
//     clients 早醒, 彻底根治「只要有 1 台设备在线就每 30 秒死循环重跑 sleep 5 巡检」!
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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"hnc.io/dpid/nlroute"
)

const (
	offloadFirstDelay  = 20 * time.Second // 启动后 20 秒第一轮(照抄 shell daemon)
	offloadPlanTimeout = 30 * time.Second
	offloadFallback    = 60 * time.Second // plan 解析失败 / 空输出
	offloadWakeEvery   = 30 * time.Second // 早醒检查周期(照抄 hnc_act_sleep_until 的 IDLE_CHUNK)
	offloadMaxSec      = 900              // 与 shell INTERVAL/IDLE_INTERVAL 的上界一致
	clsactCheckEvery   = 10 * time.Second
	clsactCheckTimeout = 5 * time.Second

	// StateIdle 关热点待机态(对应看门狗 PENDING 态); 待机且无残留待清理项时挂起调度定时器实现零唤醒。
	StateIdle = statePending
)

// ── 可注入外部调用 ──────────────────────────────────────────────────
var (
	// runOffloadPlanFn 跑一轮 plan(默认 runOffloadPlan, 返回末行)。
	runOffloadPlanFn = runOffloadPlan
	// clsactCheckFn 检查 clsact 状态(默认 checkClsact: 纯 Go netlink 优先, 异常才回退子进程)。
	clsactCheckFn = checkClsact
	// nlClsactBPFCheckFn 纯 Go RTM_GETTFILTER + bpffs 探活(默认 nlroute.CheckClsactBPF)。
	nlClsactBPFCheckFn = nlroute.CheckClsactBPF
	// clsactMapPinPath clsact pinned ip_mark_map 路径(测试可重定向)。
	clsactMapPinPath = nlroute.DefaultBPFMapPinPath
	// clsactTargetFn 该盯哪个口(默认 clsactTarget: 读 offload guard 状态; "" = 不盯)。
	clsactTargetFn = clsactTarget
	// offloadGuardStatusPath plan / apply 写的状态文件(测试重定向)。
	offloadGuardStatusPath = runDir + "/offload_guard.json"
	// offloadRunDir 清理标志位所在 run 目录(测试重定向)。
	offloadRunDir = runDir
	// offloadStateFn 读取当前看门狗状态(默认 readState)。
	offloadStateFn = readState
	// offloadFirstDelayDur / clsactEveryDur 循环节拍(单测可调小)。
	offloadFirstDelayDur = offloadFirstDelay
	clsactEveryDur       = clsactCheckEvery
)

var (
	offloadWakeCh = make(chan struct{}, 1)
	clsactWakeCh  = make(chan struct{}, 1)
)

// wakeOffloadSched 热点开启或迁移网卡时即时唤醒待机挂起的 offloadLoop 与 clsactLoop。
func wakeOffloadSched() {
	select {
	case offloadWakeCh <- struct{}{}:
	default:
	}
	select {
	case clsactWakeCh <- struct{}{}:
	default:
	}
}

// offloadNeedsCleanup 判断关热点后是否仍存在待恢复的 offload / clsact / HWNAT 状态。
// 若存在残留标记或 offload_guard.json 尚未归位到 NOHOTSPOT/SKIPPED, 保持调度直到清理完毕。
func offloadNeedsCleanup(runPath string) bool {
	for _, name := range []string{
		"offload_guard.clsact",
		"orig_tether_offload_disabled",
		"mtk_hwnat.state",
	} {
		if _, err := os.Stat(filepath.Join(runPath, name)); err == nil {
			return true
		}
	}
	if b, err := os.ReadFile(filepath.Join(runPath, "offload_guard.state")); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(ln) == "fallback=1" {
				return true
			}
		}
	}
	if b, err := os.ReadFile(offloadGuardStatusPath); err == nil {
		var st struct {
			OffloadState   string `json:"offload_state"`
			FallbackActive bool   `json:"fallback_active"`
			Clsact         string `json:"clsact"`
		}
		if json.Unmarshal(b, &st) == nil {
			if st.FallbackActive || st.Clsact == "installed" {
				return true
			}
			if st.OffloadState != "" && st.OffloadState != "NOHOTSPOT" && st.OffloadState != "SKIPPED" {
				return true
			}
		}
	}
	return false
}

// offloadIdleShouldPause 关热点处于 StateIdle 且无需任何残留清理时返回 true, 暂停定时器实现零唤醒。
func offloadIdleShouldPause() bool {
	return offloadStateFn().kind == StateIdle && !offloadNeedsCleanup(offloadRunDir)
}

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
		if cmd.Process == nil || cmd.Process.Pid <= 0 {
			return nil
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return cmd.Process.Kill()
	}
	cmd.WaitDelay = 2 * time.Second
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

// offloadPlanner offload 调度状态机: 记录上一轮 plan 决定的睡眠计划及睡眠起点的客户端数,
// advance(now) 判断现在是否该跑下一轮(睡满 / 早醒 / 首轮)。
type offloadPlanner struct {
	started     bool
	nextAt      time.Time // 下一轮 plan 时刻(睡满时间)
	wakeMode    string    // hotspot | clients | none
	prevClients int       // 进入本轮睡眠时的客户端数(防已有客户端在线时每 30s 死循环早醒)
	planCalls   int
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

// observe 记录本轮 plan 的结论(默认睡眠起点无在线客户端), 算下一轮时刻。
func (p *offloadPlanner) observe(dur time.Duration, wake string, now time.Time) {
	p.observeWithClients(dur, wake, 0, now)
}

// observeWithClients 记录本轮 plan 的结论及睡眠起点的客户端数。
func (p *offloadPlanner) observeWithClients(dur time.Duration, wake string, clients int, now time.Time) {
	p.planCalls++
	p.nextAt = now.Add(dur)
	p.wakeMode = wake
	p.prevClients = clients
}

// offloadEarlyWake 早醒条件是否满足:
//   - hotspot: 热点从关闭变为开启(level 非空且非 hotspot_off);
//   - clients: 仅当睡眠起点无客户端(prevClients <= 0)且当前出现新客户端上线(curClients > 0)时才提前唤醒!
func offloadEarlyWake(wake, level string, prevClients, curClients int) bool {
	switch wake {
	case "hotspot":
		return level != "" && level != "hotspot_off"
	case "clients":
		return prevClients <= 0 && curClients > 0
	}
	return false
}

// startOffloadSched 常驻 goroutine: 20 秒后第一轮, 之后按 plan 睡; StateIdle 待机零唤醒。
func startOffloadSched() {
	go offloadLoop()
	go clsactLoop()
}

func sleepOffloadFirstDelay(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	tmr := time.NewTimer(d)
	defer tmr.Stop()
	select {
	case <-stopCh:
		return false
	case <-offloadWakeCh:
		return true
	case <-tmr.C:
		return true
	}
}

func offloadLoop() {
	p := &offloadPlanner{}
	if offloadFirstDelayDur > 0 && !sleepOffloadFirstDelay(offloadFirstDelayDur) {
		return
	}
	last := nowFn()
	for {
		if offloadIdleShouldPause() {
			select {
			case <-stopCh:
				return
			case <-offloadWakeCh:
				p.started = false
				last = nowFn()
			}
		} else if d := last.Sub(nowFn()); d > 0 {
			tmr := time.NewTimer(d)
			select {
			case <-stopCh:
				tmr.Stop()
				return
			case <-offloadWakeCh:
				tmr.Stop()
				p.started = false
			case <-tmr.C:
			}
		}
		last = nowFn().Add(offloadWakeEvery)
		if offloadIdleShouldPause() {
			continue
		}
		now := nowFn()
		s := actSnapshotFn()
		early := s.OK && offloadEarlyWake(p.wakeMode, s.Level, p.prevClients, s.Clients)
		if p.advance(now, early) {
			dur, wake := parseOffloadPlan(runOffloadPlanFn())
			curClients := 0
			if sAfter := actSnapshotFn(); sAfter.OK {
				curClients = sAfter.Clients
			} else if s.OK {
				curClients = s.Clients
			}
			p.observeWithClients(dur, wake, curClients, now)
			last = nowFn().Add(offloadWakeEvery)
		}
	}
}

// ── clsact 调度 ─────────────────────────────────────────────────────

// clsactSched clsact 检查状态机。
type clsactSched struct {
	checks  int
	repairs int // 修复调用次数(测试断言用)
}

// checkClsact 优先使用纯 Go netlink RTM_GETTFILTER + bpffs stat 检查 clsact 状态
// (省去每 10s 一次的 hnc_clsact_ctl check 子进程, 少 360 次/小时 fork);
// 仅在网卡查询或 netlink 权限不可用时回退 execClsactCheck。
func checkClsact(iface string) string {
	if iface == "" {
		return ""
	}
	if ni, err := netInterfaceByNameFn(iface); err == nil && ni != nil && ni.Index > 0 && nlClsactBPFCheckFn != nil {
		if st, nlErr := nlClsactBPFCheckFn(ni.Index, clsactMapPinPath); nlErr == nil {
			if st.OK() {
				return `{"ok":true,"qdisc":true,"bpf_filter":true,"map":true}`
			}
			return `{"ok":false}`
		}
	}
	return execClsactCheck(iface)
}

// execClsactCheck 直接 exec hnc_clsact_ctl check <口>(不经 sh, 带 5s 硬超时防挂死)。
// 返回输出(空 = 失败)。
func execClsactCheck(iface string) string {
	ctx, cancel := context.WithTimeout(context.Background(), clsactCheckTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binDir+"/hnc_clsact_ctl", "check", iface)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = time.Second
	b, err := cmd.CombinedOutput()
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

// clsactLoop 活跃期每 10 秒一轮 clsactTick; 关热点 StateIdle 且无需清理时暂停定时器实现待机零唤醒。
func clsactLoop() {
	c := &clsactSched{}
	for {
		if clsactTargetFn() == "" && offloadIdleShouldPause() {
			select {
			case <-stopCh:
				return
			case <-clsactWakeCh:
			}
			clsactTick(c, nowFn())
			continue
		}
		tmr := time.NewTimer(clsactEveryDur)
		select {
		case <-stopCh:
			tmr.Stop()
			return
		case <-clsactWakeCh:
			tmr.Stop()
		case <-tmr.C:
		}
		clsactTick(c, nowFn())
	}
}

// clsactTick 一轮: offload guard 说 on 模式装着 clsact 才检查, 不 ok 才
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
		runScriptFn(binDir+"/hnc_offload_guard.sh", "clsact_repair", iface)
		c.repairs++
	}
}
