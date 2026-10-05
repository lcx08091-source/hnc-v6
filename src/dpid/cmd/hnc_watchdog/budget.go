// budget.go — v5.28 A1: 看门狗调用预算(热点空转耗电的根治)。
//
// 背景(v5.27 真机): 热点开着但没人用, 1 小时 watchdog 花了约 530 CPU 秒。
// 根因是 Go 版 handleActive 每轮(60 秒)都 fork 一次 capability_probe /
// httpd_drift / tc_uplink_healthy —— v5.27 只在 shell 侧给 capability_probe
// 加了 6 小时节流, Go 侧每轮照样 fork(shell 节流生效时脚本立即退出, 但
// sh 解释 851 行脚本本身就不便宜)。
//
// 本文件:
//   - 把外部调用点(runAction / runV6Sync / runStatsSample / runScript /
//     isDoze / hotspotIdle / activity 快照 / time.Now)收拢为包级变量,
//     budget_test.go 用假实现计数 + 假时钟驱动, 断言每小时调用上限。
//     生产行为不变(默认值就是原函数)。
//   - capProbeGate: capability_probe 的 Go 侧节流(启动首轮 / 网卡变化 /
//     ≥6h 一次)。shell 侧 capability_probe.sh 的节流保留作双保险。
//   - activeAux / loopState: handleActive / mainLoop 的每轮可变状态,
//     让 budget_test 能不开真循环直接驱动 tick。
//
// 节拍变化(其余不变):
//   - httpd_drift:   健康且不在恢复期 → 5 分钟一次(原每轮 60 秒)。
//   - tc_uplink_healthy: 健康且不在恢复期 → 3 分钟一次(原每轮 60 秒)。
//     最坏影响: 上行 ingress 重定向丢失, 最长约 3 分钟被 check_health
//     撞见(tc_uplink_healthy 是专项复核, check_health 每轮仍在跑),
//     原 1 分钟。
//   - 规则不健康 / 刚恢复(recoveryRounds > 0)时两者照旧每轮执行。
package main

import "time"

// ── 可替换的外部调用点(测试用, 默认 = 生产行为) ──────────────────────────
var (
        // runActionFn 执行 watchdog.sh action <name>。
        runActionFn = runAction
        // runV6SyncFn fork bin/v6_sync.sh。
        runV6SyncFn = runV6Sync
        // runStatsSampleFn fork bin/stats_sample.sh。
        runStatsSampleFn = runStatsSample
        // runScriptFn 执行其它脚本(hotspot_schedule.sh 等)。
        runScriptFn = runScript
        // writeStateFn 把状态机状态落到 run/hnc_state(状态迁移用)。
        writeStateFn = writeState
        // isDozeFn 判断系统是否 Doze(真实现可能 fork watchdog.sh)。
        isDozeFn = isDoze
        // hotspotIdleFn activity 明确说「热点未开」。
        hotspotIdleFn = hotspotIdle
        // actSnapshotFn 读一次 activity.json 快照(带缓存)。
        actSnapshotFn = actReader.Get
        // nowFn 当前时间(budget_test 用假时钟推进; restoreThrottle 窗口滚动也用它)。
        nowFn = time.Now
        // runStatsFn runAction 的记账回调(默认写 wdActions, 测试可替换)。
        runStatsFn = wdActions.record
        // wdActionsFlushFn 动作记账落盘(默认写 run/watchdog_actions.json, 测试可替换)。
        wdActionsFlushFn = wdActions.flush
)

// ── capability_probe 节流 ────────────────────────────────────────────────

// capProbeEvery 与 bin/capability_probe.sh 的 6 小时窗口同口径。
const capProbeEvery = 6 * time.Hour

// capProbeGate capability_probe 的放行闸门: 本进程启动后还没探测过、
// 热点网卡变了、或距上次探测 ≥ capProbeEvery。非并发安全 —— 只在主循环
// 串行使用(budget_test 同样串行驱动)。
type capProbeGate struct {
        done   bool
        iface  string
        lastAt time.Time
}

func (g *capProbeGate) due(iface string, now time.Time) bool {
        if !g.done || g.iface != iface {
                return true
        }
        return now.Sub(g.lastAt) >= capProbeEvery
}

func (g *capProbeGate) mark(iface string, now time.Time) {
        g.done = true
        g.iface = iface
        g.lastAt = now
}

// ── 健康时的附带检查节拍(A1) ─────────────────────────────────────────────

const (
        // httpdDriftEvery 健康时 httpd pidfile 漂移检查的间隔(原每轮 60 秒)。
        httpdDriftEvery = 5 * time.Minute
        // tcUplinkEvery 健康时上行限速专项复核的间隔(原每轮 60 秒)。
        // check_health 每轮仍在跑, 这里只是把「上行为 0 → tc_uplink_healthy
        // 复核」的专项检查放宽到 3 分钟: 上行重定向丢失最长约 3 分钟被发现(原 1 分钟)。
        tcUplinkEvery = 3 * time.Minute
)

// ── 每轮可变状态(抽出 mainLoop / handleActive 局部变量) ─────────────────

// activeAux handleActive 的辅助状态。抽出来是因为 budget_test 要用假
// 时钟反复驱动 handleActive, 不能依赖闭包里的局部变量。
type activeAux struct {
        recoveryRounds  int
        lastV6Sync      time.Time
        lastStatsSample time.Time
        lastDrift       time.Time
        lastUplink      time.Time
        cap             capProbeGate
}

// loopState 主循环每轮的可变状态。tick() 是「一轮该干的事」的纯驱动入口
// (不含睡眠与 daemon 保活 —— 那两块由 mainLoop 自己管), budget_test 直接
// 调 tick 用假时钟跑 60 分钟。
type loopState struct {
        throttle        *restoreThrottle
        currentInterval time.Duration
        firstRound      bool
        aux             activeAux
        lastLogRotate   time.Time
        lastPrune       time.Time
        lastActFlush    time.Time
}

func newLoopState() *loopState {
        return &loopState{
                throttle:        &restoreThrottle{},
                currentInterval: intervalNormal,
                firstRound:      true,
        }
}

// tick 跑一轮(定时任务 + 状态机 + 去重), 返回本轮建议的睡眠间隔。
// 热点未开的 120 秒兜底探测也在这里, 与 mainLoop 原逻辑一致。
func (ls *loopState) tick(state wdState) time.Duration {
        now := nowFn()

        // v5.25: 定时开关热点 / 只在充电时开热点(旧 Go 版从未调用, 该功能在 Go 版下不生效)
        hsSched.runIfDue(now)

        // Log rotation, cheap so always run.
        if now.Sub(ls.lastLogRotate) > logRotateInterval {
                rotateLogIfBig()
                _ = runActionFn("cleanup_stale_rules")
                _ = runActionFn("rotate_logs")
                ls.lastLogRotate = now
        }

        // State machine.
        switch state.kind {
        case statePending:
                ls.currentInterval = handlePending(ls.throttle)

        case stateActive:
                ls.currentInterval = handleActive(state.iface, ls.throttle, &ls.aux)
        }

        // rc17 hotspotd dedupe —— v5.25: 纯防御性清理, 每 10 分钟一次即可(原来每轮 fork 一次 watchdog.sh)
        if now.Sub(ls.lastPrune) >= pruneDupEvery {
                _ = runActionFn("prune_dup_hotspotd")
                ls.lastPrune = now
        }

        // v5.28 A2: 每分钟原子写一次动作记账(随现有落盘节奏, 不新开循环)。
        if now.Sub(ls.lastActFlush) >= actionsFlushEvery {
                if err := wdActionsFlushFn(actionsFile, now); err != nil {
                        logf("action stats flush: %v", err)
                }
                ls.lastActFlush = now
        }

        // v5.25: 热点未开(httpd 的 activity 新鲜可信)→ 兜底探测放宽到 120 秒, 开热点靠网卡事件即时唤醒。
        // 规则恢复 / 健康检查节拍(热点开着时)不受影响。
        if ls.currentInterval < intervalIdleProbe && hotspotIdleFn() {
                ls.currentInterval = intervalIdleProbe
        }
        return ls.currentInterval
}
