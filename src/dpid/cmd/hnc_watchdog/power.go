// power.go — v5.25 省电: 热点关着时让主循环休眠, 由内核事件唤醒。
//
// 背景(v5.24 真机自检): 热点未开时 watchdog 约 232 CPU 秒/小时。原因是主循环每 10 秒
// 都 fork 两次完整的 watchdog.sh(probe_hotspot + prune_dup_hotspotd, 每次解释 1400 行),
// 另有 is_doze 每 30 秒一次。v5.22 的「热点未开放慢」只写在 shell 版 watchdog.sh 里,
// 而真机跑的是这个 Go 版, 从没生效过。
//
// 做法:
//   - 订阅 NETLINK_ROUTE 的网卡 / IPv4 地址变化(RTMGRP_LINK | RTMGRP_IPV4_IFADDR)。
//     开热点必然伴随热点口 up + 分到私网地址, 内核会主动通知 → 立刻探测, 不用轮询。
//   - httpd 的 run/activity.json 说「热点未开」时, 探测兜底间隔从 10 秒放宽到 120 秒;
//     activity 不新鲜(httpd 挂了)时一律按旧间隔, 行为不变。
//   - 定时开关热点 / 只在充电时开热点(bin/hotspot_schedule.sh): 旧 Go 版从没调用过它,
//     这里补上 —— 时段开关在边界时刻精确唤醒执行, 充电模式每 60 秒查一次, 都没开则不跑。
//
// 不受影响: 热点开着时的健康检查 / 规则恢复 / v6 同步 / 统计采样节拍不变; 子进程保活
// 每轮照做; 告警扫描、按应用限速循环独立运行(后者热点未开时暂停, 开热点后 30 秒内恢复)。
package main

import (
        "encoding/json"
        "os"
        "strconv"
        "strings"
        "sync"
        "syscall"
        "time"

        "hnc.io/dpid/activity"
)

const (
        // intervalIdleProbe 热点未开(activity 新鲜可信)时的探测兜底间隔。
        // 真正的「热点开了」靠网卡事件即时唤醒, 这里只防事件丢失。
        intervalIdleProbe = 120 * time.Second
        // eventSettle 网卡事件到达后稍等再探测: 热点口先 up、几百毫秒后才分到地址。
        eventSettle = 1500 * time.Millisecond
        // eventMinGap 两次事件触发的探测至少间隔(移动数据口频繁变化时防抖)。
        eventMinGap = 5 * time.Second
        // pruneDupEvery hotspotd 重复进程清理(纯防御)的间隔, 原来每轮都跑。
        pruneDupEvery = 10 * time.Minute
        // scheduleChargeEvery 「只在充电时开热点」开启时的检查间隔。
        scheduleChargeEvery = 60 * time.Second
        // scheduleFallback 时段开关的兜底执行间隔(边界唤醒之外)。
        scheduleFallback = 10 * time.Minute
)

// RTMGRP_* 组掩码(linux/rtnetlink.h); syscall 包没有导出。
const (
        rtmgrpLink       = 0x1
        rtmgrpIPv4Ifaddr = 0x10
)

var actReader = activity.NewReader(runDir)

// hotspotIdle activity 新鲜且明确是「热点未开」。不新鲜 / 未知 → false(按旧行为)。
func hotspotIdle() bool {
        s := actReader.Get()
        return s.OK && s.Level == activity.LevelHotspotOff
}

// screenAwake activity 新鲜且亮屏或有界面在看 —— 此时不可能处于 Doze, 不必问系统。
func screenAwake() bool {
        s := actReader.Get()
        return s.OK && !s.Quiet
}

// ─── 网卡事件 ──────────────────────────────────────────────────────────

// linkWake 有网卡 / 地址变化时收到一个信号(容量 1, 合并突发)。
var linkWake = make(chan struct{}, 1)

// startLinkWatch 后台订阅网卡事件; 失败只记日志, 主循环照旧按间隔轮询。
func startLinkWatch() {
        fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
        if err != nil {
                logf("link watch: socket: %v (fall back to polling)", err)
                return
        }
        sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: rtmgrpLink | rtmgrpIPv4Ifaddr}
        if err := syscall.Bind(fd, sa); err != nil {
                logf("link watch: bind: %v (fall back to polling)", err)
                syscall.Close(fd)
                return
        }
        logf("link watch: subscribed to link/addr events")
        go func() {
                <-stopCh
                syscall.Close(fd)
        }()
        go func() {
                buf := make([]byte, 32<<10)
                for {
                        n, _, err := syscall.Recvfrom(fd, buf, 0)
                        if err != nil {
                                select {
                                case <-stopCh:
                                        return
                                default:
                                }
                                if err == syscall.EINTR || err == syscall.ENOBUFS {
                                        // ENOBUFS: 事件积压溢出 —— 有变化但丢了细节, 照样唤醒一次。
                                        wakeMain()
                                        continue
                                }
                                logf("link watch: recv: %v (stopped, fall back to polling)", err)
                                return
                        }
                        if n > 0 && netlinkHasLinkOrAddr(buf[:n]) {
                                wakeMain()
                        }
                }
        }()
}

func wakeMain() {
        select {
        case linkWake <- struct{}{}:
        default:
        }
}

// netlinkHasLinkOrAddr 消息里是否有网卡 / 地址的新增或删除(其余类型忽略)。
func netlinkHasLinkOrAddr(b []byte) bool {
        msgs, err := syscall.ParseNetlinkMessage(b)
        if err != nil {
                return true // 解析不了就保守地当作有变化
        }
        for _, m := range msgs {
                switch m.Header.Type {
                case syscall.RTM_NEWLINK, syscall.RTM_DELLINK, syscall.RTM_NEWADDR, syscall.RTM_DELADDR:
                        return true
                }
        }
        return false
}

// sleepOrWake 睡 d, 或被网卡事件提前叫醒。返回 (继续运行, 是否被事件叫醒)。
// 事件叫醒时先等 eventSettle(热点口拿到地址), 且距上次事件触发至少 eventMinGap。
var lastEventRound time.Time

func sleepOrWake(d time.Duration) (bool, bool) {
        t := time.NewTimer(d)
        defer t.Stop()
        for {
                select {
                case <-stopCh:
                        return false, false
                case <-t.C:
                        return true, false
                case <-linkWake:
                        if time.Since(lastEventRound) < eventMinGap {
                                continue // 抖动: 继续等(仍受原定时器约束)
                        }
                        if !sleepUntil(eventSettle) {
                                return false, false
                        }
                        // 合并 settle 期间又到的事件
                        select {
                        case <-linkWake:
                        default:
                        }
                        lastEventRound = time.Now()
                        return true, true
                }
        }
}

// ─── 定时开关热点 ─────────────────────────────────────────────────────

// scheduleCfg data/rules.json 里的四个字段(与 bin/hotspot_schedule.sh 读取的相同)。
type scheduleCfg struct {
        TimeOn   bool
        Start    int // 当天分钟数, -1 = 非法
        End      int
        ChargeOn bool
}

func parseHHMM(s string) int {
        h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
        if !ok {
                return -1
        }
        hh, e1 := strconv.Atoi(h)
        mm, e2 := strconv.Atoi(m)
        if e1 != nil || e2 != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
                return -1
        }
        return hh*60 + mm
}

func parseScheduleCfg(b []byte) scheduleCfg {
        var f struct {
                TimeOn   bool   `json:"hotspot_time_enable"`
                Start    string `json:"hotspot_time_start"`
                End      string `json:"hotspot_time_end"`
                ChargeOn bool   `json:"hotspot_charging_only"`
        }
        c := scheduleCfg{Start: -1, End: -1}
        if json.Unmarshal(b, &f) != nil {
                return c
        }
        c.TimeOn, c.ChargeOn = f.TimeOn, f.ChargeOn
        c.Start, c.End = parseHHMM(f.Start), parseHHMM(f.End)
        return c
}

// nextBoundary 距下一个时段边界(开始或结束)的时长; 边界后多等 2 秒, 保证脚本判定已跨过。
// 无合法边界返回 -1。
func (c scheduleCfg) nextBoundary(now time.Time) time.Duration {
        if !c.TimeOn || c.Start < 0 || c.End < 0 {
                return -1
        }
        best := time.Duration(-1)
        day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
        for _, m := range []int{c.Start, c.End} {
                at := day.Add(time.Duration(m)*time.Minute + 2*time.Second)
                if !at.After(now) {
                        at = at.AddDate(0, 0, 1)
                }
                if d := at.Sub(now); best < 0 || d < best {
                        best = d
                }
        }
        return best
}

type hotspotScheduler struct {
        mu      sync.Mutex
        lastRun time.Time
        cfg     scheduleCfg
        cfgAt   time.Time
        cfgMod  time.Time
}

var hsSched = &hotspotScheduler{}

func (h *hotspotScheduler) config(now time.Time) scheduleCfg {
        path := dataDir + "/rules.json"
        st, err := os.Stat(path)
        if err != nil {
                h.cfg = scheduleCfg{Start: -1, End: -1}
                return h.cfg
        }
        if !st.ModTime().Equal(h.cfgMod) || now.Sub(h.cfgAt) > 10*time.Minute {
                if b, err := os.ReadFile(path); err == nil && len(b) < 8<<20 {
                        h.cfg = parseScheduleCfg(b)
                }
                h.cfgMod, h.cfgAt = st.ModTime(), now
        }
        return h.cfg
}

// maxSleep 主循环最多睡多久才能赶上下一个需要执行的时刻; -1 = 不约束。
func (h *hotspotScheduler) maxSleep(now time.Time) time.Duration {
        h.mu.Lock()
        defer h.mu.Unlock()
        c := h.config(now)
        best := c.nextBoundary(now)
        if c.ChargeOn {
                left := scheduleChargeEvery - now.Sub(h.lastRun)
                if left < time.Second {
                        left = time.Second
                }
                if best < 0 || left < best {
                        best = left
                }
        }
        return best
}

// runIfDue 两项都没开 → 不跑(脚本本身也会立刻退出, 但省一次 fork)。
// 时段开关: 跨过边界后、或距上次超过 scheduleFallback 时跑; 充电模式: 每 scheduleChargeEvery 跑。
// 脚本自身是边沿触发(只在状态切换时动作), 多跑一次无副作用。
func (h *hotspotScheduler) runIfDue(now time.Time) {
        h.mu.Lock()
        c := h.config(now)
        due := false
        switch {
        case c.ChargeOn:
                due = now.Sub(h.lastRun) >= scheduleChargeEvery-2*time.Second
        case c.TimeOn:
                due = h.lastRun.IsZero() || now.Sub(h.lastRun) >= scheduleFallback || crossedBoundary(c, h.lastRun, now)
        }
        if due {
                h.lastRun = now
        }
        h.mu.Unlock()
        if !due {
                return
        }
        script := binDir + "/hotspot_schedule.sh"
        if _, err := os.Stat(script); err != nil {
                return
        }
        runScriptFn(script)
}

// crossedBoundary 上次执行到现在之间是否跨过了某个时段边界。
func crossedBoundary(c scheduleCfg, last, now time.Time) bool {
        if last.IsZero() {
                return true
        }
        d := c.nextBoundary(last)
        return d >= 0 && !last.Add(d).After(now)
}
