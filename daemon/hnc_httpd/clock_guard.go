// clock_guard.go — v5.20 时钟健壮性(按天落盘的写入器共用)
//
// 为什么: Android 可能在 NTP 同步前就把服务拉起(时钟停在 1970 / 2000, 或 RTC
// 过期停在几天前), 运行中 NTP/用户改时间也会让墙钟跳变。按天落盘的写入器
// (app_usage / app_time / phone_usage / limit_policy 用量)都用 now.Format 定位
// 「今天」、用两次采样的计数器差分记账, 时钟一错就会:
//   - 写出 app_usage.19700101.json 这类错日文件, 或把字节记到错的天/小时;
//   - limit_policy 的 dayKey/monthKey 变成 1970 → rollover 把当日/当月配额用量清零;
//   - 保留期清理(now − N 天)在时钟跑到未来时把历史全删。
//
// 规则:
//   clockSane(now): 年份 ≥ 2025, 且不早于我们持久化过的最晚时间戳(高水位,
//                   data/clock_hwm, 容忍 10 分钟的小幅回拨)。时钟不可信时写入器
//                   整轮跳过(不写文件、不消费计数器、不做保留期清理)。
//   clockGuard:     每个写入器一个, 比较相邻两次采样的「墙钟间隔」与「单调时钟
//                   间隔」, 差 > 10 分钟即判跳变(前跳/回跳/深睡眠), 写入器此时
//                   重建基线(丢弃这一段差分)而不是把一大坨增量记进一个桶或错的天。
//                   从「不可信」恢复时, 若不可信持续超过 10 分钟同样按跳变处理。
//
// 高水位自愈: 如果高水位本身是错的(曾经时钟跑到未来并被记下), 时钟年份合法但
// 持续落后高水位超过 6 小时(单调时钟计), 视为高水位有误, 以当前时间重置。
//
// 单调时钟: Go 的 monotonic 读数在 Android 上是 CLOCK_MONOTONIC(不含深睡眠)。
// 深睡眠 > 10 分钟也会被判成「跳变」→ 重建基线; 深睡眠期间无转发流量, 损失可忽略。

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	clockMinYear         = 2025
	clockJumpThreshold   = 10 * time.Minute
	clockBackTolerance   = 10 * time.Minute
	clockHWMHealAfter    = 6 * time.Hour
	clockHWMPersistEvery = 5 * time.Minute
	// clockTrustAfterBoot v5.25: 系统开着「自动确定时间」且开机已满这么久(NTP / 运营商时间
	// 早该校准过)时, 落后高水位视为「高水位是错的」, 立即重置, 不再干等 6 小时。
	clockTrustAfterBoot = 10 * time.Minute
	clockAutoTimeTTL    = 10 * time.Minute
)

// clockVerdict 一次采样的时钟判定
type clockVerdict int

const (
	clockOK     clockVerdict = iota // 正常记账
	clockInsane                     // 时钟不可信: 整轮跳过, 不消费计数器
	clockJump                       // 刚发生跳变(或长时间不可信后恢复): 重建基线, 本轮不记账
)

func (v clockVerdict) String() string {
	switch v {
	case clockOK:
		return "ok"
	case clockInsane:
		return "insane"
	case clockJump:
		return "jump"
	}
	return "?"
}

var monoStart = time.Now()

// monoNow 进程内单调时钟(不受墙钟调整影响)
func monoNow() time.Duration { return time.Since(monoStart) }

// bootUptime v5.25: 开机以来的时长(/proc/uptime, CLOCK_BOOTTIME, 含深睡眠, 不受改时间影响)。
// 读不到时退回进程单调时钟。用它做高水位自愈计时, httpd 重启不会让 6 小时重新计。
func bootUptime() time.Duration {
	b, err := os.ReadFile("/proc/uptime")
	if err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil && v > 0 {
				return time.Duration(v * float64(time.Second))
			}
		}
	}
	return monoNow()
}

// ─── 系统「自动确定时间」开关(缓存, 绝不阻塞调用方) ───────────────────────

var clockAutoTimeState struct {
	sync.Mutex
	on, known, running bool
	at                 time.Time
}

// clockAutoTime 返回缓存的 settings global auto_time; 过期时后台刷新, 本次仍返回旧值。
// 测试可替换。
var clockAutoTime = func() (on, known bool) {
	st := &clockAutoTimeState
	st.Lock()
	defer st.Unlock()
	if (st.at.IsZero() || time.Since(st.at) > clockAutoTimeTTL) && !st.running {
		st.running = true
		go func() {
			out, ok := puRunCmd("settings", "get", "global", "auto_time")
			st.Lock()
			st.running, st.at = false, time.Now()
			if ok {
				st.on, st.known = strings.TrimSpace(out) == "1", true
			}
			st.Unlock()
		}()
	}
	return st.on, st.known
}

// clockBootUp 开机时长来源(测试可替换)
var clockBootUp = bootUptime

// clockSaneAt 纯函数: 年份 ≥ 2025 且不早于高水位(hwm, unix 秒; 0 = 无)减容忍值。
func clockSaneAt(now time.Time, hwm int64) bool {
	if now.Year() < clockMinYear {
		return false
	}
	if hwm > 0 && now.Unix() < hwm-int64(clockBackTolerance/time.Second) {
		return false
	}
	return true
}

// 高水位状态(同一 hncDir 下所有写入器共享; 按目录分开只为测试隔离, 生产只有一个)
type clockDirState struct {
	path        string // data/clock_hwm
	statePath   string // run/clock_state.json
	hwm         int64
	savedHWM    int64
	behindSince time.Duration // 年份合法但落后高水位的起点(单调); -1 = 未落后
	lastSane    int           // -1 未知 / 0 不可信 / 1 可信, 仅用于状态变化时写 run/clock_state.json
	jumps       int
	lastJumpAt  int64
	lastJumpDlt int64
	// v5.25: 最近一次高水位重置(给自检显示「为什么恢复了」)
	resetReason string
	resetAt     int64
	resetFrom   int64
}

func (st *clockDirState) noteReset(reason string, now time.Time) {
	st.resetReason, st.resetAt, st.resetFrom = reason, now.Unix(), st.hwm
	st.lastSane = -1 // 强制下一次 publish 写 clock_state.json
}

var clockStates = struct {
	mu   sync.Mutex
	dirs map[string]*clockDirState
}{dirs: map[string]*clockDirState{}}

// clockMono 写入器取单调时钟的入口(测试可替换)
var clockMono = monoNow

// clockDirLocked 取/建某目录的状态; 首次读 data/clock_hwm(单行 unix 秒, 与 shell 侧
// bin/hnc_clock.sh 同格式)。调用方持 clockStates.mu。
func clockDirLocked(hncDir string) *clockDirState {
	if st := clockStates.dirs[hncDir]; st != nil {
		return st
	}
	st := &clockDirState{behindSince: -1, lastSane: -1}
	st.path = filepath.Join(hncDir, "data", "clock_hwm")
	st.statePath = filepath.Join(hncDir, "run", "clock_state.json")
	if b, err := os.ReadFile(st.path); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && v > 0 {
			st.hwm, st.savedHWM = v, v
		}
	}
	clockStates.dirs[hncDir] = st
	return st
}

// clockForget 测试用: 丢弃某目录的内存状态(下次重新读盘)
func clockForget(hncDir string) {
	clockStates.mu.Lock()
	delete(clockStates.dirs, hncDir)
	clockStates.mu.Unlock()
}

// clockSaneMono 全局判定(含高水位自愈); mono 为调用方的单调时钟读数。
func clockSaneMono(hncDir string, now time.Time, mono time.Duration) bool {
	clockStates.mu.Lock()
	defer clockStates.mu.Unlock()
	st := clockDirLocked(hncDir)
	ok := clockSaneAt(now, st.hwm)
	if !ok && now.Year() >= clockMinYear && st.hwm > 0 {
		// v5.25: 系统开着自动时间且开机满 10 分钟 → 当前时间可信, 是高水位错了(曾跑到未来)
		if on, known := clockAutoTime(); on && known && clockBootUp() >= clockTrustAfterBoot {
			log.Printf("clock: now %s behind high-water %s, but system auto-time is on and uptime %s; trusting system time, resetting high-water",
				now.Format(time.RFC3339), time.Unix(st.hwm, 0).Format(time.RFC3339), clockBootUp().Round(time.Second))
			st.noteReset("auto_time", now)
			st.hwm = now.Unix()
			st.persist(true)
			st.behindSince = -1
			st.publish(true, now)
			return true
		}
		// 年份合法但落后高水位: 可能是高水位本身错了(曾跑到未来)。
		// v5.25: 计时用开机时长(clockBootUp), httpd 重启不会让 6 小时重新计。
		boot := clockBootUp()
		if st.behindSince < 0 {
			st.behindSince = boot
		} else if boot-st.behindSince >= clockHWMHealAfter {
			log.Printf("clock: now %s stays behind persisted high-water %s for %s, resetting high-water",
				now.Format(time.RFC3339), time.Unix(st.hwm, 0).Format(time.RFC3339), clockHWMHealAfter)
			st.noteReset("behind_6h", now)
			st.hwm = now.Unix()
			st.persist(true)
			ok = true
		}
	}
	if ok {
		st.behindSince = -1
	}
	st.publish(ok, now)
	return ok
}

// clockSane 生产入口: 用进程单调时钟
func clockSane(hncDir string, now time.Time) bool {
	return clockSaneMono(hncDir, now, clockMono())
}

// clockNote 记录一次可信时间(推进高水位, 至多每 5 分钟落盘一次)
func clockNote(hncDir string, now time.Time) {
	clockStates.mu.Lock()
	defer clockStates.mu.Unlock()
	st := clockDirLocked(hncDir)
	if u := now.Unix(); u > st.hwm {
		st.hwm = u
	}
	st.persist(false)
}

// clockHighWater 当前高水位(unix 秒, 0 = 无)
func clockHighWater(hncDir string) int64 {
	clockStates.mu.Lock()
	defer clockStates.mu.Unlock()
	return clockDirLocked(hncDir).hwm
}

func (st *clockDirState) persist(force bool) {
	if st.hwm <= 0 {
		return
	}
	if !force && st.savedHWM > 0 && st.hwm-st.savedHWM < int64(clockHWMPersistEvery/time.Second) {
		return
	}
	if err := discoverWriteAtomic(st.path, []byte(strconv.FormatInt(st.hwm, 10)+"\n")); err == nil {
		st.savedHWM = st.hwm
	}
}

// publish 可信性变化时写 run/clock_state.json(给自检/界面), 平时不写
func (st *clockDirState) publish(sane bool, now time.Time) {
	v := 0
	if sane {
		v = 1
	}
	if v == st.lastSane {
		return
	}
	prev := st.lastSane
	st.lastSane = v
	if !sane {
		log.Printf("clock: wall clock %s is not trustworthy (min year %d, high-water %d); day-file writers paused",
			now.Format(time.RFC3339), clockMinYear, st.hwm)
	} else if prev == 0 {
		log.Printf("clock: wall clock trusted again (%s)", now.Format(time.RFC3339))
	}
	st.writeState(sane, now)
}

func (st *clockDirState) writeState(sane bool, now time.Time) {
	b, _ := json.Marshal(map[string]interface{}{
		"sane":           sane,
		"now":            now.Unix(),
		"high_water":     st.hwm,
		"min_year":       clockMinYear,
		"jumps":          st.jumps,
		"last_jump_at":   st.lastJumpAt,
		"last_jump_secs": st.lastJumpDlt,
		"hwm_reset":      st.resetReason,
		"hwm_reset_at":   st.resetAt,
		"hwm_reset_from": st.resetFrom,
	})
	_ = discoverWriteAtomic(st.statePath, b)
}

func clockRecordJump(hncDir string, now time.Time, delta time.Duration, who string) {
	clockStates.mu.Lock()
	defer clockStates.mu.Unlock()
	st := clockDirLocked(hncDir)
	st.jumps++
	st.lastJumpAt = now.Unix()
	st.lastJumpDlt = int64(delta / time.Second)
	log.Printf("clock: %s: wall clock jumped %s relative to monotonic, re-baselining counters", who, delta.Round(time.Second))
	st.writeState(st.lastSane != 0, now)
}

// clockGuard 单个写入器的跳变检测器(调用方自行加锁)
type clockGuard struct {
	name        string
	have        bool
	lastWall    time.Time
	lastMono    time.Duration
	insane      bool
	insaneSince time.Duration
}

// check 判定本次采样。now = 墙钟, mono = 单调时钟读数。
//   - 时钟不可信 → clockInsane(不更新基准; 记录不可信起点)
//   - 与上次可信采样相比 墙钟间隔 − 单调间隔 超过阈值 → clockJump
//   - 不可信持续超过阈值后恢复 → clockJump(积压的差分跨度太长, 不能记进一个桶)
//   - 否则 clockOK, 并推进全局高水位
func (g *clockGuard) check(hncDir string, now time.Time, mono time.Duration) clockVerdict {
	if !clockSaneMono(hncDir, now, mono) {
		if !g.insane {
			g.insane, g.insaneSince = true, mono
		}
		return clockInsane
	}
	v := clockOK
	var delta time.Duration
	if g.insane {
		if mono-g.insaneSince > clockJumpThreshold {
			v, delta = clockJump, mono-g.insaneSince
		}
		g.insane = false
	}
	if v == clockOK && g.have {
		wall := now.Round(0).Sub(g.lastWall)
		mon := mono - g.lastMono
		if d := wall - mon; d > clockJumpThreshold || d < -clockJumpThreshold {
			v, delta = clockJump, d
		}
	}
	g.have, g.lastWall, g.lastMono = true, now.Round(0), mono
	if v == clockJump {
		clockRecordJump(hncDir, now, delta, g.name)
	}
	clockNote(hncDir, now)
	return v
}

// step 生产入口: check + 进程单调时钟(测试可替换 clockMono)
func (g *clockGuard) step(hncDir string, now time.Time) clockVerdict {
	return g.check(hncDir, now, clockMono())
}
