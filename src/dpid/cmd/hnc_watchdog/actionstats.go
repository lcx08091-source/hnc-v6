// actionstats.go — v5.28 A2: watchdog 动作记账(失败不再被吞掉)。
//
// 背景: v5.26 真机上 `action tc_uplink_healthy` 一直 exit 127(脚本里调
// 的命令不存在), Go 侧 `_ = runAction(...)` 丢掉返回码, 几个版本没人发现。
//
// 做法: runAction(= runActionFn 的默认实现)里对每次调用记账 —— 动作名 →
// 累计 calls / fails / last_rc / last_fail_at / total_ms / max_ms, 按小时
// 桶(键 = 该小时起点)保留 24 小时; 主循环 tick 每分钟原子写一次
// run/watchdog_actions.json, httpd 的 /api/power 与自检转出(见 A2 其余部分)。
//
// 「失败」分类(actionFailed, 单独测试):
//   - 任何动作: 126 / 127(找不到命令 / 函数)、-1(超时)、64(未知动作)→ 失败;
//   - 0 → 成功;
//   - 其余非零码按动作的「正常码表」(actionNormalRC)判断 —— 这些码是
//     业务上的正常结果, 不算失败:
//     probe_hotspot  1        热点没开(PENDING 每轮探测的正常结果)
//     check_health   1 / 2    1=规则丢失(触发 full_restore 的正常信号)、2=xtables 锁忙
//     is_doze        1        不在 Doze
//     其余动作(full_restore / full_init / migrate / cleanup_stale_rules /
//     rotate_logs / capability_probe / tc_uplink_healthy / httpd_drift /
//     get_iface / prune_dup_hotspotd)非零即失败。
//
// 并发: runAction 只在主循环串行调用; 记账结构仍带锁(flush 可被测试并发读)。
package main

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"
)

// actionNormalRC 每个动作「正常非零返回码」表(其余非零码都算失败)。
var actionNormalRC = map[string]map[int]bool{
	"probe_hotspot": {1: true},
	"check_health":  {1: true, 2: true},
	"is_doze":       {1: true},
}

const (
	// actionsFile 记账落盘路径(httpd /api/power 与自检读它)。
	actionsFile = runDir + "/watchdog_actions.json"
	// actionsFlushEvery 落盘节奏(随主循环 tick, 不新开循环)。
	actionsFlushEvery = 60 * time.Second
)

// actionFailed 单次调用结果是否算失败(分类规则见文件头)。
func actionFailed(name string, rc int, err error) bool {
	if err != nil {
		return true // 起进程失败 / 超时(runAction 已把超时写成 rc=-1 + err)
	}
	switch rc {
	case 126, 127, 64, -1:
		return true
	}
	if rc == 0 {
		return false
	}
	return !actionNormalRC[name][rc]
}

// actionBucketSec 记账桶宽。v5.28 审查: 原为整点小时桶, 而「最近 1 小时」只收起点在
// 窗口内的桶 —— 11:05 时 10:00 桶整个被丢, calls_1h 只剩 5 分钟的数据(自检
// 「调用偏多」「1 小时内出现 127」都会严重少算)。改为 10 分钟桶, 与窗口有重叠
// 就计入: 统计窗口为 60~70 分钟, 误差 ≤ 1/6。
const actionBucketSec = 600

// hourKey at 所属记账桶的起点(Unix 秒, 10 分钟对齐; 名字沿用)。
func hourKey(at time.Time) int64 { return at.Unix() / actionBucketSec * actionBucketSec }

type actionHour struct {
	calls   uint64
	fails   uint64
	totalMS float64
	maxMS   float64
}

type actionCounter struct {
	buckets   map[int64]*actionHour // 小时起点 → 桶
	lastRC    int
	lastFail  time.Time
	hasFail   bool
	lifeCalls uint64
	lifeFails uint64
}

type actionStats struct {
	mu sync.Mutex
	m  map[string]*actionCounter
}

var wdActions = &actionStats{m: make(map[string]*actionCounter)}

// bucket 返回(必要时创建)动作 name 在 at 所属小时的桶。
func (s *actionStats) bucket(name string, at time.Time) *actionHour {
	c := s.m[name]
	if c == nil {
		c = &actionCounter{buckets: make(map[int64]*actionHour)}
		s.m[name] = c
	}
	k := hourKey(at)
	h := c.buckets[k]
	if h == nil {
		// 顺带淘汰 24 小时以前的桶(懒清理, flush 也做一遍)。
		cutoff := at.Add(-24 * time.Hour).Unix()
		for kk := range c.buckets {
			if kk < cutoff {
				delete(c.buckets, kk)
			}
		}
		h = &actionHour{}
		c.buckets[k] = h
	}
	return h
}

// record 记一次动作调用。at 用 nowFn()(测试可拨)。
func (s *actionStats) record(name string, rc int, err error, ms float64, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.bucket(name, at)
	c := s.m[name]
	h.calls++
	h.totalMS += ms
	if ms > h.maxMS {
		h.maxMS = ms
	}
	c.lastRC = rc
	c.lifeCalls++
	if actionFailed(name, rc, err) {
		h.fails++
		c.lifeFails++
		c.lastFail = at
		c.hasFail = true
	}
}

// wdActionOutItem run/watchdog_actions.json 里每个动作的条目。
type wdActionOutItem struct {
	Calls1H    uint64  `json:"calls_1h"`
	Fails1H    uint64  `json:"fails_1h"`
	LastRC     int     `json:"last_rc"`
	LastFailAt int64   `json:"last_fail_at"` // Unix 秒, 0=从未失败
	AvgMS      float64 `json:"avg_ms"`       // 1h 窗口内
	MaxMS      float64 `json:"max_ms"`       // 1h 窗口内
}

type wdActionOut struct {
	Schema      int                        `json:"schema"`
	GeneratedAt int64                      `json:"generated_at"`
	Actions     map[string]wdActionOutItem `json:"actions"`
	Order       []string                   `json:"order"` // 按 calls_1h 降序(前端小表用)
	// v5.29 T1: 原生检查与 shell 对照的累计不一致次数(0 = 完全一致;
	// 自检「看门狗动作」行显示)。只读快照, 不参与 actions 合计。
	NativeMismatch int `json:"native_mismatch,omitempty"`
	// v5.30 T3: M4 设备发现影子 —— 比对轮数 / 不一致轮数(连续 2 轮的差异才计)。
	// 明细(含 MAC)在 run/m4_shadow.json, 不放这里(兼容性报告会读本文件)。
	M4Checks   int `json:"m4_checks,omitempty"`
	M4Mismatch int `json:"m4_mismatch,omitempty"`
}

// snapshot 生成输出结构(1h = 最近 60 分钟, 覆盖可能跨两个整点桶)。
func (s *actionStats) snapshot(now time.Time) wdActionOut {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := wdActionOut{Schema: 1, GeneratedAt: now.Unix(), Actions: make(map[string]wdActionOutItem, len(s.m))}
	if wdActionsSnapshotExtra != nil {
		out.NativeMismatch = wdActionsSnapshotExtra()
	}
	if wdActionsM4Extra != nil {
		out.M4Checks, out.M4Mismatch = wdActionsM4Extra()
	}
	for name, c := range s.m {
		var it wdActionOutItem
		var total float64
		it.LastRC = c.lastRC
		if c.hasFail {
			it.LastFailAt = c.lastFail.Unix()
		}
		cutoff := now.Add(-time.Hour).Unix()
		for k, h := range c.buckets {
			if k+actionBucketSec <= cutoff { // 桶整个在窗口之前
				continue
			}
			it.Calls1H += h.calls
			it.Fails1H += h.fails
			total += h.totalMS
			if h.maxMS > it.MaxMS {
				it.MaxMS = h.maxMS
			}
		}
		if it.Calls1H > 0 {
			it.AvgMS = total / float64(it.Calls1H)
		}
		out.Actions[name] = it
	}
	// order: calls_1h 降序, 同数按名字稳定
	for name := range out.Actions {
		out.Order = append(out.Order, name)
	}
	sort.Slice(out.Order, func(i, j int) bool {
		a, b := out.Actions[out.Order[i]], out.Actions[out.Order[j]]
		if a.Calls1H != b.Calls1H {
			return a.Calls1H > b.Calls1H
		}
		return out.Order[i] < out.Order[j]
	})
	return out
}

// flush 原子写 run/watchdog_actions.json(tmp + rename)。
func (s *actionStats) flush(path string, now time.Time) error {
	out := s.snapshot(now)
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// actionsTotal1H 所有动作 calls_1h 之和(自检「外部进程合计」口径)。
func (o wdActionOut) actionsTotal1H() uint64 {
	var n uint64
	for _, it := range o.Actions {
		n += it.Calls1H
	}
	return n
}
