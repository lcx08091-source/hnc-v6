// power_sched.go — v5.22 功耗: 自适应间隔策略 + 循环等待助手。
//
// 所有后台循环的「下一轮何时跑」都由 powerInterval(loop, activity, flags) 一处决定,
// /api/power 原样列出每个循环的基准间隔、当前间隔与原因。shell(watchdog.sh /
// hnc_offload_guard.sh)与 dpid 读 run/activity.json 按同一张表执行, 这里的「镜像」
// 条目只用于展示与测试(数值必须与 bin/hnc_activity.sh、src/dpid/activity 保持一致)。
//
// ── 策略表(档位见 power_activity.go: unknown 一律按基准) ─────────────────────
//
//	循环              基准   hotspot_off  no_clients  background        active   说明
//	app_usage         10s    300s         60s         30s*              10s      *仅当 ct DESTROY 事件在用且无应用时长上限/域名封锁; 否则 10s
//	mac_merge         30s    600s         180s        90s               30s
//	cert_probe        20s    600s         120s        60s               20s
//	rate(速率)       2s     30s          有界面 2s / 无界面 20s(no_clients 30s)       纯界面
//	offload_status    30s    300s         有界面 30s / 无界面 120s                      纯界面(兜底本身由 guard 执行)
//	sse_poll          1.5s   5s           1.5s        1.5s              1.5s     有 SSE 连接 = 有界面
//	phone_usage       60s    熄屏且无界面 300s, 其余 60s                                本机流量计数器差分, 不丢字节
//	stats_calibration 15m    熄屏且无界面 60m, 其余 15m
//	limit_policy      60s    每分钟对齐, 任何档位不变(配额/分时段限速执法)
//	v6_neigh          事件   事件驱动 + 60s 兜底, 不变(IPv6 规则同步)
//	ct_events         事件   不变
//	─ 镜像(shell / dpid 执行) ─
//	watchdog_pending  10s    熄屏且无界面 30s(每 10s 只做内建命令的早醒检查), 其余 10s
//	watchdog_active   60s    不变(规则健康检查/v6 兜底同步/定时开关热点)
//	offload_guard     60s    热点未开/无客户端且未在兜底: 完整检测 300s(每 60s 早醒检查); 热点+客户端或兜底中: 60s(重申 ≤60s)
//	stats_sample      300s   no_clients 900s, 其余 300s
//	dpid_conntrack    15s    hotspot_off/no_clients 60s, 其余 15s
//	dpid_state_flush  5s     hotspot_off/no_clients 30s, 其余 5s
//	dpid_bytes        5s     自身归因未开启: 不采; 熄屏且无界面 30s
//	dpid_guard_poll   3s     hotspot_off: 熄屏无界面 15s / 否则 6s; no_clients 6s(hnc_dpid_guard.sh 每轮 ~10 次 fork)
//
// 循环用 powerWait 等待: 档位变化(热点开了/来了设备/打开 WebUI)时立即按新间隔重算,
// 已经超过新间隔就马上跑, 所以放慢不会拖慢「状态变活跃」后的第一轮。
package main

import (
	"sort"
	"sync"
	"time"
)

// loopFlags 与具体循环相关的额外输入
type loopFlags struct {
	CtPrecise bool // conntrack DESTROY 事件在用: 短连接字节不靠轮询抓
	Enforcing bool // app_usage: 配了应用时长上限或域名封锁(执法依赖本循环)
}

type powerLoopDef struct {
	Name     string
	Label    string
	Owner    string // httpd | watchdog | offload_guard | dpid
	Base     time.Duration
	Critical bool // 执法相关: 任何档位间隔都不放大
	Mirror   bool // 由 shell/dpid 执行, 这里只展示
}

var powerLoopDefs = []powerLoopDef{
	{"app_usage", "按应用流量采样", "httpd", 10 * time.Second, false, false},
	{"mac_merge", "随机 MAC 合并建议", "httpd", 30 * time.Second, false, false},
	{"cert_probe", "未知应用证书探测", "httpd", 20 * time.Second, false, false},
	{"rate", "实时速率采样", "httpd", 2 * time.Second, false, false},
	{"offload_status", "offload 状态缓存", "httpd", 30 * time.Second, false, false},
	{"sse_poll", "SSE 变化检测", "httpd", 1500 * time.Millisecond, false, false},
	{"phone_usage", "本机/热点月流量", "httpd", 60 * time.Second, false, false},
	{"stats_calibration", "系统流量对账", "httpd", 15 * time.Minute, false, false},
	{"limit_policy", "配额/分时段限速", "httpd", time.Minute, true, false},
	{"v6_neigh", "IPv6 邻居同步(事件+兜底)", "httpd", time.Minute, true, false},
	{"activity", "活动状态探测", "httpd", activityProbeEvery, false, false},
	{"power_sampler", "功耗自测采样", "httpd", powerSampleEvery, false, false},
	{"watchdog_pending", "watchdog 等热点(PENDING)", "watchdog", 10 * time.Second, false, true},
	{"watchdog_active", "watchdog 规则巡检(ACTIVE)", "watchdog", 60 * time.Second, true, true},
	{"offload_guard", "offload 兜底检测/重申", "offload_guard", 60 * time.Second, false, true},
	{"stats_sample", "设备流量采样", "watchdog", 300 * time.Second, false, true},
	{"dpid_conntrack", "dpid 连接表扫描", "dpid", 15 * time.Second, false, true},
	{"dpid_state_flush", "dpid 状态落盘", "dpid", 5 * time.Second, false, true},
	{"dpid_bytes", "dpid 本机按 uid 字节", "dpid", 5 * time.Second, false, true},
	{"dpid_guard_poll", "dpid 守护监视轮询", "dpid_guard", 3 * time.Second, false, true},
}

func powerLoopDef0(name string) (powerLoopDef, bool) {
	for _, d := range powerLoopDefs {
		if d.Name == name {
			return d, true
		}
	}
	return powerLoopDef{}, false
}

// powerInterval 策略本体(纯函数)。未知循环名返回 0。
func powerInterval(name string, a Activity, f loopFlags) (time.Duration, string) {
	def, ok := powerLoopDef0(name)
	if !ok {
		return 0, "unknown loop"
	}
	base := def.Base
	lvl := a.computeLevel()
	quiet := a.screenOff() && !a.WebUIActive // 熄屏且没人看界面
	if lvl == lvlUnknown {
		return base, "状态未知, 按基准"
	}
	switch name {
	case "app_usage":
		switch lvl {
		case lvlHotspotOff:
			return 300 * time.Second, "热点未开: 无客户端流量可记(热点一开立即恢复)"
		case lvlNoClients:
			return 60 * time.Second, "无在线设备: ×6"
		case lvlBackground:
			if f.Enforcing {
				return base, "后台, 但有应用时长上限/域名封锁: 保持 10s 执法精度"
			}
			if !f.CtPrecise {
				return base, "后台, 但 conntrack 事件不可用: 放慢会漏短连接, 保持 10s"
			}
			return 30 * time.Second, "后台(熄屏无界面)且有精确 DESTROY 事件: ×3"
		}
		return base, "活跃"
	case "mac_merge":
		switch lvl {
		case lvlHotspotOff:
			return 600 * time.Second, "热点未开: ×20"
		case lvlNoClients:
			return 180 * time.Second, "无在线设备: ×6"
		case lvlBackground:
			return 90 * time.Second, "后台: ×3"
		}
		return base, "活跃"
	case "cert_probe":
		switch lvl {
		case lvlHotspotOff:
			return 600 * time.Second, "热点未开: ×30"
		case lvlNoClients:
			return 120 * time.Second, "无在线设备: ×6"
		case lvlBackground:
			return 60 * time.Second, "后台: ×3"
		}
		return base, "活跃"
	case "rate":
		if a.WebUIActive {
			return base, "界面在看: 2s"
		}
		switch lvl {
		case lvlHotspotOff, lvlNoClients:
			return 30 * time.Second, "无界面且无在线设备: ×15"
		}
		return 20 * time.Second, "无界面: 速率只给界面看, ×10(打开界面立即恢复 2s)"
	case "offload_status":
		if lvl == lvlHotspotOff {
			return 300 * time.Second, "热点未开: ×10"
		}
		if a.WebUIActive {
			return base, "界面在看"
		}
		return 120 * time.Second, "无界面: 只是横幅缓存, ×4(兜底由 offload guard 执行)"
	case "sse_poll":
		if lvl == lvlHotspotOff {
			return 5 * time.Second, "热点未开: 设备表几乎不变"
		}
		return base, "有 SSE 连接"
	case "phone_usage":
		if lvl == lvlHotspotOff && quiet {
			return 300 * time.Second, "热点未开且熄屏无界面: ×5(计数器差分, 不丢字节)"
		}
		return base, "基准"
	case "stats_calibration":
		if lvl == lvlHotspotOff && quiet {
			return 60 * time.Minute, "热点未开且熄屏无界面: ×4"
		}
		return base, "基准"
	case "limit_policy":
		return base, "执法: 每分钟对齐, 不随状态变化"
	case "v6_neigh":
		return base, "执法: 事件驱动 + 60s 兜底, 不随状态变化"
	case "activity", "power_sampler":
		return base, "固定"
	// ── 镜像 ──
	case "watchdog_pending":
		if lvl == lvlHotspotOff && quiet {
			return 30 * time.Second, "熄屏无界面: ×3(每 10s 早醒检查热点)"
		}
		return base, "基准"
	case "watchdog_active":
		return base, "执法: 规则健康检查/v6 兜底同步, 不变"
	case "offload_guard":
		if lvl == lvlHotspotOff || lvl == lvlNoClients {
			return 300 * time.Second, "热点未开/无设备且未兜底: 完整检测 ×5(每 60s 早醒; 兜底中仍 60s 重申)"
		}
		return base, "热点+设备: 60s 检测/重申"
	case "stats_sample":
		if lvl == lvlNoClients {
			return 900 * time.Second, "无在线设备: ×3"
		}
		return base, "基准"
	case "dpid_conntrack":
		if lvl == lvlHotspotOff || lvl == lvlNoClients {
			return 60 * time.Second, "无在线设备: ×4"
		}
		return base, "基准"
	case "dpid_state_flush":
		if lvl == lvlHotspotOff || lvl == lvlNoClients {
			return 30 * time.Second, "无在线设备: ×6"
		}
		return base, "基准"
	case "dpid_guard_poll":
		if lvl == lvlHotspotOff {
			if quiet {
				return 15 * time.Second, "热点未开(盲态)且熄屏无界面: ×5(netlink 事件文件每轮都看)"
			}
			return 6 * time.Second, "热点未开: ×2"
		}
		if lvl == lvlNoClients {
			return 6 * time.Second, "无在线设备: ×2"
		}
		return base, "基准"
	case "dpid_bytes":
		if quiet {
			return 30 * time.Second, "熄屏无界面: ×6(自身归因未开启时完全不采)"
		}
		return base, "基准(自身归因未开启时不采)"
	}
	return base, "基准"
}

// ─── 运行期记录(给 /api/power) ─────────────────────────────────────

type powerLoopRun struct {
	Cur     time.Duration
	Reason  string
	LastRun time.Time
}

var powerRuns = struct {
	mu sync.Mutex
	m  map[string]powerLoopRun
}{m: map[string]powerLoopRun{}}

func powerRecord(name string, d time.Duration, reason string, ran time.Time) {
	powerRuns.mu.Lock()
	r := powerRuns.m[name]
	r.Cur, r.Reason = d, reason
	if !ran.IsZero() {
		r.LastRun = ran
	}
	powerRuns.m[name] = r
	powerRuns.mu.Unlock()
}

// powerCurrent 某循环最近一次采用的间隔(没记录 → 基准)
func powerCurrent(name string) time.Duration {
	powerRuns.mu.Lock()
	r, ok := powerRuns.m[name]
	powerRuns.mu.Unlock()
	if ok && r.Cur > 0 {
		return r.Cur
	}
	d, _ := powerLoopDef0(name)
	return d.Base
}

// powerWait 阻塞到 last + interval(当前活动状态); 状态变化时重算(新间隔已到期 → 立即返回)。
// stop 关闭返回 false。flags 可为 nil。
func powerWait(stop <-chan struct{}, name string, last time.Time, flags func() loopFlags) bool {
	for {
		ch := activityChanged() // 先取通道再算间隔, 防止中间发生的变化被漏掉
		var f loopFlags
		if flags != nil {
			f = flags()
		}
		d, reason := powerInterval(name, activityNow(), f)
		if d <= 0 {
			d = time.Second
		}
		powerRecord(name, d, reason, last)
		wait := time.Until(last.Add(d))
		if wait <= 0 {
			return true
		}
		t := time.NewTimer(wait)
		select {
		case <-stop:
			t.Stop()
			return false
		case <-t.C:
			return true
		case <-ch:
			t.Stop()
		}
	}
}

type powerLoopView struct {
	Name        string  `json:"name"`
	Label       string  `json:"label"`
	Owner       string  `json:"owner"`
	BaseS       float64 `json:"base_interval_s"`
	CurrentS    float64 `json:"current_interval_s"`
	Reason      string  `json:"reason"`
	Critical    bool    `json:"critical"`
	Mirror      bool    `json:"mirror"`
	LastRunAgoS int64   `json:"last_run_ago_s"` // -1 = 无记录(镜像/未跑过)
	Multiplier  float64 `json:"multiplier"`
}

// powerLoopsView 所有循环的当前间隔(httpd 自己的取运行记录, 镜像按同一策略现算)
func powerLoopsView(a Activity, f loopFlags, now time.Time) []powerLoopView {
	powerRuns.mu.Lock()
	runs := make(map[string]powerLoopRun, len(powerRuns.m))
	for k, v := range powerRuns.m {
		runs[k] = v
	}
	powerRuns.mu.Unlock()
	out := make([]powerLoopView, 0, len(powerLoopDefs))
	for _, d := range powerLoopDefs {
		cur, reason := powerInterval(d.Name, a, f)
		v := powerLoopView{Name: d.Name, Label: d.Label, Owner: d.Owner, BaseS: d.Base.Seconds(),
			CurrentS: cur.Seconds(), Reason: reason, Critical: d.Critical, Mirror: d.Mirror, LastRunAgoS: -1}
		if r, ok := runs[d.Name]; ok && !d.Mirror {
			if r.Cur > 0 { // 循环自己上报的(含只有它知道的 flags, 如 app_usage 的执法状态)
				v.CurrentS, v.Reason = r.Cur.Seconds(), r.Reason
			}
			if !r.LastRun.IsZero() {
				v.LastRunAgoS = int64(now.Sub(r.LastRun) / time.Second)
			}
		}
		if v.BaseS > 0 {
			v.Multiplier = float64(int(v.CurrentS/v.BaseS*10+0.5)) / 10
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return !out[i].Mirror && out[j].Mirror })
	return out
}
