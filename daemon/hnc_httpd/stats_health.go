// stats_health.go — v5.21 GET /api/stats_health: 统计链路健康一览(缓存 30 秒)
//
// 汇总各统计口径是否可信, 便宜(只读 /proc、两次 iptables -L、文件 mtime; 不跑 dumpsys,
// 系统统计相关字段取 stats_calibration.go 后台对账的缓存):
//   precise_mode               conntrack DESTROY 事件在线 且 nf_conntrack_acct=1
//   ct_destroy_events_per_min  最近 ≥1 分钟窗口的事件速率(进程内计数差分)
//   ct_poll_fallback           事件没订阅上/曾溢出丢失 → 按应用统计退回 10 秒轮询口径
//   iptables_stats_ok          mangle FORWARD 挂着 -j HNC_STATS, 且热点有流量时计数在涨
//   last_stats_sample_age      data/stats_raw.jsonl(stats_sample.sh)距今秒数
//   clock_sane                 clock_guard 判定
//   offload_guard_active       run/offload_guard.json fallback_active
//   offload_gap_pct / netstats_available  来自最近一次对账
//   issues[{id, level(info|warn|error), text_cn}]

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	shCacheTTL       = 30 * time.Second
	shStallMinBytes  = 8 << 20 // 热点口涨了 8MB 而 HNC_STATS 一字节不涨 → 判停滞
	shStallMinWindow = 60      // 秒
	shSampleStale    = 20 * 60 // stats_sample.sh 每 5 分钟一次, 20 分钟没更新算停
)

type shIssue struct {
	ID     string `json:"id"`
	Level  string `json:"level"` // info|warn|error
	TextCN string `json:"text_cn"`
}

// shInput 纯函数输入(测试直接构造)
type shInput struct {
	CtActive     bool
	CtAcct       int // -1 未知, 0 关, 1 开
	CtLostRecent bool
	IptChecked   bool // iptables 能跑
	IptJump      bool // FORWARD 里挂着 HNC_STATS
	IptStalled   bool
	HotspotUp    bool
	HsActive     bool  // 最近窗口热点口有流量
	SampleAge    int64 // -1 = 无文件
	ClockSane    bool
	GuardKnown   bool
	GuardActive  bool
	GuardMode    string
	NetstatsMode string
	NetstatsOK   bool
	CalStatus    string
	CalReason    string
	DriftPct     *float64
	OffloadGap   *float64
	OffloadKind  string
}

func shFmt(p float64) string { return strconv.FormatFloat(p, 'f', 0, 64) }

// shIssues 纯函数: 状态 → 问题列表(按严重度: error → warn → info)
func shIssues(in shInput) []shIssue {
	var errs, warns, infos []shIssue
	add := func(level, id, text string) {
		x := shIssue{ID: id, Level: level, TextCN: text}
		switch level {
		case "error":
			errs = append(errs, x)
		case "warn":
			warns = append(warns, x)
		default:
			infos = append(infos, x)
		}
	}
	if !in.ClockSane {
		add("error", "clock_insane", "系统时钟不可信(未同步或刚跳变), 流量统计暂停记账, 等时间同步后自动恢复")
	}
	if in.IptChecked && !in.IptJump {
		add("error", "iptables_chain_missing", "iptables 计数链 HNC_STATS 不存在或没挂到 FORWARD, 设备流量统计不会增长(重启热点或在设置里修复规则)")
	}
	if in.IptStalled {
		add("warn", "iptables_stalled", "热点口有流量但 HNC_STATS 计数不增长: 转发被分流绕过了 iptables, 或计数规则被清空")
	}
	if !in.CtActive {
		add("warn", "ct_events_off", "conntrack 连接销毁事件未订阅(内核不支持或被拒), 按应用流量退回 10 秒轮询, 短连接会少算")
	} else if in.CtLostRecent {
		add("info", "ct_events_lost", "conntrack 事件曾溢出丢失, 最近的按应用流量可能略偏小")
	}
	if in.CtAcct == 0 {
		add("warn", "ct_acct_off", "nf_conntrack_acct 未开启, 连接字节数不可用, 按应用流量统计不准")
	}
	if in.HotspotUp && in.HsActive && in.SampleAge >= 0 && in.SampleAge > shSampleStale {
		add("warn", "stats_sample_stale", "设备流量采样已 "+strconv.FormatInt(in.SampleAge/60, 10)+" 分钟未更新(watchdog / stats_sample.sh 可能没在跑)")
	}
	if in.OffloadGap != nil && *in.OffloadGap >= calGapPct {
		switch in.OffloadKind {
		case "bpf":
			add("warn", "offload_undercount", "软件分流(BPF)绕过 iptables, 设备流量统计漏计 ≈ "+shFmt(*in.OffloadGap)+"%")
		default:
			add("warn", "offload_undercount", "硬件分流导致漏计 ≈ "+shFmt(*in.OffloadGap)+"%")
		}
		if in.GuardKnown && !in.GuardActive && in.GuardMode != "off" {
			add("info", "offload_guard_inactive", "分流兜底未生效: 可在设置里把「分流兜底」设为开启, 让热点流量走慢路径以便统计与限速")
		}
	}
	if in.NetstatsMode != "off" {
		switch {
		case in.CalStatus == "drift" && in.DriftPct != nil:
			add("warn", "netstats_drift", "本机蜂窝流量与系统统计相差 "+calFmtPct(*in.DriftPct)+", 需要与系统设置一致可把对账模式设为 prefer")
		case !in.NetstatsOK && in.CalReason != "pending" && in.CalReason != "":
			add("info", "netstats_unavailable", "读不到系统流量统计(dumpsys netstats), 无法与系统设置对账")
		}
	}
	out := append(append(errs, warns...), infos...)
	if out == nil {
		out = []shIssue{}
	}
	return out
}

// ─── 采集 ─────────────────────────────────────────────────────────

type shSample struct {
	T       int64
	CtRecv  uint64
	CtLost  uint64
	Ipt     uint64
	IptOK   bool
	HsIface string
	HsBytes uint64
	HsOK    bool
}

type shState struct {
	mu      sync.Mutex
	at      time.Time
	body    map[string]interface{}
	samples []shSample // 最近 15 分钟
}

var shStates = struct {
	mu sync.Mutex
	m  map[string]*shState
}{m: map[string]*shState{}}

func shFor(hncDir string) *shState {
	shStates.mu.Lock()
	defer shStates.mu.Unlock()
	st := shStates.m[hncDir]
	if st == nil {
		st = &shState{}
		shStates.m[hncDir] = st
	}
	return st
}

func shReadInt(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return -1
	}
	return n
}

// shBase 在 samples 里找「至少 minAge 秒前」的最新一条(作为差分起点)
func shBase(samples []shSample, now int64, minAge int64) *shSample {
	var b *shSample
	for i := range samples {
		s := &samples[i]
		if now-s.T >= minAge && (b == nil || s.T > b.T) {
			b = s
		}
	}
	return b
}

// shEnv 外部依赖(测试注入)
type shEnv struct {
	hotspotIface func() string
	readNetDev   func() ([]byte, error)
	iptForward   func() (string, error)
	ctAcct       func() int
}

func (s *server) shEnvDefault() shEnv {
	return shEnv{
		hotspotIface: s.currentHotspotIface,
		readNetDev:   func() ([]byte, error) { return os.ReadFile("/proc/net/dev") },
		iptForward: func() (string, error) {
			return calRunCmd(5*time.Second, "iptables", "-w", "-t", "mangle", "-L", "FORWARD", "-nvx")
		},
		ctAcct: func() int { return shReadInt("/proc/sys/net/netfilter/nf_conntrack_acct") },
	}
}

// statsHealth 组装一次(调用方负责缓存)
func statsHealth(hncDir string, env shEnv, st *shState, now time.Time) map[string]interface{} {
	cur := shSample{T: now.Unix()}
	ctEvents.mu.Lock()
	ctActive, ctErr := ctEvents.active, ctEvents.lastErr
	cur.CtRecv, cur.CtLost = ctEvents.received, ctEvents.lostN
	ctEvents.mu.Unlock()
	acct := -1
	if env.ctAcct != nil {
		acct = env.ctAcct()
	}

	hs := ""
	if env.hotspotIface != nil {
		hs = env.hotspotIface()
	}
	if hs != "" && env.readNetDev != nil {
		if raw, err := env.readNetDev(); err == nil {
			if v, ok := puParseNetDev(raw)[hs]; ok {
				cur.HsIface, cur.HsBytes, cur.HsOK = hs, v[0]+v[1], true
			}
		}
	}
	iptChecked, iptJump := false, false
	if env.iptForward != nil {
		if out, err := env.iptForward(); err == nil {
			iptChecked = true
			_, _, j, ok := calParseIptForward(out)
			iptJump = ok
			cur.Ipt, cur.IptOK = j, ok
		}
	}

	st.mu.Lock()
	var ctRate interface{}
	lostRecent := false
	if b := shBase(st.samples, cur.T, 60); b != nil {
		if ctActive && cur.CtRecv >= b.CtRecv {
			mins := float64(cur.T-b.T) / 60
			ctRate = float64(int64(float64(cur.CtRecv-b.CtRecv)/mins*10+0.5)) / 10
		}
		lostRecent = cur.CtLost > b.CtLost
	} else if len(st.samples) == 0 {
		lostRecent = cur.CtLost > 0
	}
	stalled, hsActive := false, false
	if b := shBase(st.samples, cur.T, shStallMinWindow); b != nil && b.HsOK && cur.HsOK && b.HsIface == cur.HsIface && cur.HsBytes >= b.HsBytes {
		d := cur.HsBytes - b.HsBytes
		hsActive = d > 0
		if d >= shStallMinBytes && b.IptOK && cur.IptOK && cur.Ipt == b.Ipt {
			stalled = true
		}
	}
	keep := st.samples[:0]
	for _, x := range st.samples {
		if cur.T-x.T <= 15*60 && x.T < cur.T {
			keep = append(keep, x)
		}
	}
	st.samples = append(keep, cur)
	st.mu.Unlock()

	var sampleAge interface{}
	age := int64(-1)
	if fi, err := os.Stat(filepath.Join(hncDir, "data", "stats_raw.jsonl")); err == nil {
		age = now.Unix() - fi.ModTime().Unix()
		if age < 0 {
			age = 0
		}
		sampleAge = age
	}

	guard := readOffloadGuard(hncDir)
	guardActive, _ := guard["fallback_active"].(bool)
	guardMode, _ := guard["mode"].(string)
	offloadState, _ := guard["offload_state"].(string)

	cfg := puLoadConfig(hncDir)
	mode := cfg.netstatsMode()
	var cal *calResult
	if c := calGet(hncDir); c != nil {
		cal = c.result()
	}
	in := shInput{CtActive: ctActive, CtAcct: acct, CtLostRecent: lostRecent,
		IptChecked: iptChecked, IptJump: iptJump, IptStalled: stalled,
		HotspotUp: hs != "", HsActive: hsActive, SampleAge: age,
		ClockSane: clockSane(hncDir, now), GuardKnown: guard != nil, GuardActive: guardActive,
		GuardMode: guardMode, NetstatsMode: mode}
	var gap interface{}
	netstatsAvail := false
	calStatus := "unavailable"
	var checkedAt interface{}
	if mode == "off" {
		in.CalReason = "disabled"
	} else if cal == nil {
		in.CalReason = "pending"
	} else {
		netstatsAvail = cal.NetstatsOK
		in.NetstatsOK, in.CalStatus, in.CalReason = cal.NetstatsOK, cal.Status, cal.Reason
		in.DriftPct, in.OffloadGap, in.OffloadKind = cal.HNCvsNetstatsPct, cal.OffloadGapPct, cal.OffloadKind
		calStatus = cal.Status
		checkedAt = cal.CheckedAt
		if cal.OffloadGapPct != nil {
			gap = *cal.OffloadGapPct
		}
	}
	out := map[string]interface{}{
		"checked_at":                now.Unix(),
		"precise_mode":              ctActive && acct == 1,
		"ct_events_active":          ctActive,
		"ct_acct":                   acct,
		"ct_destroy_events_per_min": ctRate,
		"ct_poll_fallback":          !ctActive || lostRecent,
		"iptables_stats_ok":         iptChecked && iptJump && !stalled,
		"iptables_checked":          iptChecked,
		"iptables_stalled":          stalled,
		"hotspot_iface":             hs,
		"last_stats_sample_age":     sampleAge,
		"clock_sane":                in.ClockSane,
		"offload_guard_active":      guardActive,
		"offload_guard_mode":        guardMode,
		"offload_state":             offloadState,
		"offload_gap_pct":           gap,
		"offload_kind":              in.OffloadKind,
		"netstats_available":        netstatsAvail,
		"netstats_mode":             mode,
		"calibration_status":        calStatus,
		"calibration_checked_at":    checkedAt,
		"hnc_vs_netstats_pct":       in.DriftPct,
		"issues":                    shIssues(in),
	}
	if ctErr != "" && !ctActive {
		out["ct_events_error"] = ctErr
	}
	return out
}

func (s *server) apiStatsHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	st := shFor(s.hncDir)
	now := time.Now()
	st.mu.Lock()
	body, at := st.body, st.at
	st.mu.Unlock()
	if body != nil && now.Sub(at) < shCacheTTL && !now.Before(at) {
		writeJSON(w, http.StatusOK, body)
		return
	}
	body = statsHealth(s.hncDir, s.shEnvDefault(), st, now)
	st.mu.Lock()
	st.body, st.at = body, now
	st.mu.Unlock()
	writeJSON(w, http.StatusOK, body)
}
