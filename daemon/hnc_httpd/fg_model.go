// fg_model.go — DPI v2(第 3 部分): 「这台设备此刻正在用什么 App」前台模型 + 使用时间线
//
// 为什么: live_apps(api_conn.go)按平滑速率排序, 「字节最多的应用」≠「前台应用」——
// 后台更新/预加载/推送心跳/大文件下载都会抢到第一。这里在 app_usage.go 每轮(基准 10 秒,
// 后台档 30 秒)的连接表差分上, 按 (设备, 应用) 算一组短窗口特征再打分, 带滞回地选出前台。
//
// ── 输入 ──────────────────────────────────────────────────────────────────
// appUsageRecordIdent 记账完每条差分后, 把「已经定好归属的应用 id」连同连接 key 与字节交给
// fgSt.step。归属来源(规则 / 用户纠正 / 指纹 / IP 归属组织 / 共现推断 / 隧道)全在记账那一步,
// 这里不重新归类, 只认 id:
//   - _unknown / _local / 广告·SDK·CDN 档(appTier == tierHidden)不参与
//   - _tunnel → 可以是前台, 显示「VPN/代理中」, 置信度封顶 50
//   - _org:*  → IP 归属组织推断, 可以是前台, 分数 ×0.8、置信度封顶 60
//   - 系统服务档(tierSystem)分数 ×0.5、置信度封顶 50
//   - 共现推断的字节占一半以上 → 置信度封顶 70
//
// ── 每轮特征(按实际间隔 dt 折成每秒, 所以 10s / 30s 节拍下口径一致)──────────────
//   下行/上行速率; 有效速率 = 去掉「心跳连接」字节后的速率
//   心跳连接: 连接已存在 ≥ 60 秒且本轮 < 200 B/s(推送长连接、保活)
//   新建连接: 最近 max(30s, dt) 内本应用新出现的连接数(折成每分钟)
//   请求-响应: 某连接本轮上行小(≤ 24 KB)且下行 ≥ 8 KB 且 ≥ 4× 上行; 或上一轮只发了
//              请求(上行为主), 本轮来了 ≥ 8 KB 下行
//   连续性: 连续活跃秒数(中间空 ≤ max(20s, 1.5·dt) 不算断)
//   双向交互: 上行 ≥ 300 B/s 且 上/下 ≥ 0.15 且连续 ≥ 20 秒(游戏/通话/直播推流特征)
//   大文件下载: 有效 ≥ 1 MB/s、单连接占 ≥ 85%、上/下 < 5%、无请求-响应、窗口内新建 ≤ 1,
//              且不是视频/直播/音乐类 → 罚 30 分(后台下载/更新)
//   类别先验: 游戏/短视频/直播 +12, 视频 +10, 通话 +8, 资讯/购物/浏览器/AI/导航 +6,
//            社交 +5, 办公/出行/生活/拍照 +4, 音乐 +3, 下载 −10, 其它 +2
//
// ── 打分(0~100+)─────────────────────────────────────────────────────────
//   速率 0~40(0.8 KB/s→0, 2 MB/s→40, 对数) + 新建 0~15(≥12/分钟满) + 请求-响应 0~10
//   + 连续 0~15(≥60 秒满) + 双向 15 + 先验 − 大文件 30; 不活跃(有效 < 0.8 KB/s 且本轮
//   新建 < 2)= 0。平滑: s ← s + α(本轮 − s), α = 1 − e^(−dt/12s)(10s ≈ 0.57, 30s ≈ 0.92)。
//
// ── 选择(滞回)────────────────────────────────────────────────────────────
//   进入: 平滑分最高且 ≥ 30, 并连续领先 ≥ 2 轮; 或平滑分 ≥ 60 且领先当前前台 ≥ 40(大差距立即)
//   保持: 当前前台平滑分 ≥ 20, 或距它最后一次活跃 ≤ 30 秒(短暂停顿/缓冲不掉)
//   切换: 挑战者满足「进入」条件才换; 当前前台过了保持期且无合格挑战者 → 无前台
//   后台: 其余平滑分 ≥ 12、或连续 ≥ 30 秒且有效 ≥ 2 KB/s 的应用(最多 3 个), 如「后台：QQ音乐」
//   置信度 = 25 + 0.5·分数 + 0.5·领先第二名的差(各封顶), 暂停 ×0.8, 节拍 > 15s −10, 再按来源封顶。
//
// ── 功耗档 ────────────────────────────────────────────────────────────────
//   两轮间隔 > 90 秒(热点关闭 300s 档回来、休眠)→ 模型重置(不把一大段算成连续活跃);
//   /api/devices 读取时: 热点未开/无在线设备 → state=unknown; 超过 3 个当前间隔(≥ 45s)没更新
//   → state=stale(置信度减半); 30s 后台档 → coarse=true。
//
// ── 时间线 ────────────────────────────────────────────────────────────────
//   前台变化即开/关会话 {app_id, name, category, start, end, confidence(按轮平均)};
//   同一应用间隔 ≤ 120 秒重新成为前台 → 并回上一段。会话结束时间 = 该应用最后活跃时间。
//   run/fg_timeline.YYYYMMDD.json(本地日期, 跨 0 点切开), 每分钟随 app_usage 落盘,
//   保留今天 + 前 7 天; 每天最多 128 台设备 × 600 段(满了丢最短的已结束段)。
//
//   GET /api/fg_timeline?mac=<可选>&days=1..8
//     → {sessions:[{mac,app_id,name,category,start,end,sec,confidence,open}],
//        by_app:[{app_id,name,category,fg_sec,fg_min,sessions,active_sec}], total_fg_sec, current}
//     active_sec = app_time.go 的「字节阈值」口径, 两种时长并列给出。
//   /api/devices[].fg = fgView(见下)。live_apps 保留不变。

package main

import (
	"encoding/json"
	"math"
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
	fgOrgPrefix  = "_org:"
	fgTunnelName = "VPN/代理中"

	fgActiveBps   = 800.0 // 有效速率 ≥ 0.8 KB/s 算活跃(与 app_time 的 8 KB/10s 同量级)
	fgWeakBps     = 200.0 // 本轮新建 ≥ 2 条时, ≥ 0.2 KB/s 也算活跃(文字聊天/轻交互)
	fgHBAge       = 60 * time.Second
	fgHBBps       = 200.0
	fgRRMaxUp     = 24 << 10
	fgRRMinDn     = 8 << 10
	fgNewWindow   = 30 * time.Second
	fgContGap     = 20 * time.Second
	fgBidirUpBps  = 300.0
	fgBidirRatio  = 0.15
	fgBulkBps     = 1 << 20
	fgBulkShare   = 0.85
	fgBulkUpRatio = 0.05
	fgBulkPenalty = 30.0
	fgTau         = 12.0 // 秒
	fgEnter       = 30.0
	fgStay        = 20.0
	fgBigMin      = 60.0
	fgBigMargin   = 40.0
	fgLeadTicks   = 2
	fgPauseHold   = 30 * time.Second
	fgBgMin       = 12.0
	fgBgMax       = 3
	fgGapReset    = 90 * time.Second
	fgAppDrop     = 10 * time.Minute
	fgCoarseSec   = 15.0

	fgMaxConns      = 1 << 16
	fgConnIdle      = 5 * time.Minute
	fgMaxDevs       = 256
	fgMaxAppsPerDev = 64
	fgMaxNewAt      = 64

	fgMergeGap        = 120 * time.Second
	fgKeepDays        = 7 // 今天 + 前 7 天
	fgMaxSessPerDev   = 600
	fgMaxDevsPerDay   = 128
	fgStaleMinSeconds = 45
)

// fgObs 一条已归属的差分(app_usage 记账步骤给)
type fgObs struct {
	MAC, ID, Name, Category, Key string
	Up, Dn                       uint64
	Inferred                     bool
}

type fgConn struct {
	first, last time.Time
	upOnly      bool // 上一轮只发了请求(上行为主、下行很少)
}

type fgFeat struct {
	DnBps, UpBps, EffBps float64
	NewWin               int
	NewPerMin            float64
	RR                   int
	HBShare              float64
	Conns                int
	TopShare             float64
	InfShare             float64
	Bulk, Bidir, Active  bool
}

type fgApp struct {
	id, name, cat string
	smooth, inst  float64
	contSec       float64
	activeSince   time.Time
	lastActive    time.Time
	lastSeen      time.Time
	newAt         []time.Time
	lead          int
	f             fgFeat
}

type fgBg struct {
	AppID    string `json:"app_id"`
	Name     string `json:"name"`
	Category string `json:"category,omitempty"`
	Label    string `json:"label,omitempty"` // 后台播放 / 下载中 / 后台活动
}

// fgView /api/devices[].fg
type fgView struct {
	State      string   `json:"state"` // active | paused | idle | stale | unknown
	AppID      string   `json:"app_id"`
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Confidence int      `json:"confidence"`
	Since      int64    `json:"since"`
	Reasons    []string `json:"reasons"`
	Background []fgBg   `json:"background"`
	Label      string   `json:"label"`
	BgLabel    string   `json:"bg_label,omitempty"`
	Score      int      `json:"score"`
	TickSec    int      `json:"tick_sec"`
	Coarse     bool     `json:"coarse,omitempty"`
	Stale      bool     `json:"stale,omitempty"`
	Updated    int64    `json:"updated"`
}

type fgDev struct {
	apps    map[string]*fgApp
	cur     string // 经典模型的前台
	since   time.Time
	open    bool // 今天的时间线里该设备最后一段是打开的
	view    fgView
	lastObs time.Time
	// v5.27 T4: shown = 显示与时间线跟随的前台(classic 引擎时恒等于 cur, hmm 引擎时 = hmm.cur)
	shown string
	hmm   *hmmDev
	hmmAt time.Time // HMM 上一轮时刻(取这段时间内的启动事件)
}

type fgSession struct {
	App   string  `json:"app_id"`
	Name  string  `json:"name"`
	Cat   string  `json:"category,omitempty"`
	Start int64   `json:"start"`
	End   int64   `json:"end"`
	Conf  float64 `json:"confidence"`
	N     int     `json:"n,omitempty"`
}

type fgDay struct {
	Date    string                 `json:"date"`
	Devices map[string][]fgSession `json:"devices"`
}

type fgModel struct {
	mu    sync.Mutex
	devs  map[string]*fgDev
	conns map[string]*fgConn
	last  time.Time
	dt    float64
	day   *fgDay
	dirty bool
	dir   string     // 落盘目录(load 设置; 为空 = 不落盘, 单测用)
	cmp   *fgCompare // v5.27 T4: 经典 / HMM 对比统计(fg_hmm.go)
	// engine v5.27 T4: 返回当前前台引擎; nil = 用 engineCur(load / flush / 切换动作时从
	// data/dpi_experiment.json 刷新, 每轮 step 不做文件 I/O)
	engine    func() string
	engineCur string
	// started v5.27 T4: (设备, (after, upTo]) 内有启动事件的应用; nil = startupEventsForHMM
	started func(mac string, after, upTo int64) map[string]bool
}

func newFgModel() *fgModel {
	return &fgModel{devs: map[string]*fgDev{}, conns: map[string]*fgConn{}, cmp: newFgCompare()}
}

func (m *fgModel) engineLocked() string {
	if m.engine != nil {
		return m.engine()
	}
	if m.engineCur == "" {
		return fgEngineClass
	}
	return m.engineCur
}

// setEngine 切换动作写完文件后立即生效(不等下一次 flush)
func (m *fgModel) setEngine(eng string) {
	m.mu.Lock()
	m.engineCur = eng
	m.mu.Unlock()
}

// fgSt 全局模型: step 在 appUsage.mu 内调用(锁顺序 appUsage.mu → fgSt.mu); 请求路径只拿 fgSt.mu。
var fgSt = newFgModel()

func fgIsOrg(id string) bool    { return strings.HasPrefix(id, fgOrgPrefix) }
func fgIsTunnel(id string) bool { return id == tunnelAppID }

func fgCandidate(id, cat string) bool {
	if id == "" || id == appUnknownID || id == appLocalID {
		return false
	}
	return appTier(cat) != tierHidden
}

// fgCatPrior 类别先验分与理由标签
func fgCatPrior(cat string) (float64, string) {
	c := strings.ToLower(strings.TrimSpace(cat))
	switch c {
	case "short_video", "short-video":
		return 12, "短视频类"
	case "live", "live_stream", "live-stream":
		return 12, "直播类"
	case "video":
		return 10, "视频类"
	case "social_voip", "voip":
		return 8, "通话类"
	case "news", "reading":
		return 6, "资讯/阅读类"
	case "shopping":
		return 6, "购物类"
	case "browser":
		return 6, "浏览器"
	case "ai":
		return 6, "AI 助手"
	case "navigation":
		return 6, "导航类"
	case "social":
		return 5, "社交类"
	case "office", "travel", "life_service", "photo", "education":
		return 4, ""
	case "music", "audio", "podcast":
		return 3, "音乐/音频类"
	case "download", "app_store":
		return -10, "下载类"
	case tunnelCategory:
		return 0, ""
	}
	if strings.HasPrefix(c, "game") && !strings.Contains(c, "tool") {
		return 12, "游戏类"
	}
	if strings.Contains(c, "video") {
		return 10, "视频类"
	}
	if appTier(c) == tierSystem {
		return 0, ""
	}
	return 2, ""
}

func fgStreamingCat(cat string) bool {
	c := strings.ToLower(cat)
	return strings.Contains(c, "video") || strings.HasPrefix(c, "live") || c == "music" || c == "audio" || c == "podcast"
}

func fgMusicCat(cat string) bool {
	c := strings.ToLower(cat)
	return c == "music" || c == "audio" || c == "podcast"
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// fgScore 本轮分数(纯函数)
func fgScore(f fgFeat, contSec float64, id, cat string) float64 {
	if !f.Active {
		return 0
	}
	s := 0.0
	if f.EffBps > fgActiveBps {
		s += 40 * clamp01(math.Log10(f.EffBps/fgActiveBps)/math.Log10(2e6/fgActiveBps))
	}
	s += 15 * math.Min(f.NewPerMin, 12) / 12
	s += 10 * math.Min(float64(f.RR), 3) / 3
	s += 15 * math.Min(contSec, 60) / 60
	if f.Bidir {
		s += 15
	}
	p, _ := fgCatPrior(cat)
	s += p
	if f.Bulk {
		s -= fgBulkPenalty
	}
	switch {
	case fgIsOrg(id):
		s *= 0.8
	case appTier(cat) == tierSystem:
		s *= 0.5
	}
	if f.InfShare > 0.5 {
		s *= 0.9
	}
	if s < 0 {
		s = 0
	}
	return s
}

type fgAgg struct {
	name, cat     string
	dn, up, hb    uint64
	inf           uint64
	conns         map[string]uint64
	newTick, rr   int
	hasConnDetail bool
}

// reset 清空设备状态(时间回退/长间隔/时钟跳变), 打开的会话在 at 收尾
func (m *fgModel) resetLocked(at time.Time) {
	for mac, d := range m.devs {
		end := at
		if a := d.apps[d.shown]; a != nil && !a.lastActive.IsZero() && a.lastActive.Before(at) {
			end = a.lastActive
		}
		m.closeSessionLocked(mac, d, end)
	}
	m.devs = map[string]*fgDev{}
	m.conns = map[string]*fgConn{}
	m.last = time.Time{}
	m.cmp.reset() // v5.27 T4: HMM 状态在 devs 里, 随之重置; 对比统计的段起点也重来
}

func (m *fgModel) reset(at time.Time) {
	m.mu.Lock()
	m.resetLocked(at)
	m.mu.Unlock()
}

// step 一轮。level = 当前活动档(仅用于 view 的 tick/粗略标记; 打分只看实际间隔)。
func (m *fgModel) step(now time.Time, obs []fgObs, level string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	dt := 10.0
	if !m.last.IsZero() {
		switch d := now.Sub(m.last); {
		case d <= 0:
			m.resetLocked(m.last)
		case d > fgGapReset:
			m.resetLocked(m.last.Add(appUsageEvery))
		default:
			dt = d.Seconds()
		}
	}
	firstTick := m.last.IsZero()
	m.last, m.dt = now, dt
	m.rollDayLocked(now)

	per := map[string]map[string]*fgAgg{}
	for _, o := range obs {
		if o.MAC == "" || !fgCandidate(o.ID, o.Category) {
			continue
		}
		if per[o.MAC] == nil {
			per[o.MAC] = map[string]*fgAgg{}
		}
		a := per[o.MAC][o.ID]
		if a == nil {
			a = &fgAgg{name: o.Name, cat: o.Category, conns: map[string]uint64{}}
			per[o.MAC][o.ID] = a
		}
		b := o.Up + o.Dn
		a.dn += o.Dn
		a.up += o.Up
		if o.Inferred {
			a.inf += b
		}
		var c *fgConn
		isNew := false
		if o.Key != "" {
			a.hasConnDetail = true
			if _, dup := a.conns[o.Key]; !dup {
				c = m.conns[o.Key]
				if c == nil {
					c = &fgConn{first: now}
					if firstTick {
						c.first = now.Add(-fgHBAge) // 模型刚起: 已有连接按「老连接」算, 不当成新建
					} else {
						isNew = true
					}
					if len(m.conns) < fgMaxConns {
						m.conns[o.Key] = c
					}
				}
			} else {
				c = m.conns[o.Key]
			}
			a.conns[o.Key] += b
			if isNew {
				a.newTick++
			}
		}
		// 请求-响应
		if (o.Up > 0 && o.Up <= fgRRMaxUp && o.Dn >= fgRRMinDn && o.Dn >= 4*o.Up) ||
			(c != nil && c.upOnly && o.Dn >= fgRRMinDn) {
			a.rr++
		}
		if c != nil {
			c.upOnly = o.Up > 0 && o.Dn < 2*o.Up && o.Dn < fgRRMinDn
			c.last = now
		}
	}
	// 心跳字节按连接本轮合计判断(同一连接本轮可能有多条差分)
	for _, apps := range per {
		for _, a := range apps {
			for k, b := range a.conns {
				if c := m.conns[k]; c != nil && now.Sub(c.first) >= fgHBAge && float64(b)/dt < fgHBBps {
					a.hb += b
				}
			}
		}
	}
	for k, c := range m.conns {
		if now.Sub(c.last) > fgConnIdle && now.Sub(c.first) > fgConnIdle {
			delete(m.conns, k)
		}
	}

	macs := make([]string, 0, len(m.devs)+len(per))
	for mac := range m.devs {
		macs = append(macs, mac)
	}
	for mac := range per {
		if _, ok := m.devs[mac]; !ok {
			if len(m.devs) >= fgMaxDevs {
				continue
			}
			m.devs[mac] = &fgDev{apps: map[string]*fgApp{}}
			macs = append(macs, mac)
		}
	}
	sort.Strings(macs)
	for _, mac := range macs {
		d := m.devs[mac]
		m.stepDevLocked(mac, d, per[mac], now, dt, level)
		if len(d.apps) == 0 && d.cur == "" && now.Sub(d.lastObs) > fgAppDrop {
			delete(m.devs, mac)
		}
	}
}

func (m *fgModel) stepDevLocked(mac string, d *fgDev, aggs map[string]*fgAgg, now time.Time, dt float64, level string) {
	alpha := 1 - math.Exp(-dt/fgTau)
	gapTol := math.Max(fgContGap.Seconds(), 1.5*dt)
	win := math.Max(fgNewWindow.Seconds(), dt)
	if len(aggs) > 0 {
		d.lastObs = now
	}
	for id, g := range aggs {
		a := d.apps[id]
		if a == nil {
			if len(d.apps) >= fgMaxAppsPerDev {
				continue
			}
			a = &fgApp{id: id}
			d.apps[id] = a
		}
		a.name, a.cat = g.name, g.cat
		a.lastSeen = now
		for i := 0; i < g.newTick && len(a.newAt) < fgMaxNewAt; i++ {
			a.newAt = append(a.newAt, now)
		}
	}
	for id, a := range d.apps {
		// 新建窗口
		i := 0
		for i < len(a.newAt) && now.Sub(a.newAt[i]).Seconds() > win {
			i++
		}
		a.newAt = a.newAt[i:]
		g := aggs[id]
		var f fgFeat
		if g != nil {
			tot := g.dn + g.up
			eff := float64(tot-min(g.hb, tot)) / dt
			f.DnBps, f.UpBps, f.EffBps = float64(g.dn)/dt, float64(g.up)/dt, eff
			if tot > 0 {
				f.HBShare = float64(g.hb) / float64(tot)
				f.InfShare = float64(g.inf) / float64(tot)
			}
			f.Conns = len(g.conns)
			var top uint64
			for _, b := range g.conns {
				top = max(top, b)
			}
			if tot > 0 && g.hasConnDetail {
				f.TopShare = float64(top) / float64(tot)
			}
			f.RR = g.rr
			f.NewWin = len(a.newAt)
			f.NewPerMin = float64(f.NewWin) / win * 60
			f.Active = eff >= fgActiveBps || (g.newTick >= 2 && eff >= fgWeakBps)
		}
		if f.Active {
			if a.lastActive.IsZero() || now.Sub(a.lastActive).Seconds() > gapTol {
				a.activeSince = now.Add(-time.Duration(dt * float64(time.Second)))
			}
			a.lastActive = now
			a.contSec = now.Sub(a.activeSince).Seconds()
			f.Bidir = f.UpBps >= fgBidirUpBps && f.DnBps > 0 && f.UpBps/f.DnBps >= fgBidirRatio && a.contSec >= 20
			f.Bulk = f.EffBps >= fgBulkBps && f.TopShare >= fgBulkShare && f.DnBps > 0 &&
				f.UpBps/f.DnBps < fgBulkUpRatio && f.RR == 0 && f.NewWin <= 1 && !fgStreamingCat(a.cat) &&
				!fgIsTunnel(id) // 隧道天然是单连接, 看不到里面, 不按下载罚
		} else if !a.lastActive.IsZero() && now.Sub(a.lastActive).Seconds() > gapTol {
			a.contSec = 0
		}
		a.f = f
		a.inst = fgScore(f, a.contSec, id, a.cat)
		a.smooth += alpha * (a.inst - a.smooth)
		if a.smooth < 0.05 {
			a.smooth = 0
		}
	}
	for id, a := range d.apps {
		if id != d.cur && id != d.shown && (d.hmm == nil || id != d.hmm.cur) && now.Sub(a.lastSeen) > fgAppDrop {
			delete(d.apps, id)
		}
	}
	m.decideLocked(mac, d, now, dt, level, len(aggs) > 0)
}

func fgRank(d *fgDev) []*fgApp {
	list := make([]*fgApp, 0, len(d.apps))
	for _, a := range d.apps {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].smooth != list[j].smooth {
			return list[i].smooth > list[j].smooth
		}
		return list[i].id < list[j].id
	})
	return list
}

func (m *fgModel) decideLocked(mac string, d *fgDev, now time.Time, dt float64, level string, traffic bool) {
	rank := fgRank(d)
	var top *fgApp
	if len(rank) > 0 && rank[0].smooth >= fgEnter && rank[0].id != d.cur {
		top = rank[0]
	}
	for _, a := range rank {
		if a == top {
			a.lead++
		} else {
			a.lead = 0
		}
	}
	cur := d.apps[d.cur]
	if d.cur != "" && cur == nil {
		d.cur = ""
	}
	curScore := 0.0
	curOK := false
	if cur != nil {
		curScore = cur.smooth
		curOK = cur.smooth >= fgStay || (!cur.lastActive.IsZero() && now.Sub(cur.lastActive) <= fgPauseHold)
	}
	prev := d.cur
	if top != nil {
		qualified := top.lead >= fgLeadTicks || (top.smooth >= fgBigMin && top.smooth-curScore >= fgBigMargin)
		if qualified {
			d.cur = top.id
			top.lead = 0
		}
	}
	if d.cur == prev && cur != nil && !curOK {
		d.cur = ""
	}
	// v5.27 T4: HMM 每轮都算(影子); 引擎 = hmm 时显示与时间线跟随 HMM 的决定。
	hmmCur := m.hmmStepLocked(mac, d, now, dt)
	useHMM := m.engineLocked() == fgEngineHMM
	shown := d.cur
	if useHMM {
		shown = hmmCur
	}
	if traffic {
		m.cmp.record(mac, now, dt, d.cur, hmmCur)
	}
	if shown != d.shown {
		if prev := d.shown; prev != "" {
			end := now
			if p := d.apps[prev]; p != nil && !p.lastActive.IsZero() {
				end = p.lastActive
			}
			m.closeSessionLocked(mac, d, end)
		}
		d.shown = shown
		if shown != "" {
			a := d.apps[shown]
			start := a.activeSince
			if start.IsZero() || start.After(now) {
				start = now
			}
			d.since = m.openSessionLocked(mac, d, a, start)
		} else {
			d.since = time.Time{}
		}
	}
	d.view = m.buildViewLocked(d, rank, now, dt, level)
	if useHMM && d.shown != "" {
		if a := d.apps[d.shown]; a != nil {
			d.view.Confidence = hmmConfidence(a, d.hmm.post)
			d.view.Reasons = append(d.view.Reasons, "HMM 后验 "+strconv.Itoa(int(math.Round(d.hmm.post*100)))+"%")
		}
	}
	if d.shown != "" && d.open {
		end := now
		if a := d.apps[d.shown]; a != nil && !a.lastActive.IsZero() {
			end = a.lastActive
		}
		m.extendSessionLocked(mac, end, float64(d.view.Confidence))
	}
}

// hmmStepLocked v5.27 T4: 用本轮各应用的分(a.inst)跑一轮 HMM, 返回 HMM 的前台("" = 无)
func (m *fgModel) hmmStepLocked(mac string, d *fgDev, now time.Time, dt float64) string {
	if d.hmm == nil {
		d.hmm = newHMMDev()
	}
	inst := make(map[string]float64, len(d.apps))
	for id, a := range d.apps {
		inst[id] = a.inst
	}
	var started map[string]bool
	after := now.Add(-time.Duration(dt * float64(time.Second)))
	if !d.hmmAt.IsZero() && d.hmmAt.Before(now) {
		after = d.hmmAt
	}
	if m.started != nil {
		started = m.started(mac, after.Unix(), now.Unix())
	} else {
		started = startupEventsForHMM(mac, after.Unix(), now.Unix())
	}
	d.hmmAt = now
	hmmStep(d.hmm, inst, started, dt)
	if d.hmm.cur != "" && d.apps[d.hmm.cur] == nil {
		d.hmm.cur = ""
	}
	return d.hmm.cur
}

// fgConfCap 置信度按来源封顶(经典与 HMM 共用)
func fgConfCap(a *fgApp) float64 {
	capv := 95.0
	switch {
	case fgIsTunnel(a.id):
		capv = 50
	case fgIsOrg(a.id):
		capv = 60
	case appTier(a.cat) == tierSystem:
		capv = 50
	}
	if a.f.InfShare > 0.5 {
		capv = math.Min(capv, 70)
	}
	return capv
}

func fgConfidence(a *fgApp, second, dt float64) int {
	s := math.Min(a.smooth, 100)
	c := 25 + 0.5*s + 0.5*math.Min(math.Max(a.smooth-second, 0), 50)
	if !a.f.Active {
		c *= 0.8
	}
	if dt > fgCoarseSec {
		c -= 10
	}
	c = math.Max(0, math.Min(c, fgConfCap(a)))
	return int(math.Round(c))
}

// fgFmtRate 字节/秒 → "2.1 MB/s"
func fgFmtRate(bps float64) string {
	switch {
	case bps >= 1<<20:
		return strconv.FormatFloat(bps/(1<<20), 'f', 1, 64) + " MB/s"
	case bps >= 1<<10:
		return strconv.FormatFloat(bps/(1<<10), 'f', 0, 64) + " KB/s"
	}
	return strconv.FormatFloat(bps, 'f', 0, 64) + " B/s"
}

func fgReasons(a *fgApp) []string {
	var r []string
	f := a.f
	if fgIsTunnel(a.id) {
		r = append(r, "流量走 VPN/代理隧道, 看不到具体应用")
	}
	if fgIsOrg(a.id) {
		r = append(r, "按目的 IP 归属组织推断(无域名/规则命中)")
	}
	if !f.Active {
		r = append(r, "暂停中(30 秒内恢复仍算同一段)")
	}
	if f.Active && f.DnBps >= 1024 {
		p := "下行 "
		if a.contSec >= 30 {
			p = "持续下行 "
		}
		r = append(r, p+fgFmtRate(f.DnBps))
	}
	if f.Active && f.UpBps >= 100<<10 {
		r = append(r, "上行 "+fgFmtRate(f.UpBps))
	}
	if f.NewWin >= 2 {
		r = append(r, "新建 "+strconv.Itoa(f.NewWin)+" 个连接")
	}
	if f.RR > 0 {
		r = append(r, "请求-响应交互 "+strconv.Itoa(f.RR)+" 次")
	}
	if f.Bidir {
		r = append(r, "双向持续交互(游戏/通话特征)")
	}
	if a.contSec >= 60 {
		r = append(r, "连续活跃 "+strconv.Itoa(int(a.contSec/60))+" 分钟")
	}
	if _, lbl := fgCatPrior(a.cat); lbl != "" {
		r = append(r, lbl)
	}
	if f.InfShare > 0.5 {
		r = append(r, "部分归属为共现推测")
	}
	if f.HBShare > 0.5 {
		r = append(r, "以心跳/推送长连接为主")
	}
	return r
}

func fgDisplayName(a *fgApp) string {
	if fgIsTunnel(a.id) {
		return fgTunnelName
	}
	if a.name != "" {
		return a.name
	}
	return a.id
}

func (m *fgModel) buildViewLocked(d *fgDev, rank []*fgApp, now time.Time, dt float64, level string) fgView {
	v := fgView{State: "idle", Reasons: []string{}, Background: []fgBg{}, TickSec: int(math.Round(dt)),
		Coarse: dt > fgCoarseSec, Updated: now.Unix()}
	if a := d.apps[d.shown]; a != nil {
		second := 0.0
		for _, o := range rank {
			if o != a {
				second = o.smooth
				break
			}
		}
		v.AppID, v.Name, v.Category = a.id, fgDisplayName(a), a.cat
		v.Confidence = fgConfidence(a, second, dt)
		v.Score = int(math.Round(a.smooth))
		v.Reasons = fgReasons(a)
		if !d.since.IsZero() {
			v.Since = d.since.Unix()
		}
		v.State = "active"
		if !a.f.Active {
			v.State = "paused"
		}
		v.Label = "正在用：" + v.Name
		if fgIsTunnel(a.id) {
			v.Label = fgTunnelName
		}
	}
	var names []string
	for _, o := range rank {
		// 后台列表用经典模型的(排除经典前台); hmm 引擎时也排除正在显示的前台
		if o.id == d.cur || o.id == d.shown || len(v.Background) >= fgBgMax {
			continue
		}
		if o.lastActive.IsZero() || now.Sub(o.lastActive) > 60*time.Second {
			continue
		}
		if !(o.smooth >= fgBgMin || (o.contSec >= 30 && o.f.EffBps >= 2048)) {
			continue
		}
		lbl := "后台活动"
		switch {
		case o.f.Bulk:
			lbl = "下载中"
		case fgMusicCat(o.cat):
			lbl = "后台播放"
		}
		v.Background = append(v.Background, fgBg{AppID: o.id, Name: fgDisplayName(o), Category: o.cat, Label: lbl})
		names = append(names, fgDisplayName(o))
	}
	if len(names) > 0 {
		v.BgLabel = "后台：" + strings.Join(names, "、")
	}
	if dt > fgCoarseSec && v.AppID != "" {
		v.Reasons = append(v.Reasons, "采样已放慢到 "+strconv.Itoa(v.TickSec)+" 秒(省电), 判断较粗")
	}
	_ = level
	return v
}

// ─── 时间线 ───────────────────────────────────────────────────────────

func fgMidnight(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

func (m *fgModel) rollDayLocked(now time.Time) {
	date := now.Format("20060102")
	if m.day == nil {
		m.day = &fgDay{Date: date, Devices: map[string][]fgSession{}}
		return
	}
	if m.day.Date == date {
		return
	}
	mid := fgMidnight(now)
	type reopen struct {
		mac string
		s   fgSession
	}
	var re []reopen
	for mac, d := range m.devs {
		if !d.open {
			continue
		}
		l := m.day.Devices[mac]
		if n := len(l); n > 0 {
			s := l[n-1]
			if s.End > mid.Unix() {
				l[n-1].End = mid.Unix()
			}
			if d.shown != "" && s.End >= mid.Unix()-int64(fgPauseHold/time.Second) {
				l[n-1].End = mid.Unix() // 仍在用: 旧一天的段延到 0 点, 新一天从 0 点接上
				re = append(re, reopen{mac, fgSession{App: s.App, Name: s.Name, Cat: s.Cat, Start: mid.Unix(), End: max(mid.Unix(), s.End), Conf: s.Conf, N: 1}})
			}
		}
		d.open = false
	}
	if m.dirty && m.dir != "" {
		_ = fgSaveDay(m.dir, m.day)
	}
	m.day = &fgDay{Date: date, Devices: map[string][]fgSession{}}
	m.dirty = len(re) > 0
	for _, r := range re {
		m.day.Devices[r.mac] = []fgSession{r.s}
		m.devs[r.mac].open = true
		m.devs[r.mac].since = mid
	}
}

// openSessionLocked 开一段(或并回同应用的上一段), 返回该段开始时间
func (m *fgModel) openSessionLocked(mac string, d *fgDev, a *fgApp, start time.Time) time.Time {
	if m.day == nil {
		return start
	}
	l, ok := m.day.Devices[mac]
	if !ok && len(m.day.Devices) >= fgMaxDevsPerDay {
		return start
	}
	st := start.Unix()
	if mid := fgMidnight(m.last).Unix(); st < mid {
		st = mid // 跨 0 点: 今天的时间线从 0 点算起
	}
	if n := len(l); n > 0 {
		last := &l[n-1]
		if st < last.End {
			st = last.End // 和上一段不重叠
		}
		if last.App == a.id && st-last.End <= int64(fgMergeGap/time.Second) {
			last.Name, last.Cat = fgDisplayName(a), a.cat
			d.open, m.dirty = true, true
			return time.Unix(last.Start, 0)
		}
	}
	if len(l) >= fgMaxSessPerDev {
		l = fgDropShortest(l)
	}
	l = append(l, fgSession{App: a.id, Name: fgDisplayName(a), Cat: a.cat, Start: st, End: st})
	m.day.Devices[mac] = l
	d.open, m.dirty = true, true
	return time.Unix(st, 0)
}

func fgDropShortest(l []fgSession) []fgSession {
	if len(l) < 2 {
		return l
	}
	k := 0
	for i := 1; i < len(l)-1; i++ { // 最后一段可能还开着, 不丢
		if l[i].End-l[i].Start < l[k].End-l[k].Start {
			k = i
		}
	}
	return append(l[:k:k], l[k+1:]...)
}

func (m *fgModel) extendSessionLocked(mac string, end time.Time, conf float64) {
	if m.day == nil {
		return
	}
	l := m.day.Devices[mac]
	n := len(l)
	if n == 0 {
		return
	}
	s := &l[n-1]
	if e := end.Unix(); e > s.End {
		s.End = e
	}
	s.Conf = math.Round((s.Conf*float64(s.N)+conf)/float64(s.N+1)*10) / 10
	s.N++
	m.dirty = true
}

func (m *fgModel) closeSessionLocked(mac string, d *fgDev, end time.Time) {
	if !d.open || m.day == nil {
		d.open = false
		return
	}
	l := m.day.Devices[mac]
	if n := len(l); n > 0 {
		s := &l[n-1]
		if e := end.Unix(); e > s.End {
			s.End = e
		}
		m.dirty = true
	}
	d.open = false
}

func fgDayPath(hncDir, date string) string {
	return filepath.Join(hncDir, "run", "fg_timeline."+date+".json")
}

func fgSaveDay(hncDir string, d *fgDay) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return discoverWriteAtomic(fgDayPath(hncDir, d.Date), b)
}

func fgLoadDay(hncDir, date string) *fgDay {
	b, err := os.ReadFile(fgDayPath(hncDir, date))
	if err != nil {
		return nil
	}
	var d fgDay
	if json.Unmarshal(b, &d) != nil || d.Devices == nil {
		return nil
	}
	d.Date = date
	for mac, l := range d.Devices {
		if len(l) > fgMaxSessPerDev {
			d.Devices[mac] = l[len(l)-fgMaxSessPerDev:]
		}
	}
	return &d
}

// load 设置落盘目录并载入今天已有的时间线(AppUsageLoop 启动时调用)
func (m *fgModel) load(hncDir string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dir = hncDir
	m.cmp.load(hncDir) // v5.27 T4: 对比统计
	m.engineCur = fgEngineFor(hncDir)
	date := now.Format("20060102")
	if d := fgLoadDay(hncDir, date); d != nil {
		if m.day != nil && m.day.Date == date {
			for mac, l := range m.day.Devices { // 已经在内存里记了的接在后面
				d.Devices[mac] = append(d.Devices[mac], l...)
			}
		}
		m.day = d
	}
}

// flush 有变化就落盘, 并清理 7 天前的文件(随 appUsageFlush 每分钟一次)
func (m *fgModel) flush(now time.Time) {
	m.mu.Lock()
	dir := m.dir
	var cp *fgDay
	if dir != "" && m.dirty && m.day != nil {
		cp = m.day.copy()
		m.dirty = false
	}
	var cmpB []byte // v5.27 T4: 对比统计随 fg 每分钟落盘
	if dir != "" && m.cmp.dirty {
		cmpB = m.cmp.snapshot(now)
		m.cmp.dirty = false
	}
	m.mu.Unlock()
	if dir == "" {
		return
	}
	if cmpB != nil {
		_ = discoverWriteAtomic(fgCmpPath(dir), cmpB)
	}
	if eng := fgEngineFor(dir); eng != "" { // 文件被手工改过也能在一分钟内生效
		m.mu.Lock()
		m.engineCur = eng
		m.mu.Unlock()
	}
	if cp != nil {
		if err := fgSaveDay(dir, cp); err != nil {
			m.mu.Lock()
			m.dirty = true
			m.mu.Unlock()
		}
	}
	if !clockSane(dir, now) {
		return
	}
	cut := now.AddDate(0, 0, -fgKeepDays).Format("20060102")
	ents, _ := os.ReadDir(filepath.Join(dir, "run"))
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, "fg_timeline.") && strings.HasSuffix(n, ".json") {
			if date := strings.TrimSuffix(strings.TrimPrefix(n, "fg_timeline."), ".json"); len(date) == 8 && date < cut {
				_ = os.Remove(filepath.Join(dir, "run", n))
			}
		}
	}
}

func (d *fgDay) copy() *fgDay {
	out := &fgDay{Date: d.Date, Devices: make(map[string][]fgSession, len(d.Devices))}
	for k, l := range d.Devices {
		out.Devices[k] = append([]fgSession(nil), l...)
	}
	return out
}

// dayCopy 某天时间线(今天取内存副本, 其余读文件); openMAC = 今天仍打开着会话的设备
func (m *fgModel) dayCopy(date string) (*fgDay, map[string]bool) {
	m.mu.Lock()
	if m.day != nil && m.day.Date == date {
		cp := m.day.copy()
		open := map[string]bool{}
		for mac, d := range m.devs {
			if d.open {
				open[mac] = true
			}
		}
		m.mu.Unlock()
		return cp, open
	}
	dir := m.dir
	m.mu.Unlock()
	if dir == "" {
		return nil, nil
	}
	return fgLoadDay(dir, date), nil
}

// ─── 发布给 /api/devices ─────────────────────────────────────────────

// fgApplyStale 读取时按活动档/更新时间修正(纯函数)。interval = app_usage 当前间隔。
func fgApplyStale(v fgView, now time.Time, level string, interval time.Duration) fgView {
	if level == lvlHotspotOff || level == lvlNoClients {
		return fgView{State: "unknown", Reasons: []string{"热点未开或无在线设备, 不判断前台"}, Background: []fgBg{},
			TickSec: v.TickSec, Stale: true, Updated: v.Updated}
	}
	lim := 3 * interval
	if lim < fgStaleMinSeconds*time.Second {
		lim = fgStaleMinSeconds * time.Second
	}
	if age := now.Sub(time.Unix(v.Updated, 0)); v.Updated > 0 && age > lim {
		v.State, v.Stale = "stale", true
		v.Confidence /= 2
		v.Reasons = append(append([]string(nil), v.Reasons...), "数据已 "+strconv.Itoa(int(age/time.Second))+" 秒未更新")
	}
	return v
}

// fgViews 每台设备的前台视图(已按活动档修正)
func (m *fgModel) views(now time.Time, level string, interval time.Duration) map[string]fgView {
	m.mu.Lock()
	out := make(map[string]fgView, len(m.devs))
	for mac, d := range m.devs {
		if d.view.Updated == 0 {
			continue
		}
		v := d.view
		v.Reasons = append([]string(nil), v.Reasons...)
		v.Background = append([]fgBg(nil), v.Background...)
		out[mac] = v
	}
	m.mu.Unlock()
	for mac, v := range out {
		out[mac] = fgApplyStale(v, now, level, interval)
	}
	return out
}

func fgViewsByMAC(now time.Time) map[string]fgView {
	return fgSt.views(now, activityNow().Level, powerCurrent("app_usage"))
}

// ─── API ─────────────────────────────────────────────────────────────

func (s *server) apiFgTimeline(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 {
		days = 1
	}
	if days > fgKeepDays+1 {
		days = fgKeepDays + 1
	}
	mac := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mac")))
	if mac != "" && !validMAC(mac) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mac"})
		return
	}
	resolve := macAliasResolver(s.hncDir)
	if mac != "" {
		mac = resolve(mac)
	}
	writeJSON(w, http.StatusOK, s.fgTimelinePayload(fgSt, mac, days, time.Now(), resolve))
}

type fgOutSess struct {
	MAC        string `json:"mac"`
	AppID      string `json:"app_id"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	Start      int64  `json:"start"`
	End        int64  `json:"end"`
	Sec        int64  `json:"sec"`
	Confidence int    `json:"confidence"`
	Open       bool   `json:"open"`
}

type fgOutApp struct {
	AppID     string  `json:"app_id"`
	Name      string  `json:"name"`
	Category  string  `json:"category"`
	FgSec     int64   `json:"fg_sec"`
	FgMin     float64 `json:"fg_min"`
	Sessions  int     `json:"sessions"`
	ActiveSec uint64  `json:"active_sec"` // app_time.go 字节阈值口径(对照)
}

func (s *server) fgTimelinePayload(m *fgModel, mac string, days int, now time.Time, resolve func(string) string) map[string]interface{} {
	if resolve == nil {
		resolve = func(x string) string { return x }
	}
	sessions := []fgOutSess{}
	byApp := map[string]*fgOutApp{}
	since := ""
	var total int64
	for i := days - 1; i >= 0; i-- {
		date := now.AddDate(0, 0, -i).Format("20060102")
		d, open := m.dayCopy(date)
		if d != nil {
			if since == "" {
				since = date
			}
			macs := make([]string, 0, len(d.Devices))
			for k := range d.Devices {
				macs = append(macs, k)
			}
			sort.Strings(macs)
			for _, raw := range macs {
				dm := resolve(raw)
				if mac != "" && dm != mac {
					continue
				}
				l := d.Devices[raw]
				for j, ss := range l {
					sec := ss.End - ss.Start
					if sec < 0 {
						sec = 0
					}
					o := fgOutSess{MAC: dm, AppID: ss.App, Name: ss.Name, Category: ss.Cat, Start: ss.Start, End: ss.End,
						Sec: sec, Confidence: int(math.Round(ss.Conf)), Open: open[raw] && j == len(l)-1}
					sessions = append(sessions, o)
					a := byApp[ss.App]
					if a == nil {
						a = &fgOutApp{AppID: ss.App, Name: ss.Name, Category: ss.Cat}
						byApp[ss.App] = a
					}
					a.FgSec += sec
					a.Sessions++
					total += sec
				}
			}
		}
		// 对照: app_time 口径的活跃秒数
		if ad := appUsageDayCopy(s.hncDir, date); ad != nil {
			for _, cells := range ad.Active {
				for mk, sec := range cells {
					sep := strings.IndexByte(mk, '|')
					if sep < 0 || (mac != "" && resolve(mk[:sep]) != mac) {
						continue
					}
					id := mk[sep+1:]
					a := byApp[id]
					if a == nil {
						meta := ad.Apps[id]
						a = &fgOutApp{AppID: id, Name: meta.Name, Category: meta.Category}
						if a.Name == "" {
							a.Name = id
						}
						byApp[id] = a
					}
					a.ActiveSec += uint64(sec)
				}
			}
		}
	}
	sort.SliceStable(sessions, func(i, j int) bool {
		if sessions[i].Start != sessions[j].Start {
			return sessions[i].Start < sessions[j].Start
		}
		return sessions[i].MAC < sessions[j].MAC
	})
	apps := make([]fgOutApp, 0, len(byApp))
	for _, a := range byApp {
		a.FgMin = math.Round(float64(a.FgSec)/60*10) / 10
		apps = append(apps, *a)
	}
	sort.Slice(apps, func(i, j int) bool {
		if apps[i].FgSec != apps[j].FgSec {
			return apps[i].FgSec > apps[j].FgSec
		}
		if apps[i].ActiveSec != apps[j].ActiveSec {
			return apps[i].ActiveSec > apps[j].ActiveSec
		}
		return apps[i].AppID < apps[j].AppID
	})
	out := map[string]interface{}{
		"ok": true, "mac": mac, "days": days, "since": since, "now": now.Unix(),
		"sessions": sessions, "by_app": apps, "total_fg_sec": total,
		"merge_gap_sec": int(fgMergeGap / time.Second), "keep_days": fgKeepDays + 1,
	}
	if mac != "" {
		views := m.views(now, activityNow().Level, powerCurrent("app_usage"))
		if v, ok := views[mac]; ok {
			out["current"] = v
		} else {
			out["current"] = nil
		}
	}
	return out
}
