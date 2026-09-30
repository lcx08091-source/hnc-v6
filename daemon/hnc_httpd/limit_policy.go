// limit_policy.go — 设备流量配额(quota) + 分时段限速(schedule) 控制器。
//
// 设计要点
//   - 配置: data/limit_policies.json(本文件独占写, tmp+rename)。
//     {"version":1,"devices":{"<mac>":{"quota":{...},"schedule":[...]}}}
//   - 运行状态: data/limit_ctl_state.json(持久, 重启后按其重算, 不丢"手动基线")。
//   - 生效: 与 WebUI 完全同一条路径 —— actionRuleSet / actionRuleClear /
//     actionBLAdd / actionBLDel(→ apply_device_rule.sh → tc/iptables/rules.json),
//     并持有 s.actionMu, 与用户动作严格串行, tc/iptables/rules.json 三者一致。
//   - 手动基线(base): 控制器不改 rules.json 以外的"真相"。每轮读 rules.json 的
//     当前规则(obs); 若 obs 与"控制器上次施加后观测到的"(LastObserved)不同,
//     说明有外部修改(用户 rule_set / 模板 / 清理脚本), 采纳 obs 为新的 base。
//     覆盖(配额/时段)结束时恢复到 base。
//   - 幂等: 只有 desired(=effectiveRule(...)) 与 LastDesired 不同才调 apply。
//   - 优先级: block(任何来源的封锁) > quota > schedule > manual base。
//     · 手动黑名单 reason=block; 配额 action=block reason=quota; 时段 block reason=schedule
//     · 配额 throttle: 在下层(时段/手动)结果上取更严(非 0 的较小值), 不会放宽
//     · 时段窗口: 替换手动限速(down/up=0 表示该时段不限速)
//     · 被封锁时限速字段保持 base 值(进/出封锁只动 iptables, 不动 tc)
//   - 用量: 每 60s 对 devices.json 的 rx_bytes/tx_bytes(HNC_STATS iptables 累计
//     计数器, 与 /api/stats legacy、RateLoop 同源)做差分累加; 计数器回退
//     (full_restore -F / 设备换 IP 重建规则)按"复位后新增 = cur"计。
//     另每 15 分钟用 run/stats.YYYYMMDD.jsonl(DPI 15min 增量, /api/usage_month
//     同源)求同窗口合计作为下限: used = max(自有累加, DPI 合计),
//     补上 httpd 停机期间漏掉的量, 两者取 max 不会重复计。
//   - 周期: 日 = 本地零点; 月 = 与本月流量共用的结算日 billing_day(缺省 1, 超出当月
//     天数取月末)。本地时区由 main.go 的 tzlocal 设置到 time.Local。
//   - 模拟设备(MAC 前缀 02:5e:00)永不进入 apply / 用量统计。
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hnc.io/dpid/alert"
)

const (
	limitSimPrefix     = "02:5e:00" // 模拟设备(sim.go), 永不进 tc/iptables
	bytesPerGB         = 1 << 30    // 与 WebUI 月度配额换算(1073741824)一致
	quotaWarnPct       = 80
	limitHistEvery     = 15 * time.Minute
	limitStatePersist  = 5 * time.Minute
	maxScheduleWindows = 16
	defThrottleDownKb  = 1000
	defThrottleUpKb    = 500
	limitAuditTID      = "limitctl"
)

// ── 纯数据类型 ────────────────────────────────────────────────

// limitRule 一台设备在 tc/iptables 层的规则。kbit, 0 = 该方向不限速。
type limitRule struct {
	DownKbit int  `json:"down_kbit"`
	UpKbit   int  `json:"up_kbit"`
	Blocked  bool `json:"blocked"`
}

func (r limitRule) sameLimit(o limitRule) bool {
	return r.DownKbit == o.DownKbit && r.UpKbit == o.UpKbit
}

type schedWindow struct {
	Days     []int   `json:"days"` // 0=周日 … 6=周六; 空 = 每天。跨零点窗口按"开始那天"匹配
	Start    string  `json:"start"`
	End      string  `json:"end"`
	DownMbps float64 `json:"down_mbps"`
	UpMbps   float64 `json:"up_mbps"`
	Block    bool    `json:"block"`
}

type quotaPolicy struct {
	DailyGB          float64 `json:"daily_gb"`
	MonthlyGB        float64 `json:"monthly_gb"`
	Action           string  `json:"action"` // throttle | block
	ThrottleDownMbps float64 `json:"throttle_mbps"`
	ThrottleUpMbps   float64 `json:"throttle_up_mbps"`
}

type devicePolicy struct {
	Quota    *quotaPolicy  `json:"quota,omitempty"`
	Schedule []schedWindow `json:"schedule,omitempty"`
}

type policyFile struct {
	Version int                      `json:"version"`
	Devices map[string]*devicePolicy `json:"devices"`
}

// quotaVerdict effectiveRule 的配额输入。
type quotaVerdict struct {
	Exceeded         bool
	Action           string
	ThrottleDownKbit int
	ThrottleUpKbit   int
}

type effectiveResult struct {
	Rule        limitRule
	Reason      string // manual | schedule | quota | block
	WindowIndex int    // 当前命中的时段下标, -1 = 无
}

// ── 纯函数 ────────────────────────────────────────────────────

func mbpsToKbit(m float64) int {
	if m <= 0 || math.IsNaN(m) || math.IsInf(m, 0) {
		return 0
	}
	k := int(math.Round(m * 1000))
	if k < minRateKbit {
		k = minRateKbit
	}
	if k > maxRateKbit {
		k = maxRateKbit
	}
	return k
}

// stricterKbit 取更严的限速(0 = 不限)。
func stricterKbit(a, b int) int {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case a < b:
		return a
	}
	return b
}

func hhmmToMin(s string) (int, bool) {
	if !hhmmRe.MatchString(s) {
		return 0, false
	}
	h, _ := strconv.Atoi(s[:2])
	m, _ := strconv.Atoi(s[3:])
	return h*60 + m, true
}

func windowDayOK(days []int, wd int) bool {
	if len(days) == 0 {
		return true
	}
	for _, d := range days {
		if d == wd {
			return true
		}
	}
	return false
}

// activeWindow 返回 now 命中的第一个窗口下标, 无则 -1。
// start==end 视为该日全天; start>end 为跨零点窗口(属于开始那天)。
func activeWindow(ws []schedWindow, now time.Time) int {
	m := now.Hour()*60 + now.Minute()
	wd := int(now.Weekday())
	yd := (wd + 6) % 7
	for i, w := range ws {
		s, ok1 := hhmmToMin(w.Start)
		e, ok2 := hhmmToMin(w.End)
		if !ok1 || !ok2 {
			continue
		}
		switch {
		case s == e:
			if windowDayOK(w.Days, wd) {
				return i
			}
		case s < e:
			if windowDayOK(w.Days, wd) && m >= s && m < e {
				return i
			}
		default: // 跨零点
			if (windowDayOK(w.Days, wd) && m >= s) || (windowDayOK(w.Days, yd) && m < e) {
				return i
			}
		}
	}
	return -1
}

// effectiveRule 纯函数: 由手动基线 + 配额判定 + 时段 + 时间算出期望规则。
// 优先级 block > quota > schedule > manual(见文件头)。
func effectiveRule(base limitRule, q quotaVerdict, ws []schedWindow, now time.Time) effectiveResult {
	idx := activeWindow(ws, now)
	r := limitRule{DownKbit: base.DownKbit, UpKbit: base.UpKbit}
	reason := "manual"
	schedBlock := false
	if idx >= 0 {
		w := ws[idx]
		r.DownKbit, r.UpKbit = mbpsToKbit(w.DownMbps), mbpsToKbit(w.UpMbps)
		schedBlock = w.Block
		reason = "schedule"
	}
	quotaBlock := false
	if q.Exceeded {
		if q.Action == "block" {
			quotaBlock = true
		} else {
			r.DownKbit = stricterKbit(r.DownKbit, q.ThrottleDownKbit)
			r.UpKbit = stricterKbit(r.UpKbit, q.ThrottleUpKbit)
		}
		reason = "quota"
	}
	switch {
	case base.Blocked:
		reason = "block"
	case quotaBlock:
		reason = "quota"
	case schedBlock:
		reason = "schedule"
	}
	if base.Blocked || quotaBlock || schedBlock {
		// 封锁期间限速字段保持 base: 进/出封锁只动 iptables 黑名单, 不碰 tc。
		r = limitRule{DownKbit: base.DownKbit, UpKbit: base.UpKbit, Blocked: true}
	}
	return effectiveResult{Rule: r, Reason: reason, WindowIndex: idx}
}

// evalQuota 返回 state(ok|warn|exceeded)、是否超限、超限周期(daily|monthly)。
func evalQuota(q *quotaPolicy, usedDay, usedMonth uint64) (string, bool, string) {
	if q == nil {
		return "ok", false, ""
	}
	dayLim := uint64(q.DailyGB * bytesPerGB)
	monLim := uint64(q.MonthlyGB * bytesPerGB)
	if dayLim > 0 && usedDay >= dayLim {
		return "exceeded", true, "daily"
	}
	if monLim > 0 && usedMonth >= monLim {
		return "exceeded", true, "monthly"
	}
	if (dayLim > 0 && usedDay*100 >= dayLim*quotaWarnPct) ||
		(monLim > 0 && usedMonth*100 >= monLim*quotaWarnPct) {
		return "warn", false, ""
	}
	return "ok", false, ""
}

func quotaVerdictOf(q *quotaPolicy, exceeded bool) quotaVerdict {
	if q == nil || !exceeded {
		return quotaVerdict{}
	}
	v := quotaVerdict{Exceeded: true, Action: q.Action}
	v.ThrottleDownKbit = mbpsToKbit(q.ThrottleDownMbps)
	v.ThrottleUpKbit = mbpsToKbit(q.ThrottleUpMbps)
	if v.ThrottleDownKbit == 0 {
		v.ThrottleDownKbit = defThrottleDownKb
	}
	if v.ThrottleUpKbit == 0 {
		v.ThrottleUpKbit = defThrottleUpKb
	}
	return v
}

func daysIn(y int, m time.Month, loc *time.Location) int {
	return time.Date(y, m+1, 0, 0, 0, 0, 0, loc).Day()
}

// billingPeriodStart 当前计费月起点(本地零点)。billingDay 超出当月天数取月末。
func billingPeriodStart(now time.Time, billingDay int) time.Time {
	if billingDay < 1 || billingDay > 31 {
		billingDay = 1
	}
	loc := now.Location()
	y, m := now.Year(), now.Month()
	d := billingDay
	if n := daysIn(y, m, loc); d > n {
		d = n
	}
	start := time.Date(y, m, d, 0, 0, 0, 0, loc)
	if now.Before(start) {
		py, pm := y, m-1
		if pm < time.January {
			py, pm = y-1, time.December
		}
		d = billingDay
		if n := daysIn(py, pm, loc); d > n {
			d = n
		}
		start = time.Date(py, pm, d, 0, 0, 0, 0, loc)
	}
	return start
}

func dayStart(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
}

func limitSkipMAC(mac string) bool { return strings.HasPrefix(strings.ToLower(mac), limitSimPrefix) }

// ── 用量累加(计数器差分, 处理复位) ──────────────────────────

type usageAcc struct {
	HavePrev   bool   `json:"have_prev"`
	PrevRx     int64  `json:"prev_rx"`
	PrevTx     int64  `json:"prev_tx"`
	DayKey     string `json:"day_key"`
	DayBytes   uint64 `json:"day_bytes"`
	MonthKey   string `json:"month_key"`
	MonthBytes uint64 `json:"month_bytes"`
}

// rollover 进入新周期时清零对应累加。
func (u *usageAcc) rollover(dayKey, monthKey string) {
	if u.DayKey != dayKey {
		u.DayKey, u.DayBytes = dayKey, 0
	}
	if u.MonthKey != monthKey {
		u.MonthKey, u.MonthBytes = monthKey, 0
	}
}

// add 喂入一次累计计数器读数。首次只建基线; 计数器回退视为复位, 复位后
// 新增 = 当前值。
func (u *usageAcc) add(rx, tx int64, dayKey, monthKey string) {
	u.rollover(dayKey, monthKey)
	if rx < 0 || tx < 0 {
		return
	}
	if !u.HavePrev {
		u.HavePrev, u.PrevRx, u.PrevTx = true, rx, tx
		return
	}
	d := func(cur, prev int64) uint64 {
		if cur >= prev {
			return uint64(cur - prev)
		}
		return uint64(cur) // 复位
	}
	delta := d(rx, u.PrevRx) + d(tx, u.PrevTx)
	u.PrevRx, u.PrevTx = rx, tx
	u.DayBytes += delta
	u.MonthBytes += delta
}

// ── 控制器 ────────────────────────────────────────────────────

type ctlDevState struct {
	Adopted      bool      `json:"adopted"`
	Base         limitRule `json:"base"`
	LastDesired  limitRule `json:"last_desired"`
	LastObserved limitRule `json:"last_observed"`
	Usage        usageAcc  `json:"usage"`
	AlertedDay   string    `json:"alerted_day,omitempty"`
	AlertedMonth string    `json:"alerted_month,omitempty"`
	LastErr      string    `json:"last_err,omitempty"`
}

type ctlStateFile struct {
	Version int                     `json:"version"`
	Devices map[string]*ctlDevState `json:"devices"`
}

// limitView 发布给 /api/devices 的每设备视图。
type limitView struct {
	Quota     map[string]interface{} `json:"quota,omitempty"`
	Schedule  map[string]interface{} `json:"schedule,omitempty"`
	Effective map[string]interface{} `json:"effective"`
}

type devObs struct {
	online bool
	rx, tx int64
	hasCnt bool
}

type limitCtl struct {
	hncDir   string
	actionMu sync.Locker // = &server.actionMu; 锁序: actionMu → mu

	mu       sync.Mutex
	policies map[string]*devicePolicy
	st       ctlStateFile
	histDay  map[string]uint64
	histMon  map[string]uint64
	histAt   time.Time
	histKey  string
	dirty    bool
	savedAt  time.Time
	logged   map[string]string

	viewMu sync.RWMutex
	view   map[string]limitView

	poke chan struct{}
	// apply 把 obs → to 的差异落到系统; 测试注入。
	apply func(mac string, from, to limitRule) error
}

func newLimitCtl(hncDir string, actionMu sync.Locker) *limitCtl {
	c := &limitCtl{
		hncDir:   hncDir,
		actionMu: actionMu,
		policies: map[string]*devicePolicy{},
		st:       ctlStateFile{Version: 1, Devices: map[string]*ctlDevState{}},
		logged:   map[string]string{},
		view:     map[string]limitView{},
		poke:     make(chan struct{}, 1),
	}
	c.apply = c.applyViaActions
	c.load()
	return c
}

func (c *limitCtl) policyPath() string { return filepath.Join(c.hncDir, "data", "limit_policies.json") }
func (c *limitCtl) statePath() string  { return filepath.Join(c.hncDir, "data", "limit_ctl_state.json") }

func (c *limitCtl) load() {
	if b, err := os.ReadFile(c.policyPath()); err == nil {
		var pf policyFile
		if json.Unmarshal(b, &pf) == nil && pf.Devices != nil {
			for k, v := range pf.Devices {
				if v != nil {
					c.policies[strings.ToLower(k)] = v
				}
			}
		} else {
			log.Printf("limitctl: %s malformed, ignoring", c.policyPath())
		}
	}
	if b, err := os.ReadFile(c.statePath()); err == nil {
		var sf ctlStateFile
		if json.Unmarshal(b, &sf) == nil && sf.Devices != nil {
			c.st = sf
		}
	}
}

func (c *limitCtl) savePoliciesLocked() error {
	return writeJSONAtomic(c.policyPath(), policyFile{Version: 1, Devices: c.policies})
}

func (c *limitCtl) saveStateLocked(now time.Time, force bool) {
	if !force && !c.dirty && now.Sub(c.savedAt) < limitStatePersist {
		return
	}
	if err := writeJSONAtomic(c.statePath(), c.st); err != nil {
		log.Printf("limitctl: save state: %v", err)
		return
	}
	c.dirty, c.savedAt = false, now
}

// Poke 让控制器尽快跑一轮(非阻塞)。nil 安全。
func (c *limitCtl) Poke() {
	if c == nil {
		return
	}
	select {
	case c.poke <- struct{}{}:
	default:
	}
}

// Loop 启动即跑一轮(重启后按持久状态重算), 之后对齐到每分钟 +1s。
func (c *limitCtl) Loop(stop <-chan struct{}) {
	if c == nil {
		return
	}
	c.tick(time.Now())
	for {
		now := time.Now()
		next := now.Truncate(time.Minute).Add(time.Minute + time.Second)
		t := time.NewTimer(next.Sub(now))
		select {
		case <-stop:
			t.Stop()
			return
		case <-t.C:
		case <-c.poke:
			t.Stop()
			time.Sleep(300 * time.Millisecond) // 合并连发 poke
		}
		c.tick(time.Now())
	}
}

// readDevices 读 devices.json: 在线(有 IP)+ 累计计数器。
func (c *limitCtl) readDevices() (map[string]devObs, bool) {
	b, err := os.ReadFile(filepath.Join(c.hncDir, "data", "devices.json"))
	if err != nil {
		return map[string]devObs{}, false
	}
	var m map[string]map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return map[string]devObs{}, false
	}
	out := make(map[string]devObs, len(m))
	for mac, d := range m {
		if d == nil {
			continue
		}
		o := devObs{online: asString(d["ip"]) != ""}
		rx, ok1 := toInt64(d["rx_bytes"])
		tx, ok2 := toInt64(d["tx_bytes"])
		if ok1 && ok2 {
			o.rx, o.tx, o.hasCnt = rx, tx, true
		}
		out[strings.ToLower(mac)] = o
	}
	return out, true
}

func numOf(v interface{}) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f
	case bool:
		return 0
	}
	return 0
}

// readObserved 读 rules.json 当前规则 + billing_day。读/解析失败返回 ok=false
// (调用方必须跳过 reconcile, 否则会把"读不到"误当"外部清空")。
func readObserved(hncDir string) (map[string]limitRule, int, bool) {
	b, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json"))
	if err != nil {
		return nil, 1, false
	}
	var root map[string]interface{}
	if json.Unmarshal(b, &root) != nil {
		return nil, 1, false
	}
	out := map[string]limitRule{}
	if devs, ok := root["devices"].(map[string]interface{}); ok {
		for mac, raw := range devs {
			d, _ := raw.(map[string]interface{})
			if d == nil {
				continue
			}
			r := limitRule{}
			if en, _ := d["limit_enabled"].(bool); en || asString(d["limit_enabled"]) == "true" {
				r.DownKbit = mbpsToKbit(numOf(d["down_mbps"]))
				r.UpKbit = mbpsToKbit(numOf(d["up_mbps"]))
			}
			out[strings.ToLower(mac)] = r
		}
	}
	if bl, ok := root["blacklist"].([]interface{}); ok {
		for _, v := range bl {
			if s := strings.ToLower(strings.TrimSpace(asString(v))); s != "" {
				r := out[s]
				r.Blocked = true
				out[s] = r
			}
		}
	}
	// v5.19: 结算日与「本月流量」共用一处设置(data/phone_usage_config.json);
	// 旧版 rules.json 顶层 billing_day 仅作兜底
	bd := puLoadConfig(hncDir).BillingDay
	if bd < 1 || bd > 28 {
		bd = int(numOf(root["billing_day"]))
	}
	if bd < 1 || bd > 31 {
		bd = 1
	}
	return out, bd, true
}

// sumStatsHistory 汇总 run/stats.YYYYMMDD.jsonl 在 [from,to) 的每 MAC tx+rx。
func sumStatsHistory(hncDir string, from, to time.Time) map[string]uint64 {
	out := map[string]uint64{}
	for _, dk := range dayFileKeys(from, to) {
		f, err := os.Open(filepath.Join(hncDir, "run", "stats."+dk+".jsonl"))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			var row struct {
				T   int64  `json:"t"`
				MAC string `json:"mac"`
				TX  uint64 `json:"tx"`
				RX  uint64 `json:"rx"`
			}
			if json.Unmarshal(sc.Bytes(), &row) != nil || row.MAC == "" {
				continue
			}
			if row.T < from.Unix() || row.T >= to.Unix() {
				continue
			}
			out[strings.ToLower(row.MAC)] += row.TX + row.RX
		}
		f.Close()
	}
	return out
}

func maxU(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func (c *limitCtl) devState(mac string) *ctlDevState {
	s := c.st.Devices[mac]
	if s == nil {
		s = &ctlDevState{}
		c.st.Devices[mac] = s
	}
	return s
}

func (c *limitCtl) logOnce(mac, msg string) {
	if c.logged[mac] != msg {
		c.logged[mac] = msg
		if msg != "" {
			log.Printf("limitctl: %s: %s", mac, msg)
		}
	}
}

// tick 一轮: 用量累加 → 配额判定 → 期望规则 → 必要时 apply → 发布视图。
func (c *limitCtl) tick(now time.Time) {
	if c.actionMu != nil {
		c.actionMu.Lock()
		defer c.actionMu.Unlock()
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	devs, devsOK := c.readDevices()
	obs, billingDay, rulesOK := readObserved(c.hncDir)

	ds := dayStart(now)
	ms := billingPeriodStart(now, billingDay)
	dayKey, monKey := ds.Format("2006-01-02"), ms.Format("2006-01-02")

	// 1) 用量(所有非模拟在线设备都累加, 之后才设配额也有当日/当月数据)
	if devsOK {
		for mac, o := range devs {
			if limitSkipMAC(mac) || !o.hasCnt {
				continue
			}
			c.devState(mac).Usage.add(o.rx, o.tx, dayKey, monKey) // 用量按 limitStatePersist 周期落盘
		}
	}
	for _, s := range c.st.Devices {
		s.Usage.rollover(dayKey, monKey)
	}
	// 2) 历史下限(DPI 增量文件), 15 分钟 / 周期切换时刷新
	hk := dayKey + "|" + monKey
	if c.histKey != hk || now.Sub(c.histAt) >= limitHistEvery || now.Before(c.histAt) {
		if len(c.policies) > 0 {
			c.histDay = sumStatsHistory(c.hncDir, ds, now.Add(time.Second))
			c.histMon = sumStatsHistory(c.hncDir, ms, now.Add(time.Second))
		} else {
			c.histDay, c.histMon = nil, nil
		}
		c.histAt, c.histKey = now, hk
	}

	// 3) 需要 reconcile 的 MAC: 有策略的 + 仍有未恢复覆盖的
	macs := map[string]bool{}
	for m := range c.policies {
		macs[m] = true
	}
	for m, s := range c.st.Devices {
		if s.Adopted && s.LastDesired != s.Base {
			macs[m] = true
		}
	}
	keys := make([]string, 0, len(macs))
	for m := range macs {
		keys = append(keys, m)
	}
	sort.Strings(keys)

	view := map[string]limitView{}
	for _, mac := range keys {
		pol := c.policies[mac]
		sim := limitSkipMAC(mac)
		var s *ctlDevState
		if sim {
			s = &ctlDevState{} // 模拟设备: 只算视图, 不落状态、不 apply
		} else {
			s = c.devState(mac)
		}
		if rulesOK {
			o := obs[mac]
			if !s.Adopted || o != s.LastObserved {
				// 首次 / 外部修改(用户 rule_set、bl_add、模板、清理): 采纳为新基线
				s.Adopted, s.Base, s.LastDesired, s.LastObserved = true, o, o, o
				c.dirty = true
			}
		}
		var q *quotaPolicy
		var ws []schedWindow
		if pol != nil {
			q, ws = pol.Quota, pol.Schedule
		}
		usedDay := maxU(s.Usage.DayBytes, c.histDay[mac])
		usedMon := maxU(s.Usage.MonthBytes, c.histMon[mac])
		if s.Usage.DayKey != dayKey {
			usedDay = c.histDay[mac]
		}
		if s.Usage.MonthKey != monKey {
			usedMon = c.histMon[mac]
		}
		qState, exceeded, period := evalQuota(q, usedDay, usedMon)
		eff := effectiveRule(s.Base, quotaVerdictOf(q, exceeded), ws, now)

		if exceeded && !sim {
			c.maybeAlert(mac, s, q, period, dayKey, monKey, usedDay, usedMon, now)
		}

		if !sim && rulesOK && s.Adopted && eff.Rule != s.LastDesired {
			c.reconcile(mac, s, eff.Rule, devs[mac].online)
		}

		v := limitView{Effective: effView(eff)}
		if q != nil {
			v.Quota = map[string]interface{}{
				"daily_gb":         q.DailyGB,
				"monthly_gb":       q.MonthlyGB,
				"action":           q.Action,
				"throttle_mbps":    q.ThrottleDownMbps,
				"throttle_up_mbps": q.ThrottleUpMbps,
				"used_today":       usedDay,
				"used_month":       usedMon,
				"state":            qState,
				"exceeded_period":  period,
				"applied":          exceeded && eff.Reason == "quota",
				"billing_day":      billingDay,
				"month_start":      ms.Unix(),
			}
		}
		if len(ws) > 0 {
			v.Schedule = map[string]interface{}{
				"windows":             ws,
				"active_window_index": eff.WindowIndex,
			}
		}
		if s.LastErr != "" {
			v.Effective["apply_error"] = s.LastErr
		}
		view[mac] = v
	}
	c.saveStateLocked(now, false)

	c.viewMu.Lock()
	c.view = view
	c.viewMu.Unlock()
}

func kbitToMbps(k int) float64 { return float64(k) / 1000 }

func effView(e effectiveResult) map[string]interface{} {
	return map[string]interface{}{
		"down_mbps": kbitToMbps(e.Rule.DownKbit),
		"up_mbps":   kbitToMbps(e.Rule.UpKbit),
		"blocked":   e.Rule.Blocked,
		"reason":    e.Reason,
	}
}

// reconcile 把 desired 落地。离线设备只做黑名单变化(apply_device_rule.sh limit
// 需要在线 IP), 限速部分待上线后下一轮再做。无论成败都刷新 LastObserved,
// 防止"半生效"被下一轮误判为外部修改。调用方持 actionMu + mu。
func (c *limitCtl) reconcile(mac string, s *ctlDevState, desired limitRule, online bool) {
	cur := s.LastObserved
	target := desired
	partial := false
	if !online && !cur.sameLimit(desired) {
		target = limitRule{DownKbit: cur.DownKbit, UpKbit: cur.UpKbit, Blocked: desired.Blocked}
		partial = true
	}
	var err error
	if target != cur {
		err = c.apply(mac, cur, target)
	}
	if o, _, ok := readObserved(c.hncDir); ok {
		s.LastObserved = o[mac]
	} else if err == nil {
		s.LastObserved = target
	}
	c.dirty = true
	switch {
	case err != nil:
		s.LastErr = err.Error()
		c.logOnce(mac, "apply failed: "+s.LastErr)
	case partial:
		s.LastErr = ""
		c.logOnce(mac, "device offline; limit change pending")
	default:
		s.LastErr = ""
		s.LastDesired = desired
		c.logOnce(mac, "")
		log.Printf("limitctl: %s applied down=%dkbit up=%dkbit blocked=%v", mac, desired.DownKbit, desired.UpKbit, desired.Blocked)
	}
}

func kbitRateStr(k int) string {
	if k <= 0 {
		return "0"
	}
	return strconv.Itoa(k) + "kbit"
}

// applyViaActions 与 WebUI 同一条链路(调用方已持 actionMu)。
// 顺序: 要封 → 先封再改速; 要解封 → 先改速再解封。
func (c *limitCtl) applyViaActions(mac string, from, to limitRule) error {
	p := map[string]string{"mac": mac}
	run := func(name string, f func(string, map[string]string) actionResp, params map[string]string) error {
		r := f(c.hncDir, params)
		auditLog(c.hncDir, limitAuditTID, name, params, map[bool]string{true: "ok", false: "error"}[r.OK], r.Error+" "+r.Detail)
		if !r.OK {
			return fmt.Errorf("%s: %s %s", name, r.Error, strings.TrimSpace(r.Detail))
		}
		return nil
	}
	setLimit := func() error {
		if from.sameLimit(to) {
			return nil
		}
		if to.DownKbit == 0 && to.UpKbit == 0 {
			return run("rule_clear", actionRuleClear, p)
		}
		return run("rule_set", actionRuleSet, map[string]string{
			"mac": mac, "rate_down": kbitRateStr(to.DownKbit), "rate_up": kbitRateStr(to.UpKbit)})
	}
	if to.Blocked && !from.Blocked {
		if err := run("bl_add", actionBLAdd, p); err != nil {
			return err
		}
		return setLimit()
	}
	if err := setLimit(); err != nil {
		return err
	}
	if !to.Blocked && from.Blocked {
		return run("bl_del", actionBLDel, p)
	}
	return nil
}

func (c *limitCtl) maybeAlert(mac string, s *ctlDevState, q *quotaPolicy, period, dayKey, monKey string, usedDay, usedMon uint64, now time.Time) {
	key := dayKey
	alerted := &s.AlertedDay
	used, limGB := usedDay, q.DailyGB
	label := "今日"
	if period == "monthly" {
		key, alerted, used, limGB, label = monKey, &s.AlertedMonth, usedMon, q.MonthlyGB, "本计费月"
	}
	if *alerted == key {
		return
	}
	*alerted = key
	c.dirty = true
	acfg := alert.NewConfig(c.hncDir)
	if !alert.LoadConfig(acfg.AlertsConfigPath).Enabled {
		return
	}
	act := "限速"
	if q.Action == "block" {
		act = "断网"
	}
	a := alert.Alert{
		ID:     fmt.Sprintf("device_quota_%s_%s_%s", strings.ReplaceAll(mac, ":", ""), period, strings.ReplaceAll(key, "-", "")),
		Ts:     now.Unix(),
		Kind:   "device_quota",
		MAC:    mac,
		Detail: fmt.Sprintf("%s %s流量 %.2f GB 已超出配额 %.2f GB, 已自动%s(下个周期自动恢复)", mac, label, float64(used)/bytesPerGB, limGB, act),
		Extra: map[string]interface{}{
			"period":      period,
			"period_key":  key,
			"used_bytes":  used,
			"quota_bytes": uint64(limGB * bytesPerGB),
			"action":      q.Action,
		},
	}
	b, err := json.Marshal(a)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(acfg.AlertsJSONLPath), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(acfg.AlertsJSONLPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("limitctl: alert append: %v", err)
		return
	}
	_, _ = f.Write(append(b, '\n'))
	f.Close()
}

// annotateDevices 把视图字段并入 /api/devices 每行(nil 安全)。
// 无策略的设备按行内 rules 字段给出 effective(reason=manual|block)。
func (c *limitCtl) annotateDevices(rows []map[string]interface{}) {
	if c == nil {
		return
	}
	c.viewMu.RLock()
	defer c.viewMu.RUnlock()
	for _, row := range rows {
		mac := strings.ToLower(asString(row["mac"]))
		if v, ok := c.view[mac]; ok {
			row["quota"] = v.Quota
			row["schedule"] = v.Schedule
			row["effective"] = v.Effective
			continue
		}
		row["quota"] = nil
		row["schedule"] = nil
		blocked := asString(row["status"]) == "blocked"
		var dn, up float64
		if en, _ := row["limit_enabled"].(bool); en {
			dn, up = numOf(row["down_mbps"]), numOf(row["up_mbps"])
		}
		reason := "manual"
		if blocked {
			reason = "block"
		}
		row["effective"] = map[string]interface{}{"down_mbps": dn, "up_mbps": up, "blocked": blocked, "reason": reason}
	}
}

// ── actions ──────────────────────────────────────────────────

func parseNonNegFloat(s string, max float64) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > max {
		return 0, fmt.Errorf("must be a number in [0, %g]", max)
	}
	return f, nil
}

func validRateMbps(f float64) bool {
	return f == 0 || (f*1000 >= minRateKbit && f*1000 <= maxRateKbit)
}

func policyMAC(hncDir string, p map[string]string) (string, *actionResp) {
	mac := strings.ToLower(strings.TrimSpace(p["mac"]))
	if !macRE.MatchString(mac) {
		return "", &actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	if isProtectedMAC(hncDir, mac) {
		return "", &actionResp{OK: false, Error: "protected mac", Detail: "cannot set policy on host/broadcast/null mac"}
	}
	return mac, nil
}

// actionQuotaSet params: mac, daily_gb, monthly_gb, action(throttle|block),
// throttle_mbps(默认 1), throttle_up_mbps(可选, 默认 throttle_mbps/2)。
func (c *limitCtl) actionQuotaSet(p map[string]string) actionResp {
	if c == nil {
		return actionResp{OK: false, Error: "unavailable"}
	}
	mac, bad := policyMAC(c.hncDir, p)
	if bad != nil {
		return *bad
	}
	daily, err := parseNonNegFloat(p["daily_gb"], 1e6)
	if err != nil {
		return actionResp{OK: false, Error: "bad params", Detail: "daily_gb " + err.Error()}
	}
	monthly, err := parseNonNegFloat(p["monthly_gb"], 1e7)
	if err != nil {
		return actionResp{OK: false, Error: "bad params", Detail: "monthly_gb " + err.Error()}
	}
	if daily == 0 && monthly == 0 {
		return actionResp{OK: false, Error: "bad params", Detail: "at least one of daily_gb/monthly_gb must be > 0"}
	}
	act := strings.TrimSpace(p["action"])
	if act == "" {
		act = "throttle"
	}
	if act != "throttle" && act != "block" {
		return actionResp{OK: false, Error: "bad params", Detail: "action must be throttle|block"}
	}
	tdn, err := parseNonNegFloat(p["throttle_mbps"], 1e7)
	if err != nil || !validRateMbps(tdn) {
		return actionResp{OK: false, Error: "bad params", Detail: "throttle_mbps must be 0 or 0.064-10000"}
	}
	tup, err := parseNonNegFloat(p["throttle_up_mbps"], 1e7)
	if err != nil || !validRateMbps(tup) {
		return actionResp{OK: false, Error: "bad params", Detail: "throttle_up_mbps must be 0 or 0.064-10000"}
	}
	if tdn == 0 {
		tdn = float64(defThrottleDownKb) / 1000
		if tup == 0 {
			tup = float64(defThrottleUpKb) / 1000
		}
	}
	if tup == 0 {
		tup = math.Max(tdn/2, float64(minRateKbit)/1000)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pol := c.policies[mac]
	if pol == nil {
		pol = &devicePolicy{}
	}
	nq := &quotaPolicy{DailyGB: daily, MonthlyGB: monthly, Action: act, ThrottleDownMbps: tdn, ThrottleUpMbps: tup}
	old := pol.Quota
	pol.Quota = nq
	c.policies[mac] = pol
	if err := c.savePoliciesLocked(); err != nil {
		pol.Quota = old
		if old == nil && len(pol.Schedule) == 0 {
			delete(c.policies, mac)
		}
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	c.Poke()
	return actionResp{OK: true, Detail: "quota saved"}
}

func (c *limitCtl) actionQuotaClear(p map[string]string) actionResp {
	return c.clearPolicy(p, func(d *devicePolicy) { d.Quota = nil })
}

func (c *limitCtl) actionScheduleClear(p map[string]string) actionResp {
	return c.clearPolicy(p, func(d *devicePolicy) { d.Schedule = nil })
}

func (c *limitCtl) clearPolicy(p map[string]string, f func(*devicePolicy)) actionResp {
	if c == nil {
		return actionResp{OK: false, Error: "unavailable"}
	}
	mac := strings.ToLower(strings.TrimSpace(p["mac"]))
	if !macRE.MatchString(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pol := c.policies[mac]
	if pol == nil {
		return actionResp{OK: true, Detail: "nothing to clear"}
	}
	saved := *pol
	f(pol)
	if pol.Quota == nil && len(pol.Schedule) == 0 {
		delete(c.policies, mac)
	}
	if err := c.savePoliciesLocked(); err != nil {
		*pol = saved
		c.policies[mac] = pol
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	c.Poke() // 下一轮恢复手动基线
	return actionResp{OK: true, Detail: "cleared"}
}

// parseWindows 校验 schedule_set 的 windows JSON。
func parseWindows(raw string) ([]schedWindow, error) {
	var ws []schedWindow
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ws); err != nil {
		return nil, fmt.Errorf("windows must be a JSON array: %v", err)
	}
	if len(ws) == 0 {
		return nil, fmt.Errorf("windows empty (use schedule_clear)")
	}
	if len(ws) > maxScheduleWindows {
		return nil, fmt.Errorf("at most %d windows", maxScheduleWindows)
	}
	for i := range ws {
		w := &ws[i]
		if !hhmmRe.MatchString(w.Start) || !hhmmRe.MatchString(w.End) {
			return nil, fmt.Errorf("window %d: start/end must be HH:MM", i)
		}
		seen := map[int]bool{}
		days := []int{}
		for _, d := range w.Days {
			if d < 0 || d > 6 {
				return nil, fmt.Errorf("window %d: days must be 0-6", i)
			}
			if !seen[d] {
				seen[d] = true
				days = append(days, d)
			}
		}
		sort.Ints(days)
		w.Days = days
		if !validRateMbps(w.DownMbps) || !validRateMbps(w.UpMbps) || w.DownMbps < 0 || w.UpMbps < 0 {
			return nil, fmt.Errorf("window %d: down_mbps/up_mbps must be 0 or 0.064-10000", i)
		}
	}
	return ws, nil
}

// actionScheduleSet params: mac, windows(JSON 数组字符串)。
func (c *limitCtl) actionScheduleSet(p map[string]string) actionResp {
	if c == nil {
		return actionResp{OK: false, Error: "unavailable"}
	}
	mac, bad := policyMAC(c.hncDir, p)
	if bad != nil {
		return *bad
	}
	ws, err := parseWindows(p["windows"])
	if err != nil {
		return actionResp{OK: false, Error: "bad params", Detail: err.Error()}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pol := c.policies[mac]
	if pol == nil {
		pol = &devicePolicy{}
	}
	old := pol.Schedule
	pol.Schedule = ws
	c.policies[mac] = pol
	if err := c.savePoliciesLocked(); err != nil {
		pol.Schedule = old
		if old == nil && pol.Quota == nil {
			delete(c.policies, mac)
		}
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	c.Poke()
	return actionResp{OK: true, Detail: "schedule saved"}
}
