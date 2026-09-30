// stats_calibration.go — v5.21 统计校准: 与系统 NetworkStats 对账 + 硬件分流漏计检测
//
// 为什么: HNC 的本机流量(phone_usage.go)来自 /proc/net/dev, 设备流量来自 iptables
// HNC_STATS。高通 IPA 硬件分流(rmnet_ipa0 / ipacm)把热点转发直接在 IPA 里做掉,
// 主机网卡与 iptables 都看不到这部分字节; 而系统 NetworkStatsService 会通过
// TetherOffload HAL / BPF provider 把分流字节补报进 Xt 统计和 UID_TETHERING(-5)。
// 所以系统统计(=设置里「流量使用」)是对账基准:
//
//   1. 每卡本计费周期总量: `dumpsys netstats --full` 的 Xt stats(uid=-1, MOBILE,
//      metered, 按 subId / subscriberId → 卡槽), 与 phone_usage 同窗口比较 → 漂移%。
//   2. 热点(UID_TETHERING)字节: `dumpsys netstats --uid`(只要开机以来明细, 比 --full
//      --uid 轻得多), 与热点口计数(/proc/net/dev)及 iptables FORWARD 计数在同一窗口
//      比较 → 分流漏计%。热点口也少 → 硬件(IPA)分流; 只有 iptables 少 → BPF 软件
//      分流绕过 iptables(热点口计数仍在)。
//
// 窗口对齐: HNC 装机当周期没有完整数据, 对账窗口从「HNC 有完整数据的第一个小时/
// 第一天」开始(calWindowStart); 每卡对比只在窗口起点是零点时做(按天存储)。
//
// 采样: 后台每 15 分钟一次(先 `dumpsys netstats --poll` 让系统把待入账字节落账),
// 同时记一份热点口/iptables 计数快照(内存环, 12 小时), 结果缓存给 /api/phone_usage
// 和 /api/stats_health。use_netstats=off 时不跑 dumpsys。
//
// use_netstats(phone_usage_set):
//   auto   默认: 对账结果放在 calibration 里, 主数值仍是 HNC 自采
//   prefer 系统统计可用时, by_sim[].cycle_used / used_pct 与套餐告警改用系统数值
//          (和系统设置显示一致), 原值保留在 hnc_cycle_used
//   off    不调用 dumpsys

package main

import (
	"bufio"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"context"
)

const (
	calEvery          = 15 * time.Minute
	calFirstDelay     = 90 * time.Second
	calStaleAfter     = 2 * time.Hour
	calSnapKeep       = 12 * time.Hour
	calLiveMin        = time.Hour // 实时窗口至少 1 小时(UID 桶 2 小时, 太短折算误差大)
	calDriftPct       = 5.0
	calGapPct         = 10.0
	calMinCellBytes   = 32 << 20
	calMinLiveTether  = 16 << 20
	calMinCycleTether = 64 << 20
	calCmdTimeout     = 20 * time.Second
	calCmdMaxOut      = 48 << 20
)

// ─── SIM 映射 ─────────────────────────────────────────────────────

// calSub siminfo 一行(比 puSubInfo 多 MCC/MNC/IMSI, 用于 netstats subscriberId 映射)
type calSub struct {
	SubID     int
	SlotIndex int // 0-based, -1 未插
	Name      string
	Carrier   string
	MCC, MNC  string
	IMSI      string
}

func calIntStr(s string) string {
	s = strings.TrimSpace(s)
	if s == "NULL" || s == "null" {
		return ""
	}
	return s
}

// calParseSiminfo `content query --uri content://telephony/siminfo`(不带 projection,
// 各版本列不同: mcc_string/mnc_string A10+, imsi A11+; 旧版只有 int mcc/mnc)
func calParseSiminfo(out string) []calSub {
	var subs []calSub
	for _, line := range strings.Split(out, "\n") {
		kv := puParseContentRow(line)
		if kv == nil {
			continue
		}
		id, err := strconv.Atoi(strings.TrimSpace(kv["_id"]))
		if err != nil {
			continue
		}
		s := calSub{SubID: id, SlotIndex: -1}
		if v, err := strconv.Atoi(strings.TrimSpace(kv["sim_id"])); err == nil {
			s.SlotIndex = v
		}
		s.Name = calIntStr(kv["display_name"])
		s.Carrier = calIntStr(kv["carrier_name"])
		s.MCC = calIntStr(kv["mcc_string"])
		s.MNC = calIntStr(kv["mnc_string"])
		if s.MCC == "" {
			if v := calIntStr(kv["mcc"]); v != "" && v != "0" {
				s.MCC = v
			}
		}
		if s.MNC == "" {
			if v := calIntStr(kv["mnc"]); v != "" && s.MCC != "" {
				if len(v) == 1 {
					v = "0" + v // int 列丢了前导 0
				}
				s.MNC = v
			}
		}
		s.IMSI = calIntStr(kv["imsi"])
		subs = append(subs, s)
	}
	return subs
}

// calPLMNFamily 国内运营商(按 MCC+MNC 前 5 位)
func calPLMNFamily(prefix string) string {
	if len(prefix) < 5 {
		return ""
	}
	switch prefix[:5] {
	case "46000", "46002", "46004", "46007", "46008", "46013":
		return "cmcc"
	case "46001", "46006", "46009", "46010":
		return "cu"
	case "46003", "46005", "46011", "46012":
		return "ct"
	case "46015":
		return "cbn"
	}
	return ""
}

func calNameFamily(name string) string {
	u := strings.ToUpper(name)
	switch {
	case strings.Contains(name, "移动") || strings.Contains(u, "CMCC") || strings.Contains(u, "CHINA MOBILE"):
		return "cmcc"
	case strings.Contains(name, "联通") || strings.Contains(u, "UNICOM") || strings.Contains(u, "CUCC"):
		return "cu"
	case strings.Contains(name, "电信") || strings.Contains(u, "TELECOM") || strings.Contains(u, "CTCC"):
		return "ct"
	case strings.Contains(name, "广电") || strings.Contains(u, "CBN"):
		return "cbn"
	}
	return ""
}

func (s calSub) label() string {
	if s.Name != "" {
		return s.Name
	}
	return s.Carrier
}

// calMapSlot netstats ident → 卡槽(1/2, 0=未知)。依次: subId(A14+) → IMSI 前缀 →
// MCC+MNC → 运营商家族(名字)。多卡同时命中视为无法区分。
func calMapSlot(id nsIdent, subs []calSub) (int, string, string) {
	active := []calSub{}
	for _, s := range subs {
		if s.SlotIndex >= 0 {
			active = append(active, s)
		}
	}
	if id.SubID > 0 {
		for _, s := range subs {
			if s.SubID == id.SubID && s.SlotIndex >= 0 {
				return s.SlotIndex + 1, "sub_id", s.label()
			}
		}
	}
	p := id.Subscriber
	if p == "" {
		return 0, "none", ""
	}
	uniq := func(match func(calSub) bool) (calSub, bool) {
		var hit calSub
		n := 0
		for _, s := range active {
			if match(s) {
				hit = s
				n++
			}
		}
		return hit, n == 1
	}
	if s, ok := uniq(func(s calSub) bool { return len(s.IMSI) >= len(p) && strings.HasPrefix(s.IMSI, p) }); ok {
		return s.SlotIndex + 1, "imsi", s.label()
	}
	if s, ok := uniq(func(s calSub) bool {
		return s.MCC != "" && s.MNC != "" && strings.HasPrefix(p, s.MCC+s.MNC)
	}); ok {
		return s.SlotIndex + 1, "plmn", s.label()
	}
	if fam := calPLMNFamily(p); fam != "" {
		if s, ok := uniq(func(s calSub) bool {
			return calNameFamily(s.Name) == fam || calNameFamily(s.Carrier) == fam
		}); ok {
			return s.SlotIndex + 1, "carrier_name", s.label()
		}
	}
	return 0, "none", ""
}

// ─── 结果结构(API 契约) ──────────────────────────────────────────

type calCellSim struct {
	Slot           int      `json:"slot"`
	Carrier        string   `json:"carrier,omitempty"`
	SubID          int      `json:"sub_id,omitempty"`
	Subscriber     string   `json:"subscriber,omitempty"` // scrub 后前缀(460001)
	MapVia         string   `json:"map_via"`              // sub_id|imsi|plmn|carrier_name|none
	Rx             uint64   `json:"rx"`                   // 本计费周期(系统统计)
	Tx             uint64   `json:"tx"`
	Total          uint64   `json:"total"`
	WindowTotal    uint64   `json:"window_total"`               // 对账窗口内(系统)
	HNCWindowTotal *uint64  `json:"hnc_window_total,omitempty"` // 对账窗口内(HNC), 窗口非整天时缺省
	Pct            *float64 `json:"hnc_vs_netstats_pct"`
}

type calHotspotCmp struct {
	WindowStart int64    `json:"window_start"`
	HNC         uint64   `json:"hnc"`      // 热点口计数(phone_usage 热点)
	Netstats    uint64   `json:"netstats"` // UID_TETHERING
	GapPct      *float64 `json:"gap_pct"`  // (系统 − HNC)/系统, 正 = HNC 少计
}

type calOffloadWin struct {
	From           int64    `json:"from"`
	To             int64    `json:"to"`
	NetstatsTether uint64   `json:"netstats_tether"`
	HotspotIface   string   `json:"hotspot_iface,omitempty"`
	HotspotBytes   *uint64  `json:"hotspot_iface_bytes"`
	HotspotGapPct  *float64 `json:"hotspot_gap_pct"`
	FwdV4Bytes     *uint64  `json:"iptables_fwd_v4_bytes"` // HNC_STATS 跳转规则计数(仅 IPv4)
	FwdV6Bytes     *uint64  `json:"ip6tables_fwd_bytes"`   // ip6tables mangle FORWARD 策略计数(近似)
	FwdGapPct      *float64 `json:"iptables_gap_pct"`
}

type calResult struct {
	Source      string `json:"source"`           // "netstats"
	Status      string `json:"status"`           // ok|drift|unavailable
	Reason      string `json:"reason,omitempty"` // unavailable / 窗口不足等原因
	CheckedAt   int64  `json:"checked_at"`
	Stale       bool   `json:"stale,omitempty"`
	UseNetstats string `json:"use_netstats"`
	Primary     string `json:"primary"` // hnc|netstats(最终 by_sim 主数值来源)
	NetstatsOK  bool   `json:"netstats_available"`

	CycleStart  int64 `json:"cycle_start"`
	WindowStart int64 `json:"window_start,omitempty"` // HNC 与系统同窗口对账起点
	WindowFull  bool  `json:"window_full_cycle"`

	NetstatsCellBySim     []calCellSim `json:"netstats_cell_by_sim"`
	NetstatsCellTotal     uint64       `json:"netstats_cell_total"`           // 本周期, 计费(metered)
	NetstatsCellUnmetered uint64       `json:"netstats_cell_unmetered_total"` // 本周期, 不计费(IMS 等)
	NetstatsWifiTotal     uint64       `json:"netstats_wifi_total"`
	NetstatsTetherTotal   *uint64      `json:"netstats_tether_total"` // 本周期 ∩ 开机以来
	NetstatsTetherSince   int64        `json:"netstats_tether_since,omitempty"`
	NetstatsCellWindow    uint64       `json:"netstats_cell_window"`
	HNCCellWindow         uint64       `json:"hnc_cell_window"`
	HNCvsNetstatsPct      *float64     `json:"hnc_vs_netstats_pct"` // (HNC − 系统)/系统
	LowVolume             bool         `json:"low_volume,omitempty"`

	Hotspot          *calHotspotCmp `json:"hotspot_cmp,omitempty"`
	OffloadGapPct    *float64       `json:"offload_gap_pct"`
	OffloadGapSource string         `json:"offload_gap_source,omitempty"` // live_window|cycle_window|iptables
	OffloadKind      string         `json:"offload_kind,omitempty"`       // none|hw|bpf|unknown
	OffloadWindow    *calOffloadWin `json:"offload_window,omitempty"`
	TextCN           []string       `json:"text_cn,omitempty"`

	Parser map[string]interface{} `json:"parser,omitempty"`
}

func calPct(num, den float64) *float64 {
	if den <= 0 {
		return nil
	}
	v := math.Round(num*1000/den) / 10
	return &v
}

func u64p(v uint64) *uint64 { return &v }

// ─── HNC 侧窗口 ───────────────────────────────────────────────────

func calDayTime(date string, loc *time.Location) (time.Time, bool) {
	t, err := time.ParseInLocation("20060102", date, loc)
	return t, err == nil
}

// calWindowStart 对账窗口起点。HNC 覆盖了整个周期 → 周期起点; 否则从最早那天第一个
// 有数据的小时的下一个整点开始(该小时不完整), 满一天后改到次日零点(每卡可比)。
func calWindowStart(cycleStart time.Time, days []*puDay, earliest string, now time.Time) (time.Time, bool, string) {
	if earliest == "" {
		return time.Time{}, false, "hnc_no_data"
	}
	et, ok := calDayTime(earliest, cycleStart.Location())
	if !ok {
		return time.Time{}, false, "hnc_no_data"
	}
	if et.Before(cycleStart) {
		return cycleStart, true, ""
	}
	var first *puDay
	for _, d := range days {
		if d.Date == earliest {
			first = d
		}
	}
	h0 := -1
	if first != nil {
		for k := range first.Hours {
			if n, err := strconv.Atoi(k); err == nil && (h0 < 0 || n < h0) {
				h0 = n
			}
		}
	}
	if et.Equal(cycleStart) && h0 == 0 {
		return cycleStart, true, ""
	}
	if h0 < 0 {
		h0 = 0
	}
	ws := et.Add(time.Duration(h0+1) * time.Hour)
	if now.Sub(ws) >= 24*time.Hour {
		ws = et.AddDate(0, 0, 1)
	}
	if now.Sub(ws) < time.Hour {
		return ws, false, "hnc_history_too_short"
	}
	return ws, false, ""
}

// calHNCWindow HNC 在 [ws, 现在] 的蜂窝/热点合计; ws 是零点时还给出每卡合计。
func calHNCWindow(days []*puDay, ws time.Time) (cell, hs uint64, bySlot map[int]uint64, perSim bool) {
	midnight := ws.Equal(puMidnight(ws))
	wsDate := ws.Format("20060102")
	var inWin []*puDay
	for _, d := range days {
		if d.Date < wsDate {
			continue
		}
		if d.Date == wsDate && !midnight {
			for k, h := range d.Hours {
				if n, err := strconv.Atoi(k); err == nil && n >= ws.Hour() && h != nil {
					cell += h.Cell[0] + h.Cell[1]
					hs += h.Hotspot[0] + h.Hotspot[1]
				}
			}
			continue
		}
		inWin = append(inWin, d)
		for _, v := range d.Cell {
			cell += v[0] + v[1]
		}
		hs += d.Hotspot[0] + d.Hotspot[1]
	}
	if !midnight {
		return cell, hs, nil, false
	}
	bySlot = map[int]uint64{}
	for slot, a := range puAggSIM(inWin) {
		bySlot[slot] = a.Rx + a.Tx
	}
	return cell, hs, bySlot, true
}

// ─── 纯计算 ───────────────────────────────────────────────────────

type calInput struct {
	Now        time.Time
	CycleStart time.Time
	Xt         *nsDump // dumpsys netstats --full
	Uid        *nsDump // dumpsys netstats --uid(UID 段开机以来)
	Subs       []calSub
	Days       []*puDay // HNC cycleStart..now
	Earliest   string   // HNC 最早的日文件(YYYYMMDD)
	BootTime   int64
}

func calCeilHour(t time.Time) time.Time {
	tr := t.Truncate(time.Hour)
	if tr.Equal(t) {
		return t
	}
	return tr.Add(time.Hour)
}

// calCompute 纯函数: netstats + HNC 日数据 → 对账结果(不含实时分流窗口)
func calCompute(in calInput) calResult {
	now := in.Now.Unix()
	res := calResult{Source: "netstats", Status: "unavailable", CheckedAt: now,
		CycleStart: in.CycleStart.Unix(), NetstatsCellBySim: []calCellSim{}}
	parser := map[string]interface{}{}
	res.Parser = parser

	sec := "xt"
	if in.Xt == nil || !in.Xt.Sections["xt"] {
		sec = "dev"
	}
	if in.Xt == nil || !in.Xt.Sections[sec] {
		res.Reason = "netstats_parse_failed"
		return res
	}
	parser["cell_section"] = sec
	parser["xt_full"] = in.Xt.FullSec[sec]
	parser["lines"] = in.Xt.Lines
	mobile := in.Xt.nsSelect(sec, nsUIDAll, "MOBILE")
	wifi := in.Xt.nsSelect(sec, nsUIDAll, "WIFI")
	parser["mobile_keys"] = len(mobile)
	parser["wifi_keys"] = len(wifi)
	if e := nsEarliest(append(append([]*nsKey{}, mobile...), wifi...)); e > 0 {
		parser["netstats_since"] = e
	}
	res.NetstatsOK = true

	cs := in.CycleStart.Unix()
	ws, full, why := calWindowStart(in.CycleStart, in.Days, in.Earliest, in.Now)
	res.WindowFull = full
	winOK := why == "" && !ws.IsZero()
	if !ws.IsZero() {
		res.WindowStart = ws.Unix()
	}

	// 每卡(按卡槽合并; 未识别的按 subscriber 前缀分开)
	type agg struct {
		calCellSim
		rx, tx, win float64
	}
	groups := map[string]*agg{}
	order := []string{}
	var nsCellWin float64
	for _, k := range mobile {
		id := k.Primary()
		rx, tx := nsWindowBytes(k, cs, now+1, now)
		if id.Metered == 0 {
			res.NetstatsCellUnmetered += uint64(rx + tx)
			continue
		}
		slot, via, label := calMapSlot(id, in.Subs)
		gk := "s" + strconv.Itoa(slot)
		if slot == 0 {
			gk = "p" + id.Subscriber
		}
		g := groups[gk]
		if g == nil {
			g = &agg{calCellSim: calCellSim{Slot: slot, Carrier: label, Subscriber: id.Subscriber, MapVia: via}}
			if id.SubID > 0 {
				g.SubID = id.SubID
			}
			groups[gk] = g
			order = append(order, gk)
		}
		g.rx += rx
		g.tx += tx
		if winOK {
			wrx, wtx := nsWindowBytes(k, res.WindowStart, now+1, now)
			g.win += wrx + wtx
			nsCellWin += wrx + wtx
		}
	}
	for _, k := range wifi {
		rx, tx := nsWindowBytes(k, cs, now+1, now)
		res.NetstatsWifiTotal += uint64(rx + tx)
	}

	var hncCell, hncHS uint64
	var bySlot map[int]uint64
	perSim := false
	if winOK {
		hncCell, hncHS, bySlot, perSim = calHNCWindow(in.Days, ws)
		_ = hncHS
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := groups[order[i]], groups[order[j]]
		if (a.Slot == 0) != (b.Slot == 0) {
			return a.Slot != 0
		}
		return a.Slot < b.Slot
	})
	for _, gk := range order {
		g := groups[gk]
		c := g.calCellSim
		c.Rx, c.Tx = uint64(g.rx), uint64(g.tx)
		c.Total = c.Rx + c.Tx
		c.WindowTotal = uint64(g.win)
		res.NetstatsCellTotal += c.Total
		if winOK && perSim && c.Slot > 0 {
			h := bySlot[c.Slot]
			c.HNCWindowTotal = u64p(h)
			if c.WindowTotal >= calMinCellBytes/4 {
				c.Pct = calPct(float64(h)-float64(c.WindowTotal), float64(c.WindowTotal))
			}
		}
		res.NetstatsCellBySim = append(res.NetstatsCellBySim, c)
	}

	// 热点(UID_TETHERING)
	var tether []*nsKey
	var tetherSince int64
	if in.Uid != nil && in.Uid.Sections["uid"] {
		tether = in.Uid.nsSelect("uid", nsUIDTethering, "")
		tetherSince = cs
		if !in.Uid.FullSec["uid"] && in.BootTime > cs {
			tetherSince = in.BootTime
		}
		var t float64
		for _, k := range tether {
			rx, tx := nsWindowBytes(k, tetherSince, now+1, now)
			t += rx + tx
		}
		res.NetstatsTetherTotal = u64p(uint64(t))
		res.NetstatsTetherSince = tetherSince
		parser["tether_keys"] = len(tether)
	}

	if !winOK {
		res.Reason = why
		return res
	}
	res.NetstatsCellWindow = uint64(nsCellWin)
	res.HNCCellWindow = hncCell
	res.HNCvsNetstatsPct = calPct(float64(hncCell)-nsCellWin, nsCellWin)
	res.Status = "ok"
	if nsCellWin < calMinCellBytes {
		res.LowVolume = true
	} else if res.HNCvsNetstatsPct != nil && math.Abs(*res.HNCvsNetstatsPct) >= calDriftPct {
		res.Status = "drift"
		res.TextCN = append(res.TextCN, "本机蜂窝流量与系统统计相差 "+calFmtPct(*res.HNCvsNetstatsPct))
	}

	// 周期窗口的热点对比: 起点 = max(对账窗口, 系统热点明细起点), 取整点(HNC 按小时存)
	if res.NetstatsTetherTotal != nil {
		tws := ws
		if ts := time.Unix(tetherSince, 0).In(ws.Location()); ts.After(tws) {
			tws = calCeilHour(ts)
		}
		if in.Now.Sub(tws) >= time.Hour {
			_, hhs, _, _ := calHNCWindow(in.Days, tws)
			var nt float64
			for _, k := range tether {
				rx, tx := nsWindowBytes(k, tws.Unix(), now+1, now)
				nt += rx + tx
			}
			hc := &calHotspotCmp{WindowStart: tws.Unix(), HNC: hhs, Netstats: uint64(nt)}
			if nt >= calMinCycleTether {
				hc.GapPct = calPct(nt-float64(hhs), nt)
			}
			res.Hotspot = hc
		}
	}
	return res
}

func calFmtPct(v float64) string {
	s := strconv.FormatFloat(math.Abs(v), 'f', 1, 64) + "%"
	if v < 0 {
		return "−" + s + "(HNC 偏少)"
	}
	return "+" + s + "(HNC 偏多)"
}

// ─── 实时分流窗口(快照) ──────────────────────────────────────────

type calSnap struct {
	T         int64
	HsIface   string
	HsIfindex int
	HsBytes   uint64
	HsOK      bool
	FwdV4     uint64
	FwdV4OK   bool
	FwdV6     uint64
	FwdV6OK   bool
}

// calLiveWindow 取 12 小时内最老(且 ≥ 1 小时前)的快照作起点, 与当前比较
func calLiveWindow(snaps []calSnap, cur calSnap, uid *nsDump) *calOffloadWin {
	if uid == nil || !uid.Sections["uid"] {
		return nil
	}
	var base *calSnap
	for i := range snaps {
		s := &snaps[i]
		age := cur.T - s.T
		if age < int64(calLiveMin/time.Second) || age > int64(calSnapKeep/time.Second) {
			continue
		}
		if base == nil || s.T < base.T {
			base = s
		}
	}
	if base == nil {
		return nil
	}
	var nt float64
	for _, k := range uid.nsSelect("uid", nsUIDTethering, "") {
		rx, tx := nsWindowBytes(k, base.T, cur.T+1, cur.T)
		nt += rx + tx
	}
	w := &calOffloadWin{From: base.T, To: cur.T, NetstatsTether: uint64(nt)}
	enough := nt >= calMinLiveTether
	if base.HsOK && cur.HsOK && base.HsIface == cur.HsIface && cur.HsBytes >= base.HsBytes &&
		(base.HsIfindex == 0 || cur.HsIfindex == 0 || base.HsIfindex == cur.HsIfindex) {
		d := cur.HsBytes - base.HsBytes
		w.HotspotIface = cur.HsIface
		w.HotspotBytes = u64p(d)
		if enough {
			w.HotspotGapPct = calPct(nt-float64(d), nt)
		}
	}
	var fwd uint64
	fwdOK := false
	if base.FwdV4OK && cur.FwdV4OK && cur.FwdV4 >= base.FwdV4 {
		w.FwdV4Bytes = u64p(cur.FwdV4 - base.FwdV4)
		fwd += cur.FwdV4 - base.FwdV4
		fwdOK = true
	}
	if base.FwdV6OK && cur.FwdV6OK && cur.FwdV6 >= base.FwdV6 {
		w.FwdV6Bytes = u64p(cur.FwdV6 - base.FwdV6)
		fwd += cur.FwdV6 - base.FwdV6
	}
	if fwdOK && enough {
		w.FwdGapPct = calPct(nt-float64(fwd), nt)
	}
	return w
}

// calMergeOffload 选出 offload_gap_pct 与分流类型并写中文说明
func calMergeOffload(res *calResult, live *calOffloadWin) {
	res.OffloadWindow = live
	var hsGap, fwdGap *float64
	if live != nil {
		hsGap, fwdGap = live.HotspotGapPct, live.FwdGapPct
	}
	switch {
	case hsGap != nil:
		res.OffloadGapPct, res.OffloadGapSource = hsGap, "live_window"
	case res.Hotspot != nil && res.Hotspot.GapPct != nil:
		hsGap = res.Hotspot.GapPct
		res.OffloadGapPct, res.OffloadGapSource = hsGap, "cycle_window"
	case fwdGap != nil:
		res.OffloadGapPct, res.OffloadGapSource = fwdGap, "iptables"
	}
	big := func(p *float64) bool { return p != nil && *p >= calGapPct }
	switch {
	case big(hsGap):
		res.OffloadKind = "hw"
		res.TextCN = append(res.TextCN, "硬件分流导致漏计 ≈ "+strconv.FormatFloat(*hsGap, 'f', 0, 64)+"%")
	case big(fwdGap) && hsGap != nil:
		res.OffloadKind = "bpf"
		res.OffloadGapPct, res.OffloadGapSource = fwdGap, "iptables"
		res.TextCN = append(res.TextCN, "软件分流(BPF)绕过 iptables, 设备流量统计漏计 ≈ "+
			strconv.FormatFloat(*fwdGap, 'f', 0, 64)+"%(热点口计数正常)")
	case big(fwdGap):
		res.OffloadKind = "unknown"
		res.TextCN = append(res.TextCN, "分流绕过 iptables, 设备流量统计漏计 ≈ "+
			strconv.FormatFloat(*fwdGap, 'f', 0, 64)+"%")
	case res.OffloadGapPct != nil:
		res.OffloadKind = "none"
	}
}

// ─── 真机采集 ─────────────────────────────────────────────────────

type calCapWriter struct {
	b   []byte
	max int
	cut bool
}

func (w *calCapWriter) Write(p []byte) (int, error) {
	if room := w.max - len(w.b); room > 0 {
		if len(p) > room {
			w.b = append(w.b, p[:room]...)
			w.cut = true
		} else {
			w.b = append(w.b, p...)
		}
	} else if len(p) > 0 {
		w.cut = true
	}
	return len(p), nil
}

// calRunCmd 同 puRunCmd, 但超时/输出上限可控(dumpsys --full 可能几 MB)
func calRunCmd(timeout time.Duration, name string, args ...string) (string, error) {
	path := ""
	for _, d := range []string{"/system/bin/", "/system/xbin/", "/vendor/bin/"} {
		if st, err := os.Stat(d + name); err == nil && !st.IsDir() {
			path = d + name
			break
		}
	}
	if path == "" {
		p, err := exec.LookPath(name)
		if err != nil {
			return "", err
		}
		path = p
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, path, args...))
	cmd.Env = []string{"PATH=/system/bin:/system/xbin:/vendor/bin"}
	w := &calCapWriter{max: calCmdMaxOut}
	cmd.Stdout = w
	err := cmd.Run()
	if err == nil && w.cut {
		err = errors.New("output truncated")
	}
	return string(w.b), err
}

// calParseIptForward `iptables -t mangle -L FORWARD -nvx`: 策略计数 + 跳 HNC_STATS 规则计数
func calParseIptForward(out string) (policy uint64, policyOK bool, jump uint64, jumpOK bool) {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if m := calPolicyRE.FindStringSubmatch(line); m != nil {
			if v, err := strconv.ParseUint(m[1], 10, 64); err == nil {
				policy, policyOK = v, true
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 3 && f[2] == "HNC_STATS" {
			if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				jump += v
				jumpOK = true
			}
		}
	}
	return
}

var calPolicyRE = regexp.MustCompile(`^Chain FORWARD \(policy \S+ \d+ packets, (\d+) bytes\)`)

func calParseBootTime(stat string) int64 {
	for _, line := range strings.Split(stat, "\n") {
		if strings.HasPrefix(line, "btime ") {
			n, _ := strconv.ParseInt(strings.TrimSpace(line[6:]), 10, 64)
			return n
		}
	}
	return 0
}

// calEarliestDay run/ 下最早的 phone_usage 日文件
func calEarliestDay(hncDir string) string {
	files, _ := filepath.Glob(filepath.Join(hncDir, "run", "phone_usage.*.json"))
	best := ""
	for _, f := range files {
		d := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "phone_usage."), ".json")
		if len(d) != 8 {
			continue
		}
		if _, err := strconv.Atoi(d); err != nil {
			continue
		}
		if best == "" || d < best {
			best = d
		}
	}
	return best
}

// ─── 运行时 ───────────────────────────────────────────────────────

type calEnv struct {
	run          func(timeout time.Duration, name string, args ...string) (string, error)
	readNetDev   func() ([]byte, error)
	ifindex      func(name string) int
	hotspotIface func() string
	bootTime     func() int64
}

type calibrator struct {
	mu     sync.Mutex
	hncDir string
	env    calEnv
	last   *calResult
	snaps  []calSnap
	cur    calSnap // 最近一次计数快照(stats_health 复用)
	kick   chan struct{}
}

var calReg = struct {
	mu sync.Mutex
	m  map[string]*calibrator
}{m: map[string]*calibrator{}}

func calInstall(hncDir string, env calEnv) *calibrator {
	calReg.mu.Lock()
	defer calReg.mu.Unlock()
	c := &calibrator{hncDir: hncDir, env: env, kick: make(chan struct{}, 1)}
	calReg.m[hncDir] = c
	return c
}

func calGet(hncDir string) *calibrator {
	calReg.mu.Lock()
	defer calReg.mu.Unlock()
	return calReg.m[hncDir]
}

// calKick 配置变了(计费日 / use_netstats)→ 让后台尽快重算
func calKick(hncDir string) {
	if c := calGet(hncDir); c != nil {
		select {
		case c.kick <- struct{}{}:
		default:
		}
	}
}

func (c *calibrator) result() *calResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		return nil
	}
	r := *c.last
	return &r
}

// takeSnap 读热点口 /proc/net/dev 与 iptables 计数
func (c *calibrator) takeSnap(now time.Time) calSnap {
	s := calSnap{T: now.Unix()}
	if c.env.hotspotIface != nil && c.env.readNetDev != nil {
		if hs := c.env.hotspotIface(); hs != "" {
			if raw, err := c.env.readNetDev(); err == nil {
				if v, ok := puParseNetDev(raw)[hs]; ok {
					s.HsIface, s.HsBytes, s.HsOK = hs, v[0]+v[1], true
					if c.env.ifindex != nil {
						s.HsIfindex = c.env.ifindex(hs)
					}
				}
			}
		}
	}
	if c.env.run != nil {
		if out, err := c.env.run(5*time.Second, "iptables", "-w", "-t", "mangle", "-L", "FORWARD", "-nvx"); err == nil {
			_, _, j, ok := calParseIptForward(out)
			s.FwdV4, s.FwdV4OK = j, ok
		}
		if out, err := c.env.run(5*time.Second, "ip6tables", "-w", "-t", "mangle", "-L", "FORWARD", "-nvx"); err == nil {
			p, ok, _, _ := calParseIptForward(out)
			s.FwdV6, s.FwdV6OK = p, ok
		}
	}
	return s
}

func (c *calibrator) pushSnap(s calSnap) {
	cut := s.T - int64(calSnapKeep/time.Second) - 3600
	keep := c.snaps[:0]
	for _, x := range c.snaps {
		if x.T >= cut && x.T < s.T {
			keep = append(keep, x)
		}
	}
	c.snaps = append(keep, s)
}

// check 一轮对账(后台每 15 分钟)
func (c *calibrator) check(now time.Time, pu *puEngine) {
	if !clockSane(c.hncDir, now) {
		return
	}
	cfg := puLoadConfig(c.hncDir)
	mode := cfg.netstatsMode()
	snap := c.takeSnap(now)
	c.mu.Lock()
	prevSnaps := append([]calSnap(nil), c.snaps...)
	c.pushSnap(snap)
	c.cur = snap
	c.mu.Unlock()

	cycleStart := puCycleStart(now, cfg.BillingDay)
	var res calResult
	if mode == "off" {
		res = calResult{Source: "netstats", Status: "unavailable", Reason: "disabled",
			CheckedAt: now.Unix(), CycleStart: cycleStart.Unix(), NetstatsCellBySim: []calCellSim{}}
	} else {
		in := calInput{Now: now, CycleStart: cycleStart}
		_, _ = c.env.run(calCmdTimeout, "dumpsys", "netstats", "--poll")
		if out, err := c.env.run(calCmdTimeout, "dumpsys", "netstats", "--full"); err == nil || out != "" {
			in.Xt, _ = parseNetstatsDump(strings.NewReader(out), func(sec string, uid int) bool {
				return (sec == "xt" || sec == "dev") && uid == nsUIDAll
			})
		}
		if out, err := c.env.run(calCmdTimeout, "dumpsys", "netstats", "--uid"); err == nil || out != "" {
			in.Uid, _ = parseNetstatsDump(strings.NewReader(out), func(sec string, uid int) bool {
				return sec == "uid" && uid == nsUIDTethering
			})
		}
		if out, err := c.env.run(10*time.Second, "content", "query", "--uri", "content://telephony/siminfo"); err == nil {
			in.Subs = calParseSiminfo(out)
		}
		if c.env.bootTime != nil {
			in.BootTime = c.env.bootTime()
		}
		if pu != nil {
			in.Days = pu.days(cycleStart, now)
		}
		in.Earliest = calEarliestDay(c.hncDir)
		res = calCompute(in)
		if res.NetstatsOK {
			calMergeOffload(&res, calLiveWindow(prevSnaps, snap, in.Uid))
		}
	}
	res.UseNetstats = mode
	c.mu.Lock()
	c.last = &res
	c.mu.Unlock()
}

// StatsCalibrationLoop 后台对账(v5.21)
func (s *server) StatsCalibrationLoop(stop <-chan struct{}) {
	c := calInstall(s.hncDir, calEnv{
		run:        calRunCmd,
		readNetDev: func() ([]byte, error) { return os.ReadFile("/proc/net/dev") },
		ifindex: func(name string) int {
			b, err := os.ReadFile(filepath.Join("/sys/class/net", name, "ifindex"))
			if err != nil {
				return 0
			}
			n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
			return n
		},
		hotspotIface: s.currentHotspotIface,
		bootTime: func() int64 {
			b, _ := os.ReadFile("/proc/stat")
			return calParseBootTime(string(b))
		},
	})
	t := time.NewTimer(calFirstDelay)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		case <-c.kick:
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
		}
		c.check(time.Now(), s.phoneUsage())
		t.Reset(calEvery)
	}
}

// ─── 接到 /api/phone_usage ────────────────────────────────────────

// netstatsMode use_netstats 归一: auto|prefer|off
func (c puConfig) netstatsMode() string {
	switch c.UseNetstats {
	case "prefer", "off":
		return c.UseNetstats
	}
	return "auto"
}

// calUsable prefer 模式能否用该结果: 系统统计解析成功、未过期、周期一致
func calUsable(r *calResult, cycleStart time.Time, now time.Time) bool {
	return r != nil && r.NetstatsOK && r.CycleStart == cycleStart.Unix() &&
		now.Unix()-r.CheckedAt <= int64(calStaleAfter/time.Second)
}

// puCalAttach 把对账结果挂到 report 上; prefer 时替换 by_sim 的周期用量
func puCalAttach(hncDir string, cfg puConfig, cycleStart, now time.Time, resp map[string]interface{}, bySim []map[string]interface{}) {
	mode := cfg.netstatsMode()
	var r *calResult
	if c := calGet(hncDir); c != nil {
		r = c.result()
	}
	switch {
	case mode == "off":
		r = &calResult{Source: "netstats", Status: "unavailable", Reason: "disabled", NetstatsCellBySim: []calCellSim{}}
	case r == nil:
		r = &calResult{Source: "netstats", Status: "unavailable", Reason: "pending", NetstatsCellBySim: []calCellSim{}}
	case r.CycleStart != cycleStart.Unix():
		r.Stale = true
		r.Reason = "cycle_changed"
	case now.Unix()-r.CheckedAt > int64(calStaleAfter/time.Second):
		r.Stale = true
	}
	r.UseNetstats = mode
	r.Primary = "hnc"
	usable := mode != "off" && calUsable(r, cycleStart, now)
	if usable {
		ns := map[int]calCellSim{}
		for _, c := range r.NetstatsCellBySim {
			if c.Slot > 0 {
				ns[c.Slot] = c
			}
		}
		for _, row := range bySim {
			slot, _ := row["slot"].(int)
			c, ok := ns[slot]
			if !ok {
				continue
			}
			row["netstats_cycle_used"] = c.Total
			if mode != "prefer" {
				continue
			}
			row["hnc_cycle_used"] = row["cycle_used"]
			row["cycle_used"] = c.Total
			row["cycle_used_source"] = "netstats"
			if plan, _ := row["plan_bytes"].(uint64); plan > 0 {
				row["used_pct"] = math.Round(float64(c.Total)*1000/float64(plan)) / 10
			}
		}
		if mode == "prefer" {
			r.Primary = "netstats"
		}
	}
	resp["primary_source"] = r.Primary
	resp["calibration"] = r
}

// puCalPreferUsed prefer 模式下套餐告警用系统统计的每卡周期用量
func puCalPreferUsed(hncDir string, cfg puConfig, cycleStart, now time.Time, used map[int]*puSimAgg) map[int]*puSimAgg {
	if cfg.netstatsMode() != "prefer" {
		return used
	}
	c := calGet(hncDir)
	if c == nil {
		return used
	}
	r := c.result()
	if !calUsable(r, cycleStart, now) {
		return used
	}
	out := map[int]*puSimAgg{}
	for k, v := range used {
		out[k] = v
	}
	for _, s := range r.NetstatsCellBySim {
		if s.Slot <= 0 {
			continue
		}
		a := &puSimAgg{Carriers: map[string]bool{}}
		if old := used[s.Slot]; old != nil {
			x := *old
			a = &x
		}
		a.Rx, a.Tx = s.Rx, s.Tx
		if a.Carrier == "" {
			a.Carrier = s.Carrier
		}
		out[s.Slot] = a
	}
	return out
}
