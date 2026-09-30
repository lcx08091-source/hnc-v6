// phone_usage.go — 本月流量 / 本机与热点用量(手机自身的月度流量, 按网络、按卡、按"谁用的"拆分)
//
// 数据源: /proc/net/dev(每 60 秒一次 + 停机时一次), 对每个接口的累计 rx/tx 做差分。
// 与 app_usage.go(conntrack, 只看热点客户端)不同, 这里看的是整机网卡计数 ——
// 和运营商计费最接近的口径。
//
// 接口分类(puClassifyIface):
//   - cell    蜂窝: rmnet_data* / rmnetN / ccmni* / seth_lte* / wwan*
//             不计: v4-rmnet*(clat 464xlat 的 IPv4 虚拟口, 其流量翻译成 IPv6 后
//             还会再过一次 rmnet_data*, 两边都计就翻倍 —— 统一只计底层 rmnet_data*,
//             它也正是运营商实际计费的 IPv6 字节), r_rmnet*(反向 rmnet, IMS/WFC),
//             rmnet_ipa* / rmnet_mhi* / rmnet_usb*(高通物理聚合口, 是所有
//             rmnet_data* 之和, 计了会重复)。
//   - wifi    Wi-Fi 客户端(STA): wlan0 且不是当前热点口。
//   - hotspot 热点口: 与 /api/live 同源的 currentHotspotIface()(hnc_state →
//             iface.cache → rules.json); 取不到时按 ap* / softap* / swlan* 命名兜底。
//   - 其他(lo / dummy / tun* / ifb* / p2p* / wlan1+ 等)忽略。
//
// 计数器复位: 本次值 < 上次值(重启 / 接口重建)或 ifindex 变了 → 视为复位, 增量 = 本次值。
// 进程重启: 上次计数器连同 boot_id 存在 run/phone_usage_state.json; 同一次开机
// 续上差分, 换了 boot_id(手机重启)则把开机以来的计数全算作增量(开机→httpd 起来
// 之间的流量不丢); 从未有过状态文件(首次安装)只建基线, 不把历史计数算进今天。
//
// 本机 vs 热点(近似, 见 puSplitLocal):
//   热点字节 = 热点口字节, 存为"客户端视角": hotspot[0]=客户端下载(=热点口 tx),
//   hotspot[1]=客户端上传(=热点口 rx)。热点流量走上游出去, 所以
//     本机蜂窝 ≈ 蜂窝 − 热点(当上游是蜂窝), 本机 Wi-Fi ≈ Wi-Fi − 热点(当上游是 Wi-Fi),
//   逐方向相减, 小于 0 截为 0。误差来源(都会让"本机"略偏小): 热点口计数含以太网
//   帧头(约 1-3%)、客户端访问手机本身(DNS / WebUI)不走上游、clat 的 v4→v6 包头差。
//   上游判定: `ip route get 1.1.1.1` 的出口(root 无 fwmark 走默认网络), 再用本轮增量
//   交叉校验(路由说 Wi-Fi 但 Wi-Fi 增量远小于热点增量、蜂窝却够 → 改判蜂窝), 见
//   puResolveUpstream。
//
// 按卡归属: 每 5 分钟刷新一次"默认数据卡"(phone_usage_sim.go), 本分钟的蜂窝增量
// 全部记给这张卡; 识别不到记 "0|蜂窝(未知卡)"。
//
// 存储(与 app_usage 一致放 run/, 在 /data 上, 非 tmpfs):
//   run/phone_usage.YYYYMMDD.json   一天一个, 保留 400 天
//   run/phone_usage_state.json      上次计数器 + boot_id + 已发告警(去重)
//   data/phone_usage_config.json    计费日 / 每卡套餐 / 预警百分比(独立文件,
//                                   与 alerts_config.json 同款; 不写 rules.json,
//                                   避免和 shell 侧 json_set.sh 抢同一文件)
//
// API:
//   GET /api/phone_usage?period=cycle|month|today|7d|30d   (默认 cycle)
//   action phone_usage_set {billing_day, plan_sim1_gb, plan_sim2_gb, warn_percent}
//     全部可选, 只改传了的; 数值以字符串传(与其他 action 一致)。
// 告警: 某卡本计费周期用量跨过 warn_percent 或 100% 套餐 → 往 run/alerts.jsonl 追加
// 一条 kind="phone_quota"(每卡每档每周期一次)。

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hnc.io/dpid/alert"
)

const (
	puEvery        = 60 * time.Second
	puSimRefresh   = 5 * time.Minute
	puKeepDays     = 400
	puUnknownSIM   = "蜂窝(未知卡)"
	puAlertKind    = "phone_quota"
	puGiB          = 1024 * 1024 * 1024
	puDefaultWarn  = 80
	puMaxPlanGB    = 100000
	puClassCell    = "cell"
	puClassWifi    = "wifi"
	puClassHotspot = "hotspot"
)

// ─── 接口分类 ─────────────────────────────────────────────────────

var (
	puCellRE = regexp.MustCompile(`^(rmnet_data\d+|rmnet\d+|ccmni\d+|seth_lte\d+|wwan\d+)$`)
	puAPRE   = regexp.MustCompile(`^(ap\d*|softap\d*|swlan\d+)$`)
)

// puClassifyIface 返回 cell / wifi / hotspot / ""(忽略)。hotspotIface 为当前热点口(可空)。
func puClassifyIface(name, hotspotIface string) string {
	if name == "" {
		return ""
	}
	if hotspotIface != "" && name == hotspotIface {
		return puClassHotspot
	}
	if hotspotIface == "" && puAPRE.MatchString(name) {
		return puClassHotspot
	}
	if name == "wlan0" {
		return puClassWifi
	}
	if puCellRE.MatchString(name) {
		return puClassCell
	}
	return ""
}

// ─── /proc/net/dev 解析与差分 ─────────────────────────────────────

// puParseNetDev 解析 /proc/net/dev → iface → [rx_bytes, tx_bytes]
func puParseNetDev(b []byte) map[string][2]uint64 {
	out := map[string][2]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		f := strings.Fields(line[i+1:])
		if name == "" || len(f) < 9 {
			continue // 表头两行没有 ':' 或字段不足
		}
		rx, e1 := strconv.ParseUint(f[0], 10, 64)
		tx, e2 := strconv.ParseUint(f[8], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		out[name] = [2]uint64{rx, tx}
	}
	return out
}

// puCtr 一个接口上次看到的计数器
type puCtr struct {
	Ifindex int    `json:"ifindex,omitempty"`
	Rx      uint64 `json:"rx"`
	Tx      uint64 `json:"tx"`
}

// puCounterDelta 计数器差分: 变小视为复位(重启/接口重建), 增量 = 当前值
func puCounterDelta(prev, cur uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

// puStepCounters 纯函数: 上次计数器 + 本次读数 → 各接口增量 + 新的"上次"。
// baseline=true 表示 prev 可信(已建基线): prev 里没有的接口是新出现的, 全部字节算增量;
// baseline=false 只建基线, 不产生增量。
func puStepCounters(prev map[string]puCtr, cur map[string]puCtr, baseline bool) (map[string][2]uint64, map[string]puCtr) {
	deltas := map[string][2]uint64{}
	next := make(map[string]puCtr, len(cur))
	for name, c := range cur {
		next[name] = c
		if !baseline {
			continue
		}
		p, ok := prev[name]
		var d [2]uint64
		switch {
		case !ok:
			d = [2]uint64{c.Rx, c.Tx}
		case p.Ifindex != 0 && c.Ifindex != 0 && p.Ifindex != c.Ifindex:
			d = [2]uint64{c.Rx, c.Tx} // 接口被删了又建(同名新 ifindex), 计数从 0 重来
		default:
			d = [2]uint64{puCounterDelta(p.Rx, c.Rx), puCounterDelta(p.Tx, c.Tx)}
		}
		if d[0] != 0 || d[1] != 0 {
			deltas[name] = d
		}
	}
	return deltas, next
}

// ─── 本机 / 热点拆分 ──────────────────────────────────────────────

func puSub(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return 0
}

func puAdd2(a *[2]uint64, b [2]uint64) {
	a[0] += b[0]
	a[1] += b[1]
}

// puResolveUpstream 决定本分钟热点流量走的是哪条上游(cell / wifi / "")。
// routeClass 是默认路由出口的分类; 用增量交叉校验: 真正的上游本分钟至少要承载
// 约 80% 的热点字节。都不像时退回路由结果, 路由也未知则取增量大的一边。
func puResolveUpstream(routeClass string, cell, wifi, hs uint64) string {
	if hs == 0 {
		if routeClass == puClassCell || routeClass == puClassWifi {
			return routeClass
		}
		return ""
	}
	enough := func(v uint64) bool { return v*10 >= hs*8 }
	other := map[string]string{puClassCell: puClassWifi, puClassWifi: puClassCell}
	val := map[string]uint64{puClassCell: cell, puClassWifi: wifi}
	if routeClass == puClassCell || routeClass == puClassWifi {
		if enough(val[routeClass]) {
			return routeClass
		}
		if o := other[routeClass]; enough(val[o]) {
			return o
		}
		return routeClass
	}
	if cell == 0 && wifi == 0 {
		return ""
	}
	if cell >= wifi {
		return puClassCell
	}
	return puClassWifi
}

// puSplitLocal 本机 = 上游总量 − 热点(客户端视角 [下载, 上传] 对应上游 [rx, tx]),
// 逐方向截 0。upstream 不是本类别时原样返回(热点没走这条路)。
func puSplitLocal(total [2]uint64, hsClient [2]uint64, isUpstream bool) [2]uint64 {
	if !isUpstream {
		return total
	}
	return [2]uint64{puSub(total[0], hsClient[0]), puSub(total[1], hsClient[1])}
}

// ─── 按天存储 ─────────────────────────────────────────────────────

type puHour struct {
	Cell    [2]uint64 `json:"cell"`
	Wifi    [2]uint64 `json:"wifi"`
	Hotspot [2]uint64 `json:"hotspot"`
	Local   [2]uint64 `json:"local"`
}

// puDay 一天的累计。所有 [2]uint64 都是 [rx, tx](hotspot 是客户端视角 [下载, 上传])。
type puDay struct {
	Date      string               `json:"date"`                  // YYYYMMDD 本地
	Cell      map[string][2]uint64 `json:"cell"`                  // "<slot>|<carrier>" → 蜂窝总量(含热点)
	Wifi      [2]uint64            `json:"wifi"`                  // Wi-Fi 客户端总量(含热点)
	Hotspot   [2]uint64            `json:"hotspot"`               // 热点客户端合计
	LocalCell [2]uint64            `json:"local_cell"`            // 本机蜂窝(近似)
	LocalWifi [2]uint64            `json:"local_wifi"`            // 本机 Wi-Fi(近似)
	LocalSIM  map[string][2]uint64 `json:"local_cell_by_sim"`     // 本机蜂窝按卡
	HsVia     map[string][2]uint64 `json:"hotspot_via,omitempty"` // 热点走的上游 cell/wifi/unknown
	Hours     map[string]*puHour   `json:"hours,omitempty"`       // "0".."23"
}

func newPuDay(date string) *puDay {
	return &puDay{Date: date, Cell: map[string][2]uint64{}, LocalSIM: map[string][2]uint64{},
		HsVia: map[string][2]uint64{}, Hours: map[string]*puHour{}}
}

func (d *puDay) normalize(date string) {
	d.Date = date
	if d.Cell == nil {
		d.Cell = map[string][2]uint64{}
	}
	if d.LocalSIM == nil {
		d.LocalSIM = map[string][2]uint64{}
	}
	if d.HsVia == nil {
		d.HsVia = map[string][2]uint64{}
	}
	if d.Hours == nil {
		d.Hours = map[string]*puHour{}
	}
}

func (d *puDay) clone() *puDay {
	b, _ := json.Marshal(d)
	x := &puDay{}
	_ = json.Unmarshal(b, x)
	x.normalize(d.Date)
	return x
}

func puDayPath(hncDir, date string) string {
	return filepath.Join(hncDir, "run", "phone_usage."+date+".json")
}

func puLoadDay(hncDir, date string) (*puDay, bool) {
	b, err := os.ReadFile(puDayPath(hncDir, date))
	if err != nil {
		return newPuDay(date), false
	}
	var d puDay
	if json.Unmarshal(b, &d) != nil {
		return newPuDay(date), false
	}
	d.normalize(date)
	return &d, true
}

func puSaveDay(hncDir string, d *puDay) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return discoverWriteAtomic(puDayPath(hncDir, d.Date), b)
}

// ─── 配置 ─────────────────────────────────────────────────────────

type puConfig struct {
	BillingDay  int                `json:"billing_day"`  // 1-28
	PlanGB      map[string]float64 `json:"plan_gb"`      // "1"/"2" → GB(0 = 无套餐)
	WarnPercent int                `json:"warn_percent"` // 1-100
}

func puConfigPath(hncDir string) string {
	return filepath.Join(hncDir, "data", "phone_usage_config.json")
}

func puDefaultConfig() puConfig {
	return puConfig{BillingDay: 1, PlanGB: map[string]float64{"1": 0, "2": 0}, WarnPercent: puDefaultWarn}
}

func puLoadConfig(hncDir string) puConfig {
	c := puDefaultConfig()
	b, err := os.ReadFile(puConfigPath(hncDir))
	if err == nil {
		var x puConfig
		if json.Unmarshal(b, &x) == nil {
			if x.BillingDay >= 1 && x.BillingDay <= 28 {
				c.BillingDay = x.BillingDay
			}
			if x.WarnPercent >= 1 && x.WarnPercent <= 100 {
				c.WarnPercent = x.WarnPercent
			}
			for k, v := range x.PlanGB {
				if (k == "1" || k == "2") && v >= 0 && v <= puMaxPlanGB {
					c.PlanGB[k] = v
				}
			}
		}
	}
	return c
}

func (c puConfig) planBytes(slot int) uint64 {
	gb := c.PlanGB[strconv.Itoa(slot)]
	if gb <= 0 {
		return 0
	}
	return uint64(math.Round(gb * puGiB))
}

// actionPhoneUsageSet 部分更新配置: 只改传了的字段, 非法值整体拒绝(不写半截)。
func actionPhoneUsageSet(hncDir string, p map[string]string) actionResp {
	c := puLoadConfig(hncDir)
	changed := 0
	if v, ok := p["billing_day"]; ok && strings.TrimSpace(v) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 || n > 28 {
			return actionResp{OK: false, Error: "bad params", Detail: "billing_day must be 1-28"}
		}
		c.BillingDay = n
		changed++
	}
	for slot, key := range map[string]string{"1": "plan_sim1_gb", "2": "plan_sim2_gb"} {
		if v, ok := p[key]; ok && strings.TrimSpace(v) != "" {
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil || math.IsNaN(f) || f < 0 || f > puMaxPlanGB {
				return actionResp{OK: false, Error: "bad params", Detail: key + " must be 0-100000 (GB, 0 = no plan)"}
			}
			c.PlanGB[slot] = f
			changed++
		}
	}
	if v, ok := p["warn_percent"]; ok && strings.TrimSpace(v) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 || n > 100 {
			return actionResp{OK: false, Error: "bad params", Detail: "warn_percent must be 1-100"}
		}
		c.WarnPercent = n
		changed++
	}
	if changed == 0 {
		return actionResp{OK: false, Error: "bad params", Detail: "nothing to set (billing_day / plan_sim1_gb / plan_sim2_gb / warn_percent)"}
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := discoverWriteAtomic(puConfigPath(hncDir), b); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: fmt.Sprintf("billing_day=%d sim1=%gGB sim2=%gGB warn=%d%%",
		c.BillingDay, c.PlanGB["1"], c.PlanGB["2"], c.WarnPercent)}
}

// ─── 周期计算 ─────────────────────────────────────────────────────

// puCycleStart 计费周期起点(本地零点)。billingDay 1-28, 所以每个月都存在这一天,
// 不会有 2 月 30 号之类的溢出。
func puCycleStart(now time.Time, billingDay int) time.Time {
	if billingDay < 1 || billingDay > 28 {
		billingDay = 1
	}
	y, m, d := now.Date()
	if d < billingDay {
		m--
		if m < time.January {
			m, y = time.December, y-1
		}
	}
	return time.Date(y, m, billingDay, 0, 0, 0, 0, now.Location())
}

// puCycleEnd 下一个周期起点(不含)
func puCycleEnd(start time.Time) time.Time {
	return time.Date(start.Year(), start.Month()+1, start.Day(), 0, 0, 0, 0, start.Location())
}

func puMidnight(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

// puPeriodStart period → 起点(本地零点)。未知 period 当 cycle。
func puPeriodStart(period string, now time.Time, billingDay int) (string, time.Time) {
	today := puMidnight(now)
	switch period {
	case "month":
		return period, time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	case "today":
		return period, today
	case "7d":
		return period, today.AddDate(0, 0, -6)
	case "30d":
		return period, today.AddDate(0, 0, -29)
	default:
		return "cycle", puCycleStart(now, billingDay)
	}
}

// ─── 引擎 ─────────────────────────────────────────────────────────

// puEnv 外部依赖(测试注入)
type puEnv struct {
	readNetDev   func() ([]byte, error)
	ifindex      func(name string) int
	hotspotIface func() string
	upstream     func() string // 默认路由出口接口名(可空)
	sim          func() puSIM
	bootID       func() string
	emitAlert    func(a alert.Alert) error
	alertsOn     func() bool
	// 模拟环境(sim_merge.go): 今天模拟设备的热点流量, 客户端视角 [下载, 上传] 按小时;
	// ok=false 表示关闭。只在 report 里叠加到今天的副本上, 不进 e.day、不落盘、不参与告警。
	simHotspot func(now time.Time) ([24][2]uint64, bool)
}

type puState struct {
	BootID   string           `json:"boot_id"`
	At       int64            `json:"at"`
	Counters map[string]puCtr `json:"counters"`
	Fired    map[string]int64 `json:"fired"` // "<slot>|<cycle YYYYMMDD>|warn|over" → ts
}

type puIfaceInfo struct {
	Name  string `json:"name"`
	Class string `json:"class"`
}

type puEngine struct {
	mu       sync.Mutex
	hncDir   string
	env      puEnv
	day      *puDay
	dirty    bool
	prev     map[string]puCtr
	baseline bool
	loaded   bool
	bootID   string
	fired    map[string]int64

	sim      puSIM
	simAt    time.Time
	lastUp   string // 最近一次判定的热点上游类别
	lastIfs  []puIfaceInfo
	lastHS   string
	lastTick time.Time
	lastErr  string
}

func newPuEngine(hncDir string, env puEnv) *puEngine {
	return &puEngine{hncDir: hncDir, env: env, fired: map[string]int64{}}
}

func puStatePath(hncDir string) string {
	return filepath.Join(hncDir, "run", "phone_usage_state.json")
}

// loadState 首轮: 读持久化计数器决定基线策略(见文件头)。调用方持锁。
func (e *puEngine) loadState() {
	e.loaded = true
	e.bootID = e.env.bootID()
	b, err := os.ReadFile(puStatePath(e.hncDir))
	if err != nil {
		return // 首次安装: 只建基线
	}
	var st puState
	if json.Unmarshal(b, &st) != nil {
		return
	}
	if st.Fired != nil {
		e.fired = st.Fired
	}
	if st.BootID != "" && e.bootID != "" && st.BootID == e.bootID {
		e.prev = st.Counters // 同一次开机: 续上差分
	} else {
		e.prev = map[string]puCtr{} // 手机重启过: 开机以来的计数全部算增量
	}
	if e.prev == nil {
		e.prev = map[string]puCtr{}
	}
	e.baseline = true
}

func (e *puEngine) saveStateLocked(now time.Time) {
	// 只保留最近 3 个周期的告警去重记录
	cut := now.AddDate(0, -3, 0).Unix()
	for k, ts := range e.fired {
		if ts < cut {
			delete(e.fired, k)
		}
	}
	st := puState{BootID: e.bootID, At: now.Unix(), Counters: e.prev, Fired: e.fired}
	b, err := json.Marshal(st)
	if err == nil {
		_ = discoverWriteAtomic(puStatePath(e.hncDir), b)
	}
}

func (e *puEngine) currentSIMLocked(now time.Time) puSIM {
	if e.simAt.IsZero() || now.Sub(e.simAt) >= puSimRefresh || now.Before(e.simAt) {
		e.sim = e.env.sim()
		e.simAt = now
	}
	return e.sim
}

// tick 采一次样并记账。返回本轮各类增量(测试用)。
func (e *puEngine) tick(now time.Time) map[string][2]uint64 {
	raw, err := e.env.readNetDev()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastTick = now
	if err != nil {
		e.lastErr = err.Error()
		return nil
	}
	e.lastErr = ""
	if !e.loaded {
		e.loadState()
	}
	parsed := puParseNetDev(raw)
	cur := make(map[string]puCtr, len(parsed))
	for name, v := range parsed {
		idx := 0
		if e.env.ifindex != nil {
			idx = e.env.ifindex(name)
		}
		cur[name] = puCtr{Ifindex: idx, Rx: v[0], Tx: v[1]}
	}
	deltas, next := puStepCounters(e.prev, cur, e.baseline)
	e.prev, e.baseline = next, true

	hs := e.env.hotspotIface()
	e.lastHS = hs
	var ifs []puIfaceInfo
	var cell, wifi, hsIf [2]uint64
	for name := range cur {
		cls := puClassifyIface(name, hs)
		if cls == "" {
			continue
		}
		ifs = append(ifs, puIfaceInfo{Name: name, Class: cls})
		d := deltas[name]
		switch cls {
		case puClassCell:
			puAdd2(&cell, d)
		case puClassWifi:
			puAdd2(&wifi, d)
		case puClassHotspot:
			puAdd2(&hsIf, d)
		}
	}
	sort.Slice(ifs, func(i, j int) bool { return ifs[i].Name < ifs[j].Name })
	e.lastIfs = ifs
	hsClient := [2]uint64{hsIf[1], hsIf[0]} // 热点口 tx = 客户端下载

	routeClass := ""
	if e.env.upstream != nil {
		up := strings.TrimPrefix(e.env.upstream(), "v4-") // clat 口归到底层 rmnet
		routeClass = puClassifyIface(up, hs)
	}
	upstream := puResolveUpstream(routeClass, cell[0]+cell[1], wifi[0]+wifi[1], hsClient[0]+hsClient[1])
	if upstream != "" {
		e.lastUp = upstream
	}
	localCell := puSplitLocal(cell, hsClient, upstream == puClassCell)
	localWifi := puSplitLocal(wifi, hsClient, upstream == puClassWifi)

	out := map[string][2]uint64{"cell": cell, "wifi": wifi, "hotspot": hsClient,
		"local_cell": localCell, "local_wifi": localWifi}
	if cell == ([2]uint64{}) && wifi == ([2]uint64{}) && hsClient == ([2]uint64{}) {
		return out
	}

	date := now.Format("20060102")
	if e.day == nil || e.day.Date != date {
		if e.day != nil && e.dirty {
			_ = puSaveDay(e.hncDir, e.day)
		}
		e.day, _ = puLoadDay(e.hncDir, date)
		e.dirty = false
	}
	d := e.day
	if cell != ([2]uint64{}) {
		key := e.currentSIMLocked(now).key()
		v := d.Cell[key]
		puAdd2(&v, cell)
		d.Cell[key] = v
		lv := d.LocalSIM[key]
		puAdd2(&lv, localCell)
		d.LocalSIM[key] = lv
	}
	puAdd2(&d.Wifi, wifi)
	puAdd2(&d.Hotspot, hsClient)
	puAdd2(&d.LocalCell, localCell)
	puAdd2(&d.LocalWifi, localWifi)
	if hsClient != ([2]uint64{}) {
		via := upstream
		if via == "" {
			via = "unknown"
		}
		v := d.HsVia[via]
		puAdd2(&v, hsClient)
		d.HsVia[via] = v
	}
	hk := strconv.Itoa(now.Hour())
	h := d.Hours[hk]
	if h == nil {
		h = &puHour{}
		d.Hours[hk] = h
	}
	puAdd2(&h.Cell, cell)
	puAdd2(&h.Wifi, wifi)
	puAdd2(&h.Hotspot, hsClient)
	puAdd2(&h.Local, localCell)
	puAdd2(&h.Local, localWifi)
	e.dirty = true
	return out
}

// flush 落盘当天 + 状态, 清理 400 天前的文件
func (e *puEngine) flush(now time.Time) {
	e.mu.Lock()
	if e.day != nil && e.dirty {
		if err := puSaveDay(e.hncDir, e.day); err == nil {
			e.dirty = false
		}
	}
	if e.loaded {
		e.saveStateLocked(now)
	}
	e.mu.Unlock()
	ents, _ := os.ReadDir(filepath.Join(e.hncDir, "run"))
	cut := now.AddDate(0, 0, -puKeepDays).Format("20060102")
	for _, en := range ents {
		n := en.Name()
		if strings.HasPrefix(n, "phone_usage.") && strings.HasSuffix(n, ".json") {
			date := strings.TrimSuffix(strings.TrimPrefix(n, "phone_usage."), ".json")
			if len(date) == 8 && date < cut {
				_ = os.Remove(filepath.Join(e.hncDir, "run", n))
			}
		}
	}
}

// days 读 [from, to] 每天(含), 今天用内存里的最新值。缺失的天跳过。
func (e *puEngine) days(from, to time.Time) []*puDay {
	var out []*puDay
	for t := puMidnight(from); !t.After(to); t = t.AddDate(0, 0, 1) {
		date := t.Format("20060102")
		e.mu.Lock()
		var d *puDay
		if e.day != nil && e.day.Date == date {
			d = e.day.clone()
		}
		e.mu.Unlock()
		if d == nil {
			var ok bool
			if d, ok = puLoadDay(e.hncDir, date); !ok {
				continue
			}
		}
		out = append(out, d)
	}
	return out
}

// daysWithSim = days, 再把模拟热点流量叠加到今天那天(副本)上: 热点 += 模拟字节,
// 上游按蜂窝算(蜂窝 += 同样字节, 记给当前默认数据卡, hotspot_via.cell += ), 本机不变。
// 返回叠加的合计(客户端视角)与是否叠加过。
func (e *puEngine) daysWithSim(from, to, now time.Time) ([]*puDay, [2]uint64, bool) {
	days := e.days(from, to)
	var tot [2]uint64
	if e.env.simHotspot == nil || now.Before(puMidnight(from)) || now.After(to) {
		return days, tot, false
	}
	hours, ok := e.env.simHotspot(now)
	if !ok {
		return days, tot, false
	}
	date := now.Format("20060102")
	var today *puDay
	for _, d := range days {
		if d.Date == date {
			today = d
		}
	}
	if today == nil {
		today = newPuDay(date)
		days = append(days, today) // 今天是区间最后一天, 追加在末尾保持顺序
	}
	e.mu.Lock()
	key := e.sim.key()
	e.mu.Unlock()
	for h := 0; h < 24; h++ {
		v := hours[h]
		if v == ([2]uint64{}) {
			continue
		}
		puAdd2(&tot, v)
		hk := strconv.Itoa(h)
		x := today.Hours[hk]
		if x == nil {
			x = &puHour{}
			today.Hours[hk] = x
		}
		puAdd2(&x.Hotspot, v)
		puAdd2(&x.Cell, v)
	}
	if tot == ([2]uint64{}) {
		return days, tot, true
	}
	puAdd2(&today.Hotspot, tot)
	c := today.Cell[key]
	puAdd2(&c, tot)
	today.Cell[key] = c
	via := today.HsVia[puClassCell]
	puAdd2(&via, tot)
	today.HsVia[puClassCell] = via
	return days, tot, true
}

// ─── 聚合 ─────────────────────────────────────────────────────────

// puSplitKey "<slot>|<carrier>" → slot, carrier
func puSplitKey(k string) (int, string) {
	i := strings.IndexByte(k, '|')
	if i < 0 {
		return 0, k
	}
	n, _ := strconv.Atoi(k[:i])
	return n, k[i+1:]
}

type puSimAgg struct {
	Rx, Tx, LocalRx, LocalTx uint64
	Carrier                  string
	Carriers                 map[string]bool
}

// puAggSIM 按卡槽合计(同一卡槽换过卡/改过名的多条 key 合并, carrier 取最后出现的)
func puAggSIM(days []*puDay) map[int]*puSimAgg {
	out := map[int]*puSimAgg{}
	for _, d := range days {
		keys := make([]string, 0, len(d.Cell))
		for k := range d.Cell {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			slot, carrier := puSplitKey(k)
			a := out[slot]
			if a == nil {
				a = &puSimAgg{Carriers: map[string]bool{}}
				out[slot] = a
			}
			v, lv := d.Cell[k], d.LocalSIM[k]
			a.Rx += v[0]
			a.Tx += v[1]
			a.LocalRx += lv[0]
			a.LocalTx += lv[1]
			a.Carrier = carrier
			a.Carriers[carrier] = true
		}
	}
	return out
}

// puAlertDecision 纯函数: 本周期各卡已用量 → 需要新发的告警(按 fired 去重, 会写入 fired)
type puAlertOut struct {
	Slot    int
	Level   string // warn | over
	Used    uint64
	Plan    uint64
	Carrier string
	Key     string
}

func puAlertDecision(cycleStart time.Time, used map[int]*puSimAgg, cfg puConfig, fired map[string]int64, nowTs int64) []puAlertOut {
	var out []puAlertOut
	cyc := cycleStart.Format("20060102")
	for _, slot := range []int{1, 2} {
		plan := cfg.planBytes(slot)
		a := used[slot]
		if plan == 0 || a == nil {
			continue
		}
		u := a.Rx + a.Tx
		level := ""
		if u >= plan {
			level = "over"
		} else if u*100 >= plan*uint64(cfg.WarnPercent) {
			level = "warn"
		}
		if level == "" {
			continue
		}
		key := fmt.Sprintf("%d|%s|%s", slot, cyc, level)
		if _, done := fired[key]; done {
			continue
		}
		fired[key] = nowTs
		if level == "over" {
			// 直接越过 100% 时预警档也视为已发, 避免之后再补一条"达到 80%"
			fired[fmt.Sprintf("%d|%s|warn", slot, cyc)] = nowTs
		}
		out = append(out, puAlertOut{Slot: slot, Level: level, Used: u, Plan: plan, Carrier: a.Carrier, Key: key})
	}
	return out
}

func puFmtBytes(n uint64) string {
	switch {
	case n >= puGiB:
		return fmt.Sprintf("%.2f GB", float64(n)/puGiB)
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	default:
		return fmt.Sprintf("%.0f KB", float64(n)/1024)
	}
}

// checkAlerts 本周期套餐预警。
func (e *puEngine) checkAlerts(now time.Time) int {
	if e.env.alertsOn != nil && !e.env.alertsOn() {
		return 0
	}
	cfg := puLoadConfig(e.hncDir)
	if cfg.planBytes(1) == 0 && cfg.planBytes(2) == 0 {
		return 0
	}
	start := puCycleStart(now, cfg.BillingDay)
	used := puAggSIM(e.days(start, now))
	e.mu.Lock()
	if !e.loaded {
		e.loadState()
	}
	outs := puAlertDecision(start, used, cfg, e.fired, now.Unix())
	e.mu.Unlock()
	n := 0
	for _, o := range outs {
		carrier := o.Carrier
		if carrier == "" {
			carrier = puUnknownSIM
		}
		var detail string
		if o.Level == "over" {
			detail = fmt.Sprintf("卡%d(%s)本计费周期已用 %s, 超出套餐 %s", o.Slot, carrier, puFmtBytes(o.Used), puFmtBytes(o.Plan))
		} else {
			detail = fmt.Sprintf("卡%d(%s)本计费周期已用 %s, 达到套餐 %s 的 %d%%", o.Slot, carrier, puFmtBytes(o.Used), puFmtBytes(o.Plan), cfg.WarnPercent)
		}
		a := alert.Alert{
			ID:     fmt.Sprintf("%s_%s_sim%d_%s", puAlertKind, o.Level, o.Slot, start.Format("20060102")),
			Ts:     now.Unix(),
			Kind:   puAlertKind,
			Detail: detail,
			Extra: map[string]interface{}{
				"slot": o.Slot, "carrier": carrier, "level": o.Level,
				"used_bytes": o.Used, "plan_bytes": o.Plan,
				"cycle_start": start.Unix(), "warn_percent": cfg.WarnPercent,
			},
		}
		if e.env.emitAlert != nil {
			if err := e.env.emitAlert(a); err != nil {
				log.Printf("phone_usage: emit alert: %v", err)
				continue
			}
		}
		n++
	}
	if len(outs) > 0 {
		e.mu.Lock()
		e.saveStateLocked(now)
		e.mu.Unlock()
	}
	return n
}

// ─── API ──────────────────────────────────────────────────────────

type puRxTx struct {
	Rx    uint64 `json:"rx"`
	Tx    uint64 `json:"tx"`
	Total uint64 `json:"total"`
}

func mkRxTx(v [2]uint64) puRxTx { return puRxTx{Rx: v[0], Tx: v[1], Total: v[0] + v[1]} }

func (e *puEngine) report(period string, now time.Time) map[string]interface{} {
	cfg := puLoadConfig(e.hncDir)
	period, since := puPeriodStart(period, now, cfg.BillingDay)
	days, simTot, simIncluded := e.daysWithSim(since, now, now)

	var cell, wifi, hs, local [2]uint64
	type dayRow struct {
		Date    string `json:"date"`
		Cell    uint64 `json:"cell"`
		Wifi    uint64 `json:"wifi"`
		Hotspot uint64 `json:"hotspot"`
		Local   uint64 `json:"local"`
	}
	byDay := []dayRow{}
	via := map[string]puRxTx{}
	for _, d := range days {
		var dc [2]uint64
		for _, v := range d.Cell {
			puAdd2(&dc, v)
		}
		puAdd2(&cell, dc)
		puAdd2(&wifi, d.Wifi)
		puAdd2(&hs, d.Hotspot)
		var dl [2]uint64
		puAdd2(&dl, d.LocalCell)
		puAdd2(&dl, d.LocalWifi)
		puAdd2(&local, dl)
		for k, v := range d.HsVia {
			x := via[k]
			x.Rx += v[0]
			x.Tx += v[1]
			x.Total += v[0] + v[1]
			via[k] = x
		}
		ds := d.Date
		if len(ds) == 8 {
			ds = ds[:4] + "-" + ds[4:6] + "-" + ds[6:]
		}
		byDay = append(byDay, dayRow{Date: ds, Cell: dc[0] + dc[1], Wifi: d.Wifi[0] + d.Wifi[1],
			Hotspot: d.Hotspot[0] + d.Hotspot[1], Local: dl[0] + dl[1]})
	}

	// 按卡: 本 period 的量 + 本计费周期的量(套餐百分比永远按计费周期算)
	cycleStart := puCycleStart(now, cfg.BillingDay)
	agg := puAggSIM(days)
	cycAgg := agg
	if period != "cycle" {
		cycDays, _, _ := e.daysWithSim(cycleStart, now, now)
		cycAgg = puAggSIM(cycDays)
	}
	e.mu.Lock()
	curSIM := e.sim
	simKnown := !e.simAt.IsZero()
	ifs := append([]puIfaceInfo(nil), e.lastIfs...)
	lastUp, lastHS, lastErr, lastTick := e.lastUp, e.lastHS, e.lastErr, e.lastTick
	e.mu.Unlock()

	slots := map[int]bool{}
	for s := range agg {
		slots[s] = true
	}
	for s := range cycAgg {
		slots[s] = true
	}
	for _, s := range []int{1, 2} {
		if cfg.planBytes(s) > 0 {
			slots[s] = true
		}
	}
	if simKnown && curSIM.Slot > 0 {
		slots[curSIM.Slot] = true
	}
	slotList := make([]int, 0, len(slots))
	for s := range slots {
		slotList = append(slotList, s)
	}
	sort.Ints(slotList)
	bySim := []map[string]interface{}{}
	for _, s := range slotList {
		a := agg[s]
		if a == nil {
			a = &puSimAgg{Carriers: map[string]bool{}}
		}
		carrier := a.Carrier
		if c := cycAgg[s]; carrier == "" && c != nil {
			carrier = c.Carrier
		}
		if carrier == "" && simKnown && curSIM.Slot == s {
			carrier = curSIM.Carrier
		}
		if s == 0 {
			carrier = puUnknownSIM
		}
		var cycUsed uint64
		if c := cycAgg[s]; c != nil {
			cycUsed = c.Rx + c.Tx
		}
		plan := cfg.planBytes(s)
		var pct interface{}
		if plan > 0 {
			pct = math.Round(float64(cycUsed)*1000/float64(plan)) / 10
		}
		carriers := []string{}
		for c := range a.Carriers {
			carriers = append(carriers, c)
		}
		sort.Strings(carriers)
		bySim = append(bySim, map[string]interface{}{
			"slot": s, "carrier": carrier, "carriers": carriers,
			"rx": a.Rx, "tx": a.Tx, "total": a.Rx + a.Tx,
			"local_rx": a.LocalRx, "local_tx": a.LocalTx,
			"hotspot_total": puSub(a.Rx+a.Tx, a.LocalRx+a.LocalTx),
			"cycle_used":    cycUsed, "plan_bytes": plan, "used_pct": pct,
			"is_default_data": simKnown && curSIM.Slot == s && s > 0,
		})
	}

	simDetect := "unknown"
	if simKnown && curSIM.Slot > 0 {
		simDetect = "ok"
	}
	src := map[string]interface{}{
		"sim_detect":    simDetect,
		"sim_source":    curSIM.Source,
		"ifaces":        ifs,
		"hotspot_iface": lastHS,
		"upstream":      lastUp,
		"counters":      "/proc/net/dev",
	}
	if !lastTick.IsZero() {
		src["last_sample"] = lastTick.Unix()
	}
	if lastErr != "" {
		src["error"] = lastErr
	}
	var cur interface{}
	if simKnown {
		cur = map[string]interface{}{"slot": curSIM.Slot, "carrier": curSIM.Carrier, "sub_id": curSIM.SubID}
	}

	resp := map[string]interface{}{
		"period":      period,
		"since":       since.Unix(),
		"until":       now.Unix(),
		"billing_day": cfg.BillingDay,
		"cycle_start": cycleStart.Unix(),
		"cycle_end":   puCycleEnd(cycleStart).Unix(),
		"config": map[string]interface{}{
			"billing_day": cfg.BillingDay, "warn_percent": cfg.WarnPercent,
			"plan_sim1_gb": cfg.PlanGB["1"], "plan_sim2_gb": cfg.PlanGB["2"],
		},
		"totals": map[string]puRxTx{
			"cellular": mkRxTx(cell), "wifi": mkRxTx(wifi),
			"hotspot": mkRxTx(hs), "local": mkRxTx(local),
		},
		"hotspot_via": via,
		"by_sim":      bySim,
		"by_day":      byDay,
		"default_sim": cur,
		"hotspot_by_device": map[string]interface{}{
			"endpoint": "/api/usage_month",
			"note":     "每台热点设备的本自然月 rx/tx 见 /api/usage_month(iptables 统计口径, 自然月而非计费周期)",
		},
		"sources": src,
	}
	if simIncluded {
		resp["sim_included"] = true
		resp["sim_hotspot"] = mkRxTx(simTot)
	}
	if period == "today" {
		hours := make([]map[string]interface{}, 0, 24)
		var today *puDay
		if len(days) > 0 {
			today = days[len(days)-1]
		}
		for h := 0; h < 24; h++ {
			row := map[string]interface{}{"h": h, "cell": uint64(0), "wifi": uint64(0), "hotspot": uint64(0), "local": uint64(0)}
			if today != nil {
				if x := today.Hours[strconv.Itoa(h)]; x != nil {
					row["cell"] = x.Cell[0] + x.Cell[1]
					row["wifi"] = x.Wifi[0] + x.Wifi[1]
					row["hotspot"] = x.Hotspot[0] + x.Hotspot[1]
					row["local"] = x.Local[0] + x.Local[1]
				}
			}
			hours = append(hours, row)
		}
		resp["by_hour"] = hours
	}
	return resp
}

// ─── 接线 ─────────────────────────────────────────────────────────

var (
	puOnce sync.Once
	puEng  *puEngine
)

func (s *server) phoneUsage() *puEngine {
	puOnce.Do(func() {
		hncDir := s.hncDir
		acfg := alert.NewConfig(hncDir)
		puEng = newPuEngine(hncDir, puEnv{
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
			upstream:     puDefaultRouteIface,
			sim:          puDetectSIM,
			bootID: func() string {
				b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
				return strings.TrimSpace(string(b))
			},
			emitAlert:  func(a alert.Alert) error { return puAppendAlert(acfg.AlertsJSONLPath, a) },
			alertsOn:   func() bool { return alert.LoadConfig(acfg.AlertsConfigPath).Enabled },
			simHotspot: s.simHotspotHours,
		})
	})
	return puEng
}

// puAppendAlert 追加到 run/alerts.jsonl(与 dpid alert 包同格式; O_APPEND 单行写, 与 dpid 并发安全)
func puAppendAlert(path string, a alert.Alert) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// PhoneUsageLoop 每 60 秒采样+落盘, 每 5 分钟检查一次套餐告警; 停机时补采一次并落盘。
func (s *server) PhoneUsageLoop(stop <-chan struct{}) {
	e := s.phoneUsage()
	e.tick(time.Now())
	tk := time.NewTicker(puEvery)
	defer tk.Stop()
	lastAlert := time.Time{}
	for {
		select {
		case <-stop:
			now := time.Now()
			e.tick(now)
			e.flush(now)
			return
		case now := <-tk.C:
			e.tick(now)
			e.flush(now)
			if now.Sub(lastAlert) >= puSimRefresh {
				e.checkAlerts(now)
				lastAlert = now
			}
		}
	}
}

func (s *server) apiPhoneUsage(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	switch period {
	case "", "cycle", "month", "today", "7d", "30d":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "period must be cycle|month|today|7d|30d"})
		return
	}
	writeJSON(w, http.StatusOK, s.phoneUsage().report(period, time.Now()))
}
