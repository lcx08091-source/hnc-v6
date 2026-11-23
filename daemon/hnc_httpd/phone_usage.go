// phone_usage.go — 本月流量 / 本机与热点用量(手机自身的月度流量, 按网络、按卡、按"谁用的"拆分)
//
// 数据源: /proc/net/dev(每 60 秒一次 + 停机时一次), 对每个接口的累计 rx/tx 做差分。
// 与 app_usage.go(conntrack, 只看热点客户端)不同, 这里看的是整机网卡计数 ——
// 和运营商计费最接近的口径。
//
// 接口分类(puClassifyIface):
//   - cell    蜂窝: rmnet_data* / rmnetN / ccmni* / seth_lte* / sipa_eth* / wwan*(iface_patterns.go)
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
//   v5.20.1: 手机开 VPN 时 `ip route get` 是 tun0 —— 改为优先用 iface_detect.json 的
//   tethering 上游(phone_usage_upstream.go); tun* 不计数, 本机经 VPN 的字节计在物理口上。
//
// 按卡归属: 每 5 分钟刷新一次"默认数据卡"(phone_usage_sim.go), 本分钟的蜂窝增量
// 全部记给这张卡; 识别不到记 "0|蜂窝(未知卡)"。
//
// 存储(跨月历史账单迁出 32M tmpfs 至 data/, 兼容回退读旧 run/ 并平滑迁移):
//   data/phone_usage.YYYYMMDD.json  一天一个, 保留 400 天(兼容回退读旧 run/phone_usage.YYYYMMDD.json)
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// v5.20: 蜂窝 / AP 名字表统一到 iface_patterns.go(与 bin/hnc_iface.sh 同一份),
// 补上展锐 sipa_ethN / seth_*N 与 Android 12+ 双频桥接 ap_br_*。
var (
	puCellRE = hncCellIfaceRE
	puAPRE   = hncAPIfaceRE
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
	return filepath.Join(hncDir, "data", "phone_usage."+date+".json")
}

func puLegacyDayPath(hncDir, date string) string {
	return filepath.Join(hncDir, "run", "phone_usage."+date+".json")
}

func puLoadDay(hncDir, date string) (*puDay, bool) {
	for _, p := range []string{puDayPath(hncDir, date), puLegacyDayPath(hncDir, date)} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var d puDay
		if json.Unmarshal(b, &d) != nil {
			continue
		}
		d.normalize(date)
		return &d, true
	}
	return newPuDay(date), false
}

var puWriteSeq atomic.Uint64

// puWriteAtomic 严格遵循死定律七: Write / Sync / Close / Rename 任一步失败(特别是 ENOSPC)时
// 立即 os.Remove(tmp), 严禁遗留 0 字节 .tmp.* 孤儿文件。
func puWriteAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	seq := puWriteSeq.Add(1)
	tmp := fmt.Sprintf("%s.tmp.%d.%d", path, os.Getpid(), seq)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0o644)
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func puSaveDay(hncDir string, d *puDay) error {
	if err := os.MkdirAll(filepath.Join(hncDir, "data"), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return puWriteAtomic(puDayPath(hncDir, d.Date), b)
}

func puReadDaysFromDisk(hncDir string, from, to time.Time) []*puDay {
	var out []*puDay
	for t := puMidnight(from); !t.After(to); t = t.AddDate(0, 0, 1) {
		if d, ok := puLoadDay(hncDir, t.Format("20060102")); ok {
			out = append(out, d)
		}
	}
	return out
}

func puIsAllDigits8(s string) bool {
	if len(s) != 8 {
		return false
	}
	for i := 0; i < 8; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// puMigrateLegacyRunDays 平滑迁移旧版残留在 run/(32M tmpfs)下的 phone_usage.YYYYMMDD.json 至 data/。
func puMigrateLegacyRunDays(hncDir, cutDate string) {
	if hncDir == "" {
		return
	}
	runDir := filepath.Join(hncDir, "run")
	ents, err := os.ReadDir(runDir)
	if err != nil || len(ents) == 0 {
		return
	}
	dataDir := filepath.Join(hncDir, "data")
	_ = os.MkdirAll(dataDir, 0o755)
	for _, en := range ents {
		if en.IsDir() {
			continue
		}
		n := en.Name()
		if !strings.HasPrefix(n, "phone_usage.") || !strings.HasSuffix(n, ".json") {
			continue
		}
		date := strings.TrimSuffix(strings.TrimPrefix(n, "phone_usage."), ".json")
		if !puIsAllDigits8(date) {
			continue
		}
		src := filepath.Join(runDir, n)
		if cutDate != "" && date < cutDate {
			_ = os.Remove(src)
			continue
		}
		dst := filepath.Join(dataDir, n)
		if dstBytes, err := os.ReadFile(dst); err == nil {
			var existing puDay
			if json.Unmarshal(dstBytes, &existing) == nil {
				_ = os.Remove(src)
				continue
			}
		}
		srcBytes, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		var parsed puDay
		if json.Unmarshal(srcBytes, &parsed) != nil {
			continue
		}
		if puWriteAtomic(dst, srcBytes) == nil {
			_ = os.Remove(src)
		}
	}
}

// ─── 配置 ─────────────────────────────────────────────────────────

type puConfig struct {
	BillingDay   int                `json:"billing_day"`               // 1-28
	PlanGB       map[string]float64 `json:"plan_gb"`                   // "1"/"2" -> GB(0 = 无套餐)
	AnchorGB     map[string]float64 `json:"anchor_gb,omitempty"`       // v5.38.0: 运营商掌厅手动校准锚点 GB
	AnchorBase   map[string]uint64  `json:"anchor_base,omitempty"`     // v5.38.0: 设置校准锚点时的 HNC 周期累计基准字节
	AnchorNsBase map[string]uint64  `json:"anchor_ns_base,omitempty"`  // v6.1.0: 设置校准锚点时的系统 netstats 周期累计基准字节
	AnchorAt     map[string]int64   `json:"anchor_at,omitempty"`       // v6.1.0: 设置校准锚点时的 Unix 秒时间戳
	AnchorCycle  string             `json:"anchor_cycle,omitempty"`    // YYYYMMDD
	WarnPercent  int                `json:"warn_percent"`              // 1-100
	UseNetstats  string             `json:"use_netstats,omitempty"`    // v5.21: auto|prefer|off(stats_calibration.go)
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
			switch x.UseNetstats {
			case "auto", "prefer", "off":
				c.UseNetstats = x.UseNetstats
			}
			for k, v := range x.PlanGB {
				if (k == "1" || k == "2") && v >= 0 && v <= puMaxPlanGB {
					c.PlanGB[k] = v
				}
			}
			if len(x.AnchorGB) > 0 {
				c.AnchorGB = map[string]float64{}
				for k, v := range x.AnchorGB {
					if (k == "1" || k == "2") && v >= 0 && v <= puMaxPlanGB {
						c.AnchorGB[k] = v
					}
				}
			}
			if len(x.AnchorBase) > 0 {
				c.AnchorBase = map[string]uint64{}
				for k, v := range x.AnchorBase {
					if k == "1" || k == "2" {
						c.AnchorBase[k] = v
					}
				}
			}
			if len(x.AnchorNsBase) > 0 {
				c.AnchorNsBase = map[string]uint64{}
				for k, v := range x.AnchorNsBase {
					if k == "1" || k == "2" {
						c.AnchorNsBase[k] = v
					}
				}
			}
			if len(x.AnchorAt) > 0 {
				c.AnchorAt = map[string]int64{}
				for k, v := range x.AnchorAt {
					if (k == "1" || k == "2") && v > 0 {
						c.AnchorAt[k] = v
					}
				}
			}
			c.AnchorCycle = x.AnchorCycle
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
	return actionPhoneUsageSetAt(hncDir, p, time.Now())
}

func actionPhoneUsageSetAt(hncDir string, p map[string]string, now time.Time) actionResp {
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
	if v, ok := p["use_netstats"]; ok && strings.TrimSpace(v) != "" { // v5.21
		switch v = strings.ToLower(strings.TrimSpace(v)); v {
		case "auto", "prefer", "off":
			c.UseNetstats = v
			changed++
		default:
			return actionResp{OK: false, Error: "bad params", Detail: "use_netstats must be auto|prefer|off"}
		}
	}
	cycStart := puCycleStart(now, c.BillingDay)
	cycStr := cycStart.Format("20060102")
	for slot, key := range map[string]string{"1": "anchor_sim1_gb", "2": "anchor_sim2_gb"} {
		if v, ok := p[key]; ok {
			sv := strings.TrimSpace(v)
			if sv == "" || sv == "-1" || strings.EqualFold(sv, "clear") {
				if c.AnchorGB != nil {
					delete(c.AnchorGB, slot)
				}
				if c.AnchorBase != nil {
					delete(c.AnchorBase, slot)
				}
				if c.AnchorNsBase != nil {
					delete(c.AnchorNsBase, slot)
				}
				if c.AnchorAt != nil {
					delete(c.AnchorAt, slot)
				}
				changed++
				continue
			}
			f, err := strconv.ParseFloat(sv, 64)
			if err != nil || math.IsNaN(f) || f < 0 || f > puMaxPlanGB {
				return actionResp{OK: false, Error: "bad params", Detail: key + " must be 0-100000 or -1 to clear"}
			}
			if c.AnchorCycle != cycStr {
				c.AnchorGB = map[string]float64{}
				c.AnchorBase = map[string]uint64{}
				c.AnchorNsBase = map[string]uint64{}
				c.AnchorAt = map[string]int64{}
				c.AnchorCycle = cycStr
			}
			if c.AnchorGB == nil {
				c.AnchorGB = map[string]float64{}
			}
			if c.AnchorBase == nil {
				c.AnchorBase = map[string]uint64{}
			}
			if c.AnchorNsBase == nil {
				c.AnchorNsBase = map[string]uint64{}
			}
			if c.AnchorAt == nil {
				c.AnchorAt = map[string]int64{}
			}
			slotNum, _ := strconv.Atoi(slot)
			var cycDays []*puDay
			var eng *puEngine
			if puEng != nil && puEng.hncDir == hncDir {
				eng = puEng
				cycDays = eng.days(cycStart, now)
			} else {
				cycDays = puReadDaysFromDisk(hncDir, cycStart, now)
			}
			agg := puAggSIM(cycDays)
			var calRes *calResult
			if cal := calGet(hncDir); cal != nil {
				if r := cal.result(); calUsable(r, cycStart, now) {
					calRes = r
				}
			}
			maxSlots, presentSlots, slotsKnown := 2, map[int]puSIM(nil), false
			if eng != nil {
				maxSlots, presentSlots, slotsKnown = eng.simTopologySnapshot()
			}
			targetSlot, carrierHint := puPickUniqueCellSlot(calRes, maxSlots, presentSlots, slotsKnown)
			_ = puReconcileAndStripInvalidSlots(agg, maxSlots, targetSlot, carrierHint)

			var baseBytes uint64
			if a := agg[slotNum]; a != nil {
				baseBytes = a.Rx + a.Tx
			}
			c.AnchorGB[slot] = f
			c.AnchorBase[slot] = baseBytes
			c.AnchorAt[slot] = now.Unix()
			delete(c.AnchorNsBase, slot)
			if calRes != nil {
				for _, ns := range calRes.NetstatsCellBySim {
					if ns.Slot == slotNum {
						c.AnchorNsBase[slot] = ns.Total
						break
					}
				}
			}
			changed++
		}
	}
	if changed == 0 {
		return actionResp{OK: false, Error: "bad params", Detail: "nothing to set (billing_day / plan_sim1_gb / plan_sim2_gb / warn_percent / use_netstats)"}
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := puWriteAtomic(puConfigPath(hncDir), b); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	calKick(hncDir) // v5.21: 计费日/对账模式/锚点变了, 后台尽快重新对账
	return actionResp{OK: true, Detail: fmt.Sprintf("billing_day=%d sim1=%gGB sim2=%gGB warn=%d%% use_netstats=%s",
		c.BillingDay, c.PlanGB["1"], c.PlanGB["2"], c.WarnPercent, c.netstatsMode())}
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
	// v5.20.1: 热点上游 / 本机出口 / VPN(优先于 upstream; nil 时退回 upstream)
	upstreamInfo func() puUpInfo
	sim          func() puSIM
	simProbe     func() puSIMProbe // v6.1.0: 完整双卡在位与自定义名探测(优先于 sim)
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
	Fired    map[string]int64 `json:"fired"` // "<slot>|<cycle YYYYMMDD>|warn|over" -> ts
}

type puIfaceInfo struct {
	Name  string `json:"name"`
	Class string `json:"class"`
}

// puEngine 整机与按卡流量统计引擎。
// 死定律二: 64 位原子字段置于结构体 offset 0, 保证 32 位 armeabi-v7a 8 字节边界对齐。
type puEngine struct {
	simAtNs       atomic.Int64 // offset 0: 上次 SIM 探测 UnixNano
	simCachedSlot atomic.Int32
	loadedFlag    atomic.Bool

	mu          sync.Mutex
	hncDir      string
	env         puEnv
	day         *puDay
	dirty       bool
	pendingDays map[string]*puDay // 跨零点尚未成功落盘的历史脏日快照(写失败保留重试)
	prev        map[string]puCtr
	baseline    bool
	loaded      bool
	bootID      string
	fired       map[string]int64

	sim           puSIM
	simSlots      map[int]puSIM
	simSlotsKnown bool
	maxSlots      int
	simAt         time.Time
	lastUp        string // 最近一次判定的热点上游类别
	lastUpIf      puUpInfo
	lastIfs       []puIfaceInfo
	lastHS        string
	lastTick      time.Time
	lastErr       string
	guard         clockGuard // v5.20: 时钟不可信/跳变检测(clock_guard.go)
}

func newPuEngine(hncDir string, env puEnv) *puEngine {
	return &puEngine{
		hncDir:      hncDir,
		env:         env,
		pendingDays: map[string]*puDay{},
		fired:       map[string]int64{},
		maxSlots:    2,
	}
}

func puStatePath(hncDir string) string {
	return filepath.Join(hncDir, "run", "phone_usage_state.json")
}

// loadState 首轮: 读持久化计数器决定基线策略(见文件头)。调用方持锁。
func (e *puEngine) loadState() {
	var boot string
	if e.env.bootID != nil {
		boot = e.env.bootID()
	}
	b, err := os.ReadFile(puStatePath(e.hncDir))
	e.applyLoadedStateLocked(boot, b, err)
}

func (e *puEngine) applyLoadedStateLocked(boot string, b []byte, readErr error) {
	e.loaded = true
	e.loadedFlag.Store(true)
	e.bootID = boot
	if readErr != nil {
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
		_ = puWriteAtomic(puStatePath(e.hncDir), b)
	}
}

// probeSIMOutsideLock 在互斥锁外执行 SIM 探测(死定律四: 严禁持锁执行阻塞子进程)。
func (e *puEngine) probeSIMOutsideLock() (puSIMProbe, bool) {
	if e.env.simProbe != nil {
		p := e.env.simProbe()
		if p.MaxSlots <= 0 {
			p.MaxSlots = 2
		}
		return p, true
	}
	if e.env.sim != nil {
		s := e.env.sim()
		slots := map[int]puSIM{}
		if s.Slot >= 1 && s.Slot <= 2 {
			slots[s.Slot] = s
		}
		return puSIMProbe{
			Active:     s,
			Slots:      slots,
			SlotsKnown: false,
			MaxSlots:   2,
		}, true
	}
	return puSIMProbe{MaxSlots: 2}, false
}

func (e *puEngine) applySIMProbeLocked(p puSIMProbe, now time.Time) {
	if p.MaxSlots >= 1 {
		e.maxSlots = p.MaxSlots
	} else if e.maxSlots <= 0 {
		e.maxSlots = 2
	}
	e.sim = p.Active
	e.simSlots = make(map[int]puSIM, len(p.Slots))
	for k, v := range p.Slots {
		if k >= 1 && k <= e.maxSlots {
			e.simSlots[k] = v
		}
	}
	if e.sim.Slot >= 1 && e.sim.Slot <= e.maxSlots {
		if _, ok := e.simSlots[e.sim.Slot]; !ok {
			e.simSlots[e.sim.Slot] = e.sim
		}
	}
	e.simSlotsKnown = p.SlotsKnown || e.maxSlots == 1
	e.simAt = now
	e.simAtNs.Store(now.UnixNano())
	e.simCachedSlot.Store(int32(e.sim.Slot))
}

func (e *puEngine) effMaxSlotsLocked() int {
	if e.maxSlots >= 1 {
		return e.maxSlots
	}
	return 2
}

func (e *puEngine) simTopologySnapshot() (maxSlots int, present map[int]puSIM, known bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	maxSlots = e.effMaxSlotsLocked()
	if len(e.simSlots) > 0 {
		present = make(map[int]puSIM, len(e.simSlots))
		for k, v := range e.simSlots {
			if k >= 1 && k <= maxSlots {
				present[k] = v
			}
		}
	}
	known = e.simSlotsKnown || maxSlots == 1
	return maxSlots, present, known
}

// puReconcileDayUnknownSIM 当日内确认了真实上网物理卡 curSIM(Slot >= 1) 时,
// 若今日记录中存在 "0|蜂窝(未知卡)"(或任何 slot<=0 桶)且今日仅出现过 curSIM.Slot 这唯一一个有效物理卡槽,
// 直接把今日 slot=0 字节归并进 curSIM.key() 并删除未知卡键。
func puReconcileDayUnknownSIM(d *puDay, curSIM puSIM, maxSlots int) bool {
	if d == nil || curSIM.Slot < 1 || curSIM.Slot > maxSlots {
		return false
	}
	var unkKeys []string
	for k := range d.Cell {
		slot, _ := puSplitKey(k)
		if slot <= 0 {
			unkKeys = append(unkKeys, k)
		} else if slot != curSIM.Slot {
			// 今日已出现另一张有效物理卡槽流量, 不做单日盲目归并
			return false
		}
	}
	for k := range d.LocalSIM {
		slot, _ := puSplitKey(k)
		if slot > 0 && slot != curSIM.Slot {
			return false
		}
	}
	if len(unkKeys) == 0 {
		return false
	}
	sort.Strings(unkKeys)
	dstKey := curSIM.key()
	for _, uk := range unkKeys {
		if uk == dstKey {
			continue
		}
		if cv, ok := d.Cell[uk]; ok {
			curV := d.Cell[dstKey]
			puAdd2(&curV, cv)
			d.Cell[dstKey] = curV
			delete(d.Cell, uk)
		}
		if lv, ok := d.LocalSIM[uk]; ok {
			curLV := d.LocalSIM[dstKey]
			puAdd2(&curLV, lv)
			d.LocalSIM[dstKey] = curLV
			delete(d.LocalSIM, uk)
		}
	}
	return true
}

func (e *puEngine) snapshotPendingDaysLocked() []*puDay {
	if len(e.pendingDays) == 0 {
		return nil
	}
	dates := make([]string, 0, len(e.pendingDays))
	for dt := range e.pendingDays {
		dates = append(dates, dt)
	}
	sort.Strings(dates)
	snaps := make([]*puDay, 0, len(dates))
	for _, dt := range dates {
		if d := e.pendingDays[dt]; d != nil {
			snaps = append(snaps, d.clone())
		}
	}
	return snaps
}

// retrySavePendingDays 在锁外尝试落盘历史跨零点未写成功的脏日数据;
// 若 puSaveDay 返回错误, 严禁清空 pendingDays 中的对应条目, 留待下一轮重试直至成功。
func (e *puEngine) retrySavePendingDays(snaps []*puDay) {
	for _, snap := range snaps {
		if snap == nil {
			continue
		}
		if err := puSaveDay(e.hncDir, snap); err == nil {
			e.mu.Lock()
			delete(e.pendingDays, snap.Date)
			e.mu.Unlock()
		}
	}
}

// tick 采一次样并记账。返回本轮各类增量(测试用)。
// 死定律四: 所有可能阻塞的外部命令(upstreamInfo / upstream / sim / simProbe)严格在 e.mu.Lock() 之前完成!
func (e *puEngine) tick(now time.Time) map[string][2]uint64 {
	raw, err := e.env.readNetDev()
	if err != nil {
		e.mu.Lock()
		e.lastTick = now
		e.lastErr = err.Error()
		e.mu.Unlock()
		return nil
	}

	parsed := puParseNetDev(raw)
	hs := ""
	if e.env.hotspotIface != nil {
		hs = e.env.hotspotIface()
	}
	cur := make(map[string]puCtr, len(parsed))
	hasCellIface := false
	for name, v := range parsed {
		idx := 0
		if e.env.ifindex != nil {
			idx = e.env.ifindex(name)
		}
		cur[name] = puCtr{Ifindex: idx, Rx: v[0], Tx: v[1]}
		if !hasCellIface && puClassifyIface(name, hs) == puClassCell && (v[0] > 0 || v[1] > 0) {
			hasCellIface = true
		}
	}

	// 锁外采集上游路由出口(可能调用 `ip route get 1.1.1.1` 子进程)
	var ui puUpInfo
	if e.env.upstreamInfo != nil {
		ui = e.env.upstreamInfo()
	} else if e.env.upstream != nil {
		ui.Local = e.env.upstream()
	}
	ui = ui.normalized()

	// 锁外按需刷新 SIM 物理卡槽状态(可能调用 `dumpsys isub` / `telephony.registry` / 回退 `content query`)
	nowNs := now.UnixNano()
	lastSimNs := e.simAtNs.Load()
	needSim := lastSimNs == 0 ||
		nowNs-lastSimNs >= int64(puSimRefresh) ||
		nowNs < lastSimNs ||
		(e.simCachedSlot.Load() <= 0 && hasCellIface)
	var simProbeRes puSIMProbe
	var didProbeSim bool
	if needSim {
		simProbeRes, didProbeSim = e.probeSIMOutsideLock()
	}

	var bootStr string
	var stateBytes []byte
	var stateErr error
	needInitLoad := !e.loadedFlag.Load()
	if needInitLoad {
		if e.env.bootID != nil {
			bootStr = e.env.bootID()
		}
		stateBytes, stateErr = os.ReadFile(puStatePath(e.hncDir))
	}

	e.mu.Lock()
	e.lastTick = now
	e.lastErr = ""
	if !e.loaded {
		if needInitLoad {
			e.applyLoadedStateLocked(bootStr, stateBytes, stateErr)
		} else {
			e.loadState()
		}
	}
	if didProbeSim {
		e.applySIMProbeLocked(simProbeRes, now)
	}

	// v5.20: 时钟不可信 -> 不消费计数器(恢复后差分记到正确的天); 跳变或长时间
	// 不可信后恢复 -> 重建基线, 不把跨跳变的一大坨字节记进一个小时/错的天。
	e.guard.name = "phone_usage"
	switch e.guard.step(e.hncDir, now) {
	case clockInsane:
		e.mu.Unlock()
		return nil
	case clockJump:
		_, e.prev = puStepCounters(nil, cur, false)
		e.baseline = true
		e.mu.Unlock()
		return nil
	}
	deltas, next := puStepCounters(e.prev, cur, e.baseline)
	e.prev, e.baseline = next, true

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

	e.lastUpIf = ui
	routeClass := puClassifyIface(strings.TrimPrefix(ui.routeIface(), "v4-"), hs) // clat 口归到底层 rmnet
	upstream := puResolveUpstream(routeClass, cell[0]+cell[1], wifi[0]+wifi[1], hsClient[0]+hsClient[1])
	if upstream != "" {
		e.lastUp = upstream
	}
	localCell := puSplitLocal(cell, hsClient, upstream == puClassCell)
	localWifi := puSplitLocal(wifi, hsClient, upstream == puClassWifi)

	out := map[string][2]uint64{"cell": cell, "wifi": wifi, "hotspot": hsClient,
		"local_cell": localCell, "local_wifi": localWifi}

	maxSlots := e.effMaxSlotsLocked()
	date := now.Format("20060102")
	if cell == ([2]uint64{}) && wifi == ([2]uint64{}) && hsClient == ([2]uint64{}) {
		if e.day != nil && e.day.Date == date && e.sim.Slot >= 1 {
			if puReconcileDayUnknownSIM(e.day, e.sim, maxSlots) {
				e.dirty = true
			}
		}
		pendSnaps := e.snapshotPendingDaysLocked()
		e.mu.Unlock()
		e.retrySavePendingDays(pendSnaps)
		return out
	}

	if e.day == nil || e.day.Date != date {
		if e.day != nil && e.dirty {
			if e.pendingDays == nil {
				e.pendingDays = map[string]*puDay{}
			}
			// 跨零点先把昨日脏账放入 pendingDays, 落盘成功前绝不丢弃
			e.pendingDays[e.day.Date] = e.day.clone()
			if len(e.pendingDays) > 32 {
				oldest := ""
				for k := range e.pendingDays {
					if oldest == "" || k < oldest {
						oldest = k
					}
				}
				if oldest != "" && oldest != e.day.Date {
					delete(e.pendingDays, oldest)
				}
			}
		}
		if pd, ok := e.pendingDays[date]; ok && pd != nil {
			e.day = pd.clone()
			e.dirty = true
		} else {
			e.day, _ = puLoadDay(e.hncDir, date)
			e.dirty = false
		}
	}
	d := e.day
	if cell != ([2]uint64{}) {
		curSIM := e.sim
		if curSIM.Slot > maxSlots {
			curSIM = puSIM{Slot: 0, Carrier: puUnknownSIM}
		}
		key := curSIM.key()
		v := d.Cell[key]
		puAdd2(&v, cell)
		d.Cell[key] = v
		lv := d.LocalSIM[key]
		puAdd2(&lv, localCell)
		d.LocalSIM[key] = lv
	}
	if e.sim.Slot >= 1 && e.sim.Slot <= maxSlots {
		_ = puReconcileDayUnknownSIM(d, e.sim, maxSlots)
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

	pendSnaps := e.snapshotPendingDaysLocked()
	e.mu.Unlock()
	e.retrySavePendingDays(pendSnaps)
	return out
}

// flush 落盘待重试跨日账单 + 当天 + 状态, 平滑迁移旧 run/ 账单并清理 400 天前的文件
func (e *puEngine) flush(now time.Time) {
	e.mu.Lock()
	pendSnaps := e.snapshotPendingDaysLocked()
	var curSnap *puDay
	if e.day != nil && e.dirty {
		curSnap = e.day.clone()
	}
	e.mu.Unlock()

	e.retrySavePendingDays(pendSnaps)
	if curSnap != nil {
		if err := puSaveDay(e.hncDir, curSnap); err == nil {
			e.mu.Lock()
			if e.day != nil && e.day.Date == curSnap.Date {
				// 仅当落盘期间没有产生更新的字节时清除 dirty; 若期间有新采样则下一轮继续写
				if reflectDayEqual(e.day, curSnap) {
					e.dirty = false
				}
			}
			delete(e.pendingDays, curSnap.Date)
			e.mu.Unlock()
		}
	}

	// v5.20: 时钟不可信时不写状态(At 会是错的时间)、不做保留期清理
	sane := clockSane(e.hncDir, now)
	if sane {
		e.mu.Lock()
		if e.loaded {
			e.saveStateLocked(now)
		}
		e.mu.Unlock()
	}
	if !sane {
		return
	}
	cut := now.AddDate(0, 0, -puKeepDays).Format("20060102")
	puMigrateLegacyRunDays(e.hncDir, cut)
	ents, _ := os.ReadDir(filepath.Join(e.hncDir, "data"))
	for _, en := range ents {
		n := en.Name()
		if strings.HasPrefix(n, "phone_usage.") && strings.HasSuffix(n, ".json") {
			date := strings.TrimSuffix(strings.TrimPrefix(n, "phone_usage."), ".json")
			if puIsAllDigits8(date) && date < cut {
				_ = os.Remove(filepath.Join(e.hncDir, "data", n))
			}
		}
	}
}

func reflectDayEqual(a, b *puDay) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Date != b.Date || a.Wifi != b.Wifi || a.Hotspot != b.Hotspot ||
		a.LocalCell != b.LocalCell || a.LocalWifi != b.LocalWifi || len(a.Cell) != len(b.Cell) {
		return false
	}
	for k, v := range a.Cell {
		if b.Cell[k] != v {
			return false
		}
	}
	return true
}

// days 读 [from, to] 每天(含), 今天及尚未成功落盘的跨零点脏天优先取内存里的最新值。缺失的天跳过。
func (e *puEngine) days(from, to time.Time) []*puDay {
	var out []*puDay
	for t := puMidnight(from); !t.After(to); t = t.AddDate(0, 0, 1) {
		date := t.Format("20060102")
		e.mu.Lock()
		var d *puDay
		if e.day != nil && e.day.Date == date {
			d = e.day.clone()
		} else if pd := e.pendingDays[date]; pd != nil {
			d = pd.clone()
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
	simCopy := e.sim
	if simCopy.Slot <= 0 {
		simCopy = puSIM{Slot: 1, Carrier: "中国移动"}
	}
	key := simCopy.key()
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

// ─── 聚合与未知卡确定性归并 ────────────────────────────────────────

// puSplitKey "<slot>|<carrier>" -> slot, carrier
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

const puSilentSimNoiseMaxBytes = 65536 // 64KB: 副卡待机驻网微小信令噪声阈值

// puPickUniqueCellSlot 判断账期内是否可确定性锁定唯一耗流物理卡槽(1..maxSlots):
//  1. 整机当前明确仅插有 1 张物理 SIM 卡(或单卡硬件 maxSlots == 1); 或
//  2. 系统 NetworkStats 可用, 且账期内只有唯一 1 张物理卡槽有蜂窝流量(WindowTotal > 0, 另一卡槽 < 65536 字节)。
func puPickUniqueCellSlot(cal *calResult, maxSlots int, present map[int]puSIM, slotsKnown bool) (int, string) {
	if maxSlots <= 0 {
		maxSlots = 2
	}
	if maxSlots == 1 {
		return 1, present[1].Carrier
	}
	if slotsKnown && len(present) == 1 {
		for s, info := range present {
			if s >= 1 && s <= maxSlots {
				return s, info.Carrier
			}
		}
	}
	if cal != nil && cal.NetstatsOK && !cal.Stale {
		winBySlot := map[int]uint64{}
		carrierBySlot := map[int]string{}
		for _, c := range cal.NetstatsCellBySim {
			if c.Slot < 1 || c.Slot > maxSlots {
				continue
			}
			v := c.WindowTotal
			if cal.WindowStart == 0 && v == 0 {
				v = c.Total
			}
			winBySlot[c.Slot] += v
			if carrierBySlot[c.Slot] == "" && c.Carrier != "" {
				carrierBySlot[c.Slot] = c.Carrier
			}
		}
		var majorSlots, nonZeroSlots []int
		for s := 1; s <= maxSlots; s++ {
			v := winBySlot[s]
			if v >= puSilentSimNoiseMaxBytes {
				majorSlots = append(majorSlots, s)
			}
			if v > 0 {
				nonZeroSlots = append(nonZeroSlots, s)
			}
		}
		picked := 0
		if len(majorSlots) == 1 {
			picked = majorSlots[0]
		} else if len(majorSlots) == 0 && len(nonZeroSlots) == 1 {
			picked = nonZeroSlots[0]
		}
		if picked >= 1 && picked <= maxSlots {
			hint := carrierBySlot[picked]
			if hint == "" {
				hint = present[picked].Carrier
			}
			return picked, hint
		}
	}
	return 0, ""
}

// puReconcileAndStripInvalidSlots 执行确定性 slot=0 流量归并, 并剥离一切 slot <= 0 或 slot > maxSlots 的非法桶,
// 返回无法唯一归属的残余蜂窝字节数(供顶层 unattributed_* 字段展示)。
func puReconcileAndStripInvalidSlots(m map[int]*puSimAgg, maxSlots int, targetSlot int, carrierHint string) uint64 {
	if m == nil {
		return 0
	}
	if maxSlots <= 0 {
		maxSlots = 2
	}
	if targetSlot >= 1 && targetSlot <= maxSlots {
		if unk := m[0]; unk != nil && (unk.Rx > 0 || unk.Tx > 0 || unk.LocalRx > 0 || unk.LocalTx > 0) {
			dst := m[targetSlot]
			if dst == nil {
				dst = &puSimAgg{Carriers: map[string]bool{}}
				m[targetSlot] = dst
			}
			dst.Rx += unk.Rx
			dst.Tx += unk.Tx
			dst.LocalRx += unk.LocalRx
			dst.LocalTx += unk.LocalTx
			if dst.Carrier == "" && carrierHint != "" {
				dst.Carrier = carrierHint
				dst.Carriers[carrierHint] = true
			}
			delete(m, 0)
		}
	}
	var unattributed uint64
	for s, a := range m {
		if s < 1 || s > maxSlots {
			if a != nil {
				unattributed += a.Rx + a.Tx
			}
			delete(m, s)
		}
	}
	return unattributed
}

// puAlertDecision 纯函数: 本周期各卡已用量 -> 需要新发的告警(按 fired 去重, 会写入 fired)
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
	if !clockSane(e.hncDir, now) { // v5.20: 周期/去重 key 依赖日期
		return 0
	}
	cfg := puLoadConfig(e.hncDir)
	if cfg.planBytes(1) == 0 && cfg.planBytes(2) == 0 {
		return 0
	}
	start := puCycleStart(now, cfg.BillingDay)
	used := puAggSIM(e.days(start, now))

	maxSlots, presentSlots, slotsKnown := e.simTopologySnapshot()
	var calRes *calResult
	if cfg.netstatsMode() != "off" {
		if cal := calGet(e.hncDir); cal != nil {
			if r := cal.result(); calUsable(r, start, now) {
				calRes = r
			}
		}
	}
	targetSlot, carrierHint := puPickUniqueCellSlot(calRes, maxSlots, presentSlots, slotsKnown)
	_ = puReconcileAndStripInvalidSlots(used, maxSlots, targetSlot, carrierHint)

	used = puCalPreferUsed(e.hncDir, cfg, start, now, used) // prefer / autoPromote / 手动校准锚点同源对齐
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
			carrier = presentSlots[o.Slot].Carrier
		}
		if carrier == "" {
			carrier = "SIM" + strconv.Itoa(o.Slot)
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
	maxSlots := e.effMaxSlotsLocked()
	presentSlots := make(map[int]puSIM, len(e.simSlots))
	for k, v := range e.simSlots {
		if k >= 1 && k <= maxSlots {
			presentSlots[k] = v
		}
	}
	slotsKnown := e.simSlotsKnown || maxSlots == 1
	ifs := append([]puIfaceInfo(nil), e.lastIfs...)
	lastUp, lastHS, lastErr, lastTick := e.lastUp, e.lastHS, e.lastErr, e.lastTick
	lastUpIf := e.lastUpIf
	e.mu.Unlock()

	var calRes *calResult
	if cfg.netstatsMode() != "off" {
		if cal := calGet(e.hncDir); cal != nil {
			if r := cal.result(); calUsable(r, cycleStart, now) {
				calRes = r
			}
		}
	}
	cycTargetSlot, cycCarrierHint := puPickUniqueCellSlot(calRes, maxSlots, presentSlots, slotsKnown)
	unattributedCycle := puReconcileAndStripInvalidSlots(cycAgg, maxSlots, cycTargetSlot, cycCarrierHint)
	unattributedCell := unattributedCycle
	if period != "cycle" {
		periodCal := calRes
		if since.Before(cycleStart) {
			// 跨上个计费周期的窗口(如 30d)不套用本周期 netstats 唯一耗流推断, 仅允许单物理卡在位确定性归并
			periodCal = nil
		}
		perTargetSlot, perCarrierHint := puPickUniqueCellSlot(periodCal, maxSlots, presentSlots, slotsKnown)
		unattributedCell = puReconcileAndStripInvalidSlots(agg, maxSlots, perTargetSlot, perCarrierHint)
	}

	slots := map[int]bool{}
	for s := range agg {
		if s >= 1 && s <= maxSlots {
			slots[s] = true
		}
	}
	for s := range cycAgg {
		if s >= 1 && s <= maxSlots {
			slots[s] = true
		}
	}
	for s := range presentSlots {
		if s >= 1 && s <= maxSlots {
			slots[s] = true
		}
	}
	for s := 1; s <= maxSlots; s++ {
		if cfg.planBytes(s) > 0 {
			slots[s] = true
		}
	}
	if simKnown && curSIM.Slot >= 1 && curSIM.Slot <= maxSlots {
		slots[curSIM.Slot] = true
	}

	// 硬护栏: 严禁放入任何 slot <= 0 或 slot > maxSlots 的条目(双卡手机永远最多只有卡1、卡2)
	slotList := make([]int, 0, maxSlots)
	for s := range slots {
		if s >= 1 && s <= maxSlots {
			slotList = append(slotList, s)
		}
	}
	sort.Ints(slotList)
	bySim := []map[string]interface{}{}
	for _, s := range slotList {
		if s < 1 || s > maxSlots {
			continue
		}
		a := agg[s]
		if a == nil {
			a = &puSimAgg{Carriers: map[string]bool{}}
		}
		carrier := ""
		if ps, ok := presentSlots[s]; ok && ps.Carrier != "" {
			carrier = ps.Carrier
		}
		if carrier == "" {
			carrier = a.Carrier
		}
		if c := cycAgg[s]; carrier == "" && c != nil {
			carrier = c.Carrier
		}
		if carrier == "" && simKnown && curSIM.Slot == s {
			carrier = curSIM.Carrier
		}
		if carrier == "" {
			carrier = "SIM" + strconv.Itoa(s)
		}
		customName := presentSlots[s].CustomName
		if customName == "" && simKnown && curSIM.Slot == s {
			customName = curSIM.CustomName
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
			if c != "" && c != puUnknownSIM {
				carriers = append(carriers, c)
			}
		}
		sort.Strings(carriers)
		row := map[string]interface{}{
			"slot": s, "carrier": carrier, "carriers": carriers,
			"rx": a.Rx, "tx": a.Tx, "total": a.Rx + a.Tx,
			"local_rx": a.LocalRx, "local_tx": a.LocalTx,
			"hotspot_total":   puSub(a.Rx+a.Tx, a.LocalRx+a.LocalTx),
			"cycle_used":      cycUsed,
			"plan_bytes":      plan,
			"used_pct":        pct,
			"is_default_data": simKnown && curSIM.Slot == s && s > 0,
		}
		if customName != "" && customName != carrier {
			row["custom_name"] = customName
		}
		bySim = append(bySim, row)
	}

	simDetect := "unknown"
	if simKnown && curSIM.Slot >= 1 && curSIM.Slot <= maxSlots {
		simDetect = "ok"
	}
	src := map[string]interface{}{
		"sim_detect":    simDetect,
		"sim_source":    curSIM.Source,
		"ifaces":        ifs,
		"hotspot_iface": lastHS,
		"upstream":      lastUp,
		// v5.20.1
		"tether_upstream": lastUpIf.Tether,
		"local_upstream":  lastUpIf.Local,
		"vpn_active":      lastUpIf.VPN,
		"counters":        "/proc/net/dev",
	}
	if !lastTick.IsZero() {
		src["last_sample"] = lastTick.Unix()
	}
	if lastErr != "" {
		src["error"] = lastErr
	}
	var cur interface{}
	if simKnown && curSIM.Slot >= 1 && curSIM.Slot <= maxSlots {
		cm := map[string]interface{}{"slot": curSIM.Slot, "carrier": curSIM.Carrier, "sub_id": curSIM.SubID}
		if curSIM.CustomName != "" && curSIM.CustomName != curSIM.Carrier {
			cm["custom_name"] = curSIM.CustomName
		}
		cur = cm
	} else if simKnown {
		cur = map[string]interface{}{"slot": 0, "carrier": puUnknownSIM, "sub_id": curSIM.SubID}
	}

	resp := map[string]interface{}{
		"period":      period,
		"since":       since.Unix(),
		"until":       now.Unix(),
		"billing_day": cfg.BillingDay,
		"cycle_start": cycleStart.Unix(),
		"cycle_end":   puCycleEnd(cycleStart).Unix(),
		"max_slots":   maxSlots,
		"config": map[string]interface{}{
			"billing_day": cfg.BillingDay, "warn_percent": cfg.WarnPercent,
			"plan_sim1_gb": cfg.PlanGB["1"], "plan_sim2_gb": cfg.PlanGB["2"],
			"anchor_sim1_gb": cfg.AnchorGB["1"], "anchor_sim2_gb": cfg.AnchorGB["2"],
			"use_netstats": cfg.netstatsMode(),
		},
		"totals": map[string]puRxTx{
			"cellular": mkRxTx(cell), "wifi": mkRxTx(wifi),
			"hotspot": mkRxTx(hs), "local": mkRxTx(local),
		},
		"hotspot_via":              via,
		"by_sim":                   bySim,
		"unattributed_cell_bytes":  unattributedCell,
		"unattributed_cycle_bytes": unattributedCycle,
		"by_day":                   byDay,
		"default_sim":              cur,
		"hotspot_by_device": map[string]interface{}{
			"endpoint": "/api/usage_month",
			"note":     "每台热点设备的本月 rx/tx 见 /api/usage_month(v5.26 起为计费月口径, 与设备卡「本月」同源)",
		},
		"sources": src,
	}
	if simIncluded {
		resp["sim_included"] = true
		resp["sim_hotspot"] = mkRxTx(simTot)
	}
	puCalAttach(e.hncDir, cfg, cycleStart, now, resp, bySim) // v5.21: 系统 NetworkStats 对账(stats_calibration.go)
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
			upstreamInfo: func() puUpInfo {
				return puPickUpstream(readIfaceDetect(hncDir), time.Now().Unix(), puDefaultRouteIface())
			},
			sim:      puDetectSIM,
			simProbe: puDetectSIMProbe,
			bootID: func() string {
				b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
				return strings.TrimSpace(string(b))
			},
			emitAlert:  func(a alert.Alert) error { return alert.Append(acfg.AlertsJSONLPath, a) },
			alertsOn:   func() bool { return alert.LoadConfig(acfg.AlertsConfigPath).Enabled },
			simHotspot: s.simHotspotHours,
		})
	})
	return puEng
}

// 原套餐告警追加副本 v5.26 T7 删除: 统一走 alert.Append(带 flock)。

// PhoneUsageLoop 每 60 秒采样+落盘, 每 5 分钟检查一次套餐告警; 停机时补采一次并落盘。
func (s *server) PhoneUsageLoop(stop <-chan struct{}) {
	e := s.phoneUsage()
	now0 := time.Now()
	e.tick(now0)
	e.flush(now0)
	lastAlert := time.Time{}
	// v5.22: 基准 puEvery(60s); 热点未开且熄屏无界面 300s(power_sched.go phone_usage)。
	// 计数器差分, 放慢不丢字节(只是小时桶归属更粗)。
	last := time.Now()
	for {
		if !powerWait(stop, "phone_usage", last, nil) {
			now := time.Now()
			e.tick(now)
			e.flush(now)
			return
		}
		now := time.Now()
		last = now
		e.tick(now)
		e.flush(now)
		if now.Sub(lastAlert) >= puSimRefresh {
			e.checkAlerts(now)
			lastAlert = now
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
