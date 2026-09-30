// sim.go — 模拟环境(调试模式): 在真机上注入虚拟设备, 用来调试界面。
//
// 状态: data/sim.json {enabled, devices:[...], seed}(tmp+rename 原子写)。
// 模拟设备 MAC 一律是本地管理地址 02:5e:00:xx:xx:xx, 与真实网卡厂商地址不可能
// 重合; 输入一律校验这个前缀。
//
// 安全: 任何针对设备的写动作(限速/延迟/黑名单/白名单/封锁/按应用限速/改名…),
// 只要 mac 是模拟设备, 就在 dispatchAction 最前面被 simInterceptAction 截走,
// 只改 sim.json 里那台设备的状态, 绝不 runBin/exec —— tc/iptables 永远碰不到。
//
// 关闭时: 所有合并点先读一个 atomic.Bool, false 直接返回, 行为与没有这个功能完全一致。
//
// 速率: 由 (时间, seed, mac) 决定的平滑噪声生成(可复现), 叠加 jitter; 黑名单/离线 → 0,
// 限速 → 封顶。今日累计字节(按小时/应用)在内存里按速率积分, 不落盘。
// 读接口合并见 sim_merge.go。
//
// Actions(POST /api/action, params 均为字符串):
//
//	sim_set            {enabled}
//	sim_device_add     {name?, type?, rx?, tx?, app?, jitter?, ip?, vendor?, hostname?}
//	sim_device_update  {mac, name?, hostname?, vendor?, type?, ip?, rx?, tx?, jitter?, app?, app_name?,
//	                    category?, blocked?, offline?, limit_down_mbps?, limit_up_mbps?, delay_ms?}
//	sim_device_del     {mac}
//	sim_clear          {}
//	sim_preset         {preset: home|busy|idle}
//
// GET /api/sim → {ok, enabled, count, seed, devices:[...], presets, types}

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	simMACPrefix  = "02:5e:00:"
	simMaxDevices = 32
	simBackfillDT = 60 // 首次积分(零点 → 现在)的步长, 秒
	simLiveDT     = 10 // 之后增量积分的步长, 秒
)

var simMACRE = regexp.MustCompile(`^02:5e:00(:[0-9a-f]{2}){3}$`)
var simCategoryRE = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// isSimMAC: 小写、冒号分隔、02:5e:00 前缀。
func isSimMAC(mac string) bool {
	return strings.HasPrefix(mac, simMACPrefix) && simMACRE.MatchString(mac)
}

// simNormMAC 把 AA-BB-.. / 大写 统一成 aa:bb:..; 非法返回 ""。
func simNormMAC(s string) string {
	return normalizeMAC(s)
}

var simTypes = []string{"tv", "phone", "laptop", "tablet", "game", "iot", "pc"}

func simValidType(t string) bool {
	for _, x := range simTypes {
		if x == t {
			return true
		}
	}
	return false
}

// simDevice 一台模拟设备。rx_bps/tx_bps 是「基准」速率(字节/秒, rx=下行);
// 实际速率在基准上叠加 jitter 噪声并受 blocked/offline/限速约束。
type simDevice struct {
	MAC           string             `json:"mac"`
	IP            string             `json:"ip"`
	Name          string             `json:"name"`
	Hostname      string             `json:"hostname"`
	Vendor        string             `json:"vendor"`
	Type          string             `json:"type"`
	RxBps         int64              `json:"rx_bps"`
	TxBps         int64              `json:"tx_bps"`
	Jitter        float64            `json:"jitter"`
	AppID         string             `json:"app_id"`
	AppName       string             `json:"app_name"`
	Category      string             `json:"category"`
	Blocked       bool               `json:"blocked"`
	LimitDownMbps float64            `json:"limit_down_mbps"`
	LimitUpMbps   float64            `json:"limit_up_mbps"`
	DelayMs       int                `json:"delay_ms"`
	Created       int64              `json:"created"`
	JitterMs      int                `json:"jitter_ms,omitempty"`
	LossPct       float64            `json:"loss_pct,omitempty"`
	SQM           bool               `json:"sqm,omitempty"`
	Whitelist     bool               `json:"whitelist,omitempty"`
	Offline       bool               `json:"offline,omitempty"`
	AppLimits     map[string]float64 `json:"app_limits,omitempty"` // app_id → down_mbps
	ConnBlocks    []connBlock        `json:"conn_blocks,omitempty"`
	Ident         map[string]string  `json:"ident,omitempty"` // device_ident_set 的手动纠正
}

type simFile struct {
	Enabled bool        `json:"enabled"`
	Devices []simDevice `json:"devices"`
	Seed    int64       `json:"seed"`
}

// simAcc 今日累计(内存, 不落盘)
type simAcc struct {
	day        string
	last       int64 // 已积分到的时刻
	backfillTo int64 // 早于此刻的部分是首次回填(按作息曲线加权)
	hours      [24][2]uint64
}

type simStore struct {
	hncDir string
	once   sync.Once
	mu     sync.Mutex
	f      simFile
	on     atomic.Bool // enabled && len(devices)>0 的快路径标志由 hasDev 配合
	hasDev atomic.Bool
	acc    map[string]*simAcc
}

var simStores sync.Map // hncDir → *simStore

func simFor(hncDir string) *simStore {
	v, ok := simStores.Load(hncDir)
	if !ok {
		v, _ = simStores.LoadOrStore(hncDir, &simStore{hncDir: hncDir, acc: map[string]*simAcc{}})
	}
	st := v.(*simStore)
	st.once.Do(st.load)
	return st
}

func simPath(hncDir string) string { return filepath.Join(hncDir, "data", "sim.json") }

func (st *simStore) load() {
	st.mu.Lock()
	defer st.mu.Unlock()
	var f simFile
	if b, err := os.ReadFile(simPath(st.hncDir)); err == nil {
		_ = json.Unmarshal(b, &f)
	}
	kept := f.Devices[:0]
	seen := map[string]bool{}
	for _, d := range f.Devices {
		d.MAC = simNormMAC(d.MAC)
		if !isSimMAC(d.MAC) || seen[d.MAC] {
			continue // 非模拟前缀的条目一律丢弃, 永不当真实设备处理
		}
		seen[d.MAC] = true
		kept = append(kept, d)
	}
	f.Devices = kept
	if f.Seed == 0 {
		f.Seed = time.Now().UnixNano()&0x7fffffff | 1
	}
	st.f = f
	st.syncFlagsLocked()
}

func (st *simStore) syncFlagsLocked() {
	st.on.Store(st.f.Enabled)
	st.hasDev.Store(st.f.Enabled && len(st.f.Devices) > 0)
}

func (st *simStore) saveLocked() error {
	st.syncFlagsLocked()
	b, err := json.MarshalIndent(st.f, "", "  ")
	if err != nil {
		return err
	}
	return discoverWriteAtomic(simPath(st.hncDir), b)
}

func (st *simStore) findLocked(mac string) *simDevice {
	for i := range st.f.Devices {
		if st.f.Devices[i].MAC == mac {
			return &st.f.Devices[i]
		}
	}
	return nil
}

// simOn: 模拟环境已开启(可能还没有设备)
func (s *server) simOn() bool { return simFor(s.hncDir).on.Load() }

// simActive: 已开启且至少一台模拟设备 —— 读接口合并只看它
func (s *server) simActive() bool { return simFor(s.hncDir).hasDev.Load() }

// ─── 速率生成 ─────────────────────────────────────────────────────────

func simHash(seed int64, mac, stream string, i int64) float64 {
	h := fnv.New64a()
	var b [16]byte
	binary.LittleEndian.PutUint64(b[:8], uint64(seed))
	binary.LittleEndian.PutUint64(b[8:], uint64(i))
	_, _ = h.Write(b[:])
	_, _ = h.Write([]byte(mac))
	_, _ = h.Write([]byte(stream))
	return float64(h.Sum64()>>11) / float64(1<<53) // [0,1)
}

// simSmooth 值噪声: 每 period 秒一个随机格点, smoothstep 插值, 结果 [0,1)
func simSmooth(seed int64, mac, stream string, t, period float64) float64 {
	x := t / period
	i := math.Floor(x)
	f := x - i
	a := simHash(seed, mac, stream, int64(i))
	b := simHash(seed, mac, stream, int64(i)+1)
	f = f * f * (3 - 2*f)
	return a + (b-a)*f
}

// simNoise 两个八度叠加, 结果 [-1,1]
func simNoise(seed int64, mac, stream string, t float64) float64 {
	n := 0.65*simSmooth(seed, mac, stream, t, 17) + 0.35*simSmooth(seed, mac, stream+"/f", t, 4)
	return n*2 - 1
}

func mbpsToBytes(m float64) float64 { return m * 1e6 / 8 }

// simRate 某时刻的实际速率(字节/秒)。保证: 0 ≤ rx ≤ 2·rx_bps, 且限速时 ≤ 限速值;
// blocked / offline → 0。
func simRate(d *simDevice, seed int64, t float64) (rx, tx int64) {
	if d.Blocked || d.Offline {
		return 0, 0
	}
	j := d.Jitter
	if j < 0 || math.IsNaN(j) {
		j = 0
	}
	if j > 1 {
		j = 1
	}
	r := float64(d.RxBps) * (1 + j*simNoise(seed, d.MAC, "rx", t))
	w := float64(d.TxBps) * (1 + j*simNoise(seed, d.MAC, "tx", t))
	capDown := 0.0
	if d.LimitDownMbps > 0 {
		capDown = mbpsToBytes(d.LimitDownMbps)
	}
	if al := d.AppLimits[d.AppID]; al > 0 && (capDown == 0 || mbpsToBytes(al) < capDown) {
		capDown = mbpsToBytes(al) // 按应用限速也作用到主应用
	}
	if capDown > 0 && r > capDown {
		r = capDown * (0.94 + 0.05*simSmooth(seed, d.MAC, "cd", t, 6)) // 贴着上限小幅抖
	}
	if d.LimitUpMbps > 0 {
		c := mbpsToBytes(d.LimitUpMbps)
		if w > c {
			w = c * (0.94 + 0.05*simSmooth(seed, d.MAC, "cu", t, 6))
		}
	}
	if r < 0 {
		r = 0
	}
	if w < 0 {
		w = 0
	}
	return int64(r), int64(w)
}

// 家庭作息曲线(仅用于首次回填零点至今的历史)
var simDiurnal = [24]float64{.35, .2, .12, .08, .07, .08, .15, .35, .45, .4, .4, .45,
	.6, .5, .45, .45, .5, .6, .75, .9, 1, 1, .85, .6}

// advanceLocked 把每台设备的累计积分到 now。首次见到(或跨日)从本地零点回填。
func (st *simStore) advanceLocked(now time.Time) {
	today := now.Format("20060102")
	midnight := localDayStart(now).Unix()
	n := now.Unix()
	live := map[string]bool{}
	for i := range st.f.Devices {
		d := &st.f.Devices[i]
		live[d.MAC] = true
		a := st.acc[d.MAC]
		if a == nil || a.day != today {
			a = &simAcc{day: today, last: midnight, backfillTo: n}
			st.acc[d.MAC] = a
		}
		for t := a.last; t < n; {
			dt := int64(simLiveDT)
			w := 1.0
			hour := (t - midnight) / 3600
			if hour < 0 {
				hour = 0
			}
			if hour > 23 {
				hour = 23
			}
			if t < a.backfillTo {
				dt = simBackfillDT
				w = simDiurnal[hour]
			}
			if t+dt > n {
				dt = n - t
			}
			rx, tx := simRate(d, st.f.Seed, float64(t))
			a.hours[hour][0] += uint64(float64(rx) * w * float64(dt))
			a.hours[hour][1] += uint64(float64(tx) * w * float64(dt))
			t += dt
		}
		a.last = n
	}
	for mac := range st.acc {
		if !live[mac] {
			delete(st.acc, mac)
		}
	}
}

// simView 某一刻一台模拟设备的只读快照
type simView struct {
	D        simDevice
	Rx, Tx   int64 // 当前速率 字节/秒
	Hours    [24][2]uint64
	Down, Up uint64 // 今日累计
}

// snapshot 开启时返回所有模拟设备的快照(并推进累计); 关闭时 nil。
func (st *simStore) snapshot(now time.Time) ([]simView, int64) {
	if !st.hasDev.Load() {
		return nil, 0
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.f.Enabled {
		return nil, 0
	}
	st.advanceLocked(now)
	out := make([]simView, 0, len(st.f.Devices))
	for _, d := range st.f.Devices {
		v := simView{D: simCloneDevice(d)}
		v.Rx, v.Tx = simRate(&d, st.f.Seed, float64(now.Unix()))
		if a := st.acc[d.MAC]; a != nil {
			v.Hours = a.hours
			for h := 0; h < 24; h++ {
				v.Down += a.hours[h][0]
				v.Up += a.hours[h][1]
			}
		}
		out = append(out, v)
	}
	return out, st.f.Seed
}

func simCloneDevice(d simDevice) simDevice {
	if d.AppLimits != nil {
		m := make(map[string]float64, len(d.AppLimits))
		for k, v := range d.AppLimits {
			m[k] = v
		}
		d.AppLimits = m
	}
	if d.ConnBlocks != nil {
		d.ConnBlocks = append([]connBlock(nil), d.ConnBlocks...)
	}
	if d.Ident != nil {
		m := make(map[string]string, len(d.Ident))
		for k, v := range d.Ident {
			m[k] = v
		}
		d.Ident = m
	}
	return d
}

// ─── 应用库(DPI 规则库, 取不到用内置) ────────────────────────────────

type simApp struct {
	ID, Name, Cat string
	Domains       []string
}

var simBuiltinApps = []simApp{
	{"douyin", "抖音", "video", []string{"douyin.com", "douyinvod.com", "amemv.com", "douyinpic.com"}},
	{"bilibili", "哔哩哔哩", "video", []string{"bilibili.com", "bilivideo.com", "hdslb.com"}},
	{"iqiyi", "爱奇艺", "video", []string{"iqiyi.com", "qiyipic.com", "iq.com"}},
	{"tencent_video", "腾讯视频", "video", []string{"v.qq.com", "video.qq.com", "gtimg.com"}},
	{"weixin", "微信", "social", []string{"weixin.qq.com", "wx.qq.com", "qpic.cn"}},
	{"qq", "QQ", "social", []string{"qq.com", "qlogo.cn", "gtimg.cn"}},
	{"weibo", "微博", "social", []string{"weibo.com", "weibo.cn", "sinaimg.cn"}},
	{"taobao", "淘宝", "shopping", []string{"taobao.com", "alicdn.com", "tmall.com"}},
	{"honor_of_kings", "王者荣耀", "game", []string{"sgame.qq.com", "smoba.qq.com", "gcloud.qq.com"}},
	{"genshin", "原神", "game", []string{"mihoyo.com", "yuanshen.com", "hoyoverse.com"}},
	{"netease_music", "网易云音乐", "music", []string{"music.163.com", "music.126.net"}},
	{"qqmusic", "QQ 音乐", "music", []string{"y.qq.com", "stream.qqmusic.qq.com"}},
	{"zhihu", "知乎", "news", []string{"zhihu.com", "zhimg.com"}},
	{"tencent_meeting", "腾讯会议", "office", []string{"meeting.tencent.com", "wemeet.qq.com"}},
	{"deepseek", "DeepSeek", "ai", []string{"deepseek.com", "chat.deepseek.com"}},
	{"baidu_netdisk", "百度网盘", "download", []string{"pan.baidu.com", "baidupcs.com"}},
	{"mijia", "米家", "iot", []string{"io.mi.com", "iot.mi.com"}},
}

var simLib struct {
	mu   sync.Mutex
	at   map[string]time.Time
	apps map[string][]simApp
}

// simAppLibrary 从 DPI 规则库挑出真应用(有域名、分级为 app)。来源依次:
// <hnc>/etc/dpi_rules.d, <hnc>/data/dpi_rules.d, <MODDIR>/data/dpi_rules.d,
// <MODDIR>/data/dpi_rules.json; 都没有 → 内置清单。缓存 10 分钟。
func simAppLibrary(hncDir string) []simApp {
	simLib.mu.Lock()
	defer simLib.mu.Unlock()
	if simLib.apps == nil {
		simLib.apps, simLib.at = map[string][]simApp{}, map[string]time.Time{}
	}
	if a, ok := simLib.apps[hncDir]; ok && time.Since(simLib.at[hncDir]) < 10*time.Minute {
		return a
	}
	modDir := "/data/adb/modules/hotspot_network_control"
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "service.path")); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			modDir = v
		}
	}
	var files []string
	for _, dir := range []string{filepath.Join(hncDir, "etc", "dpi_rules.d"), filepath.Join(hncDir, "data", "dpi_rules.d"),
		filepath.Join(modDir, "data", "dpi_rules.d")} {
		m, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		sort.Strings(m)
		files = append(files, m...)
	}
	files = append(files, filepath.Join(modDir, "data", "dpi_rules.json"))
	seen := map[string]bool{}
	var out []simApp
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil || len(b) > 4<<20 {
			continue
		}
		var doc struct {
			Rules []struct {
				ID       string   `json:"id"`
				App      string   `json:"app"`
				Category string   `json:"category"`
				Suffixes []string `json:"suffixes"`
			} `json:"rules"`
		}
		if json.Unmarshal(b, &doc) != nil {
			continue
		}
		for _, r := range doc.Rules {
			if seen[r.ID] || !validAppID(r.ID) || r.App == "" || len(r.Suffixes) == 0 || appTier(r.Category) != tierApp {
				continue
			}
			var doms []string
			for _, d := range r.Suffixes {
				d = strings.ToLower(strings.TrimSpace(d))
				if domainRe.MatchString(d) && len(doms) < 4 {
					doms = append(doms, d)
				}
			}
			if len(doms) == 0 {
				continue
			}
			seen[r.ID] = true
			out = append(out, simApp{ID: r.ID, Name: r.App, Cat: r.Category, Domains: doms})
		}
	}
	if len(out) == 0 {
		out = simBuiltinApps
	}
	simLib.apps[hncDir], simLib.at[hncDir] = out, time.Now()
	return out
}

func simFindApp(hncDir, id string) (simApp, bool) {
	for _, a := range simAppLibrary(hncDir) {
		if a.ID == id {
			return a, true
		}
	}
	for _, a := range simBuiltinApps {
		if a.ID == id {
			return a, true
		}
	}
	return simApp{}, false
}

// 各类型偏好的应用分类
var simTypeCats = map[string][]string{
	"tv":     {"video"},
	"phone":  {"video", "social", "shopping", "music", "news"},
	"laptop": {"office", "ai", "download", "video"},
	"tablet": {"video", "education", "reading", "game"},
	"game":   {"game"},
	"iot":    {"iot", "music", "smart_home"},
	"pc":     {"download", "game", "video", "office"},
}

func simPickApp(hncDir, typ string, rng *rand.Rand) simApp {
	lib := simAppLibrary(hncDir)
	var cands []simApp
	for _, c := range simTypeCats[typ] {
		for _, a := range lib {
			if a.Cat == c {
				cands = append(cands, a)
			}
		}
		if len(cands) >= 3 {
			break
		}
	}
	if len(cands) == 0 {
		for _, c := range simTypeCats[typ] {
			for _, a := range simBuiltinApps {
				if a.Cat == c {
					cands = append(cands, a)
				}
			}
		}
	}
	if len(cands) == 0 {
		cands = lib
	}
	return cands[rng.Intn(len(cands))]
}

// ─── 设备模板 ─────────────────────────────────────────────────────────

type simTpl struct {
	names   []string
	vendors []string
	host    string
	rx      [2]int64 // 基准下行范围 字节/秒
	txRatio [2]float64
	jitter  [2]float64
}

var simTpls = map[string]simTpl{
	"tv":     {[]string{"小米电视", "海信电视", "索尼电视", "TCL 电视", "客厅电视"}, []string{"Xiaomi", "Hisense", "Sony", "TCL"}, "MiTV", [2]int64{1500 << 10, 4 << 20}, [2]float64{.02, .05}, [2]float64{.15, .35}},
	"phone":  {[]string{"iPhone 15", "小米 14", "华为 Mate 60", "OPPO Find X7", "vivo X100", "一加 12", "红米 K70"}, []string{"Apple", "Xiaomi", "HUAWEI", "OPPO", "vivo", "OnePlus"}, "Phone", [2]int64{100 << 10, 1500 << 10}, [2]float64{.05, .2}, [2]float64{.3, .7}},
	"laptop": {[]string{"MacBook Air", "ThinkPad X1", "华为 MateBook", "小米笔记本", "拯救者"}, []string{"Apple", "Lenovo", "HUAWEI", "Xiaomi"}, "LAPTOP", [2]int64{300 << 10, 3 << 20}, [2]float64{.08, .3}, [2]float64{.3, .6}},
	"tablet": {[]string{"iPad Air", "小米平板 6", "华为 MatePad", "iPad mini"}, []string{"Apple", "Xiaomi", "HUAWEI"}, "Pad", [2]int64{200 << 10, 2 << 20}, [2]float64{.03, .1}, [2]float64{.2, .5}},
	"game":   {[]string{"Switch", "PS5", "Xbox Series X", "Steam Deck"}, []string{"Nintendo", "Sony", "Microsoft", "Valve"}, "Console", [2]int64{50 << 10, 600 << 10}, [2]float64{.2, .5}, [2]float64{.4, .8}},
	"iot":    {[]string{"小爱音箱", "米家摄像头", "扫地机器人", "智能插座", "空气净化器"}, []string{"Xiaomi", "Roborock", "Aqara"}, "IoT", [2]int64{2 << 10, 30 << 10}, [2]float64{.5, 3}, [2]float64{.4, .9}},
	"pc":     {[]string{"台式机", "游戏主机 PC", "NAS", "工作站"}, []string{"Lenovo", "Dell", "ASUS", "Synology"}, "DESKTOP", [2]int64{500 << 10, 5 << 20}, [2]float64{.05, .25}, [2]float64{.3, .6}},
}

// simIdentType 模拟类型 → dpid ident.type
func simIdentType(t string) string {
	switch t {
	case "laptop":
		return "pc"
	case "game":
		return "console"
	}
	return t
}

func simOS(typ, vendor string) string {
	switch {
	case vendor == "Apple" && typ == "laptop":
		return "macOS"
	case vendor == "Apple":
		return "iOS"
	case vendor == "HUAWEI":
		return "HarmonyOS"
	case typ == "laptop" || typ == "pc":
		return "Windows"
	case typ == "tv":
		return "Android TV"
	case typ == "game":
		return ""
	case typ == "iot":
		return "Linux"
	}
	return "Android"
}

func (st *simStore) newMACLocked(rng *rand.Rand) string {
	realMACs := map[string]bool{}
	if raw, err := readJSON(filepath.Join(st.hncDir, "data", "devices.json")); err == nil {
		if m, ok := raw.(map[string]interface{}); ok {
			for k := range m {
				realMACs[strings.ToLower(k)] = true
			}
		}
	}
	for i := 0; i < 1000; i++ {
		mac := fmt.Sprintf("%s%02x:%02x:%02x", simMACPrefix, rng.Intn(256), rng.Intn(256), rng.Intn(256))
		if st.findLocked(mac) == nil && !realMACs[mac] {
			return mac
		}
	}
	return ""
}

func (st *simStore) newIPLocked(rng *rand.Rand) string {
	used := map[string]bool{}
	for _, d := range st.f.Devices {
		used[d.IP] = true
	}
	for i := 0; i < 500; i++ {
		ip := fmt.Sprintf("192.168.43.%d", 100+rng.Intn(150))
		if !used[ip] {
			return ip
		}
	}
	return "192.168.43.250"
}

func simRandRange(rng *rand.Rand, r [2]int64) int64 {
	if r[1] <= r[0] {
		return r[0]
	}
	return r[0] + rng.Int63n(r[1]-r[0])
}

func simRandF(rng *rand.Rand, r [2]float64) float64 {
	return math.Round((r[0]+rng.Float64()*(r[1]-r[0]))*100) / 100
}

// newDeviceLocked 生成一台带合理随机默认值的设备(不入库)
func (st *simStore) newDeviceLocked(typ string, rng *rand.Rand) (simDevice, error) {
	if typ == "" {
		typ = simTypes[rng.Intn(len(simTypes))]
	}
	tpl, ok := simTpls[typ]
	if !ok {
		return simDevice{}, fmt.Errorf("invalid type")
	}
	mac := st.newMACLocked(rng)
	if mac == "" {
		return simDevice{}, fmt.Errorf("no free sim mac")
	}
	vendor := tpl.vendors[rng.Intn(len(tpl.vendors))]
	rx := simRandRange(rng, tpl.rx)
	app := simPickApp(st.hncDir, typ, rng)
	return simDevice{
		MAC:      mac,
		IP:       st.newIPLocked(rng),
		Name:     "模拟-" + tpl.names[rng.Intn(len(tpl.names))],
		Hostname: fmt.Sprintf("%s-%04X", tpl.host, rng.Intn(0x10000)),
		Vendor:   vendor,
		Type:     typ,
		RxBps:    rx,
		TxBps:    int64(float64(rx) * simRandF(rng, tpl.txRatio)),
		Jitter:   simRandF(rng, tpl.jitter),
		AppID:    app.ID,
		AppName:  app.Name,
		Category: app.Cat,
		Created:  time.Now().Unix(),
	}, nil
}

// ─── 参数解析 ─────────────────────────────────────────────────────────

// simParseRate 字节/秒: "123456" | "512k" | "3m" | "1.5M"(k=1024, m=1048576); 上限 10 Gbit
func simParseRate(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mul := 1.0
	switch {
	case strings.HasSuffix(s, "k"):
		mul, s = 1024, strings.TrimSuffix(s, "k")
	case strings.HasSuffix(s, "m"):
		mul, s = 1048576, strings.TrimSuffix(s, "m")
	}
	if !floatRE.MatchString(s) {
		return 0, fmt.Errorf("rate must be bytes/s number, optional k/m suffix")
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || v*mul > 1.25e9 {
		return 0, fmt.Errorf("rate out of range (0..1.25e9 B/s)")
	}
	return int64(v * mul), nil
}

func simParseFloat(s string, min, max float64) (float64, bool) {
	s = strings.TrimSpace(s)
	if !floatRE.MatchString(s) {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || v < min || v > max {
		return 0, false
	}
	return v, true
}

func simParseBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "on", "yes":
		return true, true
	case "false", "0", "off", "no":
		return false, true
	}
	return false, false
}

func simValidText(s string, maxRunes int) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxRunes {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func simValidIP(s string) bool {
	if !ipv4RE.MatchString(s) {
		return false
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && ip.IsPrivate()
}

func simBad(detail string) actionResp {
	return actionResp{OK: false, Error: "bad params", Detail: detail}
}

// simApplyFields 把 p 里出现的可编辑字段校验后写进 d(add 与 update 共用)。
// 先全部校验到临时副本, 任一失败则 d 不变。
func simApplyFields(hncDir string, d *simDevice, p map[string]string) *actionResp {
	n := simCloneDevice(*d)
	if v, ok := p["name"]; ok {
		v = strings.TrimSpace(v)
		if !simValidText(v, 24) {
			r := simBad("name: ≤24 chars, no control chars")
			return &r
		}
		n.Name = v
	}
	if v, ok := p["hostname"]; ok {
		v = strings.TrimSpace(v)
		if !simValidText(v, 32) {
			r := simBad("hostname: ≤32 chars")
			return &r
		}
		n.Hostname = v
	}
	if v, ok := p["vendor"]; ok {
		v = strings.TrimSpace(v)
		if !simValidText(v, 24) {
			r := simBad("vendor: ≤24 chars")
			return &r
		}
		n.Vendor = v
	}
	if v, ok := p["type"]; ok && v != "" {
		if !simValidType(v) {
			r := simBad("type must be tv|phone|laptop|tablet|game|iot|pc")
			return &r
		}
		n.Type = v
	}
	if v, ok := p["ip"]; ok && v != "" {
		if !simValidIP(v) {
			r := simBad("ip must be a private IPv4")
			return &r
		}
		n.IP = v
	}
	if v, ok := p["rx"]; ok && v != "" {
		x, err := simParseRate(v)
		if err != nil {
			r := simBad("rx: " + err.Error())
			return &r
		}
		n.RxBps = x
	}
	if v, ok := p["tx"]; ok && v != "" {
		x, err := simParseRate(v)
		if err != nil {
			r := simBad("tx: " + err.Error())
			return &r
		}
		n.TxBps = x
	}
	if v, ok := p["jitter"]; ok && v != "" {
		x, ok := simParseFloat(v, 0, 1)
		if !ok {
			r := simBad("jitter must be 0..1")
			return &r
		}
		n.Jitter = x
	}
	if v, ok := p["app"]; ok {
		v = strings.TrimSpace(v)
		switch {
		case v == "":
			n.AppID, n.AppName, n.Category = "", "", ""
		case !validAppID(v):
			r := simBad("app must be 1-32 chars [a-z0-9_-]")
			return &r
		default:
			n.AppID = v
			if a, found := simFindApp(hncDir, v); found {
				n.AppName, n.Category = a.Name, a.Cat
			} else {
				n.AppName, n.Category = v, "unknown"
			}
		}
	}
	if v, ok := p["app_name"]; ok && v != "" {
		if !simValidText(v, 32) {
			r := simBad("app_name: ≤32 chars")
			return &r
		}
		n.AppName = v
	}
	if v, ok := p["category"]; ok && v != "" {
		if !simCategoryRE.MatchString(v) {
			r := simBad("category must be [a-z0-9_-]{1,32}")
			return &r
		}
		n.Category = v
	}
	for _, k := range []string{"blocked", "offline"} {
		if v, ok := p[k]; ok && v != "" {
			b, ok := simParseBool(v)
			if !ok {
				r := simBad(k + " must be true/false")
				return &r
			}
			if k == "blocked" {
				n.Blocked = b
			} else {
				n.Offline = b
			}
		}
	}
	for _, k := range []string{"limit_down_mbps", "limit_up_mbps"} {
		if v, ok := p[k]; ok && v != "" {
			x, ok := simParseFloat(v, 0, 10000)
			if !ok {
				r := simBad(k + " must be 0..10000")
				return &r
			}
			if k == "limit_down_mbps" {
				n.LimitDownMbps = x
			} else {
				n.LimitUpMbps = x
			}
		}
	}
	if v, ok := p["delay_ms"]; ok && v != "" {
		x, ok := atoiClamp(v, 0, 5000)
		if !ok {
			r := simBad("delay_ms must be 0..5000")
			return &r
		}
		n.DelayMs = x
	}
	*d = n
	return nil
}

var simAddKeys = map[string]bool{"name": true, "type": true, "rx": true, "tx": true, "app": true,
	"jitter": true, "ip": true, "vendor": true, "hostname": true}
var simUpdateKeys = map[string]bool{"mac": true, "name": true, "hostname": true, "vendor": true, "type": true,
	"ip": true, "rx": true, "tx": true, "jitter": true, "app": true, "app_name": true, "category": true,
	"blocked": true, "offline": true, "limit_down_mbps": true, "limit_up_mbps": true, "delay_ms": true}

func simUnknownKey(p map[string]string, allowed map[string]bool) string {
	for k := range p {
		if !allowed[k] {
			return k
		}
	}
	return ""
}

// ─── sim_* 动作 ───────────────────────────────────────────────────────

func actionSimSet(s *server, p map[string]string) actionResp {
	v, ok := simParseBool(p["enabled"])
	if !ok {
		return simBad("enabled must be true/false")
	}
	st := simFor(s.hncDir)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.f.Enabled = v
	if err := st.saveLocked(); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	if v {
		return actionResp{OK: true, Detail: fmt.Sprintf("模拟环境已开启(%d 台模拟设备)", len(st.f.Devices))}
	}
	return actionResp{OK: true, Detail: "模拟环境已关闭"}
}

func simRNG() *rand.Rand { return rand.New(rand.NewSource(time.Now().UnixNano())) }

func actionSimDeviceAdd(s *server, p map[string]string) actionResp {
	if k := simUnknownKey(p, simAddKeys); k != "" {
		return simBad("unknown param: " + k)
	}
	typ := strings.TrimSpace(p["type"])
	if typ != "" && !simValidType(typ) {
		return simBad("type must be tv|phone|laptop|tablet|game|iot|pc")
	}
	st := simFor(s.hncDir)
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.f.Devices) >= simMaxDevices {
		return actionResp{OK: false, Error: "too many", Detail: fmt.Sprintf("最多 %d 台模拟设备", simMaxDevices)}
	}
	d, err := st.newDeviceLocked(typ, simRNG())
	if err != nil {
		return actionResp{OK: false, Error: "sim add failed", Detail: err.Error()}
	}
	q := map[string]string{}
	for k, v := range p {
		if k != "type" {
			q[k] = v
		}
	}
	if r := simApplyFields(s.hncDir, &d, q); r != nil {
		return *r
	}
	st.f.Devices = append(st.f.Devices, d)
	if err := st.saveLocked(); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	b, _ := json.Marshal(map[string]string{"mac": d.MAC, "name": d.Name})
	return actionResp{OK: true, Detail: string(b)}
}

func actionSimDeviceUpdate(s *server, p map[string]string) actionResp {
	if k := simUnknownKey(p, simUpdateKeys); k != "" {
		return simBad("unknown param: " + k)
	}
	mac := simNormMAC(p["mac"])
	if !isSimMAC(mac) {
		return simBad("mac must be a sim mac (02:5e:00:xx:xx:xx)")
	}
	st := simFor(s.hncDir)
	st.mu.Lock()
	defer st.mu.Unlock()
	d := st.findLocked(mac)
	if d == nil {
		return actionResp{OK: false, Error: "not found", Detail: "sim device not found"}
	}
	q := map[string]string{}
	for k, v := range p {
		if k != "mac" {
			q[k] = v
		}
	}
	if r := simApplyFields(s.hncDir, d, q); r != nil {
		return *r
	}
	if err := st.saveLocked(); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: "updated " + mac}
}

func actionSimDeviceDel(s *server, p map[string]string) actionResp {
	mac := simNormMAC(p["mac"])
	if !isSimMAC(mac) {
		return simBad("mac must be a sim mac (02:5e:00:xx:xx:xx)")
	}
	st := simFor(s.hncDir)
	st.mu.Lock()
	defer st.mu.Unlock()
	kept := st.f.Devices[:0]
	found := false
	for _, d := range st.f.Devices {
		if d.MAC == mac {
			found = true
			continue
		}
		kept = append(kept, d)
	}
	if !found {
		return actionResp{OK: false, Error: "not found", Detail: "sim device not found"}
	}
	st.f.Devices = kept
	delete(st.acc, mac)
	if err := st.saveLocked(); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: "deleted " + mac}
}

func actionSimClear(s *server) actionResp {
	st := simFor(s.hncDir)
	st.mu.Lock()
	defer st.mu.Unlock()
	n := len(st.f.Devices)
	st.f.Devices = nil
	st.acc = map[string]*simAcc{}
	if err := st.saveLocked(); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: fmt.Sprintf("cleared %d sim device(s)", n)}
}

// 预设: 每项 = 类型 + 覆盖字段(其余随机)
type simPresetItem struct {
	typ string
	p   map[string]string
}

var simPresets = map[string][]simPresetItem{
	// 普通家庭晚上: 6 台, 电视在追剧, 其它零散
	"home": {
		{"tv", map[string]string{"name": "模拟-客厅电视", "rx": "3m", "tx": "90k", "jitter": "0.2"}},
		{"phone", map[string]string{"name": "模拟-爸爸的手机", "rx": "600k", "tx": "80k", "jitter": "0.5"}},
		{"phone", map[string]string{"name": "模拟-妈妈的手机", "rx": "350k", "tx": "40k", "jitter": "0.6"}},
		{"tablet", map[string]string{"name": "模拟-孩子的平板", "rx": "1.2m", "tx": "50k", "jitter": "0.3"}},
		{"laptop", map[string]string{"name": "模拟-书房笔记本", "rx": "800k", "tx": "200k", "jitter": "0.5"}},
		{"iot", map[string]string{"name": "模拟-小爱音箱", "rx": "24k", "tx": "4k", "jitter": "0.7"}},
	},
	// 高负载: 8 台, 有人下载/4K/直播上传, 含一台已限速、一台被拉黑、一台加了延迟
	"busy": {
		{"pc", map[string]string{"name": "模拟-下载机", "rx": "8m", "tx": "400k", "jitter": "0.3", "app": "baidu_netdisk"}},
		{"tv", map[string]string{"name": "模拟-4K 电视", "rx": "5m", "tx": "120k", "jitter": "0.25"}},
		{"phone", map[string]string{"name": "模拟-刷抖音的手机", "rx": "2.5m", "tx": "300k", "jitter": "0.6", "limit_down_mbps": "8"}},
		{"phone", map[string]string{"name": "模拟-直播手机", "rx": "500k", "tx": "2m", "jitter": "0.4"}},
		{"laptop", map[string]string{"name": "模拟-视频会议", "rx": "1.5m", "tx": "1m", "jitter": "0.3", "delay_ms": "80"}},
		{"game", map[string]string{"name": "模拟-Switch 更新", "rx": "3m", "tx": "60k", "jitter": "0.5"}},
		{"iot", map[string]string{"name": "模拟-米家摄像头", "rx": "20k", "tx": "250k", "jitter": "0.3"}},
		{"phone", map[string]string{"name": "模拟-陌生设备", "rx": "900k", "tx": "100k", "jitter": "0.5", "blocked": "true"}},
	},
	// 空闲: 4 台, 只有心跳级流量, 一台离线
	"idle": {
		{"phone", map[string]string{"name": "模拟-待机手机", "rx": "4k", "tx": "1k", "jitter": "0.9"}},
		{"tablet", map[string]string{"name": "模拟-充电中的平板", "rx": "2k", "tx": "1k", "jitter": "0.9"}},
		{"iot", map[string]string{"name": "模拟-智能插座", "rx": "512", "tx": "256", "jitter": "0.8"}},
		{"laptop", map[string]string{"name": "模拟-合盖的笔记本", "rx": "8k", "tx": "2k", "jitter": "0.9", "offline": "true"}},
	},
}

func actionSimPreset(s *server, p map[string]string) actionResp {
	name := strings.TrimSpace(p["preset"])
	items, ok := simPresets[name]
	if !ok {
		return simBad("preset must be home|busy|idle")
	}
	st := simFor(s.hncDir)
	st.mu.Lock()
	defer st.mu.Unlock()
	rng := simRNG()
	st.f.Devices = nil
	st.acc = map[string]*simAcc{}
	for _, it := range items {
		d, err := st.newDeviceLocked(it.typ, rng)
		if err != nil {
			return actionResp{OK: false, Error: "sim preset failed", Detail: err.Error()}
		}
		if r := simApplyFields(s.hncDir, &d, it.p); r != nil {
			return *r
		}
		st.f.Devices = append(st.f.Devices, d)
	}
	st.f.Enabled = true
	if err := st.saveLocked(); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: fmt.Sprintf("已载入预设 %s(%d 台), 模拟环境已开启", name, len(items))}
}

// ─── 安全闸: 设备级动作遇到模拟 MAC ───────────────────────────────────

// simInterceptAction 在 dispatchAction 最前面调用。p["mac"] 是模拟 MAC 时
// (已登记的模拟设备; 或模拟环境开启时任何 02:5e:00 前缀) 返回 handled=true:
// 只修改 sim 状态, 不调用任何脚本。其余情况 handled=false, 走原逻辑。
// 真实 MAC 的开销只有一次字符串前缀比较。
func simInterceptAction(s *server, action string, p map[string]string) (actionResp, bool) {
	raw, has := p["mac"]
	if !has || strings.HasPrefix(action, "sim_") {
		return actionResp{}, false
	}
	mac := simNormMAC(raw)
	if !strings.HasPrefix(mac, simMACPrefix) || !isSimMAC(mac) {
		return actionResp{}, false
	}
	st := simFor(s.hncDir)
	st.mu.Lock()
	defer st.mu.Unlock()
	d := st.findLocked(mac)
	if d == nil {
		if !st.f.Enabled {
			return actionResp{}, false // 模拟环境从未登记过它 & 已关闭: 行为与无此功能时一致
		}
		return actionResp{OK: false, Error: "not found", Detail: "sim device not found: " + mac}, true
	}
	n := simCloneDevice(*d)
	r := simDeviceAction(&n, action, p)
	if !r.OK || r.Detail == simNoChange {
		if r.Detail == simNoChange {
			r.Detail = "模拟设备: 该动作不影响模拟状态(未触达系统)"
		}
		return r, true
	}
	*d = n
	if err := st.saveLocked(); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}, true
	}
	if r.Detail == "" {
		r.Detail = "模拟设备: 已更新(未触达 tc/iptables)"
	}
	return r, true
}

const simNoChange = "\x00sim-nochange"

// simDeviceAction 按原动作的参数校验规则改模拟设备状态(纯内存, 无 I/O)。
func simDeviceAction(d *simDevice, action string, p map[string]string) actionResp {
	switch action {
	case "rule_set", "template_apply":
		dn, up := p["rate_down"], p["rate_up"]
		if dn == "" && up == "" {
			return simBad("at least one of rate_down/rate_up required")
		}
		conv := func(r string) (float64, error) {
			if r == "" {
				return 0, nil
			}
			if err := validateRate(r); err != nil {
				return 0, err
			}
			sv, err := rateToMbpsStr(r)
			if err != nil {
				return 0, err
			}
			return strconv.ParseFloat(sv, 64)
		}
		dv, err := conv(dn)
		if err != nil {
			return simBad("rate_down: " + err.Error())
		}
		uv, err := conv(up)
		if err != nil {
			return simBad("rate_up: " + err.Error())
		}
		d.LimitDownMbps, d.LimitUpMbps = dv, uv
		return actionResp{OK: true, Detail: "limit applied (sim)"}
	case "rule_clear":
		d.LimitDownMbps, d.LimitUpMbps = 0, 0
		return actionResp{OK: true, Detail: "limit cleared (sim)"}
	case "bl_add":
		d.Blocked = true
		return actionResp{OK: true, Detail: "blacklisted (sim)"}
	case "bl_del":
		d.Blocked = false
		return actionResp{OK: true, Detail: "removed from blacklist (sim)"}
	case "delay_set":
		delay, ok1 := atoiClamp(p["delay_ms"], 0, 5000)
		jit, ok2 := atoiClamp(p["jitter_ms"], 0, 5000)
		if !ok1 || !ok2 {
			return simBad("delay_ms/jitter_ms out of range (0-5000)")
		}
		loss, ok := simParseFloat(p["loss_pct"], 0, 100)
		if !ok {
			return simBad("loss_pct out of range (0-100)")
		}
		d.DelayMs, d.JitterMs, d.LossPct = delay, jit, loss
		return actionResp{OK: true, Detail: "delay injected (sim)"}
	case "delay_clear":
		d.DelayMs, d.JitterMs, d.LossPct = 0, 0, 0
		return actionResp{OK: true, Detail: "delay cleared (sim)"}
	case "rule_sqm":
		v, ok := parseEnabledParam(p)
		if !ok {
			return simBad("enabled must be true/false")
		}
		d.SQM = v
		return actionResp{OK: true}
	case "device_whitelist_set":
		v := p["enabled"]
		if v != "true" && v != "false" {
			return simBad("enabled must be true/false")
		}
		d.Whitelist = v == "true"
		return actionResp{OK: true}
	case "device_rename":
		name := strings.TrimSpace(p["name"])
		if !validDeviceName(name) {
			return simBad("name must be 1-32 printable chars, or empty to clear")
		}
		d.Name = name
		return actionResp{OK: true}
	case "device_ident_set":
		if p["clear"] == "true" {
			d.Ident = nil
			return actionResp{OK: true}
		}
		ov := map[string]string{}
		for _, k := range []string{"type", "os", "os_ver", "brand", "model"} {
			v, ok := p[k]
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			if len([]rune(v)) > 40 {
				return simBad(k + " too long")
			}
			if k == "type" && v != "" && !identTypes[v] {
				return simBad("invalid type")
			}
			ov[k] = v
		}
		d.Ident = ov
		return actionResp{OK: true}
	case "conn_block_add":
		kind := strings.TrimSpace(p["kind"])
		val := strings.ToLower(strings.TrimSpace(p["value"]))
		switch kind {
		case "ip":
			ip := net.ParseIP(val)
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || isPrivateIP(val) {
				return simBad("invalid ip")
			}
			val = ip.String()
		case "domain":
			val = strings.TrimPrefix(val, "*.")
			if !domainRe.MatchString(val) || len(val) > 253 {
				return simBad("invalid domain")
			}
		default:
			return simBad("kind must be domain|ip")
		}
		for _, it := range d.ConnBlocks {
			if it.Kind == kind && it.Value == val {
				return actionResp{OK: true, Detail: "已经封锁过了"}
			}
		}
		if len(d.ConnBlocks) >= 50 {
			return actionResp{OK: false, Error: "too many", Detail: "模拟设备封锁项已达上限 50"}
		}
		label := strings.TrimSpace(p["label"])
		if len([]rune(label)) > 40 {
			label = string([]rune(label)[:40])
		}
		d.ConnBlocks = append(d.ConnBlocks, connBlock{MAC: d.MAC, Kind: kind, Value: val, Label: label, Ts: time.Now().Unix()})
		return actionResp{OK: true}
	case "conn_block_del":
		kind := strings.TrimSpace(p["kind"])
		val := strings.ToLower(strings.TrimSpace(p["value"]))
		kept := d.ConnBlocks[:0]
		found := false
		for _, it := range d.ConnBlocks {
			if it.Kind == kind && it.Value == val {
				found = true
				continue
			}
			kept = append(kept, it)
		}
		if !found {
			return actionResp{OK: false, Error: "not found"}
		}
		d.ConnBlocks = kept
		if len(d.ConnBlocks) == 0 {
			d.ConnBlocks = nil
		}
		return actionResp{OK: true}
	case "app_limit_set":
		appID := strings.TrimSpace(p["app_id"])
		if !validAppID(appID) {
			return simBad("app_id must be 1-32 chars, [a-z0-9_-]")
		}
		rate, err := strconv.ParseFloat(strings.TrimSpace(p["down_mbps"]), 64)
		if err != nil || math.IsNaN(rate) || rate < 0 || rate > 10000 {
			return simBad("down_mbps must be 0..10000")
		}
		if rate == 0 {
			delete(d.AppLimits, appID)
		} else {
			if d.AppLimits == nil {
				d.AppLimits = map[string]float64{}
			}
			d.AppLimits[appID] = rate
		}
		if len(d.AppLimits) == 0 {
			d.AppLimits = nil
		}
		return actionResp{OK: true}
	case "app_limit_clear":
		if id := strings.TrimSpace(p["app_id"]); id != "" {
			delete(d.AppLimits, id)
		} else {
			d.AppLimits = nil
		}
		if len(d.AppLimits) == 0 {
			d.AppLimits = nil
		}
		return actionResp{OK: true}
	}
	// 其它带 mac 的动作(alert_mark_known 等): 对模拟设备一律空操作
	return actionResp{OK: true, Detail: simNoChange}
}

// ─── GET /api/sim ─────────────────────────────────────────────────────

func (s *server) apiSim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	st := simFor(s.hncDir)
	now := time.Now()
	st.mu.Lock()
	enabled, seed := st.f.Enabled, st.f.Seed
	if enabled {
		st.advanceLocked(now)
	}
	devs := make([]map[string]interface{}, 0, len(st.f.Devices))
	for _, d := range st.f.Devices {
		b, _ := json.Marshal(d)
		m := map[string]interface{}{}
		_ = json.Unmarshal(b, &m)
		rx, tx := simRate(&d, seed, float64(now.Unix()))
		m["cur_rx_bps"], m["cur_tx_bps"] = rx, tx
		m["online"] = !d.Offline
		var dn, up uint64
		if a := st.acc[d.MAC]; a != nil && enabled {
			for h := 0; h < 24; h++ {
				dn += a.hours[h][0]
				up += a.hours[h][1]
			}
		}
		m["today_rx_bytes"], m["today_tx_bytes"] = dn, up
		devs = append(devs, m)
	}
	st.mu.Unlock()
	names := make([]string, 0, len(simPresets))
	for k := range simPresets {
		names = append(names, k)
	}
	sort.Strings(names)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":         true,
		"enabled":    enabled,
		"count":      len(devs),
		"seed":       seed,
		"devices":    devs,
		"presets":    names,
		"types":      simTypes,
		"mac_prefix": simMACPrefix,
		"max":        simMaxDevices,
	})
}
