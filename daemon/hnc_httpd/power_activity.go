// power_activity.go — v5.22 功耗: 共享「活动状态」信号。
//
// 一个后台 ActivityLoop 每 15 秒做一次很便宜的探测, 汇总成 Activity:
//
//	screen_on      亮屏? 优先读 /sys/class/backlight/*/brightness(读文件, 零进程);
//	               没有背光节点或与系统判定不一致时退 `dumpsys power` 的 mWakefulness
//	               (Awake/Dreaming=亮, Asleep/Dozing=灭), 再退 `dumpsys display` 的
//	               mScreenState; dumpsys 最多 60 秒跑一次, 背光模式每 30 分钟用 dumpsys 复核一次。
//	hotspot_active 热点口存在且有私网 IPv4(hnc_state 的 ACTIVE: 在热点关掉后仍会保留, 不能单信它)
//	clients_online devices.json 里 last_seen 在 90 秒内的设备数(与 WebUI 在线判定一致)
//	webui_active   有 SSE(/api/events)连接, 或 60 秒内有鉴权通过的 API/页面请求
//
// 结果: 包级原子快照(activityNow)+ run/activity.json(单行 JSON, 字段顺序固定, 供
// watchdog.sh / hnc_offload_guard.sh / dpid 读; shell 用 case 模式匹配, 不 fork)。
// 状态「档位」变化时关闭广播通道, 等待中的循环立即按新档位重算间隔(见 power_sched.go)。
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	activityProbeEvery   = 15 * time.Second
	activityWriteRefresh = 60 * time.Second // 内容没变也至少 60 秒刷一次 ts(供 shell 判新鲜)
	webuiActiveWindow    = 60 * time.Second
	screenDumpsysEvery   = 60 * time.Second
	screenVerifyEvery    = 30 * time.Minute
	screenCmdTimeout     = 3 * time.Second
	activityOnlineWindow = 90 // 秒, 与 buildDevicesPayload 的 online 判定一致
)

// 活动档位(policy 的输入, 见 power_sched.go 表)
const (
	lvlUnknown    = "unknown"     // 还没探测过: 一律按基准间隔(保守)
	lvlHotspotOff = "hotspot_off" // 热点未开
	lvlNoClients  = "no_clients"  // 热点开着但没有在线客户端
	lvlBackground = "background"  // 有客户端, 但熄屏且没有 WebUI
	lvlActive     = "active"      // 有客户端, 亮屏或 WebUI 在看
)

var activityLevelLabel = map[string]string{
	lvlUnknown:    "未知(按基准间隔)",
	lvlHotspotOff: "热点未开",
	lvlNoClients:  "热点开着, 无在线设备",
	lvlBackground: "后台(熄屏且无界面)",
	lvlActive:     "活跃",
}

// Activity 一次探测的结果。JSON 字段顺序即 run/activity.json 的顺序(shell 依赖, 勿重排)。
type Activity struct {
	Ts            int64  `json:"ts"`
	Level         string `json:"level"`
	ScreenOn      bool   `json:"screen_on"`
	ScreenKnown   bool   `json:"screen_known"`
	ScreenSource  string `json:"screen_source"` // backlight | power | display | none
	HotspotActive bool   `json:"hotspot_active"`
	HotspotIface  string `json:"hotspot_iface"`
	ClientsOnline int    `json:"clients_online"`
	WebUIActive   bool   `json:"webui_active"`
	SSEClients    int    `json:"sse_clients"`
	LastAPIAgoS   int64  `json:"last_api_ago_s"` // -1 = 从未
	CtPrecise     bool   `json:"ct_precise"`     // conntrack DESTROY 事件在用(短连接不靠轮询)
	Known         bool   `json:"known"`
}

// computeLevel 档位判定(纯函数)。屏幕状态未知时按亮屏处理(保守, 不省)。
func (a Activity) computeLevel() string {
	if !a.Known {
		return lvlUnknown
	}
	if !a.HotspotActive {
		return lvlHotspotOff
	}
	if a.ClientsOnline <= 0 {
		return lvlNoClients
	}
	if a.ScreenKnown && !a.ScreenOn && !a.WebUIActive {
		return lvlBackground
	}
	return lvlActive
}

// screenOff 明确熄屏(未知 = 不算)
func (a Activity) screenOff() bool { return a.Known && a.ScreenKnown && !a.ScreenOn }

// sig 影响间隔的字段; 变了才广播
func (a Activity) sig() string {
	return a.Level + "|" + strconv.FormatBool(a.WebUIActive) + "|" + strconv.FormatBool(a.screenOff()) +
		"|" + strconv.FormatBool(a.CtPrecise)
}

// ─── 包级快照 + 变化广播 ───────────────────────────────────────────

var actState struct {
	cur  atomic.Pointer[Activity]
	mu   sync.Mutex
	ch   chan struct{}
	poke chan struct{}
}

func init() {
	actState.ch = make(chan struct{})
	actState.poke = make(chan struct{}, 1)
}

// activityNow 当前快照(没探测过时 Known=false → 档位 unknown)
func activityNow() Activity {
	if p := actState.cur.Load(); p != nil {
		return *p
	}
	return Activity{Level: lvlUnknown, LastAPIAgoS: -1}
}

// activityChanged 在下一次档位/界面/屏幕变化时关闭的通道
func activityChanged() <-chan struct{} {
	actState.mu.Lock()
	defer actState.mu.Unlock()
	return actState.ch
}

// activityPublish 发布新快照; sig 变了就唤醒所有等待中的循环。返回是否变化。
func activityPublish(a Activity) bool {
	a.Level = a.computeLevel()
	old := actState.cur.Swap(&a)
	if old != nil && old.sig() == a.sig() {
		return false
	}
	actState.mu.Lock()
	close(actState.ch)
	actState.ch = make(chan struct{})
	actState.mu.Unlock()
	return true
}

// activityPoke 请活动循环尽快重探一次(非阻塞)
func activityPoke() {
	select {
	case actState.poke <- struct{}{}:
	default:
	}
}

// ─── WebUI 活跃度 ─────────────────────────────────────────────────

var webuiLastHit atomic.Int64 // unix nano; 0 = 从未

// powerNoteAPIHit 记一次鉴权通过的请求; 从「不活跃」变「活跃」时立即重探, 让 UI 相关循环马上提速。
func powerNoteAPIHit(now time.Time) {
	prev := webuiLastHit.Swap(now.UnixNano())
	if prev == 0 || now.UnixNano()-prev > int64(webuiActiveWindow) {
		if a := activityNow(); !a.WebUIActive {
			activityPoke()
		}
	}
}

// activityTouchMiddleware 包在 authMiddleware 里面: 只有鉴权通过的请求才算「有人在看」
// (热点上的陌生客户端扫端口不会让后台一直保持高频)。
func activityTouchMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		powerNoteAPIHit(time.Now())
		next.ServeHTTP(w, r)
	})
}

func webuiState(now time.Time) (active bool, agoS int64, sse int) {
	sse = int(sseConns.Load())
	agoS = -1
	if last := webuiLastHit.Load(); last > 0 {
		agoS = (now.UnixNano() - last) / int64(time.Second)
		if agoS < 0 {
			agoS = 0
		}
	}
	active = sse > 0 || (agoS >= 0 && agoS < int64(webuiActiveWindow/time.Second))
	return
}

// ─── 屏幕探测 ─────────────────────────────────────────────────────

// parseWakefulness `dumpsys power` → (亮屏, 是否解析到)。
// Awake/Dreaming(屏保, 屏幕亮着)= 亮; Asleep/Dozing(含 AOD)= 灭。
func parseWakefulness(text string) (on bool, ok bool) {
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		i := strings.Index(ln, "mWakefulness=")
		if i < 0 {
			continue
		}
		v := ln[i+len("mWakefulness="):]
		if j := strings.IndexAny(v, " \t,"); j >= 0 {
			v = v[:j]
		}
		switch strings.ToLower(v) {
		case "awake", "dreaming":
			return true, true
		case "asleep", "dozing":
			return false, true
		}
	}
	return false, false
}

// parseDisplayState `dumpsys display` → (亮屏, 是否解析到)。认 mScreenState= / mGlobalDisplayState= /
// "Display Power: state=" 三种写法; ON/VR/ON_SUSPEND = 亮, OFF/DOZE/DOZE_SUSPEND = 灭。
func parseDisplayState(text string) (on bool, ok bool) {
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		v := ""
		for _, key := range []string{"mScreenState=", "mGlobalDisplayState=", "Display Power: state="} {
			if i := strings.Index(ln, key); i >= 0 {
				v = ln[i+len(key):]
				break
			}
		}
		if v == "" {
			continue
		}
		if j := strings.IndexAny(v, " \t,"); j >= 0 {
			v = v[:j]
		}
		switch strings.ToUpper(v) {
		case "ON", "VR", "ON_SUSPEND":
			return true, true
		case "OFF", "DOZE", "DOZE_SUSPEND":
			return false, true
		}
	}
	return false, false
}

// parseBacklight 背光亮度文本 → (亮, 是否有效)
func parseBacklight(s string) (bool, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return false, false
	}
	return n > 0, true
}

type screenProber struct {
	readFile func(string) ([]byte, error)
	glob     func(string) ([]string, error)
	// dumpsys(service) → 只取到包含任一 key 的行为止(流式, 不缓冲全部输出)
	dumpsys func(service string, keys []string) (string, error)
	now     func() time.Time

	mode       string // "" | backlight | power | display | none
	verifiedAt time.Time
	lastCmdAt  time.Time
	lastOn     bool
	lastOK     bool
	mismatch   int
}

var screenBacklightGlobs = []string{
	"/sys/class/backlight/*/brightness",
	"/sys/class/leds/lcd-backlight/brightness",
}

func newScreenProber() *screenProber {
	return &screenProber{
		readFile: os.ReadFile,
		glob:     filepath.Glob,
		dumpsys:  dumpsysScan,
		now:      time.Now,
	}
}

func (p *screenProber) backlight() (bool, bool) {
	any, okAny := false, false
	for _, g := range screenBacklightGlobs {
		paths, _ := p.glob(g)
		for _, path := range paths {
			b, err := p.readFile(path)
			if err != nil {
				continue
			}
			if on, ok := parseBacklight(string(b)); ok {
				okAny = true
				any = any || on
			}
		}
	}
	return any, okAny
}

// fromDumpsys power → display(权威判定, 有进程开销)
func (p *screenProber) fromDumpsys() (on bool, ok bool, src string) {
	if out, err := p.dumpsys("power", []string{"mWakefulness="}); err == nil || out != "" {
		if on, ok := parseWakefulness(out); ok {
			return on, true, "power"
		}
	}
	if out, err := p.dumpsys("display", []string{"mScreenState=", "mGlobalDisplayState=", "Display Power: state="}); err == nil || out != "" {
		if on, ok := parseDisplayState(out); ok {
			return on, true, "display"
		}
	}
	return false, false, ""
}

// probe 返回 (亮屏, 是否已知, 来源)
func (p *screenProber) probe() (bool, bool, string) {
	now := p.now()
	bl, blOK := p.backlight()
	if p.mode == "" || now.Sub(p.verifiedAt) >= screenVerifyEvery {
		on, ok, src := p.fromDumpsys()
		p.verifiedAt, p.lastCmdAt = now, now
		switch {
		case ok && blOK && on == bl:
			p.mode, p.mismatch = "backlight", 0
		case ok:
			if blOK {
				p.mismatch++ // 背光与系统判定不一致(如 AOD 时背光不为 0): 信系统
			}
			p.mode = src
		case blOK:
			p.mode = "backlight"
		default:
			p.mode = "none"
		}
		p.lastOn, p.lastOK = on, ok
		if p.mode == "backlight" {
			return bl, true, "backlight"
		}
		return on, ok, p.mode
	}
	switch p.mode {
	case "backlight":
		if blOK {
			return bl, true, "backlight"
		}
		p.mode = "" // 节点没了: 下轮重新选
		return p.lastOn, p.lastOK, "backlight"
	case "power", "display":
		if now.Sub(p.lastCmdAt) >= screenDumpsysEvery {
			p.lastCmdAt = now
			if on, ok, src := p.fromDumpsys(); ok {
				p.lastOn, p.lastOK, p.mode = on, true, src
			}
		}
		return p.lastOn, p.lastOK, p.mode
	}
	return false, false, "none"
}

// dumpsysScan 跑 dumpsys <service>, 流式读到第一条含 key 的行就结束(杀掉进程), 不缓冲大输出。
func dumpsysScan(service string, keys []string) (string, error) {
	path := ""
	for _, d := range []string{"/system/bin/", "/system/xbin/", "/vendor/bin/"} {
		if st, err := os.Stat(d + "dumpsys"); err == nil && !st.IsDir() {
			path = d + "dumpsys"
			break
		}
	}
	if path == "" {
		p, err := exec.LookPath("dumpsys")
		if err != nil {
			return "", err
		}
		path = p
	}
	ctx, cancel := context.WithTimeout(context.Background(), screenCmdTimeout)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, path, service))
	cmd.Env = []string{"PATH=/system/bin:/system/xbin:/vendor/bin"}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	var hit strings.Builder
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64<<10), 256<<10)
	lines := 0
	for sc.Scan() {
		ln := sc.Text()
		if lines++; lines > 20000 {
			break
		}
		for _, k := range keys {
			if strings.Contains(ln, k) {
				hit.WriteString(ln)
				hit.WriteByte('\n')
				break
			}
		}
		if hit.Len() > 0 {
			break
		}
	}
	cancel() // 找到就杀, 不等 dumpsys 把剩下几百行写完
	_ = cmd.Wait()
	if hit.Len() == 0 {
		return "", errNoScreenKey
	}
	return hit.String(), nil
}

type powerErr string

func (e powerErr) Error() string { return string(e) }

const errNoScreenKey = powerErr("screen state key not found")

// ─── 热点 / 客户端 ─────────────────────────────────────────────────

// activityHotspot 热点口: 先认 HNC 记录的口(hnc_state/iface.cache/iface_detect/rules)且有私网 IPv4,
// 再扫系统接口里名字明确是 AP 的口(ap0/swlan0/softap0…)。wlanN 这种可能是 STA 的口不扫, 防误判。
func (s *server) activityHotspot() (bool, string) {
	if s.simActive() {
		return true, "sim"
	}
	if ifc := s.currentHotspotIface(); ifc != "" && ifaceIPv4(ifc) != "" {
		return true, ifc
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return false, ""
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || !isAPIfaceName(i.Name) {
			continue
		}
		if ifaceIPv4(i.Name) != "" {
			return true, i.Name
		}
	}
	return false, ""
}

// countOnlineClients devices.json → last_seen 在 window 秒内的设备数(纯函数, 测试直接喂)
func countOnlineClients(devs map[string]interface{}, nowSec float64, window float64) int {
	n := 0
	for _, raw := range devs {
		d, _ := raw.(map[string]interface{})
		if d == nil {
			continue
		}
		if ls, ok := d["last_seen"].(float64); ok {
			if ls > 0 && nowSec-ls < window {
				n++
			}
			continue
		}
		if b, ok := d["online"].(bool); ok && b {
			n++
		}
	}
	return n
}

func (s *server) activityClients(now time.Time) int {
	n := 0
	if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "data", "devices.json")); err == nil {
		if m, ok := raw.(map[string]interface{}); ok {
			n = countOnlineClients(m, float64(now.Unix()), activityOnlineWindow)
		}
	}
	if n == 0 && s.simActive() {
		n = 1
	}
	return n
}

// ─── 循环 ─────────────────────────────────────────────────────────

func ctPreciseActive() bool {
	ctEvents.mu.Lock()
	defer ctEvents.mu.Unlock()
	return ctEvents.active
}

func (s *server) probeActivity(sp *screenProber, now time.Time) Activity {
	a := Activity{Ts: now.Unix(), Known: true}
	a.ScreenOn, a.ScreenKnown, a.ScreenSource = sp.probe()
	a.HotspotActive, a.HotspotIface = s.activityHotspot()
	if a.HotspotActive {
		a.ClientsOnline = s.activityClients(now)
	}
	a.WebUIActive, a.LastAPIAgoS, a.SSEClients = webuiState(now)
	a.CtPrecise = ctPreciseActive()
	a.Level = a.computeLevel()
	return a
}

func activityPath(hncDir string) string { return filepath.Join(hncDir, "run", "activity.json") }

// writeActivity 单行 JSON(tmp+rename)
func writeActivity(hncDir string, a Activity) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	p := activityPath(hncDir)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// ActivityLoop 每 15 秒探一次; 被 poke(WebUI 刚来请求)时立即探。
func (s *server) ActivityLoop(stop <-chan struct{}) {
	sp := newScreenProber()
	var lastWritten Activity
	var lastWriteAt time.Time
	tick := func() {
		now := time.Now()
		a := s.probeActivity(sp, now)
		activityPublish(a)
		cmp := a
		cmp.Ts, cmp.LastAPIAgoS = lastWritten.Ts, lastWritten.LastAPIAgoS
		if cmp != lastWritten || now.Sub(lastWriteAt) >= activityWriteRefresh {
			if err := writeActivity(s.hncDir, a); err == nil {
				lastWritten, lastWriteAt = a, now
			}
		}
	}
	tick()
	t := time.NewTicker(activityProbeEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			tick()
		case <-actState.poke:
			tick()
		}
	}
}
