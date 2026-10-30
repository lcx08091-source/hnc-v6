// app_activity.go — v5.34 应用内活动细分: 前台应用此刻「在做什么」(推测, 只用于显示)。
//
// flow_shape.go 的「此刻在」是整台设备的(所有应用的流量合起来判), 这里只看前台应用自己的
// 连接, 并换成这个应用自己的说法: 抖音「刷短视频 / 看直播 / 发视频」、微信「语音通话 /
// 视频通话 / 聊天」、王者荣耀「对局中 / 下载更新 / 在大厅」……
//
// ── 每条连接的用途标签(app_usage 记账时打, 见 appActivityTag)──────────────────────────
//  1. 域名用途规则: data/app_activity.json 里该应用的 domains(只对归到这个应用的连接生效),
//     按连接自己的 SNI(没有则用目的 IP 反查名)匹配后缀(按标签边界)+ 可选的首段前缀;
//  2. 流形态: flow_shape.go 对这条连接的判类, 置信度 ≥ appActShapeMinConf;
//  都没有 → 不打标签(不参与)。标签集合 = 流形态的类型(video_stream / live_stream /
//  voice_call / video_call / gaming / download / upload / browsing / background)。
//
// ── 每个 (设备, 应用) 的判定(fg_model.go 每轮, 见 appActTrack.actStep)──────────────────
//  按标签累计字节, 指数衰减(τ = appActTau); 打分 = 字节 × 权重: 实时类(通话 / 游戏)本身
//  字节很少 ×5, 上传 ×2, 后台 ×0.3, 其余 ×1。取最高分; 换成新标签要连续 appActSwitchTicks
//  轮领先(第一次判出 / 原标签已衰减到 0 除外)。置信度 = 该标签得分占比 × 来源系数(域名规则
//  1.0 / 流形态 0.8), 封顶 0.9; 低于 appActMinConf 不显示。
//
// ── 显示名 ───────────────────────────────────────────────────────────────────
//  应用专属说法(apps.<id>.labels)> 类别说法(categories.<类别>, 类别以 game 开头的按 game)
//  > 通用说法(flow_shape.go 的 trafficTypeLabels)。data/app_activity.json 按 dataCandidates
//  的顺序找(<hnc>/etc 覆盖 > 模块 data > <hnc>/data); 找不到 / 坏了 → 只用通用说法, 不报错。
//
// 结果: /api/devices[].fg.activity = {id, label, conf, src}(src = domain | shape)。
// 不影响归属、限速、时长、时间线。

package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	appActTau          = 30.0 // 秒
	appActShapeMinConf = 0.5
	appActSwitchTicks  = 2
	appActMinConf      = 0.35
	appActMaxConf      = 0.9
	appActShapeFactor  = 0.8
	appActMinWeight    = 1024.0 // 衰减后总加权字节 < 1 KB → 不判
	appActMaxFile      = 256 << 10
	appActRecheck      = time.Minute
)

// appActWeight 打分权重(见文件头)
func appActWeight(tag string) float64 {
	switch tag {
	case ttVoice, ttVideoCall, ttGaming:
		return 5
	case ttUpload:
		return 2
	case ttBackground:
		return 0.3
	}
	return 1
}

func appActValidTag(tag string) bool {
	switch tag {
	case ttVideo, ttLive, ttVoice, ttVideoCall, ttGaming, ttDownload, ttUpload, ttBrowsing, ttBackground:
		return true
	}
	return false
}

// ─── 规则数据 ─────────────────────────────────────────────────────────────

type appActDomain struct {
	Suffix string `json:"suffix"`
	Prefix string `json:"prefix,omitempty"` // 主机名第一段的前缀(如直播拉流的 pull-)
	Use    string `json:"use"`
}

// appActApp 一个应用 / 一个类别的说法。v5.34.0-rc2: labels 同时是「允许的标签」——
// 流形态判出的标签只有在该应用或该类别写了说法时才参与; domain_only 里的只认域名规则。
type appActApp struct {
	Labels     map[string]string `json:"labels"`
	Domains    []appActDomain    `json:"domains,omitempty"`
	DomainOnly []string          `json:"domain_only,omitempty"`
}

type appActSet struct {
	Categories map[string]appActApp `json:"categories"`
	Apps       map[string]appActApp `json:"apps"`
}

var (
	appActCur  atomic.Pointer[appActSet]
	appActFile struct {
		mu      sync.Mutex
		key     string
		checked time.Time
	}
)

// appActivityRefresh app_usage 每轮(锁外)调用: 按 mtime / 大小缓存, 最多每分钟 stat 一次。
func appActivityRefresh(hncDir string, now time.Time) {
	appActFile.mu.Lock()
	defer appActFile.mu.Unlock()
	if !appActFile.checked.IsZero() && now.Sub(appActFile.checked) < appActRecheck && now.After(appActFile.checked) {
		return
	}
	appActFile.checked = now
	path, key := "", "-"
	for _, p := range dataCandidates(hncDir, "app_activity.json") {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			path = p
			key = p + ":" + strconv.FormatInt(fi.ModTime().UnixNano(), 10) + ":" + strconv.FormatInt(fi.Size(), 10)
			break
		}
	}
	if key == appActFile.key {
		return
	}
	appActFile.key = key
	appActCur.Store(appActLoad(path))
}

// appActLoad 读并清洗规则文件; 读不到 / 太大 / 坏了 → nil(只用通用说法, 不限制标签)
func appActLoad(path string) *appActSet {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > appActMaxFile {
		return nil
	}
	var raw appActSet
	if json.Unmarshal(b, &raw) != nil {
		return nil
	}
	out := &appActSet{Categories: map[string]appActApp{}, Apps: map[string]appActApp{}}
	clean := func(a appActApp) appActApp {
		c := appActApp{Labels: map[string]string{}}
		for tag, lbl := range a.Labels {
			if lbl = strings.TrimSpace(lbl); appActValidTag(tag) && lbl != "" && len([]rune(lbl)) <= 16 {
				c.Labels[tag] = lbl
			}
		}
		for _, d := range a.Domains {
			d.Suffix = strings.Trim(strings.ToLower(strings.TrimSpace(d.Suffix)), ".")
			d.Prefix = strings.ToLower(strings.TrimSpace(d.Prefix))
			if d.Suffix != "" && strings.Contains(d.Suffix, ".") && appActValidTag(d.Use) {
				c.Domains = append(c.Domains, d)
			}
		}
		for _, t := range a.DomainOnly {
			if appActValidTag(t) {
				c.DomainOnly = append(c.DomainOnly, t)
			}
		}
		return c
	}
	for cat, a := range raw.Categories {
		out.Categories[strings.ToLower(strings.TrimSpace(cat))] = clean(a)
	}
	for id, a := range raw.Apps {
		out.Apps[id] = clean(a)
	}
	return out
}

// appActCatOf 类别查表键: 原样; 没有且以 game 开头的按 game
func appActCatOf(set *appActSet, cat string) (appActApp, bool) {
	c := strings.ToLower(strings.TrimSpace(cat))
	if a, ok := set.Categories[c]; ok {
		return a, true
	}
	if strings.HasPrefix(c, "game") {
		a, ok := set.Categories["game"]
		return a, ok
	}
	return appActApp{}, false
}

// appActShapeAllowed 流形态判出的 tag 能不能用在这个应用上: 应用或类别写了这个 tag 的说法,
// 且不在两者的 domain_only 里。没有规则文件时不限制。
func appActShapeAllowed(set *appActSet, appID, cat, tag string) bool {
	if set == nil {
		return true
	}
	a, aok := set.Apps[appID]
	c, cok := appActCatOf(set, cat)
	has := (aok && a.Labels[tag] != "") || (cok && c.Labels[tag] != "")
	if !has {
		return false
	}
	for _, x := range [][]string{a.DomainOnly, c.DomainOnly} {
		for _, t := range x {
			if t == tag {
				return false
			}
		}
	}
	return true
}

// appActDomainUse 按该应用的域名用途规则给主机名打标签(只对归到这个应用的连接用)
func appActDomainUse(set *appActSet, appID, host string) string {
	if set == nil || host == "" {
		return ""
	}
	a, ok := set.Apps[appID]
	if !ok || len(a.Domains) == 0 {
		return ""
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, d := range a.Domains {
		if h != d.Suffix && !strings.HasSuffix(h, "."+d.Suffix) {
			continue
		}
		if d.Prefix != "" {
			first := h
			if i := strings.IndexByte(h, '.'); i >= 0 {
				first = h[:i]
			}
			if !strings.HasPrefix(first, d.Prefix) {
				continue
			}
		}
		return d.Use
	}
	return ""
}

// appActivityTag 一条连接的用途标签与来源(""=不参与)。shapeType / shapeConf 来自
// flow_shape.go 对这条连接的判类, udp = 这条连接是 UDP。来源:
//   - domain: 域名用途规则命中, 且流形态没有判成别的;
//   - domain_weak: 域名规则命中, 但流形态判成了别的(比如看评论时视频 CDN 在预取)——
//     仍按域名的标签, 但不当域名证据(置信度按流形态算);
//   - shape: 流形态, 且这个应用 / 类别允许这个标签(appActShapeAllowed)。
//     例外: 允许通话、不允许直播形态的应用(会议 / 社交), UDP 上「下行稳定、几乎没上行」的
//     直播形态算语音通话 —— 会议旁听、通话里对方开摄像头自己关, 都不是在看直播。
func appActivityTag(appID, cat, host, shapeType string, shapeConf float64, udp bool) (tag, src string) {
	set := appActCur.Load()
	shapeOK := appActValidTag(shapeType) && shapeConf >= appActShapeMinConf
	if u := appActDomainUse(set, appID, host); u != "" {
		if shapeOK && shapeType != u && shapeType != ttBackground {
			return u, "domain_weak"
		}
		return u, "domain"
	}
	if !shapeOK {
		return "", ""
	}
	t := shapeType
	if t == ttLive && udp && !appActShapeAllowed(set, appID, cat, ttLive) && appActShapeAllowed(set, appID, cat, ttVoice) {
		t = ttVoice
	}
	if !appActShapeAllowed(set, appID, cat, t) {
		return "", ""
	}
	return t, "shape"
}

// ─── 总开关与每轮守卫(v5.34.0-rc2) ──────────────────────────────────────────────

// appActEnabled 总开关(data/dpi_experiment.json 的 activity_detail, 默认关)。关着时不打标签、
// 不输出; 每轮 app_usage 从文件刷新, 动作写完立即生效。
var appActEnabled atomic.Bool

// appActGuard 本轮的守卫(app_usage 每轮锁外算好)。
type appActGuard struct {
	limited    map[string]bool // mac → 正被 HNC 限速(设备限速 / 配额 / 分时段生效 / 全局整形)
	limitedApp map[string]bool // "mac|app_id" → 应用限速
	vpn        map[string]bool // mac → 疑似 / 确定走 VPN(traffic_ident.go)
	offload    bool            // 网络共享硬件加速正在旁路(conntrack 计数停住, 看到的不全)
}

var appActGuardCur atomic.Pointer[appActGuard]

// appActMaxTickSec 采样间隔超过它(省电档)→ 不输出: 节奏被平均掉, 防抖要等好几分钟
const appActMaxTickSec = 45.0

var appActExpCache struct {
	mu       sync.Mutex
	path     string
	key      string
	disabled bool
}

// appActEnabledFor 读 data/dpi_experiment.json 的 activity_detail(按 mtime 缓存; 缺失 = 关)
func appActEnabledFor(hncDir string) bool {
	if hncDir == "" {
		return false
	}
	p := fgExperimentPath(hncDir)
	key := "-"
	if fi, err := os.Stat(p); err == nil {
		key = strconv.FormatInt(fi.ModTime().UnixNano(), 10) + ":" + strconv.FormatInt(fi.Size(), 10)
	}
	appActExpCache.mu.Lock()
	defer appActExpCache.mu.Unlock()
	if appActExpCache.path == p && appActExpCache.key == key {
		return !appActExpCache.disabled
	}
	on := false
	if b, err := os.ReadFile(p); err == nil && len(b) <= 64<<10 {
		var f struct {
			ActivityDetail bool `json:"activity_detail"`
		}
		if json.Unmarshal(b, &f) == nil {
			on = f.ActivityDetail
		}
	}
	appActExpCache.path, appActExpCache.key, appActExpCache.disabled = p, key, !on
	return on
}

// actionDPIActivityDetail 开 / 关「在 App 里干什么」(原子写, 保留文件里的其它键)。
//
//	dpi_activity_detail {enabled: 1|0|true|false}
func actionDPIActivityDetail(hncDir string, p map[string]string) actionResp {
	var on bool
	switch strings.ToLower(strings.TrimSpace(p["enabled"])) {
	case "1", "true", "on":
		on = true
	case "0", "false", "off":
	default:
		return actionResp{OK: false, Error: "bad params", Detail: "enabled must be 1 or 0"}
	}
	path := fgExperimentPath(hncDir)
	m := map[string]interface{}{}
	if b, err := os.ReadFile(path); err == nil && len(b) <= 64<<10 {
		_ = json.Unmarshal(b, &m)
	}
	m["activity_detail"] = on
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return actionResp{OK: false, Error: "mkdir failed", Detail: err.Error()}
	}
	if err := writeFileAtomic(path, b); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	appActEnabled.Store(on)
	return actionResp{OK: true, Detail: "activity_detail=" + strconv.FormatBool(on)}
}

// appActGuardRefresh app_usage 每轮(锁外)调用: 刷新总开关; 开着时算守卫(关着不读任何文件)。
// limitedNow = 限速控制器里配额 / 分时段正在生效的设备(可为 nil)。
func appActGuardRefresh(hncDir string, limitedNow map[string]bool, now time.Time) {
	on := appActEnabledFor(hncDir)
	appActEnabled.Store(on)
	if !on {
		appActGuardCur.Store(nil)
		return
	}
	g := &appActGuard{limited: map[string]bool{}, limitedApp: map[string]bool{}, vpn: map[string]bool{}}
	for mac := range limitedNow {
		g.limited[mac] = true
	}
	if obs, _, ok := readObserved(hncDir); ok {
		for mac, r := range obs {
			if r.DownKbit > 0 || r.UpKbit > 0 {
				g.limited[mac] = true
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json")); err == nil {
		var top struct {
			Shaper interface{} `json:"global_shaper_enabled"`
		}
		if json.Unmarshal(b, &top) == nil && truthy(top.Shaper) {
			g.limited["*"] = true
		}
	}
	for _, it := range loadAppLimits(hncDir).Items {
		if it.DownMbps > 0 {
			g.limitedApp[strings.ToLower(it.MAC)+"|"+it.AppID] = true
		}
	}
	for mac, v := range identVPNVerdicts() {
		if v.Level == "likely" || v.Level == "certain" {
			g.vpn[mac] = true
		}
	}
	if st, ok := offloadGuardFreshState(hncDir, 3*time.Minute); ok && st == "ACTIVE" {
		g.offload = true
	}
	appActGuardCur.Store(g)
}

// appActLimited 这台设备 / 这个应用此刻是否被 HNC 限速
func appActLimited(g *appActGuard, mac, appID string) bool {
	return g != nil && (g.limited["*"] || g.limited[mac] || g.limitedApp[mac+"|"+appID])
}

// appActGate 输出闸门: 总开关关着、省电档(采样间隔 > 45 秒)、疑似 VPN、硬件加速旁路 → 不说。
func appActGate(mac string, a *fgActivity, dt float64) *fgActivity {
	if a == nil || !appActEnabled.Load() || dt > appActMaxTickSec {
		return nil
	}
	if g := appActGuardCur.Load(); g != nil && (g.offload || g.vpn[mac]) {
		return nil
	}
	return a
}

// appActForDelta 记账时一条已归属差分的用途标签: 主机名 = 连接自己的 SNI > 目的 IP 反查名,
// 流形态 = flow_shape.go 本轮对这条连接的判类(它在记账之前跑完)。总开关关着 → 不算;
// 设备 / 应用被 HNC 限速时, 流形态判出的视频 / 直播不用(令牌桶把点播的突发削成恒速,
// 正好像直播; 限速低于视频码率时视频规则又永远不中)。
func appActForDelta(ix *identCtx, mac, appID, cat string, dl appUsageDelta, names map[string]ipName) (string, string) {
	if !appActEnabled.Load() {
		return "", ""
	}
	host := ""
	if ix != nil && ix.fp != nil && dl.Key != "" {
		host = ix.fp.connSNI(dl.Key)
	}
	if host == "" {
		host = names[dl.Dst].Name
	}
	tt, ttc, _ := flowTrafficType(dl.Key)
	tag, src := appActivityTag(appID, cat, host, tt, ttc, strings.HasPrefix(dl.Key, "udp|"))
	if src != "domain" && (tag == ttVideo || tag == ttLive) && appActLimited(appActGuardCur.Load(), mac, appID) {
		return "", ""
	}
	return tag, src
}

// appActLabel 显示名: 应用专属 > 类别 > 通用
func appActLabel(appID, cat, tag string) string {
	if set := appActCur.Load(); set != nil {
		if a, ok := set.Apps[appID]; ok {
			if l := a.Labels[tag]; l != "" {
				return l
			}
		}
		if c, ok := appActCatOf(set, cat); ok && c.Labels[tag] != "" {
			return c.Labels[tag]
		}
	}
	return trafficTypeLabels[tag]
}

// ─── 每个 (设备, 应用) 的状态 ────────────────────────────────────────────────

// fgActivity /api/devices[].fg.activity
type fgActivity struct {
	ID    string  `json:"id"`
	Label string  `json:"label"`
	Conf  float64 `json:"conf"`
	Src   string  `json:"src"` // domain | shape
}

type appActTrack struct {
	w      map[string]float64 // 标签 → 衰减后的字节
	dom    map[string]float64 // 其中来自域名规则的
	cur    string
	lead   string
	leadN  int
	result *fgActivity
}

// actStep 每轮: 衰减旧字节、加上本轮各标签的字节, 再按防抖规则定当前标签。
// bytes / domBytes 为本轮该应用各标签的字节(domBytes ⊆ bytes)。
func (s *appActTrack) actStep(bytes, domBytes map[string]uint64, dt float64, appID, cat string) {
	if s.w == nil {
		s.w, s.dom = map[string]float64{}, map[string]float64{}
	}
	k := math.Exp(-dt / appActTau)
	for t := range s.w {
		s.w[t] *= k
		s.dom[t] *= k
		if s.w[t] < 1 {
			delete(s.w, t)
			delete(s.dom, t)
		}
	}
	for t, b := range bytes {
		s.w[t] += float64(b)
		s.dom[t] += float64(domBytes[t])
	}
	var total, best float64
	top := ""
	for t, w := range s.w {
		sc := w * appActWeight(t)
		total += sc
		if sc > best || (sc == best && t < top) {
			best, top = sc, t
		}
	}
	if top == "" || total < appActMinWeight {
		s.cur, s.lead, s.leadN, s.result = "", "", 0, nil
		return
	}
	switch {
	case s.cur == "" || s.w[s.cur] <= 0 || top == s.cur:
		s.cur, s.lead, s.leadN = top, "", 0
	case top == s.lead:
		s.leadN++
		if s.leadN >= appActSwitchTicks {
			s.cur, s.lead, s.leadN = top, "", 0
		}
	default:
		s.lead, s.leadN = top, 1
		if s.leadN >= appActSwitchTicks {
			s.cur, s.lead, s.leadN = top, "", 0
		}
	}
	cw := s.w[s.cur]
	src, factor := "shape", appActShapeFactor
	if cw > 0 && s.dom[s.cur] >= cw/2 {
		src, factor = "domain", 1.0
	}
	conf := math.Min(appActMaxConf, cw*appActWeight(s.cur)/total*factor)
	if conf < appActMinConf {
		s.result = nil
		return
	}
	s.result = &fgActivity{ID: s.cur, Label: appActLabel(appID, cat, s.cur), Conf: round2(conf), Src: src}
}
