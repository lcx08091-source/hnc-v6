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

type appActApp struct {
	Labels  map[string]string `json:"labels"`
	Domains []appActDomain    `json:"domains"`
}

type appActSet struct {
	Categories map[string]map[string]string `json:"categories"`
	Apps       map[string]appActApp         `json:"apps"`
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

// appActLoad 读并清洗规则文件; 读不到 / 太大 / 坏了 → nil(只用通用说法)
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
	out := &appActSet{Categories: map[string]map[string]string{}, Apps: map[string]appActApp{}}
	clean := func(m map[string]string) map[string]string {
		c := map[string]string{}
		for tag, lbl := range m {
			if lbl = strings.TrimSpace(lbl); appActValidTag(tag) && lbl != "" && len([]rune(lbl)) <= 16 {
				c[tag] = lbl
			}
		}
		return c
	}
	for cat, m := range raw.Categories {
		out.Categories[strings.ToLower(strings.TrimSpace(cat))] = clean(m)
	}
	for id, a := range raw.Apps {
		ca := appActApp{Labels: clean(a.Labels)}
		for _, d := range a.Domains {
			d.Suffix = strings.Trim(strings.ToLower(strings.TrimSpace(d.Suffix)), ".")
			d.Prefix = strings.ToLower(strings.TrimSpace(d.Prefix))
			if d.Suffix != "" && strings.Contains(d.Suffix, ".") && appActValidTag(d.Use) {
				ca.Domains = append(ca.Domains, d)
			}
		}
		out.Apps[id] = ca
	}
	return out
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
// flow_shape.go 对这条连接的判类。
func appActivityTag(appID, host, shapeType string, shapeConf float64) (tag, src string) {
	if u := appActDomainUse(appActCur.Load(), appID, host); u != "" {
		return u, "domain"
	}
	if appActValidTag(shapeType) && shapeConf >= appActShapeMinConf {
		return shapeType, "shape"
	}
	return "", ""
}

// appActForDelta 记账时一条已归属差分的用途标签: 主机名 = 连接自己的 SNI > 目的 IP 反查名,
// 流形态 = flow_shape.go 本轮对这条连接的判类(它在记账之前跑完)。
func appActForDelta(ix *identCtx, appID string, dl appUsageDelta, names map[string]ipName) (string, string) {
	host := ""
	if ix != nil && ix.fp != nil && dl.Key != "" {
		host = ix.fp.connSNI(dl.Key)
	}
	if host == "" {
		host = names[dl.Dst].Name
	}
	tt, ttc, _ := flowTrafficType(dl.Key)
	return appActivityTag(appID, host, tt, ttc)
}

// appActLabel 显示名: 应用专属 > 类别 > 通用
func appActLabel(appID, cat, tag string) string {
	if set := appActCur.Load(); set != nil {
		if a, ok := set.Apps[appID]; ok {
			if l := a.Labels[tag]; l != "" {
				return l
			}
		}
		c := strings.ToLower(strings.TrimSpace(cat))
		if m, ok := set.Categories[c]; ok && m[tag] != "" {
			return m[tag]
		}
		if strings.HasPrefix(c, "game") {
			if m, ok := set.Categories["game"]; ok && m[tag] != "" {
				return m[tag]
			}
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
