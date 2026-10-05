// flow_shape.go — DPI v2: 流形态分类(不看内容, 只看 conntrack 字节/包计数随时间的形状)
//
// 每轮 app_usage 采样(基准 10 s, 省电档可到 30–60 s)对每条热点客户端→外网的连接记一个
// 样本 {dt, 上/下行字节差, 上/下行包数差}; 连接被内核销毁(DESTROY 事件)时用事件里的最终
// 字节补最后一个(部分)样本。保留最近 fsWindow 个样本(≈ 1 分钟), 算特征后按下表判类。
//
// ── 特征(窗口内, 只用完整样本; 新连接的第一个样本起点未知 = 部分样本, 只计总量) ──
//   up/dn      平均速率 bps            tot = up + dn
//   bidir      min(up,dn)/max(up,dn)   双向对称度
//   active     速率 ≥ fsActiveBps(4 kbps) 的样本占比
//   cvDn/cvTot 每样本速率的变异系数(std/mean): 稳定 vs 突发
//   peakDn     单样本最高下行速率
//   pszUp/Dn   平均包长(字节/包)       ppsUp/Dn 包速率
//   cvPps      每样本包速率的变异系数(实时流的节拍稳定度)
//
// ── 判类(按顺序, 第一个命中的为准; 阈值见下方常量)────────────────────────────
//  0. 完整样本 < 2: 下行 ≥ 20 Mbps → download(0.4); 否则 unknown
//  1. tot < 2 kbps                                              → background(后台心跳)
//  2. UDP(非 DNS/NTP/mDNS/SSDP/DHCP/NetBIOS)且 bidir ≥ 0.15(443 端口要求 ≥ 0.3)、
//     active ≥ 0.8、每个方向 ≥ 4 kbps、tot ≤ 8 Mbps(实时交互流):
//       tot ≥ 250 kbps                                          → video_call
//       类别 game, 或 包小(平均 < 90 B)/包慢(任一方向 < 25 pps)  → gaming
//       否则(双向 ≥ 25 pps、包 ≥ 90 B、tot ≥ 16 kbps)            → voice_call
//     TCP 且规则类别 game、tot < 250 kbps、active ≥ 0.8、bidir ≥ 0.1 → gaming
//  3. 上行 ≥ 1 Mbps 且 dn/up < 0.15 且 active ≥ 0.6              → upload(批量上传)
//  4. 下行为主(dn ≥ 300 kbps 且 up/dn < 0.2):
//       稳定(active = 1 且 cvDn ≤ 0.35):
//         dn ≥ 8 Mbps                     → download(类别 video → video_stream, 视频预缓冲)
//         dn < 8 Mbps 且持续 ≥ 30 s        → live_stream(类别 download → download)
//       不稳定(分块拉取: 有空闲样本或 cvDn > 0.35), 且 dn ≥ 500 kbps、peakDn ≥ 1.5 Mbps、
//         平均下行包 ≥ 600 B              → video_stream
//       其余                              → browsing
//  5. 其余(tot ≥ 2 kbps)                                        → browsing(请求/响应式突发)
// 置信度: 每条规则有基础值, 规则类别相符 / 节拍稳定 / 样本多时加分, 采样间隔 > 45 s 时 ×0.8,
// 上限 0.95。
//
// ── 设备「此刻在」────────────────────────────────────────────────────────────
//  a. 设备有持续 ≥ 3 个样本的实时流(gaming > video_call > voice_call, 置信度 ≥ 0.5)→ 取它
//  b. 否则把设备所有非实时流按轮相加成一条设备级时间序列, 用同一张表判类(视频 App 每个分片
//     新开连接时, 单条连接太短, 合起来才看得出形状)
//  c. 窗口内设备完全没有字节 → idle
//  防抖: 新判类需连续 2 轮一致才替换当前值(第一次判出或从 idle 恢复除外); since = 新类
//  首次出现的时间。结果: /api/devices[].traffic_type {type,label,confidence,since},
//  /api/connections 每行 traffic_type / traffic_conf。
//
// 稳健性: dt ≤ 0 或 > 5 分钟(时钟跳变/长时间没采样)→ 全部重建基线; 计数器变小(五元组被
// 复用)→ 该连接重建基线; 没收到 DESTROY 的连接在快照里消失 → 标记结束, 窗口过后丢弃。
// 内存上界: fsMaxFlows 条连接 × ~0.5 KB。

package main

import (
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	fsWindow       = 6
	fsMaxFlows     = 16384
	fsMaxDT        = 5 * time.Minute
	fsSlowDT       = 45 // 秒; 采样间隔大于此值时降置信度
	fsEndedKeepFor = 60 * time.Second

	fsActiveBps      = 4000
	fsBackgroundBps  = 2000
	fsRTBidir        = 0.15
	fsRTBidir443     = 0.3
	fsRTActive       = 0.8
	fsRTMinDirBps    = 4000
	fsRTMaxBps       = 8_000_000
	fsVideoCallBps   = 250_000
	fsVoiceMinBps    = 16_000
	fsVoiceMinPPS    = 25
	fsVoiceMinPkt    = 90
	fsUploadBps      = 1_000_000
	fsDownMinBps     = 300_000
	fsDownUpRatio    = 0.2
	fsSteadyCV       = 0.35
	fsBulkBps        = 8_000_000
	fsLiveMinDur     = 30 // 秒
	fsVideoMinBps    = 500_000
	fsVideoPeakBps   = 1_500_000
	fsVideoMinPkt    = 600
	fsBurstPeakBps   = 20_000_000
	fsDevRTMinSample = 3
	fsDevSwitchTicks = 2
)

const (
	ttUnknown    = "unknown"
	ttIdle       = "idle"
	ttBackground = "background"
	ttBrowsing   = "browsing"
	ttVideo      = "video_stream"
	ttLive       = "live_stream"
	ttVoice      = "voice_call"
	ttVideoCall  = "video_call"
	ttGaming     = "gaming"
	ttDownload   = "download"
	ttUpload     = "upload"
)

var trafficTypeLabels = map[string]string{
	ttUnknown: "识别中", ttIdle: "空闲", ttBackground: "后台", ttBrowsing: "浏览",
	ttVideo: "看视频", ttLive: "看直播", ttVoice: "语音通话", ttVideoCall: "视频通话",
	ttGaming: "玩游戏", ttDownload: "下载", ttUpload: "上传",
}

func isRealtimeType(t string) bool { return t == ttVoice || t == ttVideoCall || t == ttGaming }

var fsNonRTUDPPorts = map[int]bool{53: true, 123: true, 853: true, 5353: true, 1900: true, 137: true, 138: true, 67: true, 68: true}

type fsSample struct {
	dt       float64 // 秒
	up, dn   uint64
	upP, dnP uint64
	hasPkts  bool
	partial  bool // 起点或终点不在采样点上(新连接第一轮 / DESTROY 补的尾巴)
}

type fsFeatures struct {
	n, nAll           int
	dur               float64
	upBps, dnBps      float64
	bidir             float64
	active            float64
	idle              int
	cvDn, cvTot       float64
	peakDn            float64
	pszUp, pszDn, psz float64
	ppsUp, ppsDn      float64
	cvPps             float64
	maxDT             float64
	partialDnBps      float64
}

func cvOf(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var m float64
	for _, x := range xs {
		m += x
	}
	m /= float64(len(xs))
	if m <= 0 {
		return 0
	}
	var v float64
	for _, x := range xs {
		v += (x - m) * (x - m)
	}
	return math.Sqrt(v/float64(len(xs))) / m
}

// fsFeaturesOf 纯函数(单测直接喂)
func fsFeaturesOf(ss []fsSample) fsFeatures {
	f := fsFeatures{nAll: len(ss)}
	var dt, up, dn, pdt, pdn, upP, dnP, pkB, pkUpB, pkDnB float64
	var dnR, totR, ppsR []float64
	for _, s := range ss {
		if s.dt > f.maxDT {
			f.maxDT = s.dt
		}
		if s.partial || s.dt <= 0 {
			if s.dt > 0 {
				pdt += s.dt
				pdn += float64(s.dn)
			}
			continue
		}
		f.n++
		dt += s.dt
		up += float64(s.up)
		dn += float64(s.dn)
		r := float64(s.dn) * 8 / s.dt
		dnR = append(dnR, r)
		tr := float64(s.up+s.dn) * 8 / s.dt
		totR = append(totR, tr)
		if tr >= fsActiveBps {
			f.active++
		} else {
			f.idle++
		}
		if r > f.peakDn {
			f.peakDn = r
		}
		if s.hasPkts {
			upP += float64(s.upP)
			dnP += float64(s.dnP)
			pkB += s.dt
			pkUpB += float64(s.up)
			pkDnB += float64(s.dn)
			ppsR = append(ppsR, float64(s.upP+s.dnP)/s.dt)
		}
	}
	if pdt > 0 {
		f.partialDnBps = pdn * 8 / pdt
	}
	f.dur = dt + pdt
	if f.n == 0 || dt <= 0 {
		return f
	}
	f.active /= float64(f.n)
	f.upBps, f.dnBps = up*8/dt, dn*8/dt
	if hi := math.Max(f.upBps, f.dnBps); hi > 0 {
		f.bidir = math.Min(f.upBps, f.dnBps) / hi
	}
	f.cvDn, f.cvTot, f.cvPps = cvOf(dnR), cvOf(totR), cvOf(ppsR)
	if upP > 0 {
		f.pszUp = pkUpB / upP
	}
	if dnP > 0 {
		f.pszDn = pkDnB / dnP
	}
	if upP+dnP > 0 {
		f.psz = (pkUpB + pkDnB) / (upP + dnP)
	}
	if pkB > 0 {
		f.ppsUp, f.ppsDn = upP/pkB, dnP/pkB
	}
	return f
}

type fsHint struct {
	proto    string // "" = 设备级聚合(不判实时流)
	dport    int
	category string // 规则库类别(game / video / social / download ...)
}

func fsCat(h fsHint, cats ...string) bool {
	c := strings.ToLower(h.category)
	for _, x := range cats {
		if c == x || strings.HasPrefix(c, x+"-") || strings.HasPrefix(c, x+"_") {
			return true
		}
	}
	return false
}

// classifyFlowShape 纯函数: 特征 + 提示 → (类型, 置信度 0..1)
func classifyFlowShape(f fsFeatures, h fsHint) (string, float64) {
	t, c := classifyFlowShapeRaw(f, h)
	if t != ttUnknown && f.maxDT > fsSlowDT {
		c *= 0.8
	}
	if c > 0.95 {
		c = 0.95
	}
	return t, math.Round(c*100) / 100
}

func classifyFlowShapeRaw(f fsFeatures, h fsHint) (string, float64) {
	if f.n < 2 {
		if f.partialDnBps >= fsBurstPeakBps || (f.n == 1 && f.dnBps >= fsBurstPeakBps) {
			return ttDownload, 0.4
		}
		return ttUnknown, 0
	}
	tot := f.upBps + f.dnBps
	if tot < fsBackgroundBps {
		c := 0.6
		if f.n >= 4 {
			c += 0.1
		}
		if f.active <= 0.5 {
			c += 0.1
		}
		return ttBackground, c
	}
	// 实时交互流
	if h.proto == "udp" && !fsNonRTUDPPorts[h.dport] {
		minBidir := fsRTBidir
		if h.dport == 443 {
			minBidir = fsRTBidir443
		}
		if f.bidir >= minBidir && f.active >= fsRTActive && math.Min(f.upBps, f.dnBps) >= fsRTMinDirBps && tot <= fsRTMaxBps {
			steady := 0.0
			if f.ppsUp+f.ppsDn > 0 && f.cvPps <= fsSteadyCV {
				steady = 0.1
			}
			switch {
			case tot >= fsVideoCallBps:
				c := 0.65 + steady
				if fsCat(h, "social", "im", "voip", "office") {
					c += 0.15
				}
				return ttVideoCall, c
			case fsCat(h, "game", "sdk-tencent-game"):
				return ttGaming, 0.8 + steady
			case fsCat(h, "social", "im", "voip"):
				return ttVoice, 0.75 + steady
			case f.psz > 0 && f.psz < fsVoiceMinPkt, f.ppsUp > 0 && (f.ppsUp < fsVoiceMinPPS || f.ppsDn < fsVoiceMinPPS):
				return ttGaming, 0.55 + steady
			case tot >= fsVoiceMinBps:
				return ttVoice, 0.6 + steady
			default:
				return ttGaming, 0.45 + steady
			}
		}
	}
	if h.proto == "tcp" && fsCat(h, "game") && tot < fsVideoCallBps && f.active >= fsRTActive && f.bidir >= 0.1 {
		return ttGaming, 0.6
	}
	// 批量上传
	if f.upBps >= fsUploadBps && f.dnBps/f.upBps < 0.15 && f.active >= 0.6 {
		return ttUpload, 0.65
	}
	// 下行为主
	if f.dnBps >= fsDownMinBps && f.upBps/f.dnBps < fsDownUpRatio {
		steady := f.active >= 1 && f.cvDn <= fsSteadyCV
		video := fsCat(h, "video", "music")
		if steady {
			if f.dnBps >= fsBulkBps {
				if video {
					return ttVideo, 0.6
				}
				c := 0.7
				if f.pszDn >= 1000 {
					c += 0.1
				}
				if fsCat(h, "download", "system") {
					c += 0.1
				}
				return ttDownload, c
			}
			if f.dur >= fsLiveMinDur {
				if fsCat(h, "download", "system") {
					return ttDownload, 0.6
				}
				c := 0.5
				if video {
					c += 0.2
				}
				return ttLive, c
			}
		} else if f.dnBps >= fsVideoMinBps && f.peakDn >= fsVideoPeakBps && (f.pszDn == 0 || f.pszDn >= fsVideoMinPkt) {
			c := 0.6
			if f.idle > 0 {
				c += 0.1 // 典型的「拉一段、停一会」
			}
			if video {
				c += 0.15
			}
			return ttVideo, c
		}
		return ttBrowsing, 0.4
	}
	c := 0.5
	if f.cvTot >= 0.5 {
		c += 0.1
	}
	return ttBrowsing, c
}

// ─── 状态 ─────────────────────────────────────────────────────────────

type fsFlow struct {
	mac, dst string
	proto    string
	dport    int
	cat      string
	up, dn   uint64 // 上次累计
	upP, dnP uint64
	lastAt   time.Time
	samples  []fsSample
	ended    bool
	endedAt  time.Time
	typ      string
	conf     float64
	since    time.Time
	seenTick bool
	fcDone   bool // v5.28 B3: 已收进流量形状分类的训练池(flow_cls.go)
}

type fsDev struct {
	samples []fsSample
	typ     string
	conf    float64
	since   time.Time
	cand    string
	candN   int
	candAt  time.Time
}

type fsState struct {
	lastAt time.Time
	flows  map[string]*fsFlow
	devs   map[string]*fsDev
}

func newFSState() *fsState {
	return &fsState{flows: map[string]*fsFlow{}, devs: map[string]*fsDev{}}
}

// TrafficType 发布形态
type trafficType struct {
	Type       string  `json:"type"`
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
	Since      int64   `json:"since,omitempty"`
}

type fsFlowPub struct {
	typ  string
	conf float64
}

var fsSt = newFSState() // 只在 app_usage 采样里改(调用方串行)

var fsPub struct {
	mu    sync.Mutex
	flows map[string]fsFlowPub
	devs  map[string]trafficType
}

func fsPush(ss []fsSample, s fsSample) []fsSample {
	ss = append(ss, s)
	if len(ss) > fsWindow {
		ss = append(ss[:0], ss[len(ss)-fsWindow:]...)
	}
	return ss
}

// observe 一轮采样(纯逻辑, 无 I/O; 单测直接喂)。
//
//	entries: 本轮 conntrack 快照; events: 自上轮以来的 DESTROY(带最终字节)
//	owner:   客户端 IP → MAC; cat: 目的 IP → 规则类别("" = 不知道)
func (st *fsState) observe(now time.Time, entries []ctEntry, events []ctDestroy, owner map[string]string, cat func(dst string) string) {
	dt := 0.0
	if !st.lastAt.IsZero() {
		dt = now.Sub(st.lastAt).Seconds()
		if dt == 0 {
			return // 同一份快照(conntrackSnapshot 1 s 共享)重复喂: 什么都不做
		}
	}
	if st.lastAt.IsZero() || dt <= 0 || now.Sub(st.lastAt) > fsMaxDT {
		// 首轮 / 时钟跳变 / 太久没采样: 重建基线
		st.flows, st.devs = map[string]*fsFlow{}, map[string]*fsDev{}
		dt = 0
	}
	st.lastAt = now
	devTick := map[string]*fsSample{}
	addDev := func(fl *fsFlow, s fsSample) {
		if isRealtimeType(fl.typ) {
			return
		}
		d := devTick[fl.mac]
		if d == nil {
			d = &fsSample{dt: dt, hasPkts: true}
			devTick[fl.mac] = d
		}
		d.up += s.up
		d.dn += s.dn
		if s.hasPkts {
			d.upP += s.upP
			d.dnP += s.dnP
		}
	}
	for _, fl := range st.flows {
		fl.seenTick = false
	}
	// DESTROY: 结清尾巴
	for _, ev := range events {
		if !ev.HasCnt {
			continue
		}
		fl := st.flows[ev.Key]
		if fl == nil {
			// 两次采样之间开始又结束、快照从没见过的短连接: 字节只进设备级序列;
			// 记一条已结束的占位, 让快照里可能残留的旧读数被跳过
			mac := owner[ev.Src]
			if mac == "" || isLocalDst(ev.Dst, owner) || dt <= 0 || len(st.flows) >= fsMaxFlows {
				continue
			}
			p, dp, _ := ctKeyParts(ev.Key)
			fl = &fsFlow{mac: mac, dst: ev.Dst, proto: p, dport: dp, typ: ttUnknown, ended: true, endedAt: now,
				up: ev.UpB, dn: ev.DnB, lastAt: now}
			s := fsSample{dt: dt, up: ev.UpB, dn: ev.DnB, partial: true}
			fl.samples = fsPush(fl.samples, s)
			st.flows[ev.Key] = fl
			addDev(fl, s)
			continue
		}
		if fl.ended {
			continue
		}
		s := fsSample{dt: ev.At.Sub(fl.lastAt).Seconds(), up: satSub(ev.UpB, fl.up), dn: satSub(ev.DnB, fl.dn), partial: true}
		if s.dt <= 0 || s.dt > dt+1 {
			s.dt = dt
		}
		fl.samples = fsPush(fl.samples, s)
		fl.ended, fl.endedAt = true, now
		if dt > 0 {
			addDev(fl, s)
		}
	}
	for i := range entries {
		e := &entries[i]
		mac := owner[e.Src]
		if mac == "" || isLocalDst(e.Dst, owner) {
			continue
		}
		k := e.key()
		fl := st.flows[k]
		if fl != nil && fl.ended {
			// 快照里是已结清连接的旧读数(或同五元组新连接): 已结清的按新连接重来
			if fl.endedAt.Equal(now) {
				fl.seenTick = true
				continue
			}
			fl = nil
		}
		if fl == nil {
			if len(st.flows) >= fsMaxFlows {
				continue
			}
			fl = &fsFlow{mac: mac, dst: e.Dst, proto: e.Proto, dport: e.Dport, typ: ttUnknown}
			if cat != nil {
				fl.cat = cat(e.Dst)
			}
			st.flows[k] = fl
			if dt > 0 {
				// 两次采样之间新建: 全部字节都在这段里, 但起点未知 → 部分样本
				s := fsSample{dt: dt, up: e.UpB, dn: e.DnB, upP: e.UpPkts, dnP: e.DnPkts, hasPkts: true, partial: true}
				fl.samples = fsPush(fl.samples, s)
				addDev(fl, s)
			}
		} else if e.UpB < fl.up || e.DnB < fl.dn || e.UpPkts < fl.upP || e.DnPkts < fl.dnP {
			fl.samples = nil // 计数器回退: 重建基线
		} else if dt > 0 {
			s := fsSample{dt: dt, up: e.UpB - fl.up, dn: e.DnB - fl.dn, upP: e.UpPkts - fl.upP, dnP: e.DnPkts - fl.dnP, hasPkts: true}
			fl.samples = fsPush(fl.samples, s)
			addDev(fl, s)
		}
		fl.up, fl.dn, fl.upP, fl.dnP, fl.lastAt, fl.seenTick = e.UpB, e.DnB, e.UpPkts, e.DnPkts, now, true
		if cat != nil && fl.cat == "" {
			fl.cat = cat(e.Dst)
		}
	}
	// 判类 + 清理
	for k, fl := range st.flows {
		if !fl.seenTick && !fl.ended {
			fl.ended, fl.endedAt = true, now // 没有 DESTROY 事件就从快照里消失了
		}
		if fl.ended && now.Sub(fl.endedAt) > fsEndedKeepFor {
			delete(st.flows, k)
			continue
		}
		if fl.ended {
			continue // 形态冻结在结束前
		}
		t, c := classifyFlowShape(fsFeaturesOf(fl.samples), fsHint{proto: fl.proto, dport: fl.dport, category: fl.cat})
		if t != fl.typ {
			fl.since = now
		}
		fl.typ, fl.conf = t, c
	}
	// 设备
	macs := map[string]bool{}
	for m := range st.devs {
		macs[m] = true
	}
	for m := range devTick {
		macs[m] = true
	}
	for _, fl := range st.flows {
		macs[fl.mac] = true
	}
	for mac := range macs {
		d := st.devs[mac]
		if d == nil {
			d = &fsDev{}
			st.devs[mac] = d
		}
		if dt > 0 {
			s := fsSample{dt: dt, hasPkts: true}
			if x := devTick[mac]; x != nil {
				s = *x
			}
			d.samples = fsPush(d.samples, s)
		}
		cand, conf := st.devCandidate(mac, d)
		st.devStep(d, cand, conf, now)
		if d.typ == ttIdle && len(d.samples) >= fsWindow && !st.devHasFlows(mac) {
			delete(st.devs, mac)
		}
	}
}

func (st *fsState) devHasFlows(mac string) bool {
	for _, fl := range st.flows {
		if fl.mac == mac {
			return true
		}
	}
	return false
}

func (st *fsState) devCandidate(mac string, d *fsDev) (string, float64) {
	rank := map[string]int{ttGaming: 3, ttVideoCall: 2, ttVoice: 1}
	best, bestC, bestR := "", 0.0, 0
	topCat, topB := "", uint64(0)
	for _, fl := range st.flows {
		if fl.mac != mac || fl.ended {
			continue
		}
		if r := rank[fl.typ]; r > 0 && fl.conf >= 0.5 && len(fl.samples) >= fsDevRTMinSample {
			if r > bestR || (r == bestR && fl.conf > bestC) {
				best, bestC, bestR = fl.typ, fl.conf, r
			}
			continue
		}
		if n := len(fl.samples); n > 0 && !isRealtimeType(fl.typ) {
			if b := fl.samples[n-1].up + fl.samples[n-1].dn; b > topB {
				topB, topCat = b, fl.cat
			}
		}
	}
	if best != "" {
		return best, bestC
	}
	var any uint64
	for _, s := range d.samples {
		any += s.up + s.dn
	}
	if any == 0 {
		if len(d.samples) == 0 && st.devHasFlows(mac) {
			return ttUnknown, 0
		}
		return ttIdle, 0.9
	}
	t, c := classifyFlowShape(fsFeaturesOf(d.samples), fsHint{category: topCat})
	return t, c
}

// devStep 防抖: 连续 fsDevSwitchTicks 轮一致才切换
func (st *fsState) devStep(d *fsDev, cand string, conf float64, now time.Time) {
	if cand == d.typ {
		d.conf, d.cand, d.candN = conf, "", 0
		return
	}
	if d.typ == "" || d.typ == ttUnknown || d.typ == ttIdle {
		d.typ, d.conf, d.since, d.cand, d.candN = cand, conf, now, "", 0
		return
	}
	if cand == ttUnknown {
		return // 样本不够判不出来: 保持原值
	}
	if cand != d.cand {
		d.cand, d.candN, d.candAt = cand, 0, now
	}
	d.candN++
	if d.candN >= fsDevSwitchTicks {
		d.typ, d.conf, d.since, d.cand, d.candN = cand, conf, d.candAt, "", 0
	}
}

// publish 拷一份给请求路径
func (st *fsState) publish() {
	flows := make(map[string]fsFlowPub, len(st.flows))
	for k, fl := range st.flows {
		if fl.typ != "" {
			flows[k] = fsFlowPub{typ: fl.typ, conf: fl.conf}
		}
	}
	devs := make(map[string]trafficType, len(st.devs))
	for mac, d := range st.devs {
		if d.typ == "" {
			continue
		}
		tt := trafficType{Type: d.typ, Label: trafficTypeLabels[d.typ], Confidence: d.conf}
		if !d.since.IsZero() {
			tt.Since = d.since.Unix()
		}
		devs[mac] = tt
	}
	fsPub.mu.Lock()
	fsPub.flows, fsPub.devs = flows, devs
	fsPub.mu.Unlock()
}

// flowShapeTick app_usage 每轮调用(调用方持 appUsage.mu)
func flowShapeTick(now time.Time, sn *ctSnapshot, events []ctDestroy, owner map[string]string,
	apps map[string]ipApp, names map[string]ipName) {
	if sn == nil || !sn.readable || !sn.acct {
		fsSt = newFSState()
		fsSt.publish()
		return
	}
	cat := func(dst string) string {
		if a, ok := appForIP(dst, apps, names); ok {
			return a.Category
		}
		return ""
	}
	fsSt.observe(now, sn.entries, events, owner, cat)
	fsSt.publish()
}

func flowShapeReset() {
	fsSt = newFSState()
	fsSt.publish()
}

// trafficTypesByMAC /api/devices 用
func trafficTypesByMAC() map[string]trafficType {
	fsPub.mu.Lock()
	defer fsPub.mu.Unlock()
	out := make(map[string]trafficType, len(fsPub.devs))
	for k, v := range fsPub.devs {
		out[k] = v
	}
	return out
}

// flowTrafficType /api/connections 用(按 ctEntry.key())
func flowTrafficType(key string) (string, float64, bool) {
	fsPub.mu.Lock()
	defer fsPub.mu.Unlock()
	p, ok := fsPub.flows[key]
	return p.typ, p.conf, ok
}

// sortedTrafficTypes 测试/调试: 稳定输出
func sortedTrafficTypes(m map[string]trafficType) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v.Type)
	}
	sort.Strings(out)
	return out
}
