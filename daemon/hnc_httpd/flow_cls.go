// flow_cls.go — v5.28 B3: 按流量形状猜「应用类别」(影子运行, 只标注不改归属)。
//
// 目标: 规则库认不出的连接, 至少能猜出是 7 个大类里的哪一类:
//
//	视频 / 游戏 / 通话 / 音乐 / 下载 / 浏览 / 社交。
//
// 训练(自监督): 热点客户端上规则库已认出应用的连接(非广告/SDK/CDN 档,
// 即 appTier == tierApp), 标签 = 该应用的规则类别映射到 7 大类; 特征 =
// flow_shape.go 已在算的窗口特征(上/下行速率、对称度、活跃占比、变异系数、
// 峰值、平均包长、包速率、时长)+ 协议 UDP + 端口类(web / QUIC)。
// **不用 SNI / 域名本身当特征**(否则模型只是在背规则)。
// ALPN / JA4 首字符暂未纳入: 训练样本(fsFlow)与预测行(/api/connections)
// 的这两项可得性不一致(fsFlow 不含; 行里只有部分连接有 ja4), 纳入会造成
// 训练 / 预测口径漂移 —— 待后续把 DPI 样本与 flow 键关联后再补。
//
// 模型: 分箱朴素贝叶斯, 纯 Go 手写, 无外部依赖。每 30 分钟从样本池重训一次
// (挂在 app_usage 每轮上做时间判断), 池按类上限 2000 条、按时间淘汰, 模型
// 原子存 data/flow_cls.json。
//
// 预测: 只对「规则库/指纹没认出应用」的 /api/connections 行加
// cls_category / cls_conf(新字段, 不改归属、不改显示的应用名)。
//
// 评估: dpi_eval.go 的 flow_cls 段 —— 按时间切分(今天之前的样本训练,
// 今天已认出的样本当考题), 与 flow_shape.go 的手工判类映射到大类后并排对比。
package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// ── 大类与映射表 ─────────────────────────────────────────────────────────

var clsBigCats = []string{"视频", "游戏", "通话", "音乐", "下载", "浏览", "社交"}

// bigCatMap 规则库 category → 大类(白名单式; 表里没有的 TierApp 类别 → 浏览)。
// 非 TierApp(广告/SDK/CDN/系统)不进训练, 由 bigCatOfCategory 一并判掉。
var bigCatMap = map[string]string{
	"video":    "视频",
	"music":    "音乐",
	"game":     "游戏",
	"download": "下载",
	"social":   "社交",
	// 通话: 规则库没有可标注的语音通话类别(SNI 时代通话流量无域名),
	// 训练池里不会出现这一类, 保留类名是为了和手工判类(voice_call)对齐。
}

// bigCatOfCategory 规则类别 → (大类, 是否可用于训练)。
func bigCatOfCategory(category string) (string, bool) {
	if appTier(category) != tierApp {
		return "", false
	}
	if c, ok := bigCatMap[category]; ok {
		return c, true
	}
	return "浏览", true
}

// dpiEvalFlowCls v5.28 B3: /api/dpi_eval 的 flow_cls 段。
type dpiEvalFlowCls struct {
	Samples       int     `json:"samples"`        // 考题数(今天已认出的连接)
	TrainSamples  int     `json:"train_samples"`  // 训练样本数(今天之前)
	Classes       int     `json:"classes"`        // 考题里出现的大类数
	ModelAcc      float64 `json:"model_acc"`      // 模型准确率
	ManualAcc     float64 `json:"manual_acc"`     // flow_shape 手工判类映射到大类的对照准确率
	ManualSamples int     `json:"manual_samples"` // 手工列可比对的样本数
	Note          string  `json:"note,omitempty"`
}

// fsTypeBigCat flow_shape.go 的手工判类 → 大类(评估对比用)。
// ttIdle / ttBackground / ttUnknown → ""(不参与对比: 手工也认不出)。
var fsTypeBigCat = map[string]string{
	ttVideo: "视频", ttLive: "视频",
	ttVoice: "通话", ttVideoCall: "通话",
	ttGaming:   "游戏",
	ttDownload: "下载", ttUpload: "下载",
	ttBrowsing: "浏览",
}

// ── 特征: flow_shape 窗口特征 → 分箱向量 ────────────────────────────────

const (
	fcDims = 14 // 维度见 fcVecOf 注释
)

// fcEdges 每维的分箱边界(bin = 落在的区间序号, 0..len(edges))。
// 速率/包长/时长/包速率用 log10 轨道(数值跨 4~6 个数量级); 比例类用线性轨道。
var fcEdges = [fcDims][]float64{
	{3, 4, 5, 6, 7},         // 0  log10(下行 bps)   <1kbps,1k-10k,10k-100k,100k-1M,1M-10M,>10M
	{2, 3, 4, 5, 6},         // 1  log10(上行 bps)
	{0.15, 0.3, 0.5, 0.7},   // 2  对称度 up/(up+dn)
	{0.2, 0.4, 0.6, 0.8},    // 3  活跃占比
	{0.35, 0.6, 1.0, 1.5},   // 4  下行速率变异系数
	{0.35, 0.6, 1.0, 1.5},   // 5  总速率变异系数
	{4, 5, 6, 7},            // 6  log10(峰值下行 bps)
	{5.2, 5.9, 6.6, 7.3},    // 7  log10(平均包长 字节) ~160/500/1600/4k/…
	{0, 0.7, 1.4, 2.1, 2.8}, // 8  log10(上行 pps)
	{0, 0.7, 1.4, 2.1, 2.8}, // 9  log10(下行 pps)
	{0.7, 1.7, 2.7},         // 10 log10(持续秒) <5s,5-50,50-500,>500
	{0.5},                   // 11 UDP(0/1 两箱)
	{0.5},                   // 12 端口类: web(443/80/8080)(0/1)
	{0.5},                   // 13 端口类: QUIC(udp + 443)(0/1)
}

// fcBinOf v 落进哪个箱。
func fcBinOf(v float64, edges []float64) int {
	for i, e := range edges {
		if v < e {
			return i
		}
	}
	return len(edges)
}

// fcVec 一条连接的分箱特征向量。
type fcVec [fcDims]int

// fcVecOf flow_shape 的窗口特征 + 连接元信息 → 分箱向量(纯函数)。
func fcVecOf(f fsFeatures, fl *fsFlow) fcVec {
	var v fcVec
	lg := func(x float64) float64 { return math.Log10(x + 1) }
	v[0] = fcBinOf(lg(f.dnBps), fcEdges[0])
	v[1] = fcBinOf(lg(f.upBps), fcEdges[1])
	v[2] = fcBinOf(f.bidir, fcEdges[2])
	v[3] = fcBinOf(f.active, fcEdges[3])
	v[4] = fcBinOf(f.cvDn, fcEdges[4])
	v[5] = fcBinOf(f.cvTot, fcEdges[5])
	v[6] = fcBinOf(lg(f.peakDn), fcEdges[6])
	v[7] = fcBinOf(lg(f.psz), fcEdges[7])
	v[8] = fcBinOf(math.Log10(f.ppsUp+0.1), fcEdges[8])
	v[9] = fcBinOf(math.Log10(f.ppsDn+0.1), fcEdges[9])
	v[10] = fcBinOf(lg(f.dur), fcEdges[10])
	if fl != nil {
		if fl.proto == "udp" {
			v[11] = 1
		}
		switch fl.dport {
		case 443, 80, 8080:
			v[12] = 1
		}
		if fl.proto == "udp" && fl.dport == 443 {
			v[13] = 1
		}
	}
	return v
}

// ── 样本池 ──────────────────────────────────────────────────────────────

// fcSample 一条训练样本(带手工判类, 评估对比用; manual 可为空)。
type fcSample struct {
	vec    fcVec
	cat    string
	manual string
	ts     int64
}

const (
	fcPoolPerCat   = 2000 // 每类样本上限(超出按时间淘汰最旧)
	fcRetrainEvery = 30 * time.Minute
	fcMinFeats     = 3 // fsFeatures.n 至少几轮采样才收(防碎片)
	fcJSONVersion  = 1
)

var (
	fcPoolMu sync.Mutex
	fcPool   []fcSample
)

// fcPoolAdd 加一条样本并执行上限淘汰(按类)。返回是否加入。
func fcPoolAdd(s fcSample) bool {
	fcPoolMu.Lock()
	defer fcPoolMu.Unlock()
	fcPool = append(fcPool, s)
	// 淘汰: 某类超上限时丢最旧的
	nCat := map[string]int{}
	for _, x := range fcPool {
		nCat[x.cat]++
	}
	var over string
	for c, n := range nCat {
		if n > fcPoolPerCat {
			over = c
			break
		}
	}
	if over != "" {
		out := fcPool[:0]
		dropped := false
		for _, x := range fcPool {
			if !dropped && x.cat == over {
				dropped = true // 最旧的一条(池按追加序即时间序)
				continue
			}
			out = append(out, x)
		}
		fcPool = out
	}
	return true
}

// ── 模型: 分箱朴素贝叶斯 ────────────────────────────────────────────────

// fcModelJSON data/flow_cls.json 的落盘形态。
type fcModelJSON struct {
	Version   int                `json:"version"`
	TrainedAt int64              `json:"trained_at"`
	Samples   int                `json:"samples"`
	Count     map[string][][]int `json:"count"` // cat → 维 → 箱 → 计数
	NCat      map[string]int     `json:"n"`
}

type fcModel struct {
	m fcModelJSON
}

// fcTrain 训练(拉普拉斯平滑 α = 1)。空样本返回 nil。
func fcTrain(samples []fcSample, trainedAt int64) *fcModel {
	if len(samples) == 0 {
		return nil
	}
	m := &fcModel{m: fcModelJSON{
		Version:   fcJSONVersion,
		TrainedAt: trainedAt,
		Samples:   len(samples),
		Count:     map[string][][]int{},
		NCat:      map[string]int{},
	}}
	for _, s := range samples {
		if m.m.Count[s.cat] == nil {
			c := make([][]int, fcDims)
			for d := range c {
				c[d] = make([]int, len(fcEdges[d])+1)
			}
			m.m.Count[s.cat] = c
		}
		m.m.NCat[s.cat]++
		for d := 0; d < fcDims; d++ {
			m.m.Count[s.cat][d][s.vec[d]]++
		}
	}
	return m
}

// fcPredict 返回 (大类, 后验置信 0..1)。模型为空/类未知 → ok=false。
func fcPredict(m *fcModel, v fcVec) (string, float64, bool) {
	if m == nil || len(m.m.NCat) == 0 {
		return "", 0, false
	}
	var total int
	for _, n := range m.m.NCat {
		total += n
	}
	if total == 0 {
		return "", 0, false
	}
	logPrior := math.Log(float64(total))
	scores := make(map[string]float64, len(m.m.NCat))
	best, bestS := "", math.Inf(-1)
	for cat, n := range m.m.NCat {
		s := math.Log(float64(n)) - logPrior
		for d := 0; d < fcDims; d++ {
			b := len(fcEdges[d]) + 1
			s += math.Log(float64(m.m.Count[cat][d][v[d]]+1) / float64(n+b))
		}
		scores[cat] = s
		if s > bestS {
			best, bestS = cat, s
		}
	}
	// softmax 归一 → 置信度(只保留量级差, 避 exp 溢出)
	var sum float64
	for _, s := range scores {
		sum += math.Exp(s - bestS)
	}
	if sum <= 0 || math.IsNaN(sum) {
		return best, 0, true
	}
	conf := 1 / sum
	if conf > 1 {
		conf = 1
	}
	return best, conf, true
}

// ── 在线状态: live 特征表 + 当前模型 ────────────────────────────────────

var (
	fcModelMu   sync.RWMutex
	fcLiveModel *fcModel

	fcLiveMu sync.RWMutex
	fcLive   map[string]fcVec // ctEntry.key() → 最新特征(供 /api/connections)

	fcLastTrain time.Time
)

func fcModelPath(hncDir string) string { return filepath.Join(hncDir, "data", "flow_cls.json") }

// fcSaveModel 原子落盘(tmp + rename)。
func fcSaveModel(hncDir string, m *fcModel) error {
	if m == nil {
		return nil
	}
	b, err := json.Marshal(m.m)
	if err != nil {
		return err
	}
	p := fcModelPath(hncDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p+".tmp", b, 0o644); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

// fcLoadModel 读 data/flow_cls.json(失败返回 nil; 调用方容忍缺文件)。
func fcLoadModel(hncDir string) *fcModel {
	b, err := os.ReadFile(fcModelPath(hncDir))
	if err != nil || len(b) == 0 || len(b) > 1<<20 {
		return nil
	}
	var j fcModelJSON
	if json.Unmarshal(b, &j) != nil || j.Version != fcJSONVersion {
		return nil
	}
	if len(j.NCat) == 0 {
		return nil
	}
	return &fcModel{m: j}
}

// flowClsTick 每轮 app_usage 采样后调用(与 flowShapeTick 同 goroutine, 串行):
//  1. 收割训练样本: fsSt 里已结束、cat 属 TierApp、特征足够(fl.n ≥ fcMinFeats)
//     的流 → 样本池(每条流只收一次, fcDone 标记);
//  2. 刷新 live 特征表(未结束的流), 供 /api/connections 影子预测;
//  3. 每 30 分钟(或首次)重训并落盘; 首次先尝试读已存的模型。
func flowClsTick(now time.Time, hncDir string) {
	// live 特征表全量重建(与 fsSt 同 goroutine 读, 无锁安全)
	fresh := make(map[string]fcVec, len(fsSt.flows))
	fcPoolMu.Lock()
	var added []fcSample
	for k, fl := range fsSt.flows {
		// v5.28 审查: 原来这里对 cat == "" 直接 continue —— 而 cat 为空正是「规则库
		// 认不出」的连接, 也就是分类器要预测的对象, 线上于是永远没有预测。
		// 没有类别只是不能当训练样本, 照样进实时特征表。
		f := fsFeaturesOf(fl.samples)
		if fl.ended {
			if fl.cat != "" && !fl.fcDone && f.n >= fcMinFeats {
				if cat, ok := bigCatOfCategory(fl.cat); ok {
					added = append(added, fcSample{
						vec: fcVecOf(f, fl), cat: cat,
						manual: fsTypeBigCat[fl.typ], ts: now.Unix(),
					})
				}
				fl.fcDone = true
			}
			continue
		}
		if f.n >= 1 {
			fresh[k] = fcVecOf(f, fl)
		}
	}
	fcPool = append(fcPool, added...)
	fcPoolMu.Unlock()

	fcLiveMu.Lock()
	fcLive = fresh
	fcLiveMu.Unlock()

	fcModelMu.RLock()
	haveModel := fcLiveModel != nil
	fcModelMu.RUnlock()
	if !haveModel {
		if m := fcLoadModel(hncDir); m != nil {
			fcModelMu.Lock()
			fcLiveModel = m
			fcModelMu.Unlock()
		}
	}
	if !haveModel || now.Sub(fcLastTrain) >= fcRetrainEvery {
		fcPoolMu.Lock()
		snap := append([]fcSample(nil), fcPool...)
		fcPoolMu.Unlock()
		if m := fcTrain(snap, now.Unix()); m != nil {
			fcModelMu.Lock()
			fcLiveModel = m
			fcModelMu.Unlock()
			_ = fcSaveModel(hncDir, m) // 失败只影响持久化, 不影响本次
		}
		fcLastTrain = now
	}
}

// flowClsPredict /api/connections 用(影子): 未认出应用的行 → (大类, 置信)。
func flowClsPredict(key string) (string, float64, bool) {
	fcLiveMu.RLock()
	v, ok := fcLive[key]
	fcLiveMu.RUnlock()
	if !ok {
		return "", 0, false
	}
	fcModelMu.RLock()
	m := fcLiveModel
	fcModelMu.RUnlock()
	return fcPredict(m, v)
}

// ── 评估(dpi_eval flow_cls 段) ─────────────────────────────────────────

// fcEvalSplit 按本地时区的「今天 0 点」切分样本池: 今天之前的做训练, 今天
// 已认出的做考题。纯函数(测试直接喂)。
func fcEvalSplit(samples []fcSample, now time.Time) (train, test []fcSample) {
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
	for _, s := range samples {
		if s.ts < midnight {
			train = append(train, s)
		} else {
			test = append(test, s)
		}
	}
	return train, test
}

// evalFlowCls 识别自评的 flow_cls 段: 今天之前的模型在今天已认出的连接上
// 预测类别, 与 flow_shape 手工判类并排对比。样本不足时只有说明。
func evalFlowCls(now time.Time) *dpiEvalFlowCls {
	fcPoolMu.Lock()
	snap := append([]fcSample(nil), fcPool...)
	fcPoolMu.Unlock()
	out := &dpiEvalFlowCls{}
	train, test := fcEvalSplit(snap, now)
	out.TrainSamples = len(train)
	out.Samples = len(test)
	if len(train) < fcEvalMinPerClass*2 || len(test) < fcEvalMinPerClass {
		out.Note = "流量形状分类的样本还不足(每类至少 " + strconv.Itoa(fcEvalMinPerClass) + " 条训练与考题), 先正常用一会儿。"
		return out
	}
	m := fcTrain(train, now.Unix())
	var right, manualRight, manualN int
	perClass := map[string]int{}
	for _, s := range test {
		if cat, _, ok := fcPredict(m, s.vec); ok && cat == s.cat {
			right++
		}
		perClass[s.cat]++
		if s.manual != "" {
			manualN++
			if s.manual == s.cat {
				manualRight++
			}
		}
	}
	out.ModelAcc = float64(right) / float64(len(test))
	if manualN > 0 {
		out.ManualAcc = float64(manualRight) / float64(manualN)
		out.ManualSamples = manualN
	}
	out.Classes = len(perClass)
	out.Note = "影子运行: 模型只用今天之前的样本训练, 考今天已认出的连接; 手工规则列是 flow_shape.go 的判类映射到大类后的对照。"
	return out
}

const fcEvalMinPerClass = 50 // 每类训练/考题门槛(不足只给说明)
