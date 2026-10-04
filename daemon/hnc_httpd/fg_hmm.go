// fg_hmm.go — v5.27 T4 前台 HMM(影子运行, 可切换)
//
// 为什么: fg_model.go 的「打分 + 滞回」来回跳与切换慢都靠手调阈值。这里用 HMM 的在线前向
// 滤波: 人不会每 10 秒换一次 App(转移概率很小), 一次偶然的流量尖峰压不过「一直在用的那个」;
// 而启动事件(startup_fp.go)这种强证据能让它当轮切换。
//
// 边界(工作文档 §2): 默认只在后台算、只出对比统计(fg_engine = classic)。用户在设置里把
// 引擎切到「新(实验)」后, /api/devices[].fg 的前台应用和前台时间线改由 HMM 决定;
// 后台列表仍用经典模型的。连接归属、限速、限时一律不变(前台只用于显示与时间线)。
// 挂在 fg_model.go 每轮上, 不新开循环。
//
// ── 模型(每台设备)───────────────────────────────────────────────────────
//
//	状态 = 该设备当前跟踪的、可当前台的应用(fgCandidate)+ _none(没有前台), 最多 12 个,
//	超了丢后验最低的; 新出现的应用初始 log 先验 = log(0.02)。
//	每轮(在 stepDevLocked 算完各应用本轮分 inst 之后):
//	  转移: p_stay = exp(−dt/τ); 各状态把 1−p_stay 的质量平均分给其他状态
//	  观测: log L(a) = κ·inst_a/100; log L(_none) = κ·θ/100; 本轮有启动事件的应用再 +η
//	  后验在 log 空间归一化(log-sum-exp)
//	  决定: 后验最大者 ≥ 0.55 → 它; 否则当前前台后验 ≥ 0.25 → 保持; 否则 _none
//	置信度 = round(100 × 后验), 再按 fg_model 的来源封顶(_org ≤ 60、隧道 / 系统类 ≤ 50、
//	共现为主 ≤ 70)。两轮间隔 > 90 秒 → 与经典模型一起重置(fgModel.step 的 resetLocked)。
//
// ── 引擎开关 ─────────────────────────────────────────────────────────────
//
//	data/dpi_experiment.json {"fg_engine":"classic"|"hmm"}, 按 mtime 缓存读取, 缺失 = classic。
//	action dpi_fg_engine {engine}。
//
// ── 对比统计(无论选哪个引擎都记)──────────────────────────────────────────
//
//	每台有流量的设备每轮: 两套引擎各自「是否切换」「本轮前台」, 累计到小时桶
//	{rounds, agree_rounds, sec, classic:{switches, short_segments}, hmm:{…}}
//	(short_segment = 持续 < 30 秒就结束的前台段)。run/fg_compare.json, 保留 7 天,
//	随 fg 每分钟落盘一次。GET /api/fg_compare?days=1|7。
package main

import (
	"encoding/json"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	hmmTau        = 180.0 // 秒: 前台平均停留时间尺度; p_stay = exp(−dt/τ), 10 秒一轮 ≈ 0.946
	hmmKappa      = 4.0   // 观测强度: 本轮分 100 → 似然 ×e^4
	hmmTheta      = 20.0  // _none 的等效分数: 所有应用都低于它时「没有前台」占优
	hmmEta        = 2.5   // 启动事件的额外对数似然(≈ ×12)
	hmmInitPrior  = 0.02  // 新出现的应用的初始先验
	hmmMaxStates  = 12    // 含 _none
	hmmPick       = 0.55  // 后验最大者 ≥ 它才切过去
	hmmHold       = 0.25  // 当前前台后验 ≥ 它就保持
	hmmNone       = "_none"
	hmmShortSegS  = 30 // 短于 30 秒就结束的前台段算「短段」(来回跳)
	fgEngineHMM   = "hmm"
	fgEngineClass = "classic"
	fgCmpKeepDays = 7
)

// hmmDev 一台设备的 HMM 状态
type hmmDev struct {
	logp map[string]float64 // 状态 → log 后验(已归一化)
	cur  string             // 当前决定("" = 没有前台)
	post float64            // cur 的后验
}

func newHMMDev() *hmmDev {
	return &hmmDev{logp: map[string]float64{hmmNone: 0}}
}

func logSumExp(m map[string]float64) float64 {
	mx := math.Inf(-1)
	for _, v := range m {
		if v > mx {
			mx = v
		}
	}
	if math.IsInf(mx, -1) {
		return mx
	}
	s := 0.0
	for _, v := range m {
		s += math.Exp(v - mx)
	}
	return mx + math.Log(s)
}

func (h *hmmDev) normalize() {
	z := logSumExp(h.logp)
	for k, v := range h.logp {
		h.logp[k] = v - z
	}
}

func (h *hmmDev) postOf(id string) float64 {
	if v, ok := h.logp[id]; ok {
		return math.Exp(v)
	}
	return 0
}

// hmmStep 一轮前向滤波 + 决定(纯函数式, 只改 h)。
// inst: 应用 → 本轮分(fgScore); started: 本轮有启动事件的应用。
func hmmStep(h *hmmDev, inst map[string]float64, started map[string]bool, dt float64) {
	// 状态集合: 跟随 d.apps(消失的应用移除, 新应用以 log(0.02) 先验加入)
	for id := range h.logp {
		if id == hmmNone {
			continue
		}
		if _, ok := inst[id]; !ok {
			delete(h.logp, id)
		}
	}
	ids := make([]string, 0, len(inst))
	for id := range inst {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, ok := h.logp[id]; !ok {
			h.logp[id] = math.Log(hmmInitPrior)
		}
	}
	h.normalize()
	// 超过上限: 丢后验最低的(_none 与当前前台不丢)
	for len(h.logp) > hmmMaxStates {
		low, lv := "", math.Inf(1)
		for id, v := range h.logp {
			if id == hmmNone || id == h.cur {
				continue
			}
			if v < lv || (v == lv && id > low) {
				low, lv = id, v
			}
		}
		if low == "" {
			break
		}
		delete(h.logp, low)
	}
	h.normalize()

	// 转移
	n := len(h.logp)
	if n > 1 {
		stay := math.Exp(-dt / hmmTau)
		for id, v := range h.logp {
			p := math.Exp(v)
			np := stay*p + (1-stay)*(1-p)/float64(n-1)
			h.logp[id] = math.Log(math.Max(np, 1e-300))
		}
	}
	// 观测
	for id := range h.logp {
		if id == hmmNone {
			h.logp[id] += hmmKappa * hmmTheta / 100
			continue
		}
		h.logp[id] += hmmKappa * inst[id] / 100
		if started[id] {
			h.logp[id] += hmmEta
		}
	}
	h.normalize()

	// 决定
	best, bv := "", math.Inf(-1)
	keys := make([]string, 0, len(h.logp))
	for id := range h.logp {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		if v := h.logp[id]; v > bv {
			best, bv = id, v
		}
	}
	switch {
	case math.Exp(bv) >= hmmPick:
		if best == hmmNone {
			h.cur = ""
		} else {
			h.cur = best
		}
	case h.cur != "" && h.postOf(h.cur) >= hmmHold:
		// 保持
	default:
		h.cur = ""
	}
	if h.cur != "" {
		h.post = h.postOf(h.cur)
	} else {
		h.post = h.postOf(hmmNone)
	}
}

// hmmConfidence round(100×后验), 再按 fg_model 的来源封顶
func hmmConfidence(a *fgApp, post float64) int {
	c := math.Min(100*post, fgConfCap(a))
	return int(math.Round(math.Max(c, 0)))
}

// ─── 引擎开关 ─────────────────────────────────────────────────────────

func fgExperimentPath(hncDir string) string {
	return filepath.Join(hncDir, "data", "dpi_experiment.json")
}

var fgEngineCache struct {
	mu     sync.Mutex
	path   string
	key    string
	engine string
}

// fgEngineFor 读当前前台引擎(按 mtime 缓存); 目录为空 / 文件缺失 / 内容不认 = classic。
func fgEngineFor(hncDir string) string {
	if hncDir == "" {
		return fgEngineClass
	}
	p := fgExperimentPath(hncDir)
	key := "-"
	if fi, err := os.Stat(p); err == nil {
		key = strconv.FormatInt(fi.ModTime().UnixNano(), 10) + ":" + strconv.FormatInt(fi.Size(), 10)
	}
	fgEngineCache.mu.Lock()
	defer fgEngineCache.mu.Unlock()
	if fgEngineCache.path == p && fgEngineCache.key == key {
		return fgEngineCache.engine
	}
	eng := fgEngineClass
	if b, err := os.ReadFile(p); err == nil && len(b) <= 64<<10 {
		var f struct {
			FgEngine string `json:"fg_engine"`
		}
		if json.Unmarshal(b, &f) == nil && f.FgEngine == fgEngineHMM {
			eng = fgEngineHMM
		}
	}
	fgEngineCache.path, fgEngineCache.key, fgEngineCache.engine = p, key, eng
	return eng
}

// actionDPIFgEngine 切换前台识别引擎(原子写, 保留文件里的其它键)。
func actionDPIFgEngine(hncDir string, p map[string]string) actionResp {
	eng := strings.TrimSpace(p["engine"])
	if eng != fgEngineClass && eng != fgEngineHMM {
		return actionResp{OK: false, Error: "invalid engine", Detail: "engine must be classic or hmm"}
	}
	path := fgExperimentPath(hncDir)
	m := map[string]interface{}{}
	if b, err := os.ReadFile(path); err == nil && len(b) <= 64<<10 {
		_ = json.Unmarshal(b, &m)
	}
	m["fg_engine"] = eng
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return actionResp{OK: false, Error: "mkdir failed", Detail: err.Error()}
	}
	if err := writeFileAtomic(path, b); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	fgSt.mu.Lock()
	sameDir := fgSt.dir == hncDir
	fgSt.mu.Unlock()
	if sameDir {
		fgSt.setEngine(eng)
	}
	return actionResp{OK: true, Detail: "fg_engine=" + eng}
}

// ─── 对比统计 ─────────────────────────────────────────────────────────

type fgCmpEngine struct {
	Switches      int `json:"switches"`
	ShortSegments int `json:"short_segments"`
}

type fgCmpBucket struct {
	Hour    int64       `json:"hour"` // 小时起点(unix)
	Rounds  int         `json:"rounds"`
	Agree   int         `json:"agree_rounds"`
	Sec     float64     `json:"sec"` // 设备 × 秒(观测时长, 算「每小时」用)
	Classic fgCmpEngine `json:"classic"`
	HMM     fgCmpEngine `json:"hmm"`
}

type fgCmpFile struct {
	Schema  int            `json:"schema"`
	Buckets []*fgCmpBucket `json:"buckets"`
}

// fgCmpDev 每台设备两套引擎各自当前段的开始时间
type fgCmpDev struct {
	classicCur, hmmCur     string
	classicSince, hmmSince time.Time
}

type fgCompare struct {
	buckets map[int64]*fgCmpBucket
	devs    map[string]*fgCmpDev
	dirty   bool
	loaded  bool
}

func newFgCompare() *fgCompare {
	return &fgCompare{buckets: map[int64]*fgCmpBucket{}, devs: map[string]*fgCmpDev{}}
}

func fgCmpPath(hncDir string) string { return filepath.Join(hncDir, "run", "fg_compare.json") }

func (c *fgCompare) bucket(now time.Time) *fgCmpBucket {
	h := now.Unix() / 3600 * 3600
	b := c.buckets[h]
	if b == nil {
		b = &fgCmpBucket{Hour: h}
		c.buckets[h] = b
		cut := h - fgCmpKeepDays*24*3600
		for k := range c.buckets {
			if k < cut {
				delete(c.buckets, k)
			}
		}
	}
	return b
}

// record 一台有流量的设备一轮: 两套引擎本轮的前台("" = 没有)
func (c *fgCompare) record(mac string, now time.Time, dt float64, classic, hmm string) {
	d := c.devs[mac]
	if d == nil {
		// 第一次看到这台设备: 当前段从什么时候开始不知道(since 为零值), 结束时不算短段
		d = &fgCmpDev{classicCur: classic, hmmCur: hmm}
		c.devs[mac] = d
	}
	b := c.bucket(now)
	b.Rounds++
	b.Sec += dt
	if classic == hmm {
		b.Agree++
	}
	step := func(cur *string, since *time.Time, next string, e *fgCmpEngine) {
		if *cur == next {
			return
		}
		e.Switches++
		if *cur != "" && !since.IsZero() && now.Sub(*since) < hmmShortSegS*time.Second {
			e.ShortSegments++
		}
		*cur, *since = next, now
	}
	step(&d.classicCur, &d.classicSince, classic, &b.Classic)
	step(&d.hmmCur, &d.hmmSince, hmm, &b.HMM)
	c.dirty = true
}

// forget 设备被清掉 / 模型重置时去掉段起点(下一轮重新开始计)
func (c *fgCompare) reset() { c.devs = map[string]*fgCmpDev{} }

func (c *fgCompare) load(hncDir string) {
	if c.loaded {
		return
	}
	c.loaded = true
	b, err := os.ReadFile(fgCmpPath(hncDir))
	if err != nil || len(b) > 1<<20 {
		return
	}
	var f fgCmpFile
	if json.Unmarshal(b, &f) != nil {
		return
	}
	for _, x := range f.Buckets {
		if x != nil && x.Hour > 0 {
			if cur := c.buckets[x.Hour]; cur != nil {
				// 内存里已经记了的(load 之前)叠加上去
				x.Rounds += cur.Rounds
				x.Agree += cur.Agree
				x.Sec += cur.Sec
				x.Classic.Switches += cur.Classic.Switches
				x.Classic.ShortSegments += cur.Classic.ShortSegments
				x.HMM.Switches += cur.HMM.Switches
				x.HMM.ShortSegments += cur.HMM.ShortSegments
			}
			c.buckets[x.Hour] = x
		}
	}
}

func (c *fgCompare) snapshot(now time.Time) []byte {
	cut := now.Unix()/3600*3600 - fgCmpKeepDays*24*3600
	f := fgCmpFile{Schema: 1}
	for h, b := range c.buckets {
		if h >= cut {
			cp := *b
			f.Buckets = append(f.Buckets, &cp)
		}
	}
	sort.Slice(f.Buckets, func(i, j int) bool { return f.Buckets[i].Hour < f.Buckets[j].Hour })
	b, _ := json.Marshal(f)
	return b
}

// summary days 天内合计
func (c *fgCompare) summary(now time.Time, days int) map[string]interface{} {
	cut := now.Unix() - int64(days)*24*3600
	var tot fgCmpBucket
	for h, b := range c.buckets {
		if h+3600 <= cut {
			continue
		}
		tot.Rounds += b.Rounds
		tot.Agree += b.Agree
		tot.Sec += b.Sec
		tot.Classic.Switches += b.Classic.Switches
		tot.Classic.ShortSegments += b.Classic.ShortSegments
		tot.HMM.Switches += b.HMM.Switches
		tot.HMM.ShortSegments += b.HMM.ShortSegments
	}
	hours := tot.Sec / 3600
	perHour := func(n int) float64 {
		if hours <= 0 {
			return 0
		}
		return round2(float64(n) / hours)
	}
	eng := func(e fgCmpEngine) map[string]interface{} {
		return map[string]interface{}{
			"switches": e.Switches, "short_segments": e.ShortSegments,
			"switches_per_hour": perHour(e.Switches), "short_per_hour": perHour(e.ShortSegments),
		}
	}
	agree := 0.0
	if tot.Rounds > 0 {
		agree = math.Round(float64(tot.Agree)/float64(tot.Rounds)*1000) / 10
	}
	return map[string]interface{}{
		"rounds": tot.Rounds, "agree_rounds": tot.Agree, "agree_pct": agree,
		"device_hours": round2(hours), "classic": eng(tot.Classic), "hmm": eng(tot.HMM),
	}
}

// ─── API ──────────────────────────────────────────────────────────────

// apiFgCompare GET /api/fg_compare?days=1|7
func (s *server) apiFgCompare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	days := 1
	if d := r.URL.Query().Get("days"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || (n != 1 && n != 7) {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "days must be 1 or 7"})
			return
		}
		days = n
	}
	out := fgSt.compareSummary(s.hncDir, time.Now(), days)
	out["ok"] = true
	out["days"] = days
	out["engine"] = fgEngineFor(s.hncDir)
	writeJSON(w, http.StatusOK, out)
}

func (m *fgModel) compareSummary(hncDir string, now time.Time, days int) map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dir == "" && hncDir != "" {
		// 还没 load 过(进程刚起 / 单测): 只读盘上的
		c := newFgCompare()
		c.load(hncDir)
		return c.summary(now, days)
	}
	return m.cmp.summary(now, days)
}
