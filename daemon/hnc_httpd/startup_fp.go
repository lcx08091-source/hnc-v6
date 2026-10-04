// startup_fp.go — v5.27 T3 启动指纹(影子运行)
//
// 为什么: App 冷启动 / 切回前台的头几秒, 会按固定套路连一串域名(配置 → 统计 SDK →
// 自家 API → CDN)。单个域名可能是共享的(CDN、SDK), 「一组域名一起出现」就能认出是哪个
// App, 而且这个事件本身就是「切到前台」的秒级信号(fg_hmm.go 用)。
//
// 边界(工作文档 §2): 只产出「启动事件」供前台 HMM、识别自评和调试接口使用,
// 不改任何连接的应用归属 / 限速 / 限时 / 封锁。不新增采集内容, 只用现有的 SNI + 时间。
//
// ── 学习(本机样本)──────────────────────────────────────────────────────────
// 数据: run/label_samples.YYYYMMDD.jsonl(真值 = 包名, 经 data/pkg_app_map.json 映射到
// 应用 id; 映射不到的包不学)。同一个包和它上一条样本相隔 ≥ 600 秒(= 样本去重窗口)的
// 那条样本算「启动时刻」, 取 [启动时刻, +8 秒] 内该包的样本, 按首次出现顺序去重得 token
// 列表, ≥ 2 个 token 才算一次有效启动。
// token: SNI 小写去尾点, 每个 label 里的连续数字换成 #(v26-dy.ixigua.com → v#-dy.ixigua.com);
// 跳过 IP 字面量和 ECH 外层 public_name。
// 学习表 data/startup_fp.json: 每个应用 {starts, tokens:{token:次数}}, 14 天半衰期惰性衰减,
// 最多 512 个应用 × 64 个 token。增量读样本(游标 {date, offset} 存在同一文件), 每次最多
// 50000 行, 最多 30 分钟一次, 只在 run/self_capture.enabled 存在时做(挂在 app_usage 每轮)。
// token 频率 f = 次数 / starts; 特征 token = f ≥ 0.5 且只出现在 ≤ 2 个应用的特征候选里;
// 可用 = starts ≥ 3 且特征 token ≥ 2 个。
//
// ── 识别(热点客户端)──────────────────────────────────────────────────────────
// fpSt.tick 解析出新的 dpi_flows 记录后(锁外)交给 observe。每台设备(MAC 非空)保留最近
// 20 秒的 (ts, token); 每来一条记录看窗口 [ts−8s, ts]: 对每个可用应用 A, matched = 窗口里
// 出现的 A 的特征 token, recall = Σf(matched)/Σf(A 全部特征 token); 候选 = |matched| ≥ 2 且
// recall ≥ 0.5; 取最高者且领先第二名 ≥ 0.2 → 启动事件 {mac, app_id, name, ts, score, matched};
// 同一 (mac, app) 600 秒内只出一次。内存保留最近 200 个事件。
// 导入的启动指纹(data/startup_fp_imported.json, T6 规则包)在识别时并入, 同一应用本机学到的优先。
//
//	GET /api/dpi_startup → {learned:[{app_id,name,starts,tokens:[{t,f,feat}],usable}],
//	    events:[…], stats:{samples_read, starts_learned, apps_usable, events_total, last_learn, imported}}
package main

import (
	"bufio"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hnc.io/dpid/output"
)

const (
	startupGapSec       = 600 // 与上一条样本相隔 ≥ 600 秒 = 一次启动(= 样本去重窗口)
	startupWinSec       = 8   // 启动窗口 / 识别窗口
	startupMinTokens    = 2   // 一次有效启动至少 2 个 token
	startupHalfLifeSec  = 14 * 24 * 3600
	startupMaxApps      = 512
	startupMaxTokens    = 64
	startupLearnEvery   = 30 * time.Minute
	startupMaxLines     = 50000
	startupMaxLineBytes = 64 << 10
	startupFeatFreq     = 0.5 // 特征 token 频率下限
	startupFeatMaxApps  = 2   // 特征 token 最多被几个应用共用
	startupMinStarts    = 3.0
	startupMinFeat      = 2
	startupDevKeepSec   = 20  // 每台设备保留最近 20 秒的 token
	startupMinRecall    = 0.5 // 候选 recall 下限
	startupMinLead      = 0.2 // 领先第二名
	startupDedupSec     = 600 // 同一 (mac, app) 600 秒内只出一次
	startupMaxEvents    = 200
	startupMaxDevs      = 256
	startupMaxPkgs      = 2048
	startupMaxOpen      = 256
	startupFileMaxBytes = 4 << 20
	startupMinUID       = 10000
)

// ─── token ────────────────────────────────────────────────────────────

// startupToken SNI → token; 不可用(空 / IP 字面量 / ECH 外层)返回 ""。
func startupToken(sni string) string {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(sni)), ".")
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil || output.IsECHPublicName(h) {
		return ""
	}
	b := make([]byte, 0, len(h))
	inDigits := false
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c >= '0' && c <= '9' {
			if !inDigits {
				b = append(b, '#')
				inDigits = true
			}
			continue
		}
		inDigits = false
		b = append(b, c)
	}
	return string(b)
}

// ─── 学习表 ───────────────────────────────────────────────────────────

type startupApp struct {
	AppID  string             `json:"app_id"`
	Name   string             `json:"name,omitempty"`
	Starts float64            `json:"starts"`
	Tokens map[string]float64 `json:"tokens"`
	Last   int64              `json:"last"`
	Upd    int64              `json:"upd"` // 计数衰减到的时刻
}

func startupDecay(from, to int64) float64 {
	if to <= from {
		return 1
	}
	return math.Pow(0.5, float64(to-from)/startupHalfLifeSec)
}

func (a *startupApp) decayTo(now int64) {
	f := startupDecay(a.Upd, now)
	if now > a.Upd {
		a.Upd = now
	}
	if f >= 1 {
		return
	}
	a.Starts *= f
	for t, n := range a.Tokens {
		n *= f
		if n < 0.01 {
			delete(a.Tokens, t)
			continue
		}
		a.Tokens[t] = n
	}
}

// startupCursor 样本文件读到哪了(本地日期 + 字节偏移)
type startupCursor struct {
	Date   string `json:"date"`
	Offset int64  `json:"offset"`
}

// startupOpen 一次还没收尾的启动(窗口内的样本可能在下一轮才读到)
type startupOpen struct {
	App    string   `json:"app"`
	Start  int64    `json:"start"`
	Tokens []string `json:"tokens"`
}

type startupStats struct {
	SamplesRead   uint64 `json:"samples_read"`
	StartsLearned uint64 `json:"starts_learned"`
	EventsTotal   uint64 `json:"events_total"`
	LastLearn     int64  `json:"last_learn"`
}

type startupFile struct {
	Schema  int                     `json:"schema"`
	SavedAt int64                   `json:"saved_at"`
	Cursor  startupCursor           `json:"cursor"`
	LastPkg map[string]int64        `json:"last_pkg,omitempty"` // 包 → 上一条样本时间(切分启动用)
	Open    map[string]*startupOpen `json:"open,omitempty"`     // 包 → 未收尾的启动
	Stats   startupStats            `json:"stats"`
	Apps    []*startupApp           `json:"apps"`
}

// startupTable 学习表(纯数据, 无锁; 调用方加锁)
type startupTable struct {
	apps map[string]*startupApp
}

func newStartupTable() *startupTable { return &startupTable{apps: map[string]*startupApp{}} }

// addStart 记一次启动。decay=false 时不衰减(交叉验证用的临时表)。
func (t *startupTable) addStart(app, name string, tokens []string, ts int64, decay bool) {
	a := t.apps[app]
	if a == nil {
		if len(t.apps) >= startupMaxApps {
			t.evictOne()
		}
		a = &startupApp{AppID: app, Tokens: map[string]float64{}, Upd: ts}
		t.apps[app] = a
	}
	if decay {
		a.decayTo(ts)
	}
	if name != "" {
		a.Name = name
	}
	a.Starts++
	for _, tok := range tokens {
		a.Tokens[tok]++
	}
	if len(a.Tokens) > startupMaxTokens {
		type kv struct {
			t string
			n float64
		}
		l := make([]kv, 0, len(a.Tokens))
		for k, n := range a.Tokens {
			l = append(l, kv{k, n})
		}
		sort.Slice(l, func(i, j int) bool {
			if l[i].n != l[j].n {
				return l[i].n > l[j].n
			}
			return l[i].t < l[j].t
		})
		for _, x := range l[startupMaxTokens:] {
			delete(a.Tokens, x.t)
		}
	}
	if ts > a.Last {
		a.Last = ts
	}
}

func (t *startupTable) evictOne() {
	old, ot := "", int64(math.MaxInt64)
	for id, a := range t.apps {
		if a.Last < ot || (a.Last == ot && id < old) {
			old, ot = id, a.Last
		}
	}
	delete(t.apps, old)
}

// ─── 启动切分(学习 / 交叉验证共用)────────────────────────────────────

type startupSample struct {
	Ts  int64  `json:"ts"`
	Pkg string `json:"pkg"`
	UID int    `json:"uid"`
	SNI string `json:"sni"`
}

// startupSegmenter 把按时间排好的样本切成启动; 状态可跨多次增量读取保留。
type startupSegmenter struct {
	lastPkg map[string]int64
	open    map[string]*startupOpen
}

func newStartupSegmenter() *startupSegmenter {
	return &startupSegmenter{lastPkg: map[string]int64{}, open: map[string]*startupOpen{}}
}

// feed 一条样本; 返回因这条样本而收尾的启动(可能为 nil)。
func (sg *startupSegmenter) feed(s startupSample, app string) *startupOpen {
	var done *startupOpen
	if o := sg.open[s.Pkg]; o != nil && s.Ts > o.Start+startupWinSec {
		done = o
		delete(sg.open, s.Pkg)
	}
	tok := startupToken(s.SNI)
	if o := sg.open[s.Pkg]; o != nil {
		if tok != "" && !containsStr(o.Tokens, tok) && len(o.Tokens) < startupMaxTokens {
			o.Tokens = append(o.Tokens, tok)
		}
	} else if last, ok := sg.lastPkg[s.Pkg]; !ok || s.Ts-last >= startupGapSec {
		if len(sg.open) < startupMaxOpen {
			o := &startupOpen{App: app, Start: s.Ts}
			if tok != "" {
				o.Tokens = []string{tok}
			}
			sg.open[s.Pkg] = o
		}
	}
	if s.Ts > sg.lastPkg[s.Pkg] {
		sg.lastPkg[s.Pkg] = s.Ts
	}
	if len(sg.lastPkg) > startupMaxPkgs {
		old, ot := "", int64(math.MaxInt64)
		for p, ts := range sg.lastPkg {
			if ts < ot || (ts == ot && p < old) {
				old, ot = p, ts
			}
		}
		delete(sg.lastPkg, old)
	}
	if done != nil && len(done.Tokens) < startupMinTokens {
		return nil
	}
	return done
}

// flush 收尾窗口已过(Start+8 < upTo)的启动; upTo < 0 = 全部收尾。
func (sg *startupSegmenter) flush(upTo int64) []*startupOpen {
	var out []*startupOpen
	pkgs := make([]string, 0, len(sg.open))
	for p := range sg.open {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	for _, p := range pkgs {
		o := sg.open[p]
		if upTo >= 0 && o.Start+startupWinSec >= upTo {
			continue
		}
		delete(sg.open, p)
		if len(o.Tokens) >= startupMinTokens {
			out = append(out, o)
		}
	}
	return out
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// startupTrain 交叉验证用: 用一组样本(按时间排好)训练一张不衰减的临时表。
func startupTrain(samples []startupSample, pmap, names map[string]string) *startupTable {
	t := newStartupTable()
	sg := newStartupSegmenter()
	add := func(o *startupOpen) {
		if o != nil {
			t.addStart(o.App, names[o.App], o.Tokens, o.Start, false)
		}
	}
	for _, s := range samples {
		app := pmap[s.Pkg]
		if app == "" || s.UID < startupMinUID {
			continue
		}
		add(sg.feed(s, app))
	}
	for _, o := range sg.flush(-1) {
		add(o)
	}
	return t
}

// ─── 识别模型 ─────────────────────────────────────────────────────────

type startupModelApp struct {
	id, name string
	starts   float64
	feat     map[string]float64 // 特征 token → 频率
	sumF     float64
}

type startupModel struct {
	apps  []*startupModelApp
	byTok map[string][]int
}

// startupFeatures 从学习表算每个应用的特征 token(纯函数)。
// imported: 导入的启动指纹(应用 id → token 频率), 同一应用本机学到的优先。
func buildStartupModel(t *startupTable, imported map[string]startupImported, now int64, decay bool) *startupModel {
	type cand struct {
		id, name string
		starts   float64
		freq     map[string]float64
	}
	var cands []cand
	ids := make([]string, 0, len(t.apps))
	for id := range t.apps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		a := t.apps[id]
		f := 1.0
		if decay {
			f = startupDecay(a.Upd, now)
		}
		starts := a.Starts * f
		if starts <= 0 {
			continue
		}
		fr := map[string]float64{}
		for tok, n := range a.Tokens {
			if v := n * f / starts; v >= startupFeatFreq {
				fr[tok] = math.Min(v, 1)
			}
		}
		cands = append(cands, cand{id, a.Name, starts, fr})
	}
	impIDs := make([]string, 0, len(imported))
	for id := range imported {
		if _, mine := t.apps[id]; !mine {
			impIDs = append(impIDs, id)
		}
	}
	sort.Strings(impIDs)
	for _, id := range impIDs {
		im := imported[id]
		fr := map[string]float64{}
		for tok, v := range im.Tokens {
			if v >= startupFeatFreq {
				fr[tok] = math.Min(v, 1)
			}
		}
		cands = append(cands, cand{id, im.Name, im.Starts, fr})
	}
	shared := map[string]int{}
	for _, c := range cands {
		for tok := range c.freq {
			shared[tok]++
		}
	}
	m := &startupModel{byTok: map[string][]int{}}
	for _, c := range cands {
		ma := &startupModelApp{id: c.id, name: c.name, starts: c.starts, feat: map[string]float64{}}
		for tok, v := range c.freq {
			if shared[tok] <= startupFeatMaxApps {
				ma.feat[tok] = v
				ma.sumF += v
			}
		}
		if ma.starts < startupMinStarts || len(ma.feat) < startupMinFeat {
			continue
		}
		idx := len(m.apps)
		m.apps = append(m.apps, ma)
		for tok := range ma.feat {
			m.byTok[tok] = append(m.byTok[tok], idx)
		}
	}
	return m
}

// startupFeatSet 学习表里每个应用的特征 token 集(给接口显示「feat」与 usable)
func startupFeatSet(m *startupModel) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, a := range m.apps {
		s := map[string]bool{}
		for tok := range a.feat {
			s[tok] = true
		}
		out[a.id] = s
	}
	return out
}

// ─── 识别器 ───────────────────────────────────────────────────────────

type startupEvent struct {
	MAC     string   `json:"mac"`
	AppID   string   `json:"app_id"`
	Name    string   `json:"name"`
	Ts      int64    `json:"ts"`
	Score   int      `json:"score"`
	Matched []string `json:"matched"`
}

type startupTok struct {
	ts  int64
	tok string
}

type startupRecognizer struct {
	devs    map[string][]startupTok
	lastEvt map[string]int64 // mac|app → 上次事件时间
}

func newStartupRecognizer() *startupRecognizer {
	return &startupRecognizer{devs: map[string][]startupTok{}, lastEvt: map[string]int64{}}
}

// feed 一条 (设备, 时间, token); 满足条件时返回启动事件。
func (r *startupRecognizer) feed(m *startupModel, mac string, ts int64, tok string) *startupEvent {
	if mac == "" || tok == "" || m == nil {
		return nil
	}
	w, ok := r.devs[mac]
	if !ok && len(r.devs) >= startupMaxDevs {
		// 设备太多: 丢掉最久没动的
		old, ot := "", int64(math.MaxInt64)
		for k, l := range r.devs {
			if n := len(l); n > 0 && l[n-1].ts < ot {
				old, ot = k, l[n-1].ts
			}
		}
		delete(r.devs, old)
	}
	w = append(w, startupTok{ts, tok})
	i := 0
	for i < len(w) && w[i].ts < ts-startupDevKeepSec {
		i++
	}
	w = w[i:]
	if len(w) > 256 {
		w = w[len(w)-256:]
	}
	r.devs[mac] = w
	if len(m.byTok[tok]) == 0 {
		return nil // 这条 token 不是任何应用的特征, 窗口结果不会变
	}
	// 窗口 [ts−8, ts] 里出现的特征 token
	present := map[string]bool{}
	for _, x := range w {
		if x.ts >= ts-startupWinSec && x.ts <= ts {
			present[x.tok] = true
		}
	}
	matched := map[int][]string{}
	for t := range present {
		for _, ai := range m.byTok[t] {
			matched[ai] = append(matched[ai], t)
		}
	}
	best, bestR, secondR := -1, 0.0, 0.0
	idxs := make([]int, 0, len(matched))
	for ai := range matched {
		idxs = append(idxs, ai)
	}
	sort.Ints(idxs)
	for _, ai := range idxs {
		a := m.apps[ai]
		s := 0.0
		for _, t := range matched[ai] {
			s += a.feat[t]
		}
		rec := 0.0
		if a.sumF > 0 {
			rec = s / a.sumF
		}
		ok := len(matched[ai]) >= 2 && rec >= startupMinRecall
		switch {
		case ok && rec > bestR:
			if best >= 0 {
				secondR = math.Max(secondR, bestR)
			}
			best, bestR = ai, rec
		default:
			secondR = math.Max(secondR, rec)
		}
	}
	if best < 0 || bestR-secondR < startupMinLead {
		return nil
	}
	a := m.apps[best]
	k := mac + "|" + a.id
	if last, ok := r.lastEvt[k]; ok && ts-last < startupDedupSec && ts >= last {
		return nil
	}
	r.lastEvt[k] = ts
	if len(r.lastEvt) > 4096 {
		for kk, t := range r.lastEvt {
			if ts-t >= startupDedupSec {
				delete(r.lastEvt, kk)
			}
		}
	}
	mt := append([]string(nil), matched[best]...)
	sort.Strings(mt)
	name := a.name
	if name == "" {
		name = a.id
	}
	return &startupEvent{MAC: mac, AppID: a.id, Name: name, Ts: ts, Score: int(math.Round(100 * math.Min(bestR, 1))), Matched: mt}
}

// ─── 状态(每个 hncDir 一份)───────────────────────────────────────────

// startupPackEntry 启动指纹的交换格式(规则包 startup 段 / data/startup_fp_imported.json)。
// 只有应用与特征 token 频率, 不含包名、设备、时间。
type startupPackEntry struct {
	AppID    string           `json:"app_id"`
	App      string           `json:"app"`
	Category string           `json:"category,omitempty"`
	Starts   int              `json:"starts"`
	Tokens   []startupPackTok `json:"tokens"`
}

type startupPackTok struct {
	T string  `json:"t"`
	F float64 `json:"f"`
}

type startupImported struct {
	Name   string
	Starts float64
	Tokens map[string]float64
}

type startupStore struct {
	mu        sync.Mutex
	hncDir    string
	loaded    bool
	table     *startupTable
	seg       *startupSegmenter
	cursor    startupCursor
	stats     startupStats
	model     *startupModel
	modelAt   int64
	impKey    string
	imported  map[string]startupImported
	rec       *startupRecognizer
	events    []startupEvent
	lastLearn time.Time
	learning  bool
}

var startupStores struct {
	mu sync.Mutex
	m  map[string]*startupStore
}

func startupFor(hncDir string) *startupStore {
	startupStores.mu.Lock()
	defer startupStores.mu.Unlock()
	if startupStores.m == nil {
		startupStores.m = map[string]*startupStore{}
	}
	st := startupStores.m[hncDir]
	if st == nil {
		st = &startupStore{hncDir: hncDir, table: newStartupTable(), seg: newStartupSegmenter(), rec: newStartupRecognizer()}
		startupStores.m[hncDir] = st
	}
	return st
}

func startupPath(hncDir string) string { return filepath.Join(hncDir, "data", "startup_fp.json") }
func startupImportedPath(hncDir string) string {
	return filepath.Join(hncDir, "data", "startup_fp_imported.json")
}

func (st *startupStore) loadLocked() {
	if st.loaded {
		return
	}
	st.loaded = true
	b, err := os.ReadFile(startupPath(st.hncDir))
	if err != nil || len(b) > startupFileMaxBytes {
		return
	}
	var f startupFile
	if json.Unmarshal(b, &f) != nil {
		return
	}
	for _, a := range f.Apps {
		if a == nil || a.AppID == "" || a.Tokens == nil {
			continue
		}
		st.table.apps[a.AppID] = a
	}
	for len(st.table.apps) > startupMaxApps {
		st.table.evictOne()
	}
	st.cursor, st.stats = f.Cursor, f.Stats
	if f.LastPkg != nil {
		st.seg.lastPkg = f.LastPkg
	}
	for p, o := range f.Open {
		if o != nil && o.App != "" && len(st.seg.open) < startupMaxOpen {
			st.seg.open[p] = o
		}
	}
	st.model = nil
}

func (st *startupStore) fileLocked(now time.Time) startupFile {
	f := startupFile{Schema: 1, SavedAt: now.Unix(), Cursor: st.cursor, LastPkg: st.seg.lastPkg, Open: st.seg.open, Stats: st.stats}
	ids := make([]string, 0, len(st.table.apps))
	for id := range st.table.apps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		f.Apps = append(f.Apps, st.table.apps[id])
	}
	return f
}

// importedLocked 读导入的启动指纹(按 mtime 缓存)。
func (st *startupStore) importedLocked() map[string]startupImported {
	p := startupImportedPath(st.hncDir)
	key := "-"
	if fi, err := os.Stat(p); err == nil {
		key = strconv.FormatInt(fi.ModTime().UnixNano(), 10) + ":" + strconv.FormatInt(fi.Size(), 10)
	}
	if key == st.impKey {
		return st.imported
	}
	st.impKey, st.imported, st.model = key, nil, nil
	b, err := os.ReadFile(p)
	if err != nil || len(b) > startupFileMaxBytes {
		return nil
	}
	var f struct {
		Startup []startupPackEntry `json:"startup"`
	}
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	st.imported = map[string]startupImported{}
	for _, s := range f.Startup {
		if s.AppID == "" {
			continue
		}
		im := startupImported{Name: s.App, Starts: float64(s.Starts), Tokens: map[string]float64{}}
		for _, t := range s.Tokens {
			im.Tokens[t.T] = t.F
		}
		st.imported[s.AppID] = im
	}
	return st.imported
}

// modelLocked 识别模型(学习表变了 / 导入变了 / 每 10 分钟重算一次衰减)
func (st *startupStore) modelLocked(now int64) *startupModel {
	imp := st.importedLocked()
	if st.model == nil || now-st.modelAt >= 600 || now < st.modelAt {
		st.model = buildStartupModel(st.table, imp, now, true)
		st.modelAt = now
	}
	return st.model
}

// ─── 增量学习 ─────────────────────────────────────────────────────────

func startupSampleFiles(runDir string) map[string]string {
	ents, err := os.ReadDir(runDir)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, "label_samples.") || !strings.HasSuffix(n, ".jsonl") {
			continue
		}
		d := strings.TrimSuffix(strings.TrimPrefix(n, "label_samples."), ".jsonl")
		if len(d) == 8 {
			out[d] = filepath.Join(runDir, n)
		}
	}
	return out
}

// startupReadFrom 从 off 开始读完整的行(最后一行没写完不算), 最多 maxLines 行。
// 返回解析出的样本、读到的新偏移、读了几行。
func startupReadFrom(path string, off int64, maxLines int) ([]startupSample, int64, int) {
	f, err := os.Open(path)
	if err != nil {
		return nil, off, 0
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() < off {
		off = 0 // 文件被换过(删了重建): 从头读
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, off, 0
	}
	br := bufio.NewReaderSize(f, 32<<10)
	var out []startupSample
	n := 0
	for n < maxLines {
		line, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			// 超长行: 跳过到行尾
			skipped := int64(len(line))
			for err == bufio.ErrBufferFull {
				line, err = br.ReadSlice('\n')
				skipped += int64(len(line))
			}
			if err != nil {
				break // 没写完的超长行, 下次再看
			}
			off += skipped
			n++
			continue
		}
		if err != nil {
			break // EOF: 最后一行没有换行 = 没写完, 不消费
		}
		off += int64(len(line))
		n++
		if len(line) > startupMaxLineBytes {
			continue
		}
		var s startupSample
		if json.Unmarshal(line, &s) == nil && s.Pkg != "" && s.Ts > 0 {
			out = append(out, s)
		}
	}
	return out, off, n
}

// maybeLearn 挂在 app_usage 每轮: 最多 30 分钟一次, 只在本机抓包开着时做, I/O 不在锁内。
func (st *startupStore) maybeLearn(now time.Time) {
	st.mu.Lock()
	if st.learning || (!st.lastLearn.IsZero() && now.Sub(st.lastLearn) < startupLearnEvery && now.After(st.lastLearn)) {
		st.mu.Unlock()
		return
	}
	st.lastLearn = now
	st.mu.Unlock()
	if !selfFGEnabled(st.hncDir) {
		return
	}
	st.learnOnce(now)
}

// learnOnce 增量读一次样本并学习(测试直接调)。
func (st *startupStore) learnOnce(now time.Time) {
	st.mu.Lock()
	if st.learning {
		st.mu.Unlock()
		return
	}
	st.learning = true
	st.loadLocked()
	cur := st.cursor
	st.mu.Unlock()
	defer func() {
		st.mu.Lock()
		st.learning = false
		st.mu.Unlock()
	}()

	pmap := pkgAppMap(st.hncDir)
	names := ruleNameMap(st.hncDir)
	files := startupSampleFiles(filepath.Join(st.hncDir, "run"))
	dates := make([]string, 0, len(files))
	for d := range files {
		if d >= cur.Date {
			dates = append(dates, d)
		}
	}
	sort.Strings(dates)
	type batch struct {
		samples []startupSample
	}
	var batches []batch
	budget := startupMaxLines
	for i, d := range dates {
		if budget <= 0 {
			break
		}
		off := int64(0)
		if d == cur.Date {
			off = cur.Offset
		}
		ss, noff, n := startupReadFrom(files[d], off, budget)
		budget -= n
		batches = append(batches, batch{ss})
		cur = startupCursor{Date: d, Offset: noff}
		if budget > 0 && i < len(dates)-1 {
			// 这一天读完了(还有余量), 下一天从头读
			cur = startupCursor{Date: dates[i+1], Offset: 0}
		}
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	var maxTs int64
	read := uint64(0)
	learned := uint64(0)
	add := func(o *startupOpen) {
		if o == nil {
			return
		}
		st.table.addStart(o.App, names[o.App], o.Tokens, o.Start, true)
		learned++
	}
	for _, b := range batches {
		for _, s := range b.samples {
			read++
			if s.Ts > maxTs {
				maxTs = s.Ts
			}
			app := pmap[s.Pkg]
			if app == "" || s.UID < startupMinUID {
				continue
			}
			add(st.seg.feed(s, app))
		}
	}
	if maxTs > 0 {
		for _, o := range st.seg.flush(maxTs) {
			add(o)
		}
	}
	// 太久没收尾的(样本停了): 按现在时间收尾
	for _, o := range st.seg.flush(now.Unix() - startupGapSec) {
		add(o)
	}
	st.cursor = cur
	st.stats.SamplesRead += read
	st.stats.StartsLearned += learned
	st.stats.LastLearn = now.Unix()
	if learned > 0 {
		st.model = nil
	}
	if b, err := json.Marshal(st.fileLocked(now)); err == nil {
		_ = discoverWriteAtomic(startupPath(st.hncDir), b)
	}
}

// ─── 识别入口 ─────────────────────────────────────────────────────────

// observe fpSt.tick 解析出的新 dpi_flows 记录(调用方不持任何锁)。
func (st *startupStore) observe(recs []fpFlowRec, now time.Time) {
	if len(recs) == 0 {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.loadLocked()
	m := st.modelLocked(now.Unix())
	if len(m.apps) == 0 {
		return
	}
	sorted := append([]fpFlowRec(nil), recs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Ts != sorted[j].Ts {
			return sorted[i].Ts < sorted[j].Ts
		}
		return sorted[i].Seq < sorted[j].Seq
	})
	for i := range sorted {
		r := &sorted[i]
		mac := strings.ToLower(r.MAC)
		if mac == "" || r.ECHOuter || isSimMAC(mac) {
			continue
		}
		if ev := st.rec.feed(m, mac, r.Ts, startupToken(r.SNI)); ev != nil {
			st.events = append(st.events, *ev)
			if len(st.events) > startupMaxEvents {
				st.events = st.events[len(st.events)-startupMaxEvents:]
			}
			st.stats.EventsTotal++
		}
	}
}

// eventsSince 某设备 (after, upTo] 内的启动事件涉及的应用(前台 HMM 用)。
func (st *startupStore) eventsSince(mac string, after, upTo int64) map[string]bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out map[string]bool
	for i := len(st.events) - 1; i >= 0; i-- {
		e := st.events[i]
		if e.Ts <= after {
			break
		}
		if e.MAC == mac && e.Ts <= upTo {
			if out == nil {
				out = map[string]bool{}
			}
			out[e.AppID] = true
		}
	}
	return out
}

// startupEventsForHMM 全局入口: 只有 AppUsageLoop 设置过目录才有数据(单测里为空)。
var startupHMMDir struct {
	mu  sync.Mutex
	dir string
}

func setStartupHMMDir(dir string) {
	startupHMMDir.mu.Lock()
	startupHMMDir.dir = dir
	startupHMMDir.mu.Unlock()
}

func startupEventsForHMM(mac string, after, upTo int64) map[string]bool {
	startupHMMDir.mu.Lock()
	dir := startupHMMDir.dir
	startupHMMDir.mu.Unlock()
	if dir == "" {
		return nil
	}
	return startupFor(dir).eventsSince(mac, after, upTo)
}

// ─── API ──────────────────────────────────────────────────────────────

type startupTokOut struct {
	T    string  `json:"t"`
	F    float64 `json:"f"`
	Feat bool    `json:"feat,omitempty"`
}

type startupAppOut struct {
	AppID  string          `json:"app_id"`
	Name   string          `json:"name"`
	Starts float64         `json:"starts"`
	Tokens []startupTokOut `json:"tokens"`
	Feat   int             `json:"feat"`
	Usable bool            `json:"usable"`
}

// learnedView 学习表的展示形态(衰减后), 也给规则包导出用。
func (st *startupStore) learnedView(now time.Time) ([]startupAppOut, int) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.loadLocked()
	ts := now.Unix()
	feats := startupFeatSet(buildStartupModel(st.table, nil, ts, true))
	ids := make([]string, 0, len(st.table.apps))
	for id := range st.table.apps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]startupAppOut, 0, len(ids))
	usable := 0
	for _, id := range ids {
		a := st.table.apps[id]
		f := startupDecay(a.Upd, ts)
		starts := a.Starts * f
		o := startupAppOut{AppID: id, Name: a.Name, Starts: math.Round(starts*10) / 10, Tokens: []startupTokOut{}}
		if o.Name == "" {
			o.Name = id
		}
		fs := feats[id]
		for tok, n := range a.Tokens {
			fr := 0.0
			if starts > 0 {
				fr = math.Min(n*f/starts, 1)
			}
			o.Tokens = append(o.Tokens, startupTokOut{T: tok, F: round2(fr), Feat: fs[tok]})
		}
		sort.Slice(o.Tokens, func(i, j int) bool {
			if o.Tokens[i].F != o.Tokens[j].F {
				return o.Tokens[i].F > o.Tokens[j].F
			}
			return o.Tokens[i].T < o.Tokens[j].T
		})
		o.Feat = len(fs)
		o.Usable = fs != nil
		if o.Usable {
			usable++
		}
		out = append(out, o)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Usable != out[j].Usable {
			return out[i].Usable
		}
		return out[i].Starts > out[j].Starts
	})
	return out, usable
}

func (s *server) apiDPIStartup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	now := time.Now()
	st := startupFor(s.hncDir)
	learned, usable := st.learnedView(now)
	st.mu.Lock()
	events := make([]startupEvent, 0, len(st.events))
	for i := len(st.events) - 1; i >= 0; i-- {
		events = append(events, st.events[i])
	}
	stats := map[string]interface{}{
		"samples_read": st.stats.SamplesRead, "starts_learned": st.stats.StartsLearned,
		"apps_usable": usable, "events_total": st.stats.EventsTotal, "last_learn": st.stats.LastLearn,
		"imported": len(st.importedLocked()),
	}
	st.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "learned": learned, "events": events, "stats": stats, "shadow": true,
		"thresholds": map[string]interface{}{
			"gap_sec": startupGapSec, "window_sec": startupWinSec, "min_starts": startupMinStarts,
			"min_feat": startupMinFeat, "feat_freq": startupFeatFreq, "min_recall": startupMinRecall,
			"min_lead": startupMinLead, "half_life_days": startupHalfLifeSec / 86400,
		},
	})
}

// ─── 识别自评: 按天交叉验证 ───────────────────────────────────────────

// dpiEvalStartup /api/dpi_eval 的 startup 段
type dpiEvalStartup struct {
	Days          int     `json:"days"`           // 参与交叉验证的样本天数
	AppsLearned   int     `json:"apps_learned"`   // 学习表里可用的应用数(实时表)
	Switches      int     `json:"switches"`       // 真值里的前台切换数
	SwitchHit     int     `json:"switch_hit"`     // 其中被启动事件认出的
	SwitchRate    float64 `json:"switch_rate"`    // 切换识别率
	Events        int     `json:"events"`         // 交叉验证产生的事件数
	EventsCorrect int     `json:"events_correct"` // 其中事件时刻附近真值前台就是该应用的
	EventAccuracy float64 `json:"event_accuracy"` // 事件准确率
	MedianLagSec  float64 `json:"median_lag_sec"` // 事件与真值时刻差的中位数(事件 − 真值)
	Note          string  `json:"note,omitempty"`
}

type startupFGRec struct {
	ts  int64
	app string
}

// startupLoadDays 读全部(≤ 7 天)样本, 按本地日期分组、组内按时间排序。
func startupLoadDays(hncDir string) map[string][]startupSample {
	files := startupSampleFiles(filepath.Join(hncDir, "run"))
	out := map[string][]startupSample{}
	total := 0
	dates := make([]string, 0, len(files))
	for d := range files {
		dates = append(dates, d)
	}
	sort.Strings(dates)
	for _, d := range dates {
		if total >= dpiEvalMaxSamples {
			break
		}
		ss, _, _ := startupReadFrom(files[d], 0, dpiEvalMaxSamples-total)
		total += len(ss)
		sort.SliceStable(ss, func(i, j int) bool { return ss[i].Ts < ss[j].Ts })
		if len(ss) > 0 {
			out[d] = ss
		}
	}
	return out
}

// startupLoadFG 读某天的前台真值(包名映射到应用 id, 映射不到的跳过)。
func startupLoadFG(hncDir, date string, pmap map[string]string) []startupFGRec {
	f, err := os.Open(filepath.Join(hncDir, "run", "self_fg."+date+".jsonl"))
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 8<<20))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	var out []startupFGRec
	for sc.Scan() {
		var r selfFGRecord
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.Pkg == "" {
			continue
		}
		app := pmap[r.Pkg]
		if app == "" {
			app = "pkg:" + r.Pkg // 仍然记下, 让「当时前台不是某应用」可判断
		}
		out = append(out, startupFGRec{r.Ts, app})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ts < out[j].ts })
	return out
}

// evalStartup 按天交叉验证: 对每一天 d, 用其它天训练、在 d 天的本机样本上识别,
// 和 d 天的前台真值对比。纯只读。
func evalStartup(hncDir string, now time.Time) *dpiEvalStartup {
	res := &dpiEvalStartup{}
	_, res.AppsLearned = startupFor(hncDir).learnedView(now)
	days := startupLoadDays(hncDir)
	res.Days = len(days)
	if len(days) < 2 {
		res.Note = "样本不足 2 天，无法交叉验证"
		return res
	}
	pmap := pkgAppMap(hncDir)
	names := ruleNameMap(hncDir)
	dates := make([]string, 0, len(days))
	for d := range days {
		dates = append(dates, d)
	}
	sort.Strings(dates)
	var lags []float64
	for _, d := range dates {
		var train []startupSample
		for _, o := range dates {
			if o != d {
				train = append(train, days[o]...)
			}
		}
		// 跨天拼接后仍按时间顺序(日期升序 + 组内有序)
		model := buildStartupModel(startupTrain(train, pmap, names), nil, 0, false)
		rec := newStartupRecognizer()
		var events []startupEvent
		for _, s := range days[d] {
			if s.UID < startupMinUID {
				continue
			}
			if ev := rec.feed(model, "self", s.Ts, startupToken(s.SNI)); ev != nil {
				events = append(events, *ev)
			}
		}
		truth := startupLoadFG(hncDir, d, pmap)
		// 切换 = 映射得到的应用与上一条不同的真值记录(pkg: 开头的不算切换, 但参与「当时前台」判断)
		prev := ""
		for _, t := range truth {
			if t.app == prev {
				continue
			}
			prev = t.app
			if strings.HasPrefix(t.app, "pkg:") {
				continue
			}
			res.Switches++
			best := math.MaxFloat64
			for _, e := range events {
				if e.AppID == t.app && e.Ts >= t.ts-60 && e.Ts <= t.ts+10 {
					if lag := float64(e.Ts - t.ts); math.Abs(lag) < math.Abs(best) {
						best = lag
					}
				}
			}
			if best != math.MaxFloat64 {
				res.SwitchHit++
				lags = append(lags, best)
			}
		}
		for _, e := range events {
			res.Events++
			if startupFGMatch(truth, e.AppID, e.Ts-10, e.Ts+60) {
				res.EventsCorrect++
			}
		}
	}
	res.SwitchRate = ratio(res.SwitchHit, res.Switches)
	res.EventAccuracy = ratio(res.EventsCorrect, res.Events)
	if len(lags) > 0 {
		sort.Float64s(lags)
		n := len(lags)
		if n%2 == 1 {
			res.MedianLagSec = lags[n/2]
		} else {
			res.MedianLagSec = (lags[n/2-1] + lags[n/2]) / 2
		}
	}
	res.Note = "按天交叉验证: 每天用其它天的样本学习、在当天识别。前台真值 10~60 秒探测一次, 比真实切换晚最多 60 秒。"
	return res
}

// startupFGMatch [from, to] 内是否有某时刻真值前台就是 app
func startupFGMatch(truth []startupFGRec, app string, from, to int64) bool {
	cur := ""
	for _, t := range truth {
		if t.ts <= from {
			cur = t.app
			continue
		}
		if t.ts > to {
			break
		}
		if t.app == app {
			return true
		}
	}
	return cur == app
}
