// fp_learn.go — v6.x DPI v2: 指纹学习 + 无域名连接的指纹识别
//
// 数据源: dpid 的 run/dpi_flows.json(src/dpid/output/flowlog.go): 最近 10 分钟每个
// ClientHello 的五元组 + JA4 + 首个 ALPN + SNI(+ SNI 的规则库归类)。五元组 key 与
// ctEntry.key() 同格式("proto|client_ip|sport|dst_ip|dport"), 直接 join conntrack。
//
// ── 学习 ───────────────────────────────────────────────────────────────────────
// 指纹 key = (JA4, 首个 ALPN, 目的端口类 443/80/other)。每个 ClientHello 给一个标签:
//
//	SNI(非 ECH 外层)命中用户域名规则 / 规则库 → 该应用, 权重 1
//	SNI 规则库认不出                         → "_other", 权重 1(浏览器访问任意网站
//	                                           就是这样 —— 让通用指纹变「不纯」)
//	无 SNI / ECH 外层, 但目的 IP 的 DNS 反查名归到应用 → 该应用, 权重 0.5
//	广告/统计/CDN 类(tierHidden)            → 不计(它们由各 App 自己的栈发出, 不说明是谁)
//
// 计数按 14 天半衰期衰减(惰性), 单条总量超过 5000 全体减半; 最多 4096 个 key(按最近
// 出现淘汰), 每个 key 最多记 16 台设备(设备只存 MAC 的散列前缀)。
// 可用条件: 支持度(衰减后总数)≥ 50, 或 ≥ 20 且来自 ≥ 2 台设备; 且第一名不是 "_other"、
// 占比(纯度)≥ 90%。Chromium/Cronet/OkHttp 等通用栈被很多 App 共用, 纯度达不到, 自然不用
// (这类在 /api/dpi_fp 里标 generic, 识别时计 generic_skipped)。
// 置信度 = 纯度 × 支持度/(支持度+10)(支持度 50 → ×0.83, 100 → ×0.91)。
//
// ── 识别 ───────────────────────────────────────────────────────────────────────
// 只用于「没有域名」(反查表无名, 或只有 ECH 外层 SNI)且规则归不上的连接:
// 五元组找到它的 ClientHello(找不到则用同设备同目的同端口 30 分钟内最近的一条), 依次查
// 用户 ja4 纠正 → 学习表 → 种子表(data/fp_seed.json, 默认不发; 学习表判为通用的指纹不用种子)。
// 连接 → 指纹的绑定在内存里保留到连接 2 小时无流量(上限 16384 条)。
//
// v5.27 T2 QUIC 传输参数指纹(qtp): 带 qtp 的 QUIC ClientHello 学到 key
// fpKeyOf(ja4, alpn, port)+"|"+qtp 下(门槛不变); 识别时先查带 qtp 的 key, 没有 / 不可用 /
// 判为通用再回落旧 key(旧版学到的 QUIC 条目只读兜底, 随 14 天半衰期自然淘汰)。
//
// 持久化: data/fp_learned.json, 有变化时最多 10 分钟写一次(进程被杀最多丢 10 分钟的学习)。
//
//	GET /api/dpi_fp[?all=1] → {ok, learned:[{ja4, alpn, port_class, qtp, app_id, name, category,
//	    purity, support, devices, last_seen, usable, generic, conf, top:[{id,name,share}]}],
//	    stats:{flows_seen, flows_learned, flows_attributed_by_fp, flows_attributed_by_qtp,
//	    generic_skipped, entries, usable, binds, seed}, thresholds:{...}, user_rules:[...]}
package main

import (
	"crypto/sha256"
	"encoding/hex"
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
	fpMinSupport      = 50.0
	fpMinSupportMulti = 20.0
	fpMinDevices      = 2
	fpMinPurity       = 0.90
	fpHalfLifeSec     = 14 * 24 * 3600
	fpTotalCap        = 5000.0
	fpMaxEntries      = 4096
	fpMaxDevs         = 16
	fpDevKeepSec      = 30 * 24 * 3600
	fpMaxBinds        = 16384
	fpBindIdleSec     = 2 * 3600
	fpPairSec         = 30 * 60
	fpSaveEvery       = 10 * time.Minute
	fpPruneEvery      = time.Minute
	fpDNSWeight       = 0.5
	fpOtherApp        = "_other"
	fpSeedConf        = 0.8
	fpFlowsMaxBytes   = 4 << 20
	// 用户 ja4 规则: 学习表里该指纹别的应用(含 _other)占比 ≥ 30% 且样本 ≥ 10 → 视为通用, 拒绝/不生效
	fpUserJA4MinSupport   = 10.0
	fpUserJA4GenericShare = 0.30
	fpListCap             = 300
)

type fpAppCount struct {
	N        float64 `json:"n"`
	Name     string  `json:"name,omitempty"`
	Category string  `json:"category,omitempty"`
}

type fpEntry struct {
	JA4   string                 `json:"ja4"`
	ALPN  string                 `json:"alpn,omitempty"`
	Port  string                 `json:"port"`
	QTP   string                 `json:"qtp,omitempty"` // v5.27 T2, 旧文件没有
	Apps  map[string]*fpAppCount `json:"apps"`
	Total float64                `json:"total"`
	Devs  map[string]int64       `json:"devs,omitempty"` // MAC 散列前缀 → 最近出现
	First int64                  `json:"first"`
	Last  int64                  `json:"last"`
	Upd   int64                  `json:"upd"` // 计数衰减到的时刻
}

type fpVerdict struct {
	Top, TopName, TopCat string
	Purity, Support      float64
	Devices              int
	Usable, Generic      bool
	Conf                 float64
}

func fpPortClass(dport int) string {
	switch dport {
	case 443:
		return "443"
	case 80:
		return "80"
	}
	return "other"
}

func fpKeyOf(ja4, alpn, port string) string { return ja4 + "|" + alpn + "|" + port }

// fpKeyQ v5.27 T2: 带 QUIC 传输参数指纹的 key; qtp 为空时等于旧 key。
func fpKeyQ(ja4, alpn, port, qtp string) string {
	if qtp == "" {
		return fpKeyOf(ja4, alpn, port)
	}
	return fpKeyOf(ja4, alpn, port) + "|" + qtp
}

// fpCleanQTP 只接受 qtp1_ + 12 位十六进制, 其它一律当没有。
func fpCleanQTP(q string) string {
	if fpQTPRE.MatchString(q) {
		return q
	}
	return ""
}

func fpDevKey(mac string) string {
	h := sha256.Sum256([]byte(strings.ToLower(mac)))
	return hex.EncodeToString(h[:6])
}

func fpDecayFactor(from, to int64) float64 {
	if to <= from {
		return 1
	}
	return math.Pow(0.5, float64(to-from)/fpHalfLifeSec)
}

func (e *fpEntry) decayTo(now int64) {
	f := fpDecayFactor(e.Upd, now)
	if now > e.Upd {
		e.Upd = now
	}
	if f >= 1 {
		return
	}
	e.Total = 0
	for id, a := range e.Apps {
		a.N *= f
		if a.N < 0.01 {
			delete(e.Apps, id)
			continue
		}
		e.Total += a.N
	}
}

func (e *fpEntry) learn(id, name, cat string, w float64, dev string, now int64) {
	e.decayTo(now)
	if e.Apps == nil {
		e.Apps = map[string]*fpAppCount{}
	}
	a := e.Apps[id]
	if a == nil {
		a = &fpAppCount{}
		e.Apps[id] = a
	}
	a.N += w
	if name != "" {
		a.Name = name
	}
	if cat != "" {
		a.Category = cat
	}
	e.Total += w
	if e.Total > fpTotalCap {
		e.Total = 0
		for _, x := range e.Apps {
			x.N /= 2
			e.Total += x.N
		}
	}
	if e.Devs == nil {
		e.Devs = map[string]int64{}
	}
	if _, ok := e.Devs[dev]; !ok && len(e.Devs) >= fpMaxDevs {
		old, ot := "", int64(math.MaxInt64)
		for k, t := range e.Devs {
			if t < ot || (t == ot && k < old) {
				old, ot = k, t
			}
		}
		delete(e.Devs, old)
	}
	e.Devs[dev] = now
	if e.First == 0 {
		e.First = now
	}
	e.Last = now
}

// verdict 不修改条目(衰减按比例算; 纯度与衰减无关)
func (e *fpEntry) verdict(now int64) fpVerdict {
	v := fpVerdict{}
	if e.Total <= 0 {
		return v
	}
	var topN float64
	for id, a := range e.Apps {
		if a.N > topN || (a.N == topN && id < v.Top) {
			topN, v.Top, v.TopName, v.TopCat = a.N, id, a.Name, a.Category
		}
	}
	v.Purity = topN / e.Total
	v.Support = e.Total * fpDecayFactor(e.Upd, now)
	for _, t := range e.Devs {
		if now-t <= fpDevKeepSec {
			v.Devices++
		}
	}
	enough := v.Support >= fpMinSupport || (v.Support >= fpMinSupportMulti && v.Devices >= fpMinDevices)
	pure := v.Top != fpOtherApp && v.Purity >= fpMinPurity
	v.Usable = enough && pure
	v.Generic = v.Support >= fpMinSupportMulti && !pure
	if v.Usable {
		v.Conf = v.Purity * v.Support / (v.Support + 10)
	}
	return v
}

// ─── 存储 ─────────────────────────────────────────────────────────────

type fpBind struct {
	fpKey, ja4, mac, dip string
	qKey, qtp            string // v5.27 T2: 带 qtp 的 key(无 qtp 为空)
	dport                int
	ech                  bool
	ts, seen             int64
	counted, skipped     bool
}

type fpStats struct {
	FlowsSeen       uint64 `json:"flows_seen"`
	FlowsLearned    uint64 `json:"flows_learned"`
	FlowsAttributed uint64 `json:"flows_attributed_by_fp"`
	GenericSkipped  uint64 `json:"generic_skipped"`
	// v5.27 T2: 其中靠「JA4 + QUIC 传输参数」条目归属的连接数
	FlowsByQTP uint64 `json:"flows_attributed_by_qtp,omitempty"`
}

type fpSeedEntry struct {
	JA4      string `json:"ja4"`
	AppID    string `json:"app_id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

type fpStore struct {
	mu        sync.Mutex
	hncDir    string
	loaded    bool
	m         map[string]*fpEntry
	binds     map[string]*fpBind // ct key → ClientHello
	pairs     map[string]*fpBind // proto|cip|dip|dport → 最近一条
	boot      int64
	cursor    int64
	flowsKey  string
	seed      map[string]fpSeedEntry
	seedKey   string
	imp       map[string]rulepackFP // v5.27 T6: 导入的指纹(data/fp_imported.json), key = fpKeyQ
	impKey    string
	stats     fpStats
	dirty     bool
	lastSave  time.Time
	lastPrune time.Time
}

var fpStores struct {
	mu sync.Mutex
	m  map[string]*fpStore
}

func fpFor(hncDir string) *fpStore {
	fpStores.mu.Lock()
	defer fpStores.mu.Unlock()
	if fpStores.m == nil {
		fpStores.m = map[string]*fpStore{}
	}
	st := fpStores.m[hncDir]
	if st == nil {
		st = &fpStore{hncDir: hncDir, m: map[string]*fpEntry{}, binds: map[string]*fpBind{}, pairs: map[string]*fpBind{}}
		fpStores.m[hncDir] = st
		dpiUserRulesRefresh(hncDir) // 启动后第一轮 app_usage 之前, 连接列表也能用上用户纠正
	}
	return st
}

func fpLearnedPath(hncDir string) string { return filepath.Join(hncDir, "data", "fp_learned.json") }
func fpSeedPath(hncDir string) string    { return filepath.Join(hncDir, "data", "fp_seed.json") }

type fpLearnedFile struct {
	Schema  int        `json:"schema"`
	SavedAt int64      `json:"saved_at"`
	Stats   fpStats    `json:"stats"`
	Entries []*fpEntry `json:"entries"`
}

func (st *fpStore) loadLocked() {
	if st.loaded {
		return
	}
	st.loaded = true
	b, err := os.ReadFile(fpLearnedPath(st.hncDir))
	if err != nil || len(b) > 16<<20 {
		return
	}
	var f fpLearnedFile
	if json.Unmarshal(b, &f) != nil {
		return
	}
	for _, e := range f.Entries {
		if e == nil || e.JA4 == "" || e.Apps == nil {
			continue
		}
		e.QTP = fpCleanQTP(e.QTP)
		st.m[fpKeyQ(e.JA4, e.ALPN, e.Port, e.QTP)] = e
	}
	st.stats = f.Stats
	st.evictEntriesLocked()
}

func (st *fpStore) saveLocked(now time.Time) error {
	f := fpLearnedFile{Schema: 1, SavedAt: now.Unix(), Stats: st.stats, Entries: make([]*fpEntry, 0, len(st.m))}
	keys := make([]string, 0, len(st.m))
	for k := range st.m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		f.Entries = append(f.Entries, st.m[k])
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if err := discoverWriteAtomic(fpLearnedPath(st.hncDir), b); err != nil {
		return err
	}
	st.dirty = false
	st.lastSave = now
	return nil
}

func (st *fpStore) seedLocked() map[string]fpSeedEntry {
	p := fpSeedPath(st.hncDir)
	key := "-"
	if fi, err := os.Stat(p); err == nil {
		key = strconv.FormatInt(fi.ModTime().UnixNano(), 10) + ":" + strconv.FormatInt(fi.Size(), 10)
	}
	if key == st.seedKey {
		return st.seed
	}
	st.seedKey = key
	st.seed = nil
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 1<<20 {
		return nil
	}
	var f struct {
		Entries []fpSeedEntry `json:"entries"`
	}
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	st.seed = map[string]fpSeedEntry{}
	for _, e := range f.Entries {
		if dpiJA4RE.MatchString(e.JA4) && e.AppID != "" && appTier(e.Category) != tierHidden {
			st.seed[e.JA4] = e
		}
	}
	return st.seed
}

// importedLocked v5.27 T6: 导入的指纹(规则包), 按 mtime 缓存; 广告类 / 不合法的条目不用
func (st *fpStore) importedLocked() map[string]rulepackFP {
	p := fpImportedPath(st.hncDir)
	key := "-"
	if fi, err := os.Stat(p); err == nil {
		key = strconv.FormatInt(fi.ModTime().UnixNano(), 10) + ":" + strconv.FormatInt(fi.Size(), 10)
	}
	if key == st.impKey {
		return st.imp
	}
	st.impKey, st.imp = key, nil
	list := rpReadImportedFP(st.hncDir)
	if len(list) == 0 {
		return nil
	}
	st.imp = make(map[string]rulepackFP, len(list))
	for _, e := range list {
		if dpiJA4RE.MatchString(e.JA4) && e.AppID != "" && appTier(e.Category) != tierHidden &&
			(e.QTP == "" || fpQTPRE.MatchString(e.QTP)) {
			st.imp[fpKeyQ(e.JA4, e.ALPN, e.Port, e.QTP)] = e
		}
	}
	return st.imp
}

// evictEntriesLocked 超上限时按最近出现淘汰到 90%
func (st *fpStore) evictEntriesLocked() {
	if len(st.m) <= fpMaxEntries {
		return
	}
	type kv struct {
		k    string
		last int64
	}
	l := make([]kv, 0, len(st.m))
	for k, e := range st.m {
		l = append(l, kv{k, e.Last})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].last != l[j].last {
			return l[i].last < l[j].last
		}
		return l[i].k < l[j].k
	})
	for _, x := range l[:len(l)-fpMaxEntries*9/10] {
		delete(st.m, x.k)
	}
}

func (st *fpStore) pruneBindsLocked(now int64, force bool) {
	for k, b := range st.binds {
		if now-b.seen > fpBindIdleSec {
			delete(st.binds, k)
		}
	}
	for k, b := range st.pairs {
		if now-b.ts > fpPairSec {
			delete(st.pairs, k)
		}
	}
	if !force || len(st.binds) < fpMaxBinds {
		return
	}
	// 仍然满: 删最久没用的 1/4
	l := make([]int64, 0, len(st.binds))
	for _, b := range st.binds {
		l = append(l, b.seen)
	}
	sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
	cut := l[len(l)/4]
	for k, b := range st.binds {
		if b.seen <= cut {
			delete(st.binds, k)
		}
	}
}

// ─── 摄入 dpi_flows.json ─────────────────────────────────────────────

type fpFlowRec struct {
	Seq      int64  `json:"seq"`
	Ts       int64  `json:"ts"`
	MAC      string `json:"mac"`
	CIP      string `json:"cip"`
	Sport    int    `json:"sport"`
	DIP      string `json:"dip"`
	Dport    int    `json:"dport"`
	Proto    string `json:"proto"`
	JA4      string `json:"ja4"`
	ALPN     string `json:"alpn"`
	SNI      string `json:"sni"`
	ECHOuter bool   `json:"ech_outer"`
	App      string `json:"app"`
	AppName  string `json:"app_name"`
	Category string `json:"category"`
	QTP      string `json:"qtp"` // v5.27 T2
}

type fpFlowFile struct {
	Boot  int64       `json:"boot"`
	Seq   int64       `json:"seq"`
	Flows []fpFlowRec `json:"flows"`
}

// tick 每轮 app_usage 调用: 刷新用户规则、摄入新的 ClientHello、定期裁剪与落盘。
// v5.27 T3: 返回本轮新摄入的记录(seq 新于上次), 由调用方在锁外交给启动指纹识别。
func (st *fpStore) tick(now time.Time, names map[string]ipName) []fpFlowRec {
	dpiUserRulesRefresh(st.hncDir)
	var recs []fpFlowRec
	var boot int64
	p := filepath.Join(st.hncDir, "run", "dpi_flows.json")
	key := ""
	if fi, err := os.Stat(p); err == nil && fi.Size() <= fpFlowsMaxBytes {
		key = strconv.FormatInt(fi.ModTime().UnixNano(), 10) + ":" + strconv.FormatInt(fi.Size(), 10)
	}
	st.mu.Lock()
	changed := key != "" && key != st.flowsKey
	st.mu.Unlock()
	if changed {
		if b, err := os.ReadFile(p); err == nil {
			var f fpFlowFile
			if json.Unmarshal(b, &f) == nil {
				recs, boot = f.Flows, f.Boot
			}
		}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.loadLocked()
	var fresh []fpFlowRec
	if changed {
		st.flowsKey = key
		fresh = st.ingestLocked(boot, recs, names, now)
	}
	if now.Sub(st.lastPrune) >= fpPruneEvery {
		st.lastPrune = now
		st.pruneBindsLocked(now.Unix(), false)
	}
	if st.dirty && now.Sub(st.lastSave) >= fpSaveEvery {
		_ = st.saveLocked(now)
	}
	return fresh
}

func (st *fpStore) ingestLocked(boot int64, recs []fpFlowRec, names map[string]ipName, now time.Time) []fpFlowRec {
	if boot != st.boot {
		st.boot, st.cursor = boot, 0 // dpid 重启: seq 从头来
	}
	ts := now.Unix()
	var fresh []fpFlowRec
	for i := range recs {
		r := &recs[i]
		if r.Seq <= st.cursor {
			continue
		}
		st.cursor = r.Seq
		if r.SNI != "" && r.MAC != "" {
			fresh = append(fresh, *r)
		}
		mac := strings.ToLower(r.MAC)
		if (mac != "" && isSimMAC(mac)) || r.JA4 == "" || r.CIP == "" || r.DIP == "" || (r.Proto != "tcp" && r.Proto != "udp") {
			continue
		}
		st.stats.FlowsSeen++
		fk := fpKeyOf(r.JA4, r.ALPN, fpPortClass(r.Dport))
		b := &fpBind{fpKey: fk, ja4: r.JA4, mac: mac, dip: r.DIP, dport: r.Dport, ech: r.ECHOuter, ts: r.Ts, seen: ts}
		// v5.27 T2: QUIC 带传输参数指纹 → 学到更细的 key 下(旧 key 不再增长)
		if q := fpCleanQTP(r.QTP); q != "" && r.Proto == "udp" {
			b.qtp, b.qKey = q, fpKeyQ(r.JA4, r.ALPN, fpPortClass(r.Dport), q)
		}
		lk := fk
		if b.qKey != "" {
			lk = b.qKey
		}
		if len(st.binds) >= fpMaxBinds {
			st.pruneBindsLocked(ts, true)
		}
		st.binds[r.Proto+"|"+r.CIP+"|"+strconv.Itoa(r.Sport)+"|"+r.DIP+"|"+strconv.Itoa(r.Dport)] = b
		st.pairs[r.Proto+"|"+r.CIP+"|"+r.DIP+"|"+strconv.Itoa(r.Dport)] = b
		id, name, cat, w := fpLabel(r, names)
		if id == "" || w <= 0 {
			continue
		}
		dev := mac
		if dev == "" {
			dev = r.CIP
		}
		e := st.m[lk]
		if e == nil {
			e = &fpEntry{JA4: r.JA4, ALPN: r.ALPN, Port: fpPortClass(r.Dport), QTP: b.qtp, Upd: r.Ts}
			st.m[lk] = e
		}
		lt := r.Ts
		if lt <= 0 || lt > ts {
			lt = ts
		}
		e.learn(id, name, cat, w, fpDevKey(dev), lt)
		st.stats.FlowsLearned++
		st.dirty = true
	}
	st.evictEntriesLocked()
	return fresh
}

// fpLabel 一个 ClientHello 的学习标签(见文件头)
func fpLabel(r *fpFlowRec, names map[string]ipName) (id, name, cat string, w float64) {
	if r.SNI != "" && !r.ECHOuter {
		if a, ok := dpiUserMatchName(r.SNI); ok {
			id, name, cat, w = a.ID, a.Name, a.Category, 1
		} else if r.App != "" {
			id, name, cat, w = r.App, r.AppName, r.Category, 1
		} else {
			return fpOtherApp, "", "", 1
		}
	} else if n, ok := names[r.DIP]; ok && n.App != "" {
		id, name, cat, w = n.App, n.AppName, n.Category, fpDNSWeight
	}
	if id == "" || appTier(cat) == tierHidden || strings.HasPrefix(id, "_") {
		return "", "", "", 0
	}
	if name == "" {
		name = id
	}
	return id, name, cat, w
}

// ─── 归属 ─────────────────────────────────────────────────────────────

// flowAttr 一条连接的应用归属与来源
type flowAttr struct {
	App  ipApp
	Src  string  // user | rule | name | fp | seed | imported(v5.27 规则包)
	Conf float64 // 0-1; rule/name 为 0(不显示)
	JA4  string
}

func splitCtKey(key string) (proto, src string, sport int, dst string, dport int, ok bool) {
	p := strings.Split(key, "|")
	if len(p) != 5 {
		return
	}
	var e1, e2 error
	sport, e1 = strconv.Atoi(p[2])
	dport, e2 = strconv.Atoi(p[4])
	if e1 != nil || e2 != nil {
		return
	}
	return p[0], p[1], sport, p[3], dport, true
}

// attribute 按完整优先级给一条连接(ct key)归属:
// 用户 ip+port > appForIPSrc(用户 ip/domain > ip_app_map > 域名归类) > 用户 ja4 > 学习指纹 > 种子。
// 返回的 flowAttr.JA4 即使未归属也可能非空(给界面「纠正」用)。
func (st *fpStore) attribute(key string, apps map[string]ipApp, names map[string]ipName, now time.Time) (flowAttr, bool) {
	proto, src, _, dst, dport, ok := splitCtKey(key)
	if !ok {
		return flowAttr{}, false
	}
	if a, ok := dpiUserMatchIP(dst, dport, now); ok {
		return flowAttr{App: a, Src: "user", Conf: 1}, true
	}
	if a, s, ok := appForIPSrc(dst, apps, names); ok {
		fa := flowAttr{App: a, Src: s}
		if s == "user" {
			fa.Conf = 1
		}
		return fa, true
	}
	if isPrivateIP(dst) {
		return flowAttr{}, false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.fpAttrLocked(key, proto, src, dst, dport, names, now.Unix())
}

func (st *fpStore) fpAttrLocked(key, proto, src, dst string, dport int, names map[string]ipName, now int64) (flowAttr, bool) {
	b := st.binds[key]
	if b == nil {
		if pb := st.pairs[proto+"|"+src+"|"+dst+"|"+strconv.Itoa(dport)]; pb != nil && now-pb.ts <= fpPairSec {
			b = pb
		}
	}
	if b == nil {
		return flowAttr{}, false
	}
	b.seen = now
	fa := flowAttr{JA4: b.ja4}
	if names[dst].Name != "" && !b.ech {
		return fa, false // 有域名(规则库认不出)的连接不靠指纹猜
	}
	v, byQTP, qGeneric := st.verdictForBindLocked(b, now)
	if r, ok := dpiUserMatchJA4(b.ja4); ok && !st.ja4GenericLocked(b.ja4, r.AppID, now) {
		fa.App, fa.Src, fa.Conf = r.app(), "user", 1
		return fa, true
	}
	if v.Usable {
		fa.App = ipApp{ID: v.Top, Name: v.TopName, Category: v.TopCat}
		if fa.App.Name == "" {
			fa.App.Name = v.Top
		}
		fa.Src, fa.Conf = "fp", v.Conf
		if !b.counted {
			b.counted = true
			st.stats.FlowsAttributed++
			if byQTP {
				st.stats.FlowsByQTP++
			}
		}
		return fa, true
	}
	if v.Generic || qGeneric {
		if !b.skipped {
			b.skipped = true
			st.stats.GenericSkipped++
		}
		return fa, false
	}
	// v5.27 T6: 导入的指纹 —— 学习表之后、种子表之前(学习表判为通用的已在上面挡掉);
	// 同样先带 qtp 的 key 再回落旧 key
	if imp := st.importedLocked(); imp != nil {
		ie, ok := imp[b.qKey]
		if !ok || b.qKey == "" {
			ie, ok = imp[b.fpKey]
		}
		if ok {
			n := ie.App
			if n == "" {
				n = ie.AppID
			}
			fa.App, fa.Src, fa.Conf = ipApp{ID: ie.AppID, Name: n, Category: ie.Category}, "imported", fpSeedConf
			if !b.counted {
				b.counted = true
				st.stats.FlowsAttributed++
			}
			return fa, true
		}
	}
	if se, ok := st.seedLocked()[b.ja4]; ok {
		n := se.Name
		if n == "" {
			n = se.AppID
		}
		fa.App, fa.Src, fa.Conf = ipApp{ID: se.AppID, Name: n, Category: se.Category}, "seed", fpSeedConf
		if !b.counted {
			b.counted = true
			st.stats.FlowsAttributed++
		}
		return fa, true
	}
	return fa, false
}

// verdictForBindLocked v5.27 T2「先 QTP 后回落」: 绑定的 ClientHello 有 qtp 时先看带 qtp
// 的条目, 可用(且非通用)就用它; 没有 / 不可用 / 判为通用 → 回落旧 key。
// 返回 (采用的 verdict, 是否来自 qtp 条目, qtp 条目是否判为通用)。
func (st *fpStore) verdictForBindLocked(b *fpBind, now int64) (fpVerdict, bool, bool) {
	return st.verdictForKeysLocked(b.qKey, b.fpKey, now)
}

func (st *fpStore) verdictForKeysLocked(qKey, legacyKey string, now int64) (fpVerdict, bool, bool) {
	qGeneric := false
	if qKey != "" {
		if e := st.m[qKey]; e != nil {
			v := e.verdict(now)
			if v.Usable && !v.Generic {
				return v, true, false
			}
			qGeneric = v.Generic
		}
	}
	var v fpVerdict
	if e := st.m[legacyKey]; e != nil {
		v = e.verdict(now)
	}
	return v, false, qGeneric
}

// ja4GenericLocked: 学习表里该 JA4(所有 ALPN/端口类合计)中不属于 appID 的占比 ≥ 30% 且样本 ≥ 10
func (st *fpStore) ja4GenericLocked(ja4, appID string, now int64) bool {
	g, _ := st.ja4GenericInfoLocked(ja4, appID, now)
	return g
}

func (st *fpStore) ja4GenericInfoLocked(ja4, appID string, now int64) (bool, string) {
	var total, mine float64
	for _, e := range st.m {
		if e.JA4 != ja4 {
			continue
		}
		f := fpDecayFactor(e.Upd, now)
		total += e.Total * f
		if a := e.Apps[appID]; a != nil {
			mine += a.N * f
		}
	}
	if total < fpUserJA4MinSupport {
		return false, ""
	}
	other := (total - mine) / total
	if other >= fpUserJA4GenericShare {
		return true, "其它应用/浏览器占 " + strconv.Itoa(int(math.Round(other*100))) + "%"
	}
	return false, ""
}

func (st *fpStore) ja4Generic(ja4, appID string, now time.Time) (bool, string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.loadLocked()
	return st.ja4GenericInfoLocked(ja4, appID, now.Unix())
}

// findJA4 纠正动作没带 ja4 时: 按 (设备, 目的 IP, 目的端口) 找最近的 ClientHello
func (st *fpStore) findJA4(mac, dstIP string, port int, now time.Time) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	var best *fpBind
	for _, b := range st.binds {
		if b.dip != dstIP || (port > 0 && b.dport != port) || (mac != "" && b.mac != "" && b.mac != mac) {
			continue
		}
		if best == nil || b.ts > best.ts {
			best = b
		}
	}
	if best == nil {
		return ""
	}
	return best.ja4
}

// fpClassify app_usage 记账用: 只返回 用户规则 / 指纹 / 种子 的归属; 规则库与域名归类的
// 交给原有分支(保持共现推断/隧道等逻辑的顺序)。VPN 签名流不碰。
func (cx *identCtx) fpClassify(dl appUsageDelta) (flowAttr, bool) {
	if cx == nil || cx.fp == nil || dl.Key == "" || cx.sigKey[dl.Key] {
		return flowAttr{}, false
	}
	fa, ok := cx.fp.attribute(dl.Key, cx.apps, cx.names, cx.now)
	if !ok || (fa.Src != "user" && fa.Src != "fp" && fa.Src != "seed" && fa.Src != "imported") {
		return flowAttr{}, false
	}
	return fa, true
}

// ─── API ──────────────────────────────────────────────────────────────

func (s *server) apiDPIFP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	now := time.Now()
	all := r.URL.Query().Get("all") == "1"
	st := fpFor(s.hncDir)
	st.mu.Lock()
	st.loadLocked()
	ts := now.Unix()
	type row struct {
		m       map[string]interface{}
		usable  bool
		support float64
	}
	rows := make([]row, 0, len(st.m))
	usable := 0
	for _, e := range st.m {
		v := e.verdict(ts)
		if v.Usable {
			usable++
		}
		m := map[string]interface{}{
			"ja4": e.JA4, "alpn": e.ALPN, "port_class": e.Port, "qtp": e.QTP,
			"app_id": v.Top, "name": v.TopName, "category": v.TopCat,
			"purity": round2(v.Purity), "support": math.Round(v.Support*10) / 10, "devices": v.Devices,
			"last_seen": e.Last, "first_seen": e.First, "usable": v.Usable, "generic": v.Generic,
			"conf": round2(v.Conf),
		}
		if v.Top == fpOtherApp {
			m["name"] = "未知网站/应用"
		}
		type sh struct {
			id string
			n  float64
			nm string
		}
		var tops []sh
		for id, a := range e.Apps {
			tops = append(tops, sh{id, a.N, a.Name})
		}
		sort.Slice(tops, func(i, j int) bool {
			if tops[i].n != tops[j].n {
				return tops[i].n > tops[j].n
			}
			return tops[i].id < tops[j].id
		})
		var tl []map[string]interface{}
		for i, t := range tops {
			if i >= 3 {
				break
			}
			tl = append(tl, map[string]interface{}{"id": t.id, "name": t.nm, "share": round2(t.n / e.Total)})
		}
		m["top"] = tl
		rows = append(rows, row{m, v.Usable, v.Support})
	}
	stats := map[string]interface{}{
		"flows_seen": st.stats.FlowsSeen, "flows_learned": st.stats.FlowsLearned,
		"flows_attributed_by_fp": st.stats.FlowsAttributed, "generic_skipped": st.stats.GenericSkipped,
		"flows_attributed_by_qtp": st.stats.FlowsByQTP,
		"entries":                 len(st.m), "usable": usable, "binds": len(st.binds), "seed": len(st.seedLocked()),
	}
	st.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].usable != rows[j].usable {
			return rows[i].usable
		}
		if rows[i].support != rows[j].support {
			return rows[i].support > rows[j].support
		}
		return rows[i].m["ja4"].(string)+rows[i].m["port_class"].(string)+rows[i].m["qtp"].(string) < rows[j].m["ja4"].(string)+rows[j].m["port_class"].(string)+rows[j].m["qtp"].(string)
	})
	list := make([]map[string]interface{}, 0, len(rows))
	for i, rw := range rows {
		if !all && i >= fpListCap {
			break
		}
		list = append(list, rw.m)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": true, "learned": list, "stats": stats,
		"thresholds": map[string]interface{}{
			"min_support": fpMinSupport, "min_support_multi_device": fpMinSupportMulti, "min_devices": fpMinDevices,
			"min_purity": fpMinPurity, "half_life_days": fpHalfLifeSec / 86400, "user_ip_ttl_days": int(dpiUserIPTTL / (24 * time.Hour)),
		},
		"user_rules": dpiUserRulesView(s.hncDir, now),
	})
}

// ─── app_usage 来源计数 ───────────────────────────────────────────────

// appUsageAddSrc 记账时把 fp/seed/user 归属的字节另记一份(调用方持 appUsage.mu)
func appUsageAddSrc(d *appUsageDay, mk, src string, conf float64, up, dn uint64) {
	if up == 0 && dn == 0 {
		return
	}
	switch src {
	case "fp", "seed", "imported":
		if d.FP == nil {
			d.FP = map[string][2]uint64{}
		}
		if d.FPW == nil {
			d.FPW = map[string]float64{}
		}
		v := d.FP[mk]
		v[0] += up
		v[1] += dn
		d.FP[mk] = v
		d.FPW[mk] += float64(up+dn) * conf
	case "user":
		if d.User == nil {
			d.User = map[string][2]uint64{}
		}
		v := d.User[mk]
		v[0] += up
		v[1] += dn
		d.User[mk] = v
	}
}

type appUsageSrcAgg struct {
	fp, user       map[string]uint64
	fpw            map[string]float64
	totFP, totUser uint64
}

func newAppUsageSrcAgg() *appUsageSrcAgg {
	return &appUsageSrcAgg{fp: map[string]uint64{}, user: map[string]uint64{}, fpw: map[string]float64{}}
}

func (a *appUsageSrcAgg) addDay(d *appUsageDay, mac string, resolve func(string) string) {
	match := func(mk string) (string, bool) {
		sep := strings.IndexByte(mk, '|')
		if sep < 0 || (mac != "" && resolve(mk[:sep]) != mac) {
			return "", false
		}
		return mk[sep+1:], true
	}
	for mk, v := range d.FP {
		if id, ok := match(mk); ok {
			a.fp[id] += v[0] + v[1]
			a.fpw[id] += d.FPW[mk]
			a.totFP += v[0] + v[1]
		}
	}
	for mk, v := range d.User {
		if id, ok := match(mk); ok {
			a.user[id] += v[0] + v[1]
			a.totUser += v[0] + v[1]
		}
	}
}

// annotate by_app 一行加 fp_bytes / fp_conf(字节加权平均置信度)/ user_bytes
func (a *appUsageSrcAgg) annotate(id string, m map[string]interface{}) map[string]interface{} {
	if b := a.fp[id]; b > 0 {
		m["fp_bytes"] = b
		m["fp_conf"] = round2(a.fpw[id] / float64(b))
	}
	if b := a.user[id]; b > 0 {
		m["user_bytes"] = b
	}
	return m
}
