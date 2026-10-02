// dpi_eval.go — v5.24 T4 识别自评。
//
// 干什么: 拿 dpid 落下的「本机带标签样本」(run/label_samples.*.jsonl, T1) 当
// 标准答案, 逐条算 HNC 现有几种识别方法的预测, 统计覆盖率 / 准确率 / 最容易认错
// 的应用, 结果写 run/dpi_eval.json 并由 GET /api/dpi_eval 返回。
//
// 边界(工作文档 §2): 纯只读评估旁路。不改任何识别 / 限速 / 封锁行为, 不碰
// tc/iptables, 不上传数据, 不新增第三方依赖。样本本身只含本机自己的流量。
//
// 四种方法(每条样本都算一遍):
//   - rule:     样本里的 rule_id(dpid 当时靠规则库认出来的结果)。
//   - fp:       用 ja4 + alpn + fpPortClass(dport) 查指纹学习表, Usable && !Generic
//     时预测为 verdict.Top。
//   - owner:    目的 IP 归属是 app 类时预测为 _org:<key>(只认「哪家公司」)。
//     真值是「应用」, 拿不到 应用→公司 的可靠映射, 所以按 §8 降级:
//     owner 只算覆盖率, 不算准确率, 并在 note 里说明。
//   - combined: 按现有优先级 用户纠正 > 规则 > 指纹 取第一个有结果的。
//
// 真值(T3): truth = pkg_app_map[pkg]; 包名不在表里记 "pkg:"+pkg, 这样仍能统计
// 「这个包从来没被认出来」。
package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// dpiEvalCacheTTL 接口不带 refresh 时, 缓存结果多久内直接复用。
	dpiEvalCacheTTL = 10 * time.Minute
	// dpiEvalTopN 「最常认错」「最常认不出」各取前几条。
	dpiEvalTopN = 10
	// dpiEvalMaxSamples 单次评估最多读多少条样本(防极端大文件把内存吃满)。
	dpiEvalMaxSamples = 200000
	// labelSamplesMinUID 系统 / 内核 UID 下限, 与 T1 dpid 侧一致(评估兜底再滤一次)。
	dpiEvalMinUID = 10000
)

// ─── 样本 / 结果 结构 ────────────────────────────────────────────────

// evalSample 对应 T1 落盘的一行(字段名与 output.LabelSample 一致)。
type evalSample struct {
	Ts     int64  `json:"ts"`
	Pkg    string `json:"pkg"`
	UID    int    `json:"uid"`
	SNI    string `json:"sni"`
	JA4    string `json:"ja4"`
	ALPN   string `json:"alpn"`
	DPort  int    `json:"dport"`
	RIP    string `json:"rip"`
	RuleID string `json:"rule_id"`
}

// dpiEvalMethod 单一方法的指标。accuracy_na 为真时前端显示「—」(见 owner)。
type dpiEvalMethod struct {
	Samples    int     `json:"samples"`
	Predicted  int     `json:"predicted"`
	Correct    int     `json:"correct"`
	Judged     int     `json:"judged"` // v5.25: 有标准答案(包名在对照表里)且有预测的样本, 准确率的分母
	Coverage   float64 `json:"coverage"`
	Accuracy   float64 `json:"accuracy"`
	AccuracyNA bool    `json:"accuracy_na,omitempty"`
}

// dpiEvalByApp 单个真值应用的汇总(combined 口径)。
type dpiEvalByApp struct {
	Truth      string  `json:"truth"`
	Name       string  `json:"name"`
	Samples    int     `json:"samples"`
	Coverage   float64 `json:"coverage"`
	Accuracy   float64 `json:"accuracy"`
	AccuracyNA bool    `json:"accuracy_na,omitempty"` // 没有标准答案(包名不在对照表), 只算覆盖率
}

// dpiEvalWrong 最常认错: 真值被认成 pred 的次数。
type dpiEvalWrong struct {
	Truth    string `json:"truth"`
	Name     string `json:"name"` // 真值的显示名`
	Pred     string `json:"pred"`
	PredName string `json:"pred_name"`
	N        int    `json:"n"`
}

// dpiEvalUnknown 最常认不出: 真值 + 样本数 + 最常见的 3 个 SNI。
type dpiEvalUnknown struct {
	Truth string   `json:"truth"`
	Name  string   `json:"name"`
	N     int      `json:"n"`
	SNIs  []string `json:"snis"`
}

// dpiEvalResult 就是 GET /api/dpi_eval 的返回体, 也是 run/dpi_eval.json 的内容。
type dpiEvalResult struct {
	OK            bool                     `json:"ok"`
	GeneratedAt   int64                    `json:"generated_at"`
	Days          int                      `json:"days"`
	Enabled       bool                     `json:"enabled"`
	Samples       int                      `json:"samples"`
	Apps          int                      `json:"apps"`
	Capped        bool                     `json:"capped"`
	SkippedSystem int                      `json:"skipped_system"`
	SDKSamples    int                      `json:"sdk_samples"`
	Unlabeled     int                      `json:"unlabeled"` // v5.25: 包名不在对照表(多为系统应用)的样本, 只算覆盖率不算准确率 // 规则库认成广告 / SDK / CDN 类的样本(不计入规则预测)
	Methods       map[string]dpiEvalMethod `json:"methods"`
	ByApp         []dpiEvalByApp           `json:"by_app"`
	TopWrong      []dpiEvalWrong           `json:"top_wrong"`
	TopUnknown    []dpiEvalUnknown         `json:"top_unknown"`
	FGTruth       selfFGSummary            `json:"fg_truth"`
	Note          string                   `json:"note"`
}

func emptyEvalResult(days int, enabled bool, note string, now time.Time) dpiEvalResult {
	return dpiEvalResult{
		OK: true, GeneratedAt: now.Unix(), Days: days, Enabled: enabled,
		Methods:    map[string]dpiEvalMethod{},
		ByApp:      []dpiEvalByApp{},
		TopWrong:   []dpiEvalWrong{},
		TopUnknown: []dpiEvalUnknown{},
		FGTruth:    selfFGSummary{Source: "none"},
		Note:       note,
	}
}

// ─── 对照表 / 名称表 加载 ────────────────────────────────────────────

// pkgAppMap 读 data/pkg_app_map.json(T3 生成), 返回 包名→应用id。
// 文件缺失 / 损坏返回空 map(不 panic), 此时所有真值都退化成 "pkg:"+pkg。
func pkgAppMap(hncDir string) map[string]string {
	b, err := os.ReadFile(filepath.Join(hncDir, "data", "pkg_app_map.json"))
	if err != nil || len(b) > 4<<20 {
		return map[string]string{}
	}
	var f struct {
		Schema int               `json:"schema"`
		Map    map[string]string `json:"map"`
	}
	if json.Unmarshal(b, &f) != nil || f.Map == nil {
		return map[string]string{}
	}
	return f.Map
}

// ruleNameMap 读 data/dpi_rules.d/*.json(退化时再读 dpi_rules.json),
// 返回 规则id→中文应用名, 只用于展示(top_wrong 的 pred_name / by_app 的 name)。
// 评估只读, 绝不改规则库。
func ruleNameMap(hncDir string) map[string]string {
	names, _ := ruleMeta(hncDir)
	return names
}

// ruleMeta 同时返回 规则id→名字 与「广告 / 统计 SDK / CDN 等隐藏类」规则集合。
// 隐藏类规则认出的是第三方 SDK / 基础设施, 不是「这个连接属于哪个 App」——
// 抖音里的广告 SDK 连接被认成「穿山甲」并不是认错, 评估时不算这类预测。
func ruleMeta(hncDir string) (map[string]string, map[string]bool) {
	out := map[string]string{}
	hidden := map[string]bool{}
	add := func(b []byte) {
		var f struct {
			Rules []struct {
				ID       string `json:"id"`
				App      string `json:"app"`
				Category string `json:"category"`
			} `json:"rules"`
		}
		if json.Unmarshal(b, &f) != nil {
			return
		}
		for _, r := range f.Rules {
			if r.ID != "" && r.App != "" {
				if _, ok := out[r.ID]; !ok {
					out[r.ID] = r.App
					if appTier(r.Category) != tierApp {
						hidden[r.ID] = true
					}
				}
			}
		}
	}
	// v5.25: dpid 运行时读的是 etc/dpi_rules.d(+ etc/dpi_rules.json), data/ 下是出厂副本。
	// 旧版只读 data/, 真机上读不到 → 名字全显示成 ID、广告/系统类没被排除(准确率 0%)。
	for _, dir := range []string{filepath.Join(hncDir, "etc", "dpi_rules.d"), filepath.Join(hncDir, "data", "dpi_rules.d")} {
		if entries, err := os.ReadDir(dir); err == nil {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
					names = append(names, e.Name())
				}
			}
			sort.Strings(names)
			for _, n := range names {
				if b, err := os.ReadFile(filepath.Join(dir, n)); err == nil {
					add(b)
				}
			}
		}
	}
	for _, f := range []string{filepath.Join(hncDir, "etc", "dpi_rules.json"), filepath.Join(hncDir, "data", "dpi_rules.json")} {
		if b, err := os.ReadFile(f); err == nil {
			add(b)
		}
	}
	return out, hidden
}

// ─── 预测 ────────────────────────────────────────────────────────────

// fpPredict 查指纹学习表得到 fp 预测(空串=无预测)。
// 直接在 fpStore 上加锁读, 不改指纹逻辑本身。
func fpPredict(hncDir, ja4, alpn string, dport int, now time.Time) (id, name string) {
	if ja4 == "" {
		return "", ""
	}
	st := fpFor(hncDir)
	key := fpKeyOf(ja4, alpn, fpPortClass(dport))
	st.mu.Lock()
	st.loadLocked()
	e := st.m[key]
	var v fpVerdict
	if e != nil {
		v = e.verdict(now.Unix())
	}
	st.mu.Unlock()
	if v.Usable && !v.Generic && v.Top != "" && v.Top != fpOtherApp {
		return v.Top, v.TopName
	}
	return "", ""
}

// userPredict combined 的第一优先级: 用户纠正(只读 fp_user_rules.go)。
// 顺序: 域名 > JA4 > IP(与现有识别优先级一致)。
func userPredict(sni, ja4, rip string, dport int, now time.Time) (id, name string) {
	if a, ok := dpiUserMatchName(sni); ok && a.ID != "" {
		return a.ID, a.Name
	}
	if r, ok := dpiUserMatchJA4(ja4); ok && r.AppID != "" {
		a := r.app()
		return a.ID, a.Name
	}
	if a, ok := dpiUserMatchIP(rip, dport, now); ok && a.ID != "" {
		return a.ID, a.Name
	}
	return "", ""
}

// ownerPredict IP 归属为 app 类时的伪应用(_org:<key>)。
func ownerPredict(rip string) (id, name string) {
	if a, ok := orgAppForIP(rip); ok && a.ID != "" {
		return a.ID, a.Name
	}
	return "", ""
}

// ─── 主计算 ──────────────────────────────────────────────────────────

// evalDPI 读最近 days 天的样本, 算四种方法的指标 + 按应用汇总 + top 榜。
// 纯函数式: 不写文件, 不改任何全局识别状态。
func evalDPI(hncDir string, days int, now time.Time) dpiEvalResult {
	enabled := selfFGEnabled(hncDir)
	if !enabled {
		return emptyEvalResult(days, false, "需要在设置里开启本机流量归因, 才会采集样本并评估", now)
	}

	pmap := pkgAppMap(hncDir)
	rnames, hiddenRules := ruleMeta(hncDir)
	names := map[string]string{} // 评估过程中动态收集的 预测id→显示名
	lookup := func(id string) string {
		if id == "" {
			return ""
		}
		if n, ok := names[id]; ok && n != "" {
			return n
		}
		if n, ok := rnames[id]; ok && n != "" {
			return n
		}
		if strings.HasPrefix(id, orgAppPrefix) {
			return id
		}
		if strings.HasPrefix(id, "pkg:") {
			return strings.TrimPrefix(id, "pkg:")
		}
		return id
	}

	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour).Unix()
	samples, capped, skippedSystem := loadEvalSamples(hncDir, days, cutoff, now)

	res := emptyEvalResult(days, true, "", now)
	res.SkippedSystem = skippedSystem + labelStatsSkippedSystem(hncDir)
	res.Capped = capped
	res.FGTruth = summarizeSelfFG(hncDir, now)

	methods := []string{"rule", "fp", "owner", "combined"}
	stat := map[string]*dpiEvalMethod{}
	for _, m := range methods {
		stat[m] = &dpiEvalMethod{Samples: len(samples)}
	}

	// 按真值汇总
	type appAgg struct {
		n, predicted, judged, correct int
		sniCount                      map[string]int
	}
	byTruth := map[string]*appAgg{}
	// top_wrong: (truth|pred) → n
	type wpair struct{ truth, pred string }
	wrongN := map[wpair]int{}

	res.Samples = len(samples)
	ownerAccuracyNA := false

	for _, s := range samples {
		truth := pmap[s.Pkg]
		labeled := truth != ""
		if !labeled {
			// 没有标准答案(系统应用 / 未登记的包): 认成什么都无法判对错, 只算覆盖率。
			// v5.24 把它们一律算错, 真机上系统应用一多准确率就成了 0%。
			truth = "pkg:" + s.Pkg
			res.Unlabeled++
		}

		// 四种预测
		ruleID, ruleName := s.RuleID, ""
		if hiddenRules[ruleID] {
			res.SDKSamples++ // 认出的是广告 / SDK / CDN, 不代表 App 本身
			ruleID = ""
		}
		if ruleID != "" {
			ruleName = rnames[ruleID]
			if ruleName == "" {
				ruleName = lookup(ruleID)
			}
			names[ruleID] = ruleName
		}
		fpID, fpName := fpPredict(hncDir, s.JA4, s.ALPN, s.DPort, now)
		if fpID != "" {
			names[fpID] = fpName
		}
		ownID, ownName := ownerPredict(s.RIP)
		if ownID != "" {
			names[ownID] = ownName
		}
		// combined: 用户纠正 > 规则 > 指纹
		combID, combName := userPredict(s.SNI, s.JA4, s.RIP, s.DPort, now)
		if combID != "" {
			names[combID] = combName
		} else if ruleID != "" {
			combID, combName = ruleID, ruleName
		} else if fpID != "" {
			combID, combName = fpID, fpName
		}

		preds := map[string]string{"rule": ruleID, "fp": fpID, "owner": ownID, "combined": combID}
		for _, m := range methods {
			st := stat[m]
			if preds[m] == "" {
				continue
			}
			st.Predicted++
			if m == "owner" {
				// owner 只算覆盖率: 真值是应用, 预测是公司, 无法可靠比较(§8 降级)。
				ownerAccuracyNA = true
				continue
			}
			if !labeled {
				continue
			}
			st.Judged++
			if preds[m] == truth {
				st.Correct++
			}
		}

		// by_app(combined 口径)
		ag := byTruth[truth]
		if ag == nil {
			ag = &appAgg{sniCount: map[string]int{}}
			byTruth[truth] = ag
		}
		ag.n++
		if s.SNI != "" {
			ag.sniCount[s.SNI]++
		}
		if combID != "" {
			ag.predicted++
			if labeled {
				ag.judged++
				if combID == truth {
					ag.correct++
				} else {
					wrongN[wpair{truth, combID}]++
				}
			}
		}
	}

	// 指标定型
	res.Methods = map[string]dpiEvalMethod{}
	for _, m := range methods {
		st := *stat[m]
		st.Coverage = ratio(st.Predicted, st.Samples)
		st.Accuracy = ratio(st.Correct, st.Judged)
		if m == "owner" && ownerAccuracyNA {
			st.AccuracyNA = true
			st.Accuracy = 0
			st.Correct = 0
		}
		res.Methods[m] = st
	}

	// by_app 列表
	res.Apps = len(byTruth)
	for truth, ag := range byTruth {
		res.ByApp = append(res.ByApp, dpiEvalByApp{
			Truth:      truth,
			Name:       lookup(truth),
			Samples:    ag.n,
			Coverage:   ratio(ag.predicted, ag.n),
			Accuracy:   ratio(ag.correct, ag.judged),
			AccuracyNA: strings.HasPrefix(truth, "pkg:"),
		})
	}
	sort.Slice(res.ByApp, func(i, j int) bool {
		if res.ByApp[i].Samples != res.ByApp[j].Samples {
			return res.ByApp[i].Samples > res.ByApp[j].Samples
		}
		return res.ByApp[i].Truth < res.ByApp[j].Truth
	})

	// top_wrong
	type wkv struct {
		p wpair
		n int
	}
	wl := make([]wkv, 0, len(wrongN))
	for p, n := range wrongN {
		wl = append(wl, wkv{p, n})
	}
	sort.Slice(wl, func(i, j int) bool {
		if wl[i].n != wl[j].n {
			return wl[i].n > wl[j].n
		}
		if wl[i].p.truth != wl[j].p.truth {
			return wl[i].p.truth < wl[j].p.truth
		}
		return wl[i].p.pred < wl[j].p.pred
	})
	for i := 0; i < len(wl) && i < dpiEvalTopN; i++ {
		res.TopWrong = append(res.TopWrong, dpiEvalWrong{
			Truth: wl[i].p.truth, Name: lookup(wl[i].p.truth), Pred: wl[i].p.pred,
			PredName: lookup(wl[i].p.pred), N: wl[i].n,
		})
	}

	// top_unknown: combined 认不出的真值, 按样本数降序
	ul := make([]dpiEvalUnknown, 0, len(byTruth))
	for truth, ag := range byTruth {
		if ag.predicted > 0 {
			continue // 只要能认出一部分就不算「认不出」; 这里统计从没被认出的
		}
		snis := topSNIs(ag.sniCount, 3)
		ul = append(ul, dpiEvalUnknown{Truth: truth, Name: lookup(truth), N: ag.n, SNIs: snis})
	}
	sort.Slice(ul, func(i, j int) bool {
		if ul[i].N != ul[j].N {
			return ul[i].N > ul[j].N
		}
		return ul[i].Truth < ul[j].Truth
	})
	if len(ul) > dpiEvalTopN {
		ul = ul[:dpiEvalTopN]
	}
	res.TopUnknown = ul

	if ownerAccuracyNA {
		res.Note = "IP 归属(owner)只统计覆盖率: 真值是具体应用, owner 只能认出是哪家公司, 两者无法可靠对应, 故不算准确率。"
	}
	if res.Unlabeled > 0 {
		if res.Note != "" {
			res.Note += " "
		}
		res.Note += strconv.Itoa(res.Unlabeled) + " 条样本来自没有标准答案的应用(多为系统应用, 包名不在对照表里), 只算覆盖率, 不算准确率。"
	}
	if res.SDKSamples > 0 {
		if res.Note != "" {
			res.Note += " "
		}
		res.Note += "规则库认成广告 / 统计 SDK / CDN 的 " + strconv.Itoa(res.SDKSamples) + " 条样本不算规则预测(那是第三方服务, 不代表 App 本身)。"
	}
	return res
}

// labelStatsSkippedSystem 读 dpid 写的 run/label_samples.stats.json(T1 计数快照)。
// 系统 UID 在采集端就被跳过、不会进样本文件, 只能从这里拿到数量。读不到返回 0。
func labelStatsSkippedSystem(hncDir string) int {
	b, err := os.ReadFile(filepath.Join(hncDir, "run", "label_samples.stats.json"))
	if err != nil || len(b) > 64<<10 {
		return 0
	}
	var st struct {
		SkippedSystem int `json:"skipped_system"`
	}
	if json.Unmarshal(b, &st) != nil || st.SkippedSystem < 0 {
		return 0
	}
	return st.SkippedSystem
}

// ratio 安全除法 + 保留两位(与 traffic_ident.go 的 round2 同风格)。
func ratio(num, den int) float64 {
	if den <= 0 {
		return 0
	}
	return round2(float64(num) / float64(den))
}

func topSNIs(m map[string]int, n int) []string {
	type kv struct {
		s string
		c int
	}
	l := make([]kv, 0, len(m))
	for s, c := range m {
		l = append(l, kv{s, c})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].c != l[j].c {
			return l[i].c > l[j].c
		}
		return l[i].s < l[j].s
	})
	out := make([]string, 0, n)
	for i := 0; i < len(l) && i < n; i++ {
		out = append(out, l[i].s)
	}
	return out
}

// loadEvalSamples 读最近 days 天的 label_samples.*.jsonl, 返回窗口内样本 +
// 是否有 .capped 标记 + 因系统 UID 被跳过的条数。
func loadEvalSamples(hncDir string, days int, cutoff int64, now time.Time) ([]evalSample, bool, int) {
	runDir := filepath.Join(hncDir, "run")
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return nil, false, 0
	}
	// 收集窗口内的日期(YYYYMMDD 字符串比较即可, 定长)。
	daySet := map[string]bool{}
	for d := 0; d < days; d++ {
		daySet[now.AddDate(0, 0, -d).Local().Format("20060102")] = true
	}
	capped := false
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "label_samples.") {
			continue
		}
		if strings.HasSuffix(name, ".capped") {
			day := strings.TrimSuffix(strings.TrimPrefix(name, "label_samples."), ".capped")
			if daySet[day] {
				capped = true
			}
			continue
		}
		if !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, "label_samples."), ".jsonl")
		if daySet[day] {
			files = append(files, filepath.Join(runDir, name))
		}
	}
	sort.Strings(files)

	var out []evalSample
	skippedSystem := 0
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 8*1024), 64*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var s evalSample
			if json.Unmarshal([]byte(line), &s) != nil {
				continue
			}
			if s.Ts < cutoff {
				continue
			}
			if s.UID < dpiEvalMinUID {
				skippedSystem++ // 兜底: 系统 / 内核流量不参与评估
				continue
			}
			if s.Pkg == "" {
				continue
			}
			out = append(out, s)
			if len(out) >= dpiEvalMaxSamples {
				f.Close()
				return out, capped, skippedSystem
			}
		}
		f.Close()
	}
	return out, capped, skippedSystem
}

// ─── 缓存 / 文件 / 循环 ──────────────────────────────────────────────

func dpiEvalPath(hncDir string) string { return filepath.Join(hncDir, "run", "dpi_eval.json") }

// dpiEvalCache 保存最近一次计算结果, 供不带 refresh 的请求复用。
var dpiEvalCache atomic.Value // dpiEvalResult

// evalCached 返回缓存结果(若 days 匹配且未过期); 否则返回 ok=false。
func evalCached(days int, now time.Time) (dpiEvalResult, bool) {
	v := dpiEvalCache.Load()
	if v == nil {
		return dpiEvalResult{}, false
	}
	r, _ := v.(dpiEvalResult)
	if r.Days != days || r.GeneratedAt == 0 {
		return dpiEvalResult{}, false
	}
	if now.Unix()-r.GeneratedAt > int64(dpiEvalCacheTTL/time.Second) {
		return dpiEvalResult{}, false
	}
	return r, true
}

// evalCompute 计算并缓存 + 落盘 run/dpi_eval.json。
func evalCompute(hncDir string, days int, now time.Time) dpiEvalResult {
	r := evalDPI(hncDir, days, now)
	dpiEvalCache.Store(r)
	if b, err := json.Marshal(r); err == nil {
		_ = writeFileAtomic(dpiEvalPath(hncDir), b)
	}
	return r
}

// evalGet 接口入口: 校验 days, 决定用缓存还是重算。
func evalGet(hncDir string, days int, refresh bool, now time.Time) dpiEvalResult {
	// 开关状态变了(刚开启 / 关掉本机流量归因), 缓存作废。
	if r, ok := evalCached(days, now); ok && r.Enabled != selfFGEnabled(hncDir) {
		refresh = true
	}
	if !refresh {
		if r, ok := evalCached(days, now); ok {
			return r
		}
		// 无内存缓存时尝试读磁盘缓存(进程刚重启)。
		if b, err := os.ReadFile(dpiEvalPath(hncDir)); err == nil {
			var r dpiEvalResult
			if json.Unmarshal(b, &r) == nil && r.Days == days &&
				now.Unix()-r.GeneratedAt <= int64(dpiEvalCacheTTL/time.Second) {
				dpiEvalCache.Store(r)
				return r
			}
		}
	}
	return evalCompute(hncDir, days, now)
}

// ─── HTTP ────────────────────────────────────────────────────────────

// apiDPIEval GET /api/dpi_eval[?days=1|7][&refresh=1]
func (s *server) apiDPIEval(w http.ResponseWriter, r *http.Request) {
	days := 1
	if d := r.URL.Query().Get("days"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || (n != 1 && n != 7) {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"ok": false, "error": "days must be 1 or 7",
			})
			return
		}
		days = n
	}
	refresh := r.URL.Query().Get("refresh") == "1"
	res := evalGet(s.hncDir, days, refresh, time.Now())
	res.OK = true
	writeJSON(w, http.StatusOK, res)
}

// actionDPIEvalClear 删除所有 label_samples.* / self_fg.* / dpi_eval.json(§T4)。
func actionDPIEvalClear(hncDir string) actionResp {
	runDir := filepath.Join(hncDir, "run")
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return actionResp{OK: false, Error: "read run dir failed", Detail: err.Error()}
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		del := name == "dpi_eval.json" ||
			(strings.HasPrefix(name, "label_samples.") &&
				(strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".capped"))) ||
			(strings.HasPrefix(name, "self_fg.") && strings.HasSuffix(name, ".jsonl"))
		if !del {
			continue
		}
		if os.Remove(filepath.Join(runDir, name)) == nil {
			n++
		}
	}
	dpiEvalCache.Store(dpiEvalResult{}) // 清缓存, 下次请求重新算
	return actionResp{OK: true, Detail: "removed " + strconv.Itoa(n) + " file(s)"}
}
