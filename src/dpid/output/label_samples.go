// Package output - label_samples.go: v5.24 T1 本机带标签样本工厂。
//
// 干什么: 本机(self_capture)每看到一条 TLS / QUIC ClientHello, 就把
// 「这条连接真实的 App 包名(由 /proc/net 反查 UID 得到) + 这条连接的域名与指纹」
// 记成一行带标签样本, 存 run/label_samples.YYYYMMDD.jsonl。
// 样本就是「标准答案」: 包名是真值, SNI/JA4 是输入。httpd(v5.24 T4)拿它给
// 现有识别方法打分(覆盖率 / 准确率 / 最常认错的应用)。
//
// 本文件只采集, 不参与任何识别判定 —— 现有识别输出完全不变。
//
// 边界(见工作文档 §2):
//   - 只采本机自己(self_capture 回调)的流量, 不碰热点客户端设备。
//   - 只存 时间 / 包名 / uid / SNI / JA4 / ALPN / 端口 / 是否 QUIC / ECH /
//     Partial / 远端 IP + 规则库命中结果; 不存完整 URL、内容、Cookie。
//   - 样本只写本机 run/ 下, 7 天自动过期, 不上传。
//
// 并发与资源:
//   - 抓包回调里绝不阻塞: Observe 只做廉价过滤 + 非阻塞入队, channel 满就丢弃计数;
//     规则库查表(纯内存)也放在后台 goroutine 里, 回调侧一律不做。
//   - 落盘状态(去重表 / 当天文件 / 超限标记)由后台 goroutine(Run)独占, 因此
//     文件与这些字段不加锁; 只有对外的计数字段用 mu 保护, 供状态快照读取。
//   - 同一 (pkg, sni, ja4) 组合 labelDedupWindowSec 内只记一次。
//   - 单日文件超过 labelDailyCapBytes 后停止写入, 并留下 .capped 标记文件,
//     让评估结果能标出 capped:true。
//
// 时区: 文件按「本地日期」滚动, 用 tzlocal 取 Android 真实时区(见工作文档 §7.5)。
package output

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"hnc.io/dpid/tzlocal"
)

const (
	// 文件名前缀 / 后缀: run/label_samples.20261002.jsonl(+ 同日 .capped)。
	labelSamplesPrefix   = "label_samples."
	labelSamplesJSONLEXT = ".jsonl"
	labelSamplesCapEXT   = ".capped"

	labelSamplesChanCap      = 1024               // 队列上限, 满了直接丢
	labelSamplesDedupWindow  = 600 * time.Second  // 同一 (pkg,sni,ja4) 10 分钟内只记一次
	labelSamplesDedupMax     = 50000              // 去重表上限, 超过整体清空(内存有界)
	labelSamplesDailyCapByte = int64(20 << 20)    // 单日 20 MB
	labelSamplesRetentionDay = 7                  // 保留 7 天
	labelSamplesMinUID       = 10000              // 低于此 UID 视为系统, 跳过
	labelSamplesDateLayout   = "20060102"         // 本地日期(文件名用)
	labelSamplesFileMode     = os.FileMode(0o640) // run/ 下私有, 不放全局可读
	labelSamplesLineMaxByte  = 4096               // 单样本上限保护(域名 + JA4 远小于此)
	labelSamplesStatsFile    = "label_samples.stats.json"
	labelSamplesStatsEvery   = 60 * time.Second // 计数快照落盘间隔(httpd 评估页读它显示跳过 / 丢弃数)
)

// LabelSampleInput 是调用方(抓包回调)提供的一条原始观测。
// 字段与 capture.Event / TLSInfo 的对应关系由调用方负责, 本包不 import capture
// (capture 已 import output, 反向依赖会成环)。
type LabelSampleInput struct {
	Time    time.Time
	UID     int
	Pkg     string
	SNI     string
	JA4     string
	ALPNs   []string // 取第一个, 没有则样本省略 alpn 字段
	DPort   int
	QUIC    bool
	QTP     string // v5.27 T2: QUIC 传输参数指纹(非 QUIC 为空)
	ECH     bool
	Partial bool
	RIP     string
}

// LabelSample 是落到 jsonl 里的一行。字段名固定(工作文档 T1), 不要改。
type LabelSample struct {
	Ts       int64  `json:"ts"`
	Pkg      string `json:"pkg"`
	UID      int    `json:"uid"`
	SNI      string `json:"sni"`
	JA4      string `json:"ja4"`
	ALPN     string `json:"alpn,omitempty"`
	DPort    int    `json:"dport"`
	QUIC     bool   `json:"quic"`
	ECH      bool   `json:"ech"`
	Partial  bool   `json:"partial"`
	RIP      string `json:"rip"`
	RuleID   string `json:"rule_id,omitempty"`
	RuleName string `json:"rule_name,omitempty"`
	// v5.27 T2: 可选字段, 旧行没有也照常解析。
	QTP string `json:"qtp,omitempty"`
}

// LabelSamplesStats 是写入器的计数快照(评估页 / 日志用)。
type LabelSamplesStats struct {
	Written       int64 // 实际落盘条数
	Deduped       int64 // 去重窗口内被合并的条数
	Dropped       int64 // 队列满被丢弃的条数
	SkippedSystem int64 // uid < 10000 被跳过的条数
	SkippedEmpty  int64 // pkg 或 SNI 为空被跳过的条数
	Capped        bool  // 当天是否已触到 20 MB 上限
}

// LabelSamplesWriter 带缓冲的本机样本写入器。零值不可用, 用 NewLabelSamplesWriter。
type LabelSamplesWriter struct {
	dir string
	ch  chan LabelSample

	// classify 可替换(单测); 默认用规则库后缀匹配, 在写入时就把命中结果记进样本,
	// 这样 httpd 端不必再加载 dpid 的规则库。
	classify func(host string) (l3Rule, bool)

	// loc 为 nil 时取 tzlocal.Location()(Android 真实时区)。
	loc      *time.Location
	now      func() time.Time
	dedupWin time.Duration
	// dailyCap 单日字节上限, 默认 labelSamplesDailyCapByte(单测用小值)。
	dailyCap int64

	// 以下字段只由 Run goroutine(或单测里同步调用 handle)访问。
	dedup   map[string]int64
	curDay  string
	curSize int64
	capped  bool
	f       *os.File
	swept   map[string]bool // 已做过过期清理的日期, 避免同一天反复扫盘
	started int64           // Run 启动时刻(计数快照的 since)

	mu    sync.Mutex
	stats LabelSamplesStats
}

// NewLabelSamplesWriter 返回一个未启动的写入器。dir(即 cfg.RunDir)不存在也不报错:
// 构造时不碰文件系统, 只有真的写样本时才建文件 —— 本机抓包关着就不会产生任何样本文件。
func NewLabelSamplesWriter(dir string) *LabelSamplesWriter {
	return &LabelSamplesWriter{
		dir:      dir,
		ch:       make(chan LabelSample, labelSamplesChanCap),
		classify: classifyHost,
		now:      time.Now,
		dedupWin: labelSamplesDedupWindow,
		dailyCap: labelSamplesDailyCapByte,
		dedup:    make(map[string]int64),
		swept:    make(map[string]bool),
	}
}

// Observe 由抓包回调调用: 只做廉价过滤 + 非阻塞入队, 任何情况下都不等 IO、
// 不查规则库(那条表放到落盘 goroutine 里算)、不拿文件锁。
// w 为 nil(功能未启用)时静默返回。
func (w *LabelSamplesWriter) Observe(in LabelSampleInput) {
	if w == nil {
		return
	}
	switch {
	case in.Pkg == "" || in.SNI == "":
		w.bump(func(s *LabelSamplesStats) { s.SkippedEmpty++ })
		return
	case in.UID < labelSamplesMinUID:
		// 系统 UID 的流量不是「某个 App 的标准答案」, 只计数不采集。
		w.bump(func(s *LabelSamplesStats) { s.SkippedSystem++ })
		return
	}
	ts := in.Time.Unix()
	if in.Time.IsZero() {
		ts = w.now().Unix()
	}
	s := LabelSample{
		Ts:      ts,
		Pkg:     in.Pkg,
		UID:     in.UID,
		SNI:     in.SNI,
		JA4:     in.JA4,
		DPort:   in.DPort,
		QUIC:    in.QUIC,
		ECH:     in.ECH,
		Partial: in.Partial,
		RIP:     in.RIP,
	}
	if n := len(in.ALPNs); n > 0 {
		s.ALPN = in.ALPNs[0]
	}
	if in.QUIC && ValidQTP(in.QTP) {
		s.QTP = in.QTP
	}
	select {
	case w.ch <- s:
	default:
		// 队列满(写盘落后 / 样本暴增) → 丢弃。宁可得不到样本, 也不拖慢抓包回调。
		w.bump(func(st *LabelSamplesStats) { st.Dropped++ })
	}
}

// Run 启动落盘循环, 直到 ctx 取消。返回时关闭文件句柄。
func (w *LabelSamplesWriter) Run(ctx context.Context) {
	// 启动即做一次过期清理: 进程可能停了一周以上, 重启后要先把旧样本删掉。
	now := w.now()
	w.started = now.Unix()
	w.sweepExpired(now)
	w.swept[w.dayOf(now)] = true
	tk := time.NewTicker(labelSamplesStatsEvery)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			w.closeFile()
			w.writeStats()
			return
		case <-tk.C:
			w.reopenIfRemoved()
			w.writeStats()
		case s := <-w.ch:
			w.handle(s)
		}
	}
}

// reopenIfRemoved 当天文件被外部删掉(WebUI「清除样本」)时关掉旧句柄, 下一条样本重新建文件;
// 否则会一直往已删除的文件里写, 样本直到换天前都看不见。
func (w *LabelSamplesWriter) reopenIfRemoved() {
	if w.f == nil || w.curDay == "" {
		return
	}
	if _, err := os.Stat(w.path(w.curDay, labelSamplesJSONLEXT)); os.IsNotExist(err) {
		w.closeFile()
		w.curSize = 0
		w.capped = false
		w.bump(func(st *LabelSamplesStats) { st.Capped = false })
	}
}

// labelSamplesStatsJSON 是 run/label_samples.stats.json 的内容(v5.24 T4 评估页读取)。
// 计数从本次写入器启动(since)起累计, dpid 重启或开关重开后归零。
type labelSamplesStatsJSON struct {
	Ts            int64  `json:"ts"`
	Since         int64  `json:"since"`
	Day           string `json:"day,omitempty"`
	Written       int64  `json:"written"`
	Deduped       int64  `json:"deduped"`
	Dropped       int64  `json:"dropped"`
	SkippedSystem int64  `json:"skipped_system"`
	SkippedEmpty  int64  `json:"skipped_empty"`
	Capped        bool   `json:"capped"`
}

// writeStats 把计数快照原子写到 run/label_samples.stats.json; 目录不在就算了。
func (w *LabelSamplesWriter) writeStats() {
	st := w.Stats()
	b, err := json.Marshal(labelSamplesStatsJSON{Ts: w.now().Unix(), Since: w.started, Day: w.curDay,
		Written: st.Written, Deduped: st.Deduped, Dropped: st.Dropped,
		SkippedSystem: st.SkippedSystem, SkippedEmpty: st.SkippedEmpty, Capped: st.Capped})
	if err != nil {
		return
	}
	if err := atomicWrite(filepath.Join(w.dir, labelSamplesStatsFile), b, labelSamplesFileMode); err != nil && !os.IsNotExist(err) {
		log.Printf("label-samples: write stats: %v", err)
	}
}

// Stats 返回计数快照(可在任意 goroutine 调用)。
func (w *LabelSamplesWriter) Stats() LabelSamplesStats {
	if w == nil {
		return LabelSamplesStats{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stats
}

// handle 处理一条样本: 日滚动 → 超限判定 → 去重 → 追加落盘。
// 返回是否真的写了这一行。只由 Run goroutine / 单测同步调用。
func (w *LabelSamplesWriter) handle(s LabelSample) bool {
	day := w.dayOf(time.Unix(s.Ts, 0))
	if day != w.curDay {
		// 换天: 关掉旧句柄, 清理 7 天前的样本, 新的一天重置超限状态。
		w.curDay = day
		w.closeFile()
		w.capped = false
		w.bump(func(st *LabelSamplesStats) { st.Capped = false })
		if !w.swept[day] {
			w.sweepExpired(time.Unix(s.Ts, 0))
			w.swept[day] = true
		}
	}
	if w.capped {
		return false
	}

	key := s.Pkg + "|" + s.SNI + "|" + s.JA4
	if last, ok := w.dedup[key]; ok && s.Ts-last < int64(w.dedupWin.Seconds()) {
		w.bump(func(st *LabelSamplesStats) { st.Deduped++ })
		return false
	}
	if len(w.dedup) >= labelSamplesDedupMax {
		// 表太大(长期跑 + 域名极多)就整体清空: 最坏后果是短时间内重复记几条样本,
		// 换来的是内存有界。
		w.dedup = make(map[string]int64)
	}
	w.dedup[key] = s.Ts

	// 写入时算规则命中(纯内存查表), 这样 httpd 端不必再加载 dpid 的规则库。
	// 放在去重之后, 被合并掉的重复样本不白算。
	if s.RuleID == "" {
		if r, ok := w.classify(s.SNI); ok && r.ID != "" {
			s.RuleID = r.ID
			s.RuleName = r.Name
		}
	}

	b, err := json.Marshal(s)
	if err != nil {
		return false
	}
	if len(b) > labelSamplesLineMaxByte {
		// 异常长(超大 SNI / 畸形 JA4)不入库, 免得把当天配额一次吃掉。
		return false
	}
	b = append(b, '\n')

	f, size, err := w.openCurrent(day)
	if err != nil {
		log.Printf("label-samples: open %s: %v", w.path(day, labelSamplesJSONLEXT), err)
		return false
	}
	if size+int64(len(b)) > w.capBytes() {
		w.markCapped(day)
		return false
	}
	n, err := f.Write(b)
	if err != nil {
		log.Printf("label-samples: write: %v", err)
		w.closeFile() // 下个样本重开(句柄失效 / 文件被外部删除时自愈)
		return false
	}
	w.curSize += int64(n)
	w.bump(func(st *LabelSamplesStats) { st.Written++ })
	return true
}

// openCurrent 打开(或复用)当天文件, 返回句柄与当前已有字节数。
// 首次打开时用 O_APPEND 并 stat 取真实长度, 保证进程重启后配额判定连续。
func (w *LabelSamplesWriter) openCurrent(day string) (*os.File, int64, error) {
	if w.f != nil {
		return w.f, w.curSize, nil
	}
	path := w.path(day, labelSamplesJSONLEXT)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, labelSamplesFileMode)
	if err != nil {
		return nil, 0, err
	}
	size := int64(0)
	if st, err := f.Stat(); err == nil {
		size = st.Size()
	}
	w.f = f
	w.curSize = size
	if size >= w.capBytes() {
		// 重启前就已经写满(或磁盘上留着一个超限的旧文件) → 直接进 capped 状态。
		w.markCapped(day)
		return w.f, w.curSize, nil
	}
	return f, size, nil
}

// markCapped 停止当天写入并留下 .capped 标记文件(httpd 评估据此标 capped:true)。
func (w *LabelSamplesWriter) markCapped(day string) {
	if w.capped {
		return
	}
	capBytes := w.capBytes()
	w.capped = true
	w.bump(func(st *LabelSamplesStats) { st.Capped = true })
	written := w.Stats().Written
	log.Printf("label-samples: %s 达单日上限(%d bytes), 停止当天写入", day, capBytes)
	// 已存在就不重复写(O_EXCL); 内容只作人排障用。
	if f, err := os.OpenFile(w.path(day, labelSamplesCapEXT),
		os.O_CREATE|os.O_EXCL|os.O_WRONLY, labelSamplesFileMode); err == nil {
		fmt.Fprintf(f, "date=%s cap_bytes=%d written=%d\n", day, capBytes, written)
		f.Close()
	}
}

func (w *LabelSamplesWriter) closeFile() {
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
}

// dayOf 把时刻换算成「本地日期」键。
func (w *LabelSamplesWriter) dayOf(t time.Time) string {
	loc := w.loc
	if loc == nil {
		loc = tzlocal.Location()
	}
	return t.In(loc).Format(labelSamplesDateLayout)
}

func (w *LabelSamplesWriter) path(day, ext string) string {
	return filepath.Join(w.dir, labelSamplesPrefix+day+ext)
}

// sweepExpired 删除 retention 天前的样本文件(jsonl 与配套 capped)。
// 目录读不到 / 删除失败只记日志, 不影响采集。
func (w *LabelSamplesWriter) sweepExpired(now time.Time) {
	loc := w.loc
	if loc == nil {
		loc = tzlocal.Location()
	}
	cutoff := now.In(loc).AddDate(0, 0, -labelSamplesRetentionDay).Format(labelSamplesDateLayout)
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, labelSamplesPrefix) {
			continue
		}
		rest := strings.TrimPrefix(name, labelSamplesPrefix)
		day, ext, ok := strings.Cut(rest, ".")
		if !ok || (ext != strings.TrimPrefix(labelSamplesJSONLEXT, ".") && ext != strings.TrimPrefix(labelSamplesCapEXT, ".")) {
			continue
		}
		if len(day) != len(labelSamplesDateLayout) || day >= cutoff {
			continue
		}
		if err := os.Remove(filepath.Join(w.dir, name)); err != nil {
			log.Printf("label-samples: 清理过期样本 %s: %v", name, err)
			continue
		}
		log.Printf("label-samples: 已删除过期样本 %s", name)
	}
}

// capBytes 返回当前生效的单日字节上限。
func (w *LabelSamplesWriter) capBytes() int64 {
	if w.dailyCap > 0 {
		return w.dailyCap
	}
	return labelSamplesDailyCapByte
}

func (w *LabelSamplesWriter) bump(f func(*LabelSamplesStats)) {
	if w == nil {
		return
	}
	w.mu.Lock()
	f(&w.stats)
	w.mu.Unlock()
}
