package output

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 单测统一用 UTC 时区(w.loc = time.UTC), 日期滚动不依赖跑测试机器的 TZ。
var (
	lsvDay1 = time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	lsvDay2 = time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
)

func lsvSample(ts time.Time, pkg, sni, ja4 string) LabelSample {
	return LabelSample{Ts: ts.Unix(), Pkg: pkg, UID: 10234, SNI: sni, JA4: ja4,
		DPort: 443, RIP: "203.107.13.2"}
}

func lsvInput(ts time.Time, uid int, pkg, sni, ja4 string) LabelSampleInput {
	return LabelSampleInput{Time: ts, UID: uid, Pkg: pkg, SNI: sni, JA4: ja4,
		DPort: 443, RIP: "1.2.3.4"}
}

func lsvNew(t *testing.T) *LabelSamplesWriter {
	t.Helper()
	w := NewLabelSamplesWriter(t.TempDir())
	w.loc = time.UTC
	// 默认 classify 会去读真规则库(/data/local/hnc 下), 单测环境一律换可控桩。
	w.classify = func(string) (l3Rule, bool) { return l3Rule{}, false }
	t.Cleanup(w.closeFile)
	return w
}

func lsvLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(b) == 0 {
		return nil
	}
	out := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	return out
}

// 当天文件路径(测试拼路径用)。
func lsvPath(w *LabelSamplesWriter, day time.Time, ext string) string {
	return filepath.Join(w.dir, labelSamplesPrefix+w.dayOf(day)+ext)
}

// 去重: 同一 (pkg,sni,ja4) 在窗口内只写一条; 换 ja4 / 换 pkg / 超窗口都要写。
func TestLabelSamplesDedup(t *testing.T) {
	w := lsvNew(t)
	if !w.handle(lsvSample(lsvDay1, "com.x", "a.example.com", "j1")) {
		t.Fatal("第一条应写入")
	}
	if w.handle(lsvSample(lsvDay1.Add(30*time.Second), "com.x", "a.example.com", "j1")) {
		t.Error("窗口内重复不应写入")
	}
	if !w.handle(lsvSample(lsvDay1.Add(30*time.Second), "com.x", "a.example.com", "j2")) {
		t.Error("不同 ja4 应写入")
	}
	if !w.handle(lsvSample(lsvDay1.Add(30*time.Second), "com.y", "a.example.com", "j1")) {
		t.Error("不同 pkg 应写入")
	}
	if !w.handle(lsvSample(lsvDay1.Add(labelSamplesDedupWindow+time.Second), "com.x", "a.example.com", "j1")) {
		t.Error("超窗口后应重新写入")
	}
	if got := len(lsvLines(t, lsvPath(w, lsvDay1, labelSamplesJSONLEXT))); got != 4 {
		t.Errorf("行数 = %d, want 4", got)
	}
	if st := w.Stats(); st.Written != 4 || st.Deduped != 1 {
		t.Errorf("stats = %+v, want written=4 deduped=1", st)
	}
}

// 去重表到上限整体清空(内存有界), 清空后照常工作。
func TestLabelSamplesDedupMapBounded(t *testing.T) {
	w := lsvNew(t)
	for i := 0; i < labelSamplesDedupMax; i++ {
		w.dedup["k"+strconv.Itoa(i)] = lsvDay1.Unix()
	}
	if !w.handle(lsvSample(lsvDay1, "com.x", "a.example.com", "j1")) {
		t.Fatal("应写入")
	}
	if len(w.dedup) > labelSamplesDedupMax+1 {
		t.Errorf("去重表未清空: len=%d", len(w.dedup))
	}
}

// 跳过规则: pkg / SNI 为空、系统 UID 都不入库, 只计数。走完整 Observe→Run 链路。
func TestLabelSamplesSkips(t *testing.T) {
	w := lsvNew(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()

	w.Observe(lsvInput(lsvDay1, 10234, "", "a.example.com", "j1"))      // pkg 空
	w.Observe(lsvInput(lsvDay1, 10234, "com.x", "", "j1"))              // sni 空
	w.Observe(lsvInput(lsvDay1, 9999, "com.x", "a.example.com", "j2"))  // 系统 UID
	w.Observe(lsvInput(lsvDay1, 2000, "com.x", "a.example.com", "j3"))  // 系统 UID
	w.Observe(lsvInput(lsvDay1, 10234, "com.x", "a.example.com", "j4")) // 正常

	deadline := time.Now().Add(3 * time.Second)
	for w.Stats().Written != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	st := w.Stats()
	if st.Written != 1 {
		t.Errorf("Written = %d, want 1", st.Written)
	}
	if st.SkippedEmpty != 2 {
		t.Errorf("SkippedEmpty = %d, want 2", st.SkippedEmpty)
	}
	if st.SkippedSystem != 2 {
		t.Errorf("SkippedSystem = %d, want 2", st.SkippedSystem)
	}
	if len(lsvLines(t, lsvPath(w, lsvDay1, labelSamplesJSONLEXT))) != 1 {
		t.Error("当天文件应只有 1 行")
	}
}

// 日期滚动: 跨天写新文件, 旧文件内容不动。
func TestLabelSamplesDateRoll(t *testing.T) {
	w := lsvNew(t)
	if !w.handle(lsvSample(lsvDay1, "com.x", "a.example.com", "j1")) {
		t.Fatal("day1 应写入")
	}
	if !w.handle(lsvSample(lsvDay2, "com.x", "b.example.com", "j1")) {
		t.Fatal("day2 应写入")
	}
	if n := len(lsvLines(t, lsvPath(w, lsvDay1, labelSamplesJSONLEXT))); n != 1 {
		t.Errorf("day1 行数 = %d, want 1", n)
	}
	if n := len(lsvLines(t, lsvPath(w, lsvDay2, labelSamplesJSONLEXT))); n != 1 {
		t.Errorf("day2 行数 = %d, want 1", n)
	}
	if w.curDay != w.dayOf(lsvDay2) {
		t.Errorf("curDay = %s, want %s", w.curDay, w.dayOf(lsvDay2))
	}
}

// 本地日期滚动: 用 UTC+8 时区, UTC 16:30(本地次日 00:30)应算第二天。
func TestLabelSamplesLocalDateBoundary(t *testing.T) {
	w := lsvNew(t)
	w.loc = time.FixedZone("CST", 8*3600)
	utc := time.Date(2026, 10, 2, 16, 30, 0, 0, time.UTC) // 本地 2026-10-03 00:30
	if got := w.dayOf(utc); got != "20261003" {
		t.Errorf("dayOf = %s, want 20261003", got)
	}
}

// 过期删除: 只删样本前缀的 jsonl/capped 且日期早于 cutoff; 保留期内与无关文件不动。
func TestLabelSamplesExpireSweep(t *testing.T) {
	w := lsvNew(t)
	dir := w.dir
	mk := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x\n"), labelSamplesFileMode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := mk(labelSamplesPrefix + "20260920" + labelSamplesJSONLEXT)
	oldCap := mk(labelSamplesPrefix + "20260920" + labelSamplesCapEXT)
	keep := mk(labelSamplesPrefix + "20260929" + labelSamplesJSONLEXT)
	keepCap := mk(labelSamplesPrefix + "20260929" + labelSamplesCapEXT)
	today := mk(labelSamplesPrefix + "20261003" + labelSamplesJSONLEXT)
	junk := mk("dpi_state.json")                                        // 别人的文件, 绝不能碰
	nearmiss := mk("label_samples.tmp.1")                               // 前缀同名但非样本文件
	weird := mk(labelSamplesPrefix + "20260926" + labelSamplesJSONLEXT) // 恰好等于 cutoff → 保留

	w.sweepExpired(lsvDay2) // cutoff = 2026-09-26

	for _, p := range []string{old, oldCap} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s 应被删除", filepath.Base(p))
		}
	}
	for _, p := range []string{keep, keepCap, today, junk, nearmiss, weird} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s 不该被动: %v", filepath.Base(p), err)
		}
	}
}

// 超限停止: 超过单日上限后停写 + 留 capped 标记, 换天恢复。
// 用小上限(dailyCap)避免单测真的造 20 MB 文件。
func TestLabelSamplesDailyCap(t *testing.T) {
	w := lsvNew(t)
	w.dailyCap = 400 // 一条短样本约 152 字节, 容得下 2 条

	if !w.handle(lsvSample(lsvDay1, "com.x", "a1.example.com", "j1")) {
		t.Fatal("第一条应写入")
	}
	if !w.handle(lsvSample(lsvDay1.Add(time.Second), "com.x", "a2.example.com", "j2")) {
		t.Fatal("第二条仍在配额内")
	}
	// 配额应已耗尽 → 第三条被拒 + 标记 capped。
	if w.handle(lsvSample(lsvDay1.Add(2*time.Second), "com.x", "a3.example.com", "j3")) {
		t.Error("超限后不应再写")
	}
	if !w.capped {
		t.Error("capped 应为 true")
	}
	if st := w.Stats(); !st.Capped {
		t.Error("Stats().Capped 应为 true")
	}
	capMark := lsvPath(w, lsvDay1, labelSamplesCapEXT)
	if _, err := os.Stat(capMark); err != nil {
		t.Errorf("缺少 capped 标记文件: %v", err)
	}
	if n := len(lsvLines(t, lsvPath(w, lsvDay1, labelSamplesJSONLEXT))); n != 2 {
		t.Errorf("当天行数 = %d, want 2", n)
	}
	// 换天 → 恢复正常, capped 复位。
	if !w.handle(lsvSample(lsvDay2, "com.x", "b1.example.com", "j1")) {
		t.Error("换天后应恢复写入")
	}
	if w.capped || w.Stats().Capped {
		t.Error("换天后 capped 应复位")
	}
}

// 重启后配额判定连续: 磁盘上已有超限的当天文件 → 直接 capped, 不追加。
func TestLabelSamplesCapSurvivesRestart(t *testing.T) {
	w := lsvNew(t)
	w.dailyCap = 200
	path := lsvPath(w, lsvDay1, labelSamplesJSONLEXT)
	if err := os.WriteFile(path, make([]byte, 200), labelSamplesFileMode); err != nil {
		t.Fatal(err)
	}
	before := len(lsvLines(t, path))
	if w.handle(lsvSample(lsvDay1, "com.x", "a.example.com", "j1")) {
		t.Error("已满不应写入")
	}
	if !w.capped {
		t.Error("重启后应识别为 capped")
	}
	if len(lsvLines(t, path)) != before {
		t.Error("不应追加内容")
	}
}

// channel 满时 Observe 绝不阻塞(抓包回调的硬要求)。
func TestLabelSamplesObserveNeverBlocks(t *testing.T) {
	w := lsvNew(t) // 不启动 Run → 队列必然堆满

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < labelSamplesChanCap+500; i++ {
			// 每条换 SNI, 保证都进入队路径而不是被跳过。
			w.Observe(lsvInput(lsvDay1, 10234, "com.x", "h"+strconv.Itoa(i)+".example.com", "j"))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Observe 在队列满时阻塞了")
	}
	if st := w.Stats(); st.Dropped != 500 || len(w.ch) != labelSamplesChanCap {
		t.Errorf("dropped=%d queued=%d, want 500/%d", st.Dropped, len(w.ch), labelSamplesChanCap)
	}
}

// nil writer 必须安全(功能未启用时抓包回调仍会调用)。
func TestLabelSamplesNilWriterSafe(t *testing.T) {
	var w *LabelSamplesWriter
	w.Observe(lsvInput(lsvDay1, 10234, "com.x", "a.example.com", "j1"))
	if got := w.Stats(); got != (LabelSamplesStats{}) {
		t.Errorf("nil writer 不应有计数: %+v", got)
	}
}

// 样本格式: 字段名与文档一致; alpn 取第一个; 规则未命中时省略 rule_*;
// 不出现 URL / path / cookie 这类字段。
func TestLabelSamplesJSONFormat(t *testing.T) {
	w := lsvNew(t)
	w.classify = func(host string) (l3Rule, bool) {
		if host == "api.amemv.com" {
			return l3Rule{ID: "douyin", Name: "抖音"}, true
		}
		return l3Rule{}, false
	}
	w.Observe(LabelSampleInput{Time: lsvDay1, UID: 10234, Pkg: "com.ss.android.ugc.aweme",
		SNI: "api.amemv.com", JA4: "t13d1516h2_8daaf6152771_e5627efa2ab1",
		ALPNs: []string{"h2", "http/1.1"}, DPort: 443, RIP: "203.107.13.2"})
	w.Observe(LabelSampleInput{Time: lsvDay1, UID: 10235, Pkg: "com.unknown.app",
		SNI: "novalue.example.net", JA4: "q13d030000_000000000000", DPort: 443,
		QUIC: true, ECH: true, Partial: true, RIP: "142.250.0.1"})
	// 不启动 goroutine, 同步消费队列, 避免时序依赖。
	for {
		select {
		case s := <-w.ch:
			w.handle(s)
		default:
			goto drainDone
		}
	}
drainDone:
	lines := lsvLines(t, lsvPath(w, lsvDay1, labelSamplesJSONLEXT))
	if len(lines) != 2 {
		t.Fatalf("行数 = %d, want 2\n%s", len(lines), strings.Join(lines, "\n"))
	}
	var hit map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &hit); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ts", "pkg", "uid", "sni", "ja4", "alpn", "dport",
		"quic", "ech", "partial", "rip", "rule_id", "rule_name"} {
		if _, ok := hit[k]; !ok {
			t.Errorf("第 1 行缺字段 %q: %s", k, lines[0])
		}
	}
	if hit["alpn"] != "h2" {
		t.Errorf("alpn = %v, want h2(取第一个)", hit["alpn"])
	}
	if hit["rule_id"] != "douyin" || hit["rule_name"] != "抖音" {
		t.Errorf("rule 字段不对: %s", lines[0])
	}
	if hit["ts"] != float64(lsvDay1.Unix()) || hit["uid"] != float64(10234) {
		t.Errorf("ts/uid 不对: %s", lines[0])
	}
	// 反序列化回结构体, 确认类型与格式可被 httpd 端直接用。
	var back LabelSample
	if err := json.Unmarshal([]byte(lines[0]), &back); err != nil {
		t.Fatal(err)
	}
	if back.Pkg != "com.ss.android.ugc.aweme" || back.SNI != "api.amemv.com" || back.DPort != 443 ||
		back.RIP != "203.107.13.2" || back.JA4 == "" || back.QUIC || back.ECH || back.Partial {
		t.Errorf("回读不一致: %+v", back)
	}

	var miss map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &miss); err != nil {
		t.Fatal(err)
	}
	if _, ok := miss["alpn"]; ok {
		t.Errorf("无 ALPN 应省略字段: %s", lines[1])
	}
	if _, ok := miss["rule_id"]; ok {
		t.Errorf("规则未命中应省略 rule_id: %s", lines[1])
	}
	if _, ok := miss["rule_name"]; ok {
		t.Errorf("规则未命中应省略 rule_name: %s", lines[1])
	}
	if miss["quic"] != true || miss["ech"] != true || miss["partial"] != true {
		t.Errorf("quic/ech/partial 应为 true: %s", lines[1])
	}

	// 隐私: 不该存 URL / path / cookie / UA 之类内容。
	for _, k := range []string{"url", "path", "cookie", "ua", "user_agent", "payload", "dns"} {
		for i, l := range lines {
			if strings.Contains(strings.ToLower(l), `"`+k+`":`) {
				t.Errorf("第 %d 行含不该存的字段 %q", i+1, k)
			}
		}
	}
}

// 异常超长样本不入库(免得一条吃掉当天配额), 也不 panic。
func TestLabelSamplesOversizedLineRejected(t *testing.T) {
	w := lsvNew(t)
	s := lsvSample(lsvDay1, "com.x", strings.Repeat("a", labelSamplesLineMaxByte)+".example.com", "j1")
	if w.handle(s) {
		t.Error("超长样本不应写入")
	}
	if _, err := os.Stat(lsvPath(w, lsvDay1, labelSamplesJSONLEXT)); !os.IsNotExist(err) {
		t.Error("不应创建样本文件")
	}
}

// 目录不存在时不崩、不写文件(返回 false), 之后能自愈。
func TestLabelSamplesMissingDirTolerated(t *testing.T) {
	w := lsvNew(t)
	w.dir = filepath.Join(w.dir, "nope", "deeper")
	if w.handle(lsvSample(lsvDay1, "com.x", "a.example.com", "j1")) {
		t.Error("目录不存在时不应报成功")
	}
	w.sweepExpired(lsvDay1) // 不应 panic
	if st := w.Stats(); st.Written != 0 {
		t.Errorf("不应有写入计数: %+v", st)
	}
}

// 并发 Observe + 单 goroutine 消费: 配合 go test -race 验证「回调侧多生产者、
// 落盘侧单消费者」的锁边界。消费者必须全程唯一(handle 里的文件句柄/去重表不加锁,
// 依赖单消费者), 测试等它退出后再让 Cleanup 关句柄。
func TestLabelSamplesConcurrentObserve(t *testing.T) {
	w := lsvNew(t)
	var consumed atomic.Int64
	stop := make(chan struct{})
	quit := make(chan struct{})
	go func() {
		defer close(quit)
		for {
			select {
			case <-stop:
				return
			case sm := <-w.ch:
				w.handle(sm)
				consumed.Add(1)
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				// pkg 必须唯一: 去重 key 是 pkg|sni|ja4, 不含 uid。
				w.Observe(lsvInput(lsvDay1, 10234+i, "com.x"+strconv.Itoa(i),
					"a"+strconv.Itoa(j)+".example.com", "j"))
			}
		}(i)
	}
	wg.Wait()

	// 等队列排空(8 个 pkg × 100 个 SNI 都是唯一 key, 应全部落盘)。
	deadline := time.Now().Add(5 * time.Second)
	for consumed.Load() != 800 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	close(stop)
	<-quit

	if got := consumed.Load(); got != 800 {
		t.Errorf("消费 %d 条, want 800", got)
	}
	if st := w.Stats(); st.Dropped != 0 || st.Written != 800 {
		t.Errorf("stats = %+v, want 无丢弃、written=800", st)
	}
	if n := len(lsvLines(t, lsvPath(w, lsvDay1, labelSamplesJSONLEXT))); n != 800 {
		t.Errorf("行数 = %d, want 800", n)
	}
}
