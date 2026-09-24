// Package apkscan 扫描热点主机(root 过的安卓手机)上已安装 App 的 APK,
// 提取包内写死的域名, 建立「可注册域 → 包名 → App 名称」对照表
// (run/apk_domains.json), 供 httpd 给规则库认不出的域名找出所属 App。
//
// v5.15: 首版。设计要点:
//   - 只读 /data/app 下的用户 App(base.apk + split_*.apk), 系统 App 不扫;
//   - 每个 APK 只看 classes*.dex / resources.arsc / assets 下的小文本,
//     全程流式(固定大小缓冲按块读), 不把 dex 整个读进内存;
//   - 按 APK 路径 + 大小 + mtime 增量缓存, 没变的 APK 不重扫;
//   - 单 goroutine, APK 之间可配置 sleep, 整轮可被 context 取消。
package apkscan

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Schema 是 apk_domains.json 的格式版本。
	Schema = 1
	// extractorVersion 是提取规则版本; 规则(TLD/过滤表/启发式)变了就 +1,
	// 旧缓存整体作废重扫。
	extractorVersion = 1

	// DefaultOutPath 是输出文件默认路径。
	DefaultOutPath = "/data/local/hnc/run/apk_domains.json"

	maxDistinctPerAPK = 20000     // 单 APK 可注册域上限, 防病态包撑爆 map
	maxCachedPerAPK   = 150       // 缓存里每个 APK 保留的可注册域上限
	maxEntryRead      = 512 << 20 // 单个 zip 条目最多读多少(防 zip 炸弹)
)

// ErrBusy 表示已有一轮扫描在进行。
var ErrBusy = errors.New("apkscan: scan already running")

// Options 是扫描参数。零值字段由 New 填默认值。
type Options struct {
	Roots             []string            // APK 根目录, 默认 ["/data/app"]
	OutPath           string              // 输出文件, 默认 DefaultOutPath
	MaxAPKBytes       int64               // 单个 APK 超过即跳过, 默认 400MB
	MaxAssetBytes     int64               // assets 文本上限, 默认 2MB
	ChunkSize         int                 // 流式读块大小, 默认 64KB
	PerAPKSleep       time.Duration       // 每扫完一个 APK 歇一会, 默认 100ms(<0 表示不歇)
	SDKMinApps        int                 // 出现在 ≥N 个 App 里即视为共用 SDK, 默认 6
	MaxSuffixesPerApp int                 // 每个 App 最多保留的可注册域, 默认 60
	Label             func(string) string // 包名 → 显示名, nil 或返回空时用包名
	Now               func() time.Time
}

// Output 是 apk_domains.json 的完整结构。
type Output struct {
	Schema      int                    `json:"schema"`
	Extractor   int                    `json:"extractor"`
	GeneratedAt int64                  `json:"generated_at"`
	ScanMS      int64                  `json:"scan_ms"`
	AppCount    int                    `json:"app_count"`
	Apps        map[string]*AppEntry   `json:"apps"`
	SuffixIndex map[string][]string    `json:"suffix_index"`
	SDKSuffixes []string               `json:"sdk_suffixes"`
	Stats       Stats                  `json:"stats"`
	Cache       map[string]*CacheEntry `json:"cache"`
}

// AppEntry 是一个 App(包名)的归属结果。
type AppEntry struct {
	Label    string   `json:"label"`
	Suffixes []string `json:"suffixes"` // 按出现次数降序, 已剔除基础设施与共用 SDK
	APKSize  int64    `json:"apk_size"` // base + split 总字节
	MTime    int64    `json:"mtime"`    // 各 APK 最大 mtime(unix 秒)
}

// CacheEntry 是单个 APK 文件的增量缓存。Counts 与 Suffixes 一一对应
// (出现次数), 用于同一 App 多个 split 合并排序。
type CacheEntry struct {
	Size     int64    `json:"size"`
	MTime    int64    `json:"mtime"`
	Pkg      string   `json:"pkg"`
	Suffixes []string `json:"suffixes"`
	Counts   []int    `json:"counts,omitempty"`
	Err      string   `json:"err,omitempty"` // 打不开/损坏: 记下来, 文件不变就不再重试
}

// Stats 是本轮扫描计数(诊断用)。
type Stats struct {
	APKs    int `json:"apks"`    // 枚举到的 APK 数
	Scanned int `json:"scanned"` // 本轮实际打开扫描的
	Reused  int `json:"reused"`  // 命中缓存复用的
	Skipped int `json:"skipped"` // 超大跳过的
	Failed  int `json:"failed"`  // 打不开/损坏的
}

// Scanner 执行扫描。同一时刻只允许一轮(TryLock), 扫描本身单 goroutine。
type Scanner struct {
	opt     Options
	mu      sync.Mutex
	buf     []byte
	scanned atomic.Int64 // 累计实际打开扫描的 APK 数(测试断言增量缓存用)
}

// New 构造 Scanner 并填默认值。
func New(opt Options) *Scanner {
	if len(opt.Roots) == 0 {
		opt.Roots = []string{"/data/app"}
	}
	if opt.OutPath == "" {
		opt.OutPath = DefaultOutPath
	}
	if opt.MaxAPKBytes <= 0 {
		opt.MaxAPKBytes = 400 << 20
	}
	if opt.MaxAssetBytes <= 0 {
		opt.MaxAssetBytes = 2 << 20
	}
	if opt.ChunkSize <= 0 {
		opt.ChunkSize = 64 << 10
	}
	if opt.PerAPKSleep == 0 {
		opt.PerAPKSleep = 100 * time.Millisecond
	}
	if opt.SDKMinApps <= 0 {
		opt.SDKMinApps = 6
	}
	if opt.MaxSuffixesPerApp <= 0 {
		opt.MaxSuffixesPerApp = 60
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &Scanner{opt: opt}
}

// OutPath 返回输出文件路径。
func (s *Scanner) OutPath() string { return s.opt.OutPath }

// ScannedTotal 返回累计实际打开扫描过的 APK 数。
func (s *Scanner) ScannedTotal() int64 { return s.scanned.Load() }

type apkFile struct {
	path  string
	pkg   string
	size  int64
	mtime int64
}

// Scan 跑一轮完整扫描并原子写出结果。ctx 取消时返回 ctx.Err() 且不写文件。
func (s *Scanner) Scan(ctx context.Context) (*Output, error) {
	if !s.mu.TryLock() {
		return nil, ErrBusy
	}
	defer s.mu.Unlock()

	// 扫描期间把 GC 调激进一些, 让解压缓冲/临时串尽快回收, 峰值压在几十 MB。
	old := debug.SetGCPercent(40)
	defer func() {
		debug.SetGCPercent(old)
		s.buf = nil
		debug.FreeOSMemory()
	}()
	if len(s.buf) != s.opt.ChunkSize {
		s.buf = make([]byte, s.opt.ChunkSize)
	}

	start := s.opt.Now()
	prev := loadCache(s.opt.OutPath)
	apks := enumerate(s.opt.Roots)

	out := &Output{
		Schema:      Schema,
		Extractor:   extractorVersion,
		Apps:        map[string]*AppEntry{},
		SuffixIndex: map[string][]string{},
		SDKSuffixes: []string{},
		Cache:       make(map[string]*CacheEntry, len(apks)),
	}
	out.Stats.APKs = len(apks)

	for _, a := range apks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if a.size > s.opt.MaxAPKBytes {
			out.Stats.Skipped++
			continue
		}
		if c, ok := prev[a.path]; ok && c.Size == a.size && c.MTime == a.mtime && c.Pkg == a.pkg {
			out.Cache[a.path] = c
			out.Stats.Reused++
			continue
		}
		counts, err := s.scanAPK(ctx, a.path)
		if err != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s.scanned.Add(1)
		ce := &CacheEntry{Size: a.size, MTime: a.mtime, Pkg: a.pkg, Suffixes: []string{}}
		if err != nil {
			ce.Err = err.Error()
			out.Stats.Failed++
		} else {
			out.Stats.Scanned++
			ce.Suffixes, ce.Counts = topN(counts, maxCachedPerAPK)
		}
		out.Cache[a.path] = ce
		counts = nil
		if s.opt.PerAPKSleep > 0 {
			t := time.NewTimer(s.opt.PerAPKSleep)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			}
		}
	}

	s.aggregate(out, apks)
	end := s.opt.Now()
	out.GeneratedAt = end.Unix()
	out.ScanMS = end.Sub(start).Milliseconds()
	if err := writeAtomic(s.opt.OutPath, out); err != nil {
		return out, err
	}
	return out, nil
}

// aggregate 把各 APK 的缓存合并成 App 维度, 做文档频率过滤并建反查索引。
func (s *Scanner) aggregate(out *Output, apks []apkFile) {
	type agg struct {
		counts map[string]int
		size   int64
		mtime  int64
	}
	byPkg := map[string]*agg{}
	for _, a := range apks {
		c, ok := out.Cache[a.path]
		if !ok {
			continue // 超大跳过的
		}
		g := byPkg[a.pkg]
		if g == nil {
			g = &agg{counts: map[string]int{}}
			byPkg[a.pkg] = g
		}
		g.size += a.size
		if a.mtime > g.mtime {
			g.mtime = a.mtime
		}
		for i, rd := range c.Suffixes {
			if isInfra(rd) { // 表可能比缓存新, 聚合时再滤一次
				continue
			}
			n := 1
			if i < len(c.Counts) && c.Counts[i] > 0 {
				n = c.Counts[i]
			}
			g.counts[rd] += n
		}
	}

	df := map[string]int{}
	for _, g := range byPkg {
		for rd := range g.counts {
			df[rd]++
		}
	}
	sdk := map[string]bool{}
	for rd, n := range df {
		if n >= s.opt.SDKMinApps {
			sdk[rd] = true
			out.SDKSuffixes = append(out.SDKSuffixes, rd)
		}
	}
	sort.Slice(out.SDKSuffixes, func(i, j int) bool {
		a, b := out.SDKSuffixes[i], out.SDKSuffixes[j]
		if df[a] != df[b] {
			return df[a] > df[b]
		}
		return a < b
	})

	for pkg, g := range byPkg {
		for rd := range sdk {
			delete(g.counts, rd)
		}
		sfx, _ := topN(g.counts, s.opt.MaxSuffixesPerApp)
		label := ""
		if s.opt.Label != nil {
			label = s.opt.Label(pkg)
		}
		if label == "" {
			label = pkg
		}
		out.Apps[pkg] = &AppEntry{Label: label, Suffixes: sfx, APKSize: g.size, MTime: g.mtime}
		for _, rd := range sfx {
			out.SuffixIndex[rd] = append(out.SuffixIndex[rd], pkg)
		}
	}
	for _, pkgs := range out.SuffixIndex {
		sort.Strings(pkgs)
	}
	out.AppCount = len(out.Apps)
}

// topN 按次数降序(同次数按名字)取前 n 个。
func topN(counts map[string]int, n int) ([]string, []int) {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	cs := make([]int, len(keys))
	for i, k := range keys {
		cs[i] = counts[k]
	}
	return keys, cs
}

// ---- 枚举 ----

// enumerate 遍历 APK 根目录。支持两种布局:
//
//	Android 11+: <root>/~~随机/包名-随机/{base.apk,split_*.apk}
//	老布局:      <root>/包名-N/{base.apk,split_*.apk}
func enumerate(roots []string) []apkFile {
	var out []apkFile
	for _, root := range roots {
		ents, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(root, e.Name())
			if strings.HasPrefix(e.Name(), "~~") {
				sub, err := os.ReadDir(p)
				if err != nil {
					continue
				}
				for _, se := range sub {
					if se.IsDir() {
						out = appendPkgDir(out, filepath.Join(p, se.Name()), se.Name())
					}
				}
				continue
			}
			out = appendPkgDir(out, p, e.Name())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

func appendPkgDir(out []apkFile, dir, name string) []apkFile {
	pkg := pkgFromDir(name)
	if pkg == "" {
		return out
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range ents {
		n := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(n, ".apk") {
			continue
		}
		if n != "base.apk" && !strings.HasPrefix(n, "split_") {
			continue
		}
		st, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, apkFile{
			path:  filepath.Join(dir, n),
			pkg:   pkg,
			size:  st.Size(),
			mtime: st.ModTime().Unix(),
		})
	}
	return out
}

// pkgFromDir 从 "com.foo.bar-AbC_x==" / "com.foo.bar-1" 取出包名。
// 包名不可能含 '-', 所以截到第一个 '-'; 没有 '-' 的(vmdl*.tmp 暂存目录等)不认。
func pkgFromDir(name string) string {
	i := strings.IndexByte(name, '-')
	if i <= 0 {
		return ""
	}
	pkg := name[:i]
	if !strings.Contains(pkg, ".") || pkg[0] == '.' || pkg[len(pkg)-1] == '.' {
		return ""
	}
	for _, c := range pkg {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return ""
		}
	}
	return pkg
}

// ---- 单个 APK ----

type entryKind int

const (
	kindSkip entryKind = iota
	kindText           // dex / assets 文本: 按字节流
	kindARSC           // resources.arsc: 额外按 UTF-16LE 再扫一遍
)

var assetExts = setOf(".json", ".xml", ".txt", ".properties", ".js")

func (s *Scanner) classify(f *zip.File) entryKind {
	name := f.Name
	switch {
	case name == "resources.arsc":
		return kindARSC
	case strings.HasPrefix(name, "classes") && strings.HasSuffix(name, ".dex") && !strings.Contains(name, "/"):
		return kindText
	case strings.HasPrefix(name, "assets/"):
		if f.UncompressedSize64 > uint64(s.opt.MaxAssetBytes) {
			return kindSkip
		}
		if _, ok := assetExts[strings.ToLower(filepath.Ext(name))]; ok {
			return kindText
		}
	}
	return kindSkip
}

// scanAPK 打开一个 APK 并统计可注册域出现次数。损坏的 zip 返回错误;
// 任何 panic 也兜住转成错误, 保证一个坏包不影响整轮。
func (s *Scanner) scanAPK(ctx context.Context, path string) (counts map[string]int, err error) {
	defer func() {
		if r := recover(); r != nil {
			counts, err = nil, fmt.Errorf("panic: %v", r)
		}
	}()
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	counts = map[string]int{}
	emit := func(tok []byte, urlCtx bool) {
		h, ok := hostOf(tok, urlCtx)
		if !ok {
			return
		}
		rd := registrable(string(h))
		if rd == "" || isInfra(rd) {
			return
		}
		if n, ok := counts[rd]; ok {
			counts[rd] = n + 1
		} else if len(counts) < maxDistinctPerAPK {
			counts[rd] = 1
		}
	}
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		kind := s.classify(f)
		if kind == kindSkip {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue // 单个条目坏了(不支持的压缩方式等)就跳过这个条目
		}
		err = s.scanStream(ctx, io.LimitReader(rc, maxEntryRead), kind == kindARSC, emit)
		rc.Close()
		if err != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// 条目中途读错(CRC/截断): 已扫到的部分保留, 继续下一个条目。
	}
	return counts, nil
}

// scanStream 用固定缓冲按块读 r, 喂给跨块状态机。utf16 为 true 时同时
// 按 UTF-16LE(偶数位 ASCII + 奇数位 0)再解一路, 覆盖 arsc 的 UTF-16 串池。
func (s *Scanner) scanStream(ctx context.Context, r io.Reader, utf16 bool, emit func([]byte, bool)) error {
	t8 := tokenizer{emit: emit}
	var t16 tokenizer
	var off int64
	var lo byte
	if utf16 {
		t16.emit = emit
	}
	defer func() {
		t8.flush()
		if utf16 {
			t16.flush()
		}
	}()
	for iter := 0; ; iter++ {
		if iter&63 == 63 && ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := r.Read(s.buf)
		if n > 0 {
			chunk := s.buf[:n]
			t8.feed(chunk)
			if utf16 {
				for _, c := range chunk {
					if off&1 == 0 {
						lo = c
					} else if c == 0 {
						t16.feedByte(lo)
					} else {
						t16.feedByte(0) // 非 ASCII 字符 → 分隔
					}
					off++
				}
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// ---- 读写输出 ----

// loadCache 读回上一轮输出里的缓存。schema/提取规则版本不一致则整体作废。
func loadCache(path string) map[string]*CacheEntry {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var o struct {
		Schema    int                    `json:"schema"`
		Extractor int                    `json:"extractor"`
		Cache     map[string]*CacheEntry `json:"cache"`
	}
	if json.Unmarshal(b, &o) != nil || o.Schema != Schema || o.Extractor != extractorVersion {
		return nil
	}
	for k, v := range o.Cache {
		if v == nil {
			delete(o.Cache, k)
		}
	}
	return o.Cache
}

// ReadGeneratedAt 返回输出文件的 generated_at(unix 秒); 文件不存在或坏了返回 0。
func ReadGeneratedAt(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	var o struct {
		Schema      int   `json:"schema"`
		GeneratedAt int64 `json:"generated_at"`
	}
	if json.NewDecoder(f).Decode(&o) != nil || o.Schema != Schema {
		return 0
	}
	return o.GeneratedAt
}

// writeAtomic 写 tmp(文件名带 pid, 防 -apk-scan 与常驻进程并发) → fsync → rename。
func writeAtomic(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
