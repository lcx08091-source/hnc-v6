package apkscan

import (
	"archive/zip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dexWith 模拟 dex 二进制: 字符串夹在不可打印字节中间
func dexWith(strs ...string) []byte {
	var b []byte
	b = append(b, []byte("dex\n035\x00\x01\x02")...)
	for _, s := range strs {
		b = append(b, 0x00, 0x1f, byte(len(s)))
		b = append(b, []byte(s)...)
		b = append(b, 0x00, 0x03)
	}
	return b
}

func writeAPK(t *testing.T, path string, files map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(data)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

func newTestScanner(root, out string) *Scanner {
	return New(Options{Roots: []string{root}, OutPath: out, PerAPKSleep: -1,
		Label: func(p string) string {
			if p == "com.kuaishou.nebula" {
				return "快手极速版"
			}
			return ""
		}})
}

func readOut(t *testing.T, p string) Output {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var o Output
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestScanExtractsDomains(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "app")
	out := filepath.Join(dir, "apk_domains.json")
	writeAPK(t, filepath.Join(root, "~~abc==", "com.kuaishou.nebula-XyZ==", "base.apk"), map[string][]byte{
		"classes.dex": dexWith("https://api.kuaishou.com/rest/n/feed", "img.xhscdn.com", "R.java", "icon.png",
			"com.kuaishou.android.Foo", "http://schemas.android.com/apk/res/android", "www.w3.org", "foo_bar.com"),
		"classes2.dex":        dexWith("p5.a.yximgs.com"),
		"resources.arsc":      []byte("\x00\x00h\x00t\x00t\x00p\x00s\x00:\x00/\x00/\x00m\x00.\x00g\x00i\x00f\x00s\x00h\x00o\x00w\x00.\x00c\x00o\x00m\x00\x00\x00"),
		"assets/config.json":  []byte(`{"host":"https://log.kwai-stat.cn/collect"}`),
		"res/drawable/a.png":  []byte("notadomain.com"), // 非扫描类型
		"lib/arm64/libfoo.so": []byte("secret.lib-domain.com"),
	})
	o, err := newTestScanner(root, out).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	app := o.Apps["com.kuaishou.nebula"]
	if app == nil || app.Label != "快手极速版" {
		t.Fatalf("app entry = %+v", o.Apps)
	}
	has := func(s string) bool {
		for _, x := range app.Suffixes {
			if x == s {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"kuaishou.com", "xhscdn.com", "yximgs.com", "kwai-stat.cn"} {
		if !has(want) {
			t.Errorf("missing %s in %v", want, app.Suffixes)
		}
	}
	for _, bad := range []string{"r.java", "icon.png", "android.com", "w3.org", "notadomain.com", "lib-domain.com", "bar.com", "foo_bar.com"} {
		if has(bad) {
			t.Errorf("should not contain %s: %v", bad, app.Suffixes)
		}
	}
	if !has("gifshow.com") {
		t.Errorf("resources.arsc UTF-16 host missed: %v", app.Suffixes)
	}
	if got := o.SuffixIndex["kuaishou.com"]; len(got) != 1 || got[0] != "com.kuaishou.nebula" {
		t.Fatalf("suffix_index = %v", o.SuffixIndex)
	}
	if on := readOut(t, out); on.AppCount != 1 || on.GeneratedAt == 0 {
		t.Fatalf("output file = %+v", on)
	}
}

func TestScanSDKFilterAndIncremental(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "app")
	out := filepath.Join(dir, "apk_domains.json")
	for i := 0; i < 7; i++ {
		pkg := "com.app" + string(rune('a'+i))
		writeAPK(t, filepath.Join(root, pkg+"-1", "base.apk"), map[string][]byte{
			"classes.dex": dexWith("https://alog.umeng.com/app_logs", "api."+strings.ReplaceAll(pkg, ".", "")+".cn"),
		})
	}
	s := newTestScanner(root, out)
	o, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Apps) != 7 {
		t.Fatalf("apps = %d", len(o.Apps))
	}
	sdk := strings.Join(o.SDKSuffixes, ",")
	if !strings.Contains(sdk, "umeng.com") {
		t.Fatalf("umeng.com should be SDK: %v", o.SDKSuffixes)
	}
	for pkg, a := range o.Apps {
		for _, x := range a.Suffixes {
			if x == "umeng.com" {
				t.Fatalf("%s still owns SDK domain", pkg)
			}
		}
	}
	if len(o.SuffixIndex["comappa.cn"]) != 1 {
		t.Fatalf("own domain lost: %v", o.SuffixIndex)
	}
	// 第二轮: 文件没变 → 全部复用缓存, 不重新打开
	n0 := s.ScannedTotal()
	if _, err := s.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.ScannedTotal() != n0 {
		t.Fatalf("unchanged APKs rescanned: %d -> %d", n0, s.ScannedTotal())
	}
	// 改一个 APK 的 mtime → 只重扫这一个
	p := filepath.Join(root, "com.appa-1", "base.apk")
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(p, future, future)
	if _, err := s.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.ScannedTotal() != n0+1 {
		t.Fatalf("expected exactly one rescan: %d -> %d", n0, s.ScannedTotal())
	}
}

func TestScanCorruptOversizeCancelAndChunkBoundary(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "app")
	out := filepath.Join(dir, "apk_domains.json")
	// 损坏的 zip
	_ = os.MkdirAll(filepath.Join(root, "com.broken-1"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "com.broken-1", "base.apk"), []byte("PK\x03\x04garbage"), 0o644)
	// 正常包: 域名放在块边界上(块大小 16)
	writeAPK(t, filepath.Join(root, "com.good-1", "base.apk"), map[string][]byte{
		"classes.dex": append([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"), []byte("https://edge.boundaryapp.io/x\x00")...),
	})
	s := New(Options{Roots: []string{root}, OutPath: out, PerAPKSleep: -1, ChunkSize: 16})
	o, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 包名由目录名截到第一个 '-': com.good-1 → com.good
	if a := o.Apps["com.good"]; a == nil || len(a.Suffixes) == 0 || a.Suffixes[0] != "boundaryapp.io" {
		t.Fatalf("chunk-boundary domain missed: %+v stats=%+v", o.Apps, o.Stats)
	}
	if o.Stats.Failed != 1 {
		t.Fatalf("corrupt apk should count as failed: %+v", o.Stats)
	}
	// 超大文件跳过
	s2 := New(Options{Roots: []string{root}, OutPath: filepath.Join(dir, "o2.json"), PerAPKSleep: -1, MaxAPKBytes: 10})
	o2, err := s2.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if o2.Stats.Skipped != 2 {
		t.Fatalf("oversize not skipped: %+v", o2.Stats)
	}
	// 取消: 不写文件
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s3 := New(Options{Roots: []string{root}, OutPath: filepath.Join(dir, "o3.json"), PerAPKSleep: -1})
	if _, err := s3.Scan(ctx); err == nil {
		t.Fatal("cancelled scan should error")
	}
	if _, err := os.Stat(filepath.Join(dir, "o3.json")); !os.IsNotExist(err) {
		t.Fatal("cancelled scan must not write output")
	}
}

func TestPkgFromDir(t *testing.T) {
	for in, want := range map[string]string{"com.foo.bar-AbC_x==": "com.foo.bar", "com.foo-1": "com.foo", "vmdl123.tmp": "", "nodots-1": "", "-x": ""} {
		if got := pkgFromDir(in); got != want {
			t.Errorf("pkgFromDir(%q)=%q want %q", in, got, want)
		}
	}
}
