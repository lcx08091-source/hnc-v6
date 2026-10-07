// shared_infra_test.go — v5.30 T1c: 「新发现的应用」排除公共基础设施。
//
// 「改动前会失败」: v5.29 的 Discoverer 不认识共享基础设施 ——
// TestDiscoverListedInfraNotGrouped 里 alibabadns.com 自成一组 / 混进应用组,
// TestDiscoverFreqSharedSplitsBridge 里桥接域把 4 个应用糊成一个大组。
package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 用户截图里被当成「应用」的 7 个域名(回归用例)。
var screenshotInfra = []string{"alibabadns.com", "cdngslb.com", "qtlcdn.com", "ksyuncdn.com",
	"lanniao.com", "wechatpay.cn", "tencentcos.cn"}

func shippedInfra(t *testing.T) *SharedInfra {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "data", "dpi_rules.d", SharedInfraFileName))
	if err != nil {
		t.Fatalf("模块自带名单: %v", err)
	}
	return ParseSharedInfra(b)
}

func TestSharedInfraMatch(t *testing.T) {
	si := ParseSharedInfra([]byte(`
# 注释
Example-CDN.com   # 行尾注释
cdnhwc*.com
bugly.qq.com
.dotted.net.

bad line with space
`))
	for host, want := range map[string]bool{
		"example-cdn.com":      true,
		"img.example-cdn.com":  true,
		"IMG.EXAMPLE-CDN.COM.": true,
		"notexample-cdn.com":   false, // 不是 ".它" 结尾
		"cdnhwc1.com":          true,
		"cdnhwcprov.com":       true,
		"a.cdnhwc1.com":        true, // 对可注册域通配
		"cdnhwc1.com.cn":       false,
		"xcdnhwc1.com":         false,
		"bugly.qq.com":         true,
		"android.bugly.qq.com": true,
		"qq.com":               false,
		"dotted.net":           true,
		"line":                 false,
		"":                     false,
	} {
		if got := si.Match(host); got != want {
			t.Errorf("Match(%q) = %v, want %v", host, got, want)
		}
	}
	var nilSI *SharedInfra
	if nilSI.Match("alibabadns.com") {
		t.Fatal("nil 名单不应命中")
	}
}

// 模块自带名单覆盖用户截图里的 7 个域名(名单内容可扩, 这 7 个不许掉)。
func TestShippedSharedInfraCoversScreenshot(t *testing.T) {
	si := shippedInfra(t)
	for _, d := range screenshotInfra {
		if !si.Match(d) || !si.Match("x."+d) {
			t.Errorf("名单漏了 %s", d)
		}
	}
	for _, d := range []string{"cdnhwc3.com", "dns.google", "bugly.qq.com", "mdap.alipay.com"} {
		if !si.Match(d) {
			t.Errorf("名单应命中 %s", d)
		}
	}
	for _, d := range []string{"qq.com", "alipay.com", "douyin.com", "fooapp.io"} {
		if si.Match(d) {
			t.Errorf("名单不应命中 %s", d)
		}
	}
}

func newInfraDiscoverer(t *testing.T, list string) *Discoverer {
	t.Helper()
	d := NewDiscoverer()
	dir := t.TempDir()
	d.SetPath(filepath.Join(dir, "dpi_discover.json"))
	d.SetFamilyPath(filepath.Join(dir, "dpi_ja4family.json"))
	if list != "" {
		p := filepath.Join(dir, SharedInfraFileName)
		if err := os.WriteFile(p, []byte(list), 0o644); err != nil {
			t.Fatal(err)
		}
		d.SetSharedInfraPath(p)
	}
	return d
}

// 名单命中的域名: 不单独成组、不混进应用组, 只挂在组的 shared 里。
func TestDiscoverListedInfraNotGrouped(t *testing.T) {
	d := newInfraDiscoverer(t, strings.Join(screenshotInfra, "\n"))
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i < 4; i++ {
		for _, mac := range []string{"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"} {
			burst(d, mac, "", t0.Add(time.Duration(i)*time.Minute), "api.fooapp.io", "ns1.alibabadns.com", "img.foocdn.net")
		}
	}
	for i := 0; i < 6; i++ { // 单独出现、命中数够成组的 CDN
		d.Observe("aa:bb:cc:00:00:03", "v1.cdngslb.com", "", t0.Add(time.Hour+time.Duration(i)*time.Minute), false, "", "")
	}
	gs := d.Groups(t0.Add(2 * time.Hour))
	for _, s := range screenshotInfra {
		if g := groupOf(gs, s); g != nil {
			t.Errorf("%s 不应在任何组的 suffixes 里: %+v", s, g)
		}
	}
	g := groupOf(gs, "fooapp.io")
	if g == nil || len(g.Suffixes) != 2 || groupOf(gs, "foocdn.net") != g {
		t.Fatalf("应用组应只有自己的两个域名: %+v", gs)
	}
	if len(g.Shared) != 1 || g.Shared[0].Suffix != "alibabadns.com" || g.Shared[0].Reason != sharedReasonList {
		t.Fatalf("alibabadns.com 应作为附属证据挂在组上: %+v", g.Shared)
	}
	for _, dm := range g.Domains {
		if strings.Contains(dm.Name, "alibabadns") {
			t.Fatalf("组的 domains 不应含共享域: %+v", g.Domains)
		}
	}
}

// buildBridgeWorld 4 个应用(各 2 个域名, 各自强共现)在 nDev 台设备上,
// 桥接域 bridge.example 每次都跟着出现(与每个应用强共现)。
// 应用 i 的事件在设备 i % nDev 上, 不同应用相隔 > 共现窗口。
func buildBridgeWorld(d *Discoverer, t0 time.Time, nApps, nDev int) {
	for round := 0; round < 4; round++ {
		for i := 0; i < nApps; i++ {
			mac := fmt.Sprintf("aa:bb:cc:00:01:%02x", i%nDev)
			at := t0.Add(time.Duration(round)*time.Hour + time.Duration(i)*time.Minute)
			burst(d, mac, "", at, fmt.Sprintf("api.app%d.io", i), fmt.Sprintf("img.app%dcdn.net", i), "edge.bridge-cdn.com")
		}
	}
}

func TestDiscoverFreqSharedSplitsBridge(t *testing.T) {
	d := newInfraDiscoverer(t, "") // 不靠名单
	t0 := time.Unix(1_800_000_000, 0)
	buildBridgeWorld(d, t0, discSharedMinGroups, discSharedMinDevices+1)
	gs := d.Groups(t0.Add(4 * time.Hour))
	if g := groupOf(gs, "bridge-cdn.com"); g != nil {
		t.Fatalf("桥接域应判为共享基础设施, 不在组里: %+v", g)
	}
	for i := 0; i < discSharedMinGroups; i++ {
		g := groupOf(gs, fmt.Sprintf("app%d.io", i))
		if g == nil || len(g.Suffixes) != 2 {
			t.Fatalf("应用 %d 应自成一组(不被桥接域糊在一起): %+v", i, gs)
		}
		if len(g.Shared) != 1 || g.Shared[0].Suffix != "bridge-cdn.com" || g.Shared[0].Reason != sharedReasonFreq {
			t.Fatalf("应用 %d 的 shared = %+v", i, g.Shared)
		}
	}
}

// 阈值边界: 设备数 / 组数恰好差一个时不判。
func TestDiscoverFreqSharedThresholdBoundaries(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	cases := []struct {
		name       string
		apps, devs int
		wantShared bool
	}{
		{"刚好达标", discSharedMinGroups, discSharedMinDevices, true},
		{"设备差一台", discSharedMinGroups, discSharedMinDevices - 1, false},
		{"组差一个", discSharedMinGroups - 1, discSharedMinDevices, false},
	}
	for _, c := range cases {
		d := newInfraDiscoverer(t, "")
		buildBridgeWorld(d, t0, c.apps, c.devs)
		d.mu.Lock()
		shared := classifyShared(d.nodes, d.edges, d.adj, t0.Add(4*time.Hour).Unix(), nil, map[string]int64{})
		d.mu.Unlock()
		if got := shared["bridge-cdn.com"] == sharedReasonFreq; got != c.wantShared {
			t.Errorf("%s(%d 组 / %d 台): shared=%v, want %v", c.name, c.apps, c.devs, got, c.wantShared)
		}
	}
}

func TestDevsInWindowBoundary(t *testing.T) {
	now := int64(1_800_000_000)
	n := &discNode{devs: map[string]int64{
		"a": now, "b": now - discSharedWindowSec, "c": now - discSharedWindowSec - 1,
	}}
	if got := devsInWindow(n, now); got != 2 {
		t.Fatalf("devsInWindow = %d, want 2(恰好窗口边界算, 超出 1 秒不算)", got)
	}
}

// 频度判定落盘读回: 重启后桥接域单独再出现, 也不单独成组。
func TestDiscoverFreqSharedStickyAcrossReload(t *testing.T) {
	d := newInfraDiscoverer(t, "")
	t0 := time.Unix(1_800_000_000, 0)
	buildBridgeWorld(d, t0, discSharedMinGroups, discSharedMinDevices)
	t1 := t0.Add(4 * time.Hour)
	if err := d.Flush(t1); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	path := d.path
	d.mu.Unlock()
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"shared_infra":[`) || !strings.Contains(string(b), `"suffix":"bridge-cdn.com","reason":"freq"`) {
		t.Fatalf("dpi_discover.json 应写出 shared_infra: %s", b)
	}
	d2 := NewDiscoverer()
	d2.SetPath(path)
	if err := d2.Load(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ { // 重启后只有它自己反复出现(没有边)
		d2.Observe("aa:bb:cc:00:02:01", "edge.bridge-cdn.com", "", t1.Add(time.Duration(i)*time.Minute), false, "", "")
	}
	if g := groupOf(d2.Groups(t1.Add(time.Hour)), "bridge-cdn.com"); g != nil {
		t.Fatalf("读回的频度判定应仍生效: %+v", g)
	}
	// 超过保留期后失效
	if g := groupOf(d2.Groups(t1.Add(time.Duration(discSharedStickySec+3600)*time.Second)), "bridge-cdn.com"); g == nil {
		t.Fatalf("超过 %d 秒应不再按共享处理", discSharedStickySec)
	}
}

// 名单文件改了(mtime / size 变)会重读; 删掉后只剩频度兜底。
func TestSharedInfraFileReload(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, SharedInfraFileName)
	f := sharedInfraFile{path: p}
	now := time.Unix(1_800_000_000, 0)
	if f.get(now) != nil {
		t.Fatal("文件不存在应返回 nil")
	}
	_ = os.WriteFile(p, []byte("a.com\n"), 0o644)
	if f.get(now.Add(30 * time.Second)).Match("a.com") {
		t.Fatal("复查间隔内不应重读")
	}
	if !f.get(now.Add(2 * time.Minute)).Match("a.com") {
		t.Fatal("过了复查间隔应读到新文件")
	}
	_ = os.WriteFile(p, []byte("a.com\nbb.com\n"), 0o644)
	if !f.get(now.Add(4 * time.Minute)).Match("bb.com") {
		t.Fatal("内容变了应重读")
	}
	_ = os.Remove(p)
	if f.get(now.Add(6*time.Minute)) != nil {
		t.Fatal("文件删了应返回 nil")
	}
}
