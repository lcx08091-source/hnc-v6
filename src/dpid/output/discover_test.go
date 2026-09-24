package output

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRegistrableDomain(t *testing.T) {
	for in, want := range map[string]string{
		"img.xhscdn.com": "xhscdn.com", "a.b.sina.com.cn": "sina.com.cn", "x.co.uk": "x.co.uk",
		"kuaishou.com": "kuaishou.com", "1.2.3.4": "", "": "", "*.gifshow.com": "gifshow.com", "Foo.Example.ORG.": "example.org",
	} {
		if got := registrableDomain(in); got != want {
			t.Errorf("registrableDomain(%q)=%q want %q", in, got, want)
		}
	}
}

// burst 模拟某设备在 t 时刻前后 2 秒内依次访问这些主机
func burst(d *Discoverer, mac, ja4 string, t0 time.Time, hosts ...string) {
	for i, h := range hosts {
		d.Observe(mac, h, ja4, t0.Add(time.Duration(i)*500*time.Millisecond), false, "", "")
	}
}

func groupOf(gs []DiscoverGroup, suffix string) *DiscoverGroup {
	for i := range gs {
		for _, s := range gs[i].Suffixes {
			if s == suffix {
				return &gs[i]
			}
		}
	}
	return nil
}

func TestDiscoverClustersCooccurringDomains(t *testing.T) {
	d := NewDiscoverer()
	t0 := time.Unix(1_800_000_000, 0)
	mac := "aa:bb:cc:00:00:01"
	// 同一 App 的三个域名反复在 2 秒内一起出现 → 聚成一组
	for i := 0; i < 4; i++ {
		burst(d, mac, "", t0.Add(time.Duration(i)*time.Minute), "api.fooapp.io", "img.foocdn.net", "log.foo-stat.cn")
	}
	// 另一个陌生域名只在很久以后单独出现 → 自成一组, 不并进来
	for i := 0; i < 6; i++ {
		d.Observe(mac, "x.lonely.org", "", t0.Add(time.Hour+time.Duration(i)*time.Minute), false, "", "")
	}
	gs := d.Groups(t0.Add(2 * time.Hour))
	g := groupOf(gs, "fooapp.io")
	if g == nil || len(g.Suffixes) != 3 || groupOf(gs, "foocdn.net") != g || groupOf(gs, "foo-stat.cn") != g {
		t.Fatalf("co-occurring domains not clustered: %+v", gs)
	}
	if l := groupOf(gs, "lonely.org"); l == nil || l == g || len(l.Suffixes) != 1 {
		t.Fatalf("lonely domain wrongly merged: %+v", gs)
	}
	// 组 id 稳定: 由组内字典序最小的可注册域决定
	if g.ID != discGroupID("foo-stat.cn") {
		t.Fatalf("group id = %s", g.ID)
	}
}

func TestDiscoverNoMergeAcrossDevicesOrTime(t *testing.T) {
	d := NewDiscoverer()
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i < 6; i++ {
		ts := t0.Add(time.Duration(i) * time.Minute)
		d.Observe("aa:bb:cc:00:00:01", "a.alpha.io", "", ts, false, "", "")
		d.Observe("aa:bb:cc:00:00:02", "b.beta.io", "", ts, false, "", "")                      // 不同设备
		d.Observe("aa:bb:cc:00:00:01", "c.gamma.io", "", ts.Add(20*time.Second), false, "", "") // 超出 5 秒窗口
	}
	gs := d.Groups(t0.Add(time.Hour))
	for _, s := range []string{"alpha.io", "beta.io", "gamma.io"} {
		if g := groupOf(gs, s); g == nil || len(g.Suffixes) != 1 {
			t.Fatalf("%s should be alone: %+v", s, gs)
		}
	}
}

func TestDiscoverThresholdAndSameJA4Bonus(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	// 只共现 2 次(权重 2 < 3) → 不合并
	d := NewDiscoverer()
	for i := 0; i < 2; i++ {
		burst(d, "aa:bb:cc:00:00:01", "", t0.Add(time.Duration(i)*time.Minute), "a.one.io", "b.two.io")
	}
	for i := 0; i < 4; i++ { // 凑够命中数, 让组能输出
		d.Observe("aa:bb:cc:00:00:01", "a.one.io", "", t0.Add(time.Hour+time.Duration(i)*time.Minute), false, "", "")
		d.Observe("aa:bb:cc:00:00:01", "b.two.io", "", t0.Add(2*time.Hour+time.Duration(i)*time.Minute), false, "", "")
	}
	gs := d.Groups(t0.Add(3 * time.Hour))
	if g := groupOf(gs, "one.io"); g == nil || len(g.Suffixes) != 1 {
		t.Fatalf("2 co-occurrences must not merge: %+v", gs)
	}
	// 同样 2 次但同 JA4(每次 +2 → 4 ≥ 3) → 合并
	d2 := NewDiscoverer()
	for i := 0; i < 2; i++ {
		burst(d2, "aa:bb:cc:00:00:01", "t13d_same", t0.Add(time.Duration(i)*time.Minute), "a.one.io", "b.two.io", "c.one.io", "d.two.io", "e.one.io")
	}
	gs = d2.Groups(t0.Add(10 * time.Minute))
	if g := groupOf(gs, "one.io"); g == nil || len(g.Suffixes) != 2 {
		t.Fatalf("same-JA4 co-occurrence should merge: %+v", gs)
	}
	// 命中太少(< 5 且只 1 台设备)不输出
	d3 := NewDiscoverer()
	d3.Observe("aa:bb:cc:00:00:01", "a.rare.io", "", t0, false, "", "")
	if gs := d3.Groups(t0); len(gs) != 0 {
		t.Fatalf("rare domain should be filtered: %+v", gs)
	}
}

func TestDiscoverEdgeDecay(t *testing.T) {
	d := NewDiscoverer()
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i < 4; i++ {
		burst(d, "aa:bb:cc:00:00:01", "", t0.Add(time.Duration(i)*time.Minute), "a.one.io", "b.two.io")
	}
	if g := groupOf(d.Groups(t0.Add(time.Hour)), "one.io"); g == nil || len(g.Suffixes) != 2 {
		t.Fatal("should be merged within the hour")
	}
	// 权重 4, 半衰 24h: 1 天后 2 < 3 → 分开
	// (分开后各自只有 4 次命中、1 台设备, 达不到输出门槛 —— 只要不再是同一组即可)
	if g := groupOf(d.Groups(t0.Add(25*time.Hour)), "one.io"); g != nil && len(g.Suffixes) != 1 {
		t.Fatal("edge should decay below threshold after a day")
	}
}

func TestJA4FamilyLearning(t *testing.T) {
	d := NewDiscoverer()
	t0 := time.Unix(1_800_000_000, 0)
	// JA4 A: 只在字节系应用上出现 → 学到"字节跳动"
	for i := 0; i < 25; i++ {
		d.Observe("aa:bb:cc:00:00:01", "v.douyin.com", "JA4_A", t0, true, "douyin", "video")
	}
	// JA4 B: 浏览器式混用(字节/腾讯/阿里各一份) → 占比不过线, 不标
	for i := 0; i < 30; i++ {
		rule := []string{"douyin", "wechat", "taobao"}[i%3]
		d.Observe("aa:bb:cc:00:00:01", "x.example.com", "JA4_B", t0, true, rule, "social")
	}
	// SDK 类(非 TierApp)不参与学习
	for i := 0; i < 30; i++ {
		d.Observe("aa:bb:cc:00:00:01", "x.umeng.com", "JA4_C", t0, true, "umeng", "third_party_telemetry")
	}
	d.mu.Lock()
	famA, confA, okA := d.fam.familyOf("JA4_A")
	_, _, okB := d.fam.familyOf("JA4_B")
	_, _, okC := d.fam.familyOf("JA4_C")
	d.mu.Unlock()
	if !okA || famA != "bytedance" || confA != 1 {
		t.Fatalf("JA4_A family = %q %.2f %v", famA, confA, okA)
	}
	if okB || okC {
		t.Fatal("mixed / SDK JA4 must not get a family")
	}
	// 陌生域名组用了 JA4_A → 组被标为字节跳动
	for i := 0; i < 6; i++ {
		d.Observe("aa:bb:cc:00:00:01", "api.newbyteapp.io", "JA4_A", t0.Add(time.Duration(i)*time.Minute), false, "", "")
	}
	g := groupOf(d.Groups(t0.Add(time.Hour)), "newbyteapp.io")
	if g == nil || g.Family != "bytedance" || g.FamilyName != "字节跳动" || g.FamilyConf < 0.99 {
		t.Fatalf("group family = %+v", g)
	}
}

func TestDiscoverFlushAndReload(t *testing.T) {
	dir := t.TempDir()
	mk := func() *Discoverer {
		d := NewDiscoverer()
		d.SetPath(filepath.Join(dir, "dpi_discover.json"))
		d.SetFamilyPath(filepath.Join(dir, "dpi_ja4family.json"))
		return d
	}
	t0 := time.Unix(1_800_000_000, 0)
	d := mk()
	for i := 0; i < 4; i++ {
		burst(d, "aa:bb:cc:00:00:01", "JA4_A", t0.Add(time.Duration(i)*time.Minute), "api.fooapp.io", "img.foocdn.net")
	}
	for i := 0; i < 20; i++ {
		d.Observe("aa:bb:cc:00:00:01", "v.douyin.com", "JA4_A", t0, true, "douyin", "video")
	}
	if err := d.Flush(t0.Add(10 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	before := groupOf(d.Groups(t0.Add(10*time.Minute)), "fooapp.io")
	d2 := mk()
	if err := d2.Load(); err != nil {
		t.Fatal(err)
	}
	after := groupOf(d2.Groups(t0.Add(10*time.Minute)), "fooapp.io")
	if before == nil || after == nil || after.ID != before.ID || len(after.Suffixes) != 2 || after.Hits != before.Hits {
		t.Fatalf("reload mismatch:\nbefore %+v\nafter  %+v", before, after)
	}
	if after.Family != "bytedance" {
		t.Fatalf("family table not restored: %+v", after)
	}
	// 损坏文件: 忽略, 不报错
	d3 := NewDiscoverer()
	d3.SetPath(filepath.Join(dir, "nope.json"))
	if err := d3.Load(); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverNodeCapAndConcurrency(t *testing.T) {
	d := NewDiscoverer()
	t0 := time.Unix(1_800_000_000, 0)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 700; i++ {
				d.Observe(fmt.Sprintf("aa:bb:cc:00:00:%02x", w), fmt.Sprintf("h%d.dom%d-%d.io", i, w, i), "", t0.Add(time.Duration(i)*time.Second), false, "", "")
			}
		}(w)
	}
	wg.Add(1)
	go func() { defer wg.Done(); _ = d.Groups(t0) }()
	wg.Wait()
	d.mu.Lock()
	n, e := len(d.nodes), len(d.edges)
	d.mu.Unlock()
	if n > discMaxNodes || e > discMaxEdges {
		t.Fatalf("caps exceeded: nodes=%d edges=%d", n, e)
	}
}
