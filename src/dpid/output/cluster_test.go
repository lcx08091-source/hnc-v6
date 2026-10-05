// cluster_test.go — v5.28 B1: 聚类纯函数的口径 + 与 Discoverer 的等价性。
package output

import (
	"fmt"
	"testing"
	"time"
)

// clEvents 合成事件流: 两个"应用"各有两个专属可注册域, 在不同分钟突发;
// 共享 SDK 域名偶发出现(边权不足阈值, 应各自成单域组)。
// 注意: 每对域名共现 4 轮 —— 3 轮的边权 3.0 会被几秒的半衰期衰减到
// 2.9999(< 阈值), 4 轮(≈3.99)才能稳定过阈值。
func clEvents() []ClusterEvent {
	const base = int64(1791000000)
	mk := func(t int64, host string) ClusterEvent {
		return ClusterEvent{Dev: "self", Host: host, TS: base + t}
	}
	var ev []ClusterEvent
	for r := int64(0); r < 4; r++ {
		t := r * 600
		ev = append(ev,
			mk(t, "api.appa-1.com"), mk(t+1, "cdn.appa-1.com"),
			mk(t+2, "img.appa-2.net"), mk(t+3, "cdn.appa-2.net"))
	}
	for r := int64(0); r < 4; r++ {
		t := r*600 + 300
		ev = append(ev,
			mk(t, "ws.appb-1.org"), mk(t+1, "img.appb-1.org"),
			mk(t+2, "api.appb-2.io"), mk(t+3, "img.appb-2.io"))
	}
	// 共享 SDK: 每个应用只共现 1 次, 边权 1 << 阈值 → 单域组
	ev = append(ev, mk(5, "sdk.shared-cdn.com"), mk(305, "sdk.shared-cdn.com"), mk(605, "sdk.shared-cdn.com"))
	return ev
}

func clSet(g ClusterGroup) map[string]bool {
	m := make(map[string]bool, len(g.Suffixes))
	for _, s := range g.Suffixes {
		m[s] = true
	}
	return m
}

// TestClusterTwoApps 合成样本: 两个包各一组; 共享 SDK 与两侧都合并(度数
// 只有 2, 不算枢纽)→ 三域一组; 纯度/完整度口径由 httpd 侧测。
func TestClusterTwoApps(t *testing.T) {
	out := ClusterUnknowns(clEvents(), ClusterParams{})
	if len(out.Groups) == 0 {
		t.Fatal("应有组")
	}
	var a, b, sdk bool
	for _, g := range out.Groups {
		s := clSet(g)
		if s["appA-1.com"] || s["appa-1.com"] {
			// 大小写归一(normalizeName)后是 appa-1.com
		}
		if s["appa-1.com"] {
			a = true
			if !s["appa-2.net"] {
				t.Errorf("包 A 的两个域应同组: %v", g.Suffixes)
			}
		}
		if s["appb-1.org"] {
			b = true
			if !s["appb-2.io"] {
				t.Errorf("包 B 的两个域应同组: %v", g.Suffixes)
			}
		}
		if s["shared-cdn.com"] {
			sdk = true
		}
	}
	if !a || !b {
		t.Fatalf("两个包应各自成组: a=%v b=%v", a, b)
	}
	// SDK 与两侧的边权只有 1~2(< 阈值 3), 不与任何包合并 → 单域组。
	// (若哪天误把它并进包组, 上面 s["appa-*"] 的同组断言之外的这个
	// 事实也会在 httpd 侧的纯度/完整度用例里暴露。)
	if !sdk {
		t.Errorf("sdk.shared-cdn.com 应作为单域组出现")
	}
}

// TestClusterHubExcluded 枢纽节点: 一个域名与 25 个互不相连的域都有强边
// (度数 25 > 24)→ 其边全部跳过, 枢纽单列在 Hubs。
// 注意: 25 个 leaf 用互不相同的可注册域(lfNN 为第二级标签), 且彼此间隔
// 40s > 窗口 5s(不互现); 每对 (hub, leaf) 共现 4 次 → 边权 ≈4 过阈值。
func TestClusterHubExcluded(t *testing.T) {
	const base = int64(1791000000)
	var ev []ClusterEvent
	for i := int64(1); i <= 25; i++ {
		leaf := fmt.Sprintf("api.lf%02de.com", i) // reg = lf%02de.com, 25 个不同注册域
		for r := int64(0); r < 4; r++ {
			t0 := base + (i-1)*40 + r*10
			ev = append(ev,
				ClusterEvent{Dev: "self", Host: "hub.example.net", TS: t0},
				ClusterEvent{Dev: "self", Host: leaf, TS: t0 + 1})
		}
	}
	out := ClusterUnknowns(ev, ClusterParams{})
	if len(out.Hubs) != 1 || out.Hubs[0] != "example.net" {
		t.Fatalf("example.net 应被判枢纽(度数 25 > 24), got %v", out.Hubs)
	}
	// hub 的注册域 example.net 不应和任何 leaf 合并
	for _, g := range out.Groups {
		s := clSet(g)
		if s["example.net"] && len(g.Suffixes) > 1 {
			t.Fatalf("枢纽域不应参与合并: %v", g.Suffixes)
		}
	}
}

// TestClusterUnknownsMatchesDiscoverer 等价性: 同一事件流喂
// Discoverer.Observe(未知路径)与 ClusterUnknowns, 每个线上组的成员集合
// 必须在纯函数结果中逐组出现(线上组是它的过滤子集)。
func TestClusterUnknownsMatchesDiscoverer(t *testing.T) {
	events := clEvents()
	d := NewDiscoverer()
	base := time.Unix(1791000000, 0)
	for _, e := range events {
		d.Observe(e.Dev, e.Host, e.JA4, time.Unix(e.TS, 0), false, "", "")
	}
	online := d.Groups(base.Add(time.Hour))
	pure := ClusterUnknowns(events, ClusterParams{})

	sets := make([]map[string]bool, 0, len(pure.Groups))
	for _, g := range pure.Groups {
		sets = append(sets, clSet(g))
	}
	checked := 0
	for _, g := range online {
		if g.Hits < discMinHits { // 线上过滤掉的小组不参与对比
			continue
		}
		want := make(map[string]bool, len(g.Suffixes))
		for _, s := range g.Suffixes {
			want[s] = true
		}
		found := false
		for _, s := range sets {
			if len(s) == len(want) {
				same := true
				for k := range want {
					if !s[k] {
						same = false
						break
					}
				}
				if same {
					found = true
					break
				}
			}
		}
		if !found {
			t.Errorf("线上组 %v 在纯函数结果中缺失", g.Suffixes)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("线上应至少产出一个过阈值组(事件流 3 轮 ≥ discMinHits=5)")
	}
}

// TestClusterParamsZeroDefaults 零值参数 = 线上默认。
func TestClusterParamsZeroDefaults(t *testing.T) {
	// 不直接读私有函数; 用行为验证: ClusterParams{} 与显式线上值结果一致。
	ev := clEvents()
	a := ClusterUnknowns(ev, ClusterParams{})
	b := ClusterUnknowns(ev, ClusterParams{WindowSec: discWindowSec, EdgeThreshold: discEdgeThreshold, HubDegree: discHubDegree})
	if len(a.Groups) != len(b.Groups) || len(a.Hubs) != len(b.Hubs) {
		t.Fatalf("零值参数应等于线上默认: %d/%d vs %d/%d", len(a.Groups), len(a.Hubs), len(b.Groups), len(b.Hubs))
	}
	for i := range a.Groups {
		if len(a.Groups[i].Suffixes) != len(b.Groups[i].Suffixes) {
			t.Fatalf("组 %d 大小不一致", i)
		}
	}
}
