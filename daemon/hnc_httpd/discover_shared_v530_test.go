// discover_shared_v530_test.go — v5.30 T1c: 「新发现的应用」排除公共基础设施。
//
// 回归用例 = 用户截图: alibabadns.com 被起名「Apple 旗下应用 / 证书·Apple」、
// cdngslb.com 被起名「网易云音乐」、qtlcdn.com 被起名「好游快爆」, 以及
// ksyuncdn.com / lanniao.com / wechatpay.cn / tencentcos.cn 单独成组。
// dpi_discover.json 用升级前(v5.29 dpid 写出的、没有 shared 字段)的形状 ——
// 「已经在列表里的这些组升级后不再显示」。
//
// 「改动前会失败」: v5.29 的 /api/discover 原样列出这 7 个组, 名字就是截图
// 里的那三个(TestDiscoverScreenshotInfraHidden / TestDiscoverMixedGroupNaming /
// TestDiscoverCertMustCoverHost 全部失败)。
package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hnc.io/dpid/output"
)

// installShippedInfra 把模块自带名单装进临时 hncDir 的规则目录(与真机同路径)。
func installShippedInfra(t *testing.T, dir string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "data", "dpi_rules.d", output.SharedInfraFileName))
	if err != nil {
		t.Fatalf("模块自带名单: %v", err)
	}
	writeFileT(t, filepath.Join(dir, "etc", "dpi_rules.d", output.SharedInfraFileName), string(b))
}

func resetCertState(t *testing.T) {
	t.Helper()
	certState.mu.Lock()
	certState.loaded, certState.m = false, nil
	certState.mu.Unlock()
	t.Cleanup(func() {
		certState.mu.Lock()
		certState.loaded, certState.m = false, nil
		certState.mu.Unlock()
	})
}

func discoverGet(t *testing.T, s *server) map[string]map[string]interface{} {
	t.Helper()
	rr := httptest.NewRecorder()
	s.apiDiscover(rr, httptest.NewRequest("GET", "/api/discover", nil))
	var out struct {
		Groups []map[string]interface{} `json:"groups"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v %s", err, rr.Body.String())
	}
	m := map[string]map[string]interface{}{}
	for _, g := range out.Groups {
		m[asString(g["id"])] = g
	}
	return m
}

func groupName(g map[string]interface{}) string {
	sg, _ := g["suggest"].(map[string]interface{})
	gs, _ := g["guess"].(map[string]interface{})
	return asString(sg["name"]) + " / " + asString(gs["name"])
}

const screenshotDiscover = `{"schema":1,"generated_at":1800000000,"groups":[
 {"id":"g_ali","suffixes":["alibabadns.com"],"domains":[{"name":"ns1.alibabadns.com","count":30}],"devices":["aa:bb:cc:00:00:01","aa:bb:cc:00:00:02"],"hits":30},
 {"id":"g_gslb","suffixes":["cdngslb.com"],"domains":[{"name":"m1.cdngslb.com","count":20}],"devices":["aa:bb:cc:00:00:01"],"hits":20},
 {"id":"g_qtl","suffixes":["qtlcdn.com"],"domains":[{"name":"p1.qtlcdn.com","count":18}],"devices":["aa:bb:cc:00:00:01"],"hits":18},
 {"id":"g_ks","suffixes":["ksyuncdn.com"],"domains":[{"name":"x.ksyuncdn.com","count":9}],"hits":9},
 {"id":"g_ln","suffixes":["lanniao.com"],"domains":[{"name":"x.lanniao.com","count":9}],"hits":9},
 {"id":"g_wx","suffixes":["wechatpay.cn"],"domains":[{"name":"payapp.wechatpay.cn","count":9}],"hits":9},
 {"id":"g_cos","suffixes":["tencentcos.cn"],"domains":[{"name":"b-1.cos.ap-guangzhou.tencentcos.cn","count":9}],"hits":9},
 {"id":"g_mix","suffixes":["qtlcdn.com","coolgame.com","cdngslb.com"],
  "domains":[{"name":"p2.qtlcdn.com","count":50},{"name":"api.coolgame.com","count":20},{"name":"m2.cdngslb.com","count":10}],
  "members":[{"suffix":"qtlcdn.com","hits":50},{"suffix":"coolgame.com","hits":20},{"suffix":"cdngslb.com","hits":10}],
  "devices":["aa:bb:cc:00:00:01","aa:bb:cc:00:00:02"],"hits":80}]}`

const screenshotAPK = `{"schema":1,"generated_at":100,
 "apps":{"com.netease.cloudmusic":{"label":"网易云音乐"},"com.hykb.yuanshenmap":{"label":"好游快爆"},"com.cool.game":{"label":"酷玩游戏"}},
 "suffix_index":{"cdngslb.com":["com.netease.cloudmusic"],"qtlcdn.com":["com.hykb.yuanshenmap"],"coolgame.com":["com.cool.game"]}}`

func screenshotServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	installShippedInfra(t, dir)
	writeFileT(t, filepath.Join(dir, "run", "dpi_discover.json"), screenshotDiscover)
	writeFileT(t, filepath.Join(dir, "run", "apk_domains.json"), screenshotAPK)
	// 升级前就缓存好的证书: alibabadns 的服务器回了一张 Apple 的证书(不覆盖它)
	writeFileT(t, filepath.Join(dir, "run", "cert_cache.json"), `{
 "g_ali":{"host":"ns1.alibabadns.com","org":"Apple Inc.","sans":["*.apple.com","apple.com"],"ts":1},
 "g_mix":{"host":"p2.qtlcdn.com","org":"Hangzhou Alibaba Advertising Co.,Ltd.","sans":["*.qtlcdn.com"],"ts":1}}`)
	resetCertState(t)
	return newServer(dir)
}

func TestDiscoverScreenshotInfraHidden(t *testing.T) {
	gs := discoverGet(t, screenshotServer(t))
	for _, id := range []string{"g_ali", "g_gslb", "g_qtl", "g_ks", "g_ln", "g_wx", "g_cos"} {
		if g, ok := gs[id]; ok {
			t.Errorf("%s 是公共基础设施, 不应出现在「新发现的应用」: %v(名字 %s)", id, g["suffixes"], groupName(g))
		}
	}
	for id, g := range gs {
		for _, bad := range []string{"Apple", "网易云音乐", "好游快爆"} {
			if strings.Contains(groupName(g), bad) {
				t.Errorf("%s 的名字 %q 仍来自共享域(%s)", id, groupName(g), bad)
			}
		}
	}
}

// 混合组: 应用自己的域名留下, CDN 挂到 shared(公共服务), 起名只看自己的域名。
func TestDiscoverMixedGroupNaming(t *testing.T) {
	g := discoverGet(t, screenshotServer(t))["g_mix"]
	if g == nil {
		t.Fatal("g_mix 有自己的域名, 应该显示")
	}
	if sufs := strList(g["suffixes"]); len(sufs) != 1 || sufs[0] != "coolgame.com" {
		t.Fatalf("suffixes = %v, want [coolgame.com]", sufs)
	}
	for _, d := range g["domains"].([]interface{}) {
		if n := asString(d.(map[string]interface{})["name"]); !strings.HasSuffix(n, "coolgame.com") {
			t.Errorf("domains 里不应有共享域: %s", n)
		}
	}
	sh, _ := g["shared"].([]interface{})
	got := map[string]string{}
	for _, x := range sh {
		m := x.(map[string]interface{})
		got[asString(m["suffix"])] = asString(m["label"])
	}
	if got["qtlcdn.com"] != "公共服务" || got["cdngslb.com"] != "公共服务" || len(got) != 2 {
		t.Fatalf("shared = %v", sh)
	}
	if name := groupName(g); !strings.HasPrefix(name, "酷玩游戏 / 酷玩游戏") {
		t.Fatalf("名字应来自组自己的域名(本机 App 酷玩游戏), got %q", name)
	}
	for _, a := range g["apk"].([]interface{}) {
		if l := asString(a.(map[string]interface{})["label"]); l != "酷玩游戏" {
			t.Errorf("本机 App 证据不应来自共享域: %s", l)
		}
	}
	// 旧证书是对 p2.qtlcdn.com 取的 —— 它已不属于本组, 不当证据
	if g["company"] != nil || g["cert_unused"] == nil {
		t.Fatalf("company=%v cert_unused=%v", g["company"], g["cert_unused"])
	}
}

// 证书 SAN 不覆盖探测的主机名 → 不当证据(非名单域名也一样)。
func TestDiscoverCertMustCoverHost(t *testing.T) {
	dir := t.TempDir()
	writeFileT(t, filepath.Join(dir, "run", "dpi_discover.json"), `{"schema":1,"groups":[
 {"id":"g_odd","suffixes":["oddapp.io"],"domains":[{"name":"api.oddapp.io","count":9}],"hits":9},
 {"id":"g_ok","suffixes":["goodapp.io"],"domains":[{"name":"api.goodapp.io","count":9}],"hits":9}]}`)
	writeFileT(t, filepath.Join(dir, "run", "cert_cache.json"), `{
 "g_odd":{"host":"api.oddapp.io","org":"Tencent Technology (Shenzhen) Company Limited","sans":["*.qq.com"],"ts":1},
 "g_ok":{"host":"api.goodapp.io","org":"Tencent Technology (Shenzhen) Company Limited","sans":["*.goodapp.io"],"ts":1}}`)
	resetCertState(t)
	gs := discoverGet(t, newServer(dir))
	if odd := gs["g_odd"]; odd["company"] != nil || strings.Contains(groupName(odd), "腾讯") || odd["cert_unused"] == nil {
		t.Fatalf("不覆盖的证书不应当证据: company=%v name=%q unused=%v", odd["company"], groupName(odd), odd["cert_unused"])
	}
	if ok := gs["g_ok"]; ok["company"] != "腾讯" || !strings.HasPrefix(groupName(ok), "腾讯 旗下应用") {
		t.Fatalf("覆盖的证书照常用: company=%v name=%q", ok["company"], groupName(ok))
	}
}

// dpid 频度兜底判出的(顶层 shared_infra / 组的 shared)httpd 同样剔除。
func TestDiscoverDpidFreqSharedFiltered(t *testing.T) {
	dir := t.TempDir()
	writeFileT(t, filepath.Join(dir, "run", "dpi_discover.json"), `{"schema":1,
 "shared_infra":[{"suffix":"bridge-cdn.com","reason":"freq","hits":99,"devices":5,"since":1800000000}],
 "groups":[
 {"id":"g_br","suffixes":["bridge-cdn.com"],"domains":[{"name":"e.bridge-cdn.com","count":40}],"hits":40},
 {"id":"g_app","suffixes":["app1.io","odd-edge.net"],"domains":[{"name":"api.app1.io","count":9},{"name":"x.odd-edge.net","count":3}],"hits":12,
  "shared":[{"suffix":"odd-edge.net","reason":"freq","hits":3}]}]}`)
	resetCertState(t)
	gs := discoverGet(t, newServer(dir))
	if _, ok := gs["g_br"]; ok {
		t.Fatal("顶层 shared_infra 里的域名不应单独成组")
	}
	app := gs["g_app"]
	if sufs := strList(app["suffixes"]); len(sufs) != 1 || sufs[0] != "app1.io" {
		t.Fatalf("组内被 dpid 标为 shared 的域名应剔除: %v", sufs)
	}
}

func TestCertCoversHost(t *testing.T) {
	ci := certInfo{SANs: []string{"*.example.com", "example.org"}}
	for host, want := range map[string]bool{
		"a.example.com": true, "example.com": false, "a.b.example.com": false,
		"example.org": true, "x.example.org": false, "": false,
	} {
		if got := certCoversHost(ci, host); got != want {
			t.Errorf("certCoversHost(%q) = %v, want %v", host, got, want)
		}
	}
	if !certCoversHost(certInfo{CN: "api.x.io"}, "api.x.io") {
		t.Error("没有 SAN 时用 CN")
	}
}

// 识别自评与线上一致: 名单里的域名不进聚类事件 / 真值。
func TestEvalDiscoverSkipsSharedInfra(t *testing.T) {
	si := output.ParseSharedInfra([]byte("qtlcdn.com\n"))
	var ss []evalSample
	for i := 0; i < 6; i++ {
		ss = append(ss,
			evalSample{SNI: "api.coolgame.com", Pkg: "com.cool.game", Ts: int64(1800000000 + i*60)},
			evalSample{SNI: "p1.qtlcdn.com", Pkg: "com.cool.game", Ts: int64(1800000001 + i*60)})
	}
	if all, filtered := evalDiscover(ss, nil), evalDiscover(ss, si); filtered.Samples != all.Samples/2 {
		t.Fatalf("名单里的样本应排除: all=%d filtered=%d", all.Samples, filtered.Samples)
	}
}
