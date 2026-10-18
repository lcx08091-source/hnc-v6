package main

// app_activity_test.go — v5.34 应用内活动细分。
// 「改动前会失败」: 没有 app_activity.go / fgView.Activity, 前台只知道「在用哪个应用」。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 用仓库里的 data/app_activity.json(测试结束恢复原来的规则)
func appActUseRepoData(t *testing.T) {
	t.Helper()
	old := appActCur.Load()
	t.Cleanup(func() { appActCur.Store(old) })
	set := appActLoad(filepath.Join("..", "..", "data", "app_activity.json"))
	if set == nil {
		t.Fatal("data/app_activity.json 读不出来")
	}
	appActCur.Store(set)
}

func TestAppActDomainUse(t *testing.T) {
	appActUseRepoData(t)
	set := appActCur.Load()
	cases := []struct{ app, host, want string }{
		{"douyin", "v26-dy.douyinvod.com", ttVideo},
		{"douyin", "pull-flv-l11.douyincdn.com", ttLive},
		{"douyin", "p3-sign.douyincdn.com", ""}, // 没有 pull- 前缀
		{"douyin", "xdouyinvod.com", ""},        // 不按标签边界的后缀不算
		{"kuaishou", "ali-adapt.pull.yximgs.com", ttLive},
		{"huya", "al.flv.huya.com", ttLive},
		{"taobao", "v26-dy.douyinvod.com", ""}, // 域名规则只对归到该应用的连接生效
		{"douyin", "", ""},
	}
	for _, c := range cases {
		if got := appActDomainUse(set, c.app, c.host); got != c.want {
			t.Errorf("%s %s: %q, 期望 %q", c.app, c.host, got, c.want)
		}
	}
	// 域名规则优先于流形态; 流形态置信度不够不参与
	if tag, src := appActivityTag("douyin", "pull-hls-l3.douyincdn.com", ttVideo, 0.9); tag != ttLive || src != "domain" {
		t.Fatalf("domain first: %s %s", tag, src)
	}
	if tag, src := appActivityTag("douyin", "api.amemv.com", ttVideo, 0.7); tag != ttVideo || src != "shape" {
		t.Fatalf("shape: %s %s", tag, src)
	}
	if tag, _ := appActivityTag("douyin", "api.amemv.com", ttVideo, 0.3); tag != "" {
		t.Fatalf("低置信度的流形态不应参与: %s", tag)
	}
	if tag, _ := appActivityTag("douyin", "", ttUnknown, 0.9); tag != "" {
		t.Fatalf("unknown 不是标签: %s", tag)
	}
}

func TestAppActLabels(t *testing.T) {
	appActUseRepoData(t)
	cases := []struct{ app, cat, tag, want string }{
		{"douyin", "video", ttVideo, "刷短视频"}, // 应用专属
		{"douyin", "video", ttLive, "看直播"},
		{"iqiyi", "video", ttVideo, "看视频"}, // 类别
		{"wechat", "social", ttVoice, "语音通话"},
		{"tencent_wzry_exclusive", "game", ttDownload, "下载更新"},
		{"some_game", "game-moba", ttGaming, "对局中"}, // game 开头的类别按 game
		{"quark", "browser", ttBrowsing, "浏览"},      // 通用
		{"netease_music", "music", ttLive, "听歌"},
	}
	for _, c := range cases {
		if got := appActLabel(c.app, c.cat, c.tag); got != c.want {
			t.Errorf("%s/%s/%s: %q, 期望 %q", c.app, c.cat, c.tag, got, c.want)
		}
	}
	// 没有规则文件 → 只用通用说法
	appActCur.Store(nil)
	if got := appActLabel("douyin", "video", ttVideo); got != trafficTypeLabels[ttVideo] {
		t.Fatalf("无规则文件: %q", got)
	}
}

// 规则文件里的应用都在规则库里(防止改名 / 删规则后说法悄悄失效), 标签和长度合法
func TestAppActDataMatchesRuleLibrary(t *testing.T) {
	ids := map[string]bool{}
	files, _ := filepath.Glob(filepath.Join("..", "..", "data", "dpi_rules.d", "*.json"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var d struct {
			Rules []struct {
				ID     string `json:"id"`
				Parent string `json:"_parent_rule_id"`
			} `json:"rules"`
		}
		_ = json.Unmarshal(b, &d)
		for _, r := range d.Rules {
			if r.Parent == "" {
				ids[r.ID] = true
			}
		}
	}
	if len(ids) < 100 {
		t.Fatalf("规则库只读到 %d 个应用", len(ids))
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "data", "app_activity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw appActSet
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	clean := appActLoad(filepath.Join("..", "..", "data", "app_activity.json"))
	for id, a := range raw.Apps {
		if !ids[id] {
			t.Errorf("app_activity.json 的 %s 不是规则库里的应用 id", id)
		}
		if len(clean.Apps[id].Labels) != len(a.Labels) || len(clean.Apps[id].Domains) != len(a.Domains) {
			t.Errorf("%s 有被丢弃的条目(标签不合法 / 太长 / 域名不合法)", id)
		}
	}
	for cat, m := range raw.Categories {
		if len(clean.Categories[cat]) != len(m) {
			t.Errorf("类别 %s 有被丢弃的条目", cat)
		}
	}
}

func TestAppActTrack(t *testing.T) {
	appActUseRepoData(t)
	var s appActTrack
	// 视频: 每轮 20 MB(流形态)
	for i := 0; i < 3; i++ {
		s.actStep(map[string]uint64{ttVideo: 20 << 20}, nil, 10, "douyin", "video")
	}
	if s.result == nil || s.result.ID != ttVideo || s.result.Label != "刷短视频" || s.result.Src != "shape" || s.result.Conf > 0.8 {
		t.Fatalf("video: %+v", s.result)
	}
	// 切到直播(域名规则): 第一轮不切(防抖), 第二轮切
	s.actStep(map[string]uint64{ttLive: 40 << 20}, map[string]uint64{ttLive: 40 << 20}, 10, "douyin", "video")
	if s.result == nil || s.result.ID != ttVideo {
		t.Fatalf("单轮就切了: %+v", s.result)
	}
	s.actStep(map[string]uint64{ttLive: 40 << 20}, map[string]uint64{ttLive: 40 << 20}, 10, "douyin", "video")
	if s.result == nil || s.result.ID != ttLive || s.result.Label != "看直播" || s.result.Src != "domain" {
		t.Fatalf("live: %+v", s.result)
	}
	// 没流量: 衰减到不判
	for i := 0; i < 60; i++ {
		s.actStep(nil, nil, 10, "douyin", "video")
	}
	if s.result != nil {
		t.Fatalf("idle 应清空: %+v", s.result)
	}

	// 微信: 语音通话字节很少, 但实时类权重高, 压过同时在后台缓存的视频号
	var w appActTrack
	for i := 0; i < 4; i++ {
		w.actStep(map[string]uint64{ttVoice: 60 << 10, ttVideo: 150 << 10}, nil, 10, "wechat", "social")
	}
	if w.result == nil || w.result.ID != ttVoice || w.result.Label != "语音通话" {
		t.Fatalf("voice vs video: %+v", w.result)
	}
	// 一半一半的混合 → 置信度不够不显示
	var m appActTrack
	m.actStep(map[string]uint64{ttBrowsing: 1 << 20, ttVideo: 1 << 20, ttDownload: 1 << 20}, nil, 10, "quark", "browser")
	if m.result != nil {
		t.Fatalf("三类各占三分之一不该给结论: %+v", m.result)
	}
}

// 记账: 一条差分的主机名取连接自己的 SNI, 流形态取 flow_shape 本轮的判类
func TestAppActForDelta(t *testing.T) {
	appActUseRepoData(t)
	_, st, names, _ := sniFixture(t) // fp_sni_test.go: sniKeyDY 的 SNI 是 v3-dy.douyinvod.com
	ix := &identCtx{fp: st}
	dl := appUsageDelta{Src: "192.168.43.10", Dst: sniCDN, Up: 1, Dn: 2, Key: sniKeyDY}
	if tag, src := appActForDelta(ix, "douyin", dl, names); tag != ttVideo || src != "domain" {
		t.Fatalf("SNI 命中域名规则: %s %s", tag, src)
	}
	fsPub.mu.Lock()
	old := fsPub.flows
	k := "tcp|192.168.43.10|42999|198.51.100.9|443"
	fsPub.flows = map[string]fsFlowPub{k: {typ: ttUpload, conf: 0.8}}
	fsPub.mu.Unlock()
	t.Cleanup(func() { fsPub.mu.Lock(); fsPub.flows = old; fsPub.mu.Unlock() })
	if tag, src := appActForDelta(ix, "douyin", appUsageDelta{Dst: "198.51.100.9", Key: k}, names); tag != ttUpload || src != "shape" {
		t.Fatalf("流形态: %s %s", tag, src)
	}
}

// 前台模型: 抖音成为前台后 fg.activity 跟着变; 过期视图不给活动
func TestFgActivityInView(t *testing.T) {
	appActUseRepoData(t)
	b := newFgTB(t, fgStart())
	b.tick(tk)
	live := func() []fgObs {
		o := fob("douyin", "抖音", "video", b.key("live", "7.7.7.7"), 20<<10, 3<<20)
		o.Act, o.ActSrc = ttLive, "domain"
		o2 := fob("douyin", "抖音", "video", b.newKey("7.7.7.8"), 4<<10, 40<<10)
		o2.Act, o2.ActSrc = ttBrowsing, "shape"
		return []fgObs{o, o2}
	}
	var v fgView
	for i := 0; i < 6; i++ {
		v = b.tick(tk, live())
	}
	if v.AppID != "douyin" || v.Activity == nil || v.Activity.ID != ttLive || v.Activity.Label != "看直播" || v.Activity.Src != "domain" {
		t.Fatalf("view: %+v act=%+v", v, v.Activity)
	}
	js, _ := json.Marshal(v)
	if !strings.Contains(string(js), `"activity":{"id":"live_stream","label":"看直播"`) {
		t.Fatalf("json: %s", js)
	}
	st := fgApplyStale(v, b.now.Add(10*time.Minute), "", tk)
	if !st.Stale || st.Activity != nil {
		t.Fatalf("过期视图不该再说「此刻在做什么」: %+v", st)
	}
}
