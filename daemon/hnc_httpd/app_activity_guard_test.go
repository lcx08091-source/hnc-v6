package main

// app_activity_guard_test.go — v5.34.0-rc2: 讨论(四方核对过代码)确认的 rc1 误判与隐私开关。
// 「改动前会失败」(rc1):
//   - B站 P2P 的双向 UDP 被 flow_shape 判成 video_call → 「B站 · 视频通话」;
//   - 会议旁听 / 通话关摄像头(下行稳定)→ 「看直播」;
//   - HNC 自己限速把点播削成恒速 → 「看直播」;
//   - 看评论时抖音在预取, douyinvod 域名规则照样满分判「刷短视频」;
//   - 省电档 / VPN / 硬件加速旁路时照样输出;
//   - 没有开关, 对所有设备默认计算和显示。

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// appActOn 测试期间打开总开关, 结束恢复
func appActOn(t *testing.T) {
	t.Helper()
	old := appActEnabled.Load()
	appActEnabled.Store(true)
	t.Cleanup(func() { appActEnabled.Store(old) })
}

func appActWithGuard(t *testing.T, g *appActGuard) {
	t.Helper()
	old := appActGuardCur.Load()
	appActGuardCur.Store(g)
	t.Cleanup(func() { appActGuardCur.Store(old) })
}

// 只有该应用 / 该类别写了说法的标签才参与; domain_only 的标签只认域名
func TestAppActShapeWhitelist(t *testing.T) {
	appActUseRepoData(t)
	cases := []struct {
		app, cat, shape string
		udp             bool
		want            string
		why             string
	}{
		{"bilibili", "video", ttVideoCall, true, "", "B站 P2P 双向 UDP 不能说成视频通话"},
		{"douyin", "video", ttVoice, true, "", "视频类应用没有通话"},
		{"wechat", "social", ttVideoCall, true, ttVideoCall, "微信视频通话"},
		{"wechat", "social", ttVoice, true, ttVoice, "微信语音通话"},
		{"tencent_meeting", "office", ttLive, true, ttVoice, "会议旁听(单向 UDP)算开会, 不是看直播"},
		{"tencent_meeting", "office", ttLive, false, "", "办公类没有直播"},
		{"wechat", "social", ttLive, false, "", "社交类的直播只认域名(视频号直播)"},
		{"wechat", "social", ttLive, true, ttVoice, "通话里对方开摄像头、自己关: 单向 UDP 算通话"},
		{"some_ai", "ai", ttBrowsing, false, "", "没有说法的类别宁可不说"},
		{"tencent_wzry_exclusive", "game", ttGaming, true, ttGaming, "对局中"},
		{"bilibili", "video", ttLive, false, ttLive, "视频类的直播形态照常(还要过限速守卫)"},
	}
	for _, c := range cases {
		if tag, _ := appActivityTag(c.app, c.cat, "", c.shape, 0.8, c.udp); tag != c.want {
			t.Errorf("%s: %s/%s/%s udp=%v → %q, 期望 %q", c.why, c.app, c.cat, c.shape, c.udp, tag, c.want)
		}
	}
}

// 域名和流形态冲突(预取)→ 域名证据降级, 不再满分
func TestAppActDomainConflictWeak(t *testing.T) {
	appActUseRepoData(t)
	tag, src := appActivityTag("douyin", "video", "v3-dy.douyinvod.com", ttBrowsing, 0.8, false)
	if tag != ttVideo || src != "domain_weak" {
		t.Fatalf("冲突: %s %s", tag, src)
	}
	if tag, src := appActivityTag("douyin", "video", "v3-dy.douyinvod.com", ttVideo, 0.8, false); tag != ttVideo || src != "domain" {
		t.Fatalf("一致: %s %s", tag, src)
	}
	var s appActTrack
	for i := 0; i < 3; i++ {
		s.actStep(map[string]uint64{ttVideo: 20 << 20}, nil, 10, "douyin", "video") // domain_weak 不计入域名字节
	}
	if s.result == nil || s.result.Src != "shape" || s.result.Conf > appActShapeFactor || s.result.Label != "刷抖音" {
		t.Fatalf("降级后的结果: %+v", s.result)
	}
}

// 设备 / 应用被 HNC 限速: 流形态来的视频、直播不可信; 域名来的和通话照常
func TestAppActLimitedDevice(t *testing.T) {
	appActUseRepoData(t)
	appActOn(t)
	const mac = "aa:bb:cc:00:44:01"
	appActWithGuard(t, &appActGuard{limited: map[string]bool{mac: true}, limitedApp: map[string]bool{}})
	fsPub.mu.Lock()
	old := fsPub.flows
	fsPub.flows = map[string]fsFlowPub{
		"tcp|192.168.43.10|40001|198.51.100.1|443":  {typ: ttLive, conf: 0.9},
		"udp|192.168.43.10|40002|198.51.100.2|8000": {typ: ttVoice, conf: 0.9},
	}
	fsPub.mu.Unlock()
	t.Cleanup(func() { fsPub.mu.Lock(); fsPub.flows = old; fsPub.mu.Unlock() })
	names := map[string]ipName{"198.51.100.3": {Name: "pull-flv-l1.douyincdn.com"}}
	dlLive := appUsageDelta{Dst: "198.51.100.1", Key: "tcp|192.168.43.10|40001|198.51.100.1|443"}
	if tag, _ := appActForDelta(nil, mac, "bilibili", "video", dlLive, names); tag != "" {
		t.Fatalf("限速时点播被削平, 流形态的「直播」不可信: %s", tag)
	}
	if tag, _ := appActForDelta(nil, "aa:bb:cc:00:44:02", "bilibili", "video", dlLive, names); tag != ttLive {
		t.Fatalf("没限速的设备照常: %s", tag)
	}
	dlPull := appUsageDelta{Dst: "198.51.100.3", Key: "tcp|192.168.43.10|40003|198.51.100.3|443"}
	if tag, src := appActForDelta(nil, mac, "douyin", "video", dlPull, names); tag != ttLive || src != "domain" {
		t.Fatalf("拉流域名不受限速影响: %s %s", tag, src)
	}
	dlCall := appUsageDelta{Dst: "198.51.100.2", Key: "udp|192.168.43.10|40002|198.51.100.2|8000"}
	if tag, _ := appActForDelta(nil, mac, "wechat", "social", dlCall, names); tag != ttVoice {
		t.Fatalf("限速不影响通话判断: %s", tag)
	}
	// 只限了这个应用(应用限速)也一样
	appActWithGuard(t, &appActGuard{limited: map[string]bool{}, limitedApp: map[string]bool{"aa:bb:cc:00:44:03|bilibili": true}})
	if tag, _ := appActForDelta(nil, "aa:bb:cc:00:44:03", "bilibili", "video", dlLive, names); tag != "" {
		t.Fatalf("应用限速: %s", tag)
	}
	// 总开关关着: 不打标签
	appActEnabled.Store(false)
	if tag, _ := appActForDelta(nil, "aa:bb:cc:00:44:02", "bilibili", "video", dlLive, names); tag != "" {
		t.Fatalf("总开关关着不该计算: %s", tag)
	}
}

// 输出闸门: 关着 / 省电档 / VPN / 硬件加速旁路 → 不说
func TestAppActGate(t *testing.T) {
	a := &fgActivity{ID: ttLive, Label: "看直播", Conf: 0.8, Src: "domain"}
	const mac = "aa:bb:cc:00:45:01"
	appActWithGuard(t, &appActGuard{vpn: map[string]bool{"aa:bb:cc:00:45:02": true}})
	old := appActEnabled.Load()
	t.Cleanup(func() { appActEnabled.Store(old) })
	appActEnabled.Store(false)
	if appActGate(mac, a, 10) != nil {
		t.Fatal("总开关关着")
	}
	appActEnabled.Store(true)
	if appActGate(mac, a, 10) == nil {
		t.Fatal("正常情况应输出")
	}
	if appActGate(mac, a, 60) != nil {
		t.Fatal("省电档(60 秒一轮)不该输出")
	}
	if appActGate("aa:bb:cc:00:45:02", a, 10) != nil {
		t.Fatal("疑似 VPN 不该输出")
	}
	appActWithGuard(t, &appActGuard{offload: true})
	if appActGate(mac, a, 10) != nil {
		t.Fatal("硬件加速旁路时计数不全, 不该输出")
	}
	// 读接口时总开关已关 → 视图里的活动立即消失(不等下一轮)
	appActWithGuard(t, nil)
	v := fgView{State: "active", AppID: "douyin", Activity: a, Updated: time.Now().Unix()}
	appActEnabled.Store(false)
	if fgApplyStale(v, time.Now(), "", 10*time.Second).Activity != nil {
		t.Fatal("关掉后接口不该再返回")
	}
}

// 总开关: data/dpi_experiment.json 的 activity_detail, 默认关; 动作写文件、立即生效、保留其它键
func TestAppActDetailSwitch(t *testing.T) {
	dir := fptDir(t)
	old := appActEnabled.Load()
	t.Cleanup(func() { appActEnabled.Store(old) })
	if appActEnabledFor(dir) {
		t.Fatal("默认应关闭")
	}
	_ = os.WriteFile(fgExperimentPath(dir), []byte(`{"fg_engine":"hmm"}`), 0o644)
	if r := actionDPIActivityDetail(dir, map[string]string{"enabled": "1"}); !r.OK {
		t.Fatalf("开: %+v", r)
	}
	if !appActEnabled.Load() || !appActEnabledFor(dir) || fgEngineFor(dir) != fgEngineHMM {
		t.Fatal("打开后应立即生效且保留 fg_engine")
	}
	if r := actionDPIActivityDetail(dir, map[string]string{"enabled": "0"}); !r.OK || appActEnabled.Load() || appActEnabledFor(dir) {
		t.Fatalf("关: %+v", r)
	}
	if r := actionDPIActivityDetail(dir, map[string]string{"enabled": "maybe"}); r.OK {
		t.Fatal("非法参数应拒绝")
	}
	if r := dispatchAction(newServer(dir), "dpi_activity_detail", map[string]string{"enabled": "1"}, true); !r.OK {
		t.Fatalf("dispatch: %+v", r)
	}
	rec := httptest.NewRecorder()
	newServer(dir).apiFgCompare(rec, httptest.NewRequest("GET", "/api/fg_compare?days=1", nil))
	var resp struct {
		ActivityDetail bool `json:"activity_detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !resp.ActivityDetail {
		t.Fatalf("fg_compare: %s", rec.Body.String())
	}
	b, _ := os.ReadFile(filepath.Join(dir, "data", "dpi_experiment.json"))
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	if m["fg_engine"] != "hmm" || m["activity_detail"] != true {
		t.Fatalf("文件: %s", b)
	}
}

// 守卫来源: 总开关关着不读任何文件; 开着时汇总设备限速 / 配额分时段 / 全局整形 / 应用限速
func TestAppActGuardRefresh(t *testing.T) {
	dir := fptDir(t)
	old, oldG := appActEnabled.Load(), appActGuardCur.Load()
	t.Cleanup(func() { appActEnabled.Store(old); appActGuardCur.Store(oldG) })
	now := time.Now()
	appActGuardRefresh(dir, map[string]bool{"aa:bb:cc:00:46:01": true}, now)
	if appActEnabled.Load() || appActGuardCur.Load() != nil {
		t.Fatal("默认关: 不该有守卫")
	}
	_ = os.WriteFile(fgExperimentPath(dir), []byte(`{"activity_detail":true}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"devices":{"AA:BB:CC:00:46:02":{"limit_enabled":true,"down_mbps":2}}}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, appLimitsJSONRelPath), []byte(`{"version":1,"items":[{"mac":"AA:BB:CC:00:46:03","app_id":"bilibili","down_mbps":3}]}`), 0o644)
	appActGuardRefresh(dir, map[string]bool{"aa:bb:cc:00:46:01": true}, now)
	g := appActGuardCur.Load()
	if !appActEnabled.Load() || g == nil {
		t.Fatal("打开后应有守卫")
	}
	if !appActLimited(g, "aa:bb:cc:00:46:01", "douyin") || !appActLimited(g, "aa:bb:cc:00:46:02", "douyin") ||
		!appActLimited(g, "aa:bb:cc:00:46:03", "bilibili") || appActLimited(g, "aa:bb:cc:00:46:03", "douyin") ||
		appActLimited(g, "aa:bb:cc:00:46:04", "douyin") {
		t.Fatalf("限速来源: %+v", g)
	}
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"global_shaper_enabled":"true","devices":{}}`), 0o644)
	appActGuardRefresh(dir, nil, now)
	if !appActLimited(appActGuardCur.Load(), "aa:bb:cc:00:46:04", "douyin") {
		t.Fatal("全局整形开着: 所有设备都算被限速")
	}
	// 配额 / 分时段: 限速控制器视图里 effective 有速率的设备
	c := &limitCtl{view: map[string]limitView{
		"aa:bb:cc:00:46:05": {Effective: map[string]interface{}{"down_mbps": 1.5, "up_mbps": 0.0}},
		"aa:bb:cc:00:46:06": {Effective: map[string]interface{}{"down_mbps": 0.0, "up_mbps": 0.0}},
	}}
	if ln := c.limitedNow(); !ln["aa:bb:cc:00:46:05"] || ln["aa:bb:cc:00:46:06"] {
		t.Fatalf("limitedNow: %v", ln)
	}
	if (*limitCtl)(nil).limitedNow() != nil {
		t.Fatal("nil 安全")
	}
}
