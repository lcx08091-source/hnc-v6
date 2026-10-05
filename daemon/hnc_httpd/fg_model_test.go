package main

// DPI v2 前台应用模型(fg_model.go): 合成的每轮差分序列 → 前台/后台/时间线/接口形状。

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fgMAC = "aa:bb:cc:00:00:31"

type fgTB struct {
	t    *testing.T
	m    *fgModel
	now  time.Time
	port int
	keys map[string]string
}

func newFgTB(t *testing.T, start time.Time) *fgTB {
	return &fgTB{t: t, m: newFgModel(), now: start, keys: map[string]string{}}
}

// newKey 一条新连接
func (b *fgTB) newKey(dst string) string {
	b.port++
	return fmt.Sprintf("tcp|192.168.43.10|%d|%s|443", 30000+b.port, dst)
}

// key 具名的持久连接(同名复用)
func (b *fgTB) key(name, dst string) string {
	if k, ok := b.keys[name]; ok {
		return k
	}
	k := b.newKey(dst)
	b.keys[name] = k
	return k
}

func fob(id, name, cat, key string, up, dn uint64) fgObs {
	return fgObs{MAC: fgMAC, ID: id, Name: name, Category: cat, Key: key, Up: up, Dn: dn}
}

func (b *fgTB) tick(dt time.Duration, obs ...[]fgObs) fgView {
	b.now = b.now.Add(dt)
	var all []fgObs
	for _, o := range obs {
		all = append(all, o...)
	}
	b.m.step(b.now, all, "")
	if d := b.m.devs[fgMAC]; d != nil {
		return d.view
	}
	return fgView{}
}

// ── 合成流量 ─────────────────────────────────────────────────────────

// 视频: ~2 MB/s, 一条长连接 + 每轮 2 条新分片连接
func (b *fgTB) video(dt time.Duration) []fgObs {
	f := uint64(dt / time.Second)
	return []fgObs{
		fob("bilibili", "哔哩哔哩", "video", b.key("vid", "1.1.1.1"), 30<<10*f, 1200<<10*f),
		fob("bilibili", "哔哩哔哩", "video", b.newKey("1.1.1.2"), 10<<10*f, 400<<10*f),
		fob("bilibili", "哔哩哔哩", "video", b.newKey("1.1.1.3"), 10<<10*f, 400<<10*f),
	}
}

// 微信后台心跳: 老连接, 每轮百来字节
func (b *fgTB) wechatHB() []fgObs {
	return []fgObs{fob("wechat", "微信", "social", b.key("wxhb", "2.2.2.2"), 60, 90)}
}

// 游戏: 低字节但持续双向(15 KB/s 下 / 6 KB/s 上), 单条 UDP 长连接
func (b *fgTB) game(dt time.Duration) []fgObs {
	f := uint64(dt / time.Second)
	return []fgObs{fob("wzry", "王者荣耀", "game", b.key("game", "3.3.3.3"), 6<<10*f, 15<<10*f)}
}

// 浏览: 150 KB/s, 每轮 6 条新连接, 请求小响应大
func (b *fgTB) browse(dt time.Duration) []fgObs {
	f := uint64(dt / time.Second)
	var out []fgObs
	for i := 0; i < 6; i++ {
		out = append(out, fob("quark", "夸克", "browser", b.newKey("4.4.4.4"), 1<<10, 25<<10*f/10))
	}
	return out
}

// 音乐: 40 KB/s 单连接持续
func (b *fgTB) music(dt time.Duration) []fgObs {
	f := uint64(dt / time.Second)
	return []fgObs{fob("qqmusic", "QQ音乐", "music", b.key("music", "5.5.5.5"), 1<<10*f/10, 40<<10*f)}
}

// 大文件下载: 5 MB/s 单连接, ACK 上行约 1.5%
func (b *fgTB) download(dt time.Duration) []fgObs {
	f := uint64(dt / time.Second)
	return []fgObs{fob("appstore", "软件商店", "", b.key("dl", "6.6.6.6"), 75<<10*f, 5<<20*f)}
}

func (b *fgTB) sessions() []fgSession {
	if b.m.day == nil {
		return nil
	}
	return b.m.day.Devices[fgMAC]
}

const tk = 10 * time.Second

func fgStart() time.Time { return time.Date(2026, 9, 30, 14, 0, 0, 0, time.Local) }

// ── 场景 ─────────────────────────────────────────────────────────────

func TestFgVideoWithBackgroundHeartbeats(t *testing.T) {
	b := newFgTB(t, fgStart())
	b.tick(tk, b.wechatHB()) // 模型起步: 心跳长连接按老连接
	var v fgView
	fgAt := -1
	for i := 0; i < 8; i++ {
		v = b.tick(tk, b.video(tk), b.wechatHB())
		if fgAt < 0 && v.AppID == "bilibili" {
			fgAt = i
		}
		if i == 0 && v.AppID != "" {
			t.Fatalf("单轮就判前台(无滞回): %+v", v)
		}
	}
	if fgAt < 0 || fgAt > 2 {
		t.Fatalf("视频应在 2~3 轮内成为前台, at=%d view=%+v", fgAt, v)
	}
	if v.State != "active" || v.Confidence < 70 || v.Name != "哔哩哔哩" || v.Category != "video" || v.Since == 0 {
		t.Fatalf("view: %+v", v)
	}
	joined := strings.Join(v.Reasons, " · ")
	if !strings.Contains(joined, "下行") || !strings.Contains(joined, "MB/s") || !strings.Contains(joined, "视频类") || !strings.Contains(joined, "新建") {
		t.Fatalf("reasons: %s", joined)
	}
	for _, bg := range v.Background {
		if bg.AppID == "wechat" {
			t.Fatalf("微信心跳不该出现在后台活跃列表: %+v", v.Background)
		}
	}
	if a := b.m.devs[fgMAC].apps["wechat"]; a == nil || a.f.HBShare < 0.99 || a.f.Active {
		t.Fatalf("wechat heartbeat features: %+v", a)
	}
	if s := b.sessions(); len(s) != 1 || s[0].App != "bilibili" || s[0].End <= s[0].Start || s[0].Conf < 60 {
		t.Fatalf("sessions: %+v", s)
	}
}

func TestFgSwitchAppsHysteresis(t *testing.T) {
	b := newFgTB(t, fgStart())
	b.tick(tk)
	for i := 0; i < 6; i++ {
		b.tick(tk, b.video(tk))
	}
	// 视频里夹一轮浏览(切出去看了一眼通知): 不换前台
	if v := b.tick(tk, b.video(tk), b.browse(tk)); v.AppID != "bilibili" {
		t.Fatalf("一轮插曲就切走: %+v", v)
	}
	if v := b.tick(tk, b.video(tk)); v.AppID != "bilibili" {
		t.Fatalf("%+v", v)
	}
	// 切到游戏: 第一轮不换, 2~3 轮内换
	switched := -1
	for i := 0; i < 6; i++ {
		v := b.tick(tk, b.game(tk))
		if i == 0 && v.AppID != "bilibili" {
			t.Fatalf("游戏第一轮就切换: %+v", v)
		}
		if switched < 0 && v.AppID == "wzry" {
			switched = i
		}
	}
	if switched < 1 || switched > 3 {
		t.Fatalf("switch at %d", switched)
	}
	v := b.m.devs[fgMAC].view
	if !strings.Contains(strings.Join(v.Reasons, "|"), "双向持续交互") || !strings.Contains(strings.Join(v.Reasons, "|"), "游戏类") {
		t.Fatalf("game reasons: %v", v.Reasons)
	}
	s := b.sessions()
	if len(s) != 2 || s[0].App != "bilibili" || s[1].App != "wzry" || s[1].Start < s[0].End {
		t.Fatalf("sessions: %+v", s)
	}
}

func TestFgShortPauseHoldsLongPauseReleases(t *testing.T) {
	b := newFgTB(t, fgStart())
	b.tick(tk)
	for i := 0; i < 6; i++ {
		b.tick(tk, b.video(tk))
	}
	// 20 秒暂停: 仍是视频(暂停中)
	for i := 0; i < 2; i++ {
		v := b.tick(tk)
		if v.AppID != "bilibili" {
			t.Fatalf("短暂停顿被丢: %+v", v)
		}
		if v.State != "paused" {
			t.Fatalf("state: %+v", v)
		}
	}
	for i := 0; i < 3; i++ {
		if v := b.tick(tk, b.video(tk)); v.AppID != "bilibili" || v.State != "active" {
			t.Fatalf("resume: %+v", v)
		}
	}
	if s := b.sessions(); len(s) != 1 {
		t.Fatalf("短暂停顿不该切段: %+v", s)
	}
	// 70 秒暂停: 过了 30 秒保持期就没有前台
	released := false
	for i := 0; i < 7; i++ {
		if v := b.tick(tk); v.AppID == "" {
			released = true
			if v.State != "idle" {
				t.Fatalf("idle state: %+v", v)
			}
		}
	}
	if !released {
		t.Fatal("长时间无流量仍保持前台")
	}
	// 回来继续看(间隔 < 2 分钟): 并回同一段
	for i := 0; i < 4; i++ {
		b.tick(tk, b.video(tk))
	}
	if s := b.sessions(); len(s) != 1 || s[0].App != "bilibili" {
		t.Fatalf("短间隔应合并: %+v", s)
	}
	// 再停 4 分钟后回来: 新的一段
	for i := 0; i < 24; i++ {
		b.tick(tk)
	}
	for i := 0; i < 4; i++ {
		b.tick(tk, b.video(tk))
	}
	if s := b.sessions(); len(s) != 2 || s[1].Start-s[0].End < 120 {
		t.Fatalf("长间隔应分段: %+v", s)
	}
}

func TestFgMusicPlusBrowsing(t *testing.T) {
	b := newFgTB(t, fgStart())
	b.tick(tk)
	// 只听歌: 音乐就是前台
	var v fgView
	for i := 0; i < 5; i++ {
		v = b.tick(tk, b.music(tk))
	}
	if v.AppID != "qqmusic" {
		t.Fatalf("只听歌时应为前台: %+v", v)
	}
	// 边听边刷网页: 浏览器前台, 音乐后台播放
	for i := 0; i < 5; i++ {
		v = b.tick(tk, b.music(tk), b.browse(tk))
	}
	if v.AppID != "quark" {
		t.Fatalf("前台应为浏览器: %+v", v)
	}
	if len(v.Background) == 0 || v.Background[0].AppID != "qqmusic" || v.Background[0].Label != "后台播放" || v.BgLabel != "后台：QQ音乐" {
		t.Fatalf("background: %+v / %q", v.Background, v.BgLabel)
	}
	if !strings.Contains(strings.Join(v.Reasons, "|"), "请求-响应") {
		t.Fatalf("reasons: %v", v.Reasons)
	}
}

func TestFgGameLowBytesBeatsHeartbeats(t *testing.T) {
	b := newFgTB(t, fgStart())
	b.tick(tk, b.wechatHB())
	var v fgView
	for i := 0; i < 5; i++ {
		v = b.tick(tk, b.game(tk), b.wechatHB())
	}
	if v.AppID != "wzry" || v.Confidence < 50 {
		t.Fatalf("game: %+v", v)
	}
}

func TestFgBulkDownloadNotForeground(t *testing.T) {
	b := newFgTB(t, fgStart())
	b.tick(tk)
	var v fgView
	for i := 0; i < 8; i++ {
		v = b.tick(tk, b.download(tk))
		if v.AppID != "" {
			t.Fatalf("纯后台大文件下载不该是前台: %+v (score %v)", v, b.m.devs[fgMAC].apps["appstore"].smooth)
		}
	}
	if len(v.Background) != 1 || v.Background[0].Label != "下载中" {
		t.Fatalf("download should be listed as background: %+v", v)
	}
	// 下载的同时看视频: 前台视频, 下载在后台
	for i := 0; i < 4; i++ {
		v = b.tick(tk, b.download(tk), b.video(tk))
	}
	if v.AppID != "bilibili" || len(v.Background) == 0 || v.Background[0].AppID != "appstore" {
		t.Fatalf("video+download: %+v", v)
	}
}

func TestFgScreenOffSyncBurstsStayBackground(t *testing.T) {
	b := newFgTB(t, fgStart())
	b.tick(tk, b.wechatHB())
	for i := 0; i < 60; i++ {
		obs := b.wechatHB()
		if i%12 == 5 { // 每 2 分钟一次同步: 5 条新连接、共 ~1.5 MB
			for j := 0; j < 5; j++ {
				obs = append(obs, fob("wechat", "微信", "social", b.newKey("2.2.2.9"), 4<<10, 300<<10))
			}
			obs = append(obs, fob("baidunetdisk", "百度网盘", "", b.newKey("7.7.7.7"), 2<<10, 600<<10))
		}
		if v := b.tick(tk, obs); v.AppID != "" {
			t.Fatalf("tick %d: 熄屏同步突发被判成前台: %+v", i, v)
		}
	}
	if s := b.sessions(); len(s) != 0 {
		t.Fatalf("timeline: %+v", s)
	}
}

func TestFgTunnelAndOrg(t *testing.T) {
	b := newFgTB(t, fgStart())
	b.tick(tk)
	var v fgView
	for i := 0; i < 4; i++ {
		v = b.tick(tk, []fgObs{fob(tunnelAppID, tunnelAppName, tunnelCategory, b.key("wg", "8.8.8.8"), 100<<10, 1<<20*10)})
	}
	if v.AppID != tunnelAppID || v.Name != "VPN/代理中" || v.Label != "VPN/代理中" || v.Confidence > 50 {
		t.Fatalf("tunnel: %+v", v)
	}
	b2 := newFgTB(t, fgStart())
	b2.tick(tk)
	for i := 0; i < 5; i++ {
		v = b2.tick(tk, []fgObs{
			fob("_org:bytedance", "字节系(未细分)", "org", b2.newKey("9.9.9.1"), 20<<10, 3<<20),
			fob("_org:bytedance", "字节系(未细分)", "org", b2.newKey("9.9.9.2"), 20<<10, 3<<20),
			fob("_org:bytedance", "字节系(未细分)", "org", b2.newKey("9.9.9.3"), 20<<10, 3<<20),
		})
	}
	if v.AppID != "_org:bytedance" || v.Confidence > 60 || v.Confidence == 0 || !strings.Contains(strings.Join(v.Reasons, "|"), "归属组织") {
		t.Fatalf("org: %+v", v)
	}
	// 未识别/局域网/广告 SDK 永远不参与
	b3 := newFgTB(t, fgStart())
	b3.tick(tk)
	for i := 0; i < 5; i++ {
		v = b3.tick(tk, []fgObs{
			fob(appUnknownID, "未识别", "", b3.newKey("10.0.0.1"), 1<<10, 2<<20),
			fob("pangle", "穿山甲", "ads", b3.newKey("10.0.0.2"), 1<<10, 2<<20),
		})
	}
	if d := b3.m.devs[fgMAC]; v.AppID != "" || (d != nil && len(d.apps) != 0) {
		t.Fatalf("hidden apps leaked: %+v", v)
	}
}

func TestFgPowerSchedulerTicks(t *testing.T) {
	// 后台档 30 秒一轮: 照样能判, 标 coarse, 置信度略降
	b := newFgTB(t, fgStart())
	b.tick(30 * time.Second)
	var v fgView
	for i := 0; i < 3; i++ {
		v = b.tick(30*time.Second, b.video(30*time.Second))
	}
	if v.AppID != "bilibili" || !v.Coarse || v.TickSec != 30 || v.Confidence >= 95 {
		t.Fatalf("30s tick: %+v", v)
	}
	// 30 秒档下一轮没流量: 仍在保持期(暂停)
	if v = b.tick(30 * time.Second); v.AppID != "bilibili" || v.State != "paused" {
		t.Fatalf("pause at 30s: %+v", v)
	}
	// 热点关掉 5 分钟后回来(间隔 > 90 秒): 模型重置, 段落收尾, 不把空档算进去
	end := b.sessions()[0].End
	v = b.tick(5*time.Minute, b.video(10*time.Second))
	if v.AppID != "" {
		t.Fatalf("长间隔后第一轮不该直接沿用前台: %+v", v)
	}
	if s := b.sessions(); s[0].End != end {
		t.Fatalf("会话不该延长到空档: %+v (was %d)", s, end)
	}
	// 读取时修正
	now := time.Now()
	fresh := fgView{State: "active", AppID: "x", Confidence: 80, Updated: now.Unix(), Reasons: []string{"a"}}
	if g := fgApplyStale(fresh, now, lvlNoClients, time.Minute); g.State != "unknown" || g.AppID != "" || !g.Stale {
		t.Fatalf("no_clients: %+v", g)
	}
	if g := fgApplyStale(fresh, now, lvlHotspotOff, time.Minute); g.State != "unknown" {
		t.Fatalf("hotspot_off: %+v", g)
	}
	if g := fgApplyStale(fresh, now.Add(40*time.Second), lvlActive, 10*time.Second); g.State != "active" {
		t.Fatalf("40s old still fresh: %+v", g)
	}
	if g := fgApplyStale(fresh, now.Add(100*time.Second), lvlBackground, 30*time.Second); g.State != "stale" || g.Confidence != 40 || !g.Stale {
		t.Fatalf("stale: %+v", g)
	}
	if fresh.Reasons[0] != "a" || len(fresh.Reasons) != 1 {
		t.Fatal("ApplyStale mutated input")
	}
}

func TestFgTimelinePersistRollover(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	start := time.Date(2026, 9, 30, 23, 58, 0, 0, time.Local)
	b := newFgTB(t, start)
	b.m.load(dir, start)
	b.tick(tk)
	for i := 0; i < 30; i++ { // 23:58:10 → 00:03:10, 跨 0 点
		b.tick(tk, b.video(tk))
	}
	b.m.flush(b.now)
	old := fgLoadDay(dir, "20260930")
	cur := fgLoadDay(dir, "20261001")
	if old == nil || cur == nil {
		t.Fatalf("files: %v %v", old, cur)
	}
	mid := time.Date(2026, 10, 1, 0, 0, 0, 0, time.Local).Unix()
	o, c := old.Devices[fgMAC], cur.Devices[fgMAC]
	if len(o) != 1 || o[0].End != mid || len(c) != 1 || c[0].Start != mid || c[0].End <= mid || c[0].App != "bilibili" {
		t.Fatalf("split: %+v / %+v", o, c)
	}
	// 新进程载入今天的时间线, 继续看 → 并回同一段
	m2 := newFgModel()
	m2.load(dir, b.now)
	b.m = m2
	b.tick(tk)
	for i := 0; i < 4; i++ {
		b.tick(tk, b.video(tk))
	}
	if s := b.sessions(); len(s) != 1 || s[0].Start != mid {
		t.Fatalf("reload merge: %+v", s)
	}
	// 清理: 保留今天 + 前 7 天
	for _, d := range []string{"20260920", "20260924", "20260923"} {
		_ = os.WriteFile(fgDayPath(dir, d), []byte(`{"date":"x","devices":{}}`), 0o644)
	}
	b.m.flush(b.now)
	if _, err := os.Stat(fgDayPath(dir, "20260920")); err == nil {
		t.Fatal("old file kept")
	}
	if _, err := os.Stat(fgDayPath(dir, "20260923")); err == nil {
		t.Fatal("8-day-old file kept")
	}
	if _, err := os.Stat(fgDayPath(dir, "20260924")); err != nil {
		t.Fatal("7-day-old file removed")
	}
}

func TestFgSessionBounds(t *testing.T) {
	m := newFgModel()
	m.last = fgStart()
	m.day = &fgDay{Date: fgStart().Format("20060102"), Devices: map[string][]fgSession{}}
	d := &fgDev{apps: map[string]*fgApp{}}
	base := fgStart().Unix()
	for i := 0; i < fgMaxSessPerDev+50; i++ {
		id := "a"
		if i%2 == 1 {
			id = "b"
		}
		a := &fgApp{id: id, name: id}
		m.openSessionLocked(fgMAC, d, a, time.Unix(base+int64(i)*1000, 0))
		m.extendSessionLocked(fgMAC, time.Unix(base+int64(i)*1000+int64(i%7+1)*10, 0), 50, "passive")
		m.closeSessionLocked(fgMAC, d, time.Unix(base+int64(i)*1000+int64(i%7+1)*10, 0))
	}
	if l := m.day.Devices[fgMAC]; len(l) != fgMaxSessPerDev {
		t.Fatalf("cap: %d", len(l))
	}
	// 合并: 同应用间隔 ≤ 120 秒
	m.day.Devices[fgMAC] = nil
	a := &fgApp{id: "a", name: "A"}
	m.openSessionLocked(fgMAC, d, a, time.Unix(base, 0))
	m.extendSessionLocked(fgMAC, time.Unix(base+300, 0), 80, "passive")
	m.closeSessionLocked(fgMAC, d, time.Unix(base+300, 0))
	if s := m.openSessionLocked(fgMAC, d, a, time.Unix(base+400, 0)); s.Unix() != base {
		t.Fatalf("merge start: %v", s)
	}
	m.extendSessionLocked(fgMAC, time.Unix(base+500, 0), 60, "passive")
	if l := m.day.Devices[fgMAC]; len(l) != 1 || l[0].End != base+500 || l[0].Conf != 70 {
		t.Fatalf("merged: %+v", l)
	}
}

func TestFgAPIShapes(t *testing.T) {
	resetAppTimeGlobals(t)
	old := fgSt
	t.Cleanup(func() { fgSt = old })
	oldAct := actState.cur.Load()
	actState.cur.Store(&Activity{Known: true, Level: lvlActive})
	t.Cleanup(func() { actState.cur.Store(oldAct) })

	dir := t.TempDir()
	for _, sub := range []string{"data", "run", "bin"} {
		_ = os.MkdirAll(filepath.Join(dir, sub), 0o755)
	}
	t.Setenv("HNC_CONNTRACK_PATH", filepath.Join(dir, "no_conntrack"))
	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"), []byte(`{"`+fgMAC+`":{"ip":"192.168.43.10","last_seen":1},"aa:bb:cc:00:00:32":{"ip":"192.168.43.11"}}`), 0o644)

	now := time.Now()
	b := newFgTB(t, now.Add(-2*time.Minute))
	fgSt = b.m
	b.m.load(dir, b.now)
	b.tick(tk)
	for i := 0; i < 8; i++ {
		b.tick(tk, b.video(tk), b.music(tk))
	}
	// app_time 口径对照
	d := newDay(now.Format("20060102"))
	d.Active = map[string]map[string]uint32{"14": {fgMAC + "|bilibili": 90, fgMAC + "|qqmusic": 80}}
	d.Apps["bilibili"] = appUsageMeta{Name: "哔哩哔哩", Category: "video"}
	appUsage.mu.Lock()
	appUsage.day = d
	appUsage.mu.Unlock()

	s := newServer(dir)
	_, payload := s.buildDevicesPayload()
	raw, _ := json.Marshal(payload["devices"])
	var devs []map[string]interface{}
	_ = json.Unmarshal(raw, &devs)
	found := false
	for _, dv := range devs {
		fg, ok := dv["fg"].(map[string]interface{})
		switch dv["mac"] {
		case fgMAC:
			if !ok {
				t.Fatalf("fg missing: %v", dv)
			}
			found = true
			for _, k := range []string{"app_id", "name", "category", "confidence", "since", "reasons", "background", "state", "label", "updated", "tick_sec"} {
				if _, ok := fg[k]; !ok {
					t.Fatalf("fg.%s missing: %v", k, fg)
				}
			}
			bg, _ := fg["background"].([]interface{})
			if fg["app_id"] != "bilibili" || fg["state"] != "active" || len(bg) != 1 || bg[0].(map[string]interface{})["app_id"] != "qqmusic" {
				t.Fatalf("fg: %v", fg)
			}
		default:
			if ok {
				t.Fatalf("没有流量的设备不该有 fg: %v", fg)
			}
		}
	}
	if !found {
		t.Fatalf("devices: %s", raw)
	}

	rec := httptest.NewRecorder()
	s.apiFgTimeline(rec, httptest.NewRequest("GET", "/api/fg_timeline?mac="+strings.ToUpper(fgMAC)+"&days=1", nil))
	var resp struct {
		OK       bool                     `json:"ok"`
		MAC      string                   `json:"mac"`
		Sessions []map[string]interface{} `json:"sessions"`
		ByApp    []map[string]interface{} `json:"by_app"`
		Total    float64                  `json:"total_fg_sec"`
		Current  map[string]interface{}   `json:"current"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !resp.OK || resp.MAC != fgMAC {
		t.Fatalf("resp: %s", rec.Body.String())
	}
	if len(resp.Sessions) != 1 || resp.Sessions[0]["app_id"] != "bilibili" || resp.Sessions[0]["open"] != true || resp.Sessions[0]["sec"].(float64) <= 0 {
		t.Fatalf("sessions: %s", rec.Body.String())
	}
	for _, k := range []string{"mac", "name", "category", "start", "end", "confidence"} {
		if _, ok := resp.Sessions[0][k]; !ok {
			t.Fatalf("session.%s missing", k)
		}
	}
	if len(resp.ByApp) < 2 || resp.ByApp[0]["app_id"] != "bilibili" || resp.ByApp[0]["fg_sec"].(float64) != resp.Total ||
		resp.ByApp[0]["active_sec"].(float64) != 90 {
		t.Fatalf("by_app: %s", rec.Body.String())
	}
	var music map[string]interface{}
	for _, a := range resp.ByApp {
		if a["app_id"] == "qqmusic" {
			music = a
		}
	}
	if music == nil || music["fg_sec"].(float64) != 0 || music["active_sec"].(float64) != 80 {
		t.Fatalf("music (后台不计前台分钟, 但 app_time 计): %v", music)
	}
	if resp.Current == nil || resp.Current["app_id"] != "bilibili" {
		t.Fatalf("current: %v", resp.Current)
	}
	// 坏参数
	rec = httptest.NewRecorder()
	s.apiFgTimeline(rec, httptest.NewRequest("GET", "/api/fg_timeline?mac=zz", nil))
	if rec.Code != 400 {
		t.Fatalf("bad mac: %d", rec.Code)
	}
	// 全部设备 + days 上限
	rec = httptest.NewRecorder()
	s.apiFgTimeline(rec, httptest.NewRequest("GET", "/api/fg_timeline?days=99", nil))
	var all map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &all)
	if all["days"].(float64) != 8 || len(all["sessions"].([]interface{})) != 1 {
		t.Fatalf("all: %s", rec.Body.String())
	}
	if _, ok := all["current"]; ok {
		t.Fatal("current only with mac")
	}
	// 熄屏 + 无客户端: /api/devices 的 fg 标 unknown
	actState.cur.Store(&Activity{Known: true, Level: lvlNoClients})
	v := fgViewsByMAC(time.Now())[fgMAC]
	if v.State != "unknown" || v.AppID != "" {
		t.Fatalf("no clients: %+v", v)
	}
}

// 接线: appUsageRecordIdent(真实采样路径, ix 非 nil)推进全局前台模型
func TestFgHookFromAppUsage(t *testing.T) {
	resetAppTimeGlobals(t)
	identReset()
	t.Cleanup(identReset)
	old := fgSt
	fgSt = newFgModel()
	t.Cleanup(func() { fgSt = old })
	oldAct := actState.cur.Load()
	actState.cur.Store(&Activity{Known: true, Level: lvlActive})
	t.Cleanup(func() { actState.cur.Store(oldAct) })
	ip := "192.168.43.10"
	owner := map[string]string{ip: fgMAC}
	apps := map[string]ipApp{"1.1.1.1": {ID: "bilibili", Name: "哔哩哔哩", Category: "video"}, "1.1.1.2": {ID: "bilibili", Name: "哔哩哔哩", Category: "video"}}
	names := map[string]ipName{}
	now := time.Now()
	d := newDay(now.Format("20060102"))
	port := 40000
	for i := 0; i < 6; i++ {
		now = now.Add(tk)
		deltas := []appUsageDelta{{Src: ip, Dst: "1.1.1.1", Up: 300 << 10, Dn: 12 << 20, Key: "tcp|" + ip + "|39999|1.1.1.1|443"}}
		for j := 0; j < 2; j++ {
			port++
			deltas = append(deltas, appUsageDelta{Src: ip, Dst: "1.1.1.2", Up: 100 << 10, Dn: 4 << 20, Key: fmt.Sprintf("tcp|%s|%d|1.1.1.2|443", ip, port)})
		}
		deltas = append(deltas, appUsageDelta{Src: ip, Dst: "192.168.43.1", Up: 1 << 20, Dn: 1 << 20, Key: "tcp|" + ip + "|1|192.168.43.1|80"})
		ix := identSt.observe(now, deltas, nil, nil, owner, apps, names)
		appUsageRecordIdent(d, deltas, owner, apps, names, now, 10, ix)
	}
	v := fgViewsByMAC(now)[fgMAC]
	if v.AppID != "bilibili" {
		t.Fatalf("hook: %+v", v)
	}
	if _, ok := fgSt.devs[fgMAC].apps[appLocalID]; ok {
		t.Fatal("局域网不该进前台模型")
	}
	// 不带 ix(单测/旧路径)不推进
	before := fgSt.last
	appUsageRecord(d, nil, owner, apps, names, now.Add(tk), 10)
	if !fgSt.last.Equal(before) {
		t.Fatal("appUsageRecord without ix advanced model")
	}
}
