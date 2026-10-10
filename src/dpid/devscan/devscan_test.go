// devscan_test.go — v5.31 T1 单测: 邻居事件序列 → 设备表。
//
// 覆盖 WORK-v5.31 §7 T1 验收点: 上线 / 换 IP 挑新 IP / 离开 90 秒 /
// 网卡重建 / 非热点网卡忽略; 输出 JSON 与 hotspotd 同输入样例逐字段一致
// (时间戳除外)。全部纯逻辑, 不碰真 socket / 文件。
package devscan

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"hnc.io/dpid/neigh"
)

var (
	t0   = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	macA = "02:5a:00:00:00:01"
	macB = "02:5a:00:00:00:02"
)

func ev(ifIndex int, mac, ip string, state uint16, deleted bool) neigh.Entry {
	return neigh.Entry{
		IfIndex: ifIndex,
		IP:      net.ParseIP(ip),
		MAC:     mac,
		State:   state,
		Deleted: deleted,
	}
}

// newTestTable 手动名: 02:5a:00:00:00:02 → "我的手机"; 其余走 mac 兜底
// (去冒号取后 8 位, 对齐 hnc_mac_fallback)。
func newTestTable() *Table {
	t := NewTable("wlan2", 7)
	t.Fast = func(mac string) (string, string) {
		if mac == macB {
			return "我的手机", "manual"
		}
		noColon := strings.ReplaceAll(mac, ":", "")
		return noColon[len(noColon)-8:], "mac"
	}
	return t
}

func TestApplyOnline(t *testing.T) {
	tb := newTestTable()
	if !tb.Apply(ev(7, macA, "192.168.43.101", nudReachable, false), t0) {
		t.Fatal("第一个事件应改变表")
	}
	if got := tb.Count(); got != 1 {
		t.Fatalf("设备数 = %d, 要 1", got)
	}
	b := jsonRender(t, tb)
	d := b[macA]
	if d.IP != "192.168.43.101" || d.Iface != "wlan2" || d.Status != "allowed" {
		t.Fatalf("字段不对: %+v", d)
	}
	if d.HostnameSrc != "pending" {
		t.Fatalf("mac 兜底新设备应为 pending, 得 %q", d.HostnameSrc)
	}
	if d.Hostname != "00000001" { // hnc_mac_fallback: 去冒号取后 8 位
		t.Fatalf("hostname = %q, 要 MAC 后 8 位", d.Hostname)
	}
	if d.LastSeen != t0.Unix() {
		t.Fatalf("last_seen = %d, 要 %d", d.LastSeen, t0.Unix())
	}
}

func TestApplyManualName(t *testing.T) {
	tb := newTestTable()
	tb.Apply(ev(7, macB, "192.168.43.102", nudStale, false), t0)
	d := jsonRender(t, tb)[macB]
	if d.Hostname != "我的手机" || d.HostnameSrc != "manual" {
		t.Fatalf("手动名没生效: %+v", d)
	}
}

func TestApplyIfaceFilter(t *testing.T) {
	tb := newTestTable() // ifIndex = 7
	if tb.Apply(ev(9, macA, "10.0.0.5", nudReachable, false), t0) {
		t.Fatal("非热点网卡(别的 ifindex)的事件必须忽略")
	}
	if tb.Count() != 0 {
		t.Fatal("非热点网卡不该进表")
	}
	// 全零 MAC / 非 IPv4 也不进表
	if tb.Apply(ev(7, "00:00:00:00:00:00", "192.168.43.9", nudReachable, false), t0) {
		t.Fatal("全零 MAC 必须忽略")
	}
	if tb.Apply(ev(7, macA, "fd00::1", nudReachable, false), t0) {
		t.Fatal("IPv6 必须忽略")
	}
}

func TestApplyIPChangePicksBetterState(t *testing.T) {
	tb := newTestTable()
	tb.Apply(ev(7, macA, "192.168.43.101", nudReachable, false), t0)
	// 换 IP: 旧表项还在(STALE), 新表项 REACHABLE → 挑新的
	tb.Apply(ev(7, macA, "192.168.43.112", nudReachable, false), t0.Add(2*time.Second))
	tb.Apply(ev(7, macA, "192.168.43.101", nudStale, false), t0.Add(3*time.Second))
	if d := jsonRender(t, tb)[macA]; d.IP != "192.168.43.112" {
		t.Fatalf("换 IP 后应挑 REACHABLE 的新 IP, 得 %q", d.IP)
	}
	// 反过来: 新 IP 只有 STALE, 旧 IP REACHABLE → 保留旧 IP
	tb2 := newTestTable()
	tb2.Apply(ev(7, macA, "192.168.43.101", nudReachable, false), t0)
	tb2.Apply(ev(7, macA, "192.168.43.112", nudStale, false), t0.Add(time.Second))
	if d := jsonRender(t, tb2)[macA]; d.IP != "192.168.43.101" {
		t.Fatalf("旧表项 REACHABLE 时不该被 STALE 新表项抢走, 得 %q", d.IP)
	}
	// 同状态取最近一次事件
	tb2.Apply(ev(7, macA, "192.168.43.101", nudStale, false), t0.Add(9*time.Second))
	if d := jsonRender(t, tb2)[macA]; d.IP != "192.168.43.101" {
		t.Fatalf("同状态应取最近一次事件, 得 %q", d.IP)
	}
}

func TestApplyFailedOldIPOnly(t *testing.T) {
	tb := newTestTable()
	tb.Apply(ev(7, macA, "192.168.43.101", nudReachable, false), t0)
	tb.Apply(ev(7, macA, "192.168.43.112", nudStale, false), t0.Add(time.Second))
	// 旧 IP 的表项 FAILED: 新表项还在 → 不下线, 只是候选少一个, IP 换成新表项
	if !tb.Apply(ev(7, macA, "192.168.43.101", nudFailed, false), t0.Add(2*time.Second)) {
		t.Fatal("FAILED 事件应改变表(候选减少)")
	}
	if got := tb.Count(); got != 1 {
		t.Fatalf("新表项还在, 设备不该下线; 设备数 = %d", got)
	}
	if d := jsonRender(t, tb)[macA]; d.IP != "192.168.43.112" {
		t.Fatalf("FAILED 后应保留新 IP, 得 %q", d.IP)
	}
}

func TestApplyFailedLastIPOffline(t *testing.T) {
	tb := newTestTable()
	tb.Apply(ev(7, macA, "192.168.43.101", nudReachable, false), t0)
	// 有流量去找它 → 邻居表 FAILED(RTM_DELNEIGH)→ 立即下线
	if !tb.Apply(ev(7, macA, "192.168.43.101", nudFailed, true), t0.Add(time.Second)) {
		t.Fatal("最后一个表项 FAILED 应导致下线")
	}
	if tb.Count() != 0 {
		t.Fatal("FAILED 后设备应移出表")
	}
	// DELNEIGH 但状态不是 FAILED/INCOMPLETE → 不下线(对齐 C 的判断)
	tb.Apply(ev(7, macA, "192.168.43.101", nudStale, false), t0)
	if tb.Apply(ev(7, macA, "192.168.43.101", nudStale, true), t0.Add(time.Second)) {
		t.Fatal("非 FAILED/INCOMPLETE 的 DEL 事件不应下线")
	}
	if tb.Count() != 1 {
		t.Fatal("设备应该还在")
	}
}

func TestEvictOffline90s(t *testing.T) {
	tb := newTestTable()
	tb.Apply(ev(7, macA, "192.168.43.101", nudStale, false), t0)
	// 静默 STALE: 没有任何新事件
	if n := tb.EvictOffline(t0.Add(89 * time.Second)); n != 0 {
		t.Fatal("89 秒不该离线")
	}
	if n := tb.EvictOffline(t0.Add(91 * time.Second)); n != 1 {
		t.Fatalf("91 秒应离线 1 台, 得 %d", n)
	}
	if tb.Count() != 0 {
		t.Fatal("离线后应移出表")
	}
}

func TestFullSyncMissedEvents(t *testing.T) {
	tb := newTestTable()
	// 事件丢了: 设备早已在线, FullSync 兜底发现
	if !tb.FullSync([]neigh.Entry{
		ev(7, macA, "192.168.43.101", nudStale, false),
		ev(7, macB, "192.168.43.102", nudReachable, false),
	}, t0) {
		t.Fatal("全量兜底应发现新设备")
	}
	if tb.Count() != 2 {
		t.Fatalf("设备数 = %d, 要 2", tb.Count())
	}
	// 再来一次: macA 状态未变 → 不刷 last_seen(90 秒语义);
	// macB 状态变了(REACHABLE → PROBE)→ 算一次事件, last_seen 刷新。
	seen := t0.Unix()
	if !tb.FullSync([]neigh.Entry{
		ev(7, macA, "192.168.43.101", nudStale, false),
		ev(7, macB, "192.168.43.102", nudProbe, false),
	}, t0.Add(60*time.Second)) {
		t.Fatal("macB 状态变了, 该算一次变化")
	}
	if d := jsonRender(t, tb)[macA]; d.LastSeen != seen {
		t.Fatalf("静默 STALE 不该刷 last_seen: %d != %d", d.LastSeen, seen)
	}
	// 60 秒后仍能被 90 秒离线检查移出
	if n := tb.EvictOffline(t0.Add(91 * time.Second)); n != 1 {
		t.Fatalf("91 秒应离线 1 台(macA), 得 %d", n)
	}
}

func TestIfaceRecreate(t *testing.T) {
	tb := newTestTable() // ifIndex 7
	tb.Apply(ev(7, macA, "192.168.43.101", nudReachable, false), t0)
	// 热点重启: 同名网卡重建, ifindex 变 12
	tb.SetIface("wlan2", 12)
	if tb.Apply(ev(7, macA, "192.168.43.101", nudReachable, false), t0.Add(time.Second)) {
		t.Fatal("旧 ifindex 的事件应被忽略")
	}
	if !tb.FullSync([]neigh.Entry{ev(12, macA, "192.168.43.101", nudStale, false)}, t0.Add(time.Second)) {
		t.Fatal("重建后的表项应被接受(状态从 REACHABLE 变 STALE 也算事件)")
	}
	if d := jsonRender(t, tb)[macA]; d.Iface != "wlan2" {
		t.Fatalf("网卡名应保持, 得 %q", d.Iface)
	}
}

// TestJSONMatchesHotspotdSample 输出 JSON 与 hotspotd 同输入的样例逐字段比
// (时间戳除外)。样例按 hotspotd.c write_json 的 fprintf 格式手工构造
// (同样的字段顺序与转义规则), 是「与 C 版对照」的固定锚点。
func TestJSONMatchesHotspotdSample(t *testing.T) {
	tb := NewTable("wlan2", 7)
	tb.Fast = func(mac string) (string, string) {
		switch mac {
		case macA:
			return "Redmi-TV", "mdns"
		case macB:
			return "我的手机", "manual"
		default:
			nc := strings.ReplaceAll(mac, ":", "")
			return nc[len(nc)-8:], "mac"
		}
	}
	tb.Apply(ev(7, macA, "192.168.43.101", nudReachable, false), t0)
	tb.Apply(ev(7, macB, "192.168.43.102", nudStale, false), t0.Add(time.Second))
	tb.Apply(ev(7, "02:5a:00:00:00:03", "192.168.43.103", nudDelay, false), t0)

	stats := map[string][2]int64{
		"192.168.43.101": {111, 222},
		"192.168.43.102": {333, 444},
	}
	blacklist := map[string]bool{macA: true}
	got := jsonRender2(t, tb, stats, blacklist)

	// hotspotd write_json 同输入样例(last_seen 用同一起点时刻)
	sample := `{"02:5a:00:00:00:01":{"ip":"192.168.43.101","mac":"02:5a:00:00:00:01",` +
		`"hostname":"Redmi-TV","hostname_src":"mdns","iface":"wlan2","rx_bytes":111,` +
		`"tx_bytes":222,"status":"blocked","last_seen":` + itoa(t0.Unix()) + `},` +
		`"02:5a:00:00:00:02":{"ip":"192.168.43.102","mac":"02:5a:00:00:00:02",` +
		`"hostname":"我的手机","hostname_src":"manual","iface":"wlan2","rx_bytes":333,` +
		`"tx_bytes":444,"status":"allowed","last_seen":` + itoa(t0.Add(time.Second).Unix()) + `},` +
		`"02:5a:00:00:00:03":{"ip":"192.168.43.103","mac":"02:5a:00:00:00:03",` +
		`"hostname":"00000003","hostname_src":"pending","iface":"wlan2","rx_bytes":0,` +
		`"tx_bytes":0,"status":"allowed","last_seen":` + itoa(t0.Unix()) + `}}`
	want := map[string]Device{}
	if err := json.Unmarshal([]byte(sample), &want); err != nil {
		t.Fatalf("样例本身应可解析: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("设备数 %d != %d", len(got), len(want))
	}
	for mac, w := range want {
		g, ok := got[mac]
		if !ok {
			t.Fatalf("缺设备 %s", mac)
		}
		if g != w {
			t.Fatalf("%s 字段不一致:\n got %+v\nwant %+v", mac, g, w)
		}
	}
	// 原始字节层面: 必须是紧凑 JSON、顶层是对象
	raw := tb.RenderJSON(stats, blacklist)
	if len(raw) == 0 || raw[0] != '{' || raw[len(raw)-1] != '}' {
		t.Fatalf("输出应是紧凑 JSON 对象: %q", raw)
	}
	if raw[len(raw)-1] == '\n' {
		t.Fatal("输出不应有结尾换行(C 没有)")
	}
}

// TestTableCapacity 表满淘汰最旧。
func TestTableCapacity(t *testing.T) {
	tb := NewTable("wlan2", 7)
	tb.Fast = func(mac string) (string, string) {
		nc := strings.ReplaceAll(mac, ":", "")
		return nc[len(nc)-8:], "mac"
	}
	for i := 0; i < MaxDevices; i++ {
		tb.Apply(ev(7, padMAC(i), "192.168.43.1", nudReachable, false), t0.Add(time.Duration(i)*time.Second))
	}
	if tb.Count() != MaxDevices {
		t.Fatalf("表应满: %d", tb.Count())
	}
	newMac := padMAC(200) // 最晚看到 → 不该被淘汰
	tb.Apply(ev(7, newMac, "192.168.43.9", nudReachable, false), t0.Add(1000*time.Second))
	if tb.Count() != MaxDevices {
		t.Fatalf("表满后新增应淘汰, 设备数 = %d", tb.Count())
	}
	if d := jsonRender(t, tb)[newMac]; d.IP != "192.168.43.9" {
		t.Fatal("新设备应在表里")
	}
	if d := jsonRender(t, tb)[padMAC(0)]; d.IP != "" {
		t.Fatal("最旧的 padMAC(0) 应被淘汰")
	}
}

// TestPendingDueAndResolution pending 派发与回填。
func TestPendingDueAndResolution(t *testing.T) {
	tb := newTestTable()
	tb.Apply(ev(7, macA, "192.168.43.101", nudReachable, false), t0)
	if _, _, ok := tb.PendingDue(t0); ok {
		t.Fatal("挂 pending 不足 1 秒不该派发(呼吸空间)")
	}
	mac, ip, ok := tb.PendingDue(t0.Add(2 * time.Second))
	if !ok || mac != macA || ip != "192.168.43.101" {
		t.Fatalf("应派发 macA, 得 %q %q %v", mac, ip, ok)
	}
	// 手动名设备不进 pending
	tb.Apply(ev(7, macB, "192.168.43.102", nudStale, false), t0)
	mac2, _, ok2 := tb.PendingDue(t0.Add(2 * time.Second))
	if !ok2 || mac2 != macA {
		t.Fatalf("应仍只有 macA 在 pending, 得 %q %v", mac2, ok2)
	}
	if !tb.ApplyResolution(macA, "living-room", "mdns", t0.Add(3*time.Second)) {
		t.Fatal("回填应成功")
	}
	if d := jsonRender(t, tb)[macA]; d.Hostname != "living-room" || d.HostnameSrc != "mdns" {
		t.Fatalf("回填结果不对: %+v", d)
	}
	if _, _, ok := tb.PendingDue(t0.Add(10 * time.Second)); ok {
		t.Fatal("解析完成后不应再派发")
	}
}

func jsonRender(t *testing.T, tb *Table) map[string]Device {
	return jsonRender2(t, tb, nil, nil)
}

func jsonRender2(t *testing.T, tb *Table, stats map[string][2]int64, blacklist map[string]bool) map[string]Device {
	t.Helper()
	raw := tb.RenderJSON(stats, blacklist)
	out := map[string]Device{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("RenderJSON 输出不可解析: %v (%s)", err, raw)
	}
	return out
}

func padMAC(i int) string {
	h := "0123456789abcdef"
	return "02:5a:00:" + string(h[(i>>8)&0xf]) + string(h[i&0xf]) + ":" +
		string(h[(i>>4)&0xf]) + string(h[i&0xf]) + ":aa"
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func hex2(v int) string { return padMAC(v)[:2] }

// v5.31 审查修复: 全量扫时同一 MAC 新旧两条 STALE 表项, 按内核的「最近确认」挑新 IP
// (原来两条都记成同一时刻, 挑哪个看 map 遍历顺序)。30 次 × 两种顺序, 都要挑新的。
func TestFullSyncPicksRecentlyConfirmedIP(t *testing.T) {
	old := neigh.Entry{IfIndex: 7, IP: net.ParseIP("192.168.43.102"), MAC: "02:5a:00:00:00:02", State: nudStale, ConfirmedAgo: 5 * time.Minute}
	cur := neigh.Entry{IfIndex: 7, IP: net.ParseIP("192.168.43.112"), MAC: "02:5a:00:00:00:02", State: nudStale, ConfirmedAgo: 3 * time.Second}
	now := time.Now()
	for i := 0; i < 30; i++ {
		for _, es := range [][]neigh.Entry{{old, cur}, {cur, old}} {
			tb := NewTable("wlan2", 7)
			tb.FullSync(es, now)
			var got map[string]Device
			if err := json.Unmarshal(tb.RenderJSON(nil, nil), &got); err != nil {
				t.Fatal(err)
			}
			if ip := got["02:5a:00:00:00:02"].IP; ip != "192.168.43.112" {
				t.Fatalf("第 %d 次: 挑了 %s, 应是最近确认的 192.168.43.112", i, ip)
			}
		}
	}
}
