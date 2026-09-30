package main

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 夹具由 AOSP NetworkStatsService.dump 格式手写生成(见 netstats_parse.go 文件头):
//   android10_sinceboot.txt  subType=, 数字 type=0, History since boot
//   android12_full.txt       ratType=/oemManaged=, 无 subId, networkId="SSID"
//   android13_uid.txt        --uid: UID stats(uid=-5 热点 + DBG_VPN_OUT + 普通应用) + UID tag stats
//   android14_full.txt       subId=, 不计费 IMS key, wifiNetworkKey 引号里伪造 type=/subId=
//   android16_full.txt       同 A14 + Configs/Stats Providers/BPF map content 等额外段
// 时间: 计费周期 2026-09-01 00:00 CST 起, now = 2026-09-30 12:00 CST。
//   Xt 卡1(460001) 每天 20:00 rb100M tb10M(9/1-9/29) + 9/30 10:00 rb5M tb1M, 另有 8/31 周期外 999M
//   Xt 卡2(460110) 9/10-9/29 每天 21:00 rb20M tb2M
//   UID -5 自 2026-09-28 08:00(开机)起每 2 小时 rb40M tb4M, 共 26 桶
//   Dev 的数值是 Xt 的 2 倍(验证优先用 Xt)

var (
	calTZ    = time.FixedZone("CST", 8*3600)
	calNow   = time.Date(2026, 9, 30, 12, 0, 0, 0, calTZ)
	calCycle = time.Date(2026, 9, 1, 0, 0, 0, 0, calTZ)
	calBoot  = time.Date(2026, 9, 28, 8, 0, 0, 0, calTZ).Unix()
)

const (
	mib         = 1 << 20
	calSlot1Cyc = 29*110*mib + 6*mib
	calSlot2Cyc = 20 * 22 * mib
	calSiminfo  = `Row: 0 _id=1, icc_id=89860012345678901234, sim_id=0, display_name=中国移动, carrier_name=CMCC, mcc_string=460, mnc_string=00, imsi=460001234567890
Row: 1 _id=2, icc_id=89860099999999999999, sim_id=-1, display_name=旧卡, carrier_name=CMCC, mcc_string=460, mnc_string=00, imsi=460009999999999
Row: 2 _id=3, icc_id=89861112345678901234, sim_id=1, display_name=中国电信, carrier_name=China Telecom, mcc_string=460, mnc_string=11, imsi=460110987654321
`
)

func loadFixture(t *testing.T, name string, keep func(string, int) bool) *nsDump {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "netstats", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := parseNetstatsDump(f, keep)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func keepCell(sec string, uid int) bool { return (sec == "xt" || sec == "dev") && uid == nsUIDAll }
func keepTether(sec string, uid int) bool {
	return sec == "uid" && uid == nsUIDTethering
}

func sumCycle(keys []*nsKey) uint64 {
	var t float64
	for _, k := range keys {
		rx, tx := nsWindowBytes(k, calCycle.Unix(), calNow.Unix()+1, calNow.Unix())
		t += rx + tx
	}
	return uint64(t)
}

// ─── 解析器 ───────────────────────────────────────────────────────

func TestNetstatsParseVersions(t *testing.T) {
	cases := []struct {
		file          string
		full          bool
		mobileKeys    int
		wantSubID     int
		wantUnmetered bool
	}{
		{"android10_sinceboot.txt", false, 2, -1, false},
		{"android12_full.txt", true, 2, -1, false},
		{"android13_uid.txt", false, 2, -1, false},
		{"android14_full.txt", true, 3, 1, true},
		{"android16_full.txt", true, 3, 1, true},
	}
	for _, c := range cases {
		d := loadFixture(t, c.file, nil)
		if !d.Sections["xt"] || !d.Sections["dev"] {
			t.Fatalf("%s: sections %v", c.file, d.Sections)
		}
		if d.FullSec["xt"] != c.full {
			t.Errorf("%s: full=%v want %v", c.file, d.FullSec["xt"], c.full)
		}
		mob := d.nsSelect("xt", nsUIDAll, "MOBILE")
		if len(mob) != c.mobileKeys {
			t.Fatalf("%s: mobile keys %d want %d", c.file, len(mob), c.mobileKeys)
		}
		id := mob[0].Primary()
		if id.Subscriber != "460001" || id.SubID != c.wantSubID || id.Metered != 1 {
			t.Errorf("%s: ident %+v", c.file, id)
		}
		if mob[0].BucketSec != 3600 || len(mob[0].Buckets) != 31 {
			t.Errorf("%s: bucketSec=%d n=%d", c.file, mob[0].BucketSec, len(mob[0].Buckets))
		}
		unmetered := false
		for _, k := range mob {
			if k.Primary().Metered == 0 {
				unmetered = true
			}
		}
		if unmetered != c.wantUnmetered {
			t.Errorf("%s: unmetered=%v", c.file, unmetered)
		}
		if n := len(d.nsSelect("xt", nsUIDAll, "WIFI")); n != 1 {
			t.Errorf("%s: wifi keys %d", c.file, n)
		}
		// Xt 周期内合计: 卡1 + 卡2(不含 8/31 周期外桶)
		var metered []*nsKey
		for _, k := range mob {
			if k.Primary().Metered != 0 {
				metered = append(metered, k)
			}
		}
		if got := sumCycle(metered); got != calSlot1Cyc+calSlot2Cyc {
			t.Errorf("%s: cycle metered %d want %d", c.file, got, calSlot1Cyc+calSlot2Cyc)
		}
		// Dev 是 2 倍
		if got := sumCycle(d.nsSelect("dev", nsUIDAll, "MOBILE")); c.mobileKeys == 2 && got != 2*(calSlot1Cyc+calSlot2Cyc) {
			t.Errorf("%s: dev cycle %d", c.file, got)
		}
	}
}

func TestNetstatsParseNumericTypeAndQuotedSSID(t *testing.T) {
	d := loadFixture(t, "android10_sinceboot.txt", nil)
	mob := d.nsSelect("xt", nsUIDAll, "MOBILE")
	if mob[1].Primary().Subscriber != "460110" { // "type=0" → MOBILE
		t.Errorf("numeric type ident %+v", mob[1].Primary())
	}
	d = loadFixture(t, "android14_full.txt", nil)
	w := d.nsSelect("xt", nsUIDAll, "WIFI")
	if len(w) != 1 || w[0].Primary().SubID != -1 || w[0].Primary().Type != "WIFI" {
		t.Fatalf("quoted wifiNetworkKey must not leak type/subId: %+v", w)
	}
	id := nsParseIdent(`{type=MOBILE, subscriberId=null, metered=false, roaming=true}`)
	if id.Subscriber != "" || id.Metered != 0 || !id.Roaming || id.SubID != -1 {
		t.Errorf("ident %+v", id)
	}
	set := nsParseIdentSet(`{type=MOBILE, subscriberId=460001...}, {type=MOBILE, subscriberId=460110...}`)
	if len(set) != 2 || set[1].Subscriber != "460110" {
		t.Errorf("ident set %+v", set)
	}
}

func TestNetstatsParseUidTether(t *testing.T) {
	d := loadFixture(t, "android13_uid.txt", nil)
	if !d.Sections["uid"] || !d.Sections["uidtag"] {
		t.Fatalf("sections %v", d.Sections)
	}
	teth := d.nsSelect("uid", nsUIDTethering, "")
	if len(teth) != 1 || teth[0].Set != "DEFAULT" || teth[0].BucketSec != 7200 || len(teth[0].Buckets) != 26 {
		t.Fatalf("tether keys %+v", teth) // DBG_VPN_OUT 与 uidtag 段不算
	}
	if got := sumCycle(teth); got != 26*44*mib {
		t.Errorf("tether %d", got)
	}
	// keep 过滤: 只留 uid -5
	d = loadFixture(t, "android13_uid.txt", keepTether)
	for _, k := range d.Keys {
		if k.UID != nsUIDTethering || k.Section != "uid" {
			t.Errorf("kept %s uid=%d", k.Section, k.UID)
		}
	}
	if len(d.Keys) != 2 { // DEFAULT + DBG_VPN_OUT(保留但 nsCountable 排除)
		t.Errorf("kept %d", len(d.Keys))
	}
}

func TestNetstatsParseA16ExtraSections(t *testing.T) {
	d := loadFixture(t, "android16_full.txt", nil)
	for _, k := range d.Keys {
		if k.Section != "dev" && k.Section != "xt" {
			t.Errorf("stray key in section %q (BPF map content 里的 ident 不应被解析)", k.Section)
		}
	}
	if len(d.Keys) != 8 {
		t.Errorf("keys %d want 8", len(d.Keys))
	}
}

func TestNetstatsParseGarbage(t *testing.T) {
	d, err := parseNetstatsDump(strings.NewReader("Can't find service: netstats\n"), nil)
	if err != nil || len(d.Keys) != 0 || d.Sections["xt"] {
		t.Fatalf("%+v %v", d, err)
	}
	// 毫秒 st
	d, _ = parseNetstatsDump(strings.NewReader("Xt stats:\n  ident=[{type=MOBILE}] uid=-1 set=ALL tag=0x0\n    NetworkStatsHistory: bucketDuration=3600\n      st=1788192000000 rb=10 tb=5\n"), nil)
	if len(d.Keys) != 1 || d.Keys[0].Buckets[0].St != 1788192000 || d.Keys[0].Buckets[0].Tx != 5 {
		t.Fatalf("%+v", d.Keys)
	}
}

func TestNsWindowBytesProration(t *testing.T) {
	k := &nsKey{BucketSec: 7200, Buckets: []nsBucket{{St: 0, Rx: 7200, Tx: 0}, {St: 7200, Rx: 3600, Tx: 3600}}}
	// 窗口 [3600, 7200): 第一个桶一半
	if rx, _ := nsWindowBytes(k, 3600, 7200, 100000); rx != 3600 {
		t.Errorf("half bucket rx=%v", rx)
	}
	// 未结束的桶: now=9000, 桶 [7200, 9000] 只过了 1800 秒, 窗口 [8100, ∞) 取一半
	if rx, tx := nsWindowBytes(k, 8100, 1<<40, 9000); rx != 1800 || tx != 1800 {
		t.Errorf("open bucket %v %v", rx, tx)
	}
	// 整个窗口
	if rx, tx := nsWindowBytes(k, 0, 1<<40, 1<<30); rx != 10800 || tx != 3600 {
		t.Errorf("all %v %v", rx, tx)
	}
}

// ─── 卡槽映射 ─────────────────────────────────────────────────────

func TestCalParseSiminfo(t *testing.T) {
	subs := calParseSiminfo(calSiminfo + "Row: 3 _id=7, sim_id=0, display_name=NULL, carrier_name=CU, mcc=460, mnc=1\n")
	if len(subs) != 4 {
		t.Fatalf("%+v", subs)
	}
	if subs[0].IMSI != "460001234567890" || subs[0].MCC != "460" || subs[0].MNC != "00" || subs[0].SlotIndex != 0 {
		t.Errorf("%+v", subs[0])
	}
	if subs[3].MNC != "01" || subs[3].Name != "" || subs[3].label() != "CU" {
		t.Errorf("int mnc fallback %+v", subs[3])
	}
}

func TestCalMapSlot(t *testing.T) {
	subs := calParseSiminfo(calSiminfo)
	cases := []struct {
		id   nsIdent
		subs []calSub
		slot int
		via  string
	}{
		{nsIdent{SubID: 3, Subscriber: "460001"}, subs, 2, "sub_id"}, // subId 优先
		{nsIdent{SubID: -1, Subscriber: "460001"}, subs, 1, "imsi"},  // 旧卡 _id=2 未插不参与
		{nsIdent{SubID: -1, Subscriber: "460110"}, subs, 2, "imsi"},
		{nsIdent{SubID: 2, Subscriber: ""}, subs, 0, "none"}, // subId 指向未插的卡
		// 无 IMSI 列 → MCC+MNC
		{nsIdent{SubID: -1, Subscriber: "460110"}, []calSub{{SubID: 1, SlotIndex: 0, MCC: "460", MNC: "00"}, {SubID: 2, SlotIndex: 1, MCC: "460", MNC: "11"}}, 2, "plmn"},
		// 连 MCC/MNC 都没有 → 运营商名家族
		{nsIdent{SubID: -1, Subscriber: "460030"}, []calSub{{SubID: 1, SlotIndex: 0, Name: "中国移动"}, {SubID: 2, SlotIndex: 1, Carrier: "中国电信"}}, 2, "carrier_name"},
		// 两张移动卡 → 无法区分
		{nsIdent{SubID: -1, Subscriber: "460002"}, []calSub{{SubID: 1, SlotIndex: 0, Name: "中国移动"}, {SubID: 2, SlotIndex: 1, Name: "CMCC"}}, 0, "none"},
	}
	for i, c := range cases {
		slot, via, _ := calMapSlot(c.id, c.subs)
		if slot != c.slot || via != c.via {
			t.Errorf("case %d: got %d/%s want %d/%s", i, slot, via, c.slot, c.via)
		}
	}
}

// ─── HNC 侧 ───────────────────────────────────────────────────────

func mkPuDay(date string, cell map[string][2]uint64, hsHours map[int]uint64) *puDay {
	d := newPuDay(date)
	for k, v := range cell {
		d.Cell[k] = v
		c := d.Hours["20"]
		if c == nil {
			c = &puHour{}
			d.Hours["20"] = c
		}
		puAdd2(&c.Cell, v)
	}
	for h, b := range hsHours {
		x := d.Hours[strconv.Itoa(h)]
		if x == nil {
			x = &puHour{}
			d.Hours[strconv.Itoa(h)] = x
		}
		x.Hotspot[0] += b
		d.Hotspot[0] += b
	}
	return d
}

// hncCycleDays HNC 与系统完全一致 × factor
func hncCycleDays(factor float64) []*puDay {
	var days []*puDay
	for d := 1; d <= 30; d++ {
		date := time.Date(2026, 9, d, 0, 0, 0, 0, calTZ).Format("20060102")
		cell := map[string][2]uint64{}
		if d <= 29 {
			cell["1|中国移动"] = [2]uint64{uint64(100 * mib * factor), uint64(10 * mib * factor)}
		} else {
			cell["1|中国移动"] = [2]uint64{uint64(5 * mib * factor), uint64(1 * mib * factor)}
		}
		if d >= 10 && d <= 29 {
			cell["2|中国电信"] = [2]uint64{uint64(20 * mib * factor), uint64(2 * mib * factor)}
		}
		hs := map[int]uint64{}
		for h := 0; h < 24; h++ {
			if (d == 28 && h >= 8) || d == 29 || (d == 30 && h < 12) {
				hs[h] = 11 * mib
			}
		}
		days = append(days, mkPuDay(date, cell, hs))
	}
	return days
}

func calTestInput(t *testing.T, xtFile string, factor float64) calInput {
	return calInput{Now: calNow, CycleStart: calCycle,
		Xt:   loadFixture(t, xtFile, keepCell),
		Uid:  loadFixture(t, "android13_uid.txt", keepTether),
		Subs: calParseSiminfo(calSiminfo), Days: hncCycleDays(factor),
		Earliest: "20260815", BootTime: calBoot}
}

func TestCalComputeOK(t *testing.T) {
	for _, f := range []string{"android12_full.txt", "android14_full.txt", "android16_full.txt"} {
		r := calCompute(calTestInput(t, f, 1))
		if r.Status != "ok" || !r.NetstatsOK || !r.WindowFull || r.WindowStart != calCycle.Unix() {
			t.Fatalf("%s: %+v", f, r)
		}
		if r.HNCvsNetstatsPct == nil || *r.HNCvsNetstatsPct != 0 {
			t.Errorf("%s: pct %v", f, r.HNCvsNetstatsPct)
		}
		if len(r.NetstatsCellBySim) != 2 || r.NetstatsCellBySim[0].Slot != 1 || r.NetstatsCellBySim[0].Total != calSlot1Cyc ||
			r.NetstatsCellBySim[1].Slot != 2 || r.NetstatsCellBySim[1].Total != calSlot2Cyc {
			t.Fatalf("%s: by sim %+v", f, r.NetstatsCellBySim)
		}
		wantVia := "imsi"
		if f != "android12_full.txt" {
			wantVia = "sub_id"
		}
		if r.NetstatsCellBySim[0].MapVia != wantVia || r.NetstatsCellBySim[1].Carrier != "中国电信" {
			t.Errorf("%s: %+v", f, r.NetstatsCellBySim)
		}
		if p := r.NetstatsCellBySim[0].Pct; p == nil || *p != 0 {
			t.Errorf("%s: per-sim pct %v", f, p)
		}
		if f != "android12_full.txt" && r.NetstatsCellUnmetered != 29*2*mib {
			t.Errorf("%s: unmetered %d", f, r.NetstatsCellUnmetered)
		}
		if r.NetstatsWifiTotal != 29*330*mib {
			t.Errorf("%s: wifi %d", f, r.NetstatsWifiTotal)
		}
		// 热点: 系统 26 桶 × 44M = 1144M 自开机; HNC 52 小时 × 11M = 572M → 漏 50%
		if r.NetstatsTetherTotal == nil || *r.NetstatsTetherTotal != 1144*mib || r.NetstatsTetherSince != calBoot {
			t.Errorf("%s: tether %v since %d", f, r.NetstatsTetherTotal, r.NetstatsTetherSince)
		}
		if r.Hotspot == nil || r.Hotspot.HNC != 572*mib || r.Hotspot.GapPct == nil || *r.Hotspot.GapPct != 50 {
			t.Errorf("%s: hotspot %+v", f, r.Hotspot)
		}
	}
}

func TestCalComputeDrift(t *testing.T) {
	r := calCompute(calTestInput(t, "android14_full.txt", 0.9))
	if r.Status != "drift" || r.HNCvsNetstatsPct == nil || math.Abs(*r.HNCvsNetstatsPct+10) > 0.11 {
		t.Fatalf("status=%s pct=%v", r.Status, r.HNCvsNetstatsPct)
	}
	if len(r.TextCN) == 0 || !strings.Contains(r.TextCN[0], "10.0%") || !strings.Contains(r.TextCN[0], "HNC 偏少") {
		t.Errorf("text %v", r.TextCN)
	}
	// 小偏差 → ok
	r = calCompute(calTestInput(t, "android14_full.txt", 0.97))
	if r.Status != "ok" {
		t.Errorf("3%% should be ok, got %s %v", r.Status, *r.HNCvsNetstatsPct)
	}
	// 流量太小 → ok + low_volume
	in := calTestInput(t, "android14_full.txt", 0.5)
	in.Now = time.Date(2026, 9, 1, 12, 0, 0, 0, calTZ)
	in.Days = in.Days[:1]
	r = calCompute(in)
	if r.Status != "ok" || !r.LowVolume {
		t.Errorf("low volume: %s %v", r.Status, r.LowVolume)
	}
}

func TestCalComputeUnavailable(t *testing.T) {
	r := calCompute(calInput{Now: calNow, CycleStart: calCycle})
	if r.Status != "unavailable" || r.Reason != "netstats_parse_failed" || r.NetstatsOK {
		t.Fatalf("%+v", r)
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"netstats_cell_by_sim":[]`) || !strings.Contains(string(b), `"hnc_vs_netstats_pct":null`) {
		t.Errorf("json %s", b)
	}
	// HNC 没数据: 系统数值照给, 状态 unavailable
	in := calTestInput(t, "android12_full.txt", 1)
	in.Earliest, in.Days = "", nil
	r = calCompute(in)
	if r.Status != "unavailable" || r.Reason != "hnc_no_data" || !r.NetstatsOK || r.NetstatsCellTotal != calSlot1Cyc+calSlot2Cyc {
		t.Fatalf("%+v", r)
	}
}

func TestCalWindowStart(t *testing.T) {
	day := func(date string, hours ...int) *puDay {
		d := newPuDay(date)
		for _, h := range hours {
			d.Hours[strconv.Itoa(h)] = &puHour{}
		}
		return d
	}
	// 周期当天 0 点就有数据 → 全周期
	ws, full, why := calWindowStart(calCycle, []*puDay{day("20260901", 0, 5)}, "20260901", calNow)
	if !full || !ws.Equal(calCycle) || why != "" {
		t.Errorf("full: %v %v %q", ws, full, why)
	}
	// 周期中途装机, 已过一天以上 → 次日零点
	ws, full, _ = calWindowStart(calCycle, []*puDay{day("20260920", 14, 15)}, "20260920", calNow)
	if full || !ws.Equal(time.Date(2026, 9, 21, 0, 0, 0, 0, calTZ)) {
		t.Errorf("partial: %v %v", ws, full)
	}
	// 今天刚装: 第一个有数据的小时的下一个整点
	ws, _, why = calWindowStart(calCycle, []*puDay{day("20260930", 9)}, "20260930", calNow)
	if !ws.Equal(time.Date(2026, 9, 30, 10, 0, 0, 0, calTZ)) || why != "" {
		t.Errorf("today: %v %q", ws, why)
	}
	// 不满 1 小时
	_, _, why = calWindowStart(calCycle, []*puDay{day("20260930", 11)}, "20260930", calNow)
	if why != "hnc_history_too_short" {
		t.Errorf("short: %q", why)
	}
	// 非零点窗口: 只比总量, 每卡 pct 不给
	in := calTestInput(t, "android14_full.txt", 1)
	in.Earliest = "20260930"
	in.Days = []*puDay{mkPuDay("20260930", map[string][2]uint64{"1|中国移动": {5 * mib, 1 * mib}}, map[int]uint64{8: mib})}
	in.Days[0].Hours["8"].Cell = [2]uint64{}
	r := calCompute(in)
	if r.Status != "ok" || r.WindowFull || r.NetstatsCellBySim[0].Pct != nil || r.NetstatsCellBySim[0].HNCWindowTotal != nil {
		t.Errorf("partial-hour window %+v", r)
	}
}

// ─── 分流漏计 ─────────────────────────────────────────────────────

func TestCalLiveWindowHW(t *testing.T) {
	uid := loadFixture(t, "android13_uid.txt", keepTether)
	now := calNow.Unix()
	base := calSnap{T: now - 4*3600, HsIface: "wlan2", HsIfindex: 30, HsBytes: 1000, HsOK: true, FwdV4: 0, FwdV4OK: true, FwdV6: 0, FwdV6OK: true}
	cur := calSnap{T: now, HsIface: "wlan2", HsIfindex: 30, HsBytes: 1000 + 44*mib, HsOK: true, FwdV4: 30 * mib, FwdV4OK: true, FwdV6: 10 * mib, FwdV6OK: true}
	// 太新的快照(< 1 小时)不当起点
	w := calLiveWindow([]calSnap{{T: now - 600}, base}, cur, uid)
	if w == nil || w.From != base.T || w.NetstatsTether != 88*mib {
		t.Fatalf("%+v", w)
	}
	if w.HotspotGapPct == nil || *w.HotspotGapPct != 50 || w.FwdGapPct == nil || math.Abs(*w.FwdGapPct-54.5) > 0.1 {
		t.Fatalf("gaps hs=%v fwd=%v", w.HotspotGapPct, w.FwdGapPct)
	}
	res := calResult{}
	calMergeOffload(&res, w)
	if res.OffloadKind != "hw" || *res.OffloadGapPct != 50 || res.OffloadGapSource != "live_window" ||
		len(res.TextCN) != 1 || res.TextCN[0] != "硬件分流导致漏计 ≈ 50%" {
		t.Errorf("%+v %v", res, res.TextCN)
	}
}

func TestCalLiveWindowBPF(t *testing.T) {
	uid := loadFixture(t, "android13_uid.txt", keepTether)
	now := calNow.Unix()
	base := calSnap{T: now - 4*3600, HsIface: "wlan2", HsOK: true, FwdV4OK: true}
	cur := calSnap{T: now, HsIface: "wlan2", HsBytes: 90 * mib, HsOK: true, FwdV4: 20 * mib, FwdV4OK: true}
	res := calResult{}
	calMergeOffload(&res, calLiveWindow([]calSnap{base}, cur, uid))
	if res.OffloadKind != "bpf" || res.OffloadGapSource != "iptables" || res.OffloadGapPct == nil || math.Abs(*res.OffloadGapPct-77.3) > 0.1 {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(res.TextCN[0], "BPF") {
		t.Errorf("%v", res.TextCN)
	}
	// 热点重建(ifindex 变了)→ 热点口差分无效, 只剩 iptables
	cur.HsIfindex, base.HsIfindex = 31, 30
	w := calLiveWindow([]calSnap{base}, cur, uid)
	if w.HotspotBytes != nil || w.FwdGapPct == nil {
		t.Errorf("%+v", w)
	}
	res = calResult{}
	calMergeOffload(&res, w)
	if res.OffloadKind != "unknown" {
		t.Errorf("kind %s", res.OffloadKind)
	}
	// 无分流
	cur = calSnap{T: now, HsIface: "wlan2", HsBytes: 89 * mib, HsOK: true, FwdV4: 85 * mib, FwdV4OK: true}
	base.HsIfindex = 0
	res = calResult{}
	calMergeOffload(&res, calLiveWindow([]calSnap{base}, cur, uid))
	if res.OffloadKind != "none" || len(res.TextCN) != 0 {
		t.Errorf("%+v", res)
	}
	// 没有实时窗口 → 退周期窗口
	res = calResult{Hotspot: &calHotspotCmp{GapPct: func() *float64 { v := 30.0; return &v }()}}
	calMergeOffload(&res, nil)
	if res.OffloadGapSource != "cycle_window" || res.OffloadKind != "hw" {
		t.Errorf("%+v", res)
	}
}

func TestCalParseIptForward(t *testing.T) {
	v4 := `Chain FORWARD (policy ACCEPT 1200 packets, 900000 bytes)
    pkts      bytes target     prot opt in     out     source               destination
  500000 612345678 tetherctrl_mangle_FORWARD  all  --  *      *       0.0.0.0/0            0.0.0.0/0
  499000 610000000 HNC_STATS  all  --  *      *       0.0.0.0/0            0.0.0.0/0
`
	p, pok, j, jok := calParseIptForward(v4)
	if !pok || p != 900000 || !jok || j != 610000000 {
		t.Errorf("%d %v %d %v", p, pok, j, jok)
	}
	_, _, _, jok = calParseIptForward("Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)\n")
	if jok {
		t.Error("no jump expected")
	}
	if calParseBootTime("cpu 1 2 3\nbtime 1790553600\nprocesses 5\n") != 1790553600 {
		t.Error("btime")
	}
}

// ─── 端到端(假 env) + /api/phone_usage 挂接 ─────────────────────

func fakeCalEnv(t *testing.T, xt string) calEnv {
	rd := func(n string) string {
		b, err := os.ReadFile(filepath.Join("testdata", "netstats", n))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return calEnv{
		run: func(_ time.Duration, name string, args ...string) (string, error) {
			j := name + " " + strings.Join(args, " ")
			switch {
			case strings.HasSuffix(j, "--poll"):
				return "Forced poll\n", nil
			case strings.HasSuffix(j, "--full"):
				return rd(xt), nil
			case strings.HasSuffix(j, "--uid"):
				return rd("android13_uid.txt"), nil
			case strings.HasPrefix(j, "content query"):
				return calSiminfo, nil
			case strings.HasPrefix(j, "iptables"):
				return "Chain FORWARD (policy ACCEPT 1 packets, 2 bytes)\n 1 100 HNC_STATS all -- * * 0.0.0.0/0 0.0.0.0/0\n", nil
			}
			return "", os.ErrNotExist
		},
		readNetDev:   func() ([]byte, error) { return []byte(" wlan2: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n"), nil },
		hotspotIface: func() string { return "wlan2" },
		bootTime:     func() int64 { return calBoot },
	}
}

func TestCalibratorCheckAndAttach(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	defer clockForget(dir)
	for _, d := range hncCycleDays(0.9) {
		if err := puSaveDay(dir, d); err != nil {
			t.Fatal(err)
		}
	}
	// 周期前一天的文件 → 全周期覆盖
	if err := puSaveDay(dir, newPuDay("20260831")); err != nil {
		t.Fatal(err)
	}
	pu := newPuEngine(dir, puEnv{})
	c := calInstall(dir, fakeCalEnv(t, "android14_full.txt"))
	defer func() { calReg.mu.Lock(); delete(calReg.m, dir); calReg.mu.Unlock() }()
	c.check(calNow, pu)
	r := c.result()
	if r == nil || r.Status != "drift" || r.UseNetstats != "auto" || !r.WindowFull {
		t.Fatalf("%+v", r)
	}
	if !c.cur.HsOK || c.cur.HsBytes != 300 || !c.cur.FwdV4OK || c.cur.FwdV4 != 100 {
		t.Errorf("snap %+v", c.cur)
	}

	cfg := puLoadConfig(dir)
	row := func() []map[string]interface{} {
		return []map[string]interface{}{
			{"slot": 1, "cycle_used": uint64(123), "plan_bytes": uint64(10 * puGiB), "used_pct": 0.0},
			{"slot": 2, "cycle_used": uint64(7), "plan_bytes": uint64(0), "used_pct": nil},
		}
	}
	// auto: 只加 netstats_cycle_used
	resp := map[string]interface{}{}
	rows := row()
	puCalAttach(dir, cfg, calCycle, calNow, resp, rows)
	if resp["primary_source"] != "hnc" || rows[0]["netstats_cycle_used"] != uint64(calSlot1Cyc) || rows[0]["cycle_used"] != uint64(123) {
		t.Fatalf("auto %v %v", resp["primary_source"], rows[0])
	}
	// prefer: 替换
	if ar := actionPhoneUsageSet(dir, map[string]string{"use_netstats": "prefer"}); !ar.OK {
		t.Fatal(ar)
	}
	cfg = puLoadConfig(dir)
	resp, rows = map[string]interface{}{}, row()
	puCalAttach(dir, cfg, calCycle, calNow, resp, rows)
	if resp["primary_source"] != "netstats" || rows[0]["cycle_used"] != uint64(calSlot1Cyc) || rows[0]["hnc_cycle_used"] != uint64(123) ||
		rows[0]["cycle_used_source"] != "netstats" || rows[1]["cycle_used"] != uint64(calSlot2Cyc) {
		t.Fatalf("prefer %v", rows)
	}
	if pct := rows[0]["used_pct"].(float64); math.Abs(pct-31.2) > 0.05 {
		t.Errorf("used_pct %v", pct)
	}
	cal := resp["calibration"].(*calResult)
	if cal.Primary != "netstats" || cal.UseNetstats != "prefer" {
		t.Errorf("%+v", cal)
	}
	// prefer 的告警用量
	used := puCalPreferUsed(dir, cfg, calCycle, calNow, map[int]*puSimAgg{1: {Rx: 1, Tx: 1, Carrier: "中国移动"}})
	if used[1].Rx+used[1].Tx != calSlot1Cyc || used[1].Carrier != "中国移动" || used[2].Rx+used[2].Tx != calSlot2Cyc {
		t.Errorf("prefer used %+v %+v", used[1], used[2])
	}
	// 结果过期 → 不替换
	resp, rows = map[string]interface{}{}, row()
	puCalAttach(dir, cfg, calCycle, calNow.Add(3*time.Hour), resp, rows)
	if resp["primary_source"] != "hnc" || rows[0]["cycle_used"] != uint64(123) || !resp["calibration"].(*calResult).Stale {
		t.Errorf("stale %v", rows[0])
	}
	// 计费日改了 → 周期不一致, 不替换
	resp, rows = map[string]interface{}{}, row()
	puCalAttach(dir, cfg, calCycle.AddDate(0, 0, 4), calNow, resp, rows)
	if resp["primary_source"] != "hnc" || resp["calibration"].(*calResult).Reason != "cycle_changed" {
		t.Errorf("cycle changed %v", resp["calibration"])
	}
	// off: 不跑 dumpsys
	if ar := actionPhoneUsageSet(dir, map[string]string{"use_netstats": "off"}); !ar.OK {
		t.Fatal(ar)
	}
	ran := false
	env := fakeCalEnv(t, "android14_full.txt")
	inner := env.run
	env.run = func(to time.Duration, n string, a ...string) (string, error) {
		if n == "dumpsys" {
			ran = true
		}
		return inner(to, n, a...)
	}
	c.env = env
	c.check(calNow, pu)
	if ran || c.result().Reason != "disabled" {
		t.Errorf("off mode ran=%v %+v", ran, c.result())
	}
	resp = map[string]interface{}{}
	puCalAttach(dir, puLoadConfig(dir), calCycle, calNow, resp, row())
	if resp["calibration"].(*calResult).Reason != "disabled" {
		t.Errorf("%+v", resp["calibration"])
	}
}

func TestActionPhoneUsageSetUseNetstats(t *testing.T) {
	dir := t.TempDir()
	if ar := actionPhoneUsageSet(dir, map[string]string{"use_netstats": "sometimes"}); ar.OK {
		t.Fatal("bad value accepted")
	}
	if ar := actionPhoneUsageSet(dir, map[string]string{"use_netstats": " Prefer "}); !ar.OK || !strings.Contains(ar.Detail, "use_netstats=prefer") {
		t.Fatal(ar)
	}
	if puLoadConfig(dir).netstatsMode() != "prefer" {
		t.Error("not persisted")
	}
	if (puConfig{}).netstatsMode() != "auto" {
		t.Error("default must be auto")
	}
}
