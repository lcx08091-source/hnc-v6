package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// 测试用编码器(与 tools/build_ip_owner.py 的格式一致; 生成器本身另有交叉测试)
type tOrg struct {
	key, name string
	kind      uint8
}
type tR4 struct {
	s, e uint32
	o    uint16
}
type tR6 struct {
	s, e uint64
	o    uint16
}

func encIPOwner(orgs []tOrg, v4 []tR4, v6 []tR6) []byte {
	var b bytes.Buffer
	b.WriteString(ipOwnerMagic)
	_ = binary.Write(&b, binary.LittleEndian, uint32(20260101))
	_ = binary.Write(&b, binary.LittleEndian, uint16(len(orgs)))
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(v4)))
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(v6)))
	for _, o := range orgs {
		b.WriteByte(o.kind)
		b.WriteByte(byte(len(o.key)))
		b.WriteString(o.key)
		b.WriteByte(byte(len(o.name)))
		b.WriteString(o.name)
	}
	for _, r := range v4 {
		_ = binary.Write(&b, binary.LittleEndian, r.s)
		_ = binary.Write(&b, binary.LittleEndian, r.e)
		_ = binary.Write(&b, binary.LittleEndian, r.o)
	}
	for _, r := range v6 {
		_ = binary.Write(&b, binary.LittleEndian, r.s)
		_ = binary.Write(&b, binary.LittleEndian, r.e)
		_ = binary.Write(&b, binary.LittleEndian, r.o)
	}
	_ = binary.Write(&b, binary.LittleEndian, crc32.ChecksumIEEE(b.Bytes()))
	return b.Bytes()
}

func ip4(a, b, c, d byte) uint32 { return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d) }

func testOwnerDB(t *testing.T) *ipOwnerDB {
	t.Helper()
	blob := encIPOwner(
		[]tOrg{{"tencent", "腾讯", ipOwnerKindApp}, {"cloudflare", "Cloudflare", ipOwnerKindCDN}, {"aliyun", "阿里云", ipOwnerKindCloud}, {"bytedance", "字节跳动", ipOwnerKindApp}},
		[]tR4{{ip4(1, 1, 1, 0), ip4(1, 1, 1, 255), 1}, {ip4(8, 130, 0, 0), ip4(8, 130, 255, 255), 2},
			{ip4(20, 0, 0, 0), ip4(20, 0, 1, 255), 0}, {ip4(20, 0, 2, 0), ip4(20, 0, 2, 255), 3}},
		[]tR6{{0x2400cb0000000000, 0x2400cb01ffffffff, 1}, {0x2402_4e00_0000_0000, 0x2402_4e00_ffff_ffff, 0}},
	)
	db, err := parseIPOwner(blob)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestIPOwnerParseLookupBoundaries(t *testing.T) {
	db := testOwnerDB(t)
	cases := map[string]string{
		"1.1.1.0": "cloudflare", "1.1.1.255": "cloudflare", "1.1.0.255": "", "1.1.2.0": "",
		"20.0.0.0": "tencent", "20.0.1.255": "tencent", "20.0.2.0": "bytedance", "20.0.2.255": "bytedance", "20.0.3.0": "",
		"0.0.0.0": "", "255.255.255.255": "", "8.130.5.6": "aliyun",
		"2400:cb00::1": "cloudflare", "2400:cb01:ffff:ffff:ffff::1": "cloudflare", "2400:cb02::": "",
		"2402:4e00::": "tencent", "2402:4e00:ffff:ffff:ffff:ffff:ffff:ffff": "tencent", "2402:4e01::": "",
		"::ffff:20.0.0.1": "tencent", // v4-mapped 按 v4 查
		"not-an-ip":       "", "": "",
	}
	for ip, want := range cases {
		o, ok := db.lookup(ip)
		if (want == "") == ok || (ok && o.Key != want) {
			t.Errorf("%s: got %v/%v want %q", ip, o.Key, ok, want)
		}
	}
	if o, _ := db.lookup("20.0.0.1"); o.AppID() != "_org:tencent" || o.AppName() != "腾讯系(未细分)" || o.KindName() != "app" {
		t.Errorf("tencent app meta: %v %v %v", o.AppID(), o.AppName(), o.KindName())
	}
	if o, _ := db.lookup("20.0.2.1"); o.AppName() != "字节系(未细分)" {
		t.Errorf("bytedance short name: %s", o.AppName())
	}
	var nilDB *ipOwnerDB
	if _, ok := nilDB.lookup("1.1.1.1"); ok {
		t.Error("nil db must miss")
	}
}

func TestIPOwnerParseRejectsCorrupt(t *testing.T) {
	good := encIPOwner([]tOrg{{"a", "A", 1}}, []tR4{{1, 2, 0}, {5, 9, 0}}, nil)
	if _, err := parseIPOwner(good); err != nil {
		t.Fatal(err)
	}
	bad := map[string][]byte{
		"empty":     nil,
		"magic":     append([]byte("XXXXXXXX"), good[8:]...),
		"truncated": good[:len(good)-7],
		"unsorted":  encIPOwner([]tOrg{{"a", "A", 1}}, []tR4{{5, 9, 0}, {1, 2, 0}}, nil),
		"overlap":   encIPOwner([]tOrg{{"a", "A", 1}}, []tR4{{1, 5, 0}, {5, 9, 0}}, nil),
		"inverted":  encIPOwner([]tOrg{{"a", "A", 1}}, []tR4{{9, 5, 0}}, nil),
		"badorg":    encIPOwner([]tOrg{{"a", "A", 1}}, []tR4{{1, 2, 3}}, nil),
		"v6overlap": encIPOwner([]tOrg{{"a", "A", 1}}, nil, []tR6{{1, 5, 0}, {4, 9, 0}}),
	}
	flip := append([]byte(nil), good...)
	flip[len(flip)-8] ^= 0xff
	bad["crc"] = flip
	for name, b := range bad {
		if _, err := parseIPOwner(b); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestIPOwnerLazyLoadAndReload(t *testing.T) {
	dir := t.TempDir()
	ipOwnerSetDB(nil)
	defer ipOwnerSetDB(nil)
	ipOwnerConfigure(dir)
	defer ipOwnerConfigure("")
	if _, ok := ipOwnerLookup("20.0.0.1"); ok {
		t.Fatal("no file → miss")
	}
	_ = os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	p := filepath.Join(dir, "data", "ip_owner.bin")
	_ = os.WriteFile(p, encIPOwner([]tOrg{{"tencent", "腾讯", 1}}, []tR4{{ip4(20, 0, 0, 0), ip4(20, 0, 0, 255), 0}}, nil), 0o644)
	ipOwnerConfigure("") // 改目录 = 立即重查
	ipOwnerConfigure(dir)
	if o, ok := ipOwnerLookup("20.0.0.1"); !ok || o.Key != "tencent" {
		t.Fatalf("lazy load: %v %v", o, ok)
	}
	if _, ok := ipOwnerLookup("192.168.1.1"); ok {
		t.Error("private address must not be looked up")
	}
	// 用户覆盖 etc/ 优先; 文件变了(检查间隔到期后)重读
	_ = os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "etc", "ip_owner.bin"), encIPOwner([]tOrg{{"meta", "Meta", 1}}, []tR4{{ip4(20, 0, 0, 0), ip4(20, 0, 0, 255), 0}}, nil), 0o644)
	ipOwnerSrc.mu.Lock()
	ipOwnerSrc.checked = time.Now().Add(-2 * ipOwnerRecheck)
	ipOwnerSrc.mu.Unlock()
	if o, _ := ipOwnerLookup("20.0.0.1"); o.Key != "meta" {
		t.Fatalf("override/reload: %v", o.Key)
	}
	// 损坏文件 → 当作没有
	_ = os.WriteFile(filepath.Join(dir, "etc", "ip_owner.bin"), []byte("garbage"), 0o644)
	ipOwnerSrc.mu.Lock()
	ipOwnerSrc.checked = time.Time{}
	ipOwnerSrc.mu.Unlock()
	if _, ok := ipOwnerLookup("20.0.0.1"); ok {
		t.Fatal("corrupt file must disable lookups")
	}
	// 环境变量最优先
	t.Setenv("HNC_IP_OWNER_PATH", p)
	ipOwnerSrc.mu.Lock()
	ipOwnerSrc.checked = time.Time{}
	ipOwnerSrc.mu.Unlock()
	if o, _ := ipOwnerLookup("20.0.0.1"); o.Key != "tencent" {
		t.Fatalf("env path: %v", o.Key)
	}
}

func repoRoot() string { return filepath.Join("..", "..") }

// 生成器 + 加载器交叉测试: 用 testdata 里的小 ip2asn 夹具跑 tools/build_ip_owner.py
func TestIPOwnerGeneratorFixture(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	out := filepath.Join(t.TempDir(), "o.bin")
	cmd := exec.Command(py, filepath.Join(repoRoot(), "tools", "build_ip_owner.py"),
		"--v4", filepath.Join("testdata", "ip_owner", "v4.tsv"), "--v6", filepath.Join("testdata", "ip_owner", "v6.tsv"),
		"--date", "20260101", "--out", out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generator: %v\n%s", err, b)
	}
	b, _ := os.ReadFile(out)
	db, err := parseIPOwner(b)
	if err != nil {
		t.Fatal(err)
	}
	if db.date != 20260101 {
		t.Errorf("date %d", db.date)
	}
	// 合并: 1.1.1.0/24(AS13335) + 1.1.2.0/23(AS209242) 同属 cloudflare → 一段;
	//       20.0.0.0/24 + 20.0.1.0/24(两个腾讯 ASN) → 一段;
	// 手工网段 183.232.84.0/24 把中国移动段劈成三段; 未关注的 ASN(19281/99999/0)不入库
	if len(db.v4s) != 8 {
		t.Errorf("v4 ranges = %d, want 8", len(db.v4s))
	}
	if len(db.v6s) != 4 {
		t.Errorf("v6 ranges = %d, want 4", len(db.v6s))
	}
	cases := map[string]string{
		"1.0.0.7": "cloudflare", "1.0.1.1": "", "1.1.1.1": "cloudflare", "1.1.3.255": "cloudflare", "1.1.4.0": "",
		"9.9.9.9": "", "20.0.1.200": "tencent", "20.0.2.1": "bytedance",
		"183.232.83.255": "chinamobile", "183.232.84.0": "tencent", "183.232.84.255": "tencent", "183.232.85.0": "chinamobile",
		"255.255.255.255": "google",
		"2400:cb00::1":    "cloudflare", "2400:cb01:1::": "cloudflare", "2402:4e00:1::": "tencent", "2402:4e01::1": "",
		"2001:db8::5": "tencent", "2001:db8:0:1::5": "google", "2001:db8:0:2::": "",
	}
	for ip, want := range cases {
		o, ok := db.lookup(ip)
		if (want == "") == ok || (ok && o.Key != want) {
			t.Errorf("%s: got %q/%v want %q", ip, o.Key, ok, want)
		}
	}
	// 区间之间必须有空隙或组织不同(否则没合并)
	for i := 1; i < len(db.v4s); i++ {
		if db.v4s[i] == db.v4e[i-1]+1 && db.v4o[i] == db.v4o[i-1] {
			t.Errorf("v4 ranges %d/%d not merged", i-1, i)
		}
	}
}

// 随模块发布的数据文件: 能解析、体积受控、常见地址查得对、查得快
func TestIPOwnerShippedData(t *testing.T) {
	p := filepath.Join(repoRoot(), "data", "ip_owner.bin")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("shipped data missing: %v", err)
	}
	if len(b) > 2<<20 {
		t.Fatalf("data/ip_owner.bin too large: %d", len(b))
	}
	db, err := parseIPOwner(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.v4s) < 1000 || len(db.v6s) < 100 {
		t.Fatalf("suspiciously small: v4 %d v6 %d", len(db.v4s), len(db.v6s))
	}
	for ip, want := range map[string]string{
		"1.1.1.1": "cloudflare", "8.8.8.8": "google", "17.253.144.10": "apple", "157.240.1.35": "meta",
		"183.232.84.1": "tencent", "2606:4700::1111": "cloudflare", "2a03:2880:f12f:83:face:b00c::25de": "meta",
	} {
		if o, ok := db.lookup(ip); !ok || o.Key != want {
			t.Errorf("%s: got %q want %q", ip, o.Key, want)
		}
	}
	keys := map[string]bool{}
	for _, o := range db.orgs {
		keys[o.Key] = true
		if o.Kind < ipOwnerKindApp || o.Kind > ipOwnerKindCarrier || o.Name == "" {
			t.Errorf("bad org %+v", o)
		}
	}
	for _, k := range []string{"bytedance", "tencent", "alibaba", "baidu", "bilibili", "kuaishou", "netease", "jd",
		"xiaomi", "huawei", "oppo", "apple", "google", "microsoft", "meta", "amazon", "cloudflare", "akamai", "fastly"} {
		if !keys[k] {
			t.Errorf("org %s missing", k)
		}
	}
	// 速度: 20 万次查找(含字符串解析)
	ips := []string{"1.1.1.1", "203.205.254.1", "240e::1", "100.100.100.100", "2a03:2880::1"}
	start := time.Now()
	for i := 0; i < 200000; i++ {
		db.lookup(ips[i%len(ips)])
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("lookup too slow: %v", el)
	}
	// 内存: 解析后的表 ≈ 文件大小
	var ms1, ms2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms1)
	db2, _ := parseIPOwner(b)
	runtime.ReadMemStats(&ms2)
	if grow := ms2.TotalAlloc - ms1.TotalAlloc; grow > uint64(3*len(b))+64<<10 {
		t.Errorf("parse allocated %d bytes for %d byte file", grow, len(b))
	}
	runtime.KeepAlive(db2)
}

func BenchmarkIPOwnerLookup(b *testing.B) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "data", "ip_owner.bin"))
	if err != nil {
		b.Skip(err)
	}
	db, _ := parseIPOwner(raw)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.lookup("203.205.254.1")
	}
}

// 归属优先级: 规则 / DNS 关联 > 共现推断 > IP 归属库(仅 app 类、仅无名); 云/CDN 仍未识别
func TestIPOwnerAttributionPrecedence(t *testing.T) {
	ipOwnerSetDB(testOwnerDB(t))
	defer ipOwnerSetDB(nil)
	mac := "aa:bb:cc:00:00:01"
	owner := map[string]string{"192.168.43.10": mac}
	apps := map[string]ipApp{"20.0.0.9": {ID: "wechat", Name: "微信", Category: "social"}}
	names := map[string]ipName{"20.0.0.8": {Name: "x.qq.com", Src: "dns"}}
	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.Local)
	d := &appUsageDay{Date: "20260101", Hours: map[string]map[string][2]uint64{}, Apps: map[string]appUsageMeta{}}
	deltas := []appUsageDelta{
		{Src: "192.168.43.10", Dst: "20.0.0.9", Up: 1, Dn: 10},     // 规则命中 → wechat
		{Src: "192.168.43.10", Dst: "20.0.0.8", Up: 2, Dn: 20},     // 有名无应用 → 未识别(名字更有用)
		{Src: "192.168.43.10", Dst: "20.0.0.7", Up: 3, Dn: 30},     // 无名, 腾讯 → _org:tencent
		{Src: "192.168.43.10", Dst: "20.0.2.7", Up: 4, Dn: 40},     // 无名, 字节 → _org:bytedance
		{Src: "192.168.43.10", Dst: "1.1.1.1", Up: 5, Dn: 50},      // 无名, CDN → 未识别
		{Src: "192.168.43.10", Dst: "9.9.9.9", Up: 6, Dn: 60},      // 不在库 → 未识别
		{Src: "192.168.43.10", Dst: "192.168.43.1", Up: 7, Dn: 70}, // 局域网
	}
	appUsageRecord(d, deltas, owner, apps, names, now, 10)
	h := d.Hours["10"]
	want := map[string][2]uint64{
		mac + "|wechat": {1, 10}, mac + "|_unknown": {2 + 5 + 6, 20 + 50 + 60},
		mac + "|_org:tencent": {3, 30}, mac + "|_org:bytedance": {4, 40}, mac + "|_local": {7, 70},
	}
	for k, v := range want {
		if h[k] != v {
			t.Errorf("%s = %v want %v", k, h[k], v)
		}
	}
	if m := d.Apps["_org:tencent"]; m.Name != "腾讯系(未细分)" || m.Category != "org" {
		t.Errorf("org meta %+v", m)
	}
	if d.Unknown["1.1.1.1"] == nil || d.Unknown["9.9.9.9"] == nil || d.Unknown["20.0.0.7"] != nil {
		t.Errorf("unknown agg: %v", d.Unknown)
	}
	for _, cells := range d.Active {
		for mk := range cells {
			if strings.Contains(mk, "_org:") {
				t.Errorf("org pseudo-app must not accrue app time: %s", mk)
			}
		}
	}

	// 共现推断优先于归属库
	st := newIdentState()
	st.infer[mac+"|20.0.0.7"] = identInfer{app: ipApp{ID: "qqmusic", Name: "QQ音乐", Category: "music"}, exp: now.Add(time.Minute)}
	cx := &identCtx{st: st, now: now, owner: owner, apps: apps, names: names, sigKey: map[string]bool{}}
	d2 := &appUsageDay{Date: "20260101", Hours: map[string]map[string][2]uint64{}, Apps: map[string]appUsageMeta{}}
	appUsageRecordIdent(d2, []appUsageDelta{{Src: "192.168.43.10", Dst: "20.0.0.7", Up: 1, Dn: 1, Key: "tcp|192.168.43.10|1|20.0.0.7|443"}},
		owner, apps, names, now, 10, cx)
	if d2.Hours["10"][mac+"|qqmusic"] != [2]uint64{1, 1} || d2.Hours["10"][mac+"|_org:tencent"] != [2]uint64{} {
		t.Errorf("co-occurrence must win over org: %v", d2.Hours["10"])
	}
}

// /api/dpi_unknown: 无名 IP 条目带 owner 标签; org_bytes 汇总
func TestIPOwnerDPIUnknownOwnerLabels(t *testing.T) {
	ipOwnerSetDB(testOwnerDB(t))
	defer ipOwnerSetDB(nil)
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	date := time.Now().Format("20060102")
	d := &appUsageDay{Date: date, Hours: map[string]map[string][2]uint64{"1": {
		"aa:bb:cc:00:00:01|_unknown": {10, 90}, "aa:bb:cc:00:00:01|_org:tencent": {5, 5},
	}}, Apps: map[string]appUsageMeta{}}
	appUnknownAdd(d, "1.1.1.1", "", "aa:bb:cc:00:00:01", 60)
	appUnknownAdd(d, "8.130.1.1", "", "aa:bb:cc:00:00:01", 30)
	appUnknownAdd(d, "9.9.9.9", "", "aa:bb:cc:00:00:01", 5)
	appUnknownAdd(d, "5.5.5.5", "cdn.example.com", "aa:bb:cc:00:00:01", 5)
	if err := saveAppUsageDay(dir, d); err != nil {
		t.Fatal(err)
	}
	appUsage.mu.Lock()
	saved := appUsage.day
	appUsage.day = nil
	appUsage.mu.Unlock()
	defer func() { appUsage.mu.Lock(); appUsage.day = saved; appUsage.mu.Unlock() }()
	s := newServer(dir)
	ipOwnerSetDB(testOwnerDB(t)) // newServer 只设目录, 注入的库保持
	rec := httptest.NewRecorder()
	s.apiDPIUnknown(rec, httptest.NewRequest(http.MethodGet, "/api/dpi_unknown?days=1", nil))
	var resp struct {
		Items []struct {
			Key   string                 `json:"name_or_ip"`
			Owner map[string]interface{} `json:"owner"`
		} `json:"items"`
		OrgBytes uint64 `json:"org_bytes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err, rec.Body.String())
	}
	if resp.OrgBytes != 10 {
		t.Errorf("org_bytes = %d", resp.OrgBytes)
	}
	got := map[string]string{}
	for _, it := range resp.Items {
		if it.Owner != nil {
			got[it.Key] = it.Owner["key"].(string) + "/" + it.Owner["kind"].(string)
		} else {
			got[it.Key] = ""
		}
	}
	want := map[string]string{"1.1.1.1": "cloudflare/cdn", "8.130.1.1": "aliyun/cloud", "9.9.9.9": "", "example.com": ""}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%s owner = %q (present %v) want %q", k, g, ok, v)
		}
	}
}
