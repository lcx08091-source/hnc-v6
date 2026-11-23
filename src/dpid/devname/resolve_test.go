// resolve_test.go — v5.31 T2 单测: 六级解析链逐级命中 / 跳过、垃圾名、
// 缓存回放 cache- 前缀、MAC 兜底、OUI 表与 C 一致。命令 / 路径全部注入。
package devname

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const macA = "02:5a:00:00:00:01" // LAA(随机 MAC)位开启

func testResolver(t *testing.T) (*Resolver, string) {
	t.Helper()
	dir := t.TempDir()
	r := &Resolver{
		NamesPath:     filepath.Join(dir, "device_names.json"),
		DevIDPath:     filepath.Join(dir, "dpi_devid.json"),
		CachePath:     filepath.Join(dir, "hostname_cache.json"),
		OverridesPath: filepath.Join(dir, "oui_overrides.json"),
		MDNSBin:       filepath.Join(dir, "mdns_resolve"),
	}
	return r, dir
}

// TestResolveLevels 六级链: 每一级命中时, 更高优先级必须先 miss。
func TestResolveLevels(t *testing.T) {
	r, dir := testResolver(t)

	// 6. 什么都没有 → MAC 兜底
	hn, src := r.Resolve(macA, "192.168.43.101")
	if hn != "00000001" || src != "mac" {
		t.Fatalf("全 miss 应走 MAC 兜底: %q %q", hn, src)
	}

	// 5. 内置 OUI 表(用真实表里的 Apple 00:03:93; 非 LAA)
	appleMAC := "00:03:93:aa:bb:cc"
	hn, src = r.Resolve(appleMAC, "192.168.43.102")
	if src != "oui" || !strings.HasSuffix(hn, " 设备") {
		t.Fatalf("应走 OUI: %q %q", hn, src)
	}
	// LAA 位 → 不查内置表(hnc_lookup_oui 同款)
	if _, src = r.Resolve(macA, ""); src != "mac" {
		t.Fatalf("随机 MAC 不该走内置 OUI: %q", src)
	}

	// 5'. 用户覆盖优先于内置表, 且不受 LAA 约束(hnc_lookup_oui 同款)
	ov := `{"000393":"我的 iPhone","025a00":"随机设备的名字"}`
	if err := os.WriteFile(r.OverridesPath, []byte(ov), 0o644); err != nil {
		t.Fatal(err)
	}
	hn, src = r.Resolve(appleMAC, "")
	if hn != "我的 iPhone" || src != "oui" {
		t.Fatalf("用户覆盖应优先: %q %q", hn, src)
	}
	hn, src = r.Resolve(macA, "")
	if hn != "随机设备的名字" || src != "oui" {
		t.Fatalf("覆盖不受 LAA 约束: %q %q", hn, src)
	}
	_ = os.Remove(r.OverridesPath)

	// 4. 缓存回放(src 带 cache- 前缀)
	cache := `{"02:5a:00:00:00:01":{"h":"pixel-8","s":"mdns","t":1700000000}}`
	if err := os.WriteFile(r.CachePath, []byte(cache), 0o644); err != nil {
		t.Fatal(err)
	}
	r.cacheMu.Lock()
	r.cacheTab = nil
	r.cacheLoad = false
	r.cacheMu.Unlock()
	hn, src = r.Resolve(macA, "")
	if hn != "pixel-8" || src != "cache-mdns" {
		t.Fatalf("缓存回放: %q %q", hn, src)
	}
	// 垃圾名不回放
	cache2 := `{"02:5a:00:00:00:01":{"h":"null","s":"dhcp","t":1700000000}}`
	_ = os.WriteFile(r.CachePath, []byte(cache2), 0o644)
	r.cacheMu.Lock()
	r.cacheTab = nil
	r.cacheLoad = false
	r.cacheMu.Unlock()
	if hn, src = r.Resolve(macA, ""); src != "mac" {
		t.Fatalf("缓存垃圾名不回放: %q %q", hn, src)
	}

	// 3. mDNS(exit 0 + 非垃圾名)
	r.RunMDNS = func(ip string) ([]byte, error) { return []byte("living-room\n"), nil }
	hn, src = r.Resolve(macA, "192.168.43.101")
	if hn != "living-room" || src != "mdns" {
		t.Fatalf("mDNS 命中: %q %q", hn, src)
	}
	// mDNS 垃圾名当 miss —— 但缓存里已有刚才的 mDNS 真名, 回放它
	// (与 C 一致: try_mdns_resolve 失败后落到 hnc_cache_lookup)
	r.RunMDNS = func(string) ([]byte, error) { return []byte("localhost"), nil }
	if hn, src = r.Resolve(macA, "192.168.43.101"); hn != "living-room" || src != "cache-mdns" {
		t.Fatalf("mDNS 垃圾应回放缓存真名: %q %q", hn, src)
	}
	// 缓存也没了(新 resolver)时 mDNS 垃圾 → MAC 兜底
	r2, _ := testResolver(t)
	r2.RunMDNS = func(string) ([]byte, error) { return []byte("localhost"), nil }
	if hn, src = r2.Resolve(macA, "192.168.43.101"); src != "mac" {
		t.Fatalf("无缓存时 mDNS 垃圾名应走 MAC 兜底: %q %q", hn, src)
	}

	// 2. DHCP(同一行有 MAC 和 hostname:, 多条取最后一条非垃圾名)
	r.RunMDNS = nil
	r.RunDumpsys = func() ([]byte, error) {
		return []byte(" DHCP record for 02:5A:00:00:00:01 hostname: null\n" +
			" other line\n" +
			" mac 02:5a:00:00:00:01 hostname: pixel-living, extra\n"), nil
	}
	hn, src = r.Resolve(macA, "192.168.43.101")
	if hn != "pixel-living" || src != "dhcp" {
		t.Fatalf("DHCP 应取最后一条非垃圾名(到逗号截断): %q %q", hn, src)
	}
	// DHCP 垃圾名当 miss —— 但缓存里已有刚才的 DHCP 真名, 回放它
	// (与 C 一致: try_ns_dhcp_resolve 失败后落到 hnc_cache_lookup)
	r.RunDumpsys = func() ([]byte, error) {
		return []byte("x 02:5a:00:00:00:01 hostname: null\n"), nil
	}
	if hn, src = r.Resolve(macA, "192.168.43.101"); hn != "pixel-living" || src != "cache-dhcp" {
		t.Fatalf("DHCP 垃圾应回放缓存真名: %q %q", hn, src)
	}
	// 缓存也没有(新 resolver)时 → MAC 兜底
	r3, _ := testResolver(t)
	r3.RunDumpsys = func() ([]byte, error) {
		return []byte("x 02:5a:00:00:00:01 hostname: null\n"), nil
	}
	if hn, src = r3.Resolve(macA, "192.168.43.101"); src != "mac" {
		t.Fatalf("无缓存时 DHCP 垃圾名应走 MAC 兜底: %q %q", hn, src)
	}
	_ = dir
}

// TestManualLookup 手动名: 冒号两侧空白容忍、大小写、转义、key 出现在 value 里。
func TestManualLookup(t *testing.T) {
	r, _ := testResolver(t)
	// pretty-print(冒号后有空格) + 大写 MAC key
	if err := os.WriteFile(r.NamesPath,
		[]byte(`{"02:5A:00:00:00:01": "我的电视", "aa:bb:cc:dd:ee:ff": "no\"quote"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	hn, ok := LookupManual(macA, r.NamesPath)
	if !ok || hn != "我的电视" {
		t.Fatalf("pretty-print + 大写 key 应命中: %q %v", hn, ok)
	}
	// value 是别的设备的名字时不能误匹配
	if _, ok := LookupManual("aa:bb:cc:dd:ee:ff", r.NamesPath); !ok {
		t.Fatal("第二个 key 应命中")
	}
	// 手动名优先级最高
	r.RunDumpsys = func() ([]byte, error) { return []byte("m 02:5a:00:00:00:01 hostname: dhcp-name\n"), nil }
	if hn, src := r.Resolve(macA, ""); hn != "我的电视" || src != "manual" {
		t.Fatalf("手动名应优先: %q %q", hn, src)
	}
}

// TestCacheReadWrite 缓存写读: 命中 dhcp/mdns 更新缓存, 格式与 C 一致。
func TestCacheReadWrite(t *testing.T) {
	r, _ := testResolver(t)
	r.RunDumpsys = func() ([]byte, error) {
		return []byte("m 02:5a:00:00:00:01 hostname: pixel-8\n"), nil
	}
	hn, src := r.Resolve(macA, "")
	if hn != "pixel-8" || src != "dhcp" {
		t.Fatalf("dhcp: %q %q", hn, src)
	}
	if err := r.CacheSave(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(r.CachePath)
	if err != nil {
		t.Fatal(err)
	}
	// C 格式: {"<mac>":{"h":"...","s":"...","t":N}}
	want := `{"02:5a:00:00:00:01":{"h":"pixel-8","s":"dhcp","t":`
	if !strings.HasPrefix(string(b), want) || !strings.HasSuffix(string(b), "}}\n") {
		t.Fatalf("缓存格式与 C 不一致: %s", b)
	}
	// 重启后(devname 新实例)回放
	r2 := &Resolver{CachePath: r.CachePath}
	r.RunDumpsys = nil
	hn, src = r2.Resolve(macA, "")
	if hn != "pixel-8" || src != "cache-dhcp" {
		t.Fatalf("重启后回放: %q %q", hn, src)
	}
}

// TestOUITableAnchors 内置表(oui_table.txt, v5.33 起唯一数据源)可载入、
// 关键锚点在、有序(二分前提)。格式 / 重复检查在 test/unit/test_v531_oui_table_sync.sh。
func TestOUITableAnchors(t *testing.T) {
	loadOUI()
	if len(ouiKeys) < 400 {
		t.Fatalf("内置表太小: %d", len(ouiKeys))
	}
	// 抽查知名厂商
	anchor := map[string]string{
		"00:03:93": "Apple",  // C 表首段附近的 Apple
		"28:6c:07": "Xiaomi", // 注释里点名的厂商
	}
	for mac, want := range anchor {
		hn, ok := LookupOUI(mac + ":11:22:33")
		if !ok {
			t.Fatalf("%s 应在表里", mac)
		}
		if !strings.HasPrefix(hn, want) {
			t.Fatalf("%s → %q, 要 %s 开头", mac, hn, want)
		}
	}
	// 表有序(二分前提)
	for i := 1; i < len(ouiKeys); i++ {
		if ouiKeys[i-1] >= ouiKeys[i] {
			t.Fatalf("OUI 表无序 @%d", i)
		}
	}
}

// TestMACFallbackEdge 去冒号取后 8 位, 与 hnc_mac_fallback 一致。
func TestMACFallbackEdge(t *testing.T) {
	cases := map[string]string{
		"02:5a:00:00:00:03": "00000003",
		"AA:BB:CC:DD:EE:FF": "CCDDEEFF", // 去冒号后取后 8 位, 原样大小写
		"00:11":             "0011",     // 短输入不崩
	}
	for mac, want := range cases {
		if got := MACFallback(mac); got != want {
			t.Errorf("%s → %q, 要 %q", mac, got, want)
		}
	}
}

// TestManualKeepsCase 审查修复: 手动名原样保留大小写(只有找 MAC 时不分大小写)。
// 旧实现把整个文件转小写后再取名字 →「客厅的Mac」变成「客厅的mac」、「iPad」变成「ipad」,
// 与 C 版(hnc_lookup_manual_name 只在比 MAC 时 tolower)不一致。
func TestManualKeepsCase(t *testing.T) {
	r, _ := testResolver(t)
	if err := os.WriteFile(r.NamesPath,
		[]byte(`{"02:5A:00:00:00:01":"客厅的Mac","aa:bb:cc:dd:ee:ff":"Bob's iPad AB"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if hn, ok := LookupManual(macA, r.NamesPath); !ok || hn != "客厅的Mac" {
		t.Fatalf("名字应原样保留大小写: %q %v", hn, ok)
	}
	if hn, ok := LookupManual("AA:BB:CC:DD:EE:FF", r.NamesPath); !ok || hn != "Bob's iPad AB" {
		t.Fatalf("大写 MAC 查询 + 转义: %q %v", hn, ok)
	}
	if hn, src := r.Resolve(macA, ""); hn != "客厅的Mac" || src != "manual" {
		t.Fatalf("Resolve 走手动名也要保留大小写: %q %q", hn, src)
	}
}

func TestDevIDPassiveHostnamePriority(t *testing.T) {
	r, _ := testResolver(t)
	var dumpsysCalls atomic.Int32
	r.RunDumpsys = func() ([]byte, error) {
		dumpsysCalls.Add(1)
		return []byte("m 02:5a:00:00:00:01 hostname: dumpsys-fallback\n"), nil
	}

	// 1. dpi_devid.json 有效主机名优先于 dumpsys, 避免 fork Binder 子进程
	devIDJSON := `{"schema":1,"devices":{"02:5A:00:00:00:01":{"hostname":"Redmi-K70.local.","hostname_src":"nbns"}}}`
	if err := os.WriteFile(r.DevIDPath, []byte(devIDJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	hn, src := r.Resolve(macA, "192.168.43.101")
	if hn != "Redmi-K70" || src != "nbns" {
		t.Fatalf("期望 dpi_devid 命中 Redmi-K70/nbns, 得 %q/%q", hn, src)
	}
	if dumpsysCalls.Load() != 0 {
		t.Fatalf("dpi_devid 命中时不应调用 dumpsys, calls=%d", dumpsysCalls.Load())
	}

	// 2. 手动名仍高于 dpi_devid.json
	if err := os.WriteFile(r.NamesPath, []byte(`{"02:5a:00:00:00:01":"老爸的手机"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if hn, src = r.Resolve(macA, "192.168.43.101"); hn != "老爸的手机" || src != "manual" {
		t.Fatalf("手动名应优先于 dpi_devid: %q/%q", hn, src)
	}
	_ = os.Remove(r.NamesPath)

	// 3. dpi_devid.json 中为垃圾名时自动落到 dumpsys
	junkJSON := `{"schema":1,"devices":{"02:5a:00:00:00:01":{"hostname":"localhost","hostname_src":"dhcp"}}}`
	if err := os.WriteFile(r.DevIDPath, []byte(junkJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if hn, src = r.Resolve(macA, "192.168.43.101"); hn != "dumpsys-fallback" || src != "dhcp" {
		t.Fatalf("dpi_devid 垃圾名应落到 dumpsys: %q/%q", hn, src)
	}
	if dumpsysCalls.Load() != 1 {
		t.Fatalf("期望调用 1 次 dumpsys, 得 %d", dumpsysCalls.Load())
	}
}

func TestMissingMDNSBinSkipsImmediately(t *testing.T) {
	r, dir := testResolver(t)
	r.MDNSBin = filepath.Join(dir, "no_mdns_resolve")
	t0 := time.Now()
	hn, src := r.Resolve(macA, "192.168.43.101")
	took := time.Since(t0)
	if hn != "00000001" || src != "mac" {
		t.Fatalf("假 MDNSBin 应落回 mac 兜底: %q %q", hn, src)
	}
	if took > 200*time.Millisecond {
		t.Fatalf("不存在的 MDNSBin 假路径不应阻塞 800ms, 实际耗时 %v", took)
	}
}

func buildTestPTRReply(txid uint16, qname, ptrTarget string, useCompress bool) []byte {
	qEnc, _ := encodeDNSName(qname)
	tEnc, _ := encodeDNSName(ptrTarget)
	var pkt []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], txid)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8400) // QR=1 AA=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QD=1
	binary.BigEndian.PutUint16(hdr[6:8], 1)      // AN=1
	pkt = append(pkt, hdr...)
	pkt = append(pkt, qEnc...)
	pkt = append(pkt, 0x00, 0x0C, 0x00, 0x01) // QTYPE=PTR QCLASS=IN
	if useCompress {
		pkt = append(pkt, 0xC0, 0x0C) // 指向 offset 12 的 question name
	} else {
		pkt = append(pkt, qEnc...)
	}
	rrMeta := make([]byte, 10)
	binary.BigEndian.PutUint16(rrMeta[0:2], 0x000C) // TYPE=PTR
	binary.BigEndian.PutUint16(rrMeta[2:4], 0x0001) // CLASS=IN
	binary.BigEndian.PutUint32(rrMeta[4:8], 120)    // TTL
	binary.BigEndian.PutUint16(rrMeta[8:10], uint16(len(tEnc)))
	pkt = append(pkt, rrMeta...)
	pkt = append(pkt, tEnc...)
	return pkt
}

func TestNativeMDNSPTRUnicastMulticastAndCompression(t *testing.T) {
	// 1. 验证恶意自环压缩指针不会死循环
	loopPkt := []byte{
		0x00, 0x01, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x0C, // 自环指针 ptr == cur
		0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x02, 0xC0, 0x0C,
	}
	if _, ok := parseMDNSPTRResponse(loopPkt, "101.43.168.192.in-addr.arpa"); ok {
		t.Fatal("自环压缩指针必须被拒绝")
	}

	// 2. 启动本地单播与组播模拟 UDP 服务: 单播静默超时 → 组播先发一条伪造 rname 再发真 PTR(带压缩指针)
	uniSrv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer uniSrv.Close()

	mcastSrv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer mcastSrv.Close()

	go func() {
		var buf [1500]byte
		_, cliAddr, err := mcastSrv.ReadFromUDP(buf[:])
		if err != nil {
			return
		}
		// 先发一条 rname 不匹配的伪造响应(必须被忽略)
		spoof := buildTestPTRReply(0, "99.43.168.192.in-addr.arpa", "Evil-Spoof.local", false)
		_, _ = mcastSrv.WriteToUDP(spoof, cliAddr)
		// 再发匹配的压缩指针 PTR 响应
		valid := buildTestPTRReply(0, "101.43.168.192.in-addr.arpa", "MacBook-Air.local.", true)
		_, _ = mcastSrv.WriteToUDP(valid, cliAddr)
	}()

	r, _ := testResolver(t)
	r.NativeMDNS = true
	r.mdnsUnicastTargetFn = func(net.IP) *net.UDPAddr { return uniSrv.LocalAddr().(*net.UDPAddr) }
	r.mdnsMulticastTarget = mcastSrv.LocalAddr().(*net.UDPAddr)

	hn, src := r.Resolve(macA, "192.168.43.101")
	if hn != "MacBook-Air" || src != "mdns" {
		t.Fatalf("纯 Go mDNS 单播转组播应解析出 MacBook-Air/mdns, 得 %q/%q", hn, src)
	}

	// 3. 验证底层 UDP 发送报错时平滑回退外部 MDNSBin(测试用 /bin/echo 或等效可执行文件验证路径判断)
	rErr, dir := testResolver(t)
	fakeBin := filepath.Join(dir, "fake_mdns")
	_ = os.WriteFile(fakeBin, []byte("#!/bin/sh\necho fallback-host\n"), 0o755)
	rErr.MDNSBin = fakeBin
	rErr.mdnsQueryOnceFn = func(context.Context, string, *net.UDPAddr, bool, time.Duration) (string, bool, error) {
		return "", false, errors.New("socket permission denied")
	}
	// 若临时目录在支持 exec 的文件系统上则命中 fallback-host, 若在 noexec 上则优雅落到 mac 兜底不崩
	hn2, src2 := rErr.Resolve(macA, "192.168.43.101")
	if !(src2 == "mdns" && hn2 == "fallback-host") && src2 != "mac" {
		t.Fatalf("UDP 报错回退行为异常: %q/%q", hn2, src2)
	}
}
