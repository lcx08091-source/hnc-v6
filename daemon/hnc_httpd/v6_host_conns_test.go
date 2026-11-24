package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

func TestArm32HostConnAndScalpelAtomicAlignment(t *testing.T) {
	var (
		zSc  flowScalpelEngine
		zHub CoreHub
		zV6  v6ServerState
	)
	checks := []struct {
		name   string
		offset uintptr
	}{
		{"flowScalpelEngine.seqGen", unsafe.Offsetof(zSc.seqGen)},
		{"flowScalpelEngine.cutTotal", unsafe.Offsetof(zSc.cutTotal)},
		{"flowScalpelEngine.guardBlocked", unsafe.Offsetof(zSc.guardBlocked)},
		{"flowScalpelEngine.hostCutTotal", unsafe.Offsetof(zSc.hostCutTotal)},
		{"CoreHub.seq", unsafe.Offsetof(zHub.seq)},
		{"CoreHub.lastRefreshMono", unsafe.Offsetof(zHub.lastRefreshMono)},
		{"CoreHub.vectorSyncHits", unsafe.Offsetof(zHub.vectorSyncHits)},
		{"CoreHub.shmSeqlockHits", unsafe.Offsetof(zHub.shmSeqlockHits)},
		{"CoreHub.shmFallbackCount", unsafe.Offsetof(zHub.shmFallbackCount)},
		{"v6ServerState.summaryCalls", unsafe.Offsetof(zV6.summaryCalls)},
	}
	for _, c := range checks {
		if c.offset%8 != 0 {
			t.Fatalf("64-bit atomic field %s offset=%d violates 8-byte alignment on 32-bit ARMv7", c.name, c.offset)
		}
	}
}

func hostConnSetupFakeHostEnv(t *testing.T, dir string) (procDir, pkgListPath string) {
	t.Helper()
	procDir = filepath.Join(dir, "proc_net")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pkgListPath = filepath.Join(dir, "packages.list")

	origProcFn := hostConnProcNetDirFn
	origPkgFn := hostConnPackagesListPathFn
	hostConnProcNetDirFn = func() string { return procDir }
	hostConnPackagesListPathFn = func() string { return pkgListPath }
	hostConnInvalidateProcCache()
	t.Cleanup(func() {
		hostConnProcNetDirFn = origProcFn
		hostConnPackagesListPathFn = origPkgFn
		hostConnInvalidateProcCache()
	})
	return procDir, pkgListPath
}

func TestHostConnProcNetIPv4IPv6MappedAndUIDCloneResolver(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"data", "run", "etc"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	procDir, pkgListPath := hostConnSetupFakeHostEnv(t, dir)

	// 1. 写入模拟 /data/system/packages.list 与 data/app_labels_live.json
	pkgContent := strings.Join([]string{
		"com.tencent.mm 10245 0 /data/user/0/com.tencent.mm default:targetSdkVersion=34 3003 0 1",
		"com.demo.customapp 10388 0 /data/user/0/com.demo.customapp default:targetSdkVersion=34 3003 0 1",
		"me.weishu.kernelsu 10401 0 /data/user/0/me.weishu.kernelsu default:targetSdkVersion=34 3003 0 1",
		"com.agy 10814 0 /data/user/0/com.agy default:targetSdkVersion=34 3003 0 1",
	}, "\n") + "\n"
	if err := os.WriteFile(pkgListPath, []byte(pkgContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "app_labels_live.json"),
		[]byte(`{"com.demo.customapp":"极客实验室"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// 校验系统内置 UID、普通应用、live label 缓存与多用户分身 (userId=999, appId=10245)
	if id0 := scalpelResolveHostUID(dir, 0); id0.AppName != "root/内核" || !id0.IsSystem {
		t.Fatalf("unexpected uid 0 identity: %+v", id0)
	}
	if idSys := scalpelResolveHostUID(dir, 1000); idSys.AppName != "Android 系统" || !idSys.IsSystem {
		t.Fatalf("unexpected uid 1000 identity: %+v", idSys)
	}
	if idNetd := scalpelResolveHostUID(dir, 1051); idNetd.AppName != "netd DNS守护" || !idNetd.IsSystem {
		t.Fatalf("unexpected uid 1051 identity: %+v", idNetd)
	}
	if idMedia := scalpelResolveHostUID(dir, 1013); idMedia.AppName != "mediaserver" || !idMedia.IsSystem {
		t.Fatalf("unexpected uid 1013 identity: %+v", idMedia)
	}
	if idMediaStore := scalpelResolveHostUID(dir, 1023); idMediaStore.AppName != "媒体存储" || !idMediaStore.IsSystem {
		t.Fatalf("unexpected uid 1023 identity: %+v", idMediaStore)
	}
	if idWX := scalpelResolveHostUID(dir, 10245); idWX.Package != "com.tencent.mm" || idWX.AppName != "微信" || idWX.IsSystem {
		t.Fatalf("unexpected uid 10245 identity: %+v", idWX)
	}
	if idClone := scalpelResolveHostUID(dir, 99910245); idClone.Package != "com.tencent.mm" || idClone.AppName != "微信 (分身)" || !idClone.IsClone {
		t.Fatalf("expected clone suffix for uid 99910245, got %+v", idClone)
	}
	if idLive := scalpelResolveHostUID(dir, 10388); idLive.AppName != "极客实验室" {
		t.Fatalf("expected live label cache hit, got %+v", idLive)
	}

	// 2. 写入模拟 /proc/net/{tcp,tcp6,udp,udp6} 验证字节序、LISTEN(0A) 跳过、回环跳过与 ::ffff: 归一化
	// tcp:
	//   - LISTEN 0A (0.0.0.0:8443) -> 必须跳过
	//   - 127.0.0.1:41000 -> 127.0.0.1:8080 -> 必须跳过
	//   - 10.0.2.15:51000 (0F02000A:C738) -> 104.16.132.229:443 (E5841068:01BB) ESTABLISHED(01), uid=10245
	tcpLines := "  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 10001 1 0 0\n" +
		"   1: 0100007F:A028 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 10002 1 0 0\n" +
		"   2: 0F02000A:C738 E5841068:01BB 01 00000010:00000020 00:00000000 00000000 10245        0 20001 1 0 0\n"
	_ = os.WriteFile(filepath.Join(procDir, "tcp"), []byte(tcpLines), 0o644)

	// tcp6:
	//   - ::1 回环 -> 必须跳过
	//   - ::ffff:10.0.2.15:52000 (C8+... D2F0=54000 -> C738=51000; 52000=0xCB20) -> ::ffff:93.184.216.34:80 (0050) uid=99910245 -> 归一化为 IPv4 + http_cleartext
	//   - 2409:8a00::1:53000 (0xCF08) -> 2400:3200::1:443 (0x01BB) uid=10388 -> 原生 IPv6
	tcp6Lines := "  sl  local_address                         remote_address                        st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000000000000000000001000000:9C40 00000000000000000000000001000000:01BB 01 00000000:00000000 00:00000000 00000000     0        0 30000 1 0 0\n" +
		"   1: 0000000000000000FFFF00000F02000A:CB20 0000000000000000FFFF000022D8B85D:0050 01 00000000:00000000 00:00000000 00000000 99910245     0 30001 1 0 0\n" +
		"   2: 008A0924000000000000000001000000:CF08 00320024000000000000000001000000:01BB 01 00000000:00000000 00:00000000 00000000 10388        0 30002 1 0 0\n"
	_ = os.WriteFile(filepath.Join(procDir, "tcp6"), []byte(tcp6Lines), 0o644)

	// udp:
	//   - 0.0.0.0:5353 -> 0.0.0.0:0000 未连接绑定 -> 跳过
	//   - 10.0.2.15:54000 (0xD2F0) -> 8.8.8.8:53 (0x0035) uid=10388 -> dns_direct
	//   - 10.0.2.15:54001 (0xD2F1) -> 8.8.8.8:53 (0x0035) uid=1051 (netd) -> 系统 DNS 守护不标 dns_direct
	udpLines := "  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode ref pointer drops\n" +
		"   0: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000  1020        0 40000 2 0 0\n" +
		"   1: 0F02000A:D2F0 08080808:0035 01 00000000:00000000 00:00000000 00000000 10388        0 40001 2 0 0\n" +
		"   2: 0F02000A:D2F1 08080808:0035 01 00000000:00000000 00:00000000 00000000  1051        0 40002 2 0 0\n"
	_ = os.WriteFile(filepath.Join(procDir, "udp"), []byte(udpLines), 0o644)
	_ = os.WriteFile(filepath.Join(procDir, "udp6"), []byte("  sl  local_address                         remote_address                        st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode ref pointer drops\n"), 0o644)

	ps := hostConnReadProcSnapshot()
	if !ps.readable || len(ps.list) != 5 {
		t.Fatalf("expected exactly 5 active non-loopback non-LISTEN sockets, got %d: %+v", len(ps.list), ps.list)
	}

	mappedKey := "tcp|10.0.2.15|52000|93.184.216.34|80"
	mappedSk, ok := ps.byKey[mappedKey]
	if !ok || mappedSk.IsV6 || !mappedSk.RawV6Sock || mappedSk.UID != 99910245 {
		t.Fatalf("expected ::ffff:10.0.2.15 normalized to IPv4 key %s, got ok=%v sk=%+v", mappedKey, ok, mappedSk)
	}
	if risk := scalpelDetectCleartextRisk(mappedSk.Proto, mappedSk.Dport, mappedSk.UID); risk != "http_cleartext" {
		t.Fatalf("expected http_cleartext on tcp :80, got %q", risk)
	}

	v6Key := "tcp|2409:8a00::1|53000|2400:3200::1|443"
	if v6Sk, ok := ps.byKey[v6Key]; !ok || !v6Sk.IsV6 || v6Sk.UID != 10388 {
		t.Fatalf("expected canonical IPv6 socket %s, got ok=%v sk=%+v", v6Key, ok, v6Sk)
	}

	if riskAppDNS := scalpelDetectCleartextRisk("udp", 53, 10388); riskAppDNS != "dns_direct" {
		t.Fatalf("expected dns_direct for app uid>=10000 on :53, got %q", riskAppDNS)
	}
	if riskNetdDNS := scalpelDetectCleartextRisk("udp", 53, 1051); riskNetdDNS != "" {
		t.Fatalf("expected empty risk for netd uid=1051 on :53, got %q", riskNetdDNS)
	}
}

func TestHostConnSockDestroyMsgEncodingAndDualStackFallback(t *testing.T) {
	tp4 := ScalpelTuple{
		Proto: "tcp",
		SrcIP: "10.0.2.15",
		Sport: 51000,
		DstIP: "104.16.132.229",
		Dport: 443,
	}
	msg4, err := buildScalpelSockDestroyMsg(tp4, false, 77)
	if err != nil {
		t.Fatalf("buildScalpelSockDestroyMsg v4 failed: %v", err)
	}
	if len(msg4) != 72 {
		t.Fatalf("expected 72-byte nlmsghdr+inet_diag_req_v2, got %d", len(msg4))
	}
	if gotLen := binary.LittleEndian.Uint32(msg4[0:4]); gotLen != 72 {
		t.Fatalf("nlmsg_len = %d, want 72", gotLen)
	}
	if gotType := binary.LittleEndian.Uint16(msg4[4:6]); gotType != 21 {
		t.Fatalf("nlmsg_type = %d, want SOCK_DESTROY(21)", gotType)
	}
	if gotSeq := binary.LittleEndian.Uint32(msg4[8:12]); gotSeq != 77 {
		t.Fatalf("nlmsg_seq = %d, want 77", gotSeq)
	}
	req := msg4[16:]
	if req[0] != scalpelAfInet || req[1] != 6 {
		t.Fatalf("unexpected family=%d proto=%d", req[0], req[1])
	}
	if sport := binary.BigEndian.Uint16(req[8:10]); sport != 51000 {
		t.Fatalf("idiag_sport = %d, want 51000 (network byte order)", sport)
	}
	if dport := binary.BigEndian.Uint16(req[10:12]); dport != 443 {
		t.Fatalf("idiag_dport = %d, want 443 (network byte order)", dport)
	}
	if c0, c1 := binary.LittleEndian.Uint32(req[48:52]), binary.LittleEndian.Uint32(req[52:56]); c0 != 0xffffffff || c1 != 0xffffffff {
		t.Fatalf("idiag_cookie must be INET_DIAG_NOCOOKIE (0xffffffff,0xffffffff), got (0x%x,0x%x)", c0, c1)
	}

	// 验证 ::ffff:a.b.c.d 双栈 AF_INET6 映射报文编码
	msgMapped, err := buildScalpelSockDestroyMsg(tp4, true, 78)
	if err != nil {
		t.Fatalf("buildScalpelSockDestroyMsg v4-mapped-v6 failed: %v", err)
	}
	reqM := msgMapped[16:]
	if reqM[0] != scalpelAfInet6 || reqM[12+10] != 0xff || reqM[12+11] != 0xff || reqM[12+12] != 10 || reqM[12+15] != 15 {
		t.Fatalf("invalid ::ffff:10.0.2.15 idiag_src encoding: %x", reqM[12:28])
	}
}

func TestScalpelHostFiveSafetyGuardsAndOutputCutLifecycle(t *testing.T) {
	dir := setupNativeTierTestEnv(t, "wlan2")
	for _, sub := range []string{"data", "run", "etc"} {
		_ = os.MkdirAll(filepath.Join(dir, sub), 0o755)
	}
	procDir, pkgListPath := hostConnSetupFakeHostEnv(t, dir)

	pkgLines := strings.Join([]string{
		"com.tencent.mm 10245 0 /data/user/0/com.tencent.mm default:targetSdkVersion=34 3003 0 1",
		"me.weishu.kernelsu 10401 0 /data/user/0/me.weishu.kernelsu default:targetSdkVersion=34 3003 0 1",
		"com.rifsxd.ksunext 10402 0 /data/user/0/com.rifsxd.ksunext default:targetSdkVersion=34 3003 0 1",
		"com.sukisu.ultra 10403 0 /data/user/0/com.sukisu.ultra default:targetSdkVersion=34 3003 0 1",
		"io.github.vvb2060.magisk 10404 0 /data/user/0/io.github.vvb2060.magisk default:targetSdkVersion=34 3003 0 1",
		"com.topjohnwu.magisk 10405 0 /data/user/0/com.topjohnwu.magisk default:targetSdkVersion=34 3003 0 1",
		"me.bmax.apatch 10406 0 /data/user/0/me.bmax.apatch default:targetSdkVersion=34 3003 0 1",
		"com.google.android.webview 10407 0 /data/user/0/com.google.android.webview default:targetSdkVersion=34 3003 0 1",
		"com.android.webview 10408 0 /data/user/0/com.android.webview default:targetSdkVersion=34 3003 0 1",
		"com.agy 10814 0 /data/user/0/com.agy default:targetSdkVersion=34 3003 0 1",
	}, "\n") + "\n"
	_ = os.WriteFile(pkgListPath, []byte(pkgLines), 0o644)

	// 活跃本机连接: 10.0.2.15:51000 -> 198.51.100.77:443 (4D6433C6:01BB), uid=10245
	tcpLines := "  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0F02000A:C738 4D6433C6:01BB 01 00000000:00000000 00:00000000 00000000 10245        0 50001 1 0 0\n"
	_ = os.WriteFile(filepath.Join(procDir, "tcp"), []byte(tcpLines), 0o644)

	srv := &server{hncDir: dir, jsonCache: newJSONFileCache()}
	sc := srv.v6State().scalpel
	defer sc.stopStandaloneTimer()

	origResolve := scalpelResolveBinFn
	origExec := scalpelIptExecFn
	t.Cleanup(func() {
		scalpelResolveBinFn = origResolve
		scalpelIptExecFn = origExec
	})
	scalpelResolveBinFn = func(name string) string { return "/system/bin/" + name }

	var (
		mu             sync.Mutex
		outputHooked   bool
		outputInserts  int
		destroyedSocks []ScalpelTuple
		deletedCTs     []ScalpelTuple
		hostPayloadsV4 []string
	)
	scalpelIptExecFn = func(_ string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		if strings.Contains(line, "-C OUTPUT -j HNC_SCALPEL_HOST") {
			mu.Lock()
			ok := outputHooked
			mu.Unlock()
			if !ok {
				return "No chain/target/match", errors.New("exit 1")
			}
			return "", nil
		}
		if strings.Contains(line, "-I OUTPUT 1 -j HNC_SCALPEL_HOST") {
			mu.Lock()
			outputHooked = true
			outputInserts++
			mu.Unlock()
		}
		return "", nil
	}
	sc.sockDestroyRunner = func(tp ScalpelTuple, _ uint32) error {
		mu.Lock()
		destroyedSocks = append(destroyedSocks, tp)
		mu.Unlock()
		return nil
	}
	sc.ctDelRunner = func(tp ScalpelTuple, _ uint32) error {
		mu.Lock()
		deletedCTs = append(deletedCTs, tp)
		mu.Unlock()
		return nil
	}
	sc.iptRunner = func(family int, payload string) error {
		if family == scalpelAfInet && strings.Contains(payload, ":HNC_SCALPEL_HOST") {
			mu.Lock()
			hostPayloadsV4 = append(hostPayloadsV4, payload)
			mu.Unlock()
		}
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v6/scalpel/cut", srv.apiScalpelCut)

	postCut := func(body string) (*httptest.ResponseRecorder, map[string]any) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v6/scalpel/cut", strings.NewReader(body))
		mux.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}

	// 门禁 1: 回环与链路本地地址 -> 409
	for _, body := range []string{
		`{"scope":"host","mode":"cut_once","uid":10245,"proto":"tcp","src_ip":"127.0.0.1","sport":50000,"dst_ip":"127.0.0.1","dport":9000}`,
		`{"scope":"host","mode":"cut_once","uid":10245,"proto":"tcp","src_ip":"::1","sport":50000,"dst_ip":"::1","dport":9000}`,
		`{"scope":"host","mode":"cut_once","uid":10245,"proto":"udp","src_ip":"169.254.1.2","sport":50000,"dst_ip":"169.254.1.1","dport":5353}`,
		`{"scope":"host","mode":"cut_once","uid":10245,"proto":"udp","src_ip":"fe80::2","sport":50000,"dst_ip":"fe80::1","dport":5353}`,
	} {
		rec, _ := postCut(body)
		if rec.Code != http.StatusConflict {
			t.Fatalf("guard 1 expected 409 Conflict for %s, got %d: %s", body, rec.Code, rec.Body.String())
		}
	}

	// 门禁 2: HNC WebUI 自身端口 8443/8444/8080 -> 409
	for _, port := range []int{8443, 8444, 8080} {
		recD, _ := postCut(fmt.Sprintf(`{"scope":"host","mode":"cut_once","uid":10245,"proto":"tcp","src_ip":"10.0.2.15","sport":51111,"dst_ip":"198.51.100.20","dport":%d}`, port))
		recS, _ := postCut(fmt.Sprintf(`{"scope":"host","mode":"cut_once","uid":10245,"proto":"tcp","src_ip":"10.0.2.15","sport":%d,"dst_ip":"198.51.100.20","dport":443}`, port))
		if recD.Code != http.StatusConflict || recS.Code != http.StatusConflict {
			t.Fatalf("guard 2 expected 409 for WebUI port %d, got dport=%d sport=%d", port, recD.Code, recS.Code)
		}
	}

	// 门禁 3: 系统 UID (<10000) 拒绝 cut_once 与 cut_freeze_15m；未知 UID 拒绝 freeze_15m 及核心端口 cut_once，允许普通端口 cut_once
	for _, sysUID := range []int{0, 1000, 1001, 1010, 1051} {
		rec1, _ := postCut(fmt.Sprintf(`{"scope":"host","mode":"cut_once","uid":%d,"proto":"tcp","src_ip":"10.0.2.15","sport":52100,"dst_ip":"198.51.100.20","dport":443}`, sysUID))
		rec2, _ := postCut(fmt.Sprintf(`{"scope":"host","mode":"cut_freeze_15m","uid":%d,"proto":"tcp","src_ip":"10.0.2.15","sport":52100,"dst_ip":"198.51.100.20","dport":443}`, sysUID))
		if rec1.Code != http.StatusConflict || rec2.Code != http.StatusConflict {
			t.Fatalf("guard 3 expected 409 for system UID %d, got once=%d freeze=%d", sysUID, rec1.Code, rec2.Code)
		}
	}
	recUnkFrz, _ := postCut(`{"scope":"host","mode":"cut_freeze_15m","proto":"tcp","src_ip":"10.0.2.15","sport":59999,"dst_ip":"198.51.100.20","dport":443}`)
	if recUnkFrz.Code != http.StatusConflict {
		t.Fatalf("guard 3 expected 409 when freezing unknown UID socket, got %d", recUnkFrz.Code)
	}
	recUnkDNS, _ := postCut(`{"scope":"host","mode":"cut_once","proto":"udp","src_ip":"10.0.2.15","sport":59999,"dst_ip":"8.8.8.8","dport":53}`)
	if recUnkDNS.Code != http.StatusConflict {
		t.Fatalf("guard 3 expected 409 for unknown UID on port 53, got %d", recUnkDNS.Code)
	}

	// 门禁 4: 9 个受保护包名与 selfFirewallProtectedPackages 100% 对齐, 且本机 scalpel/cut 一律拒绝 409
	if len(scalpelHostProtectedPackages) != len(selfFirewallProtectedPackages) {
		t.Fatalf("scalpelHostProtectedPackages len=%d != selfFirewallProtectedPackages len=%d",
			len(scalpelHostProtectedPackages), len(selfFirewallProtectedPackages))
	}
	for _, protPkg := range selfFirewallProtectedPackages {
		if !scalpelHostProtectedPackages[protPkg] {
			t.Fatalf("scalpelHostProtectedPackages missing protected package %q", protPkg)
		}
	}
	for _, protUID := range []int{10401, 10402, 10403, 10404, 10405, 10406, 10407, 10408, 10814} {
		for _, cutMode := range []string{"cut_once", "cut_freeze_15m"} {
			recP, respP := postCut(fmt.Sprintf(`{"scope":"host","mode":%q,"uid":%d,"proto":"tcp","src_ip":"10.0.2.15","sport":53100,"dst_ip":"198.51.100.77","dport":443}`, cutMode, protUID))
			if recP.Code != http.StatusConflict || respP["reason_code"] != "host_protected_package_blocked" {
				t.Fatalf("guard 4 expected 409 host_protected_package_blocked for uid %d mode %s, got %d %+v", protUID, cutMode, recP.Code, respP)
			}
		}
	}

	// 门禁 5: 本机 :53 / :853 系统 DNS 端口及共享 CDN (104.16.132.229) 拒绝 freeze_15m (409)
	recHostDNS, _ := postCut(`{"scope":"host","mode":"cut_freeze_15m","uid":10245,"proto":"udp","src_ip":"10.0.2.15","sport":54100,"dst_ip":"198.51.100.77","dport":53}`)
	recHostDoT, _ := postCut(`{"scope":"host","mode":"cut_freeze_15m","uid":10245,"proto":"tcp","src_ip":"10.0.2.15","sport":54101,"dst_ip":"198.51.100.77","dport":853}`)
	recHostCDN, respHostCDN := postCut(`{"scope":"host","mode":"cut_freeze_15m","uid":10245,"proto":"tcp","src_ip":"10.0.2.15","sport":54102,"dst_ip":"104.16.132.229","dport":443}`)
	if recHostDNS.Code != http.StatusConflict || recHostDoT.Code != http.StatusConflict || recHostCDN.Code != http.StatusConflict || respHostCDN["allowed_mode"] != "cut_once" {
		t.Fatalf("guard 5 expected 409 on :53/:853/shared CDN, got dns=%d dot=%d cdn=%d (%+v)",
			recHostDNS.Code, recHostDoT.Code, recHostCDN.Code, respHostCDN)
	}

	// 正向验证: 普通第三方应用 (微信 uid=10245) 执行 cut_freeze_15m 双阶段真实斩流 + 到期自动回空链零开销
	recOK, respOK := postCut(`{"scope":"host","mode":"cut_freeze_15m","proto":"tcp","src_ip":"10.0.2.15","sport":51000,"dst_ip":"198.51.100.77","dport":443}`)
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid host app cut_freeze_15m, got %d: %s", recOK.Code, recOK.Body.String())
	}
	if respOK["scope"] != "host" || respOK["sock_destroyed"] != true || respOK["package"] != "com.tencent.mm" {
		t.Fatalf("unexpected CutHost response: %+v", respOK)
	}

	mu.Lock()
	if len(destroyedSocks) != 1 || len(deletedCTs) != 1 || outputInserts != 1 {
		t.Fatalf("expected SOCK_DESTROY=1, CT_DELETE=1, OUTPUT jump=1; got sd=%d ct=%d ins=%d",
			len(destroyedSocks), len(deletedCTs), outputInserts)
	}
	latestPayload := hostPayloadsV4[len(hostPayloadsV4)-1]
	mu.Unlock()

	wantLines := []string{
		":HNC_SCALPEL_HOST - [0:0]",
		"-A HNC_SCALPEL_HOST -o lo -j RETURN",
		"-A HNC_SCALPEL_HOST -p tcp -m multiport --sports 8443,8444,8080 -j RETURN",
		"-A HNC_SCALPEL_HOST -p tcp -m multiport --dports 8443,8444,8080 -j RETURN",
		"-A HNC_SCALPEL_HOST -p tcp ! --syn -s 10.0.2.15 -d 198.51.100.77 --sport 51000 --dport 443 -j REJECT --reject-with tcp-reset",
		"-A HNC_SCALPEL_HOST -m owner --uid-owner 10245 -d 198.51.100.77 -p tcp --dport 443 -j REJECT --reject-with tcp-reset",
	}
	for _, wl := range wantLines {
		if !strings.Contains(latestPayload, wl) {
			t.Fatalf("HNC_SCALPEL_HOST payload missing line %q:\n%s", wl, latestPayload)
		}
	}

	// 验证到期 SweepExpired 自动摘除所有规则并还原为空链零开销
	sc.SweepExpired(time.Now().Add(20 * time.Minute))
	mu.Lock()
	clearedPayload := hostPayloadsV4[len(hostPayloadsV4)-1]
	mu.Unlock()
	if clearedPayload != "*filter\n:HNC_SCALPEL_HOST - [0:0]\nCOMMIT\n" {
		t.Fatalf("expected zero-overhead empty HNC_SCALPEL_HOST chain after expiry, got:\n%s", clearedPayload)
	}
}

func TestHostConnAndHotspotOrthogonalFlowSplitAcrossAPIs(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"data", "run", "etc"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	procDir, pkgListPath := hostConnSetupFakeHostEnv(t, dir)

	_ = os.WriteFile(pkgListPath, []byte("com.tencent.mm 10245 0 /data/user/0/com.tencent.mm default:targetSdkVersion=34 3003 0 1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procDir, "tcp"), []byte(
		"  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode\n"+
			"   0: 0F02000A:C738 E5841068:01BB 01 00000000:00000000 00:00000000 00000000 10245        0 60001 1 0 0\n"+
			"   1: 0F02000A:C739 22D8B85D:0050 01 00000000:00000000 00:00000000 00000000 10245        0 60002 1 0 0\n",
	), 0o644)

	fakeCT := filepath.Join(dir, "run", "fake_ct")
	_ = os.WriteFile(fakeCT, []byte(
		// 本机连接 1 (JOIN /proc/net/tcp)
		"ipv4 2 tcp 6 300 ESTABLISHED src=10.0.2.15 dst=104.16.132.229 sport=51000 dport=443 packets=10 bytes=2048 src=104.16.132.229 dst=10.0.2.15 sport=443 dport=51000 packets=20 bytes=8192 [ASSURED]\n"+
			// 热点客户端发往手机网关 :8443 WebUI 管理流 (必须被排除出热点外联流)
			"ipv4 2 tcp 6 300 ESTABLISHED src=192.168.43.88 dst=192.168.43.1 sport=55123 dport=8443 packets=5 bytes=500 src=192.168.43.1 dst=192.168.43.88 sport=8443 dport=55123 packets=5 bytes=1500 [ASSURED]\n"+
			// 热点客户端正常外联流
			"ipv4 2 tcp 6 300 ESTABLISHED src=192.168.43.88 dst=1.1.1.1 sport=55124 dport=443 packets=8 bytes=1024 src=1.1.1.1 dst=10.0.2.15 sport=443 dport=55124 packets=8 bytes=4096 [ASSURED]\n",
	), 0o644)
	t.Setenv("HNC_CONNTRACK_PATH", fakeCT)
	ctState.mu.Lock()
	ctState.snap = nil
	ctState.mu.Unlock()

	// 场景 A: 热点关闭 (INACTIVE) 且 0 在线客户端 -> hotspot_flows 必须严格为 0，host_flows == 2
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("INACTIVE\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"), []byte(`{"aa:bb:cc:dd:ee:88":{"ip":"192.168.43.88","last_seen":1}}`), 0o644)

	srv := newServer(dir)
	hub := srv.CoreHub()
	defer hub.Close()
	snapOff := hub.RefreshSnapshotNow()
	if snapOff.Live.HotspotFlows != 0 || snapOff.Live.HostFlows != 2 {
		t.Fatalf("when hotspot is INACTIVE, expected HotspotFlows=0 HostFlows=2, got %+v", snapOff.Live)
	}

	// 验证 /api/live
	liveRec := httptest.NewRecorder()
	srv.apiLive(liveRec, httptest.NewRequest(http.MethodGet, "/api/live", nil))
	var liveBody map[string]any
	_ = json.Unmarshal(liveRec.Body.Bytes(), &liveBody)
	if liveBody["hotspot_flows"].(float64) != 0 || liveBody["host_flows"].(float64) != 2 {
		t.Fatalf("/api/live flow split mismatch when hotspot off: %+v", liveBody)
	}

	// 验证 /api/connections?scope=host
	connRec := httptest.NewRecorder()
	srv.apiConnections(connRec, httptest.NewRequest(http.MethodGet, "/api/connections?scope=host", nil))
	var connBody map[string]any
	_ = json.Unmarshal(connRec.Body.Bytes(), &connBody)
	if connBody["hotspot_flows"].(float64) != 0 || connBody["host_flows"].(float64) != 2 || connBody["total"].(float64) != 2 {
		t.Fatalf("/api/connections?scope=host mismatch: %+v", connBody)
	}

	// 场景 B: 热点开启且 1 台客户端在线 -> hotspot_flows == 1 (已排除 :8443 管理流), host_flows == 2
	nowUnix := time.Now().Unix()
	_ = os.WriteFile(filepath.Join(dir, "run", "hnc_state"), []byte("ACTIVE:wlan2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"),
		[]byte(fmt.Sprintf(`{"aa:bb:cc:dd:ee:88":{"ip":"192.168.43.88","hostname":"Pad","last_seen":%d}}`, nowUnix)), 0o644)
	srv.jsonCache = newJSONFileCache()
	hub.RefreshSnapshotNow()

	scRec := httptest.NewRecorder()
	srv.apiScalpelFlows(scRec, httptest.NewRequest(http.MethodGet, "/api/v6/scalpel/flows?scope=all", nil))
	var scAll map[string]any
	_ = json.Unmarshal(scRec.Body.Bytes(), &scAll)
	if scAll["hotspot_flows"].(float64) != 1 || scAll["host_flows"].(float64) != 2 || scAll["total"].(float64) != 3 {
		t.Fatalf("/api/v6/scalpel/flows?scope=all expected hotspot=1 host=2 total=3, got %+v", scAll)
	}

	scHostRec := httptest.NewRecorder()
	srv.apiScalpelFlows(scHostRec, httptest.NewRequest(http.MethodGet, "/api/v6/scalpel/flows?scope=host&uid=10245", nil))
	var scHost map[string]any
	_ = json.Unmarshal(scHostRec.Body.Bytes(), &scHost)
	if scHost["total"].(float64) != 2 {
		t.Fatalf("expected 2 flows for uid=10245, got %+v", scHost)
	}
	sum := srv.v6State().scalpel.summary()
	if sum["hotspot_flows"] != 1 || sum["host_flows"] != 2 || sum["total_flows"] != 3 {
		t.Fatalf("scalpel.summary() mismatch: %+v", sum)
	}
}
