package output

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// v6 review fix 回归测试: sampleOnly 的变更检测依赖 connsSignature —— 同一
// 连接集不同顺序必须得到同一签名 (parseProcNet 的遍历顺序不稳定), 否则会
// 误判"变了"导致写放大修复失效。
func TestConnsSignatureOrderIndependent(t *testing.T) {
	a := []SelfAttribConnRow{
		{Proto: "tcp", Local: "10.0.0.1:44444", Remote: "93.0.0.1:443", UID: 10100},
		{Proto: "udp", Local: "10.0.0.1:5353", Remote: "8.8.8.8:53", UID: 10200},
	}
	b := []SelfAttribConnRow{
		{Proto: "udp", Local: "10.0.0.1:5353", Remote: "8.8.8.8:53", UID: 10200},
		{Proto: "tcp", Local: "10.0.0.1:44444", Remote: "93.0.0.1:443", UID: 10100},
	}
	if connsSignature(a) != connsSignature(b) {
		t.Fatal("same conn set in different order must produce the same signature")
	}

	c := append(b[:1:1], SelfAttribConnRow{Proto: "tcp", Local: "10.0.0.2:55555", Remote: "1.1.1.1:443", UID: 10100})
	if connsSignature(a) == connsSignature(c) {
		t.Fatal("different conn sets must produce different signatures")
	}

	// Pkg/State 等非 key 字段不参与签名 (连接集相同即跳过 append 的依据)。
	a[0].Pkg = "com.example.changed"
	if connsSignature(a) != connsSignature(b) {
		t.Fatal("non-key fields must not affect the signature")
	}
}

// v5.12: /proc/net/tcp6 里的 IPv4 映射地址与纯 IPv6 地址, 必须能被抓包侧
// LookupUID(net.IP.String(), port) 命中。
func TestLookupUID_CanonicalKeys(t *testing.T) {
	a := NewSelfAttribAggregator("")
	cases := []struct {
		procHex string // /proc/net/tcp6 remote 字段
		ip      string // 抓包侧 ev.DstIP.String()
	}{
		{"0000000000000000FFFF00000100007F:01BB", "127.0.0.1"},
		{"B80D0120000000000000000001000000:01BB", "2001:db8::1"},
	}
	for i, c := range cases {
		k := canonRemoteKey(parseHexAddr(c.procHex, true))
		if k == "" {
			t.Fatalf("case %d: 规范化失败 %q", i, parseHexAddr(c.procHex, true))
		}
		a.remoteToUID[k] = 10100 + i
	}
	for i, c := range cases {
		uid, _, ok := a.LookupUID(c.ip, 443)
		if !ok || uid != 10100+i {
			t.Errorf("case %d: LookupUID(%s,443) = %d,%v; keys=%v", i, c.ip, uid, ok, a.remoteToUID)
		}
	}
	// IPv4 socket(/proc/net/tcp)也照常命中。
	a.remoteToUID[canonRemoteKey(parseHexAddr("0101A8C0:0050", false))] = 10200
	if uid, _, ok := a.LookupUID("192.168.1.1", 80); !ok || uid != 10200 {
		t.Errorf("IPv4 查找失败: %d %v", uid, ok)
	}
}

func TestPackagesListExtractsSystemPkgsWithoutPM(t *testing.T) {
	fakeList := filepath.Join(t.TempDir(), "packages.list")
	content := "" +
		"android.uid.system 1000 0 /data/system default:targetSdkVersion=34 none\n" +
		"com.android.systemui 10085 0 /data/user/0/com.android.systemui platform:privapp:targetSdkVersion=34 1065\n" +
		"com.google.android.gms 10110 0 /data/user/0/com.google.android.gms default:privapp:targetSdkVersion=34 3003\n" +
		"com.vendor.ims 10120 0 /vendor/app/ImsService default:targetSdkVersion=34 none\n" +
		"com.android.tethering 10130 0 /apex/com.android.tethering/priv-app/Tethering default:targetSdkVersion=34 none\n" +
		"com.tencent.mm 10234 0 /data/user/0/com.tencent.mm default:targetSdkVersion=33 3003\n" +
		"tv.danmaku.bili 10235 0 /data/app/~~abc==/tv.danmaku.bili-xyz== default:targetSdkVersion=34 3003\n" +
		"com.sina.weibo 10236 0 /data/data/com.sina.weibo default:targetSdkVersion=33 3003\n"
	if err := os.WriteFile(fakeList, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	oldPath := packagesListPath
	packagesListPath = fakeList
	t.Cleanup(func() { packagesListPath = oldPath })

	a := NewSelfAttribAggregator("")
	pkgMap := a.getPkgCache()
	if pkgMap[10234] != "com.tencent.mm" || pkgMap[10085] != "com.android.systemui" {
		t.Fatalf("unexpected pkgMap: %v", pkgMap)
	}

	wantSys := []int{1000, 10085, 10110, 10120, 10130}
	for _, uid := range wantSys {
		if !a.IsSystemUID(uid) {
			t.Errorf("uid %d (%s) should be marked system", uid, pkgMap[uid])
		}
	}
	wantUser := []int{10234, 10235, 10236}
	for _, uid := range wantUser {
		if a.IsSystemUID(uid) {
			t.Errorf("user uid %d (%s) must NOT be marked system", uid, pkgMap[uid])
		}
	}

	sysSet, err := loadSystemPkgs()
	if err != nil {
		t.Fatalf("loadSystemPkgs from packages.list failed: %v", err)
	}
	if _, ok := sysSet["com.tencent.mm"]; ok {
		t.Fatal("user app leaked into systemPkgs")
	}
	if _, ok := sysSet["com.vendor.ims"]; !ok {
		t.Fatal("system path app missing from systemPkgs")
	}
}

func TestPMCommandKillsProcessGroupOnTimeout(t *testing.T) {
	start := time.Now()
	cmd, cancel := pmCommandWithTimeout(250*time.Millisecond, "sh", "-c", "(sleep 30) & sleep 30")
	defer cancel()
	_, err := cmd.Output()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error from pmCommandWithTimeout")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("pmCommandWithTimeout hung waiting for child process group: %v", elapsed)
	}
}

