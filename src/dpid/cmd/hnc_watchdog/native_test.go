// native_test.go — v5.29 T1: 看门狗原生检查, 用例名与 bin/watchdog.sh 的
// 分支一一对应(注释标 shell 原文行号; 路径/命令全部注入假实现)。
package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"hnc.io/dpid/nlroute"
)

// natTestEnv 每个用例的假世界: 临时目录当 run/, 注入各外部调用。
type natTestEnv struct {
	runDir  string
	dataDir string
}

func newNatTestEnv(t *testing.T) *natTestEnv {
	t.Helper()
	e := &natTestEnv{runDir: t.TempDir(), dataDir: t.TempDir()}
	oldRun, oldData := natRunDir, natDataDir
	natRunDir, natDataDir = e.runDir, e.dataDir
	t.Cleanup(func() { natRunDir, natDataDir = oldRun, oldData })
	e.resetGlobals(t)
	return e
}

// resetGlobals 重置共享缓存与对照状态(测试间不串)。
func (e *natTestEnv) resetGlobals(t *testing.T) {
	t.Helper()
	oldHCAt, oldHCRCC, oldHCI := healthCacheAt, healthCacheRC, healthCacheIface
	oldShadow := natShadowSt
	oldMM := nativeMismatchTotal
	healthCacheAt, healthCacheRC, healthCacheIface = time.Time{}, 0, ""
	natShadowSt = newNativeShadowState()
	nativeMismatchTotal = 0
	t.Cleanup(func() {
		healthCacheAt, healthCacheRC, healthCacheIface = oldHCAt, oldHCRCC, oldHCI
		natShadowSt = oldShadow
		nativeMismatchTotal = oldMM
	})
}

// inject 注入探测 / netlink / exec 的假实现并恢复。
func (e *natTestEnv) inject(t *testing.T, iface string, qdiscs []nlroute.Qdisc,
	execFn func(name string, args ...string) (string, int, error)) {
	t.Helper()
	oldHint, oldByN, oldAddrs, oldQ, oldExec := ifaceHintReadFn, netInterfaceByNameFn, netIfAddrsFn, nlQdiscListFn, execCommandFn
	ifaceHintReadFn = func() (string, bool) { return iface, iface != "" }
	netInterfaceByNameFn = func(name string) (*net.Interface, error) {
		if iface == "" && name != "ifb0" {
			return nil, os.ErrNotExist
		}
		if name != "ifb0" && name != iface {
			return nil, os.ErrNotExist
		}
		return &net.Interface{Name: name, Index: 5}, nil
	}
	netIfAddrsFn = func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.43.1").To4(), Mask: net.CIDRMask(24, 32)}}, nil
	}
	nlQdiscListFn = func(idx int) ([]nlroute.Qdisc, error) { return qdiscs, nil }
	if execFn == nil {
		// 默认: 命令都正常, HNC_RESTORE 里有 CONNMARK(健康世界)
		execFn = func(name string, args ...string) (string, int, error) {
			if len(args) > 3 && args[len(args)-1] == "HNC_RESTORE" {
				return "-A HNC_RESTORE -j CONNMARK --restore-mark\n", 0, nil
			}
			return "", 0, nil
		}
	}
	execCommandFn = execFn
	oldSys := sysIfIndexFn
	sysIfIndexFn = func(string) (string, error) { return "5", nil }
	t.Cleanup(func() {
		ifaceHintReadFn, netInterfaceByNameFn, netIfAddrsFn = oldHint, oldByN, oldAddrs
		nlQdiscListFn, execCommandFn, sysIfIndexFn = oldQ, oldExec, oldSys
	})
}

func htbRoot() []nlroute.Qdisc {
	return []nlroute.Qdisc{{Kind: "htb", Handle: 0x10000, Parent: nlroute.TC_H_ROOT}}
}

func (e *natTestEnv) write(t *testing.T, name, content string) {
	t.Helper()
	p := filepath.Join(e.runDir, name)
	if dir := filepath.Dir(p); dir != e.runDir {
		_ = os.MkdirAll(dir, 0o755)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ── nativeProbeHotspot(shell probe_valid_hotspot, watchdog.sh 572 行起) ──

func TestProbeNativePrivateIP(t *testing.T) {
	// "ip -4 addr show <口>" 有私网 IPv4 → ok + "<口> <IP>"
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", nil, nil)
	r := nativeProbeHotspot()
	if r.unknown || !r.ok || r.iface != "wlan2" || r.ip != "192.168.43.1" {
		t.Fatalf("r=%+v", r)
	}
}

func TestProbeNativeWlan0NotHotspot(t *testing.T) {
	// 探测到 wlan0(手机 STA 口) → 不认(shell: wlan0 直接视为无效)
	e := newNatTestEnv(t)
	e.inject(t, "wlan0", nil, nil)
	if r := nativeProbeHotspot(); !r.unknown {
		t.Fatalf("wlan0 应 unknown: %+v", r)
	}
}

func TestProbeNativeStaleHintUnknown(t *testing.T) {
	// ifacehint 陈旧 / 无 → unknown(调用方退回 shell, shell 会刷新缓存)
	e := newNatTestEnv(t)
	e.inject(t, "", nil, nil)
	if r := nativeProbeHotspot(); !r.unknown {
		t.Fatalf("无探测应 unknown: %+v", r)
	}
}

func TestProbeNativeNoPrivateIPUnknown(t *testing.T) {
	// 网卡没有私网 IPv4(公网 IP / 只有 v6) → unknown
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", nil, nil)
	old := netIfAddrsFn
	netIfAddrsFn = func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("8.8.8.8").To4(), Mask: net.CIDRMask(32, 32)}}, nil
	}
	t.Cleanup(func() { netIfAddrsFn = old })
	if r := nativeProbeHotspot(); !r.unknown {
		t.Fatalf("非私网应 unknown: %+v", r)
	}
}

func TestProbeNativeNoInterfaceUnknown(t *testing.T) {
	// 网卡已消失(改名窗口) → unknown
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", nil, nil)
	old := netInterfaceByNameFn
	netInterfaceByNameFn = func(string) (*net.Interface, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { netInterfaceByNameFn = old })
	if r := nativeProbeHotspot(); !r.unknown {
		t.Fatalf("网卡缺失应 unknown: %+v", r)
	}
}

// ── nativeCheckHealth(shell check_health, watchdog.sh 271 行起) ──

func TestHealthNativeEmptyIfaceLost(t *testing.T) {
	// shell 行 278: iface 空 → rc=1
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	if rc := nativeCheckHealth(""); rc != natHealthLost {
		t.Fatalf("rc=%d want lost(1)", rc)
	}
}

func TestHealthNativeRestorePendingLost(t *testing.T) {
	// shell 行 280: run/tc_restore_pending 存在 → rc=1
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	e.write(t, "tc_restore_pending", "1")
	if rc := nativeCheckHealth("wlan2"); rc != natHealthLost {
		t.Fatalf("rc=%d want lost(1)", rc)
	}
}

func TestHealthNativeRootHTBOK(t *testing.T) {
	// shell 行 289(老版词序)/行 301(根 qdisc): kind=htb 且 parent=root → 过
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	e.write(t, "tc_ifindex_wlan2", "5")
	if rc := nativeCheckHealth("wlan2"); rc != natHealthOK {
		t.Fatalf("rc=%d want ok(0)", rc)
	}
}

func TestHealthNativeMqChildHTBOk(t *testing.T) {
	// shell 行 ~301: mq 子队列 htb(handle 1:, 无 root)也算健康
	e := newNatTestEnv(t)
	qs := []nlroute.Qdisc{{Kind: "mq", Parent: nlroute.TC_H_ROOT}, {Kind: "htb", Handle: 0x10000, Parent: 1}}
	e.inject(t, "wlan2", qs, nil)
	e.write(t, "tc_ifindex_wlan2", "5")
	if rc := nativeCheckHealth("wlan2"); rc != natHealthOK {
		t.Fatalf("rc=%d want ok(0)", rc)
	}
}

func TestHealthNativeNoHTBLost(t *testing.T) {
	// qdisc 里没有 htb → rc=1(规则丢了)
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", []nlroute.Qdisc{{Kind: "fq_codel", Parent: nlroute.TC_H_ROOT}}, nil)
	e.write(t, "tc_ifindex_wlan2", "5")
	if rc := nativeCheckHealth("wlan2"); rc != natHealthLost {
		t.Fatalf("rc=%d want lost(1)", rc)
	}
}

func TestHealthNativeNetlinkFailUnknown(t *testing.T) {
	// netlink 查不了 → unknown, 退回 shell(不误判丢规则)
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", nil, nil)
	old := nlQdiscListFn
	nlQdiscListFn = func(int) ([]nlroute.Qdisc, error) { return nil, os.ErrPermission }
	t.Cleanup(func() { nlQdiscListFn = old })
	if rc := nativeCheckHealth("wlan2"); rc != natHealthUnknown {
		t.Fatalf("rc=%d want unknown", rc)
	}
}

func TestHealthNativeCapTCHTFalseSkipsTC(t *testing.T) {
	// shell 行 291: tc_htb=false → 跳过 tc 检查(不要死循环 restore)
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", nil, nil)
	e.write(t, "capabilities.json", `{"tc_htb":false}`)
	e.write(t, "tc_ifindex_wlan2", "5")
	if rc := nativeCheckHealth("wlan2"); rc != natHealthOK {
		t.Fatalf("rc=%d want ok(0)", rc)
	}
}

func TestHealthNativeIfindexMismatchLost(t *testing.T) {
	// /sys/class/net/<口>/ifindex(注入的 net 是 5)与 run/tc_ifindex_<口> 不一致 → 1
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	e.write(t, "tc_ifindex_wlan2", "9")
	if rc := nativeCheckHealth("wlan2"); rc != natHealthLost {
		t.Fatalf("rc=%d want lost(1)", rc)
	}
}

func TestHealthNativeIptablesChainGoneLost(t *testing.T) {
	// shell 行 316: iptables -S HNC_MARK rc=2 → 链真丢 → 1
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	e.write(t, "tc_ifindex_wlan2", "5")
	old := execCommandFn
	execCommandFn = func(name string, args ...string) (string, int, error) {
		if len(args) > 3 && args[len(args)-1] == "HNC_MARK" {
			return "iptables: Bad chain name.\n", 2, &fakeExitErr{code: 2}
		}
		return "-A HNC_RESTORE -j CONNMARK --restore-mark\n", 0, nil
	}
	t.Cleanup(func() { execCommandFn = old })
	if rc := nativeCheckHealth("wlan2"); rc != natHealthLost {
		t.Fatalf("rc=%d want lost(1)", rc)
	}
}

func TestHealthNativeIptablesLockBusyTransient(t *testing.T) {
	// shell 行 320: iptables rc=4(锁抢不到) → 2 跳过本轮, 不 restore
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	e.write(t, "tc_ifindex_wlan2", "5")
	old := execCommandFn
	execCommandFn = func(name string, args ...string) (string, int, error) {
		if len(args) > 3 && args[len(args)-1] == "HNC_MARK" {
			return "xtables lock\n", 4, &fakeExitErr{code: 4}
		}
		return "-A HNC_RESTORE -j CONNMARK --restore-mark\n", 0, nil
	}
	t.Cleanup(func() { execCommandFn = old })
	if rc := nativeCheckHealth("wlan2"); rc != natHealthBusy {
		t.Fatalf("rc=%d want busy(2)", rc)
	}
}

func TestHealthNativeRestoreNoConnmarkLost(t *testing.T) {
	// shell 行 335: HNC_RESTORE 里没有 CONNMARK → 1
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	e.write(t, "tc_ifindex_wlan2", "5")
	old := execCommandFn
	execCommandFn = func(name string, args ...string) (string, int, error) {
		if len(args) > 3 && args[len(args)-1] == "HNC_RESTORE" {
			return "-A HNC_RESTORE -j MARK --set-mark 0x1\n", 0, nil
		}
		return "", 0, nil
	}
	t.Cleanup(func() { execCommandFn = old })
	if rc := nativeCheckHealth("wlan2"); rc != natHealthLost {
		t.Fatalf("rc=%d want lost(1)", rc)
	}
}

func TestHealthNativeEmptyMarkChainOK(t *testing.T) {
	// shell 行 309 注释: HNC_MARK 链空是合法状态(只看命令 rc, 不看内容)
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	e.write(t, "tc_ifindex_wlan2", "5")
	if rc := nativeCheckHealth("wlan2"); rc != natHealthOK {
		t.Fatalf("rc=%d want ok(0)", rc)
	}
}

// fakeExitErr 实现 exec.ExitError 的 ExitCode 接口(避免依赖 os/exec 细节)。
type fakeExitErr struct{ code int }

func (e *fakeExitErr) Error() string { return "exit status" }
func (e *fakeExitErr) ExitCode() int { return e.code }

func TestHealthNativeCache5s(t *testing.T) {
	// shell _HEALTH_TS/_HEALTH_RC: 5 秒内重复调用不重复执行(netlink 只查一次)
	e := newNatTestEnv(t)
	calls := 0
	e.inject(t, "wlan2", nil, nil)
	old := nlQdiscListFn
	nlQdiscListFn = func(int) ([]nlroute.Qdisc, error) {
		calls++
		return htbRoot(), nil
	}
	t.Cleanup(func() { nlQdiscListFn = old })
	e.write(t, "tc_ifindex_wlan2", "5")
	base := time.Date(2026, 10, 5, 10, 0, 0, 0, time.Local)
	if rc := nativeCheckHealthCached("wlan2", base); rc != natHealthOK {
		t.Fatalf("first rc=%d", rc)
	}
	if rc := nativeCheckHealthCached("wlan2", base.Add(3*time.Second)); rc != natHealthOK {
		t.Fatalf("cached rc=%d", rc)
	}
	if calls != 1 {
		t.Fatalf("netlink calls=%d, want 1(缓存生效)", calls)
	}
	if rc := nativeCheckHealthCached("wlan2", base.Add(6*time.Second)); rc != natHealthOK {
		t.Fatalf("expired rc=%d", rc)
	}
	if calls != 2 {
		t.Fatalf("netlink calls=%d, want 2(过期重查)", calls)
	}
}

// ── nativeHttpdDriftNeeded(shell check_httpd_bind_drift, 496 行起) ──

func TestDriftNoPidNoAction(t *testing.T) {
	// shell 行 497-499: 无 pid / 无 bind_ip 文件 → 不动手
	e := newNatTestEnv(t)
	e.inject(t, "", nil, nil)
	if needed, unknown := nativeHttpdDriftNeeded(); needed || unknown {
		t.Fatalf("needed=%v unknown=%v, want false/false", needed, unknown)
	}
}

func TestDriftProcessGoneNoAction(t *testing.T) {
	// shell 行 502: pid 不存活 → 不动手
	e := newNatTestEnv(t)
	e.inject(t, "", nil, nil)
	e.write(t, "httpd.pid", "12345")
	old := processAliveFn
	processAliveFn = func(int) bool { return false }
	t.Cleanup(func() { processAliveFn = old })
	if needed, unknown := nativeHttpdDriftNeeded(); needed || unknown {
		t.Fatalf("needed=%v unknown=%v", needed, unknown)
	}
}

func TestDriftRemoteOffStillPublicNeedsAction(t *testing.T) {
	// shell 场景 1(行 520 附近): remote_enabled!=true 且 bind 不是
	// loopback-only → 需要动手(调 shell 执行)
	e := newNatTestEnv(t)
	e.inject(t, "", nil, nil)
	e.write(t, "httpd.pid", "12345")
	e.write(t, "httpd_bind_ip", "0.0.0.0")
	os.MkdirAll(e.dataDir, 0o755)
	os.WriteFile(filepath.Join(e.dataDir, "rules.json"), []byte(`{"remote_enabled":false}`), 0o644)
	old := processAliveFn
	processAliveFn = func(int) bool { return true }
	t.Cleanup(func() { processAliveFn = old })
	if needed, unknown := nativeHttpdDriftNeeded(); !needed || unknown {
		t.Fatalf("needed=%v unknown=%v, want true/false", needed, unknown)
	}
}

func TestDriftRemoteOnLoopbackWlan0NoAction(t *testing.T) {
	// shell 场景 2(行 530 附近): remote on + loopback-only, 但 iface=wlan0 → 不动手
	e := newNatTestEnv(t)
	e.inject(t, "wlan0", nil, nil)
	e.write(t, "httpd.pid", "12345")
	e.write(t, "httpd_bind_ip", "loopback-only")
	os.WriteFile(filepath.Join(e.dataDir, "rules.json"), []byte(`{"remote_enabled":true}`), 0o644)
	old := processAliveFn
	processAliveFn = func(int) bool { return true }
	t.Cleanup(func() { processAliveFn = old })
	if needed, unknown := nativeHttpdDriftNeeded(); needed || unknown {
		t.Fatalf("needed=%v unknown=%v, want false/false(wlan0 不是热点口)", needed, unknown)
	}
}

func TestDriftRemoteOnLoopbackHotspotIPNeedsAction(t *testing.T) {
	// shell 场景 2: 热点口有 IPv4 → 需要动手(升级绑定到 0.0.0.0)
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", nil, nil)
	e.write(t, "httpd.pid", "12345")
	e.write(t, "httpd_bind_ip", "loopback-only")
	os.WriteFile(filepath.Join(e.dataDir, "rules.json"), []byte(`{"remote_enabled":true}`), 0o644)
	old := processAliveFn
	processAliveFn = func(int) bool { return true }
	t.Cleanup(func() { processAliveFn = old })
	if needed, unknown := nativeHttpdDriftNeeded(); !needed || unknown {
		t.Fatalf("needed=%v unknown=%v, want true/false", needed, unknown)
	}
}

func TestDriftRulesUnreadableUnknown(t *testing.T) {
	// rules.json 读不了 / 无该键 → unknown(退回 shell 判断, 不敢瞎动手)
	e := newNatTestEnv(t)
	e.inject(t, "", nil, nil)
	e.write(t, "httpd.pid", "12345")
	e.write(t, "httpd_bind_ip", "0.0.0.0")
	old := processAliveFn
	processAliveFn = func(int) bool { return true }
	t.Cleanup(func() { processAliveFn = old })
	if needed, unknown := nativeHttpdDriftNeeded(); !needed || !unknown {
		t.Fatalf("needed=%v unknown=%v, want true/true", needed, unknown)
	}
}

// ── nativeUplinkOK(shell ensure_tc_uplink_healthy, 725 行起) ──

func TestUplinkCapFalseNoShell(t *testing.T) {
	// shell 行 727: uplink_supported=false → 降级, 不需要 shell 修
	// (shell 版会打降级标记, 这里 native=false, unknown=false)
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	e.write(t, "capabilities.json", `{"uplink_supported":false}`)
	if ok, unknown := nativeUplinkOK("wlan2"); ok || unknown {
		t.Fatalf("ok=%v unknown=%v, want false/false", ok, unknown)
	}
}

func TestUplinkIfb0MissingNeedsShell(t *testing.T) {
	// ifb0 不存在 → 需要修(ok=false → 调 shell)
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	old := netInterfaceByNameFn
	netInterfaceByNameFn = func(name string) (*net.Interface, error) {
		if name == "ifb0" {
			return nil, os.ErrNotExist
		}
		return &net.Interface{Name: name, Index: 5}, nil
	}
	t.Cleanup(func() { netInterfaceByNameFn = old })
	if ok, unknown := nativeUplinkOK("wlan2"); ok || unknown {
		t.Fatalf("ok=%v unknown=%v, want false/false", ok, unknown)
	}
}

func TestUplinkIfb0NoRootHTBNeedsShell(t *testing.T) {
	// ifb0 根 qdisc 不是 htb → 需要修
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", nil, nil)
	old := nlQdiscListFn
	nlQdiscListFn = func(int) ([]nlroute.Qdisc, error) {
		return []nlroute.Qdisc{{Kind: "fq_codel", Parent: nlroute.TC_H_ROOT}}, nil
	}
	t.Cleanup(func() { nlQdiscListFn = old })
	if ok, unknown := nativeUplinkOK("wlan2"); ok || unknown {
		t.Fatalf("ok=%v unknown=%v, want false/false", ok, unknown)
	}
}

func TestUplinkMirredMissingNeedsShell(t *testing.T) {
	// tc filter 输出里没有 mirred→ifb0 → 需要修
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	old := execCommandFn
	execCommandFn = func(name string, args ...string) (string, int, error) {
		return "filter parent ffff: protocol ip pref 1 u32 match ...\n", 0, nil
	}
	t.Cleanup(func() { execCommandFn = old })
	if ok, unknown := nativeUplinkOK("wlan2"); ok || unknown {
		t.Fatalf("ok=%v unknown=%v, want false/false", ok, unknown)
	}
}

func TestUplinkAllGoodNoShell(t *testing.T) {
	// ifb0 在 + 根 htb + ingress mirred→ifb0 → 不需要 shell
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	old := execCommandFn
	execCommandFn = func(name string, args ...string) (string, int, error) {
		return "filter parent ffff: protocol ip pref 1 flower action mirred egress redirect dev ifb0\n", 0, nil
	}
	t.Cleanup(func() { execCommandFn = old })
	if ok, unknown := nativeUplinkOK("wlan2"); !ok || unknown {
		t.Fatalf("ok=%v unknown=%v, want true/false", ok, unknown)
	}
}

func TestUplinkTCIngressFallbackParentFFFF(t *testing.T) {
	// ColorOS 魔改 tc: `ingress` 关键字被拒(rc!=0)→ 再试 parent ffff:,
	// 第二种写法看到 mirred → 不需要修
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	old := execCommandFn
	execCommandFn = func(name string, args ...string) (string, int, error) {
		for _, a := range args {
			if a == "ingress" {
				return "Bad syntax\n", 1, &fakeExitErr{code: 1}
			}
		}
		return "filter parent ffff: flower action mirred egress redirect dev ifb0\n", 0, nil
	}
	t.Cleanup(func() { execCommandFn = old })
	if ok, unknown := nativeUplinkOK("wlan2"); !ok || unknown {
		t.Fatalf("ok=%v unknown=%v, want true/false(parent ffff: 兜底)", ok, unknown)
	}
}

func TestUplinkTCIngressEmptyStillTriesParentFFFF(t *testing.T) {
	// shell: 两种写法是 && 关系(都没看到才修)。`ingress` rc=0 但输出为空
	// (部分 ROM 的 tc 不认 ingress 别名却不报错)→ 仍要试 parent ffff:。
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	old := execCommandFn
	execCommandFn = func(name string, args ...string) (string, int, error) {
		for _, a := range args {
			if a == "ingress" {
				return "", 0, nil
			}
		}
		return "filter parent ffff: flower action mirred egress redirect dev ifb0\n", 0, nil
	}
	t.Cleanup(func() { execCommandFn = old })
	if ok, unknown := nativeUplinkOK("wlan2"); !ok || unknown {
		t.Fatalf("ok=%v unknown=%v, want true/false", ok, unknown)
	}
}

func TestUplinkTCBothFailUnknown(t *testing.T) {
	// 两种写法都失败 → unknown(退回 shell 判断, 修路径逻辑不搬)
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	old := execCommandFn
	execCommandFn = func(name string, args ...string) (string, int, error) {
		return "nope\n", 1, &fakeExitErr{code: 1}
	}
	t.Cleanup(func() { execCommandFn = old })
	if ok, unknown := nativeUplinkOK("wlan2"); ok || !unknown {
		t.Fatalf("ok=%v unknown=%v, want false/true", ok, unknown)
	}
}

// ── 开关与对照机制 ──────────────────────────────────────────────────

func TestNativeSwitchDisabledFile(t *testing.T) {
	// run/wd_native.disabled 存在 → 全部退回 shell
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	e.write(t, "wd_native.disabled", "")
	if nativeEnabled() || natUse(ncProbe) || natUse(ncHealth) {
		t.Fatal("开关文件存在时 natUse 应全部 false")
	}
}

func TestShadowMismatchCountAndRevert(t *testing.T) {
	// 对照: 不一致 → 计数 + 以 shell 为准; 连续 3 次 → 该项退回 shell
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	oldAct, oldNow := runActionFn, nowFn
	base := time.Date(2026, 10, 5, 10, 0, 0, 0, time.Local)
	cur := base
	nowFn = func() time.Time { return cur }
	runActionFn = func(name string, args ...string) actionResult {
		if name == "check_health" {
			return actionResult{exitCode: 0} // shell 说健康
		}
		return actionResult{exitCode: 0}
	}
	t.Cleanup(func() { runActionFn, nowFn = oldAct, oldNow })

	for i := 1; i <= 3; i++ {
		if got := natShadowHealth("wlan2", natHealthLost); got != natHealthOK { // 原生说丢规则
			t.Fatalf("对照轮应以 shell 结论为准, got %d", got)
		}
		cur = cur.Add(31 * time.Minute)
		if nativeMismatchTotal != i {
			t.Fatalf("mismatch=%d, want %d", nativeMismatchTotal, i)
		}
		if i < 3 && !natUse(ncHealth) {
			t.Fatalf("第 %d 次后不应退回", i)
		}
	}
	if natUse(ncHealth) {
		t.Fatal("连续 3 次不一致后应退回 shell")
	}
}

func TestShadowAgreementResetsStreak(t *testing.T) {
	// 不一致后一致 → 连续计数清零(不累计误退)
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", htbRoot(), nil)
	oldAct, oldNow := runActionFn, nowFn
	base := time.Date(2026, 10, 5, 10, 0, 0, 0, time.Local)
	cur := base
	nowFn = func() time.Time { return cur }
	runActionFn = func(string, ...string) actionResult { return actionResult{exitCode: 0} }
	t.Cleanup(func() { runActionFn, nowFn = oldAct, oldNow })
	natShadowHealth("wlan2", natHealthLost)
	cur = cur.Add(31 * time.Minute)
	natShadowHealth("wlan2", natHealthOK) // 一致
	cur = cur.Add(31 * time.Minute)
	natShadowHealth("wlan2", natHealthLost)
	cur = cur.Add(31 * time.Minute)
	natShadowHealth("wlan2", natHealthLost)
	if !natUse(ncHealth) {
		t.Fatal("只有连续 2 次不一致(中间一致清零), 不应退回")
	}
	if nativeMismatchTotal != 3 {
		t.Fatalf("mismatch=%d, want 3", nativeMismatchTotal)
	}
}

func TestShadowProbeComparesIfaceIP(t *testing.T) {
	// probe 对照: 原生 "wlan2 192.168.43.1" vs shell 输出不一致 → 计数
	e := newNatTestEnv(t)
	e.inject(t, "wlan2", nil, nil)
	oldAct, oldNow := runActionFn, nowFn
	cur := time.Date(2026, 10, 5, 10, 0, 0, 0, time.Local)
	nowFn = func() time.Time { return cur }
	runActionFn = func(name string, args ...string) actionResult {
		return actionResult{exitCode: 0, stdout: "wlan2 192.168.44.1\n"} // IP 不同
	}
	t.Cleanup(func() { runActionFn, nowFn = oldAct, oldNow })
	got := natShadowProbe(nativeProbeResult{iface: "wlan2", ip: "192.168.43.1", ok: true},
		actionResult{exitCode: 0, stdout: "wlan2 192.168.43.1"})
	if nativeMismatchTotal != 1 {
		t.Fatalf("mismatch=%d, want 1", nativeMismatchTotal)
	}
	if got.stdout != "wlan2 192.168.44.1\n" {
		t.Fatalf("对照轮应以 shell 输出为准, got %q", got.stdout)
	}
}

// ── 快照带出 native_mismatch(actionstats 联动) ─────────────────────

func TestSnapshotCarriesNativeMismatch(t *testing.T) {
	old := wdActionsSnapshotExtra
	wdActionsSnapshotExtra = func() int { return 7 }
	t.Cleanup(func() { wdActionsSnapshotExtra = old })
	s := &actionStats{}
	out := s.snapshot(time.Now())
	if out.NativeMismatch != 7 {
		t.Fatalf("NativeMismatch=%d, want 7", out.NativeMismatch)
	}
}
