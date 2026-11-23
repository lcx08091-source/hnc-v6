// native.go — 看门狗的四项检查(v5.29 T1 M2 起 Go 直接读内核 / 直接 exec 命令;
// v5.33 起是唯一一份: bin/watchdog.sh 的 probe_valid_hotspot / check_health /
// check_httpd_bind_drift、30 分钟对照、开关 run/wd_native.disabled 都删了)。
//
//	检查              判断函数                 判出「要动手」时
//	热点探测          probeHotspot            —(结果驱动 PENDING / ACTIVE 状态机)
//	规则健康          checkHealth             full_restore(shell, 限流见 restoreThrottle)
//	上行链路          nativeUplinkOK          tc_uplink_healthy(shell: 修 ifb0 / mirred,
//	                                          冷却 / 失败计数 / 降级标记都在那边)
//	(httpd 漂移检查已删: 远程端口由 httpd 自己按 remote_enabled 启停, 见 hnc_httpd
//	 remote_listener.go; v5.26 起 run/httpd_bind_ip 就没人写了, 两份漂移检查都是空转。)
//
// 原则:
//   - 判断在 Go;「动手」(恢复规则 / 修上行)仍走 runActionFn 让 shell 执行;
//   - 热点探测信息(run/iface_detect.json)超过 5 分钟或看不出结果 → 跑一次唯一的热点
//     网卡探测器 `sh bin/hnc_iface.sh get`(动作名 iface_detect)刷新, 再判一次;
//   - 规则健康判不了(netlink / iptables 跑不起来)→ 本轮跳过(不误判成规则丢失去
//     full_restore), 记 native_unknown(run/watchdog_actions.json, 自检「看门狗动作」
//     一行可见)。原来这种情况退回 shell 版 check_health —— 同样要 tc / iptables, 判不了
//     的场景两边一样。
package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"hnc.io/dpid/ifacehint"
	"hnc.io/dpid/nlroute"
)

// ── 可注入点(native_test 用) ──────────────────────────────────────
// natRunDir / natDataDir 文件路径根(默认生产 runDir / dataDir; 测试用
// t.TempDir() 覆盖, 才能喂「假文件」覆盖 shell 版的文件分支)。
var natRunDir, natDataDir = runDir, dataDir

var (
	// nlQdiscListFn 查询某网卡的 qdisc(默认 nlroute.QdiscList)。
	nlQdiscListFn = nlroute.QdiscList
	// nlIngressMirredFn 原生 netlink RTM_GETTFILTER 查热点口 ingress/clsact 是否存在
	// 指向目标 ifb0 ifindex 的 mirred 动作(默认 nlroute.HasIngressMirred; 失败回退 tc filter show)。
	nlIngressMirredFn = nlroute.HasIngressMirred
	// iptTargetsPath 内核已注册 xtables target 列表路径(单测可重定向防穿透宿主机)。
	iptTargetsPath = "/proc/net/ip_tables_targets"
	// netInterfaceByNameFn 查网卡(默认 net.InterfaceByName)。
	netInterfaceByNameFn = net.InterfaceByName
	// execCommandFn 直接执行外部命令(不经 sh; iptables / tc 文本探测用),
	// 强制 10s 超时 + 独立进程组 SIGKILL + WaitDelay, 防锁阻塞挂死主循环。
	execCommandFn = func(name string, args ...string) (string, int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), nativeExecTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, resolveSysBinPath(name), args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error {
			if cmd.Process != nil && cmd.Process.Pid > 0 {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				return cmd.Process.Kill()
			}
			return nil
		}
		cmd.WaitDelay = time.Second
		b, err := cmd.CombinedOutput()
		rc := 0
		if ctx.Err() == context.DeadlineExceeded {
			rc = -1
			err = ctx.Err()
		} else if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		} else if err != nil {
			rc = -1
		}
		return string(b), rc, err
	}
	// netIfAddrsFn 网卡地址列表(默认真实 Addrs 方法; 测试注入假地址)。
	netIfAddrsFn = func(ni *net.Interface) ([]net.Addr, error) { return ni.Addrs() }
	// sysIfIndexFn 读 /sys/class/net/<口>/ifindex(默认真实; 测试注入)。
	sysIfIndexFn = readSysIfIndex
	// ifaceHintReadFn 读权威热点网卡: 只认 5 分钟内的 run/iface_detect.json
	// (不回退 hotspot_iface —— 它没有时间戳, 陈旧了也看不出来)。陈旧 →
	// probeHotspot 跑一次 hnc_iface.sh get 刷新它。
	ifaceHintReadFn = func() (string, bool) { return ifacehint.ReadDetect(natRunDir, nowFn(), natHintFresh) }
	// ifaceDetectFn 跑唯一的热点网卡探测器(默认 runIfaceDetect)。
	ifaceDetectFn = runIfaceDetect
	// probeHotspotFn / checkHealthFn 主循环用的两项检查(测试替换成「世界状态」)。
	probeHotspotFn = probeHotspot
	checkHealthFn  = checkHealth
)

func resolveSysBinPath(name string) string {
	if strings.Contains(name, "/") {
		return name
	}
	if p, err := exec.LookPath(name); err == nil && p != "" {
		return p
	}
	for _, dir := range []string{"/system/bin", "/system/xbin", "/vendor/bin"} {
		cand := dir + "/" + name
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
	}
	return name
}

// execSysCmd 先按命令名调 execCommandFn; 若启动失败(rc < 0)且为裸命令名(如 iptables / tc),
// 自动兜底试一次 /system/bin/<name>, 防止 Magisk/KSU 极简 PATH 丢失 /system/bin。
func execSysCmd(name string, args ...string) (string, int, error) {
	out, rc, err := execCommandFn(name, args...)
	if rc < 0 && !strings.Contains(name, "/") {
		if out2, rc2, err2 := execCommandFn("/system/bin/"+name, args...); rc2 >= 0 {
			return out2, rc2, err2
		}
	}
	return out, rc, err
}

// nativeExecTimeout execCommandFn 的单次外部命令超时(iptables / tc 探测)。
var nativeExecTimeout = 10 * time.Second

// ifaceDetectTimeout hnc_iface.sh get 的超时(它会跑 dumpsys / iptables 探测)。
const ifaceDetectTimeout = 15 * time.Second

// runIfaceDetect `sh bin/hnc_iface.sh get`, 经动作记账(动作名 iface_detect)。
// 输出不用 —— 它把结论写进 run/iface_detect.json, 调用方重读。
func runIfaceDetect() {
	start := nowFn()
	ctx, cancel := context.WithTimeout(context.Background(), ifaceDetectTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, shellPath(), binDir+"/hnc_iface.sh", "get")
	cmd.Env = os.Environ()
	cmd.Stdout, cmd.Stderr = nil, nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	rc := 0
	if ctx.Err() == context.DeadlineExceeded {
		rc, err = -1, ctx.Err()
	} else if ee, ok := err.(*exec.ExitError); ok {
		rc, err = ee.ExitCode(), nil
	} else if err != nil {
		rc = -1
	}
	runStatsFn("iface_detect", rc, err, nowFn().Sub(start).Seconds()*1000, nowFn())
}

// probeHotspot 热点探测(v5.33 起唯一一份; 原 shell probe_valid_hotspot):
// 先用 5 分钟内的探测结果判; 判不了(陈旧 / 没有 / 网卡没私网 IPv4)就跑一次
// hnc_iface.sh get 刷新, 再判一次。成功 → rc 0 + "<口> <IP>"; 否则 rc 1(热点没开)。
func probeHotspot() actionResult {
	r := nativeProbeHotspot()
	if r.unknown {
		ifaceDetectFn()
		r = nativeProbeHotspot()
	}
	if r.ok {
		return actionResult{exitCode: 0, stdout: r.iface + " " + r.ip}
	}
	return actionResult{exitCode: 1}
}

// nativeUnknownTotal 规则健康判不了(本轮跳过)的累计次数 —— 进
// run/watchdog_actions.json 的 native_unknown, 自检「看门狗动作」一行显示。
var nativeUnknownTotal int

// checkHealth 规则健康(v5.33 起唯一一份; 原 shell check_health): 0 健康 /
// 1 规则丢失 → full_restore / 2 临时故障(锁忙等)→ 跳过本轮。判不了按 2 处理并计数。
func checkHealth(iface string) int {
	rc := nativeCheckHealth(iface)
	if rc == natHealthUnknown {
		nativeUnknownTotal++
		if nativeUnknownTotal == 1 || nativeUnknownTotal%60 == 0 {
			logf("check_health: 判不了(netlink / iptables 跑不起来), 本轮跳过 (累计 %d 次)", nativeUnknownTotal)
		}
		return natHealthBusy
	}
	return rc
}

// natHintFresh 原生 probe 认可的 iface_detect.json 新鲜度(WORK-v5.29 §T1)。
const natHintFresh = 5 * time.Minute

// nativeProbeResult 热点探测的结论(由 probeHotspot 转成 actionResult)。
type nativeProbeResult struct {
	iface string // 有效的热点网卡(空 = 无)
	ip    string // 该网卡上的私网 IPv4
	ok    bool   // 有效热点: "<iface> <IP>"
	// unknown = 判断不出来(网卡探测陈旧 / 无私网 IP 等); probeHotspot 刷新探测再判一次。
	unknown bool
}

func isHotspotPrivateIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if ip4.IsPrivate() {
		return true
	}
	// RFC 6598 100.64.0.0/10(部分定制 ROM 热点共享网段)
	return ip4[0] == 100 && (ip4[1]&0xc0) == 64
}

func isWlan0AuthoritativeHotspot() bool {
	authIface, auth, ok := ifacehint.ReadAuthoritative(natRunDir, nowFn(), natHintFresh)
	return ok && auth && authIface == "wlan0"
}

// nativeProbeHotspot 照 v5.32 及以前的 shell probe_valid_hotspot 写的:
//   - device_detect.sh iface → ifacehint.ReadDetect(陈旧即 unknown, probeHotspot 刷新);
//   - ip -4 addr show <口> → net.InterfaceByName + Addrs;
//   - 「必须是私网 IPv4」→ RFC1918 或 100.64.0.0/10;
//   - wlan0 默认视为 STA 口拒绝, 仅当 iface_detect.json 明确含 authoritative=true 或 wlan0_ap=true 时放行。
func nativeProbeHotspot() nativeProbeResult {
	iface, ok := ifaceHintReadFn()
	if !ok || iface == "" {
		return nativeProbeResult{unknown: true}
	}
	if iface == "wlan0" && !isWlan0AuthoritativeHotspot() {
		return nativeProbeResult{unknown: true}
	}
	ni, err := netInterfaceByNameFn(iface)
	if err != nil {
		return nativeProbeResult{unknown: true}
	}
	addrs, err := netIfAddrsFn(ni)
	if err != nil {
		return nativeProbeResult{unknown: true}
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if isHotspotPrivateIPv4(ipn.IP) {
			return nativeProbeResult{iface: iface, ip: ipn.IP.To4().String(), ok: true}
		}
	}
	return nativeProbeResult{unknown: true} // 无私网 IPv4
}

// 规则健康的结论码(语义照抄 v5.32 及以前的 shell check_health)。
const (
	natHealthUnknown = -1 // 判不了 → checkHealth 按「跳过本轮」处理并计数
	natHealthOK      = 0
	natHealthLost    = 1 // 规则真丢 → full_restore
	natHealthBusy    = 2 // 锁忙等临时故障 → 跳过本轮
)

// capBool 读 run/capabilities.json 的布尔能力键(与 shell
// watchdog_cap_bool_value, watchdog.sh:90 同口径: 显式 true / false,
// 其余 unknown)。
func capBool(key string) (bool, bool) {
	b, err := os.ReadFile(natRunDir + "/capabilities.json")
	if err != nil {
		return false, false
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return false, false
	}
	v, ok := m[key].(bool)
	return v, ok
}

func isXtablesWaitUnsupported(out string) bool {
	lo := strings.ToLower(out)
	return strings.Contains(lo, "bad argument") ||
		strings.Contains(lo, "unknown option") ||
		strings.Contains(lo, "unrecognized option") ||
		strings.Contains(lo, "invalid option") ||
		strings.Contains(lo, "unknown arg")
}

func isXtablesLockBusy(out string, rc int) bool {
	if rc == 4 {
		return true
	}
	lo := strings.ToLower(out)
	return strings.Contains(lo, "resource temporarily unavailable") ||
		strings.Contains(lo, "xtables lock")
}

func isXtablesChainMissing(out string) bool {
	lo := strings.ToLower(out)
	return strings.Contains(lo, "no chain") ||
		strings.Contains(lo, "does not exist") ||
		strings.Contains(lo, "bad chain")
}

// iptablesDumpChain 查询 mangle 表指定链规则, 支持 `-w 2` → `-w` → 无 `-w` 三级回退,
// 并修复真机 AOSP `iptables -S <CHAIN>` 丢链时返回 rc==1 被误判成锁忙的 P0 漏洞。
func iptablesDumpChain(chain string) (string, int) {
	out, rc, _ := execSysCmd("iptables", "-w", "2", "-t", "mangle", "-S", chain)
	if (rc == 1 || rc == 2) && isXtablesWaitUnsupported(out) {
		out, rc, _ = execSysCmd("iptables", "-w", "-t", "mangle", "-S", chain)
		if (rc == 1 || rc == 2) && isXtablesWaitUnsupported(out) {
			out, rc, _ = execSysCmd("iptables", "-t", "mangle", "-S", chain)
		}
	}
	if rc < 0 {
		return out, natHealthUnknown
	}
	if rc == 0 {
		return out, natHealthOK
	}
	if isXtablesLockBusy(out, rc) {
		return out, natHealthBusy
	}
	if rc == 1 || rc == 2 || isXtablesChainMissing(out) {
		return out, natHealthLost
	}
	return out, natHealthBusy
}

// connmarkUnsupported 判断内核是否明确缺少 xt_CONNMARK target 支持:
// 仅当 capabilities.json 显式标记 ipt_connmark=false 或 xt_connmark=false,
// 或 /proc/net/ip_tables_targets 可读非空且不含 CONNMARK 时返回 true, 豁免 HNC_RESTORE 空链检查以防恢复风暴。
func connmarkUnsupported() bool {
	if v, known := capBool("ipt_connmark"); known && !v {
		return true
	}
	if v, known := capBool("xt_connmark"); known && !v {
		return true
	}
	if b, err := os.ReadFile(iptTargetsPath); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" && !strings.Contains(s, "CONNMARK") {
			return true
		}
	}
	return false
}

// nativeCheckHealth 规则健康检查:
//  0. iface 为空或 run/tc_restore_pending 存在 → 1;
//  1. 能力 tc_htb 显式 false → 跳过 tc 检查; 否则要求存在 kind=htb 且(parent=root 或 handle="1:");
//  2. /sys/class/net/<口>/ifindex 与 run/tc_ifindex_<口> 不一致 → 1;
//  3. iptables mangle HNC_MARK: 链丢失(rc=1/2, 非锁忙)→ 1; 锁忙(rc=4)→ 2;
//  4. iptables mangle HNC_RESTORE: 链丢失 → 1; 锁忙 → 2; 未豁免 xt_connmark 时输出无 CONNMARK → 1。
func nativeCheckHealth(iface string) int {
	if iface == "" {
		return natHealthLost
	}
	if _, err := os.Stat(natRunDir + "/tc_restore_pending"); err == nil {
		return natHealthLost
	}
	if tcCore, known := capBool("tc_htb"); known && !tcCore {
		// 跳过 tc 检查, 继续看 iptables
	} else {
		qs, err := nlQdiscListFn(ifIndex(iface))
		if err != nil {
			return natHealthUnknown
		}
		if !qdiscHasRootHTB(qs) {
			return natHealthLost
		}
	}
	want, err := sysIfIndexFn(iface)
	if err != nil {
		return natHealthUnknown
	}
	got, gerr := readFileTrim(natRunDir + "/tc_ifindex_" + iface)
	if gerr == nil {
		if got != want {
			return natHealthLost
		}
	}

	if _, st := iptablesDumpChain("HNC_MARK"); st != natHealthOK {
		return st
	}
	out, st := iptablesDumpChain("HNC_RESTORE")
	if st != natHealthOK {
		return st
	}
	if !strings.Contains(out, "CONNMARK") && !connmarkUnsupported() {
		return natHealthLost
	}
	return natHealthOK
}

// qdiscHasRootHTB shell 的 tc 根判断: kind=htb 且 (parent 根 或 handle 1:)。
func qdiscHasRootHTB(qs []nlroute.Qdisc) bool {
	for _, q := range qs {
		if q.Kind != "htb" {
			continue
		}
		if q.Parent == nlroute.TC_H_ROOT || q.Handle == nlroute.TC_HMaj(1) {
			return true
		}
	}
	return false
}

// ifIndex 网卡的 ifindex; 失败 -1(调用方 netlink 查询会失败 → unknown)。
func ifIndex(iface string) int {
	ni, err := netInterfaceByNameFn(iface)
	if err != nil {
		return -1
	}
	return ni.Index
}

// readSysIfIndex /sys/class/net/<口>/ifindex 的数值(字符串形式)。
func readSysIfIndex(iface string) (string, error) {
	return readFileTrim("/sys/class/net/" + iface + "/ifindex")
}

func readFileTrim(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// nativeUplinkOK 上行链路「需不需要修」:
//   - 能力 uplink_supported 显式 false → false;
//   - ifb0 不存在或根 qdisc 不是 htb → false;
//   - 热点口 ingress/clsact 是否存在指向 ifb0 的 mirred 动作: 优先走纯 Go nlIngressMirredFn
//     (RTM_GETTFILTER, 0 fork); 若 netlink 查询不可用则回退 tc filter show。
func nativeUplinkOK(iface string) (ok, unknown bool) {
	if cap, known := capBool("uplink_supported"); known && !cap {
		return false, false
	}
	ifb, err := netInterfaceByNameFn("ifb0")
	if err != nil || ifb == nil {
		return false, false
	}
	qs, err := nlQdiscListFn(ifb.Index)
	if err != nil {
		return false, true
	}
	rootHTB := false
	for _, q := range qs {
		if q.Kind == "htb" && q.Parent == nlroute.TC_H_ROOT {
			rootHTB = true
			break
		}
	}
	if !rootHTB {
		return false, false
	}
	if iface == "" {
		iface = "wlan2" // shell: `[ -z "$iface" ] && iface="wlan2"`
	}
	if devIdx := ifIndex(iface); devIdx > 0 && nlIngressMirredFn != nil {
		if hasMirred, nlErr := nlIngressMirredFn(devIdx, ifb.Index); nlErr == nil {
			return hasMirred, false
		}
	}
	out1, rc1, _ := execSysCmd("tc", "filter", "show", "dev", iface, "ingress")
	if rc1 == 0 && hasMirredIfb0(out1) {
		return true, false
	}
	out2, rc2, _ := execSysCmd("tc", "filter", "show", "dev", iface, "parent", "ffff:")
	if rc2 == 0 && hasMirredIfb0(out2) {
		return true, false
	}
	if rc1 != 0 && rc2 != 0 {
		return false, true // 两种写法都跑不动 → 判不了
	}
	return false, false
}

// hasMirredIfb0 同 shell `grep -qiE "mirred.*ifb0"`(同一行内 mirred 在 ifb0 之前)。
func hasMirredIfb0(out string) bool {
	for _, ln := range strings.Split(strings.ToLower(out), "\n") {
		if i := strings.Index(ln, "mirred"); i >= 0 && strings.Contains(ln[i:], "ifb0") {
			return true
		}
	}
	return false
}

// wdActionsSnapshotExtra actionstats.flush 之外带出的计数
// (run/watchdog_actions.json 顶层 native_unknown 字段)。
var wdActionsSnapshotExtra = func() int { return nativeUnknownTotal }
