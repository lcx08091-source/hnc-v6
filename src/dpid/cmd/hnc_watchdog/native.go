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
	// netInterfaceByNameFn 查网卡(默认 net.InterfaceByName)。
	netInterfaceByNameFn = net.InterfaceByName
	// netInterfacesFn 列全部网卡(默认 net.Interfaces)。
	netInterfacesFn = net.Interfaces
	// execCommandFn 直接执行外部命令(不经 sh; iptables / tc 文本探测用)。
	execCommandFn = func(name string, args ...string) (string, int, error) {
		b, err := exec.Command(name, args...).CombinedOutput()
		rc := 0
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		} else if err != nil {
			rc = -1
		}
		return string(b), rc, err
	}
	// processAliveFn PID 存活(默认 processAlive)。
	processAliveFn = processAlive
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
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	err := cmd.Run()
	rc := 0
	if ee, ok := err.(*exec.ExitError); ok {
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

// nativeProbeHotspot 照 v5.32 及以前的 shell probe_valid_hotspot 写的(行号见 git 历史)。
// 分支对应:
//   - device_detect.sh iface → ifacehint.ReadDetect(陈旧即 unknown, probeHotspot 刷新);
//   - ip -4 addr show <口> → net.InterfaceByName + Addrs;
//   - 「必须是私网 IPv4」→ ip.IsPrivate() && To4() != nil;
//   - 输出 "<口> <IP>" → ok=true(网卡非 wlan0 才算, 与 shell get_iface 语义一致)。
func nativeProbeHotspot() nativeProbeResult {
	iface, ok := ifaceHintReadFn()
	if !ok || iface == "" {
		return nativeProbeResult{unknown: true}
	}
	if iface == "wlan0" {
		// shell 探测器同样不认 wlan0(手机 wlan0 是 STA 口)
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
		ip4 := ipn.IP.To4()
		if ip4 != nil && ipn.IP.IsPrivate() {
			return nativeProbeResult{iface: iface, ip: ipn.IP.String(), ok: true}
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

// nativeCheckHealth 照 v5.32 及以前的 shell check_health 写的(注释里的「shell 行 N」
// 是当时 watchdog.sh 的行号), 逐项:
//  0. iface 为空 → 1(shell: `[ -z "$iface" ] && rc=1`);
//     run/tc_restore_pending 存在 → 1(shell: 行 281);
//  1. 能力 tc_htb 显式 false → 跳过 tc 检查(watchdog_tc_core_supported,
//     watchdog.sh:112); 否则 nlroute.QdiscList 要求存在 kind=htb 且
//     (parent = 根 0xFFFFFFFF 或 handle = "1:")的条目, 否则 1。
//     「1:」 = 0x00010000 —— 同时覆盖 root htb 与 mq 子队列 htb
//     (try_mq_child_htb 路径, shell 行 ~301);
//  2. /sys/class/net/<口>/ifindex 与 run/tc_ifindex_<口> 不一致 → 1;
//  3. iptables -w 2 -t mangle -S HNC_MARK: rc=2 → 1(链真丢); rc!=0 →
//     2(锁忙); (HNC_MARK 链空是合法状态 —— 只看命令返回, 不看内容);
//  4. iptables -w 2 -t mangle -S HNC_RESTORE: rc=2 → 1; rc!=0 → 2;
//     输出里没有 CONNMARK → 1(原 shell 版 `grep -q 'CONNMARK'`)。
//     netlink / iptables 执行失败 → unknown(不误判)。
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
	// ifindex 对比(shell: /sys/class/net/<口>/ifindex vs run/tc_ifindex_<口>)
	want, err := sysIfIndexFn(iface)
	if err != nil {
		return natHealthUnknown
	}
	got, gerr := readFileTrim(natRunDir + "/tc_ifindex_" + iface)
	if gerr == nil {
		if got != want {
			return natHealthLost
		}
	} // 没有 tc_ifindex 文件 = shell 同样放行(只在文件存在时比对)

	// exec 契约(见 execCommandFn): rc<0 = 命令没跑起来 → unknown;
	// *exec.ExitError 的退出码已折算成 rc ≥ 0, 照 shell 的 rc 语义判。
	out, rc, _ := execCommandFn("iptables", "-w", "2", "-t", "mangle", "-S", "HNC_MARK")
	if rc < 0 {
		return natHealthUnknown
	}
	if rc == 2 {
		return natHealthLost
	}
	if rc != 0 {
		return natHealthBusy
	}
	out, rc, _ = execCommandFn("iptables", "-w", "2", "-t", "mangle", "-S", "HNC_RESTORE")
	if rc < 0 {
		return natHealthUnknown
	}
	if rc == 2 {
		return natHealthLost
	}
	if rc != 0 {
		return natHealthBusy
	}
	if !strings.Contains(out, "CONNMARK") {
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

// nativeUplinkOK 上行链路「需不需要修」(修在 shell ensure_tc_uplink_healthy, 它还管
// 冷却 / 失败计数 / 降级标记, 修完自己再验证一遍):
//   - 能力 uplink_supported 显式 false → false(调 shell 动作, 它带
//     watchdog_mark_uplink_unsupported_once / 清 fail_count 的副作用);
//   - ifb0 不存在 → false;
//   - ifb0 根 qdisc 不是 htb(nlroute) → false;
//   - 热点口 ingress 没有 mirred→ifb0 过滤器 → false。判断方式: Go 直接
//     exec `tc filter show dev <口> ingress`, 失败(魔改 tc 拒绝 ingress
//     关键字, ColorOS 坑)再试 `parent ffff:`; 输出含 "mirred" 且含
//     "ifb0"(grep -iE "mirred.*ifb0" 同义)才算有。
//     任一步执行失败(netlink / tc 都跑不动)→ unknown, 调用方照样调 shell
//     (修复路径自己会判)。
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
	// shell: `! show ingress | grep mirred.*ifb0 && ! show parent ffff: | grep ...`
	// —— 两种写法任一看到就算有。ColorOS 的 tc 对 `ingress` 可能 rc=0 但
	// 输出为空, 所以第一种没看到(不论 rc)都要再试第二种。
	out1, rc1, _ := execCommandFn("tc", "filter", "show", "dev", iface, "ingress")
	if rc1 == 0 && hasMirredIfb0(out1) {
		return true, false
	}
	out2, rc2, _ := execCommandFn("tc", "filter", "show", "dev", iface, "parent", "ffff:")
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
