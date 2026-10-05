// native.go — v5.29 T1(M2): 看门狗四项检查原生化(Go 直接读内核 / 直接
// exec 命令, 不再每轮起 851 行的 sh watchdog.sh)。
//
// 对应关系(与 bin/watchdog.sh 逐分支一致, 测试用例名标注 shell 原文行号):
//
//	动作             shell 版                        本文件的判断函数
//	probe_hotspot    probe_valid_hotspot(572 行起)   nativeProbeHotspot
//	check_health     check_health(271 行起)          nativeCheckHealth
//	httpd_drift      check_httpd_bind_drift(496 行起) nativeHttpdDriftNeeded
//	tc_uplink_healthy ensure_tc_uplink_healthy(725 起) nativeUplinkOK
//
// 原则(照 WORK-v5.29.md §T1):
//   - 判断在 Go;「动手」(杀 httpd / 修 ingress / 恢复规则)仍走
//     runActionFn 让 shell 执行 —— 修复路径的冷却、失败计数、降级标记
//     逻辑一概不搬;
//   - 任何 Go 侧判不了(文件缺失 / netlink 失败 / 命令不可执行)→ 返回
//     「不确定」, 调用方退回 shell 版(shell 版会顺带刷新 iface_detect.json
//     之类的缓存);
//   - 对照机制(nativeShadow): 原生版每 30 分钟额外跑一次对应 shell 动作
//     比结论, 不一致以 shell 为准 + 记 native_mismatch; 同一项连续 3 次
//     不一致 → 该项退回 shell 直到看门狗重启;
//   - 开关: run/wd_native.disabled 存在 → 全部退回 shell(现有路径原样)。
package main

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"hnc.io/dpid/ifacehint"
	"hnc.io/dpid/nlroute"
)

// nativeEnabled 总开关: run/wd_native.disabled 存在 → false。
func nativeEnabled() bool {
	_, err := os.Stat(natRunDir + "/wd_native.disabled")
	return err != nil
}

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
	// ifaceHintReadFn 读权威热点网卡(默认 ifacehint.Read)。
	ifaceHintReadFn = func() (string, bool) { return ifacehint.Read(natRunDir, time.Now()) }
)

// nativeProbeResult probe_hotspot 的原生结论。
type nativeProbeResult struct {
	iface string // 有效的热点网卡(空 = 无)
	ip    string // 该网卡上的私网 IPv4
	ok    bool   // 与 shell "ACTIVE:<iface> <IP>" 语义对齐
	// unknown = 判断不出来(网卡探测陈旧 / 无私网 IP 等), 调用方退回 shell。
	unknown bool
}

// nativeProbeHotspot 对应 shell probe_valid_hotspot(watchdog.sh:572)。
// 分支对应:
//   - device_detect.sh iface → ifacehint.Read(陈旧即 unknown, 让 shell 顺带刷新);
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

// nativeHealthResult check_health 的原生结论, 语义完全照抄 shell。
const (
	natHealthUnknown = -1 // 判不了 → 调用方退回 shell
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

// nativeCheckHealth 对应 shell check_health(watchdog.sh:271), 逐项:
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
//     输出里没有 CONNMARK → 1(shell 行 335: `grep -q 'CONNMARK'`)。
//     netlink / iptables 执行失败 → unknown(退 shell, 不误判)。
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

// nativeHttpdDriftNeeded 对应 shell check_httpd_bind_drift
// (watchdog.sh:496)。Go 只判断「需不需要动手」:
//   - run/httpd.pid 或 run/httpd_bind_ip 不存在, 或 pid 不活, 或
//     bind_ip 为空 → 不需要(与 shell 前四个 early-return 一致);
//   - remote_enabled 显式 false 且 bind != "loopback-only" → 需要
//     (场景 1: remote 关了但 httpd 还公网绑定);
//   - remote_enabled 显式 true 且 bind == "loopback-only" → 场景 2:
//     权威网卡能读到且非 wlan0、网卡上有 IPv4 → 需要; 网卡探测不到 /
//     是 wlan0 / 无 IP → 不需要(与 shell 的三个 early-return 一致);
//   - rules.json 读不了 / remote_enabled 缺省 → 不确定(true), 调用方
//     退回 shell 动作(它 5 分钟才跑一次, 代价可忽略, 宁可保守)。
func nativeHttpdDriftNeeded() (needed, unknown bool) {
	pidStr, err := readFileTrim(natRunDir + "/httpd.pid")
	if err != nil || pidStr == "" {
		return false, false
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil || !processAliveFn(pid) {
		return false, false
	}
	bound, err := readFileTrim(natRunDir + "/httpd_bind_ip")
	if err != nil || bound == "" {
		return false, false
	}
	remote, known := rulesRemoteEnabled()
	if !known {
		return true, true
	}
	if !remote && bound != "loopback-only" {
		return true, false
	}
	if remote && bound == "loopback-only" {
		iface, ok := ifaceHintReadFn()
		if !ok || iface == "" || iface == "wlan0" {
			return false, false
		}
		ni, err := netInterfaceByNameFn(iface)
		if err != nil {
			return false, false
		}
		for _, a := range addrsOf(ni) {
			if a.To4() != nil {
				return true, false
			}
		}
		return false, false
	}
	return false, false
}

// rulesRemoteEnabled data/rules.json 的 remote_enabled(只取这一个键)。
func rulesRemoteEnabled() (bool, bool) {
	b, err := os.ReadFile(natDataDir + "/rules.json")
	if err != nil {
		return false, false
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return false, false
	}
	v, ok := m["remote_enabled"].(bool)
	return v, ok
}

func addrsOf(ni *net.Interface) []net.IP {
	var out []net.IP
	addrs, err := netIfAddrsFn(ni)
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			out = append(out, ipn.IP)
		}
	}
	return out
}

// nativeUplinkOK 对应 shell ensure_tc_uplink_healthy(watchdog.sh:725)
// 的「判断」部分:
//   - 能力 uplink_supported 显式 false → false(调 shell 动作, 它带
//     watchdog_mark_uplink_unsupported_once / 清 fail_count 的副作用);
//   - ifb0 不存在 → false;
//   - ifb0 根 qdisc 不是 htb(nlroute) → false;
//   - 热点口 ingress 没有 mirred→ifb0 过滤器 → false。判断方式: Go 直接
//     exec `tc filter show dev <口> ingress`, 失败(魔改 tc 拒绝 ingress
//     关键字, ColorOS 坑)再试 `parent ffff:`; 输出含 "mirred" 且含
//     "ifb0"(grep -iE "mirred.*ifb0" 同义)才算有。
//     任一步执行失败(能力未知 / netlink / tc 都跑不动)→ unknown, 调用方
//     退回 shell。
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
	out, rc, _ := execCommandFn("tc", "filter", "show", "dev", iface, "ingress")
	if rc != 0 {
		out, rc, _ = execCommandFn("tc", "filter", "show", "dev", iface, "parent", "ffff:")
		if rc != 0 {
			return false, true
		}
	}
	low := strings.ToLower(out)
	if !strings.Contains(low, "mirred") || !strings.Contains(low, "ifb0") {
		return false, false
	}
	return true, false
}

// ── 对照机制(nativeShadow) ────────────────────────────────────────

const (
	nativeShadowEvery = 30 * time.Minute
	nativeMaxMismatch = 3 // 连续不一致 → 该项退回 shell 直到重启
)

// nativeCheckKind 参与对照的检查项。
type nativeCheckKind string

const (
	ncProbe   nativeCheckKind = "probe_hotspot"
	ncHealth  nativeCheckKind = "check_health"
	ncDrift   nativeCheckKind = "httpd_drift"
	ncUplink  nativeCheckKind = "tc_uplink_healthy"
	natShadow nativeCheckKind = "native_shadow" // 对照本身跑的 shell 动作名(记账用)
)

// nativeShadowState 每项检查的对照状态(主循环串行使用, 无锁竞争;
// 互斥锁只为未来并发留的防御)。
type nativeShadowState struct {
	mu          sync.Mutex
	lastRun     map[nativeCheckKind]time.Time
	mismatchRun map[nativeCheckKind]int  // 连续不一致次数
	reverted    map[nativeCheckKind]bool // 连续 3 次 → 退回 shell
}

func newNativeShadowState() *nativeShadowState {
	return &nativeShadowState{
		lastRun:     map[nativeCheckKind]time.Time{},
		mismatchRun: map[nativeCheckKind]int{},
		reverted:    map[nativeCheckKind]bool{},
	}
}

// due 到对照时间了(每 30 分钟), 且该项没有被退回。
func (s *nativeShadowState) due(k nativeCheckKind, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reverted[k] {
		return false
	}
	return now.Sub(s.lastRun[k]) >= nativeShadowEvery
}

// observe 汇报一次对照结果: agree=true 清零连续计数; 不一致 +1,
// 连续 ≥3 → reverted[k]=true(该项退回 shell 直到看门狗重启)。
func (s *nativeShadowState) observe(k nativeCheckKind, agree bool, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRun[k] = now
	if agree {
		s.mismatchRun[k] = 0
		return
	}
	s.mismatchRun[k]++
	if s.mismatchRun[k] >= nativeMaxMismatch {
		s.reverted[k] = true
		logf("native check %s: mismatched %d times in a row, reverting to shell until watchdog restart", k, nativeMaxMismatch)
	}
}

// isReverted 该项是否已退回 shell。
func (s *nativeShadowState) isReverted(k nativeCheckKind) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reverted[k]
}

// nativeMismatchTotal 对照机制累计不一致数(进 run/watchdog_actions.json
// 的 native_mismatch 计数; wdActionsFlush 时由 watchActionStatsExtra 带出)。
var nativeMismatchTotal int

// ── 健康检查的 5 秒缓存(照抄 shell _HEALTH_TS/_HEALTH_RC 语义) ─────
var (
	healthCacheMu    sync.Mutex
	healthCacheAt    time.Time
	healthCacheRC    int
	healthCacheIface string
)

// nativeCheckHealthCached 同一 (iface) 5 秒内重复调用直接用缓存结论
// (shell: `[ $((now - _HEALTH_TS)) -lt 5 ] && return $_HEALTH_RC`)。
func nativeCheckHealthCached(iface string, now time.Time) int {
	healthCacheMu.Lock()
	defer healthCacheMu.Unlock()
	if !healthCacheAt.IsZero() && healthCacheIface == iface && now.Sub(healthCacheAt) < 5*time.Second {
		return healthCacheRC
	}
	rc := nativeCheckHealth(iface)
	healthCacheAt, healthCacheRC, healthCacheIface = now, rc, iface
	return rc
}

// ── 对照与开关的入口(handleActive 调用) ─────────────────────────────

// natShadowSt 对照状态实例(主循环串行驱动)。
var natShadowSt = newNativeShadowState()

// natUse 该项当前是否走原生路径(总开关开着, 且该项没被对照机制钉回 shell)。
func natUse(k nativeCheckKind) bool {
	if !nativeEnabled() {
		return false
	}
	return !natShadowSt.isReverted(k)
}

// natShadowMaybeCompare check_health 的对照(每 30 分钟一次): 额外跑一次
// shell check_health 比结论(0/1/2)。不一致 → 本轮已用原生结论的按 shell
// 结论纠正(调用方 healthRC 不可变, 这里只记账 + 连续 3 次钉回 shell;
// 纠正语义: 立即跑 shell 的 full_restore 判定交给下一轮 —— 退回后自然走
// shell 路径, 最多延迟一轮 60 秒, 与「误判一次的代价」相当)。
func natShadowMaybeCompare(iface string, nativeRC int) {
	now := nowFn()
	if !natShadowSt.due(ncHealth, now) {
		return
	}
	res := runActionFn("check_health")
	agree := res.exitCode == nativeRC
	if !agree {
		nativeMismatchTotal++
		logf("native check_health mismatch: native=%d shell=%d (iface=%s) — trusting shell", nativeRC, res.exitCode, iface)
	}
	natShadowSt.observe(ncHealth, agree, now)
}

// natShadowProbe probe_hotspot 的对照(每 30 分钟一次): 原生结论与 shell
// 输出的 "<口> <IP>" 比。返回 agree=false 时 nativeMismatchTotal 已 +1。
func natShadowProbe(r nativeProbeResult) {
	now := nowFn()
	if !natShadowSt.due(ncProbe, now) {
		return
	}
	res := runActionFn("probe_hotspot")
	var agree bool
	if r.unknown {
		agree = res.exitCode != 0 // 原生判不了, shell 也判不了 → 一致(都「无效」)
	} else if r.ok {
		fields := strings.Fields(res.stdout)
		agree = res.exitCode == 0 && len(fields) >= 2 && fields[0] == r.iface && fields[1] == r.ip
	} else {
		agree = res.exitCode != 0
	}
	if !agree {
		nativeMismatchTotal++
		logf("native probe_hotspot mismatch: native(%q %q ok=%v) shell rc=%d out=%q — trusting shell", r.iface, r.ip, r.ok, res.exitCode, res.stdout)
	}
	natShadowSt.observe(ncProbe, agree, now)
}

// wdActionsSnapshotExtra actionstats.flush 之外带出的对照计数
// (run/watchdog_actions.json 顶层 native_mismatch 字段)。
var wdActionsSnapshotExtra = func() int { return nativeMismatchTotal }
