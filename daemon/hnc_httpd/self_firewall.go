// self_firewall.go — HNC v6.x 本机应用防火墙 (HNC_SELF_UID) 与本机域名级 DNS 拦截引擎 (HNC_SELF_DNS)。
//
// 核心工程与防自锁安全保证:
//   1. 持久化落盘 data/self_firewall.json: 0600 临时文件 + fsync + rename 原子提交, 零 run/ tmpfs 膨胀。
//   2. 64 位原子字段严格置于结构体 offset 0, 100% 兼容 32 位 armeabi-v7a (GOARCH=arm)。
//   3. 六道防自锁安全红线:
//      (a) 硬性拒绝 appId = uid % 100000 < 10000 (系统/root/radio/netd/wifi 及多用户/双开系统守护进程永不可封);
//      (b) 硬性保护 Root 管理器、系统 WebView 与宿主包名 (含 /data/system/packages.list 多用户 + SDK 沙盒双向 UID 反查);
//      (c) HNC_SELF_UID 子链第 1 条铁定放行 -o lo (本机访问 127.0.0.1 或本机局域网 IP 均经 table local 走 lo 放行, 杜绝公网 8080/8443 穿透);
//      (d) IPv4/IPv6 双栈一律在锁外通过内存管道调用 iptables-restore / ip6tables-restore -w 2 --noflush
//          (携带 hubSanitizedAndroidEnv()), 无规则时清空子链并摘除 OUTPUT 跳转钩子实现待机零规则开销;
//      (e) Android 13+ SDK Sandbox 协同封禁: appId 在 10000..19999 (含多用户/双开) 自动同步为 userId*100000 + appId + 10000 生成同等规则;
//      (f) HNC_SELF_DNS 仅在 filter/OUTPUT 匹配 UDP/TCP :53 标签长度前缀 hex (--algo bm --icase) 执行 -j DROP,
//          严禁使用 REJECT 污染 netd DNS 评分, 严禁拦截 :853 DoT, 严禁触碰 mangle 表或 0x0000ffff fwmark。

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

const (
	selfFirewallUIDChain         = "HNC_SELF_UID"
	selfFirewallDNSChain         = "HNC_SELF_DNS"
	selfFirewallPerUserRange     = 100000
	selfFirewallMinAppUID        = 10000
	selfFirewallIsolatedMinAppID = 90000
	selfFirewallMaxAppUID        = 99999999
	selfFirewallSandboxMinUID    = 10000
	selfFirewallSandboxMaxUID    = 19999
	selfFirewallSandboxOffset    = 10000
	selfFirewallMaxUIDRules      = 512
	selfFirewallMaxDomains       = 1000
	selfFirewallMaxTargets       = 64
	selfFirewallRestoreTimeout   = 3 * time.Second

	SelfFirewallModeAllow          = "allow"
	SelfFirewallModeBlockCleartext = "block_cleartext"
	SelfFirewallModeBlockCellular  = "block_cellular"
	SelfFirewallModeBlockAll       = "block_all"

	defaultAndroidPackagesListPath = "/data/system/packages.list"
)

var selfFirewallCleartextPorts = []int{80, 8080, 8000, 8008, 8888}

const selfFirewallCleartextPortCSV = "80,8080,8000,8008,8888"

var selfFirewallCellularIfaces = []string{
	"rmnet+",
	"ccmni+",
	"seth_w+",
	"clat4+",
	"v4-+",
}

// selfFirewallCellularVPNIfaces 仅在全表默认路由中 VPN 活跃且物理默认路由仅有蜂窝口(无非 AP Wi-Fi/有线/USB)时动态追加。
var selfFirewallCellularVPNIfaces = []string{
	"tun+",
	"Meta",
	"wg+",
	"utun+",
	"sing_tun+",
}

// selfFirewallProtectedPackages 硬性受保护的 Root 管理器、WebView 与宿主包名列表（排序稳定输出）。
var selfFirewallProtectedPackages = []string{
	"com.agy",
	"com.android.webview",
	"com.google.android.webview",
	"com.rifsxd.ksunext",
	"com.sukisu.ultra",
	"com.topjohnwu.magisk",
	"io.github.vvb2060.magisk",
	"me.bmax.apatch",
	"me.weishu.kernelsu",
}

var selfFirewallProtectedPkgSet = func() map[string]bool {
	m := make(map[string]bool, len(selfFirewallProtectedPackages))
	for _, p := range selfFirewallProtectedPackages {
		m[p] = true
	}
	return m
}()

// SelfFirewallUIDRule 单应用 UID 本机防火墙规则。
type SelfFirewallUIDRule struct {
	UID           int      `json:"uid"`
	SDKSandboxUID int      `json:"sdk_sandbox_uid,omitempty"`
	Pkg           string   `json:"pkg,omitempty"`
	AppName       string   `json:"app_name,omitempty"`
	DisplayName   string   `json:"display_name,omitempty"`
	Mode          string   `json:"mode"` // "allow"(with non-empty block_targets) | "block_cleartext" | "block_cellular" | "block_all"
	BlockTargets  []string `json:"block_targets,omitempty"`
	UpdatedAt     int64    `json:"updated_at"`
}

type selfFirewallPersistDoc struct {
	Version        int                   `json:"version"`
	UpdatedAt      int64                 `json:"updated_at"`
	UIDRules       []SelfFirewallUIDRule `json:"uid_rules"`
	BlockedDomains []string              `json:"blocked_domains"`
}

type selfFirewallGuardError struct {
	Decision leakBlockGuardDecision
	Domain   string
}

func (e *selfFirewallGuardError) Error() string {
	if e == nil {
		return "domain blocked by shared infrastructure guard"
	}
	if e.Decision.Detail != "" {
		return e.Decision.Detail
	}
	return "domain blocked by guard: " + e.Domain
}

type selfFirewallValidationError struct {
	Code   string // "bad params" | "protected_uid" | "protected_package"
	Detail string
}

func (e *selfFirewallValidationError) Error() string {
	if e == nil {
		return "invalid self firewall parameter"
	}
	return e.Detail
}

type selfFirewallRestoreFunc func(isIPv6 bool, payload string) error
type selfFirewallIptFunc func(isIPv6 bool, args ...string) (string, error)

type selfFirewallEngine struct {
	// 64 位原子字段严格连续置于结构体顶部 offset 0, 8 (兼容 32 位 GOARCH=arm)
	applyCommits atomic.Uint64
	guardRejects atomic.Uint64

	syncDirty        atomic.Bool
	srv              *server
	applyMu          sync.Mutex
	mu               sync.Mutex
	updatedAt        int64
	lastSyncErr      string
	lastSyncFailMono int64
	uidRules         map[int]SelfFirewallUIDRule
	blockedDomains   map[string]bool
	packagesListPath string
	forceDataplane   bool
	cellularVPNHook  func() bool
	restoreExec             selfFirewallRestoreFunc
	iptExec                 selfFirewallIptFunc
	resolveBin              func(string) string
	lastAppliedCellVPN      bool
	lastAppliedCellVPNKnown bool
	lastRouteCheckMono      int64
	reconcileInFlight       atomic.Bool
}

var selfFirewallWriteSeq atomic.Uint64

// writeSelfFirewallAtomic0600 使用 0600 临时文件 + fsync + rename 原子落盘 data/self_firewall.json。
func writeSelfFirewallAtomic0600(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	seq := selfFirewallWriteSeq.Add(1)
	tmp := fmt.Sprintf("%s.tmp.%d.%d", path, os.Getpid(), seq)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_ = f.Chmod(0o600)
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func newSelfFirewallEngine(s *server) *selfFirewallEngine {
	eng := &selfFirewallEngine{
		srv:              s,
		uidRules:         make(map[int]SelfFirewallUIDRule),
		blockedDomains:   make(map[string]bool),
		packagesListPath: defaultAndroidPackagesListPath,
		resolveBin:       resolveScalpelBin,
	}
	eng.restoreExec = eng.defaultPipeRestore
	eng.iptExec = eng.defaultIptExec
	hasActive := eng.loadFromDisk()

	if hasActive && s != nil && useNativeDataplane(s.hncDir) {
		eng.syncDirty.Store(true)
		_ = eng.syncDataplane()
	}
	return eng
}

func (e *selfFirewallEngine) persistPath() string {
	if e == nil || e.srv == nil || e.srv.hncDir == "" {
		return ""
	}
	return filepath.Join(e.srv.hncDir, "data", "self_firewall.json")
}

func splitSelfFirewallUID(uid int) (userID, appID int) {
	if uid < 0 {
		return -1, -1
	}
	return uid / selfFirewallPerUserRange, uid % selfFirewallPerUserRange
}

func isProtectedSelfFirewallSystemUID(uid int) bool {
	if uid < selfFirewallMinAppUID {
		return true
	}
	_, appID := splitSelfFirewallUID(uid)
	return appID < selfFirewallMinAppUID || appID >= selfFirewallIsolatedMinAppID
}

func stripSyntheticSelfFirewallPkg(raw string) string {
	p := strings.ToLower(strings.TrimSpace(raw))
	if strings.HasPrefix(p, "uid:") || strings.HasPrefix(p, "isolated:") {
		return ""
	}
	return p
}

func isPlaceholderSelfAppName(name, pkg string, uid int) bool {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return true
	}
	if pkg != "" && strings.EqualFold(trimmed, pkg) {
		return true
	}
	low := strings.ToLower(trimmed)
	if strings.HasPrefix(low, "uid:") || strings.HasPrefix(low, "uid ") || strings.HasPrefix(low, "isolated:") {
		return true
	}
	if uid > 0 && (low == fmt.Sprintf("本机应用 · uid %d", uid) || low == fmt.Sprintf("系统服务 (uid %d)", uid)) {
		return true
	}
	return false
}

func sdkSandboxUIDForApp(uid int) int {
	if uid < selfFirewallMinAppUID || uid > selfFirewallMaxAppUID {
		return 0
	}
	userID, appID := splitSelfFirewallUID(uid)
	if appID >= selfFirewallSandboxMinUID && appID <= selfFirewallSandboxMaxUID {
		sbUID := userID*selfFirewallPerUserRange + appID + selfFirewallSandboxOffset
		if sbUID <= selfFirewallMaxAppUID {
			return sbUID
		}
	}
	return 0
}

func isProtectedSelfFirewallPkg(pkg string) bool {
	p := strings.ToLower(strings.TrimSpace(pkg))
	if p == "" {
		return false
	}
	return selfFirewallProtectedPkgSet[p]
}

func sanitizeSelfFirewallText(s string, maxRunes int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if maxRunes <= 0 {
		maxRunes = 64
	}
	var b strings.Builder
	cnt := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
		cnt++
		if cnt >= maxRunes {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

func isValidAndroidPkgName(pkg string) bool {
	if len(pkg) == 0 || len(pkg) > 160 {
		return false
	}
	if strings.HasPrefix(pkg, ".") || strings.HasSuffix(pkg, ".") || strings.Contains(pkg, "..") {
		return false
	}
	hasDot := false
	for i := 0; i < len(pkg); i++ {
		c := pkg[i]
		if c == '.' {
			hasDot = true
			continue
		}
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return hasDot
}

// lookupPackagesByUIDFromPath 在无锁状态下扫描指定 packages.list 文件中与 UID（含多用户/分身及 SDK 沙盒对应宿主 appId）绑定的全部包名。
func lookupPackagesByUIDFromPath(pPath string, uid int) []string {
	if isProtectedSelfFirewallSystemUID(uid) {
		return nil
	}
	if pPath == "" {
		pPath = defaultAndroidPackagesListPath
	}
	f, err := os.Open(pPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	_, appID := splitSelfFirewallUID(uid)
	hostAppID := appID
	if appID >= selfFirewallSandboxMinUID+selfFirewallSandboxOffset && appID <= selfFirewallSandboxMaxUID+selfFirewallSandboxOffset {
		hostAppID = appID - selfFirewallSandboxOffset
	}

	seen := make(map[string]bool)
	var pkgs []string
	sc := bufio.NewScanner(io.LimitReader(f, 4<<20))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		pkg := strings.ToLower(strings.TrimSpace(fields[0]))
		parsedUID, err := strconv.Atoi(fields[1])
		if err != nil || parsedUID < 0 {
			continue
		}
		_, parsedAppID := splitSelfFirewallUID(parsedUID)
		if parsedUID == uid || parsedAppID == appID || parsedAppID == hostAppID {
			if pkg != "" && !seen[pkg] {
				seen[pkg] = true
				pkgs = append(pkgs, pkg)
			}
		}
	}
	sort.Strings(pkgs)
	return pkgs
}

// lookupPackagesByUIDFromSystem 反查 /data/system/packages.list 中与指定 UID（及多用户/沙盒对应宿主 appId）绑定的全部包名。
func (e *selfFirewallEngine) lookupPackagesByUIDFromSystem(uid int) []string {
	var pPath string
	if e != nil {
		e.mu.Lock()
		pPath = e.packagesListPath
		e.mu.Unlock()
	}
	return lookupPackagesByUIDFromPath(pPath, uid)
}

// resolveLocalAppMetadata 尝试从本机缓存、packages.list 与 hostConnLookupPkgLabel 补齐 UID 对应的包名与显示名。
func (e *selfFirewallEngine) resolveLocalAppMetadata(uid int, hintPkg, hintAppName string) (pkg, appName string, allPkgs []string) {
	pkg = stripSyntheticSelfFirewallPkg(hintPkg)
	appName = sanitizeSelfFirewallText(hintAppName, 64)

	sysPkgs := e.lookupPackagesByUIDFromSystem(uid)
	seen := make(map[string]bool, len(sysPkgs)+2)
	for _, sp := range sysPkgs {
		seen[sp] = true
		allPkgs = append(allPkgs, sp)
	}
	if pkg != "" && !seen[pkg] {
		seen[pkg] = true
		allPkgs = append(allPkgs, pkg)
	}

	var dpiName string
	hncDir := ""
	if e != nil && e.srv != nil {
		hncDir = e.srv.hncDir
	}
	if hncDir != "" {
		// 读取 run/dpi_state.json 中 self.apps_by_uid（含 display_name / app_name / label）补充包名与应用名
		if raw, err := os.ReadFile(filepath.Join(hncDir, "run", "dpi_state.json")); err == nil && len(raw) < 4<<20 {
			var doc struct {
				Self *struct {
					AppsByUID map[string]struct {
						Pkg         string   `json:"pkg"`
						Pkgs        []string `json:"pkgs"`
						DisplayName string   `json:"display_name"`
						AppName     string   `json:"app_name"`
						Label       string   `json:"label"`
					} `json:"apps_by_uid"`
				} `json:"self"`
			}
			if json.Unmarshal(raw, &doc) == nil && doc.Self != nil {
				_, appID := splitSelfFirewallUID(uid)
				lookupKeys := []string{strconv.Itoa(uid)}
				if appID >= selfFirewallSandboxMinUID+selfFirewallSandboxOffset && appID <= selfFirewallSandboxMaxUID+selfFirewallSandboxOffset {
					lookupKeys = append(lookupKeys, strconv.Itoa(uid-selfFirewallSandboxOffset), strconv.Itoa(appID-selfFirewallSandboxOffset))
				} else if appID != uid && appID >= selfFirewallMinAppUID {
					lookupKeys = append(lookupKeys, strconv.Itoa(appID))
				}
				for _, k := range lookupKeys {
					if ap, ok := doc.Self.AppsByUID[k]; ok {
						if p := stripSyntheticSelfFirewallPkg(ap.Pkg); p != "" && !seen[p] {
							seen[p] = true
							allPkgs = append(allPkgs, p)
						}
						for _, p := range ap.Pkgs {
							lp := stripSyntheticSelfFirewallPkg(p)
							if lp != "" && !seen[lp] {
								seen[lp] = true
								allPkgs = append(allPkgs, lp)
							}
						}
						if dpiName == "" {
							for _, cand := range []string{ap.DisplayName, ap.AppName, ap.Label} {
								if clean := sanitizeSelfFirewallText(cand, 64); clean != "" {
									dpiName = clean
									break
								}
							}
						}
					}
				}
			}
		}
	}

	if pkg == "" && len(sysPkgs) > 0 {
		pkg = sysPkgs[0]
	}
	if pkg == "" && len(allPkgs) > 0 {
		pkg = allPkgs[0]
	}

	if isPlaceholderSelfAppName(appName, pkg, uid) {
		if dpiName != "" && !isPlaceholderSelfAppName(dpiName, pkg, uid) {
			appName = dpiName
		} else if e != nil && e.srv != nil && pkg != "" {
			if ix := e.srv.loadAPKIndex(); len(ix.labels) > 0 {
				if lb := sanitizeSelfFirewallText(ix.labels[pkg], 64); lb != "" {
					appName = lb
				}
			}
		}
		if isPlaceholderSelfAppName(appName, pkg, uid) && pkg != "" {
			if lb := sanitizeSelfFirewallText(hostConnLookupPkgLabel(hncDir, pkg), 64); lb != "" && !strings.EqualFold(lb, pkg) {
				appName = lb
			} else if appName == "" && lb != "" {
				appName = lb
			}
		}
		if appName == "" && dpiName != "" {
			appName = dpiName
		}
	}
	return pkg, appName, allPkgs
}

type parsedSelfBlockTarget struct {
	Canonical string
	IP        string
	Port      int
	IsIPv6    bool
}

func checkSelfBlockForbiddenHostOrGatewayIP(canonIP string) string {
	if canonIP == "" {
		return ""
	}
	for _, ifi := range webuiListIfaces() {
		for _, ipn := range ifi.Addrs {
			if ipn == nil || ipn.IP == nil || ipn.IP.IsUnspecified() || ipn.IP.IsMulticast() {
				continue
			}
			var own string
			if v4 := ipn.IP.To4(); v4 != nil {
				own = v4.String()
			} else {
				own = ipn.IP.String()
			}
			if own == canonIP {
				return "host own IP (" + canonIP + ") cannot be added to block_targets"
			}
		}
	}
	if gwIPs := parseDefaultGatewayIPsFromProcRoute(blProcNetRoutePath); gwIPs[canonIP] {
		return "default gateway IP (" + canonIP + ") cannot be added to block_targets"
	}
	return ""
}

// parseAndValidateSelfBlockTarget 严格校验单个远端公网 IP 或 ip:port / [ipv6]:port 目标。
// 严禁将私网/回环/CGNAT、198.18.0.0/15 Fake-IP、本机/网关 IP、:53/:853/WebUI 端口、公共 DNS 或共享 CDN IP 塞入 block_targets。
func parseAndValidateSelfBlockTarget(raw string) (parsedSelfBlockTarget, error) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 128 {
		return parsedSelfBlockTarget{}, errors.New("empty or oversized block_target")
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return parsedSelfBlockTarget{}, errors.New("block_target contains invalid characters")
		}
	}
	if strings.Contains(s, "/") {
		return parsedSelfBlockTarget{}, errors.New("CIDR prefix is not allowed in block_targets (single IP or ip:port only)")
	}

	hostStr := s
	portNum := 0
	if strings.HasPrefix(s, "[") {
		if h, p, err := net.SplitHostPort(s); err == nil {
			n, perr := strconv.Atoi(p)
			if perr != nil || n < 1 || n > 65535 {
				return parsedSelfBlockTarget{}, errors.New("invalid port in block_target")
			}
			hostStr = h
			portNum = n
		} else if strings.HasSuffix(s, "]") {
			hostStr = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
		} else {
			return parsedSelfBlockTarget{}, errors.New("malformed bracketed IPv6 block_target")
		}
	} else if strings.Count(s, ":") == 1 {
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			return parsedSelfBlockTarget{}, errors.New("invalid ip:port block_target")
		}
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			return parsedSelfBlockTarget{}, errors.New("port must be 1..65535 in block_target")
		}
		hostStr = h
		portNum = n
	}

	addr, err := netip.ParseAddr(hostStr)
	if err != nil || addr.Zone() != "" {
		return parsedSelfBlockTarget{}, errors.New("block_target must be a valid literal IP or ip:port")
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return parsedSelfBlockTarget{}, errors.New("private, loopback, link-local, multicast, or unspecified IP cannot be blocked")
	}
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 0 || (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) {
			return parsedSelfBlockTarget{}, errors.New("reserved or broadcast IPv4 cannot be blocked")
		}
		if b[0] == 100 && (b[1]&0xc0) == 64 {
			return parsedSelfBlockTarget{}, errors.New("CGNAT 100.64.0.0/10 IP cannot be added to block_targets")
		}
		if b[0] == 198 && (b[1]&0xfe) == 18 {
			return parsedSelfBlockTarget{}, errors.New("proxy Fake-IP 198.18.0.0/15 cannot be added to block_targets")
		}
	}
	if portNum == 53 || portNum == 853 {
		return parsedSelfBlockTarget{}, errors.New("DNS/DoT port 53/853 cannot be blocked in block_targets")
	}
	if portNum == 8443 || portNum == 8444 || portNum == 8080 {
		return parsedSelfBlockTarget{}, errors.New("WebUI management port cannot be blocked")
	}
	canonIP := addr.String()
	if _, isPublicDNS := hardBlockPublicDNSIPs[canonIP]; isPublicDNS {
		return parsedSelfBlockTarget{}, errors.New("public DNS resolver IP cannot be blocked")
	}
	if reason := checkSelfBlockForbiddenHostOrGatewayIP(canonIP); reason != "" {
		return parsedSelfBlockTarget{}, errors.New(reason)
	}
	if shared, vendor := detectSharedInfraIP(nil, canonIP); shared {
		return parsedSelfBlockTarget{}, fmt.Errorf("shared CDN/cloud IP (%s) cannot be added to block_targets", vendor)
	}

	isV6 := addr.Is6()
	canon := canonIP
	if portNum > 0 {
		if isV6 {
			canon = fmt.Sprintf("[%s]:%d", canonIP, portNum)
		} else {
			canon = fmt.Sprintf("%s:%d", canonIP, portNum)
		}
	}
	return parsedSelfBlockTarget{
		Canonical: canon,
		IP:        canonIP,
		Port:      portNum,
		IsIPv6:    isV6,
	}, nil
}

func normalizeSelfBlockTargetsList(rawTargets []string) ([]string, error) {
	return normalizeSelfBlockTargetsListForServer(nil, rawTargets)
}

func normalizeSelfBlockTargetsListForServer(s *server, rawTargets []string) ([]string, error) {
	if len(rawTargets) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(rawTargets))
	out := make([]string, 0, len(rawTargets))
	for _, raw := range rawTargets {
		for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		}) {
			trimmed := strings.TrimSpace(tok)
			if trimmed == "" {
				continue
			}
			pt, err := parseAndValidateSelfBlockTarget(trimmed)
			if err != nil {
				return nil, err
			}
			if s != nil {
				if shared, vendor := detectSharedInfraIP(s, pt.IP); shared {
					return nil, fmt.Errorf("shared CDN/cloud IP (%s) cannot be added to block_targets", vendor)
				}
			}
			if !seen[pt.Canonical] {
				seen[pt.Canonical] = true
				out = append(out, pt.Canonical)
				if len(out) > selfFirewallMaxTargets {
					return nil, fmt.Errorf("too many block_targets (max %d)", selfFirewallMaxTargets)
				}
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func sanitizePersistedSelfBlockTargets(s *server, rawTargets []string) []string {
	if len(rawTargets) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(rawTargets))
	out := make([]string, 0, len(rawTargets))
	for _, raw := range rawTargets {
		for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		}) {
			trimmed := strings.TrimSpace(tok)
			if trimmed == "" {
				continue
			}
			pt, err := parseAndValidateSelfBlockTarget(trimmed)
			if err != nil {
				continue
			}
			if s != nil {
				if shared, _ := detectSharedInfraIP(s, pt.IP); shared {
					continue
				}
			}
			if !seen[pt.Canonical] {
				seen[pt.Canonical] = true
				out = append(out, pt.Canonical)
				if len(out) >= selfFirewallMaxTargets {
					break
				}
			}
		}
		if len(out) >= selfFirewallMaxTargets {
			break
		}
	}
	sort.Strings(out)
	return out
}

// normalizeSelfDNSBlockDomain 严格规范化并校验本机 DNS 拦截域名（禁止通配符、禁止单标签 TLD、禁止纯 IP）。
func normalizeSelfDNSBlockDomain(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(strings.ToLower(s), "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return "", errors.New("domain length must be 1..253 bytes")
	}
	if strings.ContainsAny(s, "* /\\:?#[]@!$&'()+,;=\"'\t\r\n") {
		return "", errors.New("domain contains forbidden characters or wildcards")
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", errors.New("HNC_SELF_DNS requires a domain name, not an IP literal")
	}
	if s == "localhost" || strings.HasSuffix(s, ".localhost") || strings.HasSuffix(s, ".local") {
		return "", errors.New("local hostname cannot be blocked in HNC_SELF_DNS")
	}
	if strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
		return "", errors.New("malformed domain labels")
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", errors.New("single-label TLD cannot be blocked")
	}
	allDigits := true
	for _, lab := range labels {
		if len(lab) < 1 || len(lab) > 63 {
			return "", errors.New("domain label length must be 1..63")
		}
		if lab[0] == '-' || lab[len(lab)-1] == '-' {
			return "", errors.New("domain label cannot start or end with '-'")
		}
		for i := 0; i < len(lab); i++ {
			c := lab[i]
			if c >= 'a' && c <= 'z' {
				allDigits = false
			} else if (c >= '0' && c <= '9') || c == '-' {
				if c == '-' {
					allDigits = false
				}
			} else {
				return "", errors.New("domain must contain only ASCII [a-z0-9.-]")
			}
		}
	}
	if allDigits {
		return "", errors.New("numeric IPv4 literal is not a valid domain")
	}
	return s, nil
}

// buildSelfDNSWireHex 编码与 HNC_CONNBLK_DNS 完全一致的 DNS QNAME 标签长度前缀 hex (如 "|03|ads|07|example|03|com|00|")。
func buildSelfDNSWireHex(domain string) (string, bool) {
	norm, err := normalizeSelfDNSBlockDomain(domain)
	if err != nil {
		return "", false
	}
	labels := strings.Split(norm, ".")
	var b strings.Builder
	for _, lab := range labels {
		if len(lab) < 1 || len(lab) > 63 {
			return "", false
		}
		fmt.Fprintf(&b, "|%02x|%s", len(lab), lab)
	}
	b.WriteString("|00|")
	return b.String(), true
}

func isValidSelfFirewallMode(mode string) bool {
	switch mode {
	case SelfFirewallModeAllow, SelfFirewallModeBlockCleartext, SelfFirewallModeBlockCellular, SelfFirewallModeBlockAll:
		return true
	default:
		return false
	}
}

// loadFromDisk 在 e.mu 锁外完成持久化文件读取、JSON 反序列化与 packages.list 受保护包名校验,
// 最后短锁瞬间替换内存规则集, 彻底消除锁重入自死锁与持锁磁盘 I/O。
func (e *selfFirewallEngine) loadFromDisk() bool {
	if e == nil {
		return false
	}
	p := e.persistPath()
	hncDir := e.srvHncDir()
	e.mu.Lock()
	pPath := e.packagesListPath
	e.mu.Unlock()

	newUIDRules := make(map[int]SelfFirewallUIDRule)
	newBlockedDomains := make(map[string]bool)
	var newUpdatedAt int64

	if p != "" {
		if b, err := os.ReadFile(p); err == nil && len(bytes.TrimSpace(b)) > 0 {
			var rawDoc struct {
				UpdatedAt      int64                 `json:"updated_at"`
				UIDRules       []SelfFirewallUIDRule `json:"uid_rules"`
				BlockedDomains json.RawMessage       `json:"blocked_domains"`
			}
			if json.Unmarshal(b, &rawDoc) == nil {
				newUpdatedAt = rawDoc.UpdatedAt
				for _, r := range rawDoc.UIDRules {
					if isProtectedSelfFirewallSystemUID(r.UID) || r.UID > selfFirewallMaxAppUID {
						continue
					}
					mode := strings.ToLower(strings.TrimSpace(r.Mode))
					if mode == "" || !isValidSelfFirewallMode(mode) {
						continue
					}
					pkg := stripSyntheticSelfFirewallPkg(r.Pkg)
					if isProtectedSelfFirewallPkg(pkg) {
						continue
					}
					blockedBySys := false
					for _, sp := range lookupPackagesByUIDFromPath(pPath, r.UID) {
						if isProtectedSelfFirewallPkg(sp) {
							blockedBySys = true
							break
						}
					}
					if blockedBySys {
						continue
					}
					targets := sanitizePersistedSelfBlockTargets(e.srv, r.BlockTargets)
					if mode == SelfFirewallModeAllow && len(targets) == 0 {
						continue
					}
					r.Pkg = pkg
					r.AppName = sanitizeSelfFirewallText(r.AppName, 64)
					r.Mode = mode
					r.BlockTargets = targets
					r.SDKSandboxUID = sdkSandboxUIDForApp(r.UID)
					newUIDRules[r.UID] = r
					if len(newUIDRules) >= selfFirewallMaxUIDRules {
						break
					}
				}

				if len(rawDoc.BlockedDomains) > 0 {
					var strDomains []string
					if json.Unmarshal(rawDoc.BlockedDomains, &strDomains) == nil {
						for _, d := range strDomains {
							if nd, err := normalizeSelfDNSBlockDomain(d); err == nil {
								if dec := evaluateLeakBlockDomainGuard(hncDir, nd); dec.Level != leakGuardLevelHardBlock {
									newBlockedDomains[nd] = true
								}
							}
							if len(newBlockedDomains) >= selfFirewallMaxDomains {
								break
							}
						}
					} else {
						var objDomains []struct {
							Domain string `json:"domain"`
						}
						if json.Unmarshal(rawDoc.BlockedDomains, &objDomains) == nil {
							for _, item := range objDomains {
								if nd, err := normalizeSelfDNSBlockDomain(item.Domain); err == nil {
									if dec := evaluateLeakBlockDomainGuard(hncDir, nd); dec.Level != leakGuardLevelHardBlock {
										newBlockedDomains[nd] = true
									}
								}
								if len(newBlockedDomains) >= selfFirewallMaxDomains {
									break
								}
							}
						}
					}
				}
			}
		}
	}

	e.mu.Lock()
	e.uidRules = newUIDRules
	e.blockedDomains = newBlockedDomains
	e.updatedAt = newUpdatedAt
	hasActive := len(e.uidRules) > 0 || len(e.blockedDomains) > 0
	e.mu.Unlock()
	return hasActive
}

func (e *selfFirewallEngine) srvHncDir() string {
	if e != nil && e.srv != nil {
		return e.srv.hncDir
	}
	return ""
}

func (e *selfFirewallEngine) sortedSnapshotLocked() ([]SelfFirewallUIDRule, []string, int64) {
	rules := make([]SelfFirewallUIDRule, 0, len(e.uidRules))
	for _, r := range e.uidRules {
		cp := r
		if len(r.BlockTargets) > 0 {
			cp.BlockTargets = append([]string(nil), r.BlockTargets...)
		}
		cp.SDKSandboxUID = sdkSandboxUIDForApp(cp.UID)
		rules = append(rules, cp)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].UID < rules[j].UID
	})

	domains := make([]string, 0, len(e.blockedDomains))
	for d, active := range e.blockedDomains {
		if active && d != "" {
			domains = append(domains, d)
		}
	}
	sort.Strings(domains)
	return rules, domains, e.updatedAt
}

func (e *selfFirewallEngine) saveLocked(now int64) error {
	p := e.persistPath()
	if p == "" {
		return nil
	}
	if now <= 0 {
		now = time.Now().Unix()
	}
	e.updatedAt = now
	rules, domains, _ := e.sortedSnapshotLocked()
	doc := selfFirewallPersistDoc{
		Version:        1,
		UpdatedAt:      now,
		UIDRules:       rules,
		BlockedDomains: domains,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return writeSelfFirewallAtomic0600(p, b)
}

// ReloadFromDisk 在整机恢复或外部同步后重载 data/self_firewall.json 并刷新双栈子链。
func (e *selfFirewallEngine) ReloadFromDisk() {
	if e == nil {
		return
	}
	_ = e.loadFromDisk()
	e.syncDirty.Store(true)
	_ = e.syncDataplane()
}

// IsSyncDirty 返回数据面是否存在尚未成功同步至内核双栈链的脏状态。
func (e *selfFirewallEngine) IsSyncDirty() bool {
	if e == nil {
		return false
	}
	return e.syncDirty.Load()
}

// SyncIfDirty 当存在脏标记时执行一次内核双栈对账补偿同步。
func (e *selfFirewallEngine) SyncIfDirty() error {
	if e == nil || !e.syncDirty.Load() {
		return nil
	}
	return e.syncDataplane()
}

// SyncIfDirtyAfterCooldown 在存在脏标记且距上次失败已满 minCooldown 时执行后台补偿重试。
func (e *selfFirewallEngine) SyncIfDirtyAfterCooldown(minCooldown time.Duration) error {
	if e == nil || !e.syncDirty.Load() {
		return nil
	}
	if minCooldown > 0 {
		e.mu.Lock()
		lastFail := e.lastSyncFailMono
		e.mu.Unlock()
		if lastFail > 0 && monoNowNs()-lastFail < int64(minCooldown) {
			return nil
		}
	}
	return e.syncDataplane()
}

// ── 双栈 iptables-restore / ip6tables-restore 规则载荷纯函数构造器 ────────────

// evalCellularOnlyVPNFromRoutes 评估当前全表默认路由是否满足:
//  1) 存在活跃 VPN 默认路由接口 (tun*/Meta/wg*/utun*/sing_tun* 等);
//  2) 底层物理默认路由仅含蜂窝口 (rmnet*/ccmni*/seth_*/sipa_eth*/wwan*/clat4*);
//  3) 无任何非热点 AP 的 Wi-Fi / 有线 / USB 上游默认路由 (wlan*/eth*/usb*/rndis*/ncm*)。
// 仅在三者同时成立时返回 true, 彻底杜绝连 Wi-Fi 开 FlClash/VPN 时误断网!
func evalCellularOnlyVPNFromRoutes(defaultRouteDevs []string, activeIfaces map[string]bool, apIface string) bool {
	if len(defaultRouteDevs) == 0 {
		return false
	}
	apIface = strings.TrimSpace(apIface)
	hasVPN := false
	hasCellular := false
	hasNonAPWifiOrWired := false

	for _, rawDev := range defaultRouteDevs {
		dev := strings.TrimSpace(rawDev)
		if dev == "" || dev == "lo" {
			continue
		}
		if activeIfaces != nil && !activeIfaces[dev] {
			continue
		}
		if isVPNIface(dev) {
			hasVPN = true
			continue
		}
		phys := strings.TrimPrefix(dev, "v4-")
		phys = strings.TrimPrefix(phys, "clat4-")
		if (apIface != "" && (dev == apIface || phys == apIface)) || isAPIfaceName(dev) || isAPIfaceName(phys) {
			continue
		}
		switch {
		case isCellIface(phys) ||
			strings.HasPrefix(phys, "rmnet") ||
			strings.HasPrefix(phys, "ccmni") ||
			strings.HasPrefix(phys, "seth_") ||
			strings.HasPrefix(phys, "sipa_eth") ||
			strings.HasPrefix(phys, "wwan") ||
			strings.HasPrefix(dev, "clat4"):
			hasCellular = true
		case strings.HasPrefix(phys, "wlan") ||
			strings.HasPrefix(phys, "eth") ||
			strings.HasPrefix(phys, "usb") ||
			strings.HasPrefix(phys, "rndis") ||
			strings.HasPrefix(phys, "ncm") ||
			strings.HasPrefix(phys, "enx"):
			hasNonAPWifiOrWired = true
		}
	}
	return hasVPN && hasCellular && !hasNonAPWifiOrWired
}

func selfFirewallDetectActiveHotspotIface(hncDir string) string {
	hncDir = strings.TrimSpace(hncDir)
	if hncDir == "" {
		return ""
	}
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "hnc_state")); err == nil {
		st := strings.TrimSpace(string(b))
		if strings.HasPrefix(st, "ACTIVE:") {
			if ifc := strings.TrimSpace(strings.TrimPrefix(st, "ACTIVE:")); isValidHotspotIfaceName(ifc) {
				return ifc
			}
		}
	}
	_, authIfc := v6ReadIfaceDetectDefaultWANs(hncDir)
	return authIfc
}

func selfFirewallIsCellularOnlyVPNActive(hncDir string) bool {
	ifs, err := v6LiveInterfacesFn()
	if err != nil || len(ifs) == 0 {
		return false
	}
	activeIfaces := make(map[string]bool, len(ifs))
	byIdx := make(map[int]string, len(ifs))
	seenDev := make(map[string]bool, 8)
	var defaultDevs []string
	addDev := func(name string) {
		name = strings.TrimSpace(name)
		if name != "" && !seenDev[name] {
			seenDev[name] = true
			defaultDevs = append(defaultDevs, name)
		}
	}

	for _, ifi := range ifs {
		name := strings.TrimSpace(ifi.Name)
		if name == "" {
			continue
		}
		byIdx[ifi.Index] = name
		if (ifi.Flags & net.FlagUp) != 0 {
			activeIfaces[name] = true
			// Clash Meta / OpenVPN 常使用 0.0.0.0/1 + 128.0.0.0/1 (prefixLen=1) 劫持全局流量:
			// 只要 VPN 虚拟网卡处于 UP 且已配置单播地址, 即视为活跃 VPN 隧道候选。
			if isVPNIface(name) {
				if addrs, aerr := ifi.Addrs(); aerr == nil && len(addrs) > 0 {
					addDev(name)
				}
			}
		}
	}

	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		for idx, ln := range strings.Split(string(b), "\n") {
			if idx == 0 {
				continue
			}
			fs := strings.Fields(ln)
			if len(fs) >= 8 && fs[1] == "00000000" && fs[7] == "00000000" {
				if flags, ferr := strconv.ParseUint(fs[3], 16, 32); ferr == nil && (flags&0x1) != 0 {
					addDev(fs[0])
				}
			}
		}
	}
	if b6, err := os.ReadFile("/proc/net/ipv6_route"); err == nil {
		for _, ln := range strings.Split(string(b6), "\n") {
			fs := strings.Fields(ln)
			// dest_net(0) dest_prefix(1) ... flags(8) dev(9)
			if len(fs) >= 10 && fs[0] == "00000000000000000000000000000000" && fs[1] == "00" {
				if flags, ferr := strconv.ParseUint(fs[8], 16, 32); ferr == nil && (flags&0x1) != 0 && (flags&0x00200000) == 0 {
					addDev(fs[9])
				}
			}
		}
	}
	if v6DumpDefaultRouteIfindexesFn != nil {
		if idxMap, nerr := v6DumpDefaultRouteIfindexesFn(); nerr == nil {
			for idx := range idxMap {
				if nm := byIdx[idx]; nm != "" {
					addDev(nm)
				}
			}
		}
	}
	if hncDir != "" {
		detWANs, _ := v6ReadIfaceDetectDefaultWANs(hncDir)
		for k := range detWANs {
			addDev(k)
		}
	}

	apIface := selfFirewallDetectActiveHotspotIface(hncDir)
	return evalCellularOnlyVPNFromRoutes(defaultDevs, activeIfaces, apIface)
}

func (e *selfFirewallEngine) shouldBlockCellularVPN() bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	hook := e.cellularVPNHook
	forced := e.forceDataplane
	e.mu.Unlock()
	if hook != nil {
		return hook()
	}
	if forced {
		return false
	}
	return selfFirewallIsCellularOnlyVPNActive(e.srvHncDir())
}

// buildSelfUIDRestorePayload 生成 *filter 表 HNC_SELF_UID 子链的 --noflush 载荷。
// 当 rules 非空时, 链首第 1 条铁定且仅放行 -o lo (本机 127.0.0.1 及本机局域网 IP 均经内核 table local 走 lo, 严禁无目的 IP 豁免 8080/8443)。
func buildSelfUIDRestorePayload(isIPv6 bool, rules []SelfFirewallUIDRule) (payload string, ruleCount int) {
	return buildSelfUIDRestorePayloadWithOpts(isIPv6, rules, false)
}

func buildSelfUIDRestorePayloadWithOpts(isIPv6 bool, rules []SelfFirewallUIDRule, blockCellVPN bool) (payload string, ruleCount int) {
	var b strings.Builder
	b.WriteString("*filter\n")
	b.WriteString(":" + selfFirewallUIDChain + " - [0:0]\n")
	if len(rules) == 0 {
		b.WriteString("COMMIT\n")
		return b.String(), 0
	}

	// 防自锁铁律第 3 道红线: 链首恒定放行 loopback, 严禁无地址限制放行 8443/8444/8080 导致公网明文/HTTPS 穿透
	fmt.Fprintf(&b, "-A %s -o lo -j RETURN\n", selfFirewallUIDChain)
	ruleCount++

	explicitUIDSet := make(map[int]bool, len(rules))
	for _, r := range rules {
		explicitUIDSet[r.UID] = true
	}

	var bodyBuf strings.Builder
	bodyRuleCnt := 0

	emitForUID := func(u int, r SelfFirewallUIDRule) {
		for _, rawTgt := range r.BlockTargets {
			pt, err := parseAndValidateSelfBlockTarget(rawTgt)
			if err != nil || pt.IsIPv6 != isIPv6 {
				continue
			}
			if pt.Port > 0 {
				fmt.Fprintf(&bodyBuf, "-A %s -d %s -p tcp --dport %d -m owner --uid-owner %d -j REJECT --reject-with tcp-reset\n",
					selfFirewallUIDChain, pt.IP, pt.Port, u)
				fmt.Fprintf(&bodyBuf, "-A %s -d %s -p udp --dport %d -m owner --uid-owner %d -j REJECT\n",
					selfFirewallUIDChain, pt.IP, pt.Port, u)
				bodyRuleCnt += 2
			} else {
				fmt.Fprintf(&bodyBuf, "-A %s -d %s -m owner --uid-owner %d -j REJECT\n",
					selfFirewallUIDChain, pt.IP, u)
				bodyRuleCnt++
			}
		}

		switch r.Mode {
		case SelfFirewallModeBlockCleartext:
			// 仅拦截明文 HTTP 端口 80,8080,8000,8008,8888, 100% 保留 :443 HTTPS 正常使用
			fmt.Fprintf(&bodyBuf, "-A %s -p tcp -m multiport --dports %s -m owner --uid-owner %d -j REJECT --reject-with tcp-reset\n",
				selfFirewallUIDChain, selfFirewallCleartextPortCSV, u)
			bodyRuleCnt++
		case SelfFirewallModeBlockCellular:
			for _, ifc := range selfFirewallCellularIfaces {
				fmt.Fprintf(&bodyBuf, "-A %s -o %s -m owner --uid-owner %d -j REJECT\n",
					selfFirewallUIDChain, ifc, u)
				bodyRuleCnt++
			}
			if blockCellVPN {
				for _, vIfc := range selfFirewallCellularVPNIfaces {
					fmt.Fprintf(&bodyBuf, "-A %s -o %s -m owner --uid-owner %d -j REJECT\n",
						selfFirewallUIDChain, vIfc, u)
					bodyRuleCnt++
				}
			}
		case SelfFirewallModeBlockAll:
			fmt.Fprintf(&bodyBuf, "-A %s -m owner --uid-owner %d -j REJECT\n",
				selfFirewallUIDChain, u)
			bodyRuleCnt++
		}
	}

	for _, r := range rules {
		if isProtectedSelfFirewallSystemUID(r.UID) || r.UID > selfFirewallMaxAppUID {
			continue
		}
		emitForUID(r.UID, r)
		// Android 13+ SDK Sandbox 协同封禁: appId 在 10000..19999 (含双开 userId*100000) 自动为 +10000 生成同等规则
		if sbUID := sdkSandboxUIDForApp(r.UID); sbUID > 0 && !explicitUIDSet[sbUID] {
			emitForUID(sbUID, r)
		}
	}

	b.WriteString(bodyBuf.String())
	ruleCount += bodyRuleCnt
	b.WriteString("COMMIT\n")
	return b.String(), ruleCount
}

// buildSelfDNSRestorePayload 生成 *filter 表 HNC_SELF_DNS 子链的 --noflush 载荷。
// 严格仅匹配 UDP/TCP :53 的标签长度前缀 hex (--algo bm --icase) 并执行 -j DROP, 零 REJECT, 零 :853 DoT, 零 mangle。
func buildSelfDNSRestorePayload(domains []string) (payload string, ruleCount int) {
	var b strings.Builder
	b.WriteString("*filter\n")
	b.WriteString(":" + selfFirewallDNSChain + " - [0:0]\n")
	for _, dom := range domains {
		hexStr, ok := buildSelfDNSWireHex(dom)
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "-A %s -p udp --dport 53 -m string --algo bm --icase --hex-string \"%s\" -j DROP\n",
			selfFirewallDNSChain, hexStr)
		fmt.Fprintf(&b, "-A %s -p tcp --dport 53 -m string --algo bm --icase --hex-string \"%s\" -j DROP\n",
			selfFirewallDNSChain, hexStr)
		ruleCount += 2
	}
	b.WriteString("COMMIT\n")
	return b.String(), ruleCount
}

// ── 锁外双栈内存管道提交与空规则零开销拆链 ──────────────────────────────────

func (e *selfFirewallEngine) shouldRunDataplane() bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	forced := e.forceDataplane
	e.mu.Unlock()
	if forced {
		return true
	}
	return e.srv != nil && useNativeDataplane(e.srv.hncDir)
}

func runPipeRestoreSanitizedOnce(binPath string, args []string, payload string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, binPath, args...))
	cmd.Env = hubSanitizedAndroidEnv()
	cmd.Stdin = strings.NewReader(payload)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%s timed out after %v: %w", filepath.Base(binPath), timeout, ctx.Err())
		}
		return fmt.Errorf("%s %v failed: %w (%s)", filepath.Base(binPath), args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (e *selfFirewallEngine) defaultPipeRestore(isIPv6 bool, payload string) error {
	binName := "iptables-restore"
	if isIPv6 {
		binName = "ip6tables-restore"
	}
	resolver := e.resolveBin
	if resolver == nil {
		resolver = resolveScalpelBin
	}
	binPath := resolver(binName)
	if binPath == "" {
		if isIPv6 {
			return nil
		}
		return fmt.Errorf("%s not found", binName)
	}

	runWaitFallback := func(data string) error {
		err1 := runPipeRestoreSanitizedOnce(binPath, []string{"-w", "2", "--noflush"}, data, selfFirewallRestoreTimeout)
		if err1 == nil {
			return nil
		}
		if isXtablesWaitFlagError(err1.Error()) {
			err2 := runPipeRestoreSanitizedOnce(binPath, []string{"-w", "--noflush"}, data, selfFirewallRestoreTimeout)
			if err2 == nil {
				return nil
			}
			if isXtablesWaitFlagError(err2.Error()) {
				return runPipeRestoreSanitizedOnce(binPath, []string{"--noflush"}, data, selfFirewallRestoreTimeout)
			}
			return err2
		}
		return err1
	}

	err := runWaitFallback(payload)
	if err == nil {
		return nil
	}
	// HNC_SELF_UID 在裁剪 ipt_REJECT / ip6t_REJECT 模块的内核上安全降级为 -j DROP (HNC_SELF_DNS 原本即为 DROP)
	if strings.Contains(payload, "REJECT") && isIptablesRejectMissingError(err.Error()) {
		dropPayload := replaceRejectWithDropInRestorePayload(payload)
		if dropPayload != payload {
			if derr := runWaitFallback(dropPayload); derr == nil {
				return nil
			}
		}
	}
	return err
}

func (e *selfFirewallEngine) defaultIptExec(isIPv6 bool, args ...string) (string, error) {
	binName := "iptables"
	if isIPv6 {
		binName = "ip6tables"
	}
	resolver := e.resolveBin
	if resolver == nil {
		resolver = resolveScalpelBin
	}
	binPath := resolver(binName)
	if binPath == "" {
		return "", fmt.Errorf("%s not found", binName)
	}
	execOnce := func(fullArgs []string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cmd := hardenCmd(exec.CommandContext(ctx, binPath, fullArgs...))
		cmd.Env = hubSanitizedAndroidEnv()
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		return buf.String(), err
	}
	out1, err1 := execOnce(append([]string{"-w", "2"}, args...))
	if err1 == nil {
		return out1, nil
	}
	if isXtablesWaitFlagError(out1 + " " + err1.Error()) {
		out2, err2 := execOnce(append([]string{"-w"}, args...))
		if err2 == nil {
			return out2, nil
		}
		if isXtablesWaitFlagError(out2 + " " + err2.Error()) {
			return execOnce(args)
		}
		return out2, err2
	}
	return out1, err1
}

func (e *selfFirewallEngine) ensureOutputHookOutsideLock(iptFn selfFirewallIptFunc, isIPv6 bool, chain string) error {
	if iptFn == nil {
		return nil
	}
	if _, err := iptFn(isIPv6, "-t", "filter", "-C", "OUTPUT", "-j", chain); err == nil {
		return nil
	}
	_, _ = iptFn(isIPv6, "-t", "filter", "-N", chain)
	out, err := iptFn(isIPv6, "-t", "filter", "-I", "OUTPUT", "1", "-j", chain)
	if err != nil {
		return fmt.Errorf("insert OUTPUT -> %s failed: %w (%s)", chain, err, strings.TrimSpace(out))
	}
	return nil
}

func (e *selfFirewallEngine) detachAndRemoveChainOutsideLock(iptFn selfFirewallIptFunc, restoreFn selfFirewallRestoreFunc, isIPv6 bool, chain string) {
	if iptFn != nil {
		for i := 0; i < 16; i++ {
			if _, err := iptFn(isIPv6, "-t", "filter", "-D", "OUTPUT", "-j", chain); err != nil {
				break
			}
		}
		_, _ = iptFn(isIPv6, "-t", "filter", "-F", chain)
		_, _ = iptFn(isIPv6, "-t", "filter", "-X", chain)
		return
	}
	if restoreFn != nil {
		emptyPayload := "*filter\n:" + chain + " - [0:0]\nCOMMIT\n"
		_ = restoreFn(isIPv6, emptyPayload)
	}
}

func isSelfDNSXtStringUnsupported(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "string") ||
		strings.Contains(msg, "xt_string") ||
		strings.Contains(msg, "ipt_string") ||
		strings.Contains(msg, "ip6t_string")
}

func isSelfFirewallIPv6Unsupported(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "ip6tables not found") || strings.Contains(msg, "ip6tables-restore not found") {
		return true
	}
	if strings.Contains(msg, "address family not supported") || strings.Contains(msg, "eafnosupport") {
		return true
	}
	if strings.Contains(msg, "can't initialize ip6tables table") ||
		strings.Contains(msg, "table 'filter' does not exist") ||
		strings.Contains(msg, "table `filter' does not exist") ||
		strings.Contains(msg, "ip6table_filter") {
		return true
	}
	if strings.Contains(msg, "ip6_tables") && (strings.Contains(msg, "does not exist") || strings.Contains(msg, "no such file") || strings.Contains(msg, "not found")) {
		return true
	}
	return false
}

// syncDataplane 在锁外串行执行 IPv4 / IPv6 双栈内存管道原子提交与空规则拆链,
// 严格核验 HNC_SELF_UID 与 HNC_SELF_DNS 双栈挂载结果并维护 syncDirty 重试标志
// (保留裁剪内核缺 xt_string 或无 IPv6 filter 表的降级容错, 且绝不回滚已成功的 IPv4 规则)。
func (e *selfFirewallEngine) syncDataplane() error {
	if e == nil {
		return nil
	}
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	if !e.shouldRunDataplane() {
		e.syncDirty.Store(false)
		e.mu.Lock()
		e.lastSyncErr = ""
		e.mu.Unlock()
		return nil
	}

	e.mu.Lock()
	rules, domains, _ := e.sortedSnapshotLocked()
	restoreFn := e.restoreExec
	iptFn := e.iptExec
	e.mu.Unlock()

	hasUID := len(rules) > 0
	hasDNS := len(domains) > 0
	hasCellularRule := false
	for _, r := range rules {
		if r.Mode == SelfFirewallModeBlockCellular {
			hasCellularRule = true
			break
		}
	}
	blockCellVPN := false
	if hasUID && hasCellularRule {
		blockCellVPN = e.shouldBlockCellularVPN()
	}

	var syncErr error
	recordErr := func(isV6 bool, stage string, err error) {
		if err == nil {
			return
		}
		if isV6 && isSelfFirewallIPv6Unsupported(err) {
			return
		}
		fam := "ipv4"
		if isV6 {
			fam = "ipv6"
		}
		wrapped := fmt.Errorf("%s %s: %w", fam, stage, err)
		if syncErr == nil {
			syncErr = wrapped
		} else {
			syncErr = fmt.Errorf("%v; %w", syncErr, wrapped)
		}
	}

	for _, isV6 := range []bool{false, true} {
		// 1) HNC_SELF_UID 子链同步或零开销拆链
		if hasUID {
			uidPayload, _ := buildSelfUIDRestorePayloadWithOpts(isV6, rules, blockCellVPN)
			var rerr error
			if restoreFn != nil {
				rerr = restoreFn(isV6, uidPayload)
			}
			if rerr != nil {
				recordErr(isV6, "restore HNC_SELF_UID", rerr)
			} else {
				herr := e.ensureOutputHookOutsideLock(iptFn, isV6, selfFirewallUIDChain)
				if herr != nil {
					recordErr(isV6, "hook HNC_SELF_UID", herr)
				}
			}
		} else {
			e.detachAndRemoveChainOutsideLock(iptFn, restoreFn, isV6, selfFirewallUIDChain)
		}

		// 2) HNC_SELF_DNS 子链同步或零开销拆链（独立提交避免裁剪 xt_string 内核连坐回滚 HNC_SELF_UID）
		if hasDNS {
			dnsPayload, _ := buildSelfDNSRestorePayload(domains)
			var derr error
			if restoreFn != nil {
				derr = restoreFn(isV6, dnsPayload)
			}
			if derr == nil {
				herr := e.ensureOutputHookOutsideLock(iptFn, isV6, selfFirewallDNSChain)
				if herr != nil {
					recordErr(isV6, "hook HNC_SELF_DNS", herr)
				}
			} else if isSelfDNSXtStringUnsupported(derr) || (isV6 && isSelfFirewallIPv6Unsupported(derr)) {
				// 裁剪内核无 xt_string 或无 IPv6 filter 表时优雅降级保留配置并保护已成功的 UID/IPv4 链
				e.detachAndRemoveChainOutsideLock(iptFn, nil, isV6, selfFirewallDNSChain)
			} else {
				recordErr(isV6, "restore HNC_SELF_DNS", derr)
			}
		} else {
			e.detachAndRemoveChainOutsideLock(iptFn, restoreFn, isV6, selfFirewallDNSChain)
		}
	}

	if syncErr != nil {
		e.syncDirty.Store(true)
		e.mu.Lock()
		e.lastSyncErr = syncErr.Error()
		e.lastSyncFailMono = monoNowNs()
		e.mu.Unlock()
		return syncErr
	}

	e.syncDirty.Store(false)
	e.mu.Lock()
	e.lastSyncErr = ""
	e.lastSyncFailMono = 0
	if hasUID && hasCellularRule {
		e.lastAppliedCellVPN = blockCellVPN
		e.lastAppliedCellVPNKnown = true
	} else {
		e.lastAppliedCellVPN = false
		e.lastAppliedCellVPNKnown = false
	}
	e.lastRouteCheckMono = monoNowNs()
	e.mu.Unlock()
	e.applyCommits.Add(1)
	return nil
}

// CheckNetworkFlipAndSync 当存在 block_cellular 规则且上游网络类型(Wi-Fi <-> 蜂窝)或 VPN 状态导致
// cellular-only VPN 拦截条件发生翻转时, 按需重同步双栈 HNC_SELF_UID 子链; 无翻转时零子进程开销。
func (e *selfFirewallEngine) CheckNetworkFlipAndSync() (bool, error) {
	if e == nil || !e.shouldRunDataplane() {
		return false, nil
	}
	e.mu.Lock()
	hasCellularRule := false
	for _, r := range e.uidRules {
		if r.Mode == SelfFirewallModeBlockCellular {
			hasCellularRule = true
			break
		}
	}
	prevVal := e.lastAppliedCellVPN
	prevKnown := e.lastAppliedCellVPNKnown
	e.mu.Unlock()
	if !hasCellularRule {
		return false, nil
	}
	curVal := e.shouldBlockCellularVPN()
	if prevKnown && curVal == prevVal {
		return false, nil
	}
	e.syncDirty.Store(true)
	err := e.syncDataplane()
	return err == nil, err
}

// ReconcileIfNeeded 执行 SyncIfDirty 冷却补偿与 block_cellular 切网/VPN 翻转按需重同步。
// 铁律: 无脏标记且无 block_cellular 规则时立即返回; 熄屏且无脏标记时严禁无变化高频探测空转。
func (e *selfFirewallEngine) ReconcileIfNeeded(minDirtyCooldown time.Duration) (bool, error) {
	if e == nil || !e.shouldRunDataplane() {
		return false, nil
	}
	if e.syncDirty.Load() {
		err := e.SyncIfDirtyAfterCooldown(minDirtyCooldown)
		return err == nil && !e.syncDirty.Load(), err
	}
	e.mu.Lock()
	hasCellularRule := false
	for _, r := range e.uidRules {
		if r.Mode == SelfFirewallModeBlockCellular {
			hasCellularRule = true
			break
		}
	}
	lastCheck := e.lastRouteCheckMono
	e.mu.Unlock()
	if !hasCellularRule {
		return false, nil
	}
	act := activityNow()
	if act.Known && !act.ScreenOn && !act.WebUIActive {
		// 熄屏且无前台会话: 禁止高频空转轮询, 仅由显式切网对账入口(CheckNetworkFlipAndSync)按事件触发
		return false, nil
	}
	nowMono := monoNowNs()
	if lastCheck > 0 && nowMono > lastCheck && nowMono-lastCheck < int64(2*time.Second) {
		return false, nil
	}
	e.mu.Lock()
	e.lastRouteCheckMono = nowMono
	e.mu.Unlock()
	return e.CheckNetworkFlipAndSync()
}

func (e *selfFirewallEngine) triggerAsyncReconcile(minDirtyCooldown time.Duration) {
	if e == nil || !e.shouldRunDataplane() {
		return
	}
	e.mu.Lock()
	forced := e.forceDataplane
	hasCell := false
	for _, r := range e.uidRules {
		if r.Mode == SelfFirewallModeBlockCellular {
			hasCell = true
			break
		}
	}
	e.mu.Unlock()
	// 单测显式开启 forceDataplane 时不派发后台异步协程防与断言竞态, 由同步 API / ReconcileIfNeeded 验证
	if forced || (!e.syncDirty.Load() && !hasCell) {
		return
	}
	if !e.reconcileInFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer e.reconcileInFlight.Store(false)
		_, _ = e.ReconcileIfNeeded(minDirtyCooldown)
	}()
}

// ── 核心读写操作与防自锁守卫校验 ────────────────────────────────────────────

func protectedUIDReasonDetail(uid int) string {
	_, appID := splitSelfFirewallUID(uid)
	if appID >= selfFirewallIsolatedMinAppID {
		return fmt.Sprintf("拒绝操作 UID %d：Android 隔离沙盒临时进程 (appId >= 90000) 无固定身份，不可持久封禁", uid)
	}
	return fmt.Sprintf("拒绝操作 UID %d：系统核心守护进程与特权服务 (appId < 10000) 永不可封禁", uid)
}

// SetUIDRule 设置或移除单个应用 UID 的防火墙规则:
//   - rawTargets == nil (未传 block_targets) 时自动继承该 UID 已有的 BlockTargets;
//   - mode == "allow" 且最终 block_targets 为空时调用 RemoveUIDRule 删除整条规则;
//   - mode == "allow" 且最终 block_targets 非空时保留单 UID 的 IP 封禁规则。
func (e *selfFirewallEngine) SetUIDRule(uid int, mode, rawPkg, rawAppName string, rawTargets []string) (*SelfFirewallUIDRule, bool, error) {
	if e == nil {
		return nil, false, errors.New("selfFirewall engine unavailable")
	}
	if uid > selfFirewallMaxAppUID {
		return nil, false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: "uid out of valid Android range",
		}
	}
	if isProtectedSelfFirewallSystemUID(uid) {
		e.guardRejects.Add(1)
		return nil, false, &selfFirewallValidationError{
			Code:   "protected_uid",
			Detail: protectedUIDReasonDetail(uid),
		}
	}

	normMode := strings.ToLower(strings.TrimSpace(mode))
	if !isValidSelfFirewallMode(normMode) {
		return nil, false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: "mode must be allow|block_cleartext|block_cellular|block_all",
		}
	}

	inPkg := stripSyntheticSelfFirewallPkg(rawPkg)
	if inPkg != "" && !isValidAndroidPkgName(inPkg) {
		return nil, false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: "invalid Android package name",
		}
	}

	var normTargets []string
	if rawTargets == nil {
		e.mu.Lock()
		if prev, ok := e.uidRules[uid]; ok && len(prev.BlockTargets) > 0 {
			normTargets = append([]string(nil), prev.BlockTargets...)
			if inPkg == "" && prev.Pkg != "" {
				inPkg = stripSyntheticSelfFirewallPkg(prev.Pkg)
			}
			if strings.TrimSpace(rawAppName) == "" && prev.AppName != "" {
				rawAppName = prev.AppName
			}
		}
		e.mu.Unlock()
	} else if len(rawTargets) > 0 {
		parsed, err := normalizeSelfBlockTargetsListForServer(e.srv, rawTargets)
		if err != nil {
			return nil, false, &selfFirewallValidationError{
				Code:   "bad params",
				Detail: err.Error(),
			}
		}
		normTargets = parsed
	}

	// mode == "allow" 且无任何单 IP 拦截目标时: 移除该 UID 的全部防火墙限制
	if normMode == SelfFirewallModeAllow && len(normTargets) == 0 {
		removed, err := e.RemoveUIDRule(uid)
		return nil, removed, err
	}

	if isProtectedSelfFirewallPkg(inPkg) {
		e.guardRejects.Add(1)
		return nil, false, &selfFirewallValidationError{
			Code:   "protected_package",
			Detail: fmt.Sprintf("禁止封禁受保护的核心管理器/WebView/宿主应用 (%s)，防止设备自锁失联", inPkg),
		}
	}

	resolvedPkg, resolvedAppName, allPkgs := e.resolveLocalAppMetadata(uid, inPkg, rawAppName)
	for _, p := range allPkgs {
		if isProtectedSelfFirewallPkg(p) {
			e.guardRejects.Add(1)
			return nil, false, &selfFirewallValidationError{
				Code:   "protected_package",
				Detail: fmt.Sprintf("UID %d 归属受保护的核心应用 (%s)，已硬性拒绝封禁以防自锁", uid, p),
			}
		}
	}

	now := time.Now().Unix()
	rule := SelfFirewallUIDRule{
		UID:           uid,
		SDKSandboxUID: sdkSandboxUIDForApp(uid),
		Pkg:           resolvedPkg,
		AppName:       resolvedAppName,
		Mode:          normMode,
		BlockTargets:  normTargets,
		UpdatedAt:     now,
	}

	e.mu.Lock()
	if _, exists := e.uidRules[uid]; !exists && len(e.uidRules) >= selfFirewallMaxUIDRules {
		e.mu.Unlock()
		return nil, false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: fmt.Sprintf("uid_rules reached max capacity (%d)", selfFirewallMaxUIDRules),
		}
	}
	e.uidRules[uid] = rule
	saveErr := e.saveLocked(now)
	e.mu.Unlock()
	if saveErr != nil {
		return nil, false, saveErr
	}

	e.syncDirty.Store(true)
	dpErr := e.syncDataplane()
	e.notifyLeakGuardChanged()
	if dpErr != nil {
		return &rule, true, dpErr
	}
	return &rule, true, nil
}

// AddUIDBlockTarget 为指定应用 UID 追加单个远端公网 IP/ip:port 封禁目标（保留该 UID 原有 Mode, 无规则时以 mode="allow" 承载）。
func (e *selfFirewallEngine) AddUIDBlockTarget(uid int, rawTarget, rawPkg, rawAppName string) (*SelfFirewallUIDRule, bool, error) {
	if e == nil {
		return nil, false, errors.New("selfFirewall engine unavailable")
	}
	if uid > selfFirewallMaxAppUID {
		return nil, false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: "uid out of valid Android range",
		}
	}
	if isProtectedSelfFirewallSystemUID(uid) {
		e.guardRejects.Add(1)
		return nil, false, &selfFirewallValidationError{
			Code:   "protected_uid",
			Detail: protectedUIDReasonDetail(uid),
		}
	}
	inPkg := stripSyntheticSelfFirewallPkg(rawPkg)
	if inPkg != "" && !isValidAndroidPkgName(inPkg) {
		return nil, false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: "invalid Android package name",
		}
	}
	if isProtectedSelfFirewallPkg(inPkg) {
		e.guardRejects.Add(1)
		return nil, false, &selfFirewallValidationError{
			Code:   "protected_package",
			Detail: fmt.Sprintf("禁止封禁受保护的核心管理器/WebView/宿主应用 (%s)", inPkg),
		}
	}

	normOne, err := normalizeSelfBlockTargetsListForServer(e.srv, []string{rawTarget})
	if err != nil || len(normOne) == 0 {
		detail := "invalid block_target"
		if err != nil {
			detail = err.Error()
		}
		return nil, false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: detail,
		}
	}
	canonTgt := normOne[0]

	resolvedPkg, resolvedAppName, allPkgs := e.resolveLocalAppMetadata(uid, inPkg, rawAppName)
	for _, p := range allPkgs {
		if isProtectedSelfFirewallPkg(p) {
			e.guardRejects.Add(1)
			return nil, false, &selfFirewallValidationError{
				Code:   "protected_package",
				Detail: fmt.Sprintf("UID %d 归属受保护的核心应用 (%s)，已硬性拒绝封禁以防自锁", uid, p),
			}
		}
	}

	now := time.Now().Unix()
	e.mu.Lock()
	cur, exists := e.uidRules[uid]
	if !exists && len(e.uidRules) >= selfFirewallMaxUIDRules {
		e.mu.Unlock()
		return nil, false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: fmt.Sprintf("uid_rules reached max capacity (%d)", selfFirewallMaxUIDRules),
		}
	}
	mode := cur.Mode
	if mode == "" || !isValidSelfFirewallMode(mode) {
		mode = SelfFirewallModeAllow
	}
	merged := make([]string, 0, len(cur.BlockTargets)+1)
	already := false
	for _, t := range cur.BlockTargets {
		if t == canonTgt {
			already = true
		}
		merged = append(merged, t)
	}
	if !already {
		if len(merged) >= selfFirewallMaxTargets {
			e.mu.Unlock()
			return nil, false, &selfFirewallValidationError{
				Code:   "bad params",
				Detail: fmt.Sprintf("too many block_targets (max %d)", selfFirewallMaxTargets),
			}
		}
		merged = append(merged, canonTgt)
		sort.Strings(merged)
	}
	if resolvedPkg == "" {
		resolvedPkg = cur.Pkg
	}
	if resolvedAppName == "" {
		resolvedAppName = cur.AppName
	}
	nextRule := SelfFirewallUIDRule{
		UID:           uid,
		SDKSandboxUID: sdkSandboxUIDForApp(uid),
		Pkg:           resolvedPkg,
		AppName:       resolvedAppName,
		Mode:          mode,
		BlockTargets:  merged,
		UpdatedAt:     now,
	}
	e.uidRules[uid] = nextRule
	saveErr := e.saveLocked(now)
	e.mu.Unlock()
	if saveErr != nil {
		return nil, false, saveErr
	}

	e.syncDirty.Store(true)
	dpErr := e.syncDataplane()
	e.notifyLeakGuardChanged()
	if dpErr != nil {
		return &nextRule, !already, dpErr
	}
	return &nextRule, !already, nil
}

// RemoveUIDBlockTarget 从指定应用 UID 的防火墙规则中移除单个 IP/ip:port 目标;
// 若该 UID 的 Mode 为 "allow" 且移除后无剩余目标, 自动删除整条 UID 规则并在空表时拆链。
func (e *selfFirewallEngine) RemoveUIDBlockTarget(uid int, rawTarget string) (bool, error) {
	if e == nil {
		return false, errors.New("selfFirewall engine unavailable")
	}
	if uid > selfFirewallMaxAppUID {
		return false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: "uid out of valid Android range",
		}
	}
	if isProtectedSelfFirewallSystemUID(uid) {
		return false, &selfFirewallValidationError{
			Code:   "protected_uid",
			Detail: protectedUIDReasonDetail(uid),
		}
	}
	canonTgt := strings.TrimSpace(rawTarget)
	if pt, err := parseAndValidateSelfBlockTarget(canonTgt); err == nil {
		canonTgt = pt.Canonical
	}
	if canonTgt == "" {
		return false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: "empty block_target",
		}
	}

	now := time.Now().Unix()
	e.mu.Lock()
	cur, exists := e.uidRules[uid]
	if !exists || len(cur.BlockTargets) == 0 {
		e.mu.Unlock()
		return false, nil
	}
	var kept []string
	removed := false
	for _, t := range cur.BlockTargets {
		if strings.EqualFold(t, canonTgt) {
			removed = true
			continue
		}
		kept = append(kept, t)
	}
	if !removed {
		e.mu.Unlock()
		return false, nil
	}
	if (cur.Mode == "" || cur.Mode == SelfFirewallModeAllow) && len(kept) == 0 {
		delete(e.uidRules, uid)
	} else {
		cur.BlockTargets = kept
		cur.UpdatedAt = now
		e.uidRules[uid] = cur
	}
	saveErr := e.saveLocked(now)
	e.mu.Unlock()
	if saveErr != nil {
		return false, saveErr
	}

	e.syncDirty.Store(true)
	dpErr := e.syncDataplane()
	e.notifyLeakGuardChanged()
	if dpErr != nil {
		return true, dpErr
	}
	return true, nil
}

// RemoveUIDRule 移除指定应用 UID 的本机防火墙规则。
func (e *selfFirewallEngine) RemoveUIDRule(uid int) (bool, error) {
	if e == nil {
		return false, errors.New("selfFirewall engine unavailable")
	}
	if uid > selfFirewallMaxAppUID {
		return false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: "uid out of valid Android range",
		}
	}
	if isProtectedSelfFirewallSystemUID(uid) {
		return false, &selfFirewallValidationError{
			Code:   "protected_uid",
			Detail: protectedUIDReasonDetail(uid),
		}
	}
	now := time.Now().Unix()
	e.mu.Lock()
	_, existed := e.uidRules[uid]
	delete(e.uidRules, uid)
	var saveErr error
	if existed {
		saveErr = e.saveLocked(now)
	}
	e.mu.Unlock()
	if saveErr != nil {
		return false, saveErr
	}
	if existed {
		e.syncDirty.Store(true)
	}
	dpErr := e.syncDataplane()
	if existed {
		e.notifyLeakGuardChanged()
	}
	if dpErr != nil {
		return existed, dpErr
	}
	return existed, nil
}

// ClearAll 清空本机应用防火墙规则（scope: ""|"all"|"uid"|"dns"）并在全空时摘除 OUTPUT 钩子。
func (e *selfFirewallEngine) ClearAll(scope string) (removedUIDs, removedDomains int, err error) {
	if e == nil {
		return 0, 0, errors.New("selfFirewall engine unavailable")
	}
	sc := strings.ToLower(strings.TrimSpace(scope))
	if sc == "" {
		sc = "all"
	}
	if sc != "all" && sc != "uid" && sc != "dns" {
		return 0, 0, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: "scope must be all|uid|dns",
		}
	}
	now := time.Now().Unix()
	e.mu.Lock()
	if sc == "all" || sc == "uid" {
		removedUIDs = len(e.uidRules)
		e.uidRules = make(map[int]SelfFirewallUIDRule)
	}
	if sc == "all" || sc == "dns" {
		removedDomains = len(e.blockedDomains)
		e.blockedDomains = make(map[string]bool)
	}
	saveErr := e.saveLocked(now)
	e.mu.Unlock()
	if saveErr != nil {
		return removedUIDs, removedDomains, saveErr
	}
	e.syncDirty.Store(true)
	dpErr := e.syncDataplane()
	e.notifyLeakGuardChanged()
	if dpErr != nil {
		return removedUIDs, removedDomains, dpErr
	}
	return removedUIDs, removedDomains, nil
}

// BlockDomain 添加本机 DNS 拦截域名（前置复用三级共享 CDN/公共基础设施守卫）。
func (e *selfFirewallEngine) BlockDomain(rawDomain string, force bool) (normDomain string, guardDec leakBlockGuardDecision, added bool, err error) {
	if e == nil {
		return "", leakBlockGuardDecision{}, false, errors.New("selfFirewall engine unavailable")
	}
	nd, nerr := normalizeSelfDNSBlockDomain(rawDomain)
	if nerr != nil {
		return "", leakBlockGuardDecision{}, false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: nerr.Error(),
		}
	}

	guardDec = evaluateLeakBlockDomainGuard(e.srvHncDir(), nd)
	if guardDec.Level == leakGuardLevelHardBlock {
		e.guardRejects.Add(1)
		return nd, guardDec, false, &selfFirewallGuardError{Decision: guardDec, Domain: nd}
	}
	if guardDec.Level == leakGuardLevelWarnConfirm && !force {
		e.guardRejects.Add(1)
		return nd, guardDec, false, &selfFirewallGuardError{Decision: guardDec, Domain: nd}
	}

	now := time.Now().Unix()
	e.mu.Lock()
	already := e.blockedDomains[nd]
	if !already && len(e.blockedDomains) >= selfFirewallMaxDomains {
		e.mu.Unlock()
		return nd, guardDec, false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: fmt.Sprintf("blocked_domains reached max capacity (%d)", selfFirewallMaxDomains),
		}
	}
	e.blockedDomains[nd] = true
	saveErr := e.saveLocked(now)
	e.mu.Unlock()
	if saveErr != nil {
		return nd, guardDec, false, saveErr
	}
	e.syncDirty.Store(true)
	dpErr := e.syncDataplane()
	e.notifyLeakGuardChanged()
	if dpErr != nil {
		return nd, guardDec, !already, dpErr
	}
	return nd, guardDec, !already, nil
}

// UnblockDomain 移除本机 DNS 拦截域名。
func (e *selfFirewallEngine) UnblockDomain(rawDomain string) (normDomain string, removed bool, err error) {
	if e == nil {
		return "", false, errors.New("selfFirewall engine unavailable")
	}
	nd, nerr := normalizeSelfDNSBlockDomain(rawDomain)
	if nerr != nil {
		return "", false, &selfFirewallValidationError{
			Code:   "bad params",
			Detail: nerr.Error(),
		}
	}
	now := time.Now().Unix()
	e.mu.Lock()
	removed = e.blockedDomains[nd]
	delete(e.blockedDomains, nd)
	var saveErr error
	if removed {
		saveErr = e.saveLocked(now)
	}
	e.mu.Unlock()
	if saveErr != nil {
		return nd, false, saveErr
	}
	if removed {
		e.syncDirty.Store(true)
	}
	dpErr := e.syncDataplane()
	if removed {
		e.notifyLeakGuardChanged()
	}
	if dpErr != nil {
		return nd, removed, dpErr
	}
	return nd, removed, nil
}

func (e *selfFirewallEngine) notifyLeakGuardChanged() {
	if e == nil || e.srv == nil {
		return
	}
	if v, ok := v6Registry.Load(e.srv); ok {
		if st, ok2 := v.(*v6ServerState); ok2 && st != nil && st.leakGuard != nil {
			cb := readConnBlocks(e.srv.hncDir)
			st.leakGuard.mu.Lock()
			st.leakGuard.recomputeEventsBlockedLocked(cb)
			st.leakGuard.mu.Unlock()
			st.leakGuard.notifySSEChanged()
		}
	}
}

func isSelfCleartextHTTPPort(port int) bool {
	for _, p := range selfFirewallCleartextPorts {
		if port == p {
			return true
		}
	}
	return false
}

// IsDomainBlocked 判断目标域名是否命中 HNC_SELF_DNS 本机封禁集（含精确域名及全部子域）。
func (e *selfFirewallEngine) IsDomainBlocked(host string) bool {
	if e == nil {
		return false
	}
	h := strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for cur := h; ; {
		if e.blockedDomains[cur] {
			return true
		}
		dot := strings.IndexByte(cur, '.')
		if dot < 0 || dot+1 >= len(cur) {
			break
		}
		cur = cur[dot+1:]
	}
	return false
}

// IsHostEventBlocked 综合判定 LeakGuard 本机事件是否已被本机 DNS 拦截或该应用 UID 防火墙规则阻断。
func (e *selfFirewallEngine) IsHostEventBlocked(uid int, dstHost, dstIP string, dstPort int, proto string) bool {
	if e == nil {
		return false
	}
	if dstHost != "" && e.IsDomainBlocked(dstHost) {
		return true
	}
	if isProtectedSelfFirewallSystemUID(uid) || uid > selfFirewallMaxAppUID {
		return false
	}
	lookupUID := uid
	if _, appID := splitSelfFirewallUID(uid); appID >= selfFirewallSandboxMinUID+selfFirewallSandboxOffset && appID <= selfFirewallSandboxMaxUID+selfFirewallSandboxOffset {
		lookupUID = uid - selfFirewallSandboxOffset
	}

	e.mu.Lock()
	r, ok := e.uidRules[uid]
	if !ok && lookupUID != uid {
		r, ok = e.uidRules[lookupUID]
	}
	e.mu.Unlock()
	if !ok {
		return false
	}

	switch r.Mode {
	case SelfFirewallModeBlockAll:
		return true
	case SelfFirewallModeBlockCleartext:
		lp := strings.ToLower(strings.TrimSpace(proto))
		if (lp == "" || lp == "http" || lp == "tcp") && (dstPort == 0 || isSelfCleartextHTTPPort(dstPort)) {
			return true
		}
	}

	if dstIP != "" && len(r.BlockTargets) > 0 {
		if addr, err := netip.ParseAddr(strings.TrimSpace(dstIP)); err == nil {
			canonIP := addr.Unmap().String()
			for _, tgt := range r.BlockTargets {
				pt, perr := parseAndValidateSelfBlockTarget(tgt)
				if perr != nil {
					continue
				}
				if pt.IP == canonIP && (pt.Port == 0 || pt.Port == dstPort) {
					return true
				}
			}
		}
	}
	return false
}

// BlockedDomainCount 返回当前 HNC_SELF_DNS 已封禁的本机域名总数。
func (e *selfFirewallEngine) BlockedDomainCount() int {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	n := len(e.blockedDomains)
	e.mu.Unlock()
	return n
}

func (s *server) selfFirewallBlockedDomainCount() int {
	if s == nil {
		return 0
	}
	if v, ok := v6Registry.Load(s); ok {
		if st, ok2 := v.(*v6ServerState); ok2 && st != nil && st.selfFirewall != nil {
			return st.selfFirewall.BlockedDomainCount()
		}
	}
	return 0
}

func (e *selfFirewallEngine) snapshotPayload() map[string]any {
	if e == nil {
		return map[string]any{
			"ok":                 true,
			"updated_at":         int64(0),
			"uid_rules":          []SelfFirewallUIDRule{},
			"blocked_domains":    []string{},
			"protected_packages": append([]string(nil), selfFirewallProtectedPackages...),
			"sync_dirty":         false,
		}
	}
	e.mu.Lock()
	rules, domains, updatedAt := e.sortedSnapshotLocked()
	e.mu.Unlock()
	for i := range rules {
		cleanPkg := stripSyntheticSelfFirewallPkg(rules[i].Pkg)
		if cleanPkg != rules[i].Pkg {
			rules[i].Pkg = cleanPkg
		}
		if rules[i].Pkg == "" || isPlaceholderSelfAppName(rules[i].AppName, rules[i].Pkg, rules[i].UID) {
			pkg, appName, _ := e.resolveLocalAppMetadata(rules[i].UID, rules[i].Pkg, rules[i].AppName)
			if rules[i].Pkg == "" && pkg != "" {
				rules[i].Pkg = pkg
			}
			if appName != "" {
				rules[i].AppName = appName
			}
		}
		if rules[i].DisplayName == "" && rules[i].AppName != "" {
			rules[i].DisplayName = rules[i].AppName
		}
	}
	return map[string]any{
		"ok":                   true,
		"updated_at":           updatedAt,
		"uid_rules":            rules,
		"blocked_domains":      domains,
		"protected_packages":   append([]string(nil), selfFirewallProtectedPackages...),
		"uid_rule_count":       len(rules),
		"blocked_domain_count": len(domains),
		"sync_dirty":           e.syncDirty.Load(),
	}
}

func (e *selfFirewallEngine) summary() map[string]any {
	if e == nil {
		return map[string]any{}
	}
	e.mu.Lock()
	uidCnt := len(e.uidRules)
	domCnt := len(e.blockedDomains)
	updatedAt := e.updatedAt
	lastErr := e.lastSyncErr
	var cleartextCnt, cellularCnt, blockAllCnt, ipTargetOnlyCnt int
	for _, r := range e.uidRules {
		switch r.Mode {
		case SelfFirewallModeBlockCleartext:
			cleartextCnt++
		case SelfFirewallModeBlockCellular:
			cellularCnt++
		case SelfFirewallModeBlockAll:
			blockAllCnt++
		case SelfFirewallModeAllow:
			if len(r.BlockTargets) > 0 {
				ipTargetOnlyCnt++
			}
		}
	}
	e.mu.Unlock()
	out := map[string]any{
		"active":               uidCnt > 0 || domCnt > 0,
		"uid_rule_count":       uidCnt,
		"blocked_domain_count": domCnt,
		"block_cleartext_apps": cleartextCnt,
		"block_cellular_apps":  cellularCnt,
		"block_all_apps":       blockAllCnt,
		"ip_target_only_apps":  ipTargetOnlyCnt,
		"apply_commits":        e.applyCommits.Load(),
		"guard_rejects":        e.guardRejects.Load(),
		"sync_dirty":           e.syncDirty.Load(),
		"updated_at":           updatedAt,
	}
	if lastErr != "" {
		out["last_sync_error"] = lastErr
	}
	e.triggerAsyncReconcile(5 * time.Second)
	return out
}

// ── HTTP API (/api/local_apps/firewall, /api/v6/local_apps/firewall) 与 /api/action 分发 ──

func parseFlexibleTargetStrings(raw string) []string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "[") {
		var arr []string
		if json.Unmarshal([]byte(s), &arr) == nil {
			if arr == nil {
				return []string{}
			}
			return arr
		}
	}
	return []string{s}
}

func parseExplicitTargetStrings(raw string) []string {
	out := parseFlexibleTargetStrings(raw)
	if out == nil {
		return []string{}
	}
	return out
}

func firstNonEmptyParam(p map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(p[k]); v != "" {
			return v
		}
	}
	return ""
}

func selfFirewallParamTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// dispatchSelfFirewallAction 处理 POST /api/action 中的 5 个本机防火墙动作。
func dispatchSelfFirewallAction(s *server, action string, p map[string]string) actionResp {
	if s == nil {
		return actionResp{OK: false, Error: "internal error", Detail: "server unavailable"}
	}
	eng := s.v6State().selfFirewall

	mapErrToActionResp := func(err error) actionResp {
		var verr *selfFirewallValidationError
		if errors.As(err, &verr) {
			return actionResp{OK: false, Error: verr.Code, Detail: verr.Detail}
		}
		var gerr *selfFirewallGuardError
		if errors.As(err, &gerr) {
			b, _ := json.Marshal(map[string]any{
				"guard_level": gerr.Decision.Level,
				"vendor":      gerr.Decision.Vendor,
				"category":    gerr.Decision.Category,
				"domain":      gerr.Domain,
				"detail":      gerr.Decision.Detail,
			})
			return actionResp{OK: false, Error: "conflict", Detail: string(b)}
		}
		return actionResp{OK: false, Error: "apply failed", Detail: err.Error()}
	}

	switch action {
	case "self_firewall_set":
		uidStr := strings.TrimSpace(p["uid"])
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			return actionResp{OK: false, Error: "bad params", Detail: "valid numeric uid is required"}
		}
		mode := strings.ToLower(strings.TrimSpace(p["mode"]))
		if mode == "" {
			return actionResp{OK: false, Error: "bad params", Detail: "mode is required"}
		}
		var targets []string
		if rawTgt, hasTgt := p["block_targets"]; hasTgt {
			targets = parseExplicitTargetStrings(rawTgt)
		}
		rule, _, serr := eng.SetUIDRule(uid, mode, p["pkg"], p["app_name"], targets)
		if serr != nil {
			return mapErrToActionResp(serr)
		}
		if rule == nil {
			return actionResp{OK: true, Detail: fmt.Sprintf("uid=%d mode=allow (rule removed)", uid)}
		}
		return actionResp{OK: true, Detail: fmt.Sprintf("uid=%d mode=%s applied", rule.UID, rule.Mode)}

	case "self_firewall_remove":
		uidStr := strings.TrimSpace(p["uid"])
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			return actionResp{OK: false, Error: "bad params", Detail: "valid numeric uid is required"}
		}
		removed, rerr := eng.RemoveUIDRule(uid)
		if rerr != nil {
			return mapErrToActionResp(rerr)
		}
		return actionResp{OK: true, Detail: fmt.Sprintf("uid=%d removed=%v", uid, removed)}

	case "self_firewall_clear":
		rmUIDs, rmDoms, cerr := eng.ClearAll(p["scope"])
		if cerr != nil {
			return mapErrToActionResp(cerr)
		}
		return actionResp{OK: true, Detail: fmt.Sprintf("cleared uid_rules=%d blocked_domains=%d", rmUIDs, rmDoms)}

	case "self_dns_block":
		dom := firstNonEmptyParam(p, "domain", "dst_host", "value")
		if dom == "" {
			return actionResp{OK: false, Error: "bad params", Detail: "domain is required"}
		}
		force := selfFirewallParamTruthy(p["force"])
		nd, _, _, berr := eng.BlockDomain(dom, force)
		if berr != nil {
			return mapErrToActionResp(berr)
		}
		return actionResp{OK: true, Detail: "self dns blocked: " + nd}

	case "self_dns_unblock":
		dom := firstNonEmptyParam(p, "domain", "dst_host", "value")
		if dom == "" {
			return actionResp{OK: false, Error: "bad params", Detail: "domain is required"}
		}
		nd, _, uerr := eng.UnblockDomain(dom)
		if uerr != nil {
			return mapErrToActionResp(uerr)
		}
		return actionResp{OK: true, Detail: "self dns unblocked: " + nd}

	default:
		return actionResp{OK: false, Error: "unknown action"}
	}
}

// apiSelfFirewall GET/POST /api/local_apps/firewall (及 /api/v6/local_apps/firewall)
func (s *server) apiSelfFirewall(w http.ResponseWriter, r *http.Request) {
	eng := s.v6State().selfFirewall
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, eng.snapshotPayload())
		return
	}
	s.requireMutation(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action       string          `json:"action"`
			UID          *int            `json:"uid"`
			Pkg          string          `json:"pkg"`
			AppName      string          `json:"app_name"`
			Mode         string          `json:"mode"`
			BlockTargets json.RawMessage `json:"block_targets"`
			Domain       string          `json:"domain"`
			DstHost      string          `json:"dst_host"`
			Scope        string          `json:"scope"`
			Force        bool            `json:"force"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json", "detail": err.Error()})
			return
		}

		writeErr := func(err error) {
			var verr *selfFirewallValidationError
			if errors.As(err, &verr) {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"ok":          false,
					"error":       verr.Code,
					"reason_code": verr.Code,
					"detail":      verr.Detail,
				})
				return
			}
			var gerr *selfFirewallGuardError
			if errors.As(err, &gerr) {
				errCode := "guard_warn_confirm"
				if gerr.Decision.Level == leakGuardLevelHardBlock {
					errCode = "guard_hard_block"
				}
				writeJSON(w, http.StatusConflict, map[string]any{
					"ok":               false,
					"error":            errCode,
					"guard_level":      gerr.Decision.Level,
					"requires_confirm": gerr.Decision.Level == leakGuardLevelWarnConfirm,
					"vendor":           gerr.Decision.Vendor,
					"category":         gerr.Decision.Category,
					"domain":           gerr.Domain,
					"detail":           gerr.Decision.Detail,
				})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok":     false,
				"error":  "apply failed",
				"detail": err.Error(),
			})
		}

		var parsedTargets []string
		if len(req.BlockTargets) > 0 && string(bytes.TrimSpace(req.BlockTargets)) != "null" {
			var arr []string
			if json.Unmarshal(req.BlockTargets, &arr) == nil {
				if arr == nil {
					parsedTargets = []string{}
				} else {
					parsedTargets = arr
				}
			} else {
				var single string
				if json.Unmarshal(req.BlockTargets, &single) == nil {
					parsedTargets = parseExplicitTargetStrings(single)
				} else {
					writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "block_targets must be array of strings or comma-separated string"})
					return
				}
			}
		}

		act := strings.ToLower(strings.TrimSpace(req.Action))
		if act == "" {
			if req.UID != nil {
				act = "self_firewall_set"
			} else if req.Domain != "" || req.DstHost != "" {
				act = "self_dns_block"
			}
		}

		switch act {
		case "set", "self_firewall_set":
			if req.UID == nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "uid is required"})
				return
			}
			if _, _, err := eng.SetUIDRule(*req.UID, req.Mode, req.Pkg, req.AppName, parsedTargets); err != nil {
				writeErr(err)
				return
			}
		case "remove", "self_firewall_remove":
			if req.UID == nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "uid is required"})
				return
			}
			if _, err := eng.RemoveUIDRule(*req.UID); err != nil {
				writeErr(err)
				return
			}
		case "clear", "self_firewall_clear":
			if _, _, err := eng.ClearAll(req.Scope); err != nil {
				writeErr(err)
				return
			}
		case "dns_block", "self_dns_block":
			dom := strings.TrimSpace(req.Domain)
			if dom == "" {
				dom = strings.TrimSpace(req.DstHost)
			}
			if _, _, _, err := eng.BlockDomain(dom, req.Force); err != nil {
				writeErr(err)
				return
			}
		case "dns_unblock", "self_dns_unblock":
			dom := strings.TrimSpace(req.Domain)
			if dom == "" {
				dom = strings.TrimSpace(req.DstHost)
			}
			if _, _, err := eng.UnblockDomain(dom); err != nil {
				writeErr(err)
				return
			}
		default:
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":     false,
				"error":  "bad params",
				"detail": "action must be self_firewall_set|self_firewall_remove|self_firewall_clear|self_dns_block|self_dns_unblock",
			})
			return
		}

		writeJSON(w, http.StatusOK, eng.snapshotPayload())
	})(w, r)
}
