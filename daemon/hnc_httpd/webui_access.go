// webui_access.go — v5.22 WebUI 访问白名单(Go 侧纵深防御 + 配置 + action)
//
// 配置: data/webui_access.json(本文件是唯一写者, 单行紧凑 JSON, 0600, tmp+rename)
//
//	{"mode":"all|allowlist|local_only","macs":["aa:bb:cc:dd:ee:ff","192.168.43.7","fd00::7"],"updated":<unix>}
//
//	all         (缺省, 文件不存在时) 任何热点/局域网客户端都能打开登录页(仍需配对)。
//	            防火墙层仍拒绝来自蜂窝上行口(rmnet*/ccmni*/…)的连接。
//	allowlist   只有列表里的 MAC / IP 与本机 loopback 能连上 8443/8080。
//	local_only  只有 127.0.0.1 / ::1(KSU WebUI 与本机浏览器)。
//
// 两层执行:
//  1. 防火墙(主): bin/webui_guard.sh 在 filter/INPUT 挂 HNC_WEBUI 链(v4+v6), 非放行
//     客户端收到 TCP RST(= connection refused), 连 TLS 握手都到不了。
//  2. 本文件(纵深): webuiAccessGuard 中间件按同一配置判定, 防火墙缺失/被清空/
//     iptables 不可用时仍挡在 HTTP 层(403 + Connection: close)。
//
// loopback 永远放行(两层都是), KSU WebUI 不可能被锁在外面。
// 文件损坏 / mode 非法 → 按 local_only 处理(fail-closed, 与 readAuthRequired 一致;
// 本机 KSU WebUI 仍可改回)。
//
// MAC → IP: 白名单条目可以是 MAC(随 DHCP 换 IP 也有效)。防火墙层直接用
// `-m mac --mac-source`; Go 层把请求源 IP 反查邻居表(v4 /proc/net/arp,
// v6 `ip -6 neigh`), 快照缓存 2 秒。

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"hnc.io/dpid/neigh"
)

const (
	webuiModeAll       = "all"
	webuiModeAllowlist = "allowlist"
	webuiModeLocalOnly = "local_only"
	webuiAccessMaxList = 32
	// webuiClientIPParam handleAction 为 webui_access_set 注入的请求源 IP(覆盖客户端同名参数)
	webuiClientIPParam = "_client_ip"
)

type webuiAccessCfg struct {
	Mode    string   `json:"mode"`
	Macs    []string `json:"macs"`
	Updated int64    `json:"updated,omitempty"`
}

func webuiAccessPath(hncDir string) string {
	return filepath.Join(hncDir, "data", "webui_access.json")
}

// ── 配置读取(mtime+size 缓存) ─────────────────────────────────

type webuiCfgCacheEntry struct {
	mtime time.Time
	size  int64
	cfg   webuiAccessCfg
}

var (
	webuiCfgMu    sync.Mutex
	webuiCfgCache = map[string]webuiCfgCacheEntry{}
)

func loadWebUIAccess(hncDir string) webuiAccessCfg {
	p := webuiAccessPath(hncDir)
	st, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return webuiAccessCfg{Mode: webuiModeAll, Macs: []string{}}
		}
		log.Printf("webui_access: stat failed, fail-closed to local_only: %v", err)
		return webuiAccessCfg{Mode: webuiModeLocalOnly, Macs: []string{}}
	}
	webuiCfgMu.Lock()
	if e, ok := webuiCfgCache[p]; ok && e.mtime.Equal(st.ModTime()) && e.size == st.Size() {
		webuiCfgMu.Unlock()
		return e.cfg
	}
	webuiCfgMu.Unlock()
	cfg := parseWebUIAccess(p)
	webuiCfgMu.Lock()
	webuiCfgCache[p] = webuiCfgCacheEntry{mtime: st.ModTime(), size: st.Size(), cfg: cfg}
	webuiCfgMu.Unlock()
	return cfg
}

func parseWebUIAccess(p string) webuiAccessCfg {
	b, err := os.ReadFile(p)
	if err != nil {
		log.Printf("webui_access: read failed, fail-closed to local_only: %v", err)
		return webuiAccessCfg{Mode: webuiModeLocalOnly, Macs: []string{}}
	}
	var c webuiAccessCfg
	if err := json.Unmarshal(b, &c); err != nil {
		log.Printf("webui_access: parse failed, fail-closed to local_only: %v", err)
		return webuiAccessCfg{Mode: webuiModeLocalOnly, Macs: []string{}}
	}
	switch c.Mode {
	case webuiModeAll, webuiModeAllowlist, webuiModeLocalOnly:
	default:
		log.Printf("webui_access: bad mode %q, fail-closed to local_only", c.Mode)
		c.Mode = webuiModeLocalOnly
	}
	// 条目再校验一遍(手改文件不能把垃圾带进判定)
	clean, _ := normalizeAllowEntries(strings.Join(c.Macs, ","))
	c.Macs = clean
	return c
}

func saveWebUIAccess(hncDir string, c webuiAccessCfg) error {
	p := webuiAccessPath(hncDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if c.Macs == nil {
		c.Macs = []string{}
	}
	b, err := json.Marshal(c) // 单行: webui_guard.sh 用 sed/grep 解析
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// normalizeAllowEntries 解析逗号/空白分隔的 MAC / IP 列表: MAC 统一小写冒号格式,
// IP 用规范文本(IPv4-mapped 还原成 v4)。返回 (去重后的条目, 第一个非法条目)。
func normalizeAllowEntries(raw string) ([]string, string) {
	out := []string{}
	seen := map[string]bool{}
	f := func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' || r == '\r' }
	for _, tok := range strings.FieldsFunc(raw, f) {
		v := strings.ToLower(strings.TrimSpace(tok))
		if v == "" {
			continue
		}
		var norm string
		if m := strings.ReplaceAll(v, "-", ":"); macRE.MatchString(m) {
			if protectedSpecialMACs[m] {
				return out, tok
			}
			norm = m
		} else if ip := net.ParseIP(v); ip != nil && !strings.Contains(v, "%") {
			if ip.IsUnspecified() || ip.IsMulticast() {
				return out, tok
			}
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			norm = ip.String()
		} else {
			return out, tok
		}
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	return out, ""
}

// ── 客户端身份与邻居表(纯 Go Netlink + 单测桩兼容) ────────────

// clientIP 解析 RemoteAddr 为 net.IP(去端口、去 IPv6 zone、v4-mapped 还原)。
func clientIP(remoteAddr string) net.IP {
	host := ipOnly(remoteAddr)
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// localAddrIP 从请求 Context(http.LocalAddrContextKey)提取连接到达的本地目标 IP。
func localAddrIP(r *http.Request) net.IP {
	if r == nil {
		return nil
	}
	la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || la == nil {
		return nil
	}
	return clientIP(la.String())
}

func isLoopbackIP(ip net.IP) bool { return ip != nil && ip.IsLoopback() }

// 邻居表来源:
//   - neighV6Dump 非 nil 时优先调用(单测 fixture 桩钩子);
//   - 生产默认 neighV6Dump == nil, 走纯 Go Netlink(neigh.Dump / DumpNativeIPv6Neighbors),
//     彻底消除每 2 秒 fork `ip -6 neigh show` 子进程。
var (
	neighArpPath  = "/proc/net/arp"
	neighV6Dump   func() (string, error)
	neighV6Native = defaultNativeNeigh6
	neighCacheTTL = 2 * time.Second
)

var (
	neighMu      sync.Mutex
	neighSnap    map[string]string // ip(规范文本) → mac
	neighSnapAt  time.Time
	neighSnapSrc string // 快照对应的 arp 路径(测试切换 fixture 时失效)
)

func defaultNativeNeigh6(into map[string]string) {
	if es, err := neigh.Dump(syscall.AF_INET6); err == nil {
		for _, e := range es {
			if !e.Usable() || e.IP == nil {
				continue
			}
			mac := strings.ToLower(e.MAC)
			if !macRE.MatchString(mac) {
				continue
			}
			into[e.IP.String()] = mac
		}
		return
	}
	if byMAC, err := DumpNativeIPv6Neighbors(nil); err == nil {
		for mac, ips := range byMAC {
			mac = strings.ToLower(strings.TrimSpace(mac))
			if !macRE.MatchString(mac) {
				continue
			}
			for _, ip := range ips {
				if ip != nil {
					into[ip.String()] = mac
				}
			}
		}
	}
}

func parseArpTable(r *bufio.Scanner, into map[string]string) {
	first := true
	for r.Scan() {
		if first { // 表头
			first = false
			continue
		}
		f := strings.Fields(r.Text())
		// IP address  HW type  Flags  HW address  Mask  Device
		if len(f) < 4 || f[2] == "0x0" {
			continue
		}
		mac := strings.ToLower(f[3])
		ip := net.ParseIP(f[0])
		if ip == nil || ip.To4() == nil || !macRE.MatchString(mac) || mac == "00:00:00:00:00:00" {
			continue
		}
		into[ip.To4().String()] = mac
	}
}

func parseNeigh6(out string, into map[string]string) {
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 {
			continue
		}
		state := f[len(f)-1]
		if state == "FAILED" || state == "INCOMPLETE" {
			continue
		}
		mac := ""
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "lladdr" {
				mac = strings.ToLower(f[i+1])
			}
		}
		ip := net.ParseIP(f[0])
		if ip == nil || !macRE.MatchString(mac) {
			continue
		}
		into[ip.String()] = mac
	}
}

// neighborMAC 返回 ip 当前对应的 MAC(查不到返回 "")。
func neighborMAC(ip net.IP) string {
	if ip == nil {
		return ""
	}
	neighMu.Lock()
	defer neighMu.Unlock()
	if neighSnap == nil || time.Since(neighSnapAt) > neighCacheTTL || neighSnapSrc != neighArpPath {
		m := map[string]string{}
		if f, err := os.Open(neighArpPath); err == nil {
			parseArpTable(bufio.NewScanner(f), m)
			f.Close()
		}
		if neighV6Dump != nil {
			if out, err := neighV6Dump(); err == nil {
				parseNeigh6(out, m)
			}
		} else {
			neighV6Native(m)
		}
		neighSnap, neighSnapAt, neighSnapSrc = m, time.Now(), neighArpPath
	}
	return neighSnap[ip.String()]
}

// webuiClientAllowed: ip 是否命中白名单条目(IP 直接比对; MAC 条目经邻居表反查)。
// 返回 (命中?, 反查到的 MAC —— 供错误信息用)。
func webuiClientAllowed(ip net.IP, entries []string) (bool, string) {
	if ip == nil {
		return false, ""
	}
	hasMAC := false
	for _, e := range entries {
		if strings.Contains(e, ":") && macRE.MatchString(e) {
			hasMAC = true
			continue
		}
		if eip := net.ParseIP(e); eip != nil && eip.Equal(ip) {
			return true, ""
		}
	}
	mac := neighborMAC(ip)
	if !hasMAC || mac == "" {
		return false, mac
	}
	for _, e := range entries {
		if e == mac {
			return true, mac
		}
	}
	return false, mac
}

// ── 上游公共 Wi-Fi / WAN 越权访问拦截(纵深防御) ───────────────

type webuiIfaceInfo struct {
	Name  string
	Up    bool
	Addrs []*net.IPNet
}

func defaultWebUIListIfaces() []webuiIfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]webuiIfaceInfo, 0, len(ifaces))
	for _, ifi := range ifaces {
		info := webuiIfaceInfo{Name: ifi.Name, Up: ifi.Flags&net.FlagUp != 0}
		if addrs, err := ifi.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn != nil && ipn.IP != nil {
					info.Addrs = append(info.Addrs, ipn)
				}
			}
		}
		out = append(out, info)
	}
	return out
}

// webuiListIfaces 系统网卡快照入口(单测可注入 fake 拓扑)。
var (
	webuiListIfaces   = defaultWebUIListIfaces
	webuiBoundaryTTL  = 2 * time.Second
	webuiBoundaryMu   sync.Mutex
	webuiBoundarySnap = map[string]webuiBoundaryEntry{}
)

type webuiBoundaryEntry struct {
	at                time.Time
	downSet           map[string]bool
	upSet             map[string]bool
	configuredHotspot string
	ifaces            []webuiIfaceInfo
	downV4            []*net.IPNet
	downV6            []*net.IPNet
}

const webuiIfaceDetectMaxAge = 3 * time.Minute

type webuiDetectInfo struct {
	Iface              string   `json:"iface"`
	Method             string   `json:"method"`
	Authoritative      bool     `json:"authoritative"`
	Wlan0AP            bool     `json:"wlan0_ap"`
	USBTether          []string `json:"usb_tether"`
	BTTether           []string `json:"bt_tether"`
	Upstream           string   `json:"upstream"`
	TetherUpstream     string   `json:"tether_upstream"`
	LocalUpstream      string   `json:"local_upstream"`
	DefaultRouteIfaces []string `json:"default_route_ifaces"`
	Ts                 int64    `json:"ts"`
}

func isExplicitIdleStateLine(upper string) bool {
	for _, kw := range []string{"IDLE", "PENDING", "INACTIVE", "OFF", "DOWN"} {
		if upper == kw || strings.HasPrefix(upper, kw+":") {
			return true
		}
	}
	return false
}

func readWebUIIfaceDetect(hncDir string, now time.Time) (webuiDetectInfo, bool) {
	var d webuiDetectInfo
	p := filepath.Join(hncDir, "run", "iface_detect.json")
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		return d, false
	}
	b, err := os.ReadFile(p)
	if err != nil || json.Unmarshal(b, &d) != nil || !ifaceNameOK(d.Iface) {
		return webuiDetectInfo{}, false
	}
	fresh := false
	if d.Ts > 0 {
		age := now.Unix() - d.Ts
		fresh = age >= -60 && age <= int64(webuiIfaceDetectMaxAge/time.Second)
	} else {
		fresh = now.Sub(st.ModTime()) <= webuiIfaceDetectMaxAge
	}
	return d, fresh
}

func loadWebUIBoundary(hncDir string) webuiBoundaryEntry {
	webuiBoundaryMu.Lock()
	if e, ok := webuiBoundarySnap[hncDir]; ok && webuiBoundaryTTL > 0 && time.Since(e.at) <= webuiBoundaryTTL {
		webuiBoundaryMu.Unlock()
		return e
	}
	webuiBoundaryMu.Unlock()

	now := time.Now()
	downSet := map[string]bool{}
	upSet := map[string]bool{}
	activeStateSet := map[string]bool{}
	explicitIdle := false

	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "hnc_state")); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			upper := strings.ToUpper(ln)
			if strings.HasPrefix(upper, "ACTIVE:") {
				if v := strings.TrimSpace(ln[len("ACTIVE:"):]); v != "" && ifaceNameOK(v) {
					activeStateSet[v] = true
					explicitIdle = false
				}
			} else if isExplicitIdleStateLine(upper) {
				for k := range activeStateSet {
					delete(activeStateSet, k)
				}
				explicitIdle = true
			}
		}
	}
	readFirstIface := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(hncDir, rel))
		if err != nil {
			return ""
		}
		v := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
		if v != "" && ifaceNameOK(v) {
			return v
		}
		return ""
	}

	det, detFresh := readWebUIIfaceDetect(hncDir, now)

	addCandidateDown := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || !ifaceNameOK(v) || v == "wlan0" {
			return
		}
		downSet[v] = true
	}

	if !explicitIdle {
		for v := range activeStateSet {
			addCandidateDown(v)
		}
		addCandidateDown(readFirstIface(filepath.Join("run", "hotspot_iface")))
		addCandidateDown(readFirstIface(filepath.Join("run", "iface.cache")))
		addCandidateDown(det.Iface)
		for _, u := range det.USBTether {
			addCandidateDown(u)
		}
		for _, bt := range det.BTTether {
			addCandidateDown(bt)
		}

		// 单芯片机型 wlan0 严格活跃热点态门控:
		// 仅当未处于显式空闲/待命态、未被最新探测指认为上游 STA, 且满足
		// hnc_state == "ACTIVE:wlan0" 或新鲜 iface_detect.json 明确 wlan0_ap == true 时才视为下游口。
		wlan0DetectedAsUpstream := false
		if detFresh && !det.Wlan0AP {
			for _, u := range append([]string{det.Upstream, det.TetherUpstream, det.LocalUpstream}, det.DefaultRouteIfaces...) {
				if strings.TrimSpace(u) == "wlan0" {
					wlan0DetectedAsUpstream = true
					break
				}
			}
		}
		if !wlan0DetectedAsUpstream && (activeStateSet["wlan0"] || (detFresh && det.Wlan0AP)) {
			downSet["wlan0"] = true
		}
	}

	upCandidates := []string{
		det.Upstream,
		det.TetherUpstream,
		det.LocalUpstream,
		readFirstIface(filepath.Join("run", "wan_iface")),
	}
	upCandidates = append(upCandidates, det.DefaultRouteIfaces...)
	for _, up := range upCandidates {
		up = strings.TrimSpace(up)
		if up != "" && ifaceNameOK(up) && !downSet[up] {
			upSet[up] = true
		}
	}

	configuredHotspot := ""
	if b, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json")); err == nil {
		var m map[string]interface{}
		if json.Unmarshal(b, &m) == nil {
			if v, ok := m["hotspot_iface"].(string); ok {
				configuredHotspot = strings.TrimSpace(v)
			}
		}
	}

	ifaces := webuiListIfaces()
	var downV4, downV6 []*net.IPNet
	for _, ifi := range ifaces {
		if !ifi.Up || !downSet[ifi.Name] {
			continue
		}
		for _, ipn := range ifi.Addrs {
			if ipn == nil || ipn.IP == nil || ipn.IP.IsLoopback() || ipn.IP.IsUnspecified() || ipn.IP.IsMulticast() {
				continue
			}
			if v4 := ipn.IP.To4(); v4 != nil {
				downV4 = append(downV4, ipn)
			} else if !ipn.IP.IsLinkLocalUnicast() {
				downV6 = append(downV6, ipn)
			}
		}
	}

	e := webuiBoundaryEntry{
		at:                now,
		downSet:           downSet,
		upSet:             upSet,
		configuredHotspot: configuredHotspot,
		ifaces:            ifaces,
		downV4:            downV4,
		downV6:            downV6,
	}
	webuiBoundaryMu.Lock()
	if len(webuiBoundarySnap) > 16 {
		webuiBoundarySnap = map[string]webuiBoundaryEntry{}
	}
	webuiBoundarySnap[hncDir] = e
	webuiBoundaryMu.Unlock()
	return e
}

func isUpstreamWANIface(name string, b webuiBoundaryEntry) bool {
	if name == "" || b.downSet[name] {
		return false
	}
	if isCellIface(name) || isVPNIface(name) || strings.HasPrefix(name, "v4-") || strings.HasPrefix(name, "clat") {
		return true
	}
	if b.upSet[name] {
		return true
	}
	// Android 上 wlan0 默认是连接上游公共/家庭路由器的 Wi-Fi STA 口;
	// 仅当当前确实处于活跃热点态(已在上方命中 b.downSet["wlan0"])时才放行, 绝不凭持久化的 configuredHotspot 永久豁免。
	if name == "wlan0" {
		return true
	}
	return false
}

// webuiRemoteBoundaryAllowed 纵深边界检查:
//  1. 若请求到达的本地目标 IP(http.LocalAddrContextKey)明确属于上游 WAN 接口(如公共 Wi-Fi wlan0、rmnet*、tun*) → 拒绝;
//  2. 若当前存在活跃热点下游子网, 而非回环客户端源 IP 不属于任何活跃热点下游子网 → 拒绝;
//  3. 无活跃热点接口的单测环境(downV4/downV6 均为空且无 WAN localIP)继续放行, 交由后续 mode/allowlist 判定。
func webuiRemoteBoundaryAllowed(hncDir string, client net.IP, dstLocal net.IP) bool {
	if client == nil {
		return false
	}
	b := loadWebUIBoundary(hncDir)

	if dstLocal != nil && !dstLocal.IsLoopback() && !dstLocal.IsUnspecified() {
		hitDown := false
		hitUp := false
		for _, ifi := range b.ifaces {
			if !ifi.Up {
				continue
			}
			owns := false
			for _, ipn := range ifi.Addrs {
				if ipn != nil && ipn.IP != nil && ipn.IP.Equal(dstLocal) {
					owns = true
					break
				}
			}
			if !owns {
				continue
			}
			if b.downSet[ifi.Name] {
				hitDown = true
			} else if isUpstreamWANIface(ifi.Name, b) {
				hitUp = true
			}
		}
		if hitUp && !hitDown {
			return false
		}
	}

	hasActiveDown := len(b.downV4) > 0 || len(b.downV6) > 0
	if !hasActiveDown {
		return true
	}

	if v4 := client.To4(); v4 != nil {
		for _, sub := range b.downV4 {
			if sub.Contains(v4) {
				return true
			}
		}
		return false
	}

	// IPv6 客户端: 链路本地(fe80::/10)没有跨路由器路由能力, 只要目标地址不在上游 WAN 口即允许进入后续白名单判定;
	// 全局/ULA 地址必须落在当前活跃热点下游 IPv6 子网内。
	if client.IsLinkLocalUnicast() {
		return true
	}
	for _, sub := range b.downV6 {
		if sub.Contains(client) {
			return true
		}
	}
	return false
}

// webuiAccessDecision 中间件与测试共用的判定(可选传入请求到达的本地目标 IP 做 WAN 边界校验)。
func webuiAccessDecision(hncDir string, ip net.IP, localIP ...net.IP) bool {
	if isLoopbackIP(ip) {
		return true
	}
	var dstIP net.IP
	if len(localIP) > 0 {
		dstIP = localIP[0]
	}
	if !webuiRemoteBoundaryAllowed(hncDir, ip, dstIP) {
		return false
	}
	cfg := loadWebUIAccess(hncDir)
	switch cfg.Mode {
	case webuiModeAll:
		return true
	case webuiModeAllowlist:
		ok, _ := webuiClientAllowed(ip, cfg.Macs)
		return ok
	default: // local_only / 未知
		return false
	}
}

var webuiDenyLogMu sync.Mutex
var webuiDenyLogAt = map[string]time.Time{}

// webuiAccessGuard 纵深防御中间件(在 authMiddleware 之前)。
func (s *server) webuiAccessGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r.RemoteAddr)
		dstIP := localAddrIP(r)
		if webuiAccessDecision(s.hncDir, ip, dstIP) {
			next.ServeHTTP(w, r)
			return
		}
		key := ipOnly(r.RemoteAddr)
		webuiDenyLogMu.Lock()
		if t, ok := webuiDenyLogAt[key]; !ok || time.Since(t) > time.Minute {
			if len(webuiDenyLogAt) > 256 {
				webuiDenyLogAt = map[string]time.Time{}
			}
			webuiDenyLogAt[key] = time.Now()
			log.Printf("webui_access: denied %s -> %v %s (mode=%s)", key, dstIP, r.URL.Path, loadWebUIAccess(s.hncDir).Mode)
		}
		webuiDenyLogMu.Unlock()
		w.Header().Set("Connection", "close")
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "webui access denied for this client"})
	})
}

// ── /api/config 字段 ───────────────────────────────────────────

type webuiAccessView struct {
	Mode     string   `json:"mode"`
	Macs     []string `json:"macs"`
	Port     int      `json:"port"`
	Firewall string   `json:"firewall"` // run/webui_guard.state 首行(applied/failed 等), 没有则 ""
}

func webuiAccessForConfig(hncDir string) webuiAccessView {
	c := loadWebUIAccess(hncDir)
	v := webuiAccessView{Mode: c.Mode, Macs: c.Macs, Port: 8443}
	if flagPort != nil && *flagPort > 0 {
		v.Port = *flagPort
	}
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "webui_guard.state")); err == nil {
		v.Firewall = strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
	}
	if v.Macs == nil {
		v.Macs = []string{}
	}
	return v
}

// ── action: webui_access_set {mode, macs?} ────────────────────

func actionWebUIAccessSet(s *server, p map[string]string) actionResp {
	mode := strings.TrimSpace(p["mode"])
	switch mode {
	case webuiModeAll, webuiModeAllowlist, webuiModeLocalOnly:
	default:
		return actionResp{OK: false, Error: "bad params", Detail: "mode must be all|allowlist|local_only"}
	}
	cur := loadWebUIAccess(s.hncDir)
	entries := cur.Macs
	if raw, ok := p["macs"]; ok {
		list, bad := normalizeAllowEntries(raw)
		if bad != "" {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid MAC/IP entry: " + bad}
		}
		entries = list
	}
	if len(entries) > webuiAccessMaxList {
		return actionResp{OK: false, Error: "bad params", Detail: fmt.Sprintf("too many entries (max %d)", webuiAccessMaxList)}
	}
	// 自锁保护: 远程请求不能提交一个把自己挡在外面的配置(空白名单 = 只放行本机,
	// 只能在本机提交)。_client_ip 由 handleAction 从 RemoteAddr 注入, 不信任客户端。
	ip := clientIP(strings.TrimSpace(p[webuiClientIPParam]))
	if !isLoopbackIP(ip) {
		ipStr := "unknown"
		if ip != nil {
			ipStr = ip.String()
		}
		switch mode {
		case webuiModeLocalOnly:
			return actionResp{OK: false, Error: "self_lockout",
				Detail: "local_only would immediately lock out this remote client (ip " + ipStr + "); switch to local_only from the device itself (KSU WebUI)"}
		case webuiModeAllowlist:
			if ok, mac := webuiClientAllowed(ip, entries); !ok {
				who := "ip " + ipStr
				if mac != "" {
					who += ", mac " + mac
				}
				return actionResp{OK: false, Error: "self_lockout",
					Detail: "allowlist does not include the requesting client (" + who + "); add it to the list or apply from the device itself (KSU WebUI)"}
			}
		}
	}

	cfg := webuiAccessCfg{Mode: mode, Macs: entries, Updated: time.Now().Unix()}
	if err := saveWebUIAccess(s.hncDir, cfg); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	// 防火墙层; 失败不回滚(Go 层已按新配置生效), 但如实告知
	rc, out := runBin(s.hncDir, "webui_guard.sh", "apply")
	last := strings.TrimSpace(out)
	if i := strings.LastIndexByte(last, '\n'); i >= 0 {
		last = last[i+1:]
	}
	if rc != 0 {
		return actionResp{OK: true, Detail: "saved (mode=" + mode + "); firewall apply failed, HTTP-level guard active: " + last}
	}
	return actionResp{OK: true, Detail: "webui access mode=" + mode + fmt.Sprintf(" entries=%d", len(entries)) + "; " + last}
}
