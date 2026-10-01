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
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
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
		return err
	}
	return os.Rename(tmp, p)
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

// ── 客户端身份 ─────────────────────────────────────────────────

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

func isLoopbackIP(ip net.IP) bool { return ip != nil && ip.IsLoopback() }

// 邻居表来源(测试替换为 fixture)
var (
	neighArpPath = "/proc/net/arp"
	neighV6Dump  = func() (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		out, err := hardenCmd(exec.CommandContext(ctx, "ip", "-6", "neigh", "show")).Output()
		return string(out), err
	}
	neighCacheTTL = 2 * time.Second
)

var (
	neighMu      sync.Mutex
	neighSnap    map[string]string // ip(规范文本) → mac
	neighSnapAt  time.Time
	neighSnapSrc string // 快照对应的 arp 路径(测试切换 fixture 时失效)
)

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
		if ip == nil || !macRE.MatchString(mac) || mac == "00:00:00:00:00:00" {
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
		if out, err := neighV6Dump(); err == nil {
			parseNeigh6(out, m)
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

// webuiAccessDecision 中间件与测试共用的判定。
func webuiAccessDecision(hncDir string, ip net.IP) bool {
	if isLoopbackIP(ip) {
		return true
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
		if webuiAccessDecision(s.hncDir, ip) {
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
			log.Printf("webui_access: denied %s %s (mode=%s)", key, r.URL.Path, loadWebUIAccess(s.hncDir).Mode)
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
