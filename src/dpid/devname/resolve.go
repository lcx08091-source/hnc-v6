// Package devname —— v5.31 T2(迁移 M4 方案 A): Go 版设备名解析。
//
// 优先级与输出照搬 C 版 hotspotd 的 resolve_hostname(WORK-v5.31 §1.1 的
// 1–6 级; v5.33 起 C 版发现已删, 这里是唯一一份):
//  1. 手动名   data/device_names.json           → hostname_src = "manual"
//  2. DHCP     exec dumpsys network_stack(500ms) → "dhcp"
//  3. mDNS     exec bin/mdns_resolve -t 800 <ip> → "mdns"
//  4. 缓存     data/hostname_cache.json          → "cache-<原src>"
//  5. 厂商     oui_overrides.json + 内置 OUI 表  → "oui"(输出 "<Vendor> 设备")
//  6. MAC 兜底 去冒号取后 8 位                    → "mac"
//
// 垃圾名(null / localhost / 纯数字 …)在 DHCP、mDNS、缓存回放三处挡
// (hnc.io/dpid/hostname)。2、3 命中时更新缓存。5 的用户覆盖
// (data/oui_overrides.json)优先于内置表, 且不受随机 MAC(LAA)跳过约束。
// 内置 OUI 表就是 oui_table.txt(v5.31 从 C 表抽出, v5.33 起是唯一数据源)。
// 外部命令参数分开传、带超时, 不经 shell。
package devname

import (
	"bytes"
	"context"
	"embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"hnc.io/dpid/hostname"
)

//go:embed oui_table.txt
var ouiFS embed.FS

const (
	// HNLen 与 C 的 HNC_HN_LEN 对齐(64); 超长截断。
	HNLen = 64
	// cacheMaxEntries 与 C 的 HNC_CACHE_MAX_ENTRIES 对齐。
	cacheMaxEntries = 1024
	// dumpsysTimeout 适度放宽至 1000ms, 降低高负载下 Binder 调用误超时概率。
	dumpsysTimeout = 1000 * time.Millisecond
	// mdnsTimeout: 外部二进制自带 -t 800ms; 外层再多给 200ms 余量。
	mdnsTimeout = 1 * time.Second

	mdnsPort         = 5353
	mdnsMulticastIP  = "224.0.0.251"
	mdnsStageTimeout = 400 * time.Millisecond
	mdnsMaxNameJumps = 16
	mdnsMaxNameLen   = 255
)

// OUI 内置表(启动时从嵌入数据构建, 排序后二分)。
var (
	ouiOnce  sync.Once
	ouiKeys  []uint32
	ouiVends []string
)

func loadOUI() {
	ouiOnce.Do(func() {
		b, err := ouiFS.ReadFile("oui_table.txt")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(b), "\n") {
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) != 2 || len(parts[0]) != 6 {
				continue
			}
			v, err := strconv.ParseUint(parts[0], 16, 32)
			if err != nil {
				continue
			}
			ouiKeys = append(ouiKeys, uint32(v))
			ouiVends = append(ouiVends, parts[1])
		}
	})
}

// LookupOUI 厂商名(不含用户覆盖)。随机 MAC(byte0 bit1 = locally
// administered)不查内置表 —— 查了也是伪造厂商(hnc_lookup_oui 同款)。
// 返回 "<Vendor> 设备"; 没有则 false。
func LookupOUI(mac string) (string, bool) {
	loadOUI()
	b := macBytes(mac)
	if b == nil || b[0]&0x02 != 0 {
		return "", false // 随机 MAC → 走 mac 兜底
	}
	key := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	i := sort.Search(len(ouiKeys), func(i int) bool { return ouiKeys[i] >= key })
	if i < len(ouiKeys) && ouiKeys[i] == key {
		return ouiVends[i] + " 设备", true
	}
	return "", false
}

// macBytes "aa:bb:cc:dd:ee:ff" → 6 字节; 非法返回 nil。
func macBytes(mac string) []byte {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return nil
	}
	var b [6]byte
	for i, p := range parts {
		if len(p) != 2 {
			return nil
		}
		hi, lo := hexVal(p[0]), hexVal(p[1])
		if hi < 0 || lo < 0 {
			return nil
		}
		b[i] = byte(hi<<4 | lo)
	}
	return b[:]
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// MACFallback 与 hnc_mac_fallback 输出一致: 去冒号取后 8 位
// ("02:5a:00:00:00:03" → "00000003")。
func MACFallback(mac string) string {
	noColon := strings.Map(func(r rune) rune {
		if r == ':' {
			return -1
		}
		return r
	}, mac)
	if len(noColon) > 8 {
		return noColon[len(noColon)-8:]
	}
	return noColon
}

// Resolver 解析链。零值即可用(全 miss → mac 兜底); 路径 / 命令可注入,
// 单测用假实现。
type Resolver struct {
	NamesPath     string // data/device_names.json
	DevIDPath     string // run/dpi_devid.json (hnc_dpid 被动嗅探主机名)
	CachePath     string // data/hostname_cache.json
	OverridesPath string // data/oui_overrides.json
	MDNSBin       string // bin/mdns_resolve

	// 注入点(单测替换; 生产为纯 Go mDNS / exec)
	RunDumpsys          func() ([]byte, error)
	RunMDNS             func(ip string) ([]byte, error)
	Now                 func() time.Time
	NativeMDNS          bool
	mdnsUnicastTargetFn func(ip net.IP) *net.UDPAddr
	mdnsMulticastTarget *net.UDPAddr
	mdnsQueryOnceFn     func(ctx context.Context, qname string, dst *net.UDPAddr, multicast bool, timeout time.Duration) (string, bool, error)

	cacheMu    sync.Mutex
	cacheLoad  bool
	cacheTab   map[string]cacheEntry
	cacheDirty bool
}

type cacheEntry struct {
	H string `json:"h"`
	S string `json:"s"`
	T int64  `json:"t"`
}

// Resolve 完整六级链(同 C resolve_hostname 的顺序与输出)。
// ip 为空时跳过 mDNS(与 C 一致)。
func (r *Resolver) Resolve(mac, ip string) (string, string) {
	return r.ResolveContext(context.Background(), mac, ip)
}

// ResolveContext 带上下文取消的完整解析链; ctx 取消后立即中止在途外部子进程
// 或 UDP 查询, 不阻塞看门狗停机。
func (r *Resolver) ResolveContext(ctx context.Context, mac, ip string) (string, string) {
	if ctx == nil {
		ctx = context.Background()
	}
	mac = strings.ToLower(strings.TrimSpace(mac))
	// 1. 手动名
	if hn, ok := LookupManual(mac, r.NamesPath); ok {
		return hn, "manual"
	}
	// 1.5 hnc_dpid 被动嗅探主机名(run/dpi_devid.json: DHCP Opt12 / DHCPv6 / mDNS / NBNS)
	if ctx.Err() == nil {
		if hn, src, ok := LookupDevID(mac, r.DevIDPath); ok {
			r.CacheUpdate(mac, hn, src)
			return hn, src
		}
	}
	// 2. DHCP(dumpsys network_stack, 超时 1000ms)
	if ctx.Err() == nil {
		if hn, ok := r.tryDHCP(ctx, mac); ok {
			r.CacheUpdate(mac, hn, "dhcp")
			return hn, "dhcp"
		}
	}
	// 3. mDNS(只在有 IP 时; 纯 Go UDP 5353 PTR 单播+组播, 异常回退 mdns_resolve)
	if ip != "" && ctx.Err() == nil {
		if hn, ok := r.tryMDNS(ctx, ip); ok {
			r.CacheUpdate(mac, hn, "mdns")
			return hn, "mdns"
		}
	}
	// 4. 缓存回放(src 带 cache- 前缀)
	if hn, src, ok := r.cacheLookup(mac); ok {
		return hn, "cache-" + src
	}
	// 5. 厂商(用户覆盖优先, 不受 LAA 约束; 内置表跳过随机 MAC)
	if hn, ok := LookupOverride(mac, r.OverridesPath); ok {
		return hn, "oui"
	}
	if hn, ok := LookupOUI(mac); ok {
		return hn, "oui"
	}
	// 6. MAC 兜底
	return MACFallback(mac), "mac"
}

// LookupDevID 读取 hnc_dpid 被动嗅探落盘的 run/dpi_devid.json, 提取对应 MAC 的有效非垃圾主机名。
func LookupDevID(mac, devIDPath string) (string, string, bool) {
	if devIDPath == "" || mac == "" {
		return "", "", false
	}
	b, err := os.ReadFile(devIDPath)
	if err != nil || len(b) == 0 || len(b) > 4<<20 {
		return "", "", false
	}
	var f struct {
		Schema  int `json:"schema"`
		Devices map[string]struct {
			Hostname    string `json:"hostname"`
			HostnameSrc string `json:"hostname_src"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(b, &f); err != nil || len(f.Devices) == 0 {
		return "", "", false
	}
	macLC := strings.ToLower(strings.TrimSpace(mac))
	entry, ok := f.Devices[macLC]
	if !ok {
		for k, v := range f.Devices {
			if strings.EqualFold(strings.TrimSpace(k), macLC) {
				entry = v
				ok = true
				break
			}
		}
	}
	if !ok {
		return "", "", false
	}
	hn := stripLocalSuffix(entry.Hostname)
	if hn == "" || hostname.IsJunk(hn) || len(hn) > HNLen {
		return "", "", false
	}
	src := strings.ToLower(strings.TrimSpace(entry.HostnameSrc))
	switch src {
	case "dhcp", "dhcpv6", "mdns", "nbns":
	default:
		src = "dhcp"
	}
	return hn, src, true
}

// LookupManual 与 hnc_lookup_manual_name 一致: 容错的子串匹配
// "「mac」 : 「name」"(mac 大小写不敏感, 冒号两侧容忍空白, value 做
// JSON 反转义), 取第一条命中。
func LookupManual(mac, namesPath string) (string, bool) {
	if namesPath == "" {
		return "", false
	}
	b, err := os.ReadFile(namesPath)
	if err != nil || len(b) == 0 {
		return "", false
	}
	key := `"` + strings.ToLower(mac) + `"`
	// 只在「找 MAC」时不分大小写(C 是逐字节 tolower 比较); 名字从原文取, 不能跟着
	// 变小写(v5.31 审查: 「客厅的Mac」曾变成「客厅的mac」)。只折叠 ASCII 字母,
	// 字节偏移与原文一一对应。
	orig := string(b)
	s := asciiLower(orig)
	off := 0
	for {
		i := strings.Index(s[off:], key)
		if i < 0 {
			return "", false
		}
		i += off
		p := i + len(key)
		for p < len(s) && (s[p] == ' ' || s[p] == '\t' || s[p] == '\n' || s[p] == '\r') {
			p++
		}
		if p >= len(s) || s[p] != ':' {
			off = i + len(key) // 是 value 里的字符串, 继续找下一个 key
			continue
		}
		p++
		for p < len(s) && (s[p] == ' ' || s[p] == '\t' || s[p] == '\n' || s[p] == '\r') {
			p++
		}
		if p >= len(s) || s[p] != '"' {
			return "", false
		}
		p++
		var out []byte
		for p < len(orig) {
			c := orig[p]
			if c == '"' {
				break
			}
			if c == '\\' && p+1 < len(orig) {
				p++
				switch orig[p] {
				case 'n':
					out = append(out, '\n')
				case 'r':
					out = append(out, '\r')
				case 't':
					out = append(out, '\t')
				case 'u':
					if p+4 < len(orig) {
						if v, err := strconv.ParseUint(orig[p+1:p+5], 16, 32); err == nil {
							// 与 C 的对称编解码一致: BMP 内按 UTF-8 编出
							out = appendRune(out, rune(v))
							p += 4
						}
					}
				default:
					out = append(out, orig[p]) // \" \\ 等
				}
				p++
				continue
			}
			out = append(out, c)
			p++
		}
		hn := strings.TrimSpace(string(out))
		if hn != "" {
			return hn, true
		}
		return "", false
	}
}

// asciiLower 只把 A–Z 变小写(长度不变, 偏移可与原文对照)。
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func appendRune(out []byte, r rune) []byte {
	switch {
	case r < 0x80:
		out = append(out, byte(r))
	case r < 0x800:
		out = append(out, byte(0xC0|r>>6), byte(0x80|r&0x3F))
	default:
		out = append(out, byte(0xE0|r>>12), byte(0x80|r>>6&0x3F), byte(0x80|r&0x3F))
	}
	return out
}

// tryDHCP 与 hnc_ns_dhcp_pick_hostname + try_ns_dhcp_resolve 一致:
// dumpsys network_stack 输出里, 同一行既有 MAC(大小写不敏感)又有
// "hostname: ", 取提取值(到 \r / , / 行尾, 去尾部空白), 多条取最后一条
// 非垃圾名。
func (r *Resolver) tryDHCP(ctx context.Context, mac string) (string, bool) {
	out := r.dhcpOut(ctx)
	if len(out) == 0 {
		return "", false
	}
	macLC := strings.ToLower(mac)
	latest := ""
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(strings.ToLower(line), macLC) {
			continue
		}
		p := strings.Index(line, "hostname: ")
		if p < 0 {
			continue
		}
		p += len("hostname: ")
		hn := line[p:]
		if i := strings.IndexAny(hn, "\r,"); i >= 0 {
			hn = hn[:i]
		}
		hn = strings.TrimRight(hn, " \t")
		if hn != "" && !hostname.IsJunk(hn) && len(hn) <= HNLen {
			latest = hn
		}
	}
	if latest == "" {
		return "", false
	}
	return latest, true
}

func (r *Resolver) dhcpOut(ctx context.Context) []byte {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return nil
	}
	if r.RunDumpsys != nil {
		b, _ := r.RunDumpsys()
		return b
	}
	subCtx, cancel := context.WithTimeout(ctx, dumpsysTimeout)
	defer cancel()
	cmd := exec.CommandContext(subCtx, "dumpsys", "network_stack")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = time.Second
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	return b
}

// tryMDNS 优先走 RunMDNS 测试钩子; 生产默认路径用纯 Go net.UDPConn 执行
// .in-addr.arpa PTR 单播(<ip>:5353) + 组播(224.0.0.251:5353) 查询,
// 若底层 UDP 套接字/发送失败且外部 MDNSBin 存在则平滑回退 mdns_resolve 二进制。
// 当 MDNSBin 设为空或不存在的假路径(如单测 .../no_mdns_resolve)且未显式开启 NativeMDNS 时立即跳过。
func (r *Resolver) tryMDNS(ctx context.Context, ip string) (string, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return "", false
	}
	if r.RunMDNS != nil {
		out, err := r.RunMDNS(ip)
		if err != nil {
			return "", false
		}
		return cleanMDNSHostname(string(out))
	}

	hasBin := false
	if r.MDNSBin != "" {
		if fi, err := os.Stat(r.MDNSBin); err == nil && !fi.IsDir() {
			hasBin = true
		}
	}
	if !r.NativeMDNS && !hasBin {
		return "", false
	}

	pip := net.ParseIP(strings.TrimSpace(ip))
	if pip == nil || pip.To4() == nil { // 与 C 的 inet_pton 防御一致
		return "", false
	}
	ip4 := pip.To4()

	hn, ok, sockErr := r.queryMDNSNative(ctx, ip4)
	if ok {
		if clean, valid := cleanMDNSHostname(hn); valid {
			return clean, true
		}
	}
	if sockErr != nil && hasBin && ctx.Err() == nil {
		out, err := r.execMDNSBin(ctx, ip4.String())
		if err == nil {
			return cleanMDNSHostname(string(out))
		}
	}
	return "", false
}

func cleanMDNSHostname(raw string) (string, bool) {
	hn := strings.TrimRight(raw, "\n\r")
	hn = stripLocalSuffix(hn)
	if hn == "" || hostname.IsJunk(hn) || len(hn) > HNLen {
		return "", false
	}
	return hn, true
}

func stripLocalSuffix(name string) string {
	name = strings.TrimRight(strings.TrimSpace(name), ".")
	if len(name) > 6 && strings.EqualFold(name[len(name)-6:], ".local") {
		name = name[:len(name)-6]
	}
	return strings.TrimSpace(name)
}

func (r *Resolver) execMDNSBin(ctx context.Context, ip string) ([]byte, error) {
	subCtx, cancel := context.WithTimeout(ctx, mdnsTimeout)
	defer cancel()
	cmd := exec.CommandContext(subCtx, r.MDNSBin, "-t", "800", ip)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = time.Second
	return cmd.Output()
}

func (r *Resolver) queryMDNSNative(ctx context.Context, ip4 net.IP) (string, bool, error) {
	qname := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", ip4[3], ip4[2], ip4[1], ip4[0])
	queryFn := r.mdnsQueryOnceFn
	if queryFn == nil {
		queryFn = queryMDNSOnce
	}

	var uniDst *net.UDPAddr
	if r.mdnsUnicastTargetFn != nil {
		uniDst = r.mdnsUnicastTargetFn(ip4)
	} else {
		uniDst = &net.UDPAddr{IP: ip4, Port: mdnsPort}
	}
	if hn, ok, uErr := queryFn(ctx, qname, uniDst, false, mdnsStageTimeout); ok {
		return hn, true, nil
	} else if ctx.Err() != nil {
		return "", false, nil
	} else {
		mcastDst := r.mdnsMulticastTarget
		if mcastDst == nil {
			mcastDst = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: mdnsPort}
		}
		hn2, ok2, mErr := queryFn(ctx, qname, mcastDst, true, mdnsStageTimeout)
		if ok2 {
			return hn2, true, nil
		}
		if uErr != nil {
			return "", false, uErr
		}
		return "", false, mErr
	}
}

func queryMDNSOnce(ctx context.Context, qname string, dst *net.UDPAddr, multicast bool, timeout time.Duration) (string, bool, error) {
	if ctx.Err() != nil {
		return "", false, nil
	}
	txid := uint16(time.Now().UnixNano() ^ int64(os.Getpid()<<8))
	req, ok := buildMDNSPTRQuery(qname, txid)
	if !ok {
		return "", false, nil
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return "", false, err
	}
	defer conn.Close()

	if multicast {
		if raw, err := conn.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 255)
			})
		}
	}

	deadline := time.Now().Add(timeout)
	if ctxDL, hasDL := ctx.Deadline(); hasDL && ctxDL.Before(deadline) {
		deadline = ctxDL
	}
	_ = conn.SetDeadline(deadline)

	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stopWatch:
		}
	}()

	if _, err := conn.WriteToUDP(req, dst); err != nil {
		if ctx.Err() != nil {
			return "", false, nil
		}
		return "", false, err
	}

	var buf [1500]byte
	for {
		n, _, rerr := conn.ReadFromUDP(buf[:])
		if rerr != nil {
			if ne, isNet := rerr.(net.Error); isNet && ne.Timeout() {
				return "", false, nil
			}
			if ctx.Err() != nil {
				return "", false, nil
			}
			return "", false, rerr
		}
		if hn, matched := parseMDNSPTRResponse(buf[:n], qname); matched {
			return hn, true, nil
		}
	}
}

func encodeDNSName(name string) ([]byte, bool) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" || len(name) > mdnsMaxNameLen {
		return nil, false
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, false
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out, true
}

func buildMDNSPTRQuery(qname string, txid uint16) ([]byte, bool) {
	enc, ok := encodeDNSName(qname)
	if !ok {
		return nil, false
	}
	pkt := make([]byte, 12+len(enc)+4)
	binary.BigEndian.PutUint16(pkt[0:2], txid)
	binary.BigEndian.PutUint16(pkt[4:6], 1) // QDCOUNT = 1
	copy(pkt[12:], enc)
	pos := 12 + len(enc)
	binary.BigEndian.PutUint16(pkt[pos:pos+2], 0x000C)   // PTR
	binary.BigEndian.PutUint16(pkt[pos+2:pos+4], 0x0001) // IN
	return pkt, true
}

// decodeDNSName 解码 DNS 域名(含 0xC0 压缩指针); 严格要求压缩指针 ptr < cur 防自环与前跳放大。
func decodeDNSName(pkt []byte, startOff int) (string, int, bool) {
	var buf bytes.Buffer
	cur := startOff
	jumps := 0
	jumped := false
	nextOff := 0
	for {
		if cur < 0 || cur >= len(pkt) {
			return "", 0, false
		}
		l := int(pkt[cur])
		if l == 0 {
			cur++
			break
		}
		if l&0xC0 == 0xC0 {
			if cur+1 >= len(pkt) {
				return "", 0, false
			}
			ptr := ((l & 0x3F) << 8) | int(pkt[cur+1])
			if !jumped {
				nextOff = cur + 2
				jumped = true
			}
			jumps++
			if jumps > mdnsMaxNameJumps || ptr >= cur || ptr >= len(pkt) {
				return "", 0, false
			}
			cur = ptr
			continue
		}
		if l&0xC0 != 0 || l > 63 || cur+1+l > len(pkt) {
			return "", 0, false
		}
		if buf.Len()+l+1 > mdnsMaxNameLen {
			return "", 0, false
		}
		if buf.Len() > 0 {
			buf.WriteByte('.')
		}
		buf.Write(pkt[cur+1 : cur+1+l])
		cur += 1 + l
	}
	if !jumped {
		nextOff = cur
	}
	return buf.String(), nextOff, true
}

// parseMDNSPTRResponse 解析 mDNS 响应并校验 rname 匹配 expectedRName(防组播伪造)。
func parseMDNSPTRResponse(pkt []byte, expectedRName string) (string, bool) {
	if len(pkt) < 12 {
		return "", false
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&0x8000 == 0 { // QR 必须为 1(Response)
		return "", false
	}
	qdcount := int(binary.BigEndian.Uint16(pkt[4:6]))
	ancount := int(binary.BigEndian.Uint16(pkt[6:8]))
	if ancount == 0 {
		return "", false
	}
	off := 12
	for i := 0; i < qdcount; i++ {
		var ok bool
		_, off, ok = decodeDNSName(pkt, off)
		if !ok || off+4 > len(pkt) {
			return "", false
		}
		off += 4
	}
	wantName := strings.TrimSuffix(expectedRName, ".")
	for i := 0; i < ancount; i++ {
		rname, nextOff, ok := decodeDNSName(pkt, off)
		if !ok || nextOff+10 > len(pkt) {
			return "", false
		}
		rtype := binary.BigEndian.Uint16(pkt[nextOff : nextOff+2])
		rdlen := int(binary.BigEndian.Uint16(pkt[nextOff+8 : nextOff+10]))
		rdataOff := nextOff + 10
		if rdataOff+rdlen > len(pkt) {
			return "", false
		}
		off = rdataOff + rdlen
		if wantName != "" && !strings.EqualFold(strings.TrimSuffix(rname, "."), wantName) {
			continue
		}
		if rtype == 0x000C { // PTR
			target, afterRdata, ok := decodeDNSName(pkt, rdataOff)
			if !ok || afterRdata > rdataOff+rdlen {
				return "", false
			}
			hn := stripLocalSuffix(target)
			if hn != "" {
				return hn, true
			}
			return "", false
		}
	}
	return "", false
}

// LookupOverride 与 hnc_override_lookup 一致: {"<前缀>":"<标签>"},
// 前缀可带冒号(28:6c:07 / 286c07 都行, 标准化成 6 位小写 hex),
// 线性扫描, 重复以后写为准。
func LookupOverride(mac, overridesPath string) (string, bool) {
	if overridesPath == "" {
		return "", false
	}
	b, err := os.ReadFile(overridesPath)
	if err != nil {
		return "", false
	}
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		return "", false
	}
	prefix := overrideKey(mac, 6)
	if prefix == "" {
		return "", false
	}
	if label, ok := m[prefix]; ok && label != "" {
		return label, true
	}
	return "", false
}

func overrideKey(mac string, n int) string {
	var buf []byte
	for i := 0; i < len(mac) && len(buf) < n; i++ {
		c := mac[i]
		if c == ':' || c == '-' {
			continue
		}
		if hexVal(c) < 0 {
			return ""
		}
		buf = append(buf, c)
	}
	if len(buf) != n {
		return ""
	}
	return strings.ToLower(string(buf))
}

// ─── hostname cache(data/hostname_cache.json) ─────────────────────
// 格式与 C 的 hostname_cache.c 完全一致:
//   {"<mac>":{"h":"名字","s":"来源","t":<unix 秒>}}
// 只有当前写者写; tmp 文件名 .tmp.go 与 C 的 .tmp.<pid> 区分。

// CacheLookup 回放缓存(hnc_cache_lookup: 垃圾名不回放)。
func (r *Resolver) cacheLookup(mac string) (string, string, bool) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if err := r.loadCacheLocked(); err != nil {
		return "", "", false
	}
	e, ok := r.cacheTab[mac]
	if !ok || hostname.IsJunk(e.H) {
		return "", "", false
	}
	return e.H, e.S, true
}

// CacheUpdate 写缓存(hnc_cache_update: 垃圾名不进缓存)。
func (r *Resolver) CacheUpdate(mac, hn, src string) {
	if mac == "" || hn == "" || src == "" || hostname.IsJunk(hn) {
		return
	}
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if err := r.loadCacheLocked(); err != nil {
		return // 缓存坏了不影响解析主链
	}
	r.cacheTab[mac] = cacheEntry{H: hn, S: src, T: r.now().Unix()}
	r.cacheDirty = true
	if len(r.cacheTab) > cacheMaxEntries {
		r.evictOldestLocked()
	}
}

func (r *Resolver) evictOldestLocked() {
	var oldestKey string
	var oldest int64 = -1
	for k, e := range r.cacheTab {
		if oldest == -1 || e.T < oldest {
			oldestKey, oldest = k, e.T
		}
	}
	delete(r.cacheTab, oldestKey)
}

// CacheSave 落盘(原子替换)。设备离线 / 退出前调; C 也是 dirty 才存。
func (r *Resolver) CacheSave() error {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if !r.cacheDirty || r.CachePath == "" {
		return nil
	}
	if err := r.loadCacheLocked(); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	first := true
	keys := make([]string, 0, len(r.cacheTab))
	for k := range r.cacheTab {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := r.cacheTab[k]
		if !first {
			buf.WriteByte(',')
		}
		first = false
		hn, _ := json.Marshal(e.H)
		src, _ := json.Marshal(e.S)
		fmt.Fprintf(&buf, "%q:{\"h\":%s,\"s\":%s,\"t\":%d}", k, hn, src, e.T)
	}
	buf.WriteString("}\n")
	tmp := fmt.Sprintf("%s.tmp.go.%d.%d", r.CachePath, os.Getpid(), time.Now().UnixNano()&0xfffffff)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
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
	if err := os.Rename(tmp, r.CachePath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	r.cacheDirty = false
	return nil
}

// loadCacheLocked 首次访问时读文件(坏了当空, 不修 —— 只有一个写者,
// 坏文件留给用户看; hnc_cache_load 同样不 crash)。
func (r *Resolver) loadCacheLocked() error {
	if r.cacheLoad {
		return nil
	}
	r.cacheTab = map[string]cacheEntry{}
	if r.CachePath == "" {
		r.cacheLoad = true
		return nil
	}
	b, err := os.ReadFile(r.CachePath)
	if err != nil {
		r.cacheLoad = true
		return nil
	}
	m := map[string]cacheEntry{}
	_ = json.Unmarshal(b, &m) // 坏文件当空(只有一个写者, 不在这里修)
	r.cacheTab = m
	r.cacheLoad = true
	return nil
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
