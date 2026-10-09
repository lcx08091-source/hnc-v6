// Package devname —— v5.31 T2(迁移 M4 方案 A): Go 版设备名解析。
//
// 优先级与输出和 C 版 hotspotd 完全一致(resolve_hostname, hotspotd.c;
// WORK-v5.31 §1.1 的 1–6 级):
//  1. 手动名   data/device_names.json           → hostname_src = "manual"
//  2. DHCP     exec dumpsys network_stack(500ms) → "dhcp"
//  3. mDNS     exec bin/mdns_resolve -t 800 <ip> → "mdns"
//  4. 缓存     data/hostname_cache.json          → "cache-<原src>"
//  5. 厂商     oui_overrides.json + 内置 OUI 表  → "oui"(输出 "<Vendor> 设备")
//  6. MAC 兜底 去冒号取后 8 位                    → "mac"
//
// 垃圾名(null / localhost / 纯数字 …)在 DHCP、mDNS、缓存回放三处挡
// (hnc_hostname_is_junk, Go 侧同一张表 hnc.io/dpid/hostname)。
// 2、3 命中时更新缓存(只有当前写者写, tmp 名与 C 的 .tmp.<pid> 区分)。
// 5 的用户覆盖(data/oui_overrides.json)优先于内置表, 且不受随机 MAC(LAA)
// 跳过约束 —— 都与 hnc_lookup_oui 对齐。外部命令参数分开传、带超时,
// 不经 shell。
package devname

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	// dumpsysTimeout 与 C 的 500ms select 超时对齐。
	dumpsysTimeout = 500 * time.Millisecond
	// mdnsTimeout: 二进制自带 -t 800ms; 外层再多给 200ms 余量。
	mdnsTimeout = 1 * time.Second
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

// Resolver 六级链。零值即可用(全 miss → mac 兜底); 路径 / 命令可注入,
// 单测用假实现。
type Resolver struct {
	NamesPath     string // data/device_names.json
	CachePath     string // data/hostname_cache.json
	OverridesPath string // data/oui_overrides.json
	MDNSBin       string // bin/mdns_resolve

	// 注入点(单测替换; 生产为 exec)
	RunDumpsys func() ([]byte, error)
	RunMDNS    func(ip string) ([]byte, error)
	Now        func() time.Time

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
	mac = strings.ToLower(strings.TrimSpace(mac))
	// 1. 手动名
	if hn, ok := LookupManual(mac, r.NamesPath); ok {
		return hn, "manual"
	}
	// 2. DHCP(被动数据, ~35ms; 超时 500ms)
	if hn, ok := r.tryDHCP(mac); ok {
		r.CacheUpdate(mac, hn, "dhcp")
		return hn, "dhcp"
	}
	// 3. mDNS(只在有 IP 时; 二进制自带 -t 800)
	if ip != "" {
		if hn, ok := r.tryMDNS(ip); ok {
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
	s := strings.ToLower(string(b))
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
		for p < len(s) {
			c := s[p]
			if c == '"' {
				break
			}
			if c == '\\' && p+1 < len(s) {
				p++
				switch s[p] {
				case 'n':
					out = append(out, '\n')
				case 'r':
					out = append(out, '\r')
				case 't':
					out = append(out, '\t')
				case 'u':
					if p+4 < len(s) {
						if v, err := strconv.ParseUint(s[p+1:p+5], 16, 32); err == nil {
							// 与 C 的对称编解码一致: BMP 内按 UTF-8 编出
							out = appendRune(out, rune(v))
							p += 4
						}
					}
				default:
					out = append(out, s[p]) // \" \\ 等
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
func (r *Resolver) tryDHCP(mac string) (string, bool) {
	out := r.dhcpOut()
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

func (r *Resolver) dhcpOut() []byte {
	if r.RunDumpsys != nil {
		b, _ := r.RunDumpsys()
		return b
	}
	ctx, cancel := context.WithTimeout(context.Background(), dumpsysTimeout)
	defer cancel()
	b, err := exec.CommandContext(ctx, "dumpsys", "network_stack").Output()
	if err != nil {
		return nil
	}
	return b
}

// tryMDNS 与 try_mdns_resolve 一致: exit 0 才信输出, 去尾部换行,
// 垃圾名当作没解析到。
func (r *Resolver) tryMDNS(ip string) (string, bool) {
	var (
		out []byte
		err error
	)
	if r.RunMDNS != nil {
		out, err = r.RunMDNS(ip)
		if err != nil {
			return "", false
		}
	} else {
		if r.MDNSBin == "" {
			return "", false
		}
		if pip := net.ParseIP(ip); pip == nil || pip.To4() == nil { // 与 C 的 inet_pton 防御一致
			return "", false
		}
		ctx, cancel := context.WithTimeout(context.Background(), mdnsTimeout)
		defer cancel()
		out, err = exec.CommandContext(ctx, r.MDNSBin, "-t", "800", ip).Output()
		if err != nil {
			return "", false
		}
	}
	hn := strings.TrimRight(string(out), "\n\r")
	hn = strings.TrimSpace(hn)
	if hn == "" || hostname.IsJunk(hn) || len(hn) > HNLen {
		return "", false
	}
	return hn, true
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
	tmp := r.CachePath + ".tmp.go"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
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
