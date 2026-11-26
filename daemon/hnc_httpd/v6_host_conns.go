// v6_host_conns.go — HNC v6.1.0 · Vector:
// 手机本机实时 Socket 五元组解析 (/proc/net/{tcp,tcp6,udp,udp6}) +
// 零 app_process UID->包名/中文应用名缓存解析器 + 四路内存 JOIN +
// L1 明文风险标记 + 纯 Go NETLINK_SOCK_DIAG (SOCK_DESTROY=21) 微秒级断流器 +
// 本机 filter/OUTPUT 独立子链 HNC_SCALPEL_HOST 五道防自锁安全门禁。

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"hnc.io/dpid/appmeta"
)

const (
	scalpelHostChainName       = "HNC_SCALPEL_HOST"
	scalpelHostScopeHotspot    = "hotspot"
	scalpelHostScopeHost       = "host"
	scalpelHostScopeAll        = "all"
	scalpelHostNetlinkSockDiag = 4  // NETLINK_SOCK_DIAG (linux/netlink.h)
	scalpelHostSockDestroyType = 21 // SOCK_DESTROY (linux/sock_diag.h)
	scalpelHostDiagReqV2Len    = 56 // sizeof(struct inet_diag_req_v2)
	scalpelHostDiagMsgLen      = scalpelNlHdrLen + scalpelHostDiagReqV2Len
	scalpelHostNoCookie        = uint32(0xffffffff)
	scalpelHostDiagStatesMask  = uint32(0xffffffff) &^ (1 << 10) // 排除 TCP_LISTEN(10)

	hostConnProcCacheTTL  = 2 * time.Second
	hostConnIfaceCacheTTL = 3 * time.Second
	hostConnCountCacheTTL = 2 * time.Second
	hostConnMaxProcLines  = 1 << 15
)

var errScalpelSockENOENT = errors.New("sock_diag entry not found (ENOENT)")

// 可注入测试路径钩子（生产环境走 /proc/net 与 /data/system/packages.list）
var (
	hostConnProcNetDirFn       = defaultHostConnProcNetDir
	hostConnPackagesListPathFn = defaultHostConnPackagesListPath
)

func defaultHostConnProcNetDir() string {
	if p := strings.TrimSpace(os.Getenv("HNC_PROC_NET_DIR")); p != "" {
		return p
	}
	return "/proc/net"
}

func defaultHostConnPackagesListPath() string {
	if p := strings.TrimSpace(os.Getenv("HNC_PACKAGES_LIST_PATH")); p != "" {
		return p
	}
	return "/data/system/packages.list"
}

// ── 1. 纯 Go /proc/net/{tcp,tcp6,udp,udp6} 解析器 ──────────────────────────

type hostConnSockEntry struct {
	Proto     string
	SrcIP     string
	Sport     int
	DstIP     string
	Dport     int
	IsV6      bool
	RawV6Sock bool
	UID       int
	Inode     uint64
	TxQueue   uint64
	RxQueue   uint64
	StateCode uint8
	State     string
}

func (e hostConnSockEntry) key() string {
	return e.Proto + "|" + e.SrcIP + "|" + strconv.Itoa(e.Sport) + "|" + e.DstIP + "|" + strconv.Itoa(e.Dport)
}

func (e hostConnSockEntry) reverseKey() string {
	return e.Proto + "|" + e.DstIP + "|" + strconv.Itoa(e.Dport) + "|" + e.SrcIP + "|" + strconv.Itoa(e.Sport)
}

// hostConnParseHexIPv4 解析 /proc/net/tcp|udp 的 8 字符小端 32-bit 十六进制 IPv4 地址。
func hostConnParseHexIPv4(hexStr string) (netip.Addr, bool) {
	if len(hexStr) != 8 {
		return netip.Addr{}, false
	}
	v, err := strconv.ParseUint(hexStr, 16, 32)
	if err != nil {
		return netip.Addr{}, false
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	return netip.AddrFrom4(b), true
}

// hostConnParseHexIPv6 解析 /proc/net/tcp6|udp6 的 32 字符十六进制 IPv6 地址（4 组 32-bit 小端字序），
// 并将 IPv4-mapped IPv6 (::ffff:a.b.c.d) 自动归一化为标准 IPv4 地址以便与 nf_conntrack 精确 JOIN。
func hostConnParseHexIPv6(hexStr string) (netip.Addr, bool) {
	if len(hexStr) != 32 {
		return netip.Addr{}, false
	}
	var b [16]byte
	for i := 0; i < 4; i++ {
		w, err := strconv.ParseUint(hexStr[i*8:(i+1)*8], 16, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		binary.LittleEndian.PutUint32(b[i*4:(i+1)*4], uint32(w))
	}
	return netip.AddrFrom16(b).Unmap(), true
}

func hostConnParseAddrPort(token string, isV6File bool) (netip.Addr, int, bool) {
	colon := strings.IndexByte(token, ':')
	if colon <= 0 || colon+1 >= len(token) {
		return netip.Addr{}, 0, false
	}
	addrHex, portHex := token[:colon], token[colon+1:]
	portU, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	var (
		addr netip.Addr
		ok   bool
	)
	if isV6File {
		addr, ok = hostConnParseHexIPv6(addrHex)
	} else {
		addr, ok = hostConnParseHexIPv4(addrHex)
	}
	if !ok {
		return netip.Addr{}, 0, false
	}
	return addr, int(portU), true
}

func hostConnParseQueuePair(token string) (txQ, rxQ uint64) {
	colon := strings.IndexByte(token, ':')
	if colon <= 0 || colon+1 >= len(token) {
		return 0, 0
	}
	txQ, _ = strconv.ParseUint(token[:colon], 16, 64)
	rxQ, _ = strconv.ParseUint(token[colon+1:], 16, 64)
	return txQ, rxQ
}

func hostConnSocketStateName(proto string, st uint8) string {
	switch st {
	case 0x01:
		return "ESTABLISHED"
	case 0x02:
		return "SYN_SENT"
	case 0x03:
		return "SYN_RECV"
	case 0x04:
		return "FIN_WAIT1"
	case 0x05:
		return "FIN_WAIT2"
	case 0x06:
		return "TIME_WAIT"
	case 0x07:
		if proto == "udp" {
			return ""
		}
		return "CLOSE"
	case 0x08:
		return "CLOSE_WAIT"
	case 0x09:
		return "LAST_ACK"
	case 0x0A:
		return "LISTEN"
	case 0x0B:
		return "CLOSING"
	case 0x0C:
		return "NEW_SYN_RECV"
	default:
		return ""
	}
}

func hostConnIsTCPOrphanCloseState(proto string, st uint8) bool {
	if proto != "tcp" {
		return false
	}
	switch st {
	case 0x04, 0x05, 0x06, 0x07, 0x09, 0x0B, 0x0C:
		return true
	default:
		return false
	}
}

func hostConnParseProcNetLine(line, proto string, isV6File bool) (hostConnSockEntry, bool) {
	fp := ctFieldsPool.Get().(*[]string)
	f := splitASCIIFieldsInto(*fp, line)
	defer func() {
		*fp = f[:0]
		ctFieldsPool.Put(fp)
	}()

	if len(f) < 10 {
		return hostConnSockEntry{}, false
	}
	if f[0] == "sl" {
		return hostConnSockEntry{}, false
	}
	stVal, err := strconv.ParseUint(f[3], 16, 8)
	if err != nil {
		return hostConnSockEntry{}, false
	}
	st := uint8(stVal)
	// 跳过 LISTEN (0x0A) 监听套接口
	if st == 0x0A {
		return hostConnSockEntry{}, false
	}

	srcAddr, sport, ok1 := hostConnParseAddrPort(f[1], isV6File)
	dstAddr, dport, ok2 := hostConnParseAddrPort(f[2], isV6File)
	if !ok1 || !ok2 {
		return hostConnSockEntry{}, false
	}
	// 跳过未连接套接口 (远端 0.0.0.0 / :: 或 dport==0) 及本地回环 (127.0.0.0/8, ::1)
	if sport <= 0 || dport <= 0 || dstAddr.IsUnspecified() {
		return hostConnSockEntry{}, false
	}
	if srcAddr.IsLoopback() || dstAddr.IsLoopback() || srcAddr.IsMulticast() || dstAddr.IsMulticast() {
		return hostConnSockEntry{}, false
	}
	// 若源地址为 0.0.0.0/::（极少数未绑定源地址的已连接 UDP），协议簇跟随目的地址
	if !srcAddr.IsUnspecified() && (srcAddr.Is4() != dstAddr.Is4()) {
		return hostConnSockEntry{}, false
	}

	txQ, rxQ := hostConnParseQueuePair(f[4])
	uid, err := strconv.Atoi(f[7])
	if err != nil {
		uid = -1
	}
	inode, _ := strconv.ParseUint(f[9], 10, 64)

	// 过滤 TCP 04/05/06/07/0B/0C 半关闭/TIME_WAIT 孤儿行 (内核释放 fd 后将 uid/inode 归零，严禁误归为 root)
	if hostConnIsTCPOrphanCloseState(proto, st) && (uid <= 0 || inode == 0) {
		return hostConnSockEntry{}, false
	}

	return hostConnSockEntry{
		Proto:     proto,
		SrcIP:     srcAddr.String(),
		Sport:     sport,
		DstIP:     dstAddr.String(),
		Dport:     dport,
		IsV6:      dstAddr.Is6(),
		RawV6Sock: isV6File,
		UID:       uid,
		Inode:     inode,
		TxQueue:   txQ,
		RxQueue:   rxQ,
		StateCode: st,
		State:     hostConnSocketStateName(proto, st),
	}, true
}

func hostConnExtractProcLocalAddr(line string, isV6File bool) (string, bool) {
	fp := ctFieldsPool.Get().(*[]string)
	f := splitASCIIFieldsInto(*fp, line)
	defer func() {
		*fp = f[:0]
		ctFieldsPool.Put(fp)
	}()
	if len(f) < 4 || f[0] == "sl" {
		return "", false
	}
	srcAddr, _, ok := hostConnParseAddrPort(f[1], isV6File)
	if !ok {
		return "", false
	}
	srcAddr = srcAddr.Unmap()
	if !srcAddr.IsValid() || srcAddr.IsUnspecified() || srcAddr.IsLoopback() || srcAddr.IsMulticast() {
		return "", false
	}
	return srcAddr.String(), true
}

type hostConnProcSnapshot struct {
	at         time.Time
	procRoot   string
	list       []hostConnSockEntry
	byKey      map[string]hostConnSockEntry
	byRevKey   map[string]hostConnSockEntry
	localAddrs map[string]bool
	readable   bool
}

var hostConnProcCache struct {
	mu   sync.Mutex
	snap *hostConnProcSnapshot
}

func hostConnInvalidateProcCache() {
	hostConnProcCache.mu.Lock()
	hostConnProcCache.snap = nil
	hostConnProcCache.mu.Unlock()

	hostConnSplitCountCache.mu.Lock()
	hostConnSplitCountCache.byDir = nil
	hostConnSplitCountCache.mu.Unlock()
}

func hostConnBetterEntry(cand, prev hostConnSockEntry) bool {
	if prev.Inode == 0 && cand.Inode > 0 {
		return true
	}
	if prev.StateCode == 0x06 && cand.StateCode != 0x06 { // 非 TIME_WAIT 优先于 TIME_WAIT
		return true
	}
	return false
}

func hostConnReadProcSnapshot() *hostConnProcSnapshot {
	procRoot := hostConnProcNetDirFn()
	now := time.Now()

	hostConnProcCache.mu.Lock()
	if s := hostConnProcCache.snap; s != nil && s.procRoot == procRoot {
		ttl := hostConnProcCacheTTL
		if procRoot != "/proc/net" {
			ttl = 0 // 测试自定义目录实时读取不滞留旧缓存
		}
		if ttl > 0 && now.Sub(s.at) >= 0 && now.Sub(s.at) < ttl {
			hostConnProcCache.mu.Unlock()
			return s
		}
	}
	hostConnProcCache.mu.Unlock()

	specs := []struct {
		file  string
		proto string
		isV6  bool
	}{
		{"tcp", "tcp", false},
		{"tcp6", "tcp", true},
		{"udp", "udp", false},
		{"udp6", "udp", true},
	}

	byKey := make(map[string]hostConnSockEntry, 64)
	byRev := make(map[string]hostConnSockEntry, 64)
	localAddrs := make(map[string]bool, 16)
	anyReadable := false

	bufPtr := ctScanBufPool.Get().(*[]byte)
	defer func() {
		if cap(*bufPtr) <= 256*1024 {
			ctScanBufPool.Put(bufPtr)
		}
	}()

	for _, sp := range specs {
		f, err := os.Open(filepath.Join(procRoot, sp.file))
		if err != nil {
			continue
		}
		anyReadable = true
		sc := bufio.NewScanner(f)
		sc.Buffer(*bufPtr, 512*1024)
		lineCnt := 0
		for sc.Scan() {
			lineCnt++
			if lineCnt > hostConnMaxProcLines {
				break
			}
			ln := sc.Text()
			if la, ok := hostConnExtractProcLocalAddr(ln, sp.isV6); ok {
				localAddrs[la] = true
			}
			ent, ok := hostConnParseProcNetLine(ln, sp.proto, sp.isV6)
			if !ok {
				continue
			}
			k := ent.key()
			if prev, exists := byKey[k]; !exists || hostConnBetterEntry(ent, prev) {
				byKey[k] = ent
				byRev[ent.reverseKey()] = ent
			}
		}
		_ = f.Close()
	}

	list := make([]hostConnSockEntry, 0, len(byKey))
	for _, ent := range byKey {
		list = append(list, ent)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].key() < list[j].key()
	})

	snap := &hostConnProcSnapshot{
		at:         now,
		procRoot:   procRoot,
		list:       list,
		byKey:      byKey,
		byRevKey:   byRev,
		localAddrs: localAddrs,
		readable:   anyReadable,
	}

	hostConnProcCache.mu.Lock()
	hostConnProcCache.snap = snap
	hostConnProcCache.mu.Unlock()
	return snap
}

// ── 2. 零 app_process 本机 UID -> 包名/中文应用名缓存解析器 ─────────────────

type hostConnSysUIDMeta struct {
	pkg  string
	name string
}

var scalpelHostSystemUIDMap = map[int]hostConnSysUIDMeta{
	0:    {pkg: "root", name: "root/内核"},
	1000: {pkg: "android", name: "Android 系统"},
	1001: {pkg: "com.android.phone", name: "电话服务"},
	1010: {pkg: "wifi", name: "Wi-Fi 服务"},
	1013: {pkg: "mediaserver", name: "mediaserver"},
	1016: {pkg: "vpn", name: "VPN 服务"},
	1019: {pkg: "drm", name: "DRM 服务"},
	1020: {pkg: "mdnsr", name: "mDNS 守护"},
	1021: {pkg: "gps", name: "GPS 定位服务"},
	1023: {pkg: "media_rw", name: "媒体存储"},
	1036: {pkg: "logd", name: "logd 日志守护"},
	1041: {pkg: "audioserver", name: "audioserver"},
	1046: {pkg: "mediacodec", name: "mediacodec"},
	1047: {pkg: "cameraserver", name: "cameraserver"},
	1051: {pkg: "netd", name: "netd DNS守护"},
	1052: {pkg: "dnsmasq", name: "dnsmasq 守护"},
	1068: {pkg: "clatd", name: "clatd 464xlat"},
	1073: {pkg: "network_stack", name: "网络栈服务"},
	2000: {pkg: "com.android.shell", name: "ADB Shell"},
	9999: {pkg: "nobody", name: "nobody"},
}

var scalpelHostProtectedPackages = map[string]bool{
	"me.weishu.kernelsu":         true,
	"com.rifsxd.ksunext":         true,
	"com.sukisu.ultra":           true,
	"io.github.vvb2060.magisk":   true,
	"com.topjohnwu.magisk":       true,
	"me.bmax.apatch":             true,
	"com.agy":                    true,
	"com.google.android.webview": true,
	"com.android.webview":        true,
}

type hostConnPkgRecord struct {
	PrimaryPkg string
	AllPkgs    []string
	Seinfo     string
}

type hostConnIdentity struct {
	UID         int
	UserID      int
	AppID       int
	Package     string
	AllPackages []string
	AppName     string
	IsSystem    bool
	IsClone     bool
}

var hostConnPackagesCache struct {
	mu        sync.RWMutex
	path      string
	mtimeNano int64
	size      int64
	byUID     map[int]hostConnPkgRecord
}

func hostConnPreferredPrimaryPkg(cur, cand string) string {
	if cur == "" {
		return cand
	}
	// 优先选择非 provider / overlay 的主应用包名；同级取更简洁的根包名
	curAux := strings.Contains(cur, ".providers.") || strings.HasSuffix(cur, ".overlay")
	candAux := strings.Contains(cand, ".providers.") || strings.HasSuffix(cand, ".overlay")
	if curAux && !candAux {
		return cand
	}
	if !curAux && candAux {
		return cur
	}
	if len(cand) < len(cur) {
		return cand
	}
	return cur
}

func hostConnLoadPackagesMap() map[int]hostConnPkgRecord {
	path := hostConnPackagesListPathFn()
	if path == "" {
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	mt := st.ModTime().UnixNano()
	sz := st.Size()

	hostConnPackagesCache.mu.RLock()
	if hostConnPackagesCache.path == path && hostConnPackagesCache.mtimeNano == mt &&
		hostConnPackagesCache.size == sz && hostConnPackagesCache.byUID != nil {
		cached := hostConnPackagesCache.byUID
		hostConnPackagesCache.mu.RUnlock()
		return cached
	}
	hostConnPackagesCache.mu.RUnlock()

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	parsed := make(map[int]hostConnPkgRecord, 256)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 32*1024), 512*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pkg := fields[0]
		uid, err := strconv.Atoi(fields[1])
		if err != nil || uid < 0 || pkg == "" {
			continue
		}
		seinfo := ""
		if len(fields) >= 5 {
			seinfo = fields[4]
		}
		rec := parsed[uid]
		rec.PrimaryPkg = hostConnPreferredPrimaryPkg(rec.PrimaryPkg, pkg)
		dup := false
		for _, p := range rec.AllPkgs {
			if p == pkg {
				dup = true
				break
			}
		}
		if !dup {
			rec.AllPkgs = append(rec.AllPkgs, pkg)
		}
		if rec.Seinfo == "" && seinfo != "" {
			rec.Seinfo = seinfo
		}
		parsed[uid] = rec
	}

	hostConnPackagesCache.mu.Lock()
	hostConnPackagesCache.path = path
	hostConnPackagesCache.mtimeNano = mt
	hostConnPackagesCache.size = sz
	hostConnPackagesCache.byUID = parsed
	hostConnPackagesCache.mu.Unlock()
	return parsed
}

type hostConnLabelDirCache struct {
	resolver      *appmeta.Resolver
	livePath      string
	liveMtimeNano int64
	liveSize      int64
	liveMap       map[string]string
}

var (
	hostConnLabelMu   sync.Mutex
	hostConnLabelDirs = map[string]*hostConnLabelDirCache{}
)

// hostConnLookupPkgLabel 零子进程解析包名对应中文名:
// 优先级: etc/app_labels.json 用户覆盖 > data/app_labels_live.json (mtime+size 热缓存) > appmeta.Resolver 内置字典与美化兜底。
func hostConnLookupPkgLabel(hncDir, pkg string) string {
	if pkg == "" {
		return ""
	}
	cleanDir := strings.TrimSpace(hncDir)

	hostConnLabelMu.Lock()
	entry := hostConnLabelDirs[cleanDir]
	if entry == nil {
		overridePath := ""
		if cleanDir != "" {
			overridePath = filepath.Join(cleanDir, "etc", "app_labels.json")
		}
		entry = &hostConnLabelDirCache{
			resolver: appmeta.NewResolver(overridePath),
		}
		hostConnLabelDirs[cleanDir] = entry
	}
	res := entry.resolver
	var liveLabels map[string]string
	if cleanDir != "" {
		candPaths := []string{
			filepath.Join(cleanDir, "data", "app_labels_live.json"),
			filepath.Join(cleanDir, "run", "app_labels_live.json"),
		}
		var chosen string
		var st os.FileInfo
		for _, cp := range candPaths {
			if fi, err := os.Stat(cp); err == nil && !fi.IsDir() {
				chosen = cp
				st = fi
				break
			}
		}
		if chosen != "" && st != nil {
			mt := st.ModTime().UnixNano()
			sz := st.Size()
			if entry.livePath != chosen || entry.liveMtimeNano != mt || entry.liveSize != sz {
				if raw, err := os.ReadFile(chosen); err == nil {
					var m map[string]string
					if json.Unmarshal(raw, &m) == nil {
						entry.livePath = chosen
						entry.liveMtimeNano = mt
						entry.liveSize = sz
						entry.liveMap = m
					}
				}
			}
			liveLabels = entry.liveMap
		} else if entry.livePath != "" {
			entry.livePath = ""
			entry.liveMtimeNano = 0
			entry.liveSize = 0
			entry.liveMap = nil
		}
	}
	hostConnLabelMu.Unlock()

	if cleanDir != "" {
		if _, overridden := res.LabelCount(); overridden > 0 {
			// 若用户在 etc/app_labels.json 配了自定义覆盖，让 Resolver 优先命中
			// 为兼顾 liveLabels 高于静态 curatedLabels，先检查 liveLabels 是否存在：
			// 创建临时无 live 的 Resolver 会合并 curated，因此仅在无 override 命中时优先用 liveLabels。
		}
		if rawOv, err := os.ReadFile(filepath.Join(cleanDir, "etc", "app_labels.json")); err == nil {
			var ov map[string]string
			if json.Unmarshal(rawOv, &ov) == nil {
				if v := strings.TrimSpace(ov[pkg]); v != "" {
					return v
				}
			}
		}
	}
	if liveLabels != nil {
		if v := strings.TrimSpace(liveLabels[pkg]); v != "" {
			return v
		}
	}
	return res.Display(pkg)
}

const (
	scalpelHostPerUserRange  = 100000
	scalpelHostAppMinID      = 10000
	scalpelHostAppMaxID      = 19999
	scalpelHostSandboxMinID  = 20000
	scalpelHostSandboxMaxID  = 29999
	scalpelHostSandboxOffset = 10000
	scalpelHostIsolatedMinID = 90000
)

func scalpelSplitAndroidUID(uid int) (userID, appID int) {
	if uid < 0 {
		return -1, -1
	}
	return uid / scalpelHostPerUserRange, uid % scalpelHostPerUserRange
}

func scalpelIsForbiddenHostUID(uid int) (sysUID bool, isolatedUID bool) {
	if uid < 0 {
		return false, false
	}
	_, appID := scalpelSplitAndroidUID(uid)
	if appID < scalpelHostAppMinID {
		return true, false
	}
	if appID >= scalpelHostIsolatedMinID {
		return false, true
	}
	return false, false
}

// scalpelPairHostSandboxUID 按 uid % 100000 双向配对主应用 (10000..19999) 与 SDK 沙盒 (20000..29999),
// 严禁触碰 < 10000、30000..89999 与 90000+ 隔离进程区间。
func scalpelPairHostSandboxUID(uid int) (peerUID int, hasPeer bool) {
	if uid < scalpelHostAppMinID {
		return 0, false
	}
	userID, appID := scalpelSplitAndroidUID(uid)
	switch {
	case appID >= scalpelHostAppMinID && appID <= scalpelHostAppMaxID:
		return userID*scalpelHostPerUserRange + appID + scalpelHostSandboxOffset, true
	case appID >= scalpelHostSandboxMinID && appID <= scalpelHostSandboxMaxID:
		return userID*scalpelHostPerUserRange + appID - scalpelHostSandboxOffset, true
	default:
		return 0, false
	}
}

func scalpelOrderedHostFreezeUIDs(uid int) []int {
	sysUID, isolatedUID := scalpelIsForbiddenHostUID(uid)
	if uid < scalpelHostAppMinID || sysUID || isolatedUID {
		return nil
	}
	peer, ok := scalpelPairHostSandboxUID(uid)
	if !ok {
		return []int{uid}
	}
	if uid < peer {
		return []int{uid, peer}
	}
	return []int{peer, uid}
}

func scalpelSameOrPairedHostUID(u1, u2 int) bool {
	if u1 < scalpelHostAppMinID || u2 < scalpelHostAppMinID {
		return false
	}
	s1, iso1 := scalpelIsForbiddenHostUID(u1)
	s2, iso2 := scalpelIsForbiddenHostUID(u2)
	if s1 || iso1 || s2 || iso2 {
		return false
	}
	if u1 == u2 {
		return true
	}
	peer, ok := scalpelPairHostSandboxUID(u1)
	return ok && peer == u2
}

// scalpelResolveHostUID 解析 Android UID（含多用户/分身 userId = uid/100000, appId = uid%100000 及 SDK 沙盒反查）至包名与中文应用名。
func scalpelResolveHostUID(hncDir string, uid int) hostConnIdentity {
	if uid < 0 {
		return hostConnIdentity{
			UID:     -1,
			AppID:   -1,
			AppName: "本机连接",
		}
	}
	userID, appID := scalpelSplitAndroidUID(uid)
	isClone := userID > 0

	withCloneSuffix := func(label string) string {
		if isClone && label != "" && !strings.HasSuffix(label, " (分身)") {
			return label + " (分身)"
		}
		return label
	}

	pkgsMap := hostConnLoadPackagesMap()

	if appID < scalpelHostAppMinID {
		id := hostConnIdentity{
			UID:      uid,
			UserID:   userID,
			AppID:    appID,
			IsSystem: true,
			IsClone:  isClone,
		}
		if rec, ok := pkgsMap[uid]; ok {
			id.AllPackages = rec.AllPkgs
			id.Package = rec.PrimaryPkg
		} else if rec, ok := pkgsMap[appID]; ok {
			id.AllPackages = rec.AllPkgs
			id.Package = rec.PrimaryPkg
		}
		if sysMeta, ok := scalpelHostSystemUIDMap[appID]; ok {
			if id.Package == "" {
				id.Package = sysMeta.pkg
			}
			id.AppName = withCloneSuffix(sysMeta.name)
			return id
		}
		if id.Package != "" {
			id.AppName = withCloneSuffix(hostConnLookupPkgLabel(hncDir, id.Package))
			return id
		}
		id.Package = fmt.Sprintf("uid:%d", appID)
		id.AppName = withCloneSuffix(fmt.Sprintf("系统服务 (%d)", appID))
		return id
	}

	if appID >= scalpelHostIsolatedMinID {
		return hostConnIdentity{
			UID:      uid,
			UserID:   userID,
			AppID:    appID,
			Package:  fmt.Sprintf("isolated:%d", appID),
			AppName:  withCloneSuffix(fmt.Sprintf("隔离沙盒进程 (%d)", appID)),
			IsSystem: true,
			IsClone:  isClone,
		}
	}

	var (
		rec   hostConnPkgRecord
		found bool
	)
	if pkgsMap != nil {
		rec, found = pkgsMap[uid]
		if !found && userID > 0 {
			rec, found = pkgsMap[appID]
		}
		// Android 13+ SDK 沙盒 (20000..29999) 回退反查同用户或主用户宿主应用包名
		if !found && appID >= scalpelHostSandboxMinID && appID <= scalpelHostSandboxMaxID {
			hostAppID := appID - scalpelHostSandboxOffset
			if userID > 0 {
				rec, found = pkgsMap[userID*scalpelHostPerUserRange+hostAppID]
			}
			if !found {
				rec, found = pkgsMap[hostAppID]
			}
		}
	}
	if found && rec.PrimaryPkg != "" {
		label := hostConnLookupPkgLabel(hncDir, rec.PrimaryPkg)
		if label == "" {
			label = rec.PrimaryPkg
		}
		isSys := strings.Contains(rec.Seinfo, "platform") ||
			strings.HasPrefix(rec.PrimaryPkg, "com.android.providers.") ||
			rec.PrimaryPkg == "android"
		return hostConnIdentity{
			UID:         uid,
			UserID:      userID,
			AppID:       appID,
			Package:     rec.PrimaryPkg,
			AllPackages: rec.AllPkgs,
			AppName:     withCloneSuffix(label),
			IsSystem:    isSys,
			IsClone:     isClone,
		}
	}

	return hostConnIdentity{
		UID:      uid,
		UserID:   userID,
		AppID:    appID,
		AppName:  withCloneSuffix(fmt.Sprintf("UID %d", uid)),
		IsSystem: false,
		IsClone:  isClone,
	}
}

func scalpelIsProtectedHostIdentity(id hostConnIdentity) (bool, string) {
	if scalpelHostProtectedPackages[id.Package] {
		return true, id.Package
	}
	for _, p := range id.AllPackages {
		if scalpelHostProtectedPackages[p] {
			return true, p
		}
	}
	return false, ""
}

// scalpelDetectCleartextRisk 标记 L1 明文/绕过风险:
//   - appId >= 10000 直连外部真实 :53 -> "dns_direct" (豁免 198.18.0.0/15 与 fc00::/18 代理 Fake-IP DNS)
//   - TCP :80/:8080/:8000            -> "http_cleartext"
func scalpelDetectCleartextRisk(proto string, dport int, uid int) string {
	return scalpelDetectCleartextRiskForTarget(proto, "", dport, uid)
}

func scalpelDetectCleartextRiskForTarget(proto, dstIP string, dport, uid int) string {
	if dport == 53 && uid >= scalpelHostAppMinID && (uid%scalpelHostPerUserRange) >= scalpelHostAppMinID {
		if !isBenchmarkOrFakeIP(dstIP) {
			return "dns_direct"
		}
		return ""
	}
	if proto == "tcp" && (dport == 80 || dport == 8080 || dport == 8000) {
		return "http_cleartext"
	}
	return ""
}

// ── 3. 纯 Go NETLINK_SOCK_DIAG (SOCK_DESTROY = 21) 微秒级断流器 ───────────────

type scalpelSockDestroyRunner func(tuple ScalpelTuple, seq uint32) error

// buildScalpelSockDestroyMsg 纯字节级构造 NETLINK_SOCK_DIAG SOCK_DESTROY (inet_diag_req_v2) 报文:
//   - nlmsghdr (16B) 与 idiag_states / idiag_if / idiag_cookie 使用 encoding/binary.LittleEndian;
//   - idiag_sport / idiag_dport 与 IP 地址使用网络字节序 (BigEndian);
//   - idiag_cookie 置 INET_DIAG_NOCOOKIE (0xffffffff, 0xffffffff) 精确按五元组强制销毁 socket。
func buildScalpelSockDestroyMsg(in ScalpelTuple, forceV4MappedV6 bool, seq uint32) ([]byte, error) {
	norm, protoNum, isV6, err := validateScalpelTuple(in)
	if err != nil {
		return nil, err
	}
	srcIP := net.ParseIP(norm.SrcIP)
	dstIP := net.ParseIP(norm.DstIP)

	family := uint8(scalpelAfInet)
	var srcBuf, dstBuf [16]byte
	if !isV6 && !forceV4MappedV6 {
		copy(srcBuf[0:4], srcIP.To4())
		copy(dstBuf[0:4], dstIP.To4())
	} else {
		family = scalpelAfInet6
		if !isV6 && forceV4MappedV6 {
			// Android Java/Kotlin 双栈 AF_INET6 socket 内核存储为 ::ffff:a.b.c.d
			srcBuf[10], srcBuf[11] = 0xff, 0xff
			copy(srcBuf[12:16], srcIP.To4())
			dstBuf[10], dstBuf[11] = 0xff, 0xff
			copy(dstBuf[12:16], dstIP.To4())
		} else {
			copy(srcBuf[:], srcIP.To16())
			copy(dstBuf[:], dstIP.To16())
		}
	}

	msg := make([]byte, scalpelHostDiagMsgLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(scalpelHostDiagMsgLen))
	binary.LittleEndian.PutUint16(msg[4:6], scalpelHostSockDestroyType)
	binary.LittleEndian.PutUint16(msg[6:8], scalpelNlmFRequest|scalpelNlmFAck)
	binary.LittleEndian.PutUint32(msg[8:12], seq)
	binary.LittleEndian.PutUint32(msg[12:16], 0)

	req := msg[scalpelNlHdrLen:]
	req[0] = family
	req[1] = protoNum
	req[2] = 0 // idiag_ext
	req[3] = 0 // pad
	binary.LittleEndian.PutUint32(req[4:8], scalpelHostDiagStatesMask)
	binary.BigEndian.PutUint16(req[8:10], uint16(norm.Sport))
	binary.BigEndian.PutUint16(req[10:12], uint16(norm.Dport))
	copy(req[12:28], srcBuf[:])
	copy(req[28:44], dstBuf[:])
	binary.LittleEndian.PutUint32(req[44:48], 0) // idiag_if
	binary.LittleEndian.PutUint32(req[48:52], scalpelHostNoCookie)
	binary.LittleEndian.PutUint32(req[52:56], scalpelHostNoCookie)
	return msg, nil
}

func parseScalpelSockDiagAck(resp []byte) error {
	if len(resp) < scalpelNlHdrLen {
		return errors.New("short sock_diag netlink response")
	}
	nlLen := int(binary.LittleEndian.Uint32(resp[0:4]))
	nlType := binary.LittleEndian.Uint16(resp[4:6])
	if nlLen < scalpelNlHdrLen || nlLen > len(resp) {
		return errors.New("malformed sock_diag netlink length")
	}
	if nlType == scalpelNlMsgError {
		if nlLen < scalpelNlHdrLen+4 {
			return errors.New("truncated sock_diag NLMSG_ERROR")
		}
		errnoNeg := int32(binary.LittleEndian.Uint32(resp[16:20]))
		if errnoNeg == 0 {
			return nil
		}
		posErrno := -errnoNeg
		if posErrno < 0 {
			posErrno = errnoNeg
		}
		if posErrno == int32(syscall.ENOENT) {
			return errScalpelSockENOENT
		}
		return syscall.Errno(posErrno)
	}
	return nil
}

func sendScalpelSockDestroyRaw(msg []byte) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, scalpelHostNetlinkSockDiag)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	tv := syscall.Timeval{Sec: 1}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)

	for {
		err = syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		break
	}

	var buf [4096]byte
	for {
		n, _, rErr := syscall.Recvfrom(fd, buf[:], 0)
		if errors.Is(rErr, syscall.EINTR) {
			continue
		}
		if rErr != nil {
			return rErr
		}
		if n <= 0 {
			return errors.New("sock_diag destroy: empty recv")
		}
		return parseScalpelSockDiagAck(buf[:n])
	}
}

func isScalpelSockENOENT(err error) bool {
	return errors.Is(err, errScalpelSockENOENT) || errors.Is(err, syscall.ENOENT)
}

func isScalpelBenignSockDestroyErr(err error) bool {
	if err == nil || isScalpelSockENOENT(err) {
		return true
	}
	return errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.EAFNOSUPPORT) ||
		errors.Is(err, syscall.EPROTONOSUPPORT) ||
		errors.Is(err, syscall.EINVAL)
}

func defaultScalpelHostSockDestroy(tuple ScalpelTuple, seq uint32) error {
	norm, _, isV6, err := validateScalpelTuple(tuple)
	if err != nil {
		return err
	}
	msg, err := buildScalpelSockDestroyMsg(norm, false, seq)
	if err != nil {
		return err
	}
	err1 := sendScalpelSockDestroyRaw(msg)
	if err1 == nil {
		return nil
	}
	// Android 双栈兼容: IPv4 连接在内核常以 AF_INET6 ::ffff:a.b.c.d 形态驻留，ENOENT 时自动补刀
	if !isV6 && isScalpelSockENOENT(err1) {
		msgMapped, mErr := buildScalpelSockDestroyMsg(norm, true, seq+1)
		if mErr == nil {
			if err2 := sendScalpelSockDestroyRaw(msgMapped); err2 == nil || isScalpelSockENOENT(err2) {
				return err2
			}
		}
	}
	return err1
}

// ── 4. 本机安全门禁与 HNC_SCALPEL_HOST (filter/OUTPUT) 载荷构造 ──────────────

func scalpelIsWebUISelfPort(port int) bool {
	switch port {
	case 8443, 8444, 8080:
		return true
	default:
		return false
	}
}

func scalpelIsGatewayLocalServicePort(port int) bool {
	switch port {
	case 53, 67, 68, 8443, 8444, 8080:
		return true
	default:
		return false
	}
}

func scalpelIsUnknownUIDBlockedPort(port int) bool {
	switch port {
	case 53, 853, 67, 68, 123, 500, 4500, 5060, 5061:
		return true
	default:
		return false
	}
}

func scalpelLookupSocketUID(norm ScalpelTuple) (int, bool) {
	ps := hostConnReadProcSnapshot()
	if ps == nil {
		return -1, false
	}
	k := norm.Proto + "|" + norm.SrcIP + "|" + strconv.Itoa(norm.Sport) + "|" + norm.DstIP + "|" + strconv.Itoa(norm.Dport)
	if sk, ok := ps.byKey[k]; ok && sk.UID >= 0 && !(hostConnIsTCPOrphanCloseState(sk.Proto, sk.StateCode) && (sk.UID == 0 || sk.Inode == 0)) {
		return sk.UID, true
	}
	rk := norm.Proto + "|" + norm.DstIP + "|" + strconv.Itoa(norm.Dport) + "|" + norm.SrcIP + "|" + strconv.Itoa(norm.Sport)
	if sk, ok := ps.byRevKey[rk]; ok && sk.UID >= 0 && !(hostConnIsTCPOrphanCloseState(sk.Proto, sk.StateCode) && (sk.UID == 0 || sk.Inode == 0)) {
		return sk.UID, true
	}
	return -1, false
}

// evaluateScalpelHostGuard 执行本机五道防自锁安全门禁，违规一律返回 *scalpelFreezeGuardError (HTTP 409 Conflict)。
func evaluateScalpelHostGuard(s *server, norm ScalpelTuple, mode string, reqUID int, hasReqUID bool) (effectiveUID int, id hostConnIdentity, guardErr *scalpelFreezeGuardError) {
	var hncDir string
	if s != nil {
		hncDir = s.hncDir
	}

	// 门禁 1: 严禁斩断回环地址 (127.0.0.0/8, ::1) 或本机链路本地管理地址
	srcAddr, err1 := netip.ParseAddr(norm.SrcIP)
	dstAddr, err2 := netip.ParseAddr(norm.DstIP)
	if err1 == nil {
		srcAddr = srcAddr.Unmap()
	}
	if err2 == nil {
		dstAddr = dstAddr.Unmap()
	}
	if err1 != nil || err2 != nil ||
		srcAddr.IsLoopback() || dstAddr.IsLoopback() ||
		srcAddr.IsLinkLocalUnicast() || dstAddr.IsLinkLocalUnicast() ||
		srcAddr.IsLinkLocalMulticast() || dstAddr.IsLinkLocalMulticast() ||
		srcAddr.IsUnspecified() || dstAddr.IsUnspecified() {
		return -1, hostConnIdentity{}, &scalpelFreezeGuardError{
			ReasonCode: "host_loopback_or_linklocal_blocked",
			Vendor:     "Host Safety Guard",
			Detail:     "禁止斩断本机回环地址（127.0.0.0/8、::1）或链路本地管理地址，以防本地守护进程通信中断",
		}
	}

	// 门禁 2: 严禁斩断 HNC WebUI 自身端口 (sport 或 dport 为 8443, 8444, 8080)
	if scalpelIsWebUISelfPort(norm.Sport) || scalpelIsWebUISelfPort(norm.Dport) {
		hitPort := norm.Dport
		if !scalpelIsWebUISelfPort(hitPort) {
			hitPort = norm.Sport
		}
		return -1, hostConnIdentity{}, &scalpelFreezeGuardError{
			ReasonCode: "host_webui_port_blocked",
			Vendor:     "HNC WebUI Guard",
			Detail:     fmt.Sprintf("目标端口 %d 属于 HNC 控制面自身监听端口（8443/8444/8080），已拒绝斩流以防管理界面自锁失联", hitPort),
		}
	}

	// 实时核验内核 socket UID（若 socket 尚存以内核真实 UID 为准，否则回退调用方传入 UID）
	effectiveUID = -1
	if procUID, ok := scalpelLookupSocketUID(norm); ok {
		effectiveUID = procUID
	} else if hasReqUID && reqUID >= 0 {
		effectiveUID = reqUID
	}
	id = scalpelResolveHostUID(hncDir, effectiveUID)

	// 门禁 3: 严禁斩断核心系统守护进程与隔离沙盒进程 (按 uid % 100000 覆盖多用户/应用分身)
	//   - cut_freeze_15m 强制要求有效应用 UID (appId 在 10000..89999)
	//   - cut_once 拒绝 appId < 10000 系统 UID 与 appId >= 90000 隔离进程；反查不到 UID (<0) 时仅允许非 53/853/67/68 的精确五元组 cut_once
	sysUID, isolatedUID := scalpelIsForbiddenHostUID(effectiveUID)
	if mode == scalpelModeFreeze15m {
		if effectiveUID < 0 {
			return effectiveUID, id, &scalpelFreezeGuardError{
				ReasonCode: "host_uid_required_for_freeze",
				Vendor:     "Host System Guard",
				Detail:     "目标本机连接已释放无法确认所属应用 UID，已拒绝 15 分钟冻结以免误伤系统组件；仅允许使用 cut_once 执行一次性精确五元组秒斩",
			}
		}
		if sysUID {
			return effectiveUID, id, &scalpelFreezeGuardError{
				ReasonCode: "host_system_uid_blocked",
				Vendor:     "Host System Guard",
				Detail:     fmt.Sprintf("目标连接归属核心系统进程 %s (UID=%d, appId < 10000)，严禁执行本机冻结以防手机断网或系统故障", id.AppName, effectiveUID),
			}
		}
		if isolatedUID {
			return effectiveUID, id, &scalpelFreezeGuardError{
				ReasonCode: "host_isolated_uid_blocked",
				Vendor:     "Host System Guard",
				Detail:     fmt.Sprintf("目标连接归属动态隔离沙盒进程 %s (UID=%d, appId >= 90000)，严禁下发持久化冻结规则以防 UID 回收复用误伤系统 WebView 或其他应用", id.AppName, effectiveUID),
			}
		}
	} else {
		if effectiveUID >= 0 && sysUID {
			return effectiveUID, id, &scalpelFreezeGuardError{
				ReasonCode: "host_system_uid_blocked",
				Vendor:     "Host System Guard",
				Detail:     fmt.Sprintf("目标连接归属关键系统守护进程 %s (UID=%d, appId < 10000)，严禁斩流以防网络栈或电话基带异常", id.AppName, effectiveUID),
			}
		}
		if effectiveUID >= 0 && isolatedUID {
			return effectiveUID, id, &scalpelFreezeGuardError{
				ReasonCode: "host_isolated_uid_blocked",
				Vendor:     "Host System Guard",
				Detail:     fmt.Sprintf("目标连接归属系统隔离沙盒进程 %s (UID=%d, appId >= 90000)，已拒绝斩流以防误伤系统 WebView 渲染沙盒", id.AppName, effectiveUID),
			}
		}
		if effectiveUID < 0 && (scalpelIsUnknownUIDBlockedPort(norm.Sport) || scalpelIsUnknownUIDBlockedPort(norm.Dport)) {
			hitPort := norm.Dport
			if !scalpelIsUnknownUIDBlockedPort(hitPort) {
				hitPort = norm.Sport
			}
			return effectiveUID, id, &scalpelFreezeGuardError{
				ReasonCode: "host_unknown_uid_core_port_blocked",
				Vendor:     "Host System Guard",
				Detail:     fmt.Sprintf("目标本机连接 UID 未知且涉及系统基础端口 %d（DNS/DoT/DHCP），已拒绝斩流以防误伤系统守护进程", hitPort),
			}
		}
	}

	// 门禁 4: 严禁保护包名被冻结或斩断 (含按 uid % 100000 双向配对主应用 10000..19999 与 SDK 沙盒 20000..29999)
	if protected, hitPkg := scalpelIsProtectedHostIdentity(id); protected {
		return effectiveUID, id, &scalpelFreezeGuardError{
			ReasonCode: "host_protected_package_blocked",
			Vendor:     hitPkg,
			Detail:     fmt.Sprintf("应用 %s (%s) 属于受保护的核心管理器或运行宿主，严禁对其下发本机阻断规则", id.AppName, hitPkg),
		}
	}
	if peerUID, hasPeer := scalpelPairHostSandboxUID(effectiveUID); hasPeer {
		peerID := scalpelResolveHostUID(hncDir, peerUID)
		if protected, hitPkg := scalpelIsProtectedHostIdentity(peerID); protected {
			if id.Package == "" {
				id.Package = peerID.Package
			}
			if (id.AppName == "" || strings.HasPrefix(id.AppName, "UID ")) && peerID.AppName != "" {
				id.AppName = peerID.AppName
			}
			return effectiveUID, id, &scalpelFreezeGuardError{
				ReasonCode: "host_protected_package_blocked",
				Vendor:     hitPkg,
				Detail:     fmt.Sprintf("应用 %s (%s) 属于受保护的核心管理器或运行宿主（配对宿主/沙盒 UID=%d），严禁对其下发本机阻断规则", id.AppName, hitPkg, peerUID),
			}
		}
	}

	// 门禁 5: 严禁在本机 freeze_15m 冻结 :53/:853 系统 DNS 端口、Fake-IP 虚拟地址池或三级共享 CDN 门禁拦截项
	if mode == scalpelModeFreeze15m {
		if isBenchmarkOrFakeIP(norm.DstIP) {
			return effectiveUID, id, &scalpelFreezeGuardError{
				ReasonCode: "shared_cdn_freeze_blocked",
				Vendor:     "Fake-IP 虚拟地址池",
				Detail:     fmt.Sprintf("目标地址 %s 属于代理 Fake-IP 虚拟地址池（198.18.0.0/15 或 fc00::/18），已拒绝 15 分钟 IP 级冻结以防地址池轮转复用连坐误伤其他域名；仅允许使用 cut_once 执行一次性五元组秒斩", norm.DstIP),
			}
		}
		if fgErr := evaluateScalpelFreezeGuard(s, norm); fgErr != nil {
			return effectiveUID, id, fgErr
		}
	}

	return effectiveUID, id, nil
}

// buildScalpelHostRestorePayload 纯函数生成 *filter 表 HNC_SCALPEL_HOST 子链的 --noflush 内存载荷:
//   - 当无该协议栈活跃规则时生成纯空链，保持零报文匹配开销；
//   - 当存在活跃规则时，前 3 条固定写入 -o lo 与 8443,8444,8080 双向免死 RETURN 规则；
//   - 15m 端点冻结按 uid % 100000 双向配对主应用 (10000..19999) 与 SDK 沙盒 (20000..29999) 同步生成规则。
func buildScalpelHostRestorePayload(isIPv6 bool, rules []ScalpelActiveRule) string {
	var b strings.Builder
	b.WriteString("*filter\n")
	b.WriteString(":" + scalpelHostChainName + " - [0:0]\n")

	activeForFamily := 0
	for _, r := range rules {
		if r.IsIPv6 == isIPv6 {
			activeForFamily++
		}
	}
	if activeForFamily == 0 {
		b.WriteString("COMMIT\n")
		return b.String()
	}

	b.WriteString("-A " + scalpelHostChainName + " -o lo -j RETURN\n")
	b.WriteString("-A " + scalpelHostChainName + " -p tcp -m multiport --sports 8443,8444,8080 -j RETURN\n")
	b.WriteString("-A " + scalpelHostChainName + " -p tcp -m multiport --dports 8443,8444,8080 -j RETURN\n")

	emittedFreeze := make(map[string]bool, activeForFamily*2)
	for _, r := range rules {
		if r.IsIPv6 != isIPv6 {
			continue
		}
		t := r.Tuple
		rejectWith := "tcp-reset"
		if t.Proto == "udp" {
			if isIPv6 {
				rejectWith = "icmp6-port-unreachable"
			} else {
				rejectWith = "icmp-port-unreachable"
			}
		}
		if r.MatchSport {
			if t.Proto == "tcp" {
				fmt.Fprintf(&b, "-A %s -p tcp ! --syn -s %s -d %s --sport %d --dport %d -j REJECT --reject-with %s\n",
					scalpelHostChainName, t.SrcIP, t.DstIP, t.Sport, t.Dport, rejectWith)
			} else {
				fmt.Fprintf(&b, "-A %s -p %s -s %s -d %s --sport %d --dport %d -j REJECT --reject-with %s\n",
					scalpelHostChainName, t.Proto, t.SrcIP, t.DstIP, t.Sport, t.Dport, rejectWith)
			}
		} else {
			freezeUIDs := scalpelOrderedHostFreezeUIDs(r.UID)
			if len(freezeUIDs) == 0 && r.HasUID && r.UID >= scalpelHostAppMinID {
				if sysU, isoU := scalpelIsForbiddenHostUID(r.UID); !sysU && !isoU {
					freezeUIDs = []int{r.UID}
				}
			}
			for _, fUID := range freezeUIDs {
				dedupKey := fmt.Sprintf("%d|%s|%s|%d", fUID, t.Proto, t.DstIP, t.Dport)
				if emittedFreeze[dedupKey] {
					continue
				}
				emittedFreeze[dedupKey] = true
				fmt.Fprintf(&b, "-A %s -m owner --uid-owner %d -d %s -p %s --dport %d -j REJECT --reject-with %s\n",
					scalpelHostChainName, fUID, t.DstIP, t.Proto, t.Dport, rejectWith)
			}
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

// ── 5. 双域 (hotspot vs host) 正交连接分类与四路内存 JOIN ─────────────────────

type hostConnIfaceSnap struct {
	at           time.Time
	localIPs     map[string]bool
	tetherSubV4  netip.Prefix
	hasTetherSub bool
	tetherSubsV6 []netip.Prefix
}

var hostConnIfaceCache struct {
	mu          sync.Mutex
	byHotspotIf map[string]*hostConnIfaceSnap
}

var hostConnDefaultTetherPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.168.43.0/24"),
	netip.MustParsePrefix("192.168.42.0/24"),
	netip.MustParsePrefix("192.168.49.0/24"),
}

func hostConnInvalidateIfaceCache() {
	hostConnIfaceCache.mu.Lock()
	hostConnIfaceCache.byHotspotIf = nil
	hostConnIfaceCache.mu.Unlock()
}

func hostConnLocalIfaceSnapshot(hotspotIface string) *hostConnIfaceSnap {
	now := time.Now()
	hostConnIfaceCache.mu.Lock()
	if hostConnIfaceCache.byHotspotIf == nil {
		hostConnIfaceCache.byHotspotIf = make(map[string]*hostConnIfaceSnap)
	}
	if s := hostConnIfaceCache.byHotspotIf[hotspotIface]; s != nil && now.Sub(s.at) >= 0 && now.Sub(s.at) < hostConnIfaceCacheTTL {
		hostConnIfaceCache.mu.Unlock()
		return s
	}
	hostConnIfaceCache.mu.Unlock()

	localIPs := make(map[string]bool, 8)
	var tetherSub netip.Prefix
	hasTether := false
	var tetherSubsV6 []netip.Prefix

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, aErr := ifc.Addrs()
			if aErr != nil {
				continue
			}
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok || ipn.IP == nil {
					continue
				}
				addr, ok := netip.AddrFromSlice(ipn.IP)
				if !ok {
					continue
				}
				addr = addr.Unmap()
				if addr.IsLoopback() || addr.IsUnspecified() {
					continue
				}
				localIPs[addr.String()] = true
				if hotspotIface != "" && ifc.Name == hotspotIface {
					if addr.Is4() && !hasTether {
						ones, bits := ipn.Mask.Size()
						if bits == 32 && ones > 0 {
							tetherSub = netip.PrefixFrom(addr, ones).Masked()
							hasTether = true
						}
					} else if addr.Is6() && !addr.IsLinkLocalUnicast() && !addr.IsLinkLocalMulticast() && !addr.IsMulticast() {
						ones, bits := ipn.Mask.Size()
						if bits == 128 && ones > 0 && ones < 128 {
							pfx6 := netip.PrefixFrom(addr, ones).Masked()
							dup := false
							for _, ex := range tetherSubsV6 {
								if ex == pfx6 {
									dup = true
									break
								}
							}
							if !dup {
								tetherSubsV6 = append(tetherSubsV6, pfx6)
							}
						}
					}
				}
			}
		}
	}

	snap := &hostConnIfaceSnap{
		at:           now,
		localIPs:     localIPs,
		tetherSubV4:  tetherSub,
		hasTetherSub: hasTether,
		tetherSubsV6: tetherSubsV6,
	}
	hostConnIfaceCache.mu.Lock()
	hostConnIfaceCache.byHotspotIf[hotspotIface] = snap
	hostConnIfaceCache.mu.Unlock()
	return snap
}

type scalpelTetherV6PrefixOwner struct {
	prefix    netip.Prefix
	uniqueMAC string
	ambiguous bool
}

func scalpelIsRoutableUnicastV6(addr netip.Addr) bool {
	return addr.IsValid() && addr.Is6() &&
		!addr.IsLoopback() && !addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast() && !addr.IsMulticast() && !addr.IsUnspecified()
}

func scalpelIsSelfLocalAddr(ipStr, hotspotGatewayIP string, ifSnap *hostConnIfaceSnap, procSnap *hostConnProcSnapshot) bool {
	if ipStr == "" {
		return false
	}
	if hotspotGatewayIP != "" && ipStr == hotspotGatewayIP {
		return true
	}
	if ifSnap != nil && ifSnap.localIPs[ipStr] {
		return true
	}
	if procSnap != nil && procSnap.localAddrs[ipStr] {
		return true
	}
	return false
}

// scalpelBuildTetherV6PrefixOwners 从已知热点客户端 IPv6 地址构建 /64 前缀归属表，
// 用于关联同一热点客户端尚未入 macByIP 的 RFC 4941 临时隐私 IPv6 地址。
func scalpelBuildTetherV6PrefixOwners(macByIP map[string]string, hotspotGatewayIP string, ifSnap *hostConnIfaceSnap, procSnap *hostConnProcSnapshot) []scalpelTetherV6PrefixOwner {
	if len(macByIP) == 0 {
		return nil
	}
	var out []scalpelTetherV6PrefixOwner
	for ipStr, rawMAC := range macByIP {
		cMac := canonMAC(rawMAC)
		if cMac == "" || scalpelIsSelfLocalAddr(ipStr, hotspotGatewayIP, ifSnap, procSnap) {
			continue
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !scalpelIsRoutableUnicastV6(addr) {
			continue
		}
		pfx64 := netip.PrefixFrom(addr, 64).Masked()
		found := false
		for i := range out {
			if out[i].prefix == pfx64 {
				found = true
				if !out[i].ambiguous && out[i].uniqueMAC != cMac {
					out[i].ambiguous = true
					out[i].uniqueMAC = ""
				}
				break
			}
		}
		if !found {
			out = append(out, scalpelTetherV6PrefixOwner{
				prefix:    pfx64,
				uniqueMAC: cMac,
			})
		}
	}
	return out
}

// scalpelBuildDeviceDirectory 在 s.buildDeviceDirectory() 基础上补齐 data/devices.json 中的 ipv6/ip6/ips 多地址映射。
func scalpelBuildDeviceDirectory(s *server) (nameByMAC map[string]string, macByIP map[string]string) {
	if s == nil || s.hncDir == "" {
		return map[string]string{}, map[string]string{}
	}
	simEnabled := s.simOn()
	nameByMAC, macByIP = s.buildDeviceDirectory()
	if !simEnabled {
		for m := range nameByMAC {
			if strings.HasPrefix(strings.ToLower(m), simMACPrefix) {
				delete(nameByMAC, m)
			}
		}
		for ip, m := range macByIP {
			if strings.HasPrefix(strings.ToLower(m), simMACPrefix) {
				delete(macByIP, ip)
			}
		}
	}
	addIP := func(m, rawIP string) {
		trimmed := strings.TrimSpace(rawIP)
		if m == "" || trimmed == "" || trimmed == "-" {
			return
		}
		if !simEnabled && strings.HasPrefix(strings.ToLower(m), simMACPrefix) {
			return
		}
		if addr, err := netip.ParseAddr(trimmed); err == nil {
			canon := addr.Unmap().String()
			if macByIP[canon] == "" {
				macByIP[canon] = m
			}
		}
	}
	var raw any
	var rerr error
	if s.jsonCache != nil {
		raw, rerr = s.jsonCache.read(filepath.Join(s.hncDir, "data", "devices.json"))
	} else {
		raw, rerr = readJSON(filepath.Join(s.hncDir, "data", "devices.json"))
	}
	if rerr == nil {
		if dm, ok := raw.(map[string]any); ok {
			for mac, v := range dm {
				cMac := canonMAC(mac)
				d, _ := v.(map[string]any)
				if cMac == "" || d == nil {
					continue
				}
				if !simEnabled && (strings.HasPrefix(cMac, simMACPrefix) || d["sim"] == true) {
					continue
				}
				for _, k := range []string{"ipv6", "ip6", "ips", "client_ips"} {
					val := d[k]
					switch tv := val.(type) {
					case string:
						addIP(cMac, tv)
					case []any:
						for _, elem := range tv {
							addIP(cMac, asString(elem))
						}
					case []string:
						for _, elem := range tv {
							addIP(cMac, elem)
						}
					}
				}
			}
		}
	}
	return nameByMAC, macByIP
}

func scalpelInferUniqueV6PrefixMAC(ipStr string, macByIP map[string]string) string {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	if !scalpelIsRoutableUnicastV6(addr) {
		return ""
	}
	owners := scalpelBuildTetherV6PrefixOwners(macByIP, "", nil, nil)
	for _, ow := range owners {
		if ow.prefix.Contains(addr) {
			return ow.uniqueMAC
		}
	}
	return ""
}

func scalpelMatchExplicitTetherV6Prefix(addr netip.Addr, ifSnap *hostConnIfaceSnap, v6Owners []scalpelTetherV6PrefixOwner) (matched bool, uniqueMAC string) {
	if !scalpelIsRoutableUnicastV6(addr) {
		return false, ""
	}
	for _, ow := range v6Owners {
		if ow.prefix.Contains(addr) {
			return true, ow.uniqueMAC
		}
	}
	if ifSnap != nil {
		for _, pfx := range ifSnap.tetherSubsV6 {
			if pfx.Contains(addr) {
				return true, ""
			}
		}
	}
	return false, ""
}

func scalpelIsLikelyUnregisteredTetherClient(ipStr, hotspotGatewayIP string, ifSnap *hostConnIfaceSnap) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	canon := addr.String()
	if hotspotGatewayIP != "" && canon == hotspotGatewayIP {
		return false
	}
	if ifSnap != nil && ifSnap.localIPs[canon] {
		return false
	}
	if addr.Is4() {
		if ifSnap != nil && ifSnap.hasTetherSub && ifSnap.tetherSubV4.Contains(addr) {
			return true
		}
		for _, pfx := range hostConnDefaultTetherPrefixes {
			if pfx.Contains(addr) && !strings.HasSuffix(canon, ".1") {
				return true
			}
		}
		return false
	}
	if scalpelIsRoutableUnicastV6(addr) && ifSnap != nil {
		for _, pfx := range ifSnap.tetherSubsV6 {
			if pfx.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// scalpelHotspotOnlineState 统一读取当前热点开关状态与在线下游客户端数量（零子进程、纯内存/jsonCache）。
func scalpelHotspotOnlineState(s *server) (hotspotActive bool, onlineCount int, hotspotIface string, hotspotIP string) {
	if s == nil || s.hncDir == "" {
		return false, 0, "", ""
	}
	hotspotIface = s.currentHotspotIface()
	hotspotIP = ifaceIPv4(hotspotIface)
	simEnabled := s.simOn()
	simLive := s.simActive()
	nowUnix := time.Now().Unix()

	onlineMACs := make(map[string]bool)
	if s.jsonCache != nil {
		now := time.Now()
		var devMap map[string]any
		if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "data", "devices.json")); err == nil {
			devMap, _ = raw.(map[string]any)
		}
		shmRes := s.readDpiShmSnapshotReadonly(now)
		var shmOnline map[string]bool
		devMap, shmOnline = s.mergeLiveObservationsReadonly(devMap, shmRes, now)
		for mac, raw := range devMap {
			dm, _ := raw.(map[string]any)
			if dm == nil {
				continue
			}
			cMac := strings.ToLower(strings.TrimSpace(mac))
			if !simEnabled && (strings.HasPrefix(cMac, simMACPrefix) || dm["sim"] == true) {
				continue
			}
			devIP := strings.TrimSpace(asString(dm["ip"]))
			if isDeviceEntryOnline(dm, devIP, nowUnix, shmOnline[cMac]) {
				onlineMACs[cMac] = true
			}
		}
	}
	if simLive {
		views, _ := s.simViews(time.Now())
		for i := range views {
			if !views[i].D.Offline && !views[i].D.Blocked {
				onlineMACs[strings.ToLower(views[i].D.MAC)] = true
			}
		}
	}
	onlineCount = len(onlineMACs)
	hotspotActive = hotspotActiveFromState(s.hncDir, hotspotIface, hotspotIP, onlineCount)
	if simLive {
		hotspotActive = true
	}
	return hotspotActive, onlineCount, hotspotIface, hotspotIP
}

// scalpelInferTargetScope 当 POST /api/v6/scalpel/cut 未显式指定 scope（或陈旧标记未知 UID 热点临时 IPv6 流）时，
// 正交推断目标属于 "hotspot" (FORWARD -> HNC_SCALPEL) 或 "host" (OUTPUT -> HNC_SCALPEL_HOST)。
func scalpelInferTargetScope(s *server, norm ScalpelTuple, rawScope, rawMAC string, hasReqUID bool) (string, error) {
	sc := strings.ToLower(strings.TrimSpace(rawScope))
	switch sc {
	case scalpelHostScopeHotspot:
		return scalpelHostScopeHotspot, nil
	case scalpelHostScopeHost:
		if hasReqUID || canonMAC(rawMAC) != "" || s == nil || s.hncDir == "" {
			return scalpelHostScopeHost, nil
		}
		if scalpelIsWebUISelfPort(norm.Sport) || scalpelIsWebUISelfPort(norm.Dport) {
			return scalpelHostScopeHost, nil
		}
		if srcA, err := netip.ParseAddr(norm.SrcIP); err == nil {
			u := srcA.Unmap()
			if u.IsLoopback() || u.IsLinkLocalUnicast() || u.IsLinkLocalMulticast() {
				return scalpelHostScopeHost, nil
			}
		}
		if dstA, err := netip.ParseAddr(norm.DstIP); err == nil {
			u := dstA.Unmap()
			if u.IsLoopback() || u.IsLinkLocalUnicast() || u.IsLinkLocalMulticast() {
				return scalpelHostScopeHost, nil
			}
		}
		if _, ok := scalpelLookupSocketUID(norm); ok {
			return scalpelHostScopeHost, nil
		}
		hotspotActive, _, hsIface, hsIP := scalpelHotspotOnlineState(s)
		if !hotspotActive {
			return scalpelHostScopeHost, nil
		}
		_, macByIP := scalpelBuildDeviceDirectory(s)
		if macByIP[norm.SrcIP] != "" || macByIP[norm.DstIP] != "" {
			return scalpelHostScopeHotspot, nil
		}
		ifSnap := hostConnLocalIfaceSnapshot(hsIface)
		procSnap := hostConnReadProcSnapshot()
		if scalpelIsSelfLocalAddr(norm.SrcIP, hsIP, ifSnap, procSnap) {
			return scalpelHostScopeHost, nil
		}
		if scalpelIsLikelyUnregisteredTetherClient(norm.SrcIP, hsIP, ifSnap) {
			return scalpelHostScopeHotspot, nil
		}
		if srcA, err := netip.ParseAddr(norm.SrcIP); err == nil {
			srcU := srcA.Unmap()
			v6Owners := scalpelBuildTetherV6PrefixOwners(macByIP, hsIP, ifSnap, procSnap)
			if matched, _ := scalpelMatchExplicitTetherV6Prefix(srcU, ifSnap, v6Owners); matched {
				return scalpelHostScopeHotspot, nil
			}
			if procSnap != nil && procSnap.readable &&
				scalpelIsRoutableUnicastV6(srcU) &&
				!scalpelIsSelfLocalAddr(norm.DstIP, hsIP, ifSnap, procSnap) &&
				!isPrivateIP(norm.DstIP) {
				return scalpelHostScopeHotspot, nil
			}
		}
		return scalpelHostScopeHost, nil
	case "":
	default:
		return "", errors.New("scope must be hotspot or host")
	}

	if canonMAC(rawMAC) != "" {
		return scalpelHostScopeHotspot, nil
	}
	if hasReqUID {
		return scalpelHostScopeHost, nil
	}

	if srcAddr, err := netip.ParseAddr(norm.SrcIP); err == nil {
		u := srcAddr.Unmap()
		if u.IsLoopback() || u.IsLinkLocalUnicast() || u.IsLinkLocalMulticast() {
			return scalpelHostScopeHost, nil
		}
	}
	if dstAddr, err := netip.ParseAddr(norm.DstIP); err == nil {
		u := dstAddr.Unmap()
		if u.IsLoopback() || u.IsLinkLocalUnicast() || u.IsLinkLocalMulticast() {
			return scalpelHostScopeHost, nil
		}
	}

	// 若未绑定 server（如纯引擎级热点单测 newFlowScalpelEngine(nil)），默认保持原有 hotspot 语义
	if s == nil || s.hncDir == "" {
		return scalpelHostScopeHotspot, nil
	}

	_, macByIP := scalpelBuildDeviceDirectory(s)
	if macByIP[norm.SrcIP] != "" || macByIP[norm.DstIP] != "" {
		return scalpelHostScopeHotspot, nil
	}

	if _, ok := scalpelLookupSocketUID(norm); ok {
		return scalpelHostScopeHost, nil
	}

	hotspotActive, _, hsIface, hsIP := scalpelHotspotOnlineState(s)
	ifSnap := hostConnLocalIfaceSnapshot(hsIface)
	procSnap := hostConnReadProcSnapshot()
	if scalpelIsSelfLocalAddr(norm.SrcIP, hsIP, ifSnap, procSnap) {
		return scalpelHostScopeHost, nil
	}
	if scalpelIsLikelyUnregisteredTetherClient(norm.SrcIP, hsIP, ifSnap) {
		return scalpelHostScopeHotspot, nil
	}
	if srcAddr, err := netip.ParseAddr(norm.SrcIP); err == nil {
		v6Owners := scalpelBuildTetherV6PrefixOwners(macByIP, hsIP, ifSnap, procSnap)
		if matched, _ := scalpelMatchExplicitTetherV6Prefix(srcAddr.Unmap(), ifSnap, v6Owners); matched {
			return scalpelHostScopeHotspot, nil
		}
	}
	if !hotspotActive {
		return scalpelHostScopeHost, nil
	}
	return scalpelHostScopeHotspot, nil
}

type scalpelClassifiedFlow struct {
	Scope         string
	FlowKey       string
	Proto         string
	SrcIP         string
	Sport         int
	DstIP         string
	Dport         int
	IsV6          bool
	State         string
	TTL           int
	MAC           string
	DeviceName    string
	UID           int
	Package       string
	HostAppName   string
	IsSystem      bool
	CleartextRisk string
	Company       string
	OwnerJSON     map[string]interface{}
	Domain        string
	DomainSrc     string
	AppID         string
	AppName       string
	AppSrc        string
	AppConf       float64
	JA4           string
	IsSDK         bool
	UpBytes       uint64
	DownBytes     uint64
	UpBps         float64
	DownBps       float64
	Inode         uint64
	TxQueue       uint64
	RxQueue       uint64
	Unreplied     bool
	TrafficType   string
	TrafficConf   float64
	FrozenUntil   int64
}

type scalpelDualFlowSnapshot struct {
	Readable     bool
	HotspotFlows int
	HostFlows    int
	HotspotList  []scalpelClassifiedFlow
	HostList     []scalpelClassifiedFlow
}

// scalpelCollectDualDomainFlows 执行四路内存 JOIN (/proc/net/* + conntrack + DPI 域名/应用表 + ip_owner)
// 并将连接严格正交拆分为 hotspot 与 host 两个集合。
func scalpelCollectDualDomainFlows(s *server, activeHotspotRules, activeHostRules []ScalpelActiveRule) scalpelDualFlowSnapshot {
	var out scalpelDualFlowSnapshot
	if s == nil {
		return out
	}

	ctSnap := conntrackSnapshot()
	procSnap := hostConnReadProcSnapshot()
	out.Readable = (ctSnap != nil && ctSnap.readable) || (procSnap != nil && procSnap.readable)

	hotspotActive, onlineCount, hsIface, hsIP := scalpelHotspotOnlineState(s)
	ifSnap := hostConnLocalIfaceSnapshot(hsIface)
	nameByMAC, macByIP := scalpelBuildDeviceDirectory(s)
	v6PfxOwners := scalpelBuildTetherV6PrefixOwners(macByIP, hsIP, ifSnap, procSnap)
	names := s.loadIPNames()
	apps := s.loadIPApps()
	fpSt, now := fpFor(s.hncDir), time.Now()

	isGatewayAddr := func(ip string) bool {
		return scalpelIsSelfLocalAddr(ip, hsIP, ifSnap, procSnap)
	}

	frozenHotspot := func(mac, src, dst string, dport int, proto string) int64 {
		cMac := canonMAC(mac)
		for _, r := range activeHotspotRules {
			if r.Mode != "freeze_15m" || r.Tuple.DstIP != dst || r.Tuple.Dport != dport || r.Tuple.Proto != proto {
				continue
			}
			rMac := canonMAC(r.ClientMAC)
			if (rMac != "" && cMac != "" && rMac == cMac) || r.Tuple.SrcIP == src {
				return r.ExpiresUnix
			}
		}
		return 0
	}

	frozenHost := func(uid int, dst string, dport int, proto string) int64 {
		for _, r := range activeHostRules {
			if r.Mode != "freeze_15m" || r.Tuple.DstIP != dst || r.Tuple.Dport != dport || r.Tuple.Proto != proto {
				continue
			}
			if uid >= 0 && (r.UID == uid || scalpelSameOrPairedHostUID(r.UID, uid)) {
				return r.ExpiresUnix
			}
		}
		return 0
	}

	enrichTarget := func(flowKey, proto, dstIP string, dport int) (domain, domainSrc, appID, appName, appSrc string, appConf float64, ja4, company string, ownerJSON map[string]interface{}, isSDK bool) {
		if nm, ok := names[dstIP]; ok {
			domain = nm.Name
			domainSrc = nm.Src
			appID = nm.App
			appName = nm.AppName
		}
		if fpSt != nil {
			if fa, ok := fpSt.attribute(flowKey, apps, names, now); ok {
				appID = fa.App.ID
				appName = fa.App.Name
				appSrc = fa.Src
				appConf = fa.Conf
				ja4 = fa.JA4
				isSDK = appTier(fa.App.Category) == tierHidden
			} else if fa.JA4 != "" {
				ja4 = fa.JA4
			}
		}
		if appName == "" {
			if ap, ok := apps[dstIP]; ok {
				appID = ap.ID
				appName = ap.Name
				if appSrc == "" {
					appSrc = "rule"
				}
				isSDK = appTier(ap.Category) == tierHidden
			}
		}
		if !isPrivateIP(dstIP) {
			if org, ok := ipOwnerLookup(dstIP); ok {
				company = org.Name
				ownerJSON = org.JSON()
				if appName == "" && org.Kind == ipOwnerKindApp {
					appName = org.AppName()
				}
			}
		}
		if appName == "" {
			appName = wellKnownSvc(proto, dport)
		}
		return
	}

	appendHotspotEntry := func(ent ctEntry, clientMAC, clientIP, remoteIP string, sport, dport int, reversed bool) {
		if !s.simOn() && strings.HasPrefix(strings.ToLower(clientMAC), simMACPrefix) {
			return
		}
		upB, dnB := ent.UpB, ent.DnB
		k := ent.key()
		var upBps, dnBps float64
		if ctSnap != nil {
			// ctSnap 内部存 bits/s (供 liveAppMinBps 使用), 对外连接行统一 / 8 输出 bytes/s
			upBps, dnBps = ctSnap.upBps[k]/8, ctSnap.dnBps[k]/8
		}
		if reversed {
			upB, dnB = ent.DnB, ent.UpB
			upBps, dnBps = dnBps, upBps
		}
		devName := ""
		if clientMAC != "" {
			devName = nameByMAC[clientMAC]
			if devName == "" {
				devName = clientMAC
			}
		} else {
			devName = clientIP
		}
		domain, domainSrc, appID, appName, appSrc, appConf, ja4, company, ownerJSON, isSDK := enrichTarget(k, ent.Proto, remoteIP, dport)
		tt, tconf, _ := flowTrafficType(k)

		out.HotspotList = append(out.HotspotList, scalpelClassifiedFlow{
			Scope:       scalpelHostScopeHotspot,
			FlowKey:     k,
			Proto:       ent.Proto,
			SrcIP:       clientIP,
			Sport:       sport,
			DstIP:       remoteIP,
			Dport:       dport,
			IsV6:        ent.Family == "ipv6",
			State:       ent.State,
			TTL:         ent.TTL,
			MAC:         clientMAC,
			DeviceName:  devName,
			UID:         -1,
			Company:     company,
			OwnerJSON:   ownerJSON,
			Domain:      domain,
			DomainSrc:   domainSrc,
			AppID:       appID,
			AppName:     appName,
			AppSrc:      appSrc,
			AppConf:     appConf,
			JA4:         ja4,
			IsSDK:       isSDK,
			UpBytes:     upB,
			DownBytes:   dnB,
			UpBps:       upBps,
			DownBps:     dnBps,
			Unreplied:   ent.Unrepl,
			TrafficType: tt,
			TrafficConf: tconf,
			FrozenUntil: frozenHotspot(clientMAC, clientIP, remoteIP, dport, ent.Proto),
		})
	}

	// 为 conntrack 建立五元组索引供 /proc/net 本机 socket 双向 JOIN 字节与速率
	type ctIndexed struct {
		idx int
		ent ctEntry
	}
	var ctEntries []ctEntry
	if ctSnap != nil && ctSnap.readable {
		ctEntries = ctSnap.entries
	}
	ctByKey := make(map[string]ctIndexed, len(ctEntries))
	ctByRev := make(map[string]ctIndexed, len(ctEntries))
	usedCT := make([]bool, len(ctEntries))

	for i, ent := range ctEntries {
		if ent.Proto != "tcp" && ent.Proto != "udp" {
			usedCT[i] = true
			continue
		}
		k := ent.key()
		ctByKey[k] = ctIndexed{idx: i, ent: ent}
		rk := ent.Proto + "|" + ent.Dst + "|" + strconv.Itoa(ent.Dport) + "|" + ent.Src + "|" + strconv.Itoa(ent.Sport)
		ctByRev[rk] = ctIndexed{idx: i, ent: ent}
	}

	// Step A: 分类所有命中下游热点客户端 IP/MAC 的连接 (scope == "hotspot")
	for i, ent := range ctEntries {
		if usedCT[i] {
			continue
		}
		srcAddr, errS := netip.ParseAddr(ent.Src)
		dstAddr, errD := netip.ParseAddr(ent.Dst)
		if errS == nil && srcAddr.Unmap().IsLoopback() {
			usedCT[i] = true
			continue
		}
		if errD == nil && dstAddr.Unmap().IsLoopback() {
			usedCT[i] = true
			continue
		}

		macSrc := macByIP[ent.Src]
		macDst := macByIP[ent.Dst]
		if macSrc == "" && macDst == "" {
			continue
		}
		usedCT[i] = true

		// 排除下游设备发往手机网关本机的 :53/:67/:68/:8443/:8444/:8080 管理与基础服务流
		if macSrc != "" && (isGatewayAddr(ent.Dst) || isPrivateIP(ent.Dst)) && scalpelIsGatewayLocalServicePort(ent.Dport) {
			continue
		}
		if macDst != "" && (isGatewayAddr(ent.Src) || isPrivateIP(ent.Src)) && scalpelIsGatewayLocalServicePort(ent.Sport) {
			continue
		}

		if macSrc != "" {
			appendHotspotEntry(ent, macSrc, ent.Src, ent.Dst, ent.Sport, ent.Dport, false)
		} else {
			appendHotspotEntry(ent, macDst, ent.Dst, ent.Src, ent.Dport, ent.Sport, true)
		}
	}

	// Step B: 四路内存 JOIN 构建手机本机连接 (scope == "host")
	// B1) 遍历 /proc/net/{tcp,tcp6,udp,udp6} 本机活跃外联 socket 并关联 conntrack 字节/速率
	if procSnap != nil && len(procSnap.list) > 0 {
		for _, sk := range procSnap.list {
			// 排除手机网关被动响应下游热点客户端的反向服务端 socket
			if macByIP[sk.SrcIP] != "" || macByIP[sk.DstIP] != "" {
				continue
			}
			if scalpelIsGatewayLocalServicePort(sk.Sport) && isPrivateIP(sk.DstIP) {
				continue
			}
			if scalpelIsLikelyUnregisteredTetherClient(sk.DstIP, hsIP, ifSnap) {
				continue
			}
			if dstA, err := netip.ParseAddr(sk.DstIP); err == nil {
				if matched, _ := scalpelMatchExplicitTetherV6Prefix(dstA.Unmap(), ifSnap, v6PfxOwners); matched {
					continue
				}
			}

			k := sk.key()
			var (
				upB, dnB     uint64
				upBps, dnBps float64
				ttl          int
				state        = sk.State
				unreplied    bool
			)
			if hit, ok := ctByKey[k]; ok {
				usedCT[hit.idx] = true
				upB, dnB = hit.ent.UpB, hit.ent.DnB
				if ctSnap != nil {
					hk := hit.ent.key()
					upBps, dnBps = ctSnap.upBps[hk]/8, ctSnap.dnBps[hk]/8
				}
				ttl = hit.ent.TTL
				if state == "" {
					state = hit.ent.State
				}
				unreplied = hit.ent.Unrepl
			} else if revHit, ok := ctByRev[k]; ok {
				usedCT[revHit.idx] = true
				upB, dnB = revHit.ent.DnB, revHit.ent.UpB
				if ctSnap != nil {
					rk := revHit.ent.key()
					upBps, dnBps = ctSnap.dnBps[rk]/8, ctSnap.upBps[rk]/8
				}
				ttl = revHit.ent.TTL
				if state == "" {
					state = revHit.ent.State
				}
				unreplied = revHit.ent.Unrepl
			}

			id := scalpelResolveHostUID(s.hncDir, sk.UID)
			risk := scalpelDetectCleartextRiskForTarget(sk.Proto, sk.DstIP, sk.Dport, sk.UID)
			domain, domainSrc, appID, appName, appSrc, appConf, ja4, company, ownerJSON, isSDK := enrichTarget(k, sk.Proto, sk.DstIP, sk.Dport)
			if appName == "" {
				appName = id.AppName
			}
			tt, tconf, _ := flowTrafficType(k)

			out.HostList = append(out.HostList, scalpelClassifiedFlow{
				Scope:         scalpelHostScopeHost,
				FlowKey:       k,
				Proto:         sk.Proto,
				SrcIP:         sk.SrcIP,
				Sport:         sk.Sport,
				DstIP:         sk.DstIP,
				Dport:         sk.Dport,
				IsV6:          sk.IsV6,
				State:         state,
				TTL:           ttl,
				MAC:           "",
				DeviceName:    id.AppName,
				UID:           sk.UID,
				Package:       id.Package,
				HostAppName:   id.AppName,
				IsSystem:      id.IsSystem,
				CleartextRisk: risk,
				Company:       company,
				OwnerJSON:     ownerJSON,
				Domain:        domain,
				DomainSrc:     domainSrc,
				AppID:         appID,
				AppName:       appName,
				AppSrc:        appSrc,
				AppConf:       appConf,
				JA4:           ja4,
				IsSDK:         isSDK,
				UpBytes:       upB,
				DownBytes:     dnB,
				UpBps:         upBps,
				DownBps:       dnBps,
				Inode:         sk.Inode,
				TxQueue:       sk.TxQueue,
				RxQueue:       sk.RxQueue,
				Unreplied:     unreplied,
				TrafficType:   tt,
				TrafficConf:   tconf,
				FrozenUntil:   frozenHost(sk.UID, sk.DstIP, sk.Dport, sk.Proto),
			})
		}
	}

	// B2) 对剩余未命中 /proc/net 活跃 socket 的 conntrack 条目做双域精准分流:
	//   - 若命中下游热点子网、已知客户端 /64 前缀或热点激活态下的非本机临时隐私 IPv6 转发流 -> 归入 HotspotList (C058)；
	//   - 仅本机自身短命/TIME_WAIT 外联流归入 HostList。
	for i, ent := range ctEntries {
		if usedCT[i] {
			continue
		}
		srcAddr, errS := netip.ParseAddr(ent.Src)
		dstAddr, errD := netip.ParseAddr(ent.Dst)
		if errS != nil || errD != nil {
			continue
		}
		srcU := srcAddr.Unmap()
		dstU := dstAddr.Unmap()
		if srcU.IsLoopback() || dstU.IsLoopback() || srcU.IsMulticast() || dstU.IsMulticast() {
			continue
		}

		srcIsSelf := isGatewayAddr(ent.Src)
		dstIsSelf := isGatewayAddr(ent.Dst)

		// 1) 正向检查未入 macByIP 的热点客户端 (IPv4 热点网段 / IPv6 已知 /64 前缀 / 热点激活态非本机临时隐私 IPv6)
		if !srcIsSelf {
			srcExplicitTether := scalpelIsLikelyUnregisteredTetherClient(ent.Src, hsIP, ifSnap)
			inferredMAC := ""
			if !srcExplicitTether && srcU.Is6() {
				srcExplicitTether, inferredMAC = scalpelMatchExplicitTetherV6Prefix(srcU, ifSnap, v6PfxOwners)
			}
			srcUnregHotspotV6 := !srcExplicitTether && hotspotActive &&
				procSnap != nil && procSnap.readable &&
				scalpelIsRoutableUnicastV6(srcU) && !dstIsSelf && !isPrivateIP(ent.Dst) &&
				ent.State != "TIME_WAIT"

			if srcExplicitTether || srcUnregHotspotV6 {
				if (dstIsSelf || isPrivateIP(ent.Dst)) && scalpelIsGatewayLocalServicePort(ent.Dport) {
					continue
				}
				if hotspotActive && !dstIsSelf {
					appendHotspotEntry(ent, inferredMAC, ent.Src, ent.Dst, ent.Sport, ent.Dport, false)
				}
				continue
			}
		}

		// 2) 反向检查确定性热点子网/前缀 (远端主动包先入 conntrack 的场景)
		if !dstIsSelf && !srcIsSelf && !isPrivateIP(ent.Src) {
			dstExplicitTether := scalpelIsLikelyUnregisteredTetherClient(ent.Dst, hsIP, ifSnap)
			inferredMAC := ""
			if !dstExplicitTether && dstU.Is6() {
				dstExplicitTether, inferredMAC = scalpelMatchExplicitTetherV6Prefix(dstU, ifSnap, v6PfxOwners)
			}
			if dstExplicitTether {
				if scalpelIsGatewayLocalServicePort(ent.Sport) {
					continue
				}
				if hotspotActive {
					appendHotspotEntry(ent, inferredMAC, ent.Dst, ent.Src, ent.Dport, ent.Sport, true)
				}
				continue
			}
		}

		if isPrivateIP(ent.Dst) {
			continue
		}

		k := ent.key()
		var upBps, dnBps float64
		if ctSnap != nil {
			upBps, dnBps = ctSnap.upBps[k]/8, ctSnap.dnBps[k]/8
		}
		id := scalpelResolveHostUID(s.hncDir, -1)
		risk := scalpelDetectCleartextRiskForTarget(ent.Proto, ent.Dst, ent.Dport, -1)
		domain, domainSrc, appID, appName, appSrc, appConf, ja4, company, ownerJSON, isSDK := enrichTarget(k, ent.Proto, ent.Dst, ent.Dport)
		tt, tconf, _ := flowTrafficType(k)

		out.HostList = append(out.HostList, scalpelClassifiedFlow{
			Scope:         scalpelHostScopeHost,
			FlowKey:       k,
			Proto:         ent.Proto,
			SrcIP:         ent.Src,
			Sport:         ent.Sport,
			DstIP:         ent.Dst,
			Dport:         ent.Dport,
			IsV6:          ent.Family == "ipv6",
			State:         ent.State,
			TTL:           ent.TTL,
			MAC:           "",
			DeviceName:    id.AppName,
			UID:           -1,
			Package:       "",
			HostAppName:   id.AppName,
			IsSystem:      false,
			CleartextRisk: risk,
			Company:       company,
			OwnerJSON:     ownerJSON,
			Domain:        domain,
			DomainSrc:     domainSrc,
			AppID:         appID,
			AppName:       appName,
			AppSrc:        appSrc,
			AppConf:       appConf,
			JA4:           ja4,
			IsSDK:         isSDK,
			UpBytes:       ent.UpB,
			DownBytes:     ent.DnB,
			UpBps:         upBps,
			DownBps:       dnBps,
			Unreplied:     ent.Unrepl,
			TrafficType:   tt,
			TrafficConf:   tconf,
		})
	}

	// Step C (B015): 模拟环境开启时合并在线且未拉黑 (!Offline && !Blocked) 的 simConnsFor 模拟连接流;
	// 当 !s.simOn() 时主动剔除任何残留 02:5e:00:* 模拟条目确保隔离。
	if s.simActive() {
		views, seed := s.simViews(now)
		lib := func(id string) (simApp, bool) { return simFindApp(s.hncDir, id) }
		for i := range views {
			v := &views[i]
			d := &v.D
			if d.Offline || d.Blocked {
				continue
			}
			out.Readable = true
			srcIP := strings.TrimSpace(d.IP)
			if srcIP == "" {
				srcIP = "192.168.43.200"
			}
			devName := d.Name
			if devName == "" {
				devName = d.Hostname
			}
			if devName == "" {
				devName = d.MAC
			}
			simAID, simAName, _ := simAppIDName(d)
			for _, c := range simConnsFor(v, seed, lib) {
				blocked := simConnBlocked(d.ConnBlocks, c.host, c.ip)
				upBps := float64(v.Tx) * c.weight
				dnBps := float64(v.Rx) * c.weight
				if blocked {
					upBps, dnBps = 0, 0
				}
				avg := float64(d.RxBps+d.TxBps) * c.weight
				dnB := uint64(avg * c.age * 0.9)
				upB := uint64(float64(d.TxBps) * c.weight * c.age)
				if c.dport == 53 || c.dport == 123 {
					dnB, upB = uint64(200+c.sport%800), uint64(80+c.sport%300)
				}
				fk := c.proto + "|" + srcIP + "|" + strconv.Itoa(c.sport) + "|" + c.ip + "|" + strconv.Itoa(c.dport)
				st := ""
				ttl := 30 + c.sport%150
				if c.proto == "tcp" {
					st = "ESTABLISHED"
					ttl = 431000 + c.sport%999
				}
				fAppID, fAppName, fAppSrc := "", "", ""
				if c.app && d.AppID != "" {
					fAppID = simAID
					fAppName = simAName
					fAppSrc = "rule"
				}
				if fAppName == "" {
					fAppName = wellKnownSvc(c.proto, c.dport)
				}
				var company string
				var ownerJSON map[string]interface{}
				if !isPrivateIP(c.ip) {
					if org, ok := ipOwnerLookup(c.ip); ok {
						company = org.Name
						ownerJSON = org.JSON()
					}
				}
				out.HotspotList = append(out.HotspotList, scalpelClassifiedFlow{
					Scope:       scalpelHostScopeHotspot,
					FlowKey:     fk,
					Proto:       c.proto,
					SrcIP:       srcIP,
					Sport:       c.sport,
					DstIP:       c.ip,
					Dport:       c.dport,
					IsV6:        false,
					State:       st,
					TTL:         ttl,
					MAC:         d.MAC,
					DeviceName:  devName,
					UID:         -1,
					Company:     company,
					OwnerJSON:   ownerJSON,
					Domain:      c.host,
					DomainSrc:   c.nameSrc,
					AppID:       fAppID,
					AppName:     fAppName,
					AppSrc:      fAppSrc,
					UpBytes:     upB,
					DownBytes:   dnB,
					UpBps:       upBps,
					DownBps:     dnBps,
					FrozenUntil: frozenHotspot(d.MAC, srcIP, c.ip, c.dport, c.proto),
				})
			}
		}
	} else if !s.simOn() && len(out.HotspotList) > 0 {
		filtered := out.HotspotList[:0]
		for _, fl := range out.HotspotList {
			if strings.HasPrefix(strings.ToLower(fl.MAC), simMACPrefix) {
				continue
			}
			filtered = append(filtered, fl)
		}
		out.HotspotList = filtered
	}

	// 铁律校准: 当热点关闭或当前在线热点客户端数为 0 时，hotspot_flows 严格归零，绝不混入本机流或离线残留流！
	if hotspotActive && onlineCount > 0 {
		out.HotspotFlows = len(out.HotspotList)
	} else {
		out.HotspotFlows = 0
	}
	out.HostFlows = len(out.HostList)
	return out
}

// ── 6. 轻量级双域计数缓存（供 CoreHub 降级、/api/live、/api/connections、scalpel.summary 共享） ──

type hostConnSplitCountEntry struct {
	at           time.Time
	procRoot     string
	ctPath       string
	simActive    bool
	onlineCount  int
	hotspotFlows uint32
	hostFlows    uint32
}

var hostConnSplitCountCache struct {
	mu    sync.Mutex
	byDir map[string]hostConnSplitCountEntry
}

func scalpelCountSplitFlowsCached(s *server, hotspotActive bool, onlineCount int) (hotspotFlows, hostFlows uint32) {
	if s == nil || s.hncDir == "" {
		return 0, 0
	}
	now := time.Now()
	procRoot := hostConnProcNetDirFn()
	ctPath := conntrackPath()
	simAct := s.simActive()

	useCache := procRoot == "/proc/net" && os.Getenv("HNC_CONNTRACK_PATH") == ""
	if useCache {
		hostConnSplitCountCache.mu.Lock()
		if hostConnSplitCountCache.byDir != nil {
			if c, ok := hostConnSplitCountCache.byDir[s.hncDir]; ok &&
				c.procRoot == procRoot && c.ctPath == ctPath &&
				c.simActive == simAct && (!simAct || c.onlineCount == onlineCount) &&
				now.Sub(c.at) >= 0 && now.Sub(c.at) < hostConnCountCacheTTL {
				hs := c.hotspotFlows
				if !hotspotActive || onlineCount <= 0 {
					hs = 0
				}
				hostConnSplitCountCache.mu.Unlock()
				return hs, c.hostFlows
			}
		}
		hostConnSplitCountCache.mu.Unlock()
	}

	snap := scalpelCollectDualDomainFlows(s, nil, nil)
	rawHotspot := uint32(len(snap.HotspotList))
	rawHost := uint32(snap.HostFlows)

	if useCache {
		hostConnSplitCountCache.mu.Lock()
		if hostConnSplitCountCache.byDir == nil {
			hostConnSplitCountCache.byDir = make(map[string]hostConnSplitCountEntry)
		}
		hostConnSplitCountCache.byDir[s.hncDir] = hostConnSplitCountEntry{
			at:           now,
			procRoot:     procRoot,
			ctPath:       ctPath,
			simActive:    simAct,
			onlineCount:  onlineCount,
			hotspotFlows: rawHotspot,
			hostFlows:    rawHost,
		}
		hostConnSplitCountCache.mu.Unlock()
	}

	if !hotspotActive || onlineCount <= 0 {
		return 0, rawHost
	}
	return rawHotspot, rawHost
}

// scalpelLiveFlowCounts 结合 CoreHub 最新 SHM 快照（若有效且新鲜）或轻量正交分类计数，
// 确保热点关闭或 0 在线设备时 hotspot_flows 恒为 0，且模拟环境激活时准确计入模拟连接流。
func scalpelLiveFlowCounts(s *server, hotspotActive bool, onlineCount int) (hotspotFlows, hostFlows uint32) {
	if s == nil || s.hncDir == "" {
		return 0, 0
	}
	if !s.simActive() {
		if v, ok := serverHubMap.Load(s); ok {
			if hub, _ := v.(*CoreHub); hub != nil {
				if ws := hub.Snapshot(); ws != nil && ws.Live.Sim == s.simOn() && monoNowNs()-ws.GeneratedMonoNs < int64(5*time.Second) {
					hs := uint32(0)
					if hotspotActive && onlineCount > 0 && ws.Live.HotspotFlows > 0 {
						hs = uint32(ws.Live.HotspotFlows)
					}
					hf := uint32(0)
					if ws.Live.HostFlows > 0 {
						hf = uint32(ws.Live.HostFlows)
					}
					if hf > 0 || hs > 0 {
						return hs, hf
					}
				}
			}
		}
	}
	return scalpelCountSplitFlowsCached(s, hotspotActive, onlineCount)
}
