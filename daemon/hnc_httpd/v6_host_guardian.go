// v6_host_guardian.go — HNC v6.1 本机守护核心引擎:
//   1. GET /api/local_apps/traffic       eBPF 实时应用网速 + 8s 短租约零空转采样 + 前后台真实耗流排行
//   2. GET /api/local_apps/power         流式解析 batterystats --charged 后台耗电与硬件唤醒排行
//   3. GET /api/local_apps/privacy_audit L1 零抓包本机明文 HTTP / 旁路 DNS / 追踪 SDK / 后台外发实时安检
//
// 核心工程铁律:
//   - 所有 64 位原子字段严格置于结构体 offset 0, 100% 兼容 32 位 armeabi-v7a (GOARCH=arm)。
//   - 未停留在本机守护页时: 0 常驻协程、0 定时唤醒、0 BPF fd 占用、0 run/ tmpfs 写入。
//   - 严禁拿开机均速冒充实时网速, 严禁拿 CPU/锁时长比例乘算假后台毫安时, 无权限时诚实返回 available=false。
//   - RegisterServerVectorSyncProvider("host_guardian", ...) 仅返回纯无副作用内存只读摘要。

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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
	"syscall"
	"time"
	"unsafe"

	"hnc.io/dpid/appmeta"
	"hnc.io/dpid/bytestats"
)

const (
	guardianDefaultLeaseTTL     = 8 * time.Second
	guardianDefaultTickInterval = 2 * time.Second
	guardianNetstatsBootTTL     = 15 * time.Second
	guardianNetstatsFullTTL     = 60 * time.Second
	guardianPowerCacheTTL       = 45 * time.Second
	guardianPowerRefreshMinCool = 15 * time.Second
	guardianPowerCmdTimeout     = 5 * time.Second
	guardianNetstatsCmdTimeout  = 8 * time.Second
	guardianSingleFlightTimeout = 8 * time.Second
	guardianMaxStreamBytes      = 32 << 20 // 32 MiB hard stream cap
)

func init() {
	RegisterServerVectorSyncProvider("host_guardian", guardianVectorSyncSummary)
}

// ─── SingleFlight (零外部依赖并发合并器, 独立后台超时防首连接取消连坐) ──────────

type guardianSFCall struct {
	done chan struct{}
	val  any
	err  error
}

type guardianSingleFlight struct {
	mu sync.Mutex
	m  map[string]*guardianSFCall
}

func (g *guardianSingleFlight) DoCtx(callerCtx context.Context, key string, timeout time.Duration, fn func(ctx context.Context) (any, error)) (any, error) {
	if callerCtx == nil {
		callerCtx = context.Background()
	}
	if err := callerCtx.Err(); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = guardianSingleFlightTimeout
	}

	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*guardianSFCall)
	}
	c, dup := g.m[key]
	if !dup {
		c = &guardianSFCall{done: make(chan struct{})}
		g.m[key] = c
		g.mu.Unlock()

		go func(call *guardianSFCall) {
			execCtx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			defer func() {
				g.mu.Lock()
				delete(g.m, key)
				g.mu.Unlock()
				close(call.done)
			}()
			call.val, call.err = fn(execCtx)
		}(c)
	} else {
		g.mu.Unlock()
	}

	select {
	case <-c.done:
		return c.val, c.err
	case <-callerCtx.Done():
		return nil, callerCtx.Err()
	}
}

func (g *guardianSingleFlight) Do(key string, fn func() (any, error)) (any, error) {
	return g.DoCtx(context.Background(), key, guardianSingleFlightTimeout, func(_ context.Context) (any, error) {
		return fn()
	})
}

// ─── BPF 采样器抽象接口 (支持单测无 Root 注入真实行为状态机) ──────────

type guardianBPFSampler interface {
	SampleDetail() (*bytestats.NetdDetailSnapshot, error)
	Close() error
}

type guardianRealBPFSampler struct {
	inner *bytestats.NetdDetailSampler
}

func (r *guardianRealBPFSampler) SampleDetail() (*bytestats.NetdDetailSnapshot, error) {
	return r.inner.SampleDetail()
}

func (r *guardianRealBPFSampler) Close() error {
	if r == nil || r.inner == nil {
		return nil
	}
	return r.inner.Close()
}

// ─── 核心引擎实例与按 *server 惰性注册表 ──────────────────────────────

type guardianUIDRate struct {
	rxBps int64
	txBps int64
}

type guardianUIDSplitBytes struct {
	bgRx uint64
	bgTx uint64
	fgRx uint64
	fgTx uint64
}

type guardianNetstatsCacheEntry struct {
	fetchedMonoNs int64
	dump          *nsDump
	lastABTotal   uint64
}

type guardianPowerCacheEntry struct {
	fetchedMonoNs int64
	generatedAt   int64
	parsed        *guardianParsedBatteryStats
}

type guardianHostEngine struct {
	// 铁律: 所有 64 位原子字段严格置于结构体起始 offset 0, 8, 16... 保证 32 位 ARMv7 8 字节对齐
	leaseUntilMonoNs   atomic.Int64  // offset 0
	lastPowerFetchMono atomic.Int64  // offset 8
	trafficHits        atomic.Uint64 // offset 16
	powerHits          atomic.Uint64 // offset 24
	privacyHits        atomic.Uint64 // offset 32
	leaseStarts        atomic.Uint64 // offset 40
	leaseStops         atomic.Uint64 // offset 48
	totalRxBpsSnap     atomic.Int64  // offset 56
	totalTxBpsSnap     atomic.Int64  // offset 64
	lastPrivacyRisky   atomic.Int64  // offset 72

	leaseRunning      atomic.Bool
	rateWarmingUp     atomic.Bool
	powerCachedFlag   atomic.Bool
	privacyCachedFlag atomic.Bool
	trackedAppsSnap   atomic.Int32

	srv *server

	// 8s 短租约 eBPF 实时流量采样状态
	trafficMu     sync.Mutex
	bpfSampler    guardianBPFSampler
	latestBPFSnap *bytestats.NetdDetailSnapshot
	prevBPFSnap   *bytestats.NetdDetailSnapshot
	prevBPFMonoNs int64
	liveRates     map[int]guardianUIDRate
	lastBPFErr    error
	stopLeaseCh   chan struct{}
	leaseDoneCh   chan struct{}
	bootHighWater map[string]map[int]guardianUIDSplitBytes // netFilter -> uid -> monotonic floor

	// netstats 按需缓存与并发合并
	netstatsMu sync.Mutex
	bootCache  *guardianNetstatsCacheEntry
	fullCache  *guardianNetstatsCacheEntry
	netstatsSF guardianSingleFlight

	// batterystats 按需缓存与并发合并
	powerMu    sync.RWMutex
	powerCache *guardianPowerCacheEntry
	powerSF    guardianSingleFlight

	// 应用包名与中文名零 app_process 解析缓存
	pkgMu            sync.RWMutex
	pkgLoadedMonoNs  int64
	pkgListMtimeUnix int64
	pkgListSize      int64
	uidToPkg         map[int]string
	pkgToUID         map[string]int
	sysUIDs          map[int]bool
	labelResolver    *appmeta.Resolver
	liveLabelCache   map[string]string
	liveLabelMtime   int64
	liveLabelPath    string
	vpnExcludeUser   map[string]bool

	// DPI 广告/追踪 SDK 规则缓存
	ruleMu          sync.RWMutex
	ruleLoadedMono  int64
	trackerExact    map[string]guardianTrackerRule
	trackerSuffixes []guardianTrackerRule

	// 单测可覆盖钩子(生产环境均为零值)
	leaseTTL             time.Duration
	tickInterval         time.Duration
	bpfSamplerFactory    func() (guardianBPFSampler, error)
	netstatsStreamFn     func(ctx context.Context, full bool) (io.ReadCloser, error)
	batterystatsStreamFn func(ctx context.Context) (io.ReadCloser, error)
	procNetDir           string
	packagesListPath     string
	fgUIDsFallbackFn     func() (map[int]bool, bool)
	vpnActiveFn          func() bool
	nowFn                func() time.Time
}

// 编译期 32 位 / 64 位对齐断言
var (
	_ [0 - int(unsafe.Offsetof(guardianHostEngine{}.leaseUntilMonoNs))]byte
	_ [8 - int(unsafe.Alignof(guardianHostEngine{}))]byte
	_ [int(unsafe.Alignof(guardianHostEngine{})) - 8]byte
)

var guardianRegistry sync.Map // map[*server]*guardianHostEngine

func newGuardianHostEngine(s *server) *guardianHostEngine {
	var overridePath string
	if s != nil && s.hncDir != "" {
		overridePath = filepath.Join(s.hncDir, "etc", "app_labels.json")
	}
	return &guardianHostEngine{
		srv:           s,
		liveRates:     make(map[int]guardianUIDRate),
		bootHighWater: make(map[string]map[int]guardianUIDSplitBytes),
		uidToPkg:      make(map[int]string),
		pkgToUID:      make(map[string]int),
		sysUIDs:       make(map[int]bool),
		labelResolver: appmeta.NewResolver(overridePath),
	}
}

func (s *server) guardianEngine() *guardianHostEngine {
	if s == nil {
		return newGuardianHostEngine(nil)
	}
	if v, ok := guardianRegistry.Load(s); ok {
		return v.(*guardianHostEngine)
	}
	ne := newGuardianHostEngine(s)
	actual, _ := guardianRegistry.LoadOrStore(s, ne)
	return actual.(*guardianHostEngine)
}

func guardianPeekEngine(s *server) *guardianHostEngine {
	if s == nil {
		return nil
	}
	if v, ok := guardianRegistry.Load(s); ok {
		return v.(*guardianHostEngine)
	}
	return nil
}

func (s *server) guardianClose() {
	e := guardianPeekEngine(s)
	if e != nil {
		e.stopTrafficLeaseNow()
	}
}

// guardianVectorSyncSummary 供 /api/vector_sync 读取纯无副作用内存快照摘要。
// 严禁在此函数内续租、打开 BPF fd、扫描 /proc 或拉起任何子进程!
func guardianVectorSyncSummary(s *server) any {
	scEnabled, _ := s.guardianReadSelfCaptureStatus()
	e := guardianPeekEngine(s)
	if e == nil {
		return map[string]any{
			"lease_active":         false,
			"rate_warming_up":      false,
			"tracked_apps":         0,
			"total_rx_bps":         int64(0),
			"total_tx_bps":         int64(0),
			"power_cached":         false,
			"privacy_cached":       false,
			"risky_apps_count":     int64(0),
			"self_capture_enabled": scEnabled,
		}
	}
	leaseActive := e.leaseRunning.Load() && monoNowNs() <= e.leaseUntilMonoNs.Load()
	rxBps := int64(0)
	txBps := int64(0)
	if leaseActive {
		rxBps = e.totalRxBpsSnap.Load()
		txBps = e.totalTxBpsSnap.Load()
	}
	return map[string]any{
		"lease_active":         leaseActive,
		"rate_warming_up":      leaseActive && e.rateWarmingUp.Load(),
		"tracked_apps":         int(e.trackedAppsSnap.Load()),
		"total_rx_bps":         rxBps,
		"total_tx_bps":         txBps,
		"power_cached":         e.powerCachedFlag.Load(),
		"privacy_cached":       e.privacyCachedFlag.Load(),
		"risky_apps_count":     e.lastPrivacyRisky.Load(),
		"self_capture_enabled": scEnabled,
	}
}

func (e *guardianHostEngine) now() time.Time {
	if e != nil && e.nowFn != nil {
		return e.nowFn()
	}
	return time.Now()
}

func (e *guardianHostEngine) effectiveLeaseTTL() time.Duration {
	if e != nil && e.leaseTTL > 0 {
		return e.leaseTTL
	}
	return guardianDefaultLeaseTTL
}

func (e *guardianHostEngine) effectiveTickInterval() time.Duration {
	if e != nil && e.tickInterval > 0 {
		return e.tickInterval
	}
	return guardianDefaultTickInterval
}

func (e *guardianHostEngine) effectiveProcNetDir() string {
	if e != nil && e.procNetDir != "" {
		return e.procNetDir
	}
	return "/proc/net"
}

func (e *guardianHostEngine) effectivePackagesListPath() string {
	if e != nil && e.packagesListPath != "" {
		return e.packagesListPath
	}
	return "/data/system/packages.list"
}

func (e *guardianHostEngine) openBPFSampler() (guardianBPFSampler, error) {
	if e != nil && e.bpfSamplerFactory != nil {
		return e.bpfSamplerFactory()
	}
	ds, err := bytestats.NewNetdDetailSampler()
	if err != nil {
		return nil, err
	}
	return &guardianRealBPFSampler{inner: ds}, nil
}

// ─── 零 app_process 应用元数据解析 (/data/system/packages.list + appmeta) ───

type guardianAppMeta struct {
	Package  string
	AppName  string
	IsSystem bool
}

var guardianWellKnownSystemUIDs = map[int]struct {
	pkg  string
	name string
}{
	0:    {"root", "Root / 内核系统"},
	1000: {"android", "Android 系统"},
	1001: {"com.android.phone", "电话与蜂窝服务"},
	1010: {"wifi", "系统 Wi-Fi 服务"},
	1013: {"media", "多媒体服务"},
	1014: {"dhcp", "DHCP 网络服务"},
	1019: {"drm", "DRM 数字版权服务"},
	1021: {"gps", "GNSS 定位服务"},
	1027: {"nfc", "NFC 服务"},
	1036: {"logd", "系统日志服务"},
	1041: {"audioserver", "音频服务"},
	1046: {"mediacodec", "媒体编解码服务"},
	1051: {"netd", "系统网络守护 (netd)"},
	1052: {"dnsmasq", "热点 DNS/DHCP (dnsmasq)"},
	1066: {"statsd", "系统统计守护 (statsd)"},
	1068: {"incidentd", "系统诊断服务"},
	1073: {"com.android.networkstack", "系统网络栈"},
	1082: {"artd", "ART 运行时服务"},
	2000: {"com.android.shell", "ADB Shell"},
	9999: {"nobody", "Nobody"},
}

func guardianIsCoreSystemAppID(uid int) bool {
	if uid < 0 {
		return true
	}
	return (uid % 100000) < 10000
}

func guardianIsSystemAppID(uid int) bool {
	if uid < 0 {
		return true
	}
	appID := uid % 100000
	return appID < 10000 || appID >= 90000
}

var guardianBuiltinVPNConduitPkgs = map[string]bool{
	"com.follow.clash":                     true,
	"com.github.kr328.clash":               true,
	"com.github.metacubex.clash.meta":      true,
	"com.v2ray.ang":                        true,
	"com.v2ray.actinium":                   true,
	"io.nekohasekai.sfa":                   true,
	"io.nekohasekai.sagernet":              true,
	"moe.nb4a":                             true,
	"moe.matsuri.lite":                     true,
	"com.github.shadowsocks":               true,
	"io.github.trojan_gfw.igniter":         true,
	"com.getsurfboard":                     true,
	"com.hiddify.hiddify":                  true,
	"app.hiddify.com":                      true,
	"com.wireguard.android":                true,
	"net.openvpn.openvpn":                  true,
	"de.blinkt.openvpn":                    true,
	"org.torproject.android":               true,
	"com.tailscale.ipn":                    true,
	"net.mullvad.mullvadvpn":               true,
	"org.outline.android.client":           true,
	"ch.protonvpn.android":                 true,
	"com.nordvpn.android":                  true,
	"com.expressvpn.vpn":                   true,
	"com.windscribe.vpn":                   true,
	"com.surfshark.vpnclient.android":      true,
	"com.cloudflare.onedotonedotonedotone": true,
	"eu.faircode.netguard":                 true,
	"com.celzero.bravedns":                 true,
	"com.adguard.android":                  true,
}

func guardianParsePackagesListBytes(data []byte) (map[int]string, map[string]int, map[int]bool) {
	uidToPkg := make(map[int]string, 512)
	pkgToUID := make(map[string]int, 512)
	sysUIDs := make(map[int]bool, 256)
	sc := bufio.NewScanner(bytes.NewReader(data))
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
		if err != nil || pkg == "" {
			continue
		}
		if prev, exists := uidToPkg[uid]; !exists || len(pkg) < len(prev) {
			uidToPkg[uid] = pkg
		}
		if prevU, exists := pkgToUID[pkg]; !exists || uid < prevU {
			pkgToUID[pkg] = uid
		}
		isSys := guardianIsSystemAppID(uid)
		if !isSys && len(fields) >= 5 {
			seinfo := strings.ToLower(fields[4])
			if strings.Contains(seinfo, "platform") || strings.Contains(seinfo, "privapp") {
				isSys = true
			}
		}
		if !isSys && len(fields) >= 4 {
			dataPath := fields[3]
			for _, sysPfx := range []string{"/system/", "/system_ext/", "/product/", "/vendor/", "/odm/", "/oem/", "/apex/", "/data/user_de/"} {
				if strings.HasPrefix(dataPath, sysPfx) {
					isSys = true
					break
				}
			}
		}
		if isSys {
			sysUIDs[uid] = true
		}
	}
	return uidToPkg, pkgToUID, sysUIDs
}

func (e *guardianHostEngine) refreshPkgCatalogIfNeeded() {
	nowMono := monoNowNs()
	e.pkgMu.RLock()
	fresh := e.pkgLoadedMonoNs > 0 && nowMono-e.pkgLoadedMonoNs < int64(15*time.Second)
	e.pkgMu.RUnlock()
	if fresh {
		return
	}

	pPath := e.effectivePackagesListPath()
	var stMtime, stSize int64
	if st, err := os.Stat(pPath); err == nil {
		stMtime = st.ModTime().UnixNano()
		stSize = st.Size()
	}

	var liveLabelsPath string
	var liveMtime int64
	var userExclude map[string]bool
	if e.srv != nil && e.srv.hncDir != "" {
		for _, sub := range []string{"data", "run"} {
			cand := filepath.Join(e.srv.hncDir, sub, "app_labels_live.json")
			if st, err := os.Stat(cand); err == nil && !st.IsDir() {
				liveLabelsPath = cand
				liveMtime = st.ModTime().UnixNano()
				break
			}
		}
		if exList := loadFlywheelExcludeUser(e.srv.hncDir); len(exList) > 0 {
			userExclude = make(map[string]bool, len(exList))
			for _, p := range exList {
				p = strings.TrimSpace(p)
				if p != "" {
					userExclude[p] = true
				}
			}
		}
	}

	e.pkgMu.Lock()
	defer e.pkgMu.Unlock()
	if e.pkgLoadedMonoNs > 0 && nowMono-e.pkgLoadedMonoNs < int64(15*time.Second) {
		return
	}
	e.pkgLoadedMonoNs = nowMono
	e.vpnExcludeUser = userExclude

	if stSize > 0 && stSize <= 16<<20 && (stMtime != e.pkgListMtimeUnix || stSize != e.pkgListSize || len(e.uidToPkg) == 0) {
		if raw, err := os.ReadFile(pPath); err == nil {
			uMap, pMap, sMap := guardianParsePackagesListBytes(raw)
			if len(uMap) > 0 {
				e.uidToPkg = uMap
				e.pkgToUID = pMap
				e.sysUIDs = sMap
				e.pkgListMtimeUnix = stMtime
				e.pkgListSize = stSize
			}
		}
	}

	if liveLabelsPath != "" && (liveLabelsPath != e.liveLabelPath || liveMtime != e.liveLabelMtime) {
		if raw, err := os.ReadFile(liveLabelsPath); err == nil && len(raw) <= 4<<20 {
			var parsed map[string]string
			if json.Unmarshal(raw, &parsed) == nil && len(parsed) > 0 {
				e.liveLabelCache = parsed
				e.liveLabelMtime = liveMtime
				e.liveLabelPath = liveLabelsPath
			}
		}
	}
}

func (e *guardianHostEngine) isVPNConduitUID(uid int) bool {
	if uid < 0 {
		return false
	}
	if uid%100000 == 1016 {
		return true
	}
	e.refreshPkgCatalogIfNeeded()

	userProfile := uid / 100000
	baseUID := uid % 100000
	e.pkgMu.RLock()
	pkg := e.uidToPkg[uid]
	if pkg == "" && userProfile > 0 {
		pkg = e.uidToPkg[baseUID]
	}
	if pkg == "" && baseUID >= 20000 && baseUID <= 29999 {
		hostBase := baseUID - 10000
		if userProfile > 0 {
			pkg = e.uidToPkg[userProfile*100000+hostBase]
		}
		if pkg == "" {
			pkg = e.uidToPkg[hostBase]
		}
	}
	userEx := e.vpnExcludeUser
	e.pkgMu.RUnlock()

	if pkg == "" {
		return false
	}
	if guardianBuiltinVPNConduitPkgs[pkg] {
		return true
	}
	return userEx != nil && userEx[pkg]
}

func (e *guardianHostEngine) isHostVPNActive() bool {
	if e == nil {
		return false
	}
	if e.vpnActiveFn != nil {
		return e.vpnActiveFn()
	}
	if e.srv != nil && e.srv.hncDir != "" {
		detPath := filepath.Join(e.srv.hncDir, "run", "iface_detect.json")
		if raw, err := os.ReadFile(detPath); err == nil && len(raw) > 0 {
			var det struct {
				VPNActive     bool   `json:"vpn_active"`
				LocalUpstream string `json:"local_upstream"`
			}
			if json.Unmarshal(raw, &det) == nil {
				return det.VPNActive || isVPNIface(strings.TrimSpace(det.LocalUpstream))
			}
		}
	}
	// 单测注入模拟 packages.list 时不扫描宿主机真实网卡，保持测试可重复性
	if e.packagesListPath != "" {
		return false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp != 0 && isVPNIface(ifc.Name) {
			return true
		}
	}
	return false
}

func (e *guardianHostEngine) resolveAppMeta(uid int) guardianAppMeta {
	e.refreshPkgCatalogIfNeeded()

	userProfile := 0
	baseUID := uid
	if uid >= 100000 {
		userProfile = uid / 100000
		baseUID = uid % 100000
	}

	if wk, ok := guardianWellKnownSystemUIDs[baseUID]; ok {
		name := wk.name
		if userProfile > 0 {
			name = fmt.Sprintf("%s (用户%d)", name, userProfile)
		}
		return guardianAppMeta{
			Package:  wk.pkg,
			AppName:  name,
			IsSystem: true,
		}
	}

	if baseUID >= 90000 {
		name := fmt.Sprintf("隔离沙盒进程 (UID %d)", uid)
		if userProfile == 999 {
			name += " (应用分身)"
		} else if userProfile > 0 {
			name = fmt.Sprintf("%s (用户%d)", name, userProfile)
		}
		return guardianAppMeta{
			Package:  fmt.Sprintf("isolated:%d", baseUID),
			AppName:  name,
			IsSystem: true,
		}
	}

	e.pkgMu.RLock()
	pkg := e.uidToPkg[uid]
	isSys := e.sysUIDs[uid]
	if pkg == "" && userProfile > 0 {
		pkg = e.uidToPkg[baseUID]
		if e.sysUIDs[baseUID] {
			isSys = true
		}
	}
	// Android 13+ SDK 沙盒 (appId 20000..29999) 减 10000 反查同用户或主用户宿主应用包名
	if pkg == "" && baseUID >= 20000 && baseUID <= 29999 {
		hostBaseUID := baseUID - 10000
		if userProfile > 0 {
			hostUserUID := userProfile*100000 + hostBaseUID
			pkg = e.uidToPkg[hostUserUID]
			if e.sysUIDs[hostUserUID] {
				isSys = true
			}
		}
		if pkg == "" {
			pkg = e.uidToPkg[hostBaseUID]
			if e.sysUIDs[hostBaseUID] {
				isSys = true
			}
		}
	}
	var liveName string
	if pkg != "" && e.liveLabelCache != nil {
		liveName = e.liveLabelCache[pkg]
	}
	resolver := e.labelResolver
	e.pkgMu.RUnlock()

	if guardianIsSystemAppID(uid) {
		isSys = true
	}

	var appName string
	if liveName != "" {
		appName = liveName
	} else if pkg != "" && resolver != nil {
		appName = resolver.Display(pkg)
	}
	if appName == "" {
		if pkg != "" {
			appName = pkg
		} else if isSys {
			appName = fmt.Sprintf("系统服务 (UID %d)", uid)
		} else {
			appName = fmt.Sprintf("UID %d", uid)
		}
	}
	if userProfile > 0 && !strings.Contains(appName, "分身") && !strings.Contains(appName, "用户") {
		if userProfile == 999 {
			appName += " (应用分身)"
		} else {
			appName = fmt.Sprintf("%s (用户%d)", appName, userProfile)
		}
	}
	if pkg == "" {
		pkg = fmt.Sprintf("uid:%d", uid)
	}
	return guardianAppMeta{
		Package:  pkg,
		AppName:  appName,
		IsSystem: isSys,
	}
}

// ─── /proc/net/{tcp,tcp6,udp,udp6} 零抓包本机活跃套接字扫描器 ──────────

type guardianSocketEntry struct {
	Proto      string
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	StateHex   string
	UID        int
	TxQueue    uint64
}

func (sk *guardianSocketEntry) ctKey() string {
	return sk.Proto + "|" + sk.LocalIP + "|" + strconv.Itoa(sk.LocalPort) + "|" + sk.RemoteIP + "|" + strconv.Itoa(sk.RemotePort)
}

func guardianParseProcHexAddrPort(token string, ipv6 bool) (netip.Addr, int, bool) {
	hostHex, portHex, ok := strings.Cut(token, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	portVal, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	if !ipv6 {
		if len(hostHex) != 8 {
			return netip.Addr{}, 0, false
		}
		v, err := strconv.ParseUint(hostHex, 16, 32)
		if err != nil {
			return netip.Addr{}, 0, false
		}
		var b4 [4]byte
		binary.NativeEndian.PutUint32(b4[:], uint32(v))
		return netip.AddrFrom4(b4), int(portVal), true
	}
	if len(hostHex) != 32 {
		return netip.Addr{}, 0, false
	}
	var b16 [16]byte
	for i := 0; i < 4; i++ {
		w, err := strconv.ParseUint(hostHex[i*8:(i+1)*8], 16, 32)
		if err != nil {
			return netip.Addr{}, 0, false
		}
		binary.NativeEndian.PutUint32(b16[i*4:(i+1)*4], uint32(w))
	}
	// Unmap ::ffff:a.b.c.d dual-stack sockets so IPv4 DNS/SNI/CIDR tables hit cleanly.
	return netip.AddrFrom16(b16).Unmap(), int(portVal), true
}

func guardianIsTCPOrphanCloseState(stHex string) bool {
	switch strings.ToUpper(stHex) {
	case "04", "05", "06", "07", "09", "0B", "0C":
		return true
	}
	return false
}

func guardianIsActiveSocketState(proto, stHex string) bool {
	stHex = strings.ToUpper(stHex)
	if proto == "tcp" {
		// Exclude 0A (LISTEN), 06 (TIME_WAIT — kernel zeroes sk_uid to 0!),
		// 03 (SYN_RECV), 07 (CLOSE), 0B (CLOSING), and 0C (NEW_SYN_RECV).
		switch stHex {
		case "01", "02", "04", "05", "08", "09":
			return true
		}
		return false
	}
	// UDP: 01 (ESTABLISHED/connected) or 07 (unconnected with non-zero remote peer).
	return stHex != "0A"
}

func guardianScanProcSocketsDir(procDir string) ([]guardianSocketEntry, bool) {
	specs := []struct {
		file  string
		proto string
		ipv6  bool
	}{
		{"tcp", "tcp", false},
		{"tcp6", "tcp", true},
		{"udp", "udp", false},
		{"udp6", "udp", true},
	}

	out := make([]guardianSocketEntry, 0, 128)
	anyReadable := false
	var fieldsBuf [16]string

	for _, sp := range specs {
		f, err := os.Open(filepath.Join(procDir, sp.file))
		if err != nil {
			continue
		}
		anyReadable = true
		sc := bufio.NewScanner(f)
		buf := make([]byte, 32*1024)
		sc.Buffer(buf, 256*1024)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			if lineNo == 1 {
				continue // header line
			}
			if lineNo > 8192 {
				break
			}
			fields := splitASCIIFieldsInto(fieldsBuf[:0], sc.Text())
			if len(fields) < 8 {
				continue
			}
			stHex := strings.ToUpper(fields[3])
			if !guardianIsActiveSocketState(sp.proto, stHex) {
				continue
			}
			remAddr, remPort, ok := guardianParseProcHexAddrPort(fields[2], sp.ipv6)
			if !ok || remPort <= 0 || !remAddr.IsValid() || remAddr.IsUnspecified() {
				continue
			}
			locAddr, locPort, ok := guardianParseProcHexAddrPort(fields[1], sp.ipv6)
			if !ok {
				continue
			}
			uid, err := strconv.Atoi(fields[7])
			if err != nil || uid < 0 {
				continue
			}
			if sp.proto == "tcp" && guardianIsTCPOrphanCloseState(stHex) {
				if uid == 0 {
					continue
				}
				if len(fields) >= 10 {
					if inode, iErr := strconv.ParseUint(fields[9], 10, 64); iErr == nil && inode == 0 {
						continue
					}
				}
			}
			var txQ uint64
			if txHex, _, ok := strings.Cut(fields[4], ":"); ok {
				txQ, _ = strconv.ParseUint(txHex, 16, 64)
			}
			out = append(out, guardianSocketEntry{
				Proto:      sp.proto,
				LocalIP:    locAddr.String(),
				LocalPort:  locPort,
				RemoteIP:   remAddr.String(),
				RemotePort: remPort,
				StateHex:   strings.ToUpper(stHex),
				UID:        uid,
				TxQueue:    txQ,
			})
		}
		_ = f.Close()
	}
	return out, anyReadable
}

// ─── DPI 追踪器 / 广告 SDK 域名分类器 ────────────────────────────────

type guardianTrackerRule struct {
	ID       string
	SDKName  string
	Category string
	Suffix   string
}

var guardianBuiltinTrackerRules = []guardianTrackerRule{
	{ID: "adjust", SDKName: "Adjust 归因统计 SDK", Category: "ads", Suffix: "adjust.com"},
	{ID: "adjust", SDKName: "Adjust 归因统计 SDK", Category: "ads", Suffix: "adjust.net"},
	{ID: "appsflyer", SDKName: "AppsFlyer 统计 SDK", Category: "ads", Suffix: "appsflyer.com"},
	{ID: "appsflyer", SDKName: "AppsFlyer 统计 SDK", Category: "ads", Suffix: "appsflyersdk.com"},
	{ID: "doubleclick", SDKName: "Google DoubleClick 广告", Category: "ads", Suffix: "doubleclick.net"},
	{ID: "googlesyndication", SDKName: "Google AdSense/AdMob", Category: "ads", Suffix: "googlesyndication.com"},
	{ID: "app_measurement", SDKName: "Firebase Analytics 统计", Category: "ads", Suffix: "app-measurement.com"},
	{ID: "crashlytics", SDKName: "Firebase Crashlytics 遥测", Category: "third_party_telemetry", Suffix: "crashlytics.com"},
	{ID: "sensorsdata", SDKName: "神策数据埋点 SDK", Category: "ads", Suffix: "sensorsdata.cn"},
	{ID: "sensorsdata", SDKName: "神策数据埋点 SDK", Category: "ads", Suffix: "sensorsdata.com"},
	{ID: "umeng", SDKName: "友盟统计/推送 SDK", Category: "third_party_telemetry", Suffix: "umeng.com"},
	{ID: "umeng", SDKName: "友盟统计/推送 SDK", Category: "third_party_telemetry", Suffix: "umengcloud.com"},
	{ID: "pangolin", SDKName: "穿山甲广告 SDK", Category: "ads", Suffix: "pangolin-sdk-toutiao.com"},
	{ID: "pangolin", SDKName: "穿山甲广告 SDK", Category: "ads", Suffix: "pglstatp-toutiao.com"},
	{ID: "gdt_qq", SDKName: "腾讯优量汇广告 SDK", Category: "ads", Suffix: "gdt.qq.com"},
	{ID: "e_qq", SDKName: "腾讯广点通广告 SDK", Category: "ads", Suffix: "e.qq.com"},
	{ID: "bugly", SDKName: "腾讯 Bugly 崩溃遥测 SDK", Category: "third_party_telemetry", Suffix: "bugly.qq.com"},
	{ID: "sentry", SDKName: "Sentry 错误监控 SDK", Category: "third_party_telemetry", Suffix: "sentry.io"},
	{ID: "segment", SDKName: "Segment 行为分析 SDK", Category: "third_party_telemetry", Suffix: "segment.io"},
	{ID: "datadog", SDKName: "Datadog RUM 监控 SDK", Category: "third_party_telemetry", Suffix: "datadoghq.com"},
	{ID: "talkingdata", SDKName: "TalkingData 统计 SDK", Category: "third_party_telemetry", Suffix: "talkingdata.com"},
	{ID: "growingio", SDKName: "GrowingIO 增长统计 SDK", Category: "third_party_telemetry", Suffix: "growingio.com"},
	{ID: "jiguang", SDKName: "极光统计/推送 SDK", Category: "third_party_telemetry", Suffix: "jiguang.cn"},
	{ID: "getui", SDKName: "个推 SDK", Category: "third_party_telemetry", Suffix: "getui.com"},
	{ID: "mob_sdk", SDKName: "MobTech SDK", Category: "third_party_telemetry", Suffix: "mob.com"},
	{ID: "branch_io", SDKName: "Branch 深度链接归因 SDK", Category: "ads", Suffix: "branch.io"},
}

func guardianIsTrackerCategory(cat string) bool {
	switch strings.ToLower(strings.TrimSpace(cat)) {
	case "ads", "ad", "advertising", "tracker", "analytics", "third_party_telemetry", "telemetry":
		return true
	}
	return false
}

func (e *guardianHostEngine) ensureTrackerRulesLoaded() {
	nowMono := monoNowNs()
	e.ruleMu.RLock()
	fresh := e.ruleLoadedMono > 0 && nowMono-e.ruleLoadedMono < int64(60*time.Second)
	e.ruleMu.RUnlock()
	if fresh {
		return
	}

	exact := make(map[string]guardianTrackerRule, 64)
	suffixes := make([]guardianTrackerRule, 0, 128)
	seenSuffix := make(map[string]bool, 128)

	addSuffix := func(r guardianTrackerRule) {
		sfx := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(r.Suffix)), ".")
		if sfx == "" || seenSuffix[sfx] {
			return
		}
		seenSuffix[sfx] = true
		r.Suffix = sfx
		exact[sfx] = r
		suffixes = append(suffixes, r)
	}

	if e.srv != nil && e.srv.hncDir != "" {
		for _, rf := range dpiRuleFiles(e.srv.hncDir) {
			raw, err := os.ReadFile(rf)
			if err != nil || len(raw) == 0 || len(raw) > 2<<20 {
				continue
			}
			var doc struct {
				Rules []struct {
					ID       string   `json:"id"`
					App      string   `json:"app"`
					Category string   `json:"category"`
					Domains  []string `json:"domains"`
					Suffixes []string `json:"suffixes"`
				} `json:"rules"`
			}
			if json.Unmarshal(raw, &doc) != nil {
				continue
			}
			for _, rl := range doc.Rules {
				if !guardianIsTrackerCategory(rl.Category) {
					continue
				}
				label := rl.App
				if label == "" {
					label = rl.ID
				}
				for _, d := range rl.Domains {
					d = strings.ToLower(strings.TrimSpace(d))
					if d != "" {
						exact[d] = guardianTrackerRule{ID: rl.ID, SDKName: label, Category: rl.Category, Suffix: d}
					}
				}
				for _, sfx := range rl.Suffixes {
					addSuffix(guardianTrackerRule{ID: rl.ID, SDKName: label, Category: rl.Category, Suffix: sfx})
				}
			}
		}
	}

	for _, br := range guardianBuiltinTrackerRules {
		addSuffix(br)
	}

	e.ruleMu.Lock()
	e.trackerExact = exact
	e.trackerSuffixes = suffixes
	e.ruleLoadedMono = nowMono
	e.ruleMu.Unlock()
}

func (e *guardianHostEngine) matchTrackerDomain(domain string) (guardianTrackerRule, bool) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return guardianTrackerRule{}, false
	}
	e.ensureTrackerRulesLoaded()

	e.ruleMu.RLock()
	defer e.ruleMu.RUnlock()

	if r, ok := e.trackerExact[domain]; ok {
		return r, true
	}
	// Walk parent labels from specific to apex for O(labels) exact suffix lookup.
	for idx := strings.IndexByte(domain, '.'); idx >= 0 && idx+1 < len(domain); {
		sub := domain[idx+1:]
		if r, ok := e.trackerExact[sub]; ok {
			return r, true
		}
		next := strings.IndexByte(sub, '.')
		if next < 0 {
			break
		}
		idx += 1 + next
	}
	return guardianTrackerRule{}, false
}

// 系统网络连通性探测域名白名单(仅豁免 uid < 10000 的系统连通性自检 HTTP 80 探针)
var guardianCaptivePortalAllowDomains = []string{
	"connectivitycheck.gstatic.com",
	"clients3.google.com",
	"clients4.google.com",
	"www.google.cn",
	"g.cn",
	"captive.apple.com",
	"connect.rom.miui.com",
	"wifi.vivo.com.cn",
	"conn1.oppomobile.com",
	"conn2.oppomobile.com",
	"connectivitycheck.platform.hicloud.com",
	"msftconnecttest.com",
	"nmcheck.gnome.org",
}

var (
	guardianFakeIPPrefixV4 = netip.MustParsePrefix("198.18.0.0/15")
	guardianFakeIPPrefixV6 = netip.MustParsePrefix("fc00::/18")
)

// isBenchmarkOrFakeIP 判定地址是否属于代理/TUN 常用 Fake-IP 虚拟地址池 (198.18.0.0/15 或 fc00::/18)。
func isBenchmarkOrFakeIP(ipStr string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return guardianFakeIPPrefixV4.Contains(addr)
	}
	return guardianFakeIPPrefixV6.Contains(addr)
}

func guardianIsSystemCaptivePortalProbe(uid int, domain string) bool {
	if !guardianIsCoreSystemAppID(uid) {
		return false
	}
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "" {
		return false
	}
	for _, allow := range guardianCaptivePortalAllowDomains {
		if d == allow || strings.HasSuffix(d, "."+allow) {
			return true
		}
	}
	return false
}

func guardianIsPublicRoutableIP(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	if isBenchmarkOrFakeIP(ipStr) {
		return false
	}
	// Carrier-grade NAT 100.64.0.0/10 is upstream WAN on cellular networks, keep routable;
	// benchmarking/Fake-IP ranges (198.18.0.0/15, fc00::/18) are excluded above.
	return true
}

func guardianIsNonLoopbackExternalIP(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return !addr.IsLoopback() && !addr.IsUnspecified() && !addr.IsLinkLocalUnicast() && !addr.IsMulticast()
}

// ─── 引擎一: 8 秒短租约零空转 eBPF 采样 + 前后台真实耗流排行 ─────────

func (e *guardianHostEngine) stopTrafficLeaseNow() {
	e.trafficMu.Lock()
	stopCh := e.stopLeaseCh
	doneCh := e.leaseDoneCh
	e.stopLeaseCh = nil
	e.trafficMu.Unlock()

	if stopCh != nil {
		close(stopCh)
	}
	if doneCh != nil {
		<-doneCh
	}
}

func (e *guardianHostEngine) touchAndSampleTrafficLease() (*bytestats.NetdDetailSnapshot, map[int]guardianUIDRate, bool, error) {
	leaseTTL := e.effectiveLeaseTTL()

	e.trafficMu.Lock()
	defer e.trafficMu.Unlock()

	nowMono := monoNowNs()
	newDeadline := nowMono + int64(leaseTTL)
	if prev := e.leaseUntilMonoNs.Load(); newDeadline > prev {
		e.leaseUntilMonoNs.Store(newDeadline)
	}

	if e.bpfSampler != nil && e.leaseRunning.Load() {
		ratesCopy := make(map[int]guardianUIDRate, len(e.liveRates))
		for k, v := range e.liveRates {
			ratesCopy[k] = v
		}
		return e.latestBPFSnap, ratesCopy, e.rateWarmingUp.Load(), nil
	}

	// 首次进入(或上次 8s 租约已到期关闭): 打开只读 BPF 采样器采集第 0 帧基线
	sampler, err := e.openBPFSampler()
	if err != nil {
		e.lastBPFErr = err
		return nil, nil, false, err
	}
	snap0, err := sampler.SampleDetail()
	if err != nil {
		_ = sampler.Close()
		e.lastBPFErr = err
		return nil, nil, false, err
	}

	sampleMono := monoNowNs()
	if postDeadline := sampleMono + int64(leaseTTL); postDeadline > e.leaseUntilMonoNs.Load() {
		e.leaseUntilMonoNs.Store(postDeadline)
	}
	e.bpfSampler = sampler
	e.latestBPFSnap = snap0
	e.prevBPFSnap = snap0
	e.prevBPFMonoNs = sampleMono
	e.liveRates = make(map[int]guardianUIDRate)
	e.lastBPFErr = nil
	e.rateWarmingUp.Store(true)
	e.leaseRunning.Store(true)
	e.totalRxBpsSnap.Store(0)
	e.totalTxBpsSnap.Store(0)
	e.trackedAppsSnap.Store(int32(len(snap0.ByUID)))
	e.leaseStarts.Add(1)

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	e.stopLeaseCh = stopCh
	e.leaseDoneCh = doneCh

	tickDur := e.effectiveTickInterval()
	go e.runTrafficLeaseLoop(stopCh, doneCh, sampler, tickDur)

	return snap0, map[int]guardianUIDRate{}, true, nil
}

func (e *guardianHostEngine) runTrafficLeaseLoop(stopCh <-chan struct{}, doneCh chan<- struct{}, mySampler guardianBPFSampler, tickDur time.Duration) {
	defer close(doneCh)
	tk := time.NewTicker(tickDur)
	defer tk.Stop()

	shutdown := func(forced bool) bool {
		e.trafficMu.Lock()
		defer e.trafficMu.Unlock()
		if !forced && monoNowNs() <= e.leaseUntilMonoNs.Load() && e.bpfSampler == mySampler && mySampler != nil {
			// 持 trafficMu 二次复核发现租约刚被续期，绝不关闭采样器!
			return false
		}
		if e.bpfSampler != mySampler {
			if mySampler != nil {
				_ = mySampler.Close()
			}
			return true
		}
		if e.bpfSampler != nil {
			_ = e.bpfSampler.Close()
			e.bpfSampler = nil
		}
		e.liveRates = make(map[int]guardianUIDRate)
		e.stopLeaseCh = nil
		e.leaseRunning.Store(false)
		e.rateWarmingUp.Store(false)
		e.totalRxBpsSnap.Store(0)
		e.totalTxBpsSnap.Store(0)
		e.leaseStops.Add(1)
		return true
	}

	for {
		select {
		case <-stopCh:
			shutdown(true)
			return
		case <-tk.C:
			if monoNowNs() > e.leaseUntilMonoNs.Load() {
				if shutdown(false) {
					return
				}
			}

			e.trafficMu.Lock()
			sampler := e.bpfSampler
			prevSnap := e.prevBPFSnap
			prevMono := e.prevBPFMonoNs
			e.trafficMu.Unlock()

			if sampler == nil || sampler != mySampler {
				shutdown(true)
				return
			}

			curSnap, err := sampler.SampleDetail()
			sampleMono := monoNowNs()
			if err != nil {
				e.trafficMu.Lock()
				if e.bpfSampler == mySampler {
					e.lastBPFErr = err
				}
				e.trafficMu.Unlock()
				continue
			}

			dtSec := float64(sampleMono-prevMono) / float64(time.Second)
			newRates := make(map[int]guardianUIDRate, len(curSnap.ByUID))
			var sumRxBps, sumTxBps int64
			if prevSnap != nil && dtSec >= 0.005 {
				vpnActive := e.isHostVPNActive()
				for uid, curDet := range curSnap.ByUID {
					prevDet, ok := prevSnap.ByUID[uid]
					if !ok {
						continue
					}
					var rxBps, txBps int64
					if curDet.Total.RxBytes >= prevDet.Total.RxBytes {
						rxBps = int64(float64(curDet.Total.RxBytes-prevDet.Total.RxBytes) / dtSec)
					}
					if curDet.Total.TxBytes >= prevDet.Total.TxBytes {
						txBps = int64(float64(curDet.Total.TxBytes-prevDet.Total.TxBytes) / dtSec)
					}
					if rxBps > 0 || txBps > 0 {
						newRates[uid] = guardianUIDRate{rxBps: rxBps, txBps: txBps}
						if !(vpnActive && e.isVPNConduitUID(uid)) {
							sumRxBps += rxBps
							sumTxBps += txBps
						}
					}
				}
			}

			e.trafficMu.Lock()
			if e.bpfSampler == mySampler && e.bpfSampler != nil {
				e.latestBPFSnap = curSnap
				e.prevBPFSnap = curSnap
				e.prevBPFMonoNs = sampleMono
				e.liveRates = newRates
				e.rateWarmingUp.Store(false)
				e.totalRxBpsSnap.Store(sumRxBps)
				e.totalTxBpsSnap.Store(sumTxBps)
				e.trackedAppsSnap.Store(int32(len(curSnap.ByUID)))
			}
			e.trafficMu.Unlock()
		}
	}
}

func (e *guardianHostEngine) execDumpsysStream(parentCtx context.Context, timeout time.Duration, parseFn func(r io.Reader) error, args ...string) error {
	var hub *CoreHub
	if e.srv != nil {
		hub = e.srv.CoreHub()
	}
	runTask := func(ctx context.Context) error {
		cmd := hardenCmd(exec.CommandContext(ctx, "dumpsys", args...))
		cmd.Env = hubSanitizedAndroidEnv()
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		var stderrBuf bytes.Buffer
		cmd.Stderr = &stderrBuf
		if err := cmd.Start(); err != nil {
			return err
		}
		limited := io.LimitReader(stdout, guardianMaxStreamBytes)
		parseErr := parseFn(limited)
		// Drain residual output lightly so child does not block on pipe close before Wait.
		_, _ = io.Copy(io.Discard, io.LimitReader(stdout, 1<<20))
		waitErr := cmd.Wait()
		if parseErr != nil {
			return parseErr
		}
		if waitErr != nil {
			errMsg := strings.TrimSpace(stderrBuf.String())
			if errMsg != "" {
				return fmt.Errorf("%w: %s", waitErr, errMsg)
			}
			return waitErr
		}
		return nil
	}

	if hub != nil && hub.AndroidBridgeBulkhead != nil {
		return hub.AndroidBridgeBulkhead.Execute(parentCtx, timeout, runTask)
	}
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	return runTask(ctx)
}

func (e *guardianHostEngine) fetchNetstatsDumpCached(parentCtx context.Context, full bool, curBPF *bytestats.NetdDetailSnapshot, forceOnRotate bool) (*guardianNetstatsCacheEntry, error) {
	ttl := guardianNetstatsBootTTL
	sfKey := "boot"
	if full {
		ttl = guardianNetstatsFullTTL
		sfKey = "full"
	}

	nowMono := monoNowNs()
	e.netstatsMu.Lock()
	var cached *guardianNetstatsCacheEntry
	if full {
		cached = e.fullCache
	} else {
		cached = e.bootCache
	}
	if cached != nil && nowMono-cached.fetchedMonoNs < int64(ttl) {
		rotated := false
		if forceOnRotate && curBPF != nil && curBPF.HasStatsAB {
			if curBPF.StatsABTotalBytes+1024 < cached.lastABTotal {
				rotated = true
			} else if curBPF.StatsABTotalBytes > cached.lastABTotal {
				cached.lastABTotal = curBPF.StatsABTotalBytes
			}
		}
		if !rotated {
			e.netstatsMu.Unlock()
			return cached, nil
		}
	}
	e.netstatsMu.Unlock()

	val, err := e.netstatsSF.DoCtx(parentCtx, sfKey, guardianNetstatsCmdTimeout, func(sfCtx context.Context) (any, error) {
		var dump *nsDump
		keepUIDOnly := func(section string, uid int) bool {
			return section == "uid" && uid >= 0 && uid <= 100_000_000
		}
		if e.netstatsStreamFn != nil {
			rc, err := e.netstatsStreamFn(sfCtx, full)
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			d, perr := parseNetstatsDump(io.LimitReader(rc, guardianMaxStreamBytes), keepUIDOnly)
			if perr != nil {
				return nil, perr
			}
			dump = d
		} else {
			args := []string{"netstats", "--uid"}
			if full {
				args = []string{"netstats", "--uid", "--full"}
			}
			err := e.execDumpsysStream(sfCtx, guardianNetstatsCmdTimeout, func(r io.Reader) error {
				var headPeek bytes.Buffer
				tr := io.TeeReader(io.LimitReader(r, 512), &headPeek)
				rest := io.MultiReader(tr, r)
				d, perr := parseNetstatsDump(rest, keepUIDOnly)
				if perr != nil {
					return perr
				}
				if !d.Sections["uid"] {
					headStr := headPeek.String()
					if strings.Contains(headStr, "Permission Denial") || strings.Contains(headStr, "SecurityException") {
						return errors.New("permission_denied: dumpsys netstats denied")
					}
				}
				dump = d
				return nil
			}, args...)
			if err != nil {
				return nil, err
			}
		}
		if dump == nil || !dump.Sections["uid"] {
			return nil, errors.New("netstats_uid_section_missing")
		}

		var initABTotal uint64
		e.trafficMu.Lock()
		if e.latestBPFSnap != nil && e.latestBPFSnap.HasStatsAB {
			initABTotal = e.latestBPFSnap.StatsABTotalBytes
		}
		e.trafficMu.Unlock()
		if initABTotal == 0 && curBPF != nil && curBPF.HasStatsAB {
			initABTotal = curBPF.StatsABTotalBytes
		}

		entry := &guardianNetstatsCacheEntry{
			fetchedMonoNs: monoNowNs(),
			dump:          dump,
			lastABTotal:   initABTotal,
		}
		e.netstatsMu.Lock()
		if full {
			e.fullCache = entry
		} else {
			e.bootCache = entry
		}
		e.netstatsMu.Unlock()
		return entry, nil
	})
	if err != nil {
		return nil, err
	}
	return val.(*guardianNetstatsCacheEntry), nil
}

func guardianSelectBPFCountsByNet(det bytestats.NetdUIDDetail, netFilter string) (bg, fg bytestats.ByteCounts) {
	switch netFilter {
	case "mobile":
		return det.BgMobile, det.FgMobile
	case "wifi":
		return det.BgWiFi, det.FgWiFi
	default:
		return det.BgAll, det.FgAll
	}
}

func guardianIsVPNIdent(id nsIdent) bool {
	return id.Type == "VPN" || strings.HasPrefix(id.Type, "TYPE_VPN")
}

func guardianHasVPNIdent(k *nsKey) bool {
	if k == nil {
		return false
	}
	for _, id := range k.Idents {
		if guardianIsVPNIdent(id) {
			return true
		}
	}
	return false
}

func guardianMatchNetType(id nsIdent, netFilter string) bool {
	if guardianIsVPNIdent(id) {
		return false
	}
	switch netFilter {
	case "mobile":
		return id.Type == "MOBILE"
	case "wifi":
		return id.Type == "WIFI"
	default:
		return true
	}
}

func guardianAggregateNetstatsSplits(
	entry *guardianNetstatsCacheEntry,
	curBPF *bytestats.NetdDetailSnapshot,
	period string,
	netFilter string,
	now time.Time,
) map[int]guardianUIDSplitBytes {
	out := make(map[int]guardianUIDSplitBytes, 128)
	if entry == nil || entry.dump == nil {
		return out
	}
	nowUnix := now.Unix()
	var winFrom int64
	useWindow := false
	switch period {
	case "today":
		y, m, d := now.Date()
		winFrom = time.Date(y, m, d, 0, 0, 0, 0, now.Location()).Unix()
		useWindow = true
	case "7d":
		winFrom = nowUnix - 7*86400
		useWindow = true
	case "30d":
		winFrom = nowUnix - 30*86400
		useWindow = true
	}

	for _, k := range entry.dump.Keys {
		if k.Section != "uid" || k.UID < 0 || !nsCountable(k) || guardianHasVPNIdent(k) {
			continue
		}
		if !guardianMatchNetType(k.Primary(), netFilter) {
			continue
		}
		setUpper := strings.ToUpper(k.Set)
		isFg := setUpper == "FOREGROUND" || setUpper == "1"
		isBg := setUpper == "DEFAULT" || setUpper == "0"
		if !isFg && !isBg {
			continue
		}

		var rx, tx uint64
		if !useWindow {
			// period=boot: 优先累加 History since boot (!k.Full); 若仅有 Complete history 则按开机窗口切
			if k.Full && entry.dump.FullSec["uid"] {
				bootFrom := nowUnix - coreUptimeSeconds()
				if bootFrom < 0 {
					bootFrom = 0
				}
				wrx, wtx := nsWindowBytes(k, bootFrom, nowUnix+1, nowUnix)
				rx = uint64(math.Round(wrx))
				tx = uint64(math.Round(wtx))
			} else if !k.Full {
				for _, b := range k.Buckets {
					rx += b.Rx
					tx += b.Tx
				}
			}
		} else {
			wrx, wtx := nsWindowBytes(k, winFrom, nowUnix+1, nowUnix)
			rx = uint64(math.Round(wrx))
			tx = uint64(math.Round(wtx))
		}

		if rx == 0 && tx == 0 {
			continue
		}
		cur := out[k.UID]
		if isFg {
			cur.fgRx += rx
			cur.fgTx += tx
		} else {
			cur.bgRx += rx
			cur.bgTx += tx
		}
		out[k.UID] = cur
	}

	// 叠加 BPF stats_map_A + stats_map_B 中尚未被 NetworkStatsService poll 归档的实时字节
	if curBPF != nil && curBPF.HasStatsAB {
		for uid, curDet := range curBPF.ByUID {
			curBg, curFg := guardianSelectBPFCountsByNet(curDet, netFilter)
			if curBg.RxBytes == 0 && curBg.TxBytes == 0 && curFg.RxBytes == 0 && curFg.TxBytes == 0 {
				continue
			}
			sp := out[uid]
			sp.bgRx += curBg.RxBytes
			sp.bgTx += curBg.TxBytes
			sp.fgRx += curFg.RxBytes
			sp.fgTx += curFg.TxBytes
			out[uid] = sp
		}
	}

	return out
}

// LocalAppTrafficRow 表示单个本机应用的实时网速、前后台累计字节与连接态势。
type LocalAppTrafficRow struct {
	UID            int      `json:"uid"`
	Package        string   `json:"package"`
	AppName        string   `json:"app_name"`
	IsSystem       bool     `json:"is_system"`
	CurrentState   string   `json:"current_state"`
	RxBps          int64    `json:"rx_bps"`
	TxBps          int64    `json:"tx_bps"`
	TotalBps       int64    `json:"total_bps"`
	BgRxBytes      uint64   `json:"bg_rx_bytes"`
	BgTxBytes      uint64   `json:"bg_tx_bytes"`
	BgTotalBytes   uint64   `json:"bg_total_bytes"`
	FgRxBytes      uint64   `json:"fg_rx_bytes"`
	FgTxBytes      uint64   `json:"fg_tx_bytes"`
	FgTotalBytes   uint64   `json:"fg_total_bytes"`
	TotalBytes     uint64   `json:"total_bytes"`
	BgRatioPct     float64  `json:"bg_ratio_pct"`
	ActiveConns    int      `json:"active_conns"`
	TopDomains     []string `json:"top_domains"`
	CleartextFlags []string `json:"cleartext_flags"`
}

func guardianRound1(v float64) float64 {
	return math.Round(v*10) / 10
}

type guardianUIDConnEnrich struct {
	activeConns int
	domains     []string
	flags       []string
}

func (e *guardianHostEngine) collectUIDConnEnrichment() map[int]*guardianUIDConnEnrich {
	sockets, ok := guardianScanProcSocketsDir(e.effectiveProcNetDir())
	if !ok || len(sockets) == 0 {
		return nil
	}
	var names map[string]ipName
	var apps map[string]ipApp
	if e.srv != nil {
		names = e.srv.loadIPNames()
		apps = e.srv.loadIPApps()
	}

	byUID := make(map[int]*guardianUIDConnEnrich, 64)
	domainSeen := make(map[int]map[string]bool, 64)
	flagSeen := make(map[int]map[string]bool, 32)

	addFlag := func(uid int, fl string) {
		m := flagSeen[uid]
		if m == nil {
			m = make(map[string]bool, 2)
			flagSeen[uid] = m
		}
		if !m[fl] {
			m[fl] = true
			en := byUID[uid]
			en.flags = append(en.flags, fl)
		}
	}

	addDomain := func(uid int, dom string) {
		dom = strings.TrimSpace(dom)
		if dom == "" {
			return
		}
		en := byUID[uid]
		if len(en.domains) >= 3 {
			return
		}
		m := domainSeen[uid]
		if m == nil {
			m = make(map[string]bool, 4)
			domainSeen[uid] = m
		}
		if !m[dom] {
			m[dom] = true
			en.domains = append(en.domains, dom)
		}
	}

	for _, sk := range sockets {
		if !guardianIsNonLoopbackExternalIP(sk.RemoteIP) {
			continue
		}
		en := byUID[sk.UID]
		if en == nil {
			en = &guardianUIDConnEnrich{}
			byUID[sk.UID] = en
		}
		en.activeConns++

		var dom string
		if n, exists := names[sk.RemoteIP]; exists && n.Name != "" {
			dom = n.Name
		} else if a, exists := apps[sk.RemoteIP]; exists && a.Name != "" {
			dom = a.Name
		} else if org, exists := ipOwnerLookup(sk.RemoteIP); exists && org.Name != "" {
			dom = org.Name
		}
		if dom != "" {
			addDomain(sk.UID, dom)
		}

		if sk.Proto == "tcp" && (sk.RemotePort == 80 || sk.RemotePort == 8080 || sk.RemotePort == 8000) &&
			guardianIsPublicRoutableIP(sk.RemoteIP) && !guardianIsSystemCaptivePortalProbe(sk.UID, dom) {
			addFlag(sk.UID, "http_cleartext")
		}
		if sk.RemotePort == 53 && !guardianIsSystemAppID(sk.UID) && !isBenchmarkOrFakeIP(sk.RemoteIP) {
			addFlag(sk.UID, "dns_direct")
		}
	}
	return byUID
}

func guardianClassifyReasonCode(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "permission") || strings.Contains(msg, "eacces") || strings.Contains(msg, "eperm") ||
		errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM):
		return "permission_denied"
	case strings.Contains(msg, "circuit breaker"):
		return "bulkhead_circuit_open"
	case strings.Contains(msg, "timed out") || strings.Contains(msg, "deadline exceeded"):
		return "command_timeout"
	case strings.Contains(msg, "not found") || strings.Contains(msg, "no such file") || errors.Is(err, os.ErrNotExist):
		return "kernel_map_missing"
	default:
		return fallback
	}
}

func (s *server) apiLocalAppsTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	e := s.guardianEngine()
	e.trafficHits.Add(1)
	now := e.now()

	q := r.URL.Query()
	period := strings.ToLower(strings.TrimSpace(q.Get("period")))
	switch period {
	case "", "boot":
		period = "boot"
	case "today", "7d", "30d":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid period: want boot|today|7d|30d",
		})
		return
	}

	netFilter := strings.ToLower(strings.TrimSpace(q.Get("net")))
	switch netFilter {
	case "", "all":
		netFilter = "all"
	case "mobile", "wifi":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid net: want all|mobile|wifi",
		})
		return
	}

	sortBy := strings.ToLower(strings.TrimSpace(q.Get("sort")))
	switch sortBy {
	case "", "rate":
		sortBy = "rate"
	case "bg_bytes", "total_bytes":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid sort: want rate|bg_bytes|total_bytes",
		})
		return
	}

	includeSystem := q.Get("include_system") == "1" || strings.EqualFold(q.Get("include_system"), "true")
	limit := 100
	if rawLim := q.Get("limit"); rawLim != "" {
		if n, err := strconv.Atoi(rawLim); err == nil && n > 0 {
			if n > 500 {
				n = 500
			}
			limit = n
		}
	}

	// 1. 续租 8s 短租约并读取当前 eBPF 实时帧与差分网速
	bpfSnap, liveRates, warmingUp, bpfErr := e.touchAndSampleTrafficLease()

	// 2. 拉取周期前后台累计字节(boot 走 15s 缓存 + stats_map_A/B 增量; today/7d/30d 走 60s --full 切片)
	needFull := period != "boot"
	nsEntry, nsErr := e.fetchNetstatsDumpCached(r.Context(), needFull, bpfSnap, period == "boot")

	// 无权限 / 双源皆不可读时诚实返回 available=false, 绝不伪造数据
	if bpfSnap == nil && nsEntry == nil {
		reasonErr := bpfErr
		if reasonErr == nil {
			reasonErr = nsErr
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":             true,
			"available":      false,
			"reason_code":    guardianClassifyReasonCode(reasonErr, "ebpf_and_netstats_unavailable"),
			"reason":         fmt.Sprintf("bpf=%v; netstats=%v", bpfErr, nsErr),
			"generated_at":   now.Unix(),
			"period":         period,
			"net":            netFilter,
			"sort":           sortBy,
			"include_system": includeSystem,
			"apps":           []LocalAppTrafficRow{},
		})
		return
	}

	// 非 boot 周期(today/7d/30d)若 netstats --full 不可用, 绝不拿开机总流量冒充历史窗口
	if needFull && nsEntry == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":              true,
			"available":       false,
			"reason_code":     guardianClassifyReasonCode(nsErr, "netstats_full_unavailable"),
			"reason":          nsErr.Error(),
			"generated_at":    now.Unix(),
			"period":          period,
			"net":             netFilter,
			"sort":            sortBy,
			"include_system":  includeSystem,
			"rate_warming_up": warmingUp,
			"apps":            []LocalAppTrafficRow{},
		})
		return
	}

	var splitByUID map[int]guardianUIDSplitBytes
	bgSplitAvail := false
	historySource := "none"

	if nsEntry != nil {
		splitByUID = guardianAggregateNetstatsSplits(nsEntry, bpfSnap, period, netFilter, now)
		bgSplitAvail = true
		if needFull {
			historySource = "netstats_full"
		} else if bpfSnap != nil && bpfSnap.HasStatsAB {
			historySource = "netstats_ebpf_hybrid"
		} else {
			historySource = "netstats_boot"
		}
		// boot 口径下维护单调高水位, 确保 stats_map_A/B 翻转瞬间绝不发生数值倒退
		if period == "boot" {
			e.trafficMu.Lock()
			hw := e.bootHighWater[netFilter]
			if hw == nil {
				hw = make(map[int]guardianUIDSplitBytes, len(splitByUID))
				e.bootHighWater[netFilter] = hw
			}
			for uid, sp := range splitByUID {
				prev := hw[uid]
				if sp.bgRx < prev.bgRx {
					sp.bgRx = prev.bgRx
				}
				if sp.bgTx < prev.bgTx {
					sp.bgTx = prev.bgTx
				}
				if sp.fgRx < prev.fgRx {
					sp.fgRx = prev.fgRx
				}
				if sp.fgTx < prev.fgTx {
					sp.fgTx = prev.fgTx
				}
				hw[uid] = sp
				splitByUID[uid] = sp
			}
			e.trafficMu.Unlock()
		}
	} else if bpfSnap != nil && period == "boot" {
		// netstats 不可用但 BPF 可读时的诚实降级:
		// 若 stats_map_A/B 存在可提供未归档前后台计数; 若仅有 app_uid_stats_map 且 net=all 则只填真实总字节并标明 bg_split_available=false
		splitByUID = make(map[int]guardianUIDSplitBytes, len(bpfSnap.ByUID))
		if bpfSnap.HasStatsAB {
			historySource = "ebpf_unarchived_only"
			bgSplitAvail = true
			for uid, det := range bpfSnap.ByUID {
				bg, fg := guardianSelectBPFCountsByNet(det, netFilter)
				splitByUID[uid] = guardianUIDSplitBytes{
					bgRx: bg.RxBytes,
					bgTx: bg.TxBytes,
					fgRx: fg.RxBytes,
					fgTx: fg.TxBytes,
				}
			}
		} else if netFilter == "all" {
			historySource = "ebpf_boot_total_only"
			bgSplitAvail = false
		} else {
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":             true,
				"available":      false,
				"reason_code":    guardianClassifyReasonCode(nsErr, "netstats_unavailable_for_iface_filter"),
				"reason":         fmt.Sprintf("net=%s requires netstats or stats_map_A/B: %v", netFilter, nsErr),
				"generated_at":   now.Unix(),
				"period":         period,
				"net":            netFilter,
				"sort":           sortBy,
				"include_system": includeSystem,
				"apps":           []LocalAppTrafficRow{},
			})
			return
		}
	}

	connEnrich := e.collectUIDConnEnrichment()

	// 收集候选 UID 集合
	uidSet := make(map[int]struct{}, 256)
	for uid := range splitByUID {
		uidSet[uid] = struct{}{}
	}
	if bpfSnap != nil {
		for uid, det := range bpfSnap.ByUID {
			if det.Total.RxBytes > 0 || det.Total.TxBytes > 0 {
				if period == "boot" && netFilter == "all" {
					uidSet[uid] = struct{}{}
				} else if r, ok := liveRates[uid]; ok && (r.rxBps > 0 || r.txBps > 0) {
					uidSet[uid] = struct{}{}
				}
			}
		}
	}
	for uid, ce := range connEnrich {
		if ce.activeConns > 0 {
			uidSet[uid] = struct{}{}
		}
	}

	rows := make([]LocalAppTrafficRow, 0, len(uidSet))
	var sumRxBps, sumTxBps int64
	var sumTotalBytes, sumBgBytes, sumFgBytes uint64
	activeConnApps := 0
	vpnActive := e.isHostVPNActive()

	for uid := range uidSet {
		if uid < 0 || uid > 100_000_000 {
			continue
		}
		meta := e.resolveAppMeta(uid)
		if !includeSystem && meta.IsSystem {
			continue
		}

		rate := liveRates[uid]
		sp := splitByUID[uid]
		bgTotal := sp.bgRx + sp.bgTx
		fgTotal := sp.fgRx + sp.fgTx
		totBytes := bgTotal + fgTotal

		isConduit := e.isVPNConduitUID(uid)

		// period=boot & net=all 时, map_netd_app_uid_stats_map 是自开机单调递增总真值:
		// 若 bgSplitAvail 为 false, 直接采用真实 BPF 总字节且不伪造前后台拆分(汇总累加时剔除 isVPNConduitUID 防双计)。
		if period == "boot" && netFilter == "all" && bpfSnap != nil {
			if det, ok := bpfSnap.ByUID[uid]; ok {
				bpfTot := det.Total.RxBytes + det.Total.TxBytes
				if !bgSplitAvail {
					totBytes = bpfTot
				} else if bpfTot > totBytes && !bpfSnap.HasStatsAB && !vpnActive && !isConduit {
					// 当内核无 stats_map_A/B 导致未归档差额未知时, 总量对齐单调 BPF 真值
					totBytes = bpfTot
				}
			}
		}

		ce := connEnrich[uid]
		activeConns := 0
		domains := []string{}
		flags := []string{}
		if ce != nil {
			activeConns = ce.activeConns
			if len(ce.domains) > 0 {
				domains = ce.domains
			}
			if len(ce.flags) > 0 {
				flags = ce.flags
			}
		}

		if totBytes == 0 && rate.rxBps == 0 && rate.txBps == 0 && activeConns == 0 {
			continue
		}

		curState := "unknown"
		if bpfSnap != nil {
			if bpfSnap.HasCounterSetMap {
				if bpfSnap.ForegroundUIDs[uid] {
					curState = "foreground"
				} else {
					curState = "background"
				}
			}
		}

		var bgPct float64
		if bgSplitAvail && totBytes > 0 {
			bgPct = guardianRound1(float64(bgTotal) * 100 / float64(totBytes))
			if bgPct > 100 {
				bgPct = 100
			}
		}

		row := LocalAppTrafficRow{
			UID:            uid,
			Package:        meta.Package,
			AppName:        meta.AppName,
			IsSystem:       meta.IsSystem,
			CurrentState:   curState,
			RxBps:          rate.rxBps,
			TxBps:          rate.txBps,
			TotalBps:       rate.rxBps + rate.txBps,
			BgRxBytes:      sp.bgRx,
			BgTxBytes:      sp.bgTx,
			BgTotalBytes:   bgTotal,
			FgRxBytes:      sp.fgRx,
			FgTxBytes:      sp.fgTx,
			FgTotalBytes:   fgTotal,
			TotalBytes:     totBytes,
			BgRatioPct:     bgPct,
			ActiveConns:    activeConns,
			TopDomains:     domains,
			CleartextFlags: flags,
		}
		rows = append(rows, row)

		if !(vpnActive && isConduit) {
			sumRxBps += row.RxBps
			sumTxBps += row.TxBps
		}
		if !((vpnActive || !bgSplitAvail) && isConduit) {
			sumTotalBytes += row.TotalBytes
			sumBgBytes += row.BgTotalBytes
			sumFgBytes += row.FgTotalBytes
		}
		if row.ActiveConns > 0 {
			activeConnApps++
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch sortBy {
		case "bg_bytes":
			if a.BgTotalBytes != b.BgTotalBytes {
				return a.BgTotalBytes > b.BgTotalBytes
			}
			if a.TotalBytes != b.TotalBytes {
				return a.TotalBytes > b.TotalBytes
			}
		case "total_bytes":
			if a.TotalBytes != b.TotalBytes {
				return a.TotalBytes > b.TotalBytes
			}
			if a.TotalBps != b.TotalBps {
				return a.TotalBps > b.TotalBps
			}
		default: // "rate"
			if a.TotalBps != b.TotalBps {
				return a.TotalBps > b.TotalBps
			}
			if a.TotalBytes != b.TotalBytes {
				return a.TotalBytes > b.TotalBytes
			}
		}
		return a.UID < b.UID
	})

	totalAppsMatched := len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}

	rateSource := "unavailable"
	if bpfSnap != nil {
		rateSource = "ebpf_uid_map"
	}
	var overallBgPct float64
	if bgSplitAvail && sumTotalBytes > 0 {
		overallBgPct = guardianRound1(float64(sumBgBytes) * 100 / float64(sumTotalBytes))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"available":          true,
		"generated_at":       now.Unix(),
		"period":             period,
		"net":                netFilter,
		"sort":               sortBy,
		"include_system":     includeSystem,
		"rate_source":        rateSource,
		"history_source":     historySource,
		"rate_warming_up":    warmingUp,
		"bg_split_available": bgSplitAvail,
		"lease_ttl_ms":       e.effectiveLeaseTTL().Milliseconds(),
		"summary": map[string]any{
			"total_rx_bps":     sumRxBps,
			"total_tx_bps":     sumTxBps,
			"total_bps":        sumRxBps + sumTxBps,
			"total_bytes":      sumTotalBytes,
			"bg_total_bytes":   sumBgBytes,
			"fg_total_bytes":   sumFgBytes,
			"bg_ratio_pct":     overallBgPct,
			"app_count":        totalAppsMatched,
			"active_conn_apps": activeConnApps,
		},
		"apps": rows,
	})
}

// ─── 引擎二: 本机后台耗电与硬件唤醒排行 (batterystats --charged 流式解析) ───

type LocalAppWakelockItem struct {
	Name       string `json:"name"`
	DurationMs int64  `json:"duration_ms"`
	Count      int    `json:"count"`
}

type LocalAppAlarmItem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type LocalAppDevicePowerSummary struct {
	BatteryCapacityMah    float64 `json:"battery_capacity_mah"`
	ComputedDrainMah      float64 `json:"computed_drain_mah"`
	ActualDischargeMah    float64 `json:"actual_discharge_mah"`
	ScreenOffDischargeMah float64 `json:"screen_off_discharge_mah"`
	TimeOnBatteryMs       int64   `json:"time_on_battery_ms"`
	ScreenOffOnBatteryMs  int64   `json:"screen_off_on_battery_ms"`
}

type LocalAppPowerRow struct {
	UID                    int                    `json:"uid"`
	Package                string                 `json:"package"`
	AppName                string                 `json:"app_name"`
	IsSystem               bool                   `json:"is_system"`
	TotalMah               float64                `json:"total_mah"`
	FgMah                  float64                `json:"fg_mah"`
	BgMah                  float64                `json:"bg_mah"`
	FgsMah                 float64                `json:"fgs_mah"`
	CachedMah              float64                `json:"cached_mah"`
	ScreenOffMah           float64                `json:"screen_off_mah"`
	BgMahAvailable         bool                   `json:"bg_mah_available"`
	BgMahReason            string                 `json:"bg_mah_reason,omitempty"`
	BgComponentsMah        map[string]float64     `json:"bg_components_mah,omitempty"`
	WakelockPartialMs      int64                  `json:"wakelock_partial_ms"`
	WakelockBgMs           int64                  `json:"wakelock_bg_ms"`
	WakelockCount          int                    `json:"wakelock_count"`
	TopWakelocks           []LocalAppWakelockItem `json:"top_wakelocks"`
	MobileRadioActiveMs    int64                  `json:"mobile_radio_active_ms"`
	MobileRadioWakeupCount int                    `json:"mobile_radio_wakeup_count"`
	WifiRunningMs          int64                  `json:"wifi_running_ms"`
	WifiBgScanCount        int                    `json:"wifi_bg_scan_count"`
	CPUTotalMs             int64                  `json:"cpu_total_ms"`
	CPUFgMs                int64                  `json:"cpu_fg_ms"`
	CPUBgMs                int64                  `json:"cpu_bg_ms"`
	WakeupAlarmsCount      int                    `json:"wakeup_alarms_count"`
	TopWakeupAlarms        []LocalAppAlarmItem    `json:"top_wakeup_alarms"`
	BgJobsMs               int64                  `json:"bg_jobs_ms"`
	BgJobsCount            int                    `json:"bg_jobs_count"`
}

type guardianUIDPowerAccum struct {
	uid             int
	hasPowerRow     bool
	hasMultiStateBg bool
	hasLegacySipper bool
	totalMah        float64
	fgMah           float64
	bgMah           float64
	fgsMah          float64
	cachedMah       float64
	screenOffMah    float64
	hasScreenOffMah bool
	bgComponents    map[string]float64

	sumWakelockMs   int64
	totalWakeLineMs int64
	wakelockBgMs    int64
	wakelockCount   int
	topWakelocks    []LocalAppWakelockItem

	radioActiveMs int64
	radioWakeups  int
	wifiRunningMs int64
	wifiBgScans   int

	uidCPUTotalMs  int64
	uidCPUFgMs     int64
	hasUIDCPUFg    bool
	procCPUTotalMs int64
	procCPUFgMs    int64
	hasProcCPUFg   bool

	apkWakeupsSum int
	alarmItemsSum int
	topAlarms     []LocalAppAlarmItem

	bgJobsMs    int64
	bgJobsCount int

	pendingAlarmName string
	pendingJobName   string
	procHostPkg      string
}

type guardianParsedBatteryStats struct {
	Summary               LocalAppDevicePowerSummary
	ByUID                 map[int]*guardianUIDPowerAccum
	AnyMultiStatePower    bool
	AnyLegacySipperPower  bool
	AnyScreenOffUIDPower  bool
	SawSinceChargeSection bool
	SawEstimatedPowerSec  bool
}

var guardianBatteryScanBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

// guardianParseBatteryUID parses Android batterystats UID tokens:
// "0" -> 0, "1000" -> 1000, "u0a245" -> 10245, "u10a245" -> 1010245, "u0s1000" -> 1000,
// "u0sdk20245" / "u0sdk245" / "u0a245s" -> 10245 (SDK sandbox mapped -10000 to host app),
// "u0i12" -> 99012, "u0ai5" -> 90005 (isolated processes).
func guardianParseBatteryUID(tok string) (int, bool) {
	tok = strings.TrimSpace(strings.TrimSuffix(tok, ":"))
	if tok == "" {
		return 0, false
	}
	if tok[0] >= '0' && tok[0] <= '9' {
		for i := 1; i < len(tok); i++ {
			if tok[i] < '0' || tok[i] > '9' {
				return 0, false
			}
		}
		v, err := strconv.Atoi(tok)
		if err != nil || v < 0 || v > 100_000_000 {
			return 0, false
		}
		if appID := v % 100000; appID >= 20000 && appID <= 29999 {
			return v - 10000, true
		}
		return v, true
	}
	if tok[0] != 'u' {
		return 0, false
	}
	i := 1
	for i < len(tok) && tok[i] >= '0' && tok[i] <= '9' {
		i++
	}
	if i == 1 || i >= len(tok) {
		return 0, false
	}
	userID, err := strconv.Atoi(tok[1:i])
	if err != nil || userID < 0 || userID > 9999 {
		return 0, false
	}
	tail := tok[i:]
	kindTag := ""
	rest := ""
	switch {
	case strings.HasPrefix(tail, "sdk"):
		kindTag = "sdk"
		rest = tail[3:]
	case strings.HasPrefix(tail, "ai"):
		kindTag = "ai"
		rest = tail[2:]
	case len(tail) >= 2 && tail[0] == 'a' && tail[len(tail)-1] == 's':
		kindTag = "as"
		rest = tail[1 : len(tail)-1]
	default:
		kindTag = tail[:1]
		rest = tail[1:]
	}
	if rest == "" {
		return 0, false
	}
	for j := 0; j < len(rest); j++ {
		if rest[j] < '0' || rest[j] > '9' {
			return 0, false
		}
	}
	idNum, err := strconv.Atoi(rest)
	if err != nil || idNum < 0 || idNum >= 100000 {
		return 0, false
	}
	switch kindTag {
	case "a", "as":
		if idNum >= 10000 {
			return 0, false
		}
		return userID*100000 + 10000 + idNum, true
	case "sdk":
		switch {
		case idNum >= 20000 && idNum <= 29999:
			return userID*100000 + (idNum - 10000), true
		case idNum >= 10000 && idNum < 20000:
			return userID*100000 + idNum, true
		case idNum < 10000:
			return userID*100000 + 10000 + idNum, true
		default:
			return 0, false
		}
	case "s":
		return userID*100000 + idNum, true
	case "ai":
		if idNum >= 90000 && idNum < 99000 {
			return userID*100000 + idNum, true
		}
		if idNum < 9000 {
			return userID*100000 + 90000 + idNum, true
		}
		return 0, false
	case "i":
		if idNum >= 90000 && idNum < 100000 {
			return userID*100000 + idNum, true
		}
		if idNum < 10000 {
			return userID*100000 + 99000 + idNum, true
		}
		return 0, false
	default:
		return 0, false
	}
}

// guardianParseBatteryDurationMs parses AOSP formatTimeMs strings such as
// "2d 5h 14m 32s 410ms", "12m 3s 0ms", or "450ms" into milliseconds.
func guardianParseBatteryDurationMs(s string) int64 {
	var totalMs int64
	n := len(s)
	i := 0
	for i < n {
		// Stop before parenthesized ratios/counts like "(98.5%)" or "(12 times)"
		if s[i] == '(' || s[i] == ';' || s[i] == ',' {
			break
		}
		if s[i] < '0' || s[i] > '9' {
			i++
			continue
		}
		numStart := i
		for i < n && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.') {
			i++
		}
		numStr := s[numStart:i]
		unitStart := i
		for i < n && ((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z')) {
			i++
		}
		unit := strings.ToLower(s[unitStart:i])
		if unit == "" {
			continue
		}
		val, err := strconv.ParseFloat(numStr, 64)
		if err != nil {
			continue
		}
		switch unit {
		case "d":
			totalMs += int64(math.Round(val * 86400 * 1000))
		case "h":
			totalMs += int64(math.Round(val * 3600 * 1000))
		case "m":
			totalMs += int64(math.Round(val * 60 * 1000))
		case "s":
			totalMs += int64(math.Round(val * 1000))
		case "ms":
			totalMs += int64(math.Round(val))
		}
	}
	return totalMs
}

func guardianParseLeadingFloat(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	i := 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	start := i
	for i < len(s) && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.') {
		i++
	}
	if i == start {
		return 0, false
	}
	v, err := strconv.ParseFloat(s[:i], 64)
	return v, err == nil
}

// guardianParseDrainRange parses "1380-1450" -> midpoint 1415, or single float "1420" -> 1420.
func guardianParseDrainValue(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if a, b, ok := strings.Cut(s, "-"); ok {
		va, okA := guardianParseLeadingFloat(a)
		vb, okB := guardianParseLeadingFloat(b)
		if okA && okB && vb >= va {
			return guardianRound2((va + vb) / 2), true
		}
	}
	v, ok := guardianParseLeadingFloat(s)
	return guardianRound2(v), ok
}

func guardianRound2(v float64) float64 {
	return math.Round(v*100) / 100
}

func guardianPushTopWakelock(list []LocalAppWakelockItem, item LocalAppWakelockItem) []LocalAppWakelockItem {
	if item.Name == "" || item.DurationMs <= 0 {
		return list
	}
	for i := range list {
		if list[i].Name == item.Name {
			list[i].DurationMs += item.DurationMs
			list[i].Count += item.Count
			sort.Slice(list, func(a, b int) bool { return list[a].DurationMs > list[b].DurationMs })
			return list
		}
	}
	list = append(list, item)
	sort.Slice(list, func(a, b int) bool {
		if list[a].DurationMs != list[b].DurationMs {
			return list[a].DurationMs > list[b].DurationMs
		}
		return list[a].Count > list[b].Count
	})
	if len(list) > 3 {
		list = list[:3]
	}
	return list
}

func guardianPushTopAlarm(list []LocalAppAlarmItem, item LocalAppAlarmItem) []LocalAppAlarmItem {
	if item.Name == "" || item.Count <= 0 {
		return list
	}
	for i := range list {
		if list[i].Name == item.Name {
			list[i].Count += item.Count
			sort.Slice(list, func(a, b int) bool { return list[a].Count > list[b].Count })
			return list
		}
	}
	list = append(list, item)
	sort.Slice(list, func(a, b int) bool {
		if list[a].Count != list[b].Count {
			return list[a].Count > list[b].Count
		}
		return list[a].Name < list[b].Name
	})
	if len(list) > 3 {
		list = list[:3]
	}
	return list
}

func guardianExtractParensCount(s string) int {
	// Matches "(45 times)" or "38x"
	if idx := strings.Index(s, " times)"); idx > 0 {
		open := strings.LastIndexByte(s[:idx], '(')
		if open >= 0 {
			if n, err := strconv.Atoi(strings.TrimSpace(s[open+1 : idx])); err == nil && n >= 0 {
				return n
			}
		}
	}
	fields := strings.Fields(s)
	for _, f := range fields {
		f = strings.Trim(f, "(),;")
		if strings.HasSuffix(f, "x") && len(f) > 1 {
			if n, err := strconv.Atoi(f[:len(f)-1]); err == nil && n >= 0 {
				return n
			}
		}
	}
	return 0
}

func guardianParsePowerCapacityLine(trimmed string, sum *LocalAppDevicePowerSummary, screenOffTable bool) {
	// Format: "Capacity: 5000, Computed drain: 1395.4, actual drain: 1380-1450"
	parts := strings.Split(trimmed, ",")
	for _, p := range parts {
		k, v, ok := strings.Cut(strings.TrimSpace(p), ":")
		if !ok {
			continue
		}
		kl := strings.ToLower(strings.TrimSpace(k))
		switch kl {
		case "capacity":
			if !screenOffTable {
				if f, ok := guardianParseLeadingFloat(v); ok && f > 0 {
					sum.BatteryCapacityMah = guardianRound2(f)
				}
			}
		case "computed drain":
			if f, ok := guardianParseLeadingFloat(v); ok && f >= 0 {
				if screenOffTable {
					if sum.ScreenOffDischargeMah <= 0 {
						sum.ScreenOffDischargeMah = guardianRound2(f)
					}
				} else {
					sum.ComputedDrainMah = guardianRound2(f)
				}
			}
		case "actual drain":
			if f, ok := guardianParseDrainValue(v); ok && f >= 0 {
				if screenOffTable {
					sum.ScreenOffDischargeMah = f
				} else {
					sum.ActualDischargeMah = f
				}
			}
		}
	}
}

func guardianParsePowerUIDLine(trimmed string, screenOffTable bool, parsed *guardianParsedBatteryStats) {
	// Android 14~16 multi-state format:
	//   UID u0a245: 128.4 fg: 42.1 bg: 68.3 fgs: 15.2 cached: 2.8 ( cpu=85.0 cpu:fg=30.0 cpu:bg=45.0 wakelock:bg=11.8 ... )
	// Android 9~13 legacy BatterySipper format:
	//   Uid u0a245: 45.6 ( cpu=30.2 wake=5.4 radio=8.0 wifi=2.0 )
	isUpperUID := strings.HasPrefix(trimmed, "UID ")
	isLegacyUid := !isUpperUID && strings.HasPrefix(trimmed, "Uid ")
	if !isUpperUID && !isLegacyUid {
		return
	}

	rest := strings.TrimSpace(trimmed[4:])
	uidTok, afterUID, ok := strings.Cut(rest, ":")
	if !ok {
		return
	}
	uid, ok := guardianParseBatteryUID(uidTok)
	if !ok {
		return
	}

	afterUID = strings.TrimSpace(afterUID)
	totalVal, ok := guardianParseLeadingFloat(afterUID)
	if !ok {
		return
	}

	acc := parsed.ByUID[uid]
	if acc == nil {
		acc = &guardianUIDPowerAccum{uid: uid}
		parsed.ByUID[uid] = acc
	}
	acc.hasPowerRow = true

	if screenOffTable {
		acc.screenOffMah = guardianRound2(acc.screenOffMah + totalVal)
		acc.hasScreenOffMah = true
		parsed.AnyScreenOffUIDPower = true
		return
	}

	acc.totalMah = guardianRound2(acc.totalMah + totalVal)

	headPart := afterUID
	var parenPart string
	if pIdx := strings.IndexByte(afterUID, '('); pIdx >= 0 {
		headPart = afterUID[:pIdx]
		if endIdx := strings.LastIndexByte(afterUID, ')'); endIdx > pIdx {
			parenPart = afterUID[pIdx+1 : endIdx]
		} else {
			parenPart = afterUID[pIdx+1:]
		}
	}

	// Parse multi-state header tokens: fg: <v> bg: <v> fgs: <v> cached: <v>
	headFields := strings.Fields(headPart)
	sawStateSplit := false
	for i := 1; i+1 < len(headFields); i++ {
		tok := headFields[i]
		if !strings.HasSuffix(tok, ":") {
			continue
		}
		val, ok := guardianParseLeadingFloat(headFields[i+1])
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSuffix(tok, ":")) {
		case "fg":
			acc.fgMah = guardianRound2(acc.fgMah + val)
			sawStateSplit = true
		case "bg":
			acc.bgMah = guardianRound2(acc.bgMah + val)
			sawStateSplit = true
		case "fgs":
			acc.fgsMah = guardianRound2(acc.fgsMah + val)
			sawStateSplit = true
		case "cached":
			acc.cachedMah = guardianRound2(acc.cachedMah + val)
			sawStateSplit = true
		}
		i++
	}

	// Parse component breakdown inside parentheses: cpu:bg=45.0 wakelock:bg=11.8 mobile_radio:bg=12.0 ...
	if parenPart != "" {
		for _, kv := range strings.Fields(parenPart) {
			k, vStr, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			comp, state, hasColon := strings.Cut(strings.ToLower(k), ":")
			if !hasColon || state != "bg" || comp == "" {
				continue
			}
			if fv, ok := guardianParseLeadingFloat(vStr); ok && fv > 0 {
				if acc.bgComponents == nil {
					acc.bgComponents = make(map[string]float64, 4)
				}
				acc.bgComponents[comp] = guardianRound2(acc.bgComponents[comp] + fv)
				sawStateSplit = true
			}
		}
	}

	if sawStateSplit {
		acc.hasMultiStateBg = true
		parsed.AnyMultiStatePower = true
	} else {
		acc.hasLegacySipper = true
		parsed.AnyLegacySipperPower = true
	}
}

func guardianExtractProcHostPkg(trimmed string) string {
	// Matches "Proc <pkg>:<subproc>:" or "Proc <pkg>:"
	after := strings.TrimSpace(strings.TrimPrefix(trimmed, "Proc "))
	colonIdx := strings.IndexByte(after, ':')
	if colonIdx <= 0 {
		return ""
	}
	cand := strings.TrimSpace(after[:colonIdx])
	if !strings.Contains(cand, ".") || cand[0] == '.' || cand[len(cand)-1] == '.' {
		return ""
	}
	for i := 0; i < len(cand); i++ {
		c := cand[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.') {
			return ""
		}
	}
	return cand
}

func guardianParseUIDDetailLine(acc *guardianUIDPowerAccum, indent int, trimmed string) {
	// Handle 2-line pending Alarm / Job continuations first
	if acc.pendingAlarmName != "" {
		name := acc.pendingAlarmName
		acc.pendingAlarmName = ""
		if indent >= 6 {
			cnt := guardianExtractAlarmCount(trimmed)
			if cnt > 0 {
				acc.alarmItemsSum += cnt
				acc.topAlarms = guardianPushTopAlarm(acc.topAlarms, LocalAppAlarmItem{Name: name, Count: cnt})
				return
			}
		}
	}
	if acc.pendingJobName != "" {
		acc.pendingJobName = ""
		if indent >= 6 {
			dur := guardianParseBatteryDurationMs(trimmed)
			cnt := guardianExtractParensCount(trimmed)
			if dur > 0 || cnt > 0 {
				acc.bgJobsMs += dur
				acc.bgJobsCount += cnt
				return
			}
		}
	}

	switch {
	case strings.HasPrefix(trimmed, "Proc "):
		if acc.procHostPkg == "" {
			if pkg := guardianExtractProcHostPkg(trimmed); pkg != "" {
				acc.procHostPkg = pkg
			}
		}

	case strings.HasPrefix(trimmed, "Wake lock "):
		// Example:
		// Wake lock *alarm*: 3m 12s 400ms partial (45 times) max=12000 actual=192400 background: 3m 00s 100ms (42 times) realtime
		// Lock name itself may contain colons (e.g. *job*/com.foo/.Bar). Locate " partial" and split at the last ": " before it.
		pIdx := strings.Index(trimmed, " partial")
		if pIdx < 0 {
			return // ignore full/window/draw locks or "(nothing executed)"
		}
		prefix := trimmed[len("Wake lock "):pIdx]
		colonIdx := strings.LastIndex(prefix, ": ")
		if colonIdx < 0 {
			return
		}
		lockName := strings.TrimSpace(prefix[:colonIdx])
		durStr := prefix[colonIdx+2:]
		durMs := guardianParseBatteryDurationMs(durStr)
		afterPartial := trimmed[pIdx+len(" partial"):]
		cnt := guardianExtractParensCount(afterPartial)
		acc.sumWakelockMs += durMs
		acc.wakelockCount += cnt
		acc.topWakelocks = guardianPushTopWakelock(acc.topWakelocks, LocalAppWakelockItem{
			Name:       lockName,
			DurationMs: durMs,
			Count:      cnt,
		})
		if bgIdx := strings.Index(afterPartial, "background:"); bgIdx >= 0 {
			bgRest := strings.TrimSpace(afterPartial[bgIdx+len("background:"):])
			acc.wakelockBgMs += guardianParseBatteryDurationMs(bgRest)
		}

	case strings.HasPrefix(trimmed, "TOTAL wake:") || strings.HasPrefix(trimmed, "Total wake:"):
		if strings.Contains(trimmed, "partial") {
			_, after, _ := strings.Cut(trimmed, ":")
			if ms := guardianParseBatteryDurationMs(after); ms > 0 {
				acc.totalWakeLineMs += ms
			}
			if bgIdx := strings.Index(after, "background:"); bgIdx >= 0 {
				bgMs := guardianParseBatteryDurationMs(strings.TrimSpace(after[bgIdx+len("background:"):]))
				if bgMs > acc.wakelockBgMs {
					acc.wakelockBgMs = bgMs
				}
			}
		}

	case strings.Contains(trimmed, "Mobile radio active:"):
		idx := strings.Index(trimmed, "Mobile radio active:")
		after := strings.TrimSpace(trimmed[idx+len("Mobile radio active:"):])
		acc.radioActiveMs += guardianParseBatteryDurationMs(after)
		acc.radioWakeups += guardianExtractParensCount(after)

	case strings.HasPrefix(trimmed, "Wifi Running:"):
		after := strings.TrimSpace(strings.TrimPrefix(trimmed, "Wifi Running:"))
		acc.wifiRunningMs += guardianParseBatteryDurationMs(after)

	case strings.HasPrefix(trimmed, "Wifi Scan:"):
		after := strings.TrimSpace(strings.TrimPrefix(trimmed, "Wifi Scan:"))
		if bgIdx := strings.Index(after, "background:"); bgIdx >= 0 {
			bgPart := strings.TrimSpace(after[bgIdx+len("background:"):])
			acc.wifiBgScans += guardianExtractParensCount(bgPart)
		} else {
			acc.wifiBgScans += guardianExtractParensCount(after)
		}

	case strings.HasPrefix(trimmed, "Total cpu time:"):
		// "Total cpu time: u=4m 10s 200ms s=2m 05s 100ms"
		after := strings.TrimSpace(strings.TrimPrefix(trimmed, "Total cpu time:"))
		var uMs, sMs int64
		if uIdx := strings.Index(after, "u="); uIdx >= 0 {
			uPart := after[uIdx+2:]
			if sIdx := strings.Index(uPart, " s="); sIdx >= 0 {
				uMs = guardianParseBatteryDurationMs(uPart[:sIdx])
				sMs = guardianParseBatteryDurationMs(uPart[sIdx+3:])
			} else {
				uMs = guardianParseBatteryDurationMs(uPart)
			}
		}
		if uMs+sMs > 0 {
			acc.uidCPUTotalMs += uMs + sMs
		}

	case strings.HasPrefix(trimmed, "CPU:"):
		// "CPU: 2m 50s 200ms usr + 1m 35s 100ms krnl ; 1m 30s 0ms fg"
		after := strings.TrimSpace(strings.TrimPrefix(trimmed, "CPU:"))
		mainPart, fgPart, hasSemi := strings.Cut(after, ";")
		var usrMs, krnlMs int64
		if uPart, kPart, hasPlus := strings.Cut(mainPart, "+"); hasPlus {
			usrMs = guardianParseBatteryDurationMs(uPart)
			krnlMs = guardianParseBatteryDurationMs(kPart)
		} else {
			usrMs = guardianParseBatteryDurationMs(mainPart)
		}
		tot := usrMs + krnlMs
		var fgMs int64
		hasFg := false
		if hasSemi && strings.Contains(fgPart, "fg") {
			fgMs = guardianParseBatteryDurationMs(fgPart)
			hasFg = true
		}
		if indent >= 6 {
			acc.procCPUTotalMs += tot
			if hasFg {
				acc.procCPUFgMs += fgMs
				acc.hasProcCPUFg = true
			}
		} else {
			if tot > 0 {
				acc.uidCPUTotalMs += tot
			}
			if hasFg {
				acc.uidCPUFgMs += fgMs
				acc.hasUIDCPUFg = true
			}
		}

	case strings.HasPrefix(trimmed, "Wakeups:"):
		after := strings.TrimSpace(strings.TrimPrefix(trimmed, "Wakeups:"))
		if n, err := strconv.Atoi(strings.Fields(after)[0]); err == nil && n > 0 {
			acc.apkWakeupsSum += n
		}

	case strings.HasPrefix(trimmed, "Wakeup alarm ") || strings.HasPrefix(trimmed, "Alarm "):
		// Examples:
		//   Wakeup alarm *walarm*:com.tencent.mm.HEARTBEAT: 25 times
		//   Alarm *walarm*:com.tencent.mm.HEARTBEAT:
		//     25 times, ... (25 wakeups)
		isWakeupPrefix := strings.HasPrefix(trimmed, "Wakeup alarm ")
		body := trimmed
		if isWakeupPrefix {
			body = strings.TrimSpace(strings.TrimPrefix(trimmed, "Wakeup alarm "))
		} else {
			body = strings.TrimSpace(strings.TrimPrefix(trimmed, "Alarm "))
		}
		if !isWakeupPrefix && !strings.Contains(body, "*walarm*:") {
			return
		}
		bodyClean := strings.TrimPrefix(body, "*walarm*:")
		if strings.HasSuffix(bodyClean, ":") {
			acc.pendingAlarmName = strings.TrimSuffix(bodyClean, ":")
			return
		}
		if sep := strings.LastIndex(bodyClean, ": "); sep > 0 {
			name := strings.TrimSpace(bodyClean[:sep])
			cnt := guardianExtractAlarmCount(bodyClean[sep+2:])
			if cnt > 0 {
				acc.alarmItemsSum += cnt
				acc.topAlarms = guardianPushTopAlarm(acc.topAlarms, LocalAppAlarmItem{Name: name, Count: cnt})
			}
		}

	case strings.HasPrefix(trimmed, "Job "):
		// Examples:
		//   Job com.example/.SyncJob: 1m 20s 300ms (12 times)
		//   Job com.example/.SyncJob:
		//     1m 20s 300ms realtime (12 times)
		body := strings.TrimSpace(strings.TrimPrefix(trimmed, "Job "))
		if strings.HasSuffix(body, ":") {
			acc.pendingJobName = strings.TrimSuffix(body, ":")
			return
		}
		if sep := strings.LastIndex(body, ": "); sep > 0 {
			tail := body[sep+2:]
			if strings.Contains(tail, "not running") || strings.Contains(tail, "nothing executed") {
				return
			}
			dur := guardianParseBatteryDurationMs(tail)
			cnt := guardianExtractParensCount(tail)
			acc.bgJobsMs += dur
			acc.bgJobsCount += cnt
		}
	}
}

func guardianExtractAlarmCount(s string) int {
	// Matches "25 wakeups", "(25 wakeups)", or "25 times"
	fields := strings.Fields(s)
	for i := 0; i+1 < len(fields); i++ {
		numStr := strings.Trim(fields[i], "(),:")
		next := strings.Trim(fields[i+1], "(),:")
		if strings.HasPrefix(next, "wakeup") {
			if n, err := strconv.Atoi(numStr); err == nil && n >= 0 {
				return n
			}
		}
	}
	for i := 0; i+1 < len(fields); i++ {
		numStr := strings.Trim(fields[i], "(),:")
		next := strings.Trim(fields[i+1], "(),:")
		if strings.HasPrefix(next, "time") {
			if n, err := strconv.Atoi(numStr); err == nil && n >= 0 {
				return n
			}
		}
	}
	return guardianExtractParensCount(s)
}

func guardianCountLeadingSpaces(b []byte) int {
	n := 0
	for i := 0; i < len(b); i++ {
		if b[i] == ' ' {
			n++
		} else if b[i] == '\t' {
			n += 2
		} else {
			break
		}
	}
	return n
}

func guardianBytesHasPrefixTrimmed(b []byte, prefix string) bool {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	rem := b[i:]
	if len(rem) < len(prefix) {
		return false
	}
	for j := 0; j < len(prefix); j++ {
		if rem[j] != prefix[j] {
			return false
		}
	}
	return true
}

// parseBatterystatsChargedStream streams `dumpsys batterystats --charged` with O(UIDs)
// memory (< 256KB peak), fast-skipping `Battery History` / `History:` / `Per-PID Stats:` /
// `Daily stats:` blocks without allocating strings for skipped lines.
func parseBatterystatsChargedStream(r io.Reader) (*guardianParsedBatteryStats, error) {
	parsed := &guardianParsedBatteryStats{
		ByUID: make(map[int]*guardianUIDPowerAccum, 128),
	}

	bufPtr := guardianBatteryScanBufPool.Get().(*[]byte)
	defer func() {
		if cap(*bufPtr) <= 256*1024 {
			guardianBatteryScanBufPool.Put(bufPtr)
		}
	}()

	sc := bufio.NewScanner(r)
	sc.Buffer(*bufPtr, 256*1024)

	const (
		topSkip = iota
		topSinceCharge
		topStandalonePower
	)
	const (
		subNone = iota
		subPowerAll
		subPowerScreenOff
		subUIDDetail
	)

	topState := topSkip
	subState := subNone
	var curUIDAcc *guardianUIDPowerAccum
	var screenOnMs int64
	permissionDenied := false

	for sc.Scan() {
		raw := sc.Bytes()
		if len(raw) > 0 && raw[len(raw)-1] == '\r' {
			raw = raw[:len(raw)-1]
		}
		indent := guardianCountLeadingSpaces(raw)
		if indent >= len(raw) {
			continue // blank line
		}

		if !parsed.SawSinceChargeSection && !parsed.SawEstimatedPowerSec {
			if bytes.Contains(raw, []byte("Permission Denial")) || bytes.Contains(raw, []byte("SecurityException")) {
				permissionDenied = true
			}
		}

		// Fast path: while in topSkip (e.g. multi-megabyte Battery History / History: / Per-PID Stats),
		// check only zero-indent section headers using raw byte comparisons (0 heap allocations!).
		if topState == topSkip {
			if indent == 0 {
				if guardianBytesHasPrefixTrimmed(raw, "Statistics since last charge:") {
					topState = topSinceCharge
					subState = subNone
					curUIDAcc = nil
					parsed.SawSinceChargeSection = true
					continue
				}
				if guardianBytesHasPrefixTrimmed(raw, "Estimated power use (mAh)") {
					topState = topStandalonePower
					hdrLower := strings.ToLower(string(raw))
					if strings.Contains(hdrLower, "screen off") || strings.Contains(hdrLower, "doze") {
						subState = subPowerScreenOff
					} else {
						subState = subPowerAll
					}
					parsed.SawEstimatedPowerSec = true
					continue
				}
			}
			continue
		}

		// Check top-level transitions at indent == 0
		if indent == 0 {
			if guardianBytesHasPrefixTrimmed(raw, "Statistics since last charge:") {
				topState = topSinceCharge
				subState = subNone
				curUIDAcc = nil
				parsed.SawSinceChargeSection = true
				continue
			}
			if guardianBytesHasPrefixTrimmed(raw, "Estimated power use (mAh)") {
				topState = topStandalonePower
				hdrLower := strings.ToLower(string(raw))
				if strings.Contains(hdrLower, "screen off") || strings.Contains(hdrLower, "doze") {
					subState = subPowerScreenOff
				} else {
					subState = subPowerAll
				}
				curUIDAcc = nil
				parsed.SawEstimatedPowerSec = true
				continue
			}
			// Any other indent-0 header (History:, Battery History, Statistics since last unplugged:, etc.) -> skip!
			topState = topSkip
			subState = subNone
			curUIDAcc = nil
			continue
		}

		trimmed := strings.TrimSpace(string(raw[indent:]))
		if trimmed == "" {
			continue
		}

		if topState == topStandalonePower {
			if strings.HasPrefix(trimmed, "Capacity:") {
				guardianParsePowerCapacityLine(trimmed, &parsed.Summary, subState == subPowerScreenOff)
			} else if strings.HasPrefix(trimmed, "UID ") || strings.HasPrefix(trimmed, "Uid ") {
				guardianParsePowerUIDLine(trimmed, subState == subPowerScreenOff, parsed)
			}
			continue
		}

		// Inside `Statistics since last charge:`
		if indent == 2 {
			curUIDAcc = nil
			if strings.HasPrefix(trimmed, "Estimated power use (mAh)") ||
				strings.HasPrefix(trimmed, "Screen-off estimated power use (mAh)") {
				hdrLower := strings.ToLower(trimmed)
				if strings.Contains(hdrLower, "screen off") || strings.Contains(hdrLower, "screen-off") || strings.Contains(hdrLower, "doze") {
					subState = subPowerScreenOff
				} else {
					subState = subPowerAll
				}
				parsed.SawEstimatedPowerSec = true
				continue
			}

			// Explicit fast-skip of embedded History: if any ROM indents it at level 2
			if trimmed == "History:" || strings.HasPrefix(trimmed, "Battery History") {
				subState = subNone
				continue
			}

			// Check if this 2-space line is a UID header (`0:`, `1000:`, `u0a245:`)
			if strings.HasSuffix(trimmed, ":") && strings.IndexByte(trimmed, ' ') < 0 {
				if uid, ok := guardianParseBatteryUID(trimmed); ok {
					acc := parsed.ByUID[uid]
					if acc == nil {
						acc = &guardianUIDPowerAccum{uid: uid}
						parsed.ByUID[uid] = acc
					}
					curUIDAcc = acc
					subState = subUIDDetail
					continue
				}
			}

			subState = subNone
			// Device-level summary lines at indent == 2
			switch {
			case strings.HasPrefix(trimmed, "Estimated battery capacity:"):
				after := strings.TrimPrefix(trimmed, "Estimated battery capacity:")
				if f, ok := guardianParseLeadingFloat(after); ok && f > 0 && parsed.Summary.BatteryCapacityMah <= 0 {
					parsed.Summary.BatteryCapacityMah = guardianRound2(f)
				}
			case strings.HasPrefix(trimmed, "Time on battery:"):
				after := strings.TrimSpace(strings.TrimPrefix(trimmed, "Time on battery:"))
				parsed.Summary.TimeOnBatteryMs = guardianParseBatteryDurationMs(after)
			case strings.HasPrefix(trimmed, "Time on battery screen off:") || strings.HasPrefix(trimmed, "Screen off time:"):
				_, after, _ := strings.Cut(trimmed, ":")
				parsed.Summary.ScreenOffOnBatteryMs = guardianParseBatteryDurationMs(strings.TrimSpace(after))
			case strings.HasPrefix(trimmed, "Screen on:"):
				after := strings.TrimSpace(strings.TrimPrefix(trimmed, "Screen on:"))
				screenOnMs = guardianParseBatteryDurationMs(after)
			case strings.HasPrefix(trimmed, "Discharge:"):
				after := strings.TrimSpace(strings.TrimPrefix(trimmed, "Discharge:"))
				if f, ok := guardianParseLeadingFloat(after); ok && f > 0 && parsed.Summary.ActualDischargeMah <= 0 {
					parsed.Summary.ActualDischargeMah = guardianRound2(f)
				}
			case strings.HasPrefix(trimmed, "Screen off discharge:"):
				after := strings.TrimSpace(strings.TrimPrefix(trimmed, "Screen off discharge:"))
				if f, ok := guardianParseLeadingFloat(after); ok && f >= 0 {
					parsed.Summary.ScreenOffDischargeMah = guardianRound2(f)
				}
			}
			continue
		}

		// indent >= 4 inside active sub-section
		switch subState {
		case subPowerAll, subPowerScreenOff:
			if indent == 4 && (strings.Contains(strings.ToLower(trimmed), "screen off") || strings.Contains(strings.ToLower(trimmed), "doze")) && strings.HasSuffix(trimmed, ":") {
				subState = subPowerScreenOff
				continue
			}
			if strings.HasPrefix(trimmed, "Capacity:") {
				guardianParsePowerCapacityLine(trimmed, &parsed.Summary, subState == subPowerScreenOff)
			} else if strings.HasPrefix(trimmed, "UID ") || strings.HasPrefix(trimmed, "Uid ") {
				guardianParsePowerUIDLine(trimmed, subState == subPowerScreenOff, parsed)
			}
		case subUIDDetail:
			if curUIDAcc != nil {
				guardianParseUIDDetailLine(curUIDAcc, indent, trimmed)
			}
		}
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}
	if permissionDenied && !parsed.SawSinceChargeSection && !parsed.SawEstimatedPowerSec {
		return nil, errors.New("permission_denied: dumpsys batterystats denied")
	}
	if !parsed.SawSinceChargeSection && !parsed.SawEstimatedPowerSec {
		return nil, errors.New("batterystats_empty_or_unrecognized")
	}

	if parsed.Summary.ScreenOffOnBatteryMs <= 0 && parsed.Summary.TimeOnBatteryMs > 0 && screenOnMs > 0 &&
		parsed.Summary.TimeOnBatteryMs >= screenOnMs {
		parsed.Summary.ScreenOffOnBatteryMs = parsed.Summary.TimeOnBatteryMs - screenOnMs
	}

	return parsed, nil
}

func (e *guardianHostEngine) fetchPowerStatsCached(parentCtx context.Context, wantRefresh bool) (*guardianPowerCacheEntry, bool, bool, error) {
	nowMono := monoNowNs()

	e.powerMu.RLock()
	cached := e.powerCache
	e.powerMu.RUnlock()

	if cached != nil {
		ageNs := nowMono - cached.fetchedMonoNs
		if !wantRefresh && ageNs < int64(guardianPowerCacheTTL) {
			return cached, true, false, nil
		}
		if wantRefresh && ageNs < int64(guardianPowerRefreshMinCool) {
			return cached, true, true, nil
		}
	}

	val, err := e.powerSF.DoCtx(parentCtx, "batterystats", guardianSingleFlightTimeout, func(sfCtx context.Context) (any, error) {
		curMono := monoNowNs()
		e.powerMu.RLock()
		innerCached := e.powerCache
		e.powerMu.RUnlock()
		if innerCached != nil {
			ageNs := curMono - innerCached.fetchedMonoNs
			if !wantRefresh && ageNs < int64(guardianPowerCacheTTL) {
				return innerCached, nil
			}
			if wantRefresh && ageNs < int64(guardianPowerRefreshMinCool) {
				return innerCached, nil
			}
		}

		var parsed *guardianParsedBatteryStats
		if e.batterystatsStreamFn != nil {
			rc, err := e.batterystatsStreamFn(sfCtx)
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			p, perr := parseBatterystatsChargedStream(io.LimitReader(rc, guardianMaxStreamBytes))
			if perr != nil {
				return nil, perr
			}
			parsed = p
		} else {
			err := e.execDumpsysStream(sfCtx, guardianPowerCmdTimeout, func(r io.Reader) error {
				p, perr := parseBatterystatsChargedStream(r)
				if perr != nil {
					return perr
				}
				parsed = p
				return nil
			}, "batterystats", "--charged")
			if err != nil {
				return nil, err
			}
		}

		doneMono := monoNowNs()
		entry := &guardianPowerCacheEntry{
			fetchedMonoNs: doneMono,
			generatedAt:   e.now().Unix(),
			parsed:        parsed,
		}
		e.powerMu.Lock()
		e.powerCache = entry
		e.powerMu.Unlock()
		e.lastPowerFetchMono.Store(doneMono)
		e.powerCachedFlag.Store(true)
		return entry, nil
	})
	if err != nil {
		return nil, false, false, err
	}
	return val.(*guardianPowerCacheEntry), false, false, nil
}

func (s *server) apiLocalAppsPower(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	e := s.guardianEngine()
	e.powerHits.Add(1)
	now := e.now()

	q := r.URL.Query()
	sortBy := strings.ToLower(strings.TrimSpace(q.Get("sort")))
	switch sortBy {
	case "", "bg_mah":
		sortBy = "bg_mah"
	case "screen_off_mah", "total_mah", "wakelock_ms", "radio_ms", "cpu_bg_ms", "alarms":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "invalid sort: want bg_mah|screen_off_mah|total_mah|wakelock_ms|radio_ms|cpu_bg_ms|alarms",
		})
		return
	}

	includeSystem := q.Get("include_system") == "1" || strings.EqualFold(q.Get("include_system"), "true")
	wantRefresh := q.Get("refresh") == "1" || strings.EqualFold(q.Get("refresh"), "true")
	limit := 100
	if rawLim := q.Get("limit"); rawLim != "" {
		if n, err := strconv.Atoi(rawLim); err == nil && n > 0 {
			if n > 500 {
				n = 500
			}
			limit = n
		}
	}

	entry, fromCache, refreshThrottled, err := e.fetchPowerStatsCached(r.Context(), wantRefresh)
	if err != nil || entry == nil || entry.parsed == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":             true,
			"available":      false,
			"reason_code":    guardianClassifyReasonCode(err, "batterystats_unavailable"),
			"reason":         fmt.Sprintf("%v", err),
			"generated_at":   now.Unix(),
			"sort":           sortBy,
			"include_system": includeSystem,
			"apps":           []LocalAppPowerRow{},
		})
		return
	}

	parsed := entry.parsed
	globalBgMahAvail := parsed.AnyMultiStatePower
	globalBgMahReason := ""
	powerFormat := "a14_multi_state"
	if !globalBgMahAvail {
		if parsed.AnyLegacySipperPower {
			globalBgMahReason = "rom_uid_power_no_bg_split"
			powerFormat = "legacy_sipper"
		} else {
			globalBgMahReason = "power_profile_uid_split_missing"
			powerFormat = "hardware_timers_only"
		}
	}

	rows := e.buildConsolidatedPowerRows(parsed, includeSystem, globalBgMahAvail, globalBgMahReason)

	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch sortBy {
		case "bg_mah":
			if globalBgMahAvail && a.BgMah != b.BgMah {
				return a.BgMah > b.BgMah
			}
			if a.TotalMah != b.TotalMah {
				return a.TotalMah > b.TotalMah
			}
			if a.WakelockPartialMs != b.WakelockPartialMs {
				return a.WakelockPartialMs > b.WakelockPartialMs
			}
		case "screen_off_mah":
			if parsed.AnyScreenOffUIDPower && a.ScreenOffMah != b.ScreenOffMah {
				return a.ScreenOffMah > b.ScreenOffMah
			}
			if a.TotalMah != b.TotalMah {
				return a.TotalMah > b.TotalMah
			}
		case "total_mah":
			if a.TotalMah != b.TotalMah {
				return a.TotalMah > b.TotalMah
			}
		case "wakelock_ms":
			if a.WakelockPartialMs != b.WakelockPartialMs {
				return a.WakelockPartialMs > b.WakelockPartialMs
			}
		case "radio_ms":
			if a.MobileRadioActiveMs != b.MobileRadioActiveMs {
				return a.MobileRadioActiveMs > b.MobileRadioActiveMs
			}
		case "cpu_bg_ms":
			if a.CPUBgMs != b.CPUBgMs {
				return a.CPUBgMs > b.CPUBgMs
			}
			if a.CPUTotalMs != b.CPUTotalMs {
				return a.CPUTotalMs > b.CPUTotalMs
			}
		case "alarms":
			if a.WakeupAlarmsCount != b.WakeupAlarmsCount {
				return a.WakeupAlarmsCount > b.WakeupAlarmsCount
			}
		}
		return a.UID < b.UID
	})

	totalMatched := len(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}

	resp := map[string]any{
		"ok":                       true,
		"available":                true,
		"generated_at":             entry.generatedAt,
		"cached":                   fromCache,
		"refresh_throttled":        refreshThrottled,
		"sort":                     sortBy,
		"include_system":           includeSystem,
		"power_model_format":       powerFormat,
		"bg_mah_available":         globalBgMahAvail,
		"screen_off_mah_available": parsed.AnyScreenOffUIDPower,
		"app_count":                totalMatched,
		"device_summary":           parsed.Summary,
		"apps":                     rows,
	}
	if globalBgMahReason != "" {
		resp["bg_mah_reason"] = globalBgMahReason
	}
	writeJSON(w, http.StatusOK, resp)
}

func guardianClonePowerAccum(src *guardianUIDPowerAccum, targetUID int) *guardianUIDPowerAccum {
	if src == nil {
		return &guardianUIDPowerAccum{uid: targetUID}
	}
	cp := *src
	cp.uid = targetUID
	if src.bgComponents != nil {
		cp.bgComponents = make(map[string]float64, len(src.bgComponents))
		for k, v := range src.bgComponents {
			cp.bgComponents[k] = v
		}
	}
	if len(src.topWakelocks) > 0 {
		cp.topWakelocks = append([]LocalAppWakelockItem(nil), src.topWakelocks...)
	}
	if len(src.topAlarms) > 0 {
		cp.topAlarms = append([]LocalAppAlarmItem(nil), src.topAlarms...)
	}
	return &cp
}

func guardianEffectiveWakeMs(a *guardianUIDPowerAccum) int64 {
	if a.totalWakeLineMs > 0 {
		return a.totalWakeLineMs
	}
	return a.sumWakelockMs
}

func guardianEffectiveCPUTotalMs(a *guardianUIDPowerAccum) int64 {
	if a.uidCPUTotalMs > 0 {
		return a.uidCPUTotalMs
	}
	return a.procCPUTotalMs
}

func guardianMergePowerAccum(dst, src *guardianUIDPowerAccum) {
	if dst == nil || src == nil {
		return
	}
	dst.hasPowerRow = dst.hasPowerRow || src.hasPowerRow
	dst.hasMultiStateBg = dst.hasMultiStateBg || src.hasMultiStateBg
	dst.hasLegacySipper = dst.hasLegacySipper || src.hasLegacySipper
	dst.totalMah = guardianRound2(dst.totalMah + src.totalMah)
	dst.fgMah = guardianRound2(dst.fgMah + src.fgMah)
	dst.bgMah = guardianRound2(dst.bgMah + src.bgMah)
	dst.fgsMah = guardianRound2(dst.fgsMah + src.fgsMah)
	dst.cachedMah = guardianRound2(dst.cachedMah + src.cachedMah)
	dst.screenOffMah = guardianRound2(dst.screenOffMah + src.screenOffMah)
	dst.hasScreenOffMah = dst.hasScreenOffMah || src.hasScreenOffMah
	for k, v := range src.bgComponents {
		if dst.bgComponents == nil {
			dst.bgComponents = make(map[string]float64, len(src.bgComponents))
		}
		dst.bgComponents[k] = guardianRound2(dst.bgComponents[k] + v)
	}

	if dst.totalWakeLineMs > 0 || src.totalWakeLineMs > 0 {
		dst.totalWakeLineMs = guardianEffectiveWakeMs(dst) + guardianEffectiveWakeMs(src)
	}
	dst.sumWakelockMs += src.sumWakelockMs
	dst.wakelockBgMs += src.wakelockBgMs
	dst.wakelockCount += src.wakelockCount
	for _, wl := range src.topWakelocks {
		dst.topWakelocks = guardianPushTopWakelock(dst.topWakelocks, wl)
	}

	dst.radioActiveMs += src.radioActiveMs
	dst.radioWakeups += src.radioWakeups
	dst.wifiRunningMs += src.wifiRunningMs
	dst.wifiBgScans += src.wifiBgScans

	if dst.uidCPUTotalMs > 0 || src.uidCPUTotalMs > 0 {
		dst.uidCPUTotalMs = guardianEffectiveCPUTotalMs(dst) + guardianEffectiveCPUTotalMs(src)
	}
	dst.procCPUTotalMs += src.procCPUTotalMs
	if dst.hasUIDCPUFg || src.hasUIDCPUFg {
		var dfg, sfg int64
		if dst.hasUIDCPUFg {
			dfg = dst.uidCPUFgMs
		} else if dst.hasProcCPUFg {
			dfg = dst.procCPUFgMs
		}
		if src.hasUIDCPUFg {
			sfg = src.uidCPUFgMs
		} else if src.hasProcCPUFg {
			sfg = src.procCPUFgMs
		}
		dst.uidCPUFgMs = dfg + sfg
		dst.hasUIDCPUFg = true
	} else if src.hasProcCPUFg {
		dst.procCPUFgMs += src.procCPUFgMs
		dst.hasProcCPUFg = true
	}

	dst.apkWakeupsSum += src.apkWakeupsSum
	dst.alarmItemsSum += src.alarmItemsSum
	for _, al := range src.topAlarms {
		dst.topAlarms = guardianPushTopAlarm(dst.topAlarms, al)
	}
	dst.bgJobsMs += src.bgJobsMs
	dst.bgJobsCount += src.bgJobsCount
}

func (e *guardianHostEngine) lookupPkgUID(pkg string, userProfile int) (int, bool) {
	if pkg == "" {
		return 0, false
	}
	e.refreshPkgCatalogIfNeeded()
	e.pkgMu.RLock()
	baseU, ok := e.pkgToUID[pkg]
	e.pkgMu.RUnlock()
	if !ok {
		return 0, false
	}
	if userProfile > 0 && baseU < 100000 {
		return userProfile*100000 + baseU, true
	}
	return baseU, true
}

func (e *guardianHostEngine) resolveMetaForExplicitPkg(pkg string, userProfile int) guardianAppMeta {
	e.refreshPkgCatalogIfNeeded()
	e.pkgMu.RLock()
	var liveName string
	if e.liveLabelCache != nil {
		liveName = e.liveLabelCache[pkg]
	}
	resolver := e.labelResolver
	e.pkgMu.RUnlock()

	appName := liveName
	if appName == "" && resolver != nil {
		appName = resolver.Display(pkg)
	}
	if appName == "" {
		low := strings.ToLower(pkg)
		if strings.Contains(low, "webview") {
			appName = "Android System WebView"
		} else {
			appName = pkg
		}
	}
	if userProfile > 0 && !strings.Contains(appName, "分身") && !strings.Contains(appName, "用户") {
		if userProfile == 999 {
			appName += " (应用分身)"
		} else {
			appName = fmt.Sprintf("%s (用户%d)", appName, userProfile)
		}
	}
	lowPkg := strings.ToLower(pkg)
	isSys := lowPkg == "android" ||
		strings.HasPrefix(lowPkg, "com.android.") ||
		strings.HasPrefix(lowPkg, "com.google.android.webview") ||
		strings.HasPrefix(lowPkg, "com.google.android.trichromelibrary")
	return guardianAppMeta{
		Package:  pkg,
		AppName:  appName,
		IsSystem: isSys,
	}
}

func guardianBuildPowerRowFromAccum(uid int, meta guardianAppMeta, acc *guardianUIDPowerAccum, globalBgMahAvail bool, globalBgMahReason string) (LocalAppPowerRow, bool) {
	wlMs := acc.sumWakelockMs
	if acc.totalWakeLineMs > 0 {
		wlMs = acc.totalWakeLineMs
	}
	wlBgMs := acc.wakelockBgMs
	if wlBgMs > wlMs {
		wlBgMs = wlMs
	}

	cpuTotal := acc.uidCPUTotalMs
	if cpuTotal <= 0 {
		cpuTotal = acc.procCPUTotalMs
	}
	var cpuFg, cpuBg int64
	if acc.hasUIDCPUFg {
		cpuFg = acc.uidCPUFgMs
		if cpuTotal >= cpuFg {
			cpuBg = cpuTotal - cpuFg
		}
	} else if acc.hasProcCPUFg {
		cpuFg = acc.procCPUFgMs
		if cpuTotal >= cpuFg {
			cpuBg = cpuTotal - cpuFg
		}
	}

	alarmsCnt := acc.apkWakeupsSum
	if acc.alarmItemsSum > alarmsCnt {
		alarmsCnt = acc.alarmItemsSum
	}

	if acc.totalMah <= 0 && acc.screenOffMah <= 0 && wlMs <= 0 &&
		acc.radioActiveMs <= 0 && cpuTotal <= 0 && alarmsCnt <= 0 && acc.bgJobsMs <= 0 {
		return LocalAppPowerRow{}, false
	}

	rowBgAvail := acc.hasMultiStateBg
	rowBgReason := ""
	var rowBgMah float64
	if rowBgAvail {
		rowBgMah = acc.bgMah
	} else if acc.hasLegacySipper {
		// 严禁使用 CPU / Wakelock 时长比例伪造假毫安时!
		rowBgMah = 0
		rowBgReason = "rom_uid_power_no_bg_split"
	} else if !globalBgMahAvail {
		rowBgReason = globalBgMahReason
	}

	topWL := acc.topWakelocks
	if topWL == nil {
		topWL = []LocalAppWakelockItem{}
	}
	topAL := acc.topAlarms
	if topAL == nil {
		topAL = []LocalAppAlarmItem{}
	}

	return LocalAppPowerRow{
		UID:                    uid,
		Package:                meta.Package,
		AppName:                meta.AppName,
		IsSystem:               meta.IsSystem,
		TotalMah:               acc.totalMah,
		FgMah:                  acc.fgMah,
		BgMah:                  rowBgMah,
		FgsMah:                 acc.fgsMah,
		CachedMah:              acc.cachedMah,
		ScreenOffMah:           acc.screenOffMah,
		BgMahAvailable:         rowBgAvail,
		BgMahReason:            rowBgReason,
		BgComponentsMah:        acc.bgComponents,
		WakelockPartialMs:      wlMs,
		WakelockBgMs:           wlBgMs,
		WakelockCount:          acc.wakelockCount,
		TopWakelocks:           topWL,
		MobileRadioActiveMs:    acc.radioActiveMs,
		MobileRadioWakeupCount: acc.radioWakeups,
		WifiRunningMs:          acc.wifiRunningMs,
		WifiBgScanCount:        acc.wifiBgScans,
		CPUTotalMs:             cpuTotal,
		CPUFgMs:                cpuFg,
		CPUBgMs:                cpuBg,
		WakeupAlarmsCount:      alarmsCnt,
		TopWakeupAlarms:        topAL,
		BgJobsMs:               acc.bgJobsMs,
		BgJobsCount:            acc.bgJobsCount,
	}, true
}

func (e *guardianHostEngine) buildConsolidatedPowerRows(
	parsed *guardianParsedBatteryStats,
	includeSystem bool,
	globalBgMahAvail bool,
	globalBgMahReason string,
) []LocalAppPowerRow {
	if parsed == nil || len(parsed.ByUID) == 0 {
		return []LocalAppPowerRow{}
	}
	mergedByUID := make(map[int]*guardianUIDPowerAccum, len(parsed.ByUID))
	type pkgProfileKey struct {
		pkg     string
		profile int
	}
	unmappedPkgAcc := make(map[pkgProfileKey]*guardianUIDPowerAccum)
	unmappedPkgUID := make(map[pkgProfileKey]int)
	var orphanIsolatedAcc *guardianUIDPowerAccum

	addToUID := func(targetUID int, src *guardianUIDPowerAccum) {
		if dst, exists := mergedByUID[targetUID]; exists {
			guardianMergePowerAccum(dst, src)
		} else {
			mergedByUID[targetUID] = guardianClonePowerAccum(src, targetUID)
		}
	}

	uids := make([]int, 0, len(parsed.ByUID))
	for uid := range parsed.ByUID {
		uids = append(uids, uid)
	}
	sort.Ints(uids)

	for _, uid := range uids {
		if uid < 0 || uid > 100_000_000 {
			continue
		}
		acc := parsed.ByUID[uid]
		if acc == nil {
			continue
		}
		userProfile := uid / 100000
		appID := uid % 100000
		if appID >= 20000 && appID <= 29999 {
			addToUID(uid-10000, acc)
			continue
		}
		if appID >= 90000 {
			if acc.procHostPkg != "" {
				if hostUID, ok := e.lookupPkgUID(acc.procHostPkg, userProfile); ok {
					addToUID(hostUID, acc)
				} else {
					pk := pkgProfileKey{pkg: acc.procHostPkg, profile: userProfile}
					if dst, exists := unmappedPkgAcc[pk]; exists {
						guardianMergePowerAccum(dst, acc)
					} else {
						unmappedPkgAcc[pk] = guardianClonePowerAccum(acc, uid)
						unmappedPkgUID[pk] = uid
					}
				}
			} else {
				if orphanIsolatedAcc == nil {
					orphanIsolatedAcc = guardianClonePowerAccum(acc, 99000)
				} else {
					guardianMergePowerAccum(orphanIsolatedAcc, acc)
				}
			}
			continue
		}
		addToUID(uid, acc)
	}

	rows := make([]LocalAppPowerRow, 0, len(mergedByUID)+len(unmappedPkgAcc)+1)
	for uid, acc := range mergedByUID {
		meta := e.resolveAppMeta(uid)
		if !includeSystem && meta.IsSystem {
			continue
		}
		if row, ok := guardianBuildPowerRowFromAccum(uid, meta, acc, globalBgMahAvail, globalBgMahReason); ok {
			rows = append(rows, row)
		}
	}
	for pk, acc := range unmappedPkgAcc {
		meta := e.resolveMetaForExplicitPkg(pk.pkg, pk.profile)
		if !includeSystem && meta.IsSystem {
			continue
		}
		if row, ok := guardianBuildPowerRowFromAccum(unmappedPkgUID[pk], meta, acc, globalBgMahAvail, globalBgMahReason); ok {
			rows = append(rows, row)
		}
	}
	if includeSystem && orphanIsolatedAcc != nil {
		isoMeta := guardianAppMeta{
			Package:  "isolated:summary",
			AppName:  "系统隔离沙盒汇总",
			IsSystem: true,
		}
		if row, ok := guardianBuildPowerRowFromAccum(99000, isoMeta, orphanIsolatedAcc, globalBgMahAvail, globalBgMahReason); ok {
			rows = append(rows, row)
		}
	}
	return rows
}

// ─── 引擎三: L1 零抓包本机隐私与明文连接实时安检 (/api/local_apps/privacy_audit) ───

type LocalAppPrivacySummary struct {
	CleartextHTTPConns int `json:"cleartext_http_conns"`
	DirectDNSConns     int `json:"direct_dns_conns"`
	TrackerSDKConns    int `json:"tracker_sdk_conns"`
	BgActiveConns      int `json:"bg_active_conns"`
	RiskyAppsCount     int `json:"risky_apps_count"`
}

type LocalAppPrivacyFinding struct {
	RiskType   string `json:"risk_type"`
	Severity   string `json:"severity"`
	UID        int    `json:"uid"`
	Package    string `json:"package"`
	AppName    string `json:"app_name"`
	IsSystem   bool   `json:"is_system"`
	AppState   string `json:"app_state"`
	Proto      string `json:"proto"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	Domain     string `json:"domain,omitempty"`
	OwnerOrg   string `json:"owner_org,omitempty"`
	SDKName    string `json:"sdk_name,omitempty"`
	UpBytes    uint64 `json:"up_bytes,omitempty"`
	DownBytes  uint64 `json:"down_bytes,omitempty"`
	UpBps      int64  `json:"up_bps,omitempty"`
	Detail     string `json:"detail"`
}

func (s *server) guardianReadSelfCaptureStatus() (enabled bool, mode string) {
	if s == nil || s.hncDir == "" {
		return false, "off"
	}
	flagExists := false
	if _, err := os.Stat(s.selfFlagPath()); err == nil {
		flagExists = true
	}
	optInExists := false
	for _, rel := range []string{
		filepath.Join("data", "self_capture.enabled"),
		filepath.Join("data", "self_capture.optin"),
	} {
		if _, err := os.Stat(filepath.Join(s.hncDir, rel)); err == nil {
			optInExists = true
			break
		}
	}

	mode = "off"
	studioOn := false
	var (
		raw  any
		rerr error
	)
	if s.jsonCache != nil {
		raw, rerr = s.jsonCache.read(selfPolicyPath(s.hncDir))
	} else {
		raw, rerr = readJSON(selfPolicyPath(s.hncDir))
	}
	if rerr == nil {
		if m, ok := raw.(map[string]any); ok {
			if md := strings.ToLower(strings.TrimSpace(asString(m["mode"]))); md != "" {
				mode = md
				if md != "off" && md != "stop" {
					studioOn = true
				}
			}
			for _, k := range []string{"self_capture_opt_in", "self_capture_enabled", "opt_in", "enabled"} {
				if bv, okb := m[k].(bool); okb && bv {
					optInExists = true
				}
			}
		}
	}
	if (mode == "" || (rerr != nil && mode == "off")) && (flagExists || optInExists) {
		mode = "smart_screen"
	}
	enabled = flagExists || optInExists || studioOn
	return enabled, mode
}

func (e *guardianHostEngine) snapshotForegroundUIDsReadonly() (fgUIDs map[int]bool, liveRates map[int]guardianUIDRate, known bool) {
	e.trafficMu.Lock()
	if e.bpfSampler != nil && e.latestBPFSnap != nil && e.latestBPFSnap.HasCounterSetMap {
		fgCopy := make(map[int]bool, len(e.latestBPFSnap.ForegroundUIDs))
		for k, v := range e.latestBPFSnap.ForegroundUIDs {
			fgCopy[k] = v
		}
		rCopy := make(map[int]guardianUIDRate, len(e.liveRates))
		for k, v := range e.liveRates {
			rCopy[k] = v
		}
		e.trafficMu.Unlock()
		return fgCopy, rCopy, true
	}
	e.trafficMu.Unlock()

	if e.fgUIDsFallbackFn != nil {
		fg, ok := e.fgUIDsFallbackFn()
		return fg, nil, ok
	}
	fg, ok := bytestats.ReadNetdForegroundUIDs()
	return fg, nil, ok
}

func (s *server) apiLocalAppsPrivacyAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	e := s.guardianEngine()
	e.privacyHits.Add(1)
	now := e.now()
	includeSystem := r.URL.Query().Get("include_system") == "1" ||
		strings.EqualFold(r.URL.Query().Get("include_system"), "true")

	selfEnabled, selfMode := s.guardianReadSelfCaptureStatus()

	sockets, readable := guardianScanProcSocketsDir(e.effectiveProcNetDir())
	if !readable {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":                   true,
			"available":            false,
			"reason_code":          "proc_net_unreadable",
			"generated_at":         now.Unix(),
			"self_capture_enabled": selfEnabled,
			"self_capture_mode":    selfMode,
			"summary":              LocalAppPrivacySummary{},
			"findings":             []LocalAppPrivacyFinding{},
		})
		return
	}

	ctSnap := conntrackSnapshot()
	type ctFlowStat struct {
		upBytes   uint64
		downBytes uint64
		upBps     int64 // bytes/sec
	}
	ctBy5Tuple := make(map[string]ctFlowStat)
	ctByPeer := make(map[string]ctFlowStat)
	if ctSnap != nil && ctSnap.readable {
		for _, ce := range ctSnap.entries {
			k5 := ce.key()
			// conntrackSnapshot stores upBps in bits/sec; convert to bytes/sec for consistency
			var uBps int64
			if bpsBits, ok := ctSnap.upBps[k5]; ok && bpsBits > 0 {
				uBps = int64(bpsBits / 8)
			}
			st := ctFlowStat{upBytes: ce.UpB, downBytes: ce.DnB, upBps: uBps}
			ctBy5Tuple[k5] = st
			peerKey := ce.Proto + "|" + strconv.Itoa(ce.Sport) + "|" + ce.Dst + "|" + strconv.Itoa(ce.Dport)
			if prev, exists := ctByPeer[peerKey]; !exists || st.upBytes > prev.upBytes {
				ctByPeer[peerKey] = st
			}
		}
	}

	names := s.loadIPNames()
	apps := s.loadIPApps()
	fgUIDs, liveRates, fgKnown := e.snapshotForegroundUIDsReadonly()

	var summary LocalAppPrivacySummary
	findings := make([]LocalAppPrivacyFinding, 0, 32)
	riskyUIDs := make(map[int]bool, 16)
	dedupFinding := make(map[string]bool, 64)

	emitFinding := func(f LocalAppPrivacyFinding) {
		dk := f.RiskType + "|" + strconv.Itoa(f.UID) + "|" + f.Proto + "|" + f.RemoteIP + ":" + strconv.Itoa(f.RemotePort)
		if dedupFinding[dk] {
			return
		}
		dedupFinding[dk] = true
		findings = append(findings, f)
		riskyUIDs[f.UID] = true
		switch f.RiskType {
		case "http_cleartext":
			summary.CleartextHTTPConns++
		case "dns_direct":
			summary.DirectDNSConns++
		case "tracker_sdk":
			summary.TrackerSDKConns++
		case "bg_silent_uplink":
			summary.BgActiveConns++
		}
	}

	for _, sk := range sockets {
		if !guardianIsNonLoopbackExternalIP(sk.RemoteIP) {
			continue
		}
		meta := e.resolveAppMeta(sk.UID)

		var domain, ipCat, ipAppLabel string
		if n, ok := names[sk.RemoteIP]; ok {
			domain = n.Name
			ipCat = n.Category
			ipAppLabel = n.AppName
		}
		if a, ok := apps[sk.RemoteIP]; ok {
			if ipCat == "" {
				ipCat = a.Category
			}
			if ipAppLabel == "" {
				ipAppLabel = a.Name
			}
		}
		var ownerName string
		if org, ok := ipOwnerLookup(sk.RemoteIP); ok {
			ownerName = org.Name
		}

		appState := "unknown"
		if fgKnown {
			if fgUIDs[sk.UID] {
				appState = "foreground"
			} else {
				appState = "background"
			}
		}

		flowSt, hasCT := ctBy5Tuple[sk.ctKey()]
		if !hasCT {
			peerKey := sk.Proto + "|" + strconv.Itoa(sk.LocalPort) + "|" + sk.RemoteIP + "|" + strconv.Itoa(sk.RemotePort)
			flowSt, hasCT = ctByPeer[peerKey]
		}

		// 风险 1: http_cleartext — 明文 :80/:8080/:8000 公网 TCP 传输(豁免系统连通性探测)
		if sk.Proto == "tcp" && (sk.RemotePort == 80 || sk.RemotePort == 8080 || sk.RemotePort == 8000) &&
			guardianIsPublicRoutableIP(sk.RemoteIP) {
			if !guardianIsSystemCaptivePortalProbe(sk.UID, domain) && (includeSystem || !meta.IsSystem) {
				targetDesc := sk.RemoteIP
				if domain != "" {
					targetDesc = domain + " (" + sk.RemoteIP + ")"
				}
				emitFinding(LocalAppPrivacyFinding{
					RiskType:   "http_cleartext",
					Severity:   "high",
					UID:        sk.UID,
					Package:    meta.Package,
					AppName:    meta.AppName,
					IsSystem:   meta.IsSystem,
					AppState:   appState,
					Proto:      sk.Proto,
					RemoteIP:   sk.RemoteIP,
					RemotePort: sk.RemotePort,
					Domain:     domain,
					OwnerOrg:   ownerName,
					UpBytes:    flowSt.upBytes,
					DownBytes:  flowSt.downBytes,
					UpBps:      flowSt.upBps,
					Detail:     fmt.Sprintf("明文 HTTP 未加密传输至 %s:%d", targetDesc, sk.RemotePort),
				})
			}
		}

		// 风险 2: dns_direct — 第三方应用(uid >= 10000)绕过系统 netd 直连外部 :53 明文 DNS (豁免代理 Fake-IP 虚拟 DNS)
		if sk.RemotePort == 53 && !guardianIsSystemAppID(sk.UID) && !isBenchmarkOrFakeIP(sk.RemoteIP) {
			emitFinding(LocalAppPrivacyFinding{
				RiskType:   "dns_direct",
				Severity:   "high",
				UID:        sk.UID,
				Package:    meta.Package,
				AppName:    meta.AppName,
				IsSystem:   meta.IsSystem,
				AppState:   appState,
				Proto:      sk.Proto,
				RemoteIP:   sk.RemoteIP,
				RemotePort: sk.RemotePort,
				Domain:     domain,
				OwnerOrg:   ownerName,
				UpBytes:    flowSt.upBytes,
				DownBytes:  flowSt.downBytes,
				UpBps:      flowSt.upBps,
				Detail:     fmt.Sprintf("绕过系统 netd DNS 代理直连外部明文 DNS %s:53", sk.RemoteIP),
			})
		}

		// 风险 3: tracker_sdk — 连接已知广告 / 行为分析 / 第三方遥测 SDK 域名
		if includeSystem || !meta.IsSystem {
			var sdkName string
			if tr, matched := e.matchTrackerDomain(domain); matched {
				sdkName = tr.SDKName
			} else if guardianIsTrackerCategory(ipCat) && ipAppLabel != "" {
				sdkName = ipAppLabel
			}
			if sdkName != "" {
				emitFinding(LocalAppPrivacyFinding{
					RiskType:   "tracker_sdk",
					Severity:   "medium",
					UID:        sk.UID,
					Package:    meta.Package,
					AppName:    meta.AppName,
					IsSystem:   meta.IsSystem,
					AppState:   appState,
					Proto:      sk.Proto,
					RemoteIP:   sk.RemoteIP,
					RemotePort: sk.RemotePort,
					Domain:     domain,
					OwnerOrg:   ownerName,
					SDKName:    sdkName,
					UpBytes:    flowSt.upBytes,
					DownBytes:  flowSt.downBytes,
					UpBps:      flowSt.upBps,
					Detail:     fmt.Sprintf("连接第三方追踪/广告 SDK [%s] (%s)", sdkName, domain),
				})
			}
		}

		// 风险 4: bg_silent_uplink — 当前处于后台态且持续活跃外发数据的公网连接
		if appState == "background" && guardianIsPublicRoutableIP(sk.RemoteIP) && (includeSystem || !meta.IsSystem) {
			uidRate := liveRates[sk.UID]
			activeUplink := flowSt.upBps > 0 || flowSt.upBytes >= 4096 || sk.TxQueue > 0 || uidRate.txBps >= 512
			if activeUplink {
				effUpBps := flowSt.upBps
				if effUpBps <= 0 && uidRate.txBps > 0 {
					effUpBps = uidRate.txBps
				}
				target := sk.RemoteIP
				if domain != "" {
					target = domain
				} else if ownerName != "" {
					target = sk.RemoteIP + " [" + ownerName + "]"
				}
				emitFinding(LocalAppPrivacyFinding{
					RiskType:   "bg_silent_uplink",
					Severity:   "medium",
					UID:        sk.UID,
					Package:    meta.Package,
					AppName:    meta.AppName,
					IsSystem:   meta.IsSystem,
					AppState:   appState,
					Proto:      sk.Proto,
					RemoteIP:   sk.RemoteIP,
					RemotePort: sk.RemotePort,
					Domain:     domain,
					OwnerOrg:   ownerName,
					UpBytes:    flowSt.upBytes,
					DownBytes:  flowSt.downBytes,
					UpBps:      effUpBps,
					Detail:     fmt.Sprintf("应用处于后台静默状态持续向 %s:%d 外发数据", target, sk.RemotePort),
				})
			}
		}
	}

	severityRank := func(s string) int {
		switch s {
		case "high":
			return 3
		case "medium":
			return 2
		default:
			return 1
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		ri, rj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if findings[i].UpBytes != findings[j].UpBytes {
			return findings[i].UpBytes > findings[j].UpBytes
		}
		return findings[i].UID < findings[j].UID
	})

	summary.RiskyAppsCount = len(riskyUIDs)
	e.lastPrivacyRisky.Store(int64(summary.RiskyAppsCount))
	e.privacyCachedFlag.Store(true)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                   true,
		"available":            true,
		"generated_at":         now.Unix(),
		"self_capture_enabled": selfEnabled,
		"self_capture_mode":    selfMode,
		"summary":              summary,
		"findings":             findings,
	})
}
