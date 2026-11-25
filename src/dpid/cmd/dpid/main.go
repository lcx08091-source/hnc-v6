// hnc_dpid: HNC DPI daemon, AppSense-lite rc1.2-fixed / v6.0.0 Vector.
//
// rc19 adds L2 per-client DNS/SNI attribution:
// capability probe -> mode decision -> raw AF_PACKET socket -> DNS/TLS events -> per-client metadata -> dpi_state.json.
//
// It does NOT do: NFQUEUE, DNS hijacking, automatic limit/mark, or offload
// modification. (v5.14 added QUIC Initial SNI; v5.18 added plain-HTTP Host,
// multi-segment ClientHello reassembly, and conntrack-driven keep-alive of
// the IP→name table — dpid is now the only IP→name source, nDPI is gone.)
// v6.0.0 Vector adds 16KB seqcount_latch shared memory snapshot (shm_vector.bin)
// and LeakGuard real-time cleartext privacy leak sniffer.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"hnc.io/dpid/activity"
	"hnc.io/dpid/apkscan"
	"hnc.io/dpid/appmeta"
	"hnc.io/dpid/bytestats"
	"hnc.io/dpid/capture"
	"hnc.io/dpid/ifacehint"
	"hnc.io/dpid/leakguard"
	"hnc.io/dpid/output"
	"hnc.io/dpid/probe"
	"hnc.io/dpid/shm"
	"hnc.io/dpid/tzlocal"
)

const engineVersion = "0.5.4"

var (
	moduleVersion = "dev"
	versionCode   = "0"
	version       = engineVersion + "-" + moduleVersion
)

func readModuleProp(hncDir string) (modVer, verCode string) {
	candidates := []string{
		"/data/local/hnc/module.prop",
		"/data/adb/modules/hotspot_net_ctl/module.prop",
		"/data/adb/modules/hotspot_network_control/module.prop",
	}
	if cleanDir := strings.TrimSpace(hncDir); cleanDir != "" {
		candidates = append([]string{filepath.Join(cleanDir, "module.prop")}, candidates...)
	}
	seen := make(map[string]struct{}, len(candidates))
	for _, p := range candidates {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var fv, fc string
		for _, raw := range strings.Split(string(b), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if v, ok := strings.CutPrefix(line, "version="); ok && fv == "" {
				fv = strings.TrimSpace(v)
			} else if c, ok := strings.CutPrefix(line, "versionCode="); ok && fc == "" {
				fc = strings.TrimSpace(c)
			}
		}
		if fv != "" || fc != "" {
			return fv, fc
		}
	}
	return "", ""
}

func resolveDpidVersion(hncDir string) {
	modVer := strings.TrimSpace(moduleVersion)
	verCode := strings.TrimSpace(versionCode)
	if modVer == "" || modVer == "dev" || verCode == "" || verCode == "0" {
		fv, fc := readModuleProp(hncDir)
		if (modVer == "" || modVer == "dev") && fv != "" {
			modVer = fv
		}
		if (verCode == "" || verCode == "0") && fc != "" {
			verCode = fc
		}
	}
	if modVer == "" {
		modVer = "dev"
	}
	if verCode == "" {
		verCode = "0"
	}
	if trimmed, ok := strings.CutPrefix(modVer, engineVersion+"-"); ok && trimmed != "" {
		modVer = trimmed
	}
	moduleVersion = modVer
	versionCode = verCode
	version = engineVersion + "-" + modVer
}

// v5.22 功耗: hnc_httpd 写的 run/activity.json(热点/在线设备/亮屏/界面)。
// 文件缺失或过期时一律按基准间隔(旧行为)。
var actReader *activity.Reader

const (
	defaultConfigPath = "/data/local/hnc/etc/dpi_config.json"
	defaultRunDir     = "/data/local/hnc/run"

	pidFileName   = "dpid.pid"
	lockFileName  = "dpid.lock"
	probeFileName = "dpid.probe.json"
	stateFileName = "dpi_state.json"
	// v5.13: 被动设备识别结果 / IP→域名反查表, 与 dpi_state.json 同目录。
	devIDFileName  = "dpi_devid.json"
	ipNameFileName = "dpi_ipname.json"
	// v5.15: 未知应用发现(聚类结果 / JA4 家族学习表)与本机安装包域名索引。
	discoverFileName  = "dpi_discover.json"
	ja4FamilyFileName = "dpi_ja4family.json"
	flowLogFileName   = "dpi_flows.json" // v6.x DPI v2: 每连接 JA4(flowlog.go)
	apkDomainsFile    = "apk_domains.json"
	apkScanRequest    = "apk_scan.request"
	crashFlagFile     = "dpid.crashflag"

	maxCrashesWindow  = 60 * time.Second
	maxCrashesAllowed = 3
	crashLoopCooldown = 2 * time.Minute

	debugEventsPerSec = 20

	shmFlowTTLSec      = 60
	shmOnlineWindowSec = 300
	shmMaxFlowsPerDev  = 64
	shmMaxIPv6PerDev   = 16

	// appLabelDexName is the dex helper shipped alongside the dpid binary
	// (in the module bin/ dir). Run via app_process to read real PM labels.
	appLabelDexName = "hnc_applabel.dex"
	// appLabelDexModulePrimary and appLabelDexModuleLegacy are on-device
	// fallback paths if dpid's own directory cannot be determined.
	appLabelDexModulePrimary = "/data/adb/modules/hotspot_net_ctl/bin/" + appLabelDexName
	appLabelDexModuleLegacy  = "/data/adb/modules/hotspot_network_control/bin/" + appLabelDexName
)

// shmDevEntry tracks per-device live telemetry for 16KB shm_vector.bin snapshots.
// ipv6s retains multiple concurrent SLAAC / RFC 4941 privacy IPv6 addresses in memory
// for conntrack & FlowScalpel attribution while keeping shm.DeviceSlot layout intact.
type shmDevEntry struct {
	mac      [6]byte
	ipv4     [4]byte
	ipv6     [16]byte
	rxBytes  uint64
	txBytes  uint64
	lastSeen int64
	leakHit  bool
	flows    map[uint64]int64
	ipv6s    map[[16]byte]int64
}

func isLinkLocalV6Bytes(v6 [16]byte) bool {
	return v6[0] == 0xfe && (v6[1]&0xc0) == 0x80
}

// shmRuntimeTracker aggregates downstream client slots without contending on output.Writer.
type shmRuntimeTracker struct {
	// Placed at offset 0 for 32-bit ARM 64-bit atomic alignment.
	conntrackHotspotFlows atomic.Uint64
	conntrackHostFlows    atomic.Uint64
	conntrackUpdatedUnix  atomic.Int64
	sleeping              atomic.Bool

	mu            sync.Mutex
	devs          map[[6]byte]*shmDevEntry
	ctClientFlows map[[6]byte]uint32
	poke          chan struct{}
}

func newSHMRuntimeTracker() *shmRuntimeTracker {
	return &shmRuntimeTracker{
		devs:          make(map[[6]byte]*shmDevEntry, shm.MaxDevices),
		ctClientFlows: make(map[[6]byte]uint32, shm.MaxDevices),
		poke:          make(chan struct{}, 1),
	}
}

func (t *shmRuntimeTracker) notifyPoke() {
	if t == nil {
		return
	}
	select {
	case t.poke <- struct{}{}:
	default:
	}
}

func (t *shmRuntimeTracker) resetIdle(clearDevs bool) {
	t.conntrackHotspotFlows.Store(0)
	t.mu.Lock()
	clear(t.ctClientFlows)
	if clearDevs {
		clear(t.devs)
	} else {
		for _, d := range t.devs {
			clear(d.flows)
		}
	}
	t.mu.Unlock()
}

func isGatewayMgmtPacket(remoteIP string, port uint16) bool {
	if port == 67 || port == 68 {
		return true
	}
	switch port {
	case 53, 8443, 8444, 8080:
	default:
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(remoteIP))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsLoopback() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.Equal(net.IPv4bcast)
}

func (t *shmRuntimeTracker) observePacket(macRaw, clientIP, remoteIP string, isUDP bool, port uint16, pktBytes int, txFromClient bool, nowUnix int64) {
	macBytes, ok := shm.ParseMAC(macRaw)
	if !ok {
		return
	}
	v4, v6, isV4, isV6 := shm.ParseIPAddr(clientIP)
	var fhash uint64
	if remoteIP != "" && port > 0 && !isGatewayMgmtPacket(remoteIP, port) {
		h := fnv.New64a()
		if isUDP {
			_, _ = h.Write([]byte{'U'})
		} else {
			_, _ = h.Write([]byte{'T'})
		}
		_, _ = h.Write([]byte(remoteIP))
		_, _ = h.Write([]byte{byte(port >> 8), byte(port)})
		fhash = h.Sum64()
	}

	t.mu.Lock()
	d := t.devs[macBytes]
	if d == nil {
		if len(t.devs) >= shm.MaxDevices {
			var oldestKey [6]byte
			var oldestTs int64
			first := true
			for k, v := range t.devs {
				if first || v.lastSeen < oldestTs {
					oldestKey, oldestTs, first = k, v.lastSeen, false
				}
			}
			if !first {
				delete(t.devs, oldestKey)
			}
		}
		d = &shmDevEntry{
			mac:   macBytes,
			flows: make(map[uint64]int64, 16),
			ipv6s: make(map[[16]byte]int64, 4),
		}
		t.devs[macBytes] = d
	}
	d.lastSeen = nowUnix
	if isV4 {
		d.ipv4 = v4
	}
	if isV6 && v6 != ([16]byte{}) {
		if !isLinkLocalV6Bytes(v6) || d.ipv6 == ([16]byte{}) {
			d.ipv6 = v6
		}
		if d.ipv6s == nil {
			d.ipv6s = make(map[[16]byte]int64, 4)
		}
		if _, exists := d.ipv6s[v6]; !exists && len(d.ipv6s) >= shmMaxIPv6PerDev {
			for k6, ts6 := range d.ipv6s {
				if nowUnix-ts6 > shmOnlineWindowSec*2 {
					delete(d.ipv6s, k6)
				}
			}
			if len(d.ipv6s) >= shmMaxIPv6PerDev {
				var oldV6 [16]byte
				var oldTs int64
				first := true
				for k6, ts6 := range d.ipv6s {
					if first || ts6 < oldTs {
						oldV6, oldTs, first = k6, ts6, false
					}
				}
				if !first {
					delete(d.ipv6s, oldV6)
				}
			}
		}
		d.ipv6s[v6] = nowUnix
	}
	if pktBytes > 0 {
		if txFromClient {
			d.txBytes += uint64(pktBytes)
		} else {
			d.rxBytes += uint64(pktBytes)
		}
	}
	if fhash != 0 {
		if _, exists := d.flows[fhash]; !exists && len(d.flows) >= shmMaxFlowsPerDev {
			for fk, ts := range d.flows {
				if nowUnix-ts > shmFlowTTLSec {
					delete(d.flows, fk)
				}
			}
			if len(d.flows) >= shmMaxFlowsPerDev {
				for fk := range d.flows {
					delete(d.flows, fk)
					break
				}
			}
		}
		d.flows[fhash] = nowUnix
	}
	t.mu.Unlock()
	if t.sleeping.CompareAndSwap(true, false) {
		t.notifyPoke()
	}
}

func (t *shmRuntimeTracker) markLeak(macRaw string) {
	macBytes, ok := shm.ParseMAC(macRaw)
	if ok {
		t.mu.Lock()
		if d := t.devs[macBytes]; d != nil {
			d.leakHit = true
		}
		t.mu.Unlock()
	}
	t.notifyPoke()
}

func (t *shmRuntimeTracker) conntrackClients(nowUnix int64) (online []output.ConntrackClient, inactiveIPs []string) {
	if t == nil {
		return nil, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, d := range t.devs {
		ips := make([]string, 0, 1+len(d.ipv6s))
		seen := make(map[string]struct{}, 1+len(d.ipv6s))
		addIP := func(s string) {
			if s == "" {
				return
			}
			if _, dup := seen[s]; !dup {
				seen[s] = struct{}{}
				ips = append(ips, s)
			}
		}
		if d.ipv4 != ([4]byte{}) {
			addIP(net.IPv4(d.ipv4[0], d.ipv4[1], d.ipv4[2], d.ipv4[3]).String())
		}
		if d.ipv6 != ([16]byte{}) {
			addIP(net.IP(d.ipv6[:]).String())
		}
		for v6, ts6 := range d.ipv6s {
			if v6 == ([16]byte{}) {
				continue
			}
			if nowUnix-ts6 > shmOnlineWindowSec*4 {
				delete(d.ipv6s, v6)
				continue
			}
			addIP(net.IP(v6[:]).String())
		}
		if len(ips) == 0 {
			continue
		}
		if nowUnix-d.lastSeen <= shmOnlineWindowSec {
			slot := shm.DeviceSlot{MAC: d.mac}
			online = append(online, output.ConntrackClient{
				MAC: slot.MACString(),
				IPs: ips,
			})
		} else {
			inactiveIPs = append(inactiveIPs, ips...)
		}
	}
	return online, inactiveIPs
}

func (t *shmRuntimeTracker) updateConntrackSplit(split output.ConntrackFlowSplit, nowUnix int64) {
	if t == nil {
		return
	}
	t.conntrackHotspotFlows.Store(uint64(split.HotspotFlows))
	t.conntrackHostFlows.Store(uint64(split.HostFlows))
	t.conntrackUpdatedUnix.Store(nowUnix)

	t.mu.Lock()
	clear(t.ctClientFlows)
	for macStr, cnt := range split.PerClientFlows {
		if mb, ok := shm.ParseMAC(macStr); ok && cnt > 0 {
			t.ctClientFlows[mb] = cnt
		}
	}
	t.mu.Unlock()
}

func (t *shmRuntimeTracker) snapshot(nowUnix int64, act activity.Snapshot) (slots []shm.DeviceSlot, hotspotFlows uint32, hostFlows uint32) {
	hotspotZero := act.OK && (!act.Hotspot || act.Clients <= 0)

	t.mu.Lock()
	slots = make([]shm.DeviceSlot, 0, len(t.devs))
	var sumFlows uint32
	onlineCount := 0
	for _, d := range t.devs {
		for fk, ts := range d.flows {
			if nowUnix-ts > shmFlowTTLSec {
				delete(d.flows, fk)
			}
		}
		isOnline := !act.HotspotOff() && nowUnix-d.lastSeen <= shmOnlineWindowSec
		var af uint32
		if isOnline && !hotspotZero {
			onlineCount++
			af = uint32(len(d.flows))
			if ctAF := t.ctClientFlows[d.mac]; ctAF > af {
				af = ctAF
			}
			sumFlows += af
		}
		var flags uint32
		if isOnline {
			flags |= shm.FlagOnline
		}
		if d.ipv4 != ([4]byte{}) {
			flags |= shm.FlagIPv4
		}
		if d.ipv6 != ([16]byte{}) {
			flags |= shm.FlagIPv6
		}
		if d.leakHit {
			flags |= shm.FlagLeakHit
		}
		slots = append(slots, shm.DeviceSlot{
			MAC:         d.mac,
			IPv4:        d.ipv4,
			IPv6:        d.ipv6,
			RxBytes:     d.rxBytes,
			TxBytes:     d.txBytes,
			ActiveFlows: af,
			Flags:       flags,
		})
	}
	t.mu.Unlock()

	sort.Slice(slots, func(i, j int) bool {
		totI := slots[i].RxBytes + slots[i].TxBytes
		totJ := slots[j].RxBytes + slots[j].TxBytes
		if totI != totJ {
			return totI > totJ
		}
		return string(slots[i].MAC[:]) < string(slots[j].MAC[:])
	})

	hostFlows = uint32(t.conntrackHostFlows.Load())
	ctHotspot := uint32(t.conntrackHotspotFlows.Load())

	if hotspotZero {
		return slots, 0, hostFlows
	}
	if onlineCount == 0 && ctHotspot == 0 {
		return slots, 0, hostFlows
	}
	if ctHotspot > sumFlows {
		hotspotFlows = ctHotspot
	} else if onlineCount > 0 {
		hotspotFlows = sumFlows
	}
	return slots, hotspotFlows, hostFlows
}

// resolveAppLabelDex locates the app-label dex helper. Prefers a file next
// to the running dpid binary (where the module ships it), then hotspot_net_ctl
// and legacy hotspot_network_control module paths.
func resolveAppLabelDex() string {
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), appLabelDexName)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	for _, modCand := range []string{appLabelDexModulePrimary, appLabelDexModuleLegacy} {
		if _, err := os.Stat(modCand); err == nil {
			return modCand
		}
	}
	return ""
}

type Config struct {
	Iface          string `json:"iface,omitempty"`
	Snaplen        int    `json:"snaplen,omitempty"`
	RcvBufBytes    int    `json:"rcv_buf_bytes,omitempty"`
	LogLevel       string `json:"log_level,omitempty"`
	RunDir         string `json:"run_dir,omitempty"`
	DisableCapture bool   `json:"disable_capture,omitempty"`
}

func defaultConfig() Config {
	return Config{
		Snaplen:     1024,
		RcvBufBytes: 4 << 20,
		LogLevel:    "info",
		RunDir:      defaultRunDir,
	}
}

type Mode string

const (
	ModeOK        Mode = "ok"
	ModeBlind     Mode = "blind"
	ModeDisabled  Mode = "disabled"
	ModeCrashLoop Mode = "crash_loop"
)

func main() {
	// P1 timezone pitfall guard: initialize Android local timezone before time.Now() usage.
	time.Local = tzlocal.Location()

	cfgPath := flag.String("config", defaultConfigPath, "path to dpi_config.json")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		resolveDpidVersion(filepath.Dir(filepath.Dir(filepath.Clean(*cfgPath))))
		fmt.Println("hnc_dpid", version)
		return
	}

	cfg := loadConfig(*cfgPath)
	if err := os.MkdirAll(cfg.RunDir, 0o750); err != nil {
		log.Fatalf("mkdir run_dir %s: %v", cfg.RunDir, err)
	}

	// v5.29 T4: 流量录制(只录握手类事件包, 见 capture/recorder.go)。
	// exports 根 = run_dir 的上两级(run/ 的父目录就是 HNC 根)。
	_hncRoot := filepath.Dir(filepath.Clean(cfg.RunDir))
	dataDir := filepath.Join(_hncRoot, "data")
	resolveDpidVersion(_hncRoot)
	capture.DefaultRecorder.Store(capture.NewRecorder(_hncRoot, cfg.RunDir))

	lockPath := filepath.Join(cfg.RunDir, lockFileName)
	lockFD, err := acquireLock(lockPath)
	if err != nil && errors.Is(err, syscall.ENOSPC) {
		rescueTmpfsRunDir(cfg.RunDir, dataDir)
		lockFD, err = acquireLock(lockPath)
	}
	if err != nil {
		log.Fatalf("lock: %v", err)
	}
	defer releaseLock(lockFD)

	// v6.1.0-rc.4: Before writing run/dpid.pid, perform cross-filesystem (EXDEV-safe)
	// emergency rescue of 32MB tmpfs run/ (migrate/cap legacy JSONL & caches to data/, purge stale .tmp).
	rescueTmpfsRunDir(cfg.RunDir, dataDir)

	log.Printf("hnc_dpid %s starting, pid=%d", version, os.Getpid())

	// Write PID early so crash_loop, blind, disabled, and ok modes all have a pid file.
	pidPath := filepath.Join(cfg.RunDir, pidFileName)
	if err := atomicWriteString(pidPath, strconv.Itoa(os.Getpid())+"\n"); err != nil {
		log.Printf("WARN: write pid: %v", err)
	}
	defer os.Remove(pidPath)

	statePath := filepath.Join(cfg.RunDir, stateFileName)
	sw := output.NewWriter(statePath, version)
	sw.SetModuleVersion(moduleVersion, versionCode)

	if reason := checkCrashLoop(cfg.RunDir); reason != "" {
		log.Printf("ERROR: %s", reason)
		sw.SetMode(string(ModeCrashLoop), reason, "", false, false, false)
		_ = sw.Flush()
		idleUntilSignal(cfg.RunDir, sw)
		return
	}

	pr := probe.Run(probe.Options{IfaceOverride: cfg.Iface})
	if fresh := resolveCurrentIface(cfg); fresh != "" && fresh != pr.APIface {
		pr.APIface = fresh
		pr.APIfaceSource = "ifacehint"
	}
	if err := probe.WriteJSON(filepath.Join(cfg.RunDir, probeFileName), pr); err != nil {
		log.Printf("WARN: write probe: %v", err)
	}
	log.Printf("probe: af_packet=%v iface=%q src=%s offload_hint=%v conntrack=%v ipv6_capture=%v",
		pr.AFPacketAvailable, pr.APIface, pr.APIfaceSource, pr.OffloadHint, pr.ConntrackReadable, pr.IPv6Capture)

	// rc29 + RC2 fix: tell capture about the hotspot's own MAC and IP nets so
	// assignClient can identify client vs server direction accurately.
	if pr.APIface != "" {
		nets := refreshHotspotContext(pr.APIface)
		if len(nets) > 0 {
			names := make([]string, 0, len(nets))
			for _, n := range nets {
				names = append(names, n.String())
			}
			log.Printf("hotspot nets on %s: %s", pr.APIface, strings.Join(names, " "))
		} else {
			log.Printf("WARN: no IP addrs detected on %s; client/server direction inference pending", pr.APIface)
		}
	}

	mode, blindReason := decideMode(cfg, pr)
	sw.SetMode(string(mode), blindReason, pr.APIface, pr.TLSReassembly, pr.OffloadHint, pr.IPv6Capture)
	_ = sw.Flush()
	if blindReason != "" {
		log.Printf("startup mode: %s: %s", mode, blindReason)
	} else {
		log.Printf("startup mode: %s", mode)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	output.SetCompiledFPPath(cfg.RunDir)
	actReader = activity.NewReader(cfg.RunDir)

	shmTracker := newSHMRuntimeTracker()

	wakeHistCh := make(chan struct{}, 1)
	wakeIPMapCh := make(chan struct{}, 1)
	wakeSelfCh := make(chan struct{}, 1)
	wakeCaptureCh := make(chan struct{}, 1)
	wakeAppMetaCh := make(chan struct{}, 1)
	wakeStandbyLoops := func() {
		for _, ch := range []chan struct{}{wakeHistCh, wakeIPMapCh, wakeSelfCh, wakeCaptureCh, wakeAppMetaCh} {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
		shmTracker.notifyPoke()
	}
	wakeSelfAndAppMeta := func() {
		for _, ch := range []chan struct{}{wakeSelfCh, wakeAppMetaCh} {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
	startHotspotHintInotifyFull(ctx, cfg.RunDir, wakeStandbyLoops, shmTracker.notifyPoke, wakeSelfAndAppMeta)

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				log.Printf("received %v, shutting down", sig)
				cancel()
				return
			case syscall.SIGHUP:
				output.InvalidateRuleCache()
				wakeStandbyLoops()
				log.Printf("SIGHUP received: invalidated DPI rule & compiled FP caches")
			}
		}
	}()

	bumpStartCount(cfg.RunDir) // rc42: 持久 lifetime 启动计数, 供 /api/sla

	// v5.13: IP→域名反查表提前初始化, 供 SHM conntrack KeepAlive、本机自抓包 DNS/HTTP 与主抓包共用。
	ipNames := output.NewIPNameTable()
	ipNames.SetPath(filepath.Join(cfg.RunDir, ipNameFileName))
	sw.SetIPNameTable(ipNames) // v5.18: RecordFlow 域名兜底(取代 nDPI ip_to_host.json)
	go flushEvery(ctx, 10*time.Second, "dpi_ipname", ipNames.Flush)

	// v6.0.0 Vector: LeakGuard 明文隐私嗅探引擎 + 16KB 双槽 seqcount_latch 共享内存快照。
	leakEngine := leakguard.NewEngine(cfg.RunDir)
	seedKnownARPClients(leakEngine)
	leakEngine.SetIdleCheck(func() bool {
		s := actReader.Get()
		return s.OK && (!s.Hotspot || (s.Clients <= 0 && !s.WebUI))
	})
	leakEngine.SetAlertHook(func(ev leakguard.LeakEvent) {
		shmTracker.markLeak(ev.MAC)
	})
	leakEngine.Start(ctx)
	defer func() { _ = leakEngine.Close() }()

	shmWriter, shmErr := shm.OpenWriter(cfg.RunDir)
	if shmErr != nil {
		log.Printf("WARN: shm writer unavailable (%s): %v", shm.FilePath(cfg.RunDir), shmErr)
	} else {
		defer func() { _ = shmWriter.Close() }()
		scanConntrackOrthogonal(cfg, sw, ipNames, shmTracker)
		publishSHM := func() {
			nowUnix := time.Now().Unix()
			act := actReader.Get()
			if !act.ShmShouldSleep() && nowUnix-shmTracker.conntrackUpdatedUnix.Load() >= 10 {
				scanConntrackOrthogonal(cfg, sw, ipNames, shmTracker)
			}
			devSlots, hotspotFlows, hostFlows := shmTracker.snapshot(nowUnix, act)
			totalLeaks := leakEngine.TotalLeaks()
			var hdrFlags uint32
			if werr := shmWriter.WriteWithHostFlows(shm.MonotonicNs(), hotspotFlows, hostFlows, totalLeaks, hdrFlags, devSlots); werr != nil {
				log.Printf("WARN: shm write: %v", werr)
			}
		}
		publishSHM()
		go func() {
			initSnap := actReader.Get()
			wasHotspotOff := initSnap.HotspotOff()
			cur := activity.ShmFlushEvery(initSnap)
			tk := time.NewTicker(cur)
			defer tk.Stop()
			sleeping := false
			enterSleep := func(s activity.Snapshot) {
				if sleeping {
					return
				}
				// Final zeroed/clean flush before entering 0-wakeup standby.
				shmTracker.resetIdle(!s.Hotspot)
				publishSHM()
				tk.Stop()
				sleeping = true
				shmTracker.sleeping.Store(true)
			}
			if initSnap.ShmShouldSleep() {
				enterSleep(initSnap)
			}
			syncPace := func(fromPoke bool) {
				s := actReader.Get()
				hotspotOff := s.HotspotOff()
				if wasHotspotOff && !hotspotOff {
					wakeStandbyLoops()
				}
				wasHotspotOff = hotspotOff
				if s.ShmShouldSleep() {
					if fromPoke && s.Hotspot {
						// Packet/leak arrived while hotspot is active before activity.json updated Clients:
						// keep one active tick before re-evaluating standby.
						shmTracker.sleeping.Store(false)
						cur = activity.ShmFlushEvery(s)
						sleeping = false
						tk.Reset(cur)
						return
					}
					enterSleep(s)
					return
				}
				shmTracker.sleeping.Store(false)
				want := activity.ShmFlushEvery(s)
				if sleeping || want != cur {
					cur = want
					sleeping = false
					tk.Reset(cur)
				}
			}
			for {
				select {
				case <-ctx.Done():
					publishSHM()
					return
				case <-shmTracker.poke:
					s := actReader.Get()
					if !sleeping || !s.ShmShouldSleep() || s.Hotspot {
						publishSHM()
					}
					syncPace(true)
				case <-tk.C:
					if actReader.Get().ShmShouldSleep() {
						syncPace(false)
						continue
					}
					publishSHM()
					syncPace(false)
				}
			}
		}()
	}

	// rc30.4 + RC2: traffic history sampler persisted under <hnc>/data/dpi_history
	// (migrating any residual stats.*.jsonl out of 32M tmpfs run/).
	initHistoryStorage(cfg.RunDir)
	historySampler := output.NewHistorySampler(sw)
	go func() {
		cur := historySampleEvery(actReader.Get(), output.HistorySampleEvery)
		tk := time.NewTicker(cur)
		defer tk.Stop()
		retime := func() {
			if want := historySampleEvery(actReader.Get(), output.HistorySampleEvery); want != cur {
				cur = want
				tk.Reset(cur)
			}
		}
		// Establish baseline immediately so the first row arrives at the
		// FIRST scheduled tick, not the second.
		historySampler.Tick(time.Now())
		for {
			select {
			case <-ctx.Done():
				return
			case <-wakeHistCh:
				retime()
			case t := <-tk.C:
				historySampler.Tick(t)
				retime()
			}
		}
	}()

	// rc30.6: IP→app reverse map flusher. Writes /run/ip_app_map.json
	// every 30s (stretched to 120s when hotspot is off) for apply_app_limits.sh
	// to consume. Holding the data only in memory and dumping on a clock tick
	// keeps the file lock contention near zero.
	if sw.IPAppMap != nil {
		sw.IPAppMap.SetPath(filepath.Join(cfg.RunDir, "ip_app_map.json"))
		go func() {
			cur := ipAppMapFlushEvery(actReader.Get())
			tk := time.NewTicker(cur)
			defer tk.Stop()
			retime := func() {
				if want := ipAppMapFlushEvery(actReader.Get()); want != cur {
					cur = want
					tk.Reset(cur)
				}
			}
			for {
				select {
				case <-ctx.Done():
					return
				case <-wakeIPMapCh:
					retime()
				case t := <-tk.C:
					if err := sw.IPAppMap.Flush(t); err != nil {
						log.Printf("ip_app_map flush: %v", err)
					}
					retime()
				}
			}
		}()
	}

	// v5.5 + v6.1.0-rc.4: self-attribution sampler persisted under <hnc>/data/self_studio.
	selfAttribFlag := filepath.Join(cfg.RunDir, "self_capture.enabled")
	selfAttribAltFlag := filepath.Join(cfg.RunDir, "self_attrib.enabled")
	selfStudioDir := output.SelfStudioDir(_hncRoot)
	if err := os.MkdirAll(selfStudioDir, 0o755); err != nil {
		log.Printf("WARN: mkdir self_studio %s: %v", selfStudioDir, err)
	}
	selfAttrib := output.NewSelfAttribAggregator(selfStudioDir)

	var explicitSelfCapture atomic.Bool
	hasExplicitSelfCaptureFlag := func() bool {
		if _, err := os.Stat(selfAttribFlag); err == nil {
			return true
		}
		if _, err := os.Stat(selfAttribAltFlag); err == nil {
			return true
		}
		return false
	}
	explicitSelfCapture.Store(hasExplicitSelfCaptureFlag())

	appLabelsOverride := "/data/local/hnc/etc/app_labels.json"
	appResolver := appmeta.NewResolver(appLabelsOverride)
	dexPath := resolveAppLabelDex()
	appResolver.EnableLiveLabels(dexPath, filepath.Join(dataDir, "app_labels_live.json"))
	appResolver.SetIdleHook(func() bool {
		return actReader.Get().HotspotOff() && !explicitSelfCapture.Load()
	}, wakeAppMetaCh)
	appResolver.StartLiveRefresh(ctx)
	selfAttrib.SetAppMetaResolver(appResolver)
	curated, overridden := appResolver.LabelCount()
	log.Printf("appmeta: resolver ready (curated=%d, override=%d, dex=%s, from %s)",
		curated, overridden, dexPath, appLabelsOverride)
	go func() {
		var selfCaptureOn atomic.Bool
		checkFlags := func() (captureEnabled bool, explicitEnabled bool) {
			_, err := os.Stat(selfAttribFlag)
			captureEnabled = err == nil
			explicitEnabled = captureEnabled
			if !explicitEnabled {
				if _, err2 := os.Stat(selfAttribAltFlag); err2 == nil {
					explicitEnabled = true
				}
			}
			selfCaptureOn.Store(captureEnabled)
			explicitSelfCapture.Store(explicitEnabled)
			if captureEnabled {
				selfAttrib.SetEnabled(true, "")
			} else {
				selfAttrib.SetEnabled(false, "self-capture flag file not present")
			}
			return captureEnabled, explicitEnabled
		}

		var (
			samplerCancel context.CancelFunc
			samplerDone   chan struct{}
		)
		reconcileSampler := func(standby bool) {
			if standby {
				if samplerCancel != nil {
					samplerCancel()
					<-samplerDone
					samplerCancel = nil
					samplerDone = nil
				}
				return
			}
			if samplerCancel == nil {
				sctx, scancel := context.WithCancel(ctx)
				done := make(chan struct{})
				samplerCancel = scancel
				samplerDone = done
				go func() {
					defer close(done)
					selfAttrib.RunSampler(sctx, func() bool { return selfCaptureOn.Load() })
				}()
			}
		}
		defer func() {
			if samplerCancel != nil {
				samplerCancel()
				<-samplerDone
			}
		}()

		_, explicitInit := checkFlags()
		actInit := actReader.Get()
		wasOff := actInit.OK && !actInit.Hotspot
		wasExplicit := explicitInit
		cur := selfAttribTickEvery(actInit, explicitInit)
		reconcileSampler(!explicitInit && wasOff)
		tk := time.NewTicker(cur)
		defer tk.Stop()

		step := func(doSnapshot bool) {
			_, explicit := checkFlags()
			s := actReader.Get()
			off := s.OK && !s.Hotspot
			if wasOff && !off {
				wakeStandbyLoops()
			}
			if !wasExplicit && explicit {
				select {
				case wakeAppMetaCh <- struct{}{}:
				default:
				}
			}
			wasOff = off
			wasExplicit = explicit
			reconcileSampler(!explicit && off)
			if want := selfAttribTickEvery(s, explicit); want != cur {
				cur = want
				tk.Reset(cur)
			}
			if doSnapshot {
				sw.SetSelf(selfAttrib.Snapshot())
			}
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-wakeSelfCh:
				step(false)
			case <-tk.C:
				step(true)
			}
		}
	}()

	// v5.6.0-rc1 + v6.1.0: self-iface AF_PACKET capture supervisor (TLS SNI + HTTP LeakGuard + DNS ipNames).
	go runSelfCaptures(ctx, cfg, selfAttrib, ipNames, leakEngine, func() string {
		if cur := resolveCurrentIface(cfg); cur != "" {
			return cur
		}
		return pr.APIface
	})

	// v5.6.0-rc2: auto-expander goroutine.
	go selfAttrib.RunAutoExpander(ctx, cfg.RunDir)

	// v5.7.0-m1: per-uid byte sampler.
	go runByteSampler(ctx, selfAttrib, func() bool {
		_, err := os.Stat(selfAttribFlag)
		return err == nil
	})

	// v5.13: 被动设备识别器。
	devID := output.NewDeviceIdentifier()
	devID.SetPath(filepath.Join(cfg.RunDir, devIDFileName))
	_ = devID.Load()
	sw.SetDeviceIdentifier(devID)
	go flushEvery(ctx, 15*time.Second, "dpi_devid", devID.Flush)
	// v6.x DPI v2: 每连接 ClientHello 指纹(五元组 → JA4/ALPN/SNI 归类)
	flowLog = output.NewFlowLog()
	flowLog.SetPath(filepath.Join(cfg.RunDir, flowLogFileName))
	go flushEvery(ctx, 10*time.Second, "dpi_flows", flowLog.Flush)

	// v5.15: 未知应用发现器
	disc := output.NewDiscoverer()
	disc.SetPath(filepath.Join(cfg.RunDir, discoverFileName))
	disc.SetFamilyPath(filepath.Join(cfg.RunDir, ja4FamilyFileName))
	disc.SetSharedInfraPath(filepath.Join(filepath.Dir(cfg.RunDir), "etc", "dpi_rules.d", output.SharedInfraFileName))
	if err := disc.Load(); err != nil {
		log.Printf("WARN: discover load: %v", err)
	}
	sw.SetDiscoverer(disc)
	go flushEvery(ctx, 30*time.Second, "dpi_discover", disc.Flush)

	// v5.15 + v6.1.0-rc.4: 本机安装包域名扫描(持久层写 data/apk_domains.json)
	apkScanner := apkscan.New(apkscan.Options{OutPath: filepath.Join(dataDir, apkDomainsFile), Label: appResolver.Display})
	go apkscan.RunDaemon(ctx, apkScanner, apkscan.DaemonOptions{RequestFile: filepath.Join(cfg.RunDir, apkScanRequest)})

	// RC2: Decouple true blind/disabled mode (AF_PACKET unavailable or explicit
	// disable_capture=true) from cold-start standby (hotspot temporarily off at
	// boot, iface==""). Whenever canCapture(cfg, pr) is true, enter runCapture so
	// dpid wakes up as soon as the hotspot interface appears.
	if !canCapture(cfg, pr) {
		clearCrashFlag(cfg.RunDir)
		log.Printf("no capture in %s mode; idling for state writes", mode)
		idleWithFlush(ctx, sw, wakeStandbyLoops)
	} else {
		if pr.APIface != "" {
			armCrashFlag(cfg.RunDir)
		} else {
			clearCrashFlag(cfg.RunDir)
		}
		if err := runCapture(ctx, cfg, pr, sw, devID, ipNames, leakEngine, shmTracker, wakeCaptureCh, wakeStandbyLoops); err != nil {
			// Capture open/run failure is capability failure, not daemon crash.
			reason := "open/run capture failed: " + err.Error()
			log.Printf("ERROR: %s", reason)
			sw.SetMode(string(ModeBlind), reason, pr.APIface, pr.TLSReassembly, pr.OffloadHint, pr.IPv6Capture)
			_ = sw.Flush()
			clearCrashFlag(cfg.RunDir)
			idleWithFlush(ctx, sw, wakeStandbyLoops)
		}
	}

	_ = sw.Flush()
	_ = devID.Flush(time.Now())
	_ = ipNames.Flush(time.Now())
	_ = flowLog.Flush(time.Now())
	_ = disc.Flush(time.Now())
	clearCrashFlag(cfg.RunDir)
	log.Printf("hnc_dpid exited cleanly")
}

// seedKnownARPClients primes LeakGuard's known-MAC table from /proc/net/arp at startup.
func seedKnownARPClients(eng *leakguard.Engine) {
	if eng == nil {
		return
	}
	b, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return
	}
	lines := strings.Split(string(b), "\n")
	for i := 1; i < len(lines); i++ {
		fields := strings.Fields(lines[i])
		if len(fields) >= 4 {
			eng.RegisterKnownMAC(fields[3])
		}
	}
}

var conntrackScanMu sync.Mutex

func localInterfaceIPs(iface string) []string {
	if iface == "" {
		return nil
	}
	ifc, err := net.InterfaceByName(iface)
	if err != nil || ifc == nil {
		return nil
	}
	addrs, err := ifc.Addrs()
	if err != nil || len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			if v.IP != nil {
				out = append(out, v.IP.String())
			}
		case *net.IPAddr:
			if v.IP != nil {
				out = append(out, v.IP.String())
			}
		}
	}
	return out
}

func appendARPClientsForIface(iface string, existing []output.ConntrackClient) []output.ConntrackClient {
	if iface == "" {
		return existing
	}
	b, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return existing
	}
	seenIP := make(map[string]struct{}, len(existing)*2)
	for _, c := range existing {
		for _, ip := range c.IPs {
			seenIP[ip] = struct{}{}
		}
	}
	lines := strings.Split(string(b), "\n")
	for i := 1; i < len(lines); i++ {
		fields := strings.Fields(lines[i])
		if len(fields) < 6 || fields[5] != iface || fields[2] == "0x0" {
			continue
		}
		ipStr := strings.TrimSpace(fields[0])
		macBytes, ok := shm.ParseMAC(fields[3])
		if !ok || net.ParseIP(ipStr) == nil {
			continue
		}
		if _, dup := seenIP[ipStr]; dup {
			continue
		}
		seenIP[ipStr] = struct{}{}
		slot := shm.DeviceSlot{MAC: macBytes}
		existing = append(existing, output.ConntrackClient{
			MAC: slot.MACString(),
			IPs: []string{ipStr},
		})
	}
	return existing
}

func scanConntrackOrthogonal(
	cfg Config,
	sw *output.Writer,
	ipNames *output.IPNameTable,
	shmTracker *shmRuntimeTracker,
) {
	conntrackScanMu.Lock()
	defer conntrackScanMu.Unlock()

	now := time.Now()
	nowUnix := now.Unix()
	act := actReader.Get()

	apIface := resolveCurrentIface(cfg)
	if apIface != "" && !isIfaceAliveUp(apIface) {
		apIface = ""
	}

	var onlineClients []output.ConntrackClient
	var inactiveIPs []string
	if shmTracker != nil {
		onlineClients, inactiveIPs = shmTracker.conntrackClients(nowUnix)
	}
	var gatewayIPs []string
	var hotspotNets []*net.IPNet
	if apIface != "" {
		gatewayIPs = localInterfaceIPs(apIface)
		hotspotNets = ifaceNetsFn(apIface)
		onlineClients = appendARPClientsForIface(apIface, onlineClients)
	}

	hotspotActive := apIface != "" && (!act.OK || (act.Hotspot && act.Clients > 0))
	clf := output.NewConntrackClassifier(output.ConntrackFlowOptions{
		HotspotActive:     hotspotActive,
		Clients:           onlineClients,
		InactiveClientIPs: inactiveIPs,
		GatewayIPs:        gatewayIPs,
		HotspotNets:       hotspotNets,
	})

	active := make(map[string]struct{}, 256)
	dot := make(map[string]struct{})
	r := output.ReadConntrackLines(func(line string) {
		clf.ObserveLine(line)
		if d := output.ConntrackOrigDst(line); d != "" {
			active[d] = struct{}{}
		}
		if k := output.ConntrackDoTKey(line); k != "" {
			dot[k] = struct{}{}
		}
	})

	split := clf.Result()
	if sw != nil {
		sw.UpdateConntrack(r.Available, r.Readable, r.Path, int(split.HotspotFlows))
		if r.Readable {
			sw.ObserveDoTFlows(dot)
		}
	}
	if r.Readable && shmTracker != nil {
		shmTracker.updateConntrackSplit(split, nowUnix)
	}
	if ipNames != nil {
		ipNames.KeepAlive(active, now)
	}
}

// flushEvery 以固定周期调用 flush(v5.13: dpi_devid / dpi_ipname 共用)。
// flush 内部自带"无变化不写"判断, 这里只负责节拍和日志。
func flushEvery(ctx context.Context, every time.Duration, name string, flush func(time.Time) error) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-tk.C:
			if err := flush(t); err != nil {
				log.Printf("WARN: %s flush: %v", name, err)
			}
		}
	}
}

type captureRunner interface {
	Run(ctx context.Context, onEvent func(capture.Event)) error
	Close()
	Iface() string
	CurrentIfindex() int
	Stats() capture.Stats
	Rebind(newIface string) error
}

// Runtime hooks (overridable in unit tests for deterministic self-healing verification).
var (
	openCaptureFn        = func(opts capture.Options) (captureRunner, error) { return capture.Open(opts) }
	ifaceNetsFn          = capture.InterfaceNets
	ifaceByNameFn        = net.InterfaceByName
	discoverAPFn         = capture.DiscoverAPCandidates
	rebindHandleFn       = func(h captureRunner, newIface string) error { return h.Rebind(newIface) }
	rebindCheckTickEvery = 15 * time.Second
)

// setLocalMACsFor 把抓包接口自身的 MAC 告诉 capture, 避免把本机发出的
// mDNS/SSDP 公告识别成一台客户端(v5.13)。
func setLocalMACsFor(iface string) {
	if iface == "" {
		capture.SetLocalMACs(nil)
		return
	}
	ifc, err := ifaceByNameFn(iface)
	if err != nil || ifc == nil || len(ifc.HardwareAddr) != 6 {
		capture.SetLocalMACs(nil)
		return
	}
	capture.SetLocalMACs([]net.HardwareAddr{ifc.HardwareAddr})
}

// refreshHotspotContext atomically refreshes both local AP MACs and hotspot
// subnets (IPv4 + IPv6) for capture direction inference.
func refreshHotspotContext(iface string) []*net.IPNet {
	if iface == "" {
		capture.SetLocalMACs(nil)
		capture.SetHotspotNets(nil)
		return nil
	}
	setLocalMACsFor(iface)
	nets := ifaceNetsFn(iface)
	capture.SetHotspotNets(nets)
	return nets
}

func netsSignature(nets []*net.IPNet) string {
	if len(nets) == 0 {
		return ""
	}
	parts := make([]string, 0, len(nets))
	for _, n := range nets {
		if n != nil {
			parts = append(parts, n.String())
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// toDeviceHint 把 capture.DevHint 转成 output.DeviceHint(output 不依赖 capture)。
func toDeviceHint(h *capture.DevHint) output.DeviceHint {
	return output.DeviceHint{
		MAC:         h.MAC,
		Source:      h.Source,
		Hostname:    h.Hostname,
		VendorClass: h.VendorClass,
		ParamList:   h.ParamList,
		Model:       h.Model,
		OSHint:      h.OSHint,
		UserAgent:   h.UserAgent,
		Services:    append([]string(nil), h.Services...),
	}
}

func runCapture(
	ctx context.Context,
	cfg Config,
	pr probe.Result,
	sw *output.Writer,
	devID *output.DeviceIdentifier,
	ipNames *output.IPNameTable,
	leakEngine *leakguard.Engine,
	shmTracker *shmRuntimeTracker,
	wakeCaptureCh <-chan struct{},
	wakeStandbyLoops func(),
) error {
	iface := pr.APIface
	attempt := 0
	var rebindCount atomic.Int64
	// v5.22 + RC2: 接口暂时不在(开机热点未开/热点关了)时重试间隔 2s 起翻倍,
	// 同时监听 wakeCaptureCh 实现重开热点毫秒级秒醒, 每次唤醒均重新解析最新口名。
	var retry time.Duration
	for {
		if ctx.Err() != nil {
			return nil
		}
		if cur := resolveCurrentIface(cfg); cur != "" {
			iface = cur
		} else if iface != "" && !isIfaceAliveUp(iface) {
			iface = ""
		}
		if iface != "" && !isHotspotActiveOrUnknown(cfg.RunDir) && !isIfaceAliveUp(iface) {
			iface = ""
		}

		if iface == "" {
			refreshHotspotContext("")
			sw.SetMode(string(ModeBlind), "no hotspot iface detected", "", pr.TLSReassembly, pr.OffloadHint, pr.IPv6Capture)
			_ = sw.Flush()
			clearCrashFlag(cfg.RunDir)
			retry = activity.CaptureRetryBackoff(retry, actReader.Get())
			cont, woken := sleepOrWake(ctx, retry, wakeCaptureCh)
			if !cont {
				return nil
			}
			if woken {
				if isHotspotActiveOrUnknown(cfg.RunDir) {
					retry = 0
				}
			}
			continue
		}

		attempt++
		refreshHotspotContext(iface)
		h, err := openCaptureFn(capture.Options{Iface: iface, Snaplen: cfg.Snaplen, RcvBufBytes: cfg.RcvBufBytes})
		if err != nil {
			if isRecoverableCaptureError(err) {
				reason := "interface down/rebind retry: " + err.Error()
				log.Printf("WARN: %s", reason)
				sw.SetMode(string(ModeBlind), reason, iface, pr.TLSReassembly, pr.OffloadHint, pr.IPv6Capture)
				_ = sw.Flush()
				clearCrashFlag(cfg.RunDir)
				retry = activity.CaptureRetryBackoff(retry, actReader.Get())
				cont, woken := sleepOrWake(ctx, retry, wakeCaptureCh)
				if !cont {
					return nil
				}
				if woken {
					if isHotspotActiveOrUnknown(cfg.RunDir) {
						retry = 0
					}
				}
				continue
			}
			return fmt.Errorf("open capture: %w", err)
		}
		retry = 0
		armCrashFlag(cfg.RunDir)
		refreshHotspotContext(iface)

		// Launch rebind-check goroutine for this capture attempt.
		// It monitors iface/ifindex/subnet changes and zero-packet conditions.
		rebindCtx, rebindCancel := context.WithCancel(ctx)
		var rebindWG sync.WaitGroup
		rebindWG.Add(1)
		go func() {
			defer rebindWG.Done()
			rebindCheckLoop(rebindCtx, h, cfg, pr, sw, &rebindCount)
		}()

		attemptCtx, attemptCancel := context.WithCancel(ctx)
		var attemptWG sync.WaitGroup
		log.Printf("capture started on %s (snaplen=%d, rcvbuf=%d, attempt=%d)", iface, cfg.Snaplen, cfg.RcvBufBytes, attempt)
		sw.SetMode(string(ModeOK), "", iface, pr.TLSReassembly, pr.OffloadHint, pr.IPv6Capture)
		_ = sw.Flush()
		if wakeStandbyLoops != nil {
			wakeStandbyLoops()
		}

		// rc40 (P2-20): once capture has run healthily for 5 min, clear the crash flag.
		attemptWG.Add(1)
		go func(ctxLocal context.Context) {
			defer attemptWG.Done()
			t := time.NewTimer(5 * time.Minute)
			defer t.Stop()
			select {
			case <-ctxLocal.Done():
			case <-t.C:
				clearCrashFlag(cfg.RunDir)
				log.Printf("capture healthy for 5m; cleared crash flag")
			}
		}(attemptCtx)

		debug := cfg.LogLevel == "debug"
		var debugBudget atomic.Int64
		if debug {
			debugBudget.Store(int64(debugEventsPerSec))
			attemptWG.Add(1)
			go func() {
				defer attemptWG.Done()
				tk := time.NewTicker(time.Second)
				defer tk.Stop()
				for {
					select {
					case <-attemptCtx.Done():
						return
					case <-tk.C:
						debugBudget.Store(int64(debugEventsPerSec))
					}
				}
			}()
		}

		attemptWG.Add(1)
		go func(local captureRunner) {
			defer attemptWG.Done()
			// v5.22: 基准 5s; 热点上没有在线设备时 30s(activity.StateFlushEvery)
			for {
				tk := time.NewTimer(activity.StateFlushEvery(actReader.Get()))
				select {
				case <-attemptCtx.Done():
					tk.Stop()
					return
				case <-tk.C:
					s := local.Stats()
					sw.UpdateStats(output.Stats{
						Packets:        s.Packets,
						KernelDrops:    s.KernelDrops,
						DNSEvents:      s.DNSEvents,
						TLSEvents:      s.TLSEvents,
						FlowEvents:     s.FlowEvents,
						IgnoredPackets: s.IgnoredPackets,
						ParseErrors:    s.ParseErrors,
						IPAppMapSize:   sw.IPAppMapSize(),
						HTTPEvents:     s.HTTPEvents,
					})
					if err := sw.Flush(); err != nil {
						log.Printf("WARN: flush state: %v", err)
					}
				}
			}
		}(h)

		attemptWG.Add(1)
		go func(local captureRunner) {
			defer attemptWG.Done()
			tk := time.NewTicker(15 * time.Second)
			defer tk.Stop()
			var lastPkts, lastEv uint64
			var lastLog time.Time
			for {
				select {
				case <-attemptCtx.Done():
					return
				case <-tk.C:
					s := local.Stats()
					ev := s.DNSEvents + s.TLSEvents + s.FlowEvents + s.DevHintEvents + s.HTTPEvents
					if s.Packets == lastPkts && ev == lastEv && time.Since(lastLog) < 5*time.Minute {
						continue
					}
					lastPkts, lastEv, lastLog = s.Packets, ev, time.Now()
					log.Printf("stats: pkts=%d drops=%d dns=%d tls=%d flow=%d devhint=%d ignored=%d perr=%d quic_init=%d quic_ok=%d quic_fail=%d quic_sni=%d gquic_sni=%d gquic_skip=%d http=%d leaks=%d lg_drop=%d tls_partial=%d tls_pending=%d tls_reasm=%d tls_giveup=%d ipnames=%d",
						s.Packets, s.KernelDrops, s.DNSEvents, s.TLSEvents, s.FlowEvents, s.DevHintEvents, s.IgnoredPackets, s.ParseErrors,
						s.QUICInitial, s.QUICDecryptOK, s.QUICDecryptFail, s.QUICSNI, s.GQUICSNI, s.GQUICSkipped,
						s.HTTPEvents, leakEngine.TotalLeaks(), leakEngine.DroppedCount(),
						s.TLSPartial, s.TLSPending, s.TLSReassembled, s.TLSGaveUp, ipNames.Len())
				}
			}
		}(h)

		// BUG-003: 5s health watchdog.
		attemptWG.Add(1)
		go func(local captureRunner) {
			defer attemptWG.Done()
			tk := time.NewTicker(5 * time.Second)
			defer tk.Stop()
			var (
				lastPkts       uint64
				lastProgressAt = time.Now()
			)
			lastPkts = local.Stats().Packets
			for {
				select {
				case <-attemptCtx.Done():
					return
				case <-tk.C:
					s := local.Stats()
					if s.Packets != lastPkts {
						lastPkts = s.Packets
						lastProgressAt = time.Now()
						sw.SetHealth("ok", 0)
					} else {
						stall := int64(time.Since(lastProgressAt).Seconds())
						if stall >= 180 {
							sw.SetHealth("degraded", stall)
						} else {
							sw.SetHealth("ok", 0)
						}
					}
				}
			}
		}(h)

		// rc29 + v6.1.0: orthogonal conntrack telemetry (hotspotFlows vs hostFlows), refreshed every 15s.
		attemptWG.Add(1)
		go func() {
			defer attemptWG.Done()
			scanConntrackOrthogonal(cfg, sw, ipNames, shmTracker)
			for {
				t := time.NewTimer(activity.ConntrackEvery(actReader.Get()))
				select {
				case <-attemptCtx.Done():
					t.Stop()
					return
				case <-t.C:
					scanConntrackOrthogonal(cfg, sw, ipNames, shmTracker)
				}
			}
		}()

		err = h.Run(attemptCtx, func(ev capture.Event) {
			clientMAC := ev.ClientMAC.String()
			clientIP := ev.ClientIP.String()
			remoteIP := ev.RemoteIP.String()
			nowUnix := ev.Time.Unix()

			if clientMAC != "" && ev.Kind != capture.EventDevHint {
				leakEngine.RegisterKnownMAC(clientMAC)
			}

			switch ev.Kind {
			case capture.EventDNS:
				sw.RecordDNS(clientMAC, clientIP, remoteIP, ev.DNS.QName, ev.Time)
				shmTracker.observePacket(clientMAC, clientIP, remoteIP, ev.IsUDP, 53, ev.Bytes, !ev.DNS.IsResponse, nowUnix)
				if ev.DNS.IsResponse && len(ev.DNS.Records) > 0 {
					ipNames.RecordDNSAnswers(ev.DNS.QName, ev.DNS.Records, ev.Time)
					output.RecordDNSChainForInfra(ev.DNS.QName, ev.DNS.Records, nil, nowUnix)
					sw.RecordDNSAnswersMeta(clientMAC, ev.DNS.QName, ev.DNS.Records, ev.Time)
				}
			case capture.EventTLSClientHello:
				effSNI := ev.TLS.SNI
				if recQName := sw.ObserveHandshakeSideChannel(clientMAC, clientIP, remoteIP, ev.TLS.SNI, ev.TLS.IsQUIC, ev.DSCP, ev.DstPort, ev.Time); recQName != "" {
					effSNI = recQName
				}
				sw.RecordTLS(clientMAC, clientIP, remoteIP, effSNI, ev.TLS.JA4, ev.Time, ev.TLS.QTP)
				shmTracker.observePacket(clientMAC, clientIP, remoteIP, ev.IsUDP, ev.DstPort, ev.Bytes, true, nowUnix)
				recordFlowFP(ev, clientMAC, clientIP, remoteIP) // v6.x DPI v2
				if effSNI != "" {
					ipNames.RecordConnName(remoteIP, effSNI, output.IPNameSrcSNI, ev.Time)
				}
			case capture.EventHTTP:
				// v5.18: 域名 Host 头同步归因与反查表; v6.0.0: 全量前 4096B 明文请求非阻塞投递 LeakGuard。
				if ev.TLS.SNI != "" {
					sw.RecordTLS(clientMAC, clientIP, remoteIP, ev.TLS.SNI, "", ev.Time)
					ipNames.RecordConnName(remoteIP, ev.TLS.SNI, output.IPNameSrcHTTP, ev.Time)
				}
				shmTracker.observePacket(clientMAC, clientIP, remoteIP, false, ev.DstPort, ev.Bytes, true, nowUnix)
				if ev.HTTP != nil {
					dstHost := ev.HTTP.Host
					if dstHost == "" {
						if e, ok := ipNames.Lookup(remoteIP, ev.Time); ok && e.Name != "" {
							dstHost = e.Name
						}
					}
					if dstHost == "" {
						dstHost = ev.HTTP.RawHost
					}
					if dstHost == "" {
						dstHost = remoteIP
					}
					leakEngine.Submit(leakguard.PacketInput{
						Time:       ev.Time,
						ClientMAC:  clientMAC,
						ClientIP:   clientIP,
						DstIP:      remoteIP,
						SrcPort:    ev.SrcPort,
						DstPort:    ev.DstPort,
						Method:     ev.HTTP.Method,
						Path:       ev.HTTP.Path,
						DstHost:    dstHost,
						UserAgent:  ev.HTTP.UserAgent,
						RawPayload: ev.HTTP.RawPayload,
					})
				}
			case capture.EventDevHint:
				if ev.Dev != nil {
					leakEngine.RegisterKnownMAC(ev.Dev.MAC)
					devID.ObserveHint(toDeviceHint(ev.Dev), ev.Time)
				}
			case capture.EventFlow:
				port := ev.DstPort
				txFromClient := ev.SrcIP.Equal(ev.ClientIP)
				if !txFromClient {
					port = ev.SrcPort
				}
				sw.RecordFlow(clientMAC, clientIP, remoteIP, ev.IsUDP, port, uint64(ev.Bytes), txFromClient, ev.Time)
				sw.ObserveFlowSideChannel(clientMAC, clientIP, remoteIP, ev.IsUDP, ev.IsIPv6, ev.SrcPort, ev.DstPort, uint64(ev.Bytes), txFromClient, ev.DSCP, ev.TCPFlags, ev.UDPSig, ev.Time)
				shmTracker.observePacket(clientMAC, clientIP, remoteIP, ev.IsUDP, port, ev.Bytes, txFromClient, nowUnix)
			}

			if !debug {
				return
			}
			if debugBudget.Add(-1) < 0 {
				return
			}
			switch ev.Kind {
			case capture.EventDNS:
				log.Printf("DNS client=%s/%s remote=%s qname=%q qtype=%d resp=%v ttl=%d answers=%d",
					ev.ClientMAC, ev.ClientIP, ev.RemoteIP, ev.DNS.QName, ev.DNS.QType, ev.DNS.IsResponse, ev.DNS.TTL, len(ev.DNS.Answers))
			case capture.EventTLSClientHello:
				log.Printf("TLS-CH client=%s/%s remote=%s sni=%q alpn=%v ja4=%s quic=%v ech=%v partial=%v reasm=%v",
					ev.ClientMAC, ev.ClientIP, ev.RemoteIP, ev.TLS.SNI, ev.TLS.ALPN, ev.TLS.JA4, ev.TLS.IsQUIC, ev.TLS.ECH, ev.TLS.Partial, ev.TLS.Reassembled)
			case capture.EventHTTP:
				log.Printf("HTTP client=%s/%s remote=%s:%d host=%q ua=%q",
					ev.ClientMAC, ev.ClientIP, ev.RemoteIP, ev.DstPort, ev.TLS.SNI, ev.TLS.UserAgent)
			case capture.EventDevHint:
				if ev.Dev != nil {
					log.Printf("DEVHINT mac=%s src=%s host=%q vc=%q fp=%q model=%q ua=%q svc=%v",
						ev.Dev.MAC, ev.Dev.Source, ev.Dev.Hostname, ev.Dev.VendorClass, ev.Dev.ParamList, ev.Dev.Model, ev.Dev.UserAgent, ev.Dev.Services)
				}
			case capture.EventFlow:
				log.Printf("FLOW client=%s/%s remote=%s udp=%v sport=%d dport=%d bytes=%d v6=%v",
					ev.ClientMAC, ev.ClientIP, ev.RemoteIP, ev.IsUDP, ev.SrcPort, ev.DstPort, ev.Bytes, ev.IsIPv6)
			}
		})
		attemptCancel()
		rebindCancel()
		rebindWG.Wait()
		attemptWG.Wait()
		h.Close()
		if err == nil {
			return nil
		}
		if errors.Is(err, capture.ErrRebound) {
			iface = h.Iface()
			refreshHotspotContext(iface)
			log.Printf("capture rebound to %s, retrying (attempt=%d)", iface, attempt+1)
			if cont, _ := sleepOrWake(ctx, 100*time.Millisecond, wakeCaptureCh); !cont {
				return nil
			}
			continue
		}
		if isRecoverableCaptureError(err) {
			reason := "interface down/rebind retry: " + err.Error()
			log.Printf("WARN: %s", reason)
			sw.SetMode(string(ModeBlind), reason, iface, pr.TLSReassembly, pr.OffloadHint, pr.IPv6Capture)
			_ = sw.Flush()
			clearCrashFlag(cfg.RunDir)
			retry = activity.CaptureRetryBackoff(retry, actReader.Get())
			cont, woken := sleepOrWake(ctx, retry, wakeCaptureCh)
			if !cont {
				return nil
			}
			if woken {
				if isHotspotActiveOrUnknown(cfg.RunDir) {
					retry = 0
				}
			}
			continue
		}
		return err
	}
}

func isRecoverableCaptureError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENETDOWN) ||
		errors.Is(err, syscall.ENODEV) ||
		errors.Is(err, syscall.ENETRESET) ||
		errors.Is(err, syscall.ENXIO) {
		return true
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such network interface") ||
		strings.Contains(msg, "no such device") ||
		strings.Contains(msg, "network is down") ||
		strings.Contains(msg, "network is unreachable")
}

func sleepOrDone(ctx context.Context, d time.Duration) bool {
	cont, _ := sleepOrWake(ctx, d, nil)
	return cont
}

func sleepOrWake(ctx context.Context, d time.Duration, wakeCh <-chan struct{}) (cont bool, woken bool) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false, false
	case <-wakeCh:
		return true, true
	case <-t.C:
		return true, false
	}
}

func selfAttribTickEvery(s activity.Snapshot, explicitEnabled bool) time.Duration {
	if !explicitEnabled && s.OK && !s.Hotspot {
		return 30 * time.Second
	}
	return 5 * time.Second
}

func ipAppMapFlushEvery(s activity.Snapshot) time.Duration {
	if s.OK && !s.Hotspot {
		return 120 * time.Second
	}
	return 30 * time.Second
}

func historySampleEvery(s activity.Snapshot, base time.Duration) time.Duration {
	if base <= 0 {
		base = output.HistorySampleEvery
	}
	if s.OK && !s.Hotspot {
		idle := 300 * time.Second
		if stretched := base * 5; stretched > idle {
			idle = stretched
		}
		if idle > time.Hour {
			idle = time.Hour
		}
		return idle
	}
	return base
}

func idleWithFlush(ctx context.Context, sw *output.Writer, wakeStandbyLoops func()) {
	initSnap := actReader.Get()
	wasOff := initSnap.OK && !initSnap.Hotspot
	for {
		s := actReader.Get()
		off := s.OK && !s.Hotspot
		if wasOff && !off && wakeStandbyLoops != nil {
			wakeStandbyLoops()
		}
		wasOff = off
		tk := time.NewTimer(activity.BlindFlushEvery(s))
		select {
		case <-ctx.Done():
			tk.Stop()
			return
		case <-tk.C:
			_ = sw.Flush()
		}
	}
}

func idleUntilSignal(runDir string, sw *output.Writer) {
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)
	tk := time.NewTicker(30 * time.Second)
	defer tk.Stop()
	deadline := time.NewTimer(crashLoopCooldown)
	defer deadline.Stop()
	for {
		select {
		case <-sigCh:
			return
		case <-deadline.C:
			clearCrashFlag(runDir)
			log.Printf("crash-loop cooldown (%s) elapsed; cleared crash flag and exiting for launcher re-evaluation", crashLoopCooldown)
			return
		case <-tk.C:
			_ = sw.Flush()
		}
	}
}

// canCapture reports whether dpid has kernel AF_PACKET capability and capture
// is not explicitly disabled. When true, dpid enters runCapture even if no
// hotspot interface exists yet at cold boot (standby-for-iface), preventing
// permanent startup blindness.
func canCapture(cfg Config, pr probe.Result) bool {
	return !cfg.DisableCapture && pr.AFPacketAvailable
}

func decideMode(cfg Config, pr probe.Result) (Mode, string) {
	if cfg.DisableCapture {
		return ModeDisabled, "disable_capture=true"
	}
	if !pr.AFPacketAvailable {
		return ModeBlind, "AF_PACKET unavailable: " + pr.AFPacketError
	}
	if pr.APIface == "" {
		return ModeBlind, "no hotspot iface detected"
	}
	return ModeOK, ""
}

func initHistoryStorage(runDir string) string {
	cleanRun := filepath.Clean(runDir)
	histDir := filepath.Join(filepath.Dir(cleanRun), "data", "dpi_history")
	output.HistoryDir = histDir
	if err := os.MkdirAll(histDir, 0o755); err != nil {
		log.Printf("WARN: mkdir history_dir %s: %v", histDir, err)
	} else if err := output.MigrateLegacyHistory(cleanRun, histDir); err != nil {
		log.Printf("WARN: migrate legacy history from %s to %s: %v", cleanRun, histDir, err)
	}
	return histDir
}

// isHotspotActiveOrUnknown returns true when hotspot state is unknown or active.
// If actReader returns a cached hotspot-off snapshot (5s cacheTTL), it double-checks
// runDir/activity.json directly so rapid <5s hotspot re-enables are never missed.
func isHotspotActiveOrUnknown(runDir string) bool {
	act := actReader.Get()
	if !act.OK || act.Hotspot {
		return true
	}
	if runDir == "" {
		return false
	}
	b, err := os.ReadFile(filepath.Join(runDir, activity.FileName))
	if err != nil {
		return true
	}
	fresh := activity.Parse(b, time.Now())
	return !fresh.OK || fresh.Hotspot
}

func startHotspotHintInotify(ctx context.Context, runDir string, onWake func()) {
	startHotspotHintInotifyFull(ctx, runDir, onWake, nil, nil)
}

func startHotspotHintInotifyWithShm(ctx context.Context, runDir string, onWake func(), onShmWake func()) {
	startHotspotHintInotifyFull(ctx, runDir, onWake, onShmWake, nil)
}

func startHotspotHintInotifyFull(ctx context.Context, runDir string, onWake func(), onShmWake func(), onSelfWake func()) {
	if runDir == "" || onWake == nil {
		return
	}
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return
	}
	const mask = syscall.IN_MOVED_TO | syscall.IN_CLOSE_WRITE | syscall.IN_CREATE
	if _, err := syscall.InotifyAddWatch(fd, runDir, mask); err != nil {
		_ = syscall.Close(fd)
		return
	}
	f := os.NewFile(uintptr(fd), "dpid-hotspot-inotify")
	go func() {
		done := make(chan struct{})
		defer close(done)
		defer f.Close()
		go func() {
			select {
			case <-ctx.Done():
				_ = f.Close()
			case <-done:
			}
		}()
		var buf [4096]byte
		for {
			n, rerr := f.Read(buf[:])
			if rerr != nil {
				return
			}
			off := 0
			woke := false
			wokeShm := false
			wokeSelf := false
			for off+syscall.SizeofInotifyEvent <= n {
				evMask := binary.LittleEndian.Uint32(buf[off+4 : off+8])
				evLen := binary.LittleEndian.Uint32(buf[off+12 : off+16])
				hdrEnd := off + syscall.SizeofInotifyEvent
				if evLen > uint32(n-hdrEnd) {
					break
				}
				endOff := hdrEnd + int(evLen)
				raw := buf[hdrEnd:endOff]
				end := 0
				for end < len(raw) && raw[end] != 0 {
					end++
				}
				switch string(raw[:end]) {
				case "iface_detect.json", "hotspot_iface":
					woke = true
				case "self_capture.enabled", "self_attrib.enabled":
					wokeSelf = true
				case "activity.json":
					if evMask&(syscall.IN_MOVED_TO|syscall.IN_CLOSE_WRITE) != 0 {
						if actReader != nil {
							actReader.Invalidate()
						}
						if isHotspotActiveOrUnknown(runDir) {
							woke = true
						} else if onShmWake != nil && actReader != nil && !actReader.Get().ShmShouldSleep() {
							wokeShm = true
						}
					}
				}
				off = endOff
			}
			if woke {
				onWake()
			} else {
				if wokeShm && onShmWake != nil {
					onShmWake()
				}
				if wokeSelf && onSelfWake != nil {
					onSelfWake()
				}
			}
		}
	}()
}

func loadConfig(path string) Config {
	cfg := defaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("WARN: read config %s: %v", path, err)
		}
		return cfg
	}
	var raw Config
	if err := json.Unmarshal(b, &raw); err != nil {
		log.Printf("WARN: parse config %s: %v (using defaults)", path, err)
		return cfg
	}
	if raw.Iface != "" {
		cfg.Iface = raw.Iface
	}
	if raw.Snaplen > 0 {
		cfg.Snaplen = raw.Snaplen
	}
	if raw.RcvBufBytes > 0 {
		cfg.RcvBufBytes = raw.RcvBufBytes
	}
	if raw.LogLevel != "" {
		cfg.LogLevel = raw.LogLevel
	}
	if raw.RunDir != "" {
		cfg.RunDir = raw.RunDir
	}
	if raw.DisableCapture {
		cfg.DisableCapture = true
	}
	return cfg
}

func acquireLock(path string) (int, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC, 0o644)
	if err != nil {
		return -1, fmt.Errorf("open %s: %w", path, err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = syscall.Close(fd)
		if err == syscall.EWOULDBLOCK {
			return -1, fmt.Errorf("another hnc_dpid is running (%s held)", path)
		}
		return -1, fmt.Errorf("flock %s: %w", path, err)
	}
	return fd, nil
}

func releaseLock(fd int) {
	if fd >= 0 {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = syscall.Close(fd)
	}
}

var dpidAtomicSeq atomic.Uint64

func atomicWriteBytes(path string, data []byte) error {
	tmp := fmt.Sprintf("%s.tmp.%d.%d", path, os.Getpid(), dpidAtomicSeq.Add(1))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
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
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func atomicWriteString(path, data string) error {
	return atomicWriteBytes(path, []byte(data))
}

func isAllDigits8(s string) bool {
	if len(s) != 8 {
		return false
	}
	for i := 0; i < 8; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isDpidOwnedTmpName(name string) bool {
	if !strings.Contains(name, ".tmp") {
		return false
	}
	for _, p := range []string{
		"dpid.", "dpi_", "self_attrib.", "label_samples.",
		"apk_domains.json", "app_labels_live.json", "ip_app_map.json", "shm_vector.bin",
	} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func readTailCompleteLines(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	sz := fi.Size()
	if sz <= 0 || maxBytes <= 0 {
		return nil, nil
	}
	var raw []byte
	if sz <= maxBytes {
		raw, err = io.ReadAll(f)
		if err != nil {
			return nil, err
		}
	} else {
		if _, err := f.Seek(sz-maxBytes, io.SeekStart); err != nil {
			return nil, err
		}
		buf := make([]byte, maxBytes)
		n, rerr := io.ReadFull(f, buf)
		if rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) && !errors.Is(rerr, io.EOF) {
			return nil, rerr
		}
		raw = buf[:n]
		if idx := bytes.IndexByte(raw, '\n'); idx >= 0 {
			raw = raw[idx+1:]
		} else {
			return nil, nil
		}
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		raw = append(raw, '\n')
	}
	return raw, nil
}

func migrateCappedJSONL(srcPath, dstPath string, maxBytes int64) error {
	srcTail, err := readTailCompleteLines(srcPath, maxBytes)
	if err != nil {
		return err
	}
	if len(srcTail) == 0 {
		return nil
	}
	merged := srcTail
	if int64(len(srcTail)) < maxBytes {
		if dstFi, err := os.Stat(dstPath); err == nil && dstFi.Size() > 0 {
			rem := maxBytes - int64(len(srcTail))
			if dstTail, derr := readTailCompleteLines(dstPath, rem); derr == nil && len(dstTail) > 0 {
				merged = make([]byte, 0, len(dstTail)+len(srcTail))
				merged = append(merged, dstTail...)
				merged = append(merged, srcTail...)
			}
		}
	}
	return atomicWriteBytes(dstPath, merged)
}

func migrateFileCrossFS(srcPath, dstPath string, maxBytes int64) error {
	srcFi, err := os.Stat(srcPath)
	if err != nil {
		return err
	}
	if srcFi.Size() > maxBytes {
		return fmt.Errorf("source %s size %d exceeds limit %d", srcPath, srcFi.Size(), maxBytes)
	}
	if dstFi, err := os.Stat(dstPath); err == nil && dstFi.Size() > 0 && !srcFi.ModTime().After(dstFi.ModTime()) {
		return nil
	}
	b, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	return atomicWriteBytes(dstPath, b)
}

// rescueTmpfsRunDir performs EXDEV-safe cross-filesystem cleanup & migration of 32MB tmpfs run/
// strictly BEFORE dpid writes run/dpid.pid:
//   - deletes stale/dpid-owned *.tmp* files in run/
//   - migrates self_attrib.<YYYYMMDD>.jsonl (excluding control flags like self_attrib.enabled)
//     and label_samples.* to <hnc>/data/self_studio/ with 4MiB cap and 3d/7d retention
//   - migrates apk_domains.json and app_labels_live.json to <hnc>/data/
//   - immediately deletes migrated/expired files from run/ to release tmpfs space.
func rescueTmpfsRunDir(runDir, dataDir string) {
	cleanRun := strings.TrimSpace(runDir)
	if cleanRun == "" {
		return
	}
	cleanRun = filepath.Clean(cleanRun)
	hncRoot := filepath.Dir(cleanRun)
	cleanData := strings.TrimSpace(dataDir)
	if cleanData == "" {
		cleanData = filepath.Join(hncRoot, "data")
	} else {
		cleanData = filepath.Clean(cleanData)
	}
	studioDir := output.SelfStudioDir(hncRoot)

	_ = os.MkdirAll(cleanData, 0o755)
	_ = os.MkdirAll(studioDir, 0o755)

	entries, err := os.ReadDir(cleanRun)
	if err != nil {
		return
	}

	now := time.Now()
	clockSane := now.Year() >= 2024
	selfAttribCutoff := now.AddDate(0, 0, -output.SelfAttribRetainDays).Format("20060102")
	labelSamplesCutoff := now.AddDate(0, 0, -output.SelfStudioLabelRetentionDays).Format("20060102")
	const labelSamplesCapBytes = 4 << 20

	var freedBytes int64
	var cleanedCount int

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		srcPath := filepath.Join(cleanRun, name)

		// 1. Purge dpid-owned or stale (>60s) .tmp orphan files.
		if strings.Contains(name, ".tmp") {
			shouldRemove := isDpidOwnedTmpName(name)
			var sz int64
			if info, ierr := e.Info(); ierr == nil {
				sz = info.Size()
				if !shouldRemove && now.Sub(info.ModTime()) > time.Minute {
					shouldRemove = true
				}
			}
			if shouldRemove {
				if os.Remove(srcPath) == nil {
					freedBytes += sz
					cleanedCount++
				}
			}
			continue
		}

		// 2. Migrate self_attrib.<YYYYMMDD>.jsonl (NEVER touch self_attrib.enabled!).
		if strings.HasPrefix(name, "self_attrib.") && strings.HasSuffix(name, ".jsonl") {
			var sz int64
			if info, ierr := e.Info(); ierr == nil {
				sz = info.Size()
			}
			ymd := strings.TrimSuffix(strings.TrimPrefix(name, "self_attrib."), ".jsonl")
			if clockSane && isAllDigits8(ymd) && ymd < selfAttribCutoff {
				if os.Remove(srcPath) == nil {
					freedBytes += sz
					cleanedCount++
				}
				continue
			}
			if err := migrateCappedJSONL(srcPath, filepath.Join(studioDir, name), output.SelfAttribMaxDailyBytes); err != nil {
				log.Printf("WARN: tmpfs rescue migrate %s: %v", name, err)
			}
			if os.Remove(srcPath) == nil {
				freedBytes += sz
				cleanedCount++
			}
			continue
		}

		// 3. Migrate label_samples.* (.jsonl, .capped, label_samples.stats.json).
		if name == "label_samples.stats.json" {
			var sz int64
			if info, ierr := e.Info(); ierr == nil {
				sz = info.Size()
			}
			if err := migrateFileCrossFS(srcPath, filepath.Join(studioDir, name), labelSamplesCapBytes); err != nil {
				log.Printf("WARN: tmpfs rescue migrate %s: %v", name, err)
			}
			if os.Remove(srcPath) == nil {
				freedBytes += sz
				cleanedCount++
			}
			continue
		}
		if strings.HasPrefix(name, "label_samples.") && strings.HasSuffix(name, ".jsonl") {
			var sz int64
			if info, ierr := e.Info(); ierr == nil {
				sz = info.Size()
			}
			ymd := strings.TrimSuffix(strings.TrimPrefix(name, "label_samples."), ".jsonl")
			if clockSane && isAllDigits8(ymd) && ymd < labelSamplesCutoff {
				if os.Remove(srcPath) == nil {
					freedBytes += sz
					cleanedCount++
				}
				continue
			}
			if err := migrateCappedJSONL(srcPath, filepath.Join(studioDir, name), labelSamplesCapBytes); err != nil {
				log.Printf("WARN: tmpfs rescue migrate %s: %v", name, err)
			}
			if os.Remove(srcPath) == nil {
				freedBytes += sz
				cleanedCount++
			}
			continue
		}
		if strings.HasPrefix(name, "label_samples.") && strings.HasSuffix(name, ".capped") {
			var sz int64
			if info, ierr := e.Info(); ierr == nil {
				sz = info.Size()
			}
			ymd := strings.TrimSuffix(strings.TrimPrefix(name, "label_samples."), ".capped")
			if clockSane && isAllDigits8(ymd) && ymd < labelSamplesCutoff {
				if os.Remove(srcPath) == nil {
					freedBytes += sz
					cleanedCount++
				}
				continue
			}
			if err := migrateFileCrossFS(srcPath, filepath.Join(studioDir, name), labelSamplesCapBytes); err != nil {
				log.Printf("WARN: tmpfs rescue migrate %s: %v", name, err)
			}
			if os.Remove(srcPath) == nil {
				freedBytes += sz
				cleanedCount++
			}
			continue
		}

		// 4. Migrate apk_domains.json and app_labels_live.json from run/ to data/.
		if name == apkDomainsFile || name == "app_labels_live.json" {
			var sz int64
			if info, ierr := e.Info(); ierr == nil {
				sz = info.Size()
			}
			if err := migrateFileCrossFS(srcPath, filepath.Join(cleanData, name), 16<<20); err != nil {
				log.Printf("WARN: tmpfs rescue migrate %s: %v", name, err)
			}
			if os.Remove(srcPath) == nil {
				freedBytes += sz
				cleanedCount++
			}
			continue
		}
	}

	if cleanedCount > 0 {
		log.Printf("tmpfs-rescue: migrated/cleaned %d legacy file(s) from %s, freed %d bytes", cleanedCount, cleanRun, freedBytes)
	}
}

func armCrashFlag(runDir string) {
	path := filepath.Join(runDir, crashFlagFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("WARN: arm crash flag: %v", err)
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%d\n", time.Now().Unix())
	_ = f.Sync()
}

func clearCrashFlag(runDir string) {
	_ = os.Remove(filepath.Join(runDir, crashFlagFile))
}

func bumpStartCount(runDir string) {
	path := filepath.Join(runDir, "dpid.start_count")
	n := int64(0)
	if b, err := os.ReadFile(path); err == nil {
		if v, perr := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); perr == nil {
			n = v
		}
	}
	_ = atomicWriteString(path, strconv.FormatInt(n+1, 10))
}

func checkCrashLoop(runDir string) string {
	path := filepath.Join(runDir, crashFlagFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	cutoff := time.Now().Add(-maxCrashesWindow).Unix()
	recent := 0
	start := 0
	for i := 0; i <= len(b); i++ {
		if i == len(b) || b[i] == '\n' {
			if i > start {
				if ts, err := strconv.ParseInt(string(b[start:i]), 10, 64); err == nil && ts >= cutoff {
					recent++
				}
			}
			start = i + 1
		}
	}
	if recent >= maxCrashesAllowed {
		return fmt.Sprintf("crash loop: %d starts in last %s", recent, maxCrashesWindow)
	}
	return ""
}

func runByteSampler(ctx context.Context, agg *output.SelfAttribAggregator, enabled func() bool) {
	sampler := bytestats.Detect()
	defer sampler.Close()

	src := sampler.Source()
	if src == "none" {
		log.Printf("byteSampler: no backend available, byte stats permanently disabled")
		return
	}

	if enabled() {
		doByteSample(sampler, agg, src)
	}

	for {
		d := activity.ByteSampleEvery(actReader.Get(), enabled())
		if d == 0 {
			d = time.Minute
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			log.Printf("byteSampler: shutdown (source=%s)", src)
			return
		case <-t.C:
			if enabled() {
				doByteSample(sampler, agg, src)
			}
		}
	}
}

func doByteSample(sampler bytestats.ByteSampler, agg *output.SelfAttribAggregator, src string) {
	raw, err := sampler.Sample()
	if err != nil {
		log.Printf("byteSampler: sample failed (source=%s): %v", src, err)
		return
	}
	out := make(map[int]output.ByteSample, len(raw))
	for uid, bc := range raw {
		out[uid] = output.ByteSample{RxBytes: bc.RxBytes, TxBytes: bc.TxBytes}
	}
	agg.RecordBytes(out, src, time.Now().Unix())
}

func isIfaceAliveUp(name string) bool {
	if name == "" {
		return false
	}
	ifc, err := ifaceByNameFn(name)
	return err == nil && ifc != nil && ifc.Flags&net.FlagUp != 0
}

func resolveCurrentIface(cfg Config) string {
	// 1. Fresh iface_detect.json (within 10m) takes top priority so band-switching
	// (e.g. wlan2 -> ap0) never gets stuck on a stale cfg.Iface from dpi_config.json.
	if s, ok := ifacehint.ReadDetect(cfg.RunDir, time.Now(), ifacehint.FreshWindow); ok {
		return s
	}
	// 2. Fallback hotspot_iface via ifacehint.Read unless cfg.Iface explicitly
	// names a live UP interface while the fallback hint does not.
	if s, ok := ifacehint.Read(cfg.RunDir, time.Now()); ok {
		if cfg.Iface == "" || isIfaceAliveUp(s) || !isIfaceAliveUp(cfg.Iface) {
			return s
		}
	}
	// 3. Explicit cfg.Iface if alive, otherwise self-heal via live AP discovery.
	if cfg.Iface != "" {
		if isIfaceAliveUp(cfg.Iface) {
			return cfg.Iface
		}
		if cands, _ := discoverAPFn(); len(cands) > 0 {
			return cands[0].Name
		}
		return cfg.Iface
	}
	// 4. Auto-discovery fallback.
	if cands, _ := discoverAPFn(); len(cands) > 0 {
		return cands[0].Name
	}
	return ""
}

func readIfaceRxBytes(iface string) uint64 {
	data, err := os.ReadFile("/sys/class/net/" + iface + "/statistics/rx_bytes")
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return n
}

func rebindCheckLoop(ctx context.Context, h captureRunner, cfg Config, pr probe.Result, sw *output.Writer, rebindCount *atomic.Int64) {
	tickDur := rebindCheckTickEvery
	if tickDur <= 0 {
		tickDur = 15 * time.Second
	}
	ticker := time.NewTicker(tickDur)
	defer ticker.Stop()

	var (
		zeroPktStart time.Time
		lastRxBytes  uint64
		lastNetsSig  string
	)
	lastRxBytes = readIfaceRxBytes(h.Iface())
	lastNetsSig = netsSignature(ifaceNetsFn(h.Iface()))

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentIface := resolveCurrentIface(cfg)
			if currentIface == "" {
				continue
			}

			handleIface := h.Iface()
			handleIfindex := h.CurrentIfindex()

			ifc, err := ifaceByNameFn(currentIface)
			if err != nil || ifc == nil {
				continue
			}

			needRebind := false
			reason := ""

			if currentIface != handleIface {
				needRebind = true
				reason = fmt.Sprintf("iface name changed: %s -> %s", handleIface, currentIface)
			}

			if !needRebind && ifc.Index != handleIfindex {
				needRebind = true
				reason = fmt.Sprintf("ifindex changed on %s: %d -> %d", currentIface, handleIfindex, ifc.Index)
			}

			if !needRebind {
				s := h.Stats()
				rxBytes := readIfaceRxBytes(currentIface)
				if s.Packets == 0 {
					if zeroPktStart.IsZero() {
						zeroPktStart = time.Now()
					} else if time.Since(zeroPktStart) >= 3*time.Minute && rxBytes > lastRxBytes {
						needRebind = true
						reason = fmt.Sprintf("zero DPI packets for 3m but %s rx_bytes growing (%d -> %d)",
							currentIface, lastRxBytes, rxBytes)
					}
				} else {
					zeroPktStart = time.Time{}
				}
				lastRxBytes = rxBytes
			}

			if needRebind {
				log.Printf("REBIND: %s", reason)
				if err := rebindHandleFn(h, currentIface); err != nil {
					log.Printf("REBIND FAILED: %v", err)
				} else {
					nets := refreshHotspotContext(currentIface)
					lastNetsSig = netsSignature(nets)
					var cnt int
					if rebindCount != nil {
						cnt = int(rebindCount.Add(1))
					}
					sw.SetMode(string(ModeOK), "", currentIface, pr.TLSReassembly, pr.OffloadHint, pr.IPv6Capture)
					sw.SetRebindCount(cnt)
					_ = sw.Flush()
					log.Printf("REBIND OK: now on %s (ifindex=%d, rebind_count=%d)",
						currentIface, ifc.Index, cnt)
				}
				zeroPktStart = time.Time{}
				continue
			}

			// Same interface & ifindex: detect randomized subnet or delayed IPv4/IPv6 assignment.
			curNets := ifaceNetsFn(currentIface)
			if curSig := netsSignature(curNets); curSig != lastNetsSig {
				setLocalMACsFor(currentIface)
				capture.SetHotspotNets(curNets)
				lastNetsSig = curSig
				log.Printf("REBIND-NETS: hotspot subnet updated on %s: %s", currentIface, curSig)
			}
		}
	}
}
