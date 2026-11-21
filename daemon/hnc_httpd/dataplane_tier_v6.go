// dataplane_tier_v6.go — HNC v6.0.0 · Vector (T2 零子进程三级自适应限速引擎):
//
// 核心架构与硬门禁保证:
//  1. 单写者串行执行器 DataplaneActor:
//     - 所有内核 RTNetlink 写操作收敛至唯一常驻写协程复用长连接 AF_NETLINK, 彻底消除跨协程写竞争;
//     - CurrentDataplaneTierStatus() 纯走 atomic.Value + 64 位原子计数器, 零锁阻塞读请求 (< 30ns);
//     - 内置按 (操作域, hncDir, iface, ifindex) 索引的 O(1) 增量摘要对账表, 自动去重无变化的重复下发。
//  2. 三级自适应限速层级与启动期实证探针 ProbeDataplaneTier(hncDir, iface):
//     - tier1_ebpf_edt: 硬件卸载已受控 + clsact BPF 就绪 + sch_fq (或 mq 子队列 fq) 实测可用;
//     - tier2_native_netlink: 长连接 AF_NETLINK 原生维护 HTB 根/设备类/1:10 Vector Express/1:9990 UpdateLeash + fq_codel 叶子;
//     - tier3_atomic_batch: 内存拼装 `tc -force -batch -` + `iptables-restore -w 2 --noflush` 管道兜底 (单次事务严格 <= 3 次子进程)。
//  3. 32 位 ARM 对齐铁律: 所有包含 atomic.Uint64 / atomic.Int64 的结构体一律将 64 位原子字段置于 offset 0;
//     100% 标准库 encoding/binary.LittleEndian, 零 unsafe。

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DataplaneTierEDT           = "tier1_ebpf_edt"
	DataplaneTierNativeNetlink = "tier2_native_netlink"
	DataplaneTierAtomicBatch   = "tier3_atomic_batch"

	dpActorQueueSize     = 128
	dpTier3MaxSubprocs   = 3
	dpTier3BatchTimeout  = 3 * time.Second
	dpDefaultRootRateKbp = 1_000_000 // 1000 Mbit/s = 1,000,000 kbit/s
)

// DataplaneTierStatus 暴露给 /api/vector_sync 与 /api/dataplane_verify 的零阻塞实时层级快照。
type DataplaneTierStatus struct {
	ActiveTier        string `json:"active_tier"`
	SavedForks        uint64 `json:"saved_forks"`
	LastNetlinkUsec   int64  `json:"last_netlink_usec"`
	NetlinkOpsTotal   uint64 `json:"netlink_ops_total"`
	DedupHits         uint64 `json:"dedup_hits"`
	Tier3BatchCommits uint64 `json:"tier3_batch_commits"`
	Fallbacks         uint64 `json:"fallbacks"`
	OffloadControlled bool   `json:"offload_controlled"`
	ClsactBPFReady    bool   `json:"clsact_bpf_ready"`
	SchFQAvailable    bool   `json:"sch_fq_available"`
	RTNetlinkReady    bool   `json:"rtnetlink_ready"`
	ExpressActive     bool   `json:"express_active"`
	ExpressBgCeilKbps int    `json:"express_bg_ceil_kbps"`
	UpdateLeashKbps   int    `json:"update_leash_kbps"`
	GlobalDownKbps    int    `json:"global_down_kbps"`
	GlobalUpKbps      int    `json:"global_up_kbps"`
	ProbedIface       string `json:"probed_iface,omitempty"`
	UpdatedAt         int64  `json:"updated_at"`
}

type dataplaneProbeSnapshot struct {
	tier              string
	iface             string
	offloadControlled bool
	clsactBPFReady    bool
	schFQAvailable    bool
	rtnetlinkReady    bool
}

type v6ShaperDesiredState struct {
	iface    string
	ifidx    int
	ifbIdx   int
	downKbps int
	upKbps   int
}

type v6ExpressDesiredState struct {
	active     bool
	gameMark   uint32
	bgCeilKbps int
}

type v6LeashDesiredState struct {
	active    bool
	leashMark uint32
	rateKbps  int
}

type dataplaneActorJob struct {
	op     string
	fn     func(a *DataplaneActor) error
	respCh chan error
}

// DataplaneActor 单写者串行数据面执行器。
// 严格遵守 32 位 ARM 对齐铁律: 所有 64 位原子字段严格排在结构体最起始位置 (offset 0..63)。
type DataplaneActor struct {
	savedForks      atomic.Uint64
	nlOpsTotal      atomic.Uint64
	nlFallbacks     atomic.Uint64
	tier3Batches    atomic.Uint64
	dedupHits              atomic.Uint64
	reconcileInvalidations atomic.Uint64
	lastApplyUsec          atomic.Int64
	lastUpdatedUnix        atomic.Int64
	closedFlag             atomic.Int64

	statusSnap atomic.Value // 存放不可变 DataplaneTierStatus 值副本
	reqCh      chan dataplaneActorJob
	stopCh     chan struct{}
	doneCh     chan struct{}
	startOnce  sync.Once
	stopOnce   sync.Once

	// 以下字段仅由唯一常驻 writer 协程读写, 零并发竞争、零读侧锁等待:
	nlFD         int
	probeState   dataplaneProbeSnapshot
	reconcileMap map[string]string
	ifindexMap   map[string]int
	shaperSpec   v6ShaperDesiredState
	expressSpec  v6ExpressDesiredState
	leashSpec    v6LeashDesiredState
}

// dpTierHooks 汇总底层探测与执行钩子, 生产环境直连原生 AF_NETLINK / 批处理管道, 单测可局部替换确定性桩。
type dpTierHooks struct {
	openSocket        func() (int, error)
	closeSocket       func(fd int)
	ifaceIndex        func(iface string) (int, error)
	probeKernel       func(ifindex int) (hasRTNetlink bool, hasClsact bool, hasSchFQ bool)
	tuneShaperOnSock  func(fd int, downIdx int, downBps uint64, ifbIdx int, upBps uint64) (int, error)
	applyBatchOnSock  func(fd int, msgs [][]byte) (int, error)
	runTier3Cmd       func(bin string, args []string, stdin []byte) error
	resolveBin        func(name string) string
	acquireLock       func(hncDir, op string) (func(), error)
	offloadControlled func(hncDir, iface string) bool
	clsactPinnedReady func(hncDir string) bool
	schFQSysReady     func(hncDir string) bool
}

var (
	dpTierHooksMu sync.Mutex
	activeDPHooks = defaultDPTierHooks()

	defaultDPActorOnce sync.Once
	defaultDPActor     *DataplaneActor
)

func defaultDPTierHooks() dpTierHooks {
	return dpTierHooks{
		openSocket:        openRTNetlinkSocket,
		closeSocket:       nlCloseSocket,
		ifaceIndex:        nlIfaceIndexByName,
		probeKernel:       nlProbeKernelCapabilities,
		tuneShaperOnSock:  nlTuneGlobalShaperOnSocket,
		applyBatchOnSock:  nlApplyBatchWithFWFallbackOnSocket,
		runTier3Cmd:       defaultRunTier3PipeCmd,
		resolveBin:        resolveDataplaneSystemBin,
		acquireLock:       acquireNativeDataplaneLock,
		offloadControlled: defaultCheckOffloadControlled,
		clsactPinnedReady: defaultCheckClsactPinnedReady,
		schFQSysReady:     defaultCheckSchFQSysReady,
	}
}

func getDPTierHooks() dpTierHooks {
	dpTierHooksMu.Lock()
	h := activeDPHooks
	dpTierHooksMu.Unlock()
	return h
}

func init() {
	runtime.KeepAlive(&dataplaneRequiredAPIMarkers)
	RegisterVectorSyncProvider("dataplane_tier", func() any {
		return CurrentDataplaneTierStatus()
	})
}

// NewDataplaneActor 创建并启动独立的单写者 DataplaneActor 实例。
func NewDataplaneActor() *DataplaneActor {
	a := &DataplaneActor{
		reqCh:        make(chan dataplaneActorJob, dpActorQueueSize),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
		nlFD:         -1,
		reconcileMap: make(map[string]string, 16),
		ifindexMap:   make(map[string]int, 4),
		probeState: dataplaneProbeSnapshot{
			tier: DataplaneTierNativeNetlink,
		},
	}
	now := time.Now().Unix()
	a.lastUpdatedUnix.Store(now)
	a.statusSnap.Store(DataplaneTierStatus{
		ActiveTier: DataplaneTierNativeNetlink,
		UpdatedAt:  now,
	})
	a.start()
	return a
}

// DefaultDataplaneActor 返回全局单例单写者数据面执行器。
func DefaultDataplaneActor() *DataplaneActor {
	defaultDPActorOnce.Do(func() {
		defaultDPActor = NewDataplaneActor()
	})
	return defaultDPActor
}

func (a *DataplaneActor) start() {
	a.startOnce.Do(func() {
		go a.writerLoop()
	})
}

// Close 优雅停止 DataplaneActor 并回收常驻 AF_NETLINK 描述符。
func (a *DataplaneActor) Close() {
	if a == nil {
		return
	}
	a.stopOnce.Do(func() {
		a.closedFlag.Store(1)
		close(a.stopCh)
		<-a.doneCh
	})
}

func (a *DataplaneActor) writerLoop() {
	defer func() {
		if a.nlFD >= 0 {
			h := getDPTierHooks()
			h.closeSocket(a.nlFD)
			a.nlFD = -1
		}
		close(a.doneCh)
	}()

	for {
		select {
		case <-a.stopCh:
			return
		case job := <-a.reqCh:
			err := a.runGuardedJob(job)
			if job.respCh != nil {
				job.respCh <- err
			}
		}
	}
}

func (a *DataplaneActor) runGuardedJob(job dataplaneActorJob) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("dataplane actor panic in %s: %v", job.op, r)
		}
	}()
	if job.fn == nil {
		return nil
	}
	return job.fn(a)
}

// Do 向单写者协程提交串行任务并等待结果, 保证所有 Netlink 套接字写与增量缓存更新严格单线程顺序执行。
func (a *DataplaneActor) Do(op string, fn func(a *DataplaneActor) error) error {
	if a == nil {
		return errors.New("nil DataplaneActor")
	}
	if a.closedFlag.Load() != 0 {
		return errors.New("dataplane actor closed")
	}
	a.start()
	respCh := make(chan error, 1)
	job := dataplaneActorJob{
		op:     op,
		fn:     fn,
		respCh: respCh,
	}
	select {
	case <-a.stopCh:
		return errors.New("dataplane actor stopped")
	case a.reqCh <- job:
	}
	select {
	case <-a.stopCh:
		return errors.New("dataplane actor stopped while waiting")
	case err := <-respCh:
		return err
	}
}

func (a *DataplaneActor) ensureSocket(h dpTierHooks) (int, error) {
	if a.nlFD >= 0 {
		return a.nlFD, nil
	}
	fd, err := h.openSocket()
	if err != nil {
		return -1, err
	}
	a.nlFD = fd
	return fd, nil
}

func (a *DataplaneActor) resetSocket(h dpTierHooks) {
	if a.nlFD >= 0 {
		h.closeSocket(a.nlFD)
		a.nlFD = -1
	}
	a.invalidateAllReconcileLocked()
}

func (a *DataplaneActor) invalidateAllReconcileLocked() int {
	if a == nil || len(a.reconcileMap) == 0 {
		return 0
	}
	n := len(a.reconcileMap)
	clear(a.reconcileMap)
	a.reconcileInvalidations.Add(uint64(n))
	return n
}

func reconcileKeyMatches(key, hncDir, iface string) bool {
	hncDir = strings.TrimSpace(hncDir)
	iface = strings.TrimSpace(iface)
	if iface == "*" {
		iface = ""
	}
	if hncDir == "" && iface == "" {
		return true
	}
	domain, rest, ok := strings.Cut(key, ":")
	if !ok || domain == "" {
		return false
	}
	keyDir := rest
	keyIface := ""
	if d, tail, hasSep := strings.Cut(rest, ":"); hasSep {
		for {
			nextD, nextTail, more := strings.Cut(tail, ":")
			if !more {
				break
			}
			d += ":" + nextD
			tail = nextTail
		}
		if !strings.ContainsAny(tail, `/\`) {
			keyDir = d
			keyIface = tail
		}
	}
	if hncDir != "" && keyDir != hncDir {
		return false
	}
	if iface == "" {
		return true
	}
	if keyIface == "" || keyIface == iface {
		return true
	}
	if strings.HasPrefix(iface, "ifb") && (domain == "shaper" || domain == "express" || domain == "leash") {
		return true
	}
	return false
}

func (a *DataplaneActor) invalidateReconcileLocked(hncDir, iface string) int {
	if a == nil {
		return 0
	}
	iface = strings.TrimSpace(iface)
	if hncDir == "" && (iface == "" || iface == "*") {
		if a.ifindexMap != nil {
			clear(a.ifindexMap)
		}
		return a.invalidateAllReconcileLocked()
	}
	if a.ifindexMap != nil {
		if iface == "" || iface == "*" {
			clear(a.ifindexMap)
		} else {
			delete(a.ifindexMap, iface)
		}
	}
	removed := 0
	for k := range a.reconcileMap {
		if reconcileKeyMatches(k, hncDir, iface) {
			delete(a.reconcileMap, k)
			removed++
		}
	}
	if removed > 0 {
		a.reconcileInvalidations.Add(uint64(removed))
	}
	return removed
}

func (a *DataplaneActor) trackIfindexLocked(hncDir, iface string, ifindex int) bool {
	if a == nil {
		return false
	}
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return false
	}
	if a.ifindexMap == nil {
		a.ifindexMap = make(map[string]int, 4)
	}
	prev, existed := a.ifindexMap[iface]
	if ifindex <= 0 {
		if existed {
			delete(a.ifindexMap, iface)
			a.invalidateReconcileLocked(hncDir, iface)
			return true
		}
		return false
	}
	a.ifindexMap[iface] = ifindex
	if existed && prev != ifindex {
		a.invalidateReconcileLocked(hncDir, iface)
		a.ifindexMap[iface] = ifindex
		return true
	}
	return false
}

// InvalidateReconcile 清空指定接口(传 "" 或 "*" 清空全部)的内存期望摘要缓存。
func (a *DataplaneActor) InvalidateReconcile(iface string) {
	if a == nil {
		return
	}
	_ = a.Do("invalidate_reconcile", func(act *DataplaneActor) error {
		act.invalidateReconcileLocked("", iface)
		act.publishSnapshotLocked()
		return nil
	})
}

// InvalidateDataplaneReconcileNative 供规则核对或热点重初始化时清空全局 DataplaneActor 去重缓存。
func InvalidateDataplaneReconcileNative(hncDir, iface string) {
	actor := DefaultDataplaneActor()
	if actor == nil {
		return
	}
	_ = actor.Do("invalidate_reconcile", func(a *DataplaneActor) error {
		a.invalidateReconcileLocked(hncDir, iface)
		a.publishSnapshotLocked()
		return nil
	})
}

// runWithPersistentSocket 在常驻 AF_NETLINK 长连接上执行 fn, 遇底层连接陈旧错误时自动重连重试一次。
func (a *DataplaneActor) runWithPersistentSocket(h dpTierHooks, fn func(fd int) error) error {
	fd, err := a.ensureSocket(h)
	if err != nil {
		return err
	}
	t0 := time.Now()
	err = fn(fd)
	if err != nil {
		a.resetSocket(h)
		fd2, err2 := a.ensureSocket(h)
		if err2 != nil {
			return err
		}
		t0 = time.Now()
		if retryErr := fn(fd2); retryErr != nil {
			a.resetSocket(h)
			return retryErr
		}
	}
	usec := time.Since(t0).Microseconds()
	if usec <= 0 {
		usec = 1
	}
	a.lastApplyUsec.Store(usec)
	a.nlOpsTotal.Add(1)
	return nil
}

// publishSnapshotLocked 由 writer 协程内部刷新不可变状态快照 (读侧完全无锁)。
func (a *DataplaneActor) publishSnapshotLocked() {
	now := time.Now().Unix()
	a.lastUpdatedUnix.Store(now)
	tier := a.probeState.tier
	if tier == "" {
		tier = DataplaneTierNativeNetlink
	}
	leashKbps := 0
	if a.leashSpec.active {
		leashKbps = a.leashSpec.rateKbps
	}
	bgCeil := 0
	if a.expressSpec.active {
		bgCeil = a.expressSpec.bgCeilKbps
	}
	snap := DataplaneTierStatus{
		ActiveTier:        tier,
		SavedForks:        a.savedForks.Load(),
		LastNetlinkUsec:   a.lastApplyUsec.Load(),
		NetlinkOpsTotal:   a.nlOpsTotal.Load(),
		DedupHits:         a.dedupHits.Load(),
		Tier3BatchCommits: a.tier3Batches.Load(),
		Fallbacks:         a.nlFallbacks.Load(),
		OffloadControlled: a.probeState.offloadControlled,
		ClsactBPFReady:    a.probeState.clsactBPFReady,
		SchFQAvailable:    a.probeState.schFQAvailable,
		RTNetlinkReady:    a.probeState.rtnetlinkReady,
		ExpressActive:     a.expressSpec.active,
		ExpressBgCeilKbps: bgCeil,
		UpdateLeashKbps:   leashKbps,
		GlobalDownKbps:    a.shaperSpec.downKbps,
		GlobalUpKbps:      a.shaperSpec.upKbps,
		ProbedIface:       a.probeState.iface,
		UpdatedAt:         now,
	}
	a.statusSnap.Store(snap)
}

// CurrentDataplaneTierStatus 无锁读取当前生效 Tier 名称、累计省去的 fork 计数及最近一次 Netlink 下发微秒耗时。
func CurrentDataplaneTierStatus() DataplaneTierStatus {
	return DefaultDataplaneActor().Status()
}

// Status 无锁读取指定 DataplaneActor 的最新层级与性能指标。
func (a *DataplaneActor) Status() DataplaneTierStatus {
	if a == nil {
		return DataplaneTierStatus{ActiveTier: DataplaneTierNativeNetlink}
	}
	var st DataplaneTierStatus
	if raw := a.statusSnap.Load(); raw != nil {
		if cur, ok := raw.(DataplaneTierStatus); ok {
			st = cur
		}
	}
	if st.ActiveTier == "" {
		st.ActiveTier = DataplaneTierNativeNetlink
	}
	st.SavedForks = a.savedForks.Load()
	st.LastNetlinkUsec = a.lastApplyUsec.Load()
	st.NetlinkOpsTotal = a.nlOpsTotal.Load()
	st.DedupHits = a.dedupHits.Load()
	st.Tier3BatchCommits = a.tier3Batches.Load()
	st.Fallbacks = a.nlFallbacks.Load()
	if u := a.lastUpdatedUnix.Load(); u > 0 {
		st.UpdatedAt = u
	}
	return st
}

// ── 启动期实证探针 ProbeDataplaneTier ────────────────────────────────────────

// ProbeDataplaneTier 实测探测当前设备内核与硬件卸载受控状态, 选定最优限速层级:
//   - tier1_ebpf_edt: 硬件卸载已受控 + clsact BPF 生效 + sch_fq (或 mq 子队列 fq) 可用;
//   - tier2_native_netlink: AF_NETLINK RTNetlink 原生 HTB + fq_codel 可用;
//   - tier3_atomic_batch: 回退内存 `tc -force -batch -` + `iptables-restore -w 2 --noflush` 批处理管道。
func ProbeDataplaneTier(hncDir, iface string) string {
	return probeDataplaneTierOnActor(DefaultDataplaneActor(), hncDir, iface)
}

func probeDataplaneTierOnActor(actor *DataplaneActor, hncDir, iface string) string {
	hncDir = strings.TrimSpace(hncDir)
	iface = strings.TrimSpace(iface)
	if iface == "" && hncDir != "" {
		iface = readHotspotIfaceName(hncDir)
	}
	h := getDPTierHooks()

	ifidx := 0
	if iface != "" {
		if idx, err := h.ifaceIndex(iface); err == nil && idx > 0 {
			ifidx = idx
		}
	}
	hasRTNL, qdiscHasClsact, qdiscHasFQ := h.probeKernel(ifidx)
	offloadOK := h.offloadControlled(hncDir, iface)
	clsactOK := qdiscHasClsact || h.clsactPinnedReady(hncDir)
	schFQOK := qdiscHasFQ || h.schFQSysReady(hncDir)

	selected := DataplaneTierAtomicBatch
	switch {
	case hasRTNL && offloadOK && clsactOK && schFQOK:
		selected = DataplaneTierEDT
	case hasRTNL:
		selected = DataplaneTierNativeNetlink
	default:
		selected = DataplaneTierAtomicBatch
	}

	_ = actor.Do("probe_tier", func(a *DataplaneActor) error {
		a.probeState = dataplaneProbeSnapshot{
			tier:              selected,
			iface:             iface,
			offloadControlled: offloadOK,
			clsactBPFReady:    clsactOK,
			schFQAvailable:    schFQOK,
			rtnetlinkReady:    hasRTNL,
		}
		a.publishSnapshotLocked()
		return nil
	})

	if hncDir != "" && useNativeDataplane(hncDir) {
		st := actor.Status()
		if b, err := json.Marshal(st); err == nil {
			runDir := filepath.Join(hncDir, "run")
			_ = os.MkdirAll(runDir, 0o755)
			_ = discoverWriteAtomic(filepath.Join(runDir, "dataplane_tier.json"), append(b, '\n'))
		}
	}
	return selected
}

func defaultCheckOffloadControlled(hncDir, _ string) bool {
	if hncDir != "" {
		for _, rel := range []string{"run/offload_guard.state", "run/offload_slowpath.active"} {
			if b, err := os.ReadFile(filepath.Join(hncDir, rel)); err == nil {
				s := strings.ToLower(strings.TrimSpace(string(b)))
				if s != "" && !strings.Contains(s, "bypass_uncontrolled") && s != "0" && s != "false" {
					return true
				}
			}
		}
		if b, err := os.ReadFile(filepath.Join(hncDir, "run", "qdisc_caps.json")); err == nil && len(b) > 0 {
			var m map[string]any
			if json.Unmarshal(b, &m) == nil {
				if v, ok := m["offload_controlled"].(bool); ok && v {
					return true
				}
			}
		}
	}
	// Android Tethering BPF 卸载上限 map 存在或软件转发路径未被硬件独占时判定可受控
	if _, err := os.Stat(dpBPFTetherLimitPath); err == nil {
		return true
	}
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil && strings.TrimSpace(string(b)) == "1" {
		if _, hErr := os.Stat("/proc/mtketh"); hErr != nil {
			return true
		}
	}
	return false
}

func defaultCheckClsactPinnedReady(hncDir string) bool {
	if nativeBPFDirPath != "" {
		for _, name := range []string{"mac_mark_map", "ip_mark_map", "dev_stats_map"} {
			if _, err := os.Stat(filepath.Join(nativeBPFDirPath, name)); err == nil {
				return true
			}
		}
	}
	if hncDir != "" {
		if b, err := os.ReadFile(filepath.Join(hncDir, "run", "clsact.state")); err == nil {
			s := strings.ToLower(strings.TrimSpace(string(b)))
			if strings.Contains(s, "attached") || strings.Contains(s, "active") || s == "1" {
				return true
			}
		}
	}
	return false
}

func defaultCheckSchFQSysReady(hncDir string) bool {
	if _, err := os.Stat("/sys/module/sch_fq"); err == nil {
		return true
	}
	if hncDir != "" {
		if b, err := os.ReadFile(filepath.Join(hncDir, "run", "qdisc_caps.json")); err == nil && len(b) > 0 {
			s := strings.ToLower(string(b))
			if strings.Contains(s, `"sch_fq":true`) || strings.Contains(s, `"sch_fq": true`) || strings.Contains(s, `"fq":true`) {
				return true
			}
		}
	}
	return false
}

// ── 导出接口 1: TuneGlobalShaperNative (零子进程 Autorate 热调速) ─────────────

// TuneGlobalShaperNative 通过长连接 AF_NETLINK RTM_NEWTCLASS 原地更新下行热点口与 ifb0 的根类 1:1 带宽 (< 0.2ms, 0 子进程)。
// 当处于单测假脚本环境 (!useNativeDataplane) 时立即返回错误, 由调用方无缝回退 runBin("tc_manager.sh", ...)。
func TuneGlobalShaperNative(hncDir string, downKbps, upKbps int) error {
	return tuneGlobalShaperOnActor(DefaultDataplaneActor(), hncDir, downKbps, upKbps)
}

func tuneGlobalShaperOnActor(actor *DataplaneActor, hncDir string, downKbps, upKbps int) error {
	if !useNativeDataplane(hncDir) {
		return errors.New("native dataplane disabled for test/compat environment")
	}
	if downKbps <= 0 && upKbps <= 0 {
		return errors.New("TuneGlobalShaperNative: both downKbps and upKbps are <= 0")
	}
	iface := readHotspotIfaceName(hncDir)
	if iface == "" {
		return errors.New("TuneGlobalShaperNative: hotspot interface inactive")
	}

	h := getDPTierHooks()
	downIdx := 0
	if downKbps > 0 {
		idx, err := h.ifaceIndex(iface)
		if err != nil || idx <= 0 {
			return fmt.Errorf("TuneGlobalShaperNative: resolve %s ifindex: %w", iface, err)
		}
		downIdx = idx
	}
	ifbIdx := 0
	if upKbps > 0 {
		if idx, err := h.ifaceIndex("ifb0"); err == nil && idx > 0 {
			ifbIdx = idx
		}
	}

	downBps := kbpsToBytesPerSec(downKbps)
	upBps := kbpsToBytesPerSec(upKbps)

	return actor.Do("tune_global_shaper", func(a *DataplaneActor) error {
		if a.reconcileMap == nil {
			a.reconcileMap = make(map[string]string, 16)
		}
		a.trackIfindexLocked(hncDir, iface, downIdx)
		a.trackIfindexLocked(hncDir, "ifb0", ifbIdx)
		digestKey := "shaper:" + hncDir + ":" + iface
		digestVal := fmt.Sprintf("%d:%d:%d:%d", downIdx, ifbIdx, downKbps, upKbps)
		if prev, ok := a.reconcileMap[digestKey]; ok && prev == digestVal {
			a.dedupHits.Add(1)
			a.savedForks.Add(1)
			a.publishSnapshotLocked()
			return nil
		}

		unlock, lockErr := h.acquireLock(hncDir, "tune_global_shaper")
		if lockErr != nil {
			a.nlFallbacks.Add(1)
			a.publishSnapshotLocked()
			return lockErr
		}
		defer unlock()

		if a.probeState.tier != DataplaneTierAtomicBatch {
			nlErr := a.runWithPersistentSocket(h, func(fd int) error {
				_, err := h.tuneShaperOnSock(fd, downIdx, downBps, ifbIdx, upBps)
				return err
			})
			if nlErr == nil {
				a.reconcileMap[digestKey] = digestVal
				a.shaperSpec = v6ShaperDesiredState{
					iface:    iface,
					ifidx:    downIdx,
					ifbIdx:   ifbIdx,
					downKbps: downKbps,
					upKbps:   upKbps,
				}
				a.savedForks.Add(1)
				a.publishSnapshotLocked()
				return nil
			}
			a.nlFallbacks.Add(1)
		}

		// Tier 3 内存原子批处理兜底 (单次 `tc -force -batch -` 管道, <= 1 次子进程)
		tcLines := buildTier3GlobalShaperBatchLines(iface, downKbps, ifbIdx > 0, upKbps)
		if len(tcLines) > 0 {
			if bErr := execTier3AtomicBatch(h, tcLines, nil, nil); bErr == nil {
				a.tier3Batches.Add(1)
				a.reconcileMap[digestKey] = digestVal
				a.shaperSpec = v6ShaperDesiredState{
					iface:    iface,
					ifidx:    downIdx,
					ifbIdx:   ifbIdx,
					downKbps: downKbps,
					upKbps:   upKbps,
				}
				a.publishSnapshotLocked()
				return nil
			}
		}
		a.publishSnapshotLocked()
		return errors.New("TuneGlobalShaperNative: both netlink and tier3 batch failed")
	})
}

// ── 导出接口 2: ApplyVectorExpressNative (1:10 prio 0 特快通道) ──────────────

// ApplyVectorExpressNative 在热点下行口与 ifb0(若就绪)上通过原生 Netlink 幂等激活或停用
// 1:10 高优特快队列 (prio 0 + 浅驻留 fq_codel: target=2ms, interval=40ms, quantum=300)。
func ApplyVectorExpressNative(hncDir string, enable bool, gameMark uint32, bgCeilKbps int) error {
	return applyVectorExpressOnActor(DefaultDataplaneActor(), hncDir, enable, gameMark, bgCeilKbps)
}

func applyVectorExpressOnActor(actor *DataplaneActor, hncDir string, enable bool, gameMark uint32, bgCeilKbps int) error {
	if !useNativeDataplane(hncDir) {
		return errors.New("native dataplane disabled for test/compat environment")
	}
	iface := readHotspotIfaceName(hncDir)
	if iface == "" {
		return errors.New("ApplyVectorExpressNative: hotspot interface inactive")
	}
	if gameMark == 0 {
		gameMark = v6ExpressDefaultMark
	}
	gameMask := resolveOrthogonalFilterMask(gameMark, DefaultAppQoSMarkMask)
	if !enable || bgCeilKbps < 0 {
		bgCeilKbps = 0
	}

	h := getDPTierHooks()
	downIdx, err := h.ifaceIndex(iface)
	if err != nil || downIdx <= 0 {
		return fmt.Errorf("ApplyVectorExpressNative: resolve %s ifindex: %w", iface, err)
	}
	ifbIdx := 0
	if idx, uErr := h.ifaceIndex("ifb0"); uErr == nil && idx > 0 {
		ifbIdx = idx
	}

	return actor.Do("vector_express", func(a *DataplaneActor) error {
		if a.reconcileMap == nil {
			a.reconcileMap = make(map[string]string, 16)
		}
		a.trackIfindexLocked(hncDir, iface, downIdx)
		a.trackIfindexLocked(hncDir, "ifb0", ifbIdx)
		digestKey := "express:" + hncDir + ":" + iface
		digestVal := fmt.Sprintf("%d:%d:%t:0x%08x:%d", downIdx, ifbIdx, enable, gameMark&gameMask, bgCeilKbps)
		if prev, ok := a.reconcileMap[digestKey]; ok && prev == digestVal {
			a.dedupHits.Add(1)
			a.savedForks.Add(1)
			a.publishSnapshotLocked()
			return nil
		}

		unlock, lockErr := h.acquireLock(hncDir, "vector_express")
		if lockErr != nil {
			a.nlFallbacks.Add(1)
			a.publishSnapshotLocked()
			return lockErr
		}
		defer unlock()

		downRootBps := effectiveRootRateBps(a.shaperSpec.downKbps)
		upRootBps := effectiveRootRateBps(a.shaperSpec.upKbps)
		bgCeilBps := kbpsToBytesPerSec(bgCeilKbps)
		tick := readPschedTickInUsec()

		var allMsgs [][]byte
		if enable {
			allMsgs = append(allMsgs, buildVectorExpressUpsertBatch(downIdx, false, downRootBps, bgCeilBps, gameMark, gameMask, tick)...)
			if ifbIdx > 0 {
				upBgCeil := uint64(0)
				if bgCeilBps > 0 && upRootBps > 0 && bgCeilBps < upRootBps {
					upBgCeil = bgCeilBps
				}
				allMsgs = append(allMsgs, buildVectorExpressUpsertBatch(ifbIdx, true, upRootBps, upBgCeil, gameMark, gameMask, tick)...)
			}
		} else {
			allMsgs = append(allMsgs, buildVectorExpressRemoveBatch(downIdx, false, downRootBps, gameMark, gameMask, tick)...)
			if ifbIdx > 0 {
				allMsgs = append(allMsgs, buildVectorExpressRemoveBatch(ifbIdx, true, upRootBps, gameMark, gameMask, tick)...)
			}
		}

		if a.probeState.tier != DataplaneTierAtomicBatch {
			nlErr := a.runWithPersistentSocket(h, func(fd int) error {
				_, bErr := h.applyBatchOnSock(fd, allMsgs)
				return bErr
			})
			if nlErr == nil {
				a.reconcileMap[digestKey] = digestVal
				a.expressSpec = v6ExpressDesiredState{
					active:     enable,
					gameMark:   gameMark & gameMask,
					bgCeilKbps: bgCeilKbps,
				}
				a.savedForks.Add(2)
				a.publishSnapshotLocked()
				return nil
			}
			a.nlFallbacks.Add(1)
		}

		// Tier 3 批处理管道兜底 (单次 `tc -force -batch -` <= 3 次外部调用)
		tcLines := buildTier3VectorExpressBatchLines(iface, ifbIdx > 0, enable, gameMark&gameMask, gameMask, bgCeilKbps, effectiveRootRateKbps(a.shaperSpec.downKbps))
		if bErr := execTier3AtomicBatch(h, tcLines, nil, nil); bErr == nil {
			a.tier3Batches.Add(1)
			a.reconcileMap[digestKey] = digestVal
			a.expressSpec = v6ExpressDesiredState{
				active:     enable,
				gameMark:   gameMark & gameMask,
				bgCeilKbps: bgCeilKbps,
			}
			a.publishSnapshotLocked()
			return nil
		}
		a.publishSnapshotLocked()
		return errors.New("ApplyVectorExpressNative: netlink and tier3 batch failed")
	})
}

// ── 导出接口 3: ApplyUpdateLeashNative (1:9990 后台细流限速类) ───────────────

// ApplyUpdateLeashNative 幂等维护 1:9990 后台更新细流限速类:
//   - rateKbps == 0 时默认采用 1500 Kbps (leashDefaultKbps);
//   - rateKbps < 0 时幂等拆除 1:9990 及其关联 fw 过滤器与 fq_codel 叶子。
func ApplyUpdateLeashNative(hncDir string, leashMark uint32, rateKbps int) error {
	return applyUpdateLeashOnActor(DefaultDataplaneActor(), hncDir, leashMark, rateKbps)
}

// RemoveUpdateLeashNative 幂等移除 1:9990 后台更新细流限速类。
func RemoveUpdateLeashNative(hncDir string, leashMark uint32) error {
	return ApplyUpdateLeashNative(hncDir, leashMark, -1)
}

func applyUpdateLeashOnActor(actor *DataplaneActor, hncDir string, leashMark uint32, rateKbps int) error {
	if !useNativeDataplane(hncDir) {
		return errors.New("native dataplane disabled for test/compat environment")
	}
	iface := readHotspotIfaceName(hncDir)
	if iface == "" {
		return errors.New("ApplyUpdateLeashNative: hotspot interface inactive")
	}
	if leashMark == 0 {
		leashMark = v6LeashDefaultMark
	}
	leashMask := resolveOrthogonalFilterMask(leashMark, DefaultAppQoSMarkMask)

	enable := true
	if rateKbps < 0 {
		enable = false
		rateKbps = 0
	} else if rateKbps == 0 {
		rateKbps = v6LeashDefaultKbps
	}

	h := getDPTierHooks()
	downIdx, err := h.ifaceIndex(iface)
	if err != nil || downIdx <= 0 {
		return fmt.Errorf("ApplyUpdateLeashNative: resolve %s ifindex: %w", iface, err)
	}
	ifbIdx := 0
	if idx, uErr := h.ifaceIndex("ifb0"); uErr == nil && idx > 0 {
		ifbIdx = idx
	}

	return actor.Do("update_leash", func(a *DataplaneActor) error {
		if a.reconcileMap == nil {
			a.reconcileMap = make(map[string]string, 16)
		}
		a.trackIfindexLocked(hncDir, iface, downIdx)
		a.trackIfindexLocked(hncDir, "ifb0", ifbIdx)
		digestKey := "leash:" + hncDir + ":" + iface
		digestVal := fmt.Sprintf("%d:%d:%t:0x%08x:%d", downIdx, ifbIdx, enable, leashMark&leashMask, rateKbps)
		if prev, ok := a.reconcileMap[digestKey]; ok && prev == digestVal {
			a.dedupHits.Add(1)
			a.savedForks.Add(1)
			a.publishSnapshotLocked()
			return nil
		}

		unlock, lockErr := h.acquireLock(hncDir, "update_leash")
		if lockErr != nil {
			a.nlFallbacks.Add(1)
			a.publishSnapshotLocked()
			return lockErr
		}
		defer unlock()

		rateBps := kbpsToBytesPerSec(rateKbps)
		tick := readPschedTickInUsec()
		var allMsgs [][]byte
		if enable {
			allMsgs = append(allMsgs, buildUpdateLeashUpsertBatch(downIdx, false, rateBps, leashMark, leashMask, tick)...)
			if ifbIdx > 0 {
				allMsgs = append(allMsgs, buildUpdateLeashUpsertBatch(ifbIdx, true, rateBps, leashMark, leashMask, tick)...)
			}
		} else {
			allMsgs = append(allMsgs, buildUpdateLeashRemoveBatch(downIdx, false, leashMark, leashMask)...)
			if ifbIdx > 0 {
				allMsgs = append(allMsgs, buildUpdateLeashRemoveBatch(ifbIdx, true, leashMark, leashMask)...)
			}
		}

		if a.probeState.tier != DataplaneTierAtomicBatch {
			nlErr := a.runWithPersistentSocket(h, func(fd int) error {
				_, bErr := h.applyBatchOnSock(fd, allMsgs)
				return bErr
			})
			if nlErr == nil {
				a.reconcileMap[digestKey] = digestVal
				a.leashSpec = v6LeashDesiredState{
					active:    enable,
					leashMark: leashMark & leashMask,
					rateKbps:  rateKbps,
				}
				a.savedForks.Add(2)
				a.publishSnapshotLocked()
				return nil
			}
			a.nlFallbacks.Add(1)
		}

		tcLines := buildTier3UpdateLeashBatchLines(iface, ifbIdx > 0, enable, leashMark&leashMask, leashMask, rateKbps)
		if bErr := execTier3AtomicBatch(h, tcLines, nil, nil); bErr == nil {
			a.tier3Batches.Add(1)
			a.reconcileMap[digestKey] = digestVal
			a.leashSpec = v6LeashDesiredState{
				active:    enable,
				leashMark: leashMark & leashMask,
				rateKbps:  rateKbps,
			}
			a.publishSnapshotLocked()
			return nil
		}
		a.publishSnapshotLocked()
		return errors.New("ApplyUpdateLeashNative: netlink and tier3 batch failed")
	})
}

// ── Tier 3 原子批处理执行器 (严格封顶 <= 3 次子进程调用) ──────────────────────

// execTier3AtomicBatch 在内存拼装批处理缓冲并一次性提交给:
//  1. `tc -force -batch -` (1 次)
//  2. `iptables-restore -w 2 --noflush` (最多 1 次)
//  3. `ip6tables-restore -w 2 --noflush` (最多 1 次)
// 整个事务总外部子进程派生数严格封顶 <= 3!
func execTier3AtomicBatch(h dpTierHooks, tcLines []string, v4Restore, v6Restore []byte) error {
	subprocs := 0
	if len(tcLines) > 0 {
		if subprocs >= dpTier3MaxSubprocs {
			return errors.New("tier3 batch exceeded subprocess cap")
		}
		tcBin := h.resolveBin("tc")
		if tcBin == "" {
			return errors.New("tier3 batch: tc binary not found")
		}
		payload := []byte(strings.Join(tcLines, "\n") + "\n")
		subprocs++
		if err := h.runTier3Cmd(tcBin, []string{"-force", "-batch", "-"}, payload); err != nil {
			return fmt.Errorf("tier3 tc -batch failed: %w", err)
		}
	}
	if len(v4Restore) > 0 {
		if subprocs >= dpTier3MaxSubprocs {
			return errors.New("tier3 batch exceeded subprocess cap")
		}
		v4Bin := h.resolveBin("iptables-restore")
		if v4Bin == "" {
			return errors.New("tier3 batch: iptables-restore binary not found")
		}
		subprocs++
		if err := h.runTier3Cmd(v4Bin, []string{"-w", "2", "--noflush"}, v4Restore); err != nil {
			return fmt.Errorf("tier3 iptables-restore failed: %w", err)
		}
	}
	if len(v6Restore) > 0 {
		if subprocs >= dpTier3MaxSubprocs {
			return errors.New("tier3 batch exceeded subprocess cap")
		}
		if v6Bin := h.resolveBin("ip6tables-restore"); v6Bin != "" {
			subprocs++
			_ = h.runTier3Cmd(v6Bin, []string{"-w", "2", "--noflush"}, v6Restore)
		}
	}
	return nil
}

func defaultRunTier3PipeCmd(binPath string, args []string, stdin []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), dpTier3BatchTimeout)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, binPath, args...))
	cmd.Env = []string{"PATH=/system/bin:/system/xbin:/vendor/bin:/usr/sbin:/sbin:/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (%s)", filepath.Base(binPath), args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func resolveDataplaneSystemBin(name string) string {
	if strings.Contains(name, "restore") {
		return resolveIptablesRestoreBin(name)
	}
	for _, p := range []string{
		"/system/bin/" + name,
		"/system/xbin/" + name,
		"/vendor/bin/" + name,
		"/usr/sbin/" + name,
		"/sbin/" + name,
		"/usr/bin/" + name,
		"/bin/" + name,
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func buildTier3GlobalShaperBatchLines(iface string, downKbps int, hasIFB bool, upKbps int) []string {
	var lines []string
	if downKbps > 0 && iface != "" {
		bK := (hncBurstBytesForRate(kbpsToBytesPerSec(downKbps), false) + 1023) / 1024
		rateStr := strconv.Itoa(downKbps) + "kbit"
		bStr := strconv.FormatUint(uint64(bK), 10) + "k"
		lines = append(lines, fmt.Sprintf("class replace dev %s parent 1: classid 1:1 htb rate %s ceil %s burst %s cburst %s", iface, rateStr, rateStr, bStr, bStr))
	}
	if hasIFB && upKbps > 0 {
		bK := (hncBurstBytesForRate(kbpsToBytesPerSec(upKbps), false) + 1023) / 1024
		rateStr := strconv.Itoa(upKbps) + "kbit"
		bStr := strconv.FormatUint(uint64(bK), 10) + "k"
		lines = append(lines, fmt.Sprintf("class replace dev ifb0 parent 1: classid 1:1 htb rate %s ceil %s burst %s cburst %s", rateStr, rateStr, bStr, bStr))
	}
	return lines
}

func buildTier3VectorExpressBatchLines(iface string, hasIFB, enable bool, markVal, markMask uint32, bgCeilKbps, rootDownKbps int) []string {
	targets := []struct {
		dev    string
		leafID string
	}{
		{dev: iface, leafID: "1010:"},
	}
	if hasIFB {
		targets = append(targets, struct {
			dev    string
			leafID string
		}{dev: "ifb0", leafID: "1110:"})
	}
	if rootDownKbps <= 0 {
		rootDownKbps = dpDefaultRootRateKbp
	}
	var lines []string
	for _, tg := range targets {
		if enable {
			expRate := rootDownKbps / 4
			if expRate < 20000 {
				expRate = 20000
			}
			if expRate > rootDownKbps {
				expRate = rootDownKbps
			}
			lines = append(lines,
				fmt.Sprintf("class replace dev %s parent 1:1 classid 1:10 htb rate %dkbit ceil %dkbit prio 0 quantum 1514", tg.dev, expRate, rootDownKbps),
				fmt.Sprintf("qdisc replace dev %s parent 1:10 handle %s fq_codel target 2ms interval 40ms quantum 300 limit 512", tg.dev, tg.leafID),
				fmt.Sprintf("filter replace dev %s parent 1: protocol ip prio 2 handle 0x%x/0x%x fw flowid 1:10", tg.dev, markVal, markMask),
				fmt.Sprintf("filter replace dev %s parent 1: protocol ipv6 prio 4 handle 0x%x/0x%x fw flowid 1:10", tg.dev, markVal, markMask),
			)
			if bgCeilKbps > 0 && tg.dev == iface {
				lines = append(lines, fmt.Sprintf("class replace dev %s parent 1:1 classid 1:9999 htb rate %dkbit ceil %dkbit prio 7", tg.dev, bgCeilKbps, bgCeilKbps))
			}
		} else {
			lines = append(lines,
				fmt.Sprintf("filter del dev %s parent 1: protocol ip prio 2", tg.dev),
				fmt.Sprintf("filter del dev %s parent 1: protocol ipv6 prio 4", tg.dev),
				fmt.Sprintf("qdisc del dev %s parent 1:10", tg.dev),
				fmt.Sprintf("class del dev %s parent 1:1 classid 1:10", tg.dev),
			)
			if tg.dev == iface {
				lines = append(lines, fmt.Sprintf("class replace dev %s parent 1:1 classid 1:9999 htb rate %dkbit ceil %dkbit prio 7", tg.dev, rootDownKbps, rootDownKbps))
			}
		}
	}
	return lines
}

func buildTier3UpdateLeashBatchLines(iface string, hasIFB, enable bool, markVal, markMask uint32, rateKbps int) []string {
	targets := []struct {
		dev    string
		leafID string
	}{
		{dev: iface, leafID: "9990:"},
	}
	if hasIFB {
		targets = append(targets, struct {
			dev    string
			leafID string
		}{dev: "ifb0", leafID: "9991:"})
	}
	var lines []string
	for _, tg := range targets {
		if enable {
			lines = append(lines,
				fmt.Sprintf("class replace dev %s parent 1:1 classid 1:9990 htb rate %dkbit ceil %dkbit burst 16k cburst 16k prio 7 quantum 1514", tg.dev, rateKbps, rateKbps),
				fmt.Sprintf("qdisc replace dev %s parent 1:9990 handle %s fq_codel target 5ms interval 100ms quantum 1514 limit 1024", tg.dev, tg.leafID),
				fmt.Sprintf("filter replace dev %s parent 1: protocol ip prio 6 handle 0x%x/0x%x fw flowid 1:9990", tg.dev, markVal, markMask),
				fmt.Sprintf("filter replace dev %s parent 1: protocol ipv6 prio 7 handle 0x%x/0x%x fw flowid 1:9990", tg.dev, markVal, markMask),
			)
		} else {
			lines = append(lines,
				fmt.Sprintf("filter del dev %s parent 1: protocol ip prio 6", tg.dev),
				fmt.Sprintf("filter del dev %s parent 1: protocol ipv6 prio 7", tg.dev),
				fmt.Sprintf("qdisc del dev %s parent 1:9990", tg.dev),
				fmt.Sprintf("class del dev %s parent 1:1 classid 1:9990", tg.dev),
			)
		}
	}
	return lines
}

// ── 辅助换算函数 ─────────────────────────────────────────────────────────────

func kbpsToBytesPerSec(kbps int) uint64 {
	if kbps <= 0 {
		return 0
	}
	bps := (uint64(kbps) * 1000) / 8
	if bps == 0 {
		return 1
	}
	return bps
}

func effectiveRootRateKbps(configuredKbps int) int {
	if configuredKbps > 0 {
		return configuredKbps
	}
	return dpDefaultRootRateKbp
}

func effectiveRootRateBps(configuredKbps int) uint64 {
	if configuredKbps > 0 {
		return kbpsToBytesPerSec(configuredKbps)
	}
	return DefaultHTBRootRateBps
}

func resolveOrthogonalFilterMask(markVal, preferredMask uint32) uint32 {
	if preferredMask != 0 && (markVal&preferredMask) == markVal && (markVal&preferredMask) != 0 {
		return preferredMask
	}
	if markVal != 0 {
		return markVal
	}
	return DefaultAppQoSMarkMask
}
