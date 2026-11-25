// v6_leakguard_api.go — HNC v6.0.0 · Vector (T4 模块 1):
// LeakGuard 实时明文隐私泄露预警、SSE 推送、防注入状态栏通知与双栈一键反制 + v6 统一路由总入口。
//
// 核心工程保证:
//   - 零外部第三方库, 纯字节编解码, 64 位 atomic 字段严格置于结构体 offset 0 (兼容 GOARCH=arm)。
//   - Android 原生通知严格通过 exec.CommandContext 纯参数数组直调 /system/bin/cmd + 2s 硬超时 + 控制字符/元字符清洗。
//   - 锁屏脱敏: lockscreen_mask=true 时对通知正文 raw_value 中间位打码; WebUI API 与 SSE 始终返回 100% 完整原文。
//   - 系统告警统一经由 hnc.io/dpid/alert.Append 原子落盘。
//   - RC1 加固: 持久化忽略白名单、三级共享 CDN 防误杀守卫、10 条封禁一键撤销栈、0o600 最小权限与后台零唤醒停表。

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
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

	"hnc.io/dpid/alert"
	dpidlg "hnc.io/dpid/leakguard"
)

// ── v6.0.0 统一挂载入口与按 server 隔离的运行时状态池（零侵入 server.go） ───────

type v6ServerState struct {
	// 64 位原子计数严格置于 offset 0, 保证 32 位 ARM (armeabi-v7a) 8 字节对齐
	summaryCalls atomic.Uint64

	leakGuard    *leakGuardEngine
	express      *vectorExpressEngine
	leash        *updateLeashEngine
	scalpel      *flowScalpelEngine
	thermo       *thermoCruiseEngine
	selfFirewall *selfFirewallEngine
}

var v6Registry sync.Map // map[*server]*v6ServerState

func (s *server) v6State() *v6ServerState {
	if v, ok := v6Registry.Load(s); ok {
		return v.(*v6ServerState)
	}
	st := &v6ServerState{
		leakGuard:    newLeakGuardEngine(s),
		express:      newVectorExpressEngine(s),
		leash:        newUpdateLeashEngine(s),
		scalpel:      newFlowScalpelEngine(s),
		thermo:       newThermoCruiseEngine(s),
		selfFirewall: newSelfFirewallEngine(s),
	}
	actual, _ := v6Registry.LoadOrStore(s, st)
	return actual.(*v6ServerState)
}

// registerV6FeatureRoutes 供总装阶段在 server.handler() 内一键挂载 v6 核心路由。
func (s *server) registerV6FeatureRoutes(mux *http.ServeMux) {
	if s == nil || mux == nil {
		return
	}
	_ = s.v6State()

	// 模块 1: LeakGuard 隐私防泄露哨兵 (本机 + 热点双域)
	mux.HandleFunc("/api/leakguard/events", s.apiLeakGuardEvents)
	mux.HandleFunc("/api/leakguard/stream", s.apiLeakGuardStream)
	mux.HandleFunc("/api/leakguard/clear", s.requireMutation(s.apiLeakGuardClear))
	mux.HandleFunc("/api/leakguard/config", s.requireMutation(s.apiLeakGuardConfig))
	mux.HandleFunc("/api/leakguard/block-domain", s.requireMutation(s.apiLeakGuardBlockDomain))
	mux.HandleFunc("/api/leakguard/whitelist", s.requireMutation(s.apiLeakGuardWhitelist))
	mux.HandleFunc("/api/leakguard/undo-block", s.requireMutation(s.apiLeakGuardUndoBlock))

	// 模块 2: Vector Express 跨设备微秒级零排队护航
	mux.HandleFunc("/api/v6/express", s.apiVectorExpress)

	// 模块 3: UpdateLeash 200MB 免死缓冲 + 后台巨兽温柔拴绳
	mux.HandleFunc("/api/v6/update_leash", s.apiUpdateLeash)

	// 模块 4: FlowScalpel 五元组实时透视 + 免断网单流秒斩手术刀
	mux.HandleFunc("/api/v6/scalpel/flows", s.apiScalpelFlows)
	mux.HandleFunc("/api/v6/scalpel/cut", s.requireMutation(s.apiScalpelCut))

	// 模块 5: ThermoCruise sysfs 零开销温控与电量自适应巡航
	mux.HandleFunc("/api/v6/thermo", s.apiThermoCruise)

	// 模块 6: 本机应用防火墙 (HNC_SELF_UID) 与本机 DNS 拦截 (HNC_SELF_DNS)
	mux.HandleFunc("/api/local_apps/firewall", s.apiSelfFirewall)
	mux.HandleFunc("/api/v6/local_apps/firewall", s.apiSelfFirewall)
}

// registerV6FeatureRoutes 包级同名包装, 兼容 registerV6FeatureRoutes(mux, s) 与 s.registerV6FeatureRoutes(mux) 两种总装调用签名。
func registerV6FeatureRoutes(mux *http.ServeMux, s *server) {
	if s != nil && mux != nil {
		s.registerV6FeatureRoutes(mux)
	}
}

// v6FeaturesSummary 供 /api/vector_sync 或全局驾驶舱一键拉取全部 v6 模块轻量实时摘要。
func (s *server) v6FeaturesSummary() map[string]any {
	if s == nil {
		return map[string]any{}
	}
	st := s.v6State()
	st.summaryCalls.Add(1)
	return map[string]any{
		"leakguard":     st.leakGuard.summary(),
		"express":       st.express.summary(),
		"update_leash":  st.leash.summary(),
		"scalpel":       st.scalpel.summary(),
		"thermo":        st.thermo.summary(),
		"self_firewall": st.selfFirewall.summary(),
	}
}

// StartV6FeatureLoops 启动五大模块后台自适应巡检协程（幂等安全, stop 关闭时全部干净退出）。
func (s *server) StartV6FeatureLoops(stop <-chan struct{}) {
	if s == nil {
		return
	}
	st := s.v6State()
	go st.leakGuard.runLoop(stop)
	go st.express.runLoop(stop)
	go st.leash.runLoop(stop)
	go st.scalpel.runLoop(stop)
	go st.thermo.runLoop(stop)
}

// ── 模块 1: LeakGuard 核心结构与常量 ─────────────────────────────────────────

const (
	leakDefaultCapacity     = 300
	leakMinCapacity         = 10
	leakMaxCapacity         = 2000
	leakDefaultCooldownSec  = 300
	leakMinCooldownSec      = 0
	leakMaxCooldownSec      = 86400
	leakNotifyTimeout       = 2 * time.Second
	leakCmdBinPath          = "/system/bin/cmd"
	leakMaxSSEClients       = 32
	leakSSEHeartbeatDefault = 15 * time.Second
	leakDefaultPollInterval = 3 * time.Second
	leakMaxUndoStack        = 10
	leakMaxCooldownEntries  = 4096
	leakMaxTombstones       = 1024
	leakTombstoneTTLSec     = 7 * 86400
	leakMaxConcurrentNotify = 2
	leakSSEWriteTimeout     = 10 * time.Second

	leakOriginHotspot = "hotspot"
	leakOriginHost    = "host"

	leakScopeAll     = "all"
	leakScopeHotspot = "hotspot"
	leakScopeHost    = "host"

	leakTargetScopeHotspot = "hotspot"
	leakTargetScopeHost    = "host"
	leakTargetScopeBoth    = "both"
)

var leakSSEActiveConns atomic.Int64

// LeakGuardConfig 用户持久化与运行时控制配置。
type LeakGuardConfig struct {
	Capacity       int  `json:"capacity"`
	CooldownSec    int  `json:"cooldown_sec"`
	NotifyEnabled  bool `json:"notify_enabled"`
	LockscreenMask bool `json:"lockscreen_mask"`
}

func defaultLeakGuardConfig() LeakGuardConfig {
	return LeakGuardConfig{
		Capacity:       leakDefaultCapacity,
		CooldownSec:    leakDefaultCooldownSec,
		NotifyEnabled:  true,
		LockscreenMask: true,
	}
}

// LeakEvent 明文隐私泄露事件（WebUI 与 SSE 始终返回 100% 未打码的 RawValue 与 RawSnippet）。
type LeakEvent struct {
	ID         string `json:"id"`
	Ts         int64  `json:"ts"`
	Origin     string `json:"origin"`
	UID        int    `json:"uid,omitempty"`
	Pkg        string `json:"pkg,omitempty"`
	AppName    string `json:"app_name,omitempty"`
	MAC        string `json:"mac"`
	SrcIP      string `json:"src_ip"`
	DeviceName string `json:"device_name"`
	DstHost    string `json:"dst_host"`
	DstIP      string `json:"dst_ip,omitempty"`
	SrcPort    uint16 `json:"src_port,omitempty"`
	DstPort    int    `json:"dst_port,omitempty"`
	Proto      string `json:"proto,omitempty"`
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	LeakType   string `json:"leak_type"`
	LeakLabel  string `json:"leak_label,omitempty"`
	RawValue   string `json:"raw_value"`
	RawSnippet string `json:"raw_snippet"`
	HitCount   int64  `json:"hit_count,omitempty"`
	IsBlocked  bool   `json:"is_blocked"`
	fieldKey   string `json:"-"`
}

// LeakBlockUndoEntry 最近 10 条封禁一键撤销栈记录（支持热点/本机/双域回滚）。
type LeakBlockUndoEntry struct {
	ID          string   `json:"id"`
	DstHost     string   `json:"dst_host"`
	Kind        string   `json:"kind"`                   // "domain" | "ip"
	TargetScope string   `json:"target_scope,omitempty"` // "hotspot" | "host" | "both" (空默认 "hotspot")
	UID         int      `json:"uid,omitempty"`          // 本机按应用 UID 封禁公网 IP 时的目标 UID
	AlsoIP      string   `json:"also_ip,omitempty"`      // 同次连带封锁的独立 IP（若命中共享 CDN IP 自动跳过则为空）
	MACs        []string `json:"macs,omitempty"`         // 本次封禁实际作用的设备 MAC 列表
	CreatedAt   int64    `json:"created_at"`
}

type leakGuardCtrlFile struct {
	Capacity       int                 `json:"capacity"`
	CooldownSec    int                 `json:"cooldown_sec"`
	NotifyEnabled  bool                `json:"notify_enabled"`
	LockscreenMask bool                `json:"lockscreen_mask"`
	ClearSeq       int64               `json:"clear_seq"`
	ClearedAt      int64               `json:"cleared_at"`
	BlockedTargets map[string]bool     `json:"blocked_targets,omitempty"`
	IgnoreRules    []dpidlg.IgnoreRule `json:"ignore_rules"`
	UpdatedAt      int64               `json:"updated_at"`
}

type leakGuardPersistFile struct {
	Config         LeakGuardConfig      `json:"config"`
	BlockedTargets map[string]bool      `json:"blocked_targets,omitempty"`
	IgnoreRules    []dpidlg.IgnoreRule  `json:"ignore_rules,omitempty"`
	UndoStack      []LeakBlockUndoEntry `json:"undo_stack,omitempty"`
	ClearSeq       int64                `json:"clear_seq,omitempty"`
	ClearedAt      int64                `json:"cleared_at,omitempty"`
}

type leakNotifyFunc func(ctx context.Context, bin string, args ...string) error

type leakGuardEngine struct {
	// 64 位原子字段严格连续置于结构体最顶部 offset 0, 8, 16, 24, 32, 40, 48 (兼容 32 位 GOARCH=arm)
	totalHits     atomic.Int64
	clearSeq      atomic.Int64
	ignoredHits   atomic.Int64
	guardBlocks   atomic.Int64
	diskReadCount atomic.Int64
	hostHits      atomic.Int64
	hotspotHits   atomic.Int64

	tickerActive atomic.Bool

	srv               *server
	mu                sync.Mutex
	cfg               LeakGuardConfig
	clearedAt         int64
	maxSeenTs         int64
	hasEventsStat     bool
	lastEventsMtimeNs int64
	lastEventsSize    int64
	events            []LeakEvent // 按时间升序存储, 容量受 cfg.Capacity 约束
	seenIDs           map[string]int64
	mergedAliasIDs    map[string]string
	ignoredSeenIDs    map[string]int64
	cooldownLedger    map[string]int64
	blockedTargets    map[string]bool
	tombstones        map[string]bool
	tombstoneAt       map[string]int64
	ignoreRules       []dpidlg.IgnoreRule
	undoStack         []LeakBlockUndoEntry
	subs              map[chan LeakEvent]struct{}
	notifyExec        leakNotifyFunc
	notifySem         chan struct{}
	sseHeartbeat      time.Duration
	pollInterval      time.Duration
	wakeOnce          sync.Once
	wakeCh            chan struct{}
	activityHook      func() (<-chan struct{}, Activity, bool)
}

func defaultLeakNotifyExec(ctx context.Context, bin string, args ...string) error {
	// 安全铁律: 纯参数切片直调目标二进制 + hardenCmd 2s WaitDelay 防管道悬挂
	cmd := hardenCmd(exec.CommandContext(ctx, bin, args...))
	return cmd.Run()
}

var leakGuardWriteSeq atomic.Uint64

// writeLeakGuardAtomic0600 原子落盘并强制收紧权限为 0o600, 防止明文隐私配置/事件被同机非特权进程读取。
func writeLeakGuardAtomic0600(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	seq := leakGuardWriteSeq.Add(1)
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

func newLeakGuardEngine(s *server) *leakGuardEngine {
	eng := &leakGuardEngine{
		srv:            s,
		cfg:            defaultLeakGuardConfig(),
		seenIDs:        make(map[string]int64),
		mergedAliasIDs: make(map[string]string),
		ignoredSeenIDs: make(map[string]int64),
		cooldownLedger: make(map[string]int64),
		blockedTargets: make(map[string]bool),
		tombstones:     make(map[string]bool),
		tombstoneAt:    make(map[string]int64),
		subs:           make(map[chan LeakEvent]struct{}),
		notifyExec:     defaultLeakNotifyExec,
		notifySem:      make(chan struct{}, leakMaxConcurrentNotify),
		sseHeartbeat:   leakSSEHeartbeatDefault,
		pollInterval:   leakDefaultPollInterval,
	}
	eng.loadPersistedLocked()
	eng.purgeAlertsMatching(nil, eng.ignoreRules, true)
	return eng
}

func (e *leakGuardEngine) setTombstoneLocked(key string, nowTs int64) {
	if key == "" {
		return
	}
	if e.tombstones == nil {
		e.tombstones = make(map[string]bool)
	}
	if e.tombstoneAt == nil {
		e.tombstoneAt = make(map[string]int64)
	}
	if nowTs <= 0 {
		nowTs = time.Now().Unix()
	}
	e.tombstones[key] = true
	e.tombstoneAt[key] = nowTs
}

func (e *leakGuardEngine) deleteTombstoneLocked(key string) {
	delete(e.tombstones, key)
	delete(e.tombstoneAt, key)
}

func (e *leakGuardEngine) pruneTombstonesLocked(nowTs int64) {
	if len(e.tombstones) == 0 {
		if len(e.tombstoneAt) > 0 {
			e.tombstoneAt = make(map[string]int64)
		}
		return
	}
	if e.tombstoneAt == nil {
		e.tombstoneAt = make(map[string]int64, len(e.tombstones))
	}
	if nowTs <= 0 {
		nowTs = time.Now().Unix()
	}
	for k, active := range e.tombstones {
		if !active || k == "" {
			delete(e.tombstones, k)
			delete(e.tombstoneAt, k)
			continue
		}
		ts, ok := e.tombstoneAt[k]
		if !ok || ts <= 0 {
			e.tombstoneAt[k] = nowTs
			continue
		}
		if nowTs-ts > leakTombstoneTTLSec {
			delete(e.tombstones, k)
			delete(e.tombstoneAt, k)
		}
	}
	for k := range e.tombstoneAt {
		if !e.tombstones[k] {
			delete(e.tombstoneAt, k)
		}
	}
	if len(e.tombstones) <= leakMaxTombstones {
		return
	}
	type kv struct {
		k  string
		ts int64
	}
	arr := make([]kv, 0, len(e.tombstones))
	for k := range e.tombstones {
		arr = append(arr, kv{k: k, ts: e.tombstoneAt[k]})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].ts != arr[j].ts {
			return arr[i].ts < arr[j].ts
		}
		return arr[i].k < arr[j].k
	})
	drop := len(arr) - leakMaxTombstones
	for i := 0; i < drop; i++ {
		delete(e.tombstones, arr[i].k)
		delete(e.tombstoneAt, arr[i].k)
	}
}

func (e *leakGuardEngine) pruneCooldownLedgerLocked(nowTs int64) {
	if len(e.cooldownLedger) == 0 {
		return
	}
	ttl := int64(e.cfg.CooldownSec)
	if ttl > 0 && nowTs > 0 {
		for k, ts := range e.cooldownLedger {
			if nowTs-ts >= ttl {
				delete(e.cooldownLedger, k)
			}
		}
	}
	if len(e.cooldownLedger) <= leakMaxCooldownEntries {
		return
	}
	type kv struct {
		k  string
		ts int64
	}
	arr := make([]kv, 0, len(e.cooldownLedger))
	for k, ts := range e.cooldownLedger {
		arr = append(arr, kv{k: k, ts: ts})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].ts != arr[j].ts {
			return arr[i].ts < arr[j].ts
		}
		return arr[i].k < arr[j].k
	})
	drop := len(arr) - leakMaxCooldownEntries
	for i := 0; i < drop; i++ {
		delete(e.cooldownLedger, arr[i].k)
	}
}

func (e *leakGuardEngine) persistPath() string {
	return filepath.Join(e.srv.hncDir, "data", "leakguard_config.json")
}

func (e *leakGuardEngine) ctrlPath() string {
	return filepath.Join(e.srv.hncDir, "run", "leakguard_ctrl.json")
}

func (e *leakGuardEngine) dpidEventsPath() string {
	return filepath.Join(e.srv.hncDir, "run", "leakguard_events.json")
}

func (e *leakGuardEngine) loadPersistedLocked() {
	if e.srv == nil || e.srv.hncDir == "" {
		return
	}
	b, err := os.ReadFile(e.persistPath())
	if err != nil {
		return
	}
	var pf leakGuardPersistFile
	if json.Unmarshal(b, &pf) != nil {
		return
	}
	if pf.Config.Capacity >= leakMinCapacity && pf.Config.Capacity <= leakMaxCapacity {
		e.cfg = pf.Config
	}
	nowTs := time.Now().Unix()
	if pf.BlockedTargets != nil {
		for k, v := range pf.BlockedTargets {
			nk := strings.ToLower(strings.TrimSpace(k))
			if nk == "" {
				continue
			}
			if v {
				e.blockedTargets[nk] = true
			} else {
				e.setTombstoneLocked(nk, nowTs)
			}
		}
	}
	e.pruneTombstonesLocked(nowTs)
	if len(pf.IgnoreRules) > 0 {
		seen := make(map[string]bool, len(pf.IgnoreRules))
		for _, raw := range pf.IgnoreRules {
			nr, rerr := dpidlg.NormalizeIgnoreRule(raw)
			if rerr != nil {
				continue
			}
			uk := nr.UniqueKey()
			if seen[uk] {
				continue
			}
			seen[uk] = true
			e.ignoreRules = append(e.ignoreRules, nr)
			if len(e.ignoreRules) >= dpidlg.MaxIgnoreRules {
				break
			}
		}
	}
	if len(pf.UndoStack) > 0 {
		start := 0
		if len(pf.UndoStack) > leakMaxUndoStack {
			start = len(pf.UndoStack) - leakMaxUndoStack
		}
		e.undoStack = append([]LeakBlockUndoEntry(nil), pf.UndoStack[start:]...)
	}
	if pf.ClearSeq > 0 {
		e.clearSeq.Store(pf.ClearSeq)
	}
	if pf.ClearedAt > 0 {
		e.clearedAt = pf.ClearedAt
	}
}

func (e *leakGuardEngine) writeCtrlFileLocked(now int64) error {
	if e.srv == nil || e.srv.hncDir == "" {
		return nil
	}
	e.pruneTombstonesLocked(now)
	ctrlBlocked := make(map[string]bool, len(e.blockedTargets)+len(e.tombstones))
	for k := range e.tombstones {
		if k != "" {
			ctrlBlocked[k] = false
		}
	}
	for k, v := range e.blockedTargets {
		if v && k != "" {
			ctrlBlocked[k] = true
		}
	}
	ctrlRules := e.ignoreRules
	if ctrlRules == nil {
		ctrlRules = []dpidlg.IgnoreRule{}
	}
	ctrl := leakGuardCtrlFile{
		Capacity:       e.cfg.Capacity,
		CooldownSec:    e.cfg.CooldownSec,
		NotifyEnabled:  e.cfg.NotifyEnabled,
		LockscreenMask: e.cfg.LockscreenMask,
		ClearSeq:       e.clearSeq.Load(),
		ClearedAt:      e.clearedAt,
		BlockedTargets: ctrlBlocked,
		IgnoreRules:    ctrlRules,
		UpdatedAt:      now,
	}
	cb, err := json.MarshalIndent(ctrl, "", "  ")
	if err != nil {
		return err
	}
	return writeLeakGuardAtomic0600(e.ctrlPath(), cb)
}

func (e *leakGuardEngine) saveStateLocked() error {
	if e.srv == nil || e.srv.hncDir == "" {
		return nil
	}
	now := time.Now().Unix()
	e.pruneTombstonesLocked(now)
	activeBlocked := make(map[string]bool, len(e.blockedTargets))
	for k, v := range e.blockedTargets {
		if v && k != "" {
			activeBlocked[k] = true
		}
	}

	pf := leakGuardPersistFile{
		Config:         e.cfg,
		BlockedTargets: activeBlocked,
		IgnoreRules:    e.ignoreRules,
		UndoStack:      e.undoStack,
		ClearSeq:       e.clearSeq.Load(),
		ClearedAt:      e.clearedAt,
	}
	if pb, err := json.MarshalIndent(pf, "", "  "); err == nil {
		if werr := writeLeakGuardAtomic0600(e.persistPath(), pb); werr != nil {
			return werr
		}
	}
	return e.writeCtrlFileLocked(now)
}

// ReloadFromDisk 在整机备份恢复后从磁盘重新加载 LeakGuard 配置并同步 run/leakguard_ctrl.json。
func (e *leakGuardEngine) ReloadFromDisk() {
	if e == nil || e.srv == nil || e.srv.hncDir == "" {
		return
	}
	cbNow := readConnBlocks(e.srv.hncDir)
	e.mu.Lock()
	e.cfg = defaultLeakGuardConfig()
	e.blockedTargets = make(map[string]bool)
	e.tombstones = make(map[string]bool)
	e.tombstoneAt = make(map[string]int64)
	e.ignoreRules = nil
	e.undoStack = nil
	e.mergedAliasIDs = make(map[string]string)
	e.ignoredSeenIDs = make(map[string]int64)
	e.hasEventsStat = false
	e.loadPersistedLocked()
	if len(e.events) > e.cfg.Capacity {
		e.events = append([]LeakEvent(nil), e.events[len(e.events)-e.cfg.Capacity:]...)
	}
	_, purgedIDs := e.purgeIgnoredEventsWithIDsLocked()
	rulesSnap := make([]dpidlg.IgnoreRule, len(e.ignoreRules))
	copy(rulesSnap, e.ignoreRules)
	e.recomputeEventsBlockedLocked(cbNow)
	_ = e.writeCtrlFileLocked(time.Now().Unix())
	e.mu.Unlock()
	e.purgeAlertsMatching(purgedIDs, rulesSnap, true)
	e.notifySSEChanged()
}

func (st *v6ServerState) reloadAllFromDisk() {
	if st == nil {
		return
	}
	if st.leakGuard != nil {
		st.leakGuard.ReloadFromDisk()
	}
	if st.express != nil {
		st.express.ReloadFromDisk()
	}
	if st.leash != nil {
		st.leash.ReloadFromDisk()
	}
	if st.thermo != nil {
		st.thermo.ReloadFromDisk()
	}
	if st.selfFirewall != nil {
		st.selfFirewall.ReloadFromDisk()
	}
}

func (e *leakGuardEngine) peerSelfFirewall() *selfFirewallEngine {
	if e == nil || e.srv == nil {
		return nil
	}
	if v, ok := v6Registry.Load(e.srv); ok {
		if st, ok2 := v.(*v6ServerState); ok2 && st != nil {
			return st.selfFirewall
		}
	}
	return nil
}

// ── 防注入参数清洗与防锁屏社死打码器 ─────────────────────────────────────────

// sanitizeLeakNotifyArg 严格剥离所有控制字符、换行符、制表符、引号及危险元字符。
func sanitizeLeakNotifyArg(in string, maxRunes int) string {
	if maxRunes <= 0 {
		maxRunes = 160
	}
	var b strings.Builder
	b.Grow(len(in))
	lastSpace := false
	count := 0
	for _, r := range in {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			if !lastSpace && count > 0 {
				b.WriteByte(' ')
				lastSpace = true
				count++
			}
			continue
		}
		switch r {
		case '`', '$', ';', '|', '&', '<', '>', '\\', '"', '\'', '\u0000':
			continue
		}
		if unicode.IsSpace(r) {
			if !lastSpace && count > 0 {
				b.WriteByte(' ')
				lastSpace = true
				count++
			}
		} else {
			b.WriteRune(r)
			lastSpace = false
			count++
		}
		if count >= maxRunes {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// maskLeakRawValue 对敏感值中间位脱敏以防锁屏通知窥探（如 13812345678 -> 138****5678）。
func maskLeakRawValue(raw string) string {
	rs := []rune(strings.TrimSpace(raw))
	n := len(rs)
	switch {
	case n == 0:
		return "****"
	case n <= 2:
		return "****"
	case n <= 5:
		return string(rs[:1]) + "****" + string(rs[n-1:])
	case n <= 10:
		return string(rs[:2]) + "****" + string(rs[n-2:])
	case n == 11:
		return string(rs[:3]) + "****" + string(rs[7:])
	default:
		maskLen := n - 8
		if maskLen > 8 {
			maskLen = 8
		}
		return string(rs[:4]) + strings.Repeat("*", maskLen) + string(rs[n-4:])
	}
}

func normalizeLeakOrigin(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case leakOriginHost, "local", "self":
		return leakOriginHost
	default:
		return leakOriginHotspot
	}
}

func leakTypeDisplayName(leakType string) string {
	switch strings.ToLower(strings.TrimSpace(leakType)) {
	case "phone", "mobile":
		return "手机号"
	case "id_card", "idcard", "cn_id":
		return "身份证号"
	case "credential", "credentials":
		return "账号凭据/Token"
	case "password", "passwd", "pwd":
		return "明文密码"
	case "token", "bearer", "api_key", "apikey", "jwt":
		return "认证凭据/Token"
	case "bank_card", "card":
		return "银行卡号"
	case "email":
		return "邮箱地址"
	case "device_id", "deviceid", "imei", "imsi", "oaid", "android_id":
		return "设备唯一标识"
	case "gps", "location":
		return "精准定位坐标"
	case "mac_addr", "macaddr", "mac":
		return "硬件 MAC 地址"
	case "cookie", "session":
		return "会话 Cookie"
	default:
		if leakType == "" {
			return "敏感字段"
		}
		return leakType
	}
}

func formatLeakNotificationBody(ev LeakEvent, lockscreenMask bool) string {
	dev := sanitizeLeakNotifyArg(ev.DeviceName, 40)
	if normalizeLeakOrigin(ev.Origin) == leakOriginHost {
		if ev.AppName != "" {
			dev = sanitizeLeakNotifyArg("本机·"+ev.AppName, 44)
		} else if ev.Pkg != "" {
			dev = sanitizeLeakNotifyArg("本机·"+ev.Pkg, 44)
		}
	}
	if dev == "" {
		if ev.MAC != "" {
			dev = sanitizeLeakNotifyArg(ev.MAC, 24)
		} else {
			dev = sanitizeLeakNotifyArg(ev.SrcIP, 40)
		}
	}
	if dev == "" {
		dev = "未知设备"
	}
	host := sanitizeLeakNotifyArg(ev.DstHost, 64)
	if host == "" {
		host = sanitizeLeakNotifyArg(ev.DstIP, 45)
	}
	if host == "" {
		host = "未知目标"
	}
	lt := sanitizeLeakNotifyArg(ev.LeakType, 32)
	if lt == "" {
		lt = "sensitive"
	}
	val := ev.RawValue
	if lockscreenMask {
		val = maskLeakRawValue(val)
	}
	safeVal := sanitizeLeakNotifyArg(val, 80)
	raw := fmt.Sprintf("[%s] 向 [%s] 明文泄露 [%s]: [%s]", dev, host, lt, safeVal)
	return sanitizeLeakNotifyArg(raw, 220)
}

func (e *leakGuardEngine) postAndroidNotificationAsync(ev LeakEvent, lockscreenMask bool) {
	execFn := e.notifyExec
	if execFn == nil {
		return
	}
	sem := e.notifySem
	if sem != nil {
		select {
		case sem <- struct{}{}:
		default:
			// ColorOS Binder 卡死保护: 最多并发 2 个系统通知子进程, 满载时非阻塞丢弃
			return
		}
	}
	title := sanitizeLeakNotifyArg("HNC LeakGuard · 明文隐私泄露预警", 48)
	tag := "hnc_leakguard"
	body := formatLeakNotificationBody(ev, lockscreenMask)
	go func() {
		if sem != nil {
			defer func() { <-sem }()
		}
		ctx, cancel := context.WithTimeout(context.Background(), leakNotifyTimeout)
		defer cancel()
		_ = execFn(ctx, leakCmdBinPath, "notification", "post", "-t", title, tag, body)
	}()
}

// ── 事件解析、设备名实时补齐与封锁状态联动 ──────────────────────────────────

func computeLeakEventID(ev LeakEvent) string {
	if id := strings.TrimSpace(ev.ID); id != "" {
		return id
	}
	if normalizeLeakOrigin(ev.Origin) == leakOriginHost {
		sum := sha1.Sum([]byte(fmt.Sprintf("host|%d|%d|%s|%s|%s|%s|%s",
			ev.Ts, ev.UID, strings.ToLower(ev.Pkg), ev.SrcIP, strings.ToLower(ev.DstHost), ev.LeakType, ev.RawValue)))
		return "lg_" + hex.EncodeToString(sum[:8])
	}
	sum := sha1.Sum([]byte(fmt.Sprintf("%d|%s|%s|%s|%s|%s",
		ev.Ts, strings.ToLower(ev.MAC), ev.SrcIP, strings.ToLower(ev.DstHost), ev.LeakType, ev.RawValue)))
	return "lg_" + hex.EncodeToString(sum[:8])
}

func parseFlexibleLeakEvent(m map[string]any) (LeakEvent, bool) {
	if len(m) == 0 {
		return LeakEvent{}, false
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok && v != nil {
				if s, ok2 := v.(string); ok2 && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
		return ""
	}
	i64 := func(keys ...string) int64 {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				if n, ok2 := toInt64(v); ok2 && n > 0 {
					return n
				}
			}
		}
		return 0
	}
	var srcPort uint16
	if sp := i64("src_port", "sport", "local_port"); sp > 0 && sp <= 65535 {
		srcPort = uint16(sp)
	}
	ev := LeakEvent{
		ID:         str("id", "event_id"),
		Ts:         i64("ts", "timestamp", "time"),
		Origin:     normalizeLeakOrigin(str("origin", "source_domain")),
		UID:        int(i64("uid", "app_uid")),
		Pkg:        str("pkg", "package", "package_name"),
		AppName:    str("app_name", "app_label"),
		MAC:        strings.ToLower(str("mac", "client_mac")),
		SrcIP:      str("src_ip", "client_ip", "ip", "src"),
		DeviceName: str("device_name", "hostname", "device"),
		DstHost:    strings.ToLower(str("dst_host", "host", "domain", "dst")),
		DstIP:      str("dst_ip", "dst"),
		SrcPort:    srcPort,
		DstPort:    int(i64("dst_port", "dport", "port")),
		Proto:      strings.ToLower(str("proto", "protocol")),
		Method:     strings.ToUpper(str("method", "http_method")),
		Path:       str("path", "url", "uri"),
		LeakType:   str("leak_type", "type", "kind"),
		LeakLabel:  str("leak_label", "label"),
		RawValue:   str("raw_value", "value", "secret"),
		RawSnippet: str("raw_snippet", "snippet", "payload"),
		HitCount:   i64("hit_count", "hits"),
		fieldKey:   str("field_key"),
	}
	if b, ok := m["is_blocked"].(bool); ok {
		ev.IsBlocked = b
	}
	if ev.DstHost == "" && ev.DstIP != "" {
		ev.DstHost = ev.DstIP
	}
	if ev.DstHost == "" && ev.RawValue == "" && ev.RawSnippet == "" {
		return LeakEvent{}, false
	}
	if ev.Ts <= 0 {
		ev.Ts = time.Now().Unix()
	}
	if ev.LeakType == "" {
		ev.LeakType = "plaintext"
	}
	if ev.LeakLabel == "" {
		ev.LeakLabel = leakTypeDisplayName(ev.LeakType)
	}
	ev.ID = computeLeakEventID(ev)
	return ev, true
}

func decodeLeakEventsPayload(raw []byte) []LeakEvent {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	var out []LeakEvent
	if trimmed[0] == '{' {
		var obj map[string]any
		if json.Unmarshal(trimmed, &obj) == nil {
			for _, key := range []string{"events", "items", "records"} {
				if arr, ok := obj[key].([]any); ok {
					for _, item := range arr {
						if m, ok2 := item.(map[string]any); ok2 {
							if ev, ok3 := parseFlexibleLeakEvent(m); ok3 {
								out = append(out, ev)
							}
						}
					}
					return out
				}
			}
		}
	}
	if trimmed[0] == '[' {
		var arr []map[string]any
		if json.Unmarshal(trimmed, &arr) == nil {
			for _, m := range arr {
				if ev, ok := parseFlexibleLeakEvent(m); ok {
					out = append(out, ev)
				}
			}
			return out
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(trimmed))
	sc.Buffer(make([]byte, 4096), 512*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if json.Unmarshal(line, &m) == nil {
			if ev, ok := parseFlexibleLeakEvent(m); ok {
				out = append(out, ev)
			}
		}
	}
	return out
}

func hexNibbleByte(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func percentDecodeLeakValue(s string) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := hexNibbleByte(s[i+1])
			lo, ok2 := hexNibbleByte(s[i+2])
			if ok1 && ok2 {
				b.WriteByte((hi << 4) | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func normalizeValidLeakMAC(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) != 17 {
		return ""
	}
	sep := s[2]
	if sep != ':' && sep != '-' {
		return ""
	}
	var b [6]byte
	for idx := 0; idx < 6; idx++ {
		pos := idx * 3
		if idx > 0 && s[pos-1] != sep {
			return ""
		}
		hi, ok1 := hexNibbleByte(s[pos])
		lo, ok2 := hexNibbleByte(s[pos+1])
		if !ok1 || !ok2 {
			return ""
		}
		b[idx] = (hi << 4) | lo
	}
	if b[0] == b[1] && b[1] == b[2] && b[2] == b[3] && b[3] == b[4] && b[4] == b[5] {
		return ""
	}
	if b[0]&0x01 != 0 {
		return ""
	}
	if b == [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00} {
		return ""
	}
	return strings.ReplaceAll(s, "-", ":")
}

func isAllSameASCII(s string) bool {
	if len(s) == 0 {
		return true
	}
	c0 := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != c0 {
			return false
		}
	}
	return true
}

func isAllDigitsStr(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func validLeakLuhnDigits(digits string) bool {
	if !isAllDigitsStr(digits) || isAllSameASCII(digits) {
		return false
	}
	sum := 0
	parity := len(digits) % 2
	for i := 0; i < len(digits); i++ {
		d := int(digits[i] - '0')
		if i%2 == parity {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

func isLeakSnakeVersionTag(s string) bool {
	hasDigit, hasLower, hasUpper, hasOther := false, false, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c == '_' || c == '-':
		default:
			hasOther = true
		}
	}
	if !hasDigit && !hasOther && !(hasLower && hasUpper) {
		return true
	}
	if strings.ContainsRune(s, '_') {
		parts := strings.Split(s, "_")
		if len(parts) >= 3 {
			maxSeg := 0
			for _, p := range parts {
				if len(p) > maxSeg {
					maxSeg = len(p)
				}
			}
			if maxSeg < 8 {
				return true
			}
		}
	}
	return false
}

func leakValueDiversityEntropy(s string) (int, float64) {
	n := len(s)
	if n == 0 {
		return 0, 0
	}
	var counts [256]int
	distinct := 0
	for i := 0; i < n; i++ {
		b := s[i]
		if counts[b] == 0 {
			distinct++
		}
		counts[b]++
	}
	invN := 1.0 / float64(n)
	entropy := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) * invN
			entropy -= p * math.Log2(p)
		}
	}
	return distinct, entropy
}

// isStaleDirtyLeakEvent 过滤磁盘历史遗留的假阳性脏事件（如 02:00:00:00:00:00 占位 MAC、
// 组播/全同字节 MAC、9774d56d682e549c / permission_denied 占位设备号、非 Cookie/低熵 sid）。
func isStaleDirtyLeakEvent(ev LeakEvent) bool {
	lt := strings.ToLower(strings.TrimSpace(ev.LeakType))
	rawVal := strings.TrimSpace(percentDecodeLeakValue(ev.RawValue))
	fk := strings.ToLower(strings.TrimSpace(ev.fieldKey))

	switch lt {
	case "mac_addr", "macaddr", "mac", "bssid", "wifi_mac":
		return normalizeValidLeakMAC(rawVal) == ""

	case "device_id", "deviceid", "imei", "imeisv", "imsi", "meid", "oaid", "android_id", "androidid", "idfa", "idfv":
		if len(rawVal) < 14 || len(rawVal) > 64 {
			return true
		}
		var comp strings.Builder
		comp.Grow(len(rawVal))
		for i := 0; i < len(rawVal); i++ {
			c := rawVal[i]
			switch {
			case c == '-':
			case c >= '0' && c <= '9':
				comp.WriteByte(c)
			case c >= 'a' && c <= 'f':
				comp.WriteByte(c)
			case c >= 'A' && c <= 'F':
				comp.WriteByte(c + ('a' - 'A'))
			default:
				return true
			}
		}
		cs := comp.String()
		if len(cs) == 0 || isAllSameASCII(cs) || cs == "9774d56d682e549c" {
			return true
		}
		if lt == "imei" || fk == "imei" {
			return len(rawVal) != 15 || !validLeakLuhnDigits(rawVal)
		}
		return false

	case "credential", "credentials":
		if rawVal == "" {
			return true
		}
		switch strings.ToLower(rawVal) {
		case "true", "false", "null", "undefined", "nil", "none", "unknown", "permission_denied":
			return true
		}
		if sp := strings.IndexAny(rawVal, " \t"); sp > 0 {
			scheme := rawVal[:sp]
			cred := strings.TrimSpace(rawVal[sp+1:])
			if (strings.EqualFold(scheme, "bearer") || strings.EqualFold(scheme, "basic")) && len(cred) >= 8 && !isAllSameASCII(cred) {
				return false
			}
		}
		if strings.HasPrefix(rawVal, "eyJ") && strings.Count(rawVal, ".") == 2 && len(rawVal) >= 16 {
			return false
		}
		if fk == "password" || fk == "passwd" || fk == "pwd" {
			return len(rawVal) < 6 || len(rawVal) > 128 || isAllSameASCII(rawVal)
		}
		lowSnip := strings.ToLower(ev.RawSnippet)
		lowPath := strings.ToLower(ev.Path)
		inCookie := strings.Contains(lowSnip, "cookie:")
		if fk == "sid" && !inCookie {
			return true
		}
		if fk == "" && !inCookie &&
			(strings.Contains(lowSnip, "sid=") || strings.Contains(lowSnip, `"sid"`) || strings.Contains(lowPath, "sid=")) {
			return true
		}
		if len(rawVal) < 16 || len(rawVal) > 2048 || isAllDigitsStr(rawVal) || isAllSameASCII(rawVal) || isLeakSnakeVersionTag(rawVal) {
			return true
		}
		distinct, entropy := leakValueDiversityEntropy(rawVal)
		return distinct < 8 || entropy < 3.3
	}
	return false
}

func alertToDPIDLeakEvent(a alert.Alert) dpidlg.LeakEvent {
	var origin, dstHost, leakType, pkg, srcIP string
	var uid int
	if a.Extra != nil {
		origin = strings.TrimSpace(asString(a.Extra["origin"]))
		dstHost = strings.TrimSpace(asString(a.Extra["dst_host"]))
		leakType = strings.TrimSpace(asString(a.Extra["leak_type"]))
		pkg = strings.TrimSpace(asString(a.Extra["pkg"]))
		srcIP = strings.TrimSpace(asString(a.Extra["src_ip"]))
		if u64, ok := toInt64(a.Extra["uid"]); ok && u64 > 0 {
			uid = int(u64)
		}
	}
	if srcIP == "" {
		srcIP = strings.TrimSpace(a.IP)
	}
	return dpidlg.LeakEvent{
		Origin:   origin,
		UID:      uid,
		Pkg:      pkg,
		MAC:      strings.ToLower(strings.TrimSpace(a.MAC)),
		SrcIP:    srcIP,
		ClientIP: srcIP,
		DstHost:  dstHost,
		LeakType: leakType,
	}
}

func isDirtyLeakGuardAlert(a alert.Alert) bool {
	if a.Kind != "leakguard" {
		return false
	}
	lowDetail := strings.ToLower(percentDecodeLeakValue(a.Detail))
	for _, marker := range []string{
		"02:00:00:00:00:00",
		"00:00:00:00:00:00",
		"ff:ff:ff:ff:ff:ff",
		"9774d56d682e549c",
		"permission_denied",
		"00000000-0000-0000-0000-000000000000",
	} {
		if strings.Contains(lowDetail, marker) {
			return true
		}
	}
	if a.Extra != nil {
		if rv := strings.TrimSpace(asString(a.Extra["raw_value"])); rv != "" {
			lt := strings.TrimSpace(asString(a.Extra["leak_type"]))
			if isStaleDirtyLeakEvent(LeakEvent{LeakType: lt, RawValue: rv}) {
				return true
			}
		}
	}
	return false
}

func (e *leakGuardEngine) purgeAlertsMatching(dropIDs map[string]bool, rules []dpidlg.IgnoreRule, dropDirty bool) {
	if e == nil || e.srv == nil || e.srv.hncDir == "" {
		return
	}
	if len(dropIDs) == 0 && len(rules) == 0 && !dropDirty {
		return
	}
	acfg := alert.NewConfig(e.srv.hncDir)
	if st, err := os.Stat(acfg.AlertsJSONLPath); err != nil || st.IsDir() {
		return
	}
	_ = alert.PurgeLeakGuard(acfg, func(a alert.Alert) bool {
		if len(dropIDs) > 0 && dropIDs[a.ID] {
			return false
		}
		if dropDirty && isDirtyLeakGuardAlert(a) {
			return false
		}
		if len(rules) > 0 {
			dev := alertToDPIDLeakEvent(a)
			for i := range rules {
				if rules[i].MatchesEvent(dev) {
					return false
				}
			}
		}
		return true
	})
}

// buildDeviceDirectory 实时关联 s.hncDir 下的 device_names.json / devices.json / dpi_devid.json。
func (s *server) buildDeviceDirectory() (nameByMAC map[string]string, macByIP map[string]string) {
	nameByMAC = make(map[string]string)
	macByIP = make(map[string]string)
	if s == nil || s.hncDir == "" {
		return nameByMAC, macByIP
	}

	for mac, ips := range s.deviceIPsByMAC() {
		m := strings.ToLower(strings.TrimSpace(mac))
		for _, ip := range ips {
			macByIP[ip] = m
		}
	}

	for mac, id := range s.dpiIdentByMAC() {
		if hn := strings.TrimSpace(asString(id["hostname"])); hn != "" {
			nameByMAC[strings.ToLower(mac)] = hn
		}
	}

	if raw, err := os.ReadFile(filepath.Join(s.hncDir, "data", "devices.json")); err == nil {
		var dm map[string]map[string]any
		if json.Unmarshal(raw, &dm) == nil {
			for mac, d := range dm {
				m := strings.ToLower(strings.TrimSpace(mac))
				if ip := strings.TrimSpace(asString(d["ip"])); ip != "" && ip != "-" {
					if parsed := net.ParseIP(ip); parsed != nil {
						macByIP[parsed.String()] = m
					}
				}
				dropJunkHostname(d)
				if hn := strings.TrimSpace(asString(d["hostname"])); hn != "" {
					nameByMAC[m] = hn
				}
			}
		}
	}

	if raw, err := os.ReadFile(filepath.Join(s.hncDir, "data", "device_names.json")); err == nil {
		var nm map[string]string
		if json.Unmarshal(raw, &nm) == nil {
			for mac, label := range nm {
				if trimmed := strings.TrimSpace(label); trimmed != "" {
					nameByMAC[strings.ToLower(strings.TrimSpace(mac))] = trimmed
				}
			}
		}
	}
	return nameByMAC, macByIP
}

func normalizeBlockTarget(raw string) (kind, val string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", false
	}
	if strings.HasPrefix(s, "[") {
		if host, _, err := net.SplitHostPort(s); err == nil {
			s = host
		} else {
			s = strings.Trim(s, "[]")
		}
	} else if strings.Count(s, ":") == 1 {
		if host, port, err := net.SplitHostPort(s); err == nil && port != "" {
			if _, perr := strconv.Atoi(port); perr == nil {
				s = host
			}
		}
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() || isPrivateIP(ip.String()) || isNonExpandableBlockIP(ip.String()) {
			return "", "", false
		}
		return "ip", ip.String(), true
	}
	d := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(s), "*."), ".")
	if domainRe.MatchString(d) && len(d) <= 253 {
		return "domain", d, true
	}
	return "", "", false
}

func matchConnBlockTarget(it connBlock, normVal string) bool {
	v := strings.ToLower(strings.TrimSpace(it.Value))
	if v == "" {
		return false
	}
	if it.Kind == "ip" {
		return normVal == v
	}
	if it.Kind == "domain" {
		return normVal == v || strings.HasSuffix(normVal, "."+v)
	}
	return false
}

func hasAnyDeviceConnBlock(cb connBlockFile, normVal string) bool {
	normVal = strings.ToLower(strings.TrimSpace(normVal))
	if normVal == "" {
		return false
	}
	for _, it := range cb.Items {
		if strings.EqualFold(strings.TrimSpace(it.Value), normVal) {
			return true
		}
	}
	return false
}

func matchBlockedHost(hostOrIP string, mac string, cb connBlockFile, lgBlocked map[string]bool) bool {
	_, normVal, ok := normalizeBlockTarget(hostOrIP)
	if !ok {
		normVal = strings.ToLower(strings.TrimSpace(hostOrIP))
	}
	if normVal == "" {
		return false
	}
	mac = strings.ToLower(strings.TrimSpace(mac))
	anyDeviceRuleForTarget := false
	for _, it := range cb.Items {
		if !matchConnBlockTarget(it, normVal) {
			continue
		}
		anyDeviceRuleForTarget = true
		itMAC := strings.ToLower(strings.TrimSpace(it.MAC))
		if itMAC == "" || itMAC == "*" || itMAC == "all" || itMAC == "00:00:00:00:00:00" || (mac != "" && itMAC == mac) {
			return true
		}
	}
	if anyDeviceRuleForTarget {
		return false
	}
	for tgt, active := range lgBlocked {
		if !active {
			continue
		}
		if normVal == tgt || strings.HasSuffix(normVal, "."+tgt) {
			return true
		}
	}
	return false
}

func toDPIDLeakEventForMatch(ev LeakEvent) dpidlg.LeakEvent {
	return dpidlg.LeakEvent{
		Origin:   ev.Origin,
		UID:      ev.UID,
		Pkg:      ev.Pkg,
		MAC:      ev.MAC,
		SrcIP:    ev.SrcIP,
		ClientIP: ev.SrcIP,
		DstHost:  ev.DstHost,
		DstIP:    ev.DstIP,
		LeakType: ev.LeakType,
	}
}

func (e *leakGuardEngine) matchesIgnoreRuleLocked(ev LeakEvent) bool {
	if len(e.ignoreRules) == 0 {
		return false
	}
	dev := toDPIDLeakEventForMatch(ev)
	for i := range e.ignoreRules {
		if e.ignoreRules[i].MatchesEvent(dev) {
			return true
		}
	}
	return false
}

func effectiveUndoTargetScope(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case leakTargetScopeHost:
		return leakTargetScopeHost
	case leakTargetScopeBoth:
		return leakTargetScopeBoth
	default:
		return leakTargetScopeHotspot
	}
}

func parseLeakEventsScopeQuery(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", leakScopeAll:
		return leakScopeAll, true
	case leakScopeHotspot:
		return leakScopeHotspot, true
	case leakScopeHost:
		return leakScopeHost, true
	default:
		return "", false
	}
}

func parseLeakTargetScope(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", leakTargetScopeHotspot:
		return leakTargetScopeHotspot, true
	case leakTargetScopeHost:
		return leakTargetScopeHost, true
	case leakTargetScopeBoth:
		return leakTargetScopeBoth, true
	default:
		return "", false
	}
}

func (e *leakGuardEngine) purgeIgnoredEventsLocked() int {
	n, _ := e.purgeIgnoredEventsWithIDsLocked()
	return n
}

func (e *leakGuardEngine) purgeIgnoredEventsWithIDsLocked() (int, map[string]bool) {
	if len(e.events) == 0 || len(e.ignoreRules) == 0 {
		return 0, nil
	}
	if e.ignoredSeenIDs == nil {
		e.ignoredSeenIDs = make(map[string]int64)
	}
	kept := make([]LeakEvent, 0, len(e.events))
	var purgedIDs map[string]bool
	purged := 0
	var removedHits, removedHostHits, removedHotspotHits int64
	var keptHostCnt, keptHotspotCnt int64
	for _, ev := range e.events {
		isHost := normalizeLeakOrigin(ev.Origin) == leakOriginHost
		if e.matchesIgnoreRuleLocked(ev) {
			purged++
			if purgedIDs == nil {
				purgedIDs = make(map[string]bool)
			}
			purgedIDs[ev.ID] = true
			hc := ev.HitCount
			if hc <= 0 {
				hc = 1
			}
			removedHits += hc
			if isHost {
				removedHostHits += hc
			} else {
				removedHotspotHits += hc
			}
			delete(e.seenIDs, ev.ID)
			for aliasID, canonID := range e.mergedAliasIDs {
				if canonID == ev.ID {
					purgedIDs[aliasID] = true
					delete(e.seenIDs, aliasID)
					delete(e.mergedAliasIDs, aliasID)
				}
			}
			e.ignoredSeenIDs[ev.ID] = hc
			e.ignoredHits.Add(hc)
			continue
		}
		if isHost {
			keptHostCnt++
		} else {
			keptHotspotCnt++
		}
		kept = append(kept, ev)
	}
	if purged > 0 {
		e.events = kept
		cur := e.totalHits.Load()
		next := cur - removedHits
		if next < int64(len(kept)) {
			next = int64(len(kept))
		}
		e.totalHits.Store(next)

		if removedHostHits > 0 {
			nh := e.hostHits.Load() - removedHostHits
			if nh < keptHostCnt {
				nh = keptHostCnt
			}
			e.hostHits.Store(nh)
		}
		if removedHotspotHits > 0 {
			np := e.hotspotHits.Load() - removedHotspotHits
			if np < keptHotspotCnt {
				np = keptHotspotCnt
			}
			e.hotspotHits.Store(np)
		}
	}
	return purged, purgedIDs
}

func (e *leakGuardEngine) recomputeEventsBlockedLocked(cb connBlockFile) {
	sf := e.peerSelfFirewall()
	for i := range e.events {
		ev := &e.events[i]
		ev.Origin = normalizeLeakOrigin(ev.Origin)
		if ev.Origin == leakOriginHost {
			ev.IsBlocked = sf != nil && sf.IsHostEventBlocked(ev.UID, ev.DstHost, ev.DstIP, ev.DstPort, ev.Proto)
			continue
		}
		blocked := matchBlockedHost(ev.DstHost, ev.MAC, cb, e.blockedTargets)
		if !blocked && ev.DstIP != "" {
			blocked = matchBlockedHost(ev.DstIP, ev.MAC, cb, e.blockedTargets)
		}
		ev.IsBlocked = blocked
	}
}

func sameSortedMACs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (e *leakGuardEngine) pushUndoLocked(entry LeakBlockUndoEntry) {
	entryScope := effectiveUndoTargetScope(entry.TargetScope)
	entry.TargetScope = entryScope
	filtered := make([]LeakBlockUndoEntry, 0, len(e.undoStack)+1)
	for _, cur := range e.undoStack {
		if cur.Kind == entry.Kind &&
			cur.DstHost == entry.DstHost &&
			cur.UID == entry.UID &&
			cur.AlsoIP == entry.AlsoIP &&
			effectiveUndoTargetScope(cur.TargetScope) == entryScope &&
			sameSortedMACs(cur.MACs, entry.MACs) {
			continue
		}
		filtered = append(filtered, cur)
	}
	filtered = append(filtered, entry)
	if len(filtered) > leakMaxUndoStack {
		filtered = append([]LeakBlockUndoEntry(nil), filtered[len(filtered)-leakMaxUndoStack:]...)
	}
	e.undoStack = filtered
}

func (e *leakGuardEngine) pruneUndoOnUnblockLocked(kind, normVal string, unblockedMACs []string, unblockedScope string, unblockedUID int) {
	if len(e.undoStack) == 0 {
		return
	}
	uScope := effectiveUndoTargetScope(unblockedScope)
	unblockHotspot := uScope == leakTargetScopeHotspot || uScope == leakTargetScopeBoth
	unblockHost := uScope == leakTargetScopeHost || uScope == leakTargetScopeBoth

	unblkSet := make(map[string]bool, len(unblockedMACs))
	for _, m := range unblockedMACs {
		unblkSet[strings.ToLower(strings.TrimSpace(m))] = true
	}
	kept := make([]LeakBlockUndoEntry, 0, len(e.undoStack))
	for _, cur := range e.undoStack {
		if cur.Kind != kind || cur.DstHost != normVal {
			kept = append(kept, cur)
			continue
		}
		curScope := effectiveUndoTargetScope(cur.TargetScope)
		hasHotspot := curScope == leakTargetScopeHotspot || curScope == leakTargetScopeBoth
		hasHost := curScope == leakTargetScopeHost || curScope == leakTargetScopeBoth

		if unblockHost && hasHost {
			if cur.Kind != "ip" || unblockedUID <= 0 || cur.UID == 0 || cur.UID == unblockedUID {
				hasHost = false
				cur.UID = 0
			}
		}
		if unblockHotspot && hasHotspot {
			if len(cur.MACs) == 0 || len(unblkSet) == 0 {
				hasHotspot = false
				cur.MACs = nil
			} else {
				var rem []string
				for _, m := range cur.MACs {
					if !unblkSet[strings.ToLower(strings.TrimSpace(m))] {
						rem = append(rem, m)
					}
				}
				cur.MACs = rem
				if len(rem) == 0 {
					hasHotspot = false
				}
			}
		}

		switch {
		case hasHotspot && hasHost:
			cur.TargetScope = leakTargetScopeBoth
			kept = append(kept, cur)
		case hasHotspot:
			cur.TargetScope = leakTargetScopeHotspot
			cur.UID = 0
			kept = append(kept, cur)
		case hasHost:
			cur.TargetScope = leakTargetScopeHost
			cur.MACs = nil
			cur.AlsoIP = ""
			kept = append(kept, cur)
		}
	}
	e.undoStack = kept
}

func (e *leakGuardEngine) hasHostDomainInUndoLocked(normDomain string) bool {
	normDomain = strings.ToLower(strings.TrimSpace(normDomain))
	if normDomain == "" {
		return false
	}
	for _, cur := range e.undoStack {
		sc := effectiveUndoTargetScope(cur.TargetScope)
		if cur.Kind == "domain" && (sc == leakTargetScopeHost || sc == leakTargetScopeBoth) && strings.EqualFold(cur.DstHost, normDomain) {
			return true
		}
	}
	return false
}

func (e *leakGuardEngine) hasHostIPInUndoLocked(uid int, normIP string) bool {
	normIP = strings.ToLower(strings.TrimSpace(normIP))
	if uid <= 0 || normIP == "" {
		return false
	}
	for _, cur := range e.undoStack {
		sc := effectiveUndoTargetScope(cur.TargetScope)
		if cur.Kind == "ip" && cur.UID == uid && (sc == leakTargetScopeHost || sc == leakTargetScopeBoth) && strings.EqualFold(cur.DstHost, normIP) {
			return true
		}
	}
	return false
}

// DiskReadCount 返回 syncFromDisk 实际触发 os.ReadFile 的累计次数（单测核验 stat 免读短路）。
func (e *leakGuardEngine) DiskReadCount() int64 {
	if e == nil {
		return 0
	}
	return e.diskReadCount.Load()
}

func (e *leakGuardEngine) syncFromDisk() []LeakEvent {
	if e == nil || e.srv == nil || e.srv.hncDir == "" {
		return nil
	}
	epath := e.dpidEventsPath()
	st, err := os.Stat(epath)
	if err != nil || st.IsDir() || st.Size() <= 0 {
		return nil
	}
	mtimeNs := st.ModTime().UnixNano()
	sz := st.Size()

	e.mu.Lock()
	unchanged := e.hasEventsStat && e.lastEventsMtimeNs == mtimeNs && e.lastEventsSize == sz
	e.mu.Unlock()
	if unchanged {
		return nil
	}

	raw, err := os.ReadFile(epath)
	if err != nil || len(raw) == 0 {
		return nil
	}
	e.diskReadCount.Add(1)

	e.mu.Lock()
	e.hasEventsStat = true
	e.lastEventsMtimeNs = mtimeNs
	e.lastEventsSize = sz
	rulesSnap := make([]dpidlg.IgnoreRule, len(e.ignoreRules))
	copy(rulesSnap, e.ignoreRules)
	e.mu.Unlock()

	parsedAll := decodeLeakEventsPayload(raw)
	if len(parsedAll) == 0 {
		return nil
	}
	var parsed []LeakEvent
	var dirtyIDs map[string]bool
	for _, ev := range parsedAll {
		if isStaleDirtyLeakEvent(ev) {
			if dirtyIDs == nil {
				dirtyIDs = make(map[string]bool)
			}
			dirtyIDs[ev.ID] = true
			continue
		}
		parsed = append(parsed, ev)
	}
	if len(dirtyIDs) > 0 {
		if cleanDoc, merr := json.Marshal(map[string]any{"events": parsed}); merr == nil {
			cleanDoc = append(cleanDoc, '\n')
			if writeLeakGuardAtomic0600(epath, cleanDoc) == nil {
				if stAfter, serr := os.Stat(epath); serr == nil {
					e.mu.Lock()
					e.hasEventsStat = true
					e.lastEventsMtimeNs = stAfter.ModTime().UnixNano()
					e.lastEventsSize = stAfter.Size()
					e.mu.Unlock()
				}
			}
		}
		e.purgeAlertsMatching(dirtyIDs, rulesSnap, true)
	}
	if len(parsed) == 0 {
		return nil
	}
	return e.IngestEvents(parsed)
}

func isLeakFakeIPStr(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	return v4 != nil && v4[0] == 198 && (v4[1] == 18 || v4[1] == 19)
}

func canonLeakTypeForDedup(raw string) string {
	if c, ok := dpidlg.CanonicalIgnoreLeakType(raw); ok {
		return c
	}
	return strings.ToUpper(strings.TrimSpace(raw))
}

func sameLeakRawValForDedup(leakType, a, b string) bool {
	if a == b {
		return true
	}
	switch canonLeakTypeForDedup(leakType) {
	case "MAC_ADDR":
		ma := normalizeValidLeakMAC(percentDecodeLeakValue(a))
		mb := normalizeValidLeakMAC(percentDecodeLeakValue(b))
		if ma != "" && ma == mb {
			return true
		}
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	case "DEVICE_ID", "ID_CARD":
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	default:
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
}

func sameLeakTargetAndSecret(a, b LeakEvent) bool {
	if !strings.EqualFold(strings.TrimSpace(a.DstHost), strings.TrimSpace(b.DstHost)) {
		return false
	}
	if canonLeakTypeForDedup(a.LeakType) != canonLeakTypeForDedup(b.LeakType) {
		return false
	}
	return sameLeakRawValForDedup(a.LeakType, a.RawValue, b.RawValue)
}

// hostEventAttributionRank 评估本机事件归属质量:
//   2 = 真实业务 App (UID > 0 且非 VPN/代理导管)
//   1 = VPN/代理导管 App (UID > 0 且命中导管包名/UID 集合, 如 FlClash)
//   0 = 未归属/内核转发态 (UID <= 0)
func hostEventAttributionRank(ev LeakEvent, conduitPkgs map[string]bool, conduitUIDs map[int]bool) int {
	if ev.UID <= 0 {
		return 0
	}
	if conduitUIDs[ev.UID] {
		return 1
	}
	if p := strings.ToLower(strings.TrimSpace(ev.Pkg)); p != "" && conduitPkgs[p] {
		return 1
	}
	return 2
}

func loadFastVPNConduitSets(hncDir string) (map[string]bool, map[int]bool) {
	pkgs := buildConduitPkgSet(hncDir)
	uids := make(map[int]bool)
	if hncDir == "" {
		return pkgs, uids
	}
	if b, err := os.ReadFile(filepath.Join(hncDir, "run", "vpn_conduit_uids.json")); err == nil && len(b) > 0 && len(b) < 64<<10 {
		var extra struct {
			UIDs []int    `json:"uids"`
			Pkgs []string `json:"pkgs"`
		}
		if json.Unmarshal(b, &extra) == nil {
			for _, u := range extra.UIDs {
				if u >= 10000 {
					uids[u] = true
				}
			}
			for _, p := range extra.Pkgs {
				if np := strings.ToLower(strings.TrimSpace(p)); np != "" {
					pkgs[np] = true
				}
			}
		}
	}
	return pkgs, uids
}

// IngestEvents 线程安全地摄入一批 LeakEvent（支持单测直接喂入或从 run/leakguard_events.json 合并）。
func (e *leakGuardEngine) IngestEvents(incoming []LeakEvent) []LeakEvent {
	if len(incoming) == 0 {
		return nil
	}
	nameByMAC, macByIP := e.srv.buildDeviceDirectory()
	cb := readConnBlocks(e.srvHncDirSafe())
	sf := e.peerSelfFirewall()

	// 先在锁外补齐本机应用包名与显示名元数据及 VPN/代理导管名单（避免锁内文件 IO）
	prepared := make([]LeakEvent, len(incoming))
	copy(prepared, incoming)
	hasAnyHost := false
	for i := range prepared {
		prepared[i].Origin = normalizeLeakOrigin(prepared[i].Origin)
		if prepared[i].Origin == leakOriginHost {
			hasAnyHost = true
			if sf != nil && prepared[i].UID >= selfFirewallMinAppUID &&
				(prepared[i].Pkg == "" || prepared[i].AppName == "") {
				pkg, appName, _ := sf.resolveLocalAppMetadata(prepared[i].UID, prepared[i].Pkg, prepared[i].AppName)
				if prepared[i].Pkg == "" {
					prepared[i].Pkg = pkg
				}
				if prepared[i].AppName == "" {
					prepared[i].AppName = appName
				}
			}
		}
	}
	var conduitPkgs map[string]bool
	var conduitUIDs map[int]bool
	if hasAnyHost {
		conduitPkgs, conduitUIDs = loadFastVPNConduitSets(e.srvHncDirSafe())
	}

	e.mu.Lock()
	cfg := e.cfg
	clearedAt := e.clearedAt
	if e.ignoredSeenIDs == nil {
		e.ignoredSeenIDs = make(map[string]int64)
	}
	if e.mergedAliasIDs == nil {
		e.mergedAliasIDs = make(map[string]string)
	}
	var added []LeakEvent
	var toNotify []LeakEvent
	var staleAlertIDs map[string]bool

	for _, ev := range prepared {
		if ev.Ts <= 0 {
			ev.Ts = time.Now().Unix()
		}
		if clearedAt > 0 && ev.Ts < clearedAt {
			continue
		}
		if ev.Ts > e.maxSeenTs {
			e.maxSeenTs = ev.Ts
		}
		ev.Origin = normalizeLeakOrigin(ev.Origin)
		isHost := ev.Origin == leakOriginHost
		if isHost {
			ev.Pkg = strings.ToLower(strings.TrimSpace(ev.Pkg))
			ev.AppName = strings.TrimSpace(ev.AppName)
			if ev.DeviceName == "" {
				switch {
				case ev.AppName != "":
					ev.DeviceName = ev.AppName
				case ev.Pkg != "":
					ev.DeviceName = ev.Pkg
				case ev.UID > 0:
					ev.DeviceName = fmt.Sprintf("UID:%d", ev.UID)
				default:
					ev.DeviceName = "本机应用"
				}
			}
		} else {
			if ev.MAC == "" && ev.SrcIP != "" {
				if m := macByIP[ev.SrcIP]; m != "" {
					ev.MAC = m
				}
			}
			ev.MAC = strings.ToLower(strings.TrimSpace(ev.MAC))
			if ev.MAC != "" {
				if nm := nameByMAC[ev.MAC]; nm != "" {
					ev.DeviceName = nm
				}
			}
			if ev.DeviceName == "" {
				if ev.MAC != "" {
					ev.DeviceName = ev.MAC
				} else {
					ev.DeviceName = ev.SrcIP
				}
			}
		}

		if ev.LeakLabel == "" {
			ev.LeakLabel = leakTypeDisplayName(ev.LeakType)
		}
		if ev.HitCount <= 0 {
			ev.HitCount = 1
		}
		ev.ID = computeLeakEventID(ev)

		if e.matchesIgnoreRuleLocked(ev) {
			prev := e.ignoredSeenIDs[ev.ID]
			if ev.HitCount > prev {
				e.ignoredHits.Add(ev.HitCount - prev)
				e.ignoredSeenIDs[ev.ID] = ev.HitCount
			}
			continue
		}

		if isHost {
			ev.IsBlocked = sf != nil && sf.IsHostEventBlocked(ev.UID, ev.DstHost, ev.DstIP, ev.DstPort, ev.Proto)
		} else {
			blocked := matchBlockedHost(ev.DstHost, ev.MAC, cb, e.blockedTargets)
			if !blocked && ev.DstIP != "" {
				blocked = matchBlockedHost(ev.DstIP, ev.MAC, cb, e.blockedTargets)
			}
			ev.IsBlocked = blocked
		}

		if canonID, aliased := e.mergedAliasIDs[ev.ID]; aliased && canonID != "" {
			continue
		}

		if _, dup := e.seenIDs[ev.ID]; dup {
			for idx := len(e.events) - 1; idx >= 0; idx-- {
				if e.events[idx].ID == ev.ID {
					if e.events[idx].SrcPort == 0 && ev.SrcPort != 0 {
						e.events[idx].SrcPort = ev.SrcPort
					}
					if ev.HitCount > e.events[idx].HitCount {
						delta := ev.HitCount - e.events[idx].HitCount
						e.events[idx].HitCount = ev.HitCount
						e.events[idx].Ts = ev.Ts
						e.events[idx].IsBlocked = ev.IsBlocked
						e.totalHits.Add(delta)
						if isHost {
							e.hostHits.Add(delta)
						} else {
							e.hotspotHits.Add(delta)
						}
					}
					break
				}
			}
			continue
		}

		// B005: 本机跨网卡 <5s 双抓包去重合并（物理口 wlan/rmnet + TUN/Meta 导管口同时捕获同一请求）
		if isHost && ev.MAC == "" {
			mergedCrossIface := false
			evRank := hostEventAttributionRank(ev, conduitPkgs, conduitUIDs)
			for idx := len(e.events) - 1; idx >= 0; idx-- {
				cur := &e.events[idx]
				if normalizeLeakOrigin(cur.Origin) != leakOriginHost || cur.MAC != "" {
					continue
				}
				dt := ev.Ts - cur.Ts
				if dt <= -5 || dt >= 5 {
					continue
				}
				if !sameLeakTargetAndSecret(*cur, ev) {
					continue
				}
				curRank := hostEventAttributionRank(*cur, conduitPkgs, conduitUIDs)
				sameSubj := cur.UID == ev.UID && cur.Pkg == ev.Pkg
				shouldMerge := (!sameSubj && (curRank < 2 || evRank < 2)) ||
					(sameSubj && curRank < 2 && cur.SrcIP != "" && ev.SrcIP != "" && cur.SrcIP != ev.SrcIP)
				if !shouldMerge {
					continue
				}

				if evRank <= curRank {
					if evRank == curRank {
						if cur.UID <= 0 && ev.UID > 0 {
							cur.UID = ev.UID
						}
						if cur.Pkg == "" && ev.Pkg != "" {
							cur.Pkg = ev.Pkg
						}
						if cur.AppName == "" && ev.AppName != "" {
							cur.AppName = ev.AppName
							cur.DeviceName = ev.DeviceName
						}
					}
					if cur.SrcPort == 0 && ev.SrcPort != 0 {
						cur.SrcPort = ev.SrcPort
					}
					if ev.DstIP != "" && (cur.DstIP == "" || (isLeakFakeIPStr(cur.DstIP) && !isLeakFakeIPStr(ev.DstIP))) {
						cur.DstIP = ev.DstIP
					}
					if ev.Ts > cur.Ts {
						cur.Ts = ev.Ts
					}
					if ev.IsBlocked {
						cur.IsBlocked = true
					}
					e.seenIDs[ev.ID] = ev.Ts
					e.mergedAliasIDs[ev.ID] = cur.ID
					for ai := range added {
						if added[ai].ID == cur.ID {
							added[ai] = *cur
						}
					}
					for ni := range toNotify {
						if toNotify[ni].ID == cur.ID {
							toNotify[ni] = *cur
						}
					}
				} else {
					oldID := cur.ID
					oldHit := cur.HitCount
					cur.ID = ev.ID
					cur.UID = ev.UID
					cur.Pkg = ev.Pkg
					cur.AppName = ev.AppName
					cur.DeviceName = ev.DeviceName
					cur.IsBlocked = ev.IsBlocked
					if ev.SrcIP != "" {
						cur.SrcIP = ev.SrcIP
					}
					if ev.SrcPort != 0 {
						cur.SrcPort = ev.SrcPort
					}
					if ev.DstIP != "" && (cur.DstIP == "" || !isLeakFakeIPStr(ev.DstIP)) {
						cur.DstIP = ev.DstIP
					}
					if ev.Ts > cur.Ts {
						cur.Ts = ev.Ts
					}
					if ev.HitCount > oldHit {
						delta := ev.HitCount - oldHit
						cur.HitCount = ev.HitCount
						e.totalHits.Add(delta)
						e.hostHits.Add(delta)
					}
					e.seenIDs[ev.ID] = cur.Ts
					e.mergedAliasIDs[oldID] = cur.ID
					for k, v := range e.mergedAliasIDs {
						if v == oldID {
							e.mergedAliasIDs[k] = cur.ID
						}
					}
					newCdKey := fmt.Sprintf("host:%d:%s|%s|%s", cur.UID, cur.Pkg, strings.ToLower(cur.DstHost), strings.ToLower(cur.LeakType))
					e.cooldownLedger[newCdKey] = cur.Ts

					replacedInBatch := false
					for ai := range added {
						if added[ai].ID == oldID {
							added[ai] = *cur
							replacedInBatch = true
						}
					}
					for ni := range toNotify {
						if toNotify[ni].ID == oldID {
							toNotify[ni] = *cur
							replacedInBatch = true
						}
					}
					if !replacedInBatch {
						if staleAlertIDs == nil {
							staleAlertIDs = make(map[string]bool)
						}
						staleAlertIDs[oldID] = true
						toNotify = append(toNotify, *cur)
					}
				}
				mergedCrossIface = true
				break
			}
			if mergedCrossIface {
				continue
			}
		}

		e.seenIDs[ev.ID] = ev.Ts
		e.events = append(e.events, ev)
		e.totalHits.Add(ev.HitCount)
		if isHost {
			e.hostHits.Add(ev.HitCount)
		} else {
			e.hotspotHits.Add(ev.HitCount)
		}
		added = append(added, ev)

		var cdKey string
		if isHost {
			cdKey = fmt.Sprintf("host:%d:%s|%s|%s", ev.UID, ev.Pkg, strings.ToLower(ev.DstHost), strings.ToLower(ev.LeakType))
		} else {
			devKey := ev.MAC
			if devKey == "" {
				devKey = ev.SrcIP
			}
			cdKey = devKey + "|" + strings.ToLower(ev.DstHost) + "|" + strings.ToLower(ev.LeakType)
		}
		lastTs, had := e.cooldownLedger[cdKey]
		inCooldown := had && cfg.CooldownSec > 0 && (ev.Ts-lastTs) < int64(cfg.CooldownSec)
		if !inCooldown {
			e.cooldownLedger[cdKey] = ev.Ts
			toNotify = append(toNotify, ev)
		}
	}

	if len(e.events) > cfg.Capacity {
		drop := len(e.events) - cfg.Capacity
		e.events = append([]LeakEvent(nil), e.events[drop:]...)
	}
	seenLimit := cfg.Capacity * 4
	if seenLimit < 2048 {
		seenLimit = 2048
	}
	if len(e.seenIDs) > seenLimit {
		keep := make(map[string]int64, len(e.events))
		for _, it := range e.events {
			keep[it.ID] = it.Ts
		}
		e.seenIDs = keep
	}
	if len(e.mergedAliasIDs) > seenLimit {
		live := make(map[string]bool, len(e.events))
		for _, it := range e.events {
			live[it.ID] = true
		}
		nextAliases := make(map[string]string)
		for k, v := range e.mergedAliasIDs {
			if live[v] {
				nextAliases[k] = v
			}
		}
		e.mergedAliasIDs = nextAliases
	}
	if len(e.ignoredSeenIDs) > seenLimit {
		e.ignoredSeenIDs = make(map[string]int64)
	}
	pruneNow := e.maxSeenTs
	if pruneNow <= 0 {
		pruneNow = time.Now().Unix()
	}
	e.pruneCooldownLedgerLocked(pruneNow)
	e.pruneTombstonesLocked(pruneNow)

	var subs []chan LeakEvent
	if len(added) > 0 && len(e.subs) > 0 {
		subs = make([]chan LeakEvent, 0, len(e.subs))
		for ch := range e.subs {
			subs = append(subs, ch)
		}
	}
	e.mu.Unlock()

	if len(staleAlertIDs) > 0 {
		e.purgeAlertsMatching(staleAlertIDs, nil, false)
	}

	for _, ev := range added {
		for _, ch := range subs {
			select {
			case ch <- ev:
			default:
			}
		}
	}
	for _, ev := range toNotify {
		if e.srv != nil && e.srv.hncDir != "" {
			acfg := alert.NewConfig(e.srv.hncDir)
			extra := map[string]interface{}{
				"origin":    ev.Origin,
				"dst_host":  ev.DstHost,
				"leak_type": ev.LeakType,
			}
			alertMAC := ev.MAC
			alertIP := ev.SrcIP
			if ev.Origin == leakOriginHost {
				alertMAC = ""
				alertIP = ""
				extra["uid"] = ev.UID
				if ev.Pkg != "" {
					extra["pkg"] = ev.Pkg
				}
				if ev.AppName != "" {
					extra["app_name"] = ev.AppName
				}
				if ev.SrcIP != "" {
					extra["src_ip"] = ev.SrcIP
				}
			}
			_ = alert.Append(acfg.AlertsJSONLPath, alert.Alert{
				ID:     ev.ID,
				Ts:     ev.Ts,
				Kind:   "leakguard",
				MAC:    alertMAC,
				IP:     alertIP,
				Detail: fmt.Sprintf("%s 向 %s 明文传输 %s", ev.DeviceName, ev.DstHost, ev.LeakLabel),
				Extra:  extra,
			})
		}
		if cfg.NotifyEnabled {
			e.postAndroidNotificationAsync(ev, cfg.LockscreenMask)
		}
	}
	return added
}

func (e *leakGuardEngine) srvHncDirSafe() string {
	if e != nil && e.srv != nil {
		return e.srv.hncDir
	}
	return ""
}

func hostAppIdentityKey(ev LeakEvent) string {
	if p := strings.ToLower(strings.TrimSpace(ev.Pkg)); p != "" {
		return "pkg:" + p
	}
	if ev.UID > 0 {
		return fmt.Sprintf("uid:%d", ev.UID)
	}
	if an := strings.ToLower(strings.TrimSpace(ev.AppName)); an != "" {
		return "app:" + an
	}
	return ""
}

func (e *leakGuardEngine) snapshotPayload() map[string]any {
	return e.snapshotPayloadFiltered(leakScopeAll)
}

func (e *leakGuardEngine) snapshotPayloadFiltered(scopeFilter string) map[string]any {
	if norm, ok := parseLeakEventsScopeQuery(scopeFilter); ok {
		scopeFilter = norm
	} else {
		scopeFilter = leakScopeAll
	}
	e.syncFromDisk()

	nameByMAC, macByIP := e.srv.buildDeviceDirectory()
	cb := readConnBlocks(e.srvHncDirSafe())
	sf := e.peerSelfFirewall()

	e.mu.Lock()
	cfg := e.cfg
	lgBlocked := make(map[string]bool, len(e.blockedTargets))
	for k, v := range e.blockedTargets {
		if v {
			lgBlocked[k] = true
		}
	}
	ignoreRules := make([]dpidlg.IgnoreRule, len(e.ignoreRules))
	copy(ignoreRules, e.ignoreRules)
	undoStack := make([]LeakBlockUndoEntry, len(e.undoStack))
	copy(undoStack, e.undoStack)
	list := make([]LeakEvent, len(e.events))
	copy(list, e.events)
	e.mu.Unlock()

	devSet := make(map[string]bool)
	appSet := make(map[string]bool)
	blockedHostSet := make(map[string]bool)
	for k := range lgBlocked {
		blockedHostSet[k] = true
	}
	for _, it := range cb.Items {
		if strings.HasPrefix(it.Label, "LeakGuard") {
			blockedHostSet[strings.ToLower(it.Value)] = true
		}
	}

	out := make([]LeakEvent, 0, len(list))
	for i := len(list) - 1; i >= 0; i-- {
		ev := list[i]
		ev.Origin = normalizeLeakOrigin(ev.Origin)
		if ev.LeakLabel == "" {
			ev.LeakLabel = leakTypeDisplayName(ev.LeakType)
		}
		if ev.Origin == leakOriginHost {
			if ak := hostAppIdentityKey(ev); ak != "" {
				appSet[ak] = true
			}
			ev.IsBlocked = sf != nil && sf.IsHostEventBlocked(ev.UID, ev.DstHost, ev.DstIP, ev.DstPort, ev.Proto)
		} else {
			if ev.MAC == "" && ev.SrcIP != "" {
				if m := macByIP[ev.SrcIP]; m != "" {
					ev.MAC = m
				}
			}
			if ev.MAC != "" {
				if nm := nameByMAC[ev.MAC]; nm != "" {
					ev.DeviceName = nm
				}
				devSet[ev.MAC] = true
			} else if ev.SrcIP != "" {
				devSet[ev.SrcIP] = true
			}
			blocked := matchBlockedHost(ev.DstHost, ev.MAC, cb, lgBlocked)
			if !blocked && ev.DstIP != "" {
				blocked = matchBlockedHost(ev.DstIP, ev.MAC, cb, lgBlocked)
			}
			ev.IsBlocked = blocked
			if blocked && ev.DstHost != "" {
				blockedHostSet[strings.ToLower(ev.DstHost)] = true
			}
		}

		if scopeFilter == leakScopeHotspot && ev.Origin != leakOriginHotspot {
			continue
		}
		if scopeFilter == leakScopeHost && ev.Origin != leakOriginHost {
			continue
		}
		out = append(out, ev)
	}

	totalHits := e.totalHits.Load()
	if int64(len(list)) > totalHits {
		totalHits = int64(len(list))
	}
	hostHits := e.hostHits.Load()
	hotspotHits := e.hotspotHits.Load()
	ignoredHits := e.ignoredHits.Load()
	guardBlocks := e.guardBlocks.Load()
	affectedDevs := len(devSet)
	affectedApps := len(appSet)
	blockedDomains := len(blockedHostSet)
	selfBlockedDomains := 0
	if sf != nil {
		selfBlockedDomains = sf.BlockedDomainCount()
	}

	return map[string]any{
		"ok":                   true,
		"scope":                scopeFilter,
		"events":               out,
		"total_hits":           totalHits,
		"host_hits":            hostHits,
		"hotspot_hits":         hotspotHits,
		"ignored_hits":         ignoredHits,
		"guard_blocks":         guardBlocks,
		"affected_devices":     affectedDevs,
		"affected_apps":        affectedApps,
		"blocked_domains":      blockedDomains,
		"self_blocked_domains": selfBlockedDomains,
		"ignore_rules":         ignoreRules,
		"undo_stack":           undoStack,
		"undo_count":           len(undoStack),
		"stats": map[string]any{
			"total_hits":           totalHits,
			"host_hits":            hostHits,
			"hotspot_hits":         hotspotHits,
			"ignored_hits":         ignoredHits,
			"guard_blocks":         guardBlocks,
			"affected_devices":     affectedDevs,
			"affected_apps":        affectedApps,
			"blocked_domains":      blockedDomains,
			"self_blocked_domains": selfBlockedDomains,
		},
		"config": cfg,
	}
}

func (e *leakGuardEngine) summary() map[string]any {
	_, macByIP := e.srv.buildDeviceDirectory()
	cb := readConnBlocks(e.srvHncDirSafe())

	e.mu.Lock()
	cfg := e.cfg
	cnt := len(e.events)
	lgBlocked := make(map[string]bool, len(e.blockedTargets))
	for k, v := range e.blockedTargets {
		if v {
			lgBlocked[k] = true
		}
	}
	ignoreCnt := len(e.ignoreRules)
	undoCnt := len(e.undoStack)
	list := make([]LeakEvent, len(e.events))
	copy(list, e.events)
	e.mu.Unlock()

	devSet := make(map[string]bool)
	appSet := make(map[string]bool)
	blockedHostSet := make(map[string]bool)
	for k := range lgBlocked {
		blockedHostSet[k] = true
	}
	for _, it := range cb.Items {
		if strings.HasPrefix(it.Label, "LeakGuard") {
			blockedHostSet[strings.ToLower(it.Value)] = true
		}
	}
	for _, ev := range list {
		if normalizeLeakOrigin(ev.Origin) == leakOriginHost {
			if ak := hostAppIdentityKey(ev); ak != "" {
				appSet[ak] = true
			}
			continue
		}
		mac := ev.MAC
		if mac == "" && ev.SrcIP != "" {
			mac = macByIP[ev.SrcIP]
		}
		if mac != "" {
			devSet[mac] = true
		} else if ev.SrcIP != "" {
			devSet[ev.SrcIP] = true
		}
		blocked := matchBlockedHost(ev.DstHost, mac, cb, lgBlocked)
		if !blocked && ev.DstIP != "" {
			blocked = matchBlockedHost(ev.DstIP, mac, cb, lgBlocked)
		}
		if blocked && ev.DstHost != "" {
			blockedHostSet[strings.ToLower(ev.DstHost)] = true
		}
	}

	selfBlockedCnt := 0
	if sf := e.peerSelfFirewall(); sf != nil {
		selfBlockedCnt = sf.BlockedDomainCount()
	}

	totalHits := e.totalHits.Load()
	if int64(cnt) > totalHits {
		totalHits = int64(cnt)
	}

	return map[string]any{
		"total_hits":           totalHits,
		"host_hits":            e.hostHits.Load(),
		"hotspot_hits":         e.hotspotHits.Load(),
		"ignored_hits":         e.ignoredHits.Load(),
		"guard_blocks":         e.guardBlocks.Load(),
		"buffered_events":      cnt,
		"affected_devices":     len(devSet),
		"affected_apps":        len(appSet),
		"blocked_domains":      len(blockedHostSet),
		"self_blocked_domains": selfBlockedCnt,
		"ignore_rules_cnt":     ignoreCnt,
		"undo_count":           undoCnt,
		"capacity":             cfg.Capacity,
		"cooldown_sec":         cfg.CooldownSec,
		"notify_enabled":       cfg.NotifyEnabled,
		"lockscreen_mask":      cfg.LockscreenMask,
	}
}

func (e *leakGuardEngine) ensureWakeCh() chan struct{} {
	if e == nil {
		return nil
	}
	e.wakeOnce.Do(func() {
		if e.wakeCh == nil {
			e.wakeCh = make(chan struct{}, 1)
		}
	})
	return e.wakeCh
}

func (e *leakGuardEngine) notifySSEChanged() {
	ch := e.ensureWakeCh()
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

// IsTickerActive 返回后台轮询定时器是否处于激活态（待机停表时为 false）。
func (e *leakGuardEngine) IsTickerActive() bool {
	if e == nil {
		return false
	}
	return e.tickerActive.Load()
}

func (e *leakGuardEngine) effectivePollInterval() time.Duration {
	if e != nil && e.pollInterval > 0 {
		return e.pollInterval
	}
	return leakDefaultPollInterval
}

func (e *leakGuardEngine) currentActivity() (<-chan struct{}, Activity, bool) {
	if e != nil && e.activityHook != nil {
		return e.activityHook()
	}
	ch := activityChanged()
	act := activityNow()
	simOn := e != nil && e.srv != nil && e.srv.simActive()
	return ch, act, simOn
}

func (e *leakGuardEngine) hostCaptureAwake(act Activity) bool {
	if e == nil || e.srv == nil || e.srv.hncDir == "" || act.screenOff() {
		return false
	}
	_, err := os.Stat(e.srv.selfFlagPath())
	return err == nil
}

func (e *leakGuardEngine) runLoop(stop <-chan struct{}) {
	if e == nil {
		<-stop
		return
	}
	wakeCh := e.ensureWakeCh()
	var (
		tk       *time.Ticker
		tkCh     <-chan time.Time
		sleeping bool
	)
	stopTicker := func() {
		if tk != nil {
			tk.Stop()
			tk = nil
			tkCh = nil
		}
		e.tickerActive.Store(false)
	}
	ensureTicker := func() {
		if tk == nil {
			tk = time.NewTicker(e.effectivePollInterval())
			tkCh = tk.C
		}
		e.tickerActive.Store(true)
	}
	defer stopTicker()

	for {
		actCh, act, simOn := e.currentActivity()
		hotspotAwake := act.HotspotActive && (act.ClientsOnline > 0 || act.WebUIActive || leakSSEActiveConns.Load() > 0)
		shouldSleep := act.Known && !simOn && !hotspotAwake && !e.hostCaptureAwake(act)
		if shouldSleep {
			if !sleeping {
				// 进入休眠停表前先执行一次收尾同步, 随后彻底停表 0 唤醒
				e.syncFromDisk()
				stopTicker()
				sleeping = true
			}
			select {
			case <-stop:
				return
			case <-actCh:
			case <-wakeCh:
			}
			continue
		}

		if sleeping {
			sleeping = false
			e.syncFromDisk()
		}
		ensureTicker()
		select {
		case <-stop:
			return
		case <-actCh:
		case <-wakeCh:
		case <-tkCh:
			e.syncFromDisk()
		}
	}
}

// ── LeakGuard HTTP 路由处理器 ────────────────────────────────────────────────

// apiLeakGuardEvents GET /api/leakguard/events (?scope=all|hotspot|host)
func (s *server) apiLeakGuardEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "GET only"})
		return
	}
	scope, ok := parseLeakEventsScopeQuery(r.URL.Query().Get("scope"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":     false,
			"error":  "bad params",
			"detail": "scope must be all|hotspot|host",
		})
		return
	}
	writeJSON(w, http.StatusOK, s.v6State().leakGuard.snapshotPayloadFiltered(scope))
}

// apiLeakGuardStream GET /api/leakguard/stream — SSE 实时流推送新捕获的 LeakEvent + 保活心跳帧
func (s *server) apiLeakGuardStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "GET only"})
		return
	}
	streamScope, ok := parseLeakEventsScopeQuery(r.URL.Query().Get("scope"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":     false,
			"error":  "bad params",
			"detail": "scope must be all|hotspot|host",
		})
		return
	}
	eng := s.v6State().leakGuard
	if n := leakSSEActiveConns.Add(1); n > leakMaxSSEClients {
		leakSSEActiveConns.Add(-1)
		w.Header().Set("Retry-After", "5")
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "too many leakguard SSE streams"})
		return
	}
	eng.notifySSEChanged()
	defer func() {
		leakSSEActiveConns.Add(-1)
		eng.notifySSEChanged()
	}()

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	flusher, canFlush := w.(http.Flusher)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	flushOut := func() error {
		err := rc.Flush()
		if err == nil {
			return nil
		}
		if errors.Is(err, http.ErrNotSupported) {
			if canFlush {
				flusher.Flush()
			}
			return nil
		}
		return err
	}

	writeFrame := func(frame string) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(leakSSEWriteTimeout))
		if _, err := io.WriteString(w, frame); err != nil {
			return false
		}
		if flushOut() != nil {
			return false
		}
		_ = rc.SetWriteDeadline(time.Time{})
		return true
	}

	subCh := make(chan LeakEvent, 64)
	eng.mu.Lock()
	eng.subs[subCh] = struct{}{}
	hbDur := eng.sseHeartbeat
	eng.mu.Unlock()
	defer func() {
		eng.mu.Lock()
		delete(eng.subs, subCh)
		eng.mu.Unlock()
	}()

	if !writeFrame(": leakguard-stream-ready\nevent: ready\ndata: {\"ok\":true}\n\n") {
		return
	}

	if hbDur <= 0 {
		hbDur = leakSSEHeartbeatDefault
	}
	hbTicker := time.NewTicker(hbDur)
	defer hbTicker.Stop()
	pollTicker := time.NewTicker(1500 * time.Millisecond)
	defer pollTicker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-subCh:
			ev.Origin = normalizeLeakOrigin(ev.Origin)
			if streamScope == leakScopeHotspot && ev.Origin != leakOriginHotspot {
				continue
			}
			if streamScope == leakScopeHost && ev.Origin != leakOriginHost {
				continue
			}
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			if !writeFrame("event: leak\ndata: " + string(b) + "\n\n") {
				return
			}
		case <-pollTicker.C:
			eng.syncFromDisk()
		case <-hbTicker.C:
			if !writeFrame(": heartbeat\n\n") {
				return
			}
		}
	}
}

// apiLeakGuardClear POST /api/leakguard/clear
func (s *server) apiLeakGuardClear(w http.ResponseWriter, r *http.Request) {
	eng := s.v6State().leakGuard
	now := time.Now().Unix()

	eng.mu.Lock()
	clrTs := now
	if eng.maxSeenTs >= clrTs {
		clrTs = eng.maxSeenTs + 1
	}
	eng.events = nil
	eng.seenIDs = make(map[string]int64)
	eng.mergedAliasIDs = make(map[string]string)
	eng.ignoredSeenIDs = make(map[string]int64)
	eng.cooldownLedger = make(map[string]int64)
	eng.hasEventsStat = false
	eng.clearedAt = clrTs
	eng.maxSeenTs = clrTs
	seq := eng.clearSeq.Add(1)
	eng.totalHits.Store(0)
	eng.hostHits.Store(0)
	eng.hotspotHits.Store(0)
	if s.hncDir != "" {
		_ = writeLeakGuardAtomic0600(eng.dpidEventsPath(), []byte("{\"events\":[]}\n"))
	}
	err := eng.saveStateLocked()
	eng.mu.Unlock()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write ctrl failed", "detail": err.Error()})
		return
	}
	if s.hncDir != "" {
		acfg := alert.NewConfig(s.hncDir)
		if st, serr := os.Stat(acfg.AlertsJSONLPath); serr == nil && !st.IsDir() {
			_ = alert.PurgeLeakGuard(acfg, nil)
		}
	}
	eng.notifySSEChanged()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"clear_seq":  seq,
		"cleared_at": now,
	})
}

// apiLeakGuardConfig POST /api/leakguard/config
// 仅更新基础 4 字段配置, 完整保留内存与持久化层已存的 ignore_rules 与 undo_stack。
func (s *server) apiLeakGuardConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Capacity       *int  `json:"capacity"`
		CooldownSec    *int  `json:"cooldown_sec"`
		NotifyEnabled  *bool `json:"notify_enabled"`
		LockscreenMask *bool `json:"lockscreen_mask"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json", "detail": err.Error()})
		return
	}

	eng := s.v6State().leakGuard
	eng.mu.Lock()
	next := eng.cfg
	if req.Capacity != nil {
		if *req.Capacity < leakMinCapacity || *req.Capacity > leakMaxCapacity {
			eng.mu.Unlock()
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "capacity must be 10..2000"})
			return
		}
		next.Capacity = *req.Capacity
	}
	if req.CooldownSec != nil {
		if *req.CooldownSec < leakMinCooldownSec || *req.CooldownSec > leakMaxCooldownSec {
			eng.mu.Unlock()
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "cooldown_sec must be 0..86400"})
			return
		}
		next.CooldownSec = *req.CooldownSec
	}
	if req.NotifyEnabled != nil {
		next.NotifyEnabled = *req.NotifyEnabled
	}
	if req.LockscreenMask != nil {
		next.LockscreenMask = *req.LockscreenMask
	}

	eng.cfg = next
	if len(eng.events) > next.Capacity {
		eng.events = append([]LeakEvent(nil), eng.events[len(eng.events)-next.Capacity:]...)
	}
	err := eng.saveStateLocked()
	eng.mu.Unlock()

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write ctrl failed", "detail": err.Error()})
		return
	}
	eng.notifySSEChanged()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"config": next,
	})
}

func sanitizeLeakAppIdentityParams(uid int, pkg string) (int, string) {
	p := strings.TrimSpace(pkg)
	low := strings.ToLower(p)
	if strings.HasPrefix(low, "uid:") {
		if uid == 0 {
			if n, err := strconv.Atoi(strings.TrimSpace(low[4:])); err == nil && n > 0 {
				uid = n
			}
		}
		return uid, ""
	}
	if strings.HasPrefix(low, "isolated:") {
		return uid, ""
	}
	return uid, p
}

// apiLeakGuardWhitelist POST /api/leakguard/whitelist
// 支持 action: "add" | "remove" | "clear", 四级作用域 "host_type" | "host" | "device_host_type" | "app_host_type", 硬上限 200 条。
func (s *server) apiLeakGuardWhitelist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action   string `json:"action"`
		ID       string `json:"id"`
		Scope    string `json:"scope"`
		DstHost  string `json:"dst_host"`
		LeakType string `json:"leak_type"`
		MAC      string `json:"mac"`
		UID      int    `json:"uid"`
		Pkg      string `json:"pkg"`
		Note     string `json:"note"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json", "detail": err.Error()})
		return
	}

	act := strings.ToLower(strings.TrimSpace(req.Action))
	if act == "" {
		act = "add"
	}
	normUID, normPkg := sanitizeLeakAppIdentityParams(req.UID, req.Pkg)
	eng := s.v6State().leakGuard

	switch act {
	case "add":
		rule, err := dpidlg.NormalizeIgnoreRule(dpidlg.IgnoreRule{
			Scope:    req.Scope,
			DstHost:  req.DstHost,
			LeakType: req.LeakType,
			MAC:      req.MAC,
			UID:      normUID,
			Pkg:      normPkg,
			Note:     req.Note,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad whitelist rule", "detail": err.Error()})
			return
		}

		eng.mu.Lock()
		uk := rule.UniqueKey()
		existsIdx := -1
		for i := range eng.ignoreRules {
			if eng.ignoreRules[i].UniqueKey() == uk {
				existsIdx = i
				break
			}
		}
		if existsIdx < 0 {
			if len(eng.ignoreRules) >= dpidlg.MaxIgnoreRules {
				eng.mu.Unlock()
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"ok":     false,
					"error":  "too_many_rules",
					"detail": fmt.Sprintf("ignore whitelist reached max capacity (%d)", dpidlg.MaxIgnoreRules),
				})
				return
			}
			eng.ignoreRules = append(eng.ignoreRules, rule)
		} else {
			if rule.Note != "" {
				eng.ignoreRules[existsIdx].Note = rule.Note
			}
			rule = eng.ignoreRules[existsIdx]
		}
		purged, purgedIDs := eng.purgeIgnoredEventsWithIDsLocked()
		rulesOut := make([]dpidlg.IgnoreRule, len(eng.ignoreRules))
		copy(rulesOut, eng.ignoreRules)
		saveErr := eng.saveStateLocked()
		eng.mu.Unlock()
		if saveErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write whitelist failed", "detail": saveErr.Error()})
			return
		}
		eng.purgeAlertsMatching(purgedIDs, rulesOut, false)
		eng.notifySSEChanged()
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"action":        "add",
			"rule":          rule,
			"purged_events": purged,
			"ignore_rules":  rulesOut,
		})

	case "remove":
		targetID := strings.TrimSpace(req.ID)
		var targetKey string
		if targetID == "" {
			if strings.TrimSpace(req.DstHost) == "" {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "id or dst_host is required for remove"})
				return
			}
			if nr, err := dpidlg.NormalizeIgnoreRule(dpidlg.IgnoreRule{
				Scope:    req.Scope,
				DstHost:  req.DstHost,
				LeakType: req.LeakType,
				MAC:      req.MAC,
				UID:      normUID,
				Pkg:      normPkg,
			}); err == nil {
				targetKey = nr.UniqueKey()
			} else {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": err.Error()})
				return
			}
		}

		eng.mu.Lock()
		kept := make([]dpidlg.IgnoreRule, 0, len(eng.ignoreRules))
		removed := 0
		for _, cur := range eng.ignoreRules {
			if (targetID != "" && cur.ID == targetID) || (targetKey != "" && cur.UniqueKey() == targetKey) {
				removed++
				continue
			}
			kept = append(kept, cur)
		}
		eng.ignoreRules = kept
		if removed > 0 {
			eng.ignoredSeenIDs = make(map[string]int64)
			eng.hasEventsStat = false
		}
		rulesOut := make([]dpidlg.IgnoreRule, len(eng.ignoreRules))
		copy(rulesOut, eng.ignoreRules)
		saveErr := eng.saveStateLocked()
		eng.mu.Unlock()
		if saveErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write whitelist failed", "detail": saveErr.Error()})
			return
		}
		eng.notifySSEChanged()
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":           true,
			"action":       "remove",
			"removed":      removed,
			"ignore_rules": rulesOut,
		})

	case "clear":
		eng.mu.Lock()
		removed := len(eng.ignoreRules)
		eng.ignoreRules = nil
		eng.ignoredSeenIDs = make(map[string]int64)
		eng.hasEventsStat = false
		saveErr := eng.saveStateLocked()
		eng.mu.Unlock()
		if saveErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write whitelist failed", "detail": saveErr.Error()})
			return
		}
		eng.notifySSEChanged()
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":           true,
			"action":       "clear",
			"removed":      removed,
			"ignore_rules": []dpidlg.IgnoreRule{},
		})

	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "action must be add|remove|clear"})
	}
}

func applyConnBlockActionForMACs(s *server, act, kind, normVal string, targetMACs []string, scriptExists bool) (applied int, lastDetail string, errResp *actionResp) {
	applied, lastDetail, _, errResp = applyConnBlockActionTrackMACs(s, act, kind, normVal, targetMACs, scriptExists)
	return applied, lastDetail, errResp
}

func applyConnBlockActionTrackMACs(s *server, act, kind, normVal string, targetMACs []string, scriptExists bool) (applied int, lastDetail string, mutatedMACs []string, errResp *actionResp) {
	preSet := make(map[string]bool)
	if s != nil && s.hncDir != "" {
		for _, it := range readConnBlocks(s.hncDir).Items {
			if it.Kind == kind && strings.EqualFold(it.Value, normVal) {
				preSet[strings.ToLower(strings.TrimSpace(it.MAC))] = true
			}
		}
	}
	for _, mac := range targetMACs {
		nm := strings.ToLower(strings.TrimSpace(mac))
		params := map[string]string{
			"mac":   mac,
			"kind":  kind,
			"value": normVal,
			"label": "LeakGuard 反制",
		}
		var resp actionResp
		if act == "block" {
			resp = actionConnBlockAdd(s, params)
		} else {
			resp = actionConnBlockDel(s, params)
		}
		if resp.OK {
			applied++
			lastDetail = resp.Detail
			if act == "block" && !preSet[nm] && resp.Detail != "已经封锁过了" {
				mutatedMACs = append(mutatedMACs, nm)
				preSet[nm] = true
			} else if act == "unblock" && preSet[nm] {
				mutatedMACs = append(mutatedMACs, nm)
				delete(preSet, nm)
			}
			continue
		}
		if resp.Error == "sync failed" && !scriptExists {
			applied++
			lastDetail = "saved (sandbox no connblock_sync.sh)"
			if act == "block" && !preSet[nm] {
				mutatedMACs = append(mutatedMACs, nm)
				preSet[nm] = true
			} else if act == "unblock" && preSet[nm] {
				mutatedMACs = append(mutatedMACs, nm)
				delete(preSet, nm)
			}
			continue
		}
		if act == "unblock" && resp.Error == "not found" {
			continue
		}
		if len(mutatedMACs) > 0 {
			rbAct := "unblock"
			if act == "unblock" {
				rbAct = "block"
			}
			for _, rbMAC := range mutatedMACs {
				rbParams := map[string]string{
					"mac":   rbMAC,
					"kind":  kind,
					"value": normVal,
					"label": "LeakGuard 反制",
				}
				if rbAct == "block" {
					_ = actionConnBlockAdd(s, rbParams)
				} else {
					_ = actionConnBlockDel(s, rbParams)
				}
			}
			if s != nil {
				s.refreshDNSTKBlocklist(time.Now())
			}
		}
		return applied, lastDetail, nil, &resp
	}
	return applied, lastDetail, mutatedMACs, nil
}

// apiLeakGuardBlockDomain POST /api/leakguard/block-domain
// 支持 action: "block" | "unblock", target_scope: "hotspot" | "host" | "both",
// 集成三级共享基础设施防误杀守卫、空 MAC 爆炸半径防呆、also_ip 共享 IP 剥离、本机 HNC_SELF_DNS / 按应用 UID 公网 IP 封禁联动与 10 条撤销栈。
func (s *server) apiLeakGuardBlockDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action      string `json:"action"`
		Scope       string `json:"scope"`
		TargetScope string `json:"target_scope"`
		DstHost     string `json:"dst_host"`
		MAC         string `json:"mac"`
		UID         int    `json:"uid"`
		Pkg         string `json:"pkg"`
		AppName     string `json:"app_name"`
		Force       bool   `json:"force"`
		AlsoIP      string `json:"also_ip"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json", "detail": err.Error()})
		return
	}
	act := strings.ToLower(strings.TrimSpace(req.Action))
	if act == "" {
		act = "block"
	}
	if act != "block" && act != "unblock" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "action must be block|unblock"})
		return
	}
	targetScope, tsOK := parseLeakTargetScope(req.TargetScope)
	if !tsOK {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "target_scope must be hotspot|host|both"})
		return
	}
	doHotspot := targetScope == leakTargetScopeHotspot || targetScope == leakTargetScopeBoth
	doHost := targetScope == leakTargetScopeHost || targetScope == leakTargetScopeBoth

	reqScope := strings.ToLower(strings.TrimSpace(req.Scope))
	if reqScope != "" && reqScope != "device" && reqScope != "global" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "scope must be device|global"})
		return
	}
	reqMAC := strings.ToLower(strings.TrimSpace(req.MAC))
	reqUID, reqPkg := sanitizeLeakAppIdentityParams(req.UID, req.Pkg)

	if targetScope == leakTargetScopeHotspot {
		// 空 MAC 爆炸半径防呆: 纯热点非显式全局封禁(scope != "global")时严禁因空 MAC 退化为全热点所有设备集体封禁!
		if reqScope != "global" {
			if reqMAC == "" {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"ok":          false,
					"error":       "bad params",
					"reason_code": "missing_mac",
					"detail":      "非全局封禁必须指定有效的目标设备 mac（如需全热点封禁请显式传 scope:\"global\"，或仅封本机传 target_scope:\"host\"）",
				})
				return
			}
			if !validMAC(reqMAC) {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "invalid mac"})
				return
			}
		} else if reqMAC != "" && reqMAC != "all" && reqMAC != "*" && !validMAC(reqMAC) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "invalid mac"})
			return
		}
	} else if targetScope == leakTargetScopeBoth {
		if reqMAC != "" && reqMAC != "all" && reqMAC != "*" && !validMAC(reqMAC) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "invalid mac"})
			return
		}
		if reqMAC == "" && reqScope == "" {
			reqScope = "global"
		}
	} else if reqMAC != "" && reqMAC != "all" && reqMAC != "*" && !validMAC(reqMAC) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "invalid mac"})
		return
	}

	kind, normVal, ok := normalizeBlockTarget(req.DstHost)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "invalid dst_host (domain or public IP required)"})
		return
	}
	if doHost && kind == "domain" {
		if nd, derr := normalizeSelfDNSBlockDomain(normVal); derr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": derr.Error()})
			return
		} else {
			normVal = nd
		}
	}
	if doHost && kind == "ip" {
		if targetScope == leakTargetScopeHost && reqUID <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":          false,
				"error":       "bad params",
				"reason_code": "missing_uid",
				"detail":      "本机公网 IP 封禁必须指定有效的目标应用 uid",
			})
			return
		}
		if reqUID > 0 && (isProtectedSelfFirewallSystemUID(reqUID) || reqUID > selfFirewallMaxAppUID) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":     false,
				"error":  "protected_uid",
				"detail": fmt.Sprintf("禁止对系统/隔离进程 UID=%d 执行本机公网 IP 封禁", reqUID),
			})
			return
		}
	}

	st := s.v6State()
	eng := st.leakGuard
	sf := st.selfFirewall

	var guardDecision leakBlockGuardDecision
	if act == "block" {
		guardDecision = evaluateScopedLeakBlockGuard(s, kind, normVal, targetScope)
		if targetScope == leakTargetScopeBoth && kind == "ip" && reqUID > 0 && guardDecision.Level != leakGuardLevelHardBlock {
			if hostGuard := evaluateScopedLeakBlockGuard(s, "ip", normVal, leakTargetScopeHost); hostGuard.Level == leakGuardLevelHardBlock {
				guardDecision = hostGuard
			}
		}
		if guardDecision.Level == leakGuardLevelHardBlock {
			eng.guardBlocks.Add(1)
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok":           false,
				"error":        "guard_hard_block",
				"guard_level":  leakGuardLevelHardBlock,
				"target_scope": targetScope,
				"vendor":       guardDecision.Vendor,
				"category":     guardDecision.Category,
				"dst_host":     normVal,
				"detail":       guardDecision.Detail,
			})
			return
		}
		if guardDecision.Level == leakGuardLevelWarnConfirm && !req.Force {
			eng.guardBlocks.Add(1)
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok":               false,
				"error":            "guard_warn_confirm",
				"guard_level":      leakGuardLevelWarnConfirm,
				"requires_confirm": true,
				"target_scope":     targetScope,
				"vendor":           guardDecision.Vendor,
				"category":         guardDecision.Category,
				"dst_host":         normVal,
				"detail":           guardDecision.Detail,
			})
			return
		}
	}
	if doHost && kind == "ip" && reqUID > 0 {
		if _, perr := parseAndValidateSelfBlockTarget(normVal); perr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":     false,
				"error":  "bad params",
				"detail": perr.Error(),
			})
			return
		}
	}

	var (
		targetMACs          []string
		applied             int
		lastDetail          string
		skippedSharedIP     bool
		skippedIPVendor     string
		blockedAlsoIP       string
		normAlsoIP          string
		unblockedIPs        []string
		hotspotScriptExists bool
		mutatedMainMACs     []string
		addedAlsoIPMACs     []string
		removedAlsoIPMACs   map[string][]string
	)

	if doHotspot {
		if reqScope != "global" {
			targetMACs = []string{reqMAC}
		} else if reqMAC != "" && reqMAC != "all" && reqMAC != "*" {
			targetMACs = []string{reqMAC}
		} else {
			macSet := make(map[string]bool)
			var evCandMACs []string
			eng.mu.Lock()
			for _, ev := range eng.events {
				if validMAC(ev.MAC) {
					_, evHost, hok := normalizeBlockTarget(ev.DstHost)
					if !hok {
						evHost = strings.ToLower(ev.DstHost)
					}
					if evHost == normVal || strings.HasSuffix(evHost, "."+normVal) || ev.DstIP == normVal {
						evCandMACs = append(evCandMACs, ev.MAC)
					}
				}
			}
			eng.mu.Unlock()
			for _, em := range evCandMACs {
				if !isProtectedMAC(s.hncDir, em) {
					macSet[em] = true
				}
			}
			for mac := range s.deviceIPsByMAC() {
				if validMAC(mac) && !isProtectedMAC(s.hncDir, mac) {
					macSet[mac] = true
				}
			}
			if act == "block" {
				macSet["00:00:00:00:00:00"] = true
			}
			if act == "unblock" {
				for _, it := range readConnBlocks(s.hncDir).Items {
					if it.Kind == kind && strings.EqualFold(it.Value, normVal) && validMAC(it.MAC) {
						macSet[it.MAC] = true
					}
				}
			}
			for m := range macSet {
				targetMACs = append(targetMACs, m)
			}
			sort.Strings(targetMACs)
		}

		if stFile, err := os.Stat(filepath.Join(s.hncDir, "bin", "connblock_sync.sh")); err == nil && !stFile.IsDir() {
			hotspotScriptExists = true
		}

		var errResp *actionResp
		applied, lastDetail, mutatedMainMACs, errResp = applyConnBlockActionTrackMACs(s, act, kind, normVal, targetMACs, hotspotScriptExists)
		if errResp != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":     false,
				"error":  errResp.Error,
				"detail": errResp.Detail,
			})
			return
		}

		if rawAlso := strings.TrimSpace(req.AlsoIP); rawAlso != "" && kind == "domain" {
			if ipKind, parsedIP, ipOK := normalizeBlockTarget(rawAlso); ipOK && ipKind == "ip" && !strings.EqualFold(parsedIP, normVal) {
				normAlsoIP = parsedIP
				if act == "block" {
					if shared, vendor := detectSharedInfraTarget(s, normVal, normAlsoIP); shared {
						skippedSharedIP = true
						skippedIPVendor = vendor
					} else {
						if _, _, ipAdded, ipErr := applyConnBlockActionTrackMACs(s, "block", "ip", normAlsoIP, targetMACs, hotspotScriptExists); ipErr == nil {
							blockedAlsoIP = normAlsoIP
							addedAlsoIPMACs = ipAdded
						}
					}
				} else {
					unblockedIPs = append(unblockedIPs, normAlsoIP)
				}
			}
		}
		if act == "unblock" && kind == "domain" {
			eng.mu.Lock()
			for _, cur := range eng.undoStack {
				if cur.Kind == kind && cur.DstHost == normVal && cur.AlsoIP != "" {
					dup := false
					for _, existing := range unblockedIPs {
						if strings.EqualFold(existing, cur.AlsoIP) {
							dup = true
							break
						}
					}
					if !dup {
						unblockedIPs = append(unblockedIPs, cur.AlsoIP)
					}
				}
			}
			eng.mu.Unlock()
			removedAlsoIPMACs = make(map[string][]string, len(unblockedIPs))
			for _, uip := range unblockedIPs {
				_, _, ipRemoved, ipErr := applyConnBlockActionTrackMACs(s, "unblock", "ip", uip, targetMACs, hotspotScriptExists)
				if ipErr != nil {
					for prevIP, prevMACs := range removedAlsoIPMACs {
						if len(prevMACs) > 0 {
							_, _, _ = applyConnBlockActionForMACs(s, "block", "ip", prevIP, prevMACs, hotspotScriptExists)
						}
					}
					if len(mutatedMainMACs) > 0 {
						_, _, _ = applyConnBlockActionForMACs(s, "block", kind, normVal, mutatedMainMACs, hotspotScriptExists)
					}
					s.refreshDNSTKBlocklist(time.Now())
					writeJSON(w, http.StatusInternalServerError, map[string]any{
						"ok":     false,
						"error":  ipErr.Error,
						"detail": ipErr.Detail,
					})
					return
				}
				if len(ipRemoved) > 0 {
					removedAlsoIPMACs[uip] = ipRemoved
				}
			}
		}
	}

	if doHost && kind == "domain" && sf != nil {
		if act == "block" {
			// 上方已完成三级基础设施守卫确认, 此处传 force=true 直接落盘并同步 HNC_SELF_DNS
			if _, _, _, herr := sf.BlockDomain(normVal, true); herr != nil {
				if doHotspot {
					if len(addedAlsoIPMACs) > 0 && normAlsoIP != "" {
						_, _, _ = applyConnBlockActionForMACs(s, "unblock", "ip", normAlsoIP, addedAlsoIPMACs, hotspotScriptExists)
					}
					if len(mutatedMainMACs) > 0 {
						_, _, _ = applyConnBlockActionForMACs(s, "unblock", kind, normVal, mutatedMainMACs, hotspotScriptExists)
					}
					s.refreshDNSTKBlocklist(time.Now())
				}
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"ok":     false,
					"error":  "self_dns_block_failed",
					"detail": herr.Error(),
				})
				return
			}
			applied++
			if lastDetail == "" {
				lastDetail = "self dns blocked: " + normVal
			} else {
				lastDetail = lastDetail + "; self dns blocked: " + normVal
			}
		} else {
			if _, _, herr := sf.UnblockDomain(normVal); herr != nil {
				if doHotspot {
					for prevIP, prevMACs := range removedAlsoIPMACs {
						if len(prevMACs) > 0 {
							_, _, _ = applyConnBlockActionForMACs(s, "block", "ip", prevIP, prevMACs, hotspotScriptExists)
						}
					}
					if len(mutatedMainMACs) > 0 {
						_, _, _ = applyConnBlockActionForMACs(s, "block", kind, normVal, mutatedMainMACs, hotspotScriptExists)
					}
					s.refreshDNSTKBlocklist(time.Now())
				}
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"ok":     false,
					"error":  "self_dns_unblock_failed",
					"detail": herr.Error(),
				})
				return
			}
			applied++
			if lastDetail == "" {
				lastDetail = "self dns unblocked: " + normVal
			} else {
				lastDetail = lastDetail + "; self dns unblocked: " + normVal
			}
		}
	}

	hostUndoUID := 0
	if doHost && kind == "ip" && reqUID > 0 && sf != nil {
		if act == "block" {
			if _, _, herr := sf.AddUIDBlockTarget(reqUID, normVal, reqPkg, req.AppName); herr != nil {
				if doHotspot {
					if len(mutatedMainMACs) > 0 {
						_, _, _ = applyConnBlockActionForMACs(s, "unblock", kind, normVal, mutatedMainMACs, hotspotScriptExists)
					}
					s.refreshDNSTKBlocklist(time.Now())
				}
				errCode := "self_uid_block_failed"
				errDetail := herr.Error()
				var verr *selfFirewallValidationError
				if errors.As(herr, &verr) && verr != nil {
					errCode = verr.Code
					errDetail = verr.Detail
				}
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"ok":     false,
					"error":  errCode,
					"detail": errDetail,
				})
				return
			}
			hostUndoUID = reqUID
			applied++
			if lastDetail == "" {
				lastDetail = fmt.Sprintf("self uid(%d) ip blocked: %s", reqUID, normVal)
			} else {
				lastDetail = fmt.Sprintf("%s; self uid(%d) ip blocked: %s", lastDetail, reqUID, normVal)
			}
		} else {
			if _, herr := sf.RemoveUIDBlockTarget(reqUID, normVal); herr != nil {
				if doHotspot {
					if len(mutatedMainMACs) > 0 {
						_, _, _ = applyConnBlockActionForMACs(s, "block", kind, normVal, mutatedMainMACs, hotspotScriptExists)
					}
					s.refreshDNSTKBlocklist(time.Now())
				}
				errCode := "self_uid_unblock_failed"
				errDetail := herr.Error()
				var verr *selfFirewallValidationError
				if errors.As(herr, &verr) && verr != nil {
					errCode = verr.Code
					errDetail = verr.Detail
				}
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"ok":     false,
					"error":  errCode,
					"detail": errDetail,
				})
				return
			}
			applied++
			if lastDetail == "" {
				lastDetail = fmt.Sprintf("self uid(%d) ip unblocked: %s", reqUID, normVal)
			} else {
				lastDetail = fmt.Sprintf("%s; self uid(%d) ip unblocked: %s", lastDetail, reqUID, normVal)
			}
		}
	}

	cbNow := readConnBlocks(s.hncDir)
	now := time.Now().Unix()
	var undoID string

	eng.mu.Lock()
	if act == "block" {
		if doHotspot {
			eng.blockedTargets[normVal] = true
			eng.deleteTombstoneLocked(normVal)
			if blockedAlsoIP != "" {
				eng.blockedTargets[blockedAlsoIP] = true
				eng.deleteTombstoneLocked(blockedAlsoIP)
			}
		}
		effectiveUndoScope := targetScope
		if targetScope == leakTargetScopeBoth && kind != "domain" && hostUndoUID == 0 {
			effectiveUndoScope = leakTargetScopeHotspot
		}
		sum := sha1.Sum([]byte(fmt.Sprintf("%d|%s|%s|%s|%d|%s", time.Now().UnixNano(), effectiveUndoScope, kind, normVal, hostUndoUID, strings.Join(targetMACs, ","))))
		undoID = "ub_" + hex.EncodeToString(sum[:6])
		eng.pushUndoLocked(LeakBlockUndoEntry{
			ID:          undoID,
			DstHost:     normVal,
			Kind:        kind,
			TargetScope: effectiveUndoScope,
			UID:         hostUndoUID,
			AlsoIP:      blockedAlsoIP,
			MACs:        append([]string(nil), targetMACs...),
			CreatedAt:   now,
		})
	} else {
		if doHotspot {
			if !hasAnyDeviceConnBlock(cbNow, normVal) {
				delete(eng.blockedTargets, normVal)
				eng.setTombstoneLocked(normVal, now)
			}
			for _, uip := range unblockedIPs {
				if !hasAnyDeviceConnBlock(cbNow, uip) {
					delete(eng.blockedTargets, uip)
					eng.setTombstoneLocked(uip, now)
				}
			}
		}
		eng.pruneUndoOnUnblockLocked(kind, normVal, targetMACs, targetScope, reqUID)
	}
	eng.recomputeEventsBlockedLocked(cbNow)
	undoCnt := len(eng.undoStack)
	_ = eng.saveStateLocked()
	eng.mu.Unlock()

	if doHotspot {
		s.refreshDNSTKBlocklist(time.Now())
	}
	eng.notifySSEChanged()

	selfBlockedNow := false
	if sf != nil {
		if kind == "domain" {
			selfBlockedNow = sf.IsDomainBlocked(normVal)
		} else if kind == "ip" && reqUID > 0 {
			selfBlockedNow = sf.IsHostEventBlocked(reqUID, "", normVal, 80, "tcp")
		}
	}
	respBody := map[string]any{
		"ok":                true,
		"action":            act,
		"target_scope":      targetScope,
		"kind":              kind,
		"dst_host":          normVal,
		"is_blocked":        act == "block",
		"self_blocked":      selfBlockedNow,
		"macs":              targetMACs,
		"applied_cnt":       applied,
		"skipped_shared_ip": skippedSharedIP,
		"undo_count":        undoCnt,
		"detail":            lastDetail,
	}
	if reqUID > 0 {
		respBody["uid"] = reqUID
	}
	if undoID != "" {
		respBody["undo_id"] = undoID
	}
	if skippedSharedIP {
		respBody["skipped_ip"] = normAlsoIP
		respBody["skipped_ip_vendor"] = skippedIPVendor
	}
	if blockedAlsoIP != "" {
		respBody["blocked_also_ip"] = blockedAlsoIP
	}
	if act == "block" && guardDecision.Level == leakGuardLevelWarnConfirm && req.Force {
		respBody["guard_forced"] = true
		respBody["vendor"] = guardDecision.Vendor
	}
	writeJSON(w, http.StatusOK, respBody)
}

// apiLeakGuardUndoBlock POST /api/leakguard/undo-block
// 一键弹出最近 1 条（或按 id / target_scope 指定）封禁记录执行热点/本机/双域 100% 干净回滚解封;
// 若底层解封失败则将撤销栈完整恢复, 严禁吞错丢记录。
func (s *server) apiLeakGuardUndoBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID          string `json:"id"`
		TargetScope string `json:"target_scope"`
	}
	if r.Body != nil {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad body", "detail": err.Error()})
			return
		}
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) > 0 {
			dec := json.NewDecoder(bytes.NewReader(trimmed))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json", "detail": err.Error()})
				return
			}
		}
	}

	reqTargetScopeRaw := strings.ToLower(strings.TrimSpace(req.TargetScope))
	if reqTargetScopeRaw != "" {
		if _, ok := parseLeakTargetScope(reqTargetScopeRaw); !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":     false,
				"error":  "bad params",
				"detail": "target_scope must be hotspot|host|both",
			})
			return
		}
	}

	st := s.v6State()
	eng := st.leakGuard
	sf := st.selfFirewall
	targetID := strings.TrimSpace(req.ID)

	eng.mu.Lock()
	if len(eng.undoStack) == 0 {
		eng.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":     false,
			"error":  "empty_undo_stack",
			"detail": "当前没有可撤销的封禁记录",
		})
		return
	}

	matchesScopeFilter := func(entryScope string) bool {
		switch reqTargetScopeRaw {
		case "", leakTargetScopeBoth:
			return true
		case leakTargetScopeHost:
			return entryScope == leakTargetScopeHost || entryScope == leakTargetScopeBoth
		case leakTargetScopeHotspot:
			return entryScope == leakTargetScopeHotspot || entryScope == leakTargetScopeBoth
		default:
			return false
		}
	}

	pickIdx := -1
	for i := len(eng.undoStack) - 1; i >= 0; i-- {
		cur := eng.undoStack[i]
		if targetID != "" && cur.ID != targetID {
			continue
		}
		if matchesScopeFilter(effectiveUndoTargetScope(cur.TargetScope)) {
			pickIdx = i
			break
		}
	}
	if pickIdx < 0 {
		eng.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":     false,
			"error":  "undo_not_found",
			"detail": "指定的封禁撤销记录不存在",
		})
		return
	}

	prevStackSnapshot := make([]LeakBlockUndoEntry, len(eng.undoStack))
	copy(prevStackSnapshot, eng.undoStack)

	entry := eng.undoStack[pickIdx]
	origScope := effectiveUndoTargetScope(entry.TargetScope)
	entry.TargetScope = origScope

	undoHotspot := origScope == leakTargetScopeHotspot || origScope == leakTargetScopeBoth
	undoHost := origScope == leakTargetScopeHost || origScope == leakTargetScopeBoth
	executedScope := origScope

	if reqTargetScopeRaw == leakTargetScopeHost && origScope == leakTargetScopeBoth {
		undoHotspot = false
		undoHost = true
		executedScope = leakTargetScopeHost
		eng.undoStack[pickIdx].TargetScope = leakTargetScopeHotspot
		eng.undoStack[pickIdx].UID = 0
	} else if reqTargetScopeRaw == leakTargetScopeHotspot && origScope == leakTargetScopeBoth {
		undoHotspot = true
		undoHost = false
		executedScope = leakTargetScopeHotspot
		eng.undoStack[pickIdx].TargetScope = leakTargetScopeHost
		eng.undoStack[pickIdx].MACs = nil
		eng.undoStack[pickIdx].AlsoIP = ""
	} else {
		eng.undoStack = append(eng.undoStack[:pickIdx], eng.undoStack[pickIdx+1:]...)
	}
	stillHasHostRef := eng.hasHostDomainInUndoLocked(entry.DstHost)
	stillHasHostIPRef := eng.hasHostIPInUndoLocked(entry.UID, entry.DstHost)
	eng.mu.Unlock()

	var (
		macsToUnblock []string
		applied       int
		lastDetail    string
		errResp       *actionResp
	)

	if undoHotspot {
		scriptExists := false
		if stFile, err := os.Stat(filepath.Join(s.hncDir, "bin", "connblock_sync.sh")); err == nil && !stFile.IsDir() {
			scriptExists = true
		}

		existingCB := readConnBlocks(s.hncDir)
		macSet := make(map[string]bool, len(entry.MACs))
		for _, m := range entry.MACs {
			nm := strings.ToLower(strings.TrimSpace(m))
			if validMAC(nm) && !macSet[nm] {
				macSet[nm] = true
				macsToUnblock = append(macsToUnblock, nm)
			}
		}
		if len(macsToUnblock) == 0 {
			for _, it := range existingCB.Items {
				nm := strings.ToLower(strings.TrimSpace(it.MAC))
				if it.Kind == entry.Kind && strings.EqualFold(it.Value, entry.DstHost) && validMAC(nm) && !macSet[nm] {
					macSet[nm] = true
					macsToUnblock = append(macsToUnblock, nm)
				}
			}
		}
		sort.Strings(macsToUnblock)

		alsoMACsToUnblock := append([]string(nil), macsToUnblock...)
		if entry.AlsoIP != "" {
			alsoSet := make(map[string]bool, len(alsoMACsToUnblock))
			for _, m := range alsoMACsToUnblock {
				alsoSet[m] = true
			}
			for _, it := range existingCB.Items {
				nm := strings.ToLower(strings.TrimSpace(it.MAC))
				if it.Kind == "ip" && strings.EqualFold(it.Value, entry.AlsoIP) && validMAC(nm) && !alsoSet[nm] {
					alsoSet[nm] = true
					alsoMACsToUnblock = append(alsoMACsToUnblock, nm)
				}
			}
			sort.Strings(alsoMACsToUnblock)
		}

		applied, lastDetail, errResp = applyConnBlockActionForMACs(s, "unblock", entry.Kind, entry.DstHost, macsToUnblock, scriptExists)
		if errResp == nil && entry.AlsoIP != "" {
			alsoApplied, alsoDetail, ipErrResp := applyConnBlockActionForMACs(s, "unblock", "ip", entry.AlsoIP, alsoMACsToUnblock, scriptExists)
			if ipErrResp != nil {
				errResp = ipErrResp
			} else {
				applied += alsoApplied
				if lastDetail == "" && alsoDetail != "" {
					lastDetail = alsoDetail
				}
			}
		}
		if errResp == nil && applied == 0 && scriptExists {
			connBlockMu.Lock()
			syncOut, syncErr := s.connBlockSyncLocked(true)
			connBlockMu.Unlock()
			if syncErr != nil {
				errResp = &actionResp{OK: false, Error: "sync failed", Detail: syncOut}
			} else if lastDetail == "" {
				lastDetail = syncOut
			}
		}
	}

	if errResp == nil && undoHost && entry.Kind == "domain" && sf != nil && !stillHasHostRef {
		if _, _, herr := sf.UnblockDomain(entry.DstHost); herr != nil {
			errResp = &actionResp{OK: false, Error: "self_dns_unblock_failed", Detail: herr.Error()}
		} else {
			applied++
			if lastDetail == "" {
				lastDetail = "self dns unblocked: " + entry.DstHost
			} else {
				lastDetail = lastDetail + "; self dns unblocked: " + entry.DstHost
			}
		}
	}

	if errResp == nil && undoHost && entry.Kind == "ip" && entry.UID > 0 && sf != nil && !stillHasHostIPRef {
		if _, herr := sf.RemoveUIDBlockTarget(entry.UID, entry.DstHost); herr != nil {
			errResp = &actionResp{OK: false, Error: "self_uid_unblock_failed", Detail: herr.Error()}
		} else {
			applied++
			if lastDetail == "" {
				lastDetail = fmt.Sprintf("self uid(%d) ip unblocked: %s", entry.UID, entry.DstHost)
			} else {
				lastDetail = fmt.Sprintf("%s; self uid(%d) ip unblocked: %s", lastDetail, entry.UID, entry.DstHost)
			}
		}
	}

	if errResp != nil {
		// 底层解封失败: 完整恢复撤销栈快照并持久化, 绝不吞错丢记录!
		eng.mu.Lock()
		eng.undoStack = prevStackSnapshot
		remUndo := len(eng.undoStack)
		_ = eng.saveStateLocked()
		eng.mu.Unlock()
		if undoHotspot {
			s.refreshDNSTKBlocklist(time.Now())
		}
		status := http.StatusInternalServerError
		if errResp.Error == "bad params" {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]any{
			"ok":             false,
			"error":          errResp.Error,
			"detail":         errResp.Detail,
			"undo_id":        entry.ID,
			"remaining_undo": remUndo,
		})
		return
	}

	cbNow := readConnBlocks(s.hncDir)
	undoNow := time.Now().Unix()

	eng.mu.Lock()
	if undoHotspot {
		if !hasAnyDeviceConnBlock(cbNow, entry.DstHost) {
			delete(eng.blockedTargets, entry.DstHost)
			eng.setTombstoneLocked(entry.DstHost, undoNow)
		}
		if entry.AlsoIP != "" && !hasAnyDeviceConnBlock(cbNow, entry.AlsoIP) {
			delete(eng.blockedTargets, entry.AlsoIP)
			eng.setTombstoneLocked(entry.AlsoIP, undoNow)
		}
	}
	eng.recomputeEventsBlockedLocked(cbNow)
	remUndo := len(eng.undoStack)
	saveErr := eng.saveStateLocked()
	if saveErr != nil {
		eng.undoStack = prevStackSnapshot
		remUndo = len(eng.undoStack)
	}
	eng.mu.Unlock()

	if undoHotspot {
		s.refreshDNSTKBlocklist(time.Now())
	}
	eng.notifySSEChanged()

	if saveErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":             false,
			"error":          "write state failed",
			"detail":         saveErr.Error(),
			"undo_id":        entry.ID,
			"remaining_undo": remUndo,
		})
		return
	}

	undoneOut := entry
	undoneOut.TargetScope = executedScope
	selfBlockedNow := false
	if sf != nil {
		if entry.Kind == "domain" {
			selfBlockedNow = sf.IsDomainBlocked(entry.DstHost)
		} else if entry.Kind == "ip" && entry.UID > 0 {
			selfBlockedNow = sf.IsHostEventBlocked(entry.UID, "", entry.DstHost, 80, "tcp")
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"undo_id":        entry.ID,
		"target_scope":   executedScope,
		"self_blocked":   selfBlockedNow,
		"undone":         undoneOut,
		"dst_host":       entry.DstHost,
		"kind":           entry.Kind,
		"uid":            entry.UID,
		"also_ip":        entry.AlsoIP,
		"macs":           macsToUnblock,
		"applied_cnt":    applied,
		"remaining_undo": remUndo,
		"detail":         lastDetail,
	})
}
