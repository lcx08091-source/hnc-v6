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

	leakGuard *leakGuardEngine
	express   *vectorExpressEngine
	leash     *updateLeashEngine
	scalpel   *flowScalpelEngine
	thermo    *thermoCruiseEngine
}

var v6Registry sync.Map // map[*server]*v6ServerState

func (s *server) v6State() *v6ServerState {
	if v, ok := v6Registry.Load(s); ok {
		return v.(*v6ServerState)
	}
	st := &v6ServerState{
		leakGuard: newLeakGuardEngine(s),
		express:   newVectorExpressEngine(s),
		leash:     newUpdateLeashEngine(s),
		scalpel:   newFlowScalpelEngine(s),
		thermo:    newThermoCruiseEngine(s),
	}
	actual, _ := v6Registry.LoadOrStore(s, st)
	return actual.(*v6ServerState)
}

// registerV6FeatureRoutes 供总装阶段在 server.handler() 内一键挂载五大 v6 核心路由。
func (s *server) registerV6FeatureRoutes(mux *http.ServeMux) {
	if s == nil || mux == nil {
		return
	}
	_ = s.v6State()

	// 模块 1: LeakGuard 隐私防泄露哨兵
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
}

// registerV6FeatureRoutes 包级同名包装, 兼容 registerV6FeatureRoutes(mux, s) 与 s.registerV6FeatureRoutes(mux) 两种总装调用签名。
func registerV6FeatureRoutes(mux *http.ServeMux, s *server) {
	if s != nil && mux != nil {
		s.registerV6FeatureRoutes(mux)
	}
}

// v6FeaturesSummary 供 /api/vector_sync 或全局驾驶舱一键拉取五大模块轻量实时摘要。
func (s *server) v6FeaturesSummary() map[string]any {
	if s == nil {
		return map[string]any{}
	}
	st := s.v6State()
	st.summaryCalls.Add(1)
	return map[string]any{
		"leakguard":    st.leakGuard.summary(),
		"express":      st.express.summary(),
		"update_leash": st.leash.summary(),
		"scalpel":      st.scalpel.summary(),
		"thermo":       st.thermo.summary(),
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
	MAC        string `json:"mac"`
	SrcIP      string `json:"src_ip"`
	DeviceName string `json:"device_name"`
	DstHost    string `json:"dst_host"`
	DstIP      string `json:"dst_ip,omitempty"`
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
}

// LeakBlockUndoEntry 最近 10 条封禁一键撤销栈记录。
type LeakBlockUndoEntry struct {
	ID        string   `json:"id"`
	DstHost   string   `json:"dst_host"`
	Kind      string   `json:"kind"`              // "domain" | "ip"
	AlsoIP    string   `json:"also_ip,omitempty"` // 同次连带封锁的独立 IP（若命中共享 CDN IP 自动跳过则为空）
	MACs      []string `json:"macs,omitempty"`    // 本次封禁实际作用的设备 MAC 列表
	CreatedAt int64    `json:"created_at"`
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
	// 64 位原子字段严格连续置于结构体最顶部 offset 0, 8, 16, 24, 32 (兼容 32 位 GOARCH=arm)
	totalHits     atomic.Int64
	clearSeq      atomic.Int64
	ignoredHits   atomic.Int64
	guardBlocks   atomic.Int64
	diskReadCount atomic.Int64

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

// writeLeakGuardAtomic0600 原子落盘并强制收紧权限为 0o600, 防止明文隐私配置/事件被同机非特权进程读取。
func writeLeakGuardAtomic0600(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	seq := discoverWriteSeq.Add(1)
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
	e.ignoredSeenIDs = make(map[string]int64)
	e.hasEventsStat = false
	e.loadPersistedLocked()
	if len(e.events) > e.cfg.Capacity {
		e.events = append([]LeakEvent(nil), e.events[len(e.events)-e.cfg.Capacity:]...)
	}
	_ = e.purgeIgnoredEventsLocked()
	e.recomputeEventsBlockedLocked(cbNow)
	_ = e.writeCtrlFileLocked(time.Now().Unix())
	e.mu.Unlock()
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

func leakTypeDisplayName(leakType string) string {
	switch strings.ToLower(strings.TrimSpace(leakType)) {
	case "phone", "mobile":
		return "手机号"
	case "id_card", "idcard", "cn_id":
		return "身份证号"
	case "password", "passwd", "pwd":
		return "明文密码"
	case "token", "bearer", "api_key", "apikey", "jwt":
		return "认证凭据/Token"
	case "bank_card", "card":
		return "银行卡号"
	case "email":
		return "邮箱地址"
	case "imei", "imsi", "oaid", "android_id":
		return "设备唯一标识"
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
	ev := LeakEvent{
		ID:         str("id", "event_id"),
		Ts:         i64("ts", "timestamp", "time"),
		MAC:        strings.ToLower(str("mac", "client_mac")),
		SrcIP:      str("src_ip", "client_ip", "ip", "src"),
		DeviceName: str("device_name", "hostname", "device"),
		DstHost:    strings.ToLower(str("dst_host", "host", "domain", "dst")),
		DstIP:      str("dst_ip", "dst"),
		DstPort:    int(i64("dst_port", "dport", "port")),
		Proto:      strings.ToLower(str("proto", "protocol")),
		Method:     strings.ToUpper(str("method", "http_method")),
		Path:       str("path", "url", "uri"),
		LeakType:   str("leak_type", "type", "kind"),
		LeakLabel:  str("leak_label", "label"),
		RawValue:   str("raw_value", "value", "secret"),
		RawSnippet: str("raw_snippet", "snippet", "payload"),
		HitCount:   i64("hit_count", "hits"),
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
		if ip.IsLoopback() || ip.IsUnspecified() || isPrivateIP(ip.String()) {
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
		if itMAC == "" || itMAC == "*" || itMAC == "all" || (mac != "" && itMAC == mac) {
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

func (e *leakGuardEngine) purgeIgnoredEventsLocked() int {
	if len(e.events) == 0 || len(e.ignoreRules) == 0 {
		return 0
	}
	if e.ignoredSeenIDs == nil {
		e.ignoredSeenIDs = make(map[string]int64)
	}
	kept := make([]LeakEvent, 0, len(e.events))
	purged := 0
	var removedHits int64
	for _, ev := range e.events {
		if e.matchesIgnoreRuleLocked(ev) {
			purged++
			hc := ev.HitCount
			if hc <= 0 {
				hc = 1
			}
			removedHits += hc
			delete(e.seenIDs, ev.ID)
			e.ignoredSeenIDs[ev.ID] = hc
			e.ignoredHits.Add(hc)
			continue
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
	}
	return purged
}

func (e *leakGuardEngine) recomputeEventsBlockedLocked(cb connBlockFile) {
	for i := range e.events {
		blocked := matchBlockedHost(e.events[i].DstHost, e.events[i].MAC, cb, e.blockedTargets)
		if !blocked && e.events[i].DstIP != "" {
			blocked = matchBlockedHost(e.events[i].DstIP, e.events[i].MAC, cb, e.blockedTargets)
		}
		e.events[i].IsBlocked = blocked
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
	filtered := make([]LeakBlockUndoEntry, 0, len(e.undoStack)+1)
	for _, cur := range e.undoStack {
		if cur.Kind == entry.Kind && cur.DstHost == entry.DstHost && cur.AlsoIP == entry.AlsoIP && sameSortedMACs(cur.MACs, entry.MACs) {
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

func (e *leakGuardEngine) pruneUndoOnUnblockLocked(kind, normVal string, unblockedMACs []string) {
	if len(e.undoStack) == 0 {
		return
	}
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
		if len(cur.MACs) == 0 || len(unblkSet) == 0 {
			continue
		}
		var rem []string
		for _, m := range cur.MACs {
			if !unblkSet[strings.ToLower(strings.TrimSpace(m))] {
				rem = append(rem, m)
			}
		}
		if len(rem) > 0 {
			cur.MACs = rem
			kept = append(kept, cur)
		}
	}
	e.undoStack = kept
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
	e.mu.Unlock()

	parsed := decodeLeakEventsPayload(raw)
	if len(parsed) == 0 {
		return nil
	}
	return e.IngestEvents(parsed)
}

// IngestEvents 线程安全地摄入一批 LeakEvent（支持单测直接喂入或从 run/leakguard_events.json 合并）。
func (e *leakGuardEngine) IngestEvents(incoming []LeakEvent) []LeakEvent {
	if len(incoming) == 0 {
		return nil
	}
	nameByMAC, macByIP := e.srv.buildDeviceDirectory()

	e.mu.Lock()
	cfg := e.cfg
	clearedAt := e.clearedAt
	if e.ignoredSeenIDs == nil {
		e.ignoredSeenIDs = make(map[string]int64)
	}
	var added []LeakEvent
	var toNotify []LeakEvent

	for _, ev := range incoming {
		if ev.Ts <= 0 {
			ev.Ts = time.Now().Unix()
		}
		if clearedAt > 0 && ev.Ts < clearedAt {
			continue
		}
		if ev.Ts > e.maxSeenTs {
			e.maxSeenTs = ev.Ts
		}
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

		if _, dup := e.seenIDs[ev.ID]; dup {
			for idx := len(e.events) - 1; idx >= 0; idx-- {
				if e.events[idx].ID == ev.ID {
					if ev.HitCount > e.events[idx].HitCount {
						delta := ev.HitCount - e.events[idx].HitCount
						e.events[idx].HitCount = ev.HitCount
						e.events[idx].Ts = ev.Ts
						e.totalHits.Add(delta)
					}
					break
				}
			}
			continue
		}
		e.seenIDs[ev.ID] = ev.Ts
		e.events = append(e.events, ev)
		e.totalHits.Add(ev.HitCount)
		added = append(added, ev)

		devKey := ev.MAC
		if devKey == "" {
			devKey = ev.SrcIP
		}
		cdKey := devKey + "|" + strings.ToLower(ev.DstHost) + "|" + strings.ToLower(ev.LeakType)
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
			_ = alert.Append(acfg.AlertsJSONLPath, alert.Alert{
				ID:     ev.ID,
				Ts:     ev.Ts,
				Kind:   "leakguard",
				MAC:    ev.MAC,
				IP:     ev.SrcIP,
				Detail: fmt.Sprintf("%s 向 %s 明文传输 %s", ev.DeviceName, ev.DstHost, ev.LeakLabel),
				Extra: map[string]interface{}{
					"dst_host":  ev.DstHost,
					"leak_type": ev.LeakType,
				},
			})
		}
		if cfg.NotifyEnabled {
			e.postAndroidNotificationAsync(ev, cfg.LockscreenMask)
		}
	}
	return added
}

func (e *leakGuardEngine) snapshotPayload() map[string]any {
	e.syncFromDisk()

	nameByMAC, macByIP := e.srv.buildDeviceDirectory()
	cb := readConnBlocks(e.srv.hncDir)

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
		out = append(out, ev)
	}

	totalHits := e.totalHits.Load()
	if int64(len(out)) > totalHits {
		totalHits = int64(len(out))
	}
	ignoredHits := e.ignoredHits.Load()
	guardBlocks := e.guardBlocks.Load()
	affectedDevs := len(devSet)
	blockedDomains := len(blockedHostSet)

	return map[string]any{
		"ok":               true,
		"events":           out,
		"total_hits":       totalHits,
		"ignored_hits":     ignoredHits,
		"guard_blocks":     guardBlocks,
		"affected_devices": affectedDevs,
		"blocked_domains":  blockedDomains,
		"ignore_rules":     ignoreRules,
		"undo_stack":       undoStack,
		"undo_count":       len(undoStack),
		"stats": map[string]any{
			"total_hits":       totalHits,
			"ignored_hits":     ignoredHits,
			"guard_blocks":     guardBlocks,
			"affected_devices": affectedDevs,
			"blocked_domains":  blockedDomains,
		},
		"config": cfg,
	}
}

func (e *leakGuardEngine) summary() map[string]any {
	e.mu.Lock()
	cfg := e.cfg
	cnt := len(e.events)
	blockedCnt := len(e.blockedTargets)
	ignoreCnt := len(e.ignoreRules)
	undoCnt := len(e.undoStack)
	e.mu.Unlock()
	return map[string]any{
		"total_hits":       e.totalHits.Load(),
		"ignored_hits":     e.ignoredHits.Load(),
		"guard_blocks":     e.guardBlocks.Load(),
		"buffered_events":  cnt,
		"blocked_domains":  blockedCnt,
		"ignore_rules_cnt": ignoreCnt,
		"undo_count":       undoCnt,
		"notify_enabled":   cfg.NotifyEnabled,
		"lockscreen_mask":  cfg.LockscreenMask,
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
		shouldSleep := act.Known && !simOn && (!act.HotspotActive || (act.ClientsOnline <= 0 && !act.WebUIActive && leakSSEActiveConns.Load() == 0))
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

// apiLeakGuardEvents GET /api/leakguard/events
func (s *server) apiLeakGuardEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "GET only"})
		return
	}
	writeJSON(w, http.StatusOK, s.v6State().leakGuard.snapshotPayload())
}

// apiLeakGuardStream GET /api/leakguard/stream — SSE 实时流推送新捕获的 LeakEvent + 保活心跳帧
func (s *server) apiLeakGuardStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "GET only"})
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
	eng.ignoredSeenIDs = make(map[string]int64)
	eng.cooldownLedger = make(map[string]int64)
	eng.hasEventsStat = false
	eng.clearedAt = clrTs
	eng.maxSeenTs = clrTs
	seq := eng.clearSeq.Add(1)
	eng.totalHits.Store(0)
	if s.hncDir != "" {
		_ = writeLeakGuardAtomic0600(eng.dpidEventsPath(), []byte("{\"events\":[]}\n"))
	}
	err := eng.saveStateLocked()
	eng.mu.Unlock()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write ctrl failed", "detail": err.Error()})
		return
	}
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

// apiLeakGuardWhitelist POST /api/leakguard/whitelist
// 支持 action: "add" | "remove" | "clear", 三级作用域 "host_type" | "host" | "device_host_type", 硬上限 200 条。
func (s *server) apiLeakGuardWhitelist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action   string `json:"action"`
		ID       string `json:"id"`
		Scope    string `json:"scope"`
		DstHost  string `json:"dst_host"`
		LeakType string `json:"leak_type"`
		MAC      string `json:"mac"`
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
	eng := s.v6State().leakGuard

	switch act {
	case "add":
		rule, err := dpidlg.NormalizeIgnoreRule(dpidlg.IgnoreRule{
			Scope:    req.Scope,
			DstHost:  req.DstHost,
			LeakType: req.LeakType,
			MAC:      req.MAC,
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
		purged := eng.purgeIgnoredEventsLocked()
		rulesOut := make([]dpidlg.IgnoreRule, len(eng.ignoreRules))
		copy(rulesOut, eng.ignoreRules)
		saveErr := eng.saveStateLocked()
		eng.mu.Unlock()
		if saveErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write whitelist failed", "detail": saveErr.Error()})
			return
		}
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
	for _, mac := range targetMACs {
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
			continue
		}
		if resp.Error == "sync failed" && !scriptExists {
			applied++
			lastDetail = "saved (sandbox no connblock_sync.sh)"
			continue
		}
		if act == "unblock" && resp.Error == "not found" {
			continue
		}
		return applied, lastDetail, &resp
	}
	return applied, lastDetail, nil
}

// apiLeakGuardBlockDomain POST /api/leakguard/block-domain
// 支持 action: "block" | "unblock", 集成三级共享基础设施防误杀守卫、also_ip 共享 CDN IP 剥离与 10 条撤销栈。
func (s *server) apiLeakGuardBlockDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action  string `json:"action"`
		DstHost string `json:"dst_host"`
		MAC     string `json:"mac"`
		Force   bool   `json:"force"`
		AlsoIP  string `json:"also_ip"`
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
	kind, normVal, ok := normalizeBlockTarget(req.DstHost)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "invalid dst_host (domain or public IP required)"})
		return
	}

	eng := s.v6State().leakGuard

	var guardDecision leakBlockGuardDecision
	if act == "block" {
		guardDecision = evaluateLeakBlockGuard(s, kind, normVal)
		if guardDecision.Level == leakGuardLevelHardBlock {
			eng.guardBlocks.Add(1)
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok":          false,
				"error":       "guard_hard_block",
				"guard_level": leakGuardLevelHardBlock,
				"vendor":      guardDecision.Vendor,
				"category":    guardDecision.Category,
				"dst_host":    normVal,
				"detail":      guardDecision.Detail,
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
				"vendor":           guardDecision.Vendor,
				"category":         guardDecision.Category,
				"dst_host":         normVal,
				"detail":           guardDecision.Detail,
			})
			return
		}
	}

	reqMAC := strings.ToLower(strings.TrimSpace(req.MAC))
	var targetMACs []string
	if reqMAC != "" && reqMAC != "all" && reqMAC != "*" {
		if !validMAC(reqMAC) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad params", "detail": "invalid mac"})
			return
		}
		targetMACs = []string{reqMAC}
	} else {
		macSet := make(map[string]bool)
		eng.mu.Lock()
		for _, ev := range eng.events {
			if validMAC(ev.MAC) {
				_, evHost, hok := normalizeBlockTarget(ev.DstHost)
				if !hok {
					evHost = strings.ToLower(ev.DstHost)
				}
				if evHost == normVal || strings.HasSuffix(evHost, "."+normVal) || ev.DstIP == normVal {
					macSet[ev.MAC] = true
				}
			}
		}
		eng.mu.Unlock()
		for mac := range s.deviceIPsByMAC() {
			if validMAC(mac) && !isProtectedMAC(s.hncDir, mac) {
				macSet[mac] = true
			}
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

	scriptExists := false
	if st, err := os.Stat(filepath.Join(s.hncDir, "bin", "connblock_sync.sh")); err == nil && !st.IsDir() {
		scriptExists = true
	}

	applied, lastDetail, errResp := applyConnBlockActionForMACs(s, act, kind, normVal, targetMACs, scriptExists)
	if errResp != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":     false,
			"error":  errResp.Error,
			"detail": errResp.Detail,
		})
		return
	}

	var (
		skippedSharedIP bool
		skippedIPVendor string
		blockedAlsoIP   string
		normAlsoIP      string
	)
	if rawAlso := strings.TrimSpace(req.AlsoIP); rawAlso != "" && kind == "domain" {
		if ipKind, parsedIP, ipOK := normalizeBlockTarget(rawAlso); ipOK && ipKind == "ip" && !strings.EqualFold(parsedIP, normVal) {
			normAlsoIP = parsedIP
			if act == "block" {
				if shared, vendor := detectSharedInfraIP(s, normAlsoIP); shared {
					skippedSharedIP = true
					skippedIPVendor = vendor
				} else {
					if _, _, ipErr := applyConnBlockActionForMACs(s, "block", "ip", normAlsoIP, targetMACs, scriptExists); ipErr == nil {
						blockedAlsoIP = normAlsoIP
					}
				}
			} else {
				_, _, _ = applyConnBlockActionForMACs(s, "unblock", "ip", normAlsoIP, targetMACs, scriptExists)
			}
		}
	}

	cbNow := readConnBlocks(s.hncDir)
	now := time.Now().Unix()

	eng.mu.Lock()
	if act == "block" {
		eng.blockedTargets[normVal] = true
		eng.deleteTombstoneLocked(normVal)
		if blockedAlsoIP != "" {
			eng.blockedTargets[blockedAlsoIP] = true
			eng.deleteTombstoneLocked(blockedAlsoIP)
		}
		sum := sha1.Sum([]byte(fmt.Sprintf("%d|%s|%s|%s", time.Now().UnixNano(), kind, normVal, strings.Join(targetMACs, ","))))
		eng.pushUndoLocked(LeakBlockUndoEntry{
			ID:        "ub_" + hex.EncodeToString(sum[:6]),
			DstHost:   normVal,
			Kind:      kind,
			AlsoIP:    blockedAlsoIP,
			MACs:      append([]string(nil), targetMACs...),
			CreatedAt: now,
		})
	} else {
		if !hasAnyDeviceConnBlock(cbNow, normVal) {
			delete(eng.blockedTargets, normVal)
			eng.setTombstoneLocked(normVal, now)
		}
		if normAlsoIP != "" && !hasAnyDeviceConnBlock(cbNow, normAlsoIP) {
			delete(eng.blockedTargets, normAlsoIP)
			eng.setTombstoneLocked(normAlsoIP, now)
		}
		eng.pruneUndoOnUnblockLocked(kind, normVal, targetMACs)
	}
	eng.recomputeEventsBlockedLocked(cbNow)
	undoCnt := len(eng.undoStack)
	_ = eng.saveStateLocked()
	eng.mu.Unlock()

	respBody := map[string]any{
		"ok":                true,
		"action":            act,
		"kind":              kind,
		"dst_host":          normVal,
		"is_blocked":        act == "block",
		"macs":              targetMACs,
		"applied_cnt":       applied,
		"skipped_shared_ip": skippedSharedIP,
		"undo_count":        undoCnt,
		"detail":            lastDetail,
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
// 一键弹出最近 1 条（或按 id 指定）封禁记录执行回滚解封, 且仅当无其他设备封锁该目标时才从全局 blockedTargets 移除。
func (s *server) apiLeakGuardUndoBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
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

	eng := s.v6State().leakGuard
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
	pickIdx := len(eng.undoStack) - 1
	if targetID != "" {
		pickIdx = -1
		for i := len(eng.undoStack) - 1; i >= 0; i-- {
			if eng.undoStack[i].ID == targetID {
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
	}
	entry := eng.undoStack[pickIdx]
	eng.undoStack = append(eng.undoStack[:pickIdx], eng.undoStack[pickIdx+1:]...)
	eng.mu.Unlock()

	scriptExists := false
	if st, err := os.Stat(filepath.Join(s.hncDir, "bin", "connblock_sync.sh")); err == nil && !st.IsDir() {
		scriptExists = true
	}

	macsToUnblock := entry.MACs
	if len(macsToUnblock) == 0 {
		for _, it := range readConnBlocks(s.hncDir).Items {
			if it.Kind == entry.Kind && strings.EqualFold(it.Value, entry.DstHost) && validMAC(it.MAC) {
				macsToUnblock = append(macsToUnblock, it.MAC)
			}
		}
	}

	applied, lastDetail, _ := applyConnBlockActionForMACs(s, "unblock", entry.Kind, entry.DstHost, macsToUnblock, scriptExists)
	if entry.AlsoIP != "" {
		_, _, _ = applyConnBlockActionForMACs(s, "unblock", "ip", entry.AlsoIP, macsToUnblock, scriptExists)
	}

	cbNow := readConnBlocks(s.hncDir)
	undoNow := time.Now().Unix()

	eng.mu.Lock()
	if !hasAnyDeviceConnBlock(cbNow, entry.DstHost) {
		delete(eng.blockedTargets, entry.DstHost)
		eng.setTombstoneLocked(entry.DstHost, undoNow)
	}
	if entry.AlsoIP != "" && !hasAnyDeviceConnBlock(cbNow, entry.AlsoIP) {
		delete(eng.blockedTargets, entry.AlsoIP)
		eng.setTombstoneLocked(entry.AlsoIP, undoNow)
	}
	eng.recomputeEventsBlockedLocked(cbNow)
	remUndo := len(eng.undoStack)
	saveErr := eng.saveStateLocked()
	eng.mu.Unlock()

	if saveErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write state failed", "detail": saveErr.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"undone":         entry,
		"dst_host":       entry.DstHost,
		"kind":           entry.Kind,
		"also_ip":        entry.AlsoIP,
		"macs":           macsToUnblock,
		"applied_cnt":    applied,
		"remaining_undo": remUndo,
		"detail":         lastDetail,
	})
}
