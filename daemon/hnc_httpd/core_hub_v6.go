// core_hub_v6.go — HNC v6.0.0 · Vector: 四舱壁防连坐 HNC Core 中枢与无锁 RCU 原子快照环
//
// 核心架构:
//   1. WorldSnapshot 无锁原子快照环:
//      - 内部以 atomic.Pointer[WorldSnapshot] 持有最新不可变全栈态势快照(含预编码 JSON 字节);
//      - 后台协程每 1.5s 异步刷新并原子替换指针;
//      - GET /api/vector_sync 仅执行一次原子 Load()(< 50ns), 零互斥锁等待、零子进程、零磁盘阻塞!
//   2. 四大防连坐隔离舱壁 (DataplaneBulkhead / DpiShmBulkhead / AndroidBridgeBulkhead / StorageBulkhead):
//      - 有界非阻塞任务队列 + recover() 异常隔离罩 + 连续超时半开熔断器(Circuit Breaker:
//        如 AndroidBridgeBulkhead 连续 2 次超时自动熔断退避 45s) + 基于单调时钟的 actorBeatMonoNs 心跳槽;
//   3. 进程组隔离包装器 ExecIsolatedAndroidCmd:
//      - 默认 2s 硬超时; Linux/Android 下强制 Setpgid: true 并在超时瞬间向 -pgid 发送 SIGKILL 连根清理孙进程;
//   4. 解耦式扩展注册器 RegisterVectorSyncProvider(name, fn):
//      - 各 v6 子模块按名字异步注册状态快照回调, 彻底解除跨组编译期函数签名耦合。
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"hnc.io/dpid/shm"
)

const (
	worldSnapshotInterval     = 1500 * time.Millisecond
	defaultAndroidCmdTimeout  = 2 * time.Second
	bulkheadHeartbeatInterval = 500 * time.Millisecond
	bulkheadHealthyMaxAge     = 10 * time.Second
	maxDetachedRunaways       = 2
)

var (
	ErrBulkheadCircuitOpen = errors.New("bulkhead circuit breaker open")
	ErrBulkheadQueueFull   = errors.New("bulkhead bounded queue full")
	ErrBulkheadTimeout     = errors.New("bulkhead execution timed out")
	ErrBulkheadClosed      = errors.New("bulkhead closed")
	ErrBulkheadPanic       = errors.New("bulkhead task panicked")
)

// coreBootEpoch 进程启动单调时钟锚点: time.Since(coreBootEpoch) 纯走单调时钟, 免受 NTP 墙钟跳变干扰。
var coreBootEpoch = time.Now()

// monoNowFn 供单测注入可控单调时钟(生产环境恒为 monoSinceBootNs)。
var monoNowFn = monoSinceBootNs

func monoSinceBootNs() int64 {
	d := time.Since(coreBootEpoch)
	if d < 0 {
		return 0
	}
	return int64(d)
}

func monoNowNs() int64 {
	return monoNowFn()
}

func coreUptimeSeconds() int64 {
	ns := monoNowNs()
	if ns <= 0 {
		return 0
	}
	return ns / int64(time.Second)
}

// ─── 解耦式扩展模块快照注册表 ─────────────────────────────────────────

type vectorSyncProviderEntry struct {
	fn    func() any
	srvFn func(s *server) any
}

var (
	vectorProvidersMu sync.RWMutex
	vectorProviders   = map[string]vectorSyncProviderEntry{}
)

// RegisterVectorSyncProvider 注册 v6 扩展模块态势提供者(同名覆盖; fn 为 nil 时移除)。
func RegisterVectorSyncProvider(name string, fn func() any) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	vectorProvidersMu.Lock()
	defer vectorProvidersMu.Unlock()
	if fn == nil {
		delete(vectorProviders, name)
		return
	}
	vectorProviders[name] = vectorSyncProviderEntry{fn: fn}
}

// RegisterServerVectorSyncProvider 注册需要访问 *server 上下文的 v6 扩展态势提供者。
func RegisterServerVectorSyncProvider(name string, fn func(s *server) any) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	vectorProvidersMu.Lock()
	defer vectorProvidersMu.Unlock()
	if fn == nil {
		delete(vectorProviders, name)
		return
	}
	vectorProviders[name] = vectorSyncProviderEntry{srvFn: fn}
}

// UnregisterVectorSyncProvider 移除已注册的扩展模块态势提供者。
func UnregisterVectorSyncProvider(name string) {
	RegisterVectorSyncProvider(name, nil)
}

// collectVectorSyncProviders 在后台快照协程内安全收集所有已注册模块状态(带 recover 隔离罩)。
func collectVectorSyncProviders(s *server) map[string]any {
	vectorProvidersMu.RLock()
	if len(vectorProviders) == 0 {
		vectorProvidersMu.RUnlock()
		return map[string]any{}
	}
	names := make([]string, 0, len(vectorProviders))
	entries := make(map[string]vectorSyncProviderEntry, len(vectorProviders))
	for k, v := range vectorProviders {
		names = append(names, k)
		entries[k] = v
	}
	vectorProvidersMu.RUnlock()

	sort.Strings(names)
	out := make(map[string]any, len(names))
	for _, name := range names {
		ent := entries[name]
		val, err := safeCallVectorProvider(name, ent, s)
		if err != nil {
			out[name] = map[string]any{
				"ok":    false,
				"error": err.Error(),
			}
			continue
		}
		if val != nil {
			out[name] = val
		}
	}
	return out
}

func safeCallVectorProvider(name string, ent vectorSyncProviderEntry, s *server) (val any, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("provider %s panic: %v", name, p)
			log.Printf("core_hub: recovered panic in provider %q: %v", name, p)
		}
	}()
	if ent.srvFn != nil {
		return ent.srvFn(s), nil
	}
	if ent.fn != nil {
		return ent.fn(), nil
	}
	return nil, nil
}

// ─── 进程组隔离外部命令执行器 ─────────────────────────────────────────

// ExecIsolatedAndroidCmd 在独立进程组中执行外部系统命令:
//   - 默认 2s 硬超时(timeout <= 0 时自动采用 2s);
//   - Linux/Android 下启用 Setpgid: true, 超时瞬间向 -pgid 发送 SIGKILL 连根清理全部孙进程;
//   - 严禁调用 ps / pidof (违反 P3 判活铁律)。
func ExecIsolatedAndroidCmd(parentCtx context.Context, timeout time.Duration, bin string, args ...string) ([]byte, error) {
	base := filepath.Base(bin)
	if base == "ps" || base == "pidof" {
		return nil, errors.New("forbidden process lookup command: use /proc or procfind")
	}
	if timeout <= 0 {
		timeout = defaultAndroidCmdTimeout
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	cmd := hardenCmd(exec.CommandContext(ctx, bin, args...))
	cmd.Env = []string{
		"PATH=/system/bin:/system/xbin:/vendor/bin:/usr/bin:/bin",
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error {
			if cmd.Process != nil && cmd.Process.Pid > 0 {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				return cmd.Process.Kill()
			}
			return nil
		}
	}
	cmd.WaitDelay = 400 * time.Millisecond

	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out, fmt.Errorf("isolated cmd %s timed out after %v: %w", bin, timeout, context.DeadlineExceeded)
	}
	return out, err
}

// ─── 防连坐隔离舱壁 (Bulkhead + Half-Open Circuit Breaker) ───────────

type BulkheadConfig struct {
	Name             string
	QueueSize        int
	DefaultTimeout   time.Duration
	TripThreshold    int32
	CooldownDuration time.Duration
	MaxStaleAge      time.Duration
}

type bulkheadTask struct {
	ctx     context.Context
	timeout time.Duration
	fn      func(ctx context.Context) error
	doneCh  chan error // nil 表示 Fire-and-Forget 异步投递
}

// Bulkhead 单个隔离舱壁。
// 铁律: 所有 64 位原子字段严格位于结构体最前端(offset 0, 8, 16...), 保证 32 位 ARMv7 8 字节对齐。
type Bulkhead struct {
	actorBeatMonoNs   atomic.Int64  // offset 0: 事件循环单调时钟心跳(ns)
	circuitOpenUntil  atomic.Int64  // offset 8: 熔断器退避截止单调时钟(ns), 0 = closed
	totalSubmitted    atomic.Uint64 // offset 16
	totalCompleted    atomic.Uint64 // offset 24
	totalErrors       atomic.Uint64 // offset 32
	totalTimeouts     atomic.Uint64 // offset 40
	totalPanics       atomic.Uint64 // offset 48
	totalRejected     atomic.Uint64 // offset 56
	totalCircuitTrips atomic.Uint64 // offset 64
	lastExecNs        atomic.Int64  // offset 72

	consecTimeouts atomic.Int32
	halfOpenProbe  atomic.Bool
	actorRunning   atomic.Bool
	closed         atomic.Bool

	name             string
	queue            chan bulkheadTask
	runawaySem       chan struct{}
	stopCh           chan struct{}
	actorOnce        sync.Once
	stopOnce         sync.Once
	defaultTimeout   time.Duration
	tripThreshold    int32
	cooldownDuration time.Duration
	maxStaleAge      time.Duration

	errMu   sync.RWMutex
	lastErr string
}

func NewBulkhead(cfg BulkheadConfig) *Bulkhead {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 32
	}
	if cfg.DefaultTimeout <= 0 {
		cfg.DefaultTimeout = defaultAndroidCmdTimeout
	}
	if cfg.TripThreshold <= 0 {
		cfg.TripThreshold = 2
	}
	if cfg.CooldownDuration <= 0 {
		cfg.CooldownDuration = 45 * time.Second
	}
	if cfg.MaxStaleAge <= 0 {
		cfg.MaxStaleAge = bulkheadHealthyMaxAge
	}
	b := &Bulkhead{
		name:             cfg.Name,
		queue:            make(chan bulkheadTask, cfg.QueueSize),
		runawaySem:       make(chan struct{}, maxDetachedRunaways),
		stopCh:           make(chan struct{}),
		defaultTimeout:   cfg.DefaultTimeout,
		tripThreshold:    cfg.TripThreshold,
		cooldownDuration: cfg.CooldownDuration,
		maxStaleAge:      cfg.MaxStaleAge,
	}
	b.actorBeatMonoNs.Store(monoNowNs())
	return b
}

func (b *Bulkhead) StartActor() {
	if b == nil || b.closed.Load() {
		return
	}
	b.actorOnce.Do(func() {
		b.actorRunning.Store(true)
		go b.actorLoop()
	})
}

func (b *Bulkhead) Name() string { return b.name }

// Beat 在真实事件循环中推进舱壁单调时钟心跳槽。
func (b *Bulkhead) Beat() {
	if b != nil {
		b.actorBeatMonoNs.Store(monoNowNs())
	}
}

// BeatAge 返回距上次推进心跳的单调时钟时长。
func (b *Bulkhead) BeatAge() time.Duration {
	if b == nil {
		return 0
	}
	age := monoNowNs() - b.actorBeatMonoNs.Load()
	if age < 0 {
		return 0
	}
	return time.Duration(age)
}

// CircuitState 返回当前熔断器状态: "closed" | "open" | "half_open"。
func (b *Bulkhead) CircuitState() string {
	return b.circuitStateAt(monoNowNs())
}

func (b *Bulkhead) circuitStateAt(nowMono int64) string {
	if b == nil {
		return "closed"
	}
	until := b.circuitOpenUntil.Load()
	if until <= 0 {
		return "closed"
	}
	if nowMono < until {
		return "open"
	}
	return "half_open"
}

// ResetCircuit 手动复位熔断器(用于自愈确认或测试)。
func (b *Bulkhead) ResetCircuit() {
	if b == nil {
		return
	}
	b.circuitOpenUntil.Store(0)
	b.consecTimeouts.Store(0)
	b.halfOpenProbe.Store(false)
}

func (b *Bulkhead) Close() {
	if b == nil {
		return
	}
	b.closed.Store(true)
	b.stopOnce.Do(func() {
		close(b.stopCh)
	})
}

func (b *Bulkhead) setLastErr(msg string) {
	b.errMu.Lock()
	b.lastErr = msg
	b.errMu.Unlock()
}

func (b *Bulkhead) getLastErr() string {
	b.errMu.RLock()
	s := b.lastErr
	b.errMu.RUnlock()
	return s
}

func (b *Bulkhead) allowSubmission(nowMono int64) (isHalfOpenProbe bool, err error) {
	if b.closed.Load() {
		return false, ErrBulkheadClosed
	}
	until := b.circuitOpenUntil.Load()
	if until <= 0 {
		return false, nil
	}
	if nowMono < until {
		b.totalRejected.Add(1)
		return false, ErrBulkheadCircuitOpen
	}
	// 已过退避窗口 → 半开状态仅放行单次探测请求, 其余并发请求立即快速失败。
	if !b.halfOpenProbe.CompareAndSwap(false, true) {
		b.totalRejected.Add(1)
		return false, ErrBulkheadCircuitOpen
	}
	return true, nil
}

// TrySubmit 非阻塞异步投递任务到舱壁队列(队列满或熔断打开时立即返回错误, 绝不阻塞调用方)。
func (b *Bulkhead) TrySubmit(fn func(ctx context.Context) error) error {
	if b == nil || fn == nil {
		return nil
	}
	isProbe, err := b.allowSubmission(monoNowNs())
	if err != nil {
		return err
	}
	b.StartActor()
	task := bulkheadTask{
		ctx:     context.Background(),
		timeout: b.defaultTimeout,
		fn:      fn,
	}
	select {
	case b.queue <- task:
		b.totalSubmitted.Add(1)
		return nil
	default:
		if isProbe {
			b.halfOpenProbe.Store(false)
		}
		b.totalRejected.Add(1)
		return ErrBulkheadQueueFull
	}
}

// Execute 在隔离舱壁内同步等待结果(受 timeout、队列容量、异常隔离罩及半开熔断器多重保护)。
func (b *Bulkhead) Execute(parentCtx context.Context, timeout time.Duration, fn func(ctx context.Context) error) error {
	if b == nil || fn == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = b.defaultTimeout
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	isProbe, err := b.allowSubmission(monoNowNs())
	if err != nil {
		return err
	}
	b.StartActor()
	doneCh := make(chan error, 1)
	task := bulkheadTask{
		ctx:     parentCtx,
		timeout: timeout,
		fn:      fn,
		doneCh:  doneCh,
	}
	select {
	case b.queue <- task:
		b.totalSubmitted.Add(1)
	default:
		if isProbe {
			b.halfOpenProbe.Store(false)
		}
		b.totalRejected.Add(1)
		return ErrBulkheadQueueFull
	}

	waitTimer := time.NewTimer(timeout + 250*time.Millisecond)
	defer waitTimer.Stop()
	select {
	case resErr := <-doneCh:
		return resErr
	case <-parentCtx.Done():
		return parentCtx.Err()
	case <-b.stopCh:
		return ErrBulkheadClosed
	case <-waitTimer.C:
		b.recordTimeoutOrTrip()
		return ErrBulkheadTimeout
	}
}

// ExecuteInline 在调用方栈内同步执行短时任务, 不调用 StartActor() 亦不派生短命子协程:
// 完整保留半开熔断准入与 recover() 隔离罩, 直接原子刷新心跳槽与成功/错误指标。
func (b *Bulkhead) ExecuteInline(fn func() error) (err error) {
	if b == nil || fn == nil {
		return nil
	}
	startMono := monoNowNs()
	if _, allowErr := b.allowSubmission(startMono); allowErr != nil {
		return allowErr
	}
	b.actorBeatMonoNs.Store(startMono)
	b.totalSubmitted.Add(1)

	defer func() {
		if p := recover(); p != nil {
			endMono := monoNowNs()
			b.actorBeatMonoNs.Store(endMono)
			b.lastExecNs.Store(endMono - startMono)
			b.totalPanics.Add(1)
			b.totalErrors.Add(1)
			b.halfOpenProbe.Store(false)
			msg := fmt.Sprintf("panic recovered in bulkhead %s: %v", b.name, p)
			b.setLastErr(msg)
			log.Printf("core_hub: %s", msg)
			err = fmt.Errorf("%w: %v", ErrBulkheadPanic, p)
		}
	}()

	err = fn()
	endMono := monoNowNs()
	b.actorBeatMonoNs.Store(endMono)
	b.lastExecNs.Store(endMono - startMono)
	b.consecTimeouts.Store(0)
	if b.circuitOpenUntil.Load() != 0 {
		b.circuitOpenUntil.Store(0)
	}
	b.halfOpenProbe.Store(false)
	b.totalCompleted.Add(1)
	if err != nil {
		b.totalErrors.Add(1)
		b.setLastErr(err.Error())
	}
	return err
}

func (b *Bulkhead) actorLoop() {
	tk := time.NewTicker(bulkheadHeartbeatInterval)
	defer tk.Stop()
	b.Beat()
	for {
		select {
		case <-b.stopCh:
			return
		case <-tk.C:
			b.Beat()
		case task := <-b.queue:
			b.Beat()
			err := b.executeTaskIsolated(task)
			b.Beat()
			if task.doneCh != nil {
				task.doneCh <- err
			}
		}
	}
}

func (b *Bulkhead) executeTaskIsolated(task bulkheadTask) error {
	startMono := monoNowNs()
	timeout := task.timeout
	if timeout <= 0 {
		timeout = b.defaultTimeout
	}
	parent := task.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	// 若此前遗留的卡死任务已占满逃逸槽位, 直接按超时快速拒绝, 杜绝无界 goroutine 泄漏。
	select {
	case b.runawaySem <- struct{}{}:
	default:
		b.recordTimeoutOrTrip()
		return ErrBulkheadTimeout
	}

	type taskOutcome struct {
		err      error
		panicked bool
	}
	resCh := make(chan taskOutcome, 1)
	go func() {
		defer func() { <-b.runawaySem }()
		defer func() {
			if p := recover(); p != nil {
				b.totalPanics.Add(1)
				b.totalErrors.Add(1)
				msg := fmt.Sprintf("panic recovered in bulkhead %s: %v", b.name, p)
				b.setLastErr(msg)
				log.Printf("core_hub: %s", msg)
				resCh <- taskOutcome{
					err:      fmt.Errorf("%w: %v", ErrBulkheadPanic, p),
					panicked: true,
				}
			}
		}()
		err := task.fn(ctx)
		resCh <- taskOutcome{err: err}
	}()

	select {
	case out := <-resCh:
		b.lastExecNs.Store(monoNowNs() - startMono)
		if out.panicked {
			b.halfOpenProbe.Store(false)
			return out.err
		}
		if errors.Is(out.err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			b.recordTimeoutOrTrip()
			return fmt.Errorf("%w: %v", ErrBulkheadTimeout, out.err)
		}
		// 正常返回(含普通业务错误): 重置连续超时计数并关闭半开熔断器。
		b.consecTimeouts.Store(0)
		if b.circuitOpenUntil.Load() != 0 {
			b.circuitOpenUntil.Store(0)
		}
		b.halfOpenProbe.Store(false)
		b.totalCompleted.Add(1)
		if out.err != nil {
			b.totalErrors.Add(1)
			b.setLastErr(out.err.Error())
		}
		return out.err

	case <-ctx.Done():
		b.lastExecNs.Store(monoNowNs() - startMono)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			b.recordTimeoutOrTrip()
			return ErrBulkheadTimeout
		}
		b.halfOpenProbe.Store(false)
		return ctx.Err()
	}
}

func (b *Bulkhead) recordTimeoutOrTrip() {
	b.totalTimeouts.Add(1)
	ct := b.consecTimeouts.Add(1)
	b.halfOpenProbe.Store(false)
	nowMono := monoNowNs()
	if ct >= b.tripThreshold || b.circuitOpenUntil.Load() > 0 {
		until := nowMono + int64(b.cooldownDuration)
		b.circuitOpenUntil.Store(until)
		b.totalCircuitTrips.Add(1)
		msg := fmt.Sprintf("circuit tripped after %d consecutive timeouts (cooldown %v)", ct, b.cooldownDuration)
		b.setLastErr(msg)
		log.Printf("core_hub: bulkhead %q %s", b.name, msg)
	} else {
		b.setLastErr(fmt.Sprintf("timeout (%d/%d)", ct, b.tripThreshold))
	}
}

// BulkheadHealth 单个舱壁的可序列化只读快照(所有时长统一为毫秒/微秒整数, 兼容 json/v2)。
type BulkheadHealth struct {
	Name              string `json:"name"`
	Healthy           bool   `json:"healthy"`
	CircuitState      string `json:"circuit_state"`
	BeatAgeMs         int64  `json:"beat_age_ms"`
	BeatMonoNs        int64  `json:"beat_mono_ns"`
	QueueDepth        int    `json:"queue_depth"`
	QueueCap          int    `json:"queue_cap"`
	ConsecTimeouts    int32  `json:"consec_timeouts"`
	CircuitCooldownMs int64  `json:"circuit_cooldown_ms,omitempty"`
	Submitted         uint64 `json:"submitted"`
	Completed         uint64 `json:"completed"`
	Timeouts          uint64 `json:"timeouts"`
	Panics            uint64 `json:"panics"`
	Rejected          uint64 `json:"rejected"`
	CircuitTrips      uint64 `json:"circuit_trips"`
	LastExecUs        int64  `json:"last_exec_us"`
	LastError         string `json:"last_error,omitempty"`
}

func (b *Bulkhead) Health() BulkheadHealth {
	if b == nil {
		return BulkheadHealth{Healthy: false, CircuitState: "closed"}
	}
	nowMono := monoNowNs()
	// 尚未显式起常驻 Actor 协程时(如纯只读无任务空闲期), 心跳随观测刷新;
	// 一旦 Actor 启动, 仅由 actorLoop 真实循环推进, 若循环卡死则 BeatAgeMs 自然老化告警!
	if !b.actorRunning.Load() && !b.closed.Load() {
		b.actorBeatMonoNs.Store(nowMono)
	}
	beatMono := b.actorBeatMonoNs.Load()
	ageNs := nowMono - beatMono
	if ageNs < 0 {
		ageNs = 0
	}
	cState := b.circuitStateAt(nowMono)
	var remCooldownMs int64
	if until := b.circuitOpenUntil.Load(); until > nowMono {
		remCooldownMs = (until - nowMono) / int64(time.Millisecond)
	}
	healthy := !b.closed.Load() && cState != "open" && ageNs <= int64(b.maxStaleAge)
	return BulkheadHealth{
		Name:              b.name,
		Healthy:           healthy,
		CircuitState:      cState,
		BeatAgeMs:         ageNs / int64(time.Millisecond),
		BeatMonoNs:        beatMono,
		QueueDepth:        len(b.queue),
		QueueCap:          cap(b.queue),
		ConsecTimeouts:    b.consecTimeouts.Load(),
		CircuitCooldownMs: remCooldownMs,
		Submitted:         b.totalSubmitted.Load(),
		Completed:         b.totalCompleted.Load(),
		Timeouts:          b.totalTimeouts.Load(),
		Panics:            b.totalPanics.Load(),
		Rejected:          b.totalRejected.Load(),
		CircuitTrips:      b.totalCircuitTrips.Load(),
		LastExecUs:        b.lastExecNs.Load() / int64(time.Microsecond),
		LastError:         b.getLastErr(),
	}
}

// ─── WorldSnapshot 无锁 RCU 原子快照与 CoreHub 中枢 ──────────────────

type VectorLiveSummary struct {
	HotspotActive bool           `json:"hotspot_active"`
	Iface         string         `json:"iface"`
	HotspotIface  string         `json:"hotspot_iface"`
	HotspotIP     string         `json:"hotspot_ip"`
	IfaceMethod   string         `json:"iface_method,omitempty"`
	Online        int            `json:"online"`
	Total         int            `json:"total"`
	RxBps         int64          `json:"rx_bps"`
	TxBps         int64          `json:"tx_bps"`
	Sim           bool           `json:"sim,omitempty"`
	Signal        any            `json:"signal,omitempty"`
	Autorate      any            `json:"autorate,omitempty"`
	ActivityLevel string         `json:"activity_level,omitempty"`
	Devices       []VectorDevice `json:"devices"`
}

type VectorDevice struct {
	MAC          string  `json:"mac"`
	IP           string  `json:"ip,omitempty"`
	Hostname     string  `json:"hostname,omitempty"`
	Online       bool    `json:"online"`
	Status       string  `json:"status,omitempty"`
	RxBps        int64   `json:"rx_bps"`
	TxBps        int64   `json:"tx_bps"`
	LimitEnabled bool    `json:"limit_enabled,omitempty"`
	DownMbps     float64 `json:"down_mbps,omitempty"`
	UpMbps       float64 `json:"up_mbps,omitempty"`
}

// WorldSnapshot 全栈不可变只读态势快照。一旦发布至 atomic.Pointer 永不原地修改。
type WorldSnapshot struct {
	OK              bool                      `json:"ok"`
	Schema          int                       `json:"schema"`
	Seq             uint64                    `json:"seq"`
	GeneratedAt     int64                     `json:"generated_at"`
	GeneratedMonoNs int64                     `json:"generated_mono_ns"`
	Version         string                    `json:"version"`
	VersionCode     string                    `json:"version_code"`
	CoreUptimeSec   int64                     `json:"core_uptime_sec"`
	Healthy         bool                      `json:"healthy"`
	Bulkheads       map[string]BulkheadHealth `json:"bulkheads"`
	Live            VectorLiveSummary         `json:"live"`
	Extensions      map[string]any            `json:"extensions"`
	Modules         map[string]any            `json:"modules"`

	// rawJSON 后台刷快照时预先用 JSONv2 编码好的不可变字节切片, 使 HTTP 读取彻底零序列化。
	rawJSON []byte
}

// CoreHub 四舱壁防连坐核心中枢。
// 铁律: 所有 64 位原子字段严格置于结构体开头(offset 0, 8, 16), 通过 32 位 ARMv7 go vet。
type CoreHub struct {
	seq              atomic.Uint64 // offset 0
	lastRefreshMono  atomic.Int64  // offset 8
	vectorSyncHits   atomic.Uint64 // offset 16
	shmSeqlockHits   atomic.Uint64 // offset 24
	shmFallbackCount atomic.Uint64 // offset 32

	world       atomic.Pointer[WorldSnapshot]
	loopActive  atomic.Bool
	asyncFlight atomic.Bool
	closed      atomic.Bool

	DataplaneBulkhead     *Bulkhead
	DpiShmBulkhead        *Bulkhead
	AndroidBridgeBulkhead *Bulkhead
	StorageBulkhead       *Bulkhead

	srv      *server
	stopCh   chan struct{}
	stopOnce sync.Once

	shmMu           sync.Mutex
	shmReader       *shm.Reader
	shmInfo         os.FileInfo
	shmRunDir       string
	shmLastStatMono int64
	shmSnapBuf      shm.Snapshot
}

var (
	serverHubMap     sync.Map // map[*server]*CoreHub
	defaultGlobalHub atomic.Pointer[CoreHub]
)

// NewCoreHub 初始化四舱壁中枢并立即构建首帧不可变快照。
func NewCoreHub(s *server) *CoreHub {
	h := &CoreHub{
		DataplaneBulkhead: NewBulkhead(BulkheadConfig{
			Name:             "dataplane",
			QueueSize:        64,
			DefaultTimeout:   3 * time.Second,
			TripThreshold:    3,
			CooldownDuration: 15 * time.Second,
		}),
		DpiShmBulkhead: NewBulkhead(BulkheadConfig{
			Name:             "dpi_shm",
			QueueSize:        32,
			DefaultTimeout:   1500 * time.Millisecond,
			TripThreshold:    3,
			CooldownDuration: 15 * time.Second,
		}),
		AndroidBridgeBulkhead: NewBulkhead(BulkheadConfig{
			Name:             "android_bridge",
			QueueSize:        16,
			DefaultTimeout:   defaultAndroidCmdTimeout, // 2s 硬超时
			TripThreshold:    2,                        // 连续 2 次超时立即熔断
			CooldownDuration: 45 * time.Second,         // 自动退避 45s
		}),
		StorageBulkhead: NewBulkhead(BulkheadConfig{
			Name:             "storage",
			QueueSize:        32,
			DefaultTimeout:   3 * time.Second,
			TripThreshold:    3,
			CooldownDuration: 15 * time.Second,
		}),
		srv:    s,
		stopCh: make(chan struct{}),
	}
	h.RefreshSnapshotNow()
	defaultGlobalHub.CompareAndSwap(nil, h)
	return h
}

// CoreHub 获取或惰性绑定当前 *server 的四舱壁中枢实例(并发安全, 快路径 sync.Map Load)。
func (s *server) CoreHub() *CoreHub {
	if s == nil {
		if gh := defaultGlobalHub.Load(); gh != nil {
			return gh
		}
		nh := NewCoreHub(nil)
		if defaultGlobalHub.CompareAndSwap(nil, nh) {
			return nh
		}
		nh.Close()
		return defaultGlobalHub.Load()
	}
	if v, ok := serverHubMap.Load(s); ok {
		return v.(*CoreHub)
	}
	nh := NewCoreHub(s)
	actual, loaded := serverHubMap.LoadOrStore(s, nh)
	if loaded {
		nh.Close()
		return actual.(*CoreHub)
	}
	return nh
}

// Start 启动四舱壁心跳循环与后台每 1.5s 推进一次的无锁快照刷新协程(幂等)。
func (h *CoreHub) Start(extStop <-chan struct{}) {
	if h == nil || h.closed.Load() || !h.loopActive.CompareAndSwap(false, true) {
		return
	}
	h.DataplaneBulkhead.StartActor()
	h.DpiShmBulkhead.StartActor()
	h.AndroidBridgeBulkhead.StartActor()
	h.StorageBulkhead.StartActor()

	go func() {
		tk := time.NewTicker(worldSnapshotInterval)
		defer tk.Stop()
		for {
			select {
			case <-h.stopCh:
				return
			case <-extStop:
				h.Close()
				return
			case <-tk.C:
				h.RefreshSnapshotNow()
			}
		}
	}()
}

// CoreHubLoop 供 main.go 以 `go srv.CoreHubLoop(stopCh)` 方式挂载。
func (s *server) CoreHubLoop(stop <-chan struct{}) {
	if s == nil {
		return
	}
	h := s.CoreHub()
	h.Start(stop)
	select {
	case <-stop:
		h.Close()
	case <-h.stopCh:
	}
}

// Close 停止后台刷新协程与全部四个隔离舱壁。
func (h *CoreHub) Close() {
	if h == nil {
		return
	}
	h.closed.Store(true)
	h.stopOnce.Do(func() {
		close(h.stopCh)
	})
	h.DataplaneBulkhead.Close()
	h.DpiShmBulkhead.Close()
	h.AndroidBridgeBulkhead.Close()
	h.StorageBulkhead.Close()
	h.closeShmReader()
	defaultGlobalHub.CompareAndSwap(h, nil)
	if h.srv != nil {
		serverHubMap.Delete(h.srv)
		v6Registry.Delete(h.srv)
	}
}

// Snapshot 无锁 RCU 原子读取当前全栈态势快照(单条指针加载指令, < 50ns, 0 互斥锁, 0 分配)。
func (h *CoreHub) Snapshot() *WorldSnapshot {
	if h == nil {
		return nil
	}
	return h.world.Load()
}

// VectorSyncHits 返回 /api/vector_sync 累计无锁响应次数。
func (h *CoreHub) VectorSyncHits() uint64 {
	if h == nil {
		return 0
	}
	return h.vectorSyncHits.Load()
}

// triggerAsyncRefreshIfStale 当未显式开启常驻 Start 循环且快照超过 1.5s 时,
// 触发单飞短命后台刷新(用完即退, 既不阻塞当前 HTTP 请求也不在单测里驻留永久协程)。
func (h *CoreHub) triggerAsyncRefreshIfStale() {
	if h == nil || h.loopActive.Load() || h.closed.Load() {
		return
	}
	age := monoNowNs() - h.lastRefreshMono.Load()
	if age < int64(worldSnapshotInterval) {
		return
	}
	if !h.asyncFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer h.asyncFlight.Store(false)
		h.RefreshSnapshotNow()
	}()
}

// RefreshSnapshotNow 在后台组装新一代不可变 WorldSnapshot 并原子切换指针。
// 全程不拉起任何外部子进程(信号走 signalCtl 非阻塞内存快照, 配置走 mtime 缓存)。
func (h *CoreHub) RefreshSnapshotNow() *WorldSnapshot {
	if h == nil {
		return nil
	}
	now := time.Now()
	nowMono := monoNowNs()
	seq := h.seq.Add(1)

	// v6.1.0-beta.1: 通过 DpiShmBulkhead 无锁读取 16KB shm_vector.bin(异常/缺席自动无损回退 jsonCache)
	shmRes := h.pollDpiShmVector(now)

	bhMap := map[string]BulkheadHealth{
		"dataplane":      h.DataplaneBulkhead.Health(),
		"dpi_shm":        h.DpiShmBulkhead.Health(),
		"android_bridge": h.AndroidBridgeBulkhead.Health(),
		"storage":        h.StorageBulkhead.Health(),
	}
	allHealthy := true
	for _, bh := range bhMap {
		if !bh.Healthy {
			allHealthy = false
			break
		}
	}

	live := buildVectorLiveSummaryInternal(h.srv, now, shmRes, h.loopActive.Load())
	exts := collectVectorSyncProviders(h.srv)
	if exts == nil {
		exts = make(map[string]any, 2)
	}
	exts["dpi_shm_vector"] = shmRes.toExtensionMap()

	snap := &WorldSnapshot{
		OK:              true,
		Schema:          1,
		Seq:             seq,
		GeneratedAt:     now.Unix(),
		GeneratedMonoNs: nowMono,
		Version:         version,
		VersionCode:     versionCode,
		CoreUptimeSec:   coreUptimeSeconds(),
		Healthy:         allHealthy,
		Bulkheads:       bhMap,
		Live:            live,
		Extensions:      exts,
		Modules:         exts,
	}
	if encoded, err := MarshalJSONv2(snap); err == nil {
		snap.rawJSON = encoded
	}
	h.lastRefreshMono.Store(nowMono)
	h.world.Store(snap)
	return snap
}

const (
	dpiShmMaxStaleAge         = 15 * time.Second
	dpiShmMaxFutureSkew       = 5 * time.Second
	dpiShmTaskTimeout         = 250 * time.Millisecond
	dpiShmFastStatRefreshIntv = 5 * time.Second
	dpiShmFakeClockTolerance  = 2 * time.Second
)

type dpiShmDeviceLive struct {
	MAC         string `json:"mac"`
	IPv4        string `json:"ipv4,omitempty"`
	IPv6        string `json:"ipv6,omitempty"`
	RxBytes     uint64 `json:"rx_bytes"`
	TxBytes     uint64 `json:"tx_bytes"`
	ActiveFlows uint32 `json:"active_flows"`
	Flags       uint32 `json:"flags"`
}

type dpiShmReadResult struct {
	Valid          bool
	Attached       bool
	Mmapped        bool
	Stale          bool
	Seq            uint64
	UpdatedMonoNs  int64
	UpdatedUnixNs  int64
	AgeMs          int64
	DeviceCount    uint32
	ActiveFlows    uint32
	TotalLeaks     uint64
	HeaderFlags    uint32
	Source         string
	FallbackReason string
	ByMAC          map[string]dpiShmDeviceLive
}

func (r dpiShmReadResult) toExtensionMap() map[string]any {
	src := r.Source
	if src == "" {
		src = "json_fallback"
	}
	out := map[string]any{
		"attached":        r.Attached,
		"mmapped":         r.Mmapped,
		"seq":             r.Seq,
		"device_count":    r.DeviceCount,
		"active_flows":    r.ActiveFlows,
		"total_leaks":     r.TotalLeaks,
		"flags":           r.HeaderFlags,
		"updated_unix_ns": r.UpdatedUnixNs,
		"age_ms":          r.AgeMs,
		"stale":           r.Stale,
		"source":          src,
	}
	if r.FallbackReason != "" {
		out["fallback_reason"] = r.FallbackReason
	}
	if r.Valid && len(r.ByMAC) > 0 {
		devs := make([]dpiShmDeviceLive, 0, len(r.ByMAC))
		for _, d := range r.ByMAC {
			devs = append(devs, d)
		}
		sort.Slice(devs, func(i, j int) bool {
			if devs[i].ActiveFlows != devs[j].ActiveFlows {
				return devs[i].ActiveFlows > devs[j].ActiveFlows
			}
			return devs[i].MAC < devs[j].MAC
		})
		out["devices"] = devs
	}
	return out
}

func (h *CoreHub) closeShmReader() {
	if h.shmMu.TryLock() {
		h.closeShmReaderLocked()
		h.shmMu.Unlock()
	}
}

func (h *CoreHub) closeShmReaderLocked() {
	if h.shmReader != nil {
		_ = h.shmReader.Close()
		h.shmReader = nil
	}
	h.shmInfo = nil
	h.shmRunDir = ""
	h.shmLastStatMono = 0
}

func normalizeShmMAC(raw string) string {
	m := strings.ToLower(strings.TrimSpace(raw))
	if m == "" || m == "00:00:00:00:00:00" || m == "ff:ff:ff:ff:ff:ff" {
		return ""
	}
	return m
}

func cleanShmIP(raw string) string {
	ip := strings.TrimSpace(raw)
	if ip == "" || ip == "0.0.0.0" || ip == "::" || ip == "<nil>" {
		return ""
	}
	return ip
}

func (h *CoreHub) pollDpiShmVector(now time.Time) dpiShmReadResult {
	fallback := dpiShmReadResult{
		Source:         "json_fallback",
		FallbackReason: "unconfigured",
	}
	if h == nil || h.closed.Load() || h.srv == nil || h.srv.hncDir == "" {
		if h != nil {
			h.shmFallbackCount.Add(1)
		}
		return fallback
	}
	if h.DpiShmBulkhead == nil {
		h.shmFallbackCount.Add(1)
		fallback.FallbackReason = "bulkhead_absent"
		return fallback
	}

	runDir := filepath.Join(h.srv.hncDir, "run")
	shmPath := shm.FilePath(runDir)

	var (
		out   dpiShmReadResult
		bhErr error
	)
	if !h.loopActive.Load() {
		// 未调用 Start() 的构造期或单测路径: 绝不调用 Execute (避免隐式 StartActor 驻留常驻协程触发 goroutineleak)
		bhErr = h.DpiShmBulkhead.ExecuteInline(func() error {
			var err error
			out, _, err = h.readAndDecodeShmLocked(runDir, shmPath, now, false)
			return err
		})
	} else {
		nowMono := monoNowNs()
		canFastMmap := false
		if h.shmMu.TryLock() {
			if h.shmReader != nil && h.shmReader.IsMmapped() && h.shmRunDir == runDir &&
				h.shmLastStatMono > 0 && nowMono >= h.shmLastStatMono &&
				(nowMono-h.shmLastStatMono) < int64(dpiShmFastStatRefreshIntv) {
				canFastMmap = true
			}
			h.shmMu.Unlock()
		}

		needSlowPath := !canFastMmap
		if canFastMmap {
			var retrySlow bool
			bhErr = h.DpiShmBulkhead.ExecuteInline(func() error {
				var err error
				out, retrySlow, err = h.readAndDecodeShmLocked(runDir, shmPath, now, true)
				return err
			})
			if bhErr == nil && retrySlow {
				needSlowPath = true
			}
		}
		if needSlowPath {
			resCh := make(chan dpiShmReadResult, 1)
			bhErr = h.DpiShmBulkhead.Execute(context.Background(), dpiShmTaskTimeout, func(_ context.Context) error {
				res, _, err := h.readAndDecodeShmLocked(runDir, shmPath, now, false)
				resCh <- res
				return err
			})
			if bhErr == nil {
				out = <-resCh
			} else {
				select {
				case prev := <-resCh:
					out = prev
				default:
					out = dpiShmReadResult{
						Source:         "json_fallback",
						FallbackReason: "bulkhead_error",
					}
				}
			}
		}
	}

	if bhErr != nil {
		h.shmFallbackCount.Add(1)
		if out.Source == "" {
			out.Source = "json_fallback"
		}
		if out.FallbackReason == "" {
			out.FallbackReason = "bulkhead_error"
		}
		out.Valid = false
		return out
	}

	if out.Valid {
		h.shmSeqlockHits.Add(1)
	} else {
		h.shmFallbackCount.Add(1)
	}
	return out
}

func (h *CoreHub) readAndDecodeShmLocked(runDir, shmPath string, now time.Time, skipStat bool) (dpiShmReadResult, bool, error) {
	if skipStat {
		if !h.shmMu.TryLock() {
			return dpiShmReadResult{}, true, nil
		}
	} else {
		h.shmMu.Lock()
	}
	defer func() {
		if h.closed.Load() {
			h.closeShmReaderLocked()
		}
		h.shmMu.Unlock()
		if h.closed.Load() && h.shmMu.TryLock() {
			h.closeShmReaderLocked()
			h.shmMu.Unlock()
		}
	}()
	if h.closed.Load() {
		h.closeShmReaderLocked()
		return dpiShmReadResult{
			Source:         "json_fallback",
			FallbackReason: "closed",
		}, false, ErrBulkheadClosed
	}

	if !skipStat {
		curInfo, statErr := os.Stat(shmPath)
		if statErr != nil {
			h.closeShmReaderLocked()
			if errors.Is(statErr, os.ErrNotExist) {
				return dpiShmReadResult{
					Source:         "json_fallback",
					FallbackReason: "standby_absent",
				}, false, nil
			}
			return dpiShmReadResult{
				Source:         "json_fallback",
				FallbackReason: "stat_error",
			}, false, statErr
		}

		if h.shmReader != nil && (h.shmRunDir != runDir || h.shmInfo == nil || !os.SameFile(h.shmInfo, curInfo) || curInfo.Size() < shm.FileSize) {
			h.closeShmReaderLocked()
		}

		if h.shmReader == nil {
			r, openErr := shm.OpenReader(runDir)
			if openErr != nil {
				if errors.Is(openErr, os.ErrNotExist) || errors.Is(openErr, shm.ErrUninitialized) {
					return dpiShmReadResult{
						Source:         "json_fallback",
						FallbackReason: "standby_uninitialized",
					}, false, nil
				}
				return dpiShmReadResult{
					Source:         "json_fallback",
					FallbackReason: "open_corrupt",
				}, false, openErr
			}
			if freshInfo, fErr := os.Stat(shmPath); fErr == nil {
				curInfo = freshInfo
			}
			h.shmReader = r
			h.shmInfo = curInfo
			h.shmRunDir = runDir
		}
		h.shmLastStatMono = monoNowNs()
	} else if h.shmReader == nil {
		return dpiShmReadResult{}, true, nil
	}

	attached := true
	mmapped := h.shmReader.IsMmapped()
	readErr := h.shmReader.ReadInto(&h.shmSnapBuf)
	if readErr != nil {
		if skipStat {
			h.shmLastStatMono = 0
			return dpiShmReadResult{}, true, nil
		}
		switch {
		case errors.Is(readErr, shm.ErrUninitialized):
			return dpiShmReadResult{
				Attached:       attached,
				Mmapped:        mmapped,
				Source:         "json_fallback",
				FallbackReason: "uninitialized",
			}, false, nil
		case errors.Is(readErr, shm.ErrClosed):
			h.closeShmReaderLocked()
			return dpiShmReadResult{
				Source:         "json_fallback",
				FallbackReason: "reader_closed",
			}, false, nil
		default:
			h.closeShmReaderLocked()
			return dpiShmReadResult{
				Source:         "json_fallback",
				FallbackReason: "read_corrupt",
			}, false, readErr
		}
	}

	hdr := h.shmSnapBuf.Header
	if hdr.Seq == 0 || (hdr.UpdatedMonoNs <= 0 && hdr.UpdatedUnixNs <= 0) {
		return dpiShmReadResult{
			Attached:       attached,
			Mmapped:        mmapped,
			Seq:            hdr.Seq,
			UpdatedMonoNs:  hdr.UpdatedMonoNs,
			UpdatedUnixNs:  hdr.UpdatedUnixNs,
			DeviceCount:    hdr.DeviceCount,
			ActiveFlows:    hdr.ActiveFlows,
			TotalLeaks:     hdr.TotalLeaks,
			HeaderFlags:    hdr.Flags,
			Source:         "json_fallback",
			FallbackReason: "uninitialized",
		}, false, nil
	}

	wallNow := time.Now()
	checkNow := now
	if checkNow.IsZero() {
		checkNow = wallNow
	}
	wallSkew := checkNow.Sub(wallNow)
	if wallSkew < 0 {
		wallSkew = -wallSkew
	}
	var age time.Duration
	if hdr.UpdatedMonoNs > 0 && wallSkew <= dpiShmFakeClockTolerance {
		age = time.Duration(shm.MonotonicNs() - hdr.UpdatedMonoNs)
	} else {
		if hdr.UpdatedUnixNs <= 0 {
			return dpiShmReadResult{
				Attached:       attached,
				Mmapped:        mmapped,
				Seq:            hdr.Seq,
				UpdatedMonoNs:  hdr.UpdatedMonoNs,
				UpdatedUnixNs:  hdr.UpdatedUnixNs,
				DeviceCount:    hdr.DeviceCount,
				ActiveFlows:    hdr.ActiveFlows,
				TotalLeaks:     hdr.TotalLeaks,
				HeaderFlags:    hdr.Flags,
				Source:         "json_fallback",
				FallbackReason: "uninitialized",
			}, false, nil
		}
		age = checkNow.Sub(time.Unix(0, hdr.UpdatedUnixNs))
	}
	ageMs := age.Milliseconds()
	if ageMs < 0 {
		ageMs = 0
	}
	if age > dpiShmMaxStaleAge || age < -dpiShmMaxFutureSkew {
		if skipStat {
			h.shmLastStatMono = 0
			return dpiShmReadResult{}, true, nil
		}
		return dpiShmReadResult{
			Attached:       attached,
			Mmapped:        mmapped,
			Stale:          true,
			Seq:            hdr.Seq,
			UpdatedMonoNs:  hdr.UpdatedMonoNs,
			UpdatedUnixNs:  hdr.UpdatedUnixNs,
			AgeMs:          ageMs,
			DeviceCount:    hdr.DeviceCount,
			ActiveFlows:    hdr.ActiveFlows,
			TotalLeaks:     hdr.TotalLeaks,
			HeaderFlags:    hdr.Flags,
			Source:         "json_fallback",
			FallbackReason: "stale_snapshot",
		}, false, nil
	}

	limit := int(hdr.DeviceCount)
	if limit > len(h.shmSnapBuf.Devices) {
		limit = len(h.shmSnapBuf.Devices)
	}
	var byMAC map[string]dpiShmDeviceLive
	if limit > 0 {
		byMAC = make(map[string]dpiShmDeviceLive, limit)
		for i := 0; i < limit; i++ {
			slot := &h.shmSnapBuf.Devices[i]
			mac := normalizeShmMAC(slot.MACString())
			if mac == "" {
				continue
			}
			byMAC[mac] = dpiShmDeviceLive{
				MAC:         mac,
				IPv4:        cleanShmIP(slot.IPv4String()),
				IPv6:        cleanShmIP(slot.IPv6String()),
				RxBytes:     slot.RxBytes,
				TxBytes:     slot.TxBytes,
				ActiveFlows: slot.ActiveFlows,
				Flags:       slot.Flags,
			}
		}
	}

	return dpiShmReadResult{
		Valid:         true,
		Attached:      attached,
		Mmapped:       mmapped,
		Seq:           hdr.Seq,
		UpdatedMonoNs: hdr.UpdatedMonoNs,
		UpdatedUnixNs: hdr.UpdatedUnixNs,
		AgeMs:         ageMs,
		DeviceCount:   hdr.DeviceCount,
		ActiveFlows:   hdr.ActiveFlows,
		TotalLeaks:    hdr.TotalLeaks,
		HeaderFlags:   hdr.Flags,
		Source:        "shm_seqlock",
		ByMAC:         byMAC,
	}, false, nil
}

func buildVectorLiveSummary(s *server, now time.Time) VectorLiveSummary {
	return buildVectorLiveSummaryInternal(s, now, dpiShmReadResult{}, false)
}

func buildVectorLiveSummaryWithShm(s *server, now time.Time, shmRes dpiShmReadResult) VectorLiveSummary {
	return buildVectorLiveSummaryInternal(s, now, shmRes, false)
}

func buildVectorLiveSummaryInternal(s *server, now time.Time, shmRes dpiShmReadResult, allowAsyncSignal bool) VectorLiveSummary {
	act := activityNow()
	sum := VectorLiveSummary{
		ActivityLevel: act.Level,
		Devices:       []VectorDevice{},
	}
	if s == nil {
		return sum
	}

	iface := s.currentHotspotIface()
	ip := ifaceIPv4(iface)
	simLive := s.simActive()

	// 复制内存速率表(极短锁, 纯内存 map 拷贝, 零 I/O)
	s.rateMu.Lock()
	ratesSnap := make(map[string]rateOut, len(s.rates))
	for k, v := range s.rates {
		ratesSnap[k] = v
	}
	s.rateMu.Unlock()

	var devMap map[string]any
	if s.jsonCache != nil {
		if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "data", "devices.json")); err == nil {
			devMap, _ = raw.(map[string]any)
		}
	}
	if shmRes.Valid && len(shmRes.ByMAC) > 0 {
		copied := make(map[string]any, len(devMap)+len(shmRes.ByMAC))
		for k, v := range devMap {
			if inner, ok := v.(map[string]any); ok {
				cp := make(map[string]any, len(inner)+2)
				for ik, iv := range inner {
					cp[ik] = iv
				}
				copied[k] = cp
			} else {
				copied[k] = v
			}
		}
		nowSecF := float64(now.Unix())
		for mac, obs := range shmRes.ByMAC {
			bestIP := obs.IPv4
			if bestIP == "" {
				bestIP = obs.IPv6
			}
			matchedKey := ""
			for k := range copied {
				if strings.EqualFold(strings.TrimSpace(k), mac) {
					matchedKey = k
					break
				}
			}
			liveSlot := (obs.Flags&shm.FlagOnline) != 0 || obs.ActiveFlows > 0
			if matchedKey != "" {
				if dm, ok := copied[matchedKey].(map[string]any); ok {
					if asString(dm["ip"]) == "" && bestIP != "" {
						dm["ip"] = bestIP
					}
					if liveSlot {
						dm["last_seen"] = nowSecF
					}
				}
			} else if liveSlot {
				copied[mac] = map[string]any{
					"mac":       mac,
					"ip":        bestIP,
					"last_seen": nowSecF,
				}
			}
		}
		devMap = copied
	}
	var ruleDevs map[string]any
	var blSet map[string]bool
	if s.jsonCache != nil {
		if raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "data", "rules.json")); err == nil {
			if rm, ok := raw.(map[string]any); ok {
				ruleDevs, _ = rm["devices"].(map[string]any)
				if bl, ok := rm["blacklist"].([]any); ok && len(bl) > 0 {
					blSet = make(map[string]bool, len(bl))
					for _, item := range bl {
						if ms, ok := item.(string); ok {
							blSet[strings.ToLower(strings.TrimSpace(ms))] = true
						}
					}
				}
			}
		}
	}

	nowUnix := now.Unix()
	macs := make([]string, 0, len(devMap))
	for mac := range devMap {
		macs = append(macs, mac)
	}
	sort.Strings(macs)

	devices := make([]VectorDevice, 0, len(macs))
	online := 0
	var totalRx, totalTx int64

	for _, mac := range macs {
		dm, _ := devMap[mac].(map[string]any)
		if dm == nil {
			continue
		}
		macKey := strings.ToLower(strings.TrimSpace(mac))
		devIP := asString(dm["ip"])
		lastSeen, _ := toInt64(dm["last_seen"])
		isOnline := devIP != "" && (lastSeen == 0 || nowUnix-lastSeen <= activityOnlineWindow)
		if isOnline {
			online++
		}
		rt := ratesSnap[macKey]
		if rt.rxBps == 0 && rt.txBps == 0 {
			rt = ratesSnap[mac]
		}
		totalRx += rt.rxBps
		totalTx += rt.txBps

		status := asString(dm["status"])
		if blSet[macKey] {
			status = "blocked"
		} else if status == "" {
			status = "allowed"
		}
		vd := VectorDevice{
			MAC:      macKey,
			IP:       devIP,
			Hostname: asString(dm["hostname"]),
			Online:   isOnline,
			Status:   status,
			RxBps:    rt.rxBps,
			TxBps:    rt.txBps,
		}
		if ruleDevs != nil {
			rRaw, ok := ruleDevs[mac]
			if !ok {
				rRaw = ruleDevs[macKey]
			}
			if rm, ok := rRaw.(map[string]any); ok {
				if en, _ := rm["limit_enabled"].(bool); en {
					vd.LimitEnabled = true
					vd.DownMbps = numOf(rm["down_mbps"])
					vd.UpMbps = numOf(rm["up_mbps"])
				}
			}
		}
		devices = append(devices, vd)
	}

	active := hotspotActiveFromState(s.hncDir, iface, ip, online)
	if simLive {
		active = true
	}
	if det := readIfaceDetect(s.hncDir); det.Method != "" {
		sum.IfaceMethod = det.Method
	}
	if s.signalCtl != nil {
		if allowAsyncSignal {
			sum.Signal = s.signalCtl.Get(s)
		} else if simLive {
			sum.Signal = simSignalSnapshot(s)
		} else {
			s.signalCtl.mu.RLock()
			sig := s.signalCtl.last
			s.signalCtl.mu.RUnlock()
			enrichSignalDiagnosis(&sig, s)
			sum.Signal = sig
		}
	}
	if s.autorate != nil {
		ar := s.autorate.Snapshot()
		if ar.Enabled {
			sum.Autorate = ar
		}
	}

	sum.HotspotActive = active
	sum.Iface = iface
	sum.HotspotIface = iface
	sum.HotspotIP = ip
	sum.Online = online
	sum.Total = len(devices)
	sum.RxBps = totalRx
	sum.TxBps = totalTx
	sum.Sim = simLive
	sum.Devices = devices
	return sum
}

// ─── HTTP 端点与路由注册辅助 ─────────────────────────────────────────

// apiVectorSync 处理 GET /api/vector_sync:
// 单次无锁 atomic.Pointer.Load() 获取预构建不可变快照并直写响应, 零锁竞争、零子进程、零磁盘读取。
func (s *server) apiVectorSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteJSONv2(w, http.StatusMethodNotAllowed, map[string]any{
			"ok":    false,
			"error": "method not allowed",
		})
		return
	}
	hub := s.CoreHub()
	snap := hub.Snapshot()
	hub.vectorSyncHits.Add(1)
	hub.triggerAsyncRefreshIfStale()
	if snap == nil {
		snap = hub.RefreshSnapshotNow()
	}
	if len(snap.rawJSON) > 0 {
		WritePrebuiltJSONv2(w, http.StatusOK, snap.rawJSON)
		return
	}
	WriteJSONv2(w, http.StatusOK, snap)
}

// RegisterCoreHubRoutes 供总装在 server.go handler() 中一键挂载 v6 核心聚合与排障端点。
func RegisterCoreHubRoutes(mux *http.ServeMux, s *server) {
	if mux == nil || s == nil {
		return
	}
	mux.HandleFunc("/api/vector_sync", s.apiVectorSync)
	mux.HandleFunc("/api/v6/diag_dump", s.apiCoreDiagDump)
}

// RegisterCoreHubRoutes 方法包装, 兼容 s.RegisterCoreHubRoutes(mux) 与 s.registerCoreHubRoutes(mux) 两种总装调用签名。
func (s *server) RegisterCoreHubRoutes(mux *http.ServeMux) {
	RegisterCoreHubRoutes(mux, s)
}

func (s *server) registerCoreHubRoutes(mux *http.ServeMux) {
	RegisterCoreHubRoutes(mux, s)
}
