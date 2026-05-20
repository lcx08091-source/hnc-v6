// ratelimit.go — Patch 2.b per-IP rate limiter (v4_0_design_v2.1 §5)
//
// 三类限流分开桶(避免互相影响):
//   A. PIN verify: 5 次 / 分钟 → 超限锁 10 分钟(防爆破)
//   B. 未鉴权请求: 20 次 / 秒 token bucket(防 DoS)
//   C. 已鉴权请求: 不限流(可信客户端)
//
// OOM 防御(v2.1 §5.2 / Gemini 2.2):
//   - 最大 512 个 IP entry
//   - LRU 淘汰时跳过 pinLockTS > now 的 entry (fail-safe,防攻击者填满 LRU 重置锁)
//   - 全部锁定时新请求拒绝(fail-safe 非 fail-open)
//   - GC goroutine 每 5 分钟清理 lastSeen > 15 分钟 的 entry

package main

import (
	"container/list"
	"sync"
	"time"
)

const (
	rlMaxEntries       = 512
	rlPinAttemptsMax   = 5                // PIN 错误次数上限
	rlPinLockDuration  = 10 * time.Minute // PIN 锁定时长
	rlPinWindow        = 1 * time.Minute  // PIN 错误计数窗口(独立于 lock)
	rlUnauthCapacity   = 20.0             // 未鉴权 token bucket 容量
	rlUnauthRefillRate = 20.0             // 每秒填充 tokens
	rlEntryTTL         = 15 * time.Minute // GC 门槛
	rlGCInterval       = 5 * time.Minute
	// rc3.1.13.2 修 P1 (review §1): LRU 全锁时降级用的全局共享 bucket.
	// 防 DoS: 攻击者用 512 个 IP 各错 PIN 5 次锁满 LRU, 之前合法用户
	// 全被 fail-safe 拒绝 10 分钟 (evictOldestLocked 返 false).
	// 现在 LRU 满锁时合法用户共享一个全局 bucket, 容量大但严格 (50 req/s),
	// 既不让攻击者通过堆 IP 完全瘫痪服务, 又不放纵新 IP 滥用.
	// PIN verify 仍在全锁时硬拒 (避免攻击者绕开 LRU 用全局 bucket 继续爆破 PIN).
	rlGlobalCapacity   = 50.0
	rlGlobalRefillRate = 50.0
)

// rlEntry 单个 IP 的限流状态
type rlEntry struct {
	ip               string
	pinAttempts      int
	pinWindowStart   int64
	pinLockTS        int64 // Unix ts,> now 时处于锁定
	unauthTokens     float64
	unauthLastRefill int64
	lastSeen         int64
}

// RateLimiter 是 per-IP 的限流器。并发安全。
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*list.Element // IP → LRU 元素
	lru     *list.List               // 最老的在 Back
	// rc3.1.13.2: LRU 全锁时的降级 bucket
	globalTokens     float64
	globalLastRefill int64
}

// NewRateLimiter 创建空 limiter
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		entries:          make(map[string]*list.Element),
		lru:              list.New(),
		globalTokens:     rlGlobalCapacity,
		globalLastRefill: time.Now().Unix(),
	}
}

// getOrCreate 找到/创建一个 entry,并把它移到 LRU 头部。
// 调用者持 mu。nil 返回表示无法创建(LRU 全锁定,fail-safe 拒绝)。
func (rl *RateLimiter) getOrCreate(ip string, now int64) *rlEntry {
	if elem, ok := rl.entries[ip]; ok {
		rl.lru.MoveToFront(elem)
		e := elem.Value.(*rlEntry)
		e.lastSeen = now
		return e
	}
	// 新 IP,容量满则淘汰
	if rl.lru.Len() >= rlMaxEntries {
		if !rl.evictOldestLocked(now) {
			// 所有 entry 都在锁定中,fail-safe 拒绝新请求
			return nil
		}
	}
	e := &rlEntry{
		ip:               ip,
		unauthTokens:     rlUnauthCapacity,
		unauthLastRefill: now,
		lastSeen:         now,
	}
	elem := rl.lru.PushFront(e)
	rl.entries[ip] = elem
	return e
}

// evictOldestLocked 从 LRU 尾部往前找第一个未锁定的 entry 淘汰。
// 返回 true 表示淘汰成功;false 表示所有 entry 都在锁定中(fail-safe 场景)。
// 调用者持 mu。
func (rl *RateLimiter) evictOldestLocked(now int64) bool {
	for e := rl.lru.Back(); e != nil; e = e.Prev() {
		entry := e.Value.(*rlEntry)
		if entry.pinLockTS <= now {
			rl.lru.Remove(e)
			delete(rl.entries, entry.ip)
			return true
		}
	}
	return false
}

// CheckPinVerify 检查是否允许 PIN verify 请求。
// 返回:
//
//	true  → 允许
//	false → 拒绝(已锁 or LRU 全锁定)
//	retryAfter → 客户端应等多少秒(用于 429 响应头)
//
// rc30.12.33 (P0.2): 此方法仍保留, 用于 handlePairVerify 入口 "锁定状态"
// 短路检查 (避免对已锁定 IP 做无意义的 body 读取). 真正的尝试计数原子消费
// 在 ConsumePinAttempt 里, 不再用"Check + RegisterFail"两步走的旧模式.
func (rl *RateLimiter) CheckPinVerify(ip string) (allowed bool, retryAfter int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now().Unix()
	e := rl.getOrCreate(ip, now)
	if e == nil {
		return false, int64(rlPinLockDuration.Seconds())
	}
	if e.pinLockTS > now {
		return false, e.pinLockTS - now
	}
	return true, 0
}

// ConsumePinAttempt 原子地占用一次 PIN 尝试机会。
//
// rc30.12.33 (P0.2): 修复旧的 "Check + later RegisterFail" 并发漏洞。
// 旧流程: CheckPinVerify(只读) → 释放锁 → 解析 body / 读 pending / constant-time
// 比对 → 失败再 RegisterPinFail. 同一 IP 并发发起 N 个错误 PIN 请求时, N 个请求都
// 能通过 Check 进入比对, 直到 RegisterPinFail 累计到上限, 实际尝试数可达
// rlPinAttemptsMax + (N-1).
//
// 新流程: 进入 PIN 比对前先调本方法占用一次名额. 若 allowed=true, 调用方继续
// 比对; PIN 对则 ResetPin, PIN 错则不需要再调 RegisterPinFail (本方法已经
// 累计了). 若 allowed=false (本次占用刚好触发锁定 或 之前就已锁定),
// 直接 429.
//
// 返回:
//
//	allowed    本次请求是否允许进入比对 (false = 已锁定/刚被锁)
//	retryAfter 锁定剩余秒数 (仅 allowed=false 时有意义)
//	remaining  本窗口内剩余尝试次数 (允许时供前端显示, 锁定时返回 0)
func (rl *RateLimiter) ConsumePinAttempt(ip string) (allowed bool, retryAfter int64, remaining int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now().Unix()
	e := rl.getOrCreate(ip, now)
	if e == nil {
		// LRU 全锁定 / 内存压力 → 拒
		return false, int64(rlPinLockDuration.Seconds()), 0
	}
	// 之前已经锁定, 直接拒
	if e.pinLockTS > now {
		return false, e.pinLockTS - now, 0
	}
	// 窗口过期则重置
	if now-e.pinWindowStart > int64(rlPinWindow.Seconds()) {
		e.pinWindowStart = now
		e.pinAttempts = 0
	}
	// 原子占用: 计数 +1, 若达到上限立即锁定本次也算 allowed=false
	e.pinAttempts++
	if e.pinAttempts >= rlPinAttemptsMax {
		e.pinLockTS = now + int64(rlPinLockDuration.Seconds())
		return false, e.pinLockTS - now, 0
	}
	return true, 0, rlPinAttemptsMax - e.pinAttempts
}

// RegisterPinFail 记一次 PIN 验证失败。
// 累计到 rlPinAttemptsMax 触发锁定。
// 返回: locked=是否已锁定 / remaining=剩余允许尝试次数(锁定时为 0)
//
// rc30.12.33 (P0.2): 此方法 deprecated, 不再被 handlePairVerify 调用。
// 保留是因为旧 unit test 仍引用, 删除会让 ratelimit_test.go 编译失败。
// 新代码应使用 ConsumePinAttempt 做原子占用。
func (rl *RateLimiter) RegisterPinFail(ip string) (locked bool, remaining int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now().Unix()
	e := rl.getOrCreate(ip, now)
	if e == nil {
		return false, 0
	}
	// 窗口过期则重置
	if now-e.pinWindowStart > int64(rlPinWindow.Seconds()) {
		e.pinWindowStart = now
		e.pinAttempts = 0
	}
	e.pinAttempts++
	if e.pinAttempts >= rlPinAttemptsMax {
		e.pinLockTS = now + int64(rlPinLockDuration.Seconds())
		return true, 0
	}
	return false, rlPinAttemptsMax - e.pinAttempts
}

// ResetPin 成功 PIN 验证后清理计数
func (rl *RateLimiter) ResetPin(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if elem, ok := rl.entries[ip]; ok {
		e := elem.Value.(*rlEntry)
		e.pinAttempts = 0
		e.pinLockTS = 0
		e.pinWindowStart = 0
	}
}

// CheckUnauth 检查未鉴权请求的 token bucket。
// 每次成功调用扣 1 token,没 token 则拒绝。
// rc3.1.13.2: LRU 全锁时降级到全局 bucket (防 DoS, 见 const 注释).
func (rl *RateLimiter) CheckUnauth(ip string) (allowed bool, retryAfter int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now().Unix()
	e := rl.getOrCreate(ip, now)
	if e == nil {
		// LRU 全锁定 → 降级到全局 bucket
		elapsed := float64(now - rl.globalLastRefill)
		if elapsed > 0 {
			rl.globalTokens += elapsed * rlGlobalRefillRate
			if rl.globalTokens > rlGlobalCapacity {
				rl.globalTokens = rlGlobalCapacity
			}
			rl.globalLastRefill = now
		}
		if rl.globalTokens < 1.0 {
			return false, 1
		}
		rl.globalTokens -= 1.0
		return true, 0
	}
	// 补充 tokens
	elapsed := float64(now - e.unauthLastRefill)
	if elapsed > 0 {
		e.unauthTokens += elapsed * rlUnauthRefillRate
		if e.unauthTokens > rlUnauthCapacity {
			e.unauthTokens = rlUnauthCapacity
		}
		e.unauthLastRefill = now
	}
	if e.unauthTokens < 1.0 {
		return false, 2
	}
	e.unauthTokens -= 1.0
	return true, 0
}

// GCLoop 定期清理过期 entry
func (rl *RateLimiter) GCLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(rlGCInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			rl.gc()
		}
	}
}

func (rl *RateLimiter) gc() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now().Unix()
	ttlSec := int64(rlEntryTTL.Seconds())
	// 从尾部扫,删 lastSeen 太老且未锁定的
	var victims []*list.Element
	for e := rl.lru.Back(); e != nil; e = e.Prev() {
		entry := e.Value.(*rlEntry)
		if entry.pinLockTS > now {
			continue // 锁定中保留
		}
		if now-entry.lastSeen > ttlSec {
			victims = append(victims, e)
		}
	}
	for _, e := range victims {
		entry := e.Value.(*rlEntry)
		rl.lru.Remove(e)
		delete(rl.entries, entry.ip)
	}
}

// Size 当前 entry 数,诊断用
func (rl *RateLimiter) Size() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.lru.Len()
}
