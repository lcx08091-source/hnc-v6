// writelimit.go — Patch 3.a per-token write rate limit
//
// 分开放是为了把 Patch 3 专属的限流逻辑独立,不碰 Patch 2.b 的 ratelimit.go
// (那个面向 PIN/unauth 两种场景已经够复杂了)
//
// 设计: 简单滑动窗口
//   key = "wr-<TokenID 前 8 位>" 或 "wr-anon-<IP>"
//   窗口: 60 秒
//   阈值: 60 次
//   达到阈值就拒绝, 直到最老的请求滑出窗口
//
// 不做 LRU 淘汰(写操作量有限, 顶多百余个 entry, 不会 OOM)
// 做 GC: 每 5 分钟清理 lastSeen > 10 分钟的 entry

package main

import (
	"sync"
	"time"
)

const (
	writeWindowSec = 60
	writeMaxPerWin = 60
	writeEntryTTL  = 10 * time.Minute
)

type writeEntry struct {
	timestamps []int64 // 最近 N 次请求的 unix ts, 按时间排序(最老在前)
	lastSeen   int64
}

type WriteCounter struct {
	mu      sync.Mutex
	entries map[string]*writeEntry
}

func NewWriteCounter() *WriteCounter {
	return &WriteCounter{
		entries: make(map[string]*writeEntry),
	}
}

// CheckAndIncr 看当前窗口内是否还有配额,有则扣一次返 true,否则 false
// 原子: 检查和扣减在同一个锁里
func (wc *WriteCounter) CheckAndIncr(key string) bool {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	now := time.Now().Unix()

	e, ok := wc.entries[key]
	if !ok {
		e = &writeEntry{}
		wc.entries[key] = e
	}
	e.lastSeen = now

	// 裁剪窗口外的时间戳
	cutoff := now - writeWindowSec
	keepFrom := 0
	for i, ts := range e.timestamps {
		if ts > cutoff {
			keepFrom = i
			break
		}
		keepFrom = i + 1
	}
	if keepFrom > 0 {
		e.timestamps = e.timestamps[keepFrom:]
	}

	if len(e.timestamps) >= writeMaxPerWin {
		return false
	}
	e.timestamps = append(e.timestamps, now)
	return true
}

// GCLoop 每 5 分钟清理超过 TTL 没活动的 entry
func (wc *WriteCounter) GCLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			wc.gc()
		}
	}
}

func (wc *WriteCounter) gc() {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	now := time.Now().Unix()
	ttl := int64(writeEntryTTL.Seconds())
	for k, e := range wc.entries {
		if now-e.lastSeen > ttl {
			delete(wc.entries, k)
		}
	}
}

// Size 当前 entry 数, 诊断用
func (wc *WriteCounter) Size() int {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	return len(wc.entries)
}
