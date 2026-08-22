package main

// jsonFileCache: mtime+size 失效的 readJSON 结果缓存。
//
// 动机 (v6 review): /api/live 是 WebUI 状态条 1-2s 轮询的热端点, 每次请求
// 同步读 + 解析 devices/rules/device_names/dpi_state 多个 JSON, 其中
// dpi_state.json 开启 self-capture 后可达上百 KB。而这些文件的写入方
// (dpid/hotspotd) 都以 tmp+rename 原子发布, 刷新间隔最快 5s —— mtime+size
// 未变即内容未变, 缓存命中率天然很高。
//
// 约定: 返回值是跨请求共享的, 调用方只读、绝不修改 (现有消费方
// buildDevicesPayload / dpiAppsByMAC / currentHotspotIface 均满足)。
// 读失败不缓存 (文件可能只是暂时缺失, 如 hotspotd 启动窗口)。

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type jsonCacheEntry struct {
	modTime time.Time
	size    int64
	val     interface{}
}

type jsonFileCache struct {
	mu      sync.Mutex
	entries map[string]jsonCacheEntry
}

func newJSONFileCache() *jsonFileCache {
	return &jsonFileCache{entries: map[string]jsonCacheEntry{}}
}

// read 返回 path 解析后的 JSON, mtime+size 未变时直接命中缓存。
func (c *jsonFileCache) read(path string) (interface{}, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if e, ok := c.entries[path]; ok && e.size == st.Size() && e.modTime.Equal(st.ModTime()) {
		c.mu.Unlock()
		return e.val, nil
	}
	c.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	// 读后再 stat 一次 (tokens.go 的双检模式): 读取期间文件被 rename 替换时
	// 前后 stat 会不一致, 此时放弃入缓存, 避免把旧内容记在新版本名下。
	st2, err := os.Stat(path)
	if err != nil || !st2.ModTime().Equal(st.ModTime()) || st2.Size() != st.Size() {
		return v, nil
	}
	c.mu.Lock()
	c.entries[path] = jsonCacheEntry{modTime: st.ModTime(), size: st.Size(), val: v}
	c.mu.Unlock()
	return v, nil
}
