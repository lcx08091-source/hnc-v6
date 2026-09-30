// mac_alias.go — v5.21 随机 MAC: 设备合并后的 MAC 别名表 data/mac_aliases.json
//
// 格式: 扁平对象 {"<old_mac>": "<new_mac>", ...}(小写, 冒号分隔)。只由 httpd 写
// (device_merge, 见 mac_merge_action.go), tmp+rename 原子发布。
//
// 用途: 历史用量文件(run/stats.YYYYMMDD.jsonl、run/online_hours.jsonl、
// run/app_usage.YYYYMMDD.json、data/stats_*.jsonl)按 MAC 记账且不回写; 合并后
// 各读取路径用 resolveMACAlias 把旧 MAC 的行归到新 MAC 名下, 历史自然累加:
//   /api/usage_month、/api/online_hours、/api/app_usage、/api/app_time、
//   /api/dpi_history、/api/stats(legacy / dpi)、配额控制器的历史下限、
//   应用时长上限的今日已用量。
// 链式合并(a→b 之后 b→c)在写入时就压平成 a→c, b→c; 读侧仍按最多 8 跳解析兜底。

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const macAliasesRelPath = "data/mac_aliases.json"

func macAliasesPath(hncDir string) string { return filepath.Join(hncDir, macAliasesRelPath) }

var macAliasCache struct {
	mu    sync.Mutex
	path  string
	mtime time.Time
	size  int64
	m     map[string]string
}

// loadMACAliases 读别名表(按 mtime+size 缓存)。返回的 map 只读, 调用方不得修改。
// 文件缺失/损坏 = 空表。
func loadMACAliases(hncDir string) map[string]string {
	path := macAliasesPath(hncDir)
	st, err := os.Stat(path)
	macAliasCache.mu.Lock()
	defer macAliasCache.mu.Unlock()
	if err != nil {
		macAliasCache.path, macAliasCache.m = path, map[string]string{}
		macAliasCache.mtime, macAliasCache.size = time.Time{}, -1
		return macAliasCache.m
	}
	if macAliasCache.path == path && macAliasCache.m != nil &&
		st.ModTime().Equal(macAliasCache.mtime) && st.Size() == macAliasCache.size {
		return macAliasCache.m
	}
	m := readMACAliasesFile(path)
	macAliasCache.path, macAliasCache.m = path, m
	macAliasCache.mtime, macAliasCache.size = st.ModTime(), st.Size()
	return m
}

func readMACAliasesFile(path string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var raw map[string]string
	if json.Unmarshal(b, &raw) != nil {
		return out
	}
	for k, v := range raw {
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.ToLower(strings.TrimSpace(v))
		if validMAC(k) && validMAC(v) && k != v {
			out[k] = v
		}
	}
	return out
}

// saveMACAliases 原子写别名表并让缓存失效(同秒同尺寸的改写 mtime 可能不变)。
func saveMACAliases(hncDir string, m map[string]string) error {
	if m == nil {
		m = map[string]string{}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	err = discoverWriteAtomic(macAliasesPath(hncDir), b)
	macAliasCache.mu.Lock()
	macAliasCache.m = nil
	macAliasCache.mu.Unlock()
	return err
}

// addMACAlias 在 m 上登记 from→to 并压平链: 指向 from 的旧别名改指 to; to 自己
// 若曾是别名(反向合并)则删掉, 避免环。
func addMACAlias(m map[string]string, from, to string) {
	delete(m, to)
	for k, v := range m {
		if v == from {
			m[k] = to
		}
	}
	m[from] = to
}

// resolveMACAlias 沿别名链解析到当前 MAC(小写); 不在表里原样返回小写。
func resolveMACAlias(al map[string]string, mac string) string {
	mac = strings.ToLower(mac)
	if len(al) == 0 {
		return mac
	}
	for i := 0; i < 8; i++ {
		n, ok := al[mac]
		if !ok || n == mac {
			break
		}
		mac = n
	}
	return mac
}

// macAliasResolver 读路径用: 一次取表, 返回解析函数(空表时为恒等, 零开销)。
func macAliasResolver(hncDir string) func(string) string {
	al := loadMACAliases(hncDir)
	if len(al) == 0 {
		return strings.ToLower
	}
	return func(m string) string { return resolveMACAlias(al, m) }
}
