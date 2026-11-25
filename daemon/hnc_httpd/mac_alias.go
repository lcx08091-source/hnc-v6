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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	macAliasesRelPath = "data/mac_aliases.json"
	macAliasesMax     = 1024
	macAliasesTTL     = int64(90 * 86400)
	macAliasTsPrefix  = "@ts:"
)

func macAliasesPath(hncDir string) string { return filepath.Join(hncDir, macAliasesRelPath) }

// macAliasMu 叶子互斥锁, 统一串行化 mac_aliases.json 的读改写(RMW)与内存缓存。
// 严格锁序: rmacReconcileMu -> s.actionMu -> 子模块锁 -> macArchiveMu -> rmacMu -> macMergeMu -> macAliasMu(叶子锁, 持锁期间严禁再拿任何其他锁)。
var macAliasMu sync.Mutex

var macAliasCache struct {
	path  string
	mtime time.Time
	size  int64
	m     map[string]string
}

func cloneAliasMap(src map[string]string) map[string]string {
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func loadMACAliasesLocked(hncDir string) map[string]string {
	path := macAliasesPath(hncDir)
	st, err := os.Stat(path)
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

func invalidateMACAliasCacheLocked() {
	macAliasCache.path = ""
	macAliasCache.mtime = time.Time{}
	macAliasCache.size = 0
	macAliasCache.m = nil
}

// invalidateMACAliasCache 在外层不持任何锁的前提下独立短持叶子锁 macAliasMu 清空别名缓存(严守叶子锁序)。
func invalidateMACAliasCache() {
	macAliasMu.Lock()
	invalidateMACAliasCacheLocked()
	macAliasMu.Unlock()
}

// loadMACAliases 读别名表(按 mtime+size 缓存)。返回独立副本, 并发安全。
// 文件缺失/损坏 = 空表。
func loadMACAliases(hncDir string) map[string]string {
	macAliasMu.Lock()
	defer macAliasMu.Unlock()
	return cloneAliasMap(loadMACAliasesLocked(hncDir))
}

// loadMACAliasesWithTsSnapshot 在 macAliasMu 保护下一次性返回裁剪后的别名映射与时间戳表。
func loadMACAliasesWithTsSnapshot(hncDir string) (map[string]string, map[string]int64) {
	macAliasMu.Lock()
	defer macAliasMu.Unlock()
	out, tsMap := readMACAliasesWithTs(macAliasesPath(hncDir))
	pruneMACAliasesMap(out, tsMap, time.Now().Unix())
	return out, tsMap
}

func readMACAliasesWithTs(path string) (map[string]string, map[string]int64) {
	out := map[string]string{}
	tsMap := map[string]int64{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out, tsMap
	}
	var raw map[string]string
	if json.Unmarshal(b, &raw) != nil {
		return out, tsMap
	}
	for k, v := range raw {
		ks := strings.ToLower(strings.TrimSpace(k))
		vs := strings.TrimSpace(v)
		if strings.HasPrefix(ks, macAliasTsPrefix) {
			mac := strings.TrimPrefix(ks, macAliasTsPrefix)
			if validMAC(mac) {
				if ts, err := strconv.ParseInt(vs, 10, 64); err == nil && ts > 0 {
					tsMap[mac] = ts
				}
			}
			continue
		}
		vs = strings.ToLower(vs)
		if validMAC(ks) && validMAC(vs) && ks != vs {
			out[ks] = vs
		}
	}
	return out, tsMap
}

// pruneMACAliasesMap 按 90 天 TTL 与 1024 条容量上限裁剪别名表(原地修改 m 与 tsMap), 返回是否有变动。
func pruneMACAliasesMap(m map[string]string, tsMap map[string]int64, now int64) bool {
	changed := false
	if now > 0 {
		for k := range m {
			if ts := tsMap[k]; ts > 0 && now-ts > macAliasesTTL {
				delete(m, k)
				delete(tsMap, k)
				changed = true
			}
		}
	}
	for k := range tsMap {
		if _, ok := m[k]; !ok {
			delete(tsMap, k)
			changed = true
		}
	}
	if len(m) > macAliasesMax {
		type item struct {
			mac string
			ts  int64
		}
		all := make([]item, 0, len(m))
		for k := range m {
			all = append(all, item{mac: k, ts: tsMap[k]})
		}
		sort.Slice(all, func(i, j int) bool {
			if all[i].ts != all[j].ts {
				return all[i].ts < all[j].ts
			}
			return all[i].mac < all[j].mac
		})
		drop := len(m) - macAliasesMax
		for i := 0; i < drop; i++ {
			delete(m, all[i].mac)
			delete(tsMap, all[i].mac)
		}
		changed = true
	}
	return changed
}

func readMACAliasesFile(path string) map[string]string {
	out, tsMap := readMACAliasesWithTs(path)
	pruneMACAliasesMap(out, tsMap, time.Now().Unix())
	return out
}

// saveMACAliases 原子写别名表并让缓存失效(同秒同尺寸的改写 mtime 可能不变)。
func saveMACAliases(hncDir string, m map[string]string) error {
	return saveMACAliasesAt(hncDir, m, time.Now().Unix(), nil)
}

// saveMACAliasesAt 支持指定当前时间与自定义时间戳映射(供归档/后台裁剪与单测精确控制 TTL)。
func saveMACAliasesAt(hncDir string, m map[string]string, now int64, customTs map[string]int64) error {
	macAliasMu.Lock()
	defer macAliasMu.Unlock()
	return saveMACAliasesAtLocked(hncDir, m, now, customTs)
}

func saveMACAliasesAtLocked(hncDir string, m map[string]string, now int64, customTs map[string]int64) error {
	path := macAliasesPath(hncDir)
	prevM, prevTs := readMACAliasesWithTs(path)
	clean := map[string]string{}
	tsOut := map[string]int64{}
	for k, v := range m {
		ks, vs := strings.ToLower(strings.TrimSpace(k)), strings.ToLower(strings.TrimSpace(v))
		if !validMAC(ks) || !validMAC(vs) || ks == vs {
			continue
		}
		clean[ks] = vs
		if customTs != nil && customTs[ks] > 0 {
			tsOut[ks] = customTs[ks]
		} else if prevV, had := prevM[ks]; had && prevV == vs && prevTs[ks] > 0 {
			tsOut[ks] = prevTs[ks]
		} else if now > 0 {
			tsOut[ks] = now
		}
	}
	pruneMACAliasesMap(clean, tsOut, now)
	raw := make(map[string]string, len(clean)*2)
	for k, v := range clean {
		raw[k] = v
		if ts := tsOut[k]; ts > 0 {
			raw[macAliasTsPrefix+k] = strconv.FormatInt(ts, 10)
		}
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	err = discoverWriteAtomic(path, b)
	invalidateMACAliasCacheLocked()
	return err
}

// commitMACAliasStep 在叶子锁 macAliasMu 内原子完成快照采集、别名链压平登记与写盘提交。
func commitMACAliasStep(hncDir, from, to string, now int64) (fileSnap, error) {
	macAliasMu.Lock()
	defer macAliasMu.Unlock()
	path := macAliasesPath(hncDir)
	snap := snapFile(path)
	m := cloneAliasMap(loadMACAliasesLocked(hncDir))
	addMACAlias(m, from, to)
	if err := saveMACAliasesAtLocked(hncDir, m, now, nil); err != nil {
		return snap, err
	}
	return snap, nil
}

// undoMACAliasStep 在叶子锁 macAliasMu 内原子恢复快照并使缓存失效。
func undoMACAliasStep(snap fileSnap) {
	macAliasMu.Lock()
	defer macAliasMu.Unlock()
	if snap.path != "" {
		_ = snap.restore()
		invalidateMACAliasCacheLocked()
	}
}

// removeMACAliasFrom 在叶子锁 macAliasMu 内原子删除指定旧 MAC 别名绑定并写盘。
func removeMACAliasFrom(hncDir, from string, now int64) error {
	macAliasMu.Lock()
	defer macAliasMu.Unlock()
	m := cloneAliasMap(loadMACAliasesLocked(hncDir))
	delete(m, from)
	return saveMACAliasesAtLocked(hncDir, m, now, nil)
}

// pruneMACAliases 周期性裁剪过期(>90 天)或超上限(>1024 条)的别名记录; 无变动时零写盘。
func pruneMACAliases(hncDir string, now int64) {
	macAliasMu.Lock()
	defer macAliasMu.Unlock()
	path := macAliasesPath(hncDir)
	if _, err := os.Stat(path); err != nil {
		return
	}
	m, tsMap := readMACAliasesWithTs(path)
	if len(m) == 0 && len(tsMap) == 0 {
		return
	}
	changed := false
	if now > 0 {
		for k := range m {
			if tsMap[k] <= 0 {
				tsMap[k] = now
				changed = true
			}
		}
	}
	if pruneMACAliasesMap(m, tsMap, now) {
		changed = true
	}
	if changed {
		_ = saveMACAliasesAtLocked(hncDir, m, now, tsMap)
	}
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
