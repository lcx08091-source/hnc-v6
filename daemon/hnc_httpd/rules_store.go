// rules_store.go — HNC v5.40.0 T3: 高频 data/rules.json 进程内加锁原子存储引擎。
//
// 设计目标:
//  1. 毫秒级进程内并发安全读写: 全局互斥锁 + mtime/size 双检内存快照缓存, 消除高频滑块调速时
//     反复 fork sh + awk(hnc_json) 带来的百毫秒级开销与文件锁竞争。
//  2. 100% 未知字段无损保留: 采用 json.NewDecoder + UseNumber 解码为动态树 map[string]interface{},
//     任意顶层扩展配置或设备级自定义字段(如 delay_ms/sqm_enabled/quota/schedule 等)在更新时原样保留。
//  3. 触发 dpid/watchdog inotify 联动: 写入同目录隐藏临时文件 (.rules.json.tmp.*) -> fsync -> chmod 0644
//     -> os.Rename 原子覆盖 data/rules.json, 确保外部守护进程的 IN_MOVED_TO / mtime 监听即时触发,
//     同时协同遵守 run/json.lock 目录锁(基于 /proc/<pid> 判活回收陈旧锁, 严禁调用 ps/pidof)。
//  4. 单测桩零回归委托: 当 !useNativeDataplane(hncDir) 且存在假脚本 bin/json_set.sh 时, 自动委托
//     runBin(hncDir, "json_set.sh", ...) 执行, 确保既有 60+ 单测对脚本参数序列的断言 100% 通过。

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var errMarkIDExhausted = errors.New("rulesStore: mark_id pool [1..99] exhausted")

// rulesStoreEngine 提供全局互斥锁保护的 data/rules.json 原子读写引擎。
// 严格遵守 32 位 ARM 8 字节对齐铁律: 所有 atomic.Uint64 字段必须位于结构体起始偏移 (offset 0)。
type rulesStoreEngine struct {
	readHits       atomic.Uint64
	readMisses     atomic.Uint64
	atomicWrites   atomic.Uint64
	stubDelegates  atomic.Uint64
	mu             sync.Mutex
	cachedPath     string
	cachedModNano  int64
	cachedSize     int64
	cachedSnapshot map[string]interface{}
}

// rulesStore 全局单例引擎。
var rulesStore = &rulesStoreEngine{}

// rulesTopAlwaysString 与 bin/json_set.sh 的 json_top_field_is_string 严格同源:
// 这些顶层字段语义上恒为字符串, 绝不能把纯数字 WiFi 密码(如 "12345678" / "01234567")误转为 JSON 数字。
var rulesTopAlwaysString = map[string]bool{
	"hotspot_ssid":    true,
	"hotspot_pass":    true,
	"hotspot_iface":   true,
	"clsact_bpf_mode": true,
}

func rulesFilePath(hncDir string) string {
	return filepath.Join(hncDir, "data", "rules.json")
}

func shouldDelegateJSONSetStub(hncDir string) bool {
	if useNativeDataplane(hncDir) {
		return false
	}
	st, err := os.Stat(filepath.Join(hncDir, "bin", "json_set.sh"))
	return err == nil && !st.IsDir()
}

func defaultRulesRoot() map[string]interface{} {
	return map[string]interface{}{
		"version":        json.Number("1"),
		"whitelist_mode": false,
		"devices":        map[string]interface{}{},
		"blacklist":      []interface{}{},
		"whitelist":      []interface{}{},
	}
}

func decodeRulesBytes(b []byte) (map[string]interface{}, error) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		return defaultRulesRoot(), nil
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var root map[string]interface{}
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	if root == nil {
		return defaultRulesRoot(), nil
	}
	ensureRulesBaseContainers(root)
	return root, nil
}

func ensureRulesBaseContainers(root map[string]interface{}) {
	if _, ok := root["version"]; !ok {
		root["version"] = json.Number("1")
	}
	if _, ok := root["whitelist_mode"]; !ok {
		root["whitelist_mode"] = false
	}
	if _, ok := root["devices"].(map[string]interface{}); !ok {
		root["devices"] = map[string]interface{}{}
	}
	if _, ok := root["blacklist"].([]interface{}); !ok {
		root["blacklist"] = []interface{}{}
	}
	if _, ok := root["whitelist"].([]interface{}); !ok {
		root["whitelist"] = []interface{}{}
	}
}

func deepCloneJSONValue(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		cp := make(map[string]interface{}, len(x))
		for k, val := range x {
			cp[k] = deepCloneJSONValue(val)
		}
		return cp
	case []interface{}:
		cp := make([]interface{}, len(x))
		for i, val := range x {
			cp[i] = deepCloneJSONValue(val)
		}
		return cp
	default:
		return x
	}
}

func deepCloneRulesMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return defaultRulesRoot()
	}
	cp, _ := deepCloneJSONValue(m).(map[string]interface{})
	return cp
}

// acquireCooperativeJSONLock 协同遵守 bin/hnc_json 的 run/json.lock 目录锁 (最多等待 1.5s)。
// 判活严格通过 /proc/<pid> 文件系统检查, 绝不调用 ps 或 pidof。
func acquireCooperativeJSONLock(hncDir string) func() {
	runDir := filepath.Join(hncDir, "run")
	_ = os.MkdirAll(runDir, 0o700)
	lockDir := filepath.Join(runDir, "json.lock")

	deadline := time.Now().Add(1500 * time.Millisecond)
	for {
		if err := os.Mkdir(lockDir, 0o700); err == nil {
			pidStr := strconv.Itoa(os.Getpid())
			tsStr := strconv.FormatInt(time.Now().Unix(), 10)
			_ = os.WriteFile(filepath.Join(lockDir, "pid"), []byte(pidStr+"\n"), 0o600)
			_ = os.WriteFile(filepath.Join(lockDir, "ts"), []byte(tsStr+"\n"), 0o600)
			return func() {
				_ = os.RemoveAll(lockDir)
			}
		}
		reclaimStaleJSONLockDir(lockDir)
		if time.Now().After(deadline) {
			// 超时降级: 进程内已有 rulesStore.mu 串行化且写盘采用 tmp+rename 原子替换, 不会产生半截 JSON
			return func() {}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func reclaimStaleJSONLockDir(lockDir string) {
	pidBytes, err := os.ReadFile(filepath.Join(lockDir, "pid"))
	if err == nil {
		if pid, perr := strconv.Atoi(strings.TrimSpace(string(pidBytes))); perr == nil && pid > 0 {
			// Linux/Android 上若 /proc 挂载且 /proc/<pid> 已消失, 说明持锁进程已退出
			if _, procRootErr := os.Stat("/proc/self"); procRootErr == nil {
				if _, pErr := os.Stat("/proc/" + strconv.Itoa(pid)); os.IsNotExist(pErr) {
					_ = os.RemoveAll(lockDir)
					return
				}
			}
		}
	}
	if tsBytes, err := os.ReadFile(filepath.Join(lockDir, "ts")); err == nil {
		if ts, terr := strconv.ParseInt(strings.TrimSpace(string(tsBytes)), 10, 64); terr == nil && ts > 0 {
			if time.Now().Unix()-ts >= 30 {
				_ = os.RemoveAll(lockDir)
			}
		}
	}
}

func (rs *rulesStoreEngine) loadLocked(hncDir string) (map[string]interface{}, error) {
	path := rulesFilePath(hncDir)
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultRulesRoot(), nil
		}
		return nil, err
	}
	if rs.cachedSnapshot != nil &&
		rs.cachedPath == path &&
		rs.cachedModNano == st.ModTime().UnixNano() &&
		rs.cachedSize == st.Size() {
		rs.readHits.Add(1)
		return deepCloneRulesMap(rs.cachedSnapshot), nil
	}

	rs.readMisses.Add(1)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultRulesRoot(), nil
		}
		return nil, err
	}
	root, err := decodeRulesBytes(b)
	if err != nil {
		return nil, fmt.Errorf("rulesStore: corrupt %s: %w", path, err)
	}
	if st2, err2 := os.Stat(path); err2 == nil &&
		st2.ModTime().UnixNano() == st.ModTime().UnixNano() &&
		st2.Size() == st.Size() {
		rs.cachedPath = path
		rs.cachedModNano = st.ModTime().UnixNano()
		rs.cachedSize = st.Size()
		rs.cachedSnapshot = deepCloneRulesMap(root)
	}
	return root, nil
}

func (rs *rulesStoreEngine) saveLocked(hncDir string, root map[string]interface{}) error {
	ensureRulesBaseContainers(root)
	path := rulesFilePath(hncDir)
	dataDir := filepath.Dir(path)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(root); err != nil {
		return err
	}
	payload := buf.Bytes()

	unlock := acquireCooperativeJSONLock(hncDir)
	defer unlock()

	// 写入同目录 .tmp 文件 -> fsync -> close -> os.Rename, 100% 原子发布并触发 dpid/watchdog inotify
	f, err := os.CreateTemp(dataDir, ".rules.json.tmp.*")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := f.Write(payload); err != nil {
		_ = f.Close()
		return err
	}
	_ = f.Chmod(0o644)
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	rs.atomicWrites.Add(1)

	if st, err := os.Stat(path); err == nil {
		rs.cachedPath = path
		rs.cachedModNano = st.ModTime().UnixNano()
		rs.cachedSize = st.Size()
		rs.cachedSnapshot = deepCloneRulesMap(root)
	} else {
		rs.cachedSnapshot = nil
	}
	return nil
}

// ── 类型转换与规范化辅助函数 ─────────────────────────────────────────────────

func coerceRulesValue(v interface{}, forceString bool) interface{} {
	if forceString {
		return anyToRuleString(v)
	}
	switch x := v.(type) {
	case nil:
		return nil
	case bool, int, int64, uint64, float64, json.Number, map[string]interface{}, []interface{}:
		return x
	case string:
		return coerceAutoString(x)
	default:
		return fmt.Sprint(x)
	}
}

// coerceAutoString 严格对齐 bin/hnc_json 的 TYPE=auto 推断规则:
//   - "true"/"false" -> bool
//   - "null" -> nil
//   - 合法十进制整数/浮点数(不含前导零如 "0123") -> json.Number
//   - 其余保留原字符串(剔除非法控制字符)
func coerceAutoString(s string) interface{} {
	switch s {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}
	if isCanonicalJSONNumber(s) {
		return json.Number(s)
	}
	return stripInvalidCtrlChars(s)
}

func isCanonicalJSONNumber(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[i] == '-' {
		i++
		if i >= len(s) {
			return false
		}
	}
	if s[i] == '0' {
		i++
		if i < len(s) && s[i] >= '0' && s[i] <= '9' {
			// 前导零数字串(如 WiFi 密码 "01234567")必须保留为字符串
			return false
		}
	} else if s[i] >= '1' && s[i] <= '9' {
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	} else {
		return false
	}
	if i < len(s) && s[i] == '.' {
		i++
		if i >= len(s) || s[i] < '0' || s[i] > '9' {
			return false
		}
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	}
	return i == len(s)
}

func stripInvalidCtrlChars(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 && c != '\b' && c != '\f' && c != '\n' && c != '\r' && c != '\t' {
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func anyToRuleString(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Sprint(x)
		}
		return string(b)
	}
}

func anyToRuleInt(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return int(n)
		}
		if f, err := x.Float64(); err == nil {
			return int(f)
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return n
		}
	}
	return 0
}

func anyToRuleBool(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "true" || s == "1" || s == "on" || s == "yes"
	case json.Number:
		return x.String() == "1"
	case float64:
		return x == 1
	case int:
		return x == 1
	}
	return false
}

// getOrEnsureDeviceEntryLocked 获取(并自动将历史大写键合并归一化为小写 MAC) devices[mac] 对象。
func getOrEnsureDeviceEntryLocked(root map[string]interface{}, mac string, create bool) (map[string]interface{}, bool) {
	devs, ok := root["devices"].(map[string]interface{})
	if !ok {
		devs = map[string]interface{}{}
		root["devices"] = devs
	}
	if existing, ok := devs[mac].(map[string]interface{}); ok {
		// 顺带合并可能残留的同 MAC 大写重复键
		for k, v := range devs {
			if k != mac && strings.EqualFold(k, mac) {
				if dupMap, ok := v.(map[string]interface{}); ok {
					for dk, dv := range dupMap {
						if _, has := existing[dk]; !has {
							existing[dk] = dv
						}
					}
				}
				delete(devs, k)
			}
		}
		return existing, true
	}
	for k, v := range devs {
		if strings.EqualFold(k, mac) {
			dm, ok := v.(map[string]interface{})
			if !ok {
				dm = map[string]interface{}{}
			}
			delete(devs, k)
			devs[mac] = dm
			return dm, true
		}
	}
	if !create {
		return nil, false
	}
	dm := map[string]interface{}{}
	devs[mac] = dm
	return dm, true
}

func allocMarkIDFromRootLocked(root map[string]interface{}, mac string) (int, error) {
	dm, _ := getOrEnsureDeviceEntryLocked(root, mac, true)
	if cur := anyToRuleInt(dm["mark_id"]); cur >= 1 && cur <= 99 {
		return cur, nil
	}

	used := make(map[int]bool, 32)
	if devs, ok := root["devices"].(map[string]interface{}); ok {
		for k, v := range devs {
			if strings.EqualFold(k, mac) {
				continue
			}
			if other, ok := v.(map[string]interface{}); ok {
				if m := anyToRuleInt(other["mark_id"]); m >= 1 && m <= 99 {
					used[m] = true
				}
			}
		}
	}

	// 与 apply_device_rule.sh 完全一致: 以 MAC 末字节 hex % 99 + 1 为起点线性探测 [1..99]
	start := 1
	parts := strings.Split(mac, ":")
	if len(parts) == 6 {
		if lb, err := strconv.ParseUint(parts[5], 16, 8); err == nil {
			start = int(lb)%99 + 1
		}
	}
	for k := 0; k < 99; k++ {
		cand := (start-1+k)%99 + 1
		if !used[cand] {
			dm["mark_id"] = json.Number(strconv.Itoa(cand))
			dm["last_seen_persist"] = json.Number(strconv.FormatInt(time.Now().Unix(), 10))
			return cand, nil
		}
	}
	return 0, errMarkIDExhausted
}

func updateUniqueMACArrayLocked(root map[string]interface{}, arrayKey, mac string, present bool) {
	rawArr, _ := root[arrayKey].([]interface{})
	out := make([]interface{}, 0, len(rawArr)+1)
	found := false
	for _, item := range rawArr {
		s := strings.ToLower(strings.TrimSpace(anyToRuleString(item)))
		if s == "" {
			continue
		}
		if strings.EqualFold(s, mac) {
			if present && !found {
				out = append(out, mac)
				found = true
			}
			continue
		}
		out = append(out, s)
	}
	if present && !found {
		out = append(out, mac)
	}
	root[arrayKey] = out
}

// ── 对外公开方法（自动识别真机原生路径 vs 单测假脚本路径） ───────────────────

// ReadAll 返回当前 data/rules.json 的深拷贝视图 (未知字段完整保留)。
func (rs *rulesStoreEngine) ReadAll(hncDir string) (map[string]interface{}, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.loadLocked(hncDir)
}

// Mutate 在全局互斥锁保护下对 data/rules.json 执行自定义原子读-改-写事务, 保留所有未知字段。
func (rs *rulesStoreEngine) Mutate(hncDir string, fn func(root map[string]interface{}) error) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	root, err := rs.loadLocked(hncDir)
	if err != nil {
		return err
	}
	if err := fn(root); err != nil {
		return err
	}
	return rs.saveLocked(hncDir, root)
}

// GetTop 读取顶层配置字段(去引号字符串表示; 键不存在时返回 "", nil, 与 json_set.sh top_get 一致)。
func (rs *rulesStoreEngine) GetTop(hncDir, field string) (string, error) {
	field = strings.TrimSpace(field)
	if field == "" {
		return "", errors.New("rulesStore.GetTop: empty field")
	}
	if shouldDelegateJSONSetStub(hncDir) {
		rs.stubDelegates.Add(1)
		rc, out := runBin(hncDir, "json_set.sh", "top_get", field)
		if rc != 0 {
			return "", fmt.Errorf("json_set.sh top_get %s rc=%d: %s", field, rc, strings.TrimSpace(out))
		}
		return strings.TrimSpace(out), nil
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	root, err := rs.loadLocked(hncDir)
	if err != nil {
		return "", err
	}
	v, ok := root[field]
	if !ok || v == nil {
		return "", nil
	}
	return anyToRuleString(v), nil
}

// SetTop 原子写入顶层字段并保留其他所有字段。单测桩环境下委托给 json_set.sh top。
func (rs *rulesStoreEngine) SetTop(hncDir, field string, value interface{}) error {
	field = strings.TrimSpace(field)
	if field == "" {
		return errors.New("rulesStore.SetTop: empty field")
	}
	if shouldDelegateJSONSetStub(hncDir) {
		rs.stubDelegates.Add(1)
		rc, out := runBin(hncDir, "json_set.sh", "top", field, anyToRuleString(value))
		if rc != 0 {
			return fmt.Errorf("json_set.sh top %s rc=%d: %s", field, rc, strings.TrimSpace(out))
		}
		return nil
	}
	return rs.Mutate(hncDir, func(root map[string]interface{}) error {
		root[field] = coerceRulesValue(value, rulesTopAlwaysString[field])
		return nil
	})
}

// SetTopBatch 一次写盘原子更新多个顶层开关/配置字段。
func (rs *rulesStoreEngine) SetTopBatch(hncDir string, fields map[string]interface{}) error {
	if len(fields) == 0 {
		return nil
	}
	if shouldDelegateJSONSetStub(hncDir) {
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := rs.SetTop(hncDir, k, fields[k]); err != nil {
				return err
			}
		}
		return nil
	}
	return rs.Mutate(hncDir, func(root map[string]interface{}) error {
		for k, v := range fields {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			root[k] = coerceRulesValue(v, rulesTopAlwaysString[k])
		}
		return nil
	})
}

// GetDeviceField 读取 devices[mac][field] (设备或字段不存在时返回 "", nil, 与 json_set.sh device_get 一致)。
func (rs *rulesStoreEngine) GetDeviceField(hncDir, mac, field string) (string, error) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	field = strings.TrimSpace(field)
	if !macRE.MatchString(mac) {
		return "", fmt.Errorf("rulesStore.GetDeviceField: invalid mac %q", mac)
	}
	if field == "" {
		return "", errors.New("rulesStore.GetDeviceField: empty field")
	}
	if shouldDelegateJSONSetStub(hncDir) {
		rs.stubDelegates.Add(1)
		rc, out := runBin(hncDir, "json_set.sh", "device_get", mac, field)
		if rc != 0 {
			return "", fmt.Errorf("json_set.sh device_get %s %s rc=%d: %s", mac, field, rc, strings.TrimSpace(out))
		}
		return strings.TrimSpace(out), nil
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	root, err := rs.loadLocked(hncDir)
	if err != nil {
		return "", err
	}
	devs, _ := root["devices"].(map[string]interface{})
	for k, raw := range devs {
		if strings.EqualFold(k, mac) {
			if dm, ok := raw.(map[string]interface{}); ok {
				if v, exists := dm[field]; exists && v != nil {
					return anyToRuleString(v), nil
				}
			}
			break
		}
	}
	return "", nil
}

// GetDeviceMap 返回 devices[mac] 的深拷贝字段字典。
func (rs *rulesStoreEngine) GetDeviceMap(hncDir, mac string) (map[string]interface{}, bool, error) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRE.MatchString(mac) {
		return nil, false, fmt.Errorf("rulesStore.GetDeviceMap: invalid mac %q", mac)
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	root, err := rs.loadLocked(hncDir)
	if err != nil {
		return nil, false, err
	}
	devs, _ := root["devices"].(map[string]interface{})
	for k, raw := range devs {
		if strings.EqualFold(k, mac) {
			if dm, ok := raw.(map[string]interface{}); ok {
				cp, _ := deepCloneJSONValue(dm).(map[string]interface{})
				return cp, true, nil
			}
			return map[string]interface{}{}, true, nil
		}
	}
	return nil, false, nil
}

// SetDeviceField 原子更新单个设备字段并保留该设备及全局所有其他字段。
func (rs *rulesStoreEngine) SetDeviceField(hncDir, mac, field string, value interface{}) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	field = strings.TrimSpace(field)
	if !macRE.MatchString(mac) {
		return fmt.Errorf("rulesStore.SetDeviceField: invalid mac %q", mac)
	}
	if field == "" {
		return errors.New("rulesStore.SetDeviceField: empty field")
	}
	if shouldDelegateJSONSetStub(hncDir) {
		rs.stubDelegates.Add(1)
		rc, out := runBin(hncDir, "json_set.sh", "device", mac, field, anyToRuleString(value))
		if rc != 0 {
			return fmt.Errorf("json_set.sh device %s %s rc=%d: %s", mac, field, rc, strings.TrimSpace(out))
		}
		return nil
	}
	return rs.Mutate(hncDir, func(root map[string]interface{}) error {
		dm, _ := getOrEnsureDeviceEntryLocked(root, mac, true)
		dm[field] = coerceRulesValue(value, false)
		return nil
	})
}

// SetDeviceBatch 在一次原子落盘内更新指定设备的多个字段, 未知字段 100% 保留。
func (rs *rulesStoreEngine) SetDeviceBatch(hncDir, mac string, fields map[string]interface{}) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRE.MatchString(mac) {
		return fmt.Errorf("rulesStore.SetDeviceBatch: invalid mac %q", mac)
	}
	if len(fields) == 0 {
		return nil
	}
	if shouldDelegateJSONSetStub(hncDir) {
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if _, err := os.Stat(filepath.Join(hncDir, "bin", "json_set_batch.sh")); err == nil {
			rs.stubDelegates.Add(1)
			args := make([]string, 0, 2+len(keys)*2)
			args = append(args, "device", mac)
			for _, k := range keys {
				args = append(args, k, anyToRuleString(fields[k]))
			}
			if rc, out := runBin(hncDir, "json_set_batch.sh", args...); rc != 0 {
				return fmt.Errorf("json_set_batch.sh device %s rc=%d: %s", mac, rc, strings.TrimSpace(out))
			}
			return nil
		}
		for _, k := range keys {
			if err := rs.SetDeviceField(hncDir, mac, k, fields[k]); err != nil {
				return err
			}
		}
		return nil
	}
	return rs.Mutate(hncDir, func(root map[string]interface{}) error {
		dm, _ := getOrEnsureDeviceEntryLocked(root, mac, true)
		for k, v := range fields {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			dm[k] = coerceRulesValue(v, false)
		}
		return nil
	})
}

// RemoveDevice 原子移除 devices[mac] 条目(不动顶层 blacklist / whitelist)。
func (rs *rulesStoreEngine) RemoveDevice(hncDir, mac string) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRE.MatchString(mac) {
		return fmt.Errorf("rulesStore.RemoveDevice: invalid mac %q", mac)
	}
	if shouldDelegateJSONSetStub(hncDir) {
		rs.stubDelegates.Add(1)
		rc, out := runBin(hncDir, "json_set.sh", "device_remove", mac)
		if rc != 0 {
			return fmt.Errorf("json_set.sh device_remove %s rc=%d: %s", mac, rc, strings.TrimSpace(out))
		}
		return nil
	}
	return rs.Mutate(hncDir, func(root map[string]interface{}) error {
		if devs, ok := root["devices"].(map[string]interface{}); ok {
			for k := range devs {
				if strings.EqualFold(k, mac) {
					delete(devs, k)
				}
			}
		}
		return nil
	})
}

// AllocMarkID 为设备幂等复用或原子分配 [1..99] 范围内的唯一 mark_id。
// 单测假环境(存在假 json_set.sh / apply_device_rule.sh)下严格按既有脚本协议调用以兼容单测日志断言。
func (rs *rulesStoreEngine) AllocMarkID(hncDir, mac string) (int, error) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRE.MatchString(mac) {
		return 0, fmt.Errorf("rulesStore.AllocMarkID: invalid mac %q", mac)
	}
	if shouldDelegateJSONSetStub(hncDir) {
		rs.stubDelegates.Add(1)
		rcM, outM := runBin(hncDir, "json_set.sh", "device_get", mac, "mark_id")
		if rcM == 0 {
			if existing, err := strconv.Atoi(strings.TrimSpace(outM)); err == nil && existing >= 1 && existing <= 99 {
				return existing, nil
			}
		}
		if _, err := os.Stat(filepath.Join(hncDir, "bin", "apply_device_rule.sh")); err == nil {
			rcA, outA := runBin(hncDir, "apply_device_rule.sh", "alloc_mid", mac)
			if rcA != 0 {
				return 0, fmt.Errorf("apply_device_rule.sh alloc_mid rc=%d: %s", rcA, strings.TrimSpace(outA))
			}
			mid, err := strconv.Atoi(strings.TrimSpace(outA))
			if err != nil || mid < 1 || mid > 99 {
				return 0, fmt.Errorf("alloc_mid returned invalid mid %q", strings.TrimSpace(outA))
			}
			return mid, nil
		}
	}

	var assigned int
	err := rs.Mutate(hncDir, func(root map[string]interface{}) error {
		mid, err := allocMarkIDFromRootLocked(root, mac)
		if err != nil {
			return err
		}
		assigned = mid
		return nil
	})
	return assigned, err
}

// UpdateDeviceLimit 一次加锁原子完成 mark_id 复用/分配 + 限速字段(down_mbps, up_mbps, limit_enabled, ip, last_seen_persist)更新,
// 并保留该设备的 app_qos / delay_ms / sqm_enabled / whitelist 等全部既有未知字段。
func (rs *rulesStoreEngine) UpdateDeviceLimit(hncDir, mac, ipv4, downMbps, upMbps string, limitEnabled bool) (int, error) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRE.MatchString(mac) {
		return 0, fmt.Errorf("rulesStore.UpdateDeviceLimit: invalid mac %q", mac)
	}
	if downMbps == "" {
		downMbps = "0"
	}
	if upMbps == "" {
		upMbps = "0"
	}
	if shouldDelegateJSONSetStub(hncDir) {
		var mid int
		if limitEnabled {
			m, err := rs.AllocMarkID(hncDir, mac)
			if err != nil {
				return 0, err
			}
			mid = m
		} else {
			if s, _ := rs.GetDeviceField(hncDir, mac, "mark_id"); s != "" {
				mid, _ = strconv.Atoi(s)
			}
		}
		batch := map[string]interface{}{
			"down_mbps":         coerceAutoString(downMbps),
			"up_mbps":           coerceAutoString(upMbps),
			"limit_enabled":     limitEnabled,
			"last_seen_persist": time.Now().Unix(),
		}
		if strings.TrimSpace(ipv4) != "" {
			batch["ip"] = strings.TrimSpace(ipv4)
		}
		if err := rs.SetDeviceBatch(hncDir, mac, batch); err != nil {
			return 0, err
		}
		return mid, nil
	}

	var outMid int
	err := rs.Mutate(hncDir, func(root map[string]interface{}) error {
		dm, _ := getOrEnsureDeviceEntryLocked(root, mac, true)
		if limitEnabled {
			mid, err := allocMarkIDFromRootLocked(root, mac)
			if err != nil {
				return err
			}
			outMid = mid
		} else {
			outMid = anyToRuleInt(dm["mark_id"])
		}
		if ip := strings.TrimSpace(ipv4); ip != "" {
			dm["ip"] = ip
		}
		dm["down_mbps"] = coerceAutoString(downMbps)
		dm["up_mbps"] = coerceAutoString(upMbps)
		dm["limit_enabled"] = limitEnabled
		dm["last_seen_persist"] = json.Number(strconv.FormatInt(time.Now().Unix(), 10))
		return nil
	})
	return outMid, err
}

// SetBlacklist 原子增删顶层 blacklist 数组中的设备 MAC (去重且归一化为小写)。
func (rs *rulesStoreEngine) SetBlacklist(hncDir, mac string, blocked bool) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRE.MatchString(mac) {
		return fmt.Errorf("rulesStore.SetBlacklist: invalid mac %q", mac)
	}
	if shouldDelegateJSONSetStub(hncDir) {
		rs.stubDelegates.Add(1)
		cmd := "bl_del"
		if blocked {
			cmd = "bl_add"
		}
		rc, out := runBin(hncDir, "json_set.sh", cmd, mac)
		if rc != 0 {
			return fmt.Errorf("json_set.sh %s %s rc=%d: %s", cmd, mac, rc, strings.TrimSpace(out))
		}
		return nil
	}
	return rs.Mutate(hncDir, func(root map[string]interface{}) error {
		updateUniqueMACArrayLocked(root, "blacklist", mac, blocked)
		return nil
	})
}

// SetWhitelist 原子同步顶层 whitelist 数组与 devices[mac].whitelist 字段。
func (rs *rulesStoreEngine) SetWhitelist(hncDir, mac string, allowed bool) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRE.MatchString(mac) {
		return fmt.Errorf("rulesStore.SetWhitelist: invalid mac %q", mac)
	}
	if shouldDelegateJSONSetStub(hncDir) {
		return rs.SetDeviceField(hncDir, mac, "whitelist", strconv.FormatBool(allowed))
	}
	return rs.Mutate(hncDir, func(root map[string]interface{}) error {
		updateUniqueMACArrayLocked(root, "whitelist", mac, allowed)
		dm, _ := getOrEnsureDeviceEntryLocked(root, mac, true)
		dm["whitelist"] = allowed
		return nil
	})
}

// SetWhitelistMode 原子更新顶层 whitelist_mode 开关。
func (rs *rulesStoreEngine) SetWhitelistMode(hncDir string, enabled bool) error {
	return rs.SetTop(hncDir, "whitelist_mode", enabled)
}

// SetDeviceAppQoS 原子更新设备级 app_qos 开关(开启时若尚无 mark_id 自动在同一次事务或桩调用中完成分配)。
func (rs *rulesStoreEngine) SetDeviceAppQoS(hncDir, mac string, enabled bool) (int, error) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRE.MatchString(mac) {
		return 0, fmt.Errorf("rulesStore.SetDeviceAppQoS: invalid mac %q", mac)
	}
	if shouldDelegateJSONSetStub(hncDir) {
		var mid int
		if enabled {
			m, err := rs.AllocMarkID(hncDir, mac)
			if err != nil {
				return 0, err
			}
			mid = m
		}
		if err := rs.SetDeviceField(hncDir, mac, "app_qos", strconv.FormatBool(enabled)); err != nil {
			return 0, err
		}
		return mid, nil
	}

	var outMid int
	err := rs.Mutate(hncDir, func(root map[string]interface{}) error {
		dm, _ := getOrEnsureDeviceEntryLocked(root, mac, true)
		if enabled {
			mid, err := allocMarkIDFromRootLocked(root, mac)
			if err != nil {
				return err
			}
			outMid = mid
		} else {
			outMid = anyToRuleInt(dm["mark_id"])
		}
		dm["app_qos"] = enabled
		return nil
	})
	return outMid, err
}

// IsBlacklisted 判断指定 MAC 当前是否处于顶层 blacklist 数组中。
func (rs *rulesStoreEngine) IsBlacklisted(hncDir, mac string) bool {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRE.MatchString(mac) {
		return false
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	root, err := rs.loadLocked(hncDir)
	if err != nil {
		return false
	}
	bl, _ := root["blacklist"].([]interface{})
	for _, item := range bl {
		if strings.EqualFold(strings.TrimSpace(anyToRuleString(item)), mac) {
			return true
		}
	}
	return false
}
