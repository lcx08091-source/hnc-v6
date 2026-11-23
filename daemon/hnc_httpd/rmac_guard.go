// rmac_guard.go — HNC v5.38.0: 随机 MAC 高置信度无感继承 + 短命随机 MAC 槽位回收 + 客户端互访隔离
// (v5.38.0 移除陌生新随机 MAC 默认限速/默认隔离护栏，避免新连入设备被误限速或隔离；升级时自动解除旧护栏残留)
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hnc.io/dpid/alert"
)

const (
	rmacAutoInheritedMax = 1024
	rmacAutoInheritedTTL = int64(90 * 86400)
)

type rmacPolicy struct {
	AutoInherit        bool `json:"auto_inherit"`
	AutoInheritScore   int  `json:"auto_inherit_score"`
	ClientIsolation    bool `json:"client_isolation"`
	EphemeralGCMinutes int  `json:"ephemeral_gc_minutes"`
}

type rmacAutoInheritRec struct {
	OldMAC  string `json:"old_mac"`
	OldName string `json:"old_name,omitempty"`
	Score   int    `json:"score"`
	Ts      int64  `json:"ts"`
}

type rmacGuardEntry struct {
	Mode      string `json:"mode"`
	AppliedAt int64  `json:"applied_at"`
	LastSeen  int64  `json:"last_seen"`
}

type rmacStateFile struct {
	Version       int                           `json:"version"`
	AutoInherited map[string]rmacAutoInheritRec `json:"auto_inherited,omitempty"`
	Guarded       map[string]rmacGuardEntry     `json:"guarded,omitempty"` // 仅用于 v5.37 旧版残留自动清理
}

var (
	rmacMu        sync.Mutex
	rmacFlushedLS = map[string]map[string]int64{} // hncDir -> (offline random mac -> flushed last_seen 水位)
)

func defaultRMACPolicy() rmacPolicy {
	return rmacPolicy{
		AutoInherit:        true,
		AutoInheritScore:   85,
		ClientIsolation:    false,
		EphemeralGCMinutes: 30,
	}
}

func normalizeRMACPolicy(p rmacPolicy) rmacPolicy {
	if p.AutoInheritScore < 65 || p.AutoInheritScore > 100 {
		p.AutoInheritScore = 85
	}
	if p.EphemeralGCMinutes < 5 || p.EphemeralGCMinutes > 1440 {
		p.EphemeralGCMinutes = 30
	}
	return p
}

func rmacPolicyPath(hncDir string) string {
	return filepath.Join(hncDir, "data", "rmac_policy.json")
}

func rmacStatePath(hncDir string) string {
	return filepath.Join(hncDir, "data", "rmac_guard_state.json")
}

func loadRMACPolicy(hncDir string) rmacPolicy {
	def := defaultRMACPolicy()
	b, err := os.ReadFile(rmacPolicyPath(hncDir))
	if err != nil {
		return def
	}
	var p rmacPolicy
	if json.Unmarshal(b, &p) != nil {
		return def
	}
	return normalizeRMACPolicy(p)
}

func saveRMACPolicy(hncDir string, p rmacPolicy) error {
	p = normalizeRMACPolicy(p)
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return discoverWriteAtomic(rmacPolicyPath(hncDir), append(b, '\n'))
}

// pruneRMACAutoInherited 按 90 天 TTL 与 1024 条容量上限裁剪 AutoInherited, 返回是否有变动。
func pruneRMACAutoInherited(m map[string]rmacAutoInheritRec, now int64) bool {
	if len(m) == 0 {
		return false
	}
	changed := false
	if now > 0 {
		for k, rec := range m {
			if rec.Ts > 0 && now-rec.Ts > rmacAutoInheritedTTL {
				delete(m, k)
				changed = true
			}
		}
	}
	if len(m) > rmacAutoInheritedMax {
		type kv struct {
			mac string
			ts  int64
		}
		all := make([]kv, 0, len(m))
		for k, rec := range m {
			all = append(all, kv{mac: k, ts: rec.Ts})
		}
		sort.Slice(all, func(i, j int) bool {
			if all[i].ts != all[j].ts {
				return all[i].ts < all[j].ts
			}
			return all[i].mac < all[j].mac
		})
		drop := len(m) - rmacAutoInheritedMax
		for i := 0; i < drop; i++ {
			delete(m, all[i].mac)
		}
		changed = true
	}
	return changed
}

func loadRMACState(hncDir string) rmacStateFile {
	st := rmacStateFile{
		Version:       2,
		AutoInherited: map[string]rmacAutoInheritRec{},
		Guarded:       map[string]rmacGuardEntry{},
	}
	b, err := os.ReadFile(rmacStatePath(hncDir))
	if err != nil {
		return st
	}
	_ = json.Unmarshal(b, &st)
	if st.AutoInherited == nil {
		st.AutoInherited = map[string]rmacAutoInheritRec{}
	}
	if st.Guarded == nil {
		st.Guarded = map[string]rmacGuardEntry{}
	}
	return st
}

func saveRMACState(hncDir string, st rmacStateFile) {
	st.Version = 2
	if st.AutoInherited != nil {
		pruneRMACAutoInherited(st.AutoInherited, time.Now().Unix())
	}
	if b, err := json.Marshal(st); err == nil {
		_ = discoverWriteAtomic(rmacStatePath(hncDir), b)
	}
}

func saveRMACStateAt(hncDir string, st rmacStateFile, now int64) {
	st.Version = 2
	if st.AutoInherited != nil {
		pruneRMACAutoInherited(st.AutoInherited, now)
	}
	if b, err := json.Marshal(st); err == nil {
		_ = discoverWriteAtomic(rmacStatePath(hncDir), b)
	}
}

// rmacReconcile 在后台 MacMergeLoop 周期内执行:
//  0. 自动解除旧版本遗留的陌生随机 MAC 默认限速/隔离护栏, 并裁剪过期 AutoInherited;
//     0.5 旧 MAC 重新上线自动无损秒拆(核验合并后真实重连水位);
//  1. 高置信度随机 MAC 自动无感继承(旧设备离线 + 未命中 MutexApart + 综合评分 >= auto_inherit_score);
//  2. 离线短命无规则随机 MAC 自动清理陈旧邻居与记录, 防止 /24 租约池膨胀。
func (s *server) rmacReconcile(now time.Time) {
	pol := loadRMACPolicy(s.hncDir)
	nowU := now.Unix()

	// 0. 自动清理 v5.37 遗留的默认限速/隔离护栏状态 + AutoInherited 30 天长稳裁剪(1024 上限 / 90 天 TTL)
	rmacMu.Lock()
	st0 := loadRMACState(s.hncDir)
	legacyGuarded := make(map[string]rmacGuardEntry, len(st0.Guarded))
	for m, g := range st0.Guarded {
		legacyGuarded[m] = g
	}
	if len(legacyGuarded) == 0 && pruneRMACAutoInherited(st0.AutoInherited, nowU) {
		saveRMACStateAt(s.hncDir, st0, nowU)
	}
	rmacMu.Unlock()
	if len(legacyGuarded) > 0 {
		for mac, g := range legacyGuarded {
			s.actionMu.Lock()
			if g.Mode == "quarantine" {
				_ = actionBLDel(s.hncDir, map[string]string{"mac": mac})
			} else {
				_ = actionRuleClear(s.hncDir, map[string]string{"mac": mac})
			}
			s.actionMu.Unlock()
		}
		rmacMu.Lock()
		stClean := loadRMACState(s.hncDir)
		stClean.Guarded = nil
		pruneRMACAutoInherited(stClean.AutoInherited, nowU)
		saveRMACStateAt(s.hncDir, stClean, nowU)
		rmacMu.Unlock()
	}

	devsRaw := readJSONMap(filepath.Join(s.hncDir, "data", "devices.json"))
	onlineIP := map[string]string{}
	lastSeenMap := map[string]int64{}
	bytesMap := map[string]int64{}
	for m, v := range devsRaw {
		dm, _ := v.(map[string]interface{})
		if dm == nil {
			continue
		}
		mac := strings.ToLower(strings.TrimSpace(m))
		ls, _ := toInt64(dm["last_seen"])
		rx, _ := toInt64(dm["rx_bytes"])
		tx, _ := toInt64(dm["tx_bytes"])
		if rx < 0 {
			rx = 0
		}
		if tx < 0 {
			tx = 0
		}
		lastSeenMap[mac] = ls
		bytesMap[mac] = rx + tx
		if ip := strings.TrimSpace(asString(dm["ip"])); ip != "" && (ls == 0 || nowU-ls <= 120) {
			onlineIP[mac] = ip
		}
	}

	// 0.5 旧 MAC 重新上线自动无损秒拆: 先用内存缓存别名表零磁盘快筛 onlineIP[oldMAC] != ""
	{
		fastAliases := loadMACAliases(s.hncDir)
		var onlineMergedOld []string
		for oldMAC := range fastAliases {
			if onlineIP[oldMAC] != "" {
				onlineMergedOld = append(onlineMergedOld, oldMAC)
			}
		}
		if len(onlineMergedOld) > 0 {
			sort.Strings(onlineMergedOld)
			for _, oldMAC := range onlineMergedOld {
				toMAC := resolveMACAlias(fastAliases, fastAliases[oldMAC])
				arch := findMacMergeArchive(s.hncDir, oldMAC, toMAC, nowU)
				if arch == nil {
					continue
				}
				ls := lastSeenMap[oldMAC]
				curBytes := bytesMap[oldMAC]
				reconnected := !arch.OldInDevicesAtMerge ||
					(ls > arch.OldLastSeenAtMerge && ls > arch.MergedAt) ||
					(arch.OldBytesAtMerge > 0 && curBytes > arch.OldBytesAtMerge)
				if !reconnected {
					continue
				}
				oldName := arch.FromName
				if oldName == "" {
					oldName = arch.FromSnap.DeviceName
				}
				if oldName == "" {
					oldName = oldMAC
				}
				toName := arch.ToName
				if toName == "" {
					toName = toMAC
				}
				s.actionMu.Lock()
				_, err := s.deviceUnmerge(oldMAC, toMAC, true, now)
				s.actionMu.Unlock()
				if err == nil {
					cfg := alert.NewConfig(s.hncDir)
					if alert.LoadConfig(cfg.AlertsConfigPath).Enabled {
						_ = alert.Append(cfg.AlertsJSONLPath, alert.Alert{
							ID:     "mac_merge_unmerge_auto_" + strings.ReplaceAll(oldMAC, ":", "") + "_" + strconv.FormatInt(nowU, 10),
							Ts:     nowU,
							Kind:   "mac_merge_unmerge_auto",
							MAC:    oldMAC,
							Detail: fmt.Sprintf("检测到被合并的旧设备「%s」(%s)重新连入热点活跃，已自动无损拆分与「%s」(%s)的合并并恢复双方设置", oldName, oldMAC, toName, toMAC),
							Extra: map[string]interface{}{
								"from_mac": oldMAC, "to_mac": toMAC,
								"old_mac": oldMAC, "new_mac": toMAC,
								"from_name": oldName, "to_name": toName,
							},
						})
					}
				}
			}
		}
	}

	// 1. 高置信度无感继承
	if pol.AutoInherit {
		macMergeMu.Lock()
		mf := loadMacMergeFile(s.hncDir)
		macMergeMu.Unlock()
		cachedAliases := loadMACAliases(s.hncDir)
		aliases := make(map[string]string, len(cachedAliases))
		for k, v := range cachedAliases {
			aliases[k] = v
		}
		names, _ := loadDeviceNames(filepath.Join(s.hncDir, deviceNamesRelPath))

		for newMAC, cands := range mf.Suggestions {
			if len(cands) == 0 || onlineIP[newMAC] == "" || !isRandomizedMAC(newMAC) {
				continue
			}
			best := cands[0]
			if best.Score < pol.AutoInheritScore || onlineIP[best.OldMAC] != "" {
				continue
			}
			if _, gone := aliases[newMAC]; gone {
				continue
			}
			if _, gone := aliases[best.OldMAC]; gone {
				continue
			}
			if _, dis := mf.Dismissed[macMergeDismissKey(newMAC, best.OldMAC)]; dis {
				continue
			}
			if isMacMutexApart(mf, newMAC, best.OldMAC, nowU) {
				continue
			}
			oldName := macDisplayName(names, mf, best.OldMAC)
			s.actionMu.Lock()
			_, err := s.deviceMerge(best.OldMAC, newMAC, true, now)
			s.actionMu.Unlock()
			if err == nil {
				aliases[best.OldMAC] = newMAC
				rmacMu.Lock()
				st := loadRMACState(s.hncDir)
				st.AutoInherited[newMAC] = rmacAutoInheritRec{
					OldMAC:  best.OldMAC,
					OldName: oldName,
					Score:   best.Score,
					Ts:      nowU,
				}
				saveRMACStateAt(s.hncDir, st, nowU)
				rmacMu.Unlock()

				cfg := alert.NewConfig(s.hncDir)
				if alert.LoadConfig(cfg.AlertsConfigPath).Enabled {
					_ = alert.Append(cfg.AlertsJSONLPath, alert.Alert{
						ID:     "rmac_auto_inherit_" + strings.ReplaceAll(newMAC, ":", ""),
						Ts:     nowU,
						Kind:   "mac_merge_auto",
						MAC:    newMAC,
						Detail: fmt.Sprintf("设备更换随机 MAC 后已无感自动继承「%s」(置信度 %d)", oldName, best.Score),
					})
				}
			}
		}
	}

	// 2. 离线短命无规则随机 MAC 邻居清理(仅清理无手工命名、无持久化限速/黑名单的过期 STALE/FAILED 邻居)
	// 对同一批已 flush 的离线随机 MAC 按 last_seen 记录水位, 防止 devices.json 保留旧条目时每轮无限 fork ip neigh flush。
	gcSec := int64(pol.EphemeralGCMinutes) * 60
	toFlush := map[string]int64{}
	rmacMu.Lock()
	flushed := rmacFlushedLS[s.hncDir]
	if flushed != nil {
		for mac := range flushed {
			if _, exists := lastSeenMap[mac]; !exists || onlineIP[mac] != "" {
				delete(flushed, mac)
			}
		}
	}
	for mac, ls := range lastSeenMap {
		if onlineIP[mac] != "" || !isRandomizedMAC(mac) || isSimMACPrefix(mac) {
			continue
		}
		if ls > 0 && nowU-ls >= gcSec {
			if flushed == nil || flushed[mac] != ls {
				toFlush[mac] = ls
			}
		}
	}
	rmacMu.Unlock()
	if len(toFlush) > 0 {
		if ap := s.currentHotspotIface(); ap != "" {
			_, _ = calRunCmd(3*time.Second, "ip", "neigh", "flush", "dev", ap, "nud", "stale")
			_, _ = calRunCmd(3*time.Second, "ip", "neigh", "flush", "dev", ap, "nud", "failed")
			rmacMu.Lock()
			if rmacFlushedLS[s.hncDir] == nil {
				rmacFlushedLS[s.hncDir] = map[string]int64{}
			}
			for mac, ls := range toFlush {
				rmacFlushedLS[s.hncDir][mac] = ls
			}
			rmacMu.Unlock()
		}
	}
}

func actionRMACPolicySet(s *server, p map[string]string) actionResp {
	cur := loadRMACPolicy(s.hncDir)
	if v, ok := p["auto_inherit"]; ok && strings.TrimSpace(v) != "" {
		b, valid := parseBoolStr(v)
		if !valid {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid auto_inherit"}
		}
		cur.AutoInherit = b
	}
	if v := strings.TrimSpace(p["auto_inherit_score"]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 65 || n > 100 {
			return actionResp{OK: false, Error: "bad params", Detail: "auto_inherit_score must be 65..100"}
		}
		cur.AutoInheritScore = n
	}
	if v := strings.TrimSpace(p["ephemeral_gc_minutes"]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 5 || n > 1440 {
			return actionResp{OK: false, Error: "bad params", Detail: "ephemeral_gc_minutes must be 5..1440"}
		}
		cur.EphemeralGCMinutes = n
	}
	if v, ok := p["client_isolation"]; ok && strings.TrimSpace(v) != "" {
		b, valid := parseBoolStr(v)
		if !valid {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid client_isolation"}
		}
		cur.ClientIsolation = b
		_, _ = runBin(s.hncDir, "json_set.sh", "top", "client_isolation_enabled", map[bool]string{true: "true", false: "false"}[b])
		if ap := s.currentHotspotIface(); ap != "" {
			_, _ = runBin(s.hncDir, "iptables_manager.sh", "set_isolation", ap, map[bool]string{true: "on", false: "off"}[b])
		}
	}
	cur = normalizeRMACPolicy(cur)
	if err := saveRMACPolicy(s.hncDir, cur); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	go s.rmacReconcile(time.Now())
	return actionResp{OK: true, Detail: "rmac policy saved"}
}

// actionRMACTrust 保留兼容入口(幂等标记为已知设备)
func actionRMACTrust(s *server, p map[string]string) actionResp {
	mac := strings.ToLower(strings.TrimSpace(p["mac"]))
	if !validMAC(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	_ = actionAlertMarkKnown(s.hncDir, map[string]string{"mac": mac})
	return actionResp{OK: true, Detail: "known " + mac}
}

func actionClientIsolationSet(s *server, p map[string]string) actionResp {
	en, ok := parseEnabledParam(p)
	if !ok {
		return actionResp{OK: false, Error: "bad params", Detail: "enabled required"}
	}
	p2 := map[string]string{"client_isolation": map[bool]string{true: "true", false: "false"}[en]}
	return actionRMACPolicySet(s, p2)
}

func (s *server) annotateRMACGuard(rows []map[string]interface{}) {
	var autoInh map[string]interface{}
	if raw, err := s.jsonCache.read(rmacStatePath(s.hncDir)); err == nil {
		if root, ok := raw.(map[string]interface{}); ok {
			autoInh, _ = root["auto_inherited"].(map[string]interface{})
		}
	}
	for _, d := range rows {
		mac := strings.ToLower(asString(d["mac"]))
		if autoInh != nil {
			if rec, ok := autoInh[mac].(map[string]interface{}); ok && rec != nil {
				d["auto_inherited_from"] = asString(rec["old_mac"])
				d["auto_inherited_name"] = asString(rec["old_name"])
				if sc, ok2 := toInt64(rec["score"]); ok2 {
					d["auto_inherited_score"] = sc
				}
			}
		}
	}
}
