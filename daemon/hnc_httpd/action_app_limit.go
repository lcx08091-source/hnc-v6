// rc30.6: per-application rate limit configuration actions.
//
// Storage strategy: a canonical JSON file for round-tripping and inspection,
// plus a flat companion file consumed by apply_app_limits.sh (the shell
// tool that writes the actual iptables MARK + tc class rules). Two formats
// instead of one because Android shells lack jq and parsing JSON in awk is
// fragile.
//
// JSON layout (data/app_limits.json):
//   {
//     "version": 1,
//     "items": [
//       {"mac": "aa:bb:cc:dd:ee:01", "app_id": "douyin", "down_mbps": 1.0}
//     ]
//   }
//
// Flat layout (data/app_limits.flat), one line per entry:
//   <mac> <app_id> <down_mbps>
//
// Actions:
//   app_limit_set    {mac, app_id, down_mbps}   set / replace
//   app_limit_clear  {mac, app_id?}             clear one or all for a mac
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	appLimitsJSONRelPath = "data/app_limits.json"
	appLimitsFlatRelPath = "data/app_limits.flat"
)

type AppLimitItem struct {
	MAC      string  `json:"mac"`
	AppID    string  `json:"app_id"`
	DownMbps float64 `json:"down_mbps"`
}

type AppLimitFile struct {
	Version int            `json:"version"`
	Items   []AppLimitItem `json:"items"`
}

var appLimitMu sync.Mutex

// actionAppLimitSet adds or replaces a (mac, app_id) → down_mbps entry.
//   mac:     canonical aa:bb:cc:dd:ee:ff (lowercase or upper accepted)
//   app_id:  classifier rule ID (e.g. "douyin", "weixin")
//   down_mbps: target downlink in Mbps, 0 = clear
func actionAppLimitSet(hncDir string, p map[string]string) actionResp {
	mac := canonMAC(p["mac"])
	if mac == "" {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	appID := strings.TrimSpace(p["app_id"])
	if !validAppID(appID) {
		return actionResp{OK: false, Error: "bad params", Detail: "app_id must be 1-32 chars, [a-z0-9_-]"}
	}
	rateStr := strings.TrimSpace(p["down_mbps"])
	rate, err := strconv.ParseFloat(rateStr, 64)
	if err != nil || rate < 0 || rate > 10000 {
		return actionResp{OK: false, Error: "bad params", Detail: "down_mbps must be 0..10000"}
	}

	appLimitMu.Lock()
	defer appLimitMu.Unlock()

	file := loadAppLimits(hncDir)
	// Replace if exists, else append.
	found := false
	for i := range file.Items {
		if file.Items[i].MAC == mac && file.Items[i].AppID == appID {
			file.Items[i].DownMbps = rate
			found = true
			break
		}
	}
	if !found {
		if rate == 0 {
			// Nothing to clear and nothing to set.
			return actionResp{OK: true, Detail: "no-op (rate=0 and no existing entry)"}
		}
		file.Items = append(file.Items, AppLimitItem{MAC: mac, AppID: appID, DownMbps: rate})
	}
	// Rate=0 means: clear this entry.
	if rate == 0 {
		filtered := file.Items[:0]
		for _, it := range file.Items {
			if !(it.MAC == mac && it.AppID == appID) {
				filtered = append(filtered, it)
			}
		}
		file.Items = filtered
	}
	if err := saveAppLimits(hncDir, file); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	// Kick the shell limiter to apply now instead of waiting for the next
	// watchdog tick. Non-fatal if missing.
	go triggerAppLimitApply(hncDir)
	if rate == 0 {
		return actionResp{OK: true, Detail: fmt.Sprintf("cleared %s/%s", mac, appID)}
	}
	return actionResp{OK: true, Detail: fmt.Sprintf("set %s/%s = %.2f Mbps", mac, appID, rate)}
}

// actionAppLimitClear removes one or all app limits for a MAC.
//   mac:     required
//   app_id:  optional. Empty = clear all entries for this MAC.
func actionAppLimitClear(hncDir string, p map[string]string) actionResp {
	mac := canonMAC(p["mac"])
	if mac == "" {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	appID := strings.TrimSpace(p["app_id"])

	appLimitMu.Lock()
	defer appLimitMu.Unlock()

	file := loadAppLimits(hncDir)
	before := len(file.Items)
	filtered := file.Items[:0]
	for _, it := range file.Items {
		if it.MAC != mac {
			filtered = append(filtered, it)
			continue
		}
		if appID != "" && it.AppID != appID {
			filtered = append(filtered, it)
		}
	}
	file.Items = filtered
	if err := saveAppLimits(hncDir, file); err != nil {
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	removed := before - len(file.Items)
	go triggerAppLimitApply(hncDir)
	return actionResp{OK: true, Detail: fmt.Sprintf("cleared %d entry(s)", removed)}
}

// loadAppLimits reads the JSON file. Returns an empty file struct when
// the file is missing or malformed.
func loadAppLimits(hncDir string) AppLimitFile {
	path := filepath.Join(hncDir, appLimitsJSONRelPath)
	out := AppLimitFile{Version: 1, Items: []AppLimitItem{}}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var f AppLimitFile
	if err := json.Unmarshal(b, &f); err != nil {
		return out
	}
	if f.Items == nil {
		f.Items = []AppLimitItem{}
	}
	return f
}

// saveAppLimits writes BOTH the canonical JSON and the flat shell-readable
// companion file. Atomic via tmp+rename.
// saveAppLimits 原子提交两份文件 (JSON + flat).
//
// rc30.12.14: 改成事务式提交 - 两个 .tmp 都写成功后, 才依次 rename.
// 老逻辑 JSON 先 rename, flat 写失败 return nil (best-effort), 导致两份文件不一致 -
// 配置 "显示成功" 但 shell 限速读 flat 仍是旧值, UI 与实际行为脱节.
func saveAppLimits(hncDir string, file AppLimitFile) error {
	if err := os.MkdirAll(filepath.Join(hncDir, "data"), 0o755); err != nil {
		return err
	}
	file.Version = 1

	// 1) 准备 JSON 数据
	jb, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	// 2) 准备 flat 数据
	var flat []byte
	for _, it := range file.Items {
		if it.DownMbps <= 0 {
			continue
		}
		flat = append(flat, []byte(fmt.Sprintf("%s %s %g\n", it.MAC, it.AppID, it.DownMbps))...)
	}

	// 3) 两份 tmp 都写到磁盘
	jpath := filepath.Join(hncDir, appLimitsJSONRelPath)
	fpath := filepath.Join(hncDir, appLimitsFlatRelPath)
	jtmp := jpath + ".tmp"
	ftmp := fpath + ".tmp"

	if err := os.WriteFile(jtmp, jb, 0o644); err != nil {
		return fmt.Errorf("write json tmp: %w", err)
	}
	if err := os.WriteFile(ftmp, flat, 0o644); err != nil {
		_ = os.Remove(jtmp) // 回滚 JSON tmp
		return fmt.Errorf("write flat tmp: %w", err)
	}

	// 4) 两个 tmp 都成功 → 依次 rename. JSON 先 rename 因为读者用 JSON, flat 是 shell 用的次要副本.
	//    rename 是 POSIX 原子操作, 两步之间窗口极短.
	if err := os.Rename(jtmp, jpath); err != nil {
		_ = os.Remove(jtmp)
		_ = os.Remove(ftmp)
		return fmt.Errorf("rename json: %w", err)
	}
	if err := os.Rename(ftmp, fpath); err != nil {
		// JSON 已经 commit, flat rename 失败. 不删 JSON (它是 source of truth).
		// 报错让上层知道 flat 落后, 下次 saveAppLimits 会重新写.
		_ = os.Remove(ftmp)
		return fmt.Errorf("rename flat (json committed, flat lagged): %w", err)
	}
	return nil
}

// triggerAppLimitApply touches a marker file the watchdog can poll, so
// the next tick applies fresh rules without waiting up to 30s.
//
// rc30.12.14: 从 os.Create 改成 WriteFile, 不留 FD 悬挂.
// (老代码 _, _ = os.Create(marker) 返回 *os.File 但没 Close, 长期运行积累 FD 泄漏)
func triggerAppLimitApply(hncDir string) {
	marker := filepath.Join(hncDir, "run", "app_limit.dirty")
	_ = os.MkdirAll(filepath.Dir(marker), 0o755)
	_ = os.WriteFile(marker, []byte{}, 0o644)
}

// rc30.6: read current app rate limit config. Mirrors data/app_limits.json
// but in a stable shape for WebUI consumption.
//   GET /api/app_limits
//   → {"ok":true,"items":[{"mac":"...","app_id":"...","down_mbps":1.0}, ...]}
func (s *server) apiAppLimits(w http.ResponseWriter, r *http.Request) {
	file := loadAppLimits(s.hncDir)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":    true,
		"items": file.Items,
	})
}

func canonMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 17 {
		return ""
	}
	for i, c := range s {
		switch i {
		case 2, 5, 8, 11, 14:
			if c != ':' && c != '-' {
				return ""
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return ""
			}
		}
	}
	return strings.ReplaceAll(s, "-", ":")
}

func validAppID(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
