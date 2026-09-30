// offload_guard.go — v5.18 tether offload 旁路兜底(bin/hnc_offload_guard.sh)的 httpd 侧读取
//
// 设计与理由见 bin/hnc_offload_guard.sh 文件头。这里只负责:
//   - 从 rules.json 解析生效模式(clsact_bpf_mode, 旧键兼容)
//   - 读 run/offload_guard.json 透出给 /api/config 与 /api/offload_status
//   - 给 OffloadLoop 复用 guard 的新鲜采样, 避免重复跑 check_offload.sh

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// clsactModeFromRules 生效模式: clsact_bpf_mode ∈ {auto,on,off} 优先;
// 缺失/非法时旧键 clsact_bpf_enabled=true → on, 否则 auto。
func clsactModeFromRules(m map[string]interface{}) string {
	if v, ok := m["clsact_bpf_mode"].(string); ok {
		switch v = strings.ToLower(strings.TrimSpace(v)); v {
		case "auto", "on", "off":
			return v
		}
	}
	if boolField(m, "clsact_bpf_enabled") {
		return "on"
	}
	return "auto"
}

func offloadGuardPath(hncDir string) string {
	return filepath.Join(hncDir, "run", "offload_guard.json")
}

// readOffloadGuard 解析状态文件; 不存在/损坏返回 nil(JSON 输出 null)
func readOffloadGuard(hncDir string) map[string]interface{} {
	b, err := os.ReadFile(offloadGuardPath(hncDir))
	if err != nil || len(b) == 0 {
		return nil
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

// offloadGuardFreshState guard 在 maxAge 内采样过且结果是 check_offload 的
// 四态之一时返回该状态词。
func offloadGuardFreshState(hncDir string, maxAge time.Duration) (string, bool) {
	m := readOffloadGuard(hncDir)
	if m == nil {
		return "", false
	}
	lc, _ := m["last_check"].(float64)
	if lc <= 0 || time.Since(time.Unix(int64(lc), 0)) > maxAge {
		return "", false
	}
	st, _ := m["offload_state"].(string)
	switch st {
	case "NOMAP", "IDLE", "CAPABLE", "ACTIVE":
		return st, true
	}
	return "", false
}
