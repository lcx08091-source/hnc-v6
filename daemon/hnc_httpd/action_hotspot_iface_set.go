package main

import "strings"

// rc30.12.30 (P2.11): merged from hotfix16_7_compile_compat.go.
// 之前文件名按 "修第 N 个 bug" 命名 (patch 思维), 应当按功能命名.
// 跟 action_app_limit.go / action_device_rename.go / action_sqm_v53.go 风格对齐.

// requestSnapshotRefresh: compile compatibility shim (originally hotfix16.7).
// 一些 hotfix16.6 合并的代码会调用这个函数, 但这个分支没有完整的 snapshot cache
// 实现. 留成 no-op 让写 actions 能编/能跑.
func (s *server) requestSnapshotRefresh() {
	// no-op
}

// actionHotspotIfaceSet writes the preferred hotspot interface to rules.json.
// iface="" or "auto" means automatic detection.
func actionHotspotIfaceSet(hncDir string, p map[string]string) actionResp {
	iface := strings.TrimSpace(p["iface"])
	if iface == "auto" {
		iface = ""
	}

	if iface != "" {
		if len(iface) > 15 {
			return actionResp{OK: false, Error: "bad params", Detail: "iface too long"}
		}
		for _, c := range iface {
			if !((c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') ||
				c == '_' || c == '-' || c == '.') {
				return actionResp{OK: false, Error: "bad params", Detail: "invalid iface name"}
			}
		}
	}

	rc, out := runBin(hncDir, "json_set.sh", "top", "hotspot_iface", iface)
	if rc != 0 {
		return actionResp{OK: false, Error: "write failed", Detail: strings.TrimSpace(out)}
	}

	if iface == "" {
		return actionResp{OK: true, Detail: "hotspot iface set to auto"}
	}
	return actionResp{OK: true, Detail: "preferred hotspot iface set to " + iface}
}
