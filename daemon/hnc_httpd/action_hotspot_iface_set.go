package main

import "strings"

// action_hotspot_iface_set.go — 热点网卡手动指定与自动探测偏好写入

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
