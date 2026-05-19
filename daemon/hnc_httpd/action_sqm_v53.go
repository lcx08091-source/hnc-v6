package main

import "strings"

// actionSQMSet · v5.3.0-rc10
// params:
//
//	mode    optional: off | fq_codel | cake | auto | game
//	profile optional: balanced | game | bulk | custom
//	preset  optional: off | balanced | game | weaknet | poor | extreme | custom
//	apply   optional: true/false, whether to ask sqm_manager for incremental default-leaf apply
//
// The shell manager performs the actual persistence so Go, KSU WebUI and adb
// diagnostics keep identical semantics. Invalid values are rejected before shell.
// v5.3.0-rc10: apply is still incremental; if hotspot iface is absent,
// sqm_manager returns success with a saved-for-later status instead of surfacing
// a generic SQM apply failure.
func actionSQMSet(hncDir string, p map[string]string) actionResp {
	mode := strings.TrimSpace(strings.ToLower(p["mode"]))
	profile := strings.TrimSpace(strings.ToLower(p["profile"]))
	preset := strings.TrimSpace(strings.ToLower(p["preset"]))
	apply := strings.TrimSpace(strings.ToLower(p["apply"]))

	if mode == "" && profile == "" && preset == "" && apply == "" {
		return actionResp{OK: false, Error: "bad params", Detail: "one of mode/profile/preset/apply is required"}
	}

	details := []string{}
	if mode != "" {
		switch mode {
		case "off", "fq_codel", "fq-codel", "fqcodel", "cake", "auto", "game":
		default:
			return actionResp{OK: false, Error: "bad params", Detail: "invalid sqm mode"}
		}
		rc, out := runBin(hncDir, "sqm_manager.sh", "set-mode", mode)
		if rc != 0 {
			return actionResp{OK: false, Error: "sqm set-mode failed", Detail: strings.TrimSpace(out)}
		}
		details = append(details, "mode="+mode)
	}

	if profile != "" {
		switch profile {
		case "balanced", "game", "bulk", "custom":
		default:
			return actionResp{OK: false, Error: "bad params", Detail: "invalid sqm profile"}
		}
		rc, out := runBin(hncDir, "sqm_manager.sh", "set-profile", profile)
		if rc != 0 {
			return actionResp{OK: false, Error: "sqm set-profile failed", Detail: strings.TrimSpace(out)}
		}
		details = append(details, "profile="+profile)
	}

	if preset != "" {
		switch preset {
		case "off", "balanced", "game", "weaknet", "weak-net", "weak", "poor", "bad", "extreme", "custom":
		default:
			return actionResp{OK: false, Error: "bad params", Detail: "invalid sqm preset"}
		}
		rc, out := runBin(hncDir, "sqm_manager.sh", "set-preset", preset)
		if rc != 0 {
			return actionResp{OK: false, Error: "sqm set-preset failed", Detail: strings.TrimSpace(out)}
		}
		details = append(details, "preset="+preset)
	}

	switch apply {
	case "", "false", "0", "no":
		// no-op
	case "true", "1", "yes":
		rc, out := runBin(hncDir, "sqm_manager.sh", "apply")
		if rc != 0 {
			return actionResp{OK: false, Error: "sqm apply failed", Detail: strings.TrimSpace(out)}
		}
		details = append(details, "applied")
	default:
		return actionResp{OK: false, Error: "bad params", Detail: "apply must be true/false"}
	}

	return actionResp{OK: true, Detail: strings.Join(details, "; ")}
}
