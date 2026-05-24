package main

import "strings"

// actionGlobalShaperSet · rc32 全局带宽整形器 (opt-in, 默认关)
//
// params:
//
//	enabled   required: true|1|on | false|0|off
//	rate_down optional (enabled 时至少一个方向): "<n>mbit"/"<n>kbit" — WAN 下行带宽
//	rate_up   optional: WAN 上行带宽
//
// 给整个热点的 HTB 父类 1:1 设 WAN 带宽 ceil + 默认类挂 AQM 叶子,让总流量受 WAN
// 瓶颈管,AQM 才压得住 bufferbloat。手动填带宽、默认关 → 不用的人零风险。状态持久化
// 到 rules.json 顶层 global_shaper_enabled/down/up,restore_rules 重启后据此恢复。
//
// 诚实边界:固定 ceil 对蜂窝(速率乱跳)效果有限;最适合稳定链路(WiFi 中继 / 固定
// WISP / 光猫)。这是设计如此,不是 bug —— UI 文案已注明。
func actionGlobalShaperSet(hncDir string, p map[string]string) actionResp {
	enabled := false
	switch strings.TrimSpace(strings.ToLower(p["enabled"])) {
	case "true", "1", "on", "yes":
		enabled = true
	case "false", "0", "off", "no", "":
		enabled = false
	default:
		return actionResp{OK: false, Error: "bad params", Detail: "enabled must be true/false"}
	}

	if !enabled {
		// 关:复位 1:1 ceil 回 DEFAULT_RATE,并落 flag。即便没热点接口也把 flag 清掉,
		// 免得 restore_rules 下次又把它拉起来。
		_, out := runBin(hncDir, "device_detect.sh", "iface")
		iface := strings.TrimSpace(out)
		if iface != "" {
			if rc2, out2 := runBin(hncDir, "tc_manager.sh", "global_shaper", iface, "off", "0", "0"); rc2 != 0 {
				return actionResp{OK: false, Error: "shaper apply failed", Detail: strings.TrimSpace(out2)}
			}
		}
		runBin(hncDir, "json_set.sh", "top", "global_shaper_enabled", "false")
		return actionResp{OK: true, Detail: "global shaper off"}
	}

	// 开:需要 HTB。capabilities.json 权威, tc_htb=false 直接拒(别卡在 shell/tc 路径)。
	if supported, known := tcHTBSupported(hncDir); known && !supported {
		return actionResp{OK: false, Error: "unsupported", Detail: "tc_htb=false; 全局整形需要 HTB"}
	}

	rateDown := strings.TrimSpace(p["rate_down"])
	rateUp := strings.TrimSpace(p["rate_up"])
	if rateDown == "" {
		rateDown = "0"
	}
	if rateUp == "" {
		rateUp = "0"
	}
	// validateRate 允许 "0"(= 该方向不整形),其余必须合法且 >= 最小速率。
	if err := validateRate(rateDown); err != nil {
		return actionResp{OK: false, Error: "bad params", Detail: "rate_down: " + err.Error()}
	}
	if err := validateRate(rateUp); err != nil {
		return actionResp{OK: false, Error: "bad params", Detail: "rate_up: " + err.Error()}
	}
	if rateDown == "0" && rateUp == "0" {
		return actionResp{OK: false, Error: "bad params", Detail: "enabled 时至少一个方向带宽 > 0"}
	}

	_, out := runBin(hncDir, "device_detect.sh", "iface")
	iface := strings.TrimSpace(out)
	if iface == "" {
		return actionResp{OK: false, Error: "no hotspot iface", Detail: "热点未开启,无法应用全局整形"}
	}

	if rc2, out2 := runBin(hncDir, "tc_manager.sh", "global_shaper", iface, "on", rateDown, rateUp); rc2 != 0 {
		return actionResp{OK: false, Error: "shaper apply failed", Detail: strings.TrimSpace(out2)}
	}
	// 持久化(先写参数, 最后写 enabled, 让 restore 永远读到一致快照)。
	runBin(hncDir, "json_set.sh", "top", "global_shaper_down", rateDown)
	runBin(hncDir, "json_set.sh", "top", "global_shaper_up", rateUp)
	if rcW, outW := runBin(hncDir, "json_set.sh", "top", "global_shaper_enabled", "true"); rcW != 0 {
		return actionResp{OK: false, Error: "rules.json write failed", Detail: strings.TrimSpace(outW)}
	}
	return actionResp{OK: true, Detail: "global shaper on down=" + rateDown + " up=" + rateUp}
}
