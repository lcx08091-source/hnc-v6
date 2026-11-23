package main

import (
	"strings"
	"time"
)

// actionGlobalShaperSet · 全局静态带宽整形器 (opt-in, 默认关)
//
// params:
//
//	enabled   required: true|1|on | false|0|off
//	rate_down optional (enabled 时至少一个方向): "<n>mbit"/"<n>kbit" — WAN 下行带宽
//	rate_up   optional: WAN 上行带宽
//
// 状态唯一持久化到 rules.json 顶层 global_shaper_enabled/down/up (作为用户静态基准);
// 实际 1:1 根速率由 RootShaperArbiter 综合 static_shaper、5G Autorate 与 ThermoCruise 统一仲裁下发。
func actionGlobalShaperSet(s *server, p map[string]string) actionResp {
	hncDir := s.hncDir
	if rawAR, hasAR := p["autorate_enabled"]; hasAR && strings.TrimSpace(rawAR) != "" {
		if arOn, ok := parseBoolStr(rawAR); ok {
			if arOn {
				return actionAutorateSet(s, p)
			}
			if s.autorate != nil {
				s.autorate.bindServer(s)
				s.autorate.DisableFromStaticShaper()
			}
		}
	}
	enabled, ok := parseEnabledParam(p)
	if !ok {
		return actionResp{OK: false, Error: "bad params", Detail: "enabled must be true/false"}
	}

	resolveIface := func() string {
		ifc := s.currentHotspotIface()
		if ifc == "" {
			_, out := runBin(hncDir, "device_detect.sh", "iface")
			ifc = strings.TrimSpace(out)
		}
		return ifc
	}

	if !enabled {
		if rc, out := runBin(hncDir, "json_set.sh", "top", "global_shaper_enabled", "false"); rc != 0 {
			return actionResp{OK: false, Error: "rules.json write failed", Detail: strings.TrimSpace(out)}
		}
		iface := resolveIface()
		if err := s.shaperArbiter().SetStaticBaseline(time.Now(), iface, false, 0, 0, true); err != nil {
			return actionResp{OK: false, Error: "shaper apply failed", Detail: err.Error()}
		}
		return actionResp{OK: true, Detail: "global shaper off"}
	}

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
	if err := validateRate(rateDown); err != nil {
		return actionResp{OK: false, Error: "bad params", Detail: "rate_down: " + err.Error()}
	}
	if err := validateRate(rateUp); err != nil {
		return actionResp{OK: false, Error: "bad params", Detail: "rate_up: " + err.Error()}
	}
	if rateDown == "0" && rateUp == "0" {
		return actionResp{OK: false, Error: "bad params", Detail: "enabled 时至少一个方向带宽 > 0"}
	}

	iface := resolveIface()
	if iface == "" {
		return actionResp{OK: false, Error: "no hotspot iface", Detail: "热点未开启,无法应用全局整形"}
	}

	// 先持久化用户静态基准到 rules.json, 再交由 RootShaperArbiter 综合仲裁下发 1:1
	if rc1, out1 := runBin(hncDir, "json_set.sh", "top", "global_shaper_down", rateDown); rc1 != 0 {
		runBin(hncDir, "json_set.sh", "top", "global_shaper_enabled", "false")
		return actionResp{OK: false, Error: "rules.json write failed", Detail: "down: " + strings.TrimSpace(out1)}
	}
	if rc2, out2 := runBin(hncDir, "json_set.sh", "top", "global_shaper_up", rateUp); rc2 != 0 {
		runBin(hncDir, "json_set.sh", "top", "global_shaper_enabled", "false")
		return actionResp{OK: false, Error: "rules.json write failed", Detail: "up: " + strings.TrimSpace(out2)}
	}
	if rcW, outW := runBin(hncDir, "json_set.sh", "top", "global_shaper_enabled", "true"); rcW != 0 {
		return actionResp{OK: false, Error: "rules.json write failed", Detail: strings.TrimSpace(outW)}
	}

	downMbps := tcRateStrToMbps(rateDown)
	upMbps := tcRateStrToMbps(rateUp)
	if err := s.shaperArbiter().SetStaticBaseline(time.Now(), iface, true, downMbps, upMbps, true); err != nil {
		runBin(hncDir, "json_set.sh", "top", "global_shaper_enabled", "false")
		return actionResp{OK: false, Error: "shaper apply failed", Detail: err.Error()}
	}
	return actionResp{OK: true, Detail: "global shaper on down=" + rateDown + " up=" + rateUp}
}
