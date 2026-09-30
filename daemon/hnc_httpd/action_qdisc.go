// action_qdisc.go — v5.20 低延迟 qdisc 兜底链 / 默认叶子 AQM 开关
//
// run/qdisc_caps.json 由 bin/qdisc_caps.sh 写(capability_probe 开头调用):
//
//	{schema, probed_at, boot_id, kernel, tc_binary, probe_dev, module_load_attempted,
//	 order:[..], available:[..], chosen, reason, aqm, default_leaf_aqm_eligible,
//	 loaded_modules:[..], tried:[{name, method, ok, err[, path]}]}
//
// /api/capabilities 原样附在 "qdisc_caps" 字段(缺失 → null)。
package main

import (
	"path/filepath"
	"strings"
)

func (s *server) readQdiscCaps() interface{} {
	raw, err := s.jsonCache.read(filepath.Join(s.hncDir, "run", "qdisc_caps.json"))
	if err != nil {
		return nil
	}
	return raw
}

// actionTCLeafAQMSet · 设备 class 默认叶子用 AQM(fq_codel/cake…)还是 netem-0ms 占位
//
//	mode  auto(默认: 仅 qdisc_caps chosen ∈ {cake, fq_codel} 时开) | on | off
//
// 写 rules.json 顶层 tc_leaf_aqm。只影响之后新建/重设的设备叶子(set_limit / restore
// 时的 ensure_device_class); 配了延迟/抖动/丢包的设备叶子始终是 netem。
func actionTCLeafAQMSet(hncDir string, p map[string]string) actionResp {
	mode := strings.ToLower(strings.TrimSpace(p["mode"]))
	switch mode {
	case "auto", "on", "off":
	default:
		return actionResp{OK: false, Error: "bad params", Detail: "mode must be auto|on|off"}
	}
	if rc, out := runBin(hncDir, "json_set.sh", "top", "tc_leaf_aqm", mode); rc != 0 {
		return actionResp{OK: false, Error: "rules.json write failed", Detail: strings.TrimSpace(out)}
	}
	return actionResp{OK: true, Detail: "tc_leaf_aqm=" + mode + " (applies on next limit/restore)"}
}
