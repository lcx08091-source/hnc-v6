package main

import "strings"

// actionDeviceSQMSet · rc20 每设备「低延迟」(智能队列) 开关
//
// params:
//
//	mac      required
//	enabled  required: true|1|on | false|0|off
//
// 把该设备 class 的叶子 qdisc 换成 CAKE/fq_codel (AQM) 或换回 netem 占位。
// 与每设备限速/延迟共存 (限速决定瓶颈, 延迟优先占叶子)。镜像 actionDelaySet 的
// iface/mark_id/ip 解析链, 持久化到 rules.json 的 per-device sqm_enabled,
// restore_rules 会据此恢复。
func actionDeviceSQMSet(hncDir string, p map[string]string) actionResp {
	mac := p["mac"]
	if !macRE.MatchString(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	enabled := false
	switch strings.TrimSpace(strings.ToLower(p["enabled"])) {
	case "true", "1", "on", "yes":
		enabled = true
	case "false", "0", "off", "no", "":
		enabled = false
	default:
		return actionResp{OK: false, Error: "bad params", Detail: "enabled must be true/false"}
	}

	// 低延迟需要 HTB 叶子类; tc_htb 已知不支持时直接拒绝 (开启时)。
	if enabled {
		if supported, known := tcHTBSupported(hncDir); known && !supported {
			return actionResp{OK: false, Error: "unsupported", Detail: "tc_htb=false; 低延迟需要 HTB 叶子类"}
		}
	}

	rc, out := runBin(hncDir, "device_detect.sh", "iface")
	if rc != 0 {
		return actionResp{OK: false, Error: "iface detect failed", Detail: out}
	}
	iface := strings.TrimSpace(out)
	if iface == "" {
		return actionResp{OK: false, Error: "no hotspot iface"}
	}

	// mark_id: per-device。没有且要开启 → 分配; 关闭且没有 → 只写 flag。
	rcM, outM := runBin(hncDir, "json_set.sh", "device_get", mac, "mark_id")
	mid := strings.TrimSpace(outM)
	if rcM != 0 || mid == "" || mid == "0" {
		if !enabled {
			// 没分配过 mid 且要关 → 无 tc 可改, 仅落 flag=false
			runBin(hncDir, "json_set.sh", "device", mac, "sqm_enabled", "false")
			return actionResp{OK: true, Detail: "sqm off (no class)"}
		}
		rc0, out0 := runBin(hncDir, "apply_device_rule.sh", "alloc_mid", mac)
		if rc0 != 0 {
			return actionResp{OK: false, Error: "mid assign failed", Detail: out0}
		}
		mid = strings.TrimSpace(out0)
		if !intRE.MatchString(mid) {
			return actionResp{OK: false, Error: "mid assign failed", Detail: "alloc_mid returned non-integer mid: " + mid}
		}
	}

	want := "off"
	if enabled {
		want = "on"
	}
	ip := lookupCurrentDeviceIP(hncDir, mac)
	rc2, out2 := runBin(hncDir, "tc_manager.sh", "set_sqm", iface, mid, want, ip)
	if rc2 != 0 {
		return actionResp{OK: false, Error: "sqm apply failed", Detail: strings.TrimSpace(out2)}
	}

	val := "false"
	if enabled {
		val = "true"
	}
	if rcW, outW := runBin(hncDir, "json_set.sh", "device", mac, "sqm_enabled", val); rcW != 0 {
		return actionResp{OK: false, Error: "rules.json write failed", Detail: strings.TrimSpace(outW)}
	}
	return actionResp{OK: true, Detail: "sqm=" + val + " mac=" + mac}
}
