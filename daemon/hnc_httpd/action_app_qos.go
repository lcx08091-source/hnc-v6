// action_app_qos.go — v5.30 T4: 设备「按应用分优先级」开关(应用感知 QoS 初版)。
//
//	app_qos_set  mac=<MAC> enabled=true|false
//
// 持久化到 rules.json 的 devices[mac].app_qos(缺省 = 关)。真正下发由 Go 看门狗
// 每 30 秒(本动作写 run/app_limit.dirty 后 3 秒内)生成 run/app_qos.plan、调
// bin/apply_app_qos.sh: 该设备的下行 class 下挂实时 / 交互 / 后台 3 个子 class
// (rate 50/35/15, ceil 不变, 设备总限速不变)。
//
// 与「延迟模拟」互斥: 两者都要占用设备的下行叶子队列, 开着延迟时拒绝开启
// (tc_manager.sh 对应用 QoS 管着的 class 也会跳过 netem, 双保险)。
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// deviceDelayOn rules.json 里该设备是否开着延迟 / 抖动 / 丢包。
func deviceDelayOn(hncDir, mac string) bool {
	b, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json"))
	if err != nil {
		return false
	}
	var r struct {
		Devices map[string]map[string]interface{} `json:"devices"`
	}
	if json.Unmarshal(b, &r) != nil {
		return false
	}
	for k, d := range r.Devices {
		if !strings.EqualFold(k, mac) {
			continue
		}
		for _, f := range []string{"delay_ms", "jitter_ms", "loss_pct"} {
			if numFieldGT0(d[f]) {
				return true
			}
		}
	}
	return false
}

// deviceAppQosOn rules.json 里该设备是否开着 app_qos。
func deviceAppQosOn(hncDir, mac string) bool {
	b, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json"))
	if err != nil {
		return false
	}
	var r struct {
		Devices map[string]map[string]interface{} `json:"devices"`
	}
	if json.Unmarshal(b, &r) != nil {
		return false
	}
	for k, d := range r.Devices {
		if strings.EqualFold(k, mac) {
			switch v := d["app_qos"].(type) {
			case bool:
				return v
			case string:
				return strings.EqualFold(strings.TrimSpace(v), "true")
			}
		}
	}
	return false
}

func numFieldGT0(v interface{}) bool {
	switch x := v.(type) {
	case float64:
		return x > 0
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return err == nil && f > 0
	}
	return false
}

func actionAppQosSet(hncDir string, p map[string]string) actionResp {
	mac := strings.ToLower(strings.TrimSpace(p["mac"]))
	if !macRE.MatchString(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	enabled, ok := parseEnabledParam(p)
	if !ok {
		return actionResp{OK: false, Error: "bad params", Detail: "enabled must be true/false"}
	}
	if enabled {
		if supported, known := tcHTBSupported(hncDir); known && !supported {
			return actionResp{OK: false, Error: "unsupported", Detail: "tc_htb=false; 按应用分优先级需要 HTB 子类"}
		}
		if deviceDelayOn(hncDir, mac) {
			return actionResp{OK: false, Error: "conflict", Detail: "这台设备开着延迟模拟; 两者都要占用下行队列, 先关掉延迟模拟再开"}
		}
		// 设备 class 挂在 mark_id 上; 没有就分配(只分配 mid + iptables mark, 不碰限速)
		rcM, outM := runBin(hncDir, "json_set.sh", "device_get", mac, "mark_id")
		mid := strings.TrimSpace(outM)
		if rcM != 0 || mid == "" || mid == "0" {
			rc0, out0 := runBin(hncDir, "apply_device_rule.sh", "alloc_mid", mac)
			if rc0 != 0 {
				return actionResp{OK: false, Error: "mid assign failed", Detail: strings.TrimSpace(out0)}
			}
			if mid = strings.TrimSpace(out0); !intRE.MatchString(mid) {
				return actionResp{OK: false, Error: "mid assign failed", Detail: "alloc_mid returned non-integer mid: " + mid}
			}
		}
	}
	val := strconv.FormatBool(enabled)
	if rc, out := runBin(hncDir, "json_set.sh", "device", mac, "app_qos", val); rc != 0 {
		return actionResp{OK: false, Error: "rules.json write failed", Detail: strings.TrimSpace(out)}
	}
	// 看门狗 appLimitApplyLoop 见到这个标记 3 秒内重新生成计划并下发
	_ = os.WriteFile(filepath.Join(hncDir, "run", "app_limit.dirty"), nil, 0o644)
	return actionResp{OK: true, Detail: "app_qos=" + val + " mac=" + mac}
}
