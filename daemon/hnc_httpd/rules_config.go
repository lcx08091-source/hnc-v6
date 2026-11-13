package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// readRulesConfig 读取用户配置；调用者决定缺失/错误时的默认行为。
// 返回独立快照，导出等调用可以脱敏，不能借用 devices.json 的实时状态作配置。
func readRulesConfig(hncDir string) (map[string]interface{}, error) {
	b, err := os.ReadFile(filepath.Join(hncDir, "data", "rules.json"))
	if err != nil {
		return nil, err
	}
	var rules map[string]interface{}
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func readDeviceRule(hncDir, mac string) map[string]interface{} {
	rules, err := readRulesConfig(hncDir)
	if err != nil {
		return nil
	}
	devices, _ := rules["devices"].(map[string]interface{})
	for key, raw := range devices {
		if strings.EqualFold(key, mac) {
			device, _ := raw.(map[string]interface{})
			return device
		}
	}
	return nil
}

// 配置写入继续交给现有 json_set.sh/hnc_json，复用它的锁和发布方式。
// HTTP 只表达修改的字段，不另建 Go 文件写入路径。
func setRuleTop(hncDir, key, value string) (int, string) {
	return runBin(hncDir, "json_set.sh", "top", key, value)
}

func setDeviceRule(hncDir, mac, field, value string) (int, string) {
	return runBin(hncDir, "json_set.sh", "device", mac, field, value)
}
