package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// rc30.12.30 (P2.11): merged from hotfix16_9_capability_gate.go.
// 内核能力检测结果读取层. 跟 middleware.go 的 loopback secret 检查思路类似,
// 都是从 run/ 下读权威信号. 独立成 capability.go 而非塞进 middleware.go,
// 因为这跟鉴权无关, 是 tc/iptables 能力门控.
//
// readCapabilityBool: 通用 capability reader.
//   - Unknown (文件缺/解析失败/字段缺) 保留 legacy 行为 (返回 true 默认放行)
//   - 显式 false 是权威信号, 让写 actions 快速失败而不是卡在 shell/tc 路径

func readCapabilityBool(hncDir, key string) (bool, bool) {
	b, err := os.ReadFile(filepath.Join(hncDir, "run", "capabilities.json"))
	if err != nil {
		return true, false
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return true, false
	}
	if v, ok := m[key].(bool); ok {
		return v, true
	}
	return true, false
}

func tcHTBSupported(hncDir string) (bool, bool) {
	return readCapabilityBool(hncDir, "tc_htb")
}

func tcNetemSupported(hncDir string) (bool, bool) {
	return readCapabilityBool(hncDir, "tc_netem")
}
