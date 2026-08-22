package main

import "testing"

// v6 review fix 回归测试: secret 缺失窗口内被 loopback 分级放行的敏感读端点
// 必须全部登记在 isSensitiveReadPath。历史上该白名单已三次漂移, 新端点漏登记
// = 匿名数据泄露, 这里按 server.go 的路由注册逐条锁定。
func TestIsSensitiveReadPath(t *testing.T) {
	sensitive := []string{
		// 旧有端点 (防误删)
		"/api/logs", "/api/devices", "/api/live", "/api/capabilities",
		"/api/tokens", "/api/config", "/api/stats", "/api/templates",
		"/api/metrics", "/api/iface_info", "/api/offload_status",
		"/api/dpi_state", "/api/dpi_probe", "/api/alerts",
		"/api/dpi_history", "/api/app_limits",
		// v6 review 补登: self 归因 / 导出内容 / SLA / SSE 事件流
		"/api/self", "/api/self/ifaces", "/api/self/attrib",
		"/api/sla", "/api/events", "/api/exports",
		"/api/exports/export-20260822-120000.zip", // 子路径前缀匹配
	}
	for _, p := range sensitive {
		if !isSensitiveReadPath(p) {
			t.Errorf("isSensitiveReadPath(%q) = false, want true", p)
		}
	}

	nonSensitive := []string{
		"/", "/index.html", "/health", "/api/pair_pending", "/api/pair_verify",
		"/api/exportsx", "/api/selfie", // 前缀相似但不同的路径不得误中
	}
	for _, p := range nonSensitive {
		if isSensitiveReadPath(p) {
			t.Errorf("isSensitiveReadPath(%q) = true, want false", p)
		}
	}
}
