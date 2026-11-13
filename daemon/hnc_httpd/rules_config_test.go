package main

import (
	"os"
	"path/filepath"
	"testing"
)

// 配置读取收拢后，各功能仍保留自己的缺省行为，且不会把 watchdog 的设备状态
// 当成持久配置（例如设备离线后，延迟/QoS 设置仍应保留）。
func TestRulesConfigConsumers(t *testing.T) {
	const mac = "aa:bb:cc:00:00:05"
	for _, tt := range []struct {
		name, rules                    string
		auth, cert, shared, delay, qos bool
	}{
		{name: "missing", auth: true, cert: true},
		{name: "malformed", rules: "{broken", auth: true, cert: true},
		{name: "defaults", rules: `{}`, auth: true, cert: true},
		{name: "explicit false", rules: `{"auth_required":false,"discover_cert_probe":false,"devices":{"AA:BB:CC:00:00:05":{"app_qos":false,"delay_ms":0}}}`},
		{name: "enabled", rules: `{"auth_required":true,"discover_cert_probe":true,"app_limit_include_shared_ips":true,"devices":{"AA:BB:CC:00:00:05":{"app_qos":true,"delay_ms":12}}}`, auth: true, cert: true, shared: true, delay: true, qos: true},
		{name: "legacy values", rules: `{"app_limit_include_shared_ips":"on","devices":{"AA:BB:CC:00:00:05":{"app_qos":"true","loss_pct":"0.5"}}}`, auth: true, cert: true, shared: true, delay: true, qos: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
				t.Fatal(err)
			}
			if tt.rules != "" {
				writeFileT(t, filepath.Join(dir, "data", "rules.json"), tt.rules)
			}
			// 即使实时设备快照里出现同名字段，也不能参与读取用户配置。
			writeFileT(t, filepath.Join(dir, "data", "devices.json"), `{"aa:bb:cc:00:00:05":{"app_qos":true,"delay_ms":100},"auth_required":false,"discover_cert_probe":false,"app_limit_include_shared_ips":true}`)
			for _, check := range []struct {
				name      string
				got, want bool
			}{
				{"auth", readAuthRequired(dir), tt.auth},
				{"cert", certProbeEnabled(dir), tt.cert},
				{"shared", appLimitIncludeShared(dir), tt.shared},
				{"delay", deviceDelayOn(dir, mac), tt.delay},
				{"qos", deviceAppQosOn(dir, mac), tt.qos},
			} {
				if check.got != check.want {
					t.Errorf("%s = %v, want %v", check.name, check.got, check.want)
				}
			}
		})
	}
}
