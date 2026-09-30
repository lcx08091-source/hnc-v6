package main

import (
	"os"
	"path/filepath"
	"testing"
)

// v5.18: nDPI 删除后, 旧版 dpi_config.json 里残留的 nDPI 相关键不能让配置
// 加载失败(未知键忽略, 其余字段照常生效)。
func TestLoadConfigToleratesLegacyNDPIKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dpi_config.json")
	legacy := `{"iface":"wlan2","snaplen":1500,"dpid_ndpi":true,"ndpi":{"enabled":true,"config":"dpi_ndpi_config.json"},"ndpi_ip_to_host":"/data/local/hnc/run/ip_to_host.json","log_level":"debug"}`
	if err := os.WriteFile(p, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := loadConfig(p)
	if cfg.Iface != "wlan2" || cfg.Snaplen != 1500 || cfg.LogLevel != "debug" || cfg.RunDir != defaultRunDir {
		t.Fatalf("cfg=%+v", cfg)
	}
}
