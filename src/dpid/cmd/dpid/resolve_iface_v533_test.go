package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"hnc.io/dpid/capture"
)

// v5.33 + RC2: resolveCurrentIface 走 ifacehint(唯一权威出口):
// 1. 新鲜 iface_detect.json 最高优先(包括覆盖旧 dpi_config.json 里已销毁的 wlan2);
// 2. 回退合法 hotspot_iface;
// 3. 拒绝非法名字;
// 4. 无权威 hint 时采用显式 Config.Iface。
func TestResolveCurrentIfaceUsesIfacehint(t *testing.T) {
	oldDiscover := discoverAPFn
	oldByName := ifaceByNameFn
	discoverAPFn = func() ([]capture.IfaceCandidate, error) { return nil, nil }
	ifaceByNameFn = func(name string) (*net.Interface, error) { return nil, errors.New("no such iface") }
	t.Cleanup(func() {
		discoverAPFn = oldDiscover
		ifaceByNameFn = oldByName
	})

	dir := t.TempDir()
	cfg := Config{RunDir: dir}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("iface_detect.json", fmt.Sprintf(`{"schema":1,"ts":%d,"iface":"ap9"}`, time.Now().Unix()))
	write("hotspot_iface", "wlan7\n")
	if got := resolveCurrentIface(cfg); got != "ap9" {
		t.Fatalf("新鲜的 iface_detect.json 优先: got %q, want ap9", got)
	}
	// RC2: 切频段改口名(wlan2 -> ap9)后, 新鲜 iface_detect.json 优先于旧 dpi_config.json 的 wlan2。
	if got := resolveCurrentIface(Config{RunDir: dir, Iface: "wlan2"}); got != "ap9" {
		t.Fatalf("新鲜 iface_detect.json 应覆盖已销毁的旧 cfg.Iface=wlan2: got %q, want ap9", got)
	}

	os.Remove(filepath.Join(dir, "iface_detect.json"))
	if got := resolveCurrentIface(cfg); got != "wlan7" {
		t.Fatalf("回退 hotspot_iface: got %q, want wlan7", got)
	}
	write("hotspot_iface", "../../etc\n")
	if got := resolveCurrentIface(cfg); got == "../../etc" {
		t.Fatal("hotspot_iface 里的非法名字不该被采用")
	}
	if got := resolveCurrentIface(Config{RunDir: dir, Iface: "wlan3"}); got != "wlan3" {
		t.Fatalf("-iface 显式指定兜底: got %q", got)
	}
}
