package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// v5.33: resolveCurrentIface 走 ifacehint(唯一权威出口), 不再自己读 hotspot_iface。
// 「改动前会失败」: v5.32 只读 hotspot_iface —— 新鲜的 iface_detect.json 说 ap9 时仍返回
// hotspot_iface 里的 wlan7; hotspot_iface 里是非法名字也照单全收。
func TestResolveCurrentIfaceUsesIfacehint(t *testing.T) {
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
	os.Remove(filepath.Join(dir, "iface_detect.json"))
	if got := resolveCurrentIface(cfg); got != "wlan7" {
		t.Fatalf("回退 hotspot_iface: got %q, want wlan7", got)
	}
	write("hotspot_iface", "../../etc\n")
	if got := resolveCurrentIface(cfg); got == "../../etc" {
		t.Fatal("hotspot_iface 里的非法名字不该被采用")
	}
	if got := resolveCurrentIface(Config{RunDir: dir, Iface: "wlan3"}); got != "wlan3" {
		t.Fatalf("-iface 显式指定优先: got %q", got)
	}
}
