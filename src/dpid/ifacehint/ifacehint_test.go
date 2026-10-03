package ifacehint

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

var tNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.Local)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadFreshDetect(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "iface_detect.json", `{"schema":1,"ts":`+strconv.FormatInt(tNow.Add(-3*time.Minute).Unix(), 10)+`,"iface":"wlan2","method":"tethering"}`)
	write(t, dir, "hotspot_iface", "ap0\n")
	if s, ok := Read(dir, tNow); !ok || s != "wlan2" {
		t.Fatalf("got (%q,%v), want (wlan2,true)", s, ok)
	}
}

func TestReadStaleDetectFallsBack(t *testing.T) {
	dir := t.TempDir()
	// ts 超过 10 分钟 → 陈旧, 回退 hotspot_iface
	write(t, dir, "iface_detect.json", `{"schema":1,"ts":`+strconv.FormatInt(tNow.Add(-11*time.Minute).Unix(), 10)+`,"iface":"wlan2"}`)
	write(t, dir, "hotspot_iface", "ap0\n")
	if s, ok := Read(dir, tNow); !ok || s != "ap0" {
		t.Fatalf("got (%q,%v), want (ap0,true)", s, ok)
	}
}

func TestReadEmptyIfaceFallsBack(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "iface_detect.json", `{"schema":1,"ts":`+strconv.FormatInt(tNow.Unix(), 10)+`,"iface":""}`)
	write(t, dir, "hotspot_iface", "swlan0\n")
	if s, ok := Read(dir, tNow); !ok || s != "swlan0" {
		t.Fatalf("got (%q,%v), want (swlan0,true)", s, ok)
	}
}

func TestReadCorruptDetectFallsBack(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "iface_detect.json", `{"schema":1,"ts":not-a-number`)
	write(t, dir, "hotspot_iface", "wlan1\n")
	if s, ok := Read(dir, tNow); !ok || s != "wlan1" {
		t.Fatalf("got (%q,%v), want (wlan1,true)", s, ok)
	}
}

func TestReadDetectOnlyNoHint(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "iface_detect.json", `{"schema":1,"ts":`+strconv.FormatInt(tNow.Add(-time.Minute).Unix(), 10)+`,"iface":"wlan9"}`)
	if s, ok := Read(dir, tNow); !ok || s != "wlan9" {
		t.Fatalf("got (%q,%v), want (wlan9,true)", s, ok)
	}
}

func TestReadNothingAvailable(t *testing.T) {
	dir := t.TempDir()
	if s, ok := Read(dir, tNow); ok || s != "" {
		t.Fatalf("got (%q,%v), want empty", s, ok)
	}
}

func TestReadBadHintRejected(t *testing.T) {
	dir := t.TempDir()
	// hotspot_iface 含非法字符 → 拒绝; detect 陈旧 → 双双失败
	write(t, dir, "iface_detect.json", `{"schema":1,"ts":`+strconv.FormatInt(tNow.Add(-30*time.Minute).Unix(), 10)+`,"iface":"wlan2"}`)
	write(t, dir, "hotspot_iface", "rm -rf /\n")
	if s, ok := Read(dir, tNow); ok || s != "" {
		t.Fatalf("got (%q,%v), want empty", s, ok)
	}
}

func TestReadFutureTsRejected(t *testing.T) {
	dir := t.TempDir()
	// ts 在未来(时钟错乱) → 不盲信, 回退
	write(t, dir, "iface_detect.json", `{"schema":1,"ts":`+strconv.FormatInt(tNow.Add(2*time.Hour).Unix(), 10)+`,"iface":"wlan2"}`)
	write(t, dir, "hotspot_iface", "ap0\n")
	if s, ok := Read(dir, tNow); !ok || s != "ap0" {
		t.Fatalf("got (%q,%v), want (ap0,true)", s, ok)
	}
}
