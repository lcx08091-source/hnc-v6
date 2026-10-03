package clockhwm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestSane(t *testing.T) {
	cases := []struct {
		now, hwm int64
		want     bool
	}{
		{MinUnix, 0, true},                              // 恰好 2025-01-01T00:00:00Z
		{MinUnix - 1, 0, false},                         // 2024 年
		{1700000000, 0, false},                          // 2023
		{MinUnix + 86400, 0, true},                      // 无高水位
		{MinUnix + 86400, MinUnix + 86400, true},        // 恰等于高水位
		{MinUnix + 86400 - 600, MinUnix + 86400, true},  // 落后高水位恰 600s
		{MinUnix + 86400 - 601, MinUnix + 86400, false}, // 落后 601s
		{MinUnix + 86400, -5, true},                     // 负/零高水位视为无
		{MinUnix + 86400, 1, true},                      // hwm=1 无意义
	}
	for _, c := range cases {
		if got := Sane(c.now, c.hwm); got != c.want {
			t.Errorf("Sane(%d, %d) = %v, want %v", c.now, c.hwm, got, c.want)
		}
	}
}

func TestReadHWM(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "clock_hwm")
	if got := ReadHWM(p); got != 0 {
		t.Fatalf("missing file: %d", got)
	}
	for _, c := range []struct {
		content string
		want    int64
	}{
		{"1760000000\n", 1760000000},
		{"1760000000", 1760000000},
		{"  1760000000  \n", 1760000000},
		{"garbage\n", 0},
		{"-1\n", 0},
		{"0\n", 0},
		{"1760000000\nextra\n", 1760000000}, // 只取首行
	} {
		os.WriteFile(p, []byte(c.content), 0o644)
		if got := ReadHWM(p); got != c.want {
			t.Errorf("ReadHWM(%q) = %d, want %d", c.content, got, c.want)
		}
	}
}

// TestShellMirrorConstants 锁定 bin/hnc_clock.sh 的常量与 clockhwm 一致
// (写法参照 httpd power_test.go 的 TestPowerShellMirrorConstants)。
func TestShellMirrorConstants(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "bin", "hnc_clock.sh"))
	if err != nil {
		t.Skipf("read hnc_clock.sh: %v", err)
	}
	s := string(b)
	m := regexp.MustCompile(`HNC_CLOCK_MIN_TS=(\d+)`).FindStringSubmatch(s)
	if m == nil || m[1] != fmt.Sprint(MinUnix) {
		t.Errorf("hnc_clock.sh HNC_CLOCK_MIN_TS=%v, want %d", m, MinUnix)
	}
	m = regexp.MustCompile(`HNC_CLOCK_TOLERANCE=(\d+)`).FindStringSubmatch(s)
	if m == nil || m[1] != fmt.Sprint(BackTolerance) {
		t.Errorf("hnc_clock.sh HNC_CLOCK_TOLERANCE=%v, want %d", m, BackTolerance)
	}
}
