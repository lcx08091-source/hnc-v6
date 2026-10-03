package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// v5.26 T2: dpid 守护者唯一权威 run/dpid_launcher.choice 的纯函数单测。

func TestParseLauncherChoice(t *testing.T) {
	cases := map[string]string{
		"launcher":   "launcher",
		"launcher\n": "launcher",
		"guard":      "guard",
		"guard\n":    "guard",
		"supervisor": "supervisor",
		"direct":     "direct",
		" direct \n": "direct",
		"":           "",
		"\n":         "",
		"   ":        "",
		"bogus":      "",
		"Launcher":   "", // 大小写敏感
		"launch":     "",
		"directive":  "",
	}
	for raw, want := range cases {
		if got := parseLauncherChoice(raw); got != want {
			t.Errorf("parseLauncherChoice(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestDpidGuardPlan(t *testing.T) {
	cases := []struct {
		choice              string
		superviseLauncher   bool
		superviseSupervisor bool
		superviseShellGuard bool
		superviseDpidDirect bool
	}{
		{"launcher", true, false, false, false},
		{"guard", false, false, true, false},
		{"supervisor", false, true, false, false},
		{"direct", false, false, false, true},
		{"", true, true, false, false}, // 缺失/非法 → 旧行为
	}
	for _, c := range cases {
		sl, ss, sg, sd := dpidGuardPlan(c.choice)
		if sl != c.superviseLauncher || ss != c.superviseSupervisor ||
			sg != c.superviseShellGuard || sd != c.superviseDpidDirect {
			t.Errorf("dpidGuardPlan(%q) = (%v,%v,%v,%v), want (%v,%v,%v,%v)",
				c.choice, sl, ss, sg, sd,
				c.superviseLauncher, c.superviseSupervisor, c.superviseShellGuard, c.superviseDpidDirect)
		}
	}
}

func TestReadLauncherChoiceAt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dpid_launcher.choice")

	// 文件不存在 → ""
	if got := readLauncherChoiceAt(p); got != "" {
		t.Errorf("missing file: got %q, want empty", got)
	}
	// 四个合法值原样读出(容忍尾随换行)
	for _, v := range []string{"launcher", "guard", "supervisor", "direct"} {
		if err := os.WriteFile(p, []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := readLauncherChoiceAt(p); got != v {
			t.Errorf("content %q: got %q, want %q", v, got, v)
		}
	}
	// 非法内容 → ""(视同缺失, 走旧行为)
	if err := os.WriteFile(p, []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readLauncherChoiceAt(p); got != "" {
		t.Errorf("invalid content: got %q, want empty", got)
	}
}

func TestDpidDaemonDirectHasNoGuardBin(t *testing.T) {
	if dpidDaemon().guardBin == "" {
		t.Fatal("dpidDaemon 应带 guardBin(hnc_dpid_supervisor 优先)")
	}
	if d := dpidDaemonDirect(); d.guardBin != "" {
		t.Errorf("dpidDaemonDirect().guardBin = %q, want empty(direct 模式直拉 hnc_dpid)", d.guardBin)
	}
}

// findLiveByCmdlineSub 只认真正执行该脚本的进程, 不认只是「提到」名字的进程。
func TestFindLiveByCmdlineSub(t *testing.T) {
	if _, err := os.Stat("/proc/self/cmdline"); err != nil {
		t.Skip("no /proc")
	}
	run := func(args ...string) *exec.Cmd {
		c := exec.Command("sh", args...)
		if err := c.Start(); err != nil {
			t.Skip("cannot spawn sh:", err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
		return c
	}
	// $0 = 某路径下的脚本名 → 命中
	real := run("-c", "sleep 30", "/x/hnc_cmdline_probe_a.sh")
	// 参数里只是提到名字(像 grep/pgrep 的参数) → 不命中
	run("-c", "sleep 30", "grep hnc_cmdline_probe_b.sh")
	time.Sleep(100 * time.Millisecond)
	if got := findLiveByCmdlineSub("hnc_cmdline_probe_a.sh"); got != real.Process.Pid {
		t.Errorf("exec match: got %d, want %d", got, real.Process.Pid)
	}
	if got := findLiveByCmdlineSub("hnc_cmdline_probe_b.sh"); got != 0 {
		t.Errorf("mention-only should not match, got pid %d", got)
	}
}
