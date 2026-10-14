package main

import (
	"os"
	"path/filepath"
	"testing"
)

// v5.26 T2: dpid 守护者唯一权威 run/dpid_launcher.choice 的纯函数单测。

func TestParseLauncherChoice(t *testing.T) {
	cases := map[string]string{
		"launcher":   "launcher",
		"launcher\n": "launcher",
		"guard":      "", // v5.33: shell guard 已删, 旧值按缺失处理
		"guard\n":    "",
		"supervisor": "", // v5.33: Go supervisor 已删
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

func TestReadLauncherChoiceAt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dpid_launcher.choice")

	// 文件不存在 → ""
	if got := readLauncherChoiceAt(p); got != "" {
		t.Errorf("missing file: got %q, want empty", got)
	}
	// 两个合法值原样读出(容忍尾随换行)
	for _, v := range []string{"launcher", "direct"} {
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
