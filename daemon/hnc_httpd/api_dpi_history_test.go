package main

import (
	"os"
	"path/filepath"
	"testing"
)

// v6 review fix 回归测试: readHistJSONL 在文件超 10MB 时必须"截断读"而不是
// 旧实现的整文件丢弃 (return nil)。构造一个略超 10MB 的文件, 断言能拿回
// 前 10MB 内的完整行。
func TestReadHistJSONLTruncatesInsteadOfDropping(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.20260822.jsonl")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// 每行 ~128B, 写 ~11MB (86000 行)。
	line := `{"ts":1234567890,"mac":"aa:bb:cc:dd:ee:ff","app":"com.example.app.that.is.long","tx":1024,"rx":2048}` + "\n"
	written := int64(0)
	n := 0
	for written < 11*1024*1024 {
		if _, err := f.WriteString(line); err != nil {
			t.Fatal(err)
		}
		written += int64(len(line))
		n++
	}
	f.Close()

	rows := readHistJSONL(path)
	if len(rows) == 0 {
		t.Fatal("readHistJSONL returned 0 rows for an >10MB file — regression of the old drop-all behavior")
	}
	// 行数不应超过 10MB 能容纳的完整行数。
	maxRows := 10 * 1024 * 1024 / len(line)
	if len(rows) > maxRows {
		t.Fatalf("readHistJSONL read %d rows, exceeds the 10MB cap (%d)", len(rows), maxRows)
	}
}

func TestReadHistJSONLSmallAndMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.20260822.jsonl")
	if err := os.WriteFile(path, []byte("{\"ts\":1}\nnot-json\n{\"ts\":2}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rows := readHistJSONL(path)
	if len(rows) != 2 {
		t.Fatalf("want 2 parsed rows, got %d", len(rows))
	}
	if got := readHistJSONL(filepath.Join(dir, "missing.jsonl")); got != nil {
		t.Fatalf("missing file must return nil, got %v", got)
	}
}
