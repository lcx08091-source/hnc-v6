package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestJSONFileCacheHitAndInvalidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	if err := os.WriteFile(path, []byte(`{"v":1}`), 0o644); err != nil {
		t.Fatal(err)
	}

	c := newJSONFileCache()
	v1, err := c.read(path)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	m1, _ := v1.(map[string]interface{})
	if m1["v"].(float64) != 1 {
		t.Fatalf("first read parsed wrong: %v", v1)
	}

	// 未变化的文件必须命中缓存: 同一底层 map (指针相等)。
	// 注: 不能直接 v1 != v2 —— interface 持有不可比较类型 (map) 时比较会
	// runtime panic, 即使是同一指针。
	v2, err := c.read(path)
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if reflect.ValueOf(v1).Pointer() != reflect.ValueOf(v2).Pointer() {
		t.Fatalf("cache miss on unchanged file")
	}

	// mtime 变化后必须重新读。
	time.Sleep(10 * time.Millisecond) // 确保时间戳可区分
	if err := os.WriteFile(path, []byte(`{"v":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Windows/部分文件系统 mtime 粒度问题兜底: 若仍命中, 再等等重试一次。
	var v3 interface{}
	for i := 0; i < 3; i++ {
		v3, err = c.read(path)
		if err != nil {
			t.Fatalf("third read: %v", err)
		}
		if m, _ := v3.(map[string]interface{}); m["v"].(float64) == 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("stale cache after file change: %v", v3)
}

func TestJSONFileCacheMissingFile(t *testing.T) {
	c := newJSONFileCache()
	if _, err := c.read(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error for missing file, got nil (must not cache errors)")
	}
}

// 非法 JSON 不缓存: 修复后文件应能正常读到 (错误结果没有被 memoize)。
func TestJSONFileCacheBadJSONNotCached(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := newJSONFileCache()
	if _, err := c.read(path); err == nil {
		t.Fatal("expected parse error for invalid JSON")
	}
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := c.read(path)
	if err != nil {
		t.Fatalf("after fixing the file, read must succeed: %v", err)
	}
	if m, _ := v.(map[string]interface{}); m["ok"] != true {
		t.Fatalf("got %v, want {ok:true}", v)
	}
}
