package output

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// v5.12: 随机 JA4 洪泛下 per-client / 全局 JA4 表必须封顶。
func TestJA4TablesBounded(t *testing.T) {
	w := NewWriter(filepath.Join(t.TempDir(), "s.json"), "test")
	now := time.Unix(1700000000, 0)
	for i := 0; i < 5000; i++ {
		w.RecordTLS("aa:bb:cc:dd:ee:01", "10.0.0.2", "1.1.1.1", "", fmt.Sprintf("t13d_%08x", i), now.Add(time.Duration(i)*time.Second))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if n := len(w.globalJA4); n > maxGlobalNames {
		t.Fatalf("globalJA4=%d 超过上限 %d", n, maxGlobalNames)
	}
	for _, c := range w.clients {
		if n := len(c.JA4); n > maxNamesPerClient {
			t.Fatalf("client JA4=%d 超过上限 %d", n, maxNamesPerClient)
		}
		// 最新的必须保留(LRU 淘汰旧的)。
		if c.JA4[fmt.Sprintf("t13d_%08x", 4999)] == nil {
			t.Fatal("最新 JA4 被错误淘汰")
		}
	}
}
