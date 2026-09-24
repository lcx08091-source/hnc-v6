package alert

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// v5.12: 并发 MarkSeen 不得丢更新, 且不留临时文件。
func TestMarkSeen_ConcurrentNoLostUpdate(t *testing.T) {
	cfg := NewConfig(t.TempDir())
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := MarkSeen(cfg, []string{fmt.Sprintf("id_%d", i)}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	seen := LoadSeen(cfg)
	if len(seen) != 20 {
		t.Fatalf("应有 20 个已读 id, got %d", len(seen))
	}
	left, _ := filepath.Glob(filepath.Join(cfg.HNCDir, "run", "alerts_seen.json.tmp*"))
	if len(left) != 0 {
		t.Fatalf("残留临时文件: %v", left)
	}
}

// v5.12: detectUnknownDevices 扫描期间别处写入账本的条目不得被旧快照覆盖。
func TestDetectUnknownDevices_MergesLedger(t *testing.T) {
	hnc := t.TempDir()
	cfg := NewConfig(hnc)
	cfg.DisableNotify = true
	os.MkdirAll(filepath.Join(hnc, "data"), 0o755)
	os.WriteFile(cfg.DevicesJSON, []byte(`{"aa:bb:cc:dd:ee:01":{"mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.2"}}`), 0o644)

	// 验证合并保存语义: 盘上已有的其它条目与 MarkedKnownAt 必须保留。
	if err := MarkKnown(cfg, "aa:bb:cc:dd:ee:99"); err != nil {
		t.Fatal(err)
	}
	n, err := detectUnknownDevices(cfg, DefaultConfig())
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	f := loadKnownLedger(cfg.KnownDevicesPath)
	if f.MACs["aa:bb:cc:dd:ee:99"] == nil || f.MACs["aa:bb:cc:dd:ee:99"].MarkedKnownAt == 0 {
		t.Fatal("已标记为已知的条目丢失")
	}
	if f.MACs["aa:bb:cc:dd:ee:01"] == nil {
		t.Fatal("新设备未写入账本")
	}
}
