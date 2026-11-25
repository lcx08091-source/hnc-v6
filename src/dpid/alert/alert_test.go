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

func TestClearAndPurgeLeakGuard_AtomicAndSelective(t *testing.T) {
	cfg := NewConfig(t.TempDir())
	seed := []Alert{
		{ID: "ud_1", Ts: 1700000001, Kind: "unknown_device", MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.2", Detail: "Pad"},
		{ID: "lg_1", Ts: 1700000002, Kind: "leakguard", Detail: "bad sid", Extra: map[string]interface{}{"dst_host": "amdc.aliyun.com"}},
		{ID: "lg_2", Ts: 1700000003, Kind: "leakguard", Detail: "real leak", Extra: map[string]interface{}{"dst_host": "evil.example"}},
	}
	for _, a := range seed {
		if err := Append(cfg.AlertsJSONLPath, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := MarkSeen(cfg, []string{"ud_1", "lg_1", "lg_2"}); err != nil {
		t.Fatal(err)
	}

	// Selective PurgeLeakGuard keeps unknown_device and matching leakguard alerts, removes lg_1 from log and seen set.
	if err := PurgeLeakGuard(cfg, func(a Alert) bool { return a.ID != "lg_1" }); err != nil {
		t.Fatal(err)
	}
	rem, err := ListRecent(cfg, 100)
	if err != nil || len(rem) != 2 {
		t.Fatalf("expected 2 remaining alerts, got len=%d err=%v (%+v)", len(rem), err, rem)
	}
	if rem[0].ID != "lg_2" || rem[1].ID != "ud_1" {
		t.Fatalf("unexpected remaining order/items: %+v", rem)
	}
	seenAfterPurge := LoadSeen(cfg)
	if _, ok := seenAfterPurge["lg_1"]; ok {
		t.Fatal("expected purged lg_1 to be removed from seen set")
	}
	if _, ok := seenAfterPurge["ud_1"]; !ok {
		t.Fatal("expected ud_1 to stay in seen set")
	}

	// Full PurgeLeakGuard(nil) drops remaining leakguard alerts while preserving unknown_device.
	if err := PurgeLeakGuard(cfg, nil); err != nil {
		t.Fatal(err)
	}
	rem2, err := ListRecent(cfg, 100)
	if err != nil || len(rem2) != 1 || rem2[0].ID != "ud_1" {
		t.Fatalf("expected only ud_1 left after PurgeLeakGuard(nil), got %+v err=%v", rem2, err)
	}

	// Clear wipes both alerts.jsonl and alerts_seen.json cleanly without leaving temp files.
	if err := Clear(cfg); err != nil {
		t.Fatal(err)
	}
	rem3, err := ListRecent(cfg, 100)
	if err != nil || len(rem3) != 0 {
		t.Fatalf("expected empty alerts after Clear, got %+v err=%v", rem3, err)
	}
	if len(LoadSeen(cfg)) != 0 {
		t.Fatalf("expected empty seen set after Clear, got %+v", LoadSeen(cfg))
	}
	left, _ := filepath.Glob(filepath.Join(cfg.HNCDir, "run", "*.tmp*"))
	if len(left) != 0 {
		t.Fatalf("unexpected leftover temp files: %v", left)
	}
}
