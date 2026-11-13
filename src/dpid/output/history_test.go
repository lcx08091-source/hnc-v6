package output

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func historyFixture(t *testing.T) (*HistorySampler, *labelStat) {
	t.Helper()
	old := HistoryDir
	HistoryDir = t.TempDir()
	t.Cleanup(func() { HistoryDir = old })
	w := NewWriter("unused", "test")
	mac := "aa:bb:cc:dd:ee:01"
	w.RecordDNS(mac, "192.168.43.2", "192.168.43.1", "example.com", time.Now())
	label := &labelStat{Name: "Test", Category: "video"}
	w.clients[mac].Apps["test"] = label
	return NewHistorySampler(w), label
}

func readHistorySamples(t *testing.T, path string) []historySample {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []historySample
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var row historySample
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		out = append(out, row)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func failHistoryDirectory(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	HistoryDir = path
}

func TestHistoryRetriesFailedBatchWithoutLosingOrDuplicatingBytes(t *testing.T) {
	h, label := historyFixture(t)
	dir := HistoryDir
	now := time.Now().UTC().Truncate(24 * time.Hour).Add(23*time.Hour + 30*time.Minute)
	h.Tick(now)
	label.TxBytes, label.RxBytes = 100, 200
	failHistoryDirectory(t)
	failedAt := now.Add(15 * time.Minute)
	h.Tick(failedAt)
	if h.pending == nil || !h.lastTick.Equal(now) {
		t.Fatal("failed write committed its baseline or lost its batch")
	}
	label.TxBytes, label.RxBytes = 160, 230
	HistoryDir = dir
	retryAt := now.Add(45 * time.Minute) // next UTC day
	h.Tick(retryAt)
	previous := readHistorySamples(t, h.pathFor(failedAt))
	current := readHistorySamples(t, h.pathFor(retryAt))
	if len(previous) != 1 || previous[0].TX != 100 || previous[0].RX != 200 || previous[0].Ts != failedAt.Unix() {
		t.Fatalf("failed interval/date changed: %+v", previous)
	}
	if len(current) != 1 || current[0].TX != 60 || current[0].RX != 30 {
		t.Fatalf("retry duplicated or lost increments: %+v", current)
	}
	h.Tick(retryAt.Add(time.Second))
	if rows := readHistorySamples(t, h.pathFor(retryAt)); len(rows) != 1 {
		t.Fatalf("unchanged counters duplicated rows: %+v", rows)
	}
}

func TestHistoryRetainsFailedBatchAfterClientEviction(t *testing.T) {
	h, label := historyFixture(t)
	dir := HistoryDir
	now := time.Now()
	h.Tick(now)
	label.TxBytes = 100
	failHistoryDirectory(t)
	h.Tick(now.Add(time.Minute))
	for k := range h.w.clients {
		delete(h.w.clients, k)
	}
	HistoryDir = dir
	h.Tick(now.Add(2 * time.Minute))
	rows := readHistorySamples(t, h.pathFor(now.Add(time.Minute)))
	if len(rows) != 1 || rows[0].TX != 100 {
		t.Fatalf("evicted client's failed interval lost: %+v", rows)
	}
}

func TestHistoryRetainsFailedBatchAfterCounterReset(t *testing.T) {
	h, label := historyFixture(t)
	dir := HistoryDir
	now := time.Now()
	h.Tick(now)
	label.TxBytes = 100
	failHistoryDirectory(t)
	h.Tick(now.Add(time.Minute))
	label.TxBytes = 0
	HistoryDir = dir
	h.Tick(now.Add(2 * time.Minute))
	label.TxBytes = 25
	h.Tick(now.Add(3 * time.Minute))
	rows := readHistorySamples(t, h.pathFor(now.Add(time.Minute)))
	var total uint64
	for _, row := range rows {
		total += row.TX
	}
	if total != 125 {
		t.Fatalf("old failed interval or post-reset increment lost: total=%d rows=%+v", total, rows)
	}
}
