package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestDpiHistoryRC2DualDirPreferData(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "data", "dpi_history"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)

	now := time.Now()
	todayUTC := now.UTC().Format("20060102")
	ydayTs := now.Add(-24 * time.Hour)
	ydayUTC := ydayTs.UTC().Format("20060102")

	// Yesterday only in run/ (fallback), today in BOTH data/dpi_history and run/ (must prefer data/dpi_history without double-counting)
	_ = os.WriteFile(filepath.Join(dir, "run", "stats."+ydayUTC+".jsonl"),
		[]byte(fmt.Sprintf(`{"t":%d,"mac":"aa:bb:cc:00:00:01","app":"微信","tx":100,"rx":200}`+"\n", ydayTs.Unix())), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "stats."+todayUTC+".jsonl"),
		[]byte(fmt.Sprintf(`{"t":%d,"mac":"aa:bb:cc:00:00:01","app":"微信","tx":9999,"rx":9999}`+"\n", now.Add(-time.Minute).Unix())), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data", "dpi_history", "stats."+todayUTC+".jsonl"),
		[]byte(fmt.Sprintf(`{"t":%d,"mac":"aa:bb:cc:00:00:01","app":"微信","tx":300,"rx":400}`+"\n", now.Add(-time.Minute).Unix())), 0o644)

	s := newServer(dir)
	rec := httptest.NewRecorder()
	s.apiDPIHistory(rec, httptest.NewRequest("GET", "/api/dpi_history?days=2", nil))
	var out struct {
		TotalTX uint64 `json:"total_tx"`
		TotalRX uint64 `json:"total_rx"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode apiDPIHistory: %v (%s)", err, rec.Body.String())
	}
	if out.TotalTX != 400 || out.TotalRX != 600 {
		t.Fatalf("dual-dir merge mismatch: got tx=%d rx=%d (body=%s), want tx=400 rx=600", out.TotalTX, out.TotalRX, rec.Body.String())
	}
}

