package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hnc.io/dpid/output"
)

func TestHistorySamplerCancellationFlushesUnfinishedInterval(t *testing.T) {
	old := output.HistoryDir
	output.HistoryDir = t.TempDir()
	defer func() { output.HistoryDir = old }()
	w := output.NewWriter("unused", "test")
	ipt := output.NewIPNameTable()
	w.SetIPNameTable(ipt)
	now := time.Now()
	ip := "203.0.113.9"
	ipt.RecordDNS("upos-sz-mirrorcos.bilivideo.com", []string{ip}, 300, now)
	mac := "aa:bb:cc:dd:ee:01"
	w.RecordDNS(mac, "192.168.43.20", "192.168.43.1", "example.org", now)
	h := output.NewHistorySampler(w)
	h.Tick(now)
	w.RecordFlow(mac, "192.168.43.20", ip, false, 443, 1500, false, now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runHistorySampler(ctx, h, time.Hour)
	files, err := filepath.Glob(filepath.Join(output.HistoryDir, "stats.*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("shutdown did not write history: files=%v err=%v", files, err)
	}
	b, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"rx":1500`) {
		t.Fatalf("unfinished interval missing from history: %s", b)
	}
}
