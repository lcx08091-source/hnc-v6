package alert

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// v5.26 T7: Append 是 run/alerts.jsonl 追加的唯一权威实现。
// httpd 与看门狗两个进程会同时追加, 必须整行原子。

func TestAppendSingleLineJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "alerts.jsonl")
	for i := 0; i < 3; i++ {
		a := Alert{ID: fmt.Sprintf("x_%d", i), Ts: int64(i), Kind: "test", Detail: "hello"}
		if err := Append(p, a); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		var a Alert
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			t.Fatalf("line %d not valid JSON: %v (%q)", n, err, sc.Text())
		}
		if a.ID != fmt.Sprintf("x_%d", n) {
			t.Fatalf("line %d ID=%q", n, a.ID)
		}
		n++
	}
	if n != 3 {
		t.Fatalf("got %d lines, want 3", n)
	}
}

// TestAppendConcurrent 20 goroutine × 50 条并发追加: 每行合法 JSON、总行数恰好 1000。
func TestAppendConcurrent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "alerts.jsonl")
	const W, N = 20, 50
	var wg sync.WaitGroup
	for w := 0; w < W; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < N; i++ {
				a := Alert{ID: fmt.Sprintf("w%d_i%d", w, i), Ts: int64(w*N + i), Kind: "test", Detail: fmt.Sprintf("worker %d item %d", w, i)}
				if err := Append(p, a); err != nil {
					t.Errorf("Append: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		if sc.Text() == "" {
			continue
		}
		var a Alert
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			t.Fatalf("line %d corrupted (not valid JSON): %v (%q)", n, err, sc.Text())
		}
		if seen[a.ID] {
			t.Fatalf("duplicate ID %s", a.ID)
		}
		seen[a.ID] = true
		n++
	}
	if n != W*N {
		t.Fatalf("got %d lines, want %d", n, W*N)
	}
}
