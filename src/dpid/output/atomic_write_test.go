package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// v5.12: 并发 atomicWrite 同一路径, 结果必须恰为某一个写者的完整内容,
// 不得出现"新内容 + 旧内容尾巴"的交错(旧实现共用 path+".tmp")。
func TestAtomicWrite_ConcurrentNoInterleave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dpi_state.json")
	payloads := make([][]byte, 8)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte('a' + i)}, 1000*(8-i)+1)
	}
	for round := 0; round < 50; round++ {
		var wg sync.WaitGroup
		for _, p := range payloads {
			wg.Add(1)
			go func(p []byte) {
				defer wg.Done()
				_ = atomicWrite(path, p, 0o644)
			}(p)
		}
		wg.Wait()
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		ok := false
		for _, p := range payloads {
			if bytes.Equal(got, p) {
				ok = true
				break
			}
		}
		if !ok {
			t.Fatalf("round %d: 内容交错损坏 (len=%d)", round, len(got))
		}
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("残留临时文件 %s", e.Name())
		}
	}
}
