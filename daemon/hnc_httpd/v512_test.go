package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// v5.12: bcrypt 结果缓存 —— 相同 cookie 命中; token 换密钥(Hash 变)或过期即失效。
func TestVerifyCacheInvalidatesOnHashChange(t *testing.T) {
	var k [32]byte
	k[0] = 7
	verifyCachePut(k, "tid", "hashA")
	if !verifyCacheHit(k, "tid", "hashA") {
		t.Fatal("expected hit")
	}
	if verifyCacheHit(k, "tid", "hashB") {
		t.Fatal("hash changed must miss")
	}
	verifyCachePut(k, "tid", "hashA")
	verifyCacheMu.Lock()
	e := verifyCache[k]
	e.expires = time.Now().Add(-time.Second)
	verifyCache[k] = e
	verifyCacheMu.Unlock()
	if verifyCacheHit(k, "tid", "hashA") {
		t.Fatal("expired entry must miss")
	}
}

// v5.12: SaveLoop 只在有变化时写盘; 1 分钟内重复访问不标脏。
func TestTokensFlushIfDirty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "remote_tokens.json")
	s := NewTokensStore(path)
	s.mu.Lock()
	s.tokens["abc"] = Token{LastSeen: time.Now().Unix()}
	s.dirty = false
	s.mu.Unlock()
	s.UpdateLastSeen("abc") // < 60s: 不标脏
	if err := s.FlushIfDirty(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("clean store must not write file")
	}
	s.mu.Lock()
	tok := s.tokens["abc"]
	tok.LastSeen -= 120
	s.tokens["abc"] = tok
	s.mu.Unlock()
	s.UpdateLastSeen("abc")
	if err := s.FlushIfDirty(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("dirty store must write file")
	}
}

func TestHotspotScheduleSetValidation(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []map[string]string{
		{"time_enable": "yes"},
		{"start": "25:00"},
		{"time_enable": "true", "start": "08:00"},
	} {
		if r := actionHotspotScheduleSet(dir, p); r.OK || r.Error != "bad params" {
			t.Fatalf("%v should be rejected, got %+v", p, r)
		}
	}
	for _, d := range []string{"-1", "abc", "99999"} {
		if r := actionStaleTTLSet(dir, map[string]string{"days": d}); r.OK {
			t.Fatalf("days=%s should be rejected", d)
		}
	}
}
