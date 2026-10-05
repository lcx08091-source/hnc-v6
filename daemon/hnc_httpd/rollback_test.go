// rollback_test.go — v5.29 T3: 回滚信息的转出与自检行。
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRollbackStatusNilWhenNoFile(t *testing.T) {
	s := &server{hncDir: t.TempDir()}
	if got := s.rollbackStatus(); got != nil {
		t.Fatalf("无 rollback.json 应 nil, got %+v", got)
	}
}

func TestRollbackStatusRecordAndAck(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "rollback.json"),
		[]byte(`{"from":"5280001","to":"5290001","reason":"failstreak=6","at":1791204231,"action":"rolled_back"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// rollback.pinned 存在 → pinned=true
	if err := os.WriteFile(filepath.Join(data, "rollback.pinned"), []byte("5290001"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &server{hncDir: dir}
	got := s.rollbackStatus()
	if got == nil || !got.Rolled || got.From != "5280001" || got.To != "5290001" {
		t.Fatalf("got %+v", got)
	}
	if !got.Pinned || got.Acknowledged {
		t.Fatalf("pinned=%v ack=%v, want true/false", got.Pinned, got.Acknowledged)
	}
	// ack 之后 acknowledged=true
	if err := os.WriteFile(filepath.Join(data, "rollback.ack"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := s.rollbackStatus(); got == nil || !got.Acknowledged {
		t.Fatalf("ack 后应 acknowledged, got %+v", got)
	}
}

func TestScRollbackItemStates(t *testing.T) {
	// 用现有 fakeSys 基建构造 scCtx(readJSON / Stat 走真文件)
	f := newFakeSys(t.TempDir())
	c := &scCtx{env: f.scEnv()}
	// readJSON 走 fakeSys 的文件表; os.Stat(ack) 走真文件 —— 两种都喂
	f.files[f.h("data", "rollback.json")] = `{"from":"5280001","to":"5290001","reason":"failstreak=6","at":1791204231,"action":"rolled_back"}`
	if it := scRollbackItem(c); it.Status != scWarn {
		t.Fatalf("未 ack 应 WARN, got %v", it.Status)
	}
	os.MkdirAll(f.h("data"), 0o755)
	os.WriteFile(f.h("data", "rollback.ack"), nil, 0o600)
	if it := scRollbackItem(c); it.Status != scOK {
		t.Fatalf("已 ack 应 OK, got %v", it.Status)
	}
}
