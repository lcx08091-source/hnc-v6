// rollback_test.go — v5.29 T3: 回滚信息的转出与自检行。
package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
		[]byte(`{"from":"5290001","to":"5280001","reason":"failstreak=6","at":1791204231,"action":"rolled_back"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// rollback.pinned 存在 → pinned=true
	if err := os.WriteFile(filepath.Join(data, "rollback.pinned"), []byte("5290001"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &server{hncDir: dir}
	got := s.rollbackStatus()
	if got == nil || !got.Rolled || got.From != "5290001" || got.To != "5280001" ||
		got.FromName != "5.29.0-rc1" || got.ToName != "5.28.0-rc1" {
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
	f.files[f.h("data", "rollback.json")] = `{"from":"5290001","to":"5280001","reason":"failstreak=6","at":1791204231,"action":"rolled_back"}`
	it := scRollbackItem(c)
	if it.Status != scWarn {
		t.Fatalf("未 ack 应 WARN, got %v", it.Status)
	}
	// rc1: from/to 读反(「检测到 5280001 启动失败, 已退回 5290001」), 且 action
	// 恒非空 → 回滚成功也追加「本次仅记录未回滚」
	if it.Value != "已自动退回 5.28.0-rc1" || !strings.Contains(it.Detail, "检测到 5.29.0-rc1 启动失败") ||
		strings.Contains(it.Detail, "仅记录") {
		t.Fatalf("rolled_back 文案不对: value=%q detail=%q", it.Value, it.Detail)
	}
	f.files[f.h("data", "rollback.json")] = `{"from":"5290001","to":"5280001","reason":"failstreak=6","at":1791204231,"action":"recorded_only"}`
	if it := scRollbackItem(c); !strings.Contains(it.Detail, "只记录未回滚") || strings.Contains(it.Value, "已自动退回") {
		t.Fatalf("recorded_only 文案不对: value=%q detail=%q", it.Value, it.Detail)
	}
	os.MkdirAll(f.h("data"), 0o755)
	os.WriteFile(f.h("data", "rollback.ack"), nil, 0o600)
	if it := scRollbackItem(c); it.Status != scOK {
		t.Fatalf("已 ack 应 OK, got %v", it.Status)
	}
}

func TestVcName(t *testing.T) {
	for in, want := range map[string]string{
		"5290001": "5.29.0-rc1",
		"5180000": "5.18.0",
		"5271002": "5.27.1-rc2",
		"6000000": "6.0.0",
		"6000001": "6.0.1",
		"6009101": "6.1.0-alpha.1",
		"6009201": "6.1.0-beta.1",
		"6009301": "6.1.0-rc.1",
		"6009302": "6.1.0-rc.2",
		"6009303": "6.1.0-rc.3",
		"6009304": "6.1.0-rc.4",
		"6009305": "6.1.0-rc.5",
		"6010000": "6.1.0",
		"6010002": "6.1.2",
		"6019203": "6.2.0-beta.3",
		"6009100": "6009100",
		"unknown": "unknown",
		"":        "",
		"52900x1": "52900x1",
		"-600001": "-600001",
	} {
		if got := vcName(in); got != want {
			t.Errorf("vcName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRollbackCorridorRC2And610(t *testing.T) {
	// 场景 1: 6009302 (6.1.0-rc.2) 启动失败自动退回黄金底包 6000001 (6.0.1)
	dir1 := t.TempDir()
	data1 := filepath.Join(dir1, "data")
	if err := os.MkdirAll(data1, 0o755); err != nil {
		t.Fatal(err)
	}
	rc2JSON := `{"from":"6009302","to":"6000001","reason":"failstreak=6 restarts=0","at":1795382400,"action":"rolled_back"}`
	if err := os.WriteFile(filepath.Join(data1, "rollback.json"), []byte(rc2JSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data1, "rollback.pinned"), []byte("6009302\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s1 := &server{hncDir: dir1}
	got1 := s1.rollbackStatus()
	if got1 == nil || !got1.Rolled || got1.From != "6009302" || got1.To != "6000001" ||
		got1.FromName != "6.1.0-rc.2" || got1.ToName != "6.0.1" || !got1.Pinned || got1.Acknowledged {
		t.Fatalf("rc.2 -> 6.0.1 rollbackStatus mismatch: %+v", got1)
	}

	f := newFakeSys(t.TempDir())
	c := &scCtx{env: f.scEnv()}
	f.files[f.h("data", "rollback.json")] = rc2JSON
	if it := scRollbackItem(c); it.Status != scWarn || it.Value != "已自动退回 6.0.1" ||
		!strings.Contains(it.Detail, "检测到 6.1.0-rc.2 启动失败") {
		t.Fatalf("rc.2 scRollbackItem mismatch: status=%v value=%q detail=%q", it.Status, it.Value, it.Detail)
	}

	// 场景 1b: 6009304 (6.1.0-rc.4) 启动失败自动退回黄金底包 6000001 (6.0.1)
	dirRC4 := t.TempDir()
	dataRC4 := filepath.Join(dirRC4, "data")
	if err := os.MkdirAll(dataRC4, 0o755); err != nil {
		t.Fatal(err)
	}
	rc4JSON := `{"from":"6009304","to":"6000001","reason":"failstreak=6 restarts=0","at":1795390000,"action":"rolled_back"}`
	if err := os.WriteFile(filepath.Join(dataRC4, "rollback.json"), []byte(rc4JSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataRC4, "rollback.pinned"), []byte("6009304\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sRC4 := &server{hncDir: dirRC4}
	gotRC4 := sRC4.rollbackStatus()
	if gotRC4 == nil || !gotRC4.Rolled || gotRC4.From != "6009304" || gotRC4.To != "6000001" ||
		gotRC4.FromName != "6.1.0-rc.4" || gotRC4.ToName != "6.0.1" || !gotRC4.Pinned || gotRC4.Acknowledged {
		t.Fatalf("rc.4 -> 6.0.1 rollbackStatus mismatch: %+v", gotRC4)
	}
	f.files[f.h("data", "rollback.json")] = rc4JSON
	if it := scRollbackItem(c); it.Status != scWarn || it.Value != "已自动退回 6.0.1" ||
		!strings.Contains(it.Detail, "检测到 6.1.0-rc.4 启动失败") {
		t.Fatalf("rc.4 scRollbackItem mismatch: status=%v value=%q detail=%q", it.Status, it.Value, it.Detail)
	}

	// 场景 1c: 当前候选版 6009305 (6.1.0-rc.5) 启动失败同样自动退回黄金底包 6000001 (6.0.1)
	dirRC5 := t.TempDir()
	dataRC5 := filepath.Join(dirRC5, "data")
	if err := os.MkdirAll(dataRC5, 0o755); err != nil {
		t.Fatal(err)
	}
	rc5JSON := `{"from":"6009305","to":"6000001","reason":"failstreak=6 restarts=0","at":1795400000,"action":"rolled_back"}`
	if err := os.WriteFile(filepath.Join(dataRC5, "rollback.json"), []byte(rc5JSON), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataRC5, "rollback.pinned"), []byte("6009305\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sRC5 := &server{hncDir: dirRC5}
	gotRC5 := sRC5.rollbackStatus()
	if gotRC5 == nil || !gotRC5.Rolled || gotRC5.From != "6009305" || gotRC5.To != "6000001" ||
		gotRC5.FromName != "6.1.0-rc.5" || gotRC5.ToName != "6.0.1" || !gotRC5.Pinned || gotRC5.Acknowledged {
		t.Fatalf("rc.5 -> 6.0.1 rollbackStatus mismatch: %+v", gotRC5)
	}
	f.files[f.h("data", "rollback.json")] = rc5JSON
	if it := scRollbackItem(c); it.Status != scWarn || it.Value != "已自动退回 6.0.1" ||
		!strings.Contains(it.Detail, "检测到 6.1.0-rc.5 启动失败") {
		t.Fatalf("rc.5 scRollbackItem mismatch: status=%v value=%q detail=%q", it.Status, it.Value, it.Detail)
	}

	// 场景 2: 6010000 (6.1.0 正式版) 回退至 6000001 (6.0.1) 与后续预发布回退至 6010000 (6.1.0)
	dir2 := t.TempDir()
	data2 := filepath.Join(dir2, "data")
	if err := os.MkdirAll(data2, 0o755); err != nil {
		t.Fatal(err)
	}
	gaJSON := `{"from":"6010000","to":"6000001","reason":"restarts=5","at":1795468800,"action":"rolled_back"}`
	if err := os.WriteFile(filepath.Join(data2, "rollback.json"), []byte(gaJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	s2 := &server{hncDir: dir2}
	got2 := s2.rollbackStatus()
	if got2 == nil || got2.FromName != "6.1.0" || got2.ToName != "6.0.1" {
		t.Fatalf("6.1.0 -> 6.0.1 rollbackStatus mismatch: %+v", got2)
	}
	f.files[f.h("data", "rollback.json")] = `{"from":"6019301","to":"6010000","reason":"failstreak=6","at":1795555200,"action":"rolled_back"}`
	if it := scRollbackItem(c); it.Status != scWarn || it.Value != "已自动退回 6.1.0" ||
		!strings.Contains(it.Detail, "检测到 6.2.0-rc.1 启动失败") {
		t.Fatalf("6.2.0-rc.1 -> 6.1.0 scRollbackItem mismatch: status=%v value=%q detail=%q", it.Status, it.Value, it.Detail)
	}
}

func TestRollbackAckRequiresMutation(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := newServer(dir)
	h := s.requireMutation(s.apiRollbackAck)

	// 缺少 Content-Type → 415
	req := httptest.NewRequest(http.MethodPost, "/api/rollback_ack", strings.NewReader("{}"))
	req.Header.Set("X-HNC-CSRF", "1")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("missing content-type status=%d, want 415", rec.Code)
	}

	// 缺少 CSRF header → 400
	req = httptest.NewRequest(http.MethodPost, "/api/rollback_ack", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing csrf status=%d, want 400", rec.Code)
	}

	// 合法 JSON + CSRF → 200 并写 rollback.ack
	req = httptest.NewRequest(http.MethodPost, "/api/rollback_ack", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HNC-CSRF", "1")
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid ack status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "rollback.ack")); err != nil {
		t.Fatalf("rollback.ack not written: %v", err)
	}
}
