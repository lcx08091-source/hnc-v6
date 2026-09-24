package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReportableUnknown(t *testing.T) {
	for host, want := range map[string]bool{
		"api.brand-new-app.cn":          true,
		"":                              false,
		"localhost":                     false,
		"1.2.3.4":                       false,
		"2001:db8::1":                   false,
		"macbook.local":                 false,
		"4.3.2.1.in-addr.arpa":          false,
		"connectivitycheck.gstatic.com": false,
		"time.android.com":              false,
		"ntp.aliyun.com":                false,
		"cn.pool.ntp.org":               false,
		"wpad.lan":                      false,
	} {
		if got := reportableUnknown(host); got != want {
			t.Errorf("%q → %v want %v", host, got, want)
		}
	}
}

func TestTopUnknownInState(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dpi_state.json")
	w := NewWriter(p, "test")
	macA, macB := "aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02"
	// A: 30 个不同的未识别名, 其中 new0 出现最多
	for i := 0; i < 30; i++ {
		for j := 0; j <= 30-i; j++ {
			w.RecordDNS(macA, "192.168.43.10", "192.168.43.1", fmt.Sprintf("new%d.unknown-app.cn", i), t0)
		}
	}
	// B: 一个未识别 SNI + 被过滤的/能识别的名字
	w.RecordTLS(macB, "192.168.43.11", "1.2.3.4", "edge.mystery-cdn.io", "", t0)
	w.RecordDNS(macB, "192.168.43.11", "192.168.43.1", "connectivitycheck.gstatic.com", t0)
	w.RecordDNS(macB, "192.168.43.11", "192.168.43.1", "printer.local", t0)
	w.RecordDNS(macB, "192.168.43.11", "192.168.43.1", "www.youtube.com", t0) // builtin 规则命中
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.TopUnknown) != topUnknownGlobal {
		t.Fatalf("global top_unknown len=%d", len(st.TopUnknown))
	}
	if st.TopUnknown[0].Name != "new0.unknown-app.cn" || st.TopUnknown[0].Count != 31 {
		t.Fatalf("top[0]=%+v", st.TopUnknown[0])
	}
	for _, nc := range st.TopUnknown {
		if !reportableUnknown(nc.Name) || nc.Name == "www.youtube.com" {
			t.Fatalf("filtered/known name leaked: %q", nc.Name)
		}
	}
	a := st.Clients[macA]
	if len(a.TopUnknown) != topUnknownClient || a.TopUnknown[0].Name != "new0.unknown-app.cn" {
		t.Fatalf("client A top_unknown %+v", a.TopUnknown)
	}
	bcl := st.Clients[macB]
	if len(bcl.TopUnknown) != 1 || bcl.TopUnknown[0].Name != "edge.mystery-cdn.io" {
		t.Fatalf("client B top_unknown %+v", bcl.TopUnknown)
	}
	// 内存上限: 每客户端 maxNamesPerClient, 全局 maxGlobalNames。
	for i := 0; i < 400; i++ {
		w.RecordDNS(macA, "192.168.43.10", "192.168.43.1", fmt.Sprintf("flood%d.unknown-app.cn", i), t0)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if n := len(w.clients[macA].Unknown); n > maxNamesPerClient {
		t.Fatalf("per-client unknown=%d", n)
	}
	if n := len(w.globalUnknown); n > maxGlobalNames {
		t.Fatalf("global unknown=%d", n)
	}
}
