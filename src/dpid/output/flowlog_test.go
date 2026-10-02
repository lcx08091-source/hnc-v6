package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func testFlowLog(t *testing.T) *FlowLog {
	l := NewFlowLog()
	l.SetPath(filepath.Join(t.TempDir(), "dpi_flows.json"))
	l.classify = func(host string) (string, string, string, bool) {
		if host == "api.example-app.com" {
			return "example_app", "示例", "video", true
		}
		return "", "", "", false
	}
	return l
}

func TestFlowLogRecordAndKey(t *testing.T) {
	l := testFlowLog(t)
	now := time.Unix(1_700_000_000, 0)
	l.Record("aa:bb:cc:dd:ee:01", "192.168.43.5", 40000, "203.0.113.9", 443, false,
		"t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb", []string{"h2", "http/1.1"}, "API.example-app.com.", now)
	l.Record("aa:bb:cc:dd:ee:01", "2001:db8:0:0::5", 50000, "2001:db8::9", 443, true,
		"q13d0310h3_cccccccccccc_dddddddddddd", []string{"h3"}, "cloudflare-ech.com", now)
	l.Record("aa:bb:cc:dd:ee:01", "192.168.43.5", 40001, "203.0.113.9", 443, false, "", nil, "x.com", now) // 无 JA4 不记
	got := l.Snapshot(now)
	if len(got) != 2 {
		t.Fatalf("want 2 records, got %d", len(got))
	}
	a := got[0]
	if a.Proto != "tcp" || a.SNI != "api.example-app.com" || a.App != "example_app" || a.ALPN != "h2" || a.Seq != 1 {
		t.Fatalf("bad record: %+v", a)
	}
	if k := FlowKey(a.Proto, a.CIP, a.Sport, a.DIP, a.Dport); k != "tcp|192.168.43.5|40000|203.0.113.9|443" {
		t.Fatalf("key format: %s", k)
	}
	b := got[1]
	if b.Proto != "udp" || !b.ECHOuter || b.App != "" || b.CIP != "2001:db8::5" {
		t.Fatalf("ech/quic record: %+v", b)
	}
}

func TestFlowLogDedupAndBound(t *testing.T) {
	l := testFlowLog(t)
	l.max = 8
	now := time.Unix(1_700_000_000, 0)
	ja4 := "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"
	// 同五元组 + 同 JA4 重复(重传)只顺延
	l.Record("m", "10.0.0.2", 1000, "198.51.100.1", 443, false, ja4, nil, "", now)
	l.Record("m", "10.0.0.2", 1000, "198.51.100.1", 443, false, ja4, nil, "", now.Add(5*time.Second))
	if s := l.Snapshot(now.Add(5 * time.Second)); len(s) != 1 || s[0].Ts != now.Unix()+5 {
		t.Fatalf("dedup failed: %+v", s)
	}
	for i := 0; i < 50; i++ {
		l.Record("m", "10.0.0.2", 2000+i, "198.51.100.1", 443, false, ja4, nil, "", now.Add(time.Duration(i)*time.Second))
	}
	if l.Len() != 8 || len(l.idx) > 8 {
		t.Fatalf("ring not bounded: len=%d idx=%d", l.Len(), len(l.idx))
	}
	s := l.Snapshot(now.Add(60 * time.Second))
	if len(s) != 8 {
		t.Fatalf("snapshot len %d", len(s))
	}
	for i := 1; i < len(s); i++ {
		if s[i].Seq <= s[i-1].Seq {
			t.Fatalf("snapshot not seq-ordered")
		}
	}
	if s[len(s)-1].Sport != 2049 {
		t.Fatalf("newest should be last: %+v", s[len(s)-1])
	}
	// 老化: 超过 flowLogMaxAge 的不导出
	if s := l.Snapshot(now.Add(time.Duration(flowLogMaxAge+120) * time.Second)); len(s) != 0 {
		t.Fatalf("aged records exported: %d", len(s))
	}
}

func TestFlowLogFlush(t *testing.T) {
	l := testFlowLog(t)
	now := time.Unix(1_700_000_000, 0)
	if err := l.Flush(now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(l.path); !os.IsNotExist(err) {
		t.Fatalf("clean flush should not write")
	}
	for i := 0; i < 3; i++ {
		l.Record("m", "10.0.0.2", 3000+i, "198.51.100."+strconv.Itoa(i+1), 443, false, "t13d_x_y", []string{"h2"}, "", now)
	}
	if err := l.Flush(now); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(l.path)
	if err != nil {
		t.Fatal(err)
	}
	var f flowLogFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Schema != 1 || f.Seq != 3 || len(f.Flows) != 3 || f.Boot == 0 {
		t.Fatalf("bad file: %+v", f)
	}
}
