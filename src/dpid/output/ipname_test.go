package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIPNameDNSAndCNAME(t *testing.T) {
	tb := NewIPNameTable()
	// www.example.com → CNAME cdn.example.net → 两个 A + 一个 AAAA
	tb.RecordDNS("WWW.Example.com.", []string{"CNAME:cdn.example.net", "93.184.216.34", "93.184.216.35", "2606:2800:220:1::248", "0.0.0.0", "junk"}, 30, t0)
	for _, ip := range []string{"93.184.216.34", "93.184.216.35", "2606:2800:220:1::248"} {
		e, ok := tb.Lookup(ip, t0)
		if !ok || e.Name != "www.example.com" || e.Src != "dns" || e.Ts != t0.Unix() {
			t.Fatalf("%s → %+v ok=%v", ip, e, ok)
		}
	}
	if tb.Len() != 3 {
		t.Fatalf("len=%d (0.0.0.0 / junk / CNAME 应被跳过)", tb.Len())
	}
	// TTL 30s 也至少保留 10 分钟。
	if _, ok := tb.Lookup("93.184.216.34", t0.Add(9*time.Minute)); !ok {
		t.Fatal("entry should live >= 10 minutes")
	}
	if _, ok := tb.Lookup("93.184.216.34", t0.Add(11*time.Minute)); ok {
		t.Fatal("entry should expire after min TTL when DNS TTL is short")
	}
	// 长 TTL 按上限 1h 截断。
	tb.RecordDNS("long.example.com", []string{"1.1.1.1"}, 86400, t0)
	if _, ok := tb.Lookup("1.1.1.1", t0.Add(59*time.Minute)); !ok {
		t.Fatal("long TTL entry should live ~1h")
	}
	if _, ok := tb.Lookup("1.1.1.1", t0.Add(61*time.Minute)); ok {
		t.Fatal("long TTL should be capped at 1h")
	}
}

func TestIPNameSNIPriority(t *testing.T) {
	tb := NewIPNameTable()
	tb.RecordDNS("shared-cdn.example.com", []string{"10.9.8.7"}, 300, t0)
	tb.RecordSNI("10.9.8.7", "api.real-app.com", t0.Add(time.Second))
	if e, _ := tb.Lookup("10.9.8.7", t0.Add(2*time.Second)); e.Name != "api.real-app.com" || e.Src != "sni" {
		t.Fatalf("SNI should override DNS: %+v", e)
	}
	// 未过期的 SNI 不被 DNS 覆盖。
	tb.RecordDNS("other.example.com", []string{"10.9.8.7"}, 300, t0.Add(10*time.Second))
	if e, _ := tb.Lookup("10.9.8.7", t0.Add(11*time.Second)); e.Name != "api.real-app.com" {
		t.Fatalf("DNS must not override live SNI: %+v", e)
	}
	// SNI 过期(30 分钟)后 DNS 可以接管。
	later := t0.Add(31 * time.Minute)
	tb.RecordDNS("other.example.com", []string{"10.9.8.7"}, 300, later)
	if e, _ := tb.Lookup("10.9.8.7", later); e.Name != "other.example.com" || e.Src != "dns" {
		t.Fatalf("DNS should replace expired SNI: %+v", e)
	}
	// 非法 IP / 空 SNI 忽略。
	tb.RecordSNI("not-an-ip", "x.com", t0)
	tb.RecordSNI("8.8.8.8", "", t0)
	if _, ok := tb.Lookup("8.8.8.8", t0); ok {
		t.Fatal("empty SNI recorded")
	}
}

func TestIPNameLRUCap(t *testing.T) {
	tb := NewIPNameTable()
	for i := 0; i < ipNameMaxEntries+500; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)
		tb.RecordSNI(ip, fmt.Sprintf("h%d.example.com", i), t0)
	}
	if tb.Len() != ipNameMaxEntries {
		t.Fatalf("len=%d", tb.Len())
	}
	if _, ok := tb.Lookup("10.0.0.0", t0); ok {
		t.Fatal("oldest entry should be evicted")
	}
	last := ipNameMaxEntries + 499
	if _, ok := tb.Lookup(fmt.Sprintf("10.%d.%d.%d", last>>16&0xff, last>>8&0xff, last&0xff), t0); !ok {
		t.Fatal("newest entry missing")
	}
}

func TestIPNameFlush(t *testing.T) {
	tb := NewIPNameTable()
	p := filepath.Join(t.TempDir(), "dpi_ipname.json")
	tb.SetPath(p)
	// 空表且无变化: 不写文件。
	if err := tb.Flush(t0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("empty clean table should not write")
	}
	tb.RecordDNS("a.example.com", []string{"1.2.3.4"}, 60, t0)
	tb.RecordSNI("5.6.7.8", "b.example.com", t0)
	if err := tb.Flush(t0); err != nil {
		t.Fatal(err)
	}
	var f struct {
		Schema      int                    `json:"schema"`
		GeneratedAt int64                  `json:"generated_at"`
		Entries     map[string]IPNameEntry `json:"entries"`
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Schema != 1 || f.GeneratedAt != t0.Unix() || len(f.Entries) != 2 ||
		f.Entries["1.2.3.4"] != (IPNameEntry{Name: "a.example.com", Src: "dns", Ts: t0.Unix()}) ||
		f.Entries["5.6.7.8"] != (IPNameEntry{Name: "b.example.com", Src: "sni", Ts: t0.Unix()}) {
		t.Fatalf("file %s", b)
	}
	// 同一映射重复记录(ts 变化 < 60s)不算变化, 不重写。
	_ = os.Remove(p)
	tb.RecordDNS("a.example.com", []string{"1.2.3.4"}, 60, t0.Add(5*time.Second))
	if err := tb.Flush(t0.Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("unchanged table should not rewrite")
	}
	// 过期清理算变化, 会重写且条目消失。
	if err := tb.Flush(t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(p)
	f.Entries = nil // json.Unmarshal 会合并进已有 map, 先清空
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) != 0 || tb.Len() != 0 {
		t.Fatalf("expired entries not pruned: %s", b)
	}
}
