package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppTier(t *testing.T) {
	cases := map[string]int{
		"video": TierApp, "game": TierApp, "": TierApp, "p2p-bytedance-inferred": TierApp,
		"ads": TierHidden, "ad-sdk": TierHidden, "sdk-tencent-game": TierHidden, "cdn": TierHidden,
		"cloud": TierHidden, "third_party_telemetry": TierHidden, "infrastructure": TierHidden,
		"system": TierSystem, "system-xiaomi": TierSystem, "system_chipset": TierHidden,
	}
	for c, want := range cases {
		if got := AppTier(c); got != want {
			t.Errorf("AppTier(%q) = %d, want %d", c, got, want)
		}
	}
}

// v5.14: SDK 命中不抢走近期真应用的 IP; 过了保护期或同为真应用时照常覆盖。
func TestIPAppMapKeepsRealApp(t *testing.T) {
	m := NewIPAppMap()
	m.Record("1.2.3.4", "douyin", "抖音", "video", 1000, "tls")
	m.Record("1.2.3.4", "umeng", "友盟", "third_party_telemetry", 1050, "tls")
	if e := m.entries["1.2.3.4"]; e.AppID != "douyin" {
		t.Fatalf("SDK overwrote real app: %+v", e)
	}
	m.Record("1.2.3.4", "bilibili", "哔哩哔哩", "video", 1060, "tls")
	if e := m.entries["1.2.3.4"]; e.AppID != "bilibili" {
		t.Fatalf("real app should overwrite: %+v", e)
	}
	m.Record("1.2.3.4", "umeng", "友盟", "third_party_telemetry", 1060+ipAppKeepRealSec+1, "tls")
	if e := m.entries["1.2.3.4"]; e.AppID != "umeng" || e.Category != "third_party_telemetry" {
		t.Fatalf("stale real app should yield: %+v", e)
	}
}

func TestIPNameFlushCarriesApp(t *testing.T) {
	tb := NewIPNameTable()
	p := filepath.Join(t.TempDir(), "dpi_ipname.json")
	tb.SetPath(p)
	now := time.Unix(1_800_000_000, 0)
	tb.RecordDNS("upos-sz-mirrorcos.bilivideo.com", []string{"9.9.9.9"}, 300, now)
	tb.RecordDNS("unknown.example.org", []string{"8.8.4.4"}, 300, now)
	if err := tb.Flush(now); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var f ipNameFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if e := f.Entries["9.9.9.9"]; e.App != "bilibili" || e.Category != "video" || e.AppName == "" {
		t.Fatalf("bilibili entry not classified: %+v", e)
	}
	if e := f.Entries["8.8.4.4"]; e.App != "" {
		t.Fatalf("unknown host must stay unclassified: %+v", e)
	}
}
