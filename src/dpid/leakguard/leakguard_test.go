package leakguard

import (
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"
	"time"
)

func findByType(evs []LeakEvent, leakType string) *LeakEvent {
	for i := range evs {
		if evs[i].LeakType == leakType {
			return &evs[i]
		}
	}
	return nil
}

func TestJSONScanDeepNestingKVPairsAndEscapes(t *testing.T) {
	dir := t.TempDir()
	eng := NewEngine(dir)
	defer eng.Close()

	body := `{"meta":{"sdk":"1.2.3456"},"data":{"user":{"mobile":"\u0031\u0033\u003800138000"}},"attrs":[{"k":"oaid","v":"a1b2c3d4-e5f6-7890-abcd-ef1234567890"},{"v":"490154203237518","k":"imei"},{"k":"imei","v":"123456789012345"},{"gameId":"987654321012"}]}`
	raw := "POST /v2/collect HTTP/1.1\r\nHost: track.ad-sdk.example.com:8080\r\nContent-Type: application/json\r\nUser-Agent: AdSDK/4.2\r\n\r\n" + body

	evs, newCnt := eng.ProcessSync(PacketInput{
		Time:       time.Unix(1763548800, 0),
		ClientMAC:  "3c:22:fb:11:22:33",
		ClientIP:   "192.168.43.20",
		DstIP:      "203.0.113.10",
		DstPort:    8080,
		RawPayload: []byte(raw),
	})
	if newCnt != 3 || len(evs) != 3 {
		t.Fatalf("expected 3 distinct leak alerts (PHONE + OAID + valid IMEI), got new=%d evs=%+v", newCnt, evs)
	}

	var gotPhone, gotOAID, gotIMEI bool
	for _, ev := range evs {
		if strings.Contains(ev.RawValue, "*") || strings.Contains(ev.RawSnippet, "***") {
			t.Fatalf("forbidden asterisk masking detected: %+v", ev)
		}
		switch {
		case ev.LeakType == TypePhone && ev.RawValue == "13800138000":
			gotPhone = true
		case ev.LeakType == TypeDeviceID && ev.RawValue == "a1b2c3d4-e5f6-7890-abcd-ef1234567890":
			gotOAID = true
		case ev.LeakType == TypeDeviceID && ev.RawValue == "490154203237518":
			gotIMEI = true
		case ev.RawValue == "123456789012345":
			t.Fatalf("non-Luhn serial number 123456789012345 must be rejected as IMEI")
		case ev.RawValue == "987654321012":
			t.Fatalf("gameId must not false-positive as meid DEVICE_ID")
		}
	}
	if !gotPhone || !gotOAID || !gotIMEI {
		t.Fatalf("missing expected detections: phone=%v oaid=%v imei=%v (evs=%+v)", gotPhone, gotOAID, gotIMEI, evs)
	}
}

func TestJSONScanMaxDepth12Guard(t *testing.T) {
	// Build a 16-level nested object (exceeding MaxJSONDepth=12) followed by a top-level sibling.
	var sb strings.Builder
	sb.WriteString(`{"deep":`)
	for i := 0; i < 15; i++ {
		sb.WriteString(`{"n":`)
	}
	sb.WriteString(`{"mobile":"13912345678"}`)
	for i := 0; i < 15; i++ {
		sb.WriteByte('}')
	}
	sb.WriteString(`,"shallow":{"mobile":"13700001111"}}`)

	found := map[string]bool{}
	ScanJSON([]byte(sb.String()), func(k, v string) {
		if k == "mobile" {
			found[v] = true
		}
	})
	if found["13912345678"] {
		t.Fatalf("depth > 12 value should have been skipped by MaxJSONDepth guard")
	}
	if !found["13700001111"] {
		t.Fatalf("sibling after skipped deep object must still be extracted")
	}
}

func TestGPSPrecisionNegativeAndVersionFilter(t *testing.T) {
	dir := t.TempDir()
	eng := NewEngine(dir)
	defer eng.Close()

	// Case 1: Only version numbers / fewer than 4 decimals / out-of-bounds -> zero GPS alert.
	badReq := "POST /loc HTTP/1.1\r\nHost: loc.example.com\r\nContent-Type: application/json\r\n\r\n" +
		`{"lat":"1.2.3456","lon":"121.473","sdk_ver":"16.0123"}`
	evs, _ := eng.ProcessSync(PacketInput{
		Time:       time.Unix(1763548810, 0),
		ClientMAC:  "aa:bb:cc:dd:ee:01",
		RawPayload: []byte(badReq),
	})
	if findByType(evs, TypeGPS) != nil {
		t.Fatalf("expected version/short-decimal coordinates to be filtered out, got %+v", evs)
	}

	// Case 2: Valid southern/western signed coordinates with >=4 decimals -> hits GPS.
	goodReq := "POST /loc HTTP/1.1\r\nHost: loc.example.com\r\nContent-Type: application/json\r\n\r\n" +
		`{"latitude":-33.868820,"longitude":151.209295}`
	evs2, _ := eng.ProcessSync(PacketInput{
		Time:       time.Unix(1763548820, 0),
		ClientMAC:  "aa:bb:cc:dd:ee:01",
		RawPayload: []byte(goodReq),
	})
	gpsEv := findByType(evs2, TypeGPS)
	if gpsEv == nil || gpsEv.RawValue != "-33.868820,151.209295" {
		t.Fatalf("expected valid signed GPS event, got %+v", evs2)
	}
}

func TestMACPercentDecodeKnownTableAndUUIDFilter(t *testing.T) {
	dir := t.TempDir()
	eng := NewEngine(dir)
	defer eng.Close()
	eng.RegisterKnownMAC("dc:a6:32:aa:bb:cc")

	// 1. %3A URL-encoded MAC in client_mac query param + random UUID in unrelated field.
	req1 := "GET /ping?trace=550e8400-e29b-41d4-a716-446655440000&client_mac=3C%3A22%3AFB%3A44%3A55%3A66 HTTP/1.1\r\nHost: iot.camera.example\r\n\r\n"
	evs1, _ := eng.ProcessSync(PacketInput{
		Time:       time.Unix(1763548830, 0),
		ClientMAC:  "aa:bb:cc:00:11:22",
		RawPayload: []byte(req1),
	})
	if len(evs1) != 1 || evs1[0].LeakType != TypeMACAddr || evs1[0].RawValue != "3C:22:FB:44:55:66" {
		t.Fatalf("expected percent-decoded MAC_ADDR, got %+v", evs1)
	}

	// 2. Unlabeled MAC in body: unknown MAC rejected, known downstream MAC accepted.
	req2 := "POST /raw HTTP/1.1\r\nHost: iot.camera.example\r\n\r\n" +
		`{"payload":"peer=12-34-56-78-9a-bc self=dc-a6-32-aa-bb-cc"}`
	evs2, _ := eng.ProcessSync(PacketInput{
		Time:       time.Unix(1763548835, 0),
		ClientMAC:  "aa:bb:cc:00:11:22",
		RawPayload: []byte(req2),
	})
	if len(evs2) != 1 || !strings.EqualFold(evs2[0].RawValue, "dc-a6-32-aa-bb-cc") {
		t.Fatalf("expected only known downstream MAC to trigger outside key context, got %+v", evs2)
	}
}

func TestGzipDecompressionAnd16KBBombLimit(t *testing.T) {
	dir := t.TempDir()
	eng := NewEngine(dir)
	defer eng.Close()

	// Construct a 120KB repetitive payload with phone at offset 0 and another phone at offset 120KB.
	var big strings.Builder
	big.WriteString(`{"mobile":"13688889999","pad":"`)
	big.WriteString(strings.Repeat("A", 120*1024))
	big.WriteString(`","user_phone":"13511112222"}`)

	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	_, _ = zw.Write([]byte(big.String()))
	_ = zw.Close()

	var pkt bytes.Buffer
	pkt.WriteString("POST /gz HTTP/1.1\r\nHost: gz.example.com\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\n\r\n")
	pkt.Write(gzBuf.Bytes())

	evs, _ := eng.ProcessSync(PacketInput{
		Time:       time.Unix(1763548840, 0),
		ClientMAC:  "3c:22:fb:11:22:33",
		RawPayload: pkt.Bytes(),
	})
	if len(evs) != 1 || evs[0].RawValue != "13688889999" {
		t.Fatalf("expected gzip prefix phone 13688889999 (and 120KB tail capped by 16KB LimitReader), got %+v", evs)
	}
}

func TestCooldownRingIPCAndAsyncNonBlockingQueue(t *testing.T) {
	dir := t.TempDir()
	eng := NewEngine(dir)

	baseTime := time.Unix(1763549000, 0)
	req := []byte("GET /collect?phone=13800138000 HTTP/1.1\r\nHost: sdk.bad.example\r\n\r\n")

	// First hit -> new alert (hit_count=1).
	evs1, new1 := eng.ProcessSync(PacketInput{Time: baseTime, ClientMAC: "3c:22:fb:11:22:33", RawPayload: req})
	if new1 != 1 || evs1[0].HitCount != 1 {
		t.Fatalf("first hit: new=%d evs=%+v", new1, evs1)
	}
	// Second hit within 300s cooldown -> aggregated (is_new_alert=false, hit_count=2).
	evs2, new2 := eng.ProcessSync(PacketInput{Time: baseTime.Add(120 * time.Second), ClientMAC: "3c:22:fb:11:22:33", RawPayload: req})
	if new2 != 0 || evs2[0].HitCount != 2 {
		t.Fatalf("cooldown hit: new=%d evs=%+v", new2, evs2)
	}
	// Hit after 301s -> new alert!
	evs3, new3 := eng.ProcessSync(PacketInput{Time: baseTime.Add(425 * time.Second), ClientMAC: "3c:22:fb:11:22:33", RawPayload: req})
	if new3 != 1 || evs3[0].HitCount != 1 {
		t.Fatalf("post-cooldown hit: new=%d evs=%+v", new3, evs3)
	}

	// Verify tmpfs mirror leakguard_events.json was written cleanly.
	snap, err := ReadEvents(dir)
	if err != nil || len(snap.Events) != 2 || snap.TotalLeaks != 3 {
		t.Fatalf("ReadEvents mismatch: err=%v snap=%+v", err, snap)
	}

	// Dynamic control sync: add blocked domain, resize to 32, and issue clear command.
	if _, err := AddBlockedDomain(dir, "bad.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateControl(dir, func(c *ControlState) {
		c.Capacity = 32
		c.CooldownSec = 60
	}); err != nil {
		t.Fatal(err)
	}
	if !eng.SyncControl() {
		t.Fatal("expected SyncControl to detect control update")
	}
	if eng.Ring().Capacity() != 32 || eng.Ring().CooldownSec() != 60 || !eng.IsDomainBlocked("sdk.bad.example") {
		t.Fatalf("control state not applied: cap=%d cd=%d blocked=%v",
			eng.Ring().Capacity(), eng.Ring().CooldownSec(), eng.IsDomainBlocked("sdk.bad.example"))
	}

	if _, err := RequestClear(dir); err != nil {
		t.Fatal(err)
	}
	if !eng.SyncControl() || eng.Ring().Len() != 0 {
		t.Fatalf("clear signal did not empty ring: len=%d", eng.Ring().Len())
	}

	// Non-blocking SubmitPacket queue overflow test (before Start, channel cap=256).
	oversized := append([]byte("GET /x?phone=13800138000 HTTP/1.1\r\nHost: a.com\r\nX-Pad: "), bytes.Repeat([]byte("Z"), 6000)...)
	accepted := 0
	for i := 0; i < 300; i++ {
		if eng.SubmitPacket("3c:22:fb:11:22:33", "192.168.43.20", "1.2.3.4", 8080, "GET", "/x", "a.com", "", oversized, baseTime) {
			accepted++
		}
	}
	if accepted != DefaultQueueCap || eng.DroppedCount() != 300-DefaultQueueCap {
		t.Fatalf("async backpressure mismatch: accepted=%d dropped=%d", accepted, eng.DroppedCount())
	}

	ctx, cancel := context.WithCancel(context.Background())
	eng.Start(ctx)
	cancel()
	_ = eng.Close()
	if eng.ScannedCount() < DefaultQueueCap {
		t.Fatalf("expected worker to drain all %d queued packets on shutdown, got %d", DefaultQueueCap, eng.ScannedCount())
	}
}
