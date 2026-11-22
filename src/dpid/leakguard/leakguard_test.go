package leakguard

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
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

func TestEngine64BitAtomicHeadAlignment(t *testing.T) {
	var z Engine
	fields := []struct {
		name string
		off  uintptr
		want uintptr
	}{
		{"droppedCount", unsafe.Offsetof(z.droppedCount), 0},
		{"submittedCount", unsafe.Offsetof(z.submittedCount), 8},
		{"scannedCount", unsafe.Offsetof(z.scannedCount), 16},
		{"totalLeaks", unsafe.Offsetof(z.totalLeaks), 24},
		{"ignoredCount", unsafe.Offsetof(z.ignoredCount), 32},
		{"lastClearSeq", unsafe.Offsetof(z.lastClearSeq), 40},
		{"lastClearedAt", unsafe.Offsetof(z.lastClearedAt), 48},
		{"lastLazySyncUnix", unsafe.Offsetof(z.lastLazySyncUnix), 56},
	}
	for _, f := range fields {
		if f.off != f.want || f.off%8 != 0 {
			t.Fatalf("Engine.%s offset=%d want=%d (must be contiguous 8-byte aligned at struct head)", f.name, f.off, f.want)
		}
	}
	rt := reflect.TypeOf((*Engine)(nil)).Elem()
	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)
		if sf.Type == reflect.TypeOf((*atomic.Uint64)(nil)).Elem() || sf.Type == reflect.TypeOf((*atomic.Int64)(nil)).Elem() {
			if sf.Offset%8 != 0 {
				t.Fatalf("Engine.%s (%s) at offset=%d is not 8-byte aligned for 32-bit ARM", sf.Name, sf.Type, sf.Offset)
			}
		}
	}
}

func TestTombstoneAntiResurrectionAnd0600Permissions(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "run")
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Simulate ../data/leakguard_config.json holding a previously blocked domain and cold-start ignore rule.
	persistedJSON := `{"blocked_targets":{"resurrect.bad.example":true},"ignore_rules":[{"scope":"host_type","dst_host":"trusted.login.example","leak_type":"PHONE"}]}`
	if err := os.WriteFile(filepath.Join(dataDir, "leakguard_config.json"), []byte(persistedJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	ctrl0, err := ReadControl(runDir)
	if err != nil {
		t.Fatalf("ReadControl initial: %v", err)
	}
	if len(ctrl0.BlockedDomains) != 1 || ctrl0.BlockedDomains[0] != "resurrect.bad.example" {
		t.Fatalf("expected initial persisted domain merge, got %+v", ctrl0.BlockedDomains)
	}
	if len(ctrl0.IgnoreRules) != 1 || ctrl0.IgnoreRules[0].DstHost != "trusted.login.example" {
		t.Fatalf("expected cold-start ignore rule merge, got %+v", ctrl0.IgnoreRules)
	}

	// RemoveBlockedDomain must record BlockedTargets["resurrect.bad.example"]=false tombstone
	// so ReadControl never resurrects it from ../data/leakguard_config.json.
	afterRm, err := RemoveBlockedDomain(runDir, "resurrect.bad.example")
	if err != nil {
		t.Fatalf("RemoveBlockedDomain: %v", err)
	}
	if active, exists := afterRm.BlockedTargets["resurrect.bad.example"]; !exists || active {
		t.Fatalf("expected false tombstone in BlockedTargets, got %+v", afterRm.BlockedTargets)
	}
	ctrlAfter, err := ReadControl(runDir)
	if err != nil {
		t.Fatalf("ReadControl after remove: %v", err)
	}
	if len(ctrlAfter.BlockedDomains) != 0 {
		t.Fatalf("unblocked domain resurrected from data/leakguard_config.json: %+v", ctrlAfter.BlockedDomains)
	}

	eng := NewEngine(runDir)
	defer eng.Close()
	if eng.IsDomainBlocked("resurrect.bad.example") {
		t.Fatal("Engine still considers tombstoned domain blocked")
	}

	for _, p := range []string{CtrlPath(runDir), EventsPath(runDir)} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := st.Mode().Perm(); perm != 0o600 {
			t.Fatalf("file %s mode=%04o, want 0600", p, perm)
		}
	}
}

func TestIgnoreWhitelistGuardrailsPurgeAndZeroCount(t *testing.T) {
	forbidden := []string{
		"", "*", "*.qq.com", "a.*.example.com",
		"0.0.0.0/0", "1.2.3.0/24", "2001:db8::/32", "example.com/path",
		"127.0.0.1", "::1", "0.0.0.0", "::", "192.168.1.1", "10.0.0.8", "172.16.5.4",
		"169.254.1.2", "255.255.255.255", "100.64.1.1",
		"com", "cn", "net", "org", "localhost",
		"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.uk", "org.uk",
	}
	for _, bad := range forbidden {
		if _, _, err := ValidateIgnoreTarget(bad); err == nil {
			t.Fatalf("ValidateIgnoreTarget(%q) unexpectedly succeeded; P0 guardrail must reject it", bad)
		}
	}

	allowed := []string{
		"login.example.com", "portal.school.edu.cn", "api.shop.com.cn", "news.bbc.co.uk",
		"203.0.113.88", "2001:db8:abcd::99",
	}
	for _, okHost := range allowed {
		if _, _, err := ValidateIgnoreTarget(okHost); err != nil {
			t.Fatalf("ValidateIgnoreTarget(%q) failed unexpectedly: %v", okHost, err)
		}
	}

	runDir := t.TempDir()
	eng := NewEngine(runDir)
	defer eng.Close()

	var alertHits int
	eng.SetAlertHook(func(LeakEvent) { alertHits++ })

	t0 := time.Unix(1763550000, 0)
	// Seed three distinct events across two devices and two types before adding whitelist rules.
	_, _ = eng.ProcessSync(PacketInput{
		Time:       t0,
		ClientMAC:  "aa:bb:cc:dd:ee:01",
		ClientIP:   "192.168.43.10",
		DstIP:      "203.0.113.10",
		RawPayload: []byte("GET /a?phone=13800138001&oaid=a1b2c3d4-e5f6-7890-abcd-ef1234567890 HTTP/1.1\r\nHost: sub.corp.com.cn\r\n\r\n"),
	})
	_, _ = eng.ProcessSync(PacketInput{
		Time:       t0.Add(time.Second),
		ClientMAC:  "aa:bb:cc:dd:ee:02",
		ClientIP:   "192.168.43.11",
		DstIP:      "203.0.113.11",
		RawPayload: []byte("GET /b?phone=13900139002 HTTP/1.1\r\nHost: devonly.example.com\r\n\r\n"),
	})
	if eng.Ring().Len() != 3 || eng.TotalLeaks() != 3 || alertHits != 3 {
		t.Fatalf("unexpected seed state: ring=%d total=%d alerts=%d", eng.Ring().Len(), eng.TotalLeaks(), alertHits)
	}

	// Add host_type rule for corp.com.cn PHONE and device_host_type rule for mac 02 on devonly.example.com PHONE.
	r1, err := NormalizeIgnoreRule(IgnoreRule{Scope: ScopeHostType, DstHost: "corp.com.cn", LeakType: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := NormalizeIgnoreRule(IgnoreRule{
		Scope:    ScopeDeviceHostType,
		MAC:      "AA:BB:CC:DD:EE:02",
		DstHost:  "devonly.example.com",
		LeakType: "PHONE",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateControl(runDir, func(c *ControlState) {
		c.IgnoreRules = []IgnoreRule{r1, r2}
	}); err != nil {
		t.Fatal(err)
	}
	if !eng.SyncControl() {
		t.Fatal("expected SyncControl to apply new ignore rules and purge matching ring entries")
	}

	// PurgeIgnored should have evicted the two PHONE events while preserving the OAID DEVICE_ID event!
	rem := eng.Ring().Snapshot()
	if len(rem) != 1 || rem[0].LeakType != TypeDeviceID {
		t.Fatalf("expected only DEVICE_ID event to remain after PurgeIgnored, got %+v", rem)
	}

	// Subsequent matching packets must NOT enter ring, NOT increment TotalLeaks, and NOT fire alert hook.
	prevTotal := eng.TotalLeaks()
	prevAlerts := alertHits
	evsIgnored, newIgnored := eng.ProcessSync(PacketInput{
		Time:       t0.Add(10 * time.Second),
		ClientMAC:  "aa:bb:cc:dd:ee:01",
		RawPayload: []byte("GET /a?phone=13800138009 HTTP/1.1\r\nHost: login.corp.com.cn\r\n\r\n"),
	})
	if len(evsIgnored) != 0 || newIgnored != 0 || eng.TotalLeaks() != prevTotal || alertHits != prevAlerts || eng.IgnoredCount() != 1 {
		t.Fatalf("ignored packet leaked into stats: evs=%+v new=%d total=%d alerts=%d ignored=%d",
			evsIgnored, newIgnored, eng.TotalLeaks(), alertHits, eng.IgnoredCount())
	}

	// Different device (mac 01) hitting devonly.example.com must NOT be ignored by mac 02's device_host_type rule.
	evsOtherDev, newOther := eng.ProcessSync(PacketInput{
		Time:       t0.Add(15 * time.Second),
		ClientMAC:  "aa:bb:cc:dd:ee:01",
		RawPayload: []byte("GET /b?phone=13700137007 HTTP/1.1\r\nHost: devonly.example.com\r\n\r\n"),
	})
	if len(evsOtherDev) != 1 || newOther != 1 {
		t.Fatalf("device_host_type rule over-matched unrelated device: evs=%+v new=%d", evsOtherDev, newOther)
	}
}

func TestEngineSetIdleCheckThrottleAndPacketLazySync(t *testing.T) {
	runDir := t.TempDir()
	eng := NewEngine(runDir)

	var idle atomic.Bool
	idle.Store(true)
	eng.SetIdleCheck(func() bool { return idle.Load() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng.Start(ctx)
	defer eng.Close()

	// 1. In idle standby (ctrlTk=60s), updating leakguard_ctrl.json without packets
	// must NOT be polled at the 1s active cadence.
	if _, err := AddBlockedDomain(runDir, "standby-lazy.example"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1300 * time.Millisecond)
	if eng.IsDomainBlocked("api.standby-lazy.example") {
		t.Fatal("expected 1s ctrlTk polling to be suppressed while SetIdleCheck returns true")
	}

	// 2. First incoming packet on async queue (processJob) must lazily sync control
	// via lastLazySyncUnix CAS before scanning, tagging the very first alert Blocked=true.
	req := []byte("GET /hit?phone=13800138000 HTTP/1.1\r\nHost: api.standby-lazy.example\r\n\r\n")
	if !eng.SubmitPacket("3c:22:fb:11:22:33", "192.168.43.20", "203.0.113.55", 80, "GET", "/hit", "api.standby-lazy.example", "TestUA", req, time.Now()) {
		t.Fatal("SubmitPacket failed unexpectedly")
	}
	deadline := time.Now().Add(time.Second)
	for eng.ScannedCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !eng.IsDomainBlocked("api.standby-lazy.example") {
		t.Fatal("expected first packet in processJob to lazily SyncControl")
	}
	evs := eng.Ring().Snapshot()
	if len(evs) != 1 || !evs[0].Blocked || !evs[0].IsBlocked {
		t.Fatalf("expected first packet to see Blocked=true with zero lag, got %+v", evs)
	}

	// 3. CAS 1s throttle on ProcessSync: within the same Unix second, lazy sync is skipped;
	// once >1s has elapsed since lastLazySyncUnix, ProcessSync immediately syncs.
	if _, err := AddBlockedDomain(runDir, "cas-throttle.example"); err != nil {
		t.Fatal(err)
	}
	pinnedSec := time.Now().Unix()
	eng.lastLazySyncUnix.Store(pinnedSec)
	_, _ = eng.ProcessSync(PacketInput{
		Time:       time.Now(),
		ClientMAC:  "3c:22:fb:11:22:33",
		RawPayload: []byte("GET /benign HTTP/1.1\r\nHost: cas-throttle.example\r\n\r\n"),
	})
	if time.Now().Unix() == pinnedSec && eng.IsDomainBlocked("cas-throttle.example") {
		t.Fatal("expected CAS throttle to skip redundant SyncControl within the same Unix second")
	}

	// Simulate >1s elapsed since last SyncControl -> ProcessSync must immediately sync.
	eng.lastLazySyncUnix.Store(time.Now().Unix() - 2)
	evsSync, _ := eng.ProcessSync(PacketInput{
		Time:       time.Now(),
		ClientMAC:  "3c:22:fb:11:22:33",
		DstHost:    "sub.cas-throttle.example",
		RawPayload: []byte("GET /p?phone=13912345678 HTTP/1.1\r\nHost: sub.cas-throttle.example\r\n\r\n"),
	})
	if !eng.IsDomainBlocked("sub.cas-throttle.example") || len(evsSync) != 1 || !evsSync[0].Blocked {
		t.Fatalf("expected ProcessSync after >1s to lazy-sync and mark Blocked=true, got %+v", evsSync)
	}

	// 4. Resuming active state (idle=false) resets ctrlTk back to 1s immediately on wakeup.
	idle.Store(false)
	prevScanned := eng.ScannedCount()
	benign := []byte("GET /wake HTTP/1.1\r\nHost: example.org\r\n\r\n")
	eng.SubmitPacket("3c:22:fb:11:22:33", "192.168.43.20", "203.0.113.1", 80, "GET", "/wake", "example.org", "", benign, time.Now())
	wakeDeadline := time.Now().Add(500 * time.Millisecond)
	for eng.ScannedCount() <= prevScanned && time.Now().Before(wakeDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := AddBlockedDomain(runDir, "active-resumed.example"); err != nil {
		t.Fatal(err)
	}
	resumedDeadline := time.Now().Add(1800 * time.Millisecond)
	for !eng.IsDomainBlocked("active-resumed.example") && time.Now().Before(resumedDeadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if !eng.IsDomainBlocked("active-resumed.example") {
		t.Fatal("expected ctrlTk to reset back to 1s once SetIdleCheck returns false")
	}
}
