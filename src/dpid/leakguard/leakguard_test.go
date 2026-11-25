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

func TestCredentialAndIDCardZeroFalsePositiveDetection(t *testing.T) {
	dir := t.TempDir()
	eng := NewEngine(dir)
	defer eng.Close()

	// Valid 3-part JWT: header={"alg":"HS256","typ":"JWT"}, payload={"sub":"10086","role":"admin"}
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDA4NiIsInJvbGUiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// 1. Authorization: Basic / Bearer + Cookie sid + Query api_key + Body password & JWT.
	req1 := "POST /v1/auth/login?api_key=ak_live_9988776655 HTTP/1.1\r\n" +
		"Host: auth.insecure.example\r\n" +
		"Authorization: Bearer bearer_secret_token_2026\r\n" +
		"Cookie: theme=dark; sid=sess_abcdef123456\r\n" +
		"Content-Type: application/json\r\n\r\n" +
		`{"password":"PlainPassword!99","password_required":true,"flag_pwd":{"password":true},"extra_jwt":"` + jwt + `","fake_jwt":"eyJnotjson.notjson.sig123456"}`

	evs1, n1 := eng.ProcessSync(PacketInput{
		Time:       time.Unix(1763600000, 0),
		Origin:     OriginHost,
		UID:        10234,
		Pkg:        "com.example.shop",
		AppName:    "示例商城",
		ClientIP:   "10.45.12.8",
		DstIP:      "203.0.113.66",
		DstPort:    80,
		RawPayload: []byte(req1),
	})
	if n1 != 5 || len(evs1) != 5 {
		t.Fatalf("expected 5 CREDENTIAL hits (api_key, Authorization Bearer, sid, password, JWT), got n=%d evs=%+v", n1, evs1)
	}
	wantCreds := map[string]bool{
		"ak_live_9988776655":                false,
		"Bearer bearer_secret_token_2026":   false,
		"sess_abcdef123456":                 false,
		"PlainPassword!99":                  false,
		jwt:                                 false,
	}
	for _, ev := range evs1 {
		if ev.LeakType != TypeCredential || ev.LeakLabel != "账号凭据/Token" {
			t.Fatalf("unexpected credential event type/label: %+v", ev)
		}
		if ev.Origin != OriginHost || ev.UID != 10234 || ev.Pkg != "com.example.shop" || ev.AppName != "示例商城" {
			t.Fatalf("host metadata mismatch: %+v", ev)
		}
		if strings.Contains(ev.RawValue, "*") || strings.Contains(ev.RawSnippet, "***") {
			t.Fatalf("forbidden masking in RawValue/RawSnippet: %+v", ev)
		}
		if _, ok := wantCreds[ev.RawValue]; !ok {
			t.Fatalf("unexpected false-positive credential value %q in %+v", ev.RawValue, ev)
		}
		wantCreds[ev.RawValue] = true
	}
	for k, seen := range wantCreds {
		if !seen {
			t.Fatalf("missing expected credential hit %q", k)
		}
	}

	// Short Authorization (<8 token chars) must NOT trigger.
	reqShortAuth := "GET /ping HTTP/1.1\r\nHost: auth.insecure.example\r\nAuthorization: Bearer short7\r\n\r\n"
	if evsShort, _ := eng.ProcessSync(PacketInput{RawPayload: []byte(reqShortAuth)}); len(evsShort) != 0 {
		t.Fatalf("expected short Authorization (<8 chars) to be ignored, got %+v", evsShort)
	}

	// Authorization: Basic >=8 chars MUST trigger.
	reqBasic := "GET /admin HTTP/1.1\r\nHost: auth.insecure.example\r\nAuthorization: Basic YWRtaW46MTIzNDU2\r\n\r\n"
	evsBasic, _ := eng.ProcessSync(PacketInput{RawPayload: []byte(reqBasic)})
	if len(evsBasic) != 1 || evsBasic[0].LeakType != TypeCredential || evsBasic[0].RawValue != "Basic YWRtaW46MTIzNDU2" {
		t.Fatalf("expected Authorization Basic credential hit, got %+v", evsBasic)
	}

	// 2. ID_CARD: valid 18-digit Mainland China ID cards vs. 18-digit order numbers / invalid dates / bad MOD 11-2.
	validIDWithX := "11010519491231002X"
	validIDLeap := "440301200002290016" // check: 4*7+4*9+0+3*5+0+1*4+2*2+0+0+0+0+2*9+2*10+9*5+0+0+1*2 = 28+36+15+4+4+18+20+45+2 = 172; 172%11=7 -> idCardCheckMods[7]='5' (recompute exact below)
	_ = validIDLeap
	// Compute exact check char for 44030120000229001_: 172 % 11 == 7 -> '5'
	validIDLeap = "440301200002290015"
	if !ValidCNIDCard(validIDWithX) || !ValidCNIDCard(validIDLeap) || !ValidCNIDCard(strings.ToLower(validIDWithX)) {
		t.Fatalf("ValidCNIDCard rejected valid IDs: %s, %s", validIDWithX, validIDLeap)
	}

	invalidIDs := []string{
		"202611230001234560", // 18-digit order number (province 20 invalid)
		"110105194912310021", // bad ISO 7064 MOD 11-2 check digit (should be X)
		"110105199902290029", // non-leap year 1999-02-29 (even if check digit matches: sum=7+9+0+5+0+20+2+9+54+27+0+18+20+45+0+0+4=220; 220%11=0 -> '1')
		"110105199902290021", // non-leap year 1999-02-29 WITH matching MOD 11-2 check digit '1'!
		"110105199513010026", // invalid month 13
		"110105188001010024", // out-of-range year 1880
	}
	for _, badID := range invalidIDs {
		if ValidCNIDCard(badID) {
			t.Fatalf("ValidCNIDCard(%q) must be false (anti-false-positive guardrail)", badID)
		}
	}

	reqID := "POST /kyc/verify HTTP/1.1\r\nHost: kyc.example.cn\r\nContent-Type: application/json\r\n\r\n" +
		`{"order_id":"202611230001234560","bad_leap":"110105199902290021","long_num":"9911010519491231002X88","id_card":"` + validIDWithX + `","memo":"户籍核验 ` + validIDLeap + ` 完成"}`
	evsID, nID := eng.ProcessSync(PacketInput{
		Time:       time.Unix(1763600010, 0),
		Origin:     OriginHost,
		UID:        10235,
		Pkg:        "com.example.kyc",
		RawPayload: []byte(reqID),
	})
	if nID != 2 || len(evsID) != 2 {
		t.Fatalf("expected 2 ID_CARD hits (keyed + standalone, zero order-number false positives), got n=%d evs=%+v", nID, evsID)
	}
	for _, ev := range evsID {
		if ev.LeakType != TypeIDCard || ev.LeakLabel != "身份证号" {
			t.Fatalf("unexpected ID_CARD event: %+v", ev)
		}
		if ev.RawValue != validIDWithX && ev.RawValue != validIDLeap {
			t.Fatalf("unexpected ID_CARD RawValue: %q", ev.RawValue)
		}
	}
}

func TestHostOriginPerAppDeduplicationAndCanonicalTypes(t *testing.T) {
	for _, alias := range []string{"credential", "token", "password", "auth"} {
		if got, ok := CanonicalIgnoreLeakType(alias); !ok || got != TypeCredential {
			t.Fatalf("CanonicalIgnoreLeakType(%q) = (%q, %v), want (%q, true)", alias, got, ok, TypeCredential)
		}
	}
	for _, alias := range []string{"id_card", "idcard"} {
		if got, ok := CanonicalIgnoreLeakType(alias); !ok || got != TypeIDCard {
			t.Fatalf("CanonicalIgnoreLeakType(%q) = (%q, %v), want (%q, true)", alias, got, ok, TypeIDCard)
		}
	}

	rb := NewRingBuffer(64, 300)
	t0 := time.Unix(1763601000, 0)

	// App A (UID=10101, MAC="") and App B (UID=10102, MAC="") leak identical credential to same host:
	// MUST NOT swallow each other despite MAC == ""!
	evA1, newA1 := rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      10101,
		Pkg:      "com.app.alpha",
		AppName:  "Alpha",
		DstHost:  "api.shared.example",
		LeakType: TypeCredential,
		RawValue: "secret123456",
	}, t0)
	evB1, newB1 := rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      10102,
		Pkg:      "com.app.beta",
		AppName:  "Beta",
		DstHost:  "api.shared.example",
		LeakType: TypeCredential,
		RawValue: "secret123456",
	}, t0.Add(5*time.Second))
	if !newA1 || !newB1 || rb.Len() != 2 || evA1.ID == evB1.ID {
		t.Fatalf("distinct host apps with empty MAC collided in RingBuffer: newA=%v newB=%v len=%d", newA1, newB1, rb.Len())
	}

	// Same App A repeating within cooldown window -> aggregates HitCount to 2.
	evA2, newA2 := rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      10101,
		Pkg:      "com.app.alpha",
		DstHost:  "api.shared.example",
		LeakType: TypeCredential,
		RawValue: "secret123456",
	}, t0.Add(20*time.Second))
	if newA2 || evA2.HitCount != 2 || rb.Len() != 2 {
		t.Fatalf("same host app should aggregate within cooldown: newA2=%v hit=%d len=%d", newA2, evA2.HitCount, rb.Len())
	}
}

func TestRealDeviceFourCategoryFalsePositiveRegressions(t *testing.T) {
	dir := t.TempDir()
	eng := NewEngine(dir)
	defer eng.Close()

	t0 := time.Unix(1764000000, 0)

	// Category 1 (B001): Non-Cookie sid business params (Alibaba AMDC, Xingyu, MiniMax),
	// numeric snowflake IDs, snake-case version constants, and masked/constant passwords -> ZERO hits.
	fpCredReq := "POST /amdc/mobileDispatch?sid=1920202470728&session_id=19202024707281234567 HTTP/1.1\r\n" +
		"Host: amdc.m.taobao.com\r\n" +
		"Sid: da_wr_v13_g1\r\n" +
		"Cookie: sid=rrBPjfmojvS0; session_id=1234567890123456\r\n" +
		"Content-Type: application/json\r\n\r\n" +
		`{"sid":"rrBPjfmojvS0","access_token":"da_wr_v13_g1_rel","api_key":"default_session_token","password":"********","pwd":"000000","passwd":"short"}`
	if evs, n := eng.ProcessSync(PacketInput{Time: t0, Origin: OriginHost, UID: 10200, RawPayload: []byte(fpCredReq)}); len(evs) != 0 || n != 0 {
		t.Fatalf("B001 regression: expected 0 hits for AMDC/Xingyu/MiniMax sid & low-entropy/masked credentials, got n=%d evs=%+v", n, evs)
	}

	// Category 1 positive control: high-entropy Cookie sid (>=16), non-Cookie session_id (>=20), and real password (6..128).
	tpCredReq := "GET /api/profile?session_id=sess_query_AbCdEf987654 HTTP/1.1\r\n" +
		"Host: account.example.com\r\n" +
		"Cookie: sid=sess_abcdef123456\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"pwd=RealPass#2026"
	evsCredOK, nCredOK := eng.ProcessSync(PacketInput{
		Time:       t0.Add(time.Second),
		Origin:     OriginHost,
		UID:        10201,
		Pkg:        "com.example.account",
		SrcPort:    54321,
		DstPort:    80,
		RawPayload: []byte(tpCredReq),
	})
	if nCredOK != 3 || len(evsCredOK) != 3 || evsCredOK[0].SrcPort != 54321 {
		t.Fatalf("B001 positive control failed: n=%d evs=%+v", nCredOK, evsCredOK)
	}

	// Category 2 (B002): Android privacy placeholder 02:00:00:00:00:00, multicast, and all-same-byte MACs -> ZERO hits;
	// legitimate locally-administered unicast MAC 02:00:00:00:00:01 -> MUST hit.
	fpMACReq := "GET /dev?wifi_mac=02:00:00:00:00:00&bssid=01:00:5e:00:00:fb&mac=aa:aa:aa:aa:aa:aa&hwaddr=ff:ff:ff:ff:ff:ff HTTP/1.1\r\nHost: sdk.iot.example\r\n\r\n"
	if evs, n := eng.ProcessSync(PacketInput{Time: t0.Add(2 * time.Second), ClientMAC: "02:00:00:00:00:00", RawPayload: []byte(fpMACReq)}); len(evs) != 0 || n != 0 {
		t.Fatalf("B002 regression: fake/multicast/constant MACs must be rejected, got n=%d evs=%+v", n, evs)
	}
	if _, err := NormalizeIgnoreRule(IgnoreRule{Scope: ScopeDeviceHostType, MAC: "02:00:00:00:00:00", DstHost: "sdk.iot.example", LeakType: TypeMACAddr}); err == nil {
		t.Fatal("NormalizeIgnoreRule must reject 02:00:00:00:00:00 placeholder MAC")
	}
	tpMACReq := "GET /dev?wifi_mac=02:00:00:00:00:01 HTTP/1.1\r\nHost: sdk.iot.example\r\n\r\n"
	evsMACOK, nMACOK := eng.ProcessSync(PacketInput{Time: t0.Add(3 * time.Second), ClientMAC: "3c:22:fb:11:22:33", RawPayload: []byte(tpMACReq)})
	if nMACOK != 1 || len(evsMACOK) != 1 || evsMACOK[0].RawValue != "02:00:00:00:00:01" {
		t.Fatalf("B002 positive control: valid unicast random MAC 02:00:00:00:00:01 must trigger, got n=%d evs=%+v", nMACOK, evsMACOK)
	}

	// Category 3 (B003): Fake device IDs (permission_denied, 9774d56d682e549c, all-same-char) & phone key substring FPs -> ZERO hits;
	// valid IMEISV (16d), IMSI (15d), MEID (14h), ANDROID_ID (16h), 64-hex OAID, and user_phone -> MUST hit.
	fpDevReq := "POST /collect HTTP/1.1\r\nHost: ad.sdk.example\r\nContent-Type: application/json\r\n\r\n" +
		`{"imei":"permission_denied","oaid":"unavailable","android_id":"9774d56d682e549c","idfa":"00000000-0000-0000-0000-000000000000","meid":"ffffffffffffff","hotel_id":"13800138000","headphone":"13900139000"}`
	if evs, n := eng.ProcessSync(PacketInput{Time: t0.Add(4 * time.Second), ClientMAC: "3c:22:fb:11:22:33", RawPayload: []byte(fpDevReq)}); len(evs) != 0 || n != 0 {
		t.Fatalf("B003 regression: fake device IDs and non-phone keys must produce 0 hits, got n=%d evs=%+v", n, evs)
	}
	oaid64 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tpDevReq := "POST /collect HTTP/1.1\r\nHost: ad.sdk.example\r\nContent-Type: application/json\r\n\r\n" +
		`{"imeisv":"4901542032375180","imsi":"460001380013800","meid":"A000001F2B3C4D","android_id":"4f8a2c91b7e03d65","oaid":"` + oaid64 + `","user_phone":"13800138000"}`
	evsDevOK, nDevOK := eng.ProcessSync(PacketInput{Time: t0.Add(5 * time.Second), ClientMAC: "3c:22:fb:11:22:33", RawPayload: []byte(tpDevReq)})
	if nDevOK != 6 || len(evsDevOK) != 6 {
		t.Fatalf("B003 positive control: expected 6 hits (imeisv, imsi, meid, android_id, 64h oaid, user_phone), got n=%d evs=%+v", nDevOK, evsDevOK)
	}

	// Category 4 (B004/B005/B008): FlClash cross-iface (<5s) host deduplication without HitCount inflation,
	// standalone proxy subscription leak preservation, two real apps (<5s) non-collision, and ScopeAppHostType whitelist.
	rb := NewRingBuffer(64, 300)
	// Case 4a: Physical iface (FlClash conduit) arrives first, virtual Meta iface (real business app) arrives 1s later ->
	// upgrades attribution to real business app, upgrades FakeIP DstIP to public IP, keeps HitCount == 1!
	_, newC1 := rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      10300,
		Pkg:      "com.follow.clash",
		AppName:  "FlClash",
		ClientIP: "192.168.1.25",
		DstIP:    "203.0.113.88",
		SrcPort:  41001,
		DstPort:  80,
		DstHost:  "track.direct.example",
		LeakType: TypeDeviceID,
		RawValue: "490154203237518",
	}, t0)
	mergedEv, newC2 := rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      10234,
		Pkg:      "com.real.videoapp",
		AppName:  "某视频",
		ClientIP: "198.18.0.1",
		DstIP:    "198.18.0.55",
		SrcPort:  52002,
		DstPort:  80,
		DstHost:  "track.direct.example",
		LeakType: TypeDeviceID,
		RawValue: "490154203237518",
	}, t0.Add(time.Second))
	if !newC1 || newC2 || rb.Len() != 1 || mergedEv.HitCount != 1 {
		t.Fatalf("B005 reverse-order FlClash merge failed: new1=%v new2=%v len=%d ev=%+v", newC1, newC2, rb.Len(), mergedEv)
	}
	if mergedEv.UID != 10234 || mergedEv.Pkg != "com.real.videoapp" || mergedEv.DstIP != "203.0.113.88" || mergedEv.SrcPort != 52002 {
		t.Fatalf("B005 merged event lost real app attribution or public DstIP: %+v", mergedEv)
	}
	// Third duplicate from unattributed UID=-1 within <5s must also merge without overwriting real app or inflating HitCount.
	mergedEv2, newC3 := rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      -1,
		ClientIP: "10.0.0.8",
		DstHost:  "track.direct.example",
		LeakType: TypeDeviceID,
		RawValue: "490154203237518",
	}, t0.Add(2*time.Second))
	if newC3 || mergedEv2.UID != 10234 || mergedEv2.HitCount != 1 {
		t.Fatalf("B004/B005 UID=-1 merge corrupted real app event: new3=%v ev=%+v", newC3, mergedEv2)
	}

	// Case 4b: Two distinct real business apps within 1s (<5s) MUST NOT swallow each other!
	_, newRealA := rb.Record(LeakEvent{
		Origin: OriginHost, UID: 10501, Pkg: "com.real.one", DstHost: "shared.sdk.example", LeakType: TypePhone, RawValue: "13800138000",
	}, t0.Add(10*time.Second))
	_, newRealB := rb.Record(LeakEvent{
		Origin: OriginHost, UID: 10502, Pkg: "com.real.two", DstHost: "shared.sdk.example", LeakType: TypePhone, RawValue: "13800138000",
	}, t0.Add(11*time.Second))
	if !newRealA || !newRealB || rb.Len() != 3 {
		t.Fatalf("two distinct real apps within <5s collided: newA=%v newB=%v len=%d", newRealA, newRealB, rb.Len())
	}

	// Case 4c: ScopeAppHostType ignore rule matches only target host app while keeping legacy 3-scope UniqueKey intact.
	legacyRule, err := NormalizeIgnoreRule(IgnoreRule{Scope: ScopeHostType, DstHost: "trusted.login.example", LeakType: TypePhone})
	if err != nil || legacyRule.UniqueKey() != "host_type||trusted.login.example|PHONE" {
		t.Fatalf("legacy UniqueKey changed unexpectedly: err=%v uk=%q", err, legacyRule.UniqueKey())
	}
	appRule, err := NormalizeIgnoreRule(IgnoreRule{
		Scope:    ScopeAppHostType,
		UID:      10501,
		Pkg:      "COM.Real.One",
		DstHost:  "sdk.example",
		LeakType: "phone",
	})
	if err != nil || appRule.Pkg != "com.real.one" {
		t.Fatalf("NormalizeIgnoreRule(ScopeAppHostType) failed: err=%v rule=%+v", err, appRule)
	}
	if purged := rb.PurgeIgnored(appRule.MatchesEvent); purged != 1 || rb.Len() != 2 {
		t.Fatalf("expected ScopeAppHostType rule to purge only com.real.one event (purged=%d len=%d)", purged, rb.Len())
	}
	if appRule.MatchesEvent(LeakEvent{Origin: OriginHotspot, MAC: "3c:22:fb:11:22:33", DstHost: "shared.sdk.example", LeakType: TypePhone}) {
		t.Fatal("ScopeAppHostType must never match downstream hotspot device events")
	}
}

func TestCrossIfaceOutOfOrderCooldownReplayFoldsWithoutDuplicateSplit(t *testing.T) {
	rb := NewRingBuffer(16, 300)
	t0 := time.Unix(1764100000, 0)

	// 1. t=0s: Real business app sends first cleartext request (real packet arrives first, conduit 1s later).
	seedEv, new0 := rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      10234,
		Pkg:      "com.real.videoapp",
		AppName:  "某视频",
		ClientIP: "198.18.0.1",
		DstIP:    "198.18.0.55",
		SrcPort:  52001,
		DstPort:  80,
		DstHost:  "track.direct.example",
		LeakType: TypeDeviceID,
		RawValue: "490154203237518",
	}, t0)
	_, new0Dup := rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      10300,
		Pkg:      "com.follow.clash",
		AppName:  "FlClash",
		ClientIP: "192.168.1.25",
		DstIP:    "203.0.113.88",
		SrcPort:  41001,
		DstPort:  80,
		DstHost:  "track.direct.example",
		LeakType: TypeDeviceID,
		RawValue: "490154203237518",
	}, t0.Add(time.Second))
	if !new0 || new0Dup || rb.Len() != 1 {
		t.Fatalf("t=0s initial cross-iface pair unexpected state: new0=%v new0Dup=%v len=%d", new0, new0Dup, rb.Len())
	}

	// 2. t=30s (within 300s cooldown): Physical FlClash conduit packet arrives 1ms BEFORE virtual TUN real app packet.
	// Step 2a: Conduit arrives at t=30s (>5s after t=0s, so it initially occupies a temporary new slot).
	_, _ = rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      10300,
		Pkg:      "com.follow.clash",
		AppName:  "FlClash",
		ClientIP: "192.168.1.25",
		DstIP:    "203.0.113.99",
		SrcPort:  41002,
		DstPort:  80,
		DstHost:  "track.direct.example",
		LeakType: TypeDeviceID,
		RawValue: "490154203237518",
	}, t0.Add(30*time.Second))
	// Step 2b: 1ms later at t=30s, real business app packet arrives -> upgrades temporary slot and folds it
	// back into the t=0s real business app entry, removing the redundant slot so zero duplicate split remains.
	folded30, new30Real := rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      10234,
		Pkg:      "com.real.videoapp",
		AppName:  "某视频",
		ClientIP: "198.18.0.1",
		DstIP:    "198.18.0.55",
		SrcPort:  52002,
		DstPort:  80,
		DstHost:  "track.direct.example",
		LeakType: TypeDeviceID,
		RawValue: "490154203237518",
	}, t0.Add(30*time.Second+time.Millisecond))
	if new30Real || rb.Len() != 1 {
		t.Fatalf("t=30s out-of-order replay caused duplicate split: new=%v len=%d snap=%+v", new30Real, rb.Len(), rb.Snapshot())
	}
	if folded30.ID != seedEv.ID || folded30.FirstSeen != t0.Unix() || folded30.LastSeen != t0.Add(30*time.Second).Unix() || folded30.HitCount != 2 {
		t.Fatalf("t=30s folded event metadata mismatch: got %+v, seedID=%s", folded30, seedEv.ID)
	}
	if folded30.UID != 10234 || folded30.Pkg != "com.real.videoapp" || folded30.DstIP != "203.0.113.99" || folded30.SrcPort != 52002 {
		t.Fatalf("t=30s folded event lost real attribution or public DstIP: %+v", folded30)
	}

	// 3. t=60s (within 300s cooldown, with an unrelated app event interleaved after the temporary slot):
	// Unattributed UID=-1 packet arrives first at t=60s, unrelated app arrives at t=60s, real app arrives 1ms later.
	_, _ = rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      -1,
		ClientIP: "10.0.0.8",
		DstIP:    "203.0.113.100",
		DstHost:  "track.direct.example",
		LeakType: TypeDeviceID,
		RawValue: "490154203237518",
	}, t0.Add(60*time.Second))
	_, newOther := rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      10888,
		Pkg:      "com.other.reader",
		DstHost:  "news.example.com",
		LeakType: TypePhone,
		RawValue: "13800138000",
	}, t0.Add(60*time.Second))
	folded60, new60Real := rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      10234,
		Pkg:      "com.real.videoapp",
		ClientIP: "198.18.0.1",
		DstIP:    "198.18.0.55",
		SrcPort:  52003,
		DstPort:  80,
		DstHost:  "track.direct.example",
		LeakType: TypeDeviceID,
		RawValue: "490154203237518",
	}, t0.Add(60*time.Second+time.Millisecond))
	if !newOther || new60Real || rb.Len() != 2 || folded60.HitCount != 3 || folded60.DstIP != "203.0.113.100" {
		t.Fatalf("t=60s interleaved UID=-1 out-of-order fold failed: newOther=%v new60=%v len=%d folded=%+v snap=%+v",
			newOther, new60Real, rb.Len(), folded60, rb.Snapshot())
	}

	// 4. t=400s (>300s after LastSeen=t0+60s): Post-cooldown out-of-order pair MUST remain a distinct post-cooldown entry.
	_, _ = rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      10300,
		Pkg:      "com.follow.clash",
		DstIP:    "203.0.113.101",
		DstHost:  "track.direct.example",
		LeakType: TypeDeviceID,
		RawValue: "490154203237518",
	}, t0.Add(400*time.Second))
	postEv, postNew := rb.Record(LeakEvent{
		Origin:   OriginHost,
		UID:      10234,
		Pkg:      "com.real.videoapp",
		DstIP:    "198.18.0.55",
		DstHost:  "track.direct.example",
		LeakType: TypeDeviceID,
		RawValue: "490154203237518",
	}, t0.Add(400*time.Second+time.Millisecond))
	if postNew || rb.Len() != 3 || postEv.ID == seedEv.ID || postEv.HitCount != 1 {
		t.Fatalf("t=400s post-cooldown pair should stay a new entry: postNew=%v len=%d postEv=%+v", postNew, rb.Len(), postEv)
	}
}
