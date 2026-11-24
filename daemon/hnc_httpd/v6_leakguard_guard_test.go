package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	dpidlg "hnc.io/dpid/leakguard"
)

func waitLeakGuardCond(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(3 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for %s", desc)
	}
}

var guardTestReqSeq atomic.Uint64

func doGuardJSONReq(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	if body == "" {
		body = "{}"
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:42000"
	// Rotate synthetic token ID every 30 requests so 200-rule bulk tests don't trip the 60/min per-identity write rate limiter.
	tokID := fmt.Sprintf("lg-test-tok-%d", guardTestReqSeq.Add(1)/30)
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyTokenID, tokID))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-HNC-CSRF", "1")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestLeakGuard64BitAtomicHeadAlignment(t *testing.T) {
	var z leakGuardEngine
	fields := []struct {
		name string
		off  uintptr
		want uintptr
	}{
		{"totalHits", unsafe.Offsetof(z.totalHits), 0},
		{"clearSeq", unsafe.Offsetof(z.clearSeq), 8},
		{"ignoredHits", unsafe.Offsetof(z.ignoredHits), 16},
		{"guardBlocks", unsafe.Offsetof(z.guardBlocks), 24},
		{"diskReadCount", unsafe.Offsetof(z.diskReadCount), 32},
	}
	for _, f := range fields {
		if f.off != f.want || f.off%8 != 0 {
			t.Fatalf("leakGuardEngine.%s offset=%d want=%d (must be contiguous 8-byte aligned at struct head for GOARCH=arm)", f.name, f.off, f.want)
		}
	}
}

func TestLeakGuardRequireMutationAnd0600FilePermissions(t *testing.T) {
	_, mux, dir := newV6TestMux(t)

	for _, ep := range []string{"/api/leakguard/whitelist", "/api/leakguard/undo-block"} {
		// 1) GET must be rejected by requireMutation (405 Method Not Allowed)
		getReq := httptest.NewRequest(http.MethodGet, ep, nil)
		getReq.RemoteAddr = "127.0.0.1:42000"
		getRec := httptest.NewRecorder()
		mux.ServeHTTP(getRec, getReq)
		if getRec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s expected 405 from requireMutation, got %d", ep, getRec.Code)
		}

		// 2) POST without X-HNC-CSRF header must be rejected by requireMutation (400 csrf header missing)
		noCSRFReq := httptest.NewRequest(http.MethodPost, ep, strings.NewReader(`{}`))
		noCSRFReq.RemoteAddr = "127.0.0.1:42000"
		noCSRFReq.Header.Set("Content-Type", "application/json")
		noCSRFRec := httptest.NewRecorder()
		mux.ServeHTTP(noCSRFRec, noCSRFReq)
		if noCSRFRec.Code != http.StatusBadRequest || !strings.Contains(noCSRFRec.Body.String(), "csrf header missing") {
			t.Fatalf("POST %s without CSRF expected 400 csrf header missing from requireMutation, got %d body=%s",
				ep, noCSRFRec.Code, noCSRFRec.Body.String())
		}
	}

	// Trigger writes to leakguard_config.json, leakguard_ctrl.json, and leakguard_events.json
	wlRec := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/whitelist",
		`{"action":"add","scope":"host_type","dst_host":"sso.enterprise.example","leak_type":"PHONE"}`)
	if wlRec.Code != http.StatusOK {
		t.Fatalf("whitelist add failed: %d %s", wlRec.Code, wlRec.Body.String())
	}
	clrRec := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/clear", `{}`)
	if clrRec.Code != http.StatusOK {
		t.Fatalf("clear failed: %d %s", clrRec.Code, clrRec.Body.String())
	}

	for _, p := range []string{
		filepath.Join(dir, "data", "leakguard_config.json"),
		filepath.Join(dir, "run", "leakguard_ctrl.json"),
		filepath.Join(dir, "run", "leakguard_events.json"),
	} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := st.Mode().Perm(); perm != 0o600 {
			t.Fatalf("file %s mode=%04o, want strict 0600", p, perm)
		}
	}
}

func TestLeakGuardWhitelistGuardrailsScopesPurgeAndConfigPreservation(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	lg := s.v6State().leakGuard
	lg.notifyExec = func(context.Context, string, ...string) error { return nil }

	// 1. P0 anti-blinding guardrails
	badTargets := []string{
		"*", "*.qq.com", "sub.*.example.com",
		"0.0.0.0/0", "10.0.0.0/8", "2001:db8::/32",
		"127.0.0.1", "::1", "0.0.0.0", "::", "192.168.43.1", "10.1.2.3", "169.254.10.20",
		"com", "cn", "net", "org", "localhost",
		"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.uk", "org.uk",
		strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + ".example.com",
	}
	for _, bad := range badTargets {
		body := fmt.Sprintf(`{"action":"add","scope":"host","dst_host":%q}`, bad)
		rec := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/whitelist", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for P0 forbidden whitelist dst_host=%q, got %d body=%s", bad, rec.Code, rec.Body.String())
		}
	}

	// 2. Seed memory events, then add whitelist rules across all 3 scopes and verify immediate purge
	lg.IngestEvents([]LeakEvent{
		{ID: "ev_w1", Ts: 1800010001, MAC: "aa:bb:cc:dd:ee:01", SrcIP: "192.168.43.11", DstHost: "auth.corp.com.cn", LeakType: "phone", RawValue: "13800138001"},
		{ID: "ev_w2", Ts: 1800010002, MAC: "aa:bb:cc:dd:ee:01", SrcIP: "192.168.43.11", DstHost: "auth.corp.com.cn", LeakType: "oaid", RawValue: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
		{ID: "ev_w3", Ts: 1800010003, MAC: "aa:bb:cc:dd:ee:02", SrcIP: "192.168.43.12", DstHost: "iot.cam.co.uk", LeakType: "mac", RawValue: "aa:bb:cc:dd:ee:02"},
		{ID: "ev_w4", Ts: 1800010004, MAC: "aa:bb:cc:dd:ee:01", SrcIP: "192.168.43.11", DstHost: "iot.cam.co.uk", LeakType: "mac", RawValue: "aa:bb:cc:dd:ee:01"},
		{ID: "ev_w5", Ts: 1800010005, MAC: "aa:bb:cc:dd:ee:01", SrcIP: "192.168.43.11", DstHost: "203.0.113.77", DstIP: "203.0.113.77", LeakType: "gps", RawValue: "31.230416,121.473701"},
	})

	// Add scope=host_type on corp.com.cn PHONE -> purges ev_w1, keeps ev_w2 (oaid)
	r1 := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/whitelist",
		`{"action":"add","scope":"host_type","dst_host":"corp.com.cn","leak_type":"PHONE"}`)
	if r1.Code != http.StatusOK || !strings.Contains(r1.Body.String(), `"purged_events":1`) {
		t.Fatalf("scope=host_type add failed: %d %s", r1.Code, r1.Body.String())
	}

	// Add scope=device_host_type on mac 02 + cam.co.uk MAC_ADDR -> purges ev_w3, keeps ev_w4 (mac 01)
	r2 := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/whitelist",
		`{"action":"add","scope":"device_host_type","mac":"aa:bb:cc:dd:ee:02","dst_host":"cam.co.uk","leak_type":"MAC_ADDR"}`)
	if r2.Code != http.StatusOK || !strings.Contains(r2.Body.String(), `"purged_events":1`) {
		t.Fatalf("scope=device_host_type add failed: %d %s", r2.Code, r2.Body.String())
	}

	// Add scope=host on single public IP 203.0.113.77 -> purges ev_w5
	r3 := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/whitelist",
		`{"action":"add","scope":"host","dst_host":"203.0.113.77"}`)
	if r3.Code != http.StatusOK || !strings.Contains(r3.Body.String(), `"purged_events":1`) {
		t.Fatalf("scope=host IP add failed: %d %s", r3.Code, r3.Body.String())
	}

	evRec := doGuardJSONReq(t, mux, http.MethodGet, "/api/leakguard/events", "")
	var snap struct {
		Events      []LeakEvent         `json:"events"`
		IgnoredHits int64               `json:"ignored_hits"`
		IgnoreRules []dpidlg.IgnoreRule `json:"ignore_rules"`
	}
	if err := json.Unmarshal(evRec.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.Events) != 2 || snap.IgnoredHits != 3 || len(snap.IgnoreRules) != 3 {
		t.Fatalf("unexpected state after immediate purge: events=%d ignoredHits=%d rules=%d",
			len(snap.Events), snap.IgnoredHits, len(snap.IgnoreRules))
	}

	// Also create 1 block entry so undo_stack is non-empty, then POST /api/leakguard/config (4 basic fields)
	blkRec := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		`{"action":"block","dst_host":"bad-ad.tracker.example","mac":"aa:bb:cc:dd:ee:01"}`)
	if blkRec.Code != http.StatusOK {
		t.Fatalf("block failed: %d %s", blkRec.Code, blkRec.Body.String())
	}

	cfgRec := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/config",
		`{"capacity":400,"cooldown_sec":120,"notify_enabled":false,"lockscreen_mask":true}`)
	if cfgRec.Code != http.StatusOK {
		t.Fatalf("POST config failed: %d %s", cfgRec.Code, cfgRec.Body.String())
	}

	// Verify dpid ReadControl still sees all 3 ignore_rules in run/leakguard_ctrl.json
	dpidCtrl, err := dpidlg.ReadControl(filepath.Join(dir, "run"))
	if err != nil || len(dpidCtrl.IgnoreRules) != 3 {
		t.Fatalf("POST /api/leakguard/config wiped ctrl ignore_rules: err=%v rules=%+v", err, dpidCtrl.IgnoreRules)
	}

	// Reload a brand-new server from disk to verify data/leakguard_config.json preserved ignore_rules AND undo_stack!
	sReload := newServer(dir)
	lgReload := sReload.v6State().leakGuard
	lgReload.mu.Lock()
	reloadedRules := len(lgReload.ignoreRules)
	reloadedUndo := len(lgReload.undoStack)
	reloadedCap := lgReload.cfg.Capacity
	lgReload.mu.Unlock()
	if reloadedRules != 3 || reloadedUndo != 1 || reloadedCap != 400 {
		t.Fatalf("POST /api/leakguard/config wiped persisted fields: rules=%d undo=%d cap=%d",
			reloadedRules, reloadedUndo, reloadedCap)
	}

	// 3. Enforce hard cap of <= 200 rules
	for i := 0; i < 197; i++ {
		host := fmt.Sprintf("wl-%03d.safe.example", i)
		addRec := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/whitelist",
			fmt.Sprintf(`{"action":"add","scope":"host","dst_host":%q}`, host))
		if addRec.Code != http.StatusOK {
			t.Fatalf("fill rule %d failed: %d %s", i, addRec.Code, addRec.Body.String())
		}
	}
	overflowRec := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/whitelist",
		`{"action":"add","scope":"host","dst_host":"wl-overflow.safe.example"}`)
	if overflowRec.Code != http.StatusBadRequest || !strings.Contains(overflowRec.Body.String(), "too_many_rules") {
		t.Fatalf("expected 400 too_many_rules on 201st rule, got %d %s", overflowRec.Code, overflowRec.Body.String())
	}

	// Remove one rule and clear all
	rmRec := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/whitelist",
		`{"action":"remove","scope":"host","dst_host":"203.0.113.77"}`)
	if rmRec.Code != http.StatusOK || !strings.Contains(rmRec.Body.String(), `"removed":1`) {
		t.Fatalf("whitelist remove failed: %d %s", rmRec.Code, rmRec.Body.String())
	}
	clrWlRec := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/whitelist", `{"action":"clear"}`)
	if clrWlRec.Code != http.StatusOK || !strings.Contains(clrWlRec.Body.String(), `"removed":199`) {
		t.Fatalf("whitelist clear failed: %d %s", clrWlRec.Code, clrWlRec.Body.String())
	}
}

func TestLeakGuardThreeTierCDNInfraGuardAndAlsoIPSkip(t *testing.T) {
	_, mux, dir := newV6TestMux(t)
	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"), []byte(`{
		"aa:bb:cc:dd:ee:01": {"ip": "192.168.43.101", "hostname": "Pixel", "last_seen": 1800000000}
	}`), 0o600)

	// Tier 1: hard_block (HTTP 409 even when force:true!)
	hardBlockTargets := []string{
		// System Captive Portal / Public DNS / NTP (and subdomains)
		"connectivitycheck.gstatic.com", "captive.apple.com", "0.cn.pool.ntp.org", "dns.alidns.com", "223.5.5.5", "8.8.8.8",
		// Bare ecosystem & public CDN root domains
		"apple.com", "icloud.com", "cdn-apple.com",
		"google.com", "gstatic.com", "googleapis.com",
		"cloudflare.com", "akamaized.net", "cloudfront.net",
		"aliyun.com", "alicdn.com", "taobao.com", "alipay.com",
		"qq.com", "weixin.qq.com", "myqcloud.com", "gtimg.com", "qpic.cn",
		"douyin.com", "douyincdn.com", "douyinvod.com", "byteimg.com", "pstatp.com",
	}
	for _, tgt := range hardBlockTargets {
		for _, force := range []bool{false, true} {
			body := fmt.Sprintf(`{"action":"block","dst_host":%q,"mac":"aa:bb:cc:dd:ee:01","force":%v}`, tgt, force)
			rec := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain", body)
			if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"guard_level":"hard_block"`) {
				t.Fatalf("hard_block target %q (force=%v) expected 409 hard_block, got %d body=%s",
					tgt, force, rec.Code, rec.Body.String())
			}
		}
	}

	// Tier 2: warn_confirm on shared CDN subdomains & shared_infra.txt / entity_db.json (409 by default, 200 with force:true)
	warnTargets := []string{
		"img.alicdn.com",
		"a248.e.akamai.net",
		"d111111abcdef8.cloudfront.net",
		"wx.gtimg.com",
		"sf1-cdn-tos.byteimg.com",
		"cdn.bootcdn.net",
		"sub.cdnhwc1.com",
	}
	for _, tgt := range warnTargets {
		recWarn := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
			fmt.Sprintf(`{"action":"block","dst_host":%q,"mac":"aa:bb:cc:dd:ee:01"}`, tgt))
		if recWarn.Code != http.StatusConflict {
			t.Fatalf("warn_confirm target %q expected 409 without force, got %d body=%s", tgt, recWarn.Code, recWarn.Body.String())
		}
		var warnResp struct {
			GuardLevel string `json:"guard_level"`
			Vendor     string `json:"vendor"`
		}
		_ = json.Unmarshal(recWarn.Body.Bytes(), &warnResp)
		if warnResp.GuardLevel != "warn_confirm" || warnResp.Vendor == "" {
			t.Fatalf("warn_confirm target %q missing guard_level/vendor: %s", tgt, recWarn.Body.String())
		}
	}
	// Verify force:true allows blocking a warn_confirm subdomain
	recForceOK := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		`{"action":"block","dst_host":"img.alicdn.com","mac":"aa:bb:cc:dd:ee:01","force":true}`)
	if recForceOK.Code != http.StatusOK || !strings.Contains(recForceOK.Body.String(), `"guard_forced":true`) {
		t.Fatalf("warn_confirm with force:true failed: %d %s", recForceOK.Code, recForceOK.Body.String())
	}

	// Explicit pure ad/tracker exemptions must succeed immediately with 200 OK without force:true
	exemptTrackers := []string{
		"doubleclick.net", "stats.g.doubleclick.net",
		"pangle.io", "api16-access-sg.pangle.io",
		"umeng.com", "alog.umeng.com",
	}
	for _, adHost := range exemptTrackers {
		recAd := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
			fmt.Sprintf(`{"action":"block","dst_host":%q,"mac":"aa:bb:cc:dd:ee:01"}`, adHost))
		if recAd.Code != http.StatusOK {
			t.Fatalf("exempt ad tracker %q should allow direct block without 409, got %d %s",
				adHost, recAd.Code, recAd.Body.String())
		}
	}

	// Tier 3: Independent ad domain with also_ip hitting Cloudflare shared CDN IP (104.16.132.229)
	recSharedIP := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		`{"action":"block","dst_host":"pixel.evil-ad.example","also_ip":"104.16.132.229","mac":"aa:bb:cc:dd:ee:01"}`)
	if recSharedIP.Code != http.StatusOK || !strings.Contains(recSharedIP.Body.String(), `"skipped_shared_ip":true`) {
		t.Fatalf("expected skipped_shared_ip:true for Cloudflare CDN IP, got %d %s", recSharedIP.Code, recSharedIP.Body.String())
	}
	cbAfterShared := readConnBlocks(dir)
	for _, it := range cbAfterShared.Items {
		if it.Kind == "ip" && it.Value == "104.16.132.229" {
			t.Fatalf("shared CDN IP 104.16.132.229 must NOT be added to conn_blocks: %+v", cbAfterShared.Items)
		}
	}

	// Independent ad domain with dedicated non-CDN IP (203.0.113.99) -> blocks both domain and IP
	recDedIP := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		`{"action":"block","dst_host":"Dedicated.Evil-Ad.Example","also_ip":"203.0.113.99","mac":"aa:bb:cc:dd:ee:01"}`)
	if recDedIP.Code != http.StatusOK || !strings.Contains(recDedIP.Body.String(), `"blocked_also_ip":"203.0.113.99"`) {
		t.Fatalf("expected dedicated also_ip to be blocked, got %d %s", recDedIP.Code, recDedIP.Body.String())
	}
}

func TestLeakGuardPerMACIsolationTombstoneAnd10StepUndoStack(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	lg := s.v6State().leakGuard
	lg.notifyExec = func(context.Context, string, ...string) error { return nil }

	macA := "aa:bb:cc:dd:ee:01"
	macB := "aa:bb:cc:dd:ee:02"
	lg.IngestEvents([]LeakEvent{
		{ID: "ev_iso_a", Ts: 1800020001, MAC: macA, SrcIP: "192.168.43.21", DstHost: "sdk.spyware.example", LeakType: "phone", RawValue: "13811112222"},
		{ID: "ev_iso_b", Ts: 1800020002, MAC: macB, SrcIP: "192.168.43.22", DstHost: "sdk.spyware.example", LeakType: "phone", RawValue: "13933334444"},
	})

	// 1. Block sdk.spyware.example ONLY on macA -> macA must be is_blocked:true, macB must stay is_blocked:false!
	blkA := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		`{"action":"block","dst_host":"sdk.spyware.example","mac":"aa:bb:cc:dd:ee:01"}`)
	if blkA.Code != http.StatusOK {
		t.Fatalf("block macA failed: %d %s", blkA.Code, blkA.Body.String())
	}

	evRec1 := doGuardJSONReq(t, mux, http.MethodGet, "/api/leakguard/events", "")
	var snap1 struct {
		Events []LeakEvent `json:"events"`
	}
	_ = json.Unmarshal(evRec1.Body.Bytes(), &snap1)
	for _, ev := range snap1.Events {
		if ev.MAC == macA && !ev.IsBlocked {
			t.Fatalf("expected macA event to be marked is_blocked:true: %+v", ev)
		}
		if ev.MAC == macB && ev.IsBlocked {
			t.Fatalf("macA block leaked to macB (cross-device false positive): %+v", ev)
		}
	}

	// 2. Also block sdk.spyware.example on macB, then undo-block (pops macB first!)
	blkB := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		`{"action":"block","dst_host":"sdk.spyware.example","mac":"aa:bb:cc:dd:ee:02"}`)
	if blkB.Code != http.StatusOK {
		t.Fatalf("block macB failed: %d %s", blkB.Code, blkB.Body.String())
	}

	undoB := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/undo-block", `{}`)
	if undoB.Code != http.StatusOK {
		t.Fatalf("undo macB failed: %d %s", undoB.Code, undoB.Body.String())
	}
	// Since macA still blocks sdk.spyware.example, global blockedTargets must STILL retain it!
	lg.mu.Lock()
	stillGlobalAfterB := lg.blockedTargets["sdk.spyware.example"]
	lg.mu.Unlock()
	if !stillGlobalAfterB {
		t.Fatal("global blockedTargets prematurely deleted sdk.spyware.example while macA still blocks it")
	}

	// 3. Undo macA -> no device blocks sdk.spyware.example anymore -> removed from global blockedTargets + false tombstone written!
	undoA := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/undo-block", `{}`)
	if undoA.Code != http.StatusOK {
		t.Fatalf("undo macA failed: %d %s", undoA.Code, undoA.Body.String())
	}
	lg.mu.Lock()
	stillGlobalAfterA := lg.blockedTargets["sdk.spyware.example"]
	hasTombstone := lg.tombstones["sdk.spyware.example"]
	lg.mu.Unlock()
	if stillGlobalAfterA || !hasTombstone {
		t.Fatalf("expected sdk.spyware.example deleted from blockedTargets with tombstone=true, got active=%v tombstone=%v",
			stillGlobalAfterA, hasTombstone)
	}
	ctrlState, err := dpidlg.ReadControl(filepath.Join(dir, "run"))
	if err != nil || len(ctrlState.BlockedDomains) != 0 {
		t.Fatalf("dpid ReadControl still shows unblocked domain: err=%v domains=%+v", err, ctrlState.BlockedDomains)
	}

	// 4. Push 12 distinct blocks -> stack caps strictly at 10 LIFO entries
	for i := 1; i <= 12; i++ {
		d := fmt.Sprintf("ad-%02d.evil.example", i)
		r := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
			fmt.Sprintf(`{"action":"block","dst_host":%q,"mac":"aa:bb:cc:dd:ee:01"}`, d))
		if r.Code != http.StatusOK {
			t.Fatalf("block #%d failed: %d %s", i, r.Code, r.Body.String())
		}
	}
	for wantIdx := 12; wantIdx >= 3; wantIdx-- {
		uRec := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/undo-block", `{}`)
		if uRec.Code != http.StatusOK {
			t.Fatalf("undo #%d failed: %d %s", wantIdx, uRec.Code, uRec.Body.String())
		}
		wantHost := fmt.Sprintf("ad-%02d.evil.example", wantIdx)
		if !strings.Contains(uRec.Body.String(), fmt.Sprintf(`"dst_host":%q`, wantHost)) {
			t.Fatalf("expected LIFO undo of %q, got %s", wantHost, uRec.Body.String())
		}
	}
	// 11th undo must fail cleanly with 400 empty_undo_stack
	emptyRec := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/undo-block", `{}`)
	if emptyRec.Code != http.StatusBadRequest || !strings.Contains(emptyRec.Body.String(), "empty_undo_stack") {
		t.Fatalf("expected 400 empty_undo_stack after 10 undos, got %d %s", emptyRec.Code, emptyRec.Body.String())
	}
}

func TestLeakGuardStatShortCircuitAndZeroWakeupSleepResume(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	lg := s.v6State().leakGuard
	lg.notifyExec = func(context.Context, string, ...string) error { return nil }
	lg.pollInterval = 20 * time.Millisecond
	lg.sseHeartbeat = 40 * time.Millisecond

	epath := filepath.Join(dir, "run", "leakguard_events.json")
	payload1 := `{"events":[{"id":"ev_stat_1","ts":1800030001,"mac":"aa:bb:cc:dd:ee:01","dst_host":"stat.example.com","leak_type":"phone","raw_value":"13800001111"}]}`
	if err := os.WriteFile(epath, []byte(payload1), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1) (mtimeNs, size) os.Stat short-circuit verification
	for i := 0; i < 10; i++ {
		lg.syncFromDisk()
	}
	if reads := lg.DiskReadCount(); reads != 1 {
		t.Fatalf("expected exactly 1 os.ReadFile across 10 unchanged syncFromDisk calls, got %d", reads)
	}

	// Modify file content (size & mtime change) -> triggers exactly 1 new read
	payload2 := `{"events":[{"id":"ev_stat_1","ts":1800030001,"mac":"aa:bb:cc:dd:ee:01","dst_host":"stat.example.com","leak_type":"phone","raw_value":"13800001111"},{"id":"ev_stat_2","ts":1800030009,"mac":"aa:bb:cc:dd:ee:01","dst_host":"stat2.example.com","leak_type":"phone","raw_value":"13800002222"}]}`
	if err := os.WriteFile(epath, []byte(payload2), 0o600); err != nil {
		t.Fatal(err)
	}

	// 2) Zero-wakeup sleep & multi-source wakeup verification
	var actMu sync.Mutex
	curAct := Activity{Known: true, HotspotActive: true, ClientsOnline: 0, WebUIActive: false}
	curSim := false
	actCh := make(chan struct{})
	setAct := func(next Activity, sim bool) {
		actMu.Lock()
		curAct = next
		curSim = sim
		old := actCh
		actCh = make(chan struct{})
		actMu.Unlock()
		close(old)
	}

	var actChecks atomic.Int32
	lg.activityHook = func() (<-chan struct{}, Activity, bool) {
		actChecks.Add(1)
		actMu.Lock()
		defer actMu.Unlock()
		return actCh, curAct, curSim
	}

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		lg.runLoop(stopCh)
	}()
	defer func() {
		select {
		case <-doneCh:
		default:
			close(stopCh)
			<-doneCh
		}
	}()

	// Before sleeping, runLoop must perform one final tail syncFromDisk (DiskReadCount becomes 2) and stop ticker!
	waitLeakGuardCond(t, 2*time.Second, "final syncFromDisk and zero-wakeup ticker stop", func() bool {
		return actChecks.Load() >= 1 && !lg.IsTickerActive() && lg.DiskReadCount() == 2
	})

	// While sleeping with 0 wakeups, even wait 80ms: ticker remains stopped
	time.Sleep(80 * time.Millisecond)
	if lg.IsTickerActive() {
		t.Fatal("ticker should stay stopped during idle hotspot with 0 clients, no WebUI, and 0 SSE")
	}

	// Connect SSE client -> wakes runLoop and activates ticker!
	srv := httptest.NewServer(mux)
	defer srv.Close()
	sseCtx, sseCancel := context.WithTimeout(context.Background(), 2*time.Second)
	sseReq, _ := http.NewRequestWithContext(sseCtx, http.MethodGet, srv.URL+"/api/leakguard/stream", nil)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		sseCancel()
		t.Fatalf("SSE connect: %v", err)
	}
	waitLeakGuardCond(t, 2*time.Second, "SSE connect wakes LeakGuard ticker", func() bool {
		return lg.IsTickerActive()
	})

	// Disconnect SSE client -> returns to zero-wakeup stopped ticker!
	sseCancel()
	_ = sseResp.Body.Close()
	waitLeakGuardCond(t, 2*time.Second, "SSE disconnect stops LeakGuard ticker", func() bool {
		return leakSSEActiveConns.Load() == 0 && !lg.IsTickerActive()
	})

	// Activity signal: client comes online -> wakes ticker!
	setAct(Activity{Known: true, HotspotActive: true, ClientsOnline: 1, WebUIActive: false}, false)
	waitLeakGuardCond(t, 2*time.Second, "ClientsOnline=1 wakes LeakGuard ticker", func() bool {
		return lg.IsTickerActive()
	})

	// Hotspot turns off -> stops ticker!
	setAct(Activity{Known: true, HotspotActive: false, ClientsOnline: 0, WebUIActive: false}, false)
	waitLeakGuardCond(t, 2*time.Second, "HotspotActive=false stops LeakGuard ticker", func() bool {
		return !lg.IsTickerActive()
	})

	close(stopCh)
	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("leakGuardEngine.runLoop leaked goroutine on stop")
	}
}

type rc2DeadlineSSEWriter struct {
	mu           sync.Mutex
	hdr          http.Header
	deadlines    []time.Time
	writes       int
	failAfterN   int
	status       int
	readyFlushed chan struct{}
}

func (w *rc2DeadlineSSEWriter) Header() http.Header {
	if w.hdr == nil {
		w.hdr = make(http.Header)
	}
	return w.hdr
}

func (w *rc2DeadlineSSEWriter) WriteHeader(code int) { w.status = code }

func (w *rc2DeadlineSSEWriter) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	w.deadlines = append(w.deadlines, t)
	w.mu.Unlock()
	return nil
}

func (w *rc2DeadlineSSEWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.writes++
	n := w.writes
	failAt := w.failAfterN
	w.mu.Unlock()
	if failAt > 0 && n >= failAt {
		return 0, os.ErrDeadlineExceeded
	}
	return len(p), nil
}

func (w *rc2DeadlineSSEWriter) Flush() {
	select {
	case w.readyFlushed <- struct{}{}:
	default:
	}
}

func TestLeakGuardRC2LedgerCapsNotifySemAndSSEDeadline(t *testing.T) {
	srv, _, _ := newV6TestMux(t)
	lg := srv.v6State().leakGuard

	// 1. Notification concurrency semaphore cap = 2 (non-blocking drop on 3rd+ simultaneous hung Binder call)
	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	blockCh := make(chan struct{})
	lg.notifyExec = func(ctx context.Context, bin string, args ...string) error {
		cur := inFlight.Add(1)
		for {
			old := maxInFlight.Load()
			if cur <= old || maxInFlight.CompareAndSwap(old, cur) {
				break
			}
		}
		defer inFlight.Add(-1)
		select {
		case <-blockCh:
		case <-ctx.Done():
		}
		return nil
	}
	for i := 0; i < 10; i++ {
		lg.postAndroidNotificationAsync(LeakEvent{
			ID: fmt.Sprintf("n_%d", i), Ts: 1700000000 + int64(i),
			DstHost: "example.org", LeakType: "phone", RawValue: "13812345678",
		}, true)
	}
	waitLeakGuardCond(t, time.Second, "2 concurrent notifications running", func() bool {
		return inFlight.Load() == 2
	})
	time.Sleep(25 * time.Millisecond)
	if got := maxInFlight.Load(); got > 2 {
		close(blockCh)
		t.Fatalf("concurrent notifications=%d exceeded semaphore cap 2", got)
	}
	close(blockCh)
	waitLeakGuardCond(t, time.Second, "notifications drained", func() bool {
		return inFlight.Load() == 0
	})
	lg.notifyExec = func(ctx context.Context, bin string, args ...string) error { return nil }

	// 2. cooldownLedger cap 4096 & tombstones cap 1024 + 7d TTL
	baseTs := int64(1800000000)
	lg.mu.Lock()
	lg.cfg.CooldownSec = 86400
	for i := 0; i < 4500; i++ {
		lg.cooldownLedger[fmt.Sprintf("02:00:00:00:00:01|h%d.example|phone", i)] = baseTs + int64(i%100)
	}
	lg.setTombstoneLocked("expired.7d.example", baseTs-8*86400)
	for i := 0; i < 1200; i++ {
		lg.setTombstoneLocked(fmt.Sprintf("tb-%d.example", i), baseTs+int64(i%60))
	}
	lg.mu.Unlock()

	lg.IngestEvents([]LeakEvent{{
		ID: "cap_trigger", Ts: baseTs + 200, MAC: "02:00:00:00:00:01",
		DstHost: "fresh.example", LeakType: "token", RawValue: "secret",
	}})

	lg.mu.Lock()
	cdLen := len(lg.cooldownLedger)
	tbLen := len(lg.tombstones)
	_, expiredAlive := lg.tombstones["expired.7d.example"]
	lg.mu.Unlock()
	if cdLen > leakMaxCooldownEntries {
		t.Fatalf("cooldownLedger=%d exceeds cap %d", cdLen, leakMaxCooldownEntries)
	}
	if tbLen > leakMaxTombstones {
		t.Fatalf("tombstones=%d exceeds cap %d", tbLen, leakMaxTombstones)
	}
	if expiredAlive {
		t.Fatal("tombstone older than 7d TTL should have been evicted")
	}

	// 3. SSE stream sets ~10s write deadline per frame and releases slot immediately on write timeout
	lg.mu.Lock()
	lg.sseHeartbeat = 20 * time.Millisecond
	lg.mu.Unlock()

	dw := &rc2DeadlineSSEWriter{
		failAfterN:   2, // 1st write (ready) succeeds, 2nd write (heartbeat) fails with ErrDeadlineExceeded
		readyFlushed: make(chan struct{}, 4),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/leakguard/stream", nil).WithContext(ctx)
	doneSSE := make(chan struct{})
	go func() {
		srv.apiLeakGuardStream(dw, req)
		close(doneSSE)
	}()
	select {
	case <-doneSSE:
	case <-time.After(time.Second):
		t.Fatal("apiLeakGuardStream did not exit promptly on write deadline error")
	}
	if leakSSEActiveConns.Load() != 0 {
		t.Fatalf("SSE slot leaked: activeConns=%d, want 0", leakSSEActiveConns.Load())
	}
	dw.mu.Lock()
	dls := append([]time.Time(nil), dw.deadlines...)
	dw.mu.Unlock()
	hasNonZeroDeadline := false
	for _, dl := range dls {
		if !dl.IsZero() {
			hasNonZeroDeadline = true
			break
		}
	}
	if !hasNonZeroDeadline {
		t.Fatal("apiLeakGuardStream must set a non-zero write deadline before writing each SSE frame")
	}
}

func TestLeakGuardExpandConnBlocksSharedInfraAndReservedIPFilter(t *testing.T) {
	// 强校验跨片区锁定签名 detectSharedInfraIP(s *server, ipStr string) (bool, string) 零变更
	var sigGuard func(*server, string) (bool, string) = detectSharedInfraIP
	s, _, dir := newV6TestMux(t)

	// 1. 覆盖腾讯、阿里、字节、华为、苹果、谷歌、微软七大生态及公共云/CDN 识别
	sharedDomainCases := []struct {
		domain string
		ip     string
	}{
		{"short.weixin.qq.com", "198.51.100.11"},
		{"cos.ap-shanghai.myqcloud.com", "119.29.10.20"},
		{"oss-cn-hangzhou.aliyuncs.com", "47.95.10.20"},
		{"v26-web.douyinvod.com", "198.51.100.12"},
		{"tos-s3-cn-beijing.volces.com", "198.51.100.13"},
		{"grs.dbankcloud.com", "114.115.200.10"},
		{"gateway.icloud.com", "17.253.144.10"},
		{"mtalk.google.com", "142.250.190.46"},
		{"edge.microsoft.com", "20.190.159.2"},
		{"cdn.cloudflare.com", "104.16.132.229"},
	}
	for _, tc := range sharedDomainCases {
		if ok, vendor := detectSharedInfraTarget(s, tc.domain, tc.ip); !ok || vendor == "" {
			t.Fatalf("expected detectSharedInfraTarget(%q, %q) to hit shared infra, got ok=%v vendor=%q",
				tc.domain, tc.ip, ok, vendor)
		}
	}
	for _, sharedIP := range []string{
		"119.29.10.20",   // Tencent Cloud
		"47.95.10.20",    // Alibaba Cloud
		"114.115.200.10", // Huawei Cloud
		"17.253.144.10",  // Apple
		"142.250.190.46", // Google
		"20.190.159.2",   // Microsoft Azure
		"104.16.132.229", // Cloudflare
	} {
		if ok, vendor := sigGuard(s, sharedIP); !ok || vendor == "" {
			t.Fatalf("expected detectSharedInfraIP(%q) to detect shared cloud/CDN IP, got ok=%v vendor=%q",
				sharedIP, ok, vendor)
		}
	}

	// 2. 构造 run/dpi_ipname.json 反查表: 同时混入私网/回环/链路本地/CGNAT/Fake-IP/大厂共享网关 IP 与 1 个独立追踪器公网 IP
	nowTs := time.Now().Unix()
	ipNamesRaw := fmt.Sprintf(`{"entries":{
		"192.168.43.1":   {"name": "sdk.solo-tracker.example", "src": "dns", "ts": %d},
		"10.0.0.8":       {"name": "sdk.solo-tracker.example", "src": "dns", "ts": %d},
		"127.0.0.53":     {"name": "sdk.solo-tracker.example", "src": "dns", "ts": %d},
		"169.254.10.20":  {"name": "sdk.solo-tracker.example", "src": "dns", "ts": %d},
		"100.64.88.99":   {"name": "sdk.solo-tracker.example", "src": "dns", "ts": %d},
		"198.18.0.55":    {"name": "sdk.solo-tracker.example", "src": "dns", "ts": %d},
		"fc00::1234":     {"name": "sdk.solo-tracker.example", "src": "dns", "ts": %d},
		"104.16.132.229": {"name": "sdk.solo-tracker.example", "src": "dns", "ts": %d},
		"47.95.10.20":    {"name": "sdk.solo-tracker.example", "src": "dns", "ts": %d},
		"17.253.144.10":  {"name": "sdk.solo-tracker.example", "src": "dns", "ts": %d},
		"142.250.190.46": {"name": "sdk.solo-tracker.example", "src": "dns", "ts": %d},
		"20.190.159.2":   {"name": "sdk.solo-tracker.example", "src": "dns", "ts": %d},
		"198.51.100.77":  {"name": "short.weixin.qq.com", "src": "sni", "ts": %d},
		"198.51.100.88":  {"name": "sub.sdk.solo-tracker.example", "src": "dns", "ts": %d}
	}}`, nowTs, nowTs, nowTs, nowTs, nowTs, nowTs, nowTs, nowTs, nowTs, nowTs, nowTs, nowTs, nowTs, nowTs)
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "dpi_ipname.json"), []byte(ipNamesRaw), 0o600); err != nil {
		t.Fatal(err)
	}

	mac := "aa:bb:cc:dd:ee:01"
	cbf := connBlockFile{
		Items: []connBlock{
			{MAC: mac, Kind: "domain", Value: "sdk.solo-tracker.example", Ts: nowTs},
			{MAC: mac, Kind: "domain", Value: "weixin.qq.com", Ts: nowTs},
		},
	}
	expanded := s.expandConnBlocks(cbf)
	wantOnly := mac + " 198.51.100.88"
	if len(expanded) != 1 || expanded[0] != wantOnly {
		t.Fatalf("expandConnBlocks leaked shared/reserved IPs into HNC_CONNBLK: got=%v want=[%q]", expanded, wantOnly)
	}
	// DNS 域名层阻断列表必须完整保留精确域名阻断项
	dnsLines := expandConnBlockDomains(cbf)
	if len(dnsLines) != 2 {
		t.Fatalf("expected 2 exact DNS domain block rules preserved, got %v", dnsLines)
	}

	// 3. actionConnBlockAdd 显式拒绝 CGNAT 100.64.0.0/10 与代理 Fake-IP 198.18.0.0/15
	for _, badIP := range []string{"100.64.0.1", "100.127.255.254", "198.18.0.1", "198.19.255.254"} {
		resp := actionConnBlockAdd(s, map[string]string{"mac": mac, "kind": "ip", "value": badIP})
		if resp.OK {
			t.Fatalf("expected actionConnBlockAdd to reject reserved/Fake-IP %s, got %+v", badIP, resp)
		}
	}
}

func TestLeakGuardEmptyMACGuardUndoStackAlsoIPAndDNSSync(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	lg := s.v6State().leakGuard
	lg.notifyExec = func(context.Context, string, ...string) error { return nil }

	// 1. 空 MAC 爆炸半径防呆: scope != "global" 时空 MAC 必须返回 HTTP 400 missing_mac, 严禁静默封锁全热点设备
	for _, body := range []string{
		`{"action":"block","dst_host":"blast-test.evil.example","mac":""}`,
		`{"action":"block","dst_host":"blast-test.evil.example","mac":"   ","scope":"device"}`,
	} {
		rec := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain", body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"reason_code":"missing_mac"`) {
			t.Fatalf("expected 400 missing_mac for %s, got %d %s", body, rec.Code, rec.Body.String())
		}
	}
	if len(readConnBlocks(dir).Items) != 0 {
		t.Fatalf("conn_blocks.json must stay empty after rejected empty-MAC requests")
	}

	// 显式指定 scope:"global" 且 mac 为空时允许全热点级封禁(00:00:00:00:00:00)并返回顶层 undo_id
	recGlobal := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		`{"action":"block","dst_host":"global-ad.evil.example","mac":"","scope":"global"}`)
	if recGlobal.Code != http.StatusOK {
		t.Fatalf("scope:global block failed: %d %s", recGlobal.Code, recGlobal.Body.String())
	}
	var globalResp struct {
		OK     bool   `json:"ok"`
		UndoID string `json:"undo_id"`
	}
	_ = json.Unmarshal(recGlobal.Body.Bytes(), &globalResp)
	if !globalResp.OK || globalResp.UndoID == "" {
		t.Fatalf("expected top-level undo_id in global block response, got %s", recGlobal.Body.String())
	}
	// 秒级同步检查: 不等 10s 轮询, s.dnsTK() 必须立即对任意客户端拦截该全局域名!
	if !s.dnsTK().blocked("aa:bb:cc:dd:ee:99", "sub.global-ad.evil.example") {
		t.Fatal("expected s.dnsTK() blocklist to sync immediately after global block")
	}

	// 2. 单设备封禁 + 独立公网 AlsoIP 双栈联动落盘、顶层 undo_id、底层失败压回栈顶与成功后 100% 干净回滚
	mac := "aa:bb:cc:dd:ee:01"
	recDual := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		fmt.Sprintf(`{"action":"block","dst_host":"dual-ad.evil.example","also_ip":"198.51.100.201","mac":%q}`, mac))
	if recDual.Code != http.StatusOK {
		t.Fatalf("dual block failed: %d %s", recDual.Code, recDual.Body.String())
	}
	var dualResp struct {
		OK            bool   `json:"ok"`
		UndoID        string `json:"undo_id"`
		BlockedAlsoIP string `json:"blocked_also_ip"`
	}
	_ = json.Unmarshal(recDual.Body.Bytes(), &dualResp)
	if !dualResp.OK || dualResp.UndoID == "" || dualResp.BlockedAlsoIP != "198.51.100.201" {
		t.Fatalf("unexpected dual block response: %s", recDual.Body.String())
	}
	if !s.dnsTK().blocked(mac, "api.dual-ad.evil.example") {
		t.Fatal("expected s.dnsTK() blocklist to sync immediately after device block")
	}

	// 注入失败的 bin/connblock_sync.sh 模拟底层解封同步失败: undo-block 必须返回 500 且将记录重新压回栈顶!
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	syncScript := filepath.Join(binDir, "connblock_sync.sh")
	if err := os.WriteFile(syncScript, []byte("echo 'mock iptables lock error'\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	recFailUndo := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/undo-block", `{}`)
	if recFailUndo.Code != http.StatusInternalServerError || strings.Contains(recFailUndo.Body.String(), `"ok":true`) {
		t.Fatalf("expected 500 ok:false when underlying connblock_sync.sh fails on undo, got %d %s",
			recFailUndo.Code, recFailUndo.Body.String())
	}
	lg.mu.Lock()
	stackLenAfterFail := len(lg.undoStack)
	topIDAfterFail := ""
	if stackLenAfterFail > 0 {
		topIDAfterFail = lg.undoStack[stackLenAfterFail-1].ID
	}
	lg.mu.Unlock()
	if stackLenAfterFail != 2 || topIDAfterFail != dualResp.UndoID {
		t.Fatalf("failed undo MUST re-push entry onto top of undoStack: len=%d topID=%q wantID=%q",
			stackLenAfterFail, topIDAfterFail, dualResp.UndoID)
	}

	// 修复底层脚本后再次执行 undo-block: 必须彻底移除域名及关联 AlsoIP, 且立即刷新 s.dnsTK() 放行!
	if err := os.WriteFile(syncScript, []byte("exit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	recOKUndo := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/undo-block", `{}`)
	if recOKUndo.Code != http.StatusOK {
		t.Fatalf("retry undo after script recovery failed: %d %s", recOKUndo.Code, recOKUndo.Body.String())
	}
	var undoResp struct {
		OK     bool   `json:"ok"`
		UndoID string `json:"undo_id"`
		AlsoIP string `json:"also_ip"`
	}
	_ = json.Unmarshal(recOKUndo.Body.Bytes(), &undoResp)
	if !undoResp.OK || undoResp.UndoID != dualResp.UndoID || undoResp.AlsoIP != "198.51.100.201" {
		t.Fatalf("unexpected undo response: %s", recOKUndo.Body.String())
	}
	for _, it := range readConnBlocks(dir).Items {
		if it.Value == "dual-ad.evil.example" || it.Value == "198.51.100.201" {
			t.Fatalf("undo failed to clean domain or AlsoIP from conn_blocks.json: %+v", it)
		}
	}
	if s.dnsTK().blocked(mac, "api.dual-ad.evil.example") {
		t.Fatal("expected s.dnsTK() blocklist to clear unblocked domain immediately after undo")
	}
}

func TestBlackboxRTTProbeActiveIdleNoFlushAndWifiStaAttribution(t *testing.T) {
	globalJitterBlackbox.Clear()
	t.Cleanup(globalJitterBlackbox.Clear)

	s, mux, _ := newV6TestMux(t)
	s.registerV6ScreenshotPackRoutes(mux)

	var arMu sync.Mutex
	arActive := false
	arRTT := 0.0
	s.blackboxAutorateHook = func() (blackboxAutorateReading, bool) {
		arMu.Lock()
		defer arMu.Unlock()
		if !arActive {
			return blackboxAutorateReading{}, false
		}
		return blackboxAutorateReading{
			RTTMs:       arRTT,
			BaseRTTMs:   20.0,
			CapacityBps: 12_500_000,
		}, true
	}

	var actMu sync.Mutex
	curAct := Activity{Known: true, HotspotActive: true, ClientsOnline: 1}
	actCh := make(chan struct{})
	s.blackboxActivityHook = func() (<-chan struct{}, Activity) {
		actMu.Lock()
		defer actMu.Unlock()
		return actCh, curAct
	}

	// 1. Autorate 未启用时: rtt_probe_active 必须严格为 false
	recGet0 := doGuardJSONReq(t, mux, http.MethodGet, "/api/v6/blackbox?limit=10", "")
	if recGet0.Code != http.StatusOK || !strings.Contains(recGet0.Body.String(), `"rtt_probe_active":false`) {
		t.Fatalf("expected rtt_probe_active:false when autorate disabled, got %d %s", recGet0.Code, recGet0.Body.String())
	}
	if bbSum, _ := s.v6ScreenshotPackSummary()["blackbox"].(map[string]any); bbSum["rtt_probe_active"] != false {
		t.Fatalf("expected summary blackbox.rtt_probe_active=false, got %+v", bbSum)
	}

	// 2. Autorate 启用且有新鲜真实 RTT 样本: 采样 5 帧(含 1 次突刺事件), 验证 rtt_probe_active:true
	arMu.Lock()
	arActive = true
	arRTT = 26.5
	arMu.Unlock()
	s.rateMu.Lock()
	s.rates = map[string]rateOut{"aa:bb:cc:dd:ee:01": {rxBps: 120_000, txBps: 40_000}}
	s.rateMu.Unlock()

	tBase := time.Now().Add(-5 * time.Second)
	for i := 0; i < 4; i++ {
		fr, _ := s.SampleBlackboxOnce(tBase.Add(time.Duration(i*200) * time.Millisecond))
		if !fr.RTTProbeActive {
			t.Fatalf("frame %d expected RTTProbeActive=true", i)
		}
	}
	arMu.Lock()
	arRTT = 98.0
	arMu.Unlock()
	spikeFr, spikeInc := s.SampleBlackboxOnce(tBase.Add(1200 * time.Millisecond))
	if !spikeFr.RTTProbeActive || spikeInc == nil {
		t.Fatalf("expected active spike frame & incident, got frame=%+v inc=%+v", spikeFr, spikeInc)
	}

	recGet1 := doGuardJSONReq(t, mux, http.MethodGet, "/api/v6/blackbox?limit=10", "")
	if !strings.Contains(recGet1.Body.String(), `"rtt_probe_active":true`) {
		t.Fatalf("expected rtt_probe_active:true when autorate has fresh RTT, got %s", recGet1.Body.String())
	}

	// 3. Law 7: 切入 lvlNoClients 与 lvlHotspotOff 空闲态后连续请求 sample_now, 严禁推入空白帧冲刷 blackboxRing!
	ticksBeforeIdle := globalJitterBlackbox.totalTicks.Load()
	for _, idleAct := range []Activity{
		{Known: true, HotspotActive: true, ClientsOnline: 0},
		{Known: true, HotspotActive: false, ClientsOnline: 0},
	} {
		actMu.Lock()
		curAct = idleAct
		actMu.Unlock()
		arMu.Lock()
		arActive = false
		arRTT = 0
		arMu.Unlock()

		for i := 0; i < 10; i++ {
			recNow := doGuardJSONReq(t, mux, http.MethodPost, "/api/v6/blackbox", `{"action":"sample_now"}`)
			if recNow.Code != http.StatusOK {
				t.Fatalf("idle sample_now failed: %d %s", recNow.Code, recNow.Body.String())
			}
			var nowResp struct {
				OK             bool              `json:"ok"`
				IdleSkipped    bool              `json:"idle_skipped"`
				RTTProbeActive bool              `json:"rtt_probe_active"`
				Frame          BlackboxFrame     `json:"frame"`
				Incident       *BlackboxIncident `json:"incident"`
			}
			if err := json.Unmarshal(recNow.Body.Bytes(), &nowResp); err != nil {
				t.Fatal(err)
			}
			if !nowResp.OK || !nowResp.IdleSkipped || nowResp.RTTProbeActive {
				t.Fatalf("expected idle_skipped=true & rtt_probe_active=false during %+v, got %+v", idleAct, nowResp)
			}
			if nowResp.Frame.Seq != spikeFr.Seq || nowResp.Incident == nil || nowResp.Incident.IncidentID != spikeInc.IncidentID {
				t.Fatalf("idle sample_now failed to preserve latest frame/incident: got frame.Seq=%d inc=%+v",
					nowResp.Frame.Seq, nowResp.Incident)
			}
		}
	}
	if gotTicks := globalJitterBlackbox.totalTicks.Load(); gotTicks != ticksBeforeIdle {
		t.Fatalf("idle sample_now pushed blank frames into blackboxRing: totalTicks=%d want=%d", gotTicks, ticksBeforeIdle)
	}
	framesAfterIdle, incsAfterIdle := globalJitterBlackbox.Snapshot(300, false)
	if len(framesAfterIdle) != 5 || len(incsAfterIdle) != 1 {
		t.Fatalf("expected 5 frames & 1 incident intact after 20 idle sample_now calls, got frames=%d incs=%d",
			len(framesAfterIdle), len(incsAfterIdle))
	}

	// 4. attributeBlackboxSpike: 上游为 wifi_sta 或 !SignalAvailable 时绝不归因为 5G/蜂窝基站信号掉格
	jb := NewJitterBlackbox(16, 8)
	_, incWifi := jb.RecordSample(BlackboxTickInput{
		Now:             time.Unix(1880000010, 0),
		RTTMs:           132.0,
		BaseRTTMs:       20.0,
		CapacityBps:     12_500_000,
		SignalAvailable: true,
		SignalMode:      "wifi_sta",
		SignalQuality:   "weak",
		SignalRSRPdBm:   -115,
		SignalSINRdB:    -5,
		Devices: []BlackboxDeviceSample{
			{MAC: "aa:bb:cc:dd:ee:01", Name: "掌机", RxBps: 25_000, TxBps: 12_000},
		},
	})
	if incWifi == nil || incWifi.CauseDim != BlackboxDimWifiJitter || incWifi.CulpritIsHog {
		t.Fatalf("expected wifi_jitter with CulpritIsHog=false for wifi_sta upstream, got %+v", incWifi)
	}
	if incWifi.RSRPdBm != 0 || incWifi.SINRdB != 0 {
		t.Fatalf("wifi_sta incident must not carry cellular RSRP/SINR: %+v", incWifi)
	}
	for _, forbidden := range []string{"基站", "蜂窝", "5G"} {
		if strings.Contains(incWifi.VerdictZh, forbidden) || strings.Contains(incWifi.RootCauseZh, forbidden) || strings.Contains(incWifi.CauseLabelZh, forbidden) {
			t.Fatalf("wifi_sta attribution falsely blamed cellular (%q): %+v", forbidden, incWifi)
		}
	}

	_, incNoSig := jb.RecordSample(BlackboxTickInput{
		Now:             time.Unix(1880000020, 0),
		RTTMs:           140.0,
		BaseRTTMs:       22.0,
		CapacityBps:     12_500_000,
		SignalAvailable: false,
		SignalMode:      "unknown",
		SignalRSRPdBm:   -118,
		Devices: []BlackboxDeviceSample{
			{MAC: "aa:bb:cc:dd:ee:01", Name: "掌机", RxBps: 20_000, TxBps: 10_000},
		},
	})
	if incNoSig == nil || incNoSig.CauseDim != BlackboxDimUpstreamJitter || incNoSig.CulpritIsHog {
		t.Fatalf("expected upstream_jitter with CulpritIsHog=false when !SignalAvailable, got %+v", incNoSig)
	}
	if incNoSig.RSRPdBm != 0 || incNoSig.SINRdB != 0 {
		t.Fatalf("!SignalAvailable incident must not carry cellular RSRP/SINR: %+v", incNoSig)
	}
	for _, forbidden := range []string{"基站", "蜂窝", "5G"} {
		if strings.Contains(incNoSig.VerdictZh, forbidden) || strings.Contains(incNoSig.RootCauseZh, forbidden) || strings.Contains(incNoSig.CauseLabelZh, forbidden) {
			t.Fatalf("!SignalAvailable attribution falsely blamed cellular (%q): %+v", forbidden, incNoSig)
		}
	}
}

func TestLeakGuardDualDomainEventsTargetScopeAndSelfFirewallClosedLoop(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	lg := s.v6State().leakGuard
	sf := s.v6State().selfFirewall
	lg.notifyExec = func(context.Context, string, ...string) error { return nil }

	// 1. 验证 v6FeaturesSummary 挂载 self_firewall 且初始统计就绪
	v6Sum0 := s.v6FeaturesSummary()
	if _, ok := v6Sum0["self_firewall"].(map[string]any); !ok {
		t.Fatalf("v6FeaturesSummary missing self_firewall: %+v", v6Sum0)
	}

	// 2. 启动带 ?scope=host 过滤的 SSE 监听客户端, 验证实时流仅推送 host 域事件并完整携带 origin/uid/pkg/app_name/CREDENTIAL/ID_CARD
	srv := httptest.NewServer(mux)
	defer srv.Close()
	sseCtx, sseCancel := context.WithCancel(context.Background())
	defer sseCancel()
	sseReq, _ := http.NewRequestWithContext(sseCtx, http.MethodGet, srv.URL+"/api/leakguard/stream?scope=host", nil)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatalf("connect SSE ?scope=host: %v", err)
	}
	defer sseResp.Body.Close()

	var sseFramesMu sync.Mutex
	var sseLeakEvents []LeakEvent
	go func() {
		buf := make([]byte, 4096)
		var acc string
		for {
			n, rerr := sseResp.Body.Read(buf)
			if n > 0 {
				acc += string(buf[:n])
				for {
					idx := strings.Index(acc, "\n\n")
					if idx < 0 {
						break
					}
					frame := acc[:idx]
					acc = acc[idx+2:]
					if strings.Contains(frame, "event: leak") {
						for _, ln := range strings.Split(frame, "\n") {
							if strings.HasPrefix(ln, "data: ") {
								var ev LeakEvent
								if json.Unmarshal([]byte(strings.TrimPrefix(ln, "data: ")), &ev) == nil {
									sseFramesMu.Lock()
									sseLeakEvents = append(sseLeakEvents, ev)
									sseFramesMu.Unlock()
								}
							}
						}
					}
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	waitLeakGuardCond(t, time.Second, "SSE subscriber registered", func() bool {
		lg.mu.Lock()
		defer lg.mu.Unlock()
		return len(lg.subs) == 1
	})

	// 3. 写入混合热点事件 (Origin 留空默认 "hotspot") 与本机事件 (Origin="host", 含 CREDENTIAL 与 ID_CARD)
	eventsPayload := `{"events":[
		{"id":"ev_hs_1","ts":1890000001,"mac":"aa:bb:cc:dd:ee:01","src_ip":"192.168.43.11","dst_host":"hs-leak.ad-net.example","leak_type":"ID_CARD","raw_value":"110101199003071234","hit_count":2},
		{"id":"ev_host_1","ts":1890000002,"origin":"host","uid":10321,"pkg":"com.leaky.sdkapp","app_name":"某天气日历","src_ip":"10.20.30.40","dst_host":"host-leak.ad-net.example","dst_port":80,"proto":"http","leak_type":"CREDENTIAL","raw_value":"Bearer eyJhbGciOiJIUzI1NiJ9.secret","hit_count":3},
		{"id":"ev_both_hs","ts":1890000003,"origin":"hotspot","mac":"aa:bb:cc:dd:ee:01","src_ip":"192.168.43.11","dst_host":"dual-leak.ad-net.example","leak_type":"PHONE","raw_value":"13812345678","hit_count":1},
		{"id":"ev_both_host","ts":1890000004,"origin":"host","uid":10322,"pkg":"com.second.app","app_name":"某清理大师","src_ip":"10.20.30.40","dst_host":"dual-leak.ad-net.example","dst_port":8080,"proto":"http","leak_type":"ID_CARD","raw_value":"31010119920808567X","hit_count":1}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "run", "leakguard_events.json"), []byte(eventsPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	lg.syncFromDisk()

	// 验证 ?scope=host 的 SSE 流只收到 2 条本机事件, 且 CREDENTIAL / ID_CARD 标签精确翻译
	waitLeakGuardCond(t, time.Second, "2 host SSE events received", func() bool {
		sseFramesMu.Lock()
		defer sseFramesMu.Unlock()
		return len(sseLeakEvents) == 2
	})
	sseFramesMu.Lock()
	gotSSE := append([]LeakEvent(nil), sseLeakEvents...)
	sseFramesMu.Unlock()
	if gotSSE[0].Origin != "host" || gotSSE[0].UID != 10321 || gotSSE[0].Pkg != "com.leaky.sdkapp" ||
		gotSSE[0].AppName != "某天气日历" || gotSSE[0].LeakLabel != "账号凭据/Token" {
		t.Fatalf("unexpected SSE host event #0: %+v", gotSSE[0])
	}
	if gotSSE[1].LeakLabel != "身份证号" {
		t.Fatalf("expected ID_CARD label '身份证号', got %+v", gotSSE[1])
	}

	// 4. 验证 GET /api/leakguard/events?scope=all|hotspot|host 过滤与空 origin 默认 "hotspot"
	for _, tc := range []struct {
		query   string
		wantCnt int
	}{
		{"", 4},
		{"?scope=all", 4},
		{"?scope=hotspot", 2},
		{"?scope=host", 2},
	} {
		rec := doGuardJSONReq(t, mux, http.MethodGet, "/api/leakguard/events"+tc.query, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/leakguard/events%s failed: %d %s", tc.query, rec.Code, rec.Body.String())
		}
		var snap struct {
			Events      []LeakEvent `json:"events"`
			HostHits    int64       `json:"host_hits"`
			HotspotHits int64       `json:"hotspot_hits"`
			AffectedApp int         `json:"affected_apps"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
			t.Fatal(err)
		}
		if len(snap.Events) != tc.wantCnt || snap.HostHits != 4 || snap.HotspotHits != 3 || snap.AffectedApp != 2 {
			t.Fatalf("scope %q mismatch: len=%d(want %d) hostHits=%d hotspotHits=%d affectedApps=%d",
				tc.query, len(snap.Events), tc.wantCnt, snap.HostHits, snap.HotspotHits, snap.AffectedApp)
		}
		for _, ev := range snap.Events {
			if ev.Origin != "hotspot" && ev.Origin != "host" {
				t.Fatalf("event missing normalized origin: %+v", ev)
			}
		}
	}
	badScopeRec := doGuardJSONReq(t, mux, http.MethodGet, "/api/leakguard/events?scope=invalid", "")
	if badScopeRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid ?scope=invalid, got %d", badScopeRec.Code)
	}

	// 5. 测试 target_scope="host" 封禁本机域名 (无需传客户端 MAC) + summary() 指标 + 一键撤销
	blkHost := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		`{"action":"block","target_scope":"host","dst_host":"host-leak.ad-net.example"}`)
	if blkHost.Code != http.StatusOK || !strings.Contains(blkHost.Body.String(), `"self_blocked":true`) {
		t.Fatalf("target_scope=host block failed: %d %s", blkHost.Code, blkHost.Body.String())
	}
	if !sf.IsDomainBlocked("sub.host-leak.ad-net.example") {
		t.Fatal("expected selfFirewall to block host-leak.ad-net.example and subdomains")
	}
	sumAfterHostBlk := lg.summary()
	if sumAfterHostBlk["host_hits"] != int64(4) || sumAfterHostBlk["hotspot_hits"] != int64(3) ||
		sumAfterHostBlk["affected_apps"] != 2 || sumAfterHostBlk["self_blocked_domains"] != 1 {
		t.Fatalf("leakGuard.summary() dual-domain stats mismatch: %+v", sumAfterHostBlk)
	}

	// 验证本机事件 ev_host_1 的 is_blocked 自动变为 true, 而热点事件不受影响
	hostEvRec := doGuardJSONReq(t, mux, http.MethodGet, "/api/leakguard/events?scope=host", "")
	if !strings.Contains(hostEvRec.Body.String(), `"is_blocked":true`) {
		t.Fatalf("expected host event is_blocked:true after target_scope=host block: %s", hostEvRec.Body.String())
	}

	// Undo 撤销该 host 封禁 -> selfFirewall 自动解封!
	undoHost := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/undo-block", `{}`)
	if undoHost.Code != http.StatusOK || sf.IsDomainBlocked("host-leak.ad-net.example") {
		t.Fatalf("undo target_scope=host failed: code=%d blocked=%v body=%s",
			undoHost.Code, sf.IsDomainBlocked("host-leak.ad-net.example"), undoHost.Body.String())
	}

	// 6. 测试 target_scope="both" 同时封禁热点设备与本机域名, 并测试按 target_scope 分步撤销!
	blkBoth := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		`{"action":"block","target_scope":"both","dst_host":"dual-leak.ad-net.example","mac":"aa:bb:cc:dd:ee:01"}`)
	if blkBoth.Code != http.StatusOK || !sf.IsDomainBlocked("dual-leak.ad-net.example") ||
		!s.dnsTK().blocked("aa:bb:cc:dd:ee:01", "dual-leak.ad-net.example") {
		t.Fatalf("target_scope=both failed to block both domains: code=%d body=%s", blkBoth.Code, blkBoth.Body.String())
	}

	// 先仅撤销本机侧 (target_scope:"host") -> 本机解封, 热点侧保持封禁且仍留在撤销栈中!
	undoPartHost := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/undo-block", `{"target_scope":"host"}`)
	if undoPartHost.Code != http.StatusOK || sf.IsDomainBlocked("dual-leak.ad-net.example") {
		t.Fatalf("partial undo target_scope=host failed: %d %s", undoPartHost.Code, undoPartHost.Body.String())
	}
	if !s.dnsTK().blocked("aa:bb:cc:dd:ee:01", "dual-leak.ad-net.example") {
		t.Fatal("partial undo target_scope=host must keep hotspot MAC block intact")
	}

	// 再撤销剩余的热点侧 -> 双端全部干净清零!
	undoRestHotspot := doGuardJSONReq(t, mux, http.MethodPost, "/api/leakguard/undo-block", `{}`)
	if undoRestHotspot.Code != http.StatusOK || s.dnsTK().blocked("aa:bb:cc:dd:ee:01", "dual-leak.ad-net.example") {
		t.Fatalf("remaining hotspot undo failed: %d %s", undoRestHotspot.Code, undoRestHotspot.Body.String())
	}
}



