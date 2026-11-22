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
