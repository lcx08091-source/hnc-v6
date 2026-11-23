package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func newV6TestMux(t *testing.T) (*server, *http.ServeMux, string) {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"data", "run", "etc/dpi_rules.d"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s := newServer(dir)
	mux := http.NewServeMux()
	registerV6FeatureRoutes(mux, s)
	return s, mux, dir
}

func doV6JSONReq(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("{}")
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "127.0.0.1:42000"
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-HNC-CSRF", "1")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// ── 1. LeakGuard 全链路单测: 合并事件、实时设备名、防注入通知、锁屏打码、双栈封锁、SSE 与清空 ──

func TestV6LeakGuardFullLifecycleAndInjectionGuard(t *testing.T) {
	s, mux, dir := newV6TestMux(t)

	// 写入设备表与手动备注名, 验证 GET /api/leakguard/events 实时关联补齐 device_name
	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"), []byte(`{
		"aa:bb:cc:dd:ee:01": {"ip": "192.168.43.101", "hostname": "dhcp-old-name", "last_seen": 1800000000}
	}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data", "device_names.json"), []byte(`{
		"aa:bb:cc:dd:ee:01": "小明的Pad"
	}`), 0o644)

	// 拦截并记录 Android 状态栏原生通知调用参数（验证纯参数数组直调、/system/bin/cmd、控制字符与危险符号剥离）
	var notifyMu sync.Mutex
	type notifyCall struct {
		bin  string
		args []string
	}
	var calls []notifyCall
	notifyDone := make(chan struct{}, 4)

	lg := s.v6State().leakGuard
	lg.notifyExec = func(ctx context.Context, bin string, args ...string) error {
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			t.Errorf("notification context missing 2s timeout deadline")
		}
		notifyMu.Lock()
		calls = append(calls, notifyCall{bin: bin, args: append([]string(nil), args...)})
		notifyMu.Unlock()
		select {
		case notifyDone <- struct{}{}:
		default:
		}
		return nil
	}

	// 模拟 dpid 写入含恶意命令注入字符的明文泄露事件
	dpidEvents := `{"events":[
		{
			"id": "ev_inject_1",
			"ts": 1800000100,
			"src_ip": "192.168.43.101",
			"dst_host": "ad-track.evil.example",
			"dst_ip": "203.0.113.55",
			"leak_type": "phone",
			"raw_value": "13812345678; rm -rf / $(id) ` + "`reboot`" + `\n\r",
			"raw_snippet": "POST /collect HTTP/1.1\r\nHost: ad-track.evil.example\r\n\r\nmobile=13812345678"
		}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "run", "leakguard_events.json"), []byte(dpidEvents), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := doV6JSONReq(t, mux, http.MethodGet, "/api/leakguard/events", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/leakguard/events code=%d body=%s", rec.Code, rec.Body.String())
	}
	var evResp struct {
		OK              bool            `json:"ok"`
		Events          []LeakEvent     `json:"events"`
		TotalHits       int64           `json:"total_hits"`
		AffectedDevices int             `json:"affected_devices"`
		BlockedDomains  int             `json:"blocked_domains"`
		Config          LeakGuardConfig `json:"config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &evResp); err != nil {
		t.Fatal(err)
	}
	if !evResp.OK || len(evResp.Events) != 1 || evResp.TotalHits != 1 || evResp.AffectedDevices != 1 {
		t.Fatalf("unexpected events payload: %+v", evResp)
	}
	if evResp.Config.Capacity != 300 || evResp.Config.CooldownSec != 300 || !evResp.Config.LockscreenMask {
		t.Fatalf("unexpected default config: %+v", evResp.Config)
	}
	gotEv := evResp.Events[0]
	if gotEv.DeviceName != "小明的Pad" || gotEv.MAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("device enrichment failed: %+v", gotEv)
	}
	// WebUI 面板永远展示 100% 未打码完整 raw_value 与 raw_snippet
	if !strings.Contains(gotEv.RawValue, "13812345678") || !strings.Contains(gotEv.RawSnippet, "POST /collect") {
		t.Fatalf("WebUI raw_value/raw_snippet should remain unmasked: %+v", gotEv)
	}

	// 等待异步通知完成并校验防注入与锁屏打码
	select {
	case <-notifyDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for async Android notification")
	}
	notifyMu.Lock()
	if len(calls) != 1 {
		t.Fatalf("expected 1 notification call, got %d", len(calls))
	}
	c0 := calls[0]
	notifyMu.Unlock()

	if c0.bin != "/system/bin/cmd" {
		t.Fatalf("expected /system/bin/cmd, got %q", c0.bin)
	}
	if len(c0.args) != 6 || c0.args[0] != "notification" || c0.args[1] != "post" || c0.args[2] != "-t" {
		t.Fatalf("unexpected cmd notification argv: %#v", c0.args)
	}
	maskedBody := c0.args[5]
	for _, forbidden := range []string{";", "$", "`", "\n", "\r", "13812345678"} {
		if strings.Contains(maskedBody, forbidden) {
			t.Fatalf("notification body leaked unmasked/dangerous token %q: %q", forbidden, maskedBody)
		}
	}
	if !strings.Contains(maskedBody, "****") || !strings.Contains(maskedBody, "[小明的Pad]") {
		t.Fatalf("masked notification body missing expected markers: %q", maskedBody)
	}

	// 校验系统告警已通过 alert.Append 写入 run/alerts.jsonl
	alertsBytes, err := os.ReadFile(filepath.Join(dir, "run", "alerts.jsonl"))
	if err != nil || !strings.Contains(string(alertsBytes), `"kind":"leakguard"`) {
		t.Fatalf("expected alert.Append record in alerts.jsonl, err=%v content=%s", err, string(alertsBytes))
	}

	// 测试 POST /api/leakguard/config: 关闭 lockscreen_mask 后验证通知输出完整格式 + 写入 leakguard_ctrl.json
	cfgRec := doV6JSONReq(t, mux, http.MethodPost, "/api/leakguard/config",
		`{"capacity":500,"cooldown_sec":0,"notify_enabled":true,"lockscreen_mask":false}`)
	if cfgRec.Code != http.StatusOK {
		t.Fatalf("POST config failed: %d %s", cfgRec.Code, cfgRec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "leakguard_ctrl.json")); err != nil {
		t.Fatalf("leakguard_ctrl.json not written: %v", err)
	}
	// 非法范围应返回 400
	badCfg := doV6JSONReq(t, mux, http.MethodPost, "/api/leakguard/config", `{"capacity":5}`)
	if badCfg.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for out-of-range capacity, got %d", badCfg.Code)
	}

	lg.IngestEvents([]LeakEvent{{
		ID:       "ev_unmasked_2",
		Ts:       1800000200,
		MAC:      "aa:bb:cc:dd:ee:01",
		SrcIP:    "192.168.43.101",
		DstHost:  "plain.login.example",
		LeakType: "password",
		RawValue: "MyPlainSecret99",
	}})
	select {
	case <-notifyDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for unmasked notification")
	}
	notifyMu.Lock()
	unmaskedBody := calls[len(calls)-1].args[5]
	notifyMu.Unlock()
	wantExact := "[小明的Pad] 向 [plain.login.example] 明文泄露 [password]: [MyPlainSecret99]"
	if unmaskedBody != wantExact {
		t.Fatalf("lockscreen_mask=false body = %q, want %q", unmaskedBody, wantExact)
	}

	// 测试 POST /api/leakguard/block-domain (域名拦截 + 纯 IPv6 拦截 + unblock)
	blkRec := doV6JSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		`{"action":"block","dst_host":"ad-track.evil.example","mac":"aa:bb:cc:dd:ee:01"}`)
	if blkRec.Code != http.StatusOK {
		t.Fatalf("block domain failed: %d %s", blkRec.Code, blkRec.Body.String())
	}
	blkIPv6 := doV6JSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		`{"action":"block","dst_host":"2001:db8:abcd::88","mac":"aa:bb:cc:dd:ee:01"}`)
	if blkIPv6.Code != http.StatusOK {
		t.Fatalf("block IPv6 failed: %d %s", blkIPv6.Code, blkIPv6.Body.String())
	}

	// 重新查询验证对应事件已被标记 is_blocked: true, 且 conn_blocks.dns 已生成
	recAfterBlk := doV6JSONReq(t, mux, http.MethodGet, "/api/leakguard/events", "")
	if !strings.Contains(recAfterBlk.Body.String(), `"is_blocked":true`) {
		t.Fatalf("expected is_blocked:true after block-domain: %s", recAfterBlk.Body.String())
	}
	dnsFlat, _ := os.ReadFile(filepath.Join(dir, "run", "conn_blocks.dns"))
	if !strings.Contains(string(dnsFlat), "aa:bb:cc:dd:ee:01 ad-track.evil.example") {
		t.Fatalf("conn_blocks.dns missing domain rule: %s", string(dnsFlat))
	}

	// 解封域名
	unblkRec := doV6JSONReq(t, mux, http.MethodPost, "/api/leakguard/block-domain",
		`{"action":"unblock","dst_host":"ad-track.evil.example","mac":"aa:bb:cc:dd:ee:01"}`)
	if unblkRec.Code != http.StatusOK {
		t.Fatalf("unblock domain failed: %d %s", unblkRec.Code, unblkRec.Body.String())
	}

	// 测试 SSE 流推送 + 心跳帧
	lg.mu.Lock()
	lg.sseHeartbeat = 40 * time.Millisecond
	lg.mu.Unlock()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sseCtx, sseCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer sseCancel()
	sseReq, _ := http.NewRequestWithContext(sseCtx, http.MethodGet, srv.URL+"/api/leakguard/stream", nil)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatalf("SSE connect failed: %v", err)
	}
	defer sseResp.Body.Close()

	go func() {
		time.Sleep(60 * time.Millisecond)
		lg.IngestEvents([]LeakEvent{{
			ID:       "ev_sse_live",
			Ts:       1800000300,
			MAC:      "aa:bb:cc:dd:ee:01",
			DstHost:  "sse.test.example",
			LeakType: "token",
			RawValue: "Bearer_SSE_123",
		}})
	}()

	sc := bufio.NewScanner(sseResp.Body)
	gotHeartbeat := false
	gotLeakEvent := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, ": heartbeat") {
			gotHeartbeat = true
		}
		if strings.Contains(line, "Bearer_SSE_123") {
			gotLeakEvent = true
		}
		if gotHeartbeat && gotLeakEvent {
			break
		}
	}
	if !gotHeartbeat || !gotLeakEvent {
		t.Fatalf("SSE missing frames: gotHeartbeat=%v gotLeakEvent=%v", gotHeartbeat, gotLeakEvent)
	}

	sseCancel()
	_ = sseResp.Body.Close()

	// 测试 POST /api/leakguard/clear
	clrRec := doV6JSONReq(t, mux, http.MethodPost, "/api/leakguard/clear", `{}`)
	if clrRec.Code != http.StatusOK {
		t.Fatalf("clear failed: %d %s", clrRec.Code, clrRec.Body.String())
	}
	recAfterClr := doV6JSONReq(t, mux, http.MethodGet, "/api/leakguard/events", "")
	var afterClr struct {
		Events    []LeakEvent `json:"events"`
		TotalHits int64       `json:"total_hits"`
	}
	_ = json.Unmarshal(recAfterClr.Body.Bytes(), &afterClr)
	if len(afterClr.Events) != 0 || afterClr.TotalHits != 0 {
		t.Fatalf("expected 0 events after clear, got %+v", afterClr)
	}
}

// ── 2. Vector Express 单测: 常态满速、P2P 种子排除、prio 0 85% 护航与 60s 自动恢复 ──

func TestV6VectorExpressEscortAndP2PGuard(t *testing.T) {
	s, mux, _ := newV6TestMux(t)
	exp := s.v6State().express
	t0 := time.Unix(1800000000, 0)

	// 1) 常态空闲: 含未知/随机 MAC 设备 100% 满速无干预
	snap0 := exp.Step(t0, []VectorExpressDeviceSignal{
		{MAC: "f2:11:22:33:44:55", TrafficType: ttBrowsing, Confidence: 0.8, ActiveDstIPs: 6},
	})
	if snap0["state"] != expressStateIdle || snap0["bg_ceil_pct"] != 100 || snap0["unknown_devices_fullspeed"] != true {
		t.Fatalf("idle state should keep 100%% fullspeed: %+v", snap0)
	}

	// 2) BT/P2P 种子流量伪装成 UDP 高活跃连接（并发外网 IP = 120 > 48）: 必须排除不触发护航!
	snapP2P := exp.Step(t0.Add(5*time.Second), []VectorExpressDeviceSignal{
		{MAC: "aa:bb:cc:dd:ee:09", TrafficType: ttGaming, Confidence: 0.75, ActiveDstIPs: 120},
	})
	if snapP2P["state"] != expressStateIdle {
		t.Fatalf("P2P swarm should NOT trigger active_escort: %+v", snapP2P)
	}
	excl, _ := snapP2P["p2p_excluded_macs"].([]string)
	if len(excl) != 1 || excl[0] != "aa:bb:cc:dd:ee:09" {
		t.Fatalf("expected p2p_excluded_macs to record torrent device: %+v", snapP2P)
	}

	// 3) 真实游戏对局进入（低并发目的 IP = 3）: 立即激活 prio 0 浅驻留 fq_codel + 85% 背景池
	tGame := t0.Add(10 * time.Second)
	snapGame := exp.Step(tGame, []VectorExpressDeviceSignal{
		{MAC: "aa:bb:cc:dd:ee:01", TrafficType: ttGaming, Confidence: 0.9, FgAppName: "王者荣耀", ActiveDstIPs: 3},
	})
	if snapGame["state"] != expressStateActive || snapGame["bg_ceil_pct"] != 85 || !s.isVectorExpressActive() {
		t.Fatalf("gaming device did not activate escort: %+v", snapGame)
	}
	dp, _ := snapGame["dataplane"].(VectorExpressDataplaneSpec)
	if !dp.Active || dp.ClassID != "1:8010" || dp.Prio != 0 || dp.FilterPrioV4 != 4 || dp.FilterPrioV6 != 5 || dp.Qdisc != "fq_codel" || dp.BgPoolCeilPct != 85 {
		t.Fatalf("unexpected dataplane spec: %+v", dp)
	}

	// 4) 对局结束 30s 内保持 cooldown_hold 防换局抖动; 满 61s 自动恢复 100% 满速与硬件加速
	snapHold := exp.Step(tGame.Add(30*time.Second), nil)
	if snapHold["state"] != expressStateCooldown || !s.isVectorExpressActive() {
		t.Fatalf("expected cooldown_hold at +30s, got %+v", snapHold)
	}
	snapRecover := exp.Step(tGame.Add(61*time.Second), nil)
	if snapRecover["state"] != expressStateIdle || snapRecover["bg_ceil_pct"] != 100 || s.isVectorExpressActive() {
		t.Fatalf("expected full recovery after 60s, got %+v", snapRecover)
	}

	// 5) HTTP POST /api/v6/express 手动护航列表校验
	postRec := doV6JSONReq(t, mux, http.MethodPost, "/api/v6/express",
		`{"enabled":true,"auto_detect":true,"forced_macs":["AA:BB:CC:DD:EE:02"]}`)
	if postRec.Code != http.StatusOK || !strings.Contains(postRec.Body.String(), `"active_escort"`) {
		t.Fatalf("POST /api/v6/express failed: %d %s", postRec.Code, postRec.Body.String())
	}
}

// ── 3. UpdateLeash + 96-system-updates-v6.json 单测: 200MB 免死缓冲、1500Kbps 拴绳、放行与暂停 ──

func TestV6UpdateLeash200MBStateMachineAndRules(t *testing.T) {
	// 核验仓库出厂规则文件 96-system-updates-v6.json 100% 符合 {"rules":[...]} Schema 且覆盖核心域名
	rulePath := filepath.Join("..", "..", "data", "dpi_rules.d", "96-system-updates-v6.json")
	rb, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("read 96-system-updates-v6.json: %v", err)
	}
	var parsedRules struct {
		Rules []struct {
			ID       string   `json:"id"`
			Category string   `json:"category"`
			Suffixes []string `json:"suffixes"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(rb, &parsedRules); err != nil || len(parsedRules.Rules) < 3 {
		t.Fatalf("invalid 96-system-updates-v6.json: err=%v rules=%d", err, len(parsedRules.Rules))
	}
	allSuf := make(map[string]bool)
	for _, r := range parsedRules.Rules {
		if r.ID == "" || r.Category == "" {
			t.Fatalf("rule missing id or category: %+v", r)
		}
		for _, suf := range r.Suffixes {
			allSuf[suf] = true
		}
	}
	for _, must := range []string{
		"dl.delivery.mp.microsoft.com", "windowsupdate.com", "do.dsp.mp.microsoft.com",
		"swcdn.apple.com", "updates.cdn-apple.com", "mesu.apple.com", "gdmf.apple.com",
		"steamcontent.com",
	} {
		if !allSuf[must] {
			t.Errorf("96-system-updates-v6.json missing required domain %q", must)
		}
	}

	s, mux, dir := newV6TestMux(t)
	_ = os.WriteFile(filepath.Join(dir, "etc", "dpi_rules.d", "96-system-updates-v6.json"), rb, 0o644)
	leash := s.v6State().leash
	leash.mu.Lock()
	leash.reloadRuleSuffixesLocked()
	leash.mu.Unlock()

	now := time.Unix(1800001000, 0)
	const mb = 1024 * 1024

	// 1) 前 199 MB: 免死缓冲期 100% 满速放行 (applied_kbps=0, state=grace_fullspeed)
	s1 := leash.ObserveFlows(now, []UpdateFlowInput{{
		FlowKey:   "tcp|192.168.43.10|51000|13.107.4.50|443",
		MAC:       "aa:bb:cc:dd:ee:11",
		SrcIP:     "192.168.43.10",
		DstIP:     "13.107.4.50",
		DstHost:   "tlu.dl.delivery.mp.microsoft.com",
		Proto:     "tcp",
		UpBytes:   2 * mb,
		DownBytes: 199 * mb,
		DownBps:   40_000_000,
	}})
	if len(s1) != 1 || s1[0].State != leashStateGrace || s1[0].AppliedKbps != 0 {
		t.Fatalf("199MB update flow should remain unthrottled in grace buffer: %+v", s1)
	}

	// 2) 跨过 200 MB 阈值 (205 MB): 自动触发温柔拴绳 1500 Kbps!
	s2 := leash.ObserveFlows(now.Add(5*time.Second), []UpdateFlowInput{{
		FlowKey:   "tcp|192.168.43.10|51000|13.107.4.50|443",
		MAC:       "aa:bb:cc:dd:ee:11",
		SrcIP:     "192.168.43.10",
		DstIP:     "13.107.4.50",
		DstHost:   "tlu.dl.delivery.mp.microsoft.com",
		Proto:     "tcp",
		UpBytes:   2 * mb,
		DownBytes: 205 * mb,
		DownBps:   40_000_000,
	}})
	if len(s2) != 1 || s2[0].State != leashStateLeashed || s2[0].AppliedKbps != 1500 {
		t.Fatalf("205MB update flow should be leashed at 1500 Kbps: %+v", s2)
	}

	// 3) 一键 bypass_once: 立即解除限速放行
	bypRec := doV6JSONReq(t, mux, http.MethodPost, "/api/v6/update_leash",
		`{"action":"bypass_once","mac":"aa:bb:cc:dd:ee:11","dst_host":"dl.delivery.mp.microsoft.com"}`)
	if bypRec.Code != http.StatusOK || !strings.Contains(bypRec.Body.String(), `"bypassed"`) {
		t.Fatalf("bypass_once failed: %d %s", bypRec.Code, bypRec.Body.String())
	}

	// 4) 一键 pause_update 联动 conn_blocks 暂停更新
	pauseRec := doV6JSONReq(t, mux, http.MethodPost, "/api/v6/update_leash",
		`{"action":"pause_update","mac":"aa:bb:cc:dd:ee:11","dst_host":"swcdn.apple.com"}`)
	if pauseRec.Code != http.StatusOK || !strings.Contains(pauseRec.Body.String(), `"paused":true`) {
		t.Fatalf("pause_update failed: %d %s", pauseRec.Code, pauseRec.Body.String())
	}

	// 5) 修改数字型阈值配置
	cfgRec := doV6JSONReq(t, mux, http.MethodPost, "/api/v6/update_leash", `{"grace_mb":300,"leash_kbps":2500}`)
	if cfgRec.Code != http.StatusOK || !strings.Contains(cfgRec.Body.String(), `"grace_mb":300`) {
		t.Fatalf("update_leash config update failed: %d %s", cfgRec.Code, cfgRec.Body.String())
	}
}

// ── 4. FlowScalpel 单测: 纯 LittleEndian Netlink 帧与 ct_events 互解、5s 自动清理及透视过滤 ──

func TestV6FlowScalpelNetlinkAndRestore(t *testing.T) {
	// 1) 验证 IPv4 TCP 与 IPv6 UDP 的 CTNETLINK DELETE 报文编码, 并通过 ct_events.go 的 parseCtDestroy 往返核验!
	v4Tuple := ScalpelTuple{
		Proto: "tcp",
		SrcIP: "192.168.43.88",
		Sport: 54321,
		DstIP: "104.16.132.229",
		Dport: 443,
	}
	msg4, err := buildConntrackDeleteNetlinkMsg(v4Tuple, 77)
	if err != nil {
		t.Fatalf("buildConntrackDeleteNetlinkMsg v4: %v", err)
	}
	nlLen := binary.LittleEndian.Uint32(msg4[0:4])
	nlType := binary.LittleEndian.Uint16(msg4[4:6])
	nlFlags := binary.LittleEndian.Uint16(msg4[6:8])
	nlSeq := binary.LittleEndian.Uint32(msg4[8:12])
	if int(nlLen) != len(msg4) || nlType != 0x0102 || nlFlags != 0x0005 || nlSeq != 77 || msg4[16] != 2 {
		t.Fatalf("invalid IPv4 nlmsghdr/nfgenmsg: len=%d type=0x%x flags=0x%x seq=%d fam=%d",
			nlLen, nlType, nlFlags, nlSeq, msg4[16])
	}
	parsed4, ok := parseCtDestroy(nlType, msg4[16:], time.Now())
	if !ok || parsed4.Key != "tcp|192.168.43.88|54321|104.16.132.229|443" {
		t.Fatalf("ct_events.parseCtDestroy failed to round-trip IPv4 delete msg: ok=%v ev=%+v", ok, parsed4)
	}

	v6Tuple := ScalpelTuple{
		Proto: "udp",
		SrcIP: "2408:8456:1234::88",
		Sport: 60123,
		DstIP: "2606:4700::6810:84e5",
		Dport: 443,
	}
	msg6, err := buildConntrackDeleteNetlinkMsg(v6Tuple, 78)
	if err != nil {
		t.Fatalf("buildConntrackDeleteNetlinkMsg v6: %v", err)
	}
	if msg6[16] != 10 {
		t.Fatalf("expected AF_INET6 (10), got %d", msg6[16])
	}
	parsed6, ok := parseCtDestroy(binary.LittleEndian.Uint16(msg6[4:6]), msg6[16:], time.Now())
	if !ok || parsed6.Key != "udp|2408:8456:1234::88|60123|2606:4700::6810:84e5|443" {
		t.Fatalf("ct_events.parseCtDestroy failed to round-trip IPv6 delete msg: ok=%v ev=%+v", ok, parsed6)
	}

	// 2) 测试 POST /api/v6/scalpel/cut (cut_once 精确五元组 RST + 5s 后自动清理 + cut_freeze_15m)
	s, mux, dir := newV6TestMux(t)
	sc := s.v6State().scalpel
	sc.resetDuration = 80 * time.Millisecond

	var mu sync.Mutex
	var deletedTuples []ScalpelTuple
	var v4Payloads []string
	sc.ctDelRunner = func(tp ScalpelTuple, seq uint32) error {
		mu.Lock()
		deletedTuples = append(deletedTuples, tp)
		mu.Unlock()
		return nil
	}
	sc.iptRunner = func(family int, payload string) error {
		if family == scalpelAfInet {
			mu.Lock()
			v4Payloads = append(v4Payloads, payload)
			mu.Unlock()
		}
		return nil
	}

	cutRec := doV6JSONReq(t, mux, http.MethodPost, "/api/v6/scalpel/cut", `{
		"mode": "cut_once",
		"proto": "tcp",
		"src_ip": "192.168.43.88",
		"sport": 54321,
		"dst_ip": "104.16.132.229",
		"dport": 443
	}`)
	if cutRec.Code != http.StatusOK {
		t.Fatalf("scalpel cut failed: %d %s", cutRec.Code, cutRec.Body.String())
	}

	mu.Lock()
	if len(deletedTuples) != 1 || deletedTuples[0].Sport != 54321 {
		t.Fatalf("expected Netlink conntrack delete for sport 54321, got %+v", deletedTuples)
	}
	if len(v4Payloads) == 0 || !strings.Contains(v4Payloads[0], "--sport 54321 --dport 443 -j REJECT --reject-with tcp-reset") {
		t.Fatalf("expected exact 5-tuple tcp-reset rule, got: %v", v4Payloads)
	}
	mu.Unlock()

	// 等待自动清理触发, 验证临时五元组规则已被干净摘除（条件轮询留足调度余量防 Flaky）
	deadline := time.Now().Add(1500 * time.Millisecond)
	var lastPayload string
	for {
		mu.Lock()
		lastPayload = v4Payloads[len(v4Payloads)-1]
		mu.Unlock()
		if !strings.Contains(lastPayload, "54321") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("5s temporary RST rule was NOT cleaned up after expiry: %s", lastPayload)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 验证 UDP 规则使用 icmp-port-unreachable 及 cut_freeze_15m 模式
	frzRec := doV6JSONReq(t, mux, http.MethodPost, "/api/v6/scalpel/cut", `{
		"mode": "cut_freeze_15m",
		"proto": "udp",
		"src_ip": "192.168.43.88",
		"sport": 55000,
		"dst_ip": "198.51.100.77",
		"dport": 3478
	}`)
	if frzRec.Code != http.StatusOK || !strings.Contains(frzRec.Body.String(), `"frozen_until"`) {
		t.Fatalf("cut_freeze_15m failed: %d %s", frzRec.Code, frzRec.Body.String())
	}
	mu.Lock()
	udpPayload := v4Payloads[len(v4Payloads)-1]
	mu.Unlock()
	if !strings.Contains(udpPayload, "--reject-with icmp-port-unreachable") {
		t.Fatalf("UDP scalpel rule should use icmp-port-unreachable: %s", udpPayload)
	}

	// 3) 测试 GET /api/v6/scalpel/flows 按设备 MAC 过滤五元组并关联域名
	fakeCT := filepath.Join(dir, "run", "fake_nf_conntrack")
	_ = os.WriteFile(fakeCT, []byte(
		"ipv4 2 tcp 6 300 ESTABLISHED src=192.168.43.88 dst=104.16.132.229 sport=51234 dport=443 packets=12 bytes=4096 src=104.16.132.229 dst=10.0.0.2 sport=443 dport=51234 packets=20 bytes=32768 [ASSURED]\n"+
			"ipv4 2 tcp 6 300 ESTABLISHED src=192.168.43.99 dst=1.1.1.1 sport=40000 dport=443 packets=5 bytes=500 src=1.1.1.1 dst=10.0.0.2 sport=443 dport=40000 packets=5 bytes=500 [ASSURED]\n",
	), 0o644)
	t.Setenv("HNC_CONNTRACK_PATH", fakeCT)
	ctState.mu.Lock()
	ctState.snap = nil
	ctState.mu.Unlock()

	_ = os.WriteFile(filepath.Join(dir, "data", "devices.json"), []byte(`{
		"aa:bb:cc:dd:ee:88": {"ip": "192.168.43.88", "hostname": "LivingRoomTV", "last_seen": 1800000000}
	}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "dpi_ipname.json"), []byte(`{
		"entries": {"104.16.132.229": {"name": "cdn.cloudflare-stream.example", "app": "bilibili", "app_name": "哔哩哔哩", "ts": 1800000000}}
	}`), 0o644)

	flowsRec := doV6JSONReq(t, mux, http.MethodGet, "/api/v6/scalpel/flows?mac=aa:bb:cc:dd:ee:88", "")
	if flowsRec.Code != http.StatusOK {
		t.Fatalf("GET /api/v6/scalpel/flows failed: %d %s", flowsRec.Code, flowsRec.Body.String())
	}
	var flowsBody struct {
		Total int              `json:"total"`
		Flows []map[string]any `json:"flows"`
	}
	_ = json.Unmarshal(flowsRec.Body.Bytes(), &flowsBody)
	if flowsBody.Total != 1 || flowsBody.Flows[0]["domain"] != "cdn.cloudflare-stream.example" ||
		flowsBody.Flows[0]["app_name"] != "哔哩哔哩" {
		t.Fatalf("scalpel flows filter/enrichment mismatch: %+v", flowsBody)
	}
}

// ── 5. ThermoCruise 单测: sysfs 零子进程探测、3.0°C 施密特回差 + 60s 防抖、快充与游戏护航豁免 ──

func TestV6ThermoCruiseSchmittHysteresisAndExemptions(t *testing.T) {
	s, mux, dir := newV6TestMux(t)
	th := s.v6State().thermo

	// 构造模拟 /sys/class/power_supply/{usb,battery} 节点验证自动识别真实 Battery 节点
	psRoot := filepath.Join(dir, "sysfs_power")
	usbDir := filepath.Join(psRoot, "usb")
	batDir := filepath.Join(psRoot, "qcom-battery")
	_ = os.MkdirAll(usbDir, 0o755)
	_ = os.MkdirAll(batDir, 0o755)
	_ = os.WriteFile(filepath.Join(usbDir, "type"), []byte("USB\n"), 0o644)
	_ = os.WriteFile(filepath.Join(batDir, "type"), []byte("Battery\n"), 0o644)
	_ = os.WriteFile(filepath.Join(batDir, "temp"), []byte("385\n"), 0o644) // 38.5°C
	_ = os.WriteFile(filepath.Join(batDir, "capacity"), []byte("76\n"), 0o644)
	_ = os.WriteFile(filepath.Join(batDir, "status"), []byte("Discharging\n"), 0o644)

	th.mu.Lock()
	th.sysfsRoot = psRoot
	th.cachedBatDir = ""
	th.mu.Unlock()

	rd0 := th.ReadBatteryFromSysfs()
	if !rd0.Available || rd0.SupplyNode != "qcom-battery" || rd0.TempC != 38.5 || rd0.CapacityPct != 76 || rd0.IsCharging {
		t.Fatalf("sysfs battery probe mismatch: %+v", rd0)
	}

	t0 := time.Unix(1800005000, 0)
	mkRd := func(tempC float64, capPct int, status string) ThermoBatteryReading {
		return ThermoBatteryReading{
			Available:   true,
			SupplyNode:  "qcom-battery",
			TempC:       tempC,
			CapacityPct: capPct,
			Status:      status,
			IsCharging:  strings.EqualFold(status, "Charging"),
		}
	}

	// 1) 38.5°C 常温 -> Stage 0
	s0 := th.Evaluate(t0, mkRd(38.5, 76, "Discharging"), false)
	if s0["effective_stage"] != 0 || s0["raw_thermal_stage"] != 0 {
		t.Fatalf("expected stage 0 at 38.5C, got %+v", s0)
	}

	// 2) 升至 42.3°C (>= 42.0°C) -> 立即进入一阶省电巡航
	s1 := th.Evaluate(t0.Add(10*time.Second), mkRd(42.3, 75, "Discharging"), false)
	if s1["effective_stage"] != 1 || s1["stage1_polling_relaxed"] != true || s1["stage2_shaper_active"] != false {
		t.Fatalf("expected stage 1 at 42.3C, got %+v", s1)
	}

	// 3) 降至 40.0°C（处于 39.0°C~42.0°C 的 3.0°C 施密特回差死区内）持续 120s -> 绝不提前退档!
	sDeadband := th.Evaluate(t0.Add(130*time.Second), mkRd(40.0, 74, "Discharging"), false)
	if sDeadband["raw_thermal_stage"] != 1 || sDeadband["effective_stage"] != 1 {
		t.Fatalf("Schmitt hysteresis violated in deadband 40.0C: %+v", sDeadband)
	}

	// 4) 降至 38.9°C (<= 39.0°C): 仅持续 30s 仍保持一阶; 满 61s 后干净退出回 Stage 0!
	tCoolStart := t0.Add(140 * time.Second)
	sCool30 := th.Evaluate(tCoolStart, mkRd(38.9, 74, "Discharging"), false)
	if sCool30["raw_thermal_stage"] != 1 {
		t.Fatalf("should start 60s timer at tCoolStart, not exit immediately: %+v", sCool30)
	}
	sCoolMid := th.Evaluate(tCoolStart.Add(30*time.Second), mkRd(38.8, 74, "Discharging"), false)
	if sCoolMid["raw_thermal_stage"] != 1 {
		t.Fatalf("should hold stage 1 before 60s elapsed: %+v", sCoolMid)
	}
	sCoolDone := th.Evaluate(tCoolStart.Add(61*time.Second), mkRd(38.8, 74, "Discharging"), false)
	if sCoolDone["raw_thermal_stage"] != 0 || sCoolDone["effective_stage"] != 0 {
		t.Fatalf("expected clean exit to stage 0 after 60s <= 39.0C: %+v", sCoolDone)
	}

	// 5) 升至 46.0°C (>= 45.0°C, 未充电且无游戏护航) -> 触发二阶降速保护
	tHot := tCoolStart.Add(90 * time.Second)
	sStage2 := th.Evaluate(tHot, mkRd(46.0, 70, "Discharging"), false)
	if sStage2["effective_stage"] != 2 || sStage2["stage2_shaper_active"] != true || sStage2["stage2_exempt"] != false {
		t.Fatalf("expected stage 2 shaper active at 46.0C discharging: %+v", sStage2)
	}

	// 6) 快充状态豁免 (status="Charging", 46.5°C): 自动豁免二阶降速, 仅执行一阶轮询闭息!
	sCharging := th.Evaluate(tHot.Add(10*time.Second), mkRd(46.5, 72, "Charging"), false)
	if sCharging["effective_stage"] != 1 || sCharging["stage2_shaper_active"] != false ||
		sCharging["stage2_exempt"] != true || sCharging["exempt_reason"] != "charging" {
		t.Fatalf("Charging should exempt stage 2 shaper: %+v", sCharging)
	}

	// 7) Vector Express 游戏护航激活豁免 (Discharging, 46.5°C, expressActive=true): 同样豁免二阶降速!
	sExpress := th.Evaluate(tHot.Add(20*time.Second), mkRd(46.5, 71, "Discharging"), true)
	if sExpress["effective_stage"] != 1 || sExpress["stage2_shaper_active"] != false ||
		sExpress["stage2_exempt"] != true || sExpress["exempt_reason"] != "vector_express" {
		t.Fatalf("Vector Express should exempt stage 2 shaper: %+v", sExpress)
	}

	// 8) HTTP GET/POST /api/v6/thermo 与 v6FeaturesSummary 联调校验
	postRec := doV6JSONReq(t, mux, http.MethodPost, "/api/v6/thermo",
		`{"enabled":true,"stage2_shaper_enabled":true,"stage1_temp_c":43.0,"stage2_temp_c":46.0,"low_bat_pct":15}`)
	if postRec.Code != http.StatusOK || !strings.Contains(postRec.Body.String(), `"stage1_exit_temp_c":40`) {
		t.Fatalf("POST /api/v6/thermo failed: %d %s", postRec.Code, postRec.Body.String())
	}

	sum := s.v6FeaturesSummary()
	for _, key := range []string{"leakguard", "express", "update_leash", "scalpel", "thermo"} {
		if _, ok := sum[key]; !ok {
			t.Fatalf("v6FeaturesSummary missing module %q: %+v", key, sum)
		}
	}

	// 9) 删除 sysfs 目录后验证 PeekQuickState 纯内存零 sysfs IO 仍能返回上次缓存状态
	_ = os.RemoveAll(psRoot)
	qs := s.peekThermoQuickState()
	if !qs.Enabled || !qs.Available || qs.TempC <= 0 {
		t.Fatalf("peekThermoQuickState must read cached memory without sysfs IO: %+v", qs)
	}
}

func TestV6BackupRedactionAndLoopbackGuard(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dataDir, "rules.json"), []byte(`{
		"version": 1,
		"hotspot_ssid": "HNC_5G",
		"hotspot_pass": "SuperSecretPass99",
		"admin_token": "tok_secret_value",
		"devices": {},
		"blacklist": [],
		"whitelist": []
	}`), 0o600)
	_ = os.WriteFile(filepath.Join(dataDir, "vector_express.json"), []byte(`{"enabled":true}`), 0o600)
	_ = os.WriteFile(filepath.Join(dataDir, "update_leash.json"), []byte(`{"enabled":true}`), 0o600)
	_ = os.WriteFile(filepath.Join(dataDir, "thermo_cruise.json"), []byte(`{"enabled":true}`), 0o600)
	_ = os.WriteFile(filepath.Join(dataDir, "leakguard_config.json"), []byte(`{"config":{"capacity":300},"ignore_rules":["a.example"],"undo_stack":[{"op":"block"}]}`), 0o600)

	bundle, err := ExportBackupBundle(dir)
	if err != nil {
		t.Fatalf("ExportBackupBundle failed: %v", err)
	}
	if bundle.ModuleVersionCode != versionCode {
		t.Fatalf("bundle.ModuleVersionCode=%q want %q", bundle.ModuleVersionCode, versionCode)
	}
	for _, name := range []string{"rules.json", "vector_express.json", "update_leash.json", "thermo_cruise.json", "leakguard_config.json"} {
		if _, ok := bundle.Files[name]; !ok {
			t.Fatalf("expected %s in backup bundle, got keys=%v", name, bundle.FileSHA256)
		}
	}
	rulesStr := string(bundle.Files["rules.json"])
	if strings.Contains(rulesStr, "SuperSecretPass99") || strings.Contains(rulesStr, "hotspot_pass") ||
		strings.Contains(rulesStr, "tok_secret_value") || strings.Contains(rulesStr, "admin_token") {
		t.Fatalf("SECURITY: sensitive secrets leaked in exported rules.json: %s", rulesStr)
	}
	if !strings.Contains(rulesStr, `"hotspot_ssid":"HNC_5G"`) {
		t.Fatalf("non-sensitive hotspot_ssid was unexpectedly stripped: %s", rulesStr)
	}

	// 验证远程请求 POST /api/backup 被 403 拒绝 (仅限 loopback)
	dstDir := t.TempDir()
	dstSrv := newServer(dstDir)
	dstMux := http.NewServeMux()
	dstSrv.registerV6ScreenshotPackRoutes(dstMux)
	payload, _ := json.Marshal(bundle)

	remoteReq := httptest.NewRequest(http.MethodPost, "/api/backup", strings.NewReader(string(payload)))
	remoteReq.RemoteAddr = "192.168.43.88:54321"
	remoteReq.Host = "192.168.43.1:8443"
	remoteReq.Header.Set("Content-Type", "application/json")
	remoteReq.Header.Set("X-HNC-CSRF", "1")
	remoteReq = remoteReq.WithContext(context.WithValue(remoteReq.Context(), ctxKeyTokenID, "REMOTE_TOK_1"))
	remoteRec := httptest.NewRecorder()
	dstMux.ServeHTTP(remoteRec, remoteReq)
	if remoteRec.Code != http.StatusForbidden {
		t.Fatalf("remote POST /api/backup must return 403 Forbidden, got %d body=%s", remoteRec.Code, remoteRec.Body.String())
	}

	// 验证本机 loopback 请求成功恢复且落盘权限受限 (0600)
	localReq := httptest.NewRequest(http.MethodPost, "/api/backup", strings.NewReader(string(payload)))
	localReq.RemoteAddr = "127.0.0.1:45678"
	localReq.Host = "127.0.0.1:8080"
	localReq.Header.Set("Content-Type", "application/json")
	localReq.Header.Set("X-HNC-CSRF", "1")
	localRec := httptest.NewRecorder()
	dstMux.ServeHTTP(localRec, localReq)
	if localRec.Code != http.StatusOK {
		t.Fatalf("loopback POST /api/backup failed: %d %s", localRec.Code, localRec.Body.String())
	}
	if st, err := os.Stat(filepath.Join(dstDir, "data", "rules.json")); err == nil {
		if perm := st.Mode().Perm(); perm&0o077 != 0 {
			t.Fatalf("restored rules.json permissions too wide: %o (want 0600)", perm)
		}
	}

	// 验证 leakguard_config.json 超限拦截: ignore_rules > 256 或 undo_stack > 10 必须被拒绝
	tooManyIgnore := make([]string, 257)
	for i := range tooManyIgnore {
		tooManyIgnore[i] = "rule"
	}
	irBytes, _ := json.Marshal(map[string]any{"ignore_rules": tooManyIgnore})
	if err := validateBackupFileSemantics("leakguard_config.json", irBytes); err == nil {
		t.Fatal("expected validateBackupFileSemantics to reject ignore_rules > 256")
	}
	tooManyUndo := make([]int, 11)
	usBytes, _ := json.Marshal(map[string]any{"undo_stack": tooManyUndo})
	if err := validateBackupFileSemantics("leakguard_config.json", usBytes); err == nil {
		t.Fatal("expected validateBackupFileSemantics to reject undo_stack > 10")
	}
}

func TestV6ThermoWinterTempAndFullExemption(t *testing.T) {
	// 冬季低温 8.5°C: power_supply/battery/temp 原始值 "85" 必须按 0.1°C 解析为 8.5°C 而非 85°C
	if got, ok := parseSysfsTempCelsius("/sys/class/power_supply/battery/temp", "85"); !ok || got != 8.5 {
		t.Fatalf("battery winter temp raw=85 got %.2f (ok=%v), want 8.5", got, ok)
	}
	if got, ok := parseSysfsTempCelsius("/sys/class/thermal/thermal_zone0/temp", "45200"); !ok || got != 45.2 {
		t.Fatalf("thermal_zone temp raw=45200 got %.2f (ok=%v), want 45.2", got, ok)
	}

	// 验证 status="Full" (满电插电) 判定为 plugged-in 并豁免二阶降速与低电量保护
	s, _, dir := newV6TestMux(t)
	th := s.v6State().thermo
	psRoot := filepath.Join(dir, "sysfs_power_full")
	_ = os.MkdirAll(filepath.Join(psRoot, "bms"), 0o755)
	_ = os.MkdirAll(filepath.Join(psRoot, "battery"), 0o755)
	_ = os.WriteFile(filepath.Join(psRoot, "bms", "type"), []byte("Battery\n"), 0o644)
	_ = os.WriteFile(filepath.Join(psRoot, "bms", "temp"), []byte("300\n"), 0o644)
	_ = os.WriteFile(filepath.Join(psRoot, "bms", "status"), []byte("Unknown\n"), 0o644)
	_ = os.WriteFile(filepath.Join(psRoot, "battery", "type"), []byte("Battery\n"), 0o644)
	_ = os.WriteFile(filepath.Join(psRoot, "battery", "temp"), []byte("462\n"), 0o644)
	_ = os.WriteFile(filepath.Join(psRoot, "battery", "capacity"), []byte("100\n"), 0o644)
	_ = os.WriteFile(filepath.Join(psRoot, "battery", "status"), []byte("Full\n"), 0o644)

	th.mu.Lock()
	th.sysfsRoot = psRoot
	th.cachedBatDir = ""
	th.mu.Unlock()

	rd := th.ReadBatteryFromSysfs()
	if !rd.Available || rd.SupplyNode != "battery" || rd.TempC != 46.2 || !rd.IsCharging {
		t.Fatalf("expected battery node prioritized over bms with Full=>IsCharging=true, got %+v", rd)
	}
	ev := th.Evaluate(time.Unix(1800009000, 0), rd, false)
	if ev["stage2_shaper_active"] != false || ev["stage2_exempt"] != true {
		t.Fatalf("Full plugged-in status must exempt stage2 shaper: %+v", ev)
	}
}

func TestV6DataplaneAndLimitRegressions(t *testing.T) {
	// 1. tcFWLineRE 兼容真实 iproute2 格式与旧测试桩格式, 不误匹配 u32
	realLine := "filter parent 1: protocol all pref 1 fw chain 0 handle 0x820000/0xff0000 classid 1:2"
	if h, m, c := extractTCFWMatch(tcFWLineRE.FindStringSubmatch(realLine)); h != "0x820000" || m != "0xff0000" || c != "1:2" {
		t.Fatalf("real tc filter show line failed to match: h=%q m=%q c=%q", h, m, c)
	}
	legacyLine := "filter parent 1: protocol all pref 1 handle 0x850000/0xff0000 fw classid 1:5"
	if h, m, c := extractTCFWMatch(tcFWLineRE.FindStringSubmatch(legacyLine)); h != "0x850000" || m != "0xff0000" || c != "1:5" {
		t.Fatalf("legacy tc filter line failed to match: h=%q m=%q c=%q", h, m, c)
	}
	if m := tcFWLineRE.FindStringSubmatch("filter parent 1: protocol ip pref 105 u32 fh 800::800 flowid 1:5"); len(m) != 0 {
		t.Fatalf("u32 filter line must not match tcFWLineRE: %v", m)
	}

	// 2. readDeviceMarkSpec 低 16 位硬保护
	badDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(badDir, "bin"), 0o755)
	_ = os.WriteFile(filepath.Join(badDir, "bin", "hnc_constants.sh"),
		[]byte("HNC_DEV_MARK_SHIFT=8\nHNC_DEV_MARK_MASK=0x0000ffff\nHNC_DEV_MARK_BASE=0x00000080\n"), 0o644)
	val, mask := readDeviceMarkSpec(badDir, 5)
	if (val&0x0000ffff) != 0 || (mask&0x0000ffff) != 0 || mask != DefaultDevMarkMask {
		t.Fatalf("readDeviceMarkSpec failed low-16-bit guard: val=0x%x mask=0x%x", val, mask)
	}

	// 3. resolveOrthogonalFilterMask 绝不返回裸 markVal 且阻断低 16 位
	if got := resolveOrthogonalFilterMask(0x01000000, 0); got != DefaultAppQoSMarkMask {
		t.Fatalf("resolveOrthogonalFilterMask(0x01000000,0)=0x%x want 0x%x", got, DefaultAppQoSMarkMask)
	}
	if got := resolveOrthogonalFilterMask(0x01000001, 0x0000ffff); (got & 0x0000ffff) != 0 {
		t.Fatalf("resolveOrthogonalFilterMask leaked low 16 bits: 0x%x", got)
	}

	// 4. defaultCheckSchFQSysReady 结构化解析 available[], 不误判 fq_codel
	if _, err := os.Stat("/sys/module/sch_fq"); err != nil {
		qDir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(qDir, "run"), 0o755)
		_ = os.WriteFile(filepath.Join(qDir, "run", "qdisc_caps.json"),
			[]byte(`{"schema":1,"available":["fq_codel","sfq"],"chosen":"fq_codel"}`), 0o644)
		if defaultCheckSchFQSysReady(qDir) {
			t.Fatal("defaultCheckSchFQSysReady must not match fq_codel as fq")
		}
		_ = os.WriteFile(filepath.Join(qDir, "run", "qdisc_caps.json"),
			[]byte(`{"schema":1,"available":["fq_codel","fq"],"chosen":"fq_codel"}`), 0o644)
		if !defaultCheckSchFQSysReady(qDir) {
			t.Fatal("defaultCheckSchFQSysReady should match available=[\"fq\"]")
		}
	}

	// 5. midFromHTBClassMinor 与 htbClassMinorForMid 1..99 完整往返一致
	for mid := 1; mid <= 99; mid++ {
		minor, err := htbClassMinorForMid(mid)
		if err != nil {
			t.Fatalf("htbClassMinorForMid(%d) err=%v", mid, err)
		}
		gotMid, ok := midFromHTBClassMinor(minor)
		if !ok || gotMid != mid {
			t.Fatalf("midFromHTBClassMinor(0x%x) = (%d,%v), want (%d,true)", minor, gotMid, ok, mid)
		}
	}

	// 6. limitCtl 空闲无脏标记时不重复刷写 limit_ctl_state.json; 仅在 usageDirty 满 5m 时落盘
	lDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(lDir, "data"), 0o755)
	_ = os.MkdirAll(filepath.Join(lDir, "run"), 0o755)
	var actionMu sync.Mutex
	lc := newLimitCtl(lDir, &actionMu)
	tBase := time.Unix(1800010000, 0)
	lc.mu.Lock()
	lc.saveStateLocked(tBase, true)
	lc.mu.Unlock()
	stateFile := lc.statePath()
	oldTime := time.Unix(1700000000, 0)
	if err := os.Chtimes(stateFile, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes %s failed: %v", stateFile, err)
	}
	lc.mu.Lock()
	lc.saveStateLocked(tBase.Add(10*time.Minute), false)
	lc.mu.Unlock()
	st, err := os.Stat(stateFile)
	if err != nil {
		t.Fatalf("stat %s failed: %v", stateFile, err)
	}
	if !st.ModTime().Equal(oldTime) {
		t.Fatalf("idle limitCtl unexpectedly rewrote %s: mtime=%v want=%v", stateFile, st.ModTime(), oldTime)
	}
	lc.mu.Lock()
	lc.usageDirty = true
	lc.saveStateLocked(tBase.Add(10*time.Minute), false)
	lc.mu.Unlock()
	st2, err := os.Stat(stateFile)
	if err != nil || st2.ModTime().Equal(oldTime) {
		t.Fatalf("usageDirty limitCtl should persist after 5m interval: err=%v mtime=%v", err, st2.ModTime())
	}
}

func TestV6SelfStudioMigrationAndTmpfsRescue(t *testing.T) {
	s, _, dir := newV6TestMux(t)
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.Local)
	day := now.Format("20060102")
	prevDay := now.AddDate(0, 0, -1).Format("20060102")

	// 1) self_fg_truth.go: 写入路径迁至 data/self_studio/ + 1 MiB 单日硬上限 + 回退合并旧 run/
	legacyFG := filepath.Join(dir, "run", "self_fg."+prevDay+".jsonl")
	legacyRec, _ := json.Marshal(selfFGRecord{Ts: now.Add(-2 * time.Hour).Unix(), Pkg: "com.legacy.app", Source: "window"})
	if err := os.WriteFile(legacyFG, append(legacyRec, '\n'), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := appendSelfFG(dir, now, selfFGRecord{Ts: now.Unix(), Pkg: "com.studio.app", Source: "activities"}); err != nil {
		t.Fatalf("appendSelfFG failed: %v", err)
	}
	fgStudioPath := filepath.Join(dir, "data", "self_studio", "self_fg."+day+".jsonl")
	if _, err := os.Stat(fgStudioPath); err != nil {
		t.Fatalf("expected self_fg written under data/self_studio/: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "self_fg."+day+".jsonl")); !os.IsNotExist(err) {
		t.Fatalf("new self_fg must NOT be written into run/")
	}
	sum := summarizeSelfFG(dir, now)
	if sum.Switches24h != 2 || sum.LastPkg != "com.studio.app" {
		t.Fatalf("expected merged switches_24h=2 and LastPkg=com.studio.app, got %+v", sum)
	}

	// 验证单日 1 MiB 硬上限: 超限后停止当日追加, 文件体积绝不超过 1 MiB
	bigPkg := "com.cap." + strings.Repeat("a", 8000)
	for i := 0; i < 200; i++ {
		if err := appendSelfFG(dir, now, selfFGRecord{Ts: now.Unix() + int64(i+1), Pkg: bigPkg, Source: "activities"}); err != nil {
			t.Fatalf("appendSelfFG cap loop err: %v", err)
		}
	}
	fiCap, err := os.Stat(fgStudioPath)
	if err != nil || fiCap.Size() > selfFGMaxDayBytes {
		t.Fatalf("self_fg daily cap violated: err=%v size=%d max=%d", err, fiCap.Size(), selfFGMaxDayBytes)
	}

	// 2) main.go rescueRunTmpfs: 抢救 >4 MiB 膨胀文件(仅保留尾部 <=4 MiB) + 迁出 fg_timeline/apk_domains/app_labels_live + 立即删 run/ 原文件与 *.tmp*
	bloatedAttrib := filepath.Join(dir, "run", "self_attrib."+day+".jsonl")
	var sb strings.Builder
	row := `{"t":1800000000,"conns":[{"remote":"1.1.1.1:443"}]}` + "\n"
	for sb.Len() < (4<<20)+(512<<10) {
		sb.WriteString(row)
	}
	if err := os.WriteFile(bloatedAttrib, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "label_samples."+day+".jsonl"),
		[]byte(`{"ts":1800000010,"pkg":"com.demo.app","uid":10123,"sni":"api.demo.example"}`+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "fg_timeline."+day+".json"),
		[]byte(`{"date":"`+day+`","devices":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "apk_domains.json"),
		[]byte(`{"generated_at":1800000099,"apps":{"com.demo.app":{"label":"DemoApp"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "app_labels_live.json"), []byte(`{"com.demo.app":"DemoApp"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "orphan_crash.json.tmp.999"), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "self_capture.enabled"), []byte("enabled\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "self_attrib.enabled"), []byte("enabled\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cleaned := rescueRunTmpfs(dir)
	if cleaned < 6 {
		t.Fatalf("expected rescueRunTmpfs to clean/migrate >=6 files, got %d", cleaned)
	}

	rescuedAttrib := filepath.Join(dir, "data", "self_studio", "self_attrib."+day+".jsonl")
	stAttrib, err := os.Stat(rescuedAttrib)
	if err != nil || stAttrib.Size() == 0 || stAttrib.Size() > rescueMaxTailBytes {
		t.Fatalf("rescued self_attrib invalid: err=%v size=%v", err, stAttrib)
	}
	for _, mustGone := range []string{
		"self_attrib." + day + ".jsonl",
		"label_samples." + day + ".jsonl",
		"self_fg." + prevDay + ".jsonl",
		"fg_timeline." + day + ".json",
		"apk_domains.json",
		"app_labels_live.json",
		"orphan_crash.json.tmp.999",
	} {
		if _, err := os.Stat(filepath.Join(dir, "run", mustGone)); !os.IsNotExist(err) {
			t.Fatalf("run/%s should have been removed by rescueRunTmpfs", mustGone)
		}
	}
	// 实时开关标志文件必须保留在 run/
	for _, mustKeep := range []string{"self_capture.enabled", "self_attrib.enabled"} {
		if _, err := os.Stat(filepath.Join(dir, "run", mustKeep)); err != nil {
			t.Fatalf("run/%s must survive rescueRunTmpfs: %v", mustKeep, err)
		}
	}

	// 验证 apiSelfAttrib、loadAPKIndex、fgLoadDay 均从新路径正常读取
	attReq := httptest.NewRequest(http.MethodGet, "/api/self/attrib?limit=5", nil)
	attRec := httptest.NewRecorder()
	s.apiSelfAttrib(attRec, attReq)
	if attRec.Code != http.StatusOK || !strings.Contains(attRec.Body.String(), `"shown":5`) {
		t.Fatalf("apiSelfAttrib from data/self_studio failed: code=%d body=%s", attRec.Code, attRec.Body.String())
	}
	if ix := s.loadAPKIndex(); ix.apps != 1 || ix.labels["com.demo.app"] != "DemoApp" {
		t.Fatalf("loadAPKIndex from data/apk_domains.json failed: %+v", ix)
	}
	if d := fgLoadDay(dir, day); d == nil || d.Date != day {
		t.Fatalf("fgLoadDay from data/fg_timeline failed: %+v", d)
	}

	// 验证 self_attrib_purge 与 actionCacheClear 清理双目录与孤儿 .tmp, 且绝不误删 *.enabled 开关
	if r := dispatchAction(s, "self_attrib_purge", nil, true); !r.OK {
		t.Fatalf("self_attrib_purge failed: %+v", r)
	}
	if _, err := os.Stat(rescuedAttrib); !os.IsNotExist(err) {
		t.Fatalf("self_attrib_purge did not delete data/self_studio/self_attrib.*")
	}
	_ = os.WriteFile(filepath.Join(dir, "data", "dangling.json.tmp.12"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "label_samples.20260101.jsonl"), []byte("{}\n"), 0o644)
	if r := actionCacheClear(dir); !r.OK {
		t.Fatalf("actionCacheClear failed: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "dangling.json.tmp.12")); !os.IsNotExist(err) {
		t.Fatal("actionCacheClear did not remove data/*.tmp.*")
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "label_samples.20260101.jsonl")); !os.IsNotExist(err) {
		t.Fatal("actionCacheClear did not remove legacy run/label_samples.*")
	}
	for _, mustKeep := range []string{"self_capture.enabled", "self_attrib.enabled"} {
		if _, err := os.Stat(filepath.Join(dir, "run", mustKeep)); err != nil {
			t.Fatalf("run/%s must survive actionCacheClear: %v", mustKeep, err)
		}
	}
}

func TestV6SimulationPhysicalIsolationAndVectorSync(t *testing.T) {
	s, _, dir := newV6TestMux(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/vector_sync", s.apiVectorSync)
	mux.HandleFunc("/api/devices", s.apiDevices)
	mux.HandleFunc("/api/dpi_state", s.apiDPIState)

	// 写入 1 台真实设备与 run/dpi_state.json(验证 jsonCache 绝不被原地污染到 vector_sync)
	if err := os.WriteFile(filepath.Join(dir, "data", "devices.json"), []byte(`{
		"aa:bb:cc:dd:ee:01": {"ip": "192.168.43.10", "hostname": "RealPhone", "online": true, "last_seen": 1800000000}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run", "dpi_state.json"), []byte(`{
		"clients": {
			"aa:bb:cc:dd:ee:01": {"client_ip": "192.168.43.10", "client_mac": "aa:bb:cc:dd:ee:01", "last_seen": 1800000000}
		}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1) 开启仿真预设 home -> /api/devices 与 /api/dpi_state 可见 02:5e:00:*, /api/vector_sync 立即刷新 sim=true
	if r := actionSimPreset(s, map[string]string{"preset": "home"}); !r.OK {
		t.Fatalf("actionSimPreset failed: %+v", r)
	}
	devOn := doV6JSONReq(t, mux, http.MethodGet, "/api/devices", "")
	if devOn.Code != http.StatusOK || !strings.Contains(devOn.Body.String(), "02:5e:00:") {
		t.Fatalf("expected 02:5e:00:* devices in /api/devices when sim_enabled=true: %s", devOn.Body.String())
	}
	dpiOn := doV6JSONReq(t, mux, http.MethodGet, "/api/dpi_state", "")
	if dpiOn.Code != http.StatusOK || !strings.Contains(dpiOn.Body.String(), "02:5e:00:") {
		t.Fatalf("expected 02:5e:00:* clients in /api/dpi_state when sim_enabled=true: %s", dpiOn.Body.String())
	}
	vsOn := doV6JSONReq(t, mux, http.MethodGet, "/api/vector_sync", "")
	if vsOn.Code != http.StatusOK || !strings.Contains(vsOn.Body.String(), `"sim":true`) {
		t.Fatalf("expected /api/vector_sync live.sim=true immediately after preset: %s", vsOn.Body.String())
	}

	// 2) 验证 simMergeDPIState 深拷贝 clients map, 绝不原地污染 jsonCache 共享 map
	sharedClients := map[string]interface{}{
		"aa:bb:cc:dd:ee:01": map[string]interface{}{
			"client_ip":  "192.168.43.10",
			"client_mac": "aa:bb:cc:dd:ee:01",
		},
	}
	sharedRoot := map[string]interface{}{"clients": sharedClients}
	mergedOn := s.simMergeDPIState(sharedRoot).(map[string]interface{})
	mergedClients := mergedOn["clients"].(map[string]interface{})
	if len(mergedClients) <= 1 {
		t.Fatalf("expected simulated clients merged in copy, got %d", len(mergedClients))
	}
	if len(sharedClients) != 1 {
		t.Fatalf("BUG: simMergeDPIState mutated shared jsonCache clients map in place! len=%d", len(sharedClients))
	}

	// 注入内存模拟残留状态与被污染的 jsonCache 快照, 验证 sim_set(false) 瞬间清零并刷新快照
	simMAC := "02:5e:00:aa:bb:cc"
	s.rateMu.Lock()
	s.rates[simMAC] = rateOut{rxBps: 99999, txBps: 88888}
	s.rateMu.Unlock()
	fgSt.mu.Lock()
	fgSt.devs[simMAC] = &fgDev{shown: "douyin"}
	fgSt.mu.Unlock()
	s.jsonCache.mu.Lock()
	s.jsonCache.entries[filepath.Join(dir, "run", "dpi_state.json")] = jsonCacheEntry{
		modTime: time.Now(),
		size:    123,
		val: map[string]any{
			"clients": map[string]any{
				"sim-" + simMAC: map[string]any{
					"client_ip":  "192.168.43.201",
					"client_mac": simMAC,
					"last_seen":  float64(time.Now().Unix()),
				},
			},
		},
	}
	s.jsonCache.mu.Unlock()
	s.CoreHub().RefreshSnapshotNow()

	// 3) 执行 sim_set(false): 必须立即清空残留并调用 CoreHub().RefreshSnapshotNow(), /api/vector_sync 瞬间剔除全部 02:5e:00:* 且 sim=false
	if r := actionSimSet(s, map[string]string{"enabled": "false"}); !r.OK {
		t.Fatalf("actionSimSet(false) failed: %+v", r)
	}
	vsOff := doV6JSONReq(t, mux, http.MethodGet, "/api/vector_sync", "")
	if vsOff.Code != http.StatusOK {
		t.Fatalf("GET /api/vector_sync failed: %d", vsOff.Code)
	}
	if strings.Contains(vsOff.Body.String(), "02:5e:00:") || strings.Contains(vsOff.Body.String(), `"sim":true`) {
		t.Fatalf("ISOLATION BREACH: /api/vector_sync still contains sim state after sim_set(false): %s", vsOff.Body.String())
	}
	if !strings.Contains(vsOff.Body.String(), "aa:bb:cc:dd:ee:01") {
		t.Fatalf("real device missing from /api/vector_sync after sim_set(false): %s", vsOff.Body.String())
	}
	devOff := doV6JSONReq(t, mux, http.MethodGet, "/api/devices", "")
	if strings.Contains(devOff.Body.String(), "02:5e:00:") {
		t.Fatalf("/api/devices still contains 02:5e:00:* after sim_set(false): %s", devOff.Body.String())
	}
	dpiOff := doV6JSONReq(t, mux, http.MethodGet, "/api/dpi_state", "")
	if strings.Contains(dpiOff.Body.String(), "02:5e:00:") {
		t.Fatalf("/api/dpi_state still contains 02:5e:00:* after sim_set(false): %s", dpiOff.Body.String())
	}

	s.rateMu.Lock()
	_, rateHasSim := s.rates[simMAC]
	s.rateMu.Unlock()
	fgSt.mu.Lock()
	_, fgHasSim := fgSt.devs[simMAC]
	fgSt.mu.Unlock()
	if rateHasSim || fgHasSim {
		t.Fatalf("in-memory sim residue was not purged: rateHasSim=%v fgHasSim=%v", rateHasSim, fgHasSim)
	}

	// 4) 当 !s.simOn() 时, simMergeDPIState 主动过滤意外混入的 02:5e:00: 模拟客户端且不改动原 map
	pollutedClients := map[string]interface{}{
		"aa:bb:cc:dd:ee:01": map[string]interface{}{"client_mac": "aa:bb:cc:dd:ee:01"},
		"02:5e:00:11:22:33": map[string]interface{}{"client_mac": "02:5e:00:11:22:33"},
		"sim-ghost":         map[string]interface{}{"client_mac": "02:5e:00:44:55:66", "sim": true},
	}
	cleanedDPI := s.simMergeDPIState(map[string]interface{}{"clients": pollutedClients}).(map[string]interface{})
	outClients := cleanedDPI["clients"].(map[string]interface{})
	if len(outClients) != 1 || outClients["aa:bb:cc:dd:ee:01"] == nil {
		t.Fatalf("expected !simOn() to strip all 02:5e:00:* entries, got %+v", outClients)
	}
	if len(pollutedClients) != 3 {
		t.Fatalf("expected input pollutedClients map to remain unmutated, got len=%d", len(pollutedClients))
	}
}

func TestV6NetlinkStandbyZeroWakeupAndEpollReconnect(t *testing.T) {
	s, _, _ := newV6TestMux(t)

	prevAct := activityNow()
	origOpen := ctOpenDestroySubFn
	defer func() {
		ctOpenDestroySubFn = origOpen
		activityPublish(prevAct)
	}()

	var openSockets atomic.Int32
	var totalSubscribes atomic.Int32
	var writerMu sync.Mutex
	var peerWriteFD int = -1
	subReady := make(chan struct{}, 8)
	closedSig := make(chan struct{}, 8)

	ctOpenDestroySubFn = func() (*netlinkSubConn, error) {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		writerMu.Lock()
		if peerWriteFD >= 0 {
			_ = syscall.Close(peerWriteFD)
		}
		peerWriteFD = fds[1]
		writerMu.Unlock()

		openSockets.Add(1)
		totalSubscribes.Add(1)
		conn := newNetlinkSubConnFromFile(os.NewFile(uintptr(fds[0]), "mock-netlink-epoll"))
		conn.onClose = func() {
			openSockets.Add(-1)
			select {
			case closedSig <- struct{}{}:
			default:
			}
		}
		select {
		case subReady <- struct{}{}:
		default:
		}
		return conn, nil
	}
	defer func() {
		writerMu.Lock()
		if peerWriteFD >= 0 {
			_ = syscall.Close(peerWriteFD)
			peerWriteFD = -1
		}
		writerMu.Unlock()
	}()

	// 1) 初始处于待机态 lvlHotspotOff: CtEventLoop 绝不创建任何 socket (0 socket, 0 唤醒)
	activityPublish(Activity{Known: true, HotspotActive: false})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.CtEventLoop(stop)
	}()

	time.Sleep(80 * time.Millisecond)
	if got := openSockets.Load(); got != 0 || totalSubscribes.Load() != 0 {
		t.Fatalf("expected 0 sockets during initial lvlHotspotOff standby, got open=%d total=%d", got, totalSubscribes.Load())
	}

	// 2) 热点开启 -> 立即唤醒并建立 epoll 非阻塞订阅, 且能实时接收事件
	activityPublish(Activity{Known: true, HotspotActive: true, HotspotIface: "ap0", ClientsOnline: 1, ScreenKnown: true, ScreenOn: true})
	select {
	case <-subReady:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CtEventLoop to subscribe on hotspot wakeup")
	}
	if openSockets.Load() != 1 {
		t.Fatalf("expected 1 open socket when hotspot active, got %d", openSockets.Load())
	}

	delFrame, err := buildConntrackDeleteNetlinkMsg(ScalpelTuple{
		Proto: "tcp", SrcIP: "192.168.43.55", Sport: 51234, DstIP: "1.1.1.1", Dport: 443,
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = ctEventsDrain()
	writerMu.Lock()
	_, werr := syscall.Write(peerWriteFD, delFrame)
	writerMu.Unlock()
	if werr != nil {
		t.Fatalf("write mock netlink frame: %v", werr)
	}
	deadline := time.Now().Add(time.Second)
	gotEv := false
	for time.Now().Before(deadline) {
		evs, active, _ := ctEventsDrain()
		if active && len(evs) == 1 && evs[0].Key == "tcp|192.168.43.55|51234|1.1.1.1|443" {
			gotEv = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !gotEv {
		t.Fatal("epoll CtEventLoop did not deliver conntrack destroy frame")
	}

	// 3) 热点再次关闭进入 lvlHotspotOff -> 立即主动关闭订阅 socket 回到 0 socket 休眠
	activityPublish(Activity{Known: true, HotspotActive: false})
	select {
	case <-closedSig:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CtEventLoop to close socket on lvlHotspotOff")
	}
	if openSockets.Load() != 0 || ctEventsPrecise() {
		t.Fatalf("expected 0 open sockets and active=false in standby, got open=%d active=%v", openSockets.Load(), ctEventsPrecise())
	}

	// 4) stop 信号立即无泄漏退出
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("CtEventLoop did not exit promptly on stop")
	}
}
