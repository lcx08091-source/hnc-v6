package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"hnc.io/dpid/alert"
)

// DPI v2 dns_takeover.go: 健康判定、fail-open / 退避 / 重下规则、动作校验、API 形状、
// IP→域名合并、查询日志(环 / 脱敏 / 按日文件保留)。

func TestDNSHealthEval(t *testing.T) {
	cases := []struct {
		in     dnsHealthIn
		ok     bool
		reason string
	}{
		{dnsHealthIn{SelfOK: true, DPkts: -1}, true, ""},
		{dnsHealthIn{SelfOK: false}, false, "selftest"},
		{dnsHealthIn{SelfOK: true, DUp: 20, DUpErr: 10, DPkts: -1}, false, "upstream_errors"},
		{dnsHealthIn{SelfOK: true, DUp: 19, DUpErr: 19, DPkts: -1}, true, ""}, // 样本太少不判
		{dnsHealthIn{SelfOK: true, DUp: 40, DUpErr: 5, DPkts: -1}, true, ""},
		{dnsHealthIn{SelfOK: true, DPkts: 10, DClient: 0}, false, "dnat_path"},
		{dnsHealthIn{SelfOK: true, DPkts: 10, DClient: 3}, true, ""},
		{dnsHealthIn{SelfOK: true, DPkts: 9, DClient: 0}, true, ""},
	}
	for i, c := range cases {
		ok, r := dnsHealthEval(c.in)
		if ok != c.ok || r != c.reason {
			t.Fatalf("case %d: got %v %q", i, ok, r)
		}
	}
}

func TestParseDumpsysDNSAndCounters(t *testing.T) {
	out := `NetworkAgentInfo{ ... LinkProperties: {InterfaceName: rmnet_data0 LinkAddresses: [ 10.1.2.3/30 ] DnsAddresses: [ /211.138.180.2,/211.138.180.3,/2409:8057::1 ] UsePrivateDns: false}
  other ... DnsAddresses: [ /211.138.180.2,/127.0.0.1 ]`
	got := parseDumpsysDNS(out)
	if strings.Join(got, ",") != "211.138.180.2,211.138.180.3,2409:8057::1" {
		t.Fatalf("%v", got)
	}
	if p, n, ok := parseDNSTKCounters(`{"present":true,"pkts":12,"v6_present":false,"pkts_v6":3}`); !p || n != 15 || !ok {
		t.Fatal("counters")
	}
	if _, _, ok := parseDNSTKCounters("garbage"); ok {
		t.Fatal("garbage counters")
	}
	for in, want := range map[string]string{"1.2.3.4": "1.2.3.4:53", "1.2.3.4:5353": "1.2.3.4:5353",
		"2001:db8::1": "[2001:db8::1]:53", "[2001:db8::1]:54": "[2001:db8::1]:54", "0.0.0.0": "", "x": "", "1.2.3.4:0": ""} {
		if g := dnsNormUpstream(in); g != want {
			t.Fatalf("norm %q = %q want %q", in, g, want)
		}
	}
}

// tkHarness 假脚本 / 假探测 / 假热点口, 控制器真跑(转发器监听 127.0.0.1 空闲端口)
type tkHarness struct {
	t       *testing.T
	dir     string
	s       *server
	tk      *dnsTakeover
	mu      sync.Mutex
	calls   []string
	upOK    bool // 上游 :53 探测
	selfOK  bool // 转发器自检
	present bool
	pkts    int64
	applyRC int
	v6res   string
	alerts  []alert.Alert
	now     time.Time
}

func newTKHarness(t *testing.T) *tkHarness {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"data", "run", "bin", "logs"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	h := &tkHarness{t: t, dir: dir, s: newServer(dir), upOK: true, selfOK: true, present: true, v6res: "0",
		now: time.Unix(1_800_000_000, 0)}
	h.tk = h.s.dnsTK()
	uc, ln, port := freeDualPort(t)
	uc.Close()
	ln.Close()
	h.tk.port = port
	h.tk.runScript = func(args ...string) (int, string) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.calls = append(h.calls, strings.Join(args, " "))
		switch args[0] {
		case "apply":
			if h.applyRC != 0 {
				return h.applyRC, "DNSTK=error apply_failed"
			}
			h.present = true
			return 0, "DNSTK=on iface=" + args[1] + " port=" + args[2] + " rules=2 v6=" + h.v6res
		case "remove":
			h.present = false
			return 0, "DNSTK=off"
		case "counters":
			b, _ := json.Marshal(map[string]interface{}{"present": h.present, "pkts": h.pkts})
			return 0, string(b)
		}
		return 2, "usage"
	}
	h.tk.probe = func(addr string, to time.Duration) (time.Duration, int, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if strings.HasSuffix(addr, ":53") {
			if h.upOK {
				return time.Millisecond, 3, nil
			}
			return 0, -1, errors.New("timeout")
		}
		if h.selfOK {
			return 2 * time.Millisecond, 3, nil
		}
		return 0, -1, errors.New("timeout")
	}
	h.tk.ifaceAddrs = func(string) ([]string, []string) { return []string{"127.0.0.1"}, nil }
	h.tk.hotspotIface = func() string { return "wlan2" }
	h.tk.systemDNS = func() []string { return nil }
	h.tk.blockSources = func(time.Time) *dnsBlockSet { return buildDNSBlockSet(nil, encdnsConf{}, nil) }
	h.tk.emitAlert = func(a alert.Alert) { h.mu.Lock(); h.alerts = append(h.alerts, a); h.mu.Unlock() }
	h.tk.now = func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.now }
	t.Cleanup(h.tk.Shutdown)
	return h
}

func (h *tkHarness) conf(c string) {
	_ = os.WriteFile(dnsTKPath(h.dir), []byte(c), 0o644)
}

func (h *tkHarness) takeCalls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.calls
	h.calls = nil
	return c
}

func (h *tkHarness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func (h *tkHarness) set(f func()) { h.mu.Lock(); f(); h.mu.Unlock() }

func (h *tkHarness) state() (string, bool) {
	h.tk.mu.Lock()
	defer h.tk.mu.Unlock()
	return h.tk.state, h.tk.active
}

func TestDNSTakeoverLifecycleFailOpen(t *testing.T) {
	h := newTKHarness(t)
	// 关闭: 首次 tick 撤一次残留规则, 之后不再 exec
	h.tk.tick()
	if c := h.takeCalls(); len(c) != 1 || c[0] != "remove" {
		t.Fatalf("first tick (off) calls %v", c)
	}
	h.tk.tick()
	if c := h.takeCalls(); len(c) != 0 {
		t.Fatalf("idle off tick must not exec: %v", c)
	}
	if st, _ := h.state(); st != "off" {
		t.Fatal(st)
	}

	// 打开 → 选 tether 上游, 自检通过, 下规则
	h.conf(`{"enabled":true}`)
	h.tk.tick()
	c := h.takeCalls()
	if len(c) != 1 || c[0] != "apply wlan2 "+strconv.Itoa(h.tk.port)+" 127.0.0.1 127.0.0.1" {
		t.Fatalf("apply calls %v", c)
	}
	if st, act := h.state(); st != "active" || !act || h.tk.upstream != "127.0.0.1:53" || h.tk.upstreamKind != "tether" {
		t.Fatalf("state %s active=%v up=%s", st, act, h.tk.upstream)
	}
	if h.tk.fwd == nil || len(h.tk.fwd.ListenAddrs()) != 1 {
		t.Fatal("forwarder must listen")
	}
	// 稳态: 只读计数, 不重下
	h.tk.tick()
	if c := h.takeCalls(); len(c) != 1 || c[0] != "counters" {
		t.Fatalf("steady calls %v", c)
	}
	// 规则被别人清掉 → 补回
	h.set(func() { h.present = false })
	h.tk.tick()
	if c := h.takeCalls(); len(c) != 2 || c[0] != "counters" || !strings.HasPrefix(c[1], "apply ") {
		t.Fatalf("re-apply calls %v", c)
	}
	// 自检失败(重试一次仍失败)→ fail-open: 撤规则 + 告警 + 退避
	h.set(func() { h.selfOK = false })
	h.tk.tick()
	c = h.takeCalls()
	if len(c) != 2 || c[1] != "remove" {
		t.Fatalf("failopen calls %v", c)
	}
	if st, act := h.state(); st != "failopen" || act {
		t.Fatalf("state %s active=%v", st, act)
	}
	if len(h.alerts) != 1 || h.alerts[0].Kind != dnsTKAlertKind || h.alerts[0].Extra["reason"] != "selftest" {
		t.Fatalf("alerts %+v", h.alerts)
	}
	// 冷却中: 即使恢复也不重下
	h.set(func() { h.selfOK = true })
	h.advance(30 * time.Second)
	h.tk.tick()
	if c := h.takeCalls(); len(c) != 0 {
		t.Fatalf("cooldown must not apply: %v", c)
	}
	// 冷却过了 → 重新接管
	h.advance(40 * time.Second)
	h.tk.tick()
	if c := h.takeCalls(); len(c) != 1 || !strings.HasPrefix(c[0], "apply ") {
		t.Fatalf("retry calls %v", c)
	}
	// DNAT 计数在涨, 转发器一条客户端查询都没收到 → dnat_path fail-open
	h.tk.tick() // 建立基线
	h.set(func() { h.pkts = 50 })
	h.tk.tick()
	if st, act := h.state(); st != "failopen" || act || h.tk.foReason != "dnat_path" {
		t.Fatalf("dnat path: %s %v %s", st, act, h.tk.foReason)
	}
	// 第二次 fail-open 退避翻倍(2 分钟)
	h.tk.mu.Lock()
	wait := h.tk.retryAt.Sub(h.now)
	h.tk.mu.Unlock()
	if wait != 2*time.Minute {
		t.Fatalf("backoff %v", wait)
	}
	h.takeCalls()
	// 关掉开关: 关转发器(规则已撤, 不重复 exec)
	h.conf(`{"enabled":false}`)
	h.tk.tick()
	if c := h.takeCalls(); len(c) != 0 {
		t.Fatalf("disable after failopen calls %v", c)
	}
	if h.tk.fwd != nil {
		t.Fatal("forwarder must be closed when disabled")
	}
}

func TestDNSTakeoverNoUpstreamAndHotspotDown(t *testing.T) {
	h := newTKHarness(t)
	h.conf(`{"enabled":true}`)
	h.set(func() { h.upOK = false })
	h.tk.tick()
	c := h.takeCalls()
	for _, x := range c {
		if strings.HasPrefix(x, "apply") {
			t.Fatalf("must not apply without upstream: %v", c)
		}
	}
	if st, _ := h.state(); st != "failopen" || h.tk.lastErr != "no_upstream" {
		t.Fatalf("state %s err %s", st, h.tk.lastErr)
	}
	// system 兜底
	h.tk.systemDNS = func() []string { return []string{"127.0.0.1", "10.9.9.9"} }
	h.tk.probe = func(addr string, to time.Duration) (time.Duration, int, error) {
		if addr == "10.9.9.9:53" || !strings.HasSuffix(addr, ":53") {
			return time.Millisecond, 0, nil
		}
		return 0, -1, errors.New("timeout")
	}
	h.advance(2 * time.Minute)
	h.tk.tick()
	if st, act := h.state(); st != "active" || !act || h.tk.upstream != "10.9.9.9:53" || h.tk.upstreamKind != "system" {
		t.Fatalf("system fallback: %s %v %s", st, act, h.tk.upstream)
	}
	h.takeCalls()
	// 热点关了 → 撤规则 + 关转发器
	h.tk.hotspotIface = func() string { return "" }
	h.tk.tick()
	if c := h.takeCalls(); len(c) != 1 || c[0] != "remove" {
		t.Fatalf("hotspot down calls %v", c)
	}
	if st, act := h.state(); st != "waiting_hotspot" || act || h.tk.fwd != nil {
		t.Fatalf("%s %v", st, act)
	}
}

func TestDNSTakeoverApplyFailAndShutdown(t *testing.T) {
	h := newTKHarness(t)
	h.conf(`{"enabled":true}`)
	h.set(func() { h.applyRC = 1 })
	h.tk.tick()
	if st, act := h.state(); st != "error" || act {
		t.Fatalf("%s %v", st, act)
	}
	h.set(func() { h.applyRC = 0; h.v6res = "unsupported" })
	h.tk.ifaceAddrs = func(string) ([]string, []string) { return []string{"127.0.0.1"}, []string{"::1"} }
	h.tk.tick()
	if st, act := h.state(); st != "active" || !act {
		t.Fatalf("%s %v", st, act)
	}
	h.tk.mu.Lock()
	v6s := h.tk.v6Status
	h.tk.mu.Unlock()
	if v6s != "untouched" {
		t.Fatalf("v6 unsupported must report untouched, got %s", v6s)
	}
	h.takeCalls()
	h.tk.Shutdown()
	if c := h.takeCalls(); len(c) != 1 || c[0] != "remove" {
		t.Fatalf("shutdown calls %v", c)
	}
	if st, act := h.state(); st != "stopped" || act || h.tk.fwd != nil {
		t.Fatal("shutdown state")
	}
}

func TestDNSTakeoverActionAndAPI(t *testing.T) {
	h := newTKHarness(t)
	s := h.s
	for _, p := range []map[string]string{
		{}, {"enabled": "maybe"}, {"block_mode": "drop"}, {"log_queries": "x"}, {"upstream": "evil.com"},
		{"upstream": "0.0.0.0"}, {"log_redact": "2"},
	} {
		if r := actionDNSTakeoverSet(s, p); r.OK {
			t.Fatalf("accepted %v", p)
		}
	}
	if _, err := os.Stat(dnsTKPath(h.dir)); err == nil {
		t.Fatal("bad params must not write")
	}
	r := actionDNSTakeoverSet(s, map[string]string{"enabled": "true", "block_mode": "zero", "log_queries": "1"})
	if !r.OK || !strings.Contains(r.Detail, "state=active") || !strings.Contains(r.Detail, "upstream=127.0.0.1:53(tether)") {
		t.Fatalf("%+v", r)
	}
	c := loadDNSTKConf(h.dir)
	if !c.Enabled || c.BlockMode != "zero" || !c.LogQueries || c.LogRedact {
		t.Fatalf("conf %+v", c)
	}
	// 喂两条日志(一条脱敏前)
	h.tk.onLog(dnsLogEntry{Ts: time.Now().UnixMilli(), MAC: "aa:bb:cc:00:00:01", IP: "192.168.43.10", QName: "www.example.com", QType: "A", Rcode: "NOERROR", Answers: []string{"1.2.3.4"}})
	h.tk.onLog(dnsLogEntry{Ts: time.Now().UnixMilli(), MAC: "aa:bb:cc:00:00:02", IP: "192.168.43.11", QName: "www.example.com", QType: "AAAA", Rcode: "NOERROR"})

	rec := httptest.NewRecorder()
	s.apiDNS(rec, httptest.NewRequest("GET", "/api/dns", nil))
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"enabled", "active", "healthy", "listen", "upstream", "upstream_kind", "stats", "top_domains_today", "recent", "v6", "failopen", "block_mode", "blocklist"} {
		if _, ok := resp[k]; !ok {
			t.Fatalf("missing %s in %v", k, resp)
		}
	}
	st := resp["stats"].(map[string]interface{})
	for _, k := range []string{"queries", "cached", "blocked", "errors", "p50_ms", "p95_ms"} {
		if _, ok := st[k]; !ok {
			t.Fatalf("stats missing %s", k)
		}
	}
	if resp["active"] != true || resp["healthy"] != true || resp["block_mode"] != "zero" {
		t.Fatalf("%v", resp)
	}
	top := resp["top_domains_today"].([]interface{})
	if len(top) != 1 || top[0].(map[string]interface{})["count"].(float64) != 2 {
		t.Fatalf("top %v", top)
	}
	if len(resp["recent"].([]interface{})) != 2 {
		t.Fatal("recent")
	}

	rec = httptest.NewRecorder()
	s.apiDNSLog(rec, httptest.NewRequest("GET", "/api/dns/log?mac=aa:bb:cc:00:00:02&limit=10", nil))
	var lr struct {
		Entries []dnsLogEntry `json:"entries"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &lr)
	if len(lr.Entries) != 1 || lr.Entries[0].QType != "AAAA" {
		t.Fatalf("log by mac: %s", rec.Body.String())
	}
	for _, q := range []string{"/api/dns/log?mac=zz", "/api/dns/log?limit=-1"} {
		rec = httptest.NewRecorder()
		s.apiDNSLog(rec, httptest.NewRequest("GET", q, nil))
		if rec.Code != 400 {
			t.Fatalf("%s → %d", q, rec.Code)
		}
	}
	rec = httptest.NewRecorder()
	s.apiDNS(rec, httptest.NewRequest("POST", "/api/dns", nil))
	if rec.Code != 405 {
		t.Fatal("POST must be 405")
	}
	if !isSensitiveReadPath("/api/dns") || !isSensitiveReadPath("/api/dns/log") {
		t.Fatal("dns endpoints must be sensitive read paths")
	}

	// 关日志: 内存明细清空, recent 不再给
	if r := actionDNSTakeoverSet(s, map[string]string{"log_queries": "false"}); !r.OK {
		t.Fatal(r)
	}
	if got := h.tk.ring.latest("", 10); len(got) != 0 {
		t.Fatal("ring must be cleared when logging is turned off")
	}
	rec = httptest.NewRecorder()
	s.apiDNS(rec, httptest.NewRequest("GET", "/api/dns", nil))
	resp = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if _, ok := resp["recent"]; ok {
		t.Fatal("recent must be omitted when log is off")
	}
	// 关闭接管
	if r := actionDNSTakeoverSet(s, map[string]string{"enabled": "off"}); !r.OK || !strings.Contains(r.Detail, "state=off") {
		t.Fatalf("%+v", r)
	}
	if st, act := h.state(); st != "off" || act {
		t.Fatal("disable")
	}
}

func TestDNSTakeoverLogRedactAndFile(t *testing.T) {
	h := newTKHarness(t)
	h.conf(`{"enabled":true,"log_queries":true,"log_redact":true}`)
	h.tk.tick()
	ts := time.Now()
	// 按日文件 + 旧文件清理(打开当天文件时清)
	dir := filepath.Join(h.dir, "logs", "dns")
	_ = os.MkdirAll(dir, 0o755)
	old := filepath.Join(dir, dnsLogFileName(ts.AddDate(0, 0, -5)))
	keep := filepath.Join(dir, dnsLogFileName(ts.AddDate(0, 0, -2)))
	_ = os.WriteFile(old, []byte("x\n"), 0o600)
	_ = os.WriteFile(keep, []byte("x\n"), 0o600)
	h.tk.onLog(dnsLogEntry{Ts: ts.UnixMilli(), MAC: "aa:bb:cc:00:00:01", IP: "192.168.43.10", QName: "a.b.example.com.cn", QType: "A", Rcode: "NOERROR", Answers: []string{"1.2.3.4"}})
	got := h.tk.ring.latest("", 5)
	if len(got) != 1 || got[0].QName != "example.com.cn" || got[0].Answers != nil {
		t.Fatalf("redacted %+v", got)
	}
	h.tk.Shutdown() // 关 writer = flush
	b, err := os.ReadFile(filepath.Join(dir, dnsLogFileName(ts)))
	if err != nil || !strings.Contains(string(b), `"qname":"example.com.cn"`) || strings.Contains(string(b), "1.2.3.4") {
		t.Fatalf("daily file: %q %v", b, err)
	}
	if _, err := os.Stat(old); err == nil {
		t.Fatal("files older than 3 days must be pruned")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("2-day-old file must be kept")
	}
	for in, want := range map[string]string{"x.y.example.com": "example.com", "example.com": "example.com", "a.b.co.uk": "b.co.uk", "localhost": "localhost"} {
		if g := dnsRedactName(in); g != want {
			t.Fatalf("redact %s = %s", in, g)
		}
	}
}

func TestDNSTakeoverIPNamesMerge(t *testing.T) {
	h := newTKHarness(t)
	_ = os.WriteFile(filepath.Join(h.dir, "run", "dpi_ipname.json"), []byte(`{"entries":{
		"1.1.1.1":{"name":"old.example.com","src":"dns","app":"x"},
		"2.2.2.2":{"name":"cdn.example.com","src":"sni","app":"y"},
		"3.3.3.3":{"name":"same.example.com","src":"dns","app":"z","app_name":"Z"}}}`), 0o644)
	now := time.Now()
	h.tk.now = time.Now
	h.tk.names.record(dnsAnswerEvent{QName: "new.example.com", Ts: now, IPs: []dnsRR{{Type: dnsTypeA, TTL: 60, Value: "1.1.1.1"}}})
	h.tk.names.record(dnsAnswerEvent{QName: "other.example.com", Ts: now, IPs: []dnsRR{{Type: dnsTypeA, TTL: 60, Value: "2.2.2.2"}}})
	h.tk.names.record(dnsAnswerEvent{QName: "same.example.com", Ts: now, IPs: []dnsRR{{Type: dnsTypeA, TTL: 60, Value: "3.3.3.3"}}})
	h.tk.names.record(dnsAnswerEvent{QName: "v6.example.com", Ts: now, IPs: []dnsRR{{Type: dnsTypeAAAA, TTL: 60, Value: "2001:db8::1"}}})
	names := h.s.loadIPNames()
	if n := names["1.1.1.1"]; n.Name != "new.example.com" || n.Src != "dns" || n.App != "" {
		t.Fatalf("resolver answer must win over sniffed dns: %+v", n)
	}
	if n := names["2.2.2.2"]; n.Name != "cdn.example.com" || n.Src != "sni" {
		t.Fatalf("sni must keep precedence: %+v", n)
	}
	if n := names["3.3.3.3"]; n.App != "z" || n.AppName != "Z" {
		t.Fatalf("same name keeps classification: %+v", n)
	}
	if n := names["2001:db8::1"]; n.Name != "v6.example.com" {
		t.Fatalf("v6 %+v", n)
	}
	// 过期(最少保留 600 秒)后不再合并
	h.tk.now = func() time.Time { return now.Add(11 * time.Minute) }
	if n := h.s.loadIPNames()["1.1.1.1"]; n.Name != "old.example.com" {
		t.Fatalf("expired resolver entry must not merge: %+v", n)
	}
	// 没建过控制器的 server: 钩子零开销且不 panic
	s2 := newServer(t.TempDir())
	if len(s2.loadIPNames()) != 0 {
		t.Fatal("empty")
	}
}

func TestDNSIPNamesBounded(t *testing.T) {
	n := newDNSIPNames()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < dnsTKNamesMax+500; i++ {
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)).String()
		n.record(dnsAnswerEvent{QName: "a.test", Ts: now.Add(time.Duration(i) * time.Millisecond), IPs: []dnsRR{{Type: dnsTypeA, TTL: 60, Value: ip}}})
	}
	if n.size() > dnsTKNamesMax {
		t.Fatalf("size %d", n.size())
	}
}
