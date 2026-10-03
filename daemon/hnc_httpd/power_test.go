package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ─── 屏幕状态解析(dumpsys 夹具) ─────────────────────────────────────

const dumpsysPowerAwake = `POWER MANAGER (dumpsys power)

Power Manager State:
  mDirty=0x0
  mWakefulness=Awake
  mWakefulnessChanging=false
  mIsPowered=false
`

const dumpsysPowerAsleep = `Power Manager State:
  mDirty=0x0
  mWakefulness=Asleep
  mWakefulnessChanging=false
`

const dumpsysPowerDozing = `Power Manager State:
  mWakefulness=Dozing
  mWakefulnessRaw=Dozing
`

const dumpsysDisplayOn = `DISPLAY MANAGER (dumpsys display)
  mOnlyCore=false
Display Power Controller Locked State:
  mScreenState=ON
  mGlobalDisplayState=ON
`

const dumpsysDisplayOff = `Display Power Controller Locked State:
  mScreenState=OFF
`

const dumpsysDisplayDoze = `  Display Power: state=DOZE_SUSPEND
`

func TestParseWakefulness(t *testing.T) {
	cases := []struct {
		in     string
		on, ok bool
	}{
		{dumpsysPowerAwake, true, true},
		{dumpsysPowerAsleep, false, true},
		{dumpsysPowerDozing, false, true},
		{"  mWakefulness=Dreaming\n", true, true},
		{"mWakefulness=Awake mWakefulnessChanging=false", true, true},
		{"nothing here\n", false, false},
		{"", false, false},
	}
	for i, c := range cases {
		on, ok := parseWakefulness(c.in)
		if on != c.on || ok != c.ok {
			t.Errorf("case %d: got on=%v ok=%v want %v/%v", i, on, ok, c.on, c.ok)
		}
	}
}

func TestParseDisplayState(t *testing.T) {
	cases := []struct {
		in     string
		on, ok bool
	}{
		{dumpsysDisplayOn, true, true},
		{dumpsysDisplayOff, false, true},
		{dumpsysDisplayDoze, false, true},
		{"  mScreenState=DOZE\n", false, true},
		{"  mScreenState=VR\n", true, true},
		{"  mGlobalDisplayState=OFF\n", false, true},
		{"mScreenState=UNKNOWN\n", false, false},
		{"", false, false},
	}
	for i, c := range cases {
		on, ok := parseDisplayState(c.in)
		if on != c.on || ok != c.ok {
			t.Errorf("case %d: got on=%v ok=%v want %v/%v", i, on, ok, c.on, c.ok)
		}
	}
}

type fakeScreen struct {
	files   map[string]string
	power   string
	display string
	calls   int
	now     time.Time
}

func (f *fakeScreen) prober() *screenProber {
	return &screenProber{
		readFile: func(p string) ([]byte, error) {
			if v, ok := f.files[p]; ok {
				return []byte(v), nil
			}
			return nil, os.ErrNotExist
		},
		glob: func(g string) ([]string, error) {
			var out []string
			for p := range f.files {
				if ok, _ := filepath.Match(g, p); ok {
					out = append(out, p)
				}
			}
			return out, nil
		},
		dumpsys: func(svc string, keys []string) (string, error) {
			f.calls++
			switch svc {
			case "power":
				if f.power != "" {
					return f.power, nil
				}
			case "display":
				if f.display != "" {
					return f.display, nil
				}
			}
			return "", errNoScreenKey
		},
		now: func() time.Time { return f.now },
	}
}

func TestScreenProberModes(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)

	// 背光与 dumpsys 一致 → 之后只读背光(不再跑 dumpsys)
	f := &fakeScreen{files: map[string]string{"/sys/class/backlight/panel0-backlight/brightness": "512\n"}, power: dumpsysPowerAwake, now: t0}
	p := f.prober()
	if on, ok, src := p.probe(); !on || !ok || src != "backlight" {
		t.Fatalf("agree: on=%v ok=%v src=%s", on, ok, src)
	}
	f.files["/sys/class/backlight/panel0-backlight/brightness"] = "0"
	f.now = t0.Add(15 * time.Second)
	calls := f.calls
	if on, ok, src := p.probe(); on || !ok || src != "backlight" {
		t.Fatalf("backlight off: on=%v ok=%v src=%s", on, ok, src)
	}
	if f.calls != calls {
		t.Errorf("backlight mode should not run dumpsys (calls %d→%d)", calls, f.calls)
	}
	// 30 分钟后复核一次
	f.now = t0.Add(31 * time.Minute)
	f.power = dumpsysPowerAsleep
	p.probe()
	if f.calls == calls {
		t.Error("expected periodic dumpsys verification")
	}

	// AOD: 背光亮但系统 Dozing → 信系统(power 模式), dumpsys 至多 60s 一次
	f2 := &fakeScreen{files: map[string]string{"/sys/class/backlight/panel0-backlight/brightness": "20"}, power: dumpsysPowerDozing, now: t0}
	p2 := f2.prober()
	if on, ok, src := p2.probe(); on || !ok || src != "power" {
		t.Fatalf("aod: on=%v ok=%v src=%s", on, ok, src)
	}
	c := f2.calls
	f2.now = t0.Add(20 * time.Second)
	p2.probe()
	if f2.calls != c {
		t.Errorf("dumpsys should be rate limited to 60s (calls %d→%d)", c, f2.calls)
	}
	f2.power = dumpsysPowerAwake
	f2.now = t0.Add(61 * time.Second)
	if on, _, _ := p2.probe(); !on {
		t.Error("power mode should refresh after 60s")
	}

	// 没有背光节点 → power; power 无键 → display
	f3 := &fakeScreen{files: map[string]string{}, display: dumpsysDisplayOff, now: t0}
	if on, ok, src := f3.prober().probe(); on || !ok || src != "display" {
		t.Fatalf("display fallback: on=%v ok=%v src=%s", on, ok, src)
	}
	// 都没有 → 未知
	f4 := &fakeScreen{files: map[string]string{}, now: t0}
	if _, ok, src := f4.prober().probe(); ok || src != "none" {
		t.Fatalf("none: ok=%v src=%s", ok, src)
	}
	// dumpsys 不可用但有背光 → backlight
	f5 := &fakeScreen{files: map[string]string{"/sys/class/leds/lcd-backlight/brightness": "100"}, now: t0}
	if on, ok, src := f5.prober().probe(); !on || !ok || src != "backlight" {
		t.Fatalf("backlight only: on=%v ok=%v src=%s", on, ok, src)
	}
}

// ─── 档位 / 设备数 / 文件格式 ─────────────────────────────────────────

func TestActivityLevel(t *testing.T) {
	cases := []struct {
		a    Activity
		want string
	}{
		{Activity{}, lvlUnknown},
		{Activity{Known: true}, lvlHotspotOff},
		{Activity{Known: true, HotspotActive: true}, lvlNoClients},
		{Activity{Known: true, HotspotActive: true, ClientsOnline: 2, ScreenKnown: true, ScreenOn: true}, lvlActive},
		{Activity{Known: true, HotspotActive: true, ClientsOnline: 2, ScreenKnown: true}, lvlBackground},
		{Activity{Known: true, HotspotActive: true, ClientsOnline: 2, ScreenKnown: true, WebUIActive: true}, lvlActive},
		{Activity{Known: true, HotspotActive: true, ClientsOnline: 2}, lvlActive}, // 屏幕未知 = 保守
	}
	for i, c := range cases {
		if got := c.a.computeLevel(); got != c.want {
			t.Errorf("case %d: %s want %s", i, got, c.want)
		}
	}
}

func TestCountOnlineClients(t *testing.T) {
	now := 1_700_000_000.0
	devs := map[string]interface{}{
		"aa:aa:aa:aa:aa:01": map[string]interface{}{"last_seen": now - 10},
		"aa:aa:aa:aa:aa:02": map[string]interface{}{"last_seen": now - 200},
		"aa:aa:aa:aa:aa:03": map[string]interface{}{"online": true},
		"aa:aa:aa:aa:aa:04": map[string]interface{}{"last_seen": 0.0},
		"bad":               "x",
	}
	if n := countOnlineClients(devs, now, 90); n != 2 {
		t.Errorf("online=%d want 2", n)
	}
}

func TestActivityJSONShape(t *testing.T) {
	a := Activity{Ts: 123, Level: lvlBackground, ScreenKnown: true, HotspotActive: true, ClientsOnline: 3, Known: true, LastAPIAgoS: -1}
	b, _ := json.Marshal(a)
	s := string(b)
	// bin/hnc_activity.sh 依赖: 以 {"ts": 开头、screen_on 紧跟 screen_known、单行
	for _, sub := range []string{`{"ts":123,`, `"level":"background"`, `"screen_on":false,"screen_known":true`,
		`"hotspot_active":true`, `"clients_online":3`, `"webui_active":false`} {
		if !strings.Contains(s, sub) {
			t.Errorf("activity json %s missing %s", s, sub)
		}
	}
	if !strings.HasPrefix(s, `{"ts":`) || strings.Contains(s, "\n") {
		t.Errorf("activity json must be single line starting with ts: %s", s)
	}
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	if err := writeActivity(dir, a); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(activityPath(dir))
	if strings.Count(string(raw), "\n") != 1 {
		t.Errorf("file should be one line: %q", raw)
	}
}

// ─── 间隔策略 ─────────────────────────────────────────────────────

// 所有档位 × 屏幕 × 界面 × flags 组合
func allActivityStates() []Activity {
	var out []Activity
	out = append(out, Activity{}) // unknown
	for _, hot := range []bool{false, true} {
		for _, clients := range []int{0, 3} {
			for _, scr := range []int{0, 1, 2} { // 未知/亮/灭
				for _, ui := range []bool{false, true} {
					a := Activity{Known: true, HotspotActive: hot, WebUIActive: ui}
					if hot {
						a.ClientsOnline = clients
					}
					switch scr {
					case 1:
						a.ScreenKnown, a.ScreenOn = true, true
					case 2:
						a.ScreenKnown = true
					}
					out = append(out, a)
				}
			}
		}
	}
	return out
}

var allLoopFlags = []loopFlags{{}, {CtPrecise: true}, {Enforcing: true}, {CtPrecise: true, Enforcing: true}}

func TestPowerIntervalNeverFasterThanBase(t *testing.T) {
	for _, d := range powerLoopDefs {
		for _, a := range allActivityStates() {
			for _, f := range allLoopFlags {
				got, why := powerInterval(d.Name, a, f)
				if got < d.Base || got <= 0 || why == "" {
					t.Errorf("%s @ %s/%+v: %v (%s) < base %v", d.Name, a.computeLevel(), f, got, why, d.Base)
				}
				if got > time.Hour {
					t.Errorf("%s: interval %v too long", d.Name, got)
				}
			}
		}
		if got, _ := powerInterval(d.Name, Activity{}, loopFlags{}); got != d.Base {
			t.Errorf("%s: unknown state must use base, got %v", d.Name, got)
		}
	}
	if d, _ := powerInterval("no_such_loop", Activity{}, loopFlags{}); d != 0 {
		t.Error("unknown loop should be 0")
	}
}

// 执法相关的节拍在任何状态下都不变
func TestPowerEnforcementCadenceInvariant(t *testing.T) {
	for _, a := range allActivityStates() {
		lvl := a.computeLevel()
		for _, f := range allLoopFlags {
			if d, _ := powerInterval("limit_policy", a, f); d != time.Minute {
				t.Errorf("limit_policy must stay minute-aligned (60s) @ %s: %v", lvl, d)
			}
			if d, _ := powerInterval("v6_neigh", a, f); d != time.Minute {
				t.Errorf("v6_neigh fallback must stay 60s @ %s: %v", lvl, d)
			}
			if d, _ := powerInterval("watchdog_active", a, f); d != 60*time.Second {
				t.Errorf("watchdog_active must stay 60s @ %s: %v", lvl, d)
			}
			// 热点开着且有设备: offload guard 检测/重申 ≤60s
			if a.Known && a.HotspotActive && a.ClientsOnline > 0 {
				if d, _ := powerInterval("offload_guard", a, f); d > 60*time.Second {
					t.Errorf("offload_guard re-assert must be ≤60s with hotspot+clients @ %s: %v", lvl, d)
				}
			}
			// 有设备 + 执法配置 → app_usage 保持 10s
			if a.Known && a.HotspotActive && a.ClientsOnline > 0 && f.Enforcing {
				if d, _ := powerInterval("app_usage", a, f); d != 10*time.Second {
					t.Errorf("app_usage must stay 10s when enforcing @ %s: %v", lvl, d)
				}
			}
			// 有设备但没有精确事件 → 不放慢(否则漏短连接)
			if a.Known && a.HotspotActive && a.ClientsOnline > 0 && !f.CtPrecise {
				if d, _ := powerInterval("app_usage", a, f); d != 10*time.Second {
					t.Errorf("app_usage must stay 10s without ct events @ %s: %v", lvl, d)
				}
			}
			// v5.25: 开热点靠网卡事件即时唤醒、定时开关热点在边界时刻唤醒, 轮询只是兜底: 最长 120s
			if d, _ := powerInterval("watchdog_pending", a, f); d > 120*time.Second {
				t.Errorf("watchdog_pending too slow @ %s: %v", lvl, d)
			}
		}
	}
}

func TestPowerIntervalTable(t *testing.T) {
	bg := Activity{Known: true, HotspotActive: true, ClientsOnline: 2, ScreenKnown: true}
	act := Activity{Known: true, HotspotActive: true, ClientsOnline: 2, ScreenKnown: true, ScreenOn: true}
	off := Activity{Known: true, ScreenKnown: true}
	offUI := Activity{Known: true, ScreenKnown: true, WebUIActive: true}
	none := Activity{Known: true, HotspotActive: true, ScreenKnown: true, ScreenOn: true}
	ct := loopFlags{CtPrecise: true}
	cases := []struct {
		loop string
		a    Activity
		f    loopFlags
		want time.Duration
	}{
		{"app_usage", act, ct, 10 * time.Second},
		{"app_usage", bg, ct, 30 * time.Second},
		{"app_usage", none, ct, 60 * time.Second},
		{"app_usage", off, ct, 300 * time.Second},
		{"rate", act, ct, 20 * time.Second},
		{"rate", offUI, ct, 2 * time.Second},
		{"rate", off, ct, 30 * time.Second},
		{"offload_status", act, ct, 120 * time.Second},
		{"offload_status", off, ct, 300 * time.Second},
		{"phone_usage", off, ct, 300 * time.Second},
		{"phone_usage", offUI, ct, 60 * time.Second},
		{"phone_usage", bg, ct, 60 * time.Second},
		{"stats_calibration", off, ct, time.Hour},
		{"mac_merge", bg, ct, 90 * time.Second},
		{"cert_probe", off, ct, 600 * time.Second},
		{"sse_poll", off, ct, 5 * time.Second},
		{"offload_guard", none, ct, 300 * time.Second},
		{"offload_guard", act, ct, 60 * time.Second},
		{"stats_sample", none, ct, 900 * time.Second},
		{"watchdog_pending", off, ct, 120 * time.Second},
		{"watchdog_pending", offUI, ct, 120 * time.Second},
		{"dpid_conntrack", none, ct, 60 * time.Second},
		{"dpid_state_flush", bg, ct, 5 * time.Second},
		{"dpid_bytes", bg, ct, 30 * time.Second},
		{"dpid_guard_poll", off, ct, 15 * time.Second},
		{"dpid_guard_poll", offUI, ct, 6 * time.Second},
	}
	for _, c := range cases {
		if got, why := powerInterval(c.loop, c.a, c.f); got != c.want {
			t.Errorf("%s @ %s: %v (%s) want %v", c.loop, c.a.computeLevel(), got, why, c.want)
		}
	}
}

// 镜像条目的数值必须与 shell 一致(只改一边 go test 就失败)
func TestPowerShellMirrorConstants(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", p))
		if err != nil {
			t.Skipf("read %s: %v", p, err)
		}
		return string(b)
	}
	quiet := Activity{Known: true, ScreenKnown: true}
	// v5.26 T1: watchdog.sh shell 主循环已删, 镜像常量改为对比 Go 看门狗
	// power.go 的 intervalIdleProbe(原 shell PROBE_INTERVAL_PENDING_QUIET)。
	pg := read("src/dpid/cmd/hnc_watchdog/power.go")
	m := regexp.MustCompile(`intervalIdleProbe\s*=\s*(\d+)\s*\*\s*time\.Second`).FindStringSubmatch(pg)
	if d, _ := powerInterval("watchdog_pending", quiet, loopFlags{}); m == nil || m[1] != fmt.Sprint(int(d.Seconds())) {
		t.Errorf("hnc_watchdog power.go intervalIdleProbe=%v, want=%v", m, d)
	}
	og := read("bin/hnc_offload_guard.sh")
	m = regexp.MustCompile(`HNC_GUARD_IDLE_INTERVAL:-(\d+)`).FindStringSubmatch(og)
	if d, _ := powerInterval("offload_guard", quiet, loopFlags{}); m == nil || m[1] != fmt.Sprint(int(d.Seconds())) {
		t.Errorf("offload guard IDLE_INTERVAL=%v, Go=%v", m, d)
	}
	dg := read("bin/hnc_dpid_guard.sh")
	if d, _ := powerInterval("dpid_guard_poll", quiet, loopFlags{}); !strings.Contains(dg, fmt.Sprintf("GUARD_POLL=%d", int(d.Seconds()))) {
		t.Errorf("dpid guard quiet poll != %v", d)
	}
}

// ─── powerWait: 档位变化立即重算 ────────────────────────────────────

func TestPowerWaitWakesOnActivityChange(t *testing.T) {
	old := actState.cur.Load()
	defer func() {
		if old != nil {
			activityPublish(*old)
		} else {
			actState.cur.Store(nil)
		}
	}()
	activityPublish(Activity{Known: true, ScreenKnown: true}) // hotspot_off → mac_merge 600s
	stop := make(chan struct{})
	done := make(chan bool, 1)
	last := time.Now().Add(-60 * time.Second)
	go func() { done <- powerWait(stop, "mac_merge", last, nil) }()
	select {
	case <-done:
		t.Fatal("should still be waiting in hotspot_off")
	case <-time.After(100 * time.Millisecond):
	}
	// 热点开了、有设备、亮屏 → 30s, 已过 60s → 立即返回
	activityPublish(Activity{Known: true, HotspotActive: true, ClientsOnline: 1, ScreenKnown: true, ScreenOn: true})
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("powerWait returned false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("powerWait did not wake on activity change")
	}
	if d := powerCurrent("mac_merge"); d != 30*time.Second {
		t.Errorf("recorded interval %v", d)
	}
	// stop
	go func() { done <- powerWait(stop, "mac_merge", time.Now(), nil) }()
	close(stop)
	select {
	case ok := <-done:
		if ok {
			t.Fatal("expected false on stop")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("powerWait did not stop")
	}
}

func TestAppTimeCap(t *testing.T) {
	defer appTimeCapSec.Store(0)
	appTimeSetCapFor(10 * time.Second)
	if c := appTimeTickCap(); c != appTimeMaxTickSec {
		t.Errorf("base cap %d", c)
	}
	appTimeSetCapFor(30 * time.Second)
	if c := appTimeTickCap(); c != 40 {
		t.Errorf("30s cap %d want 40", c)
	}
	appTimeSetCapFor(300 * time.Second) // 慢档没有客户端, 不放宽
	if c := appTimeTickCap(); c != appTimeMaxTickSec {
		t.Errorf("slow cap %d", c)
	}
}

// ─── CPU 计算 ─────────────────────────────────────────────────────

func statLine(pid, ppid int, comm string, ut, st, cut, cst, start uint64) string {
	return fmt.Sprintf("%d (%s) S %d %d 0 0 -1 4194560 100 0 0 0 %d %d %d %d 20 0 8 0 %d 123456789 2000 18446744073709551615",
		pid, comm, ppid, pid, ut, st, cut, cst, start)
}

func TestProcStatFields(t *testing.T) {
	pp, own, ch, start, ok := procStatFields(statLine(10, 1, "sh (x) y", 300, 200, 50, 25, 9999))
	if !ok || pp != 1 || own != 500 || ch != 75 || start != 9999 {
		t.Fatalf("got pp=%d own=%d ch=%d start=%d ok=%v", pp, own, ch, start, ok)
	}
	if _, _, _, _, ok := procStatFields("garbage"); ok {
		t.Error("garbage should fail")
	}
	if n, ok := parseSchedstatSlices("123456 7890 42\n"); !ok || n != 42 {
		t.Errorf("schedstat %d %v", n, ok)
	}
}

func TestCPUPctMath(t *testing.T) {
	// 300 ticks(3 CPU 秒)/ 300s = 1% → 36 CPU 秒/小时
	if p := cpuPct(300, 300); p != 1 {
		t.Errorf("pct=%v", p)
	}
	t0 := time.Unix(1_700_000_000, 0)
	mk := func(off time.Duration, pid int, ticks, slices uint64, lvl string) powerSample {
		return powerSample{At: t0.Add(off), Wall: t0.Add(off).Unix(), UptimeS: 10000 + off.Seconds(), Level: lvl,
			Procs: map[string]powerProcSample{"hnc_httpd": {PID: pid, Start: 100000, Ticks: ticks, Slices: slices, RSSKB: 20000}}}
	}
	var ring []powerSample
	for i := 0; i <= 12; i++ { // 一小时, 每 5 分钟 +300 ticks(1%)
		ring = append(ring, mk(time.Duration(i)*5*time.Minute, 7, uint64(i)*300, uint64(i)*600, lvlActive))
	}
	procs, tot := powerProcViews(ring)
	var hp powerProcView
	for _, p := range procs {
		if p.Name == "hnc_httpd" {
			hp = p
		}
	}
	if !hp.Alive || hp.CPU5m != 1 || hp.CPU1h != 1 || hp.CPUSecPerHour != 36 || hp.Basis != "1h" || hp.Window1hS != 3600 {
		t.Fatalf("httpd view %+v", hp)
	}
	if hp.WakeupsPerMin != 120 { // 600 次 / 5 分钟
		t.Errorf("wakeups/min=%v", hp.WakeupsPerMin)
	}
	if tot.CPUSecPerHour != 36 || tot.RSSKB != 20000 {
		t.Errorf("total %+v", tot)
	}
	// since_start: 3600 ticks = 36s, 进程活了 uptime(13600) - start(1000s) = 12600s
	if want := round3(36.0 / 12600 * 100); hp.CPUSinceStart != want {
		t.Errorf("since_start %v want %v", hp.CPUSinceStart, want)
	}

	// 进程重启(PID 变): 不跨进程做差分
	ring2 := append([]powerSample(nil), ring[:12]...)
	ring2 = append(ring2, mk(60*time.Minute, 8, 5000, 10, lvlActive))
	procs2, _ := powerProcViews(ring2)
	for _, p := range procs2 {
		if p.Name == "hnc_httpd" && (p.Window5mS != 0 || p.Basis != "since_start") {
			t.Errorf("restart should reset windows: %+v", p)
		}
	}

	// 只有 10 分钟数据: 1h 窗口退最老样本, cpu_sec_per_hour 退 5m
	procs3, _ := powerProcViews(ring[:3])
	for _, p := range procs3 {
		if p.Name == "hnc_httpd" && (p.Basis != "5m" || p.Window1hS != 600 || p.CPUSecPerHour != 36) {
			t.Errorf("short window %+v", p)
		}
	}
}

func TestPowerByLevel(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	s := func(off time.Duration, ticks uint64, lvl string) powerSample {
		return powerSample{At: t0.Add(off), Level: lvl, Procs: map[string]powerProcSample{"watchdog": {PID: 5, Start: 1, Ticks: ticks}}}
	}
	acc := map[string]*powerLevelAcc{}
	powerAccumulate(acc, s(0, 0, lvlActive), s(10*time.Minute, 1200, lvlBackground))                     // 12s 记 active
	powerAccumulate(acc, s(10*time.Minute, 1200, lvlBackground), s(70*time.Minute, 1800, lvlBackground)) // 6s/小时 记 background
	v := powerLevelViews(acc)
	if len(v) != 2 || v[0].Level != lvlActive || v[0].CPUSecPerHour != 72 || v[1].Level != lvlBackground || v[1].CPUSecPerHour != 6 {
		t.Fatalf("by_level %+v", v)
	}
}

// 假 /proc: httpd(self)+ watchdog(pidfile, 带存活子进程)+ dpid(pidfile 失效 → 扫 cmdline)
func TestTakePowerSample(t *testing.T) {
	files := map[string]string{
		"/proc/uptime":                 "5000.00 9000.00\n",
		"/h/run/watchdog.pid":          "200\n",
		"/h/run/dpid.child.pid":        "999\n", // 不存在的进程
		"/proc/100/stat":               statLine(100, 1, "hnc_httpd", 100, 50, 10, 0, 500),
		"/proc/100/cmdline":            "/data/local/hnc/daemon/hnc_httpd/hnc_httpd\x00-loopback-port\x008444",
		"/proc/100/status":             "Name:\thnc_httpd\nVmRSS:\t  25000 kB\n",
		"/proc/100/task/100/schedstat": "1 2 30\n",
		"/proc/100/task/101/schedstat": "1 2 12\n",
		"/proc/200/stat":               statLine(200, 1, "sh", 20, 10, 400, 300, 600),
		"/proc/200/cmdline":            "sh\x00/data/local/hnc/bin/watchdog.sh",
		"/proc/200/status":             "VmRSS:\t 1500 kB\n",
		"/proc/201/stat":               statLine(201, 200, "sh", 5, 5, 0, 0, 700), // 存活子进程(如 v6_sync.sh)
		"/proc/201/cmdline":            "sh\x00/data/local/hnc/bin/v6_sync.sh",
		"/proc/202/stat":               statLine(202, 201, "ip", 1, 1, 0, 0, 701), // 孙进程
		"/proc/300/stat":               statLine(300, 1, "hnc_dpid", 1000, 500, 0, 0, 800),
		"/proc/300/cmdline":            "/data/local/hnc/bin/hnc_dpid\x00-config\x00/data/local/hnc/etc/dpi_config.json",
		"/proc/300/status":             "VmRSS:\t 40000 kB\n",
		"/proc/300/schedstat":          "1 2 77\n",
	}
	fs := powerFS{
		ReadFile: func(p string) ([]byte, error) {
			if v, ok := files[p]; ok {
				return []byte(v), nil
			}
			return nil, os.ErrNotExist
		},
		ReadDir: func(p string) ([]string, error) {
			switch p {
			case "/proc":
				return []string{"100", "200", "201", "202", "300", "self", "net"}, nil
			case "/proc/100/task":
				return []string{"100", "101"}, nil
			}
			return nil, os.ErrNotExist
		},
		SelfPID: 100,
	}
	smp := takePowerSample(fs, "/h", time.Unix(1_700_000_000, 0), lvlActive)
	if smp.UptimeS != 5000 {
		t.Errorf("uptime %v", smp.UptimeS)
	}
	h := smp.Procs["hnc_httpd"]
	if h.PID != 100 || h.Ticks != 160 || h.Slices != 42 || h.RSSKB != 25000 {
		t.Errorf("httpd %+v", h)
	}
	w := smp.Procs["watchdog"]
	// 自身 30 + 已回收子进程 700 + 存活子 10 + 孙 2 = 742
	if w.PID != 200 || w.Ticks != 742 {
		t.Errorf("watchdog %+v", w)
	}
	d := smp.Procs["hnc_dpid"]
	if d.PID != 300 || d.Ticks != 1500 || d.Slices != 77 {
		t.Errorf("dpid (scan fallback) %+v", d)
	}
	if _, ok := smp.Procs["hotspotd"]; ok {
		t.Error("hotspotd should be absent")
	}
}

func TestPowerTips(t *testing.T) {
	a := Activity{Known: true, HotspotActive: true, ClientsOnline: 1, ScreenKnown: true, WebUIActive: true, ScreenSource: "power"}
	procs := []powerProcView{{Name: "watchdog", Label: "watchdog(shell)", CPUSecPerHour: 150, Alive: true}, {Name: "hnc_httpd", Label: "hnc_httpd", CPUSecPerHour: 50, Alive: true}}
	tips := powerTips(a, procs, powerTotal{CPUSecPerHour: 200}, loopFlags{})
	all := strings.Join(tips, "\n")
	for _, sub := range []string{"偏高", "watchdog(shell)", "dumpsys", "conntrack 事件", "2s"} {
		if !strings.Contains(all, sub) {
			t.Errorf("tips missing %q: %s", sub, all)
		}
	}
	if tips := powerTips(Activity{Known: true, ScreenKnown: true, ScreenSource: "backlight"}, nil, powerTotal{}, loopFlags{CtPrecise: true}); len(tips) != 1 || !strings.Contains(tips[0], "正常") {
		t.Errorf("quiet tips %v", tips)
	}
}

// 自检「进程与资源」里的「功耗」项
func TestSelfcheckPowerItem(t *testing.T) {
	f := fixtureColorOSQualcomm("/data/local/hnc")
	r := runSelfcheck(f.scEnv(), scOptions{})
	if it := findItem(t, r, "process", "power"); it.Status != scInfo || !strings.Contains(it.Value, "暂无") {
		t.Errorf("no data: %+v", it)
	}
	rep := map[string]interface{}{
		"samples": 13, "level_label": "后台(熄屏且无界面)",
		"total":     map[string]interface{}{"cpu_sec_per_hour": 42.6, "wakeups_per_min": 90},
		"processes": []interface{}{map[string]interface{}{"name": "hnc_httpd", "alive": true, "cpu_sec_per_hour": 30.0}, map[string]interface{}{"name": "hotspotd", "alive": false}},
	}
	b, _ := json.Marshal(rep)
	f.files[f.h("run", "power_stats.json")] = string(b)
	r = runSelfcheck(f.scEnv(), scOptions{})
	it := expectStatus(t, r, "process", "power", scOK)
	mustContain(t, "power value", it.Value, "约 43 CPU 秒/小时")
	mustContain(t, "power value", it.Value, "后台")
	mustContain(t, "power detail", it.Detail, "hnc_httpd 30s")
	rep["total"] = map[string]interface{}{"cpu_sec_per_hour": 400.0}
	b, _ = json.Marshal(rep)
	f.files[f.h("run", "power_stats.json")] = string(b)
	r = runSelfcheck(f.scEnv(), scOptions{})
	expectStatus(t, r, "process", "power", scWarn)
}

// API 契约: 字段齐全, refresh=1 落盘 run/power_stats.json
func TestAPIPowerContract(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"run", "data", "logs"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	s := newServer(dir)
	req := httptest.NewRequest("GET", "/api/power?refresh=1", nil)
	w := httptest.NewRecorder()
	s.apiPower(w, req)
	if w.Code != 200 {
		t.Fatalf("code %d body %s", w.Code, w.Body.String())
	}
	var m map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"activity", "level", "level_label", "processes", "total", "by_level", "loops", "tips", "samples", "sample_every_s"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	procs, _ := m["processes"].([]interface{})
	if len(procs) != len(powerProcDefs) {
		t.Errorf("processes=%d", len(procs))
	}
	p0, _ := procs[0].(map[string]interface{})
	for _, k := range []string{"name", "pid", "cpu_pct_5m", "cpu_pct_1h", "cpu_sec_per_hour", "rss_kb", "wakeups_per_min"} {
		if _, ok := p0[k]; !ok {
			t.Errorf("process missing %s", k)
		}
	}
	if p0["name"] != "hnc_httpd" || p0["alive"] != true {
		t.Errorf("self process not sampled: %v", p0)
	}
	loops, _ := m["loops"].([]interface{})
	if len(loops) != len(powerLoopDefs) {
		t.Errorf("loops=%d", len(loops))
	}
	l0, _ := loops[0].(map[string]interface{})
	for _, k := range []string{"name", "base_interval_s", "current_interval_s", "reason"} {
		if _, ok := l0[k]; !ok {
			t.Errorf("loop missing %s", k)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "run", "power_stats.json")); err != nil {
		t.Errorf("power_stats.json not written: %v", err)
	}
	w2 := httptest.NewRecorder()
	s.apiPower(w2, httptest.NewRequest("POST", "/api/power", nil))
	if w2.Code != 405 {
		t.Errorf("POST code %d", w2.Code)
	}
}
