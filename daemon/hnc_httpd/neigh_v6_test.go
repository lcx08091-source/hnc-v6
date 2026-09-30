package main

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"
)

// buildNeighMsg 拼一条 ndmsg + NDA_DST + NDA_LLADDR
func buildNeighMsg(family uint8, ifindex int, state uint16, ip net.IP, mac string) []byte {
	b := make([]byte, 12)
	b[0] = family
	binary.LittleEndian.PutUint32(b[4:8], uint32(ifindex))
	binary.LittleEndian.PutUint16(b[8:10], state)
	attr := func(t uint16, v []byte) {
		l := 4 + len(v)
		h := make([]byte, 4)
		binary.LittleEndian.PutUint16(h[0:2], uint16(l))
		binary.LittleEndian.PutUint16(h[2:4], t)
		b = append(b, h...)
		b = append(b, v...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
	}
	if ip4 := ip.To4(); ip4 != nil && family == syscall.AF_INET {
		attr(ndaDst, ip4)
	} else {
		attr(ndaDst, ip.To16())
	}
	if mac != "" {
		hw, _ := net.ParseMAC(mac)
		attr(ndaLLAddr, hw)
	}
	return b
}

func TestParseNeighMsg(t *testing.T) {
	raw := buildNeighMsg(syscall.AF_INET6, 7, nudReachable, net.ParseIP("2408:8400::abcd"), "AA:BB:CC:DD:EE:05")
	ev, ok := parseNeighMsg(syscall.RTM_NEWNEIGH, raw)
	if !ok || ev.Family != syscall.AF_INET6 || ev.Ifindex != 7 || ev.State != nudReachable ||
		ev.IP.String() != "2408:8400::abcd" || ev.MAC != "aa:bb:cc:dd:ee:05" || ev.Del {
		t.Fatalf("parsed = %+v ok=%v", ev, ok)
	}
	if !neighUsable(ev) {
		t.Fatal("global REACHABLE v6 should be usable")
	}
	del, ok := parseNeighMsg(syscall.RTM_DELNEIGH, raw)
	if !ok || !del.Del || neighUsable(del) {
		t.Fatalf("del = %+v", del)
	}
	if _, ok := parseNeighMsg(syscall.RTM_NEWLINK, raw); ok {
		t.Fatal("non-neigh message accepted")
	}
	if _, ok := parseNeighMsg(syscall.RTM_NEWNEIGH, raw[:8]); ok {
		t.Fatal("short message accepted")
	}
	for _, c := range []struct {
		ip    string
		state uint16
		want  bool
	}{
		{"fe80::1", nudReachable, false},
		{"2408::1", nudStale, true},
		{"2408::1", nudDelay, true},
		{"2408::1", nudFailed, false},
		{"2408::1", nudIncomplete, false},
		{"ff02::1", nudReachable, false},
	} {
		ev, _ := parseNeighMsg(syscall.RTM_NEWNEIGH, buildNeighMsg(syscall.AF_INET6, 7, c.state, net.ParseIP(c.ip), "aa:bb:cc:dd:ee:05"))
		if got := neighUsable(ev); got != c.want {
			t.Errorf("%s state=%#x usable=%v want %v", c.ip, c.state, got, c.want)
		}
	}
	v4, _ := parseNeighMsg(syscall.RTM_NEWNEIGH, buildNeighMsg(syscall.AF_INET, 7, nudReachable, net.ParseIP("192.168.43.5"), "aa:bb:cc:dd:ee:05"))
	if neighUsable(v4) {
		t.Fatal("v4 neighbor should be ignored")
	}
}

func TestV6NeighFilter(t *testing.T) {
	clock := time.Date(2026, 9, 30, 10, 0, 0, 0, time.Local)
	f := newV6NeighFilter(t.TempDir(), func() string { return "wlan2" })
	f.now = func() time.Time { return clock }
	f.ifindexFn = func(string) int { return 7 }
	f.interestFn = func() map[string]bool { return map[string]bool{"aa:bb:cc:dd:ee:05": true} }
	ev := func(ifidx int, state uint16, ip, mac string, del bool) neighEvent {
		typ := uint16(syscall.RTM_NEWNEIGH)
		if del {
			typ = syscall.RTM_DELNEIGH
		}
		e, _ := parseNeighMsg(typ, buildNeighMsg(syscall.AF_INET6, ifidx, state, net.ParseIP(ip), mac))
		return e
	}
	const mac = "aa:bb:cc:dd:ee:05"
	if got := f.Handle(ev(7, nudReachable, "2408::a", mac, false)); got != mac {
		t.Fatalf("new address should trigger, got %q", got)
	}
	// REACHABLE → STALE → DELAY 同一地址不重复触发
	for _, st := range []uint16{nudStale, nudDelay, nudReachable} {
		if got := f.Handle(ev(7, st, "2408::a", mac, false)); got != "" {
			t.Fatalf("state flap %#x retriggered", st)
		}
	}
	// 临时地址轮换: 新地址触发
	if got := f.Handle(ev(7, nudStale, "2408::b", mac, false)); got != mac {
		t.Fatal("rotated address should trigger")
	}
	// 没有规则的设备 / 非热点口 / link-local 不触发
	if got := f.Handle(ev(7, nudReachable, "2408::c", "aa:bb:cc:dd:ee:99", false)); got != "" {
		t.Fatal("device without rules triggered")
	}
	if got := f.Handle(ev(3, nudReachable, "2408::d", mac, false)); got != "" {
		t.Fatal("upstream iface triggered")
	}
	if got := f.Handle(ev(7, nudReachable, "fe80::1", mac, false)); got != "" {
		t.Fatal("link-local triggered")
	}
	// 删除后再出现: 重新触发
	f.Handle(ev(7, 0, "2408::a", mac, true))
	if got := f.Handle(ev(7, nudReachable, "2408::a", mac, false)); got != mac {
		t.Fatal("re-appeared address should trigger")
	}
	// FAILED 也让它忘掉
	f.Handle(ev(7, nudFailed, "2408::b", mac, false))
	if got := f.Handle(ev(7, nudReachable, "2408::b", mac, false)); got != mac {
		t.Fatal("address after FAILED should trigger")
	}
	// TTL 过期后兜底再触发一次
	clock = clock.Add(v6KnownTTL + time.Second)
	if got := f.Handle(ev(7, nudStale, "2408::a", mac, false)); got != mac {
		t.Fatal("known entry should expire after TTL")
	}
}

func TestV6InterestMACs(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "data"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "run", "v6"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "data", "rules.json"), []byte(`{"devices":{
		"aa:00:00:00:00:01":{"limit_enabled":true,"down_mbps":5},
		"aa:00:00:00:00:02":{"limit_enabled":false,"down_mbps":5},
		"aa:00:00:00:00:03":{}},
		"blacklist":["AA:00:00:00:00:04"]}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data", "limit_policies.json"), []byte(`{"version":1,"devices":{
		"aa:00:00:00:00:05":{"quota":{"daily_gb":1,"action":"block"}}}}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "run", "v6", "aa:00:00:00:00:06"), []byte("#hnc_v6 iface=wlan2 mark=6 ing=0\n"), 0o644)
	got := v6InterestMACs(dir)
	want := map[string]bool{"aa:00:00:00:00:01": true, "aa:00:00:00:00:04": true, "aa:00:00:00:00:05": true, "aa:00:00:00:00:06": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("interest = %v", got)
	}
}

// 合并/去抖: 窗口内多次触发 → 一次执行; 执行期间的触发并入下一批; 全量请求透传
func TestV6SyncQueueDebounceCoalesce(t *testing.T) {
	type call struct {
		full bool
		macs []string
	}
	var mu sync.Mutex
	var calls []call
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	block := true
	q := newV6SyncQueue(40*time.Millisecond, func(full bool, macs []string) {
		mu.Lock()
		calls = append(calls, call{full, append([]string(nil), macs...)})
		b := block
		mu.Unlock()
		started <- struct{}{}
		if b {
			<-release
		}
	})
	stop := make(chan struct{})
	defer close(stop)
	go q.Loop(stop)

	t0 := time.Now()
	q.Add("AA:BB:CC:DD:EE:02")
	q.Add("aa:bb:cc:dd:ee:01")
	q.Add("aa:bb:cc:dd:ee:02") // 重复
	<-started
	if el := time.Since(t0); el < 35*time.Millisecond || el > time.Second {
		t.Fatalf("first run after %s, want ~debounce", el)
	}
	// 第一批执行中: 新触发要排到下一批
	q.Add("aa:bb:cc:dd:ee:03")
	q.Add("aa:bb:cc:dd:ee:01")
	q.AddFull()
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	if len(calls) != 1 {
		mu.Unlock()
		t.Fatalf("runs overlapped: %d", len(calls))
	}
	block = false
	mu.Unlock()
	close(release)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("second batch never ran")
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	want := []call{
		{false, []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}},
		{true, []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:03"}},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %+v", calls)
	}
}

// 事件风暴: 固定窗口, 延迟有上界(不会被持续事件无限推迟)
func TestV6SyncQueueBoundedLatency(t *testing.T) {
	ran := make(chan []string, 8)
	q := newV6SyncQueue(50*time.Millisecond, func(full bool, macs []string) { ran <- macs })
	stop := make(chan struct{})
	defer close(stop)
	go q.Loop(stop)
	t0 := time.Now()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 30; i++ {
			q.Add("aa:bb:cc:dd:ee:01")
			time.Sleep(10 * time.Millisecond)
		}
		close(done)
	}()
	select {
	case <-ran:
		if el := time.Since(t0); el > 250*time.Millisecond {
			t.Fatalf("first run delayed %s under event storm", el)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("never ran under event storm")
	}
	<-done
}
