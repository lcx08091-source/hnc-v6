//go:build linux

// m4_sim_v532_test.go — v5.32 审查: 设备换 IP 之后, 两个写者都不许「跳回旧 IP」。
// 由 test/sim/run_m4_sim_v532.sh 调(HNC_SIM_FLIP=1); 平时 go test 直接跳过。
//
// 同一份内核邻居表同时喂给两边比(测试纪律第 11 条): hotspotd(C)照常做发现、写
// data/devices.json; Go 走演练写者, 只写 run/devices.go.json。场景自己驱动 simnet:
//
//  1. 设备换 IP 后不再用网, 看 75 秒 —— 旧表项会在约 30 秒后从 REACHABLE 老化成 STALE,
//     内核为此发一条通知(审查时 C 版就是被这条通知改回了旧 IP, 持续到新 IP 自己老化);
//  2. 网关还有流量去找旧 IP(换 IP 前的连接没断干净)—— 旧表项 DELAY → PROBE → FAILED,
//     沿途的通知也不许把 IP 改回去;
//  3. 设备离开, 网关还去找它 → 表项 DELAY → PROBE → FAILED。FAILED 的通知不带 MAC
//     (内核在表项失效时不给链路地址), 两边要按 IP 认出是谁并让它下线 —— 审查前两边都
//     把这条通知丢掉, 只能等 90 秒没有事件才下线。
//
// 判定: 每个写者第一次报出新 IP 之后, 不许再报旧 IP; 且换 IP 后 10 秒内要报出新 IP
// (新表项要等网关确认可达, 约 5 秒 —— 内核建表项时把「确认时间」回拨 60 秒, 在那之前
// 它比旧 IP 的确认时间还旧); 设备离开后 20 秒内两边都不再列出它(约 8 秒 FAILED)。
package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestM4SimNoFlipBack(t *testing.T) {
	iface, simnet := os.Getenv("HNC_SIM_IFACE"), os.Getenv("HNC_SIM_SIMNET")
	if iface == "" || os.Getenv("HNC_SIM_FLIP") != "1" || simnet == "" {
		t.Skip("只在 test/sim/run_m4_sim_v532.sh 里跑(需要模拟设备)")
	}
	if !discovering() {
		t.Fatalf("前置条件: hotspotd 应在做发现, STATUS=%q", simStatus())
	}
	const (
		mac   = "02:5a:00:00:00:31"
		oldIP = "192.168.43.131"
		newIP = "192.168.43.132"
	)
	sim := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("bash", append([]string{simnet}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("simnet %v: %v %s", args, err, out)
		}
	}
	ipOf := func(path string) string {
		devs, err := readDevs(path)
		if err != nil {
			return ""
		}
		return devs[mac].IP
	}
	neighOf := func() string {
		out, _ := exec.Command("ip", "-s", "neigh", "show", "dev", iface).Output()
		var parts []string
		for _, l := range strings.Split(string(out), "\n") {
			if !strings.Contains(l, "lladdr "+mac) {
				continue
			}
			f := strings.Fields(l)
			used := ""
			for i := range f {
				if f[i] == "used" && i+1 < len(f) {
					used = f[i+1]
				}
			}
			parts = append(parts, f[0][strings.LastIndex(f[0], ".")+1:]+":"+f[len(f)-1]+"("+used+")")
		}
		return strings.Join(parts, " ")
	}

	_ = os.Remove(m4DrillOut)
	r := newM4GoRunner(iface, true) // 演练写者: 只写 run/devices.go.json
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.start()
	defer func() { close(r.stopCh); <-r.doneCh }()

	sim("add", "flip", mac, oldIP)
	defer exec.Command("bash", simnet, "del", "flip", "--quiet").Run()
	if !waitFor(20*time.Second, func() bool { return ipOf(m4DevicesJSON) == oldIP && ipOf(m4DrillOut) == oldIP }) {
		t.Fatalf("0. 两边都应先报 %s: C=%q Go=%q", oldIP, ipOf(m4DevicesJSON), ipOf(m4DrillOut))
	}
	// 旧 IP 先被网关确认可达(不然换 IP 时网关对它的回包探测落空, 旧表项直接 FAILED, 测不到老化)
	if !waitFor(15*time.Second, func() bool { return strings.Contains(neighOf(), "131:REACHABLE") }) {
		t.Fatalf("0. 网关 15 秒内没确认 %s 可达: %s", oldIP, neighOf())
	}

	type writer struct {
		name, path string
		adopted    time.Duration // 第一次报出新 IP 的时刻(相对换 IP); -1 = 还没有
		flips      []string
	}
	ws := []*writer{{name: "C", path: m4DevicesJSON, adopted: -1}, {name: "Go", path: m4DrillOut, adopted: -1}}
	t0 := time.Now()
	last := ""
	watch := func(phase string, d time.Duration) {
		end := time.Now().Add(d)
		for time.Now().Before(end) {
			el := time.Since(t0).Truncate(100 * time.Millisecond)
			line := ""
			for _, w := range ws {
				ip := ipOf(w.path)
				line += w.name + "=" + ip + " "
				switch {
				case ip == newIP && w.adopted < 0:
					w.adopted = el
				case ip == oldIP && w.adopted >= 0:
					w.flips = append(w.flips, phase+" "+el.String())
				}
			}
			if cur := line + "| " + neighOf(); cur != last {
				last = cur
				t.Logf("   %s t=%-5v %s", phase, el, cur)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	t.Logf("1. 换 IP %s → %s, 之后不用网", oldIP, newIP)
	sim("ip", "flip", newIP)
	watch("1", 75*time.Second)

	t.Logf("2. 网关还有流量去找旧 IP(旧表项 DELAY → PROBE → FAILED)")
	if out, err := exec.Command("bash", "-c", "echo hnc-sim > /dev/udp/"+oldIP+"/9").CombinedOutput(); err != nil {
		t.Fatalf("向旧 IP 发包: %v %s", err, out)
	}
	watch("2", 15*time.Second)

	t.Logf("3. 设备离开, 网关还去找它(表项 DELAY → PROBE → FAILED, FAILED 通知不带 MAC)")
	sim("del", "flip") // 不带 --quiet: 网关再往它的 IP 发一个包
	tLeave := time.Now()
	gone := map[string]time.Duration{}
	for time.Since(tLeave) < 25*time.Second && len(gone) < len(ws) {
		for _, w := range ws {
			if _, ok := gone[w.name]; !ok && ipOf(w.path) == "" {
				gone[w.name] = time.Since(tLeave).Truncate(100 * time.Millisecond)
			}
		}
		time.Sleep(250 * time.Millisecond)
	}

	for _, w := range ws {
		switch {
		case w.adopted < 0:
			t.Errorf("%s: 75 秒内一直没报出新 IP %s", w.name, newIP)
		case w.adopted > 10*time.Second:
			t.Errorf("%s: 换 IP 后 %v 才报出新 IP(上限 10 秒)", w.name, w.adopted)
		}
		if len(w.flips) > 0 {
			t.Errorf("%s: 报出新 IP 之后又跳回旧 IP %s(%d 次采样, 首次 %s)", w.name, oldIP, len(w.flips), w.flips[0])
		} else if w.adopted >= 0 {
			t.Logf("4. %s: 换 IP 后 %v 报出新 IP, 之后没有跳回旧 IP ✓", w.name, w.adopted)
		}
		if g, ok := gone[w.name]; !ok || g > 20*time.Second {
			t.Errorf("%s: 设备离开后 25 秒内还列着它(上限 20 秒; 审查前要等 90 秒没事件才下线)", w.name)
		} else {
			t.Logf("4. %s: 设备离开后 %v 下线 ✓", w.name, g)
		}
	}
}
