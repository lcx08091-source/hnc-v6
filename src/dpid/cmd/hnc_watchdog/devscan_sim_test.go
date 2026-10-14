//go:build linux

// devscan_sim_test.go — v5.33: 模拟设备上的设备发现验收(只剩 Go 一份)。
// 由 test/sim/run_devscan_sim.sh 调(HNC_SIM_DEVSCAN=1); 平时 go test 直接跳过。
//
// 运行环境(脚本保证): 独立的网络 + 挂载命名空间, 模拟目录已绑到 /data/local/hnc ——
// 这里一律走看门狗的正式路径(dataDir / runDir …), 写者就是生产的 newM4GoRunner;
// PATH 里有 test/sim/fake(假 dumpsys)。场景由本测试自己驱动 simnet.sh。
//
// 合并自 v5.30–v5.32 的三套场景(当时是 hotspotd 与 Go 对照), 现在只验 Go:
//  1. 6 台连上: DHCP 真名 / 垃圾名 null / 手动名 / 垃圾名 localhost 且在黑名单 /
//     不报名字 / 又一个真名 —— 逐字段(IP / iface / 名字和来源 / 黑名单状态)对上;
//  2. 解除黑名单 + `device_detect.sh scan`(WebUI「刷新」): 2 秒内返回设备数, 返回时
//     devices.json 已是这次扫描的结果;
//  3. pad 换 IP 后不再用网, 看 75 秒(旧表项老化 STALE): 10 秒内报新 IP, 之后不跳回;
//  4. 网关还去找旧 IP(旧表项 DELAY → PROBE → FAILED): 不跳回;
//  5. 表项全 STALE 后再 scan(全量重扫, 新旧两条都 STALE, 只有「最近确认」分胜负): 仍是新 IP;
//  6. tv 离开, 网关还去找它(FAILED 通知不带 MAC): 20 秒内下线;
//  7. watch 悄悄离开(没人找它, 表项一直 STALE): 15 秒后还在(与真机一致);
//  8. tv 换个 IP 回来; 9. 一下子连进 5 台。
//
// 在用网的设备由后台每 20 秒 poke 一次(真实设备在用网时就会刷新邻居表; 不 poke 的话
// 静默设备 90 秒后按离线移出, 测的就不是本步骤了)。被测的设备不 poke。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// simDev 是 devices.json 里一台设备的字段(devscan.Device 同构, 独立定义避免耦合)。
type simDev struct {
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Hostname    string `json:"hostname"`
	HostnameSrc string `json:"hostname_src"`
	Iface       string `json:"iface"`
	Status      string `json:"status"`
}

func readDevs(path string) (map[string]simDev, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]simDev{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("解析 %s: %v", path, err)
	}
	return m, nil
}

// simWant 一台设备的期望(空字段不比; optional = 在不在都行, 在的话照比)。
type simWant struct {
	ip, name, src, status string
	optional              bool
}

// simProblems devices.json 与期望的全部差异(集合 / IP / iface / 名字 / 状态)。
func simProblems(devs map[string]simDev, iface string, want map[string]simWant) []string {
	var out []string
	for mac, w := range want {
		d, ok := devs[mac]
		if !ok {
			if !w.optional {
				out = append(out, "缺设备 "+mac)
			}
			continue
		}
		if w.ip != "" && d.IP != w.ip {
			out = append(out, fmt.Sprintf("%s: IP %s, 期望 %s", mac, d.IP, w.ip))
		}
		if d.Iface != iface {
			out = append(out, fmt.Sprintf("%s: iface %q, 期望 %q", mac, d.Iface, iface))
		}
		if w.name != "" && (d.Hostname != w.name || d.HostnameSrc != w.src) {
			out = append(out, fmt.Sprintf("%s: 名字 %q@%s, 期望 %q@%s", mac, d.Hostname, d.HostnameSrc, w.name, w.src))
		}
		if w.status != "" && d.Status != w.status {
			out = append(out, fmt.Sprintf("%s: status %q, 期望 %q", mac, d.Status, w.status))
		}
	}
	for mac := range devs {
		if _, ok := want[mac]; !ok {
			out = append(out, "多了设备 "+mac)
		}
	}
	sort.Strings(out)
	return out
}

func TestDevscanSim(t *testing.T) {
	iface, simnet, repo := os.Getenv("HNC_SIM_IFACE"), os.Getenv("HNC_SIM_SIMNET"), os.Getenv("HNC_SIM_REPO")
	if iface == "" || simnet == "" || repo == "" || os.Getenv("HNC_SIM_DEVSCAN") != "1" {
		t.Skip("只在 test/sim/run_devscan_sim.sh 里跑(需要模拟设备)")
	}
	sim := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("bash", append([]string{simnet}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("simnet %v: %v %s", args, err, out)
		}
	}
	// 在用网的设备: 后台每 20 秒 poke 一次
	var keepMu sync.Mutex
	keep := map[string]bool{}
	setKeep := func(name string, on bool) { keepMu.Lock(); keep[name] = on; keepMu.Unlock() }
	stopKeep := make(chan struct{})
	defer close(stopKeep)
	go func() {
		tk := time.NewTicker(20 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-stopKeep:
				return
			case <-tk.C:
				keepMu.Lock()
				var names []string
				for n, on := range keep {
					if on {
						names = append(names, n)
					}
				}
				keepMu.Unlock()
				for _, n := range names {
					_ = exec.Command("bash", simnet, "poke", n).Run()
				}
			}
		}
	}()
	devs := func() map[string]simDev {
		d, err := readDevs(m4DevicesJSON)
		if err != nil {
			return map[string]simDev{}
		}
		return d
	}
	// waitWant 时限内反复比到全部对上, 返回用时; 超时记失败并列出差异。
	waitWant := func(step string, limit time.Duration, want map[string]simWant) {
		t.Helper()
		t0 := time.Now()
		var probs []string
		for {
			if probs = simProblems(devs(), iface, want); len(probs) == 0 {
				t.Logf("%s ✓ %v 对上(%d 台)", step, time.Since(t0).Truncate(100*time.Millisecond), len(want))
				return
			}
			if time.Since(t0) > limit {
				t.Errorf("%s: %v 内没对上: %s", step, limit, strings.Join(probs, "; "))
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	scan := func(step, wantN string) {
		t.Helper()
		t0 := time.Now()
		cmd := exec.Command("sh", filepath.Join(repo, "bin/device_detect.sh"), "scan")
		cmd.Env = append(os.Environ(), "HNC_DIR="+hncDir, "HNC_SKIP_PATH_HARDENING=1")
		out, err := cmd.Output()
		took := time.Since(t0)
		ack, _ := os.ReadFile(m4RefreshAckFile)
		nonce, _ := os.ReadFile(m4RefreshFile)
		switch {
		case err != nil:
			t.Errorf("%s: device_detect.sh scan: %v", step, err)
		case strings.TrimSpace(string(out)) != wantN:
			t.Errorf("%s: scan 返回 %q, 期望 %s", step, strings.TrimSpace(string(out)), wantN)
		case strings.TrimSpace(string(ack)) != strings.TrimSpace(string(nonce)):
			t.Errorf("%s: 回执 %q 与 nonce %q 不一致(写者没回执)", step, ack, nonce)
		case took > 2*time.Second:
			t.Errorf("%s: scan 用了 %v(上限 2 秒)", step, took)
		default:
			t.Logf("%s ✓ scan 返回 %s 台, 用时 %v", step, wantN, took.Truncate(10*time.Millisecond))
		}
	}

	const (
		tv, pad, mbp, phone, watch, pc = "02:5a:00:00:00:01", "02:5a:00:00:00:02", "02:5a:00:00:00:03",
			"02:5a:00:00:00:04", "02:5a:00:00:00:05", "02:5a:00:00:00:06"
	)
	if err := os.WriteFile(m4NamesPath, []byte(`{"`+mbp+`":"客厅的Mac"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesJSONPath, []byte(`{"devices":{},"blacklist":["`+phone+`"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(m4DevicesJSON)
	r := newM4GoRunner(iface)
	r.statsCmdFn = func() (map[string][2]int64, error) { return nil, os.ErrNotExist }
	r.start()
	defer func() { close(r.stopCh); <-r.doneCh }()

	t.Logf("1. 6 台连上(DHCP 真名 / 垃圾名 null / 手动名 / 垃圾名 localhost 且在黑名单 / 不报名字 / 真名)")
	sim("add", "tv", tv, "192.168.43.101", "Redmi-TV")
	sim("add", "pad", pad, "192.168.43.102", "null")
	sim("add", "mbp", mbp, "192.168.43.103")
	sim("add", "phone", phone, "192.168.43.104", "localhost")
	sim("add", "watch", watch, "192.168.43.105")
	sim("add", "pc", pc, "192.168.43.106", "DESKTOP-7Q2")
	for _, n := range []string{"tv", "mbp", "phone", "watch", "pc"} {
		setKeep(n, true)
	}
	want := map[string]simWant{
		tv:    {ip: "192.168.43.101", name: "Redmi-TV", src: "dhcp", status: "allowed"},
		pad:   {ip: "192.168.43.102", name: "00000002", src: "mac", status: "allowed"},
		mbp:   {ip: "192.168.43.103", name: "客厅的Mac", src: "manual", status: "allowed"},
		phone: {ip: "192.168.43.104", name: "00000004", src: "mac", status: "blocked"},
		watch: {ip: "192.168.43.105", name: "00000005", src: "mac", status: "allowed"},
		pc:    {ip: "192.168.43.106", name: "DESKTOP-7Q2", src: "dhcp", status: "allowed"},
	}
	waitWant("1", 30*time.Second, want)

	t.Logf("2. 解除黑名单 + device_detect.sh scan(WebUI「刷新」)")
	if err := os.WriteFile(rulesJSONPath, []byte(`{"devices":{},"blacklist":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	scan("2", "6")
	if d := devs()[phone]; d.Status != "allowed" {
		t.Errorf("2: scan 返回时 phone 应已是 allowed(这次扫描强制重写), 得 %q", d.Status)
	}
	w := want[phone]
	w.status = "allowed"
	want[phone] = w

	// 3–5: pad 换 IP 后不许跳回旧 IP(v5.32 审查的场景, 只验 Go)
	neighOf := func(mac string) string {
		out, _ := exec.Command("ip", "-s", "neigh", "show", "dev", iface).Output()
		var parts []string
		for _, l := range strings.Split(string(out), "\n") {
			if !strings.Contains(l, "lladdr "+mac) {
				continue
			}
			f := strings.Fields(l)
			parts = append(parts, f[0][strings.LastIndex(f[0], ".")+1:]+":"+f[len(f)-1])
		}
		return strings.Join(parts, " ")
	}
	if !waitFor(15*time.Second, func() bool { return strings.Contains(neighOf(pad), "102:REACHABLE") }) {
		t.Fatalf("3. 网关 15 秒内没确认 .102 可达: %s", neighOf(pad))
	}
	const oldIP, newIP = "192.168.43.102", "192.168.43.112"
	t0 := time.Now()
	adopted := time.Duration(-1)
	var flips []string
	last := ""
	watchIP := func(phase string, d time.Duration) {
		end := time.Now().Add(d)
		for time.Now().Before(end) {
			el := time.Since(t0).Truncate(100 * time.Millisecond)
			ip := devs()[pad].IP
			switch {
			case ip == newIP && adopted < 0:
				adopted = el
			case ip == oldIP && adopted >= 0:
				flips = append(flips, phase+" "+el.String())
			}
			if cur := ip + " | " + neighOf(pad); cur != last {
				last = cur
				t.Logf("   %s t=%-5v pad=%s", phase, el, cur)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	t.Logf("3. pad 换 IP .102 → .112, 之后不用网, 看 75 秒")
	sim("ip", "pad", newIP)
	watchIP("3", 75*time.Second)
	t.Logf("4. 网关还有流量去找旧 IP(旧表项 DELAY → PROBE → FAILED)")
	if out, err := exec.Command("bash", "-c", "echo hnc-sim > /dev/udp/"+oldIP+"/9").CombinedOutput(); err != nil {
		t.Fatalf("向旧 IP 发包: %v %s", err, out)
	}
	watchIP("4", 15*time.Second)
	switch {
	case adopted < 0:
		t.Errorf("3: 75 秒内一直没报出新 IP %s", newIP)
	case adopted > 10*time.Second:
		t.Errorf("3: 换 IP 后 %v 才报出新 IP(上限 10 秒)", adopted)
	default:
		t.Logf("3 ✓ 换 IP 后 %v 报出新 IP", adopted)
	}
	if len(flips) > 0 {
		t.Errorf("3/4: 报出新 IP 之后又跳回旧 IP(%d 次采样, 首次 %s)", len(flips), flips[0])
	} else if adopted >= 0 {
		t.Logf("4 ✓ 没有跳回旧 IP")
	}
	t.Logf("5. 表项都 STALE 了, 再全量重扫(scan): 仍是新 IP")
	scan("5", "6")
	if ip := devs()[pad].IP; ip != newIP {
		t.Errorf("5: 全量重扫后 pad 是 %s, 期望 %s(邻居表: %s)", ip, newIP, neighOf(pad))
	}
	w = want[pad]
	w.ip = newIP
	want[pad] = w
	setKeep("pad", true)

	t.Logf("6. tv 不用网了(表项老化成 STALE)后离开, 网关还去找它(FAILED 通知不带 MAC)")
	// 表项还是 REACHABLE 时网关发包不探测(直接发, 之后老化成 STALE 就停住), 不会 FAILED;
	// 真机上「走了的设备」也是先闲下来、再有流量去找它。
	setKeep("tv", false)
	if !waitFor(60*time.Second, func() bool { return strings.Contains(neighOf(tv), "101:STALE") }) {
		t.Fatalf("6. tv 的表项 60 秒内没老化成 STALE: %s", neighOf(tv))
	}
	sim("del", "tv") // 不带 --quiet: 网关再往它的 IP 发一个包 → DELAY → PROBE → FAILED
	delete(want, tv)
	waitWant("6", 20*time.Second, want)

	t.Logf("7. watch 悄悄离开(没人找它, 表项一直 STALE)")
	setKeep("watch", false)
	sim("del", "watch", "--quiet")
	time.Sleep(15 * time.Second)
	if _, ok := devs()[watch]; !ok {
		t.Errorf("7: watch 悄悄离开 15 秒就下线了(没有流量找它时发现不了它走了, 应还在)")
	} else {
		t.Logf("7 ✓ 15 秒后 watch 还在(与真机一致)")
	}
	// 之后在不在都行: 最后一个邻居事件 90 秒后会按离线移出(第 9 步可能赶上)
	want[watch] = simWant{optional: true}

	t.Logf("8. tv 换个 IP 回来(.121)")
	sim("add", "tv", tv, "192.168.43.121", "Redmi-TV")
	setKeep("tv", true)
	want[tv] = simWant{ip: "192.168.43.121", name: "Redmi-TV", src: "dhcp", status: "allowed"}
	waitWant("8", 15*time.Second, want)

	t.Logf("9. 一下子连进 5 台")
	for i := 7; i <= 11; i++ {
		mac := fmt.Sprintf("02:5a:00:00:00:%02x", i)
		ip := fmt.Sprintf("192.168.43.%d", 100+i)
		sim("add", fmt.Sprintf("d%d", i), mac, ip)
		setKeep(fmt.Sprintf("d%d", i), true)
		want[mac] = simWant{ip: ip}
	}
	waitWant("9", 30*time.Second, want)
}

// waitFor 时限内反复检查 cond, 成立返回 true。
func waitFor(limit time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return cond()
}
