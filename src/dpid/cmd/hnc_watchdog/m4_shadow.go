// m4_shadow.go — v5.30 T3: 迁移 M4 第一步 —— 设备发现的 Go 影子(只算只比对)。
//
// 设备发现现在是 hotspotd(C, ~6900 行)读 /proc/net/arp + 邻居表 netlink 事件,
// 写 data/devices.json。M4 要把它搬进 Go; 第一步只跑影子:
//   - 热点 ACTIVE 时每 m4ShadowEvery(5 分钟), 用 neigh 包 dump 热点网卡的
//     IPv4 邻居表(有 MAC、状态 REACHABLE / STALE / DELAY / PROBE), 得到
//     Go 看到的设备集合 {MAC → IP};
//   - 与 hotspotd 的 devices.json(同一网卡的设备; iface 字段为空的不筛)比对:
//     only_go(Go 看到、hotspotd 没有 = 多)/ only_hotspotd(少)/ ip_diff
//     (两边都有、IP 不同);
//   - 同一条不一致(MAC + 种类)连续 m4PersistRounds 轮都在才计数 —— 设备
//     刚连上 / 刚走时两边节拍不同, 一轮的差异不算;
//   - 有计数的轮次累计进 run/watchdog_actions.json 的 m4_mismatch(同时
//     m4_checks = 比对轮数), 自检「看门狗动作」行显示; 明细(含 MAC)写
//     run/m4_shadow.json 供排查, 不进兼容性报告。
//   - 不写 devices.json、不替换 hotspotd 任何功能; 名字解析(DHCP / mDNS)
//     本版不搬。
//
// 开关: run/wd_m4_shadow.disabled 存在 → 影子不跑(每轮读)。
package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"hnc.io/dpid/neigh"
)

const (
	m4ShadowEvery    = 5 * time.Minute
	m4SwitchFile     = "wd_m4_shadow.disabled"
	m4PersistRounds  = 2 // 同一不一致连续这么多轮才计数
	m4DetailMax      = 16
	m4ShadowFileName = "m4_shadow.json"
)

var (
	m4RunDir, m4DataDir = runDir, dataDir
	// neighDumpIfFn 读某网卡的 IPv4 邻居表(测试注入)。
	neighDumpIfFn = neigh.DumpIf
	// m4IfIndexFn 网卡名 → ifindex(测试注入)。
	m4IfIndexFn = func(name string) (int, error) {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return 0, err
		}
		return ifi.Index, nil
	}
)

// m4Diff 一轮比对结果(MAC 均小写)。
type m4Diff struct {
	OnlyGo       []string `json:"only_go"`       // Go 看到、hotspotd 没有(多)
	OnlyHotspotd []string `json:"only_hotspotd"` // hotspotd 有、Go 没看到(少)
	IPDiff       []string `json:"ip_diff"`       // "mac go=ip1,ip2 hotspotd=ip"
}

func (d m4Diff) empty() bool {
	return len(d.OnlyGo) == 0 && len(d.OnlyHotspotd) == 0 && len(d.IPDiff) == 0
}

// m4HDDev hotspotd 的一台设备。
type m4HDDev struct{ IP, Iface string }

// parseHotspotdDevices devices.json → MAC → 设备(只留 iface 为空或等于 iface 的)。
func parseHotspotdDevices(b []byte, iface string) map[string]m4HDDev {
	var raw map[string]map[string]interface{}
	if json.Unmarshal(b, &raw) != nil {
		return nil
	}
	out := make(map[string]m4HDDev, len(raw))
	for mac, d := range raw {
		mac = strings.ToLower(strings.TrimSpace(mac))
		if len(mac) != 17 {
			continue
		}
		ip, _ := d["ip"].(string)
		ifc, _ := d["iface"].(string)
		if ifc != "" && iface != "" && ifc != iface {
			continue
		}
		out[mac] = m4HDDev{IP: ip, Iface: ifc}
	}
	return out
}

// goDevices 邻居表 → MAC → IPv4 列表(只留 Usable 的)。
func goDevices(es []neigh.Entry) map[string][]string {
	out := map[string][]string{}
	for _, e := range es {
		if !e.Usable() || e.IP.To4() == nil {
			continue
		}
		out[e.MAC] = append(out[e.MAC], e.IP.String())
	}
	for _, ips := range out {
		sort.Strings(ips)
	}
	return out
}

// compareM4 纯函数: 两边集合 → 差异(各自排序, 便于测试与去抖比对)。
func compareM4(goSet map[string][]string, hd map[string]m4HDDev) m4Diff {
	var d m4Diff
	for mac, ips := range goSet {
		h, ok := hd[mac]
		if !ok {
			d.OnlyGo = append(d.OnlyGo, mac)
			continue
		}
		if h.IP != "" && !containsStr(ips, h.IP) {
			d.IPDiff = append(d.IPDiff, mac+" go="+strings.Join(ips, ",")+" hotspotd="+h.IP)
		}
	}
	for mac := range hd {
		if _, ok := goSet[mac]; !ok {
			d.OnlyHotspotd = append(d.OnlyHotspotd, mac)
		}
	}
	sort.Strings(d.OnlyGo)
	sort.Strings(d.OnlyHotspotd)
	sort.Strings(d.IPDiff)
	return d
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// diffKeys 一轮差异的去抖键(种类 + MAC)。
func diffKeys(d m4Diff) map[string]bool {
	k := map[string]bool{}
	for _, m := range d.OnlyGo {
		k["go:"+m] = true
	}
	for _, m := range d.OnlyHotspotd {
		k["hd:"+m] = true
	}
	for _, s := range d.IPDiff {
		k["ip:"+strings.Fields(s)[0]] = true
	}
	return k
}

// m4ShadowState 影子的累计状态(主循环串行写, flush 读 → 加锁)。
type m4ShadowState struct {
	mu       sync.Mutex
	last     time.Time
	checks   int
	mismatch int
	streak   map[string]int // 差异键 → 连续出现的轮数(去抖)
}

var m4Shadow = &m4ShadowState{}

// wdActionsM4Extra actionstats.snapshot 带出的 M4 影子计数(测试可替换)。
var wdActionsM4Extra = func() (int, int) { return m4Shadow.counts() }

// counts 给 watchdog_actions.json 用。
func (s *m4ShadowState) counts() (checks, mismatch int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checks, s.mismatch
}

// m4ShadowEnabled 开关文件不存在 = 启用(默认)。
func m4ShadowEnabled() bool {
	_, err := os.Stat(filepath.Join(m4RunDir, m4SwitchFile))
	return err != nil
}

// maybeRun 到点(5 分钟)且开关开着才比对一轮。iface = 当前热点网卡。
// 读不了邻居表 / devices.json 的轮次不计(不算比对, 也不算不一致)。
func (s *m4ShadowState) maybeRun(iface string, now time.Time) {
	if iface == "" || !m4ShadowEnabled() {
		return
	}
	s.mu.Lock()
	due := s.last.IsZero() || now.Sub(s.last) >= m4ShadowEvery || now.Before(s.last)
	if due {
		s.last = now
	}
	s.mu.Unlock()
	if !due {
		return
	}
	idx, err := m4IfIndexFn(iface)
	if err != nil || idx <= 0 {
		return
	}
	es, err := neighDumpIfFn(idx)
	if err != nil {
		return
	}
	b, err := os.ReadFile(filepath.Join(m4DataDir, "devices.json"))
	if err != nil || len(b) > 8<<20 {
		return
	}
	hd := parseHotspotdDevices(b, iface)
	if hd == nil {
		return
	}
	d := compareM4(goDevices(es), hd)
	counted := s.record(d)
	writeM4Detail(now, iface, d, counted)
}

// record 记一轮; 返回本轮是否计入 m4_mismatch(有差异连续 m4PersistRounds 轮)。
func (s *m4ShadowState) record(d m4Diff) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks++
	cur := diffKeys(d)
	if s.streak == nil {
		s.streak = map[string]int{}
	}
	persisted := false
	for k := range cur {
		s.streak[k]++
		if s.streak[k] >= m4PersistRounds {
			persisted = true
		}
	}
	for k := range s.streak {
		if !cur[k] {
			delete(s.streak, k)
		}
	}
	if persisted {
		s.mismatch++
	}
	return persisted
}

// writeM4Detail 明细写 run/m4_shadow.json(原子替换, 每类最多 m4DetailMax 条)。
func writeM4Detail(now time.Time, iface string, d m4Diff, counted bool) {
	trim := func(l []string) []string {
		if len(l) > m4DetailMax {
			return l[:m4DetailMax]
		}
		if l == nil {
			return []string{}
		}
		return l
	}
	checks, mismatch := m4Shadow.counts()
	out := map[string]interface{}{
		"schema": 1, "at": now.Unix(), "iface": iface, "counted": counted,
		"checks": checks, "mismatch": mismatch,
		"only_go": trim(d.OnlyGo), "only_hotspotd": trim(d.OnlyHotspotd), "ip_diff": trim(d.IPDiff),
	}
	b, err := json.Marshal(out)
	if err != nil {
		return
	}
	p := filepath.Join(m4RunDir, m4ShadowFileName)
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, p)
	}
}
