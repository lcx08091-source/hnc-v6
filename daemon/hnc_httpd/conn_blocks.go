// conn_blocks.go — v5.16 按设备封锁域名 / IP(从「实时连接」里一键封锁)
//
//   data/conn_blocks.json: {"items":[{"mac","kind":"domain"|"ip","value","label","ts"}]}
//   run/conn_blocks.flat:  展开后的 "<mac> <ip>" 每行一条, 交给 bin/connblock_sync.sh
//   run/conn_blocks.dns:   v5.18 DNS 层: "<mac> <domain>" 每行一条(域名封锁项原样)
//   run/connblock_caps.json: 脚本写的能力探测结果 {"dns_layer":bool,"dns_layer_v6":bool,"checked":ts}
//
// IP 层: 域名按 dpid 的 DNS/SNI 反查表(run/dpi_ipname.json)展开: 名字等于该域名
// 或是它的子域名的 IP 全部拦掉。App 换 IP 时反查表会更新, 后台(AppUsageLoop 每
// 10 秒)重新展开, 结果变了才重跑脚本。局限: 反查表里还没出现过的新 IP 在第一次
// 连接时拦不住, 直到 DNS/SNI 被看到。
// DNS 层(v5.18): 同时丢弃这台设备对该域名(及子域名)的 DNS 查询(udp/tcp 53,
// iptables -m string 匹配 DNS 线格式 qname 后缀), 让新 IP 根本解析不出来, 补上
// IP 层的首连空窗。内核无 xt_string 时脚本静默退回只有 IP 层。

package main

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type connBlock struct {
	MAC   string `json:"mac"`
	Kind  string `json:"kind"` // domain | ip
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
	Ts    int64  `json:"ts"`
	// v6.x 派生封锁项(app_time.go, 不落 conn_blocks.json, 每次展开时现算):
	//   source = "app_time"(应用时长用完, until = 本地次日 0 点自动失效) | "category"(按类别封锁)
	//   ref    = app_id / category
	Source string `json:"source,omitempty"`
	Ref    string `json:"ref,omitempty"`
	Until  int64  `json:"until,omitempty"`
}

type connBlockFile struct {
	Items []connBlock `json:"items"`
}

const connBlockMaxItems = 200
const connBlockMaxIPsPerDomain = 200

var connBlockMu sync.Mutex // 串行化读改写 + 展开/同步

func connBlocksPath(hncDir string) string { return filepath.Join(hncDir, "data", "conn_blocks.json") }
func connBlocksFlat(hncDir string) string { return filepath.Join(hncDir, "run", "conn_blocks.flat") }
func connBlocksDNS(hncDir string) string  { return filepath.Join(hncDir, "run", "conn_blocks.dns") }

// isNonExpandableBlockIP 检查是否属于严禁展开进防火墙封锁链的私网、回环、链路本地、多播、
// 运营商级 NAT(CGNAT 100.64.0.0/10)或透明代理 Fake-IP(198.18.0.0/15, fc00::/18)地址。
func isNonExpandableBlockIP(ipStr string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return true
	}
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 0 || (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) {
			return true
		}
		// RFC 6598 CGNAT: 100.64.0.0/10
		if b[0] == 100 && (b[1]&0xc0) == 64 {
			return true
		}
		// RFC 2544 / 透明代理 Fake-IP: 198.18.0.0/15
		if b[0] == 198 && (b[1]&0xfe) == 18 {
			return true
		}
	}
	return false
}

// expandConnBlockDomains 域名封锁项 → 排好序的 "mac domain" 行(DNS 层用)
func expandConnBlockDomains(f connBlockFile) []string {
	set := map[string]bool{}
	for _, it := range f.Items {
		if it.Kind != "domain" {
			continue
		}
		d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(it.Value)), ".")
		if validMAC(it.MAC) && domainRe.MatchString(d) && len(d) <= 253 {
			set[it.MAC+" "+d] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// connBlockDNSLayer DNS 层能力: available | unavailable | unknown(还没探测过)
func connBlockDNSLayer(hncDir string) string {
	b, err := os.ReadFile(filepath.Join(hncDir, "run", "connblock_caps.json"))
	if err != nil {
		return "unknown"
	}
	var c struct {
		DNSLayer *bool `json:"dns_layer"`
	}
	if json.Unmarshal(b, &c) != nil || c.DNSLayer == nil {
		return "unknown"
	}
	if *c.DNSLayer {
		return "available"
	}
	return "unavailable"
}

func joinLines(lines []string) string {
	s := strings.Join(lines, "\n")
	if len(lines) > 0 {
		s += "\n"
	}
	return s
}

func readConnBlocks(hncDir string) connBlockFile {
	var f connBlockFile
	if b, err := os.ReadFile(connBlocksPath(hncDir)); err == nil {
		_ = json.Unmarshal(b, &f)
	}
	return f
}

// expandConnBlocks 把封锁项展开成排好序的 "mac ip" 行。
// 死定律五: 域名规则反查出的候选 IP 若属于私网/CGNAT/Fake-IP 或共享 CDN/大厂云网关,
// 仅保留精确 DNS/SNI 域名阻断, 严禁自动展开进 HNC_CONNBLK 防火墙链导致连坐断流!
func (s *server) expandConnBlocks(f connBlockFile) []string {
	var names map[string]ipName
	var globalMACs []string
	var globalMACsLoaded bool
	targetMACsFor := func(mac string) []string {
		m := strings.ToLower(strings.TrimSpace(mac))
		if m != "00:00:00:00:00:00" {
			return []string{m}
		}
		if !globalMACsLoaded {
			globalMACsLoaded = true
			if s != nil {
				for dm := range s.deviceIPsByMAC() {
					dm = strings.ToLower(strings.TrimSpace(dm))
					if validMAC(dm) && dm != "00:00:00:00:00:00" && !isProtectedMAC(s.hncDir, dm) {
						globalMACs = append(globalMACs, dm)
					}
				}
				sort.Strings(globalMACs)
			}
		}
		return globalMACs
	}

	set := map[string]bool{}
	for _, it := range f.Items {
		macList := targetMACsFor(it.MAC)
		if len(macList) == 0 {
			continue
		}
		switch it.Kind {
		case "ip":
			if ip := net.ParseIP(it.Value); ip != nil && !isNonExpandableBlockIP(it.Value) {
				ipCanon := ip.String()
				for _, m := range macList {
					set[m+" "+ipCanon] = true
				}
			}
		case "domain":
			if names == nil {
				names = s.loadIPNames()
			}
			d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(it.Value)), ".")
			if d == "" {
				continue
			}
			type ipCand struct {
				ip string
				ts int64
			}
			var cands []ipCand
			for ip, nm := range names {
				h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(nm.Name)), ".")
				if h != d && !strings.HasSuffix(h, "."+d) {
					continue
				}
				if isNonExpandableBlockIP(ip) {
					continue
				}
				if shared, _ := detectSharedInfraTarget(s, h, ip); shared {
					continue
				}
				if h != d {
					if shared, _ := detectSharedInfraTarget(s, d, ip); shared {
						continue
					}
				}
				if parsed := net.ParseIP(ip); parsed != nil {
					cands = append(cands, ipCand{ip: parsed.String(), ts: nm.Ts})
				}
			}
			sort.Slice(cands, func(i, j int) bool {
				if cands[i].ts != cands[j].ts {
					return cands[i].ts > cands[j].ts
				}
				return cands[i].ip < cands[j].ip
			})
			if len(cands) > connBlockMaxIPsPerDomain {
				cands = cands[:connBlockMaxIPsPerDomain]
			}
			for _, c := range cands {
				for _, m := range macList {
					set[m+" "+c.ip] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type offloadGuardAsyncSlot struct {
	mu      sync.Mutex
	running bool
	pending bool
}

var (
	offloadGuardAsyncSlots sync.Map // map[string]*offloadGuardAsyncSlot
	offloadGuardAsyncWG    sync.WaitGroup
)

func triggerOffloadGuardApplyAsync(hncDir string) {
	hncDir = strings.TrimSpace(hncDir)
	if hncDir == "" {
		return
	}
	script := filepath.Join(hncDir, "bin", "hnc_offload_guard.sh")
	if st, err := os.Stat(script); err != nil || st.IsDir() {
		return
	}
	raw, _ := offloadGuardAsyncSlots.LoadOrStore(hncDir, &offloadGuardAsyncSlot{})
	slot := raw.(*offloadGuardAsyncSlot)
	slot.mu.Lock()
	if slot.running {
		slot.pending = true
		slot.mu.Unlock()
		return
	}
	slot.running = true
	slot.pending = false
	offloadGuardAsyncWG.Add(1)
	slot.mu.Unlock()

	go func(dir string, sl *offloadGuardAsyncSlot) {
		defer offloadGuardAsyncWG.Done()
		for {
			if st, err := os.Stat(filepath.Join(dir, "bin", "hnc_offload_guard.sh")); err == nil && !st.IsDir() {
				_, _ = runBin(dir, "hnc_offload_guard.sh", "apply")
			}
			sl.mu.Lock()
			if sl.pending {
				sl.pending = false
				sl.mu.Unlock()
				continue
			}
			sl.running = false
			sl.mu.Unlock()
			return
		}
	}(hncDir, slot)
}

func waitOffloadGuardAsyncIdle() {
	offloadGuardAsyncWG.Wait()
}

// connBlockSyncLocked 重新展开; 与现有 flat 不同(或 force)才写文件并跑脚本
func (s *server) connBlockSyncLocked(force bool) (string, error) {
	f := s.connBlocksEffective(time.Now())
	content := joinLines(s.expandConnBlocks(f))
	dnsContent := joinLines(expandConnBlockDomains(f))
	old, _ := os.ReadFile(connBlocksFlat(s.hncDir))
	oldDNS, _ := os.ReadFile(connBlocksDNS(s.hncDir))
	if !force && string(old) == content && string(oldDNS) == dnsContent {
		return "", nil
	}
	// 先写 DNS 列表再写 flat: 脚本两份都读, 任一变化都重跑
	if err := discoverWriteAtomic(connBlocksDNS(s.hncDir), []byte(dnsContent)); err != nil {
		return "", err
	}
	if err := discoverWriteAtomic(connBlocksFlat(s.hncDir), []byte(content)); err != nil {
		return "", err
	}
	rc, out := runBin(s.hncDir, "connblock_sync.sh")
	out = lastLine(strings.TrimSpace(out))
	if rc != 0 {
		return out, os.ErrInvalid
	}
	triggerOffloadGuardApplyAsync(s.hncDir)
	return out, nil
}

// connBlockRefresh 后台调用: 反查表变了就重新同步
func (s *server) connBlockRefresh() {
	connBlockMu.Lock()
	if len(s.connBlocksEffective(time.Now()).Items) == 0 {
		st, err := os.Stat(connBlocksFlat(s.hncDir))
		st2, err2 := os.Stat(connBlocksDNS(s.hncDir))
		if (err != nil || st.Size() == 0) && (err2 != nil || st2.Size() == 0) {
			connBlockMu.Unlock()
			return
		}
	}
	_, _ = s.connBlockSyncLocked(false)
	connBlockMu.Unlock()
	s.refreshDNSTKBlocklist(time.Now())
}

var domainRe = suffixRe

func actionConnBlockAdd(s *server, p map[string]string) actionResp {
	mac := strings.ToLower(strings.TrimSpace(p["mac"]))
	kind := strings.TrimSpace(p["kind"])
	val := strings.ToLower(strings.TrimSpace(p["value"]))
	if !validMAC(mac) {
		return actionResp{OK: false, Error: "bad params", Detail: "invalid mac"}
	}
	switch kind {
	case "ip":
		ip := net.ParseIP(val)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid ip"}
		}
		if isPrivateIP(val) || isNonExpandableBlockIP(val) {
			return actionResp{OK: false, Error: "bad params", Detail: "不能封锁局域网或保留地址"}
		}
		val = ip.String()
	case "domain":
		val = strings.TrimPrefix(val, "*.")
		if !domainRe.MatchString(val) || len(val) > 253 {
			return actionResp{OK: false, Error: "bad params", Detail: "invalid domain"}
		}
	default:
		return actionResp{OK: false, Error: "bad params", Detail: "kind must be domain|ip"}
	}
	label := strings.TrimSpace(p["label"])
	if len([]rune(label)) > 40 {
		label = string([]rune(label)[:40])
	}
	connBlockMu.Lock()
	f := readConnBlocks(s.hncDir)
	for _, it := range f.Items {
		if it.MAC == mac && it.Kind == kind && it.Value == val {
			connBlockMu.Unlock()
			s.refreshDNSTKBlocklist(time.Now())
			return actionResp{OK: true, Detail: "已经封锁过了"}
		}
	}
	if len(f.Items) >= connBlockMaxItems {
		connBlockMu.Unlock()
		return actionResp{OK: false, Error: "too many", Detail: "封锁项已达上限 200"}
	}
	f.Items = append(f.Items, connBlock{MAC: mac, Kind: kind, Value: val, Label: label, Ts: time.Now().Unix()})
	b, _ := json.MarshalIndent(f, "", "  ")
	if err := discoverWriteAtomic(connBlocksPath(s.hncDir), b); err != nil {
		connBlockMu.Unlock()
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	out, err := s.connBlockSyncLocked(true)
	connBlockMu.Unlock()
	s.refreshDNSTKBlocklist(time.Now())
	if err != nil {
		return actionResp{OK: false, Error: "sync failed", Detail: out}
	}
	return actionResp{OK: true, Detail: out}
}

func actionConnBlockDel(s *server, p map[string]string) actionResp {
	mac := strings.ToLower(strings.TrimSpace(p["mac"]))
	kind := strings.TrimSpace(p["kind"])
	val := strings.ToLower(strings.TrimSpace(p["value"]))
	connBlockMu.Lock()
	f := readConnBlocks(s.hncDir)
	kept := f.Items[:0]
	found := false
	for _, it := range f.Items {
		if it.MAC == mac && it.Kind == kind && it.Value == val {
			found = true
			continue
		}
		kept = append(kept, it)
	}
	if !found {
		connBlockMu.Unlock()
		return actionResp{OK: false, Error: "not found"}
	}
	f.Items = kept
	b, _ := json.MarshalIndent(f, "", "  ")
	if err := discoverWriteAtomic(connBlocksPath(s.hncDir), b); err != nil {
		connBlockMu.Unlock()
		return actionResp{OK: false, Error: "write failed", Detail: err.Error()}
	}
	out, err := s.connBlockSyncLocked(true)
	connBlockMu.Unlock()
	s.refreshDNSTKBlocklist(time.Now())
	if err != nil {
		return actionResp{OK: false, Error: "sync failed", Detail: out}
	}
	return actionResp{OK: true, Detail: out}
}

// connBlocksFor 某台设备的封锁项(给 /api/connections 与设备卡用)
func connBlocksFor(hncDir, mac string) []connBlock {
	mac = strings.ToLower(strings.TrimSpace(mac))
	var out []connBlock
	for _, it := range readConnBlocks(hncDir).Items {
		if strings.ToLower(strings.TrimSpace(it.MAC)) == mac {
			it.MAC = mac
			out = append(out, it)
		}
	}
	return out
}
