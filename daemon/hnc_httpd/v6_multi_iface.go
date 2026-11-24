// v6_multi_iface.go — HNC v6.0.0 · Vector:
//  1. Wi-Fi 7 MLO / 双频并发热点 (wlan1+wlan2+ap0+ap_br_*) + USB 共享 (rndis0/ncm0/usb0) 多下游接口自动发现与并管引擎;
//  2. 本机 tun0 VPN 共存策略路由防环路守卫 (正交高 16 位 skb->mark 保护低 16 位 netd/VPN netId + 热点子网优先直连 ip rule + PMTU MSS 钳制);
//  3. 1:fffe 局域网互传 2.5Gbps 免限速直通类构建器 (纯 Go AF_NETLINK + binary.LittleEndian, 零 unsafe.Pointer)。

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// 1:fffe 局域网互传直通类常量: 2.5 Gbps = 312,500,000 Bytes/s, prio 0 最高抢占级
	v6LANFastlaneMinor     uint16 = 0xfffe
	v6LANFastlaneHandle    uint32 = uint32(0x0001fffe)
	v6LANFastlaneLeafMaj   uint32 = uint32(0xfffe0000)
	v6LANFastlaneRateBps   uint64 = 312_500_000 // 2.5 Gbps = 2,500,000,000 bit/s / 8
	v6LANFastlaneBurstB    uint32 = 512 * 1024  // 512 KiB 大桶深保障 Wi-Fi 7 MLO / USB NCM 聚合帧零排队抖动
	v6LANFastlaneQuantumB  uint32 = 60000
	v6LANFastlaneFilterPri uint16 = 2 // 先于设备限速 u32 (prio 100+) 命中, 不与根 fw (prio 1) 冲突
	v6LANFastlaneMarkVal   uint32 = uint32(0x00fe0000)

	// tun0 共存策略路由防环路优先级: 位于 Android VPN uidrange 规则(通常 pref 9000..13000)之前、local 规则之后
	v6Tun0BypassRulePrefBase int = 8960
	v6Tun0SafeClampMSS       int = 1360
)

// DownstreamRole 标识下游接口类型。
const (
	DownstreamRoleWiFiAP    = "wifi_ap"
	DownstreamRoleWiFi7MLO  = "wifi7_mlo"
	DownstreamRoleBridge    = "ap_bridge"
	DownstreamRoleUSBTether = "usb_tether"
	DownstreamRoleBTTether  = "bt_tether"
)

// V6IfaceProbeInput 表示单个网卡的内核状态快照(既可由 sysfs+net.Interfaces 实时采集, 也可由单元测试直接注入)。
type V6IfaceProbeInput struct {
	Name         string   `json:"name"`
	Ifindex      int      `json:"ifindex"`
	OperUp       bool     `json:"oper_up"`
	Carrier      bool     `json:"carrier"`
	MasterBridge string   `json:"master_bridge,omitempty"` // 若被桥接进 ap_br_wlan2 等桥口, 记录主桥名防双重限速
	PhyIndex     int      `json:"phy_index,omitempty"`     // ieee80211 phyN 编号(同 phy 多活跃 AP 口识别为双频并发/MLO)
	MTU          int      `json:"mtu,omitempty"`
	IPv4CIDRs    []string `json:"ipv4_cidrs,omitempty"`
	IPv6Global   []string `json:"ipv6_global,omitempty"`
	IsDefaultWAN bool     `json:"is_default_wan,omitempty"` // 若持有默认网关(如 wlan0 STA 上游), 严禁误判为热点下游口
}

// V6ManagedDownstream 表示经分类去重后纳入 HNC 并管的活跃下游接口。
type V6ManagedDownstream struct {
	Name         string   `json:"name"`
	Ifindex      int      `json:"ifindex"`
	Role         string   `json:"role"`
	SubnetsV4    []string `json:"subnets_v4"`
	GatewayIPv4  string   `json:"gateway_ipv4,omitempty"`
	MemberLinks  []string `json:"member_links,omitempty"` // ap_br_* 或 MLO 组下的成员口
	ShapeEnabled bool     `json:"shape_enabled"`          // 被桥接从属口为 false(在主桥统一整形), 独立三层口全部为 true
}

// V6Tun0GuardPlan 描述本机 tun0/wg0 VPN 与多口热点共存时的防环路与免篡改策略方案。
type V6Tun0GuardPlan struct {
	VPNActive         bool     `json:"vpn_active"`
	VPNIfaces         []string `json:"vpn_ifaces,omitempty"`
	PhysicalUpstreams []string `json:"physical_upstreams,omitempty"`
	MinVPNMTU         int      `json:"min_vpn_mtu,omitempty"`
	ProtectedSubnets  []string `json:"protected_subnets,omitempty"`
	IPRulesKnown      bool     `json:"ip_rules_known"`
	IPRulesReason     string   `json:"ip_rules_reason,omitempty"`
	LoopRiskDetected  bool     `json:"loop_risk_detected"`
	LoopRiskReasons   []string `json:"loop_risk_reasons,omitempty"`
	IPRuleSpecs       []string `json:"ip_rule_specs,omitempty"`
	MangleGuardRules  []string `json:"mangle_guard_rules,omitempty"`
	Low16MarkSafe     bool     `json:"low16_mark_safe"`
}

// V6MultiIfaceSnapshot 汇总多下游并管 + tun0 防环路 + 1:fffe 局域网直通状态。
type V6MultiIfaceSnapshot struct {
	UpdatedAt          int64                 `json:"updated_at"`
	PrimaryDownstream  string                `json:"primary_downstream"`
	ManagedDownstreams []V6ManagedDownstream `json:"managed_downstreams"`
	ShapeTargets       []string              `json:"shape_targets"`
	DualBandOrMLO      bool                  `json:"dual_band_or_mlo"`
	USBTetherActive    bool                  `json:"usb_tether_active"`
	LANFastlaneClass   string                `json:"lan_fastlane_class"`
	LANFastlaneGbps    float64               `json:"lan_fastlane_gbps"`
	Tun0Guard          V6Tun0GuardPlan       `json:"tun0_guard"`
}

// v6MultiIfaceEngine 维护多接口探测缓存与并发同步计数。
// 严格遵守 32 位 ARM 对齐铁律: 所有 64 位原子字段固定在结构体起始偏移 (offset 0)。
type v6MultiIfaceEngine struct {
	probeRuns        atomic.Uint64
	reconcileRuns    atomic.Uint64
	fastlaneInstalls atomic.Uint64
	tun0GuardChecks  atomic.Uint64

	mu                   sync.RWMutex
	lastSnap             V6MultiIfaceSnapshot
	tun0ApplyMu          sync.Mutex
	appliedTun0Subnets   map[string]int
	lastTun0MangleDigest string
	tun0MangleActive     bool
	tun0BootCleaned      bool
}

var globalV6MultiIface = &v6MultiIfaceEngine{}

func v6IsPrivateIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if len(v4) != 4 {
		return false
	}
	switch {
	case v4[0] == 10:
		return true
	case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
		return true
	case v4[0] == 192 && v4[1] == 168:
		return true
	case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // CGNAT / 部分定制 tether 网段
		return true
	}
	return false
}

func v6NormalizeSubnetV4(cidrStr string) (subnetStr, hostIPStr string, ipNet *net.IPNet, ok bool) {
	ip, nw, err := net.ParseCIDR(strings.TrimSpace(cidrStr))
	if err != nil || ip == nil || nw == nil {
		return "", "", nil, false
	}
	v4 := ip.To4()
	if len(v4) != 4 || !v6IsPrivateIPv4(v4) {
		return "", "", nil, false
	}
	ones, bits := nw.Mask.Size()
	if bits != 32 || ones < 8 || ones > 30 {
		return "", "", nil, false
	}
	masked := v4.Mask(nw.Mask)
	canonNet := &net.IPNet{IP: masked, Mask: nw.Mask}
	return canonNet.String(), v4.String(), canonNet, true
}

const (
	rtnlNewRoute     uint16 = 24     // RTM_NEWROUTE
	rtnlGetRoute     uint16 = 26     // RTM_GETROUTE
	rtnlRtMsgLen     int    = 12     // sizeof(struct rtmsg)
	rtnlRtnUnicast   uint8  = 1      // RTN_UNICAST
	rtnlRtmFCloned   uint32 = 0x0200 // RTM_F_CLONED
	rtnlRtaOif       uint16 = 4      // RTA_OIF (uint32 ifindex)
	rtnlRtaMultipath uint16 = 9      // RTA_MULTIPATH (struct rtnexthop[])
)

// buildGetRouteDumpMsg 构造纯 Go RTM_GETROUTE (NLM_F_REQUEST|NLM_F_DUMP) 全表路由扫描报文,
// 用于发现 Android per-network 策略路由表(如 table 1021/1022)中持有默认路由的 Dual-STA 副网卡(wlan1)。
func buildGetRouteDumpMsg(seq uint32, family uint8) []byte {
	total := rtnlMsgHdrLen + rtnlRtMsgLen
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
	binary.LittleEndian.PutUint16(buf[4:6], rtnlGetRoute)
	binary.LittleEndian.PutUint16(buf[6:8], uint16(rtnlFRequest|rtnlFDump))
	binary.LittleEndian.PutUint32(buf[8:12], seq)
	buf[16] = family
	return buf
}

// parseDefaultRouteIfindexesMsgs 纯字节流解析 RTM_NEWROUTE dump 报文,
// 精确提取全路由表中 rtm_dst_len == 0 且 rtm_type == RTN_UNICAST 的默认路由出接口 ifindex。
func parseDefaultRouteIfindexesMsgs(b []byte) (map[int]bool, bool, error) {
	return parseDefaultRouteIfindexesMsgsWithSeq(b, 0)
}

func parseDefaultRouteIfindexesMsgsWithSeq(b []byte, wantSeq uint32) (map[int]bool, bool, error) {
	out := make(map[int]bool)
	for off := 0; off < len(b); {
		rem := len(b) - off
		if rem < rtnlMsgHdrLen {
			return out, false, errors.New("rtnl route dump: truncated nlmsghdr")
		}
		msgLen := int(binary.LittleEndian.Uint32(b[off : off+4]))
		msgType := binary.LittleEndian.Uint16(b[off+4 : off+6])
		msgSeq := binary.LittleEndian.Uint32(b[off+8 : off+12])
		if msgLen < rtnlMsgHdrLen || msgLen > rem {
			return out, false, fmt.Errorf("rtnl route dump: bad nlmsg_len %d", msgLen)
		}
		msg := b[off : off+msgLen]
		adv := rtnlAlign(msgLen)
		if adv > rem {
			off = len(b)
		} else {
			off += adv
		}
		if wantSeq != 0 && msgSeq != wantSeq {
			continue
		}

		switch msgType {
		case rtnlMsgDone:
			return out, true, nil
		case rtnlMsgError:
			if len(msg) < rtnlMsgHdrLen+4 {
				return out, false, errors.New("rtnl route dump: truncated nlmsgerr")
			}
			code := int32(binary.LittleEndian.Uint32(msg[rtnlMsgHdrLen : rtnlMsgHdrLen+4]))
			if code != 0 {
				return out, false, fmt.Errorf("rtnl route dump errno %d", code)
			}
			continue
		case rtnlMsgNoop:
			continue
		}

		if msgType != rtnlNewRoute || len(msg) < rtnlMsgHdrLen+rtnlRtMsgLen {
			continue
		}
		rtm := msg[rtnlMsgHdrLen:]
		dstLen := rtm[1]
		rtmType := rtm[7]
		rtmFlags := binary.LittleEndian.Uint32(rtm[8:12])
		if dstLen != 0 || rtmType != rtnlRtnUnicast || (rtmFlags&rtnlRtmFCloned) != 0 {
			continue
		}

		attrs := rtm[rtnlRtMsgLen:]
		for aoff := 0; aoff < len(attrs); {
			arem := len(attrs) - aoff
			if arem < rtnlAttrHdr {
				break
			}
			alen := int(binary.LittleEndian.Uint16(attrs[aoff : aoff+2]))
			atype := binary.LittleEndian.Uint16(attrs[aoff+2:aoff+4]) & 0x3fff
			if alen < rtnlAttrHdr || alen > arem {
				break
			}
			aval := attrs[aoff+4 : aoff+alen]
			switch atype {
			case rtnlRtaOif:
				if len(aval) >= 4 {
					if oif := int(int32(binary.LittleEndian.Uint32(aval[0:4]))); oif > 0 {
						out[oif] = true
					}
				}
			case rtnlRtaMultipath:
				for moff := 0; moff+8 <= len(aval); {
					nhLen := int(binary.LittleEndian.Uint16(aval[moff : moff+2]))
					if nhLen < 8 || moff+nhLen > len(aval) {
						break
					}
					if nhIfidx := int(int32(binary.LittleEndian.Uint32(aval[moff+4 : moff+8]))); nhIfidx > 0 {
						out[nhIfidx] = true
					}
					moff += rtnlAlign(nhLen)
				}
			}
			nadv := rtnlAlign(alen)
			if nadv > arem {
				break
			}
			aoff += nadv
		}
	}
	return out, false, nil
}

func v6ReadDefaultWANIfacesFromProcRoute(content string) map[string]bool {
	out := make(map[string]bool)
	for idx, ln := range strings.Split(content, "\n") {
		if idx == 0 {
			continue
		}
		fs := strings.Fields(ln)
		if len(fs) >= 8 && fs[1] == "00000000" && fs[7] == "00000000" {
			name := strings.TrimSpace(fs[0])
			if name != "" && !isVPNIface(name) {
				out[name] = true
				if phys := strings.TrimPrefix(name, "v4-"); phys != "" && !isVPNIface(phys) {
					out[phys] = true
				}
			}
		}
	}
	return out
}

// v6ReadIfaceDetectDefaultWANs 从 run/iface_detect.json 读取上游口及新增的 default_route_ifaces,
// 确保 Dual-STA 双 Wi-Fi 加速场景下持有独立策略路由表默认路由的副 STA (如 wlan1) 被精准标为默认 WAN。
func v6ReadIfaceDetectDefaultWANs(hncDir string) (map[string]bool, string) {
	out := make(map[string]bool)
	hncDir = strings.TrimSpace(hncDir)
	if hncDir == "" {
		return out, ""
	}
	b, err := os.ReadFile(filepath.Join(hncDir, "run", "iface_detect.json"))
	if err != nil || len(b) == 0 {
		return out, ""
	}
	var raw map[string]any
	if json.Unmarshal(b, &raw) != nil {
		return out, ""
	}
	detIface, _ := raw["iface"].(string)
	detIface = strings.TrimSpace(detIface)
	if !ifaceNameOK(detIface) {
		detIface = ""
	}
	authHotspot, _ := raw["authoritative"].(bool)

	addWAN := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || !ifaceNameOK(s) || isVPNIface(s) {
			return
		}
		if authHotspot && detIface != "" && s == detIface {
			return
		}
		out[s] = true
		if phys := strings.TrimPrefix(s, "v4-"); phys != "" && phys != s && !isVPNIface(phys) {
			if !(authHotspot && detIface != "" && phys == detIface) {
				out[phys] = true
			}
		}
	}

	for _, key := range []string{"upstream", "tether_upstream", "local_upstream"} {
		if v, ok := raw[key].(string); ok {
			addWAN(v)
		}
	}
	switch dr := raw["default_route_ifaces"].(type) {
	case []any:
		for _, item := range dr {
			if s, ok := item.(string); ok {
				addWAN(s)
			}
		}
	case string:
		for _, tok := range strings.FieldsFunc(dr, func(r rune) bool {
			return r == ' ' || r == ',' || r == '\t' || r == '\n'
		}) {
			addWAN(tok)
		}
	}
	if authHotspot {
		return out, detIface
	}
	return out, ""
}

var (
	v6DumpDefaultRouteIfindexesFn = dumpDefaultRouteIfindexesOS
	v6LiveInterfacesFn            = net.Interfaces
)

// CollectLiveIfaceProbeInputs 从本机 sysfs + net.Interfaces() + /proc/net/route + RTM_GETROUTE 全表 + iface_detect.json 采集实时接口状态。
func CollectLiveIfaceProbeInputs(hncDir string) []V6IfaceProbeInput {
	defaultWAN := map[string]bool{}
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		defaultWAN = v6ReadDefaultWANIfacesFromProcRoute(string(b))
	}
	authHotspotIface := ""
	if hncDir != "" {
		detWANs, authIfc := v6ReadIfaceDetectDefaultWANs(hncDir)
		authHotspotIface = authIfc
		for k := range detWANs {
			defaultWAN[k] = true
		}
	}
	var nlDefIfindexes map[int]bool
	if v6DumpDefaultRouteIfindexesFn != nil {
		if m, err := v6DumpDefaultRouteIfindexesFn(); err == nil {
			nlDefIfindexes = m
		}
	}

	ifs, err := v6LiveInterfacesFn()
	if err != nil {
		return nil
	}
	// 先将 RTM_GETROUTE 扫到的全表默认路由接口(含 v4-wlan1 对应的底层物理 wlan1)合并至 defaultWAN
	for _, ifi := range ifs {
		name := strings.TrimSpace(ifi.Name)
		if name == "" || name == "lo" || isVPNIface(name) {
			continue
		}
		if nlDefIfindexes[ifi.Index] {
			if !(authHotspotIface != "" && name == authHotspotIface) {
				defaultWAN[name] = true
			}
			if phys := strings.TrimPrefix(name, "v4-"); phys != "" && phys != name && !isVPNIface(phys) {
				if !(authHotspotIface != "" && phys == authHotspotIface) {
					defaultWAN[phys] = true
				}
			}
		}
	}

	out := make([]V6IfaceProbeInput, 0, len(ifs))
	for _, ifi := range ifs {
		name := strings.TrimSpace(ifi.Name)
		if name == "" || name == "lo" || !ifaceNameRE.MatchString(name) {
			continue
		}
		operUp := (ifi.Flags & net.FlagUp) != 0
		if b, rErr := os.ReadFile("/sys/class/net/" + name + "/operstate"); rErr == nil {
			st := strings.ToLower(strings.TrimSpace(string(b)))
			if st == "down" {
				operUp = false
			} else if st == "up" || st == "unknown" {
				operUp = (ifi.Flags & net.FlagUp) != 0
			}
		}
		carrier := operUp
		if b, cErr := os.ReadFile("/sys/class/net/" + name + "/carrier"); cErr == nil {
			carrier = strings.TrimSpace(string(b)) == "1"
		}
		masterBridge := ""
		if linkDst, lErr := os.Readlink("/sys/class/net/" + name + "/master"); lErr == nil {
			base := filepath.Base(linkDst)
			if ifaceNameRE.MatchString(base) {
				masterBridge = base
			}
		}
		phyIdx := -1
		if phyDst, pErr := os.Readlink("/sys/class/net/" + name + "/phy80211"); pErr == nil {
			base := filepath.Base(phyDst)
			if strings.HasPrefix(base, "phy") {
				if n, aErr := strconv.Atoi(strings.TrimPrefix(base, "phy")); aErr == nil {
					phyIdx = n
				}
			}
		}

		var v4CIDRs, v6Global []string
		if addrs, aErr := ifi.Addrs(); aErr == nil {
			for _, a := range addrs {
				s := a.String()
				ip, _, pErr := net.ParseCIDR(s)
				if pErr != nil || ip == nil {
					continue
				}
				if ip.To4() != nil {
					v4CIDRs = append(v4CIDRs, s)
				} else if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast() && !ip.IsUnspecified() {
					v6Global = append(v6Global, ip.String())
				}
			}
		}
		out = append(out, V6IfaceProbeInput{
			Name:         name,
			Ifindex:      ifi.Index,
			OperUp:       operUp,
			Carrier:      carrier,
			MasterBridge: masterBridge,
			PhyIndex:     phyIdx,
			MTU:          ifi.MTU,
			IPv4CIDRs:    v4CIDRs,
			IPv6Global:   v6Global,
			IsDefaultWAN: defaultWAN[name],
		})
	}
	return out
}

// AnalyzeMultiInterfaces 纯函数分析接口拓扑:
//  1. 自动发现 Wi-Fi 7 MLO / 双频并发热点 (wlan1+wlan2+ap0+ap_br_*) 与 USB/蓝牙共享 (rndis0/ncm0/usb0/bt-pan);
//  2. 自动识别桥接从属关系(若 wlan1+wlan2 挂在 ap_br_wlan 下, 仅对主桥整形防止双重限速; 若各自独立持私网段则双口并管整形);
//  3. 生成本机 tun0/wg0 VPN 共存策略路由防环路方案。
func AnalyzeMultiInterfaces(inputs []V6IfaceProbeInput, preferredPrimary string, existingIPRules []string) V6MultiIfaceSnapshot {
	globalV6MultiIface.probeRuns.Add(1)

	bridgeMembers := make(map[string][]string)
	for _, in := range inputs {
		if in.MasterBridge != "" && in.OperUp {
			bridgeMembers[in.MasterBridge] = append(bridgeMembers[in.MasterBridge], in.Name)
		}
	}
	for k := range bridgeMembers {
		sort.Strings(bridgeMembers[k])
	}

	var managed []V6ManagedDownstream
	var vpnIfaces []string
	var physUpstreams []string
	minVPNMTU := 0
	wifiAPCount := 0

	for _, in := range inputs {
		name := strings.TrimSpace(in.Name)
		if name == "" || !in.OperUp {
			continue
		}

		// 1. 识别活跃 VPN 虚拟口 (tun0 / wg0 / ppp0 等)
		if isVPNIface(name) {
			vpnIfaces = append(vpnIfaces, name)
			if in.MTU > 0 && (minVPNMTU == 0 || in.MTU < minVPNMTU) {
				minVPNMTU = in.MTU
			}
			continue
		}

		// 2. 识别蜂窝或 STA 默认上游口 (rmnet_data* / ccmni* / 持默认路由的主 STA wlan0 及 Dual-STA 副 STA wlan1)
		if isCellIface(name) || (in.IsDefaultWAN && !isAPIfaceName(name)) {
			if len(in.IPv4CIDRs) > 0 || len(in.IPv6Global) > 0 || in.IsDefaultWAN {
				physUpstreams = append(physUpstreams, name)
			}
			continue
		}

		// 3. 解析下游私有 IPv4 子网
		var subnets []string
		var gwIP string
		seenSub := map[string]bool{}
		for _, cidr := range in.IPv4CIDRs {
			sub, hostIP, _, ok := v6NormalizeSubnetV4(cidr)
			if !ok {
				continue
			}
			if gwIP == "" {
				gwIP = hostIP
			}
			if !seenSub[sub] {
				seenSub[sub] = true
				subnets = append(subnets, sub)
			}
		}
		sort.Strings(subnets)

		role := ""
		switch {
		case strings.HasPrefix(name, "ap_br_") && isAPIfaceName(name):
			role = DownstreamRoleBridge
		case isAPIfaceName(name):
			role = DownstreamRoleWiFiAP
		case hncAPMaybeIfaceRE.MatchString(name):
			// wlan1 / wlan2 / wigig0: 排除默认 WAN(含 Dual-STA 副 STA)后, 只要持有私网地址或已挂入 AP 桥即确认为并发 AP 口
			if !in.IsDefaultWAN && (len(subnets) > 0 || in.MasterBridge != "") {
				role = DownstreamRoleWiFiAP
			}
		case hncUSBTetherRE.MatchString(name):
			if len(subnets) > 0 || in.MasterBridge != "" {
				role = DownstreamRoleUSBTether
			}
		case hncBTTetherRE.MatchString(name):
			if len(subnets) > 0 || in.MasterBridge != "" {
				role = DownstreamRoleBTTether
			}
		}
		if role == "" {
			continue
		}

		// 若从属于某个活跃桥口(如 ap_br_wlan2), 该成员口标记 ShapeEnabled=false, 由主桥口统一执行 HTB 整形
		enslaved := in.MasterBridge != ""
		if enslaved && len(subnets) == 0 {
			// 纯二层桥成员记录在主桥 MemberLinks 中即可, 不单独出现在三层整形列表
			continue
		}

		if role == DownstreamRoleWiFiAP || role == DownstreamRoleBridge {
			wifiAPCount++
		}
		members := append([]string(nil), bridgeMembers[name]...)
		if len(members) >= 2 && role == DownstreamRoleBridge {
			role = DownstreamRoleWiFi7MLO
		}

		managed = append(managed, V6ManagedDownstream{
			Name:         name,
			Ifindex:      in.Ifindex,
			Role:         role,
			SubnetsV4:    subnets,
			GatewayIPv4:  gwIP,
			MemberLinks:  members,
			ShapeEnabled: !enslaved,
		})
	}

	// 若同时存在 >= 2 个独立 Wi-Fi AP 口(如 2.4GHz wlan1 + 5G/6GHz wlan2 并发或双 MLD AP), 升级标记为 wifi7_mlo
	dualOrMLO := wifiAPCount >= 2
	usbActive := false
	for i := range managed {
		if managed[i].Role == DownstreamRoleWiFi7MLO && len(managed[i].MemberLinks) >= 2 {
			dualOrMLO = true
		} else if dualOrMLO && managed[i].Role == DownstreamRoleWiFiAP {
			managed[i].Role = DownstreamRoleWiFi7MLO
		}
		if managed[i].Role == DownstreamRoleUSBTether {
			usbActive = true
		}
	}

	// 稳定排序: 首选口优先 -> Wi-Fi AP/MLO -> USB 共享 -> 蓝牙共享 -> 字典序
	roleRank := func(d V6ManagedDownstream) int {
		if preferredPrimary != "" && d.Name == preferredPrimary {
			return 0
		}
		switch d.Role {
		case DownstreamRoleBridge, DownstreamRoleWiFi7MLO, DownstreamRoleWiFiAP:
			return 1
		case DownstreamRoleUSBTether:
			return 2
		default:
			return 3
		}
	}
	sort.Slice(managed, func(i, j int) bool {
		ri, rj := roleRank(managed[i]), roleRank(managed[j])
		if ri != rj {
			return ri < rj
		}
		return managed[i].Name < managed[j].Name
	})

	var shapeTargets []string
	var allSubnets []string
	seenSubAll := map[string]bool{}
	for _, m := range managed {
		if m.ShapeEnabled {
			shapeTargets = append(shapeTargets, m.Name)
		}
		for _, sub := range m.SubnetsV4 {
			if !seenSubAll[sub] {
				seenSubAll[sub] = true
				allSubnets = append(allSubnets, sub)
			}
		}
	}
	sort.Strings(vpnIfaces)
	sort.Strings(physUpstreams)

	primary := ""
	if len(shapeTargets) > 0 {
		primary = shapeTargets[0]
	} else if preferredPrimary != "" {
		primary = preferredPrimary
	}

	tunPlan := BuildTun0AntiLoopPlan(vpnIfaces, physUpstreams, minVPNMTU, managed, allSubnets, existingIPRules)

	snap := V6MultiIfaceSnapshot{
		UpdatedAt:          time.Now().Unix(),
		PrimaryDownstream:  primary,
		ManagedDownstreams: managed,
		ShapeTargets:       shapeTargets,
		DualBandOrMLO:      dualOrMLO,
		USBTetherActive:    usbActive,
		LANFastlaneClass:   "1:fffe",
		LANFastlaneGbps:    2.5,
		Tun0Guard:          tunPlan,
	}

	globalV6MultiIface.mu.Lock()
	globalV6MultiIface.lastSnap = snap
	globalV6MultiIface.mu.Unlock()
	return snap
}

// BuildTun0AntiLoopPlan 构建本机 tun0 VPN 与多下游热点共存的策略路由防环路方案。
func BuildTun0AntiLoopPlan(
	vpnIfaces, physUpstreams []string,
	minVPNMTU int,
	downstreams []V6ManagedDownstream,
	subnets []string,
	existingIPRules []string,
) V6Tun0GuardPlan {
	return buildTun0AntiLoopPlanDetail(vpnIfaces, physUpstreams, minVPNMTU, downstreams, subnets, existingIPRules, existingIPRules != nil, "")
}

func buildTun0AntiLoopPlanDetail(
	vpnIfaces, physUpstreams []string,
	minVPNMTU int,
	downstreams []V6ManagedDownstream,
	subnets []string,
	existingIPRules []string,
	rulesKnown bool,
	rulesReason string,
) V6Tun0GuardPlan {
	globalV6MultiIface.tun0GuardChecks.Add(1)
	if !rulesKnown && rulesReason == "" && existingIPRules == nil {
		rulesReason = "ip_rule_unverified"
	}
	plan := V6Tun0GuardPlan{
		VPNActive:         len(vpnIfaces) > 0,
		VPNIfaces:         append([]string(nil), vpnIfaces...),
		PhysicalUpstreams: append([]string(nil), physUpstreams...),
		MinVPNMTU:         minVPNMTU,
		ProtectedSubnets:  append([]string(nil), subnets...),
		IPRulesKnown:      rulesKnown,
		IPRulesReason:     rulesReason,
		// HNC 全栈严格只写 [31:16] 0xffff0000, 低 16 位 [15:0] 100% 留给 Android netd / Clash / WireGuard 绕行标记!
		Low16MarkSafe: true,
	}
	if !plan.VPNActive || len(downstreams) == 0 {
		return plan
	}

	if !rulesKnown {
		plan.LoopRiskDetected = true
		plan.LoopRiskReasons = append(plan.LoopRiskReasons,
			fmt.Sprintf("VPN 接口(%s)在线但无法读取系统 ip rule 策略路由表（%s），无法确认热点网段前置直连绕行是否就绪", strings.Join(vpnIfaces, ","), plan.IPRulesReason))
	}

	joinedRules := strings.Join(existingIPRules, "\n")
	pref := v6Tun0BypassRulePrefBase
	for _, sub := range subnets {
		hasBypass := strings.Contains(joinedRules, "to "+sub+" lookup main") ||
			strings.Contains(joinedRules, "to "+sub+" lookup local_network")
		if rulesKnown && !hasBypass {
			plan.LoopRiskDetected = true
			plan.LoopRiskReasons = append(plan.LoopRiskReasons,
				fmt.Sprintf("VPN 接口(%s)在线但 ip rule 缺少目的网段 %s 的前置直连绕行规则，回包易误入 tun0 形成路由环路", strings.Join(vpnIfaces, ","), sub))
		}
		plan.IPRuleSpecs = append(plan.IPRuleSpecs,
			fmt.Sprintf("ip -4 rule add pref %d to %s lookup main", pref, sub))
		pref++
	}

	clampMSS := v6Tun0SafeClampMSS
	if minVPNMTU >= 1280 && minVPNMTU-40 < clampMSS {
		clampMSS = minVPNMTU - 40
	}
	if minVPNMTU > 0 && minVPNMTU < 1500 {
		plan.LoopRiskReasons = append(plan.LoopRiskReasons,
			fmt.Sprintf("检测到 VPN 虚拟口 MTU=%d (<1500)，已生成双向 TCPMSS clamp-mss-to-pmtu (安全上限 %d) 防大包黑洞", minVPNMTU, clampMSS))
	}

	for _, ds := range downstreams {
		if !ds.ShapeEnabled {
			continue
		}
		for _, vpn := range vpnIfaces {
			plan.MangleGuardRules = append(plan.MangleGuardRules,
				fmt.Sprintf("-A HNC_TUN_GUARD -i %s -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", ds.Name, vpn),
				fmt.Sprintf("-A HNC_TUN_GUARD -i %s -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", vpn, ds.Name),
			)
		}
		// 严防下游接口发往本机网关自身的包被策略路由重投进 tun0
		if ds.GatewayIPv4 != "" {
			plan.MangleGuardRules = append(plan.MangleGuardRules,
				fmt.Sprintf("-A HNC_TUN_GUARD -i %s -d %s/32 -j ACCEPT", ds.Name, ds.GatewayIPv4))
		}
	}
	return plan
}

var v6ReadLiveIPRulesFn = readLiveIPRulesOS

func readLiveIPRulesOS() (rules []string, reasonCode string, ok bool) {
	ipBin := resolveDataplaneSystemBin("ip")
	if ipBin == "" {
		return nil, "ip_binary_missing", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, ipBin, "-4", "rule", "show"))
	cmd.Env = subprocEnvWithFallbackPath()
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 120 {
			msg = msg[:120]
		}
		return nil, "ip_rule_exec_failed: " + msg, false
	}
	var lines []string
	for _, rawLn := range strings.Split(string(out), "\n") {
		if ln := strings.TrimSpace(rawLn); ln != "" {
			lines = append(lines, ln)
		}
	}
	if len(lines) == 0 {
		return nil, "ip_rule_empty", false
	}
	return lines, "", true
}

func analyzeMultiInterfacesWithLiveRules(inputs []V6IfaceProbeInput, preferredPrimary string) V6MultiIfaceSnapshot {
	snap, _ := analyzeMultiInterfacesWithLiveRulesDetail(inputs, preferredPrimary)
	return snap
}

func analyzeMultiInterfacesWithLiveRulesDetail(inputs []V6IfaceProbeInput, preferredPrimary string) (V6MultiIfaceSnapshot, []string) {
	var (
		rules       []string
		rulesKnown  bool
		rulesReason string
	)
	if v6ReadLiveIPRulesFn != nil {
		rules, rulesReason, rulesKnown = v6ReadLiveIPRulesFn()
	} else {
		rulesReason = "ip_rule_reader_disabled"
	}
	snap := AnalyzeMultiInterfaces(inputs, preferredPrimary, rules)
	snap.Tun0Guard = buildTun0AntiLoopPlanDetail(
		snap.Tun0Guard.VPNIfaces,
		snap.Tun0Guard.PhysicalUpstreams,
		snap.Tun0Guard.MinVPNMTU,
		snap.ManagedDownstreams,
		snap.Tun0Guard.ProtectedSubnets,
		rules,
		rulesKnown,
		rulesReason,
	)
	globalV6MultiIface.mu.Lock()
	globalV6MultiIface.lastSnap = snap
	globalV6MultiIface.mu.Unlock()
	return snap, rules
}

// ── 1:fffe 局域网互传 2.5Gbps 免限速直通类 Netlink 报文编码器 ──────────────

func v6IPv4BytesToWireLE32(b4 []byte) uint32 {
	return uint32(b4[0]) | (uint32(b4[1]) << 8) | (uint32(b4[2]) << 16) | (uint32(b4[3]) << 24)
}

// buildU32LANPairFilterMsg 构造匹配 (IPv4 src ∈ srcNet && IPv4 dst ∈ dstNet) 的双键 u32 过滤器报文,
// 命中后直接送入 1:fffe (2.5Gbps 局域网互传免限速直通类), 公网下载流量因 src 不在私网段而自然落入设备限速类!
func buildU32LANPairFilterMsg(seq uint32, ifindex int, parent uint32, prio uint16, srcCIDR, dstCIDR string, classID uint32) ([]byte, error) {
	_, srcNet, err1 := net.ParseCIDR(strings.TrimSpace(srcCIDR))
	_, dstNet, err2 := net.ParseCIDR(strings.TrimSpace(dstCIDR))
	if err1 != nil || err2 != nil || srcNet == nil || dstNet == nil {
		return nil, fmt.Errorf("invalid LAN CIDR pair (%q, %q)", srcCIDR, dstCIDR)
	}
	sIP := srcNet.IP.To4()
	dIP := dstNet.IP.To4()
	if len(sIP) != 4 || len(dIP) != 4 || len(srcNet.Mask) != 4 || len(dstNet.Mask) != 4 {
		return nil, fmt.Errorf("non-IPv4 LAN CIDR pair (%q, %q)", srcCIDR, dstCIDR)
	}

	// struct tc_u32_sel (16B) + 2 * struct tc_u32_key (32B) = 48B
	var sel [rtnlU32SelHdrSize + 2*rtnlU32KeySize]byte
	sel[0] = rtnlTcU32Terminal // flags = TC_U32_TERMINAL
	sel[2] = 2                 // nkeys = 2

	sMaskLE := v6IPv4BytesToWireLE32(srcNet.Mask)
	sValLE := v6IPv4BytesToWireLE32(sIP) & sMaskLE
	binary.LittleEndian.PutUint32(sel[16:20], sMaskLE)
	binary.LittleEndian.PutUint32(sel[20:24], sValLE)
	binary.LittleEndian.PutUint32(sel[24:28], uint32(rtnlIPv4SrcOff))
	binary.LittleEndian.PutUint32(sel[28:32], 0)

	dMaskLE := v6IPv4BytesToWireLE32(dstNet.Mask)
	dValLE := v6IPv4BytesToWireLE32(dIP) & dMaskLE
	binary.LittleEndian.PutUint32(sel[32:36], dMaskLE)
	binary.LittleEndian.PutUint32(sel[36:40], dValLE)
	binary.LittleEndian.PutUint32(sel[40:44], uint32(rtnlIPv4DstOff))
	binary.LittleEndian.PutUint32(sel[44:48], 0)

	var opts, attrs []byte
	opts = rtnlPutAttrU32(opts, rtnlTcaU32ClassID, classID)
	opts = rtnlPutAttr(opts, rtnlTcaU32Sel, sel[:])
	attrs = rtnlPutAttrString(attrs, rtnlTcaKind, "u32")
	attrs = rtnlPutAttr(attrs, rtnlTcaOptions, opts)

	info := (uint32(prio) << 16) | uint32(rtnlHtons(rtnlEthPIP))
	flags := uint16(rtnlFRequest | rtnlFAck | rtnlFCreate)
	return rtnlBuildTCMsg(rtnlNewTFilter, flags, seq, ifindex, 0, parent, info, attrs), nil
}

// BuildLANFastlaneNetlinkBatch 为指定下游网卡编码完整的 1:fffe 2.5Gbps 局域网直通类 Netlink 消息批次:
//  1. RTM_NEWTCLASS: parent 1:1 -> classid 1:fffe, RATE64=CEIL64=312,500,000 B/s (2.5Gbps), prio=0;
//  2. RTM_NEWQDISC:  parent 1:fffe -> handle fffe: fq_codel 低延迟叶子队列;
//  3. RTM_NEWTFILTER(fw): prio 1 handle 0x00fe0000/0x00ff0000 -> flowid 1:fffe (支持显式局域网标记直通);
//  4. RTM_DELTFILTER + RTM_NEWTFILTER(u32): prio 2 两两匹配全部活跃热点/USB 下游子网互传流量 -> flowid 1:fffe。
func BuildLANFastlaneNetlinkBatch(ifindex int, lanSubnets []string, tickInUsec float64) ([][]byte, error) {
	if ifindex <= 0 {
		return nil, fmt.Errorf("BuildLANFastlaneNetlinkBatch: invalid ifindex %d", ifindex)
	}
	if tickInUsec <= 0 {
		tickInUsec = pschedDefaultTickUsec
	}

	var msgs [][]byte

	// 1. 1:fffe 2.5Gbps 直通类
	clsMsg := buildHTBClassUpsertMsg(
		rtnlNextSeq(), ifindex,
		rtnlHtbRootCls, v6LANFastlaneHandle,
		v6LANFastlaneRateBps, v6LANFastlaneRateBps,
		v6LANFastlaneBurstB, v6LANFastlaneBurstB,
		v6LANFastlaneQuantumB, 0, tickInUsec,
	)
	msgs = append(msgs, clsMsg)

	// 2. fq_codel 叶子队列 (handle fffe:)
	leafMsg := buildFqCodelLeafMsg(rtnlNextSeq(), ifindex, v6LANFastlaneHandle, v6LANFastlaneLeafMaj, true)
	msgs = append(msgs, leafMsg)

	// 3. 正交 fw 直通标记过滤器 (0x00fe0000/0x00ff0000 -> 1:fffe)
	fwMsg := buildFwFilterMsg(
		rtnlNextSeq(), ifindex, rtnlHtbRootMaj,
		rtnlFilterPrioFW, rtnlEthPAll,
		v6LANFastlaneMarkVal, DefaultDevMarkMask, v6LANFastlaneHandle,
	)
	msgs = append(msgs, fwMsg)

	// 4. 先清理旧 prio 2 IPv4 互传过滤器段, 再为所有下游子网对(含同口内互传与 wlan2<->rndis0 跨口互传)建立双键 u32 直通规则
	cleanSubnets := make([]string, 0, len(lanSubnets))
	seen := map[string]bool{}
	for _, s := range lanSubnets {
		if norm, _, _, ok := v6NormalizeSubnetV4(s); ok && !seen[norm] {
			seen[norm] = true
			cleanSubnets = append(cleanSubnets, norm)
		}
	}
	sort.Strings(cleanSubnets)
	if len(cleanSubnets) > 0 {
		msgs = append(msgs, buildDelFilterMsg(rtnlNextSeq(), ifindex, rtnlHtbRootMaj, 0, v6LANFastlaneFilterPri, rtnlEthPIP, ""))
		for _, srcSub := range cleanSubnets {
			for _, dstSub := range cleanSubnets {
				u32Msg, err := buildU32LANPairFilterMsg(
					rtnlNextSeq(), ifindex, rtnlHtbRootMaj,
					v6LANFastlaneFilterPri, srcSub, dstSub, v6LANFastlaneHandle,
				)
				if err != nil {
					return nil, err
				}
				msgs = append(msgs, u32Msg)
			}
		}
	}

	return msgs, nil
}

func applyLANFastlaneBatchOnSocket(fd int, ifindex int, msgs [][]byte) error {
	if _, err := nlSendBatchWithCompatFallback(fd, msgs, true); err != nil {
		return fmt.Errorf("install 1:fffe class on ifindex=%d: %w", ifindex, err)
	}
	return nil
}

// EnsureLANFastlaneOnIface 通过原生 AF_NETLINK 在指定网卡上幂等安装 1:fffe 2.5Gbps 局域网直通类
// (支持老内核 4.14/4.19 ETH_P_ALL -> ETH_P_IP + ETH_P_IPV6 双栈回退及 fq_codel -> fq -> sfq -> pfifo 自适应叶子降级)。
func EnsureLANFastlaneOnIface(ifindex int, lanSubnets []string) error {
	if ifindex <= 0 {
		return fmt.Errorf("EnsureLANFastlaneOnIface: invalid ifindex %d", ifindex)
	}
	if err := nlEnsureHTBRoot(ifindex, rtnlDefMinor, DefaultHTBRootRateBps); err != nil {
		return err
	}
	fd, err := openRTNetlinkSocket()
	if err != nil {
		return err
	}
	defer closeRTNetlinkSocket(fd)

	msgs, err := BuildLANFastlaneNetlinkBatch(ifindex, lanSubnets, readPschedTickInUsec())
	if err != nil {
		return err
	}
	if err := applyLANFastlaneBatchOnSocket(fd, ifindex, msgs); err != nil {
		return err
	}
	globalV6MultiIface.fastlaneInstalls.Add(1)
	return nil
}

const (
	v6Tun0BypassRulePrefMax = v6Tun0BypassRulePrefBase + 15 // [8960..8975] 专属 HNC tun0 私网直连绕行槽位
	v6Tun0GuardChainName    = "HNC_TUN_GUARD"
)

var (
	v6CollectProbeInputsFn = CollectLiveIfaceProbeInputs
	v6ExecTun0IPCmdFn      = execTun0IPCmdOS
	v6ExecTun0IptRestoreFn = execTun0IptRestoreOS
	v6ExecTun0IptCmdFn     = execTun0IptCmdOS
	v6Tun0ForceDataplane   bool
)

func execTun0IPCmdOS(args ...string) (string, error) {
	ipBin := resolveDataplaneSystemBin("ip")
	if ipBin == "" {
		return "", errors.New("ip binary not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, ipBin, args...))
	cmd.Env = subprocEnvWithFallbackPath()
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func execTun0IptRestoreOS(payload []byte) error {
	restoreBin := v6ResolveRestoreBinFn("iptables-restore")
	if restoreBin == "" {
		return errors.New("iptables-restore binary not found")
	}
	return pipeIptablesRestoreWithTimeout(restoreBin, payload, iptRestoreTimeout)
}

func execTun0IptCmdOS(args ...string) (string, error) {
	iptBin := v6ResolveRestoreBinFn("iptables")
	if iptBin == "" {
		return "", errors.New("iptables binary not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := hardenCmd(exec.CommandContext(ctx, iptBin, args...))
	cmd.Env = subprocEnvWithFallbackPath()
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

type tun0ManagedRuleEntry struct {
	pref   int
	subnet string
}

// parseManagedTun0BypassRules 仅提取落在 [8960..8975] 优先级区间、不触碰 fwmark/uidrange、
// 且指向热点私有 IPv4 网段 lookup main 的 HNC 托管绕行规则。
func parseManagedTun0BypassRules(lines []string) []tun0ManagedRuleEntry {
	var out []tun0ManagedRuleEntry
	for _, raw := range lines {
		ln := strings.TrimSpace(raw)
		if ln == "" || strings.Contains(ln, "fwmark") || strings.Contains(ln, "uidrange") {
			continue
		}
		colon := strings.IndexByte(ln, ':')
		if colon <= 0 {
			continue
		}
		pref, err := strconv.Atoi(strings.TrimSpace(ln[:colon]))
		if err != nil || pref < v6Tun0BypassRulePrefBase || pref > v6Tun0BypassRulePrefMax {
			continue
		}
		rest := strings.Fields(ln[colon+1:])
		var toSpec string
		hasLookupMain := false
		for i := 0; i < len(rest); i++ {
			if rest[i] == "to" && i+1 < len(rest) {
				toSpec = rest[i+1]
				i++
			} else if (rest[i] == "lookup" || rest[i] == "table") && i+1 < len(rest) && rest[i+1] == "main" {
				hasLookupMain = true
				i++
			}
		}
		if !hasLookupMain || toSpec == "" {
			continue
		}
		if normSub, _, _, ok := v6NormalizeSubnetV4(toSpec); ok {
			out = append(out, tun0ManagedRuleEntry{pref: pref, subnet: normSub})
		}
	}
	return out
}

func liveIPRulesContainTun0Bypass(lines []string, pref int, subnet string) bool {
	prefPrefix := strconv.Itoa(pref) + ":"
	wantMain := "to " + subnet + " lookup main"
	wantTableMain := "to " + subnet + " table main"
	wantLocalNet := "to " + subnet + " lookup local_network"
	for _, raw := range lines {
		ln := strings.TrimSpace(raw)
		if strings.Contains(ln, wantLocalNet) {
			return true
		}
		if strings.HasPrefix(ln, prefPrefix) && (strings.Contains(ln, wantMain) || strings.Contains(ln, wantTableMain)) {
			return true
		}
	}
	return false
}

// syncTun0GuardDataplane 在 globalV6MultiIface.mu 锁外幂等同步/清理本机 tun0 防环路策略路由与 HNC_TUN_GUARD 钳制链。
// 严格保护低 16 位 skb->mark (0x0000ffff) 零触碰，且所有子进程通过 subprocEnvWithFallbackPath 继承完整 Android BOOTCLASSPATH。
func syncTun0GuardDataplane(plan *V6Tun0GuardPlan, existingRules []string) error {
	globalV6MultiIface.tun0ApplyMu.Lock()
	defer globalV6MultiIface.tun0ApplyMu.Unlock()

	if globalV6MultiIface.appliedTun0Subnets == nil {
		globalV6MultiIface.appliedTun0Subnets = make(map[string]int)
	}
	if plan != nil {
		plan.Low16MarkSafe = true
	}

	liveManaged := parseManagedTun0BypassRules(existingRules)
	wantActive := plan != nil && plan.VPNActive && len(plan.ProtectedSubnets) > 0 &&
		(len(plan.IPRuleSpecs) > 0 || len(plan.MangleGuardRules) > 0)

	if !wantActive {
		delSeen := make(map[string]bool)
		delRule := func(pref int, sub string) {
			if pref < v6Tun0BypassRulePrefBase || pref > v6Tun0BypassRulePrefMax || sub == "" {
				return
			}
			k := strconv.Itoa(pref) + "|" + sub
			if delSeen[k] {
				return
			}
			delSeen[k] = true
			if v6ExecTun0IPCmdFn != nil {
				_, _ = v6ExecTun0IPCmdFn("-4", "rule", "del", "pref", strconv.Itoa(pref), "to", sub, "lookup", "main")
			}
		}
		for sub, pref := range globalV6MultiIface.appliedTun0Subnets {
			delRule(pref, sub)
		}
		for _, lm := range liveManaged {
			delRule(lm.pref, lm.subnet)
		}
		clear(globalV6MultiIface.appliedTun0Subnets)

		if (globalV6MultiIface.tun0MangleActive || !globalV6MultiIface.tun0BootCleaned) && v6ExecTun0IptCmdFn != nil {
			if _, lErr := v6ExecTun0IptCmdFn("-t", "mangle", "-L", v6Tun0GuardChainName, "-n"); lErr == nil {
				for range 4 {
					if _, dErr := v6ExecTun0IptCmdFn("-t", "mangle", "-D", "FORWARD", "-j", v6Tun0GuardChainName); dErr != nil {
						break
					}
				}
				for range 4 {
					if _, dErr := v6ExecTun0IptCmdFn("-t", "mangle", "-D", "PREROUTING", "-j", v6Tun0GuardChainName); dErr != nil {
						break
					}
				}
				_, _ = v6ExecTun0IptCmdFn("-t", "mangle", "-F", v6Tun0GuardChainName)
				_, _ = v6ExecTun0IptCmdFn("-t", "mangle", "-X", v6Tun0GuardChainName)
			}
			globalV6MultiIface.tun0MangleActive = false
			globalV6MultiIface.lastTun0MangleDigest = ""
			globalV6MultiIface.tun0BootCleaned = true
		}
		return nil
	}

	// 1. 构建当前活跃下游私有网段的目标 pref 映射 [8960..8975]
	wantPrefBySub := make(map[string]int, len(plan.ProtectedSubnets))
	orderedSubs := make([]string, 0, len(plan.ProtectedSubnets))
	for i, rawSub := range plan.ProtectedSubnets {
		normSub, _, _, ok := v6NormalizeSubnetV4(rawSub)
		if !ok {
			continue
		}
		pref := v6Tun0BypassRulePrefBase + i
		if pref > v6Tun0BypassRulePrefMax {
			break
		}
		if _, exists := wantPrefBySub[normSub]; !exists {
			wantPrefBySub[normSub] = pref
			orderedSubs = append(orderedSubs, normSub)
		}
	}

	// 2. 先清理已下线网段或槽位漂移的旧 ip rule
	delStaleSeen := make(map[string]bool)
	delStale := func(pref int, sub string) {
		k := strconv.Itoa(pref) + "|" + sub
		if delStaleSeen[k] {
			return
		}
		delStaleSeen[k] = true
		if v6ExecTun0IPCmdFn != nil {
			_, _ = v6ExecTun0IPCmdFn("-4", "rule", "del", "pref", strconv.Itoa(pref), "to", sub, "lookup", "main")
		}
	}
	for sub, oldPref := range globalV6MultiIface.appliedTun0Subnets {
		if wantPref, ok := wantPrefBySub[sub]; !ok || wantPref != oldPref {
			delStale(oldPref, sub)
			delete(globalV6MultiIface.appliedTun0Subnets, sub)
		}
	}
	for _, lm := range liveManaged {
		if wantPref, ok := wantPrefBySub[lm.subnet]; !ok || wantPref != lm.pref {
			delStale(lm.pref, lm.subnet)
		}
	}

	// 3. 幂等补齐缺失的热点私有网段前置直连绕行规则
	var applyErrs []string
	allRulesReady := true
	for _, sub := range orderedSubs {
		pref := wantPrefBySub[sub]
		if liveIPRulesContainTun0Bypass(existingRules, pref, sub) {
			globalV6MultiIface.appliedTun0Subnets[sub] = pref
			continue
		}
		if v6ExecTun0IPCmdFn != nil {
			out, err := v6ExecTun0IPCmdFn("-4", "rule", "add", "pref", strconv.Itoa(pref), "to", sub, "lookup", "main")
			if err != nil && !strings.Contains(strings.ToLower(out), "file exists") {
				allRulesReady = false
				applyErrs = append(applyErrs, fmt.Sprintf("ip rule add %s: %v", sub, err))
				continue
			}
			globalV6MultiIface.appliedTun0Subnets[sub] = pref
		}
	}
	if allRulesReady && len(orderedSubs) > 0 {
		plan.LoopRiskDetected = false
	}

	// 4. 幂等原子加载 *mangle HNC_TUN_GUARD (TCPMSS clamp + 网关自身直通保护, 绝不改写 0x0000ffff mark)
	for _, r := range plan.MangleGuardRules {
		if strings.Contains(strings.ToLower(r), "0x0000ffff") || strings.Contains(strings.ToLower(r), "--set-mark") {
			return errors.New("forbidden low-16-bit mark mutation in HNC_TUN_GUARD")
		}
	}
	snippet := BuildTun0GuardRestoreSnippet(*plan)
	digest := string(snippet)
	if (!globalV6MultiIface.tun0MangleActive || globalV6MultiIface.lastTun0MangleDigest != digest) && v6ExecTun0IptRestoreFn != nil {
		if err := v6ExecTun0IptRestoreFn(snippet); err != nil {
			applyErrs = append(applyErrs, fmt.Sprintf("iptables-restore HNC_TUN_GUARD: %v", err))
		} else {
			if v6ExecTun0IptCmdFn != nil {
				if _, cErr := v6ExecTun0IptCmdFn("-t", "mangle", "-C", "FORWARD", "-j", v6Tun0GuardChainName); cErr != nil {
					if _, iErr := v6ExecTun0IptCmdFn("-t", "mangle", "-I", "FORWARD", "1", "-j", v6Tun0GuardChainName); iErr != nil {
						_, _ = v6ExecTun0IptCmdFn("-t", "mangle", "-A", "FORWARD", "-j", v6Tun0GuardChainName)
					}
				}
				if _, cErr := v6ExecTun0IptCmdFn("-t", "mangle", "-C", "PREROUTING", "-j", v6Tun0GuardChainName); cErr != nil {
					if _, iErr := v6ExecTun0IptCmdFn("-t", "mangle", "-I", "PREROUTING", "1", "-j", v6Tun0GuardChainName); iErr != nil {
						_, _ = v6ExecTun0IptCmdFn("-t", "mangle", "-A", "PREROUTING", "-j", v6Tun0GuardChainName)
					}
				}
			}
			globalV6MultiIface.lastTun0MangleDigest = digest
			globalV6MultiIface.tun0MangleActive = true
			globalV6MultiIface.tun0BootCleaned = true
		}
	}

	if len(applyErrs) > 0 {
		return errors.New(strings.Join(applyErrs, "; "))
	}
	return nil
}

// ReconcileMultiDownstreamV6 自动探测全部活跃下游接口(wlan1+wlan2+ap0+rndis0/ncm0),
// 同步本机 tun0 防环路策略路由与 HNC_TUN_GUARD 链, 并在每个需要整形的三层下游口上幂等确保 HTB 根树与 1:fffe 2.5Gbps 局域网互传直通类就绪。
func (s *server) ReconcileMultiDownstreamV6() (V6MultiIfaceSnapshot, error) {
	globalV6MultiIface.reconcileRuns.Add(1)
	preferred := ""
	if s != nil {
		preferred = s.currentHotspotIface()
	}
	hncDir := ""
	if s != nil {
		hncDir = s.hncDir
	}
	inputs := v6CollectProbeInputsFn(hncDir)
	snap, liveRules := analyzeMultiInterfacesWithLiveRulesDetail(inputs, preferred)
	if !useNativeDataplane(hncDir) && !v6Tun0ForceDataplane {
		return snap, nil
	}

	var errs []string
	if err := syncTun0GuardDataplane(&snap.Tun0Guard, liveRules); err != nil {
		errs = append(errs, "tun0_guard: "+err.Error())
	}
	globalV6MultiIface.mu.Lock()
	globalV6MultiIface.lastSnap = snap
	globalV6MultiIface.mu.Unlock()

	if len(snap.ManagedDownstreams) == 0 {
		if len(errs) > 0 {
			return snap, fmt.Errorf("multi-iface reconcile partial errors: %s", strings.Join(errs, "; "))
		}
		return snap, nil
	}

	var allSubnets []string
	for _, ds := range snap.ManagedDownstreams {
		allSubnets = append(allSubnets, ds.SubnetsV4...)
	}

	for _, ds := range snap.ManagedDownstreams {
		if !ds.ShapeEnabled || ds.Ifindex <= 0 {
			continue
		}
		if err := EnsureLANFastlaneOnIface(ds.Ifindex, allSubnets); err != nil {
			errs = append(errs, ds.Name+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return snap, fmt.Errorf("multi-iface reconcile partial errors: %s", strings.Join(errs, "; "))
	}
	return snap, nil
}

// BuildTun0GuardRestoreSnippet 生成供 iptables-restore --noflush 增量提交的 HNC_TUN_GUARD 链载荷。
func BuildTun0GuardRestoreSnippet(plan V6Tun0GuardPlan) []byte {
	var buf bytes.Buffer
	buf.WriteString("*mangle\n:HNC_TUN_GUARD - [0:0]\n")
	for _, rule := range plan.MangleGuardRules {
		buf.WriteString(rule)
		buf.WriteByte('\n')
	}
	buf.WriteString("COMMIT\n")
	return buf.Bytes()
}

func (s *server) apiV6MultiIface(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "GET only"})
		return
	}
	preferred := s.currentHotspotIface()
	snap := analyzeMultiInterfacesWithLiveRules(CollectLiveIfaceProbeInputs(s.hncDir), preferred)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"snapshot": snap,
		"counters": map[string]uint64{
			"probe_runs":        globalV6MultiIface.probeRuns.Load(),
			"reconcile_runs":    globalV6MultiIface.reconcileRuns.Load(),
			"fastlane_installs": globalV6MultiIface.fastlaneInstalls.Load(),
			"tun0_guard_checks": globalV6MultiIface.tun0GuardChecks.Load(),
		},
	})
}
