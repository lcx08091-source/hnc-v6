// traffic_ident.go — v5.21 识别准确度: 客户端 VPN/代理检测 + 隧道归属 + 共现推断
//
// 全部在 app_usage.go 每 10 秒一轮的连接表差分上做(同一把 appUsage.mu, 无额外 I/O)。
//
// ── 1. VPN / 代理检测(每台设备, 最近 identVPNWindow = 5 分钟)──────────────────
// 协议特征(签名流, 本身就是隧道):
//
//	udp 51820 WireGuard · udp/tcp 1194 OpenVPN · udp 500/4500 IPsec IKE/NAT-T ·
//	udp 1701 L2TP · tcp 1723 / gre PPTP · udp 2408 Cloudflare WARP ·
//	ESP/AH 等 conntrack 记作 "unknown" 的 L4 协议 · 目的域名属于 VPN 服务商 ·
//	规则库把目的归到 vpn/proxy 类
//
// 启发式(可疑流): 目的既无域名也归不上应用, 且是 非标准端口 TCP / 无域名 TLS(443) /
// 无域名 QUIC(udp 443, 疑 Hysteria/TUIC) / 其它 UDP(疑自定义端口 WireGuard)。
// 判定(窗口内总字节 < 256 KB 不判):
//
//	certain: 签名流字节占比 ≥ 50%
//	likely:  签名流占比 ≥ 20%; 或 单个可疑目的 IP 占比 ≥ 70% 且 窗口 ≥ 2 MB 且
//	         该目的已持续 ≥ 2 分钟 且 其余有量(≥ 64 KB)的目的 ≤ 3 个
//	         (VPN 开着时设备几乎所有流量都进隧道, 别的目的很少; 正常刷视频、
//	         打游戏会同时连很多 CDN / 推送 / 统计)
//
// 结果发布在 /api/devices 每台设备的 vpn 字段:
//
//	{"level":"none|likely|certain","reason":"...","share":0.93,"bytes":N,"dst":"x.x.x.x","window_sec":300}
//
// ── 2. 隧道归属 ────────────────────────────────────────────────────────────
// 签名流 → 始终记到伪应用 _tunnel(「VPN/代理隧道」, category "tunnel");
// 启发式判为 likely 的那个目的 IP 上本来要记「未识别」的字节 → 也记 _tunnel。
// _tunnel 不计入应用使用时长(app_time.go appTimeStep 跳过)。
//
// ── 3. 共现推断(未识别 → 推测应用)────────────────────────────────────────
// 目的 IP 没有反查名、也不在 ip_app_map 的连接, 若同一台设备在它建立前后 ±5 秒
// 内新建了某个「真应用」(tierApp) 的连接, 且这段时间里只有这一个应用在建连
// (或它的建连数 ≥ 2 且至少是第二名的 2 倍), 就推测是这个应用(App 用写死 IP
// 的 HTTPDNS / 直连服务器时很常见)。建连时间: conntrack NEW 事件(ct_new_events.go,
// 精确到秒内); 没订阅上时退回「这一轮快照里新出现」(10 秒粒度), 此时更保守:
// 必须同一轮只有这一个应用且它新建了 ≥ 2 条连接。
// 推测结果按 (设备, 目的 IP) 缓存 10 分钟(有流量就顺延); 该 IP 之后若有了域名/
// 规则命中, 以规则为准。推测的字节照常记到应用上, 另在日文件 inferred 里单独累计
// ("mac|app" → [up, down]), /api/app_usage 每个应用带 inferred_bytes, 界面可标「推测」。
// 为了能看到建连之后 5 秒内的其它连接, 新出现的无名连接字节会暂缓一轮(10 秒)再记账。

package main

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tunnelAppID    = "_tunnel"
	tunnelAppName  = "VPN/代理隧道"
	tunnelCategory = "tunnel"

	identVPNWindow        = 5 * time.Minute
	identVPNMinJudgeBytes = 256 << 10
	identVPNHeurMinBytes  = 2 << 20
	identVPNCertainShare  = 0.5
	identVPNSigLikely     = 0.2
	identVPNHeurShare     = 0.7
	identVPNHeurMinAge    = 2 * time.Minute
	identVPNOtherBytes    = 64 << 10
	identVPNMaxOthers     = 3

	identCoocWindow     = 5 * time.Second
	identInferTTL       = 10 * time.Minute
	identStartKeep      = 30 * time.Second
	identMaxPending     = 4096
	identMaxFlows       = 1 << 16
	identMaxInferCache  = 8192
	identMaxStartsPerMA = 256
)

var tunnelMeta = appUsageMeta{Name: tunnelAppName, Category: tunnelCategory}

// VPN / 代理服务商域名(后缀匹配)。只放「服务商自己的」域名, 不放通用云。
var vpnProviderSuffixes = []string{
	"nordvpn.com", "nordvpn.net", "expressvpn.com", "expressapisv2.net", "surfshark.com",
	"protonvpn.com", "protonvpn.net", "vpn-api.proton.me", "mullvad.net", "windscribe.com",
	"privateinternetaccess.com", "ipvanish.com", "hotspotshield.com", "tunnelbear.com",
	"cyberghostvpn.com", "astrill.com", "getlantern.org", "psiphon.ca", "psiphon3.com",
	"hide.me", "purevpn.com", "vyprvpn.com", "strongvpn.com", "zenmate.com",
	"engage.cloudflareclient.com", "zero-trust-client.cloudflareclient.com", "warp.plus",
}

func vpnProviderName(name string) bool {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	for _, s := range vpnProviderSuffixes {
		if n == s || strings.HasSuffix(n, "."+s) {
			return true
		}
	}
	return false
}

// ctKeyParts 从 ctEntry.key() 格式("proto|src|sport|dst|dport")取协议与目的端口
func ctKeyParts(key string) (proto string, dport int, ok bool) {
	p := strings.Split(key, "|")
	if len(p) != 5 {
		return "", 0, false
	}
	d, err := strconv.Atoi(p[4])
	if err != nil {
		return "", 0, false
	}
	return p[0], d, true
}

// tunnelSignature 协议/端口/名字特征 → 原因(""= 不是签名流)
func tunnelSignature(proto string, dport int, name string, app ipApp, hasApp bool) string {
	switch proto {
	case "udp":
		switch dport {
		case 51820:
			return "WireGuard(udp 51820)"
		case 1194:
			return "OpenVPN(udp 1194)"
		case 500, 4500:
			return "IPsec IKE/NAT-T(udp " + strconv.Itoa(dport) + ")"
		case 1701:
			return "L2TP(udp 1701)"
		case 2408:
			return "Cloudflare WARP(udp 2408)"
		}
	case "tcp":
		switch dport {
		case 1194:
			return "OpenVPN(tcp 1194)"
		case 1723:
			return "PPTP(tcp 1723)"
		}
	case "gre":
		return "GRE/PPTP 隧道"
	case "esp", "ah", "unknown":
		return "IPsec ESP 等隧道协议"
	}
	if hasApp {
		switch strings.ToLower(app.Category) {
		case "vpn", "proxy", "tunnel":
			n := app.Name
			if n == "" {
				n = app.ID
			}
			return "VPN 应用(" + n + ")"
		}
	}
	if name != "" && vpnProviderName(name) {
		return "VPN 服务商(" + baseDomain(name) + ")"
	}
	return ""
}

// 这些端口上的无名 TCP 是常见正常业务(推送/邮件/DNS), 不算可疑
var identStdTCPPorts = map[int]bool{80: true, 5228: true, 5223: true, 993: true, 995: true, 465: true,
	587: true, 25: true, 143: true, 110: true, 853: true, 53: true}
var identStdUDPPorts = map[int]bool{53: true, 123: true, 5353: true, 1900: true, 67: true, 68: true,
	137: true, 138: true, 853: true, 3478: true, 19302: true}

// tunnelSuspect 启发式可疑流 → 原因(""= 不可疑)。调用方保证不是签名流、目的非局域网。
func tunnelSuspect(proto string, dport int, name string, hasApp bool) string {
	if hasApp {
		return ""
	}
	switch proto {
	case "tcp":
		if dport == 443 {
			if name == "" {
				return "无域名的 TLS 长连接"
			}
			return ""
		}
		if identStdTCPPorts[dport] {
			return ""
		}
		return "非标准端口 TCP/TLS(" + strconv.Itoa(dport) + ")"
	case "udp":
		if identStdUDPPorts[dport] {
			return ""
		}
		if dport == 443 {
			if name == "" {
				return "无域名的 QUIC(疑 Hysteria/TUIC)"
			}
			return ""
		}
		if name == "" {
			return "UDP 隧道(疑 WireGuard/Hysteria, 端口 " + strconv.Itoa(dport) + ")"
		}
	}
	return ""
}

// ─── 状态 ─────────────────────────────────────────────────────────────

type identStart struct {
	at      time.Time
	precise bool
	app     ipApp
}

type identPending struct {
	mac, dst string
	start    time.Time
	precise  bool
	held     []appUsageDelta
}

type identInfer struct {
	app ipApp
	exp time.Time
}

type vpnTickAgg struct {
	at       time.Time
	total    uint64
	sig      map[string]uint64 // 原因 → 字节
	dstBytes map[string]uint64 // 非局域网目的 → 字节
}

type vpnDevState struct {
	ticks     []vpnTickAgg
	dstFirst  map[string]time.Time
	dstLast   map[string]time.Time
	dstReason map[string]string // 可疑目的 → 启发式原因
}

type vpnVerdict struct {
	Level     string  `json:"level"` // none | likely | certain
	Reason    string  `json:"reason,omitempty"`
	Share     float64 `json:"share"`
	Bytes     uint64  `json:"bytes"`
	Dst       string  `json:"dst,omitempty"`
	WindowSec int     `json:"window_sec"`
}

type identState struct {
	seen     map[string]time.Time    // 连接 key → 最近一次有字节(isNew 为 nil 时判新用)
	starts   map[string][]identStart // mac → 最近的「真应用」建连
	pending  map[string]*identPending
	infer    map[string]identInfer // "mac|dst" → 推测
	vpn      map[string]*vpnDevState
	verdicts map[string]vpnVerdict
	tunDst   map[string]string // mac → 启发式判定的隧道对端 IP
}

func newIdentState() *identState {
	return &identState{
		seen: map[string]time.Time{}, starts: map[string][]identStart{}, pending: map[string]*identPending{},
		infer: map[string]identInfer{}, vpn: map[string]*vpnDevState{}, verdicts: map[string]vpnVerdict{},
		tunDst: map[string]string{},
	}
}

var identSt = newIdentState() // 受 appUsage.mu 保护

// 发布给 /api/devices 的判定(独立小锁, 请求路径不碰 appUsage.mu)
var identPub struct {
	mu sync.Mutex
	v  map[string]vpnVerdict
}

func identVPNVerdicts() map[string]vpnVerdict {
	identPub.mu.Lock()
	defer identPub.mu.Unlock()
	out := make(map[string]vpnVerdict, len(identPub.v))
	for k, v := range identPub.v {
		out[k] = v
	}
	return out
}

func identReset() {
	identSt = newIdentState()
	identPub.mu.Lock()
	identPub.v = nil
	identPub.mu.Unlock()
}

// identCtx 一轮记账需要的上下文
type identCtx struct {
	st       *identState
	now      time.Time
	owner    map[string]string
	apps     map[string]ipApp
	names    map[string]ipName
	sigKey   map[string]bool // 本轮判为签名流的连接 key
	released []appUsageDelta
	fp       *fpStore // v6.x DPI v2: 指纹/用户纠正归属(fp_learn.go); nil = 不用
}

func isLocalDst(dst string, owner map[string]string) bool {
	return dst != "" && (isPrivateIP(dst) || owner[dst] != "")
}

// observe 更新 VPN 窗口与建连记录, 并裁决共现窗口已合上的暂缓连接。
//
//	newStarts: conntrack NEW 事件给的精确建连时间(key → 时间), 可为 nil
//	isNew:     这条连接是不是本轮新出现的(上一轮快照里没有); nil = 按本状态自己见过的 key 判断
func (st *identState) observe(now time.Time, deltas []appUsageDelta, newStarts map[string]time.Time,
	isNew func(key string) bool, owner map[string]string, apps map[string]ipApp, names map[string]ipName) *identCtx {
	cx := &identCtx{st: st, now: now, owner: owner, apps: apps, names: names, sigKey: map[string]bool{}}
	// (a) 精确建连事件: 真应用的建连就是共现证据(即使本轮还没字节, 如只发了 SYN)
	for key, at := range newStarts {
		p := strings.Split(key, "|")
		if len(p) != 5 {
			continue
		}
		mac := owner[p[1]]
		if mac == "" || isLocalDst(p[3], owner) {
			continue
		}
		if a, ok := appForIP(p[3], apps, names); ok && appTier(a.Category) == tierApp {
			st.addStart(mac, identStart{at: at, precise: true, app: a})
		}
	}
	// (b) 本轮差分
	for _, dl := range deltas {
		mac := owner[dl.Src]
		if mac == "" || isLocalDst(dl.Dst, owner) {
			continue
		}
		proto, dport, _ := ctKeyParts(dl.Key)
		nm := names[dl.Dst].Name
		a, hasApp := appForIP(dl.Dst, apps, names)
		sig := tunnelSignature(proto, dport, nm, a, hasApp)
		bytes := dl.Up + dl.Dn
		// VPN 窗口
		vs := st.vpn[mac]
		if vs == nil {
			vs = &vpnDevState{dstFirst: map[string]time.Time{}, dstLast: map[string]time.Time{}, dstReason: map[string]string{}}
			st.vpn[mac] = vs
		}
		if n := len(vs.ticks); n == 0 || !vs.ticks[n-1].at.Equal(now) {
			vs.ticks = append(vs.ticks, vpnTickAgg{at: now, sig: map[string]uint64{}, dstBytes: map[string]uint64{}})
		}
		t := &vs.ticks[len(vs.ticks)-1]
		t.total += bytes
		t.dstBytes[dl.Dst] += bytes
		if _, ok := vs.dstFirst[dl.Dst]; !ok {
			vs.dstFirst[dl.Dst] = now
		}
		vs.dstLast[dl.Dst] = now
		if sig != "" {
			t.sig[sig] += bytes
			if dl.Key != "" {
				cx.sigKey[dl.Key] = true
			}
		} else if r := tunnelSuspect(proto, dport, nm, hasApp); r != "" {
			vs.dstReason[dl.Dst] = r
		} else {
			delete(vs.dstReason, dl.Dst)
		}
		// 建连
		if dl.Key == "" {
			continue
		}
		var fresh bool
		if isNew != nil {
			fresh = isNew(dl.Key)
		} else {
			_, seen := st.seen[dl.Key]
			fresh = !seen
		}
		if _, ok := st.seen[dl.Key]; ok || len(st.seen) < identMaxFlows {
			st.seen[dl.Key] = now
		}
		if !fresh || sig != "" {
			continue
		}
		at, precise := newStarts[dl.Key]
		if !precise {
			at = now
		}
		if hasApp {
			if !precise && appTier(a.Category) == tierApp {
				st.addStart(mac, identStart{at: at, precise: false, app: a})
			}
			continue
		}
		if nm == "" && st.pending[dl.Key] == nil && len(st.pending) < identMaxPending {
			st.pending[dl.Key] = &identPending{mac: mac, dst: dl.Dst, start: at, precise: precise}
		}
	}
	// (c) VPN 判定
	st.judgeAll(now)
	// (d) 共现窗口已合上(建连后 ≥ 5 秒; 轮询粒度的「本轮新出现」要等到下一轮)的
	//     暂缓连接: 裁决, 放行它们攒下的字节(本轮照常记账, 推测缓存已就位)
	keys := make([]string, 0, len(st.pending))
	for k := range st.pending {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		p := st.pending[key]
		if now.Sub(p.start) < identCoocWindow {
			continue
		}
		st.decide(p, now)
		cx.released = append(cx.released, p.held...)
		delete(st.pending, key)
	}
	st.prune(now)
	return cx
}

func (st *identState) addStart(mac string, s identStart) {
	l := append(st.starts[mac], s)
	if len(l) > identMaxStartsPerMA {
		l = l[len(l)-identMaxStartsPerMA:]
	}
	st.starts[mac] = l
}

// coocCandidate 共现裁决(纯函数, 单测直接喂)。
// start/precise: 未识别连接的建连时间; starts: 该设备的真应用建连记录。
// tickSpan: 非精确模式下「同一轮」的判定宽度。
func coocCandidate(start time.Time, precise bool, starts []identStart, tickSpan time.Duration) (ipApp, bool) {
	type agg struct {
		app ipApp
		n   int
	}
	by := map[string]*agg{}
	allPrecise := precise
	for _, s := range starts {
		win := identCoocWindow
		if !precise || !s.precise {
			win = tickSpan / 2 // 两边至少一个只有轮询时间: 只认同一轮
		}
		d := s.at.Sub(start)
		if d < 0 {
			d = -d
		}
		if d > win {
			continue
		}
		if !s.precise {
			allPrecise = false
		}
		a := by[s.app.ID]
		if a == nil {
			a = &agg{app: s.app}
			by[s.app.ID] = a
		}
		a.n++
	}
	if len(by) == 0 {
		return ipApp{}, false
	}
	list := make([]*agg, 0, len(by))
	for _, a := range by {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].app.ID < list[j].app.ID
	})
	top := list[0]
	if !allPrecise {
		// 轮询粒度: 必须唯一且 ≥ 2 条建连
		if len(list) == 1 && top.n >= 2 {
			return top.app, true
		}
		return ipApp{}, false
	}
	if len(list) == 1 {
		return top.app, true
	}
	if top.n >= 2 && top.n >= 2*list[1].n {
		return top.app, true
	}
	return ipApp{}, false
}

func (st *identState) decide(p *identPending, now time.Time) {
	k := p.mac + "|" + p.dst
	if _, ok := st.infer[k]; ok {
		return
	}
	if a, ok := coocCandidate(p.start, p.precise, st.starts[p.mac], appUsageEvery); ok {
		if len(st.infer) >= identMaxInferCache {
			return
		}
		st.infer[k] = identInfer{app: a, exp: now.Add(identInferTTL)}
	}
}

// lookupInfer 推测缓存(命中顺延)
func (st *identState) lookupInfer(mac, dst string, now time.Time) (ipApp, bool) {
	k := mac + "|" + dst
	v, ok := st.infer[k]
	if !ok {
		return ipApp{}, false
	}
	if now.After(v.exp) {
		delete(st.infer, k)
		return ipApp{}, false
	}
	v.exp = now.Add(identInferTTL)
	st.infer[k] = v
	return v.app, true
}

func (st *identState) judgeAll(now time.Time) {
	for mac, vs := range st.vpn {
		v, dst := vpnJudge(vs, now)
		if v.Level == "none" && v.Bytes == 0 && len(vs.ticks) == 0 {
			delete(st.vpn, mac)
			delete(st.verdicts, mac)
			delete(st.tunDst, mac)
			continue
		}
		st.verdicts[mac] = v
		if dst != "" {
			st.tunDst[mac] = dst
		} else {
			delete(st.tunDst, mac)
		}
	}
	pub := make(map[string]vpnVerdict, len(st.verdicts))
	for k, v := range st.verdicts {
		pub[k] = v
	}
	identPub.mu.Lock()
	identPub.v = pub
	identPub.mu.Unlock()
}

// vpnJudge 按窗口判定(会裁掉窗口外的 tick)。返回判定与「启发式隧道对端」(签名判定时为空)。
func vpnJudge(vs *vpnDevState, now time.Time) (vpnVerdict, string) {
	cut := now.Add(-identVPNWindow)
	i := 0
	for i < len(vs.ticks) && !vs.ticks[i].at.After(cut) {
		i++
	}
	vs.ticks = vs.ticks[i:]
	for d, t := range vs.dstLast {
		if !t.After(cut) {
			delete(vs.dstLast, d)
			delete(vs.dstFirst, d)
			delete(vs.dstReason, d)
		}
	}
	v := vpnVerdict{Level: "none", WindowSec: int(identVPNWindow / time.Second)}
	var total uint64
	sig := map[string]uint64{}
	dst := map[string]uint64{}
	for _, t := range vs.ticks {
		total += t.total
		for r, b := range t.sig {
			sig[r] += b
		}
		for d, b := range t.dstBytes {
			dst[d] += b
		}
	}
	v.Bytes = total
	if total < identVPNMinJudgeBytes {
		return v, ""
	}
	var sigTotal, sigTop uint64
	sigReason := ""
	for r, b := range sig {
		sigTotal += b
		if b > sigTop || (b == sigTop && r < sigReason) {
			sigTop, sigReason = b, r
		}
	}
	sigShare := float64(sigTotal) / float64(total)
	if sigShare >= identVPNCertainShare {
		v.Level, v.Reason, v.Share = "certain", sigReason, round2(sigShare)
		return v, ""
	}
	// 启发式: 最大的可疑目的
	var topB uint64
	topD := ""
	for d, b := range dst {
		if vs.dstReason[d] == "" {
			continue
		}
		if b > topB || (b == topB && d < topD) {
			topB, topD = b, d
		}
	}
	if topD != "" && total >= identVPNHeurMinBytes {
		share := float64(topB) / float64(total)
		others := 0
		for d, b := range dst {
			if d != topD && b >= identVPNOtherBytes {
				others++
			}
		}
		age := now.Sub(vs.dstFirst[topD])
		if share >= identVPNHeurShare && age >= identVPNHeurMinAge && others <= identVPNMaxOthers {
			v.Level, v.Share, v.Dst = "likely", round2(share), topD
			v.Reason = vs.dstReason[topD] + ", 单一目的承载 " + strconv.Itoa(int(math.Round(share*100))) + "% 流量"
			return v, topD
		}
	}
	if sigShare >= identVPNSigLikely {
		v.Level, v.Reason, v.Share = "likely", sigReason, round2(sigShare)
	}
	return v, ""
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func (st *identState) prune(now time.Time) {
	idle := now.Add(-identVPNWindow)
	for k, t := range st.seen {
		if t.Before(idle) {
			delete(st.seen, k)
		}
	}
	keep := now.Add(-identStartKeep)
	for mac, l := range st.starts {
		i := 0
		for i < len(l) && l[i].at.Before(keep) {
			i++
		}
		if i == len(l) {
			delete(st.starts, mac)
		} else {
			st.starts[mac] = l[i:]
		}
	}
	for k, v := range st.infer {
		if now.After(v.exp) {
			delete(st.infer, k)
		}
	}
	for k, p := range st.pending {
		if now.Sub(p.start) > 3*appUsageEvery { // 兜底: 不该发生
			delete(st.pending, k)
		}
	}
}

// hold 本轮这条差分是否暂缓(它的连接还在等共现窗口合上)
func (cx *identCtx) hold(dl appUsageDelta) bool {
	if cx == nil || dl.Key == "" {
		return false
	}
	p := cx.st.pending[dl.Key]
	if p == nil {
		return false
	}
	p.held = append(p.held, dl)
	return true
}

// classify 一条差分的应用归属: (id, meta, inferred)。本地流量由调用方先处理。
func (cx *identCtx) classify(dl appUsageDelta, mac string) (string, appUsageMeta, bool, bool) {
	if cx == nil {
		return "", appUsageMeta{}, false, false
	}
	if dl.Key != "" && cx.sigKey[dl.Key] {
		return tunnelAppID, tunnelMeta, false, true
	}
	if _, ok := appForIP(dl.Dst, cx.apps, cx.names); ok {
		return "", appUsageMeta{}, false, false // 交给常规归属
	}
	if d := cx.st.tunDst[mac]; d != "" && d == dl.Dst {
		return tunnelAppID, tunnelMeta, false, true
	}
	if cx.names[dl.Dst].Name == "" {
		if a, ok := cx.st.lookupInfer(mac, dl.Dst, cx.now); ok {
			return a.ID, appUsageMeta{Name: a.Name, Category: a.Category}, true, true
		}
	}
	return "", appUsageMeta{}, false, false
}
