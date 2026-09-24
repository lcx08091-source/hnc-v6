// Package output - devid.go: v5.13 被动设备识别器(DeviceIdentifier)。
//
// 输入信号(强 → 弱):
//   - DHCP opt60 vendor class / mDNS TXT model=            强(权重 10)
//   - DHCP opt55 参数列表指纹 / 主机名模式 / SSDP UA 等     中(权重 4~6)
//   - DNS / SNI 域名特征(captive.apple.com、miui.com ...)  弱(权重 3)
//   - JA4 指纹库映射到的客户端名(iOS Safari 等)           很弱(权重 2)
//
// 汇总: 每个 MAC 的 os / os_ver / brand / model / type 各自按"证据键去重后的
// 权重和 + 多来源一致加分"投票; confidence 由 os/brand/type 三个字段的领先
// 幅度换算(0-99)。主机名不投票, 按来源优先级 dhcp > dhcpv6 > mdns > nbns 取。
//
// 规则全部写成数据表(devOpt60Rules / devOpt55Table / devHostnameRules /
// devModelRules / devServiceRules / devUARules / devDomainTable), 扩展时只
// 加表项。DHCP 只在设备接入瞬间出现, 所以识别结果持久化到 dpi_devid.json,
// 启动时读回(坏文件忽略)。
//
// 并发: 自带锁 d.mu, 与 Writer.mu 无嵌套依赖(Writer 在释放 w.mu 之后才调用
// 本识别器)。

package output

import (
	"container/list"
	"encoding/json"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultDevIDPath = "/data/local/hnc/run/dpi_devid.json"

	devIDMaxDevices  = 256
	devIDMaxEvidence = 8
	devIDMaxVoteKeys = 16
	devIDMaxServices = 8
	// last_seen 前进超过该秒数才算"变化"(避免每条 DNS 都触发重写)。
	devIDSeenDirtySec = 60

	devWStrong = 10
	devWMedium = 6
	devWWeak   = 3
	devWJA4    = 2
)

// DeviceHint 是 capture.DevHint 在 output 包内的镜像(output 不能反向依赖
// capture), 由 main.go 转换后传入。
type DeviceHint struct {
	MAC         string
	Source      string
	Hostname    string
	VendorClass string
	ParamList   string
	Model       string
	OSHint      string
	UserAgent   string
	Services    []string
}

// DevEvidence 是 dpi_devid.json 里的一条证据。
type DevEvidence struct {
	Src    string `json:"src"`
	Detail string `json:"detail"`
	Ts     int64  `json:"ts"`
}

// DeviceInfo 是 dpi_devid.json 里一台设备的汇总结果。
type DeviceInfo struct {
	Hostname    string        `json:"hostname"`
	HostnameSrc string        `json:"hostname_src"`
	OS          string        `json:"os"`
	OSVer       string        `json:"os_ver"`
	Brand       string        `json:"brand"`
	Model       string        `json:"model"`
	Type        string        `json:"type"`
	Confidence  int           `json:"confidence"`
	VendorClass string        `json:"vendor_class"`
	DHCPFP      string        `json:"dhcp_fp"`
	Services    []string      `json:"services"`
	LastSeen    int64         `json:"last_seen"`
	Evidence    []DevEvidence `json:"evidence"`
}

type devIDFile struct {
	Schema      int                   `json:"schema"`
	GeneratedAt int64                 `json:"generated_at"`
	Devices     map[string]DeviceInfo `json:"devices"`
}

// ─── 投票模型 ──────────────────────────────────────────────────────────

type devField int

const (
	fOS devField = iota
	fOSVer
	fBrand
	fModel
	fType
	nDevFields
)

// devSignal 是一条规则命中后产出的判断, 空字段表示不表态。
type devSignal struct {
	OS, OSVer, Brand, Model, Type string
	Weight                        int
	TypeWeight                    int // 0 = 同 Weight; 类型推断通常比 OS 推断弱
}

type devVote struct {
	keys map[string]int  // 证据键 → 权重(同一证据重复出现只算一次)
	srcs map[string]bool // 不同来源(dhcp/mdns/dns/...)一致时加分
	last int64
}

func (v *devVote) score() int {
	s := 0
	for _, w := range v.keys {
		s += w
	}
	if n := len(v.srcs); n > 1 {
		s += 2 * (n - 1)
	}
	return s
}

type devEvid struct {
	DevEvidence
	weight int
}

type hostnameObs struct {
	name string
	ts   int64
}

type devState struct {
	mac         string
	hostnames   map[string]hostnameObs // src → 最近一次该来源的主机名
	votes       [nDevFields]map[string]*devVote
	vendorClass string
	dhcpFP      string
	services    []string
	lastSeen    int64
	evidence    []devEvid
	el          *list.Element
}

// hostnameSrcPriority: 数字越小越可信。
var hostnameSrcPriority = map[string]int{"dhcp": 0, "dhcpv6": 1, "mdns": 2, "nbns": 3, "restored": 4}

// DeviceIdentifier 是并发安全的被动设备识别器。
type DeviceIdentifier struct {
	mu    sync.Mutex
	path  string
	max   int
	devs  map[string]*devState
	lru   *list.List // Front = 最近活跃
	dirty bool
}

func NewDeviceIdentifier() *DeviceIdentifier {
	return &DeviceIdentifier{
		path: DefaultDevIDPath,
		max:  devIDMaxDevices,
		devs: make(map[string]*devState),
		lru:  list.New(),
	}
}

// SetPath 设置持久化/输出路径(默认 DefaultDevIDPath)。
func (d *DeviceIdentifier) SetPath(p string) {
	d.mu.Lock()
	d.path = p
	d.mu.Unlock()
}

// normalizeMAC: 统一成小写冒号格式; 非 6 字节 MAC 返回空。
func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", ":")
	if len(s) != 17 {
		return ""
	}
	for i := 0; i < 17; i++ {
		c := s[i]
		if i%3 == 2 {
			if c != ':' {
				return ""
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	if s == "00:00:00:00:00:00" || s == "ff:ff:ff:ff:ff:ff" {
		return ""
	}
	return s
}

func (d *DeviceIdentifier) devLocked(mac string, now int64) *devState {
	if st, ok := d.devs[mac]; ok {
		d.lru.MoveToFront(st.el)
		if now-st.lastSeen >= devIDSeenDirtySec {
			d.dirty = true
		}
		if now > st.lastSeen {
			st.lastSeen = now
		}
		return st
	}
	for len(d.devs) >= d.max {
		back := d.lru.Back()
		if back == nil {
			break
		}
		delete(d.devs, back.Value.(string))
		d.lru.Remove(back)
	}
	st := &devState{mac: mac, hostnames: make(map[string]hostnameObs), lastSeen: now}
	st.el = d.lru.PushFront(mac)
	d.devs[mac] = st
	d.dirty = true
	return st
}

// applyLocked 把一条信号计入投票, 并记一条证据。
func (d *DeviceIdentifier) applyLocked(st *devState, src, detail string, sig devSignal, now int64) {
	key := src + ":" + detail
	tw := sig.TypeWeight
	if tw == 0 {
		tw = sig.Weight
	}
	vote := func(f devField, val string, w int) {
		if val == "" || w <= 0 {
			return
		}
		if st.votes[f] == nil {
			st.votes[f] = make(map[string]*devVote)
		}
		v := st.votes[f][val]
		if v == nil {
			if len(st.votes[f]) >= devIDMaxVoteKeys {
				return
			}
			v = &devVote{keys: map[string]int{}, srcs: map[string]bool{}}
			st.votes[f][val] = v
			d.dirty = true
		}
		if old, ok := v.keys[key]; !ok || old < w {
			if !ok && len(v.keys) >= devIDMaxVoteKeys {
				return
			}
			v.keys[key] = w
			d.dirty = true
		}
		if !v.srcs[src] {
			v.srcs[src] = true
			d.dirty = true
		}
		v.last = now
	}
	vote(fOS, sig.OS, sig.Weight)
	if sig.OS != "" && sig.OSVer != "" {
		vote(fOSVer, sig.OS+"\x00"+sig.OSVer, sig.Weight)
	}
	vote(fBrand, sig.Brand, sig.Weight)
	vote(fModel, sig.Model, sig.Weight)
	vote(fType, sig.Type, tw)
	d.addEvidenceLocked(st, src, detail, sig.Weight, now)
}

// addEvidenceLocked: 同 (src, detail) 只刷新 ts; 满 8 条时淘汰"最弱且最旧"的。
func (d *DeviceIdentifier) addEvidenceLocked(st *devState, src, detail string, w int, now int64) {
	for i := range st.evidence {
		e := &st.evidence[i]
		if e.Src == src && e.Detail == detail {
			if now-e.Ts >= devIDSeenDirtySec {
				d.dirty = true
			}
			if now > e.Ts {
				e.Ts = now
			}
			if w > e.weight {
				e.weight = w
			}
			return
		}
	}
	ne := devEvid{DevEvidence: DevEvidence{Src: src, Detail: detail, Ts: now}, weight: w}
	d.dirty = true
	if len(st.evidence) < devIDMaxEvidence {
		st.evidence = append(st.evidence, ne)
		return
	}
	worst := 0
	for i := 1; i < len(st.evidence); i++ {
		a, b := st.evidence[i], st.evidence[worst]
		if a.weight < b.weight || (a.weight == b.weight && a.Ts < b.Ts) {
			worst = i
		}
	}
	if st.evidence[worst].weight <= w {
		st.evidence[worst] = ne
	}
}

func (st *devState) setHostname(src, name string, now int64) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	if old, ok := st.hostnames[src]; ok && old.name == name {
		st.hostnames[src] = hostnameObs{name: name, ts: now}
		return false
	}
	st.hostnames[src] = hostnameObs{name: name, ts: now}
	return true
}

func (st *devState) addService(svc string) bool {
	if svc == "" {
		return false
	}
	for _, s := range st.services {
		if s == svc {
			return false
		}
	}
	if len(st.services) >= devIDMaxServices {
		return false
	}
	st.services = append(st.services, svc)
	return true
}

// ─── 输入 ──────────────────────────────────────────────────────────────

// ObserveHint 处理一条 DHCP/DHCPv6/mDNS/SSDP/NBNS 线索。
func (d *DeviceIdentifier) ObserveHint(h DeviceHint, ts time.Time) {
	mac := normalizeMAC(h.MAC)
	src := strings.TrimSpace(h.Source)
	if mac == "" || src == "" {
		return
	}
	now := ts.Unix()
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.devLocked(mac, now)

	if h.Hostname != "" {
		if st.setHostname(src, h.Hostname, now) {
			d.dirty = true
		}
		for _, sig := range matchHostname(h.Hostname) {
			d.applyLocked(st, src, "hostname="+h.Hostname, sig, now)
		}
	}
	if h.VendorClass != "" {
		if st.vendorClass != h.VendorClass {
			st.vendorClass = h.VendorClass
			d.dirty = true
		}
		label := "opt60"
		if src == "dhcpv6" {
			label = "opt16"
		}
		if sig, ok := matchVendorClass(h.VendorClass); ok {
			d.applyLocked(st, src, label+"="+h.VendorClass, sig, now)
		} else {
			d.addEvidenceLocked(st, src, label+"="+h.VendorClass, 1, now)
		}
	}
	if h.ParamList != "" {
		if st.dhcpFP != h.ParamList {
			st.dhcpFP = h.ParamList
			d.dirty = true
		}
		if sig, name, ok := matchParamList(h.ParamList); ok {
			d.applyLocked(st, src, "opt55="+name, sig, now)
		}
	}
	if h.Model != "" {
		// model= 本身就是型号, 强信号; 再按型号规则推 OS/品牌/类型。
		d.applyLocked(st, src, "model="+h.Model, devSignal{Model: h.Model, Weight: devWStrong}, now)
		for _, sig := range matchModel(h.Model) {
			d.applyLocked(st, src, "model="+h.Model, sig, now)
		}
	}
	if h.OSHint != "" {
		d.applyLocked(st, src, "os="+h.OSHint, devSignal{OS: h.OSHint, Weight: devWStrong - 2}, now)
	}
	if h.UserAgent != "" {
		for _, sig := range matchUA(h.UserAgent) {
			d.applyLocked(st, src, "ua="+truncStr(h.UserAgent, 80), sig, now)
		}
	}
	for _, svc := range h.Services {
		if st.addService(svc) {
			d.dirty = true
		}
		if sig, ok := devServiceRules[svc]; ok {
			d.applyLocked(st, src, "svc="+svc, sig, now)
		}
	}
}

// ObserveDomain 处理客户端的 DNS qname / TLS SNI(src = "dns" / "sni")。
// 热路径: 先无锁查域名表, 不命中直接返回, 不拿锁。
func (d *DeviceIdentifier) ObserveDomain(mac, host, src string, ts time.Time) {
	host = normalizeName(host)
	if host == "" {
		return
	}
	suf, sig, ok := matchDomain(host)
	if !ok {
		return
	}
	mac = normalizeMAC(mac)
	if mac == "" {
		return
	}
	now := ts.Unix()
	d.mu.Lock()
	st := d.devLocked(mac, now)
	d.applyLocked(st, src, suf, sig, now)
	d.mu.Unlock()
}

// ObserveJA4Client 处理 JA4 指纹库映射到的客户端名(如 "iOS Safari")。
func (d *DeviceIdentifier) ObserveJA4Client(mac, client string, ts time.Time) {
	sig, ok := matchJA4Client(client)
	if !ok {
		return
	}
	mac = normalizeMAC(mac)
	if mac == "" {
		return
	}
	now := ts.Unix()
	d.mu.Lock()
	st := d.devLocked(mac, now)
	d.applyLocked(st, "ja4", "client="+client, sig, now)
	d.mu.Unlock()
}

// ─── 汇总 / 输出 ───────────────────────────────────────────────────────

// winner 返回得分最高的取值与领先第二名的幅度; 平分时取最近出现的。
func winner(m map[string]*devVote, filter func(string) bool) (string, int, int) {
	best, bestScore, second := "", -1, 0
	var bestLast int64
	for val, v := range m {
		if filter != nil && !filter(val) {
			continue
		}
		s := v.score()
		switch {
		case s > bestScore || (s == bestScore && (v.last > bestLast || (v.last == bestLast && val < best))):
			if bestScore > second {
				second = bestScore
			}
			best, bestScore, bestLast = val, s, v.last
		case s > second:
			second = s
		}
	}
	if bestScore < 0 {
		return "", 0, 0
	}
	return best, bestScore, bestScore - second
}

func (st *devState) summary() DeviceInfo {
	info := DeviceInfo{
		VendorClass: st.vendorClass,
		DHCPFP:      st.dhcpFP,
		Services:    append([]string{}, st.services...),
		LastSeen:    st.lastSeen,
		Type:        "unknown",
	}
	// 主机名: 来源优先级最高者; 同优先级(理论上不会)取最新。
	bestPri := 1 << 30
	for src, h := range st.hostnames {
		pri, ok := hostnameSrcPriority[src]
		if !ok {
			pri = 10
		}
		if pri < bestPri {
			bestPri = pri
			info.Hostname, info.HostnameSrc = h.name, src
		}
	}
	if info.HostnameSrc == "restored" {
		info.HostnameSrc = ""
	}

	var margin int
	osName, _, m := winner(st.votes[fOS], nil)
	info.OS = osName
	margin += m
	if osName != "" {
		ver, _, _ := winner(st.votes[fOSVer], func(v string) bool { return strings.HasPrefix(v, osName+"\x00") })
		if ver != "" {
			info.OSVer = strings.TrimPrefix(ver, osName+"\x00")
		}
	}
	brand, _, m := winner(st.votes[fBrand], nil)
	info.Brand = brand
	margin += m
	info.Model, _, _ = winner(st.votes[fModel], nil)
	if typ, _, m := winner(st.votes[fType], nil); typ != "" {
		info.Type = typ
		margin += m
	}
	if margin > 0 {
		c := int(math.Round(100 * (1 - math.Exp(-float64(margin)/15))))
		if c > 99 {
			c = 99
		}
		info.Confidence = c
	}

	ev := append([]devEvid{}, st.evidence...)
	sort.SliceStable(ev, func(i, j int) bool {
		if ev[i].Ts != ev[j].Ts {
			return ev[i].Ts > ev[j].Ts
		}
		return ev[i].weight > ev[j].weight
	})
	info.Evidence = make([]DevEvidence, 0, len(ev))
	for _, e := range ev {
		info.Evidence = append(info.Evidence, e.DevEvidence)
	}
	return info
}

// Snapshot 返回当前全部设备的汇总(按 MAC)。
func (d *DeviceIdentifier) Snapshot() map[string]DeviceInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]DeviceInfo, len(d.devs))
	for mac, st := range d.devs {
		out[mac] = st.summary()
	}
	return out
}

// Get 返回单台设备的汇总。
func (d *DeviceIdentifier) Get(mac string) (DeviceInfo, bool) {
	mac = normalizeMAC(mac)
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.devs[mac]
	if !ok {
		return DeviceInfo{}, false
	}
	return st.summary(), true
}

// Flush 有变化时原子写 dpi_devid.json。
func (d *DeviceIdentifier) Flush(now time.Time) error {
	d.mu.Lock()
	if !d.dirty {
		d.mu.Unlock()
		return nil
	}
	out := devIDFile{Schema: 1, GeneratedAt: now.Unix(), Devices: make(map[string]DeviceInfo, len(d.devs))}
	for mac, st := range d.devs {
		out.Devices[mac] = st.summary()
	}
	path := d.path
	d.dirty = false
	d.mu.Unlock()

	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if err := atomicWrite(path, b, 0o644); err != nil {
		d.mu.Lock()
		d.dirty = true
		d.mu.Unlock()
		return err
	}
	return nil
}

// Load 读回已有 dpi_devid.json 恢复识别结果。文件不存在/损坏/schema 不符
// 一律忽略(返回 nil, 从空开始)。恢复的字段以 "restored" 证据键投票,
// 权重随原 confidence 缩放, 新的强信号可以推翻它。
func (d *DeviceIdentifier) Load() error {
	d.mu.Lock()
	path := d.path
	d.mu.Unlock()
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 || len(b) > 4<<20 {
		return nil
	}
	var f devIDFile
	if err := json.Unmarshal(b, &f); err != nil || f.Schema != 1 {
		return nil
	}
	// 按 last_seen 升序插入, 保证 LRU 顺序与原来一致(最新的在 Front)。
	macs := make([]string, 0, len(f.Devices))
	for mac := range f.Devices {
		if normalizeMAC(mac) != "" {
			macs = append(macs, mac)
		}
	}
	sort.Slice(macs, func(i, j int) bool { return f.Devices[macs[i]].LastSeen < f.Devices[macs[j]].LastSeen })

	d.mu.Lock()
	defer d.mu.Unlock()
	for _, rawMAC := range macs {
		info := f.Devices[rawMAC]
		mac := normalizeMAC(rawMAC)
		if _, exists := d.devs[mac]; exists {
			continue // 运行期已观测到的优先
		}
		st := d.devLocked(mac, info.LastSeen)
		st.lastSeen = info.LastSeen
		st.vendorClass = truncStr(info.VendorClass, 160)
		st.dhcpFP = truncStr(info.DHCPFP, 160)
		for _, s := range info.Services {
			st.addService(truncStr(s, 48))
		}
		if info.Hostname != "" {
			src := info.HostnameSrc
			if _, ok := hostnameSrcPriority[src]; !ok {
				src = "restored"
			}
			st.hostnames[src] = hostnameObs{name: truncStr(info.Hostname, 63), ts: info.LastSeen}
		}
		w := 1 + clampInt(info.Confidence, 0, 99)/10
		sig := devSignal{
			OS: truncStr(info.OS, 32), OSVer: truncStr(info.OSVer, 16), Brand: truncStr(info.Brand, 32),
			Model: truncStr(info.Model, 64), Weight: w,
		}
		if info.Type != "" && info.Type != "unknown" {
			sig.Type = truncStr(info.Type, 16)
		}
		if sig.OS != "" || sig.Brand != "" || sig.Model != "" || sig.Type != "" {
			// 恢复投票但不把 "restored" 塞进证据列表(下面单独恢复原证据)。
			ev := st.evidence
			d.applyLocked(st, "restored", "file", sig, info.LastSeen)
			st.evidence = ev
		}
		for i, e := range info.Evidence {
			if i >= devIDMaxEvidence {
				break
			}
			if e.Src == "" || e.Detail == "" {
				continue
			}
			st.evidence = append(st.evidence, devEvid{
				DevEvidence: DevEvidence{Src: truncStr(e.Src, 16), Detail: truncStr(e.Detail, 160), Ts: e.Ts},
				weight:      devWWeak,
			})
		}
	}
	d.dirty = false // 刚从文件读出, 内容与文件一致
	return nil
}

func truncStr(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	// 按 rune 边界截断
	for n > 0 && n < len(s) && (s[n]&0xc0) == 0x80 {
		n--
	}
	return s[:n]
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ─── 规则表 ────────────────────────────────────────────────────────────
//
// 说明: 以下指纹/模式来自公开资料(fingerbank 常见值、各厂商默认主机名习惯),
// 只覆盖最常见的情况, 不保证全覆盖; 命中给中等置信度, 靠多信号投票纠偏。

type devRegexRule struct {
	re  *regexp.Regexp
	sig devSignal
	// verGroup > 0 时, 用该捕获组填 OSVer。
	verGroup int
}

func rx(s string) *regexp.Regexp { return regexp.MustCompile("(?i)" + s) }

// DHCP opt60 / DHCPv6 opt16 vendor class。按顺序首个命中生效(具体 → 泛化)。
var devOpt60Rules = []devRegexRule{
	{re: rx(`^android-dhcp-(\d+)`), sig: devSignal{OS: "Android", Type: "phone", Weight: devWStrong, TypeWeight: devWWeak}, verGroup: 1},
	{re: rx(`^HUAWEI:android`), sig: devSignal{OS: "Android", Brand: "华为", Type: "phone", Weight: devWStrong, TypeWeight: devWWeak}},
	{re: rx(`^HONOR:android`), sig: devSignal{OS: "Android", Brand: "荣耀", Type: "phone", Weight: devWStrong, TypeWeight: devWWeak}},
	{re: rx(`^MSFT 5\.0`), sig: devSignal{OS: "Windows", Type: "pc", Weight: devWStrong, TypeWeight: devWMedium}},
	{re: rx(`^MSFT 98`), sig: devSignal{OS: "Windows", Type: "pc", Weight: devWStrong, TypeWeight: devWMedium}},
	{re: rx(`^dhcpcd-[0-9.]+:.*android`), sig: devSignal{OS: "Android", Weight: devWStrong - 2}},
	{re: rx(`^dhcpcd-[0-9.]+:Linux`), sig: devSignal{OS: "Linux", Weight: devWStrong - 2}},
	{re: rx(`^dhcpcd`), sig: devSignal{OS: "Linux", Weight: devWMedium}},
	{re: rx(`^udhcpc?\b`), sig: devSignal{OS: "Linux", Type: "iot", Weight: devWMedium, TypeWeight: devWWeak}},
}

func matchVendorClass(vc string) (devSignal, bool) {
	for _, r := range devOpt60Rules {
		m := r.re.FindStringSubmatch(vc)
		if m == nil {
			continue
		}
		sig := r.sig
		if r.verGroup > 0 && r.verGroup < len(m) {
			sig.OSVer = m[r.verGroup]
		}
		return sig, true
	}
	return devSignal{}, false
}

// DHCP opt55 参数请求列表指纹。key 为十进制逗号串; 观测值等于 key 或以
// "key," 开头(前缀匹配)即命中, 取最长命中。来源: fingerbank 公开常见值。
var devOpt55Table = []struct {
	fp   string
	name string
	sig  devSignal
}{
	{"1,121,3,6,15,108,114,119,252,95,44,46", "apple-ios-macos", devSignal{Brand: "Apple", Weight: devWMedium}},
	{"1,121,3,6,15,119,252,95,44,46", "apple-legacy", devSignal{Brand: "Apple", Weight: devWMedium}},
	{"1,3,6,15,26,28,51,58,59,43,114,108", "android-11+", devSignal{OS: "Android", Weight: devWMedium}},
	{"1,3,6,15,26,28,51,58,59,43", "android", devSignal{OS: "Android", Weight: devWMedium}},
	{"1,3,6,15,26,28,51,58,59", "android-legacy", devSignal{OS: "Android", Weight: devWMedium - 1}},
	{"1,3,6,15,31,33,43,44,46,47,119,121,249,252", "windows-10-11", devSignal{OS: "Windows", Type: "pc", Weight: devWMedium, TypeWeight: devWWeak}},
	{"1,15,3,6,44,46,47,31,33,121,249,43", "windows-7-8", devSignal{OS: "Windows", Type: "pc", Weight: devWMedium, TypeWeight: devWWeak}},
	{"1,28,2,3,15,6,119,12,44,47,26,121,42", "linux-dhclient", devSignal{OS: "Linux", Weight: devWMedium}},
	{"1,3,6,12,15,28,42", "udhcpc", devSignal{OS: "Linux", Type: "iot", Weight: devWWeak, TypeWeight: devWWeak}},
}

func matchParamList(pl string) (devSignal, string, bool) {
	best := -1
	for i, e := range devOpt55Table {
		if pl == e.fp || strings.HasPrefix(pl, e.fp+",") {
			if best < 0 || len(e.fp) > len(devOpt55Table[best].fp) {
				best = i
			}
		}
	}
	if best < 0 {
		return devSignal{}, "", false
	}
	return devOpt55Table[best].sig, devOpt55Table[best].name, true
}

// 主机名模式。全部命中都计入(各自独立证据), 例如 "Redmi-TV" 同时给出
// 品牌小米和类型电视。
var devHostnameRules = []devRegexRule{
	{re: rx(`iphone`), sig: devSignal{OS: "iOS", Brand: "Apple", Type: "phone", Weight: devWMedium}},
	{re: rx(`ipad`), sig: devSignal{OS: "iPadOS", Brand: "Apple", Type: "tablet", Weight: devWMedium}},
	{re: rx(`macbook|imac|mac-?mini|mac-?pro|mac-?studio`), sig: devSignal{OS: "macOS", Brand: "Apple", Type: "pc", Weight: devWMedium}},
	{re: rx(`apple-?watch`), sig: devSignal{OS: "watchOS", Brand: "Apple", Type: "watch", Weight: devWMedium}},
	{re: rx(`apple-?tv`), sig: devSignal{OS: "tvOS", Brand: "Apple", Type: "tv", Weight: devWMedium}},
	{re: rx(`^(desktop|laptop)-[a-z0-9]{4,}`), sig: devSignal{OS: "Windows", Type: "pc", Weight: devWMedium}},
	{re: rx(`galaxy-?tab`), sig: devSignal{OS: "Android", Brand: "三星", Type: "tablet", Weight: devWMedium}},
	{re: rx(`galaxy|^sm-[a-z0-9]`), sig: devSignal{OS: "Android", Brand: "三星", Type: "phone", Weight: devWMedium, TypeWeight: devWWeak}},
	{re: rx(`redmi|xiaomi|^mi-|^mi[0-9]|poco`), sig: devSignal{OS: "Android", Brand: "小米", Type: "phone", Weight: devWMedium, TypeWeight: devWWeak}},
	{re: rx(`huawei|^nova`), sig: devSignal{Brand: "华为", Type: "phone", Weight: devWMedium, TypeWeight: devWWeak}},
	{re: rx(`honor`), sig: devSignal{OS: "Android", Brand: "荣耀", Type: "phone", Weight: devWMedium, TypeWeight: devWWeak}},
	{re: rx(`oppo`), sig: devSignal{OS: "Android", Brand: "OPPO", Type: "phone", Weight: devWMedium, TypeWeight: devWWeak}},
	{re: rx(`realme|^rmx[0-9]`), sig: devSignal{OS: "Android", Brand: "realme", Type: "phone", Weight: devWMedium, TypeWeight: devWWeak}},
	{re: rx(`oneplus`), sig: devSignal{OS: "Android", Brand: "一加", Type: "phone", Weight: devWMedium, TypeWeight: devWWeak}},
	{re: rx(`vivo|iqoo`), sig: devSignal{OS: "Android", Brand: "vivo", Type: "phone", Weight: devWMedium, TypeWeight: devWWeak}},
	{re: rx(`pixel`), sig: devSignal{OS: "Android", Brand: "Google", Type: "phone", Weight: devWMedium, TypeWeight: devWWeak}},
	{re: rx(`^nothing-?phone`), sig: devSignal{OS: "Android", Brand: "Nothing", Type: "phone", Weight: devWMedium}},
	{re: rx(`^android[-_][0-9a-f]{6,}`), sig: devSignal{OS: "Android", Type: "phone", Weight: devWMedium, TypeWeight: devWWeak}},
	{re: rx(`^(esp[_-]|esp32|esp8266|tasmota|shelly)`), sig: devSignal{Type: "iot", Weight: devWMedium}},
	{re: rx(`raspberrypi`), sig: devSignal{OS: "Linux", Brand: "Raspberry Pi", Type: "iot", Weight: devWMedium, TypeWeight: devWWeak}},
	{re: rx(`^(ubuntu|debian)`), sig: devSignal{OS: "Linux", Type: "pc", Weight: devWMedium, TypeWeight: devWWeak}},
	{re: rx(`^(nintendo-?)?switch\b`), sig: devSignal{Brand: "任天堂", Type: "console", Weight: devWMedium}},
	{re: rx(`^ps[45]\b|playstation`), sig: devSignal{Brand: "索尼", Type: "console", Weight: devWMedium}},
	{re: rx(`xbox`), sig: devSignal{Brand: "微软", Type: "console", Weight: devWMedium}},
	{re: rx(`-tv$|^mitv|chromecast|androidtv|bravia`), sig: devSignal{Type: "tv", Weight: devWMedium}},
	{re: rx(`^mitv`), sig: devSignal{Brand: "小米", Weight: devWMedium}},
	{re: rx(`chromecast`), sig: devSignal{Brand: "Google", Weight: devWMedium}},
}

func matchRegexAll(rules []devRegexRule, s string) []devSignal {
	var out []devSignal
	for _, r := range rules {
		m := r.re.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		sig := r.sig
		if r.verGroup > 0 && r.verGroup < len(m) {
			sig.OSVer = m[r.verGroup]
		}
		out = append(out, sig)
	}
	return out
}

func matchHostname(h string) []devSignal { return matchRegexAll(devHostnameRules, h) }

// mDNS TXT model= / md= / am= 取值。
var devModelRules = []devRegexRule{
	{re: rx(`^(MacBook|iMac|Macmini|MacPro|MacStudio|Mac[0-9]+,)`), sig: devSignal{OS: "macOS", Brand: "Apple", Type: "pc", Weight: devWStrong}},
	{re: rx(`^iPhone`), sig: devSignal{OS: "iOS", Brand: "Apple", Type: "phone", Weight: devWStrong}},
	{re: rx(`^iPad`), sig: devSignal{OS: "iPadOS", Brand: "Apple", Type: "tablet", Weight: devWStrong}},
	{re: rx(`^AppleTV`), sig: devSignal{OS: "tvOS", Brand: "Apple", Type: "tv", Weight: devWStrong}},
	{re: rx(`^Watch[0-9]`), sig: devSignal{OS: "watchOS", Brand: "Apple", Type: "watch", Weight: devWStrong}},
	{re: rx(`^AudioAccessory|HomePod`), sig: devSignal{Brand: "Apple", Type: "iot", Weight: devWStrong}},
	{re: rx(`chromecast|google tv`), sig: devSignal{Brand: "Google", Type: "tv", Weight: devWStrong}},
}

func matchModel(m string) []devSignal { return matchRegexAll(devModelRules, m) }

// mDNS 服务类型。
var devServiceRules = map[string]devSignal{
	"_googlecast._tcp":       {Type: "tv", Weight: devWMedium - 2},
	"_androidtvremote2._tcp": {OS: "Android", Type: "tv", Weight: devWMedium},
	"_companion-link._tcp":   {Brand: "Apple", Weight: devWMedium},
	"_apple-mobdev2._tcp":    {Brand: "Apple", Weight: devWMedium},
	"_hap._tcp":              {Type: "iot", Weight: devWMedium - 2},
	"_ipp._tcp":              {Type: "iot", Weight: devWWeak},
	"_printer._tcp":          {Type: "iot", Weight: devWWeak},
	"_amzn-wplay._tcp":       {Brand: "Amazon", Type: "tv", Weight: devWMedium - 2},
}

// SSDP SERVER / USER-AGENT。
var devUARules = []devRegexRule{
	{re: rx(`Android[/ ](\d+)`), sig: devSignal{OS: "Android", Weight: devWMedium}, verGroup: 1},
	{re: rx(`Windows|Microsoft-Windows`), sig: devSignal{OS: "Windows", Weight: devWMedium}},
	{re: rx(`Darwin|CFNetwork|\biOS\b`), sig: devSignal{Brand: "Apple", Weight: devWMedium}},
	{re: rx(`MiTV|MIBOX`), sig: devSignal{Brand: "小米", Type: "tv", Weight: devWMedium}},
	{re: rx(`Samsung.*TV|Tizen`), sig: devSignal{Brand: "三星", Type: "tv", Weight: devWMedium}},
	{re: rx(`webOS`), sig: devSignal{Brand: "LG", Type: "tv", Weight: devWMedium}},
	{re: rx(`PlayStation|PS[45]\b`), sig: devSignal{Brand: "索尼", Type: "console", Weight: devWMedium}},
	{re: rx(`^Linux|\bLinux/`), sig: devSignal{OS: "Linux", Weight: devWWeak}},
}

func matchUA(ua string) []devSignal { return matchRegexAll(devUARules, ua) }

// 域名信号(DNS/SNI 后缀)。弱信号: 一台 Windows 电脑也可能访问 icloud.com。
var devDomainTable = map[string]devSignal{
	"captive.apple.com":                      {Brand: "Apple", Weight: devWWeak},
	"icloud.com":                             {Brand: "Apple", Weight: devWWeak},
	"gs.apple.com":                           {Brand: "Apple", Weight: devWWeak},
	"connectivitycheck.gstatic.com":          {OS: "Android", Weight: devWWeak},
	"connectivitycheck.android.com":          {OS: "Android", Weight: devWWeak},
	"android.clients.google.com":             {OS: "Android", Weight: devWWeak},
	"play.googleapis.com":                    {OS: "Android", Weight: devWWeak},
	"www.msftconnecttest.com":                {OS: "Windows", Weight: devWWeak},
	"windowsupdate.com":                      {OS: "Windows", Weight: devWWeak},
	"login.live.com":                         {OS: "Windows", Weight: devWWeak},
	"miui.com":                               {Brand: "小米", Weight: devWWeak},
	"xiaomi.net":                             {Brand: "小米", Weight: devWWeak},
	"mi.com":                                 {Brand: "小米", Weight: devWWeak},
	"hicloud.com":                            {Brand: "华为", Weight: devWWeak},
	"dbankcloud.cn":                          {Brand: "华为", Weight: devWWeak},
	"dbankcloud.com":                         {Brand: "华为", Weight: devWWeak},
	"dbankcloud.asia":                        {Brand: "华为", Weight: devWWeak},
	"connectivitycheck.platform.hicloud.com": {Brand: "华为", Weight: devWWeak + 1},
	"heytapmobi.com":                         {OS: "Android", Brand: "OPPO/realme/一加", Weight: devWWeak},
	"heytapdl.com":                           {OS: "Android", Brand: "OPPO/realme/一加", Weight: devWWeak},
	"coloros.com":                            {OS: "Android", Brand: "OPPO/realme/一加", Weight: devWWeak},
	"oppomobile.com":                         {OS: "Android", Brand: "OPPO/realme/一加", Weight: devWWeak},
	"vivo.com.cn":                            {OS: "Android", Brand: "vivo", Weight: devWWeak},
	"vivoglobal.com":                         {OS: "Android", Brand: "vivo", Weight: devWWeak},
	"samsungcloud.com":                       {OS: "Android", Brand: "三星", Weight: devWWeak},
	"samsungapps.com":                        {OS: "Android", Brand: "三星", Weight: devWWeak},
	"nintendo.net":                           {Brand: "任天堂", Type: "console", Weight: devWWeak},
	"playstation.net":                        {Brand: "索尼", Type: "console", Weight: devWWeak},
	"xboxlive.com":                           {Brand: "微软", Type: "console", Weight: devWWeak},
}

// matchDomain 按 label 从长到短剥离查表, 返回命中的最长后缀。
func matchDomain(host string) (string, devSignal, bool) {
	tail := host
	for {
		if sig, ok := devDomainTable[tail]; ok {
			return tail, sig, true
		}
		dot := strings.IndexByte(tail, '.')
		if dot < 0 {
			return "", devSignal{}, false
		}
		tail = tail[dot+1:]
	}
}

// JA4 指纹库客户端名 → 很弱的 OS/品牌线索。Chrome/Firefox 等跨平台客户端不表态。
func matchJA4Client(client string) (devSignal, bool) {
	c := strings.ToLower(client)
	switch {
	case c == "":
		return devSignal{}, false
	case strings.Contains(c, "ios") || strings.Contains(c, "safari"):
		return devSignal{Brand: "Apple", Weight: devWJA4}, true
	case strings.Contains(c, "android"):
		return devSignal{OS: "Android", Weight: devWJA4}, true
	case strings.Contains(c, "windows") || strings.Contains(c, "edge"):
		return devSignal{OS: "Windows", Weight: devWJA4}, true
	}
	return devSignal{}, false
}
