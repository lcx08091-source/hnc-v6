// Package output - ech_blind.go: HNC v6.0.0 抗 TLS 1.3 ECH 盲态识别联合推断引擎。
//
// 背景与问题:
//   Chrome / Firefox / Android Cronet 开启 TLS 1.3 ECH(Encrypted Client Hello) 后,
//   TLS/QUIC 握手外层明文 SNI 被替换为公共 ECH 前端名(如 cloudflare-ech.com /
//   crypto.cloudflare.com / encryptedsni.com)或干脆省略 server_name 扩展, 传统只看
//   明文 SNI 的分类器瞬间失明。
//
// 联合推断四维证据链:
//   1. DNS Type 65 HTTPS / Type 64 SVCB 缓存 (RFC 9460):
//      客户端发起 ECH 握手前必先请求 Type 65 HTTPS 记录拿到 ECHConfigList(含 config_id)、
//      ipv4hint/ipv6hint、alpn 与 altPort。按 (客户端IP, 目的IP) 双级索引缓存原始 QName,
//      并在握手时比对 ALPN / 端口 / ECHConfigID, 即使多设备共用同一 Cloudflare Anycast IP
//      也能按发起查询的客户端精准隔离归因!
//   2. 8 跳 CNAME 全链反解 (BestClassifiedCNAMEHop):
//      当业务域名采用陌生边缘调度域名并 CNAME 经由集团专属 CDN(如 *.bilivideo.com /
//      *.byteimg.com / *.dewucdn.com)再落到泛公共 ECH 节点时, 沿完整 CNAME 链提取专属跳归类。
//   3. JA4 指纹家族归因 (ja4FamilyTable):
//      当客户端走内置加密 DoH 绕过本地 DNS 导致无 SVCB 记录时, 利用 TTNet / Mars / ANet 等
//      集团自研网络库稳定的 JA4 客户端指纹锁定所属公司家族, 或对 SVCB/CNAME 候选进行交叉印证加权。
//   4. SPLT 前 10 包序列形态与软相似度 (FlowSPLTTracker + SPLTSoftSimilarity):
//      结合前 N 包方向位图、分桶包长序列及突发紧凑度推断业务形态(GameSync / VideoABR /
//      IMControl / VoIPMedia / BulkDL / APIShort)或匹配已学得的 SPLT 原型签名, 在同公司多应用间
//      完成细分消歧(如腾讯系下区分王者荣耀实时帧同步 vs 微信信令 vs 腾讯视频 ABR 流)。

package output

import (
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	echDefaultMaxEntries = 2048
	echDefaultMinTTLSec  = 300
	echDefaultMaxTTLSec  = 7200
	echMaxPrototypes     = 512
)

// ECHBlindStats 盲态联合推断引擎运行计数器快照。
type ECHBlindStats struct {
	SVCBRecorded  uint64 `json:"svcb_recorded"`
	InferQueries  uint64 `json:"infer_queries"`
	InferHits     uint64 `json:"infer_hits"`
	SVCBHits      uint64 `json:"svcb_hits"`
	CNAMEHits     uint64 `json:"cname_hits"`
	JA4FamilyHits uint64 `json:"ja4_family_hits"`
	SPLTRefined   uint64 `json:"splt_refined"`
}

// ECHSVCBHint 封装一条来自 DNS Type 65 HTTPS / Type 64 SVCB (及同包 CNAME/A/AAAA) 的观测记录。
type ECHSVCBHint struct {
	ClientIP     string
	QName        string
	Records      []DNSAnswer
	TargetIPs    []string
	ECHConfigIDs []uint8
	ALPNs        []string
	AltPort      uint16
	TTL          uint32
	ObservedAt   time.Time
}

// ECHBlindQuery 表示一次待解盲的 TLS 1.3 / QUIC 连接查询输入。
type ECHBlindQuery struct {
	ClientIP    string
	RemoteIP    string
	DstPort     uint16
	IsUDP       bool
	OuterSNI    string
	HasECHExt   bool
	ECHConfigID uint8
	HasConfigID bool
	ALPNs       []string
	JA4         string
	SPLT        *FlowSPLTTracker
	SPLTSig64   uint64
	IPNames     *IPNameTable
	Now         time.Time
}

// ECHBlindVerdict 表示联合推断引擎输出的真实应用归属判决。
type ECHBlindVerdict struct {
	AppID           string   `json:"app_id"`
	AppName         string   `json:"app_name"`
	Category        string   `json:"category"`
	Company         string   `json:"company,omitempty"`
	CompanyName     string   `json:"company_name,omitempty"`
	RealHost        string   `json:"real_host,omitempty"`
	CNAMEHop        string   `json:"cname_hop,omitempty"`
	Confidence      float64  `json:"confidence"`
	ConfidenceLevel string   `json:"confidence_level"` // "high" | "medium" | "low"
	Sources         []string `json:"sources"`
	SPLTShape       string   `json:"splt_shape,omitempty"`
}

type echSVCBRecord struct {
	qname        string
	cnameHop     string
	ruleID       string
	ruleName     string
	category     string
	company      string
	echConfigIDs []uint8
	alpns        []string
	altPort      uint16
	observedUnix int64
	expireUnix   int64
}

type echSPLTPrototype struct {
	sig64      uint64
	appID      string
	appName    string
	category   string
	company    string
	isUDP      bool
	updatedSec int64
}

// ECHBlindEngine 并发安全的抗 TLS 1.3 ECH 盲态联合推断引擎。
// 严格遵守 32 位 ARM 8 字节原子对齐: 所有 64 位原子字段固定置于结构体顶部 offset 0。
type ECHBlindEngine struct {
	svcbRecorded  atomic.Uint64
	inferQueries  atomic.Uint64
	inferHits     atomic.Uint64
	svcbHits      atomic.Uint64
	cnameHits     atomic.Uint64
	ja4FamilyHits atomic.Uint64
	spltRefined   atomic.Uint64

	mu         sync.RWMutex
	maxEntries int
	byClientIP map[string]*echSVCBRecord // "clientIP|remoteIP" -> 客户端级精准 SVCB/DNS 证据
	byRemoteIP map[string]*echSVCBRecord // "remoteIP" -> 全局级 SVCB/DNS 证据
	spltProtos []echSPLTPrototype        // 已验证流量的 SPLT 原型样本环
	protoNext  int
	ja4Fam     *ja4FamilyTable
}

// DefaultECHBlindEngine 进程级默认盲态推断单例。
var DefaultECHBlindEngine = NewECHBlindEngine(echDefaultMaxEntries)

// NewECHBlindEngine 创建指定缓存容量的 ECH 盲态联合推断引擎。
func NewECHBlindEngine(maxEntries int) *ECHBlindEngine {
	if maxEntries <= 0 {
		maxEntries = echDefaultMaxEntries
	}
	return &ECHBlindEngine{
		maxEntries: maxEntries,
		byClientIP: make(map[string]*echSVCBRecord),
		byRemoteIP: make(map[string]*echSVCBRecord),
		spltProtos: make([]echSPLTPrototype, 0, 64),
		ja4Fam:     newJA4FamilyTable(),
	}
}

var extraECHOuterSuffixes = []string{
	"cloudflare-ech.com",
	"crypto.cloudflare.com",
	"encryptedsni.com",
	"ech.cloudflare.com",
	"fastly-ech.com",
	"akamai-ech.com",
}

// IsECHBlindOrOuterSNI 判断连接是否处于 ECH 盲态(外层 SNI 为公共 ECH 前端名, 或缺失明文 SNI)。
func IsECHBlindOrOuterSNI(outerSNI string, hasECHExt bool) bool {
	h := normalizeName(outerSNI)
	if h == "" {
		return true
	}
	if IsECHPublicName(h) {
		return true
	}
	for _, suf := range extraECHOuterSuffixes {
		if h == suf || strings.HasSuffix(h, "."+suf) {
			return true
		}
	}
	// 部分自建 ECH 网关以 ech.<domain> 作为 public_name 且同时携带 ECH 扩展
	if hasECHExt && strings.HasPrefix(h, "ech.") {
		return true
	}
	return false
}

// SPLTShapeName 返回 SPLTShape 的可读名称。
func SPLTShapeName(s SPLTShape) string {
	switch s {
	case SPLTShapeGameSync:
		return "game_sync"
	case SPLTShapeIMControl:
		return "im_control"
	case SPLTShapeAPIShort:
		return "api_short"
	case SPLTShapeVideoABR:
		return "video_abr"
	case SPLTShapeBulkDL:
		return "bulk_dl"
	case SPLTShapeVoIPMedia:
		return "voip_media"
	default:
		return ""
	}
}

func echClampTTL(ttl uint32) int64 {
	sec := int64(ttl)
	if sec < echDefaultMinTTLSec {
		sec = echDefaultMinTTLSec
	}
	if sec > echDefaultMaxTTLSec {
		sec = echDefaultMaxTTLSec
	}
	return sec
}

func resolveHostAndCNAME(qname string, recs []DNSAnswer) (realHost, cnameHop, ruleID, ruleName, category string) {
	qn := normalizeName(qname)
	if qn == "" {
		return "", "", "", "", ""
	}
	realHost = qn

	// 1. 直接匹配原始 QName(若非公共 ECH 外层名且非泛多租户 CDN)
	if !IsECHPublicName(qn) && !isGenericMultiTenantCDN(qn) {
		if r, ok := classifyHost(qn); ok && r.ID != "" && !strings.HasPrefix(r.ID, "_") {
			return qn, "", r.ID, r.Name, r.Category
		}
	}

	// 2. 构建 CNAME 映射并沿 8 跳链查找专属集团 CDN / 应用跳名
	cn := make(map[string]string, len(recs))
	for _, r := range recs {
		if r.Type == 5 {
			o := normalizeName(r.Name)
			v := normalizeName(r.Value)
			if o != "" && v != "" {
				if _, exists := cn[o]; !exists {
					cn[o] = v
				}
			}
		}
	}
	if len(cn) > 0 {
		final := qn
		visited := map[string]bool{qn: true}
		for i := 0; i < ipNameMaxCNAMEHops; i++ {
			nx, ok := cn[final]
			if !ok || visited[nx] {
				break
			}
			visited[nx] = true
			final = nx
		}
		hop := BestClassifiedCNAMEHop(qn, cn, final)
		if hop != "" && hop != qn {
			cnameHop = hop
			if !isGenericMultiTenantCDN(hop) {
				if r, ok := classifyHost(hop); ok && r.ID != "" && !strings.HasPrefix(r.ID, "_") {
					return qn, hop, r.ID, r.Name, r.Category
				}
			}
		}
	}
	return qn, cnameHop, "", "", ""
}

// RecordSVCB 摄入一条 DNS Type 65 HTTPS / SVCB(及同报文 A/AAAA/CNAME)记录供后续盲态握手反解。
func (e *ECHBlindEngine) RecordSVCB(hint ECHSVCBHint) {
	qn := normalizeName(hint.QName)
	if qn == "" || IsECHPublicName(qn) {
		return
	}
	now := hint.ObservedAt
	if now.IsZero() {
		now = time.Now()
	}
	nowSec := now.Unix()
	expSec := nowSec + echClampTTL(hint.TTL)

	realHost, cnameHop, ruleID, ruleName, category := resolveHostAndCNAME(qn, hint.Records)
	ipSet := make(map[string]struct{}, len(hint.TargetIPs)+len(hint.Records))
	for _, rawIP := range hint.TargetIPs {
		if cip := canonIP(rawIP); cip != "" {
			ipSet[cip] = struct{}{}
		}
	}
	for _, r := range hint.Records {
		if r.Type == 1 || r.Type == 28 || r.Type == 64 || r.Type == 65 {
			if cip := canonIP(r.Value); cip != "" {
				ipSet[cip] = struct{}{}
			}
		}
	}
	if len(ipSet) == 0 {
		return
	}

	alpns := make([]string, 0, len(hint.ALPNs))
	for _, a := range hint.ALPNs {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" {
			alpns = append(alpns, a)
		}
	}
	cfgIDs := append([]uint8(nil), hint.ECHConfigIDs...)
	comp := companyOfRule(ruleID)
	rec := &echSVCBRecord{
		qname:        realHost,
		cnameHop:     cnameHop,
		ruleID:       ruleID,
		ruleName:     ruleName,
		category:     category,
		company:      comp,
		echConfigIDs: cfgIDs,
		alpns:        alpns,
		altPort:      hint.AltPort,
		observedUnix: nowSec,
		expireUnix:   expSec,
	}

	clientCanon := canonIP(hint.ClientIP)
	e.mu.Lock()
	e.pruneExpiredLocked(nowSec)
	for rip := range ipSet {
		if len(e.byRemoteIP) >= e.maxEntries {
			e.evictOldestMapLocked(e.byRemoteIP)
		}
		e.byRemoteIP[rip] = rec
		if clientCanon != "" {
			ck := clientCanon + "|" + rip
			if len(e.byClientIP) >= e.maxEntries {
				e.evictOldestMapLocked(e.byClientIP)
			}
			e.byClientIP[ck] = rec
		}
	}
	e.mu.Unlock()
	e.svcbRecorded.Add(1)
}

// ObserveVerifiedFlow 从明文已识别或本机真值确认的连接中在线学习 JA4 家族与 SPLT 序列原型。
func (e *ECHBlindEngine) ObserveVerifiedFlow(ruleID, ruleName, category, ja4 string, isUDP bool, dstPort uint16, splt *FlowSPLTTracker, now time.Time) {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" || strings.HasPrefix(ruleID, "_") {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	nowSec := now.Unix()
	comp := companyOfRule(ruleID)

	var sig64 uint64
	if splt != nil {
		sig64 = splt.PackSig64(isUDP, dstPort)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if ja4 != "" {
		e.ja4Fam.learn(ja4, comp, nowSec)
	}
	if sig64 != 0 {
		proto := echSPLTPrototype{
			sig64:      sig64,
			appID:      ruleID,
			appName:    ruleName,
			category:   category,
			company:    comp,
			isUDP:      isUDP,
			updatedSec: nowSec,
		}
		for i := range e.spltProtos {
			if e.spltProtos[i].appID == ruleID && e.spltProtos[i].isUDP == isUDP &&
				SPLTSoftSimilarity(e.spltProtos[i].sig64, sig64) >= 0.85 {
				e.spltProtos[i] = proto
				return
			}
		}
		if len(e.spltProtos) < echMaxPrototypes {
			e.spltProtos = append(e.spltProtos, proto)
		} else {
			e.spltProtos[e.protoNext] = proto
			e.protoNext = (e.protoNext + 1) % echMaxPrototypes
		}
	}
}

func (e *ECHBlindEngine) pruneExpiredLocked(nowSec int64) {
	if len(e.byRemoteIP) < e.maxEntries/2 && len(e.byClientIP) < e.maxEntries/2 {
		return
	}
	for k, v := range e.byRemoteIP {
		if v.expireUnix < nowSec {
			delete(e.byRemoteIP, k)
		}
	}
	for k, v := range e.byClientIP {
		if v.expireUnix < nowSec {
			delete(e.byClientIP, k)
		}
	}
}

func (e *ECHBlindEngine) evictOldestMapLocked(m map[string]*echSVCBRecord) {
	var oldK string
	var oldTs int64
	first := true
	for k, v := range m {
		if first || v.observedUnix < oldTs {
			oldK, oldTs, first = k, v.observedUnix, false
		}
	}
	if !first {
		delete(m, oldK)
	}
}

type companyShapeFallback struct {
	appID    string
	appName  string
	category string
}

// companyShapeDisambiguate 当仅有 JA4 集团家族 + SPLT 包长序列形态(如开启 DoH + ECH 无任何 DNS 可见性)时,
// 联合推断具体代表业务或家族级分类。
func companyShapeDisambiguate(companyID string, shape SPLTShape) companyShapeFallback {
	cname := companyName(companyID)
	switch companyID {
	case "bytedance":
		switch shape {
		case SPLTShapeVideoABR, SPLTShapeBulkDL:
			return companyShapeFallback{"douyin", "抖音", "video"}
		case SPLTShapeIMControl, SPLTShapeVoIPMedia:
			return companyShapeFallback{"feishu", "飞书", "im"}
		default:
			return companyShapeFallback{"bytedance_group", cname + "系应用", "app"}
		}
	case "tencent":
		switch shape {
		case SPLTShapeGameSync:
			return companyShapeFallback{"tencent_game", "腾讯游戏", "game"}
		case SPLTShapeVideoABR:
			return companyShapeFallback{"tencent_video", "腾讯视频", "video"}
		case SPLTShapeIMControl, SPLTShapeVoIPMedia:
			return companyShapeFallback{"wechat", "微信", "im"}
		default:
			return companyShapeFallback{"tencent_group", cname + "系应用", "app"}
		}
	case "mihoyo":
		return companyShapeFallback{"mihoyo_game", "米哈游游戏", "game"}
	case "netease":
		if shape == SPLTShapeGameSync {
			return companyShapeFallback{"netease_game", "网易游戏", "game"}
		}
		return companyShapeFallback{"netease_music", "网易云音乐", "music"}
	case "alibaba":
		if shape == SPLTShapeVideoABR {
			return companyShapeFallback{"youku", "优酷", "video"}
		}
		if shape == SPLTShapeIMControl || shape == SPLTShapeVoIPMedia {
			return companyShapeFallback{"dingding", "钉钉", "im"}
		}
		return companyShapeFallback{"taobao", "淘宝", "shopping"}
	case "kuaishou":
		return companyShapeFallback{"kuaishou", "快手", "video"}
	case "bilibili":
		return companyShapeFallback{"bilibili", "哔哩哔哩", "video"}
	default:
		cat := "app"
		switch shape {
		case SPLTShapeGameSync:
			cat = "game"
		case SPLTShapeVideoABR:
			cat = "video"
		case SPLTShapeIMControl:
			cat = "im"
		case SPLTShapeVoIPMedia:
			cat = "voip"
		case SPLTShapeBulkDL:
			cat = "download"
		}
		return companyShapeFallback{companyID + "_ech", cname + "系应用", cat}
	}
}

func shapeConsistentWithCategory(shape SPLTShape, category string) bool {
	if shape == SPLTShapeUnknown || category == "" {
		return false
	}
	cat := strings.ToLower(category)
	switch shape {
	case SPLTShapeGameSync:
		return strings.Contains(cat, "game")
	case SPLTShapeVideoABR:
		return strings.Contains(cat, "video") || strings.Contains(cat, "stream") || strings.Contains(cat, "live")
	case SPLTShapeIMControl:
		return strings.Contains(cat, "im") || strings.Contains(cat, "social") || strings.Contains(cat, "chat")
	case SPLTShapeVoIPMedia:
		return strings.Contains(cat, "voip") || strings.Contains(cat, "im") || strings.Contains(cat, "meeting")
	case SPLTShapeBulkDL:
		return strings.Contains(cat, "download") || strings.Contains(cat, "cloud") || strings.Contains(cat, "video")
	}
	return false
}

// Infer 对外层 SNI 为 ECH 公共前端或缺失明文 SNI 的连接执行四维证据联合推断。
// 若外层 SNI 本身就是正常可分类明文域名, 也会直接给出高置信度规则归属。
func (e *ECHBlindEngine) Infer(q ECHBlindQuery) (ECHBlindVerdict, bool) {
	e.inferQueries.Add(1)
	now := q.Now
	if now.IsZero() {
		now = time.Now()
	}
	nowSec := now.Unix()

	// 若并非盲态 ECH 外层名且自身明文 SNI 可直接命中专属规则, 直接返回明文规则结果。
	if !IsECHBlindOrOuterSNI(q.OuterSNI, q.HasECHExt) {
		if r, ok := classifyHost(q.OuterSNI); ok && r.ID != "" && !strings.HasPrefix(r.ID, "_") {
			comp := companyOfRule(r.ID)
			v := ECHBlindVerdict{
				AppID:           r.ID,
				AppName:         r.Name,
				Category:        r.Category,
				Company:         comp,
				CompanyName:     companyName(comp),
				RealHost:        normalizeName(q.OuterSNI),
				Confidence:      0.98,
				ConfidenceLevel: "high",
				Sources:         []string{"clear_sni"},
			}
			e.inferHits.Add(1)
			return v, true
		}
	}

	rip := canonIP(q.RemoteIP)
	cip := canonIP(q.ClientIP)

	var shape SPLTShape
	sig64 := q.SPLTSig64
	if q.SPLT != nil {
		shape = q.SPLT.InferShape(q.IsUDP)
		if sig64 == 0 {
			sig64 = q.SPLT.PackSig64(q.IsUDP, q.DstPort)
		}
	} else if sig64 != 0 {
		shape = SPLTShape((sig64 >> 56) & 0xF)
	}

	e.mu.RLock()
	var svcbRec *echSVCBRecord
	clientScoped := false
	if rip != "" {
		if cip != "" {
			if r := e.byClientIP[cip+"|"+rip]; r != nil && r.expireUnix >= nowSec {
				svcbRec = r
				clientScoped = true
			}
		}
		if svcbRec == nil {
			if r := e.byRemoteIP[rip]; r != nil && r.expireUnix >= nowSec {
				svcbRec = r
			}
		}
	}
	ja4Comp, ja4Share, hasJA4Fam := "", 0.0, false
	if q.JA4 != "" {
		ja4Comp, ja4Share, hasJA4Fam = e.ja4Fam.familyOf(q.JA4)
	}
	var bestProto *echSPLTPrototype
	bestProtoSim := 0.0
	if sig64 != 0 {
		for i := range e.spltProtos {
			p := &e.spltProtos[i]
			if p.isUDP != q.IsUDP {
				continue
			}
			if hasJA4Fam && p.company != "" && p.company != ja4Comp {
				continue
			}
			sim := SPLTSoftSimilarity(sig64, p.sig64)
			if sim > bestProtoSim {
				bestProtoSim = sim
				cp := *p
				bestProto = &cp
			}
		}
	}
	e.mu.RUnlock()

	var (
		appID    string
		appName  string
		category string
		company  string
		realHost string
		cnameHop string
		score    float64
		sources  []string
	)
	addSrc := func(s string) {
		for _, x := range sources {
			if x == s {
				return
			}
		}
		sources = append(sources, s)
	}

	// 维度 1 & 2: DNS Type 65 HTTPS/SVCB 缓存 + 8 跳 CNAME 链
	if svcbRec != nil && svcbRec.ruleID != "" {
		appID = svcbRec.ruleID
		appName = svcbRec.ruleName
		category = svcbRec.category
		company = svcbRec.company
		realHost = svcbRec.qname
		cnameHop = svcbRec.cnameHop
		if clientScoped {
			score += 0.56
		} else {
			score += 0.44
		}
		addSrc("svcb_https")
		e.svcbHits.Add(1)
		if cnameHop != "" {
			score += 0.12
			addSrc("cname_chain")
			e.cnameHits.Add(1)
		}
		if q.HasConfigID && len(svcbRec.echConfigIDs) > 0 {
			for _, id := range svcbRec.echConfigIDs {
				if id == q.ECHConfigID {
					score += 0.14
					addSrc("ech_config_id")
					break
				}
			}
		}
		if len(q.ALPNs) > 0 && len(svcbRec.alpns) > 0 {
			matchedALPN := false
			for _, qa := range q.ALPNs {
				for _, sa := range svcbRec.alpns {
					if strings.EqualFold(qa, sa) {
						matchedALPN = true
						break
					}
				}
			}
			if matchedALPN {
				score += 0.06
			}
		}
		if svcbRec.altPort > 0 && q.DstPort == svcbRec.altPort {
			score += 0.05
		}
	} else if q.IPNames != nil && rip != "" {
		// 退回联合 IPNameTable 中的实时 DNS / CNAME 关联记录(兼容 Flush 前尚未计算 App 的内存条目)
		if ent, ok := q.IPNames.Lookup(rip, now); ok {
			realHost = ent.Name
			cnameHop = ent.CNAME
			if ent.App != "" && !strings.HasPrefix(ent.App, "_") {
				appID, appName, category = ent.App, ent.AppName, ent.Category
			} else if ent.Name != "" && !isGenericMultiTenantCDN(ent.Name) {
				if r, ok := classifyHost(ent.Name); ok && r.ID != "" && !strings.HasPrefix(r.ID, "_") {
					appID, appName, category = r.ID, r.Name, r.Category
				}
			}
			if appID == "" && cnameHop != "" && !isGenericMultiTenantCDN(cnameHop) {
				if r, ok := classifyHost(cnameHop); ok && r.ID != "" && !strings.HasPrefix(r.ID, "_") {
					appID, appName, category = r.ID, r.Name, r.Category
				}
			}
			if appID != "" {
				company = companyOfRule(appID)
				score += 0.46
				addSrc("dns_ipname")
				if cnameHop != "" {
					score += 0.10
					addSrc("cname_chain")
					e.cnameHits.Add(1)
				}
			}
		}
	}

	// 若 IP 段本身属于专属游戏/RTC CIDR, 同样纳入联合证据
	if appID == "" && rip != "" {
		parsedIP := net.ParseIP(rip)
		proto := protoTCP
		if q.IsUDP {
			proto = protoUDP
		}
		if parsedIP != nil {
			if parsedIP.To4() != nil {
				if r, ok := classifyFlowIP(parsedIP, proto, q.DstPort); ok && r.ID != "" && !strings.HasPrefix(r.ID, "_") {
					appID, appName, category = r.ID, r.Name, r.Category
					company = companyOfRule(appID)
					score += 0.52
					addSrc("ip_cidr")
				}
			} else {
				if r, ok := classifyFlowIPv6(parsedIP, proto, q.DstPort); ok && r.ID != "" && !strings.HasPrefix(r.ID, "_") {
					appID, appName, category = r.ID, r.Name, r.Category
					company = companyOfRule(appID)
					score += 0.52
					addSrc("ip_cidr")
				}
			}
		}
	}

	// 维度 3: JA4 指纹家族交叉印证或无 DNS 盲态兜底
	if hasJA4Fam {
		if appID != "" {
			if company != "" && company == ja4Comp {
				score += 0.18 * ja4Share
				addSrc("ja4_family")
				e.ja4FamilyHits.Add(1)
			}
		} else {
			company = ja4Comp
			score += 0.44 * ja4Share
			addSrc("ja4_family")
			e.ja4FamilyHits.Add(1)
		}
	}

	// 维度 4: SPLT 包长序列原型相似度与业务形态细分消歧
	if bestProto != nil && bestProtoSim >= 0.78 {
		if appID == "" {
			appID = bestProto.appID
			appName = bestProto.appName
			category = bestProto.category
			if company == "" {
				company = bestProto.company
			}
			score += 0.42 * bestProtoSim
			addSrc("splt_proto")
			e.spltRefined.Add(1)
		} else if appID == bestProto.appID {
			score += 0.14 * bestProtoSim
			addSrc("splt_proto")
			e.spltRefined.Add(1)
		}
	}

	if shape != SPLTShapeUnknown {
		if appID == "" && company != "" {
			fb := companyShapeDisambiguate(company, shape)
			appID = fb.appID
			appName = fb.appName
			category = fb.category
			score += 0.22
			addSrc("splt_seq")
			e.spltRefined.Add(1)
		} else if appID != "" && shapeConsistentWithCategory(shape, category) {
			score += 0.10
			addSrc("splt_seq")
			e.spltRefined.Add(1)
		}
	}

	// 仅 JA4 家族命中但尚无 SPLT 包(首包阶段): 输出公司家族级归属
	if appID == "" && company != "" {
		fb := companyShapeDisambiguate(company, SPLTShapeUnknown)
		appID = fb.appID
		appName = fb.appName
		category = fb.category
	}

	if appID == "" || score < 0.30 {
		return ECHBlindVerdict{}, false
	}
	if score > 0.99 {
		score = 0.99
	}
	score = math.Round(score*100) / 100

	level := "low"
	switch {
	case score >= 0.75:
		level = "high"
	case score >= 0.50:
		level = "medium"
	}
	if appName == "" {
		appName = appID
	}
	sort.Strings(sources)

	e.inferHits.Add(1)
	return ECHBlindVerdict{
		AppID:           appID,
		AppName:         appName,
		Category:        category,
		Company:         company,
		CompanyName:     companyName(company),
		RealHost:        realHost,
		CNAMEHop:        cnameHop,
		Confidence:      score,
		ConfidenceLevel: level,
		Sources:         sources,
		SPLTShape:       SPLTShapeName(shape),
	}, true
}

// Stats 返回盲态推断引擎当前运行计数快照。
func (e *ECHBlindEngine) Stats() ECHBlindStats {
	return ECHBlindStats{
		SVCBRecorded:  e.svcbRecorded.Load(),
		InferQueries:  e.inferQueries.Load(),
		InferHits:     e.inferHits.Load(),
		SVCBHits:      e.svcbHits.Load(),
		CNAMEHits:     e.cnameHits.Load(),
		JA4FamilyHits: e.ja4FamilyHits.Load(),
		SPLTRefined:   e.spltRefined.Load(),
	}
}
